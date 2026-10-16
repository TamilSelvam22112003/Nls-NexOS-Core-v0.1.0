"""SQLite registry with idempotent, versioned schema migrations."""
import sqlite3
import json
from contextlib import contextmanager
from pathlib import Path

SCHEMA = """
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS routers(
 router_id TEXT PRIMARY KEY,
 registered INTEGER NOT NULL DEFAULT 0 CHECK(registered IN (0,1)),
 status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK(status IN ('ACTIVE','REVOKED','DISABLED')),
 expected_public_key_sha256 TEXT, allowed_ipv6 TEXT, allowed_mac TEXT,
 enrollment_token_sha256 TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS issued_certificates(
 serial_number TEXT PRIMARY KEY, router_id TEXT NOT NULL REFERENCES routers(router_id),
 not_before TEXT NOT NULL, not_after TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK(status IN ('ACTIVE','REVOKED','EXPIRED')),
 cert_sha256 TEXT NOT NULL, created_at INTEGER NOT NULL, revoked_at INTEGER
);
CREATE INDEX IF NOT EXISTS issued_router_idx ON issued_certificates(router_id);
CREATE TABLE IF NOT EXISTS enrollment_requests(
 request_id TEXT PRIMARY KEY, router_id TEXT NOT NULL, nonce_sha256 TEXT NOT NULL UNIQUE,
 created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log(
 id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER NOT NULL,
 event TEXT NOT NULL, router_id TEXT, detail TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS schema_version(version INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS directory_meta(singleton INTEGER PRIMARY KEY CHECK(singleton=1), directory_seq INTEGER NOT NULL);
INSERT OR IGNORE INTO schema_version(version) VALUES(1);
INSERT OR IGNORE INTO directory_meta(singleton,directory_seq) VALUES(1,0);
"""

_ROUTER_MIGRATIONS = {
 "expected_rsa_public_key_sha256": "TEXT",
 "ed25519_public_key": "TEXT",
 "rsa_encryption_public_key": "TEXT",
 "wan_endpoints": "TEXT NOT NULL DEFAULT '[]'",
 "gateway_ips": "TEXT NOT NULL DEFAULT '[]'",
 "prefixes": "TEXT NOT NULL DEFAULT '[]'",
 "record_seq": "INTEGER NOT NULL DEFAULT 1",
}

class Registry:
 def __init__(self, path: str | Path):
  self.path=Path(path); self.path.parent.mkdir(parents=True,exist_ok=True); self.initialize()

 @contextmanager
 def connect(self):
  con=sqlite3.connect(self.path,timeout=10); con.row_factory=sqlite3.Row
  try:
   con.execute("PRAGMA foreign_keys=ON"); con.execute("PRAGMA busy_timeout=10000")
   yield con; con.commit()
  except Exception:
   con.rollback(); raise
  finally: con.close()

 def initialize(self):
  with self.connect() as con:
   con.executescript(SCHEMA)
   router_cols={r["name"] for r in con.execute("PRAGMA table_info(routers)")}
   for name,decl in _ROUTER_MIGRATIONS.items():
    if name not in router_cols:
     con.execute(f"ALTER TABLE routers ADD COLUMN {name} {decl}")
   cert_cols={r["name"] for r in con.execute("PRAGMA table_info(issued_certificates)")}
   if "revoked_at" not in cert_cols:
    con.execute("ALTER TABLE issued_certificates ADD COLUMN revoked_at INTEGER")
   # Version 2 is the directory/enrollment schema. This is safe to rerun after
   # interruption because each ALTER is guarded by an introspection check.
   con.execute("UPDATE schema_version SET version=2")
  try: self.path.chmod(0o640)
  except OSError: pass

 def get_router(self, router_id):
  with self.connect() as con:
   row=con.execute("SELECT * FROM routers WHERE router_id=?",(router_id,)).fetchone()
   return dict(row) if row else None

 def list_routers(self):
  with self.connect() as con:
   return [dict(r) for r in con.execute("SELECT * FROM routers ORDER BY router_id")]

 def directory_seq(self):
  with self.connect() as con:
   return int(con.execute("SELECT directory_seq FROM directory_meta WHERE singleton=1").fetchone()[0])

 def bump_directory_seq(self, router_id=None):
  with self.connect() as con:
   con.execute("UPDATE directory_meta SET directory_seq=directory_seq+1 WHERE singleton=1")
   if router_id:
    con.execute("UPDATE routers SET record_seq=record_seq+1 WHERE router_id=?",(router_id,))
   return int(con.execute("SELECT directory_seq FROM directory_meta WHERE singleton=1").fetchone()[0])

 def set_directory_fields(self, router_id, *, wan_endpoints=None, gateway_ips=None, prefixes=None,
                          expected_rsa_public_key_sha256=None):
  with self.connect() as con:
   row=con.execute("SELECT router_id FROM routers WHERE router_id=?",(router_id,)).fetchone()
   if not row: raise ValueError("router must be registered before directory fields are set")
   fields={}
   for name,value in (("wan_endpoints",wan_endpoints),("gateway_ips",gateway_ips),("prefixes",prefixes)):
    if value is not None: fields[name]=json.dumps(value,separators=(",",":"),sort_keys=True)
   if expected_rsa_public_key_sha256 is not None:
    fields["expected_rsa_public_key_sha256"]=expected_rsa_public_key_sha256.lower() or None
   if fields:
    assignments=", ".join(f"{name}=?" for name in fields)
    con.execute(f"UPDATE routers SET {assignments},updated_at=? WHERE router_id=?",
                (*fields.values(),int(__import__("time").time()),router_id))
    con.execute("UPDATE routers SET record_seq=record_seq+1 WHERE router_id=?",(router_id,))
    con.execute("UPDATE directory_meta SET directory_seq=directory_seq+1 WHERE singleton=1")

 def is_request_new(self, request_id, router_id, nonce_sha256, now):
  with self.connect() as con:
   try:
    con.execute("INSERT INTO enrollment_requests(request_id,router_id,nonce_sha256,created_at) VALUES(?,?,?,?)",
                (request_id,router_id,nonce_sha256,now)); return True
   except sqlite3.IntegrityError: return False

 def record_enrollment_keys(self, router_id, ed25519_public_key, rsa_encryption_public_key, now):
  with self.connect() as con:
   con.execute("""UPDATE routers SET ed25519_public_key=?,rsa_encryption_public_key=?,
       record_seq=record_seq+1,updated_at=? WHERE router_id=?""",
       (ed25519_public_key,rsa_encryption_public_key,now,router_id))
   con.execute("UPDATE directory_meta SET directory_seq=directory_seq+1 WHERE singleton=1")

 def record_certificate(self, serial, router_id, before, after, digest, now):
  with self.connect() as con:
   con.execute("""INSERT INTO issued_certificates(serial_number,router_id,not_before,not_after,status,
       cert_sha256,created_at,revoked_at) VALUES(?,?,?,?,?,?,?,NULL)""",
       (serial,router_id,before,after,"ACTIVE",digest,now))
   con.execute("UPDATE routers SET record_seq=record_seq+1,updated_at=? WHERE router_id=?",(now,router_id))
   con.execute("UPDATE directory_meta SET directory_seq=directory_seq+1 WHERE singleton=1")

 def get_certificate(self, serial):
  with self.connect() as con:
   row=con.execute("SELECT * FROM issued_certificates WHERE lower(serial_number)=?",
                   (serial.lower().removeprefix("0x"),)).fetchone()
   return dict(row) if row else None

 def list_revoked_certificates(self):
  with self.connect() as con:
   return [dict(r) for r in con.execute(
    "SELECT serial_number,router_id,revoked_at FROM issued_certificates WHERE status='REVOKED' ORDER BY revoked_at,serial_number")]

 def revoke_certificate(self, serial, now):
  with self.connect() as con:
   row=con.execute("SELECT router_id FROM issued_certificates WHERE lower(serial_number)=?",
                   (serial.lower().removeprefix("0x"),)).fetchone()
   cur=con.execute("UPDATE issued_certificates SET status='REVOKED',revoked_at=? WHERE lower(serial_number)=? AND status='ACTIVE'",
                   (now,serial.lower().removeprefix("0x")))
   if cur.rowcount:
    con.execute("UPDATE routers SET record_seq=record_seq+1,updated_at=? WHERE router_id=?",(now,row["router_id"]))
    con.execute("UPDATE directory_meta SET directory_seq=directory_seq+1 WHERE singleton=1")
   return cur.rowcount==1

 def revoke_router(self, router_id, now):
  with self.connect() as con:
   cur=con.execute("UPDATE routers SET status='REVOKED',record_seq=record_seq+1,updated_at=? WHERE router_id=? AND status!='REVOKED'",
                   (now,router_id))
   if cur.rowcount:
    con.execute("UPDATE issued_certificates SET status='REVOKED',revoked_at=? WHERE router_id=? AND status='ACTIVE'",(now,router_id))
    con.execute("UPDATE directory_meta SET directory_seq=directory_seq+1 WHERE singleton=1")
   return cur.rowcount==1

 def audit(self,event,router_id,detail,now):
  with self.connect() as con:
   con.execute("INSERT INTO audit_log(timestamp,event,router_id,detail) VALUES(?,?,?,?)",
               (now,event,router_id,detail[:500]))
