import sqlite3
from contextlib import contextmanager
from pathlib import Path
SCHEMA = """
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS routers(router_id TEXT PRIMARY KEY,registered INTEGER NOT NULL DEFAULT 0 CHECK(registered IN (0,1)),status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK(status IN ('ACTIVE','REVOKED','DISABLED')),expected_public_key_sha256 TEXT,allowed_ipv6 TEXT,allowed_mac TEXT,enrollment_token_sha256 TEXT,created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS issued_certificates(serial_number TEXT PRIMARY KEY,router_id TEXT NOT NULL REFERENCES routers(router_id),not_before TEXT NOT NULL,not_after TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK(status IN ('ACTIVE','REVOKED','EXPIRED')),cert_sha256 TEXT NOT NULL,created_at INTEGER NOT NULL,revoked_at INTEGER);
CREATE INDEX IF NOT EXISTS issued_router_idx ON issued_certificates(router_id);
CREATE TABLE IF NOT EXISTS enrollment_requests(request_id TEXT PRIMARY KEY,router_id TEXT NOT NULL,nonce_sha256 TEXT NOT NULL UNIQUE,created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS audit_log(id INTEGER PRIMARY KEY AUTOINCREMENT,timestamp INTEGER NOT NULL,event TEXT NOT NULL,router_id TEXT,detail TEXT NOT NULL DEFAULT '');
"""
class Registry:
 def __init__(self,path: str | Path):
  self.path=Path(path);self.path.parent.mkdir(parents=True,exist_ok=True);self.initialize()
 @contextmanager
 def connect(self):
  con=sqlite3.connect(self.path,timeout=10);con.row_factory=sqlite3.Row
  try:
   con.execute("PRAGMA foreign_keys=ON");con.execute("PRAGMA busy_timeout=10000");yield con;con.commit()
  except Exception:con.rollback();raise
  finally:con.close()
 def initialize(self):
  with self.connect() as con:
   con.executescript(SCHEMA)
   cols={r["name"] for r in con.execute("PRAGMA table_info(issued_certificates)")}
   if "revoked_at" not in cols:con.execute("ALTER TABLE issued_certificates ADD COLUMN revoked_at INTEGER")
  try:self.path.chmod(0o640)
  except OSError:pass
 def get_router(self,router_id):
  with self.connect() as con:
   row=con.execute("SELECT * FROM routers WHERE router_id=?",(router_id,)).fetchone();return dict(row) if row else None
 def is_request_new(self,request_id,router_id,nonce_sha256,now):
  with self.connect() as con:
   try:
    con.execute("INSERT INTO enrollment_requests(request_id,router_id,nonce_sha256,created_at) VALUES(?,?,?,?)",(request_id,router_id,nonce_sha256,now));return True
   except sqlite3.IntegrityError:return False
 def record_certificate(self,serial,router_id,before,after,digest,now):
  with self.connect() as con:
   con.execute("INSERT INTO issued_certificates(serial_number,router_id,not_before,not_after,status,cert_sha256,created_at,revoked_at) VALUES(?,?,?,?,?,?,?,NULL)",(serial,router_id,before,after,"ACTIVE",digest,now))
 def get_certificate(self,serial):
  with self.connect() as con:
   row=con.execute("SELECT * FROM issued_certificates WHERE lower(serial_number)=?",(serial.lower().removeprefix("0x"),)).fetchone();return dict(row) if row else None
 def list_revoked_certificates(self):
  with self.connect() as con:
   return [dict(r) for r in con.execute("SELECT serial_number,router_id,revoked_at FROM issued_certificates WHERE status='REVOKED' ORDER BY revoked_at,serial_number")]
 def revoke_certificate(self,serial,now):
  with self.connect() as con:
   cur=con.execute("UPDATE issued_certificates SET status='REVOKED',revoked_at=? WHERE lower(serial_number)=? AND status='ACTIVE'",(now,serial.lower().removeprefix("0x")));return cur.rowcount==1
 def audit(self,event,router_id,detail,now):
  with self.connect() as con:con.execute("INSERT INTO audit_log(timestamp,event,router_id,detail) VALUES(?,?,?,?)",(now,event,router_id,detail[:500]))
