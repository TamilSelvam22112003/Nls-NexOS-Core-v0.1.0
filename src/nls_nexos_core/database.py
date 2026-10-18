"""SQLite registry with idempotent, versioned schema migrations."""
import sqlite3
import json
import ipaddress
from contextlib import contextmanager
from pathlib import Path

SCHEMA = """
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS routers(
 router_id TEXT PRIMARY KEY,
 registered INTEGER NOT NULL DEFAULT 0 CHECK(registered IN (0,1)),
 status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK(status IN ('ACTIVE','REVOKED','DISABLED')),
 original_ip TEXT UNIQUE,
 expected_public_key_sha256 TEXT, allowed_ipv6 TEXT, allowed_mac TEXT,
 enrollment_token_sha256 TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS issued_certificates(
 serial_number TEXT PRIMARY KEY, router_id TEXT NOT NULL REFERENCES routers(router_id),
 not_before TEXT NOT NULL, not_after TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK(status IN ('ACTIVE','REVOKED','EXPIRED')),
 cert_sha256 TEXT NOT NULL, created_at INTEGER NOT NULL, revoked_at INTEGER,
 certificate_der_b64 TEXT
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
CREATE TABLE IF NOT EXISTS schema_version(singleton INTEGER PRIMARY KEY CHECK(singleton=1), version INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS directory_meta(singleton INTEGER PRIMARY KEY CHECK(singleton=1), directory_seq INTEGER NOT NULL);
INSERT OR IGNORE INTO schema_version(singleton,version) VALUES(1,1);
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
 "original_ip_usable": "INTEGER NOT NULL DEFAULT 0 CHECK(original_ip_usable IN (0,1))",
 "original_ip": "TEXT",
}

def _parse_ip_port(endpoint, *, require_bracketed_ipv6=False, reject_special_ipv6=False):
 if not isinstance(endpoint, str) or not endpoint or "%" in endpoint:
  raise ValueError("invalid WAN endpoint or IPv6 zone identifier")
 if endpoint.startswith("["):
  if "]:" not in endpoint:
   raise ValueError("WAN IPv6 endpoint must use [address]:port")
  host, port_text = endpoint[1:].rsplit("]:", 1)
  if not host or "[" in host or "]" in host:
   raise ValueError("invalid bracketed IPv6 endpoint")
  address = ipaddress.IPv6Address(host)
 else:
  if require_bracketed_ipv6:
   raise ValueError("first WAN endpoint must use bracketed IPv6 [address]:port")
  if endpoint.count(":") != 1:
   raise ValueError("WAN IPv4 endpoint must use address:port; bracket IPv6")
  host, port_text = endpoint.rsplit(":", 1)
  address = ipaddress.ip_address(host)
 if not port_text.isascii() or not port_text.isdecimal():
  raise ValueError("WAN endpoint port must be an integer")
 port = int(port_text)
 if not 1 <= port <= 65535:
  raise ValueError("WAN endpoint port must be between 1 and 65535")
 if require_bracketed_ipv6 and not isinstance(address, ipaddress.IPv6Address):
  raise ValueError("first WAN endpoint must be IPv6")
 if reject_special_ipv6 and (address.is_unspecified or address.is_loopback or address.is_multicast or address.is_link_local or address.ipv4_mapped is not None):
  raise ValueError("first WAN endpoint uses a forbidden IPv6 address class")
 return address, port


def original_ip_from_endpoints(wan_endpoints):
 """Return canonical originalIP from ordered endpoint[0], or None if absent."""
 if not wan_endpoints:
  return None
 address, _ = _parse_ip_port(wan_endpoints[0], require_bracketed_ipv6=True, reject_special_ipv6=True)
 return str(address)


def validate_wan_endpoints(wan_endpoints):
 """Validate ordered IP:PORT endpoints and return originalIP (None for an empty list)."""
 if not isinstance(wan_endpoints, (list, tuple)):
  raise ValueError("wan_endpoints must be an ordered list")
 if not wan_endpoints:
  return None
 original_ip = original_ip_from_endpoints(wan_endpoints)
 for endpoint in wan_endpoints[1:]:
  _parse_ip_port(endpoint)
 return original_ip

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
   if "certificate_der_b64" not in cert_cols:
    con.execute("ALTER TABLE issued_certificates ADD COLUMN certificate_der_b64 TEXT")
   version_row=con.execute("SELECT version FROM schema_version WHERE singleton=1").fetchone()
   old_version=int(version_row[0]) if version_row else 1
   if old_version < 4:
    # Preserve legacy rows. Invalid and duplicate originalIP claims remain in the
    # registry but are marked unusable; deterministic ordering resolves old duplicates.
    seen=set()
    for row in con.execute("SELECT router_id,wan_endpoints FROM routers ORDER BY router_id").fetchall():
     try:
      endpoints=json.loads(row["wan_endpoints"] or "[]")
      original_ip=validate_wan_endpoints(endpoints)
      usable=original_ip is not None and original_ip not in seen
     except (ValueError,TypeError,json.JSONDecodeError):
      original_ip=None; usable=False
     if usable: seen.add(original_ip)
     con.execute("UPDATE routers SET original_ip=?,original_ip_usable=? WHERE router_id=?",
                 (original_ip if usable else None,1 if usable else 0,row["router_id"]))
   # Enforce uniqueness only for usable records; unusable legacy rows are retained.
   con.execute("CREATE UNIQUE INDEX IF NOT EXISTS routers_original_ip_unique ON routers(original_ip) WHERE original_ip IS NOT NULL AND original_ip_usable=1")
   con.execute("UPDATE schema_version SET version=4 WHERE singleton=1")
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
  endpoint_original_ip = None
  endpoint_usable = None
  if wan_endpoints is not None:
   try:
    endpoint_original_ip = validate_wan_endpoints(wan_endpoints)
    endpoint_usable = endpoint_original_ip is not None
   except (ValueError,TypeError) as exc:
    raise ValueError(f"invalid WAN endpoint metadata: {exc}") from exc
  with self.connect() as con:
   row=con.execute("SELECT router_id FROM routers WHERE router_id=?",(router_id,)).fetchone()
   if not row: raise ValueError("router must be registered before directory fields are set")
   fields={}
   for name,value in (("wan_endpoints",wan_endpoints),("gateway_ips",gateway_ips),("prefixes",prefixes)):
    if value is not None: fields[name]=json.dumps(value,separators=(",",":"),sort_keys=True)
   if endpoint_usable is not None:
    fields["original_ip_usable"]=1 if endpoint_usable else 0
    fields["original_ip"]=endpoint_original_ip
   if expected_rsa_public_key_sha256 is not None:
    fields["expected_rsa_public_key_sha256"]=expected_rsa_public_key_sha256.lower() or None
   if fields:
    assignments=", ".join(f"{name}=?" for name in fields)
    try:
     con.execute(f"UPDATE routers SET {assignments},updated_at=? WHERE router_id=?",
                 (*fields.values(),int(__import__("time").time()),router_id))
    except sqlite3.IntegrityError as exc:
     if "UNIQUE constraint failed: routers.original_ip" in str(exc):
      raise ValueError("originalIP must be unique across usable routers") from exc
     raise
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

 def record_certificate(self, serial, router_id, before, after, digest, now, certificate_der_b64=None):
  with self.connect() as con:
   con.execute("""INSERT INTO issued_certificates(serial_number,router_id,not_before,not_after,status,
       cert_sha256,created_at,revoked_at,certificate_der_b64) VALUES(?,?,?,?,?,?,?,NULL,?)""",
       (serial,router_id,before,after,"ACTIVE",digest,now,certificate_der_b64))
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

 def expire_certificates(self, now):
  from datetime import datetime, timezone
  now_dt=datetime.fromtimestamp(int(now),timezone.utc)
  expired=[]
  with self.connect() as con:
   rows=con.execute("SELECT serial_number,router_id,not_after FROM issued_certificates WHERE status='ACTIVE'").fetchall()
   for row in rows:
    try:
     expiry=datetime.fromisoformat(row["not_after"].replace("Z","+00:00"))
     if expiry.tzinfo is None: expiry=expiry.replace(tzinfo=timezone.utc)
    except (ValueError,TypeError):
     expiry=now_dt
    if expiry <= now_dt:
     cur=con.execute("UPDATE issued_certificates SET status='EXPIRED' WHERE serial_number=? AND status='ACTIVE'",(row["serial_number"],))
     if cur.rowcount:
      expired.append(row["router_id"])
   for router_id in expired:
    con.execute("UPDATE routers SET record_seq=record_seq+1,updated_at=? WHERE router_id=?",(int(now),router_id))
    con.execute("UPDATE directory_meta SET directory_seq=directory_seq+1 WHERE singleton=1")
  return len(expired)

 def set_router_status(self, router_id, status, now):
  if status not in ("ACTIVE", "DISABLED"):
   raise ValueError("admin status transition must be ACTIVE or DISABLED")
  with self.connect() as con:
   row=con.execute("SELECT status FROM routers WHERE router_id=?",(router_id,)).fetchone()
   if not row or row["status"] == "REVOKED" or row["status"] == status:
    return False
   cur=con.execute("UPDATE routers SET status=?,record_seq=record_seq+1,updated_at=? WHERE router_id=? AND status!='REVOKED'",
                   (status,int(now),router_id))
   if cur.rowcount:
    con.execute("UPDATE directory_meta SET directory_seq=directory_seq+1 WHERE singleton=1")
   return cur.rowcount == 1

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
