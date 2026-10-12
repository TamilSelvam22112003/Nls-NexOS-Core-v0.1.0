import sqlite3
from contextlib import contextmanager
from pathlib import Path
SCHEMA='''PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS routers(router_id TEXT PRIMARY KEY,registered INTEGER NOT NULL DEFAULT 0 CHECK(registered IN (0,1)),status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK(status IN ('ACTIVE','REVOKED','DISABLED')),expected_public_key_sha256 TEXT,allowed_ipv6 TEXT,allowed_mac TEXT,enrollment_token_sha256 TEXT,created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS issued_certificates(serial_number TEXT PRIMARY KEY,router_id TEXT NOT NULL REFERENCES routers(router_id),not_before TEXT NOT NULL,not_after TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'ACTIVE',cert_sha256 TEXT NOT NULL,created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS enrollment_requests(request_id TEXT PRIMARY KEY,router_id TEXT NOT NULL,nonce_sha256 TEXT NOT NULL,created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS audit_log(id INTEGER PRIMARY KEY AUTOINCREMENT,timestamp INTEGER NOT NULL,event TEXT NOT NULL,router_id TEXT,detail TEXT NOT NULL DEFAULT '');'''
class Registry:
 def __init__(self,path): self.path=Path(path); self.path.parent.mkdir(parents=True,exist_ok=True); self.initialize()
 @contextmanager
 def connect(self):
  con=sqlite3.connect(self.path,timeout=10); con.row_factory=sqlite3.Row
  try: con.execute('PRAGMA foreign_keys=ON'); con.execute('PRAGMA busy_timeout=10000'); yield con; con.commit()
  except Exception: con.rollback(); raise
  finally: con.close()
 def initialize(self):
  with self.connect() as con: con.executescript(SCHEMA)
  try:self.path.chmod(0o640)
  except OSError:pass
 def get_router(self,router_id):
  with self.connect() as con:
   row=con.execute('SELECT * FROM routers WHERE router_id=?',(router_id,)).fetchone(); return dict(row) if row else None
 def is_request_new(self,request_id,router_id,nonce_sha256,now):
  with self.connect() as con:
   try: con.execute('INSERT INTO enrollment_requests VALUES(?,?,?,?)',(request_id,router_id,nonce_sha256,now)); return True
   except sqlite3.IntegrityError:return False
 def record_certificate(self,serial,router_id,before,after,digest,now):
  with self.connect() as con: con.execute('INSERT INTO issued_certificates(serial_number,router_id,not_before,not_after,status,cert_sha256,created_at) VALUES(?,?,?,?,?,?,?)',(serial,router_id,before,after,'ACTIVE',digest,now))
 def audit(self,event,router_id,detail,now):
  with self.connect() as con: con.execute('INSERT INTO audit_log(timestamp,event,router_id,detail) VALUES(?,?,?,?)',(now,event,router_id,detail[:500]))