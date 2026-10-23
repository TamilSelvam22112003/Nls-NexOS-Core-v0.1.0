from dataclasses import dataclass
from pathlib import Path
import os
import yaml

@dataclass(frozen=True)
class Settings:
 host: str
 port: int
 database_path: Path
 ca_certificate: Path
 ca_private_key: Path
 issued_cert_dir: Path
 token_file: Path
 certificate_days: int=90
 max_request_bytes: int=65536
 control_identity_key: Path=Path("/var/lib/nls-nexos-core/identity/control-ed25519.key")
 control_id: str="nls-router-ca"
 policy_version: int=1
 replay_window: int=64
 max_clock_skew_seconds: int=120
 session_timeout_seconds: int=300
 key_rotation_seconds: int=3600
 @classmethod
 def load(cls,path: str | Path):
  raw=yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
  srv,db,pki,enr=(raw.get(k,{}) for k in ("server","database","pki","enrollment"))
  port,days,size=int(srv.get("port",4790)),int(enr.get("certificate_days",90)),int(enr.get("max_request_bytes",65536))
  replay,skew,timeout,rotation,version=(int(srv.get(k,d)) for k,d in (("replay_window",64),("max_clock_skew_seconds",120),("session_timeout_seconds",300),("key_rotation_seconds",3600),("policy_version",1)))
  if not 1<=port<=65535 or not 1<=days<=397 or not 1024<=size<=1000000:raise ValueError("invalid server/enrollment settings")
  if not 1<=replay<=4096 or not 30<=skew<=600 or not 30<=timeout<=86400 or not 60<=rotation<=604800:raise ValueError("invalid NLS security policy")
  if version != 1:raise ValueError("unsupported policy_version")
  control_id=str(srv.get("control_id","nls-router-ca"))
  if not control_id or len(control_id)>128:raise ValueError("control_id must be 1..128 characters")
  return cls(str(srv.get("host","::")),port,Path(db.get("path","/var/lib/nls-nexos-core/router-registry.sqlite3")),Path(pki.get("ca_certificate","/etc/nls-nexos-core/pki/ca-root.crt")),Path(pki.get("ca_private_key","/etc/nls-nexos-core/pki/ca-signing.key")),Path(pki.get("issued_cert_dir","/var/lib/nls-nexos-core/issued")),Path(enr.get("token_file","/etc/nls-nexos-core/enrollment-token")),days,size,Path(srv.get("identity_key","/var/lib/nls-nexos-core/identity/control-ed25519.key")),control_id,version,replay,skew,timeout,rotation)

def token_from_environment_or_file(settings: Settings) -> str:
 token=os.environ.get("NLS_CA_ENROLLMENT_TOKEN")
 if not token and settings.token_file.is_file():token=settings.token_file.read_text(encoding="utf-8").strip()
 if not token or len(token)<32:raise RuntimeError("enrollment token must contain at least 32 characters")
 return token
