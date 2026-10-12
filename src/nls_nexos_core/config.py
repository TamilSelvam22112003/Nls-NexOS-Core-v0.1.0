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
    certificate_days: int = 90
    max_request_bytes: int = 65536
    @classmethod
    def load(cls, path: str | Path) -> "Settings":
        raw=yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        srv,db,pki,enr=(raw.get(k,{}) for k in ("server","database","pki","enrollment"))
        port,days,size=int(srv.get("port",8443)),int(enr.get("certificate_days",90)),int(enr.get("max_request_bytes",65536))
        if not 1<=port<=65535 or not 1<=days<=397 or not 1024<=size<=1000000: raise ValueError("invalid server/enrollment settings")
        return cls(str(srv.get("host","127.0.0.1")),port,Path(db.get("path","/var/lib/nls-nexos-core/router-registry.sqlite3")),Path(pki.get("ca_certificate","/etc/nls-nexos-core/pki/ca-root.crt")),Path(pki.get("ca_private_key","/etc/nls-nexos-core/pki/ca-signing.key")),Path(pki.get("issued_cert_dir","/var/lib/nls-nexos-core/issued")),Path(enr.get("token_file","/etc/nls-nexos-core/enrollment-token")),days,size)

def token_from_environment_or_file(settings: Settings) -> str:
    token=os.environ.get("NLS_CA_ENROLLMENT_TOKEN")
    if not token and settings.token_file.is_file(): token=settings.token_file.read_text(encoding="utf-8").strip()
    if not token or len(token)<32: raise RuntimeError("enrollment token must contain at least 32 characters")
    return token
