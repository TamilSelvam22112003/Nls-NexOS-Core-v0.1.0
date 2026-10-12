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
    max_request_bytes: int = 65_536
    log_level: str = "INFO"

    @classmethod
    def load(cls, path: str | Path) -> "Settings":
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        server = raw.get("server", {})
        db = raw.get("database", {})
        pki = raw.get("pki", {})
        enroll = raw.get("enrollment", {})
        host = str(server.get("host", "127.0.0.1"))
        port = int(server.get("port", 8443))
        if not 1 <= port <= 65535:
            raise ValueError("server port must be within 1..65535")
        days = int(enroll.get("certificate_days", 90))
        if not 1 <= days <= 397:
            raise ValueError("certificate_days must be within 1..397")
        return cls(
            host=host,
            port=port,
            database_path=Path(db.get("path", "/var/lib/nls-nexos-core/router-registry.sqlite3")),
            ca_certificate=Path(pki.get("ca_certificate", "/etc/nls-nexos-core/pki/ca-root.crt")),
            ca_private_key=Path(pki.get("ca_private_key", "/etc/nls-nexos-core/pki/ca-signing.key")),
            issued_cert_dir=Path(pki.get("issued_cert_dir", "/var/lib/nls-nexos-core/issued")),
            token_file=Path(enroll.get("token_file", "/etc/nls-nexos-core/enrollment-token")),
            certificate_days=days,
            max_request_bytes=int(enroll.get("max_request_bytes", 65_536)),
            log_level=str(server.get("log_level", "INFO")).upper(),
        )


def token_from_environment_or_file(settings: Settings) -> str:
    token = os.environ.get("NLS_CA_ENROLLMENT_TOKEN")
    if not token and settings.token_file.is_file():
        token = settings.token_file.read_text(encoding="utf-8").strip()
    if not token or len(token) < 32:
        raise RuntimeError("enrollment token must be configured and contain at least 32 characters")
    return token
