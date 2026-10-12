import argparse
import logging
import os
from pathlib import Path
import secrets
import sqlite3
import sys
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, BasicConstraintsOID

from .config import Settings
from .database import Registry


def bootstrap(config_path: str):
    settings = Settings.load(config_path)
    settings.ca_certificate.parent.mkdir(parents=True, exist_ok=True)
    settings.ca_private_key.parent.mkdir(parents=True, exist_ok=True)
    if settings.ca_certificate.exists() or settings.ca_private_key.exists():
        raise SystemExit("CA material already exists; refusing to overwrite it")
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "NLS Router-CA Root")])
    now = __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
    cert = (
        x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now.replace(tzinfo=None))
        .not_valid_after((now.replace(tzinfo=None) + __import__("datetime").timedelta(days=3650)))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=True, encipher_only=None, decipher_only=None,
        ), critical=True)
        .sign(key, hashes.SHA256())
    )
    settings.ca_private_key.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    settings.ca_certificate.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    os.chmod(settings.ca_private_key, 0o600)
    os.chmod(settings.ca_certificate, 0o644)
    token = secrets.token_urlsafe(48)
    settings.token_file.parent.mkdir(parents=True, exist_ok=True)
    settings.token_file.write_text(token + "\n", encoding="ascii")
    os.chmod(settings.token_file, 0o600)
    Registry(settings.database_path)
    print(f"CA root created: {settings.ca_certificate}")
    print(f"CA private key created: {settings.ca_private_key}")
    print(f"Enrollment token created: {settings.token_file}")
    print("Register routers in the registry before allowing enrollment.")
    print("IMPORTANT: protect and back up CA private key securely; keep it offline where feasible.")


def register(config_path: str, router_id: str, token: str, public_key_sha256: str = "", ipv6: str = "", mac: str = ""):
    settings = Settings.load(config_path)
    registry = Registry(settings.database_path)
    now = int(time.time())
    with registry.connect() as con:
        con.execute(
            """INSERT INTO routers(router_id,registered,status,expected_public_key_sha256,allowed_ipv6,allowed_mac,enrollment_token_sha256,created_at,updated_at)
               VALUES(?,1,'ACTIVE',?,?,?,?,?,?)
               ON CONFLICT(router_id) DO UPDATE SET registered=1,status='ACTIVE',
                 expected_public_key_sha256=excluded.expected_public_key_sha256,
                 allowed_ipv6=excluded.allowed_ipv6,allowed_mac=excluded.allowed_mac,
                 enrollment_token_sha256=excluded.enrollment_token_sha256,updated_at=excluded.updated_at""",
            (router_id, public_key_sha256 or None, ipv6 or None, mac or None,
             __import__("hashlib").sha256(token.encode()).hexdigest(), now, now),
        )
    registry.audit("ROUTER_REGISTERED", router_id, "registered by local administrator", now)
    print(f"Registered router: {router_id}")


def serve(config_path: str):
    import uvicorn
    settings = Settings.load(config_path)
    # The TLS web server must use the configured server certificate and key. The app
    # itself intentionally refuses to start without CA trust/keys/token.
    raise SystemExit(
        "HTTPS listener is not yet wired to the TLS config. Run via a TLS-terminating "
        "reverse proxy with client verification; do not expose this prototype directly."
    )


def main():
    parser = argparse.ArgumentParser(prog="nls-router-ca")
    parser.add_argument("--config", default="/etc/nls-nexos-core/router-ca.yaml")
    subs = parser.add_subparsers(dest="command", required=True)
    subs.add_parser("init")
    s = subs.add_parser("serve")
    r = subs.add_parser("register-router")
    r.add_argument("router_id")
    r.add_argument("--token", required=True)
    r.add_argument("--public-key-sha256", default="")
    r.add_argument("--ipv6", default="")
    r.add_argument("--mac", default="")
    args = parser.parse_args()
    if args.command == "init":
        bootstrap(args.config)
    elif args.command == "serve":
        serve(args.config)
    elif args.command == "register-router":
        register(args.config, args.router_id, args.token, args.public_key_sha256, args.ipv6, args.mac)


if __name__ == "__main__":
    main()
