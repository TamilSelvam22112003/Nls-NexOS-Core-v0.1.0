import argparse
import base64
import hashlib
import os
import secrets
import time
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
from cryptography.x509.oid import NameOID

from .config import Settings, token_from_environment_or_file
from .control import NLSControlServer
from .ca import CertificateAuthority
from .database import Registry


def _load_or_create_control_identity(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raw = path.read_bytes()
        if len(raw) != 32:
            raise RuntimeError("invalid NLS control identity key length")
        return ed25519.Ed25519PrivateKey.from_private_bytes(raw)
    key = ed25519.Ed25519PrivateKey.generate()
    raw = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                             serialization.NoEncryption())
    tmp = path.with_suffix(".tmp")
    tmp.write_bytes(raw)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    os.chmod(path, 0o600)
    return key


def bootstrap(config_path: str):
    settings = Settings.load(config_path)
    settings.ca_certificate.parent.mkdir(parents=True, exist_ok=True)
    settings.ca_private_key.parent.mkdir(parents=True, exist_ok=True)
    if settings.ca_certificate.exists() or settings.ca_private_key.exists():
        raise SystemExit("CA material exists; refusing overwrite")
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    now = datetime.now(timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "NLS Router-CA Root")])
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now.replace(tzinfo=None))
        .not_valid_after((now + timedelta(days=3650)).replace(tzinfo=None))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=True, encipher_only=None, decipher_only=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    settings.ca_private_key.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    settings.ca_certificate.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    os.chmod(settings.ca_private_key, 0o600)
    os.chmod(settings.ca_certificate, 0o644)
    token = secrets.token_urlsafe(48)
    settings.token_file.parent.mkdir(parents=True, exist_ok=True)
    settings.token_file.write_text(token + "\n", encoding="ascii")
    os.chmod(settings.token_file, 0o600)
    Registry(settings.database_path)
    control_key = _load_or_create_control_identity(settings.control_identity_key)
    public_raw = control_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    root_fp = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
    print(f"Router-CA root certificate: {settings.ca_certificate}")
    print(f"Router-CA root SHA-256 fingerprint: {root_fp}")
    print(f"Router-CA signing key: {settings.ca_private_key}")
    print(f"NLS control identity ID: {settings.control_id}")
    print("NLS control Ed25519 public key (provision out-of-band): " +
          base64.b64encode(public_raw).decode("ascii"))
    print(f"Bootstrap enrollment token: {settings.token_file}")
    print("Protect the CA signing key and bootstrap token. The NLS control public key must be pinned on routers.")


def register(config_path: str, router_id: str, token: str,
             public_key_sha256: str = "", ipv6: str = "", mac: str = ""):
    if len(token) < 32:
        raise SystemExit("Router enrollment token must be at least 32 characters")
    settings = Settings.load(config_path)
    registry = Registry(settings.database_path)
    now = int(time.time())
    with registry.connect() as con:
        con.execute(
            """INSERT INTO routers(router_id,registered,status,expected_public_key_sha256,
                allowed_ipv6,allowed_mac,enrollment_token_sha256,created_at,updated_at)
               VALUES(?,1,'ACTIVE',?,?,?,?,?,?)
               ON CONFLICT(router_id) DO UPDATE SET registered=1,status='ACTIVE',
                 expected_public_key_sha256=excluded.expected_public_key_sha256,
                 allowed_ipv6=excluded.allowed_ipv6,allowed_mac=excluded.allowed_mac,
                 enrollment_token_sha256=excluded.enrollment_token_sha256,updated_at=excluded.updated_at""",
            (router_id, public_key_sha256 or None, ipv6 or None, mac or None,
             hashlib.sha256(token.encode()).hexdigest(), now, now),
        )
    registry.audit("ROUTER_REGISTERED", router_id, "registered by local administrator", now)
    print(f"Registered router: {router_id}")


def revoke_certificate(config_path: str, serial: str):
    settings = Settings.load(config_path)
    registry = Registry(settings.database_path)
    now = int(time.time())
    row = registry.get_certificate(serial)
    if not row:
        raise SystemExit("Certificate serial not found")
    if not registry.revoke_certificate(serial, now):
        raise SystemExit("Certificate is not active")
    registry.audit("CERT_REVOKED", row["router_id"], f"serial={row['serial_number']}", now)
    print(f"Revoked certificate {row['serial_number']} for router {row['router_id']}")


def serve(config_path: str):
    settings = Settings.load(config_path)
    registry = Registry(settings.database_path)
    token = token_from_environment_or_file(settings)
    authority = CertificateAuthority(settings, registry, token)
    identity = _load_or_create_control_identity(settings.control_identity_key)
    server = NLSControlServer(settings, registry, authority, identity)
    server.serve_forever()


def main():
    parser = argparse.ArgumentParser(prog="nls-router-ca")
    parser.add_argument("--config", default="/etc/nls-nexos-core/router-ca.yaml")
    subs = parser.add_subparsers(dest="cmd", required=True)
    subs.add_parser("init")
    subs.add_parser("serve")
    register_parser = subs.add_parser("register-router")
    register_parser.add_argument("router_id")
    token_group = register_parser.add_mutually_exclusive_group(required=True)
    token_group.add_argument("--token", help="legacy option; token may be visible in shell history")
    token_group.add_argument("--token-file", help="read router token from a protected file")
    register_parser.add_argument("--public-key-sha256", default="")
    register_parser.add_argument("--ipv6", default="")
    register_parser.add_argument("--mac", default="")
    revoke = subs.add_parser("revoke-certificate")
    revoke.add_argument("serial_number")
    args = parser.parse_args()
    if args.cmd == "init":
        bootstrap(args.config)
    elif args.cmd == "serve":
        serve(args.config)
    elif args.cmd == "revoke-certificate":
        revoke_certificate(args.config, args.serial_number)
    else:
        token = args.token if args.token is not None else open(args.token_file, encoding="utf-8").read().strip()
        register(args.config, args.router_id, token, args.public_key_sha256, args.ipv6, args.mac)


if __name__ == "__main__":
    main()
