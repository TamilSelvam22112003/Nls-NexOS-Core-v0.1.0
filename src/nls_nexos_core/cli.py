import argparse
import base64
import hashlib
import ipaddress
import json
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
from .database import Registry, validate_wan_endpoints
from .directory import record_for_router
from .directory import signed_directory_bundle


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
    registry = Registry(settings.database_path)
    control_key = _load_or_create_control_identity(settings.control_identity_key)
    public_raw = control_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    root_fp = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
    registry.audit("CA_BOOTSTRAPPED", None, "Router-CA initialized by local administrator", int(time.time()))
    print(f"Router-CA root certificate: {settings.ca_certificate}")
    print(f"Router-CA root SHA-256 fingerprint: {root_fp}")
    print(f"Router-CA signing key: {settings.ca_private_key}")
    print(f"NLS control identity ID: {settings.control_id}")
    print("NLS control Ed25519 public key (provision out-of-band): " +
          base64.b64encode(public_raw).decode("ascii"))
    print(f"Bootstrap enrollment token: {settings.token_file}")
    print("Protect the CA signing key and bootstrap token. The NLS control public key must be pinned on routers.")


def register(config_path: str, router_id: str, token: str,
             public_key_sha256: str = "", ipv6: str = "", mac: str = "",
             rsa_public_key_sha256: str = "", wan_endpoints=None, gateway_ips=None, prefixes=None):
    settings = Settings.load(config_path)
    registry = Registry(settings.database_path)
    now = int(time.time())
    if len(token) < 32:
        registry.audit("ROUTER_REGISTER_DENIED", router_id, "enrollment token length rejected", now)
        raise SystemExit("Router enrollment token must be at least 32 characters")
    if wan_endpoints is not None:
        try:
            validate_wan_endpoints(wan_endpoints)
        except (ValueError, TypeError) as exc:
            registry.audit("ROUTER_REGISTER_DENIED", router_id, "invalid WAN endpoint metadata", now)
            raise SystemExit(f"Invalid WAN endpoint metadata: {exc}") from exc
    try:
        for gateway in gateway_ips or []:
            ipaddress.ip_address(gateway)
        for prefix in prefixes or []:
            ipaddress.ip_network(prefix, strict=False)
    except ValueError as exc:
        registry.audit("ROUTER_REGISTER_DENIED", router_id, "invalid gateway or prefix metadata", now)
        raise SystemExit(f"Invalid gateway IP or prefix: {exc}") from exc
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
    metadata_supplied = bool(wan_endpoints or gateway_ips or prefixes or rsa_public_key_sha256)
    try:
        registry.set_directory_fields(
            router_id, wan_endpoints=list(wan_endpoints) if wan_endpoints else None,
            gateway_ips=list(gateway_ips) if gateway_ips else None,
            prefixes=list(prefixes) if prefixes else None,
            expected_rsa_public_key_sha256=rsa_public_key_sha256 or None,
        )
    except ValueError as exc:
        registry.audit("ROUTER_REGISTER_DENIED", router_id, "metadata registration rejected", int(time.time()))
        raise SystemExit(f"Router registration rejected: {exc}") from exc
    if not metadata_supplied:
        registry.bump_directory_seq(router_id)
    registry.audit("ROUTER_REGISTERED", router_id, "registered by local administrator", now)
    print(f"Registered router: {router_id}")


def update_router(config_path: str, router_id: str, wan_endpoints=None, gateway_ips=None, prefixes=None,
                  rsa_public_key_sha256: str | None = None):
    settings = Settings.load(config_path)
    registry = Registry(settings.database_path)
    now = int(time.time())
    if not any(value is not None for value in (wan_endpoints, gateway_ips, prefixes, rsa_public_key_sha256)):
        registry.audit("ROUTER_UPDATE_DENIED", router_id, "no metadata fields supplied", now)
        raise SystemExit("update-router requires at least one metadata option")
    try:
        for gateway in gateway_ips or []:
            ipaddress.ip_address(gateway)
        for prefix in prefixes or []:
            ipaddress.ip_network(prefix, strict=False)
    except ValueError as exc:
        registry.audit("ROUTER_UPDATE_DENIED", router_id, "invalid gateway or prefix metadata", now)
        raise SystemExit(f"Invalid gateway IP or prefix: {exc}") from exc
    try:
        registry.set_directory_fields(
            router_id, wan_endpoints=wan_endpoints, gateway_ips=gateway_ips, prefixes=prefixes,
            expected_rsa_public_key_sha256=rsa_public_key_sha256,
        )
    except ValueError as exc:
        registry.audit("ROUTER_UPDATE_DENIED", router_id, "invalid or conflicting metadata update", int(time.time()))
        raise SystemExit(f"Router metadata update rejected: {exc}") from exc
    registry.audit("ROUTER_UPDATED", router_id, "directory metadata updated by local administrator", int(time.time()))
    print(f"Updated router metadata: {router_id}")


def set_router_enabled(config_path: str, router_id: str, enabled: bool):
    settings = Settings.load(config_path)
    registry = Registry(settings.database_path)
    now = int(time.time())
    status = "ACTIVE" if enabled else "DISABLED"
    if not registry.set_router_status(router_id, status, now):
        registry.audit("ROUTER_STATUS_CHANGE_DENIED", router_id, "router missing, revoked, or already in requested state", now)
        raise SystemExit("Router not found, revoked, or already in requested state")
    registry.audit("ROUTER_ENABLED" if enabled else "ROUTER_DISABLED", router_id,
                   "status changed by local administrator", now)
    print(f"Router status set to {status}: {router_id}")


def revoke_certificate(config_path: str, serial: str):
    settings = Settings.load(config_path)
    registry = Registry(settings.database_path)
    now = int(time.time())
    row = registry.get_certificate(serial)
    if not row:
        registry.audit("CERT_REVOKE_DENIED", None, "certificate serial not found", now)
        raise SystemExit("Certificate serial not found")
    if not registry.revoke_certificate(serial, now):
        registry.audit("CERT_REVOKE_DENIED", row["router_id"], "certificate is not active", now)
        raise SystemExit("Certificate is not active")
    registry.audit("CERT_REVOKED", row["router_id"], f"serial={row['serial_number']}", now)
    print(f"Revoked certificate {row['serial_number']} for router {row['router_id']}")


def revoke_router(config_path: str, router_id: str):
    settings = Settings.load(config_path)
    registry = Registry(settings.database_path)
    now = int(time.time())
    if not registry.revoke_router(router_id, now):
        registry.audit("ROUTER_REVOKE_DENIED", router_id, "router not found or already revoked", now)
        raise SystemExit("Router not found or already revoked")
    registry.audit("ROUTER_REVOKED", router_id, "router and active certificates revoked by administrator", now)
    print(f"Revoked router and active certificates: {router_id}")


def list_routers(config_path: str):
    """Read-only listing of router endpoint/status/usability metadata."""
    settings = Settings.load(config_path)
    registry = Registry(settings.database_path)
    rows = []
    for router in registry.list_routers():
        record = record_for_router(registry, router["router_id"])
        try:
            endpoints = json.loads(router.get("wan_endpoints") or "[]")
            if not isinstance(endpoints, list):
                endpoints = []
        except (ValueError, TypeError):
            endpoints = []
        rows.append({
            "router_id": router["router_id"],
            "wan_endpoints": endpoints,
            "status": record["status"] if record else "UNKNOWN",
            "original_ip_usable": bool(record and record.get("original_ip_usable") is True),
        })
    registry.audit("ROUTERS_LISTED", None, "read-only router metadata listing", int(time.time()))
    print(json.dumps(rows, sort_keys=True, separators=(",", ":")))

def export_directory(config_path: str, output_path: str):
    settings = Settings.load(config_path)
    registry = Registry(settings.database_path)
    identity = _load_or_create_control_identity(settings.control_identity_key)
    bundle = signed_directory_bundle(registry, settings, identity)
    target = __import__("pathlib").Path(output_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(target.suffix + ".tmp")
    tmp.write_text(json.dumps(bundle, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o640)
    os.replace(tmp, target)
    registry.audit("DIRECTORY_EXPORTED", None, "signed directory bundle exported", int(time.time()))
    print(f"Exported signed directory bundle: {target}")


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
    register_parser.add_argument("--rsa-public-key-sha256", default="")
    register_parser.add_argument("--wan-endpoint", action="append", default=None)
    register_parser.add_argument("--gateway-ip", action="append", default=None)
    register_parser.add_argument("--prefix", action="append", default=None)
    revoke_router_parser = subs.add_parser("revoke-router")
    revoke_router_parser.add_argument("router_id")
    update_parser = subs.add_parser("update-router")
    update_parser.add_argument("router_id")
    update_parser.add_argument("--wan-endpoint", action="append", default=None)
    update_parser.add_argument("--gateway-ip", action="append", default=None)
    update_parser.add_argument("--prefix", action="append", default=None)
    update_parser.add_argument("--rsa-public-key-sha256", default=None)
    disable_parser = subs.add_parser("disable-router")
    disable_parser.add_argument("router_id")
    enable_parser = subs.add_parser("enable-router")
    enable_parser.add_argument("router_id")
    subs.add_parser("list-routers")
    export_parser = subs.add_parser("export-directory")
    export_parser.add_argument("--output", default="router-directory.bundle.json")
    revoke = subs.add_parser("revoke-certificate")
    revoke.add_argument("serial_number")
    args = parser.parse_args()
    if args.cmd == "init":
        bootstrap(args.config)
    elif args.cmd == "serve":
        serve(args.config)
    elif args.cmd == "revoke-certificate":
        revoke_certificate(args.config, args.serial_number)
    elif args.cmd == "revoke-router":
        revoke_router(args.config, args.router_id)
    elif args.cmd == "update-router":
        try:
            if args.wan_endpoint is not None:
                validate_wan_endpoints(args.wan_endpoint)
        except (ValueError, TypeError) as exc:
            raise SystemExit(f"Invalid WAN endpoint metadata: {exc}") from exc
        update_router(args.config, args.router_id, args.wan_endpoint, args.gateway_ip, args.prefix,
                      args.rsa_public_key_sha256)
    elif args.cmd == "disable-router":
        set_router_enabled(args.config, args.router_id, False)
    elif args.cmd == "enable-router":
        set_router_enabled(args.config, args.router_id, True)
    elif args.cmd == "list-routers":
        list_routers(args.config)
    elif args.cmd == "export-directory":
        export_directory(args.config, args.output)
    else:
        token = args.token if args.token is not None else open(args.token_file, encoding="utf-8").read().strip()
        register(args.config, args.router_id, token, args.public_key_sha256, args.ipv6, args.mac,
                 args.rsa_public_key_sha256, args.wan_endpoint, args.gateway_ip, args.prefix)


if __name__ == "__main__":
    main()
