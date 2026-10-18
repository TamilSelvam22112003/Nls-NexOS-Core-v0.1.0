"""Signed Router Directory Records (RDRs) and offline directory bundles."""
from __future__ import annotations

import base64
import json
import time
from datetime import datetime, timezone

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .database import original_ip_from_endpoints


DOMAIN = b"NLS-DIR-v1"


def _canonical(payload: dict) -> bytes:
    return cbor2.dumps(payload, canonical=True)


def sign_payload(payload: dict, private_key: Ed25519PrivateKey) -> dict:
    signer = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return {
        "payload": payload,
        "signer_public_key": base64.b64encode(signer).decode("ascii"),
        "signature": base64.b64encode(private_key.sign(DOMAIN + _canonical(payload))).decode("ascii"),
        "encoding": "canonical-cbor",
        "domain": "NLS-DIR-v1",
    }


def record_for_router(registry, router_id: str, now: int | None = None, validity_seconds: int = 30) -> dict | None:
    now = int(time.time()) if now is None else int(now)
    router = registry.get_router(router_id)
    if not router:
        return None
    with registry.connect() as con:
        cert = con.execute(
            "SELECT * FROM issued_certificates WHERE router_id=? ORDER BY created_at DESC LIMIT 1",
            (router_id,),
        ).fetchone()
    router_status = router["status"]
    serial = None
    not_after = now
    if cert:
        serial = cert["serial_number"]
        try:
            not_after_dt = datetime.fromisoformat(cert["not_after"].replace("Z", "+00:00"))
            if not_after_dt.tzinfo is None:
                not_after_dt = not_after_dt.replace(tzinfo=timezone.utc)
            not_after = int(not_after_dt.timestamp())
        except (ValueError, TypeError):
            not_after = now
        cert_status = cert["status"]
    else:
        cert_status = "EXPIRED"

    # Explicit precedence: REVOKED > DISABLED > EXPIRED > ACTIVE.
    if router_status == "REVOKED" or cert_status == "REVOKED":
        status = "REVOKED"
    elif router_status == "DISABLED":
        status = "DISABLED"
    elif cert_status == "EXPIRED" or not_after <= now or not cert:
        status = "EXPIRED"
    elif router_status == "ACTIVE" and cert_status == "ACTIVE":
        status = "ACTIVE"
    else:
        status = "DISABLED"

    def decode_list(name):
        try:
            value = json.loads(router.get(name) or "[]")
            return value if isinstance(value, list) else []
        except (ValueError, TypeError):
            return []

    wan_endpoints = decode_list("wan_endpoints")
    try:
        original_ip = original_ip_from_endpoints(wan_endpoints)
    except (ValueError, TypeError):
        original_ip = None

    spki_der_b64 = None
    identity_matches_certificate = False
    certificate_der_b64 = cert.get("certificate_der_b64") if cert else None
    try:
        raw_key = base64.b64decode(router.get("ed25519_public_key") or "", validate=True)
        if len(raw_key) != 32:
            raise ValueError("raw Ed25519 public key must be 32 bytes")
        ed_key = Ed25519PublicKey.from_public_bytes(raw_key)
        spki_der = ed_key.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        spki_der_b64 = base64.b64encode(spki_der).decode("ascii")
        cert_der = base64.b64decode(certificate_der_b64 or "", validate=True)
        issued_cert = x509.load_der_x509_certificate(cert_der)
        cert_key = issued_cert.public_key()
        cert_raw = cert_key.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        ) if isinstance(cert_key, Ed25519PublicKey) else b""
        identity_matches_certificate = (
            cert_raw == raw_key and
            format(issued_cert.serial_number, "x").lower() ==
            str(serial or "").lower().removeprefix("0x")
        )
    except (ValueError, TypeError):
        identity_matches_certificate = False

    original_ip_usable = bool(original_ip and identity_matches_certificate and router.get("original_ip_usable"))
    record_valid_until = now + min(max(int(validity_seconds), 1), 600)
    if status == "ACTIVE":
        record_valid_until = min(record_valid_until, not_after)
    return {
        "rdr_version": 2,
        "router_id": router_id,
        "ed25519_public_key": router.get("ed25519_public_key"),
        "ed25519_public_key_spki_der_b64": spki_der_b64,
        "rsa_encryption_public_key": router.get("rsa_encryption_public_key"),
        "certificate_der_b64": certificate_der_b64,
        "originalIP": original_ip,
        "original_ip_usable": original_ip_usable,
        "wan_endpoints": wan_endpoints,
        "gateway_ips": decode_list("gateway_ips"),
        "prefixes": decode_list("prefixes"),
        "certificate_serial": serial,
        "status": status,
        "record_seq": int(router.get("record_seq") or 1),
        "issued_at": now,
        "valid_until": record_valid_until,
    }


def signed_rdr(registry, router_id: str, private_key: Ed25519PrivateKey,
               now: int | None = None, client_nonce: str | None = None):
    effective_now = int(time.time()) if now is None else int(now)
    registry.expire_certificates(effective_now)
    record = record_for_router(registry, router_id, effective_now)
    if record is None:
        return None
    if client_nonce is not None:
        record["client_nonce"] = client_nonce
    return sign_payload(record, private_key)


def signed_directory_bundle(registry, settings, private_key: Ed25519PrivateKey,
                            expires_seconds: int = 600, now: int | None = None) -> dict:
    now = int(time.time()) if now is None else int(now)
    registry.expire_certificates(now)
    records = []
    for router in registry.list_routers():
        record = record_for_router(registry, router["router_id"], now, validity_seconds=600)
        if record is not None:
            records.append(sign_payload(record, private_key))
    with registry.connect() as con:
        revoked = [dict(row) for row in con.execute(
            "SELECT serial_number,router_id,revoked_at FROM issued_certificates "
            "WHERE status='REVOKED' ORDER BY serial_number"
        )]
    payload = {
        "bundle_version": 1,
        "directory_seq": registry.directory_seq(),
        "issued_at": now,
        "expires_at": now + min(max(int(expires_seconds), 1), 600),
        "records": records,
        "revoked_serials": [str(item["serial_number"]) for item in revoked],
        "policy": {
            "allowed_suites": ["X25519-HKDF-SHA256-AES-256-GCM-Ed25519-RSA-OAEP-SHA256"],
            "minimum_nls_version": 1,
            "replay_window": int(settings.replay_window),
            "handshake_timeout_seconds": 5,
            "lookup_validity_seconds": 30,
        },
    }
    return sign_payload(payload, private_key)


def status_record(registry, router_id: str, now: int | None = None) -> str:
    record = record_for_router(registry, router_id, now)
    return str(record["status"]) if record else "UNKNOWN"


def verify_signature(envelope: dict, expected_public_key: bytes) -> dict:
    try:
        if envelope.get("encoding") != "canonical-cbor" or envelope.get("domain") != "NLS-DIR-v1":
            raise ValueError("unsupported directory signature envelope")
        signer = base64.b64decode(envelope["signer_public_key"], validate=True)
        signature = base64.b64decode(envelope["signature"], validate=True)
        if signer != expected_public_key:
            raise ValueError("directory signer does not match pinned control identity")
        payload = envelope["payload"]
        if not isinstance(payload, dict):
            raise ValueError("directory payload must be a mapping")
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        Ed25519PublicKey.from_public_bytes(signer).verify(signature, DOMAIN + _canonical(payload))
        return payload
    except (KeyError, TypeError, ValueError, InvalidSignature) as exc:
        raise ValueError("Router-CA directory signature verification failed") from exc
