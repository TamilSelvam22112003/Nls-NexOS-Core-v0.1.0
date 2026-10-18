import base64
import hashlib
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from nls_nexos_core.directory import sign_payload, verify_signature, record_for_router
from nls_nexos_core.database import Registry
from nls_nexos_core.ca import rdr_ed25519_public_key_b64


def test_signed_directory_payload_round_trip():
    key = ed25519.Ed25519PrivateKey.generate()
    envelope = sign_payload({"router_id": "r1", "record_seq": 3, "status": "ACTIVE"}, key)
    pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    assert verify_signature(envelope, pub)["record_seq"] == 3


def test_directory_payload_tamper_is_rejected():
    key = ed25519.Ed25519PrivateKey.generate()
    envelope = sign_payload({"router_id": "r1", "record_seq": 3}, key)
    pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    envelope["payload"]["record_seq"] = 4
    with pytest.raises(ValueError, match="signature verification failed"):
        verify_signature(envelope, pub)


def test_wrong_directory_signer_is_rejected():
    key = ed25519.Ed25519PrivateKey.generate()
    wrong = ed25519.Ed25519PrivateKey.generate()
    envelope = sign_payload({"router_id": "r1"}, key)
    pub = wrong.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    with pytest.raises(ValueError, match="signature verification failed"):
        verify_signature(envelope, pub)


def test_rdr_ed25519_key_encoding_is_standard_base64_raw_32_bytes():
    key = ed25519.Ed25519PrivateKey.generate()
    expected = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    encoded = rdr_ed25519_public_key_b64(key.public_key())
    assert base64.b64decode(encoded, validate=True) == expected
    assert len(base64.b64decode(encoded, validate=True)) == 32


def _registered_router(tmp_path, router_status="ACTIVE", cert_status="ACTIVE", not_after=None, endpoint="[fd42:100::1]:4790"):
    db = Registry(tmp_path / "rdr.sqlite3")
    now_dt = datetime.now(timezone.utc)
    now = int(now_dt.timestamp())
    identity = ed25519.Ed25519PrivateKey.generate()
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "edge-rdr")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-ca")]))
        .public_key(identity.public_key())
        .serial_number(0xabc123)
        .not_valid_before((now_dt - timedelta(minutes=1)).replace(tzinfo=None))
        .not_valid_after((not_after or (now_dt + timedelta(days=1))).replace(tzinfo=None))
        .sign(ed25519.Ed25519PrivateKey.generate(), algorithm=None)
    )
    cert_der_b64 = base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode("ascii")
    raw_key_b64 = base64.b64encode(identity.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode("ascii")
    with db.connect() as con:
        con.execute("INSERT INTO routers(router_id,registered,status,created_at,updated_at) VALUES(?,1,?,?,?)",
                    ("edge-rdr", router_status, now, now))
    try:
        db.set_directory_fields("edge-rdr", wan_endpoints=[endpoint])
    except ValueError:
        with db.connect() as con:
            con.execute("UPDATE routers SET wan_endpoints=?,original_ip_usable=0 WHERE router_id=?",
                        (__import__("json").dumps([endpoint]), "edge-rdr"))
    db.record_certificate("abc123", "edge-rdr",
                         (now_dt - timedelta(minutes=1)).isoformat(),
                         (not_after or (now_dt + timedelta(days=1))).isoformat(),
                         hashlib.sha256(cert.public_bytes(serialization.Encoding.PEM)).hexdigest(),
                         now, cert_der_b64)
    db.record_enrollment_keys("edge-rdr", raw_key_b64, "RSA-PEM", now)
    if cert_status != "ACTIVE":
        with db.connect() as con:
            con.execute("UPDATE issued_certificates SET status=? WHERE serial_number=?", (cert_status, "abc123"))
    return db


def test_rdr_v2_contains_original_ip_certificate_der_and_spki(tmp_path):
    db = _registered_router(tmp_path)
    record = record_for_router(db, "edge-rdr")
    assert record["rdr_version"] == 2
    assert record["originalIP"] == "fd42:100::1"
    assert record["original_ip_usable"] is True
    cert = x509.load_der_x509_certificate(base64.b64decode(record["certificate_der_b64"], validate=True))
    raw = base64.b64decode(record["ed25519_public_key"], validate=True)
    assert cert.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw) == raw
    spki = serialization.load_der_public_key(base64.b64decode(record["ed25519_public_key_spki_der_b64"], validate=True))
    assert spki.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw) == raw
    assert "valid_until" in record and "expires_at" not in record


@pytest.mark.parametrize(("router_status", "cert_status", "expected"), [
    ("REVOKED", "EXPIRED", "REVOKED"),
    ("DISABLED", "EXPIRED", "DISABLED"),
    ("ACTIVE", "EXPIRED", "EXPIRED"),
    ("ACTIVE", "ACTIVE", "ACTIVE"),
])
def test_rdr_effective_status_precedence(tmp_path, router_status, cert_status, expected):
    db = _registered_router(tmp_path, router_status=router_status, cert_status=cert_status)
    assert record_for_router(db, "edge-rdr")["status"] == expected


def test_invalid_original_ip_endpoint_is_retained_but_unusable(tmp_path):
    db = _registered_router(tmp_path, endpoint="fd42:100::1:4790")
    record = record_for_router(db, "edge-rdr")
    assert record["originalIP"] is None
    assert record["original_ip_usable"] is False



def test_rdr_marks_endpoint_column_mismatch_unusable(tmp_path):
    db = _registered_router(tmp_path)
    with db.connect() as con:
        con.execute("UPDATE routers SET original_ip=? WHERE router_id=?",
                    ("fd42:100::99", "edge-rdr"))
    record = record_for_router(db, "edge-rdr")
    assert record["originalIP"] == "fd42:100::1"
    assert record["original_ip_usable"] is False
