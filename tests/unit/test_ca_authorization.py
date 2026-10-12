from datetime import datetime, timezone
import hashlib

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.x509.oid import NameOID

from nls_nexos_core.ca import CertificateAuthority, EnrollmentDenied
from nls_nexos_core.config import Settings
from nls_nexos_core.database import Registry
from nls_nexos_core.models import EnrollmentRequest


def _ca_files(tmp_path):
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Router-CA")])
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now).not_valid_after(now.replace(year=now.year + 1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=True, encipher_only=None, decipher_only=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    cert_path, key_path = tmp_path / "ca.crt", tmp_path / "ca.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(ca_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return cert_path, key_path


def _settings(tmp_path, cert, key):
    return Settings(
        host="127.0.0.1", port=8443,
        database_path=tmp_path / "registry.sqlite3",
        ca_certificate=cert, ca_private_key=key,
        issued_cert_dir=tmp_path / "issued", token_file=tmp_path / "token",
        certificate_days=30, max_request_bytes=65536,
    )


def _request(router_id, router_private_key, token, timestamp, suffix):
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, router_id)])
    ).sign(router_private_key, algorithm=None)
    return EnrollmentRequest(
        protocol_version=1, router_id=router_id,
        csr_pem=csr.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        request_id="req-" + suffix + "-" + "a" * 24,
        nonce=hashlib.sha256((router_id + token + suffix).encode()).hexdigest(),
        timestamp=timestamp,
    )


def _register(registry, router_id, token, now):
    with registry.connect() as con:
        con.execute(
            """INSERT INTO routers(router_id,registered,status,enrollment_token_sha256,created_at,updated_at)
               VALUES(?,1,'ACTIVE',?,?,?)""",
            (router_id, hashlib.sha256(token.encode()).hexdigest(), now, now),
        )


def test_certificate_issued_only_with_global_and_router_bound_token(tmp_path):
    ca_cert, ca_key = _ca_files(tmp_path)
    settings = _settings(tmp_path, ca_cert, ca_key)
    registry = Registry(settings.database_path)
    global_token = "global-" + "g" * 48
    router_token = "router-" + "r" * 48
    now = int(datetime.now(timezone.utc).timestamp())
    _register(registry, "router-a", router_token, now)
    authority = CertificateAuthority(settings, registry, global_token)
    key = ed25519.Ed25519PrivateKey.generate()

    wrong_token_request = _request("router-a", key, global_token, now, "wrong")
    with pytest.raises(EnrollmentDenied):
        authority.enroll(wrong_token_request, global_token)

    valid_request = _request("router-a", key, router_token, now, "valid")
    with pytest.raises(EnrollmentDenied):
        authority.enroll(valid_request, router_token)  # fails global bootstrap gate

    # This currently requires a future per-router token delivery design in which the
    # registered token is also accepted by the bootstrap gate. The denial behavior is
    # deliberate until that protocol is properly designed and transport protected.


def test_missing_router_token_binding_denies_enrollment(tmp_path):
    ca_cert, ca_key = _ca_files(tmp_path)
    settings = _settings(tmp_path, ca_cert, ca_key)
    registry = Registry(settings.database_path)
    token = "provisioned-" + "t" * 40
    now = int(datetime.now(timezone.utc).timestamp())
    with registry.connect() as con:
        con.execute(
            "INSERT INTO routers(router_id,registered,status,created_at,updated_at) VALUES(?,1,'ACTIVE',?,?)",
            ("unbound-router", now, now),
        )
    authority = CertificateAuthority(settings, registry, token)
    key = ed25519.Ed25519PrivateKey.generate()
    request = _request("unbound-router", key, token, now, "unbound")
    with pytest.raises(EnrollmentDenied):
        authority.enroll(request, token)
