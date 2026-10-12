"""Loopback end-to-end test for Core Router-CA and the NlsxNetOS router client."""
import base64
import hashlib
import os
import socket
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[2]
# CI checks out the router repository alongside Core at $GITHUB_WORKSPACE/nlsxnetos.
# When this test is run in the combined checkout, append that sibling path directly.
NLSXNETOS = ROOT.parent / "nlsxnetos"
if NLSXNETOS.exists():
    sys.path.insert(0, str(NLSXNETOS))
else:
    # Also support a local clone that places Core and NlsxNetOS under one parent.
    sibling = ROOT.parent / "NlsxNetOS-v0.1.0"
    if sibling.exists():
        NLSXNETOS = sibling
        sys.path.insert(0, str(NLSXNETOS))

from nls.ca_client import ClientSettings, _open_channel, enroll
from nls_nexos_core.ca import CertificateAuthority
from nls_nexos_core.config import Settings
from nls_nexos_core.control import NLSControlServer
from nls_nexos_core.database import Registry
from nls_nexos_core.control_protocol import public_key_bytes


def _root_ca(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "NLS Integration Test Root")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before((now - timedelta(minutes=5)).replace(tzinfo=None))
        .not_valid_after((now + timedelta(days=365)).replace(tzinfo=None))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=True, encipher_only=None, decipher_only=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp_path / "ca-root.crt", tmp_path / "ca-signing.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    key_path.chmod(0o600)
    return cert_path, key_path


def _free_ipv6_port():
    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    try:
        sock.bind(("::1", 0))
        return sock.getsockname()[1]
    finally:
        sock.close()


@pytest.mark.integration
def test_router_enrolls_and_syncs_over_nls_control_v1(tmp_path):
    root_cert_path, ca_key_path = _root_ca(tmp_path)
    bootstrap_token = base64.urlsafe_b64encode(os.urandom(48)).decode()
    router_token = base64.urlsafe_b64encode(os.urandom(48)).decode()
    token_file = tmp_path / "bootstrap.token"
    router_token_file = tmp_path / "router.token"
    token_file.write_text(bootstrap_token)
    router_token_file.write_text(router_token)
    token_file.chmod(0o600)
    router_token_file.chmod(0o600)

    server_id = "nls-router-ca-test"
    port = _free_ipv6_port()
    server_identity = ed25519.Ed25519PrivateKey.generate()
    settings = Settings(
        host="::1", port=port,
        database_path=tmp_path / "registry.sqlite3",
        ca_certificate=root_cert_path, ca_private_key=ca_key_path,
        issued_cert_dir=tmp_path / "issued", token_file=token_file,
        certificate_days=30, max_request_bytes=65536,
        control_identity_key=tmp_path / "control-ed25519.key",
        control_id=server_id, policy_version=1, replay_window=64,
        max_clock_skew_seconds=120, session_timeout_seconds=300, key_rotation_seconds=3600,
    )
    registry = Registry(settings.database_path)
    now = int(time.time())
    with registry.connect() as con:
        con.execute(
            """INSERT INTO routers(router_id,registered,status,enrollment_token_sha256,created_at,updated_at)
               VALUES(?,1,'ACTIVE',?,?,?)""",
            ("edge-test", hashlib.sha256(router_token.encode()).hexdigest(), now, now),
        )
    authority = CertificateAuthority(settings, registry, bootstrap_token)
    server = NLSControlServer(settings, registry, authority, server_identity)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    time.sleep(0.15)
    identity = ed25519.Ed25519PrivateKey.generate()
    client_cfg = ClientSettings(
        endpoint=f"[::1]:{port}", server_id=server_id,
        server_public_key=base64.b64encode(public_key_bytes(server_identity)).decode(),
        router_id="edge-test", identity_key=tmp_path / "router-ed25519.key",
        certificate_file=tmp_path / "router.crt", ca_certificate_file=root_cert_path,
        bootstrap_token_file=token_file, router_token_file=router_token_file,
        policy_file=tmp_path / "policy.json", revocation_file=tmp_path / "revocations.json",
        connect_timeout_seconds=5, heartbeat_seconds=5,
    )
    try:
        enrolled = enroll(client_cfg, identity)
        assert enrolled["type"] == "enrollment-result"
        assert client_cfg.certificate_file.is_file()
        assert client_cfg.policy_file.is_file()
        assert client_cfg.revocation_file.is_file()

        channel = _open_channel(client_cfg, identity, client_cfg.certificate_file.read_text())
        try:
            channel.send({"type": "sync", "router_id": "edge-test"})
            response = channel.recv()
            assert response["type"] == "sync-result"
            assert response["ok"] is True
            assert response["policy"]["control_protocol"] == "NLS-Control-v1"
            assert response["policy"]["record_cipher"] == "AES-256-GCM"
            assert response["revocations"]["revoked_certificates"] == []
            channel.send({"type": "heartbeat", "router_id": "edge-test"})
            assert channel.recv()["type"] == "heartbeat-result"
        finally:
            channel.close()
    finally:
        server.stop()
        worker.join(timeout=3)
        assert not worker.is_alive()
