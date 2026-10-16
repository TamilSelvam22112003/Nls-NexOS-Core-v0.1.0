import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from nls_nexos_core.directory import sign_payload, verify_signature


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
