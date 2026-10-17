import base64

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from nls_nexos_core.directory import sign_payload, verify_signature
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
