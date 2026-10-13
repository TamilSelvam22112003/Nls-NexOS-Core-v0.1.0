from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import pytest

from nls_nexos_core.bootstrap_envelope import (
    BootstrapEnvelopeError, decrypt_bootstrap, encrypt_bootstrap,
)


def _keys():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def test_bootstrap_encrypts_source_identity_and_round_trips():
    private, public = _keys()
    payload = {"source_ip": "fd42:100::1", "router_id": "router-a", "kind": "enroll"}
    packet = encrypt_bootstrap(payload, public, message_type="router-enroll",
                               outer_destination="fd42:100::2")
    assert b"fd42:100::1" not in packet
    assert decrypt_bootstrap(packet, private, expected_outer_destination="fd42:100::2",
                             expected_message_type="router-enroll") == payload


def test_bootstrap_rejects_wrong_outer_destination():
    private, public = _keys()
    packet = encrypt_bootstrap({"source_ip": "fd42:100::1"}, public,
                               message_type="router-enroll", outer_destination="fd42:100::2")
    with pytest.raises(BootstrapEnvelopeError):
        decrypt_bootstrap(packet, private, expected_outer_destination="fd42:100::3")
