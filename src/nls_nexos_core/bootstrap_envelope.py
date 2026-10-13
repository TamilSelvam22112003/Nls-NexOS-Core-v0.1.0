"""NLS bootstrap privacy envelope v1.

Hybrid encryption for pre-session Router-CA bootstrap messages. RSA-OAEP wraps
only a random AES key; AES-256-GCM encrypts the full JSON payload. The outer
destination remains routable; source IP and registration fields belong inside
the encrypted payload. This module is a primitive and is not a wire-path
integration by itself.
"""
from __future__ import annotations

import base64
import json
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.padding import MGF1
from cryptography.hazmat.primitives import constant_time
import os

VERSION = 1
MAX_PLAINTEXT = 1_048_576


class BootstrapEnvelopeError(ValueError):
    """Invalid or unauthentic NLS bootstrap envelope."""


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _load_public(pem: bytes):
    try:
        key = serialization.load_pem_public_key(pem)
    except (ValueError, TypeError) as exc:
        raise BootstrapEnvelopeError("invalid recipient RSA public key") from exc
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size < 2048:
        raise BootstrapEnvelopeError("recipient key must be RSA-2048 or stronger")
    return key


def _load_private(pem: bytes, password: bytes | None):
    try:
        key = serialization.load_pem_private_key(pem, password=password)
    except (ValueError, TypeError) as exc:
        raise BootstrapEnvelopeError("invalid recipient RSA private key") from exc
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 2048:
        raise BootstrapEnvelopeError("recipient key must be RSA-2048 or stronger")
    return key


def encrypt_bootstrap(payload: dict[str, Any], recipient_public_pem: bytes,
                      *, message_type: str, outer_destination: str) -> bytes:
    """Encrypt a bootstrap payload to a pre-pinned Router-CA/router RSA key.

    Put source IP, router ID, CSR, and enrollment metadata in payload. Do not
    place sensitive source identity in an unencrypted outer header.
    """
    if not message_type or len(message_type) > 64 or not outer_destination or len(outer_destination) > 128:
        raise BootstrapEnvelopeError("invalid message type or outer destination")
    plaintext = _canonical(payload)
    if len(plaintext) > MAX_PLAINTEXT:
        raise BootstrapEnvelopeError("bootstrap payload exceeds maximum size")
    recipient = _load_public(recipient_public_pem)
    content_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    aad_obj = {"version": VERSION, "message_type": message_type, "outer_destination": outer_destination}
    aad = _canonical(aad_obj)
    ciphertext = AESGCM(content_key).encrypt(nonce, plaintext, aad)
    wrapped_key = recipient.encrypt(
        content_key,
        padding.OAEP(mgf=MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=b"NLS-BOOTSTRAP-v1"),
    )
    envelope = {
        **aad_obj,
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "wrapped_key": base64.b64encode(wrapped_key).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }
    return _canonical(envelope)


def decrypt_bootstrap(envelope_bytes: bytes, recipient_private_pem: bytes,
                      *, expected_outer_destination: str,
                      expected_message_type: str | None = None,
                      password: bytes | None = None) -> dict[str, Any]:
    """Authenticate and decrypt an NLS bootstrap envelope."""
    if len(envelope_bytes) > MAX_PLAINTEXT + 8192:
        raise BootstrapEnvelopeError("bootstrap envelope exceeds maximum size")
    try:
        envelope = json.loads(envelope_bytes.decode("ascii"))
        if not isinstance(envelope, dict):
            raise ValueError("not object")
        version = envelope["version"]
        message_type = envelope["message_type"]
        outer_destination = envelope["outer_destination"]
        nonce = base64.b64decode(envelope["nonce"], validate=True)
        wrapped_key = base64.b64decode(envelope["wrapped_key"], validate=True)
        ciphertext = base64.b64decode(envelope["ciphertext"], validate=True)
    except (UnicodeError, ValueError, KeyError, TypeError) as exc:
        raise BootstrapEnvelopeError("malformed bootstrap envelope") from exc
    if version != VERSION or not isinstance(message_type, str):
        raise BootstrapEnvelopeError("unsupported bootstrap envelope version/type")
    if outer_destination != expected_outer_destination:
        raise BootstrapEnvelopeError("outer destination binding mismatch")
    if expected_message_type is not None and message_type != expected_message_type:
        raise BootstrapEnvelopeError("unexpected bootstrap message type")
    if len(nonce) != 12 or len(ciphertext) < 16:
        raise BootstrapEnvelopeError("invalid nonce or ciphertext length")
    recipient = _load_private(recipient_private_pem, password)
    try:
        content_key = recipient.decrypt(
            wrapped_key,
            padding.OAEP(mgf=MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=b"NLS-BOOTSTRAP-v1"),
        )
        if len(content_key) != 32:
            raise BootstrapEnvelopeError("invalid wrapped content key")
        aad = _canonical({"version": version, "message_type": message_type, "outer_destination": outer_destination})
        plaintext = AESGCM(content_key).decrypt(nonce, ciphertext, aad)
        value = json.loads(plaintext.decode("ascii"))
        if not isinstance(value, dict):
            raise BootstrapEnvelopeError("decrypted bootstrap payload must be an object")
        return value
    except (ValueError, InvalidTag) as exc:
        raise BootstrapEnvelopeError("bootstrap authentication/decryption failed") from exc
