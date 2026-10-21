"""Attack-path regression tests for the NLS Router-CA control record channel."""
import socket

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nls_nexos_core.control_protocol import (
    DATA,
    NLSControlError,
    _recv_protected,
    _send_protected,
    b64,
    public_key_bytes,
    read_frame,
    sign_object,
    verify_object,
    write_frame,
)


def test_control_record_ciphertext_tampering_fails_authentication():
    key = b"K" * 32
    prefix = b"SRVR"
    sender, receiver = socket.socketpair()
    tamper_sender, tamper_receiver = socket.socketpair()
    try:
        _send_protected(sender, DATA, key, prefix, 1, {"operation": "lookup"})
        kind, body = read_frame(receiver)
        changed = bytearray(body)
        changed[-1] ^= 1
        write_frame(tamper_sender, kind, bytes(changed))

        with pytest.raises(NLSControlError, match="authentication failed"):
            _recv_protected(tamper_receiver, DATA, key, prefix, 1)
    finally:
        sender.close()
        receiver.close()
        tamper_sender.close()
        tamper_receiver.close()


def test_control_record_rejects_replayed_record():
    """A record accepted at sequence 1 must be rejected when replayed at sequence 2."""
    key = b"K" * 32
    prefix = b"CLNT"
    sender, receiver = socket.socketpair()
    try:
        _send_protected(sender, DATA, key, prefix, 1, {"operation": "lookup"})
        kind, body = read_frame(receiver)

        # Deliver the captured record to a fresh receiving socket once.
        replay_sender, replay_receiver = socket.socketpair()
        try:
            write_frame(replay_sender, kind, body)
            assert _recv_protected(replay_receiver, DATA, key, prefix, 1) == {
                "operation": "lookup"
            }

            # Replaying the exact same authenticated frame must not satisfy seq=2.
            write_frame(replay_sender, kind, body)
            with pytest.raises(NLSControlError, match="replay or sequence gap"):
                _recv_protected(replay_receiver, DATA, key, prefix, 2)
        finally:
            replay_sender.close()
            replay_receiver.close()
    finally:
        sender.close()
        receiver.close()


def test_control_handshake_signature_binds_identity_fields():
    identity = Ed25519PrivateKey.generate()
    signed = sign_object(
        {"router_id": "router-a", "identity_public_key": b64(public_key_bytes(identity))},
        1,
        identity,
    )
    signed["router_id"] = "router-victim"

    with pytest.raises(NLSControlError, match="signature invalid"):
        verify_object(signed, 1, public_key_bytes(identity))


def test_control_frame_rejects_invalid_magic():
    sender, receiver = socket.socketpair()
    try:
        sender.sendall(b"NOPE" + bytes([1, DATA]) + (0).to_bytes(4, "big"))
        with pytest.raises(NLSControlError, match="invalid NLS control frame header"):
            read_frame(receiver)
    finally:
        sender.close()
        receiver.close()
