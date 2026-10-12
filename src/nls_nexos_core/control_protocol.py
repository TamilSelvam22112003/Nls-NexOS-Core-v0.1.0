"""Experimental NLS Control Record Protocol v1.

Wire format: NLSC | version:u8 | kind:u8 | payload_length:u32 | payload.
Handshake identity is Ed25519-signed; ephemeral X25519 + HKDF-SHA256 derives
independent AES-256-GCM keys. Record nonces are direction-specific prefixes and
strict monotonic 64-bit sequence numbers. This is not TLS and needs independent
protocol review before production use.
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
import socket
import time
from dataclasses import dataclass
from typing import Callable

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC = b"NLSC"
VERSION = 1
CLIENT_HELLO = 1
SERVER_HELLO = 2
CLIENT_FINISHED = 3
SERVER_FINISHED = 4
DATA = 5
CLOSE = 6
HEADER_SIZE = 10
MAX_FRAME = 1_048_576
MAX_CLOCK_SKEW_SECONDS = 120
KDF_INFO = b"NLS-Control-v1|X25519|HKDF-SHA256|AES-256-GCM"


class NLSControlError(ValueError):
    """Protocol or peer-authentication error."""


def canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def unb64(value: str, expected_len: int | None = None) -> bytes:
    if not isinstance(value, str):
        raise NLSControlError("binary field must be a base64 string")
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
    except (ValueError, UnicodeError) as exc:
        raise NLSControlError("invalid base64 field") from exc
    if expected_len is not None and len(raw) != expected_len:
        raise NLSControlError("invalid binary field length")
    return raw


def public_key_bytes(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def signing_bytes(kind: int, obj: dict) -> bytes:
    unsigned = dict(obj)
    unsigned.pop("signature", None)
    return b"NLS-CONTROL-v1|" + bytes([kind]) + b"|" + canonical(unsigned)


def sign_object(obj: dict, kind: int, private_key: Ed25519PrivateKey) -> dict:
    out = dict(obj)
    out["signature"] = b64(private_key.sign(signing_bytes(kind, out)))
    return out


def verify_object(obj: dict, kind: int, expected_public_key: bytes | None = None) -> bytes:
    try:
        pub_raw = unb64(obj["identity_public_key"], 32)
        if expected_public_key is not None and pub_raw != expected_public_key:
            raise NLSControlError("pinned NLS control identity mismatch")
        public_key = Ed25519PublicKey.from_public_bytes(pub_raw)
        public_key.verify(unb64(obj["signature"], 64), signing_bytes(kind, obj))
        return pub_raw
    except NLSControlError:
        raise
    except (KeyError, ValueError, TypeError, InvalidSignature) as exc:
        raise NLSControlError("NLS control handshake signature invalid") from exc


def _read_exact(sock: socket.socket, count: int) -> bytes:
    chunks = []
    remaining = count
    while remaining:
        block = sock.recv(remaining)
        if not block:
            raise EOFError("peer closed NLS control connection")
        chunks.append(block)
        remaining -= len(block)
    return b"".join(chunks)


def write_frame(sock: socket.socket, kind: int, body: bytes) -> None:
    if not 0 <= kind <= 255:
        raise NLSControlError("invalid NLS control frame type")
    if len(body) > MAX_FRAME:
        raise NLSControlError("NLS control frame exceeds maximum size")
    header = MAGIC + bytes([VERSION, kind]) + len(body).to_bytes(4, "big")
    sock.sendall(header + body)


def read_frame(sock: socket.socket) -> tuple[int, bytes]:
    header = _read_exact(sock, HEADER_SIZE)
    if header[:4] != MAGIC or header[4] != VERSION:
        raise NLSControlError("invalid NLS control frame header")
    length = int.from_bytes(header[6:10], "big")
    if length > MAX_FRAME:
        raise NLSControlError("NLS control frame exceeds maximum size")
    return header[5], _read_exact(sock, length)


def _write_json(sock: socket.socket, kind: int, value: dict) -> None:
    write_frame(sock, kind, canonical(value))


def _read_json(sock: socket.socket, expected_kind: int) -> dict:
    kind, body = read_frame(sock)
    if kind != expected_kind:
        raise NLSControlError("unexpected NLS control handshake message")
    try:
        value = json.loads(body.decode("ascii"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise NLSControlError("invalid NLS control JSON") from exc
    if not isinstance(value, dict):
        raise NLSControlError("NLS control message must be a JSON object")
    return value


def _check_timestamp(value: object, skew: int = MAX_CLOCK_SKEW_SECONDS) -> None:
    if type(value) is not int or abs(int(time.time()) - value) > skew:
        raise NLSControlError("NLS control handshake timestamp outside permitted window")


def _derive_keys(ephemeral_private: X25519PrivateKey, peer_ephemeral: str,
                 client_hello: dict, server_hello: dict) -> tuple[bytes, bytes, bytes]:
    try:
        peer = X25519PublicKey.from_public_bytes(unb64(peer_ephemeral, 32))
        shared = ephemeral_private.exchange(peer)
    except (ValueError, TypeError) as exc:
        raise NLSControlError("invalid NLS control X25519 public key") from exc
    transcript = hashlib.sha256(canonical(client_hello) + canonical(server_hello)).digest()
    material = HKDF(algorithm=hashes.SHA256(), length=64, salt=transcript, info=KDF_INFO).derive(shared)
    return material[:32], material[32:], transcript


def _nonce(prefix: bytes, sequence: int) -> bytes:
    if len(prefix) != 4 or not 0 <= sequence < 2**64:
        raise NLSControlError("invalid NLS control nonce or sequence")
    return prefix + sequence.to_bytes(8, "big")


def _send_protected(sock: socket.socket, kind: int, key: bytes, prefix: bytes,
                    sequence: int, message: dict) -> None:
    seq = sequence.to_bytes(8, "big")
    aad = MAGIC + bytes([VERSION, kind]) + seq
    ciphertext = AESGCM(key).encrypt(_nonce(prefix, sequence), canonical(message), aad)
    write_frame(sock, kind, seq + ciphertext)


def _recv_protected(sock: socket.socket, expected_kind: int, key: bytes,
                    prefix: bytes, expected_sequence: int) -> dict:
    kind, body = read_frame(sock)
    if kind != expected_kind or len(body) < 8 + 16:
        raise NLSControlError("invalid protected NLS control record")
    seq_raw, ciphertext = body[:8], body[8:]
    sequence = int.from_bytes(seq_raw, "big")
    if sequence != expected_sequence:
        raise NLSControlError("NLS control record replay or sequence gap")
    aad = MAGIC + bytes([VERSION, kind]) + seq_raw
    try:
        plaintext = AESGCM(key).decrypt(_nonce(prefix, sequence), ciphertext, aad)
        message = json.loads(plaintext.decode("ascii"))
    except (InvalidTag, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise NLSControlError("NLS control record authentication failed") from exc
    if not isinstance(message, dict):
        raise NLSControlError("NLS control record must contain a JSON object")
    return message


@dataclass
class NLSControlRecordChannel:
    sock: socket.socket
    send_key: bytes
    recv_key: bytes
    send_prefix: bytes
    recv_prefix: bytes
    send_sequence: int = 1
    recv_sequence: int = 1

    def send(self, message: dict) -> None:
        _send_protected(self.sock, DATA, self.send_key, self.send_prefix, self.send_sequence, message)
        self.send_sequence += 1

    def recv(self) -> dict:
        message = _recv_protected(self.sock, DATA, self.recv_key, self.recv_prefix, self.recv_sequence)
        self.recv_sequence += 1
        return message

    def close(self) -> None:
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()


def client_handshake(sock: socket.socket, identity_key: Ed25519PrivateKey,
                     router_id: str, pinned_server_public_key: str, expected_server_id: str,
                     certificate_pem: str | None = None,
                     max_clock_skew_seconds: int = MAX_CLOCK_SKEW_SECONDS) -> NLSControlRecordChannel:
    """Authenticate a pinned Router-CA control identity and establish record keys."""
    try:
        server_pin = unb64(pinned_server_public_key, 32)
    except NLSControlError as exc:
        raise NLSControlError("Router-CA control public key is not configured correctly") from exc
    ephemeral = X25519PrivateKey.generate()
    client_hello = sign_object({
        "protocol_version": VERSION,
        "router_id": router_id,
        "identity_public_key": b64(public_key_bytes(identity_key)),
        "ephemeral_public_key": b64(ephemeral.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)),
        "nonce": b64(secrets.token_bytes(32)),
        "timestamp": int(time.time()),
        "certificate_pem": certificate_pem,
    }, CLIENT_HELLO, identity_key)
    _write_json(sock, CLIENT_HELLO, client_hello)
    server_hello = _read_json(sock, SERVER_HELLO)
    if server_hello.get("protocol_version") != VERSION or server_hello.get("control_id") != expected_server_id:
        raise NLSControlError("unexpected Router-CA control identity or protocol version")
    _check_timestamp(server_hello.get("timestamp"), max_clock_skew_seconds)
    if server_hello.get("client_hello_sha256") != hashlib.sha256(canonical(client_hello)).hexdigest():
        raise NLSControlError("NLS control handshake transcript mismatch")
    server_key = verify_object(server_hello, SERVER_HELLO, server_pin)
    if bool(server_hello.get("client_authenticated")) != bool(certificate_pem):
        raise NLSControlError("NLS control client-certificate state mismatch")
    c2s, s2c, transcript = _derive_keys(
        ephemeral, str(server_hello.get("ephemeral_public_key", "")), client_hello, server_hello)
    transcript_hex = transcript.hex()
    _send_protected(sock, CLIENT_FINISHED, c2s, b"CLNT", 0,
                    {"type": "client_finished", "transcript_sha256": transcript_hex})
    finished = _recv_protected(sock, SERVER_FINISHED, s2c, b"SRVR", 0)
    if finished != {"type": "server_finished", "transcript_sha256": transcript_hex}:
        raise NLSControlError("NLS control server key confirmation failed")
    return NLSControlRecordChannel(sock, c2s, s2c, b"CLNT", b"SRVR", 1, 1)


def server_handshake(sock: socket.socket, identity_key: Ed25519PrivateKey, control_id: str,
                     authorize_client: Callable[[dict], dict | None] | None = None,
                     nonce_guard: Callable[[str], bool] | None = None,
                     max_clock_skew_seconds: int = MAX_CLOCK_SKEW_SECONDS):
    """Verify the router's signed hello and optionally its Router-CA-issued certificate."""
    client_hello = _read_json(sock, CLIENT_HELLO)
    if client_hello.get("protocol_version") != VERSION:
        raise NLSControlError("unsupported NLS control protocol version")
    router_id = client_hello.get("router_id")
    if not isinstance(router_id, str) or not router_id or len(router_id) > 128:
        raise NLSControlError("invalid router identity")
    _check_timestamp(client_hello.get("timestamp"), max_clock_skew_seconds)
    client_identity = verify_object(client_hello, CLIENT_HELLO)
    nonce = str(client_hello.get("nonce", ""))
    unb64(nonce, 32)
    if nonce_guard is not None and not nonce_guard(nonce):
        raise NLSControlError("NLS control handshake replay detected")
    certificate_pem = client_hello.get("certificate_pem")
    auth = None
    if certificate_pem is not None:
        if not isinstance(certificate_pem, str) or not certificate_pem:
            raise NLSControlError("invalid router certificate field")
        if authorize_client is None:
            raise NLSControlError("router certificate authentication is not configured")
        auth = authorize_client(client_hello)
        if not auth:
            raise NLSControlError("router certificate rejected")
    ephemeral = X25519PrivateKey.generate()
    server_hello = sign_object({
        "protocol_version": VERSION,
        "control_id": control_id,
        "identity_public_key": b64(public_key_bytes(identity_key)),
        "ephemeral_public_key": b64(ephemeral.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)),
        "nonce": b64(secrets.token_bytes(32)),
        "timestamp": int(time.time()),
        "client_hello_sha256": hashlib.sha256(canonical(client_hello)).hexdigest(),
        "client_authenticated": bool(auth),
    }, SERVER_HELLO, identity_key)
    _write_json(sock, SERVER_HELLO, server_hello)
    c2s, s2c, transcript = _derive_keys(
        ephemeral, str(client_hello.get("ephemeral_public_key", "")), client_hello, server_hello)
    transcript_hex = transcript.hex()
    finished = _recv_protected(sock, CLIENT_FINISHED, c2s, b"CLNT", 0)
    if finished != {"type": "client_finished", "transcript_sha256": transcript_hex}:
        raise NLSControlError("NLS control client key confirmation failed")
    _send_protected(sock, SERVER_FINISHED, s2c, b"SRVR", 0,
                    {"type": "server_finished", "transcript_sha256": transcript_hex})
    channel = NLSControlRecordChannel(sock, s2c, c2s, b"SRVR", b"CLNT", 1, 1)
    return channel, client_hello, auth
