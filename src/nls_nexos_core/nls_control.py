from __future__ import annotations

import hashlib
import json
import secrets
import struct
import time
from dataclasses import dataclass
from typing import Any, Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC = b'NLSC'
VERSION = 1
MAX_FRAME = 1 << 20
FRAME_HEADER = struct.Struct('!4sBBI')
RECORD_HEADER = struct.Struct('!4sB B 16s Q I')
INFO = b'NLS-NexOS-Core-control-v1'

def canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')

def b64(data: bytes) -> str:
    import base64
    return base64.b64encode(data).decode('ascii')

def unb64(value: str) -> bytes:
    import base64
    return base64.b64decode(value.encode('ascii'), validate=True)

def raw_public(key) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

def encode_frame(kind: int, body: bytes) -> bytes:
    if not 1 <= kind <= 255 or len(body) > MAX_FRAME:
        raise ValueError('invalid NLS control frame type/length')
    return FRAME_HEADER.pack(MAGIC, VERSION, kind, len(body)) + body

def decode_frame(frame: bytes) -> tuple[int, bytes]:
    if len(frame) < FRAME_HEADER.size:
        raise ValueError('truncated NLS control frame')
    magic, version, kind, size = FRAME_HEADER.unpack(frame[:FRAME_HEADER.size])
    if magic != MAGIC or version != VERSION or kind == 0 or size > MAX_FRAME or len(frame) != FRAME_HEADER.size + size:
        raise ValueError('invalid NLS control frame')
    return kind, frame[FRAME_HEADER.size:]

def signing_bytes(label: bytes, value: dict[str, Any]) -> bytes:
    unsigned = dict(value)
    unsigned.pop('signature', None)
    return b'NLS-CONTROL-V1\x00' + label + b'\x00' + canonical(unsigned)

def verify_signature(public_key_raw: bytes, label: bytes, value: dict[str, Any]) -> None:
    if len(public_key_raw) != 32:
        raise ValueError('NLS control Ed25519 public key must be 32 bytes')
    try:
        Ed25519PublicKey.from_public_bytes(public_key_raw).verify(unb64(str(value['signature'])), signing_bytes(label, value))
    except (KeyError, ValueError, TypeError, InvalidSignature) as exc:
        raise ValueError('NLS control peer signature verification failed') from exc

@dataclass(frozen=True)
class ControlKeys:
    send_key: bytes
    receive_key: bytes
    session_id: bytes

@dataclass
class PendingHandshake:
    ephemeral_private: X25519PrivateKey
    session_id: bytes
    nonce: bytes
    client_id: str
    server_id: str
    client_public: bytes
    pinned_server_public: bytes
    init_body: dict[str, Any]

def new_client_hello(*, client_id: str, server_id: str, signing_key: Ed25519PrivateKey,
                     pinned_server_public: bytes, now: int | None = None) -> tuple[dict[str, Any], PendingHandshake]:
    if not client_id or not server_id or len(pinned_server_public) != 32:
        raise ValueError('invalid NLS control identity configuration')
    now = int(time.time()) if now is None else int(now)
    eph = X25519PrivateKey.generate()
    client_public = raw_public(signing_key.public_key())
    body: dict[str, Any] = {
        'protocol_version': VERSION, 'client_id': client_id, 'server_id': server_id,
        'client_signing_key': b64(client_public),
        'server_key_sha256': hashlib.sha256(pinned_server_public).hexdigest(),
        'client_ephemeral': b64(raw_public(eph.public_key())),
        'session_id': secrets.token_hex(16), 'nonce': b64(secrets.token_bytes(32)), 'timestamp': now,
    }
    body['signature'] = b64(signing_key.sign(signing_bytes(b'CHLO', body)))
    pending = PendingHandshake(eph, bytes.fromhex(body['session_id']), unb64(body['nonce']),
        client_id, server_id, client_public, pinned_server_public, dict(body))
    return body, pending

def _derive(shared: bytes, session_id: bytes, client_nonce: bytes, server_nonce: bytes, transcript_hash: bytes) -> bytes:
    salt = hashlib.sha256(b'NLS-CTRL-TRANSCRIPT\x00' + transcript_hash + session_id + client_nonce + server_nonce).digest()
    return HKDF(algorithm=hashes.SHA256(), length=64, salt=salt, info=INFO).derive(shared)

def accept_client_hello(*, body: dict[str, Any], server_id: str, signing_key: Ed25519PrivateKey,
                        authorize_client: Callable[[str, bytes], bool], now: int | None = None,
                        max_clock_skew: int = 120) -> tuple[dict[str, Any], ControlKeys]:
    now = int(time.time()) if now is None else int(now)
    try:
        client_id = str(body['client_id'])
        session_id = bytes.fromhex(str(body['session_id']))
        timestamp = int(body['timestamp'])
        client_nonce = unb64(str(body['nonce']))
        client_public = unb64(str(body['client_signing_key']))
        client_ephemeral = X25519PublicKey.from_public_bytes(unb64(str(body['client_ephemeral'])))
    except (KeyError, ValueError, TypeError) as exc:
        raise ValueError('malformed NLS client hello') from exc
    if body.get('protocol_version') != VERSION or body.get('server_id') != server_id:
        raise ValueError('NLS control protocol/server identity mismatch')
    if abs(now - timestamp) > max_clock_skew or len(session_id) != 16 or len(client_nonce) != 32:
        raise ValueError('NLS control hello freshness/nonce check failed')
    server_public = raw_public(signing_key.public_key())
    if body.get('server_key_sha256') != hashlib.sha256(server_public).hexdigest():
        raise ValueError('client expected a different Router-CA identity')
    verify_signature(client_public, b'CHLO', body)
    if not authorize_client(client_id, client_public):
        raise ValueError('client identity is not authorized by Router-CA registry')
    server_eph = X25519PrivateKey.generate()
    shared = server_eph.exchange(client_ephemeral)
    if not any(shared):
        raise ValueError('invalid X25519 shared secret')
    server_nonce = secrets.token_bytes(32)
    transcript_hash = hashlib.sha256(canonical(body)).digest()
    material = _derive(shared, session_id, client_nonce, server_nonce, transcript_hash)
    response: dict[str, Any] = {
        'protocol_version': VERSION, 'server_id': server_id, 'client_id': client_id,
        'server_signing_key': b64(server_public), 'server_ephemeral': b64(raw_public(server_eph.public_key())),
        'session_id': session_id.hex(), 'client_nonce': b64(client_nonce), 'server_nonce': b64(server_nonce),
        'client_hello_sha256': transcript_hash.hex(), 'timestamp': now,
    }
    response['signature'] = b64(signing_key.sign(signing_bytes(b'SHLO', response)))
    return response, ControlKeys(material[32:], material[:32], session_id)

def finish_client_handshake(pending: PendingHandshake, body: dict[str, Any], now: int | None = None,
                            max_clock_skew: int = 120) -> ControlKeys:
    now = int(time.time()) if now is None else int(now)
    if body.get('server_id') != pending.server_id or body.get('client_id') != pending.client_id:
        raise ValueError('NLS control response identity mismatch')
    if body.get('session_id') != pending.session_id.hex() or body.get('client_hello_sha256') != hashlib.sha256(canonical(pending.init_body)).hexdigest():
        raise ValueError('NLS control transcript/session mismatch')
    try:
        timestamp = int(body['timestamp'])
        server_public = unb64(str(body['server_signing_key']))
        server_eph = X25519PublicKey.from_public_bytes(unb64(str(body['server_ephemeral'])))
        client_nonce = unb64(str(body['client_nonce']))
        server_nonce = unb64(str(body['server_nonce']))
    except (KeyError, ValueError, TypeError) as exc:
        raise ValueError('malformed NLS server hello') from exc
    if body.get('protocol_version') != VERSION or abs(now - timestamp) > max_clock_skew:
        raise ValueError('NLS control response freshness/version check failed')
    if not secrets.compare_digest(hashlib.sha256(server_public).digest(), hashlib.sha256(pending.pinned_server_public).digest()):
        raise ValueError('Router-CA server key pin mismatch')
    if client_nonce != pending.nonce or len(server_nonce) != 32:
        raise ValueError('NLS control nonce mismatch')
    verify_signature(server_public, b'SHLO', body)
    shared = pending.ephemeral_private.exchange(server_eph)
    if not any(shared):
        raise ValueError('invalid X25519 shared secret')
    transcript_hash = hashlib.sha256(canonical(pending.init_body)).digest()
    material = _derive(shared, pending.session_id, pending.nonce, server_nonce, transcript_hash)
    return ControlKeys(material[:32], material[32:], pending.session_id)

class NLSControlCipher:
    """Experimental record protector for an already-authenticated NLS control session."""
    def __init__(self, key: bytes, session_id: bytes, send_direction: int, receive_direction: int, max_record: int = MAX_FRAME):
        if len(key) != 32 or len(session_id) != 16 or send_direction not in (0, 1) or receive_direction not in (0, 1) or send_direction == receive_direction:
            raise ValueError('invalid NLS control cipher parameters')
        self.key, self.session_id = key, session_id
        self.send_direction, self.receive_direction = send_direction, receive_direction
        self.send_sequence = 0
        self.receive_sequence = 0
        self.max_record = max_record
    def seal(self, plaintext: bytes) -> bytes:
        if len(plaintext) > self.max_record: raise ValueError('NLS control record too large')
        seq = self.send_sequence
        nonce = self.send_direction.to_bytes(4, 'big') + seq.to_bytes(8, 'big')
        aad = MAGIC + bytes([VERSION, self.send_direction]) + self.session_id + seq.to_bytes(8, 'big')
        ciphertext = AESGCM(self.key).encrypt(nonce, plaintext, aad)
        self.send_sequence += 1
        return aad + len(ciphertext).to_bytes(4, 'big') + ciphertext
    def open(self, record: bytes) -> bytes:
        if len(record) < 34 + 16: raise ValueError('truncated NLS control record')
        if record[:4] != MAGIC or record[4] != VERSION or record[5] != self.receive_direction: raise ValueError('invalid NLS control record header')
        sid, seq, size = record[6:22], int.from_bytes(record[22:30], 'big'), int.from_bytes(record[30:34], 'big')
        if sid != self.session_id or seq != self.receive_sequence: raise ValueError('NLS control session/sequence mismatch')
        if size > self.max_record + 16 or len(record) != 34 + size: raise ValueError('invalid NLS control record length')
        nonce = self.receive_direction.to_bytes(4, 'big') + seq.to_bytes(8, 'big')
        try: plaintext = AESGCM(self.key).decrypt(nonce, record[34:], record[:30])
        except Exception as exc: raise ValueError('NLS control record authentication failed') from exc
        self.receive_sequence += 1
        return plaintext

def pack_json(value: dict[str, Any]) -> bytes:
    return encode_frame(1, canonical(value))

def unpack_json(frame: bytes) -> dict[str, Any]:
    kind, body = decode_frame(frame)
    if kind != 1: raise ValueError('unsupported NLS control message kind')
    value = json.loads(body.decode('ascii'))
    if not isinstance(value, dict): raise ValueError('NLS control message must be an object')
    return value
