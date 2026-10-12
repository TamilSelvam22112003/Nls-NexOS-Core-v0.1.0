import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from nls_nexos_core.nls_control import NLSControlCipher, accept_client_hello, decode_frame, encode_frame, finish_client_handshake, new_client_hello, pack_json, unpack_json

def raw(key): return key.public_key().public_bytes_raw()

def test_nls_mutual_handshake_uses_pinned_keys_and_directions():
    client, server = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    cp, sp = raw(client), raw(server)
    hello, pending = new_client_hello(client_id='edge-1', server_id='ca-1', signing_key=client, pinned_server_public=sp)
    response, server_keys = accept_client_hello(body=hello, server_id='ca-1', signing_key=server, authorize_client=lambda rid, pub: rid == 'edge-1' and pub == cp)
    client_keys = finish_client_handshake(pending, response)
    assert client_keys.send_key == server_keys.receive_key and client_keys.receive_key == server_keys.send_key
    assert client_keys.session_id == server_keys.session_id

def test_nls_control_handshake_rejects_unregistered_client():
    client, server = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    hello, _ = new_client_hello(client_id='edge-unknown', server_id='ca-1', signing_key=client, pinned_server_public=raw(server))
    with pytest.raises(ValueError, match='not authorized'): accept_client_hello(body=hello, server_id='ca-1', signing_key=server, authorize_client=lambda _rid, _pub: False)

def test_nls_control_handshake_rejects_server_key_pin_mismatch():
    client, server = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    other = Ed25519PrivateKey.generate()
    hello, pending = new_client_hello(client_id='edge-1', server_id='ca-1', signing_key=client, pinned_server_public=raw(other))
    with pytest.raises(ValueError, match='different Router-CA identity'):
        accept_client_hello(body=hello, server_id='ca-1', signing_key=server, authorize_client=lambda _rid, _pub: True)

def test_nls_control_cipher_roundtrip_and_replay_block():
    key, sid = b'K' * 32, b'S' * 16
    client = NLSControlCipher(key, sid, send_direction=0, receive_direction=1)
    server = NLSControlCipher(key, sid, send_direction=1, receive_direction=0)
    record = client.seal(b'policy sync')
    assert server.open(record) == b'policy sync'
    with pytest.raises(ValueError, match='sequence mismatch'): server.open(record)

def test_nls_control_cipher_rejects_tampering():
    a, b = NLSControlCipher(b'K'*32,b'S'*16,0,1), NLSControlCipher(b'K'*32,b'S'*16,1,0)
    record = bytearray(a.seal(b'hello')); record[-1] ^= 1
    with pytest.raises(ValueError, match='authentication failed'): b.open(bytes(record))

def test_nls_control_frame_strict_length():
    frame=encode_frame(1,b'{}'); assert decode_frame(frame)==(1,b'{}')
    with pytest.raises(ValueError): decode_frame(frame+b'x')
    assert unpack_json(pack_json({'operation':'health'})) == {'operation':'health'}
