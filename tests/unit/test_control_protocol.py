import socket
import threading

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nls_nexos_core.control_protocol import client_handshake, server_handshake, public_key_bytes, b64


def test_signed_nls_control_handshake_and_encrypted_records():
    client_sock, server_sock = socket.socketpair()
    client_key = Ed25519PrivateKey.generate()
    server_key = Ed25519PrivateKey.generate()
    server_pub = b64(public_key_bytes(server_key))
    results = {}

    def server():
        channel, hello, auth = server_handshake(server_sock, server_key, "ca-test")
        results["router"] = hello["router_id"]
        results["auth"] = auth
        request = channel.recv()
        results["request"] = request
        channel.send({"type": "health-result", "ok": True})
        channel.close()

    worker = threading.Thread(target=server, daemon=True)
    worker.start()
    channel = client_handshake(client_sock, client_key, "edge-test", server_pub, "ca-test")
    channel.send({"type": "health", "nonce": "n" * 32})
    response = channel.recv()
    assert response == {"type": "health-result", "ok": True}
    channel.close()
    worker.join(timeout=2)
    assert not worker.is_alive()
    assert results["router"] == "edge-test"
    assert results["auth"] is None
    assert results["request"] == {"type": "health", "nonce": "n" * 32}


def test_record_sequence_is_strict():
    from nls_nexos_core.control_protocol import NLSControlRecordChannel, NLSControlError
    client_sock, server_sock = socket.socketpair()
    client = NLSControlRecordChannel(client_sock, b"a" * 32, b"b" * 32, b"CLNT", b"SRVR")
    server = NLSControlRecordChannel(server_sock, b"b" * 32, b"a" * 32, b"SRVR", b"CLNT")
    client.send({"message": "one"})
    assert server.recv() == {"message": "one"}
    # Replay the already-consumed first record by rewinding a sender sequence.
    client.send_sequence = 1
    client.send({"message": "replay"})
    try:
        server.recv()
    except NLSControlError as exc:
        assert "sequence" in str(exc)
    else:
        raise AssertionError("replayed NLS control sequence was accepted")
    client.close()
    server.close()
