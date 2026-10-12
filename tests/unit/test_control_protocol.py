import socket
import threading
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from nls_nexos_core.control_protocol import (NLSControlError,NLSControlRecordChannel,client_handshake,server_handshake,public_key_bytes,b64)

def test_signed_nls_handshake_and_encrypted_records():
    client_sock,server_sock=socket.socketpair(); client_key=Ed25519PrivateKey.generate(); server_key=Ed25519PrivateKey.generate(); results={}
    def server():
        channel,hello,auth=server_handshake(server_sock,server_key,"ca-test")
        results.update(router=hello["router_id"],auth=auth)
        request=channel.recv(); results["request"]=request
        channel.send({"type":"health-result","ok":True}); channel.close()
    worker=threading.Thread(target=server,daemon=True); worker.start()
    channel=client_handshake(client_sock,client_key,"edge-test",b64(public_key_bytes(server_key)),"ca-test")
    channel.send({"type":"health"}); assert channel.recv()=={"type":"health-result","ok":True}
    channel.close(); worker.join(timeout=2)
    assert not worker.is_alive(); assert results=={"router":"edge-test","auth":None,"request":{"type":"health"}}

def test_record_sequence_replay_rejected():
    cs,ss=socket.socketpair(); client=NLSControlRecordChannel(cs,b"a"*32,b"b"*32,b"CLNT",b"SRVR"); server=NLSControlRecordChannel(ss,b"b"*32,b"a"*32,b"SRVR",b"CLNT")
    client.send({"m":"one"}); assert server.recv()=={"m":"one"}
    client.send_sequence=1; client.send({"m":"replay"})
    with pytest.raises(NLSControlError,match="sequence"): server.recv()
    client.close(); server.close()

def test_sequence_exhaustion_requires_reconnect():
    sock=socket.socket(); ch=NLSControlRecordChannel(sock,b"a"*32,b"b"*32,b"CLNT",b"SRVR",send_sequence=2**64-1)
    with pytest.raises(NLSControlError,match="exhausted"): ch.send({"type":"heartbeat"})
    sock.close()
