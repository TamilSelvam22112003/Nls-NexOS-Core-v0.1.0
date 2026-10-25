import pytest

from nls_nexos_core.control import NLSControlServer


def test_control_connection_admission_is_globally_bounded():
    server = NLSControlServer(None, None, None, None)
    acquired = 0
    while server._connection_slots.acquire(blocking=False):
        acquired += 1
    assert acquired == server.MAX_CONCURRENT_CONNECTIONS
    assert not server._connection_slots.acquire(blocking=False)
    for _ in range(acquired):
        server._connection_slots.release()


def test_control_connection_slot_is_released_when_handler_raises(monkeypatch):
    server = NLSControlServer(None, None, None, None)
    monkeypatch.setattr(
        server,
        "_handle_client",
        lambda _conn, _address: (_ for _ in ()).throw(RuntimeError("test failure")),
    )
    assert server._connection_slots.acquire(blocking=False)
    with pytest.raises(RuntimeError, match="test failure"):
        server._handle_client_with_slot(object(), ("127.0.0.1", 12345))
    assert server._connection_slots.acquire(blocking=False)
    server._connection_slots.release()


def test_control_handshake_timeout_is_shorter_than_authenticated_idle_timeout(monkeypatch):
    import socket
    from types import SimpleNamespace

    server = NLSControlServer(
        SimpleNamespace(control_id="test-ca", max_clock_skew_seconds=120),
        None, None, None,
    )
    timeouts = []

    class FakeConn:
        def settimeout(self, value):
            timeouts.append(value)

    class FakeChannel:
        def recv(self):
            raise socket.timeout()

        def close(self):
            pass

    def fake_handshake(conn, *_args, **_kwargs):
        assert timeouts == [server.HANDSHAKE_TIMEOUT_SECONDS]
        return FakeChannel(), {"router_id": "unidentified"}, None

    monkeypatch.setattr("nls_nexos_core.control.server_handshake", fake_handshake)
    server._handle_client(FakeConn(), ("127.0.0.1", 12345))
    assert timeouts == [
        server.HANDSHAKE_TIMEOUT_SECONDS,
        server.IDLE_TIMEOUT_SECONDS,
    ]
    assert server.HANDSHAKE_TIMEOUT_SECONDS < server.IDLE_TIMEOUT_SECONDS
