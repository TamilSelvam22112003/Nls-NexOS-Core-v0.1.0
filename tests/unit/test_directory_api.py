from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
import hashlib
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from nls_nexos_core.api import handle_control_request
from nls_nexos_core.control import NLSControlServer
from nls_nexos_core.database import Registry
from nls_nexos_core.directory import verify_signature


def _settings():
    return SimpleNamespace(
        policy_version=1, nls_protocol_version=1, replay_window=128,
        max_clock_skew_seconds=120, session_timeout_seconds=300,
        key_rotation_seconds=3600, control_id="ca-test",
    )


def _router(registry, router_id, status="ACTIVE", expired=False):
    now = int(time.time())
    with registry.connect() as con:
        con.execute(
            "INSERT INTO routers(router_id,registered,status,created_at,updated_at,ed25519_public_key,rsa_encryption_public_key,wan_endpoints,gateway_ips,prefixes) VALUES(?,1,?,?,?,'ed-pem','rsa-pem','[]','[]','[]')",
            (router_id, status, now, now),
        )
    after = (datetime.now(timezone.utc) - timedelta(days=1) if expired
             else datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
    registry.record_certificate("a1" if router_id == "router-a" else hashlib.sha256(router_id.encode()).hexdigest()[:12],
                                router_id, datetime.now(timezone.utc).isoformat(), after,
                                "f" * 64, now)
    return registry


def test_lookup_unknown_is_signed_and_nonce_bound(tmp_path):
    registry = Registry(tmp_path / "registry.sqlite3")
    _router(registry, "caller")
    key = ed25519.Ed25519PrivateKey.generate()
    nonce = "n" * 43
    caller_serial = hashlib.sha256(b"caller").hexdigest()[:12]
    response = handle_control_request(
        {"type": "lookup", "router_id": "caller", "target_router_id": "missing", "client_nonce": nonce},
        None, registry, _settings(), {"router_id": "caller", "serial_number": caller_serial}, key,
    )
    assert response["type"] == "lookup-result"
    assert response["client_nonce"] == nonce
    pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    record = verify_signature(response["record"], pub)
    assert record["status"] == "UNKNOWN"
    assert record["client_nonce"] == nonce
    with registry.connect() as con:
        audit_rows = con.execute("SELECT event,detail FROM audit_log ORDER BY id").fetchall()
    assert any(row["event"] == "DIRECTORY_LOOKUP" and "target=missing" in row["detail"] for row in audit_rows)
    assert all("bootstrap" not in row["detail"].lower() and "private key" not in row["detail"].lower()
               and "token=" not in row["detail"].lower() for row in audit_rows)


def test_lookup_reports_revoked_and_expired_router_status(tmp_path):
    registry = Registry(tmp_path / "registry.sqlite3")
    _router(registry, "caller")
    _router(registry, "router-a", status="REVOKED")
    _router(registry, "router-expired", expired=True)
    key = ed25519.Ed25519PrivateKey.generate()
    caller = {"router_id": "caller", "serial_number": hashlib.sha256(b"caller").hexdigest()[:12]}
    for target, expected in (("router-a", "REVOKED"), ("router-expired", "EXPIRED")):
        nonce = ("n" if target == "router-a" else "e") * 43
        response = handle_control_request(
            {"type": "lookup", "router_id": "caller", "target_router_id": target, "client_nonce": nonce},
            None, registry, _settings(), caller, key,
        )
        pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        assert verify_signature(response["record"], pub)["status"] == expected


def test_unauthenticated_lookup_discloses_no_record(tmp_path):
    registry = Registry(tmp_path / "registry.sqlite3")
    key = ed25519.Ed25519PrivateKey.generate()
    response = handle_control_request(
        {"type": "lookup", "router_id": "untrusted", "target_router_id": "router-a", "client_nonce": "x" * 43},
        None, registry, _settings(), None, key,
    )
    assert response["type"] == "error"
    assert "record" not in response
    with registry.connect() as con:
        assert con.execute("SELECT event FROM audit_log WHERE event='DIRECTORY_LOOKUP_DENIED'").fetchone()


def test_heartbeat_contains_directory_sequence_and_revocation_state(tmp_path):
    registry = Registry(tmp_path / "registry.sqlite3")
    _router(registry, "caller")
    with registry.connect() as con:
        con.execute("UPDATE issued_certificates SET status='REVOKED',revoked_at=? WHERE router_id='caller'",
                    (int(time.time()),))
    key = ed25519.Ed25519PrivateKey.generate()
    response = handle_control_request(
        {"type": "heartbeat", "router_id": "caller"}, None, registry, _settings(),
        {"router_id": "caller", "serial_number": "a1"}, key,
    )
    assert response["type"] == "heartbeat-result"
    assert isinstance(response["directory_seq"], int)
    assert response["revocation_state"]["revoked_certificates"]



def test_lookup_rejects_disabled_caller_even_if_transport_auth_was_cached(tmp_path):
    registry = Registry(tmp_path / "registry.sqlite3")
    _router(registry, "caller", status="DISABLED")
    key = ed25519.Ed25519PrivateKey.generate()
    caller_serial = hashlib.sha256(b"caller").hexdigest()[:12]
    response = handle_control_request(
        {"type": "lookup", "router_id": "caller", "target_router_id": "target", "client_nonce": "n" * 43},
        None, registry, _settings(), {"router_id": "caller", "serial_number": caller_serial}, key,
    )
    assert response["type"] == "error"
    assert response["code"] == "not-authorized"
    with registry.connect() as con:
        row = con.execute("SELECT detail FROM audit_log WHERE event='DIRECTORY_LOOKUP_DENIED'").fetchone()
    assert row and "token" not in row["detail"].lower() and "private" not in row["detail"].lower()


def test_lookup_rate_limit_is_per_authenticated_router(tmp_path):
    registry = Registry(tmp_path / "registry.sqlite3")
    _router(registry, "caller")
    key = ed25519.Ed25519PrivateKey.generate()
    server = NLSControlServer(_settings(), registry, object(), key)
    serial = hashlib.sha256(b"caller").hexdigest()[:12]
    server._lookup_times["caller"] = [time.monotonic()] * 120
    response = server._dispatch(
        {"type": "lookup", "router_id": "caller", "target_router_id": "target", "client_nonce": "n" * 43},
        {"router_id": "caller", "serial_number": serial},
    )
    assert response["type"] == "error" and response["code"] == "rate-limited"


def test_lookup_concurrency_cap_rejects_excess_parallel_requests(tmp_path, monkeypatch):
    import threading
    import nls_nexos_core.control as control_module
    registry = Registry(tmp_path / "registry.sqlite3")
    _router(registry, "caller")
    key = ed25519.Ed25519PrivateKey.generate()
    server = NLSControlServer(_settings(), registry, object(), key)
    server.max_concurrent_lookups_per_router = 2
    serial = hashlib.sha256(b"caller").hexdigest()[:12]
    entered = 0
    lock = threading.Lock()
    release = threading.Event()
    all_entered = threading.Event()

    def blocked_handler(**kwargs):
        nonlocal entered
        with lock:
            entered += 1
            if entered == 2:
                all_entered.set()
        release.wait(timeout=3)
        return {"type": "lookup-result", "ok": True}

    monkeypatch.setattr(control_module, "handle_control_request", blocked_handler)
    auth = {"router_id": "caller", "serial_number": serial}
    workers = [
        threading.Thread(target=server._dispatch, args=(
            {"type": "lookup", "router_id": "caller", "target_router_id": "target", "client_nonce": str(i) * 16},
            auth,
        )) for i in (1, 2)
    ]
    for worker in workers: worker.start()
    assert all_entered.wait(timeout=2)
    rejected = server._dispatch(
        {"type": "lookup", "router_id": "caller", "target_router_id": "target", "client_nonce": "z" * 16},
        auth,
    )
    assert rejected["type"] == "error" and rejected["code"] == "rate-limited"
    release.set()
    for worker in workers: worker.join(timeout=3)
    assert all(not worker.is_alive() for worker in workers)
