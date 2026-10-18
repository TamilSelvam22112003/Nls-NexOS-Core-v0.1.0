import time

from nls_nexos_core.database import Registry

def test_schema_and_router_lookup(tmp_path):
    db=Registry(tmp_path/'registry.db'); assert db.get_router('missing') is None
    with db.connect() as c: c.execute("INSERT INTO routers(router_id,registered,status,created_at,updated_at) VALUES(?,1,'ACTIVE',1,1)",('edge-1',))
    assert db.get_router('edge-1')['registered']==1

def test_duplicate_request_is_rejected(tmp_path):
    db=Registry(tmp_path/'registry.db'); assert db.is_request_new('rid','edge-1','a'*64,100); assert not db.is_request_new('rid','edge-1','a'*64,101)


def test_legacy_schema_migration_is_idempotent(tmp_path):
    import sqlite3
    path = tmp_path / "legacy.sqlite3"
    con = sqlite3.connect(path)
    con.executescript("""
      CREATE TABLE routers(router_id TEXT PRIMARY KEY, registered INTEGER NOT NULL DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'ACTIVE', expected_public_key_sha256 TEXT, allowed_ipv6 TEXT,
        allowed_mac TEXT, enrollment_token_sha256 TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
      CREATE TABLE issued_certificates(serial_number TEXT PRIMARY KEY, router_id TEXT NOT NULL,
        not_before TEXT NOT NULL, not_after TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'ACTIVE',
        cert_sha256 TEXT NOT NULL, created_at INTEGER NOT NULL);
      INSERT INTO routers(router_id,registered,status,created_at,updated_at)
        VALUES('legacy-router',1,'ACTIVE',1,1);
    """)
    con.commit()
    con.close()
    db = Registry(path)
    db.initialize()
    router = db.get_router("legacy-router")
    assert router["record_seq"] == 1
    assert router["wan_endpoints"] == "[]"
    with db.connect() as migrated:
        assert migrated.execute("SELECT version FROM schema_version").fetchone()[0] == 4
        assert router["original_ip_usable"] == 0
        columns = {row["name"] for row in migrated.execute("PRAGMA table_info(routers)")}
        assert {"ed25519_public_key", "rsa_encryption_public_key", "gateway_ips", "prefixes"} <= columns



def test_revoke_router_revokes_active_certificates_and_advances_directory(tmp_path):
    db = Registry(tmp_path / "registry.db")
    now = 100
    with db.connect() as con:
        con.execute("INSERT INTO routers(router_id,registered,status,created_at,updated_at) VALUES(?,1,'ACTIVE',?,?)",
                    ("router-a", now, now))
    db.record_certificate("abc123", "router-a", "2026-01-01T00:00:00+00:00",
                          "2027-01-01T00:00:00+00:00", "d" * 64, now)
    before = db.directory_seq()
    assert db.revoke_router("router-a", now + 1)
    assert db.get_router("router-a")["status"] == "REVOKED"
    assert db.get_certificate("abc123")["status"] == "REVOKED"
    assert db.directory_seq() > before
    assert not db.revoke_router("router-a", now + 2)


def test_certificate_expiry_advances_record_and_directory_sequences(tmp_path):
    db = Registry(tmp_path / "registry.db")
    now = int(time.time())
    with db.connect() as con:
        con.execute("INSERT INTO routers(router_id,registered,status,created_at,updated_at) VALUES(?,1,'ACTIVE',?,?)",
                    ("router-expiry", now, now))
    db.record_certificate("expired1", "router-expiry", "2020-01-01T00:00:00+00:00",
                          "2020-01-02T00:00:00+00:00", "e" * 64, now)
    before_seq = db.directory_seq()
    before_record = db.get_router("router-expiry")["record_seq"]
    assert db.expire_certificates(now + 10) == 1
    assert db.get_certificate("expired1")["status"] == "EXPIRED"
    assert db.get_router("router-expiry")["record_seq"] > before_record
    assert db.directory_seq() > before_seq


def test_wan_endpoint_order_and_original_ip_validation(tmp_path):
    import json
    import pytest
    db = Registry(tmp_path / "endpoints.sqlite3")
    now = int(time.time())
    with db.connect() as con:
        con.execute(
            "INSERT INTO routers(router_id,registered,status,created_at,updated_at) VALUES(?,1,'ACTIVE',?,?)",
            ("edge-endpoints", now, now),
        )
    db.set_directory_fields("edge-endpoints", wan_endpoints=["[fd42:100::1]:4790", "192.0.2.8:4791"])
    router = db.get_router("edge-endpoints")
    assert router["original_ip_usable"] == 1
    assert json.loads(router["wan_endpoints"]) == ["[fd42:100::1]:4790", "192.0.2.8:4791"]
    for invalid in (
        ["fd42:100::1:4790"], ["[::]:4790"], ["[::1]:4790"],
        ["[ff02::1]:4790"], ["[fe80::1]:4790"], ["[::ffff:192.0.2.1]:4790"],
        ["[fd42:100::1%eth0]:4790"], ["[fd42:100::1]:0"], ["[fd42:100::1]:65536"],
        ["[fd42:100::1]:4790", "[fe80::1%eth0]:4791"],
    ):
        with pytest.raises(ValueError):
            db.set_directory_fields("edge-endpoints", wan_endpoints=invalid)
    assert json.loads(db.get_router("edge-endpoints")["wan_endpoints"]) == ["[fd42:100::1]:4790", "192.0.2.8:4791"]



def test_original_ip_is_unique_across_usable_routers(tmp_path):
    import pytest
    db = Registry(tmp_path / "unique-original-ip.sqlite3")
    now = int(time.time())
    with db.connect() as con:
        for router_id in ("router-a", "router-b"):
            con.execute(
                "INSERT INTO routers(router_id,registered,status,created_at,updated_at) VALUES(?,1,'ACTIVE',?,?)",
                (router_id, now, now),
            )
    db.set_directory_fields("router-a", wan_endpoints=["[fd42:100::1]:4790"])
    with pytest.raises(ValueError, match="originalIP must be unique"):
        db.set_directory_fields("router-b", wan_endpoints=["[fd42:100::1]:4791"])
    assert db.get_router("router-a")["original_ip_usable"] == 1
    assert db.get_router("router-b")["original_ip_usable"] == 0


def test_disable_router_advances_sequences_and_revoked_router_cannot_be_enabled(tmp_path):
    db = Registry(tmp_path / "router-status.sqlite3")
    now = int(time.time())
    with db.connect() as con:
        con.execute(
            "INSERT INTO routers(router_id,registered,status,created_at,updated_at) VALUES(?,1,'ACTIVE',?,?)",
            ("router-status", now, now),
        )
    before = db.directory_seq()
    assert db.set_router_status("router-status", "DISABLED", now + 1)
    assert db.get_router("router-status")["status"] == "DISABLED"
    assert db.directory_seq() == before + 1
    assert db.set_router_status("router-status", "ACTIVE", now + 2)
    assert db.revoke_router("router-status", now + 3)
    assert not db.set_router_status("router-status", "ACTIVE", now + 4)
