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
        assert migrated.execute("SELECT version FROM schema_version").fetchone()[0] == 2
        columns = {row["name"] for row in migrated.execute("PRAGMA table_info(routers)")}
        assert {"ed25519_public_key", "rsa_encryption_public_key", "gateway_ips", "prefixes"} <= columns
