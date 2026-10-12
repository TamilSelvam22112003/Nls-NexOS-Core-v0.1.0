from nls_nexos_core.database import Registry

def test_schema_and_router_lookup(tmp_path):
    db=Registry(tmp_path/'registry.db'); assert db.get_router('missing') is None
    with db.connect() as c: c.execute("INSERT INTO routers(router_id,registered,status,created_at,updated_at) VALUES(?,1,'ACTIVE',1,1)",('edge-1',))
    assert db.get_router('edge-1')['registered']==1

def test_duplicate_request_is_rejected(tmp_path):
    db=Registry(tmp_path/'registry.db'); assert db.is_request_new('rid','edge-1','a'*64,100); assert not db.is_request_new('rid','edge-1','a'*64,101)
