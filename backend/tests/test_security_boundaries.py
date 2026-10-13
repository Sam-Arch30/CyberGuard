import asyncio
import json
from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.db.session import SessionLocal, request_workspace
from backend.db.models import AuditLogModel
from backend.services.safe_http_client import SafeHttpClient

@pytest.fixture
def authenticated(monkeypatch):
    monkeypatch.setenv('CYBERGUARD_REQUIRE_AUTH','true')
    monkeypatch.setenv('CYBERGUARD_DEMO_MODE','false')
    monkeypatch.setenv('CYBERGUARD_SERVER_CREDENTIALS',json.dumps({'secure-test-a':{'actor_id':'alice','role':'analyst','workspaces':['tenant-a']},'secure-test-b':{'actor_id':'bob','role':'viewer','workspaces':['tenant-b']}}))
    return TestClient(app)

@pytest.mark.parametrize('path',['/api/session','/api/audit','/api/reports','/api/impersonation/profiles','/api/admin/overview'])
def test_anonymous_invalid_and_forged_roles(authenticated,path):
    assert authenticated.get(path).status_code==401
    assert authenticated.get(path,headers={'X-Role':'admin'}).status_code==401
    assert authenticated.get(path,headers={'Authorization':'Bearer invalid'}).status_code==401
    assert authenticated.get(path,headers={'Authorization':'Bearer secure-test-a','X-Role':'admin'}).status_code==403

def test_membership_and_server_identity(authenticated):
    headers={'Authorization':'Bearer secure-test-a','X-Workspace-ID':'tenant-a','X-User':'mallory'}
    result=authenticated.get('/api/session',headers=headers)
    assert result.status_code==200
    assert result.json()['actor_id']=='alice'
    assert authenticated.get('/api/session',headers={**headers,'X-Workspace-ID':'tenant-b'}).status_code==403
    assert authenticated.get('/api/session?workspace_id=tenant-b',headers=headers).status_code==403
    assert authenticated.post('/api/impersonation/profiles',headers={'Authorization':'Bearer secure-test-b'},json={}).status_code==403

def test_orm_read_update_delete_and_write_are_scoped():
    import uuid
    first,second=str(uuid.uuid4()),str(uuid.uuid4())
    with SessionLocal() as db:
        db.add_all([AuditLogModel(id=first,action='TEST',resource_type='test',resource_id='a',workspace_id='tenant-a'),AuditLogModel(id=second,action='TEST',resource_type='test',resource_id='b',workspace_id='tenant-b')]);db.commit()
    context=request_workspace.set('tenant-a')
    try:
        with SessionLocal() as db:
            assert db.get(AuditLogModel,second) is None
            assert db.query(AuditLogModel).filter(AuditLogModel.id.in_([first,second])).count()==1
            assert db.query(AuditLogModel).filter(AuditLogModel.id==second).delete()==0
            row=AuditLogModel(action='TEST',resource_type='test',resource_id='c',workspace_id='tenant-b');db.add(row)
            with pytest.raises(Exception) as error: db.flush()
            assert getattr(error.value,'status_code',None)==403
            db.rollback()
    finally: request_workspace.reset(context)

@pytest.mark.parametrize('cap',[None,50])
def test_actual_transport_destination_host_sni_and_stream_cap(cap):
    captured={'chunks':0}
    class Stream:
        async def read(self,max_bytes,timeout=None):
            captured['chunks']+=1
            return [b'HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n'+b'A'*30,b'B'*40,b'C'*30,b''][min(captured['chunks']-1,3)]
        async def write(self,buffer,timeout=None): captured['request']=captured.get('request',b'')+buffer
        async def aclose(self): captured['closed']=True
        async def start_tls(self,ssl_context,server_hostname=None,timeout=None): captured['sni']=server_hostname;return self
        def get_extra_info(self,info): return None
    async def connect(self,host,port,timeout=None,local_address=None,socket_options=None): captured['destination']=(host,port);return Stream()
    client=SafeHttpClient(max_size_bytes=cap or 200)
    with patch.object(SafeHttpClient,'resolve_and_verify_destination',return_value=(True,'safe',['93.184.215.14'])),patch('httpcore._backends.anyio.AnyIOBackend.connect_tcp',connect):
        result=asyncio.run(client.fetch_url('https://example.com/',inspect_certificate=False))
    assert result.status_code==200,result.error
    assert captured['destination']==('93.184.215.14',443)
    assert captured['sni'] in ('example.com',b'example.com')
    assert b'Host: example.com\r\n' in captured['request']
    assert captured['closed']
    if cap: assert result.response_size==50 and result.is_truncated and captured['chunks']==2

def test_disabled_reset_rejects_normal_caller(authenticated,monkeypatch):
    monkeypatch.setenv('ALLOW_WORKSPACE_RESET','true')
    response=authenticated.post('/api/workspace/reset',headers={'Authorization':'Bearer secure-test-a'})
    assert response.status_code==403

@pytest.mark.parametrize('environment_key',['ENVIRONMENT','CYBERGUARD_ENV'])
def test_production_cannot_enable_demo_bypass(authenticated,monkeypatch,environment_key):
    monkeypatch.setenv(environment_key,'PRODUCTION')
    monkeypatch.setenv('CYBERGUARD_DEMO_MODE','true')
    monkeypatch.setenv('CYBERGUARD_REQUIRE_AUTH','false')
    assert authenticated.get('/api/session').status_code==401

def test_raw_email_storage_does_not_cross_workspaces():
    from backend.services.eml_storage_service import EMLStorageService
    token=request_workspace.set('tenant-a')
    try: first=EMLStorageService._ensure_dir()
    finally: request_workspace.reset(token)
    token=request_workspace.set('tenant-b')
    try: second=EMLStorageService._ensure_dir()
    finally: request_workspace.reset(token)
    assert first!=second
    assert first.parent==second.parent

def test_explicit_local_demo_opens_without_a_token(monkeypatch):
    monkeypatch.setenv('ENVIRONMENT','development')
    monkeypatch.setenv('CYBERGUARD_ENV','DEVELOPMENT')
    monkeypatch.setenv('CYBERGUARD_DEMO_MODE','true')
    monkeypatch.setenv('CYBERGUARD_REQUIRE_AUTH','false')
    monkeypatch.setenv('CYBERGUARD_SERVER_CREDENTIALS','{}')
    client=TestClient(app)
    assert client.get('/api/session').json()['role']=='demo'
    assert client.get('/api/reports').status_code==200
    assert client.get('/api/impersonation/profiles').status_code==200
