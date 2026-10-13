import hashlib
import json
import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.db.models import ArtifactModel
from backend.db.session import SessionLocal
from backend.services.evidence_storage import evidence_storage

client = TestClient(app)

def test_identity_eml_upload_preserves_original_and_compares_trust():
    profile = client.post('/api/impersonation/profiles', json={
        'display_name': 'Upload Finance', 'trusted_domains': ['example.test'],
        'trusted_sender_addresses': ['finance@example.test'], 'known_names': ['Upload Finance']})
    assert profile.status_code == 201
    risks = []
    for sender in ['finance@example.test', 'finance@example-alerts.test']:
        raw = f'From: Upload Finance <{sender}>\r\nSubject: Payment approval\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nPlease review this payment.\r\n'.encode()
        response = client.post('/api/impersonation/upload', data={'target_identity_hint': profile.json()['id']},
            files={'file': ('sender.eml', raw, 'message/rfc822')})
        assert response.status_code == 200, response.text
        data = response.json()
        risks.append(data['assessment']['risk_score'])
        with SessionLocal() as db:
            artifact = db.get(ArtifactModel, data['artifact_id'])
            assert artifact.sha256 == hashlib.sha256(raw).hexdigest()
            assert evidence_storage.retrieve_bytes(artifact.storage_reference) == raw
            claim = json.loads(artifact.metadata_json)['email_data']
            assert claim['from_address'] == sender
            assert claim['from_domain'] == sender.split('@')[1]
    assert risks[0] < risks[1]

@pytest.mark.parametrize('filename,raw', [
    ('bad.json', b'{broken'), ('missing.json', b'{"subject":"hello"}'),
    ('contradict.json', b'{"from_address":"a@example.test","from_domain":"other.test"}'),
    ('no-sender.eml', b'Subject: Test\r\n\r\nHello'), ('unsupported.pdf', b'%PDF')])
def test_identity_upload_validation_does_not_create_artifacts(filename, raw):
    with SessionLocal() as db:
        before = db.query(ArtifactModel).count()
    response = client.post('/api/impersonation/upload', files={'file': (filename, raw, 'application/octet-stream')})
    assert response.status_code == 422
    assert 'Invalid identity evidence' in response.json()['detail']
    with SessionLocal() as db:
        assert db.query(ArtifactModel).count() == before

def test_identity_json_upload_and_size_limit():
    raw = b'{"from_address":"finance@example.test","subject":"Hello","body_text":"Meeting"}'
    response = client.post('/api/impersonation/upload', files={'file': ('claim.json', raw, 'application/json')})
    assert response.status_code == 200
    with SessionLocal() as db:
        artifact = db.get(ArtifactModel, response.json()['artifact_id'])
        assert evidence_storage.retrieve_bytes(artifact.storage_reference) == raw
    response = client.post('/api/impersonation/upload', files={'file': ('large.eml', b'x' * (1024 * 1024 + 1), 'message/rfc822')})
    assert response.status_code == 413

def test_identity_upload_auth_and_workspace_boundaries(monkeypatch):
    monkeypatch.setenv('CYBERGUARD_REQUIRE_AUTH', 'true')
    monkeypatch.setenv('CYBERGUARD_DEMO_MODE', 'false')
    monkeypatch.setenv('CYBERGUARD_SERVER_CREDENTIALS', json.dumps({
        'upload-test-token': {'actor_id': 'upload-user', 'role': 'analyst', 'workspaces': ['upload-a']}}))
    files = {'file': ('claim.json', b'{"from_address":"a@example.test"}', 'application/json')}
    assert client.post('/api/impersonation/upload', files=files).status_code == 401
    assert client.post('/api/impersonation/upload', files=files, headers={'X-Role': 'admin'}).status_code == 401
    assert client.post('/api/impersonation/upload', files=files,
        headers={'Authorization': 'Bearer upload-test-token', 'X-Workspace-ID': 'upload-b'}).status_code == 403
