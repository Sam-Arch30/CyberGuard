"""Regression controls use actual API contracts and genuine synthetic file bytes."""
import hashlib
import json
import os
import subprocess
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.services.auth_log_parser import parse_auth_log
from backend.services.authentication_analyzers import global_adapter_registry
from backend.services import media_decoder
from backend.services.multimedia_service import MultimediaPipeline
from backend.db.session import SessionLocal
from backend.db.models import ArtifactModel, AnalysisRunModel
from backend.services.evidence_storage import evidence_storage

SAMPLES = Path(__file__).resolve().parents[2] / 'samples'
client = TestClient(app, raise_server_exceptions=False)


def upload(path, endpoint='/api/multimedia/upload'):
    file = SAMPLES / path
    return client.post(endpoint, files={'file': (file.name, file.read_bytes(), 'application/octet-stream')})


def test_all_mutable_test_paths_are_outside_repo():
    repository = SAMPLES.parent.resolve()
    for name in ('DATABASE_URL', 'CYBERGUARD_EML_STORE', 'CYBERGUARD_STORAGE_ROOT', 'CYBERGUARD_REPORTS_DIR', 'BENCHMARK_RESULTS_PATH', 'CONTINUAL_LEARNING_CANDIDATES_DIR'):
        path = Path(os.environ[name].removeprefix('sqlite:///')).resolve()
        assert not path.is_relative_to(repository)
        assert path.is_relative_to(Path(os.environ['TEMP']).resolve())


def test_json_jsonl_password_spray_equivalence():
    paths = ['06-logs/password-spray.json', '06-logs/authentication-events.jsonl']
    normalized, results = [], []
    for path in paths:
        file = SAMPLES / path
        raw = parse_auth_log(file.read_bytes(), file.name)
        events = [global_adapter_registry.normalize(event) for event in raw]
        normalized.append([(e.account_id, e.timestamp, e.source_ip, e.result) for e in events])
        response = upload(path, '/api/auth-security/upload-log')
        assert response.status_code == 200, response.text
        results.append(response.json())
    assert len(normalized[0]) == 24 and normalized[0] == normalized[1]
    for result in results:
        assert result['events_analyzed_count'] == 24
        assert result['accounts_targeted_count'] == 8
        assert result['classification'] == 'CREDENTIAL_ATTACK_DETECTED'
        assert result['overall_risk_score'] > 0
    assert results[0]['overall_risk_score'] == results[1]['overall_risk_score']
    assert [f['finding_type'] for f in results[0]['findings']] == [f['finding_type'] for f in results[1]['findings']]


def test_normal_authentication_control():
    response = upload('06-logs/normal-auth.json', '/api/auth-security/upload-log')
    assert response.status_code == 200
    assert response.json()['classification'] == 'NORMAL_AUTHENTICATION'
    assert response.json()['overall_risk_score'] == 0


@pytest.mark.parametrize('name,data,detail', [
    ('broken.json', b'{bad', 'line 1'), ('broken.jsonl', b'\n{"user":"alice"}\n{bad', 'line 3'),
    ('empty.json', b'[]', 'No authentication'), ('empty.jsonl', b'\n ', 'No authentication'),
    ('unusable.json', b'[{"hello":"world"}]', 'account'), ('scalar.jsonl', b'42', 'line 1'),
    ('empty-events.json', b'{"events":[]}', 'No authentication'), ('bytes.json', b'\xff', 'UTF-8'),
])
def test_malformed_authentication_is_rejected(name, data, detail):
    response = client.post('/api/auth-security/upload-log', files={'file': (name, data, 'application/octet-stream')})
    assert response.status_code == 422, response.text
    assert detail in response.json()['detail']


def test_explicit_syslog_still_works():
    data = b'Oct 12 10:30:00 host sshd[123]: Failed password for alice from 192.0.2.10 port 22 ssh2'
    response = client.post('/api/auth-security/upload-log?provider_hint=linux_auth', files={'file': ('auth.log', data)})
    assert response.status_code == 200, response.text
    assert response.json()['accounts_targeted_count'] == 1


def claim(sender, reply):
    # Exact keys submitted by ImpersonationView; domains must be derived by API.
    return {'artifact_type': 'EMAIL', 'email_data': {'from_address': sender, 'from_display_name': 'Example Finance', 'reply_to_address': reply, 'subject': 'Payment approval', 'body_text': 'Payment message'}}


def test_frontend_identity_contract_and_profile_persistence():
    profile = client.post('/api/impersonation/profiles', json=json.loads((SAMPLES / '07-identity/trusted-profile.json').read_text()))
    assert profile.status_code == 201
    identifier = profile.json()['id']
    loaded = client.get('/api/impersonation/profiles/' + identifier)
    assert loaded.json()['trusted_sender_addresses'] == ['finance@example.test']
    changed = client.put('/api/impersonation/profiles/' + identifier, json={'trusted_sender_addresses': ['finance@example.test', 'CFO@example.test']})
    assert changed.status_code == 200
    assert client.get('/api/impersonation/profiles/' + identifier).json()['trusted_sender_addresses'] == ['finance@example.test', 'cfo@example.test']
    assessments = []
    for sender, reply in [('finance@example.test', 'finance@example.test'), ('finance@lookalike-example.test', 'collector@untrusted.example')]:
        body = claim(sender, reply); body['target_identity_hint'] = identifier
        response = client.post('/api/impersonation/analyze', json=body)
        assert response.status_code == 200, response.text
        data = response.json(); assessments.append(data['assessment'])
        with SessionLocal() as db:
            artifact = db.get(ArtifactModel, data['artifact_id'])
            stored = json.loads(artifact.metadata_json)['claim']['email_data']
            assert stored['from_domain'] == sender.split('@')[1]
            assert stored['reply_to_domain'] == reply.split('@')[1]
            assert db.get(AnalysisRunModel, data['analysis_run_id']) is not None
    assert assessments[0]['classification'] == 'NO_IMPERSONATION_EVIDENCE'
    assert assessments[0]['risk_score'] < 20
    assert assessments[1]['risk_score'] > assessments[0]['risk_score']


@pytest.mark.parametrize('fields', [{}, {'from': 'alice@example.test'}, {'from_address': 'missing-domain'},
    {'from_address': 'alice@example.test', 'from_domain': 'trusted.example'},
    {'from_address': 'alice@example.test', 'reply_to_domain': 'trusted.example'},
    {'from_address': 'alice@example.test', 'reply_to_address': 'other@example.test', 'reply_to_domain': 'wrong.example'},
    {'from_address': 'a@example.test,b@example.test'}])
def test_invalid_identity_contract_rejected(fields):
    response = client.post('/api/impersonation/analyze', json={'artifact_type': 'EMAIL', 'email_data': fields})
    assert response.status_code == 422, response.text


@pytest.mark.parametrize('path', sorted(str(p.relative_to(SAMPLES)).replace('\\', '/') for directory in ['04-audio', '05-video'] for p in (SAMPLES / directory).iterdir()))
def test_real_media_decodes_with_bounded_output(path):
    response = upload(path)
    assert response.status_code == 200, response.text
    data = response.json(); assessment = data['assessment']
    assert assessment['processing_status'] == 'COMPLETED', assessment
    assert any(result['status'] == 'SUCCESS' for result in assessment['detector_results'])
    assert assessment['confidence'] == 0 and assessment['confidence_basis'] == 'UNAVAILABLE_NOT_CALIBRATED'
    assert all(result['confidence'] == 0 for result in assessment['detector_results'])
    assert any('not a calibrated probability' in value for value in assessment['limitations'])
    with SessionLocal() as db:
        artifact = db.get(ArtifactModel, data['artifact_id'])
        original = (SAMPLES / path).read_bytes()
        assert artifact.sha256 == hashlib.sha256(original).hexdigest()
        assert evidence_storage.retrieve_bytes(artifact.storage_reference) == original
        run = db.get(AnalysisRunModel, data['analysis_run_id'])
        assert json.loads(run.metadata_json)['processing_status'] == 'COMPLETED'


def test_missing_decoder_and_timeout_are_explicit(monkeypatch):
    raw = (SAMPLES / '04-audio/synthetic-tone.mp3').read_bytes()
    monkeypatch.setattr(media_decoder, 'decoder_executable', lambda: None)
    assessment = MultimediaPipeline().analyze_media(raw, 'whatever.mp3')
    assert assessment.processing_status == 'DECODER_UNAVAILABLE'
    assert assessment.classification == 'INSUFFICIENT_EVIDENCE'
    assert assessment.confidence == 0
    monkeypatch.setattr(media_decoder, 'decoder_executable', lambda: 'decoder')
    captured = {}
    def timeout(command, **options):
        captured.update(options)
        assert '-nostdin' in command and '-threads' in command and '-max_alloc' in command
        assert command[command.index('-protocol_whitelist') + 1] == 'file'
        assert command[command.index('-t') + 1] == '30'
        assert '-fs' in command
        assert options.get('shell', False) is False
        raise subprocess.TimeoutExpired(command, options['timeout'])
    monkeypatch.setattr(media_decoder.subprocess, 'run', timeout)
    result = media_decoder.decode_media(raw, 'AUDIO', 'MP3')
    assert result['status'] == 'PROCESSING_TIMEOUT'
    assert captured['timeout'] == 20


def test_unsupported_and_invalid_decoder_states(monkeypatch):
    assert media_decoder.decode_media(b'not media', 'UNKNOWN_MEDIA', 'UNKNOWN')['status'] == 'UNSUPPORTED_FORMAT'
    assert media_decoder.decode_media(b'', 'AUDIO', 'WAV')['status'] == 'INVALID_CONTENT'
    monkeypatch.setattr(media_decoder, 'decoder_executable', lambda: 'decoder')
    monkeypatch.setattr(media_decoder.subprocess, 'run', lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 1))
    result = media_decoder.decode_media(b'ID3truncated', 'AUDIO', 'MP3')
    assert result['status'] == 'INVALID_CONTENT'
    assert result['frames'] == [] and result['audio'] is None


def test_decoder_output_limit_is_enforced(monkeypatch):
    monkeypatch.setattr(media_decoder, 'decoder_executable', lambda: 'decoder')
    def output(command, **options):
        Path(command[-1]).write_bytes(b'0' * (media_decoder.MAX_OUTPUT + 1))
        return subprocess.CompletedProcess(command, 0)
    monkeypatch.setattr(media_decoder.subprocess, 'run', output)
    result = media_decoder.decode_media(b'ID3data', 'AUDIO', 'MP3')
    assert result['status'] == 'RESOURCE_LIMIT'
    assert result['audio'] is None


def test_stored_media_reads_are_bounded_and_missing_bytes_are_actionable(monkeypatch):
    import io
    from types import SimpleNamespace
    from fastapi import HTTPException
    from backend.api.routes import multimedia
    captured = []
    class Stream(io.BytesIO):
        def read(self, size=-1):
            captured.append(size)
            return b'0' * size
    monkeypatch.setattr(multimedia.evidence_storage, 'retrieve_stream', lambda key: Stream())
    with pytest.raises(HTTPException) as error:
        multimedia._retrieve_media(SimpleNamespace(storage_reference='isolated', sha256='unused'))
    assert error.value.status_code == 413
    assert captured == [multimedia.MAX_MEDIA_BYTES + 1]
    def missing(key):
        raise FileNotFoundError('sensitive internal path')
    monkeypatch.setattr(multimedia.evidence_storage, 'retrieve_stream', missing)
    with pytest.raises(HTTPException) as error:
        multimedia._retrieve_media(SimpleNamespace(storage_reference='isolated', sha256='unused'))
    assert error.value.status_code == 422
    assert 'sensitive' not in error.value.detail


def test_media_concurrency_limit(monkeypatch):
    from backend.api.routes import multimedia
    from fastapi import HTTPException
    from threading import BoundedSemaphore
    slots = BoundedSemaphore(1); slots.acquire()
    monkeypatch.setattr(multimedia, '_analysis_slots', slots)
    with pytest.raises(HTTPException) as error:
        multimedia._analyze(data=b'0')
    assert error.value.status_code == 429


@pytest.mark.parametrize('path', ['10-invalid/broken.mp4', '10-invalid/broken.pdf', '10-invalid/jpeg-with-pdf-extension.pdf', '10-invalid/malformed.json'])
def test_invalid_intake_preserves_original_and_shows_limitations(path):
    response = upload(path, '/api/ingest')
    assert response.status_code == 200, response.text
    data = response.json()
    assert data['warnings']
    assert any(any(word in warning.lower() for word in ['invalid', 'mismatch', 'not match']) for warning in data['warnings'])
    assert data['sha256'] == hashlib.sha256((SAMPLES / path).read_bytes()).hexdigest()


def test_broken_video_rejected_and_filename_not_detection_evidence():
    assert upload('10-invalid/broken.mp4').status_code == 422
    raw = (SAMPLES / '03-images/synthetic-card.png').read_bytes()
    pipeline = MultimediaPipeline()
    first = pipeline.analyze_media(raw, 'authentic.png')
    second = pipeline.analyze_media(raw, 'deepfake.mp4')
    assert first.risk_score == second.risk_score
    assert first.classification == second.classification
    assert first.format == second.format == 'PNG'


def test_ingested_media_analysis_and_reanalysis_preserve_original():
    saved = upload('05-video/synthetic-color-bars.mp4', '/api/ingest').json()
    identifier = saved['artifact_id']
    first = client.post('/api/multimedia/analyze', json={'artifact_id': identifier})
    second = client.post('/api/multimedia/reanalyze/' + identifier)
    assert first.status_code == second.status_code == 200, (first.text, second.text)
    assert first.json()['assessment']['processing_status'] == 'COMPLETED'
    assert first.json()['analysis_run_id'] != second.json()['analysis_run_id']
    with SessionLocal() as db:
        artifact = db.get(ArtifactModel, identifier)
        assert artifact.sha256 == saved['sha256']


def test_media_and_identity_workspace_boundaries(monkeypatch):
    monkeypatch.setenv('CYBERGUARD_DEMO_MODE', 'false')
    monkeypatch.setenv('CYBERGUARD_REQUIRE_AUTH', 'true')
    monkeypatch.setenv('CYBERGUARD_SERVER_CREDENTIALS', json.dumps({
        'audit-a': {'actor_id': 'alice', 'role': 'analyst', 'workspaces': ['audit-a']},
        'audit-b': {'actor_id': 'bob', 'role': 'analyst', 'workspaces': ['audit-b']}}))
    a = {'Authorization': 'Bearer audit-a'}; b = {'Authorization': 'Bearer audit-b'}
    response = client.post('/api/ingest', headers=a, files={'file': ('video.mp4', (SAMPLES / '05-video/synthetic-color-bars.mp4').read_bytes())})
    assert response.status_code == 200
    artifact = response.json()['artifact_id']
    assert client.post('/api/multimedia/analyze', headers=b, json={'artifact_id': artifact}).status_code == 404
    body = claim('finance@example.test', ''); body['artifact_id'] = artifact
    assert client.post('/api/impersonation/analyze', headers=b, json=body).status_code == 404
    for headers in ({}, {'X-Role': 'admin'}, {'Authorization': 'Bearer invalid'}):
        assert client.post('/api/multimedia/analyze', headers=headers, json={'artifact_id': artifact}).status_code == 401
