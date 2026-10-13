import asyncio
import json
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.db.session import SessionLocal
from backend.db.models import ArtifactModel, AnalysisRunModel, FindingModel, FindingEvidenceModel
from backend.services.analysis_results_aggregator import AnalysisResultsAggregator
from backend.services.analysis_orchestrator import AnalysisOrchestrator
from backend.services.url_batch_analysis import parse_url_lines

client = TestClient(app)

def test_campaign_candidates_collection_is_not_a_campaign_id():
    response = client.get('/api/campaigns/candidates')
    assert response.status_code == 200
    assert isinstance(response.json(), list)

def test_empty_analysis_does_not_invent_sender_baseline_or_reassessment_evidence():
    run = AnalysisRunModel(id='no-baseline-run', artifact_id='no-baseline-artifact')
    gaps = AnalysisResultsAggregator._build_uncertainty_and_gaps(run, [], None)
    assert gaps == []
    assert AnalysisResultsAggregator._build_what_would_change([], gaps) == []

def test_failed_processing_stage_is_reported_as_an_observed_gap():
    from backend.db.models import AnalysisTaskModel
    run = AnalysisRunModel(id='failed-gap-run', artifact_id='failed-gap-artifact')
    task = AnalysisTaskModel(title='File decoder', status='FAILED', error='Decoder unavailable')
    gaps = AnalysisResultsAggregator._build_uncertainty_and_gaps(run, [task], None)
    assert len(gaps) == 1
    assert gaps[0].topic == 'File decoder'
    assert 'Decoder unavailable' in gaps[0].description
    assert AnalysisResultsAggregator._build_what_would_change([], gaps) == ['Complete the unavailable check: File decoder.']

def test_investigation_stream_disconnect_drains_queue_readers(monkeypatch):
    from types import SimpleNamespace
    from backend.api.routes.investigations import stream_investigation_events
    from backend.services.investigation_workspace_service import InvestigationWorkspaceService
    from backend.services.realtime_service import global_realtime_hub
    monkeypatch.setattr(InvestigationWorkspaceService, 'resolve_context', lambda *args: (
        SimpleNamespace(id='stream-investigation'), SimpleNamespace(id='stream-run'), None, None))
    monkeypatch.setattr(InvestigationWorkspaceService, 'get_workspace_summary', lambda *args: None)

    async def exercise():
        queues, unsubscribed = {}, []
        async def subscribe(channel):
            queues[channel] = asyncio.Queue()
            return queues[channel]
        async def unsubscribe(channel, queue):
            assert queue is queues[channel]
            unsubscribed.append(channel)
        monkeypatch.setattr(global_realtime_hub, 'subscribe', subscribe)
        monkeypatch.setattr(global_realtime_hub, 'unsubscribe', unsubscribe)
        response = await stream_investigation_events('stream-investigation', db=None)
        generator = response.body_iterator
        assert 'event: snapshot' in await anext(generator)
        reader = asyncio.create_task(anext(generator))
        for _ in range(10):
            await asyncio.sleep(0)
            if len(queues) == 2 and all(queue._getters for queue in queues.values()):
                break
        assert len(queues) == 2 and all(queue._getters for queue in queues.values())
        reader.cancel()
        await asyncio.gather(reader, return_exceptions=True)
        assert all(not queue._getters for queue in queues.values())
        assert set(unsubscribed) == {'investigation:stream-investigation', 'run:stream-run'}
    asyncio.run(exercise())

@pytest.mark.parametrize('prefix', ['/api/v1/rules', '/api/rules', '/api/detections', '/detections'])
def test_registry_and_editor_contract(prefix):
    response = client.get(prefix + '/registry')
    assert response.status_code == 200
    assert any('sender_domain' in fields for fields in response.json()['data_sources'].values())
    fields = client.get(prefix + '/registry/fields')
    assert fields.status_code == 200
    sender = next(row for row in fields.json() if row['field'] == 'sender_domain')
    assert sender['allowed_operators'] and sender['field_type'] == 'DOMAIN'

def test_projection_does_not_invent_infrastructure_or_redirects():
    artifact = ArtifactModel(id='source-check', artifact_type='FILE', name='sample.txt')
    run = AnalysisRunModel(id='source-run', artifact_id=artifact.id)
    ip = FindingEvidenceModel(key='source_ip', value='10.1.2.3', evidence_type='IP', source='test')
    url = FindingEvidenceModel(key='url', value='https://example.test/', evidence_type='URL', source='test')
    finding = FindingModel(title='Redirect observation', severity='LOW', evidence_items=[ip, url])
    with SessionLocal() as db:
        result = AnalysisResultsAggregator._build_indicators_summary(db, run, artifact, [finding])
    assert result.ips[0].country is None and result.ips[0].asn is None
    assert result.urls[0].redirect_hops is None

def test_batch_defanged_equivalence_and_no_safe_verdict():
    raw = 'https://example.com/\nhttp://198.51.100.7:8080/login.exe'
    defanged = raw.replace('https://', 'hxxps://').replace('http://', 'hxxp://').replace('.', '[.]')
    original = client.post('/api/urls/analyze-batch', json={'text': raw})
    restored = client.post('/api/urls/analyze-batch', json={'text': defanged})
    assert original.status_code == restored.status_code == 200
    assert original.json()['urls_analyzed'] == 2
    assert [[f['finding_type'] for f in item['findings']] for item in original.json()['results']] == [[f['finding_type'] for f in item['findings']] for item in restored.json()['results']]
    assert original.json()['results'][0]['status'] == 'NO_STRUCTURAL_SIGNALS'
    assert original.json()['results'][1]['status'] == 'STRUCTURAL_SIGNALS_FOUND'
    assert 'safety' in ' '.join(original.json()['limitations'])

@pytest.mark.parametrize('text,expected', [(' ', 'one URL'), ('https://example.com/\nnot a url', 'Line 2'), ('\n'.join('https://example.com/' for _ in range(51)), '50 URLs'), ('file://example.com/a', 'Line 1')])
def test_bad_batch_rejected_actionably(text, expected):
    response = client.post('/api/urls/analyze-batch', json={'text': text})
    assert response.status_code == 422
    assert expected in response.json()['detail']

def test_batch_duplicates_preserve_first_source_line():
    result = parse_url_lines('https://example.com/\nhxxps://example[.]com/')
    assert len(result) == 1 and result[0]['line'] == 1

def test_upload_auth_spray_uses_real_pipeline_and_preserves_history():
    sample = Path(__file__).resolve().parents[2] / 'samples/06-logs/password-spray.json'
    payload = sample.read_bytes()
    response = client.post('/api/ingest', files={'file': ('spray.json', payload, 'application/json')})
    assert response.status_code == 200
    data = response.json()
    with SessionLocal() as db:
        artifact = db.get(ArtifactModel, data['artifact_id'])
        artifact.artifact_type = 'AUTH_LOG'
        db.commit()
        run = asyncio.run(AnalysisOrchestrator.execute_run(db, data['analysis_run_id']))
        assert run.status == 'COMPLETED'
        assert run.overall_risk_score >= 65
        findings = db.query(FindingModel).filter_by(analysis_run_id=run.id).all()
        assert any('SPRAY' in finding.finding_type.upper() for finding in findings)
        child_id = json.loads(run.metadata_json)['canonical_pipeline_run_id']
        assert child_id != run.id and db.get(AnalysisRunModel, child_id).artifact_id == artifact.id
        assert db.get(AnalysisRunModel, data['analysis_run_id']) is not None

def test_intake_file_uses_focused_pipeline_with_source_linked_urls():
    response = client.post('/api/ingest', files={'file': ('refs.txt', b'hxxps://reference[.]test/a', 'text/plain')})
    assert response.status_code == 200
    run_id = response.json()['analysis_run_id']
    with SessionLocal() as db:
        run = asyncio.run(AnalysisOrchestrator.execute_run(db, run_id))
        assert run.status == 'COMPLETED'
        assert json.loads(run.metadata_json)['canonical_pipeline_run_id'] != run.id
    projection = client.get(f'/api/analysis/{run_id}/results')
    assert projection.status_code == 200
    assert any(url['value'] == 'https://reference.test/a' for url in projection.json()['indicators_summary']['urls'])

@pytest.mark.parametrize('prefix', ['/api/api-security', '/api/network-security'])
def test_structured_telemetry_empty_and_malformed_not_reinterpreted(prefix):
    assert client.post(prefix + '/analyze-batch', json=[]).status_code == 422
    assert client.post(prefix + '/analyze-batch', json=[{'unrelated': 'value'}]).status_code == 422
    for filename, payload, expected in [('bad.json', b'{broken', 'Malformed JSON'),
                                        ('bad.jsonl', b'{"path":"/api/a","method":"GET","src_ip":"192.0.2.1"}\n{broken', 'line 2')]:
        response = client.post(prefix + '/upload-log', files={'file': (filename, payload, 'application/octet-stream')})
        assert response.status_code == 422
        assert expected in response.json()['detail']

def test_api_json_jsonl_equivalent_negative_control():
    events = [{'timestamp': '2026-10-13T10:00:00Z', 'method': 'GET', 'path': '/api/orders', 'status_code': 200, 'source_ip': '192.0.2.17'}]
    results = []
    for filename, payload in [('events.json', json.dumps(events).encode()), ('events.jsonl', json.dumps(events[0]).encode())]:
        response = client.post('/api/api-security/upload-log', files={'file': (filename, payload, 'application/octet-stream')})
        assert response.status_code == 200
        results.append(response.json())
    assert results[0]['events_analyzed_count'] == results[1]['events_analyzed_count'] == 1
    assert results[0]['classification'] == results[1]['classification']
    assert results[0]['overall_risk_score'] == results[1]['overall_risk_score'] == 0
