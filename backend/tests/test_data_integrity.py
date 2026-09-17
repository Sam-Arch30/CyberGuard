"""Regression coverage for real ingestion, provenance, and absence of invented evidence."""
import hashlib
import json
from pathlib import Path
from unittest.mock import AsyncMock
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from backend.main import app
from backend.db.session import Base, get_db
from backend.db.models import AnalysisPayloadModel, EmailAnalysisModel, EvidenceModel, AuditLogModel, CampaignModel
from backend.services.ip_intelligence_service import IPIntelligenceService
from backend.services.ip_providers import BaseIPIntelligenceProvider
from backend.services.ip_cache import IPIntelligenceCache
from backend.config.geolocation_config import GeolocationConfig


@pytest.fixture
def clean_client(monkeypatch):
    engine = create_engine('sqlite://', connect_args={'check_same_thread': False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)
    def database():
        with session() as db:
            yield db
    app.dependency_overrides[get_db] = database
    # No invented external intelligence. These tests exercise explicit unavailable enrichment.
    from backend.api.routes import email
    monkeypatch.setattr(email.global_domain_service, 'enrich_domains_batch', AsyncMock(return_value={}))
    monkeypatch.setattr(email, 'global_ip_service', IPIntelligenceService(config=GeolocationConfig(provider='unconfigured'), cache=IPIntelligenceCache()))
    monkeypatch.setattr(email.global_ai_analyst_service, 'is_enabled', lambda: False)
    yield TestClient(app), session
    app.dependency_overrides.clear()
    engine.dispose()


def ingest(client, number):
    raw = (f'From: sender@integrity.test\r\nTo: analyst@recipient.test\r\n'
           f'Subject: Integrity investigation {number}\r\nMessage-ID: <{number}@integrity.test>\r\n'
           'Received: from relay.integrity.test (relay.integrity.test [8.8.8.8]) by inbox.recipient.test; Thu, 17 Sep 2026 12:00:00 +0000\r\n'
           'Date: Thu, 17 Sep 2026 12:00:00 +0000\r\n'
           'DKIM-Signature: v=1; d=integrity.test; b=unverified\r\n'
           'Content-Type: text/plain; charset=utf-8\r\n\r\n'
           f'Message {number}. Review https://integrity.test/document\r\n').encode()
    response = client.post('/api/emails/analyze', files={'file': (f'message-{number}.eml', raw, 'message/rfc822')})
    assert response.status_code == 200, response.text
    return raw, response.json()


def test_empty_one_two_three_pipeline_and_provenance(clean_client):
    client, sessions = clean_client
    summary = client.get('/api/dashboard/summary').json()
    assert summary['metrics']['emails_analyzed'] == 0
    assert summary['metrics']['threats_detected'] == 0
    assert summary['metrics']['open_cases'] == 0
    assert summary['recent_emails'] == summary['recent_cases'] == summary['analysis_trend'] == []
    assert client.get('/api/campaigns').json() == []
    assert client.get('/api/cases').json()['total'] == 0
    assert client.get('/api/reports').json()['total'] == 0
    assert client.get('/api/emails/latest/analysis').status_code == 404
    emails = []
    for number in (1, 2, 3):
        raw, data = ingest(client, number)
        emails.append(data)
        assert data['email_sha256'] == hashlib.sha256(raw).hexdigest()
        assert data['size'] == len(raw)
        assert data['authentication']['dkim']['result'] != 'pass'
        intel = data['ip_intelligence']['8.8.8.8']
        assert intel['enrichment_available'] is False
        assert intel['latitude'] is None and intel['longitude'] is None
        assert data['ai_analyst']['available'] is False
        restored = client.get(f"/api/emails/{data['id']}/analysis")
        assert restored.status_code == 200
        assert restored.json() == data
        summary = client.get('/api/dashboard/summary').json()
        assert summary['metrics']['emails_analyzed'] == number
        assert len(summary['recent_emails']) == number
        assert summary['top_countries'] == []
        assert client.get('/api/campaigns').json() == []
        with sessions() as db:
            row = db.query(EmailAnalysisModel).filter_by(evidence_id=data['id']).one()
            assert row.threat_score == data['threat_score']['score']
            assert json.loads(row.indicators_json)['ips'] == data['ips']
            assert db.get(AnalysisPayloadModel, data['id']) is not None
        graph = data['investigation_graph']
        assert any(n['id'] == f"email:{data['id']}" for n in graph['nodes'])
        assert not any(n['type'] in ('Campaign', 'Country', 'ASN') for n in graph['nodes'])
        assert all(e['source'] in {n['id'] for n in graph['nodes']} and e['target'] in {n['id'] for n in graph['nodes']} for e in graph['edges'])
        related = client.post('/api/cross-investigation/analyze', json={'id': data['id']})
        assert related.status_code == 200, related.text
        assert set(r['id'] for r in related.json()['related_emails']) <= {e['id'] for e in emails[:-1]}
        if number == 1:
            assert related.json()['related_emails'] == related.json()['timeline'] == []
            assert related.json()['campaign_confidence'] is None
    ids = [e['id'] for e in emails]
    comparison = client.post('/api/cross-investigation/compare', json={'email_ids': ids})
    assert comparison.status_code == 200, comparison.text
    assert {e['id'] for e in comparison.json()['emails']} == set(ids)
    graph = client.post('/api/cross-investigation/graph', json={'email_ids': ids}).json()
    assert {n['id'] for n in graph['nodes'] if n['type'] == 'Email'} == {f'email:{i}' for i in ids}
    decision = client.post('/api/cross-investigation/decision', json={'email_id_a': ids[0], 'email_id_b': ids[1], 'decision': 'mark_unrelated'})
    assert decision.status_code == 200
    related = client.post('/api/cross-investigation/analyze', json={'id': ids[0]}).json()
    assert ids[1] not in {r['id'] for r in related['related_emails']}
    # Tampered client metadata is ignored when linking canonical stored evidence.
    case = client.post('/api/cases', json={'title': 'Integrity case'}).json()
    linked = client.post(f"/api/cases/{case['id']}/emails", json={'email_id': ids[0], 'threat_score': 99, 'subject': 'Invented subject'})
    assert linked.status_code == 201, linked.text
    assert linked.json()['subject'] == emails[0]['subject']
    assert linked.json()['threat_score'] == emails[0]['threat_score']['score']
    assert client.get('/api/dashboard/summary').json()['metrics']['open_cases'] == 1
    report = client.post('/api/reports/generate?format=json', json={'analysis': {'id': ids[0], 'subject': 'Fabricated report'}})
    assert report.status_code == 200, report.text
    assert emails[0]['subject'] in report.json()['title']


def test_unknown_and_demo_never_create_evidence(clean_client):
    client, sessions = clean_client
    for id in ('demo', 'sample-001', 'latest', 'missing'):
        assert client.get(f'/api/emails/{id}/analysis').status_code == 404
        assert client.get(f'/api/emails/{id}/confidence').status_code == 404
        assert client.get(f'/api/emails/{id}/attribution').status_code == 404
        assert client.get(f'/api/emails/{id}/timeline').json()['events'] == []
    assert client.get('/api/campaigns/C-042/graph').status_code == 404
    assert client.post('/api/cross-investigation/compare', json={'email_ids': ['missing-a', 'missing-b']}).status_code == 404
    payload = {'id': 'scenario-3-campaign', 'is_demo': True}
    assert client.post('/api/cross-investigation/analyze', json=payload).status_code == 422
    assert client.post('/api/reports/generate', json={'analysis': payload}).status_code == 422
    assert client.post('/api/copilot/query', json={'query': 'Explain', 'email_payload': payload}).status_code == 422
    with sessions() as db:
        assert db.query(EvidenceModel).count() == db.query(AuditLogModel).count() == db.query(CampaignModel).count() == 0
    demo = client.get('/api/benchmark/scenarios')
    assert demo.status_code == 200
    assert client.get('/api/dashboard/summary').json()['metrics']['emails_analyzed'] == 0


@pytest.mark.anyio
async def test_provider_exception_and_mock_configuration_never_enrich():
    class BrokenProvider(BaseIPIntelligenceProvider):
        async def lookup(self, ip):
            raise RuntimeError('provider outage')
    service = IPIntelligenceService(provider=BrokenProvider(), cache=IPIntelligenceCache())
    result = await service.get_ip_intelligence('8.8.8.8')
    assert result.enrichment_available is False
    assert result.latitude is result.longitude is result.asn is result.country is None
    service = IPIntelligenceService(config=GeolocationConfig(provider='mock'), cache=IPIntelligenceCache())
    result = await service.get_ip_intelligence('8.8.8.8')
    assert result.enrichment_available is False
    assert 'not configured' in result.error.lower()


def test_production_does_not_import_test_or_demo_fixtures():
    root = Path(__file__).resolve().parents[2]
    for p in (root / 'backend').rglob('*.py'):
        if any(part in ('tests', 'venv', '__pycache__') for part in p.parts):
            continue
        text = p.read_text()
        assert 'from backend.tests' not in text, p
        assert 'import backend.tests' not in text, p
    for p in (root / 'src').rglob('*.tsx'):
        text = p.read_text()
        assert 'mockData' not in text and 'buildFallback' not in text, p
        assert 'Math.random' not in text, p
        if '/data/demo/' in text:
            assert p.name == 'EmailForensicView.tsx', p
