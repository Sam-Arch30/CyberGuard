import asyncio

from fastapi.testclient import TestClient
from backend.main import app
from backend.db.session import SessionLocal
from backend.db.models import FindingModel, AnalysisRunModel, IndicatorModel
from backend.services.analysis_orchestrator import AnalysisOrchestrator
from backend.services.file_security_analyzers import FileIOCAnalyzer


def test_defanged_urls_equivalent_and_bounded():
    raw = b'https://example.test/login\nhttp://other.test/a'
    defanged = b'hxxps://example[.]test/login\nhxxp://other[.]test/a'
    assert FileIOCAnalyzer().analyze(raw)[1] == FileIOCAnalyzer().analyze(defanged)[1]
    _, observed = FileIOCAnalyzer().analyze(b'\n'.join(f'hxxps://host{i}[.]test/a'.encode() for i in range(200)))
    assert len(observed['urls']) == 50


def test_normal_text_negative_control():
    findings, observed = FileIOCAnalyzer().analyze(b'Project meeting at ten tomorrow.')
    assert observed['urls'] == []
    assert findings.findings == []


def test_ingested_defanged_list_executes_actual_extraction():
    payload = b'hxxps://example[.]test/login\nhxxps://other[.]test/payment'
    with TestClient(app) as client:
        response = client.post('/api/ingest', files={'file': ('test-list.txt', payload, 'text/plain')})
        assert response.status_code == 200
        run_id = response.json()['analysis_run_id']
        with SessionLocal() as db:
            asyncio.run(AnalysisOrchestrator.execute_run(db, run_id))
            findings = db.query(FindingModel).filter_by(analysis_run_id=run_id).all()
            assert any(f.finding_type == 'EXTERNAL_URL_EMBEDDED' for f in findings)
            assert db.query(IndicatorModel).filter_by(indicator_type='URL', normalized_value='https://example.test/login').first()
            run = db.get(AnalysisRunModel, run_id)
            assert run.overall_severity != 'SAFE'
            assert run.confidence == 0

        projection = client.get(f"/api/analysis/{run_id}/results")
        assert projection.status_code == 200
        assert len(projection.json()['indicators_summary']['urls']) == 2
