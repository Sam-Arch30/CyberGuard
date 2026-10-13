"""Create real sample results in a new isolated presentation database, never live data."""
import asyncio
import json
import sys
import tempfile
from pathlib import Path
from sample_audit_runtime import configure, verify_unchanged

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
TEMP = Path(tempfile.mkdtemp(prefix='cyberguard-sample-audit-presentation-'))
baseline = configure(TEMP)
from fastapi.testclient import TestClient
from backend.main import app
from backend.db.session import init_db, SessionLocal
from backend.services.analysis_orchestrator import AnalysisOrchestrator

init_db(max_retries=1)
records = {}
with TestClient(app, raise_server_exceptions=False) as client:
    for path in sorted((ROOT / 'samples/01-email').glob('*.eml')):
        response = client.post('/api/ingest', files={'file': (path.name, path.read_bytes(), 'message/rfc822')})
        assert response.status_code == 200, response.text
        original = response.json()
        with SessionLocal() as db:
            asyncio.run(AnalysisOrchestrator.execute_run(db, original['analysis_run_id']))
        analysis = client.post('/api/emails/analyze', files={'file': (path.name, path.read_bytes(), 'message/rfc822')})
        assert analysis.status_code == 200, analysis.text
        data = analysis.json()
        report = client.post('/api/reports/generate?format=json', json={'analysis': {'id': data.get('evidence_id') or data.get('id')}, 'analyst_name': 'Synthetic demonstration'})
        assert report.status_code == 200, report.text
        records[path.stem] = {**original, 'report_id': report.json()['id']}
    path = ROOT / 'samples/05-video/synthetic-color-bars.mp4'
    response = client.post('/api/ingest', files={'file': (path.name, path.read_bytes(), 'video/mp4')})
    assert response.status_code == 200, response.text
    records['video'] = response.json()
    with SessionLocal() as db:
        asyncio.run(AnalysisOrchestrator.execute_run(db, response.json()['analysis_run_id']))
    profile = client.post('/api/impersonation/profiles', json=json.loads((ROOT / 'samples/07-identity/trusted-profile.json').read_text()))
    assert profile.status_code == 201, profile.text
    records['profile'] = profile.json()
verify_unchanged(baseline)
runtime = ROOT / '.local-runtime'
runtime.mkdir(exist_ok=True)
(runtime / 'presentation-data.json').write_text(json.dumps({'test_root': str(TEMP), 'records': records}, indent=2), encoding='utf-8')
print('Prepared isolated presentation data:', TEMP)
