"""Tests never connect to the developer database or overwrite evaluation results."""
import os
import tempfile
from pathlib import Path
import pytest

TEST_ROOT = Path(tempfile.mkdtemp(prefix='mailtrace-tests-'))
os.environ['DATABASE_URL'] = f'sqlite:///{TEST_ROOT / "test.db"}'
os.environ['BENCHMARK_RESULTS_PATH'] = str(TEST_ROOT / 'benchmark_results.json')
os.environ['RATE_LIMIT_ENABLED'] = 'false'
os.environ.pop('LLM_PROVIDER', None)

@pytest.fixture
def stored_analysis():
    """Explicit persisted fixtures for API unit tests, never production bootstrap."""
    import json
    from backend.db.session import SessionLocal
    from backend.db.models import AnalysisPayloadModel
    def store(identifier, **fields):
        data = {'id': identifier, 'evidence_id': identifier, **fields}
        with SessionLocal() as db:
            row = db.get(AnalysisPayloadModel, identifier)
            if row:
                row.analysis_json = json.dumps(data)
            else:
                db.add(AnalysisPayloadModel(evidence_id=identifier, analysis_json=json.dumps(data)))
            db.commit()
        return data
    return store
