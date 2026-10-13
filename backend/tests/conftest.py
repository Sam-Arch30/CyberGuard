"""Tests never connect to the developer database or overwrite evaluation results."""
import os
import tempfile
from pathlib import Path
import pytest

TEST_ROOT = Path(tempfile.mkdtemp(prefix='mailtrace-tests-'))
os.environ['CYBERGUARD_DEEPFAKE_ENABLED'] = 'false'
os.environ['CYBERGUARD_DEEPFAKE_MODEL_DIR'] = str(TEST_ROOT / 'models')
os.environ['DATABASE_URL'] = f'sqlite:///{TEST_ROOT / "test.db"}'
os.environ['BENCHMARK_RESULTS_PATH'] = str(TEST_ROOT / 'benchmark_results.json')
os.environ['CYBERGUARD_EML_STORE'] = str(TEST_ROOT / 'eml')
os.environ['CYBERGUARD_REPORTS_DIR'] = str(TEST_ROOT / 'reports')
os.environ['CYBERGUARD_STORAGE_ROOT'] = str(TEST_ROOT / 'storage')
os.environ['CONTINUAL_LEARNING_CANDIDATES_DIR'] = str(TEST_ROOT / 'candidates')
# Legacy feature tests run in explicit isolated demo mode; security tests override it.
os.environ['CYBERGUARD_DEMO_MODE'] = 'true'
os.environ['CYBERGUARD_REQUIRE_AUTH'] = 'false'
os.environ['ALLOW_WORKSPACE_RESET'] = 'true'
os.environ['BACKGROUND_WORKER_ENABLED'] = 'false'
os.environ['RATE_LIMIT_ENABLED'] = 'false'
os.environ.pop('LLM_PROVIDER', None)

import hashlib
ROOT_DIR = Path(__file__).resolve().parents[2]
def _data_state():
    directories = [ROOT_DIR / 'backend/data', ROOT_DIR / 'backend/app/ml/models']
    return {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for directory in directories for p in directory.rglob('*') if p.is_file() and '__pycache__' not in p.parts and p.suffix != '.pyc'}
_INITIAL_DATA = _data_state()

@pytest.fixture(autouse=True, scope='session')
def preserve_investigation_files():
    yield
    assert _data_state() == _INITIAL_DATA, 'Tests modified repository investigation or model files'

from backend.db.session import init_db
init_db(max_retries=1, retry_delay=0.1)

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


@pytest.fixture(autouse=True)
def preserve_global_ml_classifier():
    """Ensure global ML classifier state is not permanently mutated across tests."""
    from backend.app.ml.classifier import global_phishing_classifier, PhishingClassifier
    orig_path = global_phishing_classifier.model_path
    yield
    global_phishing_classifier.model_path = PhishingClassifier.DEFAULT_MODEL_PATH
    global_phishing_classifier._load_model()

