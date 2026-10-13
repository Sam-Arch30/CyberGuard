"""Configure and verify isolated audit storage before importing application modules."""
import hashlib
import os
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def data_state():
    return {str(p): hashlib.sha256(p.read_bytes()).hexdigest()
            for directory in (ROOT / 'backend/data', ROOT / 'backend/app/ml/models')
            for p in directory.rglob('*') if p.is_file() and '__pycache__' not in p.parts and p.suffix != '.pyc'}


def configure(test_root):
    test_root = Path(test_root).resolve()
    temporary = Path(tempfile.gettempdir()).resolve()
    assert test_root.is_relative_to(temporary) and test_root.name.startswith('cyberguard-sample-audit-'), 'Audit runtime must be in its dedicated temporary directory'
    assert not test_root.is_relative_to(ROOT), 'Audit runtime must not be inside the repository'
    paths = {'DATABASE_URL': test_root / 'test.db', 'CYBERGUARD_STORAGE_ROOT': test_root / 'storage',
             'CYBERGUARD_REPORTS_DIR': test_root / 'reports', 'CYBERGUARD_EML_STORE': test_root / 'eml',
             'BENCHMARK_RESULTS_PATH': test_root / 'benchmark.json', 'CONTINUAL_LEARNING_CANDIDATES_DIR': test_root / 'candidates'}
    for key, path in paths.items():
        assert path.resolve().is_relative_to(test_root)
        os.environ[key] = 'sqlite:///' + path.as_posix() if key == 'DATABASE_URL' else str(path)
    os.environ.update({'BACKGROUND_WORKER_ENABLED': 'false', 'CYBERGUARD_DEMO_MODE': 'true', 'CYBERGUARD_REQUIRE_AUTH': 'false',
                       'CYBERGUARD_ENV': 'DEVELOPMENT', 'ENVIRONMENT': 'development', 'ALLOW_WORKSPACE_RESET': 'false',
                       'RATE_LIMIT_ENABLED': 'false', 'IP_INTELLIGENCE_PROVIDER': 'mock', 'LLM_PROVIDER': ''})
    for key in ('GEMINI_API_KEY', 'OPENAI_API_KEY', 'LLM_API_KEY', 'IP_INTELLIGENCE_API_KEY', 'IPAPI_KEY', 'IPINFO_API_KEY', 'IPINFO_TOKEN', 'VIRUSTOTAL_API_KEY', 'ABUSEIPDB_API_KEY', 'OTX_API_KEY'):
        os.environ.pop(key, None)
    return data_state()


def verify_unchanged(baseline):
    assert data_state() == baseline, 'Audit changed live investigation or model files'
