"""Read-only section API smoke audit in a fresh, integrity-checked temporary workspace."""
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from sample_audit_runtime import configure, verify_unchanged

TEMP = Path(tempfile.mkdtemp(prefix='cyberguard-sample-audit-sections-'))
baseline = configure(TEMP)
from backend.main import app
from fastapi.testclient import TestClient

OUT = ROOT / '.local-runtime' / 'readiness'
OUT.mkdir(parents=True, exist_ok=True)
checks, skipped = [], []
try:
    with TestClient(app, raise_server_exceptions=False) as client:
        for path, operations in sorted(app.openapi()['paths'].items()):
            operation = operations.get('get')
            if not operation:
                continue
            if '{' in path or any(p.get('required') for p in operation.get('parameters', [])):
                skipped.append({'path': path, 'reason': 'Requires explicit object or query input'})
                continue
            if any(word in path for word in ('/stream', '/download', '/export', '/reset', '/backup', '/test-')):
                skipped.append({'path': path, 'reason': 'Stream/file/action excluded from collection smoke check'})
                continue
            response = client.get(path)
            checks.append({'path': path, 'status': response.status_code,
                           'detail': response.text[:500] if response.status_code >= 400 else ''})
            print(response.status_code, path, flush=True)
finally:
    verify_unchanged(baseline)
    failures = [c for c in checks if c['status'] >= 500]
    (OUT / 'section-api-audit.json').write_text(json.dumps({'test_root': str(TEMP), 'checks': checks,
        'server_errors': failures, 'skipped': skipped, 'live_integrity_verified': True}, indent=2), encoding='utf-8')
print(f'COLLECTION_API_CHECKS={len(checks)} SERVER_ERRORS={len(failures)} SKIPPED={len(skipped)} LIVE_INTEGRITY_VERIFIED')
sys.exit(bool(failures))
