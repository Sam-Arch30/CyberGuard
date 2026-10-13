"""Actual offline image/video API smoke in temporary storage, not an accuracy test."""
import json, os, subprocess, sys, tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.sample_audit_runtime import configure, verify_unchanged
root = Path(tempfile.mkdtemp(prefix='cyberguard-sample-audit-trained-'))
baseline = configure(root)
os.environ['CYBERGUARD_DEEPFAKE_ENABLED'] = 'true'
from backend.services.deepfake_model import MODEL_DIR
os.environ['CYBERGUARD_DEEPFAKE_MODEL_DIR'] = str(MODEL_DIR)
from backend.services.media_decoder import decoder_executable
from backend.main import app
from fastapi.testclient import TestClient
project = Path(__file__).resolve().parents[1]
photo = project / 'presentation-assets/source-samples/nasa-astronaut.png'
video = root / 'portrait-fixture.mp4'
subprocess.run([decoder_executable(), '-nostdin', '-loglevel', 'error', '-loop', '1', '-i', str(photo), '-t', '2', '-vf', 'scale=512:512', '-threads', '2', '-pix_fmt', 'yuv420p', str(video)], timeout=20, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
results = {}
try:
    with TestClient(app, raise_server_exceptions=False) as client:
        for path, mime in [(photo, 'image/png'), (video, 'video/mp4')]:
            ingestion = client.post('/api/ingest', files={'file': (path.name, path.read_bytes(), mime)})
            assert ingestion.status_code == 200, ingestion.text
            response = client.post('/api/multimedia/analyze', json={'artifact_id': ingestion.json()['artifact_id']})
            assert response.status_code == 200, response.text
            assessment = response.json()['assessment']
            assert assessment['processing_status'] == 'COMPLETED'
            assert assessment['trained_detector']['status'] == 'COMPLETED'
            assert assessment['trained_detector']['calibrated'] is False
            assert 1 <= assessment['trained_detector']['faces_analyzed'] <= 4
            assert assessment['confidence'] == 0
            results[path.suffix] = {'http_status': response.status_code, 'processing_status': assessment['processing_status'], 'trained_detector': assessment['trained_detector']}
    output = project / 'presentation-assets/verification/trained-api-smoke.json'
    output.write_text(json.dumps(results, indent=2), encoding='utf-8')
    print(json.dumps(results, indent=2))
finally:
    verify_unchanged(baseline)
