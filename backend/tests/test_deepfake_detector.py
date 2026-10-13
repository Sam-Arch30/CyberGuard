import pytest

@pytest.fixture(autouse=True)
def explicit_research_mode(monkeypatch):
    monkeypatch.setenv("CYBERGUARD_DEEPFAKE_RESEARCH_MODE", "true")

import io
from PIL import Image
from backend.services.deepfake_detector import predict_faces

def test_audio_has_explicit_unsupported_state():
    result = predict_faces(b'audio', 'AUDIO', [])
    assert result['status'] == 'UNSUPPORTED_MEDIA_TYPE'
    assert result['calibrated'] is False
    assert 'deepfake_score' not in result

def test_missing_model_has_no_prediction(monkeypatch, tmp_path):
    monkeypatch.setenv('CYBERGUARD_DEEPFAKE_ENABLED', 'true')
    monkeypatch.setenv('CYBERGUARD_DEEPFAKE_MODEL_DIR', str(tmp_path))
    result = predict_faces(b'image', 'IMAGE', [])
    assert result['status'] == 'MODEL_UNAVAILABLE'
    assert 'prediction' not in result

def test_disabled_model_never_implies_real():
    result = predict_faces(b'image', 'IMAGE', [])
    assert result['status'] == 'DISABLED'
    assert 'deepfake_score' not in result

def test_tampered_model_fails_closed(monkeypatch, tmp_path):
    from backend.services.deepfake_model import HASHES
    for name in HASHES: (tmp_path / name).write_bytes(b'changed')
    monkeypatch.setenv('CYBERGUARD_DEEPFAKE_ENABLED', 'true')
    monkeypatch.setenv('CYBERGUARD_DEEPFAKE_MODEL_DIR', str(tmp_path))
    assert predict_faces(b'image', 'IMAGE', [])['status'] == 'MODEL_INTEGRITY_ERROR'

def test_no_face_is_not_a_real_verdict(monkeypatch, tmp_path):
    import hashlib
    import backend.services.deepfake_detector as detector
    payload = b'fixture-config'
    monkeypatch.setattr(detector, 'HASHES', {'config.json': hashlib.sha256(payload).hexdigest()})
    (tmp_path / 'config.json').write_bytes(payload)
    monkeypatch.setenv('CYBERGUARD_DEEPFAKE_ENABLED', 'true')
    monkeypatch.setenv('CYBERGUARD_DEEPFAKE_MODEL_DIR', str(tmp_path))
    image = io.BytesIO(); Image.new('RGB', (100,100), 'white').save(image, 'PNG')
    result = predict_faces(image.getvalue(), 'IMAGE', [])
    assert result['status'] == 'NO_ELIGIBLE_FACE'
    assert result['faces_analyzed'] == 0
    assert 'prediction' not in result

def test_face_inference_deadline_and_crop_cap(monkeypatch, tmp_path):
    import hashlib, subprocess
    import backend.services.deepfake_detector as detector
    import cv2
    payload = b'fixture-config'
    monkeypatch.setattr(detector, 'HASHES', {'config.json': hashlib.sha256(payload).hexdigest()})
    (tmp_path / 'config.json').write_bytes(payload)
    monkeypatch.setenv('CYBERGUARD_DEEPFAKE_ENABLED', 'true')
    monkeypatch.setenv('CYBERGUARD_DEEPFAKE_MODEL_DIR', str(tmp_path))
    class Faces:
        def empty(self): return False
        def detectMultiScale(self, *args, **kwargs): return [(10,10,50,50)] * 12
    monkeypatch.setattr(cv2, 'CascadeClassifier', lambda _: Faces())
    def timeout(args, **kwargs):
        import json
        from pathlib import Path
        assert kwargs['timeout'] == 30
        assert kwargs['env']['HF_HUB_OFFLINE'] == '1'
        assert kwargs['stdin'] == subprocess.DEVNULL
        assert kwargs.get('shell', False) is False
        request = json.loads((Path(args[-1]) / 'request.json').read_text())
        assert len(request['crops']) == 4
        raise subprocess.TimeoutExpired(args, 30)
    monkeypatch.setattr(detector.subprocess, 'run', timeout)
    image = io.BytesIO(); Image.new('RGB', (100,100), 'white').save(image, 'PNG')
    result = predict_faces(image.getvalue(), 'IMAGE', [])
    assert result['status'] == 'PROCESSING_TIMEOUT'
    assert 'deepfake_score' not in result
