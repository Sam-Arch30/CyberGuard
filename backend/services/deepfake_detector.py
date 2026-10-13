"""Offline, bounded pretrained facial-image inference. Scores are not calibrated."""
import hashlib, io, json, os, subprocess, sys, tempfile, threading
from pathlib import Path
from PIL import Image
from backend.services.deepfake_model import MODEL_DIR, MODEL_ID, REVISION, HASHES
_LOCK = threading.Lock()
_VERIFIED = None
LIMITATIONS = ['Face-image classifier applied to at most four face crops; video temporal authenticity and audio are not evaluated.', 'Model softmax scores are uncalibrated. Compression, demographics and unseen generators can change performance.', 'CyberGuard has not independently measured real-world deepfake accuracy.']
def predict_faces(data, media_type, frames):
    result = dict(status='MODEL_UNAVAILABLE', model=MODEL_ID, revision=REVISION, calibrated=False, limitations=LIMITATIONS, faces_analyzed=0)
    if media_type not in ('IMAGE', 'VIDEO'):
        return {**result, 'status': 'UNSUPPORTED_MEDIA_TYPE'}
    if os.environ.get('CYBERGUARD_DEEPFAKE_ENABLED', 'true').lower() != 'true':
        return {**result, 'status': 'DISABLED'}
    folder = Path(os.environ.get('CYBERGUARD_DEEPFAKE_MODEL_DIR', str(MODEL_DIR)))
    try:
        global _VERIFIED
        signature = tuple((str(folder / n), (folder / n).stat().st_mtime_ns, (folder / n).stat().st_size) for n in HASHES)
        if signature != _VERIFIED:
            for name, expected in HASHES.items():
                with (folder / name).open('rb') as stream:
                    if hashlib.file_digest(stream, 'sha256').hexdigest() != expected:
                        return {**result, 'status': 'MODEL_INTEGRITY_ERROR'}
            _VERIFIED = signature
        import cv2
        import numpy as np
    except (ImportError, OSError):
        return result
    if os.environ.get('CYBERGUARD_DEEPFAKE_RESEARCH_MODE', 'false').lower() != 'true':
        return {**result, 'status': 'MODEL_NOT_VALIDATED',
                'limitations': ['This model failed the collected real/fake sample checks and is withheld from normal verdicts. Raw inference requires explicit research mode.', *LIMITATIONS]}
    if not _LOCK.acquire(blocking=False): return {**result, 'status': 'BUSY'}
    try:
        with tempfile.TemporaryDirectory(prefix='cyberguard-face-') as temporary:
            root = Path(temporary); crops = []; locations = []
            cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
            if cascade.empty(): return {**result, 'status': 'FACE_DETECTOR_UNAVAILABLE'}
            sources = [(0, 0.0, data)] if media_type == 'IMAGE' else frames[:8]
            for index, timestamp, content in sources:
                with Image.open(io.BytesIO(content)) as image:
                    if image.width * image.height > 16_000_000: return {**result, 'status': 'RESOURCE_LIMIT'}
                    image = image.convert('RGB'); image.thumbnail((640, 640))
                    gray = cv2.cvtColor(np.asarray(image), cv2.COLOR_RGB2GRAY)
                    faces = cascade.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5, minSize=(40, 40))
                    for x, y, w, h in sorted(faces, key=lambda box: int(box[2]) * int(box[3]), reverse=True):
                        margin = int(max(w, h) * .2)
                        crop = image.crop((max(0, int(x)-margin), max(0, int(y)-margin), min(image.width, int(x+w)+margin), min(image.height, int(y+h)+margin))).resize((224,224))
                        name = root / f'face-{len(crops)}.png'; crop.save(name); crops.append(str(name))
                        locations.append({'frame_index': index, 'timestamp_seconds': timestamp})
                        if len(crops) == 4: break
                if len(crops) == 4: break
            if not crops: return {**result, 'status': 'NO_ELIGIBLE_FACE'}
            (root / 'request.json').write_text(json.dumps({'model_dir': str(folder), 'crops': crops}), encoding='utf-8')
            environment = {**os.environ, 'HF_HUB_OFFLINE': '1', 'TRANSFORMERS_OFFLINE': '1', 'HF_HUB_DISABLE_TELEMETRY': '1', 'OMP_NUM_THREADS': '2'}
            try:
                process = subprocess.run([sys.executable, '-m', 'backend.services.deepfake_worker', str(root)], cwd=Path(__file__).resolve().parents[2], env=environment, timeout=30, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            except subprocess.TimeoutExpired: return {**result, 'status': 'PROCESSING_TIMEOUT'}
            output = root / 'result.json'
            if process.returncode != 0 or not output.exists() or output.stat().st_size > 65536:
                return {**result, 'status': 'INFERENCE_FAILED'}
            prediction = json.loads(output.read_text(encoding='utf-8'))
            return {**result, **prediction, 'status': 'COMPLETED', 'faces_analyzed': len(crops), 'sample_locations': locations}
    except (OSError, ValueError, RuntimeError):
        return {**result, 'status': 'INFERENCE_FAILED'}
    finally:
        _LOCK.release()
