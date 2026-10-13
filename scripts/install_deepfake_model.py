"""Install only checksum-verified safetensors and configuration, never remote code."""
import hashlib, sys, urllib.request, uuid
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from backend.services.deepfake_model import MODEL_DIR, MODEL_ID, REVISION, HASHES
MODEL_DIR.mkdir(parents=True, exist_ok=True)
for name, expected in HASHES.items():
    target = MODEL_DIR / name
    if target.exists():
        if hashlib.sha256(target.read_bytes()).hexdigest() != expected:
            raise RuntimeError(f'Existing {name} has an unexpected checksum; preserved without replacement')
        print(f'Verified {name}', flush=True)
        continue
    partial = MODEL_DIR / (name + '.' + uuid.uuid4().hex + '.part')
    digest = hashlib.sha256(); total = 0
    try:
        with urllib.request.urlopen(f'https://huggingface.co/{MODEL_ID}/resolve/{REVISION}/{name}', timeout=60) as response, partial.open('wb') as output:
            while block := response.read(1024 * 1024):
                total += len(block)
                if total > 345_000_000: raise RuntimeError('Model download exceeds expected bound')
                digest.update(block); output.write(block)
        if digest.hexdigest() != expected: raise RuntimeError(f'Checksum mismatch: {name}')
        partial.replace(target)
        print(f'Installed verified {name}: {total} bytes', flush=True)
    finally:
        partial.unlink(missing_ok=True)
