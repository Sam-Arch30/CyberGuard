"""Isolated CPU inference worker; only known local ViT safetensors are loaded."""
import json, sys
from pathlib import Path
import torch
from PIL import Image
from transformers import ViTImageProcessor, ViTForImageClassification
torch.set_num_threads(2)
torch.set_num_interop_threads(1)
root = Path(sys.argv[1]); request = json.loads((root / 'request.json').read_text(encoding='utf-8'))
processor = ViTImageProcessor.from_pretrained(request['model_dir'], local_files_only=True)
model = ViTForImageClassification.from_pretrained(request['model_dir'], local_files_only=True, use_safetensors=True).eval()
if model.config.id2label != {0: 'Realism', 1: 'Deepfake'}: raise ValueError('Unexpected class mapping')
images = [Image.open(path).convert('RGB') for path in request['crops'][:4]]
with torch.inference_mode():
    scores = torch.softmax(model(**processor(images=images, return_tensors='pt')).logits, dim=-1)[:, 1].tolist()
mean = sum(scores) / len(scores)
(root / 'result.json').write_text(json.dumps({'prediction': 'UNCERTAIN' if .3 <= mean <= .7 else 'DEEPFAKE_LIKELY' if mean > .7 else 'REAL_LIKELY', 'deepfake_score': mean, 'face_scores': scores}), encoding='utf-8')
