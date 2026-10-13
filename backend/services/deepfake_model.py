"""Pinned provenance shared by installer and offline inference."""
from pathlib import Path
MODEL_ID = 'prithivMLmods/Deep-Fake-Detector-v2-Model'
REVISION = '3a99ae26f52c7ac7c3a53103b6cf3a8b617f7093'
MODEL_DIR = Path(__file__).resolve().parents[1] / 'data/models/deepfake_vit'
HASHES = {
 'model.safetensors': '88ac0939285009e3700cfc9b9a0912b14b092d200ef0df86efe4f2cf190ea4de',
 'config.json': 'b2a87a8b9c4fedab5ba35c3cd4cb3b3ba927c595c356a4897c7bd7713ea25565',
 'preprocessor_config.json': '445c77049d082004aa07593344d5e1f521f1198228bf586196f70ce7ae021414',
}
