# Pretrained face detector

Install optional dependencies with `backend/venv/Scripts/python.exe -m pip install -r backend/requirements-deepfake.txt` (CPU Torch can be installed from the official PyTorch CPU index). Then run `backend/venv/Scripts/python.exe scripts/install_deepfake_model.py`.

Model: https://huggingface.co/prithivMLmods/Deep-Fake-Detector-v2-Model (Apache-2.0), pinned revision `3a99ae26f52c7ac7c3a53103b6cf3a8b617f7093`. Only SHA-256 verified safetensors/configuration files are installed. No pickle weights, remote model code, runtime downloads or cloud inference. Large weights are excluded from Git.

Scope: detected frontal faces in images and at most eight already-decoded video frames. At most four face crops, two CPU threads, one concurrent inference and a 30-second worker deadline. The model receives only bounded 224px face crops. Original evidence is not modified. The parent records the model result and revision in the canonical analysis-run metadata; heuristic scores remain separate.

Model outputs are uncalibrated scores. The prototype uses an explicit 0.3–0.7 uncertainty band, not a validated operating threshold. Class mapping is verified (`Realism`, `Deepfake`). No-face, missing decoder/model, checksum mismatch, timeout and inference failure do not produce real/safe predictions. Audio requires another model and currently returns unsupported trained-media scope.

Use `CYBERGUARD_DEEPFAKE_ENABLED=false` to disable optional inference. `CYBERGUARD_DEEPFAKE_MODEL_DIR` selects a local directory, but all configured files must retain the pinned checksums. Tests default to a disabled model and a temporary model directory; model-specific tests explicitly override this with isolated fixtures. Live original evidence and database records are integrity-checked.

Validation: one public-domain NASA photograph ran through real inference and returned UNCERTAIN (0.6878 deepfake softmax score). Four repeated samples also exercised the video-frame entry point. This is an execution smoke test, not held-out accuracy validation or end-to-end real-video evaluation. Independent real/fake benchmark, generator/domain shift, demographic fairness and calibration evaluations remain pending. Do not advertise the model author's reported accuracy as CyberGuard accuracy.

Observed limitation: the actual MP4 API smoke, made by repeating the real NASA portrait, returned DEEPFAKE_LIKELY (0.7584). This is a false positive on a known real-source fixture. The image returned UNCERTAIN (0.6878). Model and face-crop/compression sensitivity require further evaluation before operational use.
