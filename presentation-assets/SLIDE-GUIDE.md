# CyberGuard presentation assets — 12 October 2026

Screenshots are real captures from the already open app at localhost:5173. That process still uses the previous UI/backend. They illustrate the existing workflows, **not deployment or visual verification of the new trained detector**. The report library shown is empty. No investigation records were created or modified for these captures.

| Slide | Topic | Asset / suggested content |
|---|---|---|
| 2 | What CyberGuard has | 02-overview-existing-ui.jpg — one workspace for phishing, identity and access investigations |
| 3 | What it is designed for | 03-detection-existing-ui.jpg — bring original evidence into focused analysis |
| 4 | Core capabilities | 04-identity-existing-ui.jpg — trusted profiles, claimed sender comparison; also discuss trained face inference as newly implemented, awaiting live UI verification |
| 5 | Key threat scenarios | 05-threat-scenarios-existing-ui.jpg — password spray, brute force, account takeover, MFA fatigue; scenarios shown are synthetic |
| 6 | What the project delivers | 06-reports-existing-ui.jpg — reporting interface; this live workspace has no saved reports |
| 7 | Benefits | 07-benefits.svg — intended benefits, with no invented measured improvement |
| 8 | Scalability | 08-scalability.svg — architecture direction, not a proven production scale claim |
| 9 | Expansion vision | 09-vision.svg — future evaluation, audio models, integrations and production readiness |

The SVGs are explanatory presentation graphics, not application screenshots. PowerPoint can insert SVG images directly.

## Trained detector
Pretrained Apache-2.0 face-image ViT: https://huggingface.co/prithivMLmods/Deep-Fake-Detector-v2-Model
Pinned revision: 3a99ae26f52c7ac7c3a53103b6cf3a8b617f7093. Verified safetensors only, offline CPU inference, maximum four detected face crops and eight sampled video frames, 30-second subprocess deadline, two CPU threads, one concurrent inference.

A model score is not calibrated confidence or proof that the entire recording is real/fake. Audio has no trained detector. Independent accuracy, false-positive rates and demographic/generalization evaluation remain unverified. A public NASA portrait smoke test returned UNCERTAIN, demonstrating execution rather than reliable classification.

Public-domain NASA portrait source: https://scikit-image.org/docs/stable/api/skimage.data.html#skimage.data.astronaut (Eileen Collins). The source-samples directory is excluded from the presentation ZIP.

## Restart to load updated source
Use the existing local launcher after stopping the existing managed servers. Do not reset the database. The launcher makes a SQLite backup before starting and retains token-free local prototype mode. Production/staging protection was not changed.

Updated detector route: /#/media-authenticity. A fresh updated media screenshot still requires a running updated frontend/backend.

Automatic approval review blocked both isolated presentation-server startup attempts, including authentication-enabled startup, with no specific reason supplied. No replacement server was started.

Important model limitation: the actual MP4 API smoke built from the same real NASA photograph returned DEEPFAKE_LIKELY (0.7584), a false positive. Present pretrained inference as experimental capability, not reliable detection or verified media authenticity. Both actual image and video API calls completed in temporary storage with live-file integrity checks.
