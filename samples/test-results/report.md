# CyberGuard sample test report

Date: 2026-10-13

Tested 40 files with 96 checks: 91 PASS, 5 WARN, 0 FAIL.

## Verdict

Sample controls pass; prototype capabilities remain limited.

## Detection controls

Authentication: JSON 65.0 / CREDENTIAL_ATTACK_DETECTED; equivalent JSONL 65.0 / CREDENTIAL_ATTACK_DETECTED.
Identity frontend contract: trusted 0.0 / NO_IMPERSONATION_EVIDENCE; suspicious 60.0 / IMPERSONATION_SUSPECTED.
Malformed authentication JSON: HTTP 422.

## Scope and remaining limitations

- Real FastAPI routes against an isolated database copy and temporary evidence/report/EML/benchmark/model candidate paths. Live investigation and model files are hashed before and after execution.
- No requests sent to the live backend. Background worker and external enrichment/LLM integrations disabled.
- Invalid originals can be retained at intake with explicit warnings; successful intake is not decoding or completed analysis.
- Media uses bounded decoded samples and heuristic checks. Scores are not calibrated deepfake probabilities; zero does not establish authenticity.
- Deepfake accuracy, browser interaction/visual accessibility, all background jobs and real-world threat accuracy remain unverified.
- PDF downloads checked for signature and nonempty bytes; generated report layout is not visually validated in this audit.

## Detailed results

| Sample | Check | HTTP | Result | Risk | Detail |
| --- | --- | --- | --- | --- |
| 01-email/benign-meeting.eml | Ingestion | 200 | PASS | — | SUPPORTED |
| 01-email/suspicious-credential-request.eml | Ingestion | 200 | PASS | — | SUPPORTED |
| 01-email/suspicious-payment-request.eml | Ingestion | 200 | PASS | — | SUPPORTED |
| 02-documents/benign-note.txt | Ingestion | 200 | PASS | — | SUPPORTED |
| 02-documents/suspicious-message.txt | Ingestion | 200 | PASS | — | SUPPORTED |
| 02-documents/sample.html | Ingestion | 200 | PASS | — | SUPPORTED |
| 02-documents/sample.rtf | Ingestion | 200 | PASS | — | SUPPORTED |
| 02-documents/sample.xml | Ingestion | 200 | PASS | — | SUPPORTED |
| 02-documents/sample.md | Ingestion | 200 | PASS | — | SUPPORTED |
| 02-documents/benign-document.pdf | Ingestion | 200 | PASS | — | SUPPORTED |
| 03-images/synthetic-card.png | Ingestion | 200 | PASS | — | SUPPORTED |
| 03-images/synthetic-card.jpg | Ingestion | 200 | PASS | — | SUPPORTED |
| 03-images/synthetic-card.webp | Ingestion | 200 | PASS | — | SUPPORTED |
| 03-images/synthetic-card.gif | Ingestion | 200 | PASS | — | SUPPORTED |
| 03-images/synthetic-card.bmp | Ingestion | 200 | PASS | — | SUPPORTED |
| 03-images/synthetic-diagram.svg | Ingestion | 200 | PASS | — | SUPPORTED |
| 04-audio/synthetic-tone.wav | Ingestion | 200 | PASS | — | PARTIALLY_SUPPORTED |
| 04-audio/synthetic-tone.mp3 | Ingestion | 200 | PASS | — | PARTIALLY_SUPPORTED |
| 04-audio/synthetic-tone.ogg | Ingestion | 200 | PASS | — | PARTIALLY_SUPPORTED |
| 04-audio/synthetic-tone.flac | Ingestion | 200 | PASS | — | PARTIALLY_SUPPORTED |
| 05-video/synthetic-color-bars.mp4 | Ingestion | 200 | PASS | — | PARTIALLY_SUPPORTED |
| 05-video/synthetic-color-bars.mov | Ingestion | 200 | PASS | — | PARTIALLY_SUPPORTED |
| 05-video/synthetic-color-bars.avi | Ingestion | 200 | PASS | — | PARTIALLY_SUPPORTED |
| 05-video/synthetic-color-bars.webm | Ingestion | 200 | PASS | — | PARTIALLY_SUPPORTED |
| 06-logs/normal-auth.json | Ingestion | 200 | PASS | — | SUPPORTED |
| 06-logs/password-spray.json | Ingestion | 200 | PASS | — | SUPPORTED |
| 06-logs/authentication-events.jsonl | Ingestion | 200 | PASS | — | SUPPORTED |
| 06-logs/network-connections.csv | Ingestion | 200 | PASS | — | SUPPORTED |
| 06-logs/sample-access.log | Ingestion | 200 | PASS | — | SUPPORTED |
| 06-logs/api-events.json | Ingestion | 200 | PASS | — | SUPPORTED |
| 07-identity/trusted-profile.json | Ingestion | 200 | PASS | — | SUPPORTED |
| 07-identity/identity-claim.txt | Ingestion | 200 | PASS | — | SUPPORTED |
| 08-archives/benign-bundle.zip | Ingestion | 200 | PASS | — | SUPPORTED |
| 08-archives/benign-bundle.tar.gz | Ingestion | 200 | PASS | — | SUPPORTED |
| 09-binary/benign-data.bin | Ingestion | 200 | PASS | — | SUPPORTED |
| 10-invalid/empty.txt | Ingestion | 400 | PASS | — | Uploaded file is empty (0 bytes). |
| 10-invalid/malformed.json | Ingestion | 200 | WARN | — | Invalid original evidence retained. Invalid structured log content; retained as original evidence, not parsed events. |
| 10-invalid/broken.pdf | Ingestion | 200 | WARN | — | Invalid original evidence retained. Invalid or truncated PDF structure, or extension/content mismatch. Original bytes retained; PDF decoding not verified. |
| 10-invalid/broken.mp4 | Ingestion | 200 | WARN | — | Invalid original evidence retained. Video evidence persisted. Validated full-video deepfake detection is NOT_IMPLEMENTED; bounded frame checks and optional pretrained face scoring are available separately, with independent accuracy validation pending.; Original media retained; decoding and authenticity analysis have not run. Use focused media analysis.; Content signature does not match the declared extension; format is unverified.; Reported MIME type differs from the detected content signature. |
| 10-invalid/jpeg-with-pdf-extension.pdf | Ingestion | 200 | WARN | — | Invalid original evidence retained. Original media retained; decoding and authenticity analysis have not run. Use focused media analysis.; Reported MIME type differs from the detected content signature.; Invalid or truncated PDF structure, or extension/content mismatch. Original bytes retained; PDF decoding not verified.; Duplicate artifact: This content has been previously observed and analyzed in CyberGuard. |
| 01-email/benign-meeting.eml | Email analysis | 200 | PASS | 10 |  |
| 01-email/suspicious-credential-request.eml | Email analysis | 200 | PASS | 30 |  |
| 01-email/suspicious-payment-request.eml | Email analysis | 200 | PASS | 28 |  |
| 02-documents/benign-note.txt | File analysis | 200 | PASS | 0.0 |  |
| 02-documents/suspicious-message.txt | File analysis | 200 | PASS | 0.0 |  |
| 02-documents/sample.html | File analysis | 200 | PASS | 0.0 |  |
| 02-documents/sample.rtf | File analysis | 200 | PASS | 0.0 |  |
| 02-documents/sample.xml | File analysis | 200 | PASS | 0.0 |  |
| 02-documents/sample.md | File analysis | 200 | PASS | 0.0 |  |
| 02-documents/benign-document.pdf | File analysis | 200 | PASS | 0.0 |  |
| 03-images/synthetic-card.png | Media analysis | 200 | PASS | 29.0 | COMPLETED; heuristic assessment only; deepfake accuracy is not established. |
| 03-images/synthetic-card.jpg | Media analysis | 200 | PASS | 29.0 | COMPLETED; heuristic assessment only; deepfake accuracy is not established. |
| 03-images/synthetic-card.webp | Media analysis | 200 | PASS | 29.0 | COMPLETED; heuristic assessment only; deepfake accuracy is not established. |
| 03-images/synthetic-card.gif | Media analysis | 200 | PASS | 29.0 | COMPLETED; heuristic assessment only; deepfake accuracy is not established. |
| 03-images/synthetic-card.bmp | Media analysis | 200 | PASS | 29.0 | COMPLETED; heuristic assessment only; deepfake accuracy is not established. |
| 03-images/synthetic-diagram.svg | File analysis | 200 | PASS | 0.0 |  |
| 04-audio/synthetic-tone.wav | Media analysis | 200 | PASS | 35.2 | COMPLETED; heuristic assessment only; deepfake accuracy is not established. |
| 04-audio/synthetic-tone.mp3 | Media analysis | 200 | PASS | 35.2 | COMPLETED; heuristic assessment only; deepfake accuracy is not established. |
| 04-audio/synthetic-tone.ogg | Media analysis | 200 | PASS | 35.2 | COMPLETED; heuristic assessment only; deepfake accuracy is not established. |
| 04-audio/synthetic-tone.flac | Media analysis | 200 | PASS | 35.2 | COMPLETED; heuristic assessment only; deepfake accuracy is not established. |
| 05-video/synthetic-color-bars.mp4 | Media analysis | 200 | PASS | 29.0 | COMPLETED; heuristic assessment only; deepfake accuracy is not established. |
| 05-video/synthetic-color-bars.mov | Media analysis | 200 | PASS | 29.0 | COMPLETED; heuristic assessment only; deepfake accuracy is not established. |
| 05-video/synthetic-color-bars.avi | Media analysis | 200 | PASS | 29.0 | COMPLETED; heuristic assessment only; deepfake accuracy is not established. |
| 05-video/synthetic-color-bars.webm | Media analysis | 200 | PASS | 29.0 | COMPLETED; heuristic assessment only; deepfake accuracy is not established. |
| 08-archives/benign-bundle.zip | File analysis | 200 | PASS | 0.0 |  |
| 08-archives/benign-bundle.tar.gz | File analysis | 200 | PASS | 25.0 |  |
| 09-binary/benign-data.bin | File analysis | 200 | PASS | 0.0 |  |
| 06-logs/normal-auth.json | Authentication analysis | 200 | PASS | 0.0 |  |
| 06-logs/password-spray.json | Authentication analysis | 200 | PASS | 65.0 |  |
| 06-logs/authentication-events.jsonl | Authentication analysis | 200 | PASS | 65.0 |  |
| 06-logs/network-connections.csv | Network analysis | 200 | PASS | 40.0 |  |
| 06-logs/api-events.json | API analysis | 200 | PASS | 30.0 |  |
| 10-invalid/malformed.json | Invalid JSON validation | 422 | PASS | — | Invalid JSON at line 1, column 13: Expecting value. |
| 10-invalid/broken.mp4 | Invalid video analysis | 422 | PASS | — | No cryptographic Content Credentials found; analysis relies on structural heuristics.; Authenticity assessments represent scientific evidentiary hypotheses, not legal certification.; CyberGuard does not perform unconstrained facial or biometric surveillance.; No supported media signature was identified.; Calibrated authenticity confidence is unavailable (confidence=0); configured detector scores and thresholds are heuristic, not learned deepfake probabilities.; Risk scores reflect heuristic signals, not a calibrated probability of deepfake content. A zero score does not establish authenticity. |
| 07-identity/trusted-profile.json | Profile creation | 201 | PASS | — |  |
| 07-identity/identity-claim.txt | Trusted identity | 200 | PASS | 0.0 |  |
| 07-identity/identity-claim.txt | Suspicious identity | 200 | PASS | 60.0 |  |
| 01-email/benign-meeting.eml | Report generation | 200 | PASS | — |  |
| 01-email/benign-meeting.eml | Report download | 200 | PASS | — | Valid PDF header and nonempty download |
| 01-email/suspicious-credential-request.eml | Report generation | 200 | PASS | — |  |
| 01-email/suspicious-credential-request.eml | Report download | 200 | PASS | — | Valid PDF header and nonempty download |
| 01-email/suspicious-payment-request.eml | Report generation | 200 | PASS | — |  |
| 01-email/suspicious-payment-request.eml | Report download | 200 | PASS | — | Valid PDF header and nonempty download |
| 07-identity/identity-claim.txt | Trusted identity (canonical fields) | 200 | PASS | 0.0 | Canonical domain fields validated against parsed addresses. |
| 07-identity/identity-claim.txt | Suspicious identity (canonical fields) | 200 | PASS | 60.0 | Canonical domain fields validated against parsed addresses. |
| Normal authentication control | Detection control | — | PASS | — | Observed NORMAL_AUTHENTICATION, risk 0.0. |
| Password-spray JSON control | Detection control | — | PASS | — | Observed CREDENTIAL_ATTACK_DETECTED, risk 65.0. |
| Equivalent JSONL control | Detection control | — | PASS | — | Same 24 events: JSON 65.0 / CREDENTIAL_ATTACK_DETECTED; JSONL 65.0 / CREDENTIAL_ATTACK_DETECTED. Account and finding equivalence also checked. |
| Trusted identity through UI contract | Detection control | — | PASS | — | Trusted sender: NO_IMPERSONATION_EVIDENCE at 0.0. Uses exact frontend address fields; domains derived server-side. |
| Identity discrimination through UI contract | Detection control | — | PASS | — | Trusted 0.0 / NO_IMPERSONATION_EVIDENCE; suspicious 60.0 / IMPERSONATION_SUSPECTED. |
| Malformed JSON log rejection | Detection control | — | PASS | — | Malformed .json returned HTTP 422: Invalid JSON at line 1, column 13: Expecting value. |
| Media detection coverage | Detection control | — | PASS | — | 0 valid files remain inconclusive. Completed heuristic checks do not establish deepfake detection accuracy. |
| Valid media decoding control | Detection control | — | PASS | — | Verified processing status and successful detector execution for 13 valid image/audio/video samples. |
| Deepfake accuracy evaluation | Detection control | — | WARN | — | Synthetic graphics, tones and color bars contain no labelled real/fake faces or speech. Held-out deepfake accuracy remains unverified. |
| Trusted sender profile persistence | Detection control | — | PASS | — | Reloaded protected profile must retain its configured trusted sender address. |
| Canonical identity engine control | Detection control | — | PASS | — | Canonical fields: [('NO_IMPERSONATION_EVIDENCE', 0.0), ('IMPERSONATION_SUSPECTED', 60.0)] |
