# Local prototype readiness — 2026-10-13

Target: a local demonstration prototype from the repaired C: checkout. This is not a production deployment or a claim of zero false positives. Detection scores are implementation outputs, not independently calibrated probabilities.

## Implemented repairs

- Generic evidence intake now executes the existing focused file, URL, authentication, network and API pipelines, preserving original evidence, hashes, workspace scope and canonical child-run history. Unknown stages fail explicitly.
- URL results use the actual backend response contract. Added bounded offline URL-list screening (50 URLs), with refanging on analysis copies and explicit structural-check limitations.
- API and network uploads validate declared JSON, JSONL and CSV formats. Malformed, empty or unusable batches return validation errors; malformed JSON cannot silently become normal telemetry.
- Added an API abuse detection screen. Detection entry points give email, identity, account, URL, file, network and API workflows their own controls.
- Fixed rule registry serialization, editor field metadata, version comparison and AI suggestion request paths. Registered the API prefix used by Watchlists. Alert updates subscribe to the existing workspace event stream.
- Explanation actions use the actual scoped endpoints. Missing authoritative risk results return unavailable instead of an invented explanation. IP intelligence uses its registered route.
- Reports no longer invent IP countries, ASNs, redirect counts or benign counter-evidence. A zero score is labelled as no observed signals; incomplete analysis is not a safety verdict.
- Shared typography, focus visibility, control sizing and investigation layouts were simplified. Original investigation/database records and unrelated changes were preserved.

## Capability boundaries

| Section | What can be demonstrated | Limits |
|---|---|---|
| Email / phishing | Existing header/content/link checks and evidence-backed findings | Generic scoring needs independent calibration; no guarantee against false positives or missed phishing |
| URL / URL lists | Parsed features, passive suspicious-pattern checks and per-URL findings | Offline batch checks do not inspect destination content or establish reputation; active enrichment depends on connectivity/services |
| Identity impersonation | Validated sender addresses, server-derived domains and trusted-profile comparison | Reference-dependent; absent evidence must remain insufficient |
| Authentication | Structured JSON/JSONL spray detection and normal negative controls | Rule thresholds require deployment-specific calibration |
| Network and API logs | Validated batches and existing anomaly/rule findings | Results depend on compatible telemetry and context; not a replacement for a live network sensor |
| Files | Static metadata/signature/IOC checks, original-byte preservation | Not comprehensive malware scanning; limited document/archive decoding |
| Media / voice / deepfake | Bounded decoding/metadata checks and explicit capability/error states | Face model validation failed and verdicts remain withheld; no validated trained voice-cloning detector |
| Investigations, evidence, reports | Stored evidence/results, workspace projections and reporting services | Browser/object actions require separate verification; collection GET success alone is insufficient |
| Rules, alerts, watchlists, hunting, correlation, inventory, automation | Existing local APIs and UI entry points | External connectors, destructive actions, long-running streams and every CRUD permutation are not covered by a collection smoke audit |
| Endpoint agents and OSINT | Existing local UI/API workflows | Host-specific acquisition, external credentials and live integrations require their own validation |

Generic IP, system-log and endpoint intake stages without a focused pipeline remain explicitly unsupported. An upload being retained is not proof that its threat analysis completed. Previously saved risk/severity values were preserved, not silently recalculated; legacy records can contain scores needing reassessment.

## Verification approach

Backend tests redirect the database, EML, evidence storage, reports, benchmark outputs, model directories and learning candidates into a temporary root. Integrity checks assert repository investigation/model files remain unchanged. Sample audits use isolated TestClient instances, not the live demonstration workspace. Negative controls and assertions were retained.

The API collection audit excludes required object/query inputs, streams, exports, downloads and potentially mutating actions. Build and lint success do not establish detector accuracy.

## Final verification results

All commands were run from `C:\Users\bipin\Downloads\Berum CodeBases\CyberGuard` against the final source, except earlier intermediate runs explicitly identified below.

| Exact command | Exit | Result |
|---|---:|---|
| `backend/venv/Scripts/python.exe -m pytest backend/tests -q --tb=short` | 0 | 1590 passed, 1 skipped, 0 failed; 6397 warnings; 281.74 seconds |
| `backend/venv/Scripts/python.exe -m pytest backend/tests/test_local_readiness_regressions.py backend/tests/test_section46_realtime_updates.py backend/tests/test_section39_investigation_workspace.py -q --tb=short` | 0 | 35 passed, 0 skipped, 0 failed; 145 warnings |
| `backend/venv/Scripts/python.exe -m pytest backend/tests/test_local_readiness_regressions.py backend/tests/test_section38_analysis_results.py backend/tests/test_section42_report_workspace.py backend/tests/test_observed_counterevidence.py -q --tb=short` | 0 | 32 passed, 0 skipped, 0 failed; 133 warnings; before the final stream regression was added |
| `node --test scripts/url_analysis_contract.test.mjs` | 0 | 2 passed, 0 failed, 0 skipped |
| `npm run build` | 0 | TypeScript and Vite build succeeded; bundle-size warning remains |
| `npm run lint` | 0 | 0 errors, 176 warnings |
| `npm audit --json` | 0 | 0 vulnerabilities |
| `backend/venv/Scripts/python.exe scripts/test_sample_pack.py` | 0 | 40 files, 83 checks: 79 PASS, 4 WARN, 0 FAIL |
| `backend/venv/Scripts/python.exe scripts/review_sample_results.py` | 0 | Final 96 checks: 91 PASS, 5 WARN, 0 FAIL; includes semantic/negative controls |
| `backend/venv/Scripts/python.exe scripts/audit_section_readiness.py` | 0 | 190 collection GET checks, 0 server errors; 296 routes excluded; live-data integrity verified |

The one backend skip requires a macOS Darwin host; it was not exercised on Windows. Backend warnings include framework/date-time deprecations and a scikit-learn serialized-model version mismatch (1.9.0 versus 1.9.1). Unit tests passing do not eliminate that compatibility or accuracy limitation.

The final collection audit returned 184 HTTP 200, 2 HTTP 400 for missing memory-query inputs, 1 HTTP 401 for missing agent credentials and 3 HTTP 403 for protected administrative dead-letter routes. These are recorded responses, not 190 successful feature workflows.

### Intermediate failures retained

- An earlier contended full suite exited 1: 1585 passed, 1 skipped, 1 failed, 6381 warnings. The transition-scoring performance test measured 244.28 ms against its unchanged 200 ms limit. Its isolated rerun passed (1 passed, 4 warnings); subsequent full suites passed. No performance threshold was relaxed.
- The initial URL/UI build failed on three optional `scopeId` arguments. Explicit guards fixed the TypeScript errors; final build passed.
- The first report-grounding subset exited 1: 30 passed, 1 failed, 129 warnings. The old test required an invented history gap. It now checks exact observed failed-task topics, with separate regressions requiring no invented baseline and a real failed-stage gap. The corrected subset and final full suite passed.
- One section-audit attempt exited 1 because backend startup overlapped its live-database hash window. No database was restored/reset. Rerunning with the live backend stopped verified unchanged data; the final audit also passed. The failed log is retained.

Logs are saved under `.local-runtime/readiness/logs/`, including intermediate failures. Sample outputs were refreshed at `samples/test-results/report.md`, `report.html`, `results.json` and `results.csv`. No test samples were added to the live workspace by these automated checks.

## Browser observations

Navigated 32 distinct section entry points in the repaired local browser: dashboard, detect, URL intelligence, API security, authentication, network, files, media, email analysis, impersonation, alerts, investigations, reports, operations, incidents, cases, evidence, correlations, hunting, detections, inventory, attack surface, automation, benchmarks, admin, settings, OSINT, watchlists, endpoints, campaigns, actors and cross-investigation. Follow-up observations confirmed loading completion for alerts, cases, evidence, correlations, detections and campaigns. Empty catalogues and context-required views were retained rather than populated with fabricated records.

- Submitted two offline URL controls in the browser. The reference URL reported **No structural indicators — safety undetermined**. The defanged numeric-IP / port / login / executable example reported four actual structural findings, **review required**, with the explicit no-reputation/no-destination-inspection limitation.
- Opened the rule editor and observed the typed field registry and operators. No test rule was saved into the live workspace.
- Watchlists reached its registered API and displayed the legitimate empty-state screen.
- Existing investigation analysis loaded its original 50 extracted URL references and incomplete-threat-assessment wording. Badge icons and severity text were visually checked after fixing an overly broad SVG CSS selector.
- Browser observation is entry-point smoke coverage, not verification of every CRUD action, report layout, connector or stream delivery/replay. Settings/governance options and host-agent installation were not changed.

Raw observations: `.local-runtime/readiness/browser-sections.json`. Screenshots: `.local-runtime/readiness/screenshots/`. Console history contained older rate-limit errors; they were not treated as evidence of a new successful request. Live stream-disconnect pending-reader warnings prompted a cleanup fix and a cancellation regression.

## Local activation

After all isolated checks finished, `scripts/start-local.ps1` created a consistent SQLite backup and restarted the verified C: backend/frontend on loopback ports 8000/5173. Final investigation reload confirmed the invented history gap was absent and the incomplete assessment/50 extracted references were preserved. Navigating away after that reload did not emit the earlier pending-reader warning in the observed backend log window. This is a bounded live check, not a long-duration stream soak test.

Open `http://127.0.0.1:5173/#/detect`. Local demonstration access is explicitly token-free; production/staging authentication was not disabled. Use the capability matrix above when presenting the prototype.
