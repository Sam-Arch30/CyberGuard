# Repaired CyberGuard prototype

Updated 2026-10-12 against fresh clone d638e3d from Sam-Arch30/CyberGuard.

## Start locally

Dependencies have been installed in backend/venv and node_modules on this machine.
Stop any old development servers occupying ports 8000 or 5173 first, then run from
the project root:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\start-local.ps1
```

The launcher backs up an existing local SQLite database and starts loopback servers
in explicit local prototype mode. Open http://127.0.0.1:5173 directly: no token,
connection form or sign-in is required. Local requests use workspace default and
ignore any previously saved access token/workspace. Runtime logs, process IDs and
backups are in .local-runtime. Restart both servers after this configuration change.
Production/staging authentication remains enforced; local demo mode cannot bypass it.
The launcher syntax is verified; live startup against user data remains unverified.

For installation elsewhere:

```powershell
python -m venv backend/venv
backend/venv/Scripts/python.exe -m pip install -r backend/requirements.txt
npm.cmd ci
```

Manual servers must receive CYBERGUARD_SERVER_CREDENTIALS as a JSON map from secret
tokens to objects with actor_id, role and a nonempty workspaces list. Authentication
is required by default. Credentials stay on the server and in browser session
storage; do not put them in VITE variables or source. Caller identity/role headers
cannot grant privileges. Explicit nonproduction demo mode is for isolated demo
installations only and must never be enabled with investigation data.

## Detection and reporting

- **Overview:** three balanced threat workflows, real workspace metrics and priority review.
- **Detection Center:** universal evidence upload and focused email, identity,
  authentication, network, file and URL analysis.
- **Identity Impersonation:** add independently verified reference profiles,
  compare a claimed sender and review findings, counterevidence and limitations.
- **Alert Review / Investigations:** triage saved findings and examine supporting evidence.
- **Report Library:** review stored reports and download authenticated PDF/JSON exports.
  Reports require saved investigation/analysis evidence; submitted report text does
  not replace authoritative findings.
- **Advanced Tools:** operational telemetry, rule management, evidence, correlation,
  inventory and other specialist features remain available without crowding the main UI.

The main screen uses real backend counts. Loading and API failures show unavailable
values instead of fabricated activity. Credentialed realtime views use authenticated
polling, since native EventSource does not support Authorization headers.

## Validation

See docs/development-progress.md for exact test summaries and limitations. Run:

```powershell
backend/venv/Scripts/python.exe -m pytest backend/tests -q
npm.cmd run build
npm.cmd run lint
npm.cmd audit
```

Tests isolate databases, EML files, evidence, reports, benchmark results and learning
candidates before app initialization, then assert repository data/model integrity.
The legacy feature suite uses explicit isolated demo configuration. Dedicated
security tests enable normal authentication and exercise forged identity, membership
boundaries and the actual HTTPX/HTTPCore connection destination/Host/TLS SNI.

Candidate rule lifecycle now uses `/api/v1/candidate-rules/...`, separately from
managed detection rules under `/api/v1/rules/...`; the old shared namespace caused
route collisions. Case/report numbers use random suffixes to avoid independent
workspace sequence conflicts. Update integrations that assume sequential numbers.

## Limits

This is a repaired prototype, not a guarantee of production readiness or complete
threat detection. Browser visual QA, live Docker/PostgreSQL deployment and broad
concurrency/adversarial testing remain unverified. Existing warnings and the large
frontend bundle remain. Model artifacts were saved with scikit-learn 1.9.0 while
this installation uses 1.9.1; reproduce and validate training before deployment.
The synthetic feature benchmark is not held-out accuracy or full API latency.
Deepfake accuracy is unvalidated. Some Windows endpoint adapters beyond process
collection remain incomplete; do not claim full endpoint telemetry coverage.
Legacy records without ownership are assigned to default by the additive upgrade;
review intended ownership before deploying a multi-tenant installation.


## Sample audit repairs and media checks

Authentication uploads declare their format with `.json`, `.jsonl`/`.ndjson`, or
`.log`/`.txt` for syslog. Malformed structured logs are rejected with a line/column
message. Identity requests use `from_address` and `reply_to_address`; the API derives
the domains and rejects contradictory domain fields. Existing clients using `from`
or `reply_to` must update their payload.

The Detection Center now includes a separate media check after preserving original
evidence. Install `backend/requirements.txt` into the backend virtual environment;
`imageio-ffmpeg==0.6.0` supplies the local decoder. Checks use at most 30 seconds of
mono audio or eight small video frames, with a 20-second decoding timeout, one
codec/filter thread, bounded output and two concurrent route analyses. Missing
decoders, invalid content, unsupported formats, processing limits and insufficient
evidence have explicit states. Original intake remains separate from analysis.

These are heuristic checks, not validated deepfake detection. Authenticity confidence
is unavailable (`confidence=0`, `confidence_basis=UNAVAILABLE_NOT_CALIBRATED`). A
zero risk score does not establish safety. C2PA byte markers are unverified; signature
verification is not implemented. Existing historical results are preserved.

Reproduce the isolated sample audit with:

```powershell
backend/venv/Scripts/python.exe scripts/test_sample_pack.py
backend/venv/Scripts/python.exe scripts/review_sample_results.py
```

Both scripts fail with exit 1 for failed controls. Warnings stay visible. Results
are written under `samples/test-results`; runtime evidence, database, reports,
EML, benchmarks and model candidates use a dedicated temporary directory.
