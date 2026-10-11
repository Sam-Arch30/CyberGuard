# CYBERGUARD — DEMO & EVALUATION GUIDE
## AI-Powered Cyber Threat, Phishing & Digital Impersonation Detection and Response System

---

### 1. Prerequisites

Before running the demonstration, ensure you have:
- **Node.js**: v18.0.0 or higher (`node -v`)
- **Python**: 3.10, 3.11, or 3.12 (`python3 --version`)
- **Git**: Installed and configured
- **Browser**: Modern Chromium, Firefox, or Safari browser
- **Memory**: Minimum 4 GB RAM recommended

---

### 2. Startup

#### A. Backend Service Startup
```bash
# 1. Activate virtual environment
source backend/venv/bin/activate

# 2. Start FastAPI application on port 8000
PYTHONPATH=. uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```
Verify backend health:
```bash
curl -s http://localhost:8000/health/live
# Expected: {"status":"HEALTHY","timestamp":...}
```

#### B. Frontend Application Startup
```bash
# In project root:
npm install
npm run dev
```
Open your browser to: `http://localhost:5173`

---

### 3. Demo Environment Setup & Isolation

CyberGuard includes built-in demo environment isolation:
- All demonstration entities are tagged with `is_demo: true` and namespaced identifiers (`CASE-DEMO-*`, `INC-DEMO-*`, `EV-DEMO-*`).
- Demonstration runs never pollute or delete enterprise production cases, real threat intelligence feeds, or live audit trails.
- Server-authoritative calculations ensure that **zero scores, confidence levels, or detection results are fabricated**.

Check demo environment status:
```bash
curl -s http://localhost:8000/api/demo/status
```

---

### 4. Scenario Catalog

CyberGuard provides 4 deterministic, realistic security demonstration scenarios exercising the complete pipeline:

| Scenario ID | Name | Category | Primary Threat Vectors | Expected Severity |
| :--- | :--- | :--- | :--- | :--- |
| `scenario-a-phishing` | **Scenario A: Targeted Phishing** | PHISHING | PayPal lookalike domain (`paypa1-security-update.com`), credential harvesting URL, SPF/DKIM/DMARC failure | **CRITICAL** |
| `scenario-b-bec` | **Scenario B: Executive Impersonation & BEC** | BUSINESS_EMAIL_COMPROMISE | C-suite wire transfer authorization ($248,500), display-name impersonation, urgency coercion, reply-to anomaly | **HIGH / CRITICAL** |
| `scenario-c-malicious-attachment` | **Scenario C: Weaponized Attachment** | MALWARE_DELIVERY | Double-extension attachment (`Mandatory_Compliance_Review.pdf.exe`), PE magic byte (`MZ`) header | **CRITICAL** |
| `scenario-d-multistage` | **Scenario D: Multi-Stage Attack** | COORDINATED_CAMPAIGN | Phishing delivery $\to$ Script URL $\to$ C2 IP 203.0.113.88 $\to$ Endpoint PowerShell execution $\to$ Correlated Incident | **CRITICAL** |

List all scenarios programmatically:
```bash
curl -s http://localhost:8000/api/demo/scenarios | jq .
```

---

### 5. Executing the Golden Path (Live Walkthrough)

To execute a demonstration scenario through the authentic detection pipeline:

#### Step 1: Trigger the Pipeline Execution
```bash
curl -X POST http://localhost:8000/api/demo/scenarios/scenario-a-phishing/execute \
  -H "Content-Type: application/json" \
  -H "X-User: demo.analyst@cyberguard.local" \
  -H "X-Role: analyst" \
  -d '{"workspace_id": "soc_demo_env"}' | jq .
```

#### Step 2: Returned Identifiers & Provenance Chain
The server returns the linked identifiers:
```json
{
  "status": "SUCCESS",
  "scenario": { "id": "scenario-a-phishing", ... },
  "artifact_id": "73eae6eb-2397-441f-a91d-a149a06ec45f",
  "analysis_run_id": "e485a10a-9764-4671-aea0-ed0bef98281e",
  "case_id": "c1f8a840-7546-4ec9-8664-9b22eec7b4f1",
  "case_number": "CASE-DEMO-A1B2C3",
  "incident_id": "f5e921d2-0941-4770-bd6f-0045f948bf90",
  "incident_number": "INC-DEMO-F9E8D7",
  "attack_path_id": "d0442bc8-e8cb-4f3d-b4f0-410a51c7e974",
  "evidence_id": "EV-DEMO-48B1C0",
  "findings_count": 8,
  "overall_risk_score": 85.0,
  "overall_severity": "CRITICAL",
  "is_demo": true
}
```

---

### 6. Investigation Flow

Once executed, demonstrate each section in the CyberGuard UI:

1. **Dashboard (`/`)**:
   - Observe live threat count and active alert distributions.
   - High-severity demo incident is visible in recent triage queue.
2. **Analysis Results (`/analysis`)**:
   - Inspect the raw RFC-822 email parser decomposition.
   - Inspect SPF/DKIM/DMARC authentication failures.
   - Review extracted IOCs: domains, IPs, URLs, hashes.
3. **Investigation Workspace & Case Management (`/cases`)**:
   - Open case `CASE-DEMO-*`.
   - Inspect linked findings, analyst timeline, and task checklist.
4. **Interactive Attack Path (`/attack-path` or via Incident)**:
   - View the multi-stage progression:
     - Stage 1: `INITIAL_ACCESS` (`T1566.002` Phishing Link)
     - Stage 2: `CREDENTIAL_ACCESS` (`TA0006` Lookalike Brand Harvesting)
   - Every edge is backed by real persisted relationships.

---

### 7. Response Recommendations & Human-in-the-Loop Approval

Navigate to **Response Recommendations (`/response`)**:
- Observe that the generated action: `BLOCK_SENDER_DOMAIN` (`paypa1-security-update.com`) has status: **`RECOMMENDED`**.
- **Security Rule**: The system **never auto-executes destructive response commands**.
- An analyst with role `SOC Lead` or `Platform Admin` must explicitly review and authorize the remediation action before execution.

---

### 8. Evidence Custody & Report Generation

1. **Evidence Workspace (`/evidence`)**:
   - Locate evidence record `EV-DEMO-*`.
   - Inspect SHA-256 hash calculation, file size, collection timestamp, and chain-of-custody verification status (`VERIFIED`).
2. **Executive Reports (`/reports`)**:
   - Generate an Executive SOC Incident Report for the investigation.
   - Verify that report metrics, findings, and risk scores match the analysis run.

---

### 9. Demo Reset Procedure

To return the demonstration environment to a clean state without affecting production data:

#### Via API:
```bash
curl -X POST http://localhost:8000/api/demo/reset \
  -H "X-User: admin@cyberguard.local" \
  -H "X-Role: admin" | jq .
```
Expected output:
```json
{
  "status": "DEMO_RESET_COMPLETE",
  "purged_records": {
    "findings": 8,
    "analysis_runs": 1,
    "cases": 1,
    "incidents": 1,
    "attack_paths": 1,
    "evidence": 1,
    "artifacts": 1
  },
  "isolated": true
}
```

#### Verification:
```bash
curl -s http://localhost:8000/api/demo/status
# Expected: {"demo_artifacts_active":0,"demo_cases_active":0,"environment_mode":"DEMO_READY"}
```

---

### 10. Troubleshooting

| Issue | Cause | Resolution |
| :--- | :--- | :--- |
| `HTTP 403 Forbidden` on demo execution | Role header missing or set to `unauthorized` | Pass `-H "X-Role: analyst"` or `-H "X-Role: admin"` |
| `HTTP 400 Bad Request: Unknown scenario ID` | Invalid scenario identifier | Check supported IDs: `scenario-a-phishing`, `scenario-b-bec`, `scenario-c-malicious-attachment`, `scenario-d-multistage` |
| `Connection Refused` on port 8000 | FastAPI backend not started | Run `uvicorn backend.main:app --port 8000` |
| ModuleNotFoundError: `backend` | Python path unset | Run with `PYTHONPATH=.` before command |
