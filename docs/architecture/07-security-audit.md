# 07 — Application Security & Defensive Hardening Audit

> **Audit Type:** Defensive Application Security Review (AppSec & Secure Architecture)  
> **Classification Framework:** `CRITICAL` | `HIGH` | `MEDIUM` | `LOW` | `INFORMATIONAL`  

---

## 1. Executive Security Posture

CyberGuard exhibits strong defensive foundations in several key areas (static binary inspection, zero executable invocation, strict HTML sanitization, SQL injection prevention via SQLAlchemy ORM, and append-only audit log triggers). However, as the platform transitions from an offline hackathon prototype to an enterprise cyber threat platform, critical access control and persistence vulnerabilities must be addressed.

---

## 2. Security Findings Matrix

### 2.1 [CRITICAL] Absence of Authentication and Role-Based Access Control (RBAC)
- **Location:** `backend/main.py`, all controllers in `backend/api/routes/`
- **Impact:** Complete system access without authentication. Any network client capable of reaching the backend can upload evidence, inspect sensitive investigative cases, export reports, or execute destructive actions (such as `POST /api/workspace/reset`, which deletes all database records and raw evidence files).
- **Evidence:** 
  In `backend/main.py` and route definitions, routes have no `Depends(auth_required)`. The user identity is extracted purely from an untrusted client header:
  ```python
  uploader_identity = (user or "SOC Analyst").strip() # from Header(None, alias="X-User")
  ```
- **Recommended Remediation:**
  Implement JWT / OAuth2 bearer token authentication and RBAC (`SOC Analyst`, `Lead Investigator`, `Administrator`). Secure all destructive routes (`/api/workspace/reset`, case deletions) to Administrator role only.

---

### 2.2 [HIGH] Docker Compose Missing Persistent Volumes for Raw Evidence and Reports
- **Location:** `docker-compose.yml` (`services.backend`)
- **Impact:** Irreversible evidentiary data loss upon container restart or redeployment.
- **Evidence:**
  In `docker-compose.yml`, while `postgres_data` is mounted to `/var/lib/postgresql/data`, the `backend` service has **no persistent volume mounts**:
  ```yaml
  backend:
    build:
      context: .
      dockerfile: backend/Dockerfile
    container_name: mailtrace-backend
    # MISSING: volumes for /app/backend/data/eml_store and /app/backend/data/reports
  ```
  Whenever `mailtrace-backend` is restarted or rebuilt, all original raw `.eml` files stored on container disk (`/app/backend/data/eml_store/`) and all generated PDF dossiers (`/app/backend/data/reports/`) are permanently destroyed.
- **Recommended Remediation:**
  Add named Docker volumes or host bind mounts in `docker-compose.yml`:
  ```yaml
  volumes:
    - eml_storage:/app/backend/data/eml_store
    - report_storage:/app/backend/data/reports
  ```

---

### 2.3 [HIGH] Synchronous Unbounded Network Enrichment in Core Ingestion Pipeline
- **Location:** `backend/api/routes/email.py` (lines 282–285 in `analyze_email`)
- **Impact:** Denial of Service (DoS) and request thread starvation during email ingestion.
- **Evidence:**
  During an email upload, `analyze_email` calls synchronous network lookups for all extracted IPs and domains:
  ```python
  ip_intel_dict, domain_intel_dict = await asyncio.gather(
      global_ip_service.get_batch_ip_intelligence(ip_list),
      global_domain_service.enrich_domains_batch(domain_list)
  )
  ```
  If an adversary sends an email containing multiple domains/IPs, or in network environments with unrouted IPv6 or sluggish DNS/RDAP servers, each lookup can stall for up to 75 seconds on TCP connect timeouts. Multiple concurrent uploads quickly exhaust the Uvicorn worker thread pool.
- **Recommended Remediation:**
  1. Decouple ingestion from network OSINT: ingest and parse the email immediately (returning core deterministic forensic results in $< 300\text{ ms}$), and push network enrichments (DNS, RDAP, Geolocation) to an asynchronous background task.
  2. Enforce strict socket-level connect timeouts ($\le 2.0\text{ s}$) with `httpx.Limits` and force IPv4 resolution when IPv6 is unavailable.

---

### 2.4 [MEDIUM] Missing Dependency Declarations in `backend/requirements.txt`
- **Location:** `backend/requirements.txt`
- **Impact:** Production Docker build failure or runtime crash during report generation.
- **Evidence:**
  `backend/services/report_service.py` requires `reportlab` and `PIL` (Pillow):
  ```python
  from reportlab.lib.pagesizes import letter
  from reportlab.platypus import SimpleDocTemplate, ...
  ```
  However, `backend/requirements.txt` does not list `reportlab` or `pillow`:
  ```
  fastapi>=0.100.0
  uvicorn>=0.22.0
  python-multipart>=0.0.6
  pydantic>=2.0.0
  pytest>=7.4.0
  httpx>=0.24.1
  tldextract>=3.4.0
  dnspython>=2.4.0
  scikit-learn>=1.3.0
  joblib>=1.3.0
  numpy>=1.24.0
  sqlalchemy>=2.0.0
  alembic>=1.13.0
  psycopg2-binary>=2.9.9
  ```
  While installed in the local virtual environment, a fresh `docker compose build` installs only packages from `requirements.txt`, causing report generation to fail with `ModuleNotFoundError: No module named 'reportlab'`.
- **Recommended Remediation:**
  Append `reportlab>=4.0.0` and `pillow>=10.0.0` to `backend/requirements.txt`.

---

### 2.5 [MEDIUM] Client-Side Security Calculation Fallbacks
- **Location:** `src/utils/indicatorHelper.ts`, `src/utils/confidenceResolver.ts`
- **Impact:** Potential client-side tampering of threat conclusions or inconsistent analytical outcomes across clients.
- **Evidence:**
  If backend attribution or confidence evaluations are missing or unpopulated, the frontend executes TypeScript implementations of:
  - `resolveAttribution(email)`
  - `resolveConfidenceConclusions(email)`
  - Threat score severity recalculation in `indicatorHelper.ts`
  This creates duplicate business logic and violates the security principle that security assessments must be authoritative, server-verified, and tamper-proof.
- **Recommended Remediation:**
  Ensure the backend analysis response is always complete and authoritative. Strip redundant client-side analytical calculators, using the frontend purely as a presentation layer.

---

### 2.6 [LOW] Excessive Silent Exception Catching in Core Backend Routes
- **Location:** `backend/api/routes/email.py` (lines 303, 313, 328, 334, 381, 410, 445)
- **Impact:** Hidden pipeline failures, silent data corruption, or untracked operational bugs.
- **Evidence:**
  Seven independent `try / except Exception: pass` blocks exist in `analyze_email`. For example:
  ```python
  # Section 11: NLP Phishing
  try:
      ml_pred = global_phishing_classifier.predict(...)
  except Exception:
      analysis_result.ml_assessment = None

  # Dynamic campaign registration
  try:
      CampaignService.register_new_ingested_email(...)
  except Exception:
      pass
  ```
- **Recommended Remediation:**
  Replace silent `pass` blocks with structured diagnostic logging (`logger.exception("...")`) and record degraded engine states in the response metadata (`degraded_services: ["ml_classifier"]`).

---

### 2.7 [INFORMATIONAL / POSITIVE CONTROLS] Existing Defensive Protections

1. **SQL Injection:**
   - **Protection:** 100% of database queries use SQLAlchemy parameterized queries and ORM models. Zero dynamic raw SQL string interpolation.
2. **File Upload Security:**
   - **Protection:** `UploadSecurityService` enforces 10MB limits, strips path traversal sequences (`../`), strips null bytes, blocks executable extensions (`.exe`, `.sh`, `.bat`, `.ps1`), and checks binary magic bytes (`MZ`, `\x7fELF`, Mach-O).
3. **Malicious HTML & XSS Defense:**
   - **Protection:** `HTMLSanitizerService` strips `<script>`, `<iframe>`, `<object>`, `<embed>`, `<form>`, inline event handlers (`onload`, `onclick`), and neutralizes remote image beacons (`data-blocked-src`).
4. **Server-Side Request Forgery (SSRF):**
   - **Protection:** `SSRFProtector` blocks queries to private RFC-1918 subnets, loopbacks (`127.0.0.1`, `::1`), link-local IPs (`169.254.169.254`), and cloud metadata services.
5. **Malware & Zip Bomb Defense:**
   - **Protection:** `AttachmentIntelligenceService` disassembles PE and PDF structures purely statically without executing code, and guards against zip slips and compression bombs.
6. **Audit Trail Immutability:**
   - **Protection:** Database event triggers on `AuditLogModel` prevent any `UPDATE` or `DELETE` operations on audit logs.
7. **Secret Scrubbing in Logs:**
   - **Protection:** `LogSanitizer` automatically intercepts standard logging streams and regex-redacts API keys, passwords, and authorization tokens.
