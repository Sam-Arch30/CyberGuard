# 09 — Technical Debt Audit

This document catalogues, classifies, and ranks the technical debt discovered across the CyberGuard (formerly MailTraceAI) codebase. Each debt item is prioritized by its potential to block or complicate the platform's evolution into an enterprise-grade AI Cyber Threat, Phishing, Impersonation Detection, Investigation, and Response platform.

---

## 1. Technical Debt Classification Matrix

| ID | Category | Severity | Component | Summary |
|---|---|---|---|---|
| **TD-01** | Security / Architecture | **BLOCKER** | Backend API / Routes | Zero Authentication, Authorization, or Multi-Tenant RBAC |
| **TD-02** | Infrastructure / Resilience | **BLOCKER** | `docker-compose.yml` | Missing Persistent Volumes for Uploaded `.eml` and Generated Reports |
| **TD-03** | Performance / Architecture | **BLOCKER** | Analysis Pipeline | Synchronous Unbuffered OSINT Network Requests in Core Request Path |
| **TD-04** | Dependencies / Deployment | **HIGH** | `backend/requirements.txt` | Critical Dependencies (`reportlab`, `pillow`) Missing from Manifest |
| **TD-05** | Consistency / Integrity | **HIGH** | Frontend (`src/utils/`) | Client-Side Security Calculation Fallbacks & Scoring Drift |
| **TD-06** | Maintainability | **HIGH** | Frontend UI | God Components (`CaseDetail.tsx`, `ReportSectionView.tsx`) |
| **TD-07** | Data Layer | **HIGH** | Database Schema | Orphan Schema Tables & Untracked Legacy SQLite Models |
| **TD-08** | Reliability / Observability | **MEDIUM** | Intelligence Services | Silent Broad Exception Handling (`except Exception: pass`) |
| **TD-09** | Scalability / Caching | **MEDIUM** | OSINT Services | Process-Local In-Memory Cache with Zero Cross-Worker Persistence |
| **TD-10** | Maintainability / Bundle | **MEDIUM** | Frontend Data | 1,700 Lines of Dead / Hardcoded Mock Datasets (`mockData.ts`) |
| **TD-11** | Security / Resilience | **LOW** | Ingestion Routes | Missing Rate Limiting and Concurrent Upload Concurrency Throttling |
| **TD-12** | User Experience | **LOW** | Frontend State | Ephemeral In-Memory Investigation Context Lost on Browser Refresh |

---

## 2. Detailed Technical Debt Analysis

---

### TD-01: Zero Authentication, Authorization, or Multi-Tenant RBAC
- **Severity**: **BLOCKER**
- **Location**: `backend/main.py`, `backend/routes/*.py`
- **Current State**:
  Every endpoint across all 13 route controllers is completely public and unauthenticated. Any client capable of reaching the backend HTTP port can query sensitive case data, view full email forensic contents, trigger AI Copilot prompts, generate PDF dossiers, or invoke destructive administrative operations like:
  ```http
  POST /api/workspace/reset
  ```
- **Why It Matters for CyberGuard**:
  The expanded CyberGuard platform will ingest enterprise-wide telemetry, support incident response actions (such as automated mailbox quarantine, firewall/EDR IOC blocking, and user credential revoking), and manage sensitive incident cases across security teams. Operating without an authentication framework (OAuth2/OIDC/JWT) and Role-Based Access Control (SOC Analyst L1/L2/L3, Incident Commander, Admin) makes enterprise deployment impossible and violates SOC 2, ISO 27001, and HIPAA compliance.
- **Remediation Strategy**:
  Implement a pluggable authentication middleware using FastAPI dependency injection (`Depends(get_current_user)`). Add role validation decorators before introducing response automation in Section 3.

---

### TD-02: Missing Docker Persistent Volumes for Raw Evidence and Dossiers
- **Severity**: **BLOCKER**
- **Location**: `docker-compose.yml`
- **Current State**:
  `docker-compose.yml` mounts a volume for PostgreSQL (`postgres_data:/var/lib/postgresql/data`), but omits volume mounts for the backend file storage directories:
  - `backend/data/eml_store/` (raw uploaded `.eml` evidence files)
  - `backend/data/reports/` (generated forensic PDF reports)
- **Why It Matters for CyberGuard**:
  In containerized environments, any `docker compose down && docker compose up` or container recreation destroys the entire evidence locker and generated report history, breaking forensic chain-of-custody. Database rows in `evidence` and `reports` will reference file paths that no longer exist on disk, producing unrecoverable `404 File Not Found` errors.
- **Remediation Strategy**:
  Add named volumes or host directory mounts to `docker-compose.yml`:
  ```yaml
  volumes:
    - eml_evidence_data:/app/backend/data/eml_store
    - reports_data:/app/backend/data/reports
  ```

---

### TD-03: Synchronous Blocking OSINT Network Requests in Core Ingestion Flow
- **Severity**: **BLOCKER**
- **Location**: `backend/services/email_parser.py`, `backend/services/domain_intelligence.py`, `backend/services/ip_intelligence.py`, `backend/services/geolocation_service.py`, `backend/services/url_analyzer.py`
- **Current State**:
  When a user uploads an `.eml` file to `POST /api/emails/analyze`, the FastAPI thread executes synchronous blocking network operations inline:
  1. DNS queries for MX, TXT, SPF, and DMARC records via `dnspython`.
  2. RDAP / WHOIS queries over HTTP via `httpx.get`.
  3. External IP geolocation queries to `ip-api.com`.
  4. Public suffix list fetches via `tldextract.TLDExtract(cache_dir=None)`.
  If an authoritative DNS server drops packets or an external API throttles requests, a single upload stalls for 30 to 75 seconds, blocking FastAPI worker threads.
- **Why It Matters for CyberGuard**:
  CyberGuard must support continuous ingestion of high-volume telemetry, email streams, and multi-artifact bundles. Synchronous inline OSINT analysis cannot scale past single-user manual uploads and causes HTTP gateway timeouts (504).
- **Remediation Strategy**:
  Decouple ingestion from enrichment:
  1. **Phase 1 Ingestion**: Ingest, parse MIME, calculate SHA-256 hashes, extract headers and URLs, run offline deterministic heuristics and ML classification (< 500ms). Return immediate analysis payload.
  2. **Phase 2 Enrichment**: Enqueue external OSINT enrichment (DNS, RDAP, Geolocation, AbuseIPDB, VirusTotal) as background jobs (Celery / ARQ / Redis queue) with WebSocket or SSE updates to the frontend.

---

### TD-04: Undeclared Critical Dependencies in `requirements.txt`
- **Severity**: **HIGH**
- **Location**: `backend/requirements.txt`
- **Current State**:
  The backend dependency manifest `backend/requirements.txt` lists 16 packages but omits `reportlab` and `pillow`. Both are imported directly in `backend/services/report_service.py` for PDF compilation and image formatting:
  ```python
  from reportlab.lib.pagesizes import letter
  from reportlab.platypus import SimpleDocTemplate, Paragraph, ...
  ```
  While these packages are installed in the local developer virtual environment (`backend/venv/`), any clean container build or CI pipeline executing `pip install -r backend/requirements.txt` crashes when an analyst triggers `POST /api/reports/generate`.
- **Why It Matters for CyberGuard**:
  Automated container builds, CI/CD validation, and production deployments will fail silently until report generation is tested.
- **Remediation Strategy**:
  Add `reportlab>=4.0.0` and `pillow>=10.0.0` to `backend/requirements.txt`.

---

### TD-05: Client-Side Security Calculation Fallbacks & Scoring Drift
- **Severity**: **HIGH**
- **Location**: `src/utils/indicatorHelper.ts`, `src/utils/confidenceResolver.ts`, `src/components/InvestigationGraph.tsx`
- **Current State**:
  If the backend API returns null or omitted fields for indicator severity, confidence, or threat actor attribution, the frontend utility functions re-run fallback heuristic calculations:
  ```typescript
  // indicatorHelper.ts
  if (!indicator.severity) {
      if (indicator.type === 'ip' && indicator.is_private) return 'info';
      if (indicator.suspicious) return 'high';
      return 'low';
  }
  ```
- **Why It Matters for CyberGuard**:
  Having duplicate security logic in TypeScript and Python leads to **security state divergence**. An analyst inspecting a graph node in the browser may see a "HIGH" severity indicator, while the backend database stores "LOW", and an automated response playbook treats it as "MEDIUM". All risk assessments and scoring must be authoritative and computed solely by the backend.
- **Remediation Strategy**:
  Ensure all backend serializers emit fully hydrated, schema-validated indicators with non-nullable severity and confidence scores. Deprecate client-side recalculations to presentation-only logic.

---

### TD-06: Frontend "God Components" Conflating State, View, and Business Logic
- **Severity**: **HIGH**
- **Location**: `src/components/CaseDetail.tsx` (1,234 lines), `src/components/ReportSectionView.tsx` (684 lines)
- **Current State**:
  - `CaseDetail.tsx` manages case metadata, modal state, email selection, finding toggles, note authoring, export dispatching, and evidence tabulation within a single monolithic component.
  - `ReportSectionView.tsx` combines markdown rendering, section filtering, interactive chart generation, and layout orchestration.
- **Why It Matters for CyberGuard**:
  The upcoming CyberGuard expansion requires adding Attack Path reconstruction, Digital Impersonation tracking, Response Playbook execution, and Threat Timeline views into the investigation interface. Modifying `CaseDetail.tsx` in its current state creates severe risks of regression, state collision, and merge conflicts.
- **Remediation Strategy**:
  Refactor `CaseDetail.tsx` into modular sub-components:
  - `<CaseHeader />`: Metadata, priority badges, status dropdown
  - `<CaseEvidenceLocker />`: Raw `.eml` and attachment tables
  - `<CaseFindingsManager />`: Finding creation and promotion
  - `<CaseNotesTimeline />`: Analyst commentary stream
  - `<CaseActionPanel />`: Response trigger and report dispatch

---

### TD-07: Orphan Schema Tables & Untracked Legacy Models
- **Severity**: **HIGH**
- **Location**: `backend/database.py`, SQLite database files, Alembic migrations
- **Current State**:
  The SQLite database contains 5 legacy tables with 0 rows:
  - `emails`
  - `iocs`
  - `email_iocs`
  - `email_relationships`
  - `analysis_runs`
  These tables have no corresponding SQLAlchemy models in `backend/models/*.py`, nor are they referenced anywhere in `backend/services/`. The active application instead uses `cases`, `case_emails`, `email_analyses`, and `analysis_payloads`.
- **Why It Matters for CyberGuard**:
  Orphan tables create confusion regarding where data actually lives. When database migrations run in PostgreSQL, these unused tables consume connection overhead and risk being accidentally re-bound by future developers.
- **Remediation Strategy**:
  Draft a non-destructive Alembic migration to drop the 5 unused legacy tables once PostgreSQL migration is verified.

---

### TD-08: Silent Broad Exception Handling (`except Exception: pass`)
- **Severity**: **MEDIUM**
- **Location**: `backend/services/geolocation_service.py`, `backend/services/ip_intelligence.py`, `backend/services/domain_intelligence.py`
- **Current State**:
  Multiple helper methods wrap network lookups and parsing routines in catch-all exception blocks without logging or telemetry:
  ```python
  except Exception:
      pass # Silently returns empty or None
  ```
- **Why It Matters for CyberGuard**:
  Silent exceptions conceal upstream API quota exhaustion, network DNS misconfigurations, or subtle serialization bugs. SOC analysts will see missing IP intelligence without any diagnostic record indicating whether the IP was benign, unroutable, or rate-limited by the provider.
- **Remediation Strategy**:
  Replace `except Exception: pass` with structured logger statements (`logger.warning("DNS lookup failed for %s: %s", domain, exc)`) and populate an explicit `error_state` or `partial_data` flag in the enrichment response.

---

### TD-09: Process-Local In-Memory Cache with Zero Cross-Worker Persistence
- **Severity**: **MEDIUM**
- **Location**: `backend/services/domain_intelligence.py`, `backend/services/ip_intelligence.py`
- **Current State**:
  Domain RDAP and IP intelligence results are cached in local Python dictionaries (`self.cache = {}`).
- **Why It Matters for CyberGuard**:
  In a multi-worker production deployment (e.g. `uvicorn --workers 4` or Gunicorn), workers do not share caches. Repeated analyses of identical domains or IPs cause duplicate external API queries. Furthermore, container restarts wipe all cached data, triggering external rate limits.
- **Remediation Strategy**:
  Introduce a Redis or database-backed cache layer with Time-To-Live (TTL) expiration (e.g. 24 hours for DNS/RDAP).

---

### TD-10: 1,700 Lines of Dead / Hardcoded Mock Datasets in Frontend
- **Severity**: **MEDIUM**
- **Location**: `src/data/mockData.ts` (672 lines), `src/data/sihScenariosData.ts` (1,048 lines)
- **Current State**:
  - `src/data/mockData.ts` is completely unimported across the entire codebase (zero references).
  - `src/data/sihScenariosData.ts` contains large static JSON structures for competition demonstration scenarios (e.g. CEO fraud, credential harvest, invoice scam).
- **Why It Matters for CyberGuard**:
  Shipping 1,700 lines of dead mock data bloats client bundle size, increases maintenance noise, and creates confusion about whether dashboard charts are rendering live incident telemetry or hardcoded static objects.
- **Remediation Strategy**:
  Deprecate and delete `mockData.ts`. Relocate `sihScenariosData.ts` into a dedicated test fixture directory (`backend/tests/fixtures/scenarios/`) or an optional demo-mode seed loader.

---

### TD-11: Missing Rate Limiting and Concurrency Throttling on Ingestion Endpoints
- **Severity**: **LOW**
- **Location**: `backend/routes/email_routes.py`, `backend/routes/case_routes.py`
- **Current State**:
  Upload endpoints accept raw binary payloads with a 25MB single-file limit, but enforce no per-IP or per-user rate limits.
- **Why It Matters for CyberGuard**:
  Malicious clients or misconfigured log forwarders could flood `POST /api/emails/analyze` with hundreds of concurrent multi-megabyte emails, exhausting server memory and spawning hundreds of unthrottled external DNS queries.
- **Remediation Strategy**:
  Implement rate-limiting middleware (`slowapi` or Redis token bucket) capping unauthenticated clients to 10 uploads per minute.

---

### TD-12: Ephemeral Frontend Investigation Context Lost on Browser Refresh
- **Severity**: **LOW**
- **Location**: `src/context/InvestigationContext.tsx`, `src/store/forensicStore.ts`
- **Current State**:
  Active graph layout coordinates, highlighted paths, selected filter tags, and in-progress analyst draft notes reside in React state or Zustand in-memory storage.
- **Why It Matters for CyberGuard**:
  If an analyst working on an active multi-hour investigation accidentally refreshes their browser or loses network connectivity, their visual graph workspace state is lost.
- **Remediation Strategy**:
  Persist active investigation session state to `localStorage` or introduce a backend `investigation_sessions` table saving canvas coordinates and active filters.
