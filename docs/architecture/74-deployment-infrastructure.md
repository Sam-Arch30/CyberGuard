# Section 74: Deployment & Infrastructure Architecture

## 1. Executive Summary & Topology
CyberGuard is architected as an enterprise-grade cyber threat, phishing, and digital impersonation detection system deployable as a reproducible, secure, observable, and recoverable application. This document details the infrastructure topology, environment separation, containerization, migration pipelines, disaster recovery runbooks, and production readiness criteria.

### High-Level Deployment Topology

```text
                                 ┌─────────────────────────┐
                                 │   External Clients      │
                                 │  (Browsers, Agents, SOC)│
                                 └────────────┬────────────┘
                                              │ HTTPS (Port 443)
                                              ▼
                                 ┌─────────────────────────┐
                                 │   Edge Ingress / Nginx  │
                                 │ (TLS Termination, SPA)  │
                                 └────────────┬────────────┘
                                              │ Proxy Pass (HTTP)
                                              ▼
                    ┌─────────────────────────────────────────────────────┐
                    │               frontend_net (Bridge)                 │
                    └─────────────────────────┬───────────────────────────┘
                                              │ Internal API (Port 8000)
                                              ▼
                                 ┌─────────────────────────┐
                                 │   CyberGuard Backend    │
                                 │  (FastAPI, Non-Root)    │
                                 └────────────┬────────────┘
                                              │
                    ┌─────────────────────────┴───────────────────────────┐
                    │        backend_internal_net (Internal Bridge)       │
                    └───────────┬─────────────────────────────┬───────────┘
                                │                             │
                                ▼                             ▼
                    ┌───────────────────────┐     ┌───────────────────────┐
                    │ Managed PostgreSQL 16 │     │ Dedicated Background  │
                    │  (Persistent Storage) │     │ Worker (Concurrency 4)│
                    └───────────────────────┘     └───────────┬───────────┘
                                                              │
                                                              ▼
                                                   External Security APIs
                                                  (Protected by Circuits)
```

---

## 2. Environment Matrix
CyberGuard explicitly separates environments into four distinct tiers with defined security and configuration invariants:

| Capability / Invariant | Development (`DEV`) | Testing (`TEST`) | Staging (`STAGE`) | Production (`PROD`) |
| :--- | :--- | :--- | :--- | :--- |
| **Debug Mode** | `true` allowed | `false` | `false` | `false` (Strictly enforced) |
| **Database Engine** | SQLite or PostgreSQL | Isolated SQLite / Test DB | Dedicated PostgreSQL | Managed PostgreSQL (RDS/CloudSQL)|
| **Database Persistence** | Local volume / file | In-memory / Ephemeral | Persistent Volume | Multi-AZ Managed Storage |
| **Credentials & Secrets** | Ephemeral dev defaults | Ephemeral test secrets | Vault / Secret Manager | Strong KMS / Vault Secrets |
| **External TI Providers** | Optional / Mock | Mocked / Stubbed | Rate-limited sandbox | Live APIs with Circuit Breakers |
| **CORS Policy** | Localhost (3000, 5173) | N/A (Direct HTTP) | Specific Staging Domain | Strict Production FQDNs only |
| **Automated Backups** | None | Optional | Daily snapshots | Hourly snapshots (RPO $\le 1$h) |
| **Observability** | Basic stdout | In-memory test runner | Full Structured Logging | Structured JSON + Redaction + APM|
| **Worker Concurrency** | 2 workers (in-process)| 1 worker | 4 workers | Scaled dedicated worker pool |

---

## 3. Configuration Validation & Fail-Fast Guarantees
Centralized in `backend/config/deployment_config.py`:
- **Fail-Fast on Production Insecurities**:
  - `DEBUG=true` in `PRODUCTION` raises `ConfigurationValidationError` and terminates the process immediately.
  - Insecure or default signing secrets (e.g. `secret`, `changeme`, or $<32$ characters) raise `ConfigurationValidationError` in `PRODUCTION` and `STAGING`.
  - SQLite database URLs raise `ConfigurationValidationError` in `PRODUCTION`.
  - Wildcard CORS origins (`*`) raise `ConfigurationValidationError` in `PRODUCTION` when credentials or cookies are enabled.
- **Secret Redaction**:
  - No secret values, API keys, or database passwords are ever logged in plaintext during configuration audits or runtime errors.

---

## 4. Hardened Multi-Stage Container Architecture
Implemented in `backend/Dockerfile`:
- **Multi-Stage Build Pipeline**:
  - **Stage 1 (`builder`)**: Installs compilation toolchains (`gcc`, `libpq-dev`), builds Python wheels in an isolated `/build` environment.
  - **Stage 2 (`runtime`)**: Minimal `python:3.11-slim` image containing only required runtime dynamic libraries (`libpq5`, `curl`). Build compilers (`gcc`) are completely omitted from the production image, minimizing attack surface and CVE footprint.
- **Unprivileged Non-Root User**:
  - Dedicated system user and group created: `cyberguard` (`UID 10001`, `GID 10001`).
  - Container runs under `USER cyberguard`.
  - Application directories (`/app/backend/data/storage`, `/app/backend/data/backups`, `/app/backend/data/reports`) are pre-created with strict `10001:10001` permissions.
- **Immutable Container Filesystem**:
  - Container root filesystem is treated as read-only. Writes are confined to designated mount points (`cyberguard_storage`, `eml_evidence_data`, `reports_data`, `backup_data`).

---

## 5. Network Isolation & Port Security
In `docker-compose.yml` and `docker-compose.prod.yml`:
- **Network Segmentation**:
  - `frontend_net`: Connects public reverse proxy (Nginx) and backend API.
  - `backend_internal_net`: An internal bridge network connecting PostgreSQL, backend API, and background workers.
- **Port Exposure Policy**:
  - PostgreSQL port (`5432`) is **NOT** exposed to host or public networks in production (`ports: !reset []`). It is only accessible via the internal Docker bridge network.
  - Background workers have zero listening ports; they communicate outbound to the internal PostgreSQL database and external threat intelligence APIs.

---

## 6. Health, Liveness & Readiness Probes
Implemented in `backend/api/routes/health.py`:
- **Liveness Probe (`GET /health/live`)**:
  - Verifies process execution and event-loop responsiveness.
  - Does not depend on external databases, preventing cascading container restarts during brief database failovers.
- **Readiness Probe (`GET /health/ready`)**:
  - Confirms database query execution (`SELECT 1`) and storage filesystem writeability.
  - Returns HTTP 503 if dependencies are unready, instructing load balancers to withhold traffic.
- **Dependency Health Matrix (`GET /health/dependencies`)**:
  - Deep inspection of Database, Evidence Storage, Background Worker Queue, Realtime Hub, Cache, and Circuit Breakers.
  - Canonical status semantics: `HEALTHY`, `DEGRADED`, `UNAVAILABLE`, `UNKNOWN`.
- **Public Version Provenance (`GET /api/version`)**:
  - Reports safe deployment version, build SHA, environment tier, and driver types without leaking secrets.

---

## 7. Database Persistence, Migrations & Disaster Recovery
- **Deterministic Migrations**:
  - Managed via Alembic (`scripts/migrate.py`).
  - Includes pre-migration snapshot safeguards and verification.
- **Cryptographic Backups (`scripts/backup_database.py`)**:
  - Generates atomic, compressed, timestamped database backups (`cyberguard_backup_YYYYMMDD_HHMMSS.sqlite.gz` or `.dump`).
  - Generates companion `.manifest.json` containing cryptographic SHA-256 integrity hash, byte count, driver type, and timestamp.
  - Automatic retention policy pruning retains the last $N$ backups (default 10).
- **Verified Restore (`scripts/restore_database.py`)**:
  - Validates cryptographic SHA-256 against manifest before executing restore.
  - Creates a safety pre-restore snapshot of the target database prior to overwriting.
  - Executes SQLite PRAGMA integrity checks or PostgreSQL table validation post-restore.
- **Recovery Objectives**:
  - **RPO**: $\le 1\text{ hour}$
  - **RTO**: $\le 30\text{ minutes}$

---

## 8. Continuous Integration & Deployment Pipeline
Configured in `.github/workflows/ci.yml`:
1. **Stage 1 (Lint & Typecheck)**: Flake8 Python linting, `tsc -b` TypeScript static type check.
2. **Stage 2 (Automated Test Suite)**: Pytest execution across Sections 70–74.
3. **Stage 3 (Frontend Build)**: Vite production compilation and distribution artifact verification.
4. **Stage 4 (Docker Hardening Audit)**: Multi-stage Docker build and validation that the container runs strictly as non-root UID 10001.

---

## 9. Automated Deployment Smoke Test Suite
Implemented in `scripts/smoke_test.py`:
- Independent executable with zero external dependencies (uses standard library `urllib`).
- Verifies 7 core operational checkpoints:
  1. `CHECK_01_LIVENESS_PROBE` (`/health/live`)
  2. `CHECK_02_READINESS_PROBE` (`/health/ready`)
  3. `CHECK_03_DEPENDENCIES_MATRIX` (`/health/dependencies`)
  4. `CHECK_04_VERSION_PROVENANCE` (`/api/version`)
  5. `CHECK_05_LEGACY_HEALTH_PROBE` (`/health`)
  6. `CHECK_06_PERFORMANCE_METRICS_RBAC` (`/api/admin/performance/metrics`)
  7. `CHECK_07_CIRCUIT_BREAKER_OBSERVABILITY` (`/api/admin/performance/circuits`)

---

## 10. Production Readiness Checklist

### Application Verification
- [x] TypeScript build passes (`npm run build` exits 0).
- [x] All automated unit and regression tests pass (100% pass rate).
- [x] Database migrations execute deterministically and verify active revision.
- [x] Container liveness (`/health/live`) and readiness (`/health/ready`) probes active.
- [x] Automated deployment smoke test script passes all checks.

### Security Hardening
- [x] Production containers run as unprivileged non-root user (`cyberguard`, UID 10001).
- [x] Compiler toolchains (`gcc`, `libpq-dev`) removed from production runtime image.
- [x] Startup configuration validation rejects `DEBUG=true`, weak secrets, and SQLite in production.
- [x] Secret masking prevents credential exposure in logs and diagnostic endpoints.
- [x] PostgreSQL port unexposed to public network; internal bridge networking enforced.
- [x] Section 72 security controls (SSRF protection, rate limiting, security headers, upload guards) intact.

### Infrastructure & Operations
- [x] Persistent volume mounts configured for evidence, reports, and backups.
- [x] Automated cryptographic database backup utility (`scripts/backup_database.py`) verified.
- [x] Verified database restore utility (`scripts/restore_database.py`) tested with integrity checks.
- [x] Disaster recovery runbook (`docs/runbooks/disaster-recovery.md`) documented.
- [x] Deployment runbook (`docs/runbooks/deployment.md`) documented.
- [x] Operations runbook (`docs/runbooks/operations.md`) documented.
