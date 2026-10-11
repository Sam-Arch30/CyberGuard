# CyberGuard Runbook: Daily Security Operations & Incident Mitigation

## 1. Overview
This operational guide provides step-by-step remediation procedures for system degradation, queue backlogs, resource constraints, and integration outages across the CyberGuard infrastructure.

---

## 2. Common Operational Incidents & Remediation

### 2.1 Background Worker Failure / Crash
**Symptoms**: Background jobs remain in `QUEUED` state indefinitely without progressing to `RUNNING`.
**Remediation**:
1. Check worker container status:
   ```bash
   docker compose ps worker
   docker compose logs --tail=100 worker
   ```
2. Restart worker container:
   ```bash
   docker compose restart worker
   ```
3. Inspect `/api/admin/performance/metrics` to verify worker concurrency matches configuration.

---

### 2.2 Background Job Queue Backlog
**Symptoms**: Queue depth exceeds 500 jobs; analysis latency exceeds performance budgets.
**Remediation**:
1. Scale worker replicas or concurrency:
   ```bash
   # Temporarily increase concurrency from 4 to 8:
   docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --scale worker=2
   ```
2. Verify high-priority jobs (`CRITICAL`, `HIGH`) execute ahead of bulk reports.

---

### 2.3 Database Degradation / High Connection Count
**Symptoms**: Database queries exceeding 250ms; connection pool exhaustion errors (`QueuePool limit of size 10 overflow 20 reached`).
**Remediation**:
1. Check active database connections:
   ```sql
   SELECT count(*), state FROM pg_stat_activity GROUP BY state;
   ```
2. Tune database pool settings in `.env`:
   ```bash
   DB_POOL_SIZE=20
   DB_MAX_OVERFLOW=30
   DB_POOL_RECYCLE=900
   ```
3. Restart backend service to re-initialize SQLAlchemy engine connection pools:
   ```bash
   docker compose restart backend
   ```

---

### 2.4 Evidence Storage Volume Full (Disk Exhaustion)
**Symptoms**: File ingestion fails with `OSError: [Errno 28] No space left on device`.
**Remediation**:
1. Check filesystem disk utilization:
   ```bash
   df -h /app/backend/data/storage
   ```
2. Prune old temporary uploads and test artifacts:
   ```bash
   find /app/backend/data/storage -name ".tmp_*" -mtime +1 -delete
   ```
3. Run backup archive pruning:
   ```bash
   python scripts/backup_database.py --keep 5
   ```
4. Expand underlying persistent volume capacity in cloud console if persistent capacity threshold is breached.

---

### 2.5 External Threat Intelligence Provider Outage
**Symptoms**: Third-party API (VirusTotal / RDAP / Geolocation) timeouts; high enrichment latency.
**Remediation**:
1. Inspect circuit breaker status:
   ```bash
   curl http://localhost:8000/api/admin/performance/circuits \
       -H "X-User-Role: PLATFORM_ADMIN"
   ```
2. Confirm the circuit has automatically transitioned to `OPEN` to prevent worker thread stalling.
3. If provider has recovered, manually probe or reset the breaker:
   ```bash
   curl -X POST http://localhost:8000/api/admin/performance/circuits/virustotal/reset \
       -H "X-User-Role: PLATFORM_ADMIN"
   ```

---

### 2.6 LLM Provider Outage (OpenAI / Anthropic / Gemini)
**Symptoms**: Natural language copilot and explanation requests timing out or returning 503.
**Remediation**:
1. CyberGuard automatically degrades to rule-based explainability and heuristic MITRE mapping.
2. In the administration portal (`/api/admin/settings`), temporarily switch `LLM_PROVIDER` to an active alternate or fallback provider.

---

### 2.7 High Memory / Container OOM-Killed
**Symptoms**: Backend container terminated with exit code 137 (OOM Killed).
**Remediation**:
1. Identify memory-intensive operations from `/api/admin/performance/slow-operations`.
2. Check for unbounded evidence parsing or excessive in-memory graph traversal.
3. Verify Section 72 streaming chunk limits (max 10MB default) are actively enforced.
4. Increase container memory limit in `docker-compose.prod.yml` if legitimate load requires larger working set.

---

### 2.8 Security Incident / Compromised Credential
**Symptoms**: Unauthorized administrative access attempts, unusual API token activity, or credential leak alert.
**Remediation**:
1. Revoke the affected user/token immediately in the administration console (`PATCH /api/admin/users/{user_id}/status` -> `SUSPENDED`).
2. Rotate `CYBERGUARD_AUTH_SECRET` in environment variables:
   ```bash
   # Invalidate all active JWT tokens globally:
   docker compose restart backend
   ```
3. Review append-only audit trail (`/api/audit`) to trace all actions performed by the compromised identity.
