# CyberGuard Runbook: Disaster Recovery (DR)

## 1. Overview & Recovery Objectives
This runbook defines the authoritative disaster recovery and service restoration procedures for the CyberGuard platform.

- **Recovery Point Objective (RPO)**: $\le 1\text{ hour}$ (hourly automated snapshots for managed PostgreSQL and persistent volumes).
- **Recovery Time Objective (RTO)**: $\le 30\text{ minutes}$ (automated container re-provisioning and verified database restoration).

---

## 2. Step-by-Step Recovery Procedure

### Step 1: Failure Detection & Assessment
- Alert trigger received via monitoring/health probe:
  - `/health/ready` returns HTTP 503.
  - `/health/dependencies` reports database or storage `UNAVAILABLE`.
  - Continuous container crash-loop backoff reported by container orchestrator.
- Identify the failure scope:
  - Total infrastructure outage (host/datacenter loss).
  - Database corruption or unrecoverable disk failure.
  - Evidence object storage volume detachment or corruption.

### Step 2: Incident Declaration
- Declare P1 Critical Incident in the incident response tracker.
- Notify the Security Operations Center (SOC) Lead and Infrastructure Engineering.
- Designate Incident Commander (IC) and Operations Lead (OL).

### Step 3: Service Isolation
- Divert or suspend external traffic at the load balancer / reverse proxy:
  ```bash
  # Return maintenance status 503 to prevent writes during restoration
  # Or isolate containers:
  docker compose stop backend worker
  ```
- Prevent in-flight worker jobs from executing partial updates against degraded storage.

### Step 4: Database Recovery
- Locate the most recent verified backup archive and manifest:
  ```bash
  ls -la backend/data/backups/*.manifest.json
  ```
- Run the verified restore utility (`scripts/restore_database.py`):
  ```bash
  python scripts/restore_database.py backend/data/backups/cyberguard_backup_YYYYMMDD_HHMMSS.sqlite.gz \
      --db-url "$DATABASE_URL"
  ```
- Verify cryptographic SHA-256 integrity and SQLite PRAGMA / PostgreSQL connectivity checks pass.

### Step 5: Evidence & Object Storage Recovery
- Inspect the storage volume mount (`/app/backend/data/storage`):
  ```bash
  df -h /app/backend/data/storage
  ls -la /app/backend/data/storage
  ```
- If restoring from cloud snapshots (e.g. AWS EBS, S3, or GCS volume snapshots), attach the snapshot volume to the host.
- Re-verify content-addressable SHA-256 integrity on randomly sampled evidence artifacts.

### Step 6: Application Restoration
- Deploy or restart application backend services:
  ```bash
  docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d backend
  ```
- Tail logs and verify clean startup without configuration validation errors:
  ```bash
  docker compose logs -f backend
  ```

### Step 7: Worker & Queue Restoration
- Start the dedicated background job worker service:
  ```bash
  docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d worker
  ```
- Verify workers acknowledge pending jobs without dead-letter floods.

### Step 8: Authentication & Session Verification
- Verify that administrative tokens and user sessions authenticate cleanly:
  ```bash
  curl -I http://localhost:8000/api/admin/users \
      -H "X-User-Email: admin@cyberguard.local" \
      -H "X-User-Role: PLATFORM_ADMIN" \
      -H "X-Tenant-Id: default"
  ```

### Step 9: Evidence & Audit Verification
- Confirm that chain-of-custody ledgers and forensic evidence records match historical hashes:
  ```bash
  python -c "from backend.db.session import SessionLocal; from backend.db.models import EvidenceModel; db = SessionLocal(); print('Total Evidence Records:', db.query(EvidenceModel).count())"
  ```

### Step 10: Smoke Test Execution
- Run the automated deployment smoke test script against the restored instance:
  ```bash
  python scripts/smoke_test.py --url http://localhost:8000
  ```
- Ensure all 7 checks pass with HTTP 200.

### Step 11: User & Stakeholder Communication
- Notify SOC analysts and stakeholders that platform services have returned to nominal operation.
- Re-enable client ingress traffic at the load balancer.

### Step 12: Post-Recovery Audit & Root Cause Analysis (RCA)
- Conduct post-mortem review within 24 hours.
- Document exact failure root cause, time to restore, and identify preventative controls.
