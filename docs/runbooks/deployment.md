# CyberGuard Runbook: Production Deployment

## 1. Prerequisites
Before initiating a production deployment:
1. Ensure all code changes are merged to `main` and have passed all CI stages:
   - Lint & Typecheck
   - Automated Pytest Suite
   - Security Scanning
   - Docker Multi-Stage Build & Non-Root User Verification
2. Ensure release artifacts are tagged with a semantic version (e.g. `v1.2.0`) and commit SHA.
3. Verify access to deployment target credentials (e.g. Kubernetes, AWS ECS, or Docker Compose host).
4. Verify current production database backup exists.

---

## 2. Pre-Deployment Environment Validation
Check that required production configuration variables are defined:
```bash
# Verify non-empty, strong signing secret
test -n "$CYBERGUARD_AUTH_SECRET" || (echo "ERROR: CYBERGUARD_AUTH_SECRET missing!" && exit 1)

# Verify production PostgreSQL connection string
echo "$DATABASE_URL" | grep -q "postgresql://" || (echo "ERROR: PostgreSQL DATABASE_URL required!" && exit 1)

# Verify CORS does not contain wildcard
echo "$CORS_ORIGINS" | grep -v "\*" || (echo "ERROR: Wildcard CORS forbidden in production!" && exit 1)
```

---

## 3. Build & Container Packaging
Build the production Docker images:
```bash
# Build multi-stage hardened backend image
docker build -t cyberguard-backend:v1.2.0 -f backend/Dockerfile .

# Build multi-stage Nginx frontend image
docker build -t cyberguard-frontend:v1.2.0 -f frontend/Dockerfile .
```

Verify that the backend container runs as non-root:
```bash
docker run --rm cyberguard-backend:v1.2.0 id -u
# Output must be: 10001
```

---

## 4. Pre-Deployment Database Backup & Migration
1. Create a pre-deployment database backup snapshot:
   ```bash
   python scripts/backup_database.py --db-url "$DATABASE_URL" --output-dir "/var/backups/cyberguard"
   ```
2. Apply pending database migrations:
   ```bash
   python scripts/migrate.py --revision head
   ```

---

## 5. Deployment Execution
Deploy containers using the production Compose configuration:
```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml pull
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --remove-orphans
```

---

## 6. Health & Readiness Verification
Verify container lifecycle probes:
```bash
# 1. Liveness check
curl -f http://localhost:8000/health/live

# 2. Readiness check
curl -f http://localhost:8000/health/ready

# 3. Deep subsystem dependency check
curl -f http://localhost:8000/health/dependencies
```

---

## 7. Deployment Smoke Test Execution
Run the automated non-destructive deployment smoke test suite:
```bash
python scripts/smoke_test.py --url http://localhost:8000
```
Ensure all 7 checks pass with HTTP 200.

---

## 8. Rollback Procedure
If readiness checks or smoke tests fail:
1. Revert container images to the previous stable release tag:
   ```bash
   docker compose -f docker-compose.yml -f docker-compose.prod.yml down
   # Roll back image tags in environment and restart:
   docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
   ```
2. If migrations introduced breaking schema changes, restore the pre-deployment database snapshot:
   ```bash
   python scripts/restore_database.py /var/backups/cyberguard/cyberguard_backup_PRE_DEPLOY.sqlite.gz \
       --db-url "$DATABASE_URL"
   ```
3. Re-run smoke tests to confirm nominal operation on the rolled-back version.

---

## 9. Post-Deployment Monitoring
Monitor the platform for at least 30 minutes following deployment:
- Inspect `/api/admin/performance/slow-operations` for unexpected latency regressions.
- Inspect `/api/admin/performance/circuits` for tripped third-party circuit breakers.
- Check backend log streams for unhandled exceptions or error surges.
