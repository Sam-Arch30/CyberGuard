# 08 — Deployment & Infrastructure Audit

> **Deployment Targets:** Local Bare-Metal / Multi-Container Docker / Cloud Server  
> **Container Runtime:** Docker Engine 24+ & Docker Compose v2  
> **Orchestration Config:** `docker-compose.yml` (PostgreSQL 16, FastAPI Backend, Nginx Frontend)  

---

## 1. Environment Comparison Matrix

| Architectural Dimension | Local Bare-Metal (Development) | Docker Multi-Container (`docker-compose`) | Cloud / Serverless Production |
|---|---|---|---|
| **Database Engine** | SQLite 3 (`backend/data/mailtrace.db`) | PostgreSQL 16 Alpine (`postgres:16-alpine`) | Managed PostgreSQL (RDS, Cloud SQL, Supabase) |
| **Database URL** | `sqlite:///backend/data/mailtrace.db` | `postgresql://mailtrace:...@postgresql:5432/mailtrace` | Secure remote connection string via secrets manager |
| **Database Persistence** | Host filesystem (survives restart) | Named Docker Volume (`postgres_data`) | Managed cloud disk / automated snapshots |
| **Raw EML File Storage** | `backend/data/eml_store/*.eml` (Host disk) | Container filesystem `/app/backend/data/eml_store/` (**Wiped on restart**) | **Requires Object Storage** (S3, GCS, MinIO, or EFS) |
| **PDF Report Storage** | `backend/data/reports/*.pdf` (Host disk) | Container filesystem `/app/backend/data/reports/` (**Wiped on restart**) | **Requires Object Storage** (S3, GCS, MinIO) |
| **Backend Execution** | `uvicorn backend.main:app --port 8000` | Python 3.11-slim container (`uvicorn backend.main:app`) | Container Service (ECS, Cloud Run with persistent volumes) |
| **Frontend Execution** | `npm run dev` (Vite dev server on port 5173)| Nginx Alpine serving compiled assets on port 3000 | Nginx container or CDN (Cloudflare Pages, CloudFront) |
| **Reverse Proxy** | Vite dev server proxy or direct CORS | Nginx reverse proxy routing `/api/` to `backend:8000` | Nginx Ingress Controller / Application Load Balancer |
| **Startup Order** | Manual (Start backend, then start frontend)| Docker healthchecks (`depends_on: service_healthy`) | Orchestrator readiness probes |
| **Air-Gapped Operation** | Fully supported (Offline first) | Fully supported (Pre-built container images) | Supported with private container registries |

---

## 2. Docker & Container Audit

### 2.1 Backend Dockerfile (`backend/Dockerfile`)
```dockerfile
FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl gcc libpq-dev && rm -rf /var/lib/apt/lists/*
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/ ./backend/
COPY alembic.ini .
ENV PYTHONPATH=/app PYTHONUNBUFFERED=1
EXPOSE 8000
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
```
- **Strengths:**
  - Multi-stage dependency installation with `curl` for container health checks and `libpq-dev` for Postgres.
  - Proper `PYTHONPATH=/app` configuration.
- **Weaknesses:**
  - `backend/requirements.txt` is missing `reportlab` and `pillow`. If built directly without pre-installed wheels, PDF generation endpoints will crash inside the container.
  - Runs as `root` inside the container. A non-root application user (`appuser`) should be created for least-privilege security.

### 2.2 Frontend Dockerfile (`frontend/Dockerfile`)
```dockerfile
# Stage 1: Build static bundle
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY src/ ./src/
COPY public/ ./public/
COPY index.html vite.config.ts tsconfig*.json ./
ARG VITE_API_BASE_URL=""
ENV VITE_API_BASE_URL=$VITE_API_BASE_URL
RUN npm run build

# Stage 2: Serve via Nginx
FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
```
- **Strengths:**
  - Clean multi-stage build pattern preventing dev tools and `node_modules` from leaking into the runtime container.
  - Uses `npm ci` for reproducible dependency installation.
  - Configurable `VITE_API_BASE_URL` build argument.

### 2.3 Nginx Configuration (`frontend/nginx.conf`)
- Reverse proxies `/api/` requests to `http://backend:8000/api/` with HTTP/1.1 and keepalive headers.
- Long proxy timeouts: `proxy_read_timeout 120s`, `proxy_send_timeout 120s` (essential for long-running threat intelligence queries).
- Security headers: Injects `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `X-XSS-Protection`, `Referrer-Policy`.
- SPA fallback: `try_files $uri $uri/ /index.html;`.
- Dedicated health check probe: `location = /nginx-health`.

### 2.4 Compose Orchestration (`docker-compose.yml`)
- Three services: `postgresql`, `backend`, `frontend`.
- Strong healthcheck dependency graph:
  - `backend` waits for `postgresql` to pass `pg_isready`.
  - `frontend` waits for `backend` to pass `curl http://localhost:8000/health`.
- **Critical Flaw:** Named volume `postgres_data` preserves PostgreSQL tables, but **no persistent volume is mounted for the backend container**. All uploaded `.eml` files and generated PDF reports are stored on the ephemeral container write layer and are wiped whenever `docker compose down` or container recreation occurs.

---

## 3. Environment Variable Configuration

| Variable | Default Value | Sensitivity | Purpose |
|---|---|---|---|
| `DATABASE_URL` | `sqlite:///backend/data/mailtrace.db` | High (if remote) | Primary database connection string |
| `POSTGRES_USER` | `mailtrace` | Medium | Database username |
| `POSTGRES_PASSWORD` | `mailtrace_password` | High | Database password (Must be changed in prod) |
| `POSTGRES_DB` | `mailtrace` | Low | Database name |
| `CORS_ORIGINS` | `localhost:3000, 5173, etc.` | Medium | Comma-delimited list of allowed browser origins |
| `LOG_LEVEL` | `INFO` | Low | Python logging verbosity |
| `IP_INTELLIGENCE_PROVIDER` | `ipapi` | Low | Active IP geolocation provider (`ipapi`, `ipinfo`, `mock`) |
| `IPAPI_KEY` | None | High | IP-API commercial key |
| `IPINFO_TOKEN` | None | High | IPInfo API bearer token |
| `LLM_PROVIDER` | `gemini` | Low | Active LLM inference provider (`gemini`, `openai`, `mock`) |
| `GEMINI_API_KEY` | None | High | Google Gemini API key |
| `OPENAI_API_KEY` | None | High | OpenAI API key |
| `LLM_MODEL` | `gemini-1.5-flash` | Low | Target model identifier |
| `MAX_UPLOAD_SIZE_MB` | `10` | Low | Maximum allowed upload size (MB) |
| `RATE_LIMIT_ENABLED` | `true` | Low | Global rate limiting toggle |

---

## 4. Serverless & Cloud Limitations

1. **In-Flight State & Worker Timeouts:**
   - Synchronous EML analysis taking up to 75 seconds will trigger HTTP 504 Gateway Timeouts on standard serverless platforms (e.g. AWS API Gateway has a strict 29-second hard timeout).
2. **Local Filesystem Ephemerality:**
   - Serverless containers (such as AWS Lambda, Google Cloud Run, Azure Container Apps) operate on stateless, ephemeral filesystems. File paths in `ReportModel.file_path` will point to non-existent temporary storage once the container scales to zero.
3. **In-Memory Caches:**
   - `IPIntelligenceCache`, `DomainIntelligenceCache`, and `RateLimiterMiddleware` are in-memory. In a horizontally scaled serverless environment with multiple container instances, caches are not shared, leading to duplicate external API queries and non-synchronized rate limiting.
   - **Remediation for Phase 2:** Migrate in-memory caches and rate-limiting buckets to a shared Redis cluster, and migrate `.eml` and report files to S3 / Cloud Storage buckets.
