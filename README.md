# MailTrace AI - Cybersecurity Email Forensic Investigation Platform

MailTrace AI is an enterprise-grade cyber forensic investigation platform designed to ingest, parse, inspect, and analyze RFC-822 / `.eml` email files, trace hop-by-hop relay paths, perform domain/IP intelligence lookups, detect lookalike spoofing, evaluate email security authentication (SPF, DKIM, DMARC), extract Indicators of Compromise (IOCs), and manage case investigations.

---

## Quick Start with Docker (Recommended)

Run the full stack (Frontend, FastAPI Backend, and PostgreSQL database) with a single command:

```bash
docker compose up --build
```

To run in detached background mode:

```bash
docker compose up --build -d
```

### Services & Port Mappings

| Service | Port (Host) | Internal Port | Description | Health Endpoint |
| :--- | :--- | :--- | :--- | :--- |
| **frontend** | `3000` | `80` (Nginx) | React / Vite SPA & Reverse Proxy | `http://localhost:3000/nginx-health` |
| **backend** | `8000` | `8000` (Uvicorn) | FastAPI Forensic Analysis Engine | `http://localhost:8000/health` |
| **postgresql** | `5432` | `5432` | Persistent PostgreSQL 16 DB | `pg_isready` probe |

- **Web Application UI**: [http://localhost:3000](http://localhost:3000)
- **FastAPI Interactive Docs (Swagger)**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **API Health Check**: [http://localhost:8000/health](http://localhost:8000/health)

To stop the containers:

```bash
docker compose down
```

To stop containers and purge all database volume data:

```bash
docker compose down -v
```

---

## Architecture & Docker Design

### 1. Multi-Stage Frontend Build
- **Builder Stage**: Uses `node:20-alpine`, installs dependencies with `npm ci`, compiles TypeScript, and creates a production bundle via Vite.
- **Production Stage**: Uses `nginx:alpine` to serve static assets with gzip compression, caching headers, and automatic SPA route fallback (`try_files $uri $uri/ /index.html`).
- **Reverse Proxy**: Nginx proxies all `/api/` calls directly to `http://backend:8000/api/`.

### 2. Backend Engine & Resilience
- **Runtime**: Uses `python:3.11-slim` with `curl` for container health monitoring and `libpq-dev` for PostgreSQL connectivity.
- **Graceful DB Retry Mechanism**: The backend features an automated retry loop (`init_db`) that polls and retries the database connection during container startup if PostgreSQL takes time to initialize.
- **Dependency Orchestration**: Docker Compose uses `condition: service_healthy` to ensure PostgreSQL is healthy before starting the backend, and the backend is healthy before serving the frontend.

### 3. Data Persistence
- PostgreSQL stores all forensic case files, correlation telemetry, and audit trails in a dedicated Docker named volume (`postgres_data`), ensuring zero data loss across container rebuilds.

### 4. Zero Baked Secrets & Security
- `.dockerignore` prevents `.env`, local `.db` SQLite files, `node_modules`, and Python `venv` from entering Docker build contexts.
- Sensitive credentials (`GEMINI_API_KEY`, `OPENAI_API_KEY`, `IP_INTELLIGENCE_API_KEY`) are passed strictly via environment variables at runtime.

---

## Configuration & Environment Variables

Copy `.env.example` to `.env` to configure optional external threat intelligence and LLM providers:

```bash
cp .env.example .env
```

| Variable | Default | Description |
| :--- | :--- | :--- |
| `POSTGRES_USER` | `mailtrace` | Database username |
| `POSTGRES_PASSWORD` | `mailtrace_password` | Database password |
| `POSTGRES_DB` | `mailtrace` | Database name |
| `DATABASE_URL` | Auto-constructed | SQLAlchemy database connection string |
| `IP_INTELLIGENCE_PROVIDER` | `ipapi` | IP provider (`ipapi`, `ipinfo`, or `mock`) |
| `LLM_PROVIDER` | `gemini` | AI Analyst LLM provider (`gemini`, `openai`, or `mock`) |
| `GEMINI_API_KEY` | - | Google Gemini API key |
| `OPENAI_API_KEY` | - | OpenAI API key |
| `MAX_UPLOAD_SIZE_MB` | `10` | Maximum file upload size limit |
| `RATE_LIMIT_ENABLED` | `true` | Enable rate limiting middleware |

---

## Local Development (Without Docker)

### Backend
```bash
python -m venv backend/venv
source backend/venv/bin/activate
pip install -r backend/requirements.txt
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

### Frontend
```bash
npm install
npm run dev
```

### Running Tests
```bash
PYTHONPATH=. backend/venv/bin/pytest backend/tests
npm run build
npm run lint
```
