# CyberGuard — AI-Powered Cyber Threat, Phishing & Digital Impersonation Detection and Response System

[Current validation and limitations](docs/development-progress.md)
[![Backend](https://img.shields.io/badge/backend-FastAPI%20%2F%20Python%203.11-blue.svg)]()
[![Frontend](https://img.shields.io/badge/frontend-React%2019%20%2F%20TypeScript%20%2F%20Vite-61dafb.svg)]()

[![Status](https://img.shields.io/badge/roadmap-Section%2075%20Final%20Integration-success.svg)]()

> **CyberGuard** is a unified, air-gapped-ready Cyber Threat, Phishing, and Digital Impersonation Detection and Response Platform for Security Operations Centers (SOCs).
> It provides an end-to-end security lifecycle: ingests multi-vector security artifacts (emails, files, URLs, domains, endpoint telemetry), runs deterministic static forensic inspection, correlates cross-source infrastructure, produces server-authoritative risk assessments, generates explainable ATT&CK-mapped attack paths, and coordinates human-governed remediation playbooks backed by cryptographic chains of custody.

---

For the repaired local prototype and new detection/reporting UI, use [the startup guide](README.PROTOTYPE.md).

## Table of Contents

1. [What CyberGuard Is](#1-what-cyberguard-is)
2. [Core Capabilities](#2-core-capabilities)
3. [Architecture & Golden Path](#3-architecture--golden-path)
4. [Local Setup & Prerequisites](#4-local-setup--prerequisites)
5. [Environment Variables Reference](#5-environment-variables-reference)
6. [Development Workflow](#6-development-workflow)
7. [Testing & Quality Verification](#7-testing--quality-verification)
8. [Demo Mode & Scenario Catalog](#8-demo-mode--scenario-catalog)
9. [Deployment & Infrastructure](#9-deployment--infrastructure)
10. [Security Model & Trust Boundaries](#10-security-model--trust-boundaries)
11. [Known Limitations & Fallbacks](#11-known-limitations--fallbacks)
12. [Project Status](#12-project-status)

---

## 1. What CyberGuard Is

CyberGuard transforms raw, deceptive security artifacts into actionable forensic intelligence for Tier 1–3 SOC analysts, incident response teams, and security executives. Rather than operating as an opaque black-box scanner that outputs unsubstantiated scores, CyberGuard constructs an unbroken, cryptographically hashed chain of custody (`EV-*`), provides itemized risk contribution factors, correlates shared attacker infrastructure across corporate assets, and coordinates human-authorized response actions.

---

## 2. Core Capabilities

- **Universal Artifact Ingestion**: Securely handles RFC-822 `.eml` emails, URLs, domains, files, PE attachments, JSON events, and endpoint telemetry.
- **Explainable Threat Scorer**: Calculates a server-authoritative 0–100 risk score derived from mathematical point contributions (authentication anomalies, credential harvesting links, lookalike domains, weaponized payloads) with complete mathematical audit trails.
- **Safe Static Attachment Forensics**: Never executes untrusted attachments. Inspects PE magic headers (`MZ`), Shannon entropy, section anomalies, macro streams, and disguised extensions (`.pdf.exe`) safely in-process.
- **Hop-by-Hop SMTP Relay Reconstruction**: Deconstructs `Received:` headers in strict reverse transmission order, identifies hop delay latencies, and isolates the earliest untrusted public relay hop.
- **Cross-Source Infrastructure Correlation**: Graphically models and links Emails, Domains, IPs, ASNs, URLs, File Hashes, and Endpoint processes with Cytoscape.js.
- **Interactive ATT&CK Attack Paths**: Reconstructs multi-stage attack progressions mapped to MITRE ATT&CK tactics (Initial Access, Execution, Credential Access, Command & Control).
- **Human-Governed Remediation**: Proposes actionable containment measures (Block Sender Domain, Quarantine Email, Host Isolation) with strict approval boundaries (`status: RECOMMENDED`).
- **Forensic Evidence Custody**: Immutable SHA-256 storage, verified custodial transfers, and court-admissible audit logging.
- **Executive & Technical Reporting**: Generates tamper-hashed SOC incident reports and CISO executive summaries.
- **Deterministic Demo Environment**: Isolated, resettable demonstration mode with 4 realistic security scenarios and zero pollution of production data.

---

## 3. Architecture & Golden Path

### The End-to-End Golden Path Workflow

```text
Artifact / Event Input
        ↓
Universal Ingestion Gateway (SHA-256 Hash Generated)
        ↓
Analysis Orchestrator DAG
        ↓
Detection Pipeline & Heuristic Analyzers
        ↓
Cross-Source Graph Correlation
        ↓
Server-Authoritative Risk Assessment
        ↓
Explainability & Evidence Attribution
        ↓
Alert Triage & Incident Creation
        ↓
Investigation Workspace
        ↓
Interactive ATT&CK Attack Path
        ↓
Response Recommendations (Status: RECOMMENDED)
        ↓
Human-Approved Playbook Execution
        ↓
Evidence Chain of Custody (Immutable SHA-256)
        ↓
Executive & Technical Report Generation
        ↓
History, Audit & Telemetry Monitoring
```

---

## 4. Local Setup & Prerequisites

### Prerequisites
- **Node.js**: v18.0.0 or higher
- **Python**: 3.10, 3.11, or 3.12
- **RAM**: Minimum 4 GB RAM recommended

### Step 1: Clone Repository
```bash
git clone https://github.com/Sam-Arch30/CyberGuard.git
cd CyberGuard
```

### Step 2: Backend Setup
```bash
python3 -m venv backend/venv
source backend/venv/bin/activate
pip install -r backend/requirements.txt

# Run migrations and start server
PYTHONPATH=. python3 scripts/migrate.py
PYTHONPATH=. uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```

### Step 3: Frontend Setup
```bash
# In project root:
npm install
npm run dev
```
Access the application at `http://localhost:5173`.

---

## 5. Environment Variables Reference

| Variable | Description | Default | Environment |
| :--- | :--- | :--- | :--- |
| `ENVIRONMENT` | Runtime mode (`DEVELOPMENT`, `STAGING`, `PRODUCTION`) | `DEVELOPMENT` | All |
| `DATABASE_URL` | SQLAlchemy connection string | `sqlite:///./data/cyberguard.db` | All |
| `SECRET_KEY` | Cryptographic secret for signing | (Auto-generated dev key) | Prod Required |
| `CORS_ORIGINS` | Permitted frontend origins (comma-separated) | `http://localhost:5173,...` | All |
| `STORAGE_BACKEND` | Evidence vault storage (`LOCAL`, `S3`, `GCS`) | `LOCAL` | All |
| `STORAGE_LOCAL_ROOT` | Local evidence storage directory | `data/evidence_vault` | All |
| `BACKGROUND_WORKER_ENABLED` | Run in-process background worker | `true` | Dev/Single-node |
| `WORKER_CONCURRENCY` | Worker execution slots | `2` | All |
| `CIRCUIT_BREAKER_ENABLED` | External provider fault protection | `true` | All |

---

## 6. Development Workflow

- **Backend API**: FastAPI with automatic Swagger docs at `http://localhost:8000/docs`.
- **Frontend SPA**: React 19, Vite, TypeScript, Tailwind CSS, Lucide Icons.
- **Production Build**:
  ```bash
  npm run build
  ```
  Runs `tsc -b && vite build` with zero type errors.

---

## 7. Testing & Quality Verification

```bash
# Run Section 70-75 Regression Test Suite
PYTHONPATH=. ./backend/venv/bin/pytest \
  backend/tests/test_section70_security_operations_automation.py \
  backend/tests/test_section71_platform_administration_governance.py \
  backend/tests/test_section72_security_hardening.py \
  backend/tests/test_section73_performance_scalability.py \
  backend/tests/test_section74_deployment_infrastructure.py \
  backend/tests/test_section75_final_integration_demo.py -v

# Run Automated Smoke Test Probes
PYTHONPATH=. ./backend/venv/bin/python3 scripts/smoke_test.py
```

---

## 8. Demo Mode & Scenario Catalog

CyberGuard features an isolated, deterministic demonstration mode with 4 realistic security scenarios:

1. **Scenario A — Targeted Phishing**: PayPal brand lookalike domain (`paypa1-security-update.com`), credential harvesting URL, failing SPF/DKIM/DMARC.
2. **Scenario B — Executive Impersonation & BEC**: C-suite wire transfer authorization ($248,500), display-name impersonation, urgency financial coercion.
3. **Scenario C — Weaponized Executable Attachment**: Disguised double-extension file (`Mandatory_Compliance_Review.pdf.exe`) with PE magic header (`MZ`).
4. **Scenario D — Multi-Stage Attack**: Phishing delivery $\to$ malicious script URL $\to$ C2 infrastructure IP 203.0.113.88 $\to$ endpoint PowerShell execution $\to$ correlated Incident.

### Demo Commands
- **List Scenarios**: `GET /api/demo/scenarios`
- **Execute Scenario**: `POST /api/demo/scenarios/{scenario_id}/execute`
- **Demo Status**: `GET /api/demo/status`
- **Safe Reset**: `POST /api/demo/reset` (purges only `is_demo: true` records, strictly preserving production data).

For the complete presentation walkthrough, see [Demo Guide](docs/demo-guide.md).

---

## 9. Deployment & Infrastructure

- **Containerization**: Hardened multi-stage `Dockerfile` executing under non-root UID 10001 (`cyberguard`).
- **Network Isolation**: Dual-network topology (`frontend_net`, `backend_internal_net`) preventing public database exposure.
- **Health Probes**: Canonical container probes at `/health/live`, `/health/ready`, `/health/dependencies`, and `/api/version`.
- **Database Backup & Recovery**: Cryptographic SHA-256 backup utility (`scripts/backup_database.py`) and verified restore tool (`scripts/restore_database.py`).
- **Runbooks**: Complete operational documentation in `docs/runbooks/`:
  - [Deployment Runbook](docs/runbooks/deployment.md)
  - [Operations Runbook](docs/runbooks/operations.md)
  - [Disaster Recovery Runbook](docs/runbooks/disaster-recovery.md)

---

## 10. Security Model & Trust Boundaries

- **Zero Fabricated Scores**: Server-authoritative calculations; client never manufactures risk scores or detection findings.
- **Human-in-the-Loop Safeguards**: Remediation recommendations default to `RECOMMENDED`; destructive commands require verified role approvals.
- **SSRF & Path Traversal Guards**: Restricts outbound connections to loopback/private CIDRs; sanitizes all storage paths.
- **Decompression Bomb Protection**: Enforces 20:1 max ratio, 100MB uncompressed ceiling, and 5-level directory depth limit.
- **Prompt Injection Defense**: Untrusted security text is delimiter-fenced and isolated from system directives.

---

## 11. Known Limitations & Fallbacks

1. **Air-Gapped Operation**: When external threat intelligence APIs are unreachable, CyberGuard automatically degrades to local heuristic inspection and internal rule evaluation without halting analysis.
2. **Deterministic LLM Fallback**: If cloud LLM providers are unavailable, the explainability engine falls back to deterministic rule justification.
3. **Encrypted Archives**: Password-protected attachments cannot be statically analyzed and are flagged as opaque high-risk containers.

---

## 12. Project Status

- **Status**: **COMPLETE & PRODUCTION-HARDENED**
- **Roadmap Section**: Section 75 (Final Integration & Demo Hardening)
- **All 75 Roadmap Sections Delivered, Integrated, and Validated**.
