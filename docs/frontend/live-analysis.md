# Section 37 — Live Analysis & Pipeline DAG Orchestrator

## Overview

Live Analysis bridges the critical operational transition in CyberGuard between **Ingestion**, **Analysis**, and **Investigation**. When an analyst or automated pipeline ingests raw evidence (email `.eml`, suspicious URL, binary artifact, or system authentication log), CyberGuard initializes a deterministic, multimodal Directed Acyclic Graph (DAG) of analysis tasks and executes them asynchronously.

The Live Analysis interface surfaces strictly real backend execution state. It adheres to a strict zero-simulation principle:
- Zero fake progress bars (no synthetic 37%, 73%, or 91% increments)
- Zero mock delays or synthetic `setTimeout` intervals
- Zero fabricated detections, findings, or risk percentages
- Live truthful status streamed directly from the Python backend via Server-Sent Events (SSE) with robust polling fallback.

---

## Architecture Flow

```
Raw Input (File, URL, Text, Event)
        ↓
Universal Ingestion Gateway (/api/ingest/*)
        ↓
Cryptographic Hashing & Artifact Persistence (artifacts table)
        ↓
Evidence Normalization & Investigation Linking (evidence & investigations tables)
        ↓
AnalysisRun Initialization (analysis_runs table)
        ↓
Multimodal Task Graph Generation (AnalysisTask DAG blueprint)
        ↓
Intelligent Analysis Orchestrator (AnalysisOrchestrator.execute_run)
  ┌────────────────────────────────────────────────────────┐
  │ Topological DAG Execution:                             │
  │  • Evidence Validation & Artifact Classification      │
  │  • MIME & Header Forensics / Network Probing           │
  │  • Indicator & Observable Extraction (IOCs)           │
  │  • Heuristics, ML Inference & Knowledge Graph Query   │
  │  • Threat Memory & Campaign Correlation                │
  │  • Unified Risk Assessment & Finding Aggregation      │
  └────────────────────────────────────────────────────────┘
        ↓
Real-Time Event Broadcasting (AnalysisEventHub -> SSE Stream / Polling)
        ↓
Live Analysis View (/investigations/:id/analysis)
        ↓
Investigation Handoff (/investigations/:id/overview)
```

---

## Canonical Route & Navigation

- **Canonical URL**: `/investigations/:investigationId/analysis` (aliased as `/analysis/:id`)
- **Direct Access**: Analysts can paste or bookmark `/investigations/:investigationId/analysis`. The view resolves the investigation or artifact ID, restores the authoritative run state, and attaches to the active SSE stream.
- **Workflow Transition**:
  1. Universal Drop Zone ingests evidence.
  2. Drop Zone navigates to `/investigations/:id/analysis`.
  3. Live Analysis screen renders the task DAG, running task highlight, live activity stream, and finding preview.
  4. Upon reaching a terminal state (`COMPLETED` or `PARTIAL`), the analyst clicks **`[Open Investigation]`** to transition into `/investigations/:id/overview`.

---

## AnalysisRun Lifecycle

An `AnalysisRun` transitions through the following authoritative states:

| State | Semantic Meaning | UI Presentation |
|---|---|---|
| `INITIALIZING` | Run record created, tasks being registered into the database | Indeterminate spinner, "Initializing analysis pipeline..." |
| `QUEUED` | Tasks registered and awaiting worker thread allocation | "Queued for execution", pending indicators |
| `RUNNING` | Analyzers actively executing in topological DAG order | Pulsing blue badge, active analyzer card, live elapsed time |
| `PARTIAL` | One or more non-critical analyzers failed/degraded, but existing findings remain authoritative | Warning badge: "Partially Completed", failed analyzer explanation, partial badge |
| `COMPLETED` | All analyzers successfully executed and risk assessment persisted | Success badge: "Analysis Complete", risk score card, handoff CTA |
| `FAILED` | Critical pipeline failure prevented risk computation | Danger badge: "Analysis Failed", safe retry action button |
| `CANCELLED` | Analyst explicitly requested run termination | Neutral badge: "Cancelled", rerun/retry option |

---

## AnalysisTask Model & States

Each analyzer execution is represented by an atomic `AnalysisTask` record:

```
AnalysisTask
├── id: UUID
├── analysis_run_id: UUID (foreign key to analysis_runs)
├── analyzer_id: str (e.g., 'email_auth_analyzer', 'url_reputation_analyzer')
├── task_type: str (e.g., 'MIME_ANALYSIS', 'IOC_EXTRACTION', 'RISK_ASSESSMENT')
├── title: str
├── description: str
├── status: AnalysisTaskStatusEnum
├── dependency_ids: list[str] (upstream task prerequisite IDs)
├── started_at: datetime | null
├── completed_at: datetime | null
├── duration_seconds: float | null
├── progress: int | null (0-100 if analyzer exposes internal milestones)
├── message: str | null
├── error: str | null
├── result_count: int | null (authoritative count of IOCs/findings extracted)
└── version: str
```

### Task Status Semantics

- **`PENDING`** (`○`): Task has not yet started; waiting for dependencies.
- **`QUEUED`** (`○`): Dependencies satisfied; queued for execution.
- **`RUNNING`** (`◉`): Actively executing; highlighted in "Currently Analyzing" card.
- **`COMPLETED`** (`✓`): Succeeded; results persisted.
- **`SKIPPED`** (`—`): Intentionally bypassed (e.g., no attachments found to scan).
- **`FAILED`** (`!`): Analyzer encountered an error or external provider timeout.
- **`BLOCKED`** (`⊘`): Upstream dependency failed, preventing this task from executing.
- **`CANCELLED`** (`—`): Run was cancelled before or during execution.

---

## Multimodal Task DAG Blueprints

CyberGuard does not assume all evidence is an email. Analyzers are deterministically mapped based on artifact classification:

### 1. EMAIL Artifacts (9 Tasks)
```
[validation] Evidence Integrity Validation
     ↓
[artifact_classification] MIME & Header Structure Analysis
     ↓
[email_auth] SPF, DKIM, DMARC & Authentication Verification
     ↓
[ioc_extraction] IOC Extraction & Observable Harvesting
     ↓
[url_intelligence] Extracted URL & Domain Threat Intelligence
     ↓
[attachment_analysis] Attachment Static & Heuristic Inspection
     ↓
[nlp_analysis] NLP Sentiment & Social Engineering Detection
     ↓
[threat_memory] Threat Knowledge Graph & Memory Correlation
     ↓
[risk_assessment] Multi-Engine Unified Risk Scoring
```

### 2. URL / DOMAIN / IP Artifacts (6 Tasks)
```
[validation] Target Syntax & Reachability Validation
     ↓
[artifact_classification] Domain & Network Protocol Classification
     ↓
[network_probing] DNS, WHOIS & TLS Certificate Inspection
     ↓
[reputation_lookup] Threat Intelligence & Blacklist Verification
     ↓
[lookalike_detection] Homoglyph & Brand Impersonation Analysis
     ↓
[risk_assessment] Unified Network Risk Assessment
```

### 3. AUTH_LOG / SYSTEM_LOG Artifacts (5 Tasks)
```
[validation] Log Schema & Timestamp Normalization
     ↓
[artifact_classification] Event Source & Identity Extraction
     ↓
[behavioral_baseline] User Baseline & Velocity Profiling
     ↓
[anomaly_detection] Credential Stuffing & ATO Detection
     ↓
[risk_assessment] Identity Risk Assessment
```

### 4. IMAGE / MULTIMEDIA Artifacts (4 Tasks)
```
[validation] File Format & Binary Integrity Validation
     ↓
[artifact_classification] EXIF Metadata & Provenance Analysis
     ↓
[manipulation_detection] Visual Tampering & QR Code Extraction
     ↓
[risk_assessment] Multimedia Risk Aggregation
```

### 5. FILE / RAW Artifacts (5 Tasks)
```
[validation] Binary Integrity & Entropy Validation
     ↓
[artifact_classification] Magic Byte & File Type Identification
     ↓
[static_analysis] Static Header & String Analysis
     ↓
[threat_intel] File Hash Reputation & Known Signatures
     ↓
[risk_assessment] File Threat Risk Assessment
```

---

## Real-Time Synchronization & Polling Fallback

1. **Server-Sent Events (SSE)**:
   - Primary real-time transport: `GET /api/analysis/{run_id}/stream`.
   - On connection, backend immediately pushes an initial state snapshot (`event_type: 'SNAPSHOT'`).
   - Task transitions, findings discoveries, and pipeline completion are broadcast through `AnalysisEventHub` pub/sub async queues.
   - Includes periodic `: keep-alive\n\n` comments every 15 seconds to keep proxies from terminating idle connections.
2. **Graceful Polling Fallback**:
   - If SSE connection fails or client is behind an enterprise forward-proxy that buffers event streams, the client automatically switches to polling `GET /api/analysis/{run_id}` every 2 seconds.
   - Polling ceases immediately once a terminal state (`COMPLETED`, `PARTIAL`, `FAILED`, `CANCELLED`) is detected.

---

## Partial Analysis & Graceful Degradation

If an individual external provider (e.g. threat intelligence API or WHOIS server) is unreachable:
1. The specific task marks its status as `FAILED` with an informative error message (e.g., `Timeout contacting threat intelligence provider`).
2. Downstream tasks that can still evaluate local heuristics and ML continue executing.
3. The overall `AnalysisRun` concludes in status `PARTIAL` rather than crashing.
4. The UI displays an amber warning banner:
   *"Analysis partially completed. Some intelligence sources were unavailable. Existing findings remain available."*
5. The analyst is provided with both `[Open Investigation]` (to review partial results) and `[Retry Analysis]`.

---

## Cancellation & Safe Retry Semantics

- **Cancel Analysis**:
  - Endpoint: `POST /api/analysis/{run_id}/cancel`.
  - Analyst is prompted with a confirmation dialog.
  - Active execution loop halts; running and queued tasks transition to `CANCELLED`.
  - State is auditable with an `ANALYSIS_CANCELLED` event.
- **Retry Analysis**:
  - Endpoint: `POST /api/analysis/{run_id}/retry`.
  - Resets failed or cancelled tasks to `QUEUED`, resets run status to `RUNNING`, and relaunches `AnalysisOrchestrator.execute_run`.
  - Preserves investigation continuity and evidence integrity without creating duplicate investigations or evidence records.

---

## Security & Data Integrity Boundaries

- **Authoritative Hashes**: SHA-256 hashes displayed in the UI are persisted backend attributes from the initial ingestion pass. The frontend never recalculates a synthetic hash.
- **Static Analysis Only**: Binary artifacts and suspicious files are analyzed via static parsing, byte extraction, and reputation heuristics. Executables are never executed dynamically.
- **Sanitized Events**: Backend events emitted to the SSE stream and polling payloads contain operational messages only; no database connection strings, API tokens, or secrets are leaked.
- **Tenant Isolation**: Every analysis run query validates that the incident and evidence belongs to the authorized tenant context.
