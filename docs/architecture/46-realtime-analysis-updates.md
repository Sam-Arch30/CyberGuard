# SECTION 46 — REAL-TIME ANALYSIS UPDATES ARCHITECTURE

## 1. Executive Summary & Design Principles

Section 46 connects the existing CyberGuard backend systems (**Section 45 Persistent Background Jobs**, **Analysis Orchestrator**, **AnalysisRun state**, **persisted findings**, **report generation**, and **frontend workspaces**) into an authoritative real-time and near-real-time state communication pipeline.

The design adheres to six strict architectural tenets:
1. **Database is the Single Source of Truth**: Real-time events are notifications of state changes, never an independent or competing state. Reconnecting clients or clients with sequence gaps always reconcile against authoritative database snapshots.
2. **Truthful Progress Semantics**: No fabricated percentage numbers (`37% -> 62% -> 84%`) or synthetic `setInterval` increments exist. Progress is strictly represented as real orchestrator stage transitions, verified completed vs. total task counts (`4 / 9 tasks`), or marked explicitly as `Indeterminate`.
3. **Transport Failure Isolation**: Event transport, subscriber socket disconnects, or hub backpressure never cause background worker or analysis pipeline failure. Real-time streaming is auxiliary to forensic processing.
4. **Strict Authorization & Tenant Isolation**: Every stream subscription requires tenant validation (`workspace_id`). Guessed resource IDs cannot leak events across tenant boundaries.
5. **Safe Payloads & Sanitized Error Reporting**: Raw email bytes, attachment blobs, internal tracebacks, database connection strings, passwords, and sensitive credentials are never emitted onto real-time streams.
6. **Graceful Reconnection & Controlled Polling Fallback**: SSE streams automatically reconnect using `Last-Event-ID` database replay. If SSE fails persistently (e.g. strict corporate proxy), the client gracefully degrades to controlled adaptive near-real-time polling.

---

## 2. Real-Time Architecture Diagram

```text
               ┌────────────────────────────────────────────────────────┐
               │              Background Job Worker Pool                │
               │         (AnalysisRun / Report / Correlation)           │
               └──────────────────────────┬─────────────────────────────┘
                                          │
                                          ▼
               ┌────────────────────────────────────────────────────────┐
               │           Analysis Orchestrator / Job Manager          │
               │   - Lifecycle Transitions (QUEUED -> RUNNING -> ...)   │
               │   - Stage Milestones & Dynamic Task DAGs               │
               │   - Forensic Findings Persisted                        │
               └──────────────────────────┬─────────────────────────────┘
                                          │
                        Atomic DB Commit  │
                                          ▼
        ┌─────────────────────────────────────────────────────────────────────┐
        │                 Authoritative Persistence Layer                     │
        │    - analysis_events (id, run_id, sequence, event_type, timestamp)  │
        │    - background_job_events (id, job_id, sequence, event_type)       │
        │    - findings / analysis_runs / background_jobs / reports           │
        └─────────────────────────────────┬───────────────────────────────────┘
                                          │
                                          ▼
        ┌─────────────────────────────────────────────────────────────────────┐
        │             RealtimePublisher & Global Realtime Hub                 │
        │    - Topic Routing: run:{id}, job:{id}, investigation:{id}, ws:{id} │
        │    - Monotonically Increasing Sequences (1, 2, 3...)                │
        │    - Bounded Queues & Non-blocking Event Broadcast                  │
        │    - Backpressure (preserves terminal events, drops transient prog) │
        └───────────────────┬───────────────────────────┬─────────────────────┘
                            │                           │
          SSE Streams (Direct Push)                     │ DB Replay (Last-Event-ID)
                            │                           │
                            ▼                           ▼
        ┌─────────────────────────────────────────────────────────────────────┐
        │                    Authorized Stream Endpoints                      │
        │    - GET /api/analysis/{run_id}/stream                              │
        │    - GET /api/jobs/{job_id}/stream                                  │
        │    - GET /api/jobs/stream (Workspace-wide)                          │
        │    - GET /api/investigations/{identifier}/stream                    │
        │    - GET /api/dashboard/stream (SOC Overview)                       │
        └───────────────────┬─────────────────────────────────────────────────┘
                            │
               SSE Connection / Fallback Polling
                            │
                            ▼
        ┌─────────────────────────────────────────────────────────────────────┐
        │            Frontend Real-Time Service & React Layer                 │
        │    - RealtimeService (SSE + Last-Event-ID + Gap Detection)          │
        │    - useRealtimeSubscription Hook                                   │
        │    - Deduplication (seenEventIds set)                               │
        │    - Authoritative Snapshot Invalidation                            │
        └───────┬───────────────┬────────────────┬───────────────┬────────────┘
                │               │                │               │
                ▼               ▼                ▼               ▼
          Section 37      Section 38       Section 39      Section 42 & 44
         Live Analysis   Analysis Results  Investigation    Reports & SOC
          DAG Viewer      Workstation       Workspace         Overview
```

---

## 3. Transport Selection Rationale

### Choice: Server-Sent Events (SSE) with Adaptive Polling Fallback

1. **Unidirectional Server-to-Client Pattern**: Forensic analysis updates (task transitions, new findings, progress increments, report compilation completion) are purely server-to-client notifications.
2. **Native HTTP/2 & HTTP/1.1 Compatibility**: Operates over standard HTTP without requiring special protocol upgrades or WebSocket reverse-proxy tunnels.
3. **Built-in Reconnection & Last-Event-ID**: SSE natively supports reconnecting with the `Last-Event-ID` header, enabling instant database replay of missed events.
4. **Low Overhead**: Avoids the handshake, heartbeat protocol framing, and connection state overhead of WebSockets.
5. **Controlled Polling Fallback**: If an enterprise proxy terminates persistent streaming connections, `RealtimeService` automatically drops into controlled near-real-time polling (`FALLBACK_POLLING`) without corrupting state or disrupting analysis.

---

## 4. Structured Event Schema Contract (v1)

All emitted events adhere to the versioned `RealtimeEvent` contract:

```json
{
  "schema_version": 1,
  "event_id": "c1f7a83d-e44b-4b21-8318-77b3d37a1f59",
  "sequence": 104,
  "event_type": "FINDING_PERSISTED",
  "resource_type": "ANALYSIS_RUN",
  "resource_id": "run-7801a2bc",
  "job_id": "job-9941ef21",
  "analysis_run_id": "run-7801a2bc",
  "investigation_id": "INV-2026-0041",
  "workspace_id": "default",
  "stage": "HEADER_ANALYSIS",
  "status": "RUNNING",
  "progress_percent": null,
  "message": "SPF and DMARC alignment failure detected",
  "payload": {
    "finding_id": "fnd-1002",
    "finding_type": "SPF_FAIL",
    "severity": "HIGH",
    "risk_contribution": 35.0,
    "completed_tasks": 4,
    "total_tasks": 9
  },
  "created_at": "2026-10-10T09:12:00.000Z"
}
```

### Event Taxonomy
- **Job Lifecycle**: `JOB_CREATED`, `JOB_QUEUED`, `JOB_STARTED`, `JOB_PROGRESS`, `JOB_RETRY_SCHEDULED`, `JOB_CANCEL_REQUESTED`, `JOB_CANCELLED`, `JOB_COMPLETED`, `JOB_PARTIALLY_COMPLETED`, `JOB_FAILED`, `JOB_TIMED_OUT`
- **Analysis Lifecycle**: `ANALYSIS_STARTED`, `ANALYSIS_STAGE_STARTED`, `ANALYSIS_STAGE_COMPLETED`, `ANALYSIS_PROGRESS`, `ANALYSIS_PARTIAL`, `ANALYSIS_COMPLETED`, `ANALYSIS_FAILED`, `ANALYSIS_CANCELLED`
- **Findings & Evidence**: `FINDING_PERSISTED`, `INDICATOR_DISCOVERED`, `EVIDENCE_ADDED`
- **Analyzer Health**: `ANALYZER_WARNING`, `ANALYZER_DEGRADED`, `ANALYZER_FAILED`
- **Reports**: `REPORT_GENERATION_STARTED`, `REPORT_READY`, `REPORT_FAILED`

---

## 5. Sequence Ordering, Deduplication & Replay

1. **Monotonic Sequences**: Every event assigned to a resource increments a sequential integer counter (`1, 2, 3...`), tracked in memory and persisted into `analysis_events.sequence` and `background_job_events.sequence`.
2. **Client Idempotency**: `RealtimeService` tracks `seenEventIds` in a bounded LRU Set (500 items). Duplicate delivery of the same `event_id` is discarded immediately before touching UI state.
3. **Gap Detection**: If the client receives event with `sequence > lastSeenSequence + 1` (e.g. sequence 101 followed by 104 due to network jitter), the client flags a sequence gap and triggers an authoritative backend snapshot fetch (`onAuthoritativeRefetch`).
4. **Replay Cursor**: Reconnecting clients supply `Last-Event-ID` or `?last_event_id=101`. The server queries `WHERE sequence > 101 ORDER BY sequence ASC` and replays missed events before streaming live events.

---

## 6. Authorization & Tenant Isolation

- **Resource Authorization**: Every SSE endpoint validates identity and tenant boundaries before opening the stream.
  - `GET /api/analysis/{run_id}/stream`: Resolves `AnalysisRun` and checks artifact `workspace_id`.
  - `GET /api/jobs/{job_id}/stream`: Verifies `BackgroundJob.workspace_id == request.workspace_id`.
  - `GET /api/investigations/{id}/stream`: Verifies `Incident.workspace_id == request.workspace_id`.
- Cross-tenant requests receive HTTP 403 or HTTP 404 and leak zero operational metadata.

---

## 7. Frontend Integration Matrix

| Workspace | Realtime Transport / Subscription | State Reconciliation Mechanism | Visual Indicators |
| :--- | :--- | :--- | :--- |
| **Section 37: Live Analysis** | `/api/analysis/{run_id}/stream` | Direct snapshot listener + task status refresh | `● Live` / `↻ Reconnecting` / `⚡ Polling`, `aria-live="polite"` stage announcements |
| **Section 38: Analysis Results** | `/api/analysis/{run_id}/stream` | Silent background refresh on `FINDING_PERSISTED` (preserves existing results without blanking) | Live active execution banner, live status badge |
| **Section 39: Investigation Workspace** | `/api/investigations/{id}/stream` | Refreshes investigation counts and summary bar | Live connectivity pill in `InvestigationSummaryBar` |
| **Section 42: Report Workspace** | `/api/investigations/{id}/stream` | Automatically updates on `REPORT_READY` / `REPORT_FAILED` | Generation progress indicator and notification |
| **Section 44: SOC Overview** | `/api/dashboard/stream` | 1500ms debounced telemetry refetch | `● Live Stream` freshness badge |

---

## 8. Multi-Worker & Scaling Considerations

- Events are committed to the database (`analysis_events`, `background_job_events`) prior to distribution.
- In multi-instance deployments, `RealtimePublisher` abstracts broadcasting. While single-container deployments use async in-memory pub/sub queues, the database log provides an immutable replay store that works across any number of worker processes.
- Redis pub/sub or database listen/notify can plug directly into `RealtimeEventHub` without altering frontend contracts or endpoint signatures.
