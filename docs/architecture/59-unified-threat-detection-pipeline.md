# Architecture Document: Section 59 — Unified Threat Detection Pipeline

## 1. Executive Summary & Objective

The **Unified Threat Detection Pipeline** is the production execution and orchestration layer for the CYBERGUARD platform. It connects heterogeneous security telemetry and analyzer outputs with compiled AST detection rules, evaluates rule logic deterministically, produces first-class Detection Matches, and feeds downstream security operations including Findings, Risk Assessment, Alert policies, Incident clustering, and Playbook response.

### Core Architectural Principle
The pipeline is an **execution and orchestration coordinator**, not a replacement engine:
- **Reuses Section 56 Evaluator**: Executes rules using AST evaluation via `DetectionRuleLifecycleService._evaluate_ast_against_record`.
- **Enforces Section 57 Operational Control**: Honors deployment states (`PRODUCTION`, `STAGING`, `DISABLED`), evaluates active suppressions, and feeds execution metrics back to rule health.
- **Enforces Section 58 Quality Gates**: Checks validation states (`PASS`, `BLOCKED`, `FAIL`, `STALE`) before allowing rules into production execution.
- **Reuses Section 45 Background Jobs**: Enqueues batch ingestion and replay jobs without creating redundant queue services.
- **Reuses Section 46 Realtime Infrastructure**: Emits telemetry and pipeline events via `RealtimePublisher`.
- **Reuses Section 47 Notifications**: Dispatches alert signals via `NotificationService` without duplicate dispatchers.

```
                    CYBERGUARD TELEMETRY INPUTS
                                │
        ┌───────────────────────┼───────────────────────┐
        ▼                       ▼                       ▼
      Email                  Endpoint                Network
        │                       │                       │
        ▼                       ▼                       ▼
      APIs                  Artifacts             Auth / Identity
        │                       │                       │
        └───────────────────────┼───────────────────────┘
                                ▼
                     Normalization Layer
                   (Source Adapters & Schemas)
                                │
                                ▼
                     Detection Pipeline
                                │
                                ▼
                    Applicable Rule Selection
              (Tenant Scope + Quality Gate + Sources)
                                │
                                ▼
                      Existing AST Evaluator
                  (Section 56 AST Engine + SLA)
                                │
                                ▼
                    Deterministic Match Outcome
                         MATCH / NO_MATCH
                                │
                    ┌───────────┴───────────┐
                    ▼                       ▼
                NO_MATCH                  MATCH
                    │                       │
                Complete              Detection Match
                                            │
                                            ▼
                                         Finding
                                            │
                                            ▼
                                    Unified Risk Engine
                                            │
                                            ▼
                                       Alert Policy
                                            │
                            ┌───────────────┼───────────────┐
                            ▼               ▼               ▼
                        Incident      Investigation      Campaign
                            │               │               │
                            └───────────────┼───────────────┘
                                            ▼
                                         Response
```

---

## 2. Pipeline Stages

The pipeline executes through 15 distinct lifecycle stages:

1. **RECEIVE**: Ingestion of raw telemetry from external APIs, agents, or internal analyzer outputs with payload size verification (max 1 MB).
2. **VALIDATE INPUT**: Enforces structure, prevents malformed payloads, verifies JSON schemas.
3. **NORMALIZE**: Maps source-specific keys into the canonical `NormalizedDetectionEvent` contract using domain source adapters.
4. **AUTHORIZE & TENANT SCOPE**: Binds event to `workspace_id` verified server-side; ensures cross-tenant isolation.
5. **RESOLVE APPLICABLE RULES**: Selects active eligible rules based on tenant, deployment state (`PRODUCTION`), Section 58 quality gate status (`PASS`), and source taxonomy.
6. **SUPPRESSION EVALUATION**: Checks active non-expired rule suppressions (Section 57); if suppressed, marks outcome as `SKIPPED` without alerting.
7. **EXECUTE (AST EVALUATION)**: Reuses the Section 56 AST evaluator under an execution budget and per-rule timeout guard (5.0s).
8. **PERSIST MATCH**: Stores first-class `DetectionMatchModel` with complete matched fields, evidence JSON, and provenance.
9. **DEDUPLICATE & IDEMPOTENCY**: Verifies idempotency identity `(workspace_id, rule_id, event_id)` to prevent alert flooding.
10. **FINDING GENERATION**: Produces `FindingModel` and associates extracted observables in `FindingEvidenceModel`.
11. **RISK EVALUATION**: Propagates rule severity and confidence into risk scoring metadata.
12. **ALERT POLICY EVALUATION**: For production matches on `HIGH` or `CRITICAL` rules, creates `NotificationModel` (`SECURITY_ALERT`).
13. **REALTIME NOTIFICATION**: Publishes realtime WebSocket events via Section 46 `RealtimePublisher`.
14. **OPERATIONAL TELEMETRY FEEDBACK**: Updates execution metrics in `CandidateRuleExecutionModel` and updates Section 57 health indicators.
15. **AUDIT LOGGING**: Persists audit entries in `AuditLogModel` for significant events (replays, dead-letters, batch runs).

---

## 3. Normalized Detection Event Contract

The pipeline defines a minimal, robust contract (`NormalizedDetectionEvent`):

```python
class NormalizedDetectionEvent(BaseModel):
    event_id: str                      # Unique deterministic identifier
    workspace_id: str                  # Server-authoritative tenant boundary
    event_type: str                    # e.g., ENDPOINT_EVENT, EMAIL_EVENT
    source_type: str                   # e.g., ENDPOINT, EMAIL, NETWORK, AUTH
    source_id: Optional[str]           # Artifact or device ID
    occurred_at: datetime              # Telemetry occurrence time
    received_at: datetime              # Pipeline ingress timestamp
    payload: Dict[str, Any]            # Normalized key-values (flat + dotted aliases)
    entities: List[Dict[str, Any]]     # Extracted entities (USER, DEVICE, IP, DOMAIN)
    indicators: List[Dict[str, Any]]   # Extracted observables (HASH, IP, DOMAIN, URL)
    provenance: Dict[str, Any]         # Tracing provenance dictionary
    schema_version: str                # e.g. "1.0"
```

---

## 4. Source Adapters

The pipeline standardizes payloads using dedicated adapters that generate **both flat keys and dotted field aliases** to match any AST condition without impedance mismatch:

| Adapter | Source | Key Flat Fields | Key Dotted Aliases |
| :--- | :--- | :--- | :--- |
| `EmailSourceAdapter` | EMAIL, ARTIFACT | `sender_domain`, `sender_address`, `subject`, `auth_result` | `email.sender_domain`, `email.subject`, `email.auth_result` |
| `EndpointSourceAdapter` | ENDPOINT, PROCESS | `process_name`, `command_line`, `device_id`, `sha256` | `process.name`, `process.command_line`, `endpoint.id`, `file.sha256` |
| `NetworkSourceAdapter` | NETWORK, DNS, FLOW | `ip_address`, `source_ip`, `dest_port`, `dns_query` | `network.destination_ip`, `network.source_ip`, `dns.query` |
| `AuthSourceAdapter` | IDENTITY, AUTH | `auth_result`, `user_id`, `username`, `ip_address` | `auth.status`, `auth.username`, `auth.client_ip` |
| `ApiSourceAdapter` | API, GATEWAY | `endpoint`, `method`, `response_code`, `api_key_id` | `api.endpoint`, `api.method`, `api.response_code` |
| `GenericSourceAdapter` | OTHER | Direct payload passthrough | Preserves original keys |

---

## 5. Rule Selection & Quality Gate Integration

Rules are selected based on strict criteria:
1. **Tenant Isolation**: `CandidateRuleModel.workspace_id == request.workspace_id`.
2. **Deployment State**:
   - `PRODUCTION`: `deployment_state == 'PRODUCTION'`, `status == 'ACTIVE'`.
   - `SHADOW`: `deployment_state in ['STAGING', 'PRODUCTION']`.
   - `REPLAY`: Evaluates target rule IDs or active production rules.
3. **Section 58 Quality Gates**:
   - In production mode, rules with `validation_status in ('FAIL', 'BLOCKED')` are excluded.
4. **Data Source Applicability**:
   - Matches rule's declared `data_sources` against `event.source_type` and `event.event_type`.
   - Prevents endpoint process rules from executing against email telemetry.

---

## 6. Execution Modes

The pipeline supports three distinct execution modes:
- **`PRODUCTION`**: Evaluates active production rules, produces `DetectionMatchModel`, creates `FindingModel`, evaluates alert policies, dispatches notifications, and triggers realtime alerts.
- **`SHADOW`**: Evaluates staged or candidate rules in parallel with production traffic. Records `DetectionMatchModel` with `mode="SHADOW"`, but **never** creates production findings or alerts.
- **`REPLAY`**: Bounded historical reprocessing over past `SecurityEventModel` records. Records matches with `mode="REPLAY"` without triggering alert flooding.

---

## 7. Reliability, Idempotency & Error Handling

- **Idempotency**: Downstream handoff verifies existing `(workspace_id, rule_id, event_id)` matches. Ingestion of duplicate events returns existing match IDs rather than duplicate findings or alerts.
- **Dead-Letter Storage (`DetectionDeadLetterModel`)**: Unrecoverable payload corruptions or schema rejections are recorded in `detection_dead_letters` with error codes, stage names, attempt counts, and error messages.
- **Execution Budget & Timeout**: Evaluator execution is guarded by a 5.0-second timeout SLA per rule, preventing regex catastrophic backtracking or infinite loops.
- **Rule Failure Isolation**: An evaluation failure on Rule A does not block Rule B or Rule C from evaluating the same event.

---

## 8. Database Architecture

### `detection_matches`
- `id` (VARCHAR(36), PK): Detection ID (`DET-...`).
- `workspace_id` (VARCHAR(64), indexed): Tenant boundary.
- `rule_id` (VARCHAR(36), FK `candidate_rules.id`, indexed).
- `rule_version` (VARCHAR(32)): Evaluated rule version.
- `event_id` (VARCHAR(128), indexed): Source event identifier.
- `execution_id` (VARCHAR(36), nullable): Execution telemetry foreign key.
- `finding_id` (VARCHAR(36), nullable, indexed): Created finding.
- `alert_id` (VARCHAR(36), nullable, indexed): Created alert notification.
- `incident_id` (VARCHAR(36), nullable, indexed): Correlated incident.
- `mode` (VARCHAR(20), indexed): `PRODUCTION`, `SHADOW`, or `REPLAY`.
- `status` (VARCHAR(30), indexed): `MATCH`, `SUPPRESSED`.
- `severity` (VARCHAR(20)): `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.
- `confidence` (FLOAT): 0.0 – 1.0.
- `matched_at` (DATETIME, indexed): Timestamp of match.
- `matched_fields_json` (TEXT): Array of matched field names.
- `evidence_json` (TEXT): Matched condition expressions and payload sample.
- `provenance_json` (TEXT): Telemetry provenance traces.
- `explanation_text` (TEXT): Human-readable explainability description.

### `detection_dead_letters`
- `id` (VARCHAR(36), PK): Dead-letter ID.
- `workspace_id` (VARCHAR(64), indexed).
- `event_id` (VARCHAR(128), indexed).
- `source_type` (VARCHAR(50)).
- `failure_stage` (VARCHAR(50)): `RECEIVE`, `VALIDATE`, `NORMALIZE`, `EVALUATE`, `PERSIST`.
- `error_code` (VARCHAR(50)): Structured error code.
- `error_message` (TEXT): Error details.
- `attempt_count` (INTEGER): Retry attempt count.
- `payload_json` (TEXT): Original raw payload.
- `provenance_json` (TEXT): Ingestion provenance metadata.

---

## 9. API Surface

| Method | Endpoint | Description | RBAC |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/detection/events` | Ingest single event & execute detection pipeline | Analyst, Admin |
| `POST` | `/api/v1/detection/events/batch` | Ingest batch (synchronous or Section 45 background job) | Analyst, Admin |
| `GET` | `/api/v1/detection/events/{event_id}` | Retrieve event details and associated matches | Viewer, Analyst, Admin |
| `GET` | `/api/v1/detection/events/{event_id}/trace` | Full progressive disclosure execution trace | Viewer, Analyst, Admin |
| `GET` | `/api/v1/detection/pipeline/status` | Operational pipeline health, backlog & workers | Viewer, Analyst, Admin |
| `GET` | `/api/v1/detection/pipeline/metrics` | Detailed pipeline performance metrics | Viewer, Analyst, Admin |
| `POST` | `/api/v1/detection/pipeline/replay` | Authorized historical replay over past events | Admin only |
| `GET` | `/api/v1/detection/matches` | Paginated first-class detection matches | Viewer, Analyst, Admin |
| `GET` | `/api/v1/detection/matches/{match_id}` | Match detail with rule, evidence, and provenance | Viewer, Analyst, Admin |
| `GET` | `/api/v1/detection/dead-letters` | Inspect quarantined/failed dead-letter events | Admin only |
| `POST` | `/api/v1/detection/dead-letters/{id}/retry` | Retry failed dead-letter through pipeline | Admin only |

---

## 10. Operational Frontend (SOC Interface)

Integrated into the Detection Rules workspace as **Unified Detection Pipeline**:
1. **Pipeline Telemetry Bar**: Real events processed, active rules, matches, findings, alerts, backlog, and worker count.
2. **Interactive Ingestion Sandbox**: Preset attack telemetry (PowerShell C2, Password Spraying, Executive Phishing, Tor Beaconing) to test real detection flow.
3. **Detection Matches Table**: Filterable by severity, mode, and rule with detailed Evidence Modal showing AST conditions and provenance.
4. **End-to-End Execution Trace**: Visual lifecycle trace (`RECEIVE` → `NORMALIZE` → `EVALUATE` → `FINDINGS` → `ALERTS`) with condition breakdowns.
5. **Historical Replay Console**: Controlled administrative replay with time-range boundaries and rule filters.
6. **Dead-Letter Quarantine**: Inspection and retry capabilities for unrecoverable payloads.
