# Section 53 — IOC Watchlists & Continuous Threat Monitoring Subsystem

## 1. Overview & Operational Architecture

The **IOC Watchlists & Continuous Threat Monitoring subsystem** introduces an analyst-controlled, persistent intelligence monitoring mechanism to CyberGuard. It empowers security operations teams to establish targeted watchlists for critical assets, suspect observables, and high-value incident indicators, continuously querying the Section 52 Threat Intelligence infrastructure to detect material security changes over time.

The operational flow within CyberGuard is structured as:

```text
Input (Sensors, Ingestion Gateway, Endpoints)
  ↓
Detection (Multi-engine analytical detectors)
  ↓
Alert (Security Signal: NotificationModel / SECURITY_ALERT)
  ↓
Correlation (Alert Correlation & Incident Clustering: Section 49)
  ↓
Incident (Operational Case Lifecycle: Section 50 & Section 51)
  ↓
Threat Intelligence Enrichment (Section 52: Multi-provider evidence layer)
  ↓
Watchlist Monitoring (Section 53: Continuous temporal change detection)
  ↓
Intelligence Change (Material state transition detected)
  ↓
Alert / Notification (Section 48 Alert Management & Section 47 In-App Notifications)
  ↓
Investigation (Forensic Workspace, Attack Path, Timeline)
  ↓
Response (Response Recommendation & Playbooks: Section 37 & 38)
```

### Core Principles: Separation of Concerns

1. **Intelligence (Section 52)**: Answers *"What do external and internal sources currently state about this indicator?"*
2. **Monitoring (Section 53)**: Answers *"Has this intelligence materially changed since the previous observation?"*
3. **Alerting (Section 48)**: Answers *"Is this change significant enough to generate a formal security alert requiring triage?"*
4. **Notification (Section 47)**: Answers *"Who should be alerted in realtime across open workspaces?"*
5. **Execution (Section 45)**: Handles asynchronous, distributed, idempotent background jobs.
6. **Realtime Delivery (Section 46)**: Streams incremental state change hints over WebSockets.
7. **Risk Scoring (Section 35)**: Preserves the **Unified Risk Engine** as the authoritative calculator of threat risk.

---

## 2. Architecture & Component Interaction

```mermaid
graph TD
    subgraph Watchlist Management
        WL[Watchlists: Critical Infra, Incident Observables, Phishing Domains] --> WI[Watched Indicators]
        INC[Incident / Investigation Workspace] -->|Quick Watch 1-Click Action| WI
    end

    subgraph Continuous Execution Engine: Section 45
        SCHED[BackgroundJobWorker: WATCHLIST_MONITORING_CYCLE] --> DUE{Fetch Due Active Indicators: next_check_at <= now}
        DUE --> BATCH[Batch & Group by Type / Provider]
        BATCH --> RUN_REC[WatchlistMonitoringRunModel: Tracking & Telemetry]
    end

    subgraph Threat Intelligence Layer: Section 52
        BATCH --> S52[ThreatIntelligenceService: enrich_indicator]
        S52 --> MEM[Internal Threat Memory First]
        S52 --> PROV[Provider Abstraction: VirusTotal, AlienVault, ThreatMiner]
    end

    subgraph Snapshot & Change Detection
        S52 --> FP[Deterministic SHA-256 Fingerprint Generation]
        FP --> PREV{Compare with Previous Snapshot}
        PREV -->|Fingerprint Match: Stable Intelligence| NO_CHANGE[Update last_checked_at & next_check_at]
        PREV -->|Fingerprint Mismatch| DETECT[Material Change Detector]
    end

    subgraph Triaging, Alerting & Realtime
        DETECT --> SNAP_NEW[IntelligenceSnapshotModel Created]
        DETECT --> CHG_REC[IntelligenceChangeModel Created]
        CHG_REC --> CD_CHECK{Cooldown & Alert Threshold Check}
        CD_CHECK -->|Threshold Exceeded & Cooldown Clear| S48_ALERT[Section 48 Security Alert: NotificationModel]
        CD_CHECK -->|Within Cooldown Window| SUPPRESS[Alert Suppressed to Avoid Fatigue]
        CHG_REC --> S47_NOTIF[Section 47 System In-App Notification]
        CHG_REC --> S46_RT[Section 46 Realtime Broadcast: INTELLIGENCE_CHANGE_DETECTED]
    end
```

---

## 3. Data Model & Persistence Architecture

The persistence layer is implemented in SQLAlchemy (`backend/db/models.py`) with strict foreign keys, cascade semantics, and tenant isolation:

### 3.1. `WatchlistModel` (`watchlists`)
Represents an analyst-managed collection of monitored observables.
- `id` (VARCHAR(36), PK): UUID.
- `workspace_id` (VARCHAR(64), Indexed): Tenant scoping.
- `name` (VARCHAR(255), Not Null): Human-readable title.
- `description` (TEXT): Analyst notes / monitoring scope.
- `status` (VARCHAR(32), Indexed): `ACTIVE`, `PAUSED`, `ARCHIVED`.
- `priority` (VARCHAR(32), Default `MEDIUM`): `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.
- `check_interval_minutes` (INTEGER, Default 60): Monitoring cadence (15 to 10080 mins).
- `change_sensitivity` (VARCHAR(32), Default `MEDIUM`): `LOW`, `MEDIUM`, `HIGH`.
- `alert_threshold` (VARCHAR(32), Default `HIGH`): Minimum change severity to trigger security alert (`NONE`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- `cooldown_minutes` (INTEGER, Default 60): Duplicate alert suppression period.
- `notify_on_change` (BOOLEAN, Default True): Triggers in-app analyst notifications.
- `tags_json` (TEXT): JSON array of custom labels.
- `last_monitored_at` / `next_monitoring_cycle_at` (DATETIME): Cycle timestamps.
- `created_by` / `updated_by` (VARCHAR(128)): Audit attribution.
- `created_at` / `updated_at` (DATETIME).

### 3.2. `WatchedIndicatorModel` (`watched_indicators`)
Represents an individual observable monitored under a watchlist.
- `id` (VARCHAR(36), PK): UUID.
- `workspace_id` (VARCHAR(64), Indexed): Tenant boundary.
- `watchlist_id` (VARCHAR(36), FK `watchlists.id`, ON DELETE CASCADE): Parent watchlist.
- `indicator_id` (VARCHAR(36), Nullable, FK `indicators.id`): Canonical link to core indicator entity.
- `indicator_type` (VARCHAR(32), Not Null): `IP`, `DOMAIN`, `URL`, `SHA256`, `MD5`, `SHA1`, `EMAIL`, `CERTIFICATE`, `ASN`.
- `raw_value` (VARCHAR(1024), Not Null): Original analyst input.
- `normalized_value` (VARCHAR(1024), Indexed): RFC/Punycode canonical format.
- `monitoring_status` (VARCHAR(32), Default `ACTIVE`): `ACTIVE`, `PAUSED`, `HEALTHY`, `STALE`, `DEGRADED`, `ERROR`.
- `priority` (VARCHAR(32), Default `MEDIUM`): Observable monitoring priority.
- `last_verdict` (VARCHAR(32)): Latest consensus verdict (`CLEAN`, `SUSPICIOUS`, `MALICIOUS`, `UNKNOWN`).
- `last_confidence` (FLOAT): Latest confidence rating (0.0 to 1.0).
- `last_checked_at` / `next_check_at` (DATETIME, Indexed): Scheduling coordinates.
- `last_successful_check_at` / `last_failed_check_at` (DATETIME): Execution health coordinates.
- `last_change_detected_at` (DATETIME): Timestamp of most recent material intelligence delta.
- `last_snapshot_id` (VARCHAR(36), FK `intelligence_snapshots.id`): Pointer to current snapshot.
- `failure_count` / `consecutive_failure_count` (INTEGER): Provider fault tracking.
- `last_error_message` (TEXT): Failure diagnostics.
- `source_incident_id` / `source_investigation_id` (VARCHAR(64)): Provenance back-links.
- `created_by` / `created_at` / `updated_at`.

### 3.3. `IntelligenceSnapshotModel` (`intelligence_snapshots`)
Captures an immutable, point-in-time observation of normalized threat intelligence.
- `id` (VARCHAR(36), PK): UUID.
- `workspace_id` (VARCHAR(64), Indexed): Tenant scoping.
- `watched_indicator_id` (VARCHAR(36), FK `watched_indicators.id`, ON DELETE CASCADE).
- `indicator_type` / `normalized_value`.
- `provider_consensus_verdict` (`CLEAN`, `SUSPICIOUS`, `MALICIOUS`, `UNKNOWN`).
- `consensus_confidence` (FLOAT) / `severity` (VARCHAR(32)).
- `sources_count` (INTEGER) / `has_conflicts` (BOOLEAN).
- `threat_types_json` (TEXT): Normalized threat classifications.
- `normalized_data_json` (TEXT): Sanitized attributes (ASN, registrar, hosting, campaigns).
- `fingerprint` (VARCHAR(64), Indexed): Deterministic SHA-256 state hash.
- `retrieved_at` / `created_at` (DATETIME).

### 3.4. `IntelligenceChangeModel` (`intelligence_changes`)
Captures a detected material delta between two successive snapshots.
- `id` (VARCHAR(36), PK): UUID.
- `workspace_id` (VARCHAR(64), Indexed): Tenant scoping.
- `watchlist_id` (VARCHAR(36), FK `watchlists.id`, ON DELETE CASCADE).
- `watched_indicator_id` (VARCHAR(36), FK `watched_indicators.id`, ON DELETE CASCADE).
- `change_type` (VARCHAR(64)): `NEWLY_MALICIOUS`, `NEWLY_SUSPICIOUS`, `BECAME_CLEAN`, `VERDICT_CHANGED`, `SEVERITY_CHANGED`, `CONFIDENCE_CHANGED`, `PROVIDER_CONFLICT_CHANGED`, `CAMPAIGN_ASSOCIATION_CHANGED`, `ASN_CHANGED`, `HOSTING_CHANGED`.
- `change_severity` (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- `previous_snapshot_id` / `current_snapshot_id` (FK pointers).
- `previous_verdict` / `current_verdict`.
- `previous_confidence` / `current_confidence`.
- `previous_severity` / `current_severity`.
- `change_summary` (TEXT): Human-readable explainable explanation.
- `change_details_json` (TEXT): Detailed delta payload.
- `alert_id` (VARCHAR(64), Nullable): Link to created Section 48 `NotificationModel`.
- `notification_id` (VARCHAR(64), Nullable): Link to created Section 47 notification.
- `detected_at` (DATETIME, Indexed).

### 3.5. `WatchlistMonitoringRunModel` (`watchlist_monitoring_runs`)
Maintains execution history, audit logs, and performance metrics for background monitoring jobs.
- `id` (VARCHAR(36), PK): UUID.
- `workspace_id` (VARCHAR(64), Indexed).
- `watchlist_id` (VARCHAR(36), FK `watchlists.id`, ON DELETE CASCADE).
- `job_id` (VARCHAR(36), Nullable, FK `background_jobs.id`): Section 45 execution linkage.
- `trigger_type` (`SCHEDULED`, `MANUAL`).
- `status` (`QUEUED`, `RUNNING`, `SUCCEEDED`, `PARTIALLY_SUCCEEDED`, `FAILED`, `CANCELLED`).
- `items_due` / `items_checked` / `items_changed` / `items_failed` (INTEGER).
- `alerts_created` / `notifications_created` (INTEGER).
- `started_at` / `completed_at` (DATETIME).
- `duration_ms` (INTEGER).
- `error_message` (TEXT).

---

## 4. Deterministic Snapshot Fingerprinting

To prevent false alarms and alert fatigue caused by transient provider timestamps or unordered JSON fields, `WatchlistMonitoringService.compute_snapshot_fingerprint` computes a deterministic SHA-256 hash using exclusively material security properties:

```python
canonical_dict = {
    "verdict": verdict.strip().upper(),
    "severity": severity.strip().upper(),
    "confidence_bucket": round(confidence, 2),
    "threat_types": sorted(list(set(threat_types))),
    "has_conflicts": bool(has_conflicts),
    "material_attributes": {
        "asn": material_attributes.get("asn"),
        "hosting": material_attributes.get("hosting"),
        "registrar": material_attributes.get("registrar"),
        "campaigns": sorted(material_attributes.get("campaigns") or []),
        "malware_families": sorted(material_attributes.get("malware_families") or []),
    }
}
raw_str = json.dumps(canonical_dict, sort_keys=True, separators=(",", ":"))
fingerprint = hashlib.sha256(raw_str.encode("utf-8")).hexdigest()
```

Transient properties such as `retrieved_at`, network latencies, provider query durations, and pagination offsets are excluded.

---

## 5. Material Change Detection & Classification

When a fingerprint mismatch is detected, the change engine classifies the delta into an explainable category:

| Transition Type | Trigger Condition | Change Severity | Alert Default |
|---|---|---|---|
| `NEWLY_MALICIOUS` | Previous `!= MALICIOUS`, Current `== MALICIOUS` | **CRITICAL** | Yes |
| `NEWLY_SUSPICIOUS` | Previous `CLEAN`/`UNKNOWN`, Current `== SUSPICIOUS` | **HIGH** | Yes |
| `BECAME_CLEAN` | Previous `MALICIOUS`/`SUSPICIOUS`, Current `== CLEAN` | **MEDIUM** / **LOW** | No |
| `PROVIDER_CONFLICT_CHANGED` | Contradictory provider verdicts emerge | **HIGH** | Yes |
| `CAMPAIGN_ASSOCIATION_CHANGED` | New campaign or malware family linked | **HIGH** | Yes |
| `ASN_CHANGED` | IP autonomous system network shifts | **MEDIUM** | Dependent on threshold |
| `HOSTING_CHANGED` | Domain registrar or host shifts | **LOW** | No |
| `SEVERITY_CHANGED` | Severity rating escalates | **MEDIUM** | Dependent on threshold |
| `CONFIDENCE_CHANGED` | Confidence shifts by $\ge 0.15$ (High sens) / $0.25$ (Med sens) | **LOW** / **MEDIUM** | No |

---

## 6. Alert Fatigue Protection: Deduplication & Cooldowns

To avoid overwhelming SOC analysts when an observable remains malicious across successive checks:

1. **Deterministic Alert Dedup Key**:
   ```text
   dedup_key = f"watchlist_alert:{watchlist_id}:{item_id}:{change_type}:{current_verdict}"
   ```
2. **Time-Based Cooldown Window**:
   Before dispatching a Section 48 security alert, `_is_alert_in_cooldown` queries `intelligence_changes` within the configured `cooldown_minutes` (default 60 minutes). If an alert for the same indicator and change type was dispatched recently, duplicate creation is suppressed.
3. **Recovery & Re-escalation**:
   If an indicator recovers to `CLEAN` and subsequently reverts to `MALICIOUS`, the state transition resets the alert cycle, ensuring critical re-emergence is never dropped.

---

## 7. Background Job Integration (Section 45)

All periodic monitoring and batch operations execute via Section 45 Background Jobs:

- **`JobTypeEnum.WATCHLIST_MONITORING_CYCLE`**: Dispatched on a recurring cadence or triggered per-workspace. Queries all due active items (`next_check_at <= now`), chunks execution, and records a `WatchlistMonitoringRunModel`.
- **`JobTypeEnum.WATCHLIST_REFRESH`**: Triggered when an analyst clicks "Refresh All" on a watchlist.
- **`JobTypeEnum.WATCHED_INDICATOR_CHECK`**: Asynchronous check for a single watched item.

All handlers are registered in `backend/services/background_job_worker.py` with standard exponential backoff retries and timeout guards (600s for cycles, 300s for refreshes).

---

## 8. Realtime Integration (Section 46)

Section 46 WebSockets deliver incremental hints across active browser sessions:

- `WATCHLIST_CREATED` / `WATCHLIST_UPDATED` / `WATCHLIST_PAUSED` / `WATCHLIST_RESUMED`
- `WATCH_ITEM_ADDED` / `WATCH_ITEM_REMOVED`
- `WATCH_CHECK_STARTED` / `WATCH_CHECK_COMPLETED`
- `INTELLIGENCE_CHANGE_DETECTED` (includes severity, summary, and indicator value)
- `WATCHLIST_HEALTH_CHANGED`

The UI treats WebSockets as hints: upon receiving an event, the frontend refetches authoritative data from the database, preventing race conditions or stale client caches.

---

## 9. Security, Privacy & URL Safety

1. **Server-Side Scope Resolution**:
   Tenant scoping is enforced on every query via `X-Workspace-ID` (`workspace_id`). Client payloads are never trusted for tenant identity.
2. **Indicator Validation & SSRF Guardrails**:
   Every added indicator undergoes strict validation via `IndicatorNormalizer`. URLs and IP addresses undergo Section 52 privacy policy checks: internal RFC1918 addresses and internal domains are restricted to internal feeds and cannot trigger external SSRF queries.
3. **Input Sanitization**:
   All string parameters, names, descriptions, and custom tags are escaped and length-bounded.

---

## 10. Frontend Architecture & Design System

The frontend workspace is implemented in React 19 / TypeScript / Tailwind CSS under `src/components/watchlists/` and `src/pages/Watchlists.tsx`:

1. **Watchlist List View (`WatchlistList.tsx`)**:
   - Header metrics ribbon: Total Watchlists, Monitored Observables, Malicious Detections, Unresolved Changes.
   - Status & Priority filters with real-time text search.
   - Watchlist cards featuring aggregate indicator counts, health badges, cadence metrics, and quick action controls (Pause, Resume, Refresh, Delete).
   - Modal for creating new watchlists with custom sensitivity, alert thresholds, and cooldowns.
2. **Watchlist Detail Workspace (`WatchlistDetailView.tsx`)**:
   - Top banner with priority badge, status controls, and "Refresh All" button.
   - **Observability Health Card**: Visual distribution of Healthy, Malicious, Stale, and Degraded observables, plus cycle timestamps.
   - **Monitored Indicators Tab**: Compact table displaying indicator type, raw/normalized values, consensus verdict, confidence percentage, last check, and individual refresh/remove buttons.
   - **Add Indicators Modal**: Supports single indicator creation or bulk newline-delimited imports with real-time normalization.
   - **Intelligence Changes Tab**: Explainable timeline cards displaying change type badges, severity indicators, previous vs current verdicts, and links to created Section 48 alerts.
   - **Monitoring Runs Tab**: Audit table of past background jobs, execution triggers (`SCHEDULED` vs `MANUAL`), checked/changed/failed item counts, and run duration.
3. **Quick-Watch Action (`QuickWatchModal.tsx`)**:
   - Integrated into Section 52's `IndicatorIntelligencePanel.tsx` via an eye icon button.
   - Allows analysts investigating an Incident or Investigation to immediately monitor any observable with 1 click, capturing source incident/investigation provenance without leaving their workflow.

---

## 11. Verification & Test Coverage

Test suite `backend/tests/test_section53_watchlist_monitoring.py` covers 13 test suites (100% passing):

1. `test_watchlist_creation_and_defaults`: Validates creation, default cadence, sensitivity, and alert thresholds.
2. `test_watchlist_update_and_pause_resume`: Validates lifecycle status transitions (`ACTIVE` <-> `PAUSED`).
3. `test_watchlist_deletion_cascades`: Confirms foreign key cascade deletes watched items, snapshots, and changes.
4. `test_add_indicator_normalization_and_idempotency`: Tests RFC1918/Punycode normalization and duplicate insertion rejection.
5. `test_bulk_add_indicators`: Verifies bulk text ingestion and duplicate suppression.
6. `test_snapshot_fingerprint_deterministic_stability`: Confirms SHA-256 fingerprint stability across arbitrary key orderings.
7. `test_detect_material_change_newly_malicious`: Verifies `NEWLY_MALICIOUS` detection on `UNKNOWN` -> `MALICIOUS` transition.
8. `test_detect_material_change_became_clean`: Verifies `BECAME_CLEAN` detection on `MALICIOUS` -> `CLEAN` transition.
9. `test_alert_created_on_material_change_and_cooldown_suppression`: Validates formal `SECURITY_ALERT` creation in `NotificationModel` and cooldown window suppression.
10. `test_execute_monitoring_cycle_and_run_logging`: Validates Section 45 execution cycle and `WatchlistMonitoringRunModel` telemetry logging.
11. `test_quick_watch_workflow_from_incident`: Tests 1-click monitoring provenance capture from incidents.
12. `test_multi_tenant_isolation_watchlists`: Guarantees zero cross-workspace data leakage.
13. `test_watchlists_rest_api_crud`: Full end-to-end FastAPI test client validation of all REST endpoints.
