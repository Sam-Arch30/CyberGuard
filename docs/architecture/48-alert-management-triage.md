# SECTION 48: ALERT MANAGEMENT & TRIAGE WORKSPACE

## 1. Executive Summary & Design Principles

CyberGuard Section 48 introduces the **Analyst-Facing Alert Triage Workspace** (`/alerts`), bridging the gap between automated detection and human security operations. It establishes an authoritative triage pipeline without creating redundant detection engines, incident models, or notification subsystems.

### Core Distinction: Detection to Resolution Pipeline

```text
Technical Event / Telemetry
   ↓
Automated Detection Engine
   ↓
Finding (Forensic Evidence Output)
   ↓
Risk Engine & Confidence Scorer
   ↓
Security Alert (Authoritative Operational Signal)
   ↓
Notification (Analyst Awareness & Toast / Badge)
   ↓
Alert Triage Queue (/alerts)
   ↓
┌──────────────────────────────────────────────┐
│  Acknowledge  │  Assign  │  Investigate     │
│  False Positive  │  Suppress  │  Resolve    │
└──────────────────────────────────────────────┘
   ↓
Investigation Workspace (/investigations/:id)
   ↓
Response Recommendation & Playbook (/investigations/:id/response)
   ↓
Final Authoritative Disposition (Resolved with Justification)
```

1. **Finding vs. Alert**: A finding is machine-generated evidence produced by an analyzer (e.g., `CredentialHarvesterDetector` extracting an HTML form POST URL). An alert is a user-facing security signal evaluated as requiring human triage.
2. **Alert vs. Notification**: Notifications represent transient and persistent alerts delivered to users (toasts, badge counts, drawer history). Security alerts are actionable stateful operational units managed by SOC analysts.
3. **No Mock or Fake Data**: All alert records are strictly populated from persisted `NotificationModel` records (where `category == 'SECURITY_ALERT'`), with zero client-side synthetic generators or `setInterval` mocks.
4. **No Destructive Auto-Execution**: Triage actions transition alert statuses and log audits; they never automatically delete accounts, sinkhole DNS, or block IPs from the triage view without human approval through the response playbook engine (Sections 28–29).

---

## 2. Alert Lifecycle & State Transitions

Security Alerts traverse an authoritative state machine:

```text
                 ┌───────────────┐
                 │     OPEN      │
                 └───────┬───────┘
                         │
        ┌────────────────┼────────────────┐
        │                │                │
        ▼                ▼                ▼
┌──────────────┐ ┌──────────────┐ ┌──────────────┐
│ ACKNOWLEDGED │ │INVESTIGATING │ │  SUPPRESSED  │
└───────┬──────┘ └───────┬──────┘ └──────────────┘
        │                │
        └────────┬───────┘
                 │
        ┌────────┴───────┐
        │                │
        ▼                ▼
┌──────────────┐ ┌──────────────┐
│   RESOLVED   │ │FALSE_POSITIVE│
└──────────────┘ └──────────────┘
```

| State | Description | Permitted Transitions |
|---|---|---|
| `OPEN` | Initial state of newly evaluated security alert. Includes legacy unread alerts. | `ACKNOWLEDGED`, `INVESTIGATING`, `FALSE_POSITIVE`, `SUPPRESSED`, `RESOLVED` |
| `ACKNOWLEDGED` | Analyst has reviewed the signal and assumed awareness. | `INVESTIGATING`, `FALSE_POSITIVE`, `SUPPRESSED`, `RESOLVED` |
| `INVESTIGATING` | Active forensic investigation is underway (attached to or creating an investigation). | `RESOLVED`, `FALSE_POSITIVE`, `SUPPRESSED` |
| `RESOLVED` | Threat resolved with required deterministic resolution reason. | Terminal (reopen supported via audit) |
| `FALSE_POSITIVE` | Benign activity confirmed with mandatory analyst justification. | Terminal |
| `SUPPRESSED` | Alert silenced without deleting underlying findings or evidence. | Terminal / scoped |

---

## 3. Data Model & Database Migration

Security alerts reuse `NotificationModel` (aliased as `AlertModel = NotificationModel` in `backend.db.models`) where `category == 'SECURITY_ALERT'`, avoiding duplicate rows between alerts and notifications while adding dedicated triage columns:

```sql
ALTER TABLE notifications ADD COLUMN assigned_to VARCHAR(100);
ALTER TABLE notifications ADD COLUMN resolved_at TIMESTAMP;
ALTER TABLE notifications ADD COLUMN resolved_by VARCHAR(100);
ALTER TABLE notifications ADD COLUMN resolution_reason TEXT;
ALTER TABLE notifications ADD COLUMN false_positive_reason TEXT;
ALTER TABLE notifications ADD COLUMN suppression_reason TEXT;
ALTER TABLE notifications ADD COLUMN suppression_scope VARCHAR(50);
ALTER TABLE notifications ADD COLUMN updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;

CREATE INDEX ix_notifications_assigned_to ON notifications (assigned_to);
CREATE INDEX ix_notifications_category_status_sev ON notifications (category, status, severity);
CREATE INDEX ix_notifications_updated_at ON notifications (updated_at);
```

Automated runtime migration in `backend/db/session.py` inspects `PRAGMA table_info(notifications)` on startup and adds missing columns automatically.

---

## 4. Provenance Graph & Explainable AI (Section 27 Integration)

Each alert exposed in the triage detail drawer maintains bidirectional provenance:

```text
Alert Item (#ALT-1092)
  ├── Severity & Risk Score (94 / 100)
  ├── Explainable AI "Why This Alert Exists" (Rule triggers + ML reasoning)
  ├── Originating Finding (FindingModel)
  │     ├── Analyzer ID & Rule ID (CredentialHarvesterDetector: RULE-PHISH-009)
  │     ├── Detection Method (RULE, HEURISTIC, ML, LLM)
  │     └── Evidence Items (FindingEvidenceModel: keys, values, confidence)
  ├── Analysis Run (AnalysisRunModel)
  │     ├── Status & Pipeline Version
  │     └── Target Artifact (Name, SHA256 digest, mime-type)
  └── Investigation Link (IncidentModel / INV-1042)
        └── Deep link to Forensic Workspace & Response Playbooks
```

When an analyst opens an alert, `AlertService.getAlertDetail()` queries the authoritative database models to construct this full context without returning dummy values.

---

## 5. Audit Logging (Immutable Append-Only Audit Trail)

Every state-changing triage action records an immutable audit record via `AuditService.log_audit`:

- `ALERT_ACKNOWLEDGED`: Records analyst identity, timestamp, and optional triage note.
- `ALERT_ASSIGNED`: Records assignee identity and delegating analyst.
- `ALERT_INVESTIGATING`: Records analyst transitioning alert to active investigation.
- `ALERT_RESOLVED`: Records mandatory resolution justification and resolver.
- `ALERT_FALSE_POSITIVE`: Records mandatory justification why signal was benign.
- `ALERT_SUPPRESSED`: Records suppression reason and scope (`THIS_ALERT`, `INDICATOR`, `PATTERN`).
- `ALERT_NOTE_ADDED`: Appends sanitized case observation notes with audit history.

All events are displayed chronologically in the **Audit Activity Timeline** within the alert detail view.

---

## 6. Real-Time SSE Integration (Section 46)

Alert triage operations broadcast real-time Server-Sent Events via `RealtimePublisher._async_broadcast`:

| Event Type | Scope | Trigger | Client Action |
|---|---|---|---|
| `ALERT_STATUS_CHANGED` | `WORKSPACE` | Acknowledge, investigate, or bulk acknowledge | Refreshes queue and posture metrics |
| `ALERT_ASSIGNED` | `WORKSPACE` | Alert assigned to analyst | Updates assignment chip and queue |
| `ALERT_RESOLVED` | `WORKSPACE` | Alert resolved with justification | Moves alert from Open queue to Resolved |
| `ALERT_NOTE_ADDED` | `WORKSPACE` | Triage observation appended | Appends note in activity timeline |
| `ALERT_SUPPRESSED` | `WORKSPACE` | Alert suppressed | Updates queue status without destroying input |

The frontend hook `useRealtimeSubscription({ url: '/api/events/stream' })` updates open lists and metrics seamlessly while preserving dirty input states if an analyst is drafting notes.

---

## 7. REST API Endpoints

All endpoints require `X-Workspace-ID` header (defaulting to `"default"`) and enforce strict tenant isolation.

| Method | Path | Summary | Description |
|---|---|---|---|
| `GET` | `/api/alerts` | List Security Alerts | Paginated alert queue with status, severity, query search (`q`), and sort order |
| `GET` | `/api/alerts/metrics` | Operational Metrics | Counts for Total, Open, Critical Open, High Open, Unacknowledged, Investigating, Resolved |
| `GET` | `/api/alerts/{id}` | Alert Detail & Provenance | Full explainability why-cards, evidence list, finding, analysis run, and audit timeline |
| `POST` | `/api/alerts/{id}/acknowledge` | Acknowledge Alert | Transitions alert to `ACKNOWLEDGED` with audit logging |
| `POST` | `/api/alerts/{id}/assign` | Assign Alert | Assigns alert to analyst or team |
| `POST` | `/api/alerts/{id}/investigate` | Mark Investigating | Transitions status to `INVESTIGATING` |
| `POST` | `/api/alerts/{id}/resolve` | Resolve Alert | Transitions status to `RESOLVED` with required justification |
| `POST` | `/api/alerts/{id}/false-positive`| Mark False Positive | Transitions status to `FALSE_POSITIVE` with required reason |
| `POST` | `/api/alerts/{id}/suppress` | Suppress Alert | Transitions status to `SUPPRESSED` with reason and scope |
| `POST` | `/api/alerts/{id}/notes` | Add Triage Note | Appends sanitized case observation note |
| `POST` | `/api/alerts/bulk/acknowledge` | Bulk Acknowledge | Acknowledges multiple alerts within authorized workspace scope |

---

## 8. Frontend Architecture & Theme Support

- **Page**: `src/pages/AlertWorkspace.tsx` provides an operational SOC queue layout, status tabs (`ALL`, `OPEN`, `ACKNOWLEDGED`, `INVESTIGATING`, `RESOLVED`, `FALSE_POSITIVE`, `SUPPRESSED`), severity filters, search box, metric summary cards, bulk selection, and responsive layout.
- **Drawer**: `src/components/alerts/AlertDetailDrawer.tsx` provides focused triage details, Explainable AI reasons, machine evidence indicator list, provenance cards, audit activity timeline, case note form, and action confirmation modals.
- **Deep Links**:
  - `NotificationDrawer.tsx`: Links into `/alerts` and `/alerts/:id`.
  - `Dashboard.tsx`: Priority queue links into `/alerts`.
  - `AlertDetailDrawer.tsx`: Links to `/investigations/:id` and `/investigations/:id/response`.
- **Themes**: Full semantic design token support for **Olive**, **Sakura**, **Paper**, and **Midnight** themes with contrast-safe severity badges (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).

---

## 9. Verification & Test Evidence

- **Unit & Integration Suite**: `backend/tests/test_section48_alerts_triage.py` (6 passed in 1.83s).
- **Regression Suite**: `test_section44`, `test_section45`, `test_section46`, `test_section47` (37 passed in 9.39s).
- **Frontend Type & Bundle Compilation**: `npm run build` (`tsc -b && vite build`) passed with 0 errors.
