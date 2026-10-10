# Section 47 — Notifications & Alert Center Architecture

## 1. Executive Overview

Section 47 establishes a **unified, persistent, and secure notification and alert management subsystem** for the CyberGuard AI Powered Cyber Threat & Incident Response Platform. It bridges the existing background jobs (Section 45), analysis orchestrator (Section 37), real-time updates (Section 46), investigation workspace (Section 39), reports (Section 42), and SOC Overview (Section 44) into an authoritative notifications and security alerts hub.

---

## 2. Core Tripartite Conceptual Model

CyberGuard strictly distinguishes between three concepts to avoid notification fatigue and ambiguous severity:

```
┌────────────────────────────────────────────────────────────────────────┐
│ 1. INTERNAL TECHNICAL EVENT (Section 46)                               │
│ Internal pipeline occurrences (e.g. TASK_STARTED, JOB_PROGRESS).        │
│ Strictly used for Live Analysis DAG streaming. NOT shown in Center.   │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │
                                   ▼
                   ┌───────────────────────────────┐
                   │   NOTIFICATION POLICY ENGINE  │
                   │   (Deterministic Evaluation)  │
                   └───────┬───────────────┬───────┘
                           │               │
        Qualifying Milestones              High-Confidence Security Threats
                           │               │
                           ▼               ▼
┌─────────────────────────────────────┐ ┌──────────────────────────────────────┐
│ 2. USER NOTIFICATION                │ │ 3. ACTIONABLE SECURITY ALERT         │
│ "Something relevant happened."      │ │ "Dangerous threat requires action."  │
│ - Analysis Run Completed/Failed     │ │ - High/Critical Phishing Detected    │
│ - Forensic Report Ready/Failed      │ │ - Malicious Executable Attachment    │
│ - Background Job Failed/Retrying    │ │ - Lookalike Impersonation            │
│ Categories: INFO, LOW, MEDIUM       │ │ - Credential Theft Indicator         │
│ Lifecycle: UNREAD ➔ READ            │ │ - Account Takeover Anomaly           │
│                                     │ │ Categories: HIGH, CRITICAL           │
│                                     │ │ Lifecycle: UNREAD ➔ ACKNOWLEDGED     │
└─────────────────────────────────────┘ └──────────────────────────────────────┘
```

---

## 3. Persistent Data Model (`notifications` Table)

A single compact database model, `NotificationModel` in `backend/db/models.py`, stores notifications and security alerts with authoritative foreign key provenance:

| Column | Type | Index | Description |
|---|---|---|---|
| `id` | VARCHAR(36) | Primary Key | UUID identifier |
| `workspace_id` | VARCHAR(64) | Yes | Tenant isolation partition (defaults to `default`) |
| `user_id` | VARCHAR(100) | Yes | Optional recipient scope (`NULL` = workspace-wide) |
| `category` | VARCHAR(32) | Yes | `NOTIFICATION` or `SECURITY_ALERT` |
| `notification_type` | VARCHAR(64) | Yes | Controlled taxonomy (e.g., `CRITICAL_THREAT_DETECTED`) |
| `severity` | VARCHAR(20) | Yes | Authoritative severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`) |
| `status` | VARCHAR(30) | Yes | `UNREAD`, `READ`, `ACKNOWLEDGED`, `DISMISSED` |
| `title` | VARCHAR(255) | No | Concise summary title |
| `message` | TEXT | No | Sanitized description (no raw secrets, tokens, or EML bytes) |
| `source_type` | VARCHAR(50) | Yes | Originating entity (`FINDING`, `ANALYSIS_RUN`, `REPORT`, `JOB`) |
| `source_id` | VARCHAR(128) | Yes | Identifier of the originating source entity |
| `investigation_id`| VARCHAR(128) | Yes | Associated investigation for triage routing |
| `analysis_run_id` | VARCHAR(36) | Yes | FK to `analysis_runs.id` |
| `finding_id` | VARCHAR(36) | Yes | FK to `findings.id` |
| `job_id` | VARCHAR(36) | Yes | FK to `background_jobs.id` |
| `report_id` | VARCHAR(36) | Yes | FK to `reports.id` |
| `navigation_target`| VARCHAR(255) | No | Canonical deep link target (e.g., `/investigations/{id}`) |
| `deduplication_key`| VARCHAR(190) | Yes | Deterministic key preventing duplicate notifications |
| `metadata_json` | TEXT | No | Sanitized JSON metadata (explanation points, score impacts) |
| `created_at` | DATETIME | Yes | UTC timestamp |
| `read_at` | DATETIME | No | UTC timestamp when marked read |
| `acknowledged_at`| DATETIME | No | UTC timestamp when analyst acknowledged alert |
| `acknowledged_by`| VARCHAR(100) | No | Identity of acknowledging SOC analyst |

---

## 4. Notification Policy & Noise Suppression

To avoid alert fatigue, `NotificationPolicy` in `backend/services/notification_policy.py` filters technical noise:

- **Intentionally Ignored Internal Events:**
  - `JOB_CREATED`, `JOB_QUEUED`, `JOB_STARTED`, `JOB_PROGRESS`, `JOB_RETRY_SCHEDULED`
  - `ANALYSIS_STARTED`, `ANALYSIS_STAGE_STARTED`, `ANALYSIS_STAGE_COMPLETED`, `ANALYSIS_PROGRESS`
  - `TASK_STARTED`, `TASK_PROGRESS`, `TASK_COMPLETED`
  - Routine `LOW` / `SAFE` findings
- **Qualifying Security Alerts:**
  - `CRITICAL` or `HIGH` findings persisted by analyzers (`dangerous_attachment_type`, `lookalike_impersonation`, `social_engineering_phishing`, `credential_harvesting`)
  - Overall investigation risk reaching `HIGH` or `CRITICAL` threshold ($\ge 60/100$)
- **Qualifying System Notifications:**
  - `ANALYSIS_COMPLETED` (concluded run)
  - `ANALYSIS_FAILED` (pipeline execution error)
  - `REPORT_READY` (forensic PDF/JSON dossier compiled)
  - `REPORT_FAILED` (compilation halted)
  - `JOB_FAILED` (background asynchronous task failure)

---

## 5. Deduplication Strategy

Cybersecurity monitoring pipelines generate frequent re-evaluations. Duplicate prevention is enforced via the `deduplication_key` column:

- **Finding Alerts:** `alert:finding:{workspace_id}:{finding_id}`
- **Analysis Runs:** `notif:run:{workspace_id}:{run_id}:{status}`
- **Reports:** `notif:report:{workspace_id}:{report_id}:{status}`
- **Jobs:** `notif:job:{workspace_id}:{job_id}:FAILED`
- **Investigation Risk:** `alert:inv_risk:{workspace_id}:{investigation_id}:{severity}`

If an existing record is found with the same `(workspace_id, deduplication_key)`, insertion is suppressed without throwing errors.

---

## 6. Real-Time Transport Integration (Section 46)

The notification system uses the Section 46 real-time Server-Sent Events (SSE) infrastructure without creating separate WebSocket channels:

1. A qualifying event or finding triggers `NotificationService.create_notification(...)`.
2. The record is committed to the database.
3. `RealtimePublisher._async_broadcast(...)` broadcasts a `NOTIFICATION_CREATED` event to `workspace:{workspace_id}` (and `investigation:{id}` if present).
4. Clients subscribed to `/api/dashboard/stream` or workspace streams receive `NOTIFICATION_CREATED`, `NOTIFICATION_READ`, or `ALERT_ACKNOWLEDGED`.
5. Frontend updates unread badge counts and invalidates/refetches authoritative lists on demand.

---

## 7. Frontend User Experience

- **Topbar Header Bell:**
  - Displays a compact unread count badge (`1`, `5`, `99+`).
  - Animates with pulse styling when unread `CRITICAL` or `HIGH` security alerts are present.
  - Clicking toggles the slide-out `NotificationDrawer`.
- **Slide-Out Notification Drawer:**
  - Accessible dialog (`role="dialog"`, `aria-label`, Escape to close).
  - Category tabs: `All`, `Unread`, `Alerts` (Security), `System`.
  - Severity filters: `All`, `Critical`, `High`, `Medium`, `Low`, `Info`.
  - Distinguishable visual styling:
    - **Security Alerts:** ShieldAlert icon, threat-critical or threat-high badges, explanation previews.
    - **System Notifications:** Info icon, subtle primary badges.
  - Action buttons:
    - "Open Investigation" / "Open Report" (deep link navigation).
    - "Mark as Read".
    - "Acknowledge" (for SOC analysts to acknowledge threats).
    - "Mark all read" in header.
- **Investigation Summary Bar Integration:**
  - Displays an active `ALERT` badge when the investigation is categorized as `CRITICAL` or `HIGH`.
- **SOC Overview (Dashboard) Integration:**
  - Displays unread security alerts badge in the operational header controls.
- **Theme Compatibility:**
  - Built strictly using semantic design tokens (`bg-surface`, `bg-surface-elevated`, `border-border`, `text-threat-critical`, `text-threat-high`, `text-threat-safe`), verified across Olive, Sakura, Paper, and Midnight themes.

---

## 8. Security & Data Protection

- **Tenant Isolation:** Enforced via `X-Workspace-ID` header and database partitioning. Cross-tenant access is rejected.
- **XSS Protection:** Attacker-controlled strings (email subjects, sender names, filenames, domains) are rendered strictly as text nodes in React, preventing HTML/script execution.
- **Credential Redaction:** Error messages pass through `sanitize_error_message`, scrubbing passwords, API tokens, stack traces, and internal IPs.
