# Section 44 — SOC Overview: Real-Time, Evidence-Driven Security Operations Center Dashboard

## 1. Dashboard Architecture
The **Section 44 SOC Overview** transforms CyberGuard's primary dashboard (`/dashboard`) into an operational security command workstation designed for immediate, high-fidelity threat triage and situational awareness. 

The dashboard provides an operational hierarchy that answers six fundamental security questions:
1. **What is happening across the security environment?** &rarr; Security Posture Metrics and Unified Risk Distribution.
2. **Which investigations require attention?** &rarr; Ranked, actionable Priority Queue.
3. **Which high-risk findings are new or unresolved?** &rarr; Posture metric cards with direct navigation to filtered investigation views.
4. **Are analyses, ingestion jobs, and endpoint agents functioning?** &rarr; System & Fleet Health subsystem status.
5. **What attack patterns or campaigns are emerging?** &rarr; Threat Intelligence & Campaign Correlation context.
6. **What defensive actions require analyst review?** &rarr; Pending response approval queue items linked to Section 28 & 29 workflows.

```
┌────────────────────────────────────────────────────────────────────────┐
│ SOC Command Bar: Time Window (24h/7d/30d/All) | Live Freshness | Sync   │
├────────────────────────────────────────────────────────────────────────┤
│ Posture: Active Cases | High/Crit | Approvals | Findings | Fleet | Health│
├───────────────────────────────────┬────────────────────────────────────┤
│ Priority Queue (2/3 width)        │ Risk Distribution (1/3 width)      │
│ Ranked actionable investigations, │ Unified Risk Spectrum (80-100 down)│
│ pending defensive recommendations,│ ────────────────────────────────── │
│ and failed analysis runs.         │ Subsystem & Fleet Health           │
│                                   │ DB, API, Pipeline, Online Agents   │
├───────────────────────────────────┴────────────────────────────────────┤
│ Threat Intelligence & Campaign Correlation                             │
│ Top observables with provenance tags + correlated campaign clusters    │
├────────────────────────────────────────────────────────────────────────┤
│ Investigation Activity Feed                                            │
│ Auditable timeline events from append-only audit log                   │
├────────────────────────────────────────────────────────────────────────┤
│ Universal Ingestion Gateway (Section 36 preserved)                     │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Metric Definitions & Semantics

Every metric displayed on the dashboard is computed from authoritative, persisted database records without mock counters or synthetic data:

| Metric | Source Model | Precise Operational Definition |
|---|---|---|
| **Active Cases** | `IncidentModel`, `CaseModel` | Count of distinct investigations whose persisted lifecycle status is `OPEN`, `INVESTIGATING`, or `CONTAINED`. Excludes `CLOSED`, `RESOLVED`, and `FALSE_POSITIVE`. |
| **High / Critical** | `IncidentModel`, `CaseModel` | Count of distinct active investigations whose authoritative risk assessment score is &ge; 60.0 or severity is `HIGH` or `CRITICAL`. |
| **Pending Approvals** | `ResponseRecommendationModel` | Count of defensive recommendations requiring analyst review (`status == "REVIEW_REQUIRED"` or `approval_required == True` with `status in ["GENERATED", "REVIEW_REQUIRED"]`). |
| **New Findings** | `FindingModel` | Total analytical findings created within the selected time window (`created_at >= window_start`). |
| **Fleet Agents** | `EndpointAgentModel` | Online fleet agents reporting an active heartbeat (`status == "ACTIVE"`), alongside total enrolled agents. |
| **Failed Analysis Jobs** | `AnalysisRunModel`, `AnalysisTaskModel` | Asynchronous pipeline execution jobs that terminated in `FAILED` status within the selected window. |
| **Total Investigations** | `IncidentModel`, `CaseModel` | Historical all-time count of unique incidents and cases registered in the workspace. |

---

## 3. Time Window Semantics
Analysts can adjust the aggregation window via the top command bar:
- **`24h`**: Past 24 hours (`now - 24 hours`). Filters new findings, failed jobs, and activity events.
- **`7d`**: Past 7 days (`now - 7 days`).
- **`30d`**: Past 30 days (`now - 30 days`) — default operational view.
- **`all`**: Unbounded historical record evaluation.

*Note on current vs. windowed state:* Posture metrics representing current operational state (such as *Active Cases* and *Fleet Agents*) reflect current live database state regardless of time window, preventing misleading representations of currently open threats.

---

## 4. Priority Queue Ordering
The **Priority Queue** is the primary operational component of the dashboard, ordering actionable records by a transparent, deterministic priority function:

1. **Urgency Weight**:
   - `P0`: Critical-risk active incidents (&ge; 80 score or `CRITICAL` severity), and emergency defensive action recommendations.
   - `P1`: High-risk active investigations (&ge; 60 score or `HIGH` severity), and urgent response recommendations.
   - `P2`: Failed asynchronous analysis runs requiring manual triage, and active medium-risk investigations.
   - `P3`: General open investigations in progress.
2. **Authoritative Risk Score** (secondary sort key).
3. **Last Updated Timestamp** (recency sort key).

Each entry contains a concise, human-readable reason for inclusion (e.g. *"Critical-risk active incident requiring immediate response"*), the current status, and a deep link to the corresponding investigation or response workspace.

---

## 5. Threat Intelligence Provenance
Indicators surfaced in the intelligence section maintain strict epistemic provenance labels:
- **`CURRENT_OBSERVATION`**: Directly extracted from active telemetry in current investigations.
- **`HISTORICAL_MEMORY`**: Observed in previous historical incidents and retained in Section 23 Threat Memory.
- **`ANALYST_VERIFIED`**: Validated by human analyst decision in `threat_memory_decisions`.
- **`EXTERNAL_INTELLIGENCE`**: Enriched from external threat intelligence providers.

Clicking any indicator opens the **Cross-Investigation Indicator Detail Drawer** for deep forensic drill-down.

---

## 6. Refresh & Real-Time Updates
- **Bounded Polling**: Automatic polling interval of 30 seconds.
- **Inactivity Awareness**: Utilizes `document.visibilityState` to halt background polling when the browser tab is hidden, preventing battery/network consumption. Polling resumes immediately when the tab is focused.
- **Manual Refresh**: 1-click synchronous refresh with animated feedback.
- **Data Freshness Counter**: Relative seconds counter ("Live", "12s ago") and absolute timestamp tooltip (`10:45 AM`).

---

## 7. Subsystem Health
Platform health distinguishes between **application availability** and **security posture**:
- An environment with 0 threats and operational health is not labeled "100% secure".
- Subsystems verified:
  - **Database Connection**: Live `SELECT 1` connectivity query.
  - **API Engine**: FastAPI route availability.
  - **Analysis Tasks**: Monitors pending, running, and failed asynchronous tasks.
  - **Endpoint Fleet**: Agent counts by status (`ACTIVE`, `DEGRADED`, `REVOKED`).

---

## 8. API Contract

### `GET /api/dashboard/overview`
- **Query Parameters**:
  - `time_window`: `24h` | `7d` | `30d` | `all` (default `30d`)
  - `workspace_id`: Tenant identifier (default `default`)
  - `limit_queue`: Maximum priority items (default `10`, max `50`)
  - `limit_activity`: Maximum activity items (default `15`, max `50`)
- **Response**: `SocOverviewResponse` containing:
  - `generated_at`: UTC timestamp
  - `time_window`: Active window
  - `posture`: `SocPostureMetrics`
  - `risk_distribution`: `SocRiskDistribution`
  - `priority_queue`: Array of `SocPriorityQueueItem`
  - `recent_activity`: Array of `SocActivityItem`
  - `threat_intel`: Array of `SocThreatIntelItem`
  - `active_campaigns`: Array of `SocCampaignSummaryItem`
  - `system_health`: `SocSystemHealth`
  - `partial_failures`: Array of strings

---

## 9. Security & Tenant Scoping
- **Tenant Isolation**: All queries accept `workspace_id` and enforce database-level filtering.
- **Privacy & Sanitization**: Responses omit raw MIME bodies, credentials, tokens, or unredacted evidence payloads.
- **XSS & Injection Protection**: Usernames, audit details, and indicator values are rendered as safe React text nodes.

---

## 10. Verification Commands & Results

```bash
# Section 44 test suite
PYTHONPATH=. ./backend/venv/bin/pytest backend/tests/test_section44_soc_overview.py

# Full regression verification (Sections 39, 42, 43, 44)
PYTHONPATH=. ./backend/venv/bin/pytest backend/tests/test_section44_soc_overview.py backend/tests/test_section43_history_and_search.py backend/tests/test_section42_report_workspace.py backend/tests/test_section39_investigation_workspace.py

# Frontend build & lint
npm run build
npm run lint
```

**Verification Results:**
- `test_section44_soc_overview.py`: **6 passed in 1.42s** (100% pass)
- Full regression suite: **23 passed in 10.25s** (100% pass)
- TypeScript build & Vite bundle: **0 errors**
- Linter: **0 errors**
