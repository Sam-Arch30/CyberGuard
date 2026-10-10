# Section 54 — Threat Hunting Workspace & Query Engine

## 1. Overview & Operational Architecture

The **Threat Hunting Workspace & Query Engine** provides CyberGuard with an evidence-driven, analyst-controlled query layer. It allows security analysts to proactively investigate suspicious hypotheses, uncover stealthy multi-stage attack patterns, and identify emerging indicators across data CyberGuard already possesses.

The operational flow within CyberGuard is structured as:

```text
Data Ingestion (Sensors, Ingestion Gateway, Endpoints)
  ↓
Detection (Multi-engine analytical detectors)
  ↓
Alert (Security Signal: NotificationModel / SECURITY_ALERT)
  ↓
Incident (Operational Case Lifecycle: Section 50 & Section 51)
  ↓
Threat Intelligence Enrichment (Section 52: Multi-provider evidence layer)
  ↓
Watchlist Monitoring (Section 53: Continuous temporal change detection)
  ↓
Threat Hunting (Section 54: Proactive analytical query & hypothesis testing)
  ↓
Investigation (Forensic Workspace, Attack Path, Timeline)
  ↓
Response (Response Recommendation & Playbooks: Section 37 & 38)
```

### Core Philosophy: Proactive Discovery, Not Response Automation

Threat Hunting is governed by the principle:

> **Search → Observe → Pivot → Investigate**
> *(Never: Search → Automatically Execute Response)*

Threat Hunting does not execute disruptive containment actions (such as firewall blocks, endpoint isolations, or user suspensions) directly. Instead, it surfaces correlated findings and allows analysts to hand them off seamlessly to **Section 50 Investigations**, **Section 53 Watchlists**, or **Section 48 Alerts**.

---

## 2. Distinguishing Lookup Search from Threat Hunting

| Capability | Section 43: History & Search | Section 54: Threat Hunting & Query Engine |
|---|---|---|
| **Primary Intent** | "Find this known artifact or indicator." | "Find suspicious relationships or anomalies that may not yet be alerted." |
| **Input Structure** | Unstructured query string (Text, ID, Hash, Domain). | Structured Query DSL (`field`, `operator`, `value`, `time_range`, `group_by`). |
| **Logic** | Text normalization, prefix matching, exact ID lookup. | Relational expressions, multi-predicate filtering, Top-N aggregation. |
| **Temporal Bounding** | Optional timestamp filter. | Strictly bounded time windows (`15m`, `1h`, `6h`, `24h`, `7d`, `30d`). |
| **Hypothesis Support**| None. | First-class hypothesis tracking and analyst reasoning. |
| **Saved Artifacts** | Search history. | Reusable `SavedHuntModel` queries with team sharing. |
| **Downstream Handoff**| View record details. | 1-Click Escalate to Investigation, Add to Watchlist, Graph Pivot. |

---

## 3. Architecture & Execution Engine Diagram

```mermaid
graph TD
    subgraph Analyst Workspace
        UI[Threat Hunting UI: /hunting] --> QB[Visual Query Builder]
        UI --> NL[Natural Language Query Assistant]
        NL -->|Rule-Backed Translation| QB
        UI --> SH[Saved Hunts & Built-in Templates]
        SH --> QB
    end

    subgraph Security Gatekeeper & Query Validator
        QB --> VAL{Data Source Registry & Allowlist Validator}
        VAL -->|Invalid field / Incompatible operator / SQL injection| REJ[Structured Rejection Error]
        VAL -->|Valid DSL| PLAN[Explainable Query Plan Generation]
    end

    subgraph Execution Routing
        PLAN --> MODE{Execution Mode}
        MODE -->|Fast Mode| SYNC[Direct Synchronous ORM Execution]
        MODE -->|Background Mode| ASYNC[Section 45 BackgroundJob: THREAT_HUNT_EXECUTION]
    end

    subgraph Authoritative Persistence Layer
        SYNC --> REG_DATA[(CyberGuard Data Sources)]
        ASYNC --> REG_DATA
        REG_DATA --> IND[IndicatorModel]
        REG_DATA --> ALT[NotificationModel: Alerts]
        REG_DATA --> FND[FindingModel]
        REG_DATA --> ART[ArtifactModel]
        REG_DATA --> TI[ThreatIntelligenceRecordModel]
        REG_DATA --> WC[IntelligenceChangeModel]
        REG_DATA --> INC[IncidentModel]
    end

    subgraph Aggregation, Logging & Realtime
        REG_DATA --> AGG[Server-Side Top-N Grouping]
        AGG --> AUDIT[HuntExecutionModel: Matched IDs & Duration]
        AUDIT --> RT[Section 46 Realtime: HUNT_COMPLETED]
        AUDIT --> RES[Hunt Results Workspace]
    end

    subgraph Downstream Forensic Handoffs
        RES -->|1-Click Escalate| S50[Section 50: Create Incident / Investigation]
        RES -->|1-Click Watch| S53[Section 53: Add to Watchlist]
        RES -->|Pivot| S23[Knowledge Graph & OSINT Pivot]
        RES -->|Export| EXP[JSON / CSV Audit Export]
    end
```

---

## 4. Data Source Registry

To prevent arbitrary database access or sensitive field leakage, the query engine operates strictly against a curated **Data Source Registry** (`DATA_SOURCE_REGISTRY` in `ThreatHuntingService`):

| Data Source Key | Underlying Model | Description | Default Time Field | Allowlisted Query Fields |
|---|---|---|---|---|
| `indicators` | `IndicatorModel` | Canonical forensic IOCs | `last_seen` | `indicator_type`, `normalized_value`, `reputation`, `confidence`, `first_seen`, `last_seen` |
| `alerts` | `NotificationModel` (`category="SECURITY_ALERT"`) | Triaged security signals | `created_at` | `title`, `severity`, `status`, `source_type`, `assigned_to`, `created_at` |
| `findings` | `FindingModel` | Analyzer conclusions | `created_at` | `title`, `analyzer`, `finding_type`, `severity`, `confidence`, `method`, `created_at` |
| `artifacts` | `ArtifactModel` | Forensic files & payloads | `created_at` | `filename`, `mime_type`, `sha256`, `source`, `size_bytes`, `created_at` |
| `threat_intelligence` | `ThreatIntelligenceRecordModel` | Enriched provider observations | `retrieved_at` | `indicator_type`, `normalized_value`, `provider`, `verdict`, `severity`, `confidence`, `retrieved_at` |
| `watchlist_changes` | `IntelligenceChangeModel` | Monitored reputation transitions | `detected_at` | `change_type`, `change_severity`, `previous_verdict`, `current_verdict`, `normalized_value`, `detected_at` |
| `incidents` | `IncidentModel` | Operational case containers | `opened_at` | `incident_number`, `title`, `status`, `severity`, `risk_score`, `sla_status`, `opened_at` |

### Explicit Security Allowlist
The registry strictly excludes:
- User passwords, authentication hashes, and session tokens.
- Third-party API keys and credentials (`VIRUSTOTAL_API_KEY`, etc.).
- Raw email bodies and private message contents.
- Internal database system IDs and foreign-key implementation details.

---

## 5. Query DSL & Supported Operators

Queries are expressed as structured, type-safe JSON payloads:

```json
{
  "data_source": "indicators",
  "filters": [
    {
      "field": "indicator_type",
      "operator": "equals",
      "value": "DOMAIN"
    },
    {
      "field": "reputation",
      "operator": "in",
      "value": ["MALICIOUS", "SUSPICIOUS"]
    }
  ],
  "time_range": {
    "preset": "7d"
  },
  "group_by": "reputation",
  "top_n": 10,
  "limit": 50,
  "offset": 0
}
```

### Supported Operators
- **Equality**: `equals`, `not_equals`
- **Textual**: `contains`, `starts_with`, `ends_with`
- **Set Inclusion**: `in`, `not_in`
- **Relational / Numeric**: `greater_than`, `greater_than_or_equal`, `less_than`, `less_than_or_equal`, `between`
- **Existence**: `exists`, `not_exists`
- **Temporal**: `before`, `after`, `within_last`

---

## 6. Query Cost Limits & Safety Boundaries

To prevent unbounded database scans or denial-of-service from runaway queries:
1. **Bounded Result Limit**: Maximum page size is strictly capped at `1000` records (default `50`).
2. **Mandatory Tenant Scoping**: Every query automatically injects `Model.workspace_id == workspace_id`.
3. **Bounded Time Ranges**: Relative time presets (`15m`, `1h`, `6h`, `24h`, `7d`, `30d`) compute deterministic UTC boundaries (`now - delta <= col <= now`).
4. **Top-N Cardinality Limits**: Server-side aggregations restrict grouped buckets to `top_n <= 100` (default `20`).
5. **No Raw SQL Execution**: Client input is parsed into parameterized SQLAlchemy expressions; raw string interpolation is forbidden.

---

## 7. Execution Modes & Background Orchestration

1. **Fast Mode (`FAST`)**:
   - Executes synchronously within the HTTP request lifecycle for bounded indexed lookups (< 500ms).
2. **Background Mode (`BACKGROUND`)**:
   - For long-running queries or multi-source aggregations, dispatches a Section 45 Background Job:
     ```python
     JobSubmitRequest(
         job_type=JobTypeEnum.THREAT_HUNT_EXECUTION,
         resource_type="HUNT",
         payload={"query_definition": qdef.model_dump(), "saved_hunt_id": saved_id}
     )
     ```
   - Managed by `handle_threat_hunt_execution` in `backend/services/background_job_worker.py`.
   - Progress and completion events are streamed via Section 46 WebSockets.

---

## 8. Saved Hunts & Built-in Templates

Queries can be persisted in `SavedHuntModel` (`saved_hunts`) with custom hypotheses, tags, and visibility scopes (`PRIVATE`, `TEAM`, `TENANT`).

### Built-in Templates Seeded Automatically
1. **Newly Malicious Indicators (Last 24h)**:
   - Source: `watchlist_changes`
   - Filter: `change_type == "NEWLY_MALICIOUS"`, `detected_at within last 24h`.
   - Hypothesis: "High-priority threat indicators flagged malicious by consensus intelligence within 24 hours."
2. **High-Risk Infrastructure (Domains & IPs)**:
   - Source: `threat_intelligence`
   - Filter: `verdict == "MALICIOUS"`, `indicator_type in ["DOMAIN", "IP"]`, `retrieved_at within last 7 days`.
   - Hypothesis: "External infrastructure with active malicious reputation."
3. **Unacknowledged Critical Security Alerts**:
   - Source: `alerts`
   - Filter: `severity == "CRITICAL"`, `status == "UNREAD"`.
   - Hypothesis: "Critical security alerts requiring urgent SOC triage."

---

## 9. Controlled Natural Language Assistant

Security analysts can query CyberGuard using plain English (e.g. *"Find malicious domains observed in the last 24 hours"*).

### Safety Architecture: Model Proposal, Deterministic Execution
1. The assistant extracts candidate entities, indicator types, severities, and temporal words.
2. It translates the phrase into a valid `HuntQueryDefinition` without producing SQL or shell commands.
3. The backend runs `ThreatHuntingService.validate_query` against the Data Source Registry allowlist.
4. The query plan and explanation are presented to the analyst in the UI.
5. **The query is never executed automatically**—explicit analyst review and button execution are required.

---

## 10. Downstream Integrations

1. **Section 53 IOC Watchlists**:
   - Selected hunt results can be added directly to an existing or new Watchlist via `handoff_to_watchlist`.
   - Section 53 takes over continuous polling, snapshotting, and reputation drift alerting.
2. **Section 50 Incidents & Case Lifecycle**:
   - Analysts can promote hunt results to a formal `IncidentModel` via `handoff_to_investigation`.
   - Attaches execution ID, reason, and record references to preserve forensic chain-of-custody.
3. **Section 52 Threat Intelligence (OSINT)**:
   - Deep links each observable result directly to `/osint?indicator=...` for multi-provider breakdown.
4. **Knowledge Graph & Attack Reconstruction**:
   - Pivot button links directly to `/graph?focus=...` to visualize multi-hop infrastructure relationships.
5. **Section 46 Realtime Updates**:
   - Emits `HUNT_COMPLETED`, `HUNT_FAILED`, and `HUNT_PROGRESS` WebSocket events on workspace channels.

---

## 11. Verification & Test Suite

The test suite in `backend/tests/test_section54_threat_hunting.py` validates all core capabilities:

1. `test_data_source_registry_completeness`: Verifies registry metadata, field allowlists, and operator configurations.
2. `test_query_validation_success_and_query_plan`: Verifies validation passes and generates explainable plan steps.
3. `test_query_validation_rejects_unsupported_fields_and_sql_injection`: Verifies non-allowlisted fields and invalid operators are rejected.
4. `test_query_execution_indicators`: Validates indicator queries, deterministic ranking, explainability, and pivot links.
5. `test_query_execution_alerts`: Validates security alert queries and severity filtering.
6. `test_query_aggregations_and_grouping`: Validates server-side group-by aggregation and percentage calculations.
7. `test_saved_hunts_crud_and_template_seeding`: Validates template seeding, custom hunt creation, updating, and deletion.
8. `test_natural_language_to_query_translation`: Validates NLP query translation into bounded DSL definitions.
9. `test_investigation_and_watchlist_handoffs`: Validates handoffs to Section 50 Incidents and Section 53 Watchlists.
10. `test_multi_tenant_isolation_hunting`: Guarantees zero cross-workspace data leakage.
11. `test_rest_api_hunting_routes`: Tests all FastAPI endpoints under `/api/hunting`.
