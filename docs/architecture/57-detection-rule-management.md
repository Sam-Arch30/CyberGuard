# SECTION 57 — DETECTION RULE MANAGEMENT & OPERATIONAL CONTROL ARCHITECTURE

## 1. Executive Summary & Objective

Section 56 established CyberGuard's Detection Engineering and Rule Lifecycle foundation, providing controlled DSL/AST grammar, static type validation, complexity budgets, and historical backtesting.

Section 57 turns that foundation into an enterprise-scale operational detection-management system capable of maintaining 10 to 10,000+ rules in production. The core principle is:
> **Detection engineering creates reliable rules. Detection management keeps those rules reliable in production.**

This system maintains the architectural boundary:
```text
DETECTION ENGINEERING (AST / Compilation / Backtest)
         ↓
RULE MANAGEMENT & OPERATIONAL CONTROL (Section 57)
         ↓
CONTROLLED DEPLOYMENT (Staging → Production)
         ↓
DETECTION ENGINE (Runtime AST Evaluation)
         ↓
FINDING (FindingModel)
         ↓
RISK (Unified Risk Engine)
         ↓
ALERT (AlertCenter)
         ↓
INCIDENT (Case & SLA Management)
         ↓
INVESTIGATION & RESPONSE
```

---

## 2. Rule Library & SOC Grid

### 2.1 Route & Search Capabilities
- **API Endpoint**: `GET /api/v1/rules`
- **Frontend Route**: `/detections`
- Supports server-side multi-dimensional filtering and cursor/offset pagination without client-side data bloat:
  - `status`: Lifecycle statuses (`DRAFT`, `APPROVED`, `STAGED`, `ACTIVE`, `DISABLED`, `DEPRECATED`, `RETIRED`)
  - `deployment_state`: Independent operational deployment stage (`DRAFT`, `STAGING`, `PRODUCTION`, `DISABLED`)
  - `operational_health`: Deterministic health status (`HEALTHY`, `DEGRADED`, `FAILING`, `UNKNOWN`)
  - `category`: Taxonomy categories (`PHISHING`, `IMPERSONATION`, `CREDENTIAL_THEFT`, `MALWARE`, `ENDPOINT`, `NETWORK`, `ACCOUNT_TAKEOVER`)
  - `severity`: Standard severity tiers (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL`)
  - `owner_id` & `team_id`: Direct ownership attribution
  - `collection`: Logical domain groupings (e.g., `Email Security`, `Identity Security`, `Endpoint EDR`)
  - `review_due`: Flag for rules whose `next_review_due <= now`
  - `is_stale`: Flag for rules active > 60 days with 0 matches and pending review
  - `search`: Substring search against rule name, identifier, ATT&CK techniques, and tags.

---

## 3. Operational Health vs Rule Status

A core architectural principle of Section 57 is that **Lifecycle Status** and **Operational Health** are completely decoupled:
- A rule may be `status: ACTIVE` in `deployment_state: PRODUCTION`, yet have `operational_health: DEGRADED` or `FAILING` due to an unavailable data source or excessive latency.

### 3.1 Health States
1. **`HEALTHY`**: All required dependencies operational; execution latency within SLA (p95 < 2000ms); error rate < 5%; matches within expected statistical bounds.
2. **`DEGRADED`**: Optional dependency offline, execution error rate between 5% and 25%, or latency elevated (p95 ≥ 2000ms).
3. **`FAILING`**: One or more required dependencies offline, or execution error rate ≥ 25%.
4. **`UNKNOWN`**: Rule has not recorded runtime telemetry or is currently draft/inactive.

### 3.2 Deterministic Telemetry Signals
- **Execution Telemetry (Last 24h)**: `execution_count`, `success_count`, `failure_count`, `error_rate`, `avg_duration_ms`, `p95_duration_ms`.
- **Match Rate & Anomaly Detection**: Last 24 hours vs previous 24 hours vs 7-day rolling daily average. A deterministic surge threshold (`matches_24h >= 20 and matches_24h > max(10, daily_avg * 4.0)`) flags unusual match rate anomalies.
- **Zero-Match Rules**: Rules that have executed without matching are explicitly marked `zero_match_observed: True`. Zero matches are never conflated with execution failure.
- **Stale & Review Overdue**: Configurable `review_interval_days` (default 90 days) calculates `next_review_due`. Rules past due are flagged for recertification.

---

## 4. Dependency Mapping & Availability

Rules map explicit dependencies to telemetry components:
- **`DATA_SOURCE`**: e.g., `EMAIL_EVENT`, `ENDPOINT_EVENT`, `NETWORK_EVENT`.
- **`ANALYZER`**: e.g., `email_security_analyzer`, `url_domain_intelligence`, `credential_theft_analyzer`.
- **`INTELLIGENCE`**: External feed indicators, WHOIS, or reputation services.
- **`BASELINE`**: Behavioral baseline tables and anomaly windows.
- **`WATCHLIST`**: Monitored VIP or suspicious asset lists.

Each dependency specifies `required: true|false`. If an optional analyzer degrades, the rule remains operational in `DEGRADED` health. If a required data source goes offline, the rule immediately shifts to `FAILING`.

---

## 5. Deployment Lifecycle & Staging Control

### 5.1 Deployment States
- `DRAFT` → `STAGING` → `PRODUCTION` → `DISABLED`

### 5.2 Pre-flight Deployment Dry-Run
Before activating or promoting a rule to production, the `POST /api/v1/rules/{id}/dry-run` endpoint performs deterministic dry-run verification:
1. Validates AST grammar against data source field registry.
2. Checks all required dependencies for `HEALTHY` operational status.
3. Performs historical backtest over past 7 days.
4. Synthesizes a categorical operational risk score: `LOW`, `MEDIUM`, or `HIGH`.

### 5.3 Promotion to Production
`POST /api/v1/rules/{id}/deploy` requires:
- Explicit immutable `target_version` snapshot (never deploying unversioned draft states).
- Elevated role authorization (`admin` or `lead-analyst`).
- Mandatory operational justification reason.
- Immutable audit event creation in `audit_events`.
- Section 46 realtime event broadcast `RULE_DEPLOYED`.

### 5.4 Safe Rollback
`POST /api/v1/rules/{id}/rollback`:
- Reverts rule logic to an existing historical immutable version (`CandidateRuleVersionModel`).
- Requires authorization, justification reason, and dry-run validation of the rollback target version.
- Preserves complete version history without rewriting prior immutable records.
- Dispatches high-severity Section 47 alert notification `RULE_ROLLED_BACK`.

### 5.5 Emergency Disable
`POST /api/v1/rules/{id}/emergency-disable`:
- Immediately ceases production pipeline execution without deleting the rule.
- Records actor, timestamp, and mandatory justification reason.
- Sets `deployment_state = DISABLED` and `status = DISABLED`.
- Emits critical realtime event `RULE_DISABLED` and Section 47 emergency security alert `RULE_EMERGENCY_DISABLED`.

---

## 6. Scoped Suppression Exceptions (`rule_suppressions`)

To eliminate recurring false positives without disabling whole detection rules, Section 57 introduces scoped, time-bounded suppressions:
- **Entity**: `RuleSuppressionModel` stored in table `rule_suppressions`.
- **Fields**: `id`, `rule_id`, `name`, `scope_type`, `scope_target`, `match_operator`, `match_value`, `is_active`, `expires_at`, `hit_count`, `last_hit_at`.
- **Runtime Evaluation**: When an active rule matches an event in `evaluate_telemetry_event`:
  - `DetectionRuleManagementService.check_suppression()` tests all active, unexpired suppressions.
  - If a suppression matches:
    - Finding creation is suppressed (no false alert generated).
    - Execution log records `suppression_applied_id` and increments `hit_count`.
    - Operational transparency is preserved for audits.

---

## 7. Ground-Truth Feedback & Quality Metrics

Analysts review rule matches and submit ground-truth dispositions:
- **Allowed Dispositions**: `TRUE_POSITIVE`, `FALSE_POSITIVE`, `BENIGN`, `EXPECTED_ACTIVITY`, `NEEDS_REVIEW`.
- Dispositions are stored on `CandidateRuleExecutionModel` (`disposition`, `disposition_by`, `disposition_at`, `disposition_notes`).
- **Persisted Metrics**: Precision Rate %, False Positive Rate %, Review Coverage %.
- If insufficient analyst reviews have been recorded, the API reports `has_sufficient_data: False` rather than fabricating statistical confidence.

---

## 8. Redundancy & Conflict Detection

- **Duplicate Detection**: Uses normalized AST condition fingerprints (`normalized_fingerprint`). Compares canonical condition trees to identify exact logic overlaps across active rules.
- **Conflict Detection**: Compares rule targets and suppression ranges to detect contradictory conditions.

---

## 9. Bulk Operations

- `POST /api/v1/rules/bulk`:
  - Supported actions: `ENABLE`, `DISABLE`, `SET_OWNER`, `SET_COLLECTION`, `TAG`.
  - Independent per-rule validation and authorization.
  - Returns partial-success report (`total_selected`, `successful`, `failed`, and breakdown per rule). Never reports false total success if any individual rule fails.

---

## 10. Integrations Matrix

| Section | Integration Point | Functionality |
| :--- | :--- | :--- |
| **Section 25** | Candidate Detection Rule Pipeline | Upgrades candidate rules to fully managed operational rules. |
| **Section 39** | LLM SOC Copilot | Generates compliant AST proposals; AI is strictly restricted from autonomous activation/deletion. |
| **Section 43** | Audit Logging (`AuditEventModel`) | Records immutable audit trails for deploy, rollback, emergency disable, and suppressions. |
| **Section 45** | Background Job Worker | Executes asynchronous health evaluations, large-scale simulations, and bulk operations. |
| **Section 46** | Realtime Service (`RealtimePublisher`) | Publishes `RULE_DEPLOYED`, `RULE_DISABLED`, `RULE_ROLLED_BACK`, `RULE_HEALTH_CHANGED`. |
| **Section 47** | Notifications & Alert Center | Dispatches critical security alerts for emergency disable, rollback, and degraded dependencies. |
| **Section 48** | Alert Center Integration | Rules link directly from Alert records to the exact immutable generating rule version. |
| **Section 52** | Threat Intelligence Enrichment | Verifies intelligence dependency health before rule activation. |
| **Section 53** | Watchlists Monitoring | Verifies watchlist table availability as an operational dependency. |
| **Section 54/55** | Threat Hunting Query Engine | "Hunt This Pattern" translates detection AST into structured hunt queries for retro-hunting. |
| **Section 56** | Detection Engineering Lifecycle | Inherits DSL validation, AST compiler, version immutability, and backtesting. |

---

## 11. Security & RBAC Enforcement

1. **Multi-Tenant Isolation**: Every database query filters by `workspace_id`. Cross-tenant rule reads, modifications, or evaluations are strictly rejected with HTTP 404/403.
2. **Role-Based Access Control**:
   - `analyst`: Can view rules, test events, run backtests, submit reviews, and create scoped suppressions.
   - `admin` / `lead-analyst`: Required for production deployment, rollback, and emergency disable.
   - Unauthorized attempts return HTTP 403 Forbidden.
3. **Executable Logic Safety**: Rules are evaluated via a sandboxed in-memory AST evaluator (`_evaluate_ast_against_record`). No raw Python `eval()`, JavaScript execution, or dynamic SQL queries are executed.
4. **Autonomous AI Safeguards**: AI can recommend rule definitions but can never activate, promote, rollback, or disable rules autonomously. Human authorization is strictly mandatory.

---

## 12. Limitations & Boundary Integrity

- **No Competing Detection Engine**: Section 57 does not replace or duplicate the detection engine. It operates purely as the management and operational control plane.
- **Deterministic Math Only**: Quality metrics, anomaly detection, and health signals rely strictly on actual persisted telemetry records. No fabricated precision scores or fake health percentages are generated.
- **External Format Extensibility**: Architecture exposes clean normalization interfaces for future Sigma, YARA, or Suricata importers, which translate into CyberGuard AST rather than running foreign formats natively.
