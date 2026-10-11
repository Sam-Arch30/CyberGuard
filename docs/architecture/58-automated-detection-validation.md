# SECTION 58 — AUTOMATED DETECTION VALIDATION & CONTINUOUS RULE QUALITY ARCHITECTURE

## 1. Executive Summary & Objective

Section 56 established CyberGuard's Detection Engineering core (DSL/AST grammar, compiler, evaluator, backtesting), and Section 57 added Detection Management & Operational Control (library management, deployment states, review schedules, suppressions).

**Section 58 establishes the Automated Detection Validation & Continuous Rule Quality Layer**. Its purpose is to continuously answer the foundational security operations question:
> **"Can I trust this detection rule right now?"**

The system answers this with empirical evidence rather than intuition, continuously evaluating whether detection rules are:
- **Structurally valid** (syntax, AST constraints, operator compatibility)
- **Executable** (runtime evaluation under bounded SLA without timeouts or crashes)
- **Compatible with available data** (schema contracts, registered data sources)
- **Compatible with dependencies** (telemetry pipelines, threat intelligence feeds, baselines)
- **Producing expected behavior** (deterministic positive and negative fixtures)
- **Suffering from regression** (match volume surges/collapses, latency degradation)
- **Affected by schema/data-source drift** (unregistered fields, dropped telemetry)
- **Experiencing execution-performance degradation** (p95 latency exceeding SLA)
- **Safe to promote or activate** (authoritative backend gatekeeper for production deployment)

### Complete Lifecycle
```text
Rule Creation → Validation → Review → Deployment → Continuous Validation → Quality Evaluation → Drift/Regression Detection → Warning/Failure → Analyst Action → Retest → Promotion/Rollback/Retirement
```

---

## 2. Core Architectural Principle: Validation Sits Above Existing Engines

Section 58 **orchestrates** validation rather than replacing existing components. It adheres strictly to the rule:
> **Do not build a second detection engine, evaluator, compiler, query engine, scheduler, or metrics platform.**

```text
                 DETECTION ENGINEERING (Section 56)
                         │
                         ▼
                 CandidateRuleModel
                         │
                         ▼
                  CandidateRuleVersionModel
                         │
                         ▼
                Existing Compiler (Section 56 AST Compiler)
                         │
                         ▼
               Existing Evaluator (Section 56 Evaluator)
                         │
          ┌──────────────┼──────────────┐
          ▼              ▼              ▼
       Replay         Backtest      Live Telemetry
          │              │              │
          └──────────────┼──────────────┘
                         ▼
             SECTION 58 VALIDATION ORCHESTRATOR
                         │
          ┌──────────────┼──────────────┐
          ▼              ▼              ▼
       Structural      Behavioral     Operational
       Validation      Validation     Validation
          │              │              │
          └──────────────┼──────────────┘
                         ▼
                  Quality Assessment
                         │
          ┌──────────────┼──────────────┐
          ▼              ▼              ▼
        PASS          WARNING          FAIL / BLOCKED
                         │
                         ▼
                Section 57 Operational Control
                         │
                         ▼
              Production Promotion Gate / Analyst Action
```

---

## 3. The 8 Multi-Dimensional Validation Dimensions

Each validation run evaluates a detection rule across eight distinct, non-overlapping dimensions:

| Dimension | Scope | Underlying Mechanism | Failure / Warning Semantics |
|---|---|---|---|
| **1. STRUCTURAL** | AST syntax, operators, allowed fields, nesting limits, regex safety | Section 56 `DetectionRuleLifecycleService.validate_and_compile` | **FAIL**: Syntax invalid, unsupported operator, regex unsafe |
| **2. DEPENDENCY** | Required vs optional data streams, threat feeds, baselines | Section 57 `DetectionRuleManagementService._resolve_rule_dependencies` | **BLOCKED**: Required dependency failing; **PASS_WITH_WARNINGS**: Optional degraded |
| **3. DATA COMPATIBILITY** | Field registration in data contract, active telemetry streams | `DATA_SOURCE_FIELD_REGISTRY` and live event volume checks | **FAIL**: Schema drift (missing/removed field); **PASS_WITH_WARNINGS**: Workspace telemetry inactive |
| **4. EXECUTION** | Deterministic sample evaluation under strict time bounds | Section 56 `_evaluate_ast_against_record` with SLA timeout guard | **FAIL**: Runtime exception, evaluator crash; **TIMED_OUT**: SLA exceeded (5.0s) |
| **5. PERFORMANCE** | Runtime latency benchmarks and SLA compliance | Execution clock measurement (< 200ms target) | **PASS_WITH_WARNINGS**: Latency exceeds 200ms warning threshold |
| **6. REGRESSION** | Version-to-version and historical volume changes | Comparison against 24h baseline (`CandidateRuleExecutionModel`) | **PASS_WITH_WARNINGS**: 4x surge over baseline (potential condition overbreadth) |
| **7. BEHAVIORAL QUALITY** | Analyst dispositions, false-positive ratios | Historical execution dispositions from Section 57 | **PASS_WITH_WARNINGS**: FP rate > 25%; **PASS**: FP rate <= 25% or zero matches on healthy rule |
| **8. TEST FIXTURES** | Deterministic positive and negative test cases | `DetectionRuleTestFixtureModel` evaluation harness | **FAIL**: Positive fixture does not match, or negative fixture matches |

---

## 4. Critical Semantic Distinctions

The validation framework strictly adheres to critical operational semantics:

1. **Zero Matches $\neq$ Validation Failure**:
   A targeted, high-fidelity rule with zero matches on healthy data is normal and produces `STATUS: PASS` (`ZERO_MATCHES_HEALTHY`).
2. **Required Dependency Unavailable $\neq$ Clean / No Threats**:
   If telemetry is down, the rule cannot safely observe events. It produces `STATUS: BLOCKED` (`REQUIRED_DEPENDENCY_UNAVAILABLE`), preventing false security assumptions.
3. **Match Volume Surge $\neq$ Fatal Failure**:
   A 10,000-match surge over a 20-match baseline indicates behavioral shift or condition overbreadth. It produces `STATUS: PASS_WITH_WARNINGS` (`MATCH_RATE_SURGE_REGRESSION`), requiring review rather than fatal termination.
4. **Evaluator Timeout $\neq$ PASS**:
   A rule exceeding the 5.0-second timeout SLA produces `STATUS: TIMED_OUT`, never silent pass.
5. **Realtime Transport Failure $\neq$ Backend Validation Failure**:
   If WebSocket or SSE delivery fails, the backend job completes and persists authoritatively. The client reconciles state upon reconnect.
6. **No Autonomous Modification of Production Rules**:
   Validation never automatically deletes, rewrites, suppresses, or modifies production rules. It flags problems, updates health metrics, emits alerts, and blocks unvalidated promotion.

---

## 5. Persistence & Data Model

Three dedicated database models in `backend/db/models.py` persist validation state:

### 5.1 `DetectionValidationRunModel` (`detection_validation_runs`)
- `id`: UUID primary key
- `workspace_id`: Multi-tenant isolation key
- `rule_id`: Foreign key to `candidate_rules.id`
- `rule_version`: Version string evaluated (e.g. `1`, `v2`)
- `validation_type`: `STRUCTURAL`, `DEPENDENCY`, `DATA_COMPATIBILITY`, `EXECUTION`, `REGRESSION`, `PERFORMANCE`, `BEHAVIOR`, `FIXTURES`, `FULL`
- `status`: `NOT_RUN`, `QUEUED`, `RUNNING`, `PASS`, `PASS_WITH_WARNINGS`, `FAIL`, `BLOCKED`, `CANCELLED`, `TIMED_OUT`, `STALE`
- `trigger_type`: `MANUAL`, `SCHEDULED`, `VERSION_UPDATE`, `DEPENDENCY_CHANGE`, `PROMOTION_GATE`, `CONTINUOUS_SWEEP`
- `started_at`, `completed_at`: Bounded execution timestamps
- `requested_by`, `executed_by`: Audit actor tracking
- `job_id`: Section 45 Background Job reference
- `baseline_rule_version`: Baseline version used for regression analysis
- `is_stale`, `stale_reason`: Invalidation tracking when rules or schemas update
- `summary_json`, `metadata_json`: Aggregate statistics and execution details

### 5.2 `DetectionValidationResultModel` (`detection_validation_results`)
- `id`: UUID primary key
- `run_id`: Foreign key to `detection_validation_runs.id`
- `workspace_id`, `rule_id`: Tenant and rule identifiers
- `category`: Validation dimension (`STRUCTURAL`, `DEPENDENCY`, `DATA_COMPATIBILITY`, etc.)
- `status`: `PASS`, `PASS_WITH_WARNINGS`, `FAIL`, `BLOCKED`
- `severity`: `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`
- `code`: Machine-readable code (e.g. `AST_SYNTAX_VALID`, `SCHEMA_DRIFT_FIELD_MISSING`)
- `message`: Analyst-readable explanation
- `observed_value_json`, `expected_value_json`, `baseline_value_json`: Structured comparative evidence
- `evidence_json`: Complete diagnostic payload

### 5.3 `DetectionRuleTestFixtureModel` (`detection_rule_test_fixtures`)
- `id`: UUID primary key
- `rule_id`: Foreign key to `candidate_rules.id`
- `workspace_id`: Multi-tenant key
- `name`, `description`: Test fixture metadata
- `fixture_type`: `POSITIVE` (expected match) or `NEGATIVE` (expected non-match)
- `expected_match`: Boolean expected evaluator output
- `payload_json`: Deterministic sample event payload
- `last_result`: `PASS`, `FAIL`, `NOT_RUN`, `BLOCKED`
- `last_run_at`, `last_error`: Test execution telemetry

---

## 6. Integration Architecture

### 6.1 Section 45: Background Job Orchestration
Long-running and full validations execute asynchronously via CyberGuard's Section 45 Background Job framework:
- Job types: `DETECTION_RULE_VALIDATION_RUN`, `DETECTION_RULE_CONTINUOUS_SWEEP`
- Worker handler: `BackgroundJobWorker._handle_detection_rule_validation_run` and `_handle_detection_rule_continuous_sweep`
- Supports status transitions: `QUEUED` $\rightarrow$ `RUNNING` $\rightarrow$ `SUCCEEDED` / `FAILED` / `CANCELLED`

### 6.2 Section 46: Realtime Event Streaming
Emits typed realtime events over WebSocket/SSE:
- `VALIDATION_RUN_STARTED`, `VALIDATION_RUN_PROGRESS`, `VALIDATION_RUN_COMPLETED`
- `VALIDATION_RUN_FAILED`, `VALIDATION_RUN_CANCELLED`
- `RULE_VALIDATION_STATUS_CHANGED`, `RULE_QUALITY_CHANGED`, `RULE_DRIFT_DETECTED`, `RULE_GATE_BLOCKED`

### 6.3 Section 47: Operational Notifications
Dispatches alerts for degraded quality or blocked gates:
- `VALIDATION_FAILED_CRITICAL`: Critical production rule validation failed
- `VALIDATION_SCHEMA_DRIFT`: Missing or removed schema field detected
- `VALIDATION_PERFORMANCE_REGRESSION`: Latency SLA degradation
- `VALIDATION_GATE_BLOCKED`: Promotion to production blocked by unpassed gates

### 6.4 Section 57: Production Promotion Gate
Enforces authoritative promotion criteria before activating rules to `PRODUCTION`:
1. Rule must have a completed, non-stale validation run for target version
2. Latest run status must be `PASS` or `PASS_WITH_WARNINGS` (never `FAIL`, `BLOCKED`, `NOT_RUN`, or `TIMED_OUT`)
3. Zero fatal structural errors or unhandled schema drift
4. Non-admin users are strictly blocked with HTTP 400
5. Admins may override with a mandatory, fully audited `VALIDATION_OVERRIDE_BY_ADMIN` log

---

## 7. REST API Endpoints

| Method | Path | Description | Authorization |
|---|---|---|---|
| `GET` | `/api/v1/rules/validation/overview` | SOC overview stats across rules & runs | Analyst / Admin |
| `GET` | `/api/v1/rules/validation/runs/{id}` | Detailed validation run report & evidence | Analyst / Admin |
| `POST` | `/api/v1/rules/validation/runs/{id}/cancel` | Authoritative cancellation of running job | Approver / Admin |
| `GET` | `/api/v1/rules/{id}/validation` | Latest validation summary for rule | Analyst / Admin |
| `POST` | `/api/v1/rules/{id}/validation` | Request on-demand validation (sync or async) | Analyst / Admin |
| `GET` | `/api/v1/rules/{id}/validation/gate` | Authoritative Production promotion gate check | Analyst / Admin |
| `GET` | `/api/v1/rules/{id}/validation/history` | Paginated validation run history | Analyst / Admin |
| `GET` | `/api/v1/rules/{id}/fixtures` | List deterministic test fixtures | Analyst / Admin |
| `POST` | `/api/v1/rules/{id}/fixtures` | Create positive or negative test fixture | Analyst / Admin |
| `POST` | `/api/v1/rules/{id}/fixtures/{fix_id}/run` | Execute individual test fixture | Analyst / Admin |
| `DELETE` | `/api/v1/rules/{id}/fixtures/{fix_id}` | Delete test fixture | Analyst / Admin |

---

## 8. Frontend Experience & Design System

The Section 58 UI is seamlessly integrated into the Detection Rules cockpit (`/detections`):
1. **Catalog Table Badge**: Every rule displays its real-time validation badge (`PASS`, `WARN`, `FAIL`, `BLOCKED`, `STALE`, `NOT RUN`).
2. **Continuous Validation & Quality Subtab**: Dedicated management dashboard displaying:
   - SOC Overview Cards (Total Rules, Passed, Warnings, Blocked/Failed, 24h Runs, Fixtures count)
   - Latest Validation Run Report with categorized accordion checks and evidence
   - Production Promotion Gate Inspector
   - Deterministic Test Fixtures manager (create, view, and run positive/negative fixtures)
   - Paginated historical runs comparison drawer
3. **Design System**: Fully compatible with CyberGuard's Olive, Sakura, Paper, and Midnight themes, with no synthetic or fabricated metrics.
