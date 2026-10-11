# Architecture Document: Section 60 — Behavioral Detection & Anomaly Analytics

## 1. Executive Summary & Objective

The **Behavioral Detection & Anomaly Analytics** engine elevates the CYBERGUARD platform from purely signature- and rule-based evaluation into **behavior-aware, entity-centric detection**. It establishes multi-dimensional statistical baselines across critical identity, host, network, and application entities, accurately surfaces deviations, isolates potentially poisoned training data, and generates evidence-backed behavioral findings without alert fatigue.

### Behavioral Detection Lifecycle

```
Telemetry Ingestion
        │
        ▼
Event Normalization
        │
        ▼
Entity & Context Resolution (USER, ACCOUNT, DEVICE, ENDPOINT, API_CLIENT, IP, DOMAIN)
        │
        ▼
Behavioral Feature Extraction (Numeric, Categorical, Circular Hour, Frequency)
        │
        ▼
Behavioral Baseline Check & Cold-Start Evaluation
        │
 ┌──────┴──────────────────────────────────────┐
 │ If Cold-Start (INSUFFICIENT_DATA / LEARNING) │
 │ ➔ Accumulate Baseline Samples               │
 │ ➔ Check for Poisoning / Outlier Shifts      │
 │    └─ Extreme shifts ➔ Quarantine Queue     │
 └──────┬──────────────────────────────────────┘
        │
        ▼
Deviation & Novelty Scoring (Z-Score, Standard Deviation, Circular Angular Distance)
        │
 ┌──────┴──────────────────────────────────────┐
 │ Deviation Score ≥ Threshold (Default: 0.65)  │
 │ ➔ Check Entity Cooldown (Fatigue Defense)   │
 │ ➔ Record Behavioral Deviation Record        │
 │ ➔ Generate Behavioral Finding & Evidence    │
 │ ➔ Propagate to Unified Risk Engine          │
 │ ➔ Dispatch Security Alert & Realtime Pub    │
 └─────────────────────────────────────────────┘
```

### Core Philosophical Distinctions
CYBERGUARD enforces four non-negotiable operational boundaries:
1. **NOVEL ≠ ANOMALOUS ≠ MALICIOUS**: A first-time observed administrative tool is *novel*, abnormal login volume during business hours is *anomalous*, but only confirmed adversarial activity with malicious context is *malicious*.
2. **ANOMALY ≠ RISK**: High mathematical divergence does not immediately warrant a Critical incident unless paired with privileged context, malicious intent indicators, or compounding attack paths.
3. **INSUFFICIENT DATA ≠ NORMAL**: Entities without established baselines are classified as `INSUFFICIENT_DATA` or `LEARNING`. The system explicitly avoids declaring absence of anomalies as "clean health."
4. **ZERO FAKE DATA**: All statistics, baseline bounds, sample counts, and deviations reflect actual mathematical observations.

---

## 2. Architectural Ecosystem & Reuse Strategy

Section 60 does **not** introduce redundant anomaly engines, feature databases, or separate risk calculators. Instead, it unifies existing foundational subsystems:

- **Reuses Section 30 (`BehavioralBaselineService`)**: Leverages `BehavioralStatisticsEngine`, `CircularHourDistribution`, and `BehavioralBaselineModel` for baseline calculation and distribution modeling.
- **Reuses Section 31 (`NoveltyDetectionService`)**: Correlates novelty scores with behavioral deviations to detect emerging threat patterns.
- **Reuses Section 32 (`ThreatMemoryService`)**: Queries historical actor behavior and historical attack fingerprints.
- **Reuses Section 33 (`ContinualLearningService`)**: Feeds verified behavioral feedback into long-term learning pipelines.
- **Reuses Section 35 (`RiskEngineService`)**: Enriches baseline deviations with contextual threat scores to calculate risk.
- **Reuses Section 59 (`UnifiedThreatDetectionPipelineService`)**: Integrates directly into Stage 10 of the unified detection pipeline, evaluating behavioral context alongside AST rules.
- **Reuses Section 45 Background Jobs**: Schedules `BEHAVIORAL_BASELINE_REFRESH` and `BEHAVIORAL_BATCH_ANOMALY_RUN` via `BackgroundJobWorker`.
- **Reuses Section 46 Realtime WebSockets**: Dispatches notifications via `RealtimePublisher` on `BEHAVIOR_PROFILE_UPDATED`, `BEHAVIOR_ANOMALY_DETECTED`, `BEHAVIOR_BASELINE_DEGRADED`, and `BEHAVIOR_QUARANTINE_CREATED`.
- **Reuses Section 47 Notification Engine**: Emits high-priority alert items via `NotificationService` for analysts.

---

## 3. Entity Classification & Context Resolution

The engine maintains entity profiles (`BehaviorProfileModel`) across 7 distinct security entity categories:

| Entity Type | Identifier Source | Primary Tracked Features | Baseline Dimensions |
|:---|:---|:---|:---|
| **USER** | `user_id`, `actor_id` | Login hours, auth failure rates, email volume | Temporal, Frequency |
| **ACCOUNT** | `account_id`, `username` | Access attempts, password resets, token refresh rate | Volumetric, Temporal |
| **DEVICE** | `device_id`, `hardware_id` | Network bytes, process counts, USB insertions | Host metrics, Network |
| **ENDPOINT** | `endpoint_id`, `host_id` | Process execution rate, command length, file mods | Process, Filesystem, Memory |
| **API_CLIENT** | `api_key_id`, `client_id` | Request frequency, error rates, endpoint variety | Rate, Status Codes |
| **IP** | `source_ip`, `dest_ip` | Packet rates, destination port diversity | Network Flow |
| **DOMAIN** | `domain_name`, `fqdn` | Query frequencies, DNS resolution patterns | DNS, Reputation |

Entity context is extracted during event processing through `BehavioralFeatureExtractor.extract_from_normalized_detection_event` and `extract_from_endpoint_event`.

---

## 4. Behavioral Feature Extractor

`BehavioralFeatureExtractor` translates normalized events and raw telemetry into standardized metric observations:

- `LOGIN_HOUR`: Normalized local hour of day (0–23) evaluated using circular trigonometric distributions ($d = \min(\|h_1 - h_2\|, 24 - \|h_1 - h_2\|)$).
- `ENDPOINT_PROCESS_COUNT`: Total active processes spawned within a sampling window.
- `NETWORK_BYTES_SENT`: Outbound payload volume in bytes.
- `AUTH_FAILURE_RATE`: Proportion of failed authentication events to total attempts.
- `API_CALL_FREQUENCY`: API requests dispatched per minute.
- `COMMAND_LINE_LENGTH`: Character length of executed command lines (flagging encoded scripts or buffer exploits).
- `PROCESS_EXECUTION_FREQUENCY`: Process execution rate per endpoint.
- `FILE_MODIFICATION_RATE`: File system mutation velocity per minute.
- `EMAIL_VOLUME`: Outbound emails transmitted per unit time.

---

## 5. Profile Lifecycle & Cold-Start Management

Entity profiles transition through five explicit operational lifecycle states:

```
┌────────────────────┐
│ INSUFFICIENT_DATA  │ < 5 samples (cold start)
└─────────┬──────────┘
          │
          ▼
┌────────────────────┐
│      LEARNING      │ 5 to 19 samples (provisional bounds)
└─────────┬──────────┘
          │
          ▼
┌────────────────────┐
│       ACTIVE       │ ≥ 20 samples (production evaluation)
└─────────┬──────────┘
          │
     ┌────┴────────────────────────┐
     │                             │
     ▼                             ▼
┌─────────┐                  ┌──────────┐
│  STALE  │ > 30 days idle   │ DEGRADED │ Baseline variance unstable
└─────────┘                  └──────────┘
```

- **Cold-Start Safeguard**: When an entity is in `INSUFFICIENT_DATA` or `LEARNING`, mathematical deviations are observed but **never** emit blocking or false-positive security alerts.
- **Confidence Scoring**: Confidence is mathematically computed from sample volume ($C = \min(1.0, N / 30.0)$), ensuring transparent auditability.

---

## 6. Baseline Poisoning Defense & Learning Quarantine

Adversaries may attempt slow, gradual behavioral drift (creeping baselines) to normalize malicious patterns. CYBERGUARD mitigates this via **Learning Quarantine** (`BehaviorLearningQuarantineModel`):

1. **Shift Detection**: During `LEARNING` or `ACTIVE` states, any sample that diverges by > 4.0 standard deviations from provisional statistics is intercepted.
2. **Quarantine Isolation**: The anomalous observation is segregated into the quarantine queue with status `PENDING` and excluded from baseline calculations.
3. **Analyst Review Workflow**:
   - `APPROVED`: Analyst confirms legitimate business anomaly (e.g., scheduled maintenance); sample is admitted into baseline calculations.
   - `REJECTED`: Analyst flags adversarial action or credential stuffing; sample is permanently excluded, preventing baseline poisoning.
4. **Audited Baseline Rollback**: If a baseline is found to have absorbed compromised telemetry, analysts execute `rollback_baseline`, recording the actor, justification reason, and timestamp in `BaselineAuditModel`.

---

## 7. Deviation Detection & Finding Generation

When an entity profile is `ACTIVE` and an event is evaluated:
1. Active metrics are matched against the entity's baselines (`BehavioralBaselineModel`).
2. `BehavioralStatisticsEngine` computes statistical deviation scores (0.0 to 1.0).
3. If deviation score $\ge 0.65$:
   - **Cooldown Check**: Verifies whether an alert was emitted for this entity/metric within the cooldown window (default: 30 minutes). If within cooldown, deviation is logged but alert dispatch is suppressed.
   - **Deviation Record**: Persists `BehavioralDeviationModel` with exact `observed_value`, `expected_range`, `deviation_score`, and explanation.
   - **Finding Creation**: Generates a unified `FindingModel` with category `BEHAVIORAL` and links observables via `FindingEvidenceModel`.
   - **Risk Integration**: Feeds finding into `RiskEngineService` to elevate tenant and entity risk scores.
   - **Alert Dispatch**: Dispatches `NotificationModel` (`BEHAVIORAL_ANOMALY_ALERT`) for high-severity deviations.
   - **Realtime Broadcast**: Publishes `BEHAVIOR_ANOMALY_DETECTED` over WebSockets.

---

## 8. Background Jobs & Operational Scheduling

Section 60 registers two background jobs in `BackgroundJobWorker`:

1. `BEHAVIORAL_BASELINE_REFRESH` (`JobType.BEHAVIORAL_BASELINE_REFRESH`):
   - Periodically recalculates established entity baselines.
   - Identifies stale profiles (> 30 days without telemetry) and marks them `STALE`.
   - Recalculates statistical variance and marks unstable baselines as `DEGRADED`.
2. `BEHAVIORAL_BATCH_ANOMALY_RUN` (`JobType.BEHAVIORAL_BATCH_ANOMALY_RUN`):
   - Executes offline batch anomaly evaluation across historical event windows.
   - Identifies subtle low-and-slow campaigns that evade real-time per-event thresholds.

---

## 9. Frontend Architecture (`BehavioralAnomalyView`)

The frontend console exposes a rich operational workbench integrated into the Detection Rules space (`src/components/detection/BehavioralAnomalyView.tsx`):

1. **Operational Header & KPI Deck**:
   - Total Monitored Profiles, Active Baselines, Cold-Start Learning Count, Recent Deviations (24h), Quarantined Ingestion Items, Degradation Rate.
2. **Sub-Tab 1: Behavioral Profiles**:
   - Filterable data grid by entity type, lifecycle status, quality status, and text search.
   - Interactive Profile Detail Modal: displays sample count, active baseline ranges, and historical deviation logs.
3. **Sub-Tab 2: Behavioral Anomaly Feed**:
   - Real-time deviation event stream with severity badges, deviation scores, observed vs. expected bounds, and linked finding IDs.
4. **Sub-Tab 3: Poisoning Quarantine Triage**:
   - Interactive review queue for quarantined telemetry.
   - Enables one-click analyst actions: **Approve (Admit to Baseline)** or **Reject & Exclude (Poisoning Defense)** with mandatory analyst justification notes.
5. **Sub-Tab 4: Baseline Lifecycle & Audited Rollback**:
   - Manual recalculation trigger for specific entity scopes.
   - Audited Baseline Rollback card for reverting compromised baseline versions with justification reasons.

---

## 10. Multi-Tenant Security & Access Controls

- **Strict Tenant Isolation**: All behavioral queries and database mutations enforce `workspace_id` filtering at the SQL layer. Cross-tenant baseline leaking is strictly prevented.
- **RBAC Governance**:
  - `Viewer / Analyst`: Can inspect profiles, deviations, and baseline statistics.
  - `SOC Lead / Admin`: Authorized to review learning quarantine items, trigger recalculations, and execute audited baseline rollbacks.
- **Audit Trails**: Every administrative mutation (quarantine resolution, baseline recalculation, baseline rollback) writes an un-falsifiable record to `BaselineAuditModel` and `AuditLogModel`.

---

## 11. Verification & Test Suite

The behavioral detection engine is validated through 16 automated backend test suites in `backend/tests/test_section60_behavioral_detection.py`:

1. `test_feature_extractor_login_hour`: Normalization of login hour metrics.
2. `test_feature_extractor_endpoint_event`: Extraction of process, memory, and command-line features from endpoint telemetry.
3. `test_feature_extractor_normalized_detection_event`: General feature extraction across network and authentication events.
4. `test_profile_lifecycle_insufficient_data`: Cold-start state with < 5 observations.
5. `test_profile_lifecycle_learning`: Provisional state with 5–19 observations.
6. `test_profile_lifecycle_active`: Stable production baseline activation with $\ge 20$ observations.
7. `test_evaluate_event_normal_behavior`: Zero deviation generation when observation falls inside expected bounds.
8. `test_evaluate_event_anomalous_behavior`: Generation of `BehavioralDeviationModel` and `FindingModel` when observation exceeds thresholds.
9. `test_alert_fatigue_cooldown`: Cooldown enforcement preventing duplicate alerts within window.
10. `test_learning_quarantine_extreme_shift`: Automatic quarantine of outlier samples during learning.
11. `test_review_quarantine_approval`: Approval workflow admitting sample into baseline.
12. `test_review_quarantine_rejection`: Rejection workflow excluding sample from baseline.
13. `test_audited_baseline_rollback`: Complete audit trail verification on baseline rollback.
14. `test_refresh_stale_baselines`: Automated transition of idle baselines to `STALE`.
15. `test_api_get_overview_stats`: REST API endpoint returning multi-tenant behavioral KPIs.
16. `test_pipeline_integration_behavioral_evaluation`: End-to-end integration with `UnifiedThreatDetectionPipelineService`.
