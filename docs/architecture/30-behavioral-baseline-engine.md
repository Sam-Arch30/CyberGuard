# Section 21 — Behavioral Baseline & Anomaly Detection Engine

## 1. Objective

The **Behavioral Baseline Engine** enables CyberGuard to learn normal behavioral patterns for authorized users, accounts, devices, services, network endpoints, and APIs from historical telemetry, and to detect meaningful, statistically rigorous deviations from those entity-specific baselines.

The engine answers the foundational forensic question:
> **“Is this behavior unusual for this specific entity compared with its own historical behavior?”**
> *(rather than simply “Is this behavior unusual globally?”)*

Crucially, CyberGuard establishes the strict epistemic boundary:
```
behavior deviation
        ↓
contextual exception checks
        ↓
independent evidence corroboration
        ↓
finding
        ↓
confidence scoring
        ↓
threat assessment
```

A baseline anomaly is **objective technical evidence**, not a verdict of compromise or account takeover.

---

## 2. System Architecture

```mermaid
flowchart TD
    subgraph TelemetrySources["Authorized Telemetry Projection (Section 16)"]
        SE[SecurityEventModel / Normalized Events]
        AE[NormalizedAuthEvent]
        NE[NormalizedNetworkEvent]
        APIE[NormalizedAPIEvent]
    end

    subgraph PrivacyFilter["Privacy & Redaction Layer"]
        PR[Secret Redactor<br/>Disallow Passwords / Tokens / Keys]
    end

    subgraph FeatureExtraction["Behavioral Feature Extractor"]
        BFE[BehavioralFeatureExtractor<br/>Extract LOGIN_HOUR, IP, Device, Rate, Volume]
    end

    subgraph PoisoningGuard["Baseline Poisoning & Contamination Guard"]
        BPG[BaselinePoisoningGuard<br/>Filter Confirmed Malicious / Quarantined / Threat Events]
    end

    subgraph StatisticsEngine["Robust Statistics Engine"]
        RSE[BehavioralStatisticsEngine<br/>Median, MAD, Winsorization, Percentiles<br/>Circular Hour Wrap-Around (0-23h)]
    end

    subgraph BaselineStorage["Persistent Baseline Storage"]
        BBM[(BehavioralBaselineModel<br/>Quality: STABLE, DEVELOPING, INSUFFICIENT)]
        BAL[(BaselineAuditModel<br/>FREEZE, UNFREEZE, RELEARN)]
    end

    subgraph ContextExceptions["Context & Exception Manager"]
        BCM[BaselineContextManager<br/>Service Accounts 24/7<br/>Admin Privilege Context<br/>Authorized Exceptions]
    end

    subgraph EvaluationEngine["Deviation Scoring Engine"]
        BBS[BehavioralBaselineService<br/>evaluate_deviation]
        BDM[(BehavioralDeviationModel)]
    end

    SE --> PrivacyFilter
    AE --> PrivacyFilter
    NE --> PrivacyFilter
    APIE --> PrivacyFilter

    PrivacyFilter --> BFE
    BFE --> BPG
    BPG --> RSE
    RSE --> BBM
    BBM --> BBS
    BCM --> BBS
    BBS --> BDM
```

---

## 3. Entity Model & Baseline Granularity

The engine provides a uniform, reusable baseline architecture across all entity types:

| Entity Type | Example Metrics Tracked | Contextual Policy |
| :--- | :--- | :--- |
| `USER` | `LOGIN_HOUR`, `LOGIN_DAY_PATTERN`, `LOGIN_LOCATION`, `AUTH_METHOD` | Human work-hour schedules; impossible travel evaluation. |
| `ACCOUNT` | `LOGIN_FREQUENCY`, `AUTH_FAILURE_RATE`, `LOGIN_SOURCE_IP`, `LOGIN_DEVICE` | Known devices, IP CIDRs, MFA patterns. |
| `DEVICE` | `NETWORK_DESTINATION_FREQUENCY`, `NETWORK_PORT_FREQUENCY`, `OUTBOUND_BYTES` | Known outbound gateways, DNS lookup patterns. |
| `SERVICE` | `API_REQUEST_RATE`, `API_RESPONSE_VOLUME`, `API_ENDPOINT_FREQUENCY` | High throughput, 24/7 continuous operation. |
| `API_CLIENT` | `API_ENDPOINT_FREQUENCY`, `API_METHOD_FREQUENCY`, `API_REQUEST_RATE` | Endpoint access spread, token usage consistency. |
| `NETWORK_ENTITY` | `CONNECTION_FREQUENCY`, `OUTBOUND_BYTES`, `INBOUND_BYTES`, `DNS_QUERY_FREQUENCY` | Traffic baseline, beaconing detection context. |

---

## 4. Normalized Baseline Model

Persisted in `behavioral_baselines` (`BehavioralBaselineModel`):
- `id`: Unique baseline UUID.
- `workspace_id`: Tenant workspace isolation.
- `entity_type` & `entity_id`: Stable identifier (lowercase email, username, device GUID).
- `entity_category`: `HUMAN_USER`, `SERVICE_ACCOUNT`, `APPLICATION`, `DEVICE`, `SYSTEM`, `ADMINISTRATOR`.
- `metric_type`: Controlled metric vocabulary.
- `window_type`: `ROLLING_7D`, `ROLLING_14D`, `ROLLING_30D`, `ROLLING_60D`, `ROLLING_90D`.
- `sample_count` & `valid_sample_count`: Total clean observations.
- `missing_sample_count`: Contaminated or dropped observations.
- `median_value`, `mad_value`, `percentiles_json`: Robust central tendency and dispersion.
- `distribution_json`: Categorical histogram or circular hourly distribution.
- `quality_status`: `NO_DATA`, `INSUFFICIENT_HISTORY`, `LOW_QUALITY`, `DEVELOPING`, `STABLE`, `STALE`, `DEGRADED`.
- `learning_mode`: `LEARNING`, `STABLE`, `RELEARNING`, `FROZEN`, `DEGRADED`.
- `is_frozen`: Security hold during active investigations.
- `baseline_version`, `feature_version`, `calculation_method`: Lineage stamps.

---

## 5. Robust Statistics & Circular Modeling

### 5.1 Median Absolute Deviation (MAD)
Rather than uncalibrated standard deviations skewed by extreme spikes, numerical metrics use Median Absolute Deviation:
$$\text{MAD} = \text{median}\left(|x_i - \text{median}(X)|\right)$$
Modified Z-Score:
$$M_i = \frac{0.6745 \cdot |x_i - \text{median}(X)|}{\text{MAD} + \epsilon}$$
Bounded deviation score:
$$\text{score} = 1.0 - e^{-0.35 \cdot \max(0, M_i - 2.0)}$$

### 5.2 Circular Time-of-Day Distance
Hours on a 24-hour clock wrap across midnight. The circular distance is computed as:
$$d(h_1, h_2) = \min(|h_1 - h_2|, 24.0 - |h_1 - h_2|)$$
Example: A login at 23:00 and another at 01:00 are $2.0$ hours apart, not $22.0$ hours apart.

### 5.3 Categorical Novelty & Frequency
Categorical observations (devices, source IPs, API endpoints) are scored by historical frequency:
- High frequency ($\ge 15\%$): Normal ($\text{score} = 0.0$).
- Low frequency ($5\% - 15\%$): Mild novelty ($\text{score} = 0.25$).
- Unseen category: Scored proportionally to entity stability ($\text{score} = 0.45 - 0.85$, direction `NEW`).

---

## 6. Baseline Poisoning & Contamination Guard

To prevent adversaries from gradually training CyberGuard to accept malicious activity as normal:
1. **Exclusion Categories**:
   - `CONFIRMED_MALICIOUS`
   - `KNOWN_ATTACK_ACTIVITY`
   - `HIGH_CONFIDENCE_ANOMALY`
   - `ANALYST_MARKED_MALICIOUS`
   - `QUARANTINED_ACTIVITY`
2. **Threat Linkage**: Any telemetry event linked to active `ThreatEventModel` or High/Critical `FindingModel` is excluded from baseline sample accumulation.
3. **Investigation Hold (`is_frozen`)**: Analysts or automated incident playbooks can freeze an account's baseline during an active investigation, preventing ongoing attack actions from altering the baseline.

---

## 7. Contextual Profiles & Exceptions

### 7.1 Service Accounts
Entities matching service account patterns (`svc_*`, `*_daemon`, `*@serviceaccount.com`, or flagged `is_service_account=True`):
- Operating 24/7 or overnight does not trigger `UNUSUAL_LOGIN_TIME` alerts.
- Burst request rates receive machine-execution calibration.

### 7.2 Contextual Exceptions
Auditable exception records (`BaselineException`):
- Maintenance windows, approved foreign travel, authorized penetration testing, and corporate VPN changes.
- Automatically suppress or downgrade deviation scores while recording the approval rationale and expiration timestamp.

---

## 8. Privacy Hard Guardrails

**Strict Privacy Rule**: Raw passwords, session secrets, API keys, cookies, MFA tokens, or raw authorization headers are **never** used or persisted as behavioral features.
- Validated at schema creation via `validate_feature_privacy`.
- Only sanitized identifiers, categorical hashes, or normalized metadata are retained.

---

## 9. REST API Contracts

Mounted under `/api/v1` in `backend/api/routes/behavioral_baseline.py`:
- `GET /api/v1/entities/{entity_type}/{entity_id}/baseline` — Query established baselines.
- `GET /api/v1/entities/{entity_type}/{entity_id}/baseline/history` — Lifecycle audit log.
- `POST /api/v1/entities/{entity_type}/{entity_id}/baseline/freeze` — Freeze during incident.
- `POST /api/v1/entities/{entity_type}/{entity_id}/baseline/unfreeze` — Unfreeze after containment.
- `POST /api/v1/entities/{entity_type}/{entity_id}/baseline/relearn` — Trigger adaptive relearning.
- `POST /api/v1/entities/{entity_type}/{entity_id}/exceptions` — Register authorized exception.
- `GET /api/v1/investigations/{investigation_id}/behavioral-deviations` — Retrieve investigation deviations.
- `POST /api/v1/baselines/evaluate-deviation` — Runtime deviation assessment endpoint.

---

## 10. Verification & Test Coverage

The engine is verified by 26 automated unit, boundary, API, and benchmark tests:
- `backend/tests/test_behavioral_baseline.py`: 13 core tests (zero events, insufficient history, stable creation, robust stats, circular hours, categorical novelty, poisoning protection, frozen states, service accounts, exceptions, Hero synthetic scenario).
- `backend/tests/test_behavioral_baseline_boundaries.py`: 4 boundary tests (credential rejection, non-alarmist phrasing, reproducibility).
- `backend/tests/test_behavioral_baseline_api.py`: 6 REST API route integration tests.
- `backend/tests/test_behavioral_performance.py`: 3 performance tests (1,000-event extraction < 100ms, sub-millisecond cache retrieval, bounded queries).
