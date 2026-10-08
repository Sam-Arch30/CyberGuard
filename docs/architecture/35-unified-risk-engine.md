# Section 26: Unified Risk Engine

## 1. Executive Summary & Purpose

CyberGuard operates across multiple specialized detection pipelines:
- Universal Ingestion and ThreatEvents
- Email and Phishing Intelligence
- URL / Domain Intelligence
- Attachment and File Security Analyzers
- Authentication and Account Takeover Detection
- Network Anomaly Detection
- API Abuse Detection
- Digital Impersonation Detection
- Multimedia and Deepfake Analysis
- Behavioral Baselines and Statistical Deviations (Section 21)
- Novelty Detection and Emerging Pattern Candidates (Section 22)
- Threat Memory Layer (Section 23)
- Emerging Pattern & Candidate Rule Engine (Section 25)
- Security Knowledge Graph, Cross-Incident & Temporal Correlation
- Attack Reconstruction & Attack Path Confidence (Sections 17–18)
- MITRE ATT&CK Mapping (Section 19)
- Infrastructure Attribution (Section 20)

Before Section 26, each detector produced its own diagnostic score (e.g. email threat score, URL risk, anomaly score, or classifier probability). However, no centralized, authoritative layer synthesized these multi-vector signals into a unified, mathematically rigorous assessment.

The **Unified Risk Engine** creates one centralized, deterministic, versioned risk-assessment layer. It:
1. Consumes structured findings and signals from all existing analyzers without replacing detector-local diagnostic scores.
2. Normalizes heterogeneous signal types (probabilities, boolean triggers, counts, severities, anomalies) into canonical continuous values.
3. Groups correlated evidence by shared entities to eliminate duplicate evidence counting and apply controlled correlation discounts.
4. Synthesizes independent evidence families using an asymptotic saturation curve with strict per-family caps.
5. Ingests contextual modifiers (protected identities, critical assets, behavioral deviations, novelty, threat memory, attack paths, MITRE techniques).
6. Rigorously separates **Risk Score**, **Severity**, **Confidence**, **Uncertainty**, **Probability**, and **Novelty**.
7. Enforces immutability and reproducibility through versioned configuration and incremented reassessment lineage ($v1 \to v2 \to v3$).
8. Forbids arbitrary code execution or LLM-derived risk scores.

---

## 2. Core Architecture & Pipeline

```
                     ┌─────────────────────────────┐
                     │     Incoming Telemetry      │
                     │  (Events, Findings, IOCs)   │
                     └──────────────┬──────────────┘
                                    │
                                    ▼
                     ┌─────────────────────────────┐
                     │    Signal Normalization     │
                     │  (Semantics -> 0-100 scale) │
                     └──────────────┬──────────────┘
                                    │
                                    ▼
                     ┌─────────────────────────────┐
                     │ Correlation Grouping &      │
                     │ Diminishing Returns Discount│
                     │ Schedule: [1.0, 0.4, 0.15]  │
                     └──────────────┬──────────────┘
                                    │
                                    ▼
                     ┌─────────────────────────────┐
                     │ Evidence Family Aggregation │
                     │ & Family Caps (Max 20-35)   │
                     └──────────────┬──────────────┘
                                    │
                                    ▼
                     ┌─────────────────────────────┐
                     │ Asymptotic Cross-Family     │
                     │ Non-Linear Combination      │
                     └──────────────┬──────────────┘
                                    │
                                    ▼
                     ┌─────────────────────────────┐
                     │    Contextual Modifiers     │
                     │ (Asset, Identity, Novelty,  │
                     │  Memory, Attack Path, MITRE)│
                     └──────────────┬──────────────┘
                                    │
                                    ▼
                     ┌─────────────────────────────┐
                     │   Counter-Evidence Deduct   │
                     │  (Bounded, No Blind Zero)   │
                     └──────────────┬──────────────┘
                                    │
                                    ▼
                     ┌─────────────────────────────┐
                     │   Metrics Disaggregation    │
                     │  - Risk Score (0-100)       │
                     │  - Risk Level (INFO..CRIT)  │
                     │  - Severity (Impact)        │
                     │  - Confidence (Evidence)    │
                     │  - Uncertainty (Gaps)       │
                     └──────────────┬──────────────┘
                                    │
                                    ▼
                     ┌─────────────────────────────┐
                     │ RiskAssessmentModel v(N)    │
                     │ (Persisted & Immutable)     │
                     └─────────────────────────────┘
```

---

## 3. Epistemic Separation of Concepts

The Unified Risk Engine explicitly separates concepts that naïve systems conflate:

| Concept | Definition | Mathematical Bounds | Independent Driver |
| :--- | :--- | :--- | :--- |
| **Risk Score** | Overall degree of concern and synthesized threat intensity | $0.0 - 100.0$ | Multi-vector evidence saturation + context modifiers |
| **Risk Level** | Categorical alert threshold | `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` | Risk score mapped via centralized thresholds |
| **Severity** | Potential impact or blast radius if the threat is realized | `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` | Affected asset criticality, credential exposure, privileged accounts |
| **Confidence** | Strength and multi-source corroboration of available evidence | $0.10 - 1.0$ | Source reliability, independent families, contradiction penalty |
| **Uncertainty** | Magnitude of missing telemetry, unverified feeds, or conflicts | `LOW`, `MEDIUM`, `HIGH` | Gaps in telemetry, baseline absence, signal contradictions |
| **Probability** | Statistically calibrated likelihood from a validated model | $0.0 - 1.0$ | ML model calibration (not threat score!) |
| **Novelty** | Statistical unfamiliarity relative to historical baselines | $0.0 - 1.0$ | Metric distance (unfamiliar $\ne$ malicious!) |

### Key Epistemic Invariants:
1. $\text{Severity} \ne \text{Confidence}$: An unverified allegation of root compromise has `CRITICAL` severity but `LOW` confidence. A verified benign tracking pixel has `SAFE` severity and `VERY_HIGH` confidence ($0.99$).
2. $\text{Confidence} \ne \text{Risk Score}$: A high-risk event based on a single unverified heuristic has high risk ($75.0$) but low confidence ($0.35$).
3. $\text{Novelty} \ne \text{Threat}$: A brand new internal API endpoint or domain has high novelty ($0.95$), but without corroborating threat signals, novelty contributes **$0.0$ points**.

---

## 4. Signal Normalization Layer

Different detectors yield disparate data types. The `SignalNormalizer` converts inputs into a standardized format:

```python
{
    "signal_type": "URL_PHISHING_REPUTATION",
    "source_type": "EXTERNAL_INTEL",
    "detector_id": "url_domain_intel",
    "detector_version": "1.0.0",
    "evidence_family": "URL",
    "semantics": "THREAT_SCORE",
    "direction": "SUPPORTING",
    "raw_score": 85.0,
    "normalized_score": 85.0,
    "reliability": 0.80,
    "weight": 1.0,
    "correlation_group": "URL:https://login.example.com",
    "evidence_refs": ["EVD-URL-001"],
    "provenance": {...}
}
```

### Semantic Mappings:
- **`THREAT_SCORE`**: $0.0 - 1.0 \implies \times 100.0$; $0.0 - 100.0 \implies \text{clamped}$.
- **`PROBABILITY`**: $\text{clamp}(0.0, 1.0) \times 100.0$.
- **`SEVERITY`**: Categorical mapping: `SAFE/INFO` $\to 0.0$, `LOW` $\to 25.0$, `MEDIUM` $\to 50.0$, `HIGH` $\to 75.0$, `CRITICAL` $\to 100.0$.
- **`BOOLEAN_INDICATOR`**: `True` $\to 100.0$, `False` $\to 0.0$.
- **`ANOMALY_SCORE`**: $\text{clamp}(0.0, 1.0) \times 100.0$.
- **`NOVELTY`**: Metric distance ($0.0 - 100.0$), routed to conditional contextual evaluation.
- **`COUNT`**: Scaled $\min(100.0, \text{count} \times 10.0)$.
- **`DISTANCE`**: Scaled $\min(100.0, \text{distance} \times 50.0)$.

---

## 5. Evidence Independence & Correlation Discounting

When multiple detectors discover findings relating to the same underlying artifact (e.g. four detectors analyzing the exact same URL), treating them as independent produces artificial score inflation.

### Diminishing Returns Schedule:
Signals are grouped by `(evidence_family, correlation_group, direction)` and sorted descending by baseline impact:
$$\text{Base Impact} = \text{normalized\_score} \times \text{reliability} \times \text{weight}$$

The discount schedule applies:
$$\text{Schedule} = [1.0, 0.40, 0.15, 0.05]$$

- **Rank 0 (1st Signal)**: Multiplier $= 1.0$ (100% weight)
- **Rank 1 (2nd Signal)**: Multiplier $= 0.40$ (40% incremental weight)
- **Rank 2 (3rd Signal)**: Multiplier $= 0.15$ (15% incremental weight)
- **Rank 3+ (Subsequent Signals)**: Multiplier $= 0.05$ (5% marginal weight)

Signals across **different correlation groups** (e.g. `URL:login.example.com` vs `FILE:hash123` vs `AUTH:user@corp.com`) receive their full independent primary weights.

---

## 6. Family Capping & Asymptotic Aggregation

### Evidence Families & Caps:
Each evidence family has a strict point cap defined in `risk_configuration.json`:
- `URL`: $35.0$
- `FILE`: $35.0$
- `AUTHENTICATION`: $35.0$
- `NETWORK`: $35.0$
- `API`: $30.0$
- `RULE_DETECTION`: $30.0$
- `IDENTITY`: $25.0$
- `CONTENT`: $25.0$
- `MULTIMEDIA`: $25.0$
- `BEHAVIOR`: $20.0$
- `INFRASTRUCTURE`: $20.0$
- `TEMPORAL`: $20.0$
- `GRAPH`: $20.0$
- `HISTORICAL`: $15.0$
- `NOVELTY`: $15.0$

### Asymptotic Non-Linear Combination:
To combine capped net family scores without linear inflation:
$$\text{Base Aggregated Risk} = 100 \times \left(1.0 - \prod_{f \in \text{families}} \left(1.0 - \frac{\text{net\_family}_f}{100.0}\right)\right)$$

This formula ensures:
1. Strictly bounded in $[0.0, 100.0]$.
2. Multi-vector corroboration (e.g. Phishing URL + Malicious Attachment + Anomalous Auth) asymptotically increases risk smoothly.
3. No single family can exceed its cap or force an overall verdict alone.

---

## 7. Contextual Risk Modifiers

Context modifies base risk transparently:

1. **Privileged Account / Protected Identity**: $+10.0$ points when an executive, admin, or service account is targeted.
2. **Critical Asset**: $+10.0$ points when a production database, domain controller, or payment gateway is affected.
3. **Behavioral Deviation (Section 21)**: $+8.0$ points for high deviation ($\ge 0.70$); $+4.0$ points for moderate deviation ($\ge 0.40$).
4. **Novelty Context (Section 22)**:
   - If base risk $< 25.0$: Novelty adds **$0.0$ points** (prevents flagging benign new behavior).
   - If base risk $\ge 25.0$ and novelty $\ge 0.70$: Novelty adds $+6.0$ points as corroboration.
5. **Threat Memory Context (Section 23)**:
   - Fresh / verified historical match adds $+8.0$ points.
   - Expired or dismissed memories add **$0.0$ points**.
6. **Attack Path Continuity (Sections 17–18)**:
   - Multi-stage sequential attack progression adds $+10.0 \times \text{AttackPathConfidence}$.
7. **MITRE ATT&CK Mappings (Section 19)**:
   - `SUPPORTED` mappings add $+4.0$ points each (capped at $+10.0$).
   - `PLAUSIBLE` mappings add $+2.0$ points each.
   - `INSUFFICIENT_EVIDENCE` or `REJECTED` add **$0.0$ points**.
8. **Counter-Evidence Mitigation**:
   - Explicit counter-evidence (e.g. valid cryptographic DKIM, corporate managed device) deducts up to $20.0$ points.
   - Absence of evidence is **NOT** counter-evidence!

---

## 8. Multi-Source Confidence Calculation

$$\text{Base Confidence} = \frac{\sum_{s \in \text{signals}} s.\text{reliability} \times s.\text{weight}}{\sum_{s \in \text{signals}} s.\text{weight}}$$

Adjustments:
- **Corroboration Bonus**: $+0.05$ per distinct evidence family beyond 1 (up to $+0.15$).
- **Cryptographic Provenance**: $+0.05$ for cryptographic or static hash verification.
- **Contradiction Penalty**: $-0.15 \times \text{contradiction\_count}$ (up to $-0.30$).
- Bounded to $[0.10, 1.00]$.

---

## 9. Explicit Uncertainty Representation

Uncertainty evaluates:
- Missing telemetry feeds (e.g. absent headers, offline host agent).
- Lack of behavioral baselines.
- Presence of low-reliability third-party intelligence.
- Signal contradictions.

$$\text{Uncertainty Score} = 0.40 \times (1.0 - \text{confidence}) + 0.30 \times \text{contradictions} + 0.30 \times \text{telemetry\_gaps}$$

- $< 0.35 \implies \text{LOW}$
- $0.35 - 0.65 \implies \text{MEDIUM}$
- $> 0.65 \implies \text{HIGH}$

---

## 10. Risk Scopes & Aggregation Semantics

### EVENT Scope
- Evaluates individual `ThreatEventModel`.
- Combines event telemetry, linked findings, and evidence items.
- Sets `ThreatEventModel.risk_assessment_id`, `risk_score`, `severity`, and `confidence`.

### INVESTIGATION Scope
- Evaluates an investigation scope across multiple events and entities.
- Aggregation semantics:
  - Peak event risk accounts for $60\%$ of base.
  - Cross-event evidence family diversity adds points.
  - Multi-stage attack path progression adds points.
  - Entity blast radius adds points.
  - **NOT** an arithmetic average!

### INCIDENT Scope
- Evaluates an `IncidentModel` container.
- Considers confirmed malicious activity, attack paths, affected infrastructure clusters, and response containment status.

---

## 11. Determinism, Immutability & Reassessment

1. **Pure Determinism**: Re-evaluating identical inputs with the same configuration produces 100% identical risk, severity, confidence, and uncertainty values.
2. **Reassessment Lineage**: When new evidence arrives for an assessment:
   - The prior `RiskAssessmentModel` record is marked `status = "SUPERSEDED"`.
   - A new record is created with incremented version $v(N+1)$, referencing `parent_assessment_id`.
   - Complete audit trail of `reassessment_reason` and evaluated timestamp is preserved.

---

## 12. End-to-End Walkthrough Example

### Synthetic Scenario:
An email arrives containing a link to `https://login.example-secure.com/auth`.

1. **Signals Ingested**:
   - `URL_LOOKALIKE`: Score 85, Family `URL`, Correlation `URL:example-secure.com`.
   - `CREDENTIAL_FORM`: Score 90, Family `URL`, Correlation `URL:example-secure.com`.
   - `REDIRECT_CHAIN`: Score 60, Family `URL`, Correlation `URL:example-secure.com`.
   - `EXECUTIVE_IMPERSONATION`: Score 80, Family `IDENTITY`, Correlation `USER:ceo@example.com`.
   - `THREAT_MEMORY_MATCH`: Score 75, Family `HISTORICAL`, Correlation `IOC:example-secure.com`.
   - `VALID_DKIM`: Score 40, Family `CONTENT`, Direction `COUNTER`.

2. **Deduplication & Discounting**:
   - In `URL:example-secure.com`:
     - 1st (`CREDENTIAL_FORM`): $90 \times 1.0 \times 1.0 \implies 90.0$
     - 2nd (`URL_LOOKALIKE`): $85 \times 0.40 \implies 34.0$
     - 3rd (`REDIRECT_CHAIN`): $60 \times 0.15 \implies 9.0$
     - Gross URL sum $= 133.0 \implies$ Capped at URL family cap $= 35.0$.

3. **Multi-Vector Cross-Family Combination**:
   - `URL` net $= 35.0$
   - `IDENTITY` net $= 20.0$
   - `HISTORICAL` net $= 12.0$
   - Cross-Family Base $= 100 \times (1 - (1 - 0.35)(1 - 0.20)(1 - 0.12)) = 54.24$.

4. **Contextual Modifiers**:
   - Privileged executive targeted: $+10.0$.
   - Threat memory recurrence: $+8.0$.
   - Valid DKIM mitigation: $-5.0$.
   - Final Risk Score: $\approx 67.24 \implies \text{HIGH Risk (67/100)}$.

5. **Disaggregated Outputs**:
   - Risk Level: `HIGH`
   - Severity: `HIGH` (Executive target & credential harvesting form)
   - Confidence: `0.88` (`VERY_HIGH` due to 3 independent corroborating families)
   - Uncertainty: `LOW` ($0.18$)

---

## 13. REST API Reference

| Method | Endpoint | Description | Role Required |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/risk/assessments/{id}` | Retrieve risk assessment by ID | Any |
| `GET` | `/api/v1/risk/assessments/{id}/history` | Retrieve full version history | Any |
| `GET` | `/api/v1/risk/assessments/{id}/breakdown` | Retrieve component contributors | Any |
| `GET` | `/api/v1/risk/assessments/{id}/explanation` | Retrieve structured explanation | Any |
| `POST` | `/api/v1/risk/evaluate` | Evaluate risk for scope or signals | Analyst |
| `POST` | `/api/v1/risk/reassess/{id}` | Trigger deterministic reassessment | Analyst |
| `GET` | `/api/v1/risk/config` | Retrieve active risk configuration | Any |
| `POST` | `/api/v1/risk/config` | Update versioned configuration | **Admin** |
| `GET` | `/api/v1/risk/dashboard/stats` | Executive risk statistics | Any |
