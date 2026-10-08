# 34 — Emerging Pattern & Candidate Rule Engine Architecture

## 1. Executive Summary & Purpose

Section 25 implements the **Emerging Pattern & Candidate Rule Engine** for CyberGuard. While Section 22 detects novelty (*"This behavior or sequence is technically unfamiliar"*) and Section 23 maintains persistent Threat Memory (*"We have observed related observations across investigations"*), Section 25 establishes a controlled, verifiable bridge that translates recurring, validated emerging threats into formalized, testable detection rules.

### Core Architectural Epistemic Boundary
$$\text{PATTERN} \ne \text{RULE}$$
$$\text{RULE} \ne \text{APPROVED RULE}$$
$$\text{APPROVED RULE} \ne \text{PRODUCTION RULE}$$

A novel observation or emerging pattern candidate **never** autonomously modifies or deploys production detection logic. Every candidate rule must progress through a rigorous verification pipeline:
$$\text{DISCOVER} \longrightarrow \text{FORMALIZE} \longrightarrow \text{VALIDATE} \longrightarrow \text{BACKTEST} \longrightarrow \text{FP ANALYSIS} \longrightarrow \text{HUMAN REVIEW} \longrightarrow \text{APPROVED} \longrightarrow \text{STAGED (SHADOW)} \longrightarrow \text{ACTIVE}$$

---

## 2. Core Architecture

```mermaid
graph TD
    subgraph "Observation & Novelty (Sec 22 & 23)"
        Obs[Telemetry Observation] --> Nov[Novelty Detection Engine]
        Nov --> EPC[EmergingPatternCandidate]
        TM[Threat Memory Context] --> EPC
    end

    subgraph "Candidate Rule Engine (Sec 25)"
        EPC --> Gen[Pattern-to-Rule Generator]
        Gen --> Norm[Rule Normalizer & Canonical Fingerprinter]
        Norm --> Val[Rule DSL Validator & Budget Checker]
        Val --> Cand[CandidateRuleModel (DRAFT / DISCOVERED)]
        Cand --> Backtest[Historical Backtester]
        Backtest --> QR[Rule Quality & FP Report]
        QR --> Review[Security Engineer Review Queue]
    end

    subgraph "Deployment & Lifecycle"
        Review -->|Approved| Staged[STAGED: Shadow Mode Execution]
        Review -->|Rejected| Rej[REJECTED]
        Staged --> Telemetry[Shadow Execution Telemetry]
        Telemetry --> Prom[Production Promotion Gate]
        Prom --> Active[ACTIVE Production Detection]
        Active --> Firing[ThreatEvent / Finding Emission]
        Active --> Ret[DISABLED / RETIRED / SUPERSEDED]
    end
```

---

## 3. Candidate Rule Lifecycle State Machine

A candidate rule progresses through explicit, deterministic lifecycle states:

| State | Scope | Description |
|---|---|---|
| `DISCOVERED` | Candidate | Initial automated formulation from `EmergingPatternCandidate` or recurring Threat Memory clusters. |
| `DRAFT` | Candidate | Manual or automated parameter adjustments (thresholds, condition combinations). |
| `VALIDATING` | Candidate | Syntactic validation, operator schema verification, and complexity budget evaluation. |
| `TESTED` | Candidate | Historical backtesting completed; false positive and precision metrics computed. |
| `REVIEW_REQUIRED` | Review | Queued for SOC Lead or Detection Engineering review. |
| `APPROVED` | Approved | Formally signed off by authorized reviewer. Ineligible for live alerts until staged/activated. |
| `STAGED` | Pre-Production | **Shadow Mode**: Evaluates incoming events in live traffic, recording execution telemetry without firing alerts. |
| `ACTIVE` | Production | Live production detection: fires standardized `ThreatEvent` and `Finding` objects upon match. |
| `REJECTED` | Terminated | Discarded during review due to high noise, over-generalization, or insufficient evidence. |
| `DISABLED` | Quarantined | Temporarily halted from execution due to environmental drift or false alarm spike. |
| `RETIRED` | Archived | Permanently retired due to obsolescence. Preserved for retrospective forensic reproducibility. |
| `SUPERSEDED` | Versioned | Replaced by a newer version (e.g., `v1` superseded by `v2`). |

---

## 4. Rule DSL & Safe Execution Boundary

### Zero Arbitrary Code Execution
CyberGuard rules **never** execute raw Python, JavaScript, SQL, or shell code. Rules are declared exclusively as structured JSON schemas conforming to a bounded Domain Specific Language (DSL).

### Supported DSL Operators
- **Value Equality & Comparison**: `eq`, `neq`, `gt`, `gte`, `lt`, `lte`.
- **String & Token Matching**: `contains`, `not_contains`, `starts_with`, `ends_with`, `in`, `not_in`, `exists`, `not_exists`.
- **Safe Regex**: `regex` (bounded execution, max 128 characters, ReDoS heuristics).
- **Semantic Similarity**: `similarity_gte` (character & token distance comparison against claimed targets).
- **Collection Bounds**: `count_gte`, `count_lte`.
- **Temporal Sequences**: `FOLLOWED_BY`, `PRECEDED_BY`, `WITHIN` (relative time windows).
- **Graph Topology**: `CONNECTED_TO`, `RESOLVES_TO`, `ASSOCIATED_WITH`, `SHARES_INFRASTRUCTURE`.

### Computational Complexity Budgets
To protect against resource exhaustion or denial-of-service:
- Maximum conditions per rule: 20
- Maximum complexity score: 25.0 (atomic condition = 1.0, regex = 2.0, temporal = 2.5, graph = 3.0)
- Maximum regex eval string length: 4,096 characters
- Execution timeout: 100ms per evaluation

---

## 5. Pattern Generalization vs. Overfitting

The engine guards against naive value memorization:
- **Bad Formulation (Overfitting)**: `domain == "evil-phish-portal.com"` (catches only the single observed sample).
- **Good Formulation (Structural Generalization)**:
  $$\text{url.path contains 'login'} \ \land \ \text{domain\_similarity} \ge 0.85 \ \land \ \text{redirect\_param exists}$$
  Catches recurring attack techniques even when adversary rotates domains or IP addresses.
- **Over-Generalization Protection**: Backtesting verifies that structural criteria do not inadvertently trigger on authorized corporate portals or internal SSO migrations.

---

## 6. Historical Backtesting & Ground-Truth Discipline

Candidate rules are evaluated against retained historical telemetry (`ThreatEventModel`, `FindingModel`, `SecurityEventModel`).

### Epistemic Ground Truth Separation
1. **Verified Malicious**: Ground truth from Threat Memory (`CONFIRMED_MALICIOUS`) matched by rule $\to$ **True Positive (TP)**.
2. **Verified Benign**: Ground truth from Threat Memory (`CONFIRMED_BENIGN`, `FALSE_POSITIVE`) matched by rule $\to$ **False Positive (FP)**.
3. **Unlabeled / Unverified**: Historical records lacking human validation matched by rule $\to$ **Unknown**.
   - **Crucial Rule**: Unlabeled events are **NEVER** assumed to be True Negatives. Recall is computed exclusively over the verified population, avoiding fabricated metrics.

---

## 7. Shadow Mode (Canary Staging)

Before any rule activates in production, it operates in `STAGED` shadow mode:
- Live events and telemetry pass through the rule evaluator.
- Matches are recorded in `CandidateRuleExecutionModel` (`mode="SHADOW"`).
- **Zero Production Disruption**: No `ThreatEvent` is dispatched, no SOC alerts are triggered, and no incident workflows are spawned.
- Allows detection engineers to verify empirical false positive rates on real live traffic before deployment.

---

## 8. Immutable Versioning & Provenance

When an active or approved rule requires adjustment (e.g., tightening a similarity threshold):
1. The existing version (e.g., `v1`) remains immutable in `candidate_rule_versions`.
2. A new version record (`v2`) is created with an audit trail citing `change_reason` and `editor`.
3. The parent `CandidateRuleModel` increments its version tag and re-enters the review/validation pipeline.
4. Historical analysis runs that referenced `v1` retain exact, reproducible forensic linkage.

---

## 9. Rule Firing vs. Response Boundary

When an `ACTIVE` rule matches live telemetry:
- It produces a standardized `ThreatEventModel` with `event_type="ACTIVE_RULE_DETECTION"`, structured matched conditions, and references to `rule_id` and `rule_version`.
- **Strict Boundary**: Candidate rules **never** autonomously execute destructive response actions (e.g., disabling user accounts, blocking IP firewalls, or deleting files). Response actions remain reserved for Section 27 (Response Playbook Engine) under human governance.

---

## 10. API Specification

The Candidate Rule Engine exposes REST endpoints mounted at `/api/v1/rule-candidates` and `/api/v1/rules`:

| Endpoint | Method | Role | Description |
|---|---|---|---|
| `/api/v1/rule-candidates` | GET | `ANALYST` | List candidate rules filtered by type, status, scope. |
| `/api/v1/rule-candidates` | POST | `ANALYST` | Manually formulate a candidate rule. |
| `/api/v1/rule-candidates/from-pattern` | POST | `ANALYST` | Synthesize candidate rule from `EmergingPatternCandidate`. |
| `/api/v1/rule-candidates/{id}` | GET | `ANALYST` | Fetch candidate rule details and current status. |
| `/api/v1/rule-candidates/{id}/backtest` | POST | `ANALYST` | Run historical backtest against retained telemetry. |
| `/api/v1/rule-candidates/{id}/submit-review` | POST | `ANALYST` | Submit tested candidate rule for approval. |
| `/api/v1/rule-candidates/{id}/approve` | POST | `ADMIN` / `LEAD` | Formally approve candidate rule. |
| `/api/v1/rule-candidates/{id}/reject` | POST | `ADMIN` / `LEAD` | Reject candidate rule with audit justification. |
| `/api/v1/rules` | GET | `ANALYST` | List active, staged, and approved rules. |
| `/api/v1/rules/{id}` | GET | `ANALYST` | Fetch rule details and metadata. |
| `/api/v1/rules/{id}/versions` | GET | `ANALYST` | Retrieve immutable version history. |
| `/api/v1/rules/{id}/stage` | POST | `ADMIN` | Place rule in shadow mode staging. |
| `/api/v1/rules/{id}/activate` | POST | `ADMIN` | Promote staged rule to active production detection. |
| `/api/v1/rules/{id}/disable` | POST | `ADMIN` | Temporarily disable an active rule. |
| `/api/v1/rules/{id}/retire` | POST | `ADMIN` | Permanently retire an obsolete rule. |
| `/api/v1/rules/{id}/edit` | POST | `ANALYST` | Generate a new version (`v1` $\to$ `v2`) with modified logic. |
| `/api/v1/rules/evaluate` | POST | `ANALYST` | Evaluate rules against target event or test context. |
| `/api/v1/rules/dashboard/stats` | GET | `ANALYST` | Retrieve executive metrics and shadow evaluation counts. |

---

## 11. Verification & Benchmark Results

Section 25 is verified across 15 unit, scenario, and API test suites:
- `backend/tests/test_candidate_rules.py` (10 unit tests):
  - Safe DSL validation and computational complexity bounds
  - ReDoS catastrophic backtracking rejection
  - Canonical condition sorting and deterministic fingerprint deduplication
  - Runtime operator evaluation (numeric, string, similarity, regex)
  - Emerging pattern to candidate rule synthesis
  - Ground-truth aware backtesting (unknowns separated from true negatives)
  - Complete lifecycle state machine transitions
  - Immutable versioning on rule edit
  - Shadow mode execution telemetry vs active ThreatEvent emission
  - Rule disablement and retirement
- `backend/tests/test_candidate_rules_scenarios.py` (1 scenario test):
  - Section 60 complete end-to-end lifecycle from emerging URL pattern to shadow mode, production activation, ThreatEvent firing, and threshold tuning (`v1` $\to$ `v2`).
- `backend/tests/test_candidate_rules_api.py` (4 API tests):
  - Rule creation, listing, and filtering
  - Role-based authorization enforcement (HTTP 403 on unprivileged roles)
  - Pattern synthesis and backtest endpoints
  - Full lifecycle execution and executive dashboard stats
