# Architecture Document 37: Section 28 — Response Recommendation Engine

## 1. Executive Summary & Purpose

The **Response Recommendation Engine** transforms CyberGuard's multi-layered detection, analysis, risk assessment (Section 26), and explainability outputs (Section 27) into structured, prioritized, actionable defensive recommendations for security analysts.

```
Detection (Engines 15-22)
    ↓
Analysis & Attack Reconstruction (Engines 23-26)
    ↓
Unified Risk Assessment (Section 26)
    ↓
Explainable AI (Section 27)
    ↓
Response Recommendation Engine (Section 28)
    ↓
Human Review / Approval Boundary
    ↓
Future Response Playbooks (Section 29)
```

### The Cardinal Safety Principle
> **CyberGuard may recommend an action automatically, but it must not silently perform consequential security actions.**

Section 28 creates the **advisory recommendation layer**. It provides deterministic, evidence-grounded proposals answering:
*"Given what CyberGuard knows right now, what should a human defender consider doing next?"*

Direct execution (disabling accounts, resetting passwords, isolating workstations, blocking domains/IPs, deleting files) is strictly forbidden in this section and belongs behind an explicit approval boundary dispatched to Section 29 Playbooks.

---

## 2. Architecture & Pipeline

The recommendation engine executes through a deterministic, eight-stage pipeline:

```
[RiskAssessment + Explanation + Evidence + AttackPath + Incident Context + Capabilities]
                                  ↓
                  1. Candidate Action Generation
                                  ↓
                  2. Applicability & Safety Filtering
                                  ↓
                  3. Capability Validation
                                  ↓
                  4. Evidence-Grounding Verification
                                  ↓
                  5. Deduplication & Conflict Detection
                                  ↓
                  6. Priority & Urgency Calculation
                                  ↓
                  7. Dependency Sequencing (Preservation First)
                                  ↓
                  8. Validation & Persistence
                                  ↓
                      ResponseRecommendation[]
```

1. **Candidate Generation**: Evaluates findings, threat score, indicators, authentication anomalies, and MITRE techniques to generate candidate actions across six functional categories.
2. **Applicability Filtering**: Suppresses or marks `NOT_APPLICABLE` any recommendation whose required target entities (e.g. endpoint host, compromised account, domain) are absent from evidence.
3. **Capability Validation**: Consults the `ResponseCapabilityModel` registry. Actions lacking enabled integrations are flagged `REQUIRES_CONFIGURATION` or `NOT_READY`.
4. **Evidence Grounding**: Consequential actions (`CONTAINMENT`, `HIGH_IMPACT`, `DESTRUCTIVE`) are verified to have at least one explicit evidence reference (`evidence_refs`).
5. **Deduplication & Conflict Detection**: Identifies opposing recommendations (e.g. `DISABLE_ACCOUNT` vs. active honeypot monitoring) and records explicit trade-off explanations.
6. **Priority & Urgency Calculation**: Derives operational priority (`P0`..`P4`) and temporal urgency (`IMMEDIATE`..`DEFERRED`) by evaluating risk severity, active attack progression, and forensic shelf-life.
7. **Dependency Sequencing**: Automatically orders evidence preservation actions (`PRESERVE_EMAIL`, `PRESERVE_LOGS`) before destructive or mutative containment actions.
8. **Persistence**: Persists recommendations with versioning, timestamps, and scopes (`EVENT`, `INCIDENT`, `INVESTIGATION`).

---

## 3. Data Model (`ResponseRecommendationModel`)

The recommendation model is persisted in PostgreSQL/SQLite via SQLAlchemy and validated using Pydantic schemas:

```
ResponseRecommendation
├── id: UUID / String (e.g. REC-104)
├── workspace_id: String (tenant isolation)
├── scope_type: Enum ('EVENT', 'INCIDENT', 'INVESTIGATION')
├── scope_id: String
├── incident_id: Optional String
├── threat_event_id: Optional String
├── risk_assessment_id: Optional String
├── explanation_id: Optional String
├── action_type: ActionTypeEnum
├── category: ActionCategoryEnum
├── title: String
├── description: String
├── rationale: String (why recommended)
├── priority: RecommendationPriorityEnum (P0..P4)
├── urgency: RecommendationUrgencyEnum (IMMEDIATE..DEFERRED)
├── expected_effect: String
├── prerequisites: JSON Array of PrerequisiteItem
├── affected_entities: JSON Array of AffectedEntity
├── evidence_refs: JSON Array of String
├── risk_refs: JSON Array of String
├── attack_path_refs: JSON Array of String
├── mitre_refs: JSON Array of String
├── confidence: Float (0.0 to 1.0)
├── confidence_level: String ('LOW', 'MEDIUM', 'HIGH', 'VERY_HIGH')
├── applicability: ApplicabilityEnum
├── applicability_reason: String
├── reversibility: ReversibilityEnum
├── impact: OperationalImpactEnum
├── approval_required: Boolean
├── safety_class: SafetyClassEnum
├── execution_mode: ExecutionModeEnum
├── status: RecommendationStatusEnum
├── status_reason: Optional String
├── reviewed_by: Optional String
├── reviewed_at: Optional DateTime
├── recommendation_version: Integer
├── superseded_by_id: Optional String
├── depends_on: JSON Array of recommendation IDs
├── conflicts_with: JSON Array of ConflictItem
├── metadata_payload: JSON Dict
├── created_at: DateTime (UTC)
├── updated_at: DateTime (UTC)
└── expires_at: Optional DateTime (UTC)
```

---

## 4. Controlled Action Taxonomy

Actions are organized into six operational domains:

### Investigation
- `REVIEW_EVIDENCE`: Inspect extracted observables and forensic metadata.
- `REVIEW_HEADERS`: Inspect RFC 822 transport headers and trace route.
- `INSPECT_URL`: Analyze destination URL structure, redirection hops, and cloaking.
- `INSPECT_ATTACHMENT`: Review static and dynamic sandbox analysis of attached file.
- `REVIEW_AUTHENTICATION`: Audit SPF, DKIM, DMARC, and session origin.
- `REVIEW_ENDPOINT_TELEMETRY`: Inspect host process trees and execution telemetry.
- `REVIEW_NETWORK_ACTIVITY`: Inspect DNS queries, HTTP proxies, and egress flows.
- `EXPAND_ATTACK_PATH`: Query Security Knowledge Graph for multi-stage pivots.
- `CORRELATE_RELATED_EVENTS`: Search for campaign clusters sharing IOCs.

### Containment
- `QUARANTINE_FILE`: Move malicious payload into isolated forensic holding.
- `ISOLATE_DEVICE`: Disconnect workstation/endpoint from local network via EDR.
- `BLOCK_URL`: Add malicious URI to proxy and secure web gateway filtering.
- `BLOCK_DOMAIN`: Sinkhole or block malicious domain across corporate DNS.
- `BLOCK_IP`: Deny egress/ingress traffic to malicious IP at firewall/WAF.
- `DISABLE_ACCOUNT`: Disable active directory / IAM user identity.
- `REVOKE_SESSION`: Invalidate active OAuth / cookie session tokens.
- `REVOKE_CREDENTIAL`: Revoke API keys or temporary credentials.

### Credential / Identity
- `FORCE_PASSWORD_RESET`: Require user to reset credentials upon next authentication.
- `REQUIRE_MFA_REAUTHENTICATION`: Step up authentication with hardware/push MFA.
- `REVIEW_MFA_SETTINGS`: Audit registered authenticator apps and recovery methods.
- `REVIEW_PRIVILEGED_ACCESS`: Review admin privileges and role assignments.

### Communication
- `NOTIFY_USER`: Alert affected recipient regarding suspicious lure or compromise.
- `NOTIFY_SECURITY_TEAM`: Dispatch alert to SOC tier-2 queue or incident commander.
- `ESCALATE_INCIDENT`: Escalate severity and trigger on-call rotation.
- `NOTIFY_SYSTEM_OWNER`: Notify infrastructure custodian of affected resource.

### Recovery
- `RESTORE_FROM_KNOWN_GOOD_STATE`: Reimage host or restore snapshot from backup.
- `REMOVE_MALICIOUS_ARTIFACT`: Remove persistence mechanisms or dropped droppers.
- `REVERSE_UNAUTHORIZED_CHANGE`: Revert configuration drift or IAM policy modifications.

### Evidence Preservation
- `PRESERVE_ARTIFACT`: Store immutable copy of file, attachment, or script.
- `PRESERVE_LOGS`: Snapshot relevant system and security event logs.
- `PRESERVE_NETWORK_TELEMETRY`: Capture PCAP or NetFlow slices.
- `PRESERVE_EMAIL`: Cryptographically vault raw RFC 822 email payload.
- `PRESERVE_FORENSIC_SNAPSHOT`: Take complete virtual machine / memory dump.

---

## 5. Recommendation Priority & Urgency Framework

Priority and Urgency are decoupled to reflect real-world SOC triage realities:

### Priority (`priority`)
- **P0**: Immediate containment & volatile evidence preservation consideration.
- **P1**: Urgent investigation, active credential protection, and perimeter blocking.
- **P2**: High-priority analyst actions, user notifications, campaign correlation.
- **P3**: Standard investigation procedures, baseline comparisons.
- **P4**: Informational follow-up, hygiene recommendations.

### Urgency (`urgency`)
- **IMMEDIATE**: Active threat in progress, volatile evidence about to expire, ongoing exfiltration.
- **URGENT**: Uncontained credential compromise or multi-stage progression detected.
- **SOON**: Threat contained or dormant, but requires timely analyst decision.
- **NORMAL**: Standard triage window (e.g. 24-48 hours).
- **DEFERRED**: Post-incident review or long-term remediation.

---

## 6. Safety Classes, Impact & Reversibility

Every recommendation declares its operational consequences:

| Action | Safety Class | Reversibility | Operational Impact | Approval Required |
|---|---|---|---|---|
| `REVIEW_EVIDENCE` | `INFORMATIONAL` | `REVERSIBLE` | `NONE` | No (`false`) |
| `PRESERVE_EMAIL` | `INFORMATIONAL` | `REVERSIBLE` | `NONE` | No (`false`) |
| `NOTIFY_SECURITY_TEAM` | `LOW_IMPACT` | `REVERSIBLE` | `NONE` | Configurable |
| `REVOKE_SESSION` | `REVERSIBLE` | `REVERSIBLE` | `MEDIUM` | Yes (`true`) |
| `BLOCK_DOMAIN` | `CONTAINMENT` | `REVERSIBLE` | `MEDIUM` | Yes (`true`) |
| `ISOLATE_DEVICE` | `CONTAINMENT` | `REVERSIBLE` | `HIGH` | Yes (`true`) |
| `FORCE_PASSWORD_RESET` | `REVERSIBLE` | `PARTIALLY_REVERSIBLE` | `MEDIUM` | Yes (`true`) |
| `DISABLE_ACCOUNT` | `HIGH_IMPACT` | `REVERSIBLE` | `HIGH` | Yes (`true`) |
| `QUARANTINE_FILE` | `CONTAINMENT` | `REVERSIBLE` | `LOW` | Yes (`true`) |
| `REMOVE_MALICIOUS_ARTIFACT` | `DESTRUCTIVE` | `IRREVERSIBLE` | `HIGH` | Yes (`true`) |

---

## 7. Action Applicability & Prerequisites

Recommendations are never generated blindly:

1. **Applicability Layer**:
   - `APPLICABLE`: Target entity is identified and verified via evidence.
   - `NOT_APPLICABLE`: Target entity is absent (e.g. `ISOLATE_DEVICE` when no host exists).
   - `NOT_READY`: Missing essential prerequisites.
   - `UNKNOWN`: Insufficient evidence to determine target viability.

2. **Prerequisites Checklist**:
   Each recommendation provides a list of structured conditions:
   ```json
   {
     "name": "DESTINATION_DOMAIN_IDENTIFIED",
     "description": "Malicious domain must be extracted and validated in indicators.",
     "satisfied": true
   }
   ```

---

## 8. Environment Capability Registry

The engine includes `ResponseCapabilityModel` to model actual infrastructure integration capabilities:

- `AVAILABLE`: Fully configured provider integration (e.g. Active Directory, Cloudflare DNS, Exchange Online).
- `REQUIRES_CONFIGURATION`: Capability exists conceptually, but API tokens or agent connectors are not set up.
- `UNAVAILABLE`: Capability is not supported in this environment.
- `DISABLED`: Administrator explicitly disabled this automated action type.
- `UNKNOWN`: Status unverified.

If a capability is `REQUIRES_CONFIGURATION` (such as EDR isolation), the recommendation is flagged so the analyst understands that execution will require manual or alternative intervention.

---

## 9. Dependency Sequencing & Operational Conflict Handling

1. **Evidence Preservation Precedence**:
   Containment and remediation actions declare explicit dependencies (`depends_on: ["REC-PRESERVE-01"]`). Volatile data must be snapshotted before network cutoff or file quarantine alters the forensic state.

2. **Conflict Detection**:
   When recommendations present competing tactical goals (e.g. disabling an account immediately vs. leaving it active with honeypot monitoring to map threat actor C2 infrastructure), the engine registers a `conflicts_with` item:
   ```json
   {
     "conflicting_recommendation_id": "REC-MON-02",
     "conflicting_action_type": "REVIEW_ENDPOINT_TELEMETRY",
     "tradeoff_explanation": "Disabling the account halts active compromise but prevents tracking active adversary lateral movement."
   }
   ```

---

## 10. Recommendation Lifecycle & Expiration

Recommendations progress through explicit, audited states:

```
GENERATED ──► REVIEW_REQUIRED ──► APPROVED
                      │        ──► REJECTED
                      │        ──► DEFERRED
                      ▼
              EXPIRED / SUPERSEDED
```

- `GENERATED`: Informational/advisory actions that do not require approval.
- `REVIEW_REQUIRED`: Consequential actions awaiting analyst sign-off.
- `APPROVED`: Analyst reviewed and authorized for Section 29 Playbook execution.
- `REJECTED`: Analyst rejected (e.g. legitimate business tool false positive).
- `DEFERRED`: Analyst postponed action pending further intelligence.
- `EXPIRED`: Time-to-live (`expires_at`) lapsed (e.g. session token expired naturally).
- `SUPERSEDED`: Replaced by a more comprehensive recommendation (version incremented).

---

## 11. Strict LLM Role & Guardrails

To prevent hallucinated containment actions or prompt injection exploits:

### What the LLM May Do
- Summarize authoritative recommendations in human-friendly language.
- Explain rationale and link evidence to MITRE ATT&CK techniques.
- Translate technical explanations for executive briefs.

### What the LLM May Never Do
- **Invent actions**: Cannot synthesize new action types outside the controlled taxonomy.
- **Invent evidence**: Cannot fabricate hashes, IPs, or user accounts.
- **Execute actions**: Cannot invoke containment APIs.
- **Approve actions**: Cannot bypass the human approval boundary.
- **Modify priorities or risk**: Cannot alter `P0`..`P4` or risk scores.
- **Simulate execution success**: Cannot output fake "Device isolated successfully" messages.

---

## 12. Security, Multi-Tenancy & Tampering Prevention

1. **Server-Side Authorization**:
   - Only authenticated analysts with `analyst:review` or `admin` scopes may review, approve, or reject recommendations.
2. **Immutable Target Binding**:
   - Target entities (`affected_entities`) are derived strictly on the server from validated `EvidenceModel` and `ThreatEventModel` data.
   - Client requests cannot alter the affected entity (preventing an attacker from redirecting a `DISABLE_ACCOUNT` request to an administrator).
3. **Tenant Isolation**:
   - All recommendation and capability queries enforce `workspace_id` filtering. Recommendations from Workspace A are completely invisible to Workspace B.
4. **Audit Trail**:
   - Every analyst review transition (`APPROVED`, `REJECTED`, `DEFERRED`) logs an immutable entry to `AuditLogModel` recording `user`, timestamp, previous state, new state, and review justification notes.

---

## 13. REST API Specification

Mounted at `/api/v1/recommendations`:

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/by-scope/{scope_type}/{scope_id}` | Fetch all recommendations for a given scope. |
| `POST` | `/generate` | Deterministically generate/refresh recommendations for a scope. |
| `GET` | `/capabilities` | List registered environment defensive capabilities. |
| `POST` | `/capabilities` | Register or update an environment defensive capability. |
| `GET` | `/summary/{scope_type}/{scope_id}` | Retrieve overview statistics (counts by priority/status). |
| `GET` | `/{recommendation_id}` | Retrieve single recommendation with full details. |
| `POST` | `/{recommendation_id}/approve` | Approve a recommendation (requires analyst notes). |
| `POST` | `/{recommendation_id}/reject` | Reject a recommendation (requires reason). |
| `POST` | `/{recommendation_id}/defer` | Defer a recommendation. |

---

## 14. Frontend Response Workspace Foundation

The user interface integrates cleanly into CyberGuard's existing Investigation view:

1. **Sub-Tab Navigation**: Added `Response Proposals` (`recommendations`) sub-tab alongside Graph, Campaigns, Evidence, and XAI.
2. **Safety Boundary Banner**: Prominently displays the advisory nature of Section 28, reminding analysts that consequential actions require explicit approval.
3. **Capabilities Drawer**: Inspects configured environment providers (e.g. Mail Quarantine vs. EDR Isolation).
4. **Interactive Action Cards**: Displays priority pills (`P0`..`P4`), urgency, reversibility, impact, target entities, and evidence citations.
5. **Action Detail Modal (`ActionDetailModal`)**: Deep dive into risk-benefit trade-offs, prerequisites readiness, and analyst review forms with mandatory justification notes.

---

## 15. Worked Incident Scenarios

### Scenario 1: High-Confidence Phishing Campaign
- **Input**:
  - Email with impersonated domain `micros0ft-security.com`.
  - Credential harvesting URL `hxxps://micros0ft-security.com/auth`.
  - SPF/DKIM fail; Risk Score: 88 / 100 (`CRITICAL`).
- **Engine Output**:
  1. `[P0 / IMMEDIATE]` `PRESERVE_EMAIL`: Cryptographically vault raw message payload. (Approval: No)
  2. `[P1 / URGENT]` `BLOCK_DOMAIN`: Block `micros0ft-security.com` at perimeter DNS. (Approval: Yes, Depends on: Preservation)
  3. `[P2 / URGENT]` `NOTIFY_USER`: Alert target recipient of credential harvesting attempt. (Approval: Configurable)
  4. `[P2 / NORMAL]` `CORRELATE_RELATED_EVENTS`: Search cluster for other recipients of the lookalike domain. (Approval: No)

### Scenario 2: Account Takeover (ATO) with Session Hijacking
- **Input**:
  - Legitimate credentials used from anomalous geographical ASN.
  - Active session `SESS-OAUTH-4411` generating high-volume privileged API calls.
  - Risk Score: 94 / 100 (`CRITICAL`); Attack Path: Lateral Movement.
- **Engine Output**:
  1. `[P0 / IMMEDIATE]` `PRESERVE_LOGS`: Snapshot authentication and OAuth API gateway telemetry. (Approval: No)
  2. `[P0 / IMMEDIATE]` `REVOKE_SESSION`: Invalidate active OAuth session `SESS-OAUTH-4411`. (Approval: Yes, Depends on: Log Preservation)
  3. `[P1 / URGENT]` `FORCE_PASSWORD_RESET`: Force credential reset on `victim_user@corp.com`. (Approval: Yes)
  4. `[P1 / URGENT]` `REVIEW_PRIVILEGED_ACCESS`: Audit changes made during anomalous session window. (Approval: No)

### Scenario 3: Multi-Stage Attack (Phishing → Payload → Egress C2)
- **Input**:
  - Macro-enabled document executed on workstation `WORKSTATION-CFO-01`.
  - Outbound connection to foreign IP `198.51.100.44:443`.
  - Risk Score: 96 / 100 (`CRITICAL`); EDR integration: `REQUIRES_CONFIGURATION`.
- **Engine Output**:
  1. `[P0 / IMMEDIATE]` `PRESERVE_ARTIFACT`: Vault dropped dropper file and process snapshot. (Approval: No)
  2. `[P0 / IMMEDIATE]` `ISOLATE_DEVICE`: Isolate `WORKSTATION-CFO-01` (Flagged: `REQUIRES_CONFIGURATION`). (Approval: Yes)
  3. `[P1 / URGENT]` `BLOCK_IP`: Deny egress to `198.51.100.44` on firewall boundary. (Approval: Yes)
  4. `[P1 / URGENT]` `QUARANTINE_FILE`: Quarantine malicious attachment payload. (Approval: Yes, Depends on: Preservation)
  5. `[P2 / SOON]` `EXPAND_ATTACK_PATH`: Query Security Knowledge Graph for matching C2 infrastructure. (Approval: No)

---

## 16. Verification & Test Suite

The test suite covers all requirements:

- `backend/tests/test_response_recommendation.py` (14 unit & integration tests):
  - Deterministic generation across threat scenarios.
  - Consequential actions require approval (`approval_required=True`).
  - Informational actions do not block on approval.
  - Applicability suppression when target devices are absent.
  - Capability awareness (`REQUIRES_CONFIGURATION` flags).
  - Dependency sequencing (Preservation before Quarantine).
  - Recommendation confidence decoupled from threat confidence.
  - Expiration and supersession mechanics.
  - Operational conflict detection (`conflicts_with`).
  - Analyst review workflow (`APPROVE`, `REJECT`, `DEFER`) with immutable audit logging.
  - Reversibility and impact classification.
  - Priority ordering (`P0` <= `P1` <= `P2`).
  - Full Section 52 End-to-End Scenario validation.
- `backend/tests/test_response_recommendation_api.py` (9 API endpoint tests):
  - REST route testing for generation, scope retrieval, summary metrics, capability management, and approval endpoints.
- Frontend Verification:
  - TypeScript compilation (`tsc -b && vite build`) passed with zero errors.

---

## 17. Limitations & Transition to Section 29

1. **Advisory Scope**: Section 28 intentionally does not execute changes in the environment. It prepares approved actions for **Section 29 Response Playbooks**.
2. **Capability Connectors**: Active integrations (EDR, Cloudflare, Active Directory) currently simulate capability states in testing; production deployments will bind to real enterprise API connectors in Section 29.
3. **Execution State**: Execution states (`EXECUTED`, `FAILED`, `CANCELLED`) belong to Section 29 execution engine and are not prematurely asserted in Section 28.
