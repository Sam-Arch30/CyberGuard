# Section 41 — Response Workspace Documentation

## 1. Purpose & Core Philosophy

The **Response Workspace** (`/investigations/:investigationId/response`) serves as the investigation's controlled decision-and-action surface for CyberGuard.

It is designed around the core question:
> **"What should we do now, why should we do it, what requires approval, what can be safely simulated, and what has actually happened?"**

### Essential Product Principle
The UI enforces strict separation between four operational states:
1. **What CyberGuard recommends** (Advisory recommendations synthesized from structured risk, MITRE techniques, and forensic indicators)
2. **What the analyst approves** (Explicit, authenticated analyst authorizations with mandatory justification notes)
3. **What the system actually executes** (Authorized adapters dispatching API requests or containment directives)
4. **What actually happened** (Immutable execution results, verification confirmations, or failures in the audit ledger)

**CyberGuard is not an autonomous response engine.** Consequential containment actions are always explicit, authorized, and auditable decisions. The UI never fakes execution, never fabricates telemetry, and never implies an action was taken when it was merely recommended or simulated.

---

## 2. Architecture & Component Hierarchy

```text
ResponseSectionView (/investigations/:id/response)
├── ResponseSummaryBar
│   ├── Metrics (Total, Review Required, Approved, Unavailable, Critical)
│   ├── Quick Actions (Re-evaluate Telemetry, Capability Registry)
│   └── Last Evaluated Timestamp
├── ResponseRiskSummary (Section 26 & 27 Integration)
│   ├── Authoritative Threat & Risk Score (0-100)
│   ├── Severity, Confidence, & Uncertainty Bounds
│   ├── Structured Primary Risk Drivers
│   └── "Why These Defensive Responses?" Grounding Callout
├── StaleRecommendationBanner (Run ID version comparison)
├── Operational Filters & Sort Toolbar
│   ├── Workflow Filters (All, Review Required, Approved, Completed, Rejected, Deferred)
│   ├── Category Filters (Containment, Identity, Network, Endpoint, Evidence, Comms, Recovery)
│   ├── Priority & Confidence Sorting
│   └── Indicator / Entity Text Search
├── Immediate Actions (P0 / P1 Priority Grid)
│   └── RecommendationCard
├── Standard Advisory Actions (P2 / P3 / P4 Advisory Grid)
│   └── RecommendationCard
├── PlaybookSection (Section 29 Integration)
│   ├── Staged Playbook List & Status Badges
│   ├── Multi-Step Workflow Visualization
│   ├── Dry-Run Simulation Engine Trigger & Plan Inspector
│   └── Live Playbook Execution Confirmation Modal
├── ActionHistoryTimeline (Section 32 & 33 Integration)
│   ├── Unified Chronological Event Stream (Executions, Approvals, Rejections, Generations)
│   └── Authoritative Audit References (Analyst ID, Timestamp, Reference IDs)
└── Inspection & Action Modals
    ├── RecommendationInspectorModal (Full Provenance, Evidence Chips, Attack Path Pivot)
    ├── ActionApprovalModal (Formal Gated Confirmation & Justification Recording)
    ├── CapabilityRegistryModal (Defensive Providers, Adapter Readiness, Suppression Explanations)
    └── ExecutionStatusModal (Real Step Telemetry, Adapter Versioning, Failure Diagnostics)
```

---

## 3. Recommendation Integration (Section 28)

Recommendations are fetched from the authoritative backend recommendation engine via:
- `GET /api/investigations/{identifier}/response` (or `GET /api/v1/recommendations/by-scope/INVESTIGATION/{id}`)
- `POST /api/v1/recommendations/generate` with `{ scope_type: "INVESTIGATION", scope_id: id }`

### Model Invariants
Each recommendation complies with `ResponseRecommendationModel`:
- `id`: Stable alphanumeric identifier.
- `priority`: Strict priority bands (`P0`, `P1`, `P2`, `P3`, `P4`).
- `category`: Defensive category (`CONTAINMENT`, `IDENTITY_SECURITY`, `NETWORK_SECURITY`, `ENDPOINT_SECURITY`, `EVIDENCE_PRESERVATION`, etc.).
- `status`: State machine disposition (`GENERATED`, `REVIEW_REQUIRED`, `APPROVED`, `REJECTED`, `DEFERRED`, `SUPERSEDED`, `EXPIRED`).
- `applicability`: Real capability availability (`APPLICABLE`, `NOT_APPLICABLE`, `NOT_READY`, `UNKNOWN`).
- `safety_class`: Safety tier (`INFORMATIONAL`, `LOW_IMPACT`, `REVERSIBLE`, `CONTAINMENT`, `HIGH_IMPACT`, `DESTRUCTIVE`).

---

## 4. Risk & Explanation Grounding (Sections 26 & 27)

The workspace does **not** recalculate risk in the browser. It directly renders the backend `RiskAssessmentModel`:
- Score (0 to 100)
- Confidence level (e.g. 0.85 -> 85% High Confidence)
- Uncertainty score (e.g. 15% Bounded Uncertainty)
- Primary risk drivers derived directly from evaluated rules, IOCs, and model signals.

### Provenance Chain
Every substantive recommendation exposes a verifiable provenance chain:
```text
Defensive Recommendation
         ↓
    Risk Signal
         ↓
Forensic Finding
         ↓
  Evidence Item
         ↓
Raw Source Artifact
```

Clicking an evidence reference immediately cross-navigates the investigator to the **Evidence Section** (`/investigations/:id/evidence`) or **Attack Path Section** (`/investigations/:id/attack-path`).

---

## 5. Analyst Approval Boundary

Consequential containment actions (quarantining emails, blocking IPs/domains, host isolation, credential revocation) cannot be executed silently:
1. Status is initially `REVIEW_REQUIRED` or `GENERATED`.
2. The investigator opens the **ActionApprovalModal**.
3. The analyst must select a disposition (`APPROVED`, `REJECTED`, `DEFERRED`) and supply a mandatory forensic justification note.
4. The system sends an authenticated POST request:
   - `/api/v1/recommendations/{id}/approve`
   - `/api/v1/recommendations/{id}/reject`
   - `/api/v1/recommendations/{id}/defer`
5. The immutable audit log records the reviewer's ID, disposition, timestamp, and notes.

---

## 6. Defensive Capability Registry

The **Capability Registry** (`GET /api/v1/recommendations/capabilities`) tracks configured defensive adapters:
- **Available Providers**:
  - `SWG`: Cloudflare Gateway / Zscaler (URL/Domain blocking)
  - `DNS_SINKHOLE`: CoreDNS / BIND Sinkhole (DNS redirection)
  - `FIREWALL`: Palo Alto / Fortinet Perimeter Firewall (IP ingress/egress blocks)
  - `EDR`: CrowdStrike / Microsoft Defender for Endpoint (Device isolation)
  - `IDP`: Microsoft Entra ID / Okta (Session revocation, credential reset)
- **Capability States**: `AVAILABLE`, `UNAVAILABLE`, `REQUIRES_CONFIGURATION`, `DISABLED`.
- Actions mapped to unavailable capabilities display non-clickable indicators with detailed remediation guidance.

---

## 7. Response Playbooks (Section 29)

Playbooks (`ResponsePlaybookModel`) represent multi-step, deterministic workflows:
- Automatic staging: Analysts can click **"Stage Playbook"** from any approved recommendation (`POST /api/v1/playbooks/from-recommendation/{id}`).
- Step-by-step breakdown: Each step displays sequence, step type, requires_approval flag, safety classification, and rollback policy.

### Dry-Run Simulation (`/simulate`)
Before any live action, investigators can execute a dry-run simulation:
- Evaluates target validity and scope.
- Confirms prerequisite adapter connectivity and permissions.
- Verifies absence of conflicting sessions or locks.
- Returns `SIMULATION COMPLETED — NO ACTION EXECUTED` with simulated effect preview.

### Authorized Live Execution (`/execute`)
When executing in `LIVE` mode:
- Requires strict modal confirmation.
- Dispatches adapter handlers through `PlaybookExecutor`.
- Tracks attempt count, duration, step status (`COMPLETED`, `RUNNING`, `FAILED`), and verification results.
- Never suppresses or masks execution failures.

---

## 8. Action & Audit History Timeline

The timeline streams real events:
- **Playbook Executions**: Records execution mode (`LIVE` vs `DRY_RUN`), start/end time, actor, and step count.
- **Analyst Reviews**: Records approval, rejection, or deferral with timestamp and justification notes.
- **Recommendation Generations**: Records initial recommendation synthesis.
- Selecting any timeline item opens the corresponding detail inspector modal.

---

## 9. Stale Recommendations & Conflict Handling

- **Staleness**: Each recommendation records the `analysis_run_id` under which it was generated. If the investigation's active analysis run advances (e.g. from new telemetry or forensic re-analysis), the workspace displays a prominent warning banner with an immediate **Re-evaluate Now** trigger.
- **Conflicts**: If recommendations have mutual tradeoffs (e.g., active session revocation vs active session forensic capture), `conflicts_with` items are rendered with tradeoff explanations and resolution order.

---

## 10. Security & Authorization Controls

- **IDOR Protection**: All recommendation and playbook execution endpoints enforce strict investigation tenant ownership and role-based checks.
- **No Client Manipulation**: The UI cannot mark an action as executed; only verified execution reports from backend adapters mutate execution state.
- **Idempotency**: Repeated button clicks are disabled during execution dispatch, preventing duplicate adapter commands.

---

## 11. Theme Consistency & Accessibility

- Compatible with all four system themes: **Olive**, **Sakura**, **Paper**, and **Midnight**.
- Non-color status indicators: Text badges (`P0`, `APPROVED`, `AVAILABLE`) accompany all color indicators for WCAG 2.1 AA compliance.
- Keyboard navigation: All modals trap focus, support <kbd>Esc</kbd> for dismissal, and provide explicit ARIA roles (`role="dialog"`).
- Motion: Reduced-motion CSS applied to animated pulses and spinners.
