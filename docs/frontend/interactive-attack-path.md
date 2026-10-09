# Section 40: Interactive Attack Path

## 1. Purpose
The Interactive Attack Path workspace provides an interactive, evidence-constrained visualization of the reconstructed attack progression for an investigation. Accessible via:

`/investigations/:investigationId/attack-path`

The workspace answers the primary question:
> **"Based on the available evidence, how did this incident most likely progress from the initial event to the observed outcome?"**

It strictly enforces the core design philosophy:
- The Attack Path UI is a **path-level projection of the existing Security Knowledge Graph and AI Attack Reconstruction Engine**.
- The frontend visualizes the backend's structured conclusions; it does **not** independently invent attack stages or calculate confidence.
- Rigorously distinguishes **directly observed activity (`OBSERVED`)**, **strongly supported relationships (`DERIVED`)**, **inferred relationships (`INFERRED`)**, **unresolved gaps**, and **contradictory signals**.

---

## 2. Architecture & Data Flow

```text
Security Knowledge Graph (Section 14)
          ↓
Temporal Correlation & Sequencing (Section 16)
          ↓
AI Attack Reconstruction Engine (Section 17)
          ↓
AttackPath / AttackStage / AttackEdge Models (backend/db/models.py)
          ↓
Confidence & Explainability System (Section 18)
          ↓
AttackPathService & Projection Schema (backend/services/attack_path_service.py)
          ↓
REST API: GET /api/investigations/{identifier}/attack-path
          ↓
Frontend Service: attackPathService.ts
          ↓
Interactive Attack Path Workspace (AttackPathSectionView.tsx)
          ├── AttackPathHeader
          ├── AttackStageCard
          ├── AttackTransitionEdge
          ├── AttackStageInspector
          ├── PathGapsAndContradictions
          ├── AlternativeHypothesesPanel
          ├── AttackPathTimelineSync
          └── PathContextSummary
```

---

## 3. Backend Data Models & Reuse
Section 40 reuses existing persistent database models without introducing a duplicate graph or reconstruction engine:
- `AttackPathModel`: Central path entity with classification, calibrated confidence, version, evidence gaps, contradictions, and metadata.
- `AttackStageModel`: Discrete nodes representing chronological progression (`OBSERVED`, `DERIVED`, `INFERRED`, `UNRESOLVED`).
- `AttackEdgeModel`: Directed transitions between stages with temporal gaps, shared entities, and relationship classification.
- `AttackHypothesisModel`: Competing scenarios produced by the Section 17 engine.
- `AttackTechniqueMappingModel`: Evidence-grounded MITRE ATT&CK technique associations.
- `InfrastructureAttributionModel`: Technical infrastructure intelligence (Section 20).

---

## 4. API Integration
The primary endpoint is:

```http
GET /api/investigations/{identifier}/attack-path?run_id={run_id}&force_reconstruct={bool}
```

### URL Resolution:
The endpoint accepts any valid incident ID, incident number (e.g. `INV-2026-001`), analysis run ID, or legacy case identifier.

### Response Payload:
Returns `AttackPathDetailResponse`:
- `investigation_id`, `incident_number`, `analysis_run_id`, `available_runs`
- `has_path`, `path_id`, `name`, `status`, `classification`, `completeness_score`
- `confidence`, `confidence_level`, `confidence_components`, `confidence_bottleneck`, `explanation`
- `start_time`, `end_time`, `duration_seconds`
- `stages`: List of `AttackStageProjection`
- `transitions`: List of `AttackTransitionProjection`
- `gaps`: List of `AttackGapProjection`
- `contradictions`: List of `AttackContradictionProjection`
- `alternatives`: List of `AttackAlternativeProjection`
- `mitre_techniques`: List of MITRE techniques
- `infrastructure`: List of technical infrastructure assets
- `timeline_events`: Synchronized chronological event strip
- `limitations`: Explicit forensic caveats

---

## 5. Stage Rendering & Certainty Taxonomy
Stages are displayed via `AttackStageCard` with non-color and color-coded status badges:
- `● OBSERVED`: Direct telemetry or immutable artifact represents the activity (e.g. spearphishing email delivered). Solid border and green indicator.
- `⊙ DERIVED`: Deterministic interpretation from observations (e.g. social engineering lure detected). Solid border and accent indicator.
- `◌ INFERRED`: Plausible security hypothesis supported indirectly by behavioral heuristics (e.g. credential harvesting attempt). Dashed border and warning indicator with uncertainty margin (e.g. `±30s`).
- `? UNRESOLVED`: Potential activity where telemetry is absent or inconclusive. Dashed border and warning badge.

---

## 6. Transition Rendering & Causal vs. Temporal Rigor
Transitions between stages are rendered via `AttackTransitionEdge`. The UI enforces strict linguistic and visual separation:

### Causal Evidence:
- Used **only** when `relationship_type in ("CAUSES", "TRIGGERS")` and edge certainty is `OBSERVED`/`DERIVED`.
- Label: `SUPPORTED CAUSAL LINK`.
- Narrative: *"The attachment spawned the observed process."*

### Temporal Association:
- Used when events occurred sequentially without direct execution proof.
- Label: `TEMPORAL ASSOCIATION (16s interval)`.
- Narrative: *"The process appeared 16s after the attachment was opened. Causal link unproven."*

The system **never** visually implies causality when only temporal correlation was established.

---

## 7. Confidence & Explainability Integration
- Confidence is **never** calculated on the frontend.
- Consumes calibrated backend score (0.0–1.0) and categorical level (`HIGH`, `MODERATE`, `LOW`).
- Clicking the confidence metric opens `ConfidenceExplainModal`, displaying:
  - Component breakdowns (e.g. temporal continuity, graph consistency, multi-source corroboration)
  - Primary confidence bottleneck if identified
  - Explicit definition: Confidence measures empirical evidence strength, **not** threat actor probability or human identity certainty.

---

## 8. Evidence Integration & Deep Inspection
Selecting any stage in the flow updates `AttackStageInspector`:
- Detailed analytical justification: *"Why this stage exists"*
- Structured evidence items with provenance (source gateway, timestamp, detector, finding keys/values)
- Associated security entities with risk scores
- Correlated analytical findings with severity and confidence
- Actions:
  - **Inspect Evidence Drawer**: Pivots to the comprehensive Evidence browser (Section 39).
  - **View in Knowledge Graph →**: Deep links directly to the Security Knowledge Graph with node focus.
  - **Consult AI Copilot**: Spawns contextual investigation copilot seeded with stage findings.

---

## 9. Timeline Synchronization
- `AttackPathTimelineSync` renders chronological events with event-time semantics (UTC).
- Selecting a stage highlights matching events in the timeline.
- Clicking an event in the timeline selects and focuses its mapped attack stage.

---

## 10. Alternative Hypotheses
When the backend reconstruction engine generates alternative attack scenarios (Section 17):
- Displayed via `AlternativeHypothesesPanel`.
- Shows Primary path vs Alternative A / B.
- Displays confidence score, missing evidence, and analytical rationale.
- Allows comparing scenarios without inventing hypotheses in the browser.

---

## 11. Gaps & Contradictions
- `PathGapsAndContradictions` surfaces missing telemetry:
  - Missing URL click telemetry
  - Missing endpoint process telemetry (EDR)
  - Unproven credential harvesting
  - Unconfirmed data exfiltration
- Displays contradictions (e.g. internal IP subnet vs external lure) and their impact on reconstruction confidence.
- Transparently communicates uncertainty rather than synthesizing fake intermediate stages.

---

## 12. MITRE ATT&CK & Technical Infrastructure Context
`PathContextSummary` provides structured intelligence:
- **MITRE ATT&CK Matrix**: Technique ID (e.g. `T1566.002`), tactics, status (`SUPPORTED`, `PLAUSIBLE`, `INSUFFICIENT`), and backing evidence count.
- **Observed Infrastructure**: Technical network assets (IPs, domains, ASNs, roles).
- **Strict Boundary**: Disclaims that entities represent technical network assets and must not be interpreted as physical human identities.

---

## 13. Multiple Analysis Runs
- Analysis run selector allows switching between Analysis Run #1, Run #2, etc.
- Each run renders its own version-matched reconstruction.
- Data from different runs is never silently combined.

---

## 14. Loading, Empty, and Partial States
- **Indeterminate Loading**: Truthful loading spinner without fake percentages.
- **Truthful No-Data State**: Displays *"NO RECONSTRUCTABLE ATTACK PATH"* when telemetry is insufficient, listing available raw findings, evidence, and timeline items with options to review or force reconstruction.
- **Partial Reconstruction**: Transparently flags unresolved intermediate hops.

---

## 15. Theme Compliance & Responsive Design
- Fully compatible with all 4 application themes:
  - **Olive**: Deep black operational environment with high-contrast borders.
  - **Sakura**: Soft light environment with muted rose accents.
  - **Paper**: Warm forensic document aesthetic with graphite contrast.
  - **Midnight**: Dark technical aesthetic with cyan accents.
- Responsive layout:
  - Desktop: Grid flow / vertical sequence with sticky inspector.
  - Mobile: Touch-friendly vertical stack with collapsible drawer.

---

## 16. Accessibility & Keyboard Navigation
- Keyboard navigation: Stage nodes support `tabIndex={0}` and activate via `Enter` or `Space`.
- Accessible certainty indicators: Uses distinct icons (`●`, `⊙`, `◌`, `?`) and explicit text labels alongside color.
- High-contrast text tokens: All fonts utilize semantic foreground tokens complying with WCAG 2.1 AA.

---

## 17. Security & Input Sanitization
- All investigation parameters (`identifier`, `run_id`, `stage_id`) are validated on the backend.
- Evidence descriptions and raw payloads are recursively sanitized and redacted for secrets/tokens via `sanitize_reconstruction_attributes`.
- Tenant isolation enforced via workspace scoping.

---

## 18. Testing & Verification
- **Backend Tests** (`backend/tests/test_section40_interactive_attack_path.py`):
  - 404 for nonexistent investigation
  - Truthful inconclusive state for empty incidents
  - Full projection with stages, transitions, gaps, contradictions, alternatives, MITRE, and infrastructure
  - Analysis run selection and versioning
- **Frontend Tests** (`src/utils/__tests__/attackPath.test.ts`):
  - Controlled status vocabulary invariants
  - Causal vs temporal classification rules
  - Truthful response model verification
  - Stage filter predicates
- **Build Verification**:
  - `npx tsc -b`: 0 errors
  - `npm run build`: built in ~426ms
  - `npx oxlint`: 0 errors
