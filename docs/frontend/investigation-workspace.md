# SECTION 39 — INVESTIGATION WORKSPACE ARCHITECTURE

The **Investigation Workspace** is the central persistent forensic environment in **CYBERGUARD**. It unifies the intelligence engines across the entire lifecycle of an incident, allowing an analyst to navigate seamlessly across:

```text
WHAT HAPPENED?  → Analysis
       ↓
HOW DID IT HAPPEN?  → Attack Path
       ↓
WHAT IS CONNECTED?  → Graph
       ↓
WHEN?  → Timeline
       ↓
WHAT PROVES IT?  → Evidence
       ↓
WHAT DO WE KNOW?  → Intelligence
       ↓
WHAT SHOULD WE DO?  → Response
       ↓
WHAT DO WE REPORT?  → Report
```

without losing context, resetting filters, or navigating back and forth to the top-level Dashboard.

---

## 1. HIERARCHY & ROUTING TOPOLOGY

The navigation hierarchy strictly separates top-level operational domains from the investigation context:

```text
Global AppShell
       │
       ├── Dashboard (/dashboard)
       ├── Investigations (/investigations)
       ├── Reports (/reports)
       └── Settings (/settings)

Investigation Workspace (/investigations/:investigationId)
       │
       ├── Overview (/investigations/:id or /overview)
       ├── Analysis (/investigations/:id/analysis)
       ├── Attack Path (/investigations/:id/attack-path)
       ├── Graph (/investigations/:id/graph)
       ├── Timeline (/investigations/:id/timeline)
       ├── Evidence (/investigations/:id/evidence)
       ├── Intelligence (/investigations/:id/intelligence)
       ├── Response (/investigations/:id/response)
       └── Report (/investigations/:id/report)
```

### Route Design Principles
1. **URL as the Source of Truth**: All primary workspace states and tabs are mapped directly to URL subpaths (`/investigations/:id/:section`), enabling deep linking, browser back/forward history, and bookmarkable investigations.
2. **Backward-Compatible Aliases**: Legacy routes such as `/investigate/:id/:section` and top-level shortcuts (`/analysis`, `/attack-path`, `/graph`, `/timeline`, `/evidence`, `/intelligence`, `/response`, `/report`) resolve directly to the active workspace.
3. **Identifier Flexibility**: The workspace router and backend service resolve artifact UUIDs, incident numbers (`INC-2026-XXXX`, `INV-2026-XXXX`), SHA-256 hashes, and case IDs bidirectionally.

---

## 2. SHARED INVESTIGATION CONTEXT

The workspace is powered by a consolidated `InvestigationContext` (`src/context/InvestigationContext.tsx`) that prevents repetitive data fetching across child views.

```text
InvestigationContext
├── investigation (Summary metadata: ID, title, incident number, opened/updated timestamps, artifact info)
├── risk (Authoritative unified RiskEngine assessment: score, severity, confidence, uncertainty)
├── counts (Real-time telemetry: findings, evidence, attack paths, timeline events, responses, notes)
├── top_findings (Highest severity forensic findings from orchestrator run)
├── attention_items (Backend-derived action items requiring analyst attention)
├── analyst_notes (Attributed, timestamped, auditable case notes)
└── activeSection (Current workspace view among the 9 canonical tabs)
```

### Data Loading & Freshness Strategy
- **Consolidated Summary**: Initial load retrieves `/api/investigations/:id/summary` once.
- **Progressive Data Loading**: Detailed sub-views (e.g. chronological timeline events, evidence items with SHA-256 digests) fetch their specific datasets upon user navigation.
- **Revalidation & Concurrency**: The sticky `InvestigationSummaryBar` includes a refresh trigger and displays relative updated timestamps. If another analyst updates state, a manual or automated revalidation ensures fresh data without silent overwrites.

---

## 3. INVESTIGATION HEADER & PERSISTENT SUMMARY BAR

Across all 9 workspaces, the analyst maintains constant situational awareness via two persistent contextual tiers:

### 1. Active Investigation Header
Displays email forensic attributes: subject, sender, origin IP, received timestamp, and cryptographic SHA-256 digest with one-click copy.

### 2. Investigation Summary Bar (`InvestigationSummaryBar.tsx`)
- **Authoritative ThreatScore**: Renders the canonical risk score (0–100) and severity tier (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `SAFE`). Frontend never calculates or duplicates risk scores.
- **Status Lifecycle Transition Selector**: Allows analysts to transition status with backend-enforced validation:
  ```text
  OPEN  →  INVESTIGATING  →  CONTAINED  →  RESOLVED  →  CLOSED
  ```
- **Metric Badges**: Real backend counts for findings, evidence items, attack paths, and analyst notes.
- **Attention Indicator**: Displays backend-derived alerts (e.g., `"Response review required"`, `"High-confidence finding"`) with pulse highlights.
- **Analyst Notes Quick Trigger**: Opens the slide-out `InvestigationNotesDrawer`.

---

## 4. THE 9 CANONICAL WORKSPACES

### 1. Overview (`/overview`)
The executive summary answering:
- *What is this incident?* Title, classification, and artifact name.
- *What is the current risk?* Unified risk rating, calibrated confidence, and primary score drivers.
- *What was detected?* High-priority indicators and top findings.
- *What requires attention?* Dynamic attention banner.
- *What should I do next?* Contextual recommended next steps.

### 2. Analysis (`/analysis`)
Composes **Section 37 (Live DAG Pipeline)** and **Section 38 (Analysis Results + Progressive Disclosure)**:
- Live Pipeline DAG execution view.
- 4-level progressive disclosure workstation (Executive Summary $\to$ Analyst Finding List $\to$ Finding Deep Dive $\to$ Evidence Detail Drawer).
- Counter-evidence, uncertainty quantification, and candidate rule triggers.

### 3. Attack Path (`/attack-path`)
Forensic attack reconstruction:
- Sequential attack stages (`Initial Access` $\to$ `Execution` $\to$ `Credential Access` $\to$ `Command and Control`).
- Stage confidence and MITRE ATT&CK technique mapping.
- Observed transition evidence and detection gaps/alternatives.

### 4. Graph (`/graph`)
The Security Knowledge Graph workspace:
- Interactive multi-entity network view (`ProgressiveInvestigationGraph`).
- Discovers connections between senders, domains, IP infrastructure, lookalikes, and campaigns.
- Pivot controls directly into other investigation sub-views.

### 5. Timeline (`/timeline`)
Forensic chronological sequence:
- Events ordered from initial lure receipt through analysis runs and analyst reviews.
- Provenance tags (e.g. `MTA Gateway`, `SPF Engine`, `Risk Engine`).
- Severity indicators, confidence scores, and text/severity filtering.

### 6. Evidence (`/evidence`)
Forensic evidence browser and chain of custody:
- **Original Evidence (Immutable Artifacts)**: Marked with `IMMUTABLE ORIGINAL` badge, SHA-256 hashes, file sizes, and raw download capability. Strictly read-only to preserve legal integrity.
- **Derived Evidence (Analytical Signals)**: Extracted IOCs (URLs, IPs, domain indicators, MIME types) with confidence ratings.
- Integrated with Level 4 `EvidenceDetailDrawer` for progressive disclosure.

### 7. Intelligence (`/intelligence`)
Unified threat intelligence and memory:
- Domain reputation, WHOIS records, passive DNS, and geographic hops.
- Clear distinction between *Observed Facts*, *External Threat Intel*, *Threat Memory*, and *Model Hypotheses*.

### 8. Response (`/response`)
Defensive containment recommendations:
- Playbooks: `PB-M365-PURGE` (tenant mailbox purge), `PB-FW-BLOCK` (firewall perimeter IP block), `PB-DNS-SINKHOLE` (domain sinkholing), `PB-IAM-RESET` (identity credential revocation).
- Governance safety mode: Read-only preview requiring analyst authorization before push.

### 9. Report (`/report`)
Forensic incident documentation:
- Executive briefings and structured finding summaries.
- Evidence dossier generation, hash verification, and print/PDF export.

---

## 5. ANALYST NOTES & AUDIT TRAIL

- Persistent notes are backed by backend `CaseNoteModel` and audited in `AuditLogModel`.
- The `InvestigationNotesDrawer` allows analysts to add attributed notes with real-time optimistic feed updates and backend persistence.
- Any status change, note creation, or response action records an immutable audit log entry.

---

## 6. FRONTEND & BACKEND CONTRACT RESPONSIBILITIES

| Responsibility | Backend (`investigation_workspace_service.py`) | Frontend (`InvestigationWorkspace.tsx`) |
| :--- | :--- | :--- |
| **Identity Resolution** | Resolves UUID, incident number, SHA-256, case ID | Preserves ID across routes and updates browser URL |
| **Risk Calculation** | Unified Risk Engine calculates authoritative score | Renders `ThreatScore` without local re-computation |
| **Status Transitions** | Validates allowed transitions & logs audit entry | Provides transition dropdown & handles error feedback |
| **Evidence Immutability** | Distinguishes original files from derived signals | Displays immutable badges and prevents editing |
| **Notes Storage** | Persists to database with actor attribution | Renders slide-out drawer with optimistic UI update |
| **Empty States** | Returns zero counts/empty lists (no mock data) | Renders truthful empty states with actionable next steps |

---

## 7. VERIFICATION MATRIX

- **Backend Pytest**: `backend/tests/test_section39_investigation_workspace.py` (5/5 PASSED).
- **Frontend Test Suite**: `src/utils/__tests__/investigationWorkspace.test.ts` (5/5 PASSED).
- **TypeScript & Production Build**: `tsc -b && vite build` (PASS, 0 errors, built in ~400ms).
- **Lint Verification**: `oxlint` (PASS, 0 errors).
