# Section 38 — Analysis Results + Progressive Disclosure

## 1. Overview & Objective

The **CYBERGUARD Analysis Results + Progressive Disclosure** system transforms completed or partial artifact analyses into a concise, evidence-backed, investigator-facing results experience.

Within seconds of opening an analysis, an investigator can answer:
1. **Is this dangerous?** (Unified authoritative risk header, severity, confidence, analysis completeness)
2. **Why does CyberGuard think that?** (Executive threat classification + Explainable AI evidence-backed causal assertions)
3. **What evidence supports it?** (Prioritized findings, supporting evidence drawer with sensitive redactions, counter-evidence, contradictions, uncertainty)
4. **What should I investigate next?** (Recommended action CTA, MITRE technique mappings, infrastructure attribution, attack path preview)

Forensic depth is preserved without overwhelming the analyst: conclusions sit on the surface, while deep forensic records remain accessible via progressive disclosure.

```text
┌────────────────────────────────────────────────────────────────────────┐
│ AnalysisRun                                                            │
│       ↓                                                                │
│ RiskAssessment (Sec 26 Unified Engine)                                 │
│       ↓                                                                │
│ Explanation (Sec 27 Explainable AI Assertions)                         │
│       ↓                                                                │
│ Findings (Prioritized by Risk Contribution & Severity)                 │
│       ↓                                                                │
│ Evidence (Supporting & Counter-Evidence)                               │
│       ↓                                                                │
│ Indicators / Entities (Domains, URLs, IPs, Emails, Hashes, Files)      │
│       ↓                                                                │
│ Attack Path / MITRE ATT&CK / Infrastructure Attribution                │
│       ↓                                                                │
│ Response Preview (Recommended Next Step CTA)                           │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Progressive Disclosure Hierarchy

Information is structured into four distinct forensic inspection levels:

### Level 1 — Executive (Visible Immediately)
- **Unified Risk Assessment Card**:
  - Risk score ($0 - 100$)
  - Risk level (`INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`)
  - Potential impact severity (`SAFE`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`)
  - Calibrated evidence confidence ($0.0 - 1.0$, `LOW`, `MODERATE`, `HIGH`, `VERY_HIGH`)
  - Uncertainty tier (`LOW`, `MODERATE`, `HIGH`)
  - Completeness indicator (`COMPLETE`, `PARTIAL`, `DEGRADED`)
- **Executive Threat Classification**:
  - Structured classification string (e.g. `Likely credential phishing`, `Potential account takeover`)
  - High-level executive finding summary
- **"Why CyberGuard Thinks This"**:
  - Structured Explainable AI assertions with support levels (`CONFIRMED`, `VERY_HIGH`, `HIGH`)
  - Evidence count badges linking directly into the sliding evidence inspection drawer
- **Recommended Next Step CTA**:
  - Prioritized actionable next step with deep-link navigation (`Proceed to Response Playbooks`)

### Level 2 — Analyst (Expandable Findings & Context)
- **Key Prioritized Findings**:
  - Ordered deterministically by backend `risk_contribution` followed by severity and confidence
  - Collapsed card shows: Severity indicator, Title, Analyzer name, Risk contribution (+pts), Confidence, Evidence count
  - Expanded disclosure reveals:
    - Observed vs. Expected / Baseline value comparison
    - Analyzer ID, Detection rule ID, Evaluation method (`RULE`, `ML`, `HEURISTIC`)
    - Direct supporting evidence links
    - Specific finding-level counter-evidence
- **Extracted Indicators Summary**:
  - Compact categorized indicator pills (Domains, URLs, IPs, Emails, Hashes, Attachments)
  - Detailed indicator records with lookalike flags, redirect hop counts, and credential harvesting alerts
- **Confirmation Bias Mitigation (Counter-Evidence)**:
  - Explicitly surfaced benign factors (e.g. `Domain age > 5 years`, `Valid TLS certificate`)
  - Labeled with strength and impact to ensure balanced investigator review
- **Contradictions & Information Gaps**:
  - Conflicting claims surfaced when signals point in opposing directions
  - "Unavailable Information" lists indicators or evidence that could not be retrieved
  - "What could change this assessment?" lists structured gaps that would alter the confidence or risk score
- **Identity & Behavioral Deviations**:
  - Claimed vs. Observed identity (`LOOKALIKE`, `MISMATCH`, `MATCH`)
  - Behavioral anomalies against established baselines
  - Threat Memory historical observations (`Observed`, `Verified Malicious`, `Dismissed`)

### Level 3 — Investigator (Attack Path, MITRE, Infrastructure)
- **Attack Progression Preview**:
  - Compact multi-stage preview (Initial Access $\to$ Credential Harvesting $\to$ Execution)
  - Path-level confidence rating
- **MITRE ATT&CK Mapping**:
  - Validated techniques (e.g., `T1566.002`, `T1059.001`)
  - Status strictly categorized: `SUPPORTED`, `PLAUSIBLE`, `INSUFFICIENT`, `REJECTED`
- **Infrastructure Attribution Preview**:
  - Probable origin infrastructure and associated domains
  - Strictly labeled `Infrastructure location` (geography of nodes, **never** human attacker attribution)

### Level 4 — Forensic & Provenance (Audit Tier)
- **Evidence Detail Drawer (`EvidenceDetailDrawer.tsx`)**:
  - Reusable sliding drawer for deep inspection of any evidence item
  - Automated redaction of sensitive credentials and tokens
  - SHA-256 cryptographic fingerprints, source analyzer provenance, and raw JSON inspection
- **Analysis Provenance**:
  - Persisted Detection Engine version (`2.0.0`), Risk Configuration version (`2.4.0`), Rule base (`3.1.0`), and Model weights (`2.2.0`)
  - Start time, completion time, duration, and immutable audit reference
- **Analysis Run History**:
  - Dropdown selector to switch between historical analysis runs for the same artifact

---

## 3. Authoritative Risk Principles

1. **No Frontend Score Calculation**:
   - The frontend never computes or adjusts risk scores (`score = phishing ? 30 : 20`).
   - All risk numbers originate from the backend Section 26 Unified Risk Engine (`RiskAssessmentModel`).
2. **Explicit Separation of Concepts**:
   - $\text{Risk Score} \neq \text{Severity} \neq \text{Confidence} \neq \text{Probability}$.
   - Tooltips and card metrics strictly maintain this distinction.
3. **Unknown Is Never Safe**:
   - Pending runs display `Risk assessment pending` with an animated pulse — never `Risk: 0` or `Safe`.
   - Analyzers lacking data output `Insufficient evidence`, never `No threat`.
4. **Partial Analysis Visibility**:
   - If analyzers fail or time out, the status is flagged as `PARTIAL` with a warning banner showing completed vs. total task counts.
5. **Controlled Reassessment**:
   - Investigators can trigger versioned manual risk reassessments via `POST /api/analysis/{run_id}/reassess`.

---

## 4. API Architecture

To prevent chatty, fragmented network requests, a consolidated aggregator service compiles all 4 progressive disclosure tiers into a single payload:

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/analysis/{run_id}/results` | `GET` | Aggregated 4-tier results by AnalysisRun ID |
| `/api/investigations/{identifier}/analysis/results` | `GET` | Aggregated results by Investigation ID, Incident Number, or Evidence ID |
| `/api/analysis/{run_id}/evidence/{evidence_id}` | `GET` | Lazy-loaded evidence detail with automated secret redaction |
| `/api/analysis/{run_id}/reassess` | `POST` | Triggers audited, versioned risk reassessment |

---

## 5. Security & LLM Guardrails

- **Secret Redaction**:
  - The evidence detail endpoint redacts sensitive authentication headers, passwords, and private tokens before delivering values to the client.
- **Tenant Isolation & Authorization**:
  - All aggregation endpoints verify tenant boundaries and artifact ownership on the backend.
- **LLM Restrictions**:
  - The LLM summarizes findings and provides analyst-friendly explanations, but **never** invents evidence, creates fake MITRE techniques, alters risk scores, or attributes physical human identities.
- **No Client-Side URL Fetching**:
  - Extracted URLs and domains are analyzed server-side; the browser never initiates network requests to suspicious endpoints.

---

## 6. Frontend Component Architecture

- `src/components/analysis/results/AnalysisResultsWorkstation.tsx`:
  - Primary workstation component containing the Level 1 Executive Header, Level 2 Prioritized Findings, Extracted Indicators, Counter-Evidence, Contradictions, Level 3 MITRE/Infra/Attack previews, and Level 4 Provenance.
  - Seamless toggle between "Forensic Results" and "Live Pipeline DAG".
- `src/components/analysis/results/EvidenceDetailDrawer.tsx`:
  - Sliding drawer implementing accessible inspection of supporting evidence with raw JSON review and copy actions.
- `src/services/analysisResultsService.ts`:
  - Client service interacting with `/api/analysis/{run_id}/results` and evidence endpoints.
- `src/pages/investigation/sections/AnalysisSectionView.tsx`:
  - Updated with `'results'` as the primary default subtab alongside `'live'` DAG and forensic subsections.
- `src/components/analysis/LiveAnalysisView.tsx`:
  - Auto-switches to the `AnalysisResultsWorkstation` upon analysis completion (`COMPLETED` or `PARTIAL`), with a toggle to switch between DAG and Results views.
