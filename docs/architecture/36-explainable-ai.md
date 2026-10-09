# Section 27: Explainable AI (XAI)

## 1. Executive Summary & Purpose

CyberGuard operates across multiple specialized detection pipelines, correlation engines, behavioral baselines, threat memories, and attack path reconstruction systems. However, security analysts, incident responders, and executives must never encounter opaque, black-box decisions such as:
> *"Threat detected. Risk: 92. Reason: AI says this is malicious."*

Instead, CyberGuard provides a centralized, deterministic, evidence-backed explanation layer answering:
- **What happened?**
- **Why was it detected?**
- **Which evidence supports the conclusion?**
- **How strong is that evidence?**
- **Which detectors contributed?**
- **Are the signals independent or correlated?**
- **What contradicts the conclusion?**
- **What information is missing?**
- **How confident is the system?**
- **What would change the assessment?**

### The Core Architectural Principle: Decision vs. Explanation Separation
The Explainable AI layer **explains** CyberGuard’s decisions; it **does not make** those decisions. 
- The deterministic detection, correlation, and Section 26 Unified Risk Engine remain authoritative.
- The XAI layer receives authoritative outputs (`risk_score`, `risk_level`, `confidence`, `severity`, attack paths, MITRE techniques) and maps them to structured `ExplanationUnit` records grounded in concrete telemetry.
- It never recalculates risk, changes attack path topologies, or fabricates findings.

---

## 2. End-to-End XAI Architecture

```
Detection Engines (Email, URL, Auth, File, Net, API, Media)
    ↓
Structured Findings & Evidence Artifacts
    ↓
Correlation / Intelligence (Graph, Temporal, Cross-Incident)
    ↓
Unified Risk Assessment (Section 26 Authoritative Decision)
    ↓
XAI Evidence Graph Builder
    ↓
Explanation Composer (Deterministic Grounding, Ranking, Counter-Evidence)
    ↓
Grounding Validator & Strict LLM Synthesis Layer (Anti-Hallucination Guard)
    ↓
Progressive Disclosure (L1: Executive, L2: Analyst, L3: Investigator, L4: Forensic)
    ↓
Traceable Human-Readable Investigation Explanation & Report Integration
```

---

## 3. Explanation Data Model

The explainability model is represented in PostgreSQL/SQLite by `ExplanationModel`, with associated `ExplanationSnapshotModel` and `ExplanationFeedbackModel`:

```
Explanation
├── id (UUID)
├── workspace_id
├── scope_type (EVENT | INVESTIGATION | INCIDENT | CAMPAIGN | ENTITY | ATTACK_PATH | STAGE)
├── scope_id
├── explanation_version (1, 2, ...)
├── risk_assessment_id (authoritative link)
├── threat_event_id / incident_id
├── risk_score / risk_level / severity (authoritative cache)
├── confidence / confidence_level / uncertainty
├── summary / executive_summary / analyst_summary / generated_text
├── conclusions[] (Top-level authoritative claims)
├── explanation_units[] (Ordered, evidence-backed claims)
├── evidence_groups[] (Independent vs. correlated signal families)
├── contributors[] (Risk point contributions with correlation groups)
├── counter_evidence[] (Mitigating signals & passes)
├── contradictions[] (Conflicting telemetry and resolution status)
├── uncertainty_items[] (Explicit unknowns CyberGuard cannot assert)
├── limitations[] (Technical and forensic caveats)
├── missing_information[] (Unavailable data sources)
├── detector_contributions[] (Contributing engines, versions, statuses)
├── model_contributions[] (ML model names, calibrated confidences)
├── rule_contributions[] (Matched declarative rules & criteria)
├── mitre_explanations[] (Evidence-backed technique mappings)
├── attack_path_explanation (Stage sequence, continuity, bottlenecks)
├── assessment_change_guidance (What would strengthen / weaken assessment)
├── evidence_graph (Directed nodes & edges: Conclusion → Finding → Evidence → Artifact)
├── investigator_details / forensic_details
├── validation_status (GROUNDED_AND_VALIDATED | FALLBACK_DETERMINISTIC | REJECTED)
├── provenance (Source snapshot, analysis runs, hashes, timestamps)
└── created_at / updated_at
```

---

## 4. Explanation Unit & Claim Grounding

Every substantive explanation statement is encapsulated in an `ExplanationUnit`:

```json
{
  "id": "UNIT-001",
  "claim": "The sender identity exhibits a display-name mismatch against the executive profile.",
  "claim_type": "IDENTITY",
  "support_level": "VERY_HIGH",
  "evidence_refs": ["EV-102", "EV-103"],
  "source_refs": ["Email Analyzer v2.1"],
  "confidence": 0.94,
  "confidence_level": "VERY_HIGH",
  "limitations": ["Active internal directory sync was cached 2 hours ago"],
  "explanation_order": 1,
  "provenance": {
    "detector": "Digital Impersonation Engine",
    "version": "1.4.0",
    "artifact_id": "MSG-9921",
    "timestamp": "2026-10-09T09:12:00Z"
  }
}
```

### Claim Grounding Enforcement
1. **Never fabricate intent**: Do not generate *"The attacker intentionally targeted the CFO."* Prefer observable facts: *"The message impersonates the CFO identity profile."*
2. **Mandatory Backing**: Every claim must reference at least one existing `Evidence`, `Finding`, `RiskSignal`, `Relationship`, or `ThreatMemoryEntry`.
3. **Automated Grounding Validation**: The composer verifies that every `evidence_ref` resolves to a real record.

---

## 5. Traceable Evidence Graph

CyberGuard constructs a directed evidence graph linking high-level assessments back to physical raw telemetry:

```
                    ┌─────────────────────────┐
                    │       CONCLUSION        │
                    │  (e.g., Risk: CRITICAL) │
                    └────────────┬────────────┘
                                 │
                            supported_by
                                 ↓
                    ┌─────────────────────────┐
                    │         FINDING         │
                    │ (Identity Impersonation)│
                    └────────────┬────────────┘
                                 │
                            derived_from
                                 ↓
                    ┌─────────────────────────┐
                    │        EVIDENCE         │
                    │  (Display-Name Mismatch)│
                    └────────────┬────────────┘
                                 │
                            observed_in
                                 ↓
                    ┌─────────────────────────┐
                    │    ORIGINAL ARTIFACT    │
                    │     (Email Headers)     │
                    └─────────────────────────┘
```

When an analyst clicks any claim in the CyberGuard UI, the slide-over **Evidence Drawer** pivots directly from the claim down to the raw header, byte offset, IP packet, or process telemetry snippet.

---

## 6. Evidence Provenance

Forensic defensibility requires preserving complete provenance for every claim:
- `source`: Analyzer or telemetry collector
- `detector_version`: Version of the detection logic (e.g. `Email Analyzer v2.1`)
- `analysis_run_id`: Execution run tracking ID
- `artifact_id`: SHA-256 hash or object storage reference of the raw artifact
- `timestamp`: UTC observation timestamp
- `rule_version` / `model_version`: Exact commit or artifact version evaluated

Ordinary analysts receive clean summaries; forensic investigators can expand Level 4 to view complete provenance hashes.

---

## 7. Unified Risk Integration (Section 26)

The XAI layer consumes the output of Section 26 without recalculating anything:
- **Risk Score** (e.g. 87 / 100)
- **Risk Level** (e.g. CRITICAL)
- **Severity** (e.g. HIGH)
- **Confidence** (e.g. VERY_HIGH)
- **Uncertainty** (e.g. LOW)

### Explaining Risk Contributions
For each risk signal, the composer exposes:
- Primary contributor name
- Relative contribution in points (`+24 pts`)
- Source analyzer
- Plain-English reason
- Correlation group (explaining why a 2nd URL signal received a discounted weight)

---

## 8. Counter-Evidence & Signal Disagreements

A defensible explanation must never omit contradicting signals. CyberGuard explicitly identifies mitigating telemetry:

```
Evidence Supporting Threat:
• Sender domain visually resembles corporate login portal
• Embedded URL contains credential harvesting form
• Redirect chain through bulletproof hosting

Counter-Evidence (Mitigating Signals):
• SPF passed (sender IP authorized by domain SPF record)
• DKIM passed (cryptographic signature valid for envelope domain)
• Sender IP has legitimate historical traffic (observed 45 days prior)
```

Mitigating signals are assigned a `mitigation_strength` (`HIGH`, `MODERATE`, `WEAK`) explaining why the overall threat remains critical despite passing authentication checks.

---

## 9. Contradictions

Conflicting signals are recorded as structured `ContradictionRecord` objects:
- **Claim**: *"Message is impersonating Organization X."*
- **Conflicting Signal**: *"DKIM signature validates against sender domain."*
- **Resolution Status**: `PARTIALLY_RESOLVED`
- **Resolution Analysis**: *"Cryptographic authentication passes for the attacker's registered lookalike domain, but does not match the protected brand organization profile."*

---

## 10. Epistemic Unknowns & Missing Information

CyberGuard strictly differentiates between **SAFE** and **UNKNOWN**:
- If an endpoint agent is offline, CyberGuard does NOT say *"Attachment did not execute."*
- It explicitly reports:
  - **Unknown**: *"Attachment process execution state is unverified."*
  - **Reason**: *"Endpoint telemetry was unavailable at analysis time."*
  - **Impact**: *"The transition between attachment drop and suspicious outbound network traffic cannot be causally proven."*

### Missing Information Tracking
Identifies telemetry sources that would provide definitive confirmation:
- Endpoint EDR telemetry
- Passive DNS lookback
- Full corporate proxy logs

---

## 11. Technical & Forensic Limitations

Every explanation carries defensive caveats:
- *"Active HTTP payload verification was disabled to prevent attacker notification."*
- *"Only static PE file analysis was performed; dynamic sandbox execution timed out."*
- *"Infrastructure attribution is based on shared ASN/C2 certificates and does not identify human actor identity."*

---

## 12. Attack Path Sequence & Continuity

Attack path reconstruction (Sections 17–18) is converted into clear, sequential milestones:
1. Suspicious email delivered
2. Macro-enabled document opened
3. Child process spawned (`powershell.exe`)
4. C2 beacon initiated to novel external IP
5. Privilege escalation attempt observed

### Temporal vs. Causal Distinction
- If Event A occurs at 10:02 and Event B at 10:04 without process lineage proof, CyberGuard says:
  > *"Event B occurred shortly after Event A and is temporally correlated."*
- Causal language (*"Event A triggered Event B"*) is strictly reserved for verified parent-child execution or validated API trigger tokens.

---

## 13. MITRE ATT&CK Grounding

Mappings to MITRE ATT&CK techniques must be supported by direct evidence:
- **Technique**: T1078 (Valid Accounts)
- **Tactic**: Defense Evasion / Initial Access
- **Why Mapped**: *"Authentication originated from an IP in an anomalous country that deviates 4.2 standard deviations from the user's 90-day baseline."*
- **Mapping Status**: `SUPPORTED`
- **Evidence Refs**: `["EV-AUTH-091", "EV-BASE-014"]`

Techniques suggested by external LLMs without supporting telemetry are flagged as `UNVERIFIED_SUGGESTION` and excluded from authoritative reports.

---

## 14. Behavioral Baselines & Threat Memory

### Behavioral Deviation (Section 21)
Exposes baseline expectations vs. actual observations:
- Expected login hours: 08:00 – 19:00 UTC
- Observed login: 02:34 UTC
- Expected ASN: AS15169 (Google Corporate)
- Observed ASN: AS41378 (Commercial VPN Proxy)
- Baseline Quality: `STABLE` (120 days lookback)

### Threat Memory Context (Section 23)
Summarizes historical organizational encounters:
- Previous observations: 3 times in past 60 days
- Past resolutions: 2 confirmed phishing, 1 false positive dismissal
- Memory state: `CORRELATED_ACTIVE`

---

## 15. Novelty vs. Maliciousness (Section 22)

CyberGuard never equates novelty with malice:
- *"This API endpoint is novel for the subject service account (0 occurrences in 60-day baseline)."*
- *"Novelty is HIGH, but novelty alone does not establish malicious intent without accompanying anomaly signals."*

---

## 16. LLM Grounding, Validation & Deterministic Fallback

CyberGuard supports optional natural language synthesis using LLMs (e.g. Gemini / Claude), but treats LLM outputs as untrusted:

```
Structured CyberGuard Assessment & Evidence
                    ↓
Evidence-Constrained Prompt (Ground Truth Entity Whitelist)
                    ↓
LLM Narrative Synthesis
                    ↓
Regex & Entity Grounding Validator
   ├── Check 1: No unsupported IPv4/IPv6 addresses
   ├── Check 2: No unsupported domain names / FQDNs
   ├── Check 3: No unsupported SHA256 / MD5 hashes
   ├── Check 4: No hallucinated MITRE technique IDs (Txxxx)
   └── Check 5: No altered risk scores or confidence levels
                    ↓
[VALIDATION PASSED] ──→ Display LLM Narrative with "GROUNDED & VALIDATED" Badge
[VALIDATION FAILED] ──→ Revert to Deterministic Fallback Template & Log Alert
```

### Deterministic Fallback
If the LLM is unavailable, times out, or hallucinates an unsupported entity (e.g. mentions an IP not present in the evidence), CyberGuard automatically uses its deterministic explanation templates. **Report generation and UI display never fail.**

---

## 17. Progressive Disclosure UI (Levels 1 to 4)

CyberGuard avoids cognitive overload by structuring explanations into four progressive disclosure layers:

1. **Level 1 — Executive**:
   - 1-2 sentence executive briefing
   - Authoritative risk badge (`CRITICAL · Risk 87 · Confidence: Very High`)
   - Top 3 primary supported reasons
   - "What would change this assessment?" guidance
2. **Level 2 — Analyst**:
   - Detailed analyst summary
   - Structured risk contributors with point allocations
   - Counter-evidence and mitigating signals
   - Disagreements and signal contradictions
   - Epistemic unknowns and missing telemetry
3. **Level 3 — Investigator**:
   - Independent vs. correlated evidence families
   - Contributing detector systems and versions
   - Matched declarative detection rules and ML model confidences
   - Grounded MITRE ATT&CK techniques
   - Attack path stage sequences and transition continuity
4. **Level 4 — Forensic**:
   - Traceable evidence graph topology
   - Complete forensic claims registry
   - Defensibility limitations and technical caveats
   - Raw provenance hashes, timestamps, and execution run IDs

---

## 18. Analyst Feedback & Explanation Versioning

- **Analyst Disagreement**: Analysts can record feedback (`ANALYST_CONFIRMED`, `ANALYST_DISMISSED`, `ANALYST_CORRECTED`, `ANALYST_COMMENT`) with investigative justifications.
- **Immutability**: Analyst feedback does not overwrite historical explanations; it is recorded alongside them.
- **Versioning**: If new telemetry arrives, CyberGuard creates `Explanation v2`, preserving `v1` in `ExplanationSnapshotModel`.
- **Court-Admissible Snapshots**: PDF reports embed an exact frozen explanation snapshot.

---

## 19. Privacy & Secret Redaction

Before storing or displaying explanations, the `ExplanationComposer` runs automated secret redaction:
- API keys, Bearer tokens, private keys (`-----BEGIN PRIVATE KEY-----`), password parameters (`password=...`), and session cookies are replaced with `[REDACTED_SECRET]`.

---

## 20. Explanation Quality Metrics

CyberGuard tracks internal explainability metrics:
- **Evidence Coverage**: % of findings with at least one linked evidence artifact ($100\%$)
- **Claim Grounding Rate**: % of claims referencing valid evidence ($100\%$)
- **Unsupported Claim Rate**: % of rejected claims ($0\%$)
- **LLM Fallback Rate**: Frequency of fallback to deterministic templates
- **Provenance Resolution Rate**: % of claims with intact detector/run IDs ($100\%$)

---

## 21. Worked Examples

### Worked Example 1: Phishing & Identity Impersonation
- **Scope**: Email Event `EVT-PHISH-01`
- **Authoritative Risk**: Score 88, Level `CRITICAL`, Confidence `VERY_HIGH` (0.92)
- **Primary Reasons**:
  1. Sender display name `"CEO John Doe"` mismatches envelope address `ceo-update@secure-login-portal.com`.
  2. Embedded URL `https://login.micros0ft-auth.com/token` uses typo-squatting lookalike against protected brand.
  3. Destination web page contains credential harvesting form targeting corporate SSO.
- **Counter-Evidence**: SPF passed for IP `198.51.100.22` (the attacker owned the sending infrastructure).
- **Contradiction**: Authentication passed, but domain ownership does not belong to Microsoft.
- **Guidance**: Assessment would strengthen if user entered credentials; would weaken if domain is an internal authorized simulation.

### Worked Example 2: Account Takeover (ATO)
- **Scope**: Authentication Event `EVT-ATO-42`
- **Authoritative Risk**: Score 82, Level `HIGH`, Confidence `HIGH` (0.85)
- **Primary Reasons**:
  1. 32 failed password attempts within 4 minutes preceding successful authentication (credential stuffing pattern).
  2. Successful login originated from ASN in Nigeria; historical 90-day baseline for user is 100% United States.
  3. Successful login immediately registered a new FIDO2 bypass authenticator.
- **Missing Telemetry**: Endpoint browser user-agent fingerprinting was partially masked by Cloudflare WARP.
- **MITRE Mapping**: T1110 (Brute Force) & T1078 (Valid Accounts).

### Worked Example 3: Multi-Stage Attack Path
- **Scope**: Incident `INC-APT-904`
- **Authoritative Risk**: Score 94, Level `CRITICAL`, Confidence `VERY_HIGH` (0.95)
- **Attack Sequence**:
  1. Phishing email delivered (`10:14:02 UTC`)
  2. Macro executed in Word attachment (`10:17:15 UTC`)
  3. `cmd.exe` spawned `curl.exe` to retrieve remote staging script (`10:17:28 UTC`)
  4. Scheduled task persistence created (`10:18:01 UTC`)
- **Continuity**: `VERY_HIGH` (Process GUID links step 2 to step 3).
- **Attribution Boundary**: C2 IP `203.0.113.88` matches infrastructure previously linked to UNC3890; human actor attribution remains `UNVERIFIED`.

---

## 22. API Endpoints Reference

All endpoints are mounted under `/api/v1/explanation`:

| Endpoint | Method | Description |
|---|---|---|
| `/by-scope/{scope_type}/{scope_id}` | GET | Retrieve latest structured explanation for target scope |
| `/{explanation_id}` | GET | Retrieve explanation by primary key |
| `/compose` | POST | Compose new evidence-backed explanation from authoritative assessment |
| `/{explanation_id}/layers/{layer}` | GET | Progressive disclosure view (`EXECUTIVE`, `ANALYST`, `INVESTIGATOR`, `FORENSIC`) |
| `/{explanation_id}/graph` | GET | Retrieve full evidence graph topology (nodes and edges) |
| `/{explanation_id}/evidence-chain` | GET | Retrieve ordered evidence units with provenance |
| `/{explanation_id}/contributors` | GET | Retrieve risk point contributors and correlation groups |
| `/{explanation_id}/contradictions` | GET | Retrieve signal contradictions and resolution notes |
| `/{explanation_id}/uncertainty` | GET | Retrieve epistemic unknowns and missing telemetry |
| `/{explanation_id}/feedback` | POST | Record analyst confirmation, dismissal, correction, or note |
| `/{explanation_id}/snapshot` | POST | Create frozen immutable snapshot for reports and audits |
| `/generate-narrative` | POST | Synthesize LLM narrative with strict entity-grounding validation |
| `/metrics` | GET | Retrieve explainability quality metrics |

---

## 23. Conclusion

Section 27 establishes CyberGuard as an explainable, forensically defensible cybersecurity platform. By separating decision-making from explanation, grounding every claim in immutable telemetry, exposing counter-evidence and epistemic unknowns, and enforcing strict anti-hallucination validation on LLM narratives, CyberGuard empowers security teams to understand, verify, and defend every alert.
