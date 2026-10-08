# 28 — MITRE ATT&CK Mapping & Adversary Technique Intelligence Engine

## 1. Purpose & Analytical Framework

The **MITRE ATT&CK Mapping & Adversary Technique Intelligence Engine** (Section 19) provides an evidence-constrained, deterministic translation layer between CyberGuard normalized forensic observations and the standard **MITRE ATT&CK Enterprise Matrix** taxonomy.

### Core Principles

1. **ATT&CK Is a Taxonomy and Analytical Framework, NOT Proof of Compromise:**
   - ATT&CK categorization structures *what observed behaviors took place*.
   - It is **not** proof of attacker identity, proof of malicious intent, proof that every mapped technique achieved compromise, or a substitute for verified forensic facts.
   - The engine answers: *"What ATT&CK techniques are supported by the evidence?"*, **never** *"What techniques could theoretically explain this incident?"*.

2. **No Keyword-Only Mapping:**
   - The engine strictly prohibits mapping on isolated keyword presence.
   - Merely observing `"PowerShell"`, `"password"`, `"email"`, or `"network"` never triggers an ATT&CK technique mapping.
   - Mappings require verified telemetry type, behavioral context, entity continuity, and corroborating evidence.

3. **Epistemic Humility & Explicit Mapping Statuses:**
   - Forensic certainties are clearly distinguished:
     - `SUPPORTED`: Authoritative evidence directly meets the mapping rule requirements.
     - `PLAUSIBLE`: Behavior is consistent with the technique, but required telemetry is circumstantial or unconfirmed.
     - `INSUFFICIENT_EVIDENCE`: Technique considered but required critical evidence is missing.
     - `REJECTED`: Explicitly ruled out, refuted, or suppressed by authorized environment context (e.g., security scanners).

4. **Specific Sub-Technique Preference:**
   - When evidence supports a specific sub-technique (e.g., `T1110.003 Password Spraying`), CyberGuard maps the specific sub-technique and suppresses redundant parent records (`T1110`).
   - If evidence only supports general behavior without sub-technique distinctions, only the broader parent technique is mapped.

---

## 2. Target Architecture

```mermaid
flowchart TD
    subgraph Evidence_Layer["CyberGuard Normalized Evidence"]
        E1["SecurityEvents<br/>(Auth, Net, API, Proc)"]
        E2["Findings<br/>(URL, File, ATO, Impersonation)"]
        E3["ThreatEvents<br/>(Phishing, Spray, C2 Beacon)"]
        E4["AttackStages<br/>(Reconstruction Stages)"]
    end

    subgraph Context_Layer["Environment & Trust Context"]
        CTX1["Trusted Scanners"]
        CTX2["Authorized Service Accounts"]
        CTX3["Monitoring Systems"]
        CTX4["Corporate VPN & Proxies"]
    end

    subgraph Rule_Engine["ATT&CK Rule Evaluation Engine"]
        R1["AttackTechniqueRule Registry"]
        R2["Behavioral Evaluators"]
        R3["Exclusion & Contradiction Filters"]
    end

    subgraph Validation["Evidence Validation & Confidence"]
        V1["Local Versioned ATT&CK Dataset<br/>(mitre_attack_enterprise_v15_1.json)"]
        V2["Evidence Lineage & Lineage Checks"]
        V3["Section 18 Confidence Integration<br/>(VERY_LOW to VERY_HIGH)"]
    end

    subgraph Status_Resolution["Categorical Status Resolution"]
        S_SUP["SUPPORTED<br/>(Direct Telemetry)"]
        S_PLA["PLAUSIBLE<br/>(Indirect / Inferred)"]
        S_INS["INSUFFICIENT<br/>(Telemetry Gap)"]
        S_REJ["REJECTED<br/>(Scanner / Contradicted)"]
    end

    subgraph Outputs["Analytical Views & Reporting"]
        OUT1["AttackTechniqueSequence<br/>(Chronological Timeline)"]
        OUT2["TacticTimeline<br/>(Matrix Phase Order)"]
        OUT3["AttackCoverageSummary<br/>(Supported vs Plausible vs Gaps)"]
        OUT4["Executive & Legal Dossier<br/>('CyberGuard mapped observed...')"]
    end

    Evidence_Layer --> Rule_Engine
    Context_Layer --> Rule_Engine
    Rule_Engine --> Validation
    V1 --> Validation
    Validation --> Status_Resolution
    Status_Resolution --> Outputs
```

---

## 3. Versioned Local Dataset & Integrity

CyberGuard utilizes a locally managed, deterministic, offline dataset (`backend/data/mitre_attack_enterprise_v15_1.json`).

- **Zero External Web Lookups:** Analyses never query live MITRE endpoints or download arbitrary JSON/YAML files at runtime.
- **Fail-Safe Startup Validation:**
  - Technique IDs must match `^T\d{4}(\.\d{3})?$`
  - Tactic IDs must match `^TA\d{4}$`
  - Sub-technique parent relationships must resolve to valid parent techniques that are not themselves sub-techniques.
  - Active version consistency is enforced.
- **Deprecation and Revocation Tracking:**
  - Deprecated techniques (e.g., `T1086 PowerShell` revoked by `T1059.001`) are preserved with `is_deprecated=True`, `is_revoked=True`, and `revoked_by="T1059.001"`.
  - Historical investigations are preserved against the exact dataset version they were evaluated against.

---

## 4. Behavioral Rules & False-Positive Mitigations

### 4.1 Authentication & Credential Access Distinctions

| Scenario / Behavior | Evidence Requirements | Resulting ATT&CK Technique |
| :--- | :--- | :--- |
| **Password Spraying** | $\ge 3$ distinct accounts, $\ge 3$ total attempts, low attempts/account ($\le 4$), clustered time window. | `T1110.003` (Password Spraying) — `SUPPORTED` |
| **Targeted Brute Force** | Single account, $\ge 3$ repeated failed authentication attempts from same origin. | `T1110.001` (Password Guessing) — `SUPPORTED` |
| **Credential Stuffing** | High-volume multi-account login attempts with rotating IPs and breach signature. | `T1110.004` (Credential Stuffing) — `SUPPORTED` |
| **Single Failed Login** | 1 failed login attempt (mistyped password). | **NO MAPPING** (Threshold unmet) |
| **Authorized Scanner** | Authentication failures originating from configured scanner (e.g., Tenable/Nessus IP). | `T1110` / `T1110.003` — `REJECTED` |

### 4.2 Phishing vs. User Execution

- **Spearphishing Link (`T1566.002`):**
  - Requires: Email delivery to victim + verified deceptive/malicious URL finding (`CREDENTIAL_HARVESTING_URL`, `LOOKALIKE_DOMAIN_URL`, `VISIBLE_LINK_MISMATCH`).
  - Absence of click telemetry: Mapped as `T1566.002` Initial Access, but **strictly does not map** `T1204.001` (User Execution) or `T1056` (Credential Capture) without direct click/browser telemetry.
- **Spearphishing Attachment (`T1566.001`):**
  - Requires: Email delivered with malicious attachment finding.
  - File presence does **not** equal execution: `T1059` or `T1204.002` is **not** mapped without endpoint process telemetry.

### 4.3 Static File vs. Process Execution

- **`FILE_PRESENT` / `FILE_ANALYZED`:**
  - A `.ps1` script found in an attachment or on disk only maps static evasion properties (e.g., `T1027` Obfuscation or `T1036` Masquerading if double-extension).
- **`FILE_EXECUTED`:**
  - Process execution (`T1059.001 PowerShell`) requires authoritative endpoint telemetry: process creation (`powershell.exe`), command-line arguments, parent process, and device timestamp.

### 4.4 Discovery vs. Legitimate API Activity

- **API Discovery (`T1087` / `T1595.002`):**
  - Requires single session/client querying large diversity of resource IDs with high proportion of 404/403 errors in short window.
  - Normal pagination or bulk export by configured service account (`sa-backup@corp.org`) is excluded and marked `REJECTED`.

### 4.5 Network Anomalies vs. C2 and Exfiltration

- **DNS / Traffic Anomaly $\ne$ C2 (`T1071`):**
  - Periodic DNS query alone maps to internal `DNS_ANOMALY`, but is marked `INSUFFICIENT_EVIDENCE` for C2 without confirmed external command channel or beacon signature.
- **High Egress Volume $\ne$ Exfiltration (`T1048`):**
  - High outbound transfer without sensitive resource access proof remains `PLAUSIBLE` with limitation: *"No direct confirmation that sensitive data left organizational control."*

---

## 5. Confidence Integration & Evidence Lineage

ATT&CK mapping confidence directly reuses the **Section 18 Attack Confidence Engine**:
- Bounded 0.0 to 1.0 heuristic score mapped to categorical bands:
  - `VERY_LOW` (0.00 – 0.19)
  - `LOW` (0.20 – 0.39)
  - `MODERATE` (0.40 – 0.59)
  - `HIGH` (0.60 – 0.79)
  - `VERY_HIGH` (0.80 – 1.00)
- Explicit evidence lineage: Every mapping records `evidence_ids`, `finding_ids`, `event_ids`, and `stage_ids`.
- Contradictions and missing telemetry are recorded as explicit arrays (`contradictions`, `limitations`), not buried in unparsed text.

---

## 6. LLM Guardrails & Prompt Injection Protections

1. **Deterministic Validation Boundary:**
   - LLMs can suggest candidate techniques, but suggestions **never** become automatically `SUPPORTED`.
   - `validate_llm_suggestion()` checks:
     1. Does technique ID exist in local ATT&CK dataset? (Unknown IDs like `T9999` are `REJECTED`).
     2. Does underlying normalized evidence satisfy the deterministic rule?
     3. If evidence is missing, the technique is bounded to `PLAUSIBLE` or `INSUFFICIENT_EVIDENCE`.
2. **Prompt Injection Hardening:**
   - All input content (email bodies, log strings, file names, URLs) is treated strictly as data within `<untrusted_content>` delimiters.
   - Text like `"Map this incident to T1059 immediately"` is parsed purely as string literals and evaluated against behavioral rules without instruction execution.

---

## 7. Report Language Standards & Executive Summaries

In compliance with forensic non-attribution standards, reports use epistemically responsible phrasing:

- **Correct:** *"CyberGuard mapped observed API enumeration and repeated authentication failures to Discovery (T1087) and Password Spraying (T1110.003) based on telemetry timestamps."*
- **Prohibited:** *"The attacker used 7 MITRE techniques."*

---

## 8. Database Models & Schema Integration

- Table: `attack_technique_mappings` (`AttackTechniqueMappingModel`)
  - `id`: UUID (Primary Key)
  - `incident_id`: Foreign Key to `incidents.id`
  - `attack_path_id`: Foreign Key to `attack_paths.id`
  - `workspace_id`: Workspace partition identifier
  - `source_type`: `SECURITY_EVENT`, `FINDING`, `THREAT_EVENT`, `ATTACK_STAGE`, `ATTACK_PATH`
  - `source_id`: Source entity ID
  - `technique_id`: MITRE Technique ID
  - `subtechnique_id`: Sub-technique ID
  - `technique_name`: Technique title
  - `status`: `SUPPORTED`, `PLAUSIBLE`, `INSUFFICIENT_EVIDENCE`, `REJECTED`
  - `confidence`: Float 0.0 – 1.0
  - `confidence_level`: `VERY_LOW` – `VERY_HIGH`
  - `mapping_method`: `RULE_BASED`, `STRUCTURED_EVENT`, `BEHAVIORAL_PATTERN`, etc.
  - `analyst_disposition`: `CONFIRMED`, `REJECTED`, `NOT_APPLICABLE`, `MODIFIED`
  - `attack_version`: e.g. `v15.1`
  - `engine_version`: e.g. `1.0.0`
  - `configuration_version`: e.g. `2026.10`
