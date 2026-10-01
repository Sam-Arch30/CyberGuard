# 11 — Unified CyberGuard Data Model Architecture

> **Architecture Stage:** Section 2 — Canonical Data Foundation  
> **Database Engines:** PostgreSQL 16 (Production) / SQLite 3 (Local / Testing)  
> **ORM Framework:** SQLAlchemy 2.0.52 (Declarative Base, timezone-aware UTC)  
> **Migration Manager:** Alembic 1.19.2 (Revision `b7e2a901c43f`)  

---

## 1. Primary Objective & Purpose

The **Unified CyberGuard Data Model** establishes a canonical, normalized cybersecurity data foundation across all ingestion channels and analyzers. CyberGuard is designed to ingest and analyze diverse forensic artifacts:

- Emails (`.eml`, RFC-822)
- URLs & Domains
- IP Addresses & ASN infrastructure
- File Binaries & Suspicious Attachments
- Images, Audio, and Video (deepfake / steganography telemetry)
- QR Codes & Visual Phishing Vectors
- Authentication, API, System, and Network Logs
- Endpoint Telemetry Events

Prior to Section 2, CyberGuard's data was centered exclusively on email-specific tables (`evidence`, `email_analyses`, `analysis_payloads`). The unified data model resolves this by creating canonical entities that decouple ingestion channels from analytical detection engines, while preserving **100% backward compatibility** with existing legacy routes.

The normalized pipeline follows this canonical flow:

$$\text{Artifact} \longrightarrow \text{AnalysisRun} \longrightarrow \text{Finding} \longrightarrow \text{Evidence / Indicator / Entity} \longrightarrow \text{Relationship} \longrightarrow \text{ThreatEvent} \longrightarrow \text{Incident} \longrightarrow \text{AttackPath} \longrightarrow \text{ResponseAction}$$

---

## 2. Core Entity-Relationship Diagram

```mermaid
erDiagram
    artifacts ||--o{ artifacts : "parent-child (e.g. email->attachment)"
    artifacts ||--o{ analysis_runs : "analyzed by"
    artifacts ||--o{ threat_events : "originates"
    artifacts ||--o{ finding_evidence : "references"

    analysis_runs ||--o{ findings : "produces"
    analysis_runs ||--o{ threat_events : "generates"
    analysis_runs ||--o{ relationships : "derives"

    model_versions ||--o{ findings : "provenance"

    findings ||--o{ finding_evidence : "supported by"

    incidents ||--o{ threat_events : "contains"
    incidents ||--o{ response_actions : "triggers"
    incidents ||--o{ attack_paths : "hypothesizes"

    threat_events ||--o{ response_actions : "mitigates"

    attack_paths ||--o{ attack_stages : "sequences"
    attack_paths ||--o{ attack_edges : "connects"

    artifacts {
        string id PK "UUID-36"
        string artifact_type "EMAIL, FILE, URL, DOMAIN, IP, ATTACHMENT, etc."
        string name "Filename, URL, or descriptor"
        string source "UPLOAD, API, EXTRACTION, NETWORK"
        string mime_type "message/rfc822, application/pdf, etc."
        integer size "Exact byte count"
        string sha256 IX "Cryptographic SHA-256 integrity hash"
        string sha1 "Optional SHA-1"
        string md5 "Optional MD5"
        string storage_reference "Filesystem or object storage path"
        string parent_artifact_id FK "artifacts.id (SET NULL)"
        datetime ingested_at IX "UTC timestamp"
        text metadata_json "Sanitized contextual attributes"
        datetime created_at
        datetime updated_at
    }

    analysis_runs {
        string id PK "UUID-36"
        string artifact_id FK "artifacts.id (CASCADE)"
        string status IX "QUEUED, RUNNING, COMPLETED, PARTIAL, FAILED, CANCELLED"
        datetime started_at
        datetime completed_at
        string trigger "USER, AUTOMATIC, REANALYSIS, CORRELATION, SYSTEM"
        string pipeline_version "Semantic version"
        float overall_risk_score "0.0 - 100.0"
        string overall_severity IX "SAFE, LOW, MEDIUM, HIGH, CRITICAL"
        float confidence "0.0 - 1.0"
        text error "Failure diagnostics"
        text metadata_json
        datetime created_at
    }

    findings {
        string id PK "UUID-36"
        string analysis_run_id FK "analysis_runs.id (CASCADE)"
        string analyzer IX "Analyzer class/module identifier"
        string finding_type IX "e.g. lookalike_domain, spf_failure, credential_harvesting"
        string title "Concise executive title"
        text description "Technical analytical finding"
        string severity IX "SAFE, LOW, MEDIUM, HIGH, CRITICAL"
        float confidence "0.0 - 1.0"
        float risk_contribution "0.0 - 100.0"
        string method IX "RULE, HEURISTIC, ML, LLM, EXTERNAL_INTELLIGENCE, STATISTICAL, GRAPH, MANUAL, HYBRID"
        string model_version_id FK "model_versions.id (SET NULL)"
        string rule_id "Deterministic rule identifier"
        text metadata_json
        datetime created_at
    }

    finding_evidence {
        string id PK "UUID-36"
        string finding_id FK "findings.id (CASCADE)"
        string evidence_type IX "OBSERVED_VALUE, SIMILARITY_RATIO, ML_PROBABILITY, etc."
        string source "Detection component or OSINT feed"
        string key IX "Evidence metric key"
        text value "Machine-readable fact / value"
        float confidence "0.0 - 1.0"
        string artifact_id FK "artifacts.id (SET NULL)"
        datetime timestamp "UTC observation timestamp"
        text metadata_json
        datetime created_at
    }

    indicators {
        string id PK "UUID-36"
        string indicator_type IX "IP, DOMAIN, URL, EMAIL_ADDRESS, FILE_HASH, etc."
        text value "Forensic raw literal value"
        string normalized_value IX "Canonical normalized indexed representation"
        datetime first_seen IX
        datetime last_seen IX
        float confidence "0.0 - 1.0"
        string reputation IX "MALICIOUS, SUSPICIOUS, NEUTRAL, BENIGN, UNKNOWN"
        text metadata_json
        datetime created_at
        datetime updated_at
    }

    entities {
        string id PK "UUID-36"
        string entity_type IX "USER, ACCOUNT, DEVICE, HOST, ORGANIZATION, BRAND, etc."
        string name IX "Canonical entity name"
        string external_id IX "Identity provider or CMDB ID"
        text attributes_json
        datetime first_seen
        datetime last_seen
        datetime created_at
        datetime updated_at
    }

    relationships {
        string id PK "UUID-36"
        string source_type IX "ARTIFACT, INDICATOR, ENTITY, INCIDENT"
        string source_id IX "Foreign identifier"
        string relationship_type IX "CONTAINS, REFERENCES, RESOLVES_TO, COMMUNICATES_WITH, etc."
        string target_type IX "ARTIFACT, INDICATOR, ENTITY, INCIDENT"
        string target_id IX "Foreign identifier"
        float confidence "0.0 - 1.0"
        datetime first_seen
        datetime last_seen
        string evidence_reference "Citation or proof reference"
        string analysis_run_id FK "analysis_runs.id (SET NULL)"
        string method "RULE, HEURISTIC, ML, etc."
        text metadata_json
        datetime created_at
        datetime updated_at
    }

    threat_events {
        string id PK "UUID-36"
        string event_type IX "phishing_attempt, malware_delivery, credential_harvesting"
        datetime timestamp IX "UTC event timestamp"
        string source_artifact_id FK "artifacts.id (SET NULL)"
        string analysis_run_id FK "analysis_runs.id (SET NULL)"
        string severity IX "SAFE, LOW, MEDIUM, HIGH, CRITICAL"
        float risk_score "0.0 - 100.0"
        float confidence "0.0 - 1.0"
        string status IX "OPEN, INVESTIGATING, CONFIRMED, DISMISSED, MITIGATED"
        text summary "Human-readable event summary"
        string incident_id FK "incidents.id (SET NULL)"
        text metadata_json
        datetime created_at
        datetime updated_at
    }

    incidents {
        string id PK "UUID-36"
        string incident_number UK "INC-YYYY-XXXXXX"
        string title "Incident title"
        text description "Investigation scope & overview"
        string status IX "OPEN, INVESTIGATING, CONTAINED, RESOLVED, CLOSED, FALSE_POSITIVE"
        string severity IX "SAFE, LOW, MEDIUM, HIGH, CRITICAL"
        float risk_score "0.0 - 100.0"
        float confidence "0.0 - 1.0"
        datetime opened_at
        datetime closed_at
        string assigned_to "Analyst or SOC team"
        string legacy_case_id IX "Link to legacy cases.id"
        text metadata_json
        datetime created_at
        datetime updated_at
    }

    response_actions {
        string id PK "UUID-36"
        string incident_id FK "incidents.id (CASCADE)"
        string threat_event_id FK "threat_events.id (SET NULL)"
        string action_type IX "QUARANTINE_EMAIL, BLOCK_URL, BLOCK_DOMAIN, BLOCK_IP, etc."
        text description "Prescriptive defensive action description"
        string status IX "RECOMMENDED, PENDING_APPROVAL, APPROVED, EXECUTING, COMPLETED, FAILED, REJECTED"
        string priority "LOW, MEDIUM, HIGH, CRITICAL"
        string recommended_by "CyberGuard Engine or Analyst"
        string approved_by "Authorizing Commander"
        string executed_by "Automation driver or Analyst"
        datetime created_at
        datetime approved_at
        datetime executed_at
        text metadata_json
    }

    model_versions {
        string id PK "UUID-36"
        string model_name IX "e.g. cyberguard-nlp-phishing-classifier"
        string model_type IX "NLP_CLASSIFIER, ATTRIBUTION_ENGINE, LOOKALIKE_DETECTOR"
        string version IX "Semantic version (e.g. 1.0.0)"
        string provider "scikit-learn, internal, openai, etc."
        string training_dataset_reference "Reference to weights or dataset"
        text metrics_json "F1 score, precision, recall, confusion matrix"
        string status IX "CANDIDATE, VALIDATING, ACTIVE, RETIRED, REJECTED"
        datetime deployed_at
        text metadata_json
        datetime created_at
    }

    attack_paths {
        string id PK "UUID-36"
        string incident_id FK "incidents.id (CASCADE)"
        string name "Attack progression hypothesis"
        text description
        float confidence "0.0 - 1.0"
        string status "HYPOTHESIS, VALIDATED, MITIGATED"
        text metadata_json
        datetime created_at
        datetime updated_at
    }

    attack_stages {
        string id PK "UUID-36"
        string attack_path_id FK "attack_paths.id (CASCADE)"
        integer stage_order "1, 2, 3..."
        string technique_id IX "MITRE ATT&CK ID (e.g. T1566.002)"
        string tactic "Initial Access, Execution, Persistence, etc."
        string name "Stage title"
        text description
        string status "SUSPECTED, CONFIRMED, REMEDIATED"
        text metadata_json
        datetime created_at
    }

    attack_edges {
        string id PK "UUID-36"
        string attack_path_id FK "attack_paths.id (CASCADE)"
        string source_stage_id FK "attack_stages.id (CASCADE)"
        string target_stage_id FK "attack_stages.id (CASCADE)"
        string relationship_type "LEADS_TO, TRIGGERS, ESCALATES"
        float confidence "0.0 - 1.0"
        text metadata_json
        datetime created_at
    }
```

---

## 3. Strict Separation of Concerns (Core Design Principle)

CyberGuard strictly isolates and categorizes security information:

| Level | Concept | Description | Corresponding Canonical Model |
|---|---|---|---|
| **Level 0** | **RAW INPUT** | Untouched digital object received or discovered | `ArtifactModel` |
| **Level 1** | **OBSERVED FACT** | Objective, machine-readable forensic fact | `FindingEvidenceModel` |
| **Level 2** | **DERIVED FINDING** | Analytical conclusion reached by an analyzer | `FindingModel` |
| **Level 3** | **AI / ML INTERPRETATION** | Probabilistic hypothesis or language inference | `FindingModel` (`method=ML` / `LLM`) |
| **Level 4** | **CORRELATION / GRAPH** | Link between artifacts, observables, and entities | `RelationshipModel` |
| **Level 5** | **INCIDENT** | Aggregated security event cluster requiring SOC action | `IncidentModel` & `ThreatEventModel` |
| **Level 6** | **RESPONSE** | Prescriptive defensive playbook action | `ResponseActionModel` |

### Example Walkthrough

1. **Raw Input:** An `.eml` file is uploaded. Stored as `ArtifactModel(type="EMAIL", sha256="a1b2...", storage_reference="eml_store/EVD-01.eml")`.
2. **Observed Fact:** SPF validation fails for sender domain `micros0ft-update.example`. Stored as `FindingEvidenceModel(source="SPF_VERIFIER", key="result", value="fail")`.
3. **Derived Finding:** Authentication analyzer generates a conclusion: `FindingModel(analyzer="AuthenticationAnalyzer", title="Email Authentication Failed", severity="HIGH", method="RULE")`.
4. **AI Interpretation:** NLP classifier detects urgency cues and computes a 94.2% phishing probability: `FindingModel(analyzer="NLPClassifier", method="ML", confidence=0.942, model_version_id=nlp_mv.id)`.
5. **Correlation / Graph:** Knowledge graph records that the email contains an executable attachment and references a phishing domain: `RelationshipModel(source=email.id, relationship_type="REFERENCES", target=norm_url)`.
6. **Incident:** A normalized `ThreatEventModel(event_type="phishing_attempt", risk_score=88.5, severity="HIGH")` is created and associated with `IncidentModel(incident_number="INC-2026-000001")`.
7. **Response:** A recommended action `ResponseActionModel(action_type="QUARANTINE_EMAIL", status="RECOMMENDED", priority="HIGH")` is queued for analyst review.

---

## 4. Normalization & Deduplication Rules

### 4.1 Domains
- Standardized to lowercase.
- URL schemes (`https://`, `http://`), ports, and trailing dots are stripped.
- Example: `"  HTTPS://ExAmPlE.CoM.:8080/  "` $\longrightarrow$ `"example.com"`.

### 4.2 IP Addresses
- Standardized via Python's `ipaddress` module to canonical IPv4 / IPv6 notation.
- Octets with leading zeros (e.g. `192.002.001.001`) are normalized to `192.2.1.1`.
- Raw literal representation is preserved in `IndicatorModel.value`, while canonical representation is indexed in `IndicatorModel.normalized_value`.

### 4.3 URLs
- Scheme and netloc are lowercased; paths, queries, and fragments are preserved.
- Standardized via `urllib.parse.urlsplit` / `urlunsplit`.
- Example: `"HTTPS://ExAmPlE.CoM/Login?token=ABC#top"` $\longrightarrow$ `"https://example.com/Login?token=ABC#top"`.

### 4.4 Cryptographic Hashes
- Standardized to stripped lowercase hexadecimal strings.
- Example: `" E3B0C442... "` $\longrightarrow$ `"e3b0c442..."`.

### 4.5 Email Addresses
- Stripped, domain part lowercased, local mailbox part preserved.
- Example: `" User.Name@SUB.EXAMPLE.COM "` $\longrightarrow$ `"User.Name@sub.example.com"`.

### 4.6 Deduplication Guarantee
`IndicatorModel` enforces a composite unique database index:
$$\text{Index}("ix\_indicators\_type\_norm", [\text{indicator\_type}, \text{normalized\_value}], \text{unique}=\text{True})$$
When a known indicator is re-observed, `IndicatorService.upsert_indicator` updates `last_seen`, refreshes reputation, and updates confidence without creating redundant rows.

---

## 5. Provenance & Method Model

Every `FindingModel` answers the 6 mandatory forensic provenance questions:

1. **Who/What produced this?** $\longrightarrow$ `analyzer` (e.g., `AuthenticationAnalyzer`, `LookalikeDetector`, `NLPClassifier`, `AttributionEngine`).
2. **When?** $\longrightarrow$ `created_at` (timezone-aware UTC).
3. **From which input?** $\longrightarrow$ `analysis_run_id` $\longrightarrow$ `artifact_id` $\longrightarrow$ `storage_reference` & `sha256`.
4. **Using which method?** $\longrightarrow$ `method` (`RULE`, `HEURISTIC`, `ML`, `LLM`, `EXTERNAL_INTELLIGENCE`, `STATISTICAL`, `GRAPH`, `MANUAL`, `HYBRID`).
5. **Using which model/rule?** $\longrightarrow$ `model_version_id` (foreign key to `model_versions`) or `rule_id` (e.g., `RULE-AUTH-RFC7489`).
6. **What facts support it?** $\longrightarrow$ `evidence_items` (`FindingEvidenceModel` records storing exact values, keys, sources, and confidences).

---

## 6. Service Layer Architecture

The database models are wrapped by a clean service layer in `backend/services/unified_service.py`:

- **`ArtifactService`**: Creation, hash deduplication, parent-child artifact trees, and retrieval by ID or SHA-256.
- **`AnalysisService`**: Manages AnalysisRun lifecycle (`create_analysis_run`, `complete_analysis_run`, `fail_analysis_run`, `list_runs_for_artifact`).
- **`FindingService`**: Registers analytical findings and associates granular evidence items.
- **`IndicatorService`**: Automated normalization, deduplication, and reputation indexing for IOCs.
- **`EntityService`**: Tracks higher-level security entities (Users, Devices, Hosts, Brands, Organizations).
- **`RelationshipService`**: Creates directed edges in the Security Knowledge Graph (`CONTAINS`, `REFERENCES`, `RESOLVES_TO`, `COMMUNICATES_WITH`).
- **`ThreatEventService`**: Normalizes security events across multi-vector sources.
- **`IncidentService`**: Incident container management, event correlation, and defensive `ResponseAction` queuing.
- **`ModelVersionService`**: Registers ML/LLM model versions, F1 metrics, and deployment provenance.

---

## 7. EML Integration & Dual-Write Architecture

During Section 2, CyberGuard employs a **non-destructive dual-write transition**:

1. When an `.eml` file is uploaded to `POST /api/emails/analyze`:
   - Legacy persistence completes first: `AuditService.record_evidence()`, disk `.eml` saving, `DashboardService.record_email_analysis()`, `AnalysisPayloadModel` save, and `CampaignService` registration.
   - The dual-write adapter `UnifiedIngestionAdapter.ingest_email_analysis()` is executed within the same session.
2. The adapter maps the analyzed email into:
   - Primary `Artifact(type=EMAIL)`
   - Child `Artifact(type=ATTACHMENT)` for each MIME attachment
   - `AnalysisRun(status=COMPLETED, overall_risk_score, overall_severity)`
   - Granular `Finding` records (Authentication rules, Lookalike heuristics, NLP ML intent, URL scoring, Threat Attribution)
   - Machine-readable `FindingEvidence` records for every observation
   - Normalized and deduplicated `Indicator` records for all extracted IPs, domains, URLs, email addresses, and hashes
   - Directed `Relationship` graph edges (`EMAIL CONTAINS ATTACHMENT`, `EMAIL REFERENCES URL`, `URL RESOLVES_TO DOMAIN`, `EMAIL COMMUNICATES_WITH IP`)
   - Normalized `ThreatEvent` when threat score or severity warrants investigation
3. If an error occurs in the dual-write adapter, it logs diagnostic telemetry and rolls back safely without failing the legacy API response.
4. Existing tests and frontend components receive the exact same legacy response schemas.

---

## 8. Database Migrations

Managed via Alembic in `backend/migrations/versions/`:

| Revision | Description | Down Revision |
|---|---|---|
| `ae5ff3420a0a` | Case management tables (`cases`, `case_emails`, `case_notes`, `case_findings`, `audit_logs`) | `None` |
| `64a0d89a8460` | Evidence integrity table with SHA-256 enforcement and audit log extension | `ae5ff3420a0a` |
| `8f1e92d3b45a` | Production tables (`reports`, `email_analyses`, `campaigns`, `campaign_emails`, `analyst_decisions`, `copilot_audit_logs`, `analysis_payloads`) | `64a0d89a8460` |
| **`b7e2a901c43f`** | **Unified CyberGuard Data Model**: `artifacts`, `analysis_runs`, `model_versions`, `findings`, `finding_evidence`, `indicators`, `entities`, `relationships`, `incidents`, `threat_events`, `response_actions`, `attack_paths`, `attack_stages`, `attack_edges`, plus additive `request_id` column on `audit_logs`. | `8f1e92d3b45a` |

---

## 9. Minimal Inspection API Endpoints

Registered in `backend/api/routes/unified.py` and included in FastAPI app:

- `GET /api/unified/artifacts/{id}`: Returns Artifact details by UUID or SHA-256.
- `GET /api/unified/artifacts/{id}/analysis`: Returns all AnalysisRuns for an Artifact.
- `GET /api/unified/analysis/{id}/findings`: Returns Findings and attached Evidence items for an AnalysisRun.
- `GET /api/unified/incidents/{id}`: Returns Incident details, linked ThreatEvents, and proposed ResponseActions.
- `GET /api/unified/indicators/{identifier}`: Returns deduplicated Indicator by normalized value or ID.
- `GET /api/unified/relationships`: Returns Knowledge Graph edges filtered by `source_id`, `target_id`, or `relationship_type`.

---

## 10. Future Extension Points

1. **Attack Path Engine (Section 3)**:
   - Tables `attack_paths`, `attack_stages`, and `attack_edges` are already present in the schema.
   - Section 3 can immediately map multi-stage kill chains (Initial Access $\rightarrow$ Execution $\rightarrow$ C2 Callback $\rightarrow$ Exfiltration) onto these existing tables.
2. **Automated Response Execution (Section 4)**:
   - `response_actions` already models `status` (`RECOMMENDED`, `PENDING_APPROVAL`, `APPROVED`, `EXECUTING`, `COMPLETED`, `FAILED`).
   - Webhook drivers for Google Workspace, Microsoft Graph, and EDR agents can execute approved actions directly from this table.
3. **Continual Learning & Model Drift**:
   - `model_versions` tracks model F1 metrics, training references, and deployment state, enabling A/B testing and canary evaluation of future detection algorithms.
