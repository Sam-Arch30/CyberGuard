# 03 — Data Model & Persistence Layer Audit

> **Database Engines:** PostgreSQL 16 (Production / Docker) / SQLite 3 (Air-Gapped & Local Dev)  
> **ORM Framework:** SQLAlchemy 2.0.52 (Declarative Base with `selectin` eager loading)  
> **Migration Manager:** Alembic 1.19.2 (3 applied revisions)  

---

## 1. Actual Database Entity-Relationship Diagram

```mermaid
erDiagram
    cases ||--o{ case_emails : "contains"
    cases ||--o{ case_notes : "contains"
    cases ||--o{ case_findings : "contains"
    cases ||--o{ audit_logs : "tracks"
    cases ||--o{ reports : "associates"

    campaigns ||--o{ campaign_emails : "clusters"

    evidence ||--o| analysis_payloads : "stores canonical JSON"
    evidence ||--o| email_analyses : "aggregates metrics"

    cases {
        string id PK "UUID-36"
        string case_number UK "CASE-YYYY-XXXXXX"
        string title
        text description
        string severity "low, medium, high, critical"
        string status "open, investigating, resolved, escalated"
        datetime created_at
        datetime updated_at
    }

    case_emails {
        string id PK "UUID-36"
        string case_id FK "cases.id (CASCADE)"
        string email_id "Evidence or RFC Message-ID"
        string email_sha256 "SHA-256 hash"
        string subject
        string sender
        float threat_score
        string severity
        text indicators_json "Extracted IOCs snapshot"
        datetime added_at
    }

    case_notes {
        string id PK "UUID-36"
        string case_id FK "cases.id (CASCADE)"
        string author
        text note_text
        datetime created_at
    }

    case_findings {
        string id PK "UUID-36"
        string case_id FK "cases.id (CASCADE)"
        string finding_type "e.g. lookalike_domain, spoofed_sender"
        string title
        text description
        string severity "low, medium, high, critical"
        datetime created_at
    }

    evidence {
        string id PK "UUID-36"
        string evidence_id UK "EVD-XXXXXXXX"
        string sha256 IX "Cryptographic SHA-256"
        string original_filename
        datetime upload_timestamp
        integer size "bytes"
        string uploader
    }

    audit_logs {
        string id PK "UUID-36"
        datetime timestamp IX
        string user
        string action IX "EMAIL_UPLOADED, ANALYSIS_COMPLETED, etc."
        string resource_type IX "email, case, report, evidence"
        string resource_id IX
        text metadata_json "Sanitized event context"
        string case_id FK "cases.id (CASCADE, Nullable)"
        text details
    }

    reports {
        string id PK "UUID-36"
        string report_number UK "RPT-YYYY-XXXXXX"
        string title
        string case_id FK "cases.id (SET NULL)"
        string evidence_id
        string email_sha256 IX
        float threat_score
        string severity
        string analyst_name
        text summary
        text ai_summary_json "AI Copilot / Analyst additions"
        string file_path "Path to disk PDF"
        integer file_size_bytes
        datetime created_at
    }

    email_analyses {
        string id PK "UUID-36"
        string evidence_id IX
        string email_sha256 IX
        string subject
        string sender
        string recipient
        float threat_score
        string severity IX
        string spf_result
        string dkim_result
        string dmarc_result
        text domains_json "Serialized list"
        text countries_json "Serialized list"
        text indicators_json "Aggregated IOC object"
        datetime analyzed_at IX
    }

    campaigns {
        string id PK "UUID-36"
        string campaign_id UK "e.g. C-042"
        string name
        datetime first_seen
        datetime last_seen
        integer email_count
        integer recipient_count
        integer sender_count
        integer domain_count
        integer ip_count
        integer asn_count
        float overall_confidence
        string dominant_attack_type
        text targeted_brands_json
        text targeted_organizations_json
        text fingerprint_json "Multi-vector fingerprint"
        text associated_iocs_json
        text timeline_events_json
        datetime created_at
        datetime updated_at
    }

    campaign_emails {
        string id PK "UUID-36"
        string campaign_id FK "campaigns.id (CASCADE)"
        string email_id
        string email_sha256
        string subject
        string sender
        string recipient
        datetime sent_at
        float similarity_to_campaign
        text category_scores_json
        text correlation_reasons_json
        datetime added_at
    }

    analyst_decisions {
        string id PK "UUID-36"
        string email_id_a IX
        string email_id_b IX
        string decision IX "unrelated, confirmed_related, etc."
        string campaign_id
        string case_id
        string analyst
        text notes
        datetime created_at
    }

    copilot_audit_logs {
        string id PK "UUID-36"
        string user
        text query
        string mode "email, case, campaign"
        string context_id
        text evidence_ids_json
        string confidence "CONFIRMED, PROBABLE, etc."
        string model_identifier
        datetime timestamp IX
    }

    analysis_payloads {
        string evidence_id PK "EVD-XXXXXXXX"
        text analysis_json "Canonical immutable analysis response"
        datetime created_at IX
    }
```

---

## 2. Table-by-Table Schema Inspection

### 2.1 Core Ingestion & Evidence
- **`evidence`**:
  - `id`: `String(36)` primary key (UUID v4)
  - `evidence_id`: `String(64)`, unique indexed identifier (e.g. `EVD-a1b2c3d4`)
  - `sha256`: `String(64)`, indexed primary cryptographic evidence integrity hash
  - `original_filename`: `String(255)`, sanitized filename
  - `upload_timestamp`: `DateTime(timezone=True)`
  - `size`: `Integer`, exact file size in bytes
  - `uploader`: `String(100)`, defaults to `"SOC Analyst"` or extracted from `X-User` header.

- **`analysis_payloads`**:
  - `evidence_id`: `String(128)` primary key (foreign reference to `evidence.evidence_id`)
  - `analysis_json`: `Text` (stores the 100% complete canonical forensic analysis JSON including headers, decoded body, IOCs, relay hops, attachments, attribution, confidence conclusions, and graph)
  - `created_at`: `DateTime(timezone=True)` indexed

### 2.2 Case Management Subsystem
- **`cases`**:
  - `id`: `String(36)` primary key (UUID v4)
  - `case_number`: `String(32)` unique indexed sequential identifier (e.g. `CASE-2026-000001`)
  - `title`: `String(255)`
  - `description`: `Text`, nullable
  - `severity`: `String(20)` indexed (`low`, `medium`, `high`, `critical`)
  - `status`: `String(20)` indexed (`open`, `investigating`, `resolved`, `escalated`)
  - `created_at` / `updated_at`: `DateTime`
  - *Cascading relationships:* `emails`, `notes`, `findings`, `audit_logs` (all `cascade="all, delete-orphan"`, `lazy="selectin"`).

- **`case_emails`**:
  - Links analyzed emails to cases with unique constraint `(case_id, email_id)`.
  - Foreign key to `cases.id` with `ondelete="CASCADE"`.

- **`case_notes`**:
  - Analyst observations and task updates. Foreign key to `cases.id` (`CASCADE`).

- **`case_findings`**:
  - Structured findings (`finding_type`, `title`, `description`, `severity`). Foreign key to `cases.id` (`CASCADE`).

### 2.3 Campaigns & Correlation
- **`campaigns`**:
  - Represents multi-vector threat campaigns (e.g. `C-042`).
  - Contains summary counters (`email_count`, `recipient_count`, `sender_count`, `domain_count`, `ip_count`, `asn_count`).
  - Serialized JSON attributes: `targeted_brands_json`, `targeted_organizations_json`, `fingerprint_json`, `associated_iocs_json`, `timeline_events_json`.

- **`campaign_emails`**:
  - Junction table connecting emails to campaigns with `similarity_to_campaign` score, `category_scores_json`, and `correlation_reasons_json`. Unique on `(campaign_id, email_id)`.

- **`analyst_decisions`**:
  - Records manual analyst actions on email pairs (`email_id_a`, `email_id_b`): `unrelated`, `confirmed_related`, `assigned_campaign`, `added_to_case`, `escalated`. Used as persistent feedback to suppress false positives.

### 2.4 Audit & Compliance
- **`audit_logs`**:
  - Append-only immutable log of every action taken in the platform.
  - Listeners `before_update` and `before_delete` raise `PermissionError` unless an explicit `_allow_audit_cleanup` flag is passed during workspace resets.

- **`copilot_audit_logs`**:
  - Records natural language queries submitted to Copilot, evidence IDs referenced, and model used (`mailtrace-copilot-v1`).

- **`reports`**:
  - Metadata for generated PDF documents (`report_number`, `threat_score`, `file_path`, `file_size_bytes`). Foreign key `case_id` with `ondelete="SET NULL"`.

---

## 3. Database Persistence vs Ephemeral State

| Data Asset | Actual Storage Location | Survives Browser Refresh? | Survives Backend Restart? | Survives Docker Restart? | Ephemeral / Serverless Risk |
|---|---|---|---|---|---|
| **Case Records & Notes** | Database (`cases`, `case_notes`) | YES | YES | YES (if DB volume mounted) | LOW (Fully persisted in SQL) |
| **Audit Logs** | Database (`audit_logs`) | YES | YES | YES (if DB volume mounted) | LOW (Fully persisted in SQL) |
| **Evidence Metadata** | Database (`evidence`) | YES | YES | YES (if DB volume mounted) | LOW (Fully persisted in SQL) |
| **Full Canonical Analysis JSON** | Database (`analysis_payloads`) | YES | YES | YES (if DB volume mounted) | LOW (Fully persisted in SQL) |
| **Original Uploaded .eml Bytes** | Filesystem: `backend/data/eml_store/*.eml` | YES | YES | **NO (Container wipes disk)** | **CRITICAL**: No volume mounted in `docker-compose.yml` |
| **Generated PDF Reports** | Filesystem: `backend/data/reports/*.pdf` | YES | YES | **NO (Container wipes disk)** | **HIGH**: Filesystem path lost if container restarts |
| **IP Intelligence Cache** | Memory (`IPIntelligenceCache`) | YES | NO | NO | LOW (Re-queries or gracefully degrades) |
| **Domain Intelligence Cache**| Memory (`DomainIntelligenceCache`)| YES | NO | NO | LOW (Re-queries or gracefully degrades) |
| **Rate Limiting Tokens** | Memory (`RateLimiterMiddleware`) | YES | NO | NO | LOW (Resets on restart) |
| **Client Active Investigation** | Browser `sessionStorage` & `localStorage`| YES (same tab) | YES | YES | MEDIUM (Lost on new browser tab if not in URL) |

---

## 4. Alembic Migration History

The database schema is managed via Alembic in `backend/migrations/versions/`:

1. **`ae5ff3420a0a_create_case_management_tables.py`** (2026-09-07)
   - Created `cases`, `audit_logs`, `case_emails`, `case_findings`, `case_notes`.
2. **`64a0d89a8460_create_evidence_and_update_audit_logs.py`** (2026-09-18)
   - Created `evidence` table with SHA-256 hash enforcement.
   - Updated `audit_logs` with generic `resource_type`, `resource_id`, and `user` columns, making `case_id` optional.
3. **`8f1e92d3b45a_create_production_tables.py`** (2026-09-19)
   - Created `reports`, `email_analyses`, `campaigns`, `campaign_emails`, `analyst_decisions`, `copilot_audit_logs`, and `analysis_payloads`.

### Orphan / Dead Tables in Existing Database
In `backend/data/mailtrace.db`, the following 5 tables exist from an early prototype before Alembic was introduced:
- `emails`
- `iocs`
- `email_iocs`
- `email_relationships`
- `analysis_runs`

These 5 tables contain **0 rows**, have **no SQLAlchemy models** defined in `backend/db/models.py`, and are only mentioned in the table-truncation list of `reset_workspace_state()`. They should be dropped cleanly in a future migration.
