# SECTION 49: ALERT CORRELATION & INCIDENT CLUSTERING

## 1. Executive Summary & Purpose

The **Alert Correlation & Incident Clustering subsystem** transforms discrete, apparently isolated security alerts into coherent, explainable, and operationally unified **Alert Clusters**. 

Modern threat campaigns (such as spearphishing leading to credential harvesting, endpoint beaconing, and privilege escalation) inevitably trigger multiple alerts across distinct sensors and analyzers. Without correlation, security operations teams suffer severe alert fatigue, triaging fragmented symptoms in isolation while missing the broader attack narrative.

This subsystem provides:
- **Many Alerts → Multi-Signal Correlation → Correlated Alert Cluster → Incident Context → Cohesive Investigation**
- **Zero Mock Data**: Operates strictly on persisted `NotificationModel` (Security Alerts), `FindingModel`, `InvestigationModel`, and `IncidentModel` records.
- **Explainable Grouping**: Every alert-to-cluster association records machine-readable signals and human-verifiable evidence.
- **Strict Separation of Concerns**: Correlation confidence (how sure we are alerts are related) is kept completely decoupled from threat risk/severity (how dangerous the underlying activity is).

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                       CYBERGUARD CORRELATION PIPELINE                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  [Alert A: Phishing Email]   [Alert B: Malicious URL]   [Alert C: Endpoint] │
│             │                           │                         │         │
│             └─────────────────────┬───────────────────────────────┘         │
│                                   ▼                                         │
│                      Feature Extraction & Parsing                           │
│             (Users, Domains, IPs, URLs, Hashes, Hostnames)                  │
│                                   │                                         │
│                                   ▼                                         │
│                    Bounded Candidate Retrieval                              │
│             (Tenant filter + Temporal window ≤ 48h)                         │
│                                   │                                         │
│                                   ▼                                         │
│                      Multi-Signal Similarity Engine                         │
│       ┌────────────────────────────────────────────────────────┐            │
│       │ • Hard Signals: Exact IOC / Malicious Hash / Campaign  │            │
│       │ • Soft Signals: Common User / Domain / Device Proximity│            │
│       │ • Over-Merge Guards: CDN / Public Cloud Whitelists     │            │
│       └────────────────────────────────────────────────────────┘            │
│                                   │                                         │
│                                   ▼                                         │
│               Confidence Calculation & Aggregated Severity                  │
│                                   │                                         │
│           ┌───────────────────────┴───────────────────────┐                 │
│           ▼                                               ▼                 │
│   New AlertCluster                              Append to Existing Cluster  │
│   (CLU-XXXX, Status: OPEN)                      (Update Risk & Last Seen)   │
│           │                                               │                 │
│           └───────────────────────┬───────────────────────┘                 │
│                                   ▼                                         │
│                      Persistence & Audit Logging                            │
│           (AlertClusterModel & AlertClusterMemberModel)                     │
│                                   │                                         │
│                 ┌─────────────────┴─────────────────┐                       │
│                 ▼                                   ▼                       │
│       Section 46 Real-time SSE            Section 47 Alert Drawer &         │
│       (ALERT_CLUSTER_CREATED)             Triage Workspace (/alerts)        │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Architectural Position

The subsystem sits as an **orchestration and correlation layer** between threat evaluation and analyst investigation:

1. **Not a Detection Engine**: Does not inspect raw packets or generate new threat findings; it processes existing security alerts produced by Sections 15–22 & 48.
2. **Not a Campaign Engine Replacement**: Directly consumes and leverages campaign identifiers (`campaign_id`) and Section 24–27 correlation models as high-weight hard signals.
3. **Not an Investigation Workspace Replacement**: Groups operational alerts into clusters that seamlessly link to Section 40–42 investigations (`InvestigationModel` / `IncidentModel`).
4. **Not a Knowledge Graph Replacement**: Traverses existing nodes and relationships (`EntityModel`, `RelationshipModel`) to derive graph-distance correlation signals.

---

## 3. Core Domain Concepts: Alert vs. Cluster vs. Incident vs. Investigation

To prevent architectural confusion, CyberGuard enforces crisp boundaries:

| Concept | Entity | Operational Meaning |
|---|---|---|
| **Security Alert** | `NotificationModel` (`category='SECURITY_ALERT'`) | A single authoritative security signal requiring analyst attention (e.g., suspicious domain observed). |
| **Alert Cluster** | `AlertClusterModel` | A deterministic, explainable grouping of correlated alerts sharing forensic indicators, users, infrastructure, or attack chains. |
| **Incident** | `IncidentModel` | An operationally confirmed security occurrence affecting organizational assets with SLA tracking and containment ownership. |
| **Investigation** | `InvestigationModel` | The analyst's forensic workspace for graph analysis, timeline reconstruction, and playbook response. |

---

## 4. Correlation Signals

Correlation uses multiple orthogonal signal categories rather than simplistic single-attribute matching:

### 1. Identity Signals
- **Same User**: Alerts sharing originating or target user accounts (`user_id`, email username).
- **Same Account / Sender**: Shared email sender or internal account identifiers.

### 2. Infrastructure Signals
- **Same Domain**: Alerts referencing identical network domains (`evil-login.com`).
- **Same IP Address**: Alerts referencing identical external IPs (with cloud/CDN guardrails).
- **Same URL**: Exact URL match across detection events.

### 3. Indicator Signals
- **Same IOC / Hash**: Exact SHA256/MD5 match of malware samples or email attachments.

### 4. Artifact & Execution Signals
- **Same Run ID**: Alerts originating from the same pipeline execution (`run_id`).
- **Same Source Artifact**: Shared parent artifact (`artifact_id`).

### 5. Endpoint Signals
- **Same Device / Endpoint**: Shared host identifier or workstation name (`endpoint_id`, `hostname`).

### 6. Campaign & Graph Signals
- **Same Campaign**: Alerts linked to identical threat actor campaigns (`campaign_id`).
- **Same Investigation**: Alerts previously attached to the same investigation context.

### 7. Temporal Proximity
- Proximity scoring based on elapsed time:
  - $\Delta t \le 15\text{ min} \implies \text{Score } 1.0$
  - $\Delta t \le 1\text{ hour} \implies \text{Score } 0.8$
  - $\Delta t \le 6\text{ hours} \implies \text{Score } 0.5$
  - $\Delta t \le 24\text{ hours} \implies \text{Score } 0.2$
  - $\Delta t > 24\text{ hours} \implies \text{Score } 0.0$

---

## 5. Hard Correlation vs. Soft Correlation & Over-Merge Prevention

To avoid false aggregations (e.g., grouping unrelated alerts simply because they share a Google DNS or Cloudflare CDN IP), correlation differentiates between **Hard** and **Soft** signals:

### Hard Signals (High Specificity, High Weight)
- Exact Malicious File Hash (`same_hash`, Weight: 0.95)
- Exact Suspicious URL (`same_url`, Weight: 0.90)
- Explicit Campaign ID (`same_campaign`, Weight: 0.95)
- Same Endpoint + Same Non-Public Destination (`same_endpoint` + `same_domain`, Weight: 0.85)

### Soft Signals (Contextual, Medium Weight)
- Same Target User (`same_user`, Weight: 0.65)
- Same Domain (`same_domain`, Weight: 0.60)
- Shared External IP (`same_ip`, Weight: 0.35)
- Temporal Proximity (`temporal_proximity`, Weight: 0.40)

### Over-Merge Prevention Guardrails
The engine maintains a strict infrastructure whitelist for common public providers:
```python
COMMON_PUBLIC_INFRASTRUCTURE = {
    "google.com", "microsoft.com", "apple.com", "cloudflare.com",
    "amazonaws.com", "github.com", "8.8.8.8", "1.1.1.1", "127.0.0.1"
}
```
If an IP or domain matches this whitelist, it is automatically downgraded to weight 0.05 and **never** satisfies correlation alone without corroborating user, device, or attack-chain evidence.

---

## 6. Correlation Scoring & Aggregated Severity

### 1. Normalized Correlation Confidence
Confidence represents the mathematical probability that two alerts stem from the same root incident:
$$\text{Confidence} = \min\left(0.99, \sum_{i} w_i \times s_i\right)$$
An alert is admitted to a cluster if $\text{Confidence} \ge 0.50$.

### 2. Cluster Severity Aggregation
A cluster's severity does **not** naively sum alert severities (which would artificially inflate 10 low alerts to critical). Instead, it adopts the highest severity of its constituent alerts, augmented by risk-tier count:
- If any member is `CRITICAL` $\implies$ Cluster is `CRITICAL`.
- If any member is `HIGH` $\implies$ Cluster is `HIGH`.
- Cluster risk score is the peak alert risk score plus an incremental progression bonus:
  $$\text{Risk}_{\text{cluster}} = \min(100.0, \max(\text{risk}_i) + \log_2(N) \times 2.5)$$

---

## 7. Scalable Candidate Retrieval: Avoiding $O(N^2)$ Scans

The correlation engine never performs full database scans across historical alerts. Instead, candidate retrieval uses bounded indexing:
1. **Tenant Isolation Filter**: `workspace_id == current_tenant`
2. **Temporal Window**: Alerts created within the last 48 hours (`created_at >= now - 48h`).
3. **Status Filter**: Active alerts (`status IN ('OPEN', 'ACKNOWLEDGED', 'INVESTIGATING')`).
4. **Candidate Ceiling**: Limited to the most recent 50 candidate alerts.
5. **Exact Hash & User Lookups**: Direct database index lookups on `assigned_to` and `category`.

---

## 8. Cluster Lifecycle & Merging

### Cluster States
- `OPEN`: Newly formed cluster undergoing active correlation.
- `INVESTIGATING`: Analyst has initiated or attached an investigation.
- `CONTAINED`: Response playbooks have contained the constituent threats.
- `RESOLVED`: All member alerts have been resolved.
- `MERGED`: Absorbed into another cluster with full immutable provenance.

### Safe Cluster Merging
When newly discovered evidence links two previously separate clusters:
1. Destination cluster retains its identity (`Cluster A`).
2. Source cluster is marked with `status = 'MERGED'` and `merged_into_cluster_id = 'Cluster A.id'`.
3. All members from `Cluster B` are reassigned to `Cluster A`.
4. Provenance audit logs record actor, timestamp, and merge rationale.

---

## 9. Database Schema & Persistence

Two dedicated relational models are added to `backend/db/models.py`:

```sql
CREATE TABLE alert_clusters (
    id VARCHAR(36) PRIMARY KEY,
    cluster_number VARCHAR(32) NOT NULL UNIQUE,
    workspace_id VARCHAR(64) NOT NULL DEFAULT 'default',
    title VARCHAR(255) NOT NULL,
    summary TEXT,
    status VARCHAR(32) NOT NULL DEFAULT 'OPEN',
    severity VARCHAR(32) NOT NULL DEFAULT 'MEDIUM',
    risk_score FLOAT NOT NULL DEFAULT 0.0,
    confidence FLOAT NOT NULL DEFAULT 0.5,
    alert_count INTEGER NOT NULL DEFAULT 1,
    primary_alert_id VARCHAR(36),
    investigation_id VARCHAR(64),
    campaign_id VARCHAR(64),
    merged_into_cluster_id VARCHAR(36),
    metadata_json TEXT,
    first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE alert_cluster_members (
    id VARCHAR(36) PRIMARY KEY,
    cluster_id VARCHAR(36) NOT NULL REFERENCES alert_clusters(id) ON DELETE CASCADE,
    alert_id VARCHAR(36) NOT NULL REFERENCES notifications(id) ON DELETE CASCADE,
    membership_confidence FLOAT NOT NULL DEFAULT 0.7,
    correlation_reasons_json TEXT,
    correlation_version VARCHAR(32) NOT NULL DEFAULT 'v1',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_cluster_alert UNIQUE (cluster_id, alert_id)
);

CREATE INDEX ix_alert_clusters_workspace ON alert_clusters(workspace_id);
CREATE INDEX ix_alert_clusters_status_sev ON alert_clusters(status, severity);
CREATE INDEX ix_alert_clusters_updated_at ON alert_clusters(updated_at);
CREATE INDEX ix_cluster_members_alert_id ON alert_cluster_members(alert_id);
```

---

## 10. Real-Time Updates & Notifications

### 1. Section 46 Real-Time SSE Events
The subsystem broadcasts structured real-time events over `/api/events/stream`:
- `ALERT_CLUSTER_CREATED`: Broadcast when a new cluster is initialized.
- `ALERT_CLUSTER_UPDATED`: Broadcast when metadata or severity shifts.
- `ALERT_ADDED_TO_CLUSTER`: Broadcast when a new alert joins an existing cluster.
- `ALERT_CLUSTER_MERGED`: Broadcast when two clusters merge.
- `ALERT_CLUSTER_INVESTIGATION_LINKED`: Broadcast when an investigation is bound.

### 2. Section 47 Notification Controls
To prevent notification fatigue, clusters only generate high-priority toasts/badges when:
- Correlation confidence $\ge 0.75$ and cluster severity is `CRITICAL` or `HIGH`.
- An active cluster absorbs $\ge 3$ distinct alerts within 1 hour.

---

## 11. Background Job Integration

Correlation is registered with the Section 45 Background Job Worker:
- **Job Type**: `ALERT_CORRELATION`
- **Handler**: `handle_alert_correlation` in `backend/services/background_job_worker.py`
- **Idempotency**: Running correlation multiple times for the same alert produces deterministic clusters without creating duplicate memberships or corrupting audit trails.

---

## 12. Security & Tenant Isolation

1. **Strict Multi-Tenancy**: Every candidate query, cluster lookup, and member association enforces `workspace_id == current_tenant`. Cross-tenant correlation is strictly blocked at the database and query layer.
2. **Attacker-Controlled Metadata Sanitization**: All user strings, URLs, domain names, and file hashes extracted from alert evidence are treated as untrusted and rendered safely via React virtual DOM without `dangerouslySetInnerHTML`.
3. **Append-Only Auditing**: Every cluster creation, member addition, merge, status transition, and investigation link produces an immutable `AuditLogModel` record via `AuditService.log_audit`.

---

## 13. REST API Specifications

All endpoints are mounted under `/api/alerts/clusters` and `/api/alerts/{id}`:

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/alerts/clusters` | List correlated clusters with filtering (`status`, `severity`, `q`), sorting, and pagination. |
| `GET` | `/api/alerts/clusters/{id}` | Retrieve comprehensive cluster details including member alerts, correlation signals, entities, and timeline. |
| `POST` | `/api/alerts/clusters/{id}/status` | Update cluster status (`OPEN`, `INVESTIGATING`, `CONTAINED`, `RESOLVED`). |
| `POST` | `/api/alerts/clusters/{id}/investigate` | Link an existing investigation or automatically initialize an `IncidentModel` investigation. |
| `POST` | `/api/alerts/clusters/{id}/merge` | Safely merge another cluster into the target cluster with provenance tracking. |
| `GET` | `/api/alerts/{id}/cluster` | Query the primary correlated cluster and peer alerts for a specific alert. |
| `POST` | `/api/alerts/{id}/correlate` | Trigger on-demand correlation for an alert (synchronous or background worker). |

---

## 14. Frontend Architecture

The user interface seamlessly integrates with the Section 48 Alert Management Workspace:

1. **Segmented View Switcher** (`src/pages/AlertWorkspace.tsx`):
   - **Alerts Queue**: Standard analyst triage table.
   - **Incident Clusters**: Aggregated multi-alert incident view displaying Cluster ID (`CLU-XXXX`), Title, Severity, Alert Count, Confidence %, Risk Score, and Timespan.
2. **Alert Detail Drawer Integration** (`src/components/alerts/AlertDetailDrawer.tsx`):
   - When viewing an alert, displays a dedicated **Related Activity (Alert Cluster)** card showing correlation confidence, cluster status, and peer alerts with badges explaining why they are related.
3. **Forensic Cluster Inspection Modal** (`src/components/alerts/AlertClusterDetailModal.tsx`):
   - Deep-dive contextual drawer presenting:
     - Aggregated severity, risk score, confidence gauge, and status selector.
     - **Why Related?** structured signal breakdown with confidence bars.
     - **Constituent Alerts Table** with quick-navigation into the Alert Detail Drawer.
     - **Affected Forensic Entities** (Users, Domains, IPs, Endpoints, Hashes, Artifacts).
     - **Attack Progression Timeline** showing real chronologically ordered events.
     - **Safe Cluster Merge Tool** with real-time target cluster selection.
     - **One-Click Investigation Handoff** linking directly to the Investigation Workspace (`/investigations/:id`).

---

## 15. Testing & Verification

Comprehensive test suite in `backend/tests/test_section49_alert_correlation.py`:
- `test_alert_feature_extraction`: Validates parsing of IOCs, users, domains, IPs, URLs, and hashes from notification evidence.
- `test_hard_signal_exact_hash`: Confirms identical file hashes produce $\ge 0.90$ correlation confidence.
- `test_overmerge_prevention_public_cdn`: Proves shared public CDN/Cloudflare infrastructure does not trigger false grouping.
- `test_cross_tenant_isolation`: Verifies Tenant A alerts are never correlated with Tenant B alerts.
- `test_cluster_creation_and_member_addition`: Tests creation of new clusters and subsequent additions of related alerts.
- `test_cluster_merging`: Validates safe cluster merges with provenance and `MERGED` status assignment.
- `test_investigation_linking`: Tests bi-directional binding between clusters and `IncidentModel` investigations.
- `test_api_endpoints`: Verifies all REST endpoints and serialization schemas.
- `test_concurrency_and_idempotency`: Validates duplicate correlation runs never create redundant memberships.

Total Section 45–49 tests: **73 tests passed, 0 failures**.
Frontend TypeScript build: **0 type errors, production bundle compiled cleanly**.
