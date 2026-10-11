# SECTION 63 — ASSET & IDENTITY INVENTORY
## CyberGuard Architecture Reference

---

### 1. Inventory Architecture
Section 63 implements the unified, authoritative **Asset & Identity Inventory** layer for CyberGuard. The system provides a single source of truth answering:
> *What assets, identities, accounts, devices, applications, services, and ownership relationships exist within the environment, and what does CyberGuard actually know about them?*

The architecture follows a deterministic flow from raw ingestion to operational security consumptions:
```text
Inventory Sources (CMDB, Directory, Endpoint Agent, Cloud Provider, Manual)
      ↓
Normalization & Validation (Deterministic Canonical Identifiers & Schema Checks)
      ↓
Identity Resolution (Section 61 UnifiedEntityResolver & Graph Node Correlation)
      ↓
Canonical Asset / Identity Records (AssetModel, IdentityModel)
      ↓
Ownership + Classification (Owner, Team, Department, Criticality, Environment)
      ↓
Relationship Mapping (Section 14 Security Knowledge Graph Linkage)
      ↓
Inventory State & Reconciliation (Active, Inactive, Stale, Retired, Conflict Detection)
      ↓
Exposure / Detection / Intelligence Enrichment (Sections 52, 60, 62)
      ↓
Unified Risk / Alerts / Incidents / Investigations (Sections 26, 48, 50, 55)
```

CyberGuard maintains a strict architectural separation:
- **Inventory**: What the organization knows, manages, or is supposed to govern.
- **Observation**: Empirical telemetry CyberGuard recorded across vectors.
- **Exposure**: Reachable attack surface condition (Section 62).
- **Finding**: Analytical security conclusion.
- **Alert**: Actionable operational signal (Section 48).
- **Incident**: Orchestrated case workflow (Section 50).
- **Risk**: Dynamic risk calculation from the Unified Risk Engine (Section 26).
- **Investigation**: Deep analyst exploration (Section 55).
- **Threat Intelligence**: External and internal contextual intelligence (Section 52).

---

### 2. Canonical Entities
Rather than creating duplicate models, Section 63 anchors the authoritative inventory to:
1. `AssetModel` (`table: assets` in `backend/db/models.py`):
   - Represents canonical hardware, endpoints, servers, web applications, APIs, databases, domains, and certificates.
   - Augmented in Section 63 with: `department`, `ownership_status` (`ASSIGNED`, `UNASSIGNED`, `UNKNOWN`, `CONFLICTED`, `INFERRED`), `classification`, `tags_json`, `last_observed_at`, `last_sync_at`, `is_managed`, and `is_stale`.
2. `IdentityModel` (`table: identities` in `backend/db/models.py`):
   - Represents human identities, corporate user accounts, privileged accounts, service accounts, and API clients.
   - Tracks `identity_type`, `canonical_name`, `email`, `display_name`, `department`, `manager`, `status` (`ACTIVE`, `INACTIVE`, `DORMANT`, `SUSPENDED`, `RETIRED`), `is_privileged`, `is_service_account`, `is_orphaned`, `is_dormant`, `last_authenticated_at`, `last_activity_at`, and `canonical_entity_id`.

---

### 3. Asset Types
Supported asset types in the unified inventory:
- `ENDPOINT`: Managed or unmanaged corporate workstations, laptops, or agent-enrolled endpoints.
- `SERVER`: Virtual or bare-metal internal/external application and infrastructure servers.
- `APPLICATION`: Internal or external business web applications and SaaS services.
- `API`: Enterprise REST/GraphQL endpoints, API gateways, and microservices.
- `DATABASE`: Relational, document, or analytical data stores.
- `DOMAIN` / `SUBDOMAIN`: Registered DNS zones, subdomains, and corporate web assets.
- `CERTIFICATE`: X.509 TLS/SSL certificates and cryptographic trust roots.
- `CLOUD_RESOURCE`: Cloud-native assets (compute instances, storage buckets, VPCs).

---

### 4. Identity Types
Supported identity types:
- `USER`: Human employee or contractor identity.
- `ACCOUNT`: Authenticated credentialed account (e.g., Active Directory / Okta / Azure AD login).
- `SERVICE_ACCOUNT`: Automated non-human account powering background pipelines, services, or daemons.
- `APPLICATION_IDENTITY`: Managed workload identity or OAuth application credential.
- `API_CLIENT`: Machine-to-machine API key or programmatic token client.

---

### 5. Identity Resolution
Identity resolution prevents entity explosion and duplicates. Inventory ingestion routes all incoming records through Section 61's `UnifiedEntityResolver`:
- **Order of Precedence**:
  1. Authoritative internal ID (`id`).
  2. External authoritative ID (`external_id` / directory object GUID / agent UUID).
  3. Canonical normalized identifier (lowercase FQDN, normalized IP, RFC 5322 lowercase email).
  4. Knowledge Graph alias lookup.
- When an endpoint agent registers `device_id="abc123"` and CMDB reports `hostname="WS-1042"` with `serial="abc123"`, the resolver unifies them into the same canonical `AssetModel` record instead of creating disconnected duplicates.

---

### 6. Source Authority Precedence
Different inventory sources have different authority over specific attributes:
```text
CMDB (Weight: 100) — Authoritative for ownership, team, environment, criticality
      ↓
MANUAL_ANALYST (Weight: 90) — Explicit analyst override
      ↓
DIRECTORY (Weight: 80) — Authoritative for user status, department, roles
      ↓
ENDPOINT_AGENT (Weight: 60) — Authoritative for hardware platform, agent health
      ↓
CLOUD_PROVIDER (Weight: 50) — Authoritative for cloud infrastructure resources
      ↓
NETWORK (Weight: 40) — Observed network presence
      ↓
INFERRED (Weight: 20) — Graph or correlation heuristics
```
All sources are tracked in `InventorySourceModel` with configured authority weights ($1 - 100$), health, and synchronization metrics.

---

### 7. Provenance & Auditability
Every attribute modification records:
- Source identifier (`source_id` / `source_type`).
- Timestamp of ingestion (`last_sync_at` / `last_observed_at`).
- Confidence level (`Authoritative` vs `Inferred`).
- Manual analyst overrides are captured in `InventoryOverrideModel` with `actor`, `timestamp`, `previous_value`, `new_value`, and `reason`.

---

### 8. Ownership Representation & Workflow
- Fields: `owner` (user/contact), `team` (managing unit), `department` (organizational department).
- Statuses:
  - `ASSIGNED`: Valid ownership explicitly assigned by authoritative source or analyst.
  - `UNASSIGNED`: Discovered asset with no recorded owner (Shadow IT).
  - `UNKNOWN`: Insufficient evidence or conflicting claims pending review.
  - `CONFLICTED`: Two authoritative sources assert incompatible owners.
  - `INFERRED`: Derived from behavioral correlation or parent application linkage.
- Analysts can review, reassign, or resolve ownership directly via the UI or `POST /api/v1/inventory/assets/{id}/assign-owner`.

---

### 9. Business Criticality
- Tiers: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`.
- Represents business value, operational impact, and regulatory exposure (e.g., PCI-DSS, HIPAA).
- Criticality is strictly business metadata and **NOT** security risk.

---

### 10. Lifecycle States
- `ACTIVE`: Actively observed, functioning asset or active account.
- `INACTIVE`: Intentionally decommissioned or disabled identity.
- `STALE`: Expected heartbeat or telemetry has ceased beyond configurable threshold ($>30$ days for assets, $>90$ days for accounts).
- `RETIRED`: Formally archived asset; historical forensic findings remain preserved.
- `UNKNOWN`: Unverified state during initial ingestion.

---

### 11. Freshness Semantics
Freshness tracking distinguishes administrative metadata updates from empirical observations:
- `created_at`: Record creation timestamp.
- `updated_at`: Administrative database modification time.
- `first_seen_at`: First empirical observation.
- `last_seen_at`: Most recent observation by any telemetry source.
- `last_observed_at`: Direct agent or network interaction timestamp.
- `last_sync_at`: Time source synchronization last affirmed this asset.

---

### 12. Reconciliation Lifecycle
Full and incremental reconciliation executes via Section 45 Background Jobs:
- Compares active source snapshots against current inventory.
- Identifies missing records, stale entities, and unmanaged endpoints.
- Sets `is_stale = True` when `last_seen_at < (now - 30 days)`.
- Flags unmanaged endpoints where `asset_type == ENDPOINT` but `is_managed == False`.
- Flags dormant identities where `last_activity_at < (now - 90 days)`.
- Flags orphaned service accounts with no assigned team or owner.

---

### 13. Source Conflict Management
When two sources provide divergent attribute values:
- If source authority weights differ: System automatically adopts the higher-authority value and logs the conflict as `AUTO_RESOLVED` with explanation.
- If source authority weights are equal: System records conflict in `InventoryConflictModel` with status `PENDING_REVIEW` and generates a real-time notification.
- Analysts review conflicts in the dedicated Conflict Workspace and commit manual resolutions.

---

### 14. Endpoint Inventory Integration
- Seamlessly unifies with Section 31 Endpoint Agent registry (`DeviceModel`).
- Ingests hostname, OS platform, agent status, agent version, and assigned user.
- Explicitly distinguishes:
  - **Inventory State**: `ACTIVE` / `STALE` / `RETIRED`.
  - **Agent State**: `HEALTHY` / `OFFLINE` / `UNINSTALLED`.
  - **Security State**: Current threat findings or isolation status.

---

### 15. Application Inventory
- Tracks business web applications, frontend portals, and backend suites.
- Links applications to managing teams, backing database assets, API gateways, and production host environments.

---

### 16. API Inventory
- Represents API endpoints, gateways, and microservices.
- Tracks protocol, environment, managing team, authentication requirements, and internet exposure state.

---

### 17. Cloud Resource Inventory
- Ingests cloud provider resources (virtual machines, S3/GCS buckets, RDS instances, serverless functions).
- Employs provider-native deterministic resource identifiers (e.g., `arn:aws:...`, `//compute.googleapis.com/...`).

---

### 18. Identity Inventory
- Authoritative view of enterprise users, credentials, service accounts, and API clients.
- Tracks privileged status (`is_privileged`), service account flag (`is_service_account`), and orphaned status (`is_orphaned`).
- Protects credential confidentiality: never stores passwords, hashes, tokens, or private keys.

---

### 19. Relationships & Knowledge Graph
Inventory links directly to Section 14 `SecurityGraphService`:
- Nodes: `ASSET`, `IDENTITY`, `ACCOUNT`, `APPLICATION`, `SERVICE`, `TEAM`.
- Edges:
  - `USER` $\xrightarrow{\text{OWNS}}$ `ACCOUNT`
  - `ENDPOINT` $\xrightarrow{\text{ASSIGNED\_TO}}$ `USER`
  - `APPLICATION` $\xrightarrow{\text{OWNED\_BY}}$ `TEAM`
  - `SERVICE` $\xrightarrow{\text{RUNS\_ON}}$ `ENDPOINT`
  - `API` $\xrightarrow{\text{BELONGS\_TO}}$ `APPLICATION`
  - `CERTIFICATE` $\xrightarrow{\text{SECURES}}$ `DOMAIN`

---

### 20. Section 61 Cross-Source Correlation Integration
- Section 61 queries Section 63 to enrich raw events and telemetry with authoritative business context.
- High-volume events resolve to canonical assets and identities, allowing composite attack detection across disparate logs.

---

### 21. Section 62 Attack Surface Intelligence Integration
- Section 62 discovers external and internal exposures (`ExposureModel`) on canonical assets maintained in Section 63.
- Section 62 consumes Section 63's inventory to avoid duplicating asset definitions.

---

### 22. Threat Intelligence Enrichment (Section 52)
- External IOCs and threat feeds enrich inventory assets (IPs, domains, hashes) with indicator reputations.
- Does not modify canonical asset attributes or business criticality.

---

### 23. Detection Engine Integration (Sections 56–59)
- Detection rules can reference controlled inventory metadata:
  ```dsl
  asset.environment == "PRODUCTION" and asset.criticality in ["CRITICAL", "HIGH"]
  ```
- Prevents rule execution from running arbitrary unfiltered database scans.

---

### 24. Unified Risk Engine Integration (Section 26)
- The Unified Risk Engine calculates `risk_score` and `risk_level` using:
  - Business Criticality (weight factor)
  - Ownership Status (unmanaged/shadow IT increases risk)
  - Exposure State (publicly exposed increases risk)
  - Active Security Findings & Alerts
- Inventory maintains the business attributes; Risk Engine calculates risk scores.

---

### 25. Incidents & Case Lifecycle (Section 50)
- Incidents reference canonical `affected_assets` and `affected_identities`.
- Enables incident commanders to immediately contact the authoritative business owner and team during active triage.

---

### 26. Investigations & Advanced Pivots (Section 55)
- Analysts investigating cases pivot from alert observables to:
  - Asset details & connected services
  - Identity details & associated endpoints
  - Managing team & department escalation paths

---

### 27. Real-Time WebSocket Events (Section 46)
Inventory emits real-time events on channel `inventory`:
- `ASSET_CREATED`, `ASSET_STATUS_CHANGED`, `ASSET_OWNER_CHANGED`
- `IDENTITY_CREATED`, `IDENTITY_UPDATED`, `IDENTITY_STATUS_CHANGED`
- `INVENTORY_SYNC_STARTED`, `INVENTORY_SYNC_COMPLETED`, `INVENTORY_SYNC_FAILED`
- `INVENTORY_CONFLICT_DETECTED`, `INVENTORY_CONFLICT_RESOLVED`

---

### 28. Background Job Scheduling (Section 45)
Asynchronous operations run via `BackgroundJobWorker`:
- `INVENTORY_SYNC`: Pulls and normalizes changes from external source connectors.
- `INVENTORY_RECONCILIATION`: Full multi-source reconciliation, staleness detection, and orphan scanning.
- `INVENTORY_STALE_CHECK`: Daily scheduled sweep identifying dormant accounts and stale endpoints.

---

### 29. Security & Tenant Isolation
- Strict multi-tenancy: every query filters on `tenant_id`.
- Tenant A can never query, resolve, correlate, or update Tenant B's assets or identities.
- Tested and verified in `test_multi_tenant_workspace_isolation`.

---

### 30. Privacy & Data Minimization
- Identity inventory redacts sensitive authentication credentials.
- Object-level authorization prevents unauthorized operators from viewing employee directory records or privileged service accounts.

---

### 31. RBAC Permissions
Reuses existing RBAC structure:
- `inventory.read`: View assets, identities, sources, and stats.
- `inventory.update`: Edit metadata, assign owners, set environments and criticality.
- `inventory.resolve`: Resolve conflicting source attributes and submit manual overrides.
- `inventory.sync`: Trigger background synchronization and reconciliation jobs.

---

### 32. Verification & Testing
Test suite `backend/tests/test_section63_asset_identity_inventory.py` covers 13 deterministic tests:
1. `test_asset_upsert_normalization_and_idempotency`: Verifies normalization and no duplicate creation.
2. `test_identity_upsert_normalization_and_idempotency`: Verifies identity normalization, email canonicalization, and deduplication.
3. `test_authority_based_conflict_resolution`: Verifies CMDB (weight 100) auto-resolves over Agent (weight 60).
4. `test_equal_authority_conflict_pending_review`: Verifies equal weight generates `PENDING_REVIEW` conflict.
5. `test_manual_conflict_resolution_and_override`: Tests analyst manual resolution workflow.
6. `test_manual_override_precedence_over_automated_sources`: Verifies manual overrides persist against subsequent automated syncs.
7. `test_stale_asset_reconciliation`: Tests stale asset detection on $>30$ days inactivity.
8. `test_unmanaged_endpoint_detection`: Tests unmanaged endpoint discovery.
9. `test_dormant_and_orphaned_identity_detection`: Tests detection of $>90$ days dormant accounts and unowned service accounts.
10. `test_knowledge_graph_linkage`: Verifies automated node creation in Section 14 Knowledge Graph.
11. `test_background_job_handlers`: Validates async job execution for sync and reconciliation.
12. `test_inventory_api_full_lifecycle`: End-to-end REST API lifecycle test.
13. `test_multi_tenant_workspace_isolation`: Verifies complete multi-tenant boundaries.

---

### 33. Limitations & Out-of-Scope Concepts
- **No Unrestricted Scanners**: Section 63 does not execute raw port scanning or network probing across arbitrary CIDRs; all telemetry originates from authorized agents and registered connectors.
- **No Direct Secret Storage**: Vault credentials and API tokens are referenced via safe opaque descriptors (`secret_ref`), never stored in plaintext or database columns.
- **Historical Immutability**: Decommissioned assets are marked `RETIRED` rather than hard-deleted to preserve forensic integrity of past incident investigations.
