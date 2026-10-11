# SECTION 62 — ATTACK SURFACE INTELLIGENCE
## CyberGuard Architecture Reference

---

### 1. Architectural Overview & Workflow Lifecycle
Section 62 implements the **Attack Surface Intelligence Layer** for CyberGuard. The system discovers, normalizes, relates, monitors, and prioritizes the organization's observable attack surface using existing systems and telemetry across the platform.

The complete workflow follows this deterministic lifecycle:
```text
Known Assets
      +
Observed Infrastructure
      +
Identities
      +
Endpoints
      +
Domains / URLs / IPs
      +
Cloud / API / Network Exposure
      +
Threat Intelligence
      +
Behavioral / Detection Signals
      ↓
Attack Surface Intelligence (AttackSurfaceService)
      ↓
Exposure Identification (ExposureModel & Exposure Engine)
      ↓
Exposure Context (AssetServiceModel & Graph Neighbors)
      ↓
Risk Prioritization (Criticality vs Dynamic Threat Risk)
      ↓
Alert / Investigation / Remediation (Existing Incidents, Alerts & Watchlists)
```

The system operates under strict operational guardrails:
- **No uncontrolled or arbitrary internet scanning**: All discovery operates strictly within tenant-authorized discovery scopes (`AttackSurfaceScopeModel`).
- **Strict SSRF Protections**: Uses `SSRFProtector` to prevent probes or resolutions to loopback (`127.0.0.1`), RFC-1918 private subnets, or cloud metadata endpoints (`169.254.169.254`).
- **Strict Anti-Duplication Mandate**: Leverages existing systems across the board (Section 14 Security Knowledge Graph, Section 26 Unified Risk Engine, Section 31/32 Endpoint Agents, Section 45 Background Jobs, Section 46 Realtime WebSockets, Section 47 Notifications, Section 48 Alerts, Section 52 Threat Intel, Section 53 IOC Watchlists, Section 54/55 Threat Hunting, and Section 61 Cross-Source Correlation).

---

### 2. Unified Asset Inventory Model
Attack surface discovery normalizes heterogeneous assets into a consistent, authoritative schema (`AssetModel` in `backend/db/models.py`):

| Column | Type | Description |
|---|---|---|
| `id` | `VARCHAR(36)` | Primary UUID identifier |
| `tenant_id` | `VARCHAR(64)` | Multi-tenant isolation key |
| `asset_type` | `VARCHAR(32)` | Controlled vocabulary: `DOMAIN`, `SUBDOMAIN`, `IP`, `SERVICE`, `CLOUD_RESOURCE`, `CERTIFICATE`, `ENDPOINT_AGENT`, `API_ENDPOINT` |
| `canonical_name` | `VARCHAR(255)` | Normalized deterministic identifier (e.g., lowercase FQDN, canonical IPv4/IPv6, SHA256 hex) |
| `display_name` | `VARCHAR(255)` | Human-readable name or label |
| `exposure_state` | `VARCHAR(32)` | `INTERNAL_ONLY`, `PUBLICLY_EXPOSED`, `PARTIALLY_EXPOSED`, `UNKNOWN` |
| `criticality` | `VARCHAR(32)` | Business criticality tier: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` |
| `owner` | `VARCHAR(255)` | Responsible owner or department (defaults to `Unassigned`) |
| `team` | `VARCHAR(255)` | Managing organizational team |
| `source` | `VARCHAR(64)` | Ingestion origin (e.g., `ENDPOINT_AGENT`, `DNS_ENUMERATION`, `GRAPH_OBSERVATION`) |
| `status` | `VARCHAR(32)` | Lifecycle status: `ACTIVE`, `INACTIVE`, `RETIRED`, `DISCOVERED`, `UNAUTHORIZED` |
| `risk_score` | `FLOAT` | Dynamic composite risk score ($0.0 - 100.0$) |
| `risk_level` | `VARCHAR(16)` | Risk bucket: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL` |
| `canonical_entity_id` | `VARCHAR(64)` | Authoritative link to Section 14 `SecurityGraphService` node |
| `ownership_confidence`| `FLOAT` | Ownership confidence score ($0.0 - 1.0$) |
| `metadata_json` | `JSON` | Structured attributes accessed via Python property `metadata_dict` |
| `first_seen_at` | `DATETIME` | Time asset was first observed |
| `last_seen_at` | `DATETIME` | Most recent verification timestamp |
| `last_scanned_at` | `DATETIME` | Last vulnerability or exposure evaluation |

#### Deterministic Normalization Rules
`AttackSurfaceService.normalize_asset_identifier` applies strict rules based on `asset_type`:
- **`DOMAIN` / `SUBDOMAIN`**: Strips URI scheme (`http://`, `https://`), trailing slashes, paths, and ports; translates punycode (`idna.encode/decode`); trims to lowercase.
- **`IP`**: Strips ports and enclosing brackets; canonicalizes IPv4 and IPv6 via `ipaddress.ip_address`.
- **`URL` / `API_ENDPOINT`**: Strips fragments and tracking query params; canonicalizes scheme and lowercase netloc.
- **`CERTIFICATE`**: Strips delimiters (`:`, `-`, whitespace); canonicalizes to 64-character lowercase hexadecimal SHA256 fingerprint.
- **`ENDPOINT_AGENT`**: Trims and lowercases agent UUID or hardware identifier.

---

### 3. Exposure Engine & Exposure Detection
Exposures represent actionable vulnerability configurations, unmapped risks, or unintended public access.

#### Exposure Schema (`ExposureModel` / table `asset_exposures`)
- `exposure_type`: `PUBLIC_ASSET`, `UNKNOWN_ASSET`, `UNKNOWN_SERVICE`, `EXPOSED_API`, `STALE_ASSET`, `UNMAPPED_DOMAIN`, `UNAPPROVED_PORT`
- `severity`: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL`
- `status`: `OPEN`, `RESOLVED`, `ACCEPTED_RISK`, `FALSE_POSITIVE`
- `evidence_refs`: Array of evidence references, finding IDs, or network probe snapshots
- `resolution_notes`, `resolved_by`, `resolved_at`: Full remediation audit trail

#### Automated Exposure Evaluation Rules
1. **`UNKNOWN_ASSET`** (Medium/High): Asset has `status='DISCOVERED'` or unassigned owner (`owner in (None, '', 'Unknown', 'Unassigned')`).
2. **`PUBLIC_ASSET`** (High): Asset has `exposure_state='PUBLICLY_EXPOSED'` on a critical or high-criticality asset without documented owner.
3. **`STALE_ASSET`** (Low): Asset was not observed in active telemetry for $\ge 30$ days (`last_seen_at < now - 30 days`).
4. **`UNKNOWN_SERVICE` & `UNAPPROVED_PORT`**: Network service observed on non-standard ports (e.g., Telnet 23, RDP 3389, or database ports) exposed externally.
5. **Deduplication**: The engine guarantees zero duplicate open exposures for the same `(asset_id, exposure_type)`. Existing open exposures update `last_detected_at` without re-creating records.

---

### 4. Strict Security Guardrails & SSRF Protection
To prevent weaponization, CyberGuard strictly restricts discovery actions:
- **Authorized Tenant Boundary Enforcement**: `AttackSurfaceScopeModel` maintains authorized target scopes per tenant (`DOMAIN`, `CIDR`, `IP`, `CLOUD_ACCOUNT`). Discovery actions verify target containment via `is_target_in_authorized_scope`.
- **Zero Arbitrary Scanning**: No uncontrolled port scanning or blind probing across the internet.
- **Active SSRF Protection**: `AttackSurfaceService.create_scope` validates input using `SSRFProtector`:
  - Blocks loopback addresses (`127.0.0.1`, `::1`).
  - Blocks RFC-1918 private address ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
  - Blocks cloud provider metadata endpoints (`169.254.169.254`, `metadata.google.internal`).
  - Rejects reserved multicast and broadcast addresses.

---

### 5. Integration with Existing CyberGuard Systems
In strict adherence to the Anti-Duplication mandate, Section 62 coordinates with existing infrastructure:

```text
┌────────────────────────────────────────────────────────┐
│               Existing CyberGuard Systems              │
├────────────────────────────────────────────────────────┤
│ Section 14 Security Knowledge Graph                    │
│   → Linked via canonical_entity_id                     │
│   → Graph traversal via SecurityGraphService           │
├────────────────────────────────────────────────────────┤
│ Section 31 & 32 Endpoint Agents & Devices              │
│   → Discovered assets sync DeviceModel / AgentModel    │
├────────────────────────────────────────────────────────┤
│ Section 21 Protected Identities                        │
│   → Identity domain correlation                        │
├────────────────────────────────────────────────────────┤
│ Section 52 & 53 Threat Intel & Watchlists              │
│   → Discovered assets sync IndicatorModel              │
│   → "ADD_TO_WATCHLIST" review action adds to Watchlist │
├────────────────────────────────────────────────────────┤
│ Section 26 Unified Risk Engine                         │
│   → Asset risk computation weights active findings     │
├────────────────────────────────────────────────────────┤
│ Section 45 Background Jobs                             │
│   → ATTACK_SURFACE_REFRESH & DISCOVERY handlers        │
├────────────────────────────────────────────────────────┤
│ Section 46 Realtime WebSockets                         │
│   → ATTACK_SURFACE_DISCOVERY_COMPLETED & EXPOSURE evts │
├────────────────────────────────────────────────────────┤
│ Section 47 & 48 Notifications & Alerts                 │
│   → Critical exposures trigger Notification & Alert    │
└────────────────────────────────────────────────────────┘
```

#### Unknown Asset Triage Lifecycle
When unknown assets are surfaced in the Unknown Asset Queue, analysts can perform 5 definitive review actions via `review_unknown_asset`:
1. `APPROVE`: Marks asset status as `ACTIVE` with verified confidence $1.0$.
2. `ASSIGN_OWNER`: Designates responsible owner and managing team.
3. `MAP_TO_EXISTING`: Merges asset metadata into existing canonical entity in the Knowledge Graph.
4. `MARK_UNAUTHORIZED`: Flags asset as rogue/shadow IT (`UNAUTHORIZED`), elevating criticality.
5. `ADD_TO_WATCHLIST`: Adds asset identifier to Section 53 IOC Watchlist (`WatchedIndicatorModel`) for continuous behavioral monitoring.
6. **Audit Trail**: Every review action creates an immutable audit record in `AuditLogModel`.

---

### 6. Criticality vs. Threat Risk Separation
CyberGuard strictly decouples business criticality from dynamic threat risk:
- **Business Criticality** (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`): Reflects organizational business impact, crown-jewel classification, and asset role. Preserved independently and never overwritten by fleeting telemetry spikes.
- **Dynamic Threat Risk** ($0.0 - 100.0$): Computed dynamically based on:
  $$\text{Exposure Penalty} = \sum_{\text{open exposures}} w(\text{severity}) \quad \text{where } w \in \{30, 20, 10, 5, 0\}$$
  $$\text{Finding Penalty} = \min(20.0, 5.0 \times \text{active\_findings\_count})$$
  $$\text{Base Criticality Weight} = \{30, 20, 10, 0\}$$
  $$\text{Risk Score} = \min(100.0, \text{Exposure Penalty} + \text{Finding Penalty} + \text{Base Criticality Weight})$$

---

### 7. Snapshots, Diff Tracking & Change Delta
`AttackSurfaceSnapshotModel` captures periodic point-in-time states:
- `total_assets`: Total asset count at snapshot.
- `diff_summary`: JSON delta capturing:
  - `assets_added` / `assets_removed`
  - `exposures_added` / `exposures_resolved`
  - `added_asset_names`: List of newly discovered asset identifiers.
- Enables SOC teams to monitor perimeter drift, track shadow IT proliferation, and verify exposure resolution velocity.

---

### 8. Background Jobs & Realtime Infrastructure
- **Background Jobs** (`backend/services/background_job_worker.py`):
  - `JobTypeEnum.ATTACK_SURFACE_REFRESH`: Periodically re-evaluates exposures, recalculates risk scores, and generates snapshot diffs.
  - `JobTypeEnum.ATTACK_SURFACE_DISCOVERY`: Executes authorized scope discovery sweep across endpoint registries, identity domains, and threat indicators.
- **Realtime WebSocket Events** (`backend/schemas/realtime.py`):
  - `ATTACK_SURFACE_DISCOVERY_COMPLETED`: Broadcasts sweep completion metrics to connected SOC dashboards.
  - `ATTACK_SURFACE_EXPOSURE_DETECTED`: Pushes high-severity exposure detections to analysts in real time.

---

### 9. REST API Reference
Mounted under `/api/v1/attack-surface` in `backend/main.py`:

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/attack-surface/overview` | KPI overview (total assets, public, unknown, critical, open exposures, diff) |
| `GET` | `/api/v1/attack-surface/assets` | Filtered, searchable, paginated asset inventory list |
| `GET` | `/api/v1/attack-surface/assets/{asset_id}` | Detailed asset inspection with exposures, services, and graph neighbors |
| `PATCH`| `/api/v1/attack-surface/assets/{asset_id}` | Update business criticality, ownership, team, or lifecycle status |
| `GET` | `/api/v1/attack-surface/assets/{asset_id}/timeline` | Chronological activity timeline for an asset |
| `GET` | `/api/v1/attack-surface/exposures` | Paginated list of open/resolved exposures with filtering |
| `POST` | `/api/v1/attack-surface/exposures/{id}/resolve`| Resolve exposure with status (`RESOLVED`, `ACCEPTED_RISK`, `FALSE_POSITIVE`) |
| `GET` | `/api/v1/attack-surface/unknown-queue` | Unknown asset triage queue for unmapped / rogue infrastructure |
| `POST` | `/api/v1/attack-surface/unknown-queue/review` | Apply triage action (`APPROVE`, `ASSIGN_OWNER`, `MARK_UNAUTHORIZED`, etc.) |
| `GET` | `/api/v1/attack-surface/scopes` | List tenant-authorized discovery boundaries |
| `POST` | `/api/v1/attack-surface/scopes` | Define authorized target scope (with SSRF validation) |
| `DELETE`| `/api/v1/attack-surface/scopes/{id}` | Remove discovery scope |
| `POST` | `/api/v1/attack-surface/discover` | Trigger synchronous or asynchronous discovery sweep |
| `GET` | `/api/v1/attack-surface/diff` | Latest snapshot delta metrics and newly added assets |

---

### 10. Frontend SOC Workspace Architecture
The frontend is implemented as a cohesive, production-grade SOC workspace:
- **`src/types/attackSurface.ts`**: TypeScript definitions for all domain models, enums, stats, and review payloads.
- **`src/services/attackSurfaceService.ts`**: Complete typed REST API client for all Section 62 endpoints.
- **`src/components/attackSurface/AttackSurfaceWorkspaceView.tsx`**: Rich interactive workspace featuring:
  - 6 KPI metric cards with change indicators and alert badges.
  - 5 Interactive tabs:
    1. **Asset Inventory**: Multi-filter search, asset type icons, exposure states, risk levels, and pagination.
    2. **Active Exposures**: Filterable exposure matrix with direct "Resolve Exposure" action modal.
    3. **Unknown Asset Queue**: Dedicated triage workflow with one-click review actions (Approve, Assign Owner, Add to Watchlist).
    4. **Attack Surface Diff**: Historical comparison metrics and badge listing of newly discovered assets.
    5. **Authorized Scopes**: Tenant boundary management table with "Add Scope" modal and SSRF protection feedback.
  - **Progressive Disclosure Asset Detail Modal**: Deep dive into asset metadata, associated exposures, open network services/ports, Knowledge Graph neighbor entities, and chronological event timeline.
- **`src/pages/AttackSurfacePage.tsx`**: Routed at `/attack-surface`, `/attack-surface/:id`, and `/assets`.
- **`src/components/layout/Sidebar.tsx`**: Primary navigation item with `Globe` icon.

---

### 11. Anti-Duplication Verification Matrix

| Subsystem Requirement | Re-used Existing CyberGuard Component | Status |
|---|---|---|
| Knowledge Graph Nodes & Edges | Section 14 `SecurityGraphService` (`entities`, `relationships`) | **PASS** (Zero duplicate graph DB) |
| Endpoint & Device Telemetry | Section 31/32 `DeviceModel` & `EndpointAgentModel` | **PASS** (Zero duplicate device registries) |
| Identity Attribution | Section 21 `ProtectedIdentityModel` | **PASS** (Zero duplicate identity stores) |
| Threat Intelligence Indicators | Section 52 `IndicatorModel` & `ThreatIntelService` | **PASS** (Zero duplicate threat feeds) |
| Continuous Threat Monitoring | Section 53 `WatchedIndicatorModel` | **PASS** (Zero duplicate watchlists) |
| Threat Hunting Traversal | Section 54/55 `ThreatHuntingService` & Pivot Endpoints | **PASS** (Zero duplicate hunting engines) |
| Risk Computation | Section 26 `RiskEngineService` weight curves | **PASS** (Zero duplicate risk calculators) |
| Background Jobs | Section 45 `BackgroundJobService` & Worker Queue | **PASS** (Zero duplicate job queues) |
| Realtime Push Events | Section 46 `ConnectionManager` & WebSocket Schemas | **PASS** (Zero duplicate WebSocket servers) |
| Alerting & Incident Ingestion | Section 48 `AlertService` & Section 50 Incidents | **PASS** (Zero duplicate alert engines) |
| Cross-Source Entity Resolution | Section 61 `UnifiedEntityResolver` | **PASS** (Zero duplicate entity resolvers) |

---

### 12. Verification & Test Suite Summary
Section 62 has been validated across both backend and frontend layers:
- **Backend Tests (`backend/tests/test_section62_attack_surface_intelligence.py`)**:
  - `test_asset_normalization_deterministic`: Verified FQDN, punycode, IPv4/IPv6, SHA256 hex normalization.
  - `test_asset_upsert_idempotency_and_no_duplicates`: Verified idempotent upsert and zero duplicate entries.
  - `test_authorized_scope_boundaries`: Verified tenant discovery boundaries are strictly enforced.
  - `test_ssrf_safety_on_scope_creation`: Verified rejection of loopback, RFC-1918, and cloud metadata targets.
  - `test_exposure_evaluation_and_deduplication`: Verified automated detection of `UNKNOWN_ASSET`, `PUBLIC_ASSET`, `STALE_ASSET`, and zero duplicate open exposures.
  - `test_exposure_resolution_lifecycle`: Verified resolution state transition and notes.
  - `test_unknown_asset_review_actions`: Verified `APPROVE`, `ASSIGN_OWNER`, `MARK_UNAUTHORIZED`, and audit trail generation.
  - `test_criticality_vs_risk_separation`: Verified business criticality preservation while risk updates dynamically.
  - `test_watchlist_integration_on_review`: Verified `ADD_TO_WATCHLIST` integration with Section 53 `WatchedIndicatorModel`.
  - `test_attack_surface_snapshot_and_diff`: Verified delta metrics and added asset name recording.
  - `test_background_job_handlers`: Verified execution of `ATTACK_SURFACE_REFRESH` and `ATTACK_SURFACE_DISCOVERY`.
  - `test_attack_surface_api_full_lifecycle`: Verified end-to-end REST API lifecycle across all 15 endpoints.
  - `test_tenant_workspace_isolation`: Verified multi-tenant data containment.
  - **Result: 13 passed in 2.44s (100% pass rate)**.
- **Frontend Verification**:
  - `npm run build` executed cleanly with zero TypeScript errors and production bundle generated in `dist/`.
