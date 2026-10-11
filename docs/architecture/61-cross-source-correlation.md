# SECTION 61 — CROSS-SOURCE CORRELATION & UNIFIED ENTITY CORRELATION
## CyberGuard Architecture Reference

---

### 1. Architectural Overview & Workflow Lifecycle
Section 61 implements the **Cross-Source Correlation & Unified Entity Correlation Layer** for CyberGuard. The system fuses heterogeneous security signals from diverse telemetry domains (Email, Network, Authentication, Endpoint, API, Threat Intelligence, Watchlists, and Behavioral Analytics) into explainable, evidence-backed security correlations and composite findings.

The complete workflow follows this deterministic pipeline:
```text
Telemetry / Artifacts / Findings / Intelligence
                    ↓
             Entity Resolution (UnifiedEntityResolver)
                    ↓
            Signal Normalization (CorrelationSignal)
                    ↓
            Temporal Alignment (Bounded Time Windows)
                    ↓
          Cross-Source Correlation (CrossSourceCorrelationEngine)
                    ↓
        Correlated Evidence Graph (Authoritative SecurityGraphService)
                    ↓
       Composite Finding / Signal (FindingModel is_composite=True)
                    ↓
             Unified Risk (Evidence Deduplication / Lineage)
                    ↓
          Alert / Incident (Enrichment / Co-occurrence clustering)
                    ↓
       Investigation / Attack Path (Pivot context & graph traversal)
                    ↓
            Response Workflow (Prioritized Playbook Guidance)
```

The system is strictly deterministic and evidence-backed:
- **No fake correlations, relationships, or timestamps**.
- **No duplicate graph, campaign, risk, alert, or detection engines**.
- **Confidence $\neq$ Risk**: Correlation confidence measures evidentiary association strength ($0.0 - 1.0$), while threat risk measures objective security peril ($0 - 100$).
- **Evidence Lineage & Anti-Double-Counting**: Overlapping evidence across correlated findings is discounted to prevent artificial risk inflation.

---

### 2. Signal Normalization
Signals entering the correlation layer are adapted into `CorrelationSignal` instances without redundant duplicate persistence:
- `signal_id`: Unique identifier referencing the primary source finding/event.
- `tenant_id`: Mandatory isolation key ensuring cross-tenant containment.
- `source_type`: Standardized source enum (`EMAIL`, `ENDPOINT`, `AUTHENTICATION`, `NETWORK`, `API`, `THREAT_INTEL`, `BEHAVIORAL`, `DETECTION_RULE`, `WATCHLIST`).
- `entity_refs`: Canonical entity IDs resolved via `UnifiedEntityResolver`.
- `finding_refs`, `indicator_refs`, `evidence_refs`: Pointers to persisted security evidence.
- `occurred_at`, `received_at`, `processed_at`: Distinct timestamps supporting temporal skew analysis.
- `severity`, `confidence`: Primary signal metrics.

---

### 3. Unified Entity Resolution
Entity resolution enforces a strict hierarchical identity resolution strategy:
1. **Stable Internal Entity ID**: Exact UUID lookup in the `entities` table (`SecurityGraphService`).
2. **Canonical External Identifier**: External canonical attributes (`sha256`, `cve`, `endpoint_agent_id`).
3. **Canonical Normalization**:
   - `IP`: Normalized IPv4/IPv6 address string.
   - `DOMAIN`: Lowercase, trimmed, canonical FQDN.
   - `URL`: Normalized protocol, host, port, path, and sorted query parameters.
   - `EMAIL`: Lowercased email address.
   - `HASH`: Lowercase hexadecimal digest.
4. **Deterministic Composite Key**: Type + Normalized value formatted via `make_canonical_key(type, value)`.
5. **Controlled Fuzzy & Ambiguity Preservation**: If multiple candidate entities share ambiguous attributes without deterministic proof, the resolver outputs status `AMBIGUOUS` with confidence $\le 0.50$ and does NOT auto-merge entities.
6. **Provenance & Audit Trail**: Every resolution decision is logged immutably in `EntityResolutionRecordModel` (`entity_resolution_records`), recording raw input, normalized output, resolution method, confidence, matched attributes, and timestamps.

---

### 4. Temporal Alignment & Clock Skew
Correlation respects distinct timestamp semantics:
- `occurred_at`: When the event originally occurred at the source sensor.
- `received_at`: Ingestion gateway timestamp.
- `processed_at`: Correlation engine evaluation time.
- `first_observed_at` & `last_observed_at`: Bounded duration of the correlation chain.

**Clock Skew & Late Telemetry Support**:
- Out-of-order events are permitted within the sliding temporal correlation window.
- Configurable window limits ($5\text{m}, 15\text{m}, 30\text{m}, 60\text{m}, 6\text{h}, 24\text{h}$).
- Events outside the configured boundary are strictly excluded (`time_diff \le window_seconds`).

---

### 5. Implemented Cross-Source Correlation Types
1. **`SHARED_INFRASTRUCTURE`**: Connects disparate findings that resolve to common infrastructure (e.g. email containing phishing URL resolving to malicious C2 domain and hosting IP).
2. **`TEMPORAL_ATTACK_SEQUENCE`**: Identifies multi-stage attack progressions occurring within bounded time windows across email, credential URLs, authentication events, and host actions.
3. **`AUTH_AND_ENDPOINT`**: Correlates suspicious authentication events (e.g. credential stuffing or new geo-location) with subsequent endpoint process execution or outbound socket connections on behalf of the same user/device.
4. **`BEHAVIORAL_AND_RULE_DETECTION`**: Bridges Section 60 statistical baseline anomalies (`BehavioralDeviationModel`) with Section 56/59 AST detection rule triggers (`DetectionMatchModel`) matching on the same entity.
5. **`WATCHLIST_AND_OBSERVATION`**: Correlates Section 53 continuously monitored indicators (`WatchedIndicatorModel`) with live observations across network, endpoint, or email telemetry.
6. **`SAME_ENTITY` / `SAME_INDICATOR` / `SHARED_ARTIFACT`**: Associative correlation connecting multiple analytical observations to a single resolved entity.

---

### 6. Knowledge Graph Integration
- **Authoritative Entity Store**: Section 14 `SecurityGraphService` remains the single source of truth for entity nodes and graph relationships.
- Section 61 calls `upsert_canonical_entity` to ensure resolved entities are canonicalized in the Knowledge Graph.
- Graph traversals utilize existing graph APIs without creating secondary graph databases.

---

### 7. Campaign Correlation Integration
- Section 15 `CampaignCorrelationService` remains authoritative for multi-tenant and multi-investigation campaign grouping.
- Section 61 provides campaign correlation with cross-source infrastructure chains, indicators, and temporal sequences.

---

### 8. Finding & Evidence Lineage
- Correlated signals produce or update a first-class `FindingModel` with `is_composite = True`, `parent_finding_id`, and `correlation_id`.
- Child findings retain their original identities, analyzers, and evidence items.
- Lineage is bidirectional: child findings link to composite parent, and composite findings preserve list of member finding IDs.

---

### 9. Unified Risk Engine Integration & Anti-Double-Counting
- Section 26 `RiskEngineService` remains authoritative for risk calculation.
- **Evidence Deduplication Guarantee**: When multiple findings share the same underlying indicator or raw evidence, the correlation layer discounts co-occurring risk to avoid multiplying severity.
- Risk contribution is calculated from deduplicated primary signals plus a structured correlation synergy bonus ($+5$ to $+15$) reflecting multi-stage confirmation.

---

### 10. Alert & Incident Integration
- Section 48 Alert Management and Section 50 Incident Management remain authoritative.
- Correlations enrich existing alerts or group co-occurring alerts into a unified case context to reduce analyst alert fatigue.

---

### 11. Threat Intelligence & Watchlists Integration
- Section 52 Threat Intelligence reputation scores strengthen or weaken contextual correlation confidence.
- Section 53 Watchlists (`WatchedIndicatorModel`) participate directly via `_correlate_watchlist_and_observation`.

---

### 12. Threat Hunting & Pivot Integration
- Section 54 Threat Hunting and Section 55 Advanced Pivots consume correlation results.
- Analysts can pivot from any correlation item directly into entity hunting, indicator watchlists, attack paths, or case investigations.

---

### 13. Behavioral Detection Integration
- Section 60 `BehavioralDeviationModel` anomalies participate in cross-source correlation.
- **Security Rule**: Behavioral anomalies do NOT automatically equal maliciousness. They contribute contextual anomaly weight and require corroborating detection matches or threat intelligence.

---

### 14. Idempotency & Invalidation
- Correlation keys are generated using deterministic SHA-256 hashes of:
  `workspace_id:correlation_type:sorted_member_ids:time_bucket`
- Replayed events do not duplicate existing correlations.
- If an underlying finding is retracted or an analyst rejects a correlation (`REJECTED`), the status transitions to `INVALIDATED` and historical audit records are preserved.

---

### 15. Background Jobs Integration
- Section 45 Background Job Worker executes asynchronous jobs:
  - `CROSS_SOURCE_CORRELATION`: On-demand or scheduled correlation evaluation.
  - `HISTORICAL_CORRELATION_SWEEP`: Historical lookback sweeps across ingested telemetry.

---

### 16. Realtime Updates Integration
- Section 46 Realtime WebSockets dispatch authoritative events:
  - `CORRELATION_CREATED`
  - `CORRELATION_UPDATED`
  - `CORRELATION_INVALIDATED`
  - `ENTITY_RESOLUTION_UPDATED`
  - `COMPOSITE_FINDING_CREATED`
- Scope: `CROSS_SOURCE_CORRELATION` and `ENTITY_RESOLUTION`.

---

### 17. API Contracts
All endpoints enforce `X-Workspace-ID` tenant isolation and standard RBAC:
- `GET /api/v1/correlations/overview`: High-level SOC KPIs.
- `GET /api/v1/correlations`: Paginated search with type, status, confidence filters.
- `GET /api/v1/correlations/:id`: Full detail with members, evidence, and provenance.
- `GET /api/v1/correlations/:id/timeline`: Sequential timeline sequence.
- `GET /api/v1/correlations/:id/explanation`: "Why Correlated?" explainability breakdown.
- `POST /api/v1/correlations/evaluate`: Trigger on-demand correlation.
- `POST /api/v1/correlations/:id/disposition`: Record analyst feedback (CONFIRMED, REJECTED, UNCERTAIN).
- `POST /api/v1/entities/resolve`: Deterministic entity resolution.
- `GET /api/v1/entities/resolution-history`: Audit trail of resolution decisions.

---

### 18. Frontend Implementation
- **Page**: `src/pages/CrossSourceCorrelationPage.tsx` mounted at `/correlations` and `/cross-source-correlation`.
- **Component**: `src/components/correlation/CrossSourceCorrelationView.tsx` with Olive/Sakura/Paper/Midnight themes:
  - SOC KPI Overview Banner.
  - Master-Detail Correlation Feed with real-time filters.
  - "Why Correlated?" Explainability Card with supporting reasons, contradictions, and missing telemetry alerts.
  - Chronological Event Sequence Timeline.
  - Participating Members & Evidence Matrix.
  - Interactive Unified Entity Resolver tool with live test input and resolution audit history.
  - Analyst Disposition Modal with mandatory justification logging.
- **Navigation**: Registered in `src/components/layout/Sidebar.tsx` with `GitMerge` icon.

---

### 19. Security, Privacy & Multi-Tenant Isolation
- **Tenant Containment**: All queries, resolvers, and job workers filter strictly by `workspace_id`. Cross-tenant correlation is impossible.
- **Privacy Controls**: Private employee telemetry is not leaked across tenant boundaries. Global threat intelligence IOCs remain shared without leaking tenant observation records.
- **Immutable Auditing**: `AuditLogModel` records every analyst disposition and resolution event.

---

### 20. Data Quality & Error Semantics
Explicit security distinctions enforced:
- **Missing Telemetry $\neq$ Benign Activity**: Missing endpoint or network sensors are reported as `Unavailable` rather than clean.
- **Intelligence Unavailable $\neq$ Clean Indicator**: Stale or unreachable TI returns status `UNKNOWN`.
- **Entity Unresolved $\neq$ Entities Unrelated**: Ambiguous matches are preserved as `AMBIGUOUS`.
- **Low Confidence $\neq$ False**: Confidence reflects evidentiary coverage, not verdict falsity.

---

### 21. Automated Testing Verification
Comprehensive test suites validated:
1. `backend/tests/test_section61_cross_source_correlation.py`:
   - Exact ID, External ID, and Canonical Normalization resolution tests.
   - Ambiguity preservation (no silent merging of ambiguous entities).
   - Multi-tenant isolation verification.
   - Cross-source shared infrastructure attack chain tests.
   - Authentication + Endpoint co-occurrence tests.
   - Behavioral baseline anomaly + AST detection rule match tests.
   - Section 53 Watchlist IOC observation tests.
   - Temporal window boundary and clock skew tests.
   - Composite finding generation and evidence deduplication tests.
   - Idempotency and duplicate event replay tests.
   - Analyst disposition workflow (CONFIRMED, REJECTED invalidation) tests.
   - REST API overview, detail, timeline, and resolution history tests.
2. **Regression Suite**: Sections 56, 57, 58, 59, 60, and 61 (92 passing tests).
3. **Frontend Build**: `tsc -b && vite build` passing with exit code 0.

---

### 22. Known Limitations & Boundaries
- Telemetry types not yet ingested by a deployed sensor (e.g. hardware TPM logs or cloud hypervisor telemetry) are marked as `UNAVAILABLE` rather than synthesized.
- Graph traversal depth is bounded to 3 hops during synchronous evaluation to ensure sub-second response times; wider historical sweeps are delegated to Section 45 background jobs.
