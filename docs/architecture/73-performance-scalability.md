# Section 73: Performance & Scalability Architecture

## 1. Architecture Baseline
CyberGuard is architected as an AI-powered cyber threat, phishing, and digital impersonation detection and response platform. Prior to Section 73, core operations executed with functional completeness and strict Section 72 security hardening. However, as enterprise scale increases across ingested email volume, endpoint telemetry, threat intelligence feeds, graph traversals, and multi-analyst concurrency, performance bottlenecks emerge without bounded concurrency and low-latency data access patterns.

### Component Baseline
- **Backend API**: FastAPI asynchronous framework serving REST and SSE streams.
- **Database**: SQLite (local development and integration test topology) and PostgreSQL (production topology) with SQLAlchemy ORM.
- **Evidence Storage**: Content-addressable file storage with SHA-256 verification and streaming chunk verification.
- **Analysis Orchestrator**: Multi-task DAG pipeline (`initialize_run_dag` and `execute_run`).
- **Telemetry Ingestion**: Endpoint collector ingesting security events, heartbeat payloads, and behavioral baselines.
- **Real-Time Hub**: Server-Sent Events (SSE) broadcasting monotonic event streams.

---

## 2. Performance Bottlenecks Discovered
During the repository-first performance audit, the following concrete bottlenecks were identified:
1. **Redundant Email Parsing in Analysis Orchestrator**: In `execute_run()`, tasks (`MIME_PARSING`, `AUTHENTICATION_ANALYSIS`, `SMTP_RELAY_ANALYSIS`, `ATTACHMENT_DISCOVERY`, `IOC_EXTRACTION`, `INTELLIGENCE_ENRICHMENT`, `NLP_SOCIAL_ENGINEERING`, `RISK_ASSESSMENT`) sequentially and independently invoked `EmailParserService.parse_eml_bytes(raw_bytes, ...)` up to 7 times on identical artifact bytes.
2. **N+1 Task Dependency Lookups**: Upstream dependency validation in `execute_run()` issued sequential `db.query(AnalysisTaskModel).filter(AnalysisTaskModel.id == d_id).first()` database calls inside the task execution loop for every task and dependency.
3. **Database Index Gaps on High-Traffic Query Paths**:
   - `CaseModel` lacked composite indexes for `(workspace_id, status)`, `(workspace_id, updated_at)`, and `(workspace_id, priority)`.
   - `IncidentModel` lacked composite indexes for `(workspace_id, status)`, `(workspace_id, created_at)`, and `(workspace_id, severity)`.
   - `EvidenceModel` lacked composite indexes for `(tenant_id, integrity_status)`, `(tenant_id, source_type)`, and `(tenant_id, upload_timestamp)`.
4. **Unprotected External Service Invocation Cascades**: Threat intelligence lookups and LLM provider calls risked cascading timeouts and thread pool exhaustion during third-party outages without a fast-failing circuit breaker pattern.
5. **Absence of Centralized Latency Percentile Tracking**: Metrics lacked percentiles (p50, p95, p99), throughput calculations, and automatic slow-operation diagnostics against defined performance budgets.

---

## 3. Database Optimization
Database performance was optimized by addressing hot query paths identified in dashboard queries, alert triage queues, and case searches:
- **Composite Index Additions**: Added multi-column composite indexes that directly align with workspace-scoped filtering and ordering.
- **Elimination of N+1 Queries**: Replaced repeated queries with in-memory map resolution in the analysis orchestrator and eager loading relationships (`lazy="selectin"`).
- **Bounded Result Sets**: Enforced server-side `limit` and `offset` constraints across all query endpoints (capped at 200 items per page max).

---

## 4. Query & Index Strategy
The high-value composite indexes added in Section 73 include:
```sql
-- Case Management
CREATE INDEX ix_cases_workspace_status ON cases (workspace_id, status);
CREATE INDEX ix_cases_workspace_updated ON cases (workspace_id, updated_at);
CREATE INDEX ix_cases_workspace_priority ON cases (workspace_id, priority);

-- Incident Management
CREATE INDEX ix_incidents_workspace_status ON incidents (workspace_id, status);
CREATE INDEX ix_incidents_workspace_created ON incidents (workspace_id, created_at);
CREATE INDEX ix_incidents_workspace_severity ON incidents (workspace_id, severity);

-- Evidence & Forensics
CREATE INDEX ix_evidence_tenant_integrity ON evidence (tenant_id, integrity_status);
CREATE INDEX ix_evidence_tenant_source ON evidence (tenant_id, source_type);
CREATE INDEX ix_evidence_tenant_upload ON evidence (tenant_id, upload_timestamp);
```
**Rationale**: In a multi-tenant SOC, queries are almost universally filtered by `tenant_id`/`workspace_id` combined with either status, priority, or timestamp for descending sort. Composite B-tree indexes allow direct index seeks without scanning unrelated tenant rows or performing in-memory sorting.

---

## 5. Analysis Concurrency & Orchestrator Optimization
In `backend/services/analysis_orchestrator.py`:
1. **In-Memory Task Dependency Map**: All tasks for the run are indexed into a local dictionary `task_map: Dict[str, AnalysisTaskModel] = {t.id: t for t in tasks}`, completely removing repeated database roundtrips when checking task dependency states.
2. **Parsed Email In-Memory Memoization**: Reusable `parsed_email_cache` is retained in memory for the duration of `execute_run()`. All 7 email analyzer tasks share the single parsed output, reducing CPU parsing overhead by over 80%.
3. **Execution Telemetry**: Each task duration is recorded using high-resolution monotonic clocks (`time.perf_counter()`) and fed directly into `global_performance_tracker`.

---

## 6. Job Architecture
Background jobs leverage Section 45 worker queues (`BackgroundJobManager`):
- **Worker Concurrency Bounds**: Worker pools are bounded (default 4 concurrent workers) to prevent thread/process exhaustion.
- **Job Priorities**: Priority levels (`CRITICAL`, `HIGH`, `NORMAL`, `LOW`, `BULK`) guarantee security-critical email analysis and incident correlation are never starved by bulk report exports.
- **Cancellation Checks**: Running jobs verify cancellation state between discrete task execution steps.

---

## 7. Safe Multi-Tenant Caching
The `MultiTenantCacheManager` in `backend/services/cache_service.py` provides:
- **Strict Tenant Partitioning**: All keys are prefixed as `{tenant_id}:{category}:{raw_key}`. A cache hit in one tenant can never return data belonging to another tenant.
- **TTL Expiration**: Expired entries are evicted lazily upon access and pruned periodically.
- **Bounded Capacity & LRU Eviction**: When cache size exceeds `max_entries` (default 5,000), least recently used entries are evicted.
- **Scoped Invalidation**: Supports granular invalidation by `invalidate_key()`, `invalidate_category()`, or entire `invalidate_tenant()`.

---

## 8. Threat-Intelligence Optimization
Threat intelligence enrichment (Section 52) is optimized via:
- **Tenant-Scoped Reputation Caching**: Normalized domain, IP, and hash reputation lookups are cached with configurable TTLs (default 300 seconds).
- **Batch Lookups**: Lookalike domain detection processes batch domains in a single pass (`detect_lookalikes_batch`).
- **Resilient Circuit Breaker**: VirusTotal and RDAP network calls are protected by circuit breakers that fail fast during outages.

---

## 9. Graph Optimization
The Security Knowledge Graph (Section 23, Section 40):
- **Bounded Subgraph Traversal**: Restricts graph expansion queries to a maximum depth (default 3 hops) and maximum node count (default 100 nodes).
- **Viewport-Driven UI Rendering**: Frontend renders nodes within the active canvas viewport, preventing DOM bloat during large attack path investigations.
- **Progressive Node Disclosure**: Lazy-loads child evidence and entity details only when an analyst clicks or expands an investigation node.

---

## 10. Telemetry Ingestion
Endpoint agent telemetry (Sections 31–33):
- **Batch Processing**: Endpoints submit telemetry events in bounded batches (max 100 events per batch).
- **Asynchronous Enrichment**: Telemetry batches are immediately validated and persisted; complex cross-incident correlation runs asynchronously to maintain endpoint response latencies under 50ms.
- **Payload Validation**: Strict Pydantic models validate incoming telemetry schemas, rejecting malformed events early.

---

## 11. Report Generation
Executive and forensic report generation (Section 69):
- **Asynchronous Execution**: Heavy PDF and CSV exports run as background jobs with explicit lifecycle states (`QUEUED`, `RUNNING`, `COMPLETED`, `FAILED`).
- **Stream-Based Export**: CSV exports stream rows directly rather than buffering hundreds of thousands of finding records in memory.
- **Preloaded Entity Relationships**: Report data queries use batched relational joins to eliminate N+1 queries across findings, indicators, and timeline events.

---

## 12. Realtime Performance
Real-time analysis updates (Section 46):
- **Monotonic Event Sequencing**: Realtime SSE publishers assign strictly monotonic sequence numbers (`sequence`), allowing clients to resume or reconcile missed events without full refreshes.
- **Backpressure & Buffer Caps**: In-memory broadcast queues cap client backpressure buffers (max 100 queued events per subscriber).
- **Non-Blocking Broadcasting**: Event broadcasts run asynchronously without blocking core transaction commits.

---

## 13. Frontend Performance
Frontend performance optimizations:
- **Route Code Splitting**: Production bundle built via Vite and Rollup with code splitting for workspaces, reducing initial load latency.
- **Debounced Input & Search**: Threat hunting and audit log searches debounce query inputs by 300ms, eliminating redundant backend calls during typing.
- **Memoized State Computations**: React components utilize `useMemo` and `useCallback` for graph calculations and table sorting.
- **Virtualized Tables**: Large collections (alerts, audit events, telemetry logs) use bounded pagination (25, 50, 100 rows per view).

---

## 14. LLM Performance & Cost Control
AI Analyst & SOC Copilot integrations (Sections 25, 39, 54, 72):
- **Context Filtering**: Prompts include only sanitized, relevant findings and MITRE techniques; raw multi-megabyte binary dumps are never sent.
- **Bounded Output Tokens**: Max token constraints prevent unbounded model generation loops.
- **Model Versioning**: Cache keys incorporate model provider, model version, and prompt version to prevent stale inference masquerading.
- **Tenant Scope Isolation**: AI prompt contexts and responses are strictly partitioned by tenant ID.

---

## 15. External-Provider Controls & Circuit Breakers
Implemented in `backend/services/circuit_breaker.py`:
- **Canonical 3-State FSM**:
  - `CLOSED`: Normal operation; failures are tracked.
  - `OPEN`: Fail fast immediately; raises `CircuitBreakerOpenException` without contacting provider.
  - `HALF_OPEN`: Probing state; permits limited canary requests to test provider recovery.
- **Configurable Thresholds**:
  - `failure_threshold`: 5 consecutive errors to trip.
  - `recovery_timeout_seconds`: 30.0 seconds wait in OPEN.
  - `half_open_success_threshold`: 2 consecutive successes to close.
- **Central Registry**: `CircuitBreakerRegistry` manages breakers across VirusTotal, RDAP, Anthropic, OpenAI, and Geolocation providers.

---

## 16. Storage Strategy
Evidence and artifact storage (Section 68):
- **Content-Addressable Hashing**: Storage references are keyed by cryptographic SHA-256 digests.
- **Streaming Chunks**: File ingestion and retrieval use streaming chunks (64 KB) to bound memory footprint regardless of file size.
- **Separation of Metadata and Payloads**: Database records hold forensic metadata, custody logs, and hashes; large file payloads reside on filesystem/object storage.

---

## 17. Observability & Performance Metrics
Implemented in `backend/services/performance_service.py`:
- **Percentile Calculation**: Tracks mathematically accurate p50, p95, and p99 latencies using sorted ring-buffer sample windows.
- **Throughput & Error Rates**: Calculates operations per second and error rate percentages per subsystem.
- **Performance Budgets**: Evaluates observed p95 latencies against established budgets:
  - `API_REQUEST`: Target p50 < 100ms, p95 < 250ms, max 1,000ms.
  - `DATABASE_QUERY`: Target p50 < 20ms, p95 < 50ms, max 250ms.
  - `ANALYSIS_DAG`: Target p50 < 1,000ms, p95 < 2,500ms, max 6,000ms.
  - `BACKGROUND_JOB`: Target p50 < 2,000ms, p95 < 5,000ms, max 15,000ms.
  - `THREAT_INTEL`: Target p50 < 300ms, p95 < 800ms, max 3,000ms.
  - `LLM_INFERENCE`: Target p50 < 1,500ms, p95 < 3,500ms, max 8,000ms.
  - `REPORT_GENERATION`: Target p50 < 1,200ms, p95 < 3,000ms, max 10,000ms.
  - `GRAPH_TRAVERSAL`: Target p50 < 80ms, p95 < 200ms, max 800ms.
  - `SEARCH_HUNTING`: Target p50 < 250ms, p95 < 600ms, max 2,000ms.
- **Slow-Operation Ring Buffer**: Operations exceeding `max_duration_ms` are logged with sanitized diagnostic metadata for administrator inspection.
- **Admin REST API**:
  - `GET /api/admin/performance/metrics`
  - `GET /api/admin/performance/slow-operations`
  - `GET /api/admin/performance/circuits`
  - `POST /api/admin/performance/circuits/{service_name}/reset`
  - `GET /api/admin/performance/cache-stats`

---

## 18. Load Testing
Synthetic load tests executed against the test suite validated:
- Concurrent operation recordings across multi-threaded workers.
- High-frequency cache set/get operations with concurrent eviction.
- Circuit breaker state stability under rapid failure bursts.
- Memory stability during repeated DAG execution runs.

---

## 19. Graceful Degradation
Under resource pressure or third-party outages:
1. **Threat Intelligence Outages**: Circuit breaker trips to `OPEN`. Core email analysis and heuristic detection continue normally; findings note that external TI was temporarily unavailable.
2. **LLM Provider Outages**: Copilot and natural language summaries degrade gracefully to rule-based explainability and deterministic findings.
3. **Queue Saturation**: Background jobs queue safely without dropping work; high-priority incident investigations take precedence over bulk reporting.
4. **SSE Client Disconnects**: Clients reconnect and retrieve authoritative snapshot state via standard REST endpoints using monotonic sequence checkpoints.

---

## 20. Scaling Assumptions
1. **Worker Pools**: Horizontal worker scaling via Celery or Redis queues if background job throughput exceeds single-node capacity.
2. **Database Read Replicas**: Read-heavy workloads (threat hunting, historical audit searches) can be routed to PostgreSQL read replicas using the existing composite index schema.
3. **Distributed Cache**: In-memory `MultiTenantCacheManager` can be replaced with a Redis-backed multi-tenant cluster by keeping the exact same key prefixing pattern (`{tenant_id}:{category}:{key}`).

---

## 21. Known Bottlenecks & Residual Constraints
1. **Local SQLite Limitations**: In local test environments, SQLite serializes write transactions. Production deployments must use PostgreSQL with connection pooling (PgBouncer).
2. **Memory Footprint for Massive Investigation Graphs**: Investigations with >5,000 interrelated nodes require server-side graph clustering or pagination before browser visualization.
3. **External Rate Limits**: Third-party threat intelligence APIs impose strict daily API key quotas that require enterprise tier upgrades for sustained high-volume scanning.

---

## 22. Future Scaling Options
1. **Redis-Backed Distributed Cache & Circuit Breaker State**: Share circuit breaker trips across a cluster of API worker nodes.
2. **Partitioned Historical Audit Tables**: Partition PostgreSQL audit log tables by month or year to keep active B-tree index sizes compact.
3. **Async Streaming Compression**: Enable Brotli compression on HTTP responses exceeding 10 KB for high-latency client networks.
