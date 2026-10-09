# Section 43 — History & Search Architecture & Verification

## 1. Purpose
The **History & Search Discovery Layer** establishes a unified, forensic-grade discovery mechanism across CyberGuard's accumulated investigations, reports, evidence, indicators, entities, findings, campaigns, and Threat Memory context. Rather than transforming CyberGuard into a generic, cluttered SIEM or logging dashboard, this system functions as an evidence-oriented investigation workstation:
- **Calm, information-dense, evidence-oriented** discovery.
- **Truthful representation**: strictly queries authoritative persisted database telemetry without synthetic counts, mock incidents, or hardcoded statistics.
- **Epistemic provenance**: cleanly distinguishes between `CURRENT_OBSERVATIONS`, `HISTORICAL_MEMORY`, `EXTERNAL_INTELLIGENCE`, and `ANALYST_VERIFIED` judgments.
- **Progressive disclosure & keyboard-first navigation**: `⌘K` / `Ctrl+K` global command search, URL-persisted filter states, server-side pagination, and real facet counts.

---

## 2. Search Architecture
The architecture is structured as a decoupled discovery layer resting directly on the persistent database models:

```
[ Frontend Client ]
      │
      ├── Global Search Modal (⌘K / Ctrl+K)
      ├── Historical Investigation Browser (/investigations)
      ├── Forensic Reports Browser (/reports)
      └── Cross-Investigation Indicator Detail Drawer
            │
            ▼ (REST API)
[ FastAPI Endpoints ]
      ├── GET /api/search
      ├── GET /api/search/indicator/{value}
      └── GET /api/investigations
            │
            ▼
[ SearchService ]
      ├── Query Normalizer (domain, URL, IP, hash, email case normalization)
      ├── Deterministic Result Ranker (Exact ID > Indicator > Title > Text)
      ├── Threat Memory Correlator (Section 23 Integration)
      └── Facet & Pagination Engine
            │
            ▼
[ SQLAlchemy Database Engine ]
      ├── InvestigationModel
      ├── ArtifactModel (Evidence)
      ├── IndicatorModel
      ├── FindingModel
      ├── CampaignModel
      ├── ReportModel
      └── ThreatMemoryModel
```

---

## 3. Searchable Resources
The search engine indexes and queries the following core persistent models:

1. **Investigations** (`InvestigationModel`):
   - ID (`INV-...`), incident number, title, description, classification, source type, status, risk score, severity.
2. **Indicators** (`IndicatorModel`):
   - Normalized value, original observed value, indicator type (domain, IPv4/IPv6, URL, SHA-256 hash, email address).
3. **Evidence / Artifacts** (`ArtifactModel`):
   - Artifact ID, name, SHA-256 hash, MIME type, artifact type, extraction source. Excludes raw file binary payload.
4. **Reports** (`ReportModel`):
   - Report ID, report number, title, report type, status, version, summary.
5. **Findings** (`FindingModel`):
   - Finding title, finding type, severity, analyzer, description.
6. **Campaigns** (`CampaignModel`):
   - Campaign ID, name, dominant attack type, correlation summary.
7. **Threat Memory** (`ThreatMemoryModel`):
   - Memory ID, indicator value, pattern signature, observations, verdict, analyst notes.

---

## 4. API Endpoints

### 4.1 Global Unified Search
- **Endpoint**: `GET /api/search`
- **Query Parameters**:
  - `q`: Search query string (identifier, indicator, keyword).
  - `types`: List of resource types to query (`investigation`, `indicator`, `evidence`, `report`, `finding`, `campaign`, `threat_memory`).
  - `risk`: Risk level filter (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
  - `severity`: Severity filter (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `SAFE`).
  - `status`: Status filter (`OPEN`, `INVESTIGATING`, `CONTAINED`, `RESOLVED`, `CLOSED`).
  - `source`: Source type filter (`EMAIL`, `URL`, `FILE`, `AUTHENTICATION`, `NETWORK`).
  - `from_time` / `to_time`: ISO8601 UTC timestamp bounds.
  - `limit`: Number of results (default `25`, max `100`).
  - `offset`: Pagination offset (default `0`).
- **Response**: `SearchResponse` containing `results`, `grouped_counts`, `has_more`, `next_offset`, `execution_time_ms`.

### 4.2 Cross-Investigation Indicator Lookup
- **Endpoint**: `GET /api/search/indicator/{value:path}`
- **Purpose**: Deep forensic drill-down for any domain, IP, hash, or email address across all historical investigations, campaigns, and Threat Memory.
- **Response**: `CrossInvestigationIndicatorResponse` containing:
  - `indicator_value`, `normalized_value`, `indicator_type`.
  - Aggregated metrics: `total_investigations`, `total_campaigns`, `total_evidence_objects`, `first_observed_at`, `last_observed_at`, `reputation`.
  - Provenance tiers:
    - `current_observations`: Direct link to active investigations.
    - `historical_memory`: Historical pattern data from Section 23 Threat Memory.
    - `external_intelligence`: Extracted external reputation or VT/AbuseIPDB scores.
    - `analyst_verifications`: Confirmed analyst decisions and notes.
    - `related_investigations`: Full list of investigations where the indicator appeared.

### 4.3 Historical Investigations Browser
- **Endpoint**: `GET /api/investigations`
- **Query Parameters**: `q`, `risk`, `severity`, `status`, `source`, `classification`, `from_time`, `to_time`, `sort`, `limit`, `offset`.
- **Response**: `InvestigationListResponse` with `items`, `total`, `limit`, `offset`, `facets` (real counts for risk, status, source_type, classification).

---

## 5. Normalization & Ranking

### Safe Normalization Layer
- **Cryptographic Hashes (SHA-256, MD5, SHA-1)**: Lowercased, stripped of whitespace. Exact matching only (no fuzzy matching on hashes).
- **Domain Names**: Lowercased, trailing dot removed, scheme stripped if inadvertently typed.
- **IPv4 / IPv6 Addresses**: Stripped of ports and whitespace.
- **Email Addresses**: Domain portion lowercased, surrounding whitespace trimmed. Original observed address preserved.
- **Identifiers (`INV-...`, `REP-...`, `ART-...`)**: Uppercased, normalized to canonical ID structure.

### Deterministic Ranking Matrix
Results are sorted strictly by a calibrated relevance hierarchy:
1. **1.0**: Exact ID match or exact indicator/hash match.
2. **0.9**: Exact title match.
3. **0.8**: Identifier prefix or domain structural match.
4. **0.7**: Substring or keyword match in title.
5. **0.5**: Substring match in description or notes.

---

## 6. Frontend User Experience

### 6.1 Historical Investigations Page (`/investigations`)
- Replaces legacy in-memory stores with authoritative backend telemetry via `searchService.listInvestigations()`.
- **URL-Persisted State**: All search inputs, active filter selections, sort options, and page numbers are synchronized to browser URL parameters (`?q=...&risk=HIGH&status=INVESTIGATING&page=2`). Supports browser back/forward and shareable links.
- **Progressive Disclosure Filters**: Collapsible filter drawer revealing Risk, Status, Source Type, and Time Window with real calculated facet counts.
- **Active Filter Chips**: Removable chips displaying active constraints with a 1-click "Clear all" button.
- **Compact Forensic Table**: Risk score badge, Investigation title + ID, Classification, Source, Findings & IOC count, Status, Last Updated timestamp, and quick link to Workspace.
- **Server-Side Pagination**: Bounded query loads with previous/next page navigation.

### 6.2 Global Command Search (`⌘K` / `Ctrl+K`)
- Topbar integrated command palette accessible via global shortcut (`⌘K` / `Ctrl+K`) or clicking the search trigger in the header.
- **Debounced input** (250ms) with request deduplication.
- **Keyboard navigation**: Arrow Up / Down, Enter to select, Escape to close.
- **Grouped Categories**: `EXACT MATCHES`, `INVESTIGATIONS`, `INDICATORS`, `REPORTS`, `EVIDENCE`, `FINDINGS`, `THREAT MEMORY`.
- **Scope Filters**: Quick chips to restrict query to specific resource types.

### 6.3 Cross-Investigation Indicator Detail Drawer
- Slide-over drawer displaying cross-investigation statistics, first/last seen timestamps, and epistemic tabs:
  - **CURRENT INVESTIGATION**: Telemetry observed in active incident.
  - **HISTORICAL MEMORY**: Previous incident appearances from Threat Memory.
  - **EXTERNAL INTEL**: Third-party reputation feeds.
  - **ANALYST VERIFIED**: Human analyst decisions.
- Direct navigation to any associated historical investigation.

---

## 7. Security, Tenant Isolation & Privacy
1. **Tenant Boundaries**: All search queries and indicator lookups accept `tenant_id` context and enforce tenant boundary filters server-side.
2. **Authorization & IDOR Protection**: Searches do not bypass model authorization. Query parameters cannot retrieve objects outside authorized tenant scopes.
3. **Data Sanitization & Privacy**: General search results return strictly metadata, highlights, titles, and IDs. Raw email MIME bodies, decrypted payloads, credentials, and API secrets are never returned in search responses.
4. **XSS Protection**: All matched strings and user queries are rendered as safe text nodes in React, preventing HTML/script injection from attacker-controlled email subjects or domain names.
5. **URL Safety**: URLs returned in search results are rendered safely without causing server-side requests or automatic navigation.

---

## 8. Verification & Test Suite

Automated verification is covered by `backend/tests/test_section43_history_and_search.py`:
1. `test_exact_investigation_lookup`: Verifies exact lookup by investigation number returns 1.0 relevance.
2. `test_indicator_search_and_provenance`: Verifies domain search discovers indicator and distinguishes provenance tiers.
3. `test_investigations_list_filtering_and_facets`: Verifies status/risk filtering and facet count accuracy.
4. `test_empty_database_truthful_state`: Verifies non-existent queries return empty lists without fake records or crashes.
5. `test_search_sanitization_and_injection_safety`: Verifies pathological SQL, XSS, and script characters are safely handled.
6. `test_reports_search_discovery`: Verifies forensic report discovery by title and report ID.

### Test Execution Commands
```bash
# Backend test suite
PYTHONPATH=. ./backend/venv/bin/pytest backend/tests/test_section43_history_and_search.py

# Regression verification
PYTHONPATH=. ./backend/venv/bin/pytest backend/tests/test_section39_investigation_workspace.py backend/tests/test_section42_report_workspace.py

# Frontend build & lint
npm run build
npm run lint
```
Result: **100% tests passing, 0 TypeScript build errors, 0 linter errors.**
