# 04 — API Inventory & Endpoint Audit

> **Service Framework:** FastAPI (ASGI / Uvicorn)  
> **Total Active Endpoints:** 51 routes across 13 route controllers  
> **Global Rate Limiting:** Enforced via `RateLimiterMiddleware`  
> **Global Security Headers:** Enforced via `SecurityHeadersMiddleware`  

---

## 1. Complete API Route Inventory

### 1.1 Core Email Ingestion & Forensics (`/api/emails`)
*Controller: `backend/api/routes/email.py`*

| Method | Path | Purpose | Handler Function | Auth / Headers | Request Format | Response Format | DB Effect | External Services | Frontend Consumer | Status |
|---|---|---|---|---|---|---|---|---|---|---|
| `POST` | `/api/emails/analyze` | Core EML upload & forensic analysis pipeline | `analyze_email` | Optional `X-User` | `multipart/form-data` (`file`) | `EmailAnalysisResponse` (JSON) | `evidence`, `eml_store`, `audit_logs`, `email_analyses`, `analysis_payloads`, `campaigns` | IP-API, RDAP, DNS, Gemini (optional) | `AnalyzeEmail.tsx`, `InvestigationWorkspace.tsx` | `IMPLEMENTED` |
| `GET` | `/api/emails/{id}/analysis` | Retrieve canonical immutable analysis by ID/SHA-256 | `get_canonical_email_analysis` | None | URL path param | `EmailAnalysisResponse` (JSON) | Read `analysis_payloads` | None | `InvestigationWorkspace.tsx`, `InvestigationHistory.tsx` | `IMPLEMENTED` |
| `GET` | `/api/emails/{id}/download` | Download authentic raw `.eml` file | `download_eml_file` | None | URL path param | Binary stream (`message/rfc822`) | Read `evidence` & disk | None | `EmailSectionView.tsx`, `Dashboard.tsx` | `IMPLEMENTED` |
| `GET` | `/api/emails/{id}/raw-eml` | Get unparsed raw RFC-822 text content | `get_raw_eml_text` | None | URL path param | `text/plain` | Read `eml_store` disk | None | `EmailSectionView.tsx` | `IMPLEMENTED` |
| `GET` | `/api/emails/stored-emls/inventory` | List filesystem inventory of preserved `.eml` files | `list_stored_emls_endpoint` | None | None | `List[Dict]` (JSON) | Read `eml_store` disk | None | SOC Storage Tools | `IMPLEMENTED` |
| `GET` | `/api/emails/{sha256}/timeline` | Get chain-of-custody chronological timeline | `get_email_investigation_timeline` | None | URL path param | `InvestigationTimelineResponse` | Read `audit_logs` | None | `EmailSectionView.tsx` | `IMPLEMENTED` |
| `GET` | `/api/emails/lookup/{ip}` | Manual contextual IP intelligence lookup | `lookup_ip_intelligence` | None | URL path param | `IPIntelligence` (JSON) | Memory cache read/write | IP-API / IPInfo | `ThreatIntelligence.tsx`, `IntelligenceSectionView.tsx` | `IMPLEMENTED` |
| `GET` | `/api/emails/lookup-domain/{domain}` | Manual DNS & RDAP registration lookup | `lookup_domain_intelligence` | None | URL path param | `DomainIntelligence` (JSON) | Memory cache read/write | dnspython, RDAP.org | `ThreatIntelligence.tsx`, `IntelligenceSectionView.tsx` | `IMPLEMENTED` |
| `GET` | `/api/emails/detect-lookalike/{domain}` | Detect brand impersonation & homoglyphs | `detect_lookalike_domain` | None | URL path param | `LookalikeDetectionResult` | None (pure function) | None (Local brands.json) | `AnalysisSectionView.tsx` | `IMPLEMENTED` |
| `POST` | `/api/emails/analyze-url` | Statically analyze single URL without fetching | `analyze_url_endpoint` | None | `URLAnalysisRequest` (JSON) | `URLAnalysisResult` (JSON) | None | None | `AnalysisSectionView.tsx` | `IMPLEMENTED` |
| `POST` | `/api/emails/calculate-threat-score` | Compute deterministic 9-category threat score | `calculate_threat_score_endpoint` | None | `EmailAnalysisResponse` (JSON) | `ThreatScoreResult` (JSON) | None | None | `AnalysisSectionView.tsx` | `IMPLEMENTED` |
| `POST` | `/api/emails/ml-classify` | NLP TF-IDF + Logistic Regression inference | `classify_email_text` | None | `MLClassifyRequest` (JSON) | `MLAssessmentResult` (JSON) | None | None (Local Scikit-Learn model) | `InvestigationContext.tsx` | `IMPLEMENTED` |
| `POST` | `/api/emails/ai-analyst` | Generate AI Analyst structured assessment | `generate_ai_analyst_assessment` | None | `EmailAnalysisResponse` (JSON) | `AIAnalystAssessment` (JSON) | None | Google Gemini / OpenAI REST | `OverviewSectionView.tsx` | `IMPLEMENTED` |
| `POST` | `/api/emails/investigation-graph` | Generate directed relationship graph | `generate_investigation_graph` | None | `EmailAnalysisResponse` (JSON) | `InvestigationGraphResponse` | None | None | `InvestigationSectionView.tsx` | `IMPLEMENTED` |
| `POST` | `/api/emails/investigation-graph/filter` | Filter graph nodes and prune dangling edges | `filter_investigation_graph` | None | `GraphFilterRequest` (JSON) | `InvestigationGraphResponse` | None | None | `InvestigationSectionView.tsx` | `IMPLEMENTED` |

---

### 1.2 Case Management Subsystem (`/api/cases`)
*Controller: `backend/api/routes/cases.py`*

| Method | Path | Purpose | Handler Function | Auth | Request Format | Response Format | DB Effect | Frontend Consumer | Status |
|---|---|---|---|---|---|---|---|---|---|
| `POST` | `/api/cases` | Create new incident case | `create_case_endpoint` | None | `CaseCreateRequest` | `CaseDetailResponse` (201) | `INSERT INTO cases`, `audit_logs` | `Cases.tsx` | `IMPLEMENTED` |
| `GET` | `/api/cases` | List cases with status/severity filters | `list_cases_endpoint` | None | Query params | `CaseListResponse` | `SELECT cases` | `Cases.tsx`, `Dashboard.tsx` | `IMPLEMENTED` |
| `GET` | `/api/cases/{case_id}` | Get full case dossier with notes/findings | `get_case_endpoint` | None | Path param | `CaseDetailResponse` | `SELECT cases` (joined) | `CaseDetail.tsx` | `IMPLEMENTED` |
| `PATCH` | `/api/cases/{case_id}` | Update case status or severity | `update_case_endpoint` | None | `CaseUpdateRequest` | `CaseDetailResponse` | `UPDATE cases`, `INSERT audit_logs` | `CaseDetail.tsx` | `IMPLEMENTED` |
| `POST` | `/api/cases/{case_id}/emails` | Link analyzed email to case | `add_email_to_case_endpoint` | None | `CaseEmailCreateRequest` | `CaseEmailResponse` (201) | `INSERT case_emails`, `audit_logs` | `CaseDetail.tsx`, `ReportSectionView.tsx` | `IMPLEMENTED` |
| `DELETE` | `/api/cases/{case_id}/emails/{email_id}`| Detach email from case | `remove_email_from_case_endpoint` | None | Path params | 204 No Content | `DELETE case_emails`, `audit_logs` | `CaseDetail.tsx` | `IMPLEMENTED` |
| `POST` | `/api/cases/{case_id}/notes` | Add analyst observation note | `add_note_endpoint` | None | `CaseNoteCreateRequest` | `CaseNoteResponse` (201) | `INSERT case_notes`, `audit_logs` | `CaseDetail.tsx` | `IMPLEMENTED` |
| `POST` | `/api/cases/{case_id}/findings` | Add structured forensic finding | `add_finding_endpoint` | None | `CaseFindingCreateRequest` | `CaseFindingResponse` (201) | `INSERT case_findings`, `audit_logs`| `CaseDetail.tsx` | `IMPLEMENTED` |

---

### 1.3 Campaign Correlation & Cross-Email Intelligence (`/api/campaigns` & `/api/correlation`)
*Controller: `backend/api/routes/correlation.py`*

| Method | Path | Purpose | Handler Function | Request Format | Response Format | DB Effect | Frontend Consumer | Status |
|---|---|---|---|---|---|---|---|---|
| `GET` | `/api/campaigns` | List all tracked campaign clusters | `list_campaigns_endpoint` | Query params | `List[CampaignClusterItem]` | Read `campaigns` | `CampaignIntelligence.tsx` | `IMPLEMENTED` |
| `GET` | `/api/campaigns/{campaign_id}` | Get campaign detail dossier | `get_campaign_detail_endpoint`| Path param | `CampaignDetailResponse` | Read `campaigns`, `campaign_emails`| `CampaignIntelligence.tsx` | `IMPLEMENTED` |
| `GET` | `/api/campaigns/{campaign_id}/graph` | Generate campaign relationship graph | `get_campaign_graph_endpoint` | Path param | `InvestigationGraphResponse` | Read `campaigns` | `CampaignIntelligence.tsx` | `IMPLEMENTED` |
| `POST` | `/api/campaigns/detect-alert` | Check if an email matches a campaign cluster | `detect_campaign_alert_endpoint` | Email JSON | `CampaignAlertResponse` | Read `campaigns` | `InvestigationContext.tsx` | `IMPLEMENTED` |
| `POST` | `/api/correlation/email-against-cases` | Correlate email against open cases | `correlate_email_against_cases` | Email JSON | `CampaignCorrelationResponse` | Read `cases`, `case_emails` | `InvestigationSectionView.tsx` | `IMPLEMENTED` |
| `POST` | `/api/correlation/case-against-cases` | Correlate case against all other cases | `correlate_case_against_cases` | Case ID query | `CampaignCorrelationResponse` | Read `cases` | `CaseDetail.tsx` | `IMPLEMENTED` |
| `POST` | `/api/correlation/direct-compare` | Side-by-side compare 2 entities | `direct_compare_entities` | `DirectCompareRequest` | `DirectCompareResponse` | Read DB | `CaseDetail.tsx` | `IMPLEMENTED` |

---

### 1.4 Cross-Email Investigation Workspace (`/api/cross-investigation`)
*Controller: `backend/api/routes/cross_investigation.py`*

| Method | Path | Purpose | Handler Function | Request Format | Response Format | DB Effect | Frontend Consumer | Status |
|---|---|---|---|---|---|---|---|---|
| `POST` | `/api/cross-investigation/analyze` | Discover related email activity from index | `analyze_cross_email_correlations_endpoint` | Email JSON | `CrossEmailAnalysisResponse` | Inverted index lookup | `CrossInvestigationWorkspacePage.tsx` | `IMPLEMENTED` |
| `POST` | `/api/cross-investigation/compare` | 10-dimension comparison matrix (2-5 emails)| `compare_emails_endpoint` | `CompareEmailsRequest` | `ComparisonMatrixResponse` | Read `analysis_payloads` | `CrossInvestigationWorkspacePage.tsx` | `IMPLEMENTED` |
| `POST` | `/api/cross-investigation/graph` | Build multi-email joint relationship graph | `get_cross_email_graph_endpoint` | `CrossEmailGraphFilterRequest` | `InvestigationGraphResponse` | Memory graph builder | `CrossInvestigationWorkspacePage.tsx` | `IMPLEMENTED` |
| `POST` | `/api/cross-investigation/decision` | Record false-positive suppression / link | `record_analyst_decision_endpoint` | `AnalystDecisionRequest` | `AnalystDecisionItem` | `INSERT analyst_decisions` | `CrossInvestigationWorkspacePage.tsx` | `IMPLEMENTED` |
| `GET` | `/api/cross-investigation/decisions` | List analyst feedback decisions | `list_analyst_decisions_endpoint` | Query `limit` | `List[AnalystDecisionItem]` | Read `analyst_decisions` | SOC Review | `IMPLEMENTED` |

---

### 1.5 Probabilistic Threat Attribution (`/api/emails/attribution` & `/api/cases/attribution`)
*Controller: `backend/api/routes/attribution.py`*

| Method | Path | Purpose | Handler Function | Request Format | Response Format | DB Effect | Frontend Consumer | Status |
|---|---|---|---|---|---|---|---|---|
| `POST` | `/api/emails/attribution` | Compute infrastructure attribution | `calculate_attribution_endpoint` | `EmailAnalysisResponse` | `AttributionResult` | `INSERT audit_logs` | `OverviewSectionView.tsx` | `IMPLEMENTED` |
| `GET` | `/api/emails/{email_id}/attribution` | Retrieve stored email attribution | `get_email_attribution_endpoint` | Path param | `AttributionResult` | Read DB | `EmailSectionView.tsx` | `IMPLEMENTED` |
| `GET` | `/api/cases/{case_id}/attribution` | Aggregate attribution across case emails | `get_case_attribution_endpoint` | Path param | `CaseAttributionResponse` | Read `case_emails` | `CaseDetail.tsx` | `IMPLEMENTED` |
| `GET` | `/api/campaigns/{campaign_id}/attribution` | Aggregate attribution for campaign | `get_campaign_attribution_endpoint`| Path param | `CampaignAttributionResponse`| Read `campaign_emails` | `CampaignIntelligence.tsx` | `IMPLEMENTED` |

---

### 1.6 Evidence Confidence Engine (`/api/emails/confidence`)
*Controller: `backend/api/routes/confidence.py`*

| Method | Path | Purpose | Handler Function | Request Format | Response Format | DB Effect | Frontend Consumer | Status |
|---|---|---|---|---|---|---|---|---|
| `POST` | `/api/emails/confidence` | Evaluate 8-domain confidence matrix | `calculate_confidence_endpoint` | `EmailAnalysisResponse` | `EmailConfidenceResponse` | `INSERT audit_logs` | All Investigation Sections | `IMPLEMENTED` |
| `GET` | `/api/emails/{id}/confidence` | Retrieve/compute confidence for email | `get_email_confidence_endpoint` | Path param | `EmailConfidenceResponse` | Read `analysis_payloads` | `OverviewSectionView.tsx` | `IMPLEMENTED` |

---

### 1.7 Forensic PDF Reports (`/api/reports`)
*Controller: `backend/api/routes/reports.py`*

| Method | Path | Purpose | Handler Function | Request Format | Response Format | DB Effect | Frontend Consumer | Status |
|---|---|---|---|---|---|---|---|---|
| `POST` | `/api/reports/generate` | Generate vector PDF dossier | `generate_forensic_report` | `ReportGenerateRequest` | PDF binary or JSON metadata | `INSERT reports`, writes disk PDF | `ReportSectionView.tsx` | `IMPLEMENTED` |
| `POST` | `/api/reports/generate-case-dossier` | Generate full case dossier PDF | `generate_case_dossier_report` | `ReportGenerateRequest` | PDF binary or JSON metadata | `INSERT reports`, writes disk PDF | `CaseDetail.tsx` | `IMPLEMENTED` |
| `GET` | `/api/reports` | List generated reports with pagination | `list_reports` | Query params | `ReportListResponse` | Read `reports` | `Reports.tsx` | `IMPLEMENTED` |
| `GET` | `/api/reports/{report_id}` | Get report metadata | `get_report_details` | Path param | `ReportListItemResponse` | Read `reports` | `Reports.tsx` | `IMPLEMENTED` |
| `GET` | `/api/reports/{report_id}/download` | Stream PDF binary file | `download_report_pdf` | Path param | `application/pdf` binary | Read disk PDF | `Reports.tsx`, `CaseDetail.tsx` | `IMPLEMENTED` |

---

### 1.8 Investigation Copilot (`/api/copilot`)
*Controller: `backend/api/routes/copilot.py`*

| Method | Path | Purpose | Handler Function | Request Format | Response Format | DB Effect | External Services | Frontend Consumer | Status |
|---|---|---|---|---|---|---|---|---|---|
| `POST` | `/api/copilot/query` | Ask evidence-grounded natural language question | `query_copilot` | `CopilotQueryRequest` | `CopilotQueryResponse` | `INSERT copilot_audit_logs` | Gemini / OpenAI REST | `InvestigationAIDrawer.tsx` | `IMPLEMENTED` |
| `GET` | `/api/copilot/suggested-questions` | Get pre-calibrated context questions | `get_suggested_questions` | Query `mode`, `context_id` | `List[SuggestedQuestion]` | None | None | `InvestigationAIDrawer.tsx` | `IMPLEMENTED` |
| `POST` | `/api/copilot/add-to-report` | Append Copilot findings to report dossier | `add_copilot_summary_to_report`| `CopilotAddToReportRequest` | JSON confirmation | `UPDATE reports` | None | `InvestigationAIDrawer.tsx` | `IMPLEMENTED` |
| `GET` | `/api/copilot/audit-logs` | Retrieve Copilot query audit history | `get_copilot_audit_logs` | Query `limit` | `List[CopilotAuditLogResponse]` | Read `copilot_audit_logs` | None | SOC Audit Review | `IMPLEMENTED` |

---

### 1.9 Audit Trail & Evidence Integrity (`/api/audit` & `/api/evidence`)
*Controller: `backend/api/routes/audit.py`*

| Method | Path | Purpose | Handler Function | Request Format | Response Format | DB Effect | Frontend Consumer | Status |
|---|---|---|---|---|---|---|---|---|
| `GET` | `/api/audit` | Query append-only audit trail | `list_audit_logs` | Query filters | `AuditLogListResponse` | Read `audit_logs` | Audit viewer | `IMPLEMENTED` |
| `GET` | `/api/audit/timeline/{identifier}` | Get chronological timeline by SHA/ID | `get_investigation_timeline` | Path param | `InvestigationTimelineResponse` | Read `audit_logs` | `EmailSectionView.tsx`, `CaseDetail.tsx` | `IMPLEMENTED` |
| `GET` | `/api/evidence/{identifier}/timeline` | Alias timeline endpoint | `get_evidence_timeline_alias` | Path param | `InvestigationTimelineResponse` | Read `audit_logs` | `EmailSectionView.tsx` | `IMPLEMENTED` |
| `GET` | `/api/evidence/{identifier}` | Retrieve evidence record & SHA-256 | `get_evidence_record` | Path param | `EvidenceRecordResponse` | Read `evidence` | `InvestigationHistory.tsx` | `IMPLEMENTED` |

---

### 1.10 Dashboard & Intelligence Telemetry (`/api/dashboard` & `/api/intelligence`)
*Controllers: `backend/api/routes/dashboard.py`, `backend/api/routes/intelligence.py`*

| Method | Path | Purpose | Handler Function | Request Format | Response Format | DB Effect | Frontend Consumer | Status |
|---|---|---|---|---|---|---|---|---|
| `GET` | `/api/dashboard/summary` | Aggregated SOC metrics & 30-day trends | `get_dashboard_summary` | Query `days`, `recent_limit` | `DashboardSummaryResponse` | DB aggregation | `Dashboard.tsx` | `IMPLEMENTED` |
| `GET` | `/api/dashboard/emails` | Paginated list of analyzed emails | `list_dashboard_emails` | Query `skip`, `limit` | `DashboardEmailListResponse` | Read `email_analyses` | `Dashboard.tsx`, `InvestigationHistory.tsx` | `IMPLEMENTED` |
| `GET` | `/api/intelligence/geolocation/status` | Check if geolocation provider is configured | `get_geolocation_status` | None | `GeolocationStatusResponse` | None | `ThreatIntelligence.tsx` | `IMPLEMENTED` |
| `GET` | `/api/intelligence/ip/{ip}/geolocation` | Lookup sanitized IP geolocation | `get_ip_geolocation` | Path param | `GeolocationResponse` | Memory cache | `ThreatIntelligence.tsx` | `IMPLEMENTED` |

---

### 1.11 Benchmarks & Workspace Administration (`/api/benchmark` & `/api/workspace`)
*Controllers: `backend/api/routes/benchmark.py`, `backend/main.py`*

| Method | Path | Purpose | Handler Function | Request Format | Response Format | DB Effect | Frontend Consumer | Status |
|---|---|---|---|---|---|---|---|---|
| `GET` | `/api/benchmark/latest` | Retrieve latest benchmark evaluation results | `get_latest_benchmark` | None | Metrics JSON | Read cache file | `BenchmarkEvaluation.tsx` | `IMPLEMENTED` |
| `POST` | `/api/benchmark/run` | Execute live benchmark over 60 samples | `trigger_live_benchmark` | None | Real Precision/Recall/Latency | Writes cache file | `BenchmarkEvaluation.tsx` | `IMPLEMENTED` |
| `GET` | `/api/benchmark/scenarios` | Retrieve the 3 SIH synthetic demo scenarios | `get_sih_demo_scenarios` | None | Scenarios JSON | None | `Dashboard.tsx`, Guided Tour | `IMPLEMENTED` |
| `POST` | `/api/benchmark/demo-reset` | Reset demo state without touching production | `reset_demo_state` | None | Success status | Refreshes cache | Guided Tour HUD | `IMPLEMENTED` |
| `POST` | `/api/workspace/reset` | Purge all ingested emails, cases, and `.eml` files | `reset_workspace_state` | None | Truncation summary | Wipes all DB tables & disk EMLs | Navbar "Clean Reset" button | `IMPLEMENTED` |
| `GET` | `/health` & `/api/health` | Active service and database connectivity check | `health_check` | None | `{"status": "ok", "database": "ok"}` | Active `SELECT 1` ping | Docker healthcheck, Load balancer | `IMPLEMENTED` |

---

## 2. API Findings & Inconsistencies

1. **Authentication Requirement**:
   - Currently, all endpoints operate without bearer tokens or session cookies. User identity is optionally passed via the `X-User` header (defaults to `"SOC Analyst"`). For a multi-tenant enterprise system, JWT/OAuth2 authentication must be introduced in Section 2.
2. **Synchronous Network Enrichment**:
   - `/api/emails/analyze` performs concurrent async DNS and RDAP queries during ingestion. When external resolvers have unrouted IPv6 paths, the endpoint can stall for up to 75 seconds. It is recommended to make external OSINT lookups background tasks or implement aggressive socket timeouts (e.g. 2.0s).
3. **Redundant Reset Routes**:
   - The workspace reset functionality is exposed at `/api/workspace/reset`, `/api/benchmark/workspace-reset`, and `/api/benchmark/clean-reset`. These should be unified to a single endpoint.
