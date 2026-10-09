/**
 * TypeScript Contracts for Section 38: Analysis Results + Progressive Disclosure.
 * Reflects authoritative backend Pydantic schemas from backend/schemas/analysis_results.py.
 */

// ============================================================================
// 1. LEVEL 1: EXECUTIVE SCHEMAS
// ============================================================================

export interface RiskHeaderSummary {
  score?: number | null; // Unified risk score (0-100)
  level: string; // INFO, LOW, MEDIUM, HIGH, CRITICAL, UNKNOWN
  severity: string; // SAFE, LOW, MEDIUM, HIGH, CRITICAL
  confidence?: number | null; // Calibrated evidence confidence (0.0-1.0)
  confidence_level: string; // LOW, MODERATE, HIGH, VERY_HIGH, UNKNOWN
  uncertainty: string; // LOW, MODERATE, HIGH
  is_pending: boolean;
  status_label: string;
}

export interface WhyCyberGuardThinksThisItem {
  id: string;
  claim: string;
  support_level: 'CONFIRMED' | 'VERY_HIGH' | 'HIGH' | 'MODERATE' | 'WEAK' | string;
  confidence: number;
  evidence_count: number;
  evidence_refs: string[];
}

export interface NextStepRecommendation {
  action_title: string;
  action_description: string;
  priority: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | string;
  target_route?: string | null;
}

// ============================================================================
// 2. LEVEL 2: ANALYST SCHEMAS
// ============================================================================

export interface SupportingEvidencePreview {
  id: string;
  evidence_type: string;
  source: string;
  key: string;
  value: string;
  confidence: number;
  artifact_id?: string | null;
  observed_at?: string | null;
}

export interface FindingResultDetail {
  id: string;
  analyzer: string;
  finding_type: string;
  title: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'SAFE' | 'INFO' | string;
  confidence: number;
  risk_contribution: number;
  method: string;
  rule_id?: string | null;
  observed_value?: string | null;
  expected_value?: string | null;
  evidence_count: number;
  evidence_items: SupportingEvidencePreview[];
  counter_evidence: string[];
  metadata: Record<string, unknown>;
}

export interface DomainIndicator {
  value: string;
  severity: string;
  first_seen?: string | null;
  is_lookalike: boolean;
  reputation?: string | null;
}

export interface URLIndicator {
  value: string;
  severity: string;
  first_seen?: string | null;
  redirect_hops: number;
  is_lookalike: boolean;
  credential_harvesting: boolean;
  reputation?: string | null;
}

export interface IPIndicator {
  value: string;
  severity: string;
  first_seen?: string | null;
  country?: string | null;
  asn?: string | null;
  is_vpn_proxy: boolean;
}

export interface EmailIndicator {
  value: string;
  severity: string;
  first_seen?: string | null;
  role?: string | null;
}

export interface HashIndicator {
  value: string;
  algorithm: string;
  severity: string;
  first_seen?: string | null;
}

export interface AttachmentResultItem {
  filename: string;
  mime_type: string;
  size_bytes: number;
  severity: string;
  risk_flag?: string | null;
  sha256?: string | null;
}

export interface IndicatorsSummary {
  total_count: number;
  domains: DomainIndicator[];
  urls: URLIndicator[];
  ips: IPIndicator[];
  emails: EmailIndicator[];
  hashes: HashIndicator[];
  attachments: AttachmentResultItem[];
}

export interface CounterEvidenceResultItem {
  id: string;
  title: string;
  description: string;
  source: string;
  strength: string;
  impact: string;
}

export interface ContradictionResultItem {
  id: string;
  topic: string;
  supporting_claim: string;
  contradicting_claim: string;
  severity: string;
}

export interface UncertaintyAndGapsItem {
  topic: string;
  description: string;
  impact: string;
}

export interface DigitalImpersonationSummary {
  claimed_identity: string;
  observed_identity: string;
  status: 'MATCH' | 'PARTIAL' | 'MISMATCH' | 'LOOKALIKE' | 'INSUFFICIENT' | 'UNKNOWN' | string;
  confidence: number;
  similarity_score?: number | null;
  details?: string | null;
}

export interface BehavioralAnomalyItem {
  metric: string;
  status: 'NORMAL' | 'DEVIATION' | 'ANOMALY' | string;
  deviation_score: number;
  baseline_value?: string | null;
  observed_value?: string | null;
}

export interface BehavioralSummary {
  baseline_quality: 'LOW' | 'MODERATE' | 'HIGH' | string;
  total_anomalies: number;
  anomalies: BehavioralAnomalyItem[];
}

export interface NoveltySummary {
  novelty_score: number;
  novelty_level: 'LOW' | 'MODERATE' | 'HIGH' | string;
  prior_observations_count: number;
  description: string;
}

export interface ThreatMemorySummary {
  previously_observed: boolean;
  total_observations: number;
  verified_malicious: number;
  dismissed_count: number;
  notes?: string | null;
}

// ============================================================================
// 3. LEVEL 3: INVESTIGATOR SCHEMAS
// ============================================================================

export interface AttackStagePreview {
  stage_number: number;
  stage_name: string;
  tactic: string;
  description: string;
}

export interface AttackPathPreview {
  path_id?: string | null;
  path_name: string;
  stages: AttackStagePreview[];
  confidence: 'LOW' | 'MODERATE' | 'HIGH' | 'VERY_HIGH' | string;
  stage_count: number;
}

export interface MITRETechniquePreview {
  technique_id: string; // e.g. T1566.002
  technique_name: string;
  tactic: string;
  status: 'SUPPORTED' | 'PLAUSIBLE' | 'INSUFFICIENT' | 'REJECTED' | string;
  confidence: number;
}

export interface InfrastructureAttributionPreview {
  observed_infrastructure: string[];
  associated_domains: string[];
  probable_origin_infrastructure?: string | null;
  infrastructure_location?: string | null; // Strictly 'Infrastructure location', NEVER 'Attacker location'
  asn?: string | null;
  confidence: string;
}

export interface CampaignActivityContext {
  is_campaign: boolean;
  campaign_name?: string | null;
  related_investigations_count: number;
  shared_indicators_count: number;
  dominant_attack_type?: string | null;
}

// ============================================================================
// 4. LEVEL 4: FORENSIC & PROVENANCE SCHEMAS
// ============================================================================

export interface AnalysisRunHistoryItem {
  run_id: string;
  run_number: number;
  status: string;
  overall_risk_score?: number | null;
  completed_at?: string | null;
  is_current: boolean;
}

export interface AnalysisProvenance {
  run_id: string;
  engine_version: string;
  risk_configuration_version: string;
  rules_version: string;
  models_version: string;
  started_at?: string | null;
  completed_at?: string | null;
  duration_seconds?: number | null;
  audit_reference?: string | null;
}

export interface ArtifactIdentity {
  id: string;
  name: string;
  artifact_type: string;
  size: number;
  sha256?: string | null;
  source: string;
}

// ============================================================================
// 5. UNIFIED AGGREGATED RESPONSE (CONSOLIDATED ENDPOINT)
// ============================================================================

export interface AnalysisResultsResponse {
  run_id: string;
  investigation_id?: string | null;
  evidence_id?: string | null;
  artifact: ArtifactIdentity;

  // Status & Completeness
  status: string; // INITIALIZING, QUEUED, RUNNING, PARTIAL, COMPLETED, FAILED, CANCELLED
  analysis_completeness: 'COMPLETE' | 'PARTIAL' | 'DEGRADED' | string;
  completeness_message?: string | null;
  total_tasks: number;
  completed_tasks: number;
  failed_tasks: number;

  // Level 1 — Executive
  risk: RiskHeaderSummary;
  classification: string;
  executive_summary: string;
  why_cyberguard_thinks_this: WhyCyberGuardThinksThisItem[];
  next_step_recommendation: NextStepRecommendation;

  // Level 2 — Analyst
  top_findings: FindingResultDetail[];
  indicators_summary: IndicatorsSummary;
  counter_evidence: CounterEvidenceResultItem[];
  contradictions: ContradictionResultItem[];
  uncertainty_and_gaps: UncertaintyAndGapsItem[];
  what_would_change_assessment: string[];
  digital_impersonation?: DigitalImpersonationSummary | null;
  behavioral_deviations?: BehavioralSummary | null;
  novelty?: NoveltySummary | null;
  threat_memory?: ThreatMemorySummary | null;

  // Level 3 — Investigator
  attack_path_preview?: AttackPathPreview | null;
  mitre_preview: MITRETechniquePreview[];
  infrastructure_preview?: InfrastructureAttributionPreview | null;
  campaign_context?: CampaignActivityContext | null;

  // Level 4 — Forensic
  provenance: AnalysisProvenance;
  run_history: AnalysisRunHistoryItem[];

  last_updated: string;
}

// ============================================================================
// 6. LAZY-LOAD EVIDENCE DETAIL SCHEMA
// ============================================================================

export interface EvidenceDetailResponse {
  id: string;
  finding_id?: string | null;
  evidence_type: string;
  source: string;
  key: string;
  value: string; // Sanitized/redacted
  raw_preview?: string | null;
  confidence: number;
  artifact_id?: string | null;
  sha256?: string | null;
  detected_by?: string | null;
  analysis_run_id?: string | null;
  observed_at: string;
  metadata: Record<string, unknown>;
  linked_finding_title?: string | null;
  provenance_chain: string[];
}
