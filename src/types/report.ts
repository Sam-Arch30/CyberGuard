/**
 * Section 42: Report Workspace TypeScript Type Definitions.
 */

export type ReportType = 'ANALYST' | 'EXECUTIVE' | 'FORENSIC' | 'INCIDENT' | 'EVIDENCE';
export type ReportStatus = 'DRAFT' | 'GENERATING' | 'READY' | 'STALE' | 'FAILED' | 'ARCHIVED' | 'SUPERSEDED';
export type ReportClassification = 'INTERNAL' | 'CONFIDENTIAL' | 'RESTRICTED';
export type RedactionLevel = 'NONE' | 'STANDARD' | 'STRICT';
export type EpistemicStatus = 'OBSERVED' | 'INFERRED' | 'HYPOTHESIS' | 'EXTERNAL_INTELLIGENCE' | 'ANALYST_VERIFIED';

export interface ReportContentOptions {
  include_executive_summary: boolean;
  include_timeline: boolean;
  include_attack_path: boolean;
  include_risk_assessment: boolean;
  include_findings: boolean;
  include_evidence_table: boolean;
  include_indicators: boolean;
  include_mitre_attack: boolean;
  include_infrastructure: boolean;
  include_explainability: boolean;
  include_response_actions: boolean;
  include_recommendations: boolean;
  include_audit_trail: boolean;
  include_evidence_index: boolean;
}

export const DEFAULT_CONTENT_OPTIONS: ReportContentOptions = {
  include_executive_summary: true,
  include_timeline: true,
  include_attack_path: true,
  include_risk_assessment: true,
  include_findings: true,
  include_evidence_table: true,
  include_indicators: true,
  include_mitre_attack: true,
  include_infrastructure: true,
  include_explainability: true,
  include_response_actions: true,
  include_recommendations: true,
  include_audit_trail: true,
  include_evidence_index: true,
};

export interface FactClaim {
  id: string;
  statement: string;
  status: EpistemicStatus;
  evidence_refs: string[];
  category?: string;
}

export interface ReportQualityCheck {
  is_valid: boolean;
  checks_passed: string[];
  warnings: string[];
  unavailable_sections: string[];
}

export interface ReportMetadata {
  report_id?: string;
  report_number?: string;
  investigation_id: string;
  incident_number: string;
  title: string;
  report_type: ReportType;
  classification: ReportClassification;
  redaction_level: RedactionLevel;
  report_version: number;
  generated_at: string;
  generated_by: string;
  analyst_notes?: string;
  generator_version: string;
  data_snapshot_hash: string;
}

export interface IncidentOverview {
  investigation_id: string;
  incident_number: string;
  title: string;
  status: string;
  severity: string;
  risk_score: number;
  confidence: number;
  confidence_level: string;
  source_types: string[];
  first_observed_at: string;
  last_observed_at: string;
  analysis_run_count: number;
  analysis_run_id?: string;
  evidence_count: number;
  finding_count: number;
  indicator_count: number;
  affected_entities: string[];
}

export interface ExecutiveSummary {
  detection_statement: string;
  impact_statement: string;
  evidence_support_statement: string;
  current_risk_statement: string;
  response_state_statement: string;
  uncertainty_statement: string;
  synthesized_narrative: string;
}

export interface RiskAssessmentSection {
  risk_score: number;
  severity: string;
  confidence: number;
  confidence_level: string;
  risk_vs_confidence_note: string;
  primary_signals: string[];
  counter_evidence: string[];
}

export interface TimelineReportItem {
  event_id: string;
  timestamp: string;
  event_type: string;
  title: string;
  description: string;
  source: string;
  status: 'OBSERVED' | 'INFERRED';
  uncertainty: string;
}

export interface AttackStageReportItem {
  stage_order: number;
  stage_type: string;
  name: string;
  timestamp?: string;
  confidence: number;
  status: 'OBSERVED' | 'INFERRED';
  evidence_count: number;
  mitre_technique_id?: string;
  mitre_technique_name?: string;
  relevant_entities: string[];
}

export interface AttackPathSection {
  available: boolean;
  path_id: string;
  overall_confidence: number;
  confidence_drivers: string[];
  confidence_limitations: string[];
  path_summary: string;
  stages: AttackStageReportItem[];
}

export interface FindingReportItem {
  ref_id: string;
  finding_id: string;
  title: string;
  category: string;
  severity: string;
  confidence: number;
  description: string;
  evidence_refs: string[];
  source: string;
  epistemic_status: 'OBSERVED' | 'INFERRED';
}

export interface EvidenceReportItem {
  ref_id: string;
  evidence_id: string;
  name: string;
  type: 'ORIGINAL' | 'DERIVED';
  source: string;
  mime_type: string;
  size_str: string;
  sha256: string;
  analysis_run_ref: string;
  extracted_at?: string;
}

export interface MitreReportItem {
  technique_id: string;
  technique_name: string;
  tactic: string;
  status: string;
  evidence_count: number;
  related_stage: string;
}

export interface ResponseActionReportItem {
  action_id: string;
  action_type: string;
  priority: string;
  status: string;
  target: string;
  result: string;
  executed_at?: string;
}

export interface OutstandingRecReportItem {
  rec_id: string;
  title: string;
  priority: string;
  status: string;
  category: string;
  description: string;
  target_entity: string;
}

export interface AuditTrailReportItem {
  timestamp: string;
  action: string;
  user: string;
  details: string;
  resource_type: string;
}

export interface EvidenceIndexItem {
  ref_id: string;
  type: string;
  label: string;
  digest: string;
  provenance: string;
}

export interface ReportSnapshot {
  metadata: ReportMetadata;
  incident_overview: IncidentOverview;
  executive_summary: ExecutiveSummary;
  epistemic_claims: FactClaim[];
  risk_assessment: RiskAssessmentSection;
  timeline: TimelineReportItem[];
  attack_path: AttackPathSection;
  findings: FindingReportItem[];
  evidence_summary: {
    original_artifacts_count: number;
    derived_evidence_count: number;
    indicators_count: number;
    analysis_runs_count: number;
  };
  evidence_table: EvidenceReportItem[];
  iocs: {
    ips: Array<{ value: string; origin: string; reputation: string }>;
    domains: Array<{ value: string; origin: string; reputation: string }>;
    urls: Array<{ value: string; origin: string; reputation: string }>;
    hashes: string[];
    emails: Array<{ value: string; origin: string; reputation: string }>;
  };
  mitre_attack: MitreReportItem[];
  infrastructure_intelligence: {
    observed_infrastructure: string[];
    associated_domains: string[];
    probable_origin_asn: string;
    probable_origin_country: string;
    attribution_boundary_note: string;
  };
  explainability: {
    reasoning_chain: string[];
    counter_evidence: string[];
    contradictions: string[];
    what_would_change_assessment: string[];
  };
  response: {
    summary: {
      total_recommendations: number;
      approved_count: number;
      executed_count: number;
      pending_count: number;
      failed_count: number;
    };
    actions_table: ResponseActionReportItem[];
    outstanding_recommendations: OutstandingRecReportItem[];
  };
  audit_trail: AuditTrailReportItem[];
  evidence_index: EvidenceIndexItem[];
  quality_check: ReportQualityCheck;
  provenance: Record<string, any>;
}

export interface ReportDetail {
  id: string;
  report_number: string;
  title: string;
  investigation_id?: string;
  incident_number?: string;
  case_id?: string;
  evidence_id?: string;
  email_sha256?: string;
  threat_score: number;
  severity: string;
  confidence: number;
  report_type: ReportType;
  status: ReportStatus;
  report_version: number;
  classification: ReportClassification;
  redaction_level: RedactionLevel;
  is_stale: boolean;
  analyst_name: string;
  summary: string;
  file_size_bytes: number;
  created_at: string;
  download_url: string;
  json_url: string;
  content_options: Partial<ReportContentOptions>;
  quality_check: ReportQualityCheck;
  snapshot: ReportSnapshot;
  provenance: Record<string, any>;
}

export interface ReportListItem {
  id: string;
  report_number: string;
  title: string;
  investigation_id?: string;
  incident_number?: string;
  case_id?: string;
  evidence_id?: string;
  email_sha256?: string;
  threat_score?: number;
  severity?: string;
  confidence?: number;
  report_type?: string;
  status?: string;
  report_version?: number;
  classification?: string;
  redaction_level?: string;
  is_stale?: boolean;
  analyst_name?: string;
  summary?: string;
  file_size_bytes?: number;
  created_at: string;
  download_url?: string;
}

export interface ReportComparisonItem {
  field: string;
  v1_value: any;
  v2_value: any;
  changed: boolean;
}

export interface ReportComparison {
  investigation_id: string;
  v1_report_number: string;
  v2_report_number: string;
  v1_version: number;
  v2_version: number;
  changes: ReportComparisonItem[];
}

export interface InvestigationReportGenerateRequest {
  investigation_id?: string;
  report_type?: ReportType;
  classification?: ReportClassification;
  redaction_level?: RedactionLevel;
  content_options?: Partial<ReportContentOptions>;
  analyst_name?: string;
  notes?: string;
}

export interface InvestigationReportPreviewRequest {
  report_type?: ReportType;
  classification?: ReportClassification;
  redaction_level?: RedactionLevel;
  content_options?: Partial<ReportContentOptions>;
  analyst_name?: string;
  notes?: string;
}

