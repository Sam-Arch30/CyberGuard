/**
 * Section 69: Executive Reporting & Intelligence Dissemination Frontend Types.
 */

export type ExecutiveReportClassification =
  | 'PUBLIC'
  | 'INTERNAL'
  | 'CONFIDENTIAL'
  | 'RESTRICTED'
  | 'TLP_CLEAR'
  | 'TLP_GREEN'
  | 'TLP_AMBER'
  | 'TLP_RED';

export type ExecutiveReportRedactionLevel = 'NONE' | 'STANDARD' | 'STRICT' | 'LEGAL_PRIVILEGED';

export type ExecutiveReportType =
  | 'EXECUTIVE_BRIEFING'
  | 'TECHNICAL_INCIDENT_DOSSIER'
  | 'FORENSIC_CHAIN_OF_CUSTODY'
  | 'REGULATORY_COMPLIANCE_DISCLOSURE'
  | 'THREAT_ACTOR_INTEL_DISSEMINATION'
  | 'ANALYST';

export type ExecutiveReportStatus =
  | 'DRAFT'
  | 'REVIEW_REQUESTED'
  | 'APPROVED'
  | 'FINALIZED'
  | 'SUPERSEDED'
  | 'READY';

export interface ReportSectionConfigItem {
  section_id: string;
  title: string;
  description?: string;
  enabled: boolean;
  order: number;
  required_epistemic_level?: string;
  parameters?: Record<string, any>;
}

export interface ReportTemplate {
  id: string;
  workspace_id: string;
  tenant_id: string;
  template_key: string;
  template_name: string;
  report_type: ExecutiveReportType;
  version: number;
  description?: string;
  sections_config: ReportSectionConfigItem[];
  default_classification: ExecutiveReportClassification;
  default_redaction: ExecutiveReportRedactionLevel;
  is_system: boolean;
  is_active: boolean;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface ReportSnapshot {
  id: string;
  report_id: string;
  workspace_id: string;
  tenant_id: string;
  snapshot_hash: string;
  source_identifiers: Record<string, any>;
  source_versions: Record<string, any>;
  epistemic_labels: Record<string, any>;
  created_at: string;
}

export interface ReportShareLink {
  id: string;
  report_id: string;
  workspace_id: string;
  tenant_id: string;
  share_token?: string;
  share_url?: string;
  format: string;
  classification: ExecutiveReportClassification;
  redaction_level: ExecutiveReportRedactionLevel;
  expires_at: string;
  max_uses: number;
  use_count: number;
  is_revoked: boolean;
  revoked_at?: string;
  revoked_by?: string;
  created_by: string;
  created_at: string;
}

export interface ReviewNoteItem {
  author: string;
  timestamp: string;
  content: string;
  status: string;
}

export interface ExecutiveReportDetail {
  id: string;
  report_number: string;
  title: string;
  report_type: ExecutiveReportType;
  status: ExecutiveReportStatus;
  report_version: number;
  classification: ExecutiveReportClassification;
  redaction_level: ExecutiveReportRedactionLevel;
  threat_score: number;
  severity: string;
  confidence: number;
  summary?: string;
  analyst_name?: string;
  incident_id?: string;
  case_id?: string;
  investigation_id?: string;
  evidence_id?: string;
  template_id?: string;
  template_version: number;
  source_snapshot_id?: string;
  source_data_hash?: string;
  created_by?: string;
  created_at: string;
  updated_at: string;
  generated_at?: string;
  finalized_at?: string;
  finalized_by?: string;
  approved_at?: string;
  approved_by?: string;
  is_immutable: boolean;
  review_notes: ReviewNoteItem[];
  reviewers: string[];
  evidence_gaps: string[];
  recommendations: string[];
  file_path?: string;
  file_size_bytes: number;
  html_content?: string;
  workspace_id: string;
  tenant_id: string;
}

export interface ExecutiveReportListItem {
  id: string;
  report_number: string;
  title: string;
  report_type: ExecutiveReportType;
  status: ExecutiveReportStatus;
  report_version: number;
  classification: ExecutiveReportClassification;
  redaction_level: ExecutiveReportRedactionLevel;
  threat_score: number;
  severity: string;
  confidence: number;
  incident_id?: string;
  case_id?: string;
  investigation_id?: string;
  is_immutable: boolean;
  created_by?: string;
  created_at: string;
  finalized_at?: string;
  share_links_count: number;
}

export interface ExecutiveReportMetrics {
  total_reports: number;
  draft_reports: number;
  in_review_reports: number;
  approved_reports: number;
  finalized_reports: number;
  active_share_links: number;
  by_classification: Record<string, number>;
  by_type: Record<string, number>;
  by_severity: Record<string, number>;
}
