/**
 * Section 48: Alert Management & Triage Workspace Types.
 * Type contracts for real security alerts, provenance details, explainability cards,
 * activity audit timelines, operational metrics, and analyst triage actions.
 */

export type AlertStatus =
  | 'OPEN'
  | 'ACKNOWLEDGED'
  | 'INVESTIGATING'
  | 'RESOLVED'
  | 'FALSE_POSITIVE'
  | 'SUPPRESSED';

export type AlertSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export interface AlertItem {
  id: string;
  workspace_id: string;
  alert_type: string;
  severity: AlertSeverity;
  status: AlertStatus;
  title: string;
  message: string;
  risk_score: number;
  confidence: number;
  source_type: string;
  source_id: string;
  investigation_id?: string | null;
  analysis_run_id?: string | null;
  finding_id?: string | null;
  navigation_target?: string | null;
  assigned_to?: string | null;
  created_at: string;
  updated_at: string;
  acknowledged_at?: string | null;
  acknowledged_by?: string | null;
  resolved_at?: string | null;
  resolved_by?: string | null;
}

export interface AlertEvidenceItem {
  id: string;
  evidence_type: string;
  description: string;
  source: string;
  indicator_value: string;
  relevance_score: number;
}

export interface AlertFindingDetail {
  id: string;
  title: string;
  analyzer: string;
  finding_type: string;
  severity: string;
  confidence: number;
  risk_contribution: number;
  method: string;
  rule_id?: string | null;
  description?: string | null;
}

export interface AlertAnalysisRunDetail {
  id: string;
  status: string;
  started_at?: string | null;
  completed_at?: string | null;
  overall_risk_score?: number | null;
  overall_severity?: string | null;
  artifact_name?: string | null;
  artifact_sha256?: string | null;
}

export interface AlertInvestigationDetail {
  id: string;
  incident_number: string;
  title: string;
  status: string;
  severity: string;
  risk_score?: number | null;
}

export interface AlertActivityTimelineItem {
  action: string;
  timestamp: string;
  user: string;
  details: string;
}

export interface AlertDetail extends AlertItem {
  why_created: string[];
  finding_detail?: AlertFindingDetail | null;
  evidence_items: AlertEvidenceItem[];
  analysis_run_detail?: AlertAnalysisRunDetail | null;
  investigation_detail?: AlertInvestigationDetail | null;
  activity_timeline: AlertActivityTimelineItem[];
  resolution_reason?: string | null;
  false_positive_reason?: string | null;
  suppression_reason?: string | null;
  suppression_scope?: string | null;
  metadata: Record<string, unknown>;
}

export interface AlertListResponse {
  items: AlertItem[];
  total: number;
  limit: number;
  offset: number;
  counts_by_status: Record<string, number>;
  counts_by_severity: Record<string, number>;
}

export interface AlertMetrics {
  total_alerts: number;
  open_count: number;
  critical_open: number;
  high_open: number;
  unacknowledged_count: number;
  investigating_count: number;
  resolved_count: number;
}

export interface AlertAcknowledgePayload {
  analyst_name?: string;
  note?: string;
}

export interface AlertAssignPayload {
  assigned_to: string;
  analyst_name?: string;
}

export interface AlertResolvePayload {
  resolution_reason: string;
  analyst_name?: string;
}

export interface AlertFalsePositivePayload {
  reason: string;
  analyst_name?: string;
}

export interface AlertSuppressPayload {
  reason: string;
  scope?: string;
  analyst_name?: string;
}

export interface AlertAddNotePayload {
  note: string;
  analyst_name?: string;
}

export interface AlertBulkAcknowledgePayload {
  alert_ids: string[];
  analyst_name?: string;
}
