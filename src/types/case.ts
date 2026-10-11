export type CaseStatus =
  | 'NEW'
  | 'OPEN'
  | 'IN_PROGRESS'
  | 'PENDING'
  | 'ON_HOLD'
  | 'RESOLVED'
  | 'CLOSED'
  | 'CANCELLED'
  | 'open'
  | 'investigating'
  | 'resolved'
  | 'escalated';

export type CaseSeverity =
  | 'LOW'
  | 'MEDIUM'
  | 'HIGH'
  | 'CRITICAL'
  | 'low'
  | 'medium'
  | 'high'
  | 'critical';

export type CasePriority =
  | 'P1_CRITICAL'
  | 'P2_HIGH'
  | 'P3_MEDIUM'
  | 'P4_LOW';

export type CaseCategory =
  | 'PHISHING'
  | 'ACCOUNT_TAKEOVER'
  | 'MALWARE'
  | 'MALICIOUS_ATTACHMENT'
  | 'IMPERSONATION'
  | 'CREDENTIAL_THEFT'
  | 'DATA_EXFILTRATION'
  | 'API_ABUSE'
  | 'NETWORK_ATTACK'
  | 'ENDPOINT_COMPROMISE'
  | 'FRAUD'
  | 'POLICY_VIOLATION'
  | 'OTHER';

export type CaseClassification =
  | 'PUBLIC'
  | 'INTERNAL'
  | 'CONFIDENTIAL'
  | 'RESTRICTED';

export type CaseResolutionCode =
  | 'TRUE_POSITIVE'
  | 'FALSE_POSITIVE'
  | 'BENIGN_ACTIVITY'
  | 'RESOLVED'
  | 'NO_EVIDENCE'
  | 'DUPLICATE'
  | 'RISK_ACCEPTED'
  | 'MITIGATED'
  | 'OTHER';

export type TaskStatus =
  | 'TODO'
  | 'IN_PROGRESS'
  | 'BLOCKED'
  | 'COMPLETED'
  | 'CANCELLED';

export type TaskPriority =
  | 'LOW'
  | 'MEDIUM'
  | 'HIGH'
  | 'CRITICAL';

export interface CaseEmail {
  id: string;
  case_id: string;
  email_id: string;
  email_sha256?: string;
  subject?: string;
  sender?: string;
  threat_score?: number;
  severity?: string;
  added_at: string;
}

export interface CaseNote {
  id: string;
  case_id: string;
  author: string;
  note_text: string;
  visibility?: string;
  created_at: string;
  updated_at?: string;
}

export interface CaseFinding {
  id: string;
  case_id: string;
  finding_type: string;
  title: string;
  description: string;
  severity: string;
  created_at: string;
}

export interface CaseTask {
  id: string;
  case_id: string;
  workspace_id: string;
  title: string;
  description?: string;
  status: TaskStatus | string;
  priority: TaskPriority | string;
  assignee_id?: string;
  team_id?: string;
  due_at?: string;
  completed_at?: string;
  completed_by?: string;
  created_by: string;
  order_index: number;
  is_automated_recommendation: boolean;
  source_action_id?: string;
  created_at: string;
  updated_at: string;
}

export interface AuditLog {
  id: string;
  case_id: string;
  action: string;
  details: string;
  user?: string;
  timestamp: string;
}

export interface AggregatedIndicators {
  domains: string[];
  ips: string[];
  urls: string[];
  attachments: string[];
}

export interface CaseTimelineEvent {
  id: string;
  timestamp: string;
  event_type: string;
  title: string;
  description: string;
  actor: string;
  source: string;
  metadata?: Record<string, any>;
}

export interface CaseMetricsSummary {
  total_cases: number;
  open_cases: number;
  in_progress_cases: number;
  resolved_cases: number;
  closed_cases: number;
  critical_cases: number;
  high_cases: number;
  sla_breached_cases: number;
  sla_warning_cases: number;
  unassigned_cases: number;
  overdue_tasks_count: number;
}

export interface CaseListItem {
  id: string;
  case_number: string;
  workspace_id?: string;
  title: string;
  description?: string;
  severity: CaseSeverity | string;
  priority?: CasePriority | string;
  status: CaseStatus | string;
  category?: CaseCategory | string;
  classification?: CaseClassification | string;
  owner_id?: string;
  team_id?: string;
  incident_id?: string;
  primary_investigation_id?: string;
  campaign_id?: string;
  sla_status?: string;
  next_sla_deadline?: string;
  opened_at?: string;
  resolved_at?: string;
  closed_at?: string;
  created_at: string;
  updated_at: string;
  email_count: number;
  note_count: number;
  finding_count: number;
  task_count?: number;
  open_task_count?: number;
  version?: number;
  tags?: string[];
}

export interface CaseDetail {
  id: string;
  case_number: string;
  workspace_id?: string;
  title: string;
  description?: string;
  severity: CaseSeverity | string;
  priority?: CasePriority | string;
  status: CaseStatus | string;
  category?: CaseCategory | string;
  classification?: CaseClassification | string;
  owner_id?: string;
  team_id?: string;
  created_by?: string;
  incident_id?: string;
  primary_investigation_id?: string;
  campaign_id?: string;
  sla_policy_id?: string;
  sla_status?: string;
  next_sla_deadline?: string;
  opened_at?: string;
  resolved_at?: string;
  resolved_by?: string;
  resolution_code?: string;
  resolution_summary?: string;
  closed_at?: string;
  closed_by?: string;
  closure_notes?: string;
  reopened_at?: string;
  reopened_by?: string;
  reopen_reason?: string;
  duplicate_of_id?: string;
  merged_into_id?: string;
  tags?: string[];
  custom_fields?: Record<string, any>;
  affected_assets?: string[];
  affected_identities?: string[];
  related_alerts?: string[];
  related_evidence?: string[];
  related_response_actions?: string[];
  version?: number;
  created_at: string;
  updated_at: string;

  emails: CaseEmail[];
  notes: CaseNote[];
  findings: CaseFinding[];
  tasks?: CaseTask[];
  audit_logs: AuditLog[];
  aggregated_indicators: AggregatedIndicators;
}

export interface CaseCreatePayload {
  title: string;
  description?: string;
  severity?: CaseSeverity | string;
  priority?: CasePriority | string;
  status?: CaseStatus | string;
  category?: CaseCategory | string;
  classification?: CaseClassification | string;
  owner_id?: string;
  team_id?: string;
  incident_id?: string;
  primary_investigation_id?: string;
  campaign_id?: string;
  tags?: string[];
  custom_fields?: Record<string, any>;
  affected_assets?: string[];
  affected_identities?: string[];
  related_alerts?: string[];
  related_evidence?: string[];
  initial_email?: {
    email_id: string;
    email_sha256?: string;
    subject?: string;
    sender?: string;
    threat_score?: number;
    severity?: string;
    indicators?: Record<string, any>;
  };
}

export interface CaseUpdatePayload {
  title?: string;
  description?: string;
  severity?: CaseSeverity | string;
  priority?: CasePriority | string;
  status?: CaseStatus | string;
  category?: CaseCategory | string;
  classification?: CaseClassification | string;
  owner_id?: string;
  team_id?: string;
  primary_investigation_id?: string;
  campaign_id?: string;
  tags?: string[];
  custom_fields?: Record<string, any>;
  affected_assets?: string[];
  affected_identities?: string[];
  related_alerts?: string[];
  related_evidence?: string[];
  expected_version?: number;
}

export interface CaseAssignPayload {
  owner_id?: string;
  team_id?: string;
  reason?: string;
}

export interface CaseResolvePayload {
  resolution_code: CaseResolutionCode | string;
  resolution_summary: string;
  affected_identities?: string[];
  tags?: string[];
}

export interface CaseClosePayload {
  closure_notes: string;
  force_close_tasks?: boolean;
}

export interface CaseReopenPayload {
  reopen_reason: string;
}

export interface CaseMergePayload {
  source_case_ids: string[];
  reason: string;
}

export interface CaseLinkPayload {
  entity_type: string;
  entity_id: string;
  details?: string;
}

export interface CaseTaskCreatePayload {
  title: string;
  description?: string;
  priority?: TaskPriority | string;
  assignee_id?: string;
  team_id?: string;
  due_at?: string;
  order_index?: number;
}

export interface CaseTaskUpdatePayload {
  title?: string;
  description?: string;
  status?: TaskStatus | string;
  priority?: TaskPriority | string;
  assignee_id?: string;
  team_id?: string;
  due_at?: string;
  order_index?: number;
}

export interface CaseNoteCreateRequest {
  author?: string;
  note_text: string;
  visibility?: string;
}

export interface CaseNoteUpdateRequest {
  note_text: string;
  visibility?: string;
}

export interface CaseFindingCreateRequest {
  finding_type?: string;
  title: string;
  description?: string;
  severity?: string;
}
