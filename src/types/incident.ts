/**
 * Section 50: Incident Management & Case Lifecycle Types
 * Definitive TypeScript definitions for operational SOC cases, lifecycles, and facts.
 */

export type IncidentStatus =
  | 'NEW'
  | 'OPEN'
  | 'ACKNOWLEDGED'
  | 'INVESTIGATING'
  | 'CONTAINED'
  | 'RESOLVED'
  | 'CLOSED'
  | 'FALSE_POSITIVE'
  | 'DUPLICATE'
  | 'CANCELLED';

export type IncidentSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type IncidentPriority = 'P1_CRITICAL' | 'P2_HIGH' | 'P3_MEDIUM' | 'P4_LOW';

export type IncidentCategory =
  | 'PHISHING'
  | 'CREDENTIAL_COMPROMISE'
  | 'MALWARE'
  | 'ACCOUNT_TAKEOVER'
  | 'DATA_EXFILTRATION'
  | 'MALICIOUS_ATTACHMENT'
  | 'IMPERSONATION'
  | 'NETWORK_INTRUSION'
  | 'API_ABUSE'
  | 'ENDPOINT_COMPROMISE'
  | 'SOCIAL_ENGINEERING'
  | 'OTHER';

export interface IncidentTimelineEvent {
  id: string;
  incident_id: string;
  event_type: string;
  timestamp: string;
  actor: string;
  source_type: string;
  source_id: string | null;
  summary: string;
  metadata?: Record<string, unknown>;
}

export interface IncidentNote {
  id: string;
  incident_id: string;
  author: string;
  note_text: string;
  created_at: string;
  updated_at: string;
}

export interface IncidentNextBestAction {
  action: string;
  action_type: string;
  target: string;
  reason: string;
  confidence: number;
  target_type: string;
}

export interface IncidentAffectedEntities {
  users: string[];
  endpoints: string[];
  domains: string[];
  ips: string[];
  urls: string[];
}

export interface IncidentRelatedAlert {
  id: string;
  title: string;
  severity: string;
  status: string;
  category: string;
  created_at: string;
  risk_score?: number;
  source_type?: string;
}

export interface IncidentRelatedCluster {
  id: string;
  title: string;
  severity: string;
  status: string;
  member_count: number;
  created_at: string;
}

export interface IncidentFindingSummary {
  id: string;
  title: string;
  severity: string;
  category?: string;
}

export interface IncidentEvidenceSummary {
  id: string;
  type: string;
  name?: string;
  hash?: string;
}

export interface IncidentItem {
  id: string;
  incident_number: string;
  workspace_id: string;
  title: string;
  description: string | null;
  status: IncidentStatus;
  severity: IncidentSeverity;
  priority: IncidentPriority;
  category: IncidentCategory;
  risk_score: number;
  confidence: number;
  assigned_to: string | null;
  team_id: string | null;
  primary_alert_id: string | null;
  primary_cluster_id: string | null;
  investigation_id: string | null;
  report_id: string | null;
  duplicate_of_id: string | null;
  created_at: string;
  updated_at: string;
  first_seen_at: string | null;
  last_seen_at: string | null;
  acknowledged_at: string | null;
  contained_at: string | null;
  resolved_at: string | null;
  closed_at: string | null;
  created_by: string | null;
  resolved_by: string | null;
  resolution_reason: string | null;
  age_display?: string;
  escalation_level?: number;
  sla_status?: string;
  next_sla_deadline?: string | null;
  time_remaining_mins?: number | null;
  is_overdue?: boolean;
  remaining_display?: string | null;
  overdue_display?: string | null;
}

export interface IncidentDetail extends IncidentItem {
  timeline_events: IncidentTimelineEvent[];
  notes: IncidentNote[];
  related_alerts: IncidentRelatedAlert[];
  related_clusters: IncidentRelatedCluster[];
  findings_summary: IncidentFindingSummary[];
  evidence_summary: IncidentEvidenceSummary[];
  affected_entities: IncidentAffectedEntities;
  next_best_action: IncidentNextBestAction | null;
}

export interface IncidentListResponse {
  items: IncidentItem[];
  total: number;
  page?: number;
  offset?: number;
  limit: number;
}

export interface IncidentMetrics {
  total_incidents: number;
  open_incidents: number;
  critical_incidents: number;
  unassigned_incidents: number;
  investigating_incidents: number;
  contained_incidents: number;
  resolved_incidents: number;
  closed_incidents: number;
  avg_time_to_acknowledge_hours?: number;
  avg_time_to_contain_hours?: number;
  avg_time_to_resolve_hours?: number;
  sla_breaches?: number;
  approaching_sla?: number;
  unacknowledged_critical?: number;
  escalated_incidents?: number;
  unassigned_critical?: number;
}

export interface IncidentCreatePayload {
  title: string;
  description?: string;
  severity?: IncidentSeverity;
  priority?: IncidentPriority;
  category?: IncidentCategory;
  assigned_to?: string;
  primary_alert_id?: string;
  primary_cluster_id?: string;
  investigation_id?: string;
  notes?: string;
}

export interface IncidentPromoteAlertPayload {
  alert_id: string;
  title?: string;
  severity?: IncidentSeverity;
  priority?: IncidentPriority;
  category?: IncidentCategory;
  assigned_to?: string;
  notes?: string;
}

export interface IncidentPromoteClusterPayload {
  cluster_id: string;
  title?: string;
  severity?: IncidentSeverity;
  priority?: IncidentPriority;
  category?: IncidentCategory;
  assigned_to?: string;
  notes?: string;
}

export interface IncidentStatusChangePayload {
  status: IncidentStatus;
  reason?: string;
  resolution_reason?: string;
}

export interface IncidentAssignPayload {
  assigned_to: string | null;
  team_id?: string | null;
  reason?: string;
}

export interface IncidentNoteCreatePayload {
  note_text: string;
  author?: string;
}
