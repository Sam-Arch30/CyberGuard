/**
 * Section 49: TypeScript Type Definitions for Alert Correlation & Incident Clustering.
 */

export type ClusterStatus =
  | 'OPEN'
  | 'INVESTIGATING'
  | 'CONTAINED'
  | 'RESOLVED'
  | 'FALSE_POSITIVE'
  | 'SUPPRESSED'
  | 'MERGED';

export type CorrelationSignalType =
  | 'SAME_USER'
  | 'SAME_SENDER'
  | 'SAME_DOMAIN'
  | 'SAME_PARENT_DOMAIN'
  | 'SAME_IP'
  | 'SAME_URL'
  | 'SAME_ATTACHMENT_HASH'
  | 'SAME_IOC'
  | 'SAME_SOURCE_ARTIFACT'
  | 'SAME_ANALYSIS_RUN'
  | 'SAME_INVESTIGATION'
  | 'SAME_CAMPAIGN'
  | 'SAME_ENDPOINT'
  | 'TEMPORAL_PROXIMITY'
  | 'GRAPH_RELATIONSHIP'
  | 'ATTACK_SEQUENCE';

export interface CorrelationSignal {
  type: CorrelationSignalType | string;
  strength: number;
  description: string;
  matched_value?: string | null;
}

export interface AlertClusterMember {
  id: string;
  alert_id: string;
  cluster_id: string;
  workspace_id: string;
  membership_confidence: number;
  signals: CorrelationSignal[];
  alert_summary?: {
    id: string;
    title: string;
    severity: string;
    status: string;
    alert_type: string;
    risk_score: number;
    created_at: string;
    source_type: string;
  } | null;
  created_at: string;
}

export interface AlertClusterItem {
  id: string;
  cluster_number: string;
  workspace_id: string;
  title: string;
  summary: string;
  status: ClusterStatus;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  risk_score: number;
  confidence: number;
  alert_count: number;
  primary_alert_id?: string | null;
  investigation_id?: string | null;
  campaign_id?: string | null;
  merged_into_cluster_id?: string | null;
  correlation_version: string;
  first_seen: string;
  last_seen: string;
  created_at: string;
  updated_at: string;
}

export interface AlertClusterDetail extends AlertClusterItem {
  members: AlertClusterMember[];
  aggregated_signals: CorrelationSignal[];
  entities: {
    users: string[];
    domains: string[];
    ips: string[];
    urls: string[];
    hashes: string[];
    endpoints: string[];
  };
  affected_entities?: {
    users: string[];
    domains: string[];
    ips: string[];
    urls: string[];
    hashes: string[];
    endpoints: string[];
  };
  timeline: Array<{
    timestamp: string;
    title: string;
    severity: string;
    alert_id: string;
    type: string;
  }>;
  investigation_detail?: {
    id: string;
    incident_number: string;
    title: string;
    status: string;
    severity: string;
    risk_score: number;
  } | null;
  campaign_detail?: Record<string, unknown> | null;
  activity_log: Array<{
    action: string;
    timestamp: string;
    user?: string | null;
    details?: string | null;
  }>;
}

export interface AlertClusterListResponse {
  items: AlertClusterItem[];
  total: number;
  limit: number;
  offset: number;
  counts_by_status: Record<string, number>;
  counts_by_severity: Record<string, number>;
}

export interface AlertClusterListParams {
  status?: string;
  severity?: string;
  investigation_id?: string;
  campaign_id?: string;
  q?: string;
  limit?: number;
  offset?: number;
  sort_by?: 'severity_first' | 'newest' | 'risk_desc' | 'alert_count';
}
