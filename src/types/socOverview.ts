/**
 * TypeScript definitions for Section 44: SOC Overview Dashboard.
 */

export interface SocPostureMetrics {
  active_investigations: number;
  high_risk_open: number;
  pending_response_approvals: number;
  failed_analysis_jobs: number;
  new_findings_count: number;
  active_endpoint_agents: number;
  total_investigations: number;
  sla_breaches?: number;
  approaching_sla?: number;
  unacknowledged_critical?: number;
  escalated_incidents?: number;
  unassigned_critical?: number;
}

export interface SocRiskDistribution {
  critical: number;
  high: number;
  medium: number;
  low: number;
  safe: number;
  total: number;
}

export interface SocPriorityQueueItem {
  id: string;
  investigation_id?: string;
  title: string;
  risk_score: number;
  severity: string;
  status: string;
  resource_type: string;
  reason_for_inclusion: string;
  urgency: 'P0' | 'P1' | 'P2' | 'P3' | string;
  updated_at: string;
  navigation_target: string;
  sla_status?: string;
  time_remaining_mins?: number | null;
  sla_remaining_minutes?: number | null;
  escalation_level?: number | null;
}

export interface SocActivityItem {
  id: string;
  event_type: string;
  timestamp: string;
  resource_type: string;
  resource_id: string;
  description: string;
  user?: string;
  severity?: string;
  source: string;
  navigation_target?: string;
}

export interface SocThreatIntelItem {
  indicator_value: string;
  indicator_type: string;
  investigation_count: number;
  provenance: 'CURRENT_OBSERVATION' | 'HISTORICAL_MEMORY' | 'EXTERNAL_INTELLIGENCE' | 'ANALYST_VERIFIED' | string;
  reputation?: string;
  last_seen_at: string;
}

export interface SocCampaignSummaryItem {
  id: string;
  campaign_id: string;
  name: string;
  status: string;
  incident_count: number;
  dominant_attack_type?: string;
  updated_at: string;
}

export interface SocEndpointFleetSummary {
  enrolled: number;
  active: number;
  degraded: number;
  revoked: number;
  events_received: number;
}

export interface SocSystemHealth {
  status: 'operational' | 'degraded' | 'unavailable' | string;
  api_status: string;
  database_status: string;
  analysis_engine_status: string;
  active_tasks: number;
  failed_tasks: number;
  endpoint_fleet?: SocEndpointFleetSummary;
}

export interface SocOverviewResponse {
  generated_at: string;
  time_window: '24h' | '7d' | '30d' | 'all' | string;
  posture: SocPostureMetrics;
  risk_distribution: SocRiskDistribution;
  priority_queue: SocPriorityQueueItem[];
  recent_activity: SocActivityItem[];
  threat_intel: SocThreatIntelItem[];
  active_campaigns: SocCampaignSummaryItem[];
  system_health: SocSystemHealth;
  partial_failures: string[];
}
