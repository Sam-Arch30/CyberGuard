/**
 * Section 53: Frontend TypeScript contracts for IOC Watchlists & Continuous Threat Monitoring.
 */

export type WatchlistStatus = 'ACTIVE' | 'PAUSED' | 'ARCHIVED';
export type WatchlistPriority = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type ChangeSensitivity = 'LOW' | 'MEDIUM' | 'HIGH';
export type AlertThreshold = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'NONE';
export type MonitoringStatus = 'ACTIVE' | 'PAUSED' | 'CHECKING' | 'HEALTHY' | 'STALE' | 'DEGRADED' | 'ERROR';

export type ChangeType =
  | 'NEWLY_MALICIOUS'
  | 'NEWLY_SUSPICIOUS'
  | 'BECAME_CLEAN'
  | 'VERDICT_CHANGED'
  | 'CONFIDENCE_CHANGED'
  | 'SEVERITY_CHANGED'
  | 'PROVIDER_CONFLICT_CHANGED'
  | 'ASN_CHANGED'
  | 'HOSTING_CHANGED'
  | 'CAMPAIGN_ASSOCIATION_CHANGED';

export interface WatchlistSummary {
  id: string;
  workspace_id: string;
  name: string;
  description?: string;
  status: WatchlistStatus;
  priority: WatchlistPriority;
  owner_user_id?: string;
  team_id?: string;
  check_interval_minutes: number;
  change_sensitivity: ChangeSensitivity;
  alert_threshold: AlertThreshold;
  notify_on_change: boolean;
  cooldown_minutes: number;
  total_indicators_count: number;
  active_indicators_count: number;
  stale_indicators_count: number;
  malicious_indicators_count: number;
  last_monitored_at?: string;
  next_monitoring_cycle_at?: string;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface WatchedIndicator {
  id: string;
  watchlist_id: string;
  workspace_id: string;
  indicator_id?: string;
  indicator_type: string;
  raw_value: string;
  normalized_value: string;
  display_value: string;
  monitoring_status: MonitoringStatus;
  priority: WatchlistPriority;
  first_watched_at: string;
  last_checked_at?: string;
  next_check_at?: string;
  last_successful_check_at?: string;
  last_failed_check_at?: string;
  last_change_detected_at?: string;
  last_snapshot_id?: string;
  last_verdict: string;
  last_confidence: number;
  last_severity: string;
  failure_count: number;
  consecutive_failure_count: number;
  last_error_message?: string;
  source_incident_id?: string;
  source_investigation_id?: string;
  created_at: string;
  updated_at: string;
}

export interface IntelligenceChange {
  id: string;
  workspace_id: string;
  watchlist_id: string;
  watched_indicator_id: string;
  indicator_type: string;
  normalized_value: string;
  change_type: ChangeType;
  change_severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  previous_snapshot_id?: string;
  current_snapshot_id?: string;
  previous_verdict?: string;
  current_verdict?: string;
  previous_confidence?: number;
  current_confidence?: number;
  previous_severity?: string;
  current_severity?: string;
  change_summary: string;
  change_details: Record<string, unknown>;
  alert_id?: string;
  notification_id?: string;
  acknowledged: boolean;
  acknowledged_at?: string;
  acknowledged_by?: string;
  detected_at: string;
}

export interface WatchlistMonitoringRun {
  id: string;
  workspace_id: string;
  watchlist_id: string;
  job_id?: string;
  trigger_type: 'SCHEDULED' | 'MANUAL' | 'EVENT_DRIVEN';
  status: 'QUEUED' | 'RUNNING' | 'SUCCEEDED' | 'PARTIALLY_SUCCEEDED' | 'FAILED' | 'CANCELLED';
  items_due: number;
  items_checked: number;
  items_changed: number;
  items_failed: number;
  alerts_created: number;
  notifications_created: number;
  started_at: string;
  completed_at?: string;
  duration_ms?: number;
  error_message?: string;
  run_summary: Record<string, unknown>;
}

export interface WatchlistHealth {
  watchlist_id: string;
  status: 'HEALTHY' | 'DEGRADED' | 'STALE' | 'ERROR' | 'PAUSED';
  total_indicators: number;
  healthy_count: number;
  stale_count: number;
  error_count: number;
  malicious_count: number;
  last_monitored_at?: string;
  next_cycle_at?: string;
  provider_health_summary: Record<string, string>;
}

export interface WatchlistDetail extends WatchlistSummary {
  recent_changes: IntelligenceChange[];
  recent_runs: WatchlistMonitoringRun[];
}

export interface WatchlistCreatePayload {
  name: string;
  description?: string;
  priority?: WatchlistPriority;
  check_interval_minutes?: number;
  change_sensitivity?: ChangeSensitivity;
  alert_threshold?: AlertThreshold;
  notify_on_change?: boolean;
  cooldown_minutes?: number;
  metadata?: Record<string, unknown>;
}

export interface WatchlistUpdatePayload {
  name?: string;
  description?: string;
  status?: WatchlistStatus;
  priority?: WatchlistPriority;
  check_interval_minutes?: number;
  change_sensitivity?: ChangeSensitivity;
  alert_threshold?: AlertThreshold;
  notify_on_change?: boolean;
  cooldown_minutes?: number;
  metadata?: Record<string, unknown>;
}

export interface WatchedIndicatorCreatePayload {
  indicator_value: string;
  indicator_type?: string;
  priority?: WatchlistPriority;
  source_incident_id?: string;
  source_investigation_id?: string;
  metadata?: Record<string, unknown>;
}

export interface QuickWatchPayload {
  indicator_value: string;
  indicator_type?: string;
  watchlist_id?: string;
  watchlist_name?: string;
  source_incident_id?: string;
  source_investigation_id?: string;
  reason?: string;
}
