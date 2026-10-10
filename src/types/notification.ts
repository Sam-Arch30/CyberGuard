/**
 * Section 47: Notifications & Alert Center Types.
 * Distinguishes between user-facing notifications and actionable security alerts.
 */

export type NotificationCategory = 'NOTIFICATION' | 'SECURITY_ALERT';

export type NotificationStatus = 'UNREAD' | 'READ' | 'ACKNOWLEDGED' | 'DISMISSED';

export type NotificationSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type NotificationType =
  | 'CRITICAL_THREAT_DETECTED'
  | 'HIGH_RISK_THREAT_DETECTED'
  | 'MALICIOUS_ATTACHMENT_DETECTED'
  | 'CREDENTIAL_THEFT_DETECTED'
  | 'LOOKALIKE_IMPERSONATION_DETECTED'
  | 'CAMPAIGN_CORRELATED'
  | 'ACCOUNT_TAKEOVER_DETECTED'
  | 'AUTHENTICATION_FAILURE'
  | 'ANALYSIS_COMPLETED'
  | 'ANALYSIS_PARTIALLY_COMPLETED'
  | 'ANALYSIS_FAILED'
  | 'REPORT_READY'
  | 'REPORT_FAILED'
  | 'JOB_FAILED'
  | 'JOB_RETRYING'
  | 'INVESTIGATION_STATUS_CHANGED'
  | 'INVESTIGATION_RISK_CHANGED'
  | string;

export interface NotificationItem {
  id: string;
  workspace_id: string;
  user_id?: string | null;
  category: NotificationCategory;
  notification_type: NotificationType;
  severity: NotificationSeverity;
  status: NotificationStatus;
  title: string;
  message: string;
  source_type: string;
  source_id: string;
  investigation_id?: string | null;
  analysis_run_id?: string | null;
  finding_id?: string | null;
  job_id?: string | null;
  report_id?: string | null;
  navigation_target?: string | null;
  deduplication_key: string;
  metadata: Record<string, unknown>;
  created_at: string;
  read_at?: string | null;
  acknowledged_at?: string | null;
  acknowledged_by?: string | null;
}

export interface NotificationListResponse {
  items: NotificationItem[];
  total: number;
  unread_total: number;
  unread_alerts: number;
  unread_notifications: number;
  limit: number;
  offset: number;
}

export interface NotificationUnreadCountResponse {
  total_unread: number;
  alerts_unread: number;
  notifications_unread: number;
}

export interface NotificationFilterOptions {
  category?: NotificationCategory;
  status?: NotificationStatus;
  severity?: NotificationSeverity;
  investigation_id?: string;
  limit?: number;
  offset?: number;
}
