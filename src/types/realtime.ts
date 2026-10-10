/**
 * Section 46: Structured Real-Time Event Types and Client Contracts.
 * Schema version: 1.
 */

export type RealtimeConnectionStatus =
  | 'CONNECTED'
  | 'DISCONNECTED'
  | 'RECONNECTING'
  | 'FALLBACK_POLLING';

export type RealtimeEventType =
  // Job Lifecycle
  | 'JOB_CREATED'
  | 'JOB_QUEUED'
  | 'JOB_STARTED'
  | 'JOB_PROGRESS'
  | 'JOB_RETRY_SCHEDULED'
  | 'JOB_CANCEL_REQUESTED'
  | 'JOB_CANCELLED'
  | 'JOB_COMPLETED'
  | 'JOB_PARTIALLY_COMPLETED'
  | 'JOB_FAILED'
  | 'JOB_TIMED_OUT'
  // Analysis Lifecycle
  | 'ANALYSIS_STARTED'
  | 'ANALYSIS_STAGE_STARTED'
  | 'ANALYSIS_STAGE_COMPLETED'
  | 'ANALYSIS_PROGRESS'
  | 'ANALYSIS_PARTIAL'
  | 'ANALYSIS_COMPLETED'
  | 'ANALYSIS_FAILED'
  | 'ANALYSIS_CANCELLED'
  // Findings & Evidence
  | 'FINDING_PERSISTED'
  | 'INDICATOR_DISCOVERED'
  | 'EVIDENCE_ADDED'
  // Analyzer Health & Diagnostics
  | 'ANALYZER_WARNING'
  | 'ANALYZER_DEGRADED'
  | 'ANALYZER_FAILED'
  // Reports
  | 'REPORT_GENERATION_STARTED'
  | 'REPORT_READY'
  | 'REPORT_FAILED';

export interface RealtimeEventPayload {
  finding_id?: string;
  finding_type?: string;
  severity?: string;
  title?: string;
  analyzer?: string;
  risk_contribution?: number;
  confidence?: number;
  task_id?: string;
  task_type?: string;
  completed_tasks?: number;
  total_tasks?: number;
  delay_seconds?: number;
  attempt?: number;
  max_attempts?: number;
  report_version?: number;
  report_number?: string;
  error_code?: string;
  download_url?: string;
  extra?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface RealtimeEvent {
  schema_version: number;
  event_id: string;
  sequence: number;
  event_type: RealtimeEventType | string;
  resource_type: 'ANALYSIS_RUN' | 'JOB' | 'INVESTIGATION' | 'REPORT' | 'WORKSPACE' | string;
  resource_id: string;
  job_id?: string;
  analysis_run_id?: string;
  investigation_id?: string;
  report_id?: string;
  workspace_id?: string;
  stage?: string;
  status?: string;
  progress_percent?: number;
  message: string;
  payload: RealtimeEventPayload;
  created_at: string;
}

export interface RealtimeSubscriptionOptions<T = unknown> {
  url: string;
  onEvent: (event: RealtimeEvent) => void;
  onSnapshot?: (snapshot: T) => void;
  onTerminal?: (status: string) => void;
  onError?: (error: unknown) => void;
  onStatusChange?: (status: RealtimeConnectionStatus) => void;
  /** Function to call when a sequence gap is detected or fallback polling triggers authoritative reconciliation */
  onAuthoritativeRefetch?: () => Promise<void> | void;
  /** Interval in ms for controlled adaptive polling fallback if SSE fails (default: 3000ms) */
  pollIntervalMs?: number;
}
