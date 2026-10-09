/**
 * Section 45: TypeScript definitions for Persistent Background Jobs & Lifecycle Management.
 */

export type JobType =
  | 'ARTIFACT_ANALYSIS'
  | 'REPORT_GENERATION'
  | 'CROSS_INCIDENT_CORRELATION'
  | 'ATTACK_PATH_RECONSTRUCTION'
  | 'ENDPOINT_TELEMETRY_PROCESSING'
  | 'EVIDENCE_EXPORT'
  | 'MAINTENANCE';

export type JobStatus =
  | 'QUEUED'
  | 'SCHEDULED'
  | 'RUNNING'
  | 'RETRY_WAIT'
  | 'SUCCEEDED'
  | 'PARTIALLY_SUCCEEDED'
  | 'FAILED'
  | 'CANCEL_REQUESTED'
  | 'CANCELLED'
  | 'TIMED_OUT'
  | 'DEAD_LETTER';

export type JobPriority = 'CRITICAL' | 'HIGH' | 'NORMAL' | 'LOW';

export interface JobEventRead {
  id: string;
  job_id: string;
  workspace_id: string;
  event_type: string;
  stage?: string;
  progress_percent?: number;
  message: string;
  metadata: Record<string, any>;
  timestamp: string;
}

export interface JobReadResponse {
  id: string;
  workspace_id: string;
  job_type: JobType | string;
  status: JobStatus | string;
  priority: JobPriority | string;
  priority_weight: number;
  requested_by: string;
  resource_type?: string;
  resource_id?: string;
  analysis_run_id?: string;
  report_id?: string;
  attempt_count: number;
  max_attempts: number;
  created_at: string;
  scheduled_at: string;
  started_at?: string;
  heartbeat_at?: string;
  completed_at?: string;
  updated_at: string;
  timeout_seconds: number;
  worker_id?: string;
  idempotency_key?: string;
  progress_percent?: number;
  current_stage?: string;
  error_code?: string;
  sanitized_error_message?: string;
  result_reference?: string;
  result: Record<string, any>;
  events?: JobEventRead[];
}

export interface JobListResponse {
  total: number;
  page: number;
  page_size: number;
  items: JobReadResponse[];
}

export interface JobMetricsSummary {
  queued: number;
  scheduled: number;
  running: number;
  retry_wait: number;
  succeeded: number;
  partially_succeeded: number;
  failed: number;
  dead_letter: number;
  cancelled: number;
  timed_out: number;
  total_jobs: number;
  avg_wait_duration_seconds: number;
  avg_execution_duration_seconds: number;
  active_workers: string[];
}

export interface JobActionResponse {
  success: boolean;
  job_id: string;
  previous_status: string;
  current_status: string;
  message: string;
}

export interface JobSubmitRequest {
  job_type: JobType;
  resource_type?: string;
  resource_id?: string;
  analysis_run_id?: string;
  report_id?: string;
  priority?: JobPriority;
  payload?: Record<string, any>;
  idempotency_key?: string;
  timeout_seconds?: number;
  max_attempts?: number;
}
