/**
 * Types for Section 37 Live Analysis & Task DAG Orchestration.
 */

export type AnalysisTaskStatus =
  | 'PENDING'
  | 'QUEUED'
  | 'RUNNING'
  | 'COMPLETED'
  | 'SKIPPED'
  | 'FAILED'
  | 'BLOCKED'
  | 'CANCELLED';

export type AnalysisRunStatus =
  | 'INITIALIZING'
  | 'QUEUED'
  | 'RUNNING'
  | 'PARTIAL'
  | 'COMPLETED'
  | 'FAILED'
  | 'CANCELLED';

export type AnalysisEventType =
  | 'RUN_STARTED'
  | 'TASK_STARTED'
  | 'TASK_PROGRESS'
  | 'TASK_COMPLETED'
  | 'TASK_FAILED'
  | 'FINDING_PRODUCED'
  | 'RISK_ASSESSED'
  | 'RUN_COMPLETED'
  | 'RUN_FAILED'
  | 'RUN_CANCELLED';

export interface AnalysisTask {
  id: string;
  analysis_run_id: string;
  analyzer_id: string;
  task_type: string;
  title: string;
  description?: string | null;
  status: AnalysisTaskStatus;
  dependency_ids: string[];
  started_at?: string | null;
  completed_at?: string | null;
  duration_seconds?: number | null;
  progress?: number | null;
  message?: string | null;
  error?: string | null;
  result_count: number;
  version: string;
  metadata?: Record<string, unknown>;
}

export interface AnalysisEvent {
  id: string;
  analysis_run_id: string;
  task_id?: string | null;
  event_type: AnalysisEventType;
  timestamp: string;
  task_status?: string | null;
  message: string;
  result_count: number;
  error?: string | null;
  metadata?: Record<string, unknown>;
}

export interface FindingPreview {
  id: string;
  analyzer: string;
  finding_type: string;
  title: string;
  severity: string;
  confidence: number;
  risk_contribution: number;
}

export interface AnalysisRunLiveResponse {
  id: string;
  artifact_id: string;
  investigation_id?: string | null;
  evidence_id?: string | null;
  artifact_name: string;
  artifact_type: string;
  artifact_size: number;
  artifact_sha256?: string | null;
  artifact_source: string;
  status: AnalysisRunStatus;
  trigger: string;
  pipeline_version: string;
  started_at?: string | null;
  completed_at?: string | null;
  duration_seconds?: number | null;
  overall_risk_score?: number | null;
  overall_severity?: string | null;
  confidence?: number | null;
  error?: string | null;
  total_tasks: number;
  completed_tasks: number;
  running_tasks: number;
  failed_tasks: number;
  pending_tasks: number;
  progress?: number | null;
  current_task?: AnalysisTask | null;
  tasks: AnalysisTask[];
  events: AnalysisEvent[];
  findings: FindingPreview[];
  previous_runs_count: number;
}
