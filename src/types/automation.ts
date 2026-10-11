/**
 * Section 70: Security Operations Automation (SOAR) Frontend Types.
 */

export type WorkflowType =
  | 'ALERT_TRIAGE'
  | 'INCIDENT_ESCALATION'
  | 'THREAT_HUNTING'
  | 'ACCOUNT_TAKEOVER_TRIAGE'
  | 'MALICIOUS_ATTACHMENT_TRIAGE'
  | 'SLA_BREACH_REMEDIATION'
  | 'CUSTOM';

export type WorkflowStatus = 'DRAFT' | 'VALIDATING' | 'ACTIVE' | 'PAUSED' | 'DISABLED' | 'ARCHIVED';

export type WorkflowExecutionMode = 'PRODUCTION' | 'DRY_RUN' | 'TEST' | 'SIMULATION';

export type AutomationRunStatus =
  | 'QUEUED'
  | 'RUNNING'
  | 'WAITING_FOR_APPROVAL'
  | 'PAUSED'
  | 'PARTIALLY_COMPLETED'
  | 'COMPLETED'
  | 'FAILED'
  | 'CANCELLED'
  | 'TIMED_OUT';

export type StepStatus =
  | 'PENDING'
  | 'RUNNING'
  | 'WAITING_FOR_APPROVAL'
  | 'APPROVED'
  | 'REJECTED'
  | 'COMPLETED'
  | 'PARTIALLY_COMPLETED'
  | 'FAILED'
  | 'SKIPPED'
  | 'TIMED_OUT'
  | 'POLICY_DENIED';

export type ActionRiskClassification = 'READ_ONLY' | 'LOW_IMPACT' | 'MODERATE_IMPACT' | 'HIGH_IMPACT' | 'DESTRUCTIVE';

export type ActionApprovalLevel =
  | 'AUTOMATIC'
  | 'ANALYST_APPROVAL'
  | 'SENIOR_ANALYST_APPROVAL'
  | 'ADMIN_APPROVAL'
  | 'FORBIDDEN';

export type ApprovalStatus = 'PENDING' | 'APPROVED' | 'REJECTED' | 'EXPIRED' | 'CANCELLED';

export interface ConditionRule {
  field: string;
  operator: string;
  value: any;
}

export interface ConditionGroup {
  logic: string;
  rules: ConditionRule[];
}

export interface WorkflowActionDefinition {
  step_key: string;
  action_id: string;
  name: string;
  risk_classification?: ActionRiskClassification;
  approval_level?: ActionApprovalLevel;
  required_role?: string;
  parameters?: Record<string, any>;
  max_retries?: number;
  timeout_seconds?: number;
  continue_on_failure?: boolean;
}

export interface WorkflowExecutionLimits {
  max_steps: number;
  timeout_seconds: number;
  max_retries: number;
  max_recursion_depth: number;
  deduplication_window_seconds: number;
}

export interface AutomationWorkflow {
  id: string;
  workspace_id: string;
  tenant_id: string;
  name: string;
  description?: string;
  workflow_type: WorkflowType;
  status: WorkflowStatus;
  version: number;
  owner_id: string;
  team_id?: string;
  trigger_type: string;
  trigger_config: Record<string, any>;
  conditions: ConditionGroup;
  actions: WorkflowActionDefinition[];
  approval_policy: Record<string, any>;
  execution_limits: WorkflowExecutionLimits;
  is_active: boolean;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface StepExecution {
  id: string;
  step_index: number;
  step_key: string;
  action_id: string;
  name: string;
  status: StepStatus;
  risk_classification: ActionRiskClassification;
  approval_level: ActionApprovalLevel;
  requires_approval: boolean;
  approval_id?: string;
  approval_decision?: string;
  approved_by?: string;
  approved_at?: string;
  input_params: Record<string, any>;
  output_data: Record<string, any>;
  verification_result: Record<string, any>;
  verified_state: boolean;
  error_message?: string;
  failure_category?: string;
  retry_count: number;
  execution_duration_ms: number;
  started_at?: string;
  completed_at?: string;
}

export interface AutomationRun {
  id: string;
  workspace_id: string;
  tenant_id: string;
  workflow_id?: string;
  workflow_name?: string;
  workflow_version: number;
  status: AutomationRunStatus;
  trigger_type: string;
  trigger_resource_type?: string;
  trigger_resource_id?: string;
  execution_mode: WorkflowExecutionMode;
  idempotency_key?: string;
  total_steps: number;
  completed_steps: number;
  failed_steps: number;
  skipped_steps: number;
  error_message?: string;
  failure_category?: string;
  started_at?: string;
  completed_at?: string;
  explainability_trace: Record<string, any>;
  output_summary: Record<string, any>;
  steps: StepExecution[];
  created_at: string;
}

export interface ApprovalRequest {
  id: string;
  run_id: string;
  step_id: string;
  action_id: string;
  status: ApprovalStatus;
  required_role: string;
  requested_by: string;
  requested_at: string;
  expires_at: string;
  decision?: string;
  decided_by?: string;
  decided_at?: string;
  reason?: string;
  action_payload: Record<string, any>;
  context_summary: Record<string, any>;
}

export interface RegisteredActionMeta {
  action_id: string;
  name: string;
  description: string;
  risk_classification: ActionRiskClassification;
  default_approval_level: ActionApprovalLevel;
  required_role: string;
  target_resource_type?: string;
  parameters_schema: Record<string, any>;
}

export interface AutomationMetrics {
  total_workflows: number;
  active_workflows: number;
  draft_workflows: number;
  total_runs: number;
  completed_runs: number;
  partially_completed_runs: number;
  failed_runs: number;
  pending_approvals: number;
  success_rate: number;
  average_duration_ms: number;
  failure_breakdown: Record<string, number>;
}
