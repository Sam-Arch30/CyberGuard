/**
 * TypeScript Interfaces for Section 29: Response Playbooks.
 * Models, execution states, simulation plans, and approvals.
 */

export type PlaybookStatus =
  | 'DRAFT'
  | 'VALIDATING'
  | 'READY'
  | 'REVIEW_REQUIRED'
  | 'APPROVED'
  | 'STAGED'
  | 'ACTIVE'
  | 'PAUSED'
  | 'DISABLED'
  | 'RETIRED'
  | 'SUPERSEDED';

export type PlaybookTriggerType =
  | 'MANUAL'
  | 'RECOMMENDATION_APPROVED'
  | 'INCIDENT_ESCALATION'
  | 'AUTOMATED_HIGH_CONFIDENCE';

export type StepType =
  // Evidence
  | 'PRESERVE_EVIDENCE'
  | 'COLLECT_ARTIFACT_METADATA'
  | 'CAPTURE_ANALYSIS_SNAPSHOT'
  | 'EXPORT_FORENSIC_RECORD'
  // Investigation
  | 'RUN_ANALYSIS'
  | 'REANALYZE_ARTIFACT'
  | 'ENRICH_INDICATOR'
  | 'CORRELATE_INCIDENT'
  | 'CREATE_INVESTIGATION_TASK'
  // Identity / Account
  | 'REVOKE_SESSION'
  | 'FORCE_REAUTHENTICATION'
  | 'REQUIRE_CREDENTIAL_RESET'
  | 'DISABLE_ACCOUNT'
  | 'ENABLE_ADDITIONAL_AUTHENTICATION'
  // Network
  | 'BLOCK_INDICATOR'
  | 'BLOCK_DOMAIN'
  | 'BLOCK_URL_PATTERN'
  | 'BLOCK_IP'
  | 'INCREASE_NETWORK_MONITORING'
  // Endpoint
  | 'ISOLATE_ENDPOINT'
  | 'COLLECT_ENDPOINT_ARTIFACT'
  | 'INCREASE_ENDPOINT_MONITORING'
  // Communication
  | 'CREATE_NOTIFICATION'
  | 'CREATE_CASE_NOTE'
  | 'ESCALATE_INCIDENT'
  // Verification
  | 'VERIFY_ACCOUNT_STATE'
  | 'VERIFY_SESSION_STATE'
  | 'VERIFY_ENDPOINT_STATE'
  | 'VERIFY_NETWORK_CONTROL'
  | 'VERIFY_EVIDENCE_PRESERVATION';

export type PlaybookSafetyClass =
  | 'INFORMATIONAL'
  | 'LOW_IMPACT'
  | 'REVERSIBLE'
  | 'CONTAINMENT'
  | 'HIGH_IMPACT'
  | 'DESTRUCTIVE';

export type PlaybookExecutionMode = 'DRY_RUN' | 'SIMULATION' | 'LIVE';

export type PlaybookExecutionStatus =
  | 'PENDING'
  | 'VALIDATING'
  | 'WAITING_FOR_APPROVAL'
  | 'READY'
  | 'RUNNING'
  | 'PAUSED'
  | 'COMPLETED'
  | 'PARTIALLY_COMPLETED'
  | 'FAILED'
  | 'ROLLING_BACK'
  | 'ROLLED_BACK'
  | 'CANCELLED'
  | 'EXPIRED';

export type StepExecutionStatus =
  | 'PENDING'
  | 'RUNNING'
  | 'COMPLETED'
  | 'FAILED'
  | 'SKIPPED'
  | 'ROLLED_BACK'
  | 'ROLLBACK_FAILED'
  | 'VERIFICATION_FAILED';

export type PlaybookApprovalDecision =
  | 'APPROVED'
  | 'REJECTED'
  | 'DEFERRED'
  | 'EXPIRED'
  | 'CANCELLED';

export interface TargetSnapshot {
  target_type: string;
  target_id: string;
  tenant_id: string;
  resolved_at: string;
  state_at_resolution?: Record<string, any>;
  resolution_source: string;
  metadata?: Record<string, any>;
}

export interface TargetRef {
  target_type: string;
  target_id: string;
  tenant_id?: string;
  expected_state?: Record<string, any>;
}

export interface RetryPolicy {
  max_attempts: number;
  backoff_seconds: number;
  retryable_errors: string[];
}

export interface VerificationPolicy {
  enabled: boolean;
  expected_state: string;
  timeout_seconds: number;
}

export interface RollbackPolicy {
  supports_rollback: boolean;
  compensating_action?: string;
  reversibility: string;
}

export interface StepCondition {
  field: string;
  operator: string;
  value: any;
}

export interface ResponsePlaybookStep {
  id: string;
  playbook_id: string;
  step_key: string;
  sequence: number;
  step_type: StepType;
  name: string;
  description: string;
  parameters: Record<string, any>;
  target_selector?: Record<string, any>;
  condition?: StepCondition;
  on_success: string;
  on_failure: string;
  timeout_seconds: number;
  retry_policy: RetryPolicy;
  requires_approval: boolean;
  approval_policy: string;
  safety_class: PlaybookSafetyClass;
  verification_policy: VerificationPolicy;
  rollback_policy: RollbackPolicy;
  depends_on: string[];
  continue_on_failure: boolean;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface ResponsePlaybook {
  id: string;
  playbook_key: string;
  name: string;
  description: string;
  version: number;
  parent_version?: number;
  change_summary?: string;
  status: PlaybookStatus;
  trigger_type: PlaybookTriggerType;
  scope_type: string;
  severity_min: string;
  risk_min: number;
  incident_id?: string;
  investigation_id?: string;
  source_recommendation_id?: string;
  target_selector?: Record<string, any>;
  approval_policy: string;
  execution_policy: string;
  timeout_seconds: number;
  max_runtime_seconds: number;
  created_by: string;
  updated_by: string;
  created_at: string;
  updated_at: string;
  activated_at?: string;
  retired_at?: string;
  steps: ResponsePlaybookStep[];
}

export type ResponsePlaybookSummary = ResponsePlaybook;


export interface SimulationPlanStep {
  sequence: number;
  step_key: string;
  step_type: StepType;
  name: string;
  target_snapshot: TargetSnapshot;
  capability_state: string;
  capability_provider: string;
  requires_approval: boolean;
  simulated_action: string;
  safety_class: PlaybookSafetyClass;
  rollback_available: boolean;
  would_execute: boolean;
  reason: string;
}

export interface PlaybookValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
  lint_score: number;
}

export interface SimulationPlan {
  playbook_id: string;
  playbook_key: string;
  playbook_version: number;
  mode: string;
  total_steps: number;
  steps: SimulationPlanStep[];
  validation: PlaybookValidationResult;
  capabilities_required: Array<{ action_type: string; capability_state: string; provider: string }>;
  approval_required_overall: boolean;
  summary: string;
}

export interface ResponsePlaybookStepExecution {
  id: string;
  execution_id: string;
  step_id: string;
  step_key: string;
  sequence: number;
  target_snapshot?: TargetSnapshot;
  status: StepExecutionStatus;
  started_at: string;
  completed_at?: string;
  attempt_count: number;
  adapter: string;
  adapter_version: string;
  input_summary?: Record<string, any>;
  output_summary?: Record<string, any>;
  verification_result?: Record<string, any>;
  error_code?: string;
  error_message?: string;
}

export interface ResponsePlaybookApproval {
  id: string;
  execution_id: string;
  step_id?: string;
  scope: string;
  decision: PlaybookApprovalDecision;
  requested_by: string;
  approved_by: string;
  reason: string;
  target_snapshot?: Record<string, any>;
  decided_at: string;
  created_at: string;
}

export interface ResponsePlaybookExecution {
  id: string;
  playbook_id: string;
  playbook_version: number;
  incident_id?: string;
  investigation_id?: string;
  source_recommendation_id?: string;
  trigger_source: string;
  mode: PlaybookExecutionMode;
  status: PlaybookExecutionStatus;
  started_at: string;
  completed_at?: string;
  requested_by: string;
  approved_by?: string;
  current_step_key?: string;
  result_summary?: string;
  error_code?: string;
  error_message?: string;
  step_executions: ResponsePlaybookStepExecution[];
  approvals: ResponsePlaybookApproval[];
  workspace_id: string;
  created_at: string;
}
