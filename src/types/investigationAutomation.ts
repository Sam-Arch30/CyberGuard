/**
 * Section 66: Advanced Investigation Automation TypeScript Contracts.
 * Maps 1-to-1 with backend Pydantic schemas in backend/schemas/investigation_automation.py.
 */

export type AutomationTriggerType =
  | 'MANUAL_ANALYST'
  | 'DETECTION_RULE'
  | 'ALERT_THRESHOLD'
  | 'CAMPAIGN_MATCH'
  | 'SCHEDULED_SWEEP'
  | 'API_EXTERNAL';

export type AutomationMode =
  | 'ASSISTED'
  | 'SEMI_AUTONOMOUS'
  | 'SUPERVISED_AUTONOMOUS';

export type AutomationRunStatus =
  | 'QUEUED'
  | 'PLANNING'
  | 'RUNNING'
  | 'WAITING_FOR_ANALYST'
  | 'PARTIALLY_COMPLETED'
  | 'COMPLETED'
  | 'FAILED'
  | 'CANCELLED'
  | 'TIMED_OUT';

export type StepStatus =
  | 'QUEUED'
  | 'RUNNING'
  | 'WAITING_APPROVAL'
  | 'COMPLETED'
  | 'PARTIALLY_COMPLETED'
  | 'FAILED'
  | 'SKIPPED'
  | 'CANCELLED';

export type ActionCostClass = 'FAST' | 'NORMAL' | 'EXPENSIVE';

export type ActionApprovalLevel =
  | 'READ_ONLY_AUTOMATIC'
  | 'READ_ONLY_APPROVAL_OPTIONAL'
  | 'ANALYST_APPROVAL_REQUIRED'
  | 'ADMIN_APPROVAL_REQUIRED';

export type ActionId =
  | 'GET_ASSET_CONTEXT'
  | 'GET_IDENTITY_CONTEXT'
  | 'GET_INDICATOR_CONTEXT'
  | 'GET_THREAT_INTELLIGENCE'
  | 'GET_WATCHLIST_CONTEXT'
  | 'GET_RELATED_ALERTS'
  | 'GET_RELATED_INCIDENTS'
  | 'GET_RELATED_FINDINGS'
  | 'GET_GRAPH_RELATIONSHIPS'
  | 'RUN_APPROVED_HUNT'
  | 'RUN_APPROVED_PIVOT'
  | 'GET_CAMPAIGN_CONTEXT'
  | 'GET_BEHAVIOR_CONTEXT'
  | 'BUILD_TIMELINE'
  | 'CHECK_DATA_COVERAGE'
  | 'GENERATE_INVESTIGATION_SUMMARY';

export type GapCategory =
  | 'TELEMETRY_MISSING'
  | 'LOG_GAP'
  | 'UNRESOLVED_IDENTITY'
  | 'UNMONITORED_ASSET'
  | 'INCOMPLETE_TIMELINE'
  | 'INTELLIGENCE_UNAVAILABLE';

export type GapSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type TelemetryCoverageStatus =
  | 'AVAILABLE'
  | 'PARTIAL'
  | 'STALE'
  | 'MISSING'
  | 'NOT_CONFIGURED';

export interface AutomationBudget {
  max_steps: number;
  max_depth: number;
  max_entities: number;
  max_time_seconds: number;
}

export interface AutomationStepRead {
  id: string;
  run_id: string;
  step_index: number;
  action_id: ActionId | string;
  name: string;
  cost_class: ActionCostClass;
  approval_level: ActionApprovalLevel;
  status: StepStatus;
  input_params: Record<string, any>;
  result_summary: Record<string, any>;
  result_count: number;
  warnings: string[];
  error_message?: string | null;
  approved_by?: string | null;
  started_at?: string | null;
  completed_at?: string | null;
  duration_ms: number;
}

export interface InvestigationGapRead {
  id: string;
  workspace_id: string;
  investigation_id: string;
  run_id?: string | null;
  category: GapCategory | string;
  severity: GapSeverity | string;
  title: string;
  description: string;
  remediation_recommendation?: string | null;
  created_at: string;
}

export interface TelemetryCoverageItem {
  source: string;
  status: TelemetryCoverageStatus;
  message: string;
  last_observed_at?: string | null;
}

export interface InvestigationCoverageReport {
  sources: TelemetryCoverageItem[];
  coverage_score: number;
  gaps_count: number;
}

export interface RecommendedNextStep {
  priority: string;
  title: string;
  description: string;
  action_type: string;
  handoff_route?: string | null;
}

export interface InvestigationSummaryReport {
  knowns: string[];
  unknowns: string[];
  assessment_summary: string;
  confidence: number;
  recommended_next_steps: RecommendedNextStep[];
}

export interface InvestigationAutomationRunRead {
  id: string;
  workspace_id: string;
  investigation_id: string;
  trigger_type: AutomationTriggerType | string;
  mode: AutomationMode | string;
  template_name: string;
  plan_version: string;
  status: AutomationRunStatus;
  budget: AutomationBudget;
  total_steps: number;
  completed_steps: number;
  failed_steps: number;
  steps: AutomationStepRead[];
  gaps: InvestigationGapRead[];
  coverage_summary?: InvestigationCoverageReport | null;
  investigation_summary?: InvestigationSummaryReport | null;
  error_message?: string | null;
  created_by: string;
  started_at?: string | null;
  completed_at?: string | null;
  created_at: string;
  updated_at: string;
}

export interface InvestigationAutomationRunCreate {
  template_name?: string;
  mode?: AutomationMode;
  trigger_type?: AutomationTriggerType;
  budget?: AutomationBudget;
  custom_steps?: Array<{
    step_index: number;
    action_id: ActionId | string;
    name?: string;
    input_params?: Record<string, any>;
  }>;
}

export interface AutomationTemplateDefinition {
  template_name: string;
  title: string;
  description: string;
  target_trigger: string;
  steps: Array<{
    step_index: number;
    action_id: ActionId | string;
    name: string;
  }>;
}

export interface StepApprovalRequest {
  approve: boolean;
  reason?: string;
}

export interface AutomationPolicyRead {
  id: string;
  workspace_id: string;
  name: string;
  description: string;
  status: string;
  template_name: string;
  trigger_conditions: Record<string, any>;
  allowed_steps: string[];
  limits: Record<string, any>;
  version: string;
  created_by: string;
  created_at: string;
  updated_at: string;
}
