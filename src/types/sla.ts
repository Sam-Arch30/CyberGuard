/**
 * Section 51: Incident SLA, Escalation & Workflow Automation TypeScript Types.
 */

export type SLAMilestone = 'ACKNOWLEDGEMENT' | 'INVESTIGATION' | 'CONTAINMENT' | 'RESOLUTION';

export type SLAMilestoneStatus =
  | 'NOT_STARTED'
  | 'RUNNING'
  | 'MET'
  | 'WARNING'
  | 'BREACHED'
  | 'PAUSED'
  | 'EXEMPT';

export type SLAOverallStatus =
  | 'HEALTHY'
  | 'WARNING'
  | 'BREACHED'
  | 'PAUSED'
  | 'EXEMPT'
  | 'MET';

export type EscalationCondition =
  | 'SLA_WARNING'
  | 'SLA_BREACH'
  | 'CRITICAL_UNACKNOWLEDGED'
  | 'UNASSIGNED_TIMEOUT'
  | 'PRIORITY_CRITICAL'
  | 'REOPENED';

export type EscalationActionType =
  | 'NOTIFY_OWNER'
  | 'NOTIFY_TEAM'
  | 'ASSIGN_TO_USER'
  | 'ASSIGN_TO_TEAM'
  | 'ESCALATE_PRIORITY'
  | 'CREATE_TASK';

export type RoutingStrategy = 'DIRECT_USER' | 'ROUND_ROBIN' | 'LEAST_LOADED' | 'TEAM_QUEUE';

export interface SLAMilestoneDetail {
  milestone: string;
  target_minutes: number;
  status: SLAMilestoneStatus;
  elapsed_minutes: number;
  remaining_minutes: number;
  deadline: string | null;
  met_at: string | null;
  warning_sent_at: string | null;
  breached_at: string | null;
  is_overdue: boolean;
  overdue_minutes: number;
  display_badge: string;
}

export interface IncidentSLADetail {
  incident_id: string;
  incident_number: string;
  workspace_id: string;
  policy_id: string | null;
  policy_name: string | null;
  policy_version: number;
  escalation_policy_id: string | null;
  overall_status: SLAOverallStatus;
  current_escalation_level: number;
  last_escalated_at: string | null;
  last_escalation_reason: string | null;
  is_paused: boolean;
  paused_at: string | null;
  paused_by: string | null;
  pause_reason: string | null;
  total_paused_seconds: number;
  is_exempt: boolean;
  exempt_at: string | null;
  exempt_by: string | null;
  exempt_reason: string | null;
  next_deadline: string | null;
  acknowledgement: SLAMilestoneDetail;
  investigation: SLAMilestoneDetail;
  containment: SLAMilestoneDetail;
  resolution: SLAMilestoneDetail;
  last_evaluated_at: string | null;
}

export interface SLAPolicy {
  id: string;
  workspace_id: string;
  name: string;
  description: string | null;
  severity: string;
  priority: string;
  category: string;
  acknowledgement_target_minutes: number;
  investigation_target_minutes: number;
  containment_target_minutes: number;
  resolution_target_minutes: number;
  warning_threshold_pct: number;
  escalation_policy_id: string | null;
  is_default: boolean;
  status: 'DRAFT' | 'ACTIVE' | 'DISABLED' | 'ARCHIVED' | string;
  version: number;
  created_by: string;
  updated_by: string;
  created_at: string;
  updated_at: string;
}

export interface EscalationRule {
  id: string;
  level: number;
  condition_type: string;
  milestone: string;
  action_type: string;
  target_role: string | null;
  target_user: string | null;
  target_team: string | null;
  escalate_priority_to: string | null;
  note_template: string | null;
  created_at: string;
}

export interface EscalationPolicy {
  id: string;
  workspace_id: string;
  name: string;
  description: string | null;
  cooldown_minutes: number;
  max_escalation_level: number;
  status: string;
  version: number;
  created_by: string;
  created_at: string;
  updated_at: string;
  rules: EscalationRule[];
}

export interface RoutingRule {
  id: string;
  workspace_id: string;
  name: string;
  description: string | null;
  priority_order: number;
  category: string;
  severity: string;
  min_risk_score: number;
  routing_strategy: string;
  target_team_id: string | null;
  target_user_id: string | null;
  candidate_analysts: string[];
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface WorkflowExecutionItem {
  id: string;
  incident_id: string;
  execution_key: string;
  idempotency_key: string;
  policy_id: string | null;
  policy_name?: string | null;
  rule_id: string | null;
  rule_name?: string | null;
  escalation_level: number;
  action_type: string;
  condition_type: string;
  target: string | null;
  status: string;
  executed_at: string;
  result?: Record<string, unknown> | null;
  error?: string | null;
  details: Record<string, unknown>;
}

export interface SLAPauseLogItem {
  id: string;
  incident_id: string;
  action: string;
  actor: string;
  reason: string;
  timestamp: string;
  paused_at: string;
  resumed_at?: string | null;
  paused_duration_seconds: number | null;
  duration_minutes?: number | null;
  paused_by: string;
  resumed_by?: string | null;
  active: boolean;
}

export interface WorkflowHistory {
  incident_id: string;
  executions: WorkflowExecutionItem[];
  pause_logs: SLAPauseLogItem[];
  total_executions: number;
}

export interface PolicySimulationRequest {
  severity: string;
  priority: string;
  category: string;
  risk_score: number;
  unacknowledged_minutes: number;
  uncontained_minutes: number;
  status: string;
}

export interface PolicySimulationResponse {
  matched_sla_policy: string | null;
  matched_sla_policy_id: string | null;
  matched_policy_name?: string | null;
  evaluated_sla_status?: string;
  milestone_states?: Record<string, { status: string }>;
  escalations_triggered?: Array<{
    target_tier: number;
    action: string;
    target_recipient: string;
  }>;
  target_assignee?: string | null;
  matched_sla_targets: Record<string, number>;
  simulated_milestone_status: Record<string, string>;
  triggered_escalation_rules: Array<{
    level: number;
    action_type: string;
    target: string | null;
    note_template: string | null;
  }>;
  simulated_routing_target: string | null;
  simulated_team_target: string | null;
  dry_run_summary: string;
}

export interface IncidentSLADetailResponse {
  incident_id: string;
  incident_number: string;
  overall_sla_status: string;
  milestones: {
    acknowledgement: SLAMilestoneDetail;
    investigation: SLAMilestoneDetail;
    containment: SLAMilestoneDetail;
    resolution: SLAMilestoneDetail;
  };
  policy: {
    id: string;
    name: string;
    version: number;
    severity: string;
    priority: string;
  };
  escalation: {
    current_level: number;
    max_level: number;
    current_level_name: string;
    current_target_name: string;
  };
  is_paused: boolean;
  total_paused_minutes: number;
  is_exempt: boolean;
  exemption_reason: string | null;
}

export interface WorkflowExecutionItemModel {
  id: string;
  policy_name: string;
  rule_name: string;
  action_type: string;
  condition_type: string;
  status: string;
  idempotency_key: string;
  executed_at: string;
  result?: Record<string, unknown> | null;
  error?: string | null;
}

export interface SLAPauseLogItemModel {
  id: string;
  paused_at: string;
  resumed_at?: string | null;
  duration_minutes?: number | null;
  reason: string;
  paused_by: string;
  resumed_by?: string | null;
  active: boolean;
}

export interface IncidentWorkflowHistoryResponse {
  executions: WorkflowExecutionItemModel[];
  pause_logs: SLAPauseLogItemModel[];
}

export interface SLAPolicySimulateResponse {
  matched_policy_name: string;
  evaluated_sla_status: string;
  milestone_states: Record<string, { status: string }>;
  escalations_triggered: Array<{
    target_tier: number;
    action: string;
    target_recipient: string;
  }>;
  target_assignee: string;
}

export type SLAPolicyResponse = SLAPolicy;
export type EscalationPolicyResponse = EscalationPolicy;
export type RoutingRuleResponse = RoutingRule;
export type SLAPolicySimulateRequest = PolicySimulationRequest;
export type CreateSLAPolicyRequest = Partial<SLAPolicy>;
export type CreateEscalationPolicyRequest = Partial<EscalationPolicy>;
export type CreateRoutingRuleRequest = Partial<RoutingRule>;

