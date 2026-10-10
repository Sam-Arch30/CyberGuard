/**
 * Section 56: Detection Engineering & Rule Lifecycle Foundation Types
 */

export type RuleLifecycleStatus =
  | 'DRAFT'
  | 'DISCOVERED'
  | 'VALIDATING'
  | 'CANDIDATE'
  | 'PENDING_REVIEW'
  | 'APPROVED'
  | 'STAGED'
  | 'ACTIVE'
  | 'DISABLED'
  | 'DEPRECATED'
  | 'RETIRED'
  | 'REJECTED'
  | 'ARCHIVED'
  | 'SUPERSEDED';

export type RuleSeverity =
  | 'INFORMATIONAL'
  | 'LOW'
  | 'MEDIUM'
  | 'HIGH'
  | 'CRITICAL';

export type RuleCostClass = 'LOW' | 'MEDIUM' | 'HIGH' | 'UNSUPPORTED';

export type RuleDataSource =
  | 'EMAIL_EVENT'
  | 'NETWORK_EVENT'
  | 'ENDPOINT_EVENT'
  | 'AUTH_EVENT'
  | 'API_EVENT'
  | 'INDICATOR'
  | 'THREAT_INTELLIGENCE'
  | 'WATCHLIST'
  | 'BEHAVIORAL_BASELINE'
  | 'NOVELTY_EVENT';

export interface RuleCondition {
  field: string;
  operator: string;
  value?: any;
}

export interface RuleDefinition {
  source?: string;
  logic?: string;
  logical_operator: string;
  conditions: RuleCondition[];
  nested_groups?: RuleDefinition[];
}

export interface DetectionRule {
  id: string;
  workspace_id: string;
  rule_identifier: string;
  name: string;
  description: string;
  rule_type: string;
  category: string;
  data_sources: string[];
  status: RuleLifecycleStatus;
  scope: string;
  severity: RuleSeverity;
  confidence: number;
  cost_class: RuleCostClass;
  complexity_score: number;
  version: string;
  definition: RuleDefinition;
  thresholds?: Record<string, any>;
  tags: string[];
  attack_techniques: string[];
  is_system_rule: boolean;
  provenance_type: string;
  provenance_id?: string;
  provenance_details?: Record<string, any>;
  human_readable_logic: string;
  staged_at?: string;
  activated_at?: string;
  disabled_at?: string;
  retired_at?: string;
  created_by?: string;
  reviewed_by?: string;
  reviewed_at?: string;
  review_reason?: string;
  created_at: string;
  updated_at: string;
  versions_count?: number;
}

export interface DetectionRuleValidationResult {
  is_valid: boolean;
  errors: string[];
  warnings: string[];
  complexity_score: number;
  cost_class: RuleCostClass;
  human_readable_logic: string;
  normalized_fingerprint?: string;
}

export interface DetectionRuleBacktestResult {
  execution_id: string;
  status: string;
  records_evaluated: number;
  matches_count: number;
  true_positives_count?: number;
  false_positives_count?: number;
  precision_rate?: number;
  false_positive_rate?: number;
  execution_duration_ms: number;
  matches: Array<{
    record_id: string;
    event_id: string;
    record_type: string;
    observed_at?: string;
    threat_verdict?: string;
    explanation: Record<string, any>;
  }>;
  limitations: string[];
}

export interface RuleVersionDiff {
  rule_id: string;
  v1_version: string;
  v2_version: string;
  added_conditions: any[];
  removed_conditions: any[];
  modified_conditions: any[];
  threshold_changes: Record<string, any>;
  is_breaking_change: boolean;
  summary: string;
}

export interface DetectionRuleStats {
  workspace_id: string;
  total_rules: number;
  active_rules: number;
  staged_rules: number;
  candidate_rules: number;
  pending_review_rules: number;
  draft_rules: number;
  disabled_rules: number;
  total_matches: number;
  precision_rate: number;
  cost_distribution: Record<string, number>;
  category_distribution: Record<string, number>;
}

export interface FieldDefinition {
  field: string;
  field_type: string;
  data_source: string;
  display_name: string;
  description: string;
  allowed_operators: string[];
}
