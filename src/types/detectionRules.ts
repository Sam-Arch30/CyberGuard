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

export type DeploymentState = 'DRAFT' | 'STAGING' | 'PRODUCTION' | 'DISABLED';

export type OperationalHealth = 'HEALTHY' | 'DEGRADED' | 'FAILING' | 'UNKNOWN';

export type DependencyType =
  | 'DATA_SOURCE'
  | 'ANALYZER'
  | 'INTELLIGENCE'
  | 'BASELINE'
  | 'GRAPH'
  | 'WATCHLIST';

export type DependencyHealth = 'HEALTHY' | 'DEGRADED' | 'FAILING' | 'UNKNOWN';

export type MatchDisposition =
  | 'TRUE_POSITIVE'
  | 'FALSE_POSITIVE'
  | 'BENIGN'
  | 'EXPECTED_ACTIVITY'
  | 'NEEDS_REVIEW';

export interface RuleDependency {
  name: string;
  dependency_type: DependencyType;
  required: boolean;
  health: DependencyHealth;
  status_message?: string;
  last_verified_at?: string;
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

  // Section 57 Operational Control extensions
  owner_id?: string;
  team_id?: string;
  last_editor_id?: string;
  deployment_state: DeploymentState;
  operational_health: OperationalHealth;
  health_reason?: string;
  health_updated_at?: string;
  review_interval_days?: number;
  next_review_due?: string;
  last_reviewed_at?: string;
  dependencies: RuleDependency[];
  collections: string[];
  replaced_by_rule_id?: string;
  total_match_count?: number;
  is_stale?: boolean;
  review_due?: boolean;

  // Section 58 Automated Validation & Quality extensions
  validation_status?: ValidationStatus;
  last_validation_run_id?: string;
  validation_updated_at?: string;
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

export interface RuleSuppression {
  id: string;
  rule_id: string;
  name: string;
  reason: string;
  scope_type: string;
  scope_target: string;
  match_operator: string;
  match_value: string;
  is_active: boolean;
  created_by: string;
  created_at: string;
  expires_at?: string;
  hit_count: number;
  last_hit_at?: string;
}

export interface DeploymentDryRunResult {
  rule_id: string;
  target_version: string;
  validation_status: string;
  dependencies_status: string;
  historical_backtest_status: string;
  historical_matches_observed: number;
  operational_risk: 'LOW' | 'MEDIUM' | 'HIGH';
  can_deploy: boolean;
  blocking_reasons: string[];
  warnings: string[];
  details: Record<string, any>;
}

export interface RuleSimulationResult {
  rule_id: string;
  version: string;
  events_evaluated: number;
  simulated_matches_count: number;
  duration_ms: number;
  simulated_matches: Array<{
    event_id: string;
    matched: boolean;
    matched_conditions: any[];
    explanation: string;
  }>;
  label: string;
}

export interface RuleQualityMetrics {
  rule_id: string;
  rule_identifier: string;
  total_matches: number;
  reviewed_matches: number;
  true_positives: number;
  false_positives: number;
  benign: number;
  expected_activity: number;
  needs_review: number;
  precision_rate?: number;
  false_positive_rate?: number;
  review_coverage_pct?: number;
  quality_signals: string[];
  has_sufficient_data: boolean;
}

export interface RuleOperationalHealth {
  rule_id: string;
  rule_identifier: string;
  operational_health: OperationalHealth;
  health_reason: string;
  health_updated_at: string;
  dependencies: RuleDependency[];
  dependencies_summary: string;
  execution_count_24h: number;
  success_count_24h: number;
  failure_count_24h: number;
  error_rate: number;
  avg_duration_ms: number;
  p95_duration_ms: number;
  matches_last_24h: number;
  matches_previous_24h: number;
  match_rate_anomaly: boolean;
  anomaly_details?: string;
  zero_match_observed: boolean;
  review_interval_days: number;
  next_review_due?: string;
  days_until_review?: number;
  review_due: boolean;
  is_stale: boolean;
}

export interface OperationalOverviewStats {
  workspace_id: string;
  total_rules: number;
  active_rules: number;
  staging_rules: number;
  draft_rules: number;
  disabled_rules: number;
  healthy_rules: number;
  degraded_rules: number;
  failing_rules: number;
  unknown_health: number;
  review_due_count: number;
  stale_count: number;
  total_matches_24h: number;
  high_fp_rules_count: number;
  unusual_match_rate_count: number;
  coverage_by_datasource: Record<string, number>;
}

export interface BulkOperationResult {
  total_selected: number;
  successful: number;
  failed: number;
  action: string;
  results: Array<{
    rule_id: string;
    rule_identifier: string;
    success: boolean;
    error?: string;
    details?: Record<string, any>;
  }>;
}

// ============================================================================
// Section 58: Automated Detection Validation & Continuous Rule Quality Types
// ============================================================================

export type ValidationStatus =
  | 'NOT_RUN'
  | 'QUEUED'
  | 'RUNNING'
  | 'PASS'
  | 'PASS_WITH_WARNINGS'
  | 'FAIL'
  | 'BLOCKED'
  | 'CANCELLED'
  | 'TIMED_OUT'
  | 'STALE';

export type ValidationType =
  | 'FULL'
  | 'STRUCTURAL'
  | 'DEPENDENCY'
  | 'DATA_COMPATIBILITY'
  | 'EXECUTION'
  | 'REGRESSION'
  | 'PERFORMANCE'
  | 'BEHAVIOR'
  | 'FIXTURES'
  | 'CONTINUOUS'
  | 'GATE_CHECK';

export type ValidationTrigger =
  | 'MANUAL'
  | 'SCHEDULED'
  | 'CONTINUOUS'
  | 'VERSION_CREATED'
  | 'DEPLOYMENT_GATE'
  | 'SCHEMA_CHANGE'
  | 'DEPENDENCY_CHANGE'
  | 'HEALTH_DEGRADED';

export type ValidationCategory =
  | 'STRUCTURAL'
  | 'DEPENDENCY'
  | 'DATA_COMPATIBILITY'
  | 'EXECUTION'
  | 'REGRESSION'
  | 'PERFORMANCE'
  | 'BEHAVIOR'
  | 'FIXTURE'
  | 'OPERATIONAL';

export type ValidationSeverity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type FixtureType = 'POSITIVE' | 'NEGATIVE';

export interface ValidationResultItem {
  id: string;
  category: ValidationCategory;
  status: ValidationStatus;
  severity: ValidationSeverity;
  code: string;
  message: string;
  observed_value: Record<string, any>;
  expected_value: Record<string, any>;
  baseline_value: Record<string, any>;
  evidence: Record<string, any>;
  created_at?: string;
}

export interface ValidationRun {
  id: string;
  workspace_id: string;
  rule_id: string;
  rule_version: string;
  validation_type: ValidationType;
  status: ValidationStatus;
  trigger_type: ValidationTrigger;
  started_at?: string;
  completed_at?: string;
  duration_ms?: number;
  requested_by: string;
  executed_by?: string;
  job_id?: string;
  baseline_rule_version?: string;
  is_stale: boolean;
  stale_reason?: string;
  results_count: number;
  pass_count: number;
  warning_count: number;
  fail_count: number;
  blocked_count: number;
  summary: Record<string, any>;
  checks: ValidationResultItem[];
  recommendations: string[];
  created_at: string;
}

export interface DeploymentGateCheck {
  rule_id: string;
  version: string;
  can_promote: boolean;
  status: ValidationStatus;
  gate_messages: string[];
  blocking_reasons: string[];
  warning_reasons: string[];
  last_run_id?: string;
  validated_at?: string;
}

export interface TestFixture {
  id: string;
  workspace_id: string;
  rule_id: string;
  name: string;
  description: string;
  fixture_type: FixtureType;
  payload: Record<string, any>;
  expected_match: boolean;
  is_active: boolean;
  last_run_at?: string;
  last_result?: string;
  last_error?: string;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface ValidationOverview {
  workspace_id: string;
  total_rules: number;
  passed_rules: number;
  warning_rules: number;
  failed_rules: number;
  blocked_rules: number;
  stale_rules: number;
  not_run_rules: number;
  total_validation_runs_24h: number;
  avg_validation_duration_ms: number;
  schema_drift_detected_count: number;
  performance_regression_count: number;
  critical_gate_blocked_count: number;
}

/**
 * Section 59: Unified Threat Detection Pipeline Types
 */
export type PipelineStage =
  | 'RECEIVE'
  | 'NORMALIZE'
  | 'SELECT_RULES'
  | 'EVALUATE'
  | 'PERSIST_MATCH'
  | 'CREATE_FINDING'
  | 'EVALUATE_RISK'
  | 'DISPATCH_ALERT'
  | 'COMPLETED';

export type EvaluationOutcome =
  | 'MATCH'
  | 'NO_MATCH'
  | 'SKIPPED'
  | 'SUPPRESSED'
  | 'BLOCKED'
  | 'ERROR'
  | 'TIMEOUT';

export type PipelineHealthStatus = 'HEALTHY' | 'DEGRADED' | 'BACKLOGGED' | 'FAILING';

export type PipelineMode = 'PRODUCTION' | 'SHADOW' | 'REPLAY';

export interface NormalizedDetectionEvent {
  id: string;
  event_type: string;
  source: string;
  occurred_at: string;
  received_at: string;
  entities: Record<string, string[]>;
  indicators: string[];
  provenance: Record<string, any>;
}

export interface RuleEvaluationDetail {
  rule_id: string;
  rule_name: string;
  rule_version: string;
  outcome: EvaluationOutcome;
  severity?: string;
  matched_fields: Record<string, any>;
  execution_duration_ms: number;
  explanation?: string;
  error_message?: string;
}

export interface DetectionMatchItem {
  id: string;
  workspace_id: string;
  rule_id: string;
  rule_name?: string;
  rule_version: string;
  event_id: string;
  execution_id: string;
  finding_id?: string;
  alert_id?: string;
  incident_id?: string;
  mode: string;
  status: string;
  severity: string;
  confidence?: number;
  matched_at: string;
  matched_fields?: Record<string, any>;
  evidence?: Record<string, any>;
  provenance?: Record<string, any>;
  explanation?: string;
}

export interface PipelineExecutionResult {
  event_id: string;
  workspace_id: string;
  mode: PipelineMode;
  normalized_event: NormalizedDetectionEvent;
  applicable_rules_count: number;
  evaluated_rules_count: number;
  matches_count: number;
  suppressed_count: number;
  evaluations: RuleEvaluationDetail[];
  matches: DetectionMatchItem[];
  findings_created: number;
  alerts_created: number;
  processing_duration_ms: number;
  completed_at: string;
}

export interface PipelineMetrics {
  workspace_id: string;
  events_received: number;
  events_processed: number;
  matches_created: number;
  findings_created: number;
  alerts_created: number;
  errors_total: number;
  dead_letters_total: number;
  avg_processing_latency_ms: number;
  backlog_count: number;
  health_status: PipelineHealthStatus;
}

export interface PipelineStatus {
  status: PipelineHealthStatus;
  workspace_id: string;
  active_workers: number;
  queue_depth: number;
  circuit_breaker_open: boolean;
  supported_sources: string[];
  metrics_summary: {
    events_received: number;
    events_processed: number;
    matches_created: number;
    findings_created: number;
    alerts_created: number;
    errors_total: number;
    dead_letters_total: number;
    avg_latency_ms: number;
  };
}

export interface DeadLetterItem {
  id: string;
  workspace_id: string;
  event_id: string;
  source_type: string;
  failure_stage: string;
  error_code: string;
  error_message: string;
  attempt_count: number;
  created_at: string;
}

export interface EventIngestPayload {
  event_type: string;
  source: string;
  payload: Record<string, any>;
  event_id?: string;
  timestamp?: string;
  mode?: PipelineMode;
  raw_payload?: Record<string, any>;
}

export interface PipelineReplayRequestPayload {
  start_time?: string;
  end_time?: string;
  rule_ids?: string[];
  max_events?: number;
}

/**
 * Section 60: Behavioral Detection & Anomaly Analytics Types
 */

export type ProfileStatus = 'INSUFFICIENT_DATA' | 'LEARNING' | 'ACTIVE' | 'STALE' | 'DEGRADED' | 'SUSPENDED';

export type BaselineQualityStatus = 'NO_DATA' | 'INSUFFICIENT_HISTORY' | 'DEVELOPING' | 'STABLE' | 'STALE' | 'DEGRADED';

export type QuarantineDisposition = 'PENDING' | 'APPROVED' | 'REJECTED' | 'EXPIRED';

export interface BehaviorProfile {
  id: string;
  workspace_id: string;
  entity_type: string;
  entity_id: string;
  entity_category: string;
  profile_status: ProfileStatus;
  sample_count: number;
  first_observed_at: string;
  last_observed_at: string;
  last_anomaly_at?: string | null;
  anomaly_count: number;
  quality_status: BaselineQualityStatus;
  confidence_score: number;
  baseline_version: string;
  feature_schema_version: string;
  active_metrics: string[];
  top_deviations: Array<{
    metric_type: string;
    observed_value: string;
    expected_range: string;
    deviation_score: number;
    severity: string;
    occurred_at: string;
  }>;
  metadata: Record<string, any>;
  created_at: string;
  updated_at: string;
}

export interface BehaviorProfileDetail extends BehaviorProfile {
  recent_deviations: Array<{
    id: string;
    metric_type: string;
    observed_value: string;
    expected_range: string;
    deviation_score: number;
    severity_hint: string;
    explanation: string;
    finding_id?: string;
    alert_id?: string;
    created_at: string;
  }>;
  active_baselines: Array<{
    id: string;
    metric_type: string;
    sample_count: number;
    quality_status: string;
    confidence_score: number;
    learning_mode: string;
    expected_range_summary: string;
    metric_version: string;
    updated_at: string;
  }>;
  pending_quarantine_count: number;
}

export interface BehavioralAnomalyDetail {
  id: string;
  workspace_id: string;
  entity_type: string;
  entity_id: string;
  metric_type: string;
  observed_value: string;
  baseline_expected_range: string;
  deviation_score: number;
  severity_hint: string;
  direction: string;
  explanation: string;
  evidence_ids: string[];
  limitations: string[];
  finding_id?: string;
  alert_id?: string;
  incident_id?: string;
  created_at: string;
}

export interface LearningQuarantineItem {
  id: string;
  workspace_id: string;
  entity_type: string;
  entity_id: string;
  metric_type: string;
  observed_value: string;
  event_id?: string;
  quarantine_reason: string;
  disposition: QuarantineDisposition;
  reviewed_by?: string;
  reviewed_at?: string;
  review_notes?: string;
  payload: Record<string, any>;
  created_at: string;
}

export interface BehavioralOverviewStats {
  total_profiles: number;
  active_profiles: number;
  learning_profiles: number;
  insufficient_profiles: number;
  degraded_profiles: number;
  anomalies_today: number;
  high_severity_anomalies_today: number;
  pending_quarantines: number;
  recent_deviations: BehavioralAnomalyDetail[];
}



