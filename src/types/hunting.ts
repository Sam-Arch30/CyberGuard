/**
 * Section 54: Threat Hunting Workspace & Query Engine Types
 */

export type HuntSource =
  | 'indicators'
  | 'alerts'
  | 'findings'
  | 'artifacts'
  | 'threat_intelligence'
  | 'watchlist_changes'
  | 'watched_indicators'
  | 'incidents'
  | 'cases'
  | 'threat_events'
  | 'threat_memory'
  | 'endpoint_events';

export type QueryOperator =
  | 'equals'
  | 'not_equals'
  | 'contains'
  | 'starts_with'
  | 'ends_with'
  | 'in'
  | 'not_in'
  | 'greater_than'
  | 'greater_than_or_equal'
  | 'less_than'
  | 'less_than_or_equal'
  | 'between'
  | 'exists'
  | 'not_exists'
  | 'before'
  | 'after'
  | 'within_last';

export type TimePreset = '15m' | '1h' | '6h' | '24h' | '7d' | '30d' | 'custom' | 'all';

export type HuntVisibility = 'PRIVATE' | 'TEAM' | 'TENANT';

export type HuntExecutionMode = 'FAST' | 'BACKGROUND';

export type HuntExecutionStatus =
  | 'QUEUED'
  | 'RUNNING'
  | 'SUCCEEDED'
  | 'PARTIALLY_SUCCEEDED'
  | 'FAILED'
  | 'CANCELLED';

export interface QueryFilter {
  field: string;
  operator: QueryOperator;
  value: any;
}

export interface QueryTimeRange {
  field?: string;
  preset?: TimePreset;
  from_time?: string;
  to_time?: string;
}

export interface QuerySort {
  field: string;
  direction: 'asc' | 'desc';
}

export interface HuntQueryDefinition {
  data_source: HuntSource;
  filters: QueryFilter[];
  time_range?: QueryTimeRange;
  sort?: QuerySort[];
  limit: number;
  offset: number;
  group_by?: string;
  top_n?: number;
}

export interface QueryPlanStep {
  step: string;
  description: string;
}

export interface HuntValidationResponse {
  is_valid: boolean;
  errors: string[];
  warnings: string[];
  estimated_cost: 'LOW' | 'MEDIUM' | 'HIGH' | 'RESTRICTED';
  query_plan: QueryPlanStep[];
}

export interface DataSourceField {
  name: string;
  display_name: string;
  field_type: 'string' | 'number' | 'boolean' | 'enum' | 'datetime';
  allowed_operators: QueryOperator[];
  description: string;
  is_sortable: boolean;
  is_groupable: boolean;
  options?: string[];
}

export interface DataSourceMetadata {
  key: HuntSource;
  display_name: string;
  description: string;
  fields: DataSourceField[];
  supported_relationships: string[];
  default_time_field: string;
  approximate_count?: number;
}

export interface DataSourceRegistryResponse {
  sources: DataSourceMetadata[];
}

export interface SavedHuntResponse {
  id: string;
  workspace_id: string;
  name: string;
  description?: string;
  data_source: string;
  query_definition: HuntQueryDefinition;
  hypothesis?: string;
  tags: string[];
  owner_user_id?: string;
  team_id?: string;
  visibility: HuntVisibility;
  is_template: boolean;
  last_executed_at?: string;
  last_result_count?: number;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface SavedHuntListResponse {
  items: SavedHuntResponse[];
  templates: SavedHuntResponse[];
  total: number;
}

export interface SavedHuntCreateRequest {
  name: string;
  description?: string;
  data_source: HuntSource;
  query_definition: HuntQueryDefinition;
  hypothesis?: string;
  tags?: string[];
  visibility?: HuntVisibility;
}

export interface SavedHuntUpdateRequest {
  name?: string;
  description?: string;
  query_definition?: HuntQueryDefinition;
  hypothesis?: string;
  tags?: string[];
  visibility?: HuntVisibility;
}

export interface HuntResultItem {
  id: string;
  data_source: string;
  title: string;
  primary_value: string;
  secondary_value?: string;
  severity?: string;
  verdict?: string;
  confidence?: number;
  observed_at?: string;
  properties: Record<string, any>;
  matched_reasons: string[];
  pivot_links: Record<string, any>;
}

export interface HuntAggregationBucket {
  key: string;
  count: number;
  percentage: number;
}

export interface HuntQueryResultResponse {
  execution_id: string;
  data_source: string;
  status: string;
  total_matches: number;
  items: HuntResultItem[];
  aggregations?: Record<string, HuntAggregationBucket[]>;
  duration_ms: number;
  query_plan: QueryPlanStep[];
  has_more: boolean;
  offset: number;
  limit: number;
}

export interface HuntExecutionRequest {
  query_definition: HuntQueryDefinition;
  saved_hunt_id?: string;
  execution_mode?: HuntExecutionMode;
}

export interface NaturalLanguageHuntRequest {
  prompt: string;
  suggested_source?: HuntSource;
}

export interface NaturalLanguageHuntResponse {
  interpretation: string;
  proposed_query: HuntQueryDefinition;
  confidence: number;
  explanation: string;
}

export interface HuntInvestigationHandoffRequest {
  execution_id: string;
  selected_record_ids: string[];
  investigation_title?: string;
  investigation_id?: string;
  reason?: string;
}

export interface HuntInvestigationHandoffResponse {
  success: boolean;
  investigation_id: string;
  attached_records_count: number;
  message: string;
}

export interface HuntWatchlistHandoffRequest {
  execution_id: string;
  selected_record_ids: string[];
  watchlist_id?: string;
  new_watchlist_name?: string;
  reason?: string;
}

export interface HuntWatchlistHandoffResponse {
  success: boolean;
  watchlist_id: string;
  added_indicators_count: number;
  message: string;
}
