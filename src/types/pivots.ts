/**
 * Section 55: TypeScript Definitions for Advanced Threat Hunting & Investigation Pivots.
 */
import type { HuntQueryDefinition, QueryTimeRange } from './hunting';

export type PivotCategory = 'INFRASTRUCTURE' | 'ACTIVITY' | 'SECURITY';

export type PivotSourceType =
  | 'IP'
  | 'DOMAIN'
  | 'URL'
  | 'HASH'
  | 'EMAIL'
  | 'CERTIFICATE'
  | 'ASN'
  | 'DEVICE'
  | 'USER'
  | 'ARTIFACT'
  | 'ALERT'
  | 'INCIDENT'
  | 'CAMPAIGN';

export type PivotType =
  | 'RESOLVED_IPS'
  | 'REVERSE_DNS_DOMAINS'
  | 'ASSOCIATED_CERTIFICATES'
  | 'SHARED_CERTIFICATE_DOMAINS'
  | 'SHARED_IP_DOMAINS'
  | 'BELONGS_TO_ASN'
  | 'ASN_INFRASTRUCTURE'
  | 'NAMESERVERS'
  | 'REGISTRAR'
  | 'RELATED_EMAILS'
  | 'EMAIL_RECIPIENTS'
  | 'EMAIL_ATTACHMENTS'
  | 'ENDPOINT_ACTIVITY'
  | 'NETWORK_ACTIVITY'
  | 'ARTIFACT_OBSERVATIONS'
  | 'API_ACTIVITY'
  | 'RELATED_ALERTS'
  | 'RELATED_INVESTIGATIONS'
  | 'ASSOCIATED_CAMPAIGNS'
  | 'THREAT_INTELLIGENCE'
  | 'WATCHLIST_STATUS'
  | 'ATTRIBUTION_HYPOTHESIS'
  | 'ATTACK_TECHNIQUES'
  | 'KNOWLEDGE_GRAPH_NEIGHBORS';

export type PivotCostClass = 'FAST' | 'NORMAL' | 'EXPENSIVE' | 'BACKGROUND';

export type EvidenceClassification = 'SUPPORTING' | 'CONTRADICTING' | 'NEUTRAL';

export type HypothesisStatus = 'PROPOSED' | 'INVESTIGATING' | 'CONFIRMED' | 'DISPROVED' | 'ABANDONED';

export interface PivotDefinition {
  source_type: PivotSourceType;
  pivot_type: PivotType;
  target_type: PivotSourceType;
  display_name: string;
  category: PivotCategory;
  relationship_name: string;
  description: string;
  cost_class: PivotCostClass;
  is_multi_hop_capable: boolean;
  reverse_pivot_type?: PivotType;
}

export interface PivotRegistryResponse {
  supported_source_types: PivotSourceType[];
  pivots: PivotDefinition[];
  max_depth_allowed: number;
  max_results_allowed: number;
}

export interface PivotRequest {
  source_type: PivotSourceType;
  source_value: string;
  pivot_type: PivotType;
  source_id?: string;
  time_range?: QueryTimeRange;
  depth?: number;
  limit?: number;
  investigation_id?: string;
  execution_mode?: 'FAST' | 'BACKGROUND';
}

export interface PivotResultItem {
  id: string;
  target_type: string;
  target_value: string;
  target_id?: string;
  display_label: string;
  relationship_type: string;
  relationship_description: string;
  origin: string;
  confidence: number;
  first_seen?: string;
  last_seen?: string;
  source_reference?: string;
  evidence_reference?: string;
  co_occurrence_count: number;
  classification?: EvidenceClassification;
  matched_context: Record<string, any>;
  pivot_links: Record<string, string>;
}

export interface EntityFrequencyContext {
  source_type: string;
  source_value: string;
  first_seen?: string;
  last_seen?: string;
  observed_days_span: number;
  artifact_count: number;
  investigation_count: number;
  alert_count: number;
  is_watchlist_monitored: boolean;
  reputation_verdict?: string;
  threat_score?: number;
}

export interface PivotGraphNode {
  id: string;
  label: string;
  entity_type: string;
  value: string;
  is_root: boolean;
  hop_distance: number;
  verdict?: string;
  threat_score?: number;
  metadata: Record<string, any>;
}

export interface PivotGraphEdge {
  id: string;
  source: string;
  target: string;
  relationship: string;
  label: string;
  origin: string;
  confidence: number;
  evidence_reference?: string;
  provenance_explanation: string;
}

export interface PivotResponse {
  source_type: string;
  source_value: string;
  pivot_type: string;
  depth: number;
  execution_time_ms: number;
  total_results: number;
  truncated: boolean;
  items: PivotResultItem[];
  frequency_context: EntityFrequencyContext;
  graph_nodes: PivotGraphNode[];
  graph_edges: PivotGraphEdge[];
  job_id?: string;
  execution_id?: string;
  partial_failures: string[];
}

export interface AIPivotRecommendationItem {
  pivot_type: PivotType;
  display_name: string;
  category: PivotCategory;
  rationale: string;
  expected_yield: string;
  confidence: number;
}

export interface AIPivotRecommendationResponse {
  source_type: string;
  source_value: string;
  recommendations: AIPivotRecommendationItem[];
}

export interface HypothesisRecordRequest {
  title: string;
  hypothesis_text: string;
  source_observable?: string;
  investigation_id?: string;
  supporting_items?: string[];
  contradicting_items?: string[];
  neutral_items?: string[];
  analyst_notes?: string;
  status?: HypothesisStatus;
}

export interface HypothesisResponse {
  id: string;
  workspace_id: string;
  investigation_id?: string;
  title: string;
  hypothesis_text: string;
  status: string;
  source_observable?: string;
  supporting_count: number;
  contradicting_count: number;
  neutral_count: number;
  supporting_items: string[];
  contradicting_items: string[];
  neutral_items: string[];
  analyst_notes?: string;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface PromoteToInvestigationRequest {
  investigation_id?: string;
  title?: string;
  description?: string;
  severity?: string;
  selected_target_values: string[];
  source_value: string;
  source_type: string;
  pivot_type: string;
  hypothesis_id?: string;
  analyst_notes?: string;
}

export interface PromoteToInvestigationResponse {
  investigation_id: string;
  created_relationships_count: number;
  incident_number?: string;
  message: string;
}

export interface PromoteToWatchlistRequest {
  watchlist_id?: string;
  watchlist_name?: string;
  selected_target_values: string[];
  target_type: string;
  reason?: string;
}

export interface PromoteToWatchlistResponse {
  watchlist_id: string;
  added_items_count: number;
  message: string;
}

export interface PivotToHuntQueryRequest {
  selected_target_values: string[];
  target_type: string;
}

export interface PivotToHuntQueryResponse {
  query_definition: HuntQueryDefinition;
  suggested_hunt_name: string;
}

export interface PivotHistoryStep {
  source_type: PivotSourceType;
  source_value: string;
  pivot_type?: PivotType;
  timestamp: string;
}
