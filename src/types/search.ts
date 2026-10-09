/**
 * TypeScript definitions for Section 43: History & Search.
 */

export type SearchResourceType =
  | 'investigation'
  | 'report'
  | 'indicator'
  | 'evidence'
  | 'finding'
  | 'campaign'
  | 'threat_memory';

export interface SearchResultItem {
  id: string;
  type: SearchResourceType | string;
  title: string;
  subtitle?: string;
  relevance: number;
  timestamp?: string;
  risk_score?: number;
  risk?: number;
  severity?: string;
  status?: string;
  source_type?: string;
  matched_field?: string;
  matched_fields?: string[];
  highlights: string[];
  navigation_target: string;
  metadata: Record<string, any>;
}

export interface SearchResponse {
  query: string;
  total: number;
  results: SearchResultItem[];
  grouped_counts: Record<string, number>;
  has_more: boolean;
  next_offset?: number;
  execution_time_ms: number;
}

export interface IndicatorOccurrenceItem {
  investigation_id: string;
  incident_number: string;
  title: string;
  severity: string;
  status: string;
  observed_at: string;
  source: string;
}

export interface CrossInvestigationIndicatorResponse {
  indicator_value: string;
  normalized_value: string;
  indicator_type: string;
  total_investigations: number;
  total_campaigns: number;
  total_evidence_objects: number;
  first_observed_at?: string;
  last_observed_at?: string;
  reputation?: string;
  current_observations: Array<Record<string, any>>;
  historical_memory?: Record<string, any>;
  external_intelligence?: Record<string, any>;
  analyst_verifications: Array<Record<string, any>>;
  related_investigations: IndicatorOccurrenceItem[];
  related_campaigns: Array<Record<string, any>>;
}

export interface SearchFacetsResponse {
  risk: Record<string, number>;
  severity: Record<string, number>;
  status: Record<string, number>;
  source_type: Record<string, number>;
  classification?: Record<string, number>;
  resource_types: Record<string, number>;
}

export type SearchFacets = SearchFacetsResponse;

export interface InvestigationListItem {
  id: string;
  investigation_number: string;
  title: string;
  description?: string;
  status: string;
  severity: string;
  risk_score: number;
  risk_level?: string;
  confidence: number;
  source_type: string;
  classification: string;
  findings_count: number;
  indicators_count: number;
  evidence_count: number;
  sample_indicators?: string[];
  sender?: string;
  affected_entities: string[];
  created_at: string;
  updated_at: string;
}

export interface InvestigationListResponse {
  total: number;
  limit: number;
  offset: number;
  page?: number;
  page_size?: number;
  total_pages?: number;
  has_more: boolean;
  items: InvestigationListItem[];
  facets: SearchFacetsResponse;
}
