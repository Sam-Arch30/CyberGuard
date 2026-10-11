export interface SharedIndicator {
  type: string;
  value: string;
  details?: string;
}

export interface MatchedSignalDetail {
  signal_name: string;
  weight: number;
  matched_values: string[];
  contribution: number;
}

export interface RelatedCaseItem {
  case_id: string;
  case_number: string;
  title: string;
  severity: 'low' | 'medium' | 'high' | 'critical' | string;
  status: 'open' | 'investigating' | 'resolved' | 'escalated' | string;
  correlation_score: number;
  relationship_label: string;
  shared_evidence_summary: string;
  shared_indicators: SharedIndicator[];
  matching_signals: Record<string, MatchedSignalDetail>;
}

export interface CorrelatedIngestedEmail {
  id: string;
  evidence_id: string;
  sha256?: string | null;
  original_filename?: string;
  subject: string;
  sender: string;
  recipient?: string | null;
  timestamp?: string;
  threat_score: number;
  severity: string;
  similarity_score: number;
  similarity_percentage: number;
  relationship_label: string;
  shared_evidence_summary: string;
  shared_indicators: SharedIndicator[];
  has_eml_file?: boolean;
}

export interface CampaignCorrelationResponse {
  related_cases: RelatedCaseItem[];
  correlation_score: number;
  relationship_label: string;
  shared_indicators: SharedIndicator[];
  correlated_emails?: CorrelatedIngestedEmail[];
}

// ============================================================================
// SECTION 61: CROSS-SOURCE CORRELATION & UNIFIED ENTITY CORRELATION
// ============================================================================

export type CorrelationType =
  | 'SHARED_INFRASTRUCTURE'
  | 'TEMPORAL_ATTACK_SEQUENCE'
  | 'AUTH_AND_ENDPOINT'
  | 'BEHAVIORAL_AND_RULE_DETECTION'
  | 'WATCHLIST_AND_OBSERVATION'
  | 'SAME_ENTITY'
  | 'SAME_INDICATOR'
  | 'SHARED_ARTIFACT'
  | 'API_AND_NETWORK';

export type CorrelationStatus =
  | 'CANDIDATE'
  | 'CORRELATING'
  | 'CORRELATED'
  | 'PARTIALLY_CORRELATED'
  | 'STALE'
  | 'INVALIDATED'
  | 'ARCHIVED';

export type CorrelationConfidence = 'LOW' | 'MEDIUM' | 'HIGH' | 'CERTAIN';

export type MemberType = 'ENTITY' | 'FINDING' | 'SIGNAL' | 'ALERT' | 'EVIDENCE' | 'INDICATOR';

export type SourceType =
  | 'EMAIL'
  | 'URL'
  | 'DOMAIN'
  | 'ENDPOINT'
  | 'AUTHENTICATION'
  | 'NETWORK'
  | 'API'
  | 'THREAT_INTEL'
  | 'BEHAVIORAL'
  | 'DETECTION_RULE'
  | 'WATCHLIST';

export type ResolutionMethod =
  | 'EXACT_INTERNAL_ID'
  | 'CANONICAL_EXTERNAL_ID'
  | 'CANONICAL_NORMALIZATION'
  | 'COMPOSITE_KEY'
  | 'FUZZY_MATCH'
  | 'UNRESOLVED';

export type ResolutionStatus = 'RESOLVED' | 'AMBIGUOUS' | 'UNRESOLVED';

export interface CrossSourceCorrelationItem {
  id: string;
  workspace_id: string;
  correlation_number: string;
  correlation_type: CorrelationType;
  title: string;
  description: string;
  status: CorrelationStatus;
  confidence_score: number;
  confidence_level: CorrelationConfidence;
  risk_score: number;
  risk_level: string;
  severity: string;
  first_observed_at: string;
  last_observed_at: string;
  time_window_seconds: number;
  parent_finding_id?: string | null;
  alert_id?: string | null;
  incident_id?: string | null;
  campaign_id?: string | null;
  explanation_summary?: string;
  member_count: number;
  sources: string[];
  entities: string[];
  analyst_disposition?: string | null;
  created_at: string;
  updated_at: string;
}

export interface CorrelationMemberItem {
  id: string;
  correlation_id: string;
  member_type: MemberType;
  member_id: string;
  source_type: SourceType;
  role: string;
  confidence_score: number;
  occurred_at?: string | null;
  metadata?: Record<string, any>;
  created_at: string;
}

export interface CorrelationTimelineItem {
  timestamp: string;
  source_type: SourceType;
  member_type: MemberType;
  member_id: string;
  description: string;
  role: string;
  time_from_start_seconds: number;
  metadata: Record<string, any>;
}

export interface WhyCorrelatedExplanation {
  correlation_id: string;
  correlation_number: string;
  correlation_type: CorrelationType;
  confidence_score: number;
  confidence_level: CorrelationConfidence;
  time_window_minutes: number;
  rule_version: string;
  supporting_reasons: string[];
  contradicting_evidence: string[];
  missing_telemetry_warnings: string[];
  entity_involvement: Array<{ entity_id: string; role: string; source: string }>;
  source_breakdown: Array<{ source_type: string; signal_count: number }>;
  risk_explanation: string;
  evidence_deduplication_summary: string;
}

export interface CrossSourceCorrelationDetail extends CrossSourceCorrelationItem {
  correlation_hash: string;
  rule_version: string;
  dispositioned_by?: string | null;
  dispositioned_at?: string | null;
  analyst_notes?: string | null;
  supporting_reasons: string[];
  contradicting_evidence: string[];
  missing_context: string[];
  evidence_refs: string[];
  members: CorrelationMemberItem[];
}

export interface CorrelationOverviewStats {
  total_correlations: number;
  active_correlations: number;
  high_confidence_count: number;
  candidate_count: number;
  invalidated_count: number;
  by_type: Record<string, number>;
  by_source: Record<string, number>;
  avg_time_window_minutes: number;
  recent_correlations: CrossSourceCorrelationItem[];
}

export interface EntityResolutionResult {
  entity_type: string;
  raw_identifier: string;
  normalized_identifier: string;
  canonical_entity_id?: string | null;
  resolution_method: ResolutionMethod;
  resolution_confidence: number;
  status: ResolutionStatus;
  matched_attributes: Record<string, any>;
  provenance: Record<string, any>;
  workspace_id: string;
  resolved_at: string;
}

export interface ResolutionHistoryItem {
  id: string;
  workspace_id: string;
  entity_type: string;
  canonical_entity_id: string;
  raw_identifier: string;
  normalized_identifier: string;
  resolution_method: string;
  resolution_confidence: number;
  status: string;
  matched_attributes: Record<string, any>;
  provenance: Record<string, any>;
  created_at: string;
}

export interface CorrelationDispositionPayload {
  disposition: 'CONFIRMED' | 'REJECTED' | 'UNCERTAIN';
  notes: string;
  actor: string;
}

export interface CorrelationEvaluatePayload {
  entity_id?: string;
  finding_id?: string;
  incident_id?: string;
  correlation_window_minutes?: number;
  workspace_id?: string;
}

export interface EntityResolvePayload {
  entity_type: string;
  raw_identifier: string;
  workspace_id?: string;
  context?: string;
  allow_fuzzy?: boolean;
}


