/**
 * Section 65: Threat Actor & Campaign Workspace TypeScript Types.
 */

export type AttributionState =
  | 'UNKNOWN'
  | 'SUSPECTED'
  | 'POSSIBLE'
  | 'PROBABLE'
  | 'ASSESSED'
  | 'CONFIRMED'
  | 'DISPUTED'
  | 'REJECTED';

export type SemanticClassification =
  | 'OBSERVED'
  | 'CORRELATED'
  | 'INFERRED'
  | 'HYPOTHESIZED'
  | 'ASSESSED'
  | 'EXTERNAL_INTELLIGENCE'
  | 'ANALYST_ASSERTED';

export type CampaignLifecycle =
  | 'CANDIDATE'
  | 'OPEN'
  | 'ACTIVE'
  | 'MONITORING'
  | 'CONTAINED'
  | 'INACTIVE'
  | 'CLOSED'
  | 'ARCHIVED';

export type CampaignActivity = 'ACTIVE' | 'QUIET' | 'STALE' | 'UNKNOWN';

export type HypothesisStatus = 'OPEN' | 'SUPPORTED' | 'WEAKENED' | 'REJECTED' | 'CONFIRMED';

export type ActorType =
  | 'NATION_STATE'
  | 'CYBERCRIME'
  | 'HACKTIVIST'
  | 'INSIDER'
  | 'OPPORTUNISTIC'
  | 'UNKNOWN';

export interface EvidenceItem {
  id: string;
  evidence_type: string;
  description: string;
  semantic_class: SemanticClassification;
  observed_at?: string;
  source: string;
  confidence: number;
  is_contradicting: boolean;
  raw_reference?: string;
}

export interface ActorAlias {
  alias: string;
  source: string;
  source_record_id?: string;
  observed_at?: string;
  confidence: number;
}

export interface AnalystNote {
  id: string;
  author: string;
  timestamp: string;
  content: string;
  scope: string;
}

export interface SourceConflict {
  id: string;
  provider_a: string;
  claim_a: string;
  provider_b: string;
  claim_b: string;
  subject: string;
  status: string;
  analyst_note?: string;
}

export interface ThreatActor {
  id: string;
  actor_id: string;
  workspace_id: string;
  name: string;
  canonical_name: string;
  actor_type: ActorType;
  status: string;
  attribution_state: AttributionState;
  attribution_confidence: number;
  motivation?: string;
  sophistication: string;
  description?: string;
  first_observed_at?: string;
  last_observed_at?: string;
  aliases: ActorAlias[];
  primary_targets: string[];
  observed_techniques: string[];
  observed_infrastructure: string[];
  supporting_evidence: EvidenceItem[];
  contradicting_evidence: EvidenceItem[];
  associated_campaigns_count: number;
  affected_assets_count: number;
  open_incidents_count: number;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface ThreatActorListResponse {
  items: ThreatActor[];
  total: number;
  page: number;
  page_size: number;
}

export interface AffectedAssetRef {
  asset_id: string;
  name: string;
  asset_type: string;
  priority_band: string;
  business_criticality: string;
  risk_score: number;
  active_incidents: number;
}

export interface AffectedIdentityRef {
  identity_id: string;
  email: string;
  display_name?: string;
  state: 'OBSERVED' | 'TARGETED' | 'SUSPICIOUS' | 'COMPROMISED' | 'UNKNOWN';
  is_privileged: boolean;
  observation_count: number;
}

export interface CampaignWorkspaceDetail {
  id: string;
  campaign_id: string;
  workspace_id: string;
  name: string;
  description?: string;
  lifecycle_status: CampaignLifecycle;
  activity_state: CampaignActivity;
  watch_state: string;
  attribution_state: AttributionState;
  attribution_confidence: number;
  threat_actor?: ThreatActor;
  overall_confidence: number;
  first_seen: string;
  last_seen: string;
  dominant_attack_type: string;
  targeted_brands: string[];
  email_count: number;
  recipient_count: number;
  domain_count: number;
  ip_count: number;
  asn_count: number;
  supporting_evidence: EvidenceItem[];
  contradicting_evidence: EvidenceItem[];
  mitre_techniques: string[];
  affected_assets: AffectedAssetRef[];
  affected_identities: AffectedIdentityRef[];
  related_alerts: string[];
  related_incidents: string[];
  source_conflicts: SourceConflict[];
  hypotheses_count: number;
  analyst_notes: AnalystNote[];
  provenance_history: Array<Record<string, any>>;
  correlation_summary?: string;
  created_at: string;
  updated_at: string;
}

export interface CampaignListWorkspaceResponse {
  items: CampaignWorkspaceDetail[];
  total: number;
  page: number;
  page_size: number;
}

export interface CandidateReviewRequest {
  action: 'PROMOTE' | 'MERGE' | 'REJECT' | 'REVIEW';
  name?: string;
  target_campaign_id?: string;
  threat_actor_id?: string;
  reason: string;
}

export interface CampaignMergePreviewResponse {
  source_campaign_id: string;
  source_name: string;
  target_campaign_id: string;
  target_name: string;
  source_indicators_count: number;
  source_assets_count: number;
  source_incidents_count: number;
  conflicting_sources: SourceConflict[];
  is_safe: boolean;
  warning_message?: string;
}

export interface AttributionAssessmentResponse {
  id: string;
  workspace_id: string;
  subject_type: string;
  subject_id: string;
  target_type: string;
  target_id?: string;
  prior_attribution_state: string;
  new_attribution_state: string;
  confidence: number;
  justification: string;
  supporting_evidence: EvidenceItem[];
  contradicting_evidence: EvidenceItem[];
  external_conflicts: SourceConflict[];
  assessed_by: string;
  assessed_at: string;
}

export interface Hypothesis {
  id: string;
  workspace_id: string;
  subject_type: string;
  subject_id: string;
  title: string;
  hypothesis_text: string;
  status: HypothesisStatus;
  confidence: number;
  supporting_evidence: EvidenceItem[];
  contradicting_evidence: EvidenceItem[];
  created_by: string;
  updated_by: string;
  created_at: string;
  updated_at: string;
}

export interface CampaignTimelineEvent {
  timestamp: string;
  event_type: string;
  title: string;
  description: string;
  semantic_class: SemanticClassification;
  source: string;
  raw_reference_id?: string;
}

export interface ThreatHuntHandoff {
  campaign_id: string;
  campaign_name: string;
  suggested_queries: Array<{
    title: string;
    target_data_source: string;
    query_string: string;
  }>;
  hunt_indicators: string[];
}

export interface DetectionHandoff {
  campaign_id: string;
  campaign_name: string;
  recommended_rule_title: string;
  recommended_rule_description: string;
  indicators_to_match: string[];
  attack_techniques: string[];
  suggested_severity: string;
}
