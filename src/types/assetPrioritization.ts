/**
 * Section 64: Risk-Based Asset Prioritization TypeScript Definitions.
 * Types for priority bands, factor contributions, structured explanations,
 * policies, overrides, history, and top prioritized assets.
 */

export type PriorityBand = 'P1' | 'P2' | 'P3' | 'P4' | 'UNPRIORITIZED';

export type PriorityDataQuality = 'GOOD' | 'DEGRADED' | 'STALE' | 'UNKNOWN';

export type PolicyStatus = 'ACTIVE' | 'DRAFT' | 'DISABLED' | 'ARCHIVED';

export type ContributionLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NEGLIGIBLE';

export interface PrioritizationFactorContribution {
  factor: string;
  label: string;
  value: any;
  points: number;
  weight: number;
  weighted_points: number;
  source: string;
  contribution_level: ContributionLevel;
  description: string;
}

export interface PriorityDataQualityReport {
  status: PriorityDataQuality;
  issues: string[];
  stale_sources: string[];
  uncertain_sources: string[];
}

export interface PriorityExplanation {
  asset_id: string;
  canonical_name: string;
  display_name: string;
  asset_type: string;
  priority_band: PriorityBand;
  priority_score: number;
  effective_priority: PriorityBand;
  is_overridden: boolean;
  override_priority?: PriorityBand | null;
  override_reason?: string | null;
  override_by?: string | null;
  override_at?: string | null;
  override_expires_at?: string | null;
  contributors: PrioritizationFactorContribution[];
  data_quality: PriorityDataQualityReport;
  policy_id?: string | null;
  policy_name?: string | null;
  policy_version: number;
  calculated_at?: string | null;
}

export interface PrioritizedAssetItem {
  id: string;
  asset_type: string;
  canonical_name: string;
  display_name: string;
  priority_band: PriorityBand;
  priority_score: number;
  effective_priority: PriorityBand;
  is_overridden: boolean;
  override_priority?: PriorityBand | null;
  override_reason?: string | null;
  risk_score: number;
  risk_level: string;
  criticality: string;
  exposure_state: string;
  environment: string;
  owner?: string | null;
  team?: string | null;
  department?: string | null;
  is_managed: boolean;
  is_stale: boolean;
  active_incident_count: number;
  priority_data_quality: PriorityDataQuality;
  priority_calculated_at?: string | null;
  last_seen_at: string;
}

export interface PrioritizedAssetListResponse {
  items: PrioritizedAssetItem[];
  total: number;
  p1_count: number;
  p2_count: number;
  p3_count: number;
  p4_count: number;
  unprioritized_count: number;
  overridden_count: number;
  limit: number;
  offset: number;
}

export interface PriorityHistoryItem {
  id: string;
  asset_id: string;
  priority_band: PriorityBand;
  priority_score: number;
  previous_priority_band?: PriorityBand | null;
  transition_type: string;
  transition_reason?: string | null;
  is_override: boolean;
  override_priority?: PriorityBand | null;
  override_reason?: string | null;
  override_by?: string | null;
  risk_score: number;
  business_criticality: string;
  exposure_state: string;
  data_quality: string;
  policy_version: number;
  calculated_at: string;
}

export interface PriorityHistoryResponse {
  items: PriorityHistoryItem[];
  total: number;
}

export interface PriorityOverrideRequest {
  priority: PriorityBand;
  reason: string;
  expires_in_hours?: number;
}

export interface PriorityPolicy {
  id: string;
  name: string;
  description?: string | null;
  version: number;
  status: PolicyStatus;
  configuration: Record<string, any>;
  created_by: string;
  activated_at?: string | null;
  created_at: string;
  updated_at: string;
}

export interface PrioritizedAssetSummary {
  id: string;
  canonical_name: string;
  display_name: string;
  asset_type: string;
  effective_priority: PriorityBand;
  priority_score: number;
  risk_score: number;
  criticality: string;
  exposure_state: string;
  primary_reason: string;
  owner?: string | null;
  active_incidents: number;
}

export interface PrioritizationOverviewResponse {
  top_assets: PrioritizedAssetSummary[];
  total_assets: number;
  distribution: {
    p1_count: number;
    p2_count: number;
    p3_count: number;
    p4_count: number;
    unprioritized_count: number;
    overridden_count: number;
  };
  active_policy: {
    id: string;
    name: string;
    version: number;
  };
}
