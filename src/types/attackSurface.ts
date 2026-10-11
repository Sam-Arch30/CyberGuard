/**
 * Section 62: Attack Surface Intelligence TypeScript Definitions.
 */

export type AssetType =
  | 'DOMAIN'
  | 'SUBDOMAIN'
  | 'PUBLIC_IP'
  | 'PRIVATE_IP'
  | 'ENDPOINT'
  | 'SERVER'
  | 'DEVICE'
  | 'APPLICATION'
  | 'WEB_APPLICATION'
  | 'API'
  | 'SERVICE'
  | 'CERTIFICATE'
  | 'CLOUD_RESOURCE'
  | 'EMAIL_INFRASTRUCTURE'
  | 'IDENTITY'
  | 'USER_ACCOUNT'
  | 'SERVICE_ACCOUNT';

export type AssetStatus = 'DISCOVERED' | 'ACTIVE' | 'INACTIVE' | 'STALE' | 'RETIRED' | 'UNKNOWN';

export type ExposureState = 'PUBLICLY_EXPOSED' | 'INTERNALLY_REACHABLE' | 'INTERNALLY_ONLY' | 'UNKNOWN';

export type Criticality = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';

export type OwnershipConfidence =
  | 'MANUAL'
  | 'CMDB'
  | 'DIRECTORY'
  | 'ENDPOINT_AGENT'
  | 'CLOUD_INVENTORY'
  | 'DOMAIN_MAPPING'
  | 'INFERENCE'
  | 'UNKNOWN';

export type AssetSource =
  | 'ENDPOINT_AGENT'
  | 'EMAIL_ANALYSIS'
  | 'URL_ANALYSIS'
  | 'DOMAIN_ANALYSIS'
  | 'NETWORK_TELEMETRY'
  | 'API_TELEMETRY'
  | 'AUTHENTICATION'
  | 'THREAT_INTELLIGENCE'
  | 'WATCHLIST'
  | 'INVESTIGATION'
  | 'THREAT_HUNT'
  | 'MANUAL_ANALYST'
  | 'EXTERNAL_DISCOVERY'
  | 'INTERNAL_DISCOVERY';

export type ExposureType =
  | 'PUBLIC_ASSET'
  | 'UNKNOWN_ASSET'
  | 'UNKNOWN_SERVICE'
  | 'EXPOSED_API'
  | 'EXPOSED_IDENTITY'
  | 'STALE_ASSET'
  | 'UNMAPPED_DOMAIN'
  | 'UNEXPECTED_ENDPOINT'
  | 'UNAPPROVED_PORT'
  | 'CERTIFICATE_EXPIRING';

export type ExposureStatus = 'OPEN' | 'RESOLVED' | 'ACCEPTED' | 'SUPPRESSED' | 'STALE' | 'UNKNOWN';

export type ExposureSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type ScopeType = 'DOMAIN' | 'CIDR' | 'IP' | 'CLOUD_ACCOUNT' | 'ASN';

export interface Asset {
  id: string;
  workspace_id: string;
  asset_type: AssetType;
  canonical_name: string;
  display_name: string;
  status: AssetStatus;
  exposure_state: ExposureState;
  criticality: Criticality;
  owner?: string | null;
  team?: string | null;
  business_unit?: string | null;
  environment: string;
  ownership_confidence: OwnershipConfidence;
  source: AssetSource;
  external_id?: string | null;
  canonical_entity_id?: string | null;
  risk_score: number;
  risk_level: string;
  active_finding_count: number;
  active_exposure_count: number;
  first_seen_at: string;
  last_seen_at: string;
  last_scanned_at?: string | null;
  last_analyzed_at?: string | null;
  metadata: Record<string, any>;
  created_at: string;
  updated_at: string;
}

export interface Exposure {
  id: string;
  workspace_id: string;
  asset_id: string;
  exposure_type: ExposureType;
  title: string;
  description: string;
  status: ExposureStatus;
  severity: ExposureSeverity;
  confidence: number;
  remediation_guidance?: string | null;
  evidence_refs: string[];
  source_refs: string[];
  risk_context: Record<string, any>;
  first_seen_at: string;
  last_seen_at: string;
  resolved_at?: string | null;
  resolved_by?: string | null;
  resolution_notes?: string | null;
  created_at: string;
  updated_at: string;
}

export interface AssetService {
  id: string;
  workspace_id: string;
  asset_id: string;
  port?: number | null;
  protocol: string;
  service_name: string;
  service_version?: string | null;
  transport: string;
  exposure: string;
  source: string;
  banner_snippet?: string | null;
  metadata: Record<string, any>;
  first_seen_at: string;
  last_seen_at: string;
  created_at: string;
}

export interface AssetDetail extends Asset {
  exposures: Exposure[];
  services: AssetService[];
  related_findings: Record<string, any>[];
  related_correlations: Record<string, any>[];
  threat_intelligence?: Record<string, any> | null;
  graph_neighbors: {
    relationship_type: string;
    source_type: string;
    source_id: string;
    target_type: string;
    target_id: string;
    confidence: number;
  }[];
}

export interface AttackSurfaceScope {
  id: string;
  workspace_id: string;
  scope_type: ScopeType;
  target: string;
  is_authorized: boolean;
  description: string;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface AttackSurfaceOverviewStats {
  total_assets: number;
  publicly_exposed_assets: number;
  internally_reachable_assets: number;
  unknown_assets_count: number;
  critical_assets_count: number;
  high_risk_assets_count: number;
  open_exposures_count: number;
  critical_exposures_count: number;
  by_type: Record<string, number>;
  by_exposure: Record<string, number>;
  by_criticality: Record<string, number>;
  authorized_scopes_count: number;
  recent_exposures: Exposure[];
}

export interface AttackSurfaceDiffResponse {
  snapshot_name: string;
  previous_snapshot_time?: string | null;
  current_snapshot_time: string;
  assets_added: number;
  assets_removed: number;
  exposures_added: number;
  exposures_resolved: number;
  added_asset_names: string[];
  removed_asset_names: string[];
  new_exposure_titles: string[];
  diff_summary: Record<string, any>;
}

export interface UnknownAssetQueueItem {
  id: string;
  asset_type: AssetType;
  canonical_name: string;
  display_name: string;
  exposure_state: ExposureState;
  criticality: Criticality;
  risk_score: number;
  risk_level: string;
  source: AssetSource;
  first_seen_at?: string | null;
  last_seen_at?: string | null;
  reason: string;
  active_finding_count: number;
  active_exposure_count: number;
}

export interface UnknownAssetReviewRequest {
  action: 'APPROVE' | 'ASSIGN_OWNER' | 'MAP_TO_EXISTING' | 'MARK_UNAUTHORIZED' | 'ADD_TO_WATCHLIST';
  owner?: string;
  team?: string;
  criticality?: Criticality;
  target_asset_id?: string;
  notes: string;
  actor: string;
}

export interface AttackSurfaceScopeCreateRequest {
  scope_type: ScopeType;
  target: string;
  is_authorized?: boolean;
  description?: string;
}

export interface AttackSurfaceDiscoveryRequest {
  sync_from_endpoints?: boolean;
  sync_from_identities?: boolean;
  sync_from_telemetry?: boolean;
  resolve_dns_records?: boolean;
  scope_filter?: string;
}

export interface AttackSurfaceDiscoveryResponse {
  status: string;
  assets_discovered: number;
  assets_updated: number;
  unknown_assets_flagged: number;
  exposures_created: number;
  scopes_evaluated: number;
  duration_ms: number;
  message: string;
}

export interface AssetTimelineItem {
  timestamp: string;
  event_type: string;
  title: string;
  description: string;
  severity: string;
}
