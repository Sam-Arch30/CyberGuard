/**
 * Section 63: Asset & Identity Inventory TypeScript Definitions.
 * Authoritative types for assets, identities, source precedence, conflicts, and reconciliation.
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
  | 'DATABASE'
  | 'CERTIFICATE'
  | 'CLOUD_RESOURCE'
  | 'NETWORK_DEVICE';

export type IdentityType =
  | 'USER'
  | 'ACCOUNT'
  | 'SERVICE_ACCOUNT'
  | 'APPLICATION_IDENTITY'
  | 'API_CLIENT';

export type AssetStatus = 'ACTIVE' | 'INACTIVE' | 'STALE' | 'RETIRED' | 'UNKNOWN' | 'DISCOVERED';

export type IdentityStatus = 'ACTIVE' | 'INACTIVE' | 'DORMANT' | 'SUSPENDED' | 'RETIRED' | 'UNKNOWN';

export type OwnershipStatus = 'ASSIGNED' | 'UNASSIGNED' | 'UNKNOWN' | 'CONFLICTED' | 'INFERRED';

export type Criticality = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';

export type Environment =
  | 'PRODUCTION'
  | 'STAGING'
  | 'DEVELOPMENT'
  | 'CORP'
  | 'LAB'
  | 'TEST'
  | 'PERSONAL'
  | 'UNKNOWN';

export type ConflictStatus = 'AUTO_RESOLVED' | 'PENDING_REVIEW' | 'MANUALLY_RESOLVED' | 'IGNORED';

export interface InventoryAsset {
  id: string;
  workspace_id: string;
  asset_type: AssetType;
  canonical_name: string;
  display_name: string;
  status: AssetStatus;
  exposure_state: string;
  criticality: Criticality;
  owner?: string | null;
  team?: string | null;
  business_unit?: string | null;
  department?: string | null;
  ownership_status: OwnershipStatus;
  classification?: string | null;
  environment: Environment;
  ownership_confidence: string;
  source: string;
  external_id?: string | null;
  canonical_entity_id?: string | null;
  risk_score: number;
  risk_level: string;
  active_finding_count: number;
  active_exposure_count: number;
  is_managed: boolean;
  is_stale: boolean;
  priority_band?: 'P1' | 'P2' | 'P3' | 'P4' | 'UNPRIORITIZED';
  priority_score?: number;
  effective_priority?: 'P1' | 'P2' | 'P3' | 'P4' | 'UNPRIORITIZED';
  is_overridden?: boolean;
  priority_override?: string | null;
  priority_override_reason?: string | null;
  priority_override_by?: string | null;
  priority_override_expires_at?: string | null;
  priority_data_quality?: 'GOOD' | 'DEGRADED' | 'STALE' | 'UNKNOWN';
  priority_calculated_at?: string | null;
  tags: string[];
  first_seen_at: string;
  last_seen_at: string;
  last_observed_at?: string | null;
  last_sync_at?: string | null;
  created_at: string;
  updated_at: string;
  metadata?: Record<string, any>;
}

export interface InventoryAssetDetail extends InventoryAsset {
  exposures: Array<{
    id: string;
    exposure_type: string;
    severity: string;
    status: string;
    remediation_guidance?: string;
    first_detected_at?: string;
  }>;
  services: Array<{
    id: string;
    service_name: string;
    port: number;
    protocol: string;
    is_public: boolean;
    banner?: string;
  }>;
  conflicts: Array<{
    id: string;
    field_name: string;
    status: ConflictStatus;
    resolved_value?: string;
    conflicting_values: Array<{
      source: string;
      value: string;
      authority_weight: number;
      observed_at: string;
    }>;
    resolution_reason?: string;
  }>;
  graph_neighbors: Array<{
    id: string;
    type: string;
    name: string;
    canonical_key: string;
  }>;
  timeline: Array<{
    event_type: string;
    title: string;
    timestamp?: string;
    description: string;
  }>;
}

export interface InventoryIdentity {
  id: string;
  workspace_id: string;
  identity_type: IdentityType;
  canonical_identifier: string;
  display_name: string;
  email?: string | null;
  username?: string | null;
  department?: string | null;
  team?: string | null;
  business_unit?: string | null;
  manager?: string | null;
  status: IdentityStatus;
  criticality: Criticality;
  is_privileged: boolean;
  is_service_account: boolean;
  is_orphaned: boolean;
  is_dormant: boolean;
  source: string;
  external_id?: string | null;
  canonical_entity_id?: string | null;
  risk_score: number;
  risk_level: string;
  tags: string[];
  first_seen_at: string;
  last_seen_at: string;
  last_authenticated_at?: string | null;
  last_sync_at?: string | null;
  created_at: string;
  updated_at: string;
  metadata?: Record<string, any>;
}

export interface InventoryIdentityDetail extends InventoryIdentity {
  associated_assets: Array<{
    id: string;
    canonical_name: string;
    display_name: string;
    asset_type: AssetType;
    criticality: Criticality;
    status: AssetStatus;
  }>;
  conflicts: Array<{
    id: string;
    field_name: string;
    status: ConflictStatus;
    resolved_value?: string;
    conflicting_values: Array<{
      source: string;
      value: string;
      authority_weight: number;
      observed_at: string;
    }>;
    resolution_reason?: string;
  }>;
  graph_neighbors: Array<{
    id: string;
    type: string;
    name: string;
    canonical_key: string;
  }>;
  timeline: Array<{
    event_type: string;
    title: string;
    timestamp?: string;
    description: string;
  }>;
}

export interface InventorySource {
  id: string;
  workspace_id: string;
  source_type: string;
  name: string;
  status: string;
  authority_weight: number;
  sync_interval_seconds: number;
  last_sync_at?: string | null;
  last_sync_status?: string | null;
  last_sync_record_count: number;
  health_status: string;
  capabilities: string[];
  created_at: string;
  updated_at: string;
}

export interface InventoryConflict {
  id: string;
  workspace_id: string;
  target_type: 'ASSET' | 'IDENTITY';
  target_id: string;
  target_canonical_name: string;
  field_name: string;
  conflicting_values: Array<{
    source: string;
    source_id?: string;
    value: string;
    authority_weight: number;
    observed_at: string;
  }>;
  resolved_value?: string | null;
  resolved_source?: string | null;
  resolution_reason?: string | null;
  status: ConflictStatus;
  resolved_by?: string | null;
  resolved_at?: string | null;
  created_at: string;
  updated_at: string;
}

export interface InventoryOverviewStats {
  total_assets: number;
  active_assets: number;
  stale_assets: number;
  unmanaged_assets: number;
  unowned_assets: number;
  total_identities: number;
  active_identities: number;
  privileged_identities: number;
  dormant_identities: number;
  orphaned_identities: number;
  pending_conflicts: number;
  active_sources: number;
  last_reconciliation_at?: string | null;
}

export interface InventorySyncResponse {
  assets_synced: number;
  identities_synced: number;
  conflicts_detected: number;
  sync_duration_ms: number;
  status: string;
  message: string;
}

export interface InventoryReconciliationReport {
  timestamp: string;
  stale_assets_flagged: number;
  unmanaged_endpoints_flagged: number;
  unowned_assets_flagged: number;
  dormant_identities_flagged: number;
  orphaned_accounts_flagged: number;
  conflicts_auto_resolved: number;
  conflicts_pending_review: number;
  total_records_processed: number;
  reconciliation_duration_ms: number;
}
