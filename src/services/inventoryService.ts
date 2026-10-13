import { apiFetch } from '../utils/apiClient';
/**
 * Section 63: Asset & Identity Inventory API Client Service.
 */

import type {
  InventoryAsset,
  InventoryAssetDetail,
  InventoryIdentity,
  InventoryIdentityDetail,
  InventorySource,
  InventoryConflict,
  InventoryOverviewStats,
  InventorySyncResponse,
  InventoryReconciliationReport,
} from '../types/inventory';

const BASE_URL = '/api/v1/inventory';

export class InventoryService {
  /**
   * Fetches overall inventory KPI metrics and health statistics.
   */
  static async getOverviewStats(): Promise<InventoryOverviewStats> {
    const res = await apiFetch(`${BASE_URL}/overview`);
    if (!res.ok) {
      throw new Error(`Failed to fetch inventory overview stats: ${res.statusText}`);
    }
    return res.json();
  }

  /**
   * Fetches paginated, filtered assets.
   */
  static async listAssets(params?: {
    asset_type?: string;
    status?: string;
    environment?: string;
    criticality?: string;
    ownership_status?: string;
    is_managed?: boolean;
    is_stale?: boolean;
    search?: string;
    skip?: number;
    limit?: number;
  }): Promise<{ items: InventoryAsset[]; total: number; skip: number; limit: number }> {
    const query = new URLSearchParams();
    if (params?.asset_type && params.asset_type !== 'ALL') query.set('asset_type', params.asset_type);
    if (params?.status && params.status !== 'ALL') query.set('status', params.status);
    if (params?.environment && params.environment !== 'ALL') query.set('environment', params.environment);
    if (params?.criticality && params.criticality !== 'ALL') query.set('criticality', params.criticality);
    if (params?.ownership_status && params.ownership_status !== 'ALL') query.set('ownership_status', params.ownership_status);
    if (params?.is_managed !== undefined) query.set('is_managed', String(params.is_managed));
    if (params?.is_stale !== undefined) query.set('is_stale', String(params.is_stale));
    if (params?.search) query.set('search', params.search);
    if (params?.skip !== undefined) query.set('skip', String(params.skip));
    if (params?.limit !== undefined) query.set('limit', String(params.limit));

    const res = await apiFetch(`${BASE_URL}/assets?${query.toString()}`);
    if (!res.ok) {
      throw new Error(`Failed to list inventory assets: ${res.statusText}`);
    }
    return res.json();
  }

  /**
   * Fetches full progressive disclosure details for a specific asset.
   */
  static async getAssetDetail(id: string): Promise<InventoryAssetDetail> {
    const res = await apiFetch(`${BASE_URL}/assets/${id}`);
    if (!res.ok) {
      throw new Error(`Failed to fetch asset detail for ${id}: ${res.statusText}`);
    }
    return res.json();
  }

  /**
   * Updates an asset's classification, criticality, or environment.
   */
  static async updateAsset(id: string, payload: Partial<InventoryAsset>): Promise<InventoryAsset> {
    const res = await apiFetch(`${BASE_URL}/assets/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      throw new Error(`Failed to update asset ${id}: ${res.statusText}`);
    }
    return res.json();
  }

  /**
   * Assigns asset owner with recorded analyst audit justification.
   */
  static async assignAssetOwner(
    id: string,
    payload: { owner: string; team?: string; department?: string; business_unit?: string; reason?: string }
  ): Promise<InventoryAsset> {
    const res = await apiFetch(`${BASE_URL}/assets/${id}/assign-owner`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      throw new Error(`Failed to assign owner for asset ${id}: ${res.statusText}`);
    }
    return res.json();
  }

  /**
   * Fetches paginated, filtered identities and accounts.
   */
  static async listIdentities(params?: {
    identity_type?: string;
    status?: string;
    is_privileged?: boolean;
    is_service_account?: boolean;
    is_orphaned?: boolean;
    is_dormant?: boolean;
    criticality?: string;
    search?: string;
    skip?: number;
    limit?: number;
  }): Promise<{ items: InventoryIdentity[]; total: number; skip: number; limit: number }> {
    const query = new URLSearchParams();
    if (params?.identity_type && params.identity_type !== 'ALL') query.set('identity_type', params.identity_type);
    if (params?.status && params.status !== 'ALL') query.set('status', params.status);
    if (params?.is_privileged !== undefined) query.set('is_privileged', String(params.is_privileged));
    if (params?.is_service_account !== undefined) query.set('is_service_account', String(params.is_service_account));
    if (params?.is_orphaned !== undefined) query.set('is_orphaned', String(params.is_orphaned));
    if (params?.is_dormant !== undefined) query.set('is_dormant', String(params.is_dormant));
    if (params?.criticality && params.criticality !== 'ALL') query.set('criticality', params.criticality);
    if (params?.search) query.set('search', params.search);
    if (params?.skip !== undefined) query.set('skip', String(params.skip));
    if (params?.limit !== undefined) query.set('limit', String(params.limit));

    const res = await apiFetch(`${BASE_URL}/identities?${query.toString()}`);
    if (!res.ok) {
      throw new Error(`Failed to list inventory identities: ${res.statusText}`);
    }
    return res.json();
  }

  /**
   * Fetches full progressive disclosure details for an identity.
   */
  static async getIdentityDetail(id: string): Promise<InventoryIdentityDetail> {
    const res = await apiFetch(`${BASE_URL}/identities/${id}`);
    if (!res.ok) {
      throw new Error(`Failed to fetch identity detail for ${id}: ${res.statusText}`);
    }
    return res.json();
  }

  /**
   * Lists registered authoritative sources.
   */
  static async listSources(): Promise<InventorySource[]> {
    const res = await apiFetch(`${BASE_URL}/sources`);
    if (!res.ok) {
      throw new Error(`Failed to list inventory sources: ${res.statusText}`);
    }
    return res.json();
  }

  /**
   * Creates an inventory source.
   */
  static async createSource(payload: {
    source_type: string;
    name: string;
    authority_weight: number;
    sync_interval_seconds?: number;
    capabilities?: string[];
  }): Promise<InventorySource> {
    const res = await apiFetch(`${BASE_URL}/sources`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      throw new Error(`Failed to create inventory source: ${res.statusText}`);
    }
    return res.json();
  }

  /**
   * Deletes an inventory source.
   */
  static async deleteSource(id: string): Promise<void> {
    const res = await apiFetch(`${BASE_URL}/sources/${id}`, {
      method: 'DELETE',
    });
    if (!res.ok) {
      throw new Error(`Failed to delete inventory source ${id}: ${res.statusText}`);
    }
  }

  /**
   * Lists attribute conflicts across sources.
   */
  static async listConflicts(params?: {
    status?: string;
    target_type?: string;
    skip?: number;
    limit?: number;
  }): Promise<{ items: InventoryConflict[]; total: number; skip: number; limit: number }> {
    const query = new URLSearchParams();
    if (params?.status && params.status !== 'ALL') query.set('status', params.status);
    if (params?.target_type && params.target_type !== 'ALL') query.set('target_type', params.target_type);
    if (params?.skip !== undefined) query.set('skip', String(params.skip));
    if (params?.limit !== undefined) query.set('limit', String(params.limit));

    const res = await apiFetch(`${BASE_URL}/conflicts?${query.toString()}`);
    if (!res.ok) {
      throw new Error(`Failed to list inventory conflicts: ${res.statusText}`);
    }
    return res.json();
  }

  /**
   * Resolves a source conflict with justification.
   */
  static async resolveConflict(
    id: string,
    payload: { selected_value: string; selected_source?: string; resolution_reason: string }
  ): Promise<InventoryConflict> {
    const res = await apiFetch(`${BASE_URL}/conflicts/${id}/resolve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      throw new Error(`Failed to resolve conflict ${id}: ${res.statusText}`);
    }
    return res.json();
  }

  /**
   * Runs an on-demand inventory synchronization.
   */
  static async runSync(params?: {
    sync_endpoints?: boolean;
    sync_identities?: boolean;
    sync_telemetry?: boolean;
  }): Promise<InventorySyncResponse> {
    const res = await apiFetch(`${BASE_URL}/sync`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(params || {}),
    });
    if (!res.ok) {
      throw new Error(`Failed to run inventory sync: ${res.statusText}`);
    }
    return res.json();
  }

  /**
   * Runs an on-demand full reconciliation sweep.
   */
  static async runReconciliation(): Promise<InventoryReconciliationReport> {
    const res = await apiFetch(`${BASE_URL}/reconcile`, {
      method: 'POST',
    });
    if (!res.ok) {
      throw new Error(`Failed to run inventory reconciliation: ${res.statusText}`);
    }
    return res.json();
  }
}
