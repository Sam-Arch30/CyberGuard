/**
 * Section 64: Risk-Based Asset Prioritization REST Client Service.
 * Provides client methods for prioritized asset listings, structured explanations,
 * manual analyst overrides, history timelines, policies, and overview stats.
 */

import type {
  PrioritizedAssetItem,
  PrioritizedAssetListResponse,
  PriorityExplanation,
  PriorityHistoryResponse,
  PriorityOverrideRequest,
  PriorityPolicy,
  PrioritizationOverviewResponse,
  PriorityBand,
} from '../types/assetPrioritization';

const BASE_URL = '/api/v1/prioritization';

export class AssetPrioritizationService {
  private static getHeaders(): HeadersInit {
    return {
      'Content-Type': 'application/json',
      'X-Workspace-Id': localStorage.getItem('cyberguard_workspace_id') || 'default',
      'X-Role': localStorage.getItem('cyberguard_user_role') || 'analyst',
    };
  }

  static async listPrioritizedAssets(params?: {
    priority_band?: string;
    min_priority?: string;
    criticality?: string;
    exposure_state?: string;
    environment?: string;
    search?: string;
    is_overridden?: boolean;
    sort_by?: string;
    sort_desc?: boolean;
    limit?: number;
    offset?: number;
  }): Promise<PrioritizedAssetListResponse> {
    const searchParams = new URLSearchParams();
    if (params) {
      if (params.priority_band) searchParams.append('priority_band', params.priority_band);
      if (params.min_priority) searchParams.append('min_priority', params.min_priority);
      if (params.criticality) searchParams.append('criticality', params.criticality);
      if (params.exposure_state) searchParams.append('exposure_state', params.exposure_state);
      if (params.environment) searchParams.append('environment', params.environment);
      if (params.search) searchParams.append('search', params.search);
      if (params.is_overridden !== undefined) searchParams.append('is_overridden', String(params.is_overridden));
      if (params.sort_by) searchParams.append('sort_by', params.sort_by);
      if (params.sort_desc !== undefined) searchParams.append('sort_desc', String(params.sort_desc));
      if (params.limit) searchParams.append('limit', String(params.limit));
      if (params.offset !== undefined) searchParams.append('offset', String(params.offset));
    }

    const res = await fetch(`${BASE_URL}/assets?${searchParams.toString()}`, {
      headers: this.getHeaders(),
    });
    if (!res.ok) throw new Error(`Failed to list prioritized assets: ${res.statusText}`);
    return res.json();
  }

  static async getPrioritizedAsset(assetId: string): Promise<PrioritizedAssetItem> {
    const res = await fetch(`${BASE_URL}/assets/${assetId}`, {
      headers: this.getHeaders(),
    });
    if (!res.ok) throw new Error(`Failed to get prioritized asset: ${res.statusText}`);
    return res.json();
  }

  static async getPriorityExplanation(assetId: string): Promise<PriorityExplanation> {
    const res = await fetch(`${BASE_URL}/assets/${assetId}/explanation`, {
      headers: this.getHeaders(),
    });
    if (!res.ok) throw new Error(`Failed to get priority explanation: ${res.statusText}`);
    return res.json();
  }

  static async getPriorityHistory(assetId: string, limit = 20): Promise<PriorityHistoryResponse> {
    const res = await fetch(`${BASE_URL}/assets/${assetId}/history?limit=${limit}`, {
      headers: this.getHeaders(),
    });
    if (!res.ok) throw new Error(`Failed to get priority history: ${res.statusText}`);
    return res.json();
  }

  static async applyOverride(
    assetId: string,
    priority: PriorityBand,
    reason: string,
    expiresInHours?: number
  ): Promise<PrioritizedAssetItem> {
    const payload: PriorityOverrideRequest = {
      priority,
      reason,
      expires_in_hours: expiresInHours,
    };
    const res = await fetch(`${BASE_URL}/assets/${assetId}/override`, {
      method: 'POST',
      headers: this.getHeaders(),
      body: JSON.stringify(payload),
    });
    if (!res.ok) throw new Error(`Failed to apply priority override: ${res.statusText}`);
    return res.json();
  }

  static async removeOverride(assetId: string): Promise<PrioritizedAssetItem> {
    const res = await fetch(`${BASE_URL}/assets/${assetId}/override`, {
      method: 'DELETE',
      headers: this.getHeaders(),
    });
    if (!res.ok) throw new Error(`Failed to remove priority override: ${res.statusText}`);
    return res.json();
  }

  static async recalculate(assetIds?: string[], force = false): Promise<any> {
    const res = await fetch(`${BASE_URL}/recalculate`, {
      method: 'POST',
      headers: this.getHeaders(),
      body: JSON.stringify({ asset_ids: assetIds, force }),
    });
    if (!res.ok) throw new Error(`Failed to recalculate priorities: ${res.statusText}`);
    return res.json();
  }

  static async listPolicies(): Promise<PriorityPolicy[]> {
    const res = await fetch(`${BASE_URL}/policies`, {
      headers: this.getHeaders(),
    });
    if (!res.ok) throw new Error(`Failed to list policies: ${res.statusText}`);
    return res.json();
  }

  static async getActivePolicy(): Promise<PriorityPolicy> {
    const res = await fetch(`${BASE_URL}/policies/active`, {
      headers: this.getHeaders(),
    });
    if (!res.ok) throw new Error(`Failed to get active policy: ${res.statusText}`);
    return res.json();
  }

  static async createPolicy(data: {
    name: string;
    description?: string;
    configuration: Record<string, any>;
  }): Promise<PriorityPolicy> {
    const res = await fetch(`${BASE_URL}/policies`, {
      method: 'POST',
      headers: this.getHeaders(),
      body: JSON.stringify(data),
    });
    if (!res.ok) throw new Error(`Failed to create policy: ${res.statusText}`);
    return res.json();
  }

  static async activatePolicy(policyId: string): Promise<PriorityPolicy> {
    const res = await fetch(`${BASE_URL}/policies/${policyId}/activate`, {
      method: 'POST',
      headers: this.getHeaders(),
    });
    if (!res.ok) throw new Error(`Failed to activate policy: ${res.statusText}`);
    return res.json();
  }

  static async getOverview(): Promise<PrioritizationOverviewResponse> {
    const res = await fetch(`${BASE_URL}/overview`, {
      headers: this.getHeaders(),
    });
    if (!res.ok) throw new Error(`Failed to get prioritization overview: ${res.statusText}`);
    return res.json();
  }
}
