import { apiFetch } from '../utils/apiClient';
/**
 * Section 62: Attack Surface Intelligence Service.
 * REST client for assets, actionable exposures, unknown asset review, discovery, and diffs.
 */
import { apiUrl, extractErrorMessage } from '../utils/apiClient';
import type {
  Asset,
  AssetDetail,
  Exposure,
  AttackSurfaceScope,
  AttackSurfaceOverviewStats,
  AttackSurfaceDiffResponse,
  UnknownAssetQueueItem,
  UnknownAssetReviewRequest,
  AttackSurfaceScopeCreateRequest,
  AttackSurfaceDiscoveryRequest,
  AttackSurfaceDiscoveryResponse,
  AssetTimelineItem,
} from '../types/attackSurface';

export class AttackSurfaceService {
  /**
   * Retrieves high-level Attack Surface Intelligence metrics and KPI breakdown.
   */
  static async getOverview(workspaceId: string = 'default'): Promise<AttackSurfaceOverviewStats> {
    const url = apiUrl('/api/v1/attack-surface/overview');
    const res = await apiFetch(url, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
      },
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || 'Failed to fetch attack surface overview');
    }
    return res.json();
  }

  /**
   * Queries paginated assets with server-side filters.
   */
  static async listAssets(
    params: {
      asset_type?: string;
      status?: string;
      exposure_state?: string;
      criticality?: string;
      q?: string;
      limit?: number;
      offset?: number;
    } = {},
    workspaceId: string = 'default'
  ): Promise<{ items: Asset[]; total: number; limit: number; offset: number }> {
    const qParams = new URLSearchParams();
    if (params.asset_type && params.asset_type !== 'ALL') qParams.set('asset_type', params.asset_type);
    if (params.status && params.status !== 'ALL') qParams.set('status', params.status);
    if (params.exposure_state && params.exposure_state !== 'ALL') qParams.set('exposure_state', params.exposure_state);
    if (params.criticality && params.criticality !== 'ALL') qParams.set('criticality', params.criticality);
    if (params.q) qParams.set('q', params.q);
    if (params.limit) qParams.set('limit', String(params.limit));
    if (params.offset !== undefined) qParams.set('offset', String(params.offset));

    const url = apiUrl(`/api/v1/attack-surface/assets?${qParams.toString()}`);
    const res = await apiFetch(url, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
      },
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || 'Failed to list assets');
    }
    return res.json();
  }

  /**
   * Registers a new asset explicitly.
   */
  static async createAsset(payload: Record<string, any>, workspaceId: string = 'default'): Promise<Asset> {
    const url = apiUrl('/api/v1/attack-surface/assets');
    const res = await apiFetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
      },
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || 'Failed to create asset');
    }
    return res.json();
  }

  /**
   * Retrieves full forensic progressive-disclosure asset detail.
   */
  static async getAssetDetail(assetId: string, workspaceId: string = 'default'): Promise<AssetDetail> {
    const url = apiUrl(`/api/v1/attack-surface/assets/${encodeURIComponent(assetId)}`);
    const res = await apiFetch(url, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
      },
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || 'Failed to get asset details');
    }
    return res.json();
  }

  /**
   * Updates asset metadata (owner, criticality, environment, etc.).
   */
  static async updateAsset(
    assetId: string,
    payload: Record<string, any>,
    workspaceId: string = 'default'
  ): Promise<Asset> {
    const url = apiUrl(`/api/v1/attack-surface/assets/${encodeURIComponent(assetId)}`);
    const res = await apiFetch(url, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
      },
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || 'Failed to update asset');
    }
    return res.json();
  }

  /**
   * Retrieves chronological lifecycle changes and exposure events for an asset.
   */
  static async getAssetTimeline(assetId: string, workspaceId: string = 'default'): Promise<AssetTimelineItem[]> {
    const url = apiUrl(`/api/v1/attack-surface/assets/${encodeURIComponent(assetId)}/timeline`);
    const res = await apiFetch(url, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
      },
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || 'Failed to fetch asset timeline');
    }
    return res.json();
  }

  /**
   * Lists actionable exposures across assets.
   */
  static async listExposures(
    params: {
      asset_id?: string;
      exposure_type?: string;
      status?: string;
      severity?: string;
      limit?: number;
      offset?: number;
    } = {},
    workspaceId: string = 'default'
  ): Promise<{ items: Exposure[]; total: number; limit: number; offset: number }> {
    const qParams = new URLSearchParams();
    if (params.asset_id) qParams.set('asset_id', params.asset_id);
    if (params.exposure_type && params.exposure_type !== 'ALL') qParams.set('exposure_type', params.exposure_type);
    if (params.status && params.status !== 'ALL') qParams.set('status', params.status);
    if (params.severity && params.severity !== 'ALL') qParams.set('severity', params.severity);
    if (params.limit) qParams.set('limit', String(params.limit));
    if (params.offset !== undefined) qParams.set('offset', String(params.offset));

    const url = apiUrl(`/api/v1/attack-surface/exposures?${qParams.toString()}`);
    const res = await apiFetch(url, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
      },
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || 'Failed to list exposures');
    }
    return res.json();
  }

  /**
   * Resolves an exposure with analyst rationale and audit record.
   */
  static async resolveExposure(
    exposureId: string,
    notes: string,
    actor: string = 'SOC Analyst',
    workspaceId: string = 'default'
  ): Promise<Exposure> {
    const url = apiUrl(`/api/v1/attack-surface/exposures/${encodeURIComponent(exposureId)}/resolve`);
    const res = await apiFetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
      },
      body: JSON.stringify({ notes, actor }),
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || 'Failed to resolve exposure');
    }
    return res.json();
  }

  /**
   * Retrieves the queue of unknown/unmapped assets.
   */
  static async getUnknownQueue(
    limit: number = 50,
    offset: number = 0,
    workspaceId: string = 'default'
  ): Promise<{ items: UnknownAssetQueueItem[]; total: number; limit: number; offset: number }> {
    const url = apiUrl(`/api/v1/attack-surface/unknown-queue?limit=${limit}&offset=${offset}`);
    const res = await apiFetch(url, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
      },
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || 'Failed to fetch unknown asset queue');
    }
    return res.json();
  }

  /**
   * Executes analyst triage review on an unknown asset.
   */
  static async reviewUnknownAsset(
    assetId: string,
    payload: UnknownAssetReviewRequest,
    workspaceId: string = 'default'
  ): Promise<Asset> {
    const url = apiUrl(`/api/v1/attack-surface/unknown-queue/${encodeURIComponent(assetId)}/review`);
    const res = await apiFetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
      },
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || 'Failed to review unknown asset');
    }
    return res.json();
  }

  /**
   * Lists tenant-authorized discovery scopes.
   */
  static async listScopes(workspaceId: string = 'default'): Promise<AttackSurfaceScope[]> {
    const url = apiUrl('/api/v1/attack-surface/scopes');
    const res = await apiFetch(url, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
      },
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || 'Failed to list discovery scopes');
    }
    return res.json();
  }

  /**
   * Creates an authorized discovery scope with strict SSRF guardrails.
   */
  static async createScope(
    payload: AttackSurfaceScopeCreateRequest,
    workspaceId: string = 'default'
  ): Promise<AttackSurfaceScope> {
    const url = apiUrl('/api/v1/attack-surface/scopes');
    const res = await apiFetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
      },
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || 'Failed to create discovery scope');
    }
    return res.json();
  }

  /**
   * Deletes a discovery scope.
   */
  static async deleteScope(scopeId: string, workspaceId: string = 'default'): Promise<boolean> {
    const url = apiUrl(`/api/v1/attack-surface/scopes/${encodeURIComponent(scopeId)}`);
    const res = await apiFetch(url, {
      method: 'DELETE',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
      },
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || 'Failed to delete discovery scope');
    }
    return true;
  }

  /**
   * Executes safe on-demand discovery and telemetry synchronization.
   */
  static async runDiscovery(
    payload: AttackSurfaceDiscoveryRequest = {
      sync_from_endpoints: true,
      sync_from_identities: true,
      sync_from_telemetry: true,
      resolve_dns_records: true,
    },
    workspaceId: string = 'default'
  ): Promise<AttackSurfaceDiscoveryResponse> {
    const url = apiUrl('/api/v1/attack-surface/discover');
    const res = await apiFetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
      },
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || 'Failed to run discovery sweep');
    }
    return res.json();
  }

  /**
   * Retrieves latest attack surface snapshot diff.
   */
  static async getDiff(workspaceId: string = 'default'): Promise<AttackSurfaceDiffResponse> {
    const url = apiUrl('/api/v1/attack-surface/diff');
    const res = await apiFetch(url, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
      },
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || 'Failed to fetch attack surface diff');
    }
    return res.json();
  }
}
