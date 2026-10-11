/**
 * Section 61: Cross-Source Correlation & Unified Entity Correlation Client Service.
 * Connects signals across multiple data sources into explainable, evidence-backed security correlations.
 */
import { apiUrl, extractErrorMessage } from '../utils/apiClient';
import type {
  CrossSourceCorrelationItem,
  CrossSourceCorrelationDetail,
  CorrelationTimelineItem,
  WhyCorrelatedExplanation,
  CorrelationOverviewStats,
  EntityResolutionResult,
  ResolutionHistoryItem,
  CorrelationDispositionPayload,
  CorrelationEvaluatePayload,
  EntityResolvePayload,
} from '../types/correlation';

export class CrossSourceCorrelationService {
  /**
   * Retrieves high-level correlation KPI overview and recent chains.
   */
  static async getOverview(workspaceId: string = 'default'): Promise<CorrelationOverviewStats> {
    const url = apiUrl('/api/v1/correlations/overview');
    const res = await fetch(url, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
      },
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || 'Failed to fetch correlation overview');
    }
    return res.json();
  }

  /**
   * Queries paginated correlations with server-side filters.
   */
  static async listCorrelations(
    params: {
      correlation_type?: string;
      status?: string;
      confidence_level?: string;
      entity_id?: string;
      finding_id?: string;
      alert_id?: string;
      incident_id?: string;
      q?: string;
      limit?: number;
      offset?: number;
    } = {},
    workspaceId: string = 'default'
  ): Promise<{ items: CrossSourceCorrelationItem[]; total: number; limit: number; offset: number }> {
    const qParams = new URLSearchParams();
    if (params.correlation_type) qParams.set('correlation_type', params.correlation_type);
    if (params.status) qParams.set('status', params.status);
    if (params.confidence_level) qParams.set('confidence_level', params.confidence_level);
    if (params.entity_id) qParams.set('entity_id', params.entity_id);
    if (params.finding_id) qParams.set('finding_id', params.finding_id);
    if (params.alert_id) qParams.set('alert_id', params.alert_id);
    if (params.incident_id) qParams.set('incident_id', params.incident_id);
    if (params.q) qParams.set('q', params.q);
    if (params.limit !== undefined) qParams.set('limit', String(params.limit));
    if (params.offset !== undefined) qParams.set('offset', String(params.offset));

    const url = apiUrl(`/api/v1/correlations?${qParams.toString()}`);
    const res = await fetch(url, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
      },
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || 'Failed to list correlations');
    }
    return res.json();
  }

  /**
   * Retrieves full detail for a correlation including members, evidence, and provenance.
   */
  static async getCorrelationDetail(
    correlationId: string,
    workspaceId: string = 'default'
  ): Promise<CrossSourceCorrelationDetail> {
    const url = apiUrl(`/api/v1/correlations/${encodeURIComponent(correlationId)}`);
    const res = await fetch(url, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
      },
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to fetch correlation ${correlationId}`);
    }
    return res.json();
  }

  /**
   * Retrieves chronological sequence of participating events and signals.
   */
  static async getTimeline(
    correlationId: string,
    workspaceId: string = 'default'
  ): Promise<CorrelationTimelineItem[]> {
    const url = apiUrl(`/api/v1/correlations/${encodeURIComponent(correlationId)}/timeline`);
    const res = await fetch(url, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
      },
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to fetch correlation timeline for ${correlationId}`);
    }
    return res.json();
  }

  /**
   * Retrieves explainability audit panel ("Why Correlated?") breakdown.
   */
  static async getExplanation(
    correlationId: string,
    workspaceId: string = 'default'
  ): Promise<WhyCorrelatedExplanation> {
    const url = apiUrl(`/api/v1/correlations/${encodeURIComponent(correlationId)}/explanation`);
    const res = await fetch(url, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
      },
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to fetch correlation explanation for ${correlationId}`);
    }
    return res.json();
  }

  /**
   * Triggers synchronous or on-demand cross-source evaluation.
   */
  static async evaluateCorrelation(
    payload: CorrelationEvaluatePayload,
    workspaceId: string = 'default'
  ): Promise<CrossSourceCorrelationItem[]> {
    const url = apiUrl('/api/v1/correlations/evaluate');
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
      },
      body: JSON.stringify({
        ...payload,
        workspace_id: payload.workspace_id || workspaceId,
      }),
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || 'Failed to trigger correlation evaluation');
    }
    return res.json();
  }

  /**
   * Records analyst feedback disposition (CONFIRMED, REJECTED, UNCERTAIN).
   */
  static async recordDisposition(
    correlationId: string,
    payload: CorrelationDispositionPayload,
    workspaceId: string = 'default'
  ): Promise<CrossSourceCorrelationDetail> {
    const url = apiUrl(`/api/v1/correlations/${encodeURIComponent(correlationId)}/disposition`);
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
      },
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to record disposition on ${correlationId}`);
    }
    return res.json();
  }

  /**
   * Deterministically resolves an entity identifier against the canonical Knowledge Graph.
   */
  static async resolveEntity(
    payload: EntityResolvePayload,
    workspaceId: string = 'default'
  ): Promise<EntityResolutionResult> {
    const url = apiUrl('/api/v1/entities/resolve');
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
      },
      body: JSON.stringify({
        ...payload,
        workspace_id: payload.workspace_id || workspaceId,
      }),
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || 'Failed to resolve entity');
    }
    return res.json();
  }

  /**
   * Retrieves immutable audit log of entity resolution decisions.
   */
  static async getResolutionHistory(
    params: {
      entity_type?: string;
      canonical_entity_id?: string;
      limit?: number;
    } = {},
    workspaceId: string = 'default'
  ): Promise<{ items: ResolutionHistoryItem[]; total: number }> {
    const qParams = new URLSearchParams();
    if (params.entity_type) qParams.set('entity_type', params.entity_type);
    if (params.canonical_entity_id) qParams.set('canonical_entity_id', params.canonical_entity_id);
    if (params.limit !== undefined) qParams.set('limit', String(params.limit));

    const url = apiUrl(`/api/v1/entities/resolution-history?${qParams.toString()}`);
    const res = await fetch(url, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
      },
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || 'Failed to fetch entity resolution history');
    }
    return res.json();
  }
}
