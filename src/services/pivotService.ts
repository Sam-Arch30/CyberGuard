/**
 * Section 55: Threat Hunting & Investigation Pivots API Client.
 */
import type {
  PivotRegistryResponse,
  PivotRequest,
  PivotResponse,
  EntityFrequencyContext,
  AIPivotRecommendationResponse,
  HypothesisRecordRequest,
  HypothesisResponse,
  PromoteToInvestigationRequest,
  PromoteToInvestigationResponse,
  PromoteToWatchlistRequest,
  PromoteToWatchlistResponse,
  PivotToHuntQueryRequest,
  PivotToHuntQueryResponse,
} from '../types/pivots';

const getHeaders = (): Record<string, string> => {
  const ws = localStorage.getItem('cyberguard_active_workspace') || 'default';
  const usr = localStorage.getItem('cyberguard_user_id') || 'analyst';
  return {
    'Content-Type': 'application/json',
    'X-Workspace-ID': ws,
    'X-User-ID': usr,
  };
};

export const pivotService = {
  async getRegistry(): Promise<PivotRegistryResponse> {
    const res = await fetch('/api/hunting/pivots/registry', {
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error(`Failed to load pivot registry: ${res.statusText}`);
    return res.json();
  },

  async executePivot(req: PivotRequest): Promise<PivotResponse> {
    const res = await fetch('/api/hunting/pivots/execute', {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(req),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Pivot execution failed: ${res.statusText}`);
    }
    return res.json();
  },

  async getFrequencyContext(sourceType: string, sourceValue: string): Promise<EntityFrequencyContext> {
    const params = new URLSearchParams({
      source_type: sourceType,
      source_value: sourceValue,
    });
    const res = await fetch(`/api/hunting/pivots/frequency?${params.toString()}`, {
      headers: getHeaders(),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Failed to fetch frequency context: ${res.statusText}`);
    }
    return res.json();
  },

  async getRecommendations(sourceType: string, sourceValue: string): Promise<AIPivotRecommendationResponse> {
    const params = new URLSearchParams({
      source_type: sourceType,
      source_value: sourceValue,
    });
    const res = await fetch(`/api/hunting/pivots/recommendations?${params.toString()}`, {
      headers: getHeaders(),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Failed to fetch AI recommendations: ${res.statusText}`);
    }
    return res.json();
  },

  async recordHypothesis(req: HypothesisRecordRequest): Promise<HypothesisResponse> {
    const res = await fetch('/api/hunting/pivots/hypotheses', {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(req),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Failed to save hypothesis: ${res.statusText}`);
    }
    return res.json();
  },

  async listHypotheses(investigationId?: string, sourceObservable?: string): Promise<HypothesisResponse[]> {
    const params = new URLSearchParams();
    if (investigationId) params.append('investigation_id', investigationId);
    if (sourceObservable) params.append('source_observable', sourceObservable);
    const qs = params.toString() ? `?${params.toString()}` : '';

    const res = await fetch(`/api/hunting/pivots/hypotheses${qs}`, {
      headers: getHeaders(),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Failed to list hypotheses: ${res.statusText}`);
    }
    return res.json();
  },

  async promoteToInvestigation(req: PromoteToInvestigationRequest): Promise<PromoteToInvestigationResponse> {
    const res = await fetch('/api/hunting/pivots/promote/investigation', {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(req),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Failed to promote to investigation: ${res.statusText}`);
    }
    return res.json();
  },

  async promoteToWatchlist(req: PromoteToWatchlistRequest): Promise<PromoteToWatchlistResponse> {
    const res = await fetch('/api/hunting/pivots/promote/watchlist', {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(req),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Failed to promote to watchlist: ${res.statusText}`);
    }
    return res.json();
  },

  async pivotToHuntQuery(req: PivotToHuntQueryRequest): Promise<PivotToHuntQueryResponse> {
    const res = await fetch('/api/hunting/pivots/to-hunt-query', {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(req),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Failed to generate hunt query from pivots: ${res.statusText}`);
    }
    return res.json();
  },
};
