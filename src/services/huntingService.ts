import { apiFetch } from '../utils/apiClient';
/**
 * Section 54: Threat Hunting Workspace & Query Engine API Client.
 */
import type {
  DataSourceRegistryResponse,
  HuntQueryDefinition,
  HuntValidationResponse,
  HuntExecutionRequest,
  HuntQueryResultResponse,
  SavedHuntCreateRequest,
  SavedHuntUpdateRequest,
  SavedHuntResponse,
  SavedHuntListResponse,
  NaturalLanguageHuntRequest,
  NaturalLanguageHuntResponse,
  HuntInvestigationHandoffRequest,
  HuntInvestigationHandoffResponse,
  HuntWatchlistHandoffRequest,
  HuntWatchlistHandoffResponse,
} from '../types/hunting';

const getHeaders = (): Record<string, string> => {
  const ws = localStorage.getItem('cyberguard_active_workspace') || 'default';
  const usr = localStorage.getItem('cyberguard_user_id') || 'analyst';
  return {
    'Content-Type': 'application/json',
    'X-Workspace-ID': ws,
    'X-User-ID': usr,
  };
};

export const huntingService = {
  async getRegistry(): Promise<DataSourceRegistryResponse> {
    const res = await apiFetch('/api/hunting/registry', {
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error(`Failed to load data source registry: ${res.statusText}`);
    return res.json();
  },

  async validateQuery(query: HuntQueryDefinition): Promise<HuntValidationResponse> {
    const res = await apiFetch('/api/hunting/validate', {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(query),
    });
    if (!res.ok) throw new Error(`Validation failed: ${res.statusText}`);
    return res.json();
  },

  async executeHunt(req: HuntExecutionRequest): Promise<HuntQueryResultResponse> {
    const res = await apiFetch('/api/hunting/execute', {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(req),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Query execution failed: ${res.statusText}`);
    }
    return res.json();
  },

  async listSavedHunts(): Promise<SavedHuntListResponse> {
    const res = await apiFetch('/api/hunting/saved', {
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error(`Failed to list saved hunts: ${res.statusText}`);
    return res.json();
  },

  async createSavedHunt(req: SavedHuntCreateRequest): Promise<SavedHuntResponse> {
    const res = await apiFetch('/api/hunting/saved', {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(req),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Failed to save hunt: ${res.statusText}`);
    }
    return res.json();
  },

  async updateSavedHunt(huntId: string, req: SavedHuntUpdateRequest): Promise<SavedHuntResponse> {
    const res = await apiFetch(`/api/hunting/saved/${huntId}`, {
      method: 'PATCH',
      headers: getHeaders(),
      body: JSON.stringify(req),
    });
    if (!res.ok) throw new Error(`Failed to update saved hunt: ${res.statusText}`);
    return res.json();
  },

  async deleteSavedHunt(huntId: string): Promise<void> {
    const res = await apiFetch(`/api/hunting/saved/${huntId}`, {
      method: 'DELETE',
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error(`Failed to delete saved hunt: ${res.statusText}`);
  },

  async queryAssistant(prompt: string, suggestedSource?: string): Promise<NaturalLanguageHuntResponse> {
    const payload: NaturalLanguageHuntRequest = { prompt, suggested_source: suggestedSource as any };
    const res = await apiFetch('/api/hunting/assistant', {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(payload),
    });
    if (!res.ok) throw new Error(`Assistant query failed: ${res.statusText}`);
    return res.json();
  },

  async handoffInvestigation(req: HuntInvestigationHandoffRequest): Promise<HuntInvestigationHandoffResponse> {
    const res = await apiFetch('/api/hunting/handoff/investigation', {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(req),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Investigation handoff failed: ${res.statusText}`);
    }
    return res.json();
  },

  async handoffWatchlist(req: HuntWatchlistHandoffRequest): Promise<HuntWatchlistHandoffResponse> {
    const res = await apiFetch('/api/hunting/handoff/watchlist', {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(req),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Watchlist handoff failed: ${res.statusText}`);
    }
    return res.json();
  },

  async exportResults(executionId: string, format: 'json' | 'csv'): Promise<string> {
    const res = await apiFetch('/api/hunting/export', {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify({ execution_id: executionId, format }),
    });
    if (!res.ok) throw new Error(`Export failed: ${res.statusText}`);
    return res.text();
  },
};
