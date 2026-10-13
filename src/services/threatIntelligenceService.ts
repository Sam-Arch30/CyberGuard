import { apiFetch } from '../utils/apiClient';
/**
 * Section 52: Threat Intelligence & External Intelligence Enrichment Client Service.
 */
import type {
  AggregatedIndicatorIntelligence,
  IndicatorHistoryResponse,
  ThreatIntelProviderConfig,
  PrivacyPolicyClassification,
} from '../types/threatIntelligence';

const API_BASE = '/api/intelligence';

export const threatIntelligenceService = {
  /**
   * Retrieves enriched threat intelligence for an indicator observable.
   */
  async getIndicatorIntelligence(
    indicatorType: string,
    indicatorValue: string,
    forceRefresh: boolean = false
  ): Promise<AggregatedIndicatorIntelligence> {
    const encodedVal = encodeURIComponent(indicatorValue);
    const url = `${API_BASE}/indicator/${indicatorType}/${encodedVal}${forceRefresh ? '?force_refresh=true' : ''}`;
    const res = await apiFetch(url);
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Failed to fetch intelligence (HTTP ${res.status})`);
    }
    return res.json();
  },

  /**
   * Forces a fresh intelligence lookup from configured providers bypassing all caches.
   */
  async refreshIndicatorIntelligence(
    indicatorType: string,
    indicatorValue: string
  ): Promise<AggregatedIndicatorIntelligence> {
    const encodedVal = encodeURIComponent(indicatorValue);
    const res = await apiFetch(`${API_BASE}/indicator/${indicatorType}/${encodedVal}/refresh`, {
      method: 'POST',
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Failed to refresh intelligence (HTTP ${res.status})`);
    }
    return res.json();
  },

  /**
   * Retrieves the chronological observation history across all providers for an indicator.
   */
  async getIndicatorHistory(
    indicatorType: string,
    indicatorValue: string
  ): Promise<IndicatorHistoryResponse> {
    const encodedVal = encodeURIComponent(indicatorValue);
    const res = await apiFetch(`${API_BASE}/indicator/${indicatorType}/${encodedVal}/history`);
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Failed to fetch indicator history (HTTP ${res.status})`);
    }
    return res.json();
  },

  /**
   * Lists all configured threat intelligence providers and their operational health.
   */
  async listProviders(): Promise<ThreatIntelProviderConfig[]> {
    const res = await apiFetch(`${API_BASE}/providers`);
    if (!res.ok) {
      throw new Error(`Failed to list threat intelligence providers (HTTP ${res.status})`);
    }
    return res.json();
  },

  /**
   * Updates provider configuration (enable/disable, priority, rate limit, secret API key).
   */
  async updateProvider(
    providerName: string,
    req: {
      enabled?: boolean;
      priority?: number;
      api_key?: string;
      rate_limit_per_minute?: number;
      timeout_seconds?: number;
    }
  ): Promise<ThreatIntelProviderConfig> {
    const res = await apiFetch(`${API_BASE}/providers/${providerName}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(req),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Failed to update provider (HTTP ${res.status})`);
    }
    return res.json();
  },

  /**
   * Triggers an on-demand health check on a threat intelligence provider.
   */
  async checkProviderHealth(providerName: string): Promise<{
    provider: string;
    status: string;
    message: string;
    capabilities: Record<string, any>;
  }> {
    const res = await apiFetch(`${API_BASE}/providers/${providerName}/health`, {
      method: 'POST',
    });
    if (!res.ok) {
      throw new Error(`Failed to check provider health (HTTP ${res.status})`);
    }
    return res.json();
  },

  /**
   * Checks the privacy policy classification for an indicator without executing lookups.
   */
  async classifyPrivacy(value: string, type?: string): Promise<PrivacyPolicyClassification> {
    const params = new URLSearchParams({ value });
    if (type) params.append('type', type);
    const res = await apiFetch(`${API_BASE}/privacy/classify?${params.toString()}`);
    if (!res.ok) {
      throw new Error(`Failed to classify indicator privacy (HTTP ${res.status})`);
    }
    return res.json();
  },

  /**
   * Performs batch enrichment for a list of indicators.
   */
  async batchEnrich(
    indicators: Array<{ type: string; value: string }>,
    forceRefresh: boolean = false
  ): Promise<{
    total_requested: number;
    enriched_count: number;
    results: AggregatedIndicatorIntelligence[];
    partial_failures: any[];
  }> {
    const res = await apiFetch(`${API_BASE}/batch-enrich`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ indicators, force_refresh: forceRefresh }),
    });
    if (!res.ok) {
      throw new Error(`Batch enrichment failed (HTTP ${res.status})`);
    }
    return res.json();
  },
};
