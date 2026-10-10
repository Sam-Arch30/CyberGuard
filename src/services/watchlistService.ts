/**
 * Section 53: Watchlist Monitoring & Continuous Threat Intelligence Client Service.
 */
import { apiUrl, extractErrorMessage } from '../utils/apiClient';
import type {
  WatchlistSummary,
  WatchlistDetail,
  WatchedIndicator,
  IntelligenceChange,
  WatchlistMonitoringRun,
  WatchlistHealth,
  WatchlistCreatePayload,
  WatchlistUpdatePayload,
  WatchedIndicatorCreatePayload,
  QuickWatchPayload,
} from '../types/watchlist';

export class WatchlistService {
  /**
   * Retrieves list of watchlists.
   */
  static async listWatchlists(
    params: {
      status?: string;
      priority?: string;
      q?: string;
      limit?: number;
      offset?: number;
    } = {},
    workspaceId: string = 'default'
  ): Promise<{ items: WatchlistSummary[]; total: number }> {
    const qParams = new URLSearchParams();
    if (params.status) qParams.set('status', params.status);
    if (params.priority) qParams.set('priority', params.priority);
    if (params.q) qParams.set('q', params.q);
    if (params.limit) qParams.set('limit', String(params.limit));
    if (params.offset) qParams.set('offset', String(params.offset));

    const url = apiUrl(`/api/watchlists?${qParams.toString()}`);
    const res = await fetch(url, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
      },
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(`Failed to list watchlists: ${err}`);
    }

    return res.json();
  }

  /**
   * Retrieves detail of a single watchlist including recent changes and runs.
   */
  static async getWatchlist(
    watchlistId: string,
    workspaceId: string = 'default'
  ): Promise<WatchlistDetail> {
    const url = apiUrl(`/api/watchlists/${encodeURIComponent(watchlistId)}`);
    const res = await fetch(url, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
      },
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(`Failed to get watchlist: ${err}`);
    }

    return res.json();
  }

  /**
   * Creates a new watchlist.
   */
  static async createWatchlist(
    payload: WatchlistCreatePayload,
    workspaceId: string = 'default'
  ): Promise<WatchlistSummary> {
    const url = apiUrl('/api/watchlists');
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
      throw new Error(`Failed to create watchlist: ${err}`);
    }

    return res.json();
  }

  /**
   * Updates an existing watchlist.
   */
  static async updateWatchlist(
    watchlistId: string,
    payload: WatchlistUpdatePayload,
    workspaceId: string = 'default'
  ): Promise<WatchlistSummary> {
    const url = apiUrl(`/api/watchlists/${encodeURIComponent(watchlistId)}`);
    const res = await fetch(url, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
      },
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(`Failed to update watchlist: ${err}`);
    }

    return res.json();
  }

  /**
   * Deletes a watchlist.
   */
  static async deleteWatchlist(
    watchlistId: string,
    workspaceId: string = 'default'
  ): Promise<void> {
    const url = apiUrl(`/api/watchlists/${encodeURIComponent(watchlistId)}`);
    const res = await fetch(url, {
      method: 'DELETE',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
      },
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(`Failed to delete watchlist: ${err}`);
    }
  }

  /**
   * Retrieves aggregated health metrics.
   */
  static async getWatchlistHealth(
    watchlistId: string,
    workspaceId: string = 'default'
  ): Promise<WatchlistHealth> {
    const url = apiUrl(`/api/watchlists/${encodeURIComponent(watchlistId)}/health`);
    const res = await fetch(url, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
      },
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(`Failed to get watchlist health: ${err}`);
    }

    return res.json();
  }

  /**
   * Triggers an immediate refresh cycle for an entire watchlist.
   */
  static async refreshWatchlist(
    watchlistId: string,
    workspaceId: string = 'default'
  ): Promise<WatchlistMonitoringRun[]> {
    const url = apiUrl(`/api/watchlists/${encodeURIComponent(watchlistId)}/refresh`);
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
      },
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(`Failed to refresh watchlist: ${err}`);
    }

    return res.json();
  }

  /**
   * Lists monitored indicators within a watchlist.
   */
  static async listWatchlistItems(
    watchlistId: string,
    params: {
      status?: string;
      verdict?: string;
      q?: string;
      limit?: number;
      offset?: number;
    } = {},
    workspaceId: string = 'default'
  ): Promise<{ items: WatchedIndicator[]; total: number }> {
    const qParams = new URLSearchParams();
    if (params.status) qParams.set('status', params.status);
    if (params.verdict) qParams.set('verdict', params.verdict);
    if (params.q) qParams.set('q', params.q);
    if (params.limit) qParams.set('limit', String(params.limit));
    if (params.offset) qParams.set('offset', String(params.offset));

    const url = apiUrl(`/api/watchlists/${encodeURIComponent(watchlistId)}/items?${qParams.toString()}`);
    const res = await fetch(url, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
      },
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(`Failed to list indicators: ${err}`);
    }

    return res.json();
  }

  /**
   * Adds an indicator to a watchlist.
   */
  static async addWatchlistItem(
    watchlistId: string,
    payload: WatchedIndicatorCreatePayload,
    workspaceId: string = 'default'
  ): Promise<WatchedIndicator> {
    const url = apiUrl(`/api/watchlists/${encodeURIComponent(watchlistId)}/items`);
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
      throw new Error(`Failed to add indicator: ${err}`);
    }

    return res.json();
  }

  /**
   * Bulk adds indicators to a watchlist.
   */
  static async bulkAddWatchlistItems(
    watchlistId: string,
    indicators: WatchedIndicatorCreatePayload[],
    workspaceId: string = 'default'
  ): Promise<WatchedIndicator[]> {
    const url = apiUrl(`/api/watchlists/${encodeURIComponent(watchlistId)}/items/bulk`);
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
      },
      body: JSON.stringify({ indicators, default_priority: 'MEDIUM' }),
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(`Failed to bulk add indicators: ${err}`);
    }

    return res.json();
  }

  /**
   * Removes an indicator from a watchlist.
   */
  static async removeWatchlistItem(
    watchlistId: string,
    itemId: string,
    workspaceId: string = 'default'
  ): Promise<void> {
    const url = apiUrl(`/api/watchlists/${encodeURIComponent(watchlistId)}/items/${encodeURIComponent(itemId)}`);
    const res = await fetch(url, {
      method: 'DELETE',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
      },
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(`Failed to remove indicator: ${err}`);
    }
  }

  /**
   * Triggers an immediate refresh on a single watched indicator.
   */
  static async refreshSingleIndicator(
    itemId: string,
    workspaceId: string = 'default'
  ): Promise<WatchedIndicator> {
    const url = apiUrl(`/api/watchlists/items/${encodeURIComponent(itemId)}/refresh`);
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
      },
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(`Failed to refresh indicator: ${err}`);
    }

    return res.json();
  }

  /**
   * Lists detected intelligence changes for a watchlist.
   */
  static async listWatchlistChanges(
    watchlistId: string,
    params: { severity?: string; change_type?: string; limit?: number; offset?: number } = {},
    workspaceId: string = 'default'
  ): Promise<{ items: IntelligenceChange[]; total: number }> {
    const qParams = new URLSearchParams();
    if (params.severity) qParams.set('severity', params.severity);
    if (params.change_type) qParams.set('change_type', params.change_type);
    if (params.limit) qParams.set('limit', String(params.limit));
    if (params.offset) qParams.set('offset', String(params.offset));

    const url = apiUrl(`/api/watchlists/${encodeURIComponent(watchlistId)}/changes?${qParams.toString()}`);
    const res = await fetch(url, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
      },
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(`Failed to list changes: ${err}`);
    }

    return res.json();
  }

  /**
   * Lists execution runs for a watchlist.
   */
  static async listWatchlistRuns(
    watchlistId: string,
    limit: number = 20,
    workspaceId: string = 'default'
  ): Promise<{ items: WatchlistMonitoringRun[]; total: number }> {
    const url = apiUrl(`/api/watchlists/${encodeURIComponent(watchlistId)}/runs?limit=${limit}`);
    const res = await fetch(url, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
      },
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(`Failed to list runs: ${err}`);
    }

    return res.json();
  }

  /**
   * Quick-watches an indicator from an investigation or incident with 1 click.
   */
  static async quickWatch(
    payload: QuickWatchPayload,
    workspaceId: string = 'default'
  ): Promise<WatchedIndicator> {
    const url = apiUrl('/api/watchlists/quick-watch');
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
      throw new Error(`Failed to quick watch indicator: ${err}`);
    }

    return res.json();
  }
}
