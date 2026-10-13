import { apiFetch } from '../utils/apiClient';
/**
 * Client service for Section 44: SOC Overview Dashboard.
 * Interacts with /api/dashboard/overview to retrieve real operational telemetry.
 */
import { getWorkspaceId, apiUrl, extractErrorMessage } from '../utils/apiClient';
import type { SocOverviewResponse } from '../types/socOverview';

export class SocOverviewService {
  /**
   * Fetches unified SOC Overview telemetry from authoritative backend models.
   */
  static async getOverview(
    timeWindow: '24h' | '7d' | '30d' | 'all' = '30d',
    workspaceId: string = getWorkspaceId()
  ): Promise<SocOverviewResponse> {
    const params = new URLSearchParams();
    params.set('time_window', timeWindow);
    params.set('workspace_id', workspaceId);

    const res = await apiFetch(apiUrl(`/api/dashboard/overview?${params.toString()}`));
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to fetch SOC Overview (${res.status})`);
    }
    return (await res.json()) as SocOverviewResponse;
  }
}
