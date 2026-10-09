/**
 * Frontend client service for Section 40: Interactive Attack Path.
 * Interacts with /api/investigations/:id/attack-path.
 */
import { apiUrl, extractErrorMessage } from '../utils/apiClient';
import type { AttackPathDetailResponse } from '../types/attackPath';

export const attackPathService = {
  /**
   * Retrieves the comprehensive attack path projection for an investigation.
   */
  async getAttackPath(
    identifier: string,
    runId?: string,
    forceReconstruct: boolean = false
  ): Promise<AttackPathDetailResponse> {
    const params = new URLSearchParams();
    if (runId) {
      params.append('run_id', runId);
    }
    if (forceReconstruct) {
      params.append('force_reconstruct', 'true');
    }

    const query = params.toString() ? `?${params.toString()}` : '';
    const res = await fetch(
      apiUrl(`/api/investigations/${encodeURIComponent(identifier)}/attack-path${query}`)
    );

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to load attack path for '${identifier}' (${res.status})`);
    }

    return res.json();
  },

  /**
   * Forces re-evaluation of attack reconstruction DAG on the backend.
   */
  async triggerReconstruction(identifier: string): Promise<AttackPathDetailResponse> {
    return this.getAttackPath(identifier, undefined, true);
  },
};
