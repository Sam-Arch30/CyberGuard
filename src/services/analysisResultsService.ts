import { apiFetch } from '../utils/apiClient';
/**
 * Service client for Section 38 Analysis Results & Progressive Disclosure.
 * Communicates with consolidated aggregation and forensic detail endpoints.
 */
import { apiUrl, extractErrorMessage } from '../utils/apiClient';
import type {
  AnalysisResultsResponse,
  EvidenceDetailResponse,
} from '../types/analysisResults';

export const analysisResultsService = {
  /**
   * Retrieves aggregated 4-tier analysis results by AnalysisRun ID.
   */
  async getAnalysisResults(runId: string): Promise<AnalysisResultsResponse> {
    const res = await apiFetch(apiUrl(`/api/analysis/${encodeURIComponent(runId)}/results`));
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to fetch analysis results for run '${runId}' (${res.status})`);
    }
    return res.json();
  },

  /**
   * Retrieves aggregated 4-tier analysis results by investigation ID, incident number, or evidence ID.
   */
  async getInvestigationAnalysisResults(identifier: string): Promise<AnalysisResultsResponse> {
    const res = await apiFetch(apiUrl(`/api/investigations/${encodeURIComponent(identifier)}/analysis/results`));
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to fetch analysis results for investigation '${identifier}' (${res.status})`);
    }
    return res.json();
  },

  /**
   * Lazy-loads redacted forensic details for a single evidence item.
   */
  async getEvidenceDetail(runId: string, evidenceId: string): Promise<EvidenceDetailResponse> {
    const res = await apiFetch(
      apiUrl(`/api/analysis/${encodeURIComponent(runId)}/evidence/${encodeURIComponent(evidenceId)}`)
    );
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to fetch evidence details for '${evidenceId}' (${res.status})`);
    }
    return res.json();
  },

  /**
   * Requests a versioned risk reassessment for an analysis run.
   */
  async reassessAnalysis(runId: string, reason: string = 'Manual investigator reassessment request'): Promise<AnalysisResultsResponse> {
    const res = await apiFetch(apiUrl(`/api/analysis/${encodeURIComponent(runId)}/reassess`), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ reason }),
    });
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to trigger risk reassessment for run '${runId}' (${res.status})`);
    }
    return res.json();
  },
};
