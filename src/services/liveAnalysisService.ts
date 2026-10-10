/**
 * Service client for Section 37 Live Analysis & Task DAG Orchestration.
 */
import { apiUrl, extractErrorMessage } from '../utils/apiClient';
import type { AnalysisRunLiveResponse } from '../types/analysis';
import { RealtimeService } from './realtimeService';

export const liveAnalysisService = {
  /**
   * Retrieves the live analysis run state by run ID.
   */
  async getLiveAnalysis(runId: string): Promise<AnalysisRunLiveResponse> {
    const res = await fetch(apiUrl(`/api/analysis/${encodeURIComponent(runId)}`));
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to fetch analysis run (${res.status})`);
    }
    return res.json();
  },

  /**
   * Retrieves the live analysis run state by investigation ID, incident number, or evidence ID.
   */
  async getInvestigationLiveAnalysis(investigationId: string): Promise<AnalysisRunLiveResponse> {
    const res = await fetch(apiUrl(`/api/investigations/${encodeURIComponent(investigationId)}/analysis`));
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `No analysis run associated with investigation '${investigationId}'`);
    }
    return res.json();
  },

  /**
   * Triggers execution of an initialized/queued AnalysisRun.
   */
  async startLiveAnalysis(runId: string): Promise<AnalysisRunLiveResponse> {
    const res = await fetch(apiUrl(`/api/analysis/${encodeURIComponent(runId)}/start`), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    });
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to start analysis run (${res.status})`);
    }
    return res.json();
  },

  /**
   * Cancels an active AnalysisRun.
   */
  async cancelLiveAnalysis(runId: string): Promise<AnalysisRunLiveResponse> {
    const res = await fetch(apiUrl(`/api/analysis/${encodeURIComponent(runId)}/cancel`), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    });
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to cancel analysis run (${res.status})`);
    }
    return res.json();
  },

  /**
   * Retries an AnalysisRun.
   */
  async retryLiveAnalysis(runId: string): Promise<AnalysisRunLiveResponse> {
    const res = await fetch(apiUrl(`/api/analysis/${encodeURIComponent(runId)}/retry`), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    });
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to retry analysis run (${res.status})`);
    }
    return res.json();
  },

  /**
   * Subscribes to real-time Server-Sent Events (SSE) for an active AnalysisRun.
   * Leverages Section 46 RealtimeService with reconnection replay and gap detection.
   */
  subscribeLiveAnalysisStream(
    runId: string,
    onSnapshot: (snapshot: AnalysisRunLiveResponse) => void,
    onEvent: (eventPayload: Record<string, unknown>) => void,
    onTerminal: (status: string) => void,
    onError?: (err: unknown) => void,
    onStatusChange?: (status: any) => void,
    onAuthoritativeRefetch?: () => Promise<void> | void
  ): () => void {
    return RealtimeService.subscribe<AnalysisRunLiveResponse>({
      url: `/api/analysis/${encodeURIComponent(runId)}/stream`,
      onSnapshot,
      onEvent: (evt: any) => onEvent(evt),
      onTerminal,
      onError,
      onStatusChange,
      onAuthoritativeRefetch,
    });
  },
};
