/**
 * Client service for Section 45: Persistent Background Jobs & Asynchronous Orchestration.
 * Handles job submission, status polling, cancellation, manual retries, and metrics inspection.
 */
import { apiUrl, extractErrorMessage } from '../utils/apiClient';
import type {
  JobReadResponse,
  JobListResponse,
  JobMetricsSummary,
  JobActionResponse,
  JobSubmitRequest,
  JobEventRead,
} from '../types/job';
import { RealtimeService } from './realtimeService';
import type { RealtimeEvent, RealtimeConnectionStatus } from '../types/realtime';

export class BackgroundJobService {
  /**
   * Submits a new background job.
   */
  static async submitJob(
    request: JobSubmitRequest,
    workspaceId: string = 'default'
  ): Promise<JobReadResponse> {
    const res = await fetch(apiUrl('/api/jobs'), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
      },
      body: JSON.stringify(request),
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to submit background job (${res.status})`);
    }
    return (await res.json()) as JobReadResponse;
  }

  /**
   * Retrieves paginated list of background jobs.
   */
  static async listJobs(params?: {
    status?: string;
    job_type?: string;
    resource_id?: string;
    page?: number;
    page_size?: number;
    workspaceId?: string;
  }): Promise<JobListResponse> {
    const query = new URLSearchParams();
    if (params?.status) query.set('status', params.status);
    if (params?.job_type) query.set('job_type', params.job_type);
    if (params?.resource_id) query.set('resource_id', params.resource_id);
    if (params?.page) query.set('page', params.page.toString());
    if (params?.page_size) query.set('page_size', params.page_size.toString());

    const res = await fetch(apiUrl(`/api/jobs?${query.toString()}`), {
      headers: {
        'X-Workspace-ID': params?.workspaceId || 'default',
      },
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to list background jobs (${res.status})`);
    }
    return (await res.json()) as JobListResponse;
  }

  /**
   * Fetches detailed job status including latest progress and output references.
   */
  static async getJob(jobId: string, workspaceId: string = 'default'): Promise<JobReadResponse> {
    const res = await fetch(apiUrl(`/api/jobs/${encodeURIComponent(jobId)}`), {
      headers: {
        'X-Workspace-ID': workspaceId,
      },
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to get background job (${res.status})`);
    }
    return (await res.json()) as JobReadResponse;
  }

  /**
   * Fetches chronological execution events emitted by a job.
   */
  static async getJobEvents(jobId: string, workspaceId: string = 'default'): Promise<JobEventRead[]> {
    const res = await fetch(apiUrl(`/api/jobs/${encodeURIComponent(jobId)}/events`), {
      headers: {
        'X-Workspace-ID': workspaceId,
      },
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to get job events (${res.status})`);
    }
    return (await res.json()) as JobEventRead[];
  }

  /**
   * Dispatches cancellation request to a queued or running job.
   */
  static async cancelJob(
    jobId: string,
    reason?: string,
    workspaceId: string = 'default'
  ): Promise<JobActionResponse> {
    const query = reason ? `?reason=${encodeURIComponent(reason)}` : '';
    const res = await fetch(apiUrl(`/api/jobs/${encodeURIComponent(jobId)}/cancel${query}`), {
      method: 'POST',
      headers: {
        'X-Workspace-ID': workspaceId,
      },
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to cancel job (${res.status})`);
    }
    return (await res.json()) as JobActionResponse;
  }

  /**
   * Manually retries a failed or dead-lettered job.
   */
  static async retryJob(jobId: string, workspaceId: string = 'default'): Promise<JobActionResponse> {
    const res = await fetch(apiUrl(`/api/jobs/${encodeURIComponent(jobId)}/retry`), {
      method: 'POST',
      headers: {
        'X-Workspace-ID': workspaceId,
      },
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to retry job (${res.status})`);
    }
    return (await res.json()) as JobActionResponse;
  }

  /**
   * Retrieves operational health and queue metrics summary.
   */
  static async getMetricsSummary(workspaceId: string = 'default'): Promise<JobMetricsSummary> {
    const res = await fetch(apiUrl('/api/jobs/metrics/summary'), {
      headers: {
        'X-Workspace-ID': workspaceId,
      },
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to get job metrics (${res.status})`);
    }
    return (await res.json()) as JobMetricsSummary;
  }

  /**
   * Subscribes to real-time events for a specific background job.
   */
  static subscribeJob(
    jobId: string,
    callbacks: {
      onEvent: (event: RealtimeEvent) => void;
      onSnapshot?: (snapshot: JobReadResponse) => void;
      onTerminal?: (status: string) => void;
      onError?: (error: unknown) => void;
      onStatusChange?: (status: RealtimeConnectionStatus) => void;
      onAuthoritativeRefetch?: () => Promise<void> | void;
    },
    workspaceId: string = 'default'
  ): () => void {
    return RealtimeService.subscribe<JobReadResponse>({
      url: `/api/jobs/${encodeURIComponent(jobId)}/stream`,
      onEvent: callbacks.onEvent,
      onSnapshot: callbacks.onSnapshot,
      onTerminal: callbacks.onTerminal,
      onError: callbacks.onError,
      onStatusChange: callbacks.onStatusChange,
      onAuthoritativeRefetch: callbacks.onAuthoritativeRefetch || (async () => {
        try {
          const fresh = await BackgroundJobService.getJob(jobId, workspaceId);
          if (callbacks.onSnapshot) callbacks.onSnapshot(fresh);
        } catch {
          // ignore
        }
      }),
    });
  }

  /**
   * Subscribes to workspace-level job stream for all background jobs.
   */
  static subscribeWorkspaceJobs(
    workspaceId: string = 'default',
    callbacks: {
      onEvent: (event: RealtimeEvent) => void;
      onError?: (error: unknown) => void;
      onStatusChange?: (status: RealtimeConnectionStatus) => void;
      onAuthoritativeRefetch?: () => Promise<void> | void;
    }
  ): () => void {
    return RealtimeService.subscribe<JobListResponse>({
      url: `/api/jobs/stream`,
      onEvent: callbacks.onEvent,
      onError: callbacks.onError,
      onStatusChange: callbacks.onStatusChange,
      onAuthoritativeRefetch: callbacks.onAuthoritativeRefetch,
    });
  }
}
