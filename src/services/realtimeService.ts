import { getAuthToken } from '../utils/apiClient';
/**
 * Section 46: Central Real-Time Event Subscription & Transport Service.
 * Manages Server-Sent Events (SSE) connections, automatic reconnection with Last-Event-ID,
 * sequence gap detection, authoritative state reconciliation, and adaptive polling fallback.
 */
import { apiUrl } from '../utils/apiClient';
import type {
  RealtimeConnectionStatus,
  RealtimeEvent,
  RealtimeSubscriptionOptions,
} from '../types/realtime';

export class RealtimeService {
  /**
   * Subscribes to a real-time SSE event stream with automatic reconnection,
   * sequence gap reconciliation, and adaptive polling fallback.
   *
   * @returns Unsubscribe function to terminate the connection and clear timers.
   */
  static subscribe<T = unknown>(options: RealtimeSubscriptionOptions<T>): () => void {
    let closed = false;
    let eventSource: EventSource | null = null;
    let fallbackTimer: number | null = null;
    let lastSequenceSeen = 0;
    const seenEventIds = new Set<string>();
    const maxSeenHistory = 500;

    let retryAttempts = 0;
    const maxSseRetries = 3;

    const setStatus = (status: RealtimeConnectionStatus) => {
      if (!closed && options.onStatusChange) {
        options.onStatusChange(status);
      }
    };

    // Starts controlled adaptive polling fallback
    const startPollingFallback = () => {
      if (closed || fallbackTimer !== null) return;
      setStatus('FALLBACK_POLLING');

      const intervalMs = options.pollIntervalMs || 3000;
      fallbackTimer = window.setInterval(async () => {
        if (closed || document.visibilityState !== 'visible') return;

        try {
          if (options.onAuthoritativeRefetch) {
            await options.onAuthoritativeRefetch();
          }
        } catch {
          // Suppress polling error spam
        }
      }, intervalMs);
    };

    // Process structured RealtimeEvent with sequence validation & deduplication
    const processEvent = (rawEvt: Record<string, unknown>) => {
      // Extract normalized fields
      const evtId = (rawEvt.event_id || rawEvt.id || (rawEvt.event as any)?.id) as string;
      const seq = Number(rawEvt.sequence || (rawEvt.event as any)?.sequence || 0);

      // 1. Idempotency Check: Discard duplicates
      if (evtId && seenEventIds.has(evtId)) {
        return;
      }
      if (evtId) {
        seenEventIds.add(evtId);
        if (seenEventIds.size > maxSeenHistory) {
          const first = seenEventIds.values().next().value;
          if (first) seenEventIds.delete(first);
        }
      }

      // 2. Sequence Gap Detection
      if (seq > 0 && lastSequenceSeen > 0 && seq > lastSequenceSeen + 1) {
        // Gap detected! E.g., saw 101, next is 104. Trigger authoritative reconciliation
        if (options.onAuthoritativeRefetch) {
          options.onAuthoritativeRefetch();
        }
      }
      if (seq > 0) {
        lastSequenceSeen = Math.max(lastSequenceSeen, seq);
      }

      // Build typed event
      const eventType = (rawEvt.event_type || (rawEvt.event as any)?.event_type || 'UPDATE') as string;
      const normalized: RealtimeEvent = {
        schema_version: Number(rawEvt.schema_version || 1),
        event_id: evtId || `evt-${Date.now()}`,
        sequence: seq || lastSequenceSeen,
        event_type: eventType,
        resource_type: (rawEvt.resource_type || 'ANALYSIS_RUN') as string,
        resource_id: (rawEvt.resource_id || '') as string,
        job_id: rawEvt.job_id as string | undefined,
        analysis_run_id: rawEvt.analysis_run_id as string | undefined,
        investigation_id: rawEvt.investigation_id as string | undefined,
        report_id: rawEvt.report_id as string | undefined,
        workspace_id: (rawEvt.workspace_id || 'default') as string,
        stage: rawEvt.stage as string | undefined,
        status: (rawEvt.status || (rawEvt.event as any)?.task_status) as string | undefined,
        progress_percent: typeof rawEvt.progress_percent === 'number' ? rawEvt.progress_percent : undefined,
        message: (rawEvt.message || (rawEvt.event as any)?.message || '') as string,
        payload: (rawEvt.payload || (rawEvt.event as any)?.metadata || {}) as Record<string, unknown>,
        created_at: (rawEvt.created_at || (rawEvt.event as any)?.timestamp || new Date().toISOString()) as string,
      };

      options.onEvent(normalized);
    };

    // Establishes SSE connection with Last-Event-ID parameter
    const connectSSE = () => {
      if (closed) return;
      if (getAuthToken()) { startPollingFallback(); return; }

      try {
        let streamUrl = options.url.startsWith('http') ? options.url : apiUrl(options.url);
        if (lastSequenceSeen > 0) {
          const sep = streamUrl.includes('?') ? '&' : '?';
          streamUrl = `${streamUrl}${sep}last_event_id=${lastSequenceSeen}`;
        }

        setStatus(retryAttempts > 0 ? 'RECONNECTING' : 'CONNECTED');
        eventSource = new EventSource(streamUrl);

        eventSource.onopen = () => {
          if (closed) return;
          retryAttempts = 0;
          setStatus('CONNECTED');
          if (fallbackTimer !== null) {
            clearInterval(fallbackTimer);
            fallbackTimer = null;
          }
        };

        // Snapshot listener
        eventSource.addEventListener('snapshot', (e: MessageEvent) => {
          try {
            const data = JSON.parse(e.data);
            if (options.onSnapshot) options.onSnapshot(data);
          } catch {
            // ignore JSON parse error
          }
        });

        // Terminal event listener
        eventSource.addEventListener('terminal', (e: MessageEvent) => {
          try {
            const data = JSON.parse(e.data);
            const status = data.status || data.event_type || 'COMPLETED';
            if (options.onTerminal) options.onTerminal(status);
          } catch {
            if (options.onTerminal) options.onTerminal('COMPLETED');
          }
          cleanup();
        });

        // Generic event listener
        eventSource.addEventListener('event', (e: MessageEvent) => {
          try {
            const data = JSON.parse(e.data);
            processEvent(data);
          } catch {
            // ignore
          }
        });

        // Canonical message listener
        eventSource.onmessage = (e: MessageEvent) => {
          try {
            const data = JSON.parse(e.data);
            processEvent(data);
          } catch {
            // ignore
          }
        };

        // Specific named event types (Section 46 contract)
        const commonEventTypes = [
          'job_started', 'job_progress', 'job_completed', 'job_failed', 'job_cancelled', 'job_retry_scheduled',
          'analysis_started', 'analysis_stage_started', 'analysis_stage_completed', 'analysis_progress',
          'analysis_completed', 'analysis_partial', 'analysis_failed', 'analysis_cancelled',
          'finding_persisted', 'report_generation_started', 'report_ready', 'report_failed'
        ];

        commonEventTypes.forEach((evtName) => {
          eventSource?.addEventListener(evtName, (e: MessageEvent) => {
            try {
              const data = JSON.parse(e.data);
              processEvent(data);
            } catch {
              // ignore
            }
          });
        });

        eventSource.onerror = (err) => {
          if (closed) return;
          retryAttempts += 1;
          if (options.onError) options.onError(err);

          if (retryAttempts >= maxSseRetries) {
            // If SSE repeatedly errors (e.g. strict proxy or unsupported serverless edge), switch to polling
            if (eventSource) {
              eventSource.close();
              eventSource = null;
            }
            startPollingFallback();
          } else {
            setStatus('RECONNECTING');
          }
        };

      } catch (err) {
        if (!closed) {
          if (options.onError) options.onError(err);
          startPollingFallback();
        }
      }
    };

    connectSSE();

    // Cleanup function
    const cleanup = () => {
      closed = true;
      if (eventSource) {
        eventSource.close();
        eventSource = null;
      }
      if (fallbackTimer !== null) {
        clearInterval(fallbackTimer);
        fallbackTimer = null;
      }
      setStatus('DISCONNECTED');
    };

    return cleanup;
  }
}
