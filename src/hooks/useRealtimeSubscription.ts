/**
 * Section 46: React Hook for Central Real-Time Subscriptions.
 * Provides live connection status, monotonic sequence tracking, event history,
 * and automatic cleanup on component unmount or route changes.
 */
import { useEffect, useRef, useState, useCallback } from 'react';
import { RealtimeService } from '../services/realtimeService';
import type {
  RealtimeConnectionStatus,
  RealtimeEvent,
} from '../types/realtime';

export interface UseRealtimeSubscriptionProps<T = unknown> {
  url: string | null | undefined;
  enabled?: boolean;
  onEvent?: (event: RealtimeEvent) => void;
  onSnapshot?: (snapshot: T) => void;
  onTerminal?: (status: string) => void;
  onAuthoritativeRefetch?: () => Promise<void> | void;
  pollIntervalMs?: number;
}

export function useRealtimeSubscription<T = unknown>({
  url,
  enabled = true,
  onEvent,
  onSnapshot,
  onTerminal,
  onAuthoritativeRefetch,
  pollIntervalMs = 3000,
}: UseRealtimeSubscriptionProps<T>) {
  const [status, setStatus] = useState<RealtimeConnectionStatus>('DISCONNECTED');
  const [lastEvent, setLastEvent] = useState<RealtimeEvent | null>(null);
  const [eventHistory, setEventHistory] = useState<RealtimeEvent[]>([]);

  const cleanupRef = useRef<(() => void) | null>(null);

  // Callbacks refs to prevent re-subscribing on inline closures
  const onEventRef = useRef(onEvent);
  onEventRef.current = onEvent;

  const onSnapshotRef = useRef(onSnapshot);
  onSnapshotRef.current = onSnapshot;

  const onTerminalRef = useRef(onTerminal);
  onTerminalRef.current = onTerminal;

  const onRefetchRef = useRef(onAuthoritativeRefetch);
  onRefetchRef.current = onAuthoritativeRefetch;

  const startSubscription = useCallback(() => {
    if (cleanupRef.current) {
      cleanupRef.current();
      cleanupRef.current = null;
    }

    if (!url || !enabled) {
      setStatus('DISCONNECTED');
      return;
    }

    const unsub = RealtimeService.subscribe<T>({
      url,
      onEvent: (event) => {
        setLastEvent(event);
        setEventHistory((prev) => [event, ...prev.slice(0, 49)]);
        if (onEventRef.current) {
          onEventRef.current(event);
        }
      },
      onSnapshot: (snapshot) => {
        if (onSnapshotRef.current) {
          onSnapshotRef.current(snapshot);
        }
      },
      onTerminal: (termStatus) => {
        if (onTerminalRef.current) {
          onTerminalRef.current(termStatus);
        }
      },
      onStatusChange: (newStatus) => {
        setStatus(newStatus);
      },
      onAuthoritativeRefetch: () => {
        if (onRefetchRef.current) {
          return onRefetchRef.current();
        }
      },
      pollIntervalMs,
    });

    cleanupRef.current = unsub;
  }, [url, enabled, pollIntervalMs]);

  useEffect(() => {
    startSubscription();

    return () => {
      if (cleanupRef.current) {
        cleanupRef.current();
        cleanupRef.current = null;
      }
    };
  }, [startSubscription]);

  // Handle document visibility change: if tab becomes active after backgrounding, check state
  useEffect(() => {
    const handleVisibilityChange = () => {
      if (document.visibilityState === 'visible' && enabled && url) {
        if (onRefetchRef.current) {
          onRefetchRef.current();
        }
      }
    };

    document.addEventListener('visibilitychange', handleVisibilityChange);
    return () => {
      document.removeEventListener('visibilitychange', handleVisibilityChange);
    };
  }, [enabled, url]);

  return {
    status,
    isLive: status === 'CONNECTED',
    isReconnecting: status === 'RECONNECTING',
    isPolling: status === 'FALLBACK_POLLING',
    lastEvent,
    eventHistory,
    reconnect: startSubscription,
  };
}
