"""
Local Event Buffer for Section 31 Endpoint Agent Architecture.
Provides bounded in-memory storage, priority queueing, overflow policies,
retransmission tracking, and safe acknowledgment semantics.
"""

import threading
import time
import json
import logging
from typing import List, Dict, Any, Optional, Set
from datetime import datetime, timezone

from backend.schemas.endpoint_agent import (
    RawEndpointTelemetryEvent,
    EventPriorityEnum,
    BufferOverflowPolicyEnum
)

logger = logging.getLogger("cyberguard.agent.buffer")


PRIORITY_WEIGHTS = {
    EventPriorityEnum.CRITICAL: 4,
    EventPriorityEnum.HIGH: 3,
    EventPriorityEnum.NORMAL: 2,
    EventPriorityEnum.LOW: 1
}


class LocalEventBuffer:
    """
    Thread-safe, bounded, priority-aware buffer for host telemetry.
    Ensures that temporary network outages or backend backpressure do not
    cause unbounded endpoint memory growth.
    """

    def __init__(
        self,
        max_events: int = 5000,
        max_bytes: int = 20 * 1024 * 1024,  # 20 MB
        max_age_seconds: float = 86400.0,    # 24 hours
        overflow_policy: BufferOverflowPolicyEnum = BufferOverflowPolicyEnum.DROP_LOW_PRIORITY
    ):
        self.max_events = max_events
        self.max_bytes = max_bytes
        self.max_age_seconds = max_age_seconds
        self.overflow_policy = overflow_policy

        self._lock = threading.RLock()
        self._events: List[RawEndpointTelemetryEvent] = []
        self._inflight: Dict[str, RawEndpointTelemetryEvent] = {}  # event_id -> event (sent, awaiting ACK)
        self._total_bytes: int = 0

        # Metrics & observability
        self._total_appended: int = 0
        self._total_acknowledged: int = 0
        self._total_dropped: int = 0
        self._total_retried: int = 0
        self._drops_by_priority: Dict[str, int] = {p.value: 0 for p in EventPriorityEnum}

    def _estimate_event_size(self, event: RawEndpointTelemetryEvent) -> int:
        """Approximates payload memory size in bytes."""
        try:
            return len(json.dumps(event.model_dump(mode="json")).encode("utf-8"))
        except Exception:
            return 512

    def append(self, event: RawEndpointTelemetryEvent) -> bool:
        """
        Appends an event to the buffer.
        Applies overflow policies if capacity is exceeded.
        Returns True if event was stored, False if rejected.
        """
        with self._lock:
            # Purge expired items first
            self._discard_expired_locked()

            event_size = self._estimate_event_size(event)

            # Check capacity limits
            while (len(self._events) >= self.max_events or (self._total_bytes + event_size) > self.max_bytes):
                freed = self._handle_overflow(incoming_priority=event.priority)
                if not freed:
                    # Policy could not free space (e.g. BLOCK_COLLECTOR or all events higher priority)
                    logger.warning(f"Event {event.event_id} rejected by buffer overflow policy {self.overflow_policy}")
                    return False

            self._events.append(event)
            self._total_bytes += event_size
            self._total_appended += 1
            return True

    def _handle_overflow(self, incoming_priority: EventPriorityEnum) -> bool:
        """
        Applies configured overflow policy to free space.
        Returns True if at least one event was dropped to make room, False otherwise.
        """
        if not self._events:
            return False

        if self.overflow_policy == BufferOverflowPolicyEnum.BLOCK_COLLECTOR:
            return False

        if self.overflow_policy == BufferOverflowPolicyEnum.DROP_OLDEST:
            # Drop the oldest non-CRITICAL event if possible, or oldest event
            idx_to_drop = 0
            for idx, ev in enumerate(self._events):
                if ev.priority != EventPriorityEnum.CRITICAL:
                    idx_to_drop = idx
                    break
            dropped = self._events.pop(idx_to_drop)
            self._record_drop(dropped)
            return True

        if self.overflow_policy == BufferOverflowPolicyEnum.DROP_LOW_PRIORITY:
            # Look for lowest priority event with priority <= incoming
            target_p = None
            for p_candidate in [EventPriorityEnum.LOW, EventPriorityEnum.NORMAL, EventPriorityEnum.HIGH]:
                if PRIORITY_WEIGHTS[p_candidate] <= PRIORITY_WEIGHTS[incoming_priority]:
                    for idx, ev in enumerate(self._events):
                        if ev.priority == p_candidate:
                            target_p = idx
                            break
                    if target_p is not None:
                        break

            if target_p is not None:
                dropped = self._events.pop(target_p)
                self._record_drop(dropped)
                return True
            else:
                # If cannot find lower priority, drop oldest if incoming is CRITICAL
                if incoming_priority == EventPriorityEnum.CRITICAL:
                    dropped = self._events.pop(0)
                    self._record_drop(dropped)
                    return True
                return False

        return False

    def _record_drop(self, event: RawEndpointTelemetryEvent) -> None:
        size = self._estimate_event_size(event)
        self._total_bytes = max(0, self._total_bytes - size)
        self._total_dropped += 1
        self._drops_by_priority[event.priority.value] = self._drops_by_priority.get(event.priority.value, 0) + 1
        logger.warning(f"Buffer dropped event {event.event_id} (priority={event.priority.value})")

    def peek(self, max_count: int = 50) -> List[RawEndpointTelemetryEvent]:
        """
        Retrieves up to max_count events ordered by priority then event_time.
        Marks returned events as in-flight (awaiting server ACK).
        """
        with self._lock:
            if not self._events:
                return []

            # Sort candidate events: higher priority first, then older timestamp first
            sorted_candidates = sorted(
                self._events,
                key=lambda e: (-PRIORITY_WEIGHTS.get(e.priority, 2), e.event_time)
            )

            batch = sorted_candidates[:max_count]
            batch_ids = {e.event_id for e in batch}

            # Remove from pending queue and place into inflight
            self._events = [e for e in self._events if e.event_id not in batch_ids]
            for e in batch:
                self._inflight[e.event_id] = e

            return batch

    def acknowledge(self, event_ids: List[str]) -> int:
        """
        Server acknowledged receipt of batch.
        Permanently frees acknowledged events from in-flight and buffer.
        """
        with self._lock:
            acked_count = 0
            for eid in event_ids:
                if eid in self._inflight:
                    ev = self._inflight.pop(eid)
                    size = self._estimate_event_size(ev)
                    self._total_bytes = max(0, self._total_bytes - size)
                    acked_count += 1
                else:
                    # Also check if still in _events
                    for idx, ev in enumerate(self._events):
                        if ev.event_id == eid:
                            self._events.pop(idx)
                            size = self._estimate_event_size(ev)
                            self._total_bytes = max(0, self._total_bytes - size)
                            acked_count += 1
                            break

            self._total_acknowledged += acked_count
            return acked_count

    def retry(self, event_ids: List[str]) -> None:
        """
        Server failed to process or transport timed out.
        Returns in-flight events back to the active queue for subsequent retransmission.
        """
        with self._lock:
            for eid in event_ids:
                if eid in self._inflight:
                    ev = self._inflight.pop(eid)
                    self._events.insert(0, ev)
                    self._total_retried += 1

    def discard_expired(self, max_age_seconds: Optional[float] = None) -> int:
        """Discards events older than retention limit."""
        with self._lock:
            return self._discard_expired_locked(max_age_seconds)

    def _discard_expired_locked(self, max_age_seconds: Optional[float] = None) -> int:
        limit = max_age_seconds if max_age_seconds is not None else self.max_age_seconds
        now = datetime.now(timezone.utc)
        surviving = []
        expired_count = 0

        for ev in self._events:
            ev_dt = ev.event_time if ev.event_time.tzinfo else ev.event_time.replace(tzinfo=timezone.utc)
            age = (now - ev_dt).total_seconds()
            if age > limit and ev.priority != EventPriorityEnum.CRITICAL:
                self._record_drop(ev)
                expired_count += 1
            else:
                surviving.append(ev)

        self._events = surviving
        return expired_count

    def size(self) -> int:
        """Returns count of queued events (pending + inflight)."""
        with self._lock:
            return len(self._events) + len(self._inflight)

    def pending_count(self) -> int:
        """Returns count of events waiting to be transmitted."""
        with self._lock:
            return len(self._events)

    def inflight_count(self) -> int:
        """Returns count of events currently awaiting server ACK."""
        with self._lock:
            return len(self._inflight)

    def bytes_used(self) -> int:
        with self._lock:
            return self._total_bytes

    def health(self) -> Dict[str, Any]:
        """Provides telemetry buffer operational health metrics."""
        with self._lock:
            utilization_pct = round((len(self._events) / max(1, self.max_events)) * 100.0, 2)
            bytes_utilization_pct = round((self._total_bytes / max(1, self.max_bytes)) * 100.0, 2)

            return {
                "pending_events": len(self._events),
                "inflight_events": len(self._inflight),
                "total_size": len(self._events) + len(self._inflight),
                "max_events": self.max_events,
                "bytes_used": self._total_bytes,
                "max_bytes": self.max_bytes,
                "event_utilization_percent": utilization_pct,
                "bytes_utilization_percent": bytes_utilization_pct,
                "overflow_policy": self.overflow_policy.value,
                "total_appended": self._total_appended,
                "total_acknowledged": self._total_acknowledged,
                "total_dropped": self._total_dropped,
                "total_retried": self._total_retried,
                "drops_by_priority": dict(self._drops_by_priority),
                "under_pressure": utilization_pct > 80.0 or bytes_utilization_pct > 80.0
            }
