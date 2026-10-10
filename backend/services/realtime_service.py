"""
Section 46: Real-Time Event Hub, Publisher & Reconnection Replay Service.
Provides centralized pub/sub broadcasting, monotonic sequence ordering,
database-backed event persistence, bounded subscriber queues with backpressure,
and resilient event replay for live analysis and background jobs.
"""
from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, AsyncGenerator, Dict, List, Optional, Set
from sqlalchemy import func, text
from sqlalchemy.orm import Session

from backend.db.models import (
    AnalysisEventModel,
    AnalysisRunModel,
    BackgroundJobEventModel,
    BackgroundJobModel,
    ReportModel,
    get_utc_now,
)
from backend.schemas.realtime import (
    RealtimeEvent,
    RealtimeEventTypeEnum,
    RealtimeResourceScopeEnum,
)

logger = logging.getLogger("cyberguard.services.realtime")

# Set of terminal event types that must never be dropped under backpressure
TERMINAL_EVENT_TYPES: Set[str] = {
    RealtimeEventTypeEnum.ANALYSIS_COMPLETED.value,
    RealtimeEventTypeEnum.ANALYSIS_PARTIAL.value,
    RealtimeEventTypeEnum.ANALYSIS_FAILED.value,
    RealtimeEventTypeEnum.ANALYSIS_CANCELLED.value,
    RealtimeEventTypeEnum.JOB_COMPLETED.value,
    RealtimeEventTypeEnum.JOB_PARTIALLY_COMPLETED.value,
    RealtimeEventTypeEnum.JOB_FAILED.value,
    RealtimeEventTypeEnum.JOB_CANCELLED.value,
    RealtimeEventTypeEnum.JOB_TIMED_OUT.value,
    RealtimeEventTypeEnum.REPORT_READY.value,
    RealtimeEventTypeEnum.REPORT_FAILED.value,
}


def sanitize_payload(payload: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Sanitizes event payloads:
    Removes credentials, auth tokens, passwords, raw EML bytes, full email bodies.
    Restricts string lengths and truncates oversized elements to avoid memory/network issues.
    """
    if not payload:
        return {}

    sanitized: Dict[str, Any] = {}
    sensitive_keys = {
        "password", "secret", "token", "auth", "api_key", "authorization",
        "private_key", "cookie", "session_id", "body_raw", "raw_eml", "bytes",
    }

    for k, v in payload.items():
        low_k = str(k).lower()
        if any(s in low_k for s in sensitive_keys):
            sanitized[k] = "[REDACTED]"
            continue

        if isinstance(v, (str, bytes)):
            s_val = str(v)
            if len(s_val) > 1000:
                sanitized[k] = s_val[:997] + "..."
            else:
                sanitized[k] = s_val
        elif isinstance(v, (int, float, bool)) or v is None:
            sanitized[k] = v
        elif isinstance(v, list):
            # Limit list size in payloads
            sanitized[k] = [
                str(item)[:200] if isinstance(item, (str, bytes)) else item
                for item in v[:20]
            ]
        elif isinstance(v, dict):
            sanitized[k] = sanitize_payload(v)
        else:
            sanitized[k] = str(v)[:200]

    return sanitized


class RealtimeEventHub:
    """
    Central real-time pub/sub hub supporting resource-scoped topic subscriptions,
    bounded subscriber queues, monotonic event sequences, and replay.
    """

    def __init__(self):
        # Maps channel (e.g., 'run:123', 'job:456', 'workspace:default') to sets of subscriber Queues
        self._subscribers: Dict[str, Set[asyncio.Queue]] = {}
        self._lock = asyncio.Lock()
        # In-memory highest sequence cache per resource to ensure monotonic progression
        self._sequence_cache: Dict[str, int] = {}

    async def subscribe(self, channel: str, max_queue_size: int = 100) -> asyncio.Queue:
        """Subscribes an async queue to a specific channel topic."""
        queue: asyncio.Queue = asyncio.Queue(maxsize=max_queue_size)
        async with self._lock:
            if channel not in self._subscribers:
                self._subscribers[channel] = set()
            self._subscribers[channel].add(queue)
        logger.debug("Subscribed to channel %s (total subscribers: %d)", channel, len(self._subscribers[channel]))
        return queue

    async def unsubscribe(self, channel: str, queue: asyncio.Queue) -> None:
        """Unsubscribes a queue from a channel topic and cleans up empty sets."""
        async with self._lock:
            if channel in self._subscribers:
                self._subscribers[channel].discard(queue)
                if not self._subscribers[channel]:
                    del self._subscribers[channel]
        logger.debug("Unsubscribed from channel %s", channel)

    def get_next_sequence(self, db: Session, resource_type: str, resource_id: str) -> int:
        """
        Calculates monotonically increasing sequence number for a resource.
        Initializes from database MAX(sequence) if not in memory.
        """
        cache_key = f"{resource_type}:{resource_id}"
        if cache_key in self._sequence_cache:
            self._sequence_cache[cache_key] += 1
            return self._sequence_cache[cache_key]

        # Query database for current highest sequence
        max_seq = 0
        try:
            if resource_type == RealtimeResourceScopeEnum.ANALYSIS_RUN.value:
                res = db.query(func.max(AnalysisEventModel.sequence)).filter(
                    AnalysisEventModel.analysis_run_id == resource_id
                ).scalar()
                max_seq = int(res) if res is not None else 0
            elif resource_type == RealtimeResourceScopeEnum.JOB.value:
                res = db.query(func.max(BackgroundJobEventModel.sequence)).filter(
                    BackgroundJobEventModel.job_id == resource_id
                ).scalar()
                max_seq = int(res) if res is not None else 0
        except Exception as e:
            logger.warning("Failed to query max sequence from DB for %s: %s", cache_key, e)
            max_seq = 0

        self._sequence_cache[cache_key] = max_seq + 1
        return self._sequence_cache[cache_key]

    async def broadcast(self, event: RealtimeEvent) -> None:
        """
        Broadcasts an event across all applicable topic channels:
        - run:{analysis_run_id}
        - job:{job_id}
        - investigation:{investigation_id}
        - report:{report_id}
        - workspace:{workspace_id}
        """
        target_channels: List[str] = []
        if event.analysis_run_id:
            target_channels.append(f"run:{event.analysis_run_id}")
        if event.job_id:
            target_channels.append(f"job:{event.job_id}")
        if event.investigation_id:
            target_channels.append(f"investigation:{event.investigation_id}")
        if event.report_id:
            target_channels.append(f"report:{event.report_id}")
        if event.workspace_id:
            target_channels.append(f"workspace:{event.workspace_id}")

        # Targeted resource channel
        if event.resource_type and event.resource_id:
            res_ch = f"{event.resource_type.lower()}:{event.resource_id}"
            if res_ch not in target_channels:
                target_channels.append(res_ch)

        # Collect distinct subscriber queues
        target_queues: Set[asyncio.Queue] = set()
        async with self._lock:
            for ch in target_channels:
                if ch in self._subscribers:
                    target_queues.update(self._subscribers[ch])

        if not target_queues:
            return

        is_terminal = event.event_type in TERMINAL_EVENT_TYPES
        event_dict = event.model_dump(mode="json")

        for q in target_queues:
            try:
                q.put_nowait(event_dict)
            except asyncio.QueueFull:
                if is_terminal:
                    # Under backpressure, discard oldest item to ensure terminal event is received
                    try:
                        q.get_nowait()
                    except asyncio.QueueEmpty:
                        pass
                    try:
                        q.put_nowait(event_dict)
                    except asyncio.QueueFull:
                        pass
                else:
                    # Drop non-terminal progress update to respect backpressure
                    pass

    async def publish(self, channel: str, event: RealtimeEvent) -> None:
        """Publishes an event to a channel topic (and across all associated scopes)."""
        await self.broadcast(event)

    def get_subscriber_count(self, channel: str) -> int:
        """Returns the number of active subscribers on a channel."""
        return len(self._subscribers.get(channel, set()))

    def get_replay_events(
        self,
        db: Session,
        channel: str,
        last_event_id: int = 0,
        limit: int = 100,
    ) -> List[RealtimeEvent]:
        """Dispatches event replay by channel scope."""
        if channel.startswith("run:"):
            run_id = channel.split("run:", 1)[1]
            return self.replay_analysis_events(db, run_id, since_sequence=last_event_id, limit=limit)
        elif channel.startswith("job:"):
            job_id = channel.split("job:", 1)[1]
            return self.replay_job_events(db, job_id, since_sequence=last_event_id, limit=limit)
        return []

    def replay_analysis_events(
        self,
        db: Session,
        run_id: str,
        since_sequence: int = 0,
        limit: int = 100,
    ) -> List[RealtimeEvent]:
        """
        Replays missed analysis events from the authoritative database log.
        Used on client reconnection via Last-Event-ID or sequence gap detection.
        """
        query = (
            db.query(AnalysisEventModel)
            .filter(
                AnalysisEventModel.analysis_run_id == run_id,
                AnalysisEventModel.sequence > since_sequence,
            )
            .order_by(AnalysisEventModel.sequence.asc())
            .limit(limit)
        )
        db_events = query.all()

        replayed: List[RealtimeEvent] = []
        for e in db_events:
            meta = {}
            if e.metadata_json:
                try:
                    meta = json.loads(e.metadata_json)
                except Exception:
                    pass

            replayed.append(
                RealtimeEvent(
                    schema_version=1,
                    event_id=e.id,
                    sequence=e.sequence,
                    event_type=e.event_type,
                    resource_type=RealtimeResourceScopeEnum.ANALYSIS_RUN.value,
                    resource_id=run_id,
                    analysis_run_id=run_id,
                    stage=e.task_status or "EXECUTING",
                    status=e.task_status,
                    message=e.message,
                    payload=sanitize_payload(meta),
                    created_at=e.timestamp,
                )
            )
        return replayed

    def replay_job_events(
        self,
        db: Session,
        job_id: str,
        since_sequence: int = 0,
        limit: int = 100,
    ) -> List[RealtimeEvent]:
        """
        Replays missed background job events from the authoritative database log.
        """
        query = (
            db.query(BackgroundJobEventModel)
            .filter(
                BackgroundJobEventModel.job_id == job_id,
                BackgroundJobEventModel.sequence > since_sequence,
            )
            .order_by(BackgroundJobEventModel.sequence.asc())
            .limit(limit)
        )
        db_events = query.all()

        replayed: List[RealtimeEvent] = []
        for e in db_events:
            meta = {}
            if e.metadata_json:
                try:
                    meta = json.loads(e.metadata_json)
                except Exception:
                    pass

            replayed.append(
                RealtimeEvent(
                    schema_version=1,
                    event_id=e.id,
                    sequence=e.sequence,
                    event_type=e.event_type,
                    resource_type=RealtimeResourceScopeEnum.JOB.value,
                    resource_id=job_id,
                    job_id=job_id,
                    workspace_id=e.workspace_id,
                    stage=e.stage,
                    progress_percent=e.progress_percent,
                    message=e.message,
                    payload=sanitize_payload(meta),
                    created_at=e.timestamp,
                )
            )
        return replayed


# Singleton hub instance
global_realtime_hub = RealtimeEventHub()


class RealtimePublisher:
    """
    High-level publishing API that guarantees:
    1. Database state persistence is completed first.
    2. Monotonic sequence is assigned.
    3. Payload is sanitized (no credentials or raw bytes).
    4. Event is broadcast to connected subscribers without blocking.
    5. Failures in event delivery NEVER cause background job or analysis failure.
    """

    @classmethod
    def emit_analysis_event(
        cls,
        db: Session,
        run_id: str,
        event_type: str,
        message: str,
        task_id: Optional[str] = None,
        task_status: Optional[str] = None,
        result_count: int = 0,
        error: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        investigation_id: Optional[str] = None,
        workspace_id: str = "default",
    ) -> Optional[AnalysisEventModel]:
        """
        Atomically persists an analysis event and publishes to real-time subscribers.
        """
        try:
            seq = global_realtime_hub.get_next_sequence(
                db=db,
                resource_type=RealtimeResourceScopeEnum.ANALYSIS_RUN.value,
                resource_id=run_id,
            )
            now = get_utc_now()
            evt = AnalysisEventModel(
                id=str(uuid.uuid4()),
                analysis_run_id=run_id,
                task_id=task_id,
                event_type=event_type,
                sequence=seq,
                timestamp=now,
                task_status=task_status,
                message=message,
                result_count=result_count,
                error=error,
                metadata_json=json.dumps(metadata or {}),
            )
            db.add(evt)
            db.commit()

            # Non-blocking real-time broadcast
            clean_payload = sanitize_payload(metadata or {})
            if result_count:
                clean_payload["result_count"] = result_count
            if task_id:
                clean_payload["task_id"] = task_id
            if error:
                clean_payload["error"] = error

            realtime_event = RealtimeEvent(
                schema_version=1,
                event_id=evt.id,
                sequence=seq,
                event_type=event_type,
                resource_type=RealtimeResourceScopeEnum.ANALYSIS_RUN.value,
                resource_id=run_id,
                analysis_run_id=run_id,
                investigation_id=investigation_id,
                workspace_id=workspace_id,
                stage=task_status or "EXECUTING",
                status=task_status,
                message=message,
                payload=clean_payload,
                created_at=now,
            )

            # Fire and forget async broadcast
            cls._async_broadcast(realtime_event)
            return evt

        except Exception as e:
            logger.warning("Failed to emit analysis event for run %s: %s", run_id, e)
            return None

    @classmethod
    def emit_job_event(
        cls,
        db: Session,
        job_id: str,
        event_type: str,
        message: str,
        workspace_id: str = "default",
        stage: Optional[str] = None,
        progress_percent: Optional[float] = None,
        metadata: Optional[Dict[str, Any]] = None,
        analysis_run_id: Optional[str] = None,
        investigation_id: Optional[str] = None,
        report_id: Optional[str] = None,
        status: Optional[str] = None,
    ) -> Optional[BackgroundJobEventModel]:
        """
        Atomically persists a job event and publishes to real-time subscribers.
        """
        try:
            seq = global_realtime_hub.get_next_sequence(
                db=db,
                resource_type=RealtimeResourceScopeEnum.JOB.value,
                resource_id=job_id,
            )
            now = get_utc_now()
            evt = BackgroundJobEventModel(
                id=str(uuid.uuid4()),
                job_id=job_id,
                workspace_id=workspace_id,
                event_type=event_type,
                sequence=seq,
                stage=stage,
                progress_percent=progress_percent,
                message=message,
                metadata_json=json.dumps(metadata or {}),
                timestamp=now,
            )
            db.add(evt)
            db.commit()

            clean_payload = sanitize_payload(metadata or {})
            if progress_percent is not None:
                clean_payload["progress_percent"] = progress_percent
            if stage:
                clean_payload["stage"] = stage

            realtime_event = RealtimeEvent(
                schema_version=1,
                event_id=evt.id,
                sequence=seq,
                event_type=event_type,
                resource_type=RealtimeResourceScopeEnum.JOB.value,
                resource_id=job_id,
                job_id=job_id,
                analysis_run_id=analysis_run_id,
                investigation_id=investigation_id,
                report_id=report_id,
                workspace_id=workspace_id,
                stage=stage,
                status=status,
                progress_percent=progress_percent,
                message=message,
                payload=clean_payload,
                created_at=now,
            )

            cls._async_broadcast(realtime_event)
            return evt

        except Exception as e:
            logger.warning("Failed to emit job event for job %s: %s", job_id, e)
            return None

    @classmethod
    def publish_event(
        cls,
        db: Session,
        topic: str,
        event_type: str,
        resource_type: str,
        resource_id: str,
        message: str,
        workspace_id: str = "default",
        payload: Optional[Dict[str, Any]] = None,
        persist_job_event: bool = False,
    ) -> Optional[Any]:
        """Convenience publisher method that isolates delivery errors and guarantees non-blocking execution."""
        try:
            if persist_job_event and resource_type == "JOB":
                return cls.emit_job_event(
                    db=db,
                    job_id=resource_id,
                    event_type=event_type,
                    message=message,
                    workspace_id=workspace_id,
                    metadata=payload,
                )
            evt = RealtimeEvent(
                schema_version=1,
                event_id=str(uuid.uuid4()),
                sequence=1,
                event_type=event_type,
                resource_type=resource_type,
                resource_id=resource_id,
                workspace_id=workspace_id,
                message=message,
                payload=payload or {},
            )
            cls._async_broadcast(evt)
            return evt
        except Exception as e:
            logger.warning("Failure isolated in publish_event: %s", e)
            return None

    @classmethod
    def publish_to_workspace(cls, workspace_id: str, event: RealtimeEvent) -> None:
        """Broadcasts a realtime event to subscribers scoped to workspace."""
        try:
            event.workspace_id = workspace_id
            cls._async_broadcast(event)
        except Exception as e:
            logger.warning("Failure isolated in publish_to_workspace: %s", e)

    @classmethod
    def _async_broadcast(cls, event: RealtimeEvent) -> None:
        """Schedules broadcast in running event loop safely."""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.create_task(global_realtime_hub.broadcast(event))
        except Exception:
            pass

