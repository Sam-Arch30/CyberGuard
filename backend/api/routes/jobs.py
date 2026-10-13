"""
Section 45: REST API endpoints for Asynchronous Background Jobs & Lifecycle Management.
Provides endpoints to submit, inspect, stream events, cancel, and retry jobs with tenant isolation.
"""
from __future__ import annotations

import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.schemas.jobs import (
    JobSubmitRequest,
    JobReadResponse,
    JobEventRead,
    JobListResponse,
    JobMetricsSummary,
    JobActionResponse,
)
from backend.services.background_job_service import (
    BackgroundJobService,
    JobNotFoundError,
    InvalidJobStateTransitionError,
)

logger = logging.getLogger("cyberguard.api.jobs")

router = APIRouter(prefix="/api/jobs", tags=["Background Jobs"])


@router.post(
    "",
    response_model=JobReadResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Submit Background Job",
    description="Submits an asynchronous job for background processing with idempotency support and tenant isolation.",
)
def submit_job(
    request: JobSubmitRequest,
    x_user: Optional[str] = Header(None, alias="X-User"),
    x_workspace_id: Optional[str] = Header("default", alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
):
    user_name = (x_user or "SOC Analyst").strip()
    workspace = (x_workspace_id or "default").strip()

    try:
        job, created = BackgroundJobService.submit_job(
            db=db,
            job_type=request.job_type.value,
            workspace_id=workspace,
            requested_by=user_name,
            resource_type=request.resource_type,
            resource_id=request.resource_id,
            analysis_run_id=request.analysis_run_id,
            report_id=request.report_id,
            priority=request.priority.value,
            payload=request.payload,
            idempotency_key=request.idempotency_key,
            timeout_seconds=request.timeout_seconds,
            max_attempts=request.max_attempts,
        )
        return BackgroundJobService.serialize_job(job, include_events=True)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        logger.error("Job submission failed: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail='Failed to submit background job.',
        )


@router.get(
    "",
    response_model=JobListResponse,
    summary="List Background Jobs",
    description="Returns a paginated list of background jobs filtered by status, job type, or resource reference.",
)
def list_jobs(
    status: Optional[str] = Query(None, description="Filter by job status (QUEUED, RUNNING, SUCCEEDED, etc.)"),
    job_type: Optional[str] = Query(None, description="Filter by registered job type"),
    resource_id: Optional[str] = Query(None, description="Filter by associated resource ID"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(25, ge=1, le=100, description="Items per page"),
    x_workspace_id: Optional[str] = Header("default", alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
):
    workspace = (x_workspace_id or "default").strip()
    return BackgroundJobService.list_jobs(
        db=db,
        workspace_id=workspace,
        status=status,
        job_type=job_type,
        resource_id=resource_id,
        page=page,
        page_size=page_size,
    )


@router.get(
    "/metrics/summary",
    response_model=JobMetricsSummary,
    summary="Get Background Job Metrics Summary",
    description="Returns aggregated operational observability metrics including queued, running, succeeded, failed, and dead-letter counts.",
)
def get_metrics_summary(
    x_workspace_id: Optional[str] = Header("default", alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
):
    workspace = (x_workspace_id or "default").strip()
    return BackgroundJobService.get_metrics_summary(db=db, workspace_id=workspace)


@router.get(
    "/{job_id}",
    response_model=JobReadResponse,
    summary="Get Job Status and Execution Details",
    description="Returns the current status, stage, progress, timestamps, and output references for a specific job.",
)
def get_job(
    job_id: str,
    x_workspace_id: Optional[str] = Header("default", alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
):
    workspace = (x_workspace_id or "default").strip()
    job = BackgroundJobService.get_job(db=db, job_id=job_id, workspace_id=workspace)
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Background job '{job_id}' not found in workspace '{workspace}'.",
        )
    return BackgroundJobService.serialize_job(job, include_events=True)


@router.get(
    "/{job_id}/events",
    response_model=List[JobEventRead],
    summary="Get Job Audit Events",
    description="Returns chronological state transitions and progress milestone events emitted during job lifecycle.",
)
def get_job_events(
    job_id: str,
    x_workspace_id: Optional[str] = Header("default", alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
):
    workspace = (x_workspace_id or "default").strip()
    job = BackgroundJobService.get_job(db=db, job_id=job_id, workspace_id=workspace)
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Background job '{job_id}' not found in workspace '{workspace}'.",
        )
    serialized = BackgroundJobService.serialize_job(job, include_events=True)
    return serialized.events or []


@router.post(
    "/{job_id}/cancel",
    response_model=JobActionResponse,
    summary="Cancel Background Job",
    description="Cancels a queued job or dispatches a cooperative cancellation signal to the executing worker.",
)
def cancel_job(
    job_id: str,
    reason: Optional[str] = Query(None, description="Optional cancellation justification"),
    x_workspace_id: Optional[str] = Header("default", alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
):
    workspace = (x_workspace_id or "default").strip()
    try:
        return BackgroundJobService.cancel_job(
            db=db,
            job_id=job_id,
            workspace_id=workspace,
            reason=reason,
        )
    except JobNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Background job '{job_id}' not found in workspace '{workspace}'.",
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.post(
    "/{job_id}/retry",
    response_model=JobActionResponse,
    summary="Retry Background Job",
    description="Resets attempt budget and requeues a failed, timed-out, or dead-lettered job.",
)
def retry_job(
    job_id: str,
    x_workspace_id: Optional[str] = Header("default", alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
):
    workspace = (x_workspace_id or "default").strip()
    try:
        return BackgroundJobService.retry_job(
            db=db,
            job_id=job_id,
            workspace_id=workspace,
        )
    except JobNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Background job '{job_id}' not found in workspace '{workspace}'.",
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.get(
    "/{job_id}/stream",
    summary="Stream Background Job Events (SSE - Section 46)",
    description="Provides real-time Server-Sent Events stream for a specific BackgroundJob with tenant isolation, Last-Event-ID replay, and keepalive heartbeats.",
)
async def stream_job_events(
    job_id: str,
    last_event_id: Optional[str] = Header(None, alias="Last-Event-ID"),
    last_event_query: Optional[str] = Query(None, alias="last_event_id"),
    x_workspace_id: Optional[str] = Header("default", alias="X-Workspace-ID"),
    workspace_id_query: Optional[str] = Query(None, alias="workspace_id"),
    db: Session = Depends(get_db),
):
    import asyncio
    import json
    from fastapi.responses import StreamingResponse
    from backend.services.realtime_service import global_realtime_hub

    workspace = (workspace_id_query or x_workspace_id or "default").strip()

    job = BackgroundJobService.get_job(db=db, job_id=job_id, workspace_id=workspace)
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Background job '{job_id}' not found in workspace '{workspace}'.",
        )

    # Initial snapshot
    initial_snapshot = BackgroundJobService.serialize_job(job, include_events=True).model_dump(mode="json")

    # Determine replay cursor
    raw_cursor = last_event_id or last_event_query
    since_seq = 0
    if raw_cursor:
        try:
            since_seq = int(raw_cursor)
        except (ValueError, TypeError):
            since_seq = 0

    async def event_generator():
        # 1. Send authoritative snapshot immediately
        yield f"event: snapshot\ndata: {json.dumps(initial_snapshot)}\n\n"

        # 2. Replay missed events from database if client reconnected with Last-Event-ID
        if since_seq > 0:
            missed_events = global_realtime_hub.replay_job_events(
                db=db,
                job_id=job_id,
                since_sequence=since_seq,
            )
            for m_evt in missed_events:
                yield f"id: {m_evt.sequence}\nevent: {m_evt.event_type.lower()}\ndata: {json.dumps(m_evt.model_dump(mode='json'))}\n\n"

        # If already terminal, emit terminal status and terminate
        if job.status in ("SUCCEEDED", "PARTIALLY_SUCCEEDED", "FAILED", "CANCELLED", "TIMED_OUT", "DEAD_LETTER"):
            yield f"event: terminal\ndata: {json.dumps({'status': job.status, 'job_id': job.id})}\n\n"
            return

        # 3. Subscribe to real-time event hub for this job
        queue = await global_realtime_hub.subscribe(f"job:{job_id}")
        try:
            while True:
                try:
                    # Wait for next event or 15s keepalive ping
                    msg = await asyncio.wait_for(queue.get(), timeout=15.0)

                    seq = msg.get("sequence") or ""
                    evt_type = msg.get("event_type") or "job_progress"

                    id_line = f"id: {seq}\n" if seq else ""
                    yield f"{id_line}event: {str(evt_type).lower()}\ndata: {json.dumps(msg)}\n\n"

                    # Check for terminal state
                    if evt_type in (
                        "JOB_SUCCEEDED", "JOB_COMPLETED", "JOB_PARTIALLY_COMPLETED",
                        "JOB_FAILED", "JOB_CANCELLED", "JOB_TIMED_OUT", "JOB_DEAD_LETTER"
                    ):
                        yield f"event: terminal\ndata: {json.dumps({'event_type': evt_type, 'status': msg.get('status')})}\n\n"
                        break

                except asyncio.TimeoutError:
                    # Keepalive heartbeat ping
                    yield ": keepalive\n\n"

        finally:
            await global_realtime_hub.unsubscribe(f"job:{job_id}", queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get(
    "/stream",
    summary="Stream Workspace Background Jobs (SSE - Section 46)",
    description="Provides real-time Server-Sent Events stream for background jobs in a tenant workspace.",
)
async def stream_workspace_jobs(
    x_workspace_id: Optional[str] = Header("default", alias="X-Workspace-ID"),
    workspace_id_query: Optional[str] = Query(None, alias="workspace_id"),
    db: Session = Depends(get_db),
):
    import asyncio
    import json
    from fastapi.responses import StreamingResponse
    from backend.services.realtime_service import global_realtime_hub

    workspace = (workspace_id_query or x_workspace_id or "default").strip()
    channel = f"workspace:{workspace}"

    async def event_generator():
        yield f"event: connected\ndata: {json.dumps({'workspace_id': workspace, 'channel': channel})}\n\n"

        queue = await global_realtime_hub.subscribe(channel)
        try:
            while True:
                try:
                    msg = await asyncio.wait_for(queue.get(), timeout=15.0)
                    evt_type = msg.get("event_type") or "message"
                    yield f"event: {str(evt_type).lower()}\ndata: {json.dumps(msg)}\n\n"
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        finally:
            await global_realtime_hub.unsubscribe(channel, queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
