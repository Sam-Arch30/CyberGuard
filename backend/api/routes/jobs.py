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
            detail=f"Failed to submit background job: {str(e)}",
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
