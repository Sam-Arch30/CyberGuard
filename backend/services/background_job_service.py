"""
Section 45: Persistent Background Job Submission, Lifecycle Management & Observability Service.
Guarantees transactional consistency, state transition validation, bounded querying, and tenant isolation.
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple
from sqlalchemy import func, desc
from sqlalchemy.orm import Session

from backend.db.models import (
    BackgroundJobModel,
    BackgroundJobEventModel,
    AnalysisRunModel,
    ReportModel,
    get_utc_now,
)
from backend.schemas.jobs import (
    JobTypeEnum,
    JobStatusEnum,
    JobPriorityEnum,
    PRIORITY_WEIGHTS,
    JobSubmitRequest,
    JobReadResponse,
    JobEventRead,
    JobListResponse,
    JobMetricsSummary,
    JobActionResponse,
)
from backend.services.realtime_service import RealtimePublisher

logger = logging.getLogger("cyberguard.services.background_job")

# Supported default timeouts (in seconds) per job type
DEFAULT_JOB_TIMEOUTS: Dict[str, int] = {
    JobTypeEnum.ARTIFACT_ANALYSIS.value: 300,
    JobTypeEnum.REPORT_GENERATION.value: 120,
    JobTypeEnum.CROSS_INCIDENT_CORRELATION.value: 180,
    JobTypeEnum.ATTACK_PATH_RECONSTRUCTION.value: 180,
    JobTypeEnum.ENDPOINT_TELEMETRY_PROCESSING.value: 120,
    JobTypeEnum.EVIDENCE_EXPORT.value: 180,
    JobTypeEnum.MAINTENANCE.value: 600,
    JobTypeEnum.INCIDENT_SLA_EVALUATION.value: 120,
    JobTypeEnum.INCIDENT_ESCALATION.value: 120,
    JobTypeEnum.WATCHLIST_MONITORING_CYCLE.value: 300,
    JobTypeEnum.WATCHLIST_REFRESH.value: 180,
    JobTypeEnum.WATCHED_INDICATOR_CHECK.value: 60,
    JobTypeEnum.THREAT_HUNT_EXECUTION.value: 300,
    JobTypeEnum.ADVANCED_PIVOT_EXECUTION.value: 300,
    JobTypeEnum.DETECTION_RULE_BACKTEST.value: 300,
    JobTypeEnum.DETECTION_RULE_EVALUATION.value: 180,
}

# Legal lifecycle state transition matrix
LEGAL_TRANSITIONS: Dict[str, Set[str]] = {
    JobStatusEnum.QUEUED.value: {
        JobStatusEnum.SCHEDULED.value,
        JobStatusEnum.RUNNING.value,
        JobStatusEnum.CANCELLED.value,
    },
    JobStatusEnum.SCHEDULED.value: {
        JobStatusEnum.RUNNING.value,
        JobStatusEnum.CANCELLED.value,
    },
    JobStatusEnum.RUNNING.value: {
        JobStatusEnum.SUCCEEDED.value,
        JobStatusEnum.PARTIALLY_SUCCEEDED.value,
        JobStatusEnum.RETRY_WAIT.value,
        JobStatusEnum.FAILED.value,
        JobStatusEnum.CANCEL_REQUESTED.value,
        JobStatusEnum.TIMED_OUT.value,
        JobStatusEnum.DEAD_LETTER.value,
    },
    JobStatusEnum.RETRY_WAIT.value: {
        JobStatusEnum.SCHEDULED.value,
        JobStatusEnum.RUNNING.value,
        JobStatusEnum.CANCELLED.value,
    },
    JobStatusEnum.CANCEL_REQUESTED.value: {
        JobStatusEnum.CANCELLED.value,
        JobStatusEnum.SUCCEEDED.value,
        JobStatusEnum.PARTIALLY_SUCCEEDED.value,
        JobStatusEnum.FAILED.value,
        JobStatusEnum.TIMED_OUT.value,
        JobStatusEnum.DEAD_LETTER.value,
    },
    # Terminal states
    JobStatusEnum.SUCCEEDED.value: set(),
    JobStatusEnum.PARTIALLY_SUCCEEDED.value: set(),
    JobStatusEnum.FAILED.value: {JobStatusEnum.QUEUED.value},      # Via explicit retry action
    JobStatusEnum.CANCELLED.value: set(),
    JobStatusEnum.TIMED_OUT.value: {JobStatusEnum.QUEUED.value},   # Via explicit retry action
    JobStatusEnum.DEAD_LETTER.value: {JobStatusEnum.QUEUED.value}, # Via explicit retry action
}


class InvalidJobStateTransitionError(ValueError):
    """Raised when an illegal lifecycle transition is attempted."""
    pass


class JobNotFoundError(ValueError):
    """Raised when a referenced job is not found."""
    pass


class JobLifecycleManager:
    """Validates and applies state transitions to persistent background jobs."""

    @classmethod
    def validate_transition(cls, current_status: str, target_status: str) -> None:
        if current_status == target_status:
            return
        allowed = LEGAL_TRANSITIONS.get(current_status, set())
        if target_status not in allowed:
            raise InvalidJobStateTransitionError(
                f"Illegal job state transition from '{current_status}' to '{target_status}'. "
                f"Allowed target states: {sorted(list(allowed)) or 'None (terminal)'}."
            )

    @classmethod
    def transition(
        cls,
        db: Session,
        job: BackgroundJobModel,
        target_status: str,
        message: Optional[str] = None,
        stage: Optional[str] = None,
        progress_percent: Optional[float] = None,
        error_code: Optional[str] = None,
        sanitized_error: Optional[str] = None,
        result_json: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> BackgroundJobModel:
        """Applies transition with state audit event."""
        cls.validate_transition(job.status, target_status)
        now = get_utc_now()
        previous_status = job.status
        job.status = target_status
        job.updated_at = now

        if stage is not None:
            job.current_stage = stage
        if progress_percent is not None:
            job.progress_percent = progress_percent
        if error_code is not None:
            job.error_code = error_code
        if sanitized_error is not None:
            job.sanitized_error_message = sanitized_error
        if result_json is not None:
            job.result_json = json.dumps(result_json)

        if target_status == JobStatusEnum.RUNNING.value and not job.started_at:
            job.started_at = now
            job.heartbeat_at = now
            if not job.timeout_at:
                job.timeout_at = now + timedelta(seconds=job.timeout_seconds)

        if target_status in (
            JobStatusEnum.SUCCEEDED.value,
            JobStatusEnum.PARTIALLY_SUCCEEDED.value,
            JobStatusEnum.FAILED.value,
            JobStatusEnum.CANCELLED.value,
            JobStatusEnum.TIMED_OUT.value,
            JobStatusEnum.DEAD_LETTER.value,
        ):
            job.completed_at = now

        # Record auditable event and broadcast over real-time streams
        event_type = f"JOB_{target_status}"
        event = RealtimePublisher.emit_job_event(
            db=db,
            job_id=job.id,
            event_type=event_type,
            message=message or f"Job transitioned from {previous_status} to {target_status}.",
            workspace_id=job.workspace_id,
            stage=stage or job.current_stage,
            progress_percent=progress_percent if progress_percent is not None else job.progress_percent,
            metadata=metadata or {},
            analysis_run_id=job.analysis_run_id,
            investigation_id=job.resource_id if job.resource_type in ("INCIDENT", "INVESTIGATION") else None,
            report_id=job.report_id,
            status=target_status,
        )
        if not event:
            # Fallback direct creation
            event = BackgroundJobEventModel(
                job_id=job.id,
                workspace_id=job.workspace_id,
                event_type=event_type,
                sequence=1,
                stage=stage or job.current_stage,
                progress_percent=progress_percent if progress_percent is not None else job.progress_percent,
                message=message or f"Job transitioned from {previous_status} to {target_status}.",
                metadata_json=json.dumps(metadata or {}),
                timestamp=now,
            )
            db.add(event)
            db.flush()

        # Section 47: Dispatch notification on job failure
        if target_status == JobStatusEnum.FAILED.value:
            try:
                from backend.services.notification_service import NotificationService
                NotificationService.on_job_failed(
                    db=db,
                    job=job,
                    workspace_id=job.workspace_id,
                    error_message=sanitized_error,
                    investigation_id=job.resource_id if job.resource_type in ("INCIDENT", "INVESTIGATION") else None,
                )
            except Exception as ex:
                logger.warning("Failed to dispatch job failure notification: %s", ex)

        return job


class BackgroundJobService:
    """Central service managing background job submissions, queries, retries, and actions."""

    @classmethod
    def submit_job(
        cls,
        db: Session,
        job_type: str,
        workspace_id: str = "default",
        requested_by: str = "system",
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        analysis_run_id: Optional[str] = None,
        report_id: Optional[str] = None,
        priority: str = "NORMAL",
        payload: Optional[Dict[str, Any]] = None,
        idempotency_key: Optional[str] = None,
        timeout_seconds: Optional[int] = None,
        max_attempts: Optional[int] = None,
        scheduled_at: Optional[datetime] = None,
    ) -> Tuple[BackgroundJobModel, bool]:
        """
        Submits a job for background processing with idempotency check.
        Returns (job, created_flag).
        """
        # Validate job type
        valid_types = {t.value for t in JobTypeEnum}
        if job_type not in valid_types:
            raise ValueError(
                f"Unsupported job_type '{job_type}'. Registered job types: {sorted(list(valid_types))}."
            )

        # Idempotency check: if key provided, return active or existing job
        if idempotency_key:
            existing = (
                db.query(BackgroundJobModel)
                .filter(
                    BackgroundJobModel.workspace_id == workspace_id,
                    BackgroundJobModel.idempotency_key == idempotency_key,
                )
                .first()
            )
            if existing:
                # Active or already succeeded jobs are deduplicated
                if existing.status in (
                    JobStatusEnum.QUEUED.value,
                    JobStatusEnum.SCHEDULED.value,
                    JobStatusEnum.RUNNING.value,
                    JobStatusEnum.RETRY_WAIT.value,
                    JobStatusEnum.SUCCEEDED.value,
                    JobStatusEnum.PARTIALLY_SUCCEEDED.value,
                ):
                    logger.info(
                        "Deduplicated job submission with key '%s': returning existing job %s (%s)",
                        idempotency_key,
                        existing.id,
                        existing.status,
                    )
                    return existing, False

        # Compute priority weight and timeout
        prio_upper = priority.upper()
        prio_weight = PRIORITY_WEIGHTS.get(prio_upper, 2)
        effective_timeout = timeout_seconds or DEFAULT_JOB_TIMEOUTS.get(job_type, 300)
        effective_max_attempts = max_attempts if max_attempts is not None else 3
        now = get_utc_now()
        effective_scheduled_at = scheduled_at or now

        # Create job
        sanitized_payload = payload or {}
        # Ensure no accidental passwords/secrets stored in payload
        sanitized_payload_clean = {
            k: v for k, v in sanitized_payload.items()
            if not any(secret_term in k.lower() for secret_term in ("password", "secret", "token", "api_key", "credential"))
        }

        job = BackgroundJobModel(
            workspace_id=workspace_id,
            job_type=job_type,
            status=JobStatusEnum.QUEUED.value,
            priority=prio_upper,
            priority_weight=prio_weight,
            requested_by=requested_by,
            resource_type=resource_type,
            resource_id=resource_id,
            analysis_run_id=analysis_run_id,
            report_id=report_id,
            payload_json=json.dumps(sanitized_payload_clean),
            attempt_count=0,
            max_attempts=effective_max_attempts,
            created_at=now,
            scheduled_at=effective_scheduled_at,
            updated_at=now,
            timeout_seconds=effective_timeout,
            idempotency_key=idempotency_key,
            current_stage="QUEUED",
            progress_percent=0.0,
        )
        db.add(job)
        db.flush()

        # Emit creation event and broadcast to real-time subscribers
        RealtimePublisher.emit_job_event(
            db=db,
            job_id=job.id,
            event_type="JOB_QUEUED",
            message=f"Job {job.id} of type {job_type} accepted and queued for execution.",
            workspace_id=workspace_id,
            stage="QUEUED",
            progress_percent=0.0,
            metadata={
                "job_type": job_type,
                "priority": prio_upper,
                "resource_type": resource_type,
                "resource_id": resource_id,
            },
            analysis_run_id=analysis_run_id,
            investigation_id=resource_id if resource_type in ("INCIDENT", "INVESTIGATION") else None,
            report_id=report_id,
            status=JobStatusEnum.QUEUED.value,
        )
        db.refresh(job)

        logger.info(
            "Enqueued background job %s (type=%s, priority=%s, resource=%s:%s)",
            job.id,
            job_type,
            prio_upper,
            resource_type,
            resource_id,
        )
        return job, True

    @classmethod
    def get_job(cls, db: Session, job_id: str, workspace_id: Optional[str] = None) -> Optional[BackgroundJobModel]:
        """Retrieves a background job with tenant boundary verification."""
        q = db.query(BackgroundJobModel).filter(BackgroundJobModel.id == job_id)
        if workspace_id:
            q = q.filter(BackgroundJobModel.workspace_id == workspace_id)
        return q.first()

    @classmethod
    def list_jobs(
        cls,
        db: Session,
        workspace_id: str = "default",
        status: Optional[str] = None,
        job_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        page: int = 1,
        page_size: int = 25,
    ) -> JobListResponse:
        """Bounded, paginated listing of background jobs."""
        page = max(1, page)
        page_size = max(1, min(page_size, 100))

        q = db.query(BackgroundJobModel).filter(BackgroundJobModel.workspace_id == workspace_id)
        if status:
            q = q.filter(BackgroundJobModel.status == status.upper())
        if job_type:
            q = q.filter(BackgroundJobModel.job_type == job_type.upper())
        if resource_id:
            q = q.filter(BackgroundJobModel.resource_id == resource_id)

        total = q.count()
        jobs = (
            q.order_by(desc(BackgroundJobModel.created_at))
            .offset((page - 1) * page_size)
            .limit(page_size)
            .all()
        )

        items = [cls.serialize_job(j, include_events=False) for j in jobs]
        return JobListResponse(
            total=total,
            page=page,
            page_size=page_size,
            items=items,
        )

    @classmethod
    def cancel_job(
        cls,
        db: Session,
        job_id: str,
        workspace_id: Optional[str] = None,
        reason: Optional[str] = None,
    ) -> JobActionResponse:
        """Safely requests cancellation of an active or queued job."""
        job = cls.get_job(db, job_id, workspace_id)
        if not job:
            raise JobNotFoundError(f"Background job '{job_id}' not found.")

        current_status = job.status
        if current_status in (
            JobStatusEnum.SUCCEEDED.value,
            JobStatusEnum.PARTIALLY_SUCCEEDED.value,
            JobStatusEnum.FAILED.value,
            JobStatusEnum.CANCELLED.value,
            JobStatusEnum.TIMED_OUT.value,
            JobStatusEnum.DEAD_LETTER.value,
        ):
            return JobActionResponse(
                success=False,
                job_id=job.id,
                previous_status=current_status,
                current_status=current_status,
                message=f"Cannot cancel job in terminal state '{current_status}'.",
            )

        if current_status in (JobStatusEnum.QUEUED.value, JobStatusEnum.SCHEDULED.value, JobStatusEnum.RETRY_WAIT.value):
            JobLifecycleManager.transition(
                db=db,
                job=job,
                target_status=JobStatusEnum.CANCELLED.value,
                message=reason or "Job cancelled while waiting in queue.",
                stage="CANCELLED",
            )
            # If associated with AnalysisRunModel, cascade cancellation
            if job.analysis_run_id:
                try:
                    from backend.services.analysis_orchestrator import AnalysisOrchestrator
                    AnalysisOrchestrator.cancel_run(db, job.analysis_run_id)
                except Exception:
                    pass
            db.commit()
            return JobActionResponse(
                success=True,
                job_id=job.id,
                previous_status=current_status,
                current_status=JobStatusEnum.CANCELLED.value,
                message="Queued job cancelled successfully.",
            )

        # If RUNNING, request cooperative cancellation
        JobLifecycleManager.transition(
            db=db,
            job=job,
            target_status=JobStatusEnum.CANCEL_REQUESTED.value,
            message=reason or "Cancellation requested by operator.",
            stage="CANCEL_REQUESTED",
        )
        if job.analysis_run_id:
            try:
                from backend.services.analysis_orchestrator import AnalysisOrchestrator
                AnalysisOrchestrator.cancel_run(db, job.analysis_run_id)
            except Exception:
                pass
        db.commit()
        return JobActionResponse(
            success=True,
            job_id=job.id,
            previous_status=current_status,
            current_status=JobStatusEnum.CANCEL_REQUESTED.value,
            message="Cancellation signal dispatched to executing worker.",
        )

    @classmethod
    def retry_job(
        cls,
        db: Session,
        job_id: str,
        workspace_id: Optional[str] = None,
    ) -> JobActionResponse:
        """Manually resets and requeues a failed, timed-out, or dead-lettered job."""
        job = cls.get_job(db, job_id, workspace_id)
        if not job:
            raise JobNotFoundError(f"Background job '{job_id}' not found.")

        current_status = job.status
        if current_status not in (
            JobStatusEnum.FAILED.value,
            JobStatusEnum.TIMED_OUT.value,
            JobStatusEnum.DEAD_LETTER.value,
        ):
            return JobActionResponse(
                success=False,
                job_id=job.id,
                previous_status=current_status,
                current_status=current_status,
                message=f"Only failed, timed out, or dead-lettered jobs can be retried (current status is '{current_status}').",
            )

        now = get_utc_now()
        job.status = JobStatusEnum.QUEUED.value
        job.attempt_count = 0
        job.scheduled_at = now
        job.started_at = None
        job.completed_at = None
        job.heartbeat_at = None
        job.timeout_at = None
        job.worker_id = None
        job.error_code = None
        job.sanitized_error_message = None
        job.progress_percent = 0.0
        job.current_stage = "QUEUED"
        job.updated_at = now

        # Emit retry scheduled event and broadcast
        RealtimePublisher.emit_job_event(
            db=db,
            job_id=job.id,
            event_type="JOB_RETRY_SCHEDULED",
            message="Operator manually initiated retry for job.",
            workspace_id=job.workspace_id,
            stage="QUEUED",
            progress_percent=0.0,
            metadata={"requeued_at": now.isoformat()},
            analysis_run_id=job.analysis_run_id,
            investigation_id=job.resource_id if job.resource_type in ("INCIDENT", "INVESTIGATION") else None,
            report_id=job.report_id,
            status=JobStatusEnum.QUEUED.value,
        )

        return JobActionResponse(
            success=True,
            job_id=job.id,
            previous_status=current_status,
            current_status=JobStatusEnum.QUEUED.value,
            message="Job reset and requeued successfully.",
        )

    @classmethod
    def get_metrics_summary(cls, db: Session, workspace_id: str = "default") -> JobMetricsSummary:
        """Calculates bounded aggregate observability metrics."""
        q = db.query(BackgroundJobModel.status, func.count(BackgroundJobModel.id)).filter(
            BackgroundJobModel.workspace_id == workspace_id
        ).group_by(BackgroundJobModel.status).all()

        counts = {row[0]: row[1] for row in q}

        total_jobs = sum(counts.values())

        # Average wait duration (started_at - created_at) for jobs that started
        started_jobs = (
            db.query(BackgroundJobModel)
            .filter(
                BackgroundJobModel.workspace_id == workspace_id,
                BackgroundJobModel.started_at.isnot(None),
            )
            .order_by(desc(BackgroundJobModel.created_at))
            .limit(100)
            .all()
        )

        wait_seconds_list = [
            (j.started_at - j.created_at).total_seconds()
            for j in started_jobs
            if j.started_at and j.created_at and j.started_at >= j.created_at
        ]
        avg_wait = round(sum(wait_seconds_list) / len(wait_seconds_list), 2) if wait_seconds_list else 0.0

        # Average execution duration (completed_at - started_at) for finished jobs
        completed_jobs = (
            db.query(BackgroundJobModel)
            .filter(
                BackgroundJobModel.workspace_id == workspace_id,
                BackgroundJobModel.completed_at.isnot(None),
                BackgroundJobModel.started_at.isnot(None),
            )
            .order_by(desc(BackgroundJobModel.completed_at))
            .limit(100)
            .all()
        )

        exec_seconds_list = [
            (j.completed_at - j.started_at).total_seconds()
            for j in completed_jobs
            if j.completed_at and j.started_at and j.completed_at >= j.started_at
        ]
        avg_exec = round(sum(exec_seconds_list) / len(exec_seconds_list), 2) if exec_seconds_list else 0.0

        # Active workers in the last 60 seconds
        recent_cutoff = get_utc_now() - timedelta(seconds=60)
        active_worker_rows = (
            db.query(BackgroundJobModel.worker_id)
            .filter(
                BackgroundJobModel.workspace_id == workspace_id,
                BackgroundJobModel.status == JobStatusEnum.RUNNING.value,
                BackgroundJobModel.heartbeat_at >= recent_cutoff,
                BackgroundJobModel.worker_id.isnot(None),
            )
            .distinct()
            .all()
        )
        active_workers = [r[0] for r in active_worker_rows if r[0]]

        return JobMetricsSummary(
            queued=counts.get(JobStatusEnum.QUEUED.value, 0),
            scheduled=counts.get(JobStatusEnum.SCHEDULED.value, 0),
            running=counts.get(JobStatusEnum.RUNNING.value, 0),
            retry_wait=counts.get(JobStatusEnum.RETRY_WAIT.value, 0),
            succeeded=counts.get(JobStatusEnum.SUCCEEDED.value, 0),
            partially_succeeded=counts.get(JobStatusEnum.PARTIALLY_SUCCEEDED.value, 0),
            failed=counts.get(JobStatusEnum.FAILED.value, 0),
            dead_letter=counts.get(JobStatusEnum.DEAD_LETTER.value, 0),
            cancelled=counts.get(JobStatusEnum.CANCELLED.value, 0),
            timed_out=counts.get(JobStatusEnum.TIMED_OUT.value, 0),
            total_jobs=total_jobs,
            avg_wait_duration_seconds=avg_wait,
            avg_execution_duration_seconds=avg_exec,
            active_workers=active_workers,
        )

    @classmethod
    def serialize_job(cls, job: BackgroundJobModel, include_events: bool = True) -> JobReadResponse:
        """Serializes BackgroundJobModel to Pydantic schema."""
        events_list: Optional[List[JobEventRead]] = None
        if include_events and job.events:
            events_list = [
                JobEventRead(
                    id=e.id,
                    job_id=e.job_id,
                    workspace_id=e.workspace_id,
                    event_type=e.event_type,
                    sequence=getattr(e, "sequence", 1) or 1,
                    stage=e.stage,
                    progress_percent=e.progress_percent,
                    message=e.message,
                    metadata=json.loads(e.metadata_json or "{}"),
                    timestamp=e.timestamp,
                )
                for e in sorted(job.events, key=lambda x: (getattr(x, "sequence", 1) or 1, x.timestamp))
            ]

        res_dict = {}
        if job.result_json:
            try:
                res_dict = json.loads(job.result_json)
            except Exception:
                res_dict = {}

        return JobReadResponse(
            id=job.id,
            workspace_id=job.workspace_id,
            job_type=job.job_type,
            status=job.status,
            priority=job.priority,
            priority_weight=job.priority_weight,
            requested_by=job.requested_by,
            resource_type=job.resource_type,
            resource_id=job.resource_id,
            analysis_run_id=job.analysis_run_id,
            report_id=job.report_id,
            attempt_count=job.attempt_count,
            max_attempts=job.max_attempts,
            created_at=job.created_at,
            scheduled_at=job.scheduled_at,
            started_at=job.started_at,
            heartbeat_at=job.heartbeat_at,
            completed_at=job.completed_at,
            updated_at=job.updated_at,
            timeout_seconds=job.timeout_seconds,
            worker_id=job.worker_id,
            idempotency_key=job.idempotency_key,
            progress_percent=job.progress_percent,
            current_stage=job.current_stage,
            error_code=job.error_code,
            sanitized_error_message=job.sanitized_error_message,
            result_reference=job.result_reference,
            result=res_dict,
            events=events_list,
        )
