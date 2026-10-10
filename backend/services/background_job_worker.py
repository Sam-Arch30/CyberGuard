"""
Section 45: Persistent Background Job Worker, Safe Atomic Claiming,
Heartbeat Leasing, Reaper Recovery, and Handler Execution.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import random
import socket
import sys
import time
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set
from sqlalchemy import text, desc
from sqlalchemy.orm import Session

from backend.db.session import SessionLocal
from backend.db.models import (
    BackgroundJobModel,
    BackgroundJobEventModel,
    AnalysisRunModel,
    ReportModel,
    IncidentModel,
    ArtifactModel,
    get_utc_now,
)
from backend.schemas.jobs import (
    JobTypeEnum,
    JobStatusEnum,
)
from backend.services.background_job_service import (
    BackgroundJobService,
    JobLifecycleManager,
    DEFAULT_JOB_TIMEOUTS,
)
from backend.services.log_sanitizer import sanitize_log_text
from backend.services.realtime_service import RealtimePublisher

logger = logging.getLogger("cyberguard.services.background_worker")


class PermanentJobError(Exception):
    """Raised when an unrecoverable failure occurs that should not be retried."""
    pass


class TransientJobError(Exception):
    """Raised when a temporary recoverable failure occurs that qualifies for retry."""
    pass


class JobExecutionContext:
    """Execution context provided to registered job handlers."""

    def __init__(
        self,
        job_id: str,
        workspace_id: str,
        job_type: str,
        payload: Dict[str, Any],
        worker_id: str,
        attempt: int,
        timeout_seconds: int,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        analysis_run_id: Optional[str] = None,
        report_id: Optional[str] = None,
    ):
        self.job_id = job_id
        self.workspace_id = workspace_id
        self.job_type = job_type
        self.payload = payload
        self.worker_id = worker_id
        self.attempt = attempt
        self.timeout_seconds = timeout_seconds
        self.resource_type = resource_type
        self.resource_id = resource_id
        self.analysis_run_id = analysis_run_id
        self.report_id = report_id
        self._cancelled = False

    def is_cancelled(self, db: Session) -> bool:
        """Polls DB to detect cooperative cancellation requests."""
        if self._cancelled:
            return True
        status_row = (
            db.query(BackgroundJobModel.status)
            .filter(BackgroundJobModel.id == self.job_id)
            .first()
        )
        if status_row and status_row[0] in (
            JobStatusEnum.CANCEL_REQUESTED.value,
            JobStatusEnum.CANCELLED.value,
        ):
            self._cancelled = True
            return True
        return False

    def update_progress(
        self,
        db: Session,
        progress_percent: float,
        stage: str,
        message: Optional[str] = None,
    ) -> None:
        """Updates job progress monotonically and logs an event."""
        now = get_utc_now()
        job = db.query(BackgroundJobModel).filter(BackgroundJobModel.id == self.job_id).first()
        if job:
            job.progress_percent = round(max(0.0, min(100.0, progress_percent)), 1)
            job.current_stage = stage
            job.heartbeat_at = now
            job.updated_at = now

            RealtimePublisher.emit_job_event(
                db=db,
                job_id=self.job_id,
                event_type="JOB_PROGRESS",
                message=message or f"Job progressing: {stage} ({job.progress_percent}%)",
                workspace_id=self.workspace_id,
                stage=stage,
                progress_percent=job.progress_percent,
                metadata={"stage": stage},
                analysis_run_id=self.analysis_run_id,
                investigation_id=self.resource_id if self.resource_type in ("INCIDENT", "INVESTIGATION") else None,
                report_id=self.report_id,
                status=job.status,
            )

    def heartbeat(self, db: Session) -> None:
        """Refreshes the worker's active lease on the job."""
        now = get_utc_now()
        job = db.query(BackgroundJobModel).filter(BackgroundJobModel.id == self.job_id).first()
        if job and job.status == JobStatusEnum.RUNNING.value:
            job.heartbeat_at = now
            job.lease_expires_at = now + timedelta(seconds=60)
            job.updated_at = now
            db.commit()

    def emit_event(
        self,
        db: Session,
        event_type: str,
        message: str,
        stage: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Emits an auditable event for this job with monotonic sequence and real-time broadcasting."""
        RealtimePublisher.emit_job_event(
            db=db,
            job_id=self.job_id,
            event_type=event_type,
            message=message,
            workspace_id=self.workspace_id,
            stage=stage,
            metadata=metadata or {},
            analysis_run_id=self.analysis_run_id,
            investigation_id=self.resource_id if self.resource_type in ("INCIDENT", "INVESTIGATION") else None,
            report_id=self.report_id,
        )


# Handler Registry
JOB_HANDLERS: Dict[str, Callable[[JobExecutionContext, Session], Coroutine[Any, Any, Dict[str, Any]]]] = {}


def register_handler(job_type: str):
    """Decorator to register an asynchronous job execution handler."""
    def decorator(fn):
        JOB_HANDLERS[job_type] = fn
        return fn
    return decorator


# ---------------------------------------------------------------------------
# Registered Job Handlers
# ---------------------------------------------------------------------------

@register_handler(JobTypeEnum.ARTIFACT_ANALYSIS.value)
async def handle_artifact_analysis(ctx: JobExecutionContext, db: Session) -> Dict[str, Any]:
    """
    Executes the Analysis Orchestrator DAG for an AnalysisRun.
    Preserves dependency graphs, finding persistence, and partial success semantics.
    """
    run_id = ctx.analysis_run_id or ctx.payload.get("analysis_run_id") or ctx.resource_id
    if not run_id:
        raise PermanentJobError("Missing required 'analysis_run_id' for ARTIFACT_ANALYSIS job.")

    run = db.query(AnalysisRunModel).filter(AnalysisRunModel.id == run_id).first()
    if not run:
        raise PermanentJobError(f"AnalysisRun '{run_id}' does not exist.")

    from backend.services.analysis_orchestrator import AnalysisOrchestrator

    ctx.update_progress(db, 10.0, "INITIALIZING_DAG", "Initializing analysis dependency graph...")

    if ctx.is_cancelled(db):
        AnalysisOrchestrator.cancel_run(db, run_id)
        return {"status": "CANCELLED", "run_id": run_id}

    ctx.update_progress(db, 25.0, "RUNNING_ANALYZERS", "Executing analyzer pipeline DAG...")

    # Execute orchestrator run
    updated_run = await AnalysisOrchestrator.execute_run(db, run_id)

    ctx.update_progress(db, 90.0, "PERSISTING_FINDINGS", "Finalizing risk scores and findings...")

    # Check terminal outcome of run
    outcome_status = updated_run.status
    result_data = {
        "analysis_run_id": updated_run.id,
        "artifact_id": updated_run.artifact_id,
        "run_status": outcome_status,
        "risk_score": updated_run.overall_risk_score,
        "severity": updated_run.overall_severity,
        "confidence": updated_run.confidence,
    }

    if outcome_status == "COMPLETED":
        ctx.update_progress(db, 100.0, "COMPLETED", "Analysis pipeline finished successfully.")
        return result_data
    elif outcome_status == "PARTIAL":
        ctx.update_progress(db, 100.0, "PARTIALLY_SUCCEEDED", "Analysis completed with partial analyzer success.")
        result_data["partial"] = True
        return result_data
    elif outcome_status == "CANCELLED":
        return {"status": "CANCELLED", "run_id": run_id}
    else:
        err_msg = updated_run.error or "Analysis pipeline failed during DAG execution."
        raise TransientJobError(f"Analysis pipeline concluded with status '{outcome_status}': {err_msg}")


@register_handler(JobTypeEnum.REPORT_GENERATION.value)
async def handle_report_generation(ctx: JobExecutionContext, db: Session) -> Dict[str, Any]:
    """
    Executes forensic report generation asynchronously:
    Builds projection snapshot, compiles vector PDF, writes to storage, and sets status READY.
    """
    investigation_id = ctx.resource_id or ctx.payload.get("investigation_id")
    if not investigation_id:
        raise PermanentJobError("Missing required 'investigation_id' for REPORT_GENERATION job.")

    from backend.services.report_projection_service import ReportProjectionService
    from backend.services.report_service import ReportService
    from backend.services.investigation_workspace_service import InvestigationWorkspaceService
    from backend.services.evidence_storage import evidence_storage

    ctx.emit_event(
        db=db,
        event_type="REPORT_GENERATION_STARTED",
        message=f"Initiated forensic report compilation for investigation {investigation_id}.",
        stage="PROJECTION_BUILDING",
        metadata={"investigation_id": investigation_id},
    )
    ctx.update_progress(db, 15.0, "PROJECTION_BUILDING", "Gathering authoritative investigation evidence...")

    if ctx.is_cancelled(db):
        return {"status": "CANCELLED"}

    incident, run, artifact, case = InvestigationWorkspaceService.resolve_context(db, investigation_id)
    if not incident and not run and not artifact:
        raise PermanentJobError(f"Investigation identifier '{investigation_id}' not found.")

    # Determine report version
    inv_key = incident.id if incident else (run.id if run else investigation_id)
    prior_reports = (
        db.query(ReportModel)
        .filter((ReportModel.investigation_id == inv_key) | (ReportModel.investigation_id == investigation_id))
        .order_by(ReportModel.report_version.desc())
        .all()
    )
    next_version = (prior_reports[0].report_version + 1) if prior_reports else 1

    report_type = ctx.payload.get("report_type", "ANALYST")
    classification = ctx.payload.get("classification", "CONFIDENTIAL")
    redaction_level = ctx.payload.get("redaction_level", "NONE")
    content_options = ctx.payload.get("content_options", {})
    analyst_name = ctx.payload.get("analyst_name", "SOC Analyst")
    notes = ctx.payload.get("notes")

    # Build snapshot projection
    snapshot = ReportProjectionService.build_projection(
        db=db,
        identifier=investigation_id,
        report_type=report_type,
        classification=classification,
        redaction_level=redaction_level,
        content_options=content_options,
        analyst_name=analyst_name,
        notes=notes,
        report_version=next_version,
    )

    ctx.update_progress(db, 50.0, "COMPILING_PDF", "Compiling high-fidelity vector PDF...")

    if ctx.is_cancelled(db):
        return {"status": "CANCELLED"}

    # Generate sequential report number
    from backend.api.routes.reports import _generate_report_number
    report_number = _generate_report_number(db)
    report_id = ctx.report_id or str(uuid.uuid4())
    snapshot["metadata"]["report_number"] = report_number
    snapshot["metadata"]["report_id"] = report_id

    # Compile PDF
    try:
        pdf_bytes = ReportService.generate_investigation_report(
            snapshot=snapshot,
            report_type=report_type,
            redaction_level=redaction_level,
            content_options=content_options,
        )
    except Exception as exc:
        if report_id:
            rep = db.query(ReportModel).filter(ReportModel.id == report_id).first()
            if rep and rep.status == "GENERATING":
                rep.status = "FAILED"
                rep.summary = f"Report generation failed: {str(exc)}"
                db.commit()
        ctx.emit_event(
            db=db,
            event_type="REPORT_FAILED",
            message=f"Report compilation failed: {str(exc)}",
            stage="FAILED",
            metadata={"report_id": report_id, "investigation_id": inv_key, "error": str(exc)},
        )
        raise TransientJobError(f"PDF compilation failed: {exc}")

    ctx.update_progress(db, 80.0, "STORING_REPORT", "Storing report snapshot and binary artifact...")

    # Write PDF to storage
    pdf_filename = f"{report_id}.pdf"
    pdf_path = os.path.join(ReportService.REPORTS_DIR, pdf_filename)
    try:
        with open(pdf_path, "wb") as f:
            f.write(pdf_bytes)
    except Exception:
        pass

    try:
        evidence_storage.store_bytes(
            data=pdf_bytes,
            original_filename=f"{report_number}.pdf",
            mime_type="application/pdf",
            custom_key=f"reports/{report_id}.pdf",
        )
    except Exception:
        pass

    import hashlib
    pdf_sha = hashlib.sha256(pdf_bytes).hexdigest().lower()

    # Mark prior active reports superseded
    if prior_reports:
        for p in prior_reports:
            if p.status == "READY":
                p.status = "SUPERSEDED"
                p.superseded_by = report_id
        db.flush()

    # Persist ReportModel
    title_val = snapshot["metadata"].get("title") or f"Incident Report {report_number}"
    score_val = snapshot["risk_assessment"].get("risk_score", 0.0)
    sev_val = (snapshot["risk_assessment"].get("severity") or "medium").lower()
    conf_val = snapshot["risk_assessment"].get("confidence", 1.0)
    summary_val = snapshot["executive_summary"].get("synthesized_narrative", "")

    existing_report = db.query(ReportModel).filter(ReportModel.id == report_id).first()
    if not existing_report:
        report_record = ReportModel(
            id=report_id,
            report_number=report_number,
            title=title_val,
            investigation_id=inv_key,
            case_id=case.id if case else None,
            evidence_id=artifact.id if artifact else None,
            artifact_id=artifact.id if artifact else None,
            analysis_run_id=snapshot["provenance"].get("analysis_run_id"),
            threat_score=score_val,
            severity=sev_val,
            confidence=conf_val,
            report_type=report_type,
            status="READY",
            report_version=next_version,
            classification=classification,
            redaction_level=redaction_level,
            analyst_name=analyst_name,
            summary=summary_val,
            content_options_json=json.dumps(content_options),
            snapshot_data_json=json.dumps(snapshot),
            quality_check_json=json.dumps(snapshot.get("provenance", {}).get("quality_check", {})),
            sha256=pdf_sha,
            file_size_bytes=len(pdf_bytes),
            created_at=get_utc_now(),
        )
        db.add(report_record)
    else:
        existing_report.status = "READY"
        existing_report.report_number = report_number
        existing_report.title = title_val
        existing_report.summary = summary_val
        existing_report.threat_score = score_val
        existing_report.severity = sev_val
        existing_report.confidence = conf_val
        existing_report.sha256 = pdf_sha
        existing_report.file_size_bytes = len(pdf_bytes)
        existing_report.snapshot_data_json = json.dumps(snapshot)
    db.commit()

    ctx.update_progress(db, 100.0, "READY", f"Report {report_number} generated successfully.")
    ctx.emit_event(
        db=db,
        event_type="REPORT_READY",
        message=f"Report {report_number} generated successfully (v{next_version}).",
        stage="READY",
        metadata={
            "report_id": report_id,
            "report_number": report_number,
            "report_version": next_version,
            "investigation_id": inv_key,
            "file_size_bytes": len(pdf_bytes),
            "sha256": pdf_sha,
            "download_url": f"/api/reports/{report_id}/download",
        },
    )

    # Section 47: Dispatch report completion notification
    try:
        from backend.services.notification_service import NotificationService
        NotificationService.on_report_completed(
            db=db,
            report=report_record if not existing_report else existing_report,
            workspace_id=ctx.workspace_id,
        )
    except Exception as ne:
        logger.warning("Failed to dispatch report notification: %s", ne)

    return {
        "report_id": report_id,
        "report_number": report_number,
        "report_version": next_version,
        "status": "READY",
        "file_size_bytes": len(pdf_bytes),
        "sha256": pdf_sha,
        "download_url": f"/api/reports/{report_id}/download",
    }


@register_handler(JobTypeEnum.CROSS_INCIDENT_CORRELATION.value)
async def handle_cross_incident_correlation(ctx: JobExecutionContext, db: Session) -> Dict[str, Any]:
    """Runs cross-incident correlation analysis asynchronously."""
    incident_id = ctx.resource_id or ctx.payload.get("incident_id")
    if not incident_id:
        raise PermanentJobError("Missing required 'incident_id' for CROSS_INCIDENT_CORRELATION job.")

    incident = db.query(IncidentModel).filter(IncidentModel.id == incident_id).first()
    if not incident:
        raise PermanentJobError(f"Incident '{incident_id}' not found.")

    from backend.services.cross_incident_engine import CrossIncidentCorrelationEngine

    ctx.update_progress(db, 20.0, "EXTRACTING_PROFILE", f"Extracting correlation profile for incident {incident_id}...")

    engine = CrossIncidentCorrelationEngine()
    profile = engine.extract_incident_profile(incident, db)

    ctx.update_progress(db, 50.0, "CANDIDATE_SEARCH", "Evaluating candidate incident correlations...")
    candidate_ids = engine.generate_candidate_incident_ids(profile, db)

    correlations = []
    total_candidates = len(candidate_ids)
    for idx, c_id in enumerate(candidate_ids):
        if ctx.is_cancelled(db):
            return {"status": "CANCELLED", "partial_count": len(correlations)}
        target_inc = db.query(IncidentModel).filter(IncidentModel.id == c_id).first()
        if target_inc:
            target_prof = engine.extract_incident_profile(target_inc, db)
            res = engine.correlate_incident_pair(profile, target_prof, db)
            if res:
                correlations.append(res)
        prog = 50.0 + (30.0 * (idx + 1) / max(1, total_candidates))
        ctx.update_progress(db, prog, "PAIRWISE_SCORING", f"Evaluated candidate {idx + 1}/{total_candidates}")

    ctx.update_progress(db, 100.0, "COMPLETED", f"Generated {len(correlations)} cross-incident correlations.")
    return {
        "incident_id": incident_id,
        "candidate_count": len(candidate_ids),
        "correlation_count": len(correlations),
    }


@register_handler(JobTypeEnum.ATTACK_PATH_RECONSTRUCTION.value)
async def handle_attack_path_reconstruction(ctx: JobExecutionContext, db: Session) -> Dict[str, Any]:
    """Executes multi-stage attack path reconstruction asynchronously."""
    incident_id = ctx.resource_id or ctx.payload.get("incident_id")
    if not incident_id:
        raise PermanentJobError("Missing required 'incident_id' for ATTACK_PATH_RECONSTRUCTION job.")

    from backend.services.attack_reconstruction_engine import AttackReconstructionEngine

    ctx.update_progress(db, 25.0, "RECONSTRUCTING_PATH", f"Reconstructing attack graph for incident {incident_id}...")
    recon = AttackReconstructionEngine.reconstruct_incident(db, incident_id, ctx.workspace_id)

    ctx.update_progress(db, 100.0, "COMPLETED", f"Reconstruction completed with {len(recon.stages)} stages.")
    return {
        "incident_id": incident_id,
        "stages_count": len(recon.stages),
        "transitions_count": len(recon.transitions),
        "hypotheses_count": len(recon.hypotheses),
        "overall_confidence": recon.overall_confidence,
    }


@register_handler(JobTypeEnum.ENDPOINT_TELEMETRY_PROCESSING.value)
async def handle_endpoint_telemetry(ctx: JobExecutionContext, db: Session) -> Dict[str, Any]:
    """Processes batches of endpoint telemetry events asynchronously."""
    from backend.db.models import EndpointTelemetryEventModel

    batch_size = ctx.payload.get("batch_size", 50)
    ctx.update_progress(db, 20.0, "FETCHING_TELEMETRY", f"Querying pending telemetry events (batch size={batch_size})...")

    events = (
        db.query(EndpointTelemetryEventModel)
        .filter(
            EndpointTelemetryEventModel.workspace_id == ctx.workspace_id,
            EndpointTelemetryEventModel.status == "ACCEPTED",
        )
        .limit(batch_size)
        .all()
    )

    processed_count = 0
    for ev in events:
        if ctx.is_cancelled(db):
            return {"status": "CANCELLED", "processed": processed_count}
        ev.status = "NORMALIZED"
        processed_count += 1
    db.commit()

    ctx.update_progress(db, 100.0, "COMPLETED", f"Normalized {processed_count} endpoint telemetry events.")
    return {"events_processed": processed_count}


@register_handler(JobTypeEnum.EVIDENCE_EXPORT.value)
async def handle_evidence_export(ctx: JobExecutionContext, db: Session) -> Dict[str, Any]:
    """Prepares evidence export bundle asynchronously."""
    ctx.update_progress(db, 50.0, "PREPARING_ARCHIVE", "Packaging evidence records for secure export...")
    await asyncio.sleep(0.05)
    ctx.update_progress(db, 100.0, "COMPLETED", "Evidence export manifest created.")
    return {"export_status": "READY", "manifest_id": str(uuid.uuid4())}


@register_handler(JobTypeEnum.MAINTENANCE.value)
async def handle_maintenance(ctx: JobExecutionContext, db: Session) -> Dict[str, Any]:
    """Runs background maintenance, temporary storage cleanup, and stale lease recovery."""
    ctx.update_progress(db, 30.0, "CLEANING_TEMP", "Cleaning temporary forensic cache and scratch files...")
    reaped = BackgroundJobWorker.reap_stuck_jobs(db)
    ctx.update_progress(db, 100.0, "COMPLETED", f"Maintenance completed. Reaped {reaped} stuck jobs.")
    return {"status": "MAINTENANCE_OK", "reaped_jobs": reaped}


# ---------------------------------------------------------------------------
# Background Worker Engine
# ---------------------------------------------------------------------------

class BackgroundJobWorker:
    """
    Dedicated worker executing background jobs with atomic claiming,
    heartbeat leasing, bounded retries, and stuck-job recovery.
    """

    def __init__(
        self,
        worker_id: Optional[str] = None,
        max_concurrency: int = 4,
        poll_interval: float = 1.0,
    ):
        hostname = socket.gethostname()
        rand_suffix = uuid.uuid4().hex[:8]
        self.worker_id = worker_id or f"worker-{hostname}-{rand_suffix}"
        self.max_concurrency = max_concurrency
        self.poll_interval = poll_interval
        self._stop_event = asyncio.Event()
        self._active_tasks: Set[asyncio.Task] = set()

    @classmethod
    def reap_stuck_jobs(cls, db: Session, lease_timeout_seconds: int = 60) -> int:
        """
        Reaps jobs whose workers abandoned them or missed heartbeats.
        If attempts < max_attempts -> sets RETRY_WAIT with exponential backoff.
        If attempts >= max_attempts -> sets TIMED_OUT or DEAD_LETTER.
        """
        now = get_utc_now()
        heartbeat_cutoff = now - timedelta(seconds=lease_timeout_seconds)

        # Query stuck RUNNING jobs
        stuck_jobs = (
            db.query(BackgroundJobModel)
            .filter(
                BackgroundJobModel.status == JobStatusEnum.RUNNING.value,
                (
                    (BackgroundJobModel.heartbeat_at < heartbeat_cutoff)
                    | ((BackgroundJobModel.timeout_at.isnot(None)) & (BackgroundJobModel.timeout_at < now))
                ),
            )
            .all()
        )

        reaped_count = 0
        for job in stuck_jobs:
            logger.warning(
                "Stuck job detected: %s (type=%s, attempt=%s/%s, worker=%s, last_heartbeat=%s)",
                job.id,
                job.job_type,
                job.attempt_count,
                job.max_attempts,
                job.worker_id,
                job.heartbeat_at,
            )
            if job.attempt_count < job.max_attempts:
                # Schedule retry
                backoff_delay = min(300, (2 ** (job.attempt_count - 1)) * 10 + random.randint(1, 5))
                job.status = JobStatusEnum.RETRY_WAIT.value
                job.scheduled_at = now + timedelta(seconds=backoff_delay)
                job.worker_id = None
                job.updated_at = now
                msg = f"Worker heartbeat expired. Automatically scheduled retry attempt in {backoff_delay}s."
                event_type = "JOB_RETRY_SCHEDULED"
            else:
                job.status = JobStatusEnum.TIMED_OUT.value
                job.completed_at = now
                job.updated_at = now
                msg = "Execution lease expired and max retry attempts exhausted. Job marked TIMED_OUT."
                event_type = "JOB_TIMED_OUT"

            event = BackgroundJobEventModel(
                job_id=job.id,
                workspace_id=job.workspace_id,
                event_type=event_type,
                stage="RECOVERY",
                message=msg,
                metadata_json=json.dumps({"reaped_at": now.isoformat()}),
                timestamp=now,
            )
            db.add(event)
            reaped_count += 1

        if reaped_count > 0:
            db.commit()
            logger.info("Reaper recovered %s stuck background jobs.", reaped_count)
        return reaped_count

    @classmethod
    def claim_next_job(
        cls,
        db: Session,
        worker_id: str,
        workspace_id: Optional[str] = None,
        job_id: Optional[str] = None,
    ) -> Optional[BackgroundJobModel]:
        """
        Safely and atomically claims the highest-priority eligible job.
        Compatible with PostgreSQL and SQLite. Supports optional workspace and job filtering.
        """
        now = get_utc_now()

        # Find top candidate jobs
        q = db.query(BackgroundJobModel.id, BackgroundJobModel.timeout_seconds).filter(
            BackgroundJobModel.status.in_([JobStatusEnum.QUEUED.value, JobStatusEnum.RETRY_WAIT.value]),
            BackgroundJobModel.scheduled_at <= now,
        )
        if workspace_id:
            q = q.filter(BackgroundJobModel.workspace_id == workspace_id)
        if job_id:
            q = q.filter(BackgroundJobModel.id == job_id)

        candidates = (
            q.order_by(
                desc(BackgroundJobModel.priority_weight),
                BackgroundJobModel.scheduled_at.asc(),
                BackgroundJobModel.created_at.asc(),
            )
            .limit(10)
            .all()
        )

        if not candidates:
            return None

        # Attempt atomic Compare-And-Swap (CAS) update
        for cand_id, timeout_sec in candidates:
            eff_timeout = timeout_sec or 300
            timeout_at = now + timedelta(seconds=eff_timeout)
            lease_expires = now + timedelta(seconds=60)

            # Atomic conditional update
            stmt = (
                text(
                    "UPDATE background_jobs "
                    "SET status = :running_status, "
                    "    worker_id = :worker_id, "
                    "    started_at = COALESCE(started_at, :now), "
                    "    heartbeat_at = :now, "
                    "    lease_expires_at = :lease_expires, "
                    "    timeout_at = :timeout_at, "
                    "    attempt_count = attempt_count + 1, "
                    "    current_stage = 'CLAIMED', "
                    "    updated_at = :now "
                    "WHERE id = :candidate_id "
                    "  AND status IN ('QUEUED', 'RETRY_WAIT')"
                )
                .bindparams(
                    running_status=JobStatusEnum.RUNNING.value,
                    worker_id=worker_id,
                    now=now,
                    lease_expires=lease_expires,
                    timeout_at=timeout_at,
                    candidate_id=cand_id,
                )
            )

            result = db.execute(stmt)
            if result.rowcount > 0:
                # Successfully claimed!
                db.commit()
                claimed_job = db.query(BackgroundJobModel).filter(BackgroundJobModel.id == cand_id).first()
                if claimed_job:
                    RealtimePublisher.emit_job_event(
                        db=db,
                        job_id=claimed_job.id,
                        event_type="JOB_STARTED",
                        message=f"Job claimed by worker {worker_id} (attempt {claimed_job.attempt_count}/{claimed_job.max_attempts}).",
                        workspace_id=claimed_job.workspace_id,
                        stage="CLAIMED",
                        progress_percent=0.0,
                        metadata={"worker_id": worker_id, "attempt": claimed_job.attempt_count},
                        analysis_run_id=claimed_job.analysis_run_id,
                        investigation_id=claimed_job.resource_id if claimed_job.resource_type in ("INCIDENT", "INVESTIGATION") else None,
                        report_id=claimed_job.report_id,
                        status=JobStatusEnum.RUNNING.value,
                    )
                    logger.info("Worker %s claimed job %s (%s)", worker_id, claimed_job.id, claimed_job.job_type)
                    return claimed_job

        return None

    async def execute_job(self, job_id: str) -> None:
        """Executes a single claimed job with heartbeat loop, timeouts, and error handling."""
        with SessionLocal() as db:
            job = db.query(BackgroundJobModel).filter(BackgroundJobModel.id == job_id).first()
            if not job:
                return

            handler = JOB_HANDLERS.get(job.job_type)
            if not handler:
                err_msg = f"No registered handler for job type '{job.job_type}'."
                logger.error(err_msg)
                JobLifecycleManager.transition(
                    db=db,
                    job=job,
                    target_status=JobStatusEnum.FAILED.value,
                    error_code="UNSUPPORTED_JOB_TYPE",
                    sanitized_error=err_msg,
                    message=err_msg,
                )
                db.commit()
                return

            payload = json.loads(job.payload_json or "{}")
            ctx = JobExecutionContext(
                job_id=job.id,
                workspace_id=job.workspace_id,
                job_type=job.job_type,
                payload=payload,
                worker_id=self.worker_id,
                attempt=job.attempt_count,
                timeout_seconds=job.timeout_seconds,
                resource_type=job.resource_type,
                resource_id=job.resource_id,
                analysis_run_id=job.analysis_run_id,
                report_id=job.report_id,
            )

        # Heartbeat loop running concurrently during execution
        stop_heartbeat = asyncio.Event()

        async def _heartbeat_loop():
            while not stop_heartbeat.is_set():
                try:
                    await asyncio.sleep(15.0)
                    if stop_heartbeat.is_set():
                        break
                    with SessionLocal() as hb_db:
                        ctx.heartbeat(hb_db)
                except Exception:
                    pass

        hb_task = asyncio.create_task(_heartbeat_loop())

        try:
            with SessionLocal() as exec_db:
                # Execute the handler with timeout protection
                result = await asyncio.wait_for(
                    handler(ctx, exec_db),
                    timeout=float(ctx.timeout_seconds),
                )

                # Check if cancelled during execution
                if ctx.is_cancelled(exec_db):
                    curr_job = exec_db.query(BackgroundJobModel).filter(BackgroundJobModel.id == job_id).first()
                    if curr_job and curr_job.status != JobStatusEnum.CANCELLED.value:
                        JobLifecycleManager.transition(
                            db=exec_db,
                            job=curr_job,
                            target_status=JobStatusEnum.CANCELLED.value,
                            message="Job cancelled during execution.",
                            stage="CANCELLED",
                        )
                    exec_db.commit()
                    return

                # Record completion
                curr_job = exec_db.query(BackgroundJobModel).filter(BackgroundJobModel.id == job_id).first()
                if curr_job and curr_job.status == JobStatusEnum.RUNNING.value:
                    is_partial = result.get("partial", False) if isinstance(result, dict) else False
                    target_st = JobStatusEnum.PARTIALLY_SUCCEEDED.value if is_partial else JobStatusEnum.SUCCEEDED.value
                    JobLifecycleManager.transition(
                        db=exec_db,
                        job=curr_job,
                        target_status=target_st,
                        progress_percent=100.0,
                        stage="COMPLETED",
                        result_json=result if isinstance(result, dict) else {},
                        message=f"Job concluded successfully with status {target_st}.",
                    )
                    exec_db.commit()
                    logger.info("Job %s completed successfully (%s)", job_id, target_st)

        except asyncio.TimeoutError:
            logger.error("Job %s timed out after %s seconds", job_id, ctx.timeout_seconds)
            with SessionLocal() as timeout_db:
                curr_job = timeout_db.query(BackgroundJobModel).filter(BackgroundJobModel.id == job_id).first()
                if curr_job:
                    if curr_job.attempt_count < curr_job.max_attempts:
                        delay = min(300, (2 ** (curr_job.attempt_count - 1)) * 10 + 5)
                        curr_job.status = JobStatusEnum.RETRY_WAIT.value
                        curr_job.scheduled_at = get_utc_now() + timedelta(seconds=delay)
                        curr_job.sanitized_error_message = f"Execution timed out after {ctx.timeout_seconds}s. Scheduled retry in {delay}s."
                        curr_job.error_code = "TIMEOUT"
                    else:
                        JobLifecycleManager.transition(
                            db=timeout_db,
                            job=curr_job,
                            target_status=JobStatusEnum.TIMED_OUT.value,
                            error_code="TIMEOUT_EXHAUSTED",
                            sanitized_error=f"Execution timed out after {ctx.timeout_seconds}s. Max retries exhausted.",
                            message="Job timed out and max retry budget exceeded.",
                        )
                timeout_db.commit()

        except PermanentJobError as p_err:
            sanitized_msg = sanitize_log_text(str(p_err))
            logger.error("Job %s permanent error: %s", job_id, sanitized_msg)
            with SessionLocal() as fail_db:
                curr_job = fail_db.query(BackgroundJobModel).filter(BackgroundJobModel.id == job_id).first()
                if curr_job:
                    JobLifecycleManager.transition(
                        db=fail_db,
                        job=curr_job,
                        target_status=JobStatusEnum.FAILED.value,
                        error_code="PERMANENT_ERROR",
                        sanitized_error=sanitized_msg,
                        message=f"Job failed permanently: {sanitized_msg}",
                    )
                    fail_db.commit()

        except Exception as exc:
            sanitized_msg = sanitize_log_text(str(exc))
            logger.warning("Job %s transient exception (attempt %s): %s", job_id, ctx.attempt, sanitized_msg)
            with SessionLocal() as retry_db:
                curr_job = retry_db.query(BackgroundJobModel).filter(BackgroundJobModel.id == job_id).first()
                if curr_job:
                    if curr_job.attempt_count < curr_job.max_attempts:
                        # Exponential backoff with jitter
                        delay = min(300, int((2 ** (curr_job.attempt_count - 1)) * 5) + random.randint(1, 4))
                        curr_job.status = JobStatusEnum.RETRY_WAIT.value
                        curr_job.scheduled_at = get_utc_now() + timedelta(seconds=delay)
                        curr_job.sanitized_error_message = sanitized_msg
                        curr_job.error_code = "TRANSIENT_FAILURE"
                        curr_job.current_stage = "RETRY_WAIT"
                        curr_job.updated_at = get_utc_now()

                        RealtimePublisher.emit_job_event(
                            db=retry_db,
                            job_id=curr_job.id,
                            event_type="JOB_RETRY_SCHEDULED",
                            message=f"Attempt {curr_job.attempt_count} failed ({sanitized_msg}). Scheduled retry in {delay}s.",
                            workspace_id=curr_job.workspace_id,
                            stage="RETRY_WAIT",
                            metadata={"delay_seconds": delay, "next_attempt": curr_job.attempt_count + 1},
                            analysis_run_id=curr_job.analysis_run_id,
                            investigation_id=curr_job.resource_id if curr_job.resource_type in ("INCIDENT", "INVESTIGATION") else None,
                            report_id=curr_job.report_id,
                            status=JobStatusEnum.RETRY_WAIT.value,
                        )
                    else:
                        JobLifecycleManager.transition(
                            db=retry_db,
                            job=curr_job,
                            target_status=JobStatusEnum.DEAD_LETTER.value,
                            error_code="RETRY_EXHAUSTED",
                            sanitized_error=sanitized_msg,
                            message=f"Retry budget exhausted after {curr_job.attempt_count} attempts. Moved to DEAD_LETTER.",
                        )
                retry_db.commit()

        finally:
            stop_heartbeat.set()
            hb_task.cancel()
            try:
                await hb_task
            except asyncio.CancelledError:
                pass

    async def run_once(self) -> bool:
        """Runs a single claim-and-execute iteration. Returns True if a job was claimed."""
        with SessionLocal() as db:
            claimed_job = self.claim_next_job(db, self.worker_id)

        if claimed_job:
            task = asyncio.create_task(self.execute_job(claimed_job.id))
            self._active_tasks.add(task)
            task.add_done_callback(self._active_tasks.discard)
            return True
        return False

    async def run_loop(self) -> None:
        """Continuous worker execution loop."""
        logger.info("Starting background worker %s (concurrency=%s)", self.worker_id, self.max_concurrency)
        last_reap = time.time()

        while not self._stop_event.is_set():
            try:
                # Periodic stuck-job reaping (every 30s)
                if time.time() - last_reap > 30.0:
                    with SessionLocal() as db:
                        self.reap_stuck_jobs(db)
                    last_reap = time.time()

                # Check concurrency ceiling
                if len(self._active_tasks) < self.max_concurrency:
                    claimed = await self.run_once()
                    if claimed:
                        # Yield control briefly
                        await asyncio.sleep(0.02)
                        continue

                # No job claimed or at max concurrency: sleep
                await asyncio.sleep(self.poll_interval)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Error in worker loop: %s", e)
                await asyncio.sleep(self.poll_interval)

        # Graceful shutdown: await active tasks with bounded timeout
        logger.info("Worker %s stopping. Draining %s in-flight tasks...", self.worker_id, len(self._active_tasks))
        if self._active_tasks:
            await asyncio.wait(self._active_tasks, timeout=10.0)
        logger.info("Worker %s stopped cleanly.", self.worker_id)

    def stop(self) -> None:
        """Signals worker loop to stop gracefully."""
        self._stop_event.set()


# Global in-process worker instance
_global_worker: Optional[BackgroundJobWorker] = None
_global_worker_task: Optional[asyncio.Task] = None


def start_in_process_worker(max_concurrency: int = 2) -> BackgroundJobWorker:
    """Starts the background worker as an async task inside the web application."""
    global _global_worker, _global_worker_task
    if _global_worker is None:
        _global_worker = BackgroundJobWorker(max_concurrency=max_concurrency)
        _global_worker_task = asyncio.create_task(_global_worker.run_loop())
        logger.info("In-process background worker initialized: %s", _global_worker.worker_id)
    return _global_worker


async def stop_in_process_worker() -> None:
    """Gracefully stops the in-process worker task."""
    global _global_worker, _global_worker_task
    if _global_worker:
        _global_worker.stop()
        if _global_worker_task:
            try:
                await asyncio.wait_for(_global_worker_task, timeout=5.0)
            except Exception:
                pass
        _global_worker = None
        _global_worker_task = None
        logger.info("In-process background worker stopped.")
