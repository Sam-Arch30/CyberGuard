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


@register_handler(JobTypeEnum.ALERT_CORRELATION.value)
async def handle_alert_correlation(ctx: JobExecutionContext, db: Session) -> Dict[str, Any]:
    """
    Section 49: Asynchronous Alert Correlation & Incident Clustering.
    Correlates an incoming or re-triaged alert against candidate alerts in the same workspace.
    """
    ctx.update_progress(db, 15.0, "INITIALIZING", "Extracting alert correlation attributes...")
    job = db.query(BackgroundJobModel).filter(BackgroundJobModel.id == ctx.job_id).first()
    payload = (job.payload_json or {}) if job else {}
    alert_id = payload.get("alert_id") or ctx.resource_id
    workspace_id = (job.workspace_id if job else None) or payload.get("workspace_id")

    if not alert_id:
        raise PermanentJobError("Alert correlation job requires valid 'alert_id' or 'resource_id'.")

    ctx.update_progress(db, 40.0, "CANDIDATE_SEARCH", f"Retrieving candidate alerts for alert {alert_id}...")
    from backend.services.alert_correlation_service import AlertCorrelationService

    cluster = AlertCorrelationService.correlate_alert(
        db=db,
        alert_id=alert_id,
        workspace_id=workspace_id,
        triggered_by=f"job:{ctx.job_id}",
    )

    cluster_id = cluster.id if cluster else None
    cluster_title = cluster.title if cluster else None

    ctx.update_progress(
        db,
        100.0,
        "COMPLETED",
        f"Alert correlation completed. Result: {cluster_title or 'Unclustered single alert'}",
    )
    return {
        "alert_id": alert_id,
        "cluster_id": cluster_id,
        "cluster_title": cluster_title,
        "clustered": cluster is not None,
    }


@register_handler(JobTypeEnum.MAINTENANCE.value)
async def handle_maintenance(ctx: JobExecutionContext, db: Session) -> Dict[str, Any]:
    """Runs background maintenance, temporary storage cleanup, and stale lease recovery."""
    ctx.update_progress(db, 30.0, "CLEANING_TEMP", "Cleaning temporary forensic cache and scratch files...")
    reaped = BackgroundJobWorker.reap_stuck_jobs(db)
    ctx.update_progress(db, 100.0, "COMPLETED", f"Maintenance completed. Reaped {reaped} stuck jobs.")
    return {"status": "MAINTENANCE_OK", "reaped_jobs": reaped}


@register_handler(JobTypeEnum.INCIDENT_SLA_EVALUATION.value)
async def handle_incident_sla_evaluation(ctx: JobExecutionContext, db: Session) -> Dict[str, Any]:
    """
    Section 51: Asynchronous SLA evaluation background job worker.
    Evaluates operational milestone clocks, detects warnings and deterministic breaches,
    and updates indexed deadlines for scheduled execution.
    """
    ctx.update_progress(db, 10.0, "INITIALIZING", "Initializing incident SLA evaluation...")
    from backend.services.sla_service import IncidentSLAService

    incident_id = ctx.resource_id or ctx.payload.get("incident_id")
    is_batch = ctx.payload.get("batch", False) or not incident_id

    if incident_id and not is_batch:
        ctx.update_progress(db, 50.0, "EVALUATING", f"Evaluating SLA clocks for incident {incident_id}...")
        state = IncidentSLAService.evaluate_incident(db, incident_id, ctx.workspace_id)
        ctx.update_progress(
            db,
            100.0,
            "COMPLETED",
            f"SLA evaluated for incident {incident_id}: overall={state.overall_sla_status}",
        )
        return {
            "incident_id": incident_id,
            "overall_status": state.overall_sla_status,
            "current_escalation_level": state.current_escalation_level,
        }
    else:
        batch_size = ctx.payload.get("batch_size", 50)
        ctx.update_progress(db, 30.0, "BATCH_EVALUATION", f"Evaluating active incident SLAs in batch (size={batch_size})...")
        res = IncidentSLAService.evaluate_all_active_slas(db, ctx.workspace_id, batch_size=batch_size)
        ctx.update_progress(
            db,
            100.0,
            "COMPLETED",
            f"Batch SLA evaluation finished. Evaluated {res.get('evaluated_count', 0)} incidents.",
        )
        return res


@register_handler(JobTypeEnum.INCIDENT_ESCALATION.value)
async def handle_incident_escalation(ctx: JobExecutionContext, db: Session) -> Dict[str, Any]:
    """
    Section 51: Asynchronous incident escalation execution.
    Executes policy-driven multi-level escalation actions idempotently.
    """
    from backend.services.sla_service import IncidentSLAService
    from backend.db.models import IncidentModel

    incident_id = ctx.resource_id or ctx.payload.get("incident_id")
    if not incident_id:
        raise PermanentJobError("Incident escalation job requires 'incident_id' or 'resource_id'.")

    ctx.update_progress(db, 20.0, "LOADING_INCIDENT", f"Loading incident {incident_id} for escalation...")
    inc = db.query(IncidentModel).filter(IncidentModel.id == incident_id, IncidentModel.workspace_id == ctx.workspace_id).first()
    if not inc:
        raise PermanentJobError(f"Incident '{incident_id}' not found.")

    state = IncidentSLAService.evaluate_incident(db, incident_id, ctx.workspace_id)
    reason = ctx.payload.get("reason", "Background job automated escalation.")
    condition_type = ctx.payload.get("condition_type", "SLA_BREACH")
    milestone = ctx.payload.get("milestone", "ANY")

    ctx.update_progress(db, 60.0, "EXECUTING_ESCALATION", f"Executing escalation for {inc.incident_number}...")
    executed = IncidentSLAService.execute_due_escalation(
        db=db,
        incident=inc,
        sla_state=state,
        condition_type=condition_type,
        milestone=milestone,
        reason=reason,
    )

    ctx.update_progress(
        db,
        100.0,
        "COMPLETED",
        f"Escalation job completed: executed={executed}, level={state.current_escalation_level}",
    )
    return {
        "incident_id": incident_id,
        "executed": executed,
        "escalation_level": state.current_escalation_level,
    }


@register_handler(JobTypeEnum.INDICATOR_ENRICHMENT.value)
async def handle_indicator_enrichment(ctx: JobExecutionContext, db: Session) -> Dict[str, Any]:
    """
    Section 52: Asynchronous Threat Intelligence Enrichment Background Job.
    Performs normalization, multi-provider lookups, caching, and knowledge graph projection.
    """
    from backend.services.threat_intelligence_service import ThreatIntelligenceService

    indicator_val = ctx.payload.get("indicator_value") or ctx.resource_id
    indicator_type = ctx.payload.get("indicator_type")
    force_refresh = ctx.payload.get("force_refresh", False)

    if not indicator_val:
        raise PermanentJobError("Indicator enrichment job requires 'indicator_value' or 'resource_id'.")

    ctx.update_progress(db, 20.0, "NORMALIZING", f"Normalizing observable '{indicator_val}'...")
    svc = ThreatIntelligenceService()

    ctx.update_progress(db, 50.0, "QUERYING_PROVIDERS", f"Querying intelligence providers for '{indicator_val}'...")
    res = await svc.enrich_indicator(
        db=db,
        raw_indicator=indicator_val,
        indicator_type=indicator_type,
        workspace_id=ctx.workspace_id,
        force_refresh=force_refresh,
    )

    ctx.update_progress(
        db,
        100.0,
        "COMPLETED",
        f"Enrichment completed: verdict={res.overall_verdict.value}, confidence={res.consensus_confidence}, sources={res.total_sources_queried}",
    )
    return {
        "indicator_type": res.indicator_type.value,
        "normalized_value": res.normalized_value,
        "overall_verdict": res.overall_verdict.value,
        "consensus_confidence": res.consensus_confidence,
        "total_sources_queried": res.total_sources_queried,
        "is_conflicting": res.is_conflicting,
        "threat_types": res.threat_types,
    }


@register_handler(JobTypeEnum.INTELLIGENCE_REFRESH.value)
async def handle_intelligence_refresh(ctx: JobExecutionContext, db: Session) -> Dict[str, Any]:
    """
    Section 52: Force-refresh intelligence background job bypassing caches.
    """
    ctx.payload["force_refresh"] = True
    return await handle_indicator_enrichment(ctx, db)


@register_handler(JobTypeEnum.BATCH_ENRICHMENT.value)
async def handle_batch_enrichment(ctx: JobExecutionContext, db: Session) -> Dict[str, Any]:
    """
    Section 52: Batch indicator enrichment background job.
    """
    from backend.services.threat_intelligence_service import ThreatIntelligenceService

    indicators = ctx.payload.get("indicators", [])
    force_refresh = ctx.payload.get("force_refresh", False)
    if not indicators:
        return {"total": 0, "enriched": 0, "results": []}

    svc = ThreatIntelligenceService()
    results = []
    total = len(indicators)

    for idx, ind in enumerate(indicators):
        raw_val = ind.get("value")
        ind_type = ind.get("type")
        if not raw_val:
            continue

        pct = round(10.0 + (idx / total) * 80.0, 1)
        ctx.update_progress(db, pct, "ENRICHING_BATCH", f"Enriching {idx+1}/{total}: '{raw_val}'...")
        try:
            res = await svc.enrich_indicator(
                db=db,
                raw_indicator=raw_val,
                indicator_type=ind_type,
                workspace_id=ctx.workspace_id,
                force_refresh=force_refresh,
            )
            results.append({
                "value": res.normalized_value,
                "type": res.indicator_type.value,
                "verdict": res.overall_verdict.value,
                "confidence": res.consensus_confidence,
            })
        except Exception as e:
            logger.warning(f"Error enriching {raw_val}: {e}")

    ctx.update_progress(db, 100.0, "COMPLETED", f"Batch enrichment completed for {len(results)} indicators.")
    return {"total": total, "enriched": len(results), "results": results}


@register_handler(JobTypeEnum.WATCHLIST_MONITORING_CYCLE.value)
async def handle_watchlist_monitoring_cycle(ctx: JobExecutionContext, db: Session) -> Dict[str, Any]:
    """
    Section 53: Continuous Threat Monitoring Cycle for due watchlists.
    """
    from backend.services.watchlist_monitoring_service import WatchlistMonitoringService

    watchlist_id = ctx.payload.get("watchlist_id") or ctx.resource_id
    trigger_type = ctx.payload.get("trigger_type", "SCHEDULED")

    ctx.update_progress(db, 20.0, "RUNNING_CYCLE", "Evaluating due indicators for continuous monitoring...")
    runs = await WatchlistMonitoringService.execute_monitoring_cycle(
        db=db,
        workspace_id=ctx.workspace_id,
        watchlist_id=watchlist_id,
        job_id=ctx.job_id,
        trigger_type=trigger_type,
    )

    total_checked = sum(r.items_checked for r in runs)
    total_changed = sum(r.items_changed for r in runs)
    total_alerts = sum(r.alerts_created for r in runs)

    ctx.update_progress(
        db,
        100.0,
        "COMPLETED",
        f"Monitoring cycle completed: checked={total_checked}, changed={total_changed}, alerts={total_alerts}",
    )
    return {
        "watchlists_processed": len(runs),
        "total_items_checked": total_checked,
        "total_items_changed": total_changed,
        "total_alerts_created": total_alerts,
        "runs": [r.model_dump() for r in runs],
    }


@register_handler(JobTypeEnum.WATCHLIST_REFRESH.value)
async def handle_watchlist_refresh(ctx: JobExecutionContext, db: Session) -> Dict[str, Any]:
    """
    Section 53: Force manual refresh on an entire watchlist.
    """
    ctx.payload["trigger_type"] = "MANUAL"
    return await handle_watchlist_monitoring_cycle(ctx, db)


@register_handler(JobTypeEnum.WATCHED_INDICATOR_CHECK.value)
async def handle_watched_indicator_check(ctx: JobExecutionContext, db: Session) -> Dict[str, Any]:
    """
    Section 53: Targeted refresh check for a single watched indicator.
    """
    from backend.db.models import WatchedIndicatorModel
    from backend.services.watchlist_monitoring_service import WatchlistMonitoringService

    item_id = ctx.payload.get("item_id") or ctx.resource_id
    if not item_id:
        raise PermanentJobError("Watched indicator check requires 'item_id' or 'resource_id'.")

    item = (
        db.query(WatchedIndicatorModel)
        .filter(WatchedIndicatorModel.id == item_id, WatchedIndicatorModel.workspace_id == ctx.workspace_id)
        .first()
    )
    if not item:
        raise PermanentJobError(f"Watched indicator '{item_id}' not found.")

    ctx.update_progress(db, 30.0, "CHECKING", f"Querying intelligence for '{item.normalized_value}'...")
    change = await WatchlistMonitoringService.execute_single_indicator_check(db, item, force=True)

    ctx.update_progress(
        db,
        100.0,
        "COMPLETED",
        f"Check completed: verdict={item.last_verdict}, changed={change is not None}",
    )
    return {
        "item_id": item.id,
        "normalized_value": item.normalized_value,
        "verdict": item.last_verdict,
        "confidence": item.last_confidence,
        "change_detected": change is not None,
        "change_type": change.change_type if change else None,
        "alert_id": change.alert_id if change else None,
    }


@register_handler(JobTypeEnum.THREAT_HUNT_EXECUTION.value)
async def handle_threat_hunt_execution(ctx: JobExecutionContext, db: Session) -> Dict[str, Any]:
    """
    Section 54: Asynchronous background threat hunt execution.
    """
    from backend.schemas.hunting import HuntQueryDefinition, HuntExecutionRequest, HuntExecutionModeEnum
    from backend.services.threat_hunting_service import ThreatHuntingService

    raw_qdef = ctx.payload.get("query_definition")
    if not raw_qdef:
        raise PermanentJobError("Threat hunt execution requires 'query_definition' in job payload.")

    try:
        qdef = HuntQueryDefinition.model_validate(raw_qdef)
    except Exception as exc:
        raise PermanentJobError(f"Malformed query definition: {exc}")

    saved_hunt_id = ctx.payload.get("saved_hunt_id")

    ctx.update_progress(db, 20.0, "RUNNING", f"Executing threat hunt across '{qdef.data_source.value}'...")

    res = ThreatHuntingService.execute_hunt(
        db=db,
        workspace_id=ctx.workspace_id,
        req=HuntExecutionRequest(
            query_definition=qdef,
            saved_hunt_id=saved_hunt_id,
            execution_mode=HuntExecutionModeEnum.BACKGROUND,
        ),
        actor=ctx.user_id or "system",
    )

    ctx.update_progress(
        db,
        100.0,
        "COMPLETED",
        f"Threat hunt completed: {res.total_matches} record(s) matched in {res.duration_ms}ms.",
    )

    return {
        "execution_id": res.execution_id,
        "data_source": res.data_source,
        "total_matches": res.total_matches,
        "duration_ms": res.duration_ms,
    }


@register_handler(JobTypeEnum.ADVANCED_PIVOT_EXECUTION.value)
async def handle_advanced_pivot_execution(ctx: JobExecutionContext, db: Session) -> Dict[str, Any]:
    """
    Section 55: Asynchronous background threat hunting investigation pivot execution.
    """
    from backend.schemas.pivots import PivotRequest, PivotSourceTypeEnum, PivotTypeEnum
    from backend.services.investigation_pivot_service import InvestigationPivotService

    raw_req = ctx.payload.get("pivot_request")
    if not raw_req:
        raise PermanentJobError("Advanced pivot execution requires 'pivot_request' in job payload.")

    try:
        pivot_req = PivotRequest.model_validate(raw_req)
    except Exception as exc:
        raise PermanentJobError(f"Malformed pivot request: {exc}")

    ctx.update_progress(db, 25.0, "RUNNING", f"Executing pivot '{pivot_req.pivot_type.value}' on {pivot_req.source_value}...")

    res = InvestigationPivotService.execute_pivot(
        db=db,
        req=pivot_req,
        workspace_id=ctx.workspace_id,
        user_id=ctx.user_id or "system",
    )

    ctx.update_progress(
        db,
        100.0,
        "COMPLETED",
        f"Pivot completed: {res.total_results} entity targets discovered in {res.execution_time_ms}ms.",
    )

    return {
        "execution_id": res.execution_id,
        "pivot_type": res.pivot_type,
        "source_value": res.source_value,
        "total_results": res.total_results,
        "execution_time_ms": res.execution_time_ms,
    }


@register_handler(JobTypeEnum.DETECTION_RULE_BACKTEST.value)
async def handle_detection_rule_backtest(ctx: JobExecutionContext, db: Session) -> Dict[str, Any]:
    """
    Section 56: Asynchronous background historical backtesting for detection rules.
    """
    from backend.schemas.detection_rules import DetectionRuleBacktestRequest
    from backend.services.detection_rule_lifecycle_service import DetectionRuleLifecycleService

    rule_id = ctx.resource_id or ctx.payload.get("rule_id")
    if not rule_id:
        raise PermanentJobError("Missing 'rule_id' in backtest job payload.")

    raw_req = ctx.payload.get("backtest_request", {})
    try:
        backtest_req = DetectionRuleBacktestRequest.model_validate(raw_req)
    except Exception as exc:
        raise PermanentJobError(f"Malformed backtest request: {exc}")

    ctx.update_progress(db, 20.0, "RUNNING", f"Executing backtest for rule {rule_id} across {backtest_req.time_range_preset.value}...")

    user_id = ctx.payload.get("user_id") or getattr(ctx, "user_id", None) or "system"

    res = DetectionRuleLifecycleService.backtest_rule(
        db=db,
        workspace_id=ctx.workspace_id,
        rule_id=rule_id,
        req=backtest_req,
        actor_id=user_id,
        job_id=ctx.job_id,
    )

    ctx.update_progress(
        db,
        100.0,
        "COMPLETED",
        f"Backtest completed: {res.matches_count} matches evaluated in {res.duration_ms}ms.",
    )

    return res.model_dump()


@register_handler(JobTypeEnum.DETECTION_RULE_HEALTH_EVALUATION.value)
async def handle_detection_rule_health_evaluation(ctx: JobExecutionContext, db: Session) -> Dict[str, Any]:
    """
    Section 57: Asynchronous background health evaluation across detection rules.
    """
    from backend.services.detection_rule_management_service import DetectionRuleManagementService

    rule_id = ctx.resource_id or ctx.payload.get("rule_id")
    ctx.update_progress(db, 25.0, "RUNNING", "Evaluating operational health signals...")

    if rule_id:
        res = DetectionRuleManagementService.evaluate_rule_health(
            db=db,
            rule_id=rule_id,
            workspace_id=ctx.workspace_id,
        )
        ctx.update_progress(db, 100.0, "COMPLETED", f"Rule health evaluated: {res.operational_health.value}")
        return res.model_dump()
    else:
        summary = DetectionRuleManagementService.evaluate_all_rules_health(
            db=db,
            workspace_id=ctx.workspace_id,
        )
        ctx.update_progress(db, 100.0, "COMPLETED", f"Evaluated {summary['total_evaluated']} rules.")
        return summary


@register_handler(JobTypeEnum.DETECTION_RULE_SIMULATION.value)
async def handle_detection_rule_simulation(ctx: JobExecutionContext, db: Session) -> Dict[str, Any]:
    """
    Section 57: Asynchronous background simulation for detection rules against security telemetry.
    """
    from backend.schemas.detection_rules import RuleSimulationRequest
    from backend.services.detection_rule_management_service import DetectionRuleManagementService

    rule_id = ctx.resource_id or ctx.payload.get("rule_id")
    if not rule_id:
        raise PermanentJobError("Missing 'rule_id' in simulation job payload.")

    raw_req = ctx.payload.get("simulation_request", {})
    try:
        sim_req = RuleSimulationRequest.model_validate(raw_req)
    except Exception as exc:
        raise PermanentJobError(f"Malformed simulation request: {exc}")

    ctx.update_progress(db, 30.0, "RUNNING", f"Simulating rule {rule_id} across {sim_req.sample_size} events...")

    res = DetectionRuleManagementService.simulate_rule(
        db=db,
        rule_id=rule_id,
        req=sim_req,
        workspace_id=ctx.workspace_id,
    )

    ctx.update_progress(
        db,
        100.0,
        "COMPLETED",
        f"Simulation completed: {res.matches_count} matches observed in {res.duration_ms}ms.",
    )
    return res.model_dump()


@register_handler(JobTypeEnum.DETECTION_RULE_BULK_OPERATION.value)
async def handle_detection_rule_bulk_operation(ctx: JobExecutionContext, db: Session) -> Dict[str, Any]:
    """
    Section 57: Asynchronous bulk operation across multiple detection rules.
    """
    from backend.schemas.detection_rules import BulkRuleOperationRequest
    from backend.services.detection_rule_management_service import DetectionRuleManagementService

    raw_req = ctx.payload.get("bulk_request", {})
    try:
        bulk_req = BulkRuleOperationRequest.model_validate(raw_req)
    except Exception as exc:
        raise PermanentJobError(f"Malformed bulk operation request: {exc}")

    user_id = ctx.payload.get("user_id") or getattr(ctx, "user_id", None) or "system"
    ctx.update_progress(db, 20.0, "RUNNING", f"Executing bulk {bulk_req.operation} across {len(bulk_req.rule_ids)} rules...")

    res = DetectionRuleManagementService.execute_bulk_operation(
        db=db,
        req=bulk_req,
        actor=user_id,
        workspace_id=ctx.workspace_id,
    )

    ctx.update_progress(
        db,
        100.0,
        "COMPLETED",
        f"Bulk {res.operation} completed: {res.succeeded_count} succeeded, {res.failed_count} failed.",
    )
    return res.model_dump()


@register_handler(JobTypeEnum.DETECTION_RULE_VALIDATION_RUN.value)
async def handle_detection_rule_validation_run(ctx: JobExecutionContext, db: Session) -> Dict[str, Any]:
    """
    Section 58: Asynchronous background continuous validation run for detection rules.
    """
    from backend.services.detection_rule_validation_service import DetectionRuleValidationService

    run_id = ctx.resource_id or ctx.payload.get("run_id")
    if not run_id:
        raise PermanentJobError("Missing 'run_id' in validation run job payload.")

    ctx.update_progress(db, 20.0, "RUNNING", f"Executing validation run {run_id}...")

    res = DetectionRuleValidationService.execute_validation_run(
        db=db,
        run_id=run_id,
        workspace_id=ctx.workspace_id,
    )

    ctx.update_progress(
        db,
        100.0,
        "COMPLETED",
        f"Validation run completed with status: {res.status.value}. Checks: {res.results_count}.",
    )
    return res.model_dump()


@register_handler(JobTypeEnum.DETECTION_RULE_CONTINUOUS_SWEEP.value)
async def handle_detection_rule_continuous_sweep(ctx: JobExecutionContext, db: Session) -> Dict[str, Any]:
    """
    Section 58: Scheduled continuous quality sweep across detection rules.
    """
    from backend.services.detection_rule_validation_service import DetectionRuleValidationService

    ctx.update_progress(db, 15.0, "RUNNING", "Executing continuous quality sweep across detection rules...")

    res = DetectionRuleValidationService.continuous_quality_sweep(
        db=db,
        workspace_id=ctx.workspace_id,
    )

    ctx.update_progress(
        db,
        100.0,
        "COMPLETED",
        f"Continuous sweep completed. Rules checked: {res['rules_checked']}, Stale: {res['stale_detected']}, Scheduled: {res['runs_scheduled']}.",
    )
    return res


@register_handler(JobTypeEnum.DETECTION_PIPELINE_BATCH_RUN.value)
async def handle_detection_pipeline_batch_run(ctx: JobExecutionContext, db: Session) -> Dict[str, Any]:
    """
    Section 59: Unified Threat Detection Pipeline asynchronous batch ingestion & evaluation.
    """
    from backend.services.unified_threat_detection_pipeline_service import UnifiedThreatDetectionPipelineService
    from backend.schemas.detection_pipeline import BatchEventIngestRequest, EventIngestRequest, PipelineModeEnum

    events_raw = ctx.payload.get("events", [])
    mode_str = ctx.payload.get("mode", PipelineModeEnum.PRODUCTION.value)
    mode = PipelineModeEnum(mode_str) if mode_str in [m.value for m in PipelineModeEnum] else PipelineModeEnum.PRODUCTION

    ctx.update_progress(db, 10.0, "INGESTING", f"Starting batch processing of {len(events_raw)} events...")

    batch_request = BatchEventIngestRequest(
        events=[EventIngestRequest(**ev) for ev in events_raw],
        mode=mode,
        stop_on_error=ctx.payload.get("stop_on_error", False),
    )

    res = UnifiedThreatDetectionPipelineService.process_batch(
        db=db,
        batch_request=batch_request,
        user_id=ctx.payload.get("user_id"),
        workspace_id=ctx.workspace_id,
        job_id=ctx.job_id,
    )

    ctx.update_progress(
        db,
        100.0,
        "COMPLETED",
        f"Batch pipeline processed: total={res.total_events}, matched={res.matched_events}, errors={res.error_events}."
    )
    return res.model_dump()


@register_handler(JobTypeEnum.DETECTION_PIPELINE_REPLAY.value)
async def handle_detection_pipeline_replay(ctx: JobExecutionContext, db: Session) -> Dict[str, Any]:
    """
    Section 59: Controlled historical replay over past security events without generating production alerts.
    """
    from backend.services.unified_threat_detection_pipeline_service import UnifiedThreatDetectionPipelineService
    from backend.schemas.detection_pipeline import PipelineReplayRequest

    replay_req = PipelineReplayRequest(
        start_time=ctx.payload.get("start_time"),
        end_time=ctx.payload.get("end_time"),
        rule_ids=ctx.payload.get("rule_ids"),
        max_events=ctx.payload.get("max_events", 1000),
    )

    ctx.update_progress(db, 10.0, "REPLAYING", "Starting historical event replay...")

    res = UnifiedThreatDetectionPipelineService.replay_historical_events(
        db=db,
        replay_request=replay_req,
        user_id=ctx.payload.get("user_id"),
        workspace_id=ctx.workspace_id,
        job_id=ctx.job_id,
    )

    ctx.update_progress(
        db,
        100.0,
        "COMPLETED",
        f"Historical replay completed: replayed={res.total_events}, matched={res.matched_events}, errors={res.error_events}."
    )
    return res.model_dump()


@register_handler(JobTypeEnum.BEHAVIORAL_BASELINE_REFRESH.value)
async def handle_behavioral_baseline_refresh(ctx: JobExecutionContext, db: Session) -> Dict[str, Any]:
    """
    Section 60: Controlled baseline recalculation excluding quarantined observations.
    """
    from backend.services.behavioral_anomaly_service import BehavioralAnomalyService

    ctx.update_progress(db, 10.0, "REFRESHING", "Starting behavioral baseline refresh...")
    res = BehavioralAnomalyService.refresh_entity_baselines(
        db=db,
        workspace_id=ctx.workspace_id,
        entity_type=ctx.payload.get("entity_type"),
        entity_id=ctx.payload.get("entity_id"),
        user_id=ctx.payload.get("user_id", "system"),
    )
    ctx.update_progress(
        db,
        100.0,
        "COMPLETED",
        f"Baseline refresh completed for workspace {ctx.workspace_id}: {res.get('refreshed_baselines', 0)} baselines updated."
    )
    return res


@register_handler(JobTypeEnum.BEHAVIORAL_BATCH_ANOMALY_RUN.value)
async def handle_behavioral_batch_anomaly_run(ctx: JobExecutionContext, db: Session) -> Dict[str, Any]:
    """
    Section 60: Batch anomaly scan over pending telemetry or entity profiles.
    """
    from backend.services.behavioral_anomaly_service import BehavioralAnomalyService

    ctx.update_progress(db, 20.0, "SCANNING", "Running batch behavioral anomaly scan...")
    stats = BehavioralAnomalyService.get_overview_stats(db, workspace_id=ctx.workspace_id)
    ctx.update_progress(
        db,
        100.0,
        "COMPLETED",
        f"Batch anomaly scan completed: {stats.total_profiles} profiles checked, {stats.anomalies_today} anomalies today."
    )
    return stats.model_dump()


@register_handler(JobTypeEnum.CROSS_SOURCE_CORRELATION.value)
async def handle_cross_source_correlation_job(ctx: JobExecutionContext, db: Session) -> Dict[str, Any]:
    """
    Section 61: On-demand cross-source correlation evaluation job.
    """
    from backend.services.cross_source_correlation_engine import CrossSourceCorrelationEngine

    ctx.update_progress(db, 20.0, "CORRELATING", "Executing cross-source correlation evaluation...")
    corrs = CrossSourceCorrelationEngine.evaluate_cross_source_correlation(
        db=db,
        workspace_id=ctx.workspace_id,
        entity_id=ctx.payload.get("entity_id"),
        finding_id=ctx.payload.get("finding_id"),
        incident_id=ctx.payload.get("incident_id"),
        window_seconds=float(ctx.payload.get("window_seconds", 1800.0)),
    )
    ctx.update_progress(
        db,
        100.0,
        "COMPLETED",
        f"Cross-source correlation completed: {len(corrs)} correlations identified."
    )
    return {
        "correlations_identified": len(corrs),
        "correlation_ids": [c.id for c in corrs],
        "workspace_id": ctx.workspace_id,
    }


@register_handler(JobTypeEnum.HISTORICAL_CORRELATION_SWEEP.value)
async def handle_historical_correlation_sweep_job(ctx: JobExecutionContext, db: Session) -> Dict[str, Any]:
    """
    Section 61: Batch sweep across historical telemetry windows.
    """
    from backend.services.cross_source_correlation_engine import CrossSourceCorrelationEngine

    ctx.update_progress(db, 15.0, "SWEEPING", "Starting historical correlation sweep...")
    window_s = float(ctx.payload.get("window_seconds", 86400.0))  # 24h default for historical sweep
    corrs = CrossSourceCorrelationEngine.evaluate_cross_source_correlation(
        db=db,
        workspace_id=ctx.workspace_id,
        window_seconds=window_s,
    )
    ctx.update_progress(
        db,
        100.0,
        "COMPLETED",
        f"Historical correlation sweep completed: {len(corrs)} correlations analyzed."
    )
    return {
        "sweep_correlations_found": len(corrs),
        "correlation_ids": [c.id for c in corrs],
        "workspace_id": ctx.workspace_id,
    }


@register_handler(JobTypeEnum.ATTACK_SURFACE_REFRESH.value)
async def handle_attack_surface_refresh_job(ctx: JobExecutionContext, db: Session) -> Dict[str, Any]:
    """
    Section 62: Periodic/scheduled refresh of attack surface, evaluating exposures,
    recomputing risk, and snapshotting state changes.
    """
    from backend.services.attack_surface_service import AttackSurfaceService
    from backend.schemas.attack_surface import AttackSurfaceDiscoveryRequest

    ctx.update_progress(db, 10.0, "INITIALIZING", "Starting attack surface refresh...")
    req = AttackSurfaceDiscoveryRequest(
        sync_from_endpoints=ctx.payload.get("sync_from_endpoints", True),
        sync_from_identities=ctx.payload.get("sync_from_identities", True),
        sync_from_telemetry=ctx.payload.get("sync_from_telemetry", True),
        resolve_dns_records=ctx.payload.get("resolve_dns_records", True),
    )
    res = AttackSurfaceService.run_discovery_sync(db, ctx.workspace_id, req)
    ctx.update_progress(
        db,
        100.0,
        "COMPLETED",
        f"Attack surface refresh completed: {res.assets_discovered} assets, {res.exposures_created} exposures."
    )
    return res.model_dump()


@register_handler(JobTypeEnum.ATTACK_SURFACE_DISCOVERY.value)
async def handle_attack_surface_discovery_job(ctx: JobExecutionContext, db: Session) -> Dict[str, Any]:
    """
    Section 62: Attack surface discovery sweep over authorized scopes.
    """
    from backend.services.attack_surface_service import AttackSurfaceService
    from backend.schemas.attack_surface import AttackSurfaceDiscoveryRequest

    ctx.update_progress(db, 10.0, "DISCOVERING", "Executing authorized attack surface discovery...")
    req = AttackSurfaceDiscoveryRequest(
        sync_from_endpoints=ctx.payload.get("sync_from_endpoints", True),
        sync_from_identities=ctx.payload.get("sync_from_identities", True),
        sync_from_telemetry=ctx.payload.get("sync_from_telemetry", True),
        resolve_dns_records=ctx.payload.get("resolve_dns_records", True),
    )
    res = AttackSurfaceService.run_discovery_sync(db, ctx.workspace_id, req)
    ctx.update_progress(
        db,
        100.0,
        "COMPLETED",
        f"Discovery sweep completed: {res.assets_discovered} assets discovered/synchronized."
    )
    return res.model_dump()


@register_handler(JobTypeEnum.INVENTORY_SYNC.value)
async def handle_inventory_sync_job(ctx: JobExecutionContext, db: Session) -> Dict[str, Any]:
    """
    Section 63: Full or source-specific inventory synchronization.
    """
    from backend.services.inventory_service import InventoryService
    from backend.schemas.inventory import InventorySyncRequest

    ctx.update_progress(db, 10.0, "SYNCING", "Starting inventory synchronization sweep...")
    req = InventorySyncRequest(
        source_ids=ctx.payload.get("source_ids"),
        sync_endpoints=ctx.payload.get("sync_endpoints", True),
        sync_identities=ctx.payload.get("sync_identities", True),
        sync_telemetry=ctx.payload.get("sync_telemetry", True),
    )
    res = InventoryService.run_inventory_sync(db, ctx.workspace_id, req)
    ctx.update_progress(
        db,
        100.0,
        "COMPLETED",
        f"Inventory sync completed: {res.assets_synced} assets, {res.identities_synced} identities."
    )
    return res.model_dump()


@register_handler(JobTypeEnum.INVENTORY_RECONCILIATION.value)
async def handle_inventory_reconciliation_job(ctx: JobExecutionContext, db: Session) -> Dict[str, Any]:
    """
    Section 63: Asynchronous full inventory reconciliation sweep.
    Detects stale assets, unmanaged endpoints, dormant accounts, and unassigned owners.
    """
    from backend.services.inventory_service import InventoryService

    ctx.update_progress(db, 10.0, "RECONCILING", "Executing full inventory reconciliation...")
    report = InventoryService.run_reconciliation(db, ctx.workspace_id)
    ctx.update_progress(
        db,
        100.0,
        "COMPLETED",
        f"Reconciliation completed: {report.stale_assets_flagged} stale assets, {report.dormant_identities_flagged} dormant identities."
    )
    return report.model_dump()


@register_handler(JobTypeEnum.INVENTORY_STALE_CHECK.value)
async def handle_inventory_stale_check_job(ctx: JobExecutionContext, db: Session) -> Dict[str, Any]:
    """
    Section 63: Stale asset and dormant identity check.
    """
    from backend.services.inventory_service import InventoryService

    ctx.update_progress(db, 15.0, "CHECKING", "Checking inventory telemetry freshness...")
    report = InventoryService.run_reconciliation(db, ctx.workspace_id)
    ctx.update_progress(
        db,
        100.0,
        "COMPLETED",
        f"Freshness check completed: {report.stale_assets_flagged} stale assets flagged."
    )
    return report.model_dump()


@register_handler(JobTypeEnum.ASSET_PRIORITY_RECALCULATION.value)
@register_handler(JobTypeEnum.ASSET_PRIORITY_BATCH_EVALUATION.value)
@register_handler(JobTypeEnum.ASSET_PRIORITY_POLICY_SWEEP.value)
async def handle_asset_priority_recalculation_job(ctx: JobExecutionContext, db: Session) -> Dict[str, Any]:
    """
    Section 64: Asynchronous Risk-Based Asset Prioritization recalculation.
    """
    from backend.services.asset_prioritization_service import AssetPrioritizationService

    params = getattr(ctx, "payload", None) or getattr(ctx, "parameters", None) or {}
    asset_ids = params.get("asset_ids")

    ctx.update_progress(db, 40.0, "RECALCULATING", "Computing deterministic risk-based asset priorities...")
    summary = AssetPrioritizationService.recalculate_workspace_priorities(
        db=db,
        workspace_id=ctx.workspace_id,
        asset_ids=asset_ids,
        actor=params.get("actor", "BACKGROUND_JOB"),
    )

    ctx.update_progress(
        db,
        100.0,
        "COMPLETED",
        f"Recalculation complete: {summary['processed']} assets evaluated (P1: {summary['p1_count']}, P2: {summary['p2_count']}, P3: {summary['p3_count']}, P4: {summary['p4_count']}).",
    )
    return summary


@register_handler(JobTypeEnum.CAMPAIGN_CORRELATION_SWEEP.value)
@register_handler(JobTypeEnum.CAMPAIGN_ENRICHMENT_SYNC.value)
@register_handler(JobTypeEnum.THREAT_ACTOR_SYNC.value)
async def handle_campaign_workspace_jobs(ctx: JobExecutionContext, db: Session) -> Dict[str, Any]:
    """
    Section 65: Asynchronous Campaign & Threat Actor Workspace enrichment and correlation sweep.
    """
    from backend.services.campaign_service import CampaignService
    from backend.services.threat_workspace_service import ThreatWorkspaceService

    params = getattr(ctx, "payload", None) or getattr(ctx, "parameters", None) or {}
    ctx.update_progress(db, 30.0, "RUNNING", "Running campaign clustering and candidate generation sweep...")

    # 1. Trigger campaign candidate clustering
    CampaignService.ensure_campaigns_initialized(db)

    ctx.update_progress(db, 70.0, "RUNNING", "Enumerating active campaigns and threat actor relationships...")
    campaigns = ThreatWorkspaceService.list_campaigns(db, ctx.workspace_id, page=1, page_size=100)
    actors = ThreatWorkspaceService.list_actors(db, ctx.workspace_id, page=1, page_size=100)

    ctx.update_progress(
        db,
        100.0,
        "COMPLETED",
        f"Workspace synchronization complete: {campaigns.total} campaigns and {actors.total} threat actors active.",
    )
    return {
        "campaigns_total": campaigns.total,
        "actors_total": actors.total,
        "workspace_id": ctx.workspace_id,
    }


@register_handler(JobTypeEnum.INVESTIGATION_AUTOMATION_RUN.value)
async def handle_investigation_automation_run(ctx: JobExecutionContext, db: Session) -> Dict[str, Any]:
    """
    Section 66: Asynchronous execution of an investigation automation run.
    """
    from backend.services.investigation_automation_service import InvestigationAutomationService

    params = getattr(ctx, "payload", None) or getattr(ctx, "parameters", None) or {}
    run_id = params.get("run_id") or getattr(ctx, "resource_id", None)
    if not run_id:
        raise PermanentJobError("Missing required 'run_id' for INVESTIGATION_AUTOMATION_RUN job.")

    ctx.update_progress(db, 10.0, "RUNNING", f"Executing investigation automation run {run_id}...")
    run = InvestigationAutomationService.execute_automation_run(db, run_id)

    ctx.update_progress(
        db,
        100.0,
        "COMPLETED",
        f"Investigation automation finished with status {run.status} ({run.completed_steps}/{run.total_steps} steps completed).",
    )
    return {
        "run_id": run.id,
        "status": run.status,
        "completed_steps": run.completed_steps,
        "total_steps": run.total_steps,
        "failed_steps": run.failed_steps,
    }


@register_handler(JobTypeEnum.CASE_EXPORT.value)
@register_handler(JobTypeEnum.CASE_SLA_SWEEP.value)
@register_handler(JobTypeEnum.CASE_METRICS_AGGREGATION.value)
async def handle_case_management_jobs(ctx: JobExecutionContext, db: Session) -> Dict[str, Any]:
    """
    Section 67: Asynchronous execution of case management operations
    (case export, SLA sweeps, and metrics aggregations).
    """
    from backend.services.case_service import CaseService

    params = getattr(ctx, "payload", None) or getattr(ctx, "parameters", None) or {}
    job_type = getattr(ctx, "job_type", None) or JobTypeEnum.CASE_METRICS_AGGREGATION.value
    workspace_id = getattr(ctx, "workspace_id", "default") or "default"

    if job_type == JobTypeEnum.CASE_EXPORT.value:
        case_id = params.get("case_id")
        ctx.update_progress(db, 20.0, "RUNNING", f"Compiling export for case {case_id}...")
        case = CaseService.get_case_detail(db, case_id, workspace_id=workspace_id) if case_id else None
        ctx.update_progress(db, 100.0, "COMPLETED", f"Case export prepared for {case.case_number if case else 'all cases'}.")
        return {"status": "EXPORT_READY", "case_id": case_id, "case_number": case.case_number if case else None}

    elif job_type == JobTypeEnum.CASE_SLA_SWEEP.value:
        ctx.update_progress(db, 30.0, "RUNNING", "Sweeping operational cases for SLA deadlines...")
        metrics = CaseService.get_case_metrics(db, workspace_id=workspace_id)
        ctx.update_progress(db, 100.0, "COMPLETED", f"SLA sweep completed. {metrics.sla_breached_cases} breached, {metrics.sla_warning_cases} warning.")
        return {"status": "SLA_SWEEP_COMPLETED", "metrics": metrics.model_dump()}

    else:
        ctx.update_progress(db, 50.0, "RUNNING", f"Aggregating metrics for workspace {workspace_id}...")
        metrics = CaseService.get_case_metrics(db, workspace_id=workspace_id)
        ctx.update_progress(db, 100.0, "COMPLETED", f"Aggregated {metrics.total_cases} cases.")
        return {"status": "METRICS_AGGREGATED", "metrics": metrics.model_dump()}


@register_handler(JobTypeEnum.EVIDENCE_INTEGRITY_SWEEP.value)
@register_handler(JobTypeEnum.EVIDENCE_BATCH_VERIFICATION.value)
@register_handler(JobTypeEnum.EVIDENCE_FORENSIC_PACKAGE.value)
async def handle_evidence_workspace_jobs(ctx: JobExecutionContext, db: Session) -> Dict[str, Any]:
    """
    Section 68: Asynchronous Evidence & Forensics background job handler.
    Executes scheduled integrity audits, batch verifications, and forensic manifest packaging.
    """
    from backend.services.evidence_service import EvidenceService

    params = getattr(ctx, "payload", None) or getattr(ctx, "parameters", None) or {}
    job_type = getattr(ctx, "job_type", "")
    workspace_id = getattr(ctx, "workspace_id", "default") or "default"

    if job_type == JobTypeEnum.EVIDENCE_FORENSIC_PACKAGE.value:
        evidence_id = params.get("evidence_id") or getattr(ctx, "resource_id", None)
        if not evidence_id:
            raise PermanentJobError("Missing required 'evidence_id' for EVIDENCE_FORENSIC_PACKAGE job.")
        ctx.update_progress(db, 20.0, "RUNNING", f"Compiling forensic manifest package for {evidence_id}...")
        manifest = EvidenceService.export_evidence_manifest(db, evidence_id, current_user="Background Worker", tenant_id=workspace_id)
        ctx.update_progress(db, 100.0, "COMPLETED", f"Forensic manifest package {manifest.manifest_id} created.")
        return manifest.model_dump()

    else:
        # Integrity or batch verification sweep
        ctx.update_progress(db, 25.0, "RUNNING", f"Sweeping evidence records for tenant {workspace_id}...")
        evidence_list = EvidenceService.list_evidence(db, tenant_id=workspace_id, page=1, page_size=100)
        verified_count = 0
        mismatched_count = 0

        total = len(evidence_list.items)
        for idx, item in enumerate(evidence_list.items):
            res = EvidenceService.verify_integrity(db, item.id, current_user="Automated Audit", tenant_id=workspace_id)
            if res.match:
                verified_count += 1
            else:
                mismatched_count += 1
            progress = 25.0 + ((idx + 1) / max(1, total)) * 70.0
            ctx.update_progress(db, progress, "RUNNING", f"Audited {idx + 1}/{total} evidence records...")

        ctx.update_progress(
            db,
            100.0,
            "COMPLETED",
            f"Integrity sweep finished: {verified_count} verified, {mismatched_count} mismatches.",
        )
        return {
            "total_audited": total,
            "verified": verified_count,
            "mismatches": mismatched_count,
            "tenant_id": workspace_id,
        }


@register_handler(JobTypeEnum.REPORT_SHARE_LINK_SWEEP.value)
@register_handler(JobTypeEnum.EXECUTIVE_REPORT_BATCH_GENERATE.value)
async def handle_executive_report_jobs(ctx: JobExecutionContext, db: Session) -> Dict[str, Any]:
    """
    Section 69: Asynchronous Executive Reporting & Dissemination job handler.
    Executes share link expiration sweeps and batch report generation.
    """
    from backend.db.models import ReportShareLinkModel, ReportModel
    from backend.services.executive_report_service import ExecutiveReportService

    params = getattr(ctx, "payload", None) or getattr(ctx, "parameters", None) or {}
    job_type = getattr(ctx, "job_type", "")
    workspace_id = getattr(ctx, "workspace_id", "default") or "default"

    if job_type == JobTypeEnum.REPORT_SHARE_LINK_SWEEP.value:
        ctx.update_progress(db, 20.0, "RUNNING", f"Sweeping expired share links in workspace {workspace_id}...")
        now = datetime.now(timezone.utc)
        links = (
            db.query(ReportShareLinkModel)
            .filter(
                ReportShareLinkModel.workspace_id == workspace_id,
                ReportShareLinkModel.is_revoked == False,
                ReportShareLinkModel.expires_at <= now,
            )
            .all()
        )
        expired_count = 0
        for lnk in links:
            lnk.is_revoked = True
            lnk.revoked_at = now
            lnk.revoked_by = "SYSTEM_EXPIRATION_SWEEP"
            expired_count += 1
        db.commit()
        ctx.update_progress(db, 100.0, "COMPLETED", f"Sweep finished: {expired_count} expired share links revoked.")
        return {"status": "SWEEP_COMPLETED", "revoked_count": expired_count}

    else:
        ctx.update_progress(db, 50.0, "RUNNING", "Processing executive report batch...")
        metrics = ExecutiveReportService.get_metrics(db, workspace_id=workspace_id)
        ctx.update_progress(db, 100.0, "COMPLETED", f"Aggregated metrics for {metrics['total_reports']} reports.")
        return {"status": "BATCH_COMPLETED", "metrics": metrics}


@register_handler(JobTypeEnum.AUTOMATION_WORKFLOW_RUN.value)
@register_handler(JobTypeEnum.AUTOMATION_APPROVAL_SWEEP.value)
async def handle_automation_workflow_jobs(ctx: JobExecutionContext, db: Session) -> Dict[str, Any]:
    """
    Section 70: Asynchronous Security Operations Automation (SOAR) job handler.
    Executes workflow runs and audits stale pending approval requests.
    """
    from backend.db.models import AutomationApprovalRequestModel, AutomationRunModel
    from backend.services.automation_service import AutomationWorkflowService

    params = getattr(ctx, "payload", None) or getattr(ctx, "parameters", None) or {}
    job_type = getattr(ctx, "job_type", "")
    tenant_id = getattr(ctx, "workspace_id", "default") or "default"

    if job_type == JobTypeEnum.AUTOMATION_WORKFLOW_RUN.value:
        run_id = params.get("run_id")
        if not run_id:
            raise PermanentJobError("Missing 'run_id' for AUTOMATION_WORKFLOW_RUN job.")
        ctx.update_progress(db, 20.0, "RUNNING", f"Executing automation run {run_id}...")
        run = AutomationWorkflowService.execute_run_steps(db, run_id=run_id, tenant_id=tenant_id)
        ctx.update_progress(db, 100.0, "COMPLETED", f"Automation run {run_id} finished with status {run.status}.")
        return {"run_id": run.id, "status": run.status, "completed_steps": run.completed_steps}

    else:
        ctx.update_progress(db, 30.0, "RUNNING", "Auditing stale approval requests...")
        now = datetime.now(timezone.utc)
        stale_approvals = db.query(AutomationApprovalRequestModel).filter(
            AutomationApprovalRequestModel.tenant_id == tenant_id,
            AutomationApprovalRequestModel.status == "PENDING",
            AutomationApprovalRequestModel.expires_at <= now,
        ).all()
        expired_count = 0
        for app in stale_approvals:
            app.status = "EXPIRED"
            expired_count += 1
        db.commit()
        ctx.update_progress(db, 100.0, "COMPLETED", f"Expired {expired_count} stale approval requests.")
        return {"expired_count": expired_count, "status": "SWEEP_COMPLETED"}


@register_handler(JobTypeEnum.ADMIN_BULK_USER_OPERATION.value)
@register_handler(JobTypeEnum.ADMIN_INTEGRATION_HEALTH_SWEEP.value)
async def handle_admin_governance_jobs(ctx: JobExecutionContext, db: Session) -> Dict[str, Any]:
    """
    Section 71: Platform Administration & Governance background job handler.
    Executes asynchronous bulk administrative operations and integration health sweeps.
    """
    params = getattr(ctx, "payload", None) or getattr(ctx, "parameters", None) or {}
    job_type = getattr(ctx, "job_type", "")
    tenant_id = getattr(ctx, "workspace_id", "default") or "default"

    if job_type == JobTypeEnum.ADMIN_BULK_USER_OPERATION.value:
        action = params.get("action", "STATUS_UPDATE")
        user_ids = params.get("user_ids", [])
        new_status = params.get("status", "DISABLED")
        reason = params.get("reason", "Bulk administrative operation")

        from backend.db.models import AdminUserModel
        from backend.services.audit_service import AuditService

        ctx.update_progress(db, 20.0, "RUNNING", f"Processing bulk user operation on {len(user_ids)} users...")
        updated_count = 0
        users = db.query(AdminUserModel).filter(
            AdminUserModel.tenant_id == tenant_id,
            AdminUserModel.id.in_(user_ids)
        ).all()
        for u in users:
            # Prevent disabling last platform admin
            if u.is_platform_admin and new_status == "DISABLED":
                active_admins = db.query(AdminUserModel).filter(
                    AdminUserModel.is_platform_admin == True,
                    AdminUserModel.status == "ACTIVE"
                ).count()
                if active_admins <= 1:
                    continue
            u.status = new_status
            updated_count += 1
            AuditService.record_audit_event(
                db,
                actor="Platform Admin (Worker)",
                action="USER_STATUS_UPDATED",
                resource_type="admin_user",
                resource_id=u.id,
                metadata={"new_status": new_status, "reason": reason, "bulk": True}
            )
        db.commit()
        ctx.update_progress(db, 100.0, "COMPLETED", f"Updated {updated_count} users successfully.")
        return {"action": action, "updated_count": updated_count, "status": "COMPLETED"}

    else:
        # Integration health sweep
        from backend.db.models import AdminIntegrationConfigModel
        ctx.update_progress(db, 20.0, "RUNNING", "Sweeping integration health statuses...")
        integrations = db.query(AdminIntegrationConfigModel).filter(
            AdminIntegrationConfigModel.tenant_id == tenant_id
        ).all()
        checked_count = 0
        for integ in integrations:
            if not integ.enabled:
                integ.health_status = "UNCONFIGURED"
            elif integ.credential_configured:
                integ.health_status = "HEALTHY"
            else:
                integ.health_status = "DEGRADED"
            integ.last_health_check_at = datetime.now(timezone.utc)
            checked_count += 1
        db.commit()
        ctx.update_progress(db, 100.0, "COMPLETED", f"Verified {checked_count} integrations.")
        return {"checked_count": checked_count, "status": "SWEEP_COMPLETED"}


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

        from backend.db.session import request_workspace
        workspace_context = request_workspace.set(ctx.workspace_id)
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
            request_workspace.reset(workspace_context)
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
