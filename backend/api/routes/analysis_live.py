"""
Live Analysis & Real-Time Task DAG Execution API Routes (Section 37).
Provides snapshot endpoints, SSE streaming, and interactive analysis control.
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.db.models import (
    AnalysisRunModel,
    AnalysisTaskModel,
    AnalysisEventModel,
    ArtifactModel,
    FindingModel,
    EvidenceModel,
    IncidentModel,
    RelationshipModel,
)
from backend.schemas.analysis_live import (
    AnalysisRunLiveResponse,
    AnalysisTaskRead,
    AnalysisEventRead,
    FindingPreview,
)
from backend.schemas.analysis_results import (
    AnalysisResultsResponse,
    EvidenceDetailResponse,
)
from backend.services.analysis_orchestrator import (
    AnalysisOrchestrator,
    global_event_hub,
)
from backend.services.analysis_results_aggregator import AnalysisResultsAggregator

logger = logging.getLogger("cyberguard.api.analysis_live")

router = APIRouter(tags=["Live Analysis"])


def _build_live_response(run: AnalysisRunModel, db: Session) -> AnalysisRunLiveResponse:
    """Helper to assemble a comprehensive AnalysisRunLiveResponse."""
    artifact = db.query(ArtifactModel).filter(ArtifactModel.id == run.artifact_id).first()

    # Find associated incident and evidence
    investigation_id = None
    evidence_id = None

    rel = db.query(RelationshipModel).filter(
        RelationshipModel.target_type == "ARTIFACT",
        RelationshipModel.target_id == run.artifact_id,
        RelationshipModel.source_type == "INCIDENT",
    ).first()
    if rel:
        investigation_id = rel.source_id

    if artifact and artifact.sha256:
        evd = db.query(EvidenceModel).filter(EvidenceModel.sha256 == artifact.sha256).first()
        if evd:
            evidence_id = evd.evidence_id

    tasks = db.query(AnalysisTaskModel).filter(
        AnalysisTaskModel.analysis_run_id == run.id
    ).order_by(AnalysisTaskModel.created_at).all()

    completed_media = bool(artifact and artifact.artifact_type.upper() in ('IMAGE', 'AUDIO', 'VIDEO') and run.status in ('COMPLETED', 'PARTIAL'))
    if not tasks and not completed_media:
        tasks = AnalysisOrchestrator.initialize_run_dag(db, run.id)

    events = db.query(AnalysisEventModel).filter(
        AnalysisEventModel.analysis_run_id == run.id
    ).order_by(AnalysisEventModel.timestamp.desc()).limit(50).all()

    findings = db.query(FindingModel).filter(
        FindingModel.analysis_run_id == run.id
    ).order_by(FindingModel.created_at.desc()).all()

    # Calculate statistics
    total_tasks = len(tasks)
    completed_tasks = sum(1 for t in tasks if t.status == "COMPLETED")
    running_tasks = sum(1 for t in tasks if t.status == "RUNNING")
    failed_tasks = sum(1 for t in tasks if t.status == "FAILED")
    pending_tasks = sum(1 for t in tasks if t.status in ("PENDING", "QUEUED", "BLOCKED"))

    # Truthful progress calculation
    progress = None
    if total_tasks > 0:
        progress = round((completed_tasks / total_tasks) * 100.0, 1)

    # Currently running task
    current_task = None
    running_t = next((t for t in tasks if t.status == "RUNNING"), None)
    if running_t:
        current_task = AnalysisTaskRead(
            id=running_t.id,
            analysis_run_id=running_t.analysis_run_id,
            analyzer_id=running_t.analyzer_id,
            task_type=running_t.task_type,
            title=running_t.title,
            description=running_t.description,
            status=running_t.status,
            dependency_ids=json.loads(running_t.dependency_ids_json or "[]"),
            started_at=running_t.started_at,
            completed_at=running_t.completed_at,
            duration_seconds=running_t.duration_seconds,
            progress=running_t.progress,
            message=running_t.message,
            error=running_t.error,
            result_count=running_t.result_count,
            version=running_t.version,
            metadata=json.loads(running_t.metadata_json or "{}"),
        )

    task_reads = [
        AnalysisTaskRead(
            id=t.id,
            analysis_run_id=t.analysis_run_id,
            analyzer_id=t.analyzer_id,
            task_type=t.task_type,
            title=t.title,
            description=t.description,
            status=t.status,
            dependency_ids=json.loads(t.dependency_ids_json or "[]"),
            started_at=t.started_at,
            completed_at=t.completed_at,
            duration_seconds=t.duration_seconds,
            progress=t.progress,
            message=t.message,
            error=t.error,
            result_count=t.result_count,
            version=t.version,
            metadata=json.loads(t.metadata_json or "{}"),
        )
        for t in tasks
    ]

    event_reads = [
        AnalysisEventRead(
            id=e.id,
            analysis_run_id=e.analysis_run_id,
            task_id=e.task_id,
            event_type=e.event_type,
            sequence=getattr(e, "sequence", 1) or 1,
            timestamp=e.timestamp,
            task_status=e.task_status,
            message=e.message,
            result_count=e.result_count,
            error=e.error,
            metadata=json.loads(e.metadata_json or "{}"),
        )
        for e in events
    ]

    finding_previews = [
        FindingPreview(
            id=f.id,
            analyzer=f.analyzer,
            finding_type=f.finding_type,
            title=f.title,
            severity=f.severity,
            confidence=f.confidence if f.confidence is not None else 0.0,
            risk_contribution=f.risk_contribution or 0.0,
        )
        for f in findings
    ]

    duration_seconds = None
    if run.started_at and run.completed_at:
        duration_seconds = round((run.completed_at - run.started_at).total_seconds(), 2)

    # Previous runs count for same artifact
    prev_count = 0
    if artifact:
        prev_count = db.query(AnalysisRunModel).filter(
            AnalysisRunModel.artifact_id == artifact.id,
            AnalysisRunModel.id != run.id,
        ).count()

    return AnalysisRunLiveResponse(
        id=run.id,
        artifact_id=run.artifact_id,
        investigation_id=investigation_id,
        evidence_id=evidence_id,
        artifact_name=artifact.name if artifact else "unknown",
        artifact_type=artifact.artifact_type if artifact else "FILE",
        artifact_size=(artifact.size or 0) if artifact else 0,
        artifact_sha256=artifact.sha256 if artifact else None,
        artifact_source=artifact.source if artifact else "UNKNOWN",
        status=run.status,
        trigger=run.trigger,
        pipeline_version=run.pipeline_version,
        started_at=run.started_at,
        completed_at=run.completed_at,
        duration_seconds=duration_seconds,
        overall_risk_score=run.overall_risk_score,
        overall_severity=run.overall_severity,
        confidence=run.confidence,
        error=run.error,
        total_tasks=total_tasks,
        completed_tasks=completed_tasks,
        running_tasks=running_tasks,
        failed_tasks=failed_tasks,
        pending_tasks=pending_tasks,
        progress=progress,
        current_task=current_task,
        tasks=task_reads,
        events=event_reads,
        findings=finding_previews,
        previous_runs_count=prev_count,
    )


@router.get(
    "/api/analysis/{run_id}",
    response_model=AnalysisRunLiveResponse,
    summary="Get Live Analysis Run State & Task DAG",
    description="Returns the real-time execution state, task graph, and emitted event stream for an AnalysisRun.",
)
def get_live_analysis_state(run_id: str, db: Session = Depends(get_db)):
    run = db.query(AnalysisRunModel).filter(AnalysisRunModel.id == run_id).first()
    if not run:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"AnalysisRun '{run_id}' not found.",
        )
    return _build_live_response(run, db)


@router.get(
    "/api/investigations/{id}/analysis",
    response_model=AnalysisRunLiveResponse,
    summary="Get Analysis Run State by Investigation Context",
    description="Resolves and returns the AnalysisRun associated with an investigation ID, incident number, or evidence ID.",
)
def get_investigation_live_analysis(id: str, db: Session = Depends(get_db)):
    run = AnalysisOrchestrator.resolve_run_for_investigation(db, id)
    if not run:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No analysis run associated with investigation identifier '{id}'.",
        )
    return _build_live_response(run, db)


@router.post(
    "/api/analysis/{run_id}/start",
    response_model=AnalysisRunLiveResponse,
    summary="Execute or Resume Live Analysis",
    description="Triggers live DAG task execution for an AnalysisRun.",
)
async def start_live_analysis(run_id: str, db: Session = Depends(get_db)):
    run = db.query(AnalysisRunModel).filter(AnalysisRunModel.id == run_id).first()
    if not run:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"AnalysisRun '{run_id}' not found.",
        )
    if run.status == "RUNNING":
        return _build_live_response(run, db)

    # Execute
    updated_run = await AnalysisOrchestrator.execute_run(db, run_id)
    return _build_live_response(updated_run, db)


@router.post(
    "/api/analysis/{run_id}/cancel",
    response_model=AnalysisRunLiveResponse,
    summary="Cancel Live Analysis",
    description="Cancels an in-progress or queued AnalysisRun.",
)
def cancel_live_analysis(run_id: str, db: Session = Depends(get_db)):
    try:
        updated_run = AnalysisOrchestrator.cancel_run(db, run_id)
        return _build_live_response(updated_run, db)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.post(
    "/api/analysis/{run_id}/retry",
    response_model=AnalysisRunLiveResponse,
    summary="Retry Live Analysis",
    description="Safely resets failed tasks and retriggers execution for an AnalysisRun.",
)
async def retry_live_analysis(run_id: str, db: Session = Depends(get_db)):
    try:
        run = AnalysisOrchestrator.retry_run(db, run_id)
        # Execute asynchronously
        updated_run = await AnalysisOrchestrator.execute_run(db, run.id)
        return _build_live_response(updated_run, db)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.get(
    "/api/analysis/{run_id}/stream",
    summary="Stream Live Analysis Events (SSE - Section 46)",
    description="Provides real-time Server-Sent Events stream for an active AnalysisRun with tenant isolation, Last-Event-ID replay, and keepalive heartbeats.",
)
async def stream_live_analysis(
    run_id: str,
    last_event_id: Optional[str] = Header(None, alias="Last-Event-ID"),
    last_event_query: Optional[str] = Query(None, alias="last_event_id"),
    x_workspace_id: Optional[str] = Header("default", alias="X-Workspace-ID"),
    workspace_id_query: Optional[str] = Query(None, alias="workspace_id"),
    db: Session = Depends(get_db),
):
    workspace = (workspace_id_query or x_workspace_id or "default").strip()

    run = db.query(AnalysisRunModel).filter(AnalysisRunModel.id == run_id).first()
    if not run:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"AnalysisRun '{run_id}' not found.",
        )

    # Validate tenant isolation if artifact specifies a workspace
    artifact = db.query(ArtifactModel).filter(ArtifactModel.id == run.artifact_id).first()
    if artifact:
        art_ws = getattr(artifact, "workspace_id", None)
        if art_ws in (None, "default") and artifact.metadata_json:
            try:
                meta = json.loads(artifact.metadata_json)
                art_ws = meta.get("workspace_id")
            except Exception:
                pass
        if art_ws and art_ws not in ("default", workspace):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: AnalysisRun belongs to a different workspace.",
            )

    # Initial snapshot
    initial_snapshot = _build_live_response(run, db).model_dump(mode="json")

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
            from backend.services.realtime_service import global_realtime_hub
            missed_events = global_realtime_hub.replay_analysis_events(
                db=db,
                run_id=run_id,
                since_sequence=since_seq,
            )
            for m_evt in missed_events:
                yield f"id: {m_evt.sequence}\nevent: {m_evt.event_type.lower()}\ndata: {json.dumps(m_evt.model_dump(mode='json'))}\n\n"

        # If already terminal, emit terminal status and terminate
        if run.status in ("COMPLETED", "PARTIAL", "FAILED", "CANCELLED"):
            yield f"event: terminal\ndata: {json.dumps({'status': run.status, 'analysis_run_id': run.id})}\n\n"
            return

        # 3. Subscribe to real-time event hub
        queue = await global_event_hub.subscribe(run_id)
        try:
            while True:
                try:
                    # Wait for next event or 15s keepalive ping
                    msg = await asyncio.wait_for(queue.get(), timeout=15.0)

                    # Extract sequence and event type
                    seq = msg.get("sequence") or msg.get("event", {}).get("sequence") or ""
                    evt_type = (
                        msg.get("event_type")
                        or msg.get("event", {}).get("event_type")
                        or msg.get("type", "message")
                    )

                    id_line = f"id: {seq}\n" if seq else ""
                    yield f"{id_line}event: {str(evt_type).lower()}\ndata: {json.dumps(msg)}\n\n"

                    # Also emit generic 'event' for Section 37 compatibility
                    if msg.get("type") == "EVENT":
                        yield f"event: event\ndata: {json.dumps(msg)}\n\n"

                    # Check for terminal state
                    if evt_type in (
                        "RUN_COMPLETED", "RUN_FAILED", "RUN_CANCELLED",
                        "ANALYSIS_COMPLETED", "ANALYSIS_PARTIAL", "ANALYSIS_FAILED", "ANALYSIS_CANCELLED"
                    ):
                        yield f"event: terminal\ndata: {json.dumps({'event_type': evt_type, 'status': run.status})}\n\n"
                        break

                except asyncio.TimeoutError:
                    # Keepalive heartbeat ping (prevents proxy / browser timeout)
                    yield ": keepalive\n\n"

        finally:
            await global_event_hub.unsubscribe(run_id, queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


# ============================================================================
# SECTION 38: ANALYSIS RESULTS + PROGRESSIVE DISCLOSURE ENDPOINTS
# ============================================================================

@router.get(
    "/api/analysis/{run_id}/results",
    response_model=AnalysisResultsResponse,
    summary="Get Aggregated Analysis Results (Section 38)",
    description="Returns consolidated analysis results supporting 4 progressive disclosure tiers (Executive, Analyst, Investigator, Forensic).",
)
def get_analysis_results_endpoint(
    run_id: str,
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db),
):
    results = AnalysisResultsAggregator.get_results_for_run(db, run_id, workspace_id)
    if not results:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"AnalysisRun '{run_id}' not found.",
        )
    return results


@router.get(
    "/api/investigations/{identifier}/analysis/results",
    response_model=AnalysisResultsResponse,
    summary="Get Investigation Analysis Results (Section 38)",
    description="Resolves investigation ID, incident number, evidence ID, or artifact SHA-256 and returns consolidated analysis results.",
)
def get_investigation_analysis_results_endpoint(
    identifier: str,
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db),
):
    run = AnalysisOrchestrator.resolve_run_for_investigation(db, identifier)
    if not run:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No active analysis run found for investigation identifier '{identifier}'.",
        )
    results = AnalysisResultsAggregator.get_results_for_run(db, run.id, workspace_id)
    if not results:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Failed to compile analysis results for run '{run.id}'.",
        )
    return results


@router.get(
    "/api/analysis/{run_id}/evidence/{evidence_id}",
    response_model=EvidenceDetailResponse,
    summary="Lazy-Load Forensic Evidence Details",
    description="Returns detailed evidence record, provenance, and sanitized values for deep drawer inspection.",
)
def get_evidence_detail_endpoint(
    run_id: str,
    evidence_id: str,
    db: Session = Depends(get_db),
):
    detail = AnalysisResultsAggregator.get_evidence_detail(db, run_id, evidence_id)
    if not detail:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence '{evidence_id}' not found for run '{run_id}'.",
        )
    return detail


@router.post(
    "/api/analysis/{run_id}/reassess",
    response_model=AnalysisResultsResponse,
    summary="Trigger Manual Risk Reassessment",
    description="Executes a controlled risk reassessment through the Unified Risk Engine without creating duplicate evidence records.",
)
def reassess_analysis_run_endpoint(
    run_id: str,
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db),
):
    results = AnalysisResultsAggregator.reassess_run(db, run_id, workspace_id)
    if not results:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"AnalysisRun '{run_id}' not found.",
        )
    return results
