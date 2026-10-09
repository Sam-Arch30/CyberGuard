"""
Live Analysis & Real-Time Task DAG Execution API Routes (Section 37).
Provides snapshot endpoints, SSE streaming, and interactive analysis control.
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
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
from backend.services.analysis_orchestrator import (
    AnalysisOrchestrator,
    global_event_hub,
)

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

    if not tasks:
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
            confidence=f.confidence or 1.0,
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
        artifact_size=artifact.size if artifact else 0,
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
    summary="Stream Live Analysis Events (SSE)",
    description="Provides real-time Server-Sent Events stream for an active AnalysisRun.",
)
async def stream_live_analysis(run_id: str, db: Session = Depends(get_db)):
    run = db.query(AnalysisRunModel).filter(AnalysisRunModel.id == run_id).first()
    if not run:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"AnalysisRun '{run_id}' not found.",
        )

    # Initial snapshot
    initial_snapshot = _build_live_response(run, db).model_dump(mode="json")

    async def event_generator():
        # 1. Send initial state immediately
        yield f"event: snapshot\ndata: {json.dumps(initial_snapshot)}\n\n"

        # If already terminal, close stream
        if run.status in ("COMPLETED", "PARTIAL", "FAILED", "CANCELLED"):
            yield f"event: terminal\ndata: {json.dumps({'status': run.status})}\n\n"
            return

        # 2. Subscribe to event hub
        queue = await global_event_hub.subscribe(run_id)
        try:
            while True:
                try:
                    # Wait for next event or 15s keepalive ping
                    msg = await asyncio.wait_for(queue.get(), timeout=15.0)
                    yield f"event: {msg.get('type', 'message').lower()}\ndata: {json.dumps(msg)}\n\n"

                    # If run reached terminal state, send terminal event and end
                    if msg.get("type") == "EVENT":
                        evt_type = msg.get("event", {}).get("event_type")
                        if evt_type in ("RUN_COMPLETED", "RUN_FAILED", "RUN_CANCELLED"):
                            yield f"event: terminal\ndata: {json.dumps({'event_type': evt_type})}\n\n"
                            break
                except asyncio.TimeoutError:
                    # Keepalive heartbeat ping
                    yield ": keepalive\n\n"
        finally:
            await global_event_hub.unsubscribe(run_id, queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
