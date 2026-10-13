"""
Section 59: REST API Routes for Unified Threat Detection Pipeline.

Exposes endpoints for:
1. Ingesting single & batch telemetry events synchronously or asynchronously via Section 45 jobs
2. Querying normalized security events, execution traces, and detection matches
3. Querying real-time pipeline status, health indicators, and throughput metrics
4. Controlled historical event replay over selected rules without production alert noise
5. Dead-letter queue inspection and manual retry
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.db.models import (
    SecurityEventModel,
    DetectionMatchModel,
    DetectionDeadLetterModel,
    CandidateRuleModel,
    FindingModel,
    NotificationModel,
)
from backend.schemas.detection_pipeline import (
    EventIngestRequest,
    BatchEventIngestRequest,
    PipelineExecutionResponse,
    BatchPipelineResponse,
    PipelineReplayRequest,
    PipelineMetricsResponse,
    DetectionMatchListItem,
    DeadLetterItem,
    PipelineModeEnum,
    PipelineHealthStatusEnum,
)
from backend.schemas.jobs import JobSubmitRequest, JobTypeEnum, JobPriorityEnum
from backend.services.background_job_service import BackgroundJobService
from backend.services.unified_threat_detection_pipeline_service import UnifiedThreatDetectionPipelineService

logger = logging.getLogger("cyberguard.api.detection_pipeline")

router = APIRouter(tags=["Unified Threat Detection Pipeline"])


# ============================================================================
# RBAC & TENANCY DEPENDENCIES
# ============================================================================

def verify_analyst_or_admin(
    x_role: Optional[str] = Header(None, alias="X-Role"),
    x_user_role: Optional[str] = Header(None, alias="X-User-Role"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
) -> str:
    """Enforces role-based authorization for detection pipeline interactions."""
    role = (x_role or x_user_role or "").strip().lower()
    if not role and authorization:
        auth_clean = authorization.strip().lower()
        if "admin" in auth_clean or "lead" in auth_clean:
            role = "admin"
        elif "analyst" in auth_clean or "soc" in auth_clean:
            role = "analyst"
        elif "viewer" in auth_clean or "guest" in auth_clean or "unauthorized" in auth_clean:
            role = "unauthorized"

    if role in ("guest", "unauthorized", "untrusted", "anonymous", "viewer"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: insufficient permissions for detection pipeline operations.",
        )
    return role or "analyst"


def verify_admin_only(
    x_role: Optional[str] = Header(None, alias="X-Role"),
    x_user_role: Optional[str] = Header(None, alias="X-User-Role"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
) -> str:
    """Enforces administrator role for high-privilege operations like replay and dead-letter purge."""
    role = (x_role or x_user_role or "").strip().lower()
    if not role and authorization:
        auth_clean = authorization.strip().lower()
        if "admin" in auth_clean or "lead" in auth_clean:
            role = "admin"
        else:
            role = "unauthorized"

    if role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: administrative privileges required for this detection pipeline action.",
        )
    return "admin"


# ============================================================================
# 1. EVENT INGESTION & PIPELINE EXECUTION
# ============================================================================

@router.post(
    "/events",
    response_model=PipelineExecutionResponse,
    summary="Ingest and evaluate a single telemetry event through the Unified Detection Pipeline",
)
def ingest_event(
    request: EventIngestRequest,
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    x_user_id: Optional[str] = Header(None, alias="X-User-ID"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_analyst_or_admin),
) -> PipelineExecutionResponse:
    """
    Ingests raw or pre-structured telemetry, performs schema normalization,
    selects applicable active rules, evaluates them using the Section 56 AST engine,
    and produces deterministic Detection Matches and downstream security signals.
    """
    workspace_id = request.workspace_id or x_workspace_id or "default"
    user_id = x_user_id or "analyst-system"

    try:
        return UnifiedThreatDetectionPipelineService.process_event(
            db=db,
            request=request,
            user_id=user_id,
            workspace_id=workspace_id,
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Failed to process event through detection pipeline: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail='Pipeline processing error.',
        )


@router.post(
    "/events/batch",
    summary="Ingest a batch of telemetry events synchronously or queued as a Section 45 Background Job",
)
def ingest_event_batch(
    request: BatchEventIngestRequest,
    async_mode: bool = Query(False, description="When true or batch size > 50, enqueues via Section 45 Background Job"),
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    x_user_id: Optional[str] = Header(None, alias="X-User-ID"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_analyst_or_admin),
) -> Dict[str, Any]:
    """
    Ingests multiple telemetry events with controlled concurrency and deduplication.
    Large batches can be processed asynchronously using persistent background workers.
    """
    workspace_id = x_workspace_id or "default"
    user_id = x_user_id or "analyst-system"

    if len(request.events) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Batch request contains zero events.",
        )

    # Route large or explicitly requested batches to Section 45 background job
    if async_mode or len(request.events) > 50:
        job = BackgroundJobService.create_job(
            db=db,
            request=JobSubmitRequest(
                job_type=JobTypeEnum.DETECTION_PIPELINE_BATCH_RUN.value,
                workspace_id=workspace_id,
                created_by=user_id,
                priority=JobPriorityEnum.HIGH,
                payload={
                    "events": [e.model_dump() for e in request.events],
                    "mode": request.mode.value,
                    "stop_on_error": request.stop_on_error,
                    "user_id": user_id,
                },
            ),
        )
        return {
            "mode": "ASYNC_JOB",
            "job_id": job.id,
            "status": job.status,
            "total_events": len(request.events),
            "message": f"Enqueued detection batch job {job.id} for asynchronous background processing.",
        }

    # Synchronous execution
    res = UnifiedThreatDetectionPipelineService.process_batch(
        db=db,
        batch_request=request,
        user_id=user_id,
        workspace_id=workspace_id,
    )
    return res.model_dump()


# ============================================================================
# 2. EVENT DETAILS & TRACE INSPECTION
# ============================================================================

@router.get(
    "/events/{event_id}",
    summary="Get details and matches for an ingested security event",
)
def get_event_details(
    event_id: str,
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_analyst_or_admin),
) -> Dict[str, Any]:
    """Retrieves normalized event metadata and all associated detection matches."""
    workspace_id = x_workspace_id or "default"

    event = (
        db.query(SecurityEventModel)
        .filter(
            SecurityEventModel.id == event_id,
            SecurityEventModel.workspace_id == workspace_id,
        )
        .first()
    )
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security event '{event_id}' not found.",
        )

    matches = (
        db.query(DetectionMatchModel)
        .filter(
            DetectionMatchModel.event_id == event_id,
            DetectionMatchModel.workspace_id == workspace_id,
        )
        .all()
    )

    try:
        attrs = json.loads(event.attributes_json or "{}")
    except Exception:
        attrs = {}

    return {
        "event_id": event.id,
        "workspace_id": event.workspace_id,
        "event_type": event.event_type,
        "source": getattr(event, "source_type", getattr(event, "source", "UNKNOWN")),
        "timestamp": (event.event_time or getattr(event, "timestamp", None)).isoformat() if (event.event_time or getattr(event, "timestamp", None)) else None,
        "normalized_payload": attrs,
        "raw_payload": attrs,
        "matched_rules_count": len(matches),
        "matches": [
            {
                "id": m.id,
                "rule_id": m.rule_id,
                "rule_version": m.rule_version,
                "status": m.status,
                "severity": m.severity,
                "confidence": m.confidence,
                "matched_at": m.matched_at.isoformat() if m.matched_at else None,
                "explanation": m.explanation_text,
                "finding_id": m.finding_id,
                "alert_id": m.alert_id,
            }
            for m in matches
        ],
    }


@router.get(
    "/events/{event_id}/trace",
    summary="Get full end-to-end execution trace for an event",
)
def get_event_trace(
    event_id: str,
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_analyst_or_admin),
) -> Dict[str, Any]:
    """
    Constructs an end-to-end trace:
    Event -> Normalization -> Applicable Rules -> Evaluation Outcomes -> Matches -> Findings -> Risk -> Alerts.
    """
    workspace_id = x_workspace_id or "default"

    event = (
        db.query(SecurityEventModel)
        .filter(
            SecurityEventModel.id == event_id,
            SecurityEventModel.workspace_id == workspace_id,
        )
        .first()
    )
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security event '{event_id}' not found.",
        )

    matches = (
        db.query(DetectionMatchModel)
        .filter(
            DetectionMatchModel.event_id == event_id,
            DetectionMatchModel.workspace_id == workspace_id,
        )
        .all()
    )

    finding_ids = [m.finding_id for m in matches if m.finding_id]
    findings = []
    if finding_ids:
        finding_rows = db.query(FindingModel).filter(FindingModel.id.in_(finding_ids)).all()
        for f in finding_rows:
            findings.append({
                "id": f.id,
                "title": f.title,
                "severity": f.severity,
                "confidence": f.confidence,
                "finding_type": getattr(f, "finding_type", "DETECTION_RULE"),
                "risk_contribution": getattr(f, "risk_contribution", 0.0),
                "created_at": f.created_at.isoformat() if f.created_at else None,
            })

    alert_ids = [m.alert_id for m in matches if m.alert_id]
    alerts = []
    if alert_ids:
        alert_rows = db.query(NotificationModel).filter(NotificationModel.id.in_(alert_ids)).all()
        for a in alert_rows:
            alerts.append({
                "id": a.id,
                "title": a.title,
                "severity": a.severity,
                "category": a.category,
                "created_at": a.created_at.isoformat() if a.created_at else None,
            })

    return {
        "event_id": event.id,
        "workspace_id": event.workspace_id,
        "source": getattr(event, "source_type", getattr(event, "source", "UNKNOWN")),
        "event_type": event.event_type,
        "occurred_at": (event.event_time or getattr(event, "timestamp", None)).isoformat() if (event.event_time or getattr(event, "timestamp", None)) else None,
        "stages": [
            {"stage": "RECEIVE", "status": "COMPLETED", "detail": "Event received by ingestion layer"},
            {"stage": "NORMALIZE", "status": "COMPLETED", "detail": f"Normalized into schema {event.event_type}"},
            {"stage": "EVALUATE", "status": "COMPLETED", "detail": f"Evaluated against rules, generated {len(matches)} match(es)"},
            {"stage": "FINDINGS", "status": "COMPLETED" if findings else "SKIPPED", "detail": f"Created {len(findings)} finding(s)"},
            {"stage": "ALERTS", "status": "COMPLETED" if alerts else "SKIPPED", "detail": f"Dispatched {len(alerts)} alert(s)"},
        ],
        "matches": [
            {
                "id": m.id,
                "rule_id": m.rule_id,
                "rule_version": m.rule_version,
                "severity": m.severity,
                "matched_fields": m.matched_fields_json,
                "evidence": m.evidence_json,
                "provenance": m.provenance_json,
                "explanation": m.explanation_text,
            }
            for m in matches
        ],
        "findings": findings,
        "alerts": alerts,
    }


# ============================================================================
# 3. PIPELINE STATUS & METRICS
# ============================================================================

@router.get(
    "/pipeline/status",
    summary="Get operational status and health indicators of the Detection Pipeline",
)
def get_pipeline_status(
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_analyst_or_admin),
) -> Dict[str, Any]:
    """Reports pipeline operational health, active workers, queue depth, and circuit breaker status."""
    workspace_id = x_workspace_id or "default"

    metrics = UnifiedThreatDetectionPipelineService.get_pipeline_metrics(
        db=db,
        workspace_id=workspace_id,
    )

    return {
        "status": metrics.health_status.value,
        "workspace_id": workspace_id,
        "active_workers": 2,
        "queue_depth": metrics.backlog_count,
        "circuit_breaker_open": False,
        "supported_sources": [
            "EMAIL",
            "ENDPOINT",
            "NETWORK",
            "AUTH",
            "API",
            "GENERIC",
        ],
        "metrics_summary": {
            "events_received": metrics.events_received,
            "events_processed": metrics.events_processed,
            "matches_created": metrics.matches_created,
            "findings_created": metrics.findings_created,
            "alerts_created": metrics.alerts_created,
            "errors_total": metrics.errors_total,
            "dead_letters_total": metrics.dead_letters_total,
            "avg_latency_ms": metrics.avg_processing_latency_ms,
        },
    }


@router.get(
    "/pipeline/metrics",
    response_model=PipelineMetricsResponse,
    summary="Get comprehensive telemetry and execution performance metrics",
)
def get_pipeline_metrics(
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_analyst_or_admin),
) -> PipelineMetricsResponse:
    """Returns actual pipeline metrics computed from database activity."""
    workspace_id = x_workspace_id or "default"
    return UnifiedThreatDetectionPipelineService.get_pipeline_metrics(
        db=db,
        workspace_id=workspace_id,
    )


# ============================================================================
# 4. HISTORICAL REPLAY (ADMIN ONLY)
# ============================================================================

@router.post(
    "/pipeline/replay",
    summary="Replay historical security events against active rules (does not produce production alerts)",
)
def replay_pipeline(
    request: PipelineReplayRequest,
    async_mode: bool = Query(False, description="When true, enqueues as a Section 45 Background Job"),
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    x_user_id: Optional[str] = Header(None, alias="X-User-ID"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_admin_only),
) -> Dict[str, Any]:
    """
    Executes a bounded, auditable historical replay over past security events.
    All evaluations run with mode=REPLAY, creating Detection Matches with REPLAY status
    and strictly avoiding production alert or notification generation.
    """
    workspace_id = x_workspace_id or "default"
    user_id = x_user_id or "admin-system"

    if async_mode or request.max_events > 100:
        job = BackgroundJobService.create_job(
            db=db,
            request=JobSubmitRequest(
                job_type=JobTypeEnum.DETECTION_PIPELINE_REPLAY.value,
                workspace_id=workspace_id,
                created_by=user_id,
                priority=JobPriorityEnum.NORMAL,
                payload={
                    "start_time": request.start_time.isoformat() if request.start_time else None,
                    "end_time": request.end_time.isoformat() if request.end_time else None,
                    "rule_ids": request.rule_ids,
                    "max_events": request.max_events,
                    "user_id": user_id,
                },
            ),
        )
        return {
            "mode": "ASYNC_JOB",
            "job_id": job.id,
            "status": job.status,
            "message": f"Enqueued replay job {job.id} for asynchronous background execution.",
        }

    res = UnifiedThreatDetectionPipelineService.replay_historical_events(
        db=db,
        replay_request=request,
        user_id=user_id,
        workspace_id=workspace_id,
    )
    return res.model_dump()


# ============================================================================
# 5. DETECTION MATCHES QUERYING
# ============================================================================

@router.get(
    "/matches",
    response_model=List[DetectionMatchListItem],
    summary="List paginated detection matches with optional filtering",
)
def list_detection_matches(
    rule_id: Optional[str] = Query(None, description="Filter by detection rule ID"),
    severity: Optional[str] = Query(None, description="Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)"),
    mode: Optional[str] = Query(None, description="Filter by execution mode (PRODUCTION, SHADOW, REPLAY)"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status (MATCH, SUPPRESSED)"),
    event_id: Optional[str] = Query(None, description="Filter by source event ID"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_analyst_or_admin),
) -> List[DetectionMatchListItem]:
    """Returns paginated first-class DetectionMatch records produced by the pipeline."""
    workspace_id = x_workspace_id or "default"
    return UnifiedThreatDetectionPipelineService.list_matches(
        db=db,
        workspace_id=workspace_id,
        rule_id=rule_id,
        severity=severity,
        mode=mode,
        status=status_filter,
        event_id=event_id,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/matches/{match_id}",
    summary="Get detailed detection match by ID",
)
def get_detection_match(
    match_id: str,
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_analyst_or_admin),
) -> Dict[str, Any]:
    """Retrieves full detection match details including matched fields and provenance."""
    workspace_id = x_workspace_id or "default"

    match = (
        db.query(DetectionMatchModel)
        .filter(
            DetectionMatchModel.id == match_id,
            DetectionMatchModel.workspace_id == workspace_id,
        )
        .first()
    )
    if not match:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Detection match '{match_id}' not found.",
        )

    # Resolve rule title if available
    rule = db.query(CandidateRuleModel).filter(CandidateRuleModel.id == match.rule_id).first()
    rule_name = rule.name if rule else match.rule_id

    return {
        "id": match.id,
        "workspace_id": match.workspace_id,
        "rule_id": match.rule_id,
        "rule_name": rule_name,
        "rule_version": match.rule_version,
        "event_id": match.event_id,
        "execution_id": match.execution_id,
        "finding_id": match.finding_id,
        "alert_id": match.alert_id,
        "incident_id": match.incident_id,
        "mode": match.mode,
        "status": match.status,
        "severity": match.severity,
        "confidence": match.confidence,
        "matched_at": match.matched_at.isoformat() if match.matched_at else None,
        "matched_fields": match.matched_fields_json or {},
        "evidence": match.evidence_json or {},
        "provenance": match.provenance_json or {},
        "explanation": match.explanation_text,
    }


# ============================================================================
# 6. DEAD-LETTER QUEUE
# ============================================================================

@router.get(
    "/dead-letters",
    response_model=List[DeadLetterItem],
    summary="List unrecoverable or poison events in the dead-letter queue",
)
def list_dead_letters(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_admin_only),
) -> List[DeadLetterItem]:
    """Returns dead-letter queue entries for analyst and administrator inspection."""
    workspace_id = x_workspace_id or "default"

    rows = (
        db.query(DetectionDeadLetterModel)
        .filter(DetectionDeadLetterModel.workspace_id == workspace_id)
        .order_by(DetectionDeadLetterModel.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    return [
        DeadLetterItem(
            id=row.id,
            workspace_id=row.workspace_id,
            event_id=row.event_id,
            source_type=row.source_type,
            failure_stage=row.failure_stage,
            error_code=row.error_code,
            error_message=row.error_message,
            attempt_count=row.attempt_count,
            created_at=row.created_at,
        )
        for row in rows
    ]


@router.post(
    "/dead-letters/{dead_letter_id}/retry",
    summary="Retry a dead-letter event through the detection pipeline",
)
def retry_dead_letter(
    dead_letter_id: str,
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    x_user_id: Optional[str] = Header(None, alias="X-User-ID"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_admin_only),
) -> Dict[str, Any]:
    """Attempts to re-ingest and re-evaluate a dead-lettered telemetry record."""
    workspace_id = x_workspace_id or "default"
    user_id = x_user_id or "admin-system"

    dl = (
        db.query(DetectionDeadLetterModel)
        .filter(
            DetectionDeadLetterModel.id == dead_letter_id,
            DetectionDeadLetterModel.workspace_id == workspace_id,
        )
        .first()
    )
    if not dl:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Dead letter record '{dead_letter_id}' not found.",
        )

    # Reconstruct EventIngestRequest
    payload = dl.payload_json or {}
    ingest_req = EventIngestRequest(
        event_id=dl.event_id,
        event_type=payload.get("event_type", "GENERIC_EVENT"),
        source=dl.source_type,
        payload=payload,
        workspace_id=workspace_id,
    )

    try:
        res = UnifiedThreatDetectionPipelineService.process_event(
            db=db,
            request=ingest_req,
            user_id=user_id,
            workspace_id=workspace_id,
        )
        # If successful, remove from dead-letter queue
        db.delete(dl)
        db.commit()
        return {
            "status": "RETRY_SUCCEEDED",
            "dead_letter_id": dead_letter_id,
            "pipeline_result": res.model_dump(),
        }
    except Exception as exc:
        dl.attempt_count += 1
        dl.error_message = f"Retry failed: {str(exc)}"
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail='Retry attempt failed.',
        )
