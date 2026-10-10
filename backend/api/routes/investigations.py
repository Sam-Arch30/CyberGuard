"""
API Routes for Section 39: Investigation Workspace.
Provides unified aggregation, status lifecycle management, notes, evidence browser,
and truthful timeline events.
"""
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.schemas.investigation_workspace import (
    AnalystNoteModel,
    InvestigationEvidenceItem,
    InvestigationNoteCreate,
    InvestigationStatusUpdate,
    InvestigationTimelineEventItem,
    InvestigationWorkspaceSummary,
)
from datetime import datetime, timezone
from backend.db.models import ReportModel
from backend.schemas.attack_path_projection import AttackPathDetailResponse
from backend.schemas.response_recommendation import ResponseRecommendationResponse
from backend.schemas.report import (
    ReportDetailResponse,
    ReportListItemResponse,
    InvestigationReportGenerateRequest,
    InvestigationReportPreviewRequest,
)
from backend.services.attack_path_service import AttackPathService
from backend.services.investigation_workspace_service import (
    InvestigationWorkspaceService,
)
from backend.services.report_projection_service import ReportProjectionService
from backend.services.response_recommendation_engine import ResponseRecommendationEngine
from backend.api.routes.response_recommendations import _serialize_rec
from backend.api.routes.reports import (
    _serialize_report_detail,
    _serialize_report_item,
    generate_investigation_report_endpoint,
)
from backend.schemas.search import InvestigationListResponse
from backend.services.search_service import SearchService

router = APIRouter(prefix="/api/investigations", tags=["Investigation Workspace"])


@router.get(
    "",
    response_model=InvestigationListResponse,
    summary="List and Filter Historical Investigations",
    description="Returns a paginated, searchable list of persistent investigations with real counts, risk scores, status, and filter facets.",
)
def list_investigations_endpoint(
    q: Optional[str] = Query(None, description="Search keyword or identifier"),
    risk: Optional[str] = Query(None, description="Risk level filter (CRITICAL, HIGH, MEDIUM, LOW)"),
    severity: Optional[str] = Query(None, description="Severity filter"),
    status: Optional[str] = Query(None, description="Status filter (OPEN, INVESTIGATING, CONTAINED, RESOLVED, CLOSED)"),
    source: Optional[str] = Query(None, description="Source type filter (EMAIL, URL, FILE, NETWORK, API)"),
    from_time: Optional[datetime] = Query(None, description="Created on or after"),
    to_time: Optional[datetime] = Query(None, description="Created on or before"),
    sort: str = Query("updated_desc", description="Sort order: updated_desc, created_desc, risk_desc"),
    limit: int = Query(25, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    return SearchService.list_investigations(
        db=db,
        q=q,
        risk_filter=risk,
        severity_filter=severity,
        status_filter=status,
        source_filter=source,
        from_time=from_time,
        to_time=to_time,
        sort_by=sort,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/{identifier}/summary",
    response_model=InvestigationWorkspaceSummary,
    summary="Get Consolidated Investigation Workspace Summary",
    description="Resolves any investigation ID, incident number, analysis run ID, or evidence ID to return the authoritative 9-workspace summary.",
)
def get_investigation_workspace_summary(
    identifier: str,
    db: Session = Depends(get_db),
):
    summary = InvestigationWorkspaceService.get_workspace_summary(db, identifier)
    if not summary:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation with identifier '{identifier}' was not found.",
        )
    return summary


@router.patch(
    "/{identifier}/status",
    response_model=InvestigationWorkspaceSummary,
    summary="Update Investigation Status Lifecycle",
    description="Enforces validated status state transitions (OPEN -> INVESTIGATING -> CONTAINED -> RESOLVED -> CLOSED) and audits transitions.",
)
def update_investigation_status(
    identifier: str,
    payload: InvestigationStatusUpdate,
    db: Session = Depends(get_db),
):
    try:
        updated = InvestigationWorkspaceService.update_status(
            db,
            identifier=identifier,
            new_status=payload.status,
            reason=payload.reason,
            analyst=payload.analyst or "SOC Analyst",
        )
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(val_err),
        )

    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation with identifier '{identifier}' was not found.",
        )
    return updated


@router.post(
    "/{identifier}/notes",
    response_model=AnalystNoteModel,
    status_code=status.HTTP_201_CREATED,
    summary="Add an Attributed Analyst Note",
    description="Appends a persistent, timestamped analyst note to the investigation and records an audit log event.",
)
def add_investigation_note(
    identifier: str,
    payload: InvestigationNoteCreate,
    db: Session = Depends(get_db),
):
    note = InvestigationWorkspaceService.add_note(
        db,
        identifier=identifier,
        note_text=payload.note_text,
        author=payload.author or "SOC Analyst",
    )
    if not note:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation with identifier '{identifier}' was not found.",
        )
    return note


@router.get(
    "/{identifier}/notes",
    response_model=List[AnalystNoteModel],
    summary="List Investigation Analyst Notes",
    description="Returns all chronological analyst notes recorded for this investigation.",
)
def list_investigation_notes(
    identifier: str,
    db: Session = Depends(get_db),
):
    summary = InvestigationWorkspaceService.get_workspace_summary(db, identifier)
    if not summary:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation with identifier '{identifier}' was not found.",
        )
    return summary.analyst_notes


@router.get(
    "/{identifier}/evidence",
    response_model=List[InvestigationEvidenceItem],
    summary="Get Investigation Evidence List",
    description="Lists forensic evidence items, distinguishing immutable original files from derived signals.",
)
def get_investigation_evidence(
    identifier: str,
    db: Session = Depends(get_db),
):
    items = InvestigationWorkspaceService.get_evidence_list(db, identifier)
    if not items:
        # Check if investigation actually exists
        summary = InvestigationWorkspaceService.get_workspace_summary(db, identifier)
        if not summary:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Investigation with identifier '{identifier}' was not found.",
            )
    return items


@router.get(
    "/{identifier}/timeline",
    response_model=List[InvestigationTimelineEventItem],
    summary="Get Investigation Chronological Timeline",
    description="Returns chronological events linking ingestion, analytical findings, threat progression, and audit records.",
)
def get_investigation_timeline(
    identifier: str,
    db: Session = Depends(get_db),
):
    events = InvestigationWorkspaceService.get_timeline_events(db, identifier)
    if not events:
        summary = InvestigationWorkspaceService.get_workspace_summary(db, identifier)
        if not summary:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Investigation with identifier '{identifier}' was not found.",
            )
    return events


@router.get(
    "/{identifier}/attack-path",
    response_model=AttackPathDetailResponse,
    summary="Get Interactive Attack Path Projection",
    description="Returns path-level projection of the security knowledge graph, stages, causal vs temporal transitions, gaps, and alternatives.",
)
def get_investigation_attack_path(
    identifier: str,
    run_id: Optional[str] = Query(None, description="Optional specific Analysis Run ID to view"),
    force_reconstruct: bool = Query(False, description="Force re-evaluation of attack reconstruction DAG"),
    db: Session = Depends(get_db),
):
    detail = AttackPathService.get_attack_path_detail(
        db=db,
        identifier=identifier,
        run_id=run_id,
        force_reconstruct=force_reconstruct,
    )
    if not detail:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation with identifier '{identifier}' was not found.",
        )
    return detail


@router.get(
    "/{identifier}/response",
    response_model=List[ResponseRecommendationResponse],
    summary="Get Investigation Defensive Response Recommendations",
    description="Returns prioritized, grounded defensive response recommendations for the investigation decision surface.",
)
@router.get(
    "/{identifier}/recommendations",
    response_model=List[ResponseRecommendationResponse],
    summary="Get Investigation Response Recommendations (Alias)",
    description="Alias for /{identifier}/response.",
)
def get_investigation_response_recommendations(
    identifier: str,
    db: Session = Depends(get_db),
):
    summary = InvestigationWorkspaceService.get_workspace_summary(db, identifier)
    if not summary:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation with identifier '{identifier}' was not found.",
        )

    recs = ResponseRecommendationEngine.generate_recommendations(
        db=db,
        scope_type="INVESTIGATION",
        scope_id=identifier,
        force_regenerate=False,
    )
    return [_serialize_rec(r) for r in recs]


# -----------------------------------------------------------------------------
# Section 42: Investigation Report Workspace Routes
# -----------------------------------------------------------------------------

@router.get(
    "/{identifier}/report",
    response_model=ReportDetailResponse,
    summary="Get Investigation Report Snapshot or Live Draft Preview",
    description="Returns the latest immutable report version for this investigation, or a live draft projection if none has been persisted yet.",
)
def get_investigation_report(
    identifier: str,
    db: Session = Depends(get_db),
):
    incident, run, artifact, case = InvestigationWorkspaceService.resolve_context(db, identifier)
    if not incident and not run and not artifact:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation with identifier '{identifier}' was not found.",
        )

    inv_key = incident.id if incident else (run.id if run else identifier)
    latest_report = (
        db.query(ReportModel)
        .filter((ReportModel.investigation_id == inv_key) | (ReportModel.investigation_id == identifier))
        .order_by(ReportModel.report_version.desc())
        .first()
    )

    if latest_report:
        is_stale = ReportProjectionService.check_staleness(db, latest_report)
        return _serialize_report_detail(latest_report, is_stale=is_stale)

    # If no report persisted yet, build draft projection on the fly
    snapshot = ReportProjectionService.build_projection(
        db=db,
        identifier=identifier,
        report_type="ANALYST",
        classification="CONFIDENTIAL",
        redaction_level="NONE",
        report_version=0,
    )
    score_val = snapshot["risk_assessment"].get("risk_score", 0.0)
    sev_val = snapshot["risk_assessment"].get("severity", "medium").lower()

    return ReportDetailResponse(
        id="draft",
        report_number="DRAFT-PREVIEW",
        title=snapshot["metadata"].get("title", "Draft Incident Report"),
        investigation_id=inv_key,
        incident_number=snapshot["metadata"].get("incident_number", "INV-DRAFT"),
        case_id=case.id if case else None,
        evidence_id=artifact.id if artifact else None,
        email_sha256=artifact.sha256 if artifact else None,
        threat_score=score_val,
        severity=sev_val,
        confidence=snapshot["risk_assessment"].get("confidence", 1.0),
        report_type="ANALYST",
        status="DRAFT",
        report_version=0,
        classification="CONFIDENTIAL",
        redaction_level="NONE",
        is_stale=False,
        analyst_name="SOC Lead Analyst",
        summary=snapshot["executive_summary"].get("synthesized_narrative", ""),
        file_size_bytes=0,
        created_at=datetime.now(timezone.utc),
        download_url="/api/reports/draft/download",
        json_url="/api/reports/draft/json",
        content_options={},
        quality_check=snapshot.get("quality_check", {}),
        snapshot=snapshot,
        provenance=snapshot.get("provenance", {}),
    )


@router.post(
    "/{identifier}/report/generate",
    response_model=ReportDetailResponse,
    summary="Generate New Immutable Report Version for Investigation",
    description="Compiles and persists an immutable report version (e.g., v1, v2) for this investigation.",
)
def generate_report_for_investigation(
    identifier: str,
    payload: InvestigationReportGenerateRequest,
    format: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    req = payload.model_copy(update={"investigation_id": identifier})
    return generate_investigation_report_endpoint(request=req, format=format, db=db)


@router.post(
    "/{identifier}/report/preview",
    response_model=ReportDetailResponse,
    summary="Preview Investigation Report Projection With Custom Options",
    description="Generates an ephemeral report preview projection without persisting to the database.",
)
def preview_investigation_report(
    identifier: str,
    payload: InvestigationReportPreviewRequest,
    db: Session = Depends(get_db),
):
    incident, run, artifact, case = InvestigationWorkspaceService.resolve_context(db, identifier)
    if not incident and not run and not artifact:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation with identifier '{identifier}' was not found.",
        )

    content_opts_dict = payload.content_options.model_dump() if payload.content_options else {}
    snapshot = ReportProjectionService.build_projection(
        db=db,
        identifier=identifier,
        report_type=payload.report_type,
        classification=payload.classification,
        redaction_level=payload.redaction_level,
        content_options=content_opts_dict,
        analyst_name=payload.analyst_name or "SOC Lead Analyst",
        notes=payload.notes,
        report_version=0,
    )

    inv_key = incident.id if incident else (run.id if run else identifier)
    score_val = snapshot["risk_assessment"].get("risk_score", 0.0)
    sev_val = snapshot["risk_assessment"].get("severity", "medium").lower()

    return ReportDetailResponse(
        id="preview",
        report_number="PREVIEW",
        title=snapshot["metadata"].get("title", "Preview Incident Report"),
        investigation_id=inv_key,
        incident_number=snapshot["metadata"].get("incident_number", "INV-PREVIEW"),
        case_id=case.id if case else None,
        evidence_id=artifact.id if artifact else None,
        email_sha256=artifact.sha256 if artifact else None,
        threat_score=score_val,
        severity=sev_val,
        confidence=snapshot["risk_assessment"].get("confidence", 1.0),
        report_type=payload.report_type,
        status="DRAFT",
        report_version=0,
        classification=payload.classification,
        redaction_level=payload.redaction_level,
        is_stale=False,
        analyst_name=payload.analyst_name or "SOC Lead Analyst",
        summary=snapshot["executive_summary"].get("synthesized_narrative", ""),
        file_size_bytes=0,
        created_at=datetime.now(timezone.utc),
        download_url="/api/reports/preview/download",
        json_url="/api/reports/preview/json",
        content_options=content_opts_dict,
        quality_check=snapshot.get("quality_check", {}),
        snapshot=snapshot,
        provenance=snapshot.get("provenance", {}),
    )


@router.get(
    "/{identifier}/reports",
    response_model=List[ReportListItemResponse],
    summary="List all report versions for this investigation",
    description="Returns all chronological report snapshots (v1, v2...) generated for this investigation.",
)
def list_investigation_report_versions(
    identifier: str,
    db: Session = Depends(get_db),
):
    incident, run, artifact, case = InvestigationWorkspaceService.resolve_context(db, identifier)
    if not incident and not run and not artifact:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation with identifier '{identifier}' was not found.",
        )

    inv_key = incident.id if incident else (run.id if run else identifier)
    reports = (
        db.query(ReportModel)
        .filter((ReportModel.investigation_id == inv_key) | (ReportModel.investigation_id == identifier))
        .order_by(ReportModel.report_version.desc())
        .all()
    )

    out = []
    for r in reports:
        is_stale = ReportProjectionService.check_staleness(db, r)
        out.append(_serialize_report_item(r, is_stale=is_stale))
    return out


@router.get(
    "/{identifier}/stream",
    summary="Stream Investigation Workspace Real-Time Events (SSE - Section 46)",
    description="Provides real-time Server-Sent Events stream for an investigation, including live analysis progress, newly persisted findings, and report updates.",
)
async def stream_investigation_events(
    identifier: str,
    last_event_id: Optional[str] = Query(None),
    workspace_id: Optional[str] = Query("default"),
    db: Session = Depends(get_db),
):
    import asyncio
    import json
    from fastapi.responses import StreamingResponse
    from backend.services.realtime_service import global_realtime_hub

    incident, run, artifact, case = InvestigationWorkspaceService.resolve_context(db, identifier)
    if not incident and not run and not artifact:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation with identifier '{identifier}' was not found.",
        )

    # Initial snapshot
    summary = InvestigationWorkspaceService.get_workspace_summary(db, identifier)
    summary_data = summary.model_dump(mode="json") if summary else {}

    inv_key = incident.id if incident else (run.id if run else identifier)

    async def event_generator():
        yield f"event: snapshot\ndata: {json.dumps(summary_data)}\n\n"

        # Subscribe to investigation channel and linked analysis run channel if present
        queue_inv = await global_realtime_hub.subscribe(f"investigation:{inv_key}")
        queue_run = None
        if run:
            queue_run = await global_realtime_hub.subscribe(f"run:{run.id}")

        try:
            while True:
                # Merge queues
                try:
                    tasks = [asyncio.create_task(queue_inv.get())]
                    if queue_run:
                        tasks.append(asyncio.create_task(queue_run.get()))

                    done, pending = await asyncio.wait(
                        tasks,
                        timeout=15.0,
                        return_when=asyncio.FIRST_COMPLETED,
                    )
                    for p in pending:
                        p.cancel()

                    if not done:
                        # Timeout - send keepalive
                        yield ": keepalive\n\n"
                        continue

                    for finished_task in done:
                        msg = finished_task.result()
                        evt_type = msg.get("event_type") or "investigation_update"
                        seq = msg.get("sequence") or ""
                        id_line = f"id: {seq}\n" if seq else ""
                        yield f"{id_line}event: {str(evt_type).lower()}\ndata: {json.dumps(msg)}\n\n"

                except asyncio.CancelledError:
                    break
                except Exception as e:
                    yield f": error {str(e)}\n\n"
                    break

        finally:
            await global_realtime_hub.unsubscribe(f"investigation:{inv_key}", queue_inv)
            if queue_run and run:
                await global_realtime_hub.unsubscribe(f"run:{run.id}", queue_run)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )

