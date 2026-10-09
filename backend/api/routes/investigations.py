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
from backend.schemas.attack_path_projection import AttackPathDetailResponse
from backend.schemas.response_recommendation import ResponseRecommendationResponse
from backend.services.attack_path_service import AttackPathService
from backend.services.investigation_workspace_service import (
    InvestigationWorkspaceService,
)
from backend.services.response_recommendation_engine import ResponseRecommendationEngine
from backend.api.routes.response_recommendations import _serialize_rec

router = APIRouter(prefix="/api/investigations", tags=["Investigation Workspace"])


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
