"""
REST API endpoints for Section 16:
Canonical Temporal Correlation & Event Sequencing Engine.
Provides timeline views for incidents, entities, and campaigns, and automated sequence discovery.
"""
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Path, status
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.db.models import IncidentModel, CampaignModel, TemporalSequenceCandidateModel
from backend.schemas.temporal_correlation import (
    IncidentTimelineResponse,
    EntityTimelineResponse,
    CampaignTimelineResponse,
    TemporalSequenceCandidate,
    SequenceAnalysisResponse,
)
from backend.services.temporal_engine import (
    TemporalCorrelationService,
)

router = APIRouter(tags=["Temporal Correlation & Timelines"])


def resolve_workspace(
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    workspace_id_query: str = Query("default", alias="workspace_id"),
) -> str:
    """Resolves workspace from header or query string parameter."""
    return x_workspace_id or workspace_id_query or "default"


@router.get(
    "/api/incidents/{incident_id}/timeline",
    response_model=IncidentTimelineResponse,
    summary="Get chronological incident timeline",
    description="Returns chronologically sorted security events and burst aggregations with pagination and entity filtering."
)
def get_incident_timeline_endpoint(
    incident_id: str = Path(..., description="Target incident UUID"),
    start_time: Optional[datetime] = Query(None, description="Optional start datetime filter (UTC)"),
    end_time: Optional[datetime] = Query(None, description="Optional end datetime filter (UTC)"),
    event_types: Optional[List[str]] = Query(None, description="Optional filter by event types"),
    entity_ids: Optional[List[str]] = Query(None, description="Optional filter by entity canonical keys"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=500, description="Items per page"),
    compress_bursts: bool = Query(True, description="Summarize repetitive identical event bursts"),
    workspace_id: str = Depends(resolve_workspace),
    db: Session = Depends(get_db),
):
    inc = db.query(IncidentModel).filter(
        IncidentModel.id == incident_id,
        IncidentModel.workspace_id == workspace_id,
    ).first()
    if not inc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident {incident_id} not found in workspace '{workspace_id}'."
        )

    return TemporalCorrelationService.get_incident_timeline(
        db=db,
        incident_id=incident_id,
        workspace_id=workspace_id,
        start_time=start_time,
        end_time=end_time,
        event_types=event_types,
        entity_ids=entity_ids,
        page=page,
        page_size=page_size,
        compress_bursts=compress_bursts,
    )


@router.get(
    "/api/entities/{entity_id}/timeline",
    response_model=EntityTimelineResponse,
    summary="Get entity observation timeline",
    description="Returns chronological sequence of security events and telemetry observations involving an entity."
)
def get_entity_timeline_endpoint(
    entity_id: str = Path(..., description="Target entity canonical key (e.g. 'account:alice@example.com', 'ip:198.51.100.5')"),
    start_time: Optional[datetime] = Query(None, description="Optional start datetime filter (UTC)"),
    end_time: Optional[datetime] = Query(None, description="Optional end datetime filter (UTC)"),
    event_types: Optional[List[str]] = Query(None, description="Optional filter by event types"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=500, description="Items per page"),
    compress_bursts: bool = Query(False, description="Summarize repetitive bursts"),
    workspace_id: str = Depends(resolve_workspace),
    db: Session = Depends(get_db),
):
    return TemporalCorrelationService.get_entity_timeline(
        db=db,
        entity_id=entity_id,
        workspace_id=workspace_id,
        start_time=start_time,
        end_time=end_time,
        event_types=event_types,
        page=page,
        page_size=page_size,
        compress_bursts=compress_bursts,
    )


@router.get(
    "/api/incidents/{incident_id}/sequences",
    response_model=List[TemporalSequenceCandidate],
    summary="List temporal sequence candidates for an incident",
    description="Returns pre-computed or saved temporal sequence candidates for an incident."
)
def list_incident_sequences_endpoint(
    incident_id: str = Path(..., description="Target incident UUID"),
    workspace_id: str = Depends(resolve_workspace),
    db: Session = Depends(get_db),
):
    inc = db.query(IncidentModel).filter(
        IncidentModel.id == incident_id,
        IncidentModel.workspace_id == workspace_id,
    ).first()
    if not inc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident {incident_id} not found in workspace '{workspace_id}'."
        )

    cand_models = db.query(TemporalSequenceCandidateModel).filter(
        TemporalSequenceCandidateModel.incident_id == incident_id,
        TemporalSequenceCandidateModel.workspace_id == workspace_id,
    ).order_by(TemporalSequenceCandidateModel.start_time).all()

    results = []
    for cm in cand_models:
        cand = TemporalCorrelationService.get_sequence_by_id(db, cm.id, workspace_id)
        if cand:
            results.append(cand)
    return results


@router.post(
    "/api/incidents/{incident_id}/analyze-sequences",
    response_model=SequenceAnalysisResponse,
    summary="Evaluate and generate temporal sequence candidates",
    description="Executes sub-linear candidate generation and rule evaluation over incident security events."
)
def analyze_incident_sequences_endpoint(
    incident_id: str = Path(..., description="Target incident UUID"),
    workspace_id: str = Depends(resolve_workspace),
    db: Session = Depends(get_db),
):
    inc = db.query(IncidentModel).filter(
        IncidentModel.id == incident_id,
        IncidentModel.workspace_id == workspace_id,
    ).first()
    if not inc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident {incident_id} not found in workspace '{workspace_id}'."
        )

    return TemporalCorrelationService.analyze_incident_sequences(
        db=db,
        incident_id=incident_id,
        workspace_id=workspace_id,
        persist=True,
    )


@router.get(
    "/api/sequences/{sequence_id}",
    response_model=TemporalSequenceCandidate,
    summary="Get temporal sequence candidate details",
    description="Loads a specific sequence candidate with its constituent hydrated events and evidence breakdown."
)
def get_sequence_endpoint(
    sequence_id: str = Path(..., description="Target sequence candidate UUID"),
    workspace_id: str = Depends(resolve_workspace),
    db: Session = Depends(get_db),
):
    cand = TemporalCorrelationService.get_sequence_by_id(db, sequence_id, workspace_id)
    if not cand:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Temporal sequence candidate {sequence_id} not found in workspace '{workspace_id}'."
        )
    return cand


@router.get(
    "/api/campaigns/{campaign_id}/timeline",
    response_model=CampaignTimelineResponse,
    summary="Get multi-incident campaign timeline",
    description="Consolidates chronological security events across all incidents clustered under a campaign candidate."
)
def get_campaign_timeline_endpoint(
    campaign_id: str = Path(..., description="Target campaign UUID"),
    start_time: Optional[datetime] = Query(None, description="Optional start datetime filter (UTC)"),
    end_time: Optional[datetime] = Query(None, description="Optional end datetime filter (UTC)"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=500, description="Items per page"),
    workspace_id: str = Depends(resolve_workspace),
    db: Session = Depends(get_db),
):
    return TemporalCorrelationService.get_campaign_timeline(
        db=db,
        campaign_id=campaign_id,
        workspace_id=workspace_id,
        start_time=start_time,
        end_time=end_time,
        page=page,
        page_size=page_size,
    )
