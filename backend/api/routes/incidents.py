"""
Section 50: REST API Routes for Incident Management & Case Lifecycle.
Provides endpoints for creating, promoting, triaging, transitioning,
and monitoring operational incidents.
"""
from typing import List, Optional
from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.schemas.incidents import (
    IncidentAssignRequest,
    IncidentCloseRequest,
    IncidentCreateRequest,
    IncidentDetailResponse,
    IncidentItemResponse,
    IncidentListResponse,
    IncidentMetricsResponse,
    IncidentNoteCreateRequest,
    IncidentNoteResponse,
    IncidentPromoteAlertRequest,
    IncidentPromoteClusterRequest,
    IncidentReopenRequest,
    IncidentResolveRequest,
    IncidentStatusChangeRequest,
    IncidentTimelineEventResponse,
    IncidentUpdateRequest,
)
from backend.services.incident_service import IncidentService

router = APIRouter(prefix="/api/incidents", tags=["Incident Management"])


def get_current_workspace(x_workspace_id: Optional[str] = Header(None)) -> str:
    return x_workspace_id or "default"


def get_current_analyst(x_analyst_name: Optional[str] = Header(None)) -> str:
    return x_analyst_name or "SOC Analyst"


@router.get(
    "/metrics",
    response_model=IncidentMetricsResponse,
    summary="Get aggregated incident metrics",
)
def get_incident_metrics_endpoint(
    workspace_id: str = Depends(get_current_workspace),
    db: Session = Depends(get_db),
):
    return IncidentService.get_metrics(db, workspace_id=workspace_id)


@router.get(
    "",
    response_model=IncidentListResponse,
    summary="List and filter incident cases",
)
def list_incidents_endpoint(
    status: Optional[str] = Query(None, description="Filter by status (NEW, OPEN, INVESTIGATING, etc.)"),
    severity: Optional[str] = Query(None, description="Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)"),
    priority: Optional[str] = Query(None, description="Filter by priority (P1_CRITICAL, P2_HIGH, etc.)"),
    category: Optional[str] = Query(None, description="Filter by category (PHISHING, MALWARE, etc.)"),
    assigned_to: Optional[str] = Query(None, description="Filter by assigned analyst or UNASSIGNED"),
    sla_status: Optional[str] = Query(None, description="Filter by SLA status (HEALTHY, WARNING, BREACHED, PAUSED, EXEMPT)"),
    q: Optional[str] = Query(None, description="Search term across number, title, description"),
    sort_by: str = Query("severity_first", description="Sort criteria: severity_first, newest, priority_first, risk_desc, closest_deadline, sla_breach_first"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    workspace_id: str = Depends(get_current_workspace),
    db: Session = Depends(get_db),
):
    items, total = IncidentService.list_incidents(
        db,
        workspace_id=workspace_id,
        status=status,
        severity=severity,
        priority=priority,
        category=category,
        assigned_to=assigned_to,
        sla_status=sla_status,
        q=q,
        sort_by=sort_by,
        limit=limit,
        offset=offset,
    )
    return IncidentListResponse(items=items, total=total, offset=offset, limit=limit)


@router.post(
    "",
    response_model=IncidentItemResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new incident case",
)
def create_incident_endpoint(
    req: IncidentCreateRequest,
    workspace_id: str = Depends(get_current_workspace),
    analyst: str = Depends(get_current_analyst),
    db: Session = Depends(get_db),
):
    incident = IncidentService.create_incident(
        db, req, workspace_id=workspace_id, actor=analyst
    )
    detail = IncidentService.get_incident_detail(db, incident.id, workspace_id)
    return detail


@router.post(
    "/promote-alert",
    response_model=IncidentItemResponse,
    summary="Promote security alert to incident",
)
def promote_alert_endpoint(
    req: IncidentPromoteAlertRequest,
    workspace_id: str = Depends(get_current_workspace),
    analyst: str = Depends(get_current_analyst),
    db: Session = Depends(get_db),
):
    incident = IncidentService.promote_alert_to_incident(
        db, req, workspace_id=workspace_id, actor=analyst
    )
    return incident


@router.post(
    "/promote-cluster",
    response_model=IncidentItemResponse,
    summary="Promote alert cluster to incident",
)
def promote_cluster_endpoint(
    req: IncidentPromoteClusterRequest,
    workspace_id: str = Depends(get_current_workspace),
    analyst: str = Depends(get_current_analyst),
    db: Session = Depends(get_db),
):
    incident = IncidentService.promote_cluster_to_incident(
        db, req, workspace_id=workspace_id, actor=analyst
    )
    return incident


@router.get(
    "/{id}",
    response_model=IncidentDetailResponse,
    summary="Get incident detail with facts and context",
)
def get_incident_detail_endpoint(
    id: str,
    workspace_id: str = Depends(get_current_workspace),
    db: Session = Depends(get_db),
):
    return IncidentService.get_incident_detail(db, id, workspace_id=workspace_id)


@router.patch(
    "/{id}",
    response_model=IncidentDetailResponse,
    summary="Update mutable incident metadata",
)
def update_incident_endpoint(
    id: str,
    req: IncidentUpdateRequest,
    workspace_id: str = Depends(get_current_workspace),
    analyst: str = Depends(get_current_analyst),
    db: Session = Depends(get_db),
):
    IncidentService.update_incident(db, id, req, workspace_id=workspace_id, actor=analyst)
    return IncidentService.get_incident_detail(db, id, workspace_id=workspace_id)


@router.post(
    "/{id}/status",
    response_model=IncidentDetailResponse,
    summary="Transition incident lifecycle status",
)
def transition_status_endpoint(
    id: str,
    req: IncidentStatusChangeRequest,
    workspace_id: str = Depends(get_current_workspace),
    analyst: str = Depends(get_current_analyst),
    db: Session = Depends(get_db),
):
    IncidentService.transition_status(db, id, req, workspace_id=workspace_id, actor=analyst)
    return IncidentService.get_incident_detail(db, id, workspace_id=workspace_id)


@router.post(
    "/{id}/assign",
    response_model=IncidentDetailResponse,
    summary="Assign incident to analyst/team",
)
def assign_incident_endpoint(
    id: str,
    req: IncidentAssignRequest,
    workspace_id: str = Depends(get_current_workspace),
    analyst: str = Depends(get_current_analyst),
    db: Session = Depends(get_db),
):
    IncidentService.assign_incident(db, id, req, workspace_id=workspace_id, actor=analyst)
    return IncidentService.get_incident_detail(db, id, workspace_id=workspace_id)


@router.post(
    "/{id}/resolve",
    response_model=IncidentDetailResponse,
    summary="Resolve incident with required reason",
)
def resolve_incident_endpoint(
    id: str,
    req: IncidentResolveRequest,
    workspace_id: str = Depends(get_current_workspace),
    analyst: str = Depends(get_current_analyst),
    db: Session = Depends(get_db),
):
    change_req = IncidentStatusChangeRequest(
        status="RESOLVED",
        resolution_reason=req.resolution_reason,
        notes=req.notes,
    )
    IncidentService.transition_status(db, id, change_req, workspace_id=workspace_id, actor=analyst)
    return IncidentService.get_incident_detail(db, id, workspace_id=workspace_id)


@router.post(
    "/{id}/close",
    response_model=IncidentDetailResponse,
    summary="Close incident case",
)
def close_incident_endpoint(
    id: str,
    req: IncidentCloseRequest,
    workspace_id: str = Depends(get_current_workspace),
    analyst: str = Depends(get_current_analyst),
    db: Session = Depends(get_db),
):
    change_req = IncidentStatusChangeRequest(
        status="CLOSED",
        notes=req.notes,
    )
    IncidentService.transition_status(db, id, change_req, workspace_id=workspace_id, actor=analyst)
    return IncidentService.get_incident_detail(db, id, workspace_id=workspace_id)


@router.post(
    "/{id}/reopen",
    response_model=IncidentDetailResponse,
    summary="Reopen closed or resolved incident",
)
def reopen_incident_endpoint(
    id: str,
    req: IncidentReopenRequest,
    workspace_id: str = Depends(get_current_workspace),
    analyst: str = Depends(get_current_analyst),
    db: Session = Depends(get_db),
):
    change_req = IncidentStatusChangeRequest(
        status="OPEN",
        reason=req.reason,
        notes=req.notes,
    )
    IncidentService.transition_status(db, id, change_req, workspace_id=workspace_id, actor=analyst)
    return IncidentService.get_incident_detail(db, id, workspace_id=workspace_id)


@router.post(
    "/{id}/notes",
    response_model=IncidentNoteResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Add an analyst note to the incident",
)
def add_incident_note_endpoint(
    id: str,
    req: IncidentNoteCreateRequest,
    workspace_id: str = Depends(get_current_workspace),
    analyst: str = Depends(get_current_analyst),
    db: Session = Depends(get_db),
):
    return IncidentService.add_note(db, id, req, workspace_id=workspace_id, actor=analyst)


@router.get(
    "/{id}/history",
    response_model=List[IncidentTimelineEventResponse],
    summary="Get incident history events",
)
def get_incident_history_endpoint(
    id: str,
    workspace_id: str = Depends(get_current_workspace),
    db: Session = Depends(get_db),
):
    detail = IncidentService.get_incident_detail(db, id, workspace_id=workspace_id)
    return detail.timeline_events
