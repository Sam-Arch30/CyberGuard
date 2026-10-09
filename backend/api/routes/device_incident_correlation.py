"""
REST API Endpoints for Section 33: Device-to-Incident Correlation.
Mounts routes under /api/v1:
- GET  /api/v1/incidents/{incident_id}/devices       : Incident-centric device summary
- GET  /api/v1/devices/{device_id}/incidents         : Device-centric incident history
- GET  /api/v1/incidents/{incident_id}/correlations  : All active correlations for an incident
- GET  /api/v1/devices/{device_id}/correlations      : All active correlations for a device
- POST /api/v1/correlations/{correlation_id}/review  : Analyst review / status override
- GET  /api/v1/devices/{device_id}/timeline          : Unified endpoint activity timeline
- POST /api/v1/devices/{device_id}/correlate         : On-demand correlation execution for a device
- POST /api/v1/incidents/{incident_id}/correlate     : On-demand correlation execution for an incident
"""

import json
import logging
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.db.models import DeviceModel, IncidentModel, DeviceIncidentCorrelationModel
from backend.schemas.device_incident_correlation import (
    DeviceIncidentCorrelationResponse,
    IncidentDevicesSummaryResponse,
    DeviceIncidentsHistoryResponse,
    DeviceTimelineResponse,
    ReviewCorrelationRequest,
    TriggerCorrelationRequest
)
from backend.services.device_incident_correlation_service import DeviceIncidentCorrelationService

logger = logging.getLogger("cyberguard.api.device_incident_correlation")

router = APIRouter(prefix="/api/v1", tags=["Device-to-Incident Correlation"])


def _to_correlation_response(
    c: DeviceIncidentCorrelationModel,
    db: Session
) -> DeviceIncidentCorrelationResponse:
    dev = db.query(DeviceModel).filter(DeviceModel.id == c.device_id).first()
    inc = db.query(IncidentModel).filter(IncidentModel.id == c.incident_id).first()

    return DeviceIncidentCorrelationResponse(
        id=c.id,
        workspace_id=c.workspace_id,
        device_id=c.device_id,
        incident_id=c.incident_id,
        correlation_type=c.correlation_type,
        correlation_score=c.correlation_score,
        confidence=c.confidence,
        status=c.status,
        version=c.version,
        is_current=c.is_current,
        first_observed_at=c.first_observed_at,
        last_observed_at=c.last_observed_at,
        supporting_event_ids=json.loads(c.supporting_event_ids_json or "[]"),
        supporting_evidence_ids=json.loads(c.supporting_evidence_ids_json or "[]"),
        supporting_entity_ids=json.loads(c.supporting_entity_ids_json or "[]"),
        supporting_relationship_ids=json.loads(c.supporting_relationship_ids_json or "[]"),
        matched_indicators=json.loads(c.matched_indicators_json or "[]"),
        matched_behaviors=json.loads(c.matched_behaviors_json or "[]"),
        temporal_context=json.loads(c.temporal_context_json or "{}"),
        reason_codes=json.loads(c.reason_codes_json or "[]"),
        counter_evidence=json.loads(c.counter_evidence_json or "[]"),
        limitations=json.loads(c.limitations_json or "[]"),
        structured_explanation=json.loads(c.structured_explanation_json or "{}"),
        correlation_engine_version=c.correlation_engine_version,
        reviewed_by=c.reviewed_by,
        reviewed_at=c.reviewed_at,
        review_notes=c.review_notes,
        created_at=c.created_at,
        updated_at=c.updated_at,
        device_hostname=dev.hostname if dev else None,
        device_platform=dev.platform if dev else None,
        incident_number=inc.incident_number if inc else None,
        incident_title=inc.title if inc else None
    )


# ============================================================================
# INCIDENT-CENTRIC ENDPOINTS
# ============================================================================

@router.get(
    "/incidents/{incident_id}/devices",
    response_model=IncidentDevicesSummaryResponse,
    summary="Get Incident Devices Summary"
)
def get_incident_devices(
    incident_id: str,
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db)
):
    """
    Returns an incident-centric view of all correlated devices categorized by
    association status (CONFIRMED, SUPPORTED, SUSPECTED, RELATED, OBSERVED, DISMISSED).
    """
    try:
        return DeviceIncidentCorrelationService.get_incident_devices_summary(
            db=db,
            incident_id=incident_id,
            workspace_id=workspace_id
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get(
    "/incidents/{incident_id}/correlations",
    response_model=List[DeviceIncidentCorrelationResponse],
    summary="List Incident Correlations"
)
def list_incident_correlations(
    incident_id: str,
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db)
):
    """
    Returns all active correlation records linking devices to this incident.
    """
    corrs = db.query(DeviceIncidentCorrelationModel).filter(
        and_(
            DeviceIncidentCorrelationModel.incident_id == incident_id,
            DeviceIncidentCorrelationModel.workspace_id == workspace_id,
            DeviceIncidentCorrelationModel.is_current == True
        )
    ).all()
    return [_to_correlation_response(c, db) for c in corrs]


@router.post(
    "/incidents/{incident_id}/correlate",
    response_model=List[DeviceIncidentCorrelationResponse],
    summary="Trigger Incident Correlation"
)
def trigger_incident_correlation(
    incident_id: str,
    req: TriggerCorrelationRequest = TriggerCorrelationRequest(),
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db)
):
    """
    Triggers on-demand candidate discovery and correlation evaluation for an incident.
    """
    inc = db.query(IncidentModel).filter(
        and_(IncidentModel.id == incident_id, IncidentModel.workspace_id == workspace_id)
    ).first()
    if not inc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Incident '{incident_id}' not found.")

    candidates = DeviceIncidentCorrelationService.find_candidate_devices(
        db=db,
        incident_id=incident_id,
        workspace_id=workspace_id,
        window_hours=req.window_hours
    )

    results = []
    for dev in candidates:
        corr = DeviceIncidentCorrelationService.correlate_device_with_incident(
            db=db,
            device=dev,
            incident=inc,
            workspace_id=workspace_id
        )
        results.append(_to_correlation_response(corr, db))

    return results


# ============================================================================
# DEVICE-CENTRIC ENDPOINTS
# ============================================================================

@router.get(
    "/devices/{device_id}/incidents",
    response_model=DeviceIncidentsHistoryResponse,
    summary="Get Device Incident History"
)
def get_device_incidents(
    device_id: str,
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db)
):
    """
    Returns a device-centric investigation history of all security incidents
    associated with this endpoint device.
    """
    try:
        return DeviceIncidentCorrelationService.get_device_incidents_history(
            db=db,
            device_id=device_id,
            workspace_id=workspace_id
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get(
    "/devices/{device_id}/correlations",
    response_model=List[DeviceIncidentCorrelationResponse],
    summary="List Device Correlations"
)
def list_device_correlations(
    device_id: str,
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db)
):
    """
    Returns all active correlation records linking this device to incidents.
    """
    corrs = db.query(DeviceIncidentCorrelationModel).filter(
        and_(
            DeviceIncidentCorrelationModel.device_id == device_id,
            DeviceIncidentCorrelationModel.workspace_id == workspace_id,
            DeviceIncidentCorrelationModel.is_current == True
        )
    ).all()
    return [_to_correlation_response(c, db) for c in corrs]


@router.get(
    "/devices/{device_id}/timeline",
    response_model=DeviceTimelineResponse,
    summary="Get Device Unified Activity Timeline"
)
def get_device_timeline(
    device_id: str,
    workspace_id: str = Query("default"),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db)
):
    """
    Returns a unified chronological activity timeline for this device, preserving
    event time, received time, collector source, and observation provenance.
    """
    try:
        return DeviceIncidentCorrelationService.get_device_timeline(
            db=db,
            device_id=device_id,
            workspace_id=workspace_id,
            limit=limit
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post(
    "/devices/{device_id}/correlate",
    response_model=List[DeviceIncidentCorrelationResponse],
    summary="Trigger Device Correlation"
)
def trigger_device_correlation(
    device_id: str,
    req: TriggerCorrelationRequest = TriggerCorrelationRequest(),
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db)
):
    """
    Triggers on-demand candidate discovery and correlation evaluation for a device.
    """
    dev = db.query(DeviceModel).filter(
        and_(DeviceModel.id == device_id, DeviceModel.workspace_id == workspace_id)
    ).first()
    if not dev:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Device '{device_id}' not found.")

    candidates = DeviceIncidentCorrelationService.find_candidate_incidents(
        db=db,
        device_id=device_id,
        workspace_id=workspace_id,
        window_hours=req.window_hours
    )

    results = []
    for inc in candidates:
        corr = DeviceIncidentCorrelationService.correlate_device_with_incident(
            db=db,
            device=dev,
            incident=inc,
            workspace_id=workspace_id
        )
        results.append(_to_correlation_response(corr, db))

    return results


# ============================================================================
# ANALYST REVIEW & FEEDBACK
# ============================================================================

@router.post(
    "/correlations/{correlation_id}/review",
    response_model=DeviceIncidentCorrelationResponse,
    summary="Review and Override Correlation Status"
)
def review_correlation(
    correlation_id: str,
    req: ReviewCorrelationRequest,
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db)
):
    """
    Applies auditable human-in-the-loop analyst feedback (CONFIRM_ASSOCIATION,
    DISMISS_ASSOCIATION, MARK_RELATED, MARK_FALSE_ASSOCIATION) to a device correlation.
    """
    try:
        corr = DeviceIncidentCorrelationService.review_correlation(
            db=db,
            correlation_id=correlation_id,
            action=req.action,
            reviewer=req.reviewer,
            notes=req.notes,
            workspace_id=workspace_id
        )
        return _to_correlation_response(corr, db)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
