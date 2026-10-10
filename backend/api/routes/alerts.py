"""
Section 48: REST API Endpoints for Alert Management & Triage Workspace.
Provides authoritative alert querying, metrics posture, deep forensic detail with provenance,
and state-changing triage actions (acknowledge, assign, investigate, resolve, false-positive,
suppress, notes, bulk acknowledge) backed by append-only audit logging and SSE notifications.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.schemas.alerts import (
    AlertListResponse,
    AlertDetailResponse,
    AlertItemResponse,
    AlertMetricsResponse,
    AlertAcknowledgeRequest,
    AlertAssignRequest,
    AlertResolveRequest,
    AlertFalsePositiveRequest,
    AlertSuppressRequest,
    AlertAddNoteRequest,
    AlertBulkAcknowledgeRequest,
)
from backend.services.alert_service import AlertService

logger = logging.getLogger("cyberguard.api.alerts")

router = APIRouter(prefix="/api/alerts", tags=["Alert Triage & Management"])


@router.get(
    "",
    response_model=AlertListResponse,
    status_code=status.HTTP_200_OK,
    summary="List Security Alerts",
    description="Returns filtered and paginated security alerts with server-side query search and counts.",
)
def list_alerts(
    status_filter: Optional[str] = Query(None, alias="status", description="Filter: OPEN, ACKNOWLEDGED, INVESTIGATING, RESOLVED, FALSE_POSITIVE, SUPPRESSED"),
    severity: Optional[str] = Query(None, description="Filter: CRITICAL, HIGH, MEDIUM, LOW, INFO"),
    alert_type: Optional[str] = Query(None, description="Filter by security alert type"),
    investigation_id: Optional[str] = Query(None, description="Filter by associated investigation ID"),
    assigned_to: Optional[str] = Query(None, description="Filter by assigned analyst or 'UNASSIGNED'"),
    q: Optional[str] = Query(None, description="Server-side search across title, message, source, investigation"),
    limit: int = Query(30, ge=1, le=100, description="Page limit"),
    offset: int = Query(0, ge=0, description="Page offset"),
    sort_by: str = Query("severity_first", description="Sort order: severity_first, newest, risk_desc"),
    x_workspace_id: Optional[str] = Header("default", alias="X-Workspace-ID"),
    x_user: Optional[str] = Header(None, alias="X-User"),
    workspace_id_query: Optional[str] = Query(None, alias="workspace_id"),
    db: Session = Depends(get_db),
):
    workspace = (workspace_id_query or x_workspace_id or "default").strip()

    return AlertService.list_alerts(
        db=db,
        workspace_id=workspace,
        status=status_filter,
        severity=severity,
        alert_type=alert_type,
        investigation_id=investigation_id,
        assigned_to=assigned_to,
        q=q,
        limit=limit,
        offset=offset,
        sort_by=sort_by,
    )


@router.get(
    "/metrics",
    response_model=AlertMetricsResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Alert Triage Metrics",
    description="Returns operational counts: total alerts, open, critical open, high open, unacknowledged, investigating, resolved.",
)
def get_alert_metrics(
    x_workspace_id: Optional[str] = Header("default", alias="X-Workspace-ID"),
    workspace_id_query: Optional[str] = Query(None, alias="workspace_id"),
    db: Session = Depends(get_db),
):
    workspace = (workspace_id_query or x_workspace_id or "default").strip()
    return AlertService.get_alert_metrics(db=db, workspace_id=workspace)

@router.post(
    "/bulk/acknowledge",
    status_code=status.HTTP_200_OK,
    summary="Bulk Acknowledge Security Alerts",
    description="Acknowledges multiple security alerts within the authorized workspace scope.",
)
def bulk_acknowledge(
    payload: AlertBulkAcknowledgeRequest,
    x_workspace_id: Optional[str] = Header("default", alias="X-Workspace-ID"),
    x_user: Optional[str] = Header(None, alias="X-User"),
    workspace_id_query: Optional[str] = Query(None, alias="workspace_id"),
    db: Session = Depends(get_db),
):
    workspace = (workspace_id_query or x_workspace_id or "default").strip()
    analyst = payload.analyst_name or x_user or "SOC Analyst"

    ack_ids = AlertService.bulk_acknowledge(
        db=db,
        alert_ids=payload.alert_ids,
        workspace_id=workspace,
        analyst_name=analyst,
    )
    return {
        "status": "success",
        "acknowledged_count": len(ack_ids),
        "acknowledged_ids": ack_ids,
    }


@router.get(
    "/{alert_id}",
    response_model=AlertDetailResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Alert Detail & Forensic Provenance",
    description="Returns authoritative alert details with Explainable AI why-cards, evidence items, finding, analysis run, and audit timeline.",
)
def get_alert_detail(
    alert_id: str,
    x_workspace_id: Optional[str] = Header("default", alias="X-Workspace-ID"),
    workspace_id_query: Optional[str] = Query(None, alias="workspace_id"),
    db: Session = Depends(get_db),
):
    workspace = (workspace_id_query or x_workspace_id or "default").strip()
    detail = AlertService.get_alert_detail(db=db, alert_id=alert_id, workspace_id=workspace)
    if not detail:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security alert '{alert_id}' not found in workspace '{workspace}'",
        )
    return detail


@router.post(
    "/{alert_id}/acknowledge",
    response_model=AlertItemResponse,
    status_code=status.HTTP_200_OK,
    summary="Acknowledge Security Alert",
    description="Transitions alert to ACKNOWLEDGED state with analyst identity and audit logging.",
)
def acknowledge_alert(
    alert_id: str,
    payload: Optional[AlertAcknowledgeRequest] = None,
    x_workspace_id: Optional[str] = Header("default", alias="X-Workspace-ID"),
    x_user: Optional[str] = Header(None, alias="X-User"),
    workspace_id_query: Optional[str] = Query(None, alias="workspace_id"),
    db: Session = Depends(get_db),
):
    workspace = (workspace_id_query or x_workspace_id or "default").strip()
    analyst = (payload.analyst_name if payload and payload.analyst_name else x_user) or "SOC Analyst"
    note = payload.note if payload else None

    updated = AlertService.acknowledge_alert(
        db=db,
        alert_id=alert_id,
        workspace_id=workspace,
        analyst_name=analyst,
        note=note,
    )
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security alert '{alert_id}' not found in workspace '{workspace}'",
        )
    return updated


@router.post(
    "/{alert_id}/assign",
    response_model=AlertItemResponse,
    status_code=status.HTTP_200_OK,
    summary="Assign Security Alert",
    description="Assigns alert to an analyst or team with audit record.",
)
def assign_alert(
    alert_id: str,
    payload: AlertAssignRequest,
    x_workspace_id: Optional[str] = Header("default", alias="X-Workspace-ID"),
    x_user: Optional[str] = Header(None, alias="X-User"),
    workspace_id_query: Optional[str] = Query(None, alias="workspace_id"),
    db: Session = Depends(get_db),
):
    workspace = (workspace_id_query or x_workspace_id or "default").strip()
    analyst = payload.analyst_name or x_user or "SOC Analyst"

    updated = AlertService.assign_alert(
        db=db,
        alert_id=alert_id,
        assigned_to=payload.assigned_to,
        workspace_id=workspace,
        analyst_name=analyst,
    )
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security alert '{alert_id}' not found in workspace '{workspace}'",
        )
    return updated


@router.post(
    "/{alert_id}/investigate",
    response_model=AlertItemResponse,
    status_code=status.HTTP_200_OK,
    summary="Mark Alert as Under Investigation",
    description="Transitions alert status to INVESTIGATING.",
)
def investigate_alert(
    alert_id: str,
    x_workspace_id: Optional[str] = Header("default", alias="X-Workspace-ID"),
    x_user: Optional[str] = Header(None, alias="X-User"),
    workspace_id_query: Optional[str] = Query(None, alias="workspace_id"),
    db: Session = Depends(get_db),
):
    workspace = (workspace_id_query or x_workspace_id or "default").strip()
    analyst = x_user or "SOC Analyst"

    updated = AlertService.investigate_alert(
        db=db,
        alert_id=alert_id,
        workspace_id=workspace,
        analyst_name=analyst,
    )
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security alert '{alert_id}' not found in workspace '{workspace}'",
        )
    return updated


@router.post(
    "/{alert_id}/resolve",
    response_model=AlertItemResponse,
    status_code=status.HTTP_200_OK,
    summary="Resolve Security Alert",
    description="Transitions alert to RESOLVED with required deterministic justification.",
)
def resolve_alert(
    alert_id: str,
    payload: AlertResolveRequest,
    x_workspace_id: Optional[str] = Header("default", alias="X-Workspace-ID"),
    x_user: Optional[str] = Header(None, alias="X-User"),
    workspace_id_query: Optional[str] = Query(None, alias="workspace_id"),
    db: Session = Depends(get_db),
):
    workspace = (workspace_id_query or x_workspace_id or "default").strip()
    analyst = payload.analyst_name or x_user or "SOC Analyst"

    updated = AlertService.resolve_alert(
        db=db,
        alert_id=alert_id,
        resolution_reason=payload.resolution_reason,
        workspace_id=workspace,
        analyst_name=analyst,
    )
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security alert '{alert_id}' not found in workspace '{workspace}'",
        )
    return updated


@router.post(
    "/{alert_id}/false-positive",
    response_model=AlertItemResponse,
    status_code=status.HTTP_200_OK,
    summary="Mark Alert as False Positive",
    description="Transitions alert to FALSE_POSITIVE with required justification.",
)
def mark_false_positive(
    alert_id: str,
    payload: AlertFalsePositiveRequest,
    x_workspace_id: Optional[str] = Header("default", alias="X-Workspace-ID"),
    x_user: Optional[str] = Header(None, alias="X-User"),
    workspace_id_query: Optional[str] = Query(None, alias="workspace_id"),
    db: Session = Depends(get_db),
):
    workspace = (workspace_id_query or x_workspace_id or "default").strip()
    analyst = payload.analyst_name or x_user or "SOC Analyst"

    updated = AlertService.mark_false_positive(
        db=db,
        alert_id=alert_id,
        reason=payload.reason,
        workspace_id=workspace,
        analyst_name=analyst,
    )
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security alert '{alert_id}' not found in workspace '{workspace}'",
        )
    return updated


@router.post(
    "/{alert_id}/suppress",
    response_model=AlertItemResponse,
    status_code=status.HTTP_200_OK,
    summary="Suppress Security Alert",
    description="Transitions alert to SUPPRESSED without deleting underlying findings or evidence.",
)
def suppress_alert(
    alert_id: str,
    payload: AlertSuppressRequest,
    x_workspace_id: Optional[str] = Header("default", alias="X-Workspace-ID"),
    x_user: Optional[str] = Header(None, alias="X-User"),
    workspace_id_query: Optional[str] = Query(None, alias="workspace_id"),
    db: Session = Depends(get_db),
):
    workspace = (workspace_id_query or x_workspace_id or "default").strip()
    analyst = payload.analyst_name or x_user or "SOC Analyst"

    updated = AlertService.suppress_alert(
        db=db,
        alert_id=alert_id,
        reason=payload.reason,
        scope=payload.scope,
        workspace_id=workspace,
        analyst_name=analyst,
    )
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security alert '{alert_id}' not found in workspace '{workspace}'",
        )
    return updated


@router.post(
    "/{alert_id}/notes",
    response_model=AlertDetailResponse,
    status_code=status.HTTP_200_OK,
    summary="Add Triage Note to Alert",
    description="Appends a sanitized triage observation note with audit trail.",
)
def add_note(
    alert_id: str,
    payload: AlertAddNoteRequest,
    x_workspace_id: Optional[str] = Header("default", alias="X-Workspace-ID"),
    x_user: Optional[str] = Header(None, alias="X-User"),
    workspace_id_query: Optional[str] = Query(None, alias="workspace_id"),
    db: Session = Depends(get_db),
):
    workspace = (workspace_id_query or x_workspace_id or "default").strip()
    analyst = payload.analyst_name or x_user or "SOC Analyst"

    updated = AlertService.add_note(
        db=db,
        alert_id=alert_id,
        note_text=payload.note,
        workspace_id=workspace,
        analyst_name=analyst,
    )
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security alert '{alert_id}' not found in workspace '{workspace}'",
        )
    return updated



