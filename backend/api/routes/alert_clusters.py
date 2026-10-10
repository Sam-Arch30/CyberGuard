"""
Section 49: REST API Endpoints for Alert Correlation & Incident Clustering.
Exposes cluster querying, deep forensic inspection, status updates, investigation
linking, cluster merging, and alert-to-cluster association lookups with tenant isolation
and append-only audit verification.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.db.models import NotificationModel
from backend.schemas.alert_clusters import (
    AlertClusterListResponse,
    AlertClusterDetailResponse,
    AlertClusterItemResponse,
    AlertClusterUpdateStatusRequest,
    AlertClusterLinkInvestigationRequest,
    AlertCorrelationRunRequest,
)
from backend.schemas.jobs import JobTypeEnum
from backend.services.alert_correlation_service import AlertCorrelationService
from backend.services.background_job_service import BackgroundJobService

logger = logging.getLogger("cyberguard.api.alert_clusters")

router = APIRouter(prefix="/api/alerts/clusters", tags=["Alert Correlation & Incident Clustering"])
alert_correlate_router = APIRouter(prefix="/api/alerts", tags=["Alert Correlation & Incident Clustering"])


class ClusterMergeRequest(BaseModel):
    target_cluster_id: str = Field(..., description="ID of destination cluster to merge into")
    analyst_name: Optional[str] = Field("SOC Analyst", description="Name of analyst performing merge")
    reason: Optional[str] = Field("Manual cluster consolidation", description="Justification for merge")


@router.get(
    "",
    response_model=AlertClusterListResponse,
    status_code=status.HTTP_200_OK,
    summary="List Alert Clusters",
    description="Returns filtered and paginated alert clusters within the authorized workspace.",
)
def list_alert_clusters(
    status_filter: Optional[str] = Query(None, alias="status", description="Filter: OPEN, INVESTIGATING, CONTAINED, RESOLVED, FALSE_POSITIVE, SUPPRESSED"),
    severity: Optional[str] = Query(None, description="Filter: CRITICAL, HIGH, MEDIUM, LOW, INFO"),
    investigation_id: Optional[str] = Query(None, description="Filter by linked investigation ID"),
    campaign_id: Optional[str] = Query(None, description="Filter by associated campaign ID"),
    q: Optional[str] = Query(None, description="Search across cluster title, summary, or alert content"),
    limit: int = Query(30, ge=1, le=100, description="Page limit"),
    offset: int = Query(0, ge=0, description="Page offset"),
    sort_by: str = Query("severity_first", description="Sort order: severity_first, newest, risk_desc, alert_count"),
    x_workspace_id: Optional[str] = Header("default", alias="X-Workspace-ID"),
    x_user: Optional[str] = Header(None, alias="X-User"),
    workspace_id_query: Optional[str] = Query(None, alias="workspace_id"),
    db: Session = Depends(get_db),
):
    workspace = (workspace_id_query or x_workspace_id or "default").strip()

    return AlertCorrelationService.list_clusters(
        db=db,
        workspace_id=workspace,
        status=status_filter,
        severity=severity,
        investigation_id=investigation_id,
        campaign_id=campaign_id,
        q=q,
        limit=limit,
        offset=offset,
        sort_by=sort_by,
    )


@router.get(
    "/{cluster_id}",
    response_model=AlertClusterDetailResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Alert Cluster Detail",
    description="Returns detailed cluster metadata, member alerts with correlation reasons, affected entities, and attack timeline.",
)
def get_cluster_detail(
    cluster_id: str,
    x_workspace_id: Optional[str] = Header("default", alias="X-Workspace-ID"),
    workspace_id_query: Optional[str] = Query(None, alias="workspace_id"),
    db: Session = Depends(get_db),
):
    workspace = (workspace_id_query or x_workspace_id or "default").strip()
    detail = AlertCorrelationService.get_cluster_detail(
        db=db,
        cluster_id=cluster_id,
        workspace_id=workspace,
    )
    if not detail:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert cluster '{cluster_id}' not found in workspace '{workspace}'",
        )
    return detail


@router.post(
    "/{cluster_id}/status",
    response_model=AlertClusterItemResponse,
    status_code=status.HTTP_200_OK,
    summary="Update Alert Cluster Status",
    description="Updates the lifecycle status of a cluster and emits an audit log and real-time SSE event.",
)
def update_cluster_status(
    cluster_id: str,
    payload: AlertClusterUpdateStatusRequest,
    x_workspace_id: Optional[str] = Header("default", alias="X-Workspace-ID"),
    x_user: Optional[str] = Header(None, alias="X-User"),
    workspace_id_query: Optional[str] = Query(None, alias="workspace_id"),
    db: Session = Depends(get_db),
):
    workspace = (workspace_id_query or x_workspace_id or "default").strip()
    analyst = payload.analyst_name or x_user or "SOC Analyst"

    cluster = AlertCorrelationService.update_cluster_status(
        db=db,
        cluster_id=cluster_id,
        workspace_id=workspace,
        new_status=payload.status,
        analyst_name=analyst,
        reason=payload.reason,
    )
    if not cluster:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert cluster '{cluster_id}' not found in workspace '{workspace}'",
        )
    return cluster


@router.post(
    "/{cluster_id}/investigate",
    response_model=AlertClusterItemResponse,
    status_code=status.HTTP_200_OK,
    summary="Link Cluster to Investigation",
    description="Links an alert cluster to an existing or newly created investigation workspace.",
)
def link_cluster_investigation(
    cluster_id: str,
    payload: AlertClusterLinkInvestigationRequest,
    x_workspace_id: Optional[str] = Header("default", alias="X-Workspace-ID"),
    x_user: Optional[str] = Header(None, alias="X-User"),
    workspace_id_query: Optional[str] = Query(None, alias="workspace_id"),
    db: Session = Depends(get_db),
):
    workspace = (workspace_id_query or x_workspace_id or "default").strip()
    analyst = payload.analyst_name or x_user or "SOC Analyst"

    cluster = AlertCorrelationService.link_investigation(
        db=db,
        cluster_id=cluster_id,
        workspace_id=workspace,
        investigation_id=payload.investigation_id,
        create_if_missing=payload.create_if_missing,
        analyst_name=analyst,
        investigation_title=payload.investigation_title,
    )
    if not cluster:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert cluster '{cluster_id}' not found in workspace '{workspace}'",
        )
    return cluster


@router.post(
    "/{cluster_id}/merge",
    response_model=AlertClusterItemResponse,
    status_code=status.HTTP_200_OK,
    summary="Merge Cluster into Target Cluster",
    description="Merges the given cluster into a target cluster, migrating all member alerts while preserving provenance.",
)
def merge_cluster(
    cluster_id: str,
    payload: ClusterMergeRequest,
    x_workspace_id: Optional[str] = Header("default", alias="X-Workspace-ID"),
    x_user: Optional[str] = Header(None, alias="X-User"),
    workspace_id_query: Optional[str] = Query(None, alias="workspace_id"),
    db: Session = Depends(get_db),
):
    workspace = (workspace_id_query or x_workspace_id or "default").strip()
    analyst = payload.analyst_name or x_user or "SOC Analyst"

    target_cluster = AlertCorrelationService.merge_clusters(
        db=db,
        source_cluster_id=cluster_id,
        target_cluster_id=payload.target_cluster_id,
        workspace_id=workspace,
        analyst_name=analyst,
        reason=payload.reason or "Manual cluster merge",
    )
    if not target_cluster:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Could not merge cluster '{cluster_id}' into '{payload.target_cluster_id}'. Check IDs and tenant boundary.",
        )
    return target_cluster


# ===========================================================================
# Alert-Centric Correlation Endpoints
# ===========================================================================

@alert_correlate_router.get(
    "/{alert_id}/cluster",
    response_model=Optional[AlertClusterDetailResponse],
    status_code=status.HTTP_200_OK,
    summary="Get Cluster for Specific Alert",
    description="Returns the AlertCluster detail associated with this alert, or null if the alert is currently unclustered.",
)
def get_alert_cluster(
    alert_id: str,
    x_workspace_id: Optional[str] = Header("default", alias="X-Workspace-ID"),
    workspace_id_query: Optional[str] = Query(None, alias="workspace_id"),
    db: Session = Depends(get_db),
):
    workspace = (workspace_id_query or x_workspace_id or "default").strip()

    # Check alert existence
    alert = (
        db.query(NotificationModel)
        .filter(
            NotificationModel.id == alert_id,
            NotificationModel.workspace_id == workspace,
        )
        .first()
    )
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security alert '{alert_id}' not found in workspace '{workspace}'",
        )

    cluster_detail = AlertCorrelationService.get_alert_cluster(
        db=db,
        alert_id=alert_id,
        workspace_id=workspace,
    )
    return cluster_detail


@alert_correlate_router.post(
    "/{alert_id}/correlate",
    status_code=status.HTTP_200_OK,
    summary="Trigger Alert Correlation",
    description="Runs correlation for the given alert either synchronously or asynchronously via Background Jobs.",
)
def trigger_alert_correlation(
    alert_id: str,
    payload: Optional[AlertCorrelationRunRequest] = None,
    x_workspace_id: Optional[str] = Header("default", alias="X-Workspace-ID"),
    x_user: Optional[str] = Header(None, alias="X-User"),
    workspace_id_query: Optional[str] = Query(None, alias="workspace_id"),
    db: Session = Depends(get_db),
):
    workspace = (workspace_id_query or x_workspace_id or "default").strip()
    analyst = (payload.analyst_name if payload else None) or x_user or "SOC Analyst"
    run_req = payload or AlertCorrelationRunRequest()

    alert = (
        db.query(NotificationModel)
        .filter(
            NotificationModel.id == alert_id,
            NotificationModel.workspace_id == workspace,
        )
        .first()
    )
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security alert '{alert_id}' not found in workspace '{workspace}'",
        )

    if run_req.async_job:
        job = BackgroundJobService.enqueue_job(
            db=db,
            job_type=JobTypeEnum.ALERT_CORRELATION,
            workspace_id=workspace,
            resource_type="alert",
            resource_id=alert_id,
            payload={
                "alert_id": alert_id,
                "workspace_id": workspace,
                "triggered_by": analyst,
            },
        )
        return {
            "status": "queued",
            "job_id": job.id,
            "message": "Alert correlation queued for asynchronous execution.",
        }

    cluster = AlertCorrelationService.correlate_alert(
        db=db,
        alert_id=alert_id,
        workspace_id=workspace,
        triggered_by=analyst,
    )

    return {
        "status": "completed",
        "alert_id": alert_id,
        "cluster_id": cluster.id if cluster else None,
        "cluster_title": cluster.title if cluster else None,
        "clustered": cluster is not None,
    }
