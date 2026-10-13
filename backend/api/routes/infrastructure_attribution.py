"""
Infrastructure Attribution & Origin Intelligence API Router (Section 20).
Provides REST endpoints for inspecting observed and associated infrastructure,
threat clusters, origin hypotheses, timeline events, and forensic limitations.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.schemas.infrastructure_attribution import (
    InvestigationInfrastructureResponse,
    InfrastructureAttribution,
    InfrastructureCluster,
    InfrastructureTimelineEvent,
    InfrastructureAttributionEvidence,
    InfrastructureCandidate,
)
from backend.services.infrastructure_attribution_engine import global_infrastructure_engine

logger = logging.getLogger("cyberguard.api.infrastructure")

router = APIRouter(tags=["Probable Origin Infrastructure & Threat Infrastructure Attribution"])


@router.post(
    "/api/v1/investigations/{incident_id}/infrastructure/analyze",
    response_model=InvestigationInfrastructureResponse,
    summary="Analyze incident infrastructure and compute origin hypotheses",
    description="Harvests observed endpoints, builds clusters, detects migrations, ranks candidates, and generates origin hypotheses.",
)
@router.post(
    "/api/v1/incidents/{incident_id}/infrastructure/analyze",
    response_model=InvestigationInfrastructureResponse,
    include_in_schema=False,
)
def analyze_incident_infrastructure_endpoint(
    incident_id: str,
    workspace_id: str = Query("default", description="Workspace isolation scope"),
    db: Session = Depends(get_db),
):
    try:
        return global_infrastructure_engine.analyze_incident_infrastructure(
            db=db, incident_id=incident_id, workspace_id=workspace_id, persist=True
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        logger.error(f"Infrastructure analysis failed for incident {incident_id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail='Infrastructure analysis failed.',
        )


@router.get(
    "/api/v1/investigations/{incident_id}/infrastructure",
    response_model=InvestigationInfrastructureResponse,
    summary="Get comprehensive infrastructure assessment for an investigation",
)
@router.get(
    "/api/v1/incidents/{incident_id}/infrastructure",
    response_model=InvestigationInfrastructureResponse,
    include_in_schema=False,
)
def get_incident_infrastructure_endpoint(
    incident_id: str,
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db),
):
    try:
        return global_infrastructure_engine.analyze_incident_infrastructure(
            db=db, incident_id=incident_id, workspace_id=workspace_id, persist=False
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get(
    "/api/v1/investigations/{incident_id}/infrastructure/origin",
    response_model=Optional[InfrastructureAttribution],
    summary="Get primary probable origin infrastructure hypothesis",
)
@router.get(
    "/api/v1/incidents/{incident_id}/infrastructure/origin",
    response_model=Optional[InfrastructureAttribution],
    include_in_schema=False,
)
def get_primary_origin_endpoint(
    incident_id: str,
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db),
):
    try:
        res = global_infrastructure_engine.analyze_incident_infrastructure(
            db=db, incident_id=incident_id, workspace_id=workspace_id, persist=False
        )
        return res.primary_hypothesis
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get(
    "/api/v1/investigations/{incident_id}/infrastructure/clusters",
    response_model=List[InfrastructureCluster],
    summary="Get infrastructure clusters connected to investigation",
)
@router.get(
    "/api/v1/incidents/{incident_id}/infrastructure/clusters",
    response_model=List[InfrastructureCluster],
    include_in_schema=False,
)
def get_infrastructure_clusters_endpoint(
    incident_id: str,
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db),
):
    try:
        res = global_infrastructure_engine.analyze_incident_infrastructure(
            db=db, incident_id=incident_id, workspace_id=workspace_id, persist=False
        )
        return res.clusters
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get(
    "/api/v1/investigations/{incident_id}/infrastructure/timeline",
    response_model=List[InfrastructureTimelineEvent],
    summary="Get chronological infrastructure activity and migration events",
)
@router.get(
    "/api/v1/incidents/{incident_id}/infrastructure/timeline",
    response_model=List[InfrastructureTimelineEvent],
    include_in_schema=False,
)
def get_infrastructure_timeline_endpoint(
    incident_id: str,
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db),
):
    try:
        res = global_infrastructure_engine.analyze_incident_infrastructure(
            db=db, incident_id=incident_id, workspace_id=workspace_id, persist=False
        )
        return res.timeline
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get(
    "/api/v1/investigations/{incident_id}/infrastructure/evidence",
    response_model=List[InfrastructureAttributionEvidence],
    summary="Get itemized infrastructure attribution evidence links",
)
@router.get(
    "/api/v1/incidents/{incident_id}/infrastructure/evidence",
    response_model=List[InfrastructureAttributionEvidence],
    include_in_schema=False,
)
def get_infrastructure_evidence_endpoint(
    incident_id: str,
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db),
):
    try:
        res = global_infrastructure_engine.analyze_incident_infrastructure(
            db=db, incident_id=incident_id, workspace_id=workspace_id, persist=False
        )
        return res.evidence_links
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get(
    "/api/v1/investigations/{incident_id}/infrastructure/hypotheses",
    response_model=List[InfrastructureAttribution],
    summary="Get all competing infrastructure attribution hypotheses",
)
@router.get(
    "/api/v1/incidents/{incident_id}/infrastructure/hypotheses",
    response_model=List[InfrastructureAttribution],
    include_in_schema=False,
)
def get_infrastructure_hypotheses_endpoint(
    incident_id: str,
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db),
):
    try:
        res = global_infrastructure_engine.analyze_incident_infrastructure(
            db=db, incident_id=incident_id, workspace_id=workspace_id, persist=False
        )
        hypotheses = []
        if res.primary_hypothesis:
            hypotheses.append(res.primary_hypothesis)
        hypotheses.extend(res.competing_hypotheses)
        return hypotheses
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
