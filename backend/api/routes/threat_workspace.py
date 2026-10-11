"""
Section 65: Threat Actor & Campaign Workspace REST API.
Authoritative endpoints for organizing, correlating, investigating, and tracking
suspected threat actors, campaigns, infrastructure clusters, techniques, and hypotheses.

Enforces:
- Separation of Observed Fact, Correlation, Analyst Hypothesis, and Attribution.
- Independent confidence (0.0 to 1.0) strictly separate from Risk/Severity.
- Supporting and Contradicting evidence tracking.
- Controlled candidate promotion, merging, and splitting with complete provenance.
- Multi-tenant workspace isolation and RBAC.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Header, Query, Path, status
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.services.threat_workspace_service import ThreatWorkspaceService
from backend.services.background_job_service import BackgroundJobService
from backend.schemas.jobs import JobTypeEnum
from backend.schemas.graph import InvestigationGraphResponse
from backend.schemas.threat_workspace import (
    ThreatActorCreateRequest,
    ThreatActorUpdateRequest,
    ThreatActorResponse,
    ThreatActorListResponse,
    CampaignCreateRequest,
    CampaignUpdateRequest,
    CampaignWorkspaceDetailResponse,
    CampaignListWorkspaceResponse,
    CandidateReviewRequest,
    CampaignMergePreviewRequest,
    CampaignMergePreviewResponse,
    CampaignMergeRequest,
    CampaignSplitRequest,
    AttributionAssessmentCreateRequest,
    AttributionAssessmentResponse,
    HypothesisCreateRequest,
    HypothesisUpdateRequest,
    HypothesisResponse,
    CampaignTimelineResponse,
    ThreatHuntHandoffResponse,
    DetectionHandoffResponse,
)

logger = logging.getLogger("cyberguard.api.threat_workspace")

router = APIRouter(prefix="/api/v1/threat-workspace", tags=["Threat Actor & Campaign Workspace"])


def get_actor_and_role(
    x_role: Optional[str] = Header(None, alias="X-Role"),
    x_user_role: Optional[str] = Header(None, alias="X-User-Role"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
) -> str:
    role = (x_role or x_user_role or "").strip().lower()
    if not role and authorization:
        auth_clean = authorization.strip().lower()
        if "admin" in auth_clean or "lead" in auth_clean:
            role = "admin"
        elif "analyst" in auth_clean or "soc" in auth_clean:
            role = "analyst"
        elif "viewer" in auth_clean or "unauthorized" in auth_clean:
            role = "unauthorized"

    if role in ("guest", "unauthorized", "untrusted"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: insufficient permissions for threat actor and campaign workspace operations.",
        )
    return role or "analyst"


# =============================================================================
# Threat Actors Endpoints
# =============================================================================

@router.get(
    "/actors",
    response_model=ThreatActorListResponse,
    summary="List tracked threat actors",
    description="Returns threat actor profiles in the workspace with aliases, attribution state, and technique counts.",
)
def list_threat_actors(
    query: Optional[str] = Query(None, description="Search by name, canonical name, actor ID, or alias"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status (ACTIVE, MONITORING, DORMANT, RETIRED)"),
    attribution_state: Optional[str] = Query(None, description="Filter by attribution state (SUSPECTED, POSSIBLE, CONFIRMED, etc.)"),
    actor_type: Optional[str] = Query(None, description="Filter by actor type (NATION_STATE, CYBERCRIME, etc.)"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    x_workspace_id: str = Header("default", alias="X-Workspace-Id"),
    role: str = Depends(get_actor_and_role),
    db: Session = Depends(get_db),
):
    return ThreatWorkspaceService.list_actors(
        db=db,
        workspace_id=x_workspace_id,
        query=query,
        status=status_filter,
        attribution_state=attribution_state,
        actor_type=actor_type,
        page=page,
        page_size=page_size,
    )


@router.post(
    "/actors",
    response_model=ThreatActorResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new threat actor profile",
    description="Registers an analyst-created or intelligence-imported threat actor profile with aliases and provenance.",
)
def create_threat_actor(
    req: ThreatActorCreateRequest,
    x_workspace_id: str = Header("default", alias="X-Workspace-Id"),
    x_user: Optional[str] = Header(None, alias="X-User"),
    role: str = Depends(get_actor_and_role),
    db: Session = Depends(get_db),
):
    return ThreatWorkspaceService.create_actor(
        db=db,
        workspace_id=x_workspace_id,
        req=req,
        creator=x_user or "ANALYST",
    )


@router.get(
    "/actors/{actor_id}",
    response_model=ThreatActorResponse,
    summary="Get threat actor profile details",
    description="Returns complete details, supporting/contradicting evidence, techniques, and campaign counts for an actor.",
)
def get_threat_actor_detail(
    actor_id: str = Path(..., description="Threat actor UUID or friendly ID (e.g., TA-001)"),
    x_workspace_id: str = Header("default", alias="X-Workspace-Id"),
    role: str = Depends(get_actor_and_role),
    db: Session = Depends(get_db),
):
    actor = ThreatWorkspaceService.get_actor(db=db, workspace_id=x_workspace_id, actor_id_or_uuid=actor_id)
    if not actor:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Threat Actor '{actor_id}' not found.")
    return actor


@router.patch(
    "/actors/{actor_id}",
    response_model=ThreatActorResponse,
    summary="Update threat actor profile",
    description="Updates metadata, aliases, observed techniques, or evidence for a threat actor.",
)
def update_threat_actor(
    actor_id: str,
    req: ThreatActorUpdateRequest,
    x_workspace_id: str = Header("default", alias="X-Workspace-Id"),
    x_user: Optional[str] = Header(None, alias="X-User"),
    role: str = Depends(get_actor_and_role),
    db: Session = Depends(get_db),
):
    try:
        return ThreatWorkspaceService.update_actor(
            db=db,
            workspace_id=x_workspace_id,
            actor_id_or_uuid=actor_id,
            req=req,
            updater=x_user or "ANALYST",
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


@router.post(
    "/actors/{actor_id}/assessments",
    response_model=AttributionAssessmentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Record an attribution assessment for a threat actor",
    description="Records an auditable transition in threat actor attribution state with supporting and contradicting evidence.",
)
def record_actor_attribution_assessment(
    actor_id: str,
    req: AttributionAssessmentCreateRequest,
    x_workspace_id: str = Header("default", alias="X-Workspace-Id"),
    x_user: Optional[str] = Header(None, alias="X-User"),
    role: str = Depends(get_actor_and_role),
    db: Session = Depends(get_db),
):
    try:
        return ThreatWorkspaceService.record_actor_assessment(
            db=db,
            workspace_id=x_workspace_id,
            actor_id_or_uuid=actor_id,
            req=req,
            analyst=x_user or "ANALYST",
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.get(
    "/actors/{actor_id}/assessments",
    response_model=List[AttributionAssessmentResponse],
    summary="Get attribution assessment history for a threat actor",
)
def get_actor_assessments(
    actor_id: str,
    x_workspace_id: str = Header("default", alias="X-Workspace-Id"),
    role: str = Depends(get_actor_and_role),
    db: Session = Depends(get_db),
):
    return ThreatWorkspaceService.get_actor_assessments(db=db, workspace_id=x_workspace_id, actor_id_or_uuid=actor_id)


# =============================================================================
# Campaigns Endpoints
# =============================================================================

@router.get(
    "/campaigns",
    response_model=CampaignListWorkspaceResponse,
    summary="List campaigns in workspace",
    description="Returns tracked campaigns with lifecycle status, attribution, affected assets, and confidence.",
)
def list_workspace_campaigns(
    query: Optional[str] = Query(None, description="Search by name, ID, brand, or IOC"),
    lifecycle_status: Optional[str] = Query(None, description="CANDIDATE, OPEN, ACTIVE, MONITORING, CLOSED, ARCHIVED"),
    attribution_state: Optional[str] = Query(None, description="UNKNOWN, SUSPECTED, POSSIBLE, CONFIRMED, etc."),
    activity_state: Optional[str] = Query(None, description="ACTIVE, QUIET, STALE, UNKNOWN"),
    threat_actor_id: Optional[str] = Query(None, description="Filter by associated threat actor ID"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    x_workspace_id: str = Header("default", alias="X-Workspace-Id"),
    role: str = Depends(get_actor_and_role),
    db: Session = Depends(get_db),
):
    return ThreatWorkspaceService.list_campaigns(
        db=db,
        workspace_id=x_workspace_id,
        query=query,
        lifecycle_status=lifecycle_status,
        attribution_state=attribution_state,
        activity_state=activity_state,
        threat_actor_id=threat_actor_id,
        page=page,
        page_size=page_size,
    )


@router.post(
    "/campaigns",
    response_model=CampaignWorkspaceDetailResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new campaign",
    description="Creates an analyst-defined campaign cluster linked to assets, indicators, and optionally a threat actor.",
)
def create_workspace_campaign(
    req: CampaignCreateRequest,
    x_workspace_id: str = Header("default", alias="X-Workspace-Id"),
    x_user: Optional[str] = Header(None, alias="X-User"),
    role: str = Depends(get_actor_and_role),
    db: Session = Depends(get_db),
):
    return ThreatWorkspaceService.create_campaign(
        db=db,
        workspace_id=x_workspace_id,
        req=req,
        creator=x_user or "ANALYST",
    )


@router.get(
    "/campaigns/{campaign_id}",
    response_model=CampaignWorkspaceDetailResponse,
    summary="Get campaign workspace details",
    description="Returns complete details, supporting/contradicting evidence, affected assets, identities, and related incidents.",
)
def get_workspace_campaign(
    campaign_id: str,
    x_workspace_id: str = Header("default", alias="X-Workspace-Id"),
    role: str = Depends(get_actor_and_role),
    db: Session = Depends(get_db),
):
    camp = ThreatWorkspaceService.get_campaign(db=db, workspace_id=x_workspace_id, campaign_id_or_uuid=campaign_id)
    if not camp:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Campaign '{campaign_id}' not found.")
    return camp


@router.patch(
    "/campaigns/{campaign_id}",
    response_model=CampaignWorkspaceDetailResponse,
    summary="Update campaign attributes",
)
def update_workspace_campaign(
    campaign_id: str,
    req: CampaignUpdateRequest,
    x_workspace_id: str = Header("default", alias="X-Workspace-Id"),
    x_user: Optional[str] = Header(None, alias="X-User"),
    role: str = Depends(get_actor_and_role),
    db: Session = Depends(get_db),
):
    try:
        return ThreatWorkspaceService.update_campaign(
            db=db,
            workspace_id=x_workspace_id,
            campaign_id_or_uuid=campaign_id,
            req=req,
            updater=x_user or "ANALYST",
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


@router.post(
    "/campaigns/{campaign_id}/assessments",
    response_model=AttributionAssessmentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Record an attribution assessment for a campaign",
    description="Records an auditable attribution assessment linking or updating campaign attribution to a threat actor.",
)
def record_campaign_attribution_assessment(
    campaign_id: str,
    req: AttributionAssessmentCreateRequest,
    x_workspace_id: str = Header("default", alias="X-Workspace-Id"),
    x_user: Optional[str] = Header(None, alias="X-User"),
    role: str = Depends(get_actor_and_role),
    db: Session = Depends(get_db),
):
    try:
        return ThreatWorkspaceService.record_campaign_assessment(
            db=db,
            workspace_id=x_workspace_id,
            campaign_id_or_uuid=campaign_id,
            req=req,
            analyst=x_user or "ANALYST",
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.get(
    "/campaigns/{campaign_id}/timeline",
    response_model=CampaignTimelineResponse,
    summary="Get campaign chronological timeline",
    description="Returns chronological observations (first seen, indicators, alerts, member incidents, assessments).",
)
def get_campaign_timeline(
    campaign_id: str,
    x_workspace_id: str = Header("default", alias="X-Workspace-Id"),
    role: str = Depends(get_actor_and_role),
    db: Session = Depends(get_db),
):
    try:
        return ThreatWorkspaceService.get_campaign_timeline(
            db=db,
            workspace_id=x_workspace_id,
            campaign_id_or_uuid=campaign_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


@router.get(
    "/campaigns/{campaign_id}/graph",
    response_model=InvestigationGraphResponse,
    summary="Get campaign relationship graph",
    description="Constructs bounded relationship graph connecting the campaign to actors, indicators, techniques, and incidents.",
)
def get_campaign_relationship_graph(
    campaign_id: str,
    max_nodes: int = Query(75, ge=10, le=150),
    x_workspace_id: str = Header("default", alias="X-Workspace-Id"),
    role: str = Depends(get_actor_and_role),
    db: Session = Depends(get_db),
):
    return ThreatWorkspaceService.get_campaign_graph(
        db=db,
        workspace_id=x_workspace_id,
        campaign_id_or_uuid=campaign_id,
        max_nodes=max_nodes,
    )


@router.get(
    "/campaigns/{campaign_id}/hunt-handoff",
    response_model=ThreatHuntHandoffResponse,
    summary="Generate Threat Hunting queries from campaign context",
    description="Constructs structured Threat Hunting queries targeting campaign infrastructure without arbitrary SQL.",
)
def get_campaign_hunt_handoff(
    campaign_id: str,
    x_workspace_id: str = Header("default", alias="X-Workspace-Id"),
    role: str = Depends(get_actor_and_role),
    db: Session = Depends(get_db),
):
    try:
        return ThreatWorkspaceService.get_hunt_handoff(
            db=db,
            workspace_id=x_workspace_id,
            campaign_id_or_uuid=campaign_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


@router.get(
    "/campaigns/{campaign_id}/detection-handoff",
    response_model=DetectionHandoffResponse,
    summary="Generate candidate detection rule from validated campaign pattern",
    description="Drafts a candidate detection rule targeting campaign indicators and MITRE techniques for Section 56-58 review.",
)
def get_campaign_detection_handoff(
    campaign_id: str,
    x_workspace_id: str = Header("default", alias="X-Workspace-Id"),
    role: str = Depends(get_actor_and_role),
    db: Session = Depends(get_db),
):
    try:
        return ThreatWorkspaceService.get_detection_handoff(
            db=db,
            workspace_id=x_workspace_id,
            campaign_id_or_uuid=campaign_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


# =============================================================================
# Candidate Workflows & Merge / Split Endpoints
# =============================================================================

@router.get(
    "/candidates",
    response_model=List[CampaignWorkspaceDetailResponse],
    summary="List campaign candidates",
    description="Returns automatically correlated candidate clusters requiring analyst review before becoming active campaigns.",
)
def list_campaign_candidates(
    x_workspace_id: str = Header("default", alias="X-Workspace-Id"),
    role: str = Depends(get_actor_and_role),
    db: Session = Depends(get_db),
):
    return ThreatWorkspaceService.list_candidates(db=db, workspace_id=x_workspace_id)


@router.post(
    "/candidates/{candidate_id}/review",
    response_model=CampaignWorkspaceDetailResponse,
    summary="Review campaign candidate",
    description="Analyst action to PROMOTE to active campaign, MERGE into existing campaign, or REJECT candidate.",
)
def review_campaign_candidate(
    candidate_id: str,
    req: CandidateReviewRequest,
    x_workspace_id: str = Header("default", alias="X-Workspace-Id"),
    x_user: Optional[str] = Header(None, alias="X-User"),
    role: str = Depends(get_actor_and_role),
    db: Session = Depends(get_db),
):
    try:
        return ThreatWorkspaceService.review_candidate(
            db=db,
            workspace_id=x_workspace_id,
            candidate_id_or_uuid=candidate_id,
            req=req,
            analyst=x_user or "ANALYST",
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.post(
    "/campaigns/merge-preview",
    response_model=CampaignMergePreviewResponse,
    summary="Preview campaign merge impact and conflicts",
    description="Inspects affected entities, indicators, and potential intelligence conflicts before merging two campaigns.",
)
def preview_campaign_merge(
    req: CampaignMergePreviewRequest,
    x_workspace_id: str = Header("default", alias="X-Workspace-Id"),
    role: str = Depends(get_actor_and_role),
    db: Session = Depends(get_db),
):
    try:
        return ThreatWorkspaceService.preview_merge(db=db, workspace_id=x_workspace_id, req=req)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.post(
    "/campaigns/merge",
    response_model=CampaignWorkspaceDetailResponse,
    summary="Execute campaign merge",
    description="Merges source campaign into target campaign, moving member incidents while preserving complete provenance.",
)
def merge_campaigns(
    req: CampaignMergeRequest,
    x_workspace_id: str = Header("default", alias="X-Workspace-Id"),
    x_user: Optional[str] = Header(None, alias="X-User"),
    role: str = Depends(get_actor_and_role),
    db: Session = Depends(get_db),
):
    try:
        return ThreatWorkspaceService.merge_campaigns(
            db=db,
            workspace_id=x_workspace_id,
            req=req,
            analyst=x_user or "ANALYST",
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.post(
    "/campaigns/{campaign_id}/split",
    summary="Split campaign into two distinct clusters",
    description="Detaches selected member incidents into a new campaign while preserving split lineage on both records.",
)
def split_campaign(
    campaign_id: str,
    req: CampaignSplitRequest,
    x_workspace_id: str = Header("default", alias="X-Workspace-Id"),
    x_user: Optional[str] = Header(None, alias="X-User"),
    role: str = Depends(get_actor_and_role),
    db: Session = Depends(get_db),
):
    try:
        return ThreatWorkspaceService.split_campaign(
            db=db,
            workspace_id=x_workspace_id,
            campaign_id_or_uuid=campaign_id,
            req=req,
            analyst=x_user or "ANALYST",
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


# =============================================================================
# Hypotheses Endpoints
# =============================================================================

@router.get(
    "/hypotheses",
    response_model=List[HypothesisResponse],
    summary="List analyst hypotheses for a campaign or threat actor",
)
def list_hypotheses(
    subject_id: str = Query(..., description="Campaign or Threat Actor UUID"),
    x_workspace_id: str = Header("default", alias="X-Workspace-Id"),
    role: str = Depends(get_actor_and_role),
    db: Session = Depends(get_db),
):
    return ThreatWorkspaceService.list_hypotheses(db=db, workspace_id=x_workspace_id, subject_id=subject_id)


@router.post(
    "/hypotheses",
    response_model=HypothesisResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Record a new threat hypothesis",
    description="Records an analyst hypothesis with supporting and contradicting evidence.",
)
def create_hypothesis(
    req: HypothesisCreateRequest,
    x_workspace_id: str = Header("default", alias="X-Workspace-Id"),
    x_user: Optional[str] = Header(None, alias="X-User"),
    role: str = Depends(get_actor_and_role),
    db: Session = Depends(get_db),
):
    return ThreatWorkspaceService.create_hypothesis(
        db=db,
        workspace_id=x_workspace_id,
        req=req,
        author=x_user or "ANALYST",
    )


@router.patch(
    "/hypotheses/{hypothesis_id}",
    response_model=HypothesisResponse,
    summary="Update hypothesis status or evidence",
    description="Transitions hypothesis lifecycle state (OPEN, SUPPORTED, WEAKENED, REJECTED, CONFIRMED).",
)
def update_hypothesis(
    hypothesis_id: str,
    req: HypothesisUpdateRequest,
    x_workspace_id: str = Header("default", alias="X-Workspace-Id"),
    x_user: Optional[str] = Header(None, alias="X-User"),
    role: str = Depends(get_actor_and_role),
    db: Session = Depends(get_db),
):
    try:
        return ThreatWorkspaceService.update_hypothesis(
            db=db,
            workspace_id=x_workspace_id,
            hypothesis_id=hypothesis_id,
            req=req,
            updater=x_user or "ANALYST",
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


# =============================================================================
# Background Job Synchronization Trigger
# =============================================================================

@router.post(
    "/sync",
    summary="Trigger asynchronous threat workspace correlation sweep",
    description="Enqueues a background job to cluster incidents, discover candidate campaigns, and update activity states.",
)
def trigger_workspace_sync(
    x_workspace_id: str = Header("default", alias="X-Workspace-Id"),
    x_user: Optional[str] = Header(None, alias="X-User"),
    role: str = Depends(get_actor_and_role),
    db: Session = Depends(get_db),
):
    job = BackgroundJobService.enqueue_job(
        db=db,
        workspace_id=x_workspace_id,
        job_type=JobTypeEnum.CAMPAIGN_CORRELATION_SWEEP.value,
        payload={"triggered_by": x_user or "ANALYST"},
        created_by=x_user or "ANALYST",
    )
    return {
        "status": "QUEUED",
        "job_id": job.id,
        "job_type": job.job_type,
        "message": "Campaign correlation and threat workspace synchronization job enqueued.",
    }
