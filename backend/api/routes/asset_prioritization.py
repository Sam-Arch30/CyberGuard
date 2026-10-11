"""
Section 64: Risk-Based Asset Prioritization REST API.
Authoritative endpoints for operational asset priority ranking,
structured explainable factor breakdowns, policy versioning, and manual analyst overrides.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Header, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import desc, asc

from backend.db.session import get_db
from backend.services.asset_prioritization_service import AssetPrioritizationService
from backend.services.background_job_service import BackgroundJobService
from backend.schemas.jobs import JobTypeEnum
from backend.schemas.asset_prioritization import (
    PrioritizedAssetItem,
    PrioritizedAssetListResponse,
    PriorityExplanationResponse,
    PriorityHistoryItem,
    PriorityHistoryResponse,
    PriorityOverrideRequest,
    PriorityRecalculateRequest,
    PriorityPolicyCreateRequest,
    PriorityPolicyUpdateRequest,
    PriorityPolicyResponse,
    PrioritizedAssetSummary,
)

logger = logging.getLogger("cyberguard.api.asset_prioritization")

router = APIRouter(prefix="/api/v1/prioritization", tags=["Risk-Based Asset Prioritization"])


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
            detail="Forbidden: insufficient permissions for asset prioritization operations.",
        )
    return role or "analyst"


# ---------------------------------------------------------------------------
# 1. PRIORITIZED ASSET LISTING & DETAIL
# ---------------------------------------------------------------------------

@router.get("/assets", response_model=PrioritizedAssetListResponse)
def list_prioritized_assets(
    priority_band: Optional[str] = Query("ALL", description="P1, P2, P3, P4, UNPRIORITIZED, ALL"),
    min_priority: Optional[str] = Query("ALL", description="P1, P2, P3, P4, ALL"),
    criticality: Optional[str] = Query("ALL"),
    exposure_state: Optional[str] = Query("ALL"),
    environment: Optional[str] = Query("ALL"),
    search: Optional[str] = Query(None),
    is_overridden: Optional[bool] = Query(None),
    sort_by: str = Query("priority_score", description="priority_score, risk_score, last_seen_at"),
    sort_desc: bool = Query(True),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    x_workspace_id: str = Header("default", alias="X-Workspace-Id"),
    role: str = Depends(get_actor_and_role),
    db: Session = Depends(get_db),
):
    """
    Lists prioritized assets filtered by priority band, business criticality, exposure, or environment.
    """
    items, total, counts = AssetPrioritizationService.list_prioritized_assets(
        db=db,
        workspace_id=x_workspace_id,
        priority_band=priority_band,
        min_priority=min_priority,
        criticality=criticality,
        exposure_state=exposure_state,
        environment=environment,
        search=search,
        is_overridden=is_overridden,
        sort_by=sort_by,
        sort_desc=sort_desc,
        limit=limit,
        offset=offset,
    )

    item_reads = []
    for a in items:
        item_reads.append(
            PrioritizedAssetItem(
                id=a.id,
                asset_type=a.asset_type,
                canonical_name=a.canonical_name,
                display_name=a.display_name,
                priority_band=a.priority_band,
                priority_score=a.priority_score,
                effective_priority=a.effective_priority,
                is_overridden=bool(a.priority_override),
                override_priority=a.priority_override,
                override_reason=a.priority_override_reason,
                risk_score=a.risk_score,
                risk_level=a.risk_level,
                criticality=a.criticality,
                exposure_state=a.exposure_state,
                environment=a.environment,
                owner=a.owner,
                team=a.team,
                department=a.department,
                is_managed=a.is_managed,
                is_stale=a.is_stale,
                active_incident_count=0,
                priority_data_quality=a.priority_data_quality,
                priority_calculated_at=a.priority_calculated_at,
                last_seen_at=a.last_seen_at,
            )
        )

    return PrioritizedAssetListResponse(
        items=item_reads,
        total=total,
        p1_count=counts.get("p1_count", 0),
        p2_count=counts.get("p2_count", 0),
        p3_count=counts.get("p3_count", 0),
        p4_count=counts.get("p4_count", 0),
        unprioritized_count=counts.get("unprioritized_count", 0),
        overridden_count=counts.get("overridden_count", 0),
        limit=limit,
        offset=offset,
    )


@router.get("/assets/{asset_id}", response_model=PrioritizedAssetItem)
def get_prioritized_asset(
    asset_id: str,
    x_workspace_id: str = Header("default", alias="X-Workspace-Id"),
    role: str = Depends(get_actor_and_role),
    db: Session = Depends(get_db),
):
    """
    Retrieves priority status for a specific asset.
    """
    from backend.db.models import AssetModel

    asset = (
        db.query(AssetModel)
        .filter(AssetModel.workspace_id == x_workspace_id, AssetModel.id == asset_id)
        .first()
    )
    if not asset:
        raise HTTPException(status_code=404, detail=f"Asset {asset_id} not found")

    return PrioritizedAssetItem(
        id=asset.id,
        asset_type=asset.asset_type,
        canonical_name=asset.canonical_name,
        display_name=asset.display_name,
        priority_band=asset.priority_band,
        priority_score=asset.priority_score,
        effective_priority=asset.effective_priority,
        is_overridden=bool(asset.priority_override),
        override_priority=asset.priority_override,
        override_reason=asset.priority_override_reason,
        risk_score=asset.risk_score,
        risk_level=asset.risk_level,
        criticality=asset.criticality,
        exposure_state=asset.exposure_state,
        environment=asset.environment,
        owner=asset.owner,
        team=asset.team,
        department=asset.department,
        is_managed=asset.is_managed,
        is_stale=asset.is_stale,
        active_incident_count=0,
        priority_data_quality=asset.priority_data_quality,
        priority_calculated_at=asset.priority_calculated_at,
        last_seen_at=asset.last_seen_at,
    )


# ---------------------------------------------------------------------------
# 2. EXPLANATION & AUDIT HISTORY
# ---------------------------------------------------------------------------

@router.get("/assets/{asset_id}/explanation", response_model=PriorityExplanationResponse)
def get_priority_explanation(
    asset_id: str,
    x_workspace_id: str = Header("default", alias="X-Workspace-Id"),
    role: str = Depends(get_actor_and_role),
    db: Session = Depends(get_db),
):
    """
    Retrieves the structured explainable factor contributions and data quality breakdown for an asset.
    """
    try:
        return AssetPrioritizationService.get_asset_priority_explanation(
            db=db, workspace_id=x_workspace_id, asset_id=asset_id
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/assets/{asset_id}/history", response_model=PriorityHistoryResponse)
def get_priority_history(
    asset_id: str,
    limit: int = Query(20, ge=1, le=100),
    x_workspace_id: str = Header("default", alias="X-Workspace-Id"),
    role: str = Depends(get_actor_and_role),
    db: Session = Depends(get_db),
):
    """
    Retrieves the timeline of priority transitions and evaluations for an asset.
    """
    snapshots = AssetPrioritizationService.get_asset_priority_history(
        db=db, workspace_id=x_workspace_id, asset_id=asset_id, limit=limit
    )

    items = [
        PriorityHistoryItem(
            id=s.id,
            asset_id=s.asset_id,
            priority_band=s.priority_band,
            priority_score=s.priority_score,
            previous_priority_band=s.previous_priority_band,
            transition_type=s.transition_type,
            is_override=s.is_override,
            override_priority=s.override_priority,
            override_reason=s.override_reason,
            override_by=s.override_by,
            risk_score=s.risk_score,
            business_criticality=s.business_criticality,
            exposure_state=s.exposure_state,
            data_quality=s.data_quality,
            policy_version=s.policy_version,
            calculated_at=s.calculated_at,
        )
        for s in snapshots
    ]

    return PriorityHistoryResponse(items=items, total=len(items))


# ---------------------------------------------------------------------------
# 3. MANUAL ANALYST OVERRIDES
# ---------------------------------------------------------------------------

@router.post("/assets/{asset_id}/override", response_model=PrioritizedAssetItem)
def apply_priority_override(
    asset_id: str,
    payload: PriorityOverrideRequest,
    x_workspace_id: str = Header("default", alias="X-Workspace-Id"),
    x_user: Optional[str] = Header("analyst", alias="X-User"),
    role: str = Depends(get_actor_and_role),
    db: Session = Depends(get_db),
):
    """
    Applies an auditable manual priority override to an asset.
    """
    try:
        asset = AssetPrioritizationService.apply_manual_override(
            db=db,
            workspace_id=x_workspace_id,
            asset_id=asset_id,
            priority=payload.priority,
            reason=payload.reason,
            actor=x_user or "analyst",
            expires_in_hours=payload.expires_in_hours,
        )
        return get_prioritized_asset(asset.id, x_workspace_id, role, db)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/assets/{asset_id}/override", response_model=PrioritizedAssetItem)
def remove_priority_override(
    asset_id: str,
    x_workspace_id: str = Header("default", alias="X-Workspace-Id"),
    x_user: Optional[str] = Header("analyst", alias="X-User"),
    role: str = Depends(get_actor_and_role),
    db: Session = Depends(get_db),
):
    """
    Removes a manual priority override and restores the calculated priority band.
    """
    try:
        asset = AssetPrioritizationService.remove_manual_override(
            db=db,
            workspace_id=x_workspace_id,
            asset_id=asset_id,
            actor=x_user or "analyst",
        )
        return get_prioritized_asset(asset.id, x_workspace_id, role, db)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


# ---------------------------------------------------------------------------
# 4. RECALCULATION & JOBS
# ---------------------------------------------------------------------------

@router.post("/recalculate")
def recalculate_priorities(
    payload: PriorityRecalculateRequest = PriorityRecalculateRequest(),
    run_async: bool = Query(False, description="Run as background job via Section 45"),
    x_workspace_id: str = Header("default", alias="X-Workspace-Id"),
    x_user: Optional[str] = Header("analyst", alias="X-User"),
    role: str = Depends(get_actor_and_role),
    db: Session = Depends(get_db),
):
    """
    Triggers deterministic recalculation of asset priorities.
    """
    if run_async:
        job = BackgroundJobService.create_job(
            db=db,
            workspace_id=x_workspace_id,
            job_type=JobTypeEnum.ASSET_PRIORITY_RECALCULATION.value,
            parameters={
                "asset_ids": payload.asset_ids,
                "force": payload.force,
                "actor": x_user or "analyst",
            },
        )
        return {"status": "QUEUED", "job_id": job.id, "run_async": True}

    summary = AssetPrioritizationService.recalculate_workspace_priorities(
        db=db,
        workspace_id=x_workspace_id,
        asset_ids=payload.asset_ids,
        actor=x_user or "analyst",
    )
    return {"status": "COMPLETED", "summary": summary, "run_async": False}


# ---------------------------------------------------------------------------
# 5. PRIORITIZATION POLICIES
# ---------------------------------------------------------------------------

@router.get("/policies", response_model=List[PriorityPolicyResponse])
def list_policies(
    x_workspace_id: str = Header("default", alias="X-Workspace-Id"),
    role: str = Depends(get_actor_and_role),
    db: Session = Depends(get_db),
):
    """
    Lists all prioritization policies in the workspace.
    """
    from backend.db.models import AssetPrioritizationPolicyModel

    policies = (
        db.query(AssetPrioritizationPolicyModel)
        .filter(AssetPrioritizationPolicyModel.workspace_id == x_workspace_id)
        .order_by(desc(AssetPrioritizationPolicyModel.version))
        .all()
    )
    return [
        PriorityPolicyResponse(
            id=p.id,
            name=p.name,
            description=p.description,
            version=p.version,
            status=p.status,
            configuration=p.configuration_dict,
            created_by=p.created_by,
            activated_at=p.activated_at,
            created_at=p.created_at,
            updated_at=p.updated_at,
        )
        for p in policies
    ]


@router.get("/policies/active", response_model=PriorityPolicyResponse)
def get_active_policy(
    x_workspace_id: str = Header("default", alias="X-Workspace-Id"),
    role: str = Depends(get_actor_and_role),
    db: Session = Depends(get_db),
):
    """
    Retrieves the currently active prioritization policy.
    """
    p = AssetPrioritizationService.get_or_create_active_policy(db, x_workspace_id)
    return PriorityPolicyResponse(
        id=p.id,
        name=p.name,
        description=p.description,
        version=p.version,
        status=p.status,
        configuration=p.configuration_dict,
        created_by=p.created_by,
        activated_at=p.activated_at,
        created_at=p.created_at,
        updated_at=p.updated_at,
    )


@router.post("/policies", response_model=PriorityPolicyResponse, status_code=201)
def create_policy(
    payload: PriorityPolicyCreateRequest,
    x_workspace_id: str = Header("default", alias="X-Workspace-Id"),
    x_user: Optional[str] = Header("analyst", alias="X-User"),
    role: str = Depends(get_actor_and_role),
    db: Session = Depends(get_db),
):
    """
    Creates a new prioritization policy draft.
    """
    p = AssetPrioritizationService.create_policy(
        db=db,
        workspace_id=x_workspace_id,
        name=payload.name,
        configuration=payload.configuration,
        description=payload.description,
        created_by=x_user or "analyst",
        status="DRAFT",
    )
    return PriorityPolicyResponse(
        id=p.id,
        name=p.name,
        description=p.description,
        version=p.version,
        status=p.status,
        configuration=p.configuration_dict,
        created_by=p.created_by,
        activated_at=p.activated_at,
        created_at=p.created_at,
        updated_at=p.updated_at,
    )


@router.post("/policies/{policy_id}/activate", response_model=PriorityPolicyResponse)
def activate_policy(
    policy_id: str,
    x_workspace_id: str = Header("default", alias="X-Workspace-Id"),
    role: str = Depends(get_actor_and_role),
    db: Session = Depends(get_db),
):
    """
    Activates a policy version and triggers background recalculation across the workspace.
    """
    try:
        p = AssetPrioritizationService.activate_policy(db, x_workspace_id, policy_id)
        # Trigger background recalculation with new policy
        BackgroundJobService.create_job(
            db=db,
            workspace_id=x_workspace_id,
            job_type=JobTypeEnum.ASSET_PRIORITY_RECALCULATION.value,
            parameters={"actor": "POLICY_ACTIVATION"},
        )
        return PriorityPolicyResponse(
            id=p.id,
            name=p.name,
            description=p.description,
            version=p.version,
            status=p.status,
            configuration=p.configuration_dict,
            created_by=p.created_by,
            activated_at=p.activated_at,
            created_at=p.created_at,
            updated_at=p.updated_at,
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


# ---------------------------------------------------------------------------
# 6. OVERVIEW STATS & TOP PRIORITIZED ASSETS
# ---------------------------------------------------------------------------

@router.get("/overview")
def get_prioritization_overview(
    x_workspace_id: str = Header("default", alias="X-Workspace-Id"),
    role: str = Depends(get_actor_and_role),
    db: Session = Depends(get_db),
):
    """
    Provides top prioritized assets and operational distribution for SOC overview.
    """
    top_assets = AssetPrioritizationService.get_top_prioritized_assets(db, x_workspace_id, limit=6)
    _, total, counts = AssetPrioritizationService.list_prioritized_assets(
        db=db, workspace_id=x_workspace_id, limit=1
    )
    active_policy = AssetPrioritizationService.get_or_create_active_policy(db, x_workspace_id)

    return {
        "top_assets": top_assets,
        "total_assets": total,
        "distribution": counts,
        "active_policy": {
            "id": active_policy.id,
            "name": active_policy.name,
            "version": active_policy.version,
        },
    }
