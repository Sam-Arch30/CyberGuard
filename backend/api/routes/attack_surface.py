"""
Section 62: REST API Routes for Attack Surface Intelligence.

Provides operational and analytical endpoints to:
1. View attack surface overview metrics & breakdown by type, exposure state, criticality
2. Query and filter normalized assets (Domains, Subdomains, IPs, Endpoints, Identities, APIs, Cloud Resources)
3. Inspect progressive-disclosure asset detail (active exposures, services, graph neighbors, telemetry)
4. View chronological asset timeline
5. List and resolve actionable security exposures (with audit trail)
6. Manage unknown/unmapped asset queue with analyst triage actions (Approve, Assign Owner, Map, Mark Unauthorized, Watchlist)
7. Configure and enforce tenant-authorized discovery scopes (with strict SSRF prevention)
8. Trigger safe on-demand discovery sweeps across existing telemetry, endpoint inventory, and DNS scopes
9. Inspect latest attack surface diff snapshots
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.schemas.attack_surface import (
    AssetTypeEnum,
    AssetStatusEnum,
    ExposureStateEnum,
    CriticalityEnum,
    ScopeTypeEnum,
    AssetCreateRequest,
    AssetUpdateRequest,
    AssetRead,
    AssetDetail,
    AssetListResponse,
    ExposureRead,
    ExposureResolveRequest,
    AttackSurfaceScopeRead,
    AttackSurfaceScopeCreateRequest,
    AttackSurfaceOverviewStats,
    AttackSurfaceDiffResponse,
    UnknownAssetReviewRequest,
    AttackSurfaceDiscoveryRequest,
    AttackSurfaceDiscoveryResponse,
)
from backend.services.attack_surface_service import AttackSurfaceService

logger = logging.getLogger("cyberguard.api.attack_surface")

router = APIRouter(prefix="/api/v1/attack-surface", tags=["Attack Surface Intelligence"])


class ExposureListResponse(BaseModel):
    items: List[ExposureRead]
    total: int
    limit: int
    offset: int


class UnknownAssetQueueResponse(BaseModel):
    items: List[Dict[str, Any]]
    total: int
    limit: int
    offset: int


# ============================================================================
# 1. OVERVIEW & HEALTH METRICS
# ============================================================================

@router.get(
    "/overview",
    response_model=AttackSurfaceOverviewStats,
    summary="Get Attack Surface Intelligence overview metrics",
)
def get_attack_surface_overview(
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
):
    """Returns organizational attack surface metrics, exposure breakdowns, and recent exposures."""
    try:
        return AttackSurfaceService.get_overview_stats(db, workspace_id=x_workspace_id)
    except Exception as exc:
        logger.error(f"Failed to fetch attack surface overview: {exc}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve attack surface overview: {str(exc)}",
        )


# ============================================================================
# 2. ASSETS INVENTORY (QUERY, DETAIL, CREATE, UPDATE, TIMELINE)
# ============================================================================

@router.get(
    "/assets",
    response_model=AssetListResponse,
    summary="List normalized organizational assets with server-side filters",
)
def list_assets(
    asset_type: Optional[str] = Query(None, description="Asset type or ALL"),
    status: Optional[str] = Query(None, description="Asset status or ALL"),
    exposure_state: Optional[str] = Query(None, description="Exposure state or ALL"),
    criticality: Optional[str] = Query(None, description="Criticality or ALL"),
    q: Optional[str] = Query(None, description="Search term across name, owner, team"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
):
    """Returns paginated, multi-tenant filtered assets ordered by risk score."""
    items, total = AttackSurfaceService.list_assets(
        db=db,
        workspace_id=x_workspace_id,
        asset_type=asset_type,
        status=status,
        exposure_state=exposure_state,
        criticality=criticality,
        q=q,
        limit=limit,
        offset=offset,
    )
    return AssetListResponse(
        items=[AssetRead.model_validate(item) for item in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.post(
    "/assets",
    response_model=AssetRead,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new asset explicitly",
)
def create_asset(
    req: AssetCreateRequest,
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
):
    """Registers an asset manually or from external asset ingestion, evaluating exposures and risk."""
    try:
        asset = AttackSurfaceService.upsert_asset(db, workspace_id=x_workspace_id, req=req)
        db.commit()
        return AssetRead.model_validate(asset)
    except ValueError as val_err:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err))
    except Exception as exc:
        db.rollback()
        logger.error(f"Error creating asset: {exc}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create asset: {str(exc)}",
        )


@router.get(
    "/assets/{asset_id}",
    response_model=AssetDetail,
    summary="Get comprehensive forensic asset detail",
)
def get_asset_detail(
    asset_id: str,
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
):
    """Returns progressive-disclosure asset detail: exposures, services, relationships, and threat context."""
    try:
        return AttackSurfaceService.get_asset_detail(db, workspace_id=x_workspace_id, asset_id=asset_id)
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(val_err))
    except Exception as exc:
        logger.error(f"Failed to get asset detail for {asset_id}: {exc}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch asset detail: {str(exc)}",
        )


@router.patch(
    "/assets/{asset_id}",
    response_model=AssetRead,
    summary="Update asset ownership, criticality, or environment metadata",
)
def update_asset(
    asset_id: str,
    req: AssetUpdateRequest,
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
):
    """Updates asset metadata and recomputes risk accordingly."""
    try:
        asset = AttackSurfaceService.update_asset(
            db, workspace_id=x_workspace_id, asset_id=asset_id, req=req
        )
        db.commit()
        return AssetRead.model_validate(asset)
    except ValueError as val_err:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(val_err))
    except Exception as exc:
        db.rollback()
        logger.error(f"Failed to update asset {asset_id}: {exc}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update asset: {str(exc)}",
        )


@router.get(
    "/assets/{asset_id}/timeline",
    response_model=List[Dict[str, Any]],
    summary="Get chronological change timeline for an asset",
)
def get_asset_timeline(
    asset_id: str,
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
):
    """Returns chronological audit logs, discovery milestones, and exposure state changes."""
    return AttackSurfaceService.get_asset_timeline(
        db, workspace_id=x_workspace_id, asset_id=asset_id
    )


# ============================================================================
# 3. EXPOSURES MANAGEMENT & RESOLUTION
# ============================================================================

@router.get(
    "/exposures",
    response_model=ExposureListResponse,
    summary="List actionable exposures across organizational assets",
)
def list_exposures(
    asset_id: Optional[str] = Query(None, description="Filter by asset ID"),
    exposure_type: Optional[str] = Query(None, description="Exposure type or ALL"),
    status: Optional[str] = Query(None, description="Exposure status or ALL"),
    severity: Optional[str] = Query(None, description="Severity or ALL"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
):
    """Returns filtered actionable security exposures."""
    items, total = AttackSurfaceService.list_exposures(
        db=db,
        workspace_id=x_workspace_id,
        asset_id=asset_id,
        exposure_type=exposure_type,
        status=status,
        severity=severity,
        limit=limit,
        offset=offset,
    )
    return ExposureListResponse(
        items=[ExposureRead.model_validate(item) for item in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.post(
    "/exposures/{exposure_id}/resolve",
    response_model=ExposureRead,
    summary="Resolve an exposure with analyst rationale and audit record",
)
def resolve_exposure(
    exposure_id: str,
    req: ExposureResolveRequest,
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
):
    """Marks an exposure as resolved and updates parent asset risk."""
    try:
        exp = AttackSurfaceService.resolve_exposure_by_id(
            db=db,
            workspace_id=x_workspace_id,
            exposure_id=exposure_id,
            notes=req.notes,
            actor=req.actor,
        )
        db.commit()
        return ExposureRead.model_validate(exp)
    except ValueError as val_err:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(val_err))
    except Exception as exc:
        db.rollback()
        logger.error(f"Failed to resolve exposure {exposure_id}: {exc}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to resolve exposure: {str(exc)}",
        )


# ============================================================================
# 4. UNKNOWN / UNMAPPED ASSETS QUEUE & REVIEW
# ============================================================================

@router.get(
    "/unknown-queue",
    response_model=UnknownAssetQueueResponse,
    summary="Get queue of unknown/unmapped assets requiring triage",
)
def get_unknown_queue(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
):
    """Returns unmapped/discovered assets with observation rationale."""
    items, total = AttackSurfaceService.get_unknown_asset_queue(
        db=db,
        workspace_id=x_workspace_id,
        limit=limit,
        offset=offset,
    )
    return UnknownAssetQueueResponse(
        items=items,
        total=total,
        limit=limit,
        offset=offset,
    )


@router.post(
    "/unknown-queue/{asset_id}/review",
    response_model=AssetRead,
    summary="Analyst review action on an unknown asset",
)
def review_unknown_asset(
    asset_id: str,
    req: UnknownAssetReviewRequest,
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
):
    """Executes an analyst review action: APPROVE, ASSIGN_OWNER, MAP_TO_EXISTING, MARK_UNAUTHORIZED, ADD_TO_WATCHLIST."""
    try:
        asset = AttackSurfaceService.review_unknown_asset(
            db=db,
            workspace_id=x_workspace_id,
            asset_id=asset_id,
            req=req,
        )
        db.commit()
        return AssetRead.model_validate(asset)
    except ValueError as val_err:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err))
    except Exception as exc:
        db.rollback()
        logger.error(f"Failed to review unknown asset {asset_id}: {exc}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to review unknown asset: {str(exc)}",
        )


# ============================================================================
# 5. DISCOVERY SCOPE MANAGEMENT (STRICT SSRF BOUNDARIES)
# ============================================================================

@router.get(
    "/scopes",
    response_model=List[AttackSurfaceScopeRead],
    summary="List authorized discovery scopes for the workspace",
)
def list_scopes(
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
):
    """Returns tenant-authorized domains, CIDRs, and IPs."""
    scopes = AttackSurfaceService.list_scopes(db, workspace_id=x_workspace_id)
    return [AttackSurfaceScopeRead.model_validate(s) for s in scopes]


@router.post(
    "/scopes",
    response_model=AttackSurfaceScopeRead,
    status_code=status.HTTP_201_CREATED,
    summary="Register a tenant-authorized discovery scope",
)
def create_scope(
    req: AttackSurfaceScopeCreateRequest,
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
):
    """Registers an authorized discovery scope with strict SSRF validation."""
    try:
        scope = AttackSurfaceService.create_scope(
            db=db,
            workspace_id=x_workspace_id,
            req=req,
            actor="SOC Administrator",
        )
        db.commit()
        return AttackSurfaceScopeRead.model_validate(scope)
    except ValueError as val_err:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err))
    except Exception as exc:
        db.rollback()
        logger.error(f"Failed to create discovery scope: {exc}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create discovery scope: {str(exc)}",
        )


@router.delete(
    "/scopes/{scope_id}",
    summary="Remove an authorized discovery scope",
)
def delete_scope(
    scope_id: str,
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
):
    """Removes an authorized scope from discovery execution."""
    success = AttackSurfaceService.delete_scope(db, workspace_id=x_workspace_id, scope_id=scope_id)
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scope not found")
    db.commit()
    return {"deleted": True, "id": scope_id}


# ============================================================================
# 6. ON-DEMAND DISCOVERY & SNAPSHOT DIFFS
# ============================================================================

@router.post(
    "/discover",
    response_model=AttackSurfaceDiscoveryResponse,
    summary="Run authorized discovery and synchronization cycle",
)
def run_discovery(
    req: AttackSurfaceDiscoveryRequest,
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
):
    """Synchronizes assets from endpoint inventory, telemetry, identities, and resolves DNS for authorized scopes."""
    try:
        result = AttackSurfaceService.run_discovery_sync(
            db=db,
            workspace_id=x_workspace_id,
            options=req,
        )
        db.commit()
        return result
    except Exception as exc:
        db.rollback()
        logger.error(f"Discovery run failed: {exc}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Discovery run failed: {str(exc)}",
        )


@router.get(
    "/diff",
    response_model=AttackSurfaceDiffResponse,
    summary="Get latest attack surface change diff",
)
def get_attack_surface_diff(
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
):
    """Computes difference between current attack surface and previous snapshot."""
    try:
        return AttackSurfaceService.get_latest_diff(db, workspace_id=x_workspace_id)
    except Exception as exc:
        logger.error(f"Failed to get attack surface diff: {exc}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to calculate attack surface diff: {str(exc)}",
        )
