"""
Section 63: Asset & Identity Inventory REST API.
Authoritative endpoints for enterprise assets, identities, sources,
attribute conflict resolution, and background synchronization.
"""

import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Header, Query, status
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.services.inventory_service import InventoryService
from backend.services.background_job_service import BackgroundJobService
from backend.schemas.jobs import JobTypeEnum
from backend.schemas.inventory import (
    AssetRead,
    AssetCreate,
    AssetUpdate,
    AssetDetailRead,
    IdentityRead,
    IdentityCreate,
    IdentityUpdate,
    IdentityDetailRead,
    InventorySourceRead,
    InventorySourceCreate,
    InventoryConflictRead,
    InventoryConflictResolveRequest,
    InventoryOverviewStats,
    InventorySyncRequest,
    InventorySyncResponse,
    InventoryReconciliationReport,
    OwnershipAssignRequest,
)

logger = logging.getLogger("cyberguard.api.inventory")

router = APIRouter(prefix="/api/v1/inventory", tags=["Asset & Identity Inventory"])


def get_actor_and_role(
    x_role: Optional[str] = Header(None, alias="X-Role"),
    x_user_role: Optional[str] = Header(None, alias="X-User-Role"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
) -> Tuple_Role:
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
            detail="Forbidden: insufficient permissions for inventory operations.",
        )
    return role or "analyst"


Tuple_Role = str


# ---------------------------------------------------------------------------
# 1. OVERVIEW STATS
# ---------------------------------------------------------------------------

@router.get(
    "/overview",
    response_model=InventoryOverviewStats,
    summary="Get aggregated inventory health, asset counts, and identity metrics",
)
def get_inventory_overview(
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
    _role: str = Depends(get_actor_and_role),
):
    workspace_id = x_workspace_id or "default"
    return InventoryService.get_overview_stats(db, workspace_id=workspace_id)


# ---------------------------------------------------------------------------
# 2. ASSET INVENTORY (QUERY, DETAIL, UPDATE, ASSIGN OWNER)
# ---------------------------------------------------------------------------

@router.get(
    "/assets",
    response_model=Dict[str, Any],
    summary="List paginated and filtered assets from authoritative inventory",
)
def list_inventory_assets(
    asset_type: Optional[str] = Query(None, description="Asset classification type"),
    status: Optional[str] = Query(None, description="Lifecycle status"),
    environment: Optional[str] = Query(None, description="Environment"),
    criticality: Optional[str] = Query(None, description="Business criticality"),
    ownership_status: Optional[str] = Query(None, description="Ownership status"),
    is_managed: Optional[bool] = Query(None, description="Filter by managed endpoint status"),
    is_stale: Optional[bool] = Query(None, description="Filter by stale telemetry status"),
    search: Optional[str] = Query(None, description="Search term"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
    _role: str = Depends(get_actor_and_role),
):
    workspace_id = x_workspace_id or "default"
    items, total = InventoryService.list_assets(
        db,
        workspace_id=workspace_id,
        asset_type=asset_type,
        status=status,
        environment=environment,
        criticality=criticality,
        ownership_status=ownership_status,
        is_managed=is_managed,
        is_stale=is_stale,
        search=search,
        skip=skip,
        limit=limit,
    )
    return {
        "items": items,
        "total": total,
        "skip": skip,
        "limit": limit,
    }


@router.get(
    "/assets/{asset_id}",
    response_model=AssetDetailRead,
    summary="Get detailed asset profile, exposures, services, and conflicts",
)
def get_asset_detail(
    asset_id: str,
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
    _role: str = Depends(get_actor_and_role),
):
    workspace_id = x_workspace_id or "default"
    detail = InventoryService.get_asset_detail(db, workspace_id, asset_id)
    if not detail:
        raise HTTPException(status_code=404, detail=f"Asset '{asset_id}' not found.")
    return detail


@router.post(
    "/assets",
    response_model=AssetRead,
    status_code=status.HTTP_201_CREATED,
    summary="Register or upsert an asset into authoritative inventory",
)
def create_inventory_asset(
    payload: AssetCreate,
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
    role: str = Depends(get_actor_and_role),
):
    workspace_id = x_workspace_id or "default"
    asset, _ = InventoryService.upsert_asset(
        db, workspace_id=workspace_id, payload=payload, actor=role
    )
    res = AssetRead.model_validate(asset)
    res.tags = asset.tags_list
    return res


@router.patch(
    "/assets/{asset_id}",
    response_model=AssetRead,
    summary="Update business metadata or classification for an asset",
)
def update_inventory_asset(
    asset_id: str,
    payload: AssetUpdate,
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
    role: str = Depends(get_actor_and_role),
):
    workspace_id = x_workspace_id or "default"
    detail = InventoryService.get_asset_detail(db, workspace_id, asset_id)
    if not detail:
        raise HTTPException(status_code=404, detail=f"Asset '{asset_id}' not found.")

    from backend.db.models import AssetModel, json
    asset = db.query(AssetModel).filter(
        AssetModel.id == asset_id,
        AssetModel.workspace_id == workspace_id
    ).first()

    if payload.display_name is not None:
        asset.display_name = payload.display_name
    if payload.status is not None:
        asset.status = payload.status
    if payload.exposure_state is not None:
        asset.exposure_state = payload.exposure_state
    if payload.criticality is not None:
        asset.criticality = payload.criticality
    if payload.owner is not None:
        asset.owner = payload.owner
    if payload.team is not None:
        asset.team = payload.team
    if payload.department is not None:
        asset.department = payload.department
    if payload.business_unit is not None:
        asset.business_unit = payload.business_unit
    if payload.environment is not None:
        asset.environment = payload.environment
    if payload.classification is not None:
        asset.classification = payload.classification
    if payload.is_managed is not None:
        asset.is_managed = payload.is_managed
    if payload.tags is not None:
        asset.tags_json = json.dumps(payload.tags)
    if payload.metadata is not None:
        m = asset.metadata_dict
        m.update(payload.metadata)
        asset.metadata_json = json.dumps(m)

    db.commit()
    db.refresh(asset)
    res = AssetRead.model_validate(asset)
    res.tags = asset.tags_list
    return res


@router.post(
    "/assets/{asset_id}/assign-owner",
    response_model=AssetRead,
    summary="Assign asset ownership with recorded audit justification",
)
def assign_asset_owner(
    asset_id: str,
    payload: OwnershipAssignRequest,
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
    role: str = Depends(get_actor_and_role),
):
    workspace_id = x_workspace_id or "default"
    asset = InventoryService.assign_asset_owner(
        db,
        workspace_id=workspace_id,
        asset_id=asset_id,
        req=payload,
        actor=role,
    )
    if not asset:
        raise HTTPException(status_code=404, detail=f"Asset '{asset_id}' not found.")
    res = AssetRead.model_validate(asset)
    res.tags = asset.tags_list
    return res


# ---------------------------------------------------------------------------
# 3. IDENTITY INVENTORY (QUERY, DETAIL, CREATE, UPDATE)
# ---------------------------------------------------------------------------

@router.get(
    "/identities",
    response_model=Dict[str, Any],
    summary="List paginated identities, privileged accounts, and service accounts",
)
def list_inventory_identities(
    identity_type: Optional[str] = Query(None, description="USER, ACCOUNT, SERVICE_ACCOUNT, etc."),
    status: Optional[str] = Query(None, description="ACTIVE, INACTIVE, DORMANT, etc."),
    is_privileged: Optional[bool] = Query(None, description="Filter privileged accounts"),
    is_service_account: Optional[bool] = Query(None, description="Filter service accounts"),
    is_orphaned: Optional[bool] = Query(None, description="Filter orphaned accounts"),
    is_dormant: Optional[bool] = Query(None, description="Filter dormant accounts"),
    criticality: Optional[str] = Query(None, description="Criticality tier"),
    search: Optional[str] = Query(None, description="Search username, email, department"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
    _role: str = Depends(get_actor_and_role),
):
    workspace_id = x_workspace_id or "default"
    items, total = InventoryService.list_identities(
        db,
        workspace_id=workspace_id,
        identity_type=identity_type,
        status=status,
        is_privileged=is_privileged,
        is_service_account=is_service_account,
        is_orphaned=is_orphaned,
        is_dormant=is_dormant,
        criticality=criticality,
        search=search,
        skip=skip,
        limit=limit,
    )
    return {
        "items": items,
        "total": total,
        "skip": skip,
        "limit": limit,
    }


@router.get(
    "/identities/{identity_id}",
    response_model=IdentityDetailRead,
    summary="Get detailed identity profile, associated assets, and conflicts",
)
def get_identity_detail(
    identity_id: str,
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
    _role: str = Depends(get_actor_and_role),
):
    workspace_id = x_workspace_id or "default"
    detail = InventoryService.get_identity_detail(db, workspace_id, identity_id)
    if not detail:
        raise HTTPException(status_code=404, detail=f"Identity '{identity_id}' not found.")
    return detail


@router.post(
    "/identities",
    response_model=IdentityRead,
    status_code=status.HTTP_201_CREATED,
    summary="Register or upsert an identity / account into inventory",
)
def create_inventory_identity(
    payload: IdentityCreate,
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
    _role: str = Depends(get_actor_and_role),
):
    workspace_id = x_workspace_id or "default"
    ident, _ = InventoryService.upsert_identity(db, workspace_id, payload)
    res = IdentityRead.model_validate(ident)
    res.tags = ident.tags_list
    return res


# ---------------------------------------------------------------------------
# 4. INVENTORY SOURCE REGISTRY
# ---------------------------------------------------------------------------

@router.get(
    "/sources",
    response_model=List[InventorySourceRead],
    summary="List registered inventory sources and operational health",
)
def list_inventory_sources(
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
    _role: str = Depends(get_actor_and_role),
):
    workspace_id = x_workspace_id or "default"
    return InventoryService.list_sources(db, workspace_id=workspace_id)


@router.post(
    "/sources",
    response_model=InventorySourceRead,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new inventory source with deterministic precedence weight",
)
def create_inventory_source(
    payload: InventorySourceCreate,
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
    _role: str = Depends(get_actor_and_role),
):
    workspace_id = x_workspace_id or "default"
    source = InventoryService.create_source(db, workspace_id, payload)
    res = InventorySourceRead.model_validate(source)
    res.capabilities = source.capabilities_list
    return res


@router.delete(
    "/sources/{source_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete an inventory source connector",
)
def delete_inventory_source(
    source_id: str,
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
    _role: str = Depends(get_actor_and_role),
):
    workspace_id = x_workspace_id or "default"
    success = InventoryService.delete_source(db, workspace_id, source_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"Source '{source_id}' not found.")
    return None


# ---------------------------------------------------------------------------
# 5. CONFLICT RESOLUTION WORKSPACE
# ---------------------------------------------------------------------------

@router.get(
    "/conflicts",
    response_model=Dict[str, Any],
    summary="List attribute conflicts across inventory sources",
)
def list_inventory_conflicts(
    status: Optional[str] = Query(None, description="AUTO_RESOLVED, PENDING_REVIEW, MANUALLY_RESOLVED"),
    target_type: Optional[str] = Query(None, description="ASSET or IDENTITY"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
    _role: str = Depends(get_actor_and_role),
):
    workspace_id = x_workspace_id or "default"
    items, total = InventoryService.list_conflicts(
        db,
        workspace_id=workspace_id,
        status=status,
        target_type=target_type,
        skip=skip,
        limit=limit,
    )
    return {
        "items": items,
        "total": total,
        "skip": skip,
        "limit": limit,
    }


@router.post(
    "/conflicts/{conflict_id}/resolve",
    response_model=InventoryConflictRead,
    summary="Resolve an attribute conflict between sources with audit justification",
)
def resolve_inventory_conflict(
    conflict_id: str,
    payload: InventoryConflictResolveRequest,
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
    role: str = Depends(get_actor_and_role),
):
    workspace_id = x_workspace_id or "default"
    res = InventoryService.resolve_conflict(
        db,
        workspace_id=workspace_id,
        conflict_id=conflict_id,
        selected_value=payload.selected_value,
        selected_source=payload.selected_source,
        resolution_reason=payload.resolution_reason,
        actor=role,
    )
    if not res:
        raise HTTPException(status_code=404, detail=f"Conflict '{conflict_id}' not found.")
    out = InventoryConflictRead.model_validate(res)
    out.conflicting_values = res.conflicting_values_list
    return out


# ---------------------------------------------------------------------------
# 6. SYNCHRONIZATION & RECONCILIATION
# ---------------------------------------------------------------------------

@router.post(
    "/sync",
    response_model=InventorySyncResponse,
    summary="Execute inventory sync from endpoint, identity, and telemetry sources",
)
def run_inventory_sync(
    payload: Optional[InventorySyncRequest] = None,
    run_async: bool = Query(False, description="Run as asynchronous Section 45 background job"),
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
    _role: str = Depends(get_actor_and_role),
):
    workspace_id = x_workspace_id or "default"
    req = payload or InventorySyncRequest()

    if run_async:
        job = BackgroundJobService.enqueue_job(
            db=db,
            job_type=JobTypeEnum.INVENTORY_SYNC,
            workspace_id=workspace_id,
            resource_type="inventory",
            resource_id="sync",
            payload=req.model_dump(),
        )
        return InventorySyncResponse(
            assets_synced=0,
            identities_synced=0,
            conflicts_detected=0,
            status="QUEUED",
            message=f"Inventory sync background job '{job.id}' queued successfully.",
        )

    return InventoryService.run_inventory_sync(db, workspace_id, req)


@router.post(
    "/reconcile",
    response_model=InventoryReconciliationReport,
    summary="Execute full reconciliation to detect stale assets, unmanaged endpoints, and dormant accounts",
)
def run_inventory_reconciliation(
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
    _role: str = Depends(get_actor_and_role),
):
    workspace_id = x_workspace_id or "default"
    return InventoryService.run_reconciliation(db, workspace_id)
