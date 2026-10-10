"""
Section 53: REST API Routes for IOC Watchlists & Continuous Threat Monitoring.
Provides endpoints for:
- Watchlist management (CRUD, health metrics, manual refresh)
- Watched indicator management (Add, bulk add, remove, search)
- Continuous monitoring execution & run history
- Intelligence change logs and timeline queries
- Quick-watch integration from Incidents and Investigations
"""
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.db.models import WatchedIndicatorModel
from backend.schemas.watchlists import (
    WatchlistCreateRequest,
    WatchlistUpdateRequest,
    WatchedIndicatorCreateRequest,
    WatchedIndicatorBulkAddRequest,
    QuickWatchRequest,
    WatchlistSummaryResponse,
    WatchlistDetailResponse,
    WatchlistListResponse,
    WatchedIndicatorResponse,
    WatchedIndicatorListResponse,
    IntelligenceChangeListResponse,
    WatchlistMonitoringRunResponse,
    WatchlistMonitoringRunListResponse,
    WatchlistHealthResponse,
)
from backend.services.watchlist_monitoring_service import WatchlistMonitoringService

router = APIRouter(prefix="/watchlists", tags=["IOC Watchlists & Continuous Threat Monitoring"])


# =============================================================================
# 1. Watchlist Collection Endpoints
# =============================================================================

@router.get(
    "",
    response_model=WatchlistListResponse,
    summary="List watchlists with pagination, status, and priority filtering",
)
def list_watchlists(
    status: Optional[str] = Query(None, description="Filter by status: ACTIVE, PAUSED, ARCHIVED"),
    priority: Optional[str] = Query(None, description="Filter by priority: LOW, MEDIUM, HIGH, CRITICAL"),
    q: Optional[str] = Query(None, description="Search term matching name or description"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
) -> WatchlistListResponse:
    return WatchlistMonitoringService.list_watchlists(
        db=db,
        workspace_id=x_workspace_id,
        status=status,
        priority=priority,
        q=q,
        limit=limit,
        offset=offset,
    )


@router.post(
    "",
    response_model=WatchlistSummaryResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new watchlist",
)
def create_watchlist(
    req: WatchlistCreateRequest,
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    x_user_id: str = Header("analyst", alias="X-User-ID"),
    db: Session = Depends(get_db),
) -> WatchlistSummaryResponse:
    wl = WatchlistMonitoringService.create_watchlist(
        db=db,
        workspace_id=x_workspace_id,
        req=req,
        actor=x_user_id,
    )
    return WatchlistMonitoringService._build_watchlist_summary(db, wl)


@router.post(
    "/quick-watch",
    response_model=WatchedIndicatorResponse,
    summary="Quick-watch an observable from an investigation or incident",
)
async def quick_watch_indicator(
    req: QuickWatchRequest,
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    x_user_id: str = Header("analyst", alias="X-User-ID"),
    db: Session = Depends(get_db),
) -> WatchedIndicatorResponse:
    return await WatchlistMonitoringService.quick_watch(
        db=db,
        workspace_id=x_workspace_id,
        req=req,
        actor=x_user_id,
    )


@router.get(
    "/changes/all",
    response_model=IntelligenceChangeListResponse,
    summary="List intelligence changes across all watchlists in workspace",
)
def list_all_changes(
    severity: Optional[str] = Query(None, description="Filter by change severity: LOW, MEDIUM, HIGH, CRITICAL"),
    change_type: Optional[str] = Query(None, description="Filter by change type"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
) -> IntelligenceChangeListResponse:
    return WatchlistMonitoringService.list_changes(
        db=db,
        workspace_id=x_workspace_id,
        watchlist_id=None,
        severity=severity,
        change_type=change_type,
        limit=limit,
        offset=offset,
    )


# =============================================================================
# 2. Single Watchlist Endpoints
# =============================================================================

@router.get(
    "/{watchlist_id}",
    response_model=WatchlistDetailResponse,
    summary="Get detailed watchlist metadata, indicator metrics, and recent changes",
)
def get_watchlist(
    watchlist_id: str,
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
) -> WatchlistDetailResponse:
    detail = WatchlistMonitoringService.get_watchlist(
        db=db,
        workspace_id=x_workspace_id,
        watchlist_id=watchlist_id,
    )
    if not detail:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Watchlist '{watchlist_id}' not found.")
    return detail


@router.patch(
    "/{watchlist_id}",
    response_model=WatchlistSummaryResponse,
    summary="Update watchlist configuration, pause/resume, or sensitivity",
)
def update_watchlist(
    watchlist_id: str,
    req: WatchlistUpdateRequest,
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    x_user_id: str = Header("analyst", alias="X-User-ID"),
    db: Session = Depends(get_db),
) -> WatchlistSummaryResponse:
    try:
        wl = WatchlistMonitoringService.update_watchlist(
            db=db,
            workspace_id=x_workspace_id,
            watchlist_id=watchlist_id,
            req=req,
            actor=x_user_id,
        )
        return WatchlistMonitoringService._build_watchlist_summary(db, wl)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.delete(
    "/{watchlist_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a watchlist and its monitored items",
)
def delete_watchlist(
    watchlist_id: str,
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    x_user_id: str = Header("analyst", alias="X-User-ID"),
    db: Session = Depends(get_db),
) -> None:
    success = WatchlistMonitoringService.delete_watchlist(
        db=db,
        workspace_id=x_workspace_id,
        watchlist_id=watchlist_id,
        actor=x_user_id,
    )
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Watchlist '{watchlist_id}' not found.")


@router.get(
    "/{watchlist_id}/health",
    response_model=WatchlistHealthResponse,
    summary="Get aggregated watchlist health, staleness metrics, and error rates",
)
def get_watchlist_health(
    watchlist_id: str,
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
) -> WatchlistHealthResponse:
    try:
        return WatchlistMonitoringService.get_watchlist_health(
            db=db,
            workspace_id=x_workspace_id,
            watchlist_id=watchlist_id,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post(
    "/{watchlist_id}/refresh",
    response_model=List[WatchlistMonitoringRunResponse],
    summary="Trigger immediate manual monitoring check across all indicators in watchlist",
)
async def refresh_watchlist(
    watchlist_id: str,
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
) -> List[WatchlistMonitoringRunResponse]:
    return await WatchlistMonitoringService.execute_monitoring_cycle(
        db=db,
        workspace_id=x_workspace_id,
        watchlist_id=watchlist_id,
        trigger_type="MANUAL",
    )


# =============================================================================
# 3. Watched Indicators Endpoints
# =============================================================================

@router.get(
    "/{watchlist_id}/items",
    response_model=WatchedIndicatorListResponse,
    summary="List monitored indicators in a watchlist with filters",
)
def list_watchlist_items(
    watchlist_id: str,
    status: Optional[str] = Query(None, description="Filter by status: ACTIVE, HEALTHY, STALE, ERROR"),
    verdict: Optional[str] = Query(None, description="Filter by last verdict: CLEAN, SUSPICIOUS, MALICIOUS"),
    q: Optional[str] = Query(None, description="Search term for indicator value"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
) -> WatchedIndicatorListResponse:
    return WatchlistMonitoringService.list_indicators(
        db=db,
        workspace_id=x_workspace_id,
        watchlist_id=watchlist_id,
        status=status,
        verdict=verdict,
        q=q,
        limit=limit,
        offset=offset,
    )


@router.post(
    "/{watchlist_id}/items",
    response_model=WatchedIndicatorResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Add an indicator to a watchlist",
)
def add_watchlist_item(
    watchlist_id: str,
    req: WatchedIndicatorCreateRequest,
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    x_user_id: str = Header("analyst", alias="X-User-ID"),
    db: Session = Depends(get_db),
) -> WatchedIndicatorResponse:
    try:
        item = WatchlistMonitoringService.add_indicator(
            db=db,
            workspace_id=x_workspace_id,
            watchlist_id=watchlist_id,
            req=req,
            actor=x_user_id,
        )
        return WatchlistMonitoringService._build_indicator_response(item)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post(
    "/{watchlist_id}/items/bulk",
    response_model=List[WatchedIndicatorResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Bulk add indicators to a watchlist",
)
def bulk_add_watchlist_items(
    watchlist_id: str,
    req: WatchedIndicatorBulkAddRequest,
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    x_user_id: str = Header("analyst", alias="X-User-ID"),
    db: Session = Depends(get_db),
) -> List[WatchedIndicatorResponse]:
    try:
        items = WatchlistMonitoringService.bulk_add_indicators(
            db=db,
            workspace_id=x_workspace_id,
            watchlist_id=watchlist_id,
            req=req,
            actor=x_user_id,
        )
        return [WatchlistMonitoringService._build_indicator_response(i) for i in items]
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.delete(
    "/{watchlist_id}/items/{item_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Remove an indicator from a watchlist",
)
def remove_watchlist_item(
    watchlist_id: str,
    item_id: str,
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    x_user_id: str = Header("analyst", alias="X-User-ID"),
    db: Session = Depends(get_db),
) -> None:
    success = WatchlistMonitoringService.remove_indicator(
        db=db,
        workspace_id=x_workspace_id,
        watchlist_id=watchlist_id,
        item_id=item_id,
        actor=x_user_id,
    )
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Item '{item_id}' not found.")


@router.post(
    "/items/{item_id}/refresh",
    response_model=WatchedIndicatorResponse,
    summary="Trigger immediate check on a single watched indicator",
)
async def refresh_single_indicator(
    item_id: str,
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
) -> WatchedIndicatorResponse:
    item = (
        db.query(WatchedIndicatorModel)
        .filter(WatchedIndicatorModel.id == item_id, WatchedIndicatorModel.workspace_id == x_workspace_id)
        .first()
    )
    if not item:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Watched indicator '{item_id}' not found.")

    await WatchlistMonitoringService.execute_single_indicator_check(db, item, force=True)
    db.refresh(item)
    return WatchlistMonitoringService._build_indicator_response(item)


# =============================================================================
# 4. Changes & Monitoring Runs
# =============================================================================

@router.get(
    "/{watchlist_id}/changes",
    response_model=IntelligenceChangeListResponse,
    summary="List intelligence changes for a specific watchlist",
)
def list_watchlist_changes(
    watchlist_id: str,
    severity: Optional[str] = Query(None, description="Filter by change severity"),
    change_type: Optional[str] = Query(None, description="Filter by change type"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
) -> IntelligenceChangeListResponse:
    return WatchlistMonitoringService.list_changes(
        db=db,
        workspace_id=x_workspace_id,
        watchlist_id=watchlist_id,
        severity=severity,
        change_type=change_type,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/{watchlist_id}/runs",
    response_model=WatchlistMonitoringRunListResponse,
    summary="List execution logs and metrics for watchlist monitoring runs",
)
def list_watchlist_runs(
    watchlist_id: str,
    limit: int = Query(20, ge=1, le=100),
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
) -> WatchlistMonitoringRunListResponse:
    return WatchlistMonitoringService.list_runs(
        db=db,
        workspace_id=x_workspace_id,
        watchlist_id=watchlist_id,
        limit=limit,
    )
