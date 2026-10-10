"""
Section 54: REST API Routes for Threat Hunting Workspace & Query Engine.
Exposes endpoints for:
- Data source catalog and query capabilities registry
- Safe query validation and plan generation
- Query execution (Fast synchronous mode and Section 45 Background Job mode)
- Saved hunts and template management
- Natural language to structured query translation
- Investigation and Watchlist handoffs
- Hunt results export
"""
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Response, status
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.db.models import SavedHuntModel, HuntExecutionModel
from backend.schemas.hunting import (
    DataSourceRegistryResponse,
    HuntQueryDefinition,
    HuntValidationResponse,
    HuntExecutionRequest,
    HuntQueryResultResponse,
    SavedHuntCreateRequest,
    SavedHuntUpdateRequest,
    SavedHuntResponse,
    SavedHuntListResponse,
    NaturalLanguageHuntRequest,
    NaturalLanguageHuntResponse,
    HuntInvestigationHandoffRequest,
    HuntInvestigationHandoffResponse,
    HuntWatchlistHandoffRequest,
    HuntWatchlistHandoffResponse,
    HuntExportRequest,
    HuntExecutionModeEnum,
)
from backend.schemas.jobs import JobSubmitRequest, JobTypeEnum, JobPriorityEnum
from backend.services.background_job_service import BackgroundJobService
from backend.services.threat_hunting_service import ThreatHuntingService

router = APIRouter(prefix="/hunting", tags=["Threat Hunting Workspace & Query Engine"])


# =============================================================================
# 1. Catalog & Validation
# =============================================================================

@router.get(
    "/registry",
    response_model=DataSourceRegistryResponse,
    summary="Get Data Source Registry with supported fields and query capabilities",
)
def get_registry(
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
) -> DataSourceRegistryResponse:
    return ThreatHuntingService.get_data_source_registry(db=db, workspace_id=x_workspace_id)


@router.post(
    "/validate",
    response_model=HuntValidationResponse,
    summary="Validate query definition and generate explainable query plan",
)
def validate_query(
    query: HuntQueryDefinition,
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
) -> HuntValidationResponse:
    return ThreatHuntingService.validate_query(query=query, workspace_id=x_workspace_id)


# =============================================================================
# 2. Query Execution (Fast & Background)
# =============================================================================

@router.post(
    "/execute",
    response_model=HuntQueryResultResponse,
    summary="Execute a threat hunt query against CyberGuard data sources",
)
def execute_hunt(
    req: HuntExecutionRequest,
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    x_user_id: Optional[str] = Header("analyst", alias="X-User-ID"),
    db: Session = Depends(get_db),
) -> Any:
    # If background execution requested, dispatch via Section 45 Background Jobs
    if req.execution_mode == HuntExecutionModeEnum.BACKGROUND:
        job = BackgroundJobService.submit_job(
            db=db,
            workspace_id=x_workspace_id,
            req=JobSubmitRequest(
                job_type=JobTypeEnum.THREAT_HUNT_EXECUTION,
                resource_type="HUNT",
                priority=JobPriorityEnum.HIGH,
                payload={
                    "query_definition": req.query_definition.model_dump(),
                    "saved_hunt_id": req.saved_hunt_id,
                },
            ),
            user_id=x_user_id or "analyst",
        )
        return {
            "execution_id": job.id,
            "data_source": req.query_definition.data_source.value,
            "status": "QUEUED",
            "total_matches": 0,
            "items": [],
            "aggregations": None,
            "duration_ms": 0,
            "query_plan": [],
            "has_more": False,
            "offset": 0,
            "limit": req.query_definition.limit,
        }

    try:
        return ThreatHuntingService.execute_hunt(
            db=db,
            workspace_id=x_workspace_id,
            req=req,
            actor=x_user_id or "analyst",
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


# =============================================================================
# 3. Saved Hunts & Templates Library
# =============================================================================

@router.get(
    "/saved",
    response_model=SavedHuntListResponse,
    summary="List saved hunts and built-in templates",
)
def list_saved_hunts(
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    x_user_id: Optional[str] = Header(None, alias="X-User-ID"),
    db: Session = Depends(get_db),
) -> SavedHuntListResponse:
    return ThreatHuntingService.list_saved_hunts(db=db, workspace_id=x_workspace_id, user_id=x_user_id)


@router.post(
    "/saved",
    response_model=SavedHuntResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Save a validated threat hunt query definition",
)
def create_saved_hunt(
    req: SavedHuntCreateRequest,
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    x_user_id: Optional[str] = Header("analyst", alias="X-User-ID"),
    db: Session = Depends(get_db),
) -> SavedHuntResponse:
    try:
        return ThreatHuntingService.create_saved_hunt(
            db=db, workspace_id=x_workspace_id, req=req, actor=x_user_id or "analyst"
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.patch(
    "/saved/{hunt_id}",
    response_model=SavedHuntResponse,
    summary="Update a saved threat hunt query",
)
def update_saved_hunt(
    hunt_id: str,
    req: SavedHuntUpdateRequest,
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    x_user_id: Optional[str] = Header("analyst", alias="X-User-ID"),
    db: Session = Depends(get_db),
) -> SavedHuntResponse:
    sh = ThreatHuntingService.update_saved_hunt(
        db=db, workspace_id=x_workspace_id, hunt_id=hunt_id, req=req, actor=x_user_id or "analyst"
    )
    if not sh:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Saved hunt '{hunt_id}' not found.")
    return sh


@router.delete(
    "/saved/{hunt_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a saved threat hunt",
)
def delete_saved_hunt(
    hunt_id: str,
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
):
    success = ThreatHuntingService.delete_saved_hunt(db=db, workspace_id=x_workspace_id, hunt_id=hunt_id)
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Saved hunt '{hunt_id}' not found.")
    return None


# =============================================================================
# 4. Natural Language Assistant
# =============================================================================

@router.post(
    "/assistant",
    response_model=NaturalLanguageHuntResponse,
    summary="Translate natural language question into validated Query DSL",
)
def natural_language_assistant(
    req: NaturalLanguageHuntRequest,
) -> NaturalLanguageHuntResponse:
    return ThreatHuntingService.natural_language_to_query(req)


# =============================================================================
# 5. Handoffs & Export
# =============================================================================

@router.post(
    "/handoff/investigation",
    response_model=HuntInvestigationHandoffResponse,
    summary="Create investigation or attach hunt results to incident",
)
def handoff_investigation(
    req: HuntInvestigationHandoffRequest,
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    x_user_id: Optional[str] = Header("analyst", alias="X-User-ID"),
    db: Session = Depends(get_db),
) -> HuntInvestigationHandoffResponse:
    try:
        return ThreatHuntingService.handoff_to_investigation(
            db=db, workspace_id=x_workspace_id, req=req, actor=x_user_id or "analyst"
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.post(
    "/handoff/watchlist",
    response_model=HuntWatchlistHandoffResponse,
    summary="Add selected indicators from hunt to Section 53 Watchlist",
)
def handoff_watchlist(
    req: HuntWatchlistHandoffRequest,
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    x_user_id: Optional[str] = Header("analyst", alias="X-User-ID"),
    db: Session = Depends(get_db),
) -> HuntWatchlistHandoffResponse:
    try:
        return ThreatHuntingService.handoff_to_watchlist(
            db=db, workspace_id=x_workspace_id, req=req, actor=x_user_id or "analyst"
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.post(
    "/export",
    summary="Export hunt query results as JSON or CSV",
)
def export_results(
    req: HuntExportRequest,
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
):
    try:
        content, media_type = ThreatHuntingService.export_results(
            db=db, workspace_id=x_workspace_id, execution_id=req.execution_id, format_type=req.format
        )
        return Response(content=content, media_type=media_type)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
