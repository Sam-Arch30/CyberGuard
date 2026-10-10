"""
Section 55: REST API Routes for Advanced Threat Hunting & Investigation Pivots.
Exposes endpoints for:
- Pivot catalog and capabilities registry
- Bounded multi-hop pivot execution (Synchronous and Section 45 Background Job mode)
- Entity frequency analysis & provenance context
- Explainable AI-assisted pivot recommendations
- Analyst hypothesis management and evidence classification
- Workflow handoffs to Investigations, Watchlists, and Threat Hunting.
"""
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.schemas.jobs import JobSubmitRequest, JobTypeEnum, JobPriorityEnum
from backend.schemas.pivots import (
    PivotRegistryResponse,
    PivotRequest,
    PivotResponse,
    EntityFrequencyContext,
    AIPivotRecommendationResponse,
    HypothesisRecordRequest,
    HypothesisResponse,
    PromoteToInvestigationRequest,
    PromoteToInvestigationResponse,
    PromoteToWatchlistRequest,
    PromoteToWatchlistResponse,
    PivotToHuntQueryRequest,
    PivotToHuntQueryResponse,
)
from backend.services.background_job_service import BackgroundJobService
from backend.services.investigation_pivot_service import InvestigationPivotService

router = APIRouter(prefix="/hunting/pivots", tags=["Threat Hunting & Investigation Pivots"])


# =============================================================================
# 1. Registry & Capabilities
# =============================================================================

@router.get(
    "/registry",
    response_model=PivotRegistryResponse,
    summary="Get Pivot Registry with supported source types and relational pivots",
)
def get_pivot_registry(
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
) -> PivotRegistryResponse:
    return InvestigationPivotService.get_pivot_registry(workspace_id=x_workspace_id)


# =============================================================================
# 2. Pivot Execution (Fast & Background)
# =============================================================================

@router.post(
    "/execute",
    response_model=PivotResponse,
    summary="Execute an evidence-driven investigation pivot from a suspicious observable",
)
def execute_pivot(
    req: PivotRequest,
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    x_user_id: Optional[str] = Header("analyst", alias="X-User-ID"),
    db: Session = Depends(get_db),
) -> Any:
    # If background execution requested, dispatch via Section 45 Background Jobs
    if req.execution_mode.upper() == "BACKGROUND":
        job = BackgroundJobService.submit_job(
            db=db,
            workspace_id=x_workspace_id,
            req=JobSubmitRequest(
                job_type=JobTypeEnum.ADVANCED_PIVOT_EXECUTION,
                resource_type="PIVOT",
                priority=JobPriorityEnum.HIGH,
                payload={
                    "pivot_request": req.model_dump(),
                },
            ),
            user_id=x_user_id or "analyst",
        )
        return PivotResponse(
            source_type=req.source_type.value,
            source_value=req.source_value,
            pivot_type=req.pivot_type.value,
            depth=req.depth,
            execution_time_ms=0.0,
            total_results=0,
            truncated=False,
            items=[],
            frequency_context=InvestigationPivotService.get_entity_frequency_context(
                db=db,
                source_type=req.source_type.value,
                source_value=req.source_value,
                workspace_id=x_workspace_id,
            ),
            graph_nodes=[],
            graph_edges=[],
            job_id=job.id,
        )

    try:
        return InvestigationPivotService.execute_pivot(
            db=db,
            req=req,
            workspace_id=x_workspace_id,
            user_id=x_user_id or "analyst",
        )
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(val_err),
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Pivot execution failed: {exc}",
        )


# =============================================================================
# 3. Frequency & Historical Context
# =============================================================================

@router.get(
    "/frequency",
    response_model=EntityFrequencyContext,
    summary="Get entity frequency metrics, observation span, and investigation counts",
)
def get_entity_frequency(
    source_type: str = Query(..., description="Entity type: IP, DOMAIN, HASH, etc."),
    source_value: str = Query(..., description="Observable value"),
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
) -> EntityFrequencyContext:
    return InvestigationPivotService.get_entity_frequency_context(
        db=db,
        source_type=source_type,
        source_value=source_value,
        workspace_id=x_workspace_id,
    )


# =============================================================================
# 4. AI-Assisted Pivot Recommendations
# =============================================================================

@router.get(
    "/recommendations",
    response_model=AIPivotRecommendationResponse,
    summary="Get explainable AI-assisted recommendations for the next logical investigative pivot",
)
def get_pivot_recommendations(
    source_type: str = Query(..., description="Source entity type"),
    source_value: str = Query(..., description="Observable value"),
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
) -> AIPivotRecommendationResponse:
    return InvestigationPivotService.get_pivot_recommendations(
        db=db,
        source_type=source_type,
        source_value=source_value,
        workspace_id=x_workspace_id,
    )


# =============================================================================
# 5. Analyst Hypothesis & Classification
# =============================================================================

@router.post(
    "/hypotheses",
    response_model=HypothesisResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Record an analyst hypothesis and classify evidence across pivoted entities",
)
def record_hypothesis(
    req: HypothesisRecordRequest,
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    x_user_id: Optional[str] = Header("analyst", alias="X-User-ID"),
    db: Session = Depends(get_db),
) -> HypothesisResponse:
    return InvestigationPivotService.record_hypothesis(
        db=db,
        req=req,
        workspace_id=x_workspace_id,
        user_id=x_user_id or "analyst",
    )


@router.get(
    "/hypotheses",
    response_model=List[HypothesisResponse],
    summary="List recorded analyst hypotheses for the current workspace or investigation",
)
def list_hypotheses(
    investigation_id: Optional[str] = Query(None, description="Optional investigation filter"),
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
) -> List[HypothesisResponse]:
    return InvestigationPivotService.list_hypotheses(
        db=db,
        workspace_id=x_workspace_id,
        investigation_id=investigation_id,
    )


# =============================================================================
# 6. Workflow Handoffs
# =============================================================================

@router.post(
    "/promote/investigation",
    response_model=PromoteToInvestigationResponse,
    summary="Promote selected pivot entities into an active or new Investigation",
)
def promote_to_investigation(
    req: PromoteToInvestigationRequest,
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    x_user_id: Optional[str] = Header("analyst", alias="X-User-ID"),
    db: Session = Depends(get_db),
) -> PromoteToInvestigationResponse:
    return InvestigationPivotService.promote_to_investigation(
        db=db,
        req=req,
        workspace_id=x_workspace_id,
        user_id=x_user_id or "analyst",
    )


@router.post(
    "/promote/watchlist",
    response_model=PromoteToWatchlistResponse,
    summary="Add selected pivot entities to Section 53 IOC Watchlist for continuous monitoring",
)
def promote_to_watchlist(
    req: PromoteToWatchlistRequest,
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    x_user_id: Optional[str] = Header("analyst", alias="X-User-ID"),
    db: Session = Depends(get_db),
) -> PromoteToWatchlistResponse:
    return InvestigationPivotService.promote_to_watchlist(
        db=db,
        req=req,
        workspace_id=x_workspace_id,
        user_id=x_user_id or "analyst",
    )


@router.post(
    "/to-hunt-query",
    response_model=PivotToHuntQueryResponse,
    summary="Transform selected pivot entities into a structured Section 54 Threat Hunt query",
)
def pivot_to_hunt_query(
    req: PivotToHuntQueryRequest,
) -> PivotToHuntQueryResponse:
    return InvestigationPivotService.pivot_to_hunt_query(req=req)
