"""
Cross-Email Investigation Workspace API Endpoints.
Provides correlation discovery, 2-5 email comparison matrix, focused relationship graph,
attack timeline, and persisted false-positive feedback handling.
"""
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.services.cross_email_workspace_service import global_cross_email_workspace_service
from backend.schemas.cross_email_workspace import (
    CrossEmailAnalysisResponse,
    CompareEmailsRequest,
    ComparisonMatrixResponse,
    AnalystDecisionRequest,
    AnalystDecisionItem,
    CrossEmailGraphFilterRequest
)
from backend.schemas.graph import InvestigationGraphResponse

router = APIRouter(prefix="/api/cross-investigation", tags=["Cross-Email Investigation Workspace"])


@router.post(
    "/analyze",
    response_model=CrossEmailAnalysisResponse,
    summary="Discover cross-email relationships for an analyzed email",
    description="Extracts forensic fingerprint, queries inverted indicator index, ranks related messages, and formulates relationship explanations."
)
def analyze_cross_email_correlations_endpoint(
    email_data: Dict[str, Any],
    db: Session = Depends(get_db)
):
    if email_data.get("is_demo") or email_data.get("is_synthetic"):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Demo/synthetic evidence cannot contaminate normal production investigation workspace."
        )

    try:
        return global_cross_email_workspace_service.analyze_cross_email_correlations(
            email_data=email_data,
            db=db
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to execute cross-email correlation analysis: {str(exc)}"
        )


@router.post(
    "/compare",
    response_model=ComparisonMatrixResponse,
    summary="Side-by-side comparison matrix for 2 to 5 emails",
    description="Compares 2 to 5 emails across 10 dimensions, highlighting identical, similar, conflicting, and unique evidence."
)
def compare_emails_endpoint(
    request: CompareEmailsRequest,
    db: Session = Depends(get_db)
):
    try:
        return global_cross_email_workspace_service.compare_emails_matrix(
            email_ids=request.email_ids,
            current_email=request.current_email,
            db=db
        )
    except KeyError as key_err:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(key_err)
        )
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(val_err)
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate email comparison matrix: {str(exc)}"
        )


@router.post(
    "/graph",
    response_model=InvestigationGraphResponse,
    summary="Focused cross-email investigation graph",
    description="Builds an investigation relationship graph connecting selected emails to shared URLs, IPs, ASNs, Domains, and Campaigns."
)
def get_cross_email_graph_endpoint(
    request: CrossEmailGraphFilterRequest
):
    try:
        return global_cross_email_workspace_service.build_cross_email_graph(
            email_ids=request.email_ids,
            allowed_types=request.node_types
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate cross-email investigation graph: {str(exc)}"
        )


@router.post(
    "/decision",
    response_model=AnalystDecisionItem,
    summary="Record analyst decision or false-positive feedback",
    description="Persists analyst decisions (mark unrelated, add to case, assign campaign, escalate) to guide correlation engine."
)
def record_analyst_decision_endpoint(
    request: AnalystDecisionRequest,
    db: Session = Depends(get_db)
):
    try:
        return global_cross_email_workspace_service.record_analyst_decision(
            db=db,
            email_id_a=request.email_id_a,
            email_id_b=request.email_id_b,
            decision=request.decision,
            campaign_id=request.campaign_id,
            case_id=request.case_id,
            analyst=request.analyst or "SOC Analyst",
            notes=request.notes
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to record analyst decision: {str(exc)}"
        )


@router.get(
    "/decisions",
    response_model=List[AnalystDecisionItem],
    summary="List persisted analyst correlation decisions",
    description="Returns recorded analyst decisions and false-positive suppressions."
)
def list_analyst_decisions_endpoint(
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db)
):
    try:
        return global_cross_email_workspace_service.list_analyst_decisions(db=db, limit=limit)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list analyst decisions: {str(exc)}"
        )
