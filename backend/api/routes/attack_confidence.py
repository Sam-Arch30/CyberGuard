"""
REST API endpoints for Section 18:
Attack Path Confidence & Explainability Engine.

Provides endpoints for:
- Path, stage, and transition confidence decompositions
- Confidence bottleneck reports
- Evidence-grounded explanations (stage, transition, path)
- Hypothesis comparison (no black-box ranking)
- Knowledge graph edge and cross-incident correlation explanations
- Report-ready explanations with strict epistemic safety
- Analyst disposition recording (preserving machine audit history)
"""
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Path, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
import json

from backend.db.session import get_db
from backend.db.models import (
    IncidentModel,
    AttackPathModel,
    AttackStageModel,
    AttackEdgeModel,
    AttackHypothesisModel,
    get_utc_now,
)
from backend.schemas.attack_confidence import (
    ConfidenceLevel,
    ConfidenceBreakdown,
    ConfidenceBottleneck,
    Explanation,
    HypothesisComparisonResult,
    ReportReadyExplanation,
)
from backend.services.attack_confidence_engine import AttackConfidenceEngine
from backend.services.attack_explanation_service import AttackExplanationService

router = APIRouter(tags=["Attack Path Confidence & Explainability"])


# ============================================================================
# REQUEST & RESPONSE MODELS
# ============================================================================

class CompareHypothesesRequest(BaseModel):
    hypothesis_a_id: str = Field(description="First hypothesis UUID")
    hypothesis_b_id: str = Field(description="Second hypothesis UUID")


class PathConfidenceResponse(BaseModel):
    path_id: str
    incident_id: str
    confidence_breakdown: ConfidenceBreakdown
    confidence_bottleneck: Optional[ConfidenceBottleneck] = None


class IncidentConfidenceResponse(BaseModel):
    incident_id: str
    path_id: Optional[str] = None
    confidence_breakdown: Optional[ConfidenceBreakdown] = None
    confidence_bottleneck: Optional[ConfidenceBottleneck] = None


class AnalystDispositionRequest(BaseModel):
    disposition: str = Field(description="CONFIRMED, REJECTED, MODIFIED, or PENDING")
    notes: Optional[str] = Field(default=None, description="Analyst justification and observations")
    reviewed_by: Optional[str] = Field(default=None, description="Analyst username or email")


def resolve_workspace(
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    workspace_id_query: str = Query("default", alias="workspace_id"),
) -> str:
    """Resolves workspace from header or query parameter for multi-tenant isolation."""
    return x_workspace_id or workspace_id_query or "default"


# ============================================================================
# INCIDENT LEVEL ENDPOINTS
# ============================================================================

@router.get(
    "/api/incidents/{incident_id}/confidence",
    response_model=IncidentConfidenceResponse,
    summary="Get confidence breakdown and bottleneck for incident reconstruction"
)
def get_incident_confidence(
    incident_id: str = Path(..., description="Incident UUID"),
    workspace_id: str = Depends(resolve_workspace),
    db: Session = Depends(get_db)
):
    """
    Evaluates and returns the multidimensional confidence breakdown and bottleneck
    for the primary reconstructed attack path of an incident.
    """
    incident = db.query(IncidentModel).filter(IncidentModel.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Incident {incident_id} not found.")

    path = db.query(AttackPathModel).filter(
        AttackPathModel.incident_id == incident_id,
        AttackPathModel.status == "CURRENT"
    ).order_by(AttackPathModel.confidence.desc()).first()

    if not path:
        return IncidentConfidenceResponse(incident_id=incident_id, path_id=None)

    stages = db.query(AttackStageModel).filter(AttackStageModel.attack_path_id == path.id).order_by(AttackStageModel.stage_order.asc()).all()
    edges = db.query(AttackEdgeModel).filter(AttackEdgeModel.attack_path_id == path.id).all()

    breakdown, bottleneck = AttackConfidenceEngine.score_path(
        path=path,
        stages=stages,
        edges=edges
    )

    return IncidentConfidenceResponse(
        incident_id=incident_id,
        path_id=path.id,
        confidence_breakdown=breakdown,
        confidence_bottleneck=bottleneck
    )


@router.get(
    "/api/incidents/{incident_id}/explanation",
    response_model=Explanation,
    summary="Get analyst-readable explanation for incident reconstructed attack path"
)
def get_incident_explanation(
    incident_id: str = Path(..., description="Incident UUID"),
    workspace_id: str = Depends(resolve_workspace),
    db: Session = Depends(get_db)
):
    """
    Returns full evidence-grounded explanation for the current reconstructed path.
    """
    path = db.query(AttackPathModel).filter(
        AttackPathModel.incident_id == incident_id,
        AttackPathModel.status == "CURRENT"
    ).order_by(AttackPathModel.confidence.desc()).first()

    if not path:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"No reconstructed path found for incident {incident_id}.")

    return AttackExplanationService.explain_attack_path(path_id=path.id, db=db)


@router.get(
    "/api/incidents/{incident_id}/report-explanation",
    response_model=ReportReadyExplanation,
    summary="Generate executive and technical report explanation with epistemic safety"
)
def get_incident_report_explanation(
    incident_id: str = Path(..., description="Incident UUID"),
    path_id: Optional[str] = Query(None, description="Optional specific path UUID"),
    workspace_id: str = Depends(resolve_workspace),
    db: Session = Depends(get_db)
):
    """
    Produces formatted report explanation suitable for PDF exports and management reviews.
    """
    return AttackExplanationService.generate_report_explanation(incident_id=incident_id, db=db, path_id=path_id)


@router.post(
    "/api/incidents/{incident_id}/compare-hypotheses",
    response_model=HypothesisComparisonResult,
    summary="Compare two competing attack hypotheses deterministically"
)
def compare_hypotheses_endpoint(
    req: CompareHypothesesRequest,
    incident_id: str = Path(..., description="Incident UUID"),
    workspace_id: str = Depends(resolve_workspace),
    db: Session = Depends(get_db)
):
    """
    Compares two competing attack hypotheses and explains why one outranks another.
    Eliminates opaque black-box scoring.
    """
    hyp_a = db.query(AttackHypothesisModel).filter(
        AttackHypothesisModel.id == req.hypothesis_a_id,
        AttackHypothesisModel.incident_id == incident_id
    ).first()
    if not hyp_a:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Hypothesis A {req.hypothesis_a_id} not found.")

    hyp_b = db.query(AttackHypothesisModel).filter(
        AttackHypothesisModel.id == req.hypothesis_b_id,
        AttackHypothesisModel.incident_id == incident_id
    ).first()
    if not hyp_b:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Hypothesis B {req.hypothesis_b_id} not found.")

    return AttackConfidenceEngine.compare_hypotheses(
        hypothesis_a=hyp_a,
        hypothesis_b=hyp_b
    )


# ============================================================================
# ATTACK PATH ENDPOINTS
# ============================================================================

@router.get(
    "/api/attack-paths/{path_id}/confidence",
    response_model=PathConfidenceResponse,
    summary="Get confidence breakdown and bottleneck for attack path"
)
def get_path_confidence(
    path_id: str = Path(..., description="AttackPath UUID"),
    workspace_id: str = Depends(resolve_workspace),
    db: Session = Depends(get_db)
):
    """
    Returns decomposed confidence components and identified bottleneck for an attack path.
    """
    path = db.query(AttackPathModel).filter(AttackPathModel.id == path_id).first()
    if not path:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Attack path {path_id} not found.")

    stages = db.query(AttackStageModel).filter(AttackStageModel.attack_path_id == path_id).order_by(AttackStageModel.stage_order.asc()).all()
    edges = db.query(AttackEdgeModel).filter(AttackEdgeModel.attack_path_id == path_id).all()

    breakdown, bottleneck = AttackConfidenceEngine.score_path(
        path=path,
        stages=stages,
        edges=edges
    )

    return PathConfidenceResponse(
        path_id=path.id,
        incident_id=path.incident_id,
        confidence_breakdown=breakdown,
        confidence_bottleneck=bottleneck
    )


@router.get(
    "/api/attack-paths/{path_id}/explanation",
    response_model=Explanation,
    summary="Get complete explanation for an attack path"
)
def get_path_explanation(
    path_id: str = Path(..., description="AttackPath UUID"),
    workspace_id: str = Depends(resolve_workspace),
    db: Session = Depends(get_db)
):
    """
    Returns evidence-grounded explanation for an attack path.
    """
    return AttackExplanationService.explain_attack_path(path_id=path_id, db=db)


@router.post(
    "/api/attack-paths/{path_id}/analyst-disposition",
    summary="Record analyst disposition on attack path without altering machine confidence history"
)
def record_path_analyst_disposition(
    req: AnalystDispositionRequest,
    path_id: str = Path(..., description="AttackPath UUID"),
    workspace_id: str = Depends(resolve_workspace),
    db: Session = Depends(get_db)
):
    """
    Records human analyst verdict and notes separately from algorithmic confidence.
    """
    path = db.query(AttackPathModel).filter(AttackPathModel.id == path_id).first()
    if not path:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Attack path {path_id} not found.")

    path.analyst_disposition = req.disposition
    path.analyst_notes = req.notes
    path.reviewed_by = req.reviewed_by or "analyst"
    path.reviewed_at = get_utc_now()
    db.commit()

    return {
        "status": "success",
        "path_id": path.id,
        "analyst_disposition": path.analyst_disposition,
        "reviewed_at": path.reviewed_at.isoformat()
    }


# ============================================================================
# STAGE & TRANSITION ENDPOINTS
# ============================================================================

@router.get(
    "/api/attack-stages/{stage_id}/confidence",
    response_model=ConfidenceBreakdown,
    summary="Get confidence breakdown for individual attack stage"
)
def get_stage_confidence(
    stage_id: str = Path(..., description="AttackStage UUID"),
    workspace_id: str = Depends(resolve_workspace),
    db: Session = Depends(get_db)
):
    """
    Returns 10-dimension confidence decomposition for an attack stage.
    """
    stage = db.query(AttackStageModel).filter(AttackStageModel.id == stage_id).first()
    if not stage:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Attack stage {stage_id} not found.")

    return AttackConfidenceEngine.score_stage(stage=stage)


@router.get(
    "/api/attack-stages/{stage_id}/explanation",
    response_model=Explanation,
    summary="Get evidence-grounded explanation for attack stage"
)
def get_stage_explanation(
    stage_id: str = Path(..., description="AttackStage UUID"),
    workspace_id: str = Depends(resolve_workspace),
    db: Session = Depends(get_db)
):
    """
    Returns explanation detailing why a stage exists and what evidence grounds it.
    """
    return AttackExplanationService.explain_stage(stage_id=stage_id, db=db)


@router.post(
    "/api/attack-stages/{stage_id}/analyst-disposition",
    summary="Record analyst disposition on attack stage without altering machine confidence"
)
def record_stage_analyst_disposition(
    req: AnalystDispositionRequest,
    stage_id: str = Path(..., description="AttackStage UUID"),
    workspace_id: str = Depends(resolve_workspace),
    db: Session = Depends(get_db)
):
    """
    Records analyst feedback for an attack stage.
    """
    stage = db.query(AttackStageModel).filter(AttackStageModel.id == stage_id).first()
    if not stage:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Attack stage {stage_id} not found.")

    stage.analyst_disposition = req.disposition
    stage.analyst_notes = req.notes
    db.commit()

    return {
        "status": "success",
        "stage_id": stage.id,
        "analyst_disposition": stage.analyst_disposition
    }


@router.get(
    "/api/attack-edges/{edge_id}/confidence",
    response_model=ConfidenceBreakdown,
    summary="Get confidence breakdown for attack transition edge"
)
def get_edge_confidence(
    edge_id: str = Path(..., description="AttackEdge UUID"),
    workspace_id: str = Depends(resolve_workspace),
    db: Session = Depends(get_db)
):
    """
    Returns confidence breakdown for a directed transition edge.
    """
    edge = db.query(AttackEdgeModel).filter(AttackEdgeModel.id == edge_id).first()
    if not edge:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Attack edge {edge_id} not found.")

    from_stage = db.query(AttackStageModel).filter(AttackStageModel.id == edge.from_stage_id).first()
    to_stage = db.query(AttackStageModel).filter(AttackStageModel.id == edge.to_stage_id).first()

    return AttackConfidenceEngine.score_transition(
        from_stage=from_stage,
        to_stage=to_stage,
        edge_model=edge
    )


@router.get(
    "/api/attack-edges/{edge_id}/explanation",
    response_model=Explanation,
    summary="Get explanation for attack transition edge"
)
def get_edge_explanation(
    edge_id: str = Path(..., description="AttackEdge UUID"),
    workspace_id: str = Depends(resolve_workspace),
    db: Session = Depends(get_db)
):
    """
    Explains why two stages are connected and reports gaps or speculative links.
    """
    return AttackExplanationService.explain_transition(edge_id=edge_id, db=db)


# ============================================================================
# KNOWLEDGE GRAPH & CROSS-INCIDENT CORRELATION EXPLANATIONS
# ============================================================================

@router.get(
    "/api/relationships/{relationship_id}/explanation",
    summary="Explain Knowledge Graph entity relationship from sensor observations (Section 14)"
)
def get_relationship_explanation(
    relationship_id: str = Path(..., description="Relationship UUID"),
    workspace_id: str = Depends(resolve_workspace),
    db: Session = Depends(get_db)
):
    """
    Explains an edge in the Security Knowledge Graph citing sensor observations and timestamps.
    """
    return AttackExplanationService.explain_entity_relationship(relationship_id=relationship_id, db=db)


@router.get(
    "/api/correlations/{correlation_id}/explanation",
    summary="Explain cross-incident campaign correlation (Section 15)"
)
def get_correlation_explanation(
    correlation_id: str = Path(..., description="IncidentCorrelation UUID"),
    workspace_id: str = Depends(resolve_workspace),
    db: Session = Depends(get_db)
):
    """
    Explains pairwise cross-incident correlation citing shared indicators and heuristics.
    """
    return AttackExplanationService.explain_cross_incident(correlation_id=correlation_id, db=db)
