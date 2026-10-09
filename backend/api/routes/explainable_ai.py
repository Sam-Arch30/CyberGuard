"""
REST API Endpoints for Section 27: Explainable AI (XAI).

Mounts routes under /api/v1/explanation:
- GET  /api/v1/explanation/{scope_type}/{scope_id}                 : Full structured explanation response
- GET  /api/v1/explanation/{scope_type}/{scope_id}/layers/{layer}  : Progressive disclosure layer (1..4)
- GET  /api/v1/explanation/{scope_type}/{scope_id}/graph           : Interactive evidence graph
- GET  /api/v1/explanation/{scope_type}/{scope_id}/evidence-chain  : Traceable claim chain
- GET  /api/v1/explanation/{scope_type}/{scope_id}/contributors    : Contributors & detector attribution
- GET  /api/v1/explanation/{scope_type}/{scope_id}/contradictions  : Contradictions & counter-evidence
- GET  /api/v1/explanation/{scope_type}/{scope_id}/uncertainty     : Uncertainty, gaps, & what-would-change
- GET  /api/v1/explanation/{scope_type}/{scope_id}/metrics         : Explainability quality metrics
- POST /api/v1/explanation/{scope_type}/{scope_id}/feedback        : Analyst feedback recording
- POST /api/v1/explanation/{scope_type}/{scope_id}/generate-narrative : LLM narrative with validation & fallback
- GET  /api/v1/explanation/{scope_type}/{scope_id}/snapshots       : Historical snapshots
- POST /api/v1/explanation/{scope_type}/{scope_id}/snapshots       : Create immutable snapshot
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.db.models import (
    ExplanationFeedbackModel,
    ExplanationModel,
    ExplanationSnapshotModel,
    generate_uuid,
    get_utc_now,
)
from backend.schemas.explainable_ai import (
    ContradictionRecord,
    CounterEvidenceItem,
    DetectorContribution,
    EvidenceGraph,
    ExplanationFeedbackCreate,
    ExplanationFeedbackResponse,
    ExplanationLayer,
    ExplanationQualityMetrics,
    ExplanationResponse,
    ExplanationScope,
    ExplanationSnapshotResponse,
    ExplanationUnit,
    NarrativeGenerationRequest,
    NarrativeGenerationResponse,
)
from backend.services.explanation_composer import ExplanationComposer
from backend.services.llm_explanation_service import LLMExplanationService

logger = logging.getLogger("cyberguard.api.xai")

router = APIRouter(prefix="/api/v1/explanation", tags=["Explainable AI (XAI)"])


def verify_analyst_role(
    x_role: Optional[str] = Header(None, alias="X-Role"),
    x_user_role: Optional[str] = Header(None, alias="X-User-Role"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
) -> str:
    role = (x_role or x_user_role or "").strip().lower()
    if not role and authorization:
        auth_clean = authorization.strip().lower()
        if "admin" in auth_clean:
            role = "admin"
        elif "analyst" in auth_clean:
            role = "analyst"
    return role or "analyst"


# ============================================================================
# EXPLANATION RETRIEVAL & PROGRESSIVE DISCLOSURE
# ============================================================================

@router.get("/{scope_type}/{scope_id}", response_model=ExplanationResponse, summary="Retrieve complete structured explanation")
def get_explanation(
    scope_type: str,
    scope_id: str,
    workspace_id: str = Query("default"),
    force_refresh: bool = Query(False),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_analyst_role),
):
    try:
        expl_model = ExplanationComposer.compose_explanation(
            db=db,
            scope_type=scope_type,
            scope_id=scope_id,
            workspace_id=workspace_id,
            force_refresh=force_refresh,
        )
        return ExplanationComposer.to_response_model(expl_model, db)
    except Exception as exc:
        logger.error(f"Error composing explanation for {scope_type}/{scope_id}: {exc}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.get("/{scope_type}/{scope_id}/layers/{layer_level}", summary="Retrieve explanation at specified progressive disclosure depth")
def get_explanation_layer(
    scope_type: str,
    scope_id: str,
    layer_level: str,
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_analyst_role),
):
    try:
        norm_layer = layer_level.upper()
        layer_enum = ExplanationLayer(norm_layer)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid layer '{layer_level}'. Must be one of: EXECUTIVE, ANALYST, INVESTIGATOR, FORENSIC",
        )

    expl_model = ExplanationComposer.compose_explanation(
        db=db, scope_type=scope_type, scope_id=scope_id, workspace_id=workspace_id
    )
    resp = ExplanationComposer.to_response_model(expl_model, db)

    if layer_enum == ExplanationLayer.EXECUTIVE:
        return {
            "scope_type": resp.scope_type,
            "scope_id": resp.scope_id,
            "layer": "EXECUTIVE",
            "risk_score": resp.risk_score,
            "risk_level": resp.risk_level,
            "severity": resp.severity,
            "confidence_level": resp.confidence_level,
            "summary": resp.executive_summary,
            "top_reasons": [u.claim for u in resp.explanation_units[:3]],
        }

    elif layer_enum == ExplanationLayer.ANALYST:
        return {
            "scope_type": resp.scope_type,
            "scope_id": resp.scope_id,
            "layer": "ANALYST",
            "risk_score": resp.risk_score,
            "risk_level": resp.risk_level,
            "severity": resp.severity,
            "confidence": resp.confidence,
            "confidence_level": resp.confidence_level,
            "uncertainty": resp.uncertainty,
            "summary": resp.analyst_summary,
            "contributors": resp.contributors,
            "counter_evidence": resp.counter_evidence,
            "contradictions": resp.contradictions,
            "assessment_change_guidance": resp.assessment_change_guidance,
        }

    elif layer_enum == ExplanationLayer.INVESTIGATOR:
        return {
            "scope_type": resp.scope_type,
            "scope_id": resp.scope_id,
            "layer": "INVESTIGATOR",
            "explanation_units": resp.explanation_units,
            "evidence_groups": resp.evidence_groups,
            "mitre_explanations": resp.mitre_explanations,
            "attack_path_explanation": resp.attack_path_explanation,
            "detector_contributions": resp.detector_contributions,
            "rule_contributions": resp.rule_contributions,
            "investigator_details": resp.investigator_details,
        }

    else:  # FORENSIC
        return {
            "scope_type": resp.scope_type,
            "scope_id": resp.scope_id,
            "layer": "FORENSIC",
            "explanation_id": resp.id,
            "explanation_version": resp.explanation_version,
            "risk_assessment_id": resp.risk_assessment_id,
            "evidence_graph": resp.evidence_graph,
            "forensic_details": resp.forensic_details,
            "provenance": resp.provenance,
            "source_snapshot": expl_model.source_snapshot,
            "created_at": resp.created_at,
        }


@router.get("/{scope_type}/{scope_id}/graph", response_model=EvidenceGraph, summary="Retrieve interactive evidence graph")
def get_evidence_graph(
    scope_type: str,
    scope_id: str,
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_analyst_role),
):
    expl_model = ExplanationComposer.compose_explanation(
        db=db, scope_type=scope_type, scope_id=scope_id, workspace_id=workspace_id
    )
    resp = ExplanationComposer.to_response_model(expl_model, db)
    return resp.evidence_graph


@router.get("/{scope_type}/{scope_id}/evidence-chain", response_model=List[ExplanationUnit], summary="Retrieve ordered claim evidence chain")
def get_evidence_chain(
    scope_type: str,
    scope_id: str,
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_analyst_role),
):
    expl_model = ExplanationComposer.compose_explanation(
        db=db, scope_type=scope_type, scope_id=scope_id, workspace_id=workspace_id
    )
    resp = ExplanationComposer.to_response_model(expl_model, db)
    return resp.explanation_units


@router.get("/{scope_type}/{scope_id}/contributors", summary="Retrieve risk contributors, detectors, and rules")
def get_contributors(
    scope_type: str,
    scope_id: str,
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_analyst_role),
):
    expl_model = ExplanationComposer.compose_explanation(
        db=db, scope_type=scope_type, scope_id=scope_id, workspace_id=workspace_id
    )
    resp = ExplanationComposer.to_response_model(expl_model, db)
    return {
        "risk_score": resp.risk_score,
        "contributors": resp.contributors,
        "detectors": resp.detector_contributions,
        "rules": resp.rule_contributions,
        "models": resp.model_contributions,
    }


@router.get("/{scope_type}/{scope_id}/contradictions", summary="Retrieve counter-evidence and contradictions")
def get_contradictions(
    scope_type: str,
    scope_id: str,
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_analyst_role),
):
    expl_model = ExplanationComposer.compose_explanation(
        db=db, scope_type=scope_type, scope_id=scope_id, workspace_id=workspace_id
    )
    resp = ExplanationComposer.to_response_model(expl_model, db)
    return {
        "counter_evidence": resp.counter_evidence,
        "contradictions": resp.contradictions,
    }


@router.get("/{scope_type}/{scope_id}/uncertainty", summary="Retrieve uncertainty factors, gaps, limitations and change guidance")
def get_uncertainty(
    scope_type: str,
    scope_id: str,
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_analyst_role),
):
    expl_model = ExplanationComposer.compose_explanation(
        db=db, scope_type=scope_type, scope_id=scope_id, workspace_id=workspace_id
    )
    resp = ExplanationComposer.to_response_model(expl_model, db)
    return {
        "uncertainty_level": resp.uncertainty,
        "unknowns": resp.uncertainty_items,
        "missing_information": resp.missing_information,
        "limitations": resp.limitations,
        "what_would_change": resp.assessment_change_guidance,
    }


@router.get("/{scope_type}/{scope_id}/metrics", response_model=ExplanationQualityMetrics, summary="Retrieve internal explainability quality metrics")
def get_quality_metrics(
    scope_type: str,
    scope_id: str,
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_analyst_role),
):
    expl_model = ExplanationComposer.compose_explanation(
        db=db, scope_type=scope_type, scope_id=scope_id, workspace_id=workspace_id
    )
    resp = ExplanationComposer.to_response_model(expl_model, db)
    return LLMExplanationService.compute_quality_metrics(resp)


# ============================================================================
# NARRATIVE GENERATION & ANALYST FEEDBACK
# ============================================================================

@router.post("/{scope_type}/{scope_id}/generate-narrative", response_model=NarrativeGenerationResponse, summary="Synthesize grounded narrative with validation")
async def generate_narrative(
    scope_type: str,
    scope_id: str,
    request: Optional[NarrativeGenerationRequest] = None,
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_analyst_role),
):
    req = request or NarrativeGenerationRequest(scope_id=scope_id, scope_type=ExplanationScope(scope_type.upper()))
    expl_model = ExplanationComposer.compose_explanation(
        db=db, scope_type=scope_type, scope_id=scope_id, workspace_id=workspace_id
    )
    resp = ExplanationComposer.to_response_model(expl_model, db)

    llm_service = LLMExplanationService()
    narrative_resp = await llm_service.generate_grounded_narrative(
        explanation=resp,
        detail_level=req.detail_level,
        strict_validation=req.strict_validation,
    )
    return narrative_resp


@router.post("/{scope_type}/{scope_id}/feedback", response_model=ExplanationFeedbackResponse, status_code=status.HTTP_201_CREATED, summary="Record analyst feedback")
def record_feedback(
    scope_type: str,
    scope_id: str,
    feedback: ExplanationFeedbackCreate,
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_analyst_role),
):
    expl_model = ExplanationComposer.compose_explanation(
        db=db, scope_type=scope_type, scope_id=scope_id, workspace_id=workspace_id
    )
    fb = ExplanationComposer.record_feedback(
        db=db,
        explanation_id=expl_model.id,
        analyst_id=feedback.analyst_id,
        feedback_type=feedback.feedback_type.value,
        notes=feedback.notes,
        target_claim_id=feedback.target_claim_id,
        correction_payload=feedback.correction_payload,
        workspace_id=workspace_id,
    )
    return fb


# ============================================================================
# SNAPSHOTS
# ============================================================================

@router.get("/{scope_type}/{scope_id}/snapshots", response_model=List[ExplanationSnapshotResponse], summary="List historical snapshots")
def list_snapshots(
    scope_type: str,
    scope_id: str,
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_analyst_role),
):
    snapshots = db.query(ExplanationSnapshotModel).filter(
        ExplanationSnapshotModel.workspace_id == workspace_id,
        ExplanationSnapshotModel.scope_type == scope_type.upper(),
        ExplanationSnapshotModel.scope_id == scope_id,
    ).order_by(ExplanationSnapshotModel.created_at.desc()).all()

    return snapshots


@router.post("/{scope_type}/{scope_id}/snapshots", response_model=ExplanationSnapshotResponse, status_code=status.HTTP_201_CREATED, summary="Create immutable forensic snapshot")
def create_snapshot(
    scope_type: str,
    scope_id: str,
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_analyst_role),
):
    expl_model = ExplanationComposer.compose_explanation(
        db=db, scope_type=scope_type, scope_id=scope_id, workspace_id=workspace_id
    )
    snapshot = ExplanationComposer.create_snapshot(db, explanation_id=expl_model.id, workspace_id=workspace_id)
    return snapshot
