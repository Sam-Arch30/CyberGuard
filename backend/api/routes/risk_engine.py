"""
REST API Endpoints for Section 26: Unified Risk Engine.

Mounts routes under /api/v1/risk:
- GET  /api/v1/risk/assessments/{id}            : Retrieve risk assessment by ID
- GET  /api/v1/risk/assessments/{id}/history    : Reassessment version history
- GET  /api/v1/risk/assessments/{id}/breakdown  : Detailed component contributor breakdown
- GET  /api/v1/risk/assessments/{id}/explanation: Structured explainability payload
- POST /api/v1/risk/evaluate                   : Deterministic evaluation for scope or raw signals
- POST /api/v1/risk/reassess/{id}              : Reassess assessment with new evidence (creates v(N+1))
- GET  /api/v1/risk/config                     : Active risk configuration
- POST /api/v1/risk/config                     : Update versioned risk configuration (admin only)
- GET  /api/v1/risk/dashboard/stats            : Executive risk metrics and distribution
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.db.models import RiskAssessmentModel, RiskConfigurationModel, generate_uuid, get_utc_now
from backend.schemas.risk_engine import (
    ConfidenceLevel,
    EvidenceFamily,
    RiskAssessmentCreate,
    RiskAssessmentHistoryResponse,
    RiskAssessmentResponse,
    RiskComponent,
    RiskConfigurationSchema,
    RiskContradiction,
    RiskDashboardStats,
    RiskEvaluationRequest,
    RiskExplanation,
    RiskLevel,
    RiskReassessRequest,
    RiskScope,
    RiskSeverityEnum,
    RiskSignalResponse,
    SignalDirection,
    SignalSemantics,
    UncertaintyLevel,
)
from backend.services.risk_engine_service import (
    RiskConfigurationManager,
    RiskEngineService,
)

logger = logging.getLogger("cyberguard.api.risk_engine")

router = APIRouter(prefix="/api/v1/risk", tags=["Unified Risk Engine"])


# ============================================================================
# AUTHORIZATION DEPENDENCY
# ============================================================================

def verify_risk_role(
    x_role: Optional[str] = Header(None, alias="X-Role"),
    x_user_role: Optional[str] = Header(None, alias="X-User-Role"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
) -> str:
    """Enforces role-based authorization for risk engine operations."""
    role = (x_role or x_user_role or "").strip().lower()
    if not role and authorization:
        auth_clean = authorization.strip().lower()
        if "admin" in auth_clean:
            role = "admin"
        elif "analyst" in auth_clean:
            role = "analyst"
        elif "security_engineer" in auth_clean:
            role = "security_engineer"
        elif "bearer" in auth_clean:
            role = "analyst"

    if not role:
        role = "analyst"  # Default developer / test role

    return role


def require_admin(role: str = Depends(verify_risk_role)) -> str:
    if role not in ("admin", "superuser", "security_lead"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrative privileges required to modify risk configuration.",
        )
    return role


# ============================================================================
# ASSESSMENT ENDPOINTS
# ============================================================================

@router.get("/assessments/{assessment_id}", response_model=RiskAssessmentResponse, summary="Retrieve risk assessment by ID")
def get_risk_assessment(
    assessment_id: str,
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_risk_role),
):
    record = db.query(RiskAssessmentModel).filter(
        RiskAssessmentModel.workspace_id == workspace_id,
        RiskAssessmentModel.id == assessment_id,
    ).first()
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Risk assessment '{assessment_id}' not found.")

    return _to_response_model(record)


@router.get("/assessments/{assessment_id}/history", response_model=RiskAssessmentHistoryResponse, summary="Retrieve assessment version lineage")
def get_risk_assessment_history(
    assessment_id: str,
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_risk_role),
):
    try:
        versions = RiskEngineService.get_assessment_history(db, assessment_id, workspace_id)
        current = next((v for v in versions if v.id == assessment_id), versions[-1] if versions else None)
        if not current:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment not found.")

        return RiskAssessmentHistoryResponse(
            assessment_id=assessment_id,
            scope_type=RiskScope(current.scope_type),
            scope_id=current.scope_id,
            current_version=current.version,
            history=[_to_response_model(v) for v in versions],
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


@router.get("/assessments/{assessment_id}/breakdown", response_model=List[RiskComponent], summary="Retrieve structured component contributors")
def get_risk_breakdown(
    assessment_id: str,
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_risk_role),
):
    record = db.query(RiskAssessmentModel).filter(
        RiskAssessmentModel.workspace_id == workspace_id,
        RiskAssessmentModel.id == assessment_id,
    ).first()
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Risk assessment '{assessment_id}' not found.")

    components_raw = record.components
    return [RiskComponent(**c) for c in components_raw]


@router.get("/assessments/{assessment_id}/explanation", response_model=RiskExplanation, summary="Retrieve structured explainability report")
def get_risk_explanation(
    assessment_id: str,
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_risk_role),
):
    record = db.query(RiskAssessmentModel).filter(
        RiskAssessmentModel.workspace_id == workspace_id,
        RiskAssessmentModel.id == assessment_id,
    ).first()
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Risk assessment '{assessment_id}' not found.")

    components = [RiskComponent(**c) for c in record.components]
    contradictions = [RiskContradiction(**c) for c in record.contradictions]

    return RiskExplanation(
        summary=record.explanation_summary or f"Risk Score {record.risk_score} classified as {record.risk_level}.",
        risk_level=RiskLevel(record.risk_level),
        risk_score=record.risk_score,
        severity=RiskSeverityEnum(record.severity),
        confidence=record.confidence,
        uncertainty=UncertaintyLevel(record.uncertainty),
        top_contributors=components[:5],
        supporting_evidence=[{"ref": ref} for ref in record.evidence_refs],
        counter_evidence=[{"ref": ref} for ref in record.counter_evidence_refs],
        contradictions=contradictions,
        uncertainty_factors=record.limitations,
        contextual_factors=record.contextual_factors,
        limitations=record.limitations,
    )


# ============================================================================
# EVALUATION & REASSESSMENT
# ============================================================================

@router.post("/evaluate", response_model=RiskAssessmentResponse, status_code=status.HTTP_201_CREATED, summary="Evaluate risk deterministically")
def evaluate_risk(
    request: RiskEvaluationRequest,
    db: Session = Depends(get_db),
    _role: str = Depends(verify_risk_role),
):
    """
    Evaluates risk deterministically for an EVENT, INVESTIGATION, or INCIDENT scope.
    """
    try:
        if request.scope_type == RiskScope.EVENT:
            assessment = RiskEngineService.evaluate_threat_event(
                db=db,
                threat_event_id=request.scope_id,
                workspace_id=request.workspace_id,
                additional_signals=request.additional_signals,
                context_metadata=request.context_metadata,
            )
        elif request.scope_type == RiskScope.INVESTIGATION:
            assessment = RiskEngineService.evaluate_investigation(
                db=db,
                investigation_id=request.scope_id,
                workspace_id=request.workspace_id,
                context_metadata=request.context_metadata,
            )
        elif request.scope_type == RiskScope.INCIDENT:
            assessment = RiskEngineService.evaluate_incident(
                db=db,
                incident_id=request.scope_id,
                workspace_id=request.workspace_id,
                context_metadata=request.context_metadata,
            )
        else:
            # Fallback direct evaluation of signals
            cfg = RiskConfigurationManager.load_active_config(db, request.workspace_id)
            eval_res = RiskEngineService.evaluate_signals(
                signals=request.additional_signals,
                context_metadata=request.context_metadata,
                config=cfg,
            )
            now = get_utc_now()
            assessment = RiskAssessmentModel(
                id=generate_uuid(),
                workspace_id=request.workspace_id,
                scope_type=request.scope_type.value,
                scope_id=request.scope_id,
                risk_score=eval_res["risk_score"],
                risk_level=eval_res["risk_level"].value,
                severity=eval_res["severity"].value,
                confidence=eval_res["confidence"],
                confidence_level=eval_res["confidence_level"].value,
                uncertainty=eval_res["uncertainty"].value,
                uncertainty_score=eval_res["uncertainty_score"],
                version=1,
                status="CURRENT",
                aggregation_version=eval_res["aggregation_version"],
                configuration_version=eval_res["configuration_version"],
                components_json=json.dumps([c.model_dump() for c in eval_res["components"]]),
                signals_json=json.dumps(eval_res["normalized_signals"]),
                evidence_refs_json=json.dumps(eval_res["evidence_refs"]),
                counter_evidence_refs_json=json.dumps(eval_res["counter_evidence_refs"]),
                contradictions_json=json.dumps([c.model_dump() for c in eval_res["contradictions"]]),
                limitations_json=json.dumps(eval_res["limitations"]),
                contextual_factors_json=json.dumps(eval_res["contextual_factors"]),
                explanation_summary=eval_res["explanation_summary"],
                created_by="system",
                created_at=now,
                evaluated_at=now,
            )
            db.add(assessment)
            db.commit()
            db.refresh(assessment)

        return _to_response_model(assessment)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
        logger.error(f"Error evaluating risk: {exc}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.post("/reassess/{assessment_id}", response_model=RiskAssessmentResponse, summary="Trigger deterministic reassessment with new evidence")
def reassess_risk(
    assessment_id: str,
    request: RiskReassessRequest,
    db: Session = Depends(get_db),
    _role: str = Depends(verify_risk_role),
):
    """
    Executes immutable reassessment:
    Marks prior version SUPERSEDED and creates incremented version v(N+1).
    """
    try:
        reassessed = RiskEngineService.reassess_assessment(
            db=db,
            assessment_id=assessment_id,
            workspace_id=request.workspace_id,
            request=request,
        )
        return _to_response_model(reassessed)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except Exception as exc:
        logger.error(f"Error reassessing risk: {exc}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


# ============================================================================
# CONFIGURATION & DASHBOARD
# ============================================================================

@router.get("/config", response_model=RiskConfigurationSchema, summary="Retrieve active risk configuration")
def get_risk_config(
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_risk_role),
):
    cfg = RiskConfigurationManager.load_active_config(db, workspace_id)
    return RiskConfigurationSchema(**cfg)


@router.post("/config", response_model=RiskConfigurationSchema, status_code=status.HTTP_201_CREATED, summary="Create or update versioned risk configuration")
def update_risk_config(
    new_config: RiskConfigurationSchema,
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db),
    _admin: str = Depends(require_admin),
):
    """Requires elevated admin permissions. Updates versioned configuration in DB."""
    # Retire existing active configs for this workspace
    db.query(RiskConfigurationModel).filter(
        RiskConfigurationModel.workspace_id == workspace_id,
        RiskConfigurationModel.status == "ACTIVE"
    ).update({"status": "RETIRED"})

    now = get_utc_now()
    cfg_record = RiskConfigurationModel(
        id=generate_uuid(),
        workspace_id=workspace_id,
        version=new_config.version,
        status="ACTIVE",
        thresholds_json=json.dumps(new_config.thresholds),
        confidence_levels_json=json.dumps(new_config.confidence_levels),
        uncertainty_levels_json=json.dumps(new_config.uncertainty_levels),
        family_caps_json=json.dumps(new_config.family_caps),
        family_weights_json=json.dumps(new_config.family_weights),
        correlation_discount_schedule_json=json.dumps(new_config.correlation_discount_schedule),
        reliability_defaults_json=json.dumps(new_config.reliability_defaults),
        contextual_modifiers_json=json.dumps(new_config.contextual_modifiers),
        severity_rules_json=json.dumps(new_config.severity_rules),
        created_by=_admin,
        description="Updated via admin API",
        created_at=now,
        updated_at=now,
    )
    db.add(cfg_record)
    db.commit()
    db.refresh(cfg_record)

    loaded = RiskConfigurationManager.load_active_config(db, workspace_id)
    return RiskConfigurationSchema(**loaded)


@router.get("/dashboard/stats", response_model=RiskDashboardStats, summary="Retrieve executive risk statistics")
def get_dashboard_stats(
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_risk_role),
):
    return RiskEngineService.get_dashboard_stats(db, workspace_id)


# ============================================================================
# HELPER MAPPERS
# ============================================================================

def _to_response_model(record: RiskAssessmentModel) -> RiskAssessmentResponse:
    components = [RiskComponent(**c) for c in record.components]
    contradictions = [RiskContradiction(**c) for c in record.contradictions]

    signals_resp = []
    if record.signals:
        for s in record.signals:
            signals_resp.append(
                RiskSignalResponse(
                    id=s.id,
                    assessment_id=s.assessment_id,
                    signal_type=s.signal_type,
                    source_type=s.source_type,
                    detector_id=s.detector_id,
                    detector_version=s.detector_version,
                    evidence_family=EvidenceFamily(s.evidence_family),
                    semantics=SignalSemantics(s.semantics),
                    direction=SignalDirection(s.direction),
                    raw_score=s.raw_score,
                    normalized_score=s.normalized_score,
                    reliability=s.reliability,
                    weight=s.weight,
                    contribution=s.contribution,
                    correlation_group=s.correlation_group,
                    evidence_refs=s.evidence_refs,
                    provenance=s.provenance,
                    created_at=s.created_at,
                )
            )

    return RiskAssessmentResponse(
        id=record.id,
        workspace_id=record.workspace_id,
        scope_type=RiskScope(record.scope_type),
        scope_id=record.scope_id,
        threat_event_id=record.threat_event_id,
        investigation_id=record.investigation_id,
        incident_id=record.incident_id,
        analysis_run_id=record.analysis_run_id,
        risk_score=record.risk_score,
        risk_level=RiskLevel(record.risk_level),
        severity=RiskSeverityEnum(record.severity),
        confidence=record.confidence,
        confidence_level=ConfidenceLevel(record.confidence_level),
        uncertainty=UncertaintyLevel(record.uncertainty),
        uncertainty_score=record.uncertainty_score,
        version=record.version,
        status=record.status,
        parent_assessment_id=record.parent_assessment_id,
        aggregation_version=record.aggregation_version,
        configuration_version=record.configuration_version,
        components=components,
        signals=signals_resp,
        evidence_refs=record.evidence_refs,
        counter_evidence_refs=record.counter_evidence_refs,
        contradictions=contradictions,
        limitations=record.limitations,
        contextual_factors=record.contextual_factors,
        explanation_summary=record.explanation_summary,
        created_by=record.created_by,
        reassessment_reason=record.reassessment_reason,
        created_at=record.created_at,
        evaluated_at=record.evaluated_at,
    )
