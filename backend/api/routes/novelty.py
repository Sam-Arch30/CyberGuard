"""
Novelty Detection & Emerging-Threat Identification REST API Endpoints (Section 22).

Exposes routes for evaluating pattern novelty, querying incident and entity novelty,
inspecting structural patterns, event sequences, infrastructure unfamiliarity,
tracking emerging pattern lifecycle transitions, and managing contextual suppressions.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.schemas.novelty_detection import (
    EmergingPatternCandidate,
    EmergingPatternStatus,
    EmergingStatusTransitionRequest,
    NoveltyAssessment,
    NoveltyEvaluationRequest,
    NoveltyEvaluationResponse,
    NoveltyInvestigationSummary,
    NoveltySuppressionRule,
)
from backend.services.novelty_detection_service import NoveltyDetectionService
from backend.services.novelty_metrics import novelty_metrics

router = APIRouter(tags=["Novelty & Emerging-Threat Detection"])


# ============================================================================
# 1. EVALUATION & INGESTION
# ============================================================================

@router.post(
    "/api/v1/novelty/evaluate",
    response_model=NoveltyEvaluationResponse,
    summary="Evaluate novelty of an observed pattern, sequence, or combination",
)
def evaluate_novelty(
    req: NoveltyEvaluationRequest,
    db: Session = Depends(get_db),
):
    try:
        response = NoveltyDetectionService.evaluate_pattern(
            session=db,
            request=req,
        )
        db.commit()
        return response
    except ValueError as e:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail='Novelty evaluation failed.')


# ============================================================================
# 2. INVESTIGATION NOVELTY ENDPOINTS
# ============================================================================

@router.get(
    "/api/v1/investigations/{id}/novelty",
    response_model=NoveltyInvestigationSummary,
    summary="Get comprehensive novelty assessment summary for an investigation",
)
def get_investigation_novelty(
    id: str,
    workspace_id: str = Query(default="default", description="Workspace tenant identifier"),
    db: Session = Depends(get_db),
):
    try:
        return NoveltyDetectionService.get_investigation_novelty(
            session=db,
            incident_id=id,
            workspace_id=workspace_id,
        )
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal operation failed.")


@router.get(
    "/api/v1/investigations/{id}/novelty/patterns",
    response_model=List[NoveltyAssessment],
    summary="Get structural pattern novelty assessments (API, URL, Domain) for an investigation",
)
def get_investigation_patterns(
    id: str,
    workspace_id: str = Query(default="default"),
    db: Session = Depends(get_db),
):
    try:
        return NoveltyDetectionService.get_investigation_patterns(
            session=db,
            incident_id=id,
            workspace_id=workspace_id,
        )
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal operation failed.")


@router.get(
    "/api/v1/investigations/{id}/novelty/sequences",
    response_model=List[NoveltyAssessment],
    summary="Get sequence and combination novelty assessments for an investigation",
)
def get_investigation_sequences(
    id: str,
    workspace_id: str = Query(default="default"),
    db: Session = Depends(get_db),
):
    try:
        return NoveltyDetectionService.get_investigation_sequences(
            session=db,
            incident_id=id,
            workspace_id=workspace_id,
        )
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal operation failed.")


@router.get(
    "/api/v1/investigations/{id}/novelty/infrastructure",
    response_model=List[NoveltyAssessment],
    summary="Get network and infrastructure novelty assessments for an investigation",
)
def get_investigation_infrastructure(
    id: str,
    workspace_id: str = Query(default="default"),
    db: Session = Depends(get_db),
):
    try:
        return NoveltyDetectionService.get_investigation_infrastructure(
            session=db,
            incident_id=id,
            workspace_id=workspace_id,
        )
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal operation failed.")


@router.get(
    "/api/v1/investigations/{id}/emerging-patterns",
    response_model=List[EmergingPatternCandidate],
    summary="Get emerging pattern candidates associated with an investigation",
)
def get_investigation_emerging_patterns(
    id: str,
    workspace_id: str = Query(default="default"),
    db: Session = Depends(get_db),
):
    try:
        return NoveltyDetectionService.get_investigation_emerging_patterns(
            session=db,
            incident_id=id,
            workspace_id=workspace_id,
        )
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal operation failed.")


# ============================================================================
# 3. ENTITY NOVELTY ENDPOINTS
# ============================================================================

@router.get(
    "/api/v1/entities/{id}/novelty",
    response_model=List[NoveltyAssessment],
    summary="Get novelty assessments associated with a specific entity",
)
def get_entity_novelty(
    id: str,
    workspace_id: str = Query(default="default"),
    db: Session = Depends(get_db),
):
    try:
        return NoveltyDetectionService.get_entity_novelty(
            session=db,
            entity_id=id,
            workspace_id=workspace_id,
        )
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal operation failed.")


# ============================================================================
# 4. EMERGING PATTERNS LIFECYCLE
# ============================================================================

@router.post(
    "/api/v1/novelty/emerging-patterns/{pattern_id}/status",
    response_model=EmergingPatternCandidate,
    summary="Transition lifecycle status of an emerging pattern candidate",
)
def transition_emerging_status(
    pattern_id: str,
    req: EmergingStatusTransitionRequest,
    workspace_id: str = Query(default="default"),
    db: Session = Depends(get_db),
):
    try:
        candidate = NoveltyDetectionService.transition_emerging_pattern_status(
            session=db,
            pattern_id=pattern_id,
            actor=req.actor,
            new_status=req.new_status,
            reason=req.reason,
            workspace_id=workspace_id,
        )
        db.commit()
        return candidate
    except ValueError as e:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal operation failed.")


# ============================================================================
# 5. CONTEXTUAL SUPPRESSIONS & AUDIT
# ============================================================================

@router.post(
    "/api/v1/novelty/suppressions",
    response_model=NoveltySuppressionRule,
    summary="Register an auditable contextual suppression rule",
)
def register_suppression(
    req: NoveltySuppressionRule,
    db: Session = Depends(get_db),
):
    try:
        rule_model = NoveltyDetectionService.register_suppression_rule(
            session=db,
            rule=req,
        )
        db.commit()
        return NoveltySuppressionRule(
            id=rule_model.id,
            workspace_id=rule_model.workspace_id,
            pattern_type=rule_model.pattern_type,
            entity_type=rule_model.entity_type,
            entity_id=rule_model.entity_id,
            fingerprint_hash=rule_model.fingerprint_hash,
            reason=rule_model.reason,
            approved_by=rule_model.approved_by,
            valid_from=rule_model.valid_from,
            valid_until=rule_model.valid_until,
            created_at=rule_model.created_at,
        )
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal operation failed.")


# ============================================================================
# 6. OBSERVABILITY STATS
# ============================================================================

@router.get(
    "/api/v1/novelty/stats",
    summary="Get structured observability counters and metrics for the Novelty Engine",
)
def get_novelty_stats():
    return {
        "status": "active",
        "engine_version": "1.0.0",
        "metrics": novelty_metrics.get_metrics(),
    }
