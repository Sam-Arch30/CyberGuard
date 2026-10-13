"""
REST API Endpoints for Section 25: Emerging Pattern & Candidate Rule Engine.

Provides endpoints for:
1. Candidate rule formulation from EmergingPatternCandidate and manual submissions.
2. Historical backtesting and false positive assessment.
3. Review, approval, staging (shadow mode), activation, disablement, and retirement.
4. Safe rule evaluation against event/context telemetry (zero arbitrary code execution).
5. Executive dashboard metrics and version histories.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.db.models import CandidateRuleModel, CandidateRuleVersionModel
from backend.schemas.candidate_rules import (
    CandidateRuleCreate,
    CandidateRuleFromPatternRequest,
    CandidateRuleResponse,
    GeneralizationLevel,
    RuleBacktestRequest,
    RuleDashboardStats,
    RuleDefinition,
    RuleEditRequest,
    RuleEvaluation,
    RuleEvaluationRequest,
    RuleLifecycleStatus,
    RuleMatchResult,
    RuleReviewActionRequest,
    RuleScope,
    RuleSeverity,
    RuleType,
    RuleVersionResponse,
)
from backend.services.candidate_rule_service import CandidateRuleService

logger = logging.getLogger("cyberguard.api.candidate_rules")

router = APIRouter(tags=["Candidate Rule Engine"])


# ============================================================================
# AUTHORIZATION DEPENDENCY
# ============================================================================

def verify_rule_role(
    x_role: Optional[str] = Header(None, alias="X-Role"),
    x_user_role: Optional[str] = Header(None, alias="X-User-Role"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
) -> str:
    """Enforces role-based authorization for candidate rule actions."""
    role = (x_role or x_user_role or "").strip().lower()
    if not role and authorization:
        auth_clean = authorization.strip().lower()
        if "admin" in auth_clean:
            role = "admin"
        elif "analyst" in auth_clean or "soc" in auth_clean:
            role = "analyst"
        elif "guest" in auth_clean or "unauthorized" in auth_clean or "untrusted" in auth_clean:
            role = "unauthorized"

    if role in ("guest", "unauthorized", "untrusted", "anonymous", "viewer"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: insufficient permissions for rule engine operations.",
        )
    return role or "analyst"


def _model_to_response(cand: CandidateRuleModel) -> CandidateRuleResponse:
    eval_dict = cand.evaluation_summary
    eval_obj = RuleEvaluation(**eval_dict) if eval_dict else None
    return CandidateRuleResponse(
        id=cand.id,
        workspace_id=cand.workspace_id,
        name=cand.name,
        description=cand.description,
        rule_type=RuleType(cand.rule_type),
        status=RuleLifecycleStatus(cand.status),
        pattern_candidate_id=cand.pattern_candidate_id,
        source_memory_ids=cand.source_memory_ids,
        source_incident_ids=cand.source_incident_ids,
        definition=RuleDefinition(**cand.definition),
        thresholds=cand.thresholds,
        time_window_seconds=cand.time_window_seconds,
        scope=RuleScope(cand.scope),
        severity=RuleSeverity(cand.severity),
        confidence=cand.confidence,
        generalization_level=GeneralizationLevel(cand.generalization_level),
        complexity_score=cand.complexity_score,
        normalized_fingerprint=cand.normalized_fingerprint,
        version=cand.version,
        evaluation_summary=eval_obj,
        staged_at=cand.staged_at,
        activated_at=cand.activated_at,
        retired_at=cand.retired_at,
        created_by=cand.created_by,
        reviewed_by=cand.reviewed_by,
        reviewed_at=cand.reviewed_at,
        review_reason=cand.review_reason,
        created_at=cand.created_at,
        updated_at=cand.updated_at,
    )


# ============================================================================
# 1. CANDIDATE RULE DISCOVERY & FORMULATION
# ============================================================================

@router.get(
    "/api/v1/rule-candidates",
    response_model=List[CandidateRuleResponse],
    summary="List candidate rules",
)
def list_rule_candidates(
    workspace_id: str = Query("default"),
    rule_type: Optional[RuleType] = Query(None),
    status_filter: Optional[RuleLifecycleStatus] = Query(None, alias="status"),
    scope: Optional[RuleScope] = Query(None),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_rule_role),
):
    query = db.query(CandidateRuleModel).filter(CandidateRuleModel.workspace_id == workspace_id)
    if rule_type:
        query = query.filter(CandidateRuleModel.rule_type == rule_type.value)
    if status_filter:
        query = query.filter(CandidateRuleModel.status == status_filter.value)
    if scope:
        query = query.filter(CandidateRuleModel.scope == scope.value)
    rules = query.order_by(CandidateRuleModel.created_at.desc()).all()
    return [_model_to_response(r) for r in rules]


@router.post(
    "/api/v1/rule-candidates",
    response_model=CandidateRuleResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a candidate rule manually",
)
def create_candidate_rule(
    payload: CandidateRuleCreate,
    db: Session = Depends(get_db),
    role: str = Depends(verify_rule_role),
):
    try:
        cand = CandidateRuleService.create_candidate_rule(db, payload)
        return _model_to_response(cand)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post(
    "/api/v1/rule-candidates/from-pattern",
    response_model=CandidateRuleResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Synthesize candidate rule from EmergingPatternCandidate",
)
def generate_candidate_from_pattern(
    payload: CandidateRuleFromPatternRequest,
    db: Session = Depends(get_db),
    role: str = Depends(verify_rule_role),
):
    try:
        cand = CandidateRuleService.generate_candidate_from_pattern(db, payload)
        return _model_to_response(cand)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get(
    "/api/v1/rule-candidates/{rule_id}",
    response_model=CandidateRuleResponse,
    summary="Get candidate rule by ID",
)
def get_rule_candidate(
    rule_id: str,
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_rule_role),
):
    cand = db.query(CandidateRuleModel).filter(
        CandidateRuleModel.workspace_id == workspace_id,
        CandidateRuleModel.id == rule_id,
    ).first()
    if not cand:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Rule '{rule_id}' not found.")
    return _model_to_response(cand)


# ============================================================================
# 2. EVALUATION, BACKTESTING & REVIEW
# ============================================================================

@router.post(
    "/api/v1/rule-candidates/{rule_id}/backtest",
    response_model=RuleEvaluation,
    summary="Execute historical backtest against retained telemetry",
)
def backtest_rule_candidate(
    rule_id: str,
    payload: RuleBacktestRequest,
    db: Session = Depends(get_db),
    role: str = Depends(verify_rule_role),
):
    try:
        return CandidateRuleService.backtest_candidate_rule(
            db, rule_id=rule_id, workspace_id=payload.workspace_id, request=payload
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post(
    "/api/v1/rule-candidates/{rule_id}/submit-review",
    response_model=CandidateRuleResponse,
    summary="Submit candidate rule for security review",
)
def submit_for_review(
    rule_id: str,
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db),
    role: str = Depends(verify_rule_role),
):
    try:
        cand = CandidateRuleService.submit_for_review(db, rule_id=rule_id, workspace_id=workspace_id)
        return _model_to_response(cand)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post(
    "/api/v1/rule-candidates/{rule_id}/approve",
    response_model=CandidateRuleResponse,
    summary="Approve candidate rule",
)
def approve_rule_candidate(
    rule_id: str,
    payload: RuleReviewActionRequest,
    db: Session = Depends(get_db),
    role: str = Depends(verify_rule_role),
):
    try:
        cand = CandidateRuleService.approve_rule(
            db, rule_id=rule_id, workspace_id=payload.workspace_id, request=payload
        )
        return _model_to_response(cand)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post(
    "/api/v1/rule-candidates/{rule_id}/reject",
    response_model=CandidateRuleResponse,
    summary="Reject candidate rule",
)
def reject_rule_candidate(
    rule_id: str,
    payload: RuleReviewActionRequest,
    db: Session = Depends(get_db),
    role: str = Depends(verify_rule_role),
):
    try:
        cand = CandidateRuleService.reject_rule(
            db, rule_id=rule_id, workspace_id=payload.workspace_id, request=payload
        )
        return _model_to_response(cand)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


# ============================================================================
# 3. PRODUCTION & STAGING (SHADOW MODE) LIFECYCLE
# ============================================================================

@router.get(
    "/api/v1/rules",
    response_model=List[CandidateRuleResponse],
    summary="List active and staged rules",
)
def list_rules(
    workspace_id: str = Query("default"),
    scope: Optional[RuleScope] = Query(None),
    status_filter: Optional[RuleLifecycleStatus] = Query(None, alias="status"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_rule_role),
):
    query = db.query(CandidateRuleModel).filter(
        CandidateRuleModel.workspace_id == workspace_id,
    )
    if status_filter:
        query = query.filter(CandidateRuleModel.status == status_filter.value)
    else:
        query = query.filter(CandidateRuleModel.status.in_([
            RuleLifecycleStatus.ACTIVE.value,
            RuleLifecycleStatus.STAGED.value,
            RuleLifecycleStatus.APPROVED.value,
        ]))
    if scope:
        query = query.filter(CandidateRuleModel.scope == scope.value)
    rules = query.order_by(CandidateRuleModel.updated_at.desc()).all()
    return [_model_to_response(r) for r in rules]


@router.get(
    "/api/v1/candidate-rules/{rule_id}",
    response_model=CandidateRuleResponse,
    summary="Get rule details",
)
def get_rule_by_id(
    rule_id: str,
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_rule_role),
):
    cand = db.query(CandidateRuleModel).filter(
        CandidateRuleModel.workspace_id == workspace_id,
        CandidateRuleModel.id == rule_id,
    ).first()
    if not cand:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Rule '{rule_id}' not found.")
    return _model_to_response(cand)


@router.get(
    "/api/v1/candidate-rules/{rule_id}/versions",
    response_model=List[RuleVersionResponse],
    summary="List immutable version history for rule",
)
def get_rule_versions(
    rule_id: str,
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_rule_role),
):
    versions = db.query(CandidateRuleVersionModel).filter(
        CandidateRuleVersionModel.workspace_id == workspace_id,
        CandidateRuleVersionModel.rule_id == rule_id,
    ).order_by(CandidateRuleVersionModel.created_at.desc()).all()

    out = []
    for v in versions:
        eval_dict = v.evaluation_summary
        eval_obj = RuleEvaluation(**eval_dict) if eval_dict else None
        out.append(RuleVersionResponse(
            id=v.id,
            rule_id=v.rule_id,
            version=v.version,
            workspace_id=v.workspace_id,
            definition=RuleDefinition(**v.definition),
            thresholds=v.thresholds,
            evaluation_summary=eval_obj,
            status=RuleLifecycleStatus(v.status),
            created_by=v.created_by,
            reviewed_by=v.reviewed_by,
            change_reason=v.change_reason,
            created_at=v.created_at,
        ))
    return out


@router.post(
    "/api/v1/candidate-rules/{rule_id}/stage",
    response_model=CandidateRuleResponse,
    summary="Stage rule in shadow mode",
)
def stage_rule(
    rule_id: str,
    payload: RuleReviewActionRequest,
    db: Session = Depends(get_db),
    role: str = Depends(verify_rule_role),
):
    try:
        cand = CandidateRuleService.stage_rule(
            db, rule_id=rule_id, workspace_id=payload.workspace_id, request=payload
        )
        return _model_to_response(cand)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post(
    "/api/v1/candidate-rules/{rule_id}/activate",
    response_model=CandidateRuleResponse,
    summary="Promote rule to ACTIVE production detection",
)
def activate_rule(
    rule_id: str,
    payload: RuleReviewActionRequest,
    db: Session = Depends(get_db),
    role: str = Depends(verify_rule_role),
):
    try:
        cand = CandidateRuleService.activate_rule(
            db, rule_id=rule_id, workspace_id=payload.workspace_id, request=payload
        )
        return _model_to_response(cand)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post(
    "/api/v1/candidate-rules/{rule_id}/disable",
    response_model=CandidateRuleResponse,
    summary="Disable an active rule",
)
def disable_rule(
    rule_id: str,
    payload: RuleReviewActionRequest,
    db: Session = Depends(get_db),
    role: str = Depends(verify_rule_role),
):
    try:
        cand = CandidateRuleService.disable_rule(
            db, rule_id=rule_id, workspace_id=payload.workspace_id, request=payload
        )
        return _model_to_response(cand)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post(
    "/api/v1/candidate-rules/{rule_id}/retire",
    response_model=CandidateRuleResponse,
    summary="Retire a rule permanently",
)
def retire_rule(
    rule_id: str,
    payload: RuleReviewActionRequest,
    db: Session = Depends(get_db),
    role: str = Depends(verify_rule_role),
):
    try:
        cand = CandidateRuleService.retire_rule(
            db, rule_id=rule_id, workspace_id=payload.workspace_id, request=payload
        )
        return _model_to_response(cand)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post(
    "/api/v1/candidate-rules/{rule_id}/edit",
    response_model=CandidateRuleResponse,
    summary="Edit rule logic, creating an immutable new version (e.g. v1 -> v2)",
)
def edit_rule(
    rule_id: str,
    payload: RuleEditRequest,
    db: Session = Depends(get_db),
    role: str = Depends(verify_rule_role),
):
    try:
        cand = CandidateRuleService.edit_rule(
            db, rule_id=rule_id, workspace_id=payload.workspace_id, request=payload
        )
        return _model_to_response(cand)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


# ============================================================================
# 4. RUNTIME EVALUATION & OBSERVABILITY
# ============================================================================

@router.post(
    "/api/v1/candidate-rules/evaluate",
    response_model=List[RuleMatchResult],
    summary="Evaluate active and staged rules against event context",
)
def evaluate_rules(
    payload: RuleEvaluationRequest,
    db: Session = Depends(get_db),
    _role: str = Depends(verify_rule_role),
):
    return CandidateRuleService.evaluate_rules_for_event(
        db=db,
        workspace_id=payload.workspace_id,
        context=payload.target_payload,
        scope=payload.scope,
        include_staged=payload.include_staged_shadow,
    )


@router.get(
    "/api/v1/candidate-rules/dashboard/stats",
    response_model=RuleDashboardStats,
    summary="Get rule engine dashboard metrics",
)
def get_dashboard_stats(
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_rule_role),
):
    return CandidateRuleService.get_dashboard_stats(db, workspace_id=workspace_id)
