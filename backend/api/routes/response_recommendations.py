"""
REST API Endpoints for Section 28: Response Recommendation Engine.

Mounts routes under /api/v1/recommendations:
- GET  /api/v1/recommendations/by-scope/{scope_type}/{scope_id} : Retrieve prioritized recommendations
- POST /api/v1/recommendations/generate                         : Trigger recommendation generation
- GET  /api/v1/recommendations/capabilities                     : List environment capability registry
- POST /api/v1/recommendations/capabilities                     : Register / update environment capability
- GET  /api/v1/recommendations/summary/{scope_type}/{scope_id}  : Response Workspace overview
- GET  /api/v1/recommendations/{recommendation_id}              : Retrieve single recommendation by ID
- POST /api/v1/recommendations/{recommendation_id}/approve      : Analyst approves recommendation
- POST /api/v1/recommendations/{recommendation_id}/reject       : Analyst rejects recommendation
- POST /api/v1/recommendations/{recommendation_id}/defer        : Analyst defers recommendation
"""

import json
import logging
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.db.models import (
    ResponseRecommendationModel,
    ResponseCapabilityModel,
    generate_uuid,
    get_utc_now
)
from backend.schemas.response_recommendation import (
    ResponseRecommendationResponse,
    ResponseRecommendationSummary,
    ResponseCapabilityResponse,
    ResponseCapabilityCreate,
    RecommendationGenerateRequest,
    RecommendationReviewRequest,
    ResponseWorkspaceOverview,
    RecommendationStatusEnum
)
from backend.services.response_recommendation_engine import ResponseRecommendationEngine

logger = logging.getLogger("cyberguard.api.recommendations")

router = APIRouter(prefix="/api/v1/recommendations", tags=["Response Recommendations"])


def _serialize_rec(rec: ResponseRecommendationModel) -> ResponseRecommendationResponse:
    """Helper to convert model to response schema with parsed JSON properties."""
    return ResponseRecommendationResponse(
        id=rec.id,
        workspace_id=rec.workspace_id,
        scope_type=rec.scope_type,
        scope_id=rec.scope_id,
        incident_id=rec.incident_id,
        threat_event_id=rec.threat_event_id,
        risk_assessment_id=rec.risk_assessment_id,
        explanation_id=rec.explanation_id,
        action_type=rec.action_type,  # type: ignore
        category=rec.category,  # type: ignore
        title=rec.title,
        description=rec.description,
        rationale=rec.rationale,
        priority=rec.priority,  # type: ignore
        urgency=rec.urgency,  # type: ignore
        expected_effect=rec.expected_effect,
        prerequisites=rec.prerequisites,
        affected_entities=rec.affected_entities,
        evidence_refs=rec.evidence_refs,
        risk_refs=rec.risk_refs,
        attack_path_refs=rec.attack_path_refs,
        mitre_refs=rec.mitre_refs,
        confidence=rec.confidence,
        confidence_level=rec.confidence_level,
        applicability=rec.applicability,  # type: ignore
        applicability_reason=rec.applicability_reason,
        reversibility=rec.reversibility,  # type: ignore
        impact=rec.impact,  # type: ignore
        approval_required=rec.approval_required,
        safety_class=rec.safety_class,  # type: ignore
        execution_mode=rec.execution_mode,  # type: ignore
        status=rec.status,  # type: ignore
        status_reason=rec.status_reason,
        reviewed_by=rec.reviewed_by,
        reviewed_at=rec.reviewed_at,
        recommendation_version=rec.recommendation_version,
        superseded_by_id=rec.superseded_by_id,
        depends_on=rec.depends_on,
        conflicts_with=rec.conflicts_with,
        metadata=rec.metadata_payload,
        created_at=rec.created_at,
        updated_at=rec.updated_at,
        expires_at=rec.expires_at
    )


@router.get("/by-scope/{scope_type}/{scope_id}", response_model=List[ResponseRecommendationResponse])
def get_recommendations_by_scope(
    scope_type: str,
    scope_id: str,
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db)
):
    """
    Retrieve current recommendations for target scope.
    If none exist yet, automatically invokes the ResponseRecommendationEngine.
    """
    scope_type_upper = scope_type.strip().upper()
    recs = ResponseRecommendationEngine.generate_recommendations(
        db=db,
        scope_type=scope_type_upper,
        scope_id=scope_id,
        workspace_id=workspace_id,
        force_regenerate=False
    )
    return [_serialize_rec(r) for r in recs]


@router.post("/generate", response_model=List[ResponseRecommendationResponse])
def generate_recommendations_endpoint(
    payload: RecommendationGenerateRequest,
    db: Session = Depends(get_db)
):
    """
    Explicitly trigger recommendation generation (with optional force_regenerate flag).
    """
    recs = ResponseRecommendationEngine.generate_recommendations(
        db=db,
        scope_type=payload.scope_type.upper(),
        scope_id=payload.scope_id,
        workspace_id=payload.workspace_id,
        force_regenerate=payload.force_regenerate
    )
    return [_serialize_rec(r) for r in recs]


@router.get("/capabilities", response_model=List[ResponseCapabilityResponse])
def list_capabilities(
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db)
):
    """
    List registered environment capabilities, providers, and integration readiness.
    """
    caps = ResponseRecommendationEngine.ensure_default_capabilities(db, workspace_id)
    return [
        ResponseCapabilityResponse(
            id=c.id,
            workspace_id=c.workspace_id,
            action_type=c.action_type,  # type: ignore
            provider=c.provider,
            environment=c.environment,
            enabled=c.enabled,
            reversible=c.reversible,
            approval_required=c.approval_required,
            capability_state=c.capability_state,  # type: ignore
            state_reason=c.state_reason,
            configuration=c.configuration,
            created_at=c.created_at,
            updated_at=c.updated_at
        )
        for c in caps
    ]


@router.post("/capabilities", response_model=ResponseCapabilityResponse)
def register_or_update_capability(
    payload: ResponseCapabilityCreate,
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db)
):
    """
    Register or update an environment capability.
    """
    existing = db.query(ResponseCapabilityModel).filter(
        ResponseCapabilityModel.workspace_id == workspace_id,
        ResponseCapabilityModel.action_type == payload.action_type.value
    ).first()

    now = get_utc_now()
    if existing:
        existing.provider = payload.provider
        existing.environment = payload.environment
        existing.enabled = payload.enabled
        existing.reversible = payload.reversible
        existing.approval_required = payload.approval_required
        existing.capability_state = payload.capability_state.value
        existing.state_reason = payload.state_reason
        existing.configuration_json = json.dumps(payload.configuration)
        existing.updated_at = now
        db.commit()
        db.refresh(existing)
        row = existing
    else:
        row = ResponseCapabilityModel(
            id=generate_uuid(),
            workspace_id=workspace_id,
            action_type=payload.action_type.value,
            provider=payload.provider,
            environment=payload.environment,
            enabled=payload.enabled,
            reversible=payload.reversible,
            approval_required=payload.approval_required,
            capability_state=payload.capability_state.value,
            state_reason=payload.state_reason,
            configuration_json=json.dumps(payload.configuration),
            created_at=now,
            updated_at=now
        )
        db.add(row)
        db.commit()
        db.refresh(row)

    return ResponseCapabilityResponse(
        id=row.id,
        workspace_id=row.workspace_id,
        action_type=row.action_type,  # type: ignore
        provider=row.provider,
        environment=row.environment,
        enabled=row.enabled,
        reversible=row.reversible,
        approval_required=row.approval_required,
        capability_state=row.capability_state,  # type: ignore
        state_reason=row.state_reason,
        configuration=row.configuration,
        created_at=row.created_at,
        updated_at=row.updated_at
    )


@router.get("/summary/{scope_type}/{scope_id}", response_model=ResponseWorkspaceOverview)
def get_recommendations_summary(
    scope_type: str,
    scope_id: str,
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db)
):
    """
    High-level overview of recommendations for the Response Workspace dashboard.
    """
    scope_type_upper = scope_type.strip().upper()
    recs = ResponseRecommendationEngine.generate_recommendations(
        db=db,
        scope_type=scope_type_upper,
        scope_id=scope_id,
        workspace_id=workspace_id,
        force_regenerate=False
    )

    by_priority = {"P0": 0, "P1": 0, "P2": 0, "P3": 0, "P4": 0}
    by_category: Dict[str, int] = {}
    by_status: Dict[str, int] = {}
    pending_approval = 0

    for r in recs:
        p = r.priority or "P2"
        by_priority[p] = by_priority.get(p, 0) + 1
        c = r.category or "INVESTIGATION"
        by_category[c] = by_category.get(c, 0) + 1
        s = r.status or "GENERATED"
        by_status[s] = by_status.get(s, 0) + 1
        if r.approval_required and r.status in [RecommendationStatusEnum.GENERATED.value, RecommendationStatusEnum.REVIEW_REQUIRED.value]:
            pending_approval += 1

    return ResponseWorkspaceOverview(
        workspace_id=workspace_id,
        scope_type=scope_type_upper,
        scope_id=scope_id,
        total_count=len(recs),
        by_priority=by_priority,
        by_category=by_category,
        by_status=by_status,
        pending_approval_count=pending_approval,
        recommendations=[_serialize_rec(r) for r in recs]
    )


@router.get("/{recommendation_id}", response_model=ResponseRecommendationResponse)
def get_recommendation_by_id(
    recommendation_id: str,
    db: Session = Depends(get_db)
):
    """
    Retrieve single recommendation by primary key.
    """
    rec = db.query(ResponseRecommendationModel).filter(
        ResponseRecommendationModel.id == recommendation_id
    ).first()
    if not rec:
        raise HTTPException(status_code=404, detail="Recommendation not found")
    return _serialize_rec(rec)


@router.post("/{recommendation_id}/approve", response_model=ResponseRecommendationResponse)
def approve_recommendation_endpoint(
    recommendation_id: str,
    payload: RecommendationReviewRequest,
    db: Session = Depends(get_db)
):
    """
    Analyst explicitly approves an advisory recommendation.
    NOTE: Does NOT silently execute the action. It marks the recommendation APPROVED for future playbooks.
    """
    try:
        updated = ResponseRecommendationEngine.review_recommendation(
            db=db,
            recommendation_id=recommendation_id,
            reviewer_id=payload.reviewer_id,
            disposition=RecommendationStatusEnum.APPROVED.value,
            notes=payload.notes
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if not updated:
        raise HTTPException(status_code=404, detail="Recommendation not found")
    return _serialize_rec(updated)


@router.post("/{recommendation_id}/reject", response_model=ResponseRecommendationResponse)
def reject_recommendation_endpoint(
    recommendation_id: str,
    payload: RecommendationReviewRequest,
    db: Session = Depends(get_db)
):
    """
    Analyst rejects an advisory recommendation with documented reason.
    """
    try:
        updated = ResponseRecommendationEngine.review_recommendation(
            db=db,
            recommendation_id=recommendation_id,
            reviewer_id=payload.reviewer_id,
            disposition=RecommendationStatusEnum.REJECTED.value,
            notes=payload.notes
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if not updated:
        raise HTTPException(status_code=404, detail="Recommendation not found")
    return _serialize_rec(updated)


@router.post("/{recommendation_id}/defer", response_model=ResponseRecommendationResponse)
def defer_recommendation_endpoint(
    recommendation_id: str,
    payload: RecommendationReviewRequest,
    db: Session = Depends(get_db)
):
    """
    Analyst defers an advisory recommendation for later investigation.
    """
    try:
        updated = ResponseRecommendationEngine.review_recommendation(
            db=db,
            recommendation_id=recommendation_id,
            reviewer_id=payload.reviewer_id,
            disposition=RecommendationStatusEnum.DEFERRED.value,
            notes=payload.notes
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if not updated:
        raise HTTPException(status_code=404, detail="Recommendation not found")
    return _serialize_rec(updated)
