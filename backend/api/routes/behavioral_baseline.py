"""
Behavioral Baseline REST API Endpoints (Section 21).

Provides routes for querying entity baselines, evaluation of telemetry deviations,
baseline lifecycle management (freeze/unfreeze/relearn), and exception registration.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import uuid
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.db.models import (
    BehavioralBaselineModel,
    BehavioralDeviationModel,
    BaselineAuditModel,
)
from backend.schemas.behavioral_baseline import (
    BaselineConfidenceLevel,
    BaselineEntityType,
    BaselineException,
    BaselineMetricType,
    BaselineQuality,
    BaselineWindowType,
    BehavioralBaseline,
    BehavioralDeviation,
    BaselineEvaluationRequest,
    BaselineEvaluationResponse,
    DeviationDirection,
    EntityProfileCategory,
    LearningMode,
)
from backend.services.behavioral_baseline_service import BehavioralBaselineService
from backend.services.baseline_context_manager import BaselineContextManager


router = APIRouter(tags=["Behavioral Baseline Engine"])


class FreezeRequest(BaseModel):
    actor: str = Field(description="Name or ID of analyst initiating freeze")
    reason: str = Field(description="Justification for freezing baseline")
    metric_type: Optional[str] = Field(default=None, description="Optional specific metric to freeze")


class UnfreezeRequest(BaseModel):
    actor: str = Field(description="Name or ID of analyst initiating unfreeze")
    reason: str = Field(description="Justification for unfreezing baseline")
    metric_type: Optional[str] = Field(default=None, description="Optional specific metric to unfreeze")


class RelearnRequest(BaseModel):
    actor: str = Field(description="Name or ID of analyst initiating relearn")
    reason: str = Field(description="Justification for relearning baseline")
    window_days: int = Field(default=14, ge=1, le=90)
    metric_type: Optional[str] = Field(default=None, description="Optional specific metric to relearn")


class ExceptionRegistrationRequest(BaseModel):
    reason: str = Field(description="Operational justification for exception")
    approved_by: str = Field(description="Approving authority or ticket reference")
    valid_from: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    valid_until: Optional[datetime] = None
    metric_type: Optional[str] = None


@router.get(
    "/api/v1/entities/{entity_type}/{entity_id}/baseline",
    response_model=List[BehavioralBaseline],
    summary="Get active behavioral baselines for an entity",
)
def get_entity_baselines(
    entity_type: str,
    entity_id: str,
    metric_type: Optional[str] = None,
    workspace_id: str = "default",
    db: Session = Depends(get_db),
):
    norm_id = entity_id.strip().lower()
    norm_type = entity_type.strip().upper()

    query = db.query(BehavioralBaselineModel).filter(
        BehavioralBaselineModel.workspace_id == workspace_id,
        BehavioralBaselineModel.entity_type == norm_type,
        BehavioralBaselineModel.entity_id == norm_id,
    )
    if metric_type:
        query = query.filter(BehavioralBaselineModel.metric_type == metric_type.strip().upper())

    records = query.all()
    return [BehavioralBaselineService._model_to_schema(r) for r in records]


@router.get(
    "/api/v1/entities/{entity_type}/{entity_id}/baseline/history",
    summary="Get baseline lifecycle audit history for an entity",
)
def get_entity_baseline_history(
    entity_type: str,
    entity_id: str,
    workspace_id: str = "default",
    db: Session = Depends(get_db),
):
    norm_id = entity_id.strip().lower()
    norm_type = entity_type.strip().upper()

    baselines = db.query(BehavioralBaselineModel).filter(
        BehavioralBaselineModel.workspace_id == workspace_id,
        BehavioralBaselineModel.entity_type == norm_type,
        BehavioralBaselineModel.entity_id == norm_id,
    ).all()

    if not baselines:
        return {"entity_id": entity_id, "history": []}

    b_ids = [b.id for b in baselines]
    audits = db.query(BaselineAuditModel).filter(
        BaselineAuditModel.baseline_id.in_(b_ids)
    ).order_by(BaselineAuditModel.created_at.desc()).all()

    history = []
    for a in audits:
        details = {}
        if a.details_json:
            try:
                details = json.loads(a.details_json)
            except Exception:
                pass
        history.append({
            "id": a.id,
            "baseline_id": a.baseline_id,
            "action": a.action,
            "actor": a.actor,
            "reason": a.reason,
            "details": details,
            "created_at": a.created_at.isoformat(),
        })

    return {"entity_id": entity_id, "history": history}


@router.post(
    "/api/v1/entities/{entity_type}/{entity_id}/baseline/freeze",
    response_model=List[BehavioralBaseline],
    summary="Freeze entity baselines during an active incident",
)
def freeze_entity_baselines(
    entity_type: str,
    entity_id: str,
    req: FreezeRequest,
    workspace_id: str = "default",
    db: Session = Depends(get_db),
):
    norm_id = entity_id.strip().lower()
    norm_type = entity_type.strip().upper()

    query = db.query(BehavioralBaselineModel).filter(
        BehavioralBaselineModel.workspace_id == workspace_id,
        BehavioralBaselineModel.entity_type == norm_type,
        BehavioralBaselineModel.entity_id == norm_id,
    )
    if req.metric_type:
        query = query.filter(BehavioralBaselineModel.metric_type == req.metric_type.strip().upper())

    records = query.all()
    if not records:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No baselines found for {entity_type}:{entity_id}"
        )

    results = []
    for r in records:
        frozen = BehavioralBaselineService.freeze_baseline(
            session=db,
            baseline_id=r.id,
            actor=req.actor,
            reason=req.reason,
        )
        results.append(frozen)

    return results


@router.post(
    "/api/v1/entities/{entity_type}/{entity_id}/baseline/unfreeze",
    response_model=List[BehavioralBaseline],
    summary="Unfreeze entity baselines back to stable adaptive state",
)
def unfreeze_entity_baselines(
    entity_type: str,
    entity_id: str,
    req: UnfreezeRequest,
    workspace_id: str = "default",
    db: Session = Depends(get_db),
):
    norm_id = entity_id.strip().lower()
    norm_type = entity_type.strip().upper()

    query = db.query(BehavioralBaselineModel).filter(
        BehavioralBaselineModel.workspace_id == workspace_id,
        BehavioralBaselineModel.entity_type == norm_type,
        BehavioralBaselineModel.entity_id == norm_id,
    )
    if req.metric_type:
        query = query.filter(BehavioralBaselineModel.metric_type == req.metric_type.strip().upper())

    records = query.all()
    if not records:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No baselines found for {entity_type}:{entity_id}"
        )

    results = []
    for r in records:
        unfrozen = BehavioralBaselineService.unfreeze_baseline(
            session=db,
            baseline_id=r.id,
            actor=req.actor,
            reason=req.reason,
        )
        results.append(unfrozen)

    return results


@router.post(
    "/api/v1/entities/{entity_type}/{entity_id}/baseline/relearn",
    response_model=List[BehavioralBaseline],
    summary="Trigger controlled baseline relearning for an entity",
)
def relearn_entity_baselines(
    entity_type: str,
    entity_id: str,
    req: RelearnRequest,
    workspace_id: str = "default",
    db: Session = Depends(get_db),
):
    norm_id = entity_id.strip().lower()
    norm_type = entity_type.strip().upper()

    query = db.query(BehavioralBaselineModel).filter(
        BehavioralBaselineModel.workspace_id == workspace_id,
        BehavioralBaselineModel.entity_type == norm_type,
        BehavioralBaselineModel.entity_id == norm_id,
    )
    if req.metric_type:
        query = query.filter(BehavioralBaselineModel.metric_type == req.metric_type.strip().upper())

    records = query.all()
    if not records:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No baselines found for {entity_type}:{entity_id}"
        )

    results = []
    for r in records:
        relearned = BehavioralBaselineService.relearn_baseline(
            session=db,
            baseline_id=r.id,
            actor=req.actor,
            reason=req.reason,
            window_days=req.window_days,
        )
        results.append(relearned)

    return results


@router.post(
    "/api/v1/entities/{entity_type}/{entity_id}/exceptions",
    summary="Register an auditable contextual exception",
)
def register_entity_exception(
    entity_type: str,
    entity_id: str,
    req: ExceptionRegistrationRequest,
):
    try:
        etype = BaselineEntityType(entity_type.strip().upper())
    except Exception:
        raise HTTPException(status_code=400, detail=f"Invalid entity type: {entity_type}")

    mtype = None
    if req.metric_type:
        try:
            mtype = BaselineMetricType(req.metric_type.strip().upper())
        except Exception:
            raise HTTPException(status_code=400, detail=f"Invalid metric type: {req.metric_type}")

    exc_record = BaselineException(
        id=str(uuid.uuid4()),
        entity_type=etype,
        entity_id=entity_id.strip().lower(),
        metric_type=mtype,
        reason=req.reason,
        approved_by=req.approved_by,
        valid_from=req.valid_from,
        valid_until=req.valid_until,
        is_active=True,
    )
    BaselineContextManager.register_exception(exc_record)
    return {"status": "registered", "exception_id": exc_record.id, "entity_id": entity_id}


@router.get(
    "/api/v1/investigations/{investigation_id}/behavioral-deviations",
    response_model=List[BehavioralDeviation],
    summary="Get behavioral deviations associated with an investigation",
)
def get_investigation_deviations(
    investigation_id: str,
    workspace_id: str = "default",
    db: Session = Depends(get_db),
):
    models = db.query(BehavioralDeviationModel).filter(
        BehavioralDeviationModel.workspace_id == workspace_id,
        (BehavioralDeviationModel.investigation_id == investigation_id) |
        (BehavioralDeviationModel.incident_id == investigation_id),
    ).order_by(BehavioralDeviationModel.created_at.desc()).all()

    deviations: List[BehavioralDeviation] = []
    for m in models:
        ev_list = []
        if m.evidence_ids_json:
            try:
                ev_list = json.loads(m.evidence_ids_json)
            except Exception:
                pass
        lim_list = []
        if m.limitations_json:
            try:
                lim_list = json.loads(m.limitations_json)
            except Exception:
                pass

        deviations.append(BehavioralDeviation(
            id=m.id,
            baseline_id=m.baseline_id,
            incident_id=m.incident_id,
            investigation_id=m.investigation_id,
            workspace_id=m.workspace_id,
            entity_type=BaselineEntityType(m.entity_type),
            entity_id=m.entity_id,
            metric_type=BaselineMetricType(m.metric_type),
            observed_value=m.observed_value,
            expected_range_summary=m.expected_range_summary,
            deviation_score=m.deviation_score,
            deviation_direction=DeviationDirection(m.deviation_direction),
            severity_hint=m.severity_hint,
            baseline_confidence=m.baseline_confidence,
            baseline_quality=BaselineQuality(m.baseline_quality),
            evidence_ids=ev_list,
            explanation=m.explanation,
            limitations=lim_list,
            created_at=m.created_at.replace(tzinfo=timezone.utc),
        ))

    return deviations


@router.post(
    "/api/v1/baselines/evaluate-deviation",
    response_model=BaselineEvaluationResponse,
    summary="Evaluate an observed event against an established baseline",
)
def evaluate_deviation_endpoint(
    req: BaselineEvaluationRequest,
    workspace_id: str = "default",
    db: Session = Depends(get_db),
):
    baseline = BehavioralBaselineService.get_or_create_baseline(
        session=db,
        entity_type=req.entity_type,
        entity_id=req.entity_id,
        metric_type=req.metric_type,
        workspace_id=workspace_id,
    )

    dev = BehavioralBaselineService.evaluate_deviation(
        session=db,
        baseline=baseline,
        observed_value=req.observed_value,
        event_time=req.event_time,
    )

    is_anom = (dev.deviation_score >= 0.40) if dev else False
    expl = dev.explanation if dev else "Observed value conforms to established baseline."

    return BaselineEvaluationResponse(
        is_anomalous=is_anom,
        deviation=dev,
        baseline_quality=baseline.quality_status,
        baseline_confidence=baseline.confidence_score,
        explanation=expl,
    )
