"""
Section 60: REST API Routes for Behavioral Detection & Anomaly Analytics.

Provides endpoints for:
1. Operational overview metrics for SOC dashboards
2. Behavioral profiles lifecycle inspection (Cold-start, Learning, Active, Stale, Degraded)
3. Historical deviations and evidence-backed anomaly findings
4. Realtime evaluation requests
5. Learning quarantine management against baseline poisoning
6. Controlled baseline recalculation and version rollback
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.db.models import (
    BehaviorProfileModel,
    BehaviorLearningQuarantineModel,
    BehavioralDeviationModel,
    BehavioralBaselineModel,
)
from backend.schemas.behavioral_baseline import (
    BaselineEntityType,
    BaselineMetricType,
    BaselineQuality,
)
from backend.schemas.behavioral_detection import (
    BehaviorProfileDetail,
    BehaviorProfileRead,
    BehavioralAnomalyDetail,
    BehavioralEvaluationRequest,
    BehavioralEvaluationResponse,
    BehavioralOverviewStats,
    LearningQuarantineItemRead,
    QuarantineDispositionEnum,
    QuarantineReviewRequest,
    BaselineRefreshRequest,
)
from backend.schemas.detection_pipeline import (
    NormalizedDetectionEvent,
    PipelineModeEnum,
)
from backend.schemas.jobs import JobSubmitRequest, JobTypeEnum, JobPriorityEnum
from backend.services.background_job_service import BackgroundJobService
from backend.services.behavioral_anomaly_service import BehavioralAnomalyService

logger = logging.getLogger("cyberguard.api.behavioral_detection")

router = APIRouter(prefix="/api/v1/behavioral", tags=["Behavioral Detection & Anomaly Analytics"])


# ============================================================================
# RBAC & MULTI-TENANCY HELPERS
# ============================================================================

def verify_analyst_or_admin(
    x_role: Optional[str] = Header(None, alias="X-Role"),
    x_user_role: Optional[str] = Header(None, alias="X-User-Role"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
) -> str:
    """Enforces role-based authorization for behavioral detection interactions."""
    role = (x_role or x_user_role or "").strip().lower()
    if not role and authorization:
        auth_clean = authorization.strip().lower()
        if "admin" in auth_clean:
            role = "admin"
        elif "analyst" in auth_clean or "bearer" in auth_clean:
            role = "analyst"

    if not role:
        role = "analyst"  # Default permissible role in development

    allowed = {"analyst", "senior_analyst", "admin", "lead", "soc_manager"}
    if role not in allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Role '{role}' is not authorized to access behavioral anomaly operations.",
        )
    return role


def get_workspace_id(
    x_workspace_id: Optional[str] = Header("default", alias="X-Workspace-Id")
) -> str:
    """Extracts tenant workspace boundary."""
    return (x_workspace_id or "default").strip()


# ============================================================================
# 1. SOC OPERATIONAL OVERVIEW
# ============================================================================

@router.get("/overview", response_model=BehavioralOverviewStats)
def get_behavioral_overview(
    workspace_id: str = Depends(get_workspace_id),
    role: str = Depends(verify_analyst_or_admin),
    db: Session = Depends(get_db),
):
    """
    Returns high-level SOC metrics for behavioral analytics:
    profile health distributions, 24h anomaly volume, quarantine queue depth, and recent deviations.
    """
    return BehavioralAnomalyService.get_overview_stats(db=db, workspace_id=workspace_id)


# ============================================================================
# 2. BEHAVIORAL PROFILES LIFECYCLE
# ============================================================================

@router.get("/profiles")
def list_behavior_profiles(
    status_filter: Optional[str] = Query(None, alias="status", description="INSUFFICIENT_DATA, LEARNING, ACTIVE, STALE, DEGRADED, SUSPENDED"),
    quality_filter: Optional[str] = Query(None, alias="quality", description="INSUFFICIENT_HISTORY, DEVELOPING, STABLE, STALE"),
    entity_type: Optional[str] = Query(None, description="USER, DEVICE, ENDPOINT, API_CLIENT, IP, DOMAIN"),
    search: Optional[str] = Query(None, description="Search by entity identifier"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    workspace_id: str = Depends(get_workspace_id),
    role: str = Depends(verify_analyst_or_admin),
    db: Session = Depends(get_db),
):
    """
    Lists tenant-isolated behavioral entity profiles with lifecycle state filters.
    """
    profiles, total = BehavioralAnomalyService.list_profiles(
        db=db,
        workspace_id=workspace_id,
        status=status_filter,
        quality=quality_filter,
        entity_type=entity_type,
        search=search,
        limit=limit,
        offset=offset,
    )

    items = []
    for p in profiles:
        try:
            active_metrics = json.loads(p.active_metrics_json or "[]")
        except Exception:
            active_metrics = []
        try:
            top_deviations = json.loads(p.top_deviations_json or "[]")
        except Exception:
            top_deviations = []
        try:
            meta = json.loads(p.metadata_json or "{}")
        except Exception:
            meta = {}

        items.append(BehaviorProfileRead(
            id=p.id,
            workspace_id=p.workspace_id,
            entity_type=p.entity_type,
            entity_id=p.entity_id,
            entity_category=p.entity_category,
            profile_status=p.profile_status,
            sample_count=p.sample_count,
            first_observed_at=p.first_observed_at,
            last_observed_at=p.last_observed_at,
            last_anomaly_at=p.last_anomaly_at,
            anomaly_count=p.anomaly_count,
            quality_status=p.quality_status,
            confidence_score=p.confidence_score,
            baseline_version=p.baseline_version,
            feature_schema_version=p.feature_schema_version,
            active_metrics=active_metrics,
            top_deviations=top_deviations,
            metadata=meta,
            created_at=p.created_at,
            updated_at=p.updated_at,
        ))

    return {"items": items, "total": total}


@router.get("/profiles/{profile_id}", response_model=BehaviorProfileDetail)
def get_behavior_profile_detail(
    profile_id: str,
    workspace_id: str = Depends(get_workspace_id),
    role: str = Depends(verify_analyst_or_admin),
    db: Session = Depends(get_db),
):
    """
    Retrieves complete entity behavior profile including active baselines, recent deviations,
    and learning quarantine queue depth.
    """
    detail = BehavioralAnomalyService.get_profile_detail(
        db=db,
        profile_id=profile_id,
        workspace_id=workspace_id,
    )
    if not detail:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Behavioral profile '{profile_id}' not found in workspace '{workspace_id}'.",
        )
    return detail


# ============================================================================
# 3. HISTORICAL BEHAVIORAL DEVIATIONS & FINDINGS
# ============================================================================

@router.get("/deviations")
def list_behavioral_deviations(
    entity_type: Optional[str] = Query(None, description="USER, DEVICE, ENDPOINT, API_CLIENT"),
    entity_id: Optional[str] = Query(None, description="Specific entity identifier"),
    severity: Optional[str] = Query(None, description="LOW, MEDIUM, HIGH"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    workspace_id: str = Depends(get_workspace_id),
    role: str = Depends(verify_analyst_or_admin),
    db: Session = Depends(get_db),
):
    """
    Lists tenant-isolated historical behavioral deviations with server-side pagination.
    """
    devs, total = BehavioralAnomalyService.list_deviations(
        db=db,
        workspace_id=workspace_id,
        entity_type=entity_type,
        entity_id=entity_id,
        severity=severity,
        limit=limit,
        offset=offset,
    )

    items = []
    for d in devs:
        try:
            ev_ids = json.loads(d.evidence_ids_json or "[]")
        except Exception:
            ev_ids = []
        try:
            limits = json.loads(d.limitations_json or "[]")
        except Exception:
            limits = []

        items.append(BehavioralAnomalyDetail(
            id=d.id,
            workspace_id=d.workspace_id,
            entity_type=d.entity_type,
            entity_id=d.entity_id,
            metric_type=d.metric_type,
            observed_value=d.observed_value,
            baseline_expected_range=d.expected_range_summary,
            deviation_score=d.deviation_score,
            severity_hint=d.severity_hint,
            direction=d.deviation_direction,
            explanation=d.explanation,
            evidence_ids=ev_ids,
            limitations=limits,
            finding_id=d.finding_id,
            alert_id=d.alert_id,
            incident_id=d.incident_id,
            created_at=d.created_at,
        ))

    return {"items": items, "total": total}


# ============================================================================
# 4. TELEMETRY EVALUATION
# ============================================================================

@router.post("/evaluate", response_model=BehavioralEvaluationResponse)
def evaluate_behavioral_observation(
    req: BehavioralEvaluationRequest,
    workspace_id: str = Depends(get_workspace_id),
    role: str = Depends(verify_analyst_or_admin),
    db: Session = Depends(get_db),
):
    """
    Evaluates a specific behavioral observation against the established baseline.
    Enforces cold-start and baseline-poisoning protections.
    """
    from datetime import datetime, timezone

    # Construct synthetic NormalizedDetectionEvent for uniform pipeline handling
    now = datetime.now(timezone.utc)
    norm_event = NormalizedDetectionEvent(
        event_id=req.event_id or f"EVAL-{now.timestamp()}",
        workspace_id=workspace_id,
        event_type=f"EVAL_{req.metric_type}",
        source_type=req.entity_type,
        source_id=req.entity_id,
        occurred_at=req.observed_at or now,
        received_at=now,
        payload={
            req.metric_type.lower(): req.observed_value,
            "entity_type": req.entity_type,
            "entity_id": req.entity_id,
            "user": req.entity_id if req.entity_type == "USER" else None,
            "account_id": req.entity_id if req.entity_type in ("USER", "ACCOUNT") else None,
            "endpoint_id": req.entity_id if req.entity_type in ("DEVICE", "ENDPOINT") else None,
            **req.context_data,
        },
        entities=[{"type": req.entity_type, "value": req.entity_id}],
        provenance={"channel": "MANUAL_BEHAVIORAL_EVALUATE"},
    )

    responses = BehavioralAnomalyService.evaluate_event(
        db=db,
        norm_event=norm_event,
        mode=PipelineModeEnum.PRODUCTION,
    )

    if responses:
        return responses[0]

    # If no specific observation was matched from the feature extractor, evaluate directly
    baseline = BehavioralBaselineService.get_or_create_baseline(
        session=db,
        entity_type=BaselineEntityType(req.entity_type) if req.entity_type in BaselineEntityType.__members__ else BaselineEntityType.USER,
        entity_id=req.entity_id,
        metric_type=BaselineMetricType(req.metric_type) if req.metric_type in BaselineMetricType.__members__ else BaselineMetricType.LOGIN_FREQUENCY,
        workspace_id=workspace_id,
    )

    dev = BehavioralBaselineService.evaluate_deviation(
        session=db,
        baseline=baseline,
        observed_value=req.observed_value,
        event_time=req.observed_at or now,
    )

    return BehavioralEvaluationResponse(
        evaluated=True,
        is_anomaly=dev.deviation_score >= 0.60 if dev else False,
        deviation_score=dev.deviation_score if dev else 0.0,
        severity=dev.severity_hint if dev else "LOW",
        explanation=dev.explanation if dev else "Observed value aligns with established baseline.",
        profile_status="ACTIVE",
        quality_status=baseline.quality_status,
        baseline_version=baseline.metric_version,
    )


# ============================================================================
# 5. LEARNING QUARANTINE (POISONING PREVENTION)
# ============================================================================

@router.get("/quarantine")
def list_learning_quarantine(
    disposition: Optional[str] = Query(None, description="PENDING, APPROVED, REJECTED, EXPIRED"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    workspace_id: str = Depends(get_workspace_id),
    role: str = Depends(verify_analyst_or_admin),
    db: Session = Depends(get_db),
):
    """
    Lists suspicious observations held in Learning Quarantine to prevent baseline contamination.
    """
    items, total = BehavioralAnomalyService.list_quarantine(
        db=db,
        workspace_id=workspace_id,
        disposition=disposition,
        limit=limit,
        offset=offset,
    )

    results = []
    for it in items:
        try:
            payload = json.loads(it.payload_json or "{}")
        except Exception:
            payload = {}

        results.append(LearningQuarantineItemRead(
            id=it.id,
            workspace_id=it.workspace_id,
            entity_type=it.entity_type,
            entity_id=it.entity_id,
            metric_type=it.metric_type,
            observed_value=it.observed_value,
            event_id=it.event_id,
            quarantine_reason=it.quarantine_reason,
            disposition=it.disposition,
            reviewed_by=it.reviewed_by,
            reviewed_at=it.reviewed_at,
            review_notes=it.review_notes,
            payload=payload,
            created_at=it.created_at,
        ))

    return {"items": results, "total": total}


@router.post("/quarantine/{quarantine_id}/review", response_model=LearningQuarantineItemRead)
def review_quarantine_item(
    quarantine_id: str,
    req: QuarantineReviewRequest,
    workspace_id: str = Depends(get_workspace_id),
    role: str = Depends(verify_analyst_or_admin),
    x_user_id: Optional[str] = Header("analyst", alias="X-User-Id"),
    db: Session = Depends(get_db),
):
    """
    Records an analyst disposition (APPROVED / REJECTED) on a quarantined observation.
    Rejection permanently excludes the observation from baseline models to prevent poisoning.
    """
    item = BehavioralAnomalyService.review_quarantine_item(
        db=db,
        quarantine_id=quarantine_id,
        workspace_id=workspace_id,
        reviewer=x_user_id or "analyst",
        disposition=req.disposition,
        review_notes=req.review_notes,
    )
    if not item:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Quarantine item '{quarantine_id}' not found in workspace '{workspace_id}'.",
        )

    try:
        payload = json.loads(item.payload_json or "{}")
    except Exception:
        payload = {}

    return LearningQuarantineItemRead(
        id=item.id,
        workspace_id=item.workspace_id,
        entity_type=item.entity_type,
        entity_id=item.entity_id,
        metric_type=item.metric_type,
        observed_value=item.observed_value,
        event_id=item.event_id,
        quarantine_reason=item.quarantine_reason,
        disposition=item.disposition,
        reviewed_by=item.reviewed_by,
        reviewed_at=item.reviewed_at,
        review_notes=item.review_notes,
        payload=payload,
        created_at=item.created_at,
    )


# ============================================================================
# 6. BASELINE LIFECYCLE MANAGEMENT (REFRESH & ROLLBACK)
# ============================================================================

@router.post("/baselines/refresh")
def refresh_baselines(
    req: BaselineRefreshRequest,
    run_async: bool = Query(False, description="If True, dispatches Section 45 Background Job"),
    workspace_id: str = Depends(get_workspace_id),
    role: str = Depends(verify_analyst_or_admin),
    x_user_id: Optional[str] = Header("analyst", alias="X-User-Id"),
    db: Session = Depends(get_db),
):
    """
    Triggers controlled recalculation of entity baselines, excluding rejected or quarantined observations.
    Can be run synchronously or submitted to Section 45 Background Jobs.
    """
    user = x_user_id or "analyst"

    if run_async:
        job = BackgroundJobService.submit_job(
            db=db,
            request=JobSubmitRequest(
                job_type=JobTypeEnum.BEHAVIORAL_BASELINE_REFRESH,
                priority=JobPriorityEnum.NORMAL,
                workspace_id=workspace_id,
                payload={
                    "entity_type": req.entity_type,
                    "entity_id": req.entity_id,
                    "user_id": user,
                },
            ),
            user_id=user,
        )
        return {
            "status": "QUEUED",
            "job_id": job.id,
            "message": f"Baseline refresh scheduled as background job {job.id}.",
        }

    res = BehavioralAnomalyService.refresh_entity_baselines(
        db=db,
        workspace_id=workspace_id,
        entity_type=req.entity_type,
        entity_id=req.entity_id,
        user_id=user,
    )
    return {
        "status": "COMPLETED",
        "result": res,
    }


class BaselineRollbackBody(BaseModel):
    reason: str = Field(..., description="Justification for baseline rollback")


@router.post("/baselines/{baseline_id}/rollback")
def rollback_baseline(
    baseline_id: str,
    body: BaselineRollbackBody,
    workspace_id: str = Depends(get_workspace_id),
    role: str = Depends(verify_analyst_or_admin),
    x_user_id: Optional[str] = Header("analyst", alias="X-User-Id"),
    db: Session = Depends(get_db),
):
    """
    Rolls back baseline version and marks profile for controlled recalibration.
    Fully audited in BaselineAuditModel.
    """
    user = x_user_id or "analyst"
    model = BehavioralAnomalyService.rollback_baseline(
        db=db,
        workspace_id=workspace_id,
        baseline_id=baseline_id,
        actor=user,
        reason=body.reason,
    )
    if not model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Baseline '{baseline_id}' not found in workspace '{workspace_id}'.",
        )

    return {
        "status": "ROLLED_BACK",
        "baseline_id": model.id,
        "new_version": model.metric_version,
        "quality_status": model.quality_status,
        "actor": user,
    }
