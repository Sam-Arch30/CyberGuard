"""
Section 56: REST API Routes for Detection Engineering & Rule Lifecycle Foundation.

Exposes endpoints for:
1. Detection rule catalog, filtering, and field registry
2. Safe AST validation, cost classification, and live human-readable preview
3. Controlled lifecycle management (Draft -> Candidate -> Validating -> Pending Review -> Approved -> Active -> Disabled -> Deprecated -> Archived)
4. Immutable rule versioning and visual structural diffing
5. Bounded, read-only historical backtesting (sync & Section 45 background jobs)
6. Handoff workflows (Hunt-to-Rule, Investigation-to-Rule)
7. Safe AI-assisted rule proposal parsing
8. Telemetry evaluation & FindingModel integration
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.db.models import CandidateRuleModel, CandidateRuleVersionModel
from backend.schemas.detection_rules import (
    DATA_SOURCE_FIELD_REGISTRY,
    RuleCategory,
    RuleDataSource,
    RuleProvenanceType,
    RuleCostClass,
    RuleCondition,
    RuleDefinition,
    RuleValidationResponse,
    RuleVersionDiff,
    DetectionRuleCreateRequest,
    DetectionRuleTuneRequest,
    DetectionRuleBacktestRequest,
    DetectionRuleBacktestResponse,
    DetectionRuleFromHuntRequest,
    DetectionRuleFromInvestigationRequest,
    AISuggestRuleRequest,
    AISuggestRuleResponse,
    DetectionRuleResponse,
    DetectionRuleListResponse,
    DetectionRuleStatsResponse,
)
from backend.schemas.candidate_rules import RuleLifecycleStatus, RuleSeverity
from backend.schemas.jobs import JobSubmitRequest, JobTypeEnum, JobPriorityEnum
from backend.services.background_job_service import BackgroundJobService
from backend.services.detection_rule_lifecycle_service import DetectionRuleLifecycleService

logger = logging.getLogger("cyberguard.api.detection_rules")

router = APIRouter(tags=["Detection Engineering & Rule Lifecycle"])


# ============================================================================
# RBAC & TENANCY DEPENDENCIES
# ============================================================================

def verify_analyst_or_admin(
    x_role: Optional[str] = Header(None, alias="X-Role"),
    x_user_role: Optional[str] = Header(None, alias="X-User-Role"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
) -> str:
    """Enforces role-based authorization for detection engineering actions."""
    role = (x_role or x_user_role or "").strip().lower()
    if not role and authorization:
        auth_clean = authorization.strip().lower()
        if "admin" in auth_clean:
            role = "admin"
        elif "analyst" in auth_clean or "soc" in auth_clean:
            role = "analyst"
        elif "viewer" in auth_clean or "guest" in auth_clean or "unauthorized" in auth_clean:
            role = "unauthorized"

    if role in ("guest", "unauthorized", "untrusted", "anonymous", "viewer"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: insufficient permissions for detection rule engineering.",
        )
    return role or "analyst"


def verify_approver_role(
    x_role: Optional[str] = Header(None, alias="X-Role"),
    x_user_role: Optional[str] = Header(None, alias="X-User-Role"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
) -> str:
    """Enforces authorized approver/admin role for rule activation & approval."""
    role = (x_role or x_user_role or "").strip().lower()
    if not role and authorization:
        auth_clean = authorization.strip().lower()
        if "admin" in auth_clean or "lead" in auth_clean:
            role = "admin"
        elif "analyst" in auth_clean:
            role = "analyst"
        elif "viewer" in auth_clean or "guest" in auth_clean or "unauthorized" in auth_clean:
            role = "unauthorized"

    if role in ("guest", "unauthorized", "untrusted", "anonymous", "viewer"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: rule approval and activation require analyst or admin role.",
        )
    return role or "analyst"


# ============================================================================
# 1. CATALOG, REGISTRY & STATS
# ============================================================================

@router.get(
    "/registry",
    summary="Get Data Source and Field Registry with allowed operators and types",
)
def get_registry(
    _role: str = Depends(verify_analyst_or_admin),
) -> Dict[str, Any]:
    """Returns the controlled data source registry, supported fields, types, and operators."""
    registry_data = {}
    for source, fields in DATA_SOURCE_FIELD_REGISTRY.items():
        registry_data[source.value] = {
            field: {
                "type": info["type"].value,
                "operators": [op.value for op in info["operators"]],
                "description": info.get("desc", ""),
            }
            for field, info in fields.items()
        }

    return {
        "data_sources": registry_data,
        "categories": [c.value for c in RuleCategory],
        "lifecycle_statuses": [s.value for s in RuleLifecycleStatus],
        "severities": [s.value for s in RuleSeverity],
        "cost_classes": [c.value for c in RuleCostClass],
        "provenance_types": [p.value for p in RuleProvenanceType],
    }


@router.post(
    "/validate",
    response_model=RuleValidationResponse,
    summary="Validate AST rule definition, calculate cost class, and preview logic",
)
def validate_rule_definition(
    definition: RuleDefinition,
    _role: str = Depends(verify_analyst_or_admin),
) -> RuleValidationResponse:
    """Performs static analysis, type checking, ReDoS guarding, and cost classification without saving."""
    return DetectionRuleLifecycleService.validate_rule_definition(definition)


@router.get(
    "/dashboard/stats",
    response_model=DetectionRuleStatsResponse,
    summary="Get Detection Rule Lifecycle executive metrics",
)
def get_rule_stats(
    workspace_id: str = Query("default"),
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_analyst_or_admin),
) -> DetectionRuleStatsResponse:
    eff_workspace = x_workspace_id or workspace_id
    stats = DetectionRuleLifecycleService.get_rule_stats(db, eff_workspace)
    return DetectionRuleStatsResponse(**stats)


@router.get(
    "",
    response_model=DetectionRuleListResponse,
    summary="List detection rules with search, status, category, and source filtering",
)
def list_detection_rules(
    workspace_id: str = Query("default"),
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    category: Optional[RuleCategory] = Query(None),
    status: Optional[RuleLifecycleStatus] = Query(None),
    severity: Optional[RuleSeverity] = Query(None),
    data_source: Optional[RuleDataSource] = Query(None),
    provenance_type: Optional[RuleProvenanceType] = Query(None),
    search: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_analyst_or_admin),
) -> DetectionRuleListResponse:
    eff_workspace = x_workspace_id or workspace_id
    query = db.query(CandidateRuleModel).filter(CandidateRuleModel.workspace_id == eff_workspace)

    if category:
        query = query.filter(CandidateRuleModel.category == category.value)
    if status:
        query = query.filter(CandidateRuleModel.status == status.value)
    if severity:
        query = query.filter(CandidateRuleModel.severity == severity.value)
    if provenance_type:
        query = query.filter(CandidateRuleModel.provenance_type == provenance_type.value)
    if data_source:
        query = query.filter(CandidateRuleModel.data_sources_json.contains(f'"{data_source.value}"'))
    if search:
        search_term = f"%{search.strip()}%"
        query = query.filter(
            (CandidateRuleModel.name.ilike(search_term))
            | (CandidateRuleModel.rule_identifier.ilike(search_term))
            | (CandidateRuleModel.description.ilike(search_term))
            | (CandidateRuleModel.tags_json.ilike(search_term))
        )

    total = query.count()
    rules = query.order_by(CandidateRuleModel.updated_at.desc()).offset(offset).limit(limit).all()

    items = [DetectionRuleLifecycleService.model_to_response(r) for r in rules]
    active_count = db.query(CandidateRuleModel).filter(CandidateRuleModel.workspace_id == eff_workspace, CandidateRuleModel.status == RuleLifecycleStatus.ACTIVE.value).count()
    candidate_count = db.query(CandidateRuleModel).filter(CandidateRuleModel.workspace_id == eff_workspace, CandidateRuleModel.status.in_([RuleLifecycleStatus.CANDIDATE.value, RuleLifecycleStatus.DRAFT.value])).count()
    staged_count = db.query(CandidateRuleModel).filter(CandidateRuleModel.workspace_id == eff_workspace, CandidateRuleModel.status == RuleLifecycleStatus.STAGED.value).count()
    disabled_count = db.query(CandidateRuleModel).filter(CandidateRuleModel.workspace_id == eff_workspace, CandidateRuleModel.status == RuleLifecycleStatus.DISABLED.value).count()

    return DetectionRuleListResponse(
        items=items,
        total=total,
        active_count=active_count,
        candidate_count=candidate_count,
        staged_count=staged_count,
        disabled_count=disabled_count,
    )


# ============================================================================
# 2. RULE CREATION & SOURCING
# ============================================================================

@router.post(
    "",
    response_model=DetectionRuleResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new candidate detection rule",
)
def create_detection_rule(
    payload: DetectionRuleCreateRequest,
    workspace_id: str = Query("default"),
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    x_user_id: Optional[str] = Header(None, alias="X-User-ID"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_analyst_or_admin),
) -> DetectionRuleResponse:
    eff_workspace = x_workspace_id or workspace_id
    actor = x_user_id or "analyst"
    rule = DetectionRuleLifecycleService.create_candidate_rule(
        db=db,
        workspace_id=eff_workspace,
        req=payload,
        created_by=actor,
    )
    return DetectionRuleLifecycleService.model_to_response(rule)


@router.post(
    "/from-hunt",
    response_model=DetectionRuleResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Synthesize candidate rule from Section 54/55 Threat Hunt",
)
def create_from_hunt(
    payload: DetectionRuleFromHuntRequest,
    workspace_id: str = Query("default"),
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    x_user_id: Optional[str] = Header(None, alias="X-User-ID"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_analyst_or_admin),
) -> DetectionRuleResponse:
    eff_workspace = x_workspace_id or workspace_id
    actor = x_user_id or "analyst"
    rule = DetectionRuleLifecycleService.create_from_hunt(
        db=db,
        workspace_id=eff_workspace,
        req=payload,
        actor_id=actor,
    )
    return DetectionRuleLifecycleService.model_to_response(rule)


@router.post(
    "/from-investigation",
    response_model=DetectionRuleResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Synthesize candidate rule from Section 39 Investigation",
)
def create_from_investigation(
    payload: DetectionRuleFromInvestigationRequest,
    workspace_id: str = Query("default"),
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    x_user_id: Optional[str] = Header(None, alias="X-User-ID"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_analyst_or_admin),
) -> DetectionRuleResponse:
    eff_workspace = x_workspace_id or workspace_id
    actor = x_user_id or "analyst"
    rule = DetectionRuleLifecycleService.create_from_investigation(
        db=db,
        workspace_id=eff_workspace,
        req=payload,
        actor_id=actor,
    )
    return DetectionRuleLifecycleService.model_to_response(rule)


@router.post(
    "/ai-suggest",
    response_model=AISuggestRuleResponse,
    summary="Generate candidate rule proposal from observation using strictly validated AST DSL",
)
def ai_suggest_rule(
    payload: AISuggestRuleRequest,
    _role: str = Depends(verify_analyst_or_admin),
) -> AISuggestRuleResponse:
    """Parses analyst observation into structured candidate rule. Output is strictly validated as untrusted input."""
    return DetectionRuleLifecycleService.ai_suggest_rule(payload)


# ============================================================================
# 3. RULE DETAILS, VERSIONS & TUNING
# ============================================================================

@router.get(
    "/{rule_id}",
    response_model=DetectionRuleResponse,
    summary="Get detection rule by ID or Rule Identifier",
)
def get_detection_rule(
    rule_id: str,
    workspace_id: str = Query("default"),
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_analyst_or_admin),
) -> DetectionRuleResponse:
    eff_workspace = x_workspace_id or workspace_id
    rule = db.query(CandidateRuleModel).filter(
        CandidateRuleModel.workspace_id == eff_workspace,
        (CandidateRuleModel.id == rule_id) | (CandidateRuleModel.rule_identifier == rule_id),
    ).first()

    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Detection rule '{rule_id}' not found in workspace '{eff_workspace}'.",
        )
    return DetectionRuleLifecycleService.model_to_response(rule)


@router.post(
    "/{rule_id}/tune",
    response_model=DetectionRuleResponse,
    summary="Create a new tuned version (v_n+1) from an existing rule",
)
def tune_detection_rule(
    rule_id: str,
    payload: DetectionRuleTuneRequest,
    workspace_id: str = Query("default"),
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    x_user_id: Optional[str] = Header(None, alias="X-User-ID"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_analyst_or_admin),
) -> DetectionRuleResponse:
    eff_workspace = x_workspace_id or workspace_id
    actor = x_user_id or "analyst"
    rule = DetectionRuleLifecycleService.tune_rule(
        db=db,
        workspace_id=eff_workspace,
        rule_id=rule_id,
        req=payload,
        actor_id=actor,
    )
    return DetectionRuleLifecycleService.model_to_response(rule)


@router.get(
    "/{rule_id}/versions",
    summary="Get full version history for detection rule",
)
def get_rule_versions(
    rule_id: str,
    workspace_id: str = Query("default"),
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_analyst_or_admin),
) -> List[Dict[str, Any]]:
    eff_workspace = x_workspace_id or workspace_id
    rule = db.query(CandidateRuleModel).filter(
        CandidateRuleModel.workspace_id == eff_workspace,
        (CandidateRuleModel.id == rule_id) | (CandidateRuleModel.rule_identifier == rule_id),
    ).first()

    if not rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Rule '{rule_id}' not found.")

    versions = db.query(CandidateRuleVersionModel).filter(
        CandidateRuleVersionModel.candidate_rule_id == rule.id
    ).order_by(CandidateRuleVersionModel.version.desc()).all()

    return [
        {
            "id": v.id,
            "version": v.version,
            "rule_type": v.rule_type,
            "definition": v.definition,
            "severity": v.severity,
            "confidence": v.confidence,
            "cost_class": v.cost_class,
            "data_sources": v.data_sources,
            "diff_summary": v.diff_summary,
            "change_description": v.change_description,
            "created_by": v.created_by,
            "created_at": v.created_at.isoformat() if v.created_at else None,
        }
        for v in versions
    ]


@router.get(
    "/{rule_id}/diff/{v1}/{v2}",
    response_model=RuleVersionDiff,
    summary="Get visual structural diff between two rule versions",
)
def get_version_diff(
    rule_id: str,
    v1: int,
    v2: int,
    workspace_id: str = Query("default"),
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_analyst_or_admin),
) -> RuleVersionDiff:
    eff_workspace = x_workspace_id or workspace_id
    rule = db.query(CandidateRuleModel).filter(
        CandidateRuleModel.workspace_id == eff_workspace,
        (CandidateRuleModel.id == rule_id) | (CandidateRuleModel.rule_identifier == rule_id),
    ).first()

    if not rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Rule '{rule_id}' not found.")

    v1_row = db.query(CandidateRuleVersionModel).filter(
        CandidateRuleVersionModel.candidate_rule_id == rule.id,
        CandidateRuleVersionModel.version == v1,
    ).first()
    v2_row = db.query(CandidateRuleVersionModel).filter(
        CandidateRuleVersionModel.candidate_rule_id == rule.id,
        CandidateRuleVersionModel.version == v2,
    ).first()

    if not v1_row or not v2_row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Version comparison requested between v{v1} and v{v2}, but one or both versions do not exist.",
        )

    def1 = RuleDefinition.model_validate(v1_row.definition)
    def2 = RuleDefinition.model_validate(v2_row.definition)
    return DetectionRuleLifecycleService.compute_version_diff(def1, def2, v1, v2)


# ============================================================================
# 4. HISTORICAL BACKTESTING
# ============================================================================

@router.post(
    "/{rule_id}/backtest",
    response_model=DetectionRuleBacktestResponse,
    summary="Execute bounded read-only historical backtest against security telemetry",
)
def backtest_rule(
    rule_id: str,
    payload: DetectionRuleBacktestRequest,
    async_mode: bool = Query(False, description="Whether to enqueue execution via Section 45 Background Jobs"),
    workspace_id: str = Query("default"),
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    x_user_id: Optional[str] = Header(None, alias="X-User-ID"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_analyst_or_admin),
) -> DetectionRuleBacktestResponse:
    eff_workspace = x_workspace_id or workspace_id
    actor = x_user_id or "analyst"

    rule = db.query(CandidateRuleModel).filter(
        CandidateRuleModel.workspace_id == eff_workspace,
        (CandidateRuleModel.id == rule_id) | (CandidateRuleModel.rule_identifier == rule_id),
    ).first()

    if not rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Rule '{rule_id}' not found.")

    if async_mode:
        # Enqueue via Section 45 Background Job Worker
        job = BackgroundJobService.submit_job(
            db=db,
            req=JobSubmitRequest(
                job_type=JobTypeEnum.DETECTION_RULE_BACKTEST,
                workspace_id=eff_workspace,
                resource_type="DETECTION_RULE",
                resource_id=rule.id,
                priority=JobPriorityEnum.HIGH,
                payload={
                    "rule_id": rule.id,
                    "backtest_request": payload.model_dump(),
                    "user_id": actor,
                },
            ),
        )
        return DetectionRuleBacktestResponse(
            execution_id=job.id,
            rule_id=rule.id,
            rule_version=payload.version or rule.version,
            status="QUEUED",
            data_source=payload.data_source,
            time_range=payload.time_range_preset.value,
            records_evaluated=0,
            matches_count=0,
            duration_ms=0,
            matches=[],
            limitations=[f"Job enqueued with ID '{job.id}'. Check background jobs for progress."],
        )

    # Synchronous execution
    return DetectionRuleLifecycleService.backtest_rule(
        db=db,
        workspace_id=eff_workspace,
        rule_id=rule.id,
        req=payload,
        actor_id=actor,
    )


# ============================================================================
# 5. LIFECYCLE STATE MACHINE (REVIEW, APPROVAL, ACTIVATION, DISABLE)
# ============================================================================

@router.post(
    "/{rule_id}/transition",
    response_model=DetectionRuleResponse,
    summary="Transition detection rule lifecycle state",
)
def transition_rule_status(
    rule_id: str,
    target_status: RuleLifecycleStatus,
    reason: Optional[str] = Query(None),
    workspace_id: str = Query("default"),
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    x_user_id: Optional[str] = Header(None, alias="X-User-ID"),
    db: Session = Depends(get_db),
    role: str = Depends(verify_analyst_or_admin),
) -> DetectionRuleResponse:
    eff_workspace = x_workspace_id or workspace_id
    actor = x_user_id or "analyst"

    # Approvals and activations require specific approver validation
    if target_status in (RuleLifecycleStatus.APPROVED, RuleLifecycleStatus.ACTIVE):
        verify_approver_role(authorization=role)

    rule = DetectionRuleLifecycleService.transition_status(
        db=db,
        workspace_id=eff_workspace,
        rule_id=rule_id,
        target_status=target_status,
        actor_id=actor,
        reason=reason,
    )
    return DetectionRuleLifecycleService.model_to_response(rule)


@router.post(
    "/{rule_id}/approve",
    response_model=DetectionRuleResponse,
    summary="Approve detection rule (Enforces separation of duties: creator != approver)",
)
def approve_rule(
    rule_id: str,
    reason: Optional[str] = Query(None),
    workspace_id: str = Query("default"),
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    x_user_id: Optional[str] = Header(None, alias="X-User-ID"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_approver_role),
) -> DetectionRuleResponse:
    eff_workspace = x_workspace_id or workspace_id
    actor = x_user_id or "lead-analyst"
    rule = DetectionRuleLifecycleService.transition_status(
        db=db,
        workspace_id=eff_workspace,
        rule_id=rule_id,
        target_status=RuleLifecycleStatus.APPROVED,
        actor_id=actor,
        reason=reason or "Rule approved by security lead.",
    )
    return DetectionRuleLifecycleService.model_to_response(rule)


@router.post(
    "/{rule_id}/activate",
    response_model=DetectionRuleResponse,
    summary="Activate approved detection rule into production detection pipeline",
)
def activate_rule(
    rule_id: str,
    workspace_id: str = Query("default"),
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    x_user_id: Optional[str] = Header(None, alias="X-User-ID"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_approver_role),
) -> DetectionRuleResponse:
    eff_workspace = x_workspace_id or workspace_id
    actor = x_user_id or "lead-analyst"
    rule = DetectionRuleLifecycleService.transition_status(
        db=db,
        workspace_id=eff_workspace,
        rule_id=rule_id,
        target_status=RuleLifecycleStatus.ACTIVE,
        actor_id=actor,
        reason="Rule activated in live telemetry detection pipeline.",
    )
    return DetectionRuleLifecycleService.model_to_response(rule)


@router.post(
    "/{rule_id}/disable",
    response_model=DetectionRuleResponse,
    summary="Disable an active detection rule (Emergency or routine maintenance)",
)
def disable_rule(
    rule_id: str,
    reason: Optional[str] = Query("Disabled by security analyst"),
    workspace_id: str = Query("default"),
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    x_user_id: Optional[str] = Header(None, alias="X-User-ID"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_analyst_or_admin),
) -> DetectionRuleResponse:
    eff_workspace = x_workspace_id or workspace_id
    actor = x_user_id or "analyst"
    rule = DetectionRuleLifecycleService.transition_status(
        db=db,
        workspace_id=eff_workspace,
        rule_id=rule_id,
        target_status=RuleLifecycleStatus.DISABLED,
        actor_id=actor,
        reason=reason,
    )
    return DetectionRuleLifecycleService.model_to_response(rule)


@router.post(
    "/{rule_id}/retire",
    response_model=DetectionRuleResponse,
    summary="Retire or deprecate detection rule",
)
def retire_rule(
    rule_id: str,
    reason: Optional[str] = Query("Rule deprecated"),
    workspace_id: str = Query("default"),
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    x_user_id: Optional[str] = Header(None, alias="X-User-ID"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_analyst_or_admin),
) -> DetectionRuleResponse:
    eff_workspace = x_workspace_id or workspace_id
    actor = x_user_id or "analyst"
    rule = DetectionRuleLifecycleService.transition_status(
        db=db,
        workspace_id=eff_workspace,
        rule_id=rule_id,
        target_status=RuleLifecycleStatus.DEPRECATED,
        actor_id=actor,
        reason=reason,
    )
    return DetectionRuleLifecycleService.model_to_response(rule)


# ============================================================================
# 6. RUNTIME EVALUATION & FINDING INTEGRATION
# ============================================================================

@router.post(
    "/evaluate",
    summary="Evaluate incoming event telemetry against active detection rules",
)
def evaluate_event(
    event_payload: Dict[str, Any],
    data_source: RuleDataSource = Query(RuleDataSource.EMAIL_EVENT),
    workspace_id: str = Query("default"),
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_analyst_or_admin),
) -> List[Dict[str, Any]]:
    """Evaluates telemetry event against active rules and integrates matches with FindingModel."""
    eff_workspace = x_workspace_id or workspace_id
    matches = DetectionRuleLifecycleService.evaluate_event(
        db=db,
        workspace_id=eff_workspace,
        event_payload=event_payload,
        data_source=data_source,
    )
    return [m.model_dump() if hasattr(m, "model_dump") else m for m in matches]
