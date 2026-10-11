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
from backend.db.models import (
    CandidateRuleModel,
    CandidateRuleVersionModel,
    CandidateRuleExecutionModel,
    RuleSuppressionModel,
    DetectionValidationRunModel,
    DetectionValidationResultModel,
    DetectionRuleTestFixtureModel,
)
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
    DeploymentStateEnum,
    OperationalHealthEnum,
    RuleDependency,
    RuleSuppressionCreateRequest,
    RuleSuppressionResponse,
    RuleDeploymentRequest,
    RuleRollbackRequest,
    EmergencyDisableRequest,
    DeploymentDryRunResponse,
    RuleSimulationRequest,
    RuleSimulationResponse,
    RuleOwnershipUpdateRequest,
    MatchDispositionRequest,
    MatchDispositionEnum,
    RuleQualityMetricsResponse,
    RuleOperationalHealthResponse,
    BulkRuleOperationRequest,
    BulkRuleOperationResponse,
    OperationalOverviewResponse,
    ValidationStatusEnum,
    ValidationTypeEnum,
    ValidationTriggerEnum,
    ValidationRunRequest,
    ValidationRunResponse,
    DeploymentGateCheckResponse,
    TestFixtureCreateRequest,
    TestFixtureResponse,
    ValidationOverviewStats,
)
from backend.schemas.candidate_rules import RuleLifecycleStatus, RuleSeverity
from backend.schemas.jobs import JobSubmitRequest, JobTypeEnum, JobPriorityEnum
from backend.services.background_job_service import BackgroundJobService
from backend.services.detection_rule_lifecycle_service import DetectionRuleLifecycleService
from backend.services.detection_rule_management_service import DetectionRuleManagementService
from backend.services.detection_rule_validation_service import DetectionRuleValidationService


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
    "/overview",
    response_model=OperationalOverviewResponse,
    summary="Get SOC Operational Overview and Health Metrics across Detection Rules",
)
def get_operational_overview(
    workspace_id: str = Query("default"),
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_analyst_or_admin),
) -> OperationalOverviewResponse:
    eff_workspace = x_workspace_id or workspace_id
    return DetectionRuleManagementService.get_operational_overview(db, eff_workspace)


@router.get(
    "",
    response_model=DetectionRuleListResponse,
    summary="List detection rules with server-side search, deployment state, health, owner, category, and source filtering",
)
def list_detection_rules(
    workspace_id: str = Query("default"),
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    category: Optional[RuleCategory] = Query(None),
    status: Optional[RuleLifecycleStatus] = Query(None),
    severity: Optional[RuleSeverity] = Query(None),
    data_source: Optional[RuleDataSource] = Query(None),
    provenance_type: Optional[RuleProvenanceType] = Query(None),
    deployment_state: Optional[DeploymentStateEnum] = Query(None),
    operational_health: Optional[OperationalHealthEnum] = Query(None),
    owner_id: Optional[str] = Query(None),
    team_id: Optional[str] = Query(None),
    collection: Optional[str] = Query(None),
    is_stale: Optional[bool] = Query(None),
    review_due: Optional[bool] = Query(None),
    search: Optional[str] = Query(None),
    sort_by: str = Query("updated_at"),
    sort_desc: bool = Query(True),
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
    if deployment_state:
        query = query.filter(CandidateRuleModel.deployment_state == deployment_state.value)
    if operational_health:
        query = query.filter(CandidateRuleModel.operational_health == operational_health.value)
    if owner_id:
        query = query.filter(CandidateRuleModel.owner_id == owner_id)
    if team_id:
        query = query.filter(CandidateRuleModel.team_id == team_id)
    if collection:
        query = query.filter(CandidateRuleModel.collections_json.contains(f'"{collection}"'))
    if review_due is True:
        from backend.db.models import get_utc_now
        query = query.filter(CandidateRuleModel.next_review_due <= get_utc_now())
    if is_stale is True:
        from datetime import datetime, timedelta
        from backend.db.models import get_utc_now
        threshold = get_utc_now() - timedelta(days=60)
        query = query.filter(CandidateRuleModel.updated_at <= threshold, CandidateRuleModel.total_match_count == 0)
    if data_source:
        query = query.filter(CandidateRuleModel.data_sources_json.contains(f'"{data_source.value}"'))
    if search:
        search_term = f"%{search.strip()}%"
        query = query.filter(
            (CandidateRuleModel.name.ilike(search_term))
            | (CandidateRuleModel.rule_identifier.ilike(search_term))
            | (CandidateRuleModel.description.ilike(search_term))
            | (CandidateRuleModel.tags_json.ilike(search_term))
            | (CandidateRuleModel.owner_id.ilike(search_term))
        )

    # Sorting
    if sort_by == "name":
        order_col = CandidateRuleModel.name
    elif sort_by == "created_at":
        order_col = CandidateRuleModel.created_at
    elif sort_by == "total_match_count":
        order_col = CandidateRuleModel.total_match_count
    elif sort_by == "complexity_score":
        order_col = CandidateRuleModel.complexity_score
    else:
        order_col = CandidateRuleModel.updated_at

    if sort_desc:
        query = query.order_by(order_col.desc())
    else:
        query = query.order_by(order_col.asc())

    total = query.count()
    rules = query.offset(offset).limit(limit).all()

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
    actual_event = event_payload.get("event_payload") if (isinstance(event_payload, dict) and isinstance(event_payload.get("event_payload"), dict)) else event_payload
    matches = DetectionRuleLifecycleService.evaluate_event(
        db=db,
        workspace_id=eff_workspace,
        event_payload=actual_event,
        data_source=data_source,
    )
    return [m.model_dump() if hasattr(m, "model_dump") else m for m in matches]


# ============================================================================
# 7. SECTION 57: OPERATIONAL CONTROL, DEPLOYMENT, HEALTH, & QUALITY APIS
# ============================================================================

@router.get(
    "/{rule_id}/health",
    response_model=RuleOperationalHealthResponse,
    summary="Get rule operational health, dependency status, error rates, and match anomalies",
)
def get_rule_health(
    rule_id: str,
    workspace_id: str = Query("default"),
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_analyst_or_admin),
) -> RuleOperationalHealthResponse:
    eff_workspace = x_workspace_id or workspace_id
    return DetectionRuleManagementService.evaluate_rule_health(db, rule_id, eff_workspace)


@router.post(
    "/{rule_id}/health/evaluate",
    response_model=RuleOperationalHealthResponse,
    summary="Trigger on-demand operational health re-evaluation for rule",
)
def evaluate_rule_health_on_demand(
    rule_id: str,
    workspace_id: str = Query("default"),
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_analyst_or_admin),
) -> RuleOperationalHealthResponse:
    eff_workspace = x_workspace_id or workspace_id
    return DetectionRuleManagementService.evaluate_rule_health(db, rule_id, eff_workspace)


@router.post(
    "/{rule_id}/deploy",
    response_model=DetectionRuleResponse,
    summary="Promote detection rule to STAGING or PRODUCTION environment",
)
def deploy_rule(
    rule_id: str,
    payload: RuleDeploymentRequest,
    workspace_id: str = Query("default"),
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    x_user_id: Optional[str] = Header(None, alias="X-User-ID"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_approver_role),
) -> DetectionRuleResponse:
    eff_workspace = x_workspace_id or workspace_id
    actor = x_user_id or "lead-analyst"
    rule = DetectionRuleManagementService.deploy_rule(
        db=db,
        rule_id=rule_id,
        req=payload,
        actor=actor,
        workspace_id=eff_workspace,
        actor_role=_role,
    )
    return DetectionRuleLifecycleService.model_to_response(rule)


@router.post(
    "/{rule_id}/dry-run",
    response_model=DeploymentDryRunResponse,
    summary="Pre-flight deployment dry-run check (validation, dependencies, risk calculation)",
)
def dry_run_deployment(
    rule_id: str,
    target_version: Optional[str] = Query(None),
    workspace_id: str = Query("default"),
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_analyst_or_admin),
) -> DeploymentDryRunResponse:
    eff_workspace = x_workspace_id or workspace_id
    return DetectionRuleManagementService.dry_run_deployment(
        db=db,
        rule_id=rule_id,
        target_version=target_version,
        workspace_id=eff_workspace,
    )


@router.post(
    "/{rule_id}/rollback",
    response_model=DetectionRuleResponse,
    summary="Roll back rule to target validated immutable version",
)
def rollback_rule(
    rule_id: str,
    payload: RuleRollbackRequest,
    workspace_id: str = Query("default"),
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    x_user_id: Optional[str] = Header(None, alias="X-User-ID"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_approver_role),
) -> DetectionRuleResponse:
    eff_workspace = x_workspace_id or workspace_id
    actor = x_user_id or "lead-analyst"
    rule = DetectionRuleManagementService.rollback_rule(
        db=db,
        rule_id=rule_id,
        req=payload,
        actor=actor,
        workspace_id=eff_workspace,
    )
    return DetectionRuleLifecycleService.model_to_response(rule)


@router.post(
    "/{rule_id}/emergency-disable",
    response_model=DetectionRuleResponse,
    summary="Emergency disable noisy or failing detection rule with elevated authorization and required reason",
)
def emergency_disable(
    rule_id: str,
    payload: EmergencyDisableRequest,
    workspace_id: str = Query("default"),
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    x_user_id: Optional[str] = Header(None, alias="X-User-ID"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_approver_role),
) -> DetectionRuleResponse:
    eff_workspace = x_workspace_id or workspace_id
    actor = x_user_id or "security-lead"
    rule = DetectionRuleManagementService.emergency_disable(
        db=db,
        rule_id=rule_id,
        req=payload,
        actor=actor,
        workspace_id=eff_workspace,
    )
    return DetectionRuleLifecycleService.model_to_response(rule)


@router.post(
    "/{rule_id}/simulate",
    response_model=RuleSimulationResponse,
    summary="Execute isolated read-only simulation mode against recent telemetry without alerts",
)
def simulate_rule(
    rule_id: str,
    payload: RuleSimulationRequest,
    workspace_id: str = Query("default"),
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_analyst_or_admin),
) -> RuleSimulationResponse:
    eff_workspace = x_workspace_id or workspace_id
    return DetectionRuleManagementService.simulate_rule(
        db=db,
        rule_id=rule_id,
        req=payload,
        workspace_id=eff_workspace,
    )


@router.post(
    "/{rule_id}/ownership",
    response_model=DetectionRuleResponse,
    summary="Update rule ownership, SOC team assignment, and review cadence",
)
def update_rule_ownership(
    rule_id: str,
    payload: RuleOwnershipUpdateRequest,
    workspace_id: str = Query("default"),
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    x_user_id: Optional[str] = Header(None, alias="X-User-ID"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_analyst_or_admin),
) -> DetectionRuleResponse:
    eff_workspace = x_workspace_id or workspace_id
    actor = x_user_id or "analyst"
    rule = db.query(CandidateRuleModel).filter(
        CandidateRuleModel.workspace_id == eff_workspace,
        (CandidateRuleModel.id == rule_id) | (CandidateRuleModel.rule_identifier == rule_id),
    ).first()

    if not rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Rule '{rule_id}' not found.")

    old_owner = rule.owner_id
    old_team = rule.team_id
    rule.owner_id = payload.owner_id
    if payload.team_id is not None:
        rule.team_id = payload.team_id
    if payload.review_interval_days:
        rule.review_interval_days = payload.review_interval_days
        from backend.db.models import get_utc_now
        from datetime import timedelta
        rule.next_review_due = get_utc_now() + timedelta(days=payload.review_interval_days)

    rule.last_editor_id = actor
    db.commit()

    DetectionRuleManagementService._log_audit(
        db=db,
        workspace_id=eff_workspace,
        actor=actor,
        action="RULE_OWNERSHIP_UPDATED",
        resource_id=rule.id,
        details={
            "old_owner": old_owner,
            "new_owner": payload.owner_id,
            "old_team": old_team,
            "new_team": payload.team_id,
        },
    )

    return DetectionRuleLifecycleService.model_to_response(rule)


@router.get(
    "/{rule_id}/suppressions",
    response_model=List[RuleSuppressionResponse],
    summary="List active and expired suppression exceptions for detection rule",
)
def list_rule_suppressions(
    rule_id: str,
    workspace_id: str = Query("default"),
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_analyst_or_admin),
) -> List[RuleSuppressionResponse]:
    eff_workspace = x_workspace_id or workspace_id
    suppressions = DetectionRuleManagementService.list_suppressions(db, rule_id, eff_workspace)
    return [RuleSuppressionResponse.model_validate(s) for s in suppressions]


@router.post(
    "/{rule_id}/suppressions",
    response_model=RuleSuppressionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create scoped time-bounded suppression exception for false positives without disabling rule",
)
def create_rule_suppression(
    rule_id: str,
    payload: RuleSuppressionCreateRequest,
    workspace_id: str = Query("default"),
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    x_user_id: Optional[str] = Header(None, alias="X-User-ID"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_analyst_or_admin),
) -> RuleSuppressionResponse:
    eff_workspace = x_workspace_id or workspace_id
    actor = x_user_id or "analyst"
    supp = DetectionRuleManagementService.create_suppression(
        db=db,
        rule_id=rule_id,
        req=payload,
        actor=actor,
        workspace_id=eff_workspace,
    )
    return RuleSuppressionResponse.model_validate(supp)


@router.delete(
    "/{rule_id}/suppressions/{suppression_id}",
    summary="Delete or deactivate suppression exception",
)
def delete_rule_suppression(
    rule_id: str,
    suppression_id: str,
    workspace_id: str = Query("default"),
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    x_user_id: Optional[str] = Header(None, alias="X-User-ID"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_analyst_or_admin),
) -> Dict[str, Any]:
    eff_workspace = x_workspace_id or workspace_id
    actor = x_user_id or "analyst"
    DetectionRuleManagementService.delete_suppression(
        db=db,
        rule_id=rule_id,
        suppression_id=suppression_id,
        actor=actor,
        workspace_id=eff_workspace,
    )
    return {"status": "DELETED", "suppression_id": suppression_id}


@router.post(
    "/matches/{execution_id}/disposition",
    summary="Record ground-truth analyst feedback disposition on detection match",
)
def record_match_disposition(
    execution_id: str,
    payload: MatchDispositionRequest,
    workspace_id: str = Query("default"),
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    x_user_id: Optional[str] = Header(None, alias="X-User-ID"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_analyst_or_admin),
) -> Dict[str, Any]:
    eff_workspace = x_workspace_id or workspace_id
    actor = x_user_id or "analyst"
    rec = DetectionRuleManagementService.record_match_disposition(
        db=db,
        execution_id=execution_id,
        req=payload,
        actor=actor,
        workspace_id=eff_workspace,
    )
    return {
        "execution_id": rec.id,
        "disposition": rec.disposition,
        "disposition_by": rec.disposition_by,
        "is_false_positive": rec.is_false_positive,
    }


@router.get(
    "/{rule_id}/quality",
    response_model=RuleQualityMetricsResponse,
    summary="Get aggregated false-positive feedback and detection quality signals",
)
def get_rule_quality(
    rule_id: str,
    workspace_id: str = Query("default"),
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_analyst_or_admin),
) -> RuleQualityMetricsResponse:
    eff_workspace = x_workspace_id or workspace_id
    return DetectionRuleManagementService.get_rule_quality_metrics(db, rule_id, eff_workspace)


@router.get(
    "/{rule_id}/duplicates",
    summary="Detect potential duplicate and near-duplicate detection rules using normalized AST fingerprints",
)
def get_rule_duplicates(
    rule_id: str,
    workspace_id: str = Query("default"),
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_analyst_or_admin),
) -> List[Dict[str, Any]]:
    eff_workspace = x_workspace_id or workspace_id
    return DetectionRuleManagementService.find_duplicate_rules(db, rule_id, eff_workspace)


@router.get(
    "/{rule_id}/conflicts",
    summary="Detect potential semantic rule and suppression conflicts",
)
def get_rule_conflicts(
    rule_id: str,
    workspace_id: str = Query("default"),
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_analyst_or_admin),
) -> List[Dict[str, Any]]:
    eff_workspace = x_workspace_id or workspace_id
    return DetectionRuleManagementService.find_conflicting_rules(db, rule_id, eff_workspace)


@router.get(
    "/{rule_id}/matches",
    summary="List recent execution matches with links to Finding, Alert, and Incident records",
)
def get_rule_recent_matches(
    rule_id: str,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    workspace_id: str = Query("default"),
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_analyst_or_admin),
) -> Dict[str, Any]:
    eff_workspace = x_workspace_id or workspace_id
    rule = db.query(CandidateRuleModel).filter(
        CandidateRuleModel.workspace_id == eff_workspace,
        (CandidateRuleModel.id == rule_id) | (CandidateRuleModel.rule_identifier == rule_id),
    ).first()

    if not rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Rule '{rule_id}' not found.")

    query = db.query(CandidateRuleExecutionModel).filter(
        CandidateRuleExecutionModel.workspace_id == eff_workspace,
        CandidateRuleExecutionModel.rule_id == rule.id,
        CandidateRuleExecutionModel.matched.is_(True),
    )

    total = query.count()
    rows = query.order_by(CandidateRuleExecutionModel.executed_at.desc()).offset(offset).limit(limit).all()

    matches_data = []
    for r in rows:
        matches_data.append({
            "id": r.id,
            "rule_id": r.rule_id,
            "rule_version": r.rule_version,
            "mode": r.mode,
            "detection_id": r.detection_id,
            "finding_id": r.finding_id,
            "event_id": r.event_id,
            "incident_id": r.incident_id,
            "execution_time_ms": r.execution_time_ms,
            "disposition": r.disposition,
            "disposition_by": r.disposition_by,
            "disposition_at": r.disposition_at.isoformat() if r.disposition_at else None,
            "suppression_applied_id": r.suppression_applied_id,
            "matched_conditions": r.matched_conditions,
            "match_explanation": r.match_explanation,
            "executed_at": r.executed_at.isoformat() if r.executed_at else None,
        })

    return {
        "rule_id": rule.id,
        "rule_identifier": rule.rule_identifier,
        "total": total,
        "items": matches_data,
    }


@router.post(
    "/bulk",
    response_model=BulkRuleOperationResponse,
    summary="Execute bulk operations across detection rules (ENABLE, DISABLE, ASSIGN_OWNER, SET_COLLECTION, etc.)",
)
def bulk_rule_operation(
    payload: BulkRuleOperationRequest,
    workspace_id: str = Query("default"),
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    x_user_id: Optional[str] = Header(None, alias="X-User-ID"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_approver_role),
) -> BulkRuleOperationResponse:
    eff_workspace = x_workspace_id or workspace_id
    actor = x_user_id or "lead-analyst"
    return DetectionRuleManagementService.execute_bulk_operation(
        db=db,
        req=payload,
        actor=actor,
        workspace_id=eff_workspace,
    )


@router.get(
    "/{rule_id}/hunt-pattern",
    summary="Export structured detection logic to Section 54/55 Threat Hunt pattern for SOC pivoting",
)
def hunt_rule_pattern(
    rule_id: str,
    workspace_id: str = Query("default"),
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_analyst_or_admin),
) -> Dict[str, Any]:
    eff_workspace = x_workspace_id or workspace_id
    return DetectionRuleManagementService.hunt_rule_pattern(db, rule_id, eff_workspace)


# ============================================================================
# SECTION 58: AUTOMATED DETECTION VALIDATION & CONTINUOUS QUALITY ROUTES
# ============================================================================

@router.get(
    "/validation/overview",
    response_model=ValidationOverviewStats,
    summary="Get SOC-wide continuous detection validation overview and drift metrics",
)
def get_validation_overview(
    workspace_id: str = Query("default"),
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_analyst_or_admin),
) -> ValidationOverviewStats:
    eff_workspace = x_workspace_id or workspace_id
    return DetectionRuleValidationService.get_validation_overview(db, eff_workspace)


@router.get(
    "/validation/runs/{run_id}",
    response_model=ValidationRunResponse,
    summary="Get detailed validation run results and check evidence",
)
def get_validation_run_details(
    run_id: str,
    workspace_id: str = Query("default"),
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_analyst_or_admin),
) -> ValidationRunResponse:
    eff_workspace = x_workspace_id or workspace_id
    run = db.query(DetectionValidationRunModel).filter(
        DetectionValidationRunModel.id == run_id,
        DetectionValidationRunModel.workspace_id == eff_workspace,
    ).first()
    if not run:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Validation run '{run_id}' not found.")
    return DetectionRuleValidationService._to_response(run)


@router.post(
    "/validation/runs/{run_id}/cancel",
    response_model=ValidationRunResponse,
    summary="Cancel an active or queued detection validation run",
)
def cancel_validation_run(
    run_id: str,
    workspace_id: str = Query("default"),
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    x_user_id: Optional[str] = Header(None, alias="X-User-ID"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_analyst_or_admin),
) -> ValidationRunResponse:
    eff_workspace = x_workspace_id or workspace_id
    actor = x_user_id or "analyst"
    return DetectionRuleValidationService.cancel_validation_run(db, run_id, actor, eff_workspace)


@router.post(
    "/{rule_id}/validation",
    response_model=ValidationRunResponse,
    summary="Trigger an automated multi-dimensional validation run for a detection rule",
)
def trigger_rule_validation(
    rule_id: str,
    payload: ValidationRunRequest,
    workspace_id: str = Query("default"),
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    x_user_id: Optional[str] = Header(None, alias="X-User-ID"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_analyst_or_admin),
) -> ValidationRunResponse:
    eff_workspace = x_workspace_id or workspace_id
    actor = x_user_id or "analyst"
    # Resolve rule identifier or UUID
    rule = db.query(CandidateRuleModel).filter(
        CandidateRuleModel.workspace_id == eff_workspace,
        (CandidateRuleModel.id == rule_id) | (CandidateRuleModel.rule_identifier == rule_id),
    ).first()
    if not rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Rule '{rule_id}' not found.")

    return DetectionRuleValidationService.request_validation_run(
        db=db,
        rule_id=rule.id,
        req=payload,
        actor=actor,
        workspace_id=eff_workspace,
    )


@router.get(
    "/{rule_id}/validation",
    response_model=ValidationRunResponse,
    summary="Get latest validation run for a detection rule",
)
def get_latest_rule_validation(
    rule_id: str,
    version: Optional[str] = Query(None, description="Optional target version to check"),
    workspace_id: str = Query("default"),
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_analyst_or_admin),
) -> ValidationRunResponse:
    eff_workspace = x_workspace_id or workspace_id
    rule = db.query(CandidateRuleModel).filter(
        CandidateRuleModel.workspace_id == eff_workspace,
        (CandidateRuleModel.id == rule_id) | (CandidateRuleModel.rule_identifier == rule_id),
    ).first()
    if not rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Rule '{rule_id}' not found.")

    target_ver = version or rule.version
    run = db.query(DetectionValidationRunModel).filter(
        DetectionValidationRunModel.rule_id == rule.id,
        DetectionValidationRunModel.workspace_id == eff_workspace,
        DetectionValidationRunModel.rule_version == target_ver,
    ).order_by(desc(DetectionValidationRunModel.created_at)).first()

    if not run:
        # Return synthetic empty NOT_RUN response
        return ValidationRunResponse(
            id=f"not-run-{rule.id}",
            workspace_id=eff_workspace,
            rule_id=rule.id,
            rule_version=target_ver,
            validation_type=ValidationTypeEnum.FULL,
            status=ValidationStatusEnum.NOT_RUN,
            trigger_type=ValidationTriggerEnum.MANUAL,
            requested_by="system",
            summary={"message": "No validation run has been executed for this rule version."},
            checks=[],
            recommendations=["Run validation prior to promotion or deployment."],
            created_at=rule.created_at,
        )

    return DetectionRuleValidationService._to_response(run)


@router.get(
    "/{rule_id}/validation/gate",
    response_model=DeploymentGateCheckResponse,
    summary="Evaluate production deployment gate conditions for detection rule",
)
def check_rule_deployment_gate(
    rule_id: str,
    version: Optional[str] = Query(None, description="Optional version to test gate against"),
    workspace_id: str = Query("default"),
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_analyst_or_admin),
) -> DeploymentGateCheckResponse:
    eff_workspace = x_workspace_id or workspace_id
    rule = db.query(CandidateRuleModel).filter(
        CandidateRuleModel.workspace_id == eff_workspace,
        (CandidateRuleModel.id == rule_id) | (CandidateRuleModel.rule_identifier == rule_id),
    ).first()
    if not rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Rule '{rule_id}' not found.")

    target_ver = version or rule.version
    return DetectionRuleValidationService.check_deployment_gate(
        db=db,
        rule_id=rule.id,
        target_version=target_ver,
        workspace_id=eff_workspace,
    )


@router.get(
    "/{rule_id}/validation/history",
    response_model=List[ValidationRunResponse],
    summary="Get paginated history of validation runs for a detection rule",
)
def get_rule_validation_history(
    rule_id: str,
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    workspace_id: str = Query("default"),
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_analyst_or_admin),
) -> List[ValidationRunResponse]:
    eff_workspace = x_workspace_id or workspace_id
    rule = db.query(CandidateRuleModel).filter(
        CandidateRuleModel.workspace_id == eff_workspace,
        (CandidateRuleModel.id == rule_id) | (CandidateRuleModel.rule_identifier == rule_id),
    ).first()
    if not rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Rule '{rule_id}' not found.")

    runs = db.query(DetectionValidationRunModel).filter(
        DetectionValidationRunModel.rule_id == rule.id,
        DetectionValidationRunModel.workspace_id == eff_workspace,
    ).order_by(desc(DetectionValidationRunModel.created_at)).offset(offset).limit(limit).all()

    return [DetectionRuleValidationService._to_response(r) for r in runs]


@router.get(
    "/{rule_id}/fixtures",
    response_model=List[TestFixtureResponse],
    summary="List positive and negative test fixtures for a detection rule",
)
def list_rule_fixtures(
    rule_id: str,
    workspace_id: str = Query("default"),
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_analyst_or_admin),
) -> List[TestFixtureResponse]:
    eff_workspace = x_workspace_id or workspace_id
    rule = db.query(CandidateRuleModel).filter(
        CandidateRuleModel.workspace_id == eff_workspace,
        (CandidateRuleModel.id == rule_id) | (CandidateRuleModel.rule_identifier == rule_id),
    ).first()
    if not rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Rule '{rule_id}' not found.")

    return DetectionRuleValidationService.list_fixtures(db, rule.id, eff_workspace)


@router.post(
    "/{rule_id}/fixtures",
    response_model=TestFixtureResponse,
    summary="Create a deterministic positive or negative test fixture for a detection rule",
)
def create_rule_fixture(
    rule_id: str,
    payload: TestFixtureCreateRequest,
    workspace_id: str = Query("default"),
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    x_user_id: Optional[str] = Header(None, alias="X-User-ID"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_analyst_or_admin),
) -> TestFixtureResponse:
    eff_workspace = x_workspace_id or workspace_id
    actor = x_user_id or "analyst"
    rule = db.query(CandidateRuleModel).filter(
        CandidateRuleModel.workspace_id == eff_workspace,
        (CandidateRuleModel.id == rule_id) | (CandidateRuleModel.rule_identifier == rule_id),
    ).first()
    if not rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Rule '{rule_id}' not found.")

    return DetectionRuleValidationService.create_fixture(
        db=db,
        rule_id=rule.id,
        req=payload,
        actor=actor,
        workspace_id=eff_workspace,
    )


@router.delete(
    "/{rule_id}/fixtures/{fixture_id}",
    summary="Delete a detection rule test fixture",
)
def delete_rule_fixture(
    rule_id: str,
    fixture_id: str,
    workspace_id: str = Query("default"),
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    x_user_id: Optional[str] = Header(None, alias="X-User-ID"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_analyst_or_admin),
) -> Dict[str, Any]:
    eff_workspace = x_workspace_id or workspace_id
    actor = x_user_id or "analyst"
    success = DetectionRuleValidationService.delete_fixture(db, fixture_id, actor, eff_workspace)
    return {"success": success, "fixture_id": fixture_id}


@router.post(
    "/{rule_id}/fixtures/{fixture_id}/run",
    response_model=TestFixtureResponse,
    summary="Execute an individual test fixture against detection rule definition",
)
def run_rule_fixture(
    rule_id: str,
    fixture_id: str,
    workspace_id: str = Query("default"),
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_analyst_or_admin),
) -> TestFixtureResponse:
    eff_workspace = x_workspace_id or workspace_id
    return DetectionRuleValidationService.run_fixture(db, fixture_id, eff_workspace)


