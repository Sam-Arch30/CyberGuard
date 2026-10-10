"""
Section 51: REST API Routes for Incident SLA, Escalation & Workflow Automation.
Provides endpoints for:
- Operational incident SLA clocks, status, and milestone deadlines
- Manual escalation, pause, resume, and exemption
- Workflow history and execution auditing
- Settings management: SLA Policies, Escalation Policies, and Routing Rules
- Policy dry-run simulation
"""
from datetime import datetime, timezone
from typing import List, Optional
import json
import uuid

from fastapi import APIRouter, Body, Depends, Header, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.db.models import (
    IncidentSLAPolicyModel,
    IncidentEscalationPolicyModel,
    IncidentEscalationRuleModel,
    IncidentRoutingRuleModel,
    IncidentModel,
    get_utc_now,
)
from backend.schemas.sla import (
    EscalationPolicyCreateRequest,
    EscalationPolicyListResponse,
    EscalationPolicyResponse,
    EscalationPolicyUpdateRequest,
    EscalationRuleResponse,
    IncidentEscalateRequest,
    IncidentSLADetailResponse,
    PolicySimulationRequest,
    PolicySimulationResponse,
    RoutingRuleCreateRequest,
    RoutingRuleListResponse,
    RoutingRuleResponse,
    RoutingRuleUpdateRequest,
    SLAExemptRequest,
    SLAPauseRequest,
    SLAPolicyCreateRequest,
    SLAPolicyListResponse,
    SLAPolicyResponse,
    SLAPolicyUpdateRequest,
    SLAResumeRequest,
    WorkflowHistoryResponse,
)
from backend.services.audit_service import AuditService
from backend.services.sla_service import IncidentSLAService

router = APIRouter(prefix="/api", tags=["Incident SLA & Workflow Automation"])


# ============================================================================
# DEPENDENCIES
# ============================================================================

def get_current_workspace(
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID")
) -> str:
    return x_workspace_id or "default"


def get_current_actor(
    x_user: Optional[str] = Header(None, alias="X-User"),
    x_analyst: Optional[str] = Header(None, alias="X-Analyst-Name"),
) -> str:
    return x_user or x_analyst or "SOC Analyst"


def verify_role(
    x_role: Optional[str] = Header(None, alias="X-Role"),
    x_user_role: Optional[str] = Header(None, alias="X-User-Role"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
) -> str:
    role = (x_role or x_user_role or "").strip().lower()
    if not role and authorization:
        auth_clean = authorization.strip().lower()
        if "admin" in auth_clean:
            role = "admin"
        elif "lead" in auth_clean or "manager" in auth_clean:
            role = "security_lead"
        elif "analyst" in auth_clean:
            role = "analyst"
    return role or "analyst"


def require_admin_or_lead(role: str = Depends(verify_role)) -> str:
    if role not in ("admin", "superuser", "security_lead", "soc_lead", "manager"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrative or SOC Lead privileges required for policy management.",
        )
    return role


# ============================================================================
# INCIDENT SLA OPERATIONAL ENDPOINTS
# ============================================================================

@router.get(
    "/incidents/{incident_id}/sla",
    response_model=IncidentSLADetailResponse,
    summary="Get operational SLA clocks, deadlines, and status for an incident",
)
def get_incident_sla_endpoint(
    incident_id: str,
    workspace_id: str = Depends(get_current_workspace),
    db: Session = Depends(get_db),
):
    return IncidentSLAService.get_incident_sla_detail(db, incident_id=incident_id, workspace_id=workspace_id)


@router.post(
    "/incidents/{incident_id}/sla/pause",
    response_model=IncidentSLADetailResponse,
    summary="Pause SLA clock with mandatory authorization reason",
)
def pause_incident_sla_endpoint(
    incident_id: str,
    req: SLAPauseRequest,
    workspace_id: str = Depends(get_current_workspace),
    actor: str = Depends(get_current_actor),
    db: Session = Depends(get_db),
):
    IncidentSLAService.pause_sla(
        db,
        incident_id=incident_id,
        actor=actor,
        reason=req.reason,
        workspace_id=workspace_id,
    )
    return IncidentSLAService.get_incident_sla_detail(db, incident_id=incident_id, workspace_id=workspace_id)


@router.post(
    "/incidents/{incident_id}/sla/resume",
    response_model=IncidentSLADetailResponse,
    summary="Resume a paused incident SLA clock",
)
def resume_incident_sla_endpoint(
    incident_id: str,
    req: Optional[SLAResumeRequest] = Body(default=None),
    workspace_id: str = Depends(get_current_workspace),
    actor: str = Depends(get_current_actor),
    db: Session = Depends(get_db),
):
    reason = req.reason if req else None
    IncidentSLAService.resume_sla(
        db,
        incident_id=incident_id,
        actor=actor,
        reason=reason,
        workspace_id=workspace_id,
    )
    return IncidentSLAService.get_incident_sla_detail(db, incident_id=incident_id, workspace_id=workspace_id)


@router.post(
    "/incidents/{incident_id}/sla/exempt",
    response_model=IncidentSLADetailResponse,
    summary="Mark an incident SLA as EXEMPT (authorized lead/admin only)",
)
def exempt_incident_sla_endpoint(
    incident_id: str,
    req: SLAExemptRequest,
    workspace_id: str = Depends(get_current_workspace),
    actor: str = Depends(get_current_actor),
    _role: str = Depends(require_admin_or_lead),
    db: Session = Depends(get_db),
):
    IncidentSLAService.exempt_sla(
        db,
        incident_id=incident_id,
        actor=actor,
        reason=req.reason,
        workspace_id=workspace_id,
    )
    return IncidentSLAService.get_incident_sla_detail(db, incident_id=incident_id, workspace_id=workspace_id)


@router.post(
    "/incidents/{incident_id}/escalate",
    response_model=IncidentSLADetailResponse,
    summary="Manually escalate an incident to the next tier or specified level",
)
def escalate_incident_endpoint(
    incident_id: str,
    req: IncidentEscalateRequest,
    workspace_id: str = Depends(get_current_workspace),
    actor: str = Depends(get_current_actor),
    db: Session = Depends(get_db),
):
    IncidentSLAService.manual_escalate(
        db,
        incident_id=incident_id,
        actor=actor,
        reason=req.reason,
        workspace_id=workspace_id,
        target_level=req.target_level,
        target_user=req.target_user,
        target_team=req.target_team,
    )
    return IncidentSLAService.get_incident_sla_detail(db, incident_id=incident_id, workspace_id=workspace_id)


@router.post(
    "/incidents/{incident_id}/sla/evaluate",
    response_model=IncidentSLADetailResponse,
    summary="Force on-demand SLA clock evaluation and synchronization",
)
def evaluate_incident_sla_endpoint(
    incident_id: str,
    workspace_id: str = Depends(get_current_workspace),
    db: Session = Depends(get_db),
):
    IncidentSLAService.evaluate_incident(db, incident_id=incident_id, workspace_id=workspace_id)
    return IncidentSLAService.get_incident_sla_detail(db, incident_id=incident_id, workspace_id=workspace_id)


@router.post(
    "/incidents/{incident_id}/route",
    summary="Apply automated routing rules to an incident",
)
def route_incident_endpoint(
    incident_id: str,
    workspace_id: str = Depends(get_current_workspace),
    db: Session = Depends(get_db),
):
    inc = db.query(IncidentModel).filter(
        IncidentModel.id == incident_id,
        IncidentModel.workspace_id == workspace_id,
    ).first()
    if not inc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Incident '{incident_id}' not found.")
    assigned = IncidentSLAService.route_incident(db, inc, workspace_id, trigger="MANUAL_ENDPOINT")
    return {
        "incident_id": inc.id,
        "assigned_to": inc.assigned_to,
        "team_id": inc.team_id,
        "routed": bool(assigned[0] or assigned[1]) if assigned else False,
    }


@router.get(
    "/incidents/{incident_id}/workflow-history",
    response_model=WorkflowHistoryResponse,
    summary="Retrieve workflow execution log, pause history, and escalation audit records",
)
def get_workflow_history_endpoint(
    incident_id: str,
    workspace_id: str = Depends(get_current_workspace),
    db: Session = Depends(get_db),
):
    return IncidentSLAService.get_workflow_history(db, incident_id=incident_id, workspace_id=workspace_id)


# ============================================================================
# SETTINGS: SLA POLICIES MANAGEMENT
# ============================================================================

@router.get(
    "/settings/sla-policies",
    response_model=SLAPolicyListResponse,
    summary="List configured SLA policies for workspace",
)
def list_sla_policies_endpoint(
    workspace_id: str = Depends(get_current_workspace),
    db: Session = Depends(get_db),
):
    IncidentSLAService.ensure_default_policies(db, workspace_id)
    items = (
        db.query(IncidentSLAPolicyModel)
        .filter(IncidentSLAPolicyModel.workspace_id == workspace_id)
        .order_by(IncidentSLAPolicyModel.created_at.desc())
        .all()
    )
    return SLAPolicyListResponse(
        items=[SLAPolicyResponse.model_validate(p) for p in items],
        total=len(items),
    )


@router.post(
    "/settings/sla-policies",
    response_model=SLAPolicyResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new SLA policy",
)
def create_sla_policy_endpoint(
    req: SLAPolicyCreateRequest,
    workspace_id: str = Depends(get_current_workspace),
    actor: str = Depends(get_current_actor),
    _role: str = Depends(require_admin_or_lead),
    db: Session = Depends(get_db),
):
    # Validation: target durations
    if req.acknowledgement_target_minutes > req.resolution_target_minutes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Acknowledgement target cannot exceed resolution target.",
        )

    # If is_default, unset previous defaults
    if req.is_default:
        db.query(IncidentSLAPolicyModel).filter(
            IncidentSLAPolicyModel.workspace_id == workspace_id,
            IncidentSLAPolicyModel.is_default == True,
        ).update({"is_default": False})

    pol = IncidentSLAPolicyModel(
        id=str(uuid.uuid4()),
        workspace_id=workspace_id,
        name=req.name.strip(),
        description=req.description,
        severity=req.severity,
        priority=req.priority,
        category=req.category,
        acknowledgement_target_minutes=req.acknowledgement_target_minutes,
        investigation_target_minutes=req.investigation_target_minutes,
        containment_target_minutes=req.containment_target_minutes,
        resolution_target_minutes=req.resolution_target_minutes,
        warning_threshold_pct=req.warning_threshold_pct,
        escalation_policy_id=req.escalation_policy_id,
        is_default=req.is_default,
        status=req.status.value,
        version=1,
        created_by=actor,
        updated_by=actor,
    )
    db.add(pol)
    db.commit()
    db.refresh(pol)

    AuditService.log_audit(
        db=db,
        action="SLA_POLICY_CREATED",
        resource_type="SLA_POLICY",
        resource_id=pol.id,
        user=actor,
        details=f"Created SLA policy '{pol.name}' (Ack: {pol.acknowledgement_target_minutes}m, Res: {pol.resolution_target_minutes}m).",
    )

    return SLAPolicyResponse.model_validate(pol)


@router.get(
    "/settings/sla-policies/{policy_id}",
    response_model=SLAPolicyResponse,
    summary="Get details of a specific SLA policy",
)
def get_sla_policy_endpoint(
    policy_id: str,
    workspace_id: str = Depends(get_current_workspace),
    db: Session = Depends(get_db),
):
    pol = (
        db.query(IncidentSLAPolicyModel)
        .filter(
            IncidentSLAPolicyModel.id == policy_id,
            IncidentSLAPolicyModel.workspace_id == workspace_id,
        )
        .first()
    )
    if not pol:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"SLA policy '{policy_id}' not found.")
    return SLAPolicyResponse.model_validate(pol)


@router.put(
    "/settings/sla-policies/{policy_id}",
    response_model=SLAPolicyResponse,
    summary="Update an existing SLA policy",
)
def update_sla_policy_endpoint(
    policy_id: str,
    req: SLAPolicyUpdateRequest,
    workspace_id: str = Depends(get_current_workspace),
    actor: str = Depends(get_current_actor),
    _role: str = Depends(require_admin_or_lead),
    db: Session = Depends(get_db),
):
    pol = (
        db.query(IncidentSLAPolicyModel)
        .filter(
            IncidentSLAPolicyModel.id == policy_id,
            IncidentSLAPolicyModel.workspace_id == workspace_id,
        )
        .first()
    )
    if not pol:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"SLA policy '{policy_id}' not found.")

    if req.name is not None:
        pol.name = req.name.strip()
    if req.description is not None:
        pol.description = req.description
    if req.severity is not None:
        pol.severity = req.severity
    if req.priority is not None:
        pol.priority = req.priority
    if req.category is not None:
        pol.category = req.category
    if req.acknowledgement_target_minutes is not None:
        pol.acknowledgement_target_minutes = req.acknowledgement_target_minutes
    if req.investigation_target_minutes is not None:
        pol.investigation_target_minutes = req.investigation_target_minutes
    if req.containment_target_minutes is not None:
        pol.containment_target_minutes = req.containment_target_minutes
    if req.resolution_target_minutes is not None:
        pol.resolution_target_minutes = req.resolution_target_minutes
    if req.warning_threshold_pct is not None:
        pol.warning_threshold_pct = req.warning_threshold_pct
    if req.escalation_policy_id is not None:
        pol.escalation_policy_id = req.escalation_policy_id
    if req.is_default is not None:
        if req.is_default:
            db.query(IncidentSLAPolicyModel).filter(
                IncidentSLAPolicyModel.workspace_id == workspace_id,
                IncidentSLAPolicyModel.id != pol.id,
                IncidentSLAPolicyModel.is_default == True,
            ).update({"is_default": False})
        pol.is_default = req.is_default
    if req.status is not None:
        pol.status = req.status.value

    pol.version += 1
    pol.updated_by = actor
    pol.updated_at = get_utc_now()
    db.commit()
    db.refresh(pol)

    AuditService.log_audit(
        db=db,
        action="SLA_POLICY_UPDATED",
        resource_type="SLA_POLICY",
        resource_id=pol.id,
        user=actor,
        details=f"Updated SLA policy '{pol.name}' to version {pol.version}.",
    )

    return SLAPolicyResponse.model_validate(pol)


# ============================================================================
# SETTINGS: ESCALATION POLICIES MANAGEMENT
# ============================================================================

@router.get(
    "/settings/escalation-policies",
    response_model=EscalationPolicyListResponse,
    summary="List configured Escalation policies for workspace",
)
def list_escalation_policies_endpoint(
    workspace_id: str = Depends(get_current_workspace),
    db: Session = Depends(get_db),
):
    IncidentSLAService.ensure_default_policies(db, workspace_id)
    items = (
        db.query(IncidentEscalationPolicyModel)
        .filter(IncidentEscalationPolicyModel.workspace_id == workspace_id)
        .order_by(IncidentEscalationPolicyModel.created_at.desc())
        .all()
    )
    result = []
    for p in items:
        rule_dtos = [EscalationRuleResponse.model_validate(r) for r in p.rules]
        dto = EscalationPolicyResponse(
            id=p.id,
            workspace_id=p.workspace_id,
            name=p.name,
            description=p.description,
            cooldown_minutes=p.cooldown_minutes,
            max_escalation_level=p.max_escalation_level,
            status=p.status,
            version=p.version,
            created_by=p.created_by,
            created_at=p.created_at,
            updated_at=p.updated_at,
            rules=rule_dtos,
        )
        result.append(dto)
    return EscalationPolicyListResponse(items=result, total=len(result))


@router.post(
    "/settings/escalation-policies",
    response_model=EscalationPolicyResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new Escalation policy with ordered rules",
)
def create_escalation_policy_endpoint(
    req: EscalationPolicyCreateRequest,
    workspace_id: str = Depends(get_current_workspace),
    actor: str = Depends(get_current_actor),
    _role: str = Depends(require_admin_or_lead),
    db: Session = Depends(get_db),
):
    pol = IncidentEscalationPolicyModel(
        id=str(uuid.uuid4()),
        workspace_id=workspace_id,
        name=req.name.strip(),
        description=req.description,
        cooldown_minutes=req.cooldown_minutes,
        max_escalation_level=req.max_escalation_level,
        status=req.status.value,
        version=1,
        created_by=actor,
    )
    db.add(pol)
    db.flush()

    for r in req.rules:
        rule_model = IncidentEscalationRuleModel(
            id=str(uuid.uuid4()),
            policy_id=pol.id,
            level=r.level,
            condition_type=r.condition_type.value,
            milestone=r.milestone,
            action_type=r.action_type.value,
            target_role=r.target_role,
            target_user=r.target_user,
            target_team=r.target_team,
            escalate_priority_to=r.escalate_priority_to,
            note_template=r.note_template,
        )
        db.add(rule_model)

    db.commit()
    db.refresh(pol)

    AuditService.log_audit(
        db=db,
        action="ESCALATION_POLICY_CREATED",
        resource_type="ESCALATION_POLICY",
        resource_id=pol.id,
        user=actor,
        details=f"Created Escalation policy '{pol.name}' with {len(req.rules)} rules.",
    )

    rule_dtos = [EscalationRuleResponse.model_validate(r) for r in pol.rules]
    return EscalationPolicyResponse(
        id=pol.id,
        workspace_id=pol.workspace_id,
        name=pol.name,
        description=pol.description,
        cooldown_minutes=pol.cooldown_minutes,
        max_escalation_level=pol.max_escalation_level,
        status=pol.status,
        version=pol.version,
        created_by=pol.created_by,
        created_at=pol.created_at,
        updated_at=pol.updated_at,
        rules=rule_dtos,
    )


@router.put(
    "/settings/escalation-policies/{policy_id}",
    response_model=EscalationPolicyResponse,
    summary="Update an existing Escalation policy and its rules",
)
def update_escalation_policy_endpoint(
    policy_id: str,
    req: EscalationPolicyUpdateRequest,
    workspace_id: str = Depends(get_current_workspace),
    actor: str = Depends(get_current_actor),
    _role: str = Depends(require_admin_or_lead),
    db: Session = Depends(get_db),
):
    pol = (
        db.query(IncidentEscalationPolicyModel)
        .filter(
            IncidentEscalationPolicyModel.id == policy_id,
            IncidentEscalationPolicyModel.workspace_id == workspace_id,
        )
        .first()
    )
    if not pol:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Escalation policy '{policy_id}' not found.")

    if req.name is not None:
        pol.name = req.name.strip()
    if req.description is not None:
        pol.description = req.description
    if req.cooldown_minutes is not None:
        pol.cooldown_minutes = req.cooldown_minutes
    if req.max_escalation_level is not None:
        pol.max_escalation_level = req.max_escalation_level
    if req.status is not None:
        pol.status = req.status.value

    if req.rules is not None:
        # Replace rules
        db.query(IncidentEscalationRuleModel).filter(
            IncidentEscalationRuleModel.policy_id == pol.id
        ).delete()
        for r in req.rules:
            db.add(
                IncidentEscalationRuleModel(
                    id=str(uuid.uuid4()),
                    policy_id=pol.id,
                    level=r.level,
                    condition_type=r.condition_type.value,
                    milestone=r.milestone,
                    action_type=r.action_type.value,
                    target_role=r.target_role,
                    target_user=r.target_user,
                    target_team=r.target_team,
                    escalate_priority_to=r.escalate_priority_to,
                    note_template=r.note_template,
                )
            )

    pol.version += 1
    pol.updated_at = get_utc_now()
    db.commit()
    db.refresh(pol)

    AuditService.log_audit(
        db=db,
        action="ESCALATION_POLICY_UPDATED",
        resource_type="ESCALATION_POLICY",
        resource_id=pol.id,
        user=actor,
        details=f"Updated Escalation policy '{pol.name}' to version {pol.version}.",
    )

    rule_dtos = [EscalationRuleResponse.model_validate(r) for r in pol.rules]
    return EscalationPolicyResponse(
        id=pol.id,
        workspace_id=pol.workspace_id,
        name=pol.name,
        description=pol.description,
        cooldown_minutes=pol.cooldown_minutes,
        max_escalation_level=pol.max_escalation_level,
        status=pol.status,
        version=pol.version,
        created_by=pol.created_by,
        created_at=pol.created_at,
        updated_at=pol.updated_at,
        rules=rule_dtos,
    )


# ============================================================================
# SETTINGS: ROUTING RULES MANAGEMENT
# ============================================================================

@router.get(
    "/settings/routing-rules",
    response_model=RoutingRuleListResponse,
    summary="List analyst routing rules for workspace",
)
def list_routing_rules_endpoint(
    workspace_id: str = Depends(get_current_workspace),
    db: Session = Depends(get_db),
):
    IncidentSLAService.ensure_default_policies(db, workspace_id)
    items = (
        db.query(IncidentRoutingRuleModel)
        .filter(IncidentRoutingRuleModel.workspace_id == workspace_id)
        .order_by(IncidentRoutingRuleModel.priority_order.asc())
        .all()
    )
    result = []
    for r in items:
        cands = json.loads(r.candidate_analysts_json or "[]")
        result.append(
            RoutingRuleResponse(
                id=r.id,
                workspace_id=r.workspace_id,
                name=r.name,
                description=r.description,
                priority_order=r.priority_order,
                category=r.category,
                severity=r.severity,
                min_risk_score=r.min_risk_score,
                routing_strategy=r.routing_strategy,
                target_team_id=r.target_team_id,
                target_user_id=r.target_user_id,
                candidate_analysts=cands,
                enabled=r.enabled,
                created_at=r.created_at,
                updated_at=r.updated_at,
            )
        )
    return RoutingRuleListResponse(items=result, total=len(result))


@router.post(
    "/settings/routing-rules",
    response_model=RoutingRuleResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new analyst routing rule",
)
def create_routing_rule_endpoint(
    req: RoutingRuleCreateRequest,
    workspace_id: str = Depends(get_current_workspace),
    actor: str = Depends(get_current_actor),
    _role: str = Depends(require_admin_or_lead),
    db: Session = Depends(get_db),
):
    rule = IncidentRoutingRuleModel(
        id=str(uuid.uuid4()),
        workspace_id=workspace_id,
        name=req.name.strip(),
        description=req.description,
        priority_order=req.priority_order,
        category=req.category,
        severity=req.severity,
        min_risk_score=req.min_risk_score,
        routing_strategy=req.routing_strategy.value,
        target_team_id=req.target_team_id,
        target_user_id=req.target_user_id,
        candidate_analysts_json=json.dumps(req.candidate_analysts),
        enabled=req.enabled,
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)

    AuditService.log_audit(
        db=db,
        action="ROUTING_RULE_CREATED",
        resource_type="ROUTING_RULE",
        resource_id=rule.id,
        user=actor,
        details=f"Created routing rule '{rule.name}' with strategy {rule.routing_strategy}.",
    )

    return RoutingRuleResponse(
        id=rule.id,
        workspace_id=rule.workspace_id,
        name=rule.name,
        description=rule.description,
        priority_order=rule.priority_order,
        category=rule.category,
        severity=rule.severity,
        min_risk_score=rule.min_risk_score,
        routing_strategy=rule.routing_strategy,
        target_team_id=rule.target_team_id,
        target_user_id=rule.target_user_id,
        candidate_analysts=req.candidate_analysts,
        enabled=rule.enabled,
        created_at=rule.created_at,
        updated_at=rule.updated_at,
    )


@router.put(
    "/settings/routing-rules/{rule_id}",
    response_model=RoutingRuleResponse,
    summary="Update an existing analyst routing rule",
)
def update_routing_rule_endpoint(
    rule_id: str,
    req: RoutingRuleUpdateRequest,
    workspace_id: str = Depends(get_current_workspace),
    actor: str = Depends(get_current_actor),
    _role: str = Depends(require_admin_or_lead),
    db: Session = Depends(get_db),
):
    rule = (
        db.query(IncidentRoutingRuleModel)
        .filter(
            IncidentRoutingRuleModel.id == rule_id,
            IncidentRoutingRuleModel.workspace_id == workspace_id,
        )
        .first()
    )
    if not rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Routing rule '{rule_id}' not found.")

    if req.name is not None:
        rule.name = req.name.strip()
    if req.description is not None:
        rule.description = req.description
    if req.priority_order is not None:
        rule.priority_order = req.priority_order
    if req.category is not None:
        rule.category = req.category
    if req.severity is not None:
        rule.severity = req.severity
    if req.min_risk_score is not None:
        rule.min_risk_score = req.min_risk_score
    if req.routing_strategy is not None:
        rule.routing_strategy = req.routing_strategy.value
    if req.target_team_id is not None:
        rule.target_team_id = req.target_team_id
    if req.target_user_id is not None:
        rule.target_user_id = req.target_user_id
    if req.candidate_analysts is not None:
        rule.candidate_analysts_json = json.dumps(req.candidate_analysts)
    if req.enabled is not None:
        rule.enabled = req.enabled

    rule.updated_at = get_utc_now()
    db.commit()
    db.refresh(rule)

    AuditService.log_audit(
        db=db,
        action="ROUTING_RULE_UPDATED",
        resource_type="ROUTING_RULE",
        resource_id=rule.id,
        user=actor,
        details=f"Updated routing rule '{rule.name}'.",
    )

    cands = json.loads(rule.candidate_analysts_json or "[]")
    return RoutingRuleResponse(
        id=rule.id,
        workspace_id=rule.workspace_id,
        name=rule.name,
        description=rule.description,
        priority_order=rule.priority_order,
        category=rule.category,
        severity=rule.severity,
        min_risk_score=rule.min_risk_score,
        routing_strategy=rule.routing_strategy,
        target_team_id=rule.target_team_id,
        target_user_id=rule.target_user_id,
        candidate_analysts=cands,
        enabled=rule.enabled,
        created_at=rule.created_at,
        updated_at=rule.updated_at,
    )


# ============================================================================
# POLICY SIMULATION (DRY RUN)
# ============================================================================

@router.post(
    "/settings/sla-policies/simulate",
    response_model=PolicySimulationResponse,
    summary="Safely dry-run a policy simulation without mutating database state",
)
def simulate_sla_policy_endpoint(
    req: PolicySimulationRequest,
    workspace_id: str = Depends(get_current_workspace),
    db: Session = Depends(get_db),
):
    return IncidentSLAService.simulate_policy(db, req=req, workspace_id=workspace_id)
