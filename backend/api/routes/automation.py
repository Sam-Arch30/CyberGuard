"""
Section 70: Security Operations Automation (SOAR) REST API Router.
Exposes authoritative endpoints for workflows, runs, steps, approval gates, and metrics.
"""
from typing import Optional, List, Dict, Any
import json
from fastapi import APIRouter, Depends, Query, Path, Header, HTTPException, status
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.services.automation_service import AutomationWorkflowService
from backend.services.automation_action_registry import ACTION_REGISTRY
from backend.schemas.automation_workflow import (
    WorkflowCreateRequest,
    WorkflowUpdateRequest,
    WorkflowResponse,
    WorkflowListResponse,
    WorkflowVersionResponse,
    WorkflowRunTriggerRequest,
    WorkflowRunResponse,
    WorkflowRunListResponse,
    StepExecutionResponse,
    ApprovalRequestResponse,
    ApprovalDecisionRequest,
    RegisteredActionMetadata,
    AutomationMetricsResponse,
)

router = APIRouter(prefix="/api/automation", tags=["Security Operations Automation (SOAR)"])


def get_tenant_id(
    x_tenant_id: Optional[str] = Header(None, alias="X-Tenant-ID"),
    x_tenant_id_lower: Optional[str] = Header(None, alias="X-Tenant-Id"),
) -> str:
    return (x_tenant_id or x_tenant_id_lower or "default").strip()


def get_user_info(
    x_user_id: Optional[str] = Header(None, alias="X-User-ID"),
    x_user_name: Optional[str] = Header(None, alias="X-User-Name"),
    x_user_role: Optional[str] = Header(None, alias="X-User-Role"),
) -> tuple[str, str, str]:
    uid = (x_user_id or "analyst").strip()
    uname = (x_user_name or "SOC Analyst").strip()
    urole = (x_user_role or "analyst").strip().lower()
    return uid, uname, urole


def _format_workflow(wf) -> WorkflowResponse:
    return WorkflowResponse(
        id=wf.id,
        workspace_id=wf.workspace_id,
        tenant_id=wf.tenant_id,
        name=wf.name,
        description=wf.description,
        workflow_type=wf.workflow_type,
        status=wf.status,
        version=wf.version,
        owner_id=wf.owner_id,
        team_id=wf.team_id,
        trigger_type=wf.trigger_type,
        trigger_config=json.loads(wf.trigger_config_json or "{}"),
        conditions=json.loads(wf.conditions_json or "{}"),
        actions=json.loads(wf.actions_json or "[]"),
        approval_policy=json.loads(wf.approval_policy_json or "{}"),
        execution_limits=json.loads(wf.execution_limits_json or "{}"),
        is_active=wf.is_active,
        created_by=wf.created_by,
        created_at=wf.created_at.isoformat() if wf.created_at else "",
        updated_at=wf.updated_at.isoformat() if wf.updated_at else "",
    )


def _format_run(run) -> WorkflowRunResponse:
    step_items = []
    if hasattr(run, "steps") and run.steps:
        for s in run.steps:
            step_items.append(StepExecutionResponse(
                id=s.id,
                step_index=s.step_index,
                step_key=s.step_key,
                action_id=s.action_id,
                name=s.name,
                status=s.status,
                risk_classification=s.risk_classification,
                approval_level=s.approval_level,
                requires_approval=s.requires_approval,
                approval_id=s.approval_id,
                approval_decision=s.approval_decision,
                approved_by=s.approved_by,
                approved_at=s.approved_at.isoformat() if s.approved_at else None,
                input_params=json.loads(s.input_params_json or "{}"),
                output_data=json.loads(s.output_data_json or "{}"),
                verification_result=json.loads(s.verification_result_json or "{}"),
                verified_state=s.verified_state,
                error_message=s.error_message,
                failure_category=s.failure_category,
                retry_count=s.retry_count,
                execution_duration_ms=s.execution_duration_ms,
                started_at=s.started_at.isoformat() if s.started_at else None,
                completed_at=s.completed_at.isoformat() if s.completed_at else None,
            ))

    return WorkflowRunResponse(
        id=run.id,
        workspace_id=run.workspace_id,
        tenant_id=run.tenant_id,
        workflow_id=run.workflow_id,
        workflow_name=run.workflow.name if run.workflow else None,
        workflow_version=run.workflow_version,
        status=run.status,
        trigger_type=run.trigger_type,
        trigger_resource_type=run.trigger_resource_type,
        trigger_resource_id=run.trigger_resource_id,
        execution_mode=run.execution_mode,
        idempotency_key=run.idempotency_key,
        total_steps=run.total_steps,
        completed_steps=run.completed_steps,
        failed_steps=run.failed_steps,
        skipped_steps=run.skipped_steps,
        error_message=run.error_message,
        failure_category=run.failure_category,
        started_at=run.started_at.isoformat() if run.started_at else None,
        completed_at=run.completed_at.isoformat() if run.completed_at else None,
        explainability_trace=json.loads(run.explainability_trace_json or "{}"),
        output_summary=json.loads(run.output_summary_json or "{}"),
        steps=step_items,
        created_at=run.created_at.isoformat() if run.created_at else "",
    )


# =============================================================================
# WORKFLOW ENDPOINTS
# =============================================================================

@router.get("/workflows", response_model=WorkflowListResponse)
def list_workflows(
    status: Optional[str] = Query(None),
    workflow_type: Optional[str] = Query(None),
    trigger_type: Optional[str] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_tenant_id),
):
    items, total = AutomationWorkflowService.list_workflows(
        db=db,
        tenant_id=tenant_id,
        status=status,
        workflow_type=workflow_type,
        trigger_type=trigger_type,
        skip=skip,
        limit=limit,
    )
    return WorkflowListResponse(items=[_format_workflow(w) for w in items], total=total)


@router.post("/workflows", response_model=WorkflowResponse, status_code=status.HTTP_201_CREATED)
def create_workflow(
    req: WorkflowCreateRequest,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_tenant_id),
    user_info: tuple[str, str, str] = Depends(get_user_info),
):
    uid, uname, urole = user_info
    wf = AutomationWorkflowService.create_workflow(
        db=db,
        req=req,
        tenant_id=tenant_id,
        user_id=uid,
        user_name=uname,
    )
    return _format_workflow(wf)


@router.get("/workflows/{id}", response_model=WorkflowResponse)
def get_workflow(
    id: str = Path(...),
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_tenant_id),
):
    wf = AutomationWorkflowService.get_workflow(db=db, workflow_id=id, tenant_id=tenant_id)
    if not wf:
        raise HTTPException(status_code=404, detail="Workflow not found")
    return _format_workflow(wf)


@router.put("/workflows/{id}", response_model=WorkflowResponse)
def update_workflow(
    id: str = Path(...),
    req: WorkflowUpdateRequest = ...,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_tenant_id),
    user_info: tuple[str, str, str] = Depends(get_user_info),
):
    uid, uname, urole = user_info
    try:
        wf = AutomationWorkflowService.update_workflow(
            db=db,
            workflow_id=id,
            req=req,
            tenant_id=tenant_id,
            user_name=uname,
        )
        return _format_workflow(wf)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/workflows/{id}/validate")
def validate_workflow(
    id: str = Path(...),
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_tenant_id),
):
    is_valid, errors = AutomationWorkflowService.validate_workflow(db=db, workflow_id=id, tenant_id=tenant_id)
    return {"is_valid": is_valid, "errors": errors}


@router.post("/workflows/{id}/activate", response_model=WorkflowResponse)
def activate_workflow(
    id: str = Path(...),
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_tenant_id),
    user_info: tuple[str, str, str] = Depends(get_user_info),
):
    uid, uname, urole = user_info
    try:
        wf = AutomationWorkflowService.activate_workflow(
            db=db,
            workflow_id=id,
            tenant_id=tenant_id,
            user_id=uid,
            user_name=uname,
        )
        return _format_workflow(wf)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/workflows/{id}/pause", response_model=WorkflowResponse)
def pause_workflow(
    id: str = Path(...),
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_tenant_id),
    user_info: tuple[str, str, str] = Depends(get_user_info),
):
    uid, uname, urole = user_info
    try:
        wf = AutomationWorkflowService.pause_workflow(db=db, workflow_id=id, tenant_id=tenant_id, user_name=uname)
        return _format_workflow(wf)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/workflows/{id}/disable", response_model=WorkflowResponse)
def disable_workflow(
    id: str = Path(...),
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_tenant_id),
    user_info: tuple[str, str, str] = Depends(get_user_info),
):
    uid, uname, urole = user_info
    try:
        wf = AutomationWorkflowService.disable_workflow(db=db, workflow_id=id, tenant_id=tenant_id, user_name=uname)
        return _format_workflow(wf)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/workflows/{id}/new-version", response_model=WorkflowResponse)
def create_new_version(
    id: str = Path(...),
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_tenant_id),
    user_info: tuple[str, str, str] = Depends(get_user_info),
):
    uid, uname, urole = user_info
    try:
        wf = AutomationWorkflowService.create_new_version(db=db, workflow_id=id, tenant_id=tenant_id, user_name=uname)
        return _format_workflow(wf)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/workflows/{id}/trigger", response_model=WorkflowRunResponse)
def trigger_workflow(
    id: str = Path(...),
    req: WorkflowRunTriggerRequest = ...,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_tenant_id),
    user_info: tuple[str, str, str] = Depends(get_user_info),
):
    uid, uname, urole = user_info
    wf = AutomationWorkflowService.get_workflow(db=db, workflow_id=id, tenant_id=tenant_id)
    if not wf:
        raise HTTPException(status_code=404, detail="Workflow not found")
    if wf.status != "ACTIVE" and req.execution_mode == "PRODUCTION":
        raise HTTPException(status_code=400, detail="Cannot execute non-ACTIVE workflow in PRODUCTION mode. Activate workflow or use DRY_RUN/TEST mode.")

    run = AutomationWorkflowService.create_and_execute_run(
        db=db,
        workflow=wf,
        trigger_type=wf.trigger_type,
        resource_type=req.resource_type,
        resource_id=req.resource_id,
        payload=req.payload,
        execution_mode=req.execution_mode.value,
        recursion_depth=0,
        tenant_id=tenant_id,
        user_name=uname,
    )
    return _format_run(run)


# =============================================================================
# RUNS ENDPOINTS
# =============================================================================

@router.get("/runs", response_model=WorkflowRunListResponse)
def list_runs(
    workflow_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_tenant_id),
):
    items, total = AutomationWorkflowService.list_runs(
        db=db,
        tenant_id=tenant_id,
        workflow_id=workflow_id,
        status=status,
        skip=skip,
        limit=limit,
    )
    return WorkflowRunListResponse(items=[_format_run(r) for r in items], total=total)


@router.get("/runs/{id}", response_model=WorkflowRunResponse)
def get_run(
    id: str = Path(...),
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_tenant_id),
):
    run = AutomationWorkflowService.get_run(db=db, run_id=id, tenant_id=tenant_id)
    if not run:
        raise HTTPException(status_code=404, detail="Automation run not found")
    return _format_run(run)


@router.post("/runs/{id}/cancel", response_model=WorkflowRunResponse)
def cancel_run(
    id: str = Path(...),
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_tenant_id),
    user_info: tuple[str, str, str] = Depends(get_user_info),
):
    uid, uname, urole = user_info
    try:
        run = AutomationWorkflowService.cancel_run(db=db, run_id=id, user_name=uname, tenant_id=tenant_id)
        return _format_run(run)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/runs/{id}/pause", response_model=WorkflowRunResponse)
def pause_run(
    id: str = Path(...),
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_tenant_id),
    user_info: tuple[str, str, str] = Depends(get_user_info),
):
    uid, uname, urole = user_info
    try:
        run = AutomationWorkflowService.pause_run(db=db, run_id=id, user_name=uname, tenant_id=tenant_id)
        return _format_run(run)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/runs/{id}/resume", response_model=WorkflowRunResponse)
def resume_run(
    id: str = Path(...),
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_tenant_id),
    user_info: tuple[str, str, str] = Depends(get_user_info),
):
    uid, uname, urole = user_info
    try:
        run = AutomationWorkflowService.resume_run(db=db, run_id=id, user_name=uname, tenant_id=tenant_id)
        return _format_run(run)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


# =============================================================================
# APPROVALS ENDPOINTS
# =============================================================================

@router.get("/approvals", response_model=List[ApprovalRequestResponse])
def list_pending_approvals(
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_tenant_id),
):
    approvals = AutomationWorkflowService.list_pending_approvals(db=db, tenant_id=tenant_id)
    return [
        ApprovalRequestResponse(
            id=a.id,
            run_id=a.run_id,
            step_id=a.step_id,
            action_id=a.action_id,
            status=a.status,
            required_role=a.required_role,
            requested_by=a.requested_by,
            requested_at=a.requested_at.isoformat() if a.requested_at else "",
            expires_at=a.expires_at.isoformat() if a.expires_at else "",
            decision=a.decision,
            decided_by=a.decided_by,
            decided_at=a.decided_at.isoformat() if a.decided_at else None,
            reason=a.reason,
            action_payload=json.loads(a.action_payload_json or "{}"),
            context_summary=json.loads(a.context_summary_json or "{}"),
        )
        for a in approvals
    ]


@router.post("/approvals/{id}/decide", response_model=ApprovalRequestResponse)
def decide_approval(
    id: str = Path(...),
    req: ApprovalDecisionRequest = ...,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_tenant_id),
    user_info: tuple[str, str, str] = Depends(get_user_info),
):
    uid, uname, urole = user_info
    try:
        a = AutomationWorkflowService.decide_approval(
            db=db,
            approval_id=id,
            decision=req.decision,
            reason=req.reason,
            user_id=uid,
            user_name=uname,
            user_role=urole,
            tenant_id=tenant_id,
        )
        return ApprovalRequestResponse(
            id=a.id,
            run_id=a.run_id,
            step_id=a.step_id,
            action_id=a.action_id,
            status=a.status,
            required_role=a.required_role,
            requested_by=a.requested_by,
            requested_at=a.requested_at.isoformat() if a.requested_at else "",
            expires_at=a.expires_at.isoformat() if a.expires_at else "",
            decision=a.decision,
            decided_by=a.decided_by,
            decided_at=a.decided_at.isoformat() if a.decided_at else None,
            reason=a.reason,
            action_payload=json.loads(a.action_payload_json or "{}"),
            context_summary=json.loads(a.context_summary_json or "{}"),
        )
    except PermissionError as pe:
        raise HTTPException(status_code=403, detail=str(pe))
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))


# =============================================================================
# ACTION REGISTRY & METRICS
# =============================================================================

@router.get("/actions", response_model=List[RegisteredActionMetadata])
def list_registered_actions():
    items = []
    for action in ACTION_REGISTRY.values():
        items.append(RegisteredActionMetadata(
            action_id=action.action_id,
            name=action.name,
            description=action.description,
            risk_classification=action.risk_classification,
            default_approval_level=action.default_approval_level,
            required_role=action.required_role,
            target_resource_type=action.target_resource_type,
            parameters_schema=action.parameters_schema,
        ))
    return items


@router.get("/metrics", response_model=AutomationMetricsResponse)
def get_metrics(
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_tenant_id),
):
    m = AutomationWorkflowService.get_metrics(db=db, tenant_id=tenant_id)
    return AutomationMetricsResponse(**m)
