"""
REST API Endpoints for Section 29: Response Playbooks.
Mounted under /api/v1/playbooks.
"""

from __future__ import annotations
import json
import logging
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.db.models import (
    ResponsePlaybookModel,
    ResponsePlaybookStepModel,
    ResponsePlaybookExecutionModel,
    ResponsePlaybookStepExecutionModel,
    ResponsePlaybookApprovalModel,
    AuditLogModel
)
from backend.schemas.response_playbook import (
    ResponsePlaybookCreate,
    ResponsePlaybookResponse,
    ResponsePlaybookStepResponse,
    ResponsePlaybookSummary,
    PlaybookValidationResult,
    SimulationPlan,
    PlaybookExecuteRequest,
    PlaybookApprovalRequest,
    ResponsePlaybookExecutionResponse,
    ResponsePlaybookStepExecutionResponse,
    ResponsePlaybookApprovalResponse,
    FromRecommendationRequest,
    ExecutionModeEnum
)
from backend.services.response_playbook_engine import ResponsePlaybookEngine
from backend.services.playbook_validator import PlaybookValidator

logger = logging.getLogger("cyberguard.api.playbooks")

router = APIRouter(prefix="/api/v1/playbooks", tags=["Response Playbooks"])


def _serialize_step(s: ResponsePlaybookStepModel) -> ResponsePlaybookStepResponse:
    return ResponsePlaybookStepResponse(
        id=s.id,
        playbook_id=s.playbook_id,
        step_key=s.step_key,
        sequence=s.sequence,
        step_type=s.step_type,
        name=s.name,
        description=s.description,
        parameters=s.parameters,
        target_selector=s.target_selector,
        condition=s.condition,
        on_success=s.on_success,
        on_failure=s.on_failure,
        timeout_seconds=s.timeout_seconds,
        retry_policy=s.retry_policy,
        requires_approval=s.requires_approval,
        approval_policy=s.approval_policy,
        safety_class=s.safety_class,
        verification_policy=s.verification_policy,
        rollback_policy=s.rollback_policy,
        depends_on=s.depends_on,
        enabled=s.enabled,
        created_at=s.created_at.isoformat() if s.created_at else "",
        updated_at=s.updated_at.isoformat() if s.updated_at else ""
    )


def _serialize_playbook(pb: ResponsePlaybookModel) -> ResponsePlaybookResponse:
    return ResponsePlaybookResponse(
        id=pb.id,
        workspace_id=pb.workspace_id,
        playbook_key=pb.playbook_key,
        name=pb.name,
        description=pb.description,
        version=pb.version,
        status=pb.status,
        trigger_type=pb.trigger_type,
        scope_type=pb.scope_type,
        severity_min=pb.severity_min,
        risk_min=pb.risk_min,
        incident_id=pb.incident_id,
        investigation_id=pb.investigation_id,
        source_recommendation_id=pb.source_recommendation_id,
        target_selector=pb.target_selector,
        approval_policy=pb.approval_policy,
        execution_policy=pb.execution_policy,
        timeout_seconds=pb.timeout_seconds,
        max_runtime_seconds=pb.max_runtime_seconds,
        parent_version=pb.parent_version,
        change_summary=pb.change_summary,
        created_by=pb.created_by,
        updated_by=pb.updated_by,
        approved_by=pb.approved_by,
        approved_at=pb.approved_at.isoformat() if pb.approved_at else None,
        activated_at=pb.activated_at.isoformat() if pb.activated_at else None,
        retired_at=pb.retired_at.isoformat() if pb.retired_at else None,
        created_at=pb.created_at.isoformat() if pb.created_at else "",
        updated_at=pb.updated_at.isoformat() if pb.updated_at else "",
        steps=[_serialize_step(s) for s in pb.steps]
    )


def _serialize_step_execution(se: ResponsePlaybookStepExecutionModel) -> ResponsePlaybookStepExecutionResponse:
    return ResponsePlaybookStepExecutionResponse(
        id=se.id,
        execution_id=se.execution_id,
        step_id=se.step_id,
        step_key=se.step_key,
        sequence=se.sequence,
        target_snapshot=se.target_snapshot,
        status=se.status,
        started_at=se.started_at.isoformat() if se.started_at else None,
        completed_at=se.completed_at.isoformat() if se.completed_at else None,
        attempt_count=se.attempt_count,
        adapter=se.adapter,
        adapter_version=se.adapter_version,
        input_summary=se.input_summary,
        output_summary=se.output_summary,
        verification_result=se.verification_result,
        error_code=se.error_code,
        error_message=se.error_message,
        evidence_refs=se.evidence_refs,
        audit_event_id=se.audit_event_id,
        idempotency_key=se.idempotency_key,
        created_at=se.created_at.isoformat() if se.created_at else ""
    )


def _serialize_execution(ex: ResponsePlaybookExecutionModel) -> ResponsePlaybookExecutionResponse:
    return ResponsePlaybookExecutionResponse(
        id=ex.id,
        playbook_id=ex.playbook_id,
        playbook_version=ex.playbook_version,
        incident_id=ex.incident_id,
        investigation_id=ex.investigation_id,
        source_recommendation_id=ex.source_recommendation_id,
        trigger_source=ex.trigger_source,
        mode=ex.mode,
        status=ex.status,
        started_at=ex.started_at.isoformat() if ex.started_at else None,
        completed_at=ex.completed_at.isoformat() if ex.completed_at else None,
        requested_by=ex.requested_by,
        approved_by=ex.approved_by,
        current_step_key=ex.current_step_key,
        result_summary=ex.result_summary or "",
        error_code=ex.error_code,
        error_message=ex.error_message,
        execution_context=ex.execution_context,
        workspace_id=ex.workspace_id,
        created_at=ex.created_at.isoformat() if ex.created_at else "",
        updated_at=ex.updated_at.isoformat() if ex.updated_at else "",
        step_executions=[_serialize_step_execution(se) for se in ex.step_executions],
        approvals=[
            ResponsePlaybookApprovalResponse(
                id=a.id,
                execution_id=a.execution_id,
                step_id=a.step_id,
                scope=a.scope,
                decision=a.decision,
                requested_by=a.requested_by,
                approved_by=a.approved_by,
                reason=a.reason,
                target_snapshot=a.target_snapshot,
                authorization_context=a.authorization_context,
                created_at=a.created_at.isoformat() if a.created_at else "",
                decided_at=a.decided_at.isoformat() if a.decided_at else None
            )
            for a in ex.approvals
        ]
    )


# ============================================================================
# PLAYBOOK ENDPOINTS
# ============================================================================

@router.get("", response_model=List[ResponsePlaybookSummary])
def list_playbooks(
    status: Optional[str] = None,
    scope_type: Optional[str] = None,
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    db: Session = Depends(get_db)
):
    """Lists registered playbooks in workspace. Seeds default templates if empty."""
    ResponsePlaybookEngine.seed_default_playbooks(db, workspace_id=x_workspace_id)
    playbooks = ResponsePlaybookEngine.get_playbooks(
        db,
        workspace_id=x_workspace_id,
        status=status,
        scope_type=scope_type
    )
    return [
        ResponsePlaybookSummary(
            id=p.id,
            workspace_id=p.workspace_id,
            playbook_key=p.playbook_key,
            name=p.name,
            version=p.version,
            status=p.status,
            trigger_type=p.trigger_type,
            scope_type=p.scope_type,
            step_count=len(p.steps),
            approval_policy=p.approval_policy,
            created_at=p.created_at.isoformat() if p.created_at else "",
            updated_at=p.updated_at.isoformat() if p.updated_at else ""
        )
        for p in playbooks
    ]


@router.post("", response_model=ResponsePlaybookResponse, status_code=status.HTTP_201_CREATED)
def create_playbook(
    payload: ResponsePlaybookCreate,
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    db: Session = Depends(get_db)
):
    """Registers a new validated playbook."""
    try:
        data = payload.dict()
        pb = ResponsePlaybookEngine.create_playbook(db, workspace_id=x_workspace_id, data=data)
        return _serialize_playbook(pb)
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        logger.error(f"Failed to create playbook: {e}")
        raise HTTPException(status_code=500, detail='Playbook creation failed.')


@router.post("/from-recommendation/{recommendation_id}", response_model=ResponsePlaybookResponse)
def create_from_recommendation(
    recommendation_id: str,
    payload: Optional[FromRecommendationRequest] = None,
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    db: Session = Depends(get_db)
):
    """Converts an approved Section 28 recommendation into an executable playbook."""
    try:
        user = payload.requested_by if payload else "analyst"
        pb = ResponsePlaybookEngine.create_playbook_from_recommendation(
            db=db,
            recommendation_id=recommendation_id,
            requested_by=user
        )
        return _serialize_playbook(pb)
    except ValueError as ve:
        raise HTTPException(status_code=404, detail=str(ve))
    except Exception as e:
        logger.error(f"Failed to convert recommendation to playbook: {e}")
        raise HTTPException(status_code=500, detail="Internal operation failed.")


@router.get("/executions", response_model=List[ResponsePlaybookExecutionResponse])
def list_executions(
    playbook_id: Optional[str] = None,
    status: Optional[str] = None,
    investigation_id: Optional[str] = None,
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    db: Session = Depends(get_db)
):
    """Lists playbook execution instances."""
    query = db.query(ResponsePlaybookExecutionModel).filter(
        ResponsePlaybookExecutionModel.workspace_id == x_workspace_id
    )
    if playbook_id:
        query = query.filter(ResponsePlaybookExecutionModel.playbook_id == playbook_id)
    if status:
        query = query.filter(ResponsePlaybookExecutionModel.status == status)
    if investigation_id:
        from sqlalchemy import or_
        query = query.filter(
            or_(
                ResponsePlaybookExecutionModel.investigation_id == investigation_id,
                ResponsePlaybookExecutionModel.incident_id == investigation_id
            )
        )

    execs = query.order_by(ResponsePlaybookExecutionModel.created_at.desc()).limit(100).all()
    return [_serialize_execution(ex) for ex in execs]


@router.get("/executions/{execution_id}", response_model=ResponsePlaybookExecutionResponse)
def get_execution(
    execution_id: str,
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    db: Session = Depends(get_db)
):
    """Retrieves full execution instance with step executions and approvals."""
    ex = db.query(ResponsePlaybookExecutionModel).filter(
        ResponsePlaybookExecutionModel.id == execution_id,
        ResponsePlaybookExecutionModel.workspace_id == x_workspace_id
    ).first()
    if not ex:
        raise HTTPException(status_code=404, detail="Execution not found.")
    return _serialize_execution(ex)


@router.post("/executions/{execution_id}/approve", response_model=ResponsePlaybookApprovalResponse)
def approve_execution(
    execution_id: str,
    payload: PlaybookApprovalRequest,
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    db: Session = Depends(get_db)
):
    """Records scoped analyst approval for an execution."""
    try:
        appr = ResponsePlaybookEngine.record_approval(
            db=db,
            execution_id=execution_id,
            step_id=payload.step_id,
            decision=payload.decision.value,
            approved_by=payload.approved_by,
            reason=payload.reason
        )
        return ResponsePlaybookApprovalResponse(
            id=appr.id,
            execution_id=appr.execution_id,
            step_id=appr.step_id,
            scope=appr.scope,
            decision=appr.decision,
            requested_by=appr.requested_by,
            approved_by=appr.approved_by,
            reason=appr.reason,
            target_snapshot=appr.target_snapshot,
            authorization_context=appr.authorization_context,
            created_at=appr.created_at.isoformat() if appr.created_at else "",
            decided_at=appr.decided_at.isoformat() if appr.decided_at else None
        )
    except ValueError as ve:
        raise HTTPException(status_code=404, detail=str(ve))
    except Exception as e:
        logger.error(f"Approval error: {e}")
        raise HTTPException(status_code=500, detail="Internal operation failed.")


@router.get("/executions/{execution_id}/audit")
def get_execution_audit(
    execution_id: str,
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    db: Session = Depends(get_db)
):
    """Retrieves immutable audit logs associated with this playbook execution."""
    logs = db.query(AuditLogModel).filter(
        AuditLogModel.resource_id == execution_id
    ).order_by(AuditLogModel.timestamp.asc()).all()

    return [
        {
            "id": l.id,
            "action": l.action,
            "user": l.user,
            "timestamp": l.timestamp.isoformat() if l.timestamp else "",
            "metadata": json.loads(l.metadata_json or "{}")
        }
        for l in logs
    ]


@router.get("/{playbook_id}", response_model=ResponsePlaybookResponse)
def get_playbook(
    playbook_id: str,
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    db: Session = Depends(get_db)
):
    """Retrieves single playbook with all defined steps."""
    pb = ResponsePlaybookEngine.get_playbook(db, playbook_id)
    if not pb or pb.workspace_id != x_workspace_id:
        raise HTTPException(status_code=404, detail="Playbook not found.")
    return _serialize_playbook(pb)


@router.post("/{playbook_id}/validate", response_model=PlaybookValidationResult)
def validate_playbook(
    playbook_id: str,
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    db: Session = Depends(get_db)
):
    """Validates and lints playbook structure, safety, and dependencies."""
    pb = ResponsePlaybookEngine.get_playbook(db, playbook_id)
    if not pb or pb.workspace_id != x_workspace_id:
        raise HTTPException(status_code=404, detail="Playbook not found.")

    res = PlaybookValidator.validate_and_lint(
        {
            "playbook_key": pb.playbook_key,
            "name": pb.name,
            "version": pb.version,
            "steps": [s for s in pb.steps]
        },
        db=db
    )
    return res


@router.post("/{playbook_id}/simulate", response_model=SimulationPlan)
def simulate_playbook(
    playbook_id: str,
    payload: Optional[PlaybookExecuteRequest] = None,
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    db: Session = Depends(get_db)
):
    """Compiles and returns a safe dry-run simulation plan."""
    try:
        override = payload.target_override if payload else None
        plan = ResponsePlaybookEngine.simulate_playbook(
            db=db,
            playbook_id=playbook_id,
            workspace_id=x_workspace_id,
            target_override=override
        )
        return plan
    except ValueError as ve:
        raise HTTPException(status_code=404, detail=str(ve))
    except Exception as e:
        logger.error(f"Simulation error: {e}")
        raise HTTPException(status_code=500, detail="Internal operation failed.")


@router.post("/{playbook_id}/activate", response_model=ResponsePlaybookResponse)
def activate_playbook(
    playbook_id: str,
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    db: Session = Depends(get_db)
):
    """Activates playbook for live execution."""
    try:
        pb = ResponsePlaybookEngine.activate_playbook(db, playbook_id, user_id="analyst")
        return _serialize_playbook(pb)
    except ValueError as ve:
        raise HTTPException(status_code=404, detail=str(ve))


@router.post("/{playbook_id}/execute", response_model=ResponsePlaybookExecutionResponse)
def execute_playbook(
    playbook_id: str,
    payload: PlaybookExecuteRequest,
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    db: Session = Depends(get_db)
):
    """Executes playbook in LIVE or DRY_RUN mode."""
    try:
        execution = ResponsePlaybookEngine.execute_playbook(
            db=db,
            playbook_id=playbook_id,
            workspace_id=x_workspace_id,
            mode=payload.mode.value,
            requested_by=payload.requested_by,
            target_override=payload.target_override,
            execution_context=payload.execution_context
        )
        return _serialize_execution(execution)
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except RuntimeError as re:
        raise HTTPException(status_code=409, detail=str(re))
    except Exception as e:
        logger.error(f"Execution failed: {e}")
        raise HTTPException(status_code=500, detail='Execution error.')
