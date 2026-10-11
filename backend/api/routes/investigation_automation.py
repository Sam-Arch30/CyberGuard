"""
Section 66: Advanced Investigation Automation REST API.
Authoritative endpoints for planning, executing, monitoring, and managing
automated investigation workflows, bounded steps, approval gates, gaps, and coverage.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Header, Query, Path, status
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.services.investigation_automation_service import InvestigationAutomationService
from backend.services.background_job_service import BackgroundJobService
from backend.schemas.jobs import JobTypeEnum, JobSubmitRequest
from backend.schemas.investigation_automation import (
    AutomationBudget,
    AutomationMode,
    AutomationRunStatus,
    AutomationStepCreate,
    AutomationStepRead,
    AutomationTriggerType,
    InvestigationAutomationRunCreate,
    InvestigationAutomationRunRead,
    InvestigationCoverageReport,
    InvestigationGapRead,
    InvestigationSummaryReport,
    StepApprovalRequest,
    AutomationPolicyCreate,
    AutomationPolicyRead,
    AutomationTemplateDefinition,
)

logger = logging.getLogger("cyberguard.api.investigation_automation")

router = APIRouter(tags=["Investigation Automation"])


def get_actor_and_role(
    x_role: Optional[str] = Header(None, alias="X-Role"),
    x_user_role: Optional[str] = Header(None, alias="X-User-Role"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
) -> str:
    role = (x_role or x_user_role or "").strip().lower()
    if not role and authorization:
        role = "analyst"
    return role or "analyst"


def get_workspace_id(
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    x_tenant_id: Optional[str] = Header(None, alias="X-Tenant-ID"),
) -> str:
    return (x_workspace_id or x_tenant_id or "default").strip()


def require_analyst_or_admin(role: str = Depends(get_actor_and_role)) -> str:
    allowed = {"admin", "analyst", "security_lead", "tier2", "tier3", "soc_analyst", "operator"}
    if role not in allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Role '{role}' is not authorized to execute or modify investigation automation.",
        )
    return role


# =============================================================================
# Templates & Policies Endpoints
# =============================================================================

@router.get(
    "/api/investigations/automation/templates",
    response_model=List[AutomationTemplateDefinition],
    summary="List Built-In Investigation Templates",
)
@router.get(
    "/api/v1/investigation-automation/templates",
    response_model=List[AutomationTemplateDefinition],
    summary="List Built-In Investigation Templates (v1)",
)
def list_investigation_templates():
    return InvestigationAutomationService.list_templates()


@router.get(
    "/api/investigations/automation/policies",
    response_model=List[AutomationPolicyRead],
    summary="List Investigation Automation Policies",
)
@router.get(
    "/api/v1/investigation-automation/policies",
    response_model=List[AutomationPolicyRead],
    summary="List Investigation Automation Policies (v1)",
)
def list_policies_endpoint(
    workspace_id: str = Depends(get_workspace_id),
    db: Session = Depends(get_db),
):
    return InvestigationAutomationService.list_policies(db, workspace_id)


@router.post(
    "/api/investigations/automation/policies",
    response_model=AutomationPolicyRead,
    status_code=status.HTTP_201_CREATED,
    summary="Create Investigation Automation Policy",
)
@router.post(
    "/api/v1/investigation-automation/policies",
    response_model=AutomationPolicyRead,
    status_code=status.HTTP_201_CREATED,
    summary="Create Investigation Automation Policy (v1)",
)
def create_policy_endpoint(
    req: AutomationPolicyCreate,
    workspace_id: str = Depends(get_workspace_id),
    role: str = Depends(require_analyst_or_admin),
    db: Session = Depends(get_db),
):
    return InvestigationAutomationService.create_policy(db, workspace_id, req, created_by=role)


# =============================================================================
# Investigation Runs Endpoints
# =============================================================================

@router.post(
    "/api/investigations/{identifier}/automation/runs",
    response_model=InvestigationAutomationRunRead,
    status_code=status.HTTP_201_CREATED,
    summary="Trigger Automated Investigation Run",
)
@router.post(
    "/api/v1/investigation-automation/{identifier}/runs",
    response_model=InvestigationAutomationRunRead,
    status_code=status.HTTP_201_CREATED,
    summary="Trigger Automated Investigation Run (v1)",
)
def create_and_execute_run_endpoint(
    identifier: str,
    req: InvestigationAutomationRunCreate,
    async_exec: bool = Query(False, description="If true, enqueues background job; if false, executes synchronously"),
    workspace_id: str = Depends(get_workspace_id),
    role: str = Depends(require_analyst_or_admin),
    db: Session = Depends(get_db),
):
    try:
        run = InvestigationAutomationService.create_automation_run(
            db=db,
            workspace_id=workspace_id,
            investigation_id=identifier,
            request=req,
            created_by=role,
        )

        if async_exec:
            # Enqueue background job via Section 45
            BackgroundJobService.submit_job(
                db=db,
                request=JobSubmitRequest(
                    job_type=JobTypeEnum.INVESTIGATION_AUTOMATION_RUN,
                    workspace_id=workspace_id,
                    parameters={"run_id": run.id, "investigation_id": identifier},
                ),
            )
            return InvestigationAutomationService.get_run(db, run.id)

        # Synchronous execution
        executed_run = InvestigationAutomationService.execute_automation_run(db, run.id)
        return InvestigationAutomationService.get_run(db, executed_run.id)

    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err))
    except Exception as exc:
        logger.exception("Failed to create and execute automation run: %s", exc)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.get(
    "/api/investigations/{identifier}/automation/runs",
    response_model=List[InvestigationAutomationRunRead],
    summary="List Historical Automation Runs for Investigation",
)
@router.get(
    "/api/v1/investigation-automation/{identifier}/runs",
    response_model=List[InvestigationAutomationRunRead],
    summary="List Historical Automation Runs for Investigation (v1)",
)
def list_runs_endpoint(
    identifier: str,
    limit: int = Query(20, ge=1, le=100),
    workspace_id: str = Depends(get_workspace_id),
    db: Session = Depends(get_db),
):
    return InvestigationAutomationService.list_runs(db, identifier, workspace_id=workspace_id, limit=limit)


@router.get(
    "/api/investigations/{identifier}/automation/runs/{run_id}",
    response_model=InvestigationAutomationRunRead,
    summary="Get Detailed Investigation Automation Run",
)
@router.get(
    "/api/v1/investigation-automation/runs/{run_id}",
    response_model=InvestigationAutomationRunRead,
    summary="Get Detailed Investigation Automation Run (v1)",
)
def get_run_endpoint(
    run_id: str,
    identifier: Optional[str] = None,
    db: Session = Depends(get_db),
):
    run = InvestigationAutomationService.get_run(db, run_id)
    if not run:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Automation run '{run_id}' not found.")
    return run


@router.post(
    "/api/investigations/{identifier}/automation/runs/{run_id}/cancel",
    response_model=InvestigationAutomationRunRead,
    summary="Cancel Running Investigation Automation",
)
@router.post(
    "/api/v1/investigation-automation/runs/{run_id}/cancel",
    response_model=InvestigationAutomationRunRead,
    summary="Cancel Running Investigation Automation (v1)",
)
def cancel_run_endpoint(
    run_id: str,
    identifier: Optional[str] = None,
    role: str = Depends(require_analyst_or_admin),
    db: Session = Depends(get_db),
):
    try:
        run = InvestigationAutomationService.cancel_automation_run(db, run_id, analyst_id=role)
        return InvestigationAutomationService.get_run(db, run.id)
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(val_err))


@router.post(
    "/api/investigations/{identifier}/automation/runs/{run_id}/resume",
    response_model=InvestigationAutomationRunRead,
    summary="Resume Paused or Interrupted Investigation Automation",
)
@router.post(
    "/api/v1/investigation-automation/runs/{run_id}/resume",
    response_model=InvestigationAutomationRunRead,
    summary="Resume Paused or Interrupted Investigation Automation (v1)",
)
def resume_run_endpoint(
    run_id: str,
    identifier: Optional[str] = None,
    role: str = Depends(require_analyst_or_admin),
    db: Session = Depends(get_db),
):
    try:
        run = InvestigationAutomationService.execute_automation_run(db, run_id)
        return InvestigationAutomationService.get_run(db, run.id)
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(val_err))


@router.post(
    "/api/investigations/{identifier}/automation/runs/{run_id}/retry",
    response_model=InvestigationAutomationRunRead,
    summary="Retry Failed Steps on Automation Run",
)
@router.post(
    "/api/v1/investigation-automation/runs/{run_id}/retry",
    response_model=InvestigationAutomationRunRead,
    summary="Retry Failed Steps on Automation Run (v1)",
)
def retry_run_endpoint(
    run_id: str,
    identifier: Optional[str] = None,
    role: str = Depends(require_analyst_or_admin),
    db: Session = Depends(get_db),
):
    try:
        run = InvestigationAutomationService.retry_failed_steps(db, run_id, analyst_id=role)
        return InvestigationAutomationService.get_run(db, run.id)
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(val_err))


@router.post(
    "/api/investigations/{identifier}/automation/runs/{run_id}/steps/{step_index}/approve",
    response_model=InvestigationAutomationRunRead,
    summary="Approve or Reject Gated Investigation Step",
)
@router.post(
    "/api/v1/investigation-automation/runs/{run_id}/steps/{step_index}/approve",
    response_model=InvestigationAutomationRunRead,
    summary="Approve or Reject Gated Investigation Step (v1)",
)
def approve_step_endpoint(
    run_id: str,
    step_index: int,
    req: StepApprovalRequest,
    identifier: Optional[str] = None,
    role: str = Depends(require_analyst_or_admin),
    db: Session = Depends(get_db),
):
    try:
        run = InvestigationAutomationService.approve_step(
            db=db,
            run_id=run_id,
            step_index=step_index,
            analyst_id=role,
            approve=req.approve,
            reason=req.reason,
        )
        return InvestigationAutomationService.get_run(db, run.id)
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(val_err))


@router.get(
    "/api/investigations/{identifier}/automation/gaps",
    response_model=List[InvestigationGapRead],
    summary="List Identified Telemetry & Investigation Gaps",
)
@router.get(
    "/api/v1/investigation-automation/{identifier}/gaps",
    response_model=List[InvestigationGapRead],
    summary="List Identified Telemetry & Investigation Gaps (v1)",
)
def get_gaps_endpoint(
    identifier: str,
    workspace_id: str = Depends(get_workspace_id),
    db: Session = Depends(get_db),
):
    return InvestigationAutomationService.get_investigation_gaps(db, identifier, workspace_id=workspace_id)
