"""
API Routes for MailTraceAI Evidence-Grounded Investigation Copilot.
Exposes endpoints for interactive QA, context-sensitive suggested questions,
report integration, and audit logging.
"""
from typing import List, Optional
from fastapi import APIRouter, Query, status, HTTPException

from backend.schemas.copilot import (
    CopilotMode,
    CopilotQueryRequest,
    CopilotQueryResponse,
    CopilotAddToReportRequest,
    CopilotAuditLogResponse,
    SuggestedQuestion
)
from backend.services.copilot_service import global_copilot_service

router = APIRouter(prefix="/api/copilot", tags=["Investigation Copilot"])


@router.post(
    "/query",
    response_model=CopilotQueryResponse,
    summary="Ask an evidence-grounded natural-language question",
    description="Processes investigator queries against structured forensic evidence, enforcing strict grounding, 5-tier uncertainty, and prompt-injection defenses."
)
async def query_copilot(request: CopilotQueryRequest):
    """
    Query the evidence-grounded investigation copilot.
    """
    payload = request.email_payload
    if payload and (payload.get("is_demo") or payload.get("is_synthetic")):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Demo/synthetic evidence cannot contaminate normal production copilot investigation."
        )
    return await global_copilot_service.query(request)


@router.get(
    "/suggested-questions",
    response_model=List[SuggestedQuestion],
    summary="Get suggested questions for the active investigation context",
    description="Returns pre-calibrated forensic prompts tailored to Email, Case, or Campaign investigation modes."
)
async def get_suggested_questions(
    mode: CopilotMode = Query(CopilotMode.EMAIL, description="Active investigation mode: email, case, or campaign"),
    context_id: Optional[str] = Query(None, description="Active entity ID")
):
    """
    Retrieve suggested questions for the current investigation scope.
    """
    return global_copilot_service.get_suggested_questions(mode=mode, context_id=context_id)


@router.post(
    "/add-to-report",
    summary="Append copilot-generated findings to investigation report",
    description="Integrates an 'AI-Assisted Investigation Summary' into the case or email report with provenance and timestamp."
)
async def add_copilot_summary_to_report(request: CopilotAddToReportRequest):
    """
    Append an AI-Assisted Investigation Summary to an investigation report.
    """
    return global_copilot_service.add_to_report(request)


@router.get(
    "/audit-logs",
    response_model=List[CopilotAuditLogResponse],
    summary="Retrieve Copilot query audit trail",
    description="Returns immutable records of investigator queries, referenced Evidence IDs, and confidence levels without secrets."
)
async def get_copilot_audit_logs(
    limit: int = Query(25, ge=1, le=100, description="Number of recent logs to fetch")
):
    """
    Fetch recent Copilot query audit records.
    """
    return global_copilot_service.get_audit_logs(limit=limit)
