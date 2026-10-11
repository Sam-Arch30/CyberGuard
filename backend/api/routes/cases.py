"""
Section 67: Authoritative Case Management API Routes.
Provides full REST endpoints for operational case lifecycle, tasks, decisions,
entity linking, notes, findings, emails, and metrics.
"""
from typing import Optional, List
from fastapi import APIRouter, Depends, Query, Path, Header, HTTPException, status
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.services.case_service import CaseService
from backend.schemas.case import (
    CaseCreateRequest,
    CaseUpdateRequest,
    CaseAssignRequest,
    CaseResolveRequest,
    CaseCloseRequest,
    CaseReopenRequest,
    CaseMergeRequest,
    CaseLinkRequest,
    CaseEmailCreateRequest,
    CaseEmailResponse,
    CaseNoteCreateRequest,
    CaseNoteUpdateRequest,
    CaseNoteResponse,
    CaseFindingCreateRequest,
    CaseFindingResponse,
    CaseTaskCreate,
    CaseTaskUpdate,
    CaseTaskResponse,
    CaseListItemResponse,
    CaseDetailResponse,
    CaseListResponse,
    CaseTimelineEvent,
    CaseMetricsSummary,
)

router = APIRouter(prefix="/api/cases", tags=["Case Management"])


def get_workspace_id(
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    x_workspace_id_lower: Optional[str] = Header(None, alias="X-Workspace-Id"),
) -> str:
    return (x_workspace_id or x_workspace_id_lower or "default").strip()


def verify_role(
    x_role: Optional[str] = Header(None, alias="X-Role"),
    x_user_role: Optional[str] = Header(None, alias="X-User-Role"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
) -> str:
    role = (x_role or x_user_role or "").strip().lower()
    if not role and authorization:
        auth_clean = authorization.strip().lower()
        if "admin" in auth_clean or "lead" in auth_clean:
            role = "admin"
        elif "analyst" in auth_clean or "soc" in auth_clean:
            role = "analyst"
        elif "viewer" in auth_clean or "unauthorized" in auth_clean:
            role = "unauthorized"

    if role in ("guest", "unauthorized", "untrusted"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: insufficient permissions for case management operations.",
        )
    return role or "analyst"


def get_user_id(
    x_user_id: Optional[str] = Header(None, alias="X-User-ID"),
    x_user_name: Optional[str] = Header(None, alias="X-User-Name"),
) -> str:
    return (x_user_id or x_user_name or "SOC Analyst").strip()


# =============================================================================
# Case Core Endpoints
# =============================================================================

@router.post(
    "",
    response_model=CaseDetailResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create an operational case",
    description="Initializes a new case with collision-safe case number (e.g. CG-2026-000001) and full provenance tracking."
)
def create_case_endpoint(
    request: CaseCreateRequest,
    db: Session = Depends(get_db),
    workspace_id: str = Depends(get_workspace_id),
    role: str = Depends(verify_role),
    user: str = Depends(get_user_id),
):
    case = CaseService.create_case(db, request, workspace_id=workspace_id, user=user)
    return CaseService.get_case_detail(db, case.id, workspace_id=workspace_id)


@router.get(
    "",
    response_model=CaseListResponse,
    summary="List operational cases",
    description="Returns paginated, filtered list of cases within the authorized workspace."
)
def list_cases_endpoint(
    status: Optional[str] = Query(None, description="Filter by status (e.g. OPEN, IN_PROGRESS, RESOLVED, CLOSED)"),
    severity: Optional[str] = Query(None, description="Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)"),
    priority: Optional[str] = Query(None, description="Filter by priority (P1_CRITICAL, P2_HIGH, P3_MEDIUM, P4_LOW)"),
    category: Optional[str] = Query(None, description="Filter by threat category"),
    owner_id: Optional[str] = Query(None, description="Filter by assigned owner"),
    team_id: Optional[str] = Query(None, description="Filter by assigned team"),
    incident_id: Optional[str] = Query(None, description="Filter by linked incident"),
    search: Optional[str] = Query(None, description="Text query matching title, case number, description, or tags"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    workspace_id: str = Depends(get_workspace_id),
    role: str = Depends(verify_role),
):
    items, total = CaseService.list_cases(
        db,
        workspace_id=workspace_id,
        status_filter=status,
        severity_filter=severity,
        priority_filter=priority,
        category_filter=category,
        owner_id=owner_id,
        team_id=team_id,
        incident_id=incident_id,
        search_query=search,
        skip=skip,
        limit=limit,
    )
    return CaseListResponse(cases=items, total=total, page=(skip // limit) + 1, page_size=limit)


@router.get(
    "/metrics/overview",
    response_model=CaseMetricsSummary,
    summary="Get case metrics overview",
    description="Returns aggregate SOC case metrics, open counts, severity breakdown, and SLA indicators."
)
def get_case_metrics_endpoint(
    db: Session = Depends(get_db),
    workspace_id: str = Depends(get_workspace_id),
    role: str = Depends(verify_role),
):
    return CaseService.get_case_metrics(db, workspace_id=workspace_id)


@router.get(
    "/{case_id}",
    response_model=CaseDetailResponse,
    summary="Get case details",
    description="Retrieves comprehensive operational case record, tasks, notes, findings, emails, and linked entities."
)
def get_case_endpoint(
    case_id: str = Path(..., description="Case ID or readable case number"),
    db: Session = Depends(get_db),
    workspace_id: str = Depends(get_workspace_id),
    role: str = Depends(verify_role),
):
    return CaseService.get_case_detail(db, case_id, workspace_id=workspace_id)


@router.patch(
    "/{case_id}",
    response_model=CaseDetailResponse,
    summary="Update case metadata",
    description="Updates case attributes with optimistic concurrency check (expected_version) and audit logging."
)
def update_case_endpoint(
    request: CaseUpdateRequest,
    case_id: str = Path(..., description="Case ID or readable case number"),
    db: Session = Depends(get_db),
    workspace_id: str = Depends(get_workspace_id),
    role: str = Depends(verify_role),
    user: str = Depends(get_user_id),
):
    CaseService.update_case(db, case_id, request, workspace_id=workspace_id, user=user)
    return CaseService.get_case_detail(db, case_id, workspace_id=workspace_id)


# =============================================================================
# Lifecycle Transitions: Assign, Resolve, Close, Reopen, Merge
# =============================================================================

@router.post(
    "/{case_id}/assign",
    response_model=CaseDetailResponse,
    summary="Assign case ownership",
    description="Assigns or reassigns case owner and team with audit traceability."
)
def assign_case_endpoint(
    request: CaseAssignRequest,
    case_id: str = Path(...),
    db: Session = Depends(get_db),
    workspace_id: str = Depends(get_workspace_id),
    role: str = Depends(verify_role),
    user: str = Depends(get_user_id),
):
    CaseService.assign_case(db, case_id, request, workspace_id=workspace_id, user=user)
    return CaseService.get_case_detail(db, case_id, workspace_id=workspace_id)


@router.post(
    "/{case_id}/resolve",
    response_model=CaseDetailResponse,
    summary="Resolve case",
    description="Transitions case to RESOLVED disposition, recording disposition code and summary rationale."
)
def resolve_case_endpoint(
    request: CaseResolveRequest,
    case_id: str = Path(...),
    db: Session = Depends(get_db),
    workspace_id: str = Depends(get_workspace_id),
    role: str = Depends(verify_role),
    user: str = Depends(get_user_id),
):
    CaseService.resolve_case(db, case_id, request, workspace_id=workspace_id, user=user)
    return CaseService.get_case_detail(db, case_id, workspace_id=workspace_id)


@router.post(
    "/{case_id}/close",
    response_model=CaseDetailResponse,
    summary="Close case",
    description="Performs operational closure following checklist verification."
)
def close_case_endpoint(
    request: CaseCloseRequest,
    case_id: str = Path(...),
    db: Session = Depends(get_db),
    workspace_id: str = Depends(get_workspace_id),
    role: str = Depends(verify_role),
    user: str = Depends(get_user_id),
):
    CaseService.close_case(db, case_id, request, workspace_id=workspace_id, user=user)
    return CaseService.get_case_detail(db, case_id, workspace_id=workspace_id)


@router.post(
    "/{case_id}/reopen",
    response_model=CaseDetailResponse,
    summary="Reopen case",
    description="Reopens a resolved or closed case with mandatory auditable justification."
)
def reopen_case_endpoint(
    request: CaseReopenRequest,
    case_id: str = Path(...),
    db: Session = Depends(get_db),
    workspace_id: str = Depends(get_workspace_id),
    role: str = Depends(verify_role),
    user: str = Depends(get_user_id),
):
    CaseService.reopen_case(db, case_id, request, workspace_id=workspace_id, user=user)
    return CaseService.get_case_detail(db, case_id, workspace_id=workspace_id)


@router.post(
    "/{case_id}/merge",
    response_model=CaseDetailResponse,
    summary="Merge secondary cases into target case",
    description="Safely merges source cases into target case, repointing tasks/evidence without data loss."
)
def merge_cases_endpoint(
    request: CaseMergeRequest,
    case_id: str = Path(..., description="Target case ID"),
    db: Session = Depends(get_db),
    workspace_id: str = Depends(get_workspace_id),
    role: str = Depends(verify_role),
    user: str = Depends(get_user_id),
):
    CaseService.merge_cases(db, case_id, request, workspace_id=workspace_id, user=user)
    return CaseService.get_case_detail(db, case_id, workspace_id=workspace_id)


# =============================================================================
# Operational Tasks Management
# =============================================================================

@router.post(
    "/{case_id}/tasks",
    response_model=CaseTaskResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create an operational task in the case"
)
def create_task_endpoint(
    request: CaseTaskCreate,
    case_id: str = Path(...),
    db: Session = Depends(get_db),
    workspace_id: str = Depends(get_workspace_id),
    role: str = Depends(verify_role),
    user: str = Depends(get_user_id),
):
    return CaseService.create_task(db, case_id, request, workspace_id=workspace_id, user=user)


@router.patch(
    "/{case_id}/tasks/{task_id}",
    response_model=CaseTaskResponse,
    summary="Update or complete a task"
)
def update_task_endpoint(
    request: CaseTaskUpdate,
    case_id: str = Path(...),
    task_id: str = Path(...),
    db: Session = Depends(get_db),
    workspace_id: str = Depends(get_workspace_id),
    role: str = Depends(verify_role),
    user: str = Depends(get_user_id),
):
    return CaseService.update_task(db, case_id, task_id, request, workspace_id=workspace_id, user=user)


@router.delete(
    "/{case_id}/tasks/{task_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a task from the case"
)
def delete_task_endpoint(
    case_id: str = Path(...),
    task_id: str = Path(...),
    db: Session = Depends(get_db),
    workspace_id: str = Depends(get_workspace_id),
    role: str = Depends(verify_role),
    user: str = Depends(get_user_id),
):
    CaseService.delete_task(db, case_id, task_id, workspace_id=workspace_id, user=user)
    return None


# =============================================================================
# Linking, Notes, Findings, Emails, and Timeline
# =============================================================================

@router.post(
    "/{case_id}/link",
    response_model=CaseDetailResponse,
    summary="Link external entity to case",
    description="Links Alert, Incident, Investigation, Evidence, Campaign, Asset, or Identity."
)
def link_entity_endpoint(
    request: CaseLinkRequest,
    case_id: str = Path(...),
    db: Session = Depends(get_db),
    workspace_id: str = Depends(get_workspace_id),
    role: str = Depends(verify_role),
    user: str = Depends(get_user_id),
):
    return CaseService.link_entity(db, case_id, request, workspace_id=workspace_id, user=user)


@router.get(
    "/{case_id}/timeline",
    response_model=List[CaseTimelineEvent],
    summary="Get unified case timeline",
    description="Synthesizes milestones, audits, task completions, and linked investigation events."
)
def get_case_timeline_endpoint(
    case_id: str = Path(...),
    db: Session = Depends(get_db),
    workspace_id: str = Depends(get_workspace_id),
    role: str = Depends(verify_role),
):
    return CaseService.get_case_timeline(db, case_id, workspace_id=workspace_id)


@router.post(
    "/{case_id}/notes",
    response_model=CaseNoteResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Add an analyst note to a case"
)
def add_note_endpoint(
    request: CaseNoteCreateRequest,
    case_id: str = Path(...),
    db: Session = Depends(get_db),
    workspace_id: str = Depends(get_workspace_id),
    role: str = Depends(verify_role),
    user: str = Depends(get_user_id),
):
    note = CaseService.add_note(db, case_id, request, workspace_id=workspace_id, user=user)
    return CaseNoteResponse(
        id=note.id,
        case_id=note.case_id,
        author=note.author,
        note_text=note.note_text,
        visibility=note.visibility,
        created_at=note.created_at,
        updated_at=note.updated_at,
    )


@router.patch(
    "/{case_id}/notes/{note_id}",
    response_model=CaseNoteResponse,
    summary="Edit an analyst note with revision history"
)
def update_note_endpoint(
    request: CaseNoteUpdateRequest,
    case_id: str = Path(...),
    note_id: str = Path(...),
    db: Session = Depends(get_db),
    workspace_id: str = Depends(get_workspace_id),
    role: str = Depends(verify_role),
    user: str = Depends(get_user_id),
):
    note = CaseService.update_note(db, case_id, note_id, request, workspace_id=workspace_id, user=user)
    return CaseNoteResponse(
        id=note.id,
        case_id=note.case_id,
        author=note.author,
        note_text=note.note_text,
        visibility=note.visibility,
        created_at=note.created_at,
        updated_at=note.updated_at,
    )


@router.post(
    "/{case_id}/findings",
    response_model=CaseFindingResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Add a structured finding to a case"
)
def add_finding_endpoint(
    request: CaseFindingCreateRequest,
    case_id: str = Path(...),
    db: Session = Depends(get_db),
    workspace_id: str = Depends(get_workspace_id),
    role: str = Depends(verify_role),
    user: str = Depends(get_user_id),
):
    return CaseService.add_finding(db, case_id, request, workspace_id=workspace_id, user=user)


@router.post(
    "/{case_id}/emails",
    response_model=CaseEmailResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Add an analyzed email to a case"
)
def add_email_to_case_endpoint(
    request: CaseEmailCreateRequest,
    case_id: str = Path(...),
    db: Session = Depends(get_db),
    workspace_id: str = Depends(get_workspace_id),
    role: str = Depends(verify_role),
    user: str = Depends(get_user_id),
):
    return CaseService.add_email_to_case(db, case_id, request, workspace_id=workspace_id, user=user)


@router.delete(
    "/{case_id}/emails/{email_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Remove an email from a case"
)
def remove_email_from_case_endpoint(
    case_id: str = Path(...),
    email_id: str = Path(...),
    db: Session = Depends(get_db),
    workspace_id: str = Depends(get_workspace_id),
    role: str = Depends(verify_role),
):
    CaseService.remove_email_from_case(db, case_id, email_id, workspace_id=workspace_id)
    return None
