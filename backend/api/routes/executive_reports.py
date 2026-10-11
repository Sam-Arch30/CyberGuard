"""
Section 69: Executive Reporting & Intelligence Dissemination REST API Router.
Provides enterprise endpoints for versioned report templates, immutable point-in-time
snapshots, peer review & approval workflows, redaction controls, and external share links.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional
from datetime import datetime

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Response, status
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.db.models import ReportSnapshotModel
from backend.schemas.executive_reports import (
    ReportTemplateCreateRequest,
    ReportTemplateUpdateRequest,
    ReportTemplateResponse,
    ReportTemplateListResponse,
    ReportSectionConfig,
    ReportSnapshotResponse,
    ReportSnapshotDetailResponse,
    ReportShareLinkCreateRequest,
    ReportShareLinkResponse,
    ReportShareLinkListResponse,
    PublicReportShareResponse,
    ExecutiveReportCreateRequest,
    ExecutiveReportUpdateRequest,
    ReportReviewRequest,
    ReportAddReviewNoteRequest,
    ReportApprovalRequest,
    ReportFinalizeRequest,
    ExecutiveReportDetailResponse,
    ExecutiveReportListResponse,
    ExecutiveReportListItemResponse,
    ExecutiveReportMetricsResponse,
    ReviewNote,
)
from backend.services.executive_report_service import ExecutiveReportService

logger = logging.getLogger("cyberguard.executive_reports_api")

router = APIRouter(prefix="/api/executive-reports", tags=["Executive Reports & Dissemination"])


def get_current_user_and_role(
    x_user: Optional[str] = Header(None, alias="X-User"),
    x_actor_id: Optional[str] = Header(None, alias="X-Actor-ID"),
    x_role: Optional[str] = Header(None, alias="X-Role"),
    x_user_role: Optional[str] = Header(None, alias="X-User-Role"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
) -> tuple[str, str]:
    user = (x_user or x_actor_id or "").strip() or "SOC Analyst"
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
            detail="Forbidden: insufficient permissions for executive reporting operations.",
        )

    return user, role or "analyst"


def _serialize_template(tmpl) -> ReportTemplateResponse:
    sections = []
    try:
        raw = json.loads(tmpl.sections_config_json or "[]")
        sections = [ReportSectionConfig(**s) for s in raw]
    except Exception:
        sections = []

    return ReportTemplateResponse(
        id=tmpl.id,
        workspace_id=tmpl.workspace_id,
        tenant_id=tmpl.tenant_id,
        template_key=tmpl.template_key,
        template_name=tmpl.template_name,
        report_type=tmpl.report_type,
        version=tmpl.version,
        description=tmpl.description,
        sections_config=sections,
        default_classification=tmpl.default_classification,
        default_redaction=tmpl.default_redaction,
        is_system=tmpl.is_system,
        is_active=tmpl.is_active,
        created_by=tmpl.created_by,
        created_at=tmpl.created_at,
        updated_at=tmpl.updated_at,
    )


def _serialize_report_detail(rpt) -> ExecutiveReportDetailResponse:
    rev_notes = []
    try:
        raw_notes = json.loads(rpt.review_notes_json or "[]")
        for rn in raw_notes:
            rev_notes.append(
                ReviewNote(
                    author=rn.get("author", "Unknown"),
                    timestamp=datetime.fromisoformat(rn["timestamp"]) if "timestamp" in rn else rpt.created_at,
                    content=rn.get("content", ""),
                    status=rn.get("status", "COMMENT"),
                )
            )
    except Exception:
        rev_notes = []

    reviewers = []
    try:
        reviewers = json.loads(rpt.reviewers_json or "[]")
    except Exception:
        reviewers = []

    evidence_gaps = []
    try:
        evidence_gaps = json.loads(rpt.evidence_gaps_json or "[]")
    except Exception:
        evidence_gaps = []

    recommendations = []
    try:
        recommendations = json.loads(rpt.recommendations_json or "[]")
    except Exception:
        recommendations = []

    return ExecutiveReportDetailResponse(
        id=rpt.id,
        report_number=rpt.report_number,
        title=rpt.title,
        report_type=rpt.report_type,
        status=rpt.status,
        report_version=rpt.report_version or 1,
        classification=rpt.classification,
        redaction_level=rpt.redaction_level,
        threat_score=rpt.threat_score or 0.0,
        severity=rpt.severity or "low",
        confidence=rpt.confidence or 1.0,
        summary=rpt.summary,
        analyst_name=rpt.analyst_name,
        incident_id=rpt.incident_id,
        case_id=rpt.case_id,
        investigation_id=rpt.investigation_id,
        evidence_id=rpt.evidence_id,
        template_id=rpt.template_id,
        template_version=rpt.template_version or 1,
        source_snapshot_id=rpt.source_snapshot_id,
        source_data_hash=rpt.source_data_hash,
        created_by=rpt.created_by,
        created_at=rpt.created_at,
        updated_at=rpt.updated_at or rpt.created_at,
        generated_at=rpt.generated_at,
        finalized_at=rpt.finalized_at,
        finalized_by=rpt.finalized_by,
        approved_at=rpt.approved_at,
        approved_by=rpt.approved_by,
        is_immutable=rpt.is_immutable,
        review_notes=rev_notes,
        reviewers=reviewers,
        evidence_gaps=evidence_gaps,
        recommendations=recommendations,
        file_path=rpt.file_path,
        file_size_bytes=rpt.file_size_bytes or 0,
        html_content=rpt.html_content,
        workspace_id=rpt.workspace_id or "default",
        tenant_id=rpt.tenant_id or "default",
    )


# -----------------------------------------------------------------------------
# Template Endpoints
# -----------------------------------------------------------------------------

@router.get("/templates", response_model=ReportTemplateListResponse)
def list_templates_endpoint(
    report_type: Optional[str] = Query(None),
    include_inactive: bool = Query(False),
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db),
    user_and_role: tuple[str, str] = Depends(get_current_user_and_role),
):
    items = ExecutiveReportService.list_templates(
        db=db,
        workspace_id=workspace_id,
        report_type=report_type,
        include_inactive=include_inactive,
    )
    return ReportTemplateListResponse(
        items=[_serialize_template(t) for t in items],
        total=len(items),
    )


@router.post("/templates", response_model=ReportTemplateResponse, status_code=status.HTTP_201_CREATED)
def create_template_endpoint(
    req: ReportTemplateCreateRequest,
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db),
    user_and_role: tuple[str, str] = Depends(get_current_user_and_role),
):
    user, role = user_and_role
    if role not in ("admin", "lead", "senior_analyst", "analyst"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role to create report templates.")

    tmpl = ExecutiveReportService.create_template(
        db=db,
        req=req,
        created_by=user,
        workspace_id=workspace_id,
    )
    return _serialize_template(tmpl)


@router.get("/templates/{template_id}", response_model=ReportTemplateResponse)
def get_template_endpoint(
    template_id: str,
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db),
    user_and_role: tuple[str, str] = Depends(get_current_user_and_role),
):
    tmpl = ExecutiveReportService.get_template(db, template_id, workspace_id)
    if not tmpl:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Template not found")
    return _serialize_template(tmpl)


@router.put("/templates/{template_id}", response_model=ReportTemplateResponse)
def update_template_endpoint(
    template_id: str,
    req: ReportTemplateUpdateRequest,
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db),
    user_and_role: tuple[str, str] = Depends(get_current_user_and_role),
):
    user, role = user_and_role
    if role not in ("admin", "lead", "senior_analyst"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only lead analysts or administrators can modify templates.")

    tmpl = ExecutiveReportService.update_template(db, template_id, req, user, workspace_id)
    return _serialize_template(tmpl)


@router.delete("/templates/{template_id}")
def delete_template_endpoint(
    template_id: str,
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db),
    user_and_role: tuple[str, str] = Depends(get_current_user_and_role),
):
    user, role = user_and_role
    if role not in ("admin", "lead"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin role required to delete report templates.")

    ExecutiveReportService.delete_template(db, template_id, workspace_id)
    return {"status": "success", "message": f"Template {template_id} deactivated."}


# -----------------------------------------------------------------------------
# Report Endpoints
# -----------------------------------------------------------------------------

@router.get("/reports", response_model=ExecutiveReportListResponse)
def list_reports_endpoint(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    status_filter: Optional[str] = Query(None, alias="status"),
    report_type: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db),
    user_and_role: tuple[str, str] = Depends(get_current_user_and_role),
):
    reports, total = ExecutiveReportService.list_executive_reports(
        db=db,
        workspace_id=workspace_id,
        skip=skip,
        limit=limit,
        status_filter=status_filter,
        report_type=report_type,
        severity=severity,
    )
    items = []
    for r in reports:
        items.append(
            ExecutiveReportListItemResponse(
                id=r.id,
                report_number=r.report_number,
                title=r.title,
                report_type=r.report_type,
                status=r.status,
                report_version=r.report_version or 1,
                classification=r.classification,
                redaction_level=r.redaction_level,
                threat_score=r.threat_score or 0.0,
                severity=r.severity or "low",
                confidence=r.confidence or 1.0,
                incident_id=r.incident_id,
                case_id=r.case_id,
                investigation_id=r.investigation_id,
                is_immutable=r.is_immutable,
                created_by=r.created_by,
                created_at=r.created_at,
                finalized_at=r.finalized_at,
                share_links_count=len(r.share_links) if r.share_links else 0,
            )
        )
    return ExecutiveReportListResponse(items=items, total=total)


@router.post("/reports", response_model=ExecutiveReportDetailResponse, status_code=status.HTTP_201_CREATED)
def create_report_endpoint(
    req: ExecutiveReportCreateRequest,
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db),
    user_and_role: tuple[str, str] = Depends(get_current_user_and_role),
):
    user, role = user_and_role
    report = ExecutiveReportService.create_executive_report(
        db=db,
        req=req,
        created_by=user,
        workspace_id=workspace_id,
    )
    return _serialize_report_detail(report)


@router.get("/reports/{report_id}", response_model=ExecutiveReportDetailResponse)
def get_report_endpoint(
    report_id: str,
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db),
    user_and_role: tuple[str, str] = Depends(get_current_user_and_role),
):
    report = ExecutiveReportService.get_report(db, report_id, workspace_id)
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
    return _serialize_report_detail(report)


@router.put("/reports/{report_id}", response_model=ExecutiveReportDetailResponse)
def update_report_endpoint(
    report_id: str,
    req: ExecutiveReportUpdateRequest,
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db),
    user_and_role: tuple[str, str] = Depends(get_current_user_and_role),
):
    user, role = user_and_role
    report = ExecutiveReportService.update_report(db, report_id, req, user, workspace_id)
    return _serialize_report_detail(report)


@router.get("/reports/{report_id}/preview", response_class=HTMLResponse)
def get_report_preview_endpoint(
    report_id: str,
    redaction_level: Optional[str] = Query(None),
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db),
    user_and_role: tuple[str, str] = Depends(get_current_user_and_role),
):
    report = ExecutiveReportService.get_report(db, report_id, workspace_id)
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")

    target_redaction = redaction_level or report.redaction_level
    tmpl = report.template or ExecutiveReportService.get_template(db, report.report_type, workspace_id)
    snapshot = db.query(ReportSnapshotModel).filter(ReportSnapshotModel.id == report.source_snapshot_id).first()
    payload = json.loads(snapshot.snapshot_payload_json) if snapshot else {}

    html_content = ExecutiveReportService.render_html_content(report, tmpl, payload, target_redaction)
    return HTMLResponse(content=html_content)


@router.get("/reports/{report_id}/snapshots", response_model=List[ReportSnapshotResponse])
def get_report_snapshots_endpoint(
    report_id: str,
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db),
    user_and_role: tuple[str, str] = Depends(get_current_user_and_role),
):
    snapshots = (
        db.query(ReportSnapshotModel)
        .filter(
            ReportSnapshotModel.report_id == report_id,
            ReportSnapshotModel.workspace_id == workspace_id,
        )
        .order_by(ReportSnapshotModel.created_at.desc())
        .all()
    )
    result = []
    for s in snapshots:
        result.append(
            ReportSnapshotResponse(
                id=s.id,
                report_id=s.report_id,
                workspace_id=s.workspace_id,
                tenant_id=s.tenant_id,
                snapshot_hash=s.snapshot_hash,
                source_identifiers=json.loads(s.source_identifiers_json or "{}"),
                source_versions=json.loads(s.source_versions_json or "{}"),
                epistemic_labels=json.loads(s.epistemic_labels_json or "{}"),
                created_at=s.created_at,
            )
        )
    return result


@router.post("/reports/{report_id}/review", response_model=ExecutiveReportDetailResponse)
def request_review_endpoint(
    report_id: str,
    req: ReportReviewRequest,
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db),
    user_and_role: tuple[str, str] = Depends(get_current_user_and_role),
):
    user, role = user_and_role
    report = ExecutiveReportService.request_review(db, report_id, req, user, workspace_id)
    return _serialize_report_detail(report)


@router.post("/reports/{report_id}/review-note", response_model=ExecutiveReportDetailResponse)
def add_review_note_endpoint(
    report_id: str,
    req: ReportAddReviewNoteRequest,
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db),
    user_and_role: tuple[str, str] = Depends(get_current_user_and_role),
):
    user, role = user_and_role
    report = ExecutiveReportService.add_review_note(db, report_id, req, user, workspace_id)
    return _serialize_report_detail(report)


@router.post("/reports/{report_id}/approve", response_model=ExecutiveReportDetailResponse)
def approve_report_endpoint(
    report_id: str,
    req: ReportApprovalRequest,
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db),
    user_and_role: tuple[str, str] = Depends(get_current_user_and_role),
):
    user, role = user_and_role
    if role not in ("admin", "lead", "senior_analyst"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only lead or senior analysts may formally approve reports.")

    report = ExecutiveReportService.approve_report(db, report_id, req, user, workspace_id)
    return _serialize_report_detail(report)


@router.post("/reports/{report_id}/finalize", response_model=ExecutiveReportDetailResponse)
def finalize_report_endpoint(
    report_id: str,
    req: ReportFinalizeRequest,
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db),
    user_and_role: tuple[str, str] = Depends(get_current_user_and_role),
):
    user, role = user_and_role
    if role not in ("admin", "lead"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Administrator or lead analyst role required to lock/finalize reports.")

    report = ExecutiveReportService.finalize_report(db, report_id, req, user, workspace_id)
    return _serialize_report_detail(report)


@router.post("/reports/{report_id}/version", response_model=ExecutiveReportDetailResponse)
def create_version_endpoint(
    report_id: str,
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db),
    user_and_role: tuple[str, str] = Depends(get_current_user_and_role),
):
    user, role = user_and_role
    child = ExecutiveReportService.create_version(db, report_id, user, workspace_id)
    return _serialize_report_detail(child)


# -----------------------------------------------------------------------------
# Share Link Endpoints
# -----------------------------------------------------------------------------

@router.get("/reports/{report_id}/share-links", response_model=ReportShareLinkListResponse)
def list_share_links_endpoint(
    report_id: str,
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db),
    user_and_role: tuple[str, str] = Depends(get_current_user_and_role),
):
    links = ExecutiveReportService.list_share_links(db, report_id, workspace_id)
    items = []
    for lnk in links:
        items.append(
            ReportShareLinkResponse(
                id=lnk.id,
                report_id=lnk.report_id,
                workspace_id=lnk.workspace_id,
                tenant_id=lnk.tenant_id,
                format=lnk.format,
                classification=lnk.classification,
                redaction_level=lnk.redaction_level,
                expires_at=lnk.expires_at,
                max_uses=lnk.max_uses,
                use_count=lnk.use_count,
                is_revoked=lnk.is_revoked,
                revoked_at=lnk.revoked_at,
                revoked_by=lnk.revoked_by,
                created_by=lnk.created_by,
                created_at=lnk.created_at,
            )
        )
    return ReportShareLinkListResponse(items=items, total=len(items))


@router.post("/reports/{report_id}/share-links", response_model=ReportShareLinkResponse, status_code=status.HTTP_201_CREATED)
def create_share_link_endpoint(
    report_id: str,
    req: ReportShareLinkCreateRequest,
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db),
    user_and_role: tuple[str, str] = Depends(get_current_user_and_role),
):
    user, role = user_and_role
    link, raw_token = ExecutiveReportService.create_share_link(db, report_id, req, user, workspace_id)
    share_url = f"/api/executive-reports/public/share/{raw_token}"

    return ReportShareLinkResponse(
        id=link.id,
        report_id=link.report_id,
        workspace_id=link.workspace_id,
        tenant_id=link.tenant_id,
        share_token=raw_token,
        share_url=share_url,
        format=link.format,
        classification=link.classification,
        redaction_level=link.redaction_level,
        expires_at=link.expires_at,
        max_uses=link.max_uses,
        use_count=link.use_count,
        is_revoked=link.is_revoked,
        revoked_at=link.revoked_at,
        revoked_by=link.revoked_by,
        created_by=link.created_by,
        created_at=link.created_at,
    )


@router.post("/share-links/{link_id}/revoke", response_model=ReportShareLinkResponse)
def revoke_share_link_endpoint(
    link_id: str,
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db),
    user_and_role: tuple[str, str] = Depends(get_current_user_and_role),
):
    user, role = user_and_role
    link = ExecutiveReportService.revoke_share_link(db, link_id, user, workspace_id)
    return ReportShareLinkResponse(
        id=link.id,
        report_id=link.report_id,
        workspace_id=link.workspace_id,
        tenant_id=link.tenant_id,
        format=link.format,
        classification=link.classification,
        redaction_level=link.redaction_level,
        expires_at=link.expires_at,
        max_uses=link.max_uses,
        use_count=link.use_count,
        is_revoked=link.is_revoked,
        revoked_at=link.revoked_at,
        revoked_by=link.revoked_by,
        created_by=link.created_by,
        created_at=link.created_at,
    )


# -----------------------------------------------------------------------------
# Public External Dissemination Access (No Auth required; protected by Token)
# -----------------------------------------------------------------------------

@router.get("/public/share/{token}", response_model=PublicReportShareResponse)
def get_public_share_report(token: str, db: Session = Depends(get_db)):
    report, link, html_str = ExecutiveReportService.resolve_public_share_token(db, token)

    evidence_gaps = []
    try:
        evidence_gaps = json.loads(report.evidence_gaps_json or "[]")
    except Exception:
        evidence_gaps = []

    recommendations = []
    try:
        recommendations = json.loads(report.recommendations_json or "[]")
    except Exception:
        recommendations = []

    return PublicReportShareResponse(
        report_number=report.report_number,
        title=report.title,
        report_type=report.report_type,
        classification=link.classification,
        redaction_level=link.redaction_level,
        generated_at=report.generated_at,
        finalized_at=report.finalized_at,
        summary=ExecutiveReportService.apply_redaction_to_text(report.summary or "", link.redaction_level),
        threat_score=report.threat_score or 0.0,
        severity=report.severity or "low",
        confidence=report.confidence or 1.0,
        html_content=html_str,
        evidence_gaps=evidence_gaps,
        recommendations=[ExecutiveReportService.apply_redaction_to_text(r, link.redaction_level) for r in recommendations],
        source_data_hash=report.source_data_hash,
        download_available=bool(report.file_path),
    )


@router.get("/public/share/{token}/html", response_class=HTMLResponse)
def get_public_share_report_html(token: str, db: Session = Depends(get_db)):
    _, _, html_str = ExecutiveReportService.resolve_public_share_token(db, token)
    return HTMLResponse(content=html_str)


# -----------------------------------------------------------------------------
# Metrics Endpoint
# -----------------------------------------------------------------------------

@router.get("/metrics", response_model=ExecutiveReportMetricsResponse)
def get_report_metrics_endpoint(
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db),
    user_and_role: tuple[str, str] = Depends(get_current_user_and_role),
):
    metrics = ExecutiveReportService.get_metrics(db, workspace_id)
    return ExecutiveReportMetricsResponse(**metrics)
