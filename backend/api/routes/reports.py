import os
import uuid
import hashlib
import json
from typing import Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.db.models import ReportModel, CaseModel, CaseEmailModel, ArtifactModel
from backend.schemas.report import (
    ReportGenerateRequest,
    InvestigationReportGenerateRequest,
    InvestigationReportPreviewRequest,
    ReportListResponse,
    ReportListItemResponse,
    ReportDetailResponse,
    ReportVersionComparisonResponse,
)
from backend.services.report_service import ReportService
from backend.services.report_projection_service import ReportProjectionService
from backend.services.audit_service import AuditService
from backend.services.evidence_storage import evidence_storage
from backend.services.investigation_workspace_service import InvestigationWorkspaceService

router = APIRouter(prefix="/api/reports", tags=["Forensic Reports"])


def _generate_report_number(db: Session) -> str:
    """Generates sequential report number: RPT-2026-000001."""
    current_year = datetime.now(timezone.utc).year
    prefix = f"RPT-{current_year}-"

    last_rpt = (
        db.query(ReportModel)
        .filter(ReportModel.report_number.like(f"{prefix}%"))
        .order_by(ReportModel.report_number.desc())
        .first()
    )

    if last_rpt:
        try:
            last_seq = int(last_rpt.report_number.split("-")[-1])
            next_seq = last_seq + 1
        except (ValueError, IndexError):
            next_seq = 1
    else:
        next_seq = 1

    return f"{prefix}{next_seq:06d}"


def _serialize_report_item(r: ReportModel, is_stale: bool = False) -> ReportListItemResponse:
    """Safely converts ReportModel to ReportListItemResponse."""
    return ReportListItemResponse(
        id=r.id,
        report_number=r.report_number,
        title=r.title,
        investigation_id=r.investigation_id,
        incident_number=r.investigation_id,
        case_id=r.case_id,
        evidence_id=r.evidence_id,
        email_sha256=r.email_sha256,
        threat_score=r.threat_score or 0.0,
        severity=r.severity or "low",
        confidence=r.confidence or 1.0,
        report_type=r.report_type or "ANALYST",
        status=r.status or "READY",
        report_version=r.report_version or 1,
        classification=r.classification or "CONFIDENTIAL",
        redaction_level=r.redaction_level or "NONE",
        is_stale=is_stale,
        analyst_name=r.analyst_name or "SOC Analyst",
        summary=r.summary or "",
        file_size_bytes=r.file_size_bytes or 0,
        created_at=r.created_at,
        download_url=f"/api/reports/{r.id}/download"
    )


def _serialize_report_detail(r: ReportModel, is_stale: bool = False) -> ReportDetailResponse:
    """Safely converts ReportModel to full ReportDetailResponse."""
    snapshot = json.loads(r.snapshot_data_json) if r.snapshot_data_json else {}
    quality_check = json.loads(r.quality_check_json) if r.quality_check_json else {}
    content_options = json.loads(r.content_options_json) if r.content_options_json else {}
    provenance = snapshot.get("provenance", {})

    return ReportDetailResponse(
        id=r.id,
        report_number=r.report_number,
        title=r.title,
        investigation_id=r.investigation_id,
        incident_number=snapshot.get("metadata", {}).get("incident_number") or r.investigation_id,
        case_id=r.case_id,
        evidence_id=r.evidence_id,
        email_sha256=r.email_sha256,
        threat_score=r.threat_score or 0.0,
        severity=r.severity or "low",
        confidence=r.confidence or 1.0,
        report_type=r.report_type or "ANALYST",
        status=r.status or "READY",
        report_version=r.report_version or 1,
        classification=r.classification or "CONFIDENTIAL",
        redaction_level=r.redaction_level or "NONE",
        is_stale=is_stale,
        analyst_name=r.analyst_name or "SOC Lead Analyst",
        summary=r.summary or "",
        file_size_bytes=r.file_size_bytes or 0,
        created_at=r.created_at,
        download_url=f"/api/reports/{r.id}/download",
        json_url=f"/api/reports/{r.id}/json",
        content_options=content_options,
        quality_check=quality_check,
        snapshot=snapshot,
        provenance=provenance,
    )


# -----------------------------------------------------------------------------
# Section 42: Authoritative Investigation Report Endpoints
# -----------------------------------------------------------------------------

@router.post(
    "/investigation/generate",
    response_model=ReportDetailResponse,
    summary="Generate immutable investigation report version",
    description="Assembles authoritative investigation data into an immutable snapshot, compiles vector PDF, logs audit event, and registers reproducible report version.",
)
def generate_investigation_report_endpoint(
    request: InvestigationReportGenerateRequest,
    format: Optional[str] = Query(None, description="Set to 'pdf' to receive binary PDF stream directly"),
    db: Session = Depends(get_db)
):
    incident, run, artifact, case = InvestigationWorkspaceService.resolve_context(db, request.investigation_id)
    if not incident and not run and not artifact:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation with identifier '{request.investigation_id}' was not found."
        )

    # 1. Determine sequential version for this investigation
    inv_key = incident.id if incident else (run.id if run else request.investigation_id)
    prior_reports = (
        db.query(ReportModel)
        .filter((ReportModel.investigation_id == inv_key) | (ReportModel.investigation_id == request.investigation_id))
        .order_by(ReportModel.report_version.desc())
        .all()
    )
    next_version = (prior_reports[0].report_version + 1) if prior_reports else 1

    # 2. Build authoritative snapshot projection
    content_opts_dict = request.content_options.model_dump() if request.content_options else {}
    snapshot = ReportProjectionService.build_projection(
        db=db,
        identifier=request.investigation_id,
        report_type=request.report_type,
        classification=request.classification,
        redaction_level=request.redaction_level,
        content_options=content_opts_dict,
        analyst_name=request.analyst_name or "SOC Lead Analyst",
        notes=request.notes,
        report_version=next_version,
    )

    report_number = _generate_report_number(db)
    report_id = str(uuid.uuid4())
    snapshot["metadata"]["report_number"] = report_number
    snapshot["metadata"]["report_id"] = report_id

    # 3. Generate server-side vector PDF from snapshot
    try:
        pdf_bytes = ReportService.generate_investigation_report(
            snapshot=snapshot,
            report_type=request.report_type,
            redaction_level=request.redaction_level,
            content_options=content_opts_dict,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to compile vector PDF report: {str(e)}"
        )

    # 4. Save PDF to disk and storage abstraction
    pdf_filename = f"{report_id}.pdf"
    pdf_path = os.path.join(ReportService.REPORTS_DIR, pdf_filename)
    try:
        with open(pdf_path, "wb") as f:
            f.write(pdf_bytes)
    except Exception:
        pass

    try:
        evidence_storage.store_bytes(
            data=pdf_bytes,
            original_filename=f"{report_number}.pdf",
            mime_type="application/pdf",
            custom_key=f"reports/{report_id}.pdf"
        )
    except Exception:
        pass

    pdf_sha = hashlib.sha256(pdf_bytes).hexdigest().lower()

    # 5. Mark previous active report as SUPERSEDED
    if prior_reports:
        for p in prior_reports:
            if p.status == "READY":
                p.status = "SUPERSEDED"
                p.superseded_by = report_id
        db.flush()

    # 6. Create immutable ReportModel record
    title_val = snapshot["metadata"].get("title") or f"Incident Report {report_number}"
    score_val = snapshot["risk_assessment"].get("risk_score", 0.0)
    sev_val = (snapshot["risk_assessment"].get("severity") or "medium").lower()
    conf_val = snapshot["risk_assessment"].get("confidence", 1.0)
    summary_val = snapshot["executive_summary"].get("synthesized_narrative", "")

    report_record = ReportModel(
        id=report_id,
        report_number=report_number,
        title=title_val,
        investigation_id=inv_key,
        case_id=case.id if case else None,
        evidence_id=artifact.id if artifact else None,
        artifact_id=artifact.id if artifact else None,
        analysis_run_id=snapshot["provenance"].get("analysis_run_id"),
        threat_score=score_val,
        severity=sev_val,
        confidence=conf_val,
        report_type=request.report_type,
        status="READY",
        report_version=next_version,
        classification=request.classification,
        redaction_level=request.redaction_level,
        analyst_name=request.analyst_name or "SOC Lead Analyst",
        summary=summary_val,
        content_options_json=json.dumps(content_opts_dict),
        snapshot_data_json=json.dumps(snapshot),
        quality_check_json=json.dumps(snapshot.get("quality_check", {})),
        file_path=pdf_path,
        file_size_bytes=len(pdf_bytes),
        sha256=pdf_sha,
        format="PDF",
        generator_version="ReportService-2.0",
        created_at=datetime.now(timezone.utc),
    )
    db.add(report_record)
    db.commit()
    db.refresh(report_record)

    # Section 47: Dispatch report completion notification
    try:
        from backend.services.notification_service import NotificationService
        NotificationService.on_report_completed(
            db=db,
            report=report_record,
            workspace_id="default",
        )
    except Exception as ne:
        logger.warning("Notification on report creation failed: %s", ne)

    # 7. Audit trail logging
    AuditService.log_audit(
        db=db,
        action="REPORT_GENERATED",
        resource_type="report",
        resource_id=report_record.id,
        user=request.analyst_name or "SOC Lead Analyst",
        case_id=case.id if case else None,
        metadata={
            "report_number": report_record.report_number,
            "investigation_id": inv_key,
            "report_version": next_version,
            "report_type": request.report_type,
            "classification": request.classification,
            "redaction_level": request.redaction_level,
            "file_size_bytes": len(pdf_bytes),
        },
        details=f"Investigation report {report_record.report_number} (v{next_version}) generated for {inv_key}."
    )

    if format == "pdf":
        clean_filename = f"CyberGuard_{report_record.report_number}_v{next_version}.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="{clean_filename}"',
                "X-Report-Number": report_record.report_number,
                "X-Report-Id": report_record.id
            }
        )

    return _serialize_report_detail(report_record, is_stale=False)


@router.post(
    "/investigation/generate-async",
    summary="Enqueue asynchronous investigation report generation job",
    description="Validates configuration and enqueues a persistent background job to generate an immutable report version.",
)
def generate_investigation_report_async_endpoint(
    request: InvestigationReportGenerateRequest,
    db: Session = Depends(get_db)
):
    incident, run, artifact, case = InvestigationWorkspaceService.resolve_context(db, request.investigation_id)
    if not incident and not run and not artifact:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation with identifier '{request.investigation_id}' was not found."
        )

    inv_key = incident.id if incident else (run.id if run else request.investigation_id)
    prior_reports = (
        db.query(ReportModel)
        .filter((ReportModel.investigation_id == inv_key) | (ReportModel.investigation_id == request.investigation_id))
        .order_by(ReportModel.report_version.desc())
        .all()
    )
    next_version = (prior_reports[0].report_version + 1) if prior_reports else 1
    report_id = str(uuid.uuid4())
    report_number = _generate_report_number(db)

    # Initial placeholder record in GENERATING status
    report_record = ReportModel(
        id=report_id,
        report_number=report_number,
        title=f"Incident Report {report_number}",
        investigation_id=inv_key,
        case_id=case.id if case else None,
        evidence_id=artifact.id if artifact else None,
        artifact_id=artifact.id if artifact else None,
        threat_score=incident.risk_score if incident else 0.0,
        severity=(incident.severity if incident else "medium").lower(),
        confidence=1.0,
        report_type=request.report_type,
        status="GENERATING",
        report_version=next_version,
        classification=request.classification,
        redaction_level=request.redaction_level,
        analyst_name=request.analyst_name or "SOC Lead Analyst",
        summary="Report generation is currently running in the background.",
        content_options_json=json.dumps(request.content_options.model_dump() if request.content_options else {}),
        format="PDF",
        generator_version="ReportService-2.0",
        created_at=datetime.now(timezone.utc),
    )
    db.add(report_record)
    db.commit()

    from backend.services.background_job_service import BackgroundJobService
    from backend.schemas.jobs import JobTypeEnum

    job, _ = BackgroundJobService.submit_job(
        db=db,
        job_type=JobTypeEnum.REPORT_GENERATION.value,
        resource_type="REPORT",
        resource_id=request.investigation_id,
        report_id=report_id,
        requested_by=request.analyst_name or "SOC Lead Analyst",
        payload={
            "investigation_id": request.investigation_id,
            "report_type": request.report_type,
            "classification": request.classification,
            "redaction_level": request.redaction_level,
            "content_options": request.content_options.model_dump() if request.content_options else {},
            "analyst_name": request.analyst_name or "SOC Lead Analyst",
            "notes": request.notes,
        },
        idempotency_key=f"report-gen-{inv_key}-v{next_version}",
    )

    return {
        "job_id": job.id,
        "job_status": job.status,
        "report_id": report_id,
        "report_number": report_number,
        "status": "GENERATING",
        "message": f"Report generation queued under job ID {job.id}.",
    }



@router.get(
    "",
    response_model=ReportListResponse,
    summary="List generated forensic reports",
    description="Returns chronological audit list of generated evidentiary reports with staleness indicators."
)
def list_reports(
    investigation_id: Optional[str] = Query(None, description="Filter by Investigation ID"),
    case_id: Optional[str] = Query(None, description="Filter reports by Case ID"),
    report_type: Optional[str] = Query(None, description="Filter by report type"),
    severity: Optional[str] = Query(None, description="Filter by severity level"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db)
):
    query = db.query(ReportModel)
    if investigation_id:
        query = query.filter(
            (ReportModel.investigation_id == investigation_id) |
            (ReportModel.case_id == investigation_id)
        )
    if case_id:
        query = query.filter(ReportModel.case_id == case_id)
    if report_type:
        query = query.filter(ReportModel.report_type == report_type.upper())
    if severity:
        query = query.filter(ReportModel.severity == severity.lower())

    total = query.count()
    items = query.order_by(ReportModel.created_at.desc()).offset(skip).limit(limit).all()

    report_responses = []
    for r in items:
        is_stale = ReportProjectionService.check_staleness(db, r)
        report_responses.append(_serialize_report_item(r, is_stale=is_stale))

    return ReportListResponse(
        reports=report_responses,
        total=total
    )


@router.get(
    "/{report_id}",
    response_model=ReportDetailResponse,
    summary="Get detailed report record with immutable snapshot",
    description="Returns full report details, snapshot, quality checks, and staleness evaluation."
)
def get_report_detail(
    report_id: str,
    db: Session = Depends(get_db)
):
    report = (
        db.query(ReportModel)
        .filter((ReportModel.id == report_id) | (ReportModel.report_number == report_id))
        .first()
    )
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report '{report_id}' was not found."
        )

    is_stale = ReportProjectionService.check_staleness(db, report)
    return _serialize_report_detail(report, is_stale=is_stale)


@router.get(
    "/{report_id}/download",
    summary="Download previously generated forensic report PDF",
    description="Streams the binary vector PDF file for a given report record and logs an export audit event."
)
def download_report(
    report_id: str,
    db: Session = Depends(get_db)
):
    report = (
        db.query(ReportModel)
        .filter((ReportModel.id == report_id) | (ReportModel.report_number == report_id))
        .first()
    )
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report '{report_id}' was not found."
        )

    if report.file_path and os.path.exists(report.file_path):
        with open(report.file_path, "rb") as f:
            pdf_bytes = f.read()
    else:
        # Fallback: re-render PDF if disk file missing but snapshot exists
        if report.snapshot_data_json:
            try:
                snapshot = json.loads(report.snapshot_data_json)
                content_opts = json.loads(report.content_options_json) if report.content_options_json else {}
                pdf_bytes = ReportService.generate_investigation_report(
                    snapshot=snapshot,
                    report_type=report.report_type or "ANALYST",
                    redaction_level=report.redaction_level or "NONE",
                    content_options=content_opts,
                )
            except Exception as e:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Unable to re-render report PDF: {str(e)}"
                )
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Report PDF file is not available on disk."
            )

    # Section 18 / Section 79: Export audit logging
    AuditService.log_audit(
        db=db,
        action="REPORT_EXPORTED",
        resource_type="report",
        resource_id=report.id,
        user="Investigator",
        case_id=report.case_id,
        metadata={
            "report_number": report.report_number,
            "format": "PDF",
            "file_size_bytes": len(pdf_bytes),
        },
        details=f"Report {report.report_number} exported as PDF."
    )

    clean_filename = f"CyberGuard_{report.report_number}_v{report.report_version or 1}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{clean_filename}"',
            "X-Report-Number": report.report_number,
            "X-Report-Version": str(report.report_version or 1)
        }
    )


@router.get(
    "/{report_id}/json",
    summary="Download reproducible forensic snapshot JSON bundle",
    description="Streams the canonical, reproducible JSON snapshot payload."
)
def download_report_json(
    report_id: str,
    db: Session = Depends(get_db)
):
    report = (
        db.query(ReportModel)
        .filter((ReportModel.id == report_id) | (ReportModel.report_number == report_id))
        .first()
    )
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report '{report_id}' was not found."
        )

    if not report.snapshot_data_json:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Forensic snapshot JSON is not available for this legacy report."
        )

    # Audit export
    AuditService.log_audit(
        db=db,
        action="REPORT_EXPORTED",
        resource_type="report",
        resource_id=report.id,
        user="Investigator",
        case_id=report.case_id,
        metadata={
            "report_number": report.report_number,
            "format": "JSON",
        },
        details=f"Report {report.report_number} exported as JSON bundle."
    )

    clean_filename = f"CyberGuard_{report.report_number}_v{report.report_version or 1}_snapshot.json"
    return Response(
        content=report.snapshot_data_json,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="{clean_filename}"',
            "X-Report-Number": report.report_number
        }
    )


@router.get(
    "/{r1_id}/compare/{r2_id}",
    response_model=ReportVersionComparisonResponse,
    summary="Compare two report versions",
    description="Compares metrics between two immutable report snapshots (e.g., v1 vs v2)."
)
def compare_reports_endpoint(
    r1_id: str,
    r2_id: str,
    db: Session = Depends(get_db)
):
    r1 = db.query(ReportModel).filter((ReportModel.id == r1_id) | (ReportModel.report_number == r1_id)).first()
    r2 = db.query(ReportModel).filter((ReportModel.id == r2_id) | (ReportModel.report_number == r2_id)).first()
    if not r1 or not r2:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="One or both report IDs were not found for comparison."
        )

    res = ReportProjectionService.compare_reports(db, r1, r2)
    return ReportVersionComparisonResponse(**res)


# -----------------------------------------------------------------------------
# Legacy Email & Case Dossier Endpoints (Preserved for compatibility)
# -----------------------------------------------------------------------------

@router.post(
    "/generate",
    summary="Generate forensic PDF report from email analysis telemetry",
    description="Constructs server-side vector PDF forensic report preserving literal evidence.",
)
def generate_forensic_report(
    request: ReportGenerateRequest,
    format: Optional[str] = Query(None, description="Set to 'json' to receive report metadata and download URL instead of binary PDF"),
    db: Session = Depends(get_db)
):
    analysis = request.analysis or {}
    if analysis.get("is_demo") or analysis.get("is_synthetic"):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Demo/synthetic evidence cannot contaminate normal production report generation."
        )
    email_id = analysis.get("id") or analysis.get("evidence_id")
    if email_id:
        from backend.services.analysis_repository import load_analysis
        try:
            stored_analysis = load_analysis(db, email_id)
            analysis = stored_analysis
        except Exception:
            pass

    subject = analysis.get("subject") or "Suspicious Email Investigation"
    sha256 = analysis.get("email_sha256") or analysis.get("id") or "UNCOMPUTED_HASH"
    evidence_id = analysis.get("id") or f"EVD-{sha256[:10]}"
    threat_data = analysis.get("threat_score") or {}
    score = threat_data.get("score", 0.0)
    severity = threat_data.get("severity", "low")
    summary = threat_data.get("summary", "")

    # 1. Generate PDF binary stream
    try:
        pdf_bytes = ReportService.generate_email_report(
            analysis=analysis,
            case_id=request.case_id,
            analyst_name=request.analyst_name,
            notes=request.notes
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate forensic PDF report: {str(e)}"
        )

    # 2. Persist PDF to disk and database record
    report_number = _generate_report_number(db)
    report_id = str(uuid.uuid4())
    pdf_filename = f"{report_id}.pdf"
    pdf_path = os.path.join(ReportService.REPORTS_DIR, pdf_filename)

    report_sha = hashlib.sha256(pdf_bytes).hexdigest().lower()
    try:
        with open(pdf_path, "wb") as f:
            f.write(pdf_bytes)
    except Exception:
        pass

    try:
        evidence_storage.store_bytes(
            data=pdf_bytes,
            original_filename=f"{report_number}.pdf",
            mime_type="application/pdf",
            custom_key=f"reports/{report_id}.pdf"
        )
    except Exception:
        pass

    art = db.query(ArtifactModel).filter(
        (ArtifactModel.sha256 == sha256.lower()) |
        (ArtifactModel.id == evidence_id)
    ).first()

    report_record = ReportModel(
        id=report_id,
        report_number=report_number,
        title=f"Forensic Report: {subject[:80]}",
        case_id=request.case_id,
        evidence_id=evidence_id,
        artifact_id=art.id if art else None,
        email_sha256=sha256,
        sha256=report_sha,
        format="PDF",
        generator_version="ReportService-1.0",
        threat_score=score,
        severity=severity,
        analyst_name=request.analyst_name or "SOC Lead Analyst",
        summary=summary,
        file_path=pdf_path,
        file_size_bytes=len(pdf_bytes),
        created_at=datetime.now(timezone.utc)
    )
    db.add(report_record)
    db.commit()
    db.refresh(report_record)

    AuditService.log_audit(
        db=db,
        action="REPORT_GENERATED",
        resource_type="report",
        resource_id=report_record.id,
        user=request.analyst_name or "SOC Lead Analyst",
        case_id=request.case_id,
        metadata={
            "report_number": report_record.report_number,
            "evidence_id": evidence_id,
            "email_sha256": sha256,
            "case_id": request.case_id,
            "threat_score": score,
            "severity": severity,
            "file_size_bytes": len(pdf_bytes)
        },
        details=f"Forensic report {report_record.report_number} generated for evidence {evidence_id}."
    )

    if format == "json":
        return {
            "id": report_record.id,
            "report_number": report_record.report_number,
            "title": report_record.title,
            "email_sha256": report_record.email_sha256,
            "file_size_bytes": report_record.file_size_bytes,
            "download_url": f"/api/reports/{report_record.id}/download"
        }

    clean_filename = f"CyberGuard_Forensic_Report_{sha256[:10]}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{clean_filename}"',
            "X-Report-Number": report_record.report_number,
            "X-Report-Id": report_record.id
        }
    )


@router.get(
    "/case/{case_id}",
    summary="Generate and download case-level forensic dossier",
    description="Compiles an investigation case overview, findings, notes, audit trail, and linked email summaries into a multi-page PDF."
)
def generate_case_dossier_endpoint(
    case_id: str,
    db: Session = Depends(get_db)
):
    try:
        pdf_bytes = ReportService.generate_case_dossier(db, case_id)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate case dossier: {str(e)}"
        )

    case = db.query(CaseModel).filter(CaseModel.id == case_id).first()
    case_num = case.case_number if case else "CASE"

    report_num = _generate_report_number(db)
    report_id = str(uuid.uuid4())
    pdf_filename = f"{report_id}.pdf"
    pdf_path = os.path.join(ReportService.REPORTS_DIR, pdf_filename)
    try:
        with open(pdf_path, "wb") as f:
            f.write(pdf_bytes)
    except Exception:
        pass

    report_record = ReportModel(
        id=report_id,
        report_number=report_num,
        title=f"Case Dossier: {case.title if case else case_num}",
        case_id=case_id,
        threat_score=0.0,
        severity=case.severity if case else "medium",
        analyst_name="SOC Lead Analyst",
        summary=case.description if case else "",
        file_path=pdf_path,
        file_size_bytes=len(pdf_bytes),
        created_at=datetime.now(timezone.utc)
    )
    db.add(report_record)
    db.commit()

    AuditService.log_audit(
        db=db,
        action="REPORT_GENERATED",
        resource_type="report",
        resource_id=report_record.id,
        user="SOC Lead Analyst",
        case_id=case_id,
        metadata={
            "report_number": report_num,
            "case_id": case_id,
            "case_number": case_num,
            "file_size_bytes": len(pdf_bytes)
        },
        details=f"Case dossier report {report_num} generated for {case_num}."
    )

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="Case_Dossier_{case_num}.pdf"',
            "X-Report-Number": report_num
        }
    )
