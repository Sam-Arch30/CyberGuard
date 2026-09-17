import os
import uuid
from typing import Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.db.models import ReportModel, CaseModel, CaseEmailModel
from backend.schemas.report import (
    ReportGenerateRequest,
    ReportListResponse,
    ReportListItemResponse
)
from backend.services.report_service import ReportService
from backend.services.audit_service import AuditService

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


@router.post(
    "/generate",
    summary="Generate forensic PDF report from email analysis telemetry",
    description="Constructs server-side vector PDF forensic report preserving literal evidence, cryptographic SHA-256 hashes, and deterministic threat scoring.",
    responses={
        200: {
            "content": {"application/pdf": {}},
            "description": "Returns PDF binary stream or JSON metadata if format=json."
        }
    }
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

    try:
        with open(pdf_path, "wb") as f:
            f.write(pdf_bytes)
    except Exception:
        pass

    report_record = ReportModel(
        id=report_id,
        report_number=report_number,
        title=f"Forensic Report: {subject[:80]}",
        case_id=request.case_id,
        evidence_id=evidence_id,
        email_sha256=sha256,
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

    # Section 18: Audit trail logging for report generation
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
        details=f"Forensic report {report_record.report_number} generated for evidence {evidence_id} (SHA-256: {sha256[:16]}...)."
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

    clean_filename = f"MailTrace_Forensic_Report_{sha256[:10]}.pdf"
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
    "",
    response_model=ReportListResponse,
    summary="List generated forensic reports",
    description="Returns chronological audit list of generated evidentiary reports."
)
def list_reports(
    case_id: Optional[str] = Query(None, description="Filter reports by Case ID"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db)
):
    query = db.query(ReportModel)
    if case_id:
        query = query.filter(ReportModel.case_id == case_id)

    total = query.count()
    items = query.order_by(ReportModel.created_at.desc()).offset(skip).limit(limit).all()

    return ReportListResponse(
        reports=[ReportListItemResponse.model_validate(r) for r in items],
        total=total
    )


@router.get(
    "/{report_id}/download",
    summary="Download previously generated forensic report PDF",
    description="Streams the binary PDF file for a given report record."
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
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report PDF file is not available on disk."
        )

    clean_filename = f"{report.report_number}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{clean_filename}"',
            "X-Report-Number": report.report_number
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

    # Persist report record
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

    # Section 18: Audit trail logging for case dossier generation
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
