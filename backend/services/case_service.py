import json
from datetime import datetime, timezone
from typing import List, Optional, Tuple, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import or_
from fastapi import HTTPException, status

from backend.db.models import (
    CaseModel,
    CaseEmailModel,
    CaseNoteModel,
    CaseFindingModel,
    AuditLogModel
)
from backend.schemas.case import (
    CaseCreateRequest,
    CaseUpdateRequest,
    CaseEmailCreateRequest,
    CaseNoteCreateRequest,
    CaseFindingCreateRequest,
    CaseListItemResponse,
    CaseDetailResponse,
    CaseEmailResponse,
    CaseNoteResponse,
    CaseFindingResponse,
    AuditLogResponse,
    AggregatedIndicators,
    CaseStatus,
    CaseSeverity
)
from backend.services.audit_service import AuditService


class CaseService:
    """Business logic service managing SOC investigation cases, linked emails, notes, findings, and audit trails."""

    @staticmethod
    def _generate_case_number(db: Session) -> str:
        """
        Generates readable sequential identifiers: CASE-{YEAR}-{SEQUENCE:06d}.
        E.g. CASE-2026-000001, CASE-2026-000031.
        """
        current_year = datetime.now(timezone.utc).year
        prefix = f"CASE-{current_year}-"

        last_case = (
            db.query(CaseModel)
            .filter(CaseModel.case_number.like(f"{prefix}%"))
            .order_by(CaseModel.case_number.desc())
            .first()
        )

        if last_case:
            try:
                last_seq = int(last_case.case_number.split("-")[-1])
                next_seq = last_seq + 1
            except (ValueError, IndexError):
                next_seq = 1
        else:
            next_seq = 1

        return f"{prefix}{next_seq:06d}"

    @staticmethod
    def _log_audit(
        db: Session,
        case_id: str,
        action: str,
        details: str,
        metadata: Optional[Dict[str, Any]] = None,
        user: Optional[str] = "SOC Analyst"
    ):
        """Records an audit log entry for accountability via AuditService."""
        meta = metadata or {}
        AuditService.log_audit(
            db=db,
            action=action,
            resource_type="case",
            resource_id=case_id,
            user=user,
            metadata=meta,
            case_id=case_id,
            details=details
        )

    @classmethod
    def create_case(cls, db: Session, request: CaseCreateRequest) -> CaseModel:
        """Creates a new investigation case."""
        case_number = cls._generate_case_number(db)
        case = CaseModel(
            case_number=case_number,
            title=request.title.strip(),
            description=(request.description or "").strip(),
            severity=request.severity.value if request.severity else CaseSeverity.MEDIUM.value,
            status=request.status.value if request.status else CaseStatus.OPEN.value,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        db.add(case)
        db.flush()

        # Audit initial creation
        cls._log_audit(
            db,
            case_id=case.id,
            action="CASE_CREATED",
            details=f"Case {case.case_number} created with title '{case.title}' and severity '{case.severity}'.",
            metadata={
                "case_number": case.case_number,
                "title": case.title,
                "severity": case.severity,
                "status": case.status
            }
        )

        # Attach initial email if specified
        if request.initial_email:
            cls.add_email_to_case(db, case_id=case.id, request=request.initial_email)

        db.commit()
        db.refresh(case)
        return case

    @classmethod
    def list_cases(
        cls,
        db: Session,
        status_filter: Optional[str] = None,
        severity_filter: Optional[str] = None,
        search_query: Optional[str] = None,
        skip: int = 0,
        limit: int = 50
    ) -> Tuple[List[CaseListItemResponse], int]:
        """Lists cases with optional status, severity, and text search filters."""
        query = db.query(CaseModel)

        if status_filter and status_filter.lower() != "all":
            query = query.filter(CaseModel.status == status_filter.lower())

        if severity_filter and severity_filter.lower() != "all":
            query = query.filter(CaseModel.severity == severity_filter.lower())

        if search_query and search_query.strip():
            term = f"%{search_query.strip().lower()}%"
            query = query.filter(
                or_(
                    CaseModel.title.ilike(term),
                    CaseModel.case_number.ilike(term),
                    CaseModel.description.ilike(term)
                )
            )

        total = query.count()
        cases = query.order_by(CaseModel.updated_at.desc()).offset(skip).limit(limit).all()

        item_responses = [
            CaseListItemResponse(
                id=c.id,
                case_number=c.case_number,
                title=c.title,
                description=c.description,
                severity=c.severity,
                status=c.status,
                created_at=c.created_at,
                updated_at=c.updated_at,
                email_count=len(c.emails),
                note_count=len(c.notes),
                finding_count=len(c.findings)
            )
            for c in cases
        ]

        return item_responses, total

    @classmethod
    def get_case(cls, db: Session, case_identifier: str) -> CaseModel:
        """Fetches case by UUID id or readable case_number."""
        case = (
            db.query(CaseModel)
            .filter(
                or_(
                    CaseModel.id == case_identifier,
                    CaseModel.case_number == case_identifier
                )
            )
            .first()
        )
        if not case:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Investigation case '{case_identifier}' was not found."
            )
        return case

    @classmethod
    def get_case_detail(cls, db: Session, case_identifier: str) -> CaseDetailResponse:
        """Fetches full case detail including aggregated indicators."""
        case = cls.get_case(db, case_identifier)

        # Aggregate indicators across all linked emails
        domains: set = set()
        ips: set = set()
        urls: set = set()
        attachments: set = set()

        for ce in case.emails:
            if ce.indicators_json:
                try:
                    data = json.loads(ce.indicators_json)
                    for d in data.get("domains", []):
                        if d: domains.add(str(d).lower().strip())
                    for ip in data.get("ips", []):
                        if ip: ips.add(str(ip).strip())
                    for u in data.get("urls", []):
                        if u: urls.add(str(u).strip())
                    for a in data.get("attachments", []):
                        if a:
                            name = a.get("filename") if isinstance(a, dict) else str(a)
                            if name: attachments.add(name)
                except Exception:
                    pass

        agg = AggregatedIndicators(
            domains=sorted(list(domains)),
            ips=sorted(list(ips)),
            urls=sorted(list(urls)),
            attachments=sorted(list(attachments))
        )

        return CaseDetailResponse(
            id=case.id,
            case_number=case.case_number,
            title=case.title,
            description=case.description,
            severity=case.severity,
            status=case.status,
            created_at=case.created_at,
            updated_at=case.updated_at,
            emails=[CaseEmailResponse.model_validate(e) for e in case.emails],
            notes=[CaseNoteResponse.model_validate(n) for n in case.notes],
            findings=[CaseFindingResponse.model_validate(f) for f in case.findings],
            audit_logs=[AuditLogResponse.model_validate(a) for a in case.audit_logs],
            aggregated_indicators=agg
        )

    @classmethod
    def update_case(cls, db: Session, case_identifier: str, request: CaseUpdateRequest) -> CaseModel:
        """Updates case metadata, status, or severity, logging audit transitions."""
        case = cls.get_case(db, case_identifier)
        has_changes = False

        if request.title is not None and request.title.strip() != case.title:
            cls._log_audit(db, case.id, "TITLE_UPDATED", f"Title updated to '{request.title.strip()}'.")
            case.title = request.title.strip()
            has_changes = True

        if request.description is not None and request.description != case.description:
            case.description = request.description
            has_changes = True

        if request.status is not None and request.status.value != case.status:
            old_st = case.status
            new_st = request.status.value
            case.status = new_st
            cls._log_audit(
                db,
                case.id,
                "CASE_STATUS_CHANGED",
                f"Status updated from '{old_st}' to '{new_st}'.",
                metadata={"case_number": case.case_number, "old_status": old_st, "new_status": new_st}
            )
            # Retain STATUS_CHANGED for backwards compatibility with existing assertions
            cls._log_audit(
                db,
                case.id,
                "STATUS_CHANGED",
                f"Status updated from '{old_st}' to '{new_st}'.",
                metadata={"case_number": case.case_number, "old_status": old_st, "new_status": new_st}
            )
            has_changes = True

        if request.severity is not None and request.severity.value != case.severity:
            old_sev = case.severity
            new_sev = request.severity.value
            case.severity = new_sev
            cls._log_audit(
                db,
                case.id,
                "SEVERITY_CHANGED",
                f"Severity updated from '{old_sev}' to '{new_sev}'.",
                metadata={"case_number": case.case_number, "old_severity": old_sev, "new_severity": new_sev}
            )
            has_changes = True

        if has_changes:
            case.updated_at = datetime.now(timezone.utc)
            db.commit()
            db.refresh(case)

        return case

    @classmethod
    def add_email_to_case(cls, db: Session, case_id: str, request: CaseEmailCreateRequest) -> CaseEmailModel:
        """
        Assigns an analyzed email to a case.
        Rejects duplicate email assignments with 400 Bad Request.
        """
        case = cls.get_case(db, case_id)

        # Duplicate check
        existing = (
            db.query(CaseEmailModel)
            .filter(
                CaseEmailModel.case_id == case.id,
                CaseEmailModel.email_id == request.email_id
            )
            .first()
        )
        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Email '{request.email_id}' is already linked to this case."
            )

        indicators_serialized = json.dumps(request.indicators or {})

        from backend.db.models import EmailAnalysisModel
        stored_analysis = (
            db.query(EmailAnalysisModel)
            .filter(
                or_(
                    EmailAnalysisModel.evidence_id == request.email_id,
                    EmailAnalysisModel.id == request.email_id,
                    EmailAnalysisModel.email_sha256 == request.email_id
                )
            )
            .first()
        )

        if stored_analysis:
            real_subject = stored_analysis.subject
            real_sender = stored_analysis.sender
            real_threat_score = stored_analysis.threat_score
            real_severity = stored_analysis.severity
            real_sha256 = stored_analysis.email_sha256
            real_indicators = stored_analysis.indicators_json
        else:
            real_subject = request.subject or "Untitled Email"
            real_sender = request.sender or "unknown"
            real_threat_score = request.threat_score or 0
            real_severity = request.severity or "low"
            real_sha256 = request.email_sha256
            real_indicators = indicators_serialized

        case_email = CaseEmailModel(
            case_id=case.id,
            email_id=request.email_id,
            email_sha256=real_sha256,
            subject=real_subject,
            sender=real_sender,
            threat_score=real_threat_score,
            severity=real_severity,
            indicators_json=real_indicators,
            added_at=datetime.now(timezone.utc)
        )
        db.add(case_email)
        case.updated_at = datetime.now(timezone.utc)

        cls._log_audit(
            db,
            case_id=case.id,
            action="EMAIL_ADDED_TO_CASE",
            details=f"Added email '{case_email.subject}' (Sender: {case_email.sender}, Score: {case_email.threat_score}) to case {case.case_number}.",
            metadata={
                "case_number": case.case_number,
                "email_id": case_email.email_id,
                "email_sha256": case_email.email_sha256,
                "subject": case_email.subject,
                "threat_score": case_email.threat_score
            }
        )
        # Retain EMAIL_ADDED for backwards compatibility
        cls._log_audit(
            db,
            case_id=case.id,
            action="EMAIL_ADDED",
            details=f"Added email '{case_email.subject}' (Sender: {case_email.sender}, Score: {case_email.threat_score}) to case.",
            metadata={
                "case_number": case.case_number,
                "email_id": case_email.email_id,
                "email_sha256": case_email.email_sha256
            }
        )

        db.commit()
        db.refresh(case_email)
        return case_email

    @classmethod
    def remove_email_from_case(cls, db: Session, case_id: str, email_id: str):
        """Removes a linked email from a case."""
        case = cls.get_case(db, case_id)

        case_email = (
            db.query(CaseEmailModel)
            .filter(
                CaseEmailModel.case_id == case.id,
                or_(
                    CaseEmailModel.email_id == email_id,
                    CaseEmailModel.id == email_id
                )
            )
            .first()
        )
        if not case_email:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Email '{email_id}' is not linked to this case."
            )

        email_subject = case_email.subject
        db.delete(case_email)
        case.updated_at = datetime.now(timezone.utc)

        cls._log_audit(
            db,
            case_id=case.id,
            action="EMAIL_REMOVED",
            details=f"Removed email '{email_subject}' (ID: {email_id}) from case.",
            metadata={"case_number": case.case_number, "email_id": email_id, "subject": email_subject}
        )

        db.commit()

    @classmethod
    def add_note(cls, db: Session, case_id: str, request: CaseNoteCreateRequest) -> CaseNoteModel:
        """Adds an analyst note to the case."""
        case = cls.get_case(db, case_id)

        note = CaseNoteModel(
            case_id=case.id,
            author=request.author or "SOC Analyst",
            note_text=request.note_text.strip(),
            created_at=datetime.now(timezone.utc)
        )
        db.add(note)
        case.updated_at = datetime.now(timezone.utc)

        cls._log_audit(
            db,
            case_id=case.id,
            action="NOTE_ADDED",
            details=f"Note added by {note.author}.",
            metadata={
                "case_number": case.case_number,
                "author": note.author,
                "note_id": note.id
            },
            user=note.author
        )

        db.commit()
        db.refresh(note)
        return note

    @classmethod
    def add_finding(cls, db: Session, case_id: str, request: CaseFindingCreateRequest) -> CaseFindingModel:
        """Adds a structured forensic finding to the case."""
        case = cls.get_case(db, case_id)

        finding = CaseFindingModel(
            case_id=case.id,
            finding_type=request.finding_type,
            title=request.title.strip(),
            description=request.description.strip(),
            severity=request.severity.value if request.severity else CaseSeverity.MEDIUM.value,
            created_at=datetime.now(timezone.utc)
        )
        db.add(finding)
        case.updated_at = datetime.now(timezone.utc)

        cls._log_audit(
            db,
            case_id=case.id,
            action="FINDING_ADDED",
            details=f"Finding '{finding.title}' ({finding.finding_type}) flagged with severity '{finding.severity}'."
        )

        db.commit()
        db.refresh(finding)
        return finding
