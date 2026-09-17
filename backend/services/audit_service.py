import json
import uuid
import re
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import or_

from backend.db.models import AuditLogModel, EvidenceModel, CaseModel
from backend.schemas.evidence import (
    InvestigationTimelineItem,
    InvestigationTimelineResponse,
    AuditLogItemResponse
)


EXCLUDED_BODY_KEYS = {
    "raw_email", "body", "plain_text_body", "html_body",
    "raw_body", "text_body", "content", "raw"
}

SECRET_KEYWORDS = {
    "password", "secret", "token", "api_key", "apikey",
    "auth_token", "private_key", "bearer", "credentials"
}


class AuditService:
    """
    Forensic Chain-of-Custody and Append-Only Audit Logging Service.
    Enforces privacy protections (no raw email bodies, no secrets) and immutable audit trails.
    """

    @staticmethod
    def sanitize_metadata(metadata: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Sanitizes audit metadata to comply with forensic privacy requirements:
        - Strips raw email bodies.
        - Strips API keys, passwords, and secrets.
        """
        if not metadata:
            return {}

        sanitized: Dict[str, Any] = {}
        for key, value in metadata.items():
            k_lower = key.lower()

            # 1. Reject email bodies
            if k_lower in EXCLUDED_BODY_KEYS:
                continue

            # 2. Reject secrets / credentials
            if any(secret_term in k_lower for secret_term in SECRET_KEYWORDS):
                continue

            # 3. Handle nested dictionaries recursively
            if isinstance(value, dict):
                sanitized[key] = AuditService.sanitize_metadata(value)
            elif isinstance(value, list):
                sanitized[key] = [
                    AuditService.sanitize_metadata(item) if isinstance(item, dict) else item
                    for item in value
                ]
            else:
                sanitized[key] = value

        return sanitized

    @classmethod
    def record_evidence(
        cls,
        db: Session,
        sha256: str,
        original_filename: str,
        size: int,
        uploader: Optional[str] = "SOC Analyst"
    ) -> EvidenceModel:
        """
        Records or retrieves evidence item for chain-of-custody tracking.
        Generates deterministic evidence ID: EVD-<SHA256[:10]>.
        """
        clean_sha256 = sha256.strip().lower()
        clean_filename = original_filename.strip() or "unknown.eml"
        uploader_name = uploader.strip() if uploader else "SOC Analyst"

        # Check if already registered
        existing = (
            db.query(EvidenceModel)
            .filter(EvidenceModel.sha256 == clean_sha256)
            .first()
        )
        if existing:
            return existing

        evidence_id = f"EVD-{clean_sha256[:10].upper()}"

        evidence = EvidenceModel(
            id=str(uuid.uuid4()),
            evidence_id=evidence_id,
            sha256=clean_sha256,
            original_filename=clean_filename,
            upload_timestamp=datetime.now(timezone.utc),
            size=int(size),
            uploader=uploader_name
        )
        db.add(evidence)
        db.commit()
        db.refresh(evidence)
        return evidence

    @classmethod
    def get_evidence(cls, db: Session, identifier: str) -> Optional[EvidenceModel]:
        """
        Finds evidence by evidence_id, sha256, or internal UUID.
        """
        clean_id = identifier.strip()

        return (
            db.query(EvidenceModel)
            .filter(
                or_(
                    EvidenceModel.evidence_id == clean_id,
                    EvidenceModel.sha256 == clean_id.lower(),
                    EvidenceModel.id == clean_id
                )
            )
            .first()
        )

    @classmethod
    def log_audit(
        cls,
        db: Session,
        action: str,
        resource_type: str,
        resource_id: str,
        user: Optional[str] = "SOC Analyst",
        metadata: Optional[Dict[str, Any]] = None,
        case_id: Optional[str] = None,
        details: Optional[str] = None
    ) -> AuditLogModel:
        """
        Persists an append-only, immutable audit entry.
        Never overwrites or deletes existing entries.
        """
        clean_user = (user or "SOC Analyst").strip()
        sanitized_meta = cls.sanitize_metadata(metadata)
        meta_json = json.dumps(sanitized_meta)

        detail_text = details
        if not detail_text:
            detail_text = f"{action} on {resource_type} '{resource_id}' by {clean_user}."

        audit_entry = AuditLogModel(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            user=clean_user,
            action=action.strip(),
            resource_type=resource_type.strip(),
            resource_id=resource_id.strip(),
            metadata_json=meta_json,
            case_id=case_id,
            details=detail_text
        )
        db.add(audit_entry)
        db.commit()
        db.refresh(audit_entry)
        return audit_entry

    @classmethod
    def _ensure_sample_seed(cls, db: Session):
        """
        Seeds baseline forensic evidence record and immutable chain-of-custody audit logs for sample-001.
        Ensures sample email exhibits realistic, verifiable database records immediately.
        """
        sample_sha = "97d4b2e811c7520e5e79603f9050d268159b360b9432df03d4083d8e57ef228a"
        sample_evd_id = "EVD-97D4B2E811"
        sample_filename = "urgent_microsoft_verification.eml"
        sample_size = 15420

        evd = db.query(EvidenceModel).filter(
            or_(
                EvidenceModel.sha256 == sample_sha,
                EvidenceModel.evidence_id == sample_evd_id
            )
        ).first()

        if not evd:
            evd = EvidenceModel(
                id=str(uuid.uuid4()),
                evidence_id=sample_evd_id,
                sha256=sample_sha,
                original_filename=sample_filename,
                upload_timestamp=datetime.now(timezone.utc),
                size=sample_size,
                uploader="SOC Analyst"
            )
            db.add(evd)
            db.commit()
            db.refresh(evd)

        # Check if audit logs exist for sample-001 or its evidence ID
        existing_log = db.query(AuditLogModel).filter(
            or_(
                AuditLogModel.resource_id == "sample-001",
                AuditLogModel.resource_id == sample_evd_id,
                AuditLogModel.metadata_json.like(f"%{sample_evd_id}%")
            )
        ).first()

        if not existing_log:
            cls.log_audit(
                db=db,
                action="EMAIL_UPLOADED",
                resource_type="email",
                resource_id="sample-001",
                user="SOC Analyst",
                metadata={
                    "filename": sample_filename,
                    "size": sample_size,
                    "sha256": sample_sha,
                    "evidence_id": sample_evd_id
                },
                details=f"Email file '{sample_filename}' ({sample_size} bytes) ingested into forensic pipeline."
            )
            cls.log_audit(
                db=db,
                action="EVIDENCE_RECORDED",
                resource_type="evidence",
                resource_id=sample_evd_id,
                user="Forensic Ingestion Agent",
                metadata={
                    "sha256": sample_sha,
                    "evidence_id": sample_evd_id,
                    "size": sample_size,
                    "original_filename": sample_filename
                },
                details=f"Cryptographic digest {sample_sha[:16]}... anchored with evidence identifier {sample_evd_id}."
            )
            cls.log_audit(
                db=db,
                action="ANALYSIS_STARTED",
                resource_type="email",
                resource_id="sample-001",
                user="Automated Analysis Engine",
                metadata={
                    "evidence_id": sample_evd_id,
                    "sha256": sample_sha
                },
                details="Static parsing, SPF/DKIM/DMARC evaluation, and reputation lookups started."
            )
            cls.log_audit(
                db=db,
                action="ANALYSIS_COMPLETED",
                resource_type="email",
                resource_id="sample-001",
                user="Automated Scoring Engine",
                metadata={
                    "evidence_id": sample_evd_id,
                    "threat_score": 82,
                    "severity": "CRITICAL"
                },
                details="Deterministic Threat Score: 82/100 (CRITICAL). 5 indicators of compromise extracted."
            )

    @classmethod
    def get_timeline(
        cls,
        db: Session,
        identifier: str
    ) -> InvestigationTimelineResponse:
        """
        Reconstructs the full investigation timeline for an email, evidence item, or case.
        Matches entries by resource_id, evidence_id, SHA-256, or metadata references.
        """
        clean_id = identifier.strip()

        evidence = cls.get_evidence(db, clean_id)

        # If evidence wasn't found directly by identifier (e.g. identifier is an email ID),
        # inspect audit logs for this resource_id to extract linked evidence_id or sha256
        if not evidence:
            candidate_log = (
                db.query(AuditLogModel)
                .filter(
                    or_(
                        AuditLogModel.resource_id == clean_id,
                        AuditLogModel.metadata_json.like(f"%{clean_id}%")
                    )
                )
                .first()
            )
            if candidate_log and candidate_log.metadata_json:
                try:
                    c_meta = json.loads(candidate_log.metadata_json)
                    c_evd = c_meta.get("evidence_id")
                    c_sha = c_meta.get("sha256")
                    if c_evd:
                        evidence = cls.get_evidence(db, c_evd)
                    elif c_sha:
                        evidence = cls.get_evidence(db, c_sha)
                except Exception:
                    pass

        evidence_id = evidence.evidence_id if evidence else (clean_id if clean_id.startswith("EVD-") else None)
        sha256 = evidence.sha256 if evidence else (clean_id.lower() if len(clean_id) == 64 else None)

        filters = [
            AuditLogModel.resource_id == clean_id,
            AuditLogModel.metadata_json.like(f"%{clean_id}%")
        ]
        if evidence_id:
            filters.append(AuditLogModel.resource_id == evidence_id)
            filters.append(AuditLogModel.metadata_json.like(f"%{evidence_id}%"))
        if sha256:
            filters.append(AuditLogModel.resource_id == sha256)
            filters.append(AuditLogModel.metadata_json.like(f"%{sha256}%"))

        logs = (
            db.query(AuditLogModel)
            .filter(or_(*filters))
            .order_by(AuditLogModel.timestamp.asc())
            .all()
        )

        has_added_to_case = any(l.action == "EMAIL_ADDED_TO_CASE" for l in logs)

        events: List[InvestigationTimelineItem] = []
        for log in logs:
            # Avoid redundant duplicate log entry for email case addition
            if log.action == "EMAIL_ADDED" and has_added_to_case:
                continue

            meta = {}
            if log.metadata_json:
                try:
                    meta = json.loads(log.metadata_json)
                except Exception:
                    pass

            # Construct human-friendly title and description
            title, desc = cls._format_timeline_item(log.action, log.resource_type, meta, log.details)
            time_str = log.timestamp.strftime("%H:%M")

            events.append(
                InvestigationTimelineItem(
                    id=log.id,
                    timestamp=log.timestamp,
                    time_display=time_str,
                    action=log.action,
                    title=title,
                    description=desc,
                    user=log.user or "SOC Analyst",
                    resource_type=log.resource_type,
                    resource_id=log.resource_id,
                    metadata=meta
                )
            )

        return InvestigationTimelineResponse(
            evidence_id=evidence_id,
            sha256=sha256,
            events=events,
            total=len(events)
        )

    @staticmethod
    def _format_timeline_item(
        action: str,
        resource_type: str,
        meta: Dict[str, Any],
        fallback_details: Optional[str]
    ) -> (str, Optional[str]):
        """
        Formats action code into canonical timeline display titles matching Section 18:
        e.g.
        'Email uploaded'
        'Evidence SHA-256 recorded'
        'Analysis completed'
        'Added to CASE-31'
        'Report generated'
        """
        if action == "EMAIL_UPLOADED":
            filename = meta.get("filename") or "Uploaded file"
            size_kb = f"{meta.get('size', 0) / 1024:.1f} KB" if meta.get('size') else ""
            desc = f"File: {filename} ({size_kb})" if size_kb else f"File: {filename}"
            return "Email uploaded", desc

        elif action == "EVIDENCE_RECORDED":
            sha = meta.get("sha256") or ""
            evd_id = meta.get("evidence_id") or ""
            desc = f"SHA-256: {sha[:16]}... [{evd_id}]" if sha else "Cryptographic hash verified and stored"
            return "Evidence SHA-256 recorded", desc

        elif action == "ANALYSIS_STARTED":
            return "Analysis started", "Forensic parsers, IP enrichment, and threat scoring initiated"

        elif action == "ANALYSIS_COMPLETED":
            score = meta.get("threat_score")
            sev = meta.get("severity", "LOW").upper()
            desc = f"Threat Score: {score}/100 ({sev})" if score is not None else "Forensic telemetry computed"
            return "Analysis completed", desc

        elif action in ("EMAIL_ADDED_TO_CASE", "EMAIL_ADDED"):
            case_num = meta.get("case_number") or meta.get("case_id") or "Case"
            subj = meta.get("subject", "")
            return f"Added to {case_num}", f"Subject: {subj}" if subj else None

        elif action == "CASE_CREATED":
            case_num = meta.get("case_number", "Case")
            return f"{case_num} created", meta.get("title")

        elif action in ("CASE_STATUS_CHANGED", "STATUS_CHANGED"):
            new_st = meta.get("new_status", "updated").upper()
            return f"Case status updated to {new_st}", fallback_details

        elif action == "NOTE_ADDED":
            author = meta.get("author", "Analyst")
            return f"Note added by {author}", fallback_details

        elif action == "REPORT_GENERATED":
            rpt_num = meta.get("report_number")
            desc = f"Forensic dossier {rpt_num}" if rpt_num else "PDF evidentiary report generated"
            return "Report generated", desc

        # Fallback
        readable_title = action.replace("_", " ").capitalize()
        return readable_title, fallback_details

    @classmethod
    def list_audit_logs(
        cls,
        db: Session,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        action: Optional[str] = None,
        case_id: Optional[str] = None,
        skip: int = 0,
        limit: int = 50
    ) -> (List[AuditLogItemResponse], int):
        """Lists audit logs with optional filtering."""
        query = db.query(AuditLogModel)

        if resource_type:
            query = query.filter(AuditLogModel.resource_type == resource_type)
        if resource_id:
            query = query.filter(AuditLogModel.resource_id == resource_id)
        if action:
            query = query.filter(AuditLogModel.action == action)
        if case_id:
            query = query.filter(AuditLogModel.case_id == case_id)

        total = query.count()
        records = (
            query.order_by(AuditLogModel.timestamp.desc())
            .offset(skip)
            .limit(limit)
            .all()
        )

        responses = []
        for r in records:
            meta = {}
            if r.metadata_json:
                try:
                    meta = json.loads(r.metadata_json)
                except Exception:
                    pass
            responses.append(
                AuditLogItemResponse(
                    id=r.id,
                    timestamp=r.timestamp,
                    user=r.user,
                    action=r.action,
                    resource_type=r.resource_type,
                    resource_id=r.resource_id,
                    metadata=meta,
                    case_id=r.case_id,
                    details=r.details
                )
            )

        return responses, total
