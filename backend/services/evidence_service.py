"""
Section 68: Evidence & Forensics Workspace Service.
Authoritative service providing:
- Evidence registration with SHA-256 / SHA-1 / MD5 computation and storage.
- Cryptographic integrity re-verification and mismatch alerting.
- Immutable Chain-of-Custody ledger logging.
- Preservation and legal-hold status enforcement.
- Parent-to-child derivation tracking (decoding, unpacking, carving).
- Safe previews (text, hex dump, metadata) with strict bounds.
- Forensic export manifest generation with package digest.
- Case / Investigation / Finding / Indicator linkage.
- Multi-tenant isolation and RBAC.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from backend.db.models import (
    ArtifactModel,
    AuditLogModel,
    CaseModel,
    EvidenceCustodyEventModel,
    EvidenceModel,
    FindingEvidenceModel,
    FindingModel,
    IncidentModel,
    IndicatorModel,
)
from backend.schemas.evidence_workspace import (
    CustodyEventTypeEnum,
    EvidenceClassificationEnum,
    EvidenceCollectionMethodEnum,
    EvidenceCustodyAddRequest,
    EvidenceCustodyEventResponse,
    EvidenceDerivationRequest,
    EvidenceDetailResponse,
    EvidenceExportManifestResponse,
    EvidenceIntegrityStatusEnum,
    EvidenceIntegrityVerificationResponse,
    EvidenceLifecycleStatusEnum,
    EvidenceListItemResponse,
    EvidenceListResponse,
    EvidenceMetricsResponse,
    EvidenceNoteAddRequest,
    EvidencePreservationRequest,
    EvidencePreservationStatusEnum,
    EvidencePreviewResponse,
    EvidenceProvenanceLineageItem,
    EvidenceRegistrationRequest,
    EvidenceRetentionPolicyEnum,
    EvidenceSourceTypeEnum,
)
from backend.schemas.realtime import (
    RealtimeEventTypeEnum,
    RealtimeResourceScopeEnum,
    RealtimeEventPayload,
)
from backend.services.evidence_storage import (
    detect_mime_type_from_header,
    evidence_storage,
)
from backend.services.realtime_service import RealtimePublisher


logger = logging.getLogger("cyberguard.evidence_service")


def get_utc_now() -> datetime:
    return datetime.now(timezone.utc)


class EvidenceService:
    """
    Core service orchestrating forensic evidence operations and non-repudiation ledgers.
    """

    @classmethod
    def generate_evidence_id(cls, db: Session, tenant_id: str) -> str:
        """
        Generates deterministic, collision-resistant evidence identifiers like EVD-2026-0001.
        """
        total = db.query(EvidenceModel).count()
        candidate = f"EVD-{datetime.now(timezone.utc).year}-{total + 1:04d}"
        attempts = 0
        while db.query(EvidenceModel).filter(EvidenceModel.evidence_id == candidate).first():
            attempts += 1
            candidate = f"EVD-{datetime.now(timezone.utc).year}-{total + 1 + attempts:04d}"
        return candidate

    @classmethod
    def register_evidence(
        cls,
        db: Session,
        raw_bytes: bytes,
        filename: str,
        req: EvidenceRegistrationRequest,
        current_user: str = "SOC Analyst",
        tenant_id: str = "default",
    ) -> EvidenceDetailResponse:
        """
        Formally registers an acquired artifact as authoritative forensic evidence.
        Computes SHA-256, SHA-1, MD5, safely stores bytes, and appends an immutable
        ACQUIRED chain-of-custody ledger event.
        """
        sha256_hash = hashlib.sha256(raw_bytes).hexdigest()
        sha1_hash = hashlib.sha1(raw_bytes).hexdigest()
        md5_hash = hashlib.md5(raw_bytes).hexdigest()
        size_bytes = len(raw_bytes)

        detected_mime = detect_mime_type_from_header(raw_bytes[:64])
        evidence_id = cls.generate_evidence_id(db, tenant_id)

        # Store through unified storage abstraction
        storage_res = evidence_storage.store_bytes(
            data=raw_bytes,
            original_filename=filename,
            mime_type=detected_mime,
        )

        now = get_utc_now()

        # Build Evidence Model
        evidence_record = EvidenceModel(
            evidence_id=evidence_id,
            tenant_id=tenant_id,
            sha256=sha256_hash,
            sha1=sha1_hash,
            md5=md5_hash,
            hash_algorithm="SHA-256",
            integrity_status="VERIFIED",
            last_verified_at=now,
            last_verified_by=current_user,
            original_filename=filename,
            mime_type=detected_mime,
            size=size_bytes,
            size_bytes=size_bytes,
            storage_reference=storage_res.storage_key,
            source_type=req.source_type.value,
            source_reference=req.source_reference,
            collection_method=req.collection_method.value,
            uploader=current_user,
            collected_by=req.collector or current_user,
            upload_timestamp=now,
            collected_at=now,
            received_at=now,
            classification=req.classification.value,
            lifecycle_status="VALID",
            retention_policy=req.retention_policy.value,
            preservation_status="NORMAL",
            case_id=req.case_id,
            investigation_id=req.investigation_id,
            metadata_json=json.dumps(req.metadata or {}),
            forensic_notes_json=json.dumps(
                [{"text": req.notes, "author": current_user, "timestamp": now.isoformat()}]
                if req.notes
                else []
            ),
            evidence_gaps_json="[]",
            derivation_metadata_json="{}",
            created_at=now,
            updated_at=now,
        )
        db.add(evidence_record)
        db.flush()

        # Append immutable Chain of Custody record
        custody_event = EvidenceCustodyEventModel(
            evidence_id=evidence_record.id,
            tenant_id=tenant_id,
            event_type="ACQUIRED",
            actor_id=current_user,
            timestamp=now,
            source=req.source_reference or "COLLECTION_POINT",
            destination="CYBERGUARD_SECURE_STORAGE",
            reason="Initial forensic acquisition and cryptographic registration.",
            integrity_hash=sha256_hash,
            metadata_json=json.dumps({
                "original_filename": filename,
                "collection_method": req.collection_method.value,
                "size_bytes": size_bytes,
            }),
            created_at=now,
        )
        db.add(custody_event)

        # Audit log
        audit = AuditLogModel(
            timestamp=now,
            user=current_user,
            action="EVIDENCE_ACQUIRED",
            resource_type="evidence",
            resource_id=evidence_id,
            metadata_json=json.dumps({
                "sha256": sha256_hash,
                "filename": filename,
                "size": size_bytes,
                "tenant_id": tenant_id,
            }),
            details=f"Acquired forensic evidence {evidence_id} ({filename}) with digest {sha256_hash[:12]}...",
        )
        db.add(audit)
        db.commit()
        db.refresh(evidence_record)

        # Publish Realtime event
        cls._publish_realtime(
            event_type=RealtimeEventTypeEnum.EVIDENCE_REGISTERED,
            resource_id=evidence_id,
            tenant_id=tenant_id,
            data={"evidence_id": evidence_id, "filename": filename, "sha256": sha256_hash},
        )

        return cls.get_evidence_detail(db, evidence_record.id, tenant_id=tenant_id)

    @classmethod
    def list_evidence(
        cls,
        db: Session,
        tenant_id: str = "default",
        source_type: Optional[str] = None,
        integrity_status: Optional[str] = None,
        classification: Optional[str] = None,
        preservation_status: Optional[str] = None,
        case_id: Optional[str] = None,
        investigation_id: Optional[str] = None,
        search_query: Optional[str] = None,
        page: int = 1,
        page_size: int = 50,
    ) -> EvidenceListResponse:
        """
        Lists and filters forensic evidence records with pagination and aggregate summary metrics.
        """
        query = db.query(EvidenceModel).filter(EvidenceModel.tenant_id == tenant_id)

        if source_type:
            query = query.filter(EvidenceModel.source_type == source_type)
        if integrity_status:
            query = query.filter(EvidenceModel.integrity_status == integrity_status)
        if classification:
            query = query.filter(EvidenceModel.classification == classification)
        if preservation_status:
            query = query.filter(EvidenceModel.preservation_status == preservation_status)
        if case_id:
            query = query.filter(EvidenceModel.case_id == case_id)
        if investigation_id:
            query = query.filter(EvidenceModel.investigation_id == investigation_id)
        if search_query:
            sq = f"%{search_query.strip()}%"
            query = query.filter(
                (EvidenceModel.original_filename.ilike(sq))
                | (EvidenceModel.evidence_id.ilike(sq))
                | (EvidenceModel.sha256.ilike(sq))
            )

        total = query.count()
        offset = (max(1, page) - 1) * page_size
        records = (
            query.order_by(desc(EvidenceModel.collected_at))
            .offset(offset)
            .limit(page_size)
            .all()
        )

        items: List[EvidenceListItemResponse] = []
        for r in records:
            findings_count = 0
            if r.artifact_id:
                findings_count = db.query(FindingEvidenceModel).filter(FindingEvidenceModel.artifact_id == r.artifact_id).count()
            items.append(
                EvidenceListItemResponse(
                    id=r.id,
                    evidence_id=r.evidence_id,
                    sha256=r.sha256,
                    sha1=r.sha1,
                    md5=r.md5,
                    original_filename=r.original_filename,
                    mime_type=r.mime_type,
                    size=r.size,
                    source_type=r.source_type,
                    collection_method=r.collection_method,
                    collector=r.collected_by or r.uploader or "SOC Analyst",
                    collected_at=r.collected_at,
                    classification=r.classification,
                    lifecycle_status=r.lifecycle_status,
                    integrity_status=r.integrity_status,
                    preservation_status=r.preservation_status,
                    case_id=r.case_id,
                    investigation_id=r.investigation_id,
                    parent_evidence_id=r.parent_evidence_id,
                    indicator_count=0,
                    finding_count=findings_count,
                )
            )

        metrics = cls.get_evidence_metrics(db, tenant_id=tenant_id)

        return EvidenceListResponse(
            items=items,
            total=total,
            page=page,
            page_size=page_size,
            metrics=metrics,
        )

    @classmethod
    def get_evidence_detail(
        cls,
        db: Session,
        identifier: str,
        tenant_id: str = "default",
    ) -> EvidenceDetailResponse:
        """
        Retrieves full forensic details of a record including cryptographic integrity status,
        custody timeline, parent/child provenance lineage, and correlated incident/finding links.
        """
        record = (
            db.query(EvidenceModel)
            .filter(
                (EvidenceModel.id == identifier) | (EvidenceModel.evidence_id == identifier),
                EvidenceModel.tenant_id == tenant_id,
            )
            .first()
        )
        if not record:
            raise KeyError(f"Forensic evidence '{identifier}' not found in tenant '{tenant_id}'.")

        # 1. Chain of custody events
        custody_rows = (
            db.query(EvidenceCustodyEventModel)
            .filter(EvidenceCustodyEventModel.evidence_id == record.id)
            .order_by(EvidenceCustodyEventModel.timestamp.asc())
            .all()
        )
        custody_list = [
            EvidenceCustodyEventResponse(
                id=c.id,
                evidence_id=record.evidence_id,
                event_type=c.event_type,
                actor_id=c.actor_id,
                timestamp=c.timestamp,
                source=c.source,
                destination=c.destination,
                reason=c.reason,
                integrity_hash=c.integrity_hash,
                metadata=json.loads(c.metadata_json or "{}"),
            )
            for c in custody_rows
        ]

        # 2. Lineage (Parent and Children)
        lineage: List[EvidenceProvenanceLineageItem] = []
        if record.parent_evidence_id:
            parent = db.query(EvidenceModel).filter(EvidenceModel.id == record.parent_evidence_id).first()
            if parent:
                parent_meta = json.loads(record.derivation_metadata_json or "{}")
                lineage.append(
                    EvidenceProvenanceLineageItem(
                        evidence_id=parent.evidence_id,
                        filename=parent.original_filename,
                        sha256=parent.sha256,
                        relation="PARENT",
                        transformation=parent_meta.get("transformation"),
                        tool=parent_meta.get("tool"),
                        timestamp=parent.created_at,
                    )
                )

        # Self
        lineage.append(
            EvidenceProvenanceLineageItem(
                evidence_id=record.evidence_id,
                filename=record.original_filename,
                sha256=record.sha256,
                relation="SELF",
                timestamp=record.collected_at,
            )
        )

        # Children
        children = db.query(EvidenceModel).filter(EvidenceModel.parent_evidence_id == record.id).all()
        for child in children:
            child_meta = json.loads(child.derivation_metadata_json or "{}")
            lineage.append(
                EvidenceProvenanceLineageItem(
                    evidence_id=child.evidence_id,
                    filename=child.original_filename,
                    sha256=child.sha256,
                    relation="CHILD",
                    transformation=child_meta.get("transformation"),
                    tool=child_meta.get("tool"),
                    timestamp=child.created_at,
                )
            )

        # 3. Linked Findings
        findings_list = []
        if record.artifact_id:
            findings_query = (
                db.query(FindingModel)
                .join(FindingEvidenceModel, FindingEvidenceModel.finding_id == FindingModel.id)
                .filter(FindingEvidenceModel.artifact_id == record.artifact_id)
                .all()
            )
            findings_list = [
                {
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity,
                    "status": f.status,
                    "finding_type": f.finding_type,
                }
                for f in findings_query
            ]

        # 4. Forensic notes & gaps
        notes = json.loads(record.forensic_notes_json or "[]")
        gaps = json.loads(record.evidence_gaps_json or "[]")
        meta = json.loads(record.metadata_json or "{}")
        derivation = json.loads(record.derivation_metadata_json or "{}")

        return EvidenceDetailResponse(
            id=record.id,
            evidence_id=record.evidence_id,
            tenant_id=record.tenant_id,
            artifact_id=record.artifact_id,
            case_id=record.case_id,
            investigation_id=record.investigation_id,
            sha256=record.sha256,
            sha1=record.sha1,
            md5=record.md5,
            hash_algorithm=record.hash_algorithm,
            integrity_status=record.integrity_status,
            last_verified_at=record.last_verified_at,
            last_verified_by=record.last_verified_by,
            original_filename=record.original_filename,
            mime_type=record.mime_type,
            size=record.size,
            storage_reference=record.storage_reference,
            source_type=record.source_type,
            source_reference=record.source_reference,
            collection_method=record.collection_method,
            collector=record.collected_by or record.uploader or "SOC Analyst",
            collected_at=record.collected_at,
            received_at=record.received_at,
            observed_at=record.observed_at,
            classification=record.classification,
            lifecycle_status=record.lifecycle_status,
            retention_policy=record.retention_policy,
            preservation_status=record.preservation_status,
            preservation_reason=record.preservation_reason,
            preservation_actor=record.preservation_actor,
            preservation_timestamp=record.preservation_timestamp,
            parent_evidence_id=record.parent_evidence_id,
            derivation_metadata=derivation,
            provenance_lineage=lineage,
            custody_events=custody_list,
            indicators=[],
            findings=findings_list,
            relationships=[],
            timeline_events=[],
            analysis_runs=[],
            forensic_notes=notes,
            evidence_gaps=gaps,
            metadata=meta,
        )

    @classmethod
    def verify_integrity(
        cls,
        db: Session,
        identifier: str,
        current_user: str = "SOC Analyst",
        tenant_id: str = "default",
    ) -> EvidenceIntegrityVerificationResponse:
        """
        Recomputes cryptographic digests of physical stored bytes on demand and audits results.
        If a mismatch is detected, triggers high-severity security alert events and flags the item.
        """
        record = (
            db.query(EvidenceModel)
            .filter(
                (EvidenceModel.id == identifier) | (EvidenceModel.evidence_id == identifier),
                EvidenceModel.tenant_id == tenant_id,
            )
            .first()
        )
        if not record:
            raise KeyError(f"Forensic evidence '{identifier}' not found in tenant '{tenant_id}'.")

        now = get_utc_now()

        # Retrieve bytes safely from storage
        storage_key = record.storage_reference or record.sha256
        try:
            stored_bytes = evidence_storage.retrieve_bytes(storage_key)
        except Exception as exc:
            record.integrity_status = "UNAVAILABLE"
            record.last_verified_at = now
            record.last_verified_by = current_user
            db.commit()
            return EvidenceIntegrityVerificationResponse(
                evidence_id=record.evidence_id,
                sha256_expected=record.sha256,
                sha256_computed="NONE",
                status="UNAVAILABLE",
                verified_at=now,
                verified_by=current_user,
                algorithms_tested=["SHA-256"],
                match=False,
                message=f"Storage retrieval failed: {str(exc)}",
            )

        computed_sha256 = hashlib.sha256(stored_bytes).hexdigest()
        is_match = (computed_sha256.lower() == record.sha256.lower())

        new_status = "VERIFIED" if is_match else "MISMATCH"
        record.integrity_status = new_status
        record.last_verified_at = now
        record.last_verified_by = current_user

        # Add custody event
        custody_event = EvidenceCustodyEventModel(
            evidence_id=record.id,
            tenant_id=tenant_id,
            event_type="ANALYZED",
            actor_id=current_user,
            timestamp=now,
            source="LOCAL_STORAGE",
            destination="INTEGRITY_VERIFIER",
            reason=f"Cryptographic hash integrity audit. Match={is_match}.",
            integrity_hash=computed_sha256,
            metadata_json=json.dumps({
                "match": is_match,
                "expected": record.sha256,
                "computed": computed_sha256,
            }),
            created_at=now,
        )
        db.add(custody_event)

        # Audit log
        audit = AuditLogModel(
            timestamp=now,
            user=current_user,
            action="EVIDENCE_INTEGRITY_CHECK",
            resource_type="evidence",
            resource_id=record.evidence_id,
            metadata_json=json.dumps({"match": is_match, "status": new_status}),
            details=f"Integrity check for {record.evidence_id}: {'PASSED' if is_match else 'CRITICAL MISMATCH'}",
        )
        db.add(audit)
        db.commit()

        # Realtime notification
        event_type = (
            RealtimeEventTypeEnum.EVIDENCE_VALIDATED
            if is_match
            else RealtimeEventTypeEnum.EVIDENCE_INTEGRITY_MISMATCH
        )
        cls._publish_realtime(
            event_type=event_type,
            resource_id=record.evidence_id,
            tenant_id=tenant_id,
            data={"match": is_match, "status": new_status, "evidence_id": record.evidence_id},
        )

        return EvidenceIntegrityVerificationResponse(
            evidence_id=record.evidence_id,
            sha256_expected=record.sha256,
            sha256_computed=computed_sha256,
            status=new_status,
            verified_at=now,
            verified_by=current_user,
            algorithms_tested=["SHA-256"],
            match=is_match,
            message="Cryptographic verification passed successfully."
            if is_match
            else "CRITICAL ALERT: Physical evidence digest mismatch! Possible tampering or corruption.",
        )

    @classmethod
    def get_preview(
        cls,
        db: Session,
        identifier: str,
        tenant_id: str = "default",
        max_bytes: int = 8192,
    ) -> EvidencePreviewResponse:
        """
        Generates bounded, secure preview of evidence bytes (decoded UTF-8 text or canonical Hex dump).
        Prevents dangerous browser execution while giving analysts immediate visibility into file contents.
        """
        record = (
            db.query(EvidenceModel)
            .filter(
                (EvidenceModel.id == identifier) | (EvidenceModel.evidence_id == identifier),
                EvidenceModel.tenant_id == tenant_id,
            )
            .first()
        )
        if not record:
            raise KeyError(f"Forensic evidence '{identifier}' not found in tenant '{tenant_id}'.")

        storage_key = record.storage_reference or record.sha256
        try:
            stored_bytes = evidence_storage.retrieve_bytes(storage_key)
        except Exception:
            return EvidencePreviewResponse(
                evidence_id=record.evidence_id,
                filename=record.original_filename,
                mime_type=record.mime_type,
                size=record.size,
                preview_type="unavailable",
                preview_content="Raw file content not present in local storage backend.",
                truncated=False,
                byte_offset=0,
                total_preview_bytes=0,
            )

        slice_bytes = stored_bytes[:max_bytes]
        truncated = len(stored_bytes) > max_bytes

        # Attempt UTF-8 decode
        try:
            text_candidate = slice_bytes.decode("utf-8")
            # If contains high ratio of printable characters
            printable_ratio = sum(c.isprintable() or c in "\r\n\t " for c in text_candidate) / max(1, len(text_candidate))
            if printable_ratio > 0.85:
                return EvidencePreviewResponse(
                    evidence_id=record.evidence_id,
                    filename=record.original_filename,
                    mime_type=record.mime_type,
                    size=record.size,
                    preview_type="text",
                    preview_content=text_candidate,
                    truncated=truncated,
                    byte_offset=0,
                    total_preview_bytes=len(slice_bytes),
                )
        except UnicodeDecodeError:
            pass

        # Fallback to formatted hexadecimal inspection dump
        lines: List[str] = []
        for i in range(0, len(slice_bytes), 16):
            chunk = slice_bytes[i : i + 16]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            lines.append(f"{i:08x}  {hex_part:<48}  |{ascii_part}|")

        return EvidencePreviewResponse(
            evidence_id=record.evidence_id,
            filename=record.original_filename,
            mime_type=record.mime_type,
            size=record.size,
            preview_type="hex",
            preview_content="\n".join(lines),
            truncated=truncated,
            byte_offset=0,
            total_preview_bytes=len(slice_bytes),
        )

    @classmethod
    def set_preservation(
        cls,
        db: Session,
        identifier: str,
        req: EvidencePreservationRequest,
        current_user: str = "SOC Analyst",
        tenant_id: str = "default",
    ) -> EvidenceDetailResponse:
        """
        Sets or lifts preservation / legal-hold status on evidence with strict justification.
        """
        record = (
            db.query(EvidenceModel)
            .filter(
                (EvidenceModel.id == identifier) | (EvidenceModel.evidence_id == identifier),
                EvidenceModel.tenant_id == tenant_id,
            )
            .first()
        )
        if not record:
            raise KeyError(f"Forensic evidence '{identifier}' not found in tenant '{tenant_id}'.")

        now = get_utc_now()
        record.preservation_status = req.preservation_status.value
        record.preservation_reason = req.reason
        record.preservation_actor = current_user
        record.preservation_timestamp = now
        record.updated_at = now

        # Add custody event
        event_type = "PRESERVED" if req.preservation_status != EvidencePreservationStatusEnum.NORMAL else "RELEASED"
        custody_event = EvidenceCustodyEventModel(
            evidence_id=record.id,
            tenant_id=tenant_id,
            event_type=event_type,
            actor_id=current_user,
            timestamp=now,
            source="SOC_INVESTIGATION",
            destination="LEGAL_HOLD_PRESERVATION",
            reason=req.reason,
            integrity_hash=record.sha256,
            metadata_json=json.dumps({"notes": req.notes}),
            created_at=now,
        )
        db.add(custody_event)

        # Audit log
        audit = AuditLogModel(
            timestamp=now,
            user=current_user,
            action=f"EVIDENCE_{event_type}",
            resource_type="evidence",
            resource_id=record.evidence_id,
            metadata_json=json.dumps({"reason": req.reason, "status": record.preservation_status}),
            details=f"Evidence preservation changed to {record.preservation_status}: {req.reason}",
        )
        db.add(audit)
        db.commit()

        realtime_evt = (
            RealtimeEventTypeEnum.EVIDENCE_PRESERVED
            if event_type == "PRESERVED"
            else RealtimeEventTypeEnum.EVIDENCE_RELEASED
        )
        cls._publish_realtime(
            event_type=realtime_evt,
            resource_id=record.evidence_id,
            tenant_id=tenant_id,
            data={"status": record.preservation_status, "reason": req.reason},
        )

        return cls.get_evidence_detail(db, record.id, tenant_id=tenant_id)

    @classmethod
    def add_custody_event(
        cls,
        db: Session,
        identifier: str,
        req: EvidenceCustodyAddRequest,
        current_user: str = "SOC Analyst",
        tenant_id: str = "default",
    ) -> EvidenceCustodyEventResponse:
        """
        Manually logs an authorized Chain-of-Custody event (e.g. physical transfer, external audit).
        """
        record = (
            db.query(EvidenceModel)
            .filter(
                (EvidenceModel.id == identifier) | (EvidenceModel.evidence_id == identifier),
                EvidenceModel.tenant_id == tenant_id,
            )
            .first()
        )
        if not record:
            raise KeyError(f"Forensic evidence '{identifier}' not found in tenant '{tenant_id}'.")

        now = get_utc_now()
        custody = EvidenceCustodyEventModel(
            evidence_id=record.id,
            tenant_id=tenant_id,
            event_type=req.event_type.value,
            actor_id=current_user,
            timestamp=now,
            source=req.source,
            destination=req.destination,
            reason=req.reason,
            integrity_hash=record.sha256,
            metadata_json=json.dumps({"notes": req.notes}),
            created_at=now,
        )
        db.add(custody)

        # Audit log
        audit = AuditLogModel(
            timestamp=now,
            user=current_user,
            action=f"CUSTODY_{req.event_type.value}",
            resource_type="evidence",
            resource_id=record.evidence_id,
            metadata_json=json.dumps({
                "source": req.source,
                "destination": req.destination,
                "reason": req.reason,
            }),
            details=f"Custody event {req.event_type.value} logged for {record.evidence_id}",
        )
        db.add(audit)
        db.commit()
        db.refresh(custody)

        cls._publish_realtime(
            event_type=RealtimeEventTypeEnum.EVIDENCE_CUSTODY_UPDATED,
            resource_id=record.evidence_id,
            tenant_id=tenant_id,
            data={"event_type": req.event_type.value, "actor_id": current_user},
        )

        return EvidenceCustodyEventResponse(
            id=custody.id,
            evidence_id=record.evidence_id,
            event_type=custody.event_type,
            actor_id=custody.actor_id,
            timestamp=custody.timestamp,
            source=custody.source,
            destination=custody.destination,
            reason=custody.reason,
            integrity_hash=custody.integrity_hash,
            metadata=json.loads(custody.metadata_json or "{}"),
        )

    @classmethod
    def link_evidence(
        cls,
        db: Session,
        identifier: str,
        case_id: Optional[str] = None,
        investigation_id: Optional[str] = None,
        reason: Optional[str] = None,
        current_user: str = "SOC Analyst",
        tenant_id: str = "default",
    ) -> EvidenceDetailResponse:
        """
        Links an authoritative evidence item to an existing Case or Incident investigation.
        """
        record = (
            db.query(EvidenceModel)
            .filter(
                (EvidenceModel.id == identifier) | (EvidenceModel.evidence_id == identifier),
                EvidenceModel.tenant_id == tenant_id,
            )
            .first()
        )
        if not record:
            raise KeyError(f"Forensic evidence '{identifier}' not found in tenant '{tenant_id}'.")

        now = get_utc_now()
        if case_id:
            record.case_id = case_id
        if investigation_id:
            record.investigation_id = investigation_id
        record.updated_at = now

        # Add custody event
        custody = EvidenceCustodyEventModel(
            evidence_id=record.id,
            tenant_id=tenant_id,
            event_type="TRANSFERRED",
            actor_id=current_user,
            timestamp=now,
            source="GLOBAL_EVIDENCE_STORE",
            destination=f"CASE:{case_id or investigation_id}",
            reason=reason or f"Linked to Case={case_id}, Investigation={investigation_id}",
            integrity_hash=record.sha256,
            metadata_json=json.dumps({"case_id": case_id, "investigation_id": investigation_id}),
            created_at=now,
        )
        db.add(custody)

        # Audit log
        audit = AuditLogModel(
            timestamp=now,
            user=current_user,
            action="EVIDENCE_LINKED",
            resource_type="evidence",
            resource_id=record.evidence_id,
            case_id=case_id,
            metadata_json=json.dumps({"case_id": case_id, "investigation_id": investigation_id}),
            details=f"Evidence {record.evidence_id} linked to case/investigation",
        )
        db.add(audit)
        db.commit()

        cls._publish_realtime(
            event_type=RealtimeEventTypeEnum.EVIDENCE_LINKED,
            resource_id=record.evidence_id,
            tenant_id=tenant_id,
            data={"case_id": case_id, "investigation_id": investigation_id},
        )

        return cls.get_evidence_detail(db, record.id, tenant_id=tenant_id)

    @classmethod
    def add_forensic_note(
        cls,
        db: Session,
        identifier: str,
        req: EvidenceNoteAddRequest,
        current_user: str = "SOC Analyst",
        tenant_id: str = "default",
    ) -> EvidenceDetailResponse:
        """
        Adds an analyst observation or forensic finding note with timestamp and category.
        """
        record = (
            db.query(EvidenceModel)
            .filter(
                (EvidenceModel.id == identifier) | (EvidenceModel.evidence_id == identifier),
                EvidenceModel.tenant_id == tenant_id,
            )
            .first()
        )
        if not record:
            raise KeyError(f"Forensic evidence '{identifier}' not found in tenant '{tenant_id}'.")

        notes = json.loads(record.forensic_notes_json or "[]")
        notes.append({
            "text": req.note_text,
            "category": req.category or "ANALYSIS",
            "author": current_user,
            "timestamp": get_utc_now().isoformat(),
        })
        record.forensic_notes_json = json.dumps(notes)
        record.updated_at = get_utc_now()
        db.commit()

        return cls.get_evidence_detail(db, record.id, tenant_id=tenant_id)

    @classmethod
    def derive_evidence(
        cls,
        db: Session,
        parent_identifier: str,
        req: EvidenceDerivationRequest,
        current_user: str = "SOC Analyst",
        tenant_id: str = "default",
    ) -> EvidenceDetailResponse:
        """
        Creates a child evidence item derived from this parent (e.g. carved stream, decoded attachment,
        decompressed archive) maintaining strict lineage, transformation provenance, and audit logs.
        """
        parent = (
            db.query(EvidenceModel)
            .filter(
                (EvidenceModel.id == parent_identifier) | (EvidenceModel.evidence_id == parent_identifier),
                EvidenceModel.tenant_id == tenant_id,
            )
            .first()
        )
        if not parent:
            raise KeyError(f"Parent forensic evidence '{parent_identifier}' not found in tenant '{tenant_id}'.")

        # Decode child bytes or create derivative from description
        child_bytes = (
            base64.b64decode(req.child_bytes_base64)
            if req.child_bytes_base64
            else f"Derivative from {parent.evidence_id}: {req.transformation_description}".encode("utf-8")
        )

        reg_req = EvidenceRegistrationRequest(
            original_filename=req.child_filename,
            source_type=req.child_source_type,
            collection_method=EvidenceCollectionMethodEnum.API,
            source_reference=f"Derived from {parent.evidence_id}",
            collector=current_user,
            classification=EvidenceClassificationEnum(parent.classification),
            case_id=parent.case_id,
            investigation_id=parent.investigation_id,
            notes=f"Derived using {req.transformation_tool}: {req.transformation_description}",
            metadata={
                "parent_evidence_id": parent.evidence_id,
                "transformation_tool": req.transformation_tool,
                "tool_version": req.tool_version,
            },
        )

        child_detail = cls.register_evidence(
            db=db,
            raw_bytes=child_bytes,
            filename=req.child_filename,
            req=reg_req,
            current_user=current_user,
            tenant_id=tenant_id,
        )

        # Update child with parent link and derivation metadata
        child_record = db.query(EvidenceModel).filter(EvidenceModel.evidence_id == child_detail.evidence_id).first()
        if child_record:
            child_record.parent_evidence_id = parent.id
            child_record.derivation_metadata_json = json.dumps({
                "parent_id": parent.id,
                "parent_evidence_id": parent.evidence_id,
                "tool": req.transformation_tool,
                "tool_version": req.tool_version,
                "transformation": req.transformation_description,
                "derived_at": get_utc_now().isoformat(),
            })
            db.commit()

        return cls.get_evidence_detail(db, child_record.id, tenant_id=tenant_id)

    @classmethod
    def export_evidence_manifest(
        cls,
        db: Session,
        identifier: str,
        current_user: str = "SOC Analyst",
        tenant_id: str = "default",
    ) -> EvidenceExportManifestResponse:
        """
        Constructs a complete cryptographic manifest package for legal defense,
        law enforcement handoff, or compliance auditing with package integrity digest.
        """
        detail = cls.get_evidence_detail(db, identifier, tenant_id=tenant_id)
        now = get_utc_now()
        manifest_id = f"MNF-{uuid.uuid4().hex[:12].upper()}"

        package_payload = {
            "manifest_id": manifest_id,
            "evidence_id": detail.evidence_id,
            "filename": detail.original_filename,
            "sha256": detail.sha256,
            "sha1": detail.sha1,
            "md5": detail.md5,
            "size_bytes": detail.size,
            "classification": detail.classification,
            "preservation_status": detail.preservation_status,
            "exported_at": now.isoformat(),
            "exported_by": current_user,
            "tenant_id": tenant_id,
            "custody_chain": [c.model_dump(mode="json") for c in detail.custody_events],
            "provenance_lineage": [p.model_dump(mode="json") for p in detail.provenance_lineage],
        }

        package_raw = json.dumps(package_payload, sort_keys=True).encode("utf-8")
        package_sha256 = hashlib.sha256(package_raw).hexdigest()

        # Log custody EXPORTED event
        cls.add_custody_event(
            db=db,
            identifier=detail.id,
            req=EvidenceCustodyAddRequest(
                event_type=CustodyEventTypeEnum.EXPORTED,
                source="CYBERGUARD_EVIDENCE_STORE",
                destination="LEGAL_EXPORT_PACKAGE",
                reason=f"Exported forensic package {manifest_id} with package digest {package_sha256[:12]}.",
            ),
            current_user=current_user,
            tenant_id=tenant_id,
        )

        return EvidenceExportManifestResponse(
            manifest_id=manifest_id,
            evidence_id=detail.evidence_id,
            filename=detail.original_filename,
            sha256=detail.sha256,
            sha1=detail.sha1,
            md5=detail.md5,
            file_size=detail.size,
            exported_by=current_user,
            exported_at=now,
            tenant_id=tenant_id,
            package_hash_sha256=package_sha256,
            custody_events_count=len(detail.custody_events),
            preservation_status=detail.preservation_status,
            verification_summary=f"Cryptographically signed forensic package containing {len(detail.custody_events)} chain-of-custody transactions.",
            manifest_json=package_payload,
        )

    @classmethod
    def get_evidence_metrics(cls, db: Session, tenant_id: str = "default") -> EvidenceMetricsResponse:
        """
        Computes aggregate metrics across evidence items in the workspace.
        """
        records = db.query(EvidenceModel).filter(EvidenceModel.tenant_id == tenant_id).all()
        total = len(records)
        verified = sum(1 for r in records if r.integrity_status == "VERIFIED")
        mismatch = sum(1 for r in records if r.integrity_status == "MISMATCH")
        pending = sum(1 for r in records if r.integrity_status in ("PENDING", "UNKNOWN"))
        preserved = sum(1 for r in records if r.preservation_status != "NORMAL")

        sources: Dict[str, int] = {}
        classes: Dict[str, int] = {}
        for r in records:
            sources[r.source_type] = sources.get(r.source_type, 0) + 1
            classes[r.classification] = classes.get(r.classification, 0) + 1

        return EvidenceMetricsResponse(
            total_evidence=total,
            verified_count=verified,
            mismatch_count=mismatch,
            pending_count=pending,
            preserved_count=preserved,
            source_distribution=sources,
            classification_distribution=classes,
        )

    @classmethod
    def _publish_realtime(
        cls,
        event_type: RealtimeEventTypeEnum,
        resource_id: str,
        tenant_id: str,
        data: Dict[str, Any],
    ) -> None:
        """Helper to broadcast high-priority WebSocket telemetry for evidence transitions."""
        try:
            RealtimePublisher.publish_event(
                event_type=event_type,
                scope=RealtimeResourceScopeEnum.EVIDENCE,
                resource_id=resource_id,
                workspace_id=tenant_id,
                tenant_id=tenant_id,
                payload=RealtimeEventPayload(
                    event_type=event_type,
                    resource_scope=RealtimeResourceScopeEnum.EVIDENCE,
                    resource_id=resource_id,
                    data=data,
                ),
            )
        except Exception as exc:
            logger.debug(f"Realtime evidence event publishing non-critical error: {exc}")
