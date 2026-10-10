"""
Section 48: Security Alert Management & Triage Service.
Provides authoritative alert retrieval, status lifecycle transitions, provenance aggregation,
audit recording, and Section 46 real-time SSE broadcasts with strict tenant isolation.
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy import desc, func, or_, and_
from sqlalchemy.orm import Session

from backend.db.models import (
    NotificationModel,
    FindingModel,
    FindingEvidenceModel,
    AnalysisRunModel,
    ArtifactModel,
    IncidentModel,
    AuditLogModel,
    get_utc_now,
)
from backend.schemas.alerts import (
    AlertStatusEnum,
    AlertSeverityEnum,
    AlertItemResponse,
    AlertDetailResponse,
    AlertListResponse,
    AlertMetricsResponse,
)
from backend.schemas.realtime import (
    RealtimeEvent,
    RealtimeEventTypeEnum,
    RealtimeResourceScopeEnum,
)
from backend.services.audit_service import AuditService
from backend.services.realtime_service import RealtimePublisher

logger = logging.getLogger("cyberguard.services.alerts")


class AlertService:
    """
    Core triage service managing Security Alerts.
    Operates on NotificationModel records where category == 'SECURITY_ALERT'.
    """

    @classmethod
    def list_alerts(
        cls,
        db: Session,
        workspace_id: str = "default",
        status: Optional[str] = None,
        severity: Optional[str] = None,
        alert_type: Optional[str] = None,
        investigation_id: Optional[str] = None,
        assigned_to: Optional[str] = None,
        q: Optional[str] = None,
        limit: int = 30,
        offset: int = 0,
        sort_by: str = "severity_first",
    ) -> AlertListResponse:
        """
        Retrieves paginated, filtered security alerts.
        """
        base_query = db.query(NotificationModel).filter(
            NotificationModel.workspace_id == workspace_id,
            NotificationModel.category == "SECURITY_ALERT",
        )

        # Status filter with normalization (OPEN includes legacy UNREAD)
        if status:
            statuses = [s.strip().upper() for s in status.split(",") if s.strip()]
            if "OPEN" in statuses and "UNREAD" not in statuses:
                statuses.append("UNREAD")
            base_query = base_query.filter(NotificationModel.status.in_(statuses))

        if severity:
            sevs = [s.strip().upper() for s in severity.split(",") if s.strip()]
            base_query = base_query.filter(NotificationModel.severity.in_(sevs))

        if alert_type:
            base_query = base_query.filter(NotificationModel.notification_type == alert_type.strip())

        if investigation_id:
            base_query = base_query.filter(NotificationModel.investigation_id == investigation_id.strip())

        if assigned_to:
            if assigned_to.upper() == "UNASSIGNED":
                base_query = base_query.filter(NotificationModel.assigned_to.is_(None))
            else:
                base_query = base_query.filter(NotificationModel.assigned_to == assigned_to.strip())

        # Server-side search filter
        if q and q.strip():
            term = f"%{q.strip().lower()}%"
            base_query = base_query.filter(
                or_(
                    func.lower(NotificationModel.title).like(term),
                    func.lower(NotificationModel.message).like(term),
                    func.lower(NotificationModel.source_id).like(term),
                    func.lower(NotificationModel.investigation_id).like(term),
                    func.lower(NotificationModel.notification_type).like(term),
                )
            )

        total = base_query.count()

        # Sorting
        if sort_by == "severity_first":
            # Critical -> High -> Medium -> Low -> Info, then newest
            base_query = base_query.order_by(
                desc(NotificationModel.severity == "CRITICAL"),
                desc(NotificationModel.severity == "HIGH"),
                desc(NotificationModel.severity == "MEDIUM"),
                desc(NotificationModel.created_at),
            )
        elif sort_by == "created_asc":
            base_query = base_query.order_by(NotificationModel.created_at.asc())
        elif sort_by == "updated_desc":
            base_query = base_query.order_by(desc(NotificationModel.updated_at))
        else:
            base_query = base_query.order_by(desc(NotificationModel.created_at))

        records = base_query.offset(offset).limit(limit).all()

        # Aggregated status & severity counts for quick filter pills
        status_counts = cls._get_status_counts(db, workspace_id)
        severity_counts = cls._get_severity_counts(db, workspace_id)

        items = [cls._serialize_item(r) for r in records]

        return AlertListResponse(
            items=items,
            total=total,
            limit=limit,
            offset=offset,
            counts_by_status=status_counts,
            counts_by_severity=severity_counts,
        )

    @classmethod
    def get_alert_metrics(cls, db: Session, workspace_id: str = "default") -> AlertMetricsResponse:
        """Computes fast operational metrics for the alert triage queue."""
        base_q = db.query(NotificationModel).filter(
            NotificationModel.workspace_id == workspace_id,
            NotificationModel.category == "SECURITY_ALERT",
        )

        total_alerts = base_q.count()

        open_q = base_q.filter(NotificationModel.status.in_(["OPEN", "UNREAD"]))
        open_count = open_q.count()
        critical_open = open_q.filter(NotificationModel.severity == "CRITICAL").count()
        high_open = open_q.filter(NotificationModel.severity == "HIGH").count()

        unack_count = base_q.filter(
            NotificationModel.status.in_(["OPEN", "UNREAD"]),
            NotificationModel.acknowledged_at.is_(None)
        ).count()

        investigating_count = base_q.filter(NotificationModel.status == "INVESTIGATING").count()
        resolved_count = base_q.filter(NotificationModel.status.in_(["RESOLVED", "FALSE_POSITIVE", "SUPPRESSED"])).count()

        return AlertMetricsResponse(
            total_alerts=total_alerts,
            open_count=open_count,
            critical_open=critical_open,
            high_open=high_open,
            unacknowledged_count=unack_count,
            investigating_count=investigating_count,
            resolved_count=resolved_count,
        )

    @classmethod
    def get_alert_detail(
        cls,
        db: Session,
        alert_id: str,
        workspace_id: str = "default",
    ) -> Optional[AlertDetailResponse]:
        """
        Returns rich alert record with forensic explainability, finding data, evidence,
        and audit activity timeline.
        """
        record = (
            db.query(NotificationModel)
            .filter(
                NotificationModel.id == alert_id,
                NotificationModel.workspace_id == workspace_id,
                NotificationModel.category == "SECURITY_ALERT",
            )
            .first()
        )
        if not record:
            return None

        meta = cls._parse_meta(record.metadata_json)

        # 1. Resolve Why This Alert Exists (Explainability)
        why_items: List[str] = []
        finding_info: Optional[Dict[str, Any]] = None
        evidence_list: List[Dict[str, Any]] = []

        if record.finding_id:
            fnd = db.query(FindingModel).filter(FindingModel.id == record.finding_id).first()
            if fnd:
                finding_info = {
                    "id": fnd.id,
                    "title": fnd.title,
                    "analyzer": fnd.analyzer,
                    "finding_type": fnd.finding_type,
                    "severity": fnd.severity,
                    "confidence": fnd.confidence,
                    "risk_contribution": fnd.risk_contribution,
                    "method": fnd.method,
                    "rule_id": fnd.rule_id,
                    "description": fnd.description,
                }
                if fnd.description:
                    why_items.append(fnd.description)
                if fnd.rule_id:
                    why_items.append(f"{fnd.analyzer} triggered rule: {fnd.rule_id}")

                # Load evidence items for this finding
                for ev in fnd.evidence_items:
                    evidence_list.append({
                        "id": ev.id,
                        "evidence_type": ev.evidence_type,
                        "description": getattr(ev, "key", None) or getattr(ev, "description", None) or ev.evidence_type,
                        "source": ev.source,
                        "indicator_value": getattr(ev, "value", None) or getattr(ev, "indicator_value", None) or "",
                        "relevance_score": getattr(ev, "confidence", 1.0),
                    })

        # Add explainability points from metadata
        if "explanation" in meta and meta["explanation"] not in why_items:
            why_items.append(str(meta["explanation"]))

        if not why_items:
            why_items.append(f"Authoritative security detection from {record.source_type} ({record.title})")

        # 2. Resolve Analysis Run Details
        analysis_run_info: Optional[Dict[str, Any]] = None
        if record.analysis_run_id:
            run = db.query(AnalysisRunModel).filter(AnalysisRunModel.id == record.analysis_run_id).first()
            if run:
                analysis_run_info = {
                    "id": run.id,
                    "status": run.status,
                    "started_at": run.started_at.isoformat() if run.started_at else None,
                    "completed_at": run.completed_at.isoformat() if run.completed_at else None,
                    "overall_risk_score": run.overall_risk_score,
                    "overall_severity": run.overall_severity,
                    "artifact_name": run.artifact.name if run.artifact else None,
                    "artifact_sha256": run.artifact.sha256 if run.artifact else None,
                }

        # 3. Resolve Investigation Context
        investigation_info: Optional[Dict[str, Any]] = None
        if record.investigation_id:
            inc = (
                db.query(IncidentModel)
                .filter(
                    or_(
                        IncidentModel.id == record.investigation_id,
                        IncidentModel.incident_number == record.investigation_id
                    )
                )
                .first()
            )
            if inc:
                investigation_info = {
                    "id": inc.id,
                    "incident_number": inc.incident_number,
                    "title": inc.title,
                    "status": inc.status,
                    "severity": inc.severity,
                    "risk_score": inc.risk_score,
                }

        # 4. Resolve Activity Timeline from Audit Log
        activity_logs = (
            db.query(AuditLogModel)
            .filter(
                AuditLogModel.resource_type == "alert",
                AuditLogModel.resource_id == record.id,
            )
            .order_by(AuditLogModel.timestamp.asc())
            .all()
        )
        timeline = []
        # Initial creation marker
        timeline.append({
            "action": "ALERT_CREATED",
            "timestamp": record.created_at.isoformat(),
            "user": "System Analyzer",
            "details": f"Alert initialized from {record.source_type}",
        })
        for log in activity_logs:
            timeline.append({
                "action": log.action,
                "timestamp": log.timestamp.isoformat(),
                "user": log.user or "SOC Analyst",
                "details": log.details or f"Action: {log.action}",
            })

        base_item = cls._serialize_item(record)

        return AlertDetailResponse(
            **base_item.model_dump(),
            why_created=why_items,
            finding_detail=finding_info,
            evidence_items=evidence_list,
            analysis_run_detail=analysis_run_info,
            investigation_detail=investigation_info,
            activity_timeline=timeline,
            resolution_reason=record.resolution_reason,
            false_positive_reason=record.false_positive_reason,
            suppression_reason=record.suppression_reason,
            suppression_scope=record.suppression_scope,
            metadata=meta,
        )

    # =========================================================================
    # TRIAGE ACTIONS & AUDITED STATE TRANSITIONS
    # =========================================================================

    @classmethod
    def acknowledge_alert(
        cls,
        db: Session,
        alert_id: str,
        workspace_id: str = "default",
        analyst_name: Optional[str] = None,
        note: Optional[str] = None,
    ) -> Optional[AlertItemResponse]:
        """Transitions alert to ACKNOWLEDGED state with audit logging."""
        record = cls._get_record(db, alert_id, workspace_id)
        if not record:
            return None

        now = get_utc_now()
        analyst = (analyst_name or "SOC Analyst").strip()

        record.status = AlertStatusEnum.ACKNOWLEDGED.value
        record.acknowledged_at = now
        record.acknowledged_by = analyst
        record.updated_at = now

        meta = cls._parse_meta(record.metadata_json)
        if note:
            notes = meta.setdefault("triage_notes", [])
            notes.append({"author": analyst, "note": note.strip(), "timestamp": now.isoformat()})
            record.metadata_json = json.dumps(meta)

        db.commit()
        db.refresh(record)

        AuditService.log_audit(
            db=db,
            action="ALERT_ACKNOWLEDGED",
            resource_type="alert",
            resource_id=record.id,
            user=analyst,
            details=f"Alert acknowledged by {analyst}. {note or ''}".strip(),
        )

        cls._broadcast_alert(record, RealtimeEventTypeEnum.ALERT_STATUS_CHANGED.value)
        return cls._serialize_item(record)

    @classmethod
    def assign_alert(
        cls,
        db: Session,
        alert_id: str,
        assigned_to: str,
        workspace_id: str = "default",
        analyst_name: Optional[str] = None,
    ) -> Optional[AlertItemResponse]:
        """Assigns an alert to a specific analyst."""
        record = cls._get_record(db, alert_id, workspace_id)
        if not record:
            return None

        now = get_utc_now()
        analyst = (analyst_name or "SOC Analyst").strip()
        assignee = assigned_to.strip()

        record.assigned_to = assignee
        record.updated_at = now
        db.commit()
        db.refresh(record)

        AuditService.log_audit(
            db=db,
            action="ALERT_ASSIGNED",
            resource_type="alert",
            resource_id=record.id,
            user=analyst,
            details=f"Alert assigned to {assignee} by {analyst}.",
        )

        cls._broadcast_alert(record, RealtimeEventTypeEnum.ALERT_ASSIGNED.value)
        return cls._serialize_item(record)

    @classmethod
    def investigate_alert(
        cls,
        db: Session,
        alert_id: str,
        workspace_id: str = "default",
        analyst_name: Optional[str] = None,
    ) -> Optional[AlertItemResponse]:
        """Transitions alert to INVESTIGATING state."""
        record = cls._get_record(db, alert_id, workspace_id)
        if not record:
            return None

        now = get_utc_now()
        analyst = (analyst_name or "SOC Analyst").strip()

        record.status = AlertStatusEnum.INVESTIGATING.value
        record.updated_at = now
        db.commit()
        db.refresh(record)

        AuditService.log_audit(
            db=db,
            action="ALERT_INVESTIGATING",
            resource_type="alert",
            resource_id=record.id,
            user=analyst,
            details=f"Alert placed under active investigation by {analyst}.",
        )

        cls._broadcast_alert(record, RealtimeEventTypeEnum.ALERT_STATUS_CHANGED.value)
        return cls._serialize_item(record)

    @classmethod
    def resolve_alert(
        cls,
        db: Session,
        alert_id: str,
        resolution_reason: str,
        workspace_id: str = "default",
        analyst_name: Optional[str] = None,
    ) -> Optional[AlertItemResponse]:
        """Resolves alert with disposition reason."""
        record = cls._get_record(db, alert_id, workspace_id)
        if not record:
            return None

        now = get_utc_now()
        analyst = (analyst_name or "SOC Lead Analyst").strip()
        reason = resolution_reason.strip()

        record.status = AlertStatusEnum.RESOLVED.value
        record.resolved_at = now
        record.resolved_by = analyst
        record.resolution_reason = reason
        record.updated_at = now
        db.commit()
        db.refresh(record)

        AuditService.log_audit(
            db=db,
            action="ALERT_RESOLVED",
            resource_type="alert",
            resource_id=record.id,
            user=analyst,
            details=f"Alert resolved: {reason}",
        )

        cls._broadcast_alert(record, RealtimeEventTypeEnum.ALERT_RESOLVED.value)
        return cls._serialize_item(record)

    @classmethod
    def mark_false_positive(
        cls,
        db: Session,
        alert_id: str,
        reason: str,
        workspace_id: str = "default",
        analyst_name: Optional[str] = None,
    ) -> Optional[AlertItemResponse]:
        """Marks alert as FALSE_POSITIVE with justification."""
        record = cls._get_record(db, alert_id, workspace_id)
        if not record:
            return None

        now = get_utc_now()
        analyst = (analyst_name or "SOC Analyst").strip()
        fp_reason = reason.strip()

        record.status = AlertStatusEnum.FALSE_POSITIVE.value
        record.resolved_at = now
        record.resolved_by = analyst
        record.false_positive_reason = fp_reason
        record.updated_at = now
        db.commit()
        db.refresh(record)

        AuditService.log_audit(
            db=db,
            action="ALERT_FALSE_POSITIVE",
            resource_type="alert",
            resource_id=record.id,
            user=analyst,
            details=f"Marked false positive: {fp_reason}",
        )

        cls._broadcast_alert(record, RealtimeEventTypeEnum.ALERT_STATUS_CHANGED.value)
        return cls._serialize_item(record)

    @classmethod
    def suppress_alert(
        cls,
        db: Session,
        alert_id: str,
        reason: str,
        scope: str = "THIS_ALERT",
        workspace_id: str = "default",
        analyst_name: Optional[str] = None,
    ) -> Optional[AlertItemResponse]:
        """Suppresses alert under a defined scope."""
        record = cls._get_record(db, alert_id, workspace_id)
        if not record:
            return None

        now = get_utc_now()
        analyst = (analyst_name or "SOC Analyst").strip()
        clean_scope = scope.strip().upper()

        record.status = AlertStatusEnum.SUPPRESSED.value
        record.suppression_reason = reason.strip()
        record.suppression_scope = clean_scope
        record.updated_at = now
        db.commit()
        db.refresh(record)

        AuditService.log_audit(
            db=db,
            action="ALERT_SUPPRESSED",
            resource_type="alert",
            resource_id=record.id,
            user=analyst,
            details=f"Suppressed (scope={clean_scope}): {reason.strip()}",
        )

        cls._broadcast_alert(record, RealtimeEventTypeEnum.ALERT_SUPPRESSED.value)
        return cls._serialize_item(record)

    @classmethod
    def add_note(
        cls,
        db: Session,
        alert_id: str,
        note_text: str,
        workspace_id: str = "default",
        analyst_name: Optional[str] = None,
    ) -> Optional[AlertDetailResponse]:
        """Appends an auditable analyst triage note to the alert."""
        record = cls._get_record(db, alert_id, workspace_id)
        if not record:
            return None

        now = get_utc_now()
        analyst = (analyst_name or "SOC Analyst").strip()
        text_clean = note_text.strip()

        meta = cls._parse_meta(record.metadata_json)
        notes = meta.setdefault("triage_notes", [])
        notes.append({
            "author": analyst,
            "note": text_clean,
            "timestamp": now.isoformat(),
        })
        record.metadata_json = json.dumps(meta)
        record.updated_at = now
        db.commit()
        db.refresh(record)

        AuditService.log_audit(
            db=db,
            action="ALERT_NOTE_ADDED",
            resource_type="alert",
            resource_id=record.id,
            user=analyst,
            details=f"Triage note: {text_clean}",
        )

        cls._broadcast_alert(record, RealtimeEventTypeEnum.ALERT_NOTE_ADDED.value)
        return cls.get_alert_detail(db, alert_id, workspace_id)

    @classmethod
    def bulk_acknowledge(
        cls,
        db: Session,
        alert_ids: List[str],
        workspace_id: str = "default",
        analyst_name: Optional[str] = None,
    ) -> List[str]:
        """Batch acknowledges a list of alert IDs within workspace."""
        analyst = (analyst_name or "SOC Analyst").strip()
        records = (
            db.query(NotificationModel)
            .filter(
                NotificationModel.id.in_(alert_ids),
                NotificationModel.workspace_id == workspace_id,
                NotificationModel.category == "SECURITY_ALERT",
            )
            .all()
        )
        now = get_utc_now()
        acked_ids: List[str] = []
        for r in records:
            if r.status in ("OPEN", "UNREAD"):
                r.status = AlertStatusEnum.ACKNOWLEDGED.value
                r.acknowledged_at = now
                r.acknowledged_by = analyst
                r.updated_at = now
                acked_ids.append(r.id)
                AuditService.log_audit(
                    db=db,
                    action="ALERT_ACKNOWLEDGED",
                    resource_type="alert",
                    resource_id=r.id,
                    user=analyst,
                    details=f"Bulk acknowledged by {analyst}",
                )

        if acked_ids:
            db.commit()
            evt = RealtimeEvent(
                schema_version=1,
                event_id=str(uuid.uuid4()),
                sequence=1,
                event_type=RealtimeEventTypeEnum.ALERT_STATUS_CHANGED.value,
                resource_type=RealtimeResourceScopeEnum.WORKSPACE.value,
                resource_id=workspace_id,
                workspace_id=workspace_id,
                message=f"Bulk acknowledged {len(acked_ids)} alerts",
                payload={"count": len(acked_ids), "alert_ids": acked_ids, "analyst": analyst},
            )
            RealtimePublisher._async_broadcast(evt)

        return acked_ids

    # =========================================================================
    # HELPERS
    # =========================================================================

    @classmethod
    def _get_record(cls, db: Session, alert_id: str, workspace_id: str) -> Optional[NotificationModel]:
        return (
            db.query(NotificationModel)
            .filter(
                NotificationModel.id == alert_id,
                NotificationModel.workspace_id == workspace_id,
                NotificationModel.category == "SECURITY_ALERT",
            )
            .first()
        )

    @classmethod
    def _get_status_counts(cls, db: Session, workspace_id: str) -> Dict[str, int]:
        rows = (
            db.query(NotificationModel.status, func.count(NotificationModel.id))
            .filter(
                NotificationModel.workspace_id == workspace_id,
                NotificationModel.category == "SECURITY_ALERT",
            )
            .group_by(NotificationModel.status)
            .all()
        )
        counts: Dict[str, int] = {
            "OPEN": 0,
            "ACKNOWLEDGED": 0,
            "INVESTIGATING": 0,
            "RESOLVED": 0,
            "FALSE_POSITIVE": 0,
            "SUPPRESSED": 0,
        }
        for st, c in rows:
            clean_st = "OPEN" if st == "UNREAD" else st
            counts[clean_st] = counts.get(clean_st, 0) + c
        return counts

    @classmethod
    def _get_severity_counts(cls, db: Session, workspace_id: str) -> Dict[str, int]:
        rows = (
            db.query(NotificationModel.severity, func.count(NotificationModel.id))
            .filter(
                NotificationModel.workspace_id == workspace_id,
                NotificationModel.category == "SECURITY_ALERT",
            )
            .group_by(NotificationModel.severity)
            .all()
        )
        counts: Dict[str, int] = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0,
        }
        for sev, c in rows:
            counts[sev] = counts.get(sev, 0) + c
        return counts

    @classmethod
    def _broadcast_alert(cls, record: NotificationModel, event_type: str) -> None:
        evt = RealtimeEvent(
            schema_version=1,
            event_id=str(uuid.uuid4()),
            sequence=1,
            event_type=event_type,
            resource_type=RealtimeResourceScopeEnum.ALERT.value,
            resource_id=record.id,
            workspace_id=record.workspace_id,
            investigation_id=record.investigation_id,
            analysis_run_id=record.analysis_run_id,
            status=record.status,
            message=record.title,
            payload={
                "alert_id": record.id,
                "status": record.status,
                "assigned_to": record.assigned_to,
                "severity": record.severity,
            },
        )
        RealtimePublisher._async_broadcast(evt)

    @classmethod
    def _parse_meta(cls, raw_json: Optional[str]) -> Dict[str, Any]:
        if not raw_json:
            return {}
        try:
            return json.loads(raw_json)
        except Exception:
            return {}

    @classmethod
    def _serialize_item(cls, m: NotificationModel) -> AlertItemResponse:
        meta = cls._parse_meta(m.metadata_json)
        risk = float(meta.get("risk_contribution", 0.0))
        if risk == 0.0 and m.severity == "CRITICAL":
            risk = 90.0
        elif risk == 0.0 and m.severity == "HIGH":
            risk = 70.0

        conf = float(meta.get("confidence", 1.0))
        clean_status = "OPEN" if m.status == "UNREAD" else m.status

        return AlertItemResponse(
            id=m.id,
            workspace_id=m.workspace_id,
            alert_type=m.notification_type,
            severity=m.severity,
            status=clean_status,
            title=m.title,
            message=m.message,
            risk_score=risk,
            confidence=conf,
            source_type=m.source_type,
            source_id=m.source_id,
            investigation_id=m.investigation_id,
            analysis_run_id=m.analysis_run_id,
            finding_id=m.finding_id,
            navigation_target=m.navigation_target,
            assigned_to=m.assigned_to,
            created_at=m.created_at,
            updated_at=m.updated_at or m.created_at,
            acknowledged_at=m.acknowledged_at,
            acknowledged_by=m.acknowledged_by,
            resolved_at=m.resolved_at,
            resolved_by=m.resolved_by,
        )
