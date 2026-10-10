"""
Section 47: Notification & Alert Center Service.
Provides authoritative persistence, deduplication, unread counts, acknowledgement,
and real-time integration for security alerts and system notifications.
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy import desc, func, and_
from sqlalchemy.orm import Session

from backend.db.models import (
    NotificationModel,
    FindingModel,
    AnalysisRunModel,
    ReportModel,
    BackgroundJobModel,
    get_utc_now,
)
from backend.schemas.notification import (
    NotificationCategoryEnum,
    NotificationSeverityEnum,
    NotificationStatusEnum,
    NotificationTypeEnum,
    NotificationRead,
    NotificationListResponse,
    NotificationUnreadCountResponse,
)
from backend.schemas.realtime import (
    RealtimeEvent,
    RealtimeEventTypeEnum,
    RealtimeResourceScopeEnum,
)
from backend.services.notification_policy import (
    NotificationPolicy,
    NotificationPolicyDecision,
)
from backend.services.realtime_service import RealtimePublisher, global_realtime_hub

logger = logging.getLogger("cyberguard.services.notifications")


class NotificationService:
    """
    Unified Notification and Security Alert Management Service.
    Enforces tenant isolation, idempotency deduplication, and Section 46 real-time dispatch.
    """

    @classmethod
    def create_notification(
        cls,
        db: Session,
        workspace_id: str,
        category: str,
        notification_type: str,
        severity: str,
        title: str,
        message: str,
        source_type: str,
        source_id: str,
        deduplication_key: str,
        investigation_id: Optional[str] = None,
        analysis_run_id: Optional[str] = None,
        finding_id: Optional[str] = None,
        job_id: Optional[str] = None,
        report_id: Optional[str] = None,
        navigation_target: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        user_id: Optional[str] = None,
    ) -> Optional[NotificationModel]:
        """
        Creates and persists a NotificationModel if not suppressed by deduplication.
        Emits NOTIFICATION_CREATED over Section 46 real-time channels.
        """
        try:
            # 1. Deduplication check
            existing = (
                db.query(NotificationModel)
                .filter(
                    NotificationModel.workspace_id == workspace_id,
                    NotificationModel.deduplication_key == deduplication_key,
                )
                .first()
            )
            if existing:
                logger.debug(
                    "Notification suppressed by deduplication_key=%s in workspace=%s",
                    deduplication_key,
                    workspace_id,
                )
                return existing

            # 2. Persist new record
            now = get_utc_now()
            notif = NotificationModel(
                id=str(uuid.uuid4()),
                workspace_id=workspace_id or "default",
                user_id=user_id,
                category=category,
                notification_type=notification_type,
                severity=severity,
                status=NotificationStatusEnum.UNREAD.value,
                title=title,
                message=message,
                source_type=source_type,
                source_id=source_id,
                investigation_id=investigation_id,
                analysis_run_id=analysis_run_id,
                finding_id=finding_id,
                job_id=job_id,
                report_id=report_id,
                navigation_target=navigation_target,
                deduplication_key=deduplication_key,
                metadata_json=json.dumps(metadata or {}),
                created_at=now,
            )
            db.add(notif)
            db.commit()
            db.refresh(notif)

            # 3. Non-blocking real-time broadcast via Section 46 Hub
            clean_meta = dict(metadata or {})
            clean_meta["notification_id"] = notif.id
            clean_meta["category"] = notif.category
            clean_meta["severity"] = notif.severity
            clean_meta["type"] = notif.notification_type

            realtime_event = RealtimeEvent(
                schema_version=1,
                event_id=str(uuid.uuid4()),
                sequence=1,
                event_type=RealtimeEventTypeEnum.NOTIFICATION_CREATED.value,
                resource_type=RealtimeResourceScopeEnum.NOTIFICATION.value,
                resource_id=notif.id,
                workspace_id=notif.workspace_id,
                investigation_id=notif.investigation_id,
                analysis_run_id=notif.analysis_run_id,
                job_id=notif.job_id,
                report_id=notif.report_id,
                status=notif.status,
                message=notif.title,
                payload=clean_meta,
                created_at=now,
            )
            RealtimePublisher._async_broadcast(realtime_event)

            # 4. Trigger Section 49 Alert Correlation for Security Alerts
            if notif.category == NotificationCategoryEnum.SECURITY_ALERT.value:
                try:
                    from backend.services.alert_correlation_service import AlertCorrelationService
                    AlertCorrelationService.correlate_alert(
                        db=db,
                        alert_id=notif.id,
                        workspace_id=notif.workspace_id,
                        triggered_by="system:notification_lifecycle",
                    )
                except Exception as corr_err:
                    logger.warning("Automatic alert correlation failed for alert %s (alert preserved): %s", notif.id, corr_err)

            return notif

        except Exception as e:
            logger.error("Failed to create notification: %s", e, exc_info=True)
            db.rollback()
            return None

    # =========================================================================
    # LIFECYCLE HOOKS CALLED BY PIPELINES
    # =========================================================================

    @classmethod
    def on_finding_persisted(
        cls,
        db: Session,
        finding: FindingModel,
        workspace_id: str = "default",
        investigation_id: Optional[str] = None,
    ) -> Optional[NotificationModel]:
        """Invoked when an analyzer produces and persists a finding."""
        decision = NotificationPolicy.evaluate_finding(
            finding_id=finding.id,
            finding_type=finding.finding_type,
            title=finding.title,
            severity=finding.severity,
            risk_contribution=finding.risk_contribution,
            analyzer=finding.analyzer,
            investigation_id=investigation_id,
            analysis_run_id=finding.analysis_run_id,
            description=finding.description,
            workspace_id=workspace_id,
        )
        if not decision.should_notify:
            return None

        return cls.create_notification(
            db=db,
            workspace_id=workspace_id,
            category=decision.category,
            notification_type=decision.notification_type,
            severity=decision.severity,
            title=decision.title,
            message=decision.message,
            source_type="FINDING",
            source_id=finding.id,
            deduplication_key=decision.deduplication_key,
            investigation_id=investigation_id,
            analysis_run_id=finding.analysis_run_id,
            finding_id=finding.id,
            navigation_target=decision.navigation_target,
            metadata=decision.metadata,
        )

    @classmethod
    def on_analysis_run_completed(
        cls,
        db: Session,
        run: AnalysisRunModel,
        workspace_id: str = "default",
        investigation_id: Optional[str] = None,
    ) -> Optional[NotificationModel]:
        """Invoked when AnalysisOrchestrator concludes a run."""
        decision = NotificationPolicy.evaluate_analysis_run(
            run_id=run.id,
            status=run.status,
            overall_severity=run.overall_severity,
            overall_risk_score=run.overall_risk_score,
            investigation_id=investigation_id,
            error_message=run.error,
            workspace_id=workspace_id,
        )
        if not decision.should_notify:
            return None

        return cls.create_notification(
            db=db,
            workspace_id=workspace_id,
            category=decision.category,
            notification_type=decision.notification_type,
            severity=decision.severity,
            title=decision.title,
            message=decision.message,
            source_type="ANALYSIS_RUN",
            source_id=run.id,
            deduplication_key=decision.deduplication_key,
            investigation_id=investigation_id,
            analysis_run_id=run.id,
            navigation_target=decision.navigation_target,
            metadata=decision.metadata,
        )

    @classmethod
    def on_report_completed(
        cls,
        db: Session,
        report: ReportModel,
        workspace_id: str = "default",
        error_message: Optional[str] = None,
    ) -> Optional[NotificationModel]:
        """Invoked when report generation concludes."""
        decision = NotificationPolicy.evaluate_report(
            report_id=report.id,
            report_number=report.report_number,
            status=report.status,
            investigation_id=report.investigation_id,
            workspace_id=workspace_id,
            error_message=error_message,
        )
        if not decision.should_notify:
            return None

        return cls.create_notification(
            db=db,
            workspace_id=workspace_id,
            category=decision.category,
            notification_type=decision.notification_type,
            severity=decision.severity,
            title=decision.title,
            message=decision.message,
            source_type="REPORT",
            source_id=report.id,
            deduplication_key=decision.deduplication_key,
            investigation_id=report.investigation_id,
            report_id=report.id,
            navigation_target=decision.navigation_target,
            metadata=decision.metadata,
        )

    @classmethod
    def on_job_failed(
        cls,
        db: Session,
        job: BackgroundJobModel,
        workspace_id: str = "default",
        error_message: Optional[str] = None,
        investigation_id: Optional[str] = None,
    ) -> Optional[NotificationModel]:
        """Invoked when a BackgroundJob transitions to FAILED state."""
        decision = NotificationPolicy.evaluate_job(
            job_id=job.id,
            job_type=job.job_type,
            status="FAILED",
            workspace_id=workspace_id,
            error_message=error_message or job.sanitized_error_message,
            investigation_id=investigation_id,
        )
        if not decision.should_notify:
            return None

        return cls.create_notification(
            db=db,
            workspace_id=workspace_id,
            category=decision.category,
            notification_type=decision.notification_type,
            severity=decision.severity,
            title=decision.title,
            message=decision.message,
            source_type="JOB",
            source_id=job.id,
            deduplication_key=decision.deduplication_key,
            investigation_id=investigation_id,
            job_id=job.id,
            navigation_target=decision.navigation_target,
            metadata=decision.metadata,
        )

    # =========================================================================
    # QUERY & TRIAGE APIS
    # =========================================================================

    @classmethod
    def list_notifications(
        cls,
        db: Session,
        workspace_id: str = "default",
        user_id: Optional[str] = None,
        category: Optional[str] = None,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        investigation_id: Optional[str] = None,
        limit: int = 30,
        offset: int = 0,
    ) -> NotificationListResponse:
        """
        Lists paginated notifications and alerts with strict workspace isolation.
        """
        base_query = db.query(NotificationModel).filter(
            NotificationModel.workspace_id == workspace_id
        )

        if user_id:
            # Workspace-wide notifications (user_id IS NULL) or assigned directly to user
            base_query = base_query.filter(
                (NotificationModel.user_id == user_id) | (NotificationModel.user_id.is_(None))
            )

        if category:
            base_query = base_query.filter(NotificationModel.category == category.upper())

        if status:
            base_query = base_query.filter(NotificationModel.status == status.upper())

        if severity:
            base_query = base_query.filter(NotificationModel.severity == severity.upper())

        if investigation_id:
            base_query = base_query.filter(NotificationModel.investigation_id == investigation_id)

        total = base_query.count()

        records = (
            base_query.order_by(desc(NotificationModel.created_at))
            .offset(offset)
            .limit(limit)
            .all()
        )

        # Compute unread breakdown
        unread_counts = cls.get_unread_count(db, workspace_id, user_id)

        items = [cls._serialize_notification(r) for r in records]

        return NotificationListResponse(
            items=items,
            total=total,
            unread_total=unread_counts.total_unread,
            unread_alerts=unread_counts.alerts_unread,
            unread_notifications=unread_counts.notifications_unread,
            limit=limit,
            offset=offset,
        )

    @classmethod
    def get_unread_count(
        cls,
        db: Session,
        workspace_id: str = "default",
        user_id: Optional[str] = None,
    ) -> NotificationUnreadCountResponse:
        """Fast scalar query to compute unread notifications count."""
        q = db.query(
            NotificationModel.category,
            func.count(NotificationModel.id).label("cnt")
        ).filter(
            NotificationModel.workspace_id == workspace_id,
            NotificationModel.status == NotificationStatusEnum.UNREAD.value,
        )

        if user_id:
            q = q.filter((NotificationModel.user_id == user_id) | (NotificationModel.user_id.is_(None)))

        grouped = q.group_by(NotificationModel.category).all()
        alerts_unread = 0
        notifs_unread = 0

        for cat, cnt in grouped:
            if cat == NotificationCategoryEnum.SECURITY_ALERT.value:
                alerts_unread += cnt
            else:
                notifs_unread += cnt

        return NotificationUnreadCountResponse(
            total_unread=alerts_unread + notifs_unread,
            alerts_unread=alerts_unread,
            notifications_unread=notifs_unread,
        )

    @classmethod
    def mark_as_read(
        cls,
        db: Session,
        notification_id: str,
        workspace_id: str = "default",
    ) -> Optional[NotificationRead]:
        """Marks a specific notification as READ."""
        record = (
            db.query(NotificationModel)
            .filter(
                NotificationModel.id == notification_id,
                NotificationModel.workspace_id == workspace_id,
            )
            .first()
        )
        if not record:
            return None

        if record.status == NotificationStatusEnum.UNREAD.value:
            record.status = NotificationStatusEnum.READ.value
            record.read_at = get_utc_now()
            db.commit()
            db.refresh(record)

            # Realtime broadcast
            cls._broadcast_update(record, RealtimeEventTypeEnum.NOTIFICATION_READ.value)

        return cls._serialize_notification(record)

    @classmethod
    def mark_all_as_read(
        cls,
        db: Session,
        workspace_id: str = "default",
        category: Optional[str] = None,
        user_id: Optional[str] = None,
    ) -> int:
        """Batch marks all unread notifications as READ."""
        q = db.query(NotificationModel).filter(
            NotificationModel.workspace_id == workspace_id,
            NotificationModel.status == NotificationStatusEnum.UNREAD.value,
        )
        if category:
            q = q.filter(NotificationModel.category == category.upper())
        if user_id:
            q = q.filter((NotificationModel.user_id == user_id) | (NotificationModel.user_id.is_(None)))

        records = q.all()
        now = get_utc_now()
        count = 0
        for r in records:
            r.status = NotificationStatusEnum.READ.value
            r.read_at = now
            count += 1

        if count > 0:
            db.commit()
            # Broadcast read update to workspace
            evt = RealtimeEvent(
                schema_version=1,
                event_id=str(uuid.uuid4()),
                sequence=1,
                event_type=RealtimeEventTypeEnum.NOTIFICATION_READ.value,
                resource_type=RealtimeResourceScopeEnum.WORKSPACE.value,
                resource_id=workspace_id,
                workspace_id=workspace_id,
                message=f"Marked {count} notifications as read",
                payload={"count": count, "category": category},
            )
            RealtimePublisher._async_broadcast(evt)

        return count

    @classmethod
    def acknowledge_alert(
        cls,
        db: Session,
        notification_id: str,
        workspace_id: str = "default",
        analyst_name: Optional[str] = None,
        note: Optional[str] = None,
    ) -> Optional[NotificationRead]:
        """
        Acknowledges a Security Alert.
        Transitions status from OPEN/UNREAD/READ -> ACKNOWLEDGED.
        Stores analyst identity and acknowledgement timestamp.
        """
        record = (
            db.query(NotificationModel)
            .filter(
                NotificationModel.id == notification_id,
                NotificationModel.workspace_id == workspace_id,
            )
            .first()
        )
        if not record:
            return None

        record.status = NotificationStatusEnum.ACKNOWLEDGED.value
        record.acknowledged_at = get_utc_now()
        record.acknowledged_by = (analyst_name or "SOC Lead Analyst").strip()

        if note:
            try:
                meta = json.loads(record.metadata_json or "{}")
                meta["acknowledgement_note"] = note.strip()
                record.metadata_json = json.dumps(meta)
            except Exception:
                pass

        db.commit()
        db.refresh(record)

        # Broadcast acknowledgement event
        cls._broadcast_update(record, RealtimeEventTypeEnum.ALERT_ACKNOWLEDGED.value)

        return cls._serialize_notification(record)

    @classmethod
    def _broadcast_update(cls, record: NotificationModel, event_type: str) -> None:
        """Helper to broadcast notification state changes."""
        evt = RealtimeEvent(
            schema_version=1,
            event_id=str(uuid.uuid4()),
            sequence=1,
            event_type=event_type,
            resource_type=RealtimeResourceScopeEnum.NOTIFICATION.value,
            resource_id=record.id,
            workspace_id=record.workspace_id,
            investigation_id=record.investigation_id,
            analysis_run_id=record.analysis_run_id,
            status=record.status,
            message=record.title,
            payload={
                "notification_id": record.id,
                "status": record.status,
                "acknowledged_by": record.acknowledged_by,
            },
        )
        RealtimePublisher._async_broadcast(evt)

    @classmethod
    def _serialize_notification(cls, m: NotificationModel) -> NotificationRead:
        try:
            meta = json.loads(m.metadata_json) if m.metadata_json else {}
        except Exception:
            meta = {}

        return NotificationRead(
            id=m.id,
            workspace_id=m.workspace_id,
            user_id=m.user_id,
            category=m.category,
            notification_type=m.notification_type,
            severity=m.severity,
            status=m.status,
            title=m.title,
            message=m.message,
            source_type=m.source_type,
            source_id=m.source_id,
            investigation_id=m.investigation_id,
            analysis_run_id=m.analysis_run_id,
            finding_id=m.finding_id,
            job_id=m.job_id,
            report_id=m.report_id,
            navigation_target=m.navigation_target,
            deduplication_key=m.deduplication_key,
            metadata=meta,
            created_at=m.created_at,
            read_at=m.read_at,
            acknowledged_at=m.acknowledged_at,
            acknowledged_by=m.acknowledged_by,
        )
