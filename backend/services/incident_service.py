"""
Section 50: Incident Management & Case Lifecycle Service.
Orchestrates the operational security case layer above Alerts, Alert Clusters,
Investigations, Response Playbooks, and Reports.
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from fastapi import HTTPException, status
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from backend.db.models import (
    AlertClusterMemberModel,
    AlertClusterModel,
    AnalysisRunModel,
    AuditLogModel,
    EvidenceModel,
    FindingEvidenceModel,
    FindingModel,
    IncidentModel,
    IncidentNoteModel,
    IncidentTimelineEventModel,
    NotificationModel,
    RelationshipModel,
    ResponseRecommendationModel,
    get_utc_now,
)
from backend.schemas.incidents import (
    IncidentAssignRequest,
    IncidentCategoryEnum,
    IncidentCloseRequest,
    IncidentCreateRequest,
    IncidentDetailResponse,
    IncidentItemResponse,
    IncidentMetricsResponse,
    IncidentNextBestActionResponse,
    IncidentNoteCreateRequest,
    IncidentNoteResponse,
    IncidentPriorityEnum,
    IncidentPromoteAlertRequest,
    IncidentPromoteClusterRequest,
    IncidentReopenRequest,
    IncidentResolutionReasonEnum,
    IncidentResolveRequest,
    IncidentSeverityEnum,
    IncidentStatusChangeRequest,
    IncidentStatusEnum,
    IncidentTimelineEventResponse,
    IncidentUpdateRequest,
)
from backend.schemas.realtime import (
    RealtimeEvent,
    RealtimeEventPayload,
    RealtimeEventTypeEnum,
    RealtimeResourceScopeEnum,
)
from backend.services.audit_service import AuditService
from backend.services.notification_service import NotificationService
from backend.services.realtime_service import RealtimePublisher

logger = logging.getLogger("cyberguard.services.incident_service")

# Authoritative State Machine Transitions
VALID_TRANSITIONS: Dict[str, Set[str]] = {
    IncidentStatusEnum.NEW.value: {
        IncidentStatusEnum.OPEN.value,
        IncidentStatusEnum.ACKNOWLEDGED.value,
        IncidentStatusEnum.INVESTIGATING.value,
        IncidentStatusEnum.FALSE_POSITIVE.value,
        IncidentStatusEnum.DUPLICATE.value,
        IncidentStatusEnum.CLOSED.value,
    },
    IncidentStatusEnum.OPEN.value: {
        IncidentStatusEnum.ACKNOWLEDGED.value,
        IncidentStatusEnum.INVESTIGATING.value,
        IncidentStatusEnum.CONTAINED.value,
        IncidentStatusEnum.RESOLVED.value,
        IncidentStatusEnum.FALSE_POSITIVE.value,
        IncidentStatusEnum.DUPLICATE.value,
        IncidentStatusEnum.CLOSED.value,
    },
    IncidentStatusEnum.ACKNOWLEDGED.value: {
        IncidentStatusEnum.INVESTIGATING.value,
        IncidentStatusEnum.CONTAINED.value,
        IncidentStatusEnum.RESOLVED.value,
        IncidentStatusEnum.FALSE_POSITIVE.value,
        IncidentStatusEnum.DUPLICATE.value,
        IncidentStatusEnum.CLOSED.value,
    },
    IncidentStatusEnum.INVESTIGATING.value: {
        IncidentStatusEnum.CONTAINED.value,
        IncidentStatusEnum.RESOLVED.value,
        IncidentStatusEnum.FALSE_POSITIVE.value,
        IncidentStatusEnum.DUPLICATE.value,
        IncidentStatusEnum.OPEN.value,
    },
    IncidentStatusEnum.CONTAINED.value: {
        IncidentStatusEnum.RESOLVED.value,
        IncidentStatusEnum.INVESTIGATING.value,
        IncidentStatusEnum.OPEN.value,
    },
    IncidentStatusEnum.RESOLVED.value: {
        IncidentStatusEnum.CLOSED.value,
        IncidentStatusEnum.INVESTIGATING.value,
        IncidentStatusEnum.OPEN.value,
    },
    IncidentStatusEnum.CLOSED.value: {
        IncidentStatusEnum.OPEN.value,
        IncidentStatusEnum.INVESTIGATING.value,
    },
    IncidentStatusEnum.FALSE_POSITIVE.value: {
        IncidentStatusEnum.OPEN.value,
        IncidentStatusEnum.INVESTIGATING.value,
    },
    IncidentStatusEnum.DUPLICATE.value: {
        IncidentStatusEnum.OPEN.value,
    },
}


class IncidentService:
    """Core domain service for Incident Management and Case Lifecycle."""

    @classmethod
    def generate_incident_number(cls, db: Session) -> str:
        """Readable identifiers remain unique across isolated workspaces and concurrent intake."""
        return f"INC-{datetime.now(timezone.utc).year}-{uuid.uuid4().hex[:12].upper()}"

    @classmethod
    def calculate_priority(
        cls,
        severity: str,
        risk_score: float,
        category: str = "OTHER",
        active_compromise: bool = False,
    ) -> str:
        """
        Determines incident priority (urgency of SOC response) distinctly from severity and risk.
        """
        sev = (severity or "MEDIUM").upper()
        cat = (category or "OTHER").upper()

        if (
            sev == "CRITICAL"
            or risk_score >= 80.0
            or active_compromise
            or cat in ("ACCOUNT_TAKEOVER", "DATA_EXFILTRATION")
        ):
            return IncidentPriorityEnum.P1_CRITICAL.value

        if (
            sev == "HIGH"
            or risk_score >= 60.0
            or cat in ("CREDENTIAL_COMPROMISE", "MALWARE", "NETWORK_INTRUSION", "ENDPOINT_COMPROMISE")
        ):
            return IncidentPriorityEnum.P2_HIGH.value

        if sev == "MEDIUM" or risk_score >= 30.0:
            return IncidentPriorityEnum.P3_MEDIUM.value

        return IncidentPriorityEnum.P4_LOW.value

    @classmethod
    def _broadcast_incident_event(
        cls,
        incident: IncidentModel,
        event_type: str,
        extra: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Emits normalized Section 46 real-time events over SSE."""
        payload = RealtimeEventPayload(
            incident_id=incident.id,
            incident_number=incident.incident_number,
            severity=incident.severity,
            priority=incident.priority,
            title=incident.title,
            risk_contribution=incident.risk_score,
            confidence=incident.confidence,
            extra=extra or {},
        )
        event = RealtimeEvent(
            event_id=f"evt_{uuid.uuid4().hex[:12]}",
            sequence=1,
            event_type=event_type,
            resource_type=RealtimeResourceScopeEnum.INCIDENT.value,
            resource_id=incident.id,
            incident_id=incident.id,
            investigation_id=incident.investigation_id,
            workspace_id=incident.workspace_id,
            status=incident.status,
            message=f"Incident {incident.incident_number}: {incident.title} - {event_type}",
            payload=payload,
        )
        try:
            RealtimePublisher._async_broadcast(event)
        except Exception as exc:
            logger.debug("Real-time broadcast deferred: %s", exc)

    @classmethod
    def create_incident(
        cls,
        db: Session,
        req: IncidentCreateRequest,
        workspace_id: str = "default",
        actor: str = "SYSTEM",
    ) -> IncidentModel:
        """Creates a new incident case with duplicate detection and provenance logging."""
        # 1. Duplicate Prevention Checks
        if req.primary_alert_id:
            existing = (
                db.query(IncidentModel)
                .filter(
                    IncidentModel.workspace_id == workspace_id,
                    IncidentModel.primary_alert_id == req.primary_alert_id,
                    IncidentModel.status.notin_([IncidentStatusEnum.CLOSED.value, IncidentStatusEnum.FALSE_POSITIVE.value]),
                )
                .first()
            )
            if existing:
                return existing

        if req.primary_cluster_id:
            existing = (
                db.query(IncidentModel)
                .filter(
                    IncidentModel.workspace_id == workspace_id,
                    IncidentModel.primary_cluster_id == req.primary_cluster_id,
                    IncidentModel.status.notin_([IncidentStatusEnum.CLOSED.value, IncidentStatusEnum.FALSE_POSITIVE.value]),
                )
                .first()
            )
            if existing:
                return existing

        # 2. Determine Attributes
        inc_num = cls.generate_incident_number(db)
        sev = (req.severity or "MEDIUM").upper()
        cat = (req.category or "OTHER").upper()
        risk = 75.0 if sev == "CRITICAL" else (50.0 if sev == "HIGH" else 25.0)
        priority = req.priority or cls.calculate_priority(sev, risk, cat)

        incident = IncidentModel(
            id=str(uuid.uuid4()),
            incident_number=inc_num,
            workspace_id=workspace_id,
            title=req.title.strip(),
            description=req.description.strip() if req.description else None,
            status=IncidentStatusEnum.OPEN.value,
            severity=sev,
            priority=priority,
            category=cat,
            risk_score=risk,
            confidence=1.0,
            assigned_to=req.assigned_to,
            team_id=req.team_id,
            primary_alert_id=req.primary_alert_id,
            primary_cluster_id=req.primary_cluster_id,
            investigation_id=req.investigation_id,
            created_by=actor,
            opened_at=get_utc_now(),
            created_at=get_utc_now(),
            updated_at=get_utc_now(),
        )
        db.add(incident)
        db.flush()

        # 3. Add Genesis Timeline Event
        cls._add_timeline_event(
            db=db,
            incident_id=incident.id,
            event_type="INCIDENT_CREATED",
            actor=actor,
            source_type="INCIDENT",
            source_id=incident.id,
            summary=f"Incident case {incident.incident_number} created with severity {incident.severity} and priority {incident.priority}.",
        )

        # 4. Link Originating Alert if specified
        if req.primary_alert_id:
            alert = db.query(NotificationModel).filter(NotificationModel.id == req.primary_alert_id).first()
            if alert:
                alert.investigation_id = incident.id
                if alert.status == "OPEN":
                    alert.status = "INVESTIGATING"
                cls._add_timeline_event(
                    db=db,
                    incident_id=incident.id,
                    event_type="ALERT_LINKED",
                    actor=actor,
                    source_type="ALERT",
                    source_id=alert.id,
                    summary=f"Linked primary security alert: {alert.title} ({alert.severity}).",
                )

        # 5. Link Originating Cluster if specified
        if req.primary_cluster_id:
            cluster = db.query(AlertClusterModel).filter(AlertClusterModel.id == req.primary_cluster_id).first()
            if cluster:
                cluster.investigation_id = incident.id
                cluster.status = "INVESTIGATING"
                cls._add_timeline_event(
                    db=db,
                    incident_id=incident.id,
                    event_type="CLUSTER_LINKED",
                    actor=actor,
                    source_type="ALERT_CLUSTER",
                    source_id=cluster.id,
                    summary=f"Linked primary alert cluster: {cluster.cluster_number} ({cluster.title}) containing {cluster.alert_count} alerts.",
                )
                for mem in cluster.members:
                    if mem.alert and not mem.alert.investigation_id:
                        mem.alert.investigation_id = incident.id
                        if mem.alert.status == "OPEN":
                            mem.alert.status = "INVESTIGATING"

        # 6. Add Initial Note if provided
        if req.notes:
            db.add(
                IncidentNoteModel(
                    id=str(uuid.uuid4()),
                    incident_id=incident.id,
                    author=actor,
                    note_text=req.notes.strip(),
                    created_at=get_utc_now(),
                    updated_at=get_utc_now(),
                )
            )

        db.commit()
        db.refresh(incident)

        # 6b. Section 51: Automatic Analyst Routing if explicitly requested
        if getattr(req, "auto_route", False) or req.assigned_to == "AUTO":
            incident.assigned_to = None
            try:
                from backend.services.sla_service import IncidentSLAService
                IncidentSLAService.route_incident(db, incident, workspace_id)
            except Exception as r_err:
                logger.debug("Analyst routing deferred: %s", r_err)

        # 6c. Section 51: SLA Policy Matching & Initial Clock Evaluation
        try:
            from backend.services.sla_service import IncidentSLAService
            IncidentSLAService.evaluate_incident(db, incident.id, workspace_id)
        except Exception as s_err:
            logger.debug("SLA clock evaluation deferred: %s", s_err)

        # 7. Audit & Real-time Broadcast
        AuditService.log_audit(
            db=db,
            action="INCIDENT_CREATED",
            resource_type="incident",
            resource_id=incident.id,
            user=actor,
            details=f"Created incident case {incident.incident_number}: {incident.title}",
        )

        cls._broadcast_incident_event(incident, RealtimeEventTypeEnum.INCIDENT_CREATED.value)

        # 8. Notification to assigned analyst
        if incident.assigned_to and incident.assigned_to != "Unassigned":
            try:
                NotificationService.create_notification(
                    db=db,
                    workspace_id=workspace_id,
                    category="NOTIFICATION",
                    notification_type="INCIDENT_ASSIGNED",
                    severity=incident.severity,
                    title=f"Incident Assigned: {incident.incident_number}",
                    message=f"You have been assigned to incident '{incident.title}' ({incident.priority}).",
                    source_type="INCIDENT",
                    source_id=incident.id,
                    deduplication_key=f"inc_assign_{incident.id}_{incident.assigned_to}_{int(datetime.now(timezone.utc).timestamp())}",
                    navigation_target=f"/incidents/{incident.id}",
                    user_id=incident.assigned_to,
                )
            except Exception as n_err:
                logger.debug("Incident assignment notification deferred: %s", n_err)

        return incident

    @classmethod
    def promote_alert_to_incident(
        cls,
        db: Session,
        req: IncidentPromoteAlertRequest,
        workspace_id: str = "default",
        actor: str = "SOC Analyst",
    ) -> IncidentModel:
        """Promotes an existing security alert directly into an operational Incident case."""
        alert = (
            db.query(NotificationModel)
            .filter(
                NotificationModel.id == req.alert_id,
                NotificationModel.workspace_id == workspace_id,
            )
            .first()
        )
        if not alert:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Security alert {req.alert_id} not found in workspace {workspace_id}.",
            )

        # Duplicate Prevention: Check if alert is already promoted
        existing_inc = (
            db.query(IncidentModel)
            .filter(
                IncidentModel.workspace_id == workspace_id,
                IncidentModel.primary_alert_id == alert.id,
                IncidentModel.status.notin_([IncidentStatusEnum.CLOSED.value, IncidentStatusEnum.FALSE_POSITIVE.value]),
            )
            .first()
        )
        if existing_inc:
            return existing_inc

        # Determine Category
        title_lower = (alert.title or "").lower()
        if "phish" in title_lower or "credential" in title_lower:
            cat = IncidentCategoryEnum.PHISHING.value
        elif "malware" in title_lower or "executable" in title_lower or "ransomware" in title_lower:
            cat = IncidentCategoryEnum.MALWARE.value
        elif "account" in title_lower or "login" in title_lower or "session" in title_lower:
            cat = IncidentCategoryEnum.ACCOUNT_TAKEOVER.value
        elif "exfiltration" in title_lower or "leak" in title_lower:
            cat = IncidentCategoryEnum.DATA_EXFILTRATION.value
        elif "impersonat" in title_lower or "lookalike" in title_lower or "spoof" in title_lower:
            cat = IncidentCategoryEnum.IMPERSONATION.value
        else:
            cat = IncidentCategoryEnum.OTHER.value

        alert_risk = 50.0
        try:
            if alert.metadata_json:
                meta = json.loads(alert.metadata_json)
                if isinstance(meta, dict) and "risk_score" in meta:
                    alert_risk = float(meta["risk_score"])
        except Exception:
            pass

        inc_req = IncidentCreateRequest(
            title=req.title or f"Incident: {alert.title}",
            description=f"Promoted from security alert: {alert.message}",
            severity=req.severity or alert.severity,
            priority=req.priority or cls.calculate_priority(alert.severity, alert_risk, cat),
            category=req.category or cat,
            assigned_to=req.assigned_to or alert.assigned_to,
            primary_alert_id=alert.id,
            investigation_id=alert.investigation_id,
            notes=req.notes,
        )

        incident = cls.create_incident(db, inc_req, workspace_id, actor)

        cls._add_timeline_event(
            db=db,
            incident_id=incident.id,
            event_type="ALERT_PROMOTED",
            actor=actor,
            source_type="ALERT",
            source_id=alert.id,
            summary=f"Security alert {alert.id} successfully promoted to case {incident.incident_number}.",
        )
        db.commit()
        return incident

    @classmethod
    def promote_cluster_to_incident(
        cls,
        db: Session,
        req: IncidentPromoteClusterRequest,
        workspace_id: str = "default",
        actor: str = "SOC Analyst",
    ) -> IncidentModel:
        """Promotes an AlertCluster directly into an authoritative Incident case."""
        cluster = (
            db.query(AlertClusterModel)
            .filter(
                AlertClusterModel.id == req.cluster_id,
                AlertClusterModel.workspace_id == workspace_id,
            )
            .first()
        )
        if not cluster:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Alert cluster {req.cluster_id} not found in workspace {workspace_id}.",
            )

        # Duplicate Prevention: Check if cluster is already tied to an open incident
        existing_inc = (
            db.query(IncidentModel)
            .filter(
                IncidentModel.workspace_id == workspace_id,
                IncidentModel.primary_cluster_id == cluster.id,
                IncidentModel.status.notin_([IncidentStatusEnum.CLOSED.value, IncidentStatusEnum.FALSE_POSITIVE.value]),
            )
            .first()
        )
        if existing_inc:
            return existing_inc

        # Infer category
        title_lower = (cluster.title or "").lower()
        if "phish" in title_lower or "credential" in title_lower:
            cat = IncidentCategoryEnum.PHISHING.value
        elif "malware" in title_lower or "trojan" in title_lower:
            cat = IncidentCategoryEnum.MALWARE.value
        elif "account" in title_lower or "takeover" in title_lower:
            cat = IncidentCategoryEnum.ACCOUNT_TAKEOVER.value
        elif "intrusion" in title_lower or "lateral" in title_lower:
            cat = IncidentCategoryEnum.NETWORK_INTRUSION.value
        else:
            cat = IncidentCategoryEnum.OTHER.value

        priority = req.priority or cls.calculate_priority(cluster.severity, cluster.risk_score, cat)

        inc_req = IncidentCreateRequest(
            title=req.title or cluster.title,
            description=cluster.summary,
            severity=req.severity or cluster.severity,
            priority=priority,
            category=req.category or cat,
            assigned_to=req.assigned_to,
            primary_cluster_id=cluster.id,
            primary_alert_id=cluster.primary_alert_id,
            investigation_id=cluster.investigation_id,
            notes=req.notes,
        )

        incident = cls.create_incident(db, inc_req, workspace_id, actor)

        cls._add_timeline_event(
            db=db,
            incident_id=incident.id,
            event_type="CLUSTER_PROMOTED",
            actor=actor,
            source_type="ALERT_CLUSTER",
            source_id=cluster.id,
            summary=f"Alert cluster {cluster.cluster_number} with {cluster.alert_count} alerts promoted to case {incident.incident_number}.",
        )
        db.commit()
        return incident

    @classmethod
    def transition_status(
        cls,
        db: Session,
        incident_id: str,
        req: IncidentStatusChangeRequest,
        workspace_id: str = "default",
        actor: str = "SOC Analyst",
    ) -> IncidentModel:
        """Enforces server-side state transitions with auditable verification."""
        incident = (
            db.query(IncidentModel)
            .filter(
                IncidentModel.id == incident_id,
                IncidentModel.workspace_id == workspace_id,
            )
            .first()
        )
        if not incident:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Incident {incident_id} not found in workspace {workspace_id}.",
            )

        current_status = incident.status.upper()
        target_status = req.status.upper()

        if target_status not in [s.value for s in IncidentStatusEnum]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unknown target status: {target_status}.",
            )

        # Validate Transition Machine
        allowed = VALID_TRANSITIONS.get(current_status, set())
        if target_status != current_status and target_status not in allowed:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid incident state transition from '{current_status}' to '{target_status}'. Allowed: {sorted(list(allowed))}",
            )

        # Enforce State Requirements
        if target_status == IncidentStatusEnum.RESOLVED.value:
            if not req.resolution_reason:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="A valid resolution_reason is required to mark an incident as RESOLVED.",
                )
            incident.resolution_reason = req.resolution_reason
            incident.resolved_at = get_utc_now()
            incident.resolved_by = actor

        elif target_status == IncidentStatusEnum.FALSE_POSITIVE.value:
            if not req.resolution_reason and not req.reason:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Analyst justification is required to mark an incident as FALSE_POSITIVE.",
                )
            incident.resolution_reason = req.resolution_reason or req.reason
            incident.resolved_at = get_utc_now()
            incident.resolved_by = actor

        elif target_status == IncidentStatusEnum.DUPLICATE.value:
            if not req.duplicate_of_id:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Canonical incident reference (duplicate_of_id) is required for duplicate disposition.",
                )
            canonical = db.query(IncidentModel).filter(IncidentModel.id == req.duplicate_of_id).first()
            if not canonical:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Target canonical incident {req.duplicate_of_id} not found.",
                )
            incident.duplicate_of_id = req.duplicate_of_id
            incident.resolution_reason = "DUPLICATE"
            incident.resolved_at = get_utc_now()
            incident.resolved_by = actor

        elif target_status == IncidentStatusEnum.CONTAINED.value:
            incident.contained_at = get_utc_now()

        elif target_status == IncidentStatusEnum.ACKNOWLEDGED.value:
            incident.acknowledged_at = get_utc_now()

        elif target_status == IncidentStatusEnum.CLOSED.value:
            incident.closed_at = get_utc_now()

        # Handle Reopening
        is_reopening = (
            current_status in (IncidentStatusEnum.CLOSED.value, IncidentStatusEnum.RESOLVED.value, IncidentStatusEnum.FALSE_POSITIVE.value)
            and target_status in (IncidentStatusEnum.OPEN.value, IncidentStatusEnum.INVESTIGATING.value)
        )
        if is_reopening:
            incident.closed_at = None
            incident.resolved_at = None
            incident.resolution_reason = None
            cls._add_timeline_event(
                db=db,
                incident_id=incident.id,
                event_type="INCIDENT_REOPENED",
                actor=actor,
                source_type="INCIDENT",
                source_id=incident.id,
                summary=f"Incident reopened from {current_status} to {target_status}. Reason: {req.reason or 'Case reopened by analyst'}",
            )

        incident.status = target_status
        incident.updated_at = get_utc_now()

        # Record Status Transition Timeline Event
        cls._add_timeline_event(
            db=db,
            incident_id=incident.id,
            event_type="STATUS_CHANGED",
            actor=actor,
            source_type="INCIDENT",
            source_id=incident.id,
            summary=f"Status changed from {current_status} to {target_status}. {req.reason or ''}".strip(),
        )

        if req.notes:
            db.add(
                IncidentNoteModel(
                    id=str(uuid.uuid4()),
                    incident_id=incident.id,
                    author=actor,
                    note_text=req.notes.strip(),
                    created_at=get_utc_now(),
                    updated_at=get_utc_now(),
                )
            )

        db.commit()
        db.refresh(incident)

        AuditService.log_audit(
            db=db,
            action="INCIDENT_STATUS_CHANGED",
            resource_type="incident",
            resource_id=incident.id,
            user=actor,
            details=f"Transitioned {incident.incident_number} from {current_status} to {target_status}.",
        )

        event_name = (
            RealtimeEventTypeEnum.INCIDENT_REOPENED.value
            if is_reopening
            else (
                RealtimeEventTypeEnum.INCIDENT_RESOLVED.value
                if target_status == IncidentStatusEnum.RESOLVED.value
                else (
                    RealtimeEventTypeEnum.INCIDENT_CLOSED.value
                    if target_status == IncidentStatusEnum.CLOSED.value
                    else RealtimeEventTypeEnum.INCIDENT_STATUS_CHANGED.value
                )
            )
        )
        cls._broadcast_incident_event(incident, event_name)

        # Section 51: Re-evaluate operational SLA clocks after state transition
        try:
            from backend.services.sla_service import IncidentSLAService
            IncidentSLAService.evaluate_incident(db, incident.id, workspace_id)
        except Exception as s_err:
            logger.debug("SLA re-evaluation after transition deferred: %s", s_err)

        return incident

    update_status = transition_status

    @classmethod
    def assign_incident(
        cls,
        db: Session,
        incident_id: str,
        req: IncidentAssignRequest,
        workspace_id: str = "default",
        actor: str = "SOC Analyst",
    ) -> IncidentModel:
        """Assigns or reassigns an incident to an analyst and optional team."""
        incident = (
            db.query(IncidentModel)
            .filter(
                IncidentModel.id == incident_id,
                IncidentModel.workspace_id == workspace_id,
            )
            .first()
        )
        if not incident:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Incident {incident_id} not found in workspace {workspace_id}.",
            )

        old_assignee = incident.assigned_to or "Unassigned"
        new_assignee = req.assigned_to or "Unassigned"

        incident.assigned_to = req.assigned_to
        if req.team_id is not None:
            incident.team_id = req.team_id
        incident.updated_at = get_utc_now()

        cls._add_timeline_event(
            db=db,
            incident_id=incident.id,
            event_type="INCIDENT_ASSIGNED",
            actor=actor,
            source_type="INCIDENT",
            source_id=incident.id,
            summary=f"Reassigned from {old_assignee} to {new_assignee}. {req.reason or ''}".strip(),
        )

        db.commit()
        db.refresh(incident)

        AuditService.log_audit(
            db=db,
            action="INCIDENT_ASSIGNED",
            resource_type="incident",
            resource_id=incident.id,
            user=actor,
            details=f"Assigned {incident.incident_number} to {new_assignee}.",
        )

        cls._broadcast_incident_event(incident, RealtimeEventTypeEnum.INCIDENT_ASSIGNED.value)

        # Notify newly assigned analyst
        if req.assigned_to and req.assigned_to != old_assignee:
            try:
                NotificationService.create_notification(
                    db=db,
                    workspace_id=workspace_id,
                    category="NOTIFICATION",
                    notification_type="INCIDENT_ASSIGNED",
                    severity=incident.severity,
                    title=f"Incident Assigned: {incident.incident_number}",
                    message=f"You have been assigned to incident '{incident.title}' by {actor}.",
                    source_type="INCIDENT",
                    source_id=incident.id,
                    deduplication_key=f"inc_reassign_{incident.id}_{incident.assigned_to}_{int(datetime.now(timezone.utc).timestamp())}",
                    navigation_target=f"/incidents/{incident.id}",
                    user_id=incident.assigned_to,
                )
            except Exception as n_err:
                logger.debug("Notification deferred: %s", n_err)

        # Section 51: Re-evaluate SLA clocks after assignment change
        try:
            from backend.services.sla_service import IncidentSLAService
            IncidentSLAService.evaluate_incident(db, incident.id, workspace_id)
        except Exception as s_err:
            logger.debug("SLA re-evaluation after assignment deferred: %s", s_err)

        return incident

    @classmethod
    def update_incident(
        cls,
        db: Session,
        incident_id: str,
        req: IncidentUpdateRequest,
        workspace_id: str = "default",
        actor: str = "SOC Analyst",
    ) -> IncidentModel:
        """Updates mutable metadata (title, description, priority, category)."""
        incident = (
            db.query(IncidentModel)
            .filter(
                IncidentModel.id == incident_id,
                IncidentModel.workspace_id == workspace_id,
            )
            .first()
        )
        if not incident:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Incident {incident_id} not found in workspace {workspace_id}.",
            )

        changes = []
        if req.title and req.title.strip() != incident.title:
            changes.append(f"Title updated")
            incident.title = req.title.strip()

        if req.description is not None and req.description.strip() != incident.description:
            changes.append(f"Description updated")
            incident.description = req.description.strip()

        if req.priority and req.priority != incident.priority:
            changes.append(f"Priority changed from {incident.priority} to {req.priority}")
            incident.priority = req.priority

        if req.category and req.category != incident.category:
            changes.append(f"Category changed from {incident.category} to {req.category}")
            incident.category = req.category

        if req.team_id is not None:
            incident.team_id = req.team_id

        if changes:
            incident.updated_at = get_utc_now()
            cls._add_timeline_event(
                db=db,
                incident_id=incident.id,
                event_type="INCIDENT_UPDATED",
                actor=actor,
                source_type="INCIDENT",
                source_id=incident.id,
                summary="; ".join(changes),
            )
            db.commit()
            db.refresh(incident)

            AuditService.log_audit(
                db=db,
                action="INCIDENT_UPDATED",
                resource_type="incident",
                resource_id=incident.id,
                user=actor,
                details=f"Updated {incident.incident_number}: {'; '.join(changes)}",
            )
            cls._broadcast_incident_event(incident, RealtimeEventTypeEnum.INCIDENT_UPDATED.value)

        return incident

    @classmethod
    def add_note(
        cls,
        db: Session,
        incident_id: str,
        req: IncidentNoteCreateRequest,
        workspace_id: str = "default",
        actor: str = "SOC Analyst",
    ) -> IncidentNoteModel:
        """Appends an analyst case note to the incident."""
        incident = (
            db.query(IncidentModel)
            .filter(
                IncidentModel.id == incident_id,
                IncidentModel.workspace_id == workspace_id,
            )
            .first()
        )
        if not incident:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Incident {incident_id} not found in workspace {workspace_id}.",
            )

        note = IncidentNoteModel(
            id=str(uuid.uuid4()),
            incident_id=incident.id,
            author=req.author or actor,
            note_text=req.note_text.strip(),
            created_at=get_utc_now(),
            updated_at=get_utc_now(),
        )
        db.add(note)

        cls._add_timeline_event(
            db=db,
            incident_id=incident.id,
            event_type="NOTE_ADDED",
            actor=note.author,
            source_type="INCIDENT_NOTE",
            source_id=note.id,
            summary=f"Analyst note added: {note.note_text[:80]}...",
        )

        incident.updated_at = get_utc_now()
        db.commit()
        db.refresh(note)

        AuditService.log_audit(
            db=db,
            action="INCIDENT_NOTE_ADDED",
            resource_type="incident",
            resource_id=incident.id,
            user=actor,
            details=f"Added case note to {incident.incident_number}.",
        )

        return note

    @classmethod
    def get_incident_detail(
        cls,
        db: Session,
        incident_id: str,
        workspace_id: str = "default",
    ) -> IncidentDetailResponse:
        """Retrieves complete forensic facts, related alerts, clusters, and next best action."""
        incident = (
            db.query(IncidentModel)
            .filter(
                (IncidentModel.id == incident_id) | (IncidentModel.incident_number == incident_id),
                IncidentModel.workspace_id == workspace_id,
            )
            .first()
        )
        if not incident:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Incident {incident_id} not found in workspace {workspace_id}.",
            )

        # 1. Resolve Related Alerts
        alerts_query = (
            db.query(NotificationModel)
            .filter(
                NotificationModel.workspace_id == workspace_id,
                NotificationModel.category == "SECURITY_ALERT",
                or_(
                    NotificationModel.investigation_id == incident.id,
                    NotificationModel.id == incident.primary_alert_id,
                ),
            )
        )
        related_alerts_raw = alerts_query.all()

        # If incident has a primary cluster, also gather member alerts
        if incident.primary_cluster_id:
            cluster = db.query(AlertClusterModel).filter(AlertClusterModel.id == incident.primary_cluster_id).first()
            if cluster:
                for m in cluster.members:
                    if m.alert and m.alert not in related_alerts_raw:
                        related_alerts_raw.append(m.alert)

        related_alerts = [
            {
                "id": a.id,
                "title": a.title,
                "message": a.message,
                "severity": a.severity,
                "status": a.status,
                "risk_score": a.risk_score,
                "created_at": a.created_at.isoformat() if a.created_at else None,
            }
            for a in related_alerts_raw
        ]

        # 2. Resolve Related Clusters
        clusters_query = (
            db.query(AlertClusterModel)
            .filter(
                AlertClusterModel.workspace_id == workspace_id,
                or_(
                    AlertClusterModel.investigation_id == incident.id,
                    AlertClusterModel.id == incident.primary_cluster_id,
                ),
            )
        )
        related_clusters_raw = clusters_query.all()
        related_clusters = [
            {
                "id": c.id,
                "cluster_number": c.cluster_number,
                "title": c.title,
                "summary": c.summary,
                "severity": c.severity,
                "status": c.status,
                "alert_count": c.alert_count,
                "risk_score": c.risk_score,
                "confidence": c.confidence,
            }
            for c in related_clusters_raw
        ]

        # 3. Affected Entities Aggregation
        users: Set[str] = set()
        domains: Set[str] = set()
        ips: Set[str] = set()
        endpoints: Set[str] = set()
        hashes: Set[str] = set()

        for a in related_alerts_raw:
            meta = {}
            if a.metadata_json:
                try:
                    meta = json.loads(a.metadata_json)
                except Exception:
                    pass
            if a.assigned_to:
                users.add(a.assigned_to)
            for k in ("domain", "sender_domain", "target_domain"):
                if meta.get(k):
                    domains.add(meta[k])
            for k in ("ip", "client_ip", "source_ip", "destination_ip"):
                if meta.get(k):
                    ips.add(meta[k])
            for k in ("endpoint_id", "hostname", "device_id"):
                if meta.get(k):
                    endpoints.add(meta[k])
            for k in ("sha256", "file_hash", "hash"):
                if meta.get(k):
                    hashes.add(meta[k])

        affected_entities = {
            "users": sorted(list(users)),
            "domains": sorted(list(domains)),
            "ips": sorted(list(ips)),
            "endpoints": sorted(list(endpoints)),
            "hashes": sorted(list(hashes)),
        }

        # 4. Next Best Action (Derived from existing Response Recommendations)
        next_action = None
        top_rec = (
            db.query(ResponseRecommendationModel)
            .filter(
                or_(
                    ResponseRecommendationModel.incident_id == incident.id,
                    ResponseRecommendationModel.scope_id == incident.id,
                )
            )
            .order_by(ResponseRecommendationModel.confidence.desc())
            .first()
        )
        if top_rec:
            next_action = IncidentNextBestActionResponse(
                recommendation_id=top_rec.id,
                action_type=top_rec.action_type,
                title=top_rec.title,
                description=top_rec.description,
                priority=top_rec.priority,
                confidence=top_rec.confidence,
                target_entity=top_rec.target_entity,
            )
        else:
            # Fallback deterministic recommendation based on category
            if incident.category == "PHISHING":
                next_action = IncidentNextBestActionResponse(
                    action_type="BLOCK_DOMAIN",
                    title="Block Phishing Infrastructure",
                    description="Prevent further user interaction by blocking reported lookalike domains and email senders.",
                    priority="HIGH",
                    confidence=0.90,
                )
            elif incident.category in ("MALWARE", "ENDPOINT_COMPROMISE"):
                next_action = IncidentNextBestActionResponse(
                    action_type="ISOLATE_ENDPOINT",
                    title="Isolate Compromised Host",
                    description="Quarantine affected host endpoint from corporate subnet to stop lateral movement.",
                    priority="CRITICAL",
                    confidence=0.95,
                )
            elif incident.category == "ACCOUNT_TAKEOVER":
                next_action = IncidentNextBestActionResponse(
                    action_type="REVOKE_SESSIONS",
                    title="Revoke Active Sessions & Reset Credentials",
                    description="Force sign-out across all active OAuth tokens and trigger credential reset.",
                    priority="HIGH",
                    confidence=0.92,
                )

        # 5. Timeline Events & Notes
        timeline_events = [
            IncidentTimelineEventResponse(
                id=evt.id,
                event_type=evt.event_type,
                timestamp=evt.timestamp,
                actor=evt.actor,
                source_type=evt.source_type,
                source_id=evt.source_id,
                summary=evt.summary,
                metadata=json.loads(evt.metadata_json or "{}"),
            )
            for evt in incident.timeline_events
        ]

        notes = [
            IncidentNoteResponse(
                id=n.id,
                author=n.author,
                note_text=n.note_text,
                created_at=n.created_at,
                updated_at=n.updated_at,
            )
            for n in incident.notes
        ]

        return IncidentDetailResponse(
            id=incident.id,
            incident_number=incident.incident_number,
            workspace_id=incident.workspace_id,
            title=incident.title,
            description=incident.description,
            status=incident.status,
            severity=incident.severity,
            priority=incident.priority,
            category=incident.category,
            risk_score=incident.risk_score,
            confidence=incident.confidence,
            assigned_to=incident.assigned_to,
            team_id=incident.team_id,
            primary_alert_id=incident.primary_alert_id,
            primary_cluster_id=incident.primary_cluster_id,
            investigation_id=incident.investigation_id,
            report_id=incident.report_id,
            created_by=incident.created_by,
            resolved_by=incident.resolved_by,
            resolution_reason=incident.resolution_reason,
            duplicate_of_id=incident.duplicate_of_id,
            first_seen_at=incident.first_seen_at,
            last_seen_at=incident.last_seen_at,
            opened_at=incident.opened_at,
            acknowledged_at=incident.acknowledged_at,
            contained_at=incident.contained_at,
            resolved_at=incident.resolved_at,
            closed_at=incident.closed_at,
            created_at=incident.created_at,
            updated_at=incident.updated_at,
            escalation_level=incident.escalation_level or 0,
            sla_status=incident.sla_status or "HEALTHY",
            next_sla_deadline=incident.next_sla_deadline,
            alert_count=len(related_alerts),
            cluster_count=len(related_clusters),
            findings_count=db.query(FindingModel).count(),
            evidence_count=db.query(EvidenceModel).count(),
            related_alerts=related_alerts,
            related_clusters=related_clusters,
            affected_entities=affected_entities,
            next_best_action=next_action,
            timeline_events=timeline_events,
            notes=notes,
        )

    @classmethod
    def list_incidents(
        cls,
        db: Session,
        workspace_id: str = "default",
        status: Optional[str] = None,
        severity: Optional[str] = None,
        priority: Optional[str] = None,
        category: Optional[str] = None,
        assigned_to: Optional[str] = None,
        sla_status: Optional[str] = None,
        q: Optional[str] = None,
        sort_by: str = "severity_first",
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[IncidentItemResponse], int]:
        """Server-side filtering, sorting, and pagination for the Incident Queue with SLA support."""
        query = db.query(IncidentModel).filter(IncidentModel.workspace_id == workspace_id)

        if status and status.upper() != "ALL":
            query = query.filter(IncidentModel.status == status.upper())

        if severity and severity.upper() != "ALL":
            query = query.filter(IncidentModel.severity == severity.upper())

        if priority and priority.upper() != "ALL":
            query = query.filter(IncidentModel.priority == priority.upper())

        if category and category.upper() != "ALL":
            query = query.filter(IncidentModel.category == category.upper())

        if sla_status and sla_status.upper() != "ALL":
            query = query.filter(IncidentModel.sla_status == sla_status.upper())

        if assigned_to:
            if assigned_to == "UNASSIGNED":
                query = query.filter(or_(IncidentModel.assigned_to.is_(None), IncidentModel.assigned_to == ""))
            else:
                query = query.filter(IncidentModel.assigned_to == assigned_to)

        if q and q.strip():
            term = f"%{q.strip()}%"
            query = query.filter(
                or_(
                    IncidentModel.incident_number.ilike(term),
                    IncidentModel.title.ilike(term),
                    IncidentModel.description.ilike(term),
                    IncidentModel.assigned_to.ilike(term),
                )
            )

        total = query.count()

        # Sorting
        if sort_by == "priority_first":
            query = query.order_by(
                IncidentModel.priority.asc(),
                IncidentModel.created_at.desc(),
            )
        elif sort_by == "newest":
            query = query.order_by(IncidentModel.created_at.desc())
        elif sort_by == "risk_desc":
            query = query.order_by(IncidentModel.risk_score.desc())
        elif sort_by == "closest_deadline":
            query = query.order_by(
                IncidentModel.next_sla_deadline.asc().nulls_last(),
                IncidentModel.created_at.desc(),
            )
        elif sort_by == "sla_breach_first":
            query = query.order_by(
                IncidentModel.sla_status.desc(),
                IncidentModel.created_at.desc(),
            )
        else:
            # Default: severity & recency
            query = query.order_by(
                IncidentModel.severity.desc(),
                IncidentModel.created_at.desc(),
            )

        records = query.offset(offset).limit(limit).all()
        now = datetime.now(timezone.utc)

        items = []
        for r in records:
            dl = r.next_sla_deadline
            time_rem = None
            is_overdue = False
            if dl:
                if dl.tzinfo is None:
                    dl = dl.replace(tzinfo=timezone.utc)
                diff_sec = (dl - now).total_seconds()
                time_rem = round(max(0.0, diff_sec / 60.0), 1)
                is_overdue = (diff_sec < 0 and r.status in ("NEW", "OPEN", "ACKNOWLEDGED", "INVESTIGATING"))

            items.append(
                IncidentItemResponse(
                    id=r.id,
                    incident_number=r.incident_number,
                    title=r.title,
                    description=r.description,
                    status=r.status,
                    severity=r.severity,
                    priority=r.priority,
                    category=r.category,
                    risk_score=r.risk_score,
                    confidence=r.confidence,
                    assigned_to=r.assigned_to,
                    team_id=r.team_id,
                    primary_alert_id=r.primary_alert_id,
                    primary_cluster_id=r.primary_cluster_id,
                    investigation_id=r.investigation_id,
                    report_id=r.report_id,
                    created_by=r.created_by,
                    resolution_reason=r.resolution_reason,
                    duplicate_of_id=r.duplicate_of_id,
                    first_seen_at=r.first_seen_at,
                    last_seen_at=r.last_seen_at,
                    opened_at=r.opened_at,
                    acknowledged_at=r.acknowledged_at,
                    contained_at=r.contained_at,
                    resolved_at=r.resolved_at,
                    closed_at=r.closed_at,
                    created_at=r.created_at,
                    updated_at=r.updated_at,
                    alert_count=1 if r.primary_alert_id else 0,
                    cluster_count=1 if r.primary_cluster_id else 0,
                    escalation_level=r.escalation_level or 0,
                    sla_status=r.sla_status or "HEALTHY",
                    next_sla_deadline=r.next_sla_deadline,
                    time_remaining_mins=time_rem,
                    is_overdue=is_overdue,
                )
            )

        return items, total

    @classmethod
    def get_metrics(cls, db: Session, workspace_id: str = "default") -> IncidentMetricsResponse:
        """Calculates real operational metrics for the Incident dashboard including SLA metrics."""
        all_incidents = db.query(IncidentModel).filter(IncidentModel.workspace_id == workspace_id).all()

        total = len(all_incidents)
        open_count = sum(1 for i in all_incidents if i.status in ("NEW", "OPEN"))
        critical_count = sum(1 for i in all_incidents if i.severity == "CRITICAL")
        unassigned_count = sum(1 for i in all_incidents if not i.assigned_to or i.assigned_to == "Unassigned")
        investigating_count = sum(1 for i in all_incidents if i.status == "INVESTIGATING")
        contained_count = sum(1 for i in all_incidents if i.status == "CONTAINED")
        resolved_count = sum(1 for i in all_incidents if i.status == "RESOLVED")
        closed_count = sum(1 for i in all_incidents if i.status == "CLOSED")

        # Section 51 SLA Operational Metrics
        sla_breaches = sum(
            1 for i in all_incidents
            if i.sla_status == "BREACHED" and i.status in ("NEW", "OPEN", "ACKNOWLEDGED", "INVESTIGATING")
        )
        approaching_sla = sum(
            1 for i in all_incidents
            if i.sla_status == "WARNING" and i.status in ("NEW", "OPEN", "ACKNOWLEDGED", "INVESTIGATING")
        )
        unack_critical = sum(
            1 for i in all_incidents
            if i.severity == "CRITICAL" and not i.acknowledged_at and i.status in ("NEW", "OPEN")
        )
        escalated_inc = sum(
            1 for i in all_incidents
            if (i.escalation_level or 0) > 0 and i.status in ("NEW", "OPEN", "ACKNOWLEDGED", "INVESTIGATING")
        )
        unassigned_crit = sum(
            1 for i in all_incidents
            if i.severity == "CRITICAL" and (not i.assigned_to or i.assigned_to == "Unassigned") and i.status in ("NEW", "OPEN", "ACKNOWLEDGED", "INVESTIGATING")
        )

        by_cat: Dict[str, int] = {}
        by_sev: Dict[str, int] = {}
        by_pri: Dict[str, int] = {}

        ack_times: List[float] = []
        contain_times: List[float] = []
        resolve_times: List[float] = []

        for i in all_incidents:
            by_cat[i.category] = by_cat.get(i.category, 0) + 1
            by_sev[i.severity] = by_sev.get(i.severity, 0) + 1
            by_pri[i.priority] = by_pri.get(i.priority, 0) + 1

            if i.acknowledged_at and i.opened_at:
                diff = (i.acknowledged_at - i.opened_at).total_seconds()
                if diff >= 0:
                    ack_times.append(diff)
            if i.contained_at and i.opened_at:
                diff = (i.contained_at - i.opened_at).total_seconds()
                if diff >= 0:
                    contain_times.append(diff)
            if i.resolved_at and i.opened_at:
                diff = (i.resolved_at - i.opened_at).total_seconds()
                if diff >= 0:
                    resolve_times.append(diff)

        avg_ack = sum(ack_times) / len(ack_times) if ack_times else None
        avg_contain = sum(contain_times) / len(contain_times) if contain_times else None
        avg_resolve = sum(resolve_times) / len(resolve_times) if resolve_times else None

        return IncidentMetricsResponse(
            total_incidents=total,
            open_incidents=open_count,
            critical_incidents=critical_count,
            unassigned_incidents=unassigned_count,
            investigating_incidents=investigating_count,
            contained_incidents=contained_count,
            resolved_incidents=resolved_count,
            closed_incidents=closed_count,
            avg_time_to_acknowledge_sec=avg_ack,
            avg_time_to_contain_sec=avg_contain,
            avg_time_to_resolve_sec=avg_resolve,
            sla_breaches=sla_breaches,
            approaching_sla=approaching_sla,
            unacknowledged_critical=unack_critical,
            escalated_incidents=escalated_inc,
            unassigned_critical=unassigned_crit,
            by_category=by_cat,
            by_severity=by_sev,
            by_priority=by_pri,
        )

    @classmethod
    def _add_timeline_event(
        cls,
        db: Session,
        incident_id: str,
        event_type: str,
        actor: str,
        source_type: str,
        source_id: Optional[str],
        summary: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> IncidentTimelineEventModel:
        """Appends a factual event to the incident timeline."""
        evt = IncidentTimelineEventModel(
            id=str(uuid.uuid4()),
            incident_id=incident_id,
            event_type=event_type,
            timestamp=get_utc_now(),
            actor=actor or "SYSTEM",
            source_type=source_type,
            source_id=source_id,
            summary=summary,
            metadata_json=json.dumps(metadata or {}),
        )
        db.add(evt)
        return evt
