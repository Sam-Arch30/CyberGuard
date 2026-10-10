"""
Section 51: Incident SLA, Escalation & Analyst Workflow Automation Service.
Authoritative domain service for:
- Configurable SLA Policy retrieval and matching
- Server-side operational clock calculation from real timestamps
- Idempotent warning and breach detection
- Escalation chain execution with loop cooldown and idempotency enforcement
- Intelligent analyst routing (Least-Loaded, Round-Robin, Direct)
- SLA Pause, Resume, and Exemption forensic tracking
- Safe workflow automation boundary
- Policy simulation dry-runs
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple, Union

from fastapi import HTTPException, status
from sqlalchemy import func, or_, desc, and_
from sqlalchemy.orm import Session

from backend.db.models import (
    IncidentModel,
    IncidentSLAStateModel,
    IncidentSLAPolicyModel,
    IncidentEscalationPolicyModel,
    IncidentEscalationRuleModel,
    IncidentRoutingRuleModel,
    IncidentWorkflowExecutionModel,
    IncidentSLAPauseLogModel,
    IncidentTimelineEventModel,
    IncidentNoteModel,
    NotificationModel,
    get_utc_now,
)
from backend.schemas.incidents import (
    IncidentPriorityEnum,
    IncidentSeverityEnum,
    IncidentStatusEnum,
)
from backend.schemas.notification import (
    NotificationCategoryEnum,
    NotificationSeverityEnum,
    NotificationTypeEnum,
)
from backend.schemas.realtime import (
    RealtimeEvent,
    RealtimeEventPayload,
    RealtimeEventTypeEnum,
    RealtimeResourceScopeEnum,
)
from backend.schemas.sla import (
    EscalationActionTypeEnum,
    EscalationConditionEnum,
    IncidentEscalateRequest,
    IncidentSLADetailResponse,
    PolicySimulationRequest,
    PolicySimulationResponse,
    RoutingStrategyEnum,
    SLAExemptRequest,
    SLAMilestoneDetail,
    SLAMilestoneEnum,
    SLAMilestoneStatusEnum,
    SLAOverallStatusEnum,
    SLAPauseRequest,
    SLAPolicyCreateRequest,
    SLAPolicyResponse,
    SLAPolicyUpdateRequest,
    SLAResumeRequest,
    WorkflowExecutionItemResponse,
    WorkflowHistoryResponse,
)
from backend.services.audit_service import AuditService
from backend.services.notification_service import NotificationService
from backend.services.realtime_service import RealtimePublisher

logger = logging.getLogger("cyberguard.services.sla")


class IncidentSLAService:
    """Production-grade SLA, Escalation and Routing Automation Service."""

    # =========================================================================
    # 1. DEFAULT SEEDING & POLICY RETRIEVAL
    # =========================================================================

    @classmethod
    def _emit_realtime(
        cls,
        workspace_id: str,
        incident_id: str,
        event_type: str,
        message: str,
        payload_data: Any,
        status: Optional[str] = None,
    ) -> None:
        """Publishes non-blocking realtime event to workspace subscribers safely."""
        try:
            event = RealtimeEvent(
                event_id=f"evt_{uuid.uuid4().hex[:12]}",
                sequence=1,
                event_type=event_type,
                resource_type=RealtimeResourceScopeEnum.INCIDENT.value,
                resource_id=incident_id,
                incident_id=incident_id,
                workspace_id=workspace_id,
                status=status,
                message=message,
                payload=payload_data if isinstance(payload_data, dict) else (payload_data.model_dump() if hasattr(payload_data, "model_dump") else {}),
            )
            RealtimePublisher.publish_to_workspace(workspace_id=workspace_id, event=event)
        except Exception as e:
            logger.debug("SLA realtime broadcast deferred: %s", e)

    @classmethod
    def ensure_default_policies(cls, db: Session, workspace_id: str = "default") -> None:
        """
        Seeds baseline production SLA policies, escalation policies, and routing rules
        if none exist for the workspace.
        """
        existing_sla = (
            db.query(IncidentSLAPolicyModel)
            .filter(IncidentSLAPolicyModel.workspace_id == workspace_id)
            .first()
        )
        if not existing_sla:
            # 1. Create Default Escalation Policy
            esc_policy = IncidentEscalationPolicyModel(
                id=str(uuid.uuid4()),
                workspace_id=workspace_id,
                name="Standard Multi-Tier SOC Escalation Chain",
                description="3-tier escalation chain for unacknowledged or uncontained incidents.",
                cooldown_minutes=15,
                max_escalation_level=3,
                status="ACTIVE",
                version=1,
                created_by="SYSTEM",
            )
            db.add(esc_policy)
            db.flush()

            # Rules for Escalation Policy
            rule_1 = IncidentEscalationRuleModel(
                id=str(uuid.uuid4()),
                policy_id=esc_policy.id,
                level=1,
                condition_type=EscalationConditionEnum.SLA_WARNING.value,
                milestone=SLAMilestoneEnum.ACKNOWLEDGEMENT.value,
                action_type=EscalationActionTypeEnum.NOTIFY_OWNER.value,
                target_role="Analyst",
                note_template="Approaching acknowledgement deadline (80% target consumed).",
            )
            rule_2 = IncidentEscalationRuleModel(
                id=str(uuid.uuid4()),
                policy_id=esc_policy.id,
                level=2,
                condition_type=EscalationConditionEnum.SLA_BREACH.value,
                milestone=SLAMilestoneEnum.ACKNOWLEDGEMENT.value,
                action_type=EscalationActionTypeEnum.ASSIGN_TO_USER.value,
                target_role="SOC Lead",
                target_user="Jordan Lee (SOC Lead)",
                target_team="Tier-2 SOC",
                escalate_priority_to=IncidentPriorityEnum.P1_CRITICAL.value,
                note_template="Acknowledgement SLA breached! Auto-escalated to SOC Lead.",
            )
            rule_3 = IncidentEscalationRuleModel(
                id=str(uuid.uuid4()),
                policy_id=esc_policy.id,
                level=3,
                condition_type=EscalationConditionEnum.SLA_BREACH.value,
                milestone=SLAMilestoneEnum.CONTAINMENT.value,
                action_type=EscalationActionTypeEnum.ASSIGN_TO_USER.value,
                target_role="Security Manager",
                target_user="Morgan Vance (Security Manager)",
                target_team="Incident Command",
                escalate_priority_to=IncidentPriorityEnum.P1_CRITICAL.value,
                note_template="Containment target breached! Escalated to Security Manager.",
            )
            db.add_all([rule_1, rule_2, rule_3])

            # 2. Create Tiered SLA Policies
            p_crit = IncidentSLAPolicyModel(
                id=str(uuid.uuid4()),
                workspace_id=workspace_id,
                name="Critical Incident SLA Policy",
                description="Aggressive response targets for CRITICAL severity or P1 incidents.",
                severity=IncidentSeverityEnum.CRITICAL.value,
                priority="ANY",
                category="ANY",
                acknowledgement_target_minutes=15,
                investigation_target_minutes=30,
                containment_target_minutes=60,
                resolution_target_minutes=240,
                warning_threshold_pct=80.0,
                escalation_policy_id=esc_policy.id,
                is_default=False,
                status="ACTIVE",
                version=1,
            )
            p_high = IncidentSLAPolicyModel(
                id=str(uuid.uuid4()),
                workspace_id=workspace_id,
                name="High Severity SLA Policy",
                description="Prioritized targets for HIGH severity or P2 incidents.",
                severity=IncidentSeverityEnum.HIGH.value,
                priority="ANY",
                category="ANY",
                acknowledgement_target_minutes=30,
                investigation_target_minutes=60,
                containment_target_minutes=120,
                resolution_target_minutes=480,
                warning_threshold_pct=80.0,
                escalation_policy_id=esc_policy.id,
                is_default=False,
                status="ACTIVE",
                version=1,
            )
            p_med = IncidentSLAPolicyModel(
                id=str(uuid.uuid4()),
                workspace_id=workspace_id,
                name="Medium Severity SLA Policy",
                description="Standard response targets for MEDIUM severity incidents.",
                severity=IncidentSeverityEnum.MEDIUM.value,
                priority="ANY",
                category="ANY",
                acknowledgement_target_minutes=60,
                investigation_target_minutes=180,
                containment_target_minutes=480,
                resolution_target_minutes=1440,
                warning_threshold_pct=80.0,
                escalation_policy_id=esc_policy.id,
                is_default=False,
                status="ACTIVE",
                version=1,
            )
            p_def = IncidentSLAPolicyModel(
                id=str(uuid.uuid4()),
                workspace_id=workspace_id,
                name="Default General SLA Policy",
                description="Catch-all SLA policy for unclassified or low-severity cases.",
                severity="ANY",
                priority="ANY",
                category="ANY",
                acknowledgement_target_minutes=120,
                investigation_target_minutes=240,
                containment_target_minutes=720,
                resolution_target_minutes=2880,
                warning_threshold_pct=80.0,
                escalation_policy_id=esc_policy.id,
                is_default=True,
                status="ACTIVE",
                version=1,
            )
            db.add_all([p_crit, p_high, p_med, p_def])

            # 3. Create Default Routing Rules
            r_ident = IncidentRoutingRuleModel(
                id=str(uuid.uuid4()),
                workspace_id=workspace_id,
                name="Identity & Credential Compromise Routing",
                description="Directs credential harvesting and account takeovers to Identity Security specialists.",
                priority_order=10,
                category="CREDENTIAL_COMPROMISE",
                severity="ANY",
                min_risk_score=50.0,
                routing_strategy=RoutingStrategyEnum.LEAST_LOADED.value,
                target_team_id="Identity Security",
                candidate_analysts_json=json.dumps(["Alex Rivera", "Taylor Morgan"]),
                enabled=True,
            )
            r_phish = IncidentRoutingRuleModel(
                id=str(uuid.uuid4()),
                workspace_id=workspace_id,
                name="High Risk Phishing Triage Routing",
                description="Distributes high-severity phishing incidents among frontline SOC analysts.",
                priority_order=20,
                category="PHISHING",
                severity=IncidentSeverityEnum.HIGH.value,
                min_risk_score=60.0,
                routing_strategy=RoutingStrategyEnum.ROUND_ROBIN.value,
                target_team_id="Tier-1 SOC",
                candidate_analysts_json=json.dumps(["Alex Rivera", "Jordan Lee", "Casey Smith"]),
                enabled=True,
            )
            r_crit = IncidentRoutingRuleModel(
                id=str(uuid.uuid4()),
                workspace_id=workspace_id,
                name="Critical Escalation Lead Routing",
                description="Routes all critical severity incidents immediately to Tier-2 SOC leads.",
                priority_order=5,
                category="ANY",
                severity=IncidentSeverityEnum.CRITICAL.value,
                min_risk_score=75.0,
                routing_strategy=RoutingStrategyEnum.LEAST_LOADED.value,
                target_team_id="Tier-2 SOC",
                candidate_analysts_json=json.dumps(["Jordan Lee (SOC Lead)", "Morgan Vance (Security Manager)"]),
                enabled=True,
            )
            r_frontline = IncidentRoutingRuleModel(
                id=str(uuid.uuid4()),
                workspace_id=workspace_id,
                name="Frontline SOC Triage Routing",
                description="Default routing for unclassified or general incident triage.",
                priority_order=100,
                category="ANY",
                severity="ANY",
                min_risk_score=0.0,
                routing_strategy=RoutingStrategyEnum.LEAST_LOADED.value,
                target_team_id="Frontline SOC",
                candidate_analysts_json=json.dumps(["Alex Rivera", "Taylor Morgan", "Casey Smith", "Mike Davies"]),
                enabled=True,
            )
            db.add_all([r_ident, r_phish, r_crit, r_frontline])

            db.commit()
            logger.info("Seeded default SLA policies, escalation rules, and routing rules for workspace=%s", workspace_id)

    @classmethod
    def seed_default_policies(cls, db: Session, workspace_id: str = "default") -> None:
        """Alias for ensure_default_policies."""
        cls.ensure_default_policies(db, workspace_id)

    @classmethod
    def match_policy(
        cls,
        db: Session,
        workspace_id: str = "default",
        severity: str = "ANY",
        priority: str = "ANY",
        category: str = "ANY",
    ) -> IncidentSLAPolicyModel:
        """
        Matches the most specific active SLA policy matching criteria.
        Falls back to default policy.
        """
        cls.ensure_default_policies(db, workspace_id)

        policies = (
            db.query(IncidentSLAPolicyModel)
            .filter(
                IncidentSLAPolicyModel.workspace_id == workspace_id,
                IncidentSLAPolicyModel.status == "ACTIVE",
            )
            .all()
        )

        for p in policies:
            if (
                p.severity == severity
                and p.priority == priority
                and p.category == category
            ):
                return p

        for p in policies:
            if (
                p.severity == severity
                and p.category == category
                and p.priority == "ANY"
            ):
                return p

        for p in policies:
            if (
                p.severity == severity
                and p.priority == "ANY"
                and p.category == "ANY"
            ):
                return p

        for p in policies:
            if p.is_default:
                return p

        if policies:
            return policies[0]

        return IncidentSLAPolicyModel(
            id="fallback",
            workspace_id=workspace_id,
            name="Fallback In-Memory Policy",
            acknowledgement_target_minutes=30,
            investigation_target_minutes=60,
            containment_target_minutes=120,
            resolution_target_minutes=480,
            warning_threshold_pct=80.0,
            version=1,
        )

    @classmethod
    def match_sla_policy(
        cls,
        db: Session,
        incident: IncidentModel,
        workspace_id: Optional[str] = None,
    ) -> IncidentSLAPolicyModel:
        """
        Determines the most specific active SLA policy matching the incident's
        severity, priority, and category. Falls back to default.
        """
        ws = workspace_id or incident.workspace_id or "default"
        return cls.match_policy(
            db=db,
            workspace_id=ws,
            severity=incident.severity,
            priority=incident.priority,
            category=incident.category,
        )

    # =========================================================================
    # 2. OPERATIONAL SLA CLOCKS & EVALUATION
    # =========================================================================

    @classmethod
    def _evaluate_incident_state(
        cls,
        db: Session,
        incident_id: str,
        workspace_id: str = "default",
        force_now: Optional[datetime] = None,
    ) -> IncidentSLAStateModel:
        """
        Evaluates operational SLA clocks for a specific incident against its matched policy.
        Calculates:
        - Time to Acknowledge
        - Time to Investigation
        - Time to Containment
        - Time to Resolution
        Detects warnings (e.g. 80%) and deterministic breaches (100%).
        Triggers notifications, realtime events, and escalation rules idempotently.
        """
        cls.ensure_default_policies(db, workspace_id)
        now = force_now or datetime.now(timezone.utc)

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
                detail=f"Incident '{incident_id}' not found in workspace '{workspace_id}'."
            )

        # 1. Match active policy
        policy = cls.match_sla_policy(db, incident, workspace_id)

        # 2. Retrieve or initialize IncidentSLAStateModel
        sla_state = (
            db.query(IncidentSLAStateModel)
            .filter(IncidentSLAStateModel.incident_id == incident.id)
            .first()
        )
        if not sla_state:
            sla_state = IncidentSLAStateModel(
                id=str(uuid.uuid4()),
                incident_id=incident.id,
                workspace_id=workspace_id,
                policy_id=policy.id,
                policy_name=policy.name,
                policy_version=policy.version,
                escalation_policy_id=policy.escalation_policy_id,
                ack_target_minutes=policy.acknowledgement_target_minutes,
                inv_target_minutes=policy.investigation_target_minutes,
                cont_target_minutes=policy.containment_target_minutes,
                res_target_minutes=policy.resolution_target_minutes,
                current_escalation_level=incident.escalation_level or 0,
                created_at=now,
            )
            db.add(sla_state)
            db.flush()
        elif incident.escalation_level and incident.escalation_level > (sla_state.current_escalation_level or 0):
            sla_state.current_escalation_level = incident.escalation_level

        # Update policy pointer if needed
        sla_state.policy_id = policy.id
        sla_state.policy_name = policy.name
        sla_state.policy_version = policy.version
        if policy.escalation_policy_id:
            sla_state.escalation_policy_id = policy.escalation_policy_id

        # Clocks start at incident.opened_at or created_at
        start_time = min(incident.created_at, incident.opened_at) if (incident.created_at and incident.opened_at) else (incident.created_at or incident.opened_at or now)
        if start_time.tzinfo is None:
            start_time = start_time.replace(tzinfo=timezone.utc)

        # Accumulated pause adjustment
        total_pause_delta = timedelta(seconds=sla_state.total_paused_seconds or 0)
        warn_pct = policy.warning_threshold_pct / 100.0

        # Calculate Deadlines
        ack_deadline = start_time + timedelta(minutes=policy.acknowledgement_target_minutes) + total_pause_delta
        inv_deadline = start_time + timedelta(minutes=policy.investigation_target_minutes) + total_pause_delta
        cont_deadline = start_time + timedelta(minutes=policy.containment_target_minutes) + total_pause_delta
        res_deadline = start_time + timedelta(minutes=policy.resolution_target_minutes) + total_pause_delta

        sla_state.ack_deadline = ack_deadline
        sla_state.inv_deadline = inv_deadline
        sla_state.cont_deadline = cont_deadline
        sla_state.res_deadline = res_deadline

        # Handle Closed / Inactive incidents (Requirement 47)
        is_closed_or_resolved = incident.status in (
            IncidentStatusEnum.RESOLVED.value,
            IncidentStatusEnum.CLOSED.value,
            IncidentStatusEnum.FALSE_POSITIVE.value,
            IncidentStatusEnum.DUPLICATE.value,
        )

        # Helper to compute milestone status
        def evaluate_milestone(
            target_mins: int,
            deadline: datetime,
            met_timestamp: Optional[datetime],
            is_met_condition: bool,
            warning_sent_at: Optional[datetime],
            breached_at: Optional[datetime],
            milestone_name: str,
        ) -> Tuple[str, Optional[datetime], Optional[datetime], Optional[datetime]]:
            if sla_state.is_exempt:
                return SLAMilestoneStatusEnum.EXEMPT.value, met_timestamp, warning_sent_at, breached_at
            if sla_state.is_paused:
                return SLAMilestoneStatusEnum.PAUSED.value, met_timestamp, warning_sent_at, breached_at

            # If already met
            if is_met_condition or met_timestamp is not None:
                final_met = met_timestamp or incident.updated_at or now
                if final_met.tzinfo is None:
                    final_met = final_met.replace(tzinfo=timezone.utc)
                if final_met <= deadline:
                    return SLAMilestoneStatusEnum.MET.value, final_met, warning_sent_at, breached_at
                else:
                    return SLAMilestoneStatusEnum.BREACHED.value, final_met, warning_sent_at, breached_at or final_met

            # Ongoing milestone
            effective_elapsed_mins = max(0.0, (now - start_time - total_pause_delta).total_seconds() / 60.0)
            if effective_elapsed_mins >= target_mins:
                # Deterministic BREACH
                new_breach_at = breached_at or now
                return SLAMilestoneStatusEnum.BREACHED.value, None, warning_sent_at, new_breach_at
            elif effective_elapsed_mins >= target_mins * warn_pct:
                # Deterministic WARNING
                new_warn_at = warning_sent_at or now
                return SLAMilestoneStatusEnum.WARNING.value, None, new_warn_at, breached_at
            else:
                return SLAMilestoneStatusEnum.RUNNING.value, None, warning_sent_at, breached_at

        # 1. Acknowledgement Clock
        ack_is_met = bool(incident.acknowledged_at) or incident.status in (
            IncidentStatusEnum.ACKNOWLEDGED.value,
            IncidentStatusEnum.INVESTIGATING.value,
            IncidentStatusEnum.CONTAINED.value,
            IncidentStatusEnum.RESOLVED.value,
            IncidentStatusEnum.CLOSED.value,
        )
        ack_met_time = incident.acknowledged_at or sla_state.ack_met_at
        ack_status, ack_met, ack_warn, ack_breach = evaluate_milestone(
            policy.acknowledgement_target_minutes,
            ack_deadline,
            ack_met_time,
            ack_is_met,
            sla_state.ack_warning_sent_at,
            sla_state.ack_breached_at,
            SLAMilestoneEnum.ACKNOWLEDGEMENT.value,
        )
        sla_state.ack_status = ack_status
        sla_state.ack_met_at = ack_met
        sla_state.ack_warning_sent_at = ack_warn
        sla_state.ack_breached_at = ack_breach

        # 2. Investigation Clock
        inv_is_met = incident.status in (
            IncidentStatusEnum.INVESTIGATING.value,
            IncidentStatusEnum.CONTAINED.value,
            IncidentStatusEnum.RESOLVED.value,
            IncidentStatusEnum.CLOSED.value,
        )
        inv_met_time = sla_state.inv_met_at
        if inv_is_met and not inv_met_time:
            inv_met_time = incident.updated_at or now
        inv_status, inv_met, inv_warn, inv_breach = evaluate_milestone(
            policy.investigation_target_minutes,
            inv_deadline,
            inv_met_time,
            inv_is_met,
            sla_state.inv_warning_sent_at,
            sla_state.inv_breached_at,
            SLAMilestoneEnum.INVESTIGATION.value,
        )
        sla_state.inv_status = inv_status
        sla_state.inv_met_at = inv_met
        sla_state.inv_warning_sent_at = inv_warn
        sla_state.inv_breached_at = inv_breach

        # 3. Containment Clock
        cont_is_met = bool(incident.contained_at) or incident.status in (
            IncidentStatusEnum.CONTAINED.value,
            IncidentStatusEnum.RESOLVED.value,
            IncidentStatusEnum.CLOSED.value,
        )
        cont_met_time = incident.contained_at or sla_state.cont_met_at
        cont_status, cont_met, cont_warn, cont_breach = evaluate_milestone(
            policy.containment_target_minutes,
            cont_deadline,
            cont_met_time,
            cont_is_met,
            sla_state.cont_warning_sent_at,
            sla_state.cont_breached_at,
            SLAMilestoneEnum.CONTAINMENT.value,
        )
        sla_state.cont_status = cont_status
        sla_state.cont_met_at = cont_met
        sla_state.cont_warning_sent_at = cont_warn
        sla_state.cont_breached_at = cont_breach

        # 4. Resolution Clock
        res_is_met = bool(incident.resolved_at) or incident.status in (
            IncidentStatusEnum.RESOLVED.value,
            IncidentStatusEnum.CLOSED.value,
        )
        res_met_time = incident.resolved_at or sla_state.res_met_at
        res_status, res_met, res_warn, res_breach = evaluate_milestone(
            policy.resolution_target_minutes,
            res_deadline,
            res_met_time,
            res_is_met,
            sla_state.res_warning_sent_at,
            sla_state.res_breached_at,
            SLAMilestoneEnum.RESOLUTION.value,
        )
        sla_state.res_status = res_status
        sla_state.res_met_at = res_met
        sla_state.res_warning_sent_at = res_warn
        sla_state.res_breached_at = res_breach

        # Determine Overall Status
        milestones = [ack_status, inv_status, cont_status, res_status]
        if sla_state.is_exempt:
            overall = SLAOverallStatusEnum.EXEMPT.value
        elif sla_state.is_paused:
            overall = SLAOverallStatusEnum.PAUSED.value
        elif SLAMilestoneStatusEnum.BREACHED.value in milestones:
            overall = SLAOverallStatusEnum.BREACHED.value
        elif SLAMilestoneStatusEnum.WARNING.value in milestones:
            overall = SLAOverallStatusEnum.WARNING.value
        elif all(m == SLAMilestoneStatusEnum.MET.value for m in milestones):
            overall = SLAOverallStatusEnum.MET.value
        else:
            overall = SLAOverallStatusEnum.HEALTHY.value

        sla_state.overall_sla_status = overall

        # Calculate next pending deadline for indexed scheduler query
        pending_deadlines = []
        if ack_status in (SLAMilestoneStatusEnum.RUNNING.value, SLAMilestoneStatusEnum.WARNING.value):
            pending_deadlines.append(ack_deadline)
        if inv_status in (SLAMilestoneStatusEnum.RUNNING.value, SLAMilestoneStatusEnum.WARNING.value):
            pending_deadlines.append(inv_deadline)
        if cont_status in (SLAMilestoneStatusEnum.RUNNING.value, SLAMilestoneStatusEnum.WARNING.value):
            pending_deadlines.append(cont_deadline)
        if res_status in (SLAMilestoneStatusEnum.RUNNING.value, SLAMilestoneStatusEnum.WARNING.value):
            pending_deadlines.append(res_deadline)

        next_dl = min(pending_deadlines) if pending_deadlines else None
        sla_state.next_sla_deadline = next_dl

        # Synchronize columns on IncidentModel
        incident.sla_policy_id = policy.id
        incident.sla_status = overall
        incident.next_sla_deadline = next_dl
        incident.escalation_level = sla_state.current_escalation_level

        sla_state.last_evaluated_at = now
        sla_state.updated_at = now
        db.commit()

        # Handle Warnings & Breaches (Idempotent triggers)
        if not is_closed_or_resolved:
            # 1. Check Acknowledgement Warnings / Breaches
            if ack_status == SLAMilestoneStatusEnum.WARNING.value and ack_warn == now:
                cls._handle_sla_transition(
                    db, incident, sla_state, SLAMilestoneEnum.ACKNOWLEDGEMENT.value,
                    "WARNING", policy.acknowledgement_target_minutes, now
                )
            elif ack_status == SLAMilestoneStatusEnum.BREACHED.value and ack_breach == now:
                cls._handle_sla_transition(
                    db, incident, sla_state, SLAMilestoneEnum.ACKNOWLEDGEMENT.value,
                    "BREACHED", policy.acknowledgement_target_minutes, now
                )

            # 2. Check Containment Warnings / Breaches
            if cont_status == SLAMilestoneStatusEnum.WARNING.value and cont_warn == now:
                cls._handle_sla_transition(
                    db, incident, sla_state, SLAMilestoneEnum.CONTAINMENT.value,
                    "WARNING", policy.containment_target_minutes, now
                )
            elif cont_status == SLAMilestoneStatusEnum.BREACHED.value and cont_breach == now:
                cls._handle_sla_transition(
                    db, incident, sla_state, SLAMilestoneEnum.CONTAINMENT.value,
                    "BREACHED", policy.containment_target_minutes, now
                )

            # 3. Check Resolution Warnings / Breaches
            if res_status == SLAMilestoneStatusEnum.WARNING.value and res_warn == now:
                cls._handle_sla_transition(
                    db, incident, sla_state, SLAMilestoneEnum.RESOLUTION.value,
                    "WARNING", policy.resolution_target_minutes, now
                )
            elif res_status == SLAMilestoneStatusEnum.BREACHED.value and res_breach == now:
                cls._handle_sla_transition(
                    db, incident, sla_state, SLAMilestoneEnum.RESOLUTION.value,
                    "BREACHED", policy.resolution_target_minutes, now
                )

        return sla_state

    @classmethod
    def evaluate_incident(
        cls,
        db: Session,
        incident_or_id: Union[IncidentModel, str],
        workspace_id: Optional[str] = None,
        force_now: Optional[datetime] = None,
    ) -> IncidentSLADetailResponse:
        """
        Evaluates operational SLA clocks for a specific incident against its matched policy,
        returning the complete detail response with milestone clocks, deadlines, and progressive disclosure.
        """
        if isinstance(incident_or_id, IncidentModel):
            inc_id = incident_or_id.id
            ws_id = workspace_id or incident_or_id.workspace_id or "default"
        else:
            inc_id = str(incident_or_id)
            ws_id = workspace_id or "default"

        cls._evaluate_incident_state(db, inc_id, ws_id, force_now=force_now)
        return cls.get_incident_sla_detail(db, incident_id=inc_id, workspace_id=ws_id)

    @classmethod
    def _handle_sla_transition(
        cls,
        db: Session,
        incident: IncidentModel,
        sla_state: IncidentSLAStateModel,
        milestone: str,
        transition: str,  # WARNING or BREACHED
        target_minutes: int,
        now: datetime,
    ) -> None:
        """
        Dispatches idempotent notifications, realtime events, timeline logs,
        and triggers matched escalation policy rules.
        """
        workspace_id = incident.workspace_id or "default"
        is_breach = (transition == "BREACHED")
        event_type = RealtimeEventTypeEnum.INCIDENT_SLA_BREACHED.value if is_breach else RealtimeEventTypeEnum.INCIDENT_SLA_WARNING.value
        notif_type = NotificationTypeEnum.INCIDENT_SLA_BREACHED.value if is_breach else NotificationTypeEnum.INCIDENT_SLA_WARNING.value
        sev = NotificationSeverityEnum.CRITICAL.value if is_breach else NotificationSeverityEnum.HIGH.value

        title = f"SLA {transition}: {incident.incident_number} — {milestone.title()}"
        msg = (
            f"Incident {incident.incident_number} ({incident.title}) has {transition.lower()} "
            f"its {milestone.lower()} target ({target_minutes}m)."
        )

        # 1. Deterministic Dedup Key
        dedup_key = f"sla_{transition.lower()}:{incident.id}:{milestone}:{sla_state.policy_version}"

        # 2. Notification (Section 47)
        NotificationService.create_notification(
            db=db,
            workspace_id=workspace_id,
            category=NotificationCategoryEnum.SECURITY_ALERT.value,
            notification_type=notif_type,
            severity=sev,
            title=title,
            message=msg,
            source_type="INCIDENT",
            source_id=incident.id,
            deduplication_key=dedup_key,
            navigation_target=f"/incidents/{incident.id}",
            metadata={
                "incident_id": incident.id,
                "incident_number": incident.incident_number,
                "milestone": milestone,
                "transition": transition,
                "target_minutes": target_minutes,
            },
        )

        # 3. Realtime Update (Section 46)
        cls._emit_realtime(
            workspace_id=workspace_id,
            incident_id=incident.id,
            event_type=event_type,
            message=msg,
            payload_data={
                "entity_id": incident.id,
                "status": sla_state.overall_sla_status,
                "progress_pct": 100.0 if is_breach else 80.0,
                "summary": msg,
                "details": {
                    "incident_number": incident.incident_number,
                    "milestone": milestone,
                    "transition": transition,
                    "escalation_level": sla_state.current_escalation_level,
                },
            },
            status=sla_state.overall_sla_status,
        )

        # 4. Audit Log & Timeline
        AuditService.log_audit(
            db=db,
            action=f"INCIDENT_SLA_{transition}",
            resource_type="INCIDENT",
            resource_id=incident.id,
            user="SYSTEM_SLA_ENGINE",
            case_id=incident.id,
            details=msg,
            metadata={"milestone": milestone, "transition": transition},
        )

        tl_event = IncidentTimelineEventModel(
            id=str(uuid.uuid4()),
            incident_id=incident.id,
            event_type=f"SLA_{transition}",
            timestamp=now,
            actor="SYSTEM",
            source_type="SLA_ENGINE",
            source_id=sla_state.id,
            summary=msg,
            metadata_json=json.dumps({"milestone": milestone, "target_minutes": target_minutes}),
        )
        db.add(tl_event)
        db.commit()

        # 5. Trigger Escalation Chain
        condition = EscalationConditionEnum.SLA_BREACH.value if is_breach else EscalationConditionEnum.SLA_WARNING.value
        cls.execute_due_escalation(
            db=db,
            incident=incident,
            sla_state=sla_state,
            condition_type=condition,
            milestone=milestone,
            reason=msg,
            now=now,
        )

    # =========================================================================
    # 3. ESCALATION ENGINE & LOOP PREVENTION
    # =========================================================================

    @classmethod
    def execute_due_escalation(
        cls,
        db: Session,
        incident: IncidentModel,
        sla_state: IncidentSLAStateModel,
        condition_type: str,
        milestone: str,
        reason: str,
        now: Optional[datetime] = None,
    ) -> bool:
        """
        Executes escalation policy rules for an incident while preventing infinite loops.
        Enforces:
        - Cooldown periods between escalations
        - Maximum escalation levels (e.g. 3)
        - Idempotency execution keys to prevent repeated executions
        - Closed / resolved incident suppression
        - Safe workflow action boundaries only
        """
        now = now or datetime.now(timezone.utc)
        workspace_id = incident.workspace_id or "default"

        # Check suppression for closed/resolved incidents
        if incident.status in (
            IncidentStatusEnum.RESOLVED.value,
            IncidentStatusEnum.CLOSED.value,
            IncidentStatusEnum.FALSE_POSITIVE.value,
            IncidentStatusEnum.DUPLICATE.value,
        ):
            logger.info("Suppressing escalation for closed/resolved incident %s", incident.incident_number)
            return False

        # Load escalation policy
        esc_policy_id = sla_state.escalation_policy_id
        if not esc_policy_id:
            # Try to load default escalation policy
            default_esc = (
                db.query(IncidentEscalationPolicyModel)
                .filter(
                    IncidentEscalationPolicyModel.workspace_id == workspace_id,
                    IncidentEscalationPolicyModel.status == "ACTIVE",
                )
                .first()
            )
            if default_esc:
                esc_policy_id = default_esc.id
                sla_state.escalation_policy_id = default_esc.id

        if not esc_policy_id:
            logger.info("No escalation policy configured for incident %s", incident.incident_number)
            return False

        esc_policy = (
            db.query(IncidentEscalationPolicyModel)
            .filter(IncidentEscalationPolicyModel.id == esc_policy_id)
            .first()
        )
        if not esc_policy or esc_policy.status != "ACTIVE":
            return False

        # Loop Prevention 1: Max escalation level
        if sla_state.current_escalation_level >= esc_policy.max_escalation_level:
            logger.warning(
                "Incident %s reached max escalation level (%d/%d). Halting escalation loop.",
                incident.incident_number,
                sla_state.current_escalation_level,
                esc_policy.max_escalation_level,
            )
            return False

        # Loop Prevention 2: Cooldown check
        if sla_state.last_escalated_at:
            last_esc = sla_state.last_escalated_at
            if last_esc.tzinfo is None:
                last_esc = last_esc.replace(tzinfo=timezone.utc)
            cooldown_delta = timedelta(minutes=esc_policy.cooldown_minutes)
            if now - last_esc < cooldown_delta:
                logger.info(
                    "Incident %s escalation on cooldown until %s. Skipping.",
                    incident.incident_number,
                    (last_esc + cooldown_delta).isoformat(),
                )
                return False

        # Find matching rules for target level
        next_level = sla_state.current_escalation_level + 1
        matching_rules = [
            r for r in esc_policy.rules
            if r.level == next_level
            and (r.condition_type == condition_type or r.condition_type == "ANY")
            and (r.milestone == milestone or r.milestone == "ANY")
        ]

        if not matching_rules:
            # Fallback: check rules that match condition at any level > current
            matching_rules = [
                r for r in esc_policy.rules
                if r.level > sla_state.current_escalation_level
                and (r.condition_type == condition_type or r.condition_type == "ANY")
            ]

        if not matching_rules:
            logger.info("No matching escalation rules for condition=%s at level=%d", condition_type, next_level)
            return False

        executed_any = False
        for rule in matching_rules:
            # Loop Prevention 3: Idempotency execution key
            exec_key = f"esc:{incident.id}:{rule.id}:{rule.level}:{rule.action_type}:{condition_type}"
            existing_exec = (
                db.query(IncidentWorkflowExecutionModel)
                .filter(IncidentWorkflowExecutionModel.execution_key == exec_key)
                .first()
            )
            if existing_exec:
                logger.debug("Escalation rule %s already executed with key=%s. Skipping.", rule.id, exec_key)
                continue

            # Execute safe workflow action
            success, details = cls._execute_safe_action(
                db=db,
                incident=incident,
                sla_state=sla_state,
                rule=rule,
                reason=reason,
                now=now,
            )

            # Record execution log
            wf_exec = IncidentWorkflowExecutionModel(
                id=str(uuid.uuid4()),
                incident_id=incident.id,
                workspace_id=workspace_id,
                execution_key=exec_key,
                policy_id=esc_policy.id,
                rule_id=rule.id,
                escalation_level=rule.level,
                action_type=rule.action_type,
                target=rule.target_user or rule.target_team or rule.target_role,
                status="SUCCESS" if success else "FAILED",
                executed_at=now,
                details_json=json.dumps(details),
            )
            db.add(wf_exec)
            executed_any = True

        if executed_any:
            sla_state.current_escalation_level = next_level
            sla_state.last_escalated_at = now
            sla_state.last_escalation_reason = reason
            incident.escalation_level = next_level
            db.commit()

            # Emit Realtime INCIDENT_ESCALATED
            cls._emit_realtime(
                workspace_id=workspace_id,
                incident_id=incident.id,
                event_type=RealtimeEventTypeEnum.INCIDENT_ESCALATED.value,
                message=f"Incident {incident.incident_number} escalated to Level {next_level}.",
                payload_data={
                    "entity_id": incident.id,
                    "status": incident.status,
                    "summary": f"Incident {incident.incident_number} escalated to Level {next_level}.",
                    "details": {
                        "escalation_level": next_level,
                        "reason": reason,
                        "assigned_to": incident.assigned_to,
                        "team_id": incident.team_id,
                    },
                },
                status=incident.status,
            )
            return True

        return False

    @classmethod
    def _execute_safe_action(
        cls,
        db: Session,
        incident: IncidentModel,
        sla_state: IncidentSLAStateModel,
        rule: IncidentEscalationRuleModel,
        reason: str,
        now: datetime,
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Executes a bounded safe workflow automation action.
        NO destructive remediation allowed here.
        """
        workspace_id = incident.workspace_id or "default"
        details: Dict[str, Any] = {"rule_id": rule.id, "level": rule.level}

        try:
            if rule.action_type == EscalationActionTypeEnum.NOTIFY_OWNER.value:
                recipient = incident.assigned_to or "SOC Lead"
                NotificationService.create_notification(
                    db=db,
                    workspace_id=workspace_id,
                    category=NotificationCategoryEnum.SECURITY_ALERT.value,
                    notification_type=NotificationTypeEnum.INCIDENT_SLA_WARNING.value,
                    severity=NotificationSeverityEnum.HIGH.value,
                    title=f"Escalation Notice: {incident.incident_number}",
                    message=f"Incident {incident.incident_number} attention required. {rule.note_template or reason}",
                    source_type="INCIDENT",
                    source_id=incident.id,
                    user_id=recipient,
                    deduplication_key=f"esc_notif_owner:{incident.id}:{rule.level}",
                    navigation_target=f"/incidents/{incident.id}",
                )
                details["notified_owner"] = recipient

            elif rule.action_type == EscalationActionTypeEnum.NOTIFY_TEAM.value:
                target_team = rule.target_team or incident.team_id or "Tier-2 SOC"
                NotificationService.create_notification(
                    db=db,
                    workspace_id=workspace_id,
                    category=NotificationCategoryEnum.SECURITY_ALERT.value,
                    notification_type=NotificationTypeEnum.INCIDENT_ESCALATED.value,
                    severity=NotificationSeverityEnum.CRITICAL.value,
                    title=f"Team Escalation: {incident.incident_number} ({target_team})",
                    message=f"Incident {incident.incident_number} escalated to {target_team}. {rule.note_template or reason}",
                    source_type="INCIDENT",
                    source_id=incident.id,
                    deduplication_key=f"esc_notif_team:{incident.id}:{rule.level}:{target_team}",
                    navigation_target=f"/incidents/{incident.id}",
                )
                details["notified_team"] = target_team

            elif rule.action_type == EscalationActionTypeEnum.ASSIGN_TO_USER.value:
                new_assignee = rule.target_user or "Jordan Lee (SOC Lead)"
                old_assignee = incident.assigned_to
                incident.assigned_to = new_assignee
                if rule.target_team:
                    incident.team_id = rule.target_team

                details["previous_assignee"] = old_assignee
                details["new_assignee"] = new_assignee

                # Add timeline event
                tl = IncidentTimelineEventModel(
                    id=str(uuid.uuid4()),
                    incident_id=incident.id,
                    event_type="INCIDENT_REASSIGNED",
                    timestamp=now,
                    actor="ESCALATION_ENGINE",
                    source_type="SLA_ENGINE",
                    source_id=rule.id,
                    summary=f"Incident escalated to Level {rule.level} and reassigned to {new_assignee}.",
                    metadata_json=json.dumps({"from": old_assignee, "to": new_assignee, "reason": reason}),
                )
                db.add(tl)

                # Add case note
                note = IncidentNoteModel(
                    id=str(uuid.uuid4()),
                    incident_id=incident.id,
                    author="ESCALATION_ENGINE",
                    note_text=f"[ESCALATION LEVEL {rule.level}] Reassigned to {new_assignee}. Reason: {rule.note_template or reason}",
                    created_at=now,
                )
                db.add(note)

            elif rule.action_type == EscalationActionTypeEnum.ASSIGN_TO_TEAM.value:
                old_team = incident.team_id
                incident.team_id = rule.target_team or "Tier-2 SOC"
                details["previous_team"] = old_team
                details["new_team"] = incident.team_id

            elif rule.action_type == EscalationActionTypeEnum.ESCALATE_PRIORITY.value:
                old_prio = incident.priority
                new_prio = rule.escalate_priority_to or IncidentPriorityEnum.P1_CRITICAL.value
                incident.priority = new_prio
                details["previous_priority"] = old_prio
                details["new_priority"] = new_prio

            elif rule.action_type == EscalationActionTypeEnum.CREATE_TASK.value:
                # Add workflow task note
                note = IncidentNoteModel(
                    id=str(uuid.uuid4()),
                    incident_id=incident.id,
                    author="ESCALATION_ENGINE",
                    note_text=f"[WORKFLOW ACTION] Task created for Level {rule.level}: {rule.note_template or reason}",
                    created_at=now,
                )
                db.add(note)
                details["task_created"] = True

            return True, details
        except Exception as e:
            logger.exception("Failed to execute escalation action %s on incident %s", rule.action_type, incident.id)
            details["error"] = str(e)
            return False, details

    # =========================================================================
    # 4. MANUAL ESCALATION OVERRIDE
    # =========================================================================

    @classmethod
    def manual_escalate(
        cls,
        db: Session,
        incident_id: str,
        actor: str,
        reason: str,
        workspace_id: str = "default",
        target_level: Optional[int] = None,
        target_user: Optional[str] = None,
        target_team: Optional[str] = None,
    ) -> IncidentSLAStateModel:
        """
        Allows authorized human analysts or SOC Leads to manually escalate an incident.
        Records audit trail and updates escalation level.
        """
        now = datetime.now(timezone.utc)
        incident = (
            db.query(IncidentModel)
            .filter(
                IncidentModel.id == incident_id,
                IncidentModel.workspace_id == workspace_id,
            )
            .first()
        )
        if not incident:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Incident '{incident_id}' not found.")

        sla_state = cls._evaluate_incident_state(db, incident_id, workspace_id, force_now=now)

        new_level = target_level or (sla_state.current_escalation_level + 1)
        sla_state.current_escalation_level = new_level
        sla_state.last_escalated_at = now
        sla_state.last_escalation_reason = f"Manual escalation by {actor}: {reason}"
        incident.escalation_level = new_level

        if target_user:
            incident.assigned_to = target_user
        if target_team:
            incident.team_id = target_team

        # Record Audit & Timeline
        AuditService.log_audit(
            db=db,
            action="INCIDENT_MANUAL_ESCALATE",
            resource_type="INCIDENT",
            resource_id=incident.id,
            user=actor,
            case_id=incident.id,
            details=f"Incident manually escalated to Level {new_level} by {actor}. Reason: {reason}",
            metadata={"target_user": target_user, "target_team": target_team, "level": new_level},
        )

        tl = IncidentTimelineEventModel(
            id=str(uuid.uuid4()),
            incident_id=incident.id,
            event_type="INCIDENT_MANUAL_ESCALATE",
            timestamp=now,
            actor=actor,
            source_type="ANALYST",
            source_id=actor,
            summary=f"Incident escalated to Level {new_level} by {actor}. Reason: {reason}",
            metadata_json=json.dumps({"target_user": target_user, "target_team": target_team, "level": new_level}),
        )
        db.add(tl)

        note = IncidentNoteModel(
            id=str(uuid.uuid4()),
            incident_id=incident.id,
            author=actor,
            note_text=f"[MANUAL ESCALATION LEVEL {new_level}] {reason}",
            created_at=now,
        )
        db.add(note)

        # Record Workflow Execution
        wf_exec = IncidentWorkflowExecutionModel(
            id=str(uuid.uuid4()),
            incident_id=incident.id,
            workspace_id=workspace_id,
            execution_key=f"manual_esc:{incident.id}:{new_level}:{now.isoformat()}",
            escalation_level=new_level,
            action_type="MANUAL_ESCALATION",
            target=target_user or target_team or "SOC Lead",
            status="SUCCESS",
            executed_at=now,
            details_json=json.dumps({"actor": actor, "reason": reason}),
        )
        db.add(wf_exec)
        db.commit()

        # Emit Realtime Event
        cls._emit_realtime(
            workspace_id=workspace_id,
            incident_id=incident.id,
            event_type=RealtimeEventTypeEnum.INCIDENT_ESCALATED.value,
            message=f"Incident {incident.incident_number} manually escalated to Level {new_level} by {actor}.",
            payload_data={
                "entity_id": incident.id,
                "status": incident.status,
                "summary": f"Incident {incident.incident_number} manually escalated to Level {new_level} by {actor}.",
                "details": {"escalation_level": new_level, "actor": actor, "reason": reason},
            },
            status=incident.status,
        )

        return sla_state

    # =========================================================================
    # 5. ANALYST ROUTING AUTOMATION
    # =========================================================================

    @classmethod
    def route_incident(
        cls,
        db: Session,
        incident: Union[IncidentModel, str],
        workspace_id: Optional[str] = None,
        trigger: str = "AUTO",
    ) -> Tuple[Optional[str], Optional[str]]:
        """
        Intelligently routes an incoming or unassigned incident to the appropriate
        specialized team and analyst based on category, severity, and risk score.
        Supports LEAST_LOADED, ROUND_ROBIN, and DIRECT_USER strategies.
        """
        if isinstance(incident, str):
            inc = db.query(IncidentModel).filter(IncidentModel.id == incident).first()
            if not inc:
                return (None, None)
            incident = inc

        ws = workspace_id or incident.workspace_id or "default"
        cls.ensure_default_policies(db, ws)
        now = datetime.now(timezone.utc)

        rules = (
            db.query(IncidentRoutingRuleModel)
            .filter(
                IncidentRoutingRuleModel.workspace_id == ws,
                IncidentRoutingRuleModel.enabled == True,
            )
            .order_by(IncidentRoutingRuleModel.priority_order.asc())
            .all()
        )

        matched_rule: Optional[IncidentRoutingRuleModel] = None
        for r in rules:
            cat_match = (r.category == "ANY" or r.category == incident.category)
            sev_match = (r.severity == "ANY" or r.severity == incident.severity)
            risk_match = ((incident.risk_score or 0.0) >= r.min_risk_score)
            if cat_match and sev_match and risk_match:
                matched_rule = r
                break

        if not matched_rule:
            logger.info("No routing rule matched for incident %s", incident.incident_number)
            return (incident.assigned_to, incident.team_id)

        candidates = json.loads(matched_rule.candidate_analysts_json or "[]")
        chosen_analyst: Optional[str] = matched_rule.target_user_id

        if not chosen_analyst and candidates:
            if matched_rule.routing_strategy == RoutingStrategyEnum.LEAST_LOADED.value:
                # Calculate active workload per candidate
                active_statuses = [
                    IncidentStatusEnum.NEW.value,
                    IncidentStatusEnum.OPEN.value,
                    IncidentStatusEnum.ACKNOWLEDGED.value,
                    IncidentStatusEnum.INVESTIGATING.value,
                ]
                counts: Dict[str, int] = {}
                for cand in candidates:
                    load = (
                        db.query(func.count(IncidentModel.id))
                        .filter(
                            IncidentModel.workspace_id == ws,
                            IncidentModel.assigned_to == cand,
                            IncidentModel.status.in_(active_statuses),
                        )
                        .scalar()
                        or 0
                    )
                    counts[cand] = load
                chosen_analyst = min(counts, key=counts.get)
                logger.info(
                    "Least-loaded routing selected '%s' (active incidents: %s)",
                    chosen_analyst, counts
                )
            elif matched_rule.routing_strategy == RoutingStrategyEnum.ROUND_ROBIN.value:
                # Find last assigned analyst from rule
                last_assigned = (
                    db.query(IncidentModel.assigned_to)
                    .filter(
                        IncidentModel.workspace_id == ws,
                        IncidentModel.assigned_to.in_(candidates),
                    )
                    .order_by(desc(IncidentModel.created_at))
                    .first()
                )
                last_user = last_assigned[0] if last_assigned else None
                if last_user and last_user in candidates:
                    idx = (candidates.index(last_user) + 1) % len(candidates)
                    chosen_analyst = candidates[idx]
                else:
                    chosen_analyst = candidates[0]
            else:
                chosen_analyst = candidates[0]

        # Apply assignment
        if chosen_analyst:
            incident.assigned_to = chosen_analyst
        if matched_rule.target_team_id:
            incident.team_id = matched_rule.target_team_id

        # Timeline & Audit Log
        summary = (
            f"Incident automatically routed to '{incident.assigned_to or 'Unassigned'}' "
            f"(Team: {incident.team_id or 'General'}) via rule '{matched_rule.name}'."
        )
        tl = IncidentTimelineEventModel(
            id=str(uuid.uuid4()),
            incident_id=incident.id,
            event_type="INCIDENT_ROUTED",
            timestamp=now,
            actor="ROUTING_ENGINE",
            source_type="ROUTING_RULE",
            source_id=matched_rule.id,
            summary=summary,
            metadata_json=json.dumps({
                "rule_name": matched_rule.name,
                "strategy": matched_rule.routing_strategy,
                "assigned_to": incident.assigned_to,
                "team_id": incident.team_id,
            }),
        )
        db.add(tl)

        AuditService.log_audit(
            db=db,
            action="INCIDENT_ROUTED",
            resource_type="INCIDENT",
            resource_id=incident.id,
            user="ROUTING_ENGINE",
            case_id=incident.id,
            details=summary,
            metadata={"rule_id": matched_rule.id, "strategy": matched_rule.routing_strategy},
        )
        db.commit()

        # Emit Realtime INCIDENT_ROUTED & INCIDENT_ASSIGNED
        cls._emit_realtime(
            workspace_id=ws,
            incident_id=incident.id,
            event_type=RealtimeEventTypeEnum.INCIDENT_ROUTED.value,
            message=summary,
            payload_data={
                "entity_id": incident.id,
                "status": incident.status,
                "summary": summary,
                "details": {
                    "assigned_to": incident.assigned_to,
                    "team_id": incident.team_id,
                    "rule_name": matched_rule.name,
                },
            },
            status=incident.status,
        )

        return (incident.assigned_to, incident.team_id)

    # =========================================================================
    # 6. SLA PAUSE, RESUME & EXEMPTIONS
    # =========================================================================

    @classmethod
    def pause_sla(
        cls,
        db: Session,
        incident_id: str,
        actor: str,
        reason: str,
        workspace_id: str = "default",
    ) -> IncidentSLAPauseLogModel:
        """
        Pauses SLA clock (e.g. awaiting customer input, maintenance window).
        Records forensic audit log and updates timeline.
        """
        now = datetime.now(timezone.utc)
        incident = (
            db.query(IncidentModel)
            .filter(
                IncidentModel.id == incident_id,
                IncidentModel.workspace_id == workspace_id,
            )
            .first()
        )
        if not incident:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Incident '{incident_id}' not found.")

        sla_state = cls._evaluate_incident_state(db, incident_id, workspace_id, force_now=now)

        if sla_state.is_paused:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Incident SLA is already paused.")

        sla_state.is_paused = True
        sla_state.paused_at = now
        sla_state.paused_by = actor
        sla_state.pause_reason = reason
        sla_state.overall_sla_status = SLAOverallStatusEnum.PAUSED.value
        incident.sla_status = SLAOverallStatusEnum.PAUSED.value

        # Log pause
        pause_log = IncidentSLAPauseLogModel(
            id=str(uuid.uuid4()),
            incident_id=incident.id,
            workspace_id=workspace_id,
            action="PAUSE",
            actor=actor,
            reason=reason,
            timestamp=now,
        )
        db.add(pause_log)

        tl = IncidentTimelineEventModel(
            id=str(uuid.uuid4()),
            incident_id=incident.id,
            event_type="INCIDENT_SLA_PAUSED",
            timestamp=now,
            actor=actor,
            source_type="ANALYST",
            source_id=actor,
            summary=f"Incident SLA paused by {actor}. Reason: {reason}",
            metadata_json=json.dumps({"reason": reason}),
        )
        db.add(tl)

        AuditService.log_audit(
            db=db,
            action="INCIDENT_SLA_PAUSED",
            resource_type="INCIDENT",
            resource_id=incident.id,
            user=actor,
            case_id=incident.id,
            details=f"Incident SLA paused by {actor}. Reason: {reason}",
            metadata={"reason": reason},
        )
        db.commit()

        # Emit Realtime Event
        cls._emit_realtime(
            workspace_id=workspace_id,
            incident_id=incident.id,
            event_type=RealtimeEventTypeEnum.INCIDENT_SLA_PAUSED.value,
            message=f"SLA paused by {actor}.",
            payload_data={
                "entity_id": incident.id,
                "status": incident.status,
                "summary": f"SLA paused by {actor}.",
                "details": {"actor": actor, "reason": reason},
            },
            status=incident.status,
        )

        return pause_log

    @classmethod
    def resume_sla(
        cls,
        db: Session,
        incident_id: str,
        actor: str,
        reason: Optional[str] = None,
        workspace_id: str = "default",
    ) -> IncidentSLAPauseLogModel:
        """
        Resumes a paused SLA clock. Adds elapsed pause time to total_paused_seconds
        and recalculates deadlines deterministically.
        """
        now = datetime.now(timezone.utc)
        incident = (
            db.query(IncidentModel)
            .filter(
                IncidentModel.id == incident_id,
                IncidentModel.workspace_id == workspace_id,
            )
            .first()
        )
        if not incident:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Incident '{incident_id}' not found.")

        sla_state = (
            db.query(IncidentSLAStateModel)
            .filter(IncidentSLAStateModel.incident_id == incident.id)
            .first()
        )
        if not sla_state or not sla_state.is_paused:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Incident SLA is not currently paused.")

        # Compute pause duration
        paused_since = sla_state.paused_at or now
        if paused_since.tzinfo is None:
            paused_since = paused_since.replace(tzinfo=timezone.utc)
        pause_duration_sec = int((now - paused_since).total_seconds())

        sla_state.total_paused_seconds = (sla_state.total_paused_seconds or 0) + max(0, pause_duration_sec)
        sla_state.is_paused = False
        sla_state.paused_at = None
        sla_state.paused_by = None
        sla_state.pause_reason = None

        pause_log = IncidentSLAPauseLogModel(
            id=str(uuid.uuid4()),
            incident_id=incident.id,
            workspace_id=workspace_id,
            action="RESUME",
            actor=actor,
            reason=reason or f"Resumed after {pause_duration_sec}s pause.",
            timestamp=now,
            paused_duration_seconds=pause_duration_sec,
        )
        db.add(pause_log)

        tl = IncidentTimelineEventModel(
            id=str(uuid.uuid4()),
            incident_id=incident.id,
            event_type="INCIDENT_SLA_RESUMED",
            timestamp=now,
            actor=actor,
            source_type="ANALYST",
            source_id=actor,
            summary=f"Incident SLA resumed by {actor} after {pause_duration_sec // 60}m {pause_duration_sec % 60}s pause.",
            metadata_json=json.dumps({"paused_duration_sec": pause_duration_sec}),
        )
        db.add(tl)

        AuditService.log_audit(
            db=db,
            action="INCIDENT_SLA_RESUMED",
            resource_type="INCIDENT",
            resource_id=incident.id,
            user=actor,
            case_id=incident.id,
            details=f"Incident SLA resumed by {actor}. Total pause duration added: {pause_duration_sec}s.",
            metadata={"paused_duration_sec": pause_duration_sec},
        )
        db.commit()

        # Re-evaluate clocks with updated pause delta
        cls._evaluate_incident_state(db, incident.id, workspace_id, force_now=now)

        # Emit Realtime Event
        cls._emit_realtime(
            workspace_id=workspace_id,
            incident_id=incident.id,
            event_type=RealtimeEventTypeEnum.INCIDENT_SLA_RESUMED.value,
            message=f"SLA resumed by {actor}.",
            payload_data={
                "entity_id": incident.id,
                "status": incident.status,
                "summary": f"SLA resumed by {actor}.",
                "details": {"actor": actor, "paused_duration_sec": pause_duration_sec},
            },
            status=incident.status,
        )

        return pause_log

    @classmethod
    def exempt_sla(
        cls,
        db: Session,
        incident_id: str,
        actor: str,
        reason: str,
        workspace_id: str = "default",
    ) -> IncidentSLADetailResponse:
        """
        Marks incident SLA as EXEMPT (authorized SOC leads or managers only).
        Audited strictly.
        """
        now = datetime.now(timezone.utc)
        incident = (
            db.query(IncidentModel)
            .filter(
                IncidentModel.id == incident_id,
                IncidentModel.workspace_id == workspace_id,
            )
            .first()
        )
        if not incident:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Incident '{incident_id}' not found.")

        sla_state = cls._evaluate_incident_state(db, incident_id, workspace_id, force_now=now)

        sla_state.is_exempt = True
        sla_state.exempt_at = now
        sla_state.exempt_by = actor
        sla_state.exempt_reason = reason
        sla_state.overall_sla_status = SLAOverallStatusEnum.EXEMPT.value
        sla_state.ack_status = SLAMilestoneStatusEnum.EXEMPT.value
        sla_state.inv_status = SLAMilestoneStatusEnum.EXEMPT.value
        sla_state.cont_status = SLAMilestoneStatusEnum.EXEMPT.value
        sla_state.res_status = SLAMilestoneStatusEnum.EXEMPT.value
        incident.sla_status = SLAOverallStatusEnum.EXEMPT.value

        pause_log = IncidentSLAPauseLogModel(
            id=str(uuid.uuid4()),
            incident_id=incident.id,
            workspace_id=workspace_id,
            action="EXEMPT",
            actor=actor,
            reason=reason,
            timestamp=now,
        )
        db.add(pause_log)

        tl = IncidentTimelineEventModel(
            id=str(uuid.uuid4()),
            incident_id=incident.id,
            event_type="INCIDENT_SLA_EXEMPTED",
            timestamp=now,
            actor=actor,
            source_type="ANALYST",
            source_id=actor,
            summary=f"Incident SLA exempted by {actor}. Reason: {reason}",
            metadata_json=json.dumps({"reason": reason}),
        )
        db.add(tl)

        AuditService.log_audit(
            db=db,
            action="INCIDENT_SLA_EXEMPTED",
            resource_type="INCIDENT",
            resource_id=incident.id,
            user=actor,
            case_id=incident.id,
            details=f"Incident SLA exempted by {actor}. Reason: {reason}",
            metadata={"reason": reason},
        )
        db.commit()

        # Emit Realtime Event
        cls._emit_realtime(
            workspace_id=workspace_id,
            incident_id=incident.id,
            event_type=RealtimeEventTypeEnum.INCIDENT_SLA_EXEMPTED.value,
            message=f"SLA marked EXEMPT by {actor}.",
            payload_data={
                "entity_id": incident.id,
                "status": incident.status,
                "summary": f"SLA marked EXEMPT by {actor}.",
                "details": {"actor": actor, "reason": reason},
            },
            status=incident.status,
        )

        return cls.get_incident_sla_detail(db, incident_id=incident.id, workspace_id=workspace_id)

    # =========================================================================
    # 7. BATCH EVALUATION FOR BACKGROUND WORKER
    # =========================================================================

    @classmethod
    def evaluate_all_active_slas(
        cls,
        db: Session,
        workspace_id: str = "default",
        batch_size: int = 50,
    ) -> Dict[str, Any]:
        """
        Bounded, indexed batch SLA evaluation designed for BackgroundJobWorker.
        Queries active incidents and evaluates operational clocks idempotently.
        """
        now = datetime.now(timezone.utc)
        active_statuses = [
            IncidentStatusEnum.NEW.value,
            IncidentStatusEnum.OPEN.value,
            IncidentStatusEnum.ACKNOWLEDGED.value,
            IncidentStatusEnum.INVESTIGATING.value,
        ]

        active_incidents = (
            db.query(IncidentModel.id)
            .filter(
                IncidentModel.workspace_id == workspace_id,
                IncidentModel.status.in_(active_statuses),
            )
            .order_by(IncidentModel.created_at.asc())
            .limit(batch_size)
            .all()
        )

        evaluated_count = 0
        warning_count = 0
        breach_count = 0

        for row in active_incidents:
            inc_id = row[0]
            try:
                state = cls.evaluate_incident(db, inc_id, workspace_id, force_now=now)
                evaluated_count += 1
                if state.overall_sla_status == SLAOverallStatusEnum.WARNING.value:
                    warning_count += 1
                elif state.overall_sla_status == SLAOverallStatusEnum.BREACHED.value:
                    breach_count += 1
            except Exception as e:
                logger.error("Failed to evaluate SLA for incident %s: %s", inc_id, e)

        return {
            "workspace_id": workspace_id,
            "evaluated_count": evaluated_count,
            "warning_count": warning_count,
            "breach_count": breach_count,
            "timestamp": now.isoformat(),
        }

    # =========================================================================
    # 8. DETAIL RESPONSE BUILDER
    # =========================================================================

    @classmethod
    def get_incident_sla_detail(
        cls,
        db: Session,
        incident_id: str,
        workspace_id: str = "default",
    ) -> IncidentSLADetailResponse:
        """
        Formats complete operational SLA state with progressive disclosure details.
        """
        incident = (
            db.query(IncidentModel)
            .filter(
                IncidentModel.id == incident_id,
                IncidentModel.workspace_id == workspace_id,
            )
            .first()
        )
        if not incident:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Incident '{incident_id}' not found.")

        # Ensure evaluated
        state = cls._evaluate_incident_state(db, incident_id, workspace_id)
        now = datetime.now(timezone.utc)
        start_time = min(incident.created_at, incident.opened_at) if (incident.created_at and incident.opened_at) else (incident.created_at or incident.opened_at or now)
        if start_time.tzinfo is None:
            start_time = start_time.replace(tzinfo=timezone.utc)

        total_paused_mins = (state.total_paused_seconds or 0) / 60.0

        def build_milestone_detail(
            milestone: str,
            target_mins: int,
            m_status: str,
            deadline: Optional[datetime],
            met_at: Optional[datetime],
            warn_at: Optional[datetime],
            breach_at: Optional[datetime],
        ) -> SLAMilestoneDetail:
            if met_at:
                if met_at.tzinfo is None:
                    met_at = met_at.replace(tzinfo=timezone.utc)
                elapsed_mins = max(0.0, (met_at - start_time).total_seconds() / 60.0 - total_paused_mins)
            else:
                elapsed_mins = max(0.0, (now - start_time).total_seconds() / 60.0 - total_paused_mins)

            rem_mins = max(0.0, target_mins - elapsed_mins)
            is_overdue = (elapsed_mins > target_mins) and (m_status == SLAMilestoneStatusEnum.BREACHED.value)
            overdue_mins = max(0.0, elapsed_mins - target_mins) if is_overdue else 0.0

            badge = "neutral"
            if m_status == SLAMilestoneStatusEnum.MET.value:
                badge = "success"
            elif m_status == SLAMilestoneStatusEnum.WARNING.value:
                badge = "warning"
            elif m_status == SLAMilestoneStatusEnum.BREACHED.value:
                badge = "danger"

            return SLAMilestoneDetail(
                milestone=milestone,
                target_minutes=target_mins,
                status=m_status,
                elapsed_minutes=round(elapsed_mins, 1),
                remaining_minutes=round(rem_mins, 1),
                deadline=deadline,
                met_at=met_at,
                warning_sent_at=warn_at,
                breached_at=breach_at,
                is_overdue=is_overdue,
                overdue_minutes=round(overdue_mins, 1),
                display_badge=badge,
            )

        ack_detail = build_milestone_detail(
            SLAMilestoneEnum.ACKNOWLEDGEMENT.value,
            state.ack_target_minutes,
            state.ack_status,
            state.ack_deadline,
            state.ack_met_at,
            state.ack_warning_sent_at,
            state.ack_breached_at,
        )
        inv_detail = build_milestone_detail(
            SLAMilestoneEnum.INVESTIGATION.value,
            state.inv_target_minutes,
            state.inv_status,
            state.inv_deadline,
            state.inv_met_at,
            state.inv_warning_sent_at,
            state.inv_breached_at,
        )
        cont_detail = build_milestone_detail(
            SLAMilestoneEnum.CONTAINMENT.value,
            state.cont_target_minutes,
            state.cont_status,
            state.cont_deadline,
            state.cont_met_at,
            state.cont_warning_sent_at,
            state.cont_breached_at,
        )
        res_detail = build_milestone_detail(
            SLAMilestoneEnum.RESOLUTION.value,
            state.res_target_minutes,
            state.res_status,
            state.res_deadline,
            state.res_met_at,
            state.res_warning_sent_at,
            state.res_breached_at,
        )

        return IncidentSLADetailResponse(
            incident_id=incident.id,
            incident_number=incident.incident_number,
            workspace_id=workspace_id,
            policy_id=state.policy_id,
            policy_name=state.policy_name,
            policy_version=state.policy_version,
            escalation_policy_id=state.escalation_policy_id,
            overall_status=state.overall_sla_status,
            current_escalation_level=state.current_escalation_level,
            last_escalated_at=state.last_escalated_at,
            last_escalation_reason=state.last_escalation_reason,
            is_paused=state.is_paused,
            paused_at=state.paused_at,
            paused_by=state.paused_by,
            pause_reason=state.pause_reason,
            total_paused_seconds=state.total_paused_seconds or 0,
            is_exempt=state.is_exempt,
            exempt_at=state.exempt_at,
            exempt_by=state.exempt_by,
            exempt_reason=state.exempt_reason,
            next_deadline=state.next_sla_deadline,
            acknowledgement=ack_detail,
            investigation=inv_detail,
            containment=cont_detail,
            resolution=res_detail,
            last_evaluated_at=state.last_evaluated_at,
        )

    # =========================================================================
    # 9. WORKFLOW HISTORY
    # =========================================================================

    @classmethod
    def get_workflow_history(
        cls,
        db: Session,
        incident_id: str,
        workspace_id: str = "default",
    ) -> WorkflowHistoryResponse:
        """
        Retrieves complete workflow execution and SLA pause history.
        """
        executions = (
            db.query(IncidentWorkflowExecutionModel)
            .filter(
                IncidentWorkflowExecutionModel.incident_id == incident_id,
                IncidentWorkflowExecutionModel.workspace_id == workspace_id,
            )
            .order_by(IncidentWorkflowExecutionModel.executed_at.desc())
            .all()
        )

        pauses = (
            db.query(IncidentSLAPauseLogModel)
            .filter(
                IncidentSLAPauseLogModel.incident_id == incident_id,
                IncidentSLAPauseLogModel.workspace_id == workspace_id,
            )
            .order_by(IncidentSLAPauseLogModel.timestamp.desc())
            .all()
        )

        exec_items = []
        for e in executions:
            try:
                dt = json.loads(e.details_json or "{}")
            except Exception:
                dt = {}
            exec_items.append(
                WorkflowExecutionItemResponse(
                    id=e.id,
                    incident_id=e.incident_id,
                    execution_key=e.execution_key,
                    policy_id=e.policy_id,
                    rule_id=e.rule_id,
                    escalation_level=e.escalation_level,
                    action_type=e.action_type,
                    target=e.target,
                    status=e.status,
                    executed_at=e.executed_at,
                    details=dt,
                )
            )

        pause_items = [
            {
                "id": p.id,
                "incident_id": p.incident_id,
                "action": p.action,
                "actor": p.actor,
                "reason": p.reason,
                "timestamp": p.timestamp,
                "paused_duration_seconds": p.paused_duration_seconds,
            }
            for p in pauses
        ]

        return WorkflowHistoryResponse(
            incident_id=incident_id,
            executions=exec_items,
            pause_logs=pause_items,
            total_executions=len(exec_items),
        )

    # =========================================================================
    # 10. POLICY SIMULATION / DRY RUN (Requirement 37)
    # =========================================================================

    @classmethod
    def simulate_policy(
        cls,
        db: Session,
        req: PolicySimulationRequest,
        workspace_id: str = "default",
    ) -> PolicySimulationResponse:
        """
        Safe policy dry-run / simulation without modifying database records.
        """
        cls.ensure_default_policies(db, workspace_id)

        # Mock incident
        mock_inc = IncidentModel(
            id="simulation-id",
            incident_number="INC-SIM-00001",
            workspace_id=workspace_id,
            title="Simulated Incident",
            status=req.status,
            severity=req.severity,
            priority=req.priority,
            category=req.category,
            risk_score=req.risk_score,
            created_at=datetime.now(timezone.utc) - timedelta(minutes=req.unacknowledged_minutes),
            opened_at=datetime.now(timezone.utc) - timedelta(minutes=req.unacknowledged_minutes),
        )

        matched_policy = cls.match_sla_policy(db, mock_inc, workspace_id)

        # Milestone status check
        ack_target = matched_policy.acknowledgement_target_minutes
        inv_target = matched_policy.investigation_target_minutes
        cont_target = matched_policy.containment_target_minutes
        res_target = matched_policy.resolution_target_minutes
        warn_pct = matched_policy.warning_threshold_pct / 100.0

        ack_status = "RUNNING"
        if req.unacknowledged_minutes >= ack_target:
            ack_status = "BREACHED"
        elif req.unacknowledged_minutes >= ack_target * warn_pct:
            ack_status = "WARNING"

        sim_milestones = {
            "ACKNOWLEDGEMENT": ack_status,
            "INVESTIGATION": "RUNNING",
            "CONTAINMENT": "BREACHED" if req.uncontained_minutes >= cont_target else "RUNNING",
            "RESOLUTION": "RUNNING",
        }

        # Simulate escalations
        triggered_rules = []
        if matched_policy.escalation_policy_id:
            esc_pol = (
                db.query(IncidentEscalationPolicyModel)
                .filter(IncidentEscalationPolicyModel.id == matched_policy.escalation_policy_id)
                .first()
            )
            if esc_pol:
                for r in esc_pol.rules:
                    if (
                        (r.condition_type == "SLA_BREACH" and ack_status == "BREACHED")
                        or (r.condition_type == "SLA_WARNING" and ack_status == "WARNING")
                    ):
                        triggered_rules.append({
                            "level": r.level,
                            "action_type": r.action_type,
                            "target": r.target_user or r.target_team or r.target_role,
                            "note_template": r.note_template,
                        })

        # Simulate routing
        routing_target = None
        team_target = None
        rules = (
            db.query(IncidentRoutingRuleModel)
            .filter(
                IncidentRoutingRuleModel.workspace_id == workspace_id,
                IncidentRoutingRuleModel.enabled == True,
            )
            .order_by(IncidentRoutingRuleModel.priority_order.asc())
            .all()
        )
        for r in rules:
            if (
                (r.category == "ANY" or r.category == req.category)
                and (r.severity == "ANY" or r.severity == req.severity)
                and (req.risk_score >= r.min_risk_score)
            ):
                cands = json.loads(r.candidate_analysts_json or "[]")
                routing_target = r.target_user_id or (cands[0] if cands else None)
                team_target = r.target_team_id
                break

        summary = (
            f"Dry Run Result: Matched policy '{matched_policy.name}'. "
            f"Acknowledgement SLA status: {ack_status} (elapsed: {req.unacknowledged_minutes}m, target: {ack_target}m). "
            f"Triggered escalations: {len(triggered_rules)}. "
            f"Routing target: {routing_target or 'None'} ({team_target or 'No team'})."
        )

        return PolicySimulationResponse(
            matched_sla_policy=matched_policy.name,
            matched_sla_policy_id=matched_policy.id,
            matched_sla_targets={
                "acknowledgement": ack_target,
                "investigation": inv_target,
                "containment": cont_target,
                "resolution": res_target,
            },
            simulated_milestone_status=sim_milestones,
            triggered_escalation_rules=triggered_rules,
            simulated_routing_target=routing_target,
            simulated_team_target=team_target,
            dry_run_summary=summary,
        )
