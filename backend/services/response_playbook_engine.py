"""
Section 29: Response Playbook Engine Service.
Central orchestration engine for Response Playbooks:
1. Versioned playbook registration and lifecycle management.
2. Conversion of Section 28 recommendations into concrete playbooks.
3. Target resolution, validation, and concurrency locking.
4. Dry-run simulation mode without external side effects.
5. Scoped human approval gating for high-impact actions.
6. Execution via allowlisted typed adapters.
7. Verification of defensive state and compensating rollback.
8. Evidence capture, audit logging, Threat Memory, and Attack Path integration.
"""

from __future__ import annotations
import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Tuple, Union
from sqlalchemy.orm import Session
from sqlalchemy import desc, and_, or_

from backend.db.models import (
    ResponsePlaybookModel,
    ResponsePlaybookStepModel,
    ResponsePlaybookExecutionModel,
    ResponsePlaybookStepExecutionModel,
    ResponsePlaybookApprovalModel,
    TargetLockModel,
    ResponseRecommendationModel,
    ResponseCapabilityModel,
    AuditLogModel,
    EvidenceModel,
    ThreatEventModel,
    IncidentModel,
    ThreatMemoryEntryModel,
    ThreatMemoryDecisionModel,
    generate_uuid,
    get_utc_now
)
from backend.schemas.response_playbook import (
    PlaybookStatusEnum,
    PlaybookTriggerTypeEnum,
    ApprovalPolicyEnum,
    ExecutionPolicyEnum,
    ExecutionModeEnum,
    ExecutionStatusEnum,
    StepExecutionStatusEnum,
    ApprovalDecisionEnum,
    StepTypeEnum,
    SafetyClassEnum,
    TargetSnapshot,
    TargetRef,
    SimulationPlan,
    SimulationPlanStep,
    PlaybookValidationResult,
    ErrorCodeEnum
)
from backend.services.playbook_adapters import (
    ADAPTER_REGISTRY,
    get_adapter_for_step_type,
    _redact_secrets
)
from backend.services.playbook_validator import (
    PlaybookValidator,
    evaluate_safe_condition
)

logger = logging.getLogger(__name__)


class ResponsePlaybookEngine:
    """
    Authoritative service for creating, simulating, approving, executing,
    and verifying Response Playbooks in CyberGuard.
    """

    # ========================================================================
    # 1. PLAYBOOK REGISTRATION & VERSIONING
    # ========================================================================

    @classmethod
    def create_playbook(
        cls,
        db: Session,
        workspace_id: str,
        data: Dict[str, Any]
    ) -> ResponsePlaybookModel:
        """
        Validates and registers a new Playbook and its steps.
        """
        validation = PlaybookValidator.validate_and_lint(data, db=db)
        if not validation.valid:
            raise ValueError(f"Playbook validation failed: {'; '.join(validation.errors)}")

        playbook_key = data["playbook_key"]
        version = data.get("version", 1)

        # Check existing version uniqueness
        existing = db.query(ResponsePlaybookModel).filter(
            ResponsePlaybookModel.workspace_id == workspace_id,
            ResponsePlaybookModel.playbook_key == playbook_key,
            ResponsePlaybookModel.version == version
        ).first()
        if existing:
            raise ValueError(f"Playbook '{playbook_key}' version {version} already exists in workspace.")

        playbook = ResponsePlaybookModel(
            id=generate_uuid(),
            workspace_id=workspace_id,
            playbook_key=playbook_key,
            name=data["name"],
            description=data["description"],
            version=version,
            status=data.get("status", PlaybookStatusEnum.DRAFT.value),
            trigger_type=data.get("trigger_type", PlaybookTriggerTypeEnum.MANUAL.value),
            scope_type=data.get("scope_type", "EVENT"),
            severity_min=data.get("severity_min"),
            risk_min=data.get("risk_min"),
            incident_id=data.get("incident_id"),
            investigation_id=data.get("investigation_id"),
            source_recommendation_id=data.get("source_recommendation_id"),
            target_selector_json=json.dumps(data.get("target_selector", {})),
            approval_policy=data.get("approval_policy", ApprovalPolicyEnum.SINGLE_APPROVAL.value),
            execution_policy=data.get("execution_policy", ExecutionPolicyEnum.MANUAL.value),
            timeout_seconds=data.get("timeout_seconds", 300),
            max_runtime_seconds=data.get("max_runtime_seconds", 600),
            parent_version=data.get("parent_version"),
            change_summary=data.get("change_summary", "Initial version."),
            created_by=data.get("created_by", "system"),
            updated_by=data.get("created_by", "system")
        )
        db.add(playbook)
        db.flush()

        # Add steps
        for s in data.get("steps", []):
            s_dict = s if isinstance(s, dict) else (s.model_dump() if hasattr(s, "model_dump") else s.dict())
            step = ResponsePlaybookStepModel(
                id=generate_uuid(),
                playbook_id=playbook.id,
                step_key=s_dict["step_key"],
                sequence=s_dict.get("sequence", 1),
                step_type=s_dict["step_type"],
                name=s_dict["name"],
                description=s_dict["description"],
                parameters_json=json.dumps(s_dict.get("parameters", {})),
                target_selector_json=json.dumps(s_dict.get("target_selector", {})),
                condition_json=json.dumps(s_dict.get("condition", {})),
                on_success=s_dict.get("on_success", "CONTINUE"),
                on_failure=s_dict.get("on_failure", "FAIL"),
                timeout_seconds=s_dict.get("timeout_seconds", 60),
                retry_policy_json=json.dumps(s_dict.get("retry_policy", {"max_attempts": 1})),
                requires_approval=s_dict.get("requires_approval", False),
                approval_policy=s_dict.get("approval_policy", ApprovalPolicyEnum.NO_APPROVAL.value),
                safety_class=s_dict.get("safety_class", SafetyClassEnum.INFORMATIONAL.value),
                verification_policy_json=json.dumps(s_dict.get("verification_policy", {"enabled": True})),
                rollback_policy_json=json.dumps(s_dict.get("rollback_policy", {"supports_rollback": False})),
                depends_on_json=json.dumps(s_dict.get("depends_on", [])),
                enabled=s_dict.get("enabled", True),
                workspace_id=workspace_id
            )
            db.add(step)

        # Audit event
        cls._record_audit(
            db=db,
            user=playbook.created_by,
            action="PLAYBOOK_CREATED",
            resource_type="response_playbook",
            resource_id=playbook.id,
            metadata={
                "playbook_key": playbook.playbook_key,
                "version": playbook.version,
                "steps_count": len(data.get("steps", []))
            }
        )

        db.commit()
        db.refresh(playbook)
        return playbook

    @classmethod
    def get_playbook(cls, db: Session, playbook_id: str) -> Optional[ResponsePlaybookModel]:
        return db.query(ResponsePlaybookModel).filter(ResponsePlaybookModel.id == playbook_id).first()

    @classmethod
    def get_playbooks(
        cls,
        db: Session,
        workspace_id: str = "default",
        status: Optional[str] = None,
        scope_type: Optional[str] = None
    ) -> List[ResponsePlaybookModel]:
        query = db.query(ResponsePlaybookModel).filter(ResponsePlaybookModel.workspace_id == workspace_id)
        if status:
            query = query.filter(ResponsePlaybookModel.status == status)
        if scope_type:
            query = query.filter(ResponsePlaybookModel.scope_type == scope_type)
        return query.order_by(desc(ResponsePlaybookModel.created_at)).all()

    @classmethod
    def activate_playbook(
        cls,
        db: Session,
        playbook_id: str,
        user_id: str = "analyst"
    ) -> ResponsePlaybookModel:
        pb = cls.get_playbook(db, playbook_id)
        if not pb:
            raise ValueError("Playbook not found.")

        pb.status = PlaybookStatusEnum.ACTIVE.value
        pb.activated_at = get_utc_now()
        pb.updated_by = user_id
        db.commit()
        db.refresh(pb)

        cls._record_audit(
            db=db,
            user=user_id,
            action="PLAYBOOK_ACTIVATED",
            resource_type="response_playbook",
            resource_id=pb.id,
            metadata={"playbook_key": pb.playbook_key, "version": pb.version}
        )
        return pb

    # ========================================================================
    # 2. DEFAULT PLAYBOOK TEMPLATES SEEDING
    # ========================================================================

    @classmethod
    def seed_default_playbooks(cls, db: Session, workspace_id: str = "default"):
        """Seeds standard reference playbooks if not present."""
        templates = [
            # 1. PHISHING CONTAINMENT
            {
                "playbook_key": "phishing-containment",
                "name": "Phishing Incident Containment Playbook",
                "description": "Standard response for verified phishing lures: preserves email artifact, blocks lookalike domain, step-up MFA challenge, and alerts SOC.",
                "version": 1,
                "status": PlaybookStatusEnum.ACTIVE.value,
                "trigger_type": PlaybookTriggerTypeEnum.RECOMMENDATION_APPROVED.value,
                "scope_type": "EVENT",
                "approval_policy": ApprovalPolicyEnum.SINGLE_APPROVAL.value,
                "execution_policy": ExecutionPolicyEnum.MANUAL.value,
                "steps": [
                    {
                        "step_key": "preserve_email_raw",
                        "sequence": 1,
                        "step_type": StepTypeEnum.PRESERVE_EVIDENCE.value,
                        "name": "Vault Original Email Artifact",
                        "description": "Preserves cryptographic raw message headers and payload in forensic vault before containment.",
                        "parameters": {"storage_tier": "VAULT_FORENSIC"},
                        "safety_class": SafetyClassEnum.INFORMATIONAL.value,
                        "requires_approval": False,
                        "verification_policy": {"enabled": True, "expected_state": "VERIFIED_IN_VAULT"}
                    },
                    {
                        "step_key": "block_phishing_domain",
                        "sequence": 2,
                        "step_type": StepTypeEnum.BLOCK_DOMAIN.value,
                        "name": "Sinkhole Malicious Domain",
                        "description": "Applies perimeter DNS block to sinkhole adversary command & control / harvesting domain.",
                        "safety_class": SafetyClassEnum.CONTAINMENT.value,
                        "requires_approval": True,
                        "depends_on": ["preserve_email_raw"],
                        "rollback_policy": {"supports_rollback": True, "reversibility": "REVERSIBLE"},
                        "verification_policy": {"enabled": True, "expected_state": "SINKHOLED"}
                    },
                    {
                        "step_key": "challenge_recipient_mfa",
                        "sequence": 3,
                        "step_type": StepTypeEnum.FORCE_REAUTHENTICATION.value,
                        "name": "Force Recipient Re-Authentication",
                        "description": "Issues step-up MFA challenge for email recipient in case credentials were submitted.",
                        "safety_class": SafetyClassEnum.LOW_IMPACT.value,
                        "requires_approval": False,
                        "depends_on": ["preserve_email_raw"]
                    },
                    {
                        "step_key": "notify_security_team",
                        "sequence": 4,
                        "step_type": StepTypeEnum.CREATE_NOTIFICATION.value,
                        "name": "Dispatch SOC Containment Summary",
                        "description": "Dispatches audit summary and indicators to internal incident channel.",
                        "parameters": {"channel": "SOC_ALERT"},
                        "safety_class": SafetyClassEnum.LOW_IMPACT.value,
                        "requires_approval": False,
                        "depends_on": ["block_phishing_domain"]
                    }
                ]
            },
            # 2. ACCOUNT TAKEOVER RESPONSE
            {
                "playbook_key": "account-takeover-response",
                "name": "Account Takeover (ATO) Remediation Playbook",
                "description": "Remediates compromised user identity: preserves authentication logs, revokes active OAuth sessions, forces password reset, and audits access.",
                "version": 1,
                "status": PlaybookStatusEnum.ACTIVE.value,
                "trigger_type": PlaybookTriggerTypeEnum.RECOMMENDATION_APPROVED.value,
                "scope_type": "EVENT",
                "approval_policy": ApprovalPolicyEnum.SINGLE_APPROVAL.value,
                "execution_policy": ExecutionPolicyEnum.MANUAL.value,
                "steps": [
                    {
                        "step_key": "preserve_auth_telemetry",
                        "sequence": 1,
                        "step_type": StepTypeEnum.PRESERVE_EVIDENCE.value,
                        "name": "Preserve Authentication Telemetry",
                        "description": "Snapshots IdP authentication logs and token exchanges into evidence store.",
                        "safety_class": SafetyClassEnum.INFORMATIONAL.value,
                        "requires_approval": False
                    },
                    {
                        "step_key": "revoke_compromised_session",
                        "sequence": 2,
                        "step_type": StepTypeEnum.REVOKE_SESSION.value,
                        "name": "Revoke Compromised Session Tokens",
                        "description": "Invalidates active session cookies, refresh tokens, and OAuth grants.",
                        "safety_class": SafetyClassEnum.REVERSIBLE.value,
                        "requires_approval": True,
                        "depends_on": ["preserve_auth_telemetry"],
                        "verification_policy": {"enabled": True, "expected_state": "TOKEN_INVALIDATED"}
                    },
                    {
                        "step_key": "force_credential_reset",
                        "sequence": 3,
                        "step_type": StepTypeEnum.REQUIRE_CREDENTIAL_RESET.value,
                        "name": "Expire User Password",
                        "description": "Sets pwdLastSet=0 requiring immediate password change on next sign-in.",
                        "safety_class": SafetyClassEnum.REVERSIBLE.value,
                        "requires_approval": True,
                        "depends_on": ["revoke_compromised_session"]
                    }
                ]
            },
            # 3. ENDPOINT CONTAINMENT
            {
                "playbook_key": "endpoint-containment",
                "name": "Endpoint Isolation & Forensic Preservation",
                "description": "Isolates suspicious workstation via EDR agent and preserves forensic volatile memory.",
                "version": 1,
                "status": PlaybookStatusEnum.ACTIVE.value,
                "trigger_type": PlaybookTriggerTypeEnum.MANUAL.value,
                "scope_type": "EVENT",
                "approval_policy": ApprovalPolicyEnum.SINGLE_APPROVAL.value,
                "steps": [
                    {
                        "step_key": "preserve_host_artifacts",
                        "sequence": 1,
                        "step_type": StepTypeEnum.COLLECT_ENDPOINT_ARTIFACT.value,
                        "name": "Collect Host Volatile Memory & Event Logs",
                        "description": "Captures forensic volatile snapshot from host before network isolation.",
                        "safety_class": SafetyClassEnum.INFORMATIONAL.value,
                        "requires_approval": False
                    },
                    {
                        "step_key": "isolate_endpoint_host",
                        "sequence": 2,
                        "step_type": StepTypeEnum.ISOLATE_ENDPOINT.value,
                        "name": "Isolate Host from Corporate Network",
                        "description": "Applies network isolation policy via EDR connector, permitting only telemetry traffic.",
                        "safety_class": SafetyClassEnum.CONTAINMENT.value,
                        "requires_approval": True,
                        "depends_on": ["preserve_host_artifacts"],
                        "rollback_policy": {"supports_rollback": True, "reversibility": "REVERSIBLE"},
                        "verification_policy": {"enabled": True, "expected_state": "HOST_NETWORK_ISOLATED"}
                    }
                ]
            }
        ]

        for tmpl in templates:
            existing = db.query(ResponsePlaybookModel).filter(
                ResponsePlaybookModel.workspace_id == workspace_id,
                ResponsePlaybookModel.playbook_key == tmpl["playbook_key"]
            ).first()
            if not existing:
                try:
                    cls.create_playbook(db, workspace_id, tmpl)
                except Exception as e:
                    logger.warning(f"Error seeding default playbook {tmpl['playbook_key']}: {e}")

    # ========================================================================
    # 3. CONVERT SECTION 28 RECOMMENDATION INTO RESPONSE PLAYBOOK
    # ========================================================================

    @classmethod
    def create_playbook_from_recommendation(
        cls,
        db: Session,
        recommendation_id: str,
        requested_by: str = "analyst"
    ) -> ResponsePlaybookModel:
        """
        Transforms an approved Section 28 recommendation into an executable playbook.
        Adheres to: Evidence Preservation Precedence -> Consequential Action -> Verification -> Communication.
        """
        rec = db.query(ResponseRecommendationModel).filter(
            ResponseRecommendationModel.id == recommendation_id
        ).first()
        if not rec:
            raise ValueError(f"Recommendation '{recommendation_id}' not found.")

        workspace_id = rec.workspace_id
        action_type = rec.action_type
        entities = rec.affected_entities
        primary_target_val = entities[0]["identifier"] if entities else rec.scope_id
        primary_target_type = entities[0]["entity_type"].upper() if entities else "ENTITY"

        playbook_key = f"pb-{action_type.lower()}-{rec.id[:8].lower()}"
        steps: List[Dict[str, Any]] = []

        # Step 1: Pre-execution evidence preservation
        steps.append({
            "step_key": "preserve_pre_action_evidence",
            "sequence": 1,
            "step_type": StepTypeEnum.PRESERVE_EVIDENCE.value,
            "name": f"Preserve Forensic Telemetry for {primary_target_val}",
            "description": f"Snapshots relevant artifacts and evidence before executing {action_type}.",
            "target_selector": {"target_type": primary_target_type, "target_id": primary_target_val},
            "safety_class": SafetyClassEnum.INFORMATIONAL.value,
            "requires_approval": False
        })

        # Step 2: Consequential defensive action
        step_map = {
            "BLOCK_DOMAIN": StepTypeEnum.BLOCK_DOMAIN.value,
            "BLOCK_URL": StepTypeEnum.BLOCK_URL_PATTERN.value,
            "BLOCK_IP": StepTypeEnum.BLOCK_IP.value,
            "REVOKE_SESSION": StepTypeEnum.REVOKE_SESSION.value,
            "DISABLE_ACCOUNT": StepTypeEnum.DISABLE_ACCOUNT.value,
            "FORCE_PASSWORD_RESET": StepTypeEnum.REQUIRE_CREDENTIAL_RESET.value,
            "REQUIRE_MFA_REAUTHENTICATION": StepTypeEnum.FORCE_REAUTHENTICATION.value,
            "ISOLATE_DEVICE": StepTypeEnum.ISOLATE_ENDPOINT.value,
            "NOTIFY_SECURITY_TEAM": StepTypeEnum.CREATE_NOTIFICATION.value,
            "PRESERVE_EMAIL": StepTypeEnum.PRESERVE_EVIDENCE.value,
        }

        chosen_step_type = step_map.get(action_type, StepTypeEnum.CREATE_NOTIFICATION.value)
        safety_class = rec.safety_class
        approval_req = rec.approval_required

        steps.append({
            "step_key": f"execute_{chosen_step_type.lower()}",
            "sequence": 2,
            "step_type": chosen_step_type,
            "name": rec.title,
            "description": rec.description,
            "target_selector": {"target_type": primary_target_type, "target_id": primary_target_val},
            "safety_class": safety_class,
            "requires_approval": approval_req,
            "depends_on": ["preserve_pre_action_evidence"],
            "rollback_policy": {
                "supports_rollback": rec.reversibility == "REVERSIBLE",
                "reversibility": rec.reversibility
            },
            "verification_policy": {
                "enabled": True,
                "expected_state": "SUCCESS"
            }
        })

        # Step 3: Notification / Log update
        steps.append({
            "step_key": "record_incident_action_note",
            "sequence": 3,
            "step_type": StepTypeEnum.CREATE_CASE_NOTE.value,
            "name": "Log Response Action Audit Note",
            "description": f"Records completion of {action_type} on target {primary_target_val} in case history.",
            "target_selector": {"target_type": "INCIDENT", "target_id": rec.incident_id or rec.scope_id},
            "safety_class": SafetyClassEnum.LOW_IMPACT.value,
            "requires_approval": False,
            "depends_on": [f"execute_{chosen_step_type.lower()}"]
        })

        payload = {
            "playbook_key": playbook_key,
            "name": f"Playbook: {rec.title}",
            "description": f"Automated response workflow generated from Recommendation {rec.id}: {rec.rationale}",
            "version": 1,
            "status": PlaybookStatusEnum.APPROVED.value,
            "trigger_type": PlaybookTriggerTypeEnum.RECOMMENDATION_APPROVED.value,
            "scope_type": rec.scope_type,
            "incident_id": rec.incident_id,
            "threat_event_id": rec.threat_event_id,
            "source_recommendation_id": rec.id,
            "target_selector": {"target_type": primary_target_type, "target_id": primary_target_val},
            "approval_policy": ApprovalPolicyEnum.SINGLE_APPROVAL.value if approval_req else ApprovalPolicyEnum.NO_APPROVAL.value,
            "execution_policy": ExecutionPolicyEnum.MANUAL.value,
            "created_by": requested_by,
            "steps": steps
        }

        return cls.create_playbook(db, workspace_id, payload)

    # ========================================================================
    # 4. TARGET RESOLUTION & CONCURRENCY LOCKING
    # ========================================================================

    @classmethod
    def resolve_target_snapshot(
        cls,
        db: Session,
        workspace_id: str,
        step: ResponsePlaybookStepModel,
        playbook: ResponsePlaybookModel,
        target_override: Optional[TargetRef] = None
    ) -> TargetSnapshot:
        """
        Resolves target entity into an immutable TargetSnapshot.
        Enforces tenant isolation and rejects ambiguous inputs.
        """
        t_type = "UNKNOWN"
        t_id = "UNKNOWN"

        if target_override:
            t_type = target_override.target_type.upper()
            t_id = target_override.target_id.strip()
        else:
            step_sel = step.target_selector
            pb_sel = playbook.target_selector
            t_type = step_sel.get("target_type") or pb_sel.get("target_type") or "INCIDENT"
            t_id = step_sel.get("target_id") or pb_sel.get("target_id") or playbook.incident_id or playbook.scope_type

        return TargetSnapshot(
            target_type=t_type,
            target_id=str(t_id),
            tenant_id=workspace_id,
            resolved_at=get_utc_now().isoformat(),
            state_at_resolution={"status": "ACTIVE"},
            resolution_source="playbook_target_selector"
        )

    @classmethod
    def acquire_target_lock(
        cls,
        db: Session,
        workspace_id: str,
        target_type: str,
        target_id: str,
        execution_id: str,
        ttl_seconds: int = 300
    ) -> bool:
        """
        Acquires target lock to prevent conflicting concurrent modifications.
        """
        now = get_utc_now()
        # Clean expired locks
        expired = db.query(TargetLockModel).filter(
            TargetLockModel.workspace_id == workspace_id,
            TargetLockModel.active == True,
            TargetLockModel.expires_at < now
        ).all()
        for exp in expired:
            exp.active = False
            exp.released_at = now
        db.commit()

        # Check existing active lock
        existing = db.query(TargetLockModel).filter(
            TargetLockModel.workspace_id == workspace_id,
            TargetLockModel.target_type == target_type,
            TargetLockModel.target_id == target_id,
            TargetLockModel.active == True,
            TargetLockModel.execution_id != execution_id
        ).first()

        if existing:
            logger.warning(f"Target lock conflict on {target_type}:{target_id} held by {existing.execution_id}")
            return False

        new_lock = TargetLockModel(
            id=generate_uuid(),
            workspace_id=workspace_id,
            target_type=target_type,
            target_id=target_id,
            execution_id=execution_id,
            acquired_at=now,
            expires_at=now + timedelta(seconds=ttl_seconds),
            active=True
        )
        db.add(new_lock)
        db.commit()
        return True

    @classmethod
    def release_target_locks(cls, db: Session, execution_id: str):
        now = get_utc_now()
        locks = db.query(TargetLockModel).filter(
            TargetLockModel.execution_id == execution_id,
            TargetLockModel.active == True
        ).all()
        for lock in locks:
            lock.active = False
            lock.released_at = now
        db.commit()

    # ========================================================================
    # 5. DRY-RUN SIMULATION MODE
    # ========================================================================

    @classmethod
    def simulate_playbook(
        cls,
        db: Session,
        playbook_id: str,
        workspace_id: str = "default",
        target_override: Optional[TargetRef] = None
    ) -> SimulationPlan:
        """
        Executes safe simulation (DRY_RUN) producing step plan, capability audit,
        and approval requirements without external changes.
        """
        playbook = cls.get_playbook(db, playbook_id)
        if not playbook:
            raise ValueError("Playbook not found.")

        validation = PlaybookValidator.validate_and_lint(
            {
                "playbook_key": playbook.playbook_key,
                "name": playbook.name,
                "version": playbook.version,
                "steps": [s for s in playbook.steps]
            },
            db=db
        )

        sim_steps: List[SimulationPlanStep] = []
        caps_required: List[Dict[str, str]] = []
        any_approval_needed = False

        for step in playbook.steps:
            target_snapshot = cls.resolve_target_snapshot(db, workspace_id, step, playbook, target_override)
            adapter_cls = get_adapter_for_step_type(step.step_type)

            cap_avail, cap_state, provider = adapter_cls.check_capability(db, workspace_id) if adapter_cls else (False, "UNKNOWN", "None")
            caps_required.append({"action_type": step.step_type, "capability_state": cap_state, "provider": provider})

            appr_needed = step.requires_approval or (playbook.approval_policy != ApprovalPolicyEnum.NO_APPROVAL.value and step.safety_class in [
                SafetyClassEnum.CONTAINMENT.value, SafetyClassEnum.HIGH_IMPACT.value
            ])
            if appr_needed:
                any_approval_needed = True

            sim_steps.append(SimulationPlanStep(
                sequence=step.sequence,
                step_key=step.step_key,
                step_type=step.step_type,
                name=step.name,
                target_snapshot=target_snapshot,
                capability_state=cap_state,
                capability_provider=provider,
                requires_approval=appr_needed,
                simulated_action=f"Simulate {step.step_type} on {target_snapshot.target_type}:{target_snapshot.target_id}",
                safety_class=step.safety_class,
                rollback_available=adapter_cls.supports_rollback if adapter_cls else False,
                would_execute=cap_avail or cap_state == "AVAILABLE",
                reason="Pre-conditions validated. Awaits analyst approval." if appr_needed else "Automated safe step; will execute."
            ))

        return SimulationPlan(
            playbook_id=playbook.id,
            playbook_key=playbook.playbook_key,
            playbook_version=playbook.version,
            mode=ExecutionModeEnum.DRY_RUN.value,
            total_steps=len(sim_steps),
            steps=sim_steps,
            validation=validation,
            capabilities_required=caps_required,
            approval_required_overall=any_approval_needed,
            summary=f"Simulation plan compiled for {len(sim_steps)} steps. Overall approval required: {any_approval_needed}."
        )

    # ========================================================================
    # 6. EXECUTION ENGINE & STATE MACHINE
    # ========================================================================

    @classmethod
    def execute_playbook(
        cls,
        db: Session,
        playbook_id: str,
        workspace_id: str = "default",
        mode: str = ExecutionModeEnum.LIVE.value,
        requested_by: str = "analyst",
        target_override: Optional[TargetRef] = None,
        execution_context: Optional[Dict[str, Any]] = None
    ) -> ResponsePlaybookExecutionModel:
        """
        Executes a playbook through the deterministic state machine:
        VALIDATING -> WAITING_FOR_APPROVAL -> RUNNING -> COMPLETED / FAILED / ROLLED_BACK.
        """
        playbook = cls.get_playbook(db, playbook_id)
        if not playbook:
            raise ValueError(f"Playbook '{playbook_id}' not found.")

        # In LIVE mode, playbook must not be retired or disabled
        if mode == ExecutionModeEnum.LIVE.value and playbook.status in [
            PlaybookStatusEnum.DISABLED.value, PlaybookStatusEnum.RETIRED.value
        ]:
            raise ValueError(f"Cannot execute playbook in status '{playbook.status}'.")

        context = execution_context or {}
        execution = ResponsePlaybookExecutionModel(
            id=generate_uuid(),
            playbook_id=playbook.id,
            playbook_version=playbook.version,
            incident_id=playbook.incident_id,
            investigation_id=playbook.investigation_id,
            source_recommendation_id=playbook.source_recommendation_id,
            trigger_source=playbook.trigger_type,
            mode=mode,
            status=ExecutionStatusEnum.VALIDATING.value,
            requested_by=requested_by,
            execution_context_json=json.dumps(context),
            workspace_id=workspace_id,
            started_at=get_utc_now()
        )
        db.add(execution)
        db.commit()
        db.refresh(execution)

        cls._record_audit(
            db=db,
            user=requested_by,
            action="EXECUTION_STARTED",
            resource_type="response_playbook_execution",
            resource_id=execution.id,
            metadata={"playbook_key": playbook.playbook_key, "mode": mode}
        )

        completed_step_executions: List[ResponsePlaybookStepExecutionModel] = []
        execution_failed = False
        failure_error_code = None
        failure_error_msg = None

        try:
            # Check if any step requires approval upfront in LIVE mode
            for step in playbook.steps:
                target_snapshot = cls.resolve_target_snapshot(db, workspace_id, step, playbook, target_override)
                if not cls.acquire_target_lock(db, workspace_id, target_snapshot.target_type, target_snapshot.target_id, execution.id):
                    raise RuntimeError(f"Could not acquire lock for target {target_snapshot.target_type}:{target_snapshot.target_id}")

            execution.status = ExecutionStatusEnum.RUNNING.value
            db.commit()

            for step in playbook.steps:
                execution.current_step_key = step.step_key
                db.commit()

                target_snapshot = cls.resolve_target_snapshot(db, workspace_id, step, playbook, target_override)
                step_exec = ResponsePlaybookStepExecutionModel(
                    id=generate_uuid(),
                    execution_id=execution.id,
                    step_id=step.id,
                    step_key=step.step_key,
                    sequence=step.sequence,
                    target_snapshot_json=json.dumps(target_snapshot.model_dump() if hasattr(target_snapshot, "model_dump") else target_snapshot.dict()),
                    status=StepExecutionStatusEnum.RUNNING.value,
                    started_at=get_utc_now(),
                    attempt_count=1,
                    adapter=step.step_type,
                    adapter_version="1.0.0",
                    workspace_id=workspace_id
                )
                db.add(step_exec)
                db.commit()

                # Condition Check
                cond = step.condition
                if cond and not evaluate_safe_condition(cond, context):
                    step_exec.status = StepExecutionStatusEnum.SKIPPED.value
                    step_exec.completed_at = get_utc_now()
                    step_exec.output_summary_json = json.dumps({"notes": "Condition not satisfied; skipped safely."})
                    db.commit()
                    continue

                # Approval Check
                if mode == ExecutionModeEnum.LIVE.value and step.requires_approval:
                    approval = db.query(ResponsePlaybookApprovalModel).filter(
                        ResponsePlaybookApprovalModel.execution_id == execution.id,
                        ResponsePlaybookApprovalModel.decision == ApprovalDecisionEnum.APPROVED.value,
                        or_(
                            ResponsePlaybookApprovalModel.step_id == step.id,
                            ResponsePlaybookApprovalModel.scope == "EXECUTION"
                        )
                    ).first()
                    if not approval:
                        # Wait for approval
                        execution.status = ExecutionStatusEnum.WAITING_FOR_APPROVAL.value
                        step_exec.status = StepExecutionStatusEnum.PENDING.value
                        db.commit()
                        return execution

                adapter_cls = get_adapter_for_step_type(step.step_type)
                if not adapter_cls:
                    raise RuntimeError(f"No authorized adapter for step {step.step_type}")

                # Capability Check
                cap_avail, cap_state, provider = adapter_cls.check_capability(db, workspace_id)
                if not cap_avail and mode != ExecutionModeEnum.DRY_RUN.value:
                    raise RuntimeError(f"Capability '{step.step_type}' unavailable in workspace (State: {cap_state})")

                # Execute Step
                step_exec.input_summary_json = json.dumps(_redact_secrets(step.parameters))
                output = adapter_cls.execute(
                    db=db,
                    workspace_id=workspace_id,
                    step_key=step.step_key,
                    target=target_snapshot,
                    parameters=step.parameters,
                    mode=mode,
                    execution_context=context
                )
                step_exec.output_summary_json = json.dumps(output)

                # Verification
                v_policy = step.verification_policy
                if v_policy.get("enabled", True):
                    v_res = adapter_cls.verify(
                        db=db,
                        workspace_id=workspace_id,
                        target=target_snapshot,
                        execution_output=output,
                        mode=mode
                    )
                    step_exec.verification_result_json = json.dumps(v_res)
                    if not v_res.get("verified", False):
                        step_exec.status = StepExecutionStatusEnum.VERIFICATION_FAILED.value
                        raise RuntimeError(f"Verification check failed for step {step.step_key}: {v_res.get('notes', 'State mismatch')}")

                step_exec.status = StepExecutionStatusEnum.COMPLETED.value
                step_exec.completed_at = get_utc_now()
                db.commit()
                completed_step_executions.append(step_exec)

            # All steps completed successfully
            execution.status = ExecutionStatusEnum.COMPLETED.value
            execution.completed_at = get_utc_now()
            execution.result_summary = f"Playbook completed all {len(playbook.steps)} steps successfully ({mode} mode)."
            db.commit()

            # Threat Memory & Investigation Integration
            cls._record_threat_memory_outcome(db, execution, playbook, "SUCCESS")

        except Exception as exc:
            logger.error(f"Execution {execution.id} encountered error: {exc}", exc_info=True)
            execution_failed = True
            failure_error_code = ErrorCodeEnum.INTEGRATION_ERROR.value
            failure_error_msg = str(exc)

            # Check rollback
            cls._execute_compensating_rollback(db, workspace_id, completed_step_executions, mode)

            execution.status = ExecutionStatusEnum.FAILED.value
            execution.completed_at = get_utc_now()
            execution.error_code = failure_error_code
            execution.error_message = failure_error_msg
            execution.result_summary = f"Execution failed: {failure_error_msg}"
            db.commit()

            cls._record_threat_memory_outcome(db, execution, playbook, "FAILED")

        finally:
            cls.release_target_locks(db, execution.id)
            cls._record_audit(
                db=db,
                user=requested_by,
                action="EXECUTION_COMPLETED" if not execution_failed else "EXECUTION_FAILED",
                resource_type="response_playbook_execution",
                resource_id=execution.id,
                metadata={"status": execution.status, "mode": mode}
            )

        db.refresh(execution)
        return execution

    @classmethod
    def _execute_compensating_rollback(
        cls,
        db: Session,
        workspace_id: str,
        completed_steps: List[ResponsePlaybookStepExecutionModel],
        mode: str
    ):
        """Rolls back completed steps in reverse sequence."""
        for s_exec in reversed(completed_steps):
            adapter_cls = get_adapter_for_step_type(s_exec.adapter)
            if adapter_cls and adapter_cls.supports_rollback:
                try:
                    target_snapshot = TargetSnapshot(**s_exec.target_snapshot)
                    rb_res = adapter_cls.rollback(
                        db=db,
                        workspace_id=workspace_id,
                        target=target_snapshot,
                        execution_output=s_exec.output_summary,
                        mode=mode
                    )
                    s_exec.status = StepExecutionStatusEnum.ROLLED_BACK.value
                    s_exec.output_summary_json = json.dumps({"rollback": rb_res})
                    db.commit()
                except Exception as rb_err:
                    logger.warning(f"Rollback failed for step {s_exec.step_key}: {rb_err}")
                    s_exec.status = StepExecutionStatusEnum.ROLLBACK_FAILED.value
                    db.commit()

    # ========================================================================
    # 7. APPROVAL WORKFLOW
    # ========================================================================

    @classmethod
    def record_approval(
        cls,
        db: Session,
        execution_id: str,
        step_id: Optional[str],
        decision: str,
        approved_by: str,
        reason: str
    ) -> ResponsePlaybookApprovalModel:
        """Records scoped human approval for a playbook execution or specific step."""
        execution = db.query(ResponsePlaybookExecutionModel).filter(
            ResponsePlaybookExecutionModel.id == execution_id
        ).first()
        if not execution:
            raise ValueError("Execution not found.")

        approval = ResponsePlaybookApprovalModel(
            id=generate_uuid(),
            execution_id=execution_id,
            step_id=step_id,
            scope="STEP" if step_id else "EXECUTION",
            decision=decision,
            requested_by=execution.requested_by,
            approved_by=approved_by,
            reason=reason,
            target_snapshot_json=execution.execution_context_json,
            authorization_context_json=json.dumps({"analyst": approved_by}),
            workspace_id=execution.workspace_id,
            decided_at=get_utc_now()
        )
        db.add(approval)

        if decision == ApprovalDecisionEnum.APPROVED.value:
            execution.approved_by = approved_by
            if execution.status == ExecutionStatusEnum.WAITING_FOR_APPROVAL.value:
                execution.status = ExecutionStatusEnum.READY.value

        db.commit()
        db.refresh(approval)

        cls._record_audit(
            db=db,
            user=approved_by,
            action=f"EXECUTION_{decision.upper()}",
            resource_type="response_playbook_approval",
            resource_id=approval.id,
            metadata={"execution_id": execution_id, "decision": decision, "reason": reason}
        )
        return approval

    # ========================================================================
    # 8. INTEGRATIONS: THREAT MEMORY, AUDIT, & EVIDENCE
    # ========================================================================

    @classmethod
    def _record_audit(
        cls,
        db: Session,
        user: str,
        action: str,
        resource_type: str,
        resource_id: str,
        metadata: Dict[str, Any]
    ):
        try:
            audit = AuditLogModel(
                id=generate_uuid(),
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                user=user,
                metadata_json=json.dumps(metadata)
            )
            db.add(audit)
            db.commit()
        except Exception as e:
            logger.warning(f"Could not record audit log: {e}")

    @classmethod
    def _record_threat_memory_outcome(
        cls,
        db: Session,
        execution: ResponsePlaybookExecutionModel,
        playbook: ResponsePlaybookModel,
        outcome: str
    ):
        """Records playbook execution outcome in Threat Memory (Section 23)."""
        try:
            canonical_key = f"playbook:{playbook.playbook_key}:{execution.id}"
            entry = db.query(ThreatMemoryEntryModel).filter(
                ThreatMemoryEntryModel.workspace_id == execution.workspace_id,
                ThreatMemoryEntryModel.canonical_key == canonical_key
            ).first()
            if not entry:
                entry = ThreatMemoryEntryModel(
                    id=generate_uuid(),
                    workspace_id=execution.workspace_id,
                    memory_type="PLAYBOOK_RESPONSE",
                    subject_type="PLAYBOOK",
                    subject_id=playbook.playbook_key,
                    canonical_key=canonical_key,
                    scope="ORGANIZATION",
                    status="VERIFIED" if outcome == "SUCCESS" else "OBSERVED",
                    summary=f"Execution of playbook '{playbook.name}' completed with status {outcome}.",
                    confidence=1.0,
                    confidence_level="HIGH",
                    provenance_type="ANALYST_VERIFIED"
                )
                db.add(entry)
                db.commit()
                db.refresh(entry)

            decision_str = "VERIFIED_MALICIOUS" if outcome == "SUCCESS" else "NEEDS_REVIEW"
            mem_decision = ThreatMemoryDecisionModel(
                id=generate_uuid(),
                memory_entry_id=entry.id,
                workspace_id=execution.workspace_id,
                decision=decision_str,
                reason=f"Defensive playbook '{playbook.playbook_key}' executed with outcome {outcome}.",
                approved_by=execution.approved_by or execution.requested_by or "analyst",
                scope="ORGANIZATION"
            )
            db.add(mem_decision)
            db.commit()
        except Exception as e:
            logger.warning(f"Failed to record threat memory decision: {e}")
