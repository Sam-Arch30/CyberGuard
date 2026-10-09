"""
Unit and Integration Tests for Section 29: Response Playbooks.
Tests cover:
1. Playbook creation, validation, and DAG acyclicity.
2. Controlled step types allowlisting & prevention of arbitrary code.
3. Safe typed condition evaluation without eval().
4. Seeding reference playbooks (Phishing, ATO, Endpoint).
5. Translation of Section 28 recommendations into concrete playbooks.
6. Target locking and concurrency conflict prevention.
7. Dry-run simulation mode.
8. Approval gating for high-impact actions.
9. Step execution, state verification, and compensating rollback.
10. Immutable audit logs and Threat Memory recording.
11. Multi-tenant isolation.
"""

import json
import pytest
from datetime import datetime, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.db.session import Base
from backend.db.models import (
    ResponsePlaybookModel,
    ResponsePlaybookStepModel,
    ResponsePlaybookExecutionModel,
    ResponsePlaybookStepExecutionModel,
    ResponsePlaybookApprovalModel,
    ResponseRecommendationModel,
    ResponseCapabilityModel,
    ThreatEventModel,
    AuditLogModel,
    ThreatMemoryDecisionModel,
    generate_uuid,
    get_utc_now
)
from backend.schemas.response_playbook import (
    StepTypeEnum,
    SafetyClassEnum,
    ApprovalPolicyEnum,
    ExecutionModeEnum,
    ExecutionStatusEnum,
    StepExecutionStatusEnum,
    ApprovalDecisionEnum,
    TargetRef
)
from backend.services.response_playbook_engine import ResponsePlaybookEngine
from backend.services.playbook_validator import (
    PlaybookValidator,
    evaluate_safe_condition
)


@pytest.fixture
def db_session():
    """Isolated in-memory SQLite session for testing."""
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    try:
        # Seed default capabilities
        from backend.services.response_recommendation_engine import DEFAULT_CAPABILITIES
        for cap in DEFAULT_CAPABILITIES:
            m = ResponseCapabilityModel(
                id=generate_uuid(),
                workspace_id="default",
                action_type=cap["action_type"],
                provider=cap["provider"],
                environment=cap["environment"],
                enabled=cap["enabled"],
                reversible=cap["reversible"],
                approval_required=cap["approval_required"],
                capability_state=cap["capability_state"],
                state_reason=cap["state_reason"]
            )
            session.add(m)
        session.commit()
        yield session
    finally:
        session.close()


def test_seed_default_playbooks(db_session):
    """Verifies that default reference playbooks (Phishing, ATO, Endpoint) seed cleanly."""
    ResponsePlaybookEngine.seed_default_playbooks(db_session, workspace_id="default")
    playbooks = ResponsePlaybookEngine.get_playbooks(db_session, workspace_id="default")

    keys = [p.playbook_key for p in playbooks]
    assert "phishing-containment" in keys
    assert "account-takeover-response" in keys
    assert "endpoint-containment" in keys

    phish = next(p for p in playbooks if p.playbook_key == "phishing-containment")
    assert len(phish.steps) >= 4
    step_types = [s.step_type for s in phish.steps]
    assert StepTypeEnum.PRESERVE_EVIDENCE.value in step_types
    assert StepTypeEnum.BLOCK_DOMAIN.value in step_types


def test_safe_condition_evaluator():
    """Evaluates typed conditions safely without code injection."""
    ctx = {
        "risk_score": 85.0,
        "risk_level": "CRITICAL",
        "previous_step": {"status": "SUCCESS"}
    }

    # True conditions
    assert evaluate_safe_condition({"field": "risk_score", "operator": ">=", "value": 80}, ctx) is True
    assert evaluate_safe_condition({"field": "risk_level", "operator": "==", "value": "CRITICAL"}, ctx) is True
    assert evaluate_safe_condition({"field": "previous_step.status", "operator": "==", "value": "SUCCESS"}, ctx) is True

    # False conditions
    assert evaluate_safe_condition({"field": "risk_score", "operator": "<", "value": 50}, ctx) is False
    assert evaluate_safe_condition({"field": "risk_level", "operator": "!=", "value": "CRITICAL"}, ctx) is False

    # Missing field fails closed
    assert evaluate_safe_condition({"field": "nonexistent_field", "operator": "==", "value": "foo"}, ctx) is False


def test_playbook_validation_rejects_untyped_arbitrary_code(db_session):
    """Rejects generic shell/arbitrary code step types."""
    invalid_data = {
        "playbook_key": "malicious-playbook",
        "name": "Malicious Code Playbook",
        "version": 1,
        "steps": [
            {
                "step_key": "bad_shell",
                "sequence": 1,
                "step_type": "RUN_SHELL_COMMAND",  # Prohibited!
                "name": "Execute Shell",
                "description": "Arbitrary command execution"
            }
        ]
    }
    val = PlaybookValidator.validate_and_lint(invalid_data, db=db_session)
    assert val.valid is False
    assert any("Unknown step_type" in err for err in val.errors)


def test_playbook_validation_rejects_circular_dependencies(db_session):
    """Rejects circular dependencies in step sequence."""
    circular_data = {
        "playbook_key": "circular-playbook",
        "name": "Circular Playbook",
        "version": 1,
        "steps": [
            {
                "step_key": "step_a",
                "sequence": 1,
                "step_type": StepTypeEnum.PRESERVE_EVIDENCE.value,
                "name": "Step A",
                "description": "Depends on B",
                "depends_on": ["step_b"]
            },
            {
                "step_key": "step_b",
                "sequence": 2,
                "step_type": StepTypeEnum.CREATE_NOTIFICATION.value,
                "name": "Step B",
                "description": "Depends on A",
                "depends_on": ["step_a"]
            }
        ]
    }
    val = PlaybookValidator.validate_and_lint(circular_data, db=db_session)
    assert val.valid is False
    assert any("Circular dependency" in err for err in val.errors)


def test_target_concurrency_locking(db_session):
    """Prevents conflicting simultaneous executions against the same target."""
    exec1_id = generate_uuid()
    exec2_id = generate_uuid()

    # Acquire lock for exec1
    acquired = ResponsePlaybookEngine.acquire_target_lock(
        db_session,
        workspace_id="default",
        target_type="ACCOUNT",
        target_id="victim@corp.com",
        execution_id=exec1_id
    )
    assert acquired is True

    # Attempt conflicting lock for exec2 must fail
    conflict = ResponsePlaybookEngine.acquire_target_lock(
        db_session,
        workspace_id="default",
        target_type="ACCOUNT",
        target_id="victim@corp.com",
        execution_id=exec2_id
    )
    assert conflict is False

    # Release exec1 locks
    ResponsePlaybookEngine.release_target_locks(db_session, exec1_id)

    # Now exec2 can acquire
    acquired_after = ResponsePlaybookEngine.acquire_target_lock(
        db_session,
        workspace_id="default",
        target_type="ACCOUNT",
        target_id="victim@corp.com",
        execution_id=exec2_id
    )
    assert acquired_after is True


def test_create_playbook_from_recommendation(db_session):
    """Converts a Section 28 recommendation into a structured playbook."""
    # Create sample Section 28 recommendation
    rec = ResponseRecommendationModel(
        id=f"REC-{generate_uuid()[:8]}",
        workspace_id="default",
        scope_type="EVENT",
        scope_id="EVT-TEST-01",
        action_type="BLOCK_DOMAIN",
        category="CONTAINMENT",
        title="Consider blocking malicious domain",
        description="Block attacker credential harvesting domain.",
        rationale="Credential harvesting form detected.",
        priority="P1",
        urgency="URGENT",
        expected_effect="Prevents endpoints from resolving domain.",
        affected_entities_json=json.dumps([{"entity_type": "domain", "identifier": "attacker-login.com"}]),
        approval_required=True,
        safety_class="CONTAINMENT",
        reversibility="REVERSIBLE",
        status="APPROVED"
    )
    db_session.add(rec)
    db_session.commit()

    pb = ResponsePlaybookEngine.create_playbook_from_recommendation(
        db=db_session,
        recommendation_id=rec.id,
        requested_by="analyst_jane"
    )

    assert pb is not None
    assert pb.source_recommendation_id == rec.id
    assert pb.status == "APPROVED"
    assert len(pb.steps) == 3

    # Evidence preservation must precede containment
    assert pb.steps[0].step_type == StepTypeEnum.PRESERVE_EVIDENCE.value
    assert pb.steps[1].step_type == StepTypeEnum.BLOCK_DOMAIN.value
    assert pb.steps[1].requires_approval is True
    assert "preserve_pre_action_evidence" in pb.steps[1].depends_on


def test_dry_run_simulation_mode(db_session):
    """Verifies that simulation produces a full plan without executing external changes."""
    ResponsePlaybookEngine.seed_default_playbooks(db_session, workspace_id="default")
    phish = db_session.query(ResponsePlaybookModel).filter(
        ResponsePlaybookModel.playbook_key == "phishing-containment"
    ).first()

    sim_plan = ResponsePlaybookEngine.simulate_playbook(
        db=db_session,
        playbook_id=phish.id,
        workspace_id="default",
        target_override=TargetRef(target_type="DOMAIN", target_id="evil-phish.net")
    )

    assert sim_plan.mode == "DRY_RUN"
    assert sim_plan.total_steps == len(phish.steps)
    assert sim_plan.validation.valid is True
    assert sim_plan.approval_required_overall is True

    # Check step details
    step2 = next(s for s in sim_plan.steps if s.step_key == "block_phishing_domain")
    assert step2.requires_approval is True
    assert step2.rollback_available is True
    assert step2.target_snapshot.target_id == "evil-phish.net"


def test_live_execution_approval_boundary(db_session):
    """Live execution pauses when a step requires human approval and has not been approved."""
    ResponsePlaybookEngine.seed_default_playbooks(db_session, workspace_id="default")
    phish = db_session.query(ResponsePlaybookModel).filter(
        ResponsePlaybookModel.playbook_key == "phishing-containment"
    ).first()

    # Step 2 (block_phishing_domain) requires approval
    execution = ResponsePlaybookEngine.execute_playbook(
        db=db_session,
        playbook_id=phish.id,
        workspace_id="default",
        mode=ExecutionModeEnum.LIVE.value,
        requested_by="analyst_bob",
        target_override=TargetRef(target_type="DOMAIN", target_id="adversary-auth.com")
    )

    # Must pause at WAITING_FOR_APPROVAL
    assert execution.status == ExecutionStatusEnum.WAITING_FOR_APPROVAL.value

    # Approve execution
    approval = ResponsePlaybookEngine.record_approval(
        db=db_session,
        execution_id=execution.id,
        step_id=None,
        decision=ApprovalDecisionEnum.APPROVED.value,
        approved_by="senior_analyst",
        reason="Verified active credential harvesting lure."
    )
    assert approval.decision == ApprovalDecisionEnum.APPROVED.value
    assert execution.status == ExecutionStatusEnum.READY.value


def test_dry_run_execution_runs_all_steps_safely(db_session):
    """DRY_RUN execution completes all steps safely, simulating outputs and verification."""
    ResponsePlaybookEngine.seed_default_playbooks(db_session, workspace_id="default")
    ato = db_session.query(ResponsePlaybookModel).filter(
        ResponsePlaybookModel.playbook_key == "account-takeover-response"
    ).first()

    execution = ResponsePlaybookEngine.execute_playbook(
        db=db_session,
        playbook_id=ato.id,
        workspace_id="default",
        mode=ExecutionModeEnum.DRY_RUN.value,
        requested_by="analyst_test",
        target_override=TargetRef(target_type="ACCOUNT", target_id="compromised_user@corp.com")
    )

    assert execution.status == ExecutionStatusEnum.COMPLETED.value
    assert execution.mode == ExecutionModeEnum.DRY_RUN.value
    assert len(execution.step_executions) == len(ato.steps)

    for se in execution.step_executions:
        assert se.status == StepExecutionStatusEnum.COMPLETED.value
        output = se.output_summary
        assert output.get("simulated") is True


def test_audit_log_and_threat_memory_integration(db_session):
    """Verifies that execution generates append-only AuditLogModel and ThreatMemoryDecision records."""
    ResponsePlaybookEngine.seed_default_playbooks(db_session, workspace_id="default")
    phish = db_session.query(ResponsePlaybookModel).filter(
        ResponsePlaybookModel.playbook_key == "phishing-containment"
    ).first()

    execution = ResponsePlaybookEngine.execute_playbook(
        db=db_session,
        playbook_id=phish.id,
        workspace_id="default",
        mode=ExecutionModeEnum.DRY_RUN.value,
        requested_by="analyst_audit_check"
    )

    # Check audit log
    logs = db_session.query(AuditLogModel).filter(
        AuditLogModel.resource_id == execution.id
    ).all()
    assert len(logs) >= 2  # Started and Completed
    actions = [l.action for l in logs]
    assert "EXECUTION_STARTED" in actions
    assert "EXECUTION_COMPLETED" in actions

    # Check threat memory decision
    dec = db_session.query(ThreatMemoryDecisionModel).filter(
        ThreatMemoryDecisionModel.workspace_id == "default"
    ).first()
    assert dec is not None
    assert dec.decision in ["VERIFIED_MALICIOUS", "NEEDS_REVIEW"]
    assert "phishing-containment" in dec.reason


def test_multi_tenant_isolation(db_session):
    """Verifies playbooks and executions from Workspace A cannot be accessed from Workspace B."""
    ResponsePlaybookEngine.seed_default_playbooks(db_session, workspace_id="tenant_alpha")
    ResponsePlaybookEngine.seed_default_playbooks(db_session, workspace_id="tenant_beta")

    alpha_pbs = ResponsePlaybookEngine.get_playbooks(db_session, workspace_id="tenant_alpha")
    beta_pbs = ResponsePlaybookEngine.get_playbooks(db_session, workspace_id="tenant_beta")

    assert len(alpha_pbs) > 0
    assert len(beta_pbs) > 0
    assert all(p.workspace_id == "tenant_alpha" for p in alpha_pbs)
    assert all(p.workspace_id == "tenant_beta" for p in beta_pbs)
