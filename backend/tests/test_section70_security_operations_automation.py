"""
Section 70: Security Operations Automation (SOAR) Comprehensive Test Suite.
Validates workflow lifecycles, immutable versioning, structured conditions,
authoritative triggers, deduplication, recursion guards, human approval gates,
truthful verification, failure classifications, and operational metrics.
"""
import pytest
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.main import app
from backend.db.session import get_db, SessionLocal, engine
from backend.db.models import (
    Base,
    AutomationWorkflowModel,
    AutomationWorkflowVersionModel,
    AutomationRunModel,
    AutomationRunStepModel,
    AutomationApprovalRequestModel,
    CaseModel,
    EndpointAgentModel,
    AlertModel,
)
from backend.services.automation_service import AutomationWorkflowService
from backend.schemas.automation_workflow import (
    WorkflowCreateRequest,
    WorkflowUpdateRequest,
    WorkflowTypeEnum,
    TriggerTypeEnum,
    ConditionGroup,
    ConditionRule,
    WorkflowActionDefinition,
    WorkflowExecutionLimits,
    ActionRiskClassificationEnum,
    ActionApprovalLevelEnum,
)


@pytest.fixture(scope="module")
def db_session():
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    yield session
    session.close()


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


def test_01_workflow_creation_validation_activation_and_immutable_versioning(db_session: Session):
    """Verifies that workflows start in DRAFT, must be validated, and create immutable version snapshots upon activation."""
    req = WorkflowCreateRequest(
        name="Phishing Alert Auto-Triage",
        description="Automated triage and case creation for high-severity phishing alerts.",
        workflow_type=WorkflowTypeEnum.ALERT_TRIAGE,
        trigger_type=TriggerTypeEnum.ALERT_CREATED,
        conditions=ConditionGroup(
            logic="AND",
            rules=[
                ConditionRule(field="severity", operator="in", value=["HIGH", "CRITICAL"]),
            ],
        ),
        actions=[
            WorkflowActionDefinition(
                step_key="create_case_step",
                action_id="CREATE_CASE",
                name="Create Case",
                risk_classification=ActionRiskClassificationEnum.LOW_IMPACT,
                approval_level=ActionApprovalLevelEnum.AUTOMATIC,
                parameters={"title": "Automated Phishing Investigation"},
            ),
            WorkflowActionDefinition(
                step_key="notify_analyst_step",
                action_id="SEND_NOTIFICATION",
                name="Notify Analyst",
                risk_classification=ActionRiskClassificationEnum.READ_ONLY,
                approval_level=ActionApprovalLevelEnum.AUTOMATIC,
                parameters={"title": "Phishing Triage Triggered", "severity": "high"},
            ),
        ],
        execution_limits=WorkflowExecutionLimits(max_steps=10, timeout_seconds=300),
    )

    wf = AutomationWorkflowService.create_workflow(db=db_session, req=req, tenant_id="tenant-soar-1")
    assert wf.id is not None
    assert wf.status == "DRAFT"
    assert wf.version == 1
    assert wf.is_active is False

    # Validate workflow
    is_valid, errors = AutomationWorkflowService.validate_workflow(db=db_session, workflow_id=wf.id, tenant_id="tenant-soar-1")
    assert is_valid is True
    assert len(errors) == 0

    # Activate workflow
    activated = AutomationWorkflowService.activate_workflow(db=db_session, workflow_id=wf.id, tenant_id="tenant-soar-1")
    assert activated.status == "ACTIVE"
    assert activated.is_active is True

    # Check immutable version snapshot was recorded
    versions = db_session.query(AutomationWorkflowVersionModel).filter(
        AutomationWorkflowVersionModel.workflow_id == wf.id,
    ).all()
    assert len(versions) == 1
    assert versions[0].version == 1
    assert versions[0].status == "ACTIVE"
    assert "create_case_step" in versions[0].definition_json

    # Attempting to edit an active workflow directly must raise an error
    with pytest.raises(ValueError, match="Active workflow cannot be modified in-place"):
        AutomationWorkflowService.update_workflow(
            db=db_session,
            workflow_id=wf.id,
            req=WorkflowUpdateRequest(name="Mutated In Place"),
            tenant_id="tenant-soar-1",
        )

    # Creating a new version branches to draft v2
    v2 = AutomationWorkflowService.create_new_version(db=db_session, workflow_id=wf.id, tenant_id="tenant-soar-1")
    assert v2.version == 2
    assert v2.status == "DRAFT"
    assert v2.is_active is False


def test_02_draft_workflows_cannot_execute(db_session: Session):
    """Verifies that non-ACTIVE (DRAFT) workflows cannot be triggered in production mode."""
    req = WorkflowCreateRequest(
        name="Draft Workflow",
        trigger_type=TriggerTypeEnum.ALERT_CREATED,
        actions=[
            WorkflowActionDefinition(
                step_key="step_1",
                action_id="SEND_NOTIFICATION",
                name="Send Notification",
            )
        ],
    )
    draft_wf = AutomationWorkflowService.create_workflow(db=db_session, req=req, tenant_id="tenant-soar-2")
    assert draft_wf.status == "DRAFT"

    # Evaluate trigger against DRAFT workflow should ignore it
    runs = AutomationWorkflowService.evaluate_trigger(
        db=db_session,
        trigger_type=TriggerTypeEnum.ALERT_CREATED.value,
        resource_type="ALERT",
        resource_id="alt-001",
        payload={"severity": "HIGH"},
        tenant_id="tenant-soar-2",
    )
    assert len(runs) == 0


def test_03_structured_condition_evaluator_safety():
    """Verifies that structured condition evaluator correctly supports type-safe logic without arbitrary code."""
    conds = {
        "logic": "AND",
        "rules": [
            {"field": "severity", "operator": "eq", "value": "CRITICAL"},
            {"field": "risk_score", "operator": ">=", "value": 85},
            {"field": "source", "operator": "in", "value": ["EMAIL", "ENDPOINT"]},
            {"field": "details.sender", "operator": "contains", "value": "@evil.com"},
        ],
    }

    # Matching context
    matching_ctx = {
        "severity": "CRITICAL",
        "risk_score": 90,
        "source": "EMAIL",
        "details": {"sender": "attacker@evil.com"},
    }
    assert AutomationWorkflowService.evaluate_condition_group(conds, matching_ctx) is True

    # Failing context (score too low)
    failing_ctx = {
        "severity": "CRITICAL",
        "risk_score": 50,
        "source": "EMAIL",
        "details": {"sender": "attacker@evil.com"},
    }
    assert AutomationWorkflowService.evaluate_condition_group(conds, failing_ctx) is False


def test_04_authoritative_trigger_evaluation_and_deduplication(db_session: Session):
    """Verifies that event triggers match active workflows and deduplicate rapid repeated firings."""
    req = WorkflowCreateRequest(
        name="Auto Case on Critical Alert",
        trigger_type=TriggerTypeEnum.ALERT_CREATED,
        conditions=ConditionGroup(
            rules=[ConditionRule(field="severity", operator="eq", value="CRITICAL")],
        ),
        actions=[
            WorkflowActionDefinition(
                step_key="step_1",
                action_id="SEND_NOTIFICATION",
                name="Notify",
                parameters={"title": "Critical Alert Triggered"},
            ),
        ],
    )
    wf = AutomationWorkflowService.create_workflow(db=db_session, req=req, tenant_id="tenant-soar-3")
    AutomationWorkflowService.activate_workflow(db=db_session, workflow_id=wf.id, tenant_id="tenant-soar-3")

    # First event trigger -> spawns run
    runs1 = AutomationWorkflowService.evaluate_trigger(
        db=db_session,
        trigger_type=TriggerTypeEnum.ALERT_CREATED.value,
        resource_type="ALERT",
        resource_id="alert-dedup-100",
        payload={"severity": "CRITICAL"},
        tenant_id="tenant-soar-3",
    )
    assert len(runs1) == 1
    assert runs1[0].status == "COMPLETED"

    # Immediate second identical trigger for same alert -> deduplicated!
    runs2 = AutomationWorkflowService.evaluate_trigger(
        db=db_session,
        trigger_type=TriggerTypeEnum.ALERT_CREATED.value,
        resource_type="ALERT",
        resource_id="alert-dedup-100",
        payload={"severity": "CRITICAL"},
        tenant_id="tenant-soar-3",
    )
    assert len(runs2) == 0


def test_05_recursion_and_loop_prevention_guard(db_session: Session):
    """Verifies that workflows cannot recursively self-trigger past the maximum recursion limit."""
    req = WorkflowCreateRequest(
        name="Recursion Test Workflow",
        trigger_type=TriggerTypeEnum.ALERT_CREATED,
        execution_limits=WorkflowExecutionLimits(max_recursion_depth=2),
        actions=[
            WorkflowActionDefinition(
                step_key="s1",
                action_id="SEND_NOTIFICATION",
                name="Notify",
            ),
        ],
    )
    wf = AutomationWorkflowService.create_workflow(db=db_session, req=req, tenant_id="tenant-soar-4")
    AutomationWorkflowService.activate_workflow(db=db_session, workflow_id=wf.id, tenant_id="tenant-soar-4")

    # Trigger with depth = 2 should be rejected by recursion guard
    runs = AutomationWorkflowService.evaluate_trigger(
        db=db_session,
        trigger_type=TriggerTypeEnum.ALERT_CREATED.value,
        resource_type="ALERT",
        resource_id="alt-rec-1",
        payload={"_soar_recursion_depth": 2},
        tenant_id="tenant-soar-4",
    )
    assert len(runs) == 0


def test_06_action_registry_preconditions_and_toctou_defense(db_session: Session):
    """Verifies precondition checks and TOCTOU defense when a target resource state is invalid."""
    # Create a CLOSED case
    closed_case = CaseModel(
        workspace_id="default",
        case_number="CASE-CLOSED-001",
        title="Closed Case",
        status="CLOSED",
        severity="LOW",
        priority="P4",
    )
    db_session.add(closed_case)
    db_session.commit()

    # Workflow attempting to add a task to this closed case
    req = WorkflowCreateRequest(
        name="Task on Case",
        trigger_type=TriggerTypeEnum.MANUAL,
        actions=[
            WorkflowActionDefinition(
                step_key="add_task",
                action_id="ADD_CASE_TASK",
                name="Add Task",
                parameters={"case_id": closed_case.id, "title": "Check artifacts"},
            ),
        ],
    )
    wf = AutomationWorkflowService.create_workflow(db=db_session, req=req, tenant_id="tenant-soar-5")
    AutomationWorkflowService.activate_workflow(db=db_session, workflow_id=wf.id, tenant_id="tenant-soar-5")

    run = AutomationWorkflowService.create_and_execute_run(
        db=db_session,
        workflow=wf,
        trigger_type="MANUAL",
        resource_type="CASE",
        resource_id=closed_case.id,
        payload={"case_id": closed_case.id},
        tenant_id="tenant-soar-5",
    )

    # Precondition failure: cannot add task to closed case
    assert run.status == "PARTIALLY_COMPLETED"
    step = run.steps[0]
    assert step.status == "FAILED"
    assert "CLOSED" in step.error_message


def test_07_high_impact_consequential_action_approval_gate(db_session: Session):
    """Verifies that high-impact actions enter WAITING_FOR_APPROVAL, enforce roles, and verify state upon execution."""
    endpoint = EndpointAgentModel(
        workspace_id="default",
        device_id="dev-soar-01",
        agent_id="agt-sec70-test",
        hostname="CORP-FINANCE-WKS12",
        platform="linux",
        status="ONLINE",
    )
    db_session.add(endpoint)
    db_session.commit()

    req = WorkflowCreateRequest(
        name="Containment Workflow",
        trigger_type=TriggerTypeEnum.CRITICAL_FINDING_CREATED,
        actions=[
            WorkflowActionDefinition(
                step_key="isolate_step",
                action_id="ISOLATE_ENDPOINT",
                name="Isolate Host",
                risk_classification=ActionRiskClassificationEnum.HIGH_IMPACT,
                approval_level=ActionApprovalLevelEnum.SENIOR_ANALYST_APPROVAL,
                parameters={"endpoint_id": endpoint.id},
            ),
        ],
    )
    wf = AutomationWorkflowService.create_workflow(db=db_session, req=req, tenant_id="tenant-soar-6")
    AutomationWorkflowService.activate_workflow(db=db_session, workflow_id=wf.id, tenant_id="tenant-soar-6")

    # Run workflow -> should pause at approval gate
    run = AutomationWorkflowService.create_and_execute_run(
        db=db_session,
        workflow=wf,
        trigger_type=TriggerTypeEnum.CRITICAL_FINDING_CREATED.value,
        resource_type="ENDPOINT",
        resource_id=endpoint.id,
        payload={"endpoint_id": endpoint.id},
        tenant_id="tenant-soar-6",
    )

    assert run.status == "WAITING_FOR_APPROVAL"
    assert run.steps[0].status == "WAITING_FOR_APPROVAL"
    approval_id = run.steps[0].approval_id
    assert approval_id is not None

    # Junior analyst cannot approve high-impact action
    with pytest.raises(PermissionError, match="requires 'senior_analyst'"):
        AutomationWorkflowService.decide_approval(
            db=db_session,
            approval_id=approval_id,
            decision="APPROVED",
            user_id="analyst-junior",
            user_name="Junior Analyst",
            user_role="analyst",
            tenant_id="tenant-soar-6",
        )

    # Senior analyst approves
    appr = AutomationWorkflowService.decide_approval(
        db=db_session,
        approval_id=approval_id,
        decision="APPROVED",
        user_id="lead-01",
        user_name="SOC Director",
        user_role="senior_analyst",
        reason="Confirmed command-and-control beaconing from financial controller host.",
        tenant_id="tenant-soar-6",
    )
    assert appr.decision == "APPROVED"

    # Verify run completed and endpoint was truthfully isolated
    db_session.refresh(run)
    assert run.status == "COMPLETED"
    db_session.refresh(endpoint)
    assert endpoint.status == "ISOLATED"
    assert run.steps[0].verified_state is True


def test_08_approval_expiration_enforcement(db_session: Session):
    """Verifies that expired approval requests cannot be approved."""
    endpoint = EndpointAgentModel(
        workspace_id="default",
        device_id="dev-soar-02",
        agent_id="agt-sec70-exp",
        hostname="CORP-DEV-BOX",
        platform="linux",
        status="ONLINE",
    )
    db_session.add(endpoint)
    db_session.commit()

    req = WorkflowCreateRequest(
        name="Expire Test",
        trigger_type=TriggerTypeEnum.MANUAL,
        actions=[
            WorkflowActionDefinition(
                step_key="isolate_exp",
                action_id="ISOLATE_ENDPOINT",
                name="Isolate Host",
                parameters={"endpoint_id": endpoint.id},
            ),
        ],
    )
    wf = AutomationWorkflowService.create_workflow(db=db_session, req=req, tenant_id="tenant-soar-7")
    AutomationWorkflowService.activate_workflow(db=db_session, workflow_id=wf.id, tenant_id="tenant-soar-7")

    run = AutomationWorkflowService.create_and_execute_run(
        db=db_session,
        workflow=wf,
        trigger_type="MANUAL",
        resource_type="ENDPOINT",
        resource_id=endpoint.id,
        payload={"endpoint_id": endpoint.id},
        tenant_id="tenant-soar-7",
    )

    approval_req = db_session.query(AutomationApprovalRequestModel).filter(
        AutomationApprovalRequestModel.run_id == run.id,
    ).first()
    # Force backdate expiration to simulate time passage
    approval_req.expires_at = datetime.now(timezone.utc) - timedelta(hours=2)
    db_session.commit()

    with pytest.raises(ValueError, match="EXPIRED"):
        AutomationWorkflowService.decide_approval(
            db=db_session,
            approval_id=approval_req.id,
            decision="APPROVED",
            user_id="lead-01",
            user_name="SOC Lead",
            user_role="senior_analyst",
            tenant_id="tenant-soar-7",
        )


def test_09_manual_override_cancellation_preserves_evidence(db_session: Session):
    """Verifies that cancelling an in-flight automation run halts future steps while preserving completed outputs."""
    req = WorkflowCreateRequest(
        name="Multi Step Workflow",
        trigger_type=TriggerTypeEnum.MANUAL,
        actions=[
            WorkflowActionDefinition(step_key="s1", action_id="SEND_NOTIFICATION", name="Step 1"),
            WorkflowActionDefinition(step_key="s2", action_id="SEND_NOTIFICATION", name="Step 2"),
        ],
    )
    wf = AutomationWorkflowService.create_workflow(db=db_session, req=req, tenant_id="tenant-soar-8")
    AutomationWorkflowService.activate_workflow(db=db_session, workflow_id=wf.id, tenant_id="tenant-soar-8")

    # Create run directly in RUNNING status
    run = AutomationRunModel(
        workspace_id="default",
        tenant_id="tenant-soar-8",
        workflow_id=wf.id,
        status="RUNNING",
        trigger_type="MANUAL",
        total_steps=2,
    )
    db_session.add(run)
    db_session.commit()
    db_session.refresh(run)

    step1 = AutomationRunStepModel(
        workspace_id="default",
        tenant_id="tenant-soar-8",
        run_id=run.id,
        step_index=0,
        step_key="s1",
        action_id="SEND_NOTIFICATION",
        name="Step 1",
        status="COMPLETED",
    )
    step2 = AutomationRunStepModel(
        workspace_id="default",
        tenant_id="tenant-soar-8",
        run_id=run.id,
        step_index=1,
        step_key="s2",
        action_id="SEND_NOTIFICATION",
        name="Step 2",
        status="PENDING",
    )
    db_session.add_all([step1, step2])
    db_session.commit()

    cancelled = AutomationWorkflowService.cancel_run(db=db_session, run_id=run.id, tenant_id="tenant-soar-8")
    assert cancelled.status == "CANCELLED"
    db_session.refresh(step1)
    db_session.refresh(step2)
    assert step1.status == "COMPLETED"  # Preserved
    assert step2.status == "SKIPPED"    # Future step skipped


def test_10_soar_metrics_truthfulness(db_session: Session):
    """Verifies that SOAR metrics reflect authentic database records without fabricated percentages."""
    metrics = AutomationWorkflowService.get_metrics(db=db_session, tenant_id="tenant-soar-6")
    assert metrics["total_workflows"] >= 1
    assert metrics["total_runs"] >= 1
    assert metrics["completed_runs"] >= 1
    assert isinstance(metrics["success_rate"], float)
    assert "failure_breakdown" in metrics
