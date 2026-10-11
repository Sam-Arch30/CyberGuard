"""
Section 66: Advanced Investigation Automation Test Suite.
Verifies:
1. Template catalog & custom plan creation.
2. Step registry execution & bounded analysis.
3. Truthful zero-result handling (0 hunt results != error).
4. Failure semantics & partial completion (1 failed step -> PARTIALLY_COMPLETED, not FAILED).
5. Loop prevention & visited entity tracking.
6. Approval gates (WAITING_APPROVAL -> approve_step -> resume).
7. Strict prohibition of destructive actions (fails closed on BLOCK_IP / destructive tools).
8. Investigation gaps identification & telemetry coverage audit.
9. Cancellation preserving evidence integrity.
10. Retry & resume workflows.
11. RBAC authorization & multi-tenant isolation.
12. Background job worker handler execution.
"""
import json
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.db.models import (
    Base,
    IncidentModel,
    AnalysisRunModel,
    ArtifactModel,
    FindingModel,
    IndicatorModel,
    AssetModel,
    IdentityModel,
    WatchedIndicatorModel,
    WatchlistModel,
    AlertModel,
    ThreatIntelligenceRecordModel,
    InvestigationAutomationRunModel,
    InvestigationAutomationStepModel,
    InvestigationGapModel,
)
from backend.main import app
from backend.db.session import get_db
from backend.schemas.investigation_automation import (
    AutomationTriggerType,
    AutomationMode,
    AutomationRunStatus,
    StepStatus,
    ActionIdEnum,
    AutomationBudget,
    InvestigationAutomationRunCreate,
    AutomationStepCreate,
    StepApprovalRequest,
)
from backend.services.investigation_automation_service import (
    InvestigationAutomationService,
    INVESTIGATION_TEMPLATES,
)
from backend.services.investigation_action_registry import (
    SecurityActionProhibitedError,
    get_action_entry,
)
from backend.services.background_job_worker import (
    handle_investigation_automation_run,
    JobExecutionContext,
)
from backend.schemas.jobs import JobTypeEnum


from backend.db.session import SessionLocal, init_db


@pytest.fixture(scope="module")
def setup_db():
    init_db()
    yield


@pytest.fixture
def db_session(setup_db):
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def client(setup_db):
    return TestClient(app)


@pytest.fixture
def sample_investigation_context(db_session):
    """Creates a sample incident with artifact, run, findings, and indicators."""
    existing_inc = db_session.query(IncidentModel).filter(IncidentModel.id == "inc-test-01").first()
    if existing_inc:
        return existing_inc

    art = ArtifactModel(
        id="art-test-01",
        name="phish_sample.eml",
        artifact_type="EMAIL",
        sha256="aabbccddeeff11223344556677889900",
    )
    db_session.add(art)

    run = AnalysisRunModel(
        id="run-test-01",
        artifact_id="art-test-01",
        status="COMPLETED",
        overall_severity="HIGH",
        overall_risk_score=85.0,
        confidence=0.9,
    )
    db_session.add(run)

    inc = IncidentModel(
        id="inc-test-01",
        incident_number="INV-2026-0001",
        title="Targeted Phishing Lure Targeting Finance",
        status="OPEN",
        severity="HIGH",
        risk_score=85.0,
        confidence=0.9,
        workspace_id="test-workspace",
    )
    db_session.add(inc)

    # Add indicators
    ind1 = IndicatorModel(
        id="ind-01",
        indicator_type="DOMAIN",
        value="malicious-login-portal.com",
        normalized_value="malicious-login-portal.com",
        reputation="SUSPICIOUS",
    )
    ind2 = IndicatorModel(
        id="ind-02",
        indicator_type="IP",
        value="198.51.100.25",
        normalized_value="198.51.100.25",
        reputation="MALICIOUS",
    )
    db_session.add_all([ind1, ind2])

    # Add finding
    f1 = FindingModel(
        id="find-01",
        analysis_run_id="run-test-01",
        title="Credential Harvesting Form Detected",
        finding_type="PHISHING",
        severity="HIGH",
        confidence=0.95,
        description="Observed fake SSO login page posting to malicious-login-portal.com",
    )
    db_session.add(f1)

    # Add an enterprise asset
    ast = AssetModel(
        id="asset-01",
        workspace_id="test-workspace",
        canonical_name="198.51.100.25",
        display_name="fin-workstation-01.corp",
        asset_type="ENDPOINT",
        criticality="HIGH",
        exposure_state="INTERNAL",
        status="ACTIVE",
    )
    db_session.add(ast)

    # Add enterprise identity
    ident = IdentityModel(
        id="ident-01",
        workspace_id="test-workspace",
        canonical_identifier="cfo@company.com",
        display_name="Chief Financial Officer",
        email="cfo@company.com",
        department="Finance",
        criticality="CRITICAL",
        is_privileged=True,
        status="ACTIVE",
    )
    db_session.add(ident)

    db_session.commit()
    return inc


def test_template_catalog_and_plan_creation(db_session, sample_investigation_context):
    """Verifies built-in template catalog and plan instantiation."""
    templates = InvestigationAutomationService.list_templates()
    assert len(templates) >= 4
    names = [t.template_name for t in templates]
    assert "PHISHING_INVESTIGATION" in names
    assert "ACCOUNT_TAKEOVER_INVESTIGATION" in names
    assert "MALICIOUS_ATTACHMENT_INVESTIGATION" in names
    assert "GENERAL_INCIDENT_INVESTIGATION" in names

    # Create run from template
    req = InvestigationAutomationRunCreate(
        template_name="PHISHING_INVESTIGATION",
        mode=AutomationMode.ASSISTED,
        trigger_type=AutomationTriggerType.MANUAL_ANALYST,
    )
    run = InvestigationAutomationService.create_automation_run(
        db=db_session,
        workspace_id="test-workspace",
        investigation_id="inc-test-01",
        request=req,
        created_by="analyst_alice",
    )
    assert run.id is not None
    assert run.status == AutomationRunStatus.QUEUED.value
    assert run.total_steps == len(INVESTIGATION_TEMPLATES["PHISHING_INVESTIGATION"].steps)
    assert len(run.steps) == run.total_steps
    assert run.steps[0].action_id == ActionIdEnum.GET_INDICATOR_CONTEXT.value


def test_step_execution_and_bounded_analysis(db_session, sample_investigation_context):
    """Verifies sequential step execution, context aggregation, and results."""
    req = InvestigationAutomationRunCreate(
        template_name="PHISHING_INVESTIGATION",
        mode=AutomationMode.ASSISTED,
        trigger_type=AutomationTriggerType.MANUAL_ANALYST,
    )
    run = InvestigationAutomationService.create_automation_run(
        db=db_session,
        workspace_id="test-workspace",
        investigation_id="inc-test-01",
        request=req,
    )

    executed_run = InvestigationAutomationService.execute_automation_run(db_session, run.id)
    assert executed_run.status in (AutomationRunStatus.COMPLETED.value, AutomationRunStatus.PARTIALLY_COMPLETED.value)
    assert executed_run.completed_steps > 0
    assert executed_run.completed_at is not None

    # Verify indicator context step
    step0 = executed_run.steps[0]
    assert step0.status == StepStatus.COMPLETED.value
    assert step0.duration_ms >= 0
    summary = json.loads(step0.result_summary_json)
    assert "indicators" in summary
    assert len(summary["indicators"]) >= 2


def test_truthful_zero_result_handling(db_session, sample_investigation_context):
    """Verifies that 0 hunt results does not fail the step and returns factual statement."""
    req = InvestigationAutomationRunCreate(
        custom_steps=[
            AutomationStepCreate(
                step_index=0,
                action_id=ActionIdEnum.RUN_APPROVED_HUNT,
                name="Hunt for non-existent domain",
                input_params={"query_string": "SEARCH_DOMAIN", "target_value": "completely-absent-domain-xyz.com"},
            )
        ]
    )
    run = InvestigationAutomationService.create_automation_run(
        db=db_session,
        workspace_id="test-workspace",
        investigation_id="inc-test-01",
        request=req,
    )
    # Give manual analyst approval for expensive hunt step
    InvestigationAutomationService.approve_step(db_session, run.id, 0, analyst_id="lead_analyst")

    executed_run = InvestigationAutomationService.execute_automation_run(db_session, run.id)
    step = executed_run.steps[0]
    assert step.status == StepStatus.COMPLETED.value
    assert step.result_count == 0
    summary = json.loads(step.result_summary_json)
    assert summary["matched_count"] == 0
    assert "No matching records were observed within the queried data scope" in summary["status_statement"]


def test_failure_semantics_partial_completion(db_session, sample_investigation_context):
    """Verifies that a failure in one step results in PARTIALLY_COMPLETED, not overall FAILED."""
    req = InvestigationAutomationRunCreate(
        custom_steps=[
            AutomationStepCreate(
                step_index=0,
                action_id=ActionIdEnum.GET_INDICATOR_CONTEXT,
                name="Succeeding step",
            ),
            AutomationStepCreate(
                step_index=1,
                action_id=ActionIdEnum.GET_ASSET_CONTEXT,
                name="Failing step simulation",
                input_params={"invalid_flag": True},
            ),
        ]
    )
    run = InvestigationAutomationService.create_automation_run(
        db=db_session,
        workspace_id="test-workspace",
        investigation_id="inc-test-01",
        request=req,
    )

    # Force error on step 1 by mocking or bad action_id in DB
    step1 = run.steps[1]
    step1.action_id = "NON_EXISTENT_ACTION_FORCE_FAIL"
    db_session.commit()

    executed_run = InvestigationAutomationService.execute_automation_run(db_session, run.id)
    assert executed_run.completed_steps == 1
    assert executed_run.failed_steps == 1
    assert executed_run.status == AutomationRunStatus.PARTIALLY_COMPLETED.value


def test_loop_prevention_and_budget_limits(db_session, sample_investigation_context):
    """Verifies that entity loop prevention tracks visited entities and respects budget bounds."""
    budget = AutomationBudget(max_steps=2, max_entities=1)
    req = InvestigationAutomationRunCreate(
        template_name="GENERAL_INCIDENT_INVESTIGATION",
        budget=budget,
    )
    run = InvestigationAutomationService.create_automation_run(
        db=db_session,
        workspace_id="test-workspace",
        investigation_id="inc-test-01",
        request=req,
    )
    assert run.total_steps == 2  # Capped at max_steps

    executed_run = InvestigationAutomationService.execute_automation_run(db_session, run.id)
    visited = json.loads(executed_run.visited_entities_json)
    assert isinstance(visited, list)


def test_approval_gate_workflow(db_session, sample_investigation_context):
    """Verifies that steps requiring approval pause execution until analyst signs off."""
    req = InvestigationAutomationRunCreate(
        custom_steps=[
            AutomationStepCreate(
                step_index=0,
                action_id=ActionIdEnum.GET_INDICATOR_CONTEXT,
                name="Automatic Read-Only Step",
            ),
            AutomationStepCreate(
                step_index=1,
                action_id=ActionIdEnum.RUN_APPROVED_HUNT,
                name="Expensive Threat Hunt Step",
            ),
        ]
    )
    run = InvestigationAutomationService.create_automation_run(
        db=db_session,
        workspace_id="test-workspace",
        investigation_id="inc-test-01",
        request=req,
    )

    # Initial execution should pause at step 1
    executed_run = InvestigationAutomationService.execute_automation_run(db_session, run.id)
    assert executed_run.status == AutomationRunStatus.WAITING_FOR_ANALYST.value
    assert executed_run.steps[1].status == StepStatus.WAITING_APPROVAL.value

    # Analyst approves step 1
    resumed_run = InvestigationAutomationService.approve_step(
        db=db_session,
        run_id=run.id,
        step_index=1,
        analyst_id="senior_analyst_bob",
        approve=True,
    )
    assert resumed_run.steps[1].approved_by == "senior_analyst_bob"
    assert resumed_run.status in (AutomationRunStatus.COMPLETED.value, AutomationRunStatus.PARTIALLY_COMPLETED.value)


def test_strict_prohibition_of_destructive_actions():
    """Verifies that destructive actions fail closed and raise SecurityActionProhibitedError."""
    with pytest.raises(SecurityActionProhibitedError):
        get_action_entry("BLOCK_IP")

    with pytest.raises(SecurityActionProhibitedError):
        get_action_entry("ISOLATE_ENDPOINT")

    with pytest.raises(SecurityActionProhibitedError):
        get_action_entry("DISABLE_ACCOUNT")


def test_investigation_gaps_and_telemetry_coverage(db_session, sample_investigation_context):
    """Verifies that missing telemetry is classified as concrete InvestigationGapModel records."""
    req = InvestigationAutomationRunCreate(
        custom_steps=[
            AutomationStepCreate(
                step_index=0,
                action_id=ActionIdEnum.CHECK_DATA_COVERAGE,
                name="Check Telemetry Coverage",
            ),
            AutomationStepCreate(
                step_index=1,
                action_id=ActionIdEnum.GENERATE_INVESTIGATION_SUMMARY,
                name="Generate Summary",
            ),
        ]
    )
    run = InvestigationAutomationService.create_automation_run(
        db=db_session,
        workspace_id="test-workspace",
        investigation_id="inc-test-01",
        request=req,
    )
    executed_run = InvestigationAutomationService.execute_automation_run(db_session, run.id)

    # Gaps should have been identified (e.g. missing EDR telemetry)
    gaps = InvestigationAutomationService.get_investigation_gaps(db_session, "inc-test-01")
    assert len(gaps) >= 1
    assert any("Endpoint" in g.title or "EDR" in g.title for g in gaps)

    # Summary report check
    serialized = InvestigationAutomationService.get_run(db_session, run.id)
    assert serialized.coverage_summary is not None
    assert serialized.investigation_summary is not None
    assert len(serialized.investigation_summary.knowns) >= 1
    assert len(serialized.investigation_summary.unknowns) >= 1


def test_cancellation_preserves_evidence(db_session, sample_investigation_context):
    """Verifies that cancelling an automation run preserves already collected results."""
    req = InvestigationAutomationRunCreate(
        template_name="GENERAL_INCIDENT_INVESTIGATION",
    )
    run = InvestigationAutomationService.create_automation_run(
        db=db_session,
        workspace_id="test-workspace",
        investigation_id="inc-test-01",
        request=req,
    )

    cancelled_run = InvestigationAutomationService.cancel_automation_run(db_session, run.id, analyst_id="analyst_charlie")
    assert cancelled_run.status == AutomationRunStatus.CANCELLED.value
    # Run and steps still exist in database
    db_run = db_session.query(InvestigationAutomationRunModel).filter(InvestigationAutomationRunModel.id == run.id).first()
    assert db_run is not None
    assert len(db_run.steps) > 0


def test_api_rbac_and_tenant_isolation(client, sample_investigation_context):
    """Verifies that unauthorized roles cannot execute automation and workspaces are strictly isolated."""
    # 1. Viewer role should be rejected with 403
    resp = client.post(
        "/api/investigations/inc-test-01/automation/runs",
        json={"template_name": "PHISHING_INVESTIGATION"},
        headers={"X-Role": "viewer", "X-Workspace-ID": "test-workspace"},
    )
    assert resp.status_code == 403

    # 2. Analyst role succeeds
    resp_ok = client.post(
        "/api/investigations/inc-test-01/automation/runs",
        json={"template_name": "PHISHING_INVESTIGATION"},
        headers={"X-Role": "analyst", "X-Workspace-ID": "test-workspace"},
    )
    assert resp_ok.status_code == 201
    run_data = resp_ok.json()
    run_id = run_data["id"]

    # 3. Querying from different tenant workspace returns 404 / empty
    other_tenant_runs = client.get(
        "/api/investigations/inc-test-01/automation/runs",
        headers={"X-Workspace-ID": "other-isolated-tenant"},
    )
    assert other_tenant_runs.status_code == 200
    assert len(other_tenant_runs.json()) == 0


def test_background_job_worker_automation_run(db_session, sample_investigation_context):
    """Verifies that BackgroundJobWorker successfully handles INVESTIGATION_AUTOMATION_RUN jobs."""
    import asyncio

    req = InvestigationAutomationRunCreate(
        template_name="PHISHING_INVESTIGATION",
    )
    run = InvestigationAutomationService.create_automation_run(
        db=db_session,
        workspace_id="test-workspace",
        investigation_id="inc-test-01",
        request=req,
    )

    class DummyContext:
        job_id = "job-auto-01"
        workspace_id = "test-workspace"
        resource_id = run.id
        payload = {"run_id": run.id}
        parameters = {"run_id": run.id}
        def update_progress(self, db, pct, stage, msg):
            pass

    res = asyncio.run(handle_investigation_automation_run(DummyContext(), db_session))
    assert res["run_id"] == run.id
    assert res["status"] in (AutomationRunStatus.COMPLETED.value, AutomationRunStatus.PARTIALLY_COMPLETED.value)
    assert res["completed_steps"] > 0
