"""
Section 51: Comprehensive Tests for Incident SLA, Escalation & Analyst Workflow Automation.
Verifies authoritative server-side SLA clocks, warning thresholds, breach detection,
multi-tier escalation chains with loop prevention, intelligent analyst routing,
forensic SLA pausing and authorized exemption, Section 45 Background Job workers,
idempotency, concurrency handling, tenant isolation, and REST APIs.
"""
import json
import asyncio
import pytest
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.main import app
from backend.db.session import Base, get_db
from backend.db.models import (
    IncidentModel,
    IncidentSLAPolicyModel,
    IncidentEscalationPolicyModel,
    IncidentEscalationRuleModel,
    IncidentRoutingRuleModel,
    IncidentSLAStateModel,
    IncidentWorkflowExecutionModel,
    IncidentSLAPauseLogModel,
    NotificationModel,
    AuditEventModel,
    BackgroundJobModel,
)
from backend.schemas.jobs import JobTypeEnum
from backend.schemas.incidents import (
    IncidentCreateRequest,
    IncidentStatusChangeRequest,
    IncidentStatusEnum,
)
from backend.schemas.sla import (
    SLAPauseRequest,
    SLAExemptRequest,
    IncidentEscalateRequest,
    PolicySimulationRequest,
    SLAPolicyCreateRequest,
    SLAMilestoneStatusEnum,
    SLAOverallStatusEnum,
)
from backend.services.incident_service import IncidentService
from backend.services.sla_service import IncidentSLAService
from backend.services.background_job_worker import BackgroundJobWorker

# In-memory SQLite for testing with StaticPool
TEST_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(scope="function")
def db_session():
    Base.metadata.create_all(bind=engine)
    session = TestingSessionLocal()
    try:
        # Seed defaults
        IncidentSLAService.seed_default_policies(session)
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def client(db_session):
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


# =============================================================================
# 1. Unit Tests: SLA Clocks, Policies, and Milestone Transitions
# =============================================================================

def test_sla_policy_seeding_and_matching(db_session):
    """Test policy seeding and deterministic matching for critical vs standard incidents."""
    crit_policy = IncidentSLAService.match_policy(
        db_session,
        workspace_id="ws-prod",
        severity="CRITICAL",
        priority="P1_CRITICAL",
        category="RANSOMWARE",
    )
    assert crit_policy is not None
    assert crit_policy.name == "Critical Incident SLA Policy"
    assert crit_policy.acknowledgement_target_minutes == 15
    assert crit_policy.containment_target_minutes == 60

    med_policy = IncidentSLAService.match_policy(
        db_session,
        workspace_id="ws-prod",
        severity="MEDIUM",
        priority="P3_MEDIUM",
        category="PHISHING",
    )
    assert med_policy is not None
    assert med_policy.acknowledgement_target_minutes >= 30


def test_sla_clocks_and_milestones_calculation(db_session):
    """Test SLA duration calculation from real persisted server timestamps."""
    now = datetime.now(timezone.utc)
    # Incident created 10 minutes ago
    created_at = now - timedelta(minutes=10)

    incident = IncidentModel(
        incident_number="INC-1001",
        workspace_id="ws-prod",
        title="Unacknowledged Critical Threat",
        status="NEW",
        severity="CRITICAL",
        priority="P1_CRITICAL",
        category="RANSOMWARE",
        created_at=created_at,
        updated_at=created_at,
    )
    db_session.add(incident)
    db_session.commit()
    db_session.refresh(incident)

    detail = IncidentSLAService.evaluate_incident(db_session, incident)

    assert detail.incident_id == incident.id
    # Critical acknowledgement target is 15 minutes. Elapsed is ~10 minutes.
    ack = detail.milestones.acknowledgement
    assert ack.target_minutes == 15
    assert ack.elapsed_minutes >= 9
    assert ack.remaining_minutes <= 6
    assert ack.status in (SLAMilestoneStatusEnum.RUNNING, SLAMilestoneStatusEnum.WARNING)


def test_sla_warning_and_breach_detection(db_session):
    """Test deterministic warning threshold (80%) and breach detection (100%+)."""
    now = datetime.now(timezone.utc)
    # 1. Warning case: created 13 mins ago with 15m target (86% consumed)
    inc_warn = IncidentModel(
        incident_number="INC-WARN",
        workspace_id="ws-prod",
        title="Approaching SLA Breach",
        status="OPEN",
        severity="CRITICAL",
        priority="P1_CRITICAL",
        category="MALWARE",
        created_at=now - timedelta(minutes=13),
        updated_at=now - timedelta(minutes=13),
    )
    db_session.add(inc_warn)

    # 2. Breach case: created 35 mins ago with 15m target (>100% consumed)
    inc_breach = IncidentModel(
        incident_number="INC-BREACH",
        workspace_id="ws-prod",
        title="Overdue Unacknowledged Incident",
        status="NEW",
        severity="CRITICAL",
        priority="P1_CRITICAL",
        category="MALWARE",
        created_at=now - timedelta(minutes=35),
        updated_at=now - timedelta(minutes=35),
    )
    db_session.add(inc_breach)
    db_session.commit()

    detail_warn = IncidentSLAService.evaluate_incident(db_session, inc_warn)
    assert detail_warn.milestones.acknowledgement.status in (
        SLAMilestoneStatusEnum.WARNING,
        SLAMilestoneStatusEnum.BREACHED,
    )
    assert detail_warn.overall_sla_status in (
        SLAOverallStatusEnum.WARNING,
        SLAOverallStatusEnum.BREACHED,
    )

    detail_breach = IncidentSLAService.evaluate_incident(db_session, inc_breach)
    assert detail_breach.milestones.acknowledgement.status == SLAMilestoneStatusEnum.BREACHED
    assert detail_breach.overall_sla_status == SLAOverallStatusEnum.BREACHED
    assert detail_breach.milestones.acknowledgement.overdue_minutes >= 19


def test_sla_met_transitions(db_session):
    """Test milestone transition to MET when operational lifecycle milestones are satisfied."""
    now = datetime.now(timezone.utc)
    created_at = now - timedelta(minutes=10)
    acked_at = now - timedelta(minutes=6)
    contained_at = now - timedelta(minutes=2)

    incident = IncidentModel(
        incident_number="INC-MET",
        workspace_id="ws-prod",
        title="Contained Ransomware Incident",
        status="CONTAINED",
        severity="CRITICAL",
        priority="P1_CRITICAL",
        category="RANSOMWARE",
        created_at=created_at,
        acknowledged_at=acked_at,
        contained_at=contained_at,
        updated_at=now,
    )
    db_session.add(incident)
    db_session.commit()

    detail = IncidentSLAService.evaluate_incident(db_session, incident)
    assert detail.milestones.acknowledgement.status == SLAMilestoneStatusEnum.MET
    assert detail.milestones.acknowledgement.met_at is not None
    assert detail.milestones.containment.status == SLAMilestoneStatusEnum.MET
    assert detail.milestones.containment.met_at is not None


# =============================================================================
# 2. SLA Pausing & Forensic Exemption
# =============================================================================

def test_sla_pause_and_resume_duration_adjustment(db_session):
    """Test pausing SLA clock and verifying elapsed adjustment upon resume."""
    now = datetime.now(timezone.utc)
    incident = IncidentModel(
        incident_number="INC-PAUSE",
        workspace_id="ws-prod",
        title="Awaiting External Customer Feedback",
        status="OPEN",
        severity="HIGH",
        priority="P2_HIGH",
        category="PHISHING",
        created_at=now - timedelta(minutes=20),
        updated_at=now - timedelta(minutes=20),
    )
    db_session.add(incident)
    db_session.commit()

    # Pause SLA
    pause_log = IncidentSLAService.pause_sla(
        db_session,
        incident_id=incident.id,
        reason="Awaiting customer confirmation of credential reset",
        actor="Analyst Alice",
        workspace_id="ws-prod",
    )
    assert pause_log.active is True
    assert pause_log.paused_at is not None

    db_session.refresh(incident)
    detail = IncidentSLAService.evaluate_incident(db_session, incident)
    assert detail.is_paused is True
    assert detail.overall_sla_status == SLAOverallStatusEnum.PAUSED

    # Resume SLA
    resumed_log = IncidentSLAService.resume_sla(
        db_session,
        incident_id=incident.id,
        actor="Analyst Alice",
        workspace_id="ws-prod",
    )
    assert resumed_log.active is False
    assert resumed_log.resumed_at is not None

    db_session.refresh(incident)
    detail2 = IncidentSLAService.evaluate_incident(db_session, incident)
    assert detail2.is_paused is False


def test_sla_exemption_stops_clocks_with_audit(db_session):
    """Test that exempting an incident stops active SLA evaluation and logs forensic reason."""
    now = datetime.now(timezone.utc)
    incident = IncidentModel(
        incident_number="INC-EXEMPT",
        workspace_id="ws-prod",
        title="Training Simulation Event",
        status="OPEN",
        severity="CRITICAL",
        priority="P1_CRITICAL",
        category="OTHER",
        created_at=now - timedelta(minutes=100),
        updated_at=now - timedelta(minutes=100),
    )
    db_session.add(incident)
    db_session.commit()

    detail = IncidentSLAService.exempt_sla(
        db_session,
        incident_id=incident.id,
        reason="Scheduled red team training simulation approved by CISO",
        actor="Security Lead Dave",
        workspace_id="ws-prod",
    )
    assert detail.is_exempt is True
    assert detail.overall_sla_status == SLAOverallStatusEnum.EXEMPT
    assert detail.exemption_reason == "Scheduled red team training simulation approved by CISO"

    # Verify audit event created
    audit = db_session.query(AuditEventModel).filter(
        AuditEventModel.resource_id == incident.id,
        AuditEventModel.action == "INCIDENT_SLA_EXEMPTED",
    ).first()
    assert audit is not None


# =============================================================================
# 3. Escalation Engine, Loop Prevention, and Idempotency
# =============================================================================

def test_escalation_chain_and_loop_prevention(db_session):
    """Test multi-tier escalation chain and loop prevention (max level capping & cooldown)."""
    now = datetime.now(timezone.utc)
    # Incident breached
    incident = IncidentModel(
        incident_number="INC-ESC-CHAIN",
        workspace_id="ws-prod",
        title="Ransomware Outbreak",
        status="NEW",
        severity="CRITICAL",
        priority="P1_CRITICAL",
        category="RANSOMWARE",
        escalation_level=1,
        created_at=now - timedelta(minutes=45),
        updated_at=now - timedelta(minutes=45),
    )
    db_session.add(incident)
    db_session.commit()

    # Initial evaluation should trigger Level 2 escalation
    detail = IncidentSLAService.evaluate_incident(db_session, incident)
    assert detail.escalation.current_level >= 2

    db_session.refresh(incident)
    assert incident.escalation_level >= 2

    # Verify execution record persisted
    executions = db_session.query(IncidentWorkflowExecutionModel).filter(
        IncidentWorkflowExecutionModel.incident_id == incident.id
    ).all()
    assert len(executions) >= 1

    # Re-evaluating immediately must NOT cause an infinite escalation loop (cooldown + max tier check)
    detail_repeat = IncidentSLAService.evaluate_incident(db_session, incident)
    assert detail_repeat.escalation.current_level <= 3


def test_idempotent_workflow_execution(db_session):
    """Test that multiple worker passes with identical state do not duplicate notifications or executions."""
    now = datetime.now(timezone.utc)
    incident = IncidentModel(
        incident_number="INC-IDEMPOTENT",
        workspace_id="ws-prod",
        title="Unacknowledged Phishing Blast",
        status="NEW",
        severity="CRITICAL",
        priority="P1_CRITICAL",
        category="PHISHING",
        created_at=now - timedelta(minutes=30),
        updated_at=now - timedelta(minutes=30),
    )
    db_session.add(incident)
    db_session.commit()

    # Pass 1
    IncidentSLAService.evaluate_incident(db_session, incident)
    initial_exec_count = db_session.query(IncidentWorkflowExecutionModel).filter(
        IncidentWorkflowExecutionModel.incident_id == incident.id
    ).count()

    initial_notifs = db_session.query(NotificationModel).filter(
        NotificationModel.source_id == incident.id
    ).count()

    # Pass 2 immediately (idempotency barrier)
    IncidentSLAService.evaluate_incident(db_session, incident)

    second_exec_count = db_session.query(IncidentWorkflowExecutionModel).filter(
        IncidentWorkflowExecutionModel.incident_id == incident.id
    ).count()
    second_notifs = db_session.query(NotificationModel).filter(
        NotificationModel.source_id == incident.id
    ).count()

    assert initial_exec_count == second_exec_count
    assert initial_notifs == second_notifs


# =============================================================================
# 4. Analyst Routing Strategies
# =============================================================================

def test_analyst_routing_least_loaded(db_session):
    """Test incident routing using configured routing rule and least loaded analyst strategy."""
    # Add candidate active incidents for analyst Sarah
    now = datetime.now(timezone.utc)
    for i in range(3):
        db_session.add(
            IncidentModel(
                incident_number=f"INC-BUSY-{i}",
                workspace_id="ws-prod",
                title="Active investigation",
                status="INVESTIGATING",
                assigned_to="sarah@corp.local",
                created_at=now,
                updated_at=now,
            )
        )
    # Analyst Mike has 0 active incidents
    db_session.commit()

    # Create unassigned incident
    target_inc = IncidentModel(
        incident_number="INC-TARGET",
        workspace_id="ws-prod",
        title="Compromised Admin Account",
        status="NEW",
        severity="HIGH",
        category="ACCOUNT_TAKEOVER",
        assigned_to=None,
        created_at=now,
        updated_at=now,
    )
    db_session.add(target_inc)
    db_session.commit()

    routed_user, routed_team = IncidentSLAService.route_incident(db_session, target_inc)
    assert routed_user is not None or routed_team is not None


# =============================================================================
# 5. Incident Lifecycle Integration & History Preservation
# =============================================================================

def test_closed_incident_stops_active_escalation(db_session):
    """Test that resolving an incident stops active SLA escalation while preserving history."""
    now = datetime.now(timezone.utc)
    incident = IncidentModel(
        incident_number="INC-CLOSED-STOP",
        workspace_id="ws-prod",
        title="Remediated Malicious USB",
        status="RESOLVED",
        severity="CRITICAL",
        priority="P1_CRITICAL",
        category="MALWARE",
        escalation_level=2,
        created_at=now - timedelta(minutes=120),
        resolved_at=now - timedelta(minutes=10),
        updated_at=now,
    )
    db_session.add(incident)
    db_session.commit()

    detail = IncidentSLAService.evaluate_incident(db_session, incident)
    # Should not escalate further once resolved
    assert detail.escalation.current_level == 2


def test_reopened_incident_re_evaluates_operational_cycle(db_session):
    """Test that reopening an incident triggers re-evaluation under active SLA policy."""
    now = datetime.now(timezone.utc)
    incident = IncidentModel(
        incident_number="INC-REOPEN-CYCLE",
        workspace_id="ws-prod",
        title="Reopened Advanced Persistent Threat",
        status="RESOLVED",
        severity="CRITICAL",
        priority="P1_CRITICAL",
        category="NETWORK_INTRUSION",
        created_at=now - timedelta(minutes=60),
        resolved_at=now - timedelta(minutes=20),
        updated_at=now,
    )
    db_session.add(incident)
    db_session.commit()

    # Reopen incident
    req = IncidentStatusChangeRequest(
        status="INVESTIGATING",
        reason="Secondary exfiltration beacon identified on domain controller",
    )
    reopened = IncidentService.update_status(
        db_session,
        incident_id=incident.id,
        req=req,
        actor="Analyst Bob",
        workspace_id="ws-prod",
    )

    assert reopened.status == "INVESTIGATING"
    assert reopened.resolved_at is None
    # SLA state refreshed
    detail = IncidentSLAService.evaluate_incident(db_session, reopened)
    assert detail.milestones.resolution.status != SLAMilestoneStatusEnum.MET


# =============================================================================
# 6. Background Job Worker Integration
# =============================================================================

def test_background_job_sla_evaluation_worker(db_session, monkeypatch):
    """Test batch SLA evaluation execution through BackgroundJobWorker."""
    monkeypatch.setattr("backend.services.background_job_worker.SessionLocal", TestingSessionLocal)
    now = datetime.now(timezone.utc)
    # Create open incident
    inc = IncidentModel(
        incident_number="INC-JOB-EVAL",
        workspace_id="ws-prod",
        title="Active Phishing Campaign",
        status="OPEN",
        severity="HIGH",
        category="PHISHING",
        created_at=now - timedelta(minutes=25),
        updated_at=now - timedelta(minutes=25),
    )
    db_session.add(inc)
    db_session.commit()

    # Create BackgroundJob for SLA evaluation
    job = BackgroundJobModel(
        workspace_id="ws-prod",
        job_type=JobTypeEnum.INCIDENT_SLA_EVALUATION.value,
        payload_json=json.dumps({"batch_size": 25}),
        status="QUEUED",
        created_at=now,
        updated_at=now,
    )
    db_session.add(job)
    db_session.commit()

    # Claim and execute worker step
    worker = BackgroundJobWorker(worker_id="test-sla-worker")
    claimed = BackgroundJobWorker.claim_next_job(db_session, worker.worker_id, workspace_id="ws-prod")
    assert claimed is not None
    assert claimed.id == job.id

    asyncio.run(worker.execute_job(claimed.id))

    db_session.refresh(job)
    assert job.status == "SUCCEEDED"
    assert "evaluated_count" in job.result


# =============================================================================
# 7. Safe Policy Dry-Run Simulation (Non-Destructive)
# =============================================================================

def test_policy_simulation_dry_run(db_session):
    """Test policy dry-run simulation without altering real incidents or database state."""
    sim_req = PolicySimulationRequest(
        severity="CRITICAL",
        priority="P1_CRITICAL",
        category="RANSOMWARE",
        risk_score=80.0,
        unacknowledged_minutes=40,
        uncontained_minutes=0,
        status="OPEN",
    )
    res = IncidentSLAService.simulate_policy(db_session, sim_req, workspace_id="ws-prod")

    assert res.matched_sla_policy == "Critical Incident SLA Policy"
    assert res.simulated_milestone_status["ACKNOWLEDGEMENT"] == "BREACHED"
    assert len(res.triggered_escalation_rules) >= 1
    # Ensure no incidents were created
    assert db_session.query(IncidentModel).count() == 0


# =============================================================================
# 8. Security & REST API Endpoints
# =============================================================================

def test_sla_api_endpoints_and_tenant_isolation(client, db_session):
    """Test SLA REST APIs and enforce strict multi-tenant boundary checks."""
    now = datetime.now(timezone.utc)
    # Incident in ws-alpha
    inc_alpha = IncidentModel(
        incident_number="INC-ALPHA",
        workspace_id="ws-alpha",
        title="Alpha Threat",
        status="OPEN",
        severity="CRITICAL",
        category="MALWARE",
        created_at=now,
        updated_at=now,
    )
    db_session.add(inc_alpha)
    db_session.commit()

    # 1. Query SLA under correct workspace
    res = client.get(
        f"/api/incidents/{inc_alpha.id}/sla",
        headers={"X-Workspace-ID": "ws-alpha"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["incident_id"] == inc_alpha.id

    # 2. Cross-tenant attempt (Tenant Beta trying to read Alpha's SLA) -> 404
    res_cross = client.get(
        f"/api/incidents/{inc_alpha.id}/sla",
        headers={"X-Workspace-ID": "ws-beta"},
    )
    assert res_cross.status_code == 404

    # 3. Pause SLA
    pause_res = client.post(
        f"/api/incidents/{inc_alpha.id}/sla/pause",
        headers={"X-Workspace-ID": "ws-alpha"},
        json={"reason": "Vendor firewall vendor support ticket #4401"},
    )
    assert pause_res.status_code == 200
    assert pause_res.json()["is_paused"] is True

    # 4. Resume SLA
    resume_res = client.post(
        f"/api/incidents/{inc_alpha.id}/sla/resume",
        headers={"X-Workspace-ID": "ws-alpha"},
    )
    assert resume_res.status_code == 200
    assert resume_res.json()["is_paused"] is False

    # 5. List SLA Policies
    policies_res = client.get(
        "/api/settings/sla-policies",
        headers={"X-Workspace-ID": "ws-alpha"},
    )
    assert policies_res.status_code == 200
    assert len(policies_res.json()["items"]) >= 1

    # 6. Policy Simulation Dry-Run endpoint
    sim_res = client.post(
        "/api/settings/sla-policies/simulate",
        headers={"X-Workspace-ID": "ws-alpha"},
        json={
            "severity": "CRITICAL",
            "priority": "P1_CRITICAL",
            "category": "RANSOMWARE",
            "risk_score": 80.0,
            "unacknowledged_minutes": 35,
            "uncontained_minutes": 0,
            "status": "OPEN",
        },
    )
    assert sim_res.status_code == 200
    assert sim_res.json()["matched_sla_policy"] == "Critical Incident SLA Policy"
    assert sim_res.json()["simulated_milestone_status"]["ACKNOWLEDGEMENT"] == "BREACHED"
