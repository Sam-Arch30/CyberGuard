"""
Unit and Integration Tests for Section 47: Notifications & Alert Center.
Verifies policy evaluation, deduplication, persistent models, tenant isolation,
read/unread states, alert acknowledgement, and Section 46 real-time integration.
"""
import pytest
import uuid
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.db.models import (
    Base,
    NotificationModel,
    FindingModel,
    AnalysisRunModel,
    ArtifactModel,
    ReportModel,
    BackgroundJobModel,
)
from backend.schemas.notification import (
    NotificationCategoryEnum,
    NotificationSeverityEnum,
    NotificationStatusEnum,
    NotificationTypeEnum,
)
from backend.services.notification_policy import NotificationPolicy
from backend.services.notification_service import NotificationService
from backend.services.realtime_service import global_realtime_hub
from backend.main import app
from backend.db.session import get_db

# In-memory SQLite session for isolated unit tests
@pytest.fixture
def db_session():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture
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


# ============================================================================
# 1. NOTIFICATION POLICY TESTS
# ============================================================================

def test_policy_evaluates_findings_critical_and_high():
    # Critical finding produces security alert
    crit_decision = NotificationPolicy.evaluate_finding(
        finding_id="fnd-crit-1",
        finding_type="dangerous_attachment_type",
        title="High Risk Executable Attachment: payload.exe",
        severity="CRITICAL",
        risk_contribution=45.0,
        analyzer="AttachmentSecurityAnalyzer",
        investigation_id="INV-100",
        description="Double extension PE32 executable found in archive.",
        workspace_id="test_ws",
    )
    assert crit_decision.should_notify is True
    assert crit_decision.category == NotificationCategoryEnum.SECURITY_ALERT.value
    assert crit_decision.severity == "CRITICAL"
    assert crit_decision.notification_type == NotificationTypeEnum.MALICIOUS_ATTACHMENT_DETECTED.value
    assert "/investigations/INV-100" in crit_decision.navigation_target
    assert "alert:finding:test_ws:fnd-crit-1" == crit_decision.deduplication_key

    # High finding produces security alert
    high_decision = NotificationPolicy.evaluate_finding(
        finding_id="fnd-high-1",
        finding_type="lookalike_impersonation",
        title="Lookalike Domain Detected: paypa1.com",
        severity="HIGH",
        risk_contribution=35.0,
        analyzer="LookalikeDetectorService",
        investigation_id="INV-100",
        workspace_id="test_ws",
    )
    assert high_decision.should_notify is True
    assert high_decision.category == NotificationCategoryEnum.SECURITY_ALERT.value
    assert high_decision.severity == "HIGH"
    assert high_decision.notification_type == NotificationTypeEnum.LOOKALIKE_IMPERSONATION_DETECTED.value

    # Routine Low finding is suppressed
    low_decision = NotificationPolicy.evaluate_finding(
        finding_id="fnd-low-1",
        finding_type="plain_text_relay",
        title="Plain Text Hop",
        severity="LOW",
        risk_contribution=2.0,
        analyzer="SMTPRelayAnalyzer",
        workspace_id="test_ws",
    )
    assert low_decision.should_notify is False


def test_policy_evaluates_analysis_runs():
    # Completed run creates notification
    comp_decision = NotificationPolicy.evaluate_analysis_run(
        run_id="run-1",
        status="COMPLETED",
        overall_severity="HIGH",
        overall_risk_score=78.0,
        investigation_id="INV-200",
        workspace_id="test_ws",
    )
    assert comp_decision.should_notify is True
    assert comp_decision.category == NotificationCategoryEnum.NOTIFICATION.value
    assert comp_decision.severity == "HIGH"
    assert "78/100" in comp_decision.message

    # Failed run creates notification
    fail_decision = NotificationPolicy.evaluate_analysis_run(
        run_id="run-2",
        status="FAILED",
        error_message="Connection timed out to threat feed",
        workspace_id="test_ws",
    )
    assert fail_decision.should_notify is True
    assert fail_decision.category == NotificationCategoryEnum.NOTIFICATION.value
    assert fail_decision.notification_type == NotificationTypeEnum.ANALYSIS_FAILED.value
    assert fail_decision.severity == "HIGH"

    # Queued / Running states are ignored
    queued_decision = NotificationPolicy.evaluate_analysis_run(
        run_id="run-3",
        status="RUNNING",
    )
    assert queued_decision.should_notify is False


def test_policy_evaluates_reports_and_jobs():
    # Report ready creates notification
    rep_decision = NotificationPolicy.evaluate_report(
        report_id="rep-1",
        report_number="REP-2026-001",
        status="READY",
        investigation_id="INV-300",
    )
    assert rep_decision.should_notify is True
    assert rep_decision.notification_type == NotificationTypeEnum.REPORT_READY.value
    assert rep_decision.severity == "INFO"

    # Job failed creates notification
    job_decision = NotificationPolicy.evaluate_job(
        job_id="job-1",
        job_type="ARTIFACT_ANALYSIS",
        status="FAILED",
        error_message="Worker process encountered SIGSEGV",
    )
    assert job_decision.should_notify is True
    assert job_decision.notification_type == NotificationTypeEnum.JOB_FAILED.value


# ============================================================================
# 2. PERSISTENCE & DEDUPLICATION TESTS
# ============================================================================

def test_notification_deduplication(db_session):
    # First creation succeeds
    n1 = NotificationService.create_notification(
        db=db_session,
        workspace_id="default",
        category="SECURITY_ALERT",
        notification_type="CRITICAL_THREAT_DETECTED",
        severity="CRITICAL",
        title="Credential Theft Detected",
        message="Harvesting form detected",
        source_type="FINDING",
        source_id="fnd-123",
        deduplication_key="alert:finding:default:fnd-123",
        investigation_id="INV-999",
    )
    assert n1 is not None
    assert n1.id is not None

    # Repeated creation with same deduplication key is suppressed (returns existing)
    n2 = NotificationService.create_notification(
        db=db_session,
        workspace_id="default",
        category="SECURITY_ALERT",
        notification_type="CRITICAL_THREAT_DETECTED",
        severity="CRITICAL",
        title="Duplicate Attempt",
        message="Harvesting form detected duplicate",
        source_type="FINDING",
        source_id="fnd-123",
        deduplication_key="alert:finding:default:fnd-123",
        investigation_id="INV-999",
    )
    assert n2 is not None
    assert n2.id == n1.id

    # Verify only 1 row exists in database
    count = db_session.query(NotificationModel).count()
    assert count == 1


def test_tenant_workspace_isolation(db_session):
    # Insert in tenant A
    NotificationService.create_notification(
        db=db_session,
        workspace_id="tenant_alpha",
        category="SECURITY_ALERT",
        notification_type="CRITICAL_THREAT_DETECTED",
        severity="CRITICAL",
        title="Tenant Alpha Alert",
        message="Critical threat in alpha",
        source_type="FINDING",
        source_id="fnd-alpha",
        deduplication_key="dedup-alpha",
    )

    # Insert in tenant B
    NotificationService.create_notification(
        db=db_session,
        workspace_id="tenant_beta",
        category="NOTIFICATION",
        notification_type="REPORT_READY",
        severity="INFO",
        title="Tenant Beta Report",
        message="Report ready in beta",
        source_type="REPORT",
        source_id="rep-beta",
        deduplication_key="dedup-beta",
    )

    # Query tenant Alpha
    res_alpha = NotificationService.list_notifications(db=db_session, workspace_id="tenant_alpha")
    assert res_alpha.total == 1
    assert res_alpha.items[0].title == "Tenant Alpha Alert"
    assert res_alpha.unread_alerts == 1
    assert res_alpha.unread_notifications == 0

    # Query tenant Beta
    res_beta = NotificationService.list_notifications(db=db_session, workspace_id="tenant_beta")
    assert res_beta.total == 1
    assert res_beta.items[0].title == "Tenant Beta Report"
    assert res_beta.unread_alerts == 0
    assert res_beta.unread_notifications == 1

    # Query unknown tenant
    res_empty = NotificationService.list_notifications(db=db_session, workspace_id="tenant_gamma")
    assert res_empty.total == 0


# ============================================================================
# 3. READ STATE & ACKNOWLEDGEMENT TESTS
# ============================================================================

def test_mark_as_read_and_unread_counts(db_session):
    n = NotificationService.create_notification(
        db=db_session,
        workspace_id="ws1",
        category="SECURITY_ALERT",
        notification_type="HIGH_RISK_THREAT_DETECTED",
        severity="HIGH",
        title="High Alert",
        message="Alert message",
        source_type="FINDING",
        source_id="fnd-1",
        deduplication_key="k1",
    )

    # Initial count
    counts = NotificationService.get_unread_count(db=db_session, workspace_id="ws1")
    assert counts.total_unread == 1
    assert counts.alerts_unread == 1

    # Mark as read
    updated = NotificationService.mark_as_read(db=db_session, notification_id=n.id, workspace_id="ws1")
    assert updated.status == "READ"
    assert updated.read_at is not None

    # Recalculate unread count
    counts_after = NotificationService.get_unread_count(db=db_session, workspace_id="ws1")
    assert counts_after.total_unread == 0
    assert counts_after.alerts_unread == 0


def test_mark_all_as_read(db_session):
    for i in range(5):
        NotificationService.create_notification(
            db=db_session,
            workspace_id="ws_batch",
            category="NOTIFICATION",
            notification_type="ANALYSIS_COMPLETED",
            severity="INFO",
            title=f"Notification {i}",
            message=f"Run {i} completed",
            source_type="ANALYSIS_RUN",
            source_id=f"run-{i}",
            deduplication_key=f"k-batch-{i}",
        )

    counts = NotificationService.get_unread_count(db=db_session, workspace_id="ws_batch")
    assert counts.total_unread == 5

    marked = NotificationService.mark_all_as_read(db=db_session, workspace_id="ws_batch")
    assert marked == 5

    counts_after = NotificationService.get_unread_count(db=db_session, workspace_id="ws_batch")
    assert counts_after.total_unread == 0


def test_alert_acknowledgement(db_session):
    alert = NotificationService.create_notification(
        db=db_session,
        workspace_id="ws_ack",
        category="SECURITY_ALERT",
        notification_type="CRITICAL_THREAT_DETECTED",
        severity="CRITICAL",
        title="Ransomware Dropper Observed",
        message="Immediate triage required",
        source_type="FINDING",
        source_id="fnd-dropper",
        deduplication_key="k-dropper",
    )

    acked = NotificationService.acknowledge_alert(
        db=db_session,
        notification_id=alert.id,
        workspace_id="ws_ack",
        analyst_name="Agent Mulder",
        note="Host contained at perimeter firewall.",
    )
    assert acked is not None
    assert acked.status == "ACKNOWLEDGED"
    assert acked.acknowledged_by == "Agent Mulder"
    assert acked.acknowledged_at is not None
    assert acked.metadata.get("acknowledgement_note") == "Host contained at perimeter firewall."


# ============================================================================
# 4. REST API ENDPOINT TESTS
# ============================================================================

def test_api_notifications_endpoints(client, db_session):
    # 1. Create a notification in test DB
    notif = NotificationService.create_notification(
        db=db_session,
        workspace_id="api_ws",
        category="SECURITY_ALERT",
        notification_type="CRITICAL_THREAT_DETECTED",
        severity="CRITICAL",
        title="API Test Critical Alert",
        message="Critical threat verification",
        source_type="FINDING",
        source_id="fnd-api",
        deduplication_key="k-api-1",
        investigation_id="INV-API-1",
    )

    headers = {"X-Workspace-ID": "api_ws"}

    # 2. GET /api/notifications
    res = client.get("/api/notifications", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["total"] == 1
    assert data["items"][0]["id"] == notif.id
    assert data["unread_total"] == 1
    assert data["unread_alerts"] == 1

    # 3. GET /api/notifications/unread-count
    cnt_res = client.get("/api/notifications/unread-count", headers=headers)
    assert cnt_res.status_code == 200
    cnt_data = cnt_res.json()
    assert cnt_data["total_unread"] == 1
    assert cnt_data["alerts_unread"] == 1

    # 4. PATCH /api/notifications/{id}/read
    read_res = client.patch(f"/api/notifications/{notif.id}/read", headers=headers)
    assert read_res.status_code == 200
    assert read_res.json()["status"] == "READ"

    # 5. PATCH /api/notifications/{id}/acknowledge
    ack_res = client.patch(
        f"/api/notifications/{notif.id}/acknowledge",
        headers=headers,
        json={"analyst_name": "Senior SOC Analyst", "note": "Verified genuine phishing attempt."},
    )
    assert ack_res.status_code == 200
    ack_data = ack_res.json()
    assert ack_data["status"] == "ACKNOWLEDGED"
    assert ack_data["acknowledged_by"] == "Senior SOC Analyst"

    # 6. POST /api/notifications/read-all
    read_all_res = client.post("/api/notifications/read-all", headers=headers)
    assert read_all_res.status_code == 200
    assert read_all_res.json()["success"] is True
