"""
Automated test suite for Section 44: SOC Overview Dashboard.
Verifies Security Posture metrics, deterministic Priority Queue,
Risk Distribution, Audit Activity, Threat Intelligence, and System Health.
Enforces real persisted data only and immutability invariants.
"""
from datetime import datetime, timezone, timedelta
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.main import app
from backend.db.session import get_db, SessionLocal, engine
from backend.db.models import (
    Base,
    IncidentModel,
    CaseModel,
    FindingModel,
    IndicatorModel,
    ResponseRecommendationModel,
    AuditLogModel,
    EndpointAgentModel,
    AnalysisRunModel,
    BackgroundJobModel,
    BackgroundJobEventModel,
)


@pytest.fixture
def db_session():
    """Provides an isolated database session with cleanup."""
    db = SessionLocal()
    # Allow audit log cleanup for test isolation
    try:
        setattr(db.connection(), "_allow_audit_cleanup", True)
        db.query(BackgroundJobEventModel).delete()
        db.query(BackgroundJobModel).delete()
        db.query(IncidentModel).delete()
        db.query(CaseModel).delete()
        db.query(FindingModel).delete()
        db.query(IndicatorModel).delete()
        db.query(ResponseRecommendationModel).delete()
        db.query(AuditLogModel).delete()
        db.query(AnalysisRunModel).delete()
        db.commit()
    except Exception:
        pass

    try:
        yield db
    finally:
        try:
            setattr(db.connection(), "_allow_audit_cleanup", True)
            db.query(BackgroundJobEventModel).delete()
            db.query(BackgroundJobModel).delete()
            db.query(IncidentModel).delete()
            db.query(CaseModel).delete()
            db.query(FindingModel).delete()
            db.query(IndicatorModel).delete()
            db.query(ResponseRecommendationModel).delete()
            db.query(AuditLogModel).delete()
            db.query(AnalysisRunModel).delete()
            db.commit()
        except Exception:
            db.rollback()
        db.close()


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


def test_empty_database_soc_overview(client, db_session):
    """Empty database should produce truthful zero metrics and operational health without fabrication."""
    response = client.get("/api/dashboard/overview?time_window=30d")
    assert response.status_code == 200
    data = response.json()

    assert data["time_window"] == "30d"
    assert "generated_at" in data

    # Posture metrics must be truthful 0
    posture = data["posture"]
    assert posture["active_investigations"] == 0
    assert posture["high_risk_open"] == 0
    assert posture["pending_response_approvals"] == 0
    assert posture["failed_analysis_jobs"] == 0
    assert posture["new_findings_count"] == 0
    assert posture["total_investigations"] == 0

    # Risk distribution empty
    risk_dist = data["risk_distribution"]
    assert risk_dist["critical"] == 0
    assert risk_dist["high"] == 0
    assert risk_dist["total"] == 0

    # Priority queue empty
    assert data["priority_queue"] == []

    # Health reflects real database check
    health = data["system_health"]
    assert health["database_status"] == "connected"
    assert health["api_status"] == "healthy"
    assert health["status"] == "operational"


def test_posture_metrics_aggregation(client, db_session):
    """Verifies active vs closed investigations, high-risk detection, and pending approvals."""
    now = datetime.now(timezone.utc)

    # 1. Active Critical Incident
    inc_active = IncidentModel(
        id="INC-TEST-ACTIVE",
        incident_number="INC-2026-ACTIVE",
        workspace_id="default",
        title="Active Ransomware Dropper",
        status="INVESTIGATING",
        severity="CRITICAL",
        risk_score=95.0,
        opened_at=now,
        created_at=now,
        updated_at=now,
    )
    # 2. Closed Incident (should not be counted in active_investigations)
    inc_closed = IncidentModel(
        id="INC-TEST-CLOSED",
        incident_number="INC-2026-CLOSED",
        workspace_id="default",
        title="Resolved Phishing Campaign",
        status="CLOSED",
        severity="HIGH",
        risk_score=75.0,
        opened_at=now - timedelta(days=2),
        closed_at=now,
        created_at=now - timedelta(days=2),
        updated_at=now,
    )
    # 3. Defensive Recommendation requiring review
    rec = ResponseRecommendationModel(
        id="REC-TEST-APPROVAL",
        workspace_id="default",
        scope_type="INCIDENT",
        scope_id="INC-TEST-ACTIVE",
        action_type="ISOLATE_HOST",
        title="Host Isolation Recommendation",
        description="Quarantine infected endpoint",
        rationale="Active C2 beacon observed",
        priority="P0",
        urgency="IMMEDIATE",
        expected_effect="Network isolation",
        approval_required=True,
        status="REVIEW_REQUIRED",
        created_at=now,
        updated_at=now,
    )

    db_session.add_all([inc_active, inc_closed, rec])
    db_session.commit()

    response = client.get("/api/dashboard/overview?time_window=30d")
    assert response.status_code == 200
    data = response.json()

    posture = data["posture"]
    assert posture["active_investigations"] == 1
    assert posture["high_risk_open"] == 1
    assert posture["pending_response_approvals"] == 1
    assert posture["total_investigations"] == 2

    # Risk distribution evaluates all 2 incidents (1 critical, 1 high)
    risk_dist = data["risk_distribution"]
    assert risk_dist["critical"] == 1
    assert risk_dist["high"] == 1
    assert risk_dist["total"] == 2


def test_priority_queue_deterministic_ranking(client, db_session):
    """Verifies priority queue sorts by urgency (P0 > P1 > P2) and risk score deterministically."""
    now = datetime.now(timezone.utc)

    inc_crit = IncidentModel(
        id="INC-CRIT-P0",
        incident_number="INC-001",
        workspace_id="default",
        title="Executive Account Takeover",
        status="OPEN",
        severity="CRITICAL",
        risk_score=92.0,
        created_at=now,
        updated_at=now,
    )
    inc_high = IncidentModel(
        id="INC-HIGH-P1",
        incident_number="INC-002",
        workspace_id="default",
        title="Suspicious Outbound Tunnel",
        status="INVESTIGATING",
        severity="HIGH",
        risk_score=68.0,
        created_at=now,
        updated_at=now,
    )
    db_session.add_all([inc_crit, inc_high])
    db_session.commit()

    response = client.get("/api/dashboard/overview?time_window=30d")
    assert response.status_code == 200
    data = response.json()

    queue = data["priority_queue"]
    assert len(queue) >= 2
    assert queue[0]["id"] == "INC-CRIT-P0"
    assert queue[0]["urgency"] == "P0"
    assert queue[0]["severity"] == "CRITICAL"
    assert queue[0]["navigation_target"] == "/incidents/INC-CRIT-P0"

    assert queue[1]["id"] == "INC-HIGH-P1"
    assert queue[1]["urgency"] == "P1"
    assert queue[1]["severity"] == "HIGH"


def test_time_window_filtering(client, db_session):
    """Verifies that windowed metrics correctly respect 24h vs 30d time boundaries."""
    now = datetime.now(timezone.utc)

    # Need AnalysisRunModel for foreign key constraint
    run = AnalysisRunModel(
        id="RUN-TEST-FINDINGS",
        artifact_id="ART-TEST",
        status="COMPLETED",
        started_at=now,
    )
    db_session.add(run)
    db_session.commit()

    # 1. Finding created 48 hours ago
    old_finding = FindingModel(
        id="FND-OLD",
        analysis_run_id="RUN-TEST-FINDINGS",
        finding_type="CREDENTIAL_HARVESTING",
        title="Historical Credential Harvesting",
        description="Observed 2 days ago",
        severity="HIGH",
        analyzer="email_analyzer",
        method="HEURISTIC",
        created_at=now - timedelta(hours=48),
    )
    # 2. Finding created 2 hours ago
    new_finding = FindingModel(
        id="FND-NEW",
        analysis_run_id="RUN-TEST-FINDINGS",
        finding_type="DGA_DOMAIN",
        title="Fresh DGA Domain",
        description="Observed 2 hours ago",
        severity="CRITICAL",
        analyzer="domain_analyzer",
        method="HEURISTIC",
        created_at=now - timedelta(hours=2),
    )
    db_session.add_all([old_finding, new_finding])
    db_session.commit()

    # Query 24h window
    resp_24h = client.get("/api/dashboard/overview?time_window=24h")
    assert resp_24h.status_code == 200
    data_24h = resp_24h.json()
    assert data_24h["posture"]["new_findings_count"] == 1

    # Query 30d window
    resp_30d = client.get("/api/dashboard/overview?time_window=30d")
    assert resp_30d.status_code == 200
    data_30d = resp_30d.json()
    assert data_30d["posture"]["new_findings_count"] == 2


def test_activity_feed_real_events(client, db_session):
    """Verifies that audit log records are accurately transformed into activity items with navigation targets."""
    now = datetime.now(timezone.utc)

    audit_entry = AuditLogModel(
        id="AUD-001",
        timestamp=now,
        user="analyst@cyberguard.sec",
        action="CASE_CREATED",
        resource_type="case",
        resource_id="CASE-2026-X1",
        details="Initial ingestion confirmed",
    )
    db_session.add(audit_entry)
    db_session.commit()

    response = client.get("/api/dashboard/overview?time_window=30d")
    assert response.status_code == 200
    data = response.json()

    activity = data["recent_activity"]
    assert len(activity) >= 1
    first_event = activity[0]
    assert first_event["event_type"] == "CASE_CREATED"
    assert "New investigation incident record established" in first_event["description"]
    assert first_event["user"] == "analyst@cyberguard.sec"
    assert first_event["navigation_target"] == "/investigations/CASE-2026-X1/overview"


def test_threat_intel_and_system_health(client, db_session):
    """Verifies threat intelligence indicators and database/API health states."""
    now = datetime.now(timezone.utc)

    ind = IndicatorModel(
        id="IOC-001",
        value="malicious-c2.example.com",
        normalized_value="malicious-c2.example.com",
        indicator_type="domain",
        reputation="MALICIOUS",
        first_seen=now,
        last_seen=now,
        created_at=now,
    )
    db_session.add(ind)
    db_session.commit()

    response = client.get("/api/dashboard/overview?time_window=30d")
    assert response.status_code == 200
    data = response.json()

    # Threat Intel
    assert len(data["threat_intel"]) >= 1
    assert data["threat_intel"][0]["indicator_value"] == "malicious-c2.example.com"
    assert data["threat_intel"][0]["indicator_type"] == "DOMAIN"
    assert data["threat_intel"][0]["provenance"] in ["CURRENT_OBSERVATION", "HISTORICAL_MEMORY"]

    # System Health
    health = data["system_health"]
    assert health["status"] in ["operational", "degraded"]
    assert health["database_status"] == "connected"
    assert health["api_status"] == "healthy"
