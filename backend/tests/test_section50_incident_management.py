"""
Section 50: Comprehensive Tests for Incident Management & Case Lifecycle Subsystem.
Verifies incident creation, promotion from alerts and clusters, duplicate prevention,
lifecycle state machine transitions, reopening, analyst assignment, notes, timeline events,
tenant isolation, and REST APIs.
"""
import json
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.main import app
from backend.db.session import Base, get_db
from backend.db.models import (
    IncidentModel,
    IncidentTimelineEventModel,
    IncidentNoteModel,
    NotificationModel,
    AlertClusterModel,
    AlertClusterMemberModel,
    AuditLogModel,
)
from sqlalchemy.pool import StaticPool

from backend.schemas.incidents import (
    IncidentCreateRequest,
    IncidentPromoteAlertRequest,
    IncidentPromoteClusterRequest,
    IncidentStatusChangeRequest,
    IncidentAssignRequest,
    IncidentNoteCreateRequest,
    IncidentStatusEnum,
    IncidentPriorityEnum,
    IncidentCategoryEnum,
)
from backend.services.incident_service import IncidentService

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
# Unit & Domain Tests
# =============================================================================

def test_incident_creation_and_number_generation(db_session):
    """Test incident case creation with sequential identifier and timeline event."""
    req = IncidentCreateRequest(
        title="Active Credential Harvesting Campaign",
        description="Multiple employees targeted with Microsoft lookalike phishing.",
        severity="CRITICAL",
        category="CREDENTIAL_COMPROMISE",
    )
    incident = IncidentService.create_incident(db_session, req, workspace_id="ws-alpha", actor="Analyst Bob")

    assert incident.id is not None
    assert incident.incident_number.startswith("INC-")
    assert incident.status == IncidentStatusEnum.OPEN.value
    assert incident.severity == "CRITICAL"
    assert incident.priority == IncidentPriorityEnum.P1_CRITICAL.value
    assert incident.category == "CREDENTIAL_COMPROMISE"
    assert incident.created_by == "Analyst Bob"

    # Verify genesis timeline event
    assert len(incident.timeline_events) == 1
    assert incident.timeline_events[0].event_type == "INCIDENT_CREATED"

    # Verify audit log
    audit = db_session.query(AuditLogModel).filter(AuditLogModel.resource_id == incident.id).first()
    assert audit is not None
    assert audit.action == "INCIDENT_CREATED"


def test_promote_alert_to_incident(db_session):
    """Test promoting a standalone security alert to an operational incident case."""
    alert = NotificationModel(
        id="alt-101",
        workspace_id="ws-alpha",
        title="Suspicious Outbound Connection",
        message="Endpoint reached known C2 domain evil-c2.net",
        notification_type="CRITICAL_THREAT_DETECTED",
        severity="HIGH",
        metadata_json=json.dumps({"risk_score": 75.0}),
        category="SECURITY_ALERT",
        status="OPEN",
    )
    db_session.add(alert)
    db_session.commit()

    promote_req = IncidentPromoteAlertRequest(
        alert_id=alert.id,
        notes="High risk beaconing observed.",
    )
    incident = IncidentService.promote_alert_to_incident(db_session, promote_req, workspace_id="ws-alpha", actor="Alice")

    assert incident.primary_alert_id == alert.id
    assert incident.severity == "HIGH"
    assert incident.priority == IncidentPriorityEnum.P2_HIGH.value

    # Verify alert status transitioned and investigation_id linked
    db_session.refresh(alert)
    assert alert.investigation_id == incident.id
    assert alert.status == "INVESTIGATING"

    # Check timeline events (INCIDENT_CREATED, ALERT_LINKED, ALERT_PROMOTED)
    event_types = [e.event_type for e in incident.timeline_events]
    assert "INCIDENT_CREATED" in event_types
    assert "ALERT_PROMOTED" in event_types


def test_promote_cluster_to_incident(db_session):
    """Test promoting an entire AlertCluster into an authoritative Incident case."""
    cluster = AlertClusterModel(
        id="clu-201",
        cluster_number="CLU-ABC12345",
        workspace_id="ws-alpha",
        title="Multi-stage Ransomware Precursor",
        summary="Phishing followed by C2 callback and LSASS dumping.",
        severity="CRITICAL",
        risk_score=88.0,
        confidence=0.92,
        alert_count=3,
        status="OPEN",
    )
    db_session.add(cluster)

    m1 = NotificationModel(id="alt-a", workspace_id="ws-alpha", title="Phish Email", message="Phish", notification_type="CRITICAL_THREAT_DETECTED", category="SECURITY_ALERT", severity="HIGH", status="OPEN")
    m2 = NotificationModel(id="alt-b", workspace_id="ws-alpha", title="C2 Beacon", message="Beacon", notification_type="CRITICAL_THREAT_DETECTED", category="SECURITY_ALERT", severity="CRITICAL", status="OPEN")
    db_session.add_all([m1, m2])
    db_session.flush()

    db_session.add(AlertClusterMemberModel(id="mem-1", cluster_id=cluster.id, alert_id=m1.id))
    db_session.add(AlertClusterMemberModel(id="mem-2", cluster_id=cluster.id, alert_id=m2.id))
    db_session.commit()

    promote_req = IncidentPromoteClusterRequest(cluster_id=cluster.id)
    incident = IncidentService.promote_cluster_to_incident(db_session, promote_req, workspace_id="ws-alpha", actor="Analyst Eve")

    assert incident.primary_cluster_id == cluster.id
    assert incident.severity == "CRITICAL"
    assert incident.priority == IncidentPriorityEnum.P1_CRITICAL.value

    # Check cluster and members updated
    db_session.refresh(cluster)
    assert cluster.investigation_id == incident.id
    assert cluster.status == "INVESTIGATING"

    db_session.refresh(m1)
    db_session.refresh(m2)
    assert m1.investigation_id == incident.id
    assert m2.investigation_id == incident.id


def test_duplicate_incident_prevention(db_session):
    """Ensure promoting the same alert or cluster twice returns existing active incident."""
    alert = NotificationModel(
        id="alt-dup",
        workspace_id="ws-alpha",
        title="Duplicate Test Alert",
        message="Test alert",
        notification_type="CRITICAL_THREAT_DETECTED",
        severity="MEDIUM",
        category="SECURITY_ALERT",
        status="OPEN",
    )
    db_session.add(alert)
    db_session.commit()

    promote_req = IncidentPromoteAlertRequest(alert_id=alert.id)
    inc1 = IncidentService.promote_alert_to_incident(db_session, promote_req, workspace_id="ws-alpha")
    inc2 = IncidentService.promote_alert_to_incident(db_session, promote_req, workspace_id="ws-alpha")

    assert inc1.id == inc2.id
    assert inc1.incident_number == inc2.incident_number
    assert db_session.query(IncidentModel).count() == 1


def test_valid_lifecycle_transitions(db_session):
    """Test full sequential lifecycle: NEW -> OPEN -> ACKNOWLEDGED -> INVESTIGATING -> CONTAINED -> RESOLVED -> CLOSED."""
    inc = IncidentService.create_incident(
        db_session,
        IncidentCreateRequest(title="Lifecycle Test", severity="HIGH"),
        workspace_id="ws-alpha",
    )
    assert inc.status == "OPEN"

    # Acknowledge
    inc = IncidentService.transition_status(
        db_session, inc.id, IncidentStatusChangeRequest(status="ACKNOWLEDGED"), workspace_id="ws-alpha"
    )
    assert inc.status == "ACKNOWLEDGED"
    assert inc.acknowledged_at is not None

    # Investigating
    inc = IncidentService.transition_status(
        db_session, inc.id, IncidentStatusChangeRequest(status="INVESTIGATING"), workspace_id="ws-alpha"
    )
    assert inc.status == "INVESTIGATING"

    # Contained
    inc = IncidentService.transition_status(
        db_session, inc.id, IncidentStatusChangeRequest(status="CONTAINED"), workspace_id="ws-alpha"
    )
    assert inc.status == "CONTAINED"
    assert inc.contained_at is not None

    # Resolved (requires resolution_reason)
    inc = IncidentService.transition_status(
        db_session,
        inc.id,
        IncidentStatusChangeRequest(status="RESOLVED", resolution_reason="THREAT_CONTAINED"),
        workspace_id="ws-alpha",
    )
    assert inc.status == "RESOLVED"
    assert inc.resolved_at is not None
    assert inc.resolution_reason == "THREAT_CONTAINED"

    # Closed
    inc = IncidentService.transition_status(
        db_session, inc.id, IncidentStatusChangeRequest(status="CLOSED"), workspace_id="ws-alpha"
    )
    assert inc.status == "CLOSED"
    assert inc.closed_at is not None


def test_invalid_lifecycle_transition_rejected(db_session):
    """Test invalid status transitions are rejected with 400 Bad Request."""
    inc = IncidentService.create_incident(
        db_session,
        IncidentCreateRequest(title="State Machine Test", severity="LOW"),
        workspace_id="ws-alpha",
    )
    # Cannot jump from OPEN directly to CLOSED without resolution/investigation or from CLOSED to CONTAINED
    inc.status = "CLOSED"
    db_session.commit()

    with pytest.raises(Exception) as exc_info:
        IncidentService.transition_status(
            db_session, inc.id, IncidentStatusChangeRequest(status="CONTAINED"), workspace_id="ws-alpha"
        )
    assert "Invalid incident state transition" in str(exc_info.value)


def test_reopen_incident(db_session):
    """Test reopening a closed incident resets closed_at and records timeline event."""
    inc = IncidentService.create_incident(
        db_session,
        IncidentCreateRequest(title="Reopen Test", severity="MEDIUM"),
        workspace_id="ws-alpha",
    )
    inc.status = "CLOSED"
    inc.closed_at = datetime.now(timezone.utc)
    db_session.commit()

    reopened = IncidentService.transition_status(
        db_session,
        inc.id,
        IncidentStatusChangeRequest(status="OPEN", reason="New outbound telemetry observed on host"),
        workspace_id="ws-alpha",
        actor="Analyst Charlie",
    )

    assert reopened.status == "OPEN"
    assert reopened.closed_at is None

    # Verify timeline event
    evt_types = [e.event_type for e in reopened.timeline_events]
    assert "INCIDENT_REOPENED" in evt_types


def test_false_positive_and_duplicate_handling(db_session):
    """Test transitions to FALSE_POSITIVE and DUPLICATE require mandatory justification."""
    canonical = IncidentService.create_incident(
        db_session, IncidentCreateRequest(title="Canonical Case"), workspace_id="ws-alpha"
    )
    dup = IncidentService.create_incident(
        db_session, IncidentCreateRequest(title="Duplicate Case"), workspace_id="ws-alpha"
    )

    # Transition to DUPLICATE without duplicate_of_id fails
    with pytest.raises(Exception):
        IncidentService.transition_status(
            db_session, dup.id, IncidentStatusChangeRequest(status="DUPLICATE"), workspace_id="ws-alpha"
        )

    # Succeeds with duplicate_of_id
    dup = IncidentService.transition_status(
        db_session,
        dup.id,
        IncidentStatusChangeRequest(status="DUPLICATE", duplicate_of_id=canonical.id),
        workspace_id="ws-alpha",
    )
    assert dup.status == "DUPLICATE"
    assert dup.duplicate_of_id == canonical.id
    assert dup.resolution_reason == "DUPLICATE"


def test_incident_assignment_and_notes(db_session):
    """Test analyst assignment and notes logging."""
    inc = IncidentService.create_incident(
        db_session, IncidentCreateRequest(title="Note & Assign Test"), workspace_id="ws-alpha"
    )

    assigned = IncidentService.assign_incident(
        db_session,
        inc.id,
        IncidentAssignRequest(assigned_to="Sarah Connor", reason="Escalated to Tier 2"),
        workspace_id="ws-alpha",
    )
    assert assigned.assigned_to == "Sarah Connor"

    note = IncidentService.add_note(
        db_session,
        inc.id,
        IncidentNoteCreateRequest(note_text="Host isolated from network successfully at 14:32 UTC."),
        workspace_id="ws-alpha",
        actor="Sarah Connor",
    )
    assert note.note_text.startswith("Host isolated")
    assert note.author == "Sarah Connor"

    detail = IncidentService.get_incident_detail(db_session, inc.id, workspace_id="ws-alpha")
    assert len(detail.notes) == 1
    assert detail.notes[0].author == "Sarah Connor"


def test_cross_tenant_isolation(db_session):
    """Enforce that Workspace A cannot view or mutate Workspace B incidents."""
    inc_a = IncidentService.create_incident(
        db_session, IncidentCreateRequest(title="Tenant A Incident"), workspace_id="ws-tenant-a"
    )

    # Tenant B tries to fetch Tenant A incident
    with pytest.raises(Exception) as exc_info:
        IncidentService.get_incident_detail(db_session, inc_a.id, workspace_id="ws-tenant-b")
    assert "not found" in str(exc_info.value).lower()

    # Tenant B tries to mutate Tenant A incident
    with pytest.raises(Exception) as exc_info:
        IncidentService.transition_status(
            db_session,
            inc_a.id,
            IncidentStatusChangeRequest(status="INVESTIGATING"),
            workspace_id="ws-tenant-b",
        )
    assert "not found" in str(exc_info.value).lower()


# =============================================================================
# REST API Integration Tests
# =============================================================================

def test_rest_api_incident_flow(client):
    """Test full HTTP REST workflow for Incident Management."""
    # 1. Create Incident
    create_res = client.post(
        "/api/incidents",
        headers={"x-workspace-id": "test-ws", "x-analyst-name": "TestAnalyst"},
        json={
            "title": "REST API Incident",
            "description": "Created via automated test suite",
            "severity": "HIGH",
            "category": "PHISHING",
        },
    )
    assert create_res.status_code == 201
    inc_data = create_res.json()
    inc_id = inc_data["id"]
    assert inc_data["incident_number"].startswith("INC-")

    # 2. List Incidents
    list_res = client.get(
        "/api/incidents",
        headers={"x-workspace-id": "test-ws"},
        params={"severity": "HIGH"},
    )
    assert list_res.status_code == 200
    assert list_res.json()["total"] >= 1

    # 3. Get Detail
    detail_res = client.get(
        f"/api/incidents/{inc_id}",
        headers={"x-workspace-id": "test-ws"},
    )
    assert detail_res.status_code == 200
    detail = detail_res.json()
    assert detail["title"] == "REST API Incident"
    assert detail["next_best_action"] is not None

    # 4. Assign Incident
    assign_res = client.post(
        f"/api/incidents/{inc_id}/assign",
        headers={"x-workspace-id": "test-ws"},
        json={"assigned_to": "Tier2 Analyst"},
    )
    assert assign_res.status_code == 200
    assert assign_res.json()["assigned_to"] == "Tier2 Analyst"

    # 5. Add Note
    note_res = client.post(
        f"/api/incidents/{inc_id}/notes",
        headers={"x-workspace-id": "test-ws"},
        json={"note_text": "Reviewing SPF/DKIM verification records."},
    )
    assert note_res.status_code == 201
    assert "SPF/DKIM" in note_res.json()["note_text"]

    # 6. Resolve Incident
    resolve_res = client.post(
        f"/api/incidents/{inc_id}/resolve",
        headers={"x-workspace-id": "test-ws"},
        json={"resolution_reason": "THREAT_REMEDIATED"},
    )
    assert resolve_res.status_code == 200
    assert resolve_res.json()["status"] == "RESOLVED"

    # 7. Get Metrics
    metrics_res = client.get(
        "/api/incidents/metrics",
        headers={"x-workspace-id": "test-ws"},
    )
    assert metrics_res.status_code == 200
    metrics = metrics_res.json()
    assert metrics["total_incidents"] >= 1
    assert metrics["resolved_incidents"] >= 1
