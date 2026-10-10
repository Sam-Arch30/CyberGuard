"""
Section 49: Comprehensive Unit, Integration, Concurrency, and Tenant Isolation
Tests for Alert Correlation & Incident Clustering Subsystem.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone, timedelta
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient

from backend.db.models import (
    Base,
    NotificationModel,
    AlertClusterModel,
    AlertClusterMemberModel,
    IncidentModel,
    CampaignModel,
    AuditLogModel,
    get_utc_now,
)
from backend.schemas.notification import NotificationCategoryEnum
from backend.schemas.alert_clusters import ClusterStatusEnum, CorrelationSignalTypeEnum
from backend.services.alert_correlation_service import (
    AlertCorrelationService,
    CORRELATION_THRESHOLD,
    COMMON_INFRASTRUCTURE_DOMAINS,
)
from sqlalchemy.pool import StaticPool
from backend.main import app


@pytest.fixture
def db_session():
    """In-memory SQLite session with StaticPool for cross-thread consistency."""
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
def test_client(db_session):
    """Provides FastAPI test client overriding database dependency."""
    from backend.db.session import get_db

    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()


# ===========================================================================
# 1. Feature Extraction & Comparison Tests
# ===========================================================================

def test_extract_alert_features(db_session):
    """Verifies parsing of emails, domains, URLs, IPs, and hashes from alert metadata."""
    now = get_utc_now()
    alert = NotificationModel(
        id=str(uuid.uuid4()),
        workspace_id="ws-sec49",
        category=NotificationCategoryEnum.SECURITY_ALERT.value,
        notification_type="CREDENTIAL_PHISHING",
        severity="HIGH",
        status="OPEN",
        title="Suspicious Login Page",
        message="User victim@enterprise.com targeted with malicious link",
        created_at=now,
        metadata_json=json.dumps({
            "sender": "attacker@evil-login.com",
            "recipient": "victim@enterprise.com",
            "url": "https://evil-login.com/auth/login.php",
            "domain": "evil-login.com",
            "ip": "198.51.100.24",
            "sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            "endpoint_id": "ep-workstation-88",
            "campaign_id": "camp-stealth-bear",
        }),
    )
    db_session.add(alert)
    db_session.commit()

    feat = AlertCorrelationService.extract_alert_features(db_session, alert)
    assert feat["user_id"] == "victim@enterprise.com"
    assert feat["sender"] == "attacker@evil-login.com"
    assert "evil-login.com" in feat["domains"]
    assert "https://evil-login.com/auth/login.php" in feat["urls"]
    assert "198.51.100.24" in feat["ips"]
    assert "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890" in feat["hashes"]
    assert feat["endpoint_id"] == "ep-workstation-88"
    assert feat["campaign_id"] == "camp-stealth-bear"


def test_hard_signal_hash_correlation():
    """Identical attachment hash must yield strong correlation above threshold."""
    now = get_utc_now()
    feat_a = {
        "id": "alert-1",
        "created_at": now,
        "user_id": "alice@corp.com",
        "sender": None,
        "domains": set(),
        "ips": set(),
        "urls": set(),
        "hashes": {"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
        "endpoint_id": None,
        "analysis_run_id": None,
        "campaign_id": None,
        "investigation_id": None,
    }
    feat_b = {
        "id": "alert-2",
        "created_at": now + timedelta(minutes=15),
        "user_id": "bob@corp.com",
        "sender": None,
        "domains": set(),
        "ips": set(),
        "urls": set(),
        "hashes": {"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
        "endpoint_id": None,
        "analysis_run_id": None,
        "campaign_id": None,
        "investigation_id": None,
    }

    signals, score = AlertCorrelationService.compare_alert_features(feat_a, feat_b)
    assert score >= CORRELATION_THRESHOLD
    signal_types = [s.type for s in signals]
    assert CorrelationSignalTypeEnum.SAME_ATTACHMENT_HASH.value in signal_types


def test_soft_signals_combined_correlation():
    """Same user + same domain + close temporal proximity must yield high confidence."""
    now = get_utc_now()
    feat_a = {
        "id": "alert-1",
        "created_at": now,
        "user_id": "ceo@victim.com",
        "sender": None,
        "domains": {"credential-stealer.org"},
        "ips": set(),
        "urls": set(),
        "hashes": set(),
        "endpoint_id": None,
        "analysis_run_id": None,
        "campaign_id": None,
        "investigation_id": None,
    }
    feat_b = {
        "id": "alert-2",
        "created_at": now + timedelta(minutes=5),
        "user_id": "ceo@victim.com",
        "sender": None,
        "domains": {"credential-stealer.org"},
        "ips": set(),
        "urls": set(),
        "hashes": set(),
        "endpoint_id": None,
        "analysis_run_id": None,
        "campaign_id": None,
        "investigation_id": None,
    }

    signals, score = AlertCorrelationService.compare_alert_features(feat_a, feat_b)
    assert score >= CORRELATION_THRESHOLD
    signal_types = [s.type for s in signals]
    assert CorrelationSignalTypeEnum.SAME_USER.value in signal_types
    assert CorrelationSignalTypeEnum.SAME_DOMAIN.value in signal_types
    assert CorrelationSignalTypeEnum.TEMPORAL_PROXIMITY.value in signal_types


def test_overmerge_protection_common_infrastructure():
    """Common cloud domain (google.com) alone must NOT correlate different users."""
    now = get_utc_now()
    feat_a = {
        "id": "alert-1",
        "created_at": now,
        "user_id": "user1@corp.com",
        "sender": None,
        "domains": {"google.com"},
        "ips": set(),
        "urls": set(),
        "hashes": set(),
        "endpoint_id": None,
        "analysis_run_id": None,
        "campaign_id": None,
        "investigation_id": None,
    }
    feat_b = {
        "id": "alert-2",
        "created_at": now + timedelta(hours=20),
        "user_id": "user2@corp.com",
        "sender": None,
        "domains": {"google.com"},
        "ips": set(),
        "urls": set(),
        "hashes": set(),
        "endpoint_id": None,
        "analysis_run_id": None,
        "campaign_id": None,
        "investigation_id": None,
    }

    signals, score = AlertCorrelationService.compare_alert_features(feat_a, feat_b)
    # Common domains must be excluded from domain correlation
    assert score < CORRELATION_THRESHOLD
    signal_types = [s.type for s in signals]
    assert CorrelationSignalTypeEnum.SAME_DOMAIN.value not in signal_types


# ===========================================================================
# 2. End-to-End Correlation & Clustering Service Tests
# ===========================================================================

def test_correlate_alert_creates_cluster(db_session):
    """When a second related alert arrives, an AlertCluster is created containing both."""
    now = get_utc_now()
    ws = "ws-sec49-test"

    # Alert 1: Phishing email targeting admin@domain.com with payload domain evil.cc
    alert1 = NotificationModel(
        id=str(uuid.uuid4()),
        workspace_id=ws,
        category=NotificationCategoryEnum.SECURITY_ALERT.value,
        notification_type="EMAIL_PHISHING",
        severity="HIGH",
        status="OPEN",
        title="Suspicious inbound email",
        message="Phishing attempt detected with link evil.cc",
        created_at=now,
        metadata_json=json.dumps({
            "recipient": "admin@domain.com",
            "domain": "evil.cc",
            "risk_score": 75,
        }),
    )
    db_session.add(alert1)
    db_session.commit()

    # Correlate alert1 -> single alert has no candidates yet -> stays unclustered
    cluster1 = AlertCorrelationService.correlate_alert(
        db=db_session,
        alert_id=alert1.id,
        workspace_id=ws,
        triggered_by="test",
    )
    assert cluster1 is None

    # Alert 2: 10 minutes later, endpoint connection from same user to evil.cc
    alert2 = NotificationModel(
        id=str(uuid.uuid4()),
        workspace_id=ws,
        category=NotificationCategoryEnum.SECURITY_ALERT.value,
        notification_type="C2_CALLBACK",
        severity="CRITICAL",
        status="OPEN",
        title="Endpoint contacted malicious domain",
        message="Endpoint ep-01 connected to evil.cc",
        created_at=now + timedelta(minutes=10),
        metadata_json=json.dumps({
            "user": "admin@domain.com",
            "domain": "evil.cc",
            "endpoint_id": "ep-01",
            "risk_score": 90,
        }),
    )
    db_session.add(alert2)
    db_session.commit()

    # Correlate alert2 -> finds alert1 -> creates cluster!
    cluster2 = AlertCorrelationService.correlate_alert(
        db=db_session,
        alert_id=alert2.id,
        workspace_id=ws,
        triggered_by="test",
    )
    assert cluster2 is not None
    assert cluster2.alert_count == 2
    assert cluster2.severity == "CRITICAL"  # Highest severity preserved
    assert cluster2.risk_score >= 80.0
    assert cluster2.confidence >= CORRELATION_THRESHOLD

    # Verify database members
    members = (
        db_session.query(AlertClusterMemberModel)
        .filter(AlertClusterMemberModel.cluster_id == cluster2.id)
        .all()
    )
    assert len(members) == 2
    member_alert_ids = {m.alert_id for m in members}
    assert alert1.id in member_alert_ids
    assert alert2.id in member_alert_ids


def test_third_alert_joins_existing_cluster(db_session):
    """A third related alert attaches to the already created cluster rather than creating a new one."""
    now = get_utc_now()
    ws = "ws-sec49-test"

    alert1 = NotificationModel(
        id=str(uuid.uuid4()),
        workspace_id=ws,
        category=NotificationCategoryEnum.SECURITY_ALERT.value,
        notification_type="SUSPICIOUS_URL",
        severity="HIGH",
        status="OPEN",
        title="Malicious URL analyzed",
        message="Target domain: payload.net",
        created_at=now,
        metadata_json=json.dumps({"domain": "payload.net", "user": "staff@corp.com"}),
    )
    alert2 = NotificationModel(
        id=str(uuid.uuid4()),
        workspace_id=ws,
        category=NotificationCategoryEnum.SECURITY_ALERT.value,
        notification_type="ENDPOINT_MALWARE",
        severity="HIGH",
        status="OPEN",
        title="Endpoint alert",
        message="Endpoint ep-02 accessed payload.net",
        created_at=now + timedelta(minutes=5),
        metadata_json=json.dumps({"domain": "payload.net", "user": "staff@corp.com"}),
    )
    db_session.add_all([alert1, alert2])
    db_session.commit()

    # Correlate alert2 -> creates cluster
    cluster = AlertCorrelationService.correlate_alert(db=db_session, alert_id=alert2.id, workspace_id=ws)
    assert cluster is not None
    assert cluster.alert_count == 2
    initial_cluster_id = cluster.id

    # Alert 3 arrives 15 minutes later with same domain
    alert3 = NotificationModel(
        id=str(uuid.uuid4()),
        workspace_id=ws,
        category=NotificationCategoryEnum.SECURITY_ALERT.value,
        notification_type="DATA_EXFILTRATION",
        severity="CRITICAL",
        status="OPEN",
        title="Exfiltration attempt to payload.net",
        message="Outbound transfer to payload.net",
        created_at=now + timedelta(minutes=20),
        metadata_json=json.dumps({"domain": "payload.net", "user": "staff@corp.com"}),
    )
    db_session.add(alert3)
    db_session.commit()

    # Correlate alert3
    cluster_after_3 = AlertCorrelationService.correlate_alert(db=db_session, alert_id=alert3.id, workspace_id=ws)
    assert cluster_after_3 is not None
    assert cluster_after_3.id == initial_cluster_id  # Attached to existing cluster!
    assert cluster_after_3.alert_count == 3
    assert cluster_after_3.severity == "CRITICAL"


def test_cluster_merging(db_session):
    """Merging source cluster into target cluster preserves provenance and updates status."""
    now = get_utc_now()
    ws = "ws-sec49-merge"

    # Create Cluster A with 2 alerts
    clu_a = AlertClusterModel(
        id=str(uuid.uuid4()),
        workspace_id=ws,
        title="Cluster A: Phishing Campaign",
        summary="Phishing targeting sales team",
        status=ClusterStatusEnum.OPEN.value,
        severity="HIGH",
        risk_score=70.0,
        confidence=0.85,
        first_seen=now,
        last_seen=now + timedelta(minutes=10),
        alert_count=2,
        correlation_version="v1.0",
        created_at=now,
        updated_at=now,
    )
    # Create Cluster B with 1 alert
    clu_b = AlertClusterModel(
        id=str(uuid.uuid4()),
        workspace_id=ws,
        title="Cluster B: Endpoint Ransomware",
        summary="Endpoint ransomware execution",
        status=ClusterStatusEnum.OPEN.value,
        severity="CRITICAL",
        risk_score=95.0,
        confidence=0.90,
        first_seen=now + timedelta(minutes=15),
        last_seen=now + timedelta(minutes=25),
        alert_count=1,
        correlation_version="v1.0",
        created_at=now,
        updated_at=now,
    )
    db_session.add_all([clu_a, clu_b])
    db_session.commit()

    # Create alerts and memberships
    a1 = NotificationModel(id=str(uuid.uuid4()), workspace_id=ws, category=NotificationCategoryEnum.SECURITY_ALERT.value, notification_type="PHISH", severity="HIGH", status="OPEN", title="A1", message="A1", created_at=now)
    a2 = NotificationModel(id=str(uuid.uuid4()), workspace_id=ws, category=NotificationCategoryEnum.SECURITY_ALERT.value, notification_type="PHISH", severity="HIGH", status="OPEN", title="A2", message="A2", created_at=now)
    b1 = NotificationModel(id=str(uuid.uuid4()), workspace_id=ws, category=NotificationCategoryEnum.SECURITY_ALERT.value, notification_type="RANSOM", severity="CRITICAL", status="OPEN", title="B1", message="B1", created_at=now)
    db_session.add_all([a1, a2, b1])
    db_session.commit()

    m_a1 = AlertClusterMemberModel(id=str(uuid.uuid4()), cluster_id=clu_a.id, alert_id=a1.id, membership_confidence=0.85, correlation_version="v1.0", created_at=now)
    m_a2 = AlertClusterMemberModel(id=str(uuid.uuid4()), cluster_id=clu_a.id, alert_id=a2.id, membership_confidence=0.85, correlation_version="v1.0", created_at=now)
    m_b1 = AlertClusterMemberModel(id=str(uuid.uuid4()), cluster_id=clu_b.id, alert_id=b1.id, membership_confidence=0.90, correlation_version="v1.0", created_at=now)
    db_session.add_all([m_a1, m_a2, m_b1])
    db_session.commit()

    # Merge Cluster B into Cluster A
    merged = AlertCorrelationService.merge_clusters(
        db=db_session,
        source_cluster_id=clu_b.id,
        target_cluster_id=clu_a.id,
        workspace_id=ws,
        analyst_name="Lead Analyst",
        reason="Established same threat actor behind email and ransomware",
    )
    assert merged is not None
    assert merged.id == clu_a.id
    assert merged.alert_count == 3
    assert merged.severity == "CRITICAL"  # Elevated by B1

    # Verify Cluster B state
    db_session.refresh(clu_b)
    assert clu_b.status == ClusterStatusEnum.MERGED.value
    assert clu_b.merged_into_cluster_id == clu_a.id

    # Verify all members now point to Cluster A
    all_members = db_session.query(AlertClusterMemberModel).filter(AlertClusterMemberModel.cluster_id == clu_a.id).all()
    assert len(all_members) == 3


def test_investigation_linking(db_session):
    """Linking cluster to an investigation creates/links Incident and cascades to member alerts."""
    now = get_utc_now()
    ws = "ws-sec49-inv"

    alert = NotificationModel(
        id=str(uuid.uuid4()),
        workspace_id=ws,
        category=NotificationCategoryEnum.SECURITY_ALERT.value,
        notification_type="SUSPICIOUS_LOGIN",
        severity="HIGH",
        status="OPEN",
        title="Login Anomaly",
        message="Suspicious login from unusual location",
        created_at=now,
    )
    cluster = AlertClusterModel(
        id=str(uuid.uuid4()),
        workspace_id=ws,
        title="Identity Compromise Cluster",
        summary="Suspicious logins detected",
        status=ClusterStatusEnum.OPEN.value,
        severity="HIGH",
        risk_score=75.0,
        confidence=0.8,
        first_seen=now,
        last_seen=now,
        alert_count=1,
        correlation_version="v1.0",
        created_at=now,
        updated_at=now,
    )
    member = AlertClusterMemberModel(
        id=str(uuid.uuid4()),
        cluster_id=cluster.id,
        alert_id=alert.id,
        membership_confidence=0.8,
        correlation_version="v1.0",
        created_at=now,
    )
    db_session.add_all([alert, cluster, member])
    db_session.commit()

    # Link to a new investigation
    updated_cluster = AlertCorrelationService.link_investigation(
        db=db_session,
        cluster_id=cluster.id,
        workspace_id=ws,
        create_if_missing=True,
        analyst_name="Tier-2 Analyst",
        investigation_title="Sec49 Identity Breach Investigation",
    )
    assert updated_cluster is not None
    assert updated_cluster.investigation_id is not None

    # Verify IncidentModel was created
    incident = db_session.query(IncidentModel).filter(IncidentModel.id == updated_cluster.investigation_id).first()
    assert incident is not None
    assert incident.workspace_id == ws

    # Verify member alert received investigation link
    db_session.refresh(alert)
    assert alert.investigation_id == updated_cluster.investigation_id


# ===========================================================================
# 3. Tenant Isolation Tests
# ===========================================================================

def test_tenant_isolation_prevents_cross_workspace_correlation(db_session):
    """Alerts from Tenant A must NEVER correlate with alerts from Tenant B."""
    now = get_utc_now()

    # Tenant A alert
    alert_tenant_a = NotificationModel(
        id=str(uuid.uuid4()),
        workspace_id="tenant-alpha",
        category=NotificationCategoryEnum.SECURITY_ALERT.value,
        notification_type="PHISHING",
        severity="HIGH",
        status="OPEN",
        title="Phishing against Tenant A",
        message="Target domain: shared-malware.org",
        created_at=now,
        metadata_json=json.dumps({"domain": "shared-malware.org", "user": "user@alpha.com"}),
    )
    # Tenant B alert with EXACT SAME malware domain and payload
    alert_tenant_b = NotificationModel(
        id=str(uuid.uuid4()),
        workspace_id="tenant-bravo",
        category=NotificationCategoryEnum.SECURITY_ALERT.value,
        notification_type="PHISHING",
        severity="HIGH",
        status="OPEN",
        title="Phishing against Tenant B",
        message="Target domain: shared-malware.org",
        created_at=now + timedelta(minutes=5),
        metadata_json=json.dumps({"domain": "shared-malware.org", "user": "user@bravo.com"}),
    )
    db_session.add_all([alert_tenant_a, alert_tenant_b])
    db_session.commit()

    # Correlate tenant B alert in tenant B scope
    cluster_b = AlertCorrelationService.correlate_alert(
        db=db_session,
        alert_id=alert_tenant_b.id,
        workspace_id="tenant-bravo",
    )
    # Tenant B has only 1 alert in its workspace -> must NOT correlate with Tenant A!
    assert cluster_b is None

    # Verify Tenant A alert has no cluster
    clu_a_detail = AlertCorrelationService.get_alert_cluster(
        db=db_session,
        alert_id=alert_tenant_a.id,
        workspace_id="tenant-alpha",
    )
    assert clu_a_detail is None


def test_cross_tenant_cluster_access_denied(test_client, db_session):
    """Querying a cluster from a different workspace returns 404."""
    now = get_utc_now()
    cluster = AlertClusterModel(
        id=str(uuid.uuid4()),
        workspace_id="tenant-private",
        title="Confidential Cluster",
        summary="Classified details",
        status=ClusterStatusEnum.OPEN.value,
        severity="HIGH",
        risk_score=80.0,
        confidence=0.8,
        first_seen=now,
        last_seen=now,
        alert_count=1,
        correlation_version="v1.0",
        created_at=now,
        updated_at=now,
    )
    db_session.add(cluster)
    db_session.commit()

    # Attempt access using different workspace header
    resp = test_client.get(
        f"/api/alerts/clusters/{cluster.id}",
        headers={"X-Workspace-ID": "tenant-intruder"},
    )
    assert resp.status_code == 404


# ===========================================================================
# 4. REST API Endpoint Tests
# ===========================================================================

def test_api_list_clusters(test_client, db_session):
    """Verifies GET /api/alerts/clusters returns paginated clusters."""
    now = get_utc_now()
    ws = "ws-api-test"

    clu = AlertClusterModel(
        id=str(uuid.uuid4()),
        workspace_id=ws,
        title="API Test Cluster",
        summary="Test cluster summary",
        status=ClusterStatusEnum.OPEN.value,
        severity="CRITICAL",
        risk_score=92.0,
        confidence=0.88,
        first_seen=now,
        last_seen=now,
        alert_count=3,
        correlation_version="v1.0",
        created_at=now,
        updated_at=now,
    )
    db_session.add(clu)
    db_session.commit()

    resp = test_client.get("/api/alerts/clusters", headers={"X-Workspace-ID": ws})
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 1
    assert data["items"][0]["title"] == "API Test Cluster"
    assert data["items"][0]["severity"] == "CRITICAL"


def test_api_get_cluster_detail_with_members(test_client, db_session):
    """Verifies GET /api/alerts/clusters/{id} returns full detail with members and timeline."""
    now = get_utc_now()
    ws = "ws-api-detail"

    alert = NotificationModel(
        id=str(uuid.uuid4()),
        workspace_id=ws,
        category=NotificationCategoryEnum.SECURITY_ALERT.value,
        notification_type="MALICIOUS_ATTACHMENT",
        severity="HIGH",
        status="OPEN",
        title="Malware EML Attached",
        message="Attachment payload.exe detected",
        created_at=now,
        metadata_json=json.dumps({"sha256": "aabbcc112233", "user": "target@corp.com"}),
    )
    clu = AlertClusterModel(
        id=str(uuid.uuid4()),
        workspace_id=ws,
        title="Malware Attachment Incident",
        summary="Multiple delivery attempts",
        status=ClusterStatusEnum.OPEN.value,
        severity="HIGH",
        risk_score=85.0,
        confidence=0.9,
        first_seen=now,
        last_seen=now,
        alert_count=1,
        correlation_version="v1.0",
        created_at=now,
        updated_at=now,
    )
    mem = AlertClusterMemberModel(
        id=str(uuid.uuid4()),
        cluster_id=clu.id,
        alert_id=alert.id,
        membership_confidence=0.9,
        correlation_reasons_json=json.dumps([{"type": "same_attachment_hash", "strength": 0.95}]),
        correlation_version="v1.0",
        created_at=now,
    )
    db_session.add_all([alert, clu, mem])
    db_session.commit()

    resp = test_client.get(f"/api/alerts/clusters/{clu.id}", headers={"X-Workspace-ID": ws})
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == clu.id
    assert len(data["members"]) == 1
    assert data["members"][0]["alert_id"] == alert.id
    assert len(data["members"][0]["signals"]) >= 1
    assert "target@corp.com" in data["affected_entities"]["users"]


def test_api_update_cluster_status_and_audit(test_client, db_session):
    """Verifies updating status persists and generates an AuditLog entry."""
    now = get_utc_now()
    ws = "ws-status-audit"

    clu = AlertClusterModel(
        id=str(uuid.uuid4()),
        workspace_id=ws,
        title="Status Update Cluster",
        summary="Initial state",
        status=ClusterStatusEnum.OPEN.value,
        severity="MEDIUM",
        risk_score=55.0,
        confidence=0.7,
        first_seen=now,
        last_seen=now,
        alert_count=1,
        correlation_version="v1.0",
        created_at=now,
        updated_at=now,
    )
    db_session.add(clu)
    db_session.commit()

    resp = test_client.post(
        f"/api/alerts/clusters/{clu.id}/status",
        headers={"X-Workspace-ID": ws, "X-User": "Analyst-Carol"},
        json={"status": "INVESTIGATING", "reason": "Active threat hunt underway"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "INVESTIGATING"

    # Verify AuditLogModel entry
    audit_entry = (
        db_session.query(AuditLogModel)
        .filter(
            AuditLogModel.action == "ALERT_CLUSTER_STATUS_CHANGED",
            AuditLogModel.resource_id == clu.id,
        )
        .first()
    )
    assert audit_entry is not None
    assert audit_entry.user == "Analyst-Carol"
