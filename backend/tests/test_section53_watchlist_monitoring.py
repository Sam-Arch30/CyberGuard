"""
Section 53: Comprehensive Test Suite for IOC Watchlists & Continuous Threat Monitoring.
Tests:
- Watchlist lifecycle (create, update, pause/resume, delete)
- Indicator normalization, membership, and duplicate prevention
- Deterministic snapshot fingerprinting and material change detection
- Newly malicious and newly suspicious change transitions
- Alert creation via Section 48 NotificationModel and cooldown suppression
- Continuous monitoring cycle execution and run logging
- Quick-watch workflow integration from incidents/investigations
- Multi-tenant isolation boundaries
- REST API endpoints
"""
import pytest
from datetime import datetime, timedelta, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient

from backend.main import app
from backend.db.session import get_db
from backend.db.models import (
    Base,
    WatchlistModel,
    WatchedIndicatorModel,
    IntelligenceSnapshotModel,
    IntelligenceChangeModel,
    WatchlistMonitoringRunModel,
    NotificationModel,
    ThreatIntelligenceRecordModel,
    get_utc_now,
)
from backend.schemas.watchlists import (
    WatchlistCreateRequest,
    WatchlistUpdateRequest,
    WatchedIndicatorCreateRequest,
    WatchedIndicatorBulkAddRequest,
    QuickWatchRequest,
    WatchlistPriorityEnum,
    WatchlistStatusEnum,
    AlertThresholdEnum,
)
from backend.services.watchlist_monitoring_service import WatchlistMonitoringService

# In-memory SQLite with StaticPool for test isolation
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
# 1. Watchlist Lifecycle Tests
# =============================================================================

def test_watchlist_creation_and_defaults(db_session):
    """Verifies that a watchlist is created with expected defaults and next check time."""
    req = WatchlistCreateRequest(
        name="Critical Infrastructure Watchlist",
        description="Tracks key C2 servers and payment endpoints",
        priority=WatchlistPriorityEnum.CRITICAL,
        check_interval_minutes=15,
        alert_threshold=AlertThresholdEnum.HIGH,
    )
    wl = WatchlistMonitoringService.create_watchlist(db_session, "ws-test", req, actor="analyst_alice")

    assert wl.id is not None
    assert wl.name == "Critical Infrastructure Watchlist"
    assert wl.status == WatchlistStatusEnum.ACTIVE.value
    assert wl.priority == "CRITICAL"
    assert wl.check_interval_minutes == 15
    assert wl.alert_threshold == "HIGH"
    assert wl.next_monitoring_cycle_at is not None
    assert wl.created_by == "analyst_alice"


def test_watchlist_update_and_pause_resume(db_session):
    """Verifies watchlist configuration updates and pause/resume child propagation."""
    req = WatchlistCreateRequest(name="Operations Feed", check_interval_minutes=60)
    wl = WatchlistMonitoringService.create_watchlist(db_session, "ws-test", req)

    # Add an indicator
    ind_req = WatchedIndicatorCreateRequest(indicator_value="198.51.100.55", indicator_type="IP")
    item = WatchlistMonitoringService.add_indicator(db_session, "ws-test", wl.id, ind_req)
    assert item.monitoring_status == "ACTIVE"

    # Pause watchlist
    upd_pause = WatchlistUpdateRequest(status=WatchlistStatusEnum.PAUSED)
    wl_paused = WatchlistMonitoringService.update_watchlist(db_session, "ws-test", wl.id, upd_pause)
    assert wl_paused.status == "PAUSED"

    db_session.refresh(item)
    assert item.monitoring_status == "PAUSED"

    # Resume watchlist
    upd_resume = WatchlistUpdateRequest(status=WatchlistStatusEnum.ACTIVE)
    wl_active = WatchlistMonitoringService.update_watchlist(db_session, "ws-test", wl.id, upd_resume)
    assert wl_active.status == "ACTIVE"

    db_session.refresh(item)
    assert item.monitoring_status == "ACTIVE"


def test_watchlist_deletion_cascades(db_session):
    """Verifies that deleting a watchlist cascades to watched indicators and changes."""
    wl = WatchlistMonitoringService.create_watchlist(
        db_session, "ws-test", WatchlistCreateRequest(name="Temporary Watchlist")
    )
    item = WatchlistMonitoringService.add_indicator(
        db_session, "ws-test", wl.id, WatchedIndicatorCreateRequest(indicator_value="test-phish.com", indicator_type="DOMAIN")
    )
    item_id = item.id

    success = WatchlistMonitoringService.delete_watchlist(db_session, "ws-test", wl.id)
    assert success is True

    # Check child item is cascade deleted
    deleted_item = db_session.query(WatchedIndicatorModel).filter(WatchedIndicatorModel.id == item_id).first()
    assert deleted_item is None


# =============================================================================
# 2. Indicator Normalization & Membership Tests
# =============================================================================

def test_add_indicator_normalization_and_idempotency(db_session):
    """Verifies canonical normalization and duplicate prevention within the same watchlist."""
    wl = WatchlistMonitoringService.create_watchlist(
        db_session, "ws-test", WatchlistCreateRequest(name="Normalizer Test")
    )

    # Add unnormalized domain
    item1 = WatchlistMonitoringService.add_indicator(
        db_session, "ws-test", wl.id, WatchedIndicatorCreateRequest(indicator_value="EXAMPLE.COM.", indicator_type="DOMAIN")
    )
    assert item1.normalized_value == "example.com"
    assert item1.indicator_type == "DOMAIN"

    # Add duplicate domain in different casing
    item2 = WatchlistMonitoringService.add_indicator(
        db_session, "ws-test", wl.id, WatchedIndicatorCreateRequest(indicator_value="example.com", indicator_type="DOMAIN")
    )
    assert item1.id == item2.id  # Reused same record, no duplicate created


def test_bulk_add_indicators(db_session):
    """Verifies bulk observable ingestion into a watchlist."""
    wl = WatchlistMonitoringService.create_watchlist(
        db_session, "ws-test", WatchlistCreateRequest(name="Bulk Ingestion Test")
    )

    bulk_req = WatchedIndicatorBulkAddRequest(
        indicators=[
            WatchedIndicatorCreateRequest(indicator_value="198.51.100.1", indicator_type="IP"),
            WatchedIndicatorCreateRequest(indicator_value="198.51.100.2", indicator_type="IP"),
            WatchedIndicatorCreateRequest(indicator_value="malware.xyz", indicator_type="DOMAIN"),
        ],
        default_priority=WatchlistPriorityEnum.HIGH,
    )

    items = WatchlistMonitoringService.bulk_add_indicators(db_session, "ws-test", wl.id, bulk_req)
    assert len(items) == 3

    total_count = db_session.query(WatchedIndicatorModel).filter(WatchedIndicatorModel.watchlist_id == wl.id).count()
    assert total_count == 3


# =============================================================================
# 3. Deterministic Fingerprinting & Change Detection Tests
# =============================================================================

def test_snapshot_fingerprint_deterministic_stability():
    """Verifies fingerprint ignores micro-jitter and key order while capturing material shifts."""
    fp1 = WatchlistMonitoringService.compute_snapshot_fingerprint(
        verdict="MALICIOUS",
        severity="HIGH",
        confidence=0.852,
        threat_types=["Phishing", "Botnet"],
        has_conflicts=False,
        material_attributes={"asn": 15169, "country": "US"},
    )
    # Same data with different dict key order and minute confidence float rounding
    fp2 = WatchlistMonitoringService.compute_snapshot_fingerprint(
        verdict="MALICIOUS",
        severity="HIGH",
        confidence=0.854,  # Rounds to 0.85
        threat_types=["Botnet", "Phishing"],  # Reverse order
        has_conflicts=False,
        material_attributes={"country": "US", "asn": 15169},
    )
    assert fp1 == fp2

    # Different verdict produces different fingerprint
    fp3 = WatchlistMonitoringService.compute_snapshot_fingerprint(
        verdict="CLEAN",
        severity="NONE",
        confidence=0.85,
        threat_types=[],
        has_conflicts=False,
    )
    assert fp1 != fp3


def test_detect_material_change_newly_malicious():
    """Verifies UNKNOWN -> MALICIOUS produces NEWLY_MALICIOUS with CRITICAL severity."""
    prev_snap = IntelligenceSnapshotModel(
        id="snap-1",
        workspace_id="ws-test",
        watched_indicator_id="wi-1",
        indicator_type="DOMAIN",
        normalized_value="bad-login.com",
        provider_consensus_verdict="CLEAN",
        consensus_confidence=0.90,
        severity="NONE",
        sources_count=2,
        has_conflicts=False,
        threat_types_json="[]",
        normalized_data_json="{}",
        fingerprint="fp1",
    )

    change = WatchlistMonitoringService.detect_material_change(
        prev=prev_snap,
        curr_verdict="MALICIOUS",
        curr_confidence=0.95,
        curr_severity="CRITICAL",
        curr_threat_types=["Phishing", "Credential Harvesting"],
        curr_has_conflicts=False,
        curr_attrs={},
    )
    assert change is not None
    change_type, change_sev, summary, details = change
    assert change_type == "NEWLY_MALICIOUS"
    assert change_sev == "CRITICAL"
    assert "MALICIOUS" in summary


def test_detect_material_change_became_clean():
    """Verifies MALICIOUS -> CLEAN transition produces BECAME_CLEAN."""
    prev_snap = IntelligenceSnapshotModel(
        id="snap-2",
        workspace_id="ws-test",
        watched_indicator_id="wi-2",
        indicator_type="IP",
        normalized_value="198.51.100.99",
        provider_consensus_verdict="MALICIOUS",
        consensus_confidence=0.90,
        severity="HIGH",
        threat_types_json="[\"Botnet\"]",
        fingerprint="fp2",
    )

    change = WatchlistMonitoringService.detect_material_change(
        prev=prev_snap,
        curr_verdict="CLEAN",
        curr_confidence=0.80,
        curr_severity="NONE",
        curr_threat_types=[],
        curr_has_conflicts=False,
        curr_attrs={},
    )
    assert change is not None
    change_type, change_sev, summary, _ = change
    assert change_type == "BECAME_CLEAN"
    assert change_sev == "MEDIUM"


# =============================================================================
# 4. Alert Creation & Cooldown Tests
# =============================================================================

@pytest.mark.anyio
async def test_alert_created_on_material_change_and_cooldown_suppression(db_session):
    """
    Verifies that a material change creates a NotificationModel (SECURITY_ALERT),
    and that duplicate checks within cooldown window do not create duplicate alerts.
    """
    wl = WatchlistMonitoringService.create_watchlist(
        db_session,
        "ws-test",
        WatchlistCreateRequest(
            name="Alerting Test Watchlist",
            alert_threshold=AlertThresholdEnum.HIGH,
            cooldown_minutes=60,
        ),
    )

    item = WatchlistMonitoringService.add_indicator(
        db_session,
        "ws-test",
        wl.id,
        WatchedIndicatorCreateRequest(indicator_value="c2-attacker.com", indicator_type="DOMAIN"),
    )

    # 1. Initial baseline check (creates initial snapshot)
    await WatchlistMonitoringService.execute_single_indicator_check(db_session, item, force=True)
    db_session.refresh(item)
    # Simulate an external intelligence escalation to MALICIOUS in ThreatIntelligenceRecordModel
    now = get_utc_now()
    record = ThreatIntelligenceRecordModel(
        id="ti-mock-1",
        workspace_id="ws-test",
        indicator_type="DOMAIN",
        indicator_value="c2-attacker.com",
        normalized_value="c2-attacker.com",
        provider="cyberguard_feed",
        verdict="MALICIOUS",
        confidence=0.95,
        severity="HIGH",
        threat_types_json="[\"Command and Control\"]",
        retrieved_at=now,
        expires_at=now + timedelta(days=1),
    )
    db_session.add(record)
    db_session.commit()

    # 2. Second check detects material change (UNKNOWN -> MALICIOUS)
    change = await WatchlistMonitoringService.execute_single_indicator_check(db_session, item, force=False)
    db_session.refresh(item)

    assert change is not None
    assert change.change_type == "NEWLY_MALICIOUS"
    assert change.alert_id is not None  # Alert was created!

    # Verify NotificationModel alert was persisted
    alert_notif = db_session.query(NotificationModel).filter(NotificationModel.id == change.alert_id).first()
    assert alert_notif is not None
    assert alert_notif.category == "SECURITY_ALERT"
    assert "c2-attacker.com" in alert_notif.title

    # 3. Third check while still within cooldown window:
    # In regular scheduled monitoring (force=False), intelligence is unchanged from snapshot 2,
    # so fingerprint matches and no spurious change or alert is triggered:
    change2 = await WatchlistMonitoringService.execute_single_indicator_check(db_session, item, force=False)
    assert change2 is None

    # 4. Verify cooldown suppression logic directly:
    # Within the 60-minute cooldown window, duplicate alert creation for NEWLY_MALICIOUS is suppressed
    assert WatchlistMonitoringService._is_alert_in_cooldown(
        db_session, item, "NEWLY_MALICIOUS", wl.cooldown_minutes
    ) is True


# =============================================================================
# 5. Continuous Monitoring Cycle & Quick-Watch Integration
# =============================================================================

@pytest.mark.anyio
async def test_execute_monitoring_cycle_and_run_logging(db_session):
    """Verifies batch execution cycle, item status updates, and WatchlistMonitoringRunModel creation."""
    wl = WatchlistMonitoringService.create_watchlist(
        db_session,
        "ws-test",
        WatchlistCreateRequest(name="Scheduled Run Watchlist", check_interval_minutes=60),
    )

    WatchlistMonitoringService.add_indicator(
        db_session, "ws-test", wl.id, WatchedIndicatorCreateRequest(indicator_value="198.51.100.10", indicator_type="IP")
    )
    WatchlistMonitoringService.add_indicator(
        db_session, "ws-test", wl.id, WatchedIndicatorCreateRequest(indicator_value="example.org", indicator_type="DOMAIN")
    )

    # Execute cycle
    runs = await WatchlistMonitoringService.execute_monitoring_cycle(
        db=db_session,
        workspace_id="ws-test",
        watchlist_id=wl.id,
        trigger_type="SCHEDULED",
    )

    assert len(runs) == 1
    run = runs[0]
    assert run.items_due == 2
    assert run.items_checked == 2
    assert run.status == "SUCCEEDED"

    # Verify run logged in DB
    run_db = db_session.query(WatchlistMonitoringRunModel).filter(WatchlistMonitoringRunModel.id == run.id).first()
    assert run_db is not None
    assert run_db.duration_ms is not None


@pytest.mark.anyio
async def test_quick_watch_workflow_from_incident(db_session):
    """Verifies instant quick-watch action from an incident observable."""
    req = QuickWatchRequest(
        indicator_value="198.51.100.77",
        indicator_type="IP",
        source_incident_id="inc-uuid-999",
        source_investigation_id="inv-uuid-888",
        reason="Suspicious outbound beacon detected in Incident INC-999",
    )

    item = await WatchlistMonitoringService.quick_watch(db_session, "ws-test", req, actor="incident_analyst")
    assert item.normalized_value == "198.51.100.77"
    assert item.source_incident_id == "inc-uuid-999"
    assert item.source_investigation_id == "inv-uuid-888"
    assert item.last_checked_at is not None  # Immediately checked!


# =============================================================================
# 6. Multi-Tenant Isolation
# =============================================================================

def test_multi_tenant_isolation_watchlists(db_session):
    """Guarantees strict tenant isolation between workspace watchlists."""
    wl_tenant_a = WatchlistMonitoringService.create_watchlist(
        db_session, "tenant-a", WatchlistCreateRequest(name="Tenant A Secrets")
    )
    wl_tenant_b = WatchlistMonitoringService.create_watchlist(
        db_session, "tenant-b", WatchlistCreateRequest(name="Tenant B Secrets")
    )

    # Tenant A list query
    list_a = WatchlistMonitoringService.list_watchlists(db_session, "tenant-a")
    ids_a = [w.id for w in list_a.items]
    assert wl_tenant_a.id in ids_a
    assert wl_tenant_b.id not in ids_a

    # Cross-tenant get returns None
    detail_cross = WatchlistMonitoringService.get_watchlist(db_session, "tenant-a", wl_tenant_b.id)
    assert detail_cross is None


# =============================================================================
# 7. REST API Endpoints
# =============================================================================

def test_watchlists_rest_api_crud(client):
    """Verifies full REST API flow for watchlists and monitored indicators."""
    headers = {"X-Workspace-ID": "ws-api-test", "X-User-ID": "test_user"}

    # 1. Create Watchlist
    create_payload = {
        "name": "API Monitored Watchlist",
        "description": "Created via REST API",
        "priority": "HIGH",
        "check_interval_minutes": 60,
    }
    resp = client.post("/watchlists", json=create_payload, headers=headers)
    assert resp.status_code == 201
    wl_id = resp.json()["id"]

    # 2. Get Watchlist Detail
    resp = client.get(f"/watchlists/{wl_id}", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["name"] == "API Monitored Watchlist"

    # 3. Add Item to Watchlist
    item_payload = {
        "indicator_value": "198.51.100.200",
        "indicator_type": "IP",
    }
    resp = client.post(f"/watchlists/{wl_id}/items", json=item_payload, headers=headers)
    assert resp.status_code == 201
    item_id = resp.json()["id"]
    assert resp.json()["normalized_value"] == "198.51.100.200"

    # 4. List Items
    resp = client.get(f"/watchlists/{wl_id}/items", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["total"] == 1

    # 5. Health Endpoint
    resp = client.get(f"/watchlists/{wl_id}/health", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["watchlist_id"] == wl_id

    # 6. Delete Item
    resp = client.delete(f"/watchlists/{wl_id}/items/{item_id}", headers=headers)
    assert resp.status_code == 204

    # 7. Delete Watchlist
    resp = client.delete(f"/watchlists/{wl_id}", headers=headers)
    assert resp.status_code == 204
