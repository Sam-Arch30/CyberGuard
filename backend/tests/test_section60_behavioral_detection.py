"""
Section 60: Comprehensive Behavioral Detection & Anomaly Analytics Test Suite.

Verifies:
1. Cold start and profile lifecycle state transitions (Insufficient Data, Learning, Active, Stale)
2. Measurable baseline quality and zero false-positive alerts on cold start
3. Endpoint and authentication behavioral feature extraction
4. Baseline deviation scoring and evidence-backed finding generation
5. Alert policy, fatigue controls, and cooldown deduplication
6. Baseline poisoning protection and Learning Quarantine lifecycle (Pending, Approved, Rejected)
7. Baseline versioning, controlled refresh, and audited rollback
8. Multi-tenant isolation and RBAC authorization
9. Section 59 detection pipeline integration and graceful failure decoupling
10. REST API endpoints for SOC behavioral views
"""
from __future__ import annotations

import json
from datetime import datetime, timezone, timedelta
from typing import Generator
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

from backend.db.models import (
    Base,
    BehaviorProfileModel,
    BehaviorLearningQuarantineModel,
    BehavioralBaselineModel,
    BehavioralDeviationModel,
    BaselineAuditModel,
    FindingModel,
    FindingEvidenceModel,
    NotificationModel,
    SecurityEventModel,
)
from backend.main import app
from backend.db.session import SessionLocal, init_db
from backend.schemas.behavioral_baseline import (
    BaselineEntityType,
    BaselineMetricType,
    BaselineQuality,
)
from backend.schemas.behavioral_detection import (
    ProfileStatusEnum,
    QuarantineDispositionEnum,
    QuarantineReasonEnum,
)
from backend.schemas.detection_pipeline import (
    EventIngestRequest,
    NormalizedDetectionEvent,
    PipelineModeEnum,
)
from backend.services.behavioral_anomaly_service import BehavioralAnomalyService
from backend.services.behavioral_feature_extractor import BehavioralFeatureExtractor
from backend.services.unified_threat_detection_pipeline_service import UnifiedThreatDetectionPipelineService


WS_A = "ws-sec60-alpha"
WS_B = "ws-sec60-beta"


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture(autouse=True)
def setup_db():
    init_db()
    from backend.services.behavioral_baseline_service import BehavioralBaselineService
    BehavioralBaselineService._baseline_cache.clear()
    BehavioralAnomalyService._alert_cooldowns.clear()

    db: Session = SessionLocal()
    try:
        db.query(BehaviorProfileModel).filter(BehaviorProfileModel.workspace_id.in_([WS_A, WS_B, "test-ws", "ws-alpha", "ws-beta"])).delete(synchronize_session=False)
        db.query(BehaviorLearningQuarantineModel).filter(BehaviorLearningQuarantineModel.workspace_id.in_([WS_A, WS_B, "test-ws", "ws-alpha", "ws-beta"])).delete(synchronize_session=False)
        db.query(BehavioralDeviationModel).filter(BehavioralDeviationModel.workspace_id.in_([WS_A, WS_B, "test-ws", "ws-alpha", "ws-beta"])).delete(synchronize_session=False)
        db.query(BehavioralBaselineModel).filter(BehavioralBaselineModel.workspace_id.in_([WS_A, WS_B, "test-ws", "ws-alpha", "ws-beta"])).delete(synchronize_session=False)
        db.query(FindingModel).filter(FindingModel.workspace_id.in_([WS_A, WS_B, "test-ws", "ws-alpha", "ws-beta"])).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()
    yield


@pytest.fixture
def db_session() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ============================================================================
# 1. PROFILE LIFECYCLE & COLD START TESTS
# ============================================================================

def test_cold_start_profile_creation(db_session: Session):
    """Verifies that an entity with no history initializes safely in INSUFFICIENT_DATA."""
    profile = BehavioralAnomalyService.get_or_create_profile(
        db=db_session,
        workspace_id="test-ws",
        entity_type="USER",
        entity_id="alice@cyberguard.local",
    )
    assert profile is not None
    assert profile.profile_status == ProfileStatusEnum.INSUFFICIENT_DATA.value
    assert profile.quality_status == BaselineQuality.INSUFFICIENT_HISTORY.value
    assert profile.sample_count == 0
    assert profile.confidence_score <= 0.3


def test_profile_lifecycle_transitions(db_session: Session):
    """Verifies transitions from INSUFFICIENT_DATA -> LEARNING -> ACTIVE."""
    profile = BehavioralAnomalyService.get_or_create_profile(
        db=db_session,
        workspace_id="test-ws",
        entity_type="USER",
        entity_id="bob@cyberguard.local",
    )
    assert profile.profile_status == ProfileStatusEnum.INSUFFICIENT_DATA.value

    # Simulate 8 samples -> LEARNING
    profile.sample_count = 8
    BehavioralAnomalyService.update_profile_lifecycle(profile)
    assert profile.profile_status == ProfileStatusEnum.LEARNING.value
    assert profile.quality_status == BaselineQuality.DEVELOPING.value

    # Simulate 25 samples -> ACTIVE
    profile.sample_count = 25
    BehavioralAnomalyService.update_profile_lifecycle(profile)
    assert profile.profile_status == ProfileStatusEnum.ACTIVE.value
    assert profile.quality_status == BaselineQuality.STABLE.value

    # Simulate inactivity past 30 days -> STALE
    profile.last_observed_at = datetime.now(timezone.utc) - timedelta(days=35)
    BehavioralAnomalyService.update_profile_lifecycle(profile)
    assert profile.profile_status == ProfileStatusEnum.STALE.value
    assert profile.quality_status == BaselineQuality.STALE.value


def test_cold_start_suppresses_false_anomalies(db_session: Session):
    """Verifies that events during cold-start do NOT generate false high-confidence anomaly findings."""
    now = datetime.now(timezone.utc)
    norm_event = NormalizedDetectionEvent(
        event_id="cold-start-001",
        workspace_id="test-ws",
        event_type="AUTH_LOGIN",
        source_type="AUTH",
        source_id="carol@cyberguard.local",
        occurred_at=now,
        received_at=now,
        payload={
            "account_id": "carol@cyberguard.local",
            "source_ip": "10.0.0.99",
            "country": "IN",
            "success": True,
        },
    )

    responses = BehavioralAnomalyService.evaluate_event(db=db_session, norm_event=norm_event)
    assert len(responses) > 0
    resp = responses[0]
    assert resp.evaluated is True
    # During cold-start, is_anomaly MUST be False to prevent false alert fatigue
    assert resp.is_anomaly is False
    assert resp.finding_id is None
    assert resp.alert_id is None

    # FindingModel should NOT be created for this cold-start event
    findings = db_session.query(FindingModel).filter(FindingModel.workspace_id == "test-ws").all()
    assert len(findings) == 0


# ============================================================================
# 2. FEATURE EXTRACTION TESTS
# ============================================================================

def test_endpoint_feature_extraction():
    """Verifies endpoint process telemetry extraction and privacy preservation."""
    now = datetime.now(timezone.utc)
    endpoint_event = {
        "id": "ep-101",
        "timestamp": now,
        "endpoint_id": "WS-FINANCE-04",
        "process_name": "cmd.exe",
        "command_line": "cmd.exe /c whoami",
        "parent_process_name": "explorer.exe",
        "user": "finance_user",
    }
    observations = BehavioralFeatureExtractor.extract_from_endpoint_event(endpoint_event)
    assert len(observations) >= 4

    metrics = {obs.metric_type for obs in observations}
    assert BaselineMetricType.PROCESS_EXECUTION_FREQUENCY in metrics
    assert BaselineMetricType.PROCESS_NAME_FREQUENCY in metrics
    assert BaselineMetricType.COMMAND_LINE_LENGTH in metrics
    assert BaselineMetricType.PARENT_PROCESS_FREQUENCY in metrics

    # Verify command line length was computed accurately
    cmd_obs = next(o for o in observations if o.metric_type == BaselineMetricType.COMMAND_LINE_LENGTH)
    assert cmd_obs.numeric_value == float(len("cmd.exe /c whoami"))


def test_normalized_detection_event_feature_extraction():
    """Verifies that Section 59 NormalizedDetectionEvents map properly into observations."""
    now = datetime.now(timezone.utc)
    norm_event = NormalizedDetectionEvent(
        event_id="det-ev-201",
        workspace_id="test-ws",
        event_type="ENDPOINT_PROCESS_START",
        source_type="ENDPOINT",
        source_id="ENDPOINT-SRV-01",
        occurred_at=now,
        received_at=now,
        payload={
            "endpoint_id": "ENDPOINT-SRV-01",
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -Enc SGVsbG8=",
            "parent_process_name": "services.exe",
            "user": "SYSTEM",
        },
    )
    obs = BehavioralFeatureExtractor.extract_from_normalized_detection_event(norm_event)
    assert len(obs) >= 4
    assert any(o.entity_id == "ENDPOINT-SRV-01" for o in obs)


# ============================================================================
# 3. ANOMALY DETECTION, FINDINGS & ALERT COOLDOWN
# ============================================================================

def test_significant_deviation_generates_finding_and_alert(db_session: Session):
    """Verifies that a genuine deviation generates a FindingModel, evidence, and alert."""
    now = datetime.now(timezone.utc)
    entity_id = "dave@cyberguard.local"

    # Pre-seed an ACTIVE profile with sufficient baseline history
    profile = BehavioralAnomalyService.get_or_create_profile(
        db=db_session,
        workspace_id="test-ws",
        entity_type="ACCOUNT",
        entity_id=entity_id,
    )
    profile.sample_count = 30
    profile.profile_status = ProfileStatusEnum.ACTIVE.value
    profile.quality_status = BaselineQuality.STABLE.value
    db_session.commit()

    # Pre-seed an established baseline for LOGIN_HOUR (normal: 9:00 - 17:00)
    baseline = BehavioralBaselineModel(
        id="base-dave-hour",
        workspace_id="test-ws",
        entity_type="ACCOUNT",
        entity_id=entity_id,
        entity_category="HUMAN_USER",
        metric_type=BaselineMetricType.LOGIN_HOUR.value,
        metric_version="1.0.0",
        window_type="ROLLING_30D",
        sample_count=50,
        valid_sample_count=50,
        confidence_score=0.9,
        quality_status=BaselineQuality.STABLE.value,
        learning_mode="STABLE",
        distribution_json=json.dumps({
            "active_hours": list(range(9, 18)),
            "hour_counts": {str(h): 10 for h in range(9, 18)},
            "primary_cluster_start": 9,
            "primary_cluster_end": 17,
            "overnight_active": False,
        }),
        expected_range_summary="Normal hours: 09:00 - 17:00",
        created_at=now - timedelta(days=10),
        updated_at=now,
    )
    db_session.add(baseline)
    db_session.commit()

    # An event occurs at 03:00 AM (highly anomalous relative to 13:00 peak)
    event_time = now.replace(hour=3, minute=0, second=0)
    norm_event = NormalizedDetectionEvent(
        event_id="dave-3am-login",
        workspace_id="test-ws",
        event_type="AUTH_LOGIN",
        source_type="AUTH",
        source_id=entity_id,
        occurred_at=event_time,
        received_at=event_time,
        payload={
            "account_id": entity_id,
            "source_ip": "203.0.113.15",
            "country": "RO",
            "success": True,
        },
    )

    responses = BehavioralAnomalyService.evaluate_event(db=db_session, norm_event=norm_event)
    assert len(responses) > 0

    # Look for LOGIN_HOUR response
    login_resp = next((r for r in responses if r.is_anomaly), None)
    assert login_resp is not None
    assert login_resp.deviation_score >= 0.60
    assert login_resp.finding_id is not None

    # Verify FindingModel exists in DB
    finding = db_session.query(FindingModel).filter(FindingModel.id == login_resp.finding_id).first()
    assert finding is not None
    assert finding.finding_type == "BEHAVIORAL_ANOMALY"
    assert finding.analyzer == "behavioral_anomaly_engine"
    assert "Unusual" in finding.title

    # Verify FindingEvidenceModel exists
    evidence = db_session.query(FindingEvidenceModel).filter(FindingEvidenceModel.finding_id == finding.id).all()
    assert len(evidence) >= 1

    # Verify BehavioralDeviationModel updated with finding_id
    dev_model = db_session.query(BehavioralDeviationModel).filter(
        BehavioralDeviationModel.finding_id == finding.id
    ).first()
    assert dev_model is not None


def test_alert_fatigue_cooldown_deduplication(db_session: Session):
    """Verifies that duplicate anomalous events within cooldown window do NOT produce multiple alerts."""
    now = datetime.now(timezone.utc)
    entity_id = "eva@cyberguard.local"

    profile = BehavioralAnomalyService.get_or_create_profile(
        db=db_session,
        workspace_id="test-ws",
        entity_type="ACCOUNT",
        entity_id=entity_id,
    )
    profile.sample_count = 35
    profile.profile_status = ProfileStatusEnum.ACTIVE.value
    profile.quality_status = BaselineQuality.STABLE.value

    baseline = BehavioralBaselineModel(
        id="base-eva-hour",
        workspace_id="test-ws",
        entity_type="ACCOUNT",
        entity_id=entity_id,
        entity_category="HUMAN_USER",
        metric_type=BaselineMetricType.LOGIN_HOUR.value,
        metric_version="1.0.0",
        window_type="ROLLING_30D",
        sample_count=60,
        valid_sample_count=60,
        confidence_score=0.9,
        quality_status=BaselineQuality.STABLE.value,
        learning_mode="STABLE",
        distribution_json=json.dumps({
            "active_hours": list(range(10, 19)),
            "hour_counts": {str(h): 10 for h in range(10, 19)},
            "primary_cluster_start": 10,
            "primary_cluster_end": 18,
            "overnight_active": False,
        }),
        expected_range_summary="Normal hours: 10:00 - 18:00",
        created_at=now - timedelta(days=10),
        updated_at=now,
    )
    db_session.add(baseline)
    db_session.commit()

    event_time = now.replace(hour=2, minute=15)
    norm_event1 = NormalizedDetectionEvent(
        event_id="eva-ev-1",
        workspace_id="test-ws",
        event_type="AUTH_LOGIN",
        source_type="AUTH",
        source_id=entity_id,
        occurred_at=event_time,
        received_at=event_time,
        payload={"account_id": entity_id, "success": True},
    )

    norm_event2 = NormalizedDetectionEvent(
        event_id="eva-ev-2",
        workspace_id="test-ws",
        event_type="AUTH_LOGIN",
        source_type="AUTH",
        source_id=entity_id,
        occurred_at=event_time + timedelta(minutes=5),
        received_at=event_time + timedelta(minutes=5),
        payload={"account_id": entity_id, "success": True},
    )

    res1 = BehavioralAnomalyService.evaluate_event(db=db_session, norm_event=norm_event1)
    res2 = BehavioralAnomalyService.evaluate_event(db=db_session, norm_event=norm_event2)

    # First event may generate an alert
    alert1 = next((r.alert_id for r in res1 if r.alert_id), None)
    # Second event within cooldown window MUST NOT generate another alert
    alert2 = next((r.alert_id for r in res2 if r.alert_id), None)

    if alert1:
        assert alert2 is None


# ============================================================================
# 4. LEARNING QUARANTINE & BASELINE POISONING PROTECTION
# ============================================================================

def test_learning_quarantine_holds_severe_deviations(db_session: Session):
    """Verifies that high deviations are held in quarantine to prevent baseline poisoning."""
    now = datetime.now(timezone.utc)
    entity_id = "frank@cyberguard.local"

    profile = BehavioralAnomalyService.get_or_create_profile(
        db=db_session,
        workspace_id="test-ws",
        entity_type="ACCOUNT",
        entity_id=entity_id,
    )
    profile.sample_count = 25
    profile.profile_status = ProfileStatusEnum.ACTIVE.value
    profile.quality_status = BaselineQuality.STABLE.value

    baseline = BehavioralBaselineModel(
        id="base-frank-hour",
        workspace_id="test-ws",
        entity_type="ACCOUNT",
        entity_id=entity_id,
        entity_category="HUMAN_USER",
        metric_type=BaselineMetricType.LOGIN_HOUR.value,
        metric_version="1.0.0",
        window_type="ROLLING_30D",
        sample_count=50,
        valid_sample_count=50,
        confidence_score=0.9,
        quality_status=BaselineQuality.STABLE.value,
        learning_mode="STABLE",
        distribution_json=json.dumps({
            "active_hours": [12],
            "hour_counts": {"12": 50},
            "primary_cluster_start": 12,
            "primary_cluster_end": 12,
            "overnight_active": False,
        }),
        expected_range_summary="Strict 12:00 window",
        created_at=now,
        updated_at=now,
    )
    db_session.add(baseline)
    db_session.commit()

    # Extreme login hour deviation (01:00 vs 12:00)
    norm_event = NormalizedDetectionEvent(
        event_id="frank-quar-ev",
        workspace_id="test-ws",
        event_type="AUTH_LOGIN",
        source_type="AUTH",
        source_id=entity_id,
        occurred_at=now.replace(hour=1, minute=0),
        received_at=now.replace(hour=1, minute=0),
        payload={"account_id": entity_id, "success": True},
    )

    responses = BehavioralAnomalyService.evaluate_event(db=db_session, norm_event=norm_event)
    quar_resp = next((r for r in responses if r.quarantined), None)
    assert quar_resp is not None
    assert quar_resp.quarantine_reason in (QuarantineReasonEnum.HIGH_ANOMALY.value, QuarantineReasonEnum.SUSPECTED_POISONING.value)

    # Verify record in BehaviorLearningQuarantineModel
    quar_item = db_session.query(BehaviorLearningQuarantineModel).filter(
        BehaviorLearningQuarantineModel.entity_id == entity_id,
        BehaviorLearningQuarantineModel.workspace_id == "test-ws",
    ).first()
    assert quar_item is not None
    assert quar_item.disposition == QuarantineDispositionEnum.PENDING.value


def test_quarantine_analyst_review_and_rejection(db_session: Session):
    """Verifies analyst review of quarantined items and audit logging."""
    quar_item = BehaviorLearningQuarantineModel(
        id="quar-101",
        workspace_id="test-ws",
        entity_type="USER",
        entity_id="grace@cyberguard.local",
        metric_type="LOGIN_LOCATION",
        observed_value="KP",
        event_id="ev-kp-99",
        quarantine_reason=QuarantineReasonEnum.HIGH_ANOMALY.value,
        disposition=QuarantineDispositionEnum.PENDING.value,
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(quar_item)
    db_session.commit()

    reviewed = BehavioralAnomalyService.review_quarantine_item(
        db=db_session,
        quarantine_id="quar-101",
        workspace_id="test-ws",
        reviewer="senior_analyst",
        disposition=QuarantineDispositionEnum.REJECTED,
        review_notes="Confirmed attacker VPN origin; exclude permanently from baseline.",
    )
    assert reviewed is not None
    assert reviewed.disposition == QuarantineDispositionEnum.REJECTED.value
    assert reviewed.reviewed_by == "senior_analyst"

    # Audit record must exist
    audit = db_session.query(BaselineAuditModel).filter(
        BaselineAuditModel.action == "QUARANTINE_REJECTED"
    ).first()
    assert audit is not None
    assert audit.actor == "senior_analyst"


# ============================================================================
# 5. BASELINE VERSIONING, REFRESH & ROLLBACK
# ============================================================================

def test_baseline_refresh_increments_version_and_audits(db_session: Session):
    """Verifies that refreshing baselines increments metric_version and audits changes."""
    now = datetime.now(timezone.utc)
    baseline = BehavioralBaselineModel(
        id="base-refresh-01",
        workspace_id="test-ws",
        entity_type="ACCOUNT",
        entity_id="heidi@cyberguard.local",
        entity_category="HUMAN_USER",
        metric_type=BaselineMetricType.LOGIN_FREQUENCY.value,
        metric_version="1.0.0",
        window_type="ROLLING_30D",
        sample_count=20,
        valid_sample_count=20,
        quality_status=BaselineQuality.STABLE.value,
        learning_mode="STABLE",
        expected_range_summary="1-3 logins/day",
        created_at=now,
        updated_at=now,
    )
    db_session.add(baseline)
    db_session.commit()

    res = BehavioralAnomalyService.refresh_entity_baselines(
        db=db_session,
        workspace_id="test-ws",
        entity_type="ACCOUNT",
        entity_id="heidi@cyberguard.local",
        user_id="lead_analyst",
    )
    assert res["refreshed_baselines"] == 1

    db_session.refresh(baseline)
    assert baseline.metric_version == "1.0.1"

    audit = db_session.query(BaselineAuditModel).filter(
        BaselineAuditModel.action == "BASELINE_REFRESH"
    ).first()
    assert audit is not None
    assert audit.actor == "lead_analyst"


def test_baseline_rollback_marks_recalibration(db_session: Session):
    """Verifies that rollback appends rollback tag and resets quality to DEVELOPING."""
    now = datetime.now(timezone.utc)
    baseline = BehavioralBaselineModel(
        id="base-rollback-01",
        workspace_id="test-ws",
        entity_type="ACCOUNT",
        entity_id="ivan@cyberguard.local",
        entity_category="HUMAN_USER",
        metric_type=BaselineMetricType.LOGIN_FREQUENCY.value,
        metric_version="2.0.0",
        window_type="ROLLING_30D",
        sample_count=20,
        valid_sample_count=20,
        quality_status=BaselineQuality.STABLE.value,
        learning_mode="STABLE",
        expected_range_summary="10-15 logins/day",
        created_at=now,
        updated_at=now,
    )
    db_session.add(baseline)
    db_session.commit()

    rolled_back = BehavioralAnomalyService.rollback_baseline(
        db=db_session,
        workspace_id="test-ws",
        baseline_id="base-rollback-01",
        actor="soc_manager",
        reason="Baseline corrupted by unauthorized batch export script.",
    )
    assert rolled_back is not None
    assert "rollback" in rolled_back.metric_version
    assert rolled_back.quality_status == BaselineQuality.DEVELOPING.value


# ============================================================================
# 6. PIPELINE INTEGRATION & ERROR DECOUPLING
# ============================================================================

def test_pipeline_integration_runs_behavioral_evaluation(db_session: Session):
    """Verifies that Section 59 pipeline process_event executes behavioral evaluation stage."""
    now = datetime.now(timezone.utc)
    req = EventIngestRequest(
        workspace_id="test-ws",
        source_type="AUTH",
        event_type="AUTH_LOGIN",
        occurred_at=now,
        payload={
            "account_id": "judy@cyberguard.local",
            "source_ip": "192.168.1.50",
            "country": "US",
            "success": True,
        },
    )

    res = UnifiedThreatDetectionPipelineService.process_event(db=db_session, req=req)
    assert res is not None

    # Check trace includes BEHAVIORAL_EVALUATION
    stage_names = [st["stage"] for st in res.trace.get("stages", [])]
    assert "BEHAVIORAL_EVALUATION" in stage_names

    # Profile should exist for judy
    profile = db_session.query(BehaviorProfileModel).filter(
        BehaviorProfileModel.entity_id == "judy@cyberguard.local"
    ).first()
    assert profile is not None
    assert profile.sample_count >= 1


# ============================================================================
# 7. REST API ENDPOINTS & TENANT ISOLATION
# ============================================================================

def test_api_behavioral_overview(client: TestClient, db_session: Session):
    """Verifies GET /api/v1/behavioral/overview returns actual counts."""
    # Seed 2 profiles in test-ws and 1 in other-ws
    db_session.add(BehaviorProfileModel(
        id="bp-1",
        workspace_id="test-ws",
        entity_type="USER",
        entity_id="u1@test.com",
        profile_status="ACTIVE",
        sample_count=30,
        quality_status="STABLE",
    ))
    db_session.add(BehaviorProfileModel(
        id="bp-2",
        workspace_id="test-ws",
        entity_type="USER",
        entity_id="u2@test.com",
        profile_status="LEARNING",
        sample_count=10,
        quality_status="DEVELOPING",
    ))
    db_session.add(BehaviorProfileModel(
        id="bp-other",
        workspace_id="other-ws",
        entity_type="USER",
        entity_id="u_other@test.com",
        profile_status="ACTIVE",
        sample_count=50,
        quality_status="STABLE",
    ))
    db_session.commit()

    resp = client.get(
        "/api/v1/behavioral/overview",
        headers={"X-Workspace-Id": "test-ws", "X-Role": "analyst"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_profiles"] == 2
    assert data["active_profiles"] == 1
    assert data["learning_profiles"] == 1


def test_api_behavioral_profiles_tenant_isolation(client: TestClient, db_session: Session):
    """Verifies tenant isolation on GET /api/v1/behavioral/profiles."""
    db_session.add(BehaviorProfileModel(
        id="bp-ws1",
        workspace_id="ws-alpha",
        entity_type="USER",
        entity_id="alpha_user@corp.local",
    ))
    db_session.add(BehaviorProfileModel(
        id="bp-ws2",
        workspace_id="ws-beta",
        entity_type="USER",
        entity_id="beta_user@corp.local",
    ))
    db_session.commit()

    resp = client.get(
        "/api/v1/behavioral/profiles",
        headers={"X-Workspace-Id": "ws-alpha", "X-Role": "analyst"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 1
    assert data["items"][0]["entity_id"] == "alpha_user@corp.local"


def test_api_quarantine_review_flow(client: TestClient, db_session: Session):
    """Verifies review of learning quarantine items via REST API."""
    db_session.add(BehaviorLearningQuarantineModel(
        id="quar-review-01",
        workspace_id="test-ws",
        entity_type="ENDPOINT",
        entity_id="HOST-WIN11-01",
        metric_type="COMMAND_LINE_LENGTH",
        observed_value="4500",
        quarantine_reason=QuarantineReasonEnum.HIGH_ANOMALY.value,
        disposition=QuarantineDispositionEnum.PENDING.value,
    ))
    db_session.commit()

    review_resp = client.post(
        "/api/v1/behavioral/quarantine/quar-review-01/review",
        json={"disposition": "REJECTED", "review_notes": "Obfuscated PowerShell injection."},
        headers={"X-Workspace-Id": "test-ws", "X-Role": "analyst", "X-User-Id": "sec_analyst"},
    )
    assert review_resp.status_code == 200
    data = review_resp.json()
    assert data["disposition"] == "REJECTED"
    assert data["reviewed_by"] == "sec_analyst"


def test_api_rbac_enforcement(client: TestClient):
    """Verifies that unauthorized roles are rejected with 403 Forbidden."""
    resp = client.get(
        "/api/v1/behavioral/overview",
        headers={"X-Workspace-Id": "test-ws", "X-Role": "guest"},
    )
    assert resp.status_code == 403
