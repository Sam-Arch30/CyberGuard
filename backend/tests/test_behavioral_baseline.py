"""
Unit and Integration Tests for Behavioral Baseline Engine (Section 21).
Covers baseline creation, robust statistics, circular hours, categorical novelty,
poisoning guards, frozen states, service accounts, exceptions, and synthetic scenarios.
"""
import pytest
from datetime import datetime, timezone, timedelta
import json
import uuid
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.db.session import Base
from backend.db.models import (
    BehavioralBaselineModel,
    BehavioralDeviationModel,
    BaselineAuditModel,
    SecurityEventModel,
    IncidentModel,
)
from backend.schemas.behavioral_baseline import (
    BaselineConfidenceLevel,
    BaselineEntityType,
    BaselineException,
    BaselineMetricType,
    BaselineQuality,
    DeviationDirection,
    EntityProfileCategory,
    LearningMode,
)
from backend.services.behavioral_statistics import BehavioralStatisticsEngine
from backend.services.behavioral_feature_extractor import BehavioralFeatureExtractor
from backend.services.baseline_poisoning_guard import BaselinePoisoningGuard
from backend.services.baseline_context_manager import BaselineContextManager
from backend.services.behavioral_baseline_service import BehavioralBaselineService


@pytest.fixture
def db_session():
    """In-memory SQLite session with all models created."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


def test_01_zero_events_produces_no_data(db_session):
    """Zero events should yield NO_DATA quality and zero confidence."""
    baseline = BehavioralBaselineService.build_baseline(
        session=db_session,
        entity_type=BaselineEntityType.USER,
        entity_id="unknown_user",
        metric_type=BaselineMetricType.LOGIN_HOUR,
    )
    assert baseline.sample_count == 0
    assert baseline.quality_status == BaselineQuality.NO_DATA
    assert baseline.confidence_score == 0.0


def test_02_insufficient_history_few_events(db_session):
    """Fewer than 5 events should be classified as INSUFFICIENT_HISTORY."""
    now = datetime.now(timezone.utc)
    for i in range(3):
        ev = SecurityEventModel(
            id=str(uuid.uuid4()),
            event_type="AUTH_SUCCESS",
            event_time=now - timedelta(days=i),
            source_type="AUTH",
            attributes_json=json.dumps({"account_id": "bob", "ip": "192.0.2.1"}),
        )
        db_session.add(ev)
    db_session.commit()

    baseline = BehavioralBaselineService.build_baseline(
        session=db_session,
        entity_type=BaselineEntityType.ACCOUNT,
        entity_id="bob",
        metric_type=BaselineMetricType.LOGIN_SOURCE_IP,
    )
    assert baseline.sample_count == 3
    assert baseline.quality_status == BaselineQuality.INSUFFICIENT_HISTORY
    assert baseline.confidence_score < 0.30


def test_03_stable_baseline_creation(db_session):
    """Sufficient events (>20) spanning multiple weeks should produce a STABLE baseline."""
    now = datetime.now(timezone.utc)
    for i in range(25):
        day_offset = i % 20
        hour_val = 9 + (i % 3)  # logins between 09:00 and 11:00
        ev_time = (now - timedelta(days=day_offset)).replace(hour=hour_val, minute=15)
        ev = SecurityEventModel(
            id=str(uuid.uuid4()),
            event_type="AUTH_SUCCESS",
            event_time=ev_time,
            source_type="AUTH",
            attributes_json=json.dumps({"account_id": "alice", "device_id": "macbook-pro-1", "ip": "198.51.100.10"}),
        )
        db_session.add(ev)
    db_session.commit()

    baseline = BehavioralBaselineService.build_baseline(
        session=db_session,
        entity_type=BaselineEntityType.ACCOUNT,
        entity_id="alice",
        metric_type=BaselineMetricType.LOGIN_HOUR,
    )
    assert baseline.sample_count == 25
    assert baseline.quality_status == BaselineQuality.STABLE
    assert baseline.confidence_score >= 0.80
    assert baseline.median_value is not None
    assert 9.0 <= baseline.median_value <= 11.5


def test_04_robust_statistics_numerical():
    """Verifies Median, MAD, and Percentiles calculation."""
    samples = [10.0, 11.0, 12.0, 10.5, 11.5, 10.2, 500.0]  # 500.0 is an outlier
    winsorized = BehavioralStatisticsEngine.winsorize(samples)
    med = BehavioralStatisticsEngine.calculate_median(winsorized)
    mad = BehavioralStatisticsEngine.calculate_mad(winsorized, median=med)
    perc = BehavioralStatisticsEngine.calculate_percentiles(winsorized)

    assert 10.0 <= med <= 12.0
    assert mad < 3.0
    assert perc.p50 == med


def test_05_circular_hour_distance():
    """Circular distance must handle wrap-around correctly across midnight."""
    # 23:00 to 01:00 is 2.0 hours apart, not 22.0
    d1 = BehavioralStatisticsEngine.circular_hour_distance(23.0, 1.0)
    assert abs(d1 - 2.0) < 1e-4

    # 14:00 to 18:00 is 4.0 hours apart
    d2 = BehavioralStatisticsEngine.circular_hour_distance(14.0, 18.0)
    assert abs(d2 - 4.0) < 1e-4

    # 02:00 to 02:30 is 0.5 hours apart
    d3 = BehavioralStatisticsEngine.circular_hour_distance(2.0, 2.5)
    assert abs(d3 - 0.5) < 1e-4


def test_06_categorical_novelty():
    """Categorical evaluation correctly distinguishes known vs rare vs unseen categories."""
    dist = {"laptop-01": 40, "phone-01": 10}
    total = 50

    # Known device
    score1, dir1, expl1 = BehavioralStatisticsEngine.evaluate_categorical_deviation("laptop-01", dist, total)
    assert score1 == 0.0

    # Unseen device
    score2, dir2, expl2 = BehavioralStatisticsEngine.evaluate_categorical_deviation("unknown-tablet", dist, total)
    assert score2 >= 0.60
    assert dir2 == DeviationDirection.NEW


def test_07_normal_behavior_within_baseline(db_session):
    """Event within established normal baseline yields no significant deviation."""
    now = datetime.now(timezone.utc)
    for i in range(20):
        ev = SecurityEventModel(
            id=str(uuid.uuid4()),
            event_type="AUTH_SUCCESS",
            event_time=(now - timedelta(days=i % 15)).replace(hour=10, minute=0),
            source_type="AUTH",
            attributes_json=json.dumps({"account_id": "alice", "ip": "203.0.113.5"}),
        )
        db_session.add(ev)
    db_session.commit()

    baseline = BehavioralBaselineService.build_baseline(
        session=db_session,
        entity_type=BaselineEntityType.ACCOUNT,
        entity_id="alice",
        metric_type=BaselineMetricType.LOGIN_HOUR,
    )

    # Alice logs in at 10:15 (normal work hour)
    dev = BehavioralBaselineService.evaluate_deviation(
        session=db_session,
        baseline=baseline,
        observed_value=10.25,
        event_time=now,
    )
    assert dev.deviation_score == 0.0


def test_08_unusual_login_time_detection(db_session):
    """Alice logging in at 03:17 vs normal 09:00-17:00 yields an anomalous deviation."""
    now = datetime.now(timezone.utc)
    for i in range(30):
        ev = SecurityEventModel(
            id=str(uuid.uuid4()),
            event_type="AUTH_SUCCESS",
            event_time=(now - timedelta(days=i % 25)).replace(hour=9 + (i % 8), minute=0),
            source_type="AUTH",
            attributes_json=json.dumps({"account_id": "alice", "ip": "203.0.113.5"}),
        )
        db_session.add(ev)
    db_session.commit()

    baseline = BehavioralBaselineService.build_baseline(
        session=db_session,
        entity_type=BaselineEntityType.ACCOUNT,
        entity_id="alice",
        metric_type=BaselineMetricType.LOGIN_HOUR,
    )

    # Alice logs in at 03:17 (3.28 float)
    dev = BehavioralBaselineService.evaluate_deviation(
        session=db_session,
        baseline=baseline,
        observed_value=3.28,
        event_time=now,
    )
    assert dev is not None
    assert dev.deviation_score >= 0.50
    assert "established historical schedule" in dev.explanation


def test_09_poisoning_protection(db_session):
    """Malicious and quarantined events must be excluded from baseline calculation."""
    now = datetime.now(timezone.utc)

    # 10 clean events
    for i in range(10):
        ev = SecurityEventModel(
            id=str(uuid.uuid4()),
            event_type="AUTH_SUCCESS",
            event_time=now - timedelta(days=i),
            source_type="AUTH",
            attributes_json=json.dumps({"account_id": "alice", "ip": "192.0.2.10"}),
        )
        db_session.add(ev)

    # 5 attacker events flagged as malicious
    for i in range(5):
        ev_bad = SecurityEventModel(
            id=str(uuid.uuid4()),
            event_type="AUTH_SUCCESS",
            event_time=now - timedelta(days=i),
            source_type="AUTH",
            attributes_json=json.dumps({"account_id": "alice", "ip": "198.51.100.99", "is_malicious": True}),
        )
        db_session.add(ev_bad)
    db_session.commit()

    baseline = BehavioralBaselineService.build_baseline(
        session=db_session,
        entity_type=BaselineEntityType.ACCOUNT,
        entity_id="alice",
        metric_type=BaselineMetricType.LOGIN_SOURCE_IP,
    )

    # Baseline should only include clean IP, not the attacker's IP
    assert "192.0.2.10" in baseline.categorical_distribution
    assert "198.51.100.99" not in baseline.categorical_distribution
    assert baseline.missing_sample_count == 5


def test_10_frozen_baseline_state(db_session):
    """Frozen baseline cannot be modified by background recalculation during an incident."""
    now = datetime.now(timezone.utc)
    for i in range(15):
        ev = SecurityEventModel(
            id=str(uuid.uuid4()),
            event_type="AUTH_SUCCESS",
            event_time=now - timedelta(days=i),
            source_type="AUTH",
            attributes_json=json.dumps({"account_id": "alice", "ip": "192.0.2.1"}),
        )
        db_session.add(ev)
    db_session.commit()

    baseline = BehavioralBaselineService.build_baseline(
        session=db_session,
        entity_type=BaselineEntityType.ACCOUNT,
        entity_id="alice",
        metric_type=BaselineMetricType.LOGIN_SOURCE_IP,
    )

    # Analyst freezes baseline during investigation
    frozen = BehavioralBaselineService.freeze_baseline(
        session=db_session,
        baseline_id=baseline.id,
        actor="secops_analyst_1",
        reason="Active incident investigation INC-401",
    )
    assert frozen.is_frozen is True
    assert frozen.learning_mode == LearningMode.FROZEN

    # Attempt rebuild - should preserve frozen baseline without update
    rebuilt = BehavioralBaselineService.build_baseline(
        session=db_session,
        entity_type=BaselineEntityType.ACCOUNT,
        entity_id="alice",
        metric_type=BaselineMetricType.LOGIN_SOURCE_IP,
    )
    assert rebuilt.is_frozen is True


def test_11_service_account_contextual_handling(db_session):
    """Service accounts operating 24/7 or overnight should not trigger human login time anomalies."""
    now = datetime.now(timezone.utc)
    for i in range(20):
        ev = SecurityEventModel(
            id=str(uuid.uuid4()),
            event_type="AUTH_SUCCESS",
            event_time=(now - timedelta(days=i % 10)).replace(hour=2, minute=0),
            source_type="AUTH",
            attributes_json=json.dumps({"account_id": "svc_backup_daemon", "ip": "10.0.1.5"}),
        )
        db_session.add(ev)
    db_session.commit()

    baseline = BehavioralBaselineService.build_baseline(
        session=db_session,
        entity_type=BaselineEntityType.ACCOUNT,
        entity_id="svc_backup_daemon",
        metric_type=BaselineMetricType.LOGIN_HOUR,
    )
    assert baseline.entity_category == EntityProfileCategory.SERVICE_ACCOUNT

    dev = BehavioralBaselineService.evaluate_deviation(
        session=db_session,
        baseline=baseline,
        observed_value=3.5,
        event_time=now,
    )
    # Score suppressed for service account
    assert dev.deviation_score == 0.0
    assert "Service account continuous execution" in dev.explanation


def test_12_contextual_exception_suppression(db_session):
    """Active authorized exceptions suppress behavioral alert."""
    now = datetime.now(timezone.utc)
    for i in range(15):
        ev = SecurityEventModel(
            id=str(uuid.uuid4()),
            event_type="AUTH_SUCCESS",
            event_time=(now - timedelta(days=i)).replace(hour=10, minute=0),
            source_type="AUTH",
            attributes_json=json.dumps({"account_id": "charlie", "ip": "203.0.113.1"}),
        )
        db_session.add(ev)
    db_session.commit()

    baseline = BehavioralBaselineService.build_baseline(
        session=db_session,
        entity_type=BaselineEntityType.ACCOUNT,
        entity_id="charlie",
        metric_type=BaselineMetricType.LOGIN_HOUR,
    )

    # Register an approved maintenance window exception
    exc = BaselineException(
        id=str(uuid.uuid4()),
        entity_type=BaselineEntityType.ACCOUNT,
        entity_id="charlie",
        metric_type=BaselineMetricType.LOGIN_HOUR,
        reason="Scheduled ERP migration",
        approved_by="IT Director",
        valid_from=now - timedelta(hours=2),
        valid_until=now + timedelta(hours=6),
    )
    BaselineContextManager.register_exception(exc)

    dev = BehavioralBaselineService.evaluate_deviation(
        session=db_session,
        baseline=baseline,
        observed_value=2.0,  # 02:00 AM
        event_time=now,
    )
    assert dev.deviation_score == 0.0
    assert "Deviation suppressed by active authorized exception" in dev.explanation


def test_13_synthetic_end_to_end_scenario(db_session):
    """
    Scenario: Alice has 30 days of standard 08:30-18:00 logins from corporate IP.
    An anomalous 03:17 login occurs from an external IP.
    Verifies that the engine produces objective behavioral deviations without
    prematurely declaring a confirmed account takeover verdict.
    """
    now = datetime.now(timezone.utc)
    # Build 30 days of baseline
    for d in range(30):
        ev = SecurityEventModel(
            id=str(uuid.uuid4()),
            event_type="AUTH_SUCCESS",
            event_time=(now - timedelta(days=d)).replace(hour=9, minute=15),
            source_type="AUTH",
            attributes_json=json.dumps({
                "account_id": "alice@corp.test",
                "ip": "198.51.100.25",
                "device_id": "corp-laptop-01",
                "country": "United States",
            }),
        )
        db_session.add(ev)
    db_session.commit()

    # Build baselines for hour and IP
    hour_baseline = BehavioralBaselineService.build_baseline(
        session=db_session,
        entity_type=BaselineEntityType.ACCOUNT,
        entity_id="alice@corp.test",
        metric_type=BaselineMetricType.LOGIN_HOUR,
    )
    ip_baseline = BehavioralBaselineService.build_baseline(
        session=db_session,
        entity_type=BaselineEntityType.ACCOUNT,
        entity_id="alice@corp.test",
        metric_type=BaselineMetricType.LOGIN_SOURCE_IP,
    )

    assert hour_baseline.quality_status == BaselineQuality.STABLE
    assert ip_baseline.quality_status == BaselineQuality.STABLE

    # Observed anomalous event: 03:17 from foreign IP
    incident = IncidentModel(id=str(uuid.uuid4()), incident_number="INC-S21-HERO", title="Synthetic Auth Investigation")
    db_session.add(incident)
    db_session.commit()

    hour_dev = BehavioralBaselineService.evaluate_deviation(
        session=db_session,
        baseline=hour_baseline,
        observed_value=3.28,
        incident_id=incident.id,
    )
    ip_dev = BehavioralBaselineService.evaluate_deviation(
        session=db_session,
        baseline=ip_baseline,
        observed_value="203.0.113.88",
        incident_id=incident.id,
    )

    assert hour_dev.deviation_score >= 0.50
    assert ip_dev.deviation_score >= 0.60
    assert ip_dev.deviation_direction == DeviationDirection.NEW

    # Non-verdict guarantee: deviation must describe objective statistical variance,
    # NOT claim "Account takeover confirmed" or "Hacker detected"
    for dev in (hour_dev, ip_dev):
        assert "hacker" not in dev.explanation.lower()
        assert "takeover confirmed" not in dev.explanation.lower()
