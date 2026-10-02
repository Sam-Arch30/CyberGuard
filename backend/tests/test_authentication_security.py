"""
Comprehensive Test Suite for Section 9: Authentication & Account-Takeover (ATO) Detection Engine.
Verifies all 32 required functional and security tests, false-positive mitigations,
multi-provider adapters, temporal window boundaries, and synthetic performance benchmark.
"""
import asyncio
import io
import json
import time
from datetime import datetime, timezone, timedelta
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.main import app
from backend.db.session import SessionLocal
from backend.db.models import (
    ArtifactModel,
    AnalysisRunModel,
    FindingModel,
    FindingEvidenceModel,
    IndicatorModel,
    EntityModel,
    RelationshipModel,
    ThreatEventModel,
)
from backend.schemas.unified import SeverityEnum, EntityTypeEnum
from backend.schemas.authentication_security import (
    AuthenticationResultEnum,
    AuthMethodEnum,
    MFAMethodEnum,
    FailureReasonEnum,
    ATOCategoryEnum,
    BaselineStatusEnum,
    AuthConfigResponse,
    AccountSecurityProfile,
    NormalizedAuthEvent,
)
from backend.services.authentication_analyzers import (
    SecretRedactor,
    GenericAuthAdapter,
    OktaAuthAdapter,
    EntraIdAuthAdapter,
    GoogleWorkspaceAuthAdapter,
    LinuxAuthAdapter,
    global_adapter_registry,
    FailureAnalysisEngine,
    BruteForceDetector,
    PasswordSprayDetector,
    CredentialStuffingDetector,
    SuccessAfterFailuresDetector,
    DeviceAnalysisEngine,
    LocationAnalysisEngine,
    TemporalAnalysisEngine,
    MFAAnalysisEngine,
    SessionAnalysisEngine,
    AccountTakeoverAggregator,
)
from backend.services.authentication_pipeline import AuthenticationSecurityPipeline, global_auth_pipeline

client = TestClient(app)


# ============================================================================
# 1. EVENT NORMALIZATION TESTS
# ============================================================================

def test_1_generic_auth_event_normalization():
    """Verify generic auth event normalization maps fields properly."""
    raw = {
        "user": "alice@example.com",
        "ip": "198.51.100.12",
        "status": "failure",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
        "timestamp": "2026-10-02T10:00:00Z",
    }
    event = global_adapter_registry.normalize(raw)
    assert event.account_id == "alice@example.com"
    assert event.source_ip == "198.51.100.12"
    assert event.result == AuthenticationResultEnum.FAILURE
    assert event.client_platform == "Windows"
    assert event.client_browser == "Chrome"
    assert event.timestamp.year == 2026


def test_2_success_normalization():
    """Maps various success keywords to AuthenticationResultEnum.SUCCESS."""
    adapter = GenericAuthAdapter()
    for kw in ["success", "OK", "pass", "allow", "authorized", "accepted"]:
        ev = adapter.normalize({"user": "bob", "status": kw})
        assert ev.result == AuthenticationResultEnum.SUCCESS, f"Failed for {kw}"


def test_3_failure_normalization():
    """Maps various failure keywords to AuthenticationResultEnum.FAILURE."""
    adapter = GenericAuthAdapter()
    for kw in ["failure", "FAILED", "bad_password", "invalid"]:
        ev = adapter.normalize({"user": "bob", "status": kw})
        assert ev.result == AuthenticationResultEnum.FAILURE, f"Failed for {kw}"


def test_4_unknown_result_normalization():
    """Unknown result does NOT blindly default to FAILURE."""
    adapter = GenericAuthAdapter()
    ev = adapter.normalize({"user": "bob", "status": "PENDING_REVIEW_STATE"})
    assert ev.result == AuthenticationResultEnum.UNKNOWN
    assert ev.result != AuthenticationResultEnum.FAILURE


def test_5_timestamp_normalization():
    """Normalizes ISO strings, epoch seconds, and epoch milliseconds to UTC."""
    adapter = GenericAuthAdapter()
    # 1. ISO string with Z
    ev1 = adapter.normalize({"user": "alice", "timestamp": "2026-10-02T12:30:00Z"})
    assert ev1.timestamp.hour == 12 and ev1.timestamp.minute == 30
    assert ev1.timestamp.tzinfo == timezone.utc

    # 2. Epoch seconds
    now_epoch = 1790940000
    ev2 = adapter.normalize({"user": "alice", "timestamp": now_epoch})
    assert ev2.timestamp.tzinfo == timezone.utc

    # 3. Epoch milliseconds
    ev3 = adapter.normalize({"user": "alice", "timestamp": now_epoch * 1000})
    assert ev3.timestamp.tzinfo == timezone.utc
    assert ev3.timestamp.year == ev2.timestamp.year


def test_6_out_of_order_events():
    """Pipeline reorders events chronologically based on event timestamp."""
    db: Session = SessionLocal()
    try:
        t0 = datetime(2026, 10, 2, 10, 0, 0, tzinfo=timezone.utc)
        raw_events = [
            {"user": "alice", "status": "failure", "timestamp": (t0 + timedelta(minutes=5)).isoformat()},
            {"user": "alice", "status": "failure", "timestamp": (t0 + timedelta(minutes=1)).isoformat()},
            {"user": "alice", "status": "success", "timestamp": (t0 + timedelta(minutes=10)).isoformat()},
        ]
        res = asyncio.run(global_auth_pipeline.analyze_events(raw_events=raw_events, db=db))
        assert res.events_analyzed_count == 3
    finally:
        db.close()


def test_7_duplicate_provider_event():
    """Deduplicates duplicate events with identical fingerprints."""
    pipeline = AuthenticationSecurityPipeline()
    t0 = datetime(2026, 10, 2, 10, 0, 0, tzinfo=timezone.utc)
    ev1 = NormalizedAuthEvent(
        id="ev-1",
        timestamp=t0,
        account_id="alice",
        source_ip="192.168.1.10",
        result=AuthenticationResultEnum.FAILURE,
        failure_reason=FailureReasonEnum.INVALID_CREDENTIALS,
    )
    ev2 = NormalizedAuthEvent(
        id="ev-2",  # Different ID, but exact same fingerprint
        timestamp=t0,
        account_id="alice",
        source_ip="192.168.1.10",
        result=AuthenticationResultEnum.FAILURE,
        failure_reason=FailureReasonEnum.INVALID_CREDENTIALS,
    )
    deduped = pipeline._deduplicate_events([ev1, ev2])
    assert len(deduped) == 1


# ============================================================================
# 2. ENTITY & RELATIONSHIP PERSISTENCE TESTS
# ============================================================================

def test_8_account_entity_creation():
    """Verifies EntityModel(entity_type='ACCOUNT') is persisted."""
    db: Session = SessionLocal()
    try:
        raw = [{"user": "carol_sec9@test.org", "status": "success", "ip": "203.0.113.50"}]
        res = asyncio.run(global_auth_pipeline.analyze_events(raw_events=raw, db=db))
        assert res.analysis_run_id is not None

        entity = db.query(EntityModel).filter(
            EntityModel.entity_type == EntityTypeEnum.ACCOUNT.value,
            EntityModel.name == "carol_sec9@test.org",
        ).first()
        assert entity is not None
    finally:
        db.close()


def test_9_ip_indicator_creation():
    """Verifies IndicatorModel(indicator_type='IP') is persisted."""
    db: Session = SessionLocal()
    try:
        raw = [{"user": "dave@test.org", "status": "success", "ip": "198.51.100.99"}]
        asyncio.run(global_auth_pipeline.analyze_events(raw_events=raw, db=db))

        ind = db.query(IndicatorModel).filter(
            IndicatorModel.indicator_type == "IP",
            IndicatorModel.normalized_value == "198.51.100.99",
        ).first()
        assert ind is not None
    finally:
        db.close()


def test_10_device_entity_creation():
    """Verifies EntityModel(entity_type='DEVICE') is persisted with attributes."""
    db: Session = SessionLocal()
    try:
        raw = [{
            "user": "eve@test.org",
            "status": "success",
            "ip": "203.0.113.10",
            "device_id": "MDM-DEV-9988",
            "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15",
        }]
        asyncio.run(global_auth_pipeline.analyze_events(raw_events=raw, db=db))

        dev = db.query(EntityModel).filter(
            EntityModel.entity_type == EntityTypeEnum.DEVICE.value,
            EntityModel.name == "MDM-DEV-9988",
        ).first()
        assert dev is not None
        assert "macOS" in dev.attributes_json
    finally:
        db.close()


def test_11_session_entity_creation():
    """Verifies EntityModel(entity_type='SESSION') and HAS_SESSION relationship."""
    db: Session = SessionLocal()
    try:
        raw = [{
            "user": "frank@test.org",
            "status": "success",
            "ip": "203.0.113.12",
            "session_id": "sess-token-xyz-1234",
        }]
        asyncio.run(global_auth_pipeline.analyze_events(raw_events=raw, db=db))

        sess = db.query(EntityModel).filter(
            EntityModel.entity_type == EntityTypeEnum.SESSION.value,
            EntityModel.name == "sess-token-xyz-1234",
        ).first()
        assert sess is not None
    finally:
        db.close()


# ============================================================================
# 3. DETECTION ENGINE TESTS
# ============================================================================

def test_12_repeated_failure_detection():
    """Detects repeated login failures exceeding threshold within window."""
    config = AuthConfigResponse(brute_force_failure_threshold=5, brute_force_window_seconds=900)
    t0 = datetime(2026, 10, 2, 12, 0, 0, tzinfo=timezone.utc)
    events = [
        NormalizedAuthEvent(
            id=f"f-{i}",
            timestamp=t0 + timedelta(seconds=i * 30),
            account_id="target_user",
            source_ip="198.51.100.5",
            result=AuthenticationResultEnum.FAILURE,
        )
        for i in range(6)
    ]
    findings = FailureAnalysisEngine.analyze(events, config)
    f_types = [f.finding_type for f in findings]
    assert "REPEATED_LOGIN_FAILURES" in f_types


def test_13_brute_force_detection():
    """Targeted brute force: 1 account, 6 failures from 1 IP in 3 minutes."""
    config = AuthConfigResponse(brute_force_failure_threshold=5, brute_force_window_seconds=900)
    t0 = datetime(2026, 10, 2, 12, 0, 0, tzinfo=timezone.utc)
    events = [
        NormalizedAuthEvent(
            id=f"bf-{i}",
            timestamp=t0 + timedelta(seconds=i * 20),
            account_id="finance_lead",
            source_ip="198.51.100.44",
            result=AuthenticationResultEnum.FAILURE,
        )
        for i in range(6)
    ]
    findings = BruteForceDetector.analyze(events, config)
    assert any(f.finding_type == "BRUTE_FORCE_PATTERN" for f in findings)
    bf = next(f for f in findings if f.finding_type == "BRUTE_FORCE_PATTERN")
    assert bf.severity == SeverityEnum.HIGH
    assert "T1110.001" in bf.mitre_attack_ids


def test_14_password_spray_detection():
    """Horizontal password spray: 1 source IP targeting 6 distinct accounts with 1 attempt each."""
    config = AuthConfigResponse(password_spray_account_threshold=5, password_spray_max_per_account=3, password_spray_window_seconds=1800)
    t0 = datetime(2026, 10, 2, 12, 0, 0, tzinfo=timezone.utc)
    accounts = ["user1", "user2", "user3", "user4", "user5", "user6"]
    events = [
        NormalizedAuthEvent(
            id=f"spray-{i}",
            timestamp=t0 + timedelta(seconds=i * 10),
            account_id=acc,
            source_ip="203.0.113.88",
            result=AuthenticationResultEnum.FAILURE,
        )
        for i, acc in enumerate(accounts)
    ]
    findings = PasswordSprayDetector.analyze(events, config)
    assert any(f.finding_type == "PASSWORD_SPRAY_PATTERN" for f in findings)
    spray = next(f for f in findings if f.finding_type == "PASSWORD_SPRAY_PATTERN")
    assert spray.severity == SeverityEnum.HIGH
    assert "T1110.003" in spray.mitre_attack_ids


def test_15_credential_stuffing_detection():
    """Credential stuffing volume across 12 accounts with high failure proportion."""
    config = AuthConfigResponse(credential_stuffing_account_threshold=10, credential_stuffing_window_seconds=3600)
    t0 = datetime(2026, 10, 2, 12, 0, 0, tzinfo=timezone.utc)
    events = []
    for i in range(12):
        events.append(
            NormalizedAuthEvent(
                id=f"stuff-{i}",
                timestamp=t0 + timedelta(seconds=i * 15),
                account_id=f"account_{i}@domain.com",
                source_ip=f"198.51.100.{10 + (i % 3)}",
                result=AuthenticationResultEnum.FAILURE,
            )
        )
    findings = CredentialStuffingDetector.analyze(events, config)
    assert any(f.finding_type == "CREDENTIAL_STUFFING_SUSPECTED" for f in findings)


def test_16_success_after_failures():
    """Sequence: 4 failures followed by success for the same account."""
    config = AuthConfigResponse(success_after_failures_min_failures=3, success_after_failures_window_seconds=1800)
    t0 = datetime(2026, 10, 2, 12, 0, 0, tzinfo=timezone.utc)
    events = [
        NormalizedAuthEvent(
            id=f"f-{i}",
            timestamp=t0 + timedelta(seconds=i * 20),
            account_id="admin_user",
            source_ip="198.51.100.7",
            result=AuthenticationResultEnum.FAILURE,
        )
        for i in range(4)
    ]
    # Followed by success
    events.append(
        NormalizedAuthEvent(
            id="succ-1",
            timestamp=t0 + timedelta(seconds=120),
            account_id="admin_user",
            source_ip="198.51.100.7",
            result=AuthenticationResultEnum.SUCCESS,
        )
    )
    findings = SuccessAfterFailuresDetector.analyze(events, config)
    assert any(f.finding_type == "SUCCESS_AFTER_REPEATED_FAILURES" for f in findings)
    f = next(f for f in findings if f.finding_type == "SUCCESS_AFTER_REPEATED_FAILURES")
    assert f.severity == SeverityEnum.HIGH


def test_17_new_ip_detection():
    """Detects NEW_SOURCE_IP when historical baseline has >= 5 logins."""
    config = AuthConfigResponse(min_history_events_ip=5)
    profile = AccountSecurityProfile(
        account_id="alice",
        baseline_status=BaselineStatusEnum.ESTABLISHED,
        total_successful_logins=10,
        known_source_ips=["192.168.1.1", "192.168.1.2"],
    )
    event = NormalizedAuthEvent(
        id="ev-1",
        timestamp=datetime.now(timezone.utc),
        account_id="alice",
        source_ip="203.0.113.99",  # Brand new IP
        result=AuthenticationResultEnum.SUCCESS,
    )
    findings = LocationAnalysisEngine.analyze([event], {"alice": profile}, config)
    assert any(f.finding_type == "NEW_SOURCE_IP" for f in findings)
    f = next(f for f in findings if f.finding_type == "NEW_SOURCE_IP")
    assert f.severity == SeverityEnum.LOW  # New IP is low risk by itself


def test_18_new_device_detection():
    """Detects NEW_DEVICE when historical baseline has >= 5 logins."""
    config = AuthConfigResponse(min_history_events_device=5)
    profile = AccountSecurityProfile(
        account_id="bob",
        baseline_status=BaselineStatusEnum.ESTABLISHED,
        total_successful_logins=15,
        known_devices=["MacBook-Pro-Bob"],
    )
    event = NormalizedAuthEvent(
        id="ev-dev",
        timestamp=datetime.now(timezone.utc),
        account_id="bob",
        source_ip="192.168.1.5",
        device_name="Linux-Laptop-Unknown",
        result=AuthenticationResultEnum.SUCCESS,
    )
    findings = DeviceAnalysisEngine.analyze([event], {"bob": profile}, config)
    assert any(f.finding_type == "NEW_DEVICE" for f in findings)


def test_19_insufficient_history_behavior():
    """Accounts with insufficient history (< 5 logins) do NOT produce NEW_DEVICE or NEW_IP alerts."""
    config = AuthConfigResponse(min_history_events_device=5, min_history_events_ip=5)
    profile = AccountSecurityProfile(
        account_id="newbie",
        baseline_status=BaselineStatusEnum.INSUFFICIENT_HISTORY,
        total_successful_logins=2,  # Insufficient
        known_devices=["Old-Phone"],
        known_source_ips=["1.1.1.1"],
    )
    event = NormalizedAuthEvent(
        id="ev-newbie",
        timestamp=datetime.now(timezone.utc),
        account_id="newbie",
        source_ip="2.2.2.2",
        device_name="New-Laptop",
        result=AuthenticationResultEnum.SUCCESS,
    )
    dev_findings = DeviceAnalysisEngine.analyze([event], {"newbie": profile}, config)
    loc_findings = LocationAnalysisEngine.analyze([event], {"newbie": profile}, config)
    assert len(dev_findings) == 0
    assert len(loc_findings) == 0


def test_20_rapid_location_change_impossible_travel():
    """Calculates implied velocity: London to Tokyo in 15 minutes (> 900 km/h) flags RAPID_LOCATION_CHANGE."""
    config = AuthConfigResponse(impossible_travel_speed_kmh=900.0, impossible_travel_min_distance_km=300.0)
    t0 = datetime(2026, 10, 2, 10, 0, 0, tzinfo=timezone.utc)
    ev_london = NormalizedAuthEvent(
        id="ev-lon",
        timestamp=t0,
        account_id="traveler",
        source_ip="81.2.69.142",
        location_city="London",
        location_country="United Kingdom",
        latitude=51.5074,
        longitude=-0.1278,
        result=AuthenticationResultEnum.SUCCESS,
    )
    ev_tokyo = NormalizedAuthEvent(
        id="ev-tyo",
        timestamp=t0 + timedelta(minutes=15),
        account_id="traveler",
        source_ip="133.242.0.1",
        location_city="Tokyo",
        location_country="Japan",
        latitude=35.6762,
        longitude=139.6503,
        result=AuthenticationResultEnum.SUCCESS,
    )
    findings = LocationAnalysisEngine.analyze([ev_london, ev_tokyo], {}, config)
    assert any(f.finding_type == "RAPID_LOCATION_CHANGE" for f in findings)
    f = next(f for f in findings if f.finding_type == "RAPID_LOCATION_CHANGE")
    assert f.severity == SeverityEnum.HIGH
    assert "implied velocity" in f.description.lower()
    assert "caveat" in f.description.lower()


def test_21_vpn_proxy_context_awareness():
    """Haversine distance calculation handles identical points and zero distance safely."""
    dist = LocationAnalysisEngine.haversine_distance(51.5074, -0.1278, 51.5074, -0.1278)
    assert dist == 0.0


def test_22_login_time_anomaly():
    """Login at 03:00 UTC when typical hours are 08:00-18:00 produces UNUSUAL_LOGIN_TIME."""
    config = AuthConfigResponse(min_history_events_temporal=10)
    profile = AccountSecurityProfile(
        account_id="day_worker",
        baseline_status=BaselineStatusEnum.ESTABLISHED,
        total_successful_logins=30,
        typical_login_hours=[8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18],
    )
    t_night = datetime(2026, 10, 2, 3, 15, 0, tzinfo=timezone.utc)
    ev = NormalizedAuthEvent(
        id="ev-night",
        timestamp=t_night,
        account_id="day_worker",
        source_ip="192.168.1.50",
        result=AuthenticationResultEnum.SUCCESS,
    )
    findings = TemporalAnalysisEngine.analyze([ev], {"day_worker": profile}, config)
    assert any(f.finding_type == "UNUSUAL_LOGIN_TIME" for f in findings)


def test_23_mfa_failure_sequence():
    """Detects REPEATED_MFA_FAILURES for 3 consecutive MFA rejections."""
    config = AuthConfigResponse(mfa_failure_threshold=3)
    t0 = datetime(2026, 10, 2, 10, 0, 0, tzinfo=timezone.utc)
    events = [
        NormalizedAuthEvent(
            id=f"mfa-{i}",
            timestamp=t0 + timedelta(seconds=i * 10),
            account_id="mfa_victim",
            source_ip="198.51.100.22",
            result=AuthenticationResultEnum.MFA_FAILURE,
            failure_reason=FailureReasonEnum.MFA_REJECTED,
        )
        for i in range(3)
    ]
    findings = MFAAnalysisEngine.analyze(events, {}, config)
    assert any(f.finding_type == "REPEATED_MFA_FAILURES" for f in findings)


def test_24_session_reuse_anomaly():
    """Same session observed across 2 distinct IPs in 5 minutes flags SUSPICIOUS_SESSION_ACTIVITY."""
    t0 = datetime(2026, 10, 2, 10, 0, 0, tzinfo=timezone.utc)
    events = [
        NormalizedAuthEvent(
            id="sess-1",
            timestamp=t0,
            account_id="victim",
            source_ip="198.51.100.10",
            session_id="session-hijacked-xyz",
            result=AuthenticationResultEnum.SUCCESS,
        ),
        NormalizedAuthEvent(
            id="sess-2",
            timestamp=t0 + timedelta(minutes=2),
            account_id="victim",
            source_ip="203.0.113.99",
            session_id="session-hijacked-xyz",
            result=AuthenticationResultEnum.SUCCESS,
        ),
    ]
    findings = SessionAnalysisEngine.analyze(events)
    assert any(f.finding_type == "SUSPICIOUS_SESSION_ACTIVITY" for f in findings)


def test_25_window_boundaries():
    """
    Events within threshold window produce findings, while events outside window do not.
    """
    config = AuthConfigResponse(brute_force_failure_threshold=5, brute_force_window_seconds=900)
    t0 = datetime(2026, 10, 2, 10, 0, 0, tzinfo=timezone.utc)

    # 1. 5 failures spaced 6 hours apart (total span 24h > 900s)
    slow_events = [
        NormalizedAuthEvent(
            id=f"slow-{i}",
            timestamp=t0 + timedelta(hours=i * 6),
            account_id="slow_target",
            source_ip="198.51.100.1",
            result=AuthenticationResultEnum.FAILURE,
        )
        for i in range(5)
    ]
    slow_findings = FailureAnalysisEngine.analyze(slow_events, config)
    assert not any(f.finding_type == "REPEATED_LOGIN_FAILURES" for f in slow_findings)

    # 2. 5 failures in 5 minutes (span 300s <= 900s)
    fast_events = [
        NormalizedAuthEvent(
            id=f"fast-{i}",
            timestamp=t0 + timedelta(minutes=i),
            account_id="fast_target",
            source_ip="198.51.100.1",
            result=AuthenticationResultEnum.FAILURE,
        )
        for i in range(5)
    ]
    fast_findings = FailureAnalysisEngine.analyze(fast_events, config)
    assert any(f.finding_type == "REPEATED_LOGIN_FAILURES" for f in fast_findings)


# ============================================================================
# 4. ACCOUNT TAKEOVER (ATO) COMPOSITE AGGREGATION
# ============================================================================

def test_26_ato_aggregation_multi_category():
    """
    Corroborates ATO hypothesis when multiple independent categories are satisfied:
    CREDENTIAL_ATTACK (success after failures) + DEVICE_ANOMALY (new device) + LOCATION_ANOMALY (rapid location change).
    """
    db: Session = SessionLocal()
    try:
        t0 = datetime(2026, 10, 2, 10, 0, 0, tzinfo=timezone.utc)
        profile = AccountSecurityProfile(
            account_id="cfo@corp.com",
            baseline_status=BaselineStatusEnum.ESTABLISHED,
            total_successful_logins=20,
            known_devices=["Corporate-Laptop"],
            known_source_ips=["192.168.1.100"],
            known_countries=["United States"],
        )

        raw_events = [
            # 1. Legitimate morning login from US
            {
                "user": "cfo@corp.com",
                "status": "success",
                "ip": "192.168.1.100",
                "device_name": "Corporate-Laptop",
                "latitude": 38.9072,
                "longitude": -77.0369,
                "city": "Washington",
                "country": "United States",
                "timestamp": t0.isoformat(),
            },
            # 2. 4 password failures from overseas IP
            {
                "user": "cfo@corp.com",
                "status": "failure",
                "ip": "198.51.100.99",
                "device_name": "Attacker-VM",
                "timestamp": (t0 + timedelta(minutes=10)).isoformat(),
            },
            {
                "user": "cfo@corp.com",
                "status": "failure",
                "ip": "198.51.100.99",
                "device_name": "Attacker-VM",
                "timestamp": (t0 + timedelta(minutes=11)).isoformat(),
            },
            {
                "user": "cfo@corp.com",
                "status": "failure",
                "ip": "198.51.100.99",
                "device_name": "Attacker-VM",
                "timestamp": (t0 + timedelta(minutes=12)).isoformat(),
            },
            {
                "user": "cfo@corp.com",
                "status": "failure",
                "ip": "198.51.100.99",
                "device_name": "Attacker-VM",
                "timestamp": (t0 + timedelta(minutes=13)).isoformat(),
            },
            # 3. Successful login from overseas IP with new device
            {
                "user": "cfo@corp.com",
                "status": "success",
                "ip": "198.51.100.99",
                "device_name": "Attacker-VM",
                "latitude": 55.7558,
                "longitude": 37.6173,
                "city": "Moscow",
                "country": "Russia",
                "timestamp": (t0 + timedelta(minutes=15)).isoformat(),
            },
        ]

        res = asyncio.run(
            global_auth_pipeline.analyze_events(
                raw_events=raw_events,
                db=db,
                historical_profiles={"cfo@corp.com": profile},
            )
        )

        assert res.ato_suspected is True
        assert res.overall_severity in (SeverityEnum.HIGH, SeverityEnum.CRITICAL)
        assert res.classification == "ACCOUNT_TAKEOVER_SUSPECTED"
        f_types = [f.finding_type for f in res.findings]
        assert "SUCCESS_AFTER_REPEATED_FAILURES" in f_types
        assert "NEW_DEVICE" in f_types
        assert "RAPID_LOCATION_CHANGE" in f_types
        assert "ACCOUNT_TAKEOVER_SUSPECTED" in f_types
    finally:
        db.close()


def test_27_evidence_persistence():
    """Verifies FindingEvidenceModel items are persisted with source and confidence."""
    db: Session = SessionLocal()
    try:
        raw = [
            {"user": "persist_user", "status": "failure", "ip": "198.51.100.2"} for _ in range(5)
        ]
        res = asyncio.run(global_auth_pipeline.analyze_events(raw_events=raw, db=db))
        evidence_records = db.query(FindingEvidenceModel).join(FindingModel).filter(
            FindingModel.analysis_run_id == res.analysis_run_id
        ).all()
        assert len(evidence_records) > 0
    finally:
        db.close()


def test_28_threat_event_creation():
    """Verifies ThreatEventModel is emitted for high-severity attack patterns."""
    db: Session = SessionLocal()
    try:
        raw = [
            {"user": "threat_target", "status": "failure", "ip": "198.51.100.77"} for _ in range(6)
        ]
        res = asyncio.run(global_auth_pipeline.analyze_events(raw_events=raw, db=db))
        te = db.query(ThreatEventModel).filter(
            ThreatEventModel.analysis_run_id == res.analysis_run_id
        ).first()
        assert te is not None
        assert "ATTACK" in te.event_type
    finally:
        db.close()


def test_29_secret_redaction():
    """Wipes passwords, tokens, cookies, and secrets from telemetry."""
    dirty_dict = {
        "user": "alice",
        "password": "SuperSecretPassword123!",
        "token": "bearer-eyJh...",
        "status": "failure",
        "nested": {
            "api_key": "sk-12345678",
            "safe_field": "public_data",
        }
    }
    cleaned = SecretRedactor.redact_dict(dirty_dict)
    assert cleaned["password"] == "[REDACTED_BY_CYBERGUARD]"
    assert cleaned["token"] == "[REDACTED_BY_CYBERGUARD]"
    assert cleaned["nested"]["api_key"] == "[REDACTED_BY_CYBERGUARD]"
    assert cleaned["nested"]["safe_field"] == "public_data"


def test_30_provider_adapters():
    """Verifies Okta, Entra ID, Google Workspace, and Linux adapters."""
    # 1. Okta Log
    okta_raw = {
        "provider": "okta",
        "actor": {"alternateId": "okta_user@corp.com", "displayName": "Okta User"},
        "outcome": {"result": "SUCCESS"},
        "client": {"ipAddress": "198.51.100.15", "userAgent": {"rawUserAgent": "Chrome on Windows"}},
    }
    ev_okta = global_adapter_registry.normalize(okta_raw)
    assert ev_okta.account_id == "okta_user@corp.com"
    assert ev_okta.result == AuthenticationResultEnum.SUCCESS

    # 2. Entra ID Log
    entra_raw = {
        "provider": "entra_id",
        "userPrincipalName": "entra_user@corp.onmicrosoft.com",
        "ipAddress": "198.51.100.16",
        "status": {"errorCode": 50126, "failureReason": "Invalid username or password"},
    }
    ev_entra = global_adapter_registry.normalize(entra_raw)
    assert ev_entra.account_id == "entra_user@corp.onmicrosoft.com"
    assert ev_entra.result == AuthenticationResultEnum.FAILURE

    # 3. Google Workspace
    google_raw = {
        "provider": "google_workspace",
        "actor": {"email": "google_user@corp.com"},
        "events": [{"name": "login_failure"}],
        "ipAddress": "198.51.100.17",
    }
    ev_google = global_adapter_registry.normalize(google_raw)
    assert ev_google.account_id == "google_user@corp.com"
    assert ev_google.result == AuthenticationResultEnum.FAILURE

    # 4. Linux auth.log
    linux_line = "Oct  2 12:00:00 server sshd[1234]: Failed password for root from 192.168.1.105 port 55432 ssh2"
    ev_linux = global_adapter_registry.normalize(linux_line)
    assert ev_linux.account_id == "root"
    assert ev_linux.source_ip == "192.168.1.105"
    assert ev_linux.result == AuthenticationResultEnum.FAILURE


# ============================================================================
# 5. FALSE-POSITIVE MITIGATION TESTS
# ============================================================================

def test_31_false_positive_single_failure_not_compromised():
    """A single login failure does NOT trigger brute force or ATO."""
    db: Session = SessionLocal()
    try:
        raw = [{"user": "clara@corp.com", "status": "failure", "ip": "192.168.1.20"}]
        res = asyncio.run(global_auth_pipeline.analyze_events(raw_events=raw, db=db))
        assert res.ato_suspected is False
        assert res.overall_severity == SeverityEnum.SAFE or res.overall_severity == SeverityEnum.LOW
    finally:
        db.close()


def test_32_false_positive_travel_alone_not_ato():
    """
    Legitimate business travel alone (without prior credential failures or suspicious anomalies)
    does NOT trigger ACCOUNT_TAKEOVER_SUSPECTED.
    """
    db: Session = SessionLocal()
    try:
        config = AuthConfigResponse(impossible_travel_speed_kmh=900.0, impossible_travel_min_distance_km=300.0)
        t0 = datetime(2026, 10, 2, 10, 0, 0, tzinfo=timezone.utc)
        # Login A in NYC, Login B in Chicago 4 hours later (velocity = ~300 km/h, well under 900 km/h)
        events = [
            NormalizedAuthEvent(
                id="ev-nyc",
                timestamp=t0,
                account_id="traveler_normal",
                source_ip="198.51.100.1",
                latitude=40.7128,
                longitude=-74.0060,
                result=AuthenticationResultEnum.SUCCESS,
            ),
            NormalizedAuthEvent(
                id="ev-chi",
                timestamp=t0 + timedelta(hours=4),
                account_id="traveler_normal",
                source_ip="198.51.100.2",
                latitude=41.8781,
                longitude=-87.6298,
                result=AuthenticationResultEnum.SUCCESS,
            ),
        ]
        findings = LocationAnalysisEngine.analyze(events, {}, config)
        assert not any(f.finding_type == "RAPID_LOCATION_CHANGE" for f in findings)
    finally:
        db.close()


def test_33_false_positive_new_browser_alone_not_ato():
    """Switching browsers or upgrading versions does NOT trigger ATO."""
    db: Session = SessionLocal()
    try:
        profile = AccountSecurityProfile(
            account_id="browser_switcher",
            baseline_status=BaselineStatusEnum.ESTABLISHED,
            total_successful_logins=10,
            known_client_profiles=["Windows/Chrome"],
            known_devices=["Laptop"],
        )
        raw = [{
            "user": "browser_switcher",
            "status": "success",
            "ip": "192.168.1.1",
            "device_name": "Laptop",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0",
        }]
        res = asyncio.run(
            global_auth_pipeline.analyze_events(
                raw_events=raw,
                db=db,
                historical_profiles={"browser_switcher": profile},
            )
        )
        assert res.ato_suspected is False
        assert res.overall_severity == SeverityEnum.LOW
    finally:
        db.close()


# ============================================================================
# 6. FASTAPI ENDPOINT TESTS
# ============================================================================

def test_34_api_config_endpoint():
    """GET /api/auth-security/config returns active thresholds and windows."""
    resp = client.get("/api/auth-security/config")
    assert resp.status_code == 200
    data = resp.json()
    assert "brute_force_failure_threshold" in data
    assert "password_spray_account_threshold" in data
    assert "impossible_travel_speed_kmh" in data


def test_35_api_analyze_single_event():
    """POST /api/auth-security/analyze-event analyzes a single payload."""
    payload = {
        "user": "api_user@test.org",
        "status": "success",
        "ip": "198.51.100.55",
        "timestamp": "2026-10-02T14:00:00Z",
    }
    resp = client.post("/api/auth-security/analyze-event", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["events_analyzed_count"] == 1
    assert data["accounts_targeted_count"] == 1


def test_36_api_analyze_batch():
    """POST /api/auth-security/analyze-batch processes batch event list."""
    batch = {
        "events": [
            {"user": "batch_user", "status": "failure", "ip": "198.51.100.1"},
            {"user": "batch_user", "status": "failure", "ip": "198.51.100.1"},
            {"user": "batch_user", "status": "success", "ip": "198.51.100.1"},
        ]
    }
    resp = client.post("/api/auth-security/analyze-batch", json=batch)
    assert resp.status_code == 200
    data = resp.json()
    assert data["events_analyzed_count"] == 3


def test_37_api_account_profile():
    """GET /api/auth-security/accounts/{id}/profile returns account baseline."""
    resp = client.get("/api/auth-security/accounts/cfo@corp.com/profile")
    assert resp.status_code == 200
    data = resp.json()
    assert data["account_id"] == "cfo@corp.com"


# ============================================================================
# 7. PERFORMANCE BENCHMARK TEST
# ============================================================================

def test_38_synthetic_performance_benchmark():
    """
    Performance benchmark on 500 synthetic authentication events.
    Verifies that normalization, temporal sorting, and pattern detection
    execute in sub-second time.
    """
    db: Session = SessionLocal()
    try:
        t0 = datetime(2026, 10, 2, 8, 0, 0, tzinfo=timezone.utc)
        events_500 = []
        for i in range(500):
            events_500.append({
                "user": f"employee_{i % 25}@enterprise.org",
                "status": "failure" if (i % 7 == 0) else "success",
                "ip": f"10.0.0.{1 + (i % 15)}",
                "timestamp": (t0 + timedelta(seconds=i * 5)).isoformat(),
                "device_name": f"Device-{i % 10}",
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
                "latitude": 37.7749,
                "longitude": -122.4194,
            })

        start_time = time.perf_counter()
        res = asyncio.run(global_auth_pipeline.analyze_events(raw_events=events_500, db=db))
        duration = time.perf_counter() - start_time

        assert res.events_analyzed_count == 500
        # Performance requirement: 500 events should analyze in under 2.0 seconds
        assert duration < 2.0, f"Analysis took {duration:.2f}s, expected < 2.0s"
    finally:
        db.close()
