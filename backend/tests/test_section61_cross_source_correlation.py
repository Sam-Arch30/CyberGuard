"""
Section 61: Cross-Source Correlation & Unified Entity Correlation Test Suite.
Validates:
1. Deterministic Entity Resolution (Exact ID, External ID, Canonical normalization, Ambiguity preservation)
2. Cross-Source Correlator logic (Shared Infrastructure, Attack Sequence, Auth+Endpoint, Behavioral+Rule, Watchlist+Observation)
3. Bounded Temporal Windows & Clock Skew Tolerance
4. Composite Finding Generation & Evidence Lineage (No Double-Counting)
5. Idempotency & Duplicate Replay Protection
6. Analyst Disposition & Audit Trail
7. REST API Endpoints
"""
import json
import uuid
from datetime import datetime, timezone, timedelta
import pytest
from fastapi.testclient import TestClient

from backend.db.session import get_db, init_db
from backend.db.models import (
    EntityModel,
    FindingModel,
    FindingEvidenceModel,
    CrossSourceCorrelationModel,
    CorrelationMemberModel,
    EntityResolutionRecordModel,
    BehavioralDeviationModel,
    DetectionMatchModel,
    CandidateRuleModel,
    WatchedIndicatorModel,
    WatchlistModel,
    AuditLogModel,
    get_utc_now,
    generate_uuid,
)
from backend.schemas.cross_source_correlation import (
    CorrelationTypeEnum,
    CorrelationStatusEnum,
    ResolutionMethodEnum,
    ResolutionStatusEnum,
    CorrelationDispositionRequest,
    CorrelationEvaluationRequest,
    EntityResolutionRequest,
)
from backend.services.unified_entity_resolver import UnifiedEntityResolver
from backend.services.cross_source_correlation_engine import CrossSourceCorrelationEngine
from backend.main import app


@pytest.fixture(scope="module")
def client():
    init_db()
    return TestClient(app)


@pytest.fixture
def db_session():
    init_db()
    gen = get_db()
    db = next(gen)
    try:
        yield db
    finally:
        try:
            next(gen)
        except StopIteration:
            pass


# ============================================================================
# 1. ENTITY RESOLUTION TESTS
# ============================================================================

def test_entity_resolution_deterministic_id(db_session):
    """Verifies that an existing EntityModel is resolved via stable internal UUID."""
    ws = f"ws-ent-{uuid.uuid4().hex[:6]}"
    ent = EntityModel(
        id=generate_uuid(),
        entity_type="USER",
        name="alice@enterprise.corp",
        canonical_key=f"user:{ws}:alice@enterprise.corp",
        workspace_id=ws,
        first_seen=get_utc_now(),
        last_seen=get_utc_now(),
    )
    db_session.add(ent)
    db_session.commit()

    res = UnifiedEntityResolver.resolve_entity(
        db=db_session,
        entity_type="USER",
        raw_identifier=ent.id,
        workspace_id=ws,
    )
    assert res.status == ResolutionStatusEnum.RESOLVED
    assert res.canonical_entity_id == ent.id
    assert res.resolution_method == ResolutionMethodEnum.EXACT_ID
    assert res.resolution_confidence == 1.0


def test_entity_resolution_external_id(db_session):
    """Verifies resolution via canonical external identifier."""
    ws = f"ws-ent-{uuid.uuid4().hex[:6]}"
    ext_id = f"okta-user-{uuid.uuid4().hex[:6]}"
    ent = EntityModel(
        id=generate_uuid(),
        entity_type="USER",
        name="bob_smith",
        external_id=ext_id,
        canonical_key=f"user:{ws}:bob_smith",
        workspace_id=ws,
        first_seen=get_utc_now(),
        last_seen=get_utc_now(),
    )
    db_session.add(ent)
    db_session.commit()

    res = UnifiedEntityResolver.resolve_entity(
        db=db_session,
        entity_type="USER",
        raw_identifier="bob_smith",
        workspace_id=ws,
        context=ext_id,
    )
    assert res.status == ResolutionStatusEnum.RESOLVED
    assert res.canonical_entity_id == ent.id
    assert res.resolution_method == ResolutionMethodEnum.EXACT_ID


def test_entity_resolution_canonical_normalization_ip(db_session):
    """Verifies IP normalization resolves to canonical entity."""
    ws = f"ws-ent-{uuid.uuid4().hex[:6]}"
    raw_ip = "185.220.101.5"

    res = UnifiedEntityResolver.resolve_entity(
        db=db_session,
        entity_type="IP",
        raw_identifier=raw_ip,
        workspace_id=ws,
    )
    assert res.status == ResolutionStatusEnum.RESOLVED
    assert res.normalized_identifier == "185.220.101.5"
    assert "ip:185.220.101.5" in res.canonical_key
    assert res.resolution_confidence == 1.0


def test_entity_resolution_canonical_normalization_domain_url(db_session):
    """Verifies domain and URL normalization downcases and strips default schemas."""
    ws = f"ws-ent-{uuid.uuid4().hex[:6]}"
    res_domain = UnifiedEntityResolver.resolve_entity(
        db=db_session,
        entity_type="DOMAIN",
        raw_identifier="PAYPAL-SECURITY-CHECK.XYZ.",
        workspace_id=ws,
    )
    assert res_domain.status == ResolutionStatusEnum.RESOLVED
    assert res_domain.normalized_identifier == "paypal-security-check.xyz"

    res_url = UnifiedEntityResolver.resolve_entity(
        db=db_session,
        entity_type="URL",
        raw_identifier="HTTPS://LOGIN.PHISH-PORTAL.COM:443/auth?ref=1",
        workspace_id=ws,
    )
    assert res_url.status == ResolutionStatusEnum.RESOLVED
    assert "login.phish-portal.com" in res_url.normalized_identifier


def test_entity_resolution_ambiguity_preservation(db_session):
    """Verifies that when multiple fuzzy matches exist, ambiguity is preserved without silent merging."""
    ws = f"ws-ent-{uuid.uuid4().hex[:6]}"
    ent1 = EntityModel(
        id=generate_uuid(),
        entity_type="USER",
        name="john.doe.finance",
        canonical_key=f"user:{ws}:john.doe.finance",
        workspace_id=ws,
        first_seen=get_utc_now(),
        last_seen=get_utc_now(),
    )
    ent2 = EntityModel(
        id=generate_uuid(),
        entity_type="USER",
        name="john.doe.engineering",
        canonical_key=f"user:{ws}:john.doe.engineering",
        workspace_id=ws,
        first_seen=get_utc_now(),
        last_seen=get_utc_now(),
    )
    db_session.add_all([ent1, ent2])
    db_session.commit()

    res = UnifiedEntityResolver.resolve_entity(
        db=db_session,
        entity_type="USER",
        raw_identifier="john.doe",
        workspace_id=ws,
        allow_fuzzy=True,
    )
    assert res.status == ResolutionStatusEnum.AMBIGUOUS
    assert res.canonical_entity_id is None
    assert res.resolution_confidence <= 0.50
    assert len(res.matched_attributes.get("candidate_ids", [])) == 2


def test_entity_resolution_tenant_isolation(db_session):
    """Verifies that entities in workspace A are not resolved for queries in workspace B."""
    ws_a = f"ws-a-{uuid.uuid4().hex[:6]}"
    ws_b = f"ws-b-{uuid.uuid4().hex[:6]}"

    ent_a = EntityModel(
        id=generate_uuid(),
        entity_type="ENDPOINT",
        name="workstation-99",
        canonical_key=f"device:{ws_a}:workstation-99",
        workspace_id=ws_a,
        first_seen=get_utc_now(),
        last_seen=get_utc_now(),
    )
    db_session.add(ent_a)
    db_session.commit()

    # Query in workspace B should NOT match ent_a by internal ID
    res_b = UnifiedEntityResolver.resolve_entity(
        db=db_session,
        entity_type="ENDPOINT",
        raw_identifier=ent_a.id,
        workspace_id=ws_b,
    )
    assert res_b.canonical_entity_id != ent_a.id


# ============================================================================
# 2. CROSS-SOURCE CORRELATION TESTS
# ============================================================================

def test_cross_source_shared_infrastructure_sequence(db_session):
    """Correlates Email finding with endpoint network connection sharing destination IP."""
    ws = f"ws-corr-{uuid.uuid4().hex[:6]}"
    now = get_utc_now()
    shared_ip = "185.190.140.22"

    # 1. Email finding containing URL with shared IP
    f_email = FindingModel(
        id=generate_uuid(),
        workspace_id=ws,
        analyzer="email_phishing_analyzer",
        source_type="EMAIL",
        finding_type="PHISHING_EMAIL",
        title="Phishing email with credential harvesting link",
        description="Message contained outbound hyperlink",
        severity="HIGH",
        confidence=0.90,
        risk_contribution=70.0,
        created_at=now - timedelta(minutes=10),
    )
    f_email.details = {"indicators": [shared_ip]}
    db_session.add(f_email)

    # 2. Endpoint finding reporting outbound connection to same IP
    f_endpoint = FindingModel(
        id=generate_uuid(),
        workspace_id=ws,
        analyzer="endpoint_telemetry_pipeline",
        source_type="ENDPOINT",
        finding_type="UNUSUAL_OUTBOUND_CONNECTION",
        title="Endpoint connected to suspicious IP",
        description="PowerShell process connected outbound",
        severity="HIGH",
        confidence=0.88,
        risk_contribution=65.0,
        created_at=now - timedelta(minutes=5),
    )
    f_endpoint.details = {"indicators": [shared_ip]}
    db_session.add(f_endpoint)
    db_session.commit()

    corrs = CrossSourceCorrelationEngine.evaluate_cross_source_correlation(
        db=db_session,
        workspace_id=ws,
        window_seconds=1800.0,
    )

    assert len(corrs) >= 1
    c = corrs[0]
    assert c.correlation_type in (
        CorrelationTypeEnum.TEMPORAL_ATTACK_SEQUENCE.value,
        CorrelationTypeEnum.SHARED_INFRASTRUCTURE.value,
    )
    assert c.status == CorrelationStatusEnum.CORRELATED.value
    assert c.confidence_score >= 0.85
    assert shared_ip in c.title


def test_cross_source_auth_and_endpoint(db_session):
    """Correlates suspicious authentication with concurrent endpoint execution for same user."""
    ws = f"ws-corr-{uuid.uuid4().hex[:6]}"
    now = get_utc_now()
    user = f"user_{uuid.uuid4().hex[:6]}"

    f_auth = FindingModel(
        id=generate_uuid(),
        workspace_id=ws,
        analyzer="authentication_analyzer",
        source_type="AUTH",
        finding_type="SUSPICIOUS_AUTHENTICATION",
        title=f"Unusual login for {user}",
        description="Login from novel geolocation",
        severity="MEDIUM",
        confidence=0.85,
        risk_contribution=55.0,
        created_at=now - timedelta(minutes=8),
    )
    f_auth.details = {"user_id": user, "ip": "194.26.29.10"}
    db_session.add(f_auth)

    f_ep = FindingModel(
        id=generate_uuid(),
        workspace_id=ws,
        analyzer="endpoint_agent",
        source_type="ENDPOINT",
        finding_type="SUSPICIOUS_PROCESS_EXECUTION",
        title="Encoded PowerShell script execution",
        description="Execution of obfuscated command line",
        severity="HIGH",
        confidence=0.92,
        risk_contribution=75.0,
        created_at=now - timedelta(minutes=2),
    )
    f_ep.details = {"user_id": user, "endpoint_id": "laptop-finance-01"}
    db_session.add(f_ep)
    db_session.commit()

    corrs = CrossSourceCorrelationEngine.evaluate_cross_source_correlation(
        db=db_session,
        workspace_id=ws,
        window_seconds=1800.0,
    )

    auth_corrs = [c for c in corrs if c.correlation_type == CorrelationTypeEnum.AUTH_AND_ENDPOINT.value]
    assert len(auth_corrs) == 1
    assert user in auth_corrs[0].title
    assert auth_corrs[0].confidence_score >= 0.85


def test_cross_source_behavioral_and_rule_detection(db_session):
    """Correlates Section 60 behavioral anomaly with Section 56/59 detection match on same entity."""
    ws = f"ws-corr-{uuid.uuid4().hex[:6]}"
    now = get_utc_now()
    entity = f"host-{uuid.uuid4().hex[:6]}"

    dev = BehavioralDeviationModel(
        id=generate_uuid(),
        workspace_id=ws,
        entity_type="ENDPOINT",
        entity_id=entity,
        metric_type="ENDPOINT_PROCESS_COUNT",
        observed_value="250.0",
        expected_range_summary="Mean: 40.0, StdDev: 8.0",
        deviation_score=0.91,
        severity_hint="HIGH",
        explanation="Process count exceeded 4 standard deviations",
        created_at=now - timedelta(minutes=4),
    )
    db_session.add(dev)

    rule = CandidateRuleModel(
        id=generate_uuid(),
        workspace_id=ws,
        rule_identifier="RULE-RANSOMWARE-BURST",
        name="Mass File & Process Activity",
        normalized_fingerprint=f"fp-{uuid.uuid4().hex[:8]}",
        version="1.0.0",
        severity="HIGH",
    )
    db_session.add(rule)
    db_session.flush()

    match = DetectionMatchModel(
        id=f"DET-{uuid.uuid4().hex[:12]}",
        workspace_id=ws,
        rule_id=rule.id,
        rule_version="1.0.0",
        event_id=f"evt-{uuid.uuid4().hex[:6]}",
        evidence_json=json.dumps({"entity_id": entity, "process_count": 250}),
        matched_fields_json=json.dumps(["process_count"]),
        severity="HIGH",
        confidence=0.95,
        created_at=now - timedelta(minutes=2),
    )
    db_session.add(match)
    db_session.commit()

    corrs = CrossSourceCorrelationEngine.evaluate_cross_source_correlation(
        db=db_session,
        workspace_id=ws,
        window_seconds=1800.0,
    )

    b_corrs = [c for c in corrs if c.correlation_type == CorrelationTypeEnum.BEHAVIORAL_AND_RULE_DETECTION.value]
    assert len(b_corrs) == 1
    assert entity in b_corrs[0].title


def test_cross_source_watchlist_and_observation(db_session):
    """Correlates Section 53 watchlist IOC with live finding observation."""
    ws = f"ws-corr-{uuid.uuid4().hex[:6]}"
    now = get_utc_now()
    watched_val = f"malware-c2-{uuid.uuid4().hex[:4]}.org"

    wl = WatchlistModel(
        id=generate_uuid(),
        workspace_id=ws,
        name="Test Watchlist",
        status="ACTIVE",
        priority="HIGH",
    )
    db_session.add(wl)
    db_session.flush()

    watched = WatchedIndicatorModel(
        id=generate_uuid(),
        workspace_id=ws,
        watchlist_id=wl.id,
        indicator_type="DOMAIN",
        raw_value=watched_val,
        display_value=watched_val,
        normalized_value=watched_val.lower(),
        monitoring_status="ACTIVE",
        priority="HIGH",
        created_at=now - timedelta(hours=2),
    )
    db_session.add(watched)

    f = FindingModel(
        id=generate_uuid(),
        workspace_id=ws,
        analyzer="network_analyzer",
        source_type="NETWORK",
        finding_type="C2_BEACONING",
        title="DNS resolution to suspicious domain",
        description="Host performed DNS query",
        severity="HIGH",
        confidence=0.95,
        risk_contribution=85.0,
        created_at=now - timedelta(minutes=3),
    )
    f.details = {"indicators": [watched_val]}
    db_session.add(f)
    db_session.commit()

    corrs = CrossSourceCorrelationEngine.evaluate_cross_source_correlation(
        db=db_session,
        workspace_id=ws,
        window_seconds=1800.0,
    )

    w_corrs = [c for c in corrs if c.correlation_type == CorrelationTypeEnum.WATCHLIST_AND_OBSERVATION.value]
    assert len(w_corrs) == 1
    assert watched_val in w_corrs[0].title


def test_temporal_window_boundary(db_session):
    """Verifies that events occurring outside the configured correlation window are not correlated."""
    ws = f"ws-corr-{uuid.uuid4().hex[:6]}"
    now = get_utc_now()
    shared_ip = "192.168.1.100"

    # Event 1: 5 hours ago
    f1 = FindingModel(
        id=generate_uuid(),
        workspace_id=ws,
        analyzer="email_phishing_analyzer",
        source_type="EMAIL",
        finding_type="PHISHING_EMAIL",
        title="Email from 5 hours ago",
        description="Historical event",
        severity="MEDIUM",
        created_at=now - timedelta(hours=5),
    )
    f1.details = {"indicators": [shared_ip]}

    # Event 2: Now
    f2 = FindingModel(
        id=generate_uuid(),
        workspace_id=ws,
        analyzer="endpoint_agent",
        source_type="ENDPOINT",
        finding_type="SUSPICIOUS_PROCESS_EXECUTION",
        title="Current event",
        description="Recent event",
        severity="HIGH",
        created_at=now,
    )
    f2.details = {"indicators": [shared_ip]}

    db_session.add_all([f1, f2])
    db_session.commit()

    # Budget window is 1 hour (3600s); 5 hour separation must fail correlation
    corrs = CrossSourceCorrelationEngine.evaluate_cross_source_correlation(
        db=db_session,
        workspace_id=ws,
        window_seconds=3600.0,
    )
    # No correlations should be established between f1 and f2
    matching = [c for c in corrs if shared_ip in c.title]
    assert len(matching) == 0


def test_composite_finding_generation_and_no_double_counting(db_session):
    """Verifies parent composite finding is created, child findings linked, and risk score discounted."""
    ws = f"ws-corr-{uuid.uuid4().hex[:6]}"
    now = get_utc_now()
    shared_domain = f"phish-{uuid.uuid4().hex[:6]}.net"

    f1 = FindingModel(
        id=generate_uuid(),
        workspace_id=ws,
        analyzer="email_analyzer",
        source_type="EMAIL",
        finding_type="PHISHING_EMAIL",
        title="Phishing Email",
        description="Desc",
        severity="HIGH",
        confidence=0.90,
        risk_contribution=70.0,
        created_at=now - timedelta(minutes=5),
    )
    f1.details = {"indicators": [shared_domain]}

    f2 = FindingModel(
        id=generate_uuid(),
        workspace_id=ws,
        analyzer="endpoint_analyzer",
        source_type="ENDPOINT",
        finding_type="MALICIOUS_DOWNLOAD",
        title="Host Download",
        description="Desc",
        severity="HIGH",
        confidence=0.85,
        risk_contribution=60.0,
        created_at=now - timedelta(minutes=2),
    )
    f2.details = {"indicators": [shared_domain]}

    db_session.add_all([f1, f2])
    db_session.commit()

    corrs = CrossSourceCorrelationEngine.evaluate_cross_source_correlation(
        db=db_session,
        workspace_id=ws,
        window_seconds=1800.0,
    )
    assert len(corrs) >= 1
    corr = corrs[0]

    # Verify parent finding exists
    assert corr.parent_finding_id is not None
    parent = db_session.query(FindingModel).filter(FindingModel.id == corr.parent_finding_id).first()
    assert parent is not None
    assert parent.is_composite == True
    assert parent.finding_type == "COMPOSITE_CORRELATION"

    # Verify child findings point to parent
    db_session.refresh(f1)
    db_session.refresh(f2)
    assert f1.parent_finding_id == parent.id
    assert f2.parent_finding_id == parent.id

    # Verify Risk is NOT double-counted: max(70, 60) + 0.3 * 60 = 70 + 18 = 88, NOT 130!
    assert parent.risk_contribution < 100.0
    assert corr.risk_score == parent.risk_contribution


def test_idempotency_duplicate_event(db_session):
    """Verifies executing correlation repeatedly produces zero duplicate records."""
    ws = f"ws-corr-{uuid.uuid4().hex[:6]}"
    now = get_utc_now()
    shared_ip = "185.220.101.99"

    f1 = FindingModel(
        id=generate_uuid(),
        workspace_id=ws,
        analyzer="email_analyzer",
        source_type="EMAIL",
        finding_type="PHISHING_EMAIL",
        title="Phishing Email",
        description="Desc",
        severity="HIGH",
        created_at=now - timedelta(minutes=5),
    )
    f1.details = {"indicators": [shared_ip]}

    f2 = FindingModel(
        id=generate_uuid(),
        workspace_id=ws,
        analyzer="endpoint_analyzer",
        source_type="ENDPOINT",
        finding_type="OUTBOUND_C2",
        title="Host connection",
        description="Desc",
        severity="HIGH",
        created_at=now - timedelta(minutes=2),
    )
    f2.details = {"indicators": [shared_ip]}

    db_session.add_all([f1, f2])
    db_session.commit()

    # Run 1
    corrs1 = CrossSourceCorrelationEngine.evaluate_cross_source_correlation(db=db_session, workspace_id=ws)
    count1 = db_session.query(CrossSourceCorrelationModel).filter(CrossSourceCorrelationModel.workspace_id == ws).count()

    # Run 2 (exact same input)
    corrs2 = CrossSourceCorrelationEngine.evaluate_cross_source_correlation(db=db_session, workspace_id=ws)
    count2 = db_session.query(CrossSourceCorrelationModel).filter(CrossSourceCorrelationModel.workspace_id == ws).count()

    assert count1 == count2
    assert count1 >= 1


def test_analyst_disposition_workflow(db_session):
    """Verifies analyst disposition (Confirm / Reject / Uncertain) updates status and creates audit log."""
    ws = f"ws-corr-{uuid.uuid4().hex[:6]}"
    corr = CrossSourceCorrelationModel(
        id=generate_uuid(),
        workspace_id=ws,
        correlation_type=CorrelationTypeEnum.SHARED_INFRASTRUCTURE.value,
        title="Test Correlation",
        description="Testing disposition",
        status=CorrelationStatusEnum.CORRELATED.value,
        confidence_score=0.90,
        confidence_level="HIGH",
        risk_score=75.0,
        risk_level="HIGH",
        severity="HIGH",
        idempotency_hash="hash-123456",
        explanation_summary="Explanation",
        first_observed_at=get_utc_now(),
        last_observed_at=get_utc_now(),
        created_at=get_utc_now(),
        updated_at=get_utc_now(),
    )
    db_session.add(corr)
    db_session.commit()

    req = CorrelationDispositionRequest(
        disposition="CONFIRMED",
        notes="Confirmed credential harvesting attack sequence",
        actor="lead_analyst_dan",
    )
    updated = CrossSourceCorrelationEngine.record_disposition(
        db=db_session,
        correlation_id=corr.id,
        req=req,
        workspace_id=ws,
    )

    assert updated.analyst_disposition == "CONFIRMED"
    assert updated.dispositioned_by == "lead_analyst_dan"

    # Verify audit log created
    audit = db_session.query(AuditLogModel).filter(
        AuditLogModel.resource_id == corr.id,
        AuditLogModel.action == "CORRELATION_CONFIRMED"
    ).first()
    assert audit is not None


# ============================================================================
# 3. REST API TESTS
# ============================================================================

def test_api_overview_and_endpoints(client, db_session):
    """Tests the REST API routes for Section 61."""
    ws = f"ws-api-{uuid.uuid4().hex[:6]}"
    headers = {"X-Workspace-ID": ws}

    # 1. Overview
    res = client.get("/api/v1/correlations/overview", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert "total_correlations" in data

    # 2. Entity Resolution via API
    res_ent = client.post(
        "/api/v1/entities/resolve",
        headers=headers,
        json={"entity_type": "IP", "raw_identifier": "194.26.29.15", "workspace_id": ws},
    )
    assert res_ent.status_code == 200
    ent_data = res_ent.json()
    assert ent_data["normalized_identifier"] == "194.26.29.15"
    assert ent_data["status"] == "RESOLVED"

    # 3. Resolution History
    res_hist = client.get("/api/v1/entities/resolution-history", headers=headers)
    assert res_hist.status_code == 200
    hist_data = res_hist.json()
    assert hist_data["total"] >= 1

    # 4. List correlations
    res_list = client.get("/api/v1/correlations", headers=headers)
    assert res_list.status_code == 200
    assert "items" in res_list.json()
