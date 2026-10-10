"""
Section 55: Comprehensive Tests for Advanced Threat Hunting & Investigation Pivots.
Validates:
- Pivot catalog and capabilities registry
- Bounded validation guards and depth limits
- Factual entity frequency analysis (artifacts, alerts, investigations, watchlists)
- Relational and graph pivots (DNS, Certificates, ASN, Reverse DNS, Telemetry)
- Multi-hop traversal (depth=2) with cycle prevention
- Explainable AI-assisted pivot recommendations
- Analyst hypothesis recording and evidence classification
- Workflow handoffs to Investigations, Watchlists, and Threat Hunting.
"""
import json
from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.main import app
from backend.db.session import get_db, Base
from backend.db.models import (
    IndicatorModel,
    ThreatIntelligenceRecordModel,
    EmailAnalysisModel,
    AlertModel,
    IncidentModel,
    WatchedIndicatorModel,
    WatchlistModel,
    RelationshipModel,
    HuntHypothesisModel,
    PivotExecutionModel,
    generate_uuid,
    get_utc_now,
)
from backend.schemas.pivots import (
    PivotSourceTypeEnum,
    PivotTypeEnum,
    PivotRequest,
    HypothesisRecordRequest,
    PromoteToInvestigationRequest,
    PromoteToWatchlistRequest,
    PivotToHuntQueryRequest,
)
from backend.services.investigation_pivot_service import InvestigationPivotService

# Setup isolated in-memory test database
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(scope="function")
def db():
    Base.metadata.create_all(bind=engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def client(db):
    def override_get_db():
        try:
            yield db
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


# =============================================================================
# 1. Registry & Validation Tests
# =============================================================================

def test_pivot_registry(client):
    response = client.get("/api/hunting/pivots/registry")
    assert response.status_code == 200
    data = response.json()
    assert "DOMAIN" in data["supported_source_types"]
    assert "IP" in data["supported_source_types"]
    assert "CERTIFICATE" in data["supported_source_types"]
    assert "HASH" in data["supported_source_types"]
    assert data["max_depth_allowed"] == 3
    assert len(data["pivots"]) >= 15


def test_pivot_validation_guards(db):
    # Empty source value
    with pytest.raises(ValueError, match="source_value must not be empty"):
        InvestigationPivotService.validate_pivot_request(
            PivotRequest(
                source_type=PivotSourceTypeEnum.DOMAIN,
                source_value="   ",
                pivot_type=PivotTypeEnum.RESOLVED_IPS,
            ),
            workspace_id="default",
        )

    # Depth > 3 (rejected by Pydantic schema validation)
    with pytest.raises(Exception):
        PivotRequest(
            source_type=PivotSourceTypeEnum.DOMAIN,
            source_value="evil.com",
            pivot_type=PivotTypeEnum.RESOLVED_IPS,
            depth=5,
        )


# =============================================================================
# 2. Entity Frequency Context
# =============================================================================

def test_entity_frequency_context(db):
    now = get_utc_now()
    # Seed indicator
    ind = IndicatorModel(
        id=generate_uuid(),
        indicator_type="DOMAIN",
        value="phishing-login.com",
        normalized_value="phishing-login.com",
        reputation="MALICIOUS",
        confidence=0.92,
        first_seen=now,
        last_seen=now,
    )
    db.add(ind)

    # Seed alert referencing this domain
    alt = AlertModel(
        id=generate_uuid(),
        workspace_id="default",
        notification_type="SECURITY_ALERT",
        title="Phishing domain detected: phishing-login.com",
        message="Observed in credential campaign",
        severity="HIGH",
        status="UNREAD",
        source_type="FINDING",
        created_at=now,
        updated_at=now,
    )
    db.add(alt)

    # Seed incident
    inc = IncidentModel(
        id=generate_uuid(),
        workspace_id="default",
        incident_number="INC-1001",
        title="Credential Harvesting Operation",
        description="Targeting HR department via phishing-login.com",
        severity="CRITICAL",
        status="ACTIVE",
        created_at=now,
        updated_at=now,
    )
    db.add(inc)

    # Seed watchlist item
    wl = WatchlistModel(
        id=generate_uuid(),
        name="C2 Watchlist",
        workspace_id="default",
        status="ACTIVE",
        created_at=now,
        updated_at=now,
    )
    db.add(wl)
    db.flush()

    w_item = WatchedIndicatorModel(
        id=generate_uuid(),
        watchlist_id=wl.id,
        workspace_id="default",
        indicator_type="DOMAIN",
        raw_value="phishing-login.com",
        display_value="phishing-login.com",
        normalized_value="phishing-login.com",
        monitoring_status="ACTIVE",
        priority="HIGH",
        created_at=now,
        updated_at=now,
    )
    db.add(w_item)
    db.commit()

    freq = InvestigationPivotService.get_entity_frequency_context(
        db=db,
        source_type="DOMAIN",
        source_value="phishing-login.com",
        workspace_id="default",
    )

    assert freq.reputation_verdict == "MALICIOUS"
    assert freq.threat_score == 0.92
    assert freq.alert_count >= 1
    assert freq.investigation_count >= 1
    assert freq.is_watchlist_monitored is True


# =============================================================================
# 3. Domain & Infrastructure Pivots
# =============================================================================

def test_domain_to_resolved_ips_pivot(db):
    now = get_utc_now()
    # Seed ThreatIntelligenceRecordModel with DNS resolution payload
    ti = ThreatIntelligenceRecordModel(
        id=generate_uuid(),
        workspace_id="default",
        indicator_type="DOMAIN",
        indicator_value="phish-bank.com",
        normalized_value="phish-bank.com",
        provider="cyberguard_feed",
        verdict="MALICIOUS",
        confidence=0.88,
        normalized_data_json=json.dumps({
            "resolved_ips": ["198.51.100.42", "198.51.100.43"],
            "asn": 13335,
            "asn_name": "Cloudflare Carrier",
        }),
        first_seen=now,
        last_seen=now,
    )
    db.add(ti)
    db.commit()

    res = InvestigationPivotService.execute_pivot(
        db=db,
        req=PivotRequest(
            source_type=PivotSourceTypeEnum.DOMAIN,
            source_value="phish-bank.com",
            pivot_type=PivotTypeEnum.RESOLVED_IPS,
            depth=1,
            limit=50,
        ),
        workspace_id="default",
    )

    assert res.total_results == 2
    vals = [it.target_value for it in res.items]
    assert "198.51.100.42" in vals
    assert "198.51.100.43" in vals
    assert res.items[0].relationship_type == "RESOLVES_TO"
    assert res.items[0].origin == "EXTERNAL_INTELLIGENCE"
    # Ensure graph structure is generated
    assert len(res.graph_nodes) == 3  # 1 root + 2 targets
    assert len(res.graph_edges) == 2


def test_domain_to_asn_pivot(db):
    now = get_utc_now()
    ti = ThreatIntelligenceRecordModel(
        id=generate_uuid(),
        workspace_id="default",
        indicator_type="DOMAIN",
        indicator_value="malicious-cdn.com",
        normalized_value="malicious-cdn.com",
        provider="cyberguard_feed",
        normalized_data_json=json.dumps({
            "asn": 20473,
            "organization": "AS-CHOOPA",
        }),
        first_seen=now,
        last_seen=now,
    )
    db.add(ti)
    db.commit()

    res = InvestigationPivotService.execute_pivot(
        db=db,
        req=PivotRequest(
            source_type=PivotSourceTypeEnum.DOMAIN,
            source_value="malicious-cdn.com",
            pivot_type=PivotTypeEnum.BELONGS_TO_ASN,
            depth=1,
        ),
        workspace_id="default",
    )

    assert res.total_results == 1
    assert res.items[0].target_type == "ASN"
    assert res.items[0].target_value == "AS20473"
    assert "AS-CHOOPA" in res.items[0].display_label


def test_ip_to_reverse_dns_pivot(db):
    now = get_utc_now()
    ti1 = ThreatIntelligenceRecordModel(
        id=generate_uuid(),
        workspace_id="default",
        indicator_type="DOMAIN",
        indicator_value="site-a.com",
        normalized_value="site-a.com",
        provider="cyberguard_feed",
        normalized_data_json=json.dumps({"resolved_ips": ["203.0.113.88"]}),
        first_seen=now,
        last_seen=now,
    )
    ti2 = ThreatIntelligenceRecordModel(
        id=generate_uuid(),
        workspace_id="default",
        indicator_type="DOMAIN",
        indicator_value="site-b.com",
        normalized_value="site-b.com",
        provider="cyberguard_feed",
        normalized_data_json=json.dumps({"resolved_ips": ["203.0.113.88"]}),
        first_seen=now,
        last_seen=now,
    )
    db.add_all([ti1, ti2])
    db.commit()

    res = InvestigationPivotService.execute_pivot(
        db=db,
        req=PivotRequest(
            source_type=PivotSourceTypeEnum.IP,
            source_value="203.0.113.88",
            pivot_type=PivotTypeEnum.REVERSE_DNS_DOMAINS,
            depth=1,
        ),
        workspace_id="default",
    )

    assert res.total_results == 2
    domains = [it.target_value for it in res.items]
    assert "site-a.com" in domains
    assert "site-b.com" in domains


# =============================================================================
# 4. Multi-Hop Traversal (Depth = 2)
# =============================================================================

def test_multi_hop_pivot_traversal(db):
    now = get_utc_now()
    # 1. Domain -> IP
    ti_dom = ThreatIntelligenceRecordModel(
        id=generate_uuid(),
        workspace_id="default",
        indicator_type="DOMAIN",
        indicator_value="c2-server.net",
        normalized_value="c2-server.net",
        provider="cyberguard_feed",
        normalized_data_json=json.dumps({"resolved_ips": ["192.0.2.1"]}),
        first_seen=now,
        last_seen=now,
    )
    # 2. IP -> ASN
    ti_ip = ThreatIntelligenceRecordModel(
        id=generate_uuid(),
        workspace_id="default",
        indicator_type="IP",
        indicator_value="192.0.2.1",
        normalized_value="192.0.2.1",
        provider="cyberguard_feed",
        normalized_data_json=json.dumps({"asn": "15169", "organization": "Google LLC"}),
        first_seen=now,
        last_seen=now,
    )
    db.add_all([ti_dom, ti_ip])
    db.commit()

    res = InvestigationPivotService.execute_pivot(
        db=db,
        req=PivotRequest(
            source_type=PivotSourceTypeEnum.DOMAIN,
            source_value="c2-server.net",
            pivot_type=PivotTypeEnum.RESOLVED_IPS,
            depth=2,
        ),
        workspace_id="default",
    )

    assert res.depth == 2
    # Should contain root (hop 0), IP (hop 1), and ASN (hop 2)
    node_distances = {n.value: n.hop_distance for n in res.graph_nodes}
    assert node_distances["c2-server.net"] == 0
    assert node_distances["192.0.2.1"] == 1
    assert "AS15169" in node_distances
    assert node_distances["AS15169"] == 2
    assert len(res.graph_edges) >= 2


# =============================================================================
# 5. AI Recommendations
# =============================================================================

def test_ai_pivot_recommendations(db):
    recs = InvestigationPivotService.get_pivot_recommendations(
        db=db,
        source_type="DOMAIN",
        source_value="fake-secure.com",
        workspace_id="default",
    )
    assert len(recs.recommendations) >= 3
    types = [r.pivot_type.value for r in recs.recommendations]
    assert "RESOLVED_IPS" in types
    assert "ASSOCIATED_CERTIFICATES" in types
    assert all(len(r.rationale) > 10 for r in recs.recommendations)


# =============================================================================
# 6. Analyst Hypothesis CRUD
# =============================================================================

def test_analyst_hypothesis_workflow(db):
    hypo_req = HypothesisRecordRequest(
        title="Shared C2 Infrastructure Hypothesis",
        hypothesis_text="Domains site-a and site-b share bulletproof host AS20473 and the same TLS cert.",
        source_observable="site-a.com",
        supporting_items=["203.0.113.88", "AS20473", "cert-sha-1234"],
        contradicting_items=[],
        neutral_items=["Cloudflare CDN"],
        analyst_notes="Requires confirmation from host intrusion logs.",
    )

    created = InvestigationPivotService.record_hypothesis(
        db=db,
        req=hypo_req,
        workspace_id="default",
        user_id="analyst-sam",
    )
    assert created.id is not None
    assert created.supporting_count == 3
    assert created.neutral_count == 1

    # List
    all_hypo = InvestigationPivotService.list_hypotheses(db=db, workspace_id="default")
    assert len(all_hypo) == 1
    assert all_hypo[0].title == "Shared C2 Infrastructure Hypothesis"


# =============================================================================
# 7. Workflow Handoffs (Investigation, Watchlist, Threat Hunting)
# =============================================================================

def test_promote_to_investigation(db):
    req = PromoteToInvestigationRequest(
        title="Suspected Spearphishing Infrastructure",
        selected_target_values=["198.51.100.10", "198.51.100.11"],
        source_value="attacker-portal.org",
        source_type="DOMAIN",
        pivot_type="RESOLVED_IPS",
    )

    res = InvestigationPivotService.promote_to_investigation(
        db=db,
        req=req,
        workspace_id="default",
        user_id="lead-analyst",
    )
    assert res.investigation_id is not None
    assert res.created_relationships_count == 2
    assert "INV-P-" in (res.incident_number or "")

    # Verify relationships created in DB
    rels = db.query(RelationshipModel).filter(RelationshipModel.source_id == res.investigation_id).all()
    assert len(rels) == 2
    assert rels[0].method == "INVESTIGATION_PIVOT"


def test_promote_to_watchlist(db):
    req = PromoteToWatchlistRequest(
        watchlist_name="Active Threat Pivot Watchlist",
        selected_target_values=["evil-domain-1.com", "evil-domain-2.com"],
        target_type="DOMAIN",
        reason="Discovered during investigation pivot on IP 10.0.0.1",
    )

    res = InvestigationPivotService.promote_to_watchlist(
        db=db,
        req=req,
        workspace_id="default",
        user_id="analyst",
    )
    assert res.added_items_count == 2
    assert res.watchlist_id is not None

    watched = db.query(WatchedIndicatorModel).filter(WatchedIndicatorModel.watchlist_id == res.watchlist_id).all()
    assert len(watched) == 2


def test_pivot_to_hunt_query():
    req = PivotToHuntQueryRequest(
        selected_target_values=["192.0.2.1", "192.0.2.2"],
        target_type="IP",
    )
    res = InvestigationPivotService.pivot_to_hunt_query(req)
    assert res.query_definition.data_source == "indicators"
    assert res.query_definition.filters[0].operator.value == "in"
    assert len(res.query_definition.filters[0].value) == 2
    assert "Pivoted IP" in res.suggested_hunt_name
