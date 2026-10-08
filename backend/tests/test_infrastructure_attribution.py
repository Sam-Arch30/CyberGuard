"""
Core Functional Test Suite for Section 20:
Probable Origin Infrastructure & Threat Infrastructure Attribution Engine.
Covers Direct Infrastructure, Relationships, Clustering, Temporal Transitions,
Confidence Breakdown, Ambiguity Controls, Privacy Safeguards, and the Synthetic End-to-End Scenario.
"""
import json
import pytest
from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.db.models import (
    Base,
    IncidentModel,
    SecurityEventModel,
    ThreatEventModel,
    FindingModel,
    EntityModel,
    RelationshipModel,
    CampaignModel,
    InfrastructureAttributionModel,
    InfrastructureClusterModel,
    generate_uuid,
    get_utc_now,
)
from backend.schemas.attack_confidence import ConfidenceLevel
from backend.schemas.infrastructure_attribution import (
    OriginType,
    InfrastructureRole,
    InfrastructureDirection,
    AttributionStatus,
    AttributionHypothesisType,
    EvidenceFamily,
    SupportDirection,
    InfrastructureCandidate,
    FORENSIC_INFRASTRUCTURE_DISCLAIMER,
)
from backend.services.infrastructure_candidate_generator import InfrastructureCandidateGenerator
from backend.services.infrastructure_clusterer import InfrastructureClusterer
from backend.services.infrastructure_temporal_analyzer import InfrastructureTemporalAnalyzer
from backend.services.infrastructure_attribution_engine import InfrastructureAttributionEngine
from backend.services.ip_cache import global_ip_cache
from backend.schemas.ip_intelligence import IPIntelligence


@pytest.fixture
def db_session():
    """Isolated in-memory SQLite database session for unit testing."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


@pytest.fixture
def engine_service():
    """Initializes InfrastructureAttributionEngine."""
    return InfrastructureAttributionEngine()


# ============================================================================
# 1. DIRECT INFRASTRUCTURE EXTRACTION TESTS
# ============================================================================

def test_01_observed_ip_extraction(db_session, engine_service):
    """Verifies public observed source IP is harvested from security events."""
    inc = IncidentModel(
        id="INC-TEST-001",
        incident_number="INC-2026-0001",
        title="Brute Force Alert",
        workspace_id="default",
    )
    db_session.add(inc)

    se = SecurityEventModel(
        id="SE-001",
        incident_id=inc.id,
        workspace_id="default",
        event_type="AUTHENTICATION",
        source_type="AUTH_LOG",
        event_time=get_utc_now(),
        attributes_json=json.dumps({"source_ip": "198.51.100.25", "account": "admin@example.com"}),
    )
    db_session.add(se)
    db_session.commit()

    obs, assoc = engine_service.candidate_generator.generate_candidates(db_session, inc)
    assert len(obs) >= 1
    cand = next((c for c in obs if c.value == "198.51.100.25"), None)
    assert cand is not None
    assert cand.entity_type == "IP"
    assert cand.role == InfrastructureRole.ORIGIN_CANDIDATE
    assert cand.direction == InfrastructureDirection.OBSERVED_SOURCE
    assert cand.is_observed is True


def test_02_observed_destination_and_domain_extraction(db_session, engine_service):
    """Verifies observed destination server and domain are captured with destination direction."""
    inc = IncidentModel(id="INC-TEST-002", incident_number="INC-2026-0002", title="C2 Callback", workspace_id="default")
    db_session.add(inc)

    se = SecurityEventModel(
        id="SE-002",
        incident_id=inc.id,
        workspace_id="default",
        event_type="NETWORK_TRAFFIC",
        source_type="ZEEK_CONN",
        event_time=get_utc_now(),
        attributes_json=json.dumps({"destination_ip": "203.0.113.88", "domain": "malicious-c2.test"}),
    )
    db_session.add(se)
    db_session.commit()

    obs, assoc = engine_service.candidate_generator.generate_candidates(db_session, inc)
    ip_cand = next((c for c in obs if c.value == "203.0.113.88"), None)
    dom_cand = next((c for c in obs if c.value == "malicious-c2.test"), None)

    assert ip_cand is not None
    assert ip_cand.direction == InfrastructureDirection.OBSERVED_DESTINATION
    assert dom_cand is not None
    assert dom_cand.entity_type == "DOMAIN"
    assert dom_cand.role == InfrastructureRole.HOSTING_INFRASTRUCTURE


def test_03_observed_mail_relay_extraction(db_session, engine_service):
    """Verifies email relay IP extracted from findings is classified as MAIL_RELAY."""
    inc = IncidentModel(id="INC-TEST-003", incident_number="INC-2026-0003", title="Phishing Mail", workspace_id="default")
    db_session.add(inc)

    f = FindingModel(
        id="FIND-001",
        analysis_run_id="ANALYSIS-001",
        analyzer="EMAIL_ANALYZER",
        finding_type="SUSPICIOUS_RELAY",
        title="Suspicious Relay",
        description="External untrusted relay observed",
        severity="HIGH",
        method="RULE",
        metadata_json=json.dumps({"relay_ip": "198.51.100.99", "sender_domain": "spoofed-corp.test"}),
    )
    db_session.add(f)

    # Link finding via analysis_run_id on ThreatEventModel
    te = ThreatEventModel(
        id="TE-001",
        incident_id=inc.id,
        analysis_run_id="ANALYSIS-001",
        event_type="PHISHING_DELIVERY",
        summary="Phishing email delivered",
        metadata_json=json.dumps({"ip": "198.51.100.99"}),
    )
    db_session.add(te)
    db_session.commit()

    obs, assoc = engine_service.candidate_generator.generate_candidates(db_session, inc)
    relay_cand = next((c for c in obs if c.value == "198.51.100.99"), None)
    assert relay_cand is not None
    assert relay_cand.role == InfrastructureRole.MAIL_RELAY
    assert relay_cand.direction == InfrastructureDirection.RELAY_INFRASTRUCTURE


# ============================================================================
# 2. KNOWLEDGE GRAPH INFRASTRUCTURE RELATIONSHIPS
# ============================================================================

def test_04_domain_resolves_to_ip_and_asn_relationship(db_session, engine_service):
    """Verifies graph traversal from observed domain to associated IP and ASN."""
    inc = IncidentModel(id="INC-TEST-004", incident_number="INC-2026-0004", title="Web Threat", workspace_id="default")
    db_session.add(inc)

    se = SecurityEventModel(
        id="SE-004",
        incident_id=inc.id,
        workspace_id="default",
        event_type="DNS_QUERY",
        source_type="DNS",
        event_time=get_utc_now(),
        attributes_json=json.dumps({"domain": "phish-portal.test"}),
    )
    db_session.add(se)

    # Knowledge graph nodes and edges
    ent_dom = EntityModel(id="ent-phish", name="phish-portal.test", entity_type="DOMAIN", canonical_key="domain:phish-portal.test")
    ent_ip = EntityModel(id="ent-ip", name="203.0.113.50", entity_type="IP", canonical_key="ip:203.0.113.50")
    ent_asn = EntityModel(id="ent-asn", name="AS64512", entity_type="ASN", canonical_key="asn:AS64512")
    db_session.add_all([ent_dom, ent_ip, ent_asn])

    rel1 = RelationshipModel(id="rel-1", source_type="DOMAIN", source_id="domain:phish-portal.test", target_type="IP", target_id="ip:203.0.113.50", relationship_type="RESOLVES_TO")
    rel2 = RelationshipModel(id="rel-2", source_type="IP", source_id="ip:203.0.113.50", target_type="ASN", target_id="asn:AS64512", relationship_type="BELONGS_TO")
    db_session.add_all([rel1, rel2])
    db_session.commit()

    obs, assoc = engine_service.candidate_generator.generate_candidates(db_session, inc)
    assoc_vals = [a.value for a in assoc]
    assert "203.0.113.50" in assoc_vals or "ent-ip" in str(assoc_vals)
    assert "AS64512" in assoc_vals or "ent-asn" in str(assoc_vals)


# ============================================================================
# 3. CLUSTERING LOGIC
# ============================================================================

def test_05_shared_dedicated_ip_clustering(db_session, engine_service):
    """Verifies that multiple domains pointing to the same non-cloud IP form a hosting cluster."""
    candidates = [
        InfrastructureCandidate(
            id="c1",
            entity_type="IP",
            canonical_key="ip:203.0.113.10",
            value="203.0.113.10",
            role=InfrastructureRole.HOSTING_INFRASTRUCTURE,
            direction=InfrastructureDirection.INFRASTRUCTURE_ENDPOINT,
            is_observed=True,
            is_direct=True,
            is_shared_infrastructure=False,
            is_cloud_provider=False,
            is_cdn=False,
            evidence_refs=["ev-1"],
        ),
        InfrastructureCandidate(
            id="c2",
            entity_type="DOMAIN",
            canonical_key="domain:login-fake.test",
            value="login-fake.test",
            role=InfrastructureRole.HOSTING_INFRASTRUCTURE,
            direction=InfrastructureDirection.INFRASTRUCTURE_ENDPOINT,
            is_observed=True,
            is_direct=True,
            evidence_refs=["203.0.113.10", "ev-2"],
        ),
        InfrastructureCandidate(
            id="c3",
            entity_type="DOMAIN",
            canonical_key="domain:portal-secure.test",
            value="portal-secure.test",
            role=InfrastructureRole.HOSTING_INFRASTRUCTURE,
            direction=InfrastructureDirection.INFRASTRUCTURE_ENDPOINT,
            is_observed=True,
            is_direct=True,
            evidence_refs=["203.0.113.10", "ev-3"],
        ),
    ]

    clusterer = InfrastructureClusterer()
    clusters = clusterer.cluster_infrastructure(candidates, "INC-001")
    assert len(clusters) >= 1
    cl = clusters[0]
    assert "203.0.113.10" in cl.name
    assert len(cl.members) >= 2
    assert cl.confidence >= 0.70


def test_06_generic_cloud_suppression_in_clustering(db_session, engine_service):
    """Verifies that generic cloud providers (AWS, Cloudflare) do NOT form dedicated malicious clusters on their own."""
    candidates = [
        InfrastructureCandidate(
            id="c1",
            entity_type="IP",
            canonical_key="ip:104.21.10.5",
            value="104.21.10.5",
            role=InfrastructureRole.HOSTING_INFRASTRUCTURE,
            direction=InfrastructureDirection.INFRASTRUCTURE_ENDPOINT,
            is_observed=True,
            is_direct=True,
            is_shared_infrastructure=True,
            is_cloud_provider=True,
            is_cdn=True,
            asn="AS13335",
            hosting_provider="Cloudflare",
            evidence_refs=["ev-1"],
        ),
    ]

    clusterer = InfrastructureClusterer()
    clusters = clusterer.cluster_infrastructure(candidates, "INC-002")
    # Should not produce a false dedicated hosting cluster for Cloudflare
    for cl in clusters:
        assert "Dedicated" not in cl.name
        assert cl.confidence < 0.70


def test_07_campaign_linked_clustering(db_session, engine_service):
    """Verifies that candidates linked to a shared campaign are clustered together with high confidence."""
    candidates = [
        InfrastructureCandidate(
            id="c1",
            entity_type="IP",
            canonical_key="ip:198.51.100.1",
            value="198.51.100.1",
            role=InfrastructureRole.ORIGIN_CANDIDATE,
            direction=InfrastructureDirection.OBSERVED_SOURCE,
            is_observed=True,
            is_direct=True,
            campaign_ids=["CAMP-FIN-2026"],
            evidence_refs=["ev-1"],
        ),
        InfrastructureCandidate(
            id="c2",
            entity_type="DOMAIN",
            canonical_key="domain:banking-auth.test",
            value="banking-auth.test",
            role=InfrastructureRole.HOSTING_INFRASTRUCTURE,
            direction=InfrastructureDirection.INFRASTRUCTURE_ENDPOINT,
            is_observed=True,
            is_direct=True,
            campaign_ids=["CAMP-FIN-2026"],
            evidence_refs=["ev-2"],
        ),
    ]

    clusterer = InfrastructureClusterer()
    clusters = clusterer.cluster_infrastructure(candidates, "INC-003")
    assert len(clusters) == 1
    assert "CAMP-FIN-2026" in clusters[0].name
    assert clusters[0].campaign_count == 1
    assert clusters[0].confidence >= 0.80


# ============================================================================
# 4. TEMPORAL ANALYSIS & INFRASTRUCTURE MIGRATION
# ============================================================================

def test_08_infrastructure_migration_detection(db_session, engine_service):
    """Verifies that chronological shifts in domain IP resolution are flagged as INFRASTRUCTURE_MIGRATION."""
    inc = IncidentModel(id="INC-TEST-008", incident_number="INC-2026-0008", title="Rotating C2", workspace_id="default")
    db_session.add(inc)

    t0 = datetime(2026, 10, 1, 12, 0, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 10, 5, 12, 0, 0, tzinfo=timezone.utc)

    # Add historical relationships in knowledge graph
    rel1 = RelationshipModel(id="rel-t1", source_type="DOMAIN", source_id="domain:fast-flux.test", target_type="IP", target_id="ip:203.0.113.10", relationship_type="RESOLVES_TO", created_at=t0)
    rel2 = RelationshipModel(id="rel-t2", source_type="DOMAIN", source_id="domain:fast-flux.test", target_type="IP", target_id="ip:203.0.113.20", relationship_type="RESOLVES_TO", created_at=t1)
    db_session.add_all([rel1, rel2])
    db_session.commit()

    candidates = [
        InfrastructureCandidate(
            id="cand-dom",
            entity_type="DOMAIN",
            canonical_key="domain:fast-flux.test",
            value="fast-flux.test",
            role=InfrastructureRole.HOSTING_INFRASTRUCTURE,
            direction=InfrastructureDirection.INFRASTRUCTURE_ENDPOINT,
            is_observed=True,
            is_direct=True,
        )
    ]

    analyzer = InfrastructureTemporalAnalyzer()
    timeline = analyzer.analyze_timeline(db_session, inc, candidates)

    mig_events = [e for e in timeline if e.event_type == "INFRASTRUCTURE_MIGRATION"]
    assert len(mig_events) >= 1
    assert mig_events[0].is_migration is True
    assert "203.0.113.20" in mig_events[0].description


# ============================================================================
# 5. CONFIDENCE BREAKDOWN & EVIDENCE INDEPENDENCE
# ============================================================================

def test_09_confidence_penalties_for_shared_hosting_and_cdn(db_session, engine_service):
    """Verifies that shared hosting or CDN presence applies negative penalties to candidate ranking."""
    cand_dedicated = InfrastructureCandidate(
        id="c_ded",
        entity_type="IP",
        canonical_key="ip:198.51.100.10",
        value="198.51.100.10",
        role=InfrastructureRole.ORIGIN_CANDIDATE,
        direction=InfrastructureDirection.OBSERVED_SOURCE,
        is_observed=True,
        is_direct=True,
        is_shared_infrastructure=False,
        evidence_refs=["ev-1", "ev-2"],
    )

    cand_shared = InfrastructureCandidate(
        id="c_shared",
        entity_type="IP",
        canonical_key="ip:104.21.5.5",
        value="104.21.5.5",
        role=InfrastructureRole.ORIGIN_CANDIDATE,
        direction=InfrastructureDirection.OBSERVED_SOURCE,
        is_observed=True,
        is_direct=True,
        is_shared_infrastructure=True,
        is_cdn=True,
        evidence_refs=["ev-1", "ev-2"],
    )

    ranked = engine_service._rank_candidates([cand_dedicated, cand_shared])
    assert ranked[0].id == "c_ded"
    assert ranked[0].ranking_score > ranked[1].ranking_score
    assert any("CDN" in lim for lim in ranked[1].limitations)


# ============================================================================
# 6. COMPROMISED HOSTING & COMPETING HYPOTHESES
# ============================================================================

def test_10_competing_hypotheses_preservation(db_session, engine_service):
    """Verifies that engine produces alternative hypotheses (H1, H2, H3) rather than a single forced interpretation."""
    inc = IncidentModel(id="INC-TEST-010", incident_number="INC-2026-0010", title="Suspicious Egress", workspace_id="default")
    db_session.add(inc)

    se = SecurityEventModel(
        id="SE-010",
        incident_id=inc.id,
        workspace_id="default",
        event_type="NETWORK_EGRESS",
        source_type="FIREWALL",
        event_time=get_utc_now(),
        attributes_json=json.dumps({"source_ip": "198.51.100.77"}),
    )
    db_session.add(se)
    db_session.commit()

    resp = engine_service.analyze_incident_infrastructure(db_session, inc.id, persist=False)
    assert resp.primary_hypothesis is not None
    assert len(resp.competing_hypotheses) >= 1
    types = [h.hypothesis_type for h in [resp.primary_hypothesis] + resp.competing_hypotheses]
    assert AttributionHypothesisType.COMPROMISED_HOSTING in types


# ============================================================================
# 7. INSUFFICIENT EVIDENCE VALID FIRST-CLASS RESULT
# ============================================================================

def test_11_insufficient_evidence_when_telemetry_absent(db_session, engine_service):
    """Verifies that an incident with no public telemetry cleanly evaluates to ORIGIN_INSUFFICIENT_EVIDENCE."""
    inc = IncidentModel(id="INC-EMPTY-001", incident_number="INC-2026-EMPTY", title="Internal Only Alert", workspace_id="default")
    db_session.add(inc)
    db_session.commit()

    resp = engine_service.analyze_incident_infrastructure(db_session, inc.id, persist=False)
    assert resp.primary_hypothesis is not None
    assert resp.primary_hypothesis.hypothesis_type == AttributionHypothesisType.ORIGIN_INSUFFICIENT_EVIDENCE
    assert resp.primary_hypothesis.status == AttributionStatus.INSUFFICIENT_EVIDENCE
    assert "could not establish a reliable infrastructure-origin hypothesis" in resp.primary_hypothesis.hypothesis


# ============================================================================
# 8. SYNTHETIC END-TO-END SCENARIO (SECTION 38)
# ============================================================================

def test_12_synthetic_end_to_end_scenario(db_session, engine_service):
    """
    Scenario from Prompt Section 38:
    Phishing Email -> https://login-example.test -> lookalike domain -> 203.0.113.10
    -> ASN TEST-ASN -> previous synthetic incident -> same infrastructure cluster.
    """
    # 1. Previous historical incident
    past_inc = IncidentModel(id="INC-SYNTH-HIST", incident_number="INC-2026-HIST01", title="Past Phishing Campaign", workspace_id="default")
    db_session.add(past_inc)
    past_te = ThreatEventModel(
        id="TE-HIST-001",
        incident_id=past_inc.id,
        event_type="PHISHING_DELIVERY",
        summary="Historical campaign node 203.0.113.10 observed",
        metadata_json=json.dumps({"ip": "203.0.113.10"}),
    )
    db_session.add(past_te)

    # 2. Target incident
    inc = IncidentModel(id="INC-SYNTH-TARGET", incident_number="INC-2026-TARGET", title="Active Phishing Campaign", workspace_id="default")
    db_session.add(inc)

    # Direct telemetry in target incident
    se1 = SecurityEventModel(
        id="SE-TARGET-001",
        incident_id=inc.id,
        workspace_id="default",
        event_type="EMAIL_INGEST",
        source_type="EMAIL_GATEWAY",
        event_time=get_utc_now(),
        attributes_json=json.dumps({"domain": "login-example.test", "source_ip": "203.0.113.10"}),
    )
    db_session.add(se1)

    # Mock IP cache enrichment
    global_ip_cache.set(
        "203.0.113.10",
        IPIntelligence(
            ip="203.0.113.10",
            asn="AS64512",
            asn_org="TEST-ASN Hosting Network",
            country="Netherlands",
            country_code="NL",
            city="Amsterdam",
            isp="TEST-ASN Hosting Network",
            is_hosting=False,
            is_proxy_vpn_tor=False,
        )
    )

    db_session.commit()

    resp = engine_service.analyze_incident_infrastructure(db_session, inc.id, persist=True)

    # Verify observed infrastructure
    obs_vals = [o.value for o in resp.observed_infrastructure]
    assert "203.0.113.10" in obs_vals
    assert "login-example.test" in obs_vals

    # Verify probable origin infrastructure
    assert resp.primary_hypothesis is not None
    assert "203.0.113.10" in resp.primary_hypothesis.origin_value
    assert resp.primary_hypothesis.confidence_level in (ConfidenceLevel.VERY_HIGH, ConfidenceLevel.HIGH, ConfidenceLevel.MODERATE)

    # Verify historical association is captured
    cand_ip = next(c for c in resp.observed_infrastructure if c.value == "203.0.113.10")
    assert "INC-SYNTH-HIST" in cand_ip.historical_incident_ids

    # Verify forensic disclaimer is present
    assert resp.disclaimer == FORENSIC_INFRASTRUCTURE_DISCLAIMER
    assert any("does not establish human identity" in lim for lim in resp.limitations)
    assert any("server facility geography" in lim for lim in resp.primary_hypothesis.limitations)

    # Verify DB persistence
    persisted_attr = db_session.query(InfrastructureAttributionModel).filter_by(incident_id=inc.id).first()
    assert persisted_attr is not None
    assert "203.0.113.10" in persisted_attr.origin_value
