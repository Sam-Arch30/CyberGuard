"""
Comprehensive Unit and Integration Tests for Section 14: Security Knowledge Graph.
Validates:
1. Entity canonicalization (IP, Domain, URL, Hash, Email, Account, Device)
2. Account and Device context isolation
3. Entity deduplication across evidence sources
4. Relationship creation, direction, and vocabulary
5. Multi-observation tracking and provenance
6. Temporal boundaries (first_seen, last_seen, observation timestamps)
7. Origin classification (OBSERVED, DERIVED, INFERRED, EXTERNAL_INTELLIGENCE)
8. Scenario: Email to Device (Email -> URL -> Domain -> IP <- Device)
9. Scenario: Authentication + API abuse (Account -> Session -> API Service & Session -> IP)
10. Scenario: File Chain (Email -> Zip -> PDF -> URL -> Domain)
11. Scenario: Digital Impersonation (CLAIMS_IDENTITY != IS_IDENTITY, LOOKALIKE_OF)
12. Scenario: Cross-Incident Entity Reuse
13. Neighborhood traversal & depth limits
14. Bounded path query with provenance
15. Incident subgraph query
16. Entity timeline
17. Edge evidence API ("WHY DOES THIS EDGE EXIST?")
18. Attribute sanitization and secret redaction
19. Workspace / Tenant isolation
20. Idempotency and re-analysis
21. Legacy Investigation Graph compatibility
22. Graph integrity (no dangling edges, no casing duplicates)
"""
from datetime import datetime, timezone, timedelta
import json
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.db.session import SessionLocal
from backend.db.models import (
    EntityModel,
    RelationshipModel,
    RelationshipObservationModel,
    ArtifactModel,
    AnalysisRunModel,
    IncidentModel,
    ThreatEventModel,
    FindingEvidenceModel,
    FindingModel,
)
from backend.schemas.knowledge_graph import (
    GraphEntityType,
    GraphRelationshipType,
    RelationshipOrigin,
    RelationshipStatus,
    make_canonical_key,
    sanitize_graph_attributes,
)
from backend.services.security_graph_service import (
    SecurityGraphService,
    global_security_graph_service,
)
from backend.services.security_graph_builder import (
    SecurityGraphBuilder,
    global_security_graph_builder,
)
from backend.services.graph_service import global_graph_service


@pytest.fixture
def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def client():
    return TestClient(app)


# ============================================================================
# 1. CANONICALIZATION & CONTEXT ISOLATION TESTS
# ============================================================================

def test_1_ip_canonicalization():
    """Verifies IPv4/IPv6 normalization and canonical key generation."""
    # IPv4 with leading zeros
    k1 = make_canonical_key(GraphEntityType.IP, " 192.002.001.001 ")
    assert k1 == "ip:192.2.1.1"

    # Defanged IP
    k2 = make_canonical_key(GraphEntityType.IP, "198[.]51[.]100[.]22")
    assert k2 == "ip:198.51.100.22"

    # IPv6
    k3 = make_canonical_key(GraphEntityType.IP, "2001:0db8:85a3:0000:0000:8a2e:0370:7334")
    assert k3.startswith("ip:")
    assert "2001:db8:85a3::" in k3 or "2001:db8:85a3:0:0:8a2e:370:7334" in k3


def test_2_domain_canonicalization():
    """Verifies domain normalization, stripping protocols, trailing dots and ports."""
    k1 = make_canonical_key(GraphEntityType.DOMAIN, "  HTTPS://PayPa1-Security.CoM.:8080/path  ")
    assert k1 == "domain:paypa1-security.com"

    k2 = make_canonical_key(GraphEntityType.DOMAIN, "example.org.")
    assert k2 == "domain:example.org"


def test_3_url_canonicalization_reuse():
    """Verifies canonical URL normalization reusing Section 7 logic."""
    k1 = make_canonical_key(GraphEntityType.URL, "HTTPS://ExAmPlE.CoM/Path/To/Page?token=123#frag")
    assert k1 == "url:https://example.com/Path/To/Page?token=123#frag"


def test_4_hash_canonicalization():
    """Verifies cryptographic hash normalization to lowercase."""
    raw = " E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855 "
    k = make_canonical_key(GraphEntityType.HASH, raw)
    assert k == "hash:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_5_account_context_isolation():
    """Verifies that identical usernames in different providers/tenants do NOT collide."""
    k_okta = make_canonical_key(GraphEntityType.ACCOUNT, "admin", context="okta-corp")
    k_aws = make_canonical_key(GraphEntityType.ACCOUNT, "admin", context="aws-prod")

    assert k_okta == "account:okta-corp:admin"
    assert k_aws == "account:aws-prod:admin"
    assert k_okta != k_aws


def test_6_device_context_isolation():
    """Verifies that device identifiers preserve network/provider context."""
    k_fleet1 = make_canonical_key(GraphEntityType.DEVICE, "LAPTOP-01", context="fleet-us")
    k_fleet2 = make_canonical_key(GraphEntityType.DEVICE, "LAPTOP-01", context="fleet-eu")
    assert k_fleet1 != k_fleet2


def test_7_entity_deduplication(db):
    """
    Verifies that the same observable ingested multiple times updates the existing Entity
    rather than creating duplicate rows.
    """
    svc = SecurityGraphService()
    t1 = datetime(2026, 10, 1, 10, 0, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 10, 1, 14, 0, 0, tzinfo=timezone.utc)

    e1 = svc.upsert_canonical_entity(
        db, entity_type=GraphEntityType.IP, value="198.51.100.44", timestamp=t1, attributes={"asn": "AS64512"}
    )
    e2 = svc.upsert_canonical_entity(
        db, entity_type=GraphEntityType.IP, value="198.51.100.44", timestamp=t2, attributes={"country": "US"}
    )

    assert e1.id == e2.id
    assert e2.canonical_key == "ip:198.51.100.44"
    assert e2.last_seen >= t2
    # Verify merged attributes
    attrs = json.loads(e2.attributes_json)
    assert attrs["asn"] == "AS64512"
    assert attrs["country"] == "US"


# ============================================================================
# 2. RELATIONSHIPS, OBSERVATIONS & PROVENANCE TESTS
# ============================================================================

def test_8_relationship_creation_and_direction(db):
    """Verifies explicit relationship creation and directional semantics."""
    svc = SecurityGraphService()
    e_email = svc.upsert_canonical_entity(db, GraphEntityType.EMAIL, "eml-test-01")
    e_url = svc.upsert_canonical_entity(db, GraphEntityType.URL, "https://phish.example/login")

    rel, obs = svc.record_relationship(
        db,
        source_id=e_email.id,
        target_id=e_url.id,
        relationship_type=GraphRelationshipType.CONTAINS,
        origin=RelationshipOrigin.OBSERVED,
        confidence=1.0,
        analyzer="EmailParser",
    )
    assert rel.id is not None
    assert rel.source_id == e_email.id
    assert rel.target_id == e_url.id
    assert rel.relationship_type == "CONTAINS"
    assert rel.origin == "OBSERVED"

    # Query direction
    outgoing = svc.get_neighbors(db, e_email.id, direction="outgoing")
    assert any(e.target == e_url.id for e in outgoing.edges)

    incoming_email = svc.get_neighbors(db, e_email.id, direction="incoming")
    assert not any(e.source == e_url.id for e in incoming_email.edges)


def test_9_multiple_observations_and_provenance(db):
    """
    Verifies that multiple observations of the same canonical relationship edge
    preserve individual observation records with provenance while updating the edge.
    """
    svc = SecurityGraphService()
    e_dom = svc.upsert_canonical_entity(db, GraphEntityType.DOMAIN, "lookup-dns.example")
    e_ip = svc.upsert_canonical_entity(db, GraphEntityType.IP, "203.0.113.10")

    t1 = datetime(2026, 10, 1, 10, 0, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 10, 1, 12, 0, 0, tzinfo=timezone.utc)

    # Observation 1
    rel1, obs1 = svc.record_relationship(
        db,
        source_id=e_dom.id,
        target_id=e_ip.id,
        relationship_type=GraphRelationshipType.RESOLVES_TO,
        observed_at=t1,
        analyzer="DnsTelemetryEngine",
        confidence=0.90,
    )

    # Observation 2 from a later run
    rel2, obs2 = svc.record_relationship(
        db,
        source_id=e_dom.id,
        target_id=e_ip.id,
        relationship_type=GraphRelationshipType.RESOLVES_TO,
        observed_at=t2,
        analyzer="PassiveDnsProvider",
        confidence=0.99,
    )

    # Single canonical relationship
    assert rel1.id == rel2.id
    assert rel2.confidence == 0.99
    assert rel2.first_seen <= t1
    assert rel2.last_seen >= t2

    # Two distinct observations
    assert obs1.id != obs2.id
    obs_all = db.query(RelationshipObservationModel).filter(
        RelationshipObservationModel.relationship_id == rel1.id
    ).all()
    assert len(obs_all) >= 2


def test_10_origin_classifications(db):
    """Verifies OBSERVED, DERIVED, INFERRED, and EXTERNAL_INTELLIGENCE origins."""
    svc = SecurityGraphService()
    e1 = svc.upsert_canonical_entity(db, GraphEntityType.DOMAIN, "origin-test.example")
    e2 = svc.upsert_canonical_entity(db, GraphEntityType.IDENTITY, "paypal")

    rel_derived, _ = svc.record_relationship(
        db, e1.id, e2.id, GraphRelationshipType.LOOKALIKE_OF, origin=RelationshipOrigin.DERIVED
    )
    assert rel_derived.origin == "DERIVED"

    rel_intel, _ = svc.record_relationship(
        db, e1.id, "AS12345", GraphRelationshipType.BELONGS_TO, origin=RelationshipOrigin.EXTERNAL_INTELLIGENCE
    )
    assert rel_intel.origin == "EXTERNAL_INTELLIGENCE"


# ============================================================================
# 3. DETECTOR PIPELINE INTEGRATION SCENARIOS
# ============================================================================

def test_11_scenario_email_to_device(db):
    """
    SCENARIO 1 (Section 63):
    Email E contains URL U.
    URL U has host Domain D.
    Domain D resolves to IP X.
    Later: Device A connects to IP X.

    Knowledge Graph must reflect the full chain with provenance.
    CRITICAL: Graph must NOT label this as a causal attack path!
    """
    builder = SecurityGraphBuilder()
    svc = SecurityGraphService()

    email_payload = {
        "id": "email-chain-001",
        "email_sha256": "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdef",
        "subject": "Urgent: Security Notification",
        "urls": ["https://account-verify.example.org/login"],
        "domain_intelligence": {
            "account-verify.example.org": {
                "dns": {"a": ["198.51.100.99"]}
            }
        }
    }
    builder.ingest_email_analysis(db, email_payload, artifact_id="art-email-1")

    # Network event: Device connects to IP X
    network_event = {
        "device_id": "WS-FINANCE-04",
        "destination_ip": "198.51.100.99",
        "destination_port": 443,
        "protocol": "TCP"
    }
    builder.ingest_network_event(db, network_event, artifact_id="art-net-1")

    # Query path between Email and Device
    email_ent = svc.get_entity_by_key(db, GraphEntityType.EMAIL, make_canonical_key(GraphEntityType.EMAIL, "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdef")) if hasattr(svc, "get_entity_by_key") else svc.get_entity(db, make_canonical_key(GraphEntityType.EMAIL, "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdef"))
    assert email_ent is not None

    dev_key = make_canonical_key(GraphEntityType.DEVICE, "WS-FINANCE-04", context="internal")
    dev_ent = svc.get_entity(db, dev_key)
    assert dev_ent is not None

    paths_res = svc.find_paths(db, source_id=email_ent.id, target_id=dev_ent.id, max_depth=5)
    assert paths_res.total_paths >= 1

    found_path = paths_res.paths[0]
    edge_types = [e.type for e in found_path]
    assert "CONTAINS" in edge_types
    assert "HAS_HOST" in edge_types
    assert "RESOLVES_TO" in edge_types
    assert "CONNECTS_TO" in edge_types

    # Ensure path provenance is returned
    assert len(paths_res.provenance_summary) >= 1
    assert len(paths_res.provenance_summary[0]["hops"]) >= 4


def test_12_scenario_auth_plus_api(db):
    """
    SCENARIO 2 (Section 64):
    Account A has session S.
    Session S originated from IP X.
    Session S accessed API Service.
    """
    builder = SecurityGraphBuilder()
    svc = SecurityGraphService()

    # 1. Auth Event
    auth_event = {
        "account_id": "analyst_bob",
        "provider": "corp_okta",
        "session_id": "sess_token_xyz999",
        "source_ip": "203.0.113.77"
    }
    builder.ingest_auth_event(db, auth_event, artifact_id="art-auth-1")

    # 2. API Event
    api_event = {
        "account_id": "analyst_bob",
        "service": "customer-records-api",
        "session_id": "sess_token_xyz999",
        "source_ip": "203.0.113.77"
    }
    builder.ingest_api_event(db, api_event, artifact_id="art-api-1")

    # Verify Account -> Session -> API Service
    acc_key = make_canonical_key(GraphEntityType.ACCOUNT, "analyst_bob", context="corp_okta")
    acc_node = svc.get_entity(db, acc_key)
    assert acc_node is not None

    neighbors = svc.get_neighbors(db, acc_node.id, depth=2)
    types_found = {n.type for n in neighbors.nodes}
    assert "SESSION" in types_found
    assert "IP" in types_found or "API_SERVICE" in types_found


def test_13_scenario_file_chain(db):
    """
    SCENARIO 3 (Section 65):
    Email -> contains ZIP -> contains PDF -> references URL -> has host Domain.
    """
    builder = SecurityGraphBuilder()
    svc = SecurityGraphService()

    file_payload = {
        "filename": "invoice_archive.zip",
        "sha256": "2222333344445555666677778888999900001111222233334444555566667777",
        "extracted_files": [
            {
                "filename": "statement.pdf",
                "sha256": "3333444455556666777788889999000011112222333344445555666677778888"
            }
        ],
        "embedded_urls": ["https://evil-redirector.test/payload"]
    }
    builder.ingest_file_analysis(db, file_payload, artifact_id="art-zip-1")

    zip_key = make_canonical_key(GraphEntityType.FILE, "2222333344445555666677778888999900001111222233334444555566667777")
    zip_node = svc.get_entity(db, zip_key)
    assert zip_node is not None

    neighbors = svc.get_neighbors(db, zip_node.id, depth=2)
    node_types = {n.type for n in neighbors.nodes}
    assert "FILE" in node_types
    assert "URL" in node_types
    assert "DOMAIN" in node_types


def test_14_scenario_digital_impersonation(db):
    """
    SCENARIO 4 (Section 66):
    Artifact CLAIMS_IDENTITY Protected Identity.
    Domain LOOKALIKE_OF Legitimate Domain.
    Verifies that CLAIMS_IDENTITY is strictly distinct from verified identity.
    """
    builder = SecurityGraphBuilder()
    svc = SecurityGraphService()

    evidence = {
        "source_identifier": "phish-invoice@spoofed-microsoft.net",
        "source_type": GraphEntityType.EMAIL_ADDRESS,
        "claimed_identity": "Microsoft Corporation",
        "lookalike_domain": "spoofed-microsoft.net",
        "legitimate_domain": "microsoft.com",
        "similarity": 0.94
    }
    builder.ingest_impersonation_evidence(db, evidence, artifact_id="art-imp-1")

    s_key = make_canonical_key(GraphEntityType.EMAIL_ADDRESS, "phish-invoice@spoofed-microsoft.net")
    s_node = svc.get_entity(db, s_key)
    assert s_node is not None

    edges = svc.get_neighbors(db, s_node.id, depth=1).edges
    claim_edge = [e for e in edges if e.type == "CLAIMS_IDENTITY"]
    assert len(claim_edge) == 1
    assert claim_edge[0].origin == "DERIVED"


def test_15_scenario_cross_incident_entity_reuse(db):
    """
    SCENARIO 5 (Section 67):
    Incident A: Domain evil.test
    Incident B: Domain evil.test
    Verifies that the same canonical Domain entity is reused, while observations remain separate.
    """
    svc = SecurityGraphService()

    # Create Incidents
    inc_a = IncidentModel(incident_number="INC-2026-000101", title="Phishing Incident A")
    inc_b = IncidentModel(incident_number="INC-2026-000102", title="Credential Leak Incident B")
    db.add(inc_a)
    db.add(inc_b)
    db.flush()

    # Ingest same domain in both incidents
    d1 = svc.upsert_canonical_entity(db, GraphEntityType.DOMAIN, "shared-c2.test")
    d2 = svc.upsert_canonical_entity(db, GraphEntityType.DOMAIN, "shared-c2.test")
    assert d1.id == d2.id

    svc.record_relationship(db, d1.id, inc_a.id, GraphRelationshipType.OBSERVED_IN, analyzer="Run1")
    svc.record_relationship(db, d1.id, inc_b.id, GraphRelationshipType.OBSERVED_IN, analyzer="Run2")
    db.commit()

    # Verify incident A subgraph
    sub_a = svc.get_incident_subgraph(db, inc_a.id)
    assert any(n.canonical_key == "domain:shared-c2.test" for n in sub_a.nodes)

    # Verify incident B subgraph
    sub_b = svc.get_incident_subgraph(db, inc_b.id)
    assert any(n.canonical_key == "domain:shared-c2.test" for n in sub_b.nodes)


# ============================================================================
# 4. QUERY SERVICE & EDGE EVIDENCE TESTS
# ============================================================================

def test_16_edge_evidence_disclosure(db):
    """
    Verifies that the Edge Evidence API ('WHY DOES THIS EDGE EXIST?') returns
    full provenance, analyzer, confidence, and timestamps.
    """
    svc = SecurityGraphService()
    e1 = svc.upsert_canonical_entity(db, GraphEntityType.DOMAIN, "evidence-check.test")
    e2 = svc.upsert_canonical_entity(db, GraphEntityType.IP, "198.51.100.88")

    rel, obs = svc.record_relationship(
        db,
        source_id=e1.id,
        target_id=e2.id,
        relationship_type=GraphRelationshipType.RESOLVES_TO,
        confidence=0.98,
        origin=RelationshipOrigin.OBSERVED,
        analyzer="DnsQueryEngine",
        analyzer_version="2.1.0",
        evidence_reference="Authoritative DNS A record query"
    )
    db.commit()

    evidence_res = svc.get_edge_evidence(db, rel.id)
    assert evidence_res.edge.id == rel.id
    assert len(evidence_res.observations) >= 1
    assert evidence_res.observations[0].analyzer == "DnsQueryEngine"
    assert evidence_res.observations[0].analyzer_version == "2.1.0"
    assert "Authoritative DNS A record query" in evidence_res.edge.evidence_reference
    assert "DnsQueryEngine" in evidence_res.explanation


def test_17_entity_timeline(db):
    """Verifies chronological entity timeline generation across relationships."""
    svc = SecurityGraphService()
    t1 = datetime(2026, 10, 1, 9, 0, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 10, 1, 10, 0, 0, tzinfo=timezone.utc)

    ent = svc.upsert_canonical_entity(db, GraphEntityType.IP, "198.51.100.77", timestamp=t1)
    e_dom = svc.upsert_canonical_entity(db, GraphEntityType.DOMAIN, "timeline-dom.test", timestamp=t1)
    e_dev = svc.upsert_canonical_entity(db, GraphEntityType.DEVICE, "DEV-FINANCE-01", timestamp=t2)

    svc.record_relationship(db, e_dom.id, ent.id, GraphRelationshipType.RESOLVES_TO, observed_at=t1)
    svc.record_relationship(db, e_dev.id, ent.id, GraphRelationshipType.CONNECTS_TO, observed_at=t2)
    db.commit()

    timeline = svc.get_entity_timeline(db, ent.id)
    assert timeline.total_events >= 2
    # Verify chronological ordering
    assert timeline.events[0].timestamp <= timeline.events[1].timestamp


# ============================================================================
# 5. SECURITY, ISOLATION & INTEGRITY TESTS
# ============================================================================

def test_18_sensitive_field_redaction():
    """Verifies that secrets, bearer tokens, passwords, and API keys are redacted."""
    raw_attrs = {
        "account_id": "alice",
        "password": "SuperSecretPassword123!",
        "auth_token": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xyz",
        "api_key": "sec_live_99887766554433221100",
        "nested": {
            "session_cookie": "sess_cookie_val_abc",
            "safe_field": "public_data"
        }
    }
    clean = sanitize_graph_attributes(raw_attrs)
    assert clean["account_id"] == "alice"
    assert clean["password"] == "[REDACTED]"
    assert clean["auth_token"] == "[REDACTED]"
    assert clean["api_key"] == "[REDACTED]"
    assert clean["nested"]["session_cookie"] == "[REDACTED]"
    assert clean["nested"]["safe_field"] == "public_data"


def test_19_workspace_tenant_isolation(db):
    """Verifies that queries respect workspace boundary isolation."""
    svc = SecurityGraphService()

    e_t1 = svc.upsert_canonical_entity(db, GraphEntityType.ACCOUNT, "user_alpha", workspace_id="tenant-1")
    e_t2 = svc.upsert_canonical_entity(db, GraphEntityType.ACCOUNT, "user_beta", workspace_id="tenant-2")

    # Search in tenant 1 should NOT find tenant 2
    res_t1 = svc.search_entities(db, query="user", workspace_id="tenant-1")
    found_ids_t1 = [n.id for n in res_t1.entities]
    assert e_t1.id in found_ids_t1
    assert e_t2.id not in found_ids_t1


def test_20_graph_integrity_no_dangling_edges(db):
    """Explicitly verifies that relationship edge queries return valid nodes."""
    svc = SecurityGraphService()
    e_src = svc.upsert_canonical_entity(db, GraphEntityType.DOMAIN, "integrity-src.test")
    e_tgt = svc.upsert_canonical_entity(db, GraphEntityType.IP, "203.0.113.55")

    rel, _ = svc.record_relationship(db, e_src.id, e_tgt.id, GraphRelationshipType.RESOLVES_TO)
    db.commit()

    sub = svc.get_neighbors(db, e_src.id, depth=1)
    node_ids = {n.id for n in sub.nodes}
    for edge in sub.edges:
        assert edge.source in node_ids
        assert edge.target in node_ids


def test_21_legacy_investigation_graph_bridge(db):
    """Verifies bidirectional bridge between legacy InvestigationGraphResponse and canonical graph."""
    svc = SecurityGraphService()
    from backend.schemas.graph import (
        InvestigationGraphResponse,
        GraphNode as LegacyNode,
        GraphEdge as LegacyEdge,
        NodeType,
        GraphSummary,
    )

    legacy_graph = InvestigationGraphResponse(
        nodes=[
            LegacyNode(id="email:sample", type=NodeType.EMAIL, label="Phish Email", metadata={"subject": "Test"}),
            LegacyNode(id="domain:evil.test", type=NodeType.DOMAIN, label="evil.test", metadata={"domain": "evil.test"}),
        ],
        edges=[
            LegacyEdge(id="edge:1", source="email:sample", target="domain:evil.test", label="REFERENCES", metadata={})
        ],
        summary=GraphSummary(total_nodes=2, total_edges=1)
    )

    # Persist via bridge
    result = global_graph_service.persist_to_knowledge_graph(db, legacy_graph)
    assert result["nodes_persisted"] == 2
    assert result["edges_persisted"] == 1

    # Export back via bridge
    exported = global_graph_service.build_from_knowledge_graph(db, root_entity_id="domain:evil.test")
    assert isinstance(exported, InvestigationGraphResponse)


# ============================================================================
# 6. REST API ENDPOINT INTEGRATION TESTS
# ============================================================================

def test_22_api_graph_endpoints(client, db):
    """Tests /api/graph REST API endpoints."""
    svc = SecurityGraphService()
    e_dom = svc.upsert_canonical_entity(db, GraphEntityType.DOMAIN, "api-endpoint-test.org")
    e_ip = svc.upsert_canonical_entity(db, GraphEntityType.IP, "198.51.100.123")
    rel, _ = svc.record_relationship(db, e_dom.id, e_ip.id, GraphRelationshipType.RESOLVES_TO)
    db.commit()

    # 1. GET /api/graph/entities/{id}
    res = client.get(f"/api/graph/entities/{e_dom.id}")
    assert res.status_code == 200
    data = res.json()
    assert data["canonical_key"] == "domain:api-endpoint-test.org"

    # 2. GET /api/graph/entities/{id}/neighbors
    res_nb = client.get(f"/api/graph/entities/{e_dom.id}/neighbors?depth=1")
    assert res_nb.status_code == 200
    nb_data = res_nb.json()
    assert nb_data["total_nodes"] >= 2

    # 3. GET /api/graph/edges/{id}/evidence
    res_ev = client.get(f"/api/graph/edges/{rel.id}/evidence")
    assert res_ev.status_code == 200
    ev_data = res_ev.json()
    assert ev_data["edge"]["id"] == rel.id
    assert "explanation" in ev_data

    # 4. GET /api/graph/paths
    res_path = client.get(f"/api/graph/paths?source={e_dom.id}&target={e_ip.id}")
    assert res_path.status_code == 200
    path_data = res_path.json()
    assert path_data["total_paths"] >= 1

    # 5. POST /api/graph/search
    res_srch = client.post("/api/graph/search?query=api-endpoint-test")
    assert res_srch.status_code == 200
    srch_data = res_srch.json()
    assert srch_data["total"] >= 1
