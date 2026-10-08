"""
Performance & Scalability Benchmark Suite for Section 20:
Probable Origin Infrastructure & Threat Infrastructure Attribution Engine.
Measures candidate harvesting, graph traversal bounding, clustering, and end-to-end latency.
"""
import json
import time
import pytest
from datetime import datetime, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.db.models import (
    Base,
    IncidentModel,
    SecurityEventModel,
    ThreatEventModel,
    EntityModel,
    RelationshipModel,
    CampaignModel,
)
from backend.services.infrastructure_candidate_generator import InfrastructureCandidateGenerator
from backend.services.infrastructure_clusterer import InfrastructureClusterer
from backend.services.infrastructure_attribution_engine import InfrastructureAttributionEngine
from backend.schemas.infrastructure_attribution import (
    InfrastructureCandidate,
    InfrastructureRole,
    InfrastructureDirection,
)


@pytest.fixture
def db_session():
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


def test_perf_01_candidate_generation_large_volume(db_session):
    """Benchmarks candidate generation across 500 security events."""
    inc = IncidentModel(id="INC-PERF-001", incident_number="INC-2026-P01", title="Large Scale Telemetry", workspace_id="default")
    db_session.add(inc)

    now = datetime.now(timezone.utc)
    events = [
        SecurityEventModel(
            id=f"SE-PERF-{i}",
            incident_id=inc.id,
            workspace_id="default",
            event_type="NETWORK_FLOW",
            source_type="FIREWALL",
            event_time=now,
            attributes_json=json.dumps({
                "source_ip": f"198.51.{i % 255}.{(i * 7) % 255}",
                "destination_ip": f"203.0.113.{(i * 3) % 255}",
                "domain": f"host-{i % 50}.target-domain.test",
            }),
        )
        for i in range(500)
    ]
    db_session.bulk_save_objects(events)
    db_session.commit()

    generator = InfrastructureCandidateGenerator(max_candidates=100)
    t0 = time.monotonic()
    obs, assoc = generator.generate_candidates(db_session, inc)
    elapsed = time.monotonic() - t0

    print(f"\n[BENCHMARK] 500 SecurityEvents candidate generation: {elapsed * 1000:.2f} ms")
    assert len(obs) <= 100
    assert elapsed < 0.25  # Should process in < 250ms


def test_perf_02_bounded_graph_traversal_safety(db_session):
    """Verifies that dense/cyclic knowledge graph traversal respects MAX_GRAPH_DEPTH and does not loop."""
    inc = IncidentModel(id="INC-PERF-002", incident_number="INC-2026-P02", title="Cyclic Graph", workspace_id="default")
    db_session.add(inc)

    se = SecurityEventModel(
        id="SE-START",
        incident_id=inc.id,
        workspace_id="default",
        event_type="DNS",
        source_type="DNS",
        event_time=datetime.now(timezone.utc),
        attributes_json=json.dumps({"domain": "node-0.test"}),
    )
    db_session.add(se)

    # Create cyclic graph: node 0 -> node 1 -> node 2 -> ... -> node 0
    entities = []
    relationships = []
    for i in range(50):
        entities.append(EntityModel(id=f"ent-{i}", name=f"node-{i}.test", entity_type="DOMAIN", canonical_key=f"domain:node-{i}.test"))
        next_i = (i + 1) % 50
        relationships.append(RelationshipModel(id=f"rel-{i}", source_type="DOMAIN", source_id=f"domain:node-{i}.test", target_type="DOMAIN", target_id=f"domain:node-{next_i}.test", relationship_type="RESOLVES_TO"))

    db_session.bulk_save_objects(entities)
    db_session.bulk_save_objects(relationships)
    db_session.commit()

    generator = InfrastructureCandidateGenerator(max_graph_depth=3, max_candidates=50)
    t0 = time.monotonic()
    obs, assoc = generator.generate_candidates(db_session, inc)
    elapsed = time.monotonic() - t0

    print(f"\n[BENCHMARK] Cyclic graph traversal (50 nodes, depth 3): {elapsed * 1000:.2f} ms")
    assert elapsed < 0.15  # Strict sub-150ms bound
    assert len(assoc) <= 50


def test_perf_03_clustering_scale(db_session):
    """Benchmarks clustering algorithm across 150 candidates."""
    candidates = []
    for i in range(150):
        candidates.append(
            InfrastructureCandidate(
                id=f"c-{i}",
                entity_type="DOMAIN" if i % 2 == 0 else "IP",
                canonical_key=f"item:{i}",
                value=f"endpoint-{i}.test" if i % 2 == 0 else f"198.51.100.{i}",
                role=InfrastructureRole.HOSTING_INFRASTRUCTURE,
                direction=InfrastructureDirection.INFRASTRUCTURE_ENDPOINT,
                is_observed=True,
                is_direct=True,
                campaign_ids=[f"CAMP-{(i % 5):02d}"],
                historical_incident_ids=[f"INC-HIST-{(i % 3):02d}"],
                evidence_refs=[f"ev-{i}"],
            )
        )

    clusterer = InfrastructureClusterer()
    t0 = time.monotonic()
    clusters = clusterer.cluster_infrastructure(candidates, "INC-PERF-CLUST")
    elapsed = time.monotonic() - t0

    print(f"\n[BENCHMARK] Clustering 150 candidates: {elapsed * 1000:.2f} ms")
    assert elapsed < 0.05  # Should cluster in < 50ms
    assert len(clusters) >= 1


def test_perf_04_end_to_end_analysis_latency(db_session):
    """Measures full end-to-end engine latency for a complete incident."""
    inc = IncidentModel(id="INC-E2E-PERF", incident_number="INC-2026-E2E", title="E2E Benchmark", workspace_id="default")
    db_session.add(inc)

    for i in range(25):
        db_session.add(
            SecurityEventModel(
                id=f"SE-E2E-{i}",
                incident_id=inc.id,
                workspace_id="default",
                event_type="AUTH",
                source_type="IDP",
                event_time=datetime.now(timezone.utc),
                attributes_json=json.dumps({"source_ip": f"203.0.113.{i}", "domain": f"corp-{i}.test"}),
            )
        )
    db_session.commit()

    engine = InfrastructureAttributionEngine()
    t0 = time.monotonic()
    resp = engine.analyze_incident_infrastructure(db_session, inc.id, persist=True)
    elapsed = time.monotonic() - t0

    print(f"\n[BENCHMARK] Full End-to-End Infrastructure Analysis: {elapsed * 1000:.2f} ms")
    assert resp.primary_hypothesis is not None
    assert elapsed < 0.20  # Complete pipeline under 200ms
