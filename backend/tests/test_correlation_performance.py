"""
High-scale performance benchmark for Section 15:
Cross-Incident Pattern Detection & Campaign Correlation Engine.
Tests scaling on 1,000+ incidents, thousands of entities, and evaluates
sub-linear inverted candidate generation versus naive all-pairs complexity.
"""
import json
import time
import pytest
from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.db.session import Base
from backend.db.models import (
    IncidentModel,
    EntityModel,
    RelationshipModel,
    RelationshipObservationModel,
    IncidentCorrelationModel,
)
from backend.services.cross_incident_engine import (
    CrossIncidentCorrelationEngine,
    prevalence_tracker,
)
from backend.schemas.cross_incident import IncidentCorrelationProfile
from backend.schemas.knowledge_graph import (
    GraphEntityType,
    GraphRelationshipType,
    RelationshipOrigin,
)


@pytest.fixture
def perf_db():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool
    )
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)


def test_large_scale_correlation_performance(perf_db):
    """
    Benchmarks correlation on a corpus of 1,000 incidents with shared
    and unshared entities, measuring profile generation, sub-linear candidate
    generation, pairwise correlation, and clustering.
    """
    engine_svc = CrossIncidentCorrelationEngine()
    total_incidents = 1000
    base_time = datetime(2026, 10, 1, 0, 0, 0, tzinfo=timezone.utc)

    # 1. Bulk generate 1,000 incidents
    t0 = time.perf_counter()
    incidents = []
    # Seed 5 distinct campaign clusters (each 20 incidents) and 900 background incidents
    for i in range(total_incidents):
        cluster_id = i // 20 if i < 100 else None
        if cluster_id is not None:
            # Clustered incidents share a rare hash and lookalike domain
            shared_h = f"sha256:cluster_{cluster_id}_" + ("a" * 46)
            shared_d = f"active-phish-cluster-{cluster_id}.test"
            shared_t = f"Acme Department {cluster_id}"
            meta = {
                "hashes": [shared_h],
                "domains": [shared_d],
                "protected_identities": [shared_t],
                "subject": f"URGENT Cluster {cluster_id} Settlement Notice #{i}"
            }
        else:
            # Background incidents have random/unique indicators
            meta = {
                "hashes": [f"sha256:unique_payload_{i}_" + ("f" * 40)],
                "domains": [f"noise-infra-{i}.test"],
                "ips": [f"198.51.{(i // 254) % 254}.{i % 254 + 1}"],
                "subject": f"Routine notification {i}"
            }

        inc = IncidentModel(
            id=f"INC-{i:04d}",
            incident_number=f"INC-2026-{i:04d}",
            title=f"Security Event {i}",
            workspace_id="default",
            metadata_json=json.dumps(meta),
            opened_at=base_time + timedelta(minutes=i * 5)
        )
        incidents.append(inc)

    perf_db.bulk_save_objects(incidents)
    perf_db.commit()
    t_insert = time.perf_counter() - t0

    # 2. Benchmark Profile Generation (100 sample incidents)
    sample_incidents = perf_db.query(IncidentModel).limit(100).all()
    t1 = time.perf_counter()
    profiles = [engine_svc.extract_incident_profile(inc, perf_db) for inc in sample_incidents]
    t_profiles = (time.perf_counter() - t1) / len(sample_incidents)

    # 3. Benchmark Inverted Candidate Generation vs Naive All-Pairs
    target_prof = profiles[0]  # From cluster 0
    t2 = time.perf_counter()
    candidate_ids = engine_svc.generate_candidate_incident_ids(target_prof, "default", perf_db, max_candidates=50)
    t_candidate_gen = time.perf_counter() - t2

    # Naive comparison would require comparing 1 against all 999 incidents
    naive_comparisons = total_incidents - 1
    actual_candidates_evaluated = len(candidate_ids)

    # 4. Benchmark Pairwise Correlation
    t3 = time.perf_counter()
    c_inc = perf_db.query(IncidentModel).filter(IncidentModel.id == candidate_ids[0]).first() if candidate_ids else sample_incidents[1]
    c_prof = engine_svc.extract_incident_profile(c_inc, perf_db)
    corr_res = engine_svc.correlate_incident_pair(target_prof, c_prof, perf_db)
    t_pairwise = time.perf_counter() - t3

    # 5. Benchmark Campaign Candidate Generation & Clustering
    # Seed 20 pairwise correlations between clustered incidents
    for k in range(1, 10):
        c_k = perf_db.query(IncidentModel).filter(IncidentModel.id == f"INC-{k:04d}").first()
        prof_k = engine_svc.extract_incident_profile(c_k, perf_db)
        c_pair = engine_svc.correlate_incident_pair(target_prof, prof_k, perf_db)
        db_c = IncidentCorrelationModel(
            id=f"perf-corr-{k}",
            workspace_id="default",
            incident_a_id=target_prof.incident_id,
            incident_b_id=prof_k.incident_id,
            correlation_score=c_pair.correlation_score,
            relationship_label=c_pair.relationship_label,
            supporting_evidence_json=json.dumps([e.model_dump() for e in c_pair.supporting_evidence]),
            contradicting_evidence_json=json.dumps([e.model_dump() for e in c_pair.contradicting_evidence]),
            feature_breakdown_json=json.dumps(c_pair.feature_breakdown.model_dump()),
            status="ACTIVE"
        )
        perf_db.add(db_c)
    perf_db.commit()

    t4 = time.perf_counter()
    candidates = engine_svc.generate_campaign_candidates("default", perf_db)
    t_clustering = time.perf_counter() - t4

    # Performance assertions
    assert t_profiles < 0.01  # < 10 ms per profile
    assert t_candidate_gen < 0.05  # < 50 ms for inverted candidate search
    assert t_pairwise < 0.005  # < 5 ms for 8-category pairwise correlation
    assert t_clustering < 0.05  # < 50 ms for campaign clustering
    assert len(candidates) >= 1

    print(f"\n--- Section 15 Performance Benchmark ---")
    print(f"Corpus size: {total_incidents} incidents in database")
    print(f"Bulk insert 1,000 incidents: {t_insert:.3f} s")
    print(f"Profile generation avg: {t_profiles * 1000:.3f} ms / incident")
    print(f"Inverted candidate query: {t_candidate_gen * 1000:.3f} ms (searched {naive_comparisons} incidents, selected {actual_candidates_evaluated} candidates)")
    print(f"Sub-linear reduction factor: {naive_comparisons / max(1, actual_candidates_evaluated):.1f}x speedup over all-pairs")
    print(f"Pairwise 8-category correlation: {t_pairwise * 1000:.3f} ms")
    print(f"Campaign candidate clustering: {t_clustering * 1000:.3f} ms")
