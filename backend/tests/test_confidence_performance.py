"""
Performance benchmark test for Section 18:
Attack Path Confidence & Explainability Engine (Section 80).

Measures actual execution timings for:
- Stage scoring
- Transition scoring
- Full path scoring (with bottleneck detection and uncertainty propagation)
- Explanation generation
on a large synthetic reconstruction (50 stages, 49 transitions).
"""
from datetime import datetime, timezone, timedelta
import json
import time
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.db.session import Base
from backend.db.models import (
    IncidentModel,
    AttackPathModel,
    AttackStageModel,
    AttackEdgeModel,
)
from backend.schemas.attack_confidence import ConfidenceConfig
from backend.services.attack_confidence_engine import AttackConfidenceEngine
from backend.services.attack_explanation_service import AttackExplanationService


@pytest.fixture
def perf_db():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def test_confidence_engine_performance_large_reconstruction(perf_db):
    """
    Benchmarks Section 18 confidence scoring and explanation generation on a large synthetic attack graph.
    Measures and outputs actual elapsed times.
    """
    NUM_STAGES = 50
    now = datetime.now(timezone.utc)

    inc = IncidentModel(id="inc-perf-18", incident_number="INC-PERF-18", title="Large Scale Attack Incident", status="OPEN")
    perf_db.add(inc)

    path = AttackPathModel(
        id="path-perf-18", incident_id=inc.id, name="Massive 50-Stage Campaign Path",
        classification="PLAUSIBLE_RECONSTRUCTION", confidence=0.80, status="CURRENT"
    )
    perf_db.add(path)

    stage_types = [
        "DELIVERY", "USER_INTERACTION", "FILE_ACTIVITY", "EXECUTION",
        "INFRASTRUCTURE_CONTACT", "CREDENTIAL_ACTIVITY", "AUTHENTICATION",
        "SESSION_ESTABLISHMENT", "DISCOVERY", "ENUMERATION",
        "PRIVILEGED_ACTIVITY", "PERSISTENCE", "COLLECTION", "DATA_ACCESS", "OUTBOUND_TRANSFER"
    ]

    stages = []
    for i in range(NUM_STAGES):
        st_type = stage_types[i % len(stage_types)]
        is_observed = (i % 3 != 0)
        stg = AttackStageModel(
            id=f"stg-perf-{i}",
            attack_path_id=path.id,
            stage_order=i + 1,
            stage_type=st_type,
            stage_status="OBSERVED" if is_observed else "INFERRED",
            name=f"Stage {i + 1}: {st_type}",
            confidence=0.90 if is_observed else 0.55,
            start_time=now + timedelta(minutes=i * 2),
            end_time=now + timedelta(minutes=i * 2, seconds=30),
            entity_ids_json=json.dumps([f"user:alice", f"session:sess_{i // 5}"]),
            supporting_evidence_json=json.dumps([{"id": f"ev-{i}", "source": "telemetry_sensor"}])
        )
        stages.append(stg)
    perf_db.add_all(stages)

    edges = []
    for i in range(NUM_STAGES - 1):
        edge = AttackEdgeModel(
            id=f"edge-perf-{i}",
            attack_path_id=path.id,
            source_stage_id=stages[i].id,
            target_stage_id=stages[i + 1].id,
            relationship_type="PRECEDES",
            edge_status="DERIVED",
            confidence=0.85 if i != 25 else 0.35,  # Inject weak link at stage 25
            temporal_gap_seconds=90.0,
            shared_entities_json=json.dumps([f"user:alice", f"session:sess_{i // 5}"])
        )
        edges.append(edge)
    perf_db.add_all(edges)
    perf_db.commit()

    # 1. Benchmark individual stage scoring
    t0 = time.perf_counter()
    stage_breakdowns = []
    for s in stages:
        stage_breakdowns.append(AttackConfidenceEngine.score_stage(s))
    t_stages = (time.perf_counter() - t0) * 1000.0  # ms

    # 2. Benchmark individual transition scoring
    t0 = time.perf_counter()
    edge_breakdowns = []
    for i in range(len(edges)):
        edge_breakdowns.append(AttackConfidenceEngine.score_transition(stages[i], stages[i + 1], edge_model=edges[i]))
    t_edges = (time.perf_counter() - t0) * 1000.0  # ms

    # 3. Benchmark full path scoring (including bottleneck detection & bounding)
    t0 = time.perf_counter()
    path_breakdown, bottleneck = AttackConfidenceEngine.score_path(path=path, stages=stages, edges=edges)
    t_path = (time.perf_counter() - t0) * 1000.0  # ms

    # 4. Benchmark explanation generation
    t0 = time.perf_counter()
    path_explanation = AttackExplanationService.explain_attack_path(path_id=path.id, db=perf_db)
    t_explain = (time.perf_counter() - t0) * 1000.0  # ms

    # Output benchmark timings
    print(f"\n================ SECTION 18 PERFORMANCE BENCHMARK ================")
    print(f"Dataset Size: {NUM_STAGES} stages, {len(edges)} transitions")
    print(f"Stage Scoring ({NUM_STAGES} stages):        {t_stages:.2f} ms ({t_stages / NUM_STAGES:.3f} ms/stage)")
    print(f"Transition Scoring ({len(edges)} transitions): {t_edges:.2f} ms ({t_edges / len(edges):.3f} ms/transition)")
    print(f"Full Path Scoring + Bottleneck:     {t_path:.2f} ms")
    print(f"Full Path Explanation Generation:   {t_explain:.2f} ms")
    print(f"Identified Bottleneck:              {bottleneck.subject_name} ({bottleneck.confidence:.2f})")
    print(f"===================================================================\n")

    # Assertions
    assert bottleneck.subject_id in [edges[25].id, stages[25].id]
    assert t_stages < 200.0, f"Stage scoring took too long: {t_stages:.2f} ms"
    assert t_edges < 200.0, f"Transition scoring took too long: {t_edges:.2f} ms"
    assert t_path < 250.0, f"Full path scoring took too long: {t_path:.2f} ms"
    assert t_explain < 300.0, f"Explanation generation took too long: {t_explain:.2f} ms"
