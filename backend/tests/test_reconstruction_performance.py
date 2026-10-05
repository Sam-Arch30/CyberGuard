"""
Performance Benchmark Test for Section 17:
AI Attack Reconstruction Engine (Section 94).

Tests large synthetic incidents with:
- 1,000+ SecurityEvents
- 100+ Entities
- Cross-telemetry event sequences
- Measures:
  - Context loading
  - Candidate stage generation
  - DAG transition construction
  - Contradiction & gap detection
  - Hypothesis ranking
  - Persistence & retrieval
"""
import time
from datetime import datetime, timezone, timedelta
import json
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.db.session import Base
from backend.db.models import (
    IncidentModel,
    SecurityEventModel,
    EntityModel,
    FindingModel,
    ArtifactModel,
    AnalysisRunModel,
    ThreatEventModel,
    AttackPathModel,
)
from backend.schemas.temporal_correlation import SecurityEventType
from backend.services.attack_reconstruction_engine import attack_reconstruction_engine


@pytest.fixture
def perf_db():
    """In-memory SQLite database optimized for benchmark."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = Session()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def test_reconstruction_performance_large_incident(perf_db):
    """
    Benchmarks Attack Reconstruction on an incident containing:
    - 1,200 SecurityEvents
    - 120 Entities
    - Multi-source telemetry (Email, Auth, API, Network, File)
    """
    now = datetime(2026, 10, 6, 8, 0, 0, tzinfo=timezone.utc)
    inc = IncidentModel(
        id="inc-perf-benchmark",
        incident_number="INC-2026-PERF01",
        title="High-Scale Attack Benchmark",
        workspace_id="default"
    )
    perf_db.add(inc)

    # 1. Create 120 Entities
    t0_setup = time.perf_counter()
    entities = []
    for i in range(120):
        ent = EntityModel(
            id=f"ent-perf-{i}",
            entity_type="IP" if i % 2 == 0 else "ACCOUNT",
            name=f"10.0.0.{i}" if i % 2 == 0 else f"user_{i}@corp.com",
            canonical_key=f"10.0.0.{i}" if i % 2 == 0 else f"user_{i}@corp.com",
            workspace_id="default"
        )
        entities.append(ent)
    perf_db.bulk_save_objects(entities)

    # 2. Create 1,200 SecurityEvents
    event_types = [
        SecurityEventType.EMAIL_RECEIVED.value,
        SecurityEventType.URL_ACCESSED.value,
        SecurityEventType.DNS_QUERY.value,
        SecurityEventType.NETWORK_CONNECTION.value,
        SecurityEventType.AUTH_FAILURE.value,
        SecurityEventType.AUTH_SUCCESS.value,
        SecurityEventType.SESSION_CREATED.value,
        SecurityEventType.API_ENUMERATION.value,
        SecurityEventType.BULK_RESOURCE_ACCESS.value,
        SecurityEventType.HIGH_OUTBOUND_DATA_VOLUME.value,
    ]

    events = []
    for i in range(1200):
        etype = event_types[i % len(event_types)]
        ent_id = f"ent-perf-{i % 120}"
        ev = SecurityEventModel(
            id=f"ev-perf-{i}",
            incident_id=inc.id,
            workspace_id="default",
            event_type=etype,
            event_time=now + timedelta(seconds=i * 5),
            source_type="TELEMETRY",
            entity_ids_json=json.dumps([ent_id]),
            summary=f"Synthetic telemetry event {i} of type {etype}"
        )
        events.append(ev)
    perf_db.bulk_save_objects(events)
    perf_db.commit()
    setup_duration_ms = (time.perf_counter() - t0_setup) * 1000

    # 3. Benchmark Context Loading
    t0_load = time.perf_counter()
    incident_obj, telemetry = attack_reconstruction_engine.load_context(perf_db, inc.id, "default")
    load_duration_ms = (time.perf_counter() - t0_load) * 1000

    # 4. Benchmark Candidate Stage Generation
    t0_stages = time.perf_counter()
    stages = attack_reconstruction_engine.build_candidate_stages(telemetry)
    stage_gen_duration_ms = (time.perf_counter() - t0_stages) * 1000

    # 5. Benchmark Transition Building
    t0_trans = time.perf_counter()
    transitions = attack_reconstruction_engine.build_transitions(stages, telemetry)
    transition_gen_duration_ms = (time.perf_counter() - t0_trans) * 1000

    # 6. Benchmark Contradictions & Gaps
    t0_gaps = time.perf_counter()
    contradictions, gaps = attack_reconstruction_engine.detect_contradictions_and_gaps(stages, telemetry)
    gap_duration_ms = (time.perf_counter() - t0_gaps) * 1000

    # 7. Benchmark Hypothesis Generation & Ranking
    t0_hyp = time.perf_counter()
    hypotheses = attack_reconstruction_engine.generate_and_rank_hypotheses(inc.id, stages, contradictions, gaps)
    hyp_duration_ms = (time.perf_counter() - t0_hyp) * 1000

    # 8. Full End-to-End Reconstruction & Persistence
    t0_e2e = time.perf_counter()
    resp = attack_reconstruction_engine.reconstruct_incident(perf_db, inc.id, force_reanalysis=True)
    e2e_duration_ms = (time.perf_counter() - t0_e2e) * 1000

    # 9. Retrieval from Database
    t0_retrieve = time.perf_counter()
    persisted_path = perf_db.query(AttackPathModel).filter(
        AttackPathModel.incident_id == inc.id,
        AttackPathModel.status == "CURRENT"
    ).first()
    retrieved_resp = attack_reconstruction_engine._hydrate_response_from_model(perf_db, persisted_path)
    retrieve_duration_ms = (time.perf_counter() - t0_retrieve) * 1000

    # Print Forensic Benchmark Report
    print("\n" + "=" * 60)
    print("SECTION 17 ATTACK RECONSTRUCTION ENGINE BENCHMARK REPORT")
    print("=" * 60)
    print(f"Dataset Size:           1,200 SecurityEvents, 120 Entities")
    print(f"Database Environment:   SQLite in-memory (StaticPool)")
    print(f"Setup / Bulk Ingestion: {setup_duration_ms:.2f} ms")
    print(f"Context Loading:        {load_duration_ms:.2f} ms")
    print(f"Candidate Stage Gen:    {stage_gen_duration_ms:.2f} ms ({len(stages)} stages)")
    print(f"DAG Transition Gen:     {transition_gen_duration_ms:.2f} ms ({len(transitions)} edges)")
    print(f"Contradiction & Gaps:   {gap_duration_ms:.2f} ms")
    print(f"Hypothesis Ranking:     {hyp_duration_ms:.2f} ms ({len(hypotheses)} hypotheses)")
    print(f"Full End-to-End Recon:  {e2e_duration_ms:.2f} ms")
    print(f"Reconstruction Fetch:   {retrieve_duration_ms:.2f} ms")
    print("=" * 60)

    # Validations & SLAs
    assert len(stages) >= 5
    assert len(transitions) >= 4
    assert len(hypotheses) >= 2
    assert resp.attack_path is not None
    assert retrieved_resp.attack_path.id == resp.attack_path.id

    # Performance SLAs
    assert load_duration_ms < 100.0, f"Context loading took {load_duration_ms} ms (SLA < 100ms)"
    assert stage_gen_duration_ms < 50.0, f"Stage generation took {stage_gen_duration_ms} ms (SLA < 50ms)"
    assert e2e_duration_ms < 250.0, f"Full reconstruction took {e2e_duration_ms} ms (SLA < 250ms)"
    assert retrieve_duration_ms < 50.0, f"Retrieval took {retrieve_duration_ms} ms (SLA < 50ms)"
