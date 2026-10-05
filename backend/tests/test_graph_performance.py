"""
Large-Scale Performance Benchmark for Security Knowledge Graph (Section 70).
Generates a safe synthetic graph of 10,000+ entities and 25,000+ relationships.
Measures:
1. Entity lookup latency
2. Neighbor expansion latency (depth 1 and depth 2)
3. Incident subgraph query latency
4. Bounded multi-hop path search latency
5. Entity timeline query latency
"""
import os
import random
import time
import tempfile
from pathlib import Path
from datetime import datetime, timezone
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.db.session import Base
from backend.db.models import EntityModel, RelationshipModel, RelationshipObservationModel, IncidentModel
from backend.schemas.knowledge_graph import (
    GraphEntityType,
    GraphRelationshipType,
    RelationshipOrigin,
    make_canonical_key,
)
from backend.services.security_graph_service import SecurityGraphService


@pytest.fixture(scope="module")
def perf_db():
    """Isolated high-capacity SQLite in-memory or fast tempfile DB for benchmarking."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "perf_graph.db"
        engine = create_engine(f"sqlite:///{db_path}", echo=False)
        Base.metadata.create_all(bind=engine)
        Session = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        session = Session()

        yield session

        session.close()
        engine.dispose()


def test_large_scale_graph_performance(perf_db):
    """
    Populates 10,000 entities and 25,000 relationships and measures key queries.
    """
    svc = SecurityGraphService()
    now = datetime.now(timezone.utc)

    NUM_ENTITIES = 10000
    NUM_RELATIONSHIPS = 25000

    print(f"\n--- GENERATING SYNTHETIC GRAPH: {NUM_ENTITIES} ENTITIES & {NUM_RELATIONSHIPS} EDGES ---")
    gen_start = time.perf_counter()

    entity_ids: list[str] = []
    entity_keys: list[str] = []

    # 1. Create Incidents
    incidents = []
    for i in range(10):
        inc = IncidentModel(
            id=f"inc-perf-{i:03d}",
            incident_number=f"INC-2026-{1000+i}",
            title=f"Synthetic Campaign Incident {i}",
            status="OPEN",
            severity="HIGH",
            risk_score=75.0,
            opened_at=now,
        )
        perf_db.add(inc)
        incidents.append(inc)
    perf_db.flush()

    # 2. Batch Insert 10,000 Entities
    entity_objects = []
    for i in range(NUM_ENTITIES):
        e_type_idx = i % 7
        if e_type_idx == 0:
            etype = "IP"
            val = f"198.51.{i // 256}.{i % 256}"
            disp = val
            key = f"ip:{val}"
        elif e_type_idx == 1:
            etype = "DOMAIN"
            val = f"host-{i}.threat-net.test"
            disp = val
            key = f"domain:{val}"
        elif e_type_idx == 2:
            etype = "URL"
            val = f"https://host-{i}.threat-net.test/login?id={i}"
            disp = val[:40]
            key = f"url:{val}"
        elif e_type_idx == 3:
            etype = "ACCOUNT"
            val = f"employee_{i}"
            disp = f"employee_{i}"
            key = f"account:okta-corp:employee_{i}"
        elif e_type_idx == 4:
            etype = "DEVICE"
            val = f"DEV-HOST-{i:05d}"
            disp = f"Device {val}"
            key = f"device:fleet-us:{val}"
        elif e_type_idx == 5:
            etype = "FILE"
            val = f"{i:064x}"
            disp = f"malware_{i}.bin"
            key = f"file:{val}"
        else:
            etype = "HASH"
            val = f"{i:064x}"
            disp = f"SHA256:{val[:8]}..."
            key = f"hash:{val}"

        eid = f"ent-{i:06d}"
        entity_ids.append(eid)
        entity_keys.append(key)

        ent = EntityModel(
            id=eid,
            entity_type=etype,
            name=disp,
            canonical_key=key,
            attributes_json='{"synthetic": true}',
            first_seen=now,
            last_seen=now,
            created_at=now,
            updated_at=now,
        )
        entity_objects.append(ent)

        if len(entity_objects) >= 2000:
            perf_db.bulk_save_objects(entity_objects)
            perf_db.flush()
            entity_objects = []

    if entity_objects:
        perf_db.bulk_save_objects(entity_objects)
        perf_db.flush()

    # 3. Batch Insert 25,000 Relationships & Observations
    rel_objects = []
    obs_objects = []
    rel_types = [
        "CONTAINS", "REFERENCES", "RESOLVES_TO", "CONNECTS_TO",
        "AUTHENTICATED_FROM", "USED_DEVICE", "HAS_SESSION", "HAS_HASH", "OBSERVED_IN"
    ]

    random.seed(42)
    for r in range(NUM_RELATIONSHIPS):
        rid = f"rel-{r:06d}"
        src = random.choice(entity_ids)
        tgt = random.choice(entity_ids)
        if src == tgt:
            tgt = entity_ids[(r + 1) % NUM_ENTITIES]
        rtype = random.choice(rel_types)

        rel = RelationshipModel(
            id=rid,
            source_type="ENTITY",
            source_id=src,
            relationship_type=rtype,
            target_type="ENTITY",
            target_id=tgt,
            confidence=0.95,
            origin="OBSERVED",
            status="ACTIVE",
            first_seen=now,
            last_seen=now,
            metadata_json='{"synthetic": true}',
            created_at=now,
            updated_at=now,
        )
        rel_objects.append(rel)

        obs = RelationshipObservationModel(
            id=f"obs-{r:06d}",
            relationship_id=rid,
            observed_at=now,
            analyzer="SyntheticLoadGenerator",
            analyzer_version="1.0",
            confidence=0.95,
            origin="OBSERVED",
            attributes_json='{}',
            created_at=now,
        )
        obs_objects.append(obs)

        if len(rel_objects) >= 5000:
            perf_db.bulk_save_objects(rel_objects)
            perf_db.bulk_save_objects(obs_objects)
            perf_db.flush()
            rel_objects = []
            obs_objects = []

    if rel_objects:
        perf_db.bulk_save_objects(rel_objects)
        perf_db.bulk_save_objects(obs_objects)
        perf_db.flush()

    perf_db.commit()
    gen_duration = time.perf_counter() - gen_start
    print(f"Graph population complete in {gen_duration:.2f}s.")

    # =========================================================================
    # BENCHMARK 1: ENTITY LOOKUP
    # =========================================================================
    lookup_samples = random.sample(entity_ids, 500)
    start_t = time.perf_counter()
    for eid in lookup_samples:
        node = svc.get_entity(perf_db, eid)
        assert node is not None
    duration_lookup = time.perf_counter() - start_t
    avg_lookup_ms = (duration_lookup / len(lookup_samples)) * 1000
    print(f"1. Entity Lookup (500 queries): Total {duration_lookup:.3f}s | Avg {avg_lookup_ms:.3f} ms/lookup")
    assert avg_lookup_ms < 10.0, "Entity lookup exceeded performance budget"

    # =========================================================================
    # BENCHMARK 2: NEIGHBOR TRAVERSAL (Depth 1 & Depth 2)
    # =========================================================================
    neighbor_samples = random.sample(entity_ids, 100)
    start_t = time.perf_counter()
    for eid in neighbor_samples:
        sub = svc.get_neighbors(perf_db, eid, depth=1, max_nodes=50)
    duration_nb_d1 = time.perf_counter() - start_t
    avg_nb_d1_ms = (duration_nb_d1 / len(neighbor_samples)) * 1000
    print(f"2a. Neighbor Expansion Depth 1 (100 queries): Total {duration_nb_d1:.3f}s | Avg {avg_nb_d1_ms:.3f} ms/query")
    assert avg_nb_d1_ms < 50.0, "Neighbor depth 1 exceeded performance budget"

    start_t = time.perf_counter()
    for eid in neighbor_samples[:30]:
        sub = svc.get_neighbors(perf_db, eid, depth=2, max_nodes=100)
    duration_nb_d2 = time.perf_counter() - start_t
    avg_nb_d2_ms = (duration_nb_d2 / 30) * 1000
    print(f"2b. Neighbor Expansion Depth 2 (30 queries): Total {duration_nb_d2:.3f}s | Avg {avg_nb_d2_ms:.3f} ms/query")
    assert avg_nb_d2_ms < 100.0, "Neighbor depth 2 exceeded performance budget"

    # =========================================================================
    # BENCHMARK 3: INCIDENT SUBGRAPH QUERY
    # =========================================================================
    start_t = time.perf_counter()
    for inc in incidents:
        sub_inc = svc.get_incident_subgraph(perf_db, inc.id, max_nodes=150)
    duration_inc = time.perf_counter() - start_t
    avg_inc_ms = (duration_inc / len(incidents)) * 1000
    print(f"3. Incident Subgraph (10 queries): Total {duration_inc:.3f}s | Avg {avg_inc_ms:.3f} ms/query")
    assert avg_inc_ms < 100.0, "Incident subgraph query exceeded budget"

    # =========================================================================
    # BENCHMARK 4: BOUNDED MULTI-HOP PATH SEARCH
    # =========================================================================
    path_pairs = [
        (random.choice(entity_ids), random.choice(entity_ids))
        for _ in range(25)
    ]
    start_t = time.perf_counter()
    for src_id, tgt_id in path_pairs:
        path_res = svc.find_paths(perf_db, source_id=src_id, target_id=tgt_id, max_depth=3, max_paths=5)
    duration_path = time.perf_counter() - start_t
    avg_path_ms = (duration_path / len(path_pairs)) * 1000
    print(f"4. Bounded Path Search (25 queries, max depth 3): Total {duration_path:.3f}s | Avg {avg_path_ms:.3f} ms/query")
    assert avg_path_ms < 200.0, "Path search exceeded performance budget"

    # =========================================================================
    # BENCHMARK 5: ENTITY TIMELINE QUERY
    # =========================================================================
    timeline_samples = random.sample(entity_ids, 50)
    start_t = time.perf_counter()
    for eid in timeline_samples:
        tl = svc.get_entity_timeline(perf_db, eid, limit=50)
    duration_tl = time.perf_counter() - start_t
    avg_tl_ms = (duration_tl / len(timeline_samples)) * 1000
    print(f"5. Entity Timeline (50 queries): Total {duration_tl:.3f}s | Avg {avg_tl_ms:.3f} ms/query")
    assert avg_tl_ms < 50.0, "Entity timeline exceeded budget"

    print("--- BENCHMARK COMPLETED SUCCESSFULLY ---\n")
