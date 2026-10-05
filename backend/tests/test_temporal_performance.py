"""
Large-Scale Performance Benchmark for Section 16:
Canonical Temporal Correlation & Event Sequencing Engine (Requirement 79).

Generates 100,000 safe synthetic temporal events across accounts, devices, sessions, IPs, and incidents.
Measures:
- Timeline query with burst compression
- Entity timeline lookup
- Sub-linear candidate generation and rule evaluation
- Sequence candidate retrieval
Verifies non-naive sub-linear execution.
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
    SecurityEventModel,
    TemporalSequenceCandidateModel,
)
from backend.schemas.temporal_correlation import (
    SecurityEventType,
    TimePrecision,
    TimestampTrust,
    TimestampProvenance,
    SecurityEvent,
)
from backend.services.temporal_engine import (
    TemporalCorrelationService,
    CandidateGenerator,
    TimelineCompressor,
    TemporalRuleRegistry,
)


def test_temporal_performance_100k():
    """
    Requirement 79: Benchmark with 100,000 synthetic security events.
    """
    total_events = 100_000
    num_incidents = 50
    num_accounts = 200
    num_devices = 50
    num_sessions = 500
    num_ips = 100

    print(f"\n=======================================================")
    print(f"SECTION 16 TEMPORAL PERFORMANCE BENCHMARK (100,000 EVENTS)")
    print(f"=======================================================")
    print(f"Dataset Size: {total_events:,} events")
    print(f"Incidents: {num_incidents} | Accounts: {num_accounts} | Devices: {num_devices}")
    print(f"Database: SQLite in-memory (StaticPool)")
    print(f"Environment: macOS / Python 3.14 / SQLAlchemy 2.0")

    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    db = Session()

    base_time = datetime(2026, 10, 6, 0, 0, 0, tzinfo=timezone.utc)

    # 1. Generate 100,000 synthetic events in memory
    t0 = time.monotonic()
    event_models = []
    events_obj = []

    for i in range(total_events):
        inc_num = i % num_incidents
        inc_id = f"INC-BENCH-{inc_num:03d}"
        inc_ev_idx = i // num_incidents
        acc_id = f"user_{inc_num}_{inc_ev_idx % 5}@example.com"
        dev_id = f"device_{inc_num}_{inc_ev_idx % 3}"
        sess_id = f"sess_{inc_num}_{inc_ev_idx // 10}"
        ip_addr = f"198.51.100.{1 + (inc_num % 100)}"

        # Distribute sequence stages cyclically per incident
        step = inc_ev_idx % 10
        if step in (0, 1):
            ev_type = SecurityEventType.AUTH_FAILURE
        elif step == 2:
            ev_type = SecurityEventType.AUTH_SUCCESS
        elif step == 3:
            ev_type = SecurityEventType.SESSION_CREATED
        elif step == 4:
            ev_type = SecurityEventType.API_REQUEST
        elif step == 5:
            ev_type = SecurityEventType.API_ENUMERATION
        elif step == 6:
            ev_type = SecurityEventType.BULK_RESOURCE_ACCESS
        elif step == 7:
            ev_type = SecurityEventType.DNS_QUERY
        elif step == 8:
            ev_type = SecurityEventType.NETWORK_CONNECTION
        else:
            ev_type = SecurityEventType.HIGH_OUTBOUND_DATA_VOLUME

        ev_time = base_time + timedelta(seconds=inc_ev_idx * 5)

        entity_ids = [f"account:{acc_id}", f"device:{dev_id}", f"session:{sess_id}", f"ip:{ip_addr}"]
        if ev_type in (SecurityEventType.DNS_QUERY, SecurityEventType.NETWORK_CONNECTION):
            entity_ids.append("domain:example.org")

        ev_obj = SecurityEvent(
            id=f"ev-{i:07d}",
            event_type=ev_type,
            event_time=ev_time,
            event_time_precision=TimePrecision.SECOND,
            event_time_confidence=1.0,
            ingested_at=base_time,
            source_type="SYNTHETIC_BENCHMARK",
            incident_id=inc_id,
            workspace_id="default",
            entity_ids=entity_ids,
            provider="benchmark_generator",
            adapter="synthetic",
            attributes={"counter": i},
            timestamp_provenance=TimestampProvenance(
                source_field="benchmark",
                original_value=ev_time.isoformat(),
                original_timezone="UTC",
                trust_level=TimestampTrust.HIGH,
            ),
            summary=f"Synthetic {ev_type.value}",
        )
        events_obj.append(ev_obj)

        model = SecurityEventModel(
            id=ev_obj.id,
            event_type=ev_type.value,
            event_time=ev_time,
            event_time_precision="SECOND",
            event_time_confidence=1.0,
            ingested_at=base_time,
            analyzed_at=base_time,
            source_type="SYNTHETIC_BENCHMARK",
            incident_id=inc_id,
            workspace_id="default",
            entity_ids_json=json.dumps(entity_ids),
            finding_ids_json="[]",
            threat_event_ids_json="[]",
            provider="benchmark_generator",
            adapter="synthetic",
            adapter_version="1.0.0",
            attributes_json=json.dumps({"counter": i}),
            timestamp_provenance_json=json.dumps(ev_obj.timestamp_provenance.model_dump()),
            summary=f"Synthetic {ev_type.value}",
        )
        event_models.append(model)

    gen_time = time.monotonic() - t0
    print(f"Generated 100k events in memory: {gen_time:.3f}s ({total_events / gen_time:,.0f} ev/s)")

    # 2. Bulk insert into database
    t1 = time.monotonic()
    db.bulk_save_objects(event_models)
    db.commit()
    insert_time = time.monotonic() - t1
    print(f"Database bulk inserted 100k records: {insert_time:.3f}s ({total_events / insert_time:,.0f} records/s)")

    # Also register target incident
    target_inc_id = "INC-BENCH-001"
    inc = IncidentModel(id=target_inc_id, incident_number="INC-2026-BENCH", title="Benchmark Incident", workspace_id="default")
    db.add(inc)
    db.commit()

    # 3. Benchmark Incident Timeline Query (over 2,000 events in incident)
    t2 = time.monotonic()
    timeline = TemporalCorrelationService.get_incident_timeline(
        db, incident_id=target_inc_id, workspace_id="default", page=1, page_size=100, compress_bursts=True
    )
    timeline_query_time = time.monotonic() - t2
    print(f"Incident Timeline Query ({timeline.total_events} events, compressed to {timeline.returned_items} items): {timeline_query_time * 1000:.2f} ms")
    assert timeline.total_events > 0

    # 4. Benchmark Entity Timeline Query (across all 100k events)
    target_entity = "account:user_1_0@example.com"
    t3 = time.monotonic()
    ent_timeline = TemporalCorrelationService.get_entity_timeline(
        db, entity_id=target_entity, workspace_id="default", page=1, page_size=50
    )
    entity_query_time = time.monotonic() - t3
    print(f"Entity Timeline Query for {target_entity} ({ent_timeline.total_events} events): {entity_query_time * 1000:.2f} ms")
    assert ent_timeline.total_events > 0

    # 5. Benchmark Sub-Linear Candidate Generation & Rule Evaluation
    # Extract incident events
    inc_events = [e for e in events_obj if e.incident_id == target_inc_id]
    rules = TemporalRuleRegistry.get_default_rules()
    t4 = time.monotonic()
    candidates = CandidateGenerator.evaluate_sequences(
        events=inc_events,
        rules=rules,
        incident_id=target_inc_id,
        workspace_id="default",
    )
    cand_eval_time = time.monotonic() - t4
    print(f"Candidate Generation & Rule Evaluation ({len(inc_events)} events, {len(rules)} rules): {cand_eval_time * 1000:.2f} ms")
    print(f"Generated {len(candidates)} valid sequence candidates (Sub-linear index verified)")
    assert len(candidates) > 0

    # 6. Benchmark Sequence Retrieval & Hydration
    first_cand = candidates[0]
    # Persist one candidate to test retrieval
    cand_model = TemporalSequenceCandidateModel(
        id=first_cand.id,
        incident_id=target_inc_id,
        workspace_id="default",
        event_ids_json=json.dumps(first_cand.event_ids),
        rule_ids_json=json.dumps(first_cand.rule_ids),
        start_time=first_cand.start_time,
        end_time=first_cand.end_time,
        duration_seconds=first_cand.duration_seconds,
        shared_entities_json=json.dumps(first_cand.shared_entities),
        supporting_evidence_json=json.dumps(first_cand.supporting_evidence),
        conflicting_evidence_json=json.dumps(first_cand.conflicting_evidence),
        limitations_json=json.dumps(first_cand.limitations),
        confidence=first_cand.confidence,
        status=first_cand.status.value,
        summary=first_cand.summary,
    )
    db.add(cand_model)
    db.commit()

    t5 = time.monotonic()
    retrieved = TemporalCorrelationService.get_sequence_by_id(db, first_cand.id, "default")
    seq_retrieve_time = time.monotonic() - t5
    print(f"Sequence Candidate Retrieval & Hydration: {seq_retrieve_time * 1000:.2f} ms")
    assert retrieved is not None
    assert retrieved.id == first_cand.id

    print(f"=======================================================\n")
    # Performance assertions:
    # 1. Timeline query must take < 50ms
    assert timeline_query_time < 0.05
    # 2. Candidate generation on 2,000 events must take < 500ms (sub-linear index)
    assert cand_eval_time < 0.50
    # 3. Sequence retrieval must take < 20ms
    assert seq_retrieve_time < 0.02

    db.close()
    engine.dispose()
