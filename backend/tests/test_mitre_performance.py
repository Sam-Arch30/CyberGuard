"""
Performance & Benchmark Tests for MITRE ATT&CK Mapping & Intelligence Engine (Section 73).
Measures dataset loading, candidate generation, evidence validation, deduplication,
incident-level mapping, and report generation over high-volume telemetry.
"""
from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone
import pytest

from backend.db.session import SessionLocal, init_db
from backend.db.models import IncidentModel, SecurityEventModel
from backend.schemas.mitre_attack import AttackMappingStatus
from backend.services.mitre_dataset_service import MitreDatasetService
from backend.services.mitre_mapping_engine import MITREAttackMappingEngine


@pytest.fixture(scope="module", autouse=True)
def setup_database():
    init_db()


@pytest.fixture
def db_session():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def test_perf_01_dataset_load_time():
    """Measures cold and warm dataset loading time."""
    start = time.perf_counter()
    service = MitreDatasetService()
    duration_ms = (time.perf_counter() - start) * 1000.0

    assert duration_ms < 100.0, f"Dataset load took {duration_ms:.2f}ms, expected < 100ms"
    assert len(service.list_techniques()) >= 20


def test_perf_02_high_volume_candidate_generation_and_validation():
    """
    Evaluates 1,000 synthetic finding inputs across mapping rules.
    Measures candidate generation and rule evaluation latency.
    """
    engine = MITREAttackMappingEngine()

    findings = []
    for i in range(1000):
        mod = i % 5
        if mod == 0:
            findings.append({
                "id": f"find-{i}",
                "finding_type": "PASSWORD_SPRAYING",
                "metadata": {"distinct_accounts": 15, "attempt_count": 25, "source_ip": f"198.51.100.{i % 250}"}
            })
        elif mod == 1:
            findings.append({
                "id": f"find-{i}",
                "finding_type": "CREDENTIAL_HARVESTING_URL",
                "metadata": {"has_suspicious_link": True, "recipient": f"user{i}@corp.com"}
            })
        elif mod == 2:
            findings.append({
                "id": f"find-{i}",
                "finding_type": "API_ENUMERATION",
                "metadata": {"distinct_resources": 100, "error_count": 50}
            })
        elif mod == 3:
            findings.append({
                "id": f"find-{i}",
                "finding_type": "HIGH_OUTBOUND_DATA",
                "metadata": {"bytes_transferred": 10000000, "sensitive_resource_accessed": False}
            })
        else:
            findings.append({
                "id": f"find-{i}",
                "finding_type": "AUTH_FAILURE",
                "metadata": {"account_count": 1, "failed_attempts": 1}  # benign
            })

    start = time.perf_counter()
    all_candidates = []
    for f in findings:
        all_candidates.extend(engine.map_finding(f))
    total_eval_ms = (time.perf_counter() - start) * 1000.0

    avg_per_finding_ms = total_eval_ms / len(findings)
    assert total_eval_ms < 500.0, f"1,000 findings evaluation took {total_eval_ms:.2f}ms, expected < 500ms"
    assert avg_per_finding_ms < 1.0, f"Average latency per finding was {avg_per_finding_ms:.3f}ms, expected < 1.0ms"
    assert len(all_candidates) >= 700


def test_perf_03_deduplication_scale():
    """
    Measures deduplication and hierarchy consolidation performance over 1,000 candidate mappings.
    """
    engine = MITREAttackMappingEngine()

    # Create 1,000 candidate mappings
    candidates = []
    for i in range(1000):
        tid = "T1110.003" if i % 2 == 0 else "T1566.002"
        candidates.append(
            engine.map_finding({
                "id": f"f-{i}",
                "finding_type": "PASSWORD_SPRAYING" if i % 2 == 0 else "CREDENTIAL_HARVESTING_URL",
                "metadata": {
                    "distinct_accounts": 10,
                    "attempt_count": 15,
                    "has_suspicious_link": True,
                    "recipient": "user@org.com",
                },
                "evidence_items": [{"id": f"ev-{i % 50}"}]
            })[0]
        )

    start = time.perf_counter()
    deduped = engine.deduplicate_mappings(candidates)
    duration_ms = (time.perf_counter() - start) * 1000.0

    assert duration_ms < 100.0, f"Deduplication over 1,000 mappings took {duration_ms:.2f}ms, expected < 100ms"
    assert len(deduped) <= 2
    # Verify evidence references merged
    assert len(deduped[0].evidence_ids) >= 10


def test_perf_04_incident_mapping_and_report_generation(db_session):
    """
    Measures complete end-to-end incident mapping and report synthesis.
    """
    engine = MITREAttackMappingEngine()

    inc = IncidentModel(
        title="Perf Test Incident",
        incident_number=f"INC-{uuid.uuid4().hex[:6]}",
        status="OPEN"
    )
    db_session.add(inc)
    db_session.flush()

    for i in range(100):
        sev = SecurityEventModel(
            incident_id=inc.id,
            event_type="AUTH_FAILURE",
            event_time=datetime.now(timezone.utc),
            source_type="AUTH_LOG",
            summary=f"Event {i}",
            attributes_json=json.dumps({"distinct_accounts": 15, "attempt_count": 25, "source_ip": "198.51.100.10"})
        )
        db_session.add(sev)
    db_session.commit()

    start = time.perf_counter()
    report = engine.map_incident(inc.id, db=db_session, persist=True)
    duration_ms = (time.perf_counter() - start) * 1000.0

    assert duration_ms < 200.0, f"End-to-end incident mapping took {duration_ms:.2f}ms, expected < 200ms"
    assert len(report.supported_mappings) >= 1
    assert report.sequence is not None
    assert len(report.tactic_timeline) >= 1
