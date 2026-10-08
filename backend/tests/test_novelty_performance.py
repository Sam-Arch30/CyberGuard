"""
Performance and Scalability Tests for Novelty Engine (Section 22).

Verifies sub-quadratic execution time, bounded candidate comparisons,
and search limit metrics enforcement under heavy pattern volume.
"""
import pytest
import time
from datetime import datetime, timezone
import json
import uuid
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.db.session import Base
from backend.db.models import PatternFingerprintModel
from backend.schemas.novelty_detection import NoveltyCategory, NoveltyEvaluationRequest
from backend.services.novelty_detection_service import NoveltyDetectionService
from backend.config.novelty_config import DEFAULT_NOVELTY_CONFIG


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


def test_perf_01_bounded_candidate_evaluation(db_session):
    """
    Evaluates that even with 500 stored patterns, evaluation remains bounded
    by MAX_SIMILARITY_CANDIDATES and completes within milliseconds.
    """
    now = datetime.now(timezone.utc)
    # Seed 500 historical fingerprints
    seed_records = []
    for i in range(500):
        seed_records.append(PatternFingerprintModel(
            id=str(uuid.uuid4()),
            workspace_id="default",
            pattern_type=NoveltyCategory.NOVEL_API_BEHAVIOR.value,
            fingerprint_hash=f"hash_{i:04d}",
            fingerprint_repr=f"API:GET /api/v1/resource_{i} | res=res_{i}",
            attributes_json=json.dumps({
                "method": "GET",
                "route_template": f"/api/v1/resource_{i}",
                "resource_type": f"res_{i}",
            }),
            first_seen_at=now,
            last_seen_at=now,
            observation_count=1 + (i % 5),
        ))
    db_session.bulk_save_objects(seed_records)
    db_session.commit()

    # Time evaluation of a new pattern
    req = NoveltyEvaluationRequest(
        entity_type="SERVICE",
        entity_id="test-service",
        novelty_type=NoveltyCategory.NOVEL_API_BEHAVIOR,
        attributes={"method": "GET", "path": "/api/v1/resource_999", "resource_type": "res_999"},
    )

    start = time.perf_counter()
    res = NoveltyDetectionService.evaluate_pattern(session=db_session, request=req)
    elapsed = time.perf_counter() - start

    # Should execute in under 200 milliseconds thanks to candidate bounds
    assert elapsed < 0.20
    # Candidate comparison was bounded
    assert res.assessment.historical_sample_count <= DEFAULT_NOVELTY_CONFIG.MAX_SIMILARITY_CANDIDATES
