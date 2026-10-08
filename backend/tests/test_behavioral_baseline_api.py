"""
REST API Route Integration Tests for Behavioral Baseline Engine (Section 21).
Covers endpoints for baseline retrieval, freezing, unfreezing, relearning, exceptions, and deviation evaluation.
"""
import pytest
from datetime import datetime, timezone, timedelta
import json
import uuid
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.main import app
from backend.db.session import Base, get_db
from sqlalchemy.pool import StaticPool
from backend.db.models import (
    BehavioralBaselineModel,
    BehavioralDeviationModel,
    SecurityEventModel,
)


@pytest.fixture
def client_and_session():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    TestingSessionLocal = sessionmaker(bind=engine)
    session = TestingSessionLocal()

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)
    yield client, session
    app.dependency_overrides.clear()
    session.close()


def test_api_01_get_and_build_baseline(client_and_session):
    client, session = client_and_session
    now = datetime.now(timezone.utc)

    # Add historical events
    for i in range(15):
        ev = SecurityEventModel(
            id=str(uuid.uuid4()),
            event_type="AUTH_SUCCESS",
            event_time=(now - timedelta(days=i)).replace(hour=10, minute=0),
            source_type="AUTH",
            attributes_json=json.dumps({"account_id": "test_user", "ip": "192.0.2.10"}),
        )
        session.add(ev)
    session.commit()

    # Pre-build baseline in DB
    from backend.services.behavioral_baseline_service import BehavioralBaselineService
    from backend.schemas.behavioral_baseline import BaselineEntityType, BaselineMetricType
    BehavioralBaselineService.build_baseline(
        session=session,
        entity_type=BaselineEntityType.ACCOUNT,
        entity_id="test_user",
        metric_type=BaselineMetricType.LOGIN_HOUR,
    )

    res = client.get("/api/v1/entities/ACCOUNT/test_user/baseline")
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)
    assert len(data) >= 1
    assert data[0]["entity_id"] == "test_user"


def test_api_02_freeze_and_unfreeze_baseline(client_and_session):
    client, session = client_and_session
    b = BehavioralBaselineModel(
        id=str(uuid.uuid4()),
        workspace_id="default",
        entity_type="ACCOUNT",
        entity_id="frozen_user",
        metric_type="LOGIN_HOUR",
        sample_count=20,
    )
    session.add(b)
    session.commit()

    # Freeze
    res_freeze = client.post(
        "/api/v1/entities/ACCOUNT/frozen_user/baseline/freeze",
        json={"actor": "analyst_bob", "reason": "Suspected breach INC-900"},
    )
    assert res_freeze.status_code == 200
    frozen_data = res_freeze.json()
    assert frozen_data[0]["is_frozen"] is True
    assert frozen_data[0]["learning_mode"] == "FROZEN"

    # Unfreeze
    res_unfreeze = client.post(
        "/api/v1/entities/ACCOUNT/frozen_user/baseline/unfreeze",
        json={"actor": "analyst_bob", "reason": "Incident contained and resolved"},
    )
    assert res_unfreeze.status_code == 200
    unfrozen_data = res_unfreeze.json()
    assert unfrozen_data[0]["is_frozen"] is False
    assert unfrozen_data[0]["learning_mode"] == "STABLE"


def test_api_03_relearn_baseline(client_and_session):
    client, session = client_and_session
    b = BehavioralBaselineModel(
        id=str(uuid.uuid4()),
        workspace_id="default",
        entity_type="ACCOUNT",
        entity_id="relearn_user",
        metric_type="LOGIN_HOUR",
        sample_count=20,
    )
    session.add(b)
    session.commit()

    res = client.post(
        "/api/v1/entities/ACCOUNT/relearn_user/baseline/relearn",
        json={"actor": "analyst_bob", "reason": "Permanent role change to night shift", "window_days": 14},
    )
    assert res.status_code == 200


def test_api_04_register_exception(client_and_session):
    client, session = client_and_session
    res = client.post(
        "/api/v1/entities/ACCOUNT/travel_user/exceptions",
        json={
            "reason": "Authorized overseas summit in Tokyo",
            "approved_by": "CISO",
            "valid_from": datetime.now(timezone.utc).isoformat(),
            "valid_until": (datetime.now(timezone.utc) + timedelta(days=7)).isoformat(),
            "metric_type": "LOGIN_LOCATION",
        },
    )
    assert res.status_code == 200
    assert res.json()["status"] == "registered"


def test_api_05_evaluate_deviation_endpoint(client_and_session):
    client, session = client_and_session
    now = datetime.now(timezone.utc)

    # 20 historical morning events
    for i in range(20):
        ev = SecurityEventModel(
            id=str(uuid.uuid4()),
            event_type="AUTH_SUCCESS",
            event_time=(now - timedelta(days=i)).replace(hour=9, minute=0),
            source_type="AUTH",
            attributes_json=json.dumps({"account_id": "eval_user", "ip": "192.0.2.1"}),
        )
        session.add(ev)
    session.commit()

    # Query deviation for 03:00 AM (anomalous)
    res = client.post(
        "/api/v1/baselines/evaluate-deviation",
        json={
            "entity_type": "ACCOUNT",
            "entity_id": "eval_user",
            "metric_type": "LOGIN_HOUR",
            "observed_value": 3.0,
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["is_anomalous"] is True
    assert data["deviation"]["deviation_score"] >= 0.40


def test_api_06_get_investigation_deviations(client_and_session):
    client, session = client_and_session
    inv_id = str(uuid.uuid4())
    dev = BehavioralDeviationModel(
        id=str(uuid.uuid4()),
        investigation_id=inv_id,
        workspace_id="default",
        entity_type="ACCOUNT",
        entity_id="alice",
        metric_type="LOGIN_HOUR",
        observed_value="03:15",
        expected_range_summary="09:00–18:00",
        deviation_score=0.85,
        deviation_direction="BELOW_NORMAL",
        severity_hint="HIGH",
        explanation="Login occurred 6 hours outside normal hours.",
    )
    session.add(dev)
    session.commit()

    res = client.get(f"/api/v1/investigations/{inv_id}/behavioral-deviations")
    assert res.status_code == 200
    data = res.json()
    assert len(data) == 1
    assert data[0]["entity_id"] == "alice"
    assert data[0]["deviation_score"] == 0.85
