import os
import unittest
from unittest.mock import patch, MagicMock
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError

from backend.main import app
from backend.db.session import init_db

client = TestClient(app)


def test_health_endpoint_healthy():
    """Verify GET /health returns 200 and healthy status when database is reachable."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "cyberguard"
    assert data["database"] == "ok"


def test_health_endpoint_degraded_when_db_down():
    """Verify GET /health returns 503 and degraded status when database is unreachable."""
    with patch("backend.main.engine.connect") as mock_connect:
        mock_connect.side_effect = OperationalError("connection refused", {}, Exception("DB down"))
        response = client.get("/health")
        assert response.status_code == 503
        data = response.json()
        assert data["status"] == "degraded"
        assert "unhealthy" in data["database"]


def test_init_db_retry_success(tmp_path, caplog):
    """Retry a failed connection, then create and inspect a real isolated schema."""
    from sqlalchemy import create_engine, inspect
    isolated = create_engine('sqlite:///' + (tmp_path / 'retry.db').as_posix())
    real_connect = isolated.connect
    call_count = 0

    def connect():
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise OperationalError('starting up', {}, Exception('starting up'))
        return real_connect()

    try:
        with patch('backend.db.session.engine', isolated), patch.object(isolated, 'connect', side_effect=connect):
            success = init_db(max_retries=3, retry_delay=0.01)
        assert success is True
        assert call_count == 4  # Failed attempt, retry, create_all, additive schema transaction.
        assert len([r for r in caplog.records if 'Database not ready (attempt 1/3)' in r.message]) == 1
        assert 'artifacts' in inspect(isolated).get_table_names()
        assert 'workspace_id' in {column['name'] for column in inspect(isolated).get_columns('artifacts')}
    finally:
        isolated.dispose()


def test_init_db_exhausted_retries_raises():
    """Verify init_db raises OperationalError when all retries are exhausted."""
    with patch("backend.db.session.engine.connect") as mock_connect:
        mock_connect.side_effect = OperationalError("failed to connect", {}, Exception("timeout"))
        with pytest.raises(OperationalError):
            init_db(max_retries=2, retry_delay=0.01)
