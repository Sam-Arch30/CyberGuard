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
    assert data["service"] == "cybersecurity-email-parser"
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


def test_init_db_retry_success():
    """Verify init_db retries on initial failure and succeeds on subsequent attempt."""
    call_count = 0

    def mock_connect():
        nonlocal call_count
        call_count += 1
        if call_count < 2:
            raise OperationalError("starting up", {}, Exception("starting up"))
        mock_conn = MagicMock()
        return mock_conn

    with patch("backend.db.session.engine.connect", side_effect=mock_connect):
        with patch("backend.db.session.Base.metadata.create_all"):
            success = init_db(max_retries=3, retry_delay=0.01)
            assert success is True
            assert call_count == 2


def test_init_db_exhausted_retries_raises():
    """Verify init_db raises OperationalError when all retries are exhausted."""
    with patch("backend.db.session.engine.connect") as mock_connect:
        mock_connect.side_effect = OperationalError("failed to connect", {}, Exception("timeout"))
        with pytest.raises(OperationalError):
            init_db(max_retries=2, retry_delay=0.01)
