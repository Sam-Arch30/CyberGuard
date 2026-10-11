"""
Section 74: Automated Deployment & Infrastructure Test Suite.
Validates environment separation, startup configuration validation, health probes,
database backup and restore integrity, Dockerfile non-root security, and deployment smoke tests.
"""
import gzip
import json
import os
import sqlite3
import tempfile
import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch

from backend.main import app
from backend.config.deployment_config import (
    DeploymentConfig,
    EnvironmentEnum,
    ConfigurationValidationError,
    DatabaseConfig,
    AuthSecurityConfig,
    CorsConfig,
    global_deployment_config,
)
from scripts.backup_database import run_backup, compute_sha256
from scripts.restore_database import run_restore, verify_backup_integrity
from scripts.smoke_test import run_smoke_tests


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


# ===========================================================================
# 1. Environment Separation & Startup Configuration Validation Tests
# ===========================================================================

def test_development_configuration_defaults():
    """Verify development environment loads successfully with sensible defaults."""
    with patch.dict(os.environ, {"CYBERGUARD_ENV": "DEVELOPMENT", "DEBUG": "true"}, clear=False):
        cfg = DeploymentConfig.load()
        assert cfg.environment == EnvironmentEnum.DEVELOPMENT
        assert cfg.debug_mode is True
        assert cfg.database.url is not None
        assert cfg.auth.jwt_secret is not None
        assert cfg.cors.has_wildcard is False


def test_production_rejects_debug_mode():
    """Verify production strictly forbids DEBUG=true."""
    with patch.dict(os.environ, {"CYBERGUARD_ENV": "PRODUCTION", "DEBUG": "true"}, clear=False):
        with pytest.raises(ConfigurationValidationError) as exc:
            DeploymentConfig.load()
        assert "DEBUG mode cannot be enabled in PRODUCTION" in str(exc.value)


def test_production_rejects_weak_secrets():
    """Verify production strictly forbids missing or weak signing secrets."""
    with patch.dict(os.environ, {
        "CYBERGUARD_ENV": "PRODUCTION",
        "DEBUG": "false",
        "CYBERGUARD_AUTH_SECRET": "short_secret",
        "DATABASE_URL": "postgresql://usr:pwd@localhost:5432/cyberguard"
    }, clear=False):
        with pytest.raises(ConfigurationValidationError) as exc:
            DeploymentConfig.load()
        assert "at least 32 characters" in str(exc.value)


def test_production_rejects_sqlite():
    """Verify production strictly forbids SQLite databases."""
    with patch.dict(os.environ, {
        "CYBERGUARD_ENV": "PRODUCTION",
        "DEBUG": "false",
        "CYBERGUARD_AUTH_SECRET": "a" * 32,
        "DATABASE_URL": "sqlite:///backend/data/test.db"
    }, clear=False):
        with pytest.raises(ConfigurationValidationError) as exc:
            DeploymentConfig.load()
        assert "SQLite is strictly forbidden in PRODUCTION" in str(exc.value)


def test_production_rejects_wildcard_cors():
    """Verify production strictly forbids wildcard CORS origins."""
    with patch.dict(os.environ, {
        "CYBERGUARD_ENV": "PRODUCTION",
        "DEBUG": "false",
        "CYBERGUARD_AUTH_SECRET": "a" * 32,
        "DATABASE_URL": "postgresql://usr:pwd@localhost:5432/cyberguard",
        "CORS_ORIGINS": "https://cyberguard.local,*"
    }, clear=False):
        with pytest.raises(ConfigurationValidationError) as exc:
            DeploymentConfig.load()
        assert "Wildcard ('*') in CORS_ORIGINS is strictly forbidden" in str(exc.value)


def test_secret_masking_helper():
    """Verify secret values are masked for safe observability."""
    cfg = DeploymentConfig.load()
    masked = cfg.mask_secret("very_secret_production_key_12345678")
    assert masked.startswith("ver...")
    assert masked.endswith("678")
    assert "production" not in masked


# ===========================================================================
# 2. Health, Liveness, Readiness & Version Probes Tests
# ===========================================================================

def test_liveness_probe_endpoint(client):
    """Verify GET /health/live returns HTTP 200 with uptime and healthy status."""
    resp = client.get("/health/live")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "HEALTHY"
    assert data["probe"] == "liveness"
    assert data["uptime_seconds"] >= 0


def test_readiness_probe_endpoint(client):
    """Verify GET /health/ready returns HTTP 200 with ready=True."""
    resp = client.get("/health/ready")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "HEALTHY"
    assert data["ready"] is True


def test_dependencies_health_matrix_endpoint(client):
    """Verify GET /health/dependencies returns structured subsystem matrix."""
    resp = client.get("/health/dependencies")
    assert resp.status_code in (200, 503)
    data = resp.json()
    assert "subsystems" in data
    assert "overall_status" in data
    subsystems = data["subsystems"]
    assert "database" in subsystems
    assert "evidence_storage" in subsystems
    assert "background_worker" in subsystems
    assert "cache" in subsystems


def test_version_metadata_endpoint(client):
    """Verify GET /api/version returns public metadata without leaking secrets."""
    resp = client.get("/api/version")
    assert resp.status_code == 200
    data = resp.json()
    assert data["service"] == "cyberguard"
    assert "version" in data
    assert "environment" in data
    assert "build_sha" in data
    # Ensure no secrets leak in public metadata
    raw_text = resp.text.lower()
    assert "password" not in raw_text
    assert "jwt_secret" not in raw_text


def test_legacy_health_endpoint(client):
    """Verify backward compatibility on legacy /health route."""
    resp = client.get("/health")
    assert resp.status_code in (200, 503)
    data = resp.json()
    assert "status" in data


# ===========================================================================
# 3. Database Backup & Restore Utility Tests
# ===========================================================================

def test_sqlite_database_backup_and_integrity():
    """Verify backup_database script generates atomic compressed archive and manifest."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a sample SQLite DB with test records
        db_path = os.path.join(tmpdir, "source.db")
        conn = sqlite3.connect(db_path)
        conn.execute("CREATE TABLE test_cases (id TEXT PRIMARY KEY, title TEXT);")
        conn.execute("INSERT INTO test_cases VALUES ('1', 'Phishing Incident A');")
        conn.commit()
        conn.close()

        backup_dir = os.path.join(tmpdir, "backups")
        db_url = f"sqlite:///{db_path}"

        # Run backup
        manifest = run_backup(db_url, backup_dir)
        assert manifest["integrity_verified"] is True
        archive_path = manifest["archive_path"]
        assert os.path.exists(archive_path)

        # Verify computed SHA-256 matches
        computed_sha = compute_sha256(archive_path)
        assert computed_sha == manifest["sha256"]

        # Verify integrity check passes
        verified = verify_backup_integrity(archive_path)
        assert verified["sha256"] == computed_sha


def test_database_restore_with_integrity_verification():
    """Verify restore_database script verifies integrity and restores schema."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # 1. Create source DB
        src_path = os.path.join(tmpdir, "src.db")
        conn = sqlite3.connect(src_path)
        conn.execute("CREATE TABLE cases (id TEXT PRIMARY KEY, title TEXT);")
        conn.execute("INSERT INTO cases VALUES ('c-100', 'Case Investigation 100');")
        conn.commit()
        conn.close()

        # 2. Create backup
        backup_dir = os.path.join(tmpdir, "backups")
        manifest = run_backup(f"sqlite:///{src_path}", backup_dir)
        archive_path = manifest["archive_path"]

        # 3. Restore into new target database
        target_path = os.path.join(tmpdir, "restored.db")
        target_url = f"sqlite:///{target_path}"
        report = run_restore(archive_path, target_url)

        assert report["status"] == "RESTORE_SUCCESSFUL"
        assert os.path.exists(target_path)

        # 4. Verify target contains the restored record
        conn_res = sqlite3.connect(target_path)
        cursor = conn_res.cursor()
        cursor.execute("SELECT title FROM cases WHERE id='c-100';")
        row = cursor.fetchone()
        conn_res.close()
        assert row is not None
        assert row[0] == "Case Investigation 100"


def test_restore_rejects_corrupted_backup():
    """Verify restore utility aborts if cryptographic SHA-256 integrity fails."""
    with tempfile.TemporaryDirectory() as tmpdir:
        src_path = os.path.join(tmpdir, "src.db")
        conn = sqlite3.connect(src_path)
        conn.execute("CREATE TABLE test_tab (id INT);")
        conn.commit()
        conn.close()

        backup_dir = os.path.join(tmpdir, "backups")
        manifest = run_backup(f"sqlite:///{src_path}", backup_dir)
        archive_path = manifest["archive_path"]

        # Tamper with the archive file
        with open(archive_path, "ab") as f:
            f.write(b"CORRUPTED_BYTES")

        target_path = os.path.join(tmpdir, "corrupt_target.db")
        with pytest.raises(ValueError) as exc:
            run_restore(archive_path, f"sqlite:///{target_path}")
        assert "integrity check FAILED" in str(exc.value)


# ===========================================================================
# 4. Dockerfile & Container Hardening Structure Tests
# ===========================================================================

def test_dockerfile_multi_stage_and_non_root():
    """Verify backend/Dockerfile enforces multi-stage build and unprivileged user."""
    dockerfile_path = "backend/Dockerfile"
    assert os.path.exists(dockerfile_path)

    with open(dockerfile_path, "r") as f:
        content = f.read()

    # Multi-stage check
    assert "AS builder" in content
    assert "AS runtime" in content

    # Non-root user check
    assert "groupadd -g 10001 cyberguard" in content
    assert "useradd -u 10001" in content
    assert "USER cyberguard" in content

    # Health check probe configured
    assert "HEALTHCHECK" in content
    assert "/health/live" in content


def test_docker_compose_security_configuration():
    """Verify docker-compose.yml defines network isolation and persistent volumes."""
    compose_path = "docker-compose.yml"
    assert os.path.exists(compose_path)

    with open(compose_path, "r") as f:
        content = f.read()

    assert "backend_internal_net" in content
    assert "frontend_net" in content
    assert "cyberguard-backend" in content
    assert "cyberguard-worker" in content
    assert "cyberguard-postgresql" in content
    assert "/health/ready" in content


def test_docker_compose_prod_override():
    """Verify docker-compose.prod.yml disables public DB port and sets resource limits."""
    prod_compose_path = "docker-compose.prod.yml"
    assert os.path.exists(prod_compose_path)

    with open(prod_compose_path, "r") as f:
        content = f.read()

    assert "ports: !reset []" in content
    assert "resources:" in content
    assert "limits:" in content
    assert "CYBERGUARD_ENV: PRODUCTION" in content


def test_smoke_test_runner_logic():
    """Verify smoke test runner evaluates liveness, readiness, dependencies, and version."""
    from scripts.smoke_test import run_smoke_tests

    # Mock responses for the 7 endpoints
    def mock_make_request(url, method="GET", data=None, headers=None):
        if url.endswith("/health/live"):
            return 200, {"status": "HEALTHY"}
        elif url.endswith("/health/ready"):
            return 200, {"ready": True}
        elif url.endswith("/health/dependencies"):
            return 200, {"overall_status": "HEALTHY"}
        elif url.endswith("/api/version"):
            return 200, {"version": "1.0.0", "environment": "TESTING"}
        elif url.endswith("/health"):
            return 200, {"status": "ok"}
        elif url.endswith("/api/admin/performance/metrics"):
            return 200, {"categories": {}}
        elif url.endswith("/api/admin/performance/circuits"):
            return 200, {"circuits": []}
        elif url.endswith("/api/demo/scenarios"):
            return 200, {"status": "SUCCESS", "count": 4}
        elif url.endswith("/api/demo/status"):
            return 200, {"environment_mode": "DEMO_READY"}
        return 404, {"error": "Not Found"}

    with patch("scripts.smoke_test.make_request", side_effect=mock_make_request):
        report = run_smoke_tests("http://mock-cyberguard:8000")
        assert report["overall_status"] == "PASS"
        assert report["total_checks"] == 9
        assert report["passed_checks"] == 9
        assert report["failed_checks"] == 0

