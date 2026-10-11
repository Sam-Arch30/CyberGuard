"""
Section 74: Dedicated Health, Liveness, Readiness & Dependency Health Endpoints.
Implements canonical Kubernetes / Cloud Container probes:
- /health/live: Liveness probe (process responsiveness)
- /health/ready: Readiness probe (traffic ingress capability)
- /health/dependencies: Deep dependency status matrix
- /api/version: Deployment metadata & build provenance
"""
from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, status
from fastapi.responses import JSONResponse
from sqlalchemy import text

from backend.db.session import engine
from backend.config.deployment_config import global_deployment_config
from backend.services.evidence_storage import evidence_storage
from backend.services.circuit_breaker import CircuitBreakerRegistry
from backend.services.cache_service import global_cache_manager

router = APIRouter(tags=["Deployment & Health"])

PROCESS_START_TIME = time.time()


class HealthStatusEnum(str, Enum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    UNAVAILABLE = "UNAVAILABLE"
    UNKNOWN = "UNKNOWN"


@router.get("/health/live", summary="Container liveness probe")
async def liveness_probe():
    """
    Answers: Is this process alive and responsive?
    Does NOT depend on external databases or remote services.
    """
    uptime = max(0.0, round(time.time() - PROCESS_START_TIME, 2))
    return {
        "status": HealthStatusEnum.HEALTHY.value,
        "probe": "liveness",
        "service": "cyberguard",
        "uptime_seconds": uptime,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/health/ready", summary="Container readiness probe")
async def readiness_probe():
    """
    Answers: Can this instance safely accept and process client traffic?
    Checks database read/write connectivity and primary storage root accessibility.
    """
    errors: List[str] = []

    # 1. Database readiness check
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception as db_err:
        errors.append(f"Database unavailable: {str(db_err)}")

    # 2. Storage root writeability check
    try:
        storage_root = global_deployment_config.storage.storage_root
        if not os.path.exists(storage_root):
            os.makedirs(storage_root, exist_ok=True)
        # Test file creation and immediate deletion
        test_file = os.path.join(storage_root, ".readiness_probe.tmp")
        with open(test_file, "w") as f:
            f.write("probe")
        if os.path.exists(test_file):
            os.remove(test_file)
    except Exception as storage_err:
        errors.append(f"Storage unavailable: {str(storage_err)}")

    if errors:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "status": HealthStatusEnum.UNAVAILABLE.value,
                "probe": "readiness",
                "ready": False,
                "errors": errors,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )

    return {
        "status": HealthStatusEnum.HEALTHY.value,
        "probe": "readiness",
        "ready": True,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/health/dependencies", summary="Detailed dependency health matrix")
async def dependency_health_matrix():
    """
    Provides detailed health and diagnostic status across all application subsystems:
    - Database
    - Evidence Object Storage
    - Background Worker Queue
    - Realtime Hub
    - Multi-Tenant Cache
    - External Provider Circuit Breakers
    """
    subsystems: Dict[str, Dict[str, Any]] = {}
    overall_status = HealthStatusEnum.HEALTHY

    # 1. Database
    try:
        t0 = time.perf_counter()
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        latency_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        subsystems["database"] = {
            "status": HealthStatusEnum.HEALTHY.value,
            "driver": "sqlite" if global_deployment_config.database.is_sqlite else "postgresql",
            "latency_ms": latency_ms,
        }
    except Exception as err:
        overall_status = HealthStatusEnum.UNAVAILABLE
        subsystems["database"] = {
            "status": HealthStatusEnum.UNAVAILABLE.value,
            "error": str(err),
        }

    # 2. Evidence Storage
    try:
        storage_root = global_deployment_config.storage.storage_root
        accessible = os.path.isdir(storage_root) and os.access(storage_root, os.W_OK)
        subsystems["evidence_storage"] = {
            "status": HealthStatusEnum.HEALTHY.value if accessible else HealthStatusEnum.DEGRADED.value,
            "storage_root": storage_root,
            "writable": accessible,
        }
        if not accessible and overall_status != HealthStatusEnum.UNAVAILABLE:
            overall_status = HealthStatusEnum.DEGRADED
    except Exception as err:
        subsystems["evidence_storage"] = {
            "status": HealthStatusEnum.DEGRADED.value,
            "error": str(err),
        }

    # 3. Background Job Worker
    worker_cfg = global_deployment_config.worker
    subsystems["background_worker"] = {
        "status": HealthStatusEnum.HEALTHY.value if worker_cfg.enabled else HealthStatusEnum.DEGRADED.value,
        "enabled": worker_cfg.enabled,
        "concurrency": worker_cfg.concurrency,
    }

    # 4. Multi-Tenant Cache
    try:
        cache_stats = global_cache_manager.get_stats()
        subsystems["cache"] = {
            "status": HealthStatusEnum.HEALTHY.value,
            "active_entries": cache_stats.get("active_entries", 0),
            "hit_rate_percent": cache_stats.get("hit_rate_percent", 0.0),
        }
    except Exception as err:
        subsystems["cache"] = {
            "status": HealthStatusEnum.DEGRADED.value,
            "error": str(err),
        }

    # 5. External Provider Circuit Breakers
    try:
        circuit_statuses = CircuitBreakerRegistry.get_all_statuses()
        open_circuits = [c["service_name"] for c in circuit_statuses if c.get("state") == "OPEN"]
        subsystems["external_circuits"] = {
            "status": HealthStatusEnum.DEGRADED.value if open_circuits else HealthStatusEnum.HEALTHY.value,
            "total_registered": len(circuit_statuses),
            "open_circuits": open_circuits,
        }
        if open_circuits and overall_status == HealthStatusEnum.HEALTHY:
            overall_status = HealthStatusEnum.DEGRADED
    except Exception as err:
        subsystems["external_circuits"] = {
            "status": HealthStatusEnum.UNKNOWN.value,
            "error": str(err),
        }

    http_code = (
        status.HTTP_200_OK
        if overall_status in (HealthStatusEnum.HEALTHY, HealthStatusEnum.DEGRADED)
        else status.HTTP_503_SERVICE_UNAVAILABLE
    )

    return JSONResponse(
        status_code=http_code,
        content={
            "overall_status": overall_status.value,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "environment": global_deployment_config.environment.value,
            "subsystems": subsystems,
        }
    )


@router.get("/api/version", summary="Safe application build & deployment version metadata")
async def deployment_version_metadata():
    """Returns safe build provenance metadata without exposing internal secrets."""
    return global_deployment_config.get_public_metadata()


# Backward-compatible legacy health check routes
@router.get("/health", summary="Legacy health probe")
@router.get("/api/health", summary="Legacy health probe")
async def legacy_health_probe():
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception as exc:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "status": "degraded",
                "service": "cyberguard",
                "database": f"unhealthy: {str(exc)}"
            }
        )

    return {
        "status": "ok",
        "service": "cyberguard",
        "database": "ok",
        "environment": global_deployment_config.environment.value,
        "version": global_deployment_config.version,
    }
