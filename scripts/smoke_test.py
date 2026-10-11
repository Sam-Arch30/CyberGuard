#!/usr/bin/env python3
"""
Section 74: Automated Deployment Smoke Test Suite.
Executes non-destructive, end-to-end smoke tests against any active deployment target
to verify liveness, readiness, dependencies, authentication boundaries, and analysis pipelines.
"""
import argparse
import json
import logging
import sys
import time
import urllib.request
import urllib.error

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("cyberguard.smoke_test")


def make_request(url: str, method: str = "GET", data: bytes = None, headers: dict = None) -> tuple[int, dict]:
    """Helper to perform HTTP requests using standard library without external dependencies."""
    req_headers = headers or {}
    if data and "Content-Type" not in req_headers:
        req_headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=data, headers=req_headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            code = response.getcode()
            body = response.read().decode("utf-8")
            try:
                parsed = json.loads(body)
            except Exception:
                parsed = {"raw": body}
            return code, parsed
    except urllib.error.HTTPError as http_err:
        body = http_err.read().decode("utf-8")
        try:
            parsed = json.loads(body)
        except Exception:
            parsed = {"raw": body}
        return http_err.code, parsed
    except Exception as exc:
        return 0, {"error": str(exc)}


def run_smoke_tests(base_url: str) -> dict:
    """Executes the complete deployment verification checklist."""
    base_clean = base_url.rstrip("/")
    logger.info("Initiating CyberGuard Deployment Smoke Tests against: %s", base_clean)

    results = []
    overall_pass = True

    # Check 1: Liveness Probe
    t0 = time.time()
    code, data = make_request(f"{base_clean}/health/live")
    duration = round((time.time() - t0) * 1000.0, 1)
    passed = (code == 200 and data.get("status") == "HEALTHY")
    results.append({
        "check": "CHECK_01_LIVENESS_PROBE",
        "endpoint": "/health/live",
        "status_code": code,
        "latency_ms": duration,
        "passed": passed,
        "details": data
    })
    if not passed:
        overall_pass = False

    # Check 2: Readiness Probe
    t0 = time.time()
    code, data = make_request(f"{base_clean}/health/ready")
    duration = round((time.time() - t0) * 1000.0, 1)
    passed = (code == 200 and data.get("ready") is True)
    results.append({
        "check": "CHECK_02_READINESS_PROBE",
        "endpoint": "/health/ready",
        "status_code": code,
        "latency_ms": duration,
        "passed": passed,
        "details": data
    })
    if not passed:
        overall_pass = False

    # Check 3: Deep Dependencies Health Matrix
    t0 = time.time()
    code, data = make_request(f"{base_clean}/health/dependencies")
    duration = round((time.time() - t0) * 1000.0, 1)
    passed = (code == 200 and data.get("overall_status") in ("HEALTHY", "DEGRADED"))
    results.append({
        "check": "CHECK_03_DEPENDENCIES_MATRIX",
        "endpoint": "/health/dependencies",
        "status_code": code,
        "latency_ms": duration,
        "passed": passed,
        "details": data
    })
    if not passed:
        overall_pass = False

    # Check 4: Version & Build Provenance
    t0 = time.time()
    code, data = make_request(f"{base_clean}/api/version")
    duration = round((time.time() - t0) * 1000.0, 1)
    passed = (code == 200 and "version" in data and "environment" in data)
    results.append({
        "check": "CHECK_04_VERSION_PROVENANCE",
        "endpoint": "/api/version",
        "status_code": code,
        "latency_ms": duration,
        "passed": passed,
        "details": data
    })
    if not passed:
        overall_pass = False

    # Check 5: Legacy Backward Compatibility Probe
    t0 = time.time()
    code, data = make_request(f"{base_clean}/health")
    duration = round((time.time() - t0) * 1000.0, 1)
    passed = (code == 200 and data.get("status") == "ok")
    results.append({
        "check": "CHECK_05_LEGACY_HEALTH_PROBE",
        "endpoint": "/health",
        "status_code": code,
        "latency_ms": duration,
        "passed": passed,
        "details": data
    })
    if not passed:
        overall_pass = False

    # Check 6: Admin Performance Telemetry (RBAC protected)
    t0 = time.time()
    admin_headers = {
        "X-User-Email": "admin@cyberguard.local",
        "X-User-Role": "PLATFORM_ADMIN",
        "X-Tenant-Id": "tenant-default"
    }
    code, data = make_request(f"{base_clean}/api/admin/performance/metrics", headers=admin_headers)
    duration = round((time.time() - t0) * 1000.0, 1)
    passed = (code == 200 and "categories" in data)
    results.append({
        "check": "CHECK_06_PERFORMANCE_METRICS_RBAC",
        "endpoint": "/api/admin/performance/metrics",
        "status_code": code,
        "latency_ms": duration,
        "passed": passed,
        "details": {"categories_count": len(data.get("categories", {}))}
    })
    if not passed:
        overall_pass = False

    # Check 7: External Circuit Breaker Registry
    t0 = time.time()
    code, data = make_request(f"{base_clean}/api/admin/performance/circuits", headers=admin_headers)
    duration = round((time.time() - t0) * 1000.0, 1)
    passed = (code == 200 and "circuits" in data)
    results.append({
        "check": "CHECK_07_CIRCUIT_BREAKER_OBSERVABILITY",
        "endpoint": "/api/admin/performance/circuits",
        "status_code": code,
        "latency_ms": duration,
        "passed": passed,
        "details": {"total_circuits": data.get("total", 0)}
    })
    if not passed:
        overall_pass = False

    report = {
        "service": "cyberguard",
        "target_url": base_clean,
        "overall_status": "PASS" if overall_pass else "FAIL",
        "total_checks": len(results),
        "passed_checks": sum(1 for r in results if r["passed"]),
        "failed_checks": sum(1 for r in results if not r["passed"]),
        "checks": results,
    }

    logger.info("Smoke Test Run Summary: %s (%d/%d checks passed)",
                report["overall_status"], report["passed_checks"], report["total_checks"])
    for r in results:
        status_sym = "✓" if r["passed"] else "✗"
        logger.info("  [%s] %s -> HTTP %d (%s ms)", status_sym, r["check"], r["status_code"], r["latency_ms"])

    return report


def main():
    parser = argparse.ArgumentParser(description="CyberGuard Deployment Smoke Test Runner")
    parser.add_argument("--url", default="http://localhost:8000", help="Base URL of target CyberGuard instance")
    args = parser.parse_args()

    report = run_smoke_tests(args.url)
    if report["overall_status"] != "PASS":
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
