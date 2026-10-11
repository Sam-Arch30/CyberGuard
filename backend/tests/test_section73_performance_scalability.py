"""
Section 73: Performance & Scalability Test Suite.
Validates latency percentiles (p50, p95, p99), performance budgets, slow-operation detection,
resilient 3-state circuit breakers, safe multi-tenant caching, and database composite indexes.
"""
import time
import pytest
from unittest.mock import MagicMock, patch

from backend.services.performance_service import (
    PerformanceMetricsTracker,
    PerformanceCategoryEnum,
    DEFAULT_PERFORMANCE_BUDGETS,
    ExecutionTimer,
    global_performance_tracker,
)
from backend.services.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitState,
    CircuitBreakerOpenException,
    CircuitBreakerRegistry,
)
from backend.services.cache_service import (
    MultiTenantCacheManager,
    global_cache_manager,
)
from backend.db.models import CaseModel, IncidentModel, EvidenceModel


# ===========================================================================
# 1. Performance Metrics Tracker & Percentiles Tests
# ===========================================================================

def test_performance_metrics_percentiles_calculation():
    """Verify p50, p95, p99 percentiles are mathematically computed accurately."""
    tracker = PerformanceMetricsTracker()
    category = PerformanceCategoryEnum.API_REQUEST.value

    # Feed 100 deterministic duration samples: 1ms to 100ms
    for ms in range(1, 101):
        tracker.record_operation(
            category=category,
            operation_name="test_api_call",
            duration_ms=float(ms),
            is_error=False,
            tenant_id="tenant-alpha"
        )

    summary = tracker.get_metrics_summary()
    assert category in summary["categories"]
    cat_metrics = summary["categories"][category]

    assert cat_metrics["total_operations"] == 100
    assert cat_metrics["error_count"] == 0
    assert cat_metrics["error_rate_percent"] == 0.0

    # For 1..100: p50 should be ~50ms, p95 ~95ms, p99 ~99ms
    assert 48.0 <= cat_metrics["latency_p50_ms"] <= 52.0
    assert 93.0 <= cat_metrics["latency_p95_ms"] <= 97.0
    assert 97.0 <= cat_metrics["latency_p99_ms"] <= 100.0

    # Verify budget comparison
    assert "budget" in cat_metrics
    budget = cat_metrics["budget"]
    assert budget["p95_within_budget"] is True  # Budget is 250ms


def test_performance_metrics_error_rate():
    """Verify error rate tracking and percentage computation."""
    tracker = PerformanceMetricsTracker()
    category = PerformanceCategoryEnum.DATABASE_QUERY.value

    for i in range(10):
        tracker.record_operation(
            category=category,
            operation_name="db_select",
            duration_ms=10.0,
            is_error=(i < 3),  # 3 errors out of 10
            tenant_id="tenant-alpha"
        )

    summary = tracker.get_metrics_summary()
    cat_metrics = summary["categories"][category]
    assert cat_metrics["total_operations"] == 10
    assert cat_metrics["error_count"] == 3
    assert cat_metrics["error_rate_percent"] == 30.0


def test_slow_operation_detection():
    """Verify operations exceeding max_duration_ms budget are logged in ring buffer."""
    tracker = PerformanceMetricsTracker()
    category = PerformanceCategoryEnum.API_REQUEST.value

    # API max budget is 1000ms. Send an operation taking 1500ms
    tracker.record_operation(
        category=category,
        operation_name="slow_export_endpoint",
        duration_ms=1500.0,
        is_error=False,
        tenant_id="tenant-beta",
        details={"path": "/api/export", "query_size": 5000}
    )

    slow_ops = tracker.get_slow_operations(limit=10)
    assert len(slow_ops) >= 1
    slowest = slow_ops[0]
    assert slowest["operation_name"] == "slow_export_endpoint"
    assert slowest["duration_ms"] == 1500.0
    assert slowest["budget_max_ms"] == 1000.0
    assert slowest["tenant_id"] == "tenant-beta"
    assert slowest["details"]["query_size"] == 5000


def test_execution_timer_context_manager():
    """Verify ExecutionTimer records duration accurately."""
    tracker = PerformanceMetricsTracker()
    category = PerformanceCategoryEnum.SEARCH_HUNTING.value

    with ExecutionTimer(
        category=category,
        operation_name="threat_hunt_query",
        tenant_id="tenant-gamma",
        tracker=tracker
    ) as timer:
        time.sleep(0.01)  # sleep 10ms

    summary = tracker.get_metrics_summary()
    assert category in summary["categories"]
    metrics = summary["categories"][category]
    assert metrics["total_operations"] == 1
    assert timer.duration_ms >= 8.0  # At least ~10ms


# ===========================================================================
# 2. Circuit Breaker 3-State Lifecycle Tests
# ===========================================================================

def test_circuit_breaker_closed_to_open_transition():
    """Verify circuit trips from CLOSED to OPEN after consecutive failures threshold."""
    config = CircuitBreakerConfig(
        failure_threshold=3,
        recovery_timeout_seconds=0.1,  # Short recovery for fast testing
        half_open_success_threshold=2
    )
    cb = CircuitBreaker("threat_intel_virustotal", config)
    assert cb.state == CircuitState.CLOSED

    # 2 failures do not trip
    cb.record_failure("HTTP 503")
    cb.record_failure("HTTP 504")
    assert cb.state == CircuitState.CLOSED

    # 3rd failure trips to OPEN
    cb.record_failure("Timeout")
    assert cb.state == CircuitState.OPEN

    # In OPEN state, can_execute returns False
    allowed, retry_after = cb.can_execute()
    assert allowed is False
    assert retry_after is not None

    # Attempting to execute raises CircuitBreakerOpenException
    with pytest.raises(CircuitBreakerOpenException) as excinfo:
        cb.execute(lambda: "never_run")
    assert "OPEN" in str(excinfo.value)


def test_circuit_breaker_recovery_to_half_open_and_closed():
    """Verify circuit transitions OPEN -> HALF_OPEN -> CLOSED on successful probes."""
    config = CircuitBreakerConfig(
        failure_threshold=2,
        recovery_timeout_seconds=0.05,
        half_open_success_threshold=2
    )
    cb = CircuitBreaker("llm_anthropic", config)

    # Trip to OPEN
    cb.record_failure("RateLimit")
    cb.record_failure("RateLimit")
    assert cb.state == CircuitState.OPEN

    # Wait for recovery timeout
    time.sleep(0.06)

    # Status check should transition to HALF_OPEN
    assert cb.state == CircuitState.HALF_OPEN

    # First successful probe
    cb.record_success()
    assert cb.state == CircuitState.HALF_OPEN

    # Second successful probe meets half_open_success_threshold -> recovers to CLOSED
    cb.record_success()
    assert cb.state == CircuitState.CLOSED


def test_circuit_breaker_probe_failure_re_trips_to_open():
    """Verify a probe failure in HALF_OPEN immediately re-trips back to OPEN."""
    config = CircuitBreakerConfig(
        failure_threshold=2,
        recovery_timeout_seconds=0.05,
        half_open_success_threshold=2
    )
    cb = CircuitBreaker("rdap_lookup", config)

    # Trip to OPEN
    cb.record_failure("Error 1")
    cb.record_failure("Error 2")
    assert cb.state == CircuitState.OPEN

    time.sleep(0.06)
    assert cb.state == CircuitState.HALF_OPEN

    # Probe fails -> immediately trips back to OPEN
    cb.record_failure("Probe failed")
    assert cb.state == CircuitState.OPEN


def test_circuit_breaker_manual_reset():
    """Verify manual reset restores CLOSED state."""
    config = CircuitBreakerConfig(failure_threshold=1)
    cb = CircuitBreaker("geo_service", config)
    cb.record_failure("Down")
    assert cb.state == CircuitState.OPEN

    cb.reset()
    assert cb.state == CircuitState.CLOSED
    status = cb.get_status()
    assert status["state"] == "CLOSED"
    assert status["failure_count"] == 0


def test_circuit_breaker_registry():
    """Verify registry manages multiple distinct service breakers."""
    cb1 = CircuitBreakerRegistry.get_breaker("service_one")
    cb2 = CircuitBreakerRegistry.get_breaker("service_two")
    assert cb1.service_name == "service_one"
    assert cb2.service_name == "service_two"

    all_statuses = CircuitBreakerRegistry.get_all_statuses()
    service_names = [s["service_name"] for s in all_statuses]
    assert "service_one" in service_names
    assert "service_two" in service_names


# ===========================================================================
# 3. Safe Multi-Tenant Caching Tests
# ===========================================================================

def test_cache_multi_tenant_isolation():
    """Verify strict tenant isolation: identical keys for different tenants do NOT collide."""
    cache = MultiTenantCacheManager(default_ttl_seconds=60.0)

    # Set value for tenant-alpha
    cache.set(tenant_id="tenant-alpha", category="threat_intel", key="evil.com", value={"reputation": "MALICIOUS"})

    # Set value for tenant-beta
    cache.set(tenant_id="tenant-beta", category="threat_intel", key="evil.com", value={"reputation": "BENIGN_CUSTOM"})

    # Verify alpha gets alpha's value
    val_alpha = cache.get(tenant_id="tenant-alpha", category="threat_intel", key="evil.com")
    assert val_alpha == {"reputation": "MALICIOUS"}

    # Verify beta gets beta's value
    val_beta = cache.get(tenant_id="tenant-beta", category="threat_intel", key="evil.com")
    assert val_beta == {"reputation": "BENIGN_CUSTOM"}

    # Verify tenant-gamma gets None
    val_gamma = cache.get(tenant_id="tenant-gamma", category="threat_intel", key="evil.com")
    assert val_gamma is None


def test_cache_ttl_expiration():
    """Verify cached entries expire after TTL."""
    cache = MultiTenantCacheManager(default_ttl_seconds=0.05)

    cache.set(tenant_id="t1", category="dns", key="test.org", value="1.2.3.4", ttl_seconds=0.05)
    assert cache.get(tenant_id="t1", category="dns", key="test.org") == "1.2.3.4"

    # Wait for TTL to elapse
    time.sleep(0.06)
    assert cache.get(tenant_id="t1", category="dns", key="test.org") is None


def test_cache_invalidation_scopes():
    """Verify key, category, and tenant scoped invalidations."""
    cache = MultiTenantCacheManager()

    cache.set("t1", "dns", "a.com", "1.1.1.1")
    cache.set("t1", "dns", "b.com", "2.2.2.2")
    cache.set("t1", "whois", "a.com", "Registrar X")
    cache.set("t2", "dns", "a.com", "9.9.9.9")

    # Invalidate single key
    assert cache.invalidate_key("t1", "dns", "a.com") is True
    assert cache.get("t1", "dns", "a.com") is None
    assert cache.get("t1", "dns", "b.com") == "2.2.2.2"

    # Invalidate entire category for t1
    removed = cache.invalidate_category("t1", "dns")
    assert removed >= 1
    assert cache.get("t1", "dns", "b.com") is None
    assert cache.get("t1", "whois", "a.com") == "Registrar X"

    # Invalidate entire tenant t1
    cache.invalidate_tenant("t1")
    assert cache.get("t1", "whois", "a.com") is None
    # t2 should be completely unaffected
    assert cache.get("t2", "dns", "a.com") == "9.9.9.9"


def test_cache_lru_capacity_eviction():
    """Verify cache evicts oldest entry when max_entries is exceeded."""
    cache = MultiTenantCacheManager(max_entries=3)

    cache.set("t", "cat", "k1", "v1")
    cache.set("t", "cat", "k2", "v2")
    cache.set("t", "cat", "k3", "v3")

    # Access k1 to make k2 the least recently used
    cache.get("t", "cat", "k1")

    # Add 4th entry -> k2 should be evicted
    cache.set("t", "cat", "k4", "v4")

    assert cache.get("t", "cat", "k1") == "v1"
    assert cache.get("t", "cat", "k2") is None  # Evicted
    assert cache.get("t", "cat", "k3") == "v3"
    assert cache.get("t", "cat", "k4") == "v4"

    stats = cache.get_stats()
    assert stats["evictions"] == 1


# ===========================================================================
# 4. Database Composite Index Verification Tests
# ===========================================================================

def test_database_models_composite_indexes_configured():
    """Verify high-value composite indexes are properly declared on critical models."""
    # Verify CaseModel composite indexes
    case_table_args = getattr(CaseModel, "__table_args__", ())
    index_names = [idx.name for idx in case_table_args if hasattr(idx, "name")]
    assert "ix_cases_workspace_status" in index_names
    assert "ix_cases_workspace_updated" in index_names
    assert "ix_cases_workspace_priority" in index_names

    # Verify IncidentModel composite indexes
    incident_table_args = getattr(IncidentModel, "__table_args__", ())
    incident_idx_names = [idx.name for idx in incident_table_args if hasattr(idx, "name")]
    assert "ix_incidents_workspace_status" in incident_idx_names
    assert "ix_incidents_workspace_created" in incident_idx_names
    assert "ix_incidents_workspace_severity" in incident_idx_names

    # Verify EvidenceModel composite indexes
    evidence_table_args = getattr(EvidenceModel, "__table_args__", ())
    evidence_idx_names = [idx.name for idx in evidence_table_args if hasattr(idx, "name")]
    assert "ix_evidence_tenant_integrity" in evidence_idx_names
    assert "ix_evidence_tenant_source" in evidence_idx_names
    assert "ix_evidence_tenant_upload" in evidence_idx_names


# ===========================================================================
# 5. Administrative Performance API Tests
# ===========================================================================

def test_admin_performance_metrics_endpoint():
    """Verify GET /api/admin/performance/metrics returns aggregated percentiles."""
    from fastapi.testclient import TestClient
    from backend.main import app
    client = TestClient(app)

    # Record sample operation
    global_performance_tracker.record_operation(
        category=PerformanceCategoryEnum.API_REQUEST.value,
        operation_name="test_endpoint",
        duration_ms=45.0,
        tenant_id="tenant-admin"
    )

    resp = client.get(
        "/api/admin/performance/metrics",
        headers={
            "X-User-Email": "admin@cyberguard.local",
            "X-User-Role": "PLATFORM_ADMIN",
            "X-Tenant-Id": "tenant-default"
        }
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "categories" in data
    assert "uptime_seconds" in data


def test_admin_performance_circuits_and_reset_endpoints():
    """Verify circuits observability and reset endpoints."""
    from fastapi.testclient import TestClient
    from backend.main import app
    client = TestClient(app)

    # Ensure circuit exists
    cb = CircuitBreakerRegistry.get_breaker("virustotal_test")
    cb.record_failure("test fail")

    # Inspect circuits
    resp = client.get(
        "/api/admin/performance/circuits",
        headers={
            "X-User-Email": "admin@cyberguard.local",
            "X-User-Role": "PLATFORM_ADMIN",
            "X-Tenant-Id": "tenant-default"
        }
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "circuits" in data
    assert data["total"] >= 1

    # Reset circuit
    resp_reset = client.post(
        "/api/admin/performance/circuits/virustotal_test/reset",
        headers={
            "X-User-Email": "admin@cyberguard.local",
            "X-User-Role": "PLATFORM_ADMIN",
            "X-Tenant-Id": "tenant-default"
        }
    )
    assert resp_reset.status_code == 200
    reset_data = resp_reset.json()
    assert reset_data["status"] == "RESET"
    assert reset_data["circuit"]["state"] == "CLOSED"


def test_admin_performance_cache_stats_endpoint():
    """Verify GET /api/admin/performance/cache-stats."""
    from fastapi.testclient import TestClient
    from backend.main import app
    client = TestClient(app)

    resp = client.get(
        "/api/admin/performance/cache-stats",
        headers={
            "X-User-Email": "admin@cyberguard.local",
            "X-User-Role": "PLATFORM_ADMIN",
            "X-Tenant-Id": "tenant-default"
        }
    )
    assert resp.status_code == 200
    stats = resp.json()
    assert "active_entries" in stats
    assert "hit_rate_percent" in stats
    assert "hits" in stats
    assert "misses" in stats

