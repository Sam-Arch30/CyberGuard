"""
Section 73: Performance Monitoring, Metrics Aggregation & Scalability Coordinator.
Tracks latency percentiles (p50, p95, p99), throughput, error rates, performance budgets,
slow-operation diagnostics, and synthetic benchmarks across all critical paths.
"""
from __future__ import annotations

import logging
import math
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from threading import Lock
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("cyberguard.performance")


class PerformanceCategoryEnum(str, Enum):
    API_REQUEST = "API_REQUEST"
    DATABASE_QUERY = "DATABASE_QUERY"
    ANALYSIS_DAG = "ANALYSIS_DAG"
    BACKGROUND_JOB = "BACKGROUND_JOB"
    THREAT_INTEL = "THREAT_INTEL"
    LLM_INFERENCE = "LLM_INFERENCE"
    REPORT_GENERATION = "REPORT_GENERATION"
    GRAPH_TRAVERSAL = "GRAPH_TRAVERSAL"
    SEARCH_HUNTING = "SEARCH_HUNTING"


@dataclass
class PerformanceBudget:
    category: PerformanceCategoryEnum
    target_p50_ms: float
    target_p95_ms: float
    target_p99_ms: float
    max_duration_ms: float


# Authoritative performance budgets across CyberGuard subsystems
DEFAULT_PERFORMANCE_BUDGETS: Dict[str, PerformanceBudget] = {
    PerformanceCategoryEnum.API_REQUEST.value: PerformanceBudget(
        category=PerformanceCategoryEnum.API_REQUEST,
        target_p50_ms=100.0,
        target_p95_ms=250.0,
        target_p99_ms=500.0,
        max_duration_ms=1000.0,
    ),
    PerformanceCategoryEnum.DATABASE_QUERY.value: PerformanceBudget(
        category=PerformanceCategoryEnum.DATABASE_QUERY,
        target_p50_ms=20.0,
        target_p95_ms=50.0,
        target_p99_ms=100.0,
        max_duration_ms=250.0,
    ),
    PerformanceCategoryEnum.ANALYSIS_DAG.value: PerformanceBudget(
        category=PerformanceCategoryEnum.ANALYSIS_DAG,
        target_p50_ms=1000.0,
        target_p95_ms=2500.0,
        target_p99_ms=4000.0,
        max_duration_ms=6000.0,
    ),
    PerformanceCategoryEnum.BACKGROUND_JOB.value: PerformanceBudget(
        category=PerformanceCategoryEnum.BACKGROUND_JOB,
        target_p50_ms=2000.0,
        target_p95_ms=5000.0,
        target_p99_ms=10000.0,
        max_duration_ms=15000.0,
    ),
    PerformanceCategoryEnum.THREAT_INTEL.value: PerformanceBudget(
        category=PerformanceCategoryEnum.THREAT_INTEL,
        target_p50_ms=300.0,
        target_p95_ms=800.0,
        target_p99_ms=1500.0,
        max_duration_ms=3000.0,
    ),
    PerformanceCategoryEnum.LLM_INFERENCE.value: PerformanceBudget(
        category=PerformanceCategoryEnum.LLM_INFERENCE,
        target_p50_ms=1500.0,
        target_p95_ms=3500.0,
        target_p99_ms=5000.0,
        max_duration_ms=8000.0,
    ),
    PerformanceCategoryEnum.REPORT_GENERATION.value: PerformanceBudget(
        category=PerformanceCategoryEnum.REPORT_GENERATION,
        target_p50_ms=1200.0,
        target_p95_ms=3000.0,
        target_p99_ms=6000.0,
        max_duration_ms=10000.0,
    ),
    PerformanceCategoryEnum.GRAPH_TRAVERSAL.value: PerformanceBudget(
        category=PerformanceCategoryEnum.GRAPH_TRAVERSAL,
        target_p50_ms=80.0,
        target_p95_ms=200.0,
        target_p99_ms=400.0,
        max_duration_ms=800.0,
    ),
    PerformanceCategoryEnum.SEARCH_HUNTING.value: PerformanceBudget(
        category=PerformanceCategoryEnum.SEARCH_HUNTING,
        target_p50_ms=150.0,
        target_p95_ms=400.0,
        target_p99_ms=800.0,
        max_duration_ms=1500.0,
    ),
}


@dataclass
class SlowOperationRecord:
    operation_id: str
    category: str
    operation_name: str
    duration_ms: float
    budget_max_ms: float
    timestamp: str
    tenant_id: str
    details: Dict[str, Any] = field(default_factory=dict)


class PerformanceMetricsTracker:
    """
    Thread-safe latency, throughput, error-rate, and percentile metrics aggregator.
    Maintains bounded sample buffers per category to compute accurate p50, p95, and p99 figures.
    """

    def __init__(self, sample_window_size: int = 1000, max_slow_records: int = 100):
        self._sample_window_size = sample_window_size
        self._max_slow_records = max_slow_records
        self._samples: Dict[str, deque] = {}
        self._total_counts: Dict[str, int] = {}
        self._error_counts: Dict[str, int] = {}
        self._slow_records: deque = deque(maxlen=max_slow_records)
        self._start_time = time.time()
        self._lock = Lock()

    def record_operation(
        self,
        category: str,
        operation_name: str,
        duration_ms: float,
        is_error: bool = False,
        tenant_id: str = "default",
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Records an execution sample for a specific category.
        Detects budget breaches and archives slow operations automatically.
        """
        cat_key = category.upper()
        now = time.time()

        with self._lock:
            # Initialize category buffers if absent
            if cat_key not in self._samples:
                self._samples[cat_key] = deque(maxlen=self._sample_window_size)
                self._total_counts[cat_key] = 0
                self._error_counts[cat_key] = 0

            self._samples[cat_key].append(duration_ms)
            self._total_counts[cat_key] += 1
            if is_error:
                self._error_counts[cat_key] += 1

            # Check if duration breaches category budget
            budget = DEFAULT_PERFORMANCE_BUDGETS.get(cat_key)
            if budget and duration_ms > budget.max_duration_ms:
                slow_record = SlowOperationRecord(
                    operation_id=f"slow_{int(now * 1000)}_{len(self._slow_records)}",
                    category=cat_key,
                    operation_name=operation_name,
                    duration_ms=round(duration_ms, 2),
                    budget_max_ms=budget.max_duration_ms,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    tenant_id=tenant_id,
                    details=details or {}
                )
                self._slow_records.append(slow_record)
                logger.warning(
                    f"SLOW OPERATION DETECTED [{cat_key}] '{operation_name}': "
                    f"{duration_ms:.2f}ms (budget max: {budget.max_duration_ms}ms)"
                )

    def _calculate_percentile(self, sorted_values: List[float], percentile: float) -> float:
        if not sorted_values:
            return 0.0
        k = (len(sorted_values) - 1) * (percentile / 100.0)
        f = math.floor(k)
        c = math.ceil(k)
        if f == c:
            return sorted_values[int(k)]
        d0 = sorted_values[int(f)] * (c - k)
        d1 = sorted_values[int(c)] * (k - f)
        return d0 + d1

    def get_metrics_summary(self) -> Dict[str, Any]:
        """
        Calculates truthful latency percentiles, throughput (req/s), and error rates.
        """
        uptime_seconds = max(1.0, time.time() - self._start_time)
        categories_data: Dict[str, Any] = {}

        with self._lock:
            for cat_key, sample_deque in self._samples.items():
                samples = list(sample_deque)
                count = self._total_counts.get(cat_key, 0)
                errors = self._error_counts.get(cat_key, 0)
                error_rate = (errors / count * 100.0) if count > 0 else 0.0
                throughput = count / uptime_seconds

                if samples:
                    sorted_samples = sorted(samples)
                    p50 = self._calculate_percentile(sorted_samples, 50.0)
                    p95 = self._calculate_percentile(sorted_samples, 95.0)
                    p99 = self._calculate_percentile(sorted_samples, 99.0)
                    avg_ms = sum(samples) / len(samples)
                    min_ms = sorted_samples[0]
                    max_ms = sorted_samples[-1]
                else:
                    p50 = p95 = p99 = avg_ms = min_ms = max_ms = 0.0

                budget = DEFAULT_PERFORMANCE_BUDGETS.get(cat_key)
                categories_data[cat_key] = {
                    "total_operations": count,
                    "sample_count": len(samples),
                    "throughput_ops_per_sec": round(throughput, 2),
                    "error_count": errors,
                    "error_rate_percent": round(error_rate, 2),
                    "latency_p50_ms": round(p50, 2),
                    "latency_p95_ms": round(p95, 2),
                    "latency_p99_ms": round(p99, 2),
                    "latency_avg_ms": round(avg_ms, 2),
                    "latency_min_ms": round(min_ms, 2),
                    "latency_max_ms": round(max_ms, 2),
                    "budget": {
                        "target_p50_ms": budget.target_p50_ms if budget else None,
                        "target_p95_ms": budget.target_p95_ms if budget else None,
                        "target_p99_ms": budget.target_p99_ms if budget else None,
                        "max_duration_ms": budget.max_duration_ms if budget else None,
                        "p95_within_budget": (p95 <= budget.target_p95_ms) if budget and samples else True,
                    } if budget else None
                }

        return {
            "uptime_seconds": round(uptime_seconds, 1),
            "inspected_at": datetime.now(timezone.utc).isoformat(),
            "categories": categories_data,
        }

    def get_slow_operations(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Returns recent operations that breached performance budgets."""
        with self._lock:
            records = list(self._slow_records)[-limit:]
            return [
                {
                    "operation_id": r.operation_id,
                    "category": r.category,
                    "operation_name": r.operation_name,
                    "duration_ms": r.duration_ms,
                    "budget_max_ms": r.budget_max_ms,
                    "timestamp": r.timestamp,
                    "tenant_id": r.tenant_id,
                    "details": r.details,
                }
                for r in reversed(records)
            ]

    def reset_metrics(self) -> None:
        """Resets all metrics and sample buffers."""
        with self._lock:
            self._samples.clear()
            self._total_counts.clear()
            self._error_counts.clear()
            self._slow_records.clear()
            self._start_time = time.time()


# Global tracker instance
global_performance_tracker = PerformanceMetricsTracker()


class ExecutionTimer:
    """Context manager for timing and recording operation performance."""

    def __init__(
        self,
        category: str,
        operation_name: str,
        tenant_id: str = "default",
        details: Optional[Dict[str, Any]] = None,
        tracker: Optional[PerformanceMetricsTracker] = None
    ):
        self.category = category
        self.operation_name = operation_name
        self.tenant_id = tenant_id
        self.details = details or {}
        self.tracker = tracker or global_performance_tracker
        self.start_time: float = 0.0
        self.duration_ms: float = 0.0

    def __enter__(self) -> ExecutionTimer:
        self.start_time = time.perf_counter()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.duration_ms = (time.perf_counter() - self.start_time) * 1000.0
        is_error = exc_type is not None
        self.tracker.record_operation(
            category=self.category,
            operation_name=self.operation_name,
            duration_ms=self.duration_ms,
            is_error=is_error,
            tenant_id=self.tenant_id,
            details=self.details
        )
