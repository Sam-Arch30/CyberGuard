"""
Section 73: Resilient External Integration Circuit Breaker Service.
Protects CyberGuard against cascading timeouts, resource starvation, and external provider failures.
Implements the canonical 3-state Circuit Breaker pattern (CLOSED, OPEN, HALF_OPEN)
for Threat Intelligence APIs, LLM providers, RDAP, Geolocation, and WHOIS.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from enum import Enum
from threading import Lock
from typing import Any, Callable, Dict, Optional, Tuple

logger = logging.getLogger("cyberguard.circuit_breaker")


class CircuitState(str, Enum):
    CLOSED = "CLOSED"      # Normal operation: requests pass through
    OPEN = "OPEN"          # Tripped: requests fail-fast without calling external service
    HALF_OPEN = "HALF_OPEN"# Probing: limited requests allowed to test recovery


@dataclass
class CircuitBreakerConfig:
    failure_threshold: int = 5          # Consecutive failures before tripping to OPEN
    recovery_timeout_seconds: float = 30.0 # Time to wait in OPEN before moving to HALF_OPEN
    half_open_success_threshold: int = 2   # Consecutive successes in HALF_OPEN to close circuit
    invocation_timeout_seconds: float = 10.0 # Request execution timeout


class CircuitBreakerOpenException(Exception):
    """Raised when an external service invocation is rejected because the circuit is OPEN."""
    def __init__(self, service_name: str, retry_after_seconds: float):
        self.service_name = service_name
        self.retry_after_seconds = retry_after_seconds
        super().__init__(
            f"Circuit breaker for service '{service_name}' is OPEN. "
            f"Failing fast to preserve resources. Retry after {retry_after_seconds:.1f}s."
        )


class CircuitBreaker:
    """
    Thread-safe circuit breaker protecting an external service endpoint.
    """

    def __init__(self, service_name: str, config: Optional[CircuitBreakerConfig] = None):
        self.service_name = service_name
        self.config = config or CircuitBreakerConfig()
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._last_state_change = time.time()
        self._last_failure_time = 0.0
        self._last_failure_reason: Optional[str] = None
        self._total_requests = 0
        self._total_failures = 0
        self._total_circuit_trips = 0
        self._lock = Lock()

    @property
    def state(self) -> CircuitState:
        with self._lock:
            self._check_half_open_transition()
            return self._state

    def _check_half_open_transition(self) -> None:
        """Transitions from OPEN to HALF_OPEN if recovery timeout has elapsed."""
        if self._state == CircuitState.OPEN:
            elapsed = time.time() - self._last_state_change
            if elapsed >= self.config.recovery_timeout_seconds:
                self._state = CircuitState.HALF_OPEN
                self._success_count = 0
                self._last_state_change = time.time()
                logger.info(
                    f"Circuit breaker for '{self.service_name}' transitioned to HALF_OPEN (probing recovery)."
                )

    def can_execute(self) -> Tuple[bool, Optional[float]]:
        """
        Determines whether a request is allowed to execute.
        Returns (is_allowed, retry_after_seconds).
        """
        with self._lock:
            self._check_half_open_transition()
            if self._state == CircuitState.OPEN:
                retry_after = max(
                    0.0,
                    self.config.recovery_timeout_seconds - (time.time() - self._last_state_change)
                )
                return False, retry_after
            return True, None

    def record_success(self) -> None:
        """Records a successful external service response."""
        with self._lock:
            self._total_requests += 1
            if self._state == CircuitState.HALF_OPEN:
                self._success_count += 1
                if self._success_count >= self.config.half_open_success_threshold:
                    self._state = CircuitState.CLOSED
                    self._failure_count = 0
                    self._success_count = 0
                    self._last_state_change = time.time()
                    self._last_failure_reason = None
                    logger.info(
                        f"Circuit breaker for '{self.service_name}' recovered and is now CLOSED."
                    )
            elif self._state == CircuitState.CLOSED:
                self._failure_count = 0

    def record_failure(self, error_reason: str) -> None:
        """Records an external service error or timeout."""
        with self._lock:
            self._total_requests += 1
            self._total_failures += 1
            self._last_failure_time = time.time()
            self._last_failure_reason = str(error_reason)

            if self._state == CircuitState.CLOSED:
                self._failure_count += 1
                if self._failure_count >= self.config.failure_threshold:
                    self._state = CircuitState.OPEN
                    self._last_state_change = time.time()
                    self._total_circuit_trips += 1
                    logger.warning(
                        f"Circuit breaker for '{self.service_name}' TRIPPED to OPEN after "
                        f"{self._failure_count} consecutive failures. Last error: {error_reason}"
                    )
            elif self._state == CircuitState.HALF_OPEN:
                self._state = CircuitState.OPEN
                self._last_state_change = time.time()
                self._total_circuit_trips += 1
                logger.warning(
                    f"Probe request in HALF_OPEN failed for '{self.service_name}'. "
                    f"Returning to OPEN. Error: {error_reason}"
                )

    def execute(self, func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        """
        Synchronous wrapper: executes func if allowed, tracks success/failure.
        Raises CircuitBreakerOpenException if circuit is OPEN.
        """
        allowed, retry_after = self.can_execute()
        if not allowed:
            raise CircuitBreakerOpenException(self.service_name, retry_after or 30.0)

        try:
            result = func(*args, **kwargs)
            self.record_success()
            return result
        except Exception as exc:
            self.record_failure(str(exc))
            raise

    async def execute_async(self, coro_func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        """
        Asynchronous wrapper: executes coroutine if allowed, tracks success/failure.
        Raises CircuitBreakerOpenException if circuit is OPEN.
        """
        allowed, retry_after = self.can_execute()
        if not allowed:
            raise CircuitBreakerOpenException(self.service_name, retry_after or 30.0)

        try:
            result = await coro_func(*args, **kwargs)
            self.record_success()
            return result
        except Exception as exc:
            self.record_failure(str(exc))
            raise

    def get_status(self) -> Dict[str, Any]:
        """Returns structured observability status."""
        with self._lock:
            self._check_half_open_transition()
            return {
                "service_name": self.service_name,
                "state": self._state.value,
                "failure_count": self._failure_count,
                "success_count": self._success_count,
                "total_requests": self._total_requests,
                "total_failures": self._total_failures,
                "total_circuit_trips": self._total_circuit_trips,
                "last_failure_reason": self._last_failure_reason,
                "last_state_change": self._last_state_change,
            }

    def reset(self) -> None:
        """Manually resets the circuit breaker to closed state."""
        with self._lock:
            self._state = CircuitState.CLOSED
            self._failure_count = 0
            self._success_count = 0
            self._last_state_change = time.time()
            self._last_failure_reason = None


class CircuitBreakerRegistry:
    """Central registry of circuit breakers by provider/service name."""

    _instances: Dict[str, CircuitBreaker] = {}
    _lock = Lock()

    @classmethod
    def get_breaker(cls, service_name: str, config: Optional[CircuitBreakerConfig] = None) -> CircuitBreaker:
        name_clean = service_name.lower().strip()
        with cls._lock:
            if name_clean not in cls._instances:
                cls._instances[name_clean] = CircuitBreaker(name_clean, config)
            return cls._instances[name_clean]

    @classmethod
    def get_all_statuses(cls) -> List[Dict[str, Any]]:
        with cls._lock:
            return [cb.get_status() for cb in cls._instances.values()]

    @classmethod
    def reset_all(cls) -> None:
        with cls._lock:
            for cb in cls._instances.values():
                cb.reset()
