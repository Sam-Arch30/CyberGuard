import time
import os
import threading
from typing import Dict, List, Tuple
from fastapi import Request, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware


class SlidingWindowRateLimiter:
    """Thread-safe in-memory sliding window rate limiter."""

    def __init__(self):
        self._lock = threading.Lock()
        self._records: Dict[Tuple[str, str], List[float]] = {}
        self._last_cleanup = time.monotonic()

    def is_allowed(self, client_ip: str, category: str, max_requests: int, window_seconds: float = 60.0) -> Tuple[bool, int]:
        """
        Determines if request is permitted under sliding window.
        Returns (is_allowed, remaining_requests).
        """
        now = time.monotonic()
        key = (client_ip, category)

        with self._lock:
            # Periodic cleanup every 60 seconds
            if now - self._last_cleanup > 60.0:
                self._cleanup(now, window_seconds)

            timestamps = self._records.get(key, [])
            # Filter timestamps within current window
            valid_timestamps = [t for t in timestamps if now - t < window_seconds]

            if len(valid_timestamps) >= max_requests:
                self._records[key] = valid_timestamps
                return False, 0

            valid_timestamps.append(now)
            self._records[key] = valid_timestamps
            remaining = max(0, max_requests - len(valid_timestamps))
            return True, remaining

    def _cleanup(self, now: float, window_seconds: float):
        self._last_cleanup = now
        stale_keys = []
        for key, timestamps in self._records.items():
            fresh = [t for t in timestamps if now - t < window_seconds]
            if fresh:
                self._records[key] = fresh
            else:
                stale_keys.append(key)
        for k in stale_keys:
            del self._records[k]


global_rate_limiter = SlidingWindowRateLimiter()


class RateLimiterMiddleware(BaseHTTPMiddleware):
    """
    FastAPI middleware applying tiered rate limiting:
    - Email Upload & Analysis: 20 req/min
    - LLM Inference: 10 req/min
    - External Intelligence: 60 req/min
    - General endpoints: 120 req/min
    """

    def __init__(self, app, enabled: bool = True):
        super().__init__(app)
        self.enabled = enabled and os.getenv("RATE_LIMIT_ENABLED", "true").lower() != "false"

    async def dispatch(self, request: Request, call_next):
        if not self.enabled:
            return await call_next(request)

        # Allow health checks and docs without rate limiting
        path = request.url.path
        if path in ("/health", "/docs", "/openapi.json", "/redoc"):
            return await call_next(request)

        # Determine client IP (support X-Forwarded-For)
        client_ip = "127.0.0.1"
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            client_ip = forwarded.split(",")[0].strip()
        elif request.client and request.client.host:
            client_ip = request.client.host

        # Categorize route and configure limits
        if path == "/api/emails/analyze" and request.method == "POST":
            category = "upload_analysis"
            limit = int(os.getenv("RATE_LIMIT_ANALYSIS_PER_MIN", "20"))
        elif "/ai-analyst" in path and request.method == "POST":
            category = "llm_requests"
            limit = int(os.getenv("RATE_LIMIT_LLM_PER_MIN", "10"))
        elif path.startswith("/api/emails/lookup") or path.startswith("/api/emails/detect-lookalike"):
            category = "intelligence"
            limit = int(os.getenv("RATE_LIMIT_INTEL_PER_MIN", "60"))
        elif path.startswith("/api/admin"):
            category = "administration"
            limit = int(os.getenv("RATE_LIMIT_ADMIN_PER_MIN", "60"))
        elif path.startswith("/api/search") or path.startswith("/api/threat-hunting"):
            category = "search_hunting"
            limit = int(os.getenv("RATE_LIMIT_SEARCH_PER_MIN", "60"))
        elif path.startswith("/api/reports") or path.startswith("/api/v1/executive-reports"):
            category = "reports_export"
            limit = int(os.getenv("RATE_LIMIT_REPORTS_PER_MIN", "30"))
        else:
            category = "general"
            limit = int(os.getenv("RATE_LIMIT_GENERAL_PER_MIN", "120"))

        allowed, remaining = global_rate_limiter.is_allowed(client_ip, category, limit)

        if not allowed:
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "detail": f"Rate limit exceeded for category '{category}'. Please try again in 60 seconds.",
                    "error_code": "RATE_LIMIT_EXCEEDED"
                },
                headers={
                    "Retry-After": "60",
                    "X-RateLimit-Limit": str(limit),
                    "X-RateLimit-Remaining": "0"
                }
            )

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        return response
