"""
Section 73: Safe Multi-Tenant Cache Service.
Provides high-performance, in-memory TTL caching with strict tenant isolation.
Guarantees that cached entries are strictly partitioned by tenant_id, preventing cross-tenant leakage.
"""
from __future__ import annotations

import logging
import time
from collections import OrderedDict
from dataclasses import dataclass
from threading import Lock
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("cyberguard.cache")


@dataclass
class CacheEntry:
    value: Any
    expires_at: float
    created_at: float
    tenant_id: str
    category: str
    key: str


class MultiTenantCacheManager:
    """
    Thread-safe, bounded, multi-tenant cache manager.
    Enforces tenant boundaries by prefixing all cache keys:
        {tenant_id}:{category}:{raw_key}
    """

    def __init__(self, default_ttl_seconds: float = 300.0, max_entries: int = 5000):
        self._default_ttl = default_ttl_seconds
        self._max_entries = max_entries
        self._entries: OrderedDict[str, CacheEntry] = OrderedDict()
        self._hits = 0
        self._misses = 0
        self._evictions = 0
        self._lock = Lock()

    def _build_scoped_key(self, tenant_id: str, category: str, key: str) -> str:
        t_clean = (tenant_id or "default").strip().lower()
        c_clean = category.strip().lower()
        k_clean = str(key).strip().lower()
        return f"{t_clean}:{c_clean}:{k_clean}"

    def get(self, tenant_id: str, category: str, key: str) -> Optional[Any]:
        """
        Retrieves a cached item within the tenant scope.
        Returns None if expired or not found.
        """
        scoped_key = self._build_scoped_key(tenant_id, category, key)
        now = time.time()

        with self._lock:
            entry = self._entries.get(scoped_key)
            if entry is None:
                self._misses += 1
                return None

            # Check expiration
            if now > entry.expires_at:
                del self._entries[scoped_key]
                self._misses += 1
                return None

            # Move to end (LRU freshness)
            self._entries.move_to_end(scoped_key)
            self._hits += 1
            return entry.value

    def set(
        self,
        tenant_id: str,
        category: str,
        key: str,
        value: Any,
        ttl_seconds: Optional[float] = None
    ) -> None:
        """
        Stores an item in the tenant-scoped cache with TTL expiration.
        """
        scoped_key = self._build_scoped_key(tenant_id, category, key)
        duration = ttl_seconds if ttl_seconds is not None else self._default_ttl
        now = time.time()
        expires_at = now + duration

        with self._lock:
            # Check capacity and evict oldest if needed
            if len(self._entries) >= self._max_entries and scoped_key not in self._entries:
                self._entries.popitem(last=False)
                self._evictions += 1

            self._entries[scoped_key] = CacheEntry(
                value=value,
                expires_at=expires_at,
                created_at=now,
                tenant_id=(tenant_id or "default").strip().lower(),
                category=category.strip().lower(),
                key=str(key).strip().lower()
            )
            self._entries.move_to_end(scoped_key)

    def invalidate_key(self, tenant_id: str, category: str, key: str) -> bool:
        """Removes a specific cached entry."""
        scoped_key = self._build_scoped_key(tenant_id, category, key)
        with self._lock:
            if scoped_key in self._entries:
                del self._entries[scoped_key]
                return True
            return False

    def invalidate_category(self, tenant_id: str, category: str) -> int:
        """Invalidates all entries in a category for a specific tenant."""
        t_clean = (tenant_id or "default").strip().lower()
        c_clean = category.strip().lower()
        prefix = f"{t_clean}:{c_clean}:"

        removed = 0
        with self._lock:
            keys_to_remove = [k for k in self._entries if k.startswith(prefix)]
            for k in keys_to_remove:
                del self._entries[k]
                removed += 1
        return removed

    def invalidate_tenant(self, tenant_id: str) -> int:
        """Invalidates all cached entries belonging to a tenant."""
        t_clean = (tenant_id or "default").strip().lower()
        prefix = f"{t_clean}:"

        removed = 0
        with self._lock:
            keys_to_remove = [k for k in self._entries if k.startswith(prefix)]
            for k in keys_to_remove:
                del self._entries[k]
                removed += 1
        return removed

    def clear(self) -> None:
        """Flushes the entire cache."""
        with self._lock:
            self._entries.clear()

    def get_stats(self) -> Dict[str, Any]:
        """Returns cache efficiency metrics."""
        with self._lock:
            total_requests = self._hits + self._misses
            hit_rate = (self._hits / total_requests * 100.0) if total_requests > 0 else 0.0
            now = time.time()
            active_count = sum(1 for e in self._entries.values() if e.expires_at > now)

            return {
                "active_entries": active_count,
                "total_stored_entries": len(self._entries),
                "max_entries": self._max_entries,
                "hits": self._hits,
                "misses": self._misses,
                "evictions": self._evictions,
                "hit_rate_percent": round(hit_rate, 2),
            }


# Global singleton cache instance
global_cache_manager = MultiTenantCacheManager()
