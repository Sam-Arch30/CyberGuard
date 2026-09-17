import time
import threading
from typing import Optional, Dict, Tuple
from backend.schemas.ip_intelligence import IPIntelligence


class IPIntelligenceCache:
    """
    Thread-safe backend in-memory TTL cache for IP intelligence and Geolocation lookups.
    Avoids repeated external provider API calls for identical IP addresses.
    Distinguishes success TTL (1 hour) vs failure TTL (30 seconds) to avoid caching
    transient provider errors or rate limits indefinitely.
    """

    def __init__(
        self,
        ttl_seconds: int = 3600,
        failure_ttl_seconds: int = 30,
        max_entries: int = 2000
    ):
        self.ttl_seconds = ttl_seconds
        self.failure_ttl_seconds = failure_ttl_seconds
        self.max_entries = max_entries
        self._cache: Dict[str, Tuple[IPIntelligence, float, bool]] = {}  # (data, timestamp, is_failure)
        self._lock = threading.Lock()

    def get(self, ip: str) -> Optional[IPIntelligence]:
        """Retrieve cached IPIntelligence if present and not expired."""
        intel, _ = self.get_with_cached_flag(ip)
        return intel

    def get_with_cached_flag(self, ip: str) -> Tuple[Optional[IPIntelligence], bool]:
        """
        Retrieve cached IPIntelligence along with a boolean indicating whether
        the returned item was served from cache.
        """
        clean_ip = ip.strip() if ip else ""
        if not clean_ip:
            return None, False

        with self._lock:
            if clean_ip in self._cache:
                entry, timestamp, is_failure = self._cache[clean_ip]
                active_ttl = self.failure_ttl_seconds if is_failure else self.ttl_seconds
                if time.time() - timestamp < active_ttl:
                    return entry, True
                else:
                    del self._cache[clean_ip]
            return None, False

    def set(self, ip: str, data: IPIntelligence) -> None:
        """
        Store IPIntelligence in cache.
        Failures are stored with short failure_ttl_seconds to enable quick recovery.
        """
        clean_ip = ip.strip() if ip else ""
        if not clean_ip:
            return

        is_failure = bool(data.error and not data.enrichment_available)

        with self._lock:
            # Evict oldest entries if cache exceeds max size
            if len(self._cache) >= self.max_entries:
                oldest_ip = min(self._cache.keys(), key=lambda k: self._cache[k][1])
                del self._cache[oldest_ip]

            self._cache[clean_ip] = (data, time.time(), is_failure)

    def clear(self) -> None:
        """Clear all cached entries."""
        with self._lock:
            self._cache.clear()

    def size(self) -> int:
        """Return current count of cached items."""
        with self._lock:
            return len(self._cache)


# Global singleton cache instance
global_ip_cache = IPIntelligenceCache()
