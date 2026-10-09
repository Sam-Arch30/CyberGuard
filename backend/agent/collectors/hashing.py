"""
Bounded Process and File Binary Hashing Cache for Section 32 Endpoint Telemetry.
Provides thread-safe, bounded LRU caching of SHA-256 hashes using (path, size, mtime)
to prevent redundant disk I/O and avoid blocking the telemetry pipeline.

STRICT INVARIANTS:
- Never executes the file or dynamically inspects binary execution.
- Bounded file size threshold: does not hash arbitrarily large files.
- Cache invalidated automatically when mtime or file size changes.
"""

import os
import hashlib
import threading
import logging
from typing import Dict, Tuple, Optional

logger = logging.getLogger("cyberguard.agent.hashing")


class BinaryHashCache:
    """
    Thread-safe, size-bounded LRU cache for binary SHA-256 calculations.
    """

    def __init__(
        self,
        max_cache_entries: int = 2000,
        max_file_size_bytes: int = 50 * 1024 * 1024,  # 50 MB
        read_chunk_size: int = 64 * 1024              # 64 KB
    ):
        self.max_entries = max_cache_entries
        self.max_file_size = max_file_size_bytes
        self.chunk_size = read_chunk_size

        self._lock = threading.RLock()
        # map: normalized_path -> (sha256_hash, file_size, mtime, last_accessed_time)
        self._cache: Dict[str, Tuple[str, int, float, float]] = {}
        self._cache_hits = 0
        self._cache_misses = 0
        self._hashes_calculated = 0
        self._oversized_skipped = 0

    def compute_sha256(self, file_path: str) -> Optional[str]:
        """
        Computes or retrieves cached SHA-256 hash for a given file path.
        Returns None if file does not exist, is inaccessible, or exceeds max size limit.
        """
        if not file_path or not isinstance(file_path, str):
            return None

        normalized_path = os.path.normpath(file_path)

        try:
            stat_info = os.stat(normalized_path)
            size = stat_info.st_size
            mtime = stat_info.st_mtime
        except (OSError, PermissionError, FileNotFoundError):
            return None

        # Check file size limit
        if size > self.max_file_size:
            with self._lock:
                self._oversized_skipped += 1
            logger.debug(f"Skipping hash for oversized file ({size} bytes): {normalized_path}")
            return "OVERSIZED_SKIPPED"

        import time
        now = time.time()

        with self._lock:
            cached = self._cache.get(normalized_path)
            if cached:
                cached_hash, cached_size, cached_mtime, _ = cached
                # Validate mtime and size
                if cached_size == size and abs(cached_mtime - mtime) < 0.001:
                    self._cache_hits += 1
                    # Update access time
                    self._cache[normalized_path] = (cached_hash, cached_size, cached_mtime, now)
                    return cached_hash

            self._cache_misses += 1

        # Calculate hash outside lock to prevent blocking concurrent readers
        try:
            hasher = hashlib.sha256()
            with open(normalized_path, "rb") as f:
                while True:
                    chunk = f.read(self.chunk_size)
                    if not chunk:
                        break
                    hasher.update(chunk)
            computed_hash = hasher.hexdigest()
        except (OSError, PermissionError):
            return None

        with self._lock:
            # Evict oldest entry if capacity exceeded
            if len(self._cache) >= self.max_entries:
                oldest_key = min(self._cache.keys(), key=lambda k: self._cache[k][3])
                del self._cache[oldest_key]

            self._cache[normalized_path] = (computed_hash, size, mtime, now)
            self._hashes_calculated += 1

        return computed_hash

    def get_metrics(self) -> Dict[str, int]:
        with self._lock:
            return {
                "cache_entries": len(self._cache),
                "cache_hits": self._cache_hits,
                "cache_misses": self._cache_misses,
                "hashes_calculated": self._hashes_calculated,
                "oversized_skipped": self._oversized_skipped
            }

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()
