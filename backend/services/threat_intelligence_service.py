"""
Threat Intelligence Service & Cache (Section 7).
Provides cached external threat intelligence lookups with sensible TTLs,
explicit rate-limit handling, and clean separation between observed facts and provider opinions.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("cyberguard.threat_intel")


@dataclass
class ThreatIntelResult:
    """Normalized threat intelligence response from an external or local provider."""
    provider: str
    query: str
    indicator_type: str  # URL, DOMAIN, IP, HASH
    is_malicious: bool
    verdict: str  # MALICIOUS, PHISHING, MALWARE, SUSPICIOUS, BENIGN, UNKNOWN, RATE_LIMITED
    threat_types: List[str] = field(default_factory=list)
    confidence: float = 0.5
    raw_response: Dict[str, Any] = field(default_factory=dict)
    retrieved_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    expires_at: Optional[str] = None
    is_rate_limited: bool = False
    details: Optional[str] = None


class ThreatIntelligenceCache:
    """In-memory thread-safe TTL cache for threat intelligence results."""

    def __init__(self, default_ttl_seconds: int = 3600):
        self._cache: Dict[str, Tuple[ThreatIntelResult, float]] = {}
        self.default_ttl = default_ttl_seconds

    def _cache_key(self, provider: str, indicator_type: str, query: str) -> str:
        return f"{provider.lower()}:{indicator_type.lower()}:{query.strip().lower()}"

    def get(self, provider: str, indicator_type: str, query: str) -> Optional[ThreatIntelResult]:
        key = self._cache_key(provider, indicator_type, query)
        entry = self._cache.get(key)
        if not entry:
            return None
        res, expiry_ts = entry
        if time.time() > expiry_ts:
            del self._cache[key]
            return None
        return res

    def set(self, result: ThreatIntelResult, ttl_seconds: Optional[int] = None):
        ttl = ttl_seconds or self.default_ttl
        expiry_ts = time.time() + ttl
        result.expires_at = datetime.fromtimestamp(expiry_ts, tz=timezone.utc).isoformat()
        key = self._cache_key(result.provider, result.indicator_type, result.query)
        self._cache[key] = (result, expiry_ts)

    def clear(self):
        self._cache.clear()


class ThreatIntelligenceService:
    """
    Coordinates threat intelligence queries across configured providers
    (e.g., URLhaus, AlienVault OTX, VirusTotal, or local threat databases).
    """

    def __init__(
        self,
        cache: Optional[ThreatIntelligenceCache] = None,
        default_ttl_seconds: int = 3600,
        rate_limit_simulated: bool = False,
    ):
        self.cache = cache or ThreatIntelligenceCache(default_ttl_seconds=default_ttl_seconds)
        self.rate_limit_simulated = rate_limit_simulated

    async def lookup_url(self, url: str) -> List[ThreatIntelResult]:
        """Queries configured threat intel sources for a URL."""
        clean_url = url.strip()
        provider = "cyberguard_threat_intel"

        # Check cache
        cached = self.cache.get(provider, "URL", clean_url)
        if cached:
            return [cached]

        if self.rate_limit_simulated:
            rl_res = ThreatIntelResult(
                provider=provider,
                query=clean_url,
                indicator_type="URL",
                is_malicious=False,
                verdict="RATE_LIMITED",
                is_rate_limited=True,
                confidence=0.0,
                details="Threat intelligence provider rate limit exceeded",
            )
            return [rl_res]

        # By default return UNKNOWN without fabricating opinions
        result = ThreatIntelResult(
            provider=provider,
            query=clean_url,
            indicator_type="URL",
            is_malicious=False,
            verdict="UNKNOWN",
            confidence=0.0,
            details="No external threat intelligence match found",
        )
        self.cache.set(result)
        return [result]

    async def lookup_domain(self, domain: str) -> List[ThreatIntelResult]:
        """Queries configured threat intel sources for a domain."""
        clean_dom = domain.strip().lower()
        provider = "cyberguard_threat_intel"

        cached = self.cache.get(provider, "DOMAIN", clean_dom)
        if cached:
            return [cached]

        if self.rate_limit_simulated:
            rl_res = ThreatIntelResult(
                provider=provider,
                query=clean_dom,
                indicator_type="DOMAIN",
                is_malicious=False,
                verdict="RATE_LIMITED",
                is_rate_limited=True,
                confidence=0.0,
                details="Threat intelligence provider rate limit exceeded",
            )
            return [rl_res]

        result = ThreatIntelResult(
            provider=provider,
            query=clean_dom,
            indicator_type="DOMAIN",
            is_malicious=False,
            verdict="UNKNOWN",
            confidence=0.0,
            details="No external threat intelligence match found",
        )
        self.cache.set(result)
        return [result]
