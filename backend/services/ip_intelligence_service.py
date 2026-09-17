import os
from typing import List, Dict, Optional
from backend.schemas.ip_intelligence import IPIntelligence
from backend.services.relay_reconstructor import RelayReconstructorService
from backend.services.ip_providers import (
    BaseIPIntelligenceProvider,
    IPApiProvider,
    IPInfoProvider,
    MockIPIntelligenceProvider,
    UnconfiguredIPIntelligenceProvider,
)
from backend.config.geolocation_config import GeolocationConfig, global_geolocation_config
from backend.services.ip_cache import global_ip_cache, IPIntelligenceCache


class IPIntelligenceService:
    """
    Main orchestration service for IP Intelligence enrichment.
    Protects private IPs, manages cache lookups, and invokes configurable providers.
    """

    def __init__(
        self,
        provider: Optional[BaseIPIntelligenceProvider] = None,
        cache: Optional[IPIntelligenceCache] = None,
        config: Optional[GeolocationConfig] = None
    ):
        self.config = config or global_geolocation_config
        self.cache = cache or global_ip_cache
        self.provider = provider or self._get_default_provider()

    def _get_default_provider(self) -> BaseIPIntelligenceProvider:
        provider_name = self.config.provider
        if provider_name == "ipinfo":
            return IPInfoProvider(config=self.config)
        elif provider_name == "ipapi":
            return IPApiProvider(config=self.config)
        return UnconfiguredIPIntelligenceProvider()

    async def get_ip_intelligence(self, ip: str) -> IPIntelligence:
        """
        Enrich a single IP address with infrastructure & geolocation context.
        Bypasses external provider calls for private/loopback/reserved IPs.
        """
        if not ip:
            return IPIntelligence(
                ip="",
                scope="unknown",
                enrichment_available=False,
                error="Empty IP address provided"
            )

        # 1. Private / Loopback / Non-routable IP check
        is_public = RelayReconstructorService.is_public_ip(ip)
        if not is_public:
            return IPIntelligence(
                ip=ip,
                scope="private",
                enrichment_available=False,
                infrastructure_type="Private/Reserved Address — external geolocation unavailable.",
                error="Private/Reserved Address — external geolocation unavailable."
            )

        # 2. Check Backend Cache
        cached_res = self.cache.get(ip)
        if cached_res is not None:
            return cached_res

        # 3. Provider Lookup with Graceful Error Handling
        try:
            res = await self.provider.lookup(ip)
        except Exception as e:
            res = IPIntelligence(
                ip=ip,
                scope="public",
                enrichment_available=False,
                error=f"Lookup unavailable: {str(e)}"
            )

        # 4. Save result in cache
        self.cache.set(ip, res)
        return res

    async def get_batch_ip_intelligence(self, ips: List[str]) -> Dict[str, IPIntelligence]:
        """
        Batch enrich a list of IP addresses, returning a dictionary keyed by IP string.
        """
        results: Dict[str, IPIntelligence] = {}
        unique_ips = list(set([i.strip() for i in ips if i and i.strip()]))

        for ip in unique_ips:
            results[ip] = await self.get_ip_intelligence(ip)

        return results


# Default global service instance
global_ip_service = IPIntelligenceService()
