import os
from typing import Optional, Dict, Any
from backend.schemas.ip_intelligence import (
    IPIntelligence,
    GeolocationResponse,
    GeolocationStatusResponse,
    FORENSIC_DISCLAIMER_NOTICE,
)
from backend.config.geolocation_config import GeolocationConfig, global_geolocation_config
from backend.services.ip_cache import IPIntelligenceCache, global_ip_cache
from backend.services.ip_providers import (
    BaseIPIntelligenceProvider,
    IPApiProvider,
    IPInfoProvider,
    MockIPIntelligenceProvider,
)


class GeolocationService:
    """
    Dedicated server-side Geolocation Service for MailTraceAI.
    Responsibilities:
    - Queries configured IP intelligence / geolocation provider (IPApi, IPInfo, Mock)
    - Enforces SSRF and RFC1918 protection so private/loopback IPs are never sent to external APIs
    - Sanitizes and normalizes output (never exposes keys, tokens, or headers)
    - Leverages TTL-aware caching (3600s success, 30s failure) to protect quotas
    - Guarantees forensically accurate terminology ('Observed Infrastructure Location')
    """

    def __init__(
        self,
        config: Optional[GeolocationConfig] = None,
        provider: Optional[BaseIPIntelligenceProvider] = None,
        cache: Optional[IPIntelligenceCache] = None,
    ):
        self.config = config or global_geolocation_config
        self.cache = cache or global_ip_cache
        self.provider = provider or self._resolve_provider()

    def _resolve_provider(self) -> BaseIPIntelligenceProvider:
        provider_type = self.config.provider
        if provider_type == "ipinfo":
            return IPInfoProvider(config=self.config)
        elif provider_type == "mock":
            return MockIPIntelligenceProvider()
        return IPApiProvider(config=self.config)

    def get_status(self) -> GeolocationStatusResponse:
        """
        Return safe configuration status.
        STRICT SECURITY: Never exposes credentials or partial key strings.
        """
        raw_status = self.config.get_provider_status()
        return GeolocationStatusResponse(
            provider=raw_status["provider"],
            status=raw_status["status"],
            tier=raw_status["tier"],
            mode=raw_status["mode"],
        )

    async def get_geolocation(self, ip: str) -> GeolocationResponse:
        """
        Lookup normalized, sanitized geolocation data for an IP address.
        """
        clean_ip = (ip or "").strip()
        provider_name = self.provider.get_provider_name()

        # 1. Check Cache
        cached_entry, is_cached = self.cache.get_with_cached_flag(clean_ip)
        if cached_entry is not None:
            source_tag = "backend_cache"
            return self._build_sanitized_response(
                intel=cached_entry,
                provider_name=provider_name,
                source=source_tag,
                cached=True
            )

        # 2. Call Active Provider
        try:
            intel = await self.provider.lookup(clean_ip)
        except Exception as exc:
            # Fallback error response without exposing internal secrets
            intel = IPIntelligence(
                ip=clean_ip,
                scope="unknown",
                enrichment_available=False,
                error=f"Geolocation provider lookup error: {str(exc)}"
            )

        # 3. Store in cache (cache handles distinct TTLs for success vs failure)
        self.cache.set(clean_ip, intel)

        # 4. Source tagging
        if intel.scope in ("private", "loopback", "reserved"):
            source_tag = "local_rfc1918"
        else:
            source_tag = "external_live"

        return self._build_sanitized_response(
            intel=intel,
            provider_name=provider_name,
            source=source_tag,
            cached=False
        )

    def _build_sanitized_response(
        self,
        intel: IPIntelligence,
        provider_name: str,
        source: str,
        cached: bool
    ) -> GeolocationResponse:
        """
        Transforms IPIntelligence into a sanitized GeolocationResponse.
        Guarantees no API credentials, auth headers, or raw tokens are present.
        """
        confidence_val = 0.90
        if intel.confidence is not None:
            confidence_val = intel.confidence
        elif intel.latitude is not None and intel.longitude is not None:
            confidence_val = 0.92
        elif intel.scope in ("private", "loopback", "reserved"):
            confidence_val = 1.0
        else:
            confidence_val = 0.50

        infra_label = intel.infrastructure_type or "Observed Infrastructure Location"
        if "attacker" in infra_label.lower():
            infra_label = "Observed Infrastructure Location"

        return GeolocationResponse(
            ip=intel.ip,
            country=intel.country,
            country_code=intel.country_code,
            region=intel.region,
            city=intel.city,
            latitude=intel.latitude,
            longitude=intel.longitude,
            timezone=intel.timezone,
            isp=intel.isp,
            asn=intel.asn,
            asn_org=intel.asn_org,
            provider=provider_name,
            source=source,
            infrastructure_type=infra_label,
            confidence=confidence_val,
            cached=cached,
            notice=FORENSIC_DISCLAIMER_NOTICE,
            error=intel.error,
        )


# Global default GeolocationService singleton
global_geolocation_service = GeolocationService()
