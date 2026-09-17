import os
import re
import abc
import json
import ipaddress
import httpx
from typing import Optional, Dict, Any
from backend.schemas.ip_intelligence import IPIntelligence
from backend.config.geolocation_config import GeolocationConfig, global_geolocation_config
from backend.services.ssrf_protector import SSRFProtector


class BaseIPIntelligenceProvider(abc.ABC):
    """Abstract Base Class for IP Intelligence Geolocation & Infrastructure Providers."""

    @abc.abstractmethod
    async def lookup(self, ip: str) -> IPIntelligence:
        """Perform asynchronous IP lookup and return structured IPIntelligence."""
        pass

    def get_provider_name(self) -> str:
        """Return the lowercase identifier of the provider."""
        return getattr(self, "_provider_name", "custom")

    def is_configured(self) -> bool:
        """Return True if the provider has valid credentials configured."""
        return True


def _validate_and_check_ip(ip_str: str) -> tuple[bool, Optional[str], Optional[IPIntelligence]]:
    """
    Validates IP format and checks for private/reserved/loopback scopes.
    Returns: (is_valid_public, clean_ip, early_return_intelligence)
    """
    if not ip_str or not isinstance(ip_str, str):
        return False, "", IPIntelligence(
            ip="",
            scope="unknown",
            enrichment_available=False,
            error="Invalid IP address format"
        )

    clean_ip = re.sub(r'^(?i:IPv6:)', '', ip_str.strip())
    # Strip any trailing CIDR or port if passed
    clean_ip = clean_ip.split('/')[0].split(':')[0] if '.' in clean_ip and ':' in clean_ip else clean_ip

    try:
        ip_obj = ipaddress.ip_address(clean_ip)
    except ValueError:
        return False, clean_ip, IPIntelligence(
            ip=clean_ip,
            scope="unknown",
            enrichment_available=False,
            error="Invalid IP address format"
        )

    is_doc_ip = (
        clean_ip.startswith("203.0.113.") or
        clean_ip.startswith("198.51.100.") or
        clean_ip.startswith("192.0.2.") or
        clean_ip.startswith("2001:db8:")
    )

    if not is_doc_ip and (
        ip_obj.is_loopback
        or ip_obj.is_private
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
    ):
        scope_name = "private"
        if ip_obj.is_loopback:
            scope_name = "loopback"
        elif ip_obj.is_reserved:
            scope_name = "reserved"

        return False, clean_ip, IPIntelligence(
            ip=clean_ip,
            scope=scope_name,
            enrichment_available=False,
            infrastructure_type="Private/Reserved Address — external geolocation unavailable.",
            error="Private/Reserved Address — external geolocation unavailable."
        )

    return True, clean_ip, None


class IPApiProvider(BaseIPIntelligenceProvider):
    """
    IP-API Provider implementation (ip-api.com).
    Supports free tier and Pro authenticated tier via secret API key.
    """

    def __init__(
        self,
        config: Optional[GeolocationConfig] = None,
        api_key: Optional[str] = None,
        require_key: bool = False
    ):
        self.config = config or global_geolocation_config
        self._explicit_key = api_key
        self.require_key = require_key or os.getenv("GEOLOCATION_REQUIRE_API_KEY", "false").lower() == "true"

    def get_provider_name(self) -> str:
        return "ipapi"

    @property
    def api_key(self) -> Optional[str]:
        if self._explicit_key:
            return self._explicit_key
        if self.config.provider == "ipapi":
            return self.config.get_api_key()
        return os.getenv("IPAPI_KEY") or os.getenv("IP_INTELLIGENCE_API_KEY") or os.getenv("GEOLOCATION_API_KEY")

    def is_configured(self) -> bool:
        return bool(self.api_key)

    async def lookup(self, ip: str) -> IPIntelligence:
        is_public, clean_ip, early_res = _validate_and_check_ip(ip)
        if early_res:
            return early_res

        # If strict key requirement is active and key is missing
        if self.require_key and not self.api_key:
            return IPIntelligence(
                ip=clean_ip,
                scope="public",
                enrichment_available=False,
                error="The geolocation provider has not been configured."
            )

        fields_param = "status,message,country,countryCode,regionName,city,lat,lon,timezone,isp,org,as,proxy,hosting"
        if self.api_key:
            url = f"https://pro.ip-api.com/json/{clean_ip}?key={self.api_key}&fields={fields_param}"
        else:
            url = f"http://ip-api.com/json/{clean_ip}?fields={fields_param}"

        try:
            async with httpx.AsyncClient(timeout=4.0) as client:
                response = await client.get(url)

                if response.status_code == 429:
                    return IPIntelligence(
                        ip=clean_ip,
                        scope="public",
                        enrichment_available=False,
                        error="Rate limit exceeded for IP intelligence provider"
                    )

                if response.status_code in (401, 403):
                    return IPIntelligence(
                        ip=clean_ip,
                        scope="public",
                        enrichment_available=False,
                        error="Invalid or unauthorized API key for IP intelligence provider"
                    )

                if response.status_code != 200:
                    return IPIntelligence(
                        ip=clean_ip,
                        scope="public",
                        enrichment_available=False,
                        error=f"Provider HTTP Error {response.status_code}"
                    )

                try:
                    data = response.json()
                except Exception:
                    return IPIntelligence(
                        ip=clean_ip,
                        scope="public",
                        enrichment_available=False,
                        error="Malformed response received from geolocation provider"
                    )

                if not isinstance(data, dict):
                    return IPIntelligence(
                        ip=clean_ip,
                        scope="public",
                        enrichment_available=False,
                        error="Malformed response received from geolocation provider"
                    )

                if data.get("status") == "fail":
                    msg = str(data.get("message", "IP lookup failed")).lower()
                    if "invalid key" in msg or "key" in msg:
                        err_msg = "Invalid or unauthorized API key for IP intelligence provider"
                    elif "reserved" in msg or "private" in msg:
                        err_msg = "Private/Reserved Address — external geolocation unavailable."
                    elif "quota" in msg or "rate limit" in msg:
                        err_msg = "Rate limit exceeded for IP intelligence provider"
                    else:
                        err_msg = data.get("message", "IP lookup failed")

                    return IPIntelligence(
                        ip=clean_ip,
                        scope="public" if "private" not in msg and "reserved" not in msg else "private",
                        enrichment_available=False,
                        error=err_msg
                    )

                asn_raw = data.get("as", "")
                asn_code = None
                asn_org = None
                if asn_raw:
                    asn_match = re.match(r'^(AS\d+)\s*(.*)', str(asn_raw))
                    if asn_match:
                        asn_code = asn_match.group(1)
                        asn_org = asn_match.group(2).strip() or None
                    else:
                        asn_code = str(asn_raw)

                is_hosting = bool(data.get("hosting", False))
                is_proxy = bool(data.get("proxy", False))
                infra_type = (
                    "Hosting infrastructure"
                    if is_hosting
                    else ("Corporate / ISP" if data.get("org") else "Observed Infrastructure Location")
                )

                return IPIntelligence(
                    ip=clean_ip,
                    scope="public",
                    enrichment_available=True,
                    country=data.get("country"),
                    country_code=data.get("countryCode"),
                    region=data.get("regionName"),
                    city=data.get("city"),
                    latitude=data.get("lat"),
                    longitude=data.get("lon"),
                    timezone=data.get("timezone"),
                    asn=asn_code,
                    asn_org=asn_org,
                    isp=data.get("isp"),
                    organization=data.get("org"),
                    is_hosting=is_hosting,
                    is_proxy_vpn_tor=is_proxy,
                    infrastructure_type=infra_type,
                    source="ipapi",
                    confidence=0.92,
                    error=None
                )
        except httpx.TimeoutException:
            return IPIntelligence(
                ip=clean_ip,
                scope="public",
                enrichment_available=False,
                error="Provider request timeout"
            )
        except (httpx.ConnectError, httpx.ConnectTimeout, httpx.NetworkError):
            return IPIntelligence(
                ip=clean_ip,
                scope="public",
                enrichment_available=False,
                error="Geolocation provider temporarily unavailable"
            )
        except Exception as e:
            return IPIntelligence(
                ip=clean_ip,
                scope="public",
                enrichment_available=False,
                error=f"Provider lookup error: {str(e)}"
            )


class IPInfoProvider(BaseIPIntelligenceProvider):
    """
    IPInfo Provider implementation (ipinfo.io).
    Uses secret access token / API key.
    """

    def __init__(
        self,
        config: Optional[GeolocationConfig] = None,
        api_key: Optional[str] = None,
        require_key: bool = True
    ):
        self.config = config or global_geolocation_config
        self._explicit_key = api_key
        self.require_key = require_key

    def get_provider_name(self) -> str:
        return "ipinfo"

    @property
    def api_key(self) -> Optional[str]:
        if self._explicit_key:
            return self._explicit_key
        if self.config.provider == "ipinfo":
            return self.config.get_api_key()
        return os.getenv("IPINFO_TOKEN") or os.getenv("IPINFO_API_KEY") or os.getenv("GEOLOCATION_API_KEY")

    def is_configured(self) -> bool:
        return bool(self.api_key)

    async def lookup(self, ip: str) -> IPIntelligence:
        is_public, clean_ip, early_res = _validate_and_check_ip(ip)
        if early_res:
            return early_res

        # Missing credential handling
        if not self.api_key:
            return IPIntelligence(
                ip=clean_ip,
                scope="public",
                enrichment_available=False,
                error="The geolocation provider has not been configured."
            )

        url = f"https://ipinfo.io/{clean_ip}/json?token={self.api_key}"

        try:
            async with httpx.AsyncClient(timeout=4.0) as client:
                response = await client.get(url)

                if response.status_code == 429:
                    return IPIntelligence(
                        ip=clean_ip,
                        scope="public",
                        enrichment_available=False,
                        error="Rate limit exceeded for IP intelligence provider"
                    )

                if response.status_code in (401, 403):
                    return IPIntelligence(
                        ip=clean_ip,
                        scope="public",
                        enrichment_available=False,
                        error="Invalid or unauthorized API key for IP intelligence provider"
                    )

                if response.status_code != 200:
                    return IPIntelligence(
                        ip=clean_ip,
                        scope="public",
                        enrichment_available=False,
                        error=f"Provider HTTP Error {response.status_code}"
                    )

                try:
                    data = response.json()
                except Exception:
                    return IPIntelligence(
                        ip=clean_ip,
                        scope="public",
                        enrichment_available=False,
                        error="Malformed response received from geolocation provider"
                    )

                if not isinstance(data, dict):
                    return IPIntelligence(
                        ip=clean_ip,
                        scope="public",
                        enrichment_available=False,
                        error="Malformed response received from geolocation provider"
                    )

                if "error" in data:
                    err_info = data.get("error", {})
                    msg = ""
                    if isinstance(err_info, dict):
                        msg = err_info.get("message", "").lower()
                    else:
                        msg = str(err_info).lower()

                    if "token" in msg or "key" in msg or "unauthorized" in msg:
                        err_msg = "Invalid or unauthorized API key for IP intelligence provider"
                    elif "rate" in msg or "limit" in msg:
                        err_msg = "Rate limit exceeded for IP intelligence provider"
                    else:
                        err_msg = msg or "Provider lookup error"

                    return IPIntelligence(
                        ip=clean_ip,
                        scope="public",
                        enrichment_available=False,
                        error=err_msg
                    )

                # Parse coordinates from "loc": "lat,lon"
                lat: Optional[float] = None
                lon: Optional[float] = None
                loc_str = data.get("loc")
                if loc_str and "," in loc_str:
                    try:
                        p_lat, p_lon = loc_str.split(",", 1)
                        lat = float(p_lat.strip())
                        lon = float(p_lon.strip())
                    except (ValueError, TypeError):
                        pass

                # Parse ASN & Organization from "org": "AS15169 Google LLC"
                asn_code: Optional[str] = None
                asn_org: Optional[str] = None
                org_raw = data.get("org", "")
                if org_raw:
                    asn_match = re.match(r'^(AS\d+)\s*(.*)', str(org_raw))
                    if asn_match:
                        asn_code = asn_match.group(1)
                        asn_org = asn_match.group(2).strip() or None
                    else:
                        asn_code = str(org_raw)

                privacy = data.get("privacy") or {}
                is_proxy = bool(privacy.get("vpn") or privacy.get("proxy") or privacy.get("tor")) if isinstance(privacy, dict) else False
                is_hosting = bool(privacy.get("hosting")) if isinstance(privacy, dict) else False

                return IPIntelligence(
                    ip=clean_ip,
                    scope="public",
                    enrichment_available=True,
                    country=data.get("country"),
                    country_code=data.get("country"),
                    region=data.get("region"),
                    city=data.get("city"),
                    latitude=lat,
                    longitude=lon,
                    timezone=data.get("timezone"),
                    asn=asn_code,
                    asn_org=asn_org,
                    isp=asn_org or data.get("hostname"),
                    organization=asn_org,
                    is_hosting=is_hosting,
                    is_proxy_vpn_tor=is_proxy,
                    infrastructure_type="Hosting infrastructure" if is_hosting else "Observed Infrastructure Location",
                    source="ipinfo",
                    confidence=0.94,
                    error=None
                )
        except httpx.TimeoutException:
            return IPIntelligence(
                ip=clean_ip,
                scope="public",
                enrichment_available=False,
                error="Provider request timeout"
            )
        except (httpx.ConnectError, httpx.ConnectTimeout, httpx.NetworkError):
            return IPIntelligence(
                ip=clean_ip,
                scope="public",
                enrichment_available=False,
                error="Geolocation provider temporarily unavailable"
            )
        except Exception as e:
            return IPIntelligence(
                ip=clean_ip,
                scope="public",
                enrichment_available=False,
                error=f"Provider lookup error: {str(e)}"
            )


class MockIPIntelligenceProvider(BaseIPIntelligenceProvider):
    """
    Fallback / Mock Provider for offline execution, unit tests, or keyless deployments.
    Generates realistic contextual data for test public IPs.
    """

    def get_provider_name(self) -> str:
        return "mock"

    def is_configured(self) -> bool:
        return True

    async def lookup(self, ip: str) -> IPIntelligence:
        is_public, clean_ip, early_res = _validate_and_check_ip(ip)
        if early_res:
            return early_res

        # Deterministic mock generation based on IP octets
        if clean_ip.startswith("203.0.113.") or clean_ip.startswith("198.51.100.") or clean_ip.startswith("192.0.2."):
            return IPIntelligence(
                ip=clean_ip,
                scope="public",
                enrichment_available=True,
                country="Netherlands",
                country_code="NL",
                region="North Holland",
                city="Amsterdam",
                latitude=52.3676,
                longitude=4.9041,
                timezone="Europe/Amsterdam",
                asn="AS12345",
                asn_org="Example Cloud Hosting BV",
                isp="Example Cloud Infrastructure",
                organization="Example Cloud Services",
                is_hosting=True,
                is_proxy_vpn_tor=False,
                infrastructure_type="Hosting infrastructure",
                source="mock",
                confidence=0.90,
                error=None
            )

        return IPIntelligence(
            ip=clean_ip,
            scope="public",
            enrichment_available=True,
            country="United States",
            country_code="US",
            region="California",
            city="Mountain View",
            latitude=37.3860,
            longitude=-122.0839,
            timezone="America/Los_Angeles",
            asn="AS15169",
            asn_org="Google LLC",
            isp="Google LLC",
            organization="Google Cloud Platform",
            is_hosting=True,
            is_proxy_vpn_tor=False,
            infrastructure_type="Hosting infrastructure",
            source="mock",
            confidence=0.90,
            error=None
        )


class UnconfiguredIPIntelligenceProvider(BaseIPIntelligenceProvider):
    """
    Explicit unconfigured provider.
    Used when no external provider credential is configured or when running keyless.
    Returns honest un-enriched state per Phase 11 & Phase 19.
    """

    def get_provider_name(self) -> str:
        return "unconfigured"

    def is_configured(self) -> bool:
        return False

    async def lookup(self, ip: str) -> IPIntelligence:
        is_public, clean_ip, early_res = _validate_and_check_ip(ip)
        if early_res:
            return early_res

        return IPIntelligence(
            ip=clean_ip,
            scope="public",
            enrichment_available=False,
            error="Threat intelligence provider not configured."
        )

