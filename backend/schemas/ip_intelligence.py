from typing import Optional
from pydantic import BaseModel, Field

FORENSIC_DISCLAIMER_NOTICE = (
    "IP geolocation represents the estimated location of observed network infrastructure "
    "and does not establish the physical location of the threat actor."
)


class IPIntelligence(BaseModel):
    ip: str = Field(..., description="IP address string")
    scope: str = Field("public", description="Scope: public, private, loopback, link_local, reserved, unknown")
    enrichment_available: bool = Field(True, description="True if public IP enrichment data was obtained or attempted")
    country: Optional[str] = Field(None, description="Country name or ISO code")
    country_code: Optional[str] = Field(None, description="2-letter country code (ISO-3166-1 alpha-2)")
    region: Optional[str] = Field(None, description="State or Region name")
    city: Optional[str] = Field(None, description="City name")
    latitude: Optional[float] = Field(None, description="Latitude coordinate")
    longitude: Optional[float] = Field(None, description="Longitude coordinate")
    timezone: Optional[str] = Field(None, description="Timezone string e.g. UTC, Europe/Amsterdam")
    asn: Optional[str] = Field(None, description="Autonomous System Number e.g. AS12345")
    asn_org: Optional[str] = Field(None, description="ASN Organization name")
    isp: Optional[str] = Field(None, description="Internet Service Provider name")
    organization: Optional[str] = Field(None, description="Organization name")
    is_hosting: Optional[bool] = Field(None, description="True if IP belongs to cloud/datacenter hosting provider")
    is_proxy_vpn_tor: Optional[bool] = Field(None, description="True if IP belongs to known proxy, VPN, or Tor exit node")
    infrastructure_type: Optional[str] = Field("Observed Infrastructure Location", description="Type description e.g. Observed Infrastructure Location, Hosting infrastructure, Corporate / ISP")
    source: Optional[str] = Field(None, description="Source provider identifier or cache source")
    confidence: Optional[float] = Field(None, description="Confidence score 0.0 to 1.0")
    error: Optional[str] = Field(None, description="Error message if provider lookup failed, timed out, or rate limited")


class GeolocationResponse(BaseModel):
    """
    Sanitized normalized response for Geolocation Map and forensic inspection.
    STRICT SECURITY GUARANTEE: Never exposes API keys, tokens, or internal provider secrets.
    """
    ip: str = Field(..., description="IP address string")
    country: Optional[str] = Field(None, description="Country name")
    country_code: Optional[str] = Field(None, description="2-letter country code")
    region: Optional[str] = Field(None, description="Region or state name")
    city: Optional[str] = Field(None, description="City name")
    latitude: Optional[float] = Field(None, description="Latitude coordinate")
    longitude: Optional[float] = Field(None, description="Longitude coordinate")
    timezone: Optional[str] = Field(None, description="Timezone string")
    isp: Optional[str] = Field(None, description="Internet Service Provider name")
    asn: Optional[str] = Field(None, description="Autonomous System Number e.g. AS15169")
    asn_org: Optional[str] = Field(None, description="ASN Organization name")
    provider: str = Field(..., description="Active geolocation provider identifier")
    source: str = Field("external_live", description="Data provenance (external_live, backend_cache, local_rfc1918)")
    infrastructure_type: str = Field("Observed Infrastructure Location", description="Forensically accurate infrastructure label")
    confidence: float = Field(0.9, description="Confidence score 0.0 - 1.0")
    cached: bool = Field(False, description="True if retrieved from backend cache")
    notice: str = Field(FORENSIC_DISCLAIMER_NOTICE, description="Forensic accuracy disclaimer notice")
    error: Optional[str] = Field(None, description="Error or fallback reason if geolocation unavailable")


class GeolocationStatusResponse(BaseModel):
    """
    Safe status response for the configured Geolocation Provider.
    STRICT SECURITY: Never leaks credentials or partial key strings.
    """
    provider: str = Field(..., description="Active geolocation provider identifier (e.g. ipapi, ipinfo, mock)")
    status: str = Field(..., description="High-level status: 'Configured' or 'Not Configured'")
    tier: str = Field(..., description="Configured tier e.g. authenticated_pro, free_unauthenticated, offline_mock")
    mode: str = Field(..., description="Operational mode: external_live, rate_limited, air_gapped")
