from typing import List, Optional
from pydantic import BaseModel, Field

from backend.schemas.lookalike import LookalikeDetectionResult


class DNSRecords(BaseModel):
    """DNS records extracted for a domain."""
    a: List[str] = Field(default_factory=list, description="IPv4 addresses (A records)")
    aaaa: List[str] = Field(default_factory=list, description="IPv6 addresses (AAAA records)")
    mx: List[str] = Field(default_factory=list, description="Mail exchangers (MX records)")
    ns: List[str] = Field(default_factory=list, description="Authoritative nameservers (NS records)")
    txt: List[str] = Field(default_factory=list, description="Text records (TXT records)")


class DomainRegistration(BaseModel):
    """Domain registration details obtained from RDAP / WHOIS sources."""
    registrar: Optional[str] = Field(None, description="Registrar organization name")
    registration_date: Optional[str] = Field(None, description="Creation or registration timestamp (ISO)")
    expiration_date: Optional[str] = Field(None, description="Expiration timestamp (ISO) if available")
    nameservers: List[str] = Field(default_factory=list, description="Delegated nameservers from registration data")
    status: List[str] = Field(default_factory=list, description="Domain status codes (e.g., clientTransferProhibited)")
    country: Optional[str] = Field(None, description="Registrant country if available")
    registration_source: str = Field("unavailable", description="Data source: RDAP, WHOIS, or unavailable")


class DomainIntelligence(BaseModel):
    """Contextual DNS and registration intelligence for an observed domain."""
    domain: str = Field(..., description="Observed domain name")
    punycode: Optional[str] = Field(None, description="ASCII / Punycode representation if internationalized")
    dns: DNSRecords = Field(default_factory=DNSRecords, description="Resolved DNS records")
    registration: DomainRegistration = Field(default_factory=DomainRegistration, description="Registration metadata")
    domain_age_days: Optional[int] = Field(None, description="Reliable age in days from creation date, or None")
    newly_registered_domain: Optional[bool] = Field(None, description="Neutral flag: True if domain age <= threshold (default 30 days)")
    is_resolvable: bool = Field(False, description="True if domain resolves at least one DNS record")
    status_message: Optional[str] = Field(None, description="Resolution status (e.g., Active, NXDOMAIN, Timeout)")
    lookalike: Optional[LookalikeDetectionResult] = Field(None, description="Potential lookalike domain / brand impersonation findings if detected")

