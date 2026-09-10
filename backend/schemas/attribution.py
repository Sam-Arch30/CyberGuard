from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class EvidenceItem(BaseModel):
    """Specific observation contributing positively or negatively to infrastructure attribution confidence."""
    evidence_type: str = Field(..., description="Machine-readable evidence identifier (e.g. EARLIEST_UNTRUSTED_RELAY, ASN_CONSISTENCY)")
    observation: str = Field(..., description="Human-readable forensic observation and analysis finding")
    contribution: float = Field(..., description="Weight or score contribution toward overall attribution confidence (+/-)")
    source: str = Field(..., description="Originating analysis component or data source (e.g. SMTP Relay, IP Intel, DNS, Campaign Correlator)")
    timestamp: Optional[str] = Field(None, description="Observed event or analysis timestamp (ISO-8601) if applicable")


class AttributionResult(BaseModel):
    """Explainable Probabilistic Infrastructure and Campaign Attribution Result."""
    attribution_id: str = Field(..., description="Unique attribution assessment identifier (e.g. ATTR-ABC12345)")
    email_id: Optional[str] = Field(None, description="Target email identifier or evidence reference")
    case_id: Optional[str] = Field(None, description="Associated investigation case identifier if applicable")
    campaign_id: Optional[str] = Field(None, description="Associated threat campaign identifier if correlated")

    probable_origin_ip: Optional[str] = Field(None, description="Probable origin public sending infrastructure IP address (or Unknown)")
    probable_origin_asn: Optional[str] = Field(None, description="Autonomous System Number of the origin infrastructure (e.g. AS64512)")
    probable_origin_provider: Optional[str] = Field(None, description="Observed hosting provider, ISP, or organization operating origin infrastructure")
    probable_infrastructure_country: Optional[str] = Field(None, description="Country hosting the observed network infrastructure (not physical actor location)")

    confidence_score: float = Field(..., description="Evidence-weighted confidence percentage (0.0 to 100.0)")
    confidence_level: str = Field(..., description="Confidence tier: LOW (0-39), MODERATE (40-69), HIGH (70-84), VERY HIGH (85-100)")

    supporting_evidence: List[EvidenceItem] = Field(default_factory=list, description="Forensic signals that support this infrastructure attribution")
    conflicting_evidence: List[EvidenceItem] = Field(default_factory=list, description="Contradictory signals, anonymization indicators, or uncertainty factors")

    related_domains: List[str] = Field(default_factory=list, description="Correlated malicious, lookalike, or relay domains sharing this infrastructure")
    related_ips: List[str] = Field(default_factory=list, description="Correlated IP addresses identified in the same network or transmission path")
    related_campaigns: List[str] = Field(default_factory=list, description="Related threat campaigns or investigation cases exhibiting shared infrastructure")

    analysis_timestamp: str = Field(..., description="Timestamp when attribution analysis was generated (ISO-8601)")
    disclaimer: str = Field(
        "Location refers to observed network infrastructure and should not be interpreted as the physical location of the threat actor.",
        description="Mandatory forensic disclaimer on infrastructure vs physical identity attribution"
    )


class CaseAttributionResponse(BaseModel):
    """Consolidated infrastructure attribution across all emails in an investigation case."""
    case_id: str = Field(..., description="Case identifier")
    case_number: Optional[str] = Field(None, description="Formatted case number (e.g. CASE-2026-000001)")
    total_emails_analyzed: int = Field(0, description="Total emails evaluated in this case")
    attribution: AttributionResult = Field(..., description="Aggregated case infrastructure attribution result")
    per_email_attributions: List[AttributionResult] = Field(default_factory=list, description="Individual email attribution results")


class CampaignAttributionResponse(BaseModel):
    """Consolidated infrastructure attribution for a multi-case threat campaign cluster."""
    campaign_id: str = Field(..., description="Campaign identifier or label")
    campaign_name: str = Field(..., description="Display title for the campaign cluster")
    related_case_count: int = Field(0, description="Number of correlated cases in this campaign")
    attribution: AttributionResult = Field(..., description="Aggregated campaign infrastructure attribution")
    shared_infrastructure_summary: Dict[str, Any] = Field(default_factory=dict, description="Summary of shared IPs, ASNs, providers, and domains")
