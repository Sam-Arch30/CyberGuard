from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from backend.schemas.correlation import SharedIndicator
from backend.schemas.graph import InvestigationGraphResponse


class RelatedEmailItem(BaseModel):
    """Forensic telemetry and similarity summary for a related email message."""
    id: str = Field(..., description="Unique email identifier or evidence ID")
    email_sha256: Optional[str] = Field(None, description="SHA-256 digest of raw email file")
    subject: str = Field(..., description="Email subject line")
    sender: str = Field(..., description="Sender From address")
    recipient: str = Field(..., description="Recipient To address")
    received_time: str = Field(..., description="Formatted timestamp or ISO date")
    threat_score: float = Field(0.0, description="Global threat score 0-100")
    severity: str = Field("low", description="Severity classification: low, medium, high, critical")
    campaign: Optional[str] = Field(None, description="Associated Campaign identifier (e.g. C-042)")
    similarity: float = Field(0.0, description="Confidence similarity percentage (0-100)")
    shared_indicators: List[SharedIndicator] = Field(default_factory=list, description="List of technical indicators shared with target email")
    status: str = Field("Investigating", description="Investigation status: Investigating, Flagged, Unrelated, Confirmed, Escalated")
    is_synthetic: bool = Field(False, description="True if synthetic/demo telemetry; false if real observed evidence")
    correlation_reasons: List[str] = Field(default_factory=list, description="Human-readable explanations for correlation")


class CrossEmailTimelineEvent(BaseModel):
    """Chronological event across correlated email infrastructure."""
    id: str = Field(..., description="Unique timeline event identifier")
    timestamp: str = Field(..., description="ISO timestamp of observed event")
    time_display: str = Field(..., description="Short display time (e.g. '09:14' or '10:02')")
    event_type: str = Field(..., description="Type of event: email_delivered, domain_registered, redirect_identified, ip_observed, harvester_deployed")
    title: str = Field(..., description="Short title of the attack timeline milestone")
    description: str = Field(..., description="Forensic context detailing the event")
    related_emails: List[str] = Field(default_factory=list, description="IDs of emails involved in this milestone")
    indicators: List[str] = Field(default_factory=list, description="Associated technical indicators")
    severity: str = Field("medium", description="Severity level: low, medium, high, critical")


class CrossEmailAnalysisResponse(BaseModel):
    """Response payload when an email analysis completes and cross-email correlation is triggered."""
    related_activity_detected: bool = Field(..., description="Whether correlated emails meet significance threshold")
    related_count: int = Field(0, description="Total count of potentially related emails discovered")
    campaign_confidence: Optional[float] = Field(None, description="Campaign cluster confidence percentage (e.g. 89.0)")
    campaign_id: Optional[str] = Field(None, description="Primary correlated campaign cluster ID")
    strongest_relationships: List[str] = Field(
        default_factory=list,
        description="Top relationship explanations (e.g. 'same redirect domain', 'same ASN', 'highly similar HTML template')"
    )
    related_emails: List[RelatedEmailItem] = Field(default_factory=list, description="Ranked related emails table items")
    timeline: List[CrossEmailTimelineEvent] = Field(default_factory=list, description="Cross-email chronological attack timeline")
    is_synthetic: bool = Field(False, description="Whether this evaluation contains synthetic demo cluster data")


class ComparisonFieldItem(BaseModel):
    """Side-by-side comparison for a specific forensic field across selected emails."""
    field_key: str = Field(..., description="Machine identifier for field (e.g. 'sender_ip', 'spf_result')")
    field_label: str = Field(..., description="Human-readable label for field")
    values: Dict[str, Any] = Field(default_factory=dict, description="Map of email_id -> string or structured value")
    comparison_status: str = Field(..., description="Highlight status: identical, similar, conflicting, unique")
    similarity_score: Optional[float] = Field(None, description="0.0 to 1.0 similarity score where applicable")
    explanation: Optional[str] = Field(None, description="Analyst note explaining difference or convergence")


class ComparisonCategory(BaseModel):
    """Group of comparative fields representing one forensic dimension."""
    category_id: str = Field(..., description="Category key: headers, auth, relay, domains, ips, urls, content, attachments, threat_scores, fingerprints")
    category_title: str = Field(..., description="Category display title")
    items: List[ComparisonFieldItem] = Field(default_factory=list, description="Field comparison rows")
    category_alignment: str = Field("mixed", description="Dominant category status: identical, similar, conflicting, mixed")


class ComparisonEmailMeta(BaseModel):
    """Header overview for an email in comparison mode."""
    id: str = Field(..., description="Email identifier")
    subject: str = Field(..., description="Subject line")
    sender: str = Field(..., description="Sender From header")
    recipient: str = Field(..., description="Recipient To header")
    threat_score: float = Field(0.0, description="Threat score")
    severity: str = Field("low", description="Severity level")
    received_time: str = Field(..., description="Delivery timestamp")
    is_synthetic: bool = Field(False, description="Synthetic demo flag")


class ComparisonMatrixResponse(BaseModel):
    """Side-by-side comparison matrix for 2-5 selected emails."""
    emails: List[ComparisonEmailMeta] = Field(default_factory=list, description="Metadata columns for compared emails")
    categories: List[ComparisonCategory] = Field(default_factory=list, description="Detailed comparison categories")
    summary: Dict[str, int] = Field(
        default_factory=dict,
        description="Counts of identical, similar, conflicting, and unique indicators"
    )
    overall_alignment_percentage: float = Field(0.0, description="Overall infrastructure similarity score (0-100%)")


class CompareEmailsRequest(BaseModel):
    """Request payload to compare 2-5 emails side-by-side."""
    email_ids: List[str] = Field(..., min_length=2, max_length=5, description="List of 2 to 5 email IDs to compare")
    current_email: Optional[Dict[str, Any]] = Field(None, description="Optional raw or analyzed email payload for the active email")


class AnalystDecisionRequest(BaseModel):
    """Payload to record analyst decision or false positive feedback on related emails."""
    email_id_a: str = Field(..., description="Source email identifier")
    email_id_b: str = Field(..., description="Target correlated email identifier")
    decision: str = Field(
        ...,
        description="Action type: 'mark_unrelated', 'confirmed_related', 'assigned_campaign', 'added_to_case', 'escalated'"
    )
    campaign_id: Optional[str] = Field(None, description="Campaign ID if assigning to campaign")
    case_id: Optional[str] = Field(None, description="Case ID if adding to case")
    analyst: Optional[str] = Field("SOC Analyst", description="Investigator username/callsign")
    notes: Optional[str] = Field(None, description="Forensic rationale or case justification")


class AnalystDecisionItem(BaseModel):
    """Persisted record of an analyst's decision on correlated emails."""
    id: str = Field(..., description="Decision UUID")
    email_id_a: str = Field(..., description="Source email identifier")
    email_id_b: str = Field(..., description="Target correlated email identifier")
    decision: str = Field(..., description="Decision type")
    campaign_id: Optional[str] = Field(None, description="Campaign ID")
    case_id: Optional[str] = Field(None, description="Case ID")
    analyst: str = Field(..., description="Investigator username")
    notes: Optional[str] = Field(None, description="Analyst notes")
    created_at: str = Field(..., description="Timestamp ISO")


class CrossEmailGraphFilterRequest(BaseModel):
    """Request to generate or filter a multi-email connection graph."""
    email_ids: List[str] = Field(..., min_length=1, description="List of email IDs to include in graph")
    node_types: Optional[List[str]] = Field(None, description="Allowed node types to filter (Emails, Domains, IPs, URLs, ASNs, Recipients, Campaigns)")
