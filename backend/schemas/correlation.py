from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict


class SharedIndicator(BaseModel):
    """Specific indicator observed in common between two or more forensic entities."""
    type: str = Field(..., description="Indicator type (ip, domain, reply_to, sender, attachment_hash, url_domain, nameserver, registrar, asn, brand, subject)")
    value: str = Field(..., description="The shared indicator value (e.g., 185.220.101.5 or evil-billing.com)")
    details: Optional[str] = Field(None, description="Context or explanation of the indicator")


class MatchedSignalDetail(BaseModel):
    """Detailed breakdown of a matching correlation signal and its contribution."""
    signal_name: str = Field(..., description="Name of the signal (e.g., same_ip, same_attachment_hash)")
    weight: float = Field(..., description="Base weight configured for this signal")
    matched_values: List[str] = Field(default_factory=list, description="Specific matched values for this signal")
    contribution: float = Field(..., description="Weighted contribution towards the overall correlation score")


class RelatedCaseItem(BaseModel):
    """A case identified as having shared infrastructure or behavioral overlap."""
    case_id: str = Field(..., description="Target case unique database identifier")
    case_number: str = Field(..., description="Readable case number (e.g., CASE-2026-000031)")
    title: str = Field(..., description="Title of the related case")
    severity: str = Field(..., description="Severity level of the related case")
    status: str = Field(..., description="Current status of the related case")
    correlation_score: float = Field(..., description="Explainable correlation score between 0.0 and 1.0")
    relationship_label: str = Field(..., description="Defensible relationship label (e.g., Likely campaign relationship)")
    shared_evidence_summary: str = Field(..., description="Concise human-readable evidence summary (e.g., '2 IPs, 1 domain, 1 Reply-To address')")
    shared_indicators: List[SharedIndicator] = Field(default_factory=list, description="List of all shared indicators")
    matching_signals: Dict[str, MatchedSignalDetail] = Field(default_factory=dict, description="Breakdown of matched signals and scoring weights")

    model_config = ConfigDict(from_attributes=True)


class CorrelatedIngestedEmail(BaseModel):
    """An ingested .eml email identified as sharing IOCs or infrastructure with the target email."""
    id: str = Field(..., description="Evidence ID or unique email identifier")
    evidence_id: Optional[str] = Field(None, description="Deterministic evidence ID (e.g. EVD-73D3AA17A2)")
    sha256: Optional[str] = Field(None, description="Cryptographic SHA-256 hash")
    original_filename: Optional[str] = Field(None, description="Original .eml filename")
    subject: str = Field(..., description="Email subject line")
    sender: str = Field(..., description="Sender address or RFC-5322 From header")
    recipient: Optional[str] = Field(None, description="Recipient address")
    threat_score: float = Field(0.0, description="Calculated threat score (0-100)")
    severity: str = Field("low", description="Severity classification (critical, high, medium, low)")
    timestamp: str = Field("", description="Ingestion or message timestamp")
    similarity_score: float = Field(0.0, description="Pairwise similarity score (0.0 to 1.0)")
    similarity_percentage: int = Field(0, description="Formatted similarity percentage (0-100%)")
    relationship_label: str = Field("Shared IOCs", description="Explainable relationship label")
    shared_evidence_summary: str = Field("", description="Human-readable summary of shared IOCs")
    shared_indicators: List[SharedIndicator] = Field(default_factory=list, description="List of shared forensic indicators")

    model_config = ConfigDict(from_attributes=True)


class CampaignCorrelationResponse(BaseModel):
    """Correlation analysis output comparing an email or case against existing investigations."""
    related_cases: List[RelatedCaseItem] = Field(default_factory=list, description="Cases exhibiting shared infrastructure or behavioral overlap")
    correlated_emails: List[CorrelatedIngestedEmail] = Field(default_factory=list, description="Other ingested .eml emails exhibiting shared IOCs")
    correlation_score: float = Field(0.0, description="Highest correlation score among related cases/emails, or pairwise comparison score")
    relationship_label: str = Field("Inconclusive / No significant relationship", description="Highest relationship confidence label")
    shared_indicators: List[SharedIndicator] = Field(default_factory=list, description="Aggregated list of all shared indicators across related investigations")


class DirectCompareRequest(BaseModel):
    """Payload to compare two arbitrary email analyses or indicator collections."""
    entity_a: Dict[str, Any] = Field(..., description="First email analysis or indicator dictionary")
    entity_b: Dict[str, Any] = Field(..., description="Second email analysis or indicator dictionary")


class DirectCompareResponse(BaseModel):
    """Comparison result between two specific entities."""
    correlation_score: float = Field(..., description="Pairwise explainable similarity score (0.0 to 1.0)")
    relationship_label: str = Field(..., description="Non-attribution relationship label")
    shared_evidence_summary: str = Field(..., description="Formatted summary string")
    shared_indicators: List[SharedIndicator] = Field(default_factory=list, description="Shared indicators")
    matching_signals: Dict[str, MatchedSignalDetail] = Field(default_factory=dict, description="Breakdown of signal weights and matches")


# =============================================================================
# Multidimensional Campaign Fingerprinting Schemas
# =============================================================================

class InfrastructureFingerprint(BaseModel):
    origin_ip: Optional[str] = Field(None, description="Probable originating or first-hop IP")
    relay_ips: List[str] = Field(default_factory=list, description="Relay and hop IPs observed")
    asns: List[str] = Field(default_factory=list, description="Autonomous System Numbers")
    hosting_providers: List[str] = Field(default_factory=list, description="Hosting providers and ISPs")
    nameservers: List[str] = Field(default_factory=list, description="Authoritative nameservers")
    mx_infrastructure: List[str] = Field(default_factory=list, description="Mail exchange infrastructure")


class DomainFingerprint(BaseModel):
    sender_domain: Optional[str] = Field(None, description="Sender domain")
    reply_to_domain: Optional[str] = Field(None, description="Reply-To domain")
    linked_domains: List[str] = Field(default_factory=list, description="Domains linked inside email body")
    registration_age_days: Optional[int] = Field(None, description="Domain registration age in days")
    registrars: List[str] = Field(default_factory=list, description="Domain registrars")
    dns_characteristics: Dict[str, Any] = Field(default_factory=dict, description="DNS characteristics and records")
    lookalike_targets: List[str] = Field(default_factory=list, description="Targeted brand or impersonation targets")


class UrlFingerprint(BaseModel):
    normalized_urls: List[str] = Field(default_factory=list, description="Canonical normalized URLs")
    destination_domains: List[str] = Field(default_factory=list, description="Destination domains")
    redirect_chains: List[List[str]] = Field(default_factory=list, description="Redirect chains observed")
    path_patterns: List[str] = Field(default_factory=list, description="URL path regex or token patterns")
    query_parameter_keys: List[str] = Field(default_factory=list, description="Query parameter structure")


class EmailStructureFingerprint(BaseModel):
    subject_pattern: str = Field("", description="Normalized token pattern of subject line")
    sender_naming_pattern: str = Field("", description="Sender display name format / persona pattern")
    html_template_hash: str = Field("", description="SimHash / DOM structural hash of email HTML template")
    header_patterns: Dict[str, str] = Field(default_factory=dict, description="Header presence and ordering patterns")
    attachment_names: List[str] = Field(default_factory=list, description="Attachment filenames and patterns")
    attachment_types: List[str] = Field(default_factory=list, description="Attachment MIME types and extensions")


class ContentFingerprint(BaseModel):
    nlp_embeddings: Dict[str, float] = Field(default_factory=dict, description="TF-IDF or embedding vector representation")
    phishing_intent: str = Field("unknown", description="Categorized phishing intent (e.g. credential_harvesting, wire_fraud)")
    repeated_phrases: List[str] = Field(default_factory=list, description="Characteristic repeated phrases / n-grams")
    targeted_organizations: List[str] = Field(default_factory=list, description="Targeted organizations or business units")
    requested_actions: List[str] = Field(default_factory=list, description="Actions requested of the victim")


class AuthenticationFingerprint(BaseModel):
    spf_pattern: str = Field("neutral", description="SPF result and mechanism pattern")
    dkim_pattern: str = Field("neutral", description="DKIM verification and selector pattern")
    dmarc_pattern: str = Field("neutral", description="DMARC policy and alignment status")
    alignment_status: Dict[str, bool] = Field(default_factory=dict, description="SPF/DKIM identifier alignment")


class AttachmentFingerprint(BaseModel):
    hashes: List[str] = Field(default_factory=list, description="Exact SHA-256 hashes")
    fuzzy_hashes: List[str] = Field(default_factory=list, description="Fuzzy / SimHash payload hashes")
    filenames: List[str] = Field(default_factory=list, description="Attachment filenames")
    mime_types: List[str] = Field(default_factory=list, description="Payload MIME types")


class CampaignFingerprint(BaseModel):
    """Multidimensional fingerprint for high-fidelity campaign clustering."""
    infrastructure: InfrastructureFingerprint = Field(default_factory=InfrastructureFingerprint)
    domain: DomainFingerprint = Field(default_factory=DomainFingerprint)
    url: UrlFingerprint = Field(default_factory=UrlFingerprint)
    email_structure: EmailStructureFingerprint = Field(default_factory=EmailStructureFingerprint)
    content: ContentFingerprint = Field(default_factory=ContentFingerprint)
    authentication: AuthenticationFingerprint = Field(default_factory=AuthenticationFingerprint)
    attachments: AttachmentFingerprint = Field(default_factory=AttachmentFingerprint)


# =============================================================================
# Category Scores & Campaign Objects
# =============================================================================

class CategorySimilarityScores(BaseModel):
    infrastructure_similarity: float = Field(0.0, description="Infrastructure similarity percentage (0-100)")
    domain_similarity: float = Field(0.0, description="Domain similarity percentage (0-100)")
    url_similarity: float = Field(0.0, description="URL similarity percentage (0-100)")
    content_similarity: float = Field(0.0, description="Content / NLP similarity percentage (0-100)")
    template_similarity: float = Field(0.0, description="HTML / email template similarity percentage (0-100)")
    authentication_similarity: float = Field(0.0, description="Authentication similarity percentage (0-100)")
    attachment_similarity: float = Field(0.0, description="Attachment / payload similarity percentage (0-100)")
    overall_confidence: float = Field(0.0, description="Weighted composite campaign confidence (0-100)")
    category_weights: Dict[str, float] = Field(default_factory=dict, description="Active weights applied")
    strongest_signals: List[str] = Field(default_factory=list, description="Strongest correlation reasons")


class CampaignTimelineEvent(BaseModel):
    id: str = Field(..., description="Unique event ID")
    timestamp: str = Field(..., description="ISO timestamp")
    event_type: str = Field(..., description="first_email | new_domain | infrastructure_change | new_url | victim_expansion")
    title: str = Field(..., description="Short event title")
    description: str = Field(..., description="Detailed event description")
    severity: str = Field("info", description="Severity level: info, low, medium, high, critical")
    indicators: List[str] = Field(default_factory=list, description="Indicators involved in this event")


class CampaignIOC(BaseModel):
    type: str = Field(..., description="ip, domain, url, hash, sender, recipient")
    value: str = Field(..., description="Indicator value")
    first_seen: str = Field(..., description="First observed timestamp")
    last_seen: str = Field(..., description="Last observed timestamp")
    confidence: float = Field(1.0, description="Confidence score")


class CampaignClusterItem(BaseModel):
    """Campaign summary card format."""
    campaign_id: str = Field(..., description="Campaign ID (e.g. C-042)")
    name: str = Field(..., description="Descriptive campaign title")
    first_seen: str = Field(..., description="First seen date")
    last_seen: str = Field(..., description="Last seen date")
    email_count: int = Field(0, description="Number of related emails")
    recipient_count: int = Field(0, description="Unique recipient count")
    sender_count: int = Field(0, description="Unique sender identities")
    domain_count: int = Field(0, description="Unique domain count")
    ip_count: int = Field(0, description="Unique IP addresses")
    asn_count: int = Field(0, description="Unique ASNs")
    overall_confidence: float = Field(0.0, description="Overall campaign confidence (0-100)")
    dominant_attack_type: str = Field("Phishing", description="Dominant attack type")
    targeted_brands: List[str] = Field(default_factory=list, description="Targeted brands")
    targeted_organizations: List[str] = Field(default_factory=list, description="Targeted victim organizations")
    category_scores: Optional[CategorySimilarityScores] = Field(None, description="Category similarity breakdown")


class CampaignDetailResponse(CampaignClusterItem):
    """Detailed campaign response with all 9 tabs data."""
    fingerprint: CampaignFingerprint = Field(default_factory=CampaignFingerprint)
    associated_iocs: List[CampaignIOC] = Field(default_factory=list)
    timeline: List[CampaignTimelineEvent] = Field(default_factory=list)
    emails: List[Dict[str, Any]] = Field(default_factory=list)
    infrastructure_summary: Dict[str, Any] = Field(default_factory=dict)
    domain_summary: Dict[str, Any] = Field(default_factory=dict)
    url_summary: Dict[str, Any] = Field(default_factory=dict)
    recipient_summary: Dict[str, Any] = Field(default_factory=dict)


class CampaignAlertResponse(BaseModel):
    """Proactive campaign detection alert when analyzing a new email."""
    is_campaign_detected: bool = Field(False, description="True if email correlates to a known campaign")
    campaign_id: Optional[str] = Field(None, description="Matched campaign ID (e.g. C-042)")
    campaign_name: Optional[str] = Field(None, description="Matched campaign name")
    correlated_message_count: int = Field(0, description="Number of previously analyzed messages in this campaign")
    overall_confidence: float = Field(0.0, description="Campaign confidence score (0-100)")
    message_alert: str = Field(
        "",
        description="Formatted alert statement, e.g. 'This email shares infrastructure or behavioral characteristics with 16 previously analyzed messages.'"
    )
    strongest_reasons: List[str] = Field(default_factory=list, description="Strongest correlation reasons")
    category_scores: CategorySimilarityScores = Field(default_factory=CategorySimilarityScores)
