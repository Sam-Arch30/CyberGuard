from typing import List, Optional, Union, Dict
from pydantic import BaseModel, Field
from backend.schemas.ip_intelligence import IPIntelligence
from backend.schemas.domain_intelligence import DomainIntelligence
from backend.schemas.lookalike import LookalikeDetectionResult
from backend.schemas.url_analysis import URLAnalysisResult
from backend.schemas.threat_score import ThreatScoreResult
from backend.schemas.ai_analyst import AIAnalystAssessment
from backend.schemas.graph import InvestigationGraphResponse
from backend.schemas.attribution import AttributionResult
from backend.schemas.evidence_confidence import ForensicConclusion


class ProtocolResult(BaseModel):
    result: str = Field("unknown", description="Result: pass, fail, softfail, neutral, none, temperror, permerror, unknown")
    details: Optional[str] = Field(None, description="Detailed header snippet or explanation")


class SenderAlignment(BaseModel):
    from_domain: Optional[str] = Field(None, description="Domain extracted from From header")
    reply_to_domain: Optional[str] = Field(None, description="Domain extracted from Reply-To header")
    return_path_domain: Optional[str] = Field(None, description="Domain extracted from Return-Path header")
    reply_to_mismatch: bool = Field(False, description="True if Reply-To domain differs from From domain")
    return_path_mismatch: bool = Field(False, description="True if Return-Path domain differs from From domain")


class AuthenticationAnalysis(BaseModel):
    verification_type: str = Field("observed_header", description="Verification type: 'observed_header' or 'independent_validation'")
    verification_notice: str = Field("Observed authentication result from supplied headers (unverified by local server)", description="Security notice regarding header authenticity")
    observed_header: Optional[str] = Field(None, description="Raw Authentication-Results or Received-SPF header content")
    spf: ProtocolResult = Field(default_factory=ProtocolResult)
    dkim: ProtocolResult = Field(default_factory=ProtocolResult)
    dmarc: ProtocolResult = Field(default_factory=ProtocolResult)
    alignment: SenderAlignment = Field(default_factory=SenderAlignment)


class IPIndicator(BaseModel):
    value: str = Field(..., description="IP address string")
    version: int = Field(4, description="IP version (4 or 6)")
    scope: str = Field("public", description="Scope: public, private, loopback, link_local, reserved, unknown")
    source: Optional[str] = Field("unknown", description="Extraction source location")


class DomainIndicator(BaseModel):
    value: str = Field(..., description="Normalized domain name")
    source: Optional[str] = Field("unknown", description="Extraction source location")


class URLIndicator(BaseModel):
    value: str = Field(..., description="Extracted URL string")
    source: Optional[str] = Field("unknown", description="Extraction source location")


class EmailAddressIndicator(BaseModel):
    value: str = Field(..., description="Normalized email address")
    source: Optional[str] = Field("unknown", description="Extraction source location")


from backend.schemas.attachment_analysis import AttachmentStaticAnalysisResult


class AttachmentIndicator(BaseModel):
    filename: Optional[str] = Field(None, description="Filename of the attachment")
    mime_type: Optional[str] = Field(None, description="MIME content type of the attachment")
    size: Optional[int] = Field(0, description="Attachment file size in bytes")
    sha256: str = Field(..., description="SHA-256 hash of attachment payload")
    md5: Optional[str] = Field(None, description="MD5 hash of attachment payload")
    sha1: Optional[str] = Field(None, description="SHA-1 hash of attachment payload")
    static_analysis: Optional[AttachmentStaticAnalysisResult] = Field(None, description="Detailed static malware and intelligence analysis")


class IndicatorsGroup(BaseModel):
    ips: List[IPIndicator] = Field(default_factory=list)
    domains: List[DomainIndicator] = Field(default_factory=list)
    urls: List[URLIndicator] = Field(default_factory=list)
    email_addresses: List[EmailAddressIndicator] = Field(default_factory=list)
    attachments: List[AttachmentIndicator] = Field(default_factory=list)


class AttachmentInfo(BaseModel):
    filename: Optional[str] = Field(None, description="Filename of the attachment")
    mime_type: Optional[str] = Field(None, description="MIME content type of the attachment")
    size: Optional[int] = Field(0, description="Attachment file size in bytes")
    sha256: Optional[str] = Field(None, description="SHA-256 hash of attachment payload")
    md5: Optional[str] = Field(None, description="MD5 hash of attachment payload")
    sha1: Optional[str] = Field(None, description="SHA-1 hash of attachment payload")
    static_analysis: Optional[AttachmentStaticAnalysisResult] = Field(None, description="Detailed static malware and intelligence analysis")


class BodyInfo(BaseModel):
    plain_text: Optional[str] = Field(None, description="Extracted plain-text body")
    html: Optional[str] = Field(None, description="Extracted HTML body")


class HeaderInfo(BaseModel):
    from_header: Optional[str] = Field(None, alias="from", description="From header")
    to: Optional[Union[str, List[str]]] = Field(None, description="To header")
    cc: Optional[Union[str, List[str]]] = Field(None, description="Cc header")
    subject: Optional[str] = Field(None, description="Subject header")
    date: Optional[str] = Field(None, description="Date header")
    reply_to: Optional[str] = Field(None, description="Reply-To header")
    return_path: Optional[str] = Field(None, description="Return-Path header")
    message_id: Optional[str] = Field(None, description="Message-ID header")
    received: List[str] = Field(default_factory=list, description="List of Received header lines")
    authentication_results: Optional[str] = Field(None, description="Authentication-Results header")

    model_config = {
        "populate_by_name": True
    }


class FileMeta(BaseModel):
    filename: str = Field(..., description="Name of the uploaded .eml file")
    size_bytes: int = Field(..., description="Size of the uploaded file in bytes")


class RelayHop(BaseModel):
    hop_number: int = Field(..., description="Hop number")
    from_host: Optional[str] = Field(None, description="Sender hostname extracted from 'from'")
    from_ip: Optional[str] = Field(None, description="Sender IP address extracted from 'from'")
    by_host: Optional[str] = Field(None, description="Receiving mail server hostname extracted from 'by'")
    by_ip: Optional[str] = Field(None, description="Receiving mail server IP address extracted from 'by'")
    protocol: Optional[str] = Field(None, description="Transfer protocol e.g. ESMTP, ESMTPS, HTTP, etc.")
    id: Optional[str] = Field(None, description="Message identifier assigned by hop server")
    recipient: Optional[str] = Field(None, description="Intended recipient for this hop ('for')")
    timestamp: Optional[str] = Field(None, description="Timestamp string from Received header")
    parser_confidence: str = Field("high", description="Parser confidence: high, medium, or low")
    raw: str = Field(..., description="Original unparsed Received header text")


class EarliestObservableNode(BaseModel):
    earliest_observable_ip: Optional[str] = Field(None, description="Earliest usable public IP address in transmission path")
    from_host: Optional[str] = Field(None, description="Associated sender host name if present")
    confidence: str = Field("medium", description="Confidence level: high, medium, low, or none")
    reason: str = Field("Earliest public IP found in Received chain", description="Explanatory text for identified IP")


class RelayPathAnalysis(BaseModel):
    header_order_hops: List[RelayHop] = Field(default_factory=list, description="Hops in original header order (top = recipient MX)")
    transmission_order_hops: List[RelayHop] = Field(default_factory=list, description="Hops in derived chronological order (1 = sender origin)")
    earliest_observable_node: EarliestObservableNode = Field(default_factory=EarliestObservableNode)
    trust_notice: str = Field(
        "Headers nearest the recipient's mail infrastructure provide stronger evidence than upstream headers, which may be forged by prior nodes.",
        description="Forensic explanation of Received header trust hierarchy"
    )


class MLAssessmentResult(BaseModel):
    classification: str = Field(..., description="Binary classification: phishing or legitimate")
    probability: Optional[float] = Field(None, description="NLP-based phishing probability between 0.0 and 1.0")
    confidence: str = Field("medium", description="Confidence level: high, medium, low, or none")
    available: bool = Field(True, description="Whether the ML inference service was available")
    top_features: List[str] = Field(default_factory=list, description="Top indicative linguistic features detected")
    model_name: str = Field("TF-IDF + Logistic Regression", description="Model architecture identifier")
    notice: Optional[str] = Field(None, description="Informational notice regarding model execution or edge cases")


class MLClassifyRequest(BaseModel):
    subject: Optional[str] = Field("", description="Email subject line")
    body: Optional[str] = Field("", description="Email body content (plain text or extracted)")


class EmailAnalysisResponse(BaseModel):
    id: Optional[str] = Field(None, description="Identifier for the analysis session or evidence record")
    evidence_id: Optional[str] = Field(None, description="Unique chain-of-custody evidence identifier (e.g. EVD-A1B2C3D4)")
    email_sha256: Optional[str] = Field(None, description="SHA-256 hash of raw uploaded email bytes")
    original_filename: Optional[str] = Field(None, description="Original filename of uploaded .eml file")
    upload_timestamp: Optional[str] = Field(None, description="ISO timestamp when email was ingested")
    size: Optional[int] = Field(None, description="Uploaded file size in bytes")
    uploader: Optional[str] = Field("SOC Analyst", description="Uploader or analyst identity")
    authentication: Optional[AuthenticationAnalysis] = Field(None, description="Structured authentication analysis and sender alignment")
    relay_analysis: Optional[RelayPathAnalysis] = Field(None, description="Parsed Received header chain and relay transmission path")
    ip_intelligence: Dict[str, IPIntelligence] = Field(default_factory=dict, description="Contextual IP intelligence and infrastructure metadata dictionary keyed by IP")
    domain_intelligence: Dict[str, DomainIntelligence] = Field(default_factory=dict, description="Contextual domain intelligence and DNS/RDAP registration metadata keyed by domain")
    lookalike_domains: List[LookalikeDetectionResult] = Field(default_factory=list, description="Suspicious lookalike domains and potential brand impersonation findings")
    url_analysis: List[URLAnalysisResult] = Field(default_factory=list, description="Static non-invasive URL feature and suspicion analysis")
    threat_score: Optional[ThreatScoreResult] = Field(None, description="Explainable deterministic global threat score")
    ml_phishing_probability: Optional[float] = Field(None, description="NLP-based phishing probability (0.0 to 1.0)")
    ml_assessment: Optional[MLAssessmentResult] = Field(None, description="Detailed ML NLP text classification assessment")
    ai_analyst: Optional[AIAnalystAssessment] = Field(None, description="Structured AI Analyst assessment based on forensic findings")
    investigation_graph: Optional[InvestigationGraphResponse] = Field(None, description="Forensic investigation relationship graph")
    attribution: Optional[AttributionResult] = Field(None, description="Probabilistic infrastructure and campaign attribution assessment")
    forensic_conclusions: List[ForensicConclusion] = Field(default_factory=list, description="Structured forensic conclusions from the Evidence Confidence Engine")
    indicators: IndicatorsGroup = Field(default_factory=IndicatorsGroup, description="Structured indicators group")

    # Top-level flat fields for direct accessibility / backwards compatibility
    subject: Optional[str] = Field(None, description="Email subject")
    from_header: Optional[str] = Field(None, alias="from", description="From header")
    to: Optional[Union[str, List[str]]] = Field(None, description="To header")
    cc: Optional[Union[str, List[str]]] = Field(None, description="Cc header")
    date: Optional[str] = Field(None, description="Date header")
    reply_to: Optional[str] = Field(None, description="Reply-To header")
    return_path: Optional[str] = Field(None, description="Return-Path header")
    message_id: Optional[str] = Field(None, description="Message-ID header")
    received: List[str] = Field(default_factory=list, description="List of Received headers in original order")
    authentication_results: Optional[str] = Field(None, description="Authentication-Results header string")

    plain_text_body: Optional[str] = Field(None, description="Plain text body content")
    html_body: Optional[str] = Field(None, description="HTML body content")
    raw_email: Optional[str] = Field(None, description="Full raw email source string")

    urls: List[str] = Field(default_factory=list, description="Extracted URLs")
    ips: List[str] = Field(default_factory=list, description="Extracted IP addresses")
    domains: List[str] = Field(default_factory=list, description="Extracted domain names")
    emails: List[str] = Field(default_factory=list, description="Extracted email addresses")
    attachments: List[AttachmentInfo] = Field(default_factory=list, description="Extracted attachments metadata")

    # Structured nested objects for backwards compatibility
    file_info: Optional[FileMeta] = None
    headers: Optional[HeaderInfo] = None
    body: Optional[BodyInfo] = None

    model_config = {
        "populate_by_name": True
    }


class ErrorResponse(BaseModel):
    detail: str = Field(..., description="Error message description")
    error_code: str = Field("MALFORMED_EMAIL", description="Error type code")
