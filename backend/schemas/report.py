from typing import Optional, Dict, Any, List, Literal
from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict


ReportType = Literal["ANALYST", "EXECUTIVE", "FORENSIC", "INCIDENT", "EVIDENCE"]
ReportStatus = Literal["DRAFT", "GENERATING", "READY", "STALE", "FAILED", "ARCHIVED", "SUPERSEDED"]
ReportClassification = Literal["INTERNAL", "CONFIDENTIAL", "RESTRICTED"]
RedactionLevel = Literal["NONE", "STANDARD", "STRICT"]
EpistemicStatus = Literal["OBSERVED", "INFERRED", "HYPOTHESIS", "EXTERNAL_INTELLIGENCE", "ANALYST_VERIFIED"]


class ReportContentOptions(BaseModel):
    include_executive_summary: bool = True
    include_timeline: bool = True
    include_attack_path: bool = True
    include_risk_assessment: bool = True
    include_findings: bool = True
    include_evidence_table: bool = True
    include_indicators: bool = True
    include_mitre_attack: bool = True
    include_infrastructure: bool = True
    include_explainability: bool = True
    include_response_actions: bool = True
    include_recommendations: bool = True
    include_audit_trail: bool = True
    include_evidence_index: bool = True


class FactClaim(BaseModel):
    id: str
    statement: str
    status: EpistemicStatus
    evidence_refs: List[str] = Field(default_factory=list)
    category: Optional[str] = None


class ReportQualityCheck(BaseModel):
    is_valid: bool = True
    checks_passed: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    unavailable_sections: List[str] = Field(default_factory=list)


class ReportGenerateRequest(BaseModel):
    """Legacy email report generation request."""
    analysis: Dict[str, Any] = Field(..., description="Full EmailAnalysisResponse payload or dictionary")
    case_id: Optional[str] = Field(None, description="Optional Case ID to associate with report")
    analyst_name: Optional[str] = Field("SOC Lead Analyst", description="Analyst name or investigator signature")
    classification_override: Optional[str] = Field(None, description="Optional analyst classification override")
    notes: Optional[str] = Field(None, description="Optional investigator notes or recommendations")


class InvestigationReportGenerateRequest(BaseModel):
    """Section 42: Authoritative investigation report generation request."""
    investigation_id: str = Field(..., description="Investigation ID, Incident Number, Run ID, or Artifact ID")
    report_type: ReportType = Field("ANALYST", description="Report format: ANALYST, EXECUTIVE, FORENSIC")
    classification: ReportClassification = Field("CONFIDENTIAL", description="Security classification label")
    redaction_level: RedactionLevel = Field("NONE", description="Redaction policy: NONE, STANDARD, STRICT")
    content_options: Optional[ReportContentOptions] = Field(default_factory=ReportContentOptions)
    analyst_name: Optional[str] = Field("SOC Lead Analyst", description="Analyst name or signature")
    notes: Optional[str] = Field(None, description="Investigator notes to include in dossier")


class InvestigationReportPreviewRequest(BaseModel):
    """Section 42: Request to project a report preview without persisting to database."""
    report_type: ReportType = Field("ANALYST", description="Report format: ANALYST, EXECUTIVE, FORENSIC")
    classification: ReportClassification = Field("CONFIDENTIAL", description="Security classification label")
    redaction_level: RedactionLevel = Field("NONE", description="Redaction policy: NONE, STANDARD, STRICT")
    content_options: Optional[ReportContentOptions] = Field(default_factory=ReportContentOptions)
    analyst_name: Optional[str] = Field("SOC Lead Analyst", description="Analyst name")
    notes: Optional[str] = Field(None, description="Investigator notes")


class ReportListItemResponse(BaseModel):
    id: str
    report_number: str
    title: str
    investigation_id: Optional[str] = None
    incident_number: Optional[str] = None
    case_id: Optional[str] = None
    evidence_id: Optional[str] = None
    email_sha256: Optional[str] = None
    threat_score: Optional[float] = 0.0
    severity: Optional[str] = "low"
    confidence: Optional[float] = 1.0
    report_type: Optional[str] = "ANALYST"
    status: Optional[str] = "READY"
    report_version: Optional[int] = 1
    classification: Optional[str] = "CONFIDENTIAL"
    redaction_level: Optional[str] = "NONE"
    is_stale: bool = False
    analyst_name: Optional[str] = "SOC Analyst"
    summary: Optional[str] = ""
    file_size_bytes: Optional[int] = 0
    created_at: datetime
    download_url: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class ReportListResponse(BaseModel):
    reports: List[ReportListItemResponse] = Field(default_factory=list)
    total: int = 0


class ReportDetailResponse(BaseModel):
    id: str
    report_number: str
    title: str
    investigation_id: Optional[str] = None
    incident_number: Optional[str] = None
    case_id: Optional[str] = None
    evidence_id: Optional[str] = None
    email_sha256: Optional[str] = None
    threat_score: float = 0.0
    severity: str = "low"
    confidence: float = 1.0
    report_type: str = "ANALYST"
    status: str = "READY"
    report_version: int = 1
    classification: str = "CONFIDENTIAL"
    redaction_level: str = "NONE"
    is_stale: bool = False
    analyst_name: str = "SOC Lead Analyst"
    summary: str = ""
    file_size_bytes: int = 0
    created_at: datetime
    download_url: str
    json_url: str
    content_options: Dict[str, Any] = Field(default_factory=dict)
    quality_check: Dict[str, Any] = Field(default_factory=dict)
    snapshot: Dict[str, Any] = Field(default_factory=dict)
    provenance: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(from_attributes=True)


class ReportVersionComparisonItem(BaseModel):
    field: str
    v1_value: Any
    v2_value: Any
    changed: bool


class ReportVersionComparisonResponse(BaseModel):
    investigation_id: str
    v1_report_number: str
    v2_report_number: str
    v1_version: int
    v2_version: int
    changes: List[ReportVersionComparisonItem] = Field(default_factory=list)
