"""
Section 69: Executive Reporting & Intelligence Dissemination Pydantic Schemas.
Defines versioned templates, immutable point-in-time snapshots, review/approval workflows,
redaction controls, and secure share links.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, ConfigDict


class ReportClassificationEnum(str, Enum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"
    TLP_CLEAR = "TLP_CLEAR"
    TLP_GREEN = "TLP_GREEN"
    TLP_AMBER = "TLP_AMBER"
    TLP_RED = "TLP_RED"


class ReportRedactionLevelEnum(str, Enum):
    NONE = "NONE"
    STANDARD = "STANDARD"
    STRICT = "STRICT"
    LEGAL_PRIVILEGED = "LEGAL_PRIVILEGED"


class ReportTypeEnum(str, Enum):
    EXECUTIVE_BRIEFING = "EXECUTIVE_BRIEFING"
    TECHNICAL_INCIDENT_DOSSIER = "TECHNICAL_INCIDENT_DOSSIER"
    FORENSIC_CHAIN_OF_CUSTODY = "FORENSIC_CHAIN_OF_CUSTODY"
    REGULATORY_COMPLIANCE_DISCLOSURE = "REGULATORY_COMPLIANCE_DISCLOSURE"
    THREAT_ACTOR_INTEL_DISSEMINATION = "THREAT_ACTOR_INTEL_DISSEMINATION"
    ANALYST = "ANALYST"


class ReportStatusEnum(str, Enum):
    DRAFT = "DRAFT"
    REVIEW_REQUESTED = "REVIEW_REQUESTED"
    APPROVED = "APPROVED"
    FINALIZED = "FINALIZED"
    SUPERSEDED = "SUPERSEDED"
    READY = "READY"


# ---------------------------------------------------------
# Template Schemas
# ---------------------------------------------------------

class ReportSectionConfig(BaseModel):
    section_id: str
    title: str
    description: Optional[str] = None
    enabled: bool = True
    order: int = 0
    required_epistemic_level: Optional[str] = None  # FACT, CORROBORATED, HYPOTHESIS
    parameters: Dict[str, Any] = Field(default_factory=dict)


class ReportTemplateCreateRequest(BaseModel):
    template_key: str = Field(..., min_length=3, max_length=64)
    template_name: str = Field(..., min_length=3, max_length=128)
    report_type: ReportTypeEnum
    description: Optional[str] = None
    sections_config: List[ReportSectionConfig] = Field(default_factory=list)
    default_classification: ReportClassificationEnum = ReportClassificationEnum.CONFIDENTIAL
    default_redaction: ReportRedactionLevelEnum = ReportRedactionLevelEnum.NONE


class ReportTemplateUpdateRequest(BaseModel):
    template_name: Optional[str] = None
    description: Optional[str] = None
    sections_config: Optional[List[ReportSectionConfig]] = None
    default_classification: Optional[ReportClassificationEnum] = None
    default_redaction: Optional[ReportRedactionLevelEnum] = None
    is_active: Optional[bool] = None


class ReportTemplateResponse(BaseModel):
    id: str
    workspace_id: str
    tenant_id: str
    template_key: str
    template_name: str
    report_type: str
    version: int
    description: Optional[str] = None
    sections_config: List[ReportSectionConfig]
    default_classification: str
    default_redaction: str
    is_system: bool
    is_active: bool
    created_by: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ReportTemplateListResponse(BaseModel):
    items: List[ReportTemplateResponse]
    total: int


# ---------------------------------------------------------
# Snapshot Schemas
# ---------------------------------------------------------

class ReportSnapshotResponse(BaseModel):
    id: str
    report_id: str
    workspace_id: str
    tenant_id: str
    snapshot_hash: str
    source_identifiers: Dict[str, Any]
    source_versions: Dict[str, Any]
    epistemic_labels: Dict[str, Any]
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ReportSnapshotDetailResponse(ReportSnapshotResponse):
    snapshot_payload: Dict[str, Any]


# ---------------------------------------------------------
# Share Link Schemas
# ---------------------------------------------------------

class ReportShareLinkCreateRequest(BaseModel):
    format: str = "PDF"  # PDF, HTML, JSON
    classification: ReportClassificationEnum = ReportClassificationEnum.CONFIDENTIAL
    redaction_level: ReportRedactionLevelEnum = ReportRedactionLevelEnum.STANDARD
    expires_in_hours: int = Field(default=72, ge=1, le=720)
    max_uses: int = Field(default=10, ge=1, le=1000)


class ReportShareLinkResponse(BaseModel):
    id: str
    report_id: str
    workspace_id: str
    tenant_id: str
    share_token: Optional[str] = None  # Returned ONLY on creation
    share_url: Optional[str] = None
    format: str
    classification: str
    redaction_level: str
    expires_at: datetime
    max_uses: int
    use_count: int
    is_revoked: bool
    revoked_at: Optional[datetime] = None
    revoked_by: Optional[str] = None
    created_by: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ReportShareLinkListResponse(BaseModel):
    items: List[ReportShareLinkResponse]
    total: int


class PublicReportShareResponse(BaseModel):
    report_number: str
    title: str
    report_type: str
    classification: str
    redaction_level: str
    generated_at: Optional[datetime] = None
    finalized_at: Optional[datetime] = None
    summary: Optional[str] = None
    threat_score: float
    severity: str
    confidence: float
    html_content: Optional[str] = None
    evidence_gaps: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    source_data_hash: Optional[str] = None
    download_available: bool = False


# ---------------------------------------------------------
# Review & Lifecycle Schemas
# ---------------------------------------------------------

class ReviewNote(BaseModel):
    author: str
    timestamp: datetime
    content: str
    status: str = "COMMENT"  # COMMENT, CHANGE_REQUESTED, APPROVED


class ReportReviewRequest(BaseModel):
    reviewers: List[str] = Field(default_factory=list)
    note: Optional[str] = None


class ReportAddReviewNoteRequest(BaseModel):
    note: str = Field(..., min_length=2)
    status: str = "COMMENT"


class ReportApprovalRequest(BaseModel):
    approval_notes: Optional[str] = None


class ReportFinalizeRequest(BaseModel):
    finalization_notes: Optional[str] = None


# ---------------------------------------------------------
# Executive Report CRUD Schemas
# ---------------------------------------------------------

class ExecutiveReportCreateRequest(BaseModel):
    title: str = Field(..., min_length=3, max_length=255)
    report_type: ReportTypeEnum = ReportTypeEnum.EXECUTIVE_BRIEFING
    template_key: Optional[str] = None
    incident_id: Optional[str] = None
    case_id: Optional[str] = None
    investigation_id: Optional[str] = None
    evidence_id: Optional[str] = None
    classification: ReportClassificationEnum = ReportClassificationEnum.CONFIDENTIAL
    redaction_level: ReportRedactionLevelEnum = ReportRedactionLevelEnum.NONE
    summary: Optional[str] = None
    content_options: Dict[str, Any] = Field(default_factory=dict)


class ExecutiveReportUpdateRequest(BaseModel):
    title: Optional[str] = None
    summary: Optional[str] = None
    classification: Optional[ReportClassificationEnum] = None
    redaction_level: Optional[ReportRedactionLevelEnum] = None
    recommendations: Optional[List[str]] = None
    evidence_gaps: Optional[List[str]] = None
    content_options: Optional[Dict[str, Any]] = None


class ExecutiveReportDetailResponse(BaseModel):
    id: str
    report_number: str
    title: str
    report_type: str
    status: str
    report_version: int
    classification: str
    redaction_level: str
    threat_score: float
    severity: str
    confidence: float
    summary: Optional[str] = None
    analyst_name: Optional[str] = None
    incident_id: Optional[str] = None
    case_id: Optional[str] = None
    investigation_id: Optional[str] = None
    evidence_id: Optional[str] = None
    template_id: Optional[str] = None
    template_version: int
    source_snapshot_id: Optional[str] = None
    source_data_hash: Optional[str] = None
    created_by: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    generated_at: Optional[datetime] = None
    finalized_at: Optional[datetime] = None
    finalized_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    approved_by: Optional[str] = None
    is_immutable: bool
    review_notes: List[ReviewNote] = Field(default_factory=list)
    reviewers: List[str] = Field(default_factory=list)
    evidence_gaps: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    file_path: Optional[str] = None
    file_size_bytes: int = 0
    html_content: Optional[str] = None
    workspace_id: str
    tenant_id: str

    model_config = ConfigDict(from_attributes=True)


class ExecutiveReportListItemResponse(BaseModel):
    id: str
    report_number: str
    title: str
    report_type: str
    status: str
    report_version: int
    classification: str
    redaction_level: str
    threat_score: float
    severity: str
    confidence: float
    incident_id: Optional[str] = None
    case_id: Optional[str] = None
    investigation_id: Optional[str] = None
    is_immutable: bool
    created_by: Optional[str] = None
    created_at: datetime
    finalized_at: Optional[datetime] = None
    share_links_count: int = 0


class ExecutiveReportListResponse(BaseModel):
    items: List[ExecutiveReportListItemResponse]
    total: int


class ExecutiveReportMetricsResponse(BaseModel):
    total_reports: int
    draft_reports: int
    in_review_reports: int
    approved_reports: int
    finalized_reports: int
    active_share_links: int
    by_classification: Dict[str, int]
    by_type: Dict[str, int]
    by_severity: Dict[str, int]
