"""
Section 68: Evidence & Forensics Workspace Pydantic Schemas.
Provides strict contracts for authoritative evidence records, cryptographic integrity
verification, immutable chain-of-custody ledgers, provenance lineage, safe previews,
and forensic export manifests.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class EvidenceSourceTypeEnum(str, Enum):
    EMAIL = "EMAIL"
    FILE = "FILE"
    ATTACHMENT = "ATTACHMENT"
    URL = "URL"
    ENDPOINT = "ENDPOINT"
    NETWORK = "NETWORK"
    MANUAL_UPLOAD = "MANUAL_UPLOAD"
    THREAT_INTEL = "THREAT_INTEL"


class EvidenceCollectionMethodEnum(str, Enum):
    INGESTION_GATEWAY = "INGESTION_GATEWAY"
    MANUAL_UPLOAD = "MANUAL_UPLOAD"
    ENDPOINT_AGENT = "ENDPOINT_AGENT"
    API = "API"
    CONNECTOR = "CONNECTOR"


class EvidenceIntegrityStatusEnum(str, Enum):
    UNKNOWN = "UNKNOWN"
    PENDING = "PENDING"
    VERIFIED = "VERIFIED"
    MISMATCH = "MISMATCH"
    UNAVAILABLE = "UNAVAILABLE"


class EvidenceClassificationEnum(str, Enum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"
    SENSITIVE = "SENSITIVE"


class EvidenceLifecycleStatusEnum(str, Enum):
    REGISTERED = "REGISTERED"
    VALIDATING = "VALIDATING"
    VALID = "VALID"
    INVALID = "INVALID"
    QUARANTINED = "QUARANTINED"
    PRESERVED = "PRESERVED"
    RELEASED = "RELEASED"
    RETIRED = "RETIRED"


class EvidenceRetentionPolicyEnum(str, Enum):
    INDEFINITE = "INDEFINITE"
    RETENTION_30_DAYS = "30_DAYS"
    RETENTION_90_DAYS = "90_DAYS"
    RETENTION_1_YEAR = "1_YEAR"
    LEGAL_HOLD = "LEGAL_HOLD"


class EvidencePreservationStatusEnum(str, Enum):
    NORMAL = "NORMAL"
    PRESERVED = "PRESERVED"
    ON_HOLD = "ON_HOLD"


class CustodyEventTypeEnum(str, Enum):
    ACQUIRED = "ACQUIRED"
    REGISTERED = "REGISTERED"
    TRANSFERRED = "TRANSFERRED"
    ACCESSED = "ACCESSED"
    COPIED = "COPIED"
    ANALYZED = "ANALYZED"
    EXPORTED = "EXPORTED"
    PRESERVED = "PRESERVED"
    RELEASED = "RELEASED"


# ---------------------------------------------------------------------------
# Request Models
# ---------------------------------------------------------------------------

class EvidenceRegistrationRequest(BaseModel):
    original_filename: str = Field(..., min_length=1, max_length=255)
    source_type: EvidenceSourceTypeEnum = EvidenceSourceTypeEnum.FILE
    collection_method: EvidenceCollectionMethodEnum = EvidenceCollectionMethodEnum.MANUAL_UPLOAD
    source_reference: Optional[str] = None
    collector: Optional[str] = "SOC Analyst"
    classification: EvidenceClassificationEnum = EvidenceClassificationEnum.INTERNAL
    case_id: Optional[str] = None
    investigation_id: Optional[str] = None
    retention_policy: EvidenceRetentionPolicyEnum = EvidenceRetentionPolicyEnum.INDEFINITE
    notes: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class EvidencePreservationRequest(BaseModel):
    preservation_status: EvidencePreservationStatusEnum
    reason: str = Field(..., min_length=3, max_length=1000)
    notes: Optional[str] = None


class EvidenceCustodyAddRequest(BaseModel):
    event_type: CustodyEventTypeEnum
    source: Optional[str] = None
    destination: Optional[str] = None
    reason: Optional[str] = None
    notes: Optional[str] = None


class EvidenceLinkRequest(BaseModel):
    case_id: Optional[str] = None
    investigation_id: Optional[str] = None
    reason: Optional[str] = None


class EvidenceNoteAddRequest(BaseModel):
    note_text: str = Field(..., min_length=1, max_length=5000)
    category: Optional[str] = "ANALYSIS"  # ANALYSIS, INTEGRITY, HANDLING, LEGAL


class EvidenceDerivationRequest(BaseModel):
    transformation_tool: str = Field(..., min_length=1, max_length=100)
    tool_version: Optional[str] = "1.0"
    transformation_description: str = Field(..., min_length=1, max_length=500)
    child_filename: str = Field(..., min_length=1, max_length=255)
    child_bytes_base64: Optional[str] = None
    child_source_type: EvidenceSourceTypeEnum = EvidenceSourceTypeEnum.FILE


# ---------------------------------------------------------------------------
# Response Models
# ---------------------------------------------------------------------------

class EvidenceCustodyEventResponse(BaseModel):
    id: str
    evidence_id: str
    event_type: str
    actor_id: str
    timestamp: datetime
    source: Optional[str] = None
    destination: Optional[str] = None
    reason: Optional[str] = None
    integrity_hash: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(from_attributes=True)


class EvidenceListItemResponse(BaseModel):
    id: str
    evidence_id: str
    sha256: str
    sha1: Optional[str] = None
    md5: Optional[str] = None
    original_filename: str
    mime_type: Optional[str] = None
    size: int
    source_type: str
    collection_method: str
    collector: str
    collected_at: datetime
    classification: str
    lifecycle_status: str
    integrity_status: str
    preservation_status: str
    case_id: Optional[str] = None
    investigation_id: Optional[str] = None
    parent_evidence_id: Optional[str] = None
    indicator_count: int = 0
    finding_count: int = 0

    model_config = ConfigDict(from_attributes=True)


class EvidenceMetricsResponse(BaseModel):
    total_evidence: int = 0
    verified_count: int = 0
    mismatch_count: int = 0
    pending_count: int = 0
    preserved_count: int = 0
    source_distribution: Dict[str, int] = Field(default_factory=dict)
    classification_distribution: Dict[str, int] = Field(default_factory=dict)


class EvidenceListResponse(BaseModel):
    items: List[EvidenceListItemResponse] = Field(default_factory=list)
    total: int = 0
    page: int = 1
    page_size: int = 50
    metrics: EvidenceMetricsResponse = Field(default_factory=EvidenceMetricsResponse)


class EvidenceIntegrityVerificationResponse(BaseModel):
    evidence_id: str
    sha256_expected: str
    sha256_computed: str
    status: str
    verified_at: datetime
    verified_by: str
    algorithms_tested: List[str] = Field(default_factory=lambda: ["SHA-256"])
    match: bool
    message: str


class EvidencePreviewResponse(BaseModel):
    evidence_id: str
    filename: str
    mime_type: Optional[str] = None
    size: int
    preview_type: str  # text, hex, json, unavailable
    preview_content: str
    truncated: bool = False
    byte_offset: int = 0
    total_preview_bytes: int = 0


class EvidenceExportManifestResponse(BaseModel):
    manifest_id: str
    evidence_id: str
    filename: str
    sha256: str
    sha1: Optional[str] = None
    md5: Optional[str] = None
    file_size: int
    exported_by: str
    exported_at: datetime
    tenant_id: str
    package_hash_sha256: str
    custody_events_count: int
    preservation_status: str
    verification_summary: str
    manifest_json: Dict[str, Any] = Field(default_factory=dict)


class EvidenceProvenanceLineageItem(BaseModel):
    evidence_id: str
    filename: str
    sha256: str
    relation: str  # SELF, PARENT, CHILD
    transformation: Optional[str] = None
    tool: Optional[str] = None
    timestamp: Optional[datetime] = None


class EvidenceDetailResponse(BaseModel):
    id: str
    evidence_id: str
    tenant_id: str
    artifact_id: Optional[str] = None
    case_id: Optional[str] = None
    investigation_id: Optional[str] = None

    # Hashes & Integrity
    sha256: str
    sha1: Optional[str] = None
    md5: Optional[str] = None
    hash_algorithm: str = "SHA-256"
    integrity_status: str
    last_verified_at: Optional[datetime] = None
    last_verified_by: Optional[str] = None

    # Artifact info
    original_filename: str
    mime_type: Optional[str] = None
    size: int
    storage_reference: Optional[str] = None

    # Provenance
    source_type: str
    source_reference: Optional[str] = None
    collection_method: str
    collector: str
    collected_at: datetime
    received_at: datetime
    observed_at: Optional[datetime] = None

    # Classification & Lifecycle
    classification: str
    lifecycle_status: str
    retention_policy: str
    preservation_status: str
    preservation_reason: Optional[str] = None
    preservation_actor: Optional[str] = None
    preservation_timestamp: Optional[datetime] = None

    # Parent/Child Lineage
    parent_evidence_id: Optional[str] = None
    derivation_metadata: Dict[str, Any] = Field(default_factory=dict)
    provenance_lineage: List[EvidenceProvenanceLineageItem] = Field(default_factory=list)

    # Chain of Custody
    custody_events: List[EvidenceCustodyEventResponse] = Field(default_factory=list)

    # Linked Context
    indicators: List[Dict[str, Any]] = Field(default_factory=list)
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    relationships: List[Dict[str, Any]] = Field(default_factory=list)
    timeline_events: List[Dict[str, Any]] = Field(default_factory=list)
    analysis_runs: List[Dict[str, Any]] = Field(default_factory=list)
    forensic_notes: List[Dict[str, Any]] = Field(default_factory=list)
    evidence_gaps: List[Dict[str, Any]] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(from_attributes=True)
