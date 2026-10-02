"""
Unified CyberGuard Cybersecurity Data Model Schemas and Enums.
Provides standardized, extensible schemas for all CyberGuard analyzers and persistence.
"""
from __future__ import annotations

import re
import ipaddress
import urllib.parse
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field, field_validator, model_validator, ConfigDict


# ============================================================================
# CANONICAL ENUMS
# ============================================================================

class SeverityEnum(str, Enum):
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ArtifactTypeEnum(str, Enum):
    EMAIL = "EMAIL"
    FILE = "FILE"
    ATTACHMENT = "ATTACHMENT"
    URL = "URL"
    DOMAIN = "DOMAIN"
    IP = "IP"
    IMAGE = "IMAGE"
    AUDIO = "AUDIO"
    VIDEO = "VIDEO"
    QR_CODE = "QR_CODE"
    AUTH_LOG = "AUTH_LOG"
    SYSTEM_LOG = "SYSTEM_LOG"
    NETWORK_LOG = "NETWORK_LOG"
    API_LOG = "API_LOG"
    ENDPOINT_EVENT = "ENDPOINT_EVENT"
    TEXT = "TEXT"
    OTHER = "OTHER"


class AnalysisStatusEnum(str, Enum):
    INGESTED = "INGESTED"
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    ANALYZING = "ANALYZING"
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    UNSUPPORTED = "UNSUPPORTED"
    CANCELLED = "CANCELLED"


class InputModeEnum(str, Enum):
    FILE_UPLOAD = "FILE_UPLOAD"
    TEXT_INPUT = "TEXT_INPUT"
    STRUCTURED_EVENT = "STRUCTURED_EVENT"
    ENDPOINT_TELEMETRY = "ENDPOINT_TELEMETRY"
    CONNECTOR_INPUT = "CONNECTOR_INPUT"
    BATCH_IMPORT = "BATCH_IMPORT"


class SupportStatusEnum(str, Enum):
    SUPPORTED = "SUPPORTED"
    PARTIALLY_SUPPORTED = "PARTIALLY_SUPPORTED"
    UNSUPPORTED_FOR_ANALYSIS = "UNSUPPORTED_FOR_ANALYSIS"


class CapabilityStatusEnum(str, Enum):
    AVAILABLE = "AVAILABLE"
    DISABLED = "DISABLED"
    NOT_CONFIGURED = "NOT_CONFIGURED"
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"


class AnalysisTriggerEnum(str, Enum):
    USER = "USER"
    AUTOMATIC = "AUTOMATIC"
    REANALYSIS = "REANALYSIS"
    CORRELATION = "CORRELATION"
    SYSTEM = "SYSTEM"


class FindingMethodEnum(str, Enum):
    DETERMINISTIC = "DETERMINISTIC"
    RULE = "RULE"
    HEURISTIC = "HEURISTIC"
    ML = "ML"
    LLM = "LLM"
    EXTERNAL_INTELLIGENCE = "EXTERNAL_INTELLIGENCE"
    STATISTICAL = "STATISTICAL"
    GRAPH = "GRAPH"
    MANUAL = "MANUAL"
    HYBRID = "HYBRID"


class IndicatorTypeEnum(str, Enum):
    IP = "IP"
    DOMAIN = "DOMAIN"
    URL = "URL"
    EMAIL_ADDRESS = "EMAIL_ADDRESS"
    FILE_HASH = "FILE_HASH"
    PHONE = "PHONE"
    USERNAME = "USERNAME"
    DEVICE_ID = "DEVICE_ID"
    CERTIFICATE = "CERTIFICATE"
    USER_AGENT = "USER_AGENT"
    PROCESS = "PROCESS"
    REGISTRY_KEY = "REGISTRY_KEY"
    FILENAME = "FILENAME"
    OTHER = "OTHER"


class EntityTypeEnum(str, Enum):
    USER = "USER"
    ACCOUNT = "ACCOUNT"
    DEVICE = "DEVICE"
    HOST = "HOST"
    ORGANIZATION = "ORGANIZATION"
    BRAND = "BRAND"
    SERVICE = "SERVICE"
    PROCESS = "PROCESS"
    SESSION = "SESSION"
    APPLICATION = "APPLICATION"
    CAMPAIGN = "CAMPAIGN"
    MALWARE_FAMILY = "MALWARE_FAMILY"
    THREAT_ACTOR = "THREAT_ACTOR"
    INFRASTRUCTURE = "INFRASTRUCTURE"
    OTHER = "OTHER"


class RelationshipTypeEnum(str, Enum):
    CONTAINS = "CONTAINS"
    REFERENCES = "REFERENCES"
    RESOLVES_TO = "RESOLVES_TO"
    REDIRECTS_TO = "REDIRECTS_TO"
    CONNECTS_TO = "CONNECTS_TO"
    COMMUNICATES_WITH = "COMMUNICATES_WITH"
    AUTHENTICATED_FROM = "AUTHENTICATED_FROM"
    SPAWNED = "SPAWNED"
    DOWNLOADED = "DOWNLOADED"
    ACCESSED = "ACCESSED"
    OBSERVED_ON = "OBSERVED_ON"
    ASSOCIATED_WITH = "ASSOCIATED_WITH"
    SIMILAR_TO = "SIMILAR_TO"
    RELATED_TO = "RELATED_TO"
    PART_OF = "PART_OF"
    TARGETED = "TARGETED"
    ATTRIBUTED_TO = "ATTRIBUTED_TO"
    HAS_HOST = "HAS_HOST"
    SUBMITS_TO = "SUBMITS_TO"
    USES_NAMESERVER = "USES_NAMESERVER"
    MAIL_EXCHANGER = "MAIL_EXCHANGER"
    HAS_HASH = "HAS_HASH"
    OTHER = "OTHER"


class IncidentStatusEnum(str, Enum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class ResponseStatusEnum(str, Enum):
    RECOMMENDED = "RECOMMENDED"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    EXECUTING = "EXECUTING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    REJECTED = "REJECTED"


class ModelStatusEnum(str, Enum):
    CANDIDATE = "CANDIDATE"
    VALIDATING = "VALIDATING"
    ACTIVE = "ACTIVE"
    RETIRED = "RETIRED"
    REJECTED = "REJECTED"


# ============================================================================
# NORMALIZATION UTILITIES
# ============================================================================

def normalize_severity(val: Optional[Union[str, SeverityEnum]]) -> SeverityEnum:
    """Normalizes any legacy or variant severity string to canonical SeverityEnum."""
    if not val:
        return SeverityEnum.LOW
    if isinstance(val, SeverityEnum):
        return val
    clean = str(val).strip().upper()
    mapping = {
        "SAFE": SeverityEnum.SAFE,
        "LEGITIMATE": SeverityEnum.SAFE,
        "CLEAN": SeverityEnum.SAFE,
        "NONE": SeverityEnum.SAFE,
        "LOW": SeverityEnum.LOW,
        "MEDIUM": SeverityEnum.MEDIUM,
        "MODERATE": SeverityEnum.MEDIUM,
        "HIGH": SeverityEnum.HIGH,
        "CRITICAL": SeverityEnum.CRITICAL,
    }
    return mapping.get(clean, SeverityEnum.LOW)


def normalize_confidence(val: Optional[Union[float, int, str]]) -> float:
    """
    Standardizes confidence to 0.0 - 1.0.
    Handles legacy integer percentages (e.g. 85 -> 0.85), strings ("85%"), or discrete labels ("HIGH").
    Clamps floats above 1.0 to 1.0.
    """
    if val is None:
        return 1.0
    if isinstance(val, int):
        if val > 1 and val <= 100:
            return round(val / 100.0, 4)
        if val > 100:
            return 1.0
        return max(0.0, min(1.0, float(val)))
    if isinstance(val, float):
        return max(0.0, min(1.0, round(val, 4)))

    clean = str(val).strip().upper()
    if clean.endswith("%"):
        try:
            return max(0.0, min(1.0, round(float(clean[:-1].strip()) / 100.0, 4)))
        except ValueError:
            pass
    try:
        fval = float(clean)
        if fval > 1.0 and fval <= 100.0 and "." not in clean:
            return round(fval / 100.0, 4)
        return max(0.0, min(1.0, round(fval, 4)))
    except ValueError:
        pass

    label_map = {
        "CONFIRMED": 1.0,
        "VERY_HIGH": 0.95,
        "HIGH": 0.85,
        "PROBABLE": 0.80,
        "MEDIUM": 0.50,
        "POSSIBLE": 0.50,
        "LOW": 0.25,
        "UNLIKELY": 0.10,
        "UNKNOWN": 0.50,
    }
    return label_map.get(clean, 0.5)


def normalize_risk_score(val: Optional[Union[float, int]]) -> Optional[float]:
    """Validates and bounds risk score to 0.0 - 100.0."""
    if val is None:
        return None
    try:
        fval = float(val)
        return max(0.0, min(100.0, round(fval, 2)))
    except (TypeError, ValueError):
        return None


def normalize_domain(domain: str) -> str:
    """Canonical domain normalization: lowercase, strip protocol/trailing dots/spaces."""
    d = domain.strip().lower()
    if "://" in d:
        parsed = urllib.parse.urlparse(d)
        d = parsed.netloc or parsed.path
    if ":" in d:
        d = d.split(":")[0]
    return d.rstrip(".").strip()


def normalize_ip(ip_str: str) -> str:
    """Canonical IP normalization for IPv4/IPv6 using standard library."""
    clean = ip_str.strip().lower().replace("[.]", ".").replace("(.)", ".")
    if clean.startswith("ipv6:"):
        clean = clean[5:].strip()
    try:
        return str(ipaddress.ip_address(clean))
    except ValueError:
        # Handle leading zeros in IPv4 octets (e.g. 192.002.001.001 -> 192.2.1.1)
        if "." in clean and ":" not in clean:
            parts = clean.split(".")
            if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                try:
                    clean_octets = ".".join(str(int(p)) for p in parts)
                    return str(ipaddress.ip_address(clean_octets))
                except ValueError:
                    pass
        return clean


def normalize_url(url: str) -> str:
    """Canonical URL normalization: lowercase scheme and host, preserve path & query."""
    clean = url.strip()
    try:
        parsed = urllib.parse.urlsplit(clean)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        path = parsed.path
        if not path and (parsed.query or parsed.fragment):
            path = "/"
        normalized = urllib.parse.urlunsplit((scheme, netloc, path, parsed.query, parsed.fragment))
        return normalized
    except Exception:
        return clean


def normalize_email_address(email: str) -> str:
    """Canonical email normalization: lowercases domain while preserving case-sensitivities safely."""
    clean = email.strip()
    if "@" in clean:
        local, domain = clean.rsplit("@", 1)
        return f"{local.strip()}@{normalize_domain(domain)}"
    return clean.lower()


def normalize_hash(h: str) -> str:
    """Canonical cryptographic hash normalization: lowercase hex string."""
    return h.strip().lower()


def normalize_indicator(indicator_type: Union[IndicatorTypeEnum, str], value: str) -> tuple[str, str]:
    """
    Returns (raw_value, normalized_value) for any indicator type.
    Forensic raw integrity is strictly preserved in raw_value.
    """
    raw = value.strip()
    t = IndicatorTypeEnum(indicator_type) if isinstance(indicator_type, str) else indicator_type

    if t == IndicatorTypeEnum.DOMAIN:
        norm = normalize_domain(raw)
    elif t == IndicatorTypeEnum.IP:
        norm = normalize_ip(raw)
    elif t == IndicatorTypeEnum.URL:
        norm = normalize_url(raw)
    elif t == IndicatorTypeEnum.EMAIL_ADDRESS:
        norm = normalize_email_address(raw)
    elif t == IndicatorTypeEnum.FILE_HASH:
        norm = normalize_hash(raw)
    else:
        norm = raw.lower()

    return raw, norm


# ============================================================================
# PYDANTIC DATA TRANSFER MODELS
# ============================================================================

class ArtifactBase(BaseModel):
    artifact_type: ArtifactTypeEnum
    name: str = Field(..., max_length=255)
    source: str = Field(default="UPLOAD", max_length=100)
    mime_type: Optional[str] = Field(default=None, max_length=100)
    size: Optional[int] = Field(default=None, ge=0)
    sha256: Optional[str] = Field(default=None, max_length=64)
    sha1: Optional[str] = Field(default=None, max_length=40)
    md5: Optional[str] = Field(default=None, max_length=32)
    storage_reference: Optional[str] = Field(default=None, max_length=500)
    parent_artifact_id: Optional[str] = Field(default=None, max_length=36)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("sha256", "sha1", "md5", mode="before")
    @classmethod
    def _lower_hashes(cls, v: Optional[str]) -> Optional[str]:
        return v.strip().lower() if isinstance(v, str) else v


class ArtifactCreate(ArtifactBase):
    pass


class ArtifactRead(ArtifactBase):
    id: str
    ingested_at: datetime
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AnalysisRunBase(BaseModel):
    artifact_id: str
    status: AnalysisStatusEnum = AnalysisStatusEnum.QUEUED
    trigger: AnalysisTriggerEnum = AnalysisTriggerEnum.USER
    pipeline_version: str = Field(default="1.0.0", max_length=50)
    overall_risk_score: Optional[float] = Field(default=None, ge=0.0, le=100.0)
    overall_severity: Optional[SeverityEnum] = None
    confidence: Optional[float] = Field(default=1.0, ge=0.0, le=1.0)
    error: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AnalysisRunCreate(AnalysisRunBase):
    pass


class AnalysisRunRead(AnalysisRunBase):
    id: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class FindingEvidenceBase(BaseModel):
    evidence_type: str = Field(..., max_length=50)
    source: str = Field(..., max_length=100)
    key: str = Field(..., max_length=100)
    value: str
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    artifact_id: Optional[str] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = Field(default_factory=dict)


class FindingEvidenceCreate(FindingEvidenceBase):
    finding_id: Optional[str] = None


class FindingEvidenceRead(FindingEvidenceBase):
    id: str
    finding_id: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class FindingBase(BaseModel):
    analysis_run_id: str
    analyzer: str = Field(..., max_length=100)
    finding_type: str = Field(..., max_length=100)
    title: str = Field(..., max_length=255)
    description: str
    severity: SeverityEnum = SeverityEnum.LOW
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    risk_contribution: float = Field(default=0.0, ge=0.0, le=100.0)
    method: FindingMethodEnum = FindingMethodEnum.RULE
    model_version_id: Optional[str] = None
    rule_id: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class FindingCreate(FindingBase):
    evidence_items: List[FindingEvidenceCreate] = Field(default_factory=list)


class FindingRead(FindingBase):
    id: str
    created_at: datetime
    evidence_items: List[FindingEvidenceRead] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)


class IndicatorBase(BaseModel):
    indicator_type: IndicatorTypeEnum
    value: str
    normalized_value: Optional[str] = None
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    reputation: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class IndicatorCreate(IndicatorBase):
    pass


class IndicatorRead(IndicatorBase):
    id: str
    normalized_value: str
    first_seen: datetime
    last_seen: datetime
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class EntityBase(BaseModel):
    entity_type: EntityTypeEnum
    name: str = Field(..., max_length=255)
    external_id: Optional[str] = None
    attributes: Dict[str, Any] = Field(default_factory=dict)


class EntityCreate(EntityBase):
    pass


class EntityRead(EntityBase):
    id: str
    first_seen: datetime
    last_seen: datetime
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class RelationshipBase(BaseModel):
    source_type: str = Field(..., max_length=50)
    source_id: str = Field(..., max_length=128)
    relationship_type: RelationshipTypeEnum
    target_type: str = Field(..., max_length=50)
    target_id: str = Field(..., max_length=128)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    evidence_reference: Optional[str] = None
    analysis_run_id: Optional[str] = None
    method: str = Field(default="RULE", max_length=50)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class RelationshipCreate(RelationshipBase):
    pass


class RelationshipRead(RelationshipBase):
    id: str
    first_seen: datetime
    last_seen: datetime
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ThreatEventBase(BaseModel):
    event_type: str = Field(..., max_length=100)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source_artifact_id: Optional[str] = None
    analysis_run_id: Optional[str] = None
    severity: SeverityEnum = SeverityEnum.MEDIUM
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    status: str = Field(default="OPEN", max_length=30)
    summary: str
    incident_id: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ThreatEventCreate(ThreatEventBase):
    pass


class ThreatEventRead(ThreatEventBase):
    id: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class IncidentBase(BaseModel):
    title: str = Field(..., max_length=255)
    description: Optional[str] = None
    status: IncidentStatusEnum = IncidentStatusEnum.OPEN
    severity: SeverityEnum = SeverityEnum.MEDIUM
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    assigned_to: Optional[str] = None
    legacy_case_id: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class IncidentCreate(IncidentBase):
    incident_number: Optional[str] = None


class IncidentRead(IncidentBase):
    id: str
    incident_number: str
    opened_at: datetime
    closed_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ResponseActionBase(BaseModel):
    incident_id: str
    threat_event_id: Optional[str] = None
    action_type: str = Field(..., max_length=50)
    description: str
    status: ResponseStatusEnum = ResponseStatusEnum.RECOMMENDED
    priority: str = Field(default="MEDIUM", max_length=20)
    recommended_by: str = Field(..., max_length=100)
    approved_by: Optional[str] = None
    executed_by: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ResponseActionCreate(ResponseActionBase):
    pass


class ResponseActionRead(ResponseActionBase):
    id: str
    created_at: datetime
    approved_at: Optional[datetime] = None
    executed_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class ModelVersionBase(BaseModel):
    model_name: str = Field(..., max_length=100)
    model_type: str = Field(..., max_length=50)
    version: str = Field(..., max_length=50)
    provider: str = Field(..., max_length=100)
    training_dataset_reference: Optional[str] = None
    metrics: Dict[str, Any] = Field(default_factory=dict)
    status: ModelStatusEnum = ModelStatusEnum.ACTIVE
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ModelVersionCreate(ModelVersionBase):
    pass


class ModelVersionRead(ModelVersionBase):
    id: str
    deployed_at: Optional[datetime] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ============================================================================
# SECTION 3: STORAGE & INGESTION SCHEMAS
# ============================================================================

class StorageBackendEnum(str, Enum):
    LOCAL = "LOCAL"
    S3 = "S3"
    GCS = "GCS"
    AZURE = "AZURE"


class IntegrityStatusEnum(str, Enum):
    UNVERIFIED = "UNVERIFIED"
    VERIFIED = "VERIFIED"
    MISMATCH = "MISMATCH"
    MISSING = "MISSING"


class RetentionPolicyEnum(str, Enum):
    INDEFINITE = "INDEFINITE"
    THIRTY_DAYS = "30_DAYS"
    NINETY_DAYS = "90_DAYS"
    ONE_YEAR = "1_YEAR"
    LEGAL_HOLD = "LEGAL_HOLD"


class ArtifactStorageRecordBase(BaseModel):
    artifact_id: str
    storage_backend: StorageBackendEnum = StorageBackendEnum.LOCAL
    storage_key: str = Field(..., max_length=500)
    sha256: str = Field(..., max_length=64)
    size: int = Field(..., ge=0)
    mime_type: Optional[str] = None
    original_filename: Optional[str] = None
    stored_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    verified_at: Optional[datetime] = None
    integrity_status: IntegrityStatusEnum = IntegrityStatusEnum.UNVERIFIED
    retention_policy: RetentionPolicyEnum = RetentionPolicyEnum.INDEFINITE
    retain_until: Optional[datetime] = None
    legal_hold: bool = False
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ArtifactStorageRecordCreate(ArtifactStorageRecordBase):
    pass


class ArtifactStorageRecordRead(ArtifactStorageRecordBase):
    id: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class IngestionRecordBase(BaseModel):
    artifact_id: str
    source: str = Field(default="UPLOAD", max_length=50)
    submitted_by: Optional[str] = None
    received_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    original_filename: Optional[str] = None
    request_id: Optional[str] = None
    context: Dict[str, Any] = Field(default_factory=dict)
    status: str = Field(default="COMPLETED", max_length=30)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class IngestionRecordCreate(IngestionRecordBase):
    pass


class IngestionRecordRead(IngestionRecordBase):
    id: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class IntegrityCheckResult(BaseModel):
    artifact_id: str
    storage_key: Optional[str] = None
    expected_sha256: str
    actual_sha256: Optional[str] = None
    status: IntegrityStatusEnum
    verified_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    details: Optional[str] = None


class ReanalyzeRequest(BaseModel):
    trigger: str = Field(default="REANALYSIS", max_length=50)
    pipeline_version: str = Field(default="1.1.0", max_length=50)
    force: bool = False


class OrphanReport(BaseModel):
    missing_files: List[Dict[str, Any]] = Field(default_factory=list)
    untracked_files: List[Dict[str, Any]] = Field(default_factory=list)
    stale_temp_files: List[Dict[str, Any]] = Field(default_factory=list)
    scan_timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ============================================================================
# SECTION 4: UNIVERSAL INGESTION SCHEMAS
# ============================================================================

class DetectedInput(BaseModel):
    input_mode: InputModeEnum
    artifact_type: ArtifactTypeEnum
    detected_mime: Optional[str] = None
    reported_mime: Optional[str] = None
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    detector: str = Field(default="heuristic")
    support_status: SupportStatusEnum = SupportStatusEnum.SUPPORTED
    warnings: List[str] = Field(default_factory=list)
    candidate_analyzers: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AnalyzerCapabilityRead(BaseModel):
    name: str
    version: str
    supported_artifact_types: List[ArtifactTypeEnum]
    status: CapabilityStatusEnum
    description: str


class IngestTextRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=1000000, description="Raw text, URL, domain, IP, or JSON")
    source: str = Field(default="TEXT_INPUT", max_length=50)
    submitted_by: Optional[str] = None
    notes: Optional[str] = None
    case_id: Optional[str] = None
    incident_id: Optional[str] = None
    request_id: Optional[str] = None


class IngestEventRequest(BaseModel):
    event: Dict[str, Any] = Field(..., description="Structured JSON security event")
    source_type: Optional[str] = Field(default="SECURITY_EVENT", max_length=50)
    source: str = Field(default="STRUCTURED_EVENT", max_length=50)
    submitted_by: Optional[str] = None
    notes: Optional[str] = None
    case_id: Optional[str] = None
    incident_id: Optional[str] = None
    request_id: Optional[str] = None


class DetectInputRequest(BaseModel):
    text: Optional[str] = None
    filename: Optional[str] = None
    content_type: Optional[str] = None


class IngestionResult(BaseModel):
    ingestion_id: str
    artifact_id: str
    artifact_type: ArtifactTypeEnum
    input_mode: InputModeEnum
    name: str
    original_value: Optional[str] = None
    normalized_value: Optional[str] = None
    sha256: Optional[str] = None
    size: Optional[int] = None
    mime_type: Optional[str] = None
    classification: DetectedInput
    storage_status: str = Field(default="STORED")
    storage_key: Optional[str] = None
    analysis_status: AnalysisStatusEnum = AnalysisStatusEnum.INGESTED
    candidate_analyzers: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = ConfigDict(from_attributes=True)
