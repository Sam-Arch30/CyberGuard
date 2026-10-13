"""
Unified Multimedia Authenticity Schemas & Models for Section 13.
Defines canonical enums, detector representations, findings, and assessment schemas
for image, audio, and video deepfake/authenticity forensics.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, ConfigDict

from backend.schemas.unified import SeverityEnum


# ============================================================================
# CANONICAL ENUMS
# ============================================================================

class MediaTypeEnum(str, Enum):
    IMAGE = "IMAGE"
    AUDIO = "AUDIO"
    VIDEO = "VIDEO"
    UNKNOWN_MEDIA = "UNKNOWN_MEDIA"


class MediaFormatEnum(str, Enum):
    JPEG = "JPEG"
    PNG = "PNG"
    WEBP = "WEBP"
    GIF = "GIF"
    BMP = "BMP"
    WAV = "WAV"
    MP3 = "MP3"
    OGG = "OGG"
    FLAC = "FLAC"
    AVI = "AVI"
    MP4 = "MP4"
    MOV = "MOV"
    WEBM = "WEBM"
    UNKNOWN = "UNKNOWN"


class DetectorStatusEnum(str, Enum):
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    UNAVAILABLE = "UNAVAILABLE"
    UNSUPPORTED = "UNSUPPORTED"
    TIMEOUT = "TIMEOUT"
    INVALID_INPUT = "INVALID_INPUT"


class AuthenticityClassificationEnum(str, Enum):
    NO_STRONG_MANIPULATION_SIGNAL = "NO_STRONG_MANIPULATION_SIGNAL"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    MANIPULATION_SIGNALS_DETECTED = "MANIPULATION_SIGNALS_DETECTED"
    SYNTHETIC_MEDIA_SIGNALS_DETECTED = "SYNTHETIC_MEDIA_SIGNALS_DETECTED"
    STRONG_SYNTHETIC_MEDIA_INDICATORS = "STRONG_SYNTHETIC_MEDIA_INDICATORS"


class MediaEvidenceCategoryEnum(str, Enum):
    PROVENANCE = "PROVENANCE"
    METADATA = "METADATA"
    IMAGE_DETECTOR = "IMAGE_DETECTOR"
    AUDIO_DETECTOR = "AUDIO_DETECTOR"
    VIDEO_DETECTOR = "VIDEO_DETECTOR"
    TEMPORAL_CONSISTENCY = "TEMPORAL_CONSISTENCY"
    MODEL_AGREEMENT = "MODEL_AGREEMENT"


class ProvenanceStatusEnum(str, Enum):
    VALID_CREDENTIALS = "VALID_CREDENTIALS"
    UNVERIFIED_CREDENTIALS = "UNVERIFIED_CREDENTIALS"
    INVALID_CREDENTIALS = "INVALID_CREDENTIALS"
    NO_CREDENTIALS_FOUND = "NO_CREDENTIALS_FOUND"
    UNSUPPORTED_CONTAINER = "UNSUPPORTED_CONTAINER"


# ============================================================================
# DATA MODELS
# ============================================================================

class MediaIdentity(BaseModel):
    """Immutable identity properties of a media artifact."""
    model_config = ConfigDict(extra="ignore")

    artifact_id: str
    sha256: str
    original_filename: str
    mime_type: str
    media_type: MediaTypeEnum
    format: MediaFormatEnum
    size_bytes: int


class MediaMetadata(BaseModel):
    """Extracted structural and container metadata from media."""
    model_config = ConfigDict(extra="ignore")

    width: Optional[int] = None
    height: Optional[int] = None
    color_mode: Optional[str] = None
    exif_present: bool = False
    camera_make: Optional[str] = None
    camera_model: Optional[str] = None
    software: Optional[str] = None
    duration_seconds: Optional[float] = None
    sample_rate: Optional[int] = None
    channels: Optional[int] = None
    bitrate: Optional[int] = None
    codecs: List[str] = Field(default_factory=list)
    frame_rate: Optional[float] = None
    has_audio_track: bool = False
    has_video_track: bool = False
    container_tags: Dict[str, Any] = Field(default_factory=dict)


class ProvenanceRecord(BaseModel):
    """Cryptographic provenance / Content Credentials (C2PA) verification result."""
    model_config = ConfigDict(extra="ignore")

    status: ProvenanceStatusEnum = ProvenanceStatusEnum.NO_CREDENTIALS_FOUND
    credential_present: bool = False
    signature_valid: Optional[bool] = None
    issuer: Optional[str] = None
    claim_generator: Optional[str] = None
    assertions: List[Dict[str, Any]] = Field(default_factory=list)
    validation_details: str = "No verifiable Content Credentials found."


class DetectorResult(BaseModel):
    """Structured output from an individual media detector adapter."""
    model_config = ConfigDict(extra="ignore")

    detector_id: str
    detector_name: str
    detector_version: str
    media_type: MediaTypeEnum
    status: DetectorStatusEnum
    score: Optional[float] = Field(default=None, description="Score 0.0-1.0 if calibrated")
    label: Optional[str] = None
    confidence: Optional[float] = None
    evidence: Dict[str, Any] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    runtime_ms: float = 0.0
    model_name: Optional[str] = None
    model_version: Optional[str] = None
    limitations: List[str] = Field(default_factory=list)


class TemporalSegment(BaseModel):
    """Localized temporal region of interest (audio segment or video frame/scene)."""
    model_config = ConfigDict(extra="ignore")

    start_seconds: float
    end_seconds: float
    frame_index: Optional[int] = None
    timestamp_iso: Optional[str] = None
    score: float
    label: str
    evidence_detail: str


class MediaFindingEvidence(BaseModel):
    """Forensic evidence item attached to a finding."""
    model_config = ConfigDict(extra="ignore")

    category: MediaEvidenceCategoryEnum
    source: str
    key: str
    value: Any
    confidence: float = 1.0


class MediaFinding(BaseModel):
    """Explainable finding emitted by the multimedia forensics engine."""
    model_config = ConfigDict(extra="ignore")

    finding_type: str
    title: str
    description: str
    severity: SeverityEnum
    confidence: float
    risk_contribution: float
    rule_id: str
    category: MediaEvidenceCategoryEnum
    evidence_items: List[MediaFindingEvidence] = Field(default_factory=list)
    limitation: str
    mitre_attack_ids: List[str] = Field(default_factory=list)


class MediaAuthenticityAssessment(BaseModel):
    """Overall synthesized multimedia authenticity assessment."""
    model_config = ConfigDict(extra="ignore")

    artifact_id: str
    media_type: MediaTypeEnum
    format: MediaFormatEnum
    processing_status: str = "INSUFFICIENT_EVIDENCE"
    analysis_scope: str = "Bounded heuristic analysis; authenticity is not established."
    trained_detector: Optional[Dict[str, Any]] = None
    confidence_basis: str = "UNAVAILABLE_NOT_CALIBRATED"
    classification: AuthenticityClassificationEnum
    confidence: float
    risk_score: float
    summary: str
    supporting_findings: List[MediaFinding] = Field(default_factory=list)
    contradicting_findings: List[MediaFinding] = Field(default_factory=list)
    detector_results: List[DetectorResult] = Field(default_factory=list)
    temporal_segments: List[TemporalSegment] = Field(default_factory=list)
    provenance: ProvenanceRecord
    metadata: MediaMetadata
    limitations: List[str] = Field(default_factory=list)
    analysis_run_id: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ============================================================================
# API REQUEST & RESPONSE SCHEMAS
# ============================================================================

class MediaAnalysisRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    media_bytes_b64: Optional[str] = None
    filename: str = "unnamed_media"
    artifact_id: Optional[str] = None
    declared_mime: Optional[str] = None
    context_claimed_identity_id: Optional[str] = None


class MediaAnalysisResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    success: bool
    artifact_id: str
    analysis_run_id: str
    media_identity: MediaIdentity
    assessment: MediaAuthenticityAssessment
    threat_event_id: Optional[str] = None
