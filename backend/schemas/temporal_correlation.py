"""
Canonical Temporal Correlation & Event Sequencing Schemas (Section 16).
Provides normalized event contracts, timestamp provenance models, controlled event vocabularies,
timeline responses, burst representations, and temporal sequence candidate contracts.
"""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
from enum import Enum
import re
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field, ConfigDict

from backend.schemas.unified import SeverityEnum
from backend.services.log_sanitizer import sanitize_log_text


# ============================================================================
# 1. CONTROLLED VOCABULARY & ENUMS
# ============================================================================

class SecurityEventType(str, Enum):
    EMAIL_RECEIVED = "EMAIL_RECEIVED"
    EMAIL_SENT = "EMAIL_SENT"
    FILE_OBSERVED = "FILE_OBSERVED"
    FILE_EXTRACTED = "FILE_EXTRACTED"
    URL_OBSERVED = "URL_OBSERVED"
    URL_REDIRECTED = "URL_REDIRECTED"
    URL_ACCESSED = "URL_ACCESSED"  # Telemetry proven access only
    DOMAIN_RESOLVED = "DOMAIN_RESOLVED"
    AUTH_ATTEMPT = "AUTH_ATTEMPT"
    AUTH_SUCCESS = "AUTH_SUCCESS"
    AUTH_FAILURE = "AUTH_FAILURE"
    MFA_EVENT = "MFA_EVENT"
    SESSION_CREATED = "SESSION_CREATED"
    SESSION_ACTIVITY = "SESSION_ACTIVITY"
    NETWORK_CONNECTION = "NETWORK_CONNECTION"
    DNS_QUERY = "DNS_QUERY"
    DNS_RESPONSE = "DNS_RESPONSE"
    API_REQUEST = "API_REQUEST"
    API_RESPONSE = "API_RESPONSE"
    API_ENUMERATION = "API_ENUMERATION"
    BULK_RESOURCE_ACCESS = "BULK_RESOURCE_ACCESS"
    HIGH_OUTBOUND_DATA_VOLUME = "HIGH_OUTBOUND_DATA_VOLUME"
    MEDIA_OBSERVED = "MEDIA_OBSERVED"
    FINDING_CREATED = "FINDING_CREATED"
    THREAT_EVENT_CREATED = "THREAT_EVENT_CREATED"
    OTHER = "OTHER"


class TimePrecision(str, Enum):
    EXACT = "EXACT"
    MILLISECOND = "MILLISECOND"
    SECOND = "SECOND"
    MINUTE = "MINUTE"
    DATE_ONLY = "DATE_ONLY"
    UNKNOWN = "UNKNOWN"


class TimestampTrust(str, Enum):
    HIGH = "HIGH"        # Server auth log, gateway audit, kernel monotonic timestamp
    MEDIUM = "MEDIUM"    # Intermediate network sensor, local MTA Received header
    LOW = "LOW"          # Sender-controlled Date header, mutable mtime, client clock
    UNCERTAIN = "UNCERTAIN"


class SequenceStatus(str, Enum):
    OBSERVED_SEQUENCE = "OBSERVED_SEQUENCE"
    TEMPORALLY_ASSOCIATED = "TEMPORALLY_ASSOCIATED"
    POSSIBLE_SECURITY_SEQUENCE = "POSSIBLE_SECURITY_SEQUENCE"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    CONFLICTING_TIMESTAMPS = "CONFLICTING_TIMESTAMPS"


class TemporalRelationshipType(str, Enum):
    BEFORE = "BEFORE"
    AFTER = "AFTER"
    OVERLAPS = "OVERLAPS"
    WITHIN_WINDOW_OF = "WITHIN_WINDOW_OF"
    POSSIBLY_PRECEDES = "POSSIBLY_PRECEDES"
    ORDER_UNCERTAIN = "ORDER_UNCERTAIN"


# ============================================================================
# 2. PRIVACY & SANITIZATION UTILITIES
# ============================================================================

SENSITIVE_KEY_SUBSTRINGS = {
    "password", "secret", "token", "auth", "credential", "cookie",
    "api_key", "apikey", "bearer", "private_key", "session_key", "jwt",
    "mfa_code", "totp", "otp", "authorization"
}


def sanitize_temporal_attributes(data: Any) -> Any:
    """Recursively redacts credential keys and secret tokens from temporal event attributes."""
    if isinstance(data, dict):
        sanitized = {}
        for k, v in data.items():
            k_lower = str(k).lower()
            if any(sub in k_lower for sub in SENSITIVE_KEY_SUBSTRINGS):
                sanitized[k] = "[REDACTED_CREDENTIAL]"
            else:
                sanitized[k] = sanitize_temporal_attributes(v)
        return sanitized
    elif isinstance(data, list):
        return [sanitize_temporal_attributes(item) for item in data]
    elif isinstance(data, str):
        return sanitize_log_text(data)
    return data


# ============================================================================
# 3. TIMESTAMP PROVENANCE & NORMALIZATION MODELS
# ============================================================================

class TimestampProvenance(BaseModel):
    """
    Granular audit trail of how an event timestamp was obtained, parsed, and normalized.
    """
    model_config = ConfigDict(extra="ignore")

    source_field: str = Field(
        description="Source metadata field (e.g. 'Received[0]', 'Date', 'auth_log.timestamp', 'flow.start_time')"
    )
    original_value: str = Field(
        description="Original verbatim timestamp string or representation from raw evidence"
    )
    original_timezone: Optional[str] = Field(
        default=None,
        description="Detected original timezone or offset string, or 'UNKNOWN_TIMEZONE'"
    )
    clock_offset_applied_seconds: float = Field(
        default=0.0,
        description="Sensor or adapter clock offset explicitly applied to achieve true UTC"
    )
    trust_level: TimestampTrust = Field(
        default=TimestampTrust.MEDIUM,
        description="Authoritative trust ranking of this timestamp source"
    )
    precision: TimePrecision = Field(
        default=TimePrecision.SECOND,
        description="Recorded temporal granularity"
    )
    notes: Optional[str] = Field(
        default=None,
        description="Forensic context or ambiguity explanations"
    )


class SecurityEvent(BaseModel):
    """
    Canonical normalized security event.
    Acts as a temporal projection/index over normalized multi-source evidence.
    """
    model_config = ConfigDict(extra="ignore")

    id: str = Field(description="Unique identifier for the security event")
    event_type: SecurityEventType = Field(description="Controlled event category")
    event_time: datetime = Field(description="Normalized UTC event occurrence timestamp")
    event_time_end: Optional[datetime] = Field(
        default=None,
        description="Optional UTC timestamp marking end of duration for interval events"
    )
    event_time_precision: TimePrecision = Field(
        default=TimePrecision.SECOND,
        description="Precision level of event_time"
    )
    event_time_confidence: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="Confidence in timestamp accuracy (0.0 - 1.0)"
    )
    ingested_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC time when CyberGuard ingested the parent artifact"
    )
    analyzed_at: Optional[datetime] = Field(
        default=None,
        description="UTC time when CyberGuard analyzed or projected the event"
    )
    source_type: str = Field(
        description="Telemetry channel (e.g. 'EMAIL', 'AUTH_LOG', 'NETWORK_LOG', 'API_LOG', 'FILE', 'MEDIA')"
    )
    source_artifact_id: Optional[str] = Field(
        default=None,
        description="Parent stored artifact UUID"
    )
    analysis_run_id: Optional[str] = Field(
        default=None,
        description="Parent analysis run UUID"
    )
    incident_id: Optional[str] = Field(
        default=None,
        description="Associated incident UUID"
    )
    workspace_id: str = Field(
        default="default",
        description="Tenant / workspace identifier for strict partition isolation"
    )
    entity_ids: List[str] = Field(
        default_factory=list,
        description="Referenced canonical Knowledge Graph entity canonical_keys or IDs"
    )
    finding_ids: List[str] = Field(
        default_factory=list,
        description="Referenced finding UUIDs produced by detection engines"
    )
    threat_event_ids: List[str] = Field(
        default_factory=list,
        description="Referenced ThreatEvent UUIDs"
    )
    provider: str = Field(
        default="generic",
        description="Sensor, gateway, or IdP provider name"
    )
    adapter: str = Field(
        default="generic",
        description="Telemetry adapter module"
    )
    adapter_version: str = Field(
        default="1.0.0",
        description="Version of ingestion/parsing adapter"
    )
    attributes: Dict[str, Any] = Field(
        default_factory=dict,
        description="Sanitized domain attributes without credentials or tokens"
    )
    timestamp_provenance: TimestampProvenance = Field(
        description="Detailed provenance of event_time"
    )
    summary: Optional[str] = Field(
        default=None,
        description="Concise human-readable summary of activity"
    )


# ============================================================================
# 4. TIMELINE PRESENTATION & BURST MODELS
# ============================================================================

class TimelineBurstSummary(BaseModel):
    """
    Compact presentation item representing a burst of repetitive identical events.
    Preserves underlying raw events while preventing timeline flooding.
    """
    model_config = ConfigDict(extra="ignore")

    event_type: SecurityEventType = Field(description="Common event type in burst")
    count: int = Field(description="Number of collapsed events in this burst window")
    start_time: datetime = Field(description="Earliest event UTC timestamp in burst")
    end_time: datetime = Field(description="Latest event UTC timestamp in burst")
    duration_seconds: float = Field(description="Span of burst in seconds")
    representative_event_ids: List[str] = Field(
        default_factory=list,
        description="Subset of event IDs for direct analyst inspection"
    )
    shared_entities: List[str] = Field(
        default_factory=list,
        description="Entities common to all events in burst"
    )
    summary: str = Field(description="Human-readable burst description (e.g. '214 AUTH_FAILURE events')")


class TimelineItem(BaseModel):
    """
    Polymorphic timeline presentation item: either an individual event or a burst summary.
    """
    model_config = ConfigDict(extra="ignore")

    item_type: str = Field(description="'EVENT' or 'BURST'")
    event: Optional[SecurityEvent] = Field(default=None, description="Populated when item_type == 'EVENT'")
    burst: Optional[TimelineBurstSummary] = Field(default=None, description="Populated when item_type == 'BURST'")


class IncidentTimelineResponse(BaseModel):
    """Chronologically sorted incident timeline with pagination and optional burst compression."""
    incident_id: str
    workspace_id: str
    total_events: int
    returned_items: int
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    items: List[TimelineItem]
    page: int = 1
    page_size: int = 50
    has_more: bool = False


class EntityTimelineResponse(BaseModel):
    """Chronological timeline of security observations involving an entity."""
    entity_id: str
    canonical_key: Optional[str] = None
    entity_type: Optional[str] = None
    workspace_id: str
    total_events: int
    items: List[TimelineItem]
    page: int = 1
    page_size: int = 50
    has_more: bool = False


# ============================================================================
# 5. TEMPORAL RULE & SEQUENCE CANDIDATE MODELS
# ============================================================================

class TemporalRule(BaseModel):
    """
    Versioned declarative rule for temporal sequence matching.
    """
    model_config = ConfigDict(extra="ignore")

    rule_id: str = Field(description="Unique deterministic rule identifier")
    version: str = Field(default="1.0.0", description="Semantic rule version")
    name: str = Field(description="Human-readable rule title")
    description: str = Field(description="Analytical explanation of what the sequence signifies")
    source_event_types: List[SecurityEventType] = Field(description="Permitted predecessor event types")
    target_event_types: List[SecurityEventType] = Field(description="Permitted successor event types")
    min_delay_seconds: float = Field(default=0.0, description="Minimum separation between source and target")
    max_delay_seconds: float = Field(description="Maximum permissible window between source and target")
    required_shared_entities: List[str] = Field(
        default_factory=list,
        description="Entity types that MUST match between source and target (e.g. ['ACCOUNT'], ['SESSION'])"
    )
    optional_shared_entities: List[str] = Field(
        default_factory=list,
        description="Entity types that strengthen correlation if shared (e.g. ['IP', 'DEVICE'])"
    )
    required_conditions: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional metric or attribute checks"
    )
    resulting_status: SequenceStatus = Field(
        default=SequenceStatus.TEMPORALLY_ASSOCIATED,
        description="Status assigned when sequence matches"
    )
    base_confidence: float = Field(
        default=0.70,
        ge=0.0,
        le=1.0,
        description="Base confidence score before evidence weighting"
    )


class TemporalSequenceCandidate(BaseModel):
    """
    Explainable multi-event temporal sequence candidate.
    Exposes ordered events, shared entities, matched rules, supporting and conflicting evidence,
    and non-attribution limitations.
    """
    model_config = ConfigDict(extra="ignore")

    id: str = Field(description="Unique UUID for sequence candidate")
    incident_id: str = Field(description="Parent incident UUID")
    workspace_id: str = Field(default="default", description="Workspace isolation partition")
    event_ids: List[str] = Field(description="Chronologically ordered sequence of SecurityEvent UUIDs")
    events: List[SecurityEvent] = Field(default_factory=list, description="Hydrated security event objects")
    rule_ids: List[str] = Field(default_factory=list, description="Matched temporal rule IDs")
    start_time: datetime = Field(description="Earliest event timestamp in sequence")
    end_time: datetime = Field(description="Latest event timestamp in sequence")
    duration_seconds: float = Field(description="Total duration of sequence in seconds")
    shared_entities: List[str] = Field(
        default_factory=list,
        description="Canonical entity keys linking events across the sequence"
    )
    supporting_evidence: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Structured rationale items strengthening temporal relationship"
    )
    conflicting_evidence: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Structured conflicting or contradictory indicators (e.g. timestamp inversions)"
    )
    limitations: List[str] = Field(
        default_factory=list,
        description="Explicit non-attribution guarantees and missing telemetry caveats"
    )
    confidence: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Calibrated confidence in temporal correlation validity"
    )
    status: SequenceStatus = Field(
        default=SequenceStatus.OBSERVED_SEQUENCE,
        description="Analytical status (strictly NO 'CONFIRMED_ATTACK_CHAIN')"
    )
    summary: str = Field(description="Executive analytical explanation of observed sequence")
    engine_version: str = Field(default="1.0.0")
    rule_version: str = Field(default="1.0.0")


class SequenceAnalysisResponse(BaseModel):
    """Response payload for on-demand temporal sequence detection across an incident."""
    incident_id: str
    workspace_id: str
    candidates: List[TemporalSequenceCandidate]
    total_candidates: int
    events_analyzed: int
    rules_evaluated: int
    analysis_duration_ms: float


class CampaignTimelineResponse(BaseModel):
    """Consolidated chronological timeline across all incidents belonging to a campaign candidate."""
    campaign_id: str
    workspace_id: str
    incidents: List[str]
    total_events: int
    first_observed_time: Optional[datetime] = None
    last_observed_time: Optional[datetime] = None
    items: List[TimelineItem]
