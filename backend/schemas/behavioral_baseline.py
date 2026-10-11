"""
Behavioral Baseline & Anomaly Detection Schemas (Section 21).

Pydantic V2 models defining entity-specific behavioral baselines, robust statistical
distributions, deviation metrics, contextual profiles, poisoning protections, and audit records.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
import math
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field, ConfigDict, field_validator


# ============================================================================
# 1. CONTROLLED VOCABULARY & ENUMS
# ============================================================================

class BaselineEntityType(str, Enum):
    USER = "USER"
    ACCOUNT = "ACCOUNT"
    DEVICE = "DEVICE"
    ENDPOINT = "ENDPOINT"
    SERVICE = "SERVICE"
    API_CLIENT = "API_CLIENT"
    NETWORK_ENTITY = "NETWORK_ENTITY"
    INFRASTRUCTURE = "INFRASTRUCTURE"
    IP = "IP"
    DOMAIN = "DOMAIN"


class BaselineMetricType(str, Enum):
    # Authentication & User Metrics
    LOGIN_FREQUENCY = "LOGIN_FREQUENCY"
    LOGIN_HOUR = "LOGIN_HOUR"
    LOGIN_DAY_PATTERN = "LOGIN_DAY_PATTERN"
    LOGIN_SOURCE_IP = "LOGIN_SOURCE_IP"
    LOGIN_DEVICE = "LOGIN_DEVICE"
    LOGIN_LOCATION = "LOGIN_LOCATION"
    AUTH_FAILURE_RATE = "AUTH_FAILURE_RATE"
    AUTH_METHOD = "AUTH_METHOD"
    MFA_PATTERN = "MFA_PATTERN"
    SESSION_DURATION = "SESSION_DURATION"

    # API Metrics
    API_REQUEST_RATE = "API_REQUEST_RATE"
    API_ENDPOINT_FREQUENCY = "API_ENDPOINT_FREQUENCY"
    API_METHOD_FREQUENCY = "API_METHOD_FREQUENCY"
    API_RESPONSE_VOLUME = "API_RESPONSE_VOLUME"

    # Network Metrics
    NETWORK_DESTINATION_FREQUENCY = "NETWORK_DESTINATION_FREQUENCY"
    NETWORK_PORT_FREQUENCY = "NETWORK_PORT_FREQUENCY"
    NETWORK_PROTOCOL_FREQUENCY = "NETWORK_PROTOCOL_FREQUENCY"
    OUTBOUND_BYTES = "OUTBOUND_BYTES"
    INBOUND_BYTES = "INBOUND_BYTES"
    CONNECTION_FREQUENCY = "CONNECTION_FREQUENCY"
    DNS_QUERY_FREQUENCY = "DNS_QUERY_FREQUENCY"
    DNS_DOMAIN_PATTERN = "DNS_DOMAIN_PATTERN"

    # Endpoint & Process Metrics (Section 60)
    PROCESS_EXECUTION_FREQUENCY = "PROCESS_EXECUTION_FREQUENCY"
    PROCESS_NAME_FREQUENCY = "PROCESS_NAME_FREQUENCY"
    COMMAND_LINE_LENGTH = "COMMAND_LINE_LENGTH"
    PARENT_PROCESS_FREQUENCY = "PARENT_PROCESS_FREQUENCY"
    FILE_MODIFICATION_RATE = "FILE_MODIFICATION_RATE"

    # Resource & Telemetry Metrics
    RESOURCE_ACCESS_FREQUENCY = "RESOURCE_ACCESS_FREQUENCY"
    EMAIL_VOLUME = "EMAIL_VOLUME"


class BaselineWindowType(str, Enum):
    ROLLING_7D = "ROLLING_7D"
    ROLLING_14D = "ROLLING_14D"
    ROLLING_30D = "ROLLING_30D"
    ROLLING_60D = "ROLLING_60D"
    ROLLING_90D = "ROLLING_90D"


class BaselineQuality(str, Enum):
    NO_DATA = "NO_DATA"
    INSUFFICIENT_HISTORY = "INSUFFICIENT_HISTORY"
    LOW_QUALITY = "LOW_QUALITY"
    DEVELOPING = "DEVELOPING"
    STABLE = "STABLE"
    STALE = "STALE"
    DEGRADED = "DEGRADED"


class LearningMode(str, Enum):
    LEARNING = "LEARNING"
    STABLE = "STABLE"
    RELEARNING = "RELEARNING"
    FROZEN = "FROZEN"
    DEGRADED = "DEGRADED"


class DeviationDirection(str, Enum):
    ABOVE_NORMAL = "ABOVE_NORMAL"
    BELOW_NORMAL = "BELOW_NORMAL"
    NEW = "NEW"
    MISSING = "MISSING"
    CHANGED = "CHANGED"


class EntityProfileCategory(str, Enum):
    HUMAN_USER = "HUMAN_USER"
    SERVICE_ACCOUNT = "SERVICE_ACCOUNT"
    APPLICATION = "APPLICATION"
    DEVICE = "DEVICE"
    SYSTEM = "SYSTEM"
    ADMINISTRATOR = "ADMINISTRATOR"
    UNKNOWN = "UNKNOWN"


class ExclusionCategory(str, Enum):
    CONFIRMED_MALICIOUS = "CONFIRMED_MALICIOUS"
    KNOWN_ATTACK_ACTIVITY = "KNOWN_ATTACK_ACTIVITY"
    HIGH_CONFIDENCE_ANOMALY = "HIGH_CONFIDENCE_ANOMALY"
    ANALYST_MARKED_MALICIOUS = "ANALYST_MARKED_MALICIOUS"
    QUARANTINED_ACTIVITY = "QUARANTINED_ACTIVITY"


class BaselineConfidenceLevel(str, Enum):
    VERY_LOW = "VERY_LOW"
    LOW = "LOW"
    MODERATE = "MODERATE"
    HIGH = "HIGH"
    VERY_HIGH = "VERY_HIGH"


# ============================================================================
# 2. PRIVACY SAFEGUARDS & RESTRICTED KEYS
# ============================================================================

FORBIDDEN_FEATURE_KEYWORDS = {
    "password", "passwd", "secret", "token", "apikey", "api_key",
    "cookie", "session_secret", "mfa_code", "totp_code", "auth_header",
    "authorization", "bearer", "private_key", "credential"
}


def validate_feature_privacy(key: str, value: Any) -> None:
    """Verifies that sensitive credentials or secrets are never used as behavioral features."""
    lower_key = key.lower()
    for kw in FORBIDDEN_FEATURE_KEYWORDS:
        if kw in lower_key:
            raise ValueError(
                f"Privacy violation: Feature key '{key}' contains sensitive credential keyword '{kw}'. "
                "Raw credentials, tokens, and authorization secrets must never be ingested or persisted as baseline features."
            )
    if isinstance(value, str):
        lower_val = value.lower()
        if lower_val.startswith("bearer ") or lower_val.startswith("basic "):
            raise ValueError("Privacy violation: Raw authorization bearer/basic strings cannot be stored in baseline features.")


# ============================================================================
# 3. STATISTICAL DISTRIBUTION MODELS
# ============================================================================

class BaselinePercentiles(BaseModel):
    model_config = ConfigDict(extra="ignore")
    p10: Optional[float] = None
    p25: Optional[float] = None
    p50: Optional[float] = None  # Median
    p75: Optional[float] = None
    p90: Optional[float] = None
    p95: Optional[float] = None
    p99: Optional[float] = None


class CategoryFrequency(BaseModel):
    model_config = ConfigDict(extra="ignore")
    category: str
    count: int
    frequency: float = Field(ge=0.0, le=1.0)


class CircularHourDistribution(BaseModel):
    """
    Time-of-day distribution with circular distance metrics (0-23 hours).
    Accounts for wrap-around where hour 23 and hour 1 are 2 hours apart, not 22 hours.
    """
    model_config = ConfigDict(extra="ignore")
    active_hours: List[int] = Field(default_factory=list, description="List of hours (0-23) observed historically")
    hour_counts: Dict[str, int] = Field(default_factory=dict, description="Counts per hour bin '0'-'23'")
    primary_cluster_start: Optional[int] = None
    primary_cluster_end: Optional[int] = None
    overnight_active: bool = False


# ============================================================================
# 4. BEHAVIORAL BASELINE CONTRACT
# ============================================================================

class BehavioralBaseline(BaseModel):
    """
    Normalized, entity-specific behavioral baseline model.
    Encapsulates robust statistical distributions, quality states, and version stamps.
    """
    model_config = ConfigDict(extra="ignore")

    id: str = Field(description="Unique baseline record UUID")
    workspace_id: str = Field(default="default")
    entity_type: BaselineEntityType
    entity_id: str = Field(description="Stable normalized entity identifier (lowercase username, account UUID, host GUID)")
    entity_category: EntityProfileCategory = Field(default=EntityProfileCategory.HUMAN_USER)
    metric_type: BaselineMetricType
    metric_version: str = Field(default="1.0.0")
    window_type: BaselineWindowType = Field(default=BaselineWindowType.ROLLING_30D)
    window_start: Optional[datetime] = None
    window_end: Optional[datetime] = None
    sample_count: int = Field(default=0, ge=0)
    valid_sample_count: int = Field(default=0, ge=0)
    missing_sample_count: int = Field(default=0, ge=0)

    # Numerical statistics (robust)
    median_value: Optional[float] = None
    mean_value: Optional[float] = None
    standard_deviation: Optional[float] = None
    mad: Optional[float] = Field(default=None, description="Median Absolute Deviation")
    percentiles: Optional[BaselinePercentiles] = None
    minimum: Optional[float] = None
    maximum: Optional[float] = None

    # Categorical & Temporal distributions
    categorical_distribution: Dict[str, int] = Field(default_factory=dict)
    circular_hour_distribution: Optional[CircularHourDistribution] = None
    expected_range_summary: str = Field(default="", description="Analyst-friendly summary of normal range")

    # Quality & State
    confidence_score: float = Field(default=0.5, ge=0.0, le=1.0)
    confidence_level: BaselineConfidenceLevel = Field(default=BaselineConfidenceLevel.MODERATE)
    quality_status: BaselineQuality = Field(default=BaselineQuality.INSUFFICIENT_HISTORY)
    learning_mode: LearningMode = Field(default=LearningMode.LEARNING)

    # Freeze & Control
    is_frozen: bool = False
    frozen_reason: Optional[str] = None
    frozen_by: Optional[str] = None
    frozen_at: Optional[datetime] = None

    # Lineage & Versioning
    baseline_version: str = Field(default="1.0.0")
    feature_version: str = Field(default="1.0.0")
    calculation_method: str = Field(default="ROBUST_STATISTICS")
    configuration_version: str = Field(default="2026.10")
    source_count: int = Field(default=0, ge=0)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("categorical_distribution")
    @classmethod
    def check_distribution_privacy(cls, v: Dict[str, int]) -> Dict[str, int]:
        for k in v.keys():
            validate_feature_privacy(k, k)
        return v


# ============================================================================
# 5. BEHAVIORAL DEVIATION MODEL
# ============================================================================

class BehavioralDeviation(BaseModel):
    """
    Normalized result of comparing an observed event against an established baseline.
    Represents objective deviation evidence without premature security verdicts.
    """
    model_config = ConfigDict(extra="ignore")

    id: str = Field(description="Unique deviation finding UUID")
    baseline_id: Optional[str] = Field(default=None, description="Associated baseline UUID if established")
    incident_id: Optional[str] = None
    investigation_id: Optional[str] = None
    workspace_id: str = Field(default="default")
    entity_type: BaselineEntityType
    entity_id: str
    metric_type: BaselineMetricType
    observed_value: str = Field(description="Stringified observed value or category")
    expected_range_summary: str = Field(description="Summary of normal historical expectations")
    deviation_score: float = Field(ge=0.0, le=1.0, description="Normalized deviation magnitude (0.0=normal, 1.0=extreme anomaly)")
    deviation_direction: DeviationDirection
    severity_hint: str = Field(default="LOW", description="LOW, MEDIUM, HIGH, CRITICAL hint for risk aggregation")
    baseline_confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    baseline_quality: BaselineQuality = Field(default=BaselineQuality.STABLE)
    evidence_ids: List[str] = Field(default_factory=list, description="IDs of underlying telemetry events")
    explanation: str = Field(description="Epistemically humble, evidence-backed explanation")
    limitations: List[str] = Field(default_factory=list, description="Documented caveats (e.g. developing baseline, proxy ambiguity)")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ============================================================================
# 6. EXCEPTIONS & AUDIT MODELS
# ============================================================================

class BaselineException(BaseModel):
    """
    Auditable exception record (e.g. maintenance window, approved travel, sanctioned pen-test).
    """
    model_config = ConfigDict(extra="ignore")

    id: str = Field(description="Exception UUID")
    entity_type: BaselineEntityType
    entity_id: str
    metric_type: Optional[BaselineMetricType] = None
    reason: str
    approved_by: str
    valid_from: datetime
    valid_until: Optional[datetime] = None
    is_active: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class BaselineAuditRecord(BaseModel):
    """
    Audit log entry for any baseline state change (freeze, unfreeze, relearn, exception).
    """
    model_config = ConfigDict(extra="ignore")

    id: str
    baseline_id: str
    action: str  # FREEZE, UNFREEZE, RELEARN, EXCEPTION_ADDED, EXCEPTION_REMOVED, RECALCULATE
    actor: str
    reason: str
    details: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ============================================================================
# 7. EVALUATION REQUEST / RESPONSE SCHEMAS
# ============================================================================

class BaselineEvaluationRequest(BaseModel):
    entity_type: BaselineEntityType
    entity_id: str
    metric_type: BaselineMetricType
    observed_value: Union[float, int, str]
    event_time: Optional[datetime] = None
    context: Dict[str, Any] = Field(default_factory=dict)


class BaselineEvaluationResponse(BaseModel):
    is_anomalous: bool
    deviation: Optional[BehavioralDeviation] = None
    baseline_quality: BaselineQuality
    baseline_confidence: float
    explanation: str
