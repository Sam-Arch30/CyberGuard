"""
Authentication and Account-Takeover (ATO) Security Schemas.
Pydantic V2 models defining canonical event normalization, security findings,
baseline profiles, and analysis payloads.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, ConfigDict

from backend.schemas.unified import SeverityEnum


# ============================================================================
# CANONICAL AUTHENTICATION ENUMS
# ============================================================================

class AuthenticationResultEnum(str, Enum):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    CHALLENGE = "CHALLENGE"
    MFA_REQUIRED = "MFA_REQUIRED"
    MFA_SUCCESS = "MFA_SUCCESS"
    MFA_FAILURE = "MFA_FAILURE"
    LOCKED = "LOCKED"
    DENIED = "DENIED"
    UNKNOWN = "UNKNOWN"


class AuthMethodEnum(str, Enum):
    PASSWORD = "PASSWORD"
    TOKEN = "TOKEN"
    SSO = "SSO"
    CERTIFICATE = "CERTIFICATE"
    API_KEY = "API_KEY"
    BIOMETRIC = "BIOMETRIC"
    OAUTH = "OAUTH"
    OTHER = "OTHER"
    UNKNOWN = "UNKNOWN"


class MFAMethodEnum(str, Enum):
    TOTP = "TOTP"
    PUSH = "PUSH"
    SMS = "SMS"
    EMAIL = "EMAIL"
    FIDO2 = "FIDO2"
    HARDWARE_KEY = "HARDWARE_KEY"
    NONE = "NONE"
    OTHER = "OTHER"
    UNKNOWN = "UNKNOWN"


class FailureReasonEnum(str, Enum):
    INVALID_CREDENTIALS = "INVALID_CREDENTIALS"
    USER_NOT_FOUND = "USER_NOT_FOUND"
    ACCOUNT_LOCKED = "ACCOUNT_LOCKED"
    ACCOUNT_DISABLED = "ACCOUNT_DISABLED"
    PASSWORD_EXPIRED = "PASSWORD_EXPIRED"
    MFA_REJECTED = "MFA_REJECTED"
    MFA_TIMEOUT = "MFA_TIMEOUT"
    IP_BLOCKED = "IP_BLOCKED"
    LOCATION_RESTRICTED = "LOCATION_RESTRICTED"
    DEVICE_UNTRUSTED = "DEVICE_UNTRUSTED"
    OTHER = "OTHER"
    UNKNOWN = "UNKNOWN"


class ATOCategoryEnum(str, Enum):
    CREDENTIAL_ATTACK = "CREDENTIAL_ATTACK"
    SOURCE_ANOMALY = "SOURCE_ANOMALY"
    DEVICE_ANOMALY = "DEVICE_ANOMALY"
    LOCATION_ANOMALY = "LOCATION_ANOMALY"
    MFA_ANOMALY = "MFA_ANOMALY"
    SESSION_ANOMALY = "SESSION_ANOMALY"
    TEMPORAL_ANOMALY = "TEMPORAL_ANOMALY"


class BaselineStatusEnum(str, Enum):
    ESTABLISHED = "ESTABLISHED"
    INSUFFICIENT_HISTORY = "INSUFFICIENT_HISTORY"
    NEW_ENTITY = "NEW_ENTITY"


# ============================================================================
# NORMALIZED AUTHENTICATION EVENT
# ============================================================================

class NormalizedAuthEvent(BaseModel):
    """
    Canonical representation of a single normalized authentication event.
    Raw fields and secrets are sanitized and redacted.
    """
    model_config = ConfigDict(extra="ignore")

    id: str = Field(description="Unique identifier for this authentication event")
    timestamp: datetime = Field(description="Normalized UTC event occurrence timestamp")
    account_id: str = Field(description="Normalized lowercase account or user principal name")
    username: Optional[str] = Field(default=None, description="Reported username or display name")
    user_id: Optional[str] = Field(default=None, description="Unique directory/IDP identifier if provided")
    source_ip: str = Field(description="Client source IPv4 or IPv6 address")
    source_port: Optional[int] = Field(default=None, description="Optional network source port")
    destination_service: Optional[str] = Field(default=None, description="Target service or application (e.g. portal, vpn, m365)")
    device_id: Optional[str] = Field(default=None, description="Unique device identifier (MDM/GUID) if provided")
    device_name: Optional[str] = Field(default=None, description="Reported device hostname or friendly name")
    user_agent: Optional[str] = Field(default=None, description="Sanitized client user-agent string")
    client_platform: Optional[str] = Field(default=None, description="Normalized OS platform (Windows, macOS, Linux, iOS, Android, etc.)")
    client_browser: Optional[str] = Field(default=None, description="Normalized browser family (Chrome, Edge, Firefox, Safari, etc.)")
    session_id: Optional[str] = Field(default=None, description="Session identifier or session fingerprint")
    authentication_method: AuthMethodEnum = Field(default=AuthMethodEnum.UNKNOWN, description="Authentication mechanism")
    mfa_method: MFAMethodEnum = Field(default=MFAMethodEnum.NONE, description="MFA factor type")
    result: AuthenticationResultEnum = Field(default=AuthenticationResultEnum.UNKNOWN, description="Normalized authentication outcome")
    failure_reason: Optional[FailureReasonEnum] = Field(default=None, description="Categorized failure reason if applicable")
    failure_detail: Optional[str] = Field(default=None, description="Sanitized diagnostic message from upstream provider")
    location_city: Optional[str] = Field(default=None, description="Approximate city from telemetry or IP enrichment")
    location_country: Optional[str] = Field(default=None, description="Country name")
    location_country_code: Optional[str] = Field(default=None, description="Two-letter ISO country code")
    latitude: Optional[float] = Field(default=None, description="Approximate latitude")
    longitude: Optional[float] = Field(default=None, description="Approximate longitude")
    isp: Optional[str] = Field(default=None, description="Internet Service Provider or cloud host")
    asn: Optional[str] = Field(default=None, description="Autonomous System Number")
    is_vpn_or_proxy: Optional[bool] = Field(default=None, description="Indicates if IP is classified as VPN/proxy/hosting")
    provider: str = Field(default="generic", description="Originating log adapter or identity provider name")
    raw_artifact_id: Optional[str] = Field(default=None, description="Reference to parent stored artifact")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Sanitized auxiliary metadata without secrets")


class AuthEventBatch(BaseModel):
    """Container for batch authentication ingestion."""
    events: List[Dict[str, Any]] = Field(description="Raw or semi-structured event dictionaries")
    provider_hint: Optional[str] = Field(default=None, description="Optional adapter hint (okta, entra_id, google, linux, generic)")
    context: Dict[str, Any] = Field(default_factory=dict, description="Contextual investigation or batch metadata")


# ============================================================================
# ACCOUNT HISTORICAL PROFILE
# ============================================================================

class AccountSecurityProfile(BaseModel):
    """
    Lightweight historical baseline profile for an account.
    """
    account_id: str
    baseline_status: BaselineStatusEnum
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    total_successful_logins: int = 0
    total_failed_logins: int = 0
    known_source_ips: List[str] = Field(default_factory=list)
    known_devices: List[str] = Field(default_factory=list)
    known_countries: List[str] = Field(default_factory=list)
    known_client_profiles: List[str] = Field(default_factory=list)
    typical_login_hours: List[int] = Field(default_factory=list)
    mfa_always_used: bool = False
    last_successful_login_location: Optional[Dict[str, Any]] = None
    last_successful_login_timestamp: Optional[datetime] = None


# ============================================================================
# FINDINGS & EVIDENCE SCHEMAS
# ============================================================================

class FindingEvidenceItem(BaseModel):
    key: str
    value: str
    source: str
    confidence: float = 1.0
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AuthenticationFindingItem(BaseModel):
    finding_type: str
    title: str
    description: str
    severity: SeverityEnum
    confidence: float = 1.0
    risk_contribution: float = 0.0
    method: str = "DETERMINISTIC"
    rule_id: Optional[str] = None
    category: ATOCategoryEnum
    target_account: Optional[str] = None
    evidence_items: List[FindingEvidenceItem] = Field(default_factory=list)
    mitre_attack_ids: List[str] = Field(default_factory=list)


# ============================================================================
# CONFIGURATION & RESPONSE SCHEMAS
# ============================================================================

class AuthConfigResponse(BaseModel):
    version: str = "1.0.0"
    brute_force_failure_threshold: int = 5
    brute_force_window_seconds: int = 900
    password_spray_account_threshold: int = 5
    password_spray_max_per_account: int = 3
    password_spray_window_seconds: int = 1800
    credential_stuffing_account_threshold: int = 10
    credential_stuffing_window_seconds: int = 3600
    success_after_failures_min_failures: int = 3
    success_after_failures_window_seconds: int = 1800
    min_history_events_device: int = 5
    min_history_events_ip: int = 5
    min_history_events_temporal: int = 10
    impossible_travel_speed_kmh: float = 900.0
    impossible_travel_min_distance_km: float = 300.0
    mfa_failure_threshold: int = 3
    ato_min_categories_threshold: int = 2
    supported_adapters: List[str] = Field(default_factory=lambda: [
        "generic", "okta", "entra_id", "google_workspace", "linux_auth"
    ])


class AuthSecurityAnalysisResponse(BaseModel):
    analysis_run_id: str
    artifact_id: Optional[str] = None
    events_analyzed_count: int
    accounts_targeted_count: int
    unique_source_ips_count: int
    overall_risk_score: float = Field(ge=0.0, le=100.0)
    overall_severity: SeverityEnum
    confidence: float = Field(ge=0.0, le=1.0)
    classification: str
    findings: List[AuthenticationFindingItem] = Field(default_factory=list)
    corroborated_threat_events: List[Dict[str, Any]] = Field(default_factory=list)
    account_profiles: Dict[str, AccountSecurityProfile] = Field(default_factory=dict)
    ato_suspected: bool = False
    ato_summary: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
