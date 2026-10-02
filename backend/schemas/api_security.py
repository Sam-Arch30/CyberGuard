"""
API Abuse Security Schemas.
Pydantic V2 models defining normalized API events, baseline profiles,
detection findings, configuration parameters, and API security analysis responses.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, ConfigDict

from backend.schemas.unified import SeverityEnum


# ============================================================================
# CANONICAL API SECURITY ENUMS
# ============================================================================

class HTTPMethodEnum(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"
    CONNECT = "CONNECT"
    TRACE = "TRACE"
    OTHER = "OTHER"


class APIEventTypeEnum(str, Enum):
    REQUEST = "REQUEST"
    RESPONSE = "RESPONSE"
    API_CALL = "API_CALL"
    AUTH_FAILURE = "AUTH_FAILURE"
    AUTH_SUCCESS = "AUTH_SUCCESS"
    ADMIN_ACTION = "ADMIN_ACTION"
    OTHER = "OTHER"


class ClientTypeEnum(str, Enum):
    BROWSER = "BROWSER"
    MOBILE = "MOBILE"
    AUTOMATION = "AUTOMATION"
    BOT = "BOT"
    CLI = "CLI"
    SDK = "SDK"
    UNKNOWN = "UNKNOWN"


class APICategoryEnum(str, Enum):
    RATE_ANOMALY = "RATE_ANOMALY"
    BURST_ANOMALY = "BURST_ANOMALY"
    ENUMERATION = "ENUMERATION"
    AUTHENTICATION_ANOMALY = "AUTHENTICATION_ANOMALY"
    AUTHORIZATION_ANOMALY = "AUTHORIZATION_ANOMALY"
    MISSING_ENDPOINT_ANOMALY = "MISSING_ENDPOINT_ANOMALY"
    METHOD_ANOMALY = "METHOD_ANOMALY"
    SENSITIVE_ENDPOINT = "SENSITIVE_ENDPOINT"
    SESSION_ANOMALY = "SESSION_ANOMALY"
    DATA_VOLUME_ANOMALY = "DATA_VOLUME_ANOMALY"
    SCRAPING_ANOMALY = "SCRAPING_ANOMALY"
    PERIODICITY_ANOMALY = "PERIODICITY_ANOMALY"
    COMPOSITE_ABUSE = "COMPOSITE_ABUSE"


# ============================================================================
# NORMALIZED API EVENT
# ============================================================================

class NormalizedAPIEvent(BaseModel):
    """
    Canonical representation of a single normalized API telemetry event.
    Operates strictly on authorized telemetry with secret redaction and token fingerprinting.
    """
    model_config = ConfigDict(extra="ignore")

    id: str = Field(description="Unique identifier for this API event")
    timestamp: datetime = Field(description="Normalized UTC event occurrence timestamp")
    ingested_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Ingestion timestamp")
    provider: str = Field(default="generic", description="Originating telemetry source or log adapter name")
    event_type: APIEventTypeEnum = Field(default=APIEventTypeEnum.REQUEST, description="API event type category")
    service: str = Field(default="api_service", description="Target API service name or application identifier")
    application: Optional[str] = Field(default=None, description="Client application or subsystem name")
    source_ip: str = Field(description="Client source IPv4 or IPv6 address")
    source_port: Optional[int] = Field(default=None, description="Client TCP port")
    account_id: Optional[str] = Field(default=None, description="Associated account identifier or username")
    user_id: Optional[str] = Field(default=None, description="Associated user identity")
    session_id: Optional[str] = Field(default=None, description="Client session identifier")
    device_id: Optional[str] = Field(default=None, description="Client device identifier if present")
    token_fingerprint: Optional[str] = Field(default=None, description="Cryptographic HMAC-SHA256 fingerprint of authentication token (never raw secret)")
    api_key_id: Optional[str] = Field(default=None, description="Non-secret API key identifier if provided")
    is_service_account: bool = Field(default=False, description="Flag indicating service account or machine-to-machine identity")
    method: HTTPMethodEnum = Field(default=HTTPMethodEnum.GET, description="Normalized HTTP method")
    raw_method: str = Field(default="GET", description="Original raw HTTP method string")
    endpoint: str = Field(description="Requested API URI path (e.g. /api/v1/users/1001)")
    route_template: Optional[str] = Field(default=None, description="Normalized conservative route template (e.g. /api/v1/users/{id})")
    query_metadata: Dict[str, Any] = Field(default_factory=dict, description="Sanitized query parameter metadata (secrets redacted)")
    status_code: int = Field(default=200, description="HTTP response status code")
    request_bytes: Optional[int] = Field(default=None, description="Request payload size in bytes")
    response_bytes: Optional[int] = Field(default=None, description="Response payload size in bytes")
    duration_ms: Optional[float] = Field(default=None, description="Request duration / execution latency in milliseconds")
    authentication_status: Optional[str] = Field(default=None, description="Authentication outcome (SUCCESS, FAILURE, MISSING, EXPIRED)")
    authorization_status: Optional[str] = Field(default=None, description="Authorization outcome (ALLOWED, DENIED, INSUFFICIENT_SCOPE)")
    resource_type: Optional[str] = Field(default=None, description="Inferred or declared resource type (e.g. users, orders, export)")
    resource_id_hash: Optional[str] = Field(default=None, description="Safe hash slice of resource identifier for enumeration tracking")
    user_agent: Optional[str] = Field(default=None, description="Sanitized client User-Agent string")
    client_type: ClientTypeEnum = Field(default=ClientTypeEnum.UNKNOWN, description="Inferred client platform or automation category")
    raw_artifact_id: Optional[str] = Field(default=None, description="Parent stored artifact reference")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Sanitized auxiliary metadata")


# ============================================================================
# METRICS & BASELINE PROFILES
# ============================================================================

class AccountAPIBaselineProfile(BaseModel):
    """
    Lightweight baseline profile of observed API request patterns for an account or client identity.
    """
    account_id: str
    is_service_account: bool = False
    total_requests_observed: int = 0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    known_endpoints: List[str] = Field(default_factory=list)
    known_methods: List[str] = Field(default_factory=list)
    known_source_ips: List[str] = Field(default_factory=list)
    known_user_agents: List[str] = Field(default_factory=list)
    total_response_bytes: int = 0


# ============================================================================
# FINDINGS & CONFIGURATION SCHEMAS
# ============================================================================

class APIFindingEvidenceItem(BaseModel):
    key: str
    value: str
    source: str
    confidence: float = 1.0
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class APIFindingItem(BaseModel):
    finding_type: str
    title: str
    description: str
    severity: SeverityEnum
    confidence: float = 1.0
    risk_contribution: float = 0.0
    method: str = "DETERMINISTIC"
    rule_id: Optional[str] = None
    rule_version: str = "1.0.0"
    category: APICategoryEnum
    target_account: Optional[str] = None
    target_session: Optional[str] = None
    target_source_ip: Optional[str] = None
    target_endpoint: Optional[str] = None
    evidence_items: List[APIFindingEvidenceItem] = Field(default_factory=list)
    mitre_attack_ids: List[str] = Field(default_factory=list)
    limitation: Optional[str] = Field(
        default=None,
        description="Explicit limitation or false-positive boundary explanation"
    )


class APIConfigResponse(BaseModel):
    version: str = "1.0.0"
    rate_window_seconds: int = 60
    rate_threshold_human: int = 60
    rate_threshold_service: int = 300
    burst_window_seconds: int = 10
    burst_threshold: int = 30
    endpoint_enum_window_seconds: int = 180
    endpoint_enum_distinct_threshold: int = 12
    resource_enum_window_seconds: int = 180
    resource_enum_distinct_threshold: int = 15
    auth_failure_threshold: int = 5
    auth_failure_window_seconds: int = 300
    authz_failure_threshold: int = 5
    authz_failure_window_seconds: int = 300
    missing_endpoint_threshold: int = 10
    missing_endpoint_window_seconds: int = 120
    high_response_volume_bytes: int = 15 * 1024 * 1024  # 15 MB
    bulk_export_min_bytes: int = 2 * 1024 * 1024  # 2 MB
    scraping_min_requests: int = 25
    scraping_min_resources: int = 20
    scraping_max_duration_seconds: int = 120
    rapid_source_change_window_seconds: int = 600  # 10 minutes
    min_history_events_baseline: int = 5
    periodicity_min_observations: int = 5
    periodicity_max_cv: float = 0.15
    sensitive_routes: List[str] = Field(default_factory=lambda: [
        "/admin", "/api/admin", "/api/v1/admin",
        "/export", "/api/export", "/api/v1/export", "/api/reports/export",
        "/secrets", "/api/secrets", "/keys", "/api/keys",
        "/billing", "/api/billing", "/payments", "/api/payments",
        "/tokens", "/api/tokens", "/oauth/token"
    ])
    supported_adapters: List[str] = Field(default_factory=lambda: [
        "generic_json", "generic_csv", "gateway_json"
    ])


class APISecurityAnalysisResponse(BaseModel):
    analysis_run_id: str
    artifact_id: Optional[str] = None
    events_analyzed_count: int
    accounts_observed_count: int
    sessions_observed_count: int
    unique_endpoints_count: int
    unique_source_ips_count: int
    total_request_bytes: int = 0
    total_response_bytes: int = 0
    overall_risk_score: float = Field(ge=0.0, le=100.0)
    overall_severity: SeverityEnum
    confidence: float = Field(ge=0.0, le=1.0)
    classification: str
    findings: List[APIFindingItem] = Field(default_factory=list)
    corroborated_threat_events: List[Dict[str, Any]] = Field(default_factory=list)
    account_profiles: Dict[str, AccountAPIBaselineProfile] = Field(default_factory=dict)
    api_abuse_suspected: bool = False
    possible_exfiltration_detected: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
