"""
Pydantic v2 schemas for Section 31: Endpoint Agent Architecture.
Defines contracts for enrollment, machine authentication, telemetry ingestion,
configuration management, health heartbeats, and administrative controls.
"""

from datetime import datetime
from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field, ConfigDict


# ============================================================================
# ENUMS
# ============================================================================

class AgentStatusEnum(str, Enum):
    ENROLLING = "ENROLLING"
    ACTIVE = "ACTIVE"
    DEGRADED = "DEGRADED"
    OFFLINE = "OFFLINE"
    REVOKED = "REVOKED"
    DISABLED = "DISABLED"


class DeviceStatusEnum(str, Enum):
    ACTIVE = "ACTIVE"
    OFFLINE = "OFFLINE"
    DECOMMISSIONED = "DECOMMISSIONED"


class EnrollmentStateEnum(str, Enum):
    ENROLLED = "ENROLLED"
    PENDING_VERIFICATION = "PENDING_VERIFICATION"
    REVOKED = "REVOKED"


class ConfigurationStatusEnum(str, Enum):
    DRAFT = "DRAFT"
    VALIDATING = "VALIDATING"
    ACTIVE = "ACTIVE"
    SUPERSEDED = "SUPERSEDED"
    REVOKED = "REVOKED"


class CollectorCapabilityStateEnum(str, Enum):
    AVAILABLE = "AVAILABLE"
    UNAVAILABLE = "UNAVAILABLE"
    DISABLED = "DISABLED"
    REQUIRES_PERMISSION = "REQUIRES_PERMISSION"
    REQUIRES_CONFIGURATION = "REQUIRES_CONFIGURATION"
    DEGRADED = "DEGRADED"
    ERROR = "ERROR"


class EndpointEventTypeEnum(str, Enum):
    PROCESS = "PROCESS"
    NETWORK = "NETWORK"
    DNS = "DNS"
    AUTHENTICATION = "AUTHENTICATION"
    SYSTEM = "SYSTEM"
    SYSTEM_SECURITY = "SYSTEM_SECURITY"
    FILE_METADATA = "FILE_METADATA"
    FILE = "FILE"
    DEVICE_HEALTH = "DEVICE_HEALTH"
    SECURITY_AUDIT = "SECURITY_AUDIT"


class EventPriorityEnum(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    NORMAL = "NORMAL"
    LOW = "LOW"


class AgentHealthStateEnum(str, Enum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    OFFLINE = "OFFLINE"
    UNAUTHORIZED = "UNAUTHORIZED"
    MISCONFIGURED = "MISCONFIGURED"
    BUFFER_PRESSURE = "BUFFER_PRESSURE"
    COLLECTOR_FAILURE = "COLLECTOR_FAILURE"


class CredentialTypeEnum(str, Enum):
    HMAC_KEY = "HMAC_KEY"
    BEARER_TOKEN = "BEARER_TOKEN"
    MTLS_CERT = "MTLS_CERT"


class BufferOverflowPolicyEnum(str, Enum):
    DROP_OLDEST = "DROP_OLDEST"
    DROP_LOW_PRIORITY = "DROP_LOW_PRIORITY"
    BLOCK_COLLECTOR = "BLOCK_COLLECTOR"


# ============================================================================
# ENROLLMENT SCHEMAS
# ============================================================================

class CreateEnrollmentTokenRequest(BaseModel):
    description: Optional[str] = Field(None, description="Administrative label or device assignment target")
    expires_in_minutes: int = Field(60, ge=1, le=1440, description="Token validity window (default 60 mins)")
    max_uses: int = Field(1, ge=1, le=100, description="Number of agent enrollments permitted with token (default 1)")
    workspace_id: str = Field("default", description="Tenant workspace to bind enrollment")


class EnrollmentTokenResponse(BaseModel):
    token_id: str
    token_prefix: str
    raw_token: str = Field(..., description="Secret one-time enrollment token; only revealed upon creation")
    workspace_id: str
    description: Optional[str] = None
    expires_at: datetime
    max_uses: int
    created_at: datetime


class AgentEnrollmentRequest(BaseModel):
    enrollment_token: str = Field(..., description="Short-lived, single-use enrollment token")
    device_uid: str = Field(..., description="Stable hardware/OS machine identifier (machine-id or system UUID)")
    hostname: str = Field(..., description="Current endpoint hostname")
    platform: str = Field(..., description="Host OS platform (macos, windows, linux)")
    os_version: Optional[str] = None
    architecture: Optional[str] = None
    manufacturer: Optional[str] = None
    model: Optional[str] = None
    agent_version: str = Field("1.0.0", description="Installed agent runtime semantic version")
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AgentEnrollmentResponse(BaseModel):
    agent_id: str = Field(..., description="Assigned persistent agent identifier (e.g. AGT-XXXXXXXX)")
    device_id: str = Field(..., description="Associated stable hardware device identifier")
    workspace_id: str
    key_id: str = Field(..., description="Assigned machine credential key identifier")
    credential_secret: str = Field(..., description="Machine HMAC secret / bearer token established for connection auth")
    credential_type: CredentialTypeEnum
    configuration_version: str
    server_endpoint: str
    heartbeat_interval_seconds: float
    enrolled_at: datetime


# ============================================================================
# CREDENTIAL ROTATION SCHEMAS
# ============================================================================

class CredentialRotateRequest(BaseModel):
    current_key_id: str = Field(..., description="Existing active machine key ID")


class CredentialRotateResponse(BaseModel):
    agent_id: str
    key_id: str
    new_credential_secret: str
    credential_type: CredentialTypeEnum
    expires_at: Optional[datetime] = None
    rotated_at: datetime


# ============================================================================
# TELEMETRY EVENT INGESTION SCHEMAS
# ============================================================================

class RawEndpointTelemetryEvent(BaseModel):
    event_id: str = Field(..., description="Unique client event UUID")
    sequence_number: int = Field(..., ge=0, description="Monotonically increasing sequence number per agent session")
    event_type: EndpointEventTypeEnum
    event_time: datetime = Field(..., description="Local timestamp when host event occurred")
    collector_id: str = Field(..., description="Collector adapter identifier (e.g. process_collector)")
    collector_version: str = "1.0.0"
    configuration_version: str = "1.0.0"
    agent_version: str = "1.0.0"
    schema_version: str = "1.0.0"
    priority: EventPriorityEnum = EventPriorityEnum.NORMAL
    payload: Dict[str, Any] = Field(..., description="Structured, redacted event telemetry")
    integrity_hash: Optional[str] = None


class BatchTelemetryIngestRequest(BaseModel):
    agent_id: str
    batch_id: str = Field(..., description="Client batch transmission identifier")
    events: List[RawEndpointTelemetryEvent] = Field(..., max_length=200)
    timestamp: datetime = Field(..., description="Batch dispatch timestamp on client")


class BatchTelemetryIngestResponse(BaseModel):
    batch_id: str
    accepted_count: int
    rejected_count: int
    duplicate_count: int
    accepted_event_ids: List[str]
    rejected_event_ids: Dict[str, str] = Field(default_factory=dict, description="Rejected event IDs mapped to error reason")
    server_time: datetime
    clock_offset_ms: float = Field(0.0, description="Computed server vs client clock skew in milliseconds")


# ============================================================================
# AGENT HEARTBEAT SCHEMAS
# ============================================================================

class AgentHeartbeatRequest(BaseModel):
    agent_id: str
    health_state: AgentHealthStateEnum
    collector_states: Dict[str, str] = Field(default_factory=dict, description="Status per collector (e.g. {'process': 'HEALTHY'})")
    buffer_events_count: int = Field(0, ge=0)
    buffer_bytes: int = Field(0, ge=0)
    cpu_usage_percent: float = Field(0.0, ge=0.0, le=100.0)
    memory_usage_mb: float = Field(0.0, ge=0.0)
    last_event_time: Optional[datetime] = None
    agent_version: str = "1.0.0"
    configuration_version: str = "1.0.0"


class AgentHeartbeatResponse(BaseModel):
    status: str = "ACK"
    health_state: AgentHealthStateEnum
    configuration_version_active: str
    reconfigure_required: bool = False
    server_time: datetime


# ============================================================================
# CONFIGURATION SCHEMAS
# ============================================================================

class AgentConfigurationResponse(BaseModel):
    configuration_id: str
    version: str
    status: ConfigurationStatusEnum
    collection_policy: Dict[str, Any] = Field(default_factory=dict)
    sampling_policy: Dict[str, Any] = Field(default_factory=dict)
    privacy_policy: Dict[str, Any] = Field(default_factory=dict)
    batch_size: int = 50
    flush_interval_seconds: float = 10.0
    max_buffer_size_events: int = 5000
    max_buffer_size_bytes: int = 20971520
    server_endpoint: str = "/api/v1/endpoint"
    enabled_collectors: List[str] = Field(default_factory=list)
    signature: Optional[str] = None
    created_at: datetime


# ============================================================================
# ADMINISTRATIVE SUMMARY SCHEMAS
# ============================================================================

class AgentSummaryResponse(BaseModel):
    id: str
    agent_id: str
    device_id: str
    workspace_id: str
    hostname: str
    platform: str
    platform_version: Optional[str] = None
    architecture: Optional[str] = None
    agent_version: str
    status: AgentStatusEnum
    enrollment_state: EnrollmentStateEnum
    configuration_version: str
    last_seen_at: datetime
    last_heartbeat_at: Optional[datetime] = None
    clock_offset_ms: float = 0.0
    enrolled_at: datetime
    revoked_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class DeviceSummaryResponse(BaseModel):
    id: str
    workspace_id: str
    device_uid: str
    hostname: str
    platform: str
    os_version: Optional[str] = None
    architecture: Optional[str] = None
    status: DeviceStatusEnum
    agent_count: int = 0
    first_seen_at: datetime
    last_seen_at: datetime

    model_config = ConfigDict(from_attributes=True)
