"""
Section 28: Response Recommendation Engine Pydantic Schemas.
Controlled action taxonomies, lifecycle enums, and request/response models.
"""

from enum import Enum
from typing import Dict, Any, List, Optional
from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict


# ============================================================================
# CONTROLLED TAXONOMY & ENUMS
# ============================================================================

class ActionCategoryEnum(str, Enum):
    IMMEDIATE = "IMMEDIATE"
    CONTAINMENT = "CONTAINMENT"
    INVESTIGATION = "INVESTIGATION"
    EVIDENCE_PRESERVATION = "EVIDENCE_PRESERVATION"
    IDENTITY_SECURITY = "IDENTITY_SECURITY"
    NETWORK_SECURITY = "NETWORK_SECURITY"
    ENDPOINT_SECURITY = "ENDPOINT_SECURITY"
    COMMUNICATION = "COMMUNICATION"
    RECOVERY = "RECOVERY"
    FOLLOW_UP = "FOLLOW_UP"


class ActionTypeEnum(str, Enum):
    # Investigation Actions
    REVIEW_EVIDENCE = "REVIEW_EVIDENCE"
    REVIEW_HEADERS = "REVIEW_HEADERS"
    INSPECT_URL = "INSPECT_URL"
    INSPECT_ATTACHMENT = "INSPECT_ATTACHMENT"
    REVIEW_AUTHENTICATION = "REVIEW_AUTHENTICATION"
    REVIEW_ENDPOINT_TELEMETRY = "REVIEW_ENDPOINT_TELEMETRY"
    REVIEW_NETWORK_ACTIVITY = "REVIEW_NETWORK_ACTIVITY"
    EXPAND_ATTACK_PATH = "EXPAND_ATTACK_PATH"
    CORRELATE_RELATED_EVENTS = "CORRELATE_RELATED_EVENTS"

    # Containment Actions
    QUARANTINE_FILE = "QUARANTINE_FILE"
    ISOLATE_DEVICE = "ISOLATE_DEVICE"
    BLOCK_URL = "BLOCK_URL"
    BLOCK_DOMAIN = "BLOCK_DOMAIN"
    BLOCK_IP = "BLOCK_IP"
    DISABLE_ACCOUNT = "DISABLE_ACCOUNT"
    REVOKE_SESSION = "REVOKE_SESSION"
    REVOKE_CREDENTIAL = "REVOKE_CREDENTIAL"

    # Credential / Identity Actions
    FORCE_PASSWORD_RESET = "FORCE_PASSWORD_RESET"
    REQUIRE_MFA_REAUTHENTICATION = "REQUIRE_MFA_REAUTHENTICATION"
    REVIEW_MFA_SETTINGS = "REVIEW_MFA_SETTINGS"
    REVIEW_PRIVILEGED_ACCESS = "REVIEW_PRIVILEGED_ACCESS"

    # Communication Actions
    NOTIFY_USER = "NOTIFY_USER"
    NOTIFY_SECURITY_TEAM = "NOTIFY_SECURITY_TEAM"
    ESCALATE_INCIDENT = "ESCALATE_INCIDENT"
    NOTIFY_SYSTEM_OWNER = "NOTIFY_SYSTEM_OWNER"

    # Recovery Actions
    RESTORE_FROM_KNOWN_GOOD_STATE = "RESTORE_FROM_KNOWN_GOOD_STATE"
    REMOVE_MALICIOUS_ARTIFACT = "REMOVE_MALICIOUS_ARTIFACT"
    REVERSE_UNAUTHORIZED_CHANGE = "REVERSE_UNAUTHORIZED_CHANGE"

    # Evidence Preservation Actions
    PRESERVE_ARTIFACT = "PRESERVE_ARTIFACT"
    PRESERVE_LOGS = "PRESERVE_LOGS"
    PRESERVE_NETWORK_TELEMETRY = "PRESERVE_NETWORK_TELEMETRY"
    PRESERVE_EMAIL = "PRESERVE_EMAIL"
    PRESERVE_FORENSIC_SNAPSHOT = "PRESERVE_FORENSIC_SNAPSHOT"


class RecommendationPriorityEnum(str, Enum):
    P0 = "P0"  # Immediate containment consideration
    P1 = "P1"  # Urgent investigation/response
    P2 = "P2"  # High-priority analyst action
    P3 = "P3"  # Normal investigation
    P4 = "P4"  # Informational/follow-up


class RecommendationUrgencyEnum(str, Enum):
    IMMEDIATE = "IMMEDIATE"
    URGENT = "URGENT"
    SOON = "SOON"
    NORMAL = "NORMAL"
    DEFERRED = "DEFERRED"


class ApplicabilityEnum(str, Enum):
    APPLICABLE = "APPLICABLE"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNKNOWN = "UNKNOWN"
    NOT_READY = "NOT_READY"


class ReversibilityEnum(str, Enum):
    REVERSIBLE = "REVERSIBLE"
    PARTIALLY_REVERSIBLE = "PARTIALLY_REVERSIBLE"
    IRREVERSIBLE = "IRREVERSIBLE"
    UNKNOWN = "UNKNOWN"


class OperationalImpactEnum(str, Enum):
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"


class SafetyClassEnum(str, Enum):
    INFORMATIONAL = "INFORMATIONAL"
    LOW_IMPACT = "LOW_IMPACT"
    REVERSIBLE = "REVERSIBLE"
    CONTAINMENT = "CONTAINMENT"
    HIGH_IMPACT = "HIGH_IMPACT"
    DESTRUCTIVE = "DESTRUCTIVE"


class ExecutionModeEnum(str, Enum):
    MANUAL = "MANUAL"
    AUTOMATED_VIA_PLAYBOOK = "AUTOMATED_VIA_PLAYBOOK"
    HUMAN_IN_THE_LOOP = "HUMAN_IN_THE_LOOP"


class RecommendationStatusEnum(str, Enum):
    GENERATED = "GENERATED"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    SUPERSEDED = "SUPERSEDED"
    DEFERRED = "DEFERRED"


class CapabilityStateEnum(str, Enum):
    AVAILABLE = "AVAILABLE"
    UNAVAILABLE = "UNAVAILABLE"
    UNKNOWN = "UNKNOWN"
    DISABLED = "DISABLED"
    REQUIRES_CONFIGURATION = "REQUIRES_CONFIGURATION"


# ============================================================================
# STRUCTURED COMPONENTS
# ============================================================================

class AffectedEntity(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    entity_type: str = Field(..., description="ACCOUNT, DEVICE, URL, DOMAIN, IP, FILE, SESSION, API_KEY")
    identifier: str = Field(..., description="Target identity string (e.g., email, IP, hash, domain)")
    role: str = Field("TARGET", description="TARGET, SOURCE, INTERMEDIARY, RECIPIENT")
    evidence_ref: Optional[str] = Field(None, description="Linked Evidence or Finding ID")


class PrerequisiteItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    name: str
    description: str
    satisfied: bool = True
    remedy: Optional[str] = None


class ConflictItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    conflicting_recommendation_id: str
    conflicting_action_type: str
    tradeoff_explanation: str


# ============================================================================
# RESPONSE RECOMMENDATION SCHEMAS
# ============================================================================

class ResponseRecommendationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    workspace_id: str
    scope_type: str
    scope_id: str
    incident_id: Optional[str] = None
    threat_event_id: Optional[str] = None
    risk_assessment_id: Optional[str] = None
    explanation_id: Optional[str] = None

    action_type: ActionTypeEnum
    category: ActionCategoryEnum
    title: str
    description: str
    rationale: str

    priority: RecommendationPriorityEnum
    urgency: RecommendationUrgencyEnum
    expected_effect: str

    prerequisites: List[Dict[str, Any]] = Field(default_factory=list)
    affected_entities: List[Dict[str, Any]] = Field(default_factory=list)
    evidence_refs: List[str] = Field(default_factory=list)
    risk_refs: List[str] = Field(default_factory=list)
    attack_path_refs: List[str] = Field(default_factory=list)
    mitre_refs: List[str] = Field(default_factory=list)

    confidence: float
    confidence_level: str

    applicability: ApplicabilityEnum
    applicability_reason: str

    reversibility: ReversibilityEnum
    impact: OperationalImpactEnum

    approval_required: bool
    safety_class: SafetyClassEnum
    execution_mode: ExecutionModeEnum

    status: RecommendationStatusEnum
    status_reason: Optional[str] = None
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[datetime] = None

    recommendation_version: int
    superseded_by_id: Optional[str] = None

    depends_on: List[str] = Field(default_factory=list)
    conflicts_with: List[Dict[str, Any]] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    created_at: datetime
    updated_at: datetime
    expires_at: Optional[datetime] = None


class ResponseRecommendationSummary(BaseModel):
    id: str
    action_type: str
    title: str
    category: str
    priority: str
    urgency: str
    approval_required: bool
    status: str
    evidence_count: int


# ============================================================================
# CAPABILITY REGISTRY SCHEMAS
# ============================================================================

class ResponseCapabilityResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    workspace_id: str
    action_type: ActionTypeEnum
    provider: str
    environment: str
    enabled: bool
    reversible: bool
    approval_required: bool
    capability_state: CapabilityStateEnum
    state_reason: Optional[str] = None
    configuration: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime


class ResponseCapabilityCreate(BaseModel):
    action_type: ActionTypeEnum
    provider: str
    environment: str = "PRODUCTION"
    enabled: bool = True
    reversible: bool = True
    approval_required: bool = True
    capability_state: CapabilityStateEnum = CapabilityStateEnum.AVAILABLE
    state_reason: Optional[str] = None
    configuration: Dict[str, Any] = Field(default_factory=dict)


# ============================================================================
# REQUEST SCHEMAS
# ============================================================================

class RecommendationGenerateRequest(BaseModel):
    scope_type: str = "EVENT"
    scope_id: str
    workspace_id: str = "default"
    force_regenerate: bool = False


class RecommendationReviewRequest(BaseModel):
    reviewer_id: str = Field(..., description="Identifier of the reviewing human security analyst")
    disposition: RecommendationStatusEnum = Field(..., description="APPROVED, REJECTED, or DEFERRED")
    notes: str = Field(..., description="Audit justification for analyst disposition")


class ResponseWorkspaceOverview(BaseModel):
    workspace_id: str
    scope_type: str
    scope_id: str
    total_count: int
    by_priority: Dict[str, int]
    by_category: Dict[str, int]
    by_status: Dict[str, int]
    pending_approval_count: int
    recommendations: List[ResponseRecommendationResponse]
