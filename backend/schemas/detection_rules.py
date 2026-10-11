"""
Section 56: Detection Engineering & Rule Lifecycle Schemas & Controlled DSL.

Provides structured models for:
- Full rule lifecycle states (DRAFT, CANDIDATE, VALIDATING, PENDING_REVIEW, APPROVED, STAGED, ACTIVE, DISABLED, DEPRECATED, ARCHIVED, REJECTED)
- Controlled categories, data sources, and allowed operator registries
- Safe AST and human-readable translation (zero arbitrary code execution)
- Immutability diffing and historical backtesting schemas
- Hunt-to-rule and Investigation-to-rule handoff DTOs
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
import re
from typing import Any, Dict, List, Optional, Set, Union
from pydantic import BaseModel, ConfigDict, Field, field_validator

from backend.schemas.candidate_rules import (
    DslOperator,
    GeneralizationLevel,
    RuleLifecycleStatus,
    RuleScope,
    RuleSeverity,
    RuleType,
)


# ============================================================================
# 1. CONTROLLED TAXONOMIES & VOCABULARIES
# ============================================================================

class RuleCategory(str, Enum):
    EMAIL = "EMAIL"
    PHISHING = "PHISHING"
    URL = "URL"
    DOMAIN = "DOMAIN"
    ATTACHMENT = "ATTACHMENT"
    IDENTITY = "IDENTITY"
    AUTHENTICATION = "AUTHENTICATION"
    ENDPOINT = "ENDPOINT"
    NETWORK = "NETWORK"
    API = "API"
    BEHAVIORAL = "BEHAVIORAL"
    INFRASTRUCTURE = "INFRASTRUCTURE"
    CAMPAIGN = "CAMPAIGN"
    CORRELATION = "CORRELATION"
    ANOMALY = "ANOMALY"


class RuleDataSource(str, Enum):
    EMAIL_EVENT = "EMAIL_EVENT"
    NETWORK_EVENT = "NETWORK_EVENT"
    ENDPOINT_EVENT = "ENDPOINT_EVENT"
    AUTH_EVENT = "AUTH_EVENT"
    API_EVENT = "API_EVENT"
    INDICATOR = "INDICATOR"
    THREAT_INTELLIGENCE = "THREAT_INTELLIGENCE"
    WATCHLIST = "WATCHLIST"
    BEHAVIORAL_BASELINE = "BEHAVIORAL_BASELINE"
    NOVELTY_EVENT = "NOVELTY_EVENT"


class RuleProvenanceType(str, Enum):
    HUNT = "HUNT"
    INVESTIGATION = "INVESTIGATION"
    FINDING = "FINDING"
    THREAT_INTELLIGENCE = "THREAT_INTELLIGENCE"
    ANALYST_CREATED = "ANALYST_CREATED"
    SYSTEM_PROPOSED = "SYSTEM_PROPOSED"
    CAMPAIGN = "CAMPAIGN"
    WATCHLIST = "WATCHLIST"


class RuleCostClass(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    UNSUPPORTED = "UNSUPPORTED"


# ============================================================================
# Section 57: Detection Rule Management & Operational Control Enums & Models
# ============================================================================

class DeploymentStateEnum(str, Enum):
    DRAFT = "DRAFT"
    STAGING = "STAGING"
    PRODUCTION = "PRODUCTION"
    DISABLED = "DISABLED"


class OperationalHealthEnum(str, Enum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    FAILING = "FAILING"
    UNKNOWN = "UNKNOWN"


class DependencyTypeEnum(str, Enum):
    DATA_SOURCE = "DATA_SOURCE"
    ANALYZER = "ANALYZER"
    INTELLIGENCE = "INTELLIGENCE"
    BASELINE = "BASELINE"
    WATCHLIST = "WATCHLIST"


class DependencyHealthEnum(str, Enum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    FAILING = "FAILING"
    UNKNOWN = "UNKNOWN"


class MatchDispositionEnum(str, Enum):
    TRUE_POSITIVE = "TRUE_POSITIVE"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    BENIGN = "BENIGN"
    EXPECTED_ACTIVITY = "EXPECTED_ACTIVITY"
    NEEDS_REVIEW = "NEEDS_REVIEW"


class RuleDependency(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    name: str
    type: DependencyTypeEnum = DependencyTypeEnum.DATA_SOURCE
    required: bool = True
    health: DependencyHealthEnum = DependencyHealthEnum.HEALTHY
    details: Optional[str] = None



class RuleFieldType(str, Enum):
    STRING = "STRING"
    NUMBER = "NUMBER"
    BOOLEAN = "BOOLEAN"
    TIMESTAMP = "TIMESTAMP"
    IP = "IP"
    DOMAIN = "DOMAIN"
    HASH = "HASH"
    ENUM = "ENUM"


class RuleFieldDefinition(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    field: str
    field_type: RuleFieldType
    data_source: RuleDataSource
    display_name: str
    description: str
    allowed_operators: List[DslOperator]


# Centralized data source field registry allowlist
DATA_SOURCE_FIELD_REGISTRY: Dict[str, RuleFieldDefinition] = {
    # Email Events
    "sender_domain": RuleFieldDefinition(
        field="sender_domain",
        field_type=RuleFieldType.DOMAIN,
        data_source=RuleDataSource.EMAIL_EVENT,
        display_name="Sender Domain",
        description="Originating sender domain from SMTP envelope",
        allowed_operators=[
            DslOperator.EQUALS,
            DslOperator.NOT_EQUALS,
            DslOperator.CONTAINS,
            DslOperator.STARTS_WITH,
            DslOperator.ENDS_WITH,
            DslOperator.IN,
            DslOperator.NOT_IN,
            DslOperator.REGEX,
            DslOperator.LOOKALIKE,
        ],
    ),
    "has_attachments": RuleFieldDefinition(
        field="has_attachments",
        field_type=RuleFieldType.BOOLEAN,
        data_source=RuleDataSource.EMAIL_EVENT,
        display_name="Has Attachments",
        description="Whether email contains one or more attachments",
        allowed_operators=[DslOperator.EQUALS],
    ),
    "attachment_type": RuleFieldDefinition(
        field="attachment_type",
        field_type=RuleFieldType.STRING,
        data_source=RuleDataSource.EMAIL_EVENT,
        display_name="Attachment MIME Type",
        description="MIME type or extension of email attachment",
        allowed_operators=[
            DslOperator.EQUALS,
            DslOperator.NOT_EQUALS,
            DslOperator.CONTAINS,
            DslOperator.STARTS_WITH,
            DslOperator.ENDS_WITH,
            DslOperator.IN,
            DslOperator.NOT_IN,
        ],
    ),
    "sender_address": RuleFieldDefinition(
        field="sender_address",
        field_type=RuleFieldType.STRING,
        data_source=RuleDataSource.EMAIL_EVENT,
        display_name="Sender Email Address",
        description="Full email address of the sender",
        allowed_operators=[
            DslOperator.EQUALS,
            DslOperator.NOT_EQUALS,
            DslOperator.CONTAINS,
            DslOperator.ENDS_WITH,
            DslOperator.IN,
            DslOperator.NOT_IN,
        ],
    ),
    "subject": RuleFieldDefinition(
        field="subject",
        field_type=RuleFieldType.STRING,
        data_source=RuleDataSource.EMAIL_EVENT,
        display_name="Email Subject",
        description="Subject line of analyzed email message",
        allowed_operators=[
            DslOperator.EQUALS,
            DslOperator.CONTAINS,
            DslOperator.STARTS_WITH,
            DslOperator.ENDS_WITH,
            DslOperator.REGEX,
        ],
    ),
    "url_count": RuleFieldDefinition(
        field="url_count",
        field_type=RuleFieldType.NUMBER,
        data_source=RuleDataSource.EMAIL_EVENT,
        display_name="URL Count",
        description="Number of distinct URLs found in email message body",
        allowed_operators=[
            DslOperator.EQUALS,
            DslOperator.NOT_EQUALS,
            DslOperator.GREATER_THAN,
            DslOperator.GREATER_THAN_OR_EQUAL,
            DslOperator.LESS_THAN,
            DslOperator.LESS_THAN_OR_EQUAL,
        ],
    ),
    "attachment_count": RuleFieldDefinition(
        field="attachment_count",
        field_type=RuleFieldType.NUMBER,
        data_source=RuleDataSource.EMAIL_EVENT,
        display_name="Attachment Count",
        description="Number of file attachments in email",
        allowed_operators=[
            DslOperator.EQUALS,
            DslOperator.GREATER_THAN,
            DslOperator.GREATER_THAN_OR_EQUAL,
            DslOperator.LESS_THAN,
        ],
    ),
    "contains_login_url": RuleFieldDefinition(
        field="contains_login_url",
        field_type=RuleFieldType.BOOLEAN,
        data_source=RuleDataSource.EMAIL_EVENT,
        display_name="Contains Login/Auth URL",
        description="Flag indicating presence of credential harvesting or login landing page",
        allowed_operators=[DslOperator.EQUALS],
    ),
    "is_external": RuleFieldDefinition(
        field="is_external",
        field_type=RuleFieldType.BOOLEAN,
        data_source=RuleDataSource.EMAIL_EVENT,
        display_name="Is External Origin",
        description="Flag indicating sender domain is outside the protected tenant envelope",
        allowed_operators=[DslOperator.EQUALS],
    ),

    # Indicators & Threat Intelligence
    "threat_verdict": RuleFieldDefinition(
        field="threat_verdict",
        field_type=RuleFieldType.ENUM,
        data_source=RuleDataSource.THREAT_INTELLIGENCE,
        display_name="Threat Verdict",
        description="Multi-engine verdict consensus (MALICIOUS, SUSPICIOUS, BENIGN, UNKNOWN)",
        allowed_operators=[DslOperator.EQUALS, DslOperator.NOT_EQUALS, DslOperator.IN],
    ),
    "confidence": RuleFieldDefinition(
        field="confidence",
        field_type=RuleFieldType.NUMBER,
        data_source=RuleDataSource.THREAT_INTELLIGENCE,
        display_name="Intelligence Confidence",
        description="Provider consensus confidence score between 0.0 and 1.0",
        allowed_operators=[
            DslOperator.GREATER_THAN_OR_EQUAL,
            DslOperator.GREATER_THAN,
            DslOperator.LESS_THAN,
            DslOperator.LESS_THAN_OR_EQUAL,
        ],
    ),
    "domain_age_days": RuleFieldDefinition(
        field="domain_age_days",
        field_type=RuleFieldType.NUMBER,
        data_source=RuleDataSource.THREAT_INTELLIGENCE,
        display_name="Domain Age (Days)",
        description="Age of domain registration in days",
        allowed_operators=[
            DslOperator.LESS_THAN,
            DslOperator.LESS_THAN_OR_EQUAL,
            DslOperator.GREATER_THAN,
            DslOperator.GREATER_THAN_OR_EQUAL,
        ],
    ),
    "ip_address": RuleFieldDefinition(
        field="ip_address",
        field_type=RuleFieldType.IP,
        data_source=RuleDataSource.NETWORK_EVENT,
        display_name="IP Address",
        description="Resolved IPv4 or IPv6 network address",
        allowed_operators=[
            DslOperator.EQUALS,
            DslOperator.NOT_EQUALS,
            DslOperator.IN,
            DslOperator.NOT_IN,
            DslOperator.CONNECTED_TO,
            DslOperator.SHARES_INFRASTRUCTURE,
        ],
    ),
    "dest_port": RuleFieldDefinition(
        field="dest_port",
        field_type=RuleFieldType.NUMBER,
        data_source=RuleDataSource.NETWORK_EVENT,
        display_name="Destination Port",
        description="Destination TCP/UDP network port",
        allowed_operators=[
            DslOperator.EQUALS,
            DslOperator.NOT_EQUALS,
            DslOperator.IN,
            DslOperator.NOT_IN,
            DslOperator.GREATER_THAN,
            DslOperator.LESS_THAN,
            DslOperator.GREATER_THAN_OR_EQUAL,
            DslOperator.LESS_THAN_OR_EQUAL,
        ],
    ),
    "auth_result": RuleFieldDefinition(
        field="auth_result",
        field_type=RuleFieldType.ENUM,
        data_source=RuleDataSource.AUTH_EVENT,
        display_name="Authentication Result",
        description="Outcome of authentication attempt (SUCCESS, FAILED, CHALLENGED)",
        allowed_operators=[
            DslOperator.EQUALS,
            DslOperator.NOT_EQUALS,
            DslOperator.IN,
            DslOperator.NOT_IN,
        ],
    ),
    "asn_number": RuleFieldDefinition(
        field="asn_number",
        field_type=RuleFieldType.STRING,
        data_source=RuleDataSource.THREAT_INTELLIGENCE,
        display_name="Autonomous System Number",
        description="Routing BGP Autonomous System (e.g. AS13335)",
        allowed_operators=[DslOperator.EQUALS, DslOperator.NOT_EQUALS, DslOperator.IN],
    ),
    "sha256": RuleFieldDefinition(
        field="sha256",
        field_type=RuleFieldType.HASH,
        data_source=RuleDataSource.INDICATOR,
        display_name="SHA256 Hash",
        description="Cryptographic SHA-256 fingerprint",
        allowed_operators=[DslOperator.EQUALS, DslOperator.IN, DslOperator.NOT_IN],
    ),
    "watchlist_monitored": RuleFieldDefinition(
        field="watchlist_monitored",
        field_type=RuleFieldType.BOOLEAN,
        data_source=RuleDataSource.WATCHLIST,
        display_name="Watchlist Monitored",
        description="Flag indicating indicator is enrolled in an active threat watchlist",
        allowed_operators=[DslOperator.EQUALS],
    ),

    # Endpoint Telemetry
    "process_name": RuleFieldDefinition(
        field="process_name",
        field_type=RuleFieldType.STRING,
        data_source=RuleDataSource.ENDPOINT_EVENT,
        display_name="Process Executable Name",
        description="Host process image or binary name (e.g. powershell.exe, curl)",
        allowed_operators=[
            DslOperator.EQUALS,
            DslOperator.NOT_EQUALS,
            DslOperator.CONTAINS,
            DslOperator.ENDS_WITH,
            DslOperator.IN,
            DslOperator.REGEX,
        ],
    ),
    "command_line": RuleFieldDefinition(
        field="command_line",
        field_type=RuleFieldType.STRING,
        data_source=RuleDataSource.ENDPOINT_EVENT,
        display_name="Command Line Arguments",
        description="Full process command line invocation string",
        allowed_operators=[
            DslOperator.CONTAINS,
            DslOperator.STARTS_WITH,
            DslOperator.REGEX,
        ],
    ),

    # Behavioral & Novelty
    "behavioral_deviation": RuleFieldDefinition(
        field="behavioral_deviation",
        field_type=RuleFieldType.NUMBER,
        data_source=RuleDataSource.BEHAVIORAL_BASELINE,
        display_name="Behavioral Deviation Z-Score",
        description="Statistical standard deviations away from baseline historical activity",
        allowed_operators=[
            DslOperator.GREATER_THAN,
            DslOperator.GREATER_THAN_OR_EQUAL,
        ],
    ),
    "novelty_score": RuleFieldDefinition(
        field="novelty_score",
        field_type=RuleFieldType.NUMBER,
        data_source=RuleDataSource.NOVELTY_EVENT,
        display_name="Emerging Threat Novelty Score",
        description="Zero-day / novelty outlier metric between 0.0 and 1.0",
        allowed_operators=[
            DslOperator.GREATER_THAN,
            DslOperator.GREATER_THAN_OR_EQUAL,
        ],
    ),
}


# ============================================================================
# 2. STRUCTURED DETECTION RULE DSL & AST MODELS
# ============================================================================

class RuleCondition(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    field: str = Field(description="Target attribute or feature path (e.g. sender_domain, url_count)")
    operator: DslOperator = Field(description="Safe DSL operator from controlled vocabulary")
    value: Optional[Any] = Field(default=None, description="Expected value or numerical threshold")
    case_sensitive: bool = Field(default=False, description="Case sensitivity for string operations")
    time_window_seconds: Optional[int] = Field(default=None, ge=1, le=86400 * 30, description="Temporal window if applicable")
    nested_definition: Optional[RuleDefinition] = Field(default=None, description="Optional nested AST for composite conditions")

    @field_validator("operator", mode="before")
    @classmethod
    def normalize_operator(cls, v: Any) -> Any:
        if isinstance(v, str):
            mapping = {
                "eq": "EQUALS",
                "neq": "NOT_EQUALS",
                "gt": "GREATER_THAN",
                "gte": "GREATER_THAN_OR_EQUAL",
                "lt": "LESS_THAN",
                "lte": "LESS_THAN_OR_EQUAL",
                "contains": "CONTAINS",
                "not_contains": "NOT_CONTAINS",
                "starts_with": "STARTS_WITH",
                "ends_with": "ENDS_WITH",
                "regex": "REGEX",
                "in": "IN",
                "not_in": "NOT_IN",
                "exists": "EXISTS",
                "not_exists": "NOT_EXISTS",
                "lookalike": "LOOKALIKE",
            }
            return mapping.get(v.lower(), v.upper() if v.upper() in DslOperator.__members__ else v)
        return v

    @field_validator("field")
    @classmethod
    def validate_field(cls, v: str) -> str:
        clean = v.strip()
        if not clean or len(clean) > 128:
            raise ValueError("Field name must be 1-128 characters")
        if re.search(r"[^\w\.\-\_]", clean):
            raise ValueError(f"Field contains invalid characters: {clean}")
        return clean


class RuleDefinition(BaseModel):
    """
    Structured, allowlisted Abstract Syntax Tree (AST) for detection rules.
    Strictly forbids raw SQL, Python eval(), or arbitrary code execution.
    """
    model_config = ConfigDict(from_attributes=True)

    source: Optional[str] = Field(default=None, description="Optional target data source declaration")
    logic: Optional[str] = Field(default=None, description="Alias for logical_operator")
    logical_operator: str = Field(default="AND", description="Logical combinator (AND, OR, NOT)")
    conditions: List[RuleCondition] = Field(default_factory=list, description="Atomic condition list")
    nested_groups: Optional[List[RuleDefinition]] = Field(default=None, description="Nested condition groups (max depth 3)")
    temporal_constraints: List[Dict[str, Any]] = Field(default_factory=list, description="Sequence constraints")
    graph_constraints: List[Dict[str, Any]] = Field(default_factory=list, description="Graph traversal constraints")

    @field_validator("logical_operator", mode="before")
    @classmethod
    def validate_logical_operator(cls, v: Any) -> str:
        if isinstance(v, str):
            upper = v.upper()
            if upper not in ("AND", "OR", "NOT"):
                raise ValueError("Logical operator must be 'AND', 'OR', or 'NOT'")
            return upper
        return "AND"

    @classmethod
    def model_validate(cls, obj: Any, *args, **kwargs) -> RuleDefinition:
        if isinstance(obj, dict):
            if "logic" in obj and not obj.get("logical_operator"):
                obj = dict(obj)
                obj["logical_operator"] = obj["logic"]
        return super().model_validate(obj, *args, **kwargs)


RuleCondition.model_rebuild()
RuleDefinition.model_rebuild()


class RuleValidationResponse(BaseModel):
    is_valid: bool
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    complexity_score: float = 1.0
    cost_class: RuleCostClass = RuleCostClass.LOW
    human_readable_logic: str = ""
    normalized_fingerprint: str = ""


# ============================================================================
# 3. VERSION DIFF & MATCH EXPLANATION MODELS
# ============================================================================

class RuleVersionDiff(BaseModel):
    rule_id: str
    v1_version: str
    v2_version: str
    has_changes: bool = False
    added_conditions: List[Dict[str, Any]] = Field(default_factory=list)
    removed_conditions: List[Dict[str, Any]] = Field(default_factory=list)
    modified_conditions: List[Dict[str, Any]] = Field(default_factory=list)
    conditions_added: List[Dict[str, Any]] = Field(default_factory=list)
    conditions_removed: List[Dict[str, Any]] = Field(default_factory=list)
    thresholds_modified: List[Dict[str, Any]] = Field(default_factory=list)
    data_sources_modified: Dict[str, Any] = Field(default_factory=dict)
    severity_changed: Optional[Dict[str, str]] = None
    cost_class_changed: Optional[Dict[str, str]] = None
    summary_text: str = ""


class DetectionMatchExplanation(BaseModel):
    rule_id: str
    rule_version: str
    rule_name: str
    matched: bool
    summary: str
    matched_fields: List[str] = Field(default_factory=list)
    condition_results: List[Dict[str, Any]] = Field(default_factory=list)
    observed_values: Dict[str, Any] = Field(default_factory=dict)
    explanation: Optional[Dict[str, Any]] = None
    execution_time_ms: float = 0.0


# ============================================================================
# 4. REQUEST & RESPONSE DTOs
# ============================================================================

class DetectionRuleCreateRequest(BaseModel):
    workspace_id: str = Field(default="default")
    rule_identifier: Optional[str] = Field(default=None, description="Optional human code e.g. RULE-101")
    name: str = Field(min_length=3, max_length=255)
    description: str = Field(default="", max_length=3000)
    rule_type: RuleType = Field(default=RuleType.STRUCTURAL)
    category: RuleCategory = Field(default=RuleCategory.PHISHING)
    data_sources: List[RuleDataSource] = Field(default_factory=lambda: [RuleDataSource.EMAIL_EVENT])
    scope: RuleScope = Field(default=RuleScope.GLOBAL)
    severity: RuleSeverity = Field(default=RuleSeverity.MEDIUM)
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    generalization_level: GeneralizationLevel = Field(default=GeneralizationLevel.STRUCTURAL)
    time_window_seconds: Optional[int] = Field(default=None, ge=1, le=86400 * 30)
    definition: RuleDefinition
    thresholds: Dict[str, Any] = Field(default_factory=dict)
    tags: List[str] = Field(default_factory=list)
    attack_techniques: List[str] = Field(default_factory=list)
    provenance_type: RuleProvenanceType = Field(default=RuleProvenanceType.ANALYST_CREATED)
    provenance_id: Optional[str] = None
    provenance_details: Dict[str, Any] = Field(default_factory=dict)
    created_by: str = Field(default="analyst")
    # Section 57 operational additions
    owner_id: str = Field(default="analyst")
    team_id: Optional[str] = None
    collections: List[str] = Field(default_factory=list)
    dependencies: List[RuleDependency] = Field(default_factory=list)
    review_interval_days: int = Field(default=90, ge=1, le=365)


class DetectionRuleTuneRequest(BaseModel):
    """Creates a new immutable version from an existing rule (e.g. v1 -> v2)."""
    workspace_id: str = Field(default="default")
    change_reason: Optional[str] = Field(default=None, max_length=500, description="Analytical rationale for tuning")
    change_description: Optional[str] = Field(default=None, max_length=500, description="Analytical rationale for tuning")
    definition: RuleDefinition
    thresholds: Optional[Dict[str, Any]] = None
    severity: Optional[RuleSeverity] = None
    confidence: Optional[float] = None
    data_sources: Optional[List[RuleDataSource]] = None
    tags: Optional[List[str]] = None
    attack_techniques: Optional[List[str]] = None
    editor: str = Field(default="analyst")
    # Section 57 operational additions
    owner_id: Optional[str] = None
    team_id: Optional[str] = None
    collections: Optional[List[str]] = None
    dependencies: Optional[List[RuleDependency]] = None
    review_interval_days: Optional[int] = None


class DetectionRuleBacktestRequest(BaseModel):
    workspace_id: str = Field(default="default")
    time_range_preset: Optional[str] = Field(default="LAST_30_DAYS")
    lookback_days: int = Field(default=30, ge=1, le=365)
    max_records: Optional[int] = None
    max_events_to_scan: int = Field(default=500, ge=1, le=5000)
    data_source: Optional[str] = None
    version: Optional[str] = None
    time_range_start: Optional[datetime] = None
    time_range_end: Optional[datetime] = None
    sample_mode: bool = False
    run_async: bool = False
    async_mode: bool = False


class DetectionRuleBacktestResponse(BaseModel):
    execution_id: str
    rule_id: str
    rule_version: str
    status: str
    data_source: Optional[str] = None
    time_range: Optional[str] = None
    records_evaluated: int = 0
    scanned_event_count: int = 0
    matches_count: int = 0
    historical_match_count: int = 0
    duration_ms: float = 0.0
    precision: float = 0.0
    recall: Optional[float] = None
    false_positive_count: int = 0
    unknown_count: int = 0
    matches: List[Dict[str, Any]] = Field(default_factory=list)
    matched_records: List[Dict[str, Any]] = Field(default_factory=list)
    job_id: Optional[str] = None
    limitations: List[str] = Field(default_factory=list)


class DetectionRuleFromHuntRequest(BaseModel):
    workspace_id: str = Field(default="default")
    hunt_execution_id: str
    rule_name: str
    category: RuleCategory = RuleCategory.INFRASTRUCTURE
    selected_indicators: List[str] = Field(default_factory=list)
    analyst_notes: Optional[str] = None
    created_by: str = Field(default="analyst")


class DetectionRuleFromInvestigationRequest(BaseModel):
    workspace_id: str = Field(default="default")
    investigation_id: str
    incident_id: Optional[str] = None
    rule_name: str
    category: RuleCategory = RuleCategory.CAMPAIGN
    selected_evidence_ids: List[str] = Field(default_factory=list)
    analyst_notes: Optional[str] = None
    created_by: str = Field(default="analyst")


class AISuggestRuleRequest(BaseModel):
    prompt: Optional[str] = Field(default=None, max_length=1000, description="Analyst description of threat pattern")
    observation_text: Optional[str] = Field(default=None, max_length=1000, description="Analyst description of threat pattern")
    data_source_hint: Optional[str] = None
    data_sources: Optional[List[RuleDataSource]] = None
    category: Optional[RuleCategory] = None
    workspace_id: str = Field(default="default")

    @classmethod
    def model_validate(cls, obj: Any, *args, **kwargs) -> AISuggestRuleRequest:
        if isinstance(obj, dict):
            obj = dict(obj)
            if "observation_text" in obj and not obj.get("prompt"):
                obj["prompt"] = obj["observation_text"]
            if "data_source_hint" in obj and not obj.get("data_sources"):
                hint = obj["data_source_hint"]
                obj["data_sources"] = [RuleDataSource(hint)] if hint in RuleDataSource._value2member_map_ else [RuleDataSource.EMAIL_EVENT]
        return super().model_validate(obj, *args, **kwargs)


class AISuggestRuleResponse(BaseModel):
    suggested_name: str
    description: str
    category: RuleCategory
    data_sources: List[RuleDataSource]
    severity: RuleSeverity
    definition: RuleDefinition
    explanation: str
    estimated_cost: RuleCostClass
    suggested_rule: Optional[Dict[str, Any]] = None
    validation_preview: Optional[RuleValidationResponse] = None


class DetectionRuleResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    workspace_id: str
    rule_identifier: Optional[str] = None
    name: str
    description: str
    rule_type: RuleType
    category: RuleCategory
    data_sources: List[str] = Field(default_factory=list)
    status: RuleLifecycleStatus
    scope: RuleScope
    severity: RuleSeverity
    confidence: float
    cost_class: RuleCostClass
    generalization_level: GeneralizationLevel
    complexity_score: float
    normalized_fingerprint: str
    version: str
    definition: RuleDefinition
    thresholds: Dict[str, Any] = Field(default_factory=dict)
    tags: List[str] = Field(default_factory=list)
    attack_techniques: List[str] = Field(default_factory=list)
    is_system_rule: bool = False
    provenance_type: str
    provenance_id: Optional[str] = None
    provenance_details: Dict[str, Any] = Field(default_factory=dict)
    human_readable_logic: str = ""
    staged_at: Optional[datetime] = None
    activated_at: Optional[datetime] = None
    disabled_at: Optional[datetime] = None
    retired_at: Optional[datetime] = None
    created_by: str
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[datetime] = None
    review_reason: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    versions_count: int = 1
    # Section 57 Operational additions
    owner_id: str = "analyst"
    team_id: Optional[str] = None
    last_editor_id: Optional[str] = None
    deployment_state: DeploymentStateEnum = DeploymentStateEnum.DRAFT
    operational_health: OperationalHealthEnum = OperationalHealthEnum.HEALTHY
    health_reason: Optional[str] = None
    health_updated_at: Optional[datetime] = None
    review_interval_days: int = 90
    next_review_due: Optional[datetime] = None
    last_reviewed_at: Optional[datetime] = None
    dependencies: List[RuleDependency] = Field(default_factory=list)
    collections: List[str] = Field(default_factory=list)
    replaced_by_rule_id: Optional[str] = None
    last_matched_at: Optional[datetime] = None
    total_match_count: int = 0
    matches_last_24h: int = 0
    active_suppressions_count: int = 0
    # Section 58 Operational additions
    last_validation_run_id: Optional[str] = None
    validation_status: Optional[str] = "NOT_RUN"
    validation_updated_at: Optional[datetime] = None


class DetectionRuleListResponse(BaseModel):
    items: List[DetectionRuleResponse]
    total: int
    active_count: int
    candidate_count: int
    staged_count: int
    disabled_count: int


class DetectionRuleStatsResponse(BaseModel):
    workspace_id: str
    total_rules: int
    active_rules: int
    staged_rules: int
    pending_review_rules: int
    draft_rules: int
    disabled_rules: int
    total_matches: int
    precision_rate: float
    cost_distribution: Dict[str, int] = Field(default_factory=dict)
    category_distribution: Dict[str, int] = Field(default_factory=dict)


# ============================================================================
# Section 57: Request & Response DTOs
# ============================================================================

class RuleSuppressionCreateRequest(BaseModel):
    name: str = Field(min_length=2, max_length=255)
    reason: str = Field(min_length=3, max_length=500)
    scope_type: str = Field(default="ENTITY", description="ENTITY, FIELD, CONDITION, SOURCE, ENVIRONMENT, GLOBAL")
    scope_target: str = Field(description="Target field e.g. sender_domain, ip_address, recipient, subject")
    match_value: str = Field(description="Target value e.g. internal-scanner.corp, 10.0.0.1")
    match_operator: str = Field(default="EQUALS", description="EQUALS, CONTAINS, ENDS_WITH, REGEX")
    expires_in_days: Optional[int] = Field(default=None, ge=1, le=365)
    expires_at: Optional[datetime] = None


class RuleSuppressionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    workspace_id: str
    rule_id: str
    name: str
    reason: str
    scope_type: str
    scope_target: str
    match_value: str
    match_operator: str
    is_active: bool
    expires_at: Optional[datetime] = None
    created_by: str
    approved_by: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class RuleDeploymentRequest(BaseModel):
    target_state: DeploymentStateEnum = Field(description="STAGING or PRODUCTION")
    version: Optional[str] = Field(default=None, description="Optional target version e.g. v1, v2")
    reason: Optional[str] = Field(default=None, max_length=500)


class RuleRollbackRequest(BaseModel):
    target_version: str = Field(description="Target immutable version to roll back to e.g. v1, v2")
    reason: str = Field(min_length=3, max_length=500, description="Required analytical justification for rollback")


class EmergencyDisableRequest(BaseModel):
    reason: str = Field(min_length=3, max_length=500, description="Required mandatory reason for emergency disable")


class DeploymentDryRunResponse(BaseModel):
    rule_id: str
    target_version: str
    validation_status: str  # PASS / FAIL
    validation_errors: List[str] = Field(default_factory=list)
    dependency_status: str  # PASS / DEGRADED / FAIL
    missing_required_dependencies: List[str] = Field(default_factory=list)
    historical_test_status: str  # PASS / INSUFFICIENT_DATA / FAIL
    historical_matches_sample: int = 0
    operational_risk: str  # LOW / MEDIUM / HIGH
    risk_factors: List[str] = Field(default_factory=list)
    can_deploy: bool = True


class RuleSimulationRequest(BaseModel):
    sample_size: int = Field(default=50, ge=1, le=500)
    data_source: Optional[str] = None


class RuleSimulationResponse(BaseModel):
    rule_id: str
    rule_version: str
    status: str = "COMPLETED"
    events_scanned: int = 0
    matches_count: int = 0
    simulation_matches: List[Dict[str, Any]] = Field(default_factory=list)
    duration_ms: float = 0.0
    is_simulation: bool = True


class RuleOwnershipUpdateRequest(BaseModel):
    owner_id: str = Field(min_length=1, max_length=100)
    team_id: Optional[str] = Field(default=None, max_length=100)
    review_interval_days: Optional[int] = Field(default=None, ge=1, le=365)


class MatchDispositionRequest(BaseModel):
    disposition: MatchDispositionEnum
    notes: Optional[str] = Field(default=None, max_length=500)


class RuleQualityMetricsResponse(BaseModel):
    rule_id: str
    total_matches: int = 0
    reviewed_matches: int = 0
    true_positives: int = 0
    false_positives: int = 0
    benign_count: int = 0
    expected_activity_count: int = 0
    needs_review_count: int = 0
    false_positive_rate: Optional[float] = None
    precision_rate: Optional[float] = None
    review_coverage_rate: Optional[float] = None
    insufficient_data: bool = True
    quality_verdict: str = "INSUFFICIENT_DATA"


class RuleOperationalHealthResponse(BaseModel):
    rule_id: str
    rule_identifier: Optional[str] = None
    deployment_state: DeploymentStateEnum
    operational_health: OperationalHealthEnum
    health_reason: Optional[str] = None
    health_updated_at: Optional[datetime] = None
    execution_count_24h: int = 0
    success_count_24h: int = 0
    failure_count_24h: int = 0
    error_rate_24h: float = 0.0
    average_duration_ms: float = 0.0
    p95_duration_ms: float = 0.0
    matches_last_24h: int = 0
    matches_prev_24h: int = 0
    match_rate_anomaly: bool = False
    anomaly_details: Optional[str] = None
    zero_match: bool = False
    is_stale: bool = False
    review_due: bool = False
    next_review_due: Optional[datetime] = None
    days_until_review: Optional[int] = None
    dependencies: List[RuleDependency] = Field(default_factory=list)
    dependency_health_summary: str = "HEALTHY"


class BulkRuleOperationRequest(BaseModel):
    rule_ids: List[str] = Field(min_length=1, max_length=200)
    operation: str = Field(description="ENABLE, DISABLE, ASSIGN_OWNER, ASSIGN_TEAM, ADD_TAG, REMOVE_TAG, SET_COLLECTION, ACTIVATE")
    owner_id: Optional[str] = None
    team_id: Optional[str] = None
    tag: Optional[str] = None
    collection: Optional[str] = None
    reason: Optional[str] = None


class BulkRuleOperationResponse(BaseModel):
    operation: str
    total_requested: int
    succeeded_count: int
    failed_count: int
    succeeded_rule_ids: List[str] = Field(default_factory=list)
    failed_rules: List[Dict[str, str]] = Field(default_factory=list)


class OperationalOverviewResponse(BaseModel):
    workspace_id: str
    total_rules: int
    active_rules: int
    staging_rules: int
    draft_rules: int
    disabled_rules: int
    healthy_rules: int
    degraded_rules: int
    failing_rules: int
    unknown_health_rules: int
    review_due_count: int
    stale_rules_count: int
    zero_match_count: int
    high_fp_count: int
    unusual_match_rate_count: int
    total_matches_24h: int
    coverage_by_source: Dict[str, int] = Field(default_factory=dict)
    coverage_by_collection: Dict[str, int] = Field(default_factory=dict)


# ============================================================================
# Section 58: Automated Detection Validation & Continuous Rule Quality Schemas
# ============================================================================

class ValidationStatusEnum(str, Enum):
    NOT_RUN = "NOT_RUN"
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    PASS = "PASS"
    PASS_WITH_WARNINGS = "PASS_WITH_WARNINGS"
    FAIL = "FAIL"
    BLOCKED = "BLOCKED"
    CANCELLED = "CANCELLED"
    TIMED_OUT = "TIMED_OUT"
    STALE = "STALE"


class ValidationTypeEnum(str, Enum):
    FULL = "FULL"
    STRUCTURAL = "STRUCTURAL"
    DEPENDENCY = "DEPENDENCY"
    DATA_COMPATIBILITY = "DATA_COMPATIBILITY"
    EXECUTION = "EXECUTION"
    REGRESSION = "REGRESSION"
    PERFORMANCE = "PERFORMANCE"
    BEHAVIOR = "BEHAVIOR"
    FIXTURES = "FIXTURES"
    CONTINUOUS = "CONTINUOUS"
    GATE_CHECK = "GATE_CHECK"


class ValidationTriggerEnum(str, Enum):
    MANUAL = "MANUAL"
    SCHEDULED = "SCHEDULED"
    CONTINUOUS = "CONTINUOUS"
    VERSION_CREATED = "VERSION_CREATED"
    DEPLOYMENT_GATE = "DEPLOYMENT_GATE"
    SCHEMA_CHANGE = "SCHEMA_CHANGE"
    DEPENDENCY_CHANGE = "DEPENDENCY_CHANGE"
    HEALTH_DEGRADED = "HEALTH_DEGRADED"


class ValidationCategoryEnum(str, Enum):
    STRUCTURAL = "STRUCTURAL"
    DEPENDENCY = "DEPENDENCY"
    DATA_COMPATIBILITY = "DATA_COMPATIBILITY"
    EXECUTION = "EXECUTION"
    REGRESSION = "REGRESSION"
    PERFORMANCE = "PERFORMANCE"
    BEHAVIOR = "BEHAVIOR"
    FIXTURE = "FIXTURE"
    OPERATIONAL = "OPERATIONAL"


class ValidationSeverityEnum(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FixtureTypeEnum(str, Enum):
    POSITIVE = "POSITIVE"
    NEGATIVE = "NEGATIVE"


class ValidationRunRequest(BaseModel):
    validation_type: ValidationTypeEnum = ValidationTypeEnum.FULL
    trigger_type: ValidationTriggerEnum = ValidationTriggerEnum.MANUAL
    version: Optional[str] = None
    baseline_version: Optional[str] = None
    data_window_days: int = Field(default=7, ge=1, le=90)
    run_async: bool = False
    idempotency_key: Optional[str] = None


class ValidationResultItem(BaseModel):
    id: str
    category: ValidationCategoryEnum
    status: ValidationStatusEnum
    severity: ValidationSeverityEnum
    code: str
    message: str
    observed_value: Any = Field(default_factory=dict)
    expected_value: Any = Field(default_factory=dict)
    baseline_value: Any = Field(default_factory=dict)
    evidence: Any = Field(default_factory=dict)
    created_at: Optional[datetime] = None


class ValidationRunResponse(BaseModel):
    id: str
    workspace_id: str
    rule_id: str
    rule_version: str
    validation_type: ValidationTypeEnum
    status: ValidationStatusEnum
    trigger_type: ValidationTriggerEnum
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_ms: Optional[float] = None
    requested_by: str
    executed_by: Optional[str] = None
    job_id: Optional[str] = None
    baseline_rule_version: Optional[str] = None
    is_stale: bool = False
    stale_reason: Optional[str] = None
    results_count: int = 0
    pass_count: int = 0
    warning_count: int = 0
    fail_count: int = 0
    blocked_count: int = 0
    summary: Dict[str, Any] = Field(default_factory=dict)
    checks: List[ValidationResultItem] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    created_at: datetime


class DeploymentGateCheckResponse(BaseModel):
    rule_id: str
    version: str
    can_promote: bool
    status: ValidationStatusEnum
    gate_messages: List[str] = Field(default_factory=list)
    blocking_reasons: List[str] = Field(default_factory=list)
    warning_reasons: List[str] = Field(default_factory=list)
    last_run_id: Optional[str] = None
    validated_at: Optional[datetime] = None


class TestFixtureCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: Optional[str] = ""
    fixture_type: FixtureTypeEnum = FixtureTypeEnum.POSITIVE
    payload: Dict[str, Any]
    expected_match: bool = True
    is_active: bool = True


class TestFixtureResponse(BaseModel):
    id: str
    workspace_id: str
    rule_id: str
    name: str
    description: str
    fixture_type: FixtureTypeEnum
    payload: Dict[str, Any]
    expected_match: bool
    is_active: bool
    last_run_at: Optional[datetime] = None
    last_result: Optional[str] = None
    last_error: Optional[str] = None
    created_by: str
    created_at: datetime
    updated_at: datetime


class ValidationOverviewStats(BaseModel):
    workspace_id: str
    total_rules: int
    passed_rules: int
    warning_rules: int
    failed_rules: int
    blocked_rules: int
    stale_rules: int
    not_run_rules: int
    total_validation_runs_24h: int
    avg_validation_duration_ms: float
    schema_drift_detected_count: int
    performance_regression_count: int
    critical_gate_blocked_count: int



