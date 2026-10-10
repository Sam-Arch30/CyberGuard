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

