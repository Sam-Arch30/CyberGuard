"""
Pydantic V2 schemas for Section 25: Emerging Pattern & Candidate Rule Engine.

Defines:
- Rule types (INDICATOR, STRUCTURAL, BEHAVIORAL, SEQUENCE, CORRELATION, GRAPH, HYBRID)
- Lifecycle states (DISCOVERED, DRAFT, VALIDATING, TESTED, REVIEW_REQUIRED, APPROVED, STAGED, ACTIVE, REJECTED, DISABLED, RETIRED, SUPERSEDED)
- Safe Rule DSL operators and conditions (zero arbitrary code execution)
- Rule definitions, execution budgets, backtest evaluations, and quality reports
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
import re
from typing import Any, Dict, List, Optional, Set, Union
from pydantic import BaseModel, Field, ConfigDict, field_validator


# ============================================================================
# 1. ENUMS & CONTROLLED VOCABULARIES
# ============================================================================

class RuleType(str, Enum):
    """Categorical classification of candidate detection rules."""
    INDICATOR = "INDICATOR"          # Exact match on hash, domain, IP, URL
    STRUCTURAL = "STRUCTURAL"        # URL structure, domain pattern, file/email format
    BEHAVIORAL = "BEHAVIORAL"        # Auth sequence, API abuse, network anomalies
    SEQUENCE = "SEQUENCE"            # Event A -> Event B -> Event C
    CORRELATION = "CORRELATION"      # Multi-signal temporal combination
    GRAPH = "GRAPH"                  # Knowledge graph entity/infrastructure traversal
    HYBRID = "HYBRID"                # Multi-modal combination of structural, behavioral & graph


class RuleLifecycleStatus(str, Enum):
    """Formal lifecycle state machine for candidate rules."""
    DISCOVERED = "DISCOVERED"        # Proposed from EmergingPatternCandidate or Threat Memory
    DRAFT = "DRAFT"                  # Under human or automated formulation
    VALIDATING = "VALIDATING"        # Under syntax and complexity budget validation
    TESTED = "TESTED"                # Historical backtesting and FP analysis complete
    REVIEW_REQUIRED = "REVIEW_REQUIRED" # Awaiting security engineer review
    APPROVED = "APPROVED"            # Approved by authorized reviewer (not yet active)
    STAGED = "STAGED"                # Operating in shadow mode (monitoring without alerting)
    ACTIVE = "ACTIVE"                # Deployed in production detection pipeline
    REJECTED = "REJECTED"            # Rejected during review or failed backtesting
    DISABLED = "DISABLED"            # Temporarily disabled due to noise or drift
    RETIRED = "RETIRED"              # Permanently retired due to obsolescence
    SUPERSEDED = "SUPERSEDED"        # Replaced by a newer version (e.g. v1 -> v2)


class RuleScope(str, Enum):
    """Execution scope of detection rule."""
    EMAIL = "EMAIL"
    URL = "URL"
    AUTH = "AUTH"
    NETWORK = "NETWORK"
    API = "API"
    FILE = "FILE"
    MEDIA = "MEDIA"
    GLOBAL = "GLOBAL"


class RuleSeverity(str, Enum):
    """Threat severity assigned when the rule triggers."""
    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class GeneralizationLevel(str, Enum):
    """Level of generalization exhibited by the candidate rule."""
    EXACT = "EXACT"                  # Low coverage, high specificity (memorized attributes)
    STRUCTURAL = "STRUCTURAL"        # Moderate coverage, structural token patterns
    BEHAVIORAL = "BEHAVIORAL"        # Moderate-high coverage, behavioral deviation sequences
    SEQUENTIAL = "SEQUENTIAL"        # High specificity to attack stage progressions
    CORRELATIONAL = "CORRELATIONAL"  # Balanced coverage of weak combined signals
    GRAPH = "GRAPH"                  # Graph topological relationships
    HYBRID = "HYBRID"                # Multi-faceted generalization


class DslOperator(str, Enum):
    """Safe, validated operators supported by CyberGuard Rule DSL."""
    # Equality & comparison
    EQUALS = "eq"
    NOT_EQUALS = "neq"
    GREATER_THAN = "gt"
    GREATER_THAN_OR_EQUAL = "gte"
    LESS_THAN = "lt"
    LESS_THAN_OR_EQUAL = "lte"

    # String & collection operators
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    STARTS_WITH = "starts_with"
    ENDS_WITH = "ends_with"
    REGEX = "regex"
    IN = "in"
    NOT_IN = "not_in"
    EXISTS = "exists"
    NOT_EXISTS = "not_exists"

    # Semantic & statistical
    SIMILARITY_GTE = "similarity_gte"
    COUNT_GTE = "count_gte"
    COUNT_LTE = "count_lte"

    # Temporal sequence operators
    FOLLOWED_BY = "FOLLOWED_BY"
    PRECEDED_BY = "PRECEDED_BY"
    WITHIN = "WITHIN"

    # Graph relationship operators
    CONNECTED_TO = "CONNECTED_TO"
    RESOLVES_TO = "RESOLVES_TO"
    ASSOCIATED_WITH = "ASSOCIATED_WITH"
    SHARES_INFRASTRUCTURE = "SHARES_INFRASTRUCTURE"


# ============================================================================
# 2. RULE DEFINITION & DSL MODELS
# ============================================================================

class RuleCondition(BaseModel):
    """Atomic evaluation condition in the Rule DSL."""
    model_config = ConfigDict(from_attributes=True)

    field: str = Field(description="Target attribute or feature path (e.g. url.has_login_path, sender_domain)")
    operator: DslOperator = Field(description="Safe DSL operator")
    value: Optional[Any] = Field(default=None, description="Expected value or threshold")
    case_sensitive: bool = Field(default=False, description="Case sensitivity for string operations")
    time_window_seconds: Optional[int] = Field(default=None, ge=1, le=86400 * 30, description="Temporal window if applicable")

    @field_validator("field")
    @classmethod
    def validate_field_name(cls, v: str) -> str:
        clean = v.strip()
        if not clean or len(clean) > 128:
            raise ValueError("Field name must be 1-128 characters")
        if re.search(r"[^\w\.\-\_]", clean):
            raise ValueError(f"Field contains invalid characters: {clean}")
        return clean


class RuleDefinition(BaseModel):
    """Structured rule definition. NEVER contains arbitrary executable code."""
    model_config = ConfigDict(from_attributes=True)

    logical_operator: str = Field(default="AND", description="Logical combinator for conditions (AND or OR)")
    conditions: List[RuleCondition] = Field(default_factory=list, description="List of atomic conditions")
    temporal_constraints: List[Dict[str, Any]] = Field(default_factory=list, description="Sequence constraints")
    graph_constraints: List[Dict[str, Any]] = Field(default_factory=list, description="Graph traversal constraints")

    @field_validator("logical_operator")
    @classmethod
    def validate_logical_operator(cls, v: str) -> str:
        upper = v.upper()
        if upper not in ("AND", "OR"):
            raise ValueError("Logical operator must be 'AND' or 'OR'")
        return upper


# ============================================================================
# 3. RULE EVALUATION & QUALITY SCHEMAS
# ============================================================================

class RuleEvaluation(BaseModel):
    """Structured outcome of historical backtesting and quality assessment."""
    model_config = ConfigDict(from_attributes=True)

    historical_match_count: int = Field(default=0, ge=0)
    validated_positive_count: int = Field(default=0, ge=0)
    false_positive_count: int = Field(default=0, ge=0)
    unknown_count: int = Field(default=0, ge=0, description="Matches without ground-truth labels (NOT assumed true negatives)")
    precision: float = Field(default=0.0, ge=0.0, le=1.0)
    recall: Optional[float] = Field(default=None, ge=0.0, le=1.0, description="Recall over verified malicious subset")
    coverage: float = Field(default=0.0, ge=0.0, le=1.0)
    generalization_score: float = Field(default=0.0, ge=0.0, le=1.0, description="Cross-campaign and cross-incident generalization")
    complexity_score: float = Field(default=1.0, ge=0.0, description="Computational budget complexity metric")
    execution_time_ms: float = Field(default=0.0, ge=0.0)
    campaigns_evaluated: List[str] = Field(default_factory=list)
    evaluation_window_start: Optional[datetime] = None
    evaluation_window_end: Optional[datetime] = None
    limitations: List[str] = Field(default_factory=list)


class RuleMatchResult(BaseModel):
    """Evaluation result when a candidate/active rule evaluates an event or context."""
    rule_id: str
    rule_version: str
    rule_name: str
    matched: bool
    matched_conditions: List[Dict[str, Any]] = Field(default_factory=list)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    severity: RuleSeverity = Field(default=RuleSeverity.MEDIUM)
    explanation: str = Field(default="")
    evidence_items: List[Dict[str, Any]] = Field(default_factory=list)
    execution_time_ms: float = Field(default=0.0)


# ============================================================================
# 4. CANDIDATE RULE DOMAIN & DTO SCHEMAS
# ============================================================================

class CandidateRuleBase(BaseModel):
    workspace_id: str = Field(default="default")
    name: str = Field(min_length=3, max_length=255)
    description: str = Field(default="", max_length=2000)
    rule_type: RuleType = Field(default=RuleType.STRUCTURAL)
    scope: RuleScope = Field(default=RuleScope.GLOBAL)
    severity: RuleSeverity = Field(default=RuleSeverity.MEDIUM)
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    generalization_level: GeneralizationLevel = Field(default=GeneralizationLevel.STRUCTURAL)
    time_window_seconds: Optional[int] = Field(default=None, ge=1, le=86400 * 30)


class CandidateRuleCreate(CandidateRuleBase):
    definition: RuleDefinition
    thresholds: Dict[str, Any] = Field(default_factory=dict)
    pattern_candidate_id: Optional[str] = None
    source_memory_ids: List[str] = Field(default_factory=list)
    source_incident_ids: List[str] = Field(default_factory=list)
    created_by: str = Field(default="analyst")


class CandidateRuleFromPatternRequest(BaseModel):
    """Request to synthesize a candidate rule from an EmergingPatternCandidate."""
    workspace_id: str = Field(default="default")
    pattern_candidate_id: str = Field(description="ID of EmergingPatternCandidate")
    proposed_name: Optional[str] = None
    rule_type: Optional[RuleType] = None
    generalization_level: Optional[GeneralizationLevel] = None
    created_by: str = Field(default="automated_engine")


class CandidateRuleResponse(CandidateRuleBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    status: RuleLifecycleStatus
    version: str
    pattern_candidate_id: Optional[str] = None
    source_memory_ids: List[str] = Field(default_factory=list)
    source_incident_ids: List[str] = Field(default_factory=list)
    definition: RuleDefinition
    thresholds: Dict[str, Any] = Field(default_factory=dict)
    complexity_score: float = 1.0
    normalized_fingerprint: str
    evaluation_summary: Optional[RuleEvaluation] = None
    staged_at: Optional[datetime] = None
    activated_at: Optional[datetime] = None
    retired_at: Optional[datetime] = None
    created_by: str
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[datetime] = None
    review_reason: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class RuleVersionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    rule_id: str
    version: str
    workspace_id: str
    definition: RuleDefinition
    thresholds: Dict[str, Any] = Field(default_factory=dict)
    evaluation_summary: Optional[RuleEvaluation] = None
    status: RuleLifecycleStatus
    created_by: str
    reviewed_by: Optional[str] = None
    change_reason: Optional[str] = None
    created_at: datetime


# ============================================================================
# 5. WORKFLOW & LIFECYCLE ACTION SCHEMAS
# ============================================================================

class RuleBacktestRequest(BaseModel):
    """Initiates historical backtesting against retained telemetry."""
    workspace_id: str = Field(default="default")
    lookback_days: int = Field(default=90, ge=1, le=730)
    max_events_to_scan: int = Field(default=1000, ge=10, le=10000)
    exclude_origin_campaigns: bool = Field(default=False, description="Exclude origin campaign to test pure generalization")


class RuleReviewActionRequest(BaseModel):
    """Common request payload for review, approval, staging, or activation."""
    workspace_id: str = Field(default="default")
    reviewer: str = Field(default="security_lead")
    reason: str = Field(min_length=5, max_length=500, description="Audit justification for action")


class RuleEditRequest(BaseModel):
    """Edits rule definition, producing an immutable new version (e.g. v1 -> v2)."""
    workspace_id: str = Field(default="default")
    editor: str = Field(default="security_analyst")
    change_reason: str = Field(min_length=5, max_length=500)
    definition: RuleDefinition
    thresholds: Optional[Dict[str, Any]] = None
    severity: Optional[RuleSeverity] = None
    confidence: Optional[float] = None


class RuleEvaluationRequest(BaseModel):
    """Evaluates candidate or active rules against a target event or context payload."""
    workspace_id: str = Field(default="default")
    rule_ids: Optional[List[str]] = None  # None evaluates all active/staged rules for scope
    scope: Optional[RuleScope] = None
    target_payload: Dict[str, Any] = Field(description="Event, finding, or telemetry dictionary")
    include_staged_shadow: bool = Field(default=True, description="Whether to include staged rules in shadow mode")


class RuleDashboardStats(BaseModel):
    """Executive metrics for candidate rule engine."""
    workspace_id: str = "default"
    total_candidate_rules: int = 0
    discovered_count: int = 0
    tested_count: int = 0
    review_required_count: int = 0
    approved_count: int = 0
    staged_shadow_count: int = 0
    active_production_count: int = 0
    retired_count: int = 0
    avg_precision: float = 0.0
    shadow_evaluations_count: int = 0
