"""
Section 54: Pydantic Schemas & DTOs for Threat Hunting Workspace & Query Engine.
Defines the controlled Query DSL, field/operator taxonomies, data source registry,
saved hunt models, execution logs, and investigation/watchlist handoff contracts.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


# =============================================================================
# 1. Enums & Taxonomies
# =============================================================================

class HuntSourceEnum(str, Enum):
    INDICATORS = "indicators"
    ALERTS = "alerts"
    FINDINGS = "findings"
    ARTIFACTS = "artifacts"
    THREAT_INTELLIGENCE = "threat_intelligence"
    WATCHLIST_CHANGES = "watchlist_changes"
    WATCHED_INDICATORS = "watched_indicators"
    INCIDENTS = "incidents"
    CASES = "cases"
    THREAT_EVENTS = "threat_events"
    THREAT_MEMORY = "threat_memory"
    ENDPOINT_EVENTS = "endpoint_events"


class QueryOperatorEnum(str, Enum):
    # Equality
    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    # Textual
    CONTAINS = "contains"
    STARTS_WITH = "starts_with"
    ENDS_WITH = "ends_with"
    # Sets
    IN = "in"
    NOT_IN = "not_in"
    # Relational
    GREATER_THAN = "greater_than"
    GREATER_THAN_OR_EQUAL = "greater_than_or_equal"
    LESS_THAN = "less_than"
    LESS_THAN_OR_EQUAL = "less_than_or_equal"
    BETWEEN = "between"
    # Existence
    EXISTS = "exists"
    NOT_EXISTS = "not_exists"
    # Temporal
    BEFORE = "before"
    AFTER = "after"
    WITHIN_LAST = "within_last"


class TimePresetEnum(str, Enum):
    M15 = "15m"
    H1 = "1h"
    H6 = "6h"
    H24 = "24h"
    D7 = "7d"
    D30 = "30d"
    CUSTOM = "custom"
    ALL = "all"


class HuntVisibilityEnum(str, Enum):
    PRIVATE = "PRIVATE"
    TEAM = "TEAM"
    TENANT = "TENANT"


class HuntExecutionModeEnum(str, Enum):
    FAST = "FAST"
    BACKGROUND = "BACKGROUND"


class HuntExecutionStatusEnum(str, Enum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    PARTIALLY_SUCCEEDED = "PARTIALLY_SUCCEEDED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


# =============================================================================
# 2. Query DSL Specifications
# =============================================================================

class QueryFilter(BaseModel):
    field: str = Field(..., description="Canonical field key from Data Source Registry")
    operator: QueryOperatorEnum = Field(..., description="Supported relational or textual operator")
    value: Any = Field(..., description="Filter operand (scalar, list for IN/BETWEEN, or boolean)")


class QueryTimeRange(BaseModel):
    field: Optional[str] = Field(None, description="Temporal field (e.g. observed_at, first_seen, created_at)")
    preset: Optional[TimePresetEnum] = Field(TimePresetEnum.D7, description="Relative time window preset")
    from_time: Optional[datetime] = Field(None, description="Explicit start boundary for custom range")
    to_time: Optional[datetime] = Field(None, description="Explicit end boundary for custom range")


class QuerySort(BaseModel):
    field: str = Field(..., description="Field to sort results by")
    direction: str = Field("desc", description="Sort direction: 'asc' or 'desc'")


class HuntQueryDefinition(BaseModel):
    data_source: HuntSourceEnum = Field(HuntSourceEnum.INDICATORS, description="Authoritative CyberGuard data source")
    filters: List[QueryFilter] = Field(default_factory=list, description="Array of validated filter conditions")
    time_range: Optional[QueryTimeRange] = Field(None, description="Bounded time range for query")
    sort: List[QuerySort] = Field(default_factory=list, description="Sorting criteria")
    limit: int = Field(50, ge=1, le=1000, description="Result page size (bounded cost limit)")
    offset: int = Field(0, ge=0, description="Pagination offset")
    group_by: Optional[str] = Field(None, description="Optional server-side aggregation grouping field")
    top_n: Optional[int] = Field(20, ge=1, le=100, description="Top-N cardinality limit for aggregations")


# =============================================================================
# 3. Query Validation & Plan Responses
# =============================================================================

class QueryPlanStep(BaseModel):
    step: str
    description: str


class HuntValidationResponse(BaseModel):
    is_valid: bool
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    estimated_cost: str = Field("LOW", description="LOW, MEDIUM, HIGH, RESTRICTED")
    query_plan: List[QueryPlanStep] = Field(default_factory=list)


# =============================================================================
# 4. Data Source Registry Schemas
# =============================================================================

class DataSourceField(BaseModel):
    name: str
    display_name: str
    field_type: str = Field(..., description="string, number, boolean, enum, datetime")
    allowed_operators: List[QueryOperatorEnum]
    description: str
    is_sortable: bool = True
    is_groupable: bool = False
    options: Optional[List[str]] = None


class DataSourceMetadata(BaseModel):
    key: HuntSourceEnum
    display_name: str
    description: str
    fields: List[DataSourceField]
    supported_relationships: List[str]
    default_time_field: str
    approximate_count: Optional[int] = None


class DataSourceRegistryResponse(BaseModel):
    sources: List[DataSourceMetadata]


# =============================================================================
# 5. Saved Hunts DTOs
# =============================================================================

class SavedHuntCreateRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=200)
    description: Optional[str] = Field(None, max_length=2000)
    data_source: HuntSourceEnum = Field(HuntSourceEnum.INDICATORS)
    query_definition: HuntQueryDefinition
    hypothesis: Optional[str] = Field(None, max_length=2000)
    tags: List[str] = Field(default_factory=list)
    visibility: HuntVisibilityEnum = Field(HuntVisibilityEnum.TEAM)


class SavedHuntUpdateRequest(BaseModel):
    name: Optional[str] = Field(None, min_length=2, max_length=200)
    description: Optional[str] = None
    query_definition: Optional[HuntQueryDefinition] = None
    hypothesis: Optional[str] = None
    tags: Optional[List[str]] = None
    visibility: Optional[HuntVisibilityEnum] = None


class SavedHuntResponse(BaseModel):
    id: str
    workspace_id: str
    name: str
    description: Optional[str]
    data_source: str
    query_definition: HuntQueryDefinition
    hypothesis: Optional[str]
    tags: List[str]
    owner_user_id: Optional[str]
    team_id: Optional[str]
    visibility: str
    is_template: bool
    last_executed_at: Optional[datetime]
    last_result_count: Optional[int]
    created_by: str
    created_at: datetime
    updated_at: datetime


class SavedHuntListResponse(BaseModel):
    items: List[SavedHuntResponse]
    templates: List[SavedHuntResponse]
    total: int


# =============================================================================
# 6. Hunt Results & Aggregation Schemas
# =============================================================================

class HuntResultItem(BaseModel):
    id: str
    data_source: str
    title: str
    primary_value: str
    secondary_value: Optional[str] = None
    severity: Optional[str] = None
    verdict: Optional[str] = None
    confidence: Optional[float] = None
    observed_at: Optional[datetime] = None
    properties: Dict[str, Any] = Field(default_factory=dict)
    matched_reasons: List[str] = Field(default_factory=list)
    pivot_links: Dict[str, Any] = Field(default_factory=dict)


class HuntAggregationBucket(BaseModel):
    key: str
    count: int
    percentage: float


class HuntQueryResultResponse(BaseModel):
    execution_id: str
    data_source: str
    status: str
    total_matches: int
    items: List[HuntResultItem]
    aggregations: Optional[Dict[str, List[HuntAggregationBucket]]] = None
    duration_ms: int
    query_plan: List[QueryPlanStep] = Field(default_factory=list)
    has_more: bool = False
    offset: int = 0
    limit: int = 50


class HuntExecutionRequest(BaseModel):
    query_definition: HuntQueryDefinition
    saved_hunt_id: Optional[str] = None
    execution_mode: HuntExecutionModeEnum = Field(HuntExecutionModeEnum.FAST)


class HuntExecutionResponse(BaseModel):
    id: str
    workspace_id: str
    saved_hunt_id: Optional[str]
    data_source: str
    execution_mode: str
    status: str
    result_count: int
    matched_record_ids: List[str]
    duration_ms: Optional[int]
    error_message: Optional[str]
    executed_by: str
    job_id: Optional[str]
    started_at: datetime
    completed_at: Optional[datetime]


class HuntExecutionListResponse(BaseModel):
    items: List[HuntExecutionResponse]
    total: int


# =============================================================================
# 7. AI-Assisted Query & Handoff Schemas
# =============================================================================

class NaturalLanguageHuntRequest(BaseModel):
    prompt: str = Field(..., min_length=3, max_length=1000, description="Analyst question in natural language")
    suggested_source: Optional[HuntSourceEnum] = None


class NaturalLanguageHuntResponse(BaseModel):
    interpretation: str
    proposed_query: HuntQueryDefinition
    confidence: float
    explanation: str


class HuntInvestigationHandoffRequest(BaseModel):
    execution_id: str
    selected_record_ids: List[str] = Field(..., min_length=1)
    investigation_title: Optional[str] = None
    investigation_id: Optional[str] = None
    reason: Optional[str] = None


class HuntInvestigationHandoffResponse(BaseModel):
    success: bool
    investigation_id: str
    attached_records_count: int
    message: str


class HuntWatchlistHandoffRequest(BaseModel):
    execution_id: str
    selected_record_ids: List[str] = Field(..., min_length=1)
    watchlist_id: Optional[str] = None
    new_watchlist_name: Optional[str] = None
    reason: Optional[str] = None


class HuntWatchlistHandoffResponse(BaseModel):
    success: bool
    watchlist_id: str
    added_indicators_count: int
    message: str


class HuntExportRequest(BaseModel):
    execution_id: str
    format: str = Field("json", description="json or csv")
