"""
Section 66: Pydantic schemas for Advanced Investigation Automation.
Provides strictly validated, typed contracts for investigation automation plans,
bounded steps, action registry contracts, telemetry coverage, investigation gaps,
knowns vs unknowns summaries, and policy management.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class AutomationTriggerType(str, Enum):
    MANUAL_ANALYST = "MANUAL_ANALYST"
    CRITICAL_ALERT = "CRITICAL_ALERT"
    HIGH_RISK_INCIDENT = "HIGH_RISK_INCIDENT"
    CAMPAIGN_MATCH = "CAMPAIGN_MATCH"
    DETECTION_RULE_ALERT = "DETECTION_RULE_ALERT"
    POLICY_SCHEDULE = "POLICY_SCHEDULE"


class AutomationMode(str, Enum):
    MANUAL = "MANUAL"
    ASSISTED = "ASSISTED"
    POLICY_AUTOMATIC = "POLICY_AUTOMATIC"


class AutomationRunStatus(str, Enum):
    QUEUED = "QUEUED"
    PLANNING = "PLANNING"
    RUNNING = "RUNNING"
    PARTIALLY_COMPLETED = "PARTIALLY_COMPLETED"
    WAITING_FOR_ANALYST = "WAITING_FOR_ANALYST"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    TIMED_OUT = "TIMED_OUT"


class StepStatus(str, Enum):
    QUEUED = "QUEUED"
    WAITING_APPROVAL = "WAITING_APPROVAL"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    PARTIALLY_COMPLETED = "PARTIALLY_COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    SKIPPED = "SKIPPED"


class ActionCostClass(str, Enum):
    FAST = "FAST"
    NORMAL = "NORMAL"
    EXPENSIVE = "EXPENSIVE"
    BACKGROUND = "BACKGROUND"


class ActionApprovalLevel(str, Enum):
    READ_ONLY_AUTOMATIC = "READ_ONLY_AUTOMATIC"
    READ_ONLY_APPROVAL_OPTIONAL = "READ_ONLY_APPROVAL_OPTIONAL"
    ANALYST_APPROVAL_REQUIRED = "ANALYST_APPROVAL_REQUIRED"
    ADMIN_APPROVAL_REQUIRED = "ADMIN_APPROVAL_REQUIRED"
    FORBIDDEN = "FORBIDDEN"


class ActionIdEnum(str, Enum):
    GET_ASSET_CONTEXT = "GET_ASSET_CONTEXT"
    GET_IDENTITY_CONTEXT = "GET_IDENTITY_CONTEXT"
    GET_INDICATOR_CONTEXT = "GET_INDICATOR_CONTEXT"
    GET_THREAT_INTELLIGENCE = "GET_THREAT_INTELLIGENCE"
    GET_WATCHLIST_CONTEXT = "GET_WATCHLIST_CONTEXT"
    GET_RELATED_ALERTS = "GET_RELATED_ALERTS"
    GET_RELATED_INCIDENTS = "GET_RELATED_INCIDENTS"
    GET_RELATED_FINDINGS = "GET_RELATED_FINDINGS"
    GET_GRAPH_RELATIONSHIPS = "GET_GRAPH_RELATIONSHIPS"
    RUN_APPROVED_HUNT = "RUN_APPROVED_HUNT"
    RUN_APPROVED_PIVOT = "RUN_APPROVED_PIVOT"
    GET_CAMPAIGN_CONTEXT = "GET_CAMPAIGN_CONTEXT"
    GET_BEHAVIOR_CONTEXT = "GET_BEHAVIOR_CONTEXT"
    BUILD_TIMELINE = "BUILD_TIMELINE"
    CHECK_DATA_COVERAGE = "CHECK_DATA_COVERAGE"
    GENERATE_INVESTIGATION_SUMMARY = "GENERATE_INVESTIGATION_SUMMARY"


class GapCategory(str, Enum):
    TELEMETRY_MISSING = "TELEMETRY_MISSING"
    AUTHENTICATION_STALE = "AUTHENTICATION_STALE"
    INTELLIGENCE_UNAVAILABLE = "INTELLIGENCE_UNAVAILABLE"
    TEMPORAL_BLINDSPOT = "TEMPORAL_BLINDSPOT"
    UNRESOLVED_IDENTITY = "UNRESOLVED_IDENTITY"
    ENDPOINT_OFFLINE = "ENDPOINT_OFFLINE"


class GapSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class TelemetryCoverageStatus(str, Enum):
    AVAILABLE = "AVAILABLE"
    PARTIAL = "PARTIAL"
    STALE = "STALE"
    MISSING = "MISSING"
    NOT_CONFIGURED = "NOT_CONFIGURED"


class AutomationBudget(BaseModel):
    max_steps: int = Field(default=15, ge=1, le=50)
    max_time_seconds: int = Field(default=300, ge=10, le=1800)
    max_depth: int = Field(default=2, ge=1, le=4)
    max_entities: int = Field(default=50, ge=1, le=200)
    max_hunts: int = Field(default=5, ge=0, le=20)
    max_evidence: int = Field(default=50, ge=1, le=200)


class AutomationStepCreate(BaseModel):
    step_index: int = Field(ge=0)
    action_id: ActionIdEnum
    name: str = Field(min_length=1, max_length=255)
    cost_class: ActionCostClass = ActionCostClass.NORMAL
    approval_level: ActionApprovalLevel = ActionApprovalLevel.READ_ONLY_AUTOMATIC
    input_params: Dict[str, Any] = Field(default_factory=dict)


class AutomationStepRead(BaseModel):
    id: str
    run_id: str
    step_index: int
    action_id: str
    name: str
    cost_class: str
    approval_level: str
    status: str
    input_params: Dict[str, Any] = Field(default_factory=dict)
    result_summary: Dict[str, Any] = Field(default_factory=dict)
    result_count: int = 0
    warnings: List[str] = Field(default_factory=list)
    error_message: Optional[str] = None
    approved_by: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_ms: int = 0


class InvestigationGapRead(BaseModel):
    id: str
    workspace_id: str
    investigation_id: str
    run_id: Optional[str] = None
    category: str
    severity: str
    title: str
    description: str
    remediation_recommendation: Optional[str] = None
    created_at: datetime


class TelemetryCoverageItem(BaseModel):
    source: str
    status: TelemetryCoverageStatus
    message: str
    last_observed_at: Optional[datetime] = None


class InvestigationCoverageReport(BaseModel):
    sources: List[TelemetryCoverageItem] = Field(default_factory=list)
    coverage_score: float = Field(ge=0.0, le=1.0, default=0.0)
    gaps_count: int = 0
    evaluated_at: datetime = Field(default_factory=datetime.utcnow)


class RecommendedNextStep(BaseModel):
    priority: str  # P1, P2, P3, P4
    title: str
    description: str
    action_type: str  # HUNT, RESPONSE, PIVOT, ENRICHMENT, REVIEW
    handoff_route: Optional[str] = None
    target_identifier: Optional[str] = None


class InvestigationSummaryReport(BaseModel):
    knowns: List[str] = Field(default_factory=list)
    unknowns: List[str] = Field(default_factory=list)
    assessment_summary: str = ""
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)
    recommended_next_steps: List[RecommendedNextStep] = Field(default_factory=list)


class InvestigationAutomationRunRead(BaseModel):
    id: str
    workspace_id: str
    investigation_id: str
    trigger_type: str
    mode: str
    template_name: str
    plan_version: str
    status: str
    budget: AutomationBudget
    total_steps: int
    completed_steps: int
    failed_steps: int
    steps: List[AutomationStepRead] = Field(default_factory=list)
    gaps: List[InvestigationGapRead] = Field(default_factory=list)
    coverage_summary: Optional[InvestigationCoverageReport] = None
    investigation_summary: Optional[InvestigationSummaryReport] = None
    error_message: Optional[str] = None
    created_by: str
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime


class InvestigationAutomationRunCreate(BaseModel):
    template_name: Optional[str] = "GENERAL_INCIDENT_INVESTIGATION"
    mode: Optional[AutomationMode] = AutomationMode.ASSISTED
    trigger_type: Optional[AutomationTriggerType] = AutomationTriggerType.MANUAL_ANALYST
    budget: Optional[AutomationBudget] = None
    custom_steps: Optional[List[AutomationStepCreate]] = None


class StepApprovalRequest(BaseModel):
    approve: bool
    reason: Optional[str] = None


class AutomationTemplateDefinition(BaseModel):
    template_name: str
    title: str
    description: str
    target_trigger: str
    steps: List[AutomationStepCreate]


class AutomationPolicyCreate(BaseModel):
    name: str = Field(min_length=2, max_length=255)
    description: Optional[str] = None
    template_name: str = "GENERAL_INCIDENT_INVESTIGATION"
    trigger_conditions: Dict[str, Any] = Field(default_factory=dict)
    allowed_steps: List[str] = Field(default_factory=list)
    limits: Dict[str, Any] = Field(default_factory=dict)


class AutomationPolicyRead(BaseModel):
    id: str
    workspace_id: str
    name: str
    description: Optional[str] = None
    status: str
    template_name: str
    trigger_conditions: Dict[str, Any] = Field(default_factory=dict)
    allowed_steps: List[str] = Field(default_factory=list)
    limits: Dict[str, Any] = Field(default_factory=dict)
    version: str
    created_by: str
    created_at: datetime
    updated_at: datetime
