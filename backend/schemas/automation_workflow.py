"""
Section 70: Security Operations Automation (SOAR) Schemas.
Authoritative Pydantic models for workflows, runs, steps, approvals, and metrics.
"""
from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class WorkflowTypeEnum(str, Enum):
    ALERT_TRIAGE = "ALERT_TRIAGE"
    INCIDENT_ESCALATION = "INCIDENT_ESCALATION"
    THREAT_HUNTING = "THREAT_HUNTING"
    ACCOUNT_TAKEOVER_TRIAGE = "ACCOUNT_TAKEOVER_TRIAGE"
    MALICIOUS_ATTACHMENT_TRIAGE = "MALICIOUS_ATTACHMENT_TRIAGE"
    SLA_BREACH_REMEDIATION = "SLA_BREACH_REMEDIATION"
    CUSTOM = "CUSTOM"


class WorkflowStatusEnum(str, Enum):
    DRAFT = "DRAFT"
    VALIDATING = "VALIDATING"
    ACTIVE = "ACTIVE"
    PAUSED = "PAUSED"
    DISABLED = "DISABLED"
    ARCHIVED = "ARCHIVED"


class WorkflowExecutionModeEnum(str, Enum):
    PRODUCTION = "PRODUCTION"
    DRY_RUN = "DRY_RUN"
    TEST = "TEST"
    SIMULATION = "SIMULATION"


class AutomationRunStatusEnum(str, Enum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    WAITING_FOR_APPROVAL = "WAITING_FOR_APPROVAL"
    PAUSED = "PAUSED"
    PARTIALLY_COMPLETED = "PARTIALLY_COMPLETED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    TIMED_OUT = "TIMED_OUT"


class StepStatusEnum(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    WAITING_FOR_APPROVAL = "WAITING_FOR_APPROVAL"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    COMPLETED = "COMPLETED"
    PARTIALLY_COMPLETED = "PARTIALLY_COMPLETED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"
    TIMED_OUT = "TIMED_OUT"
    POLICY_DENIED = "POLICY_DENIED"


class ActionRiskClassificationEnum(str, Enum):
    READ_ONLY = "READ_ONLY"
    LOW_IMPACT = "LOW_IMPACT"
    MODERATE_IMPACT = "MODERATE_IMPACT"
    HIGH_IMPACT = "HIGH_IMPACT"
    DESTRUCTIVE = "DESTRUCTIVE"


class ActionApprovalLevelEnum(str, Enum):
    AUTOMATIC = "AUTOMATIC"
    ANALYST_APPROVAL = "ANALYST_APPROVAL"
    SENIOR_ANALYST_APPROVAL = "SENIOR_ANALYST_APPROVAL"
    ADMIN_APPROVAL = "ADMIN_APPROVAL"
    FORBIDDEN = "FORBIDDEN"


class ApprovalStatusEnum(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    CANCELLED = "CANCELLED"


class FailureCategoryEnum(str, Enum):
    VALIDATION_FAILURE = "VALIDATION_FAILURE"
    AUTHORIZATION_FAILURE = "AUTHORIZATION_FAILURE"
    POLICY_DENIED = "POLICY_DENIED"
    RESOURCE_NOT_FOUND = "RESOURCE_NOT_FOUND"
    RESOURCE_STATE_CONFLICT = "RESOURCE_STATE_CONFLICT"
    TRANSIENT_PROVIDER_FAILURE = "TRANSIENT_PROVIDER_FAILURE"
    TIMEOUT = "TIMEOUT"
    RATE_LIMITED = "RATE_LIMITED"
    INTEGRATION_UNAVAILABLE = "INTEGRATION_UNAVAILABLE"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class TriggerTypeEnum(str, Enum):
    ALERT_CREATED = "ALERT_CREATED"
    ALERT_ESCALATED = "ALERT_ESCALATED"
    INCIDENT_CREATED = "INCIDENT_CREATED"
    INCIDENT_SEVERITY_CHANGED = "INCIDENT_SEVERITY_CHANGED"
    FINDING_CREATED = "FINDING_CREATED"
    CRITICAL_FINDING_CREATED = "CRITICAL_FINDING_CREATED"
    WATCHLIST_MATCHED = "WATCHLIST_MATCHED"
    THREAT_INTELLIGENCE_CHANGED = "THREAT_INTELLIGENCE_CHANGED"
    DETECTION_RULE_MATCHED = "DETECTION_RULE_MATCHED"
    BEHAVIORAL_ANOMALY_DETECTED = "BEHAVIORAL_ANOMALY_DETECTED"
    SLA_WARNING = "SLA_WARNING"
    SLA_BREACH = "SLA_BREACH"
    CASE_CREATED = "CASE_CREATED"
    INVESTIGATION_COMPLETED = "INVESTIGATION_COMPLETED"
    REPORT_READY = "REPORT_READY"
    MANUAL = "MANUAL"


class ConditionRule(BaseModel):
    model_config = ConfigDict(extra="ignore")
    field: str
    operator: str = Field(description="eq, neq, gt, gte, lt, lte, in, contains")
    value: Any


class ConditionGroup(BaseModel):
    model_config = ConfigDict(extra="ignore")
    logic: str = "AND"  # AND / OR
    rules: List[ConditionRule] = Field(default_factory=list)


class WorkflowActionDefinition(BaseModel):
    model_config = ConfigDict(extra="ignore")
    step_key: str
    action_id: str
    name: str
    risk_classification: ActionRiskClassificationEnum = ActionRiskClassificationEnum.LOW_IMPACT
    approval_level: ActionApprovalLevelEnum = ActionApprovalLevelEnum.AUTOMATIC
    required_role: str = "analyst"
    parameters: Dict[str, Any] = Field(default_factory=dict)
    max_retries: int = 0
    timeout_seconds: int = 60
    continue_on_failure: bool = False


class WorkflowExecutionLimits(BaseModel):
    model_config = ConfigDict(extra="ignore")
    max_steps: int = 20
    timeout_seconds: int = 600
    max_retries: int = 2
    max_recursion_depth: int = 3
    deduplication_window_seconds: int = 300


# Requests / Responses
class WorkflowCreateRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")
    name: str
    description: Optional[str] = None
    workflow_type: WorkflowTypeEnum = WorkflowTypeEnum.ALERT_TRIAGE
    trigger_type: TriggerTypeEnum
    trigger_config: Dict[str, Any] = Field(default_factory=dict)
    conditions: ConditionGroup = Field(default_factory=ConditionGroup)
    actions: List[WorkflowActionDefinition] = Field(default_factory=list)
    approval_policy: Dict[str, Any] = Field(default_factory=dict)
    execution_limits: WorkflowExecutionLimits = Field(default_factory=WorkflowExecutionLimits)
    owner_id: str = "SOC Analyst"
    team_id: Optional[str] = None


class WorkflowUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")
    name: Optional[str] = None
    description: Optional[str] = None
    workflow_type: Optional[WorkflowTypeEnum] = None
    trigger_type: Optional[TriggerTypeEnum] = None
    trigger_config: Optional[Dict[str, Any]] = None
    conditions: Optional[ConditionGroup] = None
    actions: Optional[List[WorkflowActionDefinition]] = None
    approval_policy: Optional[Dict[str, Any]] = None
    execution_limits: Optional[WorkflowExecutionLimits] = None
    owner_id: Optional[str] = None
    team_id: Optional[str] = None


class WorkflowResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True, extra="ignore")
    id: str
    workspace_id: str
    tenant_id: str
    name: str
    description: Optional[str] = None
    workflow_type: str
    status: str
    version: int
    owner_id: str
    team_id: Optional[str] = None
    trigger_type: str
    trigger_config: Dict[str, Any] = Field(default_factory=dict)
    conditions: Dict[str, Any] = Field(default_factory=dict)
    actions: List[Dict[str, Any]] = Field(default_factory=list)
    approval_policy: Dict[str, Any] = Field(default_factory=dict)
    execution_limits: Dict[str, Any] = Field(default_factory=dict)
    is_active: bool
    created_by: str
    created_at: str
    updated_at: str


class WorkflowListResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    items: List[WorkflowResponse]
    total: int


class WorkflowVersionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True, extra="ignore")
    id: str
    workflow_id: str
    version: int
    status: str
    change_summary: Optional[str] = None
    validated_at: Optional[str] = None
    created_by: str
    created_at: str
    definition: Dict[str, Any] = Field(default_factory=dict)


class WorkflowRunTriggerRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    payload: Dict[str, Any] = Field(default_factory=dict)
    execution_mode: WorkflowExecutionModeEnum = WorkflowExecutionModeEnum.PRODUCTION


class StepExecutionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True, extra="ignore")
    id: str
    step_index: int
    step_key: str
    action_id: str
    name: str
    status: str
    risk_classification: str
    approval_level: str
    requires_approval: bool
    approval_id: Optional[str] = None
    approval_decision: Optional[str] = None
    approved_by: Optional[str] = None
    approved_at: Optional[str] = None
    input_params: Dict[str, Any] = Field(default_factory=dict)
    output_data: Dict[str, Any] = Field(default_factory=dict)
    verification_result: Dict[str, Any] = Field(default_factory=dict)
    verified_state: bool
    error_message: Optional[str] = None
    failure_category: Optional[str] = None
    retry_count: int
    execution_duration_ms: int
    started_at: Optional[str] = None
    completed_at: Optional[str] = None


class WorkflowRunResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True, extra="ignore")
    id: str
    workspace_id: str
    tenant_id: str
    workflow_id: Optional[str] = None
    workflow_name: Optional[str] = None
    workflow_version: int
    status: str
    trigger_type: str
    trigger_resource_type: Optional[str] = None
    trigger_resource_id: Optional[str] = None
    execution_mode: str
    idempotency_key: Optional[str] = None
    total_steps: int
    completed_steps: int
    failed_steps: int
    skipped_steps: int
    error_message: Optional[str] = None
    failure_category: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    explainability_trace: Dict[str, Any] = Field(default_factory=dict)
    output_summary: Dict[str, Any] = Field(default_factory=dict)
    steps: List[StepExecutionResponse] = Field(default_factory=list)
    created_at: str


class WorkflowRunListResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    items: List[WorkflowRunResponse]
    total: int


class ApprovalRequestResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True, extra="ignore")
    id: str
    run_id: str
    step_id: str
    action_id: str
    status: str
    required_role: str
    requested_by: str
    requested_at: str
    expires_at: str
    decision: Optional[str] = None
    decided_by: Optional[str] = None
    decided_at: Optional[str] = None
    reason: Optional[str] = None
    action_payload: Dict[str, Any] = Field(default_factory=dict)
    context_summary: Dict[str, Any] = Field(default_factory=dict)


class ApprovalDecisionRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")
    decision: str = Field(description="APPROVED or REJECTED")
    reason: Optional[str] = None


class RegisteredActionMetadata(BaseModel):
    model_config = ConfigDict(extra="ignore")
    action_id: str
    name: str
    description: str
    risk_classification: ActionRiskClassificationEnum
    default_approval_level: ActionApprovalLevelEnum
    required_role: str
    target_resource_type: Optional[str] = None
    parameters_schema: Dict[str, Any] = Field(default_factory=dict)


class AutomationMetricsResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    total_workflows: int
    active_workflows: int
    draft_workflows: int
    total_runs: int
    completed_runs: int
    partially_completed_runs: int
    failed_runs: int
    pending_approvals: int
    success_rate: float
    average_duration_ms: float
    failure_breakdown: Dict[str, int]
