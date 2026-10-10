"""
Section 51: Pydantic schemas for Incident SLA, Escalation & Analyst Workflow Automation.
Defines contracts for SLA policies, escalation chains, routing strategies,
live milestone clocks, workflow history, and policy simulation.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


# ============================================================================
# ENUMS
# ============================================================================

class SLAMilestoneEnum(str, Enum):
    ACKNOWLEDGEMENT = "ACKNOWLEDGEMENT"
    INVESTIGATION = "INVESTIGATION"
    CONTAINMENT = "CONTAINMENT"
    RESOLUTION = "RESOLUTION"


class SLAMilestoneStatusEnum(str, Enum):
    NOT_STARTED = "NOT_STARTED"
    RUNNING = "RUNNING"
    MET = "MET"
    WARNING = "WARNING"
    BREACHED = "BREACHED"
    PAUSED = "PAUSED"
    EXEMPT = "EXEMPT"


class SLAOverallStatusEnum(str, Enum):
    HEALTHY = "HEALTHY"
    WARNING = "WARNING"
    BREACHED = "BREACHED"
    PAUSED = "PAUSED"
    EXEMPT = "EXEMPT"
    MET = "MET"


class EscalationConditionEnum(str, Enum):
    SLA_WARNING = "SLA_WARNING"
    SLA_BREACH = "SLA_BREACH"
    CRITICAL_UNACKNOWLEDGED = "CRITICAL_UNACKNOWLEDGED"
    UNASSIGNED_TIMEOUT = "UNASSIGNED_TIMEOUT"
    PRIORITY_CRITICAL = "PRIORITY_CRITICAL"
    REOPENED = "REOPENED"


class EscalationActionTypeEnum(str, Enum):
    NOTIFY_OWNER = "NOTIFY_OWNER"
    NOTIFY_TEAM = "NOTIFY_TEAM"
    ASSIGN_TO_USER = "ASSIGN_TO_USER"
    ASSIGN_TO_TEAM = "ASSIGN_TO_TEAM"
    ESCALATE_PRIORITY = "ESCALATE_PRIORITY"
    CREATE_TASK = "CREATE_TASK"


class RoutingStrategyEnum(str, Enum):
    DIRECT_USER = "DIRECT_USER"
    ROUND_ROBIN = "ROUND_ROBIN"
    LEAST_LOADED = "LEAST_LOADED"
    TEAM_QUEUE = "TEAM_QUEUE"


class PolicyStatusEnum(str, Enum):
    DRAFT = "DRAFT"
    ACTIVE = "ACTIVE"
    DISABLED = "DISABLED"
    ARCHIVED = "ARCHIVED"


# ============================================================================
# SLA POLICY SCHEMAS
# ============================================================================

class SLAPolicyCreateRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    description: Optional[str] = None
    severity: str = Field("ANY", description="CRITICAL, HIGH, MEDIUM, LOW, INFO, ANY")
    priority: str = Field("ANY", description="P1_CRITICAL, P2_HIGH, P3_MEDIUM, P4_LOW, ANY")
    category: str = Field("ANY", description="PHISHING, MALWARE, etc. or ANY")
    acknowledgement_target_minutes: int = Field(30, ge=1, le=10080)
    investigation_target_minutes: int = Field(60, ge=1, le=10080)
    containment_target_minutes: int = Field(120, ge=1, le=20160)
    resolution_target_minutes: int = Field(480, ge=1, le=43200)
    warning_threshold_pct: float = Field(80.0, ge=10.0, le=95.0)
    escalation_policy_id: Optional[str] = None
    is_default: bool = False
    status: PolicyStatusEnum = PolicyStatusEnum.ACTIVE


class SLAPolicyUpdateRequest(BaseModel):
    name: Optional[str] = Field(None, min_length=2, max_length=100)
    description: Optional[str] = None
    severity: Optional[str] = None
    priority: Optional[str] = None
    category: Optional[str] = None
    acknowledgement_target_minutes: Optional[int] = Field(None, ge=1, le=10080)
    investigation_target_minutes: Optional[int] = Field(None, ge=1, le=10080)
    containment_target_minutes: Optional[int] = Field(None, ge=1, le=20160)
    resolution_target_minutes: Optional[int] = Field(None, ge=1, le=43200)
    warning_threshold_pct: Optional[float] = Field(None, ge=10.0, le=95.0)
    escalation_policy_id: Optional[str] = None
    is_default: Optional[bool] = None
    status: Optional[PolicyStatusEnum] = None


class SLAPolicyResponse(BaseModel):
    id: str
    workspace_id: str
    name: str
    description: Optional[str] = None
    severity: str
    priority: str
    category: str
    acknowledgement_target_minutes: int
    investigation_target_minutes: int
    containment_target_minutes: int
    resolution_target_minutes: int
    warning_threshold_pct: float
    escalation_policy_id: Optional[str] = None
    is_default: bool
    status: str
    version: int
    created_by: str
    updated_by: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class SLAPolicyListResponse(BaseModel):
    items: List[SLAPolicyResponse]
    total: int


# ============================================================================
# ESCALATION POLICY SCHEMAS
# ============================================================================

class EscalationRuleCreate(BaseModel):
    level: int = Field(1, ge=1, le=5)
    condition_type: EscalationConditionEnum = EscalationConditionEnum.SLA_BREACH
    milestone: str = Field("ANY", description="ACKNOWLEDGEMENT, INVESTIGATION, CONTAINMENT, RESOLUTION, ANY")
    action_type: EscalationActionTypeEnum = EscalationActionTypeEnum.NOTIFY_TEAM
    target_role: Optional[str] = Field(None, description="SOC Lead, Security Manager")
    target_user: Optional[str] = None
    target_team: Optional[str] = None
    escalate_priority_to: Optional[str] = None
    note_template: Optional[str] = None


class EscalationRuleResponse(BaseModel):
    id: str
    level: int
    condition_type: str
    milestone: str
    action_type: str
    target_role: Optional[str] = None
    target_user: Optional[str] = None
    target_team: Optional[str] = None
    escalate_priority_to: Optional[str] = None
    note_template: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class EscalationPolicyCreateRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    description: Optional[str] = None
    cooldown_minutes: int = Field(15, ge=1, le=1440)
    max_escalation_level: int = Field(3, ge=1, le=5)
    status: PolicyStatusEnum = PolicyStatusEnum.ACTIVE
    rules: List[EscalationRuleCreate] = Field(default_factory=list)


class EscalationPolicyUpdateRequest(BaseModel):
    name: Optional[str] = Field(None, min_length=2, max_length=100)
    description: Optional[str] = None
    cooldown_minutes: Optional[int] = Field(None, ge=1, le=1440)
    max_escalation_level: Optional[int] = Field(None, ge=1, le=5)
    status: Optional[PolicyStatusEnum] = None
    rules: Optional[List[EscalationRuleCreate]] = None


class EscalationPolicyResponse(BaseModel):
    id: str
    workspace_id: str
    name: str
    description: Optional[str] = None
    cooldown_minutes: int
    max_escalation_level: int
    status: str
    version: int
    created_by: str
    created_at: datetime
    updated_at: datetime
    rules: List[EscalationRuleResponse] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)


class EscalationPolicyListResponse(BaseModel):
    items: List[EscalationPolicyResponse]
    total: int


# ============================================================================
# ROUTING RULE SCHEMAS
# ============================================================================

class RoutingRuleCreateRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    description: Optional[str] = None
    priority_order: int = Field(10, ge=1, le=1000)
    category: str = Field("ANY")
    severity: str = Field("ANY")
    min_risk_score: float = Field(0.0, ge=0.0, le=100.0)
    routing_strategy: RoutingStrategyEnum = RoutingStrategyEnum.ROUND_ROBIN
    target_team_id: Optional[str] = None
    target_user_id: Optional[str] = None
    candidate_analysts: List[str] = Field(default_factory=list)
    enabled: bool = True


class RoutingRuleUpdateRequest(BaseModel):
    name: Optional[str] = Field(None, min_length=2, max_length=100)
    description: Optional[str] = None
    priority_order: Optional[int] = Field(None, ge=1, le=1000)
    category: Optional[str] = None
    severity: Optional[str] = None
    min_risk_score: Optional[float] = Field(None, ge=0.0, le=100.0)
    routing_strategy: Optional[RoutingStrategyEnum] = None
    target_team_id: Optional[str] = None
    target_user_id: Optional[str] = None
    candidate_analysts: Optional[List[str]] = None
    enabled: Optional[bool] = None


class RoutingRuleResponse(BaseModel):
    id: str
    workspace_id: str
    name: str
    description: Optional[str] = None
    priority_order: int
    category: str
    severity: str
    min_risk_score: float
    routing_strategy: str
    target_team_id: Optional[str] = None
    target_user_id: Optional[str] = None
    candidate_analysts: List[str] = Field(default_factory=list)
    enabled: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class RoutingRuleListResponse(BaseModel):
    items: List[RoutingRuleResponse]
    total: int


# ============================================================================
# OPERATIONAL INCIDENT SLA CLOCKS & DETAILS
# ============================================================================

class SLAMilestoneDetail(BaseModel):
    milestone: str
    target_minutes: int
    status: SLAMilestoneStatusEnum
    elapsed_minutes: float
    remaining_minutes: float
    deadline: Optional[datetime] = None
    met_at: Optional[datetime] = None
    warning_sent_at: Optional[datetime] = None
    breached_at: Optional[datetime] = None
    is_overdue: bool = False
    overdue_minutes: float = 0.0
    display_badge: str = "default"  # success, warning, danger, neutral


class SLAMilestonesContainer(BaseModel):
    acknowledgement: SLAMilestoneDetail
    investigation: SLAMilestoneDetail
    containment: SLAMilestoneDetail
    resolution: SLAMilestoneDetail


class EscalationSummary(BaseModel):
    current_level: int
    last_escalated_at: Optional[datetime] = None
    last_escalation_reason: Optional[str] = None


class IncidentSLADetailResponse(BaseModel):
    incident_id: str
    incident_number: str
    workspace_id: str
    policy_id: Optional[str] = None
    policy_name: Optional[str] = None
    policy_version: int = 1
    escalation_policy_id: Optional[str] = None
    overall_status: SLAOverallStatusEnum
    current_escalation_level: int = 0
    last_escalated_at: Optional[datetime] = None
    last_escalation_reason: Optional[str] = None
    is_paused: bool = False
    paused_at: Optional[datetime] = None
    paused_by: Optional[str] = None
    pause_reason: Optional[str] = None
    total_paused_seconds: int = 0
    is_exempt: bool = False
    exempt_at: Optional[datetime] = None
    exempt_by: Optional[str] = None
    exempt_reason: Optional[str] = None
    next_deadline: Optional[datetime] = None
    acknowledgement: SLAMilestoneDetail
    investigation: SLAMilestoneDetail
    containment: SLAMilestoneDetail
    resolution: SLAMilestoneDetail
    last_evaluated_at: Optional[datetime] = None

    @property
    def milestones(self) -> SLAMilestonesContainer:
        return SLAMilestonesContainer(
            acknowledgement=self.acknowledgement,
            investigation=self.investigation,
            containment=self.containment,
            resolution=self.resolution,
        )

    @property
    def overall_sla_status(self) -> SLAOverallStatusEnum:
        return self.overall_status

    @property
    def exemption_reason(self) -> Optional[str]:
        return self.exempt_reason

    @property
    def escalation(self) -> EscalationSummary:
        return EscalationSummary(
            current_level=self.current_escalation_level,
            last_escalated_at=self.last_escalated_at,
            last_escalation_reason=self.last_escalation_reason,
        )


# ============================================================================
# OPERATIONAL MUTATION REQUESTS
# ============================================================================

class SLAPauseRequest(BaseModel):
    reason: str = Field(..., min_length=3, max_length=500, description="Mandatory authorization reason for pausing SLA")


class SLAResumeRequest(BaseModel):
    reason: Optional[str] = Field(None, max_length=500)


class SLAExemptRequest(BaseModel):
    reason: str = Field(..., min_length=3, max_length=500, description="Mandatory authorization reason for exempting SLA")


class IncidentEscalateRequest(BaseModel):
    reason: str = Field(..., min_length=3, max_length=500, description="Reason for escalation")
    target_level: Optional[int] = Field(None, ge=1, le=5)
    target_user: Optional[str] = None
    target_team: Optional[str] = None


# ============================================================================
# WORKFLOW EXECUTION & HISTORY SCHEMAS
# ============================================================================

class WorkflowExecutionItemResponse(BaseModel):
    id: str
    incident_id: str
    execution_key: str
    policy_id: Optional[str] = None
    rule_id: Optional[str] = None
    escalation_level: int
    action_type: str
    target: Optional[str] = None
    status: str
    executed_at: datetime
    details: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(from_attributes=True)


class SLAPauseLogItemResponse(BaseModel):
    id: str
    incident_id: str
    action: str
    actor: str
    reason: str
    timestamp: datetime
    paused_duration_seconds: Optional[int] = None

    model_config = ConfigDict(from_attributes=True)


class WorkflowHistoryResponse(BaseModel):
    incident_id: str
    executions: List[WorkflowExecutionItemResponse]
    pause_logs: List[SLAPauseLogItemResponse]
    total_executions: int


# ============================================================================
# POLICY SIMULATION SCHEMAS
# ============================================================================

class PolicySimulationRequest(BaseModel):
    severity: str = Field("HIGH")
    priority: str = Field("P2_HIGH")
    category: str = Field("PHISHING")
    risk_score: float = Field(75.0, ge=0.0, le=100.0)
    unacknowledged_minutes: int = Field(35, ge=0)
    uncontained_minutes: int = Field(0, ge=0)
    status: str = Field("OPEN")


class PolicySimulationResponse(BaseModel):
    matched_sla_policy: Optional[str] = None
    matched_sla_policy_id: Optional[str] = None
    matched_sla_targets: Dict[str, int] = Field(default_factory=dict)
    simulated_milestone_status: Dict[str, str] = Field(default_factory=dict)
    triggered_escalation_rules: List[Dict[str, Any]] = Field(default_factory=list)
    simulated_routing_target: Optional[str] = None
    simulated_team_target: Optional[str] = None
    dry_run_summary: str
