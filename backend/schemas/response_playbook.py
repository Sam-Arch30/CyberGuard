"""
Pydantic Schemas for Section 29: Response Playbooks.
Controlled data models for playbook definitions, versioning, allowlisted steps,
target validation, approval policies, simulations, and execution records.
"""

from __future__ import annotations
from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field


# ============================================================================
# CONTROLLED TAXONOMIES & ENUMS
# ============================================================================

class PlaybookStatusEnum(str, Enum):
    DRAFT = "DRAFT"
    VALIDATING = "VALIDATING"
    READY = "READY"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    APPROVED = "APPROVED"
    STAGED = "STAGED"
    ACTIVE = "ACTIVE"
    PAUSED = "PAUSED"
    DISABLED = "DISABLED"
    RETIRED = "RETIRED"
    SUPERSEDED = "SUPERSEDED"


class PlaybookTriggerTypeEnum(str, Enum):
    RECOMMENDATION_APPROVED = "RECOMMENDATION_APPROVED"
    MANUAL = "MANUAL"
    INCIDENT_SEVERITY = "INCIDENT_SEVERITY"


class ApprovalPolicyEnum(str, Enum):
    NO_APPROVAL = "NO_APPROVAL"
    SINGLE_APPROVAL = "SINGLE_APPROVAL"
    PRIVILEGED_APPROVAL = "PRIVILEGED_APPROVAL"
    DUAL_APPROVAL = "DUAL_APPROVAL"


class ExecutionPolicyEnum(str, Enum):
    MANUAL = "MANUAL"
    AUTOMATED_AFTER_APPROVAL = "AUTOMATED_AFTER_APPROVAL"
    SIMULATE_ONLY = "SIMULATE_ONLY"


class ExecutionModeEnum(str, Enum):
    LIVE = "LIVE"
    DRY_RUN = "DRY_RUN"


class ExecutionStatusEnum(str, Enum):
    PENDING = "PENDING"
    VALIDATING = "VALIDATING"
    WAITING_FOR_APPROVAL = "WAITING_FOR_APPROVAL"
    READY = "READY"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    COMPLETED = "COMPLETED"
    PARTIALLY_COMPLETED = "PARTIALLY_COMPLETED"
    FAILED = "FAILED"
    ROLLING_BACK = "ROLLING_BACK"
    ROLLED_BACK = "ROLLED_BACK"
    CANCELLED = "CANCELLED"
    EXPIRED = "EXPIRED"


class StepExecutionStatusEnum(str, Enum):
    PENDING = "PENDING"
    SKIPPED = "SKIPPED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    ROLLED_BACK = "ROLLED_BACK"
    ROLLBACK_FAILED = "ROLLBACK_FAILED"
    VERIFICATION_FAILED = "VERIFICATION_FAILED"


class ApprovalDecisionEnum(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    DEFERRED = "DEFERRED"
    EXPIRED = "EXPIRED"
    CANCELLED = "CANCELLED"


class StepTypeEnum(str, Enum):
    # Evidence Preservation
    PRESERVE_EVIDENCE = "PRESERVE_EVIDENCE"
    COLLECT_ARTIFACT_METADATA = "COLLECT_ARTIFACT_METADATA"
    CAPTURE_ANALYSIS_SNAPSHOT = "CAPTURE_ANALYSIS_SNAPSHOT"
    EXPORT_FORENSIC_RECORD = "EXPORT_FORENSIC_RECORD"

    # Investigation & Enrichment
    RUN_ANALYSIS = "RUN_ANALYSIS"
    REANALYZE_ARTIFACT = "REANALYZE_ARTIFACT"
    ENRICH_INDICATOR = "ENRICH_INDICATOR"
    CORRELATE_INCIDENT = "CORRELATE_INCIDENT"
    CREATE_INVESTIGATION_TASK = "CREATE_INVESTIGATION_TASK"

    # Identity / Account Containment
    REVOKE_SESSION = "REVOKE_SESSION"
    FORCE_REAUTHENTICATION = "FORCE_REAUTHENTICATION"
    REQUIRE_CREDENTIAL_RESET = "REQUIRE_CREDENTIAL_RESET"
    DISABLE_ACCOUNT = "DISABLE_ACCOUNT"
    ENABLE_ADDITIONAL_AUTHENTICATION = "ENABLE_ADDITIONAL_AUTHENTICATION"

    # Network Containment
    BLOCK_INDICATOR = "BLOCK_INDICATOR"
    BLOCK_DOMAIN = "BLOCK_DOMAIN"
    BLOCK_URL_PATTERN = "BLOCK_URL_PATTERN"
    BLOCK_IP = "BLOCK_IP"
    INCREASE_NETWORK_MONITORING = "INCREASE_NETWORK_MONITORING"

    # Endpoint (Controlled allowlist)
    ISOLATE_ENDPOINT = "ISOLATE_ENDPOINT"
    COLLECT_ENDPOINT_ARTIFACT = "COLLECT_ENDPOINT_ARTIFACT"
    INCREASE_ENDPOINT_MONITORING = "INCREASE_ENDPOINT_MONITORING"

    # Communication
    CREATE_NOTIFICATION = "CREATE_NOTIFICATION"
    CREATE_CASE_NOTE = "CREATE_CASE_NOTE"
    ESCALATE_INCIDENT = "ESCALATE_INCIDENT"

    # Verification
    VERIFY_ACCOUNT_STATE = "VERIFY_ACCOUNT_STATE"
    VERIFY_SESSION_STATE = "VERIFY_SESSION_STATE"
    VERIFY_ENDPOINT_STATE = "VERIFY_ENDPOINT_STATE"
    VERIFY_NETWORK_CONTROL = "VERIFY_NETWORK_CONTROL"
    VERIFY_EVIDENCE_PRESERVATION = "VERIFY_EVIDENCE_PRESERVATION"


class SafetyClassEnum(str, Enum):
    INFORMATIONAL = "INFORMATIONAL"
    LOW_IMPACT = "LOW_IMPACT"
    REVERSIBLE = "REVERSIBLE"
    CONTAINMENT = "CONTAINMENT"
    HIGH_IMPACT = "HIGH_IMPACT"
    DESTRUCTIVE = "DESTRUCTIVE"


class TargetTypeEnum(str, Enum):
    SESSION = "SESSION"
    ACCOUNT = "ACCOUNT"
    DEVICE = "DEVICE"
    DOMAIN = "DOMAIN"
    URL = "URL"
    IP = "IP"
    ARTIFACT = "ARTIFACT"
    EMAIL = "EMAIL"
    INCIDENT = "INCIDENT"
    INVESTIGATION = "INVESTIGATION"


class ErrorCodeEnum(str, Enum):
    VALIDATION_ERROR = "VALIDATION_ERROR"
    AUTHORIZATION_ERROR = "AUTHORIZATION_ERROR"
    CAPABILITY_UNAVAILABLE = "CAPABILITY_UNAVAILABLE"
    TARGET_NOT_FOUND = "TARGET_NOT_FOUND"
    TARGET_AMBIGUOUS = "TARGET_AMBIGUOUS"
    PRECONDITION_FAILED = "PRECONDITION_FAILED"
    CONFLICT = "CONFLICT"
    TIMEOUT = "TIMEOUT"
    RATE_LIMITED = "RATE_LIMITED"
    INTEGRATION_ERROR = "INTEGRATION_ERROR"
    VERIFICATION_FAILED = "VERIFICATION_FAILED"
    POLICY_BLOCKED = "POLICY_BLOCKED"
    UNKNOWN_ERROR = "UNKNOWN_ERROR"


# ============================================================================
# VALUE OBJECTS & CONFIG SCHEMAS
# ============================================================================

class TargetRef(BaseModel):
    target_type: str
    target_id: str


class TargetSnapshot(BaseModel):
    target_type: str
    target_id: str
    tenant_id: str = "default"
    resolved_at: str
    state_at_resolution: Dict[str, Any] = Field(default_factory=dict)
    resolution_source: str = "evidence_graph"


class RetryPolicy(BaseModel):
    max_attempts: int = 1
    backoff_seconds: float = 1.0
    retryable_errors: List[str] = Field(default_factory=lambda: ["TIMEOUT", "RATE_LIMITED", "INTEGRATION_ERROR"])


class VerificationPolicy(BaseModel):
    enabled: bool = True
    expected_state: str = "SUCCESS"
    timeout_seconds: int = 30
    query_pattern: Optional[Dict[str, Any]] = None


class RollbackPolicy(BaseModel):
    supports_rollback: bool = True
    reversibility: str = "REVERSIBLE"  # REVERSIBLE, PARTIALLY_REVERSIBLE, IRREVERSIBLE, UNKNOWN
    compensating_step_type: Optional[str] = None
    parameters: Optional[Dict[str, Any]] = None


class StepCondition(BaseModel):
    field: str
    operator: str  # ==, !=, >, >=, <, <=, in, contains, not_in
    value: Any


# ============================================================================
# STEP & PLAYBOOK SCHEMAS
# ============================================================================

class ResponsePlaybookStepCreate(BaseModel):
    step_key: str
    sequence: int = 1
    step_type: StepTypeEnum
    name: str
    description: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    target_selector: Dict[str, Any] = Field(default_factory=dict)
    condition: Dict[str, Any] = Field(default_factory=dict)
    on_success: str = "CONTINUE"
    on_failure: str = "FAIL"
    timeout_seconds: int = 60
    retry_policy: RetryPolicy = Field(default_factory=RetryPolicy)
    requires_approval: bool = False
    approval_policy: ApprovalPolicyEnum = ApprovalPolicyEnum.NO_APPROVAL
    safety_class: SafetyClassEnum = SafetyClassEnum.INFORMATIONAL
    verification_policy: VerificationPolicy = Field(default_factory=VerificationPolicy)
    rollback_policy: RollbackPolicy = Field(default_factory=RollbackPolicy)
    depends_on: List[str] = Field(default_factory=list)
    enabled: bool = True


class ResponsePlaybookStepResponse(BaseModel):
    id: str
    playbook_id: str
    step_key: str
    sequence: int
    step_type: str
    name: str
    description: str
    parameters: Dict[str, Any]
    target_selector: Dict[str, Any]
    condition: Dict[str, Any]
    on_success: str
    on_failure: str
    timeout_seconds: int
    retry_policy: Dict[str, Any]
    requires_approval: bool
    approval_policy: str
    safety_class: str
    verification_policy: Dict[str, Any]
    rollback_policy: Dict[str, Any]
    depends_on: List[str]
    enabled: bool
    created_at: str
    updated_at: str


class ResponsePlaybookCreate(BaseModel):
    workspace_id: str = "default"
    playbook_key: str
    name: str
    description: str
    version: int = 1
    status: PlaybookStatusEnum = PlaybookStatusEnum.DRAFT
    trigger_type: PlaybookTriggerTypeEnum = PlaybookTriggerTypeEnum.MANUAL
    scope_type: str = "EVENT"
    severity_min: Optional[str] = None
    risk_min: Optional[float] = None
    incident_id: Optional[str] = None
    investigation_id: Optional[str] = None
    source_recommendation_id: Optional[str] = None
    target_selector: Dict[str, Any] = Field(default_factory=dict)
    approval_policy: ApprovalPolicyEnum = ApprovalPolicyEnum.SINGLE_APPROVAL
    execution_policy: ExecutionPolicyEnum = ExecutionPolicyEnum.MANUAL
    timeout_seconds: int = 300
    max_runtime_seconds: int = 600
    change_summary: Optional[str] = None
    created_by: str = "system"
    steps: List[ResponsePlaybookStepCreate] = Field(default_factory=list)


class ResponsePlaybookUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    status: Optional[PlaybookStatusEnum] = None
    approval_policy: Optional[ApprovalPolicyEnum] = None
    execution_policy: Optional[ExecutionPolicyEnum] = None
    change_summary: Optional[str] = None
    updated_by: str = "system"


class ResponsePlaybookResponse(BaseModel):
    id: str
    workspace_id: str
    playbook_key: str
    name: str
    description: str
    version: int
    status: str
    trigger_type: str
    scope_type: str
    severity_min: Optional[str] = None
    risk_min: Optional[float] = None
    incident_id: Optional[str] = None
    investigation_id: Optional[str] = None
    source_recommendation_id: Optional[str] = None
    target_selector: Dict[str, Any]
    approval_policy: str
    execution_policy: str
    timeout_seconds: int
    max_runtime_seconds: int
    parent_version: Optional[int] = None
    change_summary: Optional[str] = None
    created_by: str
    updated_by: str
    approved_by: Optional[str] = None
    approved_at: Optional[str] = None
    activated_at: Optional[str] = None
    retired_at: Optional[str] = None
    created_at: str
    updated_at: str
    steps: List[ResponsePlaybookStepResponse] = Field(default_factory=list)


class ResponsePlaybookSummary(BaseModel):
    id: str
    workspace_id: str
    playbook_key: str
    name: str
    version: int
    status: str
    trigger_type: str
    scope_type: str
    step_count: int
    approval_policy: str
    created_at: str
    updated_at: str


# ============================================================================
# VALIDATION & LINTER SCHEMAS
# ============================================================================

class PlaybookValidationResult(BaseModel):
    valid: bool
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    lint_notices: List[str] = Field(default_factory=list)


# ============================================================================
# SIMULATION / DRY-RUN SCHEMAS
# ============================================================================

class SimulationPlanStep(BaseModel):
    sequence: int
    step_key: str
    step_type: str
    name: str
    target_snapshot: TargetSnapshot
    capability_state: str
    capability_provider: str
    requires_approval: bool
    simulated_action: str
    safety_class: str
    rollback_available: bool
    would_execute: bool
    reason: str


class SimulationPlan(BaseModel):
    playbook_id: str
    playbook_key: str
    playbook_version: int
    mode: str = "DRY_RUN"
    total_steps: int
    steps: List[SimulationPlanStep]
    validation: PlaybookValidationResult
    capabilities_required: List[Dict[str, str]]
    approval_required_overall: bool
    summary: str


# ============================================================================
# EXECUTION & APPROVAL SCHEMAS
# ============================================================================

class PlaybookExecuteRequest(BaseModel):
    mode: ExecutionModeEnum = ExecutionModeEnum.LIVE
    requested_by: str = "analyst"
    target_override: Optional[TargetRef] = None
    execution_context: Dict[str, Any] = Field(default_factory=dict)


class PlaybookApprovalRequest(BaseModel):
    step_id: Optional[str] = None
    scope: str = "EXECUTION"  # EXECUTION, STEP
    decision: ApprovalDecisionEnum
    approved_by: str
    reason: str


class ResponsePlaybookApprovalResponse(BaseModel):
    id: str
    execution_id: str
    step_id: Optional[str] = None
    scope: str
    decision: str
    requested_by: str
    approved_by: Optional[str] = None
    reason: str
    target_snapshot: Dict[str, Any]
    authorization_context: Dict[str, Any]
    created_at: str
    decided_at: Optional[str] = None


class ResponsePlaybookStepExecutionResponse(BaseModel):
    id: str
    execution_id: str
    step_id: Optional[str] = None
    step_key: str
    sequence: int
    target_snapshot: Dict[str, Any]
    status: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    attempt_count: int
    adapter: str
    adapter_version: str
    input_summary: Dict[str, Any]
    output_summary: Dict[str, Any]
    verification_result: Dict[str, Any]
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    evidence_refs: List[str] = Field(default_factory=list)
    audit_event_id: Optional[str] = None
    idempotency_key: Optional[str] = None
    created_at: str


class ResponsePlaybookExecutionResponse(BaseModel):
    id: str
    playbook_id: str
    playbook_version: int
    incident_id: Optional[str] = None
    investigation_id: Optional[str] = None
    source_recommendation_id: Optional[str] = None
    trigger_source: str
    mode: str
    status: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    requested_by: str
    approved_by: Optional[str] = None
    current_step_key: Optional[str] = None
    result_summary: str
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    execution_context: Dict[str, Any]
    workspace_id: str
    created_at: str
    updated_at: str
    step_executions: List[ResponsePlaybookStepExecutionResponse] = Field(default_factory=list)
    approvals: List[ResponsePlaybookApprovalResponse] = Field(default_factory=list)


class FromRecommendationRequest(BaseModel):
    recommendation_id: str
    requested_by: str = "analyst"
    auto_stage: bool = True
