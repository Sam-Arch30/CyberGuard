"""
Section 67: Pydantic Schemas for Authoritative Case Management.
Coordinates investigations, incidents, evidence, tasks, decisions, response actions, and final resolution.
"""
from datetime import datetime
from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict


class CaseStatus(str, Enum):
    NEW = "NEW"
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    PENDING = "PENDING"
    ON_HOLD = "ON_HOLD"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"
    CANCELLED = "CANCELLED"

    # Backward compatibility with legacy lowercase values
    open = "OPEN"
    investigating = "IN_PROGRESS"
    resolved = "RESOLVED"
    escalated = "IN_PROGRESS"


class CaseSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    # Backward compatibility with legacy lowercase
    low = "LOW"
    medium = "MEDIUM"
    high = "HIGH"
    critical = "CRITICAL"


class CasePriority(str, Enum):
    P1_CRITICAL = "P1_CRITICAL"
    P2_HIGH = "P2_HIGH"
    P3_MEDIUM = "P3_MEDIUM"
    P4_LOW = "P4_LOW"


class CaseCategory(str, Enum):
    PHISHING = "PHISHING"
    ACCOUNT_TAKEOVER = "ACCOUNT_TAKEOVER"
    MALWARE = "MALWARE"
    MALICIOUS_ATTACHMENT = "MALICIOUS_ATTACHMENT"
    IMPERSONATION = "IMPERSONATION"
    CREDENTIAL_THEFT = "CREDENTIAL_THEFT"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    API_ABUSE = "API_ABUSE"
    NETWORK_ATTACK = "NETWORK_ATTACK"
    ENDPOINT_COMPROMISE = "ENDPOINT_COMPROMISE"
    FRAUD = "FRAUD"
    POLICY_VIOLATION = "POLICY_VIOLATION"
    OTHER = "OTHER"


class CaseClassification(str, Enum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"


class CaseResolutionCode(str, Enum):
    TRUE_POSITIVE = "TRUE_POSITIVE"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    BENIGN_ACTIVITY = "BENIGN_ACTIVITY"
    RESOLVED = "RESOLVED"
    NO_EVIDENCE = "NO_EVIDENCE"
    DUPLICATE = "DUPLICATE"
    RISK_ACCEPTED = "RISK_ACCEPTED"
    MITIGATED = "MITIGATED"
    OTHER = "OTHER"


class TaskStatus(str, Enum):
    TODO = "TODO"
    IN_PROGRESS = "IN_PROGRESS"
    BLOCKED = "BLOCKED"
    COMPLETED = "COMPLETED"
    CANCELLED = "CANCELLED"


class TaskPriority(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# -------------------------------------------------------------------------
# Sub-entity Schemas: Emails, Notes, Findings, Tasks
# -------------------------------------------------------------------------

class CaseEmailBase(BaseModel):
    email_id: str = Field(..., description="Unique email identifier or filename")
    email_sha256: Optional[str] = Field(None, description="SHA-256 hash of email")
    subject: Optional[str] = Field("Untitled Email", description="Subject line")
    sender: Optional[str] = Field("unknown", description="Sender address")
    threat_score: Optional[float] = Field(0.0, description="Evaluated threat score (0-100)")
    severity: Optional[str] = Field("LOW", description="Evaluated threat severity")


class CaseEmailCreateRequest(CaseEmailBase):
    indicators: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Extracted indicators for aggregation")


class CaseEmailResponse(CaseEmailBase):
    id: str
    case_id: str
    added_at: datetime

    model_config = ConfigDict(from_attributes=True)


class CaseNoteCreateRequest(BaseModel):
    author: Optional[str] = Field("SOC Analyst", description="Analyst name or username")
    note_text: str = Field(..., description="Analyst note or evidentiary observation")
    visibility: Optional[str] = Field("ANALYST", description="Visibility: ANALYST, TEAM, EXECUTIVE, CONFIDENTIAL")


class CaseNoteUpdateRequest(BaseModel):
    note_text: str = Field(..., description="Updated note text")
    visibility: Optional[str] = Field(None, description="Updated visibility tier")


class CaseNoteResponse(BaseModel):
    id: str
    case_id: str
    author: str
    note_text: str
    visibility: str = "ANALYST"
    created_at: datetime
    updated_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class CaseFindingCreateRequest(BaseModel):
    finding_type: str = Field(..., description="Classification category (e.g. lookalike_domain, credential_harvesting)")
    title: str = Field(..., description="Concise finding headline")
    description: str = Field(..., description="Detailed forensic description of finding")
    severity: Optional[CaseSeverity] = Field(CaseSeverity.MEDIUM, description="Finding severity level")


class CaseFindingResponse(BaseModel):
    id: str
    case_id: str
    finding_type: str
    title: str
    description: str
    severity: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class CaseTaskCreate(BaseModel):
    title: str = Field(..., description="Concise task title")
    description: Optional[str] = Field(None, description="Detailed task context and instructions")
    priority: Optional[TaskPriority] = Field(TaskPriority.MEDIUM, description="Task priority")
    assignee_id: Optional[str] = Field(None, description="Analyst assigned to task")
    team_id: Optional[str] = Field(None, description="Assigned team")
    due_at: Optional[datetime] = Field(None, description="Due date and time")
    order_index: Optional[int] = Field(0, description="Display order sequence")
    is_automated_recommendation: Optional[bool] = Field(False, description="Whether generated by Section 66 automation")
    source_action_id: Optional[str] = Field(None, description="Originating action ID")


class CaseTaskUpdate(BaseModel):
    title: Optional[str] = Field(None, description="Updated title")
    description: Optional[str] = Field(None, description="Updated description")
    status: Optional[TaskStatus] = Field(None, description="Updated status")
    priority: Optional[TaskPriority] = Field(None, description="Updated priority")
    assignee_id: Optional[str] = Field(None, description="Assigned analyst")
    team_id: Optional[str] = Field(None, description="Assigned team")
    due_at: Optional[datetime] = Field(None, description="Due deadline")
    order_index: Optional[int] = Field(None, description="Sort order")


class CaseTaskResponse(BaseModel):
    id: str
    case_id: str
    workspace_id: str
    title: str
    description: Optional[str] = None
    status: str
    priority: str
    assignee_id: Optional[str] = None
    team_id: Optional[str] = None
    due_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    completed_by: Optional[str] = None
    created_by: str
    order_index: int = 0
    is_automated_recommendation: bool = False
    source_action_id: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AuditLogResponse(BaseModel):
    id: str
    case_id: str
    action: str
    details: str
    user: Optional[str] = "SOC Analyst"
    timestamp: datetime

    model_config = ConfigDict(from_attributes=True)


class AggregatedIndicators(BaseModel):
    domains: List[str] = Field(default_factory=list, description="Unique domains across linked emails/findings")
    ips: List[str] = Field(default_factory=list, description="Unique IPs across linked emails/findings")
    urls: List[str] = Field(default_factory=list, description="Unique URLs across linked emails/findings")
    attachments: List[str] = Field(default_factory=list, description="Unique attachment filenames or hashes")


# -------------------------------------------------------------------------
# Case Action Requests
# -------------------------------------------------------------------------

class CaseCreateRequest(BaseModel):
    title: str = Field(..., description="Case title")
    description: Optional[str] = Field("", description="Detailed incident context and operational notes")
    status: Optional[CaseStatus] = Field(CaseStatus.OPEN, description="Initial case status")
    severity: Optional[CaseSeverity] = Field(CaseSeverity.MEDIUM, description="Initial case severity")
    priority: Optional[CasePriority] = Field(CasePriority.P3_MEDIUM, description="Initial operational priority")
    category: Optional[CaseCategory] = Field(CaseCategory.PHISHING, description="Threat classification category")
    classification: Optional[CaseClassification] = Field(CaseClassification.INTERNAL, description="Data sensitivity classification")
    owner_id: Optional[str] = Field(None, description="Assigned analyst ID")
    team_id: Optional[str] = Field(None, description="Assigned team ID")
    incident_id: Optional[str] = Field(None, description="Linked authoritative incident ID")
    primary_investigation_id: Optional[str] = Field(None, description="Linked authoritative investigation ID")
    campaign_id: Optional[str] = Field(None, description="Linked Section 65 threat campaign ID")
    tags: Optional[List[str]] = Field(default_factory=list, description="Operational tags")
    custom_fields: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Validated custom key-value pairs")
    affected_assets: Optional[List[str]] = Field(default_factory=list, description="Pointers to affected assets")
    affected_identities: Optional[List[str]] = Field(default_factory=list, description="Pointers to affected user accounts")
    related_alerts: Optional[List[str]] = Field(default_factory=list, description="Linked security alert IDs")
    related_evidence: Optional[List[str]] = Field(default_factory=list, description="Linked evidence record IDs")
    initial_email: Optional[CaseEmailCreateRequest] = Field(None, description="Optional email to immediately attach to new case")


class CaseUpdateRequest(BaseModel):
    title: Optional[str] = Field(None, description="Updated case title")
    description: Optional[str] = Field(None, description="Updated description")
    severity: Optional[CaseSeverity] = Field(None, description="Updated severity")
    priority: Optional[CasePriority] = Field(None, description="Updated operational priority")
    category: Optional[CaseCategory] = Field(None, description="Updated threat category")
    classification: Optional[CaseClassification] = Field(None, description="Updated data classification")
    status: Optional[CaseStatus] = Field(None, description="Updated lifecycle status")
    owner_id: Optional[str] = Field(None, description="Assigned owner ID")
    team_id: Optional[str] = Field(None, description="Assigned team ID")
    primary_investigation_id: Optional[str] = Field(None, description="Primary investigation identifier")
    campaign_id: Optional[str] = Field(None, description="Threat campaign ID")
    tags: Optional[List[str]] = Field(None, description="Updated tags")
    custom_fields: Optional[Dict[str, Any]] = Field(None, description="Updated custom fields")
    affected_assets: Optional[List[str]] = Field(None, description="Updated affected assets list")
    affected_identities: Optional[List[str]] = Field(None, description="Updated affected identities list")
    related_alerts: Optional[List[str]] = Field(None, description="Updated related alerts")
    related_evidence: Optional[List[str]] = Field(None, description="Updated related evidence")
    expected_version: Optional[int] = Field(None, description="Optimistic concurrency check version")


class CaseAssignRequest(BaseModel):
    owner_id: Optional[str] = Field(None, description="New owner analyst username/ID")
    team_id: Optional[str] = Field(None, description="New owner team ID")
    reason: Optional[str] = Field("Routine assignment", description="Auditable reason for change")


class CaseResolveRequest(BaseModel):
    resolution_code: CaseResolutionCode = Field(..., description="Disposition code")
    resolution_summary: str = Field(..., description="Detailed explanation of findings and actions taken")
    affected_identities: Optional[List[str]] = Field(None, description="Final confirmed affected identities")
    tags: Optional[List[str]] = Field(None, description="Post-incident tags")


class CaseCloseRequest(BaseModel):
    closure_notes: str = Field(..., description="Post-incident review and sign-off notes")
    force_close_tasks: Optional[bool] = Field(False, description="Automatically cancel any open tasks")


class CaseReopenRequest(BaseModel):
    reopen_reason: str = Field(..., description="Mandatory justification for reopening the case")


class CaseMergeRequest(BaseModel):
    source_case_ids: List[str] = Field(..., min_length=1, description="List of case IDs to merge into this target case")
    reason: str = Field(..., description="Auditable justification for merging cases")


class CaseLinkRequest(BaseModel):
    entity_type: str = Field(..., description="ALERT, INCIDENT, INVESTIGATION, EVIDENCE, RESPONSE_ACTION, CAMPAIGN, ASSET, IDENTITY")
    entity_id: str = Field(..., description="Identifier of the target entity")
    details: Optional[str] = Field(None, description="Contextual note describing the link")


# -------------------------------------------------------------------------
# Case Response Schemas
# -------------------------------------------------------------------------

class CaseListItemResponse(BaseModel):
    id: str
    case_number: str
    workspace_id: str
    title: str
    description: Optional[str] = ""
    severity: str
    priority: str
    status: str
    category: str
    classification: str
    owner_id: Optional[str] = None
    team_id: Optional[str] = None
    incident_id: Optional[str] = None
    primary_investigation_id: Optional[str] = None
    campaign_id: Optional[str] = None
    sla_status: str = "HEALTHY"
    next_sla_deadline: Optional[datetime] = None
    opened_at: datetime
    resolved_at: Optional[datetime] = None
    closed_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime
    email_count: int = 0
    note_count: int = 0
    finding_count: int = 0
    task_count: int = 0
    open_task_count: int = 0
    version: int = 1
    tags: List[str] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)


class CaseDetailResponse(BaseModel):
    id: str
    case_number: str
    workspace_id: str
    title: str
    description: Optional[str] = ""
    severity: str
    priority: str
    status: str
    category: str
    classification: str
    owner_id: Optional[str] = None
    team_id: Optional[str] = None
    created_by: str = "SYSTEM"
    incident_id: Optional[str] = None
    primary_investigation_id: Optional[str] = None
    campaign_id: Optional[str] = None
    sla_policy_id: Optional[str] = None
    sla_status: str = "HEALTHY"
    next_sla_deadline: Optional[datetime] = None
    opened_at: datetime
    resolved_at: Optional[datetime] = None
    resolved_by: Optional[str] = None
    resolution_code: Optional[str] = None
    resolution_summary: Optional[str] = None
    closed_at: Optional[datetime] = None
    closed_by: Optional[str] = None
    closure_notes: Optional[str] = None
    reopened_at: Optional[datetime] = None
    reopened_by: Optional[str] = None
    reopen_reason: Optional[str] = None
    duplicate_of_id: Optional[str] = None
    merged_into_id: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    custom_fields: Dict[str, Any] = Field(default_factory=dict)
    affected_assets: List[str] = Field(default_factory=list)
    affected_identities: List[str] = Field(default_factory=list)
    related_alerts: List[str] = Field(default_factory=list)
    related_evidence: List[str] = Field(default_factory=list)
    related_response_actions: List[str] = Field(default_factory=list)
    version: int = 1
    created_at: datetime
    updated_at: datetime

    emails: List[CaseEmailResponse] = Field(default_factory=list)
    notes: List[CaseNoteResponse] = Field(default_factory=list)
    findings: List[CaseFindingResponse] = Field(default_factory=list)
    tasks: List[CaseTaskResponse] = Field(default_factory=list)
    audit_logs: List[AuditLogResponse] = Field(default_factory=list)
    aggregated_indicators: AggregatedIndicators = Field(default_factory=AggregatedIndicators)

    model_config = ConfigDict(from_attributes=True)


class CaseListResponse(BaseModel):
    cases: List[CaseListItemResponse] = Field(default_factory=list)
    total: int = 0
    page: int = 1
    page_size: int = 50


class CaseTimelineEvent(BaseModel):
    id: str
    timestamp: datetime
    event_type: str
    title: str
    description: str
    actor: str = "SYSTEM"
    source: str = "CASE"
    metadata: Dict[str, Any] = Field(default_factory=dict)


class CaseMetricsSummary(BaseModel):
    total_cases: int = 0
    open_cases: int = 0
    in_progress_cases: int = 0
    resolved_cases: int = 0
    closed_cases: int = 0
    critical_cases: int = 0
    high_cases: int = 0
    sla_breached_cases: int = 0
    sla_warning_cases: int = 0
    unassigned_cases: int = 0
    overdue_tasks_count: int = 0
