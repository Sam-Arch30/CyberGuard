"""
Pydantic v2 Schemas for Section 30: LLM SOC Copilot.
Defines schemas for conversations, messages, context snapshots, citations, claim validation, tools, and feedback.
"""

from __future__ import annotations
from enum import Enum
from typing import Dict, Any, List, Optional
from datetime import datetime
from pydantic import BaseModel, Field


class CopilotModeEnum(str, Enum):
    ANALYST = "ANALYST"
    EXECUTIVE = "EXECUTIVE"
    FORENSIC = "FORENSIC"
    COMPARISON = "COMPARISON"


class IntentEnum(str, Enum):
    INCIDENT_SUMMARY = "INCIDENT_SUMMARY"
    EVIDENCE_QUERY = "EVIDENCE_QUERY"
    FINDING_EXPLANATION = "FINDING_EXPLANATION"
    RISK_EXPLANATION = "RISK_EXPLANATION"
    TIMELINE_QUERY = "TIMELINE_QUERY"
    ATTACK_PATH_QUERY = "ATTACK_PATH_QUERY"
    GRAPH_QUERY = "GRAPH_QUERY"
    THREAT_MEMORY_QUERY = "THREAT_MEMORY_QUERY"
    MITRE_QUERY = "MITRE_QUERY"
    RESPONSE_QUERY = "RESPONSE_QUERY"
    REPORT_GENERATION = "REPORT_GENERATION"
    COMPARISON = "COMPARISON"
    GENERAL_CYBERGUARD_HELP = "GENERAL_CYBERGUARD_HELP"
    UNKNOWN = "UNKNOWN"


class SemanticTypeEnum(str, Enum):
    OBSERVED_FACT = "OBSERVED_FACT"
    DERIVED_INFERENCE = "DERIVED_INFERENCE"
    HYPOTHESIS = "HYPOTHESIS"
    RECOMMENDATION = "RECOMMENDATION"
    ACTION_OPTION = "ACTION_OPTION"


class ValidationStatusEnum(str, Enum):
    SUPPORTED = "SUPPORTED"
    PARTIALLY_SUPPORTED = "PARTIALLY_SUPPORTED"
    UNSUPPORTED = "UNSUPPORTED"
    UNVERIFIABLE = "UNVERIFIABLE"


class CitationSourceTypeEnum(str, Enum):
    EVIDENCE = "EVIDENCE"
    FINDING = "FINDING"
    THREAT_EVENT = "THREAT_EVENT"
    ANALYSIS_RUN = "ANALYSIS_RUN"
    RISK_ASSESSMENT = "RISK_ASSESSMENT"
    ATTACK_STAGE = "ATTACK_STAGE"
    ATTACK_PATH = "ATTACK_PATH"
    MITRE_MAPPING = "MITRE_MAPPING"
    THREAT_MEMORY_ENTRY = "THREAT_MEMORY_ENTRY"
    RESPONSE_RECOMMENDATION = "RESPONSE_RECOMMENDATION"
    RESPONSE_PLAYBOOK_EXECUTION = "RESPONSE_PLAYBOOK_EXECUTION"


class MessageRoleEnum(str, Enum):
    USER = "USER"
    ASSISTANT = "ASSISTANT"
    SYSTEM = "SYSTEM"
    TOOL = "TOOL"


class MessageTypeEnum(str, Enum):
    QUESTION = "QUESTION"
    ANSWER = "ANSWER"
    SUMMARY = "SUMMARY"
    EXPLANATION = "EXPLANATION"
    INVESTIGATION_RESULT = "INVESTIGATION_RESULT"
    RECOMMENDATION_SUMMARY = "RECOMMENDATION_SUMMARY"
    REPORT_DRAFT = "REPORT_DRAFT"
    ERROR = "ERROR"


class FeedbackRatingEnum(str, Enum):
    HELPFUL = "HELPFUL"
    NOT_HELPFUL = "NOT_HELPFUL"
    INCORRECT = "INCORRECT"
    MISSING_EVIDENCE = "MISSING_EVIDENCE"


# ============================================================================
# STRUCTURED CITATIONS & CLAIMS
# ============================================================================

class CopilotCitation(BaseModel):
    citation_id: str
    source_type: CitationSourceTypeEnum
    source_id: str
    source_version: Optional[str] = None
    claim_span: str
    title: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class CopilotClaim(BaseModel):
    claim_text: str
    semantic_type: SemanticTypeEnum = SemanticTypeEnum.DERIVED_INFERENCE
    validation_status: ValidationStatusEnum = ValidationStatusEnum.SUPPORTED
    supporting_evidence_ids: List[str] = Field(default_factory=list)
    notes: Optional[str] = None


# ============================================================================
# CONTEXT SNAPSHOT
# ============================================================================

class ContextSnapshotResponse(BaseModel):
    id: str
    conversation_id: str
    scope: str
    investigation_id: Optional[str] = None
    incident_id: Optional[str] = None
    context_version: str = "1.0.0"
    retrieved_entity_ids: List[str] = Field(default_factory=list)
    retrieved_evidence_ids: List[str] = Field(default_factory=list)
    retrieved_finding_ids: List[str] = Field(default_factory=list)
    risk_assessment_version: Optional[int] = None
    attack_path_version: Optional[str] = None
    explanation_version: Optional[int] = None
    threat_memory_snapshot: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


# ============================================================================
# CONVERSATION & MESSAGE SCHEMAS
# ============================================================================

class CreateConversationRequest(BaseModel):
    title: Optional[str] = None
    investigation_id: Optional[str] = None
    incident_id: Optional[str] = None
    workspace_id: str = "default"
    model_provider: Optional[str] = None
    model_name: Optional[str] = None


class ConversationResponse(BaseModel):
    id: str
    workspace_id: str
    investigation_id: Optional[str] = None
    incident_id: Optional[str] = None
    title: str
    status: str
    created_by: str
    model_provider: str
    model_name: str
    context_policy_version: str
    created_at: datetime
    updated_at: datetime
    message_count: int = 0


class PostMessageRequest(BaseModel):
    content: str
    mode: CopilotModeEnum = CopilotModeEnum.ANALYST
    user_id: str = "analyst"
    investigation_id: Optional[str] = None
    incident_id: Optional[str] = None
    target_scope_id: Optional[str] = None
    email_payload: Optional[Dict[str, Any]] = None
    include_tools: bool = True


class MessageResponse(BaseModel):
    id: str
    conversation_id: str
    role: MessageRoleEnum
    content: str
    message_type: MessageTypeEnum
    context_snapshot_id: Optional[str] = None
    model_provider: str
    model_name: str
    prompt_version: str
    claims: List[CopilotClaim] = Field(default_factory=list)
    citations: List[CopilotCitation] = Field(default_factory=list)
    uncertainties: List[str] = Field(default_factory=list)
    hypotheses: List[str] = Field(default_factory=list)
    next_steps: List[str] = Field(default_factory=list)
    tools_called: List[str] = Field(default_factory=list)
    latency_ms: Optional[float] = None
    created_at: datetime


class StructuredCopilotAnswer(BaseModel):
    assessment: str
    why: List[str] = Field(default_factory=list)
    attack_path: Optional[str] = None
    confidence: str = "HIGH"
    claims: List[CopilotClaim] = Field(default_factory=list)
    citations: List[CopilotCitation] = Field(default_factory=list)
    uncertainties: List[str] = Field(default_factory=list)
    hypotheses: List[str] = Field(default_factory=list)
    recommended_next_steps: List[str] = Field(default_factory=list)
    mode: CopilotModeEnum = CopilotModeEnum.ANALYST
    intent: IntentEnum = IntentEnum.UNKNOWN
    tools_used: List[str] = Field(default_factory=list)
    is_fallback: bool = False


class CopilotQueryRequest(BaseModel):
    query: str
    conversation_id: Optional[str] = None
    mode: CopilotModeEnum = CopilotModeEnum.ANALYST
    workspace_id: str = "default"
    investigation_id: Optional[str] = None
    incident_id: Optional[str] = None
    target_scope_id: Optional[str] = None
    email_payload: Optional[Dict[str, Any]] = None
    compare_run_ids: Optional[List[str]] = None


class FeedbackRequest(BaseModel):
    rating: FeedbackRatingEnum
    feedback_text: Optional[str] = None
    claim_incorrect: bool = False
    citation_incorrect: bool = False
    insufficient_context: bool = False
    analyst_id: str = "analyst"


class FeedbackResponse(BaseModel):
    id: str
    message_id: str
    conversation_id: str
    rating: FeedbackRatingEnum
    analyst_id: str
    feedback_text: Optional[str] = None
    created_at: datetime
