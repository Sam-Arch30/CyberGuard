"""
Pydantic Schemas for Section 39: Investigation Workspace.
Provides unified contracts for the persistent investigation workstation shell,
summary aggregation, status transitions, analyst notes, evidence browsing, and timeline.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from backend.schemas.analysis_results import (
    RiskHeaderSummary,
    FindingResultDetail,
)


class InvestigationSummaryModel(BaseModel):
    investigation_id: str
    incident_number: str
    title: str
    description: Optional[str] = None
    status: str = "OPEN"  # OPEN, INVESTIGATING, CONTAINED, RESOLVED, CLOSED, FALSE_POSITIVE
    severity: str = "MEDIUM"  # SAFE, LOW, MEDIUM, HIGH, CRITICAL
    risk_score: Optional[float] = None
    confidence: Optional[float] = None
    opened_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    assigned_to: Optional[str] = None
    artifact_name: str
    artifact_type: str
    artifact_id: Optional[str] = None
    sha256: Optional[str] = None


class InvestigationCountsModel(BaseModel):
    findings_count: int = 0
    evidence_count: int = 0
    indicators_count: int = 0
    attack_paths_count: int = 0
    timeline_events_count: int = 0
    response_actions_count: int = 0
    notes_count: int = 0


class AnalystNoteModel(BaseModel):
    id: str
    author: str = "SOC Analyst"
    note_text: str
    created_at: datetime = Field(default_factory=datetime.utcnow)


class InvestigationWorkspaceSummary(BaseModel):
    """
    Consolidated investigation summary for Section 39 workspace header, overview, and navigation.
    """
    investigation: InvestigationSummaryModel
    risk: RiskHeaderSummary
    classification: str
    executive_summary: str
    status: str
    counts: InvestigationCountsModel
    top_findings: List[FindingResultDetail] = Field(default_factory=list)
    attention_items: List[str] = Field(default_factory=list)
    analyst_notes: List[AnalystNoteModel] = Field(default_factory=list)
    last_updated: datetime = Field(default_factory=datetime.utcnow)

    model_config = ConfigDict(from_attributes=True)


class InvestigationStatusUpdate(BaseModel):
    status: str = Field(..., description="Target status: OPEN, INVESTIGATING, CONTAINED, RESOLVED, CLOSED, FALSE_POSITIVE")
    reason: Optional[str] = Field(None, description="Auditable justification for status transition")
    analyst: Optional[str] = Field("SOC Analyst", description="Name/identifier of analyst making change")


class InvestigationNoteCreate(BaseModel):
    note_text: str = Field(..., min_length=1, max_length=5000, description="Analyst note text")
    author: Optional[str] = Field("SOC Analyst", description="Author identity")


class InvestigationEvidenceItem(BaseModel):
    """
    Forensic evidence item distinguishing immutable original artifacts from derived analytic evidence.
    """
    id: str
    name: str
    evidence_type: str
    is_original: bool = False  # True for original files/attachments (.eml, .pdf), False for derived IOCs/signals
    sha256: Optional[str] = None
    size_bytes: Optional[int] = None
    source: str
    observed_at: datetime
    confidence: float = 1.0
    details: Dict[str, Any] = Field(default_factory=dict)


class InvestigationTimelineEventItem(BaseModel):
    """
    Chronological timeline entry linking threat events, audit logs, and evidence telemetry.
    """
    id: str
    timestamp: datetime
    event_type: str
    title: str
    description: str
    severity: str = "LOW"
    source: str
    confidence: float = 1.0
    evidence_ref: Optional[str] = None
