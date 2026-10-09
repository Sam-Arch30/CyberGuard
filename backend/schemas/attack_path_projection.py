"""
Schema definitions for Section 40: Interactive Attack Path.
Provides path-level projections of the Security Knowledge Graph,
Attack Stages, Transitions, Evidence Gaps, Contradictions,
Alternative Hypotheses, MITRE ATT&CK context, and Infrastructure context.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, ConfigDict


class AttackStageProjection(BaseModel):
    """
    Projection of an AttackStage node for interactive visualization.
    """
    model_config = ConfigDict(extra="ignore")

    id: str = Field(description="Stage UUID")
    stage_order: int = Field(default=1, description="Sequential position in path")
    stage_type: str = Field(description="Controlled vocabulary type (e.g. DELIVERY, SOCIAL_ENGINEERING)")
    stage_status: str = Field(description="OBSERVED, DERIVED, INFERRED, or UNRESOLVED")
    technique_id: Optional[str] = Field(default=None, description="MITRE ATT&CK Technique ID")
    tactic: Optional[str] = Field(default=None, description="MITRE ATT&CK Tactic")
    title: str = Field(description="Human readable stage title")
    description: Optional[str] = Field(default=None, description="Analytical description")
    start_time: Optional[datetime] = Field(default=None, description="Earliest observation timestamp")
    end_time: Optional[datetime] = Field(default=None, description="Latest observation timestamp")
    time_uncertainty: Optional[str] = Field(default=None, description="Temporal uncertainty note (e.g. ±15s)")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Calibrated confidence")
    confidence_level: str = Field(default="HIGH", description="VERY_HIGH, HIGH, MODERATE, LOW")
    entity_ids: List[str] = Field(default_factory=list)
    finding_ids: List[str] = Field(default_factory=list)
    evidence_ids: List[str] = Field(default_factory=list)
    event_ids: List[str] = Field(default_factory=list)
    evidence_count: int = Field(default=0)
    finding_count: int = Field(default=0)
    supporting_evidence: List[Dict[str, Any]] = Field(default_factory=list)
    contradicting_evidence: List[Dict[str, Any]] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    entities_detail: List[Dict[str, Any]] = Field(default_factory=list)
    findings_detail: List[Dict[str, Any]] = Field(default_factory=list)


class AttackTransitionProjection(BaseModel):
    """
    Projection of a directed transition edge between stages.
    Rigorously distinguishes causal links from temporal correlations.
    """
    model_config = ConfigDict(extra="ignore")

    id: str = Field(description="Transition UUID")
    from_stage_id: str = Field(description="Source stage UUID")
    to_stage_id: str = Field(description="Target stage UUID")
    relationship_type: str = Field(default="PRECEDES")
    edge_status: str = Field(default="DERIVED", description="OBSERVED, DERIVED, INFERRED")
    is_causal: bool = Field(default=False, description="True ONLY when authoritative causal evidence exists")
    relationship_label: str = Field(default="TEMPORAL ASSOCIATION")
    relationship_description: str = Field(default="")
    temporal_gap_seconds: Optional[float] = Field(default=None)
    temporal_gap_formatted: Optional[str] = Field(default=None)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    confidence_level: str = Field(default="HIGH")
    shared_entities: List[str] = Field(default_factory=list)
    supporting_evidence_count: int = Field(default=0)
    supporting_evidence: List[Dict[str, Any]] = Field(default_factory=list)
    contradicting_evidence: List[Dict[str, Any]] = Field(default_factory=list)


class AttackGapProjection(BaseModel):
    """
    Explicit missing telemetry or unresolved transition in the attack path.
    """
    model_config = ConfigDict(extra="ignore")

    id: str = Field(description="Gap identifier")
    category: str = Field(description="Gap category classification")
    title: str = Field(description="Concise description of what is missing")
    description: str = Field(description="Forensic context on missing evidence")
    affected_stage_ids: List[str] = Field(default_factory=list)
    impact: str = Field(description="Impact on reconstruction confidence")


class AttackContradictionProjection(BaseModel):
    """
    Conflicting telemetry or behavioral anomaly requiring investigator attention.
    """
    model_config = ConfigDict(extra="ignore")

    id: str = Field(description="Contradiction identifier")
    title: str = Field(description="Contradiction summary")
    description: str = Field(description="Detailed conflicting evidence explanation")
    conflicting_evidence: List[Dict[str, Any]] = Field(default_factory=list)
    assessment_impact: str = Field(description="Effect on path confidence")


class AttackAlternativeProjection(BaseModel):
    """
    Alternative hypothesis produced by the reconstruction engine.
    """
    model_config = ConfigDict(extra="ignore")

    id: str = Field(description="Hypothesis UUID")
    title: str = Field(description="Hypothesis title")
    description: Optional[str] = Field(default=None)
    status: str = Field(default="PLAUSIBLE")
    is_primary: bool = Field(default=False)
    stage_ids: List[str] = Field(default_factory=list)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    confidence_level: str = Field(default="MODERATE")
    missing_evidence: List[str] = Field(default_factory=list)
    supporting_evidence: List[Dict[str, Any]] = Field(default_factory=list)
    contradicting_evidence: List[Dict[str, Any]] = Field(default_factory=list)


class AttackPathDetailResponse(BaseModel):
    """
    Comprehensive response for Section 40 Interactive Attack Path workspace.
    """
    model_config = ConfigDict(extra="ignore")

    investigation_id: str
    incident_number: Optional[str] = None
    analysis_run_id: Optional[str] = None
    available_runs: List[Dict[str, Any]] = Field(default_factory=list)

    # Path Summary
    has_path: bool = False
    path_id: Optional[str] = None
    name: Optional[str] = None
    classification: Optional[str] = None
    status: str = "INCONCLUSIVE"  # ESTABLISHED, PARTIAL, SUPPORTED_HYPOTHESIS, LOW_CONFIDENCE, INCONCLUSIVE
    status_rationale: Optional[str] = None
    completeness_score: float = 0.0

    # Calibrated Confidence
    confidence: float = 0.0
    confidence_level: str = "LOW"
    confidence_components: Dict[str, Any] = Field(default_factory=dict)
    confidence_bottleneck: Optional[Dict[str, Any]] = None
    explanation: Dict[str, Any] = Field(default_factory=dict)

    # Time Bounds
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    duration_seconds: Optional[float] = None

    # Versioning & Forensics
    version: int = 1
    engine_version: str = "1.0.0"
    rule_version: str = "1.0.0"
    generated_at: Optional[datetime] = None

    # Graph Projections
    stages: List[AttackStageProjection] = Field(default_factory=list)
    transitions: List[AttackTransitionProjection] = Field(default_factory=list)
    gaps: List[AttackGapProjection] = Field(default_factory=list)
    contradictions: List[AttackContradictionProjection] = Field(default_factory=list)
    alternatives: List[AttackAlternativeProjection] = Field(default_factory=list)

    # Supporting Context
    mitre_techniques: List[Dict[str, Any]] = Field(default_factory=list)
    infrastructure: List[Dict[str, Any]] = Field(default_factory=list)
    timeline_events: List[Dict[str, Any]] = Field(default_factory=list)

    # Aggregate Counts
    total_evidence_count: int = 0
    total_findings_count: int = 0
    total_entities_count: int = 0

    # Forensics Limitations
    limitations: List[str] = Field(default_factory=list)
