"""
Pydantic Schemas for Section 38: Analysis Results + Progressive Disclosure.
Provides unified, evidence-backed contracts for executive, analyst, investigator,
and forensic inspection tiers.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


# ============================================================================
# 1. LEVEL 1: EXECUTIVE SCHEMAS
# ============================================================================

class RiskHeaderSummary(BaseModel):
    """
    Explicitly separated risk metrics.
    Risk Score != Severity != Confidence != Probability.
    """
    score: Optional[float] = Field(default=None, description="Unified risk score (0-100)")
    level: str = Field(default="UNKNOWN", description="INFO, LOW, MEDIUM, HIGH, CRITICAL, UNKNOWN")
    severity: str = Field(default="LOW", description="SAFE, LOW, MEDIUM, HIGH, CRITICAL")
    confidence: Optional[float] = Field(default=None, description="Calibrated evidence confidence (0.0-1.0)")
    confidence_level: str = Field(default="UNKNOWN", description="LOW, MODERATE, HIGH, VERY_HIGH, UNKNOWN")
    uncertainty: str = Field(default="LOW", description="LOW, MODERATE, HIGH")
    is_pending: bool = Field(default=False, description="True if assessment is still computing")
    status_label: str = Field(default="Risk assessment pending", description="Human-readable assessment status")


class WhyCyberGuardThinksThisItem(BaseModel):
    """
    Atomic evidence-backed assertion in Level 1.
    Must trace directly to structured findings and evidence references.
    """
    id: str
    claim: str
    support_level: str = "HIGH"  # CONFIRMED, VERY_HIGH, HIGH, MODERATE, WEAK
    confidence: float = 1.0
    evidence_count: int = 0
    evidence_refs: List[str] = Field(default_factory=list)


class NextStepRecommendation(BaseModel):
    """
    Immediate response preview CTA.
    """
    action_title: str
    action_description: str
    priority: str = "HIGH"  # CRITICAL, HIGH, MEDIUM, LOW
    target_route: Optional[str] = None


# ============================================================================
# 2. LEVEL 2: ANALYST SCHEMAS
# ============================================================================

class SupportingEvidencePreview(BaseModel):
    id: str
    evidence_type: str
    source: str
    key: str
    value: str
    confidence: float = 1.0
    artifact_id: Optional[str] = None
    observed_at: Optional[datetime] = None


class FindingResultDetail(BaseModel):
    """
    Structured finding with progressive expansion capabilities.
    """
    id: str
    analyzer: str
    finding_type: str
    title: str
    description: str
    severity: str
    confidence: float = 1.0
    risk_contribution: float = 0.0
    method: str = "RULE"
    rule_id: Optional[str] = None
    observed_value: Optional[str] = None
    expected_value: Optional[str] = None
    evidence_count: int = 0
    evidence_items: List[SupportingEvidencePreview] = Field(default_factory=list)
    counter_evidence: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class DomainIndicator(BaseModel):
    value: str
    severity: str = "LOW"
    first_seen: Optional[datetime] = None
    is_lookalike: bool = False
    reputation: Optional[str] = None


class URLIndicator(BaseModel):
    value: str
    severity: str = "LOW"
    first_seen: Optional[datetime] = None
    redirect_hops: int = 0
    is_lookalike: bool = False
    credential_harvesting: bool = False
    reputation: Optional[str] = None


class IPIndicator(BaseModel):
    value: str
    severity: str = "LOW"
    first_seen: Optional[datetime] = None
    country: Optional[str] = None
    asn: Optional[str] = None
    is_vpn_proxy: bool = False


class EmailIndicator(BaseModel):
    value: str
    severity: str = "LOW"
    first_seen: Optional[datetime] = None
    role: Optional[str] = None  # sender, recipient, return-path


class HashIndicator(BaseModel):
    value: str
    algorithm: str = "SHA-256"
    severity: str = "LOW"
    first_seen: Optional[datetime] = None


class AttachmentResultItem(BaseModel):
    filename: str
    mime_type: str
    size_bytes: int
    severity: str = "SAFE"
    risk_flag: Optional[str] = None
    sha256: Optional[str] = None


class IndicatorsSummary(BaseModel):
    total_count: int = 0
    domains: List[DomainIndicator] = Field(default_factory=list)
    urls: List[URLIndicator] = Field(default_factory=list)
    ips: List[IPIndicator] = Field(default_factory=list)
    emails: List[EmailIndicator] = Field(default_factory=list)
    hashes: List[HashIndicator] = Field(default_factory=list)
    attachments: List[AttachmentResultItem] = Field(default_factory=list)


class CounterEvidenceResultItem(BaseModel):
    id: str
    title: str
    description: str
    source: str
    strength: str = "MODERATE"
    impact: str = "Reduces probability of malicious intent"


class ContradictionResultItem(BaseModel):
    id: str
    topic: str
    supporting_claim: str
    contradicting_claim: str
    severity: str = "MEDIUM"


class UncertaintyAndGapsItem(BaseModel):
    topic: str
    description: str
    impact: str


class DigitalImpersonationSummary(BaseModel):
    claimed_identity: str
    observed_identity: str
    status: str  # MATCH, PARTIAL, MISMATCH, LOOKALIKE, INSUFFICIENT, UNKNOWN
    confidence: float = 1.0
    similarity_score: Optional[float] = None
    details: Optional[str] = None


class BehavioralAnomalyItem(BaseModel):
    metric: str
    status: str  # NORMAL, DEVIATION, ANOMALY
    deviation_score: float = 0.0
    baseline_value: Optional[str] = None
    observed_value: Optional[str] = None


class BehavioralSummary(BaseModel):
    baseline_quality: str = "MODERATE"  # LOW, MODERATE, HIGH
    total_anomalies: int = 0
    anomalies: List[BehavioralAnomalyItem] = Field(default_factory=list)


class NoveltySummary(BaseModel):
    novelty_score: float = 0.0
    novelty_level: str = "LOW"  # LOW, MODERATE, HIGH
    prior_observations_count: int = 0
    description: str = "Pattern previously observed"


class ThreatMemorySummary(BaseModel):
    previously_observed: bool = False
    total_observations: int = 0
    verified_malicious: int = 0
    dismissed_count: int = 0
    notes: Optional[str] = None


# ============================================================================
# 3. LEVEL 3: INVESTIGATOR SCHEMAS
# ============================================================================

class AttackStagePreview(BaseModel):
    stage_number: int
    stage_name: str
    tactic: str
    description: str


class AttackPathPreview(BaseModel):
    path_id: Optional[str] = None
    path_name: str = "Single-Stage Ingestion Attack"
    stages: List[AttackStagePreview] = Field(default_factory=list)
    confidence: str = "MODERATE"  # LOW, MODERATE, HIGH, VERY_HIGH
    stage_count: int = 1


class MITRETechniquePreview(BaseModel):
    technique_id: str  # e.g., T1566.002
    technique_name: str
    tactic: str
    status: str = "SUPPORTED"  # SUPPORTED, PLAUSIBLE, INSUFFICIENT, REJECTED
    confidence: float = 0.85


class InfrastructureAttributionPreview(BaseModel):
    observed_infrastructure: List[str] = Field(default_factory=list)
    associated_domains: List[str] = Field(default_factory=list)
    probable_origin_infrastructure: Optional[str] = None
    infrastructure_location: Optional[str] = None  # Strictly labeled 'Infrastructure location', NOT 'Attacker location'
    asn: Optional[str] = None
    confidence: str = "MODERATE"


class CampaignActivityContext(BaseModel):
    is_campaign: bool = False
    campaign_name: Optional[str] = None
    related_investigations_count: int = 0
    shared_indicators_count: int = 0
    dominant_attack_type: Optional[str] = None


# ============================================================================
# 4. LEVEL 4: FORENSIC & PROVENANCE SCHEMAS
# ============================================================================

class AnalysisRunHistoryItem(BaseModel):
    run_id: str
    run_number: int
    status: str
    overall_risk_score: Optional[float] = None
    completed_at: Optional[datetime] = None
    is_current: bool = False


class AnalysisProvenance(BaseModel):
    run_id: str
    engine_version: str = "2.0.0"
    risk_configuration_version: str = "2.4.0"
    rules_version: str = "3.1.0"
    models_version: str = "2.2.0"
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    audit_reference: Optional[str] = None


class ArtifactIdentity(BaseModel):
    id: str
    name: str
    artifact_type: str
    size: int
    sha256: Optional[str] = None
    source: str


# ============================================================================
# 5. UNIFIED AGGREGATED RESPONSE (CONSOLIDATED ENDPOINT)
# ============================================================================

class AnalysisResultsResponse(BaseModel):
    """
    Consolidated investigation-analysis response aggregating all 4 progressive
    disclosure levels. Prevents chatty, fragmented network calls.
    """
    run_id: str
    investigation_id: Optional[str] = None
    evidence_id: Optional[str] = None
    artifact: ArtifactIdentity

    # Status & Completeness
    status: str  # INITIALIZING, QUEUED, RUNNING, PARTIAL, COMPLETED, FAILED, CANCELLED
    analysis_completeness: str = "COMPLETE"  # COMPLETE, PARTIAL, DEGRADED
    completeness_message: Optional[str] = None
    total_tasks: int = 0
    completed_tasks: int = 0
    failed_tasks: int = 0

    # Level 1 — Executive
    risk: RiskHeaderSummary
    classification: str
    executive_summary: str
    why_cyberguard_thinks_this: List[WhyCyberGuardThinksThisItem] = Field(default_factory=list)
    next_step_recommendation: NextStepRecommendation

    # Level 2 — Analyst
    top_findings: List[FindingResultDetail] = Field(default_factory=list)
    indicators_summary: IndicatorsSummary = Field(default_factory=IndicatorsSummary)
    counter_evidence: List[CounterEvidenceResultItem] = Field(default_factory=list)
    contradictions: List[ContradictionResultItem] = Field(default_factory=list)
    uncertainty_and_gaps: List[UncertaintyAndGapsItem] = Field(default_factory=list)
    what_would_change_assessment: List[str] = Field(default_factory=list)
    digital_impersonation: Optional[DigitalImpersonationSummary] = None
    behavioral_deviations: Optional[BehavioralSummary] = None
    novelty: Optional[NoveltySummary] = None
    threat_memory: Optional[ThreatMemorySummary] = None

    # Level 3 — Investigator
    attack_path_preview: Optional[AttackPathPreview] = None
    mitre_preview: List[MITRETechniquePreview] = Field(default_factory=list)
    infrastructure_preview: Optional[InfrastructureAttributionPreview] = None
    campaign_context: Optional[CampaignActivityContext] = None

    # Level 4 — Forensic
    provenance: AnalysisProvenance
    run_history: List[AnalysisRunHistoryItem] = Field(default_factory=list)

    last_updated: datetime = Field(default_factory=datetime.utcnow)

    model_config = ConfigDict(from_attributes=True)


# ============================================================================
# 6. LAZY-LOAD EVIDENCE DETAIL SCHEMA
# ============================================================================

class EvidenceDetailResponse(BaseModel):
    """
    Detailed evidence record for reusable sliding drawer inspection.
    """
    id: str
    finding_id: Optional[str] = None
    evidence_type: str
    source: str
    key: str
    value: str  # Redacted of sensitive secrets
    raw_preview: Optional[str] = None
    confidence: float = 1.0
    artifact_id: Optional[str] = None
    sha256: Optional[str] = None
    detected_by: Optional[str] = None
    analysis_run_id: Optional[str] = None
    observed_at: datetime
    metadata: Dict[str, Any] = Field(default_factory=dict)
    linked_finding_title: Optional[str] = None
    provenance_chain: List[str] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)
