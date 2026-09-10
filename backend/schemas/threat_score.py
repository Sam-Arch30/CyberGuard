from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class ThreatScoreContribution(BaseModel):
    """Legacy structured contribution for backward compatibility."""
    signal: str = Field(..., description="Machine identifier for the evaluated signal")
    label: str = Field(..., description="Human-readable title describing the signal")
    points: int = Field(..., description="Risk score points contributed by this signal")
    evidence: str = Field(..., description="Specific evidence string or snippet supporting this contribution")


class PositiveEvidence(BaseModel):
    """Legacy positive evidence for backward compatibility."""
    signal: str = Field(..., description="Machine identifier for the positive or neutral signal")
    label: str = Field(..., description="Human-readable description of the verified security control")
    evidence: str = Field(..., description="Supporting evidence details")


class ThreatSignalContribution(BaseModel):
    """
    Explainable threat signal contribution representing a discrete positive
    (risk-increasing) or negative (mitigating) forensic observation.
    """
    signal_id: str = Field(..., description="Unique machine identifier for this signal observation")
    category: str = Field(
        ...,
        description="Forensic category: authentication, sender_identity, domain_intelligence, "
                    "lookalike_detection, url_intelligence, infrastructure, email_content, "
                    "campaign_intelligence, attachments"
    )
    name: str = Field(..., description="Human-readable name of the evaluated signal")
    description: str = Field(..., description="Explanation of what was detected")
    why_it_matters: Optional[str] = Field(None, description="Security justification explaining why this signal impacts threat risk")
    raw_value: Optional[Any] = Field(None, description="Observed raw forensic value (e.g. 'fail', 0.94, 5 days)")
    normalized_value: float = Field(0.0, description="Normalized signal strength from 0.0 to 1.0")
    weight: float = Field(..., description="Configured rule weight applied to this signal")
    contribution: int = Field(..., description="Signed points added or subtracted from the threat score (e.g. +18 or -5)")
    direction: str = Field(..., description="'increase_risk' for threats, 'decrease_risk' for mitigations")
    confidence: float = Field(1.0, description="Confidence in this specific signal observation (0.0 to 1.0)")
    evidence_reference: Optional[str] = Field(None, description="Specific forensic artifact reference (domain, URL, IP, or evidence ID)")
    source: str = Field(..., description="Subsystem that extracted and validated this signal")


class CategoryScoreBreakdown(BaseModel):
    """Aggregated risk score and signal breakdown for an analytical domain."""
    category: str = Field(..., description="Category machine identifier")
    display_name: str = Field(..., description="Human-readable category title")
    risk_score: int = Field(0, description="Net points contributed by this category")
    positive_signals_count: int = Field(0, description="Count of risk-increasing signals in this category")
    mitigating_signals_count: int = Field(0, description="Count of risk-mitigating signals in this category")
    signals: List[ThreatSignalContribution] = Field(default_factory=list, description="All contributing signals in this category")


class ThreatScoreResult(BaseModel):
    """
    Complete explainable threat score result providing deterministic scoring,
    risk categorization, visual contribution breakdown, and audit metadata.
    """
    score: int = Field(..., description="Deterministic global threat score between 0 and 100")
    risk_level: str = Field("LOW", description="Risk level: LOW (0-24), SUSPICIOUS (25-49), HIGH (50-74), CRITICAL (75-100)")
    severity: str = Field("low", description="Legacy severity classification: low, suspicious, high, or critical")
    confidence: str = Field("MODERATE", description="Evidence confidence tier: LOW, MODERATE, HIGH, or VERY HIGH")
    positive_contributions: List[ThreatSignalContribution] = Field(
        default_factory=list,
        description="Structured risk-increasing signals that elevated the score"
    )
    negative_contributions: List[ThreatSignalContribution] = Field(
        default_factory=list,
        description="Structured mitigating signals that reduced the score"
    )
    top_reasons: List[str] = Field(default_factory=list, description="Top threat drivers formatted for quick executive review")
    reasons: List[ThreatScoreContribution] = Field(
        default_factory=list,
        description="Legacy detailed list of positive risk contributions for backward compatibility"
    )
    positive_evidence: List[PositiveEvidence] = Field(
        default_factory=list,
        description="Legacy list of verified security controls for backward compatibility"
    )
    summary: str = Field("", description="Executive forensic summary explaining the threat score")
    why_flagged: Optional[str] = Field(
        None,
        description="Deterministic evidence-backed narrative explaining why this email was flagged"
    )
    category_breakdowns: Dict[str, CategoryScoreBreakdown] = Field(
        default_factory=dict,
        description="Categorized score contributions across all 9 risk domains"
    )
    model_version: str = Field("v1.0-tfidf-logistic", description="NLP text classification model version")
    scoring_version: str = Field("2.0.0-explainable", description="Threat scoring algorithm version")
    audit_metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Snapshot of weights, timestamps, and evidence IDs for historical reproducibility"
    )
