from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class EvidenceCategory(str, Enum):
    CONFIRMED_EVIDENCE = "confirmed_evidence"
    PROBABLE_INFERENCE = "probable_inference"
    WEAK_HYPOTHESIS = "weak_hypothesis"
    UNAVAILABLE_INFORMATION = "unavailable_information"


class ConclusionType(str, Enum):
    THREAT_CLASSIFICATION = "THREAT_CLASSIFICATION"
    INFRASTRUCTURE_ATTRIBUTION = "INFRASTRUCTURE_ATTRIBUTION"
    CAMPAIGN_ASSOCIATION = "CAMPAIGN_ASSOCIATION"
    GEOLOCATION = "GEOLOCATION"
    LOOKALIKE_DOMAIN = "LOOKALIKE_DOMAIN"
    MALICIOUS_URL = "MALICIOUS_URL"
    NLP_CLASSIFICATION = "NLP_CLASSIFICATION"
    ATTACHMENT_VERDICT = "ATTACHMENT_VERDICT"


class EvaluatedEvidence(BaseModel):
    evidence_id: str = Field(..., description="Unique reference for this piece of forensic evidence")
    statement: str = Field(..., description="Observable empirical fact or forensic finding")
    source_module: str = Field(..., description="Service or module that provided the evidence")
    source_quality: float = Field(default=0.8, ge=0.0, le=1.0, description="Inherent quality or authority of data source (0.0 to 1.0)")
    reliability: float = Field(default=0.8, ge=0.0, le=1.0, description="Cryptographic or empirical reliability (0.0 to 1.0)")
    independence_cluster: Optional[str] = Field(None, description="Cluster ID for anti-double-counting (e.g. maxmind_derived_geo)")
    recency_days: Optional[float] = Field(None, description="Age of intelligence observation in days")
    specificity: float = Field(default=0.8, ge=0.0, le=1.0, description="Granularity/precision of match (0.0 to 1.0)")
    consistency: float = Field(default=0.8, ge=0.0, le=1.0, description="Agreement with surrounding signals (0.0 to 1.0)")
    raw_contribution: float = Field(..., description="Base points contributed before correlation discounting")
    effective_contribution: float = Field(..., description="Effective score contribution after deduplication and recency decay")
    is_conflicting: bool = Field(default=False, description="True if this evidence contradicts the conclusion statement")
    evidence_category: EvidenceCategory = Field(default=EvidenceCategory.PROBABLE_INFERENCE, description="Degree of certainty category")
    timestamp: Optional[str] = Field(None, description="ISO timestamp of observation")


class ForensicConclusion(BaseModel):
    conclusion_id: str = Field(..., description="Unique conclusion identifier (e.g. CONC-GEO-A1B2C3D4)")
    type: ConclusionType = Field(..., description="Category of forensic determination")
    statement: str = Field(..., description="Clear, defensible assertion answering 'What do we believe?'")
    confidence_score: float = Field(..., ge=0.0, le=100.0, description="Calibrated confidence score (0 to 100) without false precision")
    confidence_level: str = Field(..., description="Confidence tier: LOW, MODERATE, HIGH, VERY HIGH")
    supporting_evidence: List[EvaluatedEvidence] = Field(default_factory=list, description="Evidence items corroborating the conclusion")
    conflicting_evidence: List[EvaluatedEvidence] = Field(default_factory=list, description="Contradictory or anomalous evidence items")
    limitations: List[str] = Field(default_factory=list, description="Forensic disclaimers, visibility gaps, and technical bounds")
    source_modules: List[str] = Field(default_factory=list, description="List of modules that contributed telemetry")
    generated_at: str = Field(..., description="ISO timestamp when conclusion was computed")
    engine_version: str = Field("1.0.0", description="Version of the Evidence Confidence Engine algorithm")


class EmailConfidenceResponse(BaseModel):
    email_id: Optional[str] = Field(None, description="Associated email analysis ID")
    evidence_id: Optional[str] = Field(None, description="Associated chain-of-custody evidence ID")
    conclusions: List[ForensicConclusion] = Field(default_factory=list, description="List of generated forensic conclusions")
    overall_confidence_score: float = Field(..., ge=0.0, le=100.0, description="Aggregated confidence across all conclusions")
    overall_confidence_level: str = Field(..., description="Aggregated confidence tier (LOW, MODERATE, HIGH, VERY HIGH)")
    engine_version: str = Field("1.0.0", description="Version of the Evidence Confidence Engine algorithm")
    generated_at: str = Field(..., description="ISO timestamp of generation")
