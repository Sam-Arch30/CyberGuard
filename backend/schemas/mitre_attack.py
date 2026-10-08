"""
Unified MITRE ATT&CK Mapping & Adversary Technique Intelligence Schemas (Section 19).
Defines canonical Pydantic V2 schemas for ATT&CK tactics, techniques, mapping rules,
evidence validation, technique sequences, tactic timelines, coverage assessments,
environment exclusions, and LLM suggestion validation.

CORE PRINCIPLES:
1. ATT&CK IS A TAXONOMY & ANALYTICAL FRAMEWORK, not proof of compromise or attacker identity.
2. NO KEYWORD-ONLY MAPPING: Keyword presence alone ("PowerShell", "password", "email")
   must never trigger an ATT&CK mapping without verified behavior, context, and evidence.
3. PRESERVE EPISTEMIC STATUS: Differentiate between SUPPORTED, PLAUSIBLE,
   INSUFFICIENT_EVIDENCE, and REJECTED technique mappings.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Union
from pydantic import BaseModel, Field, ConfigDict, field_validator

from backend.schemas.attack_confidence import ConfidenceLevel


# ============================================================================
# 1. CANONICAL ENUMS
# ============================================================================

class AttackMappingStatus(str, Enum):
    """
    Forensic certainty status for MITRE ATT&CK mappings.
    """
    SUPPORTED = "SUPPORTED"                        # Direct normalized evidence satisfies the mapping rule
    PLAUSIBLE = "PLAUSIBLE"                        # Consistent with technique but evidence is indirect or incomplete
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE" # Candidate technique considered but required evidence is missing
    REJECTED = "REJECTED"                          # Considered and explicitly contradicted or excluded by context


class MappingMethod(str, Enum):
    """
    Method by which candidate technique mapping was produced.
    """
    RULE_BASED = "RULE_BASED"
    STRUCTURED_EVENT = "STRUCTURED_EVENT"
    BEHAVIORAL_PATTERN = "BEHAVIORAL_PATTERN"
    ATTACK_STAGE_MAPPING = "ATTACK_STAGE_MAPPING"
    ANALYST_ASSIGNED = "ANALYST_ASSIGNED"
    IMPORT_FROM_EXTERNAL_SOURCE = "IMPORT_FROM_EXTERNAL_SOURCE"
    LLM_SUGGESTED = "LLM_SUGGESTED"                # Strictly never automatically SUPPORTED


class AnalystDispositionEnum(str, Enum):
    """
    Analyst triage and disposition for mapped ATT&CK techniques.
    """
    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    MODIFIED = "MODIFIED"
    PENDING = "PENDING"


# ============================================================================
# 2. CANONICAL ATT&CK TAXONOMY MODELS
# ============================================================================

class AttackTactic(BaseModel):
    """
    Canonical representation of a MITRE ATT&CK tactic.
    """
    model_config = ConfigDict(extra="ignore")

    tactic_id: str = Field(description="MITRE Tactic ID (e.g. TA0001)")
    name: str = Field(description="Tactic Name (e.g. Initial Access)")
    short_name: str = Field(description="URL-friendly short name (e.g. initial-access)")
    description: str = Field(description="Concise description of the tactical goal")
    order: int = Field(default=1, description="Relative chronological matrix phase order")

    @field_validator("tactic_id")
    @classmethod
    def validate_tactic_id(cls, v: str) -> str:
        v_clean = v.strip().upper()
        if not re.match(r"^TA\d{4}$", v_clean):
            raise ValueError(f"Invalid MITRE tactic ID: {v}. Expected format TA####.")
        return v_clean


class AttackTechnique(BaseModel):
    """
    Canonical representation of a MITRE ATT&CK technique or sub-technique.
    """
    model_config = ConfigDict(extra="ignore")

    technique_id: str = Field(description="MITRE Technique ID (e.g. T1566 or T1566.002)")
    name: str = Field(description="Technique Name (e.g. Spearphishing Link)")
    description: str = Field(description="Concise analytical summary from local dataset")
    tactic_ids: List[str] = Field(default_factory=list, description="Associated MITRE Tactic IDs")
    parent_technique_id: Optional[str] = Field(default=None, description="Parent Technique ID if subtechnique")
    is_subtechnique: bool = Field(default=False, description="True if subtechnique")
    platforms: List[str] = Field(default_factory=list, description="Supported target platforms")
    version: str = Field(default="v15.1", description="Dataset ATT&CK version")
    is_deprecated: bool = Field(default=False, description="True if marked deprecated in ATT&CK")
    is_revoked: bool = Field(default=False, description="True if revoked by another technique")
    revoked_by: Optional[str] = Field(default=None, description="Technique ID that revoked this technique")
    data_sources: List[str] = Field(default_factory=list, description="ATT&CK Data Sources")
    source: str = Field(default="MITRE ATT&CK Enterprise", description="Dataset source attribution")
    retrieved_at: Optional[datetime] = Field(default=None, description="Dataset release timestamp")

    @field_validator("technique_id")
    @classmethod
    def validate_technique_id(cls, v: str) -> str:
        v_clean = v.strip().upper()
        if not re.match(r"^T\d{4}(\.\d{3})?$", v_clean):
            raise ValueError(f"Invalid MITRE technique ID: {v}. Expected format T#### or T####.###.")
        return v_clean


# ============================================================================
# 3. RULE-BASED MAPPING ENGINE SPECIFICATION
# ============================================================================

class AttackTechniqueRule(BaseModel):
    """
    Versioned declarative rule for mapping observations to an ATT&CK technique.
    """
    model_config = ConfigDict(extra="ignore")

    id: str = Field(description="Unique rule ID (e.g. RULE-T1110.003-AUTH-SPRAY)")
    name: str = Field(description="Descriptive rule title")
    version: str = Field(default="1.0.0", description="Rule definition version")
    technique_id: str = Field(description="Target MITRE Technique ID")
    subtechnique_id: Optional[str] = Field(default=None, description="Target Sub-technique ID if applicable")
    tactic_ids: List[str] = Field(default_factory=list, description="Resulting Tactic IDs")
    required_events: List[str] = Field(default_factory=list, description="Required SecurityEvent types")
    required_findings: List[str] = Field(default_factory=list, description="Required Finding types")
    required_stage_types: List[str] = Field(default_factory=list, description="Required AttackStage types")
    required_context: Dict[str, Any] = Field(default_factory=dict, description="Required context constraints")
    excluded_context: List[str] = Field(default_factory=list, description="Context conditions that invalidate mapping")
    minimum_confidence: float = Field(default=0.5, ge=0.0, le=1.0, description="Minimum evidence score required")
    explanation_template: str = Field(default="", description="Grounding explanation rationale template")
    limitations_template: List[str] = Field(default_factory=list, description="Caveats and missing telemetry")


# ============================================================================
# 4. TECHNIQUE MAPPING MODEL
# ============================================================================

class AttackTechniqueMapping(BaseModel):
    """
    Discrete evidence-grounded mapping from CyberGuard observations to an ATT&CK technique.
    """
    model_config = ConfigDict(extra="ignore")

    id: str = Field(description="Unique UUID for this technique mapping")
    incident_id: Optional[str] = Field(default=None, description="Associated Incident UUID")
    source_type: str = Field(description="SECURITY_EVENT, FINDING, THREAT_EVENT, ATTACK_STAGE, ATTACK_PATH, HYPOTHESIS")
    source_id: str = Field(description="Underlying source record ID")
    technique_id: str = Field(description="MITRE Technique ID (e.g. T1110.003)")
    technique_name: str = Field(description="Technique title")
    subtechnique_id: Optional[str] = Field(default=None, description="Subtechnique ID if specific")
    tactic_ids: List[str] = Field(default_factory=list, description="Derived Tactic IDs")
    tactic_names: List[str] = Field(default_factory=list, description="Derived Tactic names")
    status: AttackMappingStatus = Field(default=AttackMappingStatus.SUPPORTED)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Heuristic evidence strength (Section 18)")
    confidence_level: ConfidenceLevel = Field(default=ConfidenceLevel.HIGH)
    evidence_ids: List[str] = Field(default_factory=list, description="Underlying FindingEvidence UUIDs")
    finding_ids: List[str] = Field(default_factory=list, description="Underlying Finding UUIDs")
    event_ids: List[str] = Field(default_factory=list, description="Underlying SecurityEvent UUIDs")
    stage_ids: List[str] = Field(default_factory=list, description="Underlying AttackStage UUIDs")
    mapping_method: MappingMethod = Field(default=MappingMethod.RULE_BASED)
    mapping_rule_id: Optional[str] = Field(default=None, description="ID of rule that generated this mapping")
    explanation: str = Field(default="", description="Clear why-this-technique explanation")
    limitations: List[str] = Field(default_factory=list, description="Explicit boundaries and missing telemetry")
    contradictions: List[str] = Field(default_factory=list, description="Conflicting facts or baseline notes")
    attack_version: str = Field(default="v15.1", description="ATT&CK Enterprise dataset version")
    engine_version: str = Field(default="1.0.0")
    configuration_version: str = Field(default="2026.10")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    analyst_disposition: Optional[str] = Field(default=None)
    analyst_notes: Optional[str] = Field(default=None)
    metadata: Dict[str, Any] = Field(default_factory=dict)


# ============================================================================
# 5. SEQUENCE, TIMELINE, AND COVERAGE SCHEMAS
# ============================================================================

class AttackTechniqueSequence(BaseModel):
    """
    Time-ordered observed sequence of mapped ATT&CK techniques for an incident.
    Does NOT assert that technique ordering was required by the adversary.
    """
    model_config = ConfigDict(extra="ignore")

    sequence_id: str = Field(description="Unique UUID for sequence")
    incident_id: str = Field(description="Parent Incident UUID")
    technique_mappings: List[AttackTechniqueMapping] = Field(default_factory=list)
    ordered_by_time: bool = Field(default=True)
    stage_ids: List[str] = Field(default_factory=list)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    confidence_level: ConfidenceLevel = Field(default=ConfidenceLevel.HIGH)
    explanation: str = Field(default="")


class TacticTimelineEntry(BaseModel):
    """
    Tactic-grouped chronological entry for analyst UI / timeline view.
    """
    model_config = ConfigDict(extra="ignore")

    tactic_id: str
    tactic_name: str
    order: int
    earliest_time: Optional[datetime] = None
    latest_time: Optional[datetime] = None
    mappings: List[AttackTechniqueMapping] = Field(default_factory=list)


class AttackCoverageSummary(BaseModel):
    """
    Analytical coverage summary of supported, plausible, and unmapped behaviors.
    Does NOT compute an arbitrary percentage coverage metric.
    """
    model_config = ConfigDict(extra="ignore")

    supported_count: int = 0
    plausible_count: int = 0
    insufficient_count: int = 0
    rejected_count: int = 0
    supported_techniques: List[str] = Field(default_factory=list)
    plausible_techniques: List[str] = Field(default_factory=list)
    insufficient_techniques: List[str] = Field(default_factory=list)
    rejected_techniques: List[str] = Field(default_factory=list)
    unmapped_behaviors: List[str] = Field(
        default_factory=list,
        description="Identified behaviors without confident ATT&CK mapping (Req 38)"
    )


# ============================================================================
# 6. ENVIRONMENT CONTEXT & EXCLUSION CONFIGURATION
# ============================================================================

class EnvironmentContextConfig(BaseModel):
    """
    Authorized configuration for corporate scanners, monitoring, and infrastructure.
    Prevents false-positive brute force or discovery technique mappings.
    """
    model_config = ConfigDict(extra="ignore")

    trusted_scanners: List[str] = Field(default_factory=list, description="IPs, FQDNs, or IDs of vulnerability scanners")
    monitoring_systems: List[str] = Field(default_factory=list, description="Health check / synthetic monitor IPs")
    authorized_service_accounts: List[str] = Field(default_factory=list, description="Service accounts authorized for bulk export")
    corporate_vpn_ranges: List[str] = Field(default_factory=list, description="Known corporate egress CIDR ranges")
    corporate_proxies: List[str] = Field(default_factory=list, description="Authorized corporate proxy egresses")
    version: str = Field(default="1.0.0")
    last_updated: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ============================================================================
# 7. LLM SUGGESTION & VALIDATION SCHEMAS
# ============================================================================

class LLMTechniqueSuggestion(BaseModel):
    """
    Structured suggestion payload from auxiliary LLM.
    """
    model_config = ConfigDict(extra="ignore")

    candidate_technique_id: str
    reason: str
    source_stage_or_event_id: Optional[str] = None
    confidence_suggestion: Optional[float] = None


class LLMValidationResult(BaseModel):
    """
    Deterministic validation output for an LLM candidate technique suggestion.
    """
    model_config = ConfigDict(extra="ignore")

    suggested_technique_id: str
    technique_exists: bool
    technique_name: Optional[str] = None
    is_deprecated: bool = False
    is_revoked: bool = False
    rule_satisfied: bool
    contradicted: bool
    resulting_status: AttackMappingStatus # PLAUSIBLE, INSUFFICIENT_EVIDENCE, REJECTED
    explanation: str
    resulting_mapping: Optional[AttackTechniqueMapping] = None


# ============================================================================
# 8. INCIDENT-LEVEL MITRE ATT&CK ASSESSMENT & REPORT
# ============================================================================

class MitreAttackAnalysisReport(BaseModel):
    """
    Complete MITRE ATT&CK Assessment formatted for executive and technical reports.
    Preserves epistemically safe language ("CyberGuard mapped observed activity to...").
    """
    model_config = ConfigDict(extra="ignore")

    incident_id: str
    attack_version: str = "v15.1"
    engine_version: str = "1.0.0"
    tactics_present: List[str] = Field(default_factory=list)
    supported_mappings: List[AttackTechniqueMapping] = Field(default_factory=list)
    plausible_mappings: List[AttackTechniqueMapping] = Field(default_factory=list)
    insufficient_mappings: List[AttackTechniqueMapping] = Field(default_factory=list)
    rejected_mappings: List[AttackTechniqueMapping] = Field(default_factory=list)
    coverage_summary: AttackCoverageSummary
    sequence: Optional[AttackTechniqueSequence] = None
    tactic_timeline: List[TacticTimelineEntry] = Field(default_factory=list)
    executive_summary: str = Field(description="Epistemically safe executive summary")
    analyst_summary: str = Field(description="Technical summary with evidence counts")
    limitations: List[str] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
