"""
REST API Routes for MITRE ATT&CK Mapping & Intelligence Engine (Section 19).
Exposes endpoints for tactics, techniques, incident mapping, path mapping,
tactic timelines, analyst feedback, LLM suggestion validation, and environment exclusions.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.db.models import AttackTechniqueMappingModel, AttackPathModel, IncidentModel
from backend.schemas.mitre_attack import (
    AnalystDispositionEnum,
    AttackCoverageSummary,
    AttackMappingStatus,
    AttackTactic,
    AttackTechnique,
    AttackTechniqueMapping,
    AttackTechniqueSequence,
    EnvironmentContextConfig,
    LLMTechniqueSuggestion,
    LLMValidationResult,
    MitreAttackAnalysisReport,
    TacticTimelineEntry,
)
from backend.services.mitre_dataset_service import global_mitre_dataset_service
from backend.services.mitre_mapping_engine import (
    MITREAttackMappingEngine,
    global_mitre_mapping_engine,
)
from backend.services.mitre_rules import MappingEvaluationContext

router = APIRouter(prefix="/api", tags=["MITRE ATT&CK Mapping"])


class AnalystFeedbackRequest(BaseModel):
    disposition: AnalystDispositionEnum = Field(description="CONFIRMED, REJECTED, NOT_APPLICABLE, MODIFIED")
    notes: Optional[str] = Field(default=None, description="Analyst reasoning notes")
    reviewed_by: Optional[str] = Field(default="SOC Analyst", description="Analyst identifier")


class ValidateLLMSuggestionRequest(BaseModel):
    suggestion: LLMTechniqueSuggestion
    context_attributes: Dict[str, Any] = Field(default_factory=dict)
    source_type: str = Field(default="HYPOTHESIS")
    source_id: str = Field(default="llm-eval-1")


# ============================================================================
# 1. TAXONOMY & DATASET ENDPOINTS
# ============================================================================

@router.get("/attack-mapping/tactics", response_model=List[AttackTactic])
def list_attack_tactics():
    """
    Returns all canonical Enterprise ATT&CK tactics in matrix phase order.
    """
    return global_mitre_dataset_service.list_tactics()


@router.get("/attack-mapping/techniques", response_model=List[AttackTechnique])
def list_attack_techniques(
    tactic_id: Optional[str] = Query(None, description="Filter by Tactic ID (e.g. TA0001)"),
    include_deprecated: bool = Query(False, description="Include deprecated / revoked techniques"),
    subtechniques_only: bool = Query(False, description="Filter for sub-techniques only")
):
    """
    Lists versioned Enterprise ATT&CK techniques with optional filtering.
    """
    return global_mitre_dataset_service.list_techniques(
        tactic_id=tactic_id,
        include_deprecated=include_deprecated,
        subtechniques_only=subtechniques_only
    )


@router.get("/attack-mapping/techniques/{technique_id}", response_model=AttackTechnique)
def get_attack_technique(technique_id: str):
    """
    Returns detailed canonical metadata for an ATT&CK technique or sub-technique.
    """
    tech = global_mitre_dataset_service.get_technique(technique_id)
    if not tech:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Technique '{technique_id}' not found in active ATT&CK dataset."
        )
    return tech


# ============================================================================
# 2. INCIDENT & PATH MAPPING ENDPOINTS
# ============================================================================

@router.post("/incidents/{incident_id}/mitre-map", response_model=MitreAttackAnalysisReport)
def map_incident_techniques(
    incident_id: str,
    db: Session = Depends(get_db)
):
    """
    Executes end-to-end evidence-driven ATT&CK mapping across all normalized observations
    in an Incident (Events, Findings, ThreatEvents, AttackStages).
    """
    inc = db.query(IncidentModel).filter(IncidentModel.id == incident_id).first()
    if not inc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found."
        )

    return global_mitre_mapping_engine.map_incident(incident_id, db=db, persist=True)


@router.get("/incidents/{incident_id}/mitre-mappings", response_model=List[AttackTechniqueMapping])
def get_incident_mitre_mappings(
    incident_id: str,
    status_filter: Optional[str] = Query(None, description="SUPPORTED, PLAUSIBLE, INSUFFICIENT_EVIDENCE, REJECTED"),
    db: Session = Depends(get_db)
):
    """
    Retrieves stored ATT&CK technique mappings for an incident.
    """
    query = db.query(AttackTechniqueMappingModel).filter(
        AttackTechniqueMappingModel.incident_id == incident_id
    )
    if status_filter:
        query = query.filter(AttackTechniqueMappingModel.status == status_filter.upper())

    records = query.all()
    results = []
    for r in records:
        results.append(
            AttackTechniqueMapping(
                id=r.id,
                incident_id=r.incident_id,
                source_type=r.source_type,
                source_id=r.source_id,
                technique_id=r.technique_id,
                technique_name=r.technique_name,
                subtechnique_id=r.subtechnique_id,
                tactic_ids=json.loads(r.tactic_ids_json or "[]"),
                tactic_names=json.loads(r.tactic_names_json or "[]"),
                status=AttackMappingStatus(r.status),
                confidence=r.confidence,
                confidence_level=r.confidence_level,
                evidence_ids=json.loads(r.evidence_ids_json or "[]"),
                finding_ids=json.loads(r.finding_ids_json or "[]"),
                event_ids=json.loads(r.event_ids_json or "[]"),
                stage_ids=json.loads(r.stage_ids_json or "[]"),
                mapping_method=r.mapping_method,
                mapping_rule_id=r.mapping_rule_id,
                explanation=r.explanation,
                limitations=json.loads(r.limitations_json or "[]"),
                contradictions=json.loads(r.contradictions_json or "[]"),
                attack_version=r.attack_version,
                engine_version=r.engine_version,
                configuration_version=r.configuration_version,
                created_at=r.created_at,
                analyst_disposition=r.analyst_disposition,
                analyst_notes=r.analyst_notes,
                metadata=json.loads(r.metadata_json or "{}"),
            )
        )
    return results


@router.get("/incidents/{incident_id}/mitre-timeline")
def get_incident_mitre_timeline(
    incident_id: str,
    db: Session = Depends(get_db)
):
    """
    Returns the tactic-ordered timeline and chronological technique sequence for an incident.
    """
    report = global_mitre_mapping_engine.map_incident(incident_id, db=db, persist=False)
    return {
        "incident_id": incident_id,
        "attack_version": report.attack_version,
        "sequence": report.sequence,
        "tactic_timeline": report.tactic_timeline,
        "coverage_summary": report.coverage_summary,
    }


@router.post("/attack-paths/{path_id}/mitre-map", response_model=List[AttackTechniqueMapping])
def map_attack_path_techniques(
    path_id: str,
    db: Session = Depends(get_db)
):
    """
    Maps techniques across all stages of a reconstructed AttackPath.
    """
    path = db.query(AttackPathModel).filter(AttackPathModel.id == path_id).first()
    if not path:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"AttackPath '{path_id}' not found."
        )

    return global_mitre_mapping_engine.map_path(path, incident_id=path.incident_id)


# ============================================================================
# 3. ANALYST FEEDBACK & DISPOSITION
# ============================================================================

@router.post("/mitre-mappings/{mapping_id}/feedback", response_model=Dict[str, Any])
def submit_analyst_feedback(
    mapping_id: str,
    feedback: AnalystFeedbackRequest,
    db: Session = Depends(get_db)
):
    """
    Records an analyst's review disposition (CONFIRMED, REJECTED, NOT_APPLICABLE)
    for a machine-generated technique mapping.
    """
    mapping = db.query(AttackTechniqueMappingModel).filter(
        AttackTechniqueMappingModel.id == mapping_id
    ).first()
    if not mapping:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"AttackTechniqueMapping '{mapping_id}' not found."
        )

    mapping.analyst_disposition = feedback.disposition.value
    mapping.analyst_notes = feedback.notes
    mapping.reviewed_by = feedback.reviewed_by
    mapping.reviewed_at = datetime.now(timezone.utc)
    db.commit()

    return {
        "mapping_id": mapping_id,
        "disposition": mapping.analyst_disposition,
        "analyst_notes": mapping.analyst_notes,
        "reviewed_by": mapping.reviewed_by,
        "status": "SAVED",
    }


# ============================================================================
# 4. LLM SUGGESTION VALIDATION & ENVIRONMENT CONFIGURATION
# ============================================================================

@router.post("/attack-mapping/validate-llm-suggestion", response_model=LLMValidationResult)
def validate_llm_suggestion_route(
    req: ValidateLLMSuggestionRequest
):
    """
    Deterministically validates an LLM-proposed technique suggestion against local ATT&CK data.
    Ensures suggestions NEVER become automatically SUPPORTED without evidence.
    """
    ctx = MappingEvaluationContext(
        source_type=req.source_type,
        source_id=req.source_id,
        attributes=req.context_attributes,
        environment_config=global_mitre_mapping_engine.get_environment_config(),
    )
    return global_mitre_mapping_engine.validate_llm_suggestion(req.suggestion, context=ctx)


@router.get("/attack-mapping/environment-exclusions", response_model=EnvironmentContextConfig)
def get_environment_exclusions():
    """
    Retrieves currently configured authorized scanners, proxies, and service accounts.
    """
    return global_mitre_mapping_engine.get_environment_config()


@router.post("/attack-mapping/environment-exclusions", response_model=EnvironmentContextConfig)
def update_environment_exclusions(
    config: EnvironmentContextConfig
):
    """
    Updates authorized environment exclusions to suppress false positives from known scanners.
    """
    global_mitre_mapping_engine.set_environment_config(config)
    return global_mitre_mapping_engine.get_environment_config()
