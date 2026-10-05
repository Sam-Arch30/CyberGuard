"""
REST API endpoints for Section 17:
AI Attack Reconstruction Engine.
Provides endpoints for incident attack path reconstruction, candidate stage inspection,
evidence-gap queries, alternative hypotheses evaluation, and analyst feedback.
"""
from typing import List, Optional
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Path, status
from sqlalchemy.orm import Session
import json

from backend.db.session import get_db
from backend.db.models import IncidentModel, AttackPathModel, AttackStageModel, AttackEdgeModel, AttackHypothesisModel
from backend.schemas.attack_reconstruction import (
    AttackReconstructionResponse,
    ReconstructIncidentRequest,
    AttackStageSchema,
    AttackTransitionSchema,
    AttackHypothesisSchema,
    HypothesesResponse,
    EvidenceGapsResponse,
    TransitionEvidenceResponse,
    AnalystFeedbackRequest,
    ReconstructionStatusEnum,
    calculate_confidence_level,
    AttackStageType,
    StageStatusEnum,
    StageRelationshipType,
)
from backend.services.attack_reconstruction_engine import attack_reconstruction_engine

router = APIRouter(tags=["AI Attack Reconstruction Engine"])


def resolve_workspace(
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    workspace_id_query: str = Query("default", alias="workspace_id"),
) -> str:
    """Resolves workspace from header or query parameter."""
    return x_workspace_id or workspace_id_query or "default"


@router.get(
    "/api/incidents/{incident_id}/reconstruction",
    response_model=AttackReconstructionResponse,
    summary="Get current attack reconstruction for an incident",
    description="Returns the active, evidence-constrained multi-stage attack reconstruction."
)
def get_incident_reconstruction_endpoint(
    incident_id: str = Path(..., description="Target incident UUID"),
    workspace_id: str = Depends(resolve_workspace),
    db: Session = Depends(get_db)
):
    incident = db.query(IncidentModel).filter(
        IncidentModel.id == incident_id,
        IncidentModel.workspace_id == workspace_id
    ).first()
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident {incident_id} not found in workspace {workspace_id}"
        )

    current_path = db.query(AttackPathModel).filter(
        AttackPathModel.incident_id == incident_id,
        AttackPathModel.workspace_id == workspace_id,
        AttackPathModel.status == ReconstructionStatusEnum.CURRENT.value
    ).first()

    if not current_path:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No attack reconstruction found for incident {incident_id}. Trigger reconstruction via POST /api/incidents/{incident_id}/reconstruct"
        )

    return attack_reconstruction_engine._hydrate_response_from_model(db, current_path)


@router.post(
    "/api/incidents/{incident_id}/reconstruct",
    response_model=AttackReconstructionResponse,
    summary="Reconstruct attack path for an incident",
    description="Executes deterministic stage extraction, DAG transition mapping, contradiction checks, and hypothesis synthesis."
)
def reconstruct_incident_endpoint(
    incident_id: str = Path(..., description="Target incident UUID"),
    payload: Optional[ReconstructIncidentRequest] = None,
    workspace_id: str = Depends(resolve_workspace),
    db: Session = Depends(get_db)
):
    incident = db.query(IncidentModel).filter(
        IncidentModel.id == incident_id,
        IncidentModel.workspace_id == workspace_id
    ).first()
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident {incident_id} not found in workspace {workspace_id}"
        )

    force = payload.force_reanalysis if payload else False
    include_llm = payload.include_llm_summary if payload else False

    try:
        response = attack_reconstruction_engine.reconstruct_incident(
            db=db,
            incident_id=incident_id,
            workspace_id=workspace_id,
            force_reanalysis=force,
            include_llm_summary=include_llm
        )
        return response
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to reconstruct incident: {str(e)}"
        )


@router.get(
    "/api/incidents/{incident_id}/hypotheses",
    response_model=HypothesesResponse,
    summary="Get alternative and primary attack hypotheses",
    description="Returns ranked hypotheses with supporting, contradicting, and missing evidence items."
)
def get_incident_hypotheses_endpoint(
    incident_id: str = Path(..., description="Target incident UUID"),
    workspace_id: str = Depends(resolve_workspace),
    db: Session = Depends(get_db)
):
    hypotheses_models = db.query(AttackHypothesisModel).filter(
        AttackHypothesisModel.incident_id == incident_id,
        AttackHypothesisModel.workspace_id == workspace_id
    ).order_by(AttackHypothesisModel.confidence.desc()).all()

    schemas: List[AttackHypothesisSchema] = []
    for h in hypotheses_models:
        schemas.append(
            AttackHypothesisSchema(
                id=h.id,
                incident_id=h.incident_id,
                attack_path_id=h.attack_path_id,
                title=h.title,
                description=h.description,
                status=h.status,
                is_primary=h.is_primary,
                stage_ids=json.loads(h.stage_ids_json) if h.stage_ids_json else [],
                confidence=h.confidence,
                confidence_level=calculate_confidence_level(h.confidence),
                supporting_evidence=json.loads(h.supporting_evidence_json) if h.supporting_evidence_json else [],
                contradicting_evidence=json.loads(h.contradicting_evidence_json) if h.contradicting_evidence_json else [],
                missing_evidence=json.loads(h.missing_evidence_json) if h.missing_evidence_json else [],
                analyst_disposition=h.analyst_disposition,
                analyst_notes=h.analyst_notes
            )
        )

    return HypothesesResponse(
        incident_id=incident_id,
        workspace_id=workspace_id,
        hypotheses=schemas,
        total=len(schemas)
    )


@router.get(
    "/api/incidents/{incident_id}/evidence-gaps",
    response_model=EvidenceGapsResponse,
    summary="Get explicit missing telemetry evidence gaps",
    description="Lists telemetry gaps that could not be verified (e.g. unobserved URL click, missing process telemetry)."
)
def get_incident_evidence_gaps_endpoint(
    incident_id: str = Path(..., description="Target incident UUID"),
    workspace_id: str = Depends(resolve_workspace),
    db: Session = Depends(get_db)
):
    current_path = db.query(AttackPathModel).filter(
        AttackPathModel.incident_id == incident_id,
        AttackPathModel.workspace_id == workspace_id,
        AttackPathModel.status == ReconstructionStatusEnum.CURRENT.value
    ).first()

    gaps: List[str] = []
    if current_path and current_path.evidence_gaps_json:
        gaps = json.loads(current_path.evidence_gaps_json)

    return EvidenceGapsResponse(
        incident_id=incident_id,
        workspace_id=workspace_id,
        evidence_gaps=gaps,
        total=len(gaps)
    )


@router.get(
    "/api/attack-stages/{stage_id}",
    response_model=AttackStageSchema,
    summary="Get single attack stage details",
    description="Fetches full stage evidence, status (OBSERVED/DERIVED/INFERRED), and limitations."
)
def get_attack_stage_endpoint(
    stage_id: str = Path(..., description="Target AttackStage UUID"),
    workspace_id: str = Depends(resolve_workspace),
    db: Session = Depends(get_db)
):
    stage = db.query(AttackStageModel).filter(AttackStageModel.id == stage_id).first()
    if not stage:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"AttackStage {stage_id} not found")

    return AttackStageSchema(
        id=stage.id,
        stage_order=stage.stage_order,
        stage_type=AttackStageType(stage.stage_type) if stage.stage_type in AttackStageType.__members__ else AttackStageType.UNKNOWN_ACTIVITY,
        stage_status=StageStatusEnum(stage.stage_status) if stage.stage_status in StageStatusEnum.__members__ else StageStatusEnum.OBSERVED,
        technique_id=stage.technique_id,
        tactic=stage.tactic,
        title=stage.name,
        description=stage.description,
        status=stage.status,
        start_time=stage.start_time,
        end_time=stage.end_time,
        confidence=stage.confidence,
        confidence_level=calculate_confidence_level(stage.confidence),
        entity_ids=json.loads(stage.entity_ids_json) if stage.entity_ids_json else [],
        event_ids=json.loads(stage.event_ids_json) if stage.event_ids_json else [],
        finding_ids=json.loads(stage.finding_ids_json) if stage.finding_ids_json else [],
        evidence_ids=json.loads(stage.evidence_ids_json) if stage.evidence_ids_json else [],
        relationship_ids=json.loads(stage.relationship_ids_json) if stage.relationship_ids_json else [],
        supporting_evidence=json.loads(stage.supporting_evidence_json) if stage.supporting_evidence_json else [],
        contradicting_evidence=json.loads(stage.contradicting_evidence_json) if stage.contradicting_evidence_json else [],
        limitations=json.loads(stage.limitations_json) if stage.limitations_json else [],
        analyst_disposition=stage.analyst_disposition,
        analyst_notes=stage.analyst_notes
    )


@router.post(
    "/api/attack-stages/{stage_id}/feedback",
    response_model=AttackStageSchema,
    summary="Record analyst feedback on an attack stage"
)
def record_stage_feedback_endpoint(
    stage_id: str = Path(..., description="Target AttackStage UUID"),
    feedback: AnalystFeedbackRequest = ...,
    workspace_id: str = Depends(resolve_workspace),
    db: Session = Depends(get_db)
):
    try:
        return attack_reconstruction_engine.record_stage_feedback(
            db=db,
            stage_id=stage_id,
            feedback=feedback,
            workspace_id=workspace_id
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get(
    "/api/attack-edges/{edge_id}/evidence",
    response_model=TransitionEvidenceResponse,
    summary="Get detailed evidence for an attack transition edge"
)
def get_attack_edge_evidence_endpoint(
    edge_id: str = Path(..., description="Target AttackEdge UUID"),
    workspace_id: str = Depends(resolve_workspace),
    db: Session = Depends(get_db)
):
    edge = db.query(AttackEdgeModel).filter(AttackEdgeModel.id == edge_id).first()
    if not edge:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"AttackEdge {edge_id} not found")

    return TransitionEvidenceResponse(
        transition_id=edge.id,
        from_stage_id=edge.source_stage_id,
        to_stage_id=edge.target_stage_id,
        relationship_type=edge.relationship_type,
        edge_status=edge.edge_status,
        confidence=edge.confidence,
        confidence_level=calculate_confidence_level(edge.confidence),
        shared_entities=json.loads(edge.shared_entities_json) if edge.shared_entities_json else [],
        temporal_gap_seconds=edge.temporal_gap_seconds,
        supporting_evidence=json.loads(edge.supporting_evidence_json) if edge.supporting_evidence_json else [],
        contradicting_evidence=json.loads(edge.contradicting_evidence_json) if edge.contradicting_evidence_json else []
    )


@router.post(
    "/api/attack-edges/{edge_id}/feedback",
    response_model=TransitionEvidenceResponse,
    summary="Record analyst feedback on an attack edge"
)
def record_edge_feedback_endpoint(
    edge_id: str = Path(..., description="Target AttackEdge UUID"),
    feedback: AnalystFeedbackRequest = ...,
    workspace_id: str = Depends(resolve_workspace),
    db: Session = Depends(get_db)
):
    try:
        return attack_reconstruction_engine.record_transition_feedback(
            db=db,
            edge_id=edge_id,
            feedback=feedback,
            workspace_id=workspace_id
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post(
    "/api/attack-hypotheses/{hypothesis_id}/feedback",
    response_model=AttackHypothesisSchema,
    summary="Record analyst feedback on an attack hypothesis"
)
def record_hypothesis_feedback_endpoint(
    hypothesis_id: str = Path(..., description="Target AttackHypothesis UUID"),
    feedback: AnalystFeedbackRequest = ...,
    workspace_id: str = Depends(resolve_workspace),
    db: Session = Depends(get_db)
):
    try:
        return attack_reconstruction_engine.record_hypothesis_feedback(
            db=db,
            hypothesis_id=hypothesis_id,
            feedback=feedback,
            workspace_id=workspace_id
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
