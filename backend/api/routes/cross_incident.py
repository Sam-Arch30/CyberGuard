"""
REST API endpoints for Section 15:
Cross-Incident Pattern Detection & Campaign Correlation Engine.
"""
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Path, status
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_, desc

from backend.db.session import get_db
from backend.db.models import IncidentModel, IncidentCorrelationModel, CampaignModel
from backend.services.cross_incident_engine import global_cross_incident_engine
from backend.schemas.cross_incident import (
    IncidentCorrelationResult,
    CampaignCandidateResponse,
    CrossIncidentSearchResponse,
    RelatedIncidentItem,
    IncidentPairCompareRequest,
    AnalystReviewRequest,
)

router = APIRouter(tags=["Cross-Incident Correlation & Campaigns"])


@router.get(
    "/api/incidents/{incident_id}/related",
    response_model=CrossIncidentSearchResponse,
    summary="Find related incidents sharing correlated indicators",
    description="Queries the inverted index for candidate incidents, evaluates supporting vs. contradicting evidence, and returns ranked correlations."
)
def find_related_incidents_endpoint(
    incident_id: str = Path(..., description="Target incident ID"),
    workspace_id: str = Query("default", description="Workspace / tenant identifier"),
    limit: int = Query(20, ge=1, le=100, description="Max related incidents to return"),
    db: Session = Depends(get_db)
):
    target_inc = db.query(IncidentModel).filter(
        IncidentModel.id == incident_id,
        or_(IncidentModel.workspace_id == workspace_id, IncidentModel.workspace_id == "default")
    ).first()
    if not target_inc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Incident {incident_id} not found.")

    target_profile = global_cross_incident_engine.extract_incident_profile(target_inc, db)
    candidate_ids = global_cross_incident_engine.generate_candidate_incident_ids(
        target_profile, workspace_id, db, max_candidates=limit * 2
    )

    related_items: List[RelatedIncidentItem] = []

    for cid in candidate_ids:
        if cid == incident_id:
            continue
        c_inc = db.query(IncidentModel).filter(IncidentModel.id == cid).first()
        if not c_inc:
            continue

        c_profile = global_cross_incident_engine.extract_incident_profile(c_inc, db)
        corr_res = global_cross_incident_engine.correlate_incident_pair(target_profile, c_profile, db)

        # Store or update correlation record
        existing = db.query(IncidentCorrelationModel).filter(
            IncidentCorrelationModel.workspace_id == workspace_id,
            or_(
                and_(IncidentCorrelationModel.incident_a_id == incident_id, IncidentCorrelationModel.incident_b_id == cid),
                and_(IncidentCorrelationModel.incident_a_id == cid, IncidentCorrelationModel.incident_b_id == incident_id),
            )
        ).first()

        import json
        if existing:
            existing.correlation_score = corr_res.correlation_score
            existing.relationship_label = corr_res.relationship_label
            existing.supporting_evidence_json = json.dumps([e.model_dump() for e in corr_res.supporting_evidence])
            existing.contradicting_evidence_json = json.dumps([e.model_dump() for e in corr_res.contradicting_evidence])
            existing.feature_breakdown_json = json.dumps(corr_res.feature_breakdown.model_dump())
            db.commit()
        else:
            new_corr = IncidentCorrelationModel(
                id=corr_res.id,
                workspace_id=workspace_id,
                incident_a_id=incident_id,
                incident_b_id=cid,
                correlation_score=corr_res.correlation_score,
                confidence=corr_res.confidence,
                relationship_label=corr_res.relationship_label,
                supporting_evidence_json=json.dumps([e.model_dump() for e in corr_res.supporting_evidence]),
                contradicting_evidence_json=json.dumps([e.model_dump() for e in corr_res.contradicting_evidence]),
                feature_breakdown_json=json.dumps(corr_res.feature_breakdown.model_dump()),
                shared_indicators_json=json.dumps([e.value for e in corr_res.supporting_evidence]),
                status="ACTIVE",
                engine_version=corr_res.engine_version,
                config_version=corr_res.config_version,
            )
            db.add(new_corr)
            db.commit()

        if corr_res.correlation_score > 0.05:
            shared_summary = [f"{e.evidence_type}: {e.value}" for e in corr_res.supporting_evidence[:5]]
            related_items.append(RelatedIncidentItem(
                incident_id=c_inc.id,
                incident_number=c_inc.incident_number,
                title=c_inc.title,
                correlation_score=corr_res.correlation_score,
                relationship_label=corr_res.relationship_label,
                shared_indicators_summary=shared_summary,
                supporting_evidence_count=len(corr_res.supporting_evidence),
                contradicting_evidence_count=len(corr_res.contradicting_evidence),
                status=c_inc.status,
                created_at=c_inc.created_at,
            ))

    # Sort descending by correlation score
    related_items.sort(key=lambda x: x.correlation_score, reverse=True)

    return CrossIncidentSearchResponse(
        incident_id=target_inc.id,
        incident_number=target_inc.incident_number,
        total_candidates=len(candidate_ids),
        related_incidents=related_items[:limit]
    )


@router.post(
    "/api/correlations/compare",
    response_model=IncidentCorrelationResult,
    summary="Compare two incidents directly for cross-incident pattern correlation"
)
def compare_incidents_endpoint(
    request: IncidentPairCompareRequest,
    db: Session = Depends(get_db)
):
    inc_a = db.query(IncidentModel).filter(
        IncidentModel.id == request.incident_a_id,
        or_(IncidentModel.workspace_id == request.workspace_id, IncidentModel.workspace_id == "default")
    ).first()
    inc_b = db.query(IncidentModel).filter(
        IncidentModel.id == request.incident_b_id,
        or_(IncidentModel.workspace_id == request.workspace_id, IncidentModel.workspace_id == "default")
    ).first()

    if not inc_a:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Incident {request.incident_a_id} not found.")
    if not inc_b:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Incident {request.incident_b_id} not found.")

    prof_a = global_cross_incident_engine.extract_incident_profile(inc_a, db)
    prof_b = global_cross_incident_engine.extract_incident_profile(inc_b, db)

    return global_cross_incident_engine.correlate_incident_pair(prof_a, prof_b, db)


@router.get(
    "/api/correlations/{correlation_id}",
    response_model=IncidentCorrelationResult,
    summary="Get detailed incident correlation breakdown by ID"
)
def get_correlation_details_endpoint(
    correlation_id: str = Path(..., description="Correlation ID"),
    db: Session = Depends(get_db)
):
    corr = db.query(IncidentCorrelationModel).filter(
        IncidentCorrelationModel.id == correlation_id
    ).first()
    if not corr:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Correlation {correlation_id} not found.")

    import json
    from backend.schemas.cross_incident import CorrelationEvidenceItem, ContradictingEvidenceItem, FeatureBreakdown
    return IncidentCorrelationResult(
        id=corr.id,
        workspace_id=corr.workspace_id,
        incident_a_id=corr.incident_a_id,
        incident_b_id=corr.incident_b_id,
        correlation_score=corr.correlation_score,
        confidence=corr.confidence,
        relationship_label=corr.relationship_label,
        supporting_evidence=[CorrelationEvidenceItem(**e) for e in json.loads(corr.supporting_evidence_json)],
        contradicting_evidence=[ContradictingEvidenceItem(**e) for e in json.loads(corr.contradicting_evidence_json)],
        feature_breakdown=FeatureBreakdown(**json.loads(corr.feature_breakdown_json)),
        status=corr.status,
        reviewed_by=corr.reviewed_by,
        reviewed_at=corr.reviewed_at,
        review_notes=corr.review_notes,
        engine_version=corr.engine_version,
        config_version=corr.config_version,
        created_at=corr.created_at,
    )


@router.post(
    "/api/correlations/{correlation_id}/review",
    response_model=IncidentCorrelationResult,
    summary="Submit analyst confirmation or rejection for an incident correlation"
)
def review_correlation_endpoint(
    request: AnalystReviewRequest,
    correlation_id: str = Path(..., description="Correlation ID to review"),
    db: Session = Depends(get_db)
):
    try:
        return global_cross_incident_engine.review_correlation(
            correlation_id=correlation_id,
            decision=request.decision,
            notes=request.notes,
            analyst_id=request.analyst_id,
            db=db
        )
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.get(
    "/api/campaigns/candidates",
    response_model=List[CampaignCandidateResponse],
    summary="List all dynamically generated Campaign Candidates",
    description="Returns clustered campaign candidates with supporting/contradicting evidence and non-attribution semantics."
)
def list_campaign_candidates_endpoint(
    workspace_id: str = Query("default", description="Workspace / tenant identifier"),
    db: Session = Depends(get_db)
):
    try:
        return global_cross_incident_engine.generate_campaign_candidates(workspace_id=workspace_id, db=db)
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.get(
    "/api/campaigns/candidates/{campaign_id}",
    response_model=CampaignCandidateResponse,
    summary="Get campaign candidate details by ID or campaign_id"
)
def get_campaign_candidate_endpoint(
    campaign_id: str = Path(..., description="Campaign ID or UUID"),
    workspace_id: str = Query("default", description="Workspace / tenant identifier"),
    db: Session = Depends(get_db)
):
    camp = db.query(CampaignModel).filter(
        or_(CampaignModel.id == campaign_id, CampaignModel.campaign_id == campaign_id),
        or_(CampaignModel.workspace_id == workspace_id, CampaignModel.workspace_id == "default")
    ).first()
    if not camp:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Campaign candidate {campaign_id} not found.")

    import json
    from backend.schemas.cross_incident import CorrelationEvidenceItem, ContradictingEvidenceItem
    inc_ids = [ci.incident_id for ci in camp.incidents] if hasattr(camp, "incidents") and camp.incidents else []
    supp = [CorrelationEvidenceItem(**e) for e in json.loads(camp.supporting_evidence_json)] if camp.supporting_evidence_json else []
    contra = [ContradictingEvidenceItem(**e) for e in json.loads(camp.contradicting_evidence_json)] if camp.contradicting_evidence_json else []

    return CampaignCandidateResponse(
        id=camp.id,
        campaign_id=camp.campaign_id,
        workspace_id=camp.workspace_id,
        name=camp.name,
        status=camp.status,
        overall_confidence=camp.overall_confidence,
        correlation_summary=camp.correlation_summary or "",
        incident_count=len(inc_ids),
        incident_ids=inc_ids,
        supporting_evidence=supp,
        contradicting_evidence=contra,
        first_seen=camp.first_seen,
        last_seen=camp.last_seen,
        dominant_attack_type=camp.dominant_attack_type,
        engine_version=camp.engine_version,
    )


@router.post(
    "/api/campaigns/candidates/{campaign_id}/review",
    response_model=CampaignCandidateResponse,
    summary="Submit analyst review (confirm or reject) for a campaign candidate"
)
def review_campaign_candidate_endpoint(
    request: AnalystReviewRequest,
    campaign_id: str = Path(..., description="Campaign ID or UUID to review"),
    db: Session = Depends(get_db)
):
    try:
        return global_cross_incident_engine.review_campaign_candidate(
            campaign_id=campaign_id,
            decision=request.decision,
            notes=request.notes,
            analyst_id=request.analyst_id,
            db=db
        )
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))
