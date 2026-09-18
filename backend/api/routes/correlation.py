from typing import Optional, Dict, Any, List
from fastapi import APIRouter, Depends, Query, Path, HTTPException
from sqlalchemy.orm import Session
import json
from datetime import datetime, timezone

from backend.db.session import get_db
from backend.db.models import CaseModel, CaseEmailModel, CampaignModel, CampaignEmailModel
from backend.services.campaign_correlator import CampaignCorrelator
from backend.services.campaign_service import CampaignService
from backend.services.graph_service import global_graph_service
from backend.schemas.correlation import (
    CampaignCorrelationResponse,
    DirectCompareRequest,
    DirectCompareResponse,
    CampaignFingerprint,
    CategorySimilarityScores,
    CampaignClusterItem,
    CampaignDetailResponse,
    CampaignAlertResponse,
    CampaignIOC,
    CampaignTimelineEvent
)
from backend.schemas.graph import InvestigationGraphResponse

router = APIRouter(tags=["Campaign Correlation & Intelligence"])
correlator = CampaignCorrelator()


# -----------------------------------------------------------------------------
def _load_campaign_details_from_db(db: Session) -> List[CampaignDetailResponse]:
    """Loads all real persisted campaigns from database."""
    CampaignService.ensure_campaigns_initialized(db)
    db_campaigns = db.query(CampaignModel).all()
    results: List[CampaignDetailResponse] = []
    for db_c in db_campaigns:
        brands = json.loads(db_c.targeted_brands_json) if db_c.targeted_brands_json else []
        orgs = json.loads(db_c.targeted_organizations_json) if db_c.targeted_organizations_json else []
        fp_dict = json.loads(db_c.fingerprint_json) if db_c.fingerprint_json else {}
        scores_dict = fp_dict.get("category_scores") if fp_dict else None
        cat_scores = CategorySimilarityScores(**scores_dict) if scores_dict else None
        iocs_list = [CampaignIOC(**i) for i in json.loads(db_c.associated_iocs_json)] if db_c.associated_iocs_json else []
        tl_list = [CampaignTimelineEvent(**e) for e in json.loads(db_c.timeline_events_json)] if db_c.timeline_events_json else []

        emails = []
        for ce in db_c.emails:
            emails.append({
                "id": ce.email_id,
                "subject": ce.subject,
                "sender": ce.sender,
                "recipient": ce.recipient,
                "date": ce.sent_at.strftime("%Y-%m-%d %H:%M:%S UTC") if ce.sent_at else "",
                "threat_score": 85,
                "similarity": ce.similarity_to_campaign,
                "correlation_reasons": json.loads(ce.correlation_reasons_json) if ce.correlation_reasons_json else []
            })

        results.append(CampaignDetailResponse(
            campaign_id=db_c.campaign_id,
            name=db_c.name,
            first_seen=db_c.first_seen.strftime("%Y-%m-%d %H:%M:%S UTC") if db_c.first_seen else "",
            last_seen=db_c.last_seen.strftime("%Y-%m-%d %H:%M:%S UTC") if db_c.last_seen else "",
            email_count=db_c.email_count,
            recipient_count=db_c.recipient_count,
            sender_count=db_c.sender_count,
            domain_count=db_c.domain_count,
            ip_count=db_c.ip_count,
            asn_count=db_c.asn_count,
            overall_confidence=db_c.overall_confidence,
            dominant_attack_type=db_c.dominant_attack_type,
            targeted_brands=brands,
            targeted_organizations=orgs,
            category_scores=cat_scores,
            fingerprint=CampaignFingerprint(**fp_dict) if fp_dict else CampaignFingerprint(),
            associated_iocs=iocs_list,
            timeline=tl_list,
            emails=emails
        ))
    return results

@router.get(
    "/api/campaigns",
    response_model=List[CampaignClusterItem],
    summary="List all campaign clusters",
    description="Returns all tracked campaign clusters formatted for SOC campaign cards."
)
def list_campaigns_endpoint(
    query: Optional[str] = Query(None, description="Search by name, brand, or IOC"),
    attack_type: Optional[str] = Query(None, description="Filter by dominant attack type"),
    min_confidence: Optional[float] = Query(None, ge=0.0, le=100.0, description="Minimum confidence percentage"),
    db: Session = Depends(get_db)
):
    CampaignService.ensure_campaigns_initialized(db)
    # Retrieve from database if populated
    db_campaigns = db.query(CampaignModel).all()
    results: List[CampaignClusterItem] = []

    if db_campaigns:
        for c in db_campaigns:
            brands = json.loads(c.targeted_brands_json) if c.targeted_brands_json else []
            orgs = json.loads(c.targeted_organizations_json) if c.targeted_organizations_json else []
            scores_dict = json.loads(c.fingerprint_json).get("category_scores") if c.fingerprint_json else None
            cat_scores = CategorySimilarityScores(**scores_dict) if scores_dict else None

            item = CampaignClusterItem(
                campaign_id=c.campaign_id,
                name=c.name,
                first_seen=c.first_seen.strftime("%Y-%m-%d %H:%M:%S UTC"),
                last_seen=c.last_seen.strftime("%Y-%m-%d %H:%M:%S UTC"),
                email_count=c.email_count,
                recipient_count=c.recipient_count,
                sender_count=c.sender_count,
                domain_count=c.domain_count,
                ip_count=c.ip_count,
                asn_count=c.asn_count,
                overall_confidence=c.overall_confidence,
                dominant_attack_type=c.dominant_attack_type,
                targeted_brands=brands,
                targeted_organizations=orgs,
                category_scores=cat_scores
            )
            results.append(item)

    # Apply filters
    if query:
        q = query.lower()
        results = [
            r for r in results
            if q in r.name.lower() or q in r.campaign_id.lower() or any(q in b.lower() for b in r.targeted_brands)
        ]
    if attack_type:
        at = attack_type.lower()
        results = [r for r in results if at in r.dominant_attack_type.lower()]
    if min_confidence is not None:
        results = [r for r in results if r.overall_confidence >= min_confidence]

    return results


@router.get(
    "/api/campaigns/{campaign_id}",
    response_model=CampaignDetailResponse,
    summary="Get detailed campaign intelligence",
    description="Returns complete 9-tab campaign investigation detail including fingerprint, IOCs, timeline, and emails."
)
def get_campaign_detail_endpoint(
    campaign_id: str = Path(..., description="Campaign ID (e.g. C-042)"),
    db: Session = Depends(get_db)
):
    CampaignService.ensure_campaigns_initialized(db)
    clean_id = campaign_id.upper().strip()
    db_c = db.query(CampaignModel).filter(CampaignModel.campaign_id == clean_id).first()

    if db_c:
        brands = json.loads(db_c.targeted_brands_json) if db_c.targeted_brands_json else []
        orgs = json.loads(db_c.targeted_organizations_json) if db_c.targeted_organizations_json else []
        fp_dict = json.loads(db_c.fingerprint_json) if db_c.fingerprint_json else {}
        scores_dict = fp_dict.get("category_scores") if fp_dict else None
        cat_scores = CategorySimilarityScores(**scores_dict) if scores_dict else None
        iocs_list = [CampaignIOC(**i) for i in json.loads(db_c.associated_iocs_json)] if db_c.associated_iocs_json else []
        tl_list = [CampaignTimelineEvent(**e) for e in json.loads(db_c.timeline_events_json)] if db_c.timeline_events_json else []

        emails = []
        for ce in db_c.emails:
            emails.append({
                "id": ce.email_id,
                "subject": ce.subject,
                "sender": ce.sender,
                "recipient": ce.recipient,
                "date": ce.sent_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
                "threat_score": 85,
                "similarity": ce.similarity_to_campaign,
                "correlation_reasons": json.loads(ce.correlation_reasons_json) if ce.correlation_reasons_json else []
            })

        return CampaignDetailResponse(
            campaign_id=db_c.campaign_id,
            name=db_c.name,
            first_seen=db_c.first_seen.strftime("%Y-%m-%d %H:%M:%S UTC"),
            last_seen=db_c.last_seen.strftime("%Y-%m-%d %H:%M:%S UTC"),
            email_count=db_c.email_count,
            recipient_count=db_c.recipient_count,
            sender_count=db_c.sender_count,
            domain_count=db_c.domain_count,
            ip_count=db_c.ip_count,
            asn_count=db_c.asn_count,
            overall_confidence=db_c.overall_confidence,
            dominant_attack_type=db_c.dominant_attack_type,
            targeted_brands=brands,
            targeted_organizations=orgs,
            category_scores=cat_scores,
            fingerprint=CampaignFingerprint(**fp_dict) if fp_dict else CampaignFingerprint(),
            associated_iocs=iocs_list,
            timeline=tl_list,
            emails=emails
        )

    raise HTTPException(status_code=404, detail=f"Campaign '{campaign_id}' not found.")


@router.get(
    "/api/campaigns/{campaign_id}/graph",
    response_model=InvestigationGraphResponse,
    summary="Get first-class campaign relationship graph",
    description="Generates an interactive relationship graph connecting Campaign node to Emails, Domains, IPs, URLs, and Recipients."
)
def get_campaign_graph_endpoint(
    campaign_id: str = Path(..., description="Campaign ID (e.g. C-042)"),
    db: Session = Depends(get_db)
):
    camp_detail = get_campaign_detail_endpoint(campaign_id=campaign_id, db=db)
    return global_graph_service.build_campaign_graph(camp_detail.model_dump())


@router.post(
    "/api/campaigns/fingerprint",
    response_model=CampaignFingerprint,
    summary="Generate multidimensional campaign fingerprint",
    description="Extracts 7 dimensions of forensic indicators into a CampaignFingerprint object."
)
def generate_fingerprint_endpoint(
    email_data: Dict[str, Any]
):
    return correlator.generate_fingerprint(email_data)


@router.post(
    "/api/campaigns/detect-alert",
    response_model=CampaignAlertResponse,
    summary="Detect potential campaign and generate SOC alert",
    description="Evaluates email against existing campaign clusters and returns proactive campaign detection alert banner."
)
def detect_campaign_alert_endpoint(
    email_data: Dict[str, Any],
    threshold: float = Query(0.50, ge=0.0, le=1.0, description="Minimum confidence threshold"),
    db: Session = Depends(get_db)
):
    campaigns = _load_campaign_details_from_db(db)
    if not campaigns:
        return CampaignAlertResponse(
            is_campaign_detected=False,
            message_alert="No campaigns detected."
        )
    return correlator.correlate_email_against_campaigns(email_data, campaigns, threshold=threshold)


# -----------------------------------------------------------------------------
# Backward-Compatible Correlation Endpoints
# -----------------------------------------------------------------------------

@router.post(
    "/api/correlation/email",
    response_model=CampaignCorrelationResponse,
    summary="Correlate analyzed email against existing cases",
    description="Compares forensic indicators of an analyzed email against all investigation cases."
)
def correlate_email_endpoint(
    email_data: Dict[str, Any],
    min_score: float = Query(0.15, ge=0.0, le=1.0, description="Minimum correlation score threshold"),
    limit: int = Query(10, ge=1, le=50, description="Max related cases to return"),
    db: Session = Depends(get_db)
):
    return correlator.correlate_email_against_cases(
        db=db,
        email_data=email_data,
        min_score=min_score,
        limit=limit
    )


@router.get(
    "/api/cases/{case_id}/correlation",
    response_model=CampaignCorrelationResponse,
    summary="Correlate case against all other investigations",
    description="Identifies related cases exhibiting shared infrastructure or behavioral similarities."
)
def correlate_case_endpoint(
    case_id: str = Path(..., description="Case ID or Case Number"),
    min_score: float = Query(0.15, ge=0.0, le=1.0, description="Minimum correlation score threshold"),
    limit: int = Query(10, ge=1, le=50, description="Max related cases to return"),
    db: Session = Depends(get_db)
):
    return correlator.correlate_case_against_cases(
        db=db,
        target_case_id=case_id,
        min_score=min_score,
        limit=limit
    )


@router.post(
    "/api/correlation/compare",
    response_model=DirectCompareResponse,
    summary="Direct pairwise comparison between two entities",
    description="Calculates explainable correlation score and shared indicators between two arbitrary email/indicator profiles."
)
def direct_compare_endpoint(
    request: DirectCompareRequest
):
    return correlator.direct_compare(
        entity_a=request.entity_a,
        entity_b=request.entity_b
    )
