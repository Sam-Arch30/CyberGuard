import json
from typing import Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Header, Path, Query, status
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.db.models import EmailAnalysisModel, CaseModel, CaseEmailModel, EvidenceModel
from backend.schemas.attribution import (
    AttributionResult,
    CaseAttributionResponse,
    CampaignAttributionResponse
)
from backend.schemas.email import EmailAnalysisResponse
from backend.services.attribution_engine import global_attribution_engine
from backend.services.audit_service import AuditService

router = APIRouter(tags=["Probabilistic Threat Attribution"])


@router.post(
    "/api/emails/attribution",
    response_model=AttributionResult,
    summary="Compute probabilistic infrastructure attribution for an analyzed email",
    description="Calculates explainable infrastructure attribution, confidence score, and supporting/conflicting evidence from an EmailAnalysisResponse object."
)
def calculate_attribution_endpoint(
    analysis: EmailAnalysisResponse,
    case_id: Optional[str] = Query(None, description="Optional associated case ID"),
    user: Optional[str] = Header(None, alias="X-User"),
    db: Session = Depends(get_db)
):
    """
    Direct endpoint to compute infrastructure attribution for a provided EmailAnalysisResponse.
    """
    attribution = global_attribution_engine.attribute_email(analysis, db=db, case_id=case_id)

    # Record ATTRIBUTION_GENERATED audit log
    uploader = (user or "SOC Analyst").strip()
    evidence_ref = analysis.evidence_id or analysis.id or analysis.email_sha256 or attribution.attribution_id
    try:
        AuditService.log_audit(
            db=db,
            action="ATTRIBUTION_GENERATED",
            resource_type="attribution",
            resource_id=attribution.attribution_id,
            user=uploader,
            metadata={
                "attribution_id": attribution.attribution_id,
                "evidence_ref": evidence_ref,
                "confidence_score": attribution.confidence_score,
                "confidence_level": attribution.confidence_level,
                "probable_origin_ip": attribution.probable_origin_ip,
                "probable_origin_asn": attribution.probable_origin_asn,
                "probable_infrastructure_country": attribution.probable_infrastructure_country,
                "supporting_evidence_count": len(attribution.supporting_evidence),
                "conflicting_evidence_count": len(attribution.conflicting_evidence)
            },
            details=f"Infrastructure attribution generated: {attribution.probable_origin_ip or 'Unknown'} "
                    f"({attribution.probable_origin_provider or 'Unknown Provider'}), "
                    f"Confidence: {attribution.confidence_score}% ({attribution.confidence_level})."
        )
    except Exception:
        pass

    return attribution


@router.get(
    "/api/emails/{email_id}/attribution",
    response_model=AttributionResult,
    summary="Get infrastructure attribution for an analyzed email by identifier",
    description="Retrieves or generates explainable infrastructure attribution for an email using its evidence ID or SHA-256."
)
def get_email_attribution_endpoint(
    email_id: str = Path(..., description="Evidence ID (e.g. EVD-A1B2C3D4) or SHA-256 hash"),
    db: Session = Depends(get_db)
):
    """
    Look up and return infrastructure attribution for an email stored in the database.
    """
    clean_id = email_id.strip()

    # 1. Search email_analyses table
    record = db.query(EmailAnalysisModel).filter(
        (EmailAnalysisModel.evidence_id == clean_id) |
        (EmailAnalysisModel.email_sha256 == clean_id) |
        (EmailAnalysisModel.id == clean_id)
    ).first()

    if record:
        ind: Dict[str, Any] = {}
        if record.indicators_json:
            try:
                ind = json.loads(record.indicators_json)
            except Exception:
                ind = {}

        synth_analysis = {
            "id": record.evidence_id or record.id,
            "evidence_id": record.evidence_id,
            "email_sha256": record.email_sha256,
            "subject": record.subject,
            "from_header": record.sender,
            "threat_score": {"score": record.threat_score, "severity": record.severity},
            "ips": ind.get("ips", []),
            "domains": ind.get("domains", []),
            "urls": ind.get("urls", [])
        }
        return global_attribution_engine.attribute_email(synth_analysis, db=db)

    # 2. Search case_emails table
    case_em = db.query(CaseEmailModel).filter(
        (CaseEmailModel.email_id == clean_id) |
        (CaseEmailModel.email_sha256 == clean_id)
    ).first()

    if case_em:
        ind: Dict[str, Any] = {}
        if case_em.indicators_json:
            try:
                ind = json.loads(case_em.indicators_json)
            except Exception:
                ind = {}

        synth_analysis = {
            "id": case_em.email_id,
            "email_sha256": case_em.email_sha256,
            "subject": case_em.subject,
            "from_header": case_em.sender,
            "threat_score": {"score": case_em.threat_score, "severity": case_em.severity},
            "ips": ind.get("ips", []),
            "domains": ind.get("domains", []),
            "urls": ind.get("urls", [])
        }
        return global_attribution_engine.attribute_email(synth_analysis, db=db, case_id=case_em.case_id)

    # 3. Check evidence table
    evd = db.query(EvidenceModel).filter(
        (EvidenceModel.evidence_id == clean_id) |
        (EvidenceModel.sha256 == clean_id)
    ).first()

    if evd:
        synth_analysis = {
            "id": evd.evidence_id,
            "evidence_id": evd.evidence_id,
            "email_sha256": evd.sha256,
            "subject": evd.original_filename,
            "ips": [],
            "domains": [],
            "urls": []
        }
        return global_attribution_engine.attribute_email(synth_analysis, db=db)

    # If ID is sample-001 / latest fallback
    if clean_id in ("sample-001", "latest", "demo"):
        sample_sim = {
            "id": "sample-001",
            "evidence_id": "EVD-97D4B2E811",
            "email_sha256": "97d4b2e811c7520e5e79603f9050d268159b360b9432df03d4083d8e57ef228a",
            "subject": "URGENT: Verify your Microsoft Account",
            "from_header": "Microsoft Security <security@micros0ft-example.com>",
            "threat_score": {"score": 82.0, "severity": "critical"},
            "ips": ["203.0.113.25", "198.51.100.12"],
            "domains": ["micros0ft-example.com", "example.net"],
            "urls": ["https://micros0ft-example.com/login"],
            "relay_analysis": {
                "earliest_observable_node": {
                    "earliest_observable_ip": "203.0.113.25",
                    "from_host": "mail.example.net"
                }
            },
            "ip_intelligence": {
                "203.0.113.25": {
                    "country": "United States",
                    "asn": "AS64512",
                    "organization": "Threat Hosting Corp",
                    "is_hosting": True,
                    "is_proxy_vpn_tor": True
                }
            },
            "domain_intelligence": {
                "micros0ft-example.com": {
                    "domain": "micros0ft-example.com",
                    "dns": {"a": ["203.0.113.25"]},
                    "lookalike": {
                        "domain": "micros0ft-example.com",
                        "suspected_brand": "microsoft.com"
                    }
                }
            }
        }
        return global_attribution_engine.attribute_email(sample_sim, db=db)

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Email analysis or evidence record '{clean_id}' was not found."
    )


@router.get(
    "/api/cases/{case_id}/attribution",
    response_model=CaseAttributionResponse,
    summary="Get infrastructure attribution for an investigation case",
    description="Synthesizes infrastructure attribution across all emails linked to the investigation case."
)
def get_case_attribution_endpoint(
    case_id: str = Path(..., description="Case ID or Case Number (e.g. CASE-2026-000001)"),
    db: Session = Depends(get_db)
):
    """
    Returns aggregated infrastructure attribution for an investigation case.
    """
    return global_attribution_engine.attribute_case(db=db, case_id=case_id)


@router.get(
    "/api/campaigns/{campaign_id}/attribution",
    response_model=CampaignAttributionResponse,
    summary="Get infrastructure attribution for a threat campaign cluster",
    description="Synthesizes infrastructure attribution across correlated cases forming a threat campaign cluster."
)
def get_campaign_attribution_endpoint(
    campaign_id: str = Path(..., description="Campaign identifier, name, or case number"),
    db: Session = Depends(get_db)
):
    """
    Returns aggregated infrastructure attribution for a threat campaign cluster.
    """
    return global_attribution_engine.attribute_campaign(db=db, campaign_id=campaign_id)
