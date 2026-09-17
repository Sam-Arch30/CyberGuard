import json
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from fastapi import APIRouter, Depends, HTTPException, Header, Path, Query, status
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.db.models import EmailAnalysisModel, EvidenceModel
from backend.schemas.evidence_confidence import (
    ForensicConclusion,
    EmailConfidenceResponse
)
from backend.schemas.email import EmailAnalysisResponse
from backend.services.evidence_confidence_engine import EvidenceConfidenceEngine
from backend.services.audit_service import AuditService

router = APIRouter(tags=["Evidence Confidence Engine"])
global_confidence_engine = EvidenceConfidenceEngine()


@router.post(
    "/api/emails/confidence",
    response_model=EmailConfidenceResponse,
    summary="Compute evidence confidence conclusions across 8 forensic domains",
    description="Evaluates multi-dimensional evidence quality, detects contradictions, eliminates double-counting of correlated feeds, and produces explainable forensic conclusions."
)
def calculate_confidence_endpoint(
    analysis: EmailAnalysisResponse,
    user: Optional[str] = Header(None, alias="X-User"),
    db: Session = Depends(get_db)
):
    """
    Direct endpoint to evaluate evidence confidence conclusions for a provided EmailAnalysisResponse.
    """
    conclusions = global_confidence_engine.evaluate_email(analysis)
    uploader = (user or "SOC Analyst").strip()
    evidence_ref = analysis.evidence_id or analysis.id or analysis.email_sha256 or "EVD-UNKNOWN"

    overall_score = 0.0
    if conclusions:
        overall_score = round(sum(c.confidence_score for c in conclusions) / len(conclusions))
    overall_tier = global_confidence_engine._get_tier(overall_score)

    response = EmailConfidenceResponse(
        email_id=analysis.id,
        evidence_id=analysis.evidence_id,
        conclusions=conclusions,
        overall_confidence_score=overall_score,
        overall_confidence_level=overall_tier,
        engine_version=global_confidence_engine.engine_version,
        generated_at=datetime.now(timezone.utc).isoformat()
    )

    # Record CONFIDENCE_EVALUATED audit log
    try:
        AuditService.log_audit(
            db=db,
            action="CONFIDENCE_EVALUATED",
            resource_type="confidence",
            resource_id=f"CONF-{evidence_ref}",
            user=uploader,
            metadata={
                "evidence_ref": evidence_ref,
                "engine_version": global_confidence_engine.engine_version,
                "conclusion_count": len(conclusions),
                "overall_confidence_score": overall_score,
                "overall_confidence_level": overall_tier,
                "conclusion_types": [c.type.value for c in conclusions]
            },
            details=f"Evidence confidence evaluated: {len(conclusions)} conclusions generated. "
                    f"Overall confidence: {overall_score}% ({overall_tier}). Engine version: {global_confidence_engine.engine_version}."
        )
    except Exception:
        pass

    return response


@router.get(
    "/api/emails/{id}/confidence",
    response_model=EmailConfidenceResponse,
    summary="Retrieve or evaluate evidence confidence conclusions for an email by ID or SHA-256",
    description="Loads existing analysis record or generates fresh confidence conclusions for the specified email."
)
def get_email_confidence_endpoint(
    id: str = Path(..., description="Evidence ID, analysis ID, or SHA-256"),
    user: Optional[str] = Header(None, alias="X-User"),
    db: Session = Depends(get_db)
):
    """
    Fetches or computes evidence confidence conclusions for an email by identifier.
    """
    clean_id = id.strip()
    analysis_record = None

    from backend.services.analysis_repository import load_analysis
    try:
        data = load_analysis(db, clean_id)
        analysis_obj = EmailAnalysisResponse(**data)
        return calculate_confidence_endpoint(analysis_obj, user=user, db=db)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=404, detail=f"Email record '{clean_id}' not found: {str(e)}")

