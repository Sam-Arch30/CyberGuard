"""
Digital Impersonation API Endpoints (Section 12).
Provides REST endpoints for Protected Identity Profile management,
audit event inspection, and multi-channel digital impersonation analysis.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.db.models import ArtifactModel, AuditLogModel
from backend.schemas.unified import ArtifactTypeEnum, AnalysisTriggerEnum
from backend.schemas.impersonation import (
    ProtectedIdentityProfile,
    CreateProtectedIdentityRequest,
    UpdateProtectedIdentityRequest,
    ImpersonationAnalysisRequest,
    ImpersonationAnalysisResponse,
)
from backend.services.impersonation_service import (
    global_protected_identity_manager,
    global_impersonation_pipeline,
)
from backend.services.evidence_storage import evidence_storage

logger = logging.getLogger("cyberguard.api.impersonation")

router = APIRouter(prefix="/api/impersonation", tags=["Digital Impersonation"])


@router.get("/profiles", response_model=List[ProtectedIdentityProfile])
def list_protected_identities(
    active_only: bool = Query(True, description="Filter for active profiles only"),
    db: Session = Depends(get_db),
) -> List[ProtectedIdentityProfile]:
    """Lists all configured reference/protected identity profiles."""
    return global_protected_identity_manager.get_all(db=db, active_only=active_only)


@router.post("/profiles", response_model=ProtectedIdentityProfile, status_code=status.HTTP_201_CREATED)
def create_protected_identity(
    request: CreateProtectedIdentityRequest,
    db: Session = Depends(get_db),
) -> ProtectedIdentityProfile:
    """Creates a new protected reference identity profile with audit trail."""
    try:
        return global_protected_identity_manager.create_profile(request, db=db)
    except Exception as e:
        logger.error(f"Failed to create protected identity profile: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Could not create protected identity profile: {str(e)}",
        )


@router.get("/profiles/{profile_id}", response_model=ProtectedIdentityProfile)
def get_protected_identity(
    profile_id: str,
    db: Session = Depends(get_db),
) -> ProtectedIdentityProfile:
    """Retrieves a specific protected identity profile by ID."""
    profile = global_protected_identity_manager.get_by_id(profile_id, db=db)
    if not profile:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Protected identity profile '{profile_id}' not found.",
        )
    return profile


@router.put("/profiles/{profile_id}", response_model=ProtectedIdentityProfile)
def update_protected_identity(
    profile_id: str,
    request: UpdateProtectedIdentityRequest,
    db: Session = Depends(get_db),
) -> ProtectedIdentityProfile:
    """Updates an existing profile, incrementing its revision and recording audit logs."""
    updated = global_protected_identity_manager.update_profile(profile_id, request, db=db)
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Protected identity profile '{profile_id}' not found.",
        )
    return updated


@router.delete("/profiles/{profile_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_protected_identity(
    profile_id: str,
    db: Session = Depends(get_db),
):
    """Deactivates a protected identity profile and writes an audit log."""
    success = global_protected_identity_manager.disable_profile(profile_id, db=db)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Protected identity profile '{profile_id}' not found.",
        )
    return None


@router.post("/analyze", response_model=ImpersonationAnalysisResponse)
def analyze_impersonation(
    request: ImpersonationAnalysisRequest,
    db: Session = Depends(get_db),
) -> ImpersonationAnalysisResponse:
    """
    Analyzes an email, URL, website, or cross-channel bundle for digital impersonation.
    """
    try:
        return global_impersonation_pipeline.analyze(
            artifact_type=request.artifact_type,
            email_data=request.email_data,
            url_data=request.url_data,
            website_data=request.website_data,
            target_identity_hint=request.target_identity_hint,
            artifact_id=request.artifact_id,
            db=db,
            trigger=AnalysisTriggerEnum.USER,
        )
    except Exception as e:
        logger.error(f"Impersonation analysis failed: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Impersonation analysis error: {str(e)}",
        )


@router.post("/reanalyze/{artifact_id}", response_model=ImpersonationAnalysisResponse)
def reanalyze_impersonation(
    artifact_id: str,
    db: Session = Depends(get_db),
) -> ImpersonationAnalysisResponse:
    """
    Re-analyzes an existing artifact for impersonation, generating a new AnalysisRun
    without overwriting historical analysis records.
    """
    art = db.query(ArtifactModel).filter(ArtifactModel.id == artifact_id).first()
    if not art:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Artifact '{artifact_id}' not found.",
        )

    meta = {}
    try:
        meta = json.loads(art.metadata_json or "{}")
    except Exception:
        pass

    email_data = meta.get("email_data")
    url_data = meta.get("url_data")
    website_data = meta.get("website_data")

    # If artifact is URL/DOMAIN, extract from content or metadata
    if art.artifact_type == ArtifactTypeEnum.URL.value and not url_data:
        url_data = {"url": art.name}
    elif art.artifact_type == ArtifactTypeEnum.EMAIL.value and not email_data:
        email_data = meta.get("parsed_email", {})

    return global_impersonation_pipeline.analyze(
        artifact_type=ArtifactTypeEnum(art.artifact_type) if art.artifact_type in ArtifactTypeEnum._value2member_map_ else ArtifactTypeEnum.UNKNOWN,
        email_data=email_data,
        url_data=url_data,
        website_data=website_data,
        artifact_id=artifact_id,
        db=db,
        trigger=AnalysisTriggerEnum.REANALYSIS,
    )


@router.get("/audit-logs", response_model=List[Dict[str, Any]])
def get_impersonation_audit_logs(
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
) -> List[Dict[str, Any]]:
    """Retrieves immutable audit logs for protected identity configuration events."""
    logs = (
        db.query(AuditLogModel)
        .filter(AuditLogModel.resource_type == "protected_identity")
        .order_by(AuditLogModel.timestamp.desc())
        .limit(limit)
        .all()
    )

    results = []
    for log in logs:
        results.append({
            "id": log.id,
            "timestamp": log.timestamp.isoformat() if log.timestamp else None,
            "user": log.user,
            "action": log.action,
            "resource_id": log.resource_id,
            "details": log.details,
            "metadata": json.loads(log.metadata_json or "{}"),
        })
    return results
