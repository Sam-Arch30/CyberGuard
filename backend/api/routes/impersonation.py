"""
Digital Impersonation API Endpoints (Section 12).
Provides REST endpoints for Protected Identity Profile management,
audit event inspection, and multi-channel digital impersonation analysis.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status, UploadFile, File, Form
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
            detail='Could not create protected identity profile.',
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


@router.post('/upload', response_model=ImpersonationAnalysisResponse)
async def upload_identity_evidence(
    file: UploadFile = File(...),
    target_identity_hint: Optional[str] = Form(None),
    db: Session = Depends(get_db),
):
    """Analyze an original EML or JSON sender claim; retain its bytes and hash."""
    from email import policy
    from email.parser import BytesParser
    from pydantic import ValidationError
    from backend.services.upload_security import UploadSecurityService
    import uuid
    raw = await UploadSecurityService.read_bounded_upload(file, max_bytes=1024 * 1024)
    filename = UploadSecurityService.sanitize_filename(file.filename)
    if target_identity_hint and not global_protected_identity_manager.get_by_id(target_identity_hint, db=db):
        raise HTTPException(404, 'The selected trusted profile is unavailable in this workspace.')
    try:
        if not raw:
            raise ValueError('Identity evidence is empty.')
        if filename.lower().endswith('.json'):
            data = json.loads(raw.decode('utf-8-sig'))
            if not isinstance(data, dict):
                raise ValueError('Provide one JSON sender claim, not a list.')
            claim = data.get('email_data', data)
            if not isinstance(claim, dict):
                raise ValueError('email_data must be a JSON object.')
        elif filename.lower().endswith('.eml'):
            message = BytesParser(policy=policy.default).parsebytes(raw)
            if len(message.get_all('From', [])) != 1:
                raise ValueError('The EML must contain exactly one From header.')
            part = message.get_body(preferencelist=('plain', 'html'))
            claim = {'from_address': str(message.get('From', '')),
                     'reply_to_address': str(message.get('Reply-To', '')),
                     'subject': str(message.get('Subject', '')),
                     'body_text': part.get_content() if part else ''}
        else:
            raise ValueError('Upload .eml email evidence or a .json sender claim.')
        request = ImpersonationAnalysisRequest(email_data=claim, target_identity_hint=target_identity_hint)
    except ValidationError as exc:
        raise HTTPException(422, f"Invalid identity evidence: {exc.errors()[0]['msg']}") from exc
    except (ValueError, UnicodeError, LookupError) as exc:
        raise HTTPException(422, f'Invalid identity evidence: {exc}') from exc
    try:
        stored = evidence_storage.store_bytes(raw, original_filename=filename, mime_type=file.content_type)
        artifact = ArtifactModel(id=str(uuid.uuid4()), artifact_type='EMAIL', name=filename,
            source='IDENTITY_UPLOAD', mime_type=file.content_type, size=len(raw),
            sha256=stored.sha256, storage_reference=stored.storage_key,
            metadata_json=json.dumps({'email_data': request.email_data}))
        db.add(artifact); db.commit()
        request.artifact_id = artifact.id
        return analyze_impersonation(request, db)
    except HTTPException:
        raise
    except Exception:
        logger.exception('Identity upload analysis failed')
        raise HTTPException(500, 'Identity upload analysis failed. Please retry.')


@router.post("/analyze", response_model=ImpersonationAnalysisResponse)
def analyze_impersonation(
    request: ImpersonationAnalysisRequest,
    db: Session = Depends(get_db),
) -> ImpersonationAnalysisResponse:
    """
    Analyzes an email, URL, website, or cross-channel bundle for digital impersonation.
    """
    if request.artifact_id:
        artifact = db.get(ArtifactModel, request.artifact_id)
        if not artifact: raise HTTPException(404, 'Artifact not found.')
    else:
        import hashlib
        import uuid
        raw = request.model_dump_json().encode()
        artifact = ArtifactModel(id=str(uuid.uuid4()), artifact_type=request.artifact_type.value,
            name='Identity claim assessment', source='API', mime_type='application/json',
            sha256=hashlib.sha256(raw).hexdigest(), size=len(raw),
            metadata_json=json.dumps({'claim':request.model_dump(mode='json')}))
        db.add(artifact); db.commit()
        request.artifact_id = artifact.id
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
            detail='Impersonation analysis error.',
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

    email_data = meta.get("email_data") or meta.get("claim", {}).get("email_data")
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
