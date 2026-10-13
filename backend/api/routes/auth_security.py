"""
Authentication and Account Takeover (ATO) Security API Endpoints.
Provides routes for event ingestion, batch log analysis, artifact re-analysis,
and detection engine configuration.
"""
from __future__ import annotations
from backend.services.upload_security import UploadSecurityService

import json
import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File, status
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.db.models import ArtifactModel, EntityModel
from backend.schemas.unified import EntityTypeEnum
from backend.schemas.authentication_security import (
    AuthConfigResponse,
    AuthEventBatch,
    AuthSecurityAnalysisResponse,
    AccountSecurityProfile,
    BaselineStatusEnum,
)
from backend.services.authentication_pipeline import global_auth_pipeline

logger = logging.getLogger("cyberguard.api.auth_security")

router = APIRouter(prefix="/api/auth-security", tags=["Authentication Security"])


@router.get("/config", response_model=AuthConfigResponse)
def get_auth_security_config() -> AuthConfigResponse:
    """
    Returns active configuration parameters, detection thresholds, and temporal windows.
    """
    return global_auth_pipeline.config


@router.post("/analyze-event", response_model=AuthSecurityAnalysisResponse)
async def analyze_single_event(
    event_payload: Dict[str, Any],
    provider_hint: Optional[str] = Query(None, description="Optional adapter hint (okta, entra_id, google_workspace, linux_auth, generic)"),
    db: Session = Depends(get_db),
) -> AuthSecurityAnalysisResponse:
    """
    Analyze a single authentication event against historical baseline and detection rules.
    """
    try:
        response = await global_auth_pipeline.analyze_events(
            raw_events=[event_payload],
            db=db,
            provider_hint=provider_hint,
        )
        return response
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error analyzing single authentication event: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail='Authentication analysis failed.',
        )


@router.post("/analyze-batch", response_model=AuthSecurityAnalysisResponse)
async def analyze_batch_events(
    batch: AuthEventBatch,
    db: Session = Depends(get_db),
) -> AuthSecurityAnalysisResponse:
    """
    Analyze a batch of authentication events (e.g. from SIEM forwarder or bulk export).
    """
    try:
        response = await global_auth_pipeline.analyze_events(
            raw_events=batch.events,
            db=db,
            provider_hint=batch.provider_hint,
        )
        return response
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error analyzing batch authentication events: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail='Batch authentication analysis failed.',
        )


@router.post("/upload-log", response_model=AuthSecurityAnalysisResponse)
async def upload_log_file(
    file: UploadFile = File(...),
    provider_hint: Optional[str] = Query(None, description="Optional adapter hint (linux_auth, okta, entra_id, etc.)"),
    db: Session = Depends(get_db),
) -> AuthSecurityAnalysisResponse:
    """
    Upload and analyze an authentication log file (JSON array, JSON lines, or Linux syslog format).
    """
    try:
        content_bytes = await UploadSecurityService.read_bounded_upload(file, max_bytes=50 * 1024 * 1024)
        from backend.services.auth_log_parser import parse_auth_log
        raw_events = parse_auth_log(content_bytes, file.filename or '', file.content_type or '', provider_hint)

        response = await global_auth_pipeline.analyze_events(
            raw_events=raw_events,
            db=db,
            provider_hint=provider_hint,
        )
        return response
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error analyzing uploaded authentication log: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail='Log file analysis failed.',
        )


@router.post("/analyze-artifact/{artifact_id}", response_model=AuthSecurityAnalysisResponse)
async def analyze_stored_artifact(
    artifact_id: str,
    db: Session = Depends(get_db),
) -> AuthSecurityAnalysisResponse:
    """
    Re-analyze a stored AUTH_LOG artifact directly from evidence storage.
    Creates a new independent AnalysisRunModel with full historical provenance.
    """
    try:
        return await global_auth_pipeline.analyze_artifact(artifact_id=artifact_id, db=db)
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(ve))
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error re-analyzing artifact {artifact_id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail='Artifact re-analysis failed.',
        )


@router.get("/accounts/{account_id}/profile", response_model=AccountSecurityProfile)
def get_account_profile(
    account_id: str,
    db: Session = Depends(get_db),
) -> AccountSecurityProfile:
    """
    Returns the historical security profile and baseline status for an account.
    """
    clean_account = account_id.strip().lower()
    entity = db.query(EntityModel).filter(
        EntityModel.entity_type == EntityTypeEnum.ACCOUNT.value,
        EntityModel.name == clean_account,
    ).first()

    if not entity:
        return AccountSecurityProfile(
            account_id=clean_account,
            baseline_status=BaselineStatusEnum.NEW_ENTITY,
            total_successful_logins=0,
            total_failed_logins=0,
            known_source_ips=[],
            known_devices=[],
            known_countries=[],
            known_client_profiles=[],
            typical_login_hours=[],
        )

    # Decode attributes
    attrs = json.loads(entity.attributes_json or "{}")
    return AccountSecurityProfile(
        account_id=clean_account,
        baseline_status=BaselineStatusEnum.ESTABLISHED if attrs.get("success_count", 0) >= 5 else BaselineStatusEnum.INSUFFICIENT_HISTORY,
        first_seen=entity.first_seen,
        last_seen=entity.last_seen,
        total_successful_logins=attrs.get("success_count", 0),
        total_failed_logins=attrs.get("failure_count", 0),
        known_source_ips=attrs.get("known_ips", []),
        known_devices=attrs.get("known_devices", []),
        known_countries=attrs.get("known_countries", []),
        known_client_profiles=attrs.get("known_profiles", []),
        typical_login_hours=attrs.get("typical_hours", []),
        mfa_always_used=attrs.get("mfa_always_used", False),
    )
