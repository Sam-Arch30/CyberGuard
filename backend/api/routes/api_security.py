"""
API Abuse Security API Endpoints.
Provides routes for API telemetry ingestion, batch analysis, log file uploads,
artifact re-analysis, engine configuration, and account baseline profile inspection.
"""
from __future__ import annotations

import csv
import io
import json
import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File, status
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.db.models import ArtifactModel, EntityModel
from backend.schemas.unified import EntityTypeEnum
from backend.schemas.api_security import (
    APIConfigResponse,
    APISecurityAnalysisResponse,
    AccountAPIBaselineProfile,
)
from backend.services.api_pipeline import global_api_pipeline

logger = logging.getLogger("cyberguard.api.api_security")

router = APIRouter(prefix="/api/api-security", tags=["API Security"])


@router.get("/config", response_model=APIConfigResponse)
def get_api_security_config() -> APIConfigResponse:
    """
    Returns active configuration parameters, detection thresholds, and sensitive routes.
    """
    return global_api_pipeline.config


@router.post("/analyze-event", response_model=APISecurityAnalysisResponse)
async def analyze_single_api_event(
    event_payload: Dict[str, Any],
    provider_hint: Optional[str] = Query(None, description="Optional adapter hint (generic_json, generic_csv, gateway_json)"),
    db: Session = Depends(get_db),
) -> APISecurityAnalysisResponse:
    """
    Analyze a single API request/telemetry event.
    """
    try:
        response = await global_api_pipeline.analyze_events(
            raw_events=[event_payload],
            db=db,
            provider_hint=provider_hint,
        )
        return response
    except Exception as e:
        logger.error(f"Error analyzing single API event: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"API event analysis failed: {str(e)}",
        )


@router.post("/analyze-batch", response_model=APISecurityAnalysisResponse)
async def analyze_batch_api_events(
    events: List[Dict[str, Any]],
    provider_hint: Optional[str] = Query(None, description="Optional adapter hint"),
    db: Session = Depends(get_db),
) -> APISecurityAnalysisResponse:
    """
    Analyze a batch of API telemetry events.
    """
    try:
        response = await global_api_pipeline.analyze_events(
            raw_events=events,
            db=db,
            provider_hint=provider_hint,
        )
        return response
    except Exception as e:
        logger.error(f"Error analyzing batch API events: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Batch API analysis failed: {str(e)}",
        )


@router.post("/upload-log", response_model=APISecurityAnalysisResponse)
async def upload_api_log_file(
    file: UploadFile = File(...),
    provider_hint: Optional[str] = Query(None, description="Optional adapter hint (generic_json, generic_csv, gateway_json)"),
    db: Session = Depends(get_db),
) -> APISecurityAnalysisResponse:
    """
    Upload and analyze API telemetry logs (JSON array, JSON lines, or CSV).
    """
    try:
        content_bytes = await file.read()
        text_content = content_bytes.decode("utf-8", errors="replace")

        raw_events: List[Any] = []
        filename = (file.filename or "").lower()

        # Try parsing JSON first
        if filename.endswith(".json") or text_content.strip().startswith(("[", "{")):
            try:
                parsed = json.loads(text_content)
                if isinstance(parsed, list):
                    raw_events = parsed
                elif isinstance(parsed, dict):
                    raw_events = [parsed]
            except json.JSONDecodeError:
                # Try JSON Lines
                for line in text_content.splitlines():
                    line = line.strip()
                    if line:
                        try:
                            raw_events.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue

        # If not parsed as JSON, try CSV
        if not raw_events and (filename.endswith(".csv") or "," in text_content.splitlines()[0] if text_content.splitlines() else False):
            reader = csv.DictReader(io.StringIO(text_content))
            for row in reader:
                raw_events.append(dict(row))
            if not provider_hint:
                provider_hint = "generic_csv"

        if not raw_events:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Unable to parse log file as JSON, JSON Lines, or CSV.",
            )

        response = await global_api_pipeline.analyze_events(
            raw_events=raw_events,
            db=db,
            provider_hint=provider_hint,
        )
        return response

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error processing uploaded API log: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"API log processing failed: {str(e)}",
        )


@router.post("/reanalyze/{artifact_id}", response_model=APISecurityAnalysisResponse)
async def reanalyze_api_artifact(
    artifact_id: str,
    db: Session = Depends(get_db),
) -> APISecurityAnalysisResponse:
    """
    Re-analyze an existing stored API log artifact, creating a new AnalysisRun.
    """
    try:
        response = await global_api_pipeline.reanalyze_artifact(
            artifact_id=artifact_id,
            db=db,
        )
        return response
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(ve))
    except Exception as e:
        logger.error(f"Error reanalyzing API artifact {artifact_id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"API re-analysis failed: {str(e)}",
        )


@router.get("/account/{account_id}", response_model=Optional[AccountAPIBaselineProfile])
def get_account_profile(
    account_id: str,
    db: Session = Depends(get_db),
) -> Optional[AccountAPIBaselineProfile]:
    """
    Retrieves the baseline profile and historical known endpoints/methods for an account.
    """
    profile = global_api_pipeline.get_account_profile(account_id)
    if profile:
        return profile

    # Fallback: check database entity
    ent = db.query(EntityModel).filter(
        EntityModel.entity_type == EntityTypeEnum.ACCOUNT.value,
        EntityModel.name == account_id,
    ).first()
    if not ent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No API baseline profile found for account: {account_id}",
        )

    return AccountAPIBaselineProfile(
        account_id=account_id,
        is_service_account="service" in account_id.lower(),
        total_requests_observed=1,
        first_seen=ent.first_seen,
        last_seen=ent.last_seen,
    )
