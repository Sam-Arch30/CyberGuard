"""
Multimedia Authenticity API Endpoints (Section 13).
Provides REST endpoints for media forensics, deepfake detection, detector registry inspection,
and re-analysis.
"""
from __future__ import annotations

import base64
import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File, Form, status
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.db.models import ArtifactModel, AnalysisRunModel
from backend.schemas.unified import AnalysisTriggerEnum
from backend.schemas.multimedia import (
    MediaAnalysisRequest,
    MediaAnalysisResponse,
    MediaIdentity,
    DetectorResult,
    DetectorStatusEnum,
)
from backend.services.multimedia_service import (
    MultimediaPipeline,
    MediaFormatIdentifier,
    MAX_MEDIA_BYTES,
)
from backend.services.evidence_storage import evidence_storage

logger = logging.getLogger("cyberguard.api.multimedia")

router = APIRouter(prefix="/api/multimedia", tags=["Multimedia Forensics"])
global_multimedia_pipeline = MultimediaPipeline()


@router.get("/detectors", response_model=List[Dict[str, Any]])
def list_detectors() -> List[Dict[str, Any]]:
    """
    Lists all registered media detector adapters, their versions, supported media types,
    and operational capabilities.
    """
    detectors_info = []
    for d in global_multimedia_pipeline.registry._detectors.values():
        detectors_info.append({
            "detector_id": d.detector_id,
            "detector_name": d.detector_name,
            "detector_version": d.detector_version,
            "supported_media_types": [mt.value for mt in d.supported_media_types],
            "model_name": d.model_name,
            "model_version": d.model_version,
            "status": DetectorStatusEnum.SUCCESS.value,
        })
    return detectors_info


@router.post("/analyze", response_model=MediaAnalysisResponse)
def analyze_media_payload(
    request: MediaAnalysisRequest,
    db: Session = Depends(get_db),
) -> MediaAnalysisResponse:
    """
    Analyzes base64-encoded media bytes or an existing stored artifact for synthetic manipulation,
    deepfakes, and provenance credentials.
    """
    media_bytes = b""
    filename = request.filename

    if request.media_bytes_b64:
        try:
            media_bytes = base64.b64decode(request.media_bytes_b64)
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid base64 media payload: {str(e)}",
            )
    elif request.artifact_id:
        art = db.query(ArtifactModel).filter(ArtifactModel.id == request.artifact_id).first()
        if not art:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Artifact '{request.artifact_id}' not found.",
            )
        filename = art.source_uri or filename
        # Attempt to read from evidence storage
        raw = evidence_storage.retrieve(request.artifact_id)
        if raw is not None:
            media_bytes = raw
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Raw media content for artifact '{request.artifact_id}' is unavailable.",
            )
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Must provide either 'media_bytes_b64' or 'artifact_id'.",
        )

    if len(media_bytes) > MAX_MEDIA_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Media size exceeds maximum permitted limit ({len(media_bytes)} > {MAX_MEDIA_BYTES} bytes).",
        )

    try:
        assessment = global_multimedia_pipeline.analyze_media(
            data=media_bytes,
            original_filename=filename,
            artifact_id=request.artifact_id,
            context_claimed_identity_id=request.context_claimed_identity_id,
            trigger=AnalysisTriggerEnum.USER,
            db=db,
        )

        media_type, media_format, mime_type = MediaFormatIdentifier.identify(media_bytes, filename)

        import hashlib
        sha256 = hashlib.sha256(media_bytes).hexdigest()

        identity = MediaIdentity(
            artifact_id=assessment.artifact_id,
            sha256=sha256,
            original_filename=filename,
            mime_type=mime_type,
            media_type=media_type,
            format=media_format,
            size_bytes=len(media_bytes),
        )

        return MediaAnalysisResponse(
            success=True,
            artifact_id=assessment.artifact_id,
            analysis_run_id=assessment.analysis_run_id,
            media_identity=identity,
            assessment=assessment,
        )

    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
    except Exception as e:
        logger.exception("Error executing multimedia analysis")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Analysis failed: {str(e)}")


@router.post("/upload", response_model=MediaAnalysisResponse)
async def upload_and_analyze_media(
    file: UploadFile = File(...),
    context_claimed_identity_id: Optional[str] = Form(None),
    db: Session = Depends(get_db),
) -> MediaAnalysisResponse:
    """Uploads a media file directly for comprehensive authenticity and deepfake analysis."""
    media_bytes = await file.read()

    if len(media_bytes) > MAX_MEDIA_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Uploaded file exceeds {MAX_MEDIA_BYTES // (1024 * 1024)}MB limit.",
        )

    filename = file.filename or "uploaded_media"

    assessment = global_multimedia_pipeline.analyze_media(
        data=media_bytes,
        original_filename=filename,
        context_claimed_identity_id=context_claimed_identity_id,
        trigger=AnalysisTriggerEnum.USER,
        db=db,
    )

    media_type, media_format, mime_type = MediaFormatIdentifier.identify(media_bytes, filename)
    import hashlib
    sha256 = hashlib.sha256(media_bytes).hexdigest()

    identity = MediaIdentity(
        artifact_id=assessment.artifact_id,
        sha256=sha256,
        original_filename=filename,
        mime_type=mime_type,
        media_type=media_type,
        format=media_format,
        size_bytes=len(media_bytes),
    )

    return MediaAnalysisResponse(
        success=True,
        artifact_id=assessment.artifact_id,
        analysis_run_id=assessment.analysis_run_id,
        media_identity=identity,
        assessment=assessment,
    )


@router.post("/reanalyze/{artifact_id}", response_model=MediaAnalysisResponse)
def reanalyze_media_artifact(
    artifact_id: str,
    db: Session = Depends(get_db),
) -> MediaAnalysisResponse:
    """
    Triggers re-analysis of a previously ingested media artifact without overwriting
    historical analysis runs.
    """
    art = db.query(ArtifactModel).filter(ArtifactModel.id == artifact_id).first()
    if not art:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Artifact '{artifact_id}' not found.")

    raw = evidence_storage.retrieve(artifact_id)
    if raw is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Binary payload for artifact '{artifact_id}' is not in persistent storage.",
        )

    assessment = global_multimedia_pipeline.analyze_media(
        data=raw,
        original_filename=art.source_uri or "stored_media",
        artifact_id=artifact_id,
        trigger=AnalysisTriggerEnum.REANALYSIS,
        db=db,
    )

    media_type, media_format, mime_type = MediaFormatIdentifier.identify(raw, art.source_uri or "")
    import hashlib
    sha256 = hashlib.sha256(raw).hexdigest()

    identity = MediaIdentity(
        artifact_id=artifact_id,
        sha256=sha256,
        original_filename=art.source_uri or "stored_media",
        mime_type=mime_type,
        media_type=media_type,
        format=media_format,
        size_bytes=len(raw),
    )

    return MediaAnalysisResponse(
        success=True,
        artifact_id=artifact_id,
        analysis_run_id=assessment.analysis_run_id,
        media_identity=identity,
        assessment=assessment,
    )
