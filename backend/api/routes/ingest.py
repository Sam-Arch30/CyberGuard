"""
Universal Ingestion Gateway API routes.

Provides canonical endpoints to ingest files, URLs, domains, IPs, text, and structured events
into CyberGuard's persistent forensic architecture.
"""
from __future__ import annotations
from backend.services.upload_security import UploadSecurityService

import json
import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, File, Form, Header, HTTPException, Request, UploadFile, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.schemas.unified import (
    AnalyzerCapabilityRead,
    DetectedInput,
    DetectInputRequest,
    IngestEventRequest,
    IngestionResult,
    IngestTextRequest,
)
from backend.services.universal_ingestion import (
    global_capability_registry,
    FileTooLargeError,
    IngestionException,
    InvalidInputError,
    MalformedEventError,
    StorageFailureError,
    TypeDetector,
    UniversalIngestionService,
)

logger = logging.getLogger("cyberguard.api.ingest")

router = APIRouter(prefix="/api/ingest", tags=["Universal Ingestion"])


# ============================================================================
# CANONICAL INGESTION ENDPOINT
# ============================================================================

@router.post(
    "",
    response_model=IngestionResult,
    summary="Universal Evidence Ingestion Gateway",
    description=(
        "Accepts cybersecurity evidence in any supported format (multipart file upload, "
        "raw text/URL/domain/IP, or structured JSON security event), determines artifact type, "
        "validates security constraints, persists original evidence, and resolves candidate analyzers."
    ),
    responses={
        400: {"description": "Invalid input, empty payload, or malformed event"},
        413: {"description": "Payload exceeds maximum allowed upload size"},
        422: {"description": "Validation or classification failure"},
    }
)
async def ingest_evidence(
    request: Request,
    user: Optional[str] = Header(None, alias="X-User"),
    db: Session = Depends(get_db)
):
    """
    Polymorphic ingestion entrypoint. Inspects Content-Type:
    - multipart/form-data: processes file upload with metadata.
    - application/json: processes text, URL, domain, IP, or structured security event.
    """
    content_type = request.headers.get("content-type", "").lower()
    uploader_identity = (user or "SOC Analyst").strip()

    try:
        # A. Multipart File Upload
        if "multipart/form-data" in content_type:
            form = await request.form()
            file_item = form.get("file")
            if not file_item or not hasattr(file_item, "read"):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Multipart form must include a 'file' field."
                )

            content_bytes = await UploadSecurityService.read_bounded_upload(file_item, max_bytes=50 * 1024 * 1024)
            raw_filename = getattr(file_item, "filename", None) or "upload.bin"
            file_mime = getattr(file_item, "content_type", None)

            source = form.get("source") or "UPLOAD"
            notes = form.get("notes")
            case_id = form.get("case_id")
            incident_id = form.get("incident_id")
            request_id = form.get("request_id")

            return UniversalIngestionService.ingest_file(
                db=db,
                content_bytes=content_bytes,
                filename=raw_filename,
                reported_mime=file_mime,
                source=source,
                submitted_by=uploader_identity,
                notes=notes,
                case_id=case_id,
                incident_id=incident_id,
                request_id=request_id,
            )

        # B. JSON Payload (Text, URL, Domain, IP, or Structured Event)
        elif "application/json" in content_type or not content_type:
            try:
                body = await request.json()
            except HTTPException:
                raise
            except Exception as e:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail='Malformed JSON request body.'
                )

            if not isinstance(body, dict):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="JSON payload must be a JSON object."
                )

            # Check if structured event payload
            if "event" in body and isinstance(body["event"], dict):
                return UniversalIngestionService.ingest_event(
                    db=db,
                    event_dict=body["event"],
                    source_type=body.get("source_type"),
                    source=body.get("source", "STRUCTURED_EVENT"),
                    submitted_by=body.get("submitted_by") or uploader_identity,
                    notes=body.get("notes"),
                    case_id=body.get("case_id"),
                    incident_id=body.get("incident_id"),
                    request_id=body.get("request_id"),
                )

            # Check if text payload
            text_val = body.get("text") or body.get("value") or body.get("input")
            if text_val and isinstance(text_val, str):
                return UniversalIngestionService.ingest_text(
                    db=db,
                    text=text_val,
                    source=body.get("source", "TEXT_INPUT"),
                    submitted_by=body.get("submitted_by") or uploader_identity,
                    notes=body.get("notes"),
                    case_id=body.get("case_id"),
                    incident_id=body.get("incident_id"),
                    request_id=body.get("request_id"),
                )

            # If body directly contains an event dictionary (e.g. event_type, auth_status, etc.)
            if any(k in body for k in ("event_type", "source_type", "auth", "login", "user_id")):
                return UniversalIngestionService.ingest_event(
                    db=db,
                    event_dict=body,
                    source_type=body.get("source_type"),
                    source="STRUCTURED_EVENT",
                    submitted_by=uploader_identity,
                )

            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Request body must contain either 'file' in multipart, 'text' in JSON, or 'event' dictionary."
            )

        else:
            # Fallback raw text stream
            raw_body = await request.body()
            text_str = raw_body.decode("utf-8", errors="replace")
            if not text_str.strip():
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Raw request body cannot be empty."
                )
            return UniversalIngestionService.ingest_text(
                db=db,
                text=text_str,
                source="RAW_STREAM",
                submitted_by=uploader_identity,
            )

    except HTTPException:
        raise
    except FileTooLargeError as e:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE if hasattr(status, "HTTP_413_REQUEST_ENTITY_TOO_LARGE") else 413,
            detail=e.message
        )
    except (InvalidInputError, MalformedEventError) as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=e.message)
    except StorageFailureError as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=e.message)
    except IngestionException as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=e.message)
    except Exception:
        db.rollback()
        logger.exception('Ingestion failed while processing evidence')
        raise HTTPException(500, 'Evidence processing failed. Check the backend logs and database schema.')



# ============================================================================
# EXPLICIT MODAL SUBROUTES
# ============================================================================

@router.post(
    "/file",
    response_model=IngestionResult,
    summary="Ingest File Upload",
    description="Explicit file upload endpoint (multipart/form-data)."
)
async def ingest_file_endpoint(
    file: UploadFile = File(...),
    source: Optional[str] = Form("UPLOAD"),
    submitted_by: Optional[str] = Form(None),
    notes: Optional[str] = Form(None),
    case_id: Optional[str] = Form(None),
    incident_id: Optional[str] = Form(None),
    request_id: Optional[str] = Form(None),
    user: Optional[str] = Header(None, alias="X-User"),
    db: Session = Depends(get_db)
):
    uploader = (submitted_by or user or "SOC Analyst").strip()
    try:
        content_bytes = await UploadSecurityService.read_bounded_upload(file, max_bytes=50 * 1024 * 1024)
        return UniversalIngestionService.ingest_file(
            db=db,
            content_bytes=content_bytes,
            filename=file.filename or "upload.bin",
            reported_mime=file.content_type,
            source=source,
            submitted_by=uploader,
            notes=notes,
            case_id=case_id,
            incident_id=incident_id,
            request_id=request_id,
        )
    except FileTooLargeError as e:
        raise HTTPException(status_code=413, detail=e.message)
    except (InvalidInputError, MalformedEventError) as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=e.message)
    except StorageFailureError as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=e.message)


@router.post(
    "/text",
    response_model=IngestionResult,
    summary="Ingest Text / URL / Domain / IP",
    description="Explicit text ingestion endpoint (application/json)."
)
async def ingest_text_endpoint(
    req: IngestTextRequest,
    user: Optional[str] = Header(None, alias="X-User"),
    db: Session = Depends(get_db)
):
    uploader = (req.submitted_by or user or "SOC Analyst").strip()
    try:
        return UniversalIngestionService.ingest_text(
            db=db,
            text=req.text,
            source=req.source,
            submitted_by=uploader,
            notes=req.notes,
            case_id=req.case_id,
            incident_id=req.incident_id,
            request_id=req.request_id,
        )
    except (InvalidInputError, MalformedEventError) as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=e.message)
    except StorageFailureError as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=e.message)


@router.post(
    "/event",
    response_model=IngestionResult,
    summary="Ingest Structured Security Event",
    description="Explicit structured event ingestion endpoint (application/json)."
)
async def ingest_event_endpoint(
    req: IngestEventRequest,
    user: Optional[str] = Header(None, alias="X-User"),
    db: Session = Depends(get_db)
):
    uploader = (req.submitted_by or user or "SOC Analyst").strip()
    try:
        return UniversalIngestionService.ingest_event(
            db=db,
            event_dict=req.event,
            source_type=req.source_type,
            source=req.source,
            submitted_by=uploader,
            notes=req.notes,
            case_id=req.case_id,
            incident_id=req.incident_id,
            request_id=req.request_id,
        )
    except (InvalidInputError, MalformedEventError) as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=e.message)
    except StorageFailureError as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=e.message)


# ============================================================================
# DETECTION & CAPABILITY INSPECTION ENDPOINTS
# ============================================================================

@router.post(
    "/detect",
    response_model=DetectedInput,
    summary="Pre-Flight Type Detection & Classification",
    description=(
        "Inspects an input without persisting it to storage or creating database records. "
        "Useful for UI drag-and-drop feedback, pre-flight validation, and detector debugging."
    )
)
async def detect_input_endpoint(
    req: DetectInputRequest
):
    if not req.text:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Must provide 'text' to detect.")
    try:
        return UniversalIngestionService.detect_only(text=req.text)
    except IngestionException as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=e.message)


@router.get(
    "/capabilities",
    response_model=List[AnalyzerCapabilityRead],
    summary="List Analyzer Capabilities",
    description="Lists all detection and analysis capabilities in the CyberGuard platform with their status and supported artifact types."
)
def list_capabilities_endpoint():
    caps = global_capability_registry.list_all()
    return [
        AnalyzerCapabilityRead(
            name=c.name,
            version=c.version,
            supported_artifact_types=c.supported_artifact_types,
            status=c.status,
            description=c.description,
        )
        for c in caps
    ]
