"""
Section 68: Evidence & Forensics Workspace REST API Router.
Authoritative endpoints for managing forensic evidence, cryptographic integrity,
immutable chain-of-custody, provenance lineage, safe previews, and legal export packages.
"""
from __future__ import annotations

import base64
import io
import logging
from typing import Any, Dict, List, Optional

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Header,
    Path,
    Query,
    UploadFile,
    status,
)
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.schemas.evidence_workspace import (
    EvidenceClassificationEnum,
    EvidenceCollectionMethodEnum,
    EvidenceCustodyAddRequest,
    EvidenceCustodyEventResponse,
    EvidenceDerivationRequest,
    EvidenceDetailResponse,
    EvidenceExportManifestResponse,
    EvidenceIntegrityVerificationResponse,
    EvidenceListResponse,
    EvidenceMetricsResponse,
    EvidenceNoteAddRequest,
    EvidencePreservationRequest,
    EvidencePreviewResponse,
    EvidenceRegistrationRequest,
    EvidenceRetentionPolicyEnum,
    EvidenceSourceTypeEnum,
)
from backend.services.evidence_service import EvidenceService
from backend.services.evidence_storage import evidence_storage

logger = logging.getLogger("cyberguard.evidence_workspace_api")

router = APIRouter(prefix="/api/v1/evidence", tags=["Evidence & Forensics Workspace"])


def get_current_user_and_role(
    x_user: Optional[str] = Header(None, alias="X-User"),
    x_actor_id: Optional[str] = Header(None, alias="X-Actor-ID"),
    x_role: Optional[str] = Header(None, alias="X-Role"),
    x_user_role: Optional[str] = Header(None, alias="X-User-Role"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
) -> tuple[str, str]:
    user = (x_user or x_actor_id or "").strip() or "SOC Analyst"
    role = (x_role or x_user_role or "").strip().lower()

    if not role and authorization:
        auth_clean = authorization.strip().lower()
        if "admin" in auth_clean or "lead" in auth_clean:
            role = "admin"
        elif "analyst" in auth_clean or "soc" in auth_clean:
            role = "analyst"
        elif "viewer" in auth_clean or "unauthorized" in auth_clean:
            role = "unauthorized"

    if role in ("guest", "unauthorized", "untrusted"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: insufficient permissions for forensic evidence operations.",
        )

    return user, role or "analyst"


# =============================================================================
# Evidence Listing and Metrics
# =============================================================================

@router.get(
    "",
    response_model=EvidenceListResponse,
    summary="List evidence records",
    description="Returns paginated, searchable forensic evidence records with filter controls and workspace metrics.",
)
def list_evidence(
    source_type: Optional[str] = Query(None, description="Filter by source type (EMAIL, FILE, ATTACHMENT, URL, etc.)"),
    integrity_status: Optional[str] = Query(None, description="Filter by integrity (VERIFIED, MISMATCH, PENDING, UNKNOWN)"),
    classification: Optional[str] = Query(None, description="Filter by classification (PUBLIC, INTERNAL, CONFIDENTIAL, etc.)"),
    preservation_status: Optional[str] = Query(None, description="Filter by preservation (NORMAL, PRESERVED, ON_HOLD)"),
    case_id: Optional[str] = Query(None, description="Filter by linked Case ID"),
    investigation_id: Optional[str] = Query(None, description="Filter by linked Investigation ID"),
    query: Optional[str] = Query(None, alias="q", description="Search by filename, Evidence ID, or SHA-256 hash"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=200, description="Page size"),
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    x_tenant_id: Optional[str] = Header(None, alias="X-Tenant-ID"),
    db: Session = Depends(get_db),
    user_info: tuple[str, str] = Depends(get_current_user_and_role),
):
    tenant_id = x_tenant_id or x_workspace_id or "default"
    return EvidenceService.list_evidence(
        db=db,
        tenant_id=tenant_id,
        source_type=source_type,
        integrity_status=integrity_status,
        classification=classification,
        preservation_status=preservation_status,
        case_id=case_id,
        investigation_id=investigation_id,
        search_query=query,
        page=page,
        page_size=page_size,
    )


@router.get(
    "/metrics/summary",
    response_model=EvidenceMetricsResponse,
    summary="Get evidence workspace metrics",
    description="Returns aggregate counts of evidence, integrity verification status, and classifications.",
)
def get_evidence_metrics(
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    x_tenant_id: Optional[str] = Header(None, alias="X-Tenant-ID"),
    db: Session = Depends(get_db),
    user_info: tuple[str, str] = Depends(get_current_user_and_role),
):
    tenant_id = x_tenant_id or x_workspace_id or "default"
    return EvidenceService.get_evidence_metrics(db=db, tenant_id=tenant_id)


# =============================================================================
# Registration & Ingestion
# =============================================================================

@router.post(
    "/upload",
    response_model=EvidenceDetailResponse,
    summary="Upload and register forensic evidence file",
    description="Accepts multipart file upload, calculates cryptographic hashes, and creates chain-of-custody entry.",
)
async def upload_evidence(
    file: UploadFile = File(...),
    source_type: EvidenceSourceTypeEnum = Form(EvidenceSourceTypeEnum.FILE),
    collection_method: EvidenceCollectionMethodEnum = Form(EvidenceCollectionMethodEnum.MANUAL_UPLOAD),
    source_reference: Optional[str] = Form(None),
    collector: Optional[str] = Form(None),
    classification: EvidenceClassificationEnum = Form(EvidenceClassificationEnum.INTERNAL),
    case_id: Optional[str] = Form(None),
    investigation_id: Optional[str] = Form(None),
    retention_policy: EvidenceRetentionPolicyEnum = Form(EvidenceRetentionPolicyEnum.INDEFINITE),
    notes: Optional[str] = Form(None),
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    x_tenant_id: Optional[str] = Header(None, alias="X-Tenant-ID"),
    db: Session = Depends(get_db),
    user_info: tuple[str, str] = Depends(get_current_user_and_role),
):
    current_user, role = user_info
    tenant_id = x_tenant_id or x_workspace_id or "default"

    raw_bytes = await UploadSecurityService.read_bounded_upload(file, max_bytes=50 * 1024 * 1024)
    if not raw_bytes:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Uploaded file cannot be empty.")

    req = EvidenceRegistrationRequest(
        original_filename=file.filename or "unnamed_artifact.bin",
        source_type=source_type,
        collection_method=collection_method,
        source_reference=source_reference,
        collector=collector or current_user,
        classification=classification,
        case_id=case_id,
        investigation_id=investigation_id,
        retention_policy=retention_policy,
        notes=notes,
    )

    return EvidenceService.register_evidence(
        db=db,
        raw_bytes=raw_bytes,
        filename=file.filename or "unnamed_artifact.bin",
        req=req,
        current_user=current_user,
        tenant_id=tenant_id,
    )


class EvidenceRegisterJsonRequest(EvidenceRegistrationRequest):
    content_base64: Optional[str] = None
    raw_content_utf8: Optional[str] = None


@router.post(
    "/register",
    response_model=EvidenceDetailResponse,
    summary="Register evidence via JSON",
    description="Registers evidence with either base64 encoded payload or direct raw text content.",
)
def register_evidence_json(
    body: EvidenceRegisterJsonRequest,
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    x_tenant_id: Optional[str] = Header(None, alias="X-Tenant-ID"),
    db: Session = Depends(get_db),
    user_info: tuple[str, str] = Depends(get_current_user_and_role),
):
    current_user, role = user_info
    tenant_id = x_tenant_id or x_workspace_id or "default"

    if body.content_base64:
        try:
            raw_bytes = base64.b64decode(body.content_base64)
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid base64 payload: {exc}")
    elif body.raw_content_utf8 is not None:
        raw_bytes = body.raw_content_utf8.encode("utf-8")
    else:
        raw_bytes = f"Evidence Artifact: {body.original_filename}".encode("utf-8")

    return EvidenceService.register_evidence(
        db=db,
        raw_bytes=raw_bytes,
        filename=body.original_filename,
        req=body,
        current_user=current_user,
        tenant_id=tenant_id,
    )


# =============================================================================
# Evidence Detail, Preview, Verification, Preservation
# =============================================================================

@router.get(
    "/{evidence_id}",
    response_model=EvidenceDetailResponse,
    summary="Get full evidence details",
    description="Retrieves metadata, hashes, integrity status, chain of custody ledger, and provenance lineage.",
)
def get_evidence_detail(
    evidence_id: str = Path(..., description="Evidence ID or UUID"),
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    x_tenant_id: Optional[str] = Header(None, alias="X-Tenant-ID"),
    db: Session = Depends(get_db),
    user_info: tuple[str, str] = Depends(get_current_user_and_role),
):
    tenant_id = x_tenant_id or x_workspace_id or "default"
    try:
        return EvidenceService.get_evidence_detail(db=db, identifier=evidence_id, tenant_id=tenant_id)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


@router.get(
    "/{evidence_id}/preview",
    response_model=EvidencePreviewResponse,
    summary="Get safe bounded preview of evidence contents",
    description="Returns secure UTF-8 text or hex dump preview without browser script execution risk.",
)
def get_evidence_preview(
    evidence_id: str = Path(..., description="Evidence ID or UUID"),
    max_bytes: int = Query(8192, ge=128, le=65536, description="Max bytes to preview"),
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    x_tenant_id: Optional[str] = Header(None, alias="X-Tenant-ID"),
    db: Session = Depends(get_db),
    user_info: tuple[str, str] = Depends(get_current_user_and_role),
):
    tenant_id = x_tenant_id or x_workspace_id or "default"
    try:
        return EvidenceService.get_preview(db=db, identifier=evidence_id, tenant_id=tenant_id, max_bytes=max_bytes)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


@router.post(
    "/{evidence_id}/verify",
    response_model=EvidenceIntegrityVerificationResponse,
    summary="Reverify cryptographic hash integrity",
    description="Recomputes cryptographic digests of physical stored bytes on demand and audits results.",
)
def verify_evidence_integrity(
    evidence_id: str = Path(..., description="Evidence ID or UUID"),
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    x_tenant_id: Optional[str] = Header(None, alias="X-Tenant-ID"),
    db: Session = Depends(get_db),
    user_info: tuple[str, str] = Depends(get_current_user_and_role),
):
    current_user, role = user_info
    tenant_id = x_tenant_id or x_workspace_id or "default"
    try:
        return EvidenceService.verify_integrity(
            db=db,
            identifier=evidence_id,
            current_user=current_user,
            tenant_id=tenant_id,
        )
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


@router.post(
    "/{evidence_id}/preserve",
    response_model=EvidenceDetailResponse,
    summary="Set preservation / legal hold status",
    description="Updates legal hold or preservation status with mandatory justification and audit logging.",
)
def set_evidence_preservation(
    body: EvidencePreservationRequest,
    evidence_id: str = Path(..., description="Evidence ID or UUID"),
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    x_tenant_id: Optional[str] = Header(None, alias="X-Tenant-ID"),
    db: Session = Depends(get_db),
    user_info: tuple[str, str] = Depends(get_current_user_and_role),
):
    current_user, role = user_info
    tenant_id = x_tenant_id or x_workspace_id or "default"
    try:
        return EvidenceService.set_preservation(
            db=db,
            identifier=evidence_id,
            req=body,
            current_user=current_user,
            tenant_id=tenant_id,
        )
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


@router.post(
    "/{evidence_id}/custody",
    response_model=EvidenceCustodyEventResponse,
    summary="Append Chain-of-Custody record",
    description="Appends an immutable entry to the evidence chain-of-custody ledger.",
)
def add_custody_event(
    body: EvidenceCustodyAddRequest,
    evidence_id: str = Path(..., description="Evidence ID or UUID"),
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    x_tenant_id: Optional[str] = Header(None, alias="X-Tenant-ID"),
    db: Session = Depends(get_db),
    user_info: tuple[str, str] = Depends(get_current_user_and_role),
):
    current_user, role = user_info
    tenant_id = x_tenant_id or x_workspace_id or "default"
    try:
        return EvidenceService.add_custody_event(
            db=db,
            identifier=evidence_id,
            req=body,
            current_user=current_user,
            tenant_id=tenant_id,
        )
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


class EvidenceLinkPayload(BaseModel):
    case_id: Optional[str] = None
    investigation_id: Optional[str] = None
    reason: Optional[str] = None


@router.post(
    "/{evidence_id}/link",
    response_model=EvidenceDetailResponse,
    summary="Link evidence to Case or Investigation",
    description="Associates evidence record with a Case or Investigation and appends a TRANSFERRED custody record.",
)
def link_evidence(
    body: EvidenceLinkPayload,
    evidence_id: str = Path(..., description="Evidence ID or UUID"),
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    x_tenant_id: Optional[str] = Header(None, alias="X-Tenant-ID"),
    db: Session = Depends(get_db),
    user_info: tuple[str, str] = Depends(get_current_user_and_role),
):
    current_user, role = user_info
    tenant_id = x_tenant_id or x_workspace_id or "default"
    try:
        return EvidenceService.link_evidence(
            db=db,
            identifier=evidence_id,
            case_id=body.case_id,
            investigation_id=body.investigation_id,
            reason=body.reason,
            current_user=current_user,
            tenant_id=tenant_id,
        )
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


@router.post(
    "/{evidence_id}/notes",
    response_model=EvidenceDetailResponse,
    summary="Add forensic analyst note",
    description="Adds an analyst observation note with timestamp and category.",
)
def add_forensic_note(
    body: EvidenceNoteAddRequest,
    evidence_id: str = Path(..., description="Evidence ID or UUID"),
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    x_tenant_id: Optional[str] = Header(None, alias="X-Tenant-ID"),
    db: Session = Depends(get_db),
    user_info: tuple[str, str] = Depends(get_current_user_and_role),
):
    current_user, role = user_info
    tenant_id = x_tenant_id or x_workspace_id or "default"
    try:
        return EvidenceService.add_forensic_note(
            db=db,
            identifier=evidence_id,
            req=body,
            current_user=current_user,
            tenant_id=tenant_id,
        )
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


@router.post(
    "/{evidence_id}/derive",
    response_model=EvidenceDetailResponse,
    summary="Create child derivative evidence",
    description="Derives a child evidence item (unpacked, carved, decoded) maintaining strict parent lineage and tool metadata.",
)
def derive_evidence(
    body: EvidenceDerivationRequest,
    evidence_id: str = Path(..., description="Parent Evidence ID or UUID"),
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    x_tenant_id: Optional[str] = Header(None, alias="X-Tenant-ID"),
    db: Session = Depends(get_db),
    user_info: tuple[str, str] = Depends(get_current_user_and_role),
):
    current_user, role = user_info
    tenant_id = x_tenant_id or x_workspace_id or "default"
    try:
        return EvidenceService.derive_evidence(
            db=db,
            parent_identifier=evidence_id,
            req=body,
            current_user=current_user,
            tenant_id=tenant_id,
        )
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


@router.get(
    "/{evidence_id}/export-manifest",
    response_model=EvidenceExportManifestResponse,
    summary="Generate forensic export manifest package",
    description="Constructs signed legal/compliance manifest containing complete hashes and custody audit history.",
)
def export_evidence_manifest(
    evidence_id: str = Path(..., description="Evidence ID or UUID"),
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    x_tenant_id: Optional[str] = Header(None, alias="X-Tenant-ID"),
    db: Session = Depends(get_db),
    user_info: tuple[str, str] = Depends(get_current_user_and_role),
):
    current_user, role = user_info
    tenant_id = x_tenant_id or x_workspace_id or "default"
    try:
        return EvidenceService.export_evidence_manifest(
            db=db,
            identifier=evidence_id,
            current_user=current_user,
            tenant_id=tenant_id,
        )
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


@router.get(
    "/{evidence_id}/download",
    summary="Download original raw evidence stream",
    description="Streams physical artifact bytes with strict security headers preventing browser execution.",
)
def download_evidence(
    evidence_id: str = Path(..., description="Evidence ID or UUID"),
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    x_tenant_id: Optional[str] = Header(None, alias="X-Tenant-ID"),
    db: Session = Depends(get_db),
    user_info: tuple[str, str] = Depends(get_current_user_and_role),
):
    tenant_id = x_tenant_id or x_workspace_id or "default"
    try:
        detail = EvidenceService.get_evidence_detail(db=db, identifier=evidence_id, tenant_id=tenant_id)
        storage_key = detail.storage_reference or detail.sha256
        raw_bytes = evidence_storage.retrieve_bytes(storage_key)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Evidence artifact bytes unavailable: {exc}")

    # Log access custody event
    current_user, _ = user_info
    EvidenceService.add_custody_event(
        db=db,
        identifier=detail.id,
        req=EvidenceCustodyAddRequest(
            event_type=CustodyEventTypeEnum.ACCESSED,
            source="STORAGE_BACKEND",
            destination="USER_DOWNLOAD",
            reason="Analyst downloaded raw artifact bytes.",
        ),
        current_user=current_user,
        tenant_id=tenant_id,
    )

    raw_filename = detail.original_filename or f"evidence_{detail.evidence_id}.bin"
    from backend.services.upload_security import UploadSecurityService
    safe_filename = UploadSecurityService.sanitize_filename(raw_filename).replace('"', '').replace('\r', '').replace('\n', '')
    return StreamingResponse(
        io.BytesIO(raw_bytes),
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{safe_filename}"',
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'none'",
        },
    )
