"""
File Security & Attachment Static Analyzer API Routes (Section 8).
Provides endpoints for safe, zero-execution static file analysis,
durable artifact re-analysis, and capability inspection.
"""
from backend.services.upload_security import UploadSecurityService
import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.services.file_security_pipeline import FileSecurityPipeline
from backend.schemas.file_security import (
    FileSecurityAnalysisResponse,
    FileSecurityConfigResponse,
)

logger = logging.getLogger("cyberguard.files_api")
router = APIRouter(prefix="/api/files", tags=["Attachment & File Security"])

pipeline = FileSecurityPipeline()


@router.post("/analyze", response_model=FileSecurityAnalysisResponse, summary="Analyze an uploaded file via safe static analysis")
async def analyze_file(
    file: UploadFile = File(..., description="File or attachment binary payload to analyze"),
    uploader: str = Form("ANALYST", description="Identity or system submitting the file"),
    db: Session = Depends(get_db),
) -> FileSecurityAnalysisResponse:
    """
    Executes comprehensive safe static file analysis:
    1. Cryptographic hashing (SHA-256 primary, SHA-1, MD5)
    2. Deep MIME & magic byte verification (claimed vs detected mismatch)
    3. Filename security (double extension evasion, Right-to-Left Override Unicode deception)
    4. Format-specific static inspection (PDF JavaScript/OpenAction, Office VBA macros, PE headers/entropy, Scripts)
    5. Safe archive extraction (Zip-Slip traversal defense, Zip-Bomb limits)
    6. Observable IOC extraction (URLs, domains, IPs, hashes)
    7. External threat intelligence reputation lookup (Privacy-preserving, NO MATCH != SAFE)
    8. Canonical persistence across Artifacts, AnalysisRuns, Findings, Evidence, Indicators, and Relationships
    """
    try:
        payload = await UploadSecurityService.read_bounded_upload(file, max_bytes=50 * 1024 * 1024)
        filename = file.filename or "uploaded_file.bin"
        reported_mime = file.content_type

        return await pipeline.analyze_file(
            payload_bytes=payload,
            filename=filename,
            reported_mime=reported_mime,
            uploader=uploader,
            db=db,
        )
    except ValueError as ve:
        logger.warning(f"File analysis validation error: {ve}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"Error during file analysis: {exc}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail='File analysis error.',
        )


@router.post("/analyze-artifact/{artifact_id}", response_model=FileSecurityAnalysisResponse, summary="Re-analyze a durable stored file artifact")
async def analyze_artifact(
    artifact_id: str,
    uploader: str = Form("ANALYST", description="Identity requesting re-analysis"),
    db: Session = Depends(get_db),
) -> FileSecurityAnalysisResponse:
    """
    Re-analyzes an existing durable artifact loaded directly from storage.
    Always generates a new independent AnalysisRunModel record preserving historical observation lineage.
    """
    try:
        return await pipeline.reanalyze_artifact(
            artifact_id=artifact_id,
            db=db,
            uploader=uploader,
        )
    except ValueError as ve:
        logger.warning(f"Artifact re-analysis validation error: {ve}")
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(ve))
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"Error during artifact re-analysis: {exc}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail='Artifact re-analysis error.',
        )


@router.get("/config", response_model=FileSecurityConfigResponse, summary="Get file analyzer configuration and capability matrix")
async def get_file_config() -> FileSecurityConfigResponse:
    """
    Returns static analyzer limits, threat intelligence configuration, and format capability matrix.
    """
    return FileSecurityConfigResponse(
        max_file_size_bytes=pipeline.MAX_FILE_SIZE,
        max_archive_uncompressed_bytes=pipeline.archive_analyzer.MAX_UNCOMPRESSED_TOTAL,
        max_archive_entries=pipeline.archive_analyzer.MAX_ENTRIES,
        max_archive_depth=pipeline.archive_analyzer.MAX_ARCHIVE_DEPTH,
        max_compression_ratio=pipeline.archive_analyzer.MAX_COMPRESSION_RATIO,
        max_extracted_strings=pipeline.ioc_analyzer.MAX_EXTRACTED_CHARS,
        threat_intel_provider="cyberguard_threat_intel",
        reputation_cache_ttl_seconds=pipeline.threat_intel.cache.default_ttl,
        supported_formats={
            "PDF": {"identity": True, "metadata": True, "static_analysis": True, "ioc_extraction": True},
            "DOCX": {"identity": True, "metadata": True, "static_analysis": True, "ioc_extraction": True},
            "DOCM": {"identity": True, "metadata": True, "static_analysis": True, "ioc_extraction": True},
            "XLSX": {"identity": True, "metadata": True, "static_analysis": True, "ioc_extraction": True},
            "XLSM": {"identity": True, "metadata": True, "static_analysis": True, "ioc_extraction": True},
            "PPTX": {"identity": True, "metadata": True, "static_analysis": True, "ioc_extraction": True},
            "ZIP": {"identity": True, "metadata": True, "static_analysis": True, "ioc_extraction": True},
            "TAR": {"identity": True, "metadata": True, "static_analysis": True, "ioc_extraction": True},
            "GZ": {"identity": True, "metadata": True, "static_analysis": True, "ioc_extraction": True},
            "PE/EXE": {"identity": True, "metadata": True, "static_analysis": True, "ioc_extraction": True},
            "Script": {"identity": True, "metadata": True, "static_analysis": True, "ioc_extraction": True},
            "Image": {"identity": True, "metadata": True, "static_analysis": True, "ioc_extraction": False},
            "Audio": {"identity": True, "metadata": False, "static_analysis": False, "ioc_extraction": False},
            "Video": {"identity": True, "metadata": False, "static_analysis": False, "ioc_extraction": False},
            "Unknown": {"identity": True, "metadata": True, "static_analysis": False, "ioc_extraction": True},
        },
    )
