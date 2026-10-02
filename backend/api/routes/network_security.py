"""
Network and Traffic Anomaly Security API Endpoints.
Provides routes for network telemetry ingestion, NetFlow/DNS batch analysis,
log uploads, artifact re-analysis, and engine configuration.
"""
from __future__ import annotations

import csv
import json
import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File, status
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.db.models import ArtifactModel, EntityModel
from backend.schemas.unified import EntityTypeEnum
from backend.schemas.network_security import (
    NetworkConfigResponse,
    NetworkSecurityAnalysisResponse,
    DeviceNetworkProfile,
)
from backend.services.network_pipeline import global_network_pipeline

logger = logging.getLogger("cyberguard.api.network_security")

router = APIRouter(prefix="/api/network-security", tags=["Network Security"])


@router.get("/config", response_model=NetworkConfigResponse)
def get_network_security_config() -> NetworkConfigResponse:
    """
    Returns active configuration parameters, detection thresholds, and internal network CIDRs.
    """
    return global_network_pipeline.config


@router.post("/analyze-event", response_model=NetworkSecurityAnalysisResponse)
async def analyze_single_network_event(
    event_payload: Dict[str, Any],
    provider_hint: Optional[str] = Query(None, description="Optional adapter hint (generic_json, dns_log, netflow_json)"),
    db: Session = Depends(get_db),
) -> NetworkSecurityAnalysisResponse:
    """
    Analyze a single network connection, flow, or DNS query event.
    """
    try:
        response = await global_network_pipeline.analyze_events(
            raw_events=[event_payload],
            db=db,
            provider_hint=provider_hint,
        )
        return response
    except Exception as e:
        logger.error(f"Error analyzing single network event: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Network analysis failed: {str(e)}",
        )


@router.post("/analyze-batch", response_model=NetworkSecurityAnalysisResponse)
async def analyze_batch_network_events(
    events: List[Dict[str, Any]],
    provider_hint: Optional[str] = Query(None, description="Optional adapter hint"),
    db: Session = Depends(get_db),
) -> NetworkSecurityAnalysisResponse:
    """
    Analyze a batch of network flow or DNS query records.
    """
    try:
        response = await global_network_pipeline.analyze_events(
            raw_events=events,
            db=db,
            provider_hint=provider_hint,
        )
        return response
    except Exception as e:
        logger.error(f"Error analyzing batch network events: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Batch network analysis failed: {str(e)}",
        )


@router.post("/upload-log", response_model=NetworkSecurityAnalysisResponse)
async def upload_network_log_file(
    file: UploadFile = File(...),
    provider_hint: Optional[str] = Query(None, description="Optional adapter hint (generic_json, generic_csv, dns_log, netflow_json)"),
    db: Session = Depends(get_db),
) -> NetworkSecurityAnalysisResponse:
    """
    Upload and analyze network telemetry logs (JSON array, JSON lines, or CSV).
    """
    try:
        content_bytes = await file.read()
        text_content = content_bytes.decode("utf-8", errors="replace")

        # Try parsing JSON
        raw_events: List[Any] = []
        try:
            parsed = json.loads(text_content)
            if isinstance(parsed, list):
                raw_events = parsed
            elif isinstance(parsed, dict) and "events" in parsed and isinstance(parsed["events"], list):
                raw_events = parsed["events"]
            else:
                raw_events = [parsed]
        except Exception:
            # Fallback: CSV or lines
            lines = text_content.splitlines()
            if lines and "," in lines[0]:
                reader = csv.DictReader(lines)
                raw_events = list(reader)
            else:
                raw_events = [line.strip() for line in lines if line.strip()]

        response = await global_network_pipeline.analyze_events(
            raw_events=raw_events,
            db=db,
            provider_hint=provider_hint,
        )
        return response
    except Exception as e:
        logger.error(f"Error analyzing uploaded network log: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Network log file analysis failed: {str(e)}",
        )


@router.post("/analyze-artifact/{artifact_id}", response_model=NetworkSecurityAnalysisResponse)
async def analyze_stored_network_artifact(
    artifact_id: str,
    db: Session = Depends(get_db),
) -> NetworkSecurityAnalysisResponse:
    """
    Re-analyze a stored NETWORK_LOG artifact directly from evidence storage.
    Creates a new independent AnalysisRunModel with full historical provenance.
    """
    try:
        return await global_network_pipeline.analyze_artifact(artifact_id=artifact_id, db=db)
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(ve))
    except Exception as e:
        logger.error(f"Error re-analyzing network artifact {artifact_id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Network artifact re-analysis failed: {str(e)}",
        )


@router.get("/devices/{device_id}/profile", response_model=DeviceNetworkProfile)
def get_device_network_profile(
    device_id: str,
    db: Session = Depends(get_db),
) -> DeviceNetworkProfile:
    """
    Returns baseline observed network telemetry for a host/device.
    """
    clean_id = device_id.strip()
    entity = db.query(EntityModel).filter(
        EntityModel.entity_type == EntityTypeEnum.DEVICE.value,
        EntityModel.name == clean_id,
    ).first()

    if not entity:
        return DeviceNetworkProfile(
            device_id=clean_id,
            total_connections_observed=0,
            known_destinations=[],
            known_ports=[],
            known_domains=[],
        )

    attrs = json.loads(entity.attributes_json or "{}")
    return DeviceNetworkProfile(
        device_id=clean_id,
        total_connections_observed=attrs.get("connections_count", 0),
        first_seen=entity.first_seen,
        last_seen=entity.last_seen,
        known_destinations=attrs.get("known_destinations", []),
        known_ports=attrs.get("known_ports", []),
        known_domains=attrs.get("known_domains", []),
        total_bytes_sent=attrs.get("bytes_sent", 0),
        total_bytes_received=attrs.get("bytes_received", 0),
    )
