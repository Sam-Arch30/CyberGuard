"""
Geolocation and IP Intelligence API Routes.
Provides sanitized server-side geolocation lookups and safe provider status endpoints.
Strictly safeguards API credentials, ensuring no keys, tokens, or auth headers are ever exposed.
"""
import logging
from fastapi import APIRouter, HTTPException, status
from backend.schemas.ip_intelligence import GeolocationResponse, GeolocationStatusResponse
from backend.services.geolocation_service import global_geolocation_service

logger = logging.getLogger("intelligence_routes")
router = APIRouter(prefix="/api/intelligence", tags=["IP & Geolocation Intelligence"])


@router.get("/geolocation/status", response_model=GeolocationStatusResponse, summary="Check safe geolocation configuration status")
async def get_geolocation_status() -> GeolocationStatusResponse:
    """
    Returns high-level status of the Geolocation Provider (Configured / Not Configured).
    STRICT SECURITY GUARANTEE: Never exposes API credentials, tokens, or partial characters.
    """
    try:
        return global_geolocation_service.get_status()
    except Exception as exc:
        logger.error(f"Error checking geolocation status: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error retrieving geolocation provider status"
        )


@router.get("/ip/{ip:path}/geolocation", response_model=GeolocationResponse, summary="Lookup sanitized IP geolocation telemetry")
async def get_ip_geolocation(ip: str) -> GeolocationResponse:
    """
    Resolves normalized geolocation intelligence for an IP address.
    Features:
    - Server-side credential isolation (secret keys never touch the client)
    - Private / Loopback / Reserved address protection via SSRF defense
    - TTL caching to preserve provider quota and minimize latency
    - Forensically accurate infrastructure classification
    """
    if not ip or not ip.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="IP address parameter cannot be empty."
        )

    try:
        result = await global_geolocation_service.get_geolocation(ip.strip())
        return result
    except Exception as exc:
        logger.error(f"Unexpected error resolving geolocation for IP: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal error resolving IP geolocation"
        )
