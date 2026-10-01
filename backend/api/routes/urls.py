"""
URL, Domain & Website Intelligence API Routes (Section 7).
Provides endpoints to analyze directly submitted URLs, domains, and durable artifacts.
All outbound network inspection strictly adheres to centralized SSRF defense gates.
"""
import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.services.safe_http_client import SafeHttpClient
from backend.services.url_domain_pipeline import URLDomainIntelligencePipeline

logger = logging.getLogger("cyberguard.urls_api")
router = APIRouter(prefix="/api/urls", tags=["URL & Domain Intelligence"])

pipeline = URLDomainIntelligencePipeline()


class URLAnalyzeRequest(BaseModel):
    url: str = Field(..., description="The URL to investigate", min_length=1)
    active_analysis_enabled: bool = Field(True, description="Whether to execute controlled active HTTP website inspection")
    uploader: str = Field("ANALYST", description="Identity or system submitting the URL")


class DomainAnalyzeRequest(BaseModel):
    domain: str = Field(..., description="The domain or hostname to investigate", min_length=1)
    uploader: str = Field("ANALYST", description="Identity or system submitting the domain")


class URLConfigResponse(BaseModel):
    active_analysis_enabled: bool
    allowed_schemes: List[str]
    ssrf_protection_active: bool
    blocked_target_categories: List[str]
    max_redirects: int
    max_response_size_bytes: int
    connect_timeout_seconds: float
    total_timeout_seconds: float


@router.post("/analyze", summary="Analyze a URL with passive structural and SSRF-defended website intelligence")
async def analyze_url(
    req: URLAnalyzeRequest,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """
    Executes end-to-end investigation of a URL:
    1. Passive URL structural analysis (scheme, hostname, port, path, query, userinfo, IP host, punycode, subdomains)
    2. Registrable domain and lookalike detection
    3. DNS resolution (A, AAAA, MX, NS, TXT) and relationship generation
    4. Domain registration / RDAP age and privacy redaction handling
    5. Controlled active HTTP inspection with SSRF gate (if enabled)
    6. Static HTML parsing for password fields, login forms, and cross-domain data submission
    7. Canonical persistence across Artifacts, AnalysisRuns, Findings, Evidence, Indicators, and Relationships
    """
    try:
        result = await pipeline.analyze_url(
            url=req.url,
            db=db,
            active_analysis_enabled=req.active_analysis_enabled,
            uploader=req.uploader,
        )
        return result
    except Exception as exc:
        logger.error(f"Error analyzing URL '{req.url}': {exc}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error analyzing URL: {str(exc)}",
        )


@router.post("/analyze-domain", summary="Analyze a domain with DNS and registration intelligence")
async def analyze_domain(
    req: DomainAnalyzeRequest,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """
    Executes domain intelligence:
    1. Registrable domain extraction via Public Suffix List
    2. Lookalike domain detection against protected targets
    3. DNS resolution and relationship mapping (RESOLVES_TO, USES_NAMESERVER, MAIL_EXCHANGER)
    4. RDAP / WHOIS registration age and redaction handling
    5. External threat intelligence query
    6. Canonical persistence
    """
    try:
        result = await pipeline.analyze_domain(
            domain=req.domain,
            db=db,
            uploader=req.uploader,
        )
        return result
    except Exception as exc:
        logger.error(f"Error analyzing domain '{req.domain}': {exc}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error analyzing domain: {str(exc)}",
        )


@router.post("/analyze-artifact/{artifact_id}", summary="Re-analyze an existing URL or Domain artifact from storage")
async def analyze_artifact(
    artifact_id: str,
    active_analysis_enabled: bool = True,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """
    Re-analyzes an existing durable artifact loaded directly from content-addressed storage.
    Creates a new independent AnalysisRunModel record preserving observation history.
    """
    try:
        result = await pipeline.analyze_artifact(
            artifact_id=artifact_id,
            db=db,
            active_analysis_enabled=active_analysis_enabled,
        )
        return result
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except Exception as exc:
        logger.error(f"Error re-analyzing artifact '{artifact_id}': {exc}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error analyzing artifact: {str(exc)}",
        )


@router.get("/config", response_model=URLConfigResponse, summary="Get URL analysis and network security configuration")
async def get_url_config() -> URLConfigResponse:
    """Returns network safety gate settings and active inspection parameters."""
    return URLConfigResponse(
        active_analysis_enabled=True,
        allowed_schemes=list(SafeHttpClient.ALLOWED_SCHEMES),
        ssrf_protection_active=True,
        blocked_target_categories=[
            "loopback (127.0.0.0/8, ::1)",
            "private_rfc1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7)",
            "link_local (169.254.0.0/16, fe80::/10)",
            "cloud_metadata (169.254.169.254, fd00:ec2::254, metadata.google.internal)",
            "multicast (224.0.0.0/4, ff00::/8)",
            "reserved & unspecified (0.0.0.0/8, ::)",
            "carrier_grade_nat (100.64.0.0/10)",
        ],
        max_redirects=SafeHttpClient.DEFAULT_MAX_REDIRECTS,
        max_response_size_bytes=SafeHttpClient.DEFAULT_MAX_SIZE_BYTES,
        connect_timeout_seconds=SafeHttpClient.DEFAULT_CONNECT_TIMEOUT,
        total_timeout_seconds=SafeHttpClient.DEFAULT_TOTAL_TIMEOUT,
    )
