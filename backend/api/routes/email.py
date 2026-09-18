import asyncio
import json
import re
from typing import Optional
from fastapi import APIRouter, File, UploadFile, HTTPException, Header, Depends, status, Response
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.schemas.email import EmailAnalysisResponse, ErrorResponse, MLAssessmentResult, MLClassifyRequest
from backend.schemas.evidence import InvestigationTimelineResponse
from backend.schemas.ai_analyst import AIAnalystAssessment
from backend.schemas.graph import InvestigationGraphResponse, GraphFilterRequest
from backend.schemas.ip_intelligence import IPIntelligence
from backend.schemas.domain_intelligence import DomainIntelligence
from backend.schemas.lookalike import LookalikeDetectionResult
from backend.schemas.url_analysis import URLAnalysisResult, URLAnalysisRequest
from backend.schemas.threat_score import ThreatScoreResult
from backend.services.email_parser import EmailParserService, EmailParseException
from backend.services.ip_intelligence_service import global_ip_service
from backend.services.domain_intelligence_service import DomainIntelligenceService
from backend.services.lookalike_detector import LookalikeDetectorService
from backend.services.url_analyzer import URLAnalyzerService
from backend.services.threat_scorer import ThreatScorerService
from backend.services.ai_analyst_service import global_ai_analyst_service
from backend.services.graph_service import global_graph_service
from backend.services.ioc_extractor import IOCExtractorService
from backend.services.audit_service import AuditService
from backend.services.upload_security import UploadSecurityService
from backend.services.html_sanitizer import HTMLSanitizerService
from backend.services.attribution_engine import global_attribution_engine
from backend.services.evidence_confidence_engine import EvidenceConfidenceEngine
from backend.app.ml.classifier import global_phishing_classifier

global_lookalike_detector = LookalikeDetectorService()
global_domain_service = DomainIntelligenceService(lookalike_detector=global_lookalike_detector)
global_url_analyzer = URLAnalyzerService(lookalike_detector=global_lookalike_detector)
global_threat_scorer = ThreatScorerService()
global_confidence_engine = EvidenceConfidenceEngine()

router = APIRouter(prefix="/api/emails", tags=["Email Analysis"])


@router.get(
    "/lookup/{ip:path}",
    response_model=IPIntelligence,
    summary="Look up contextual IP intelligence for a given IP address",
    description="Returns geolocation, ASN, ISP, organization, and hosting/proxy indicators for a public IP, or private scope metadata."
)
async def lookup_ip_intelligence(ip: str):
    """
    Look up IP intelligence for a single IP address.
    """
    clean_ip = ip.strip()
    return await global_ip_service.get_ip_intelligence(clean_ip)


@router.get(
    "/lookup-domain/{domain:path}",
    response_model=DomainIntelligence,
    summary="Look up contextual DNS and registration intelligence for a domain",
    description="Returns A, AAAA, MX, NS, TXT DNS records, RDAP registration metadata, domain age, and new domain flags."
)
async def lookup_domain_intelligence(domain: str):
    """
    Look up domain intelligence for a single domain name.
    """
    clean_domain = domain.strip().lower().rstrip(".")
    return await global_domain_service.lookup_domain(clean_domain)


@router.get(
    "/detect-lookalike/{domain:path}",
    response_model=Optional[LookalikeDetectionResult],
    summary="Detect suspicious lookalike domain and brand impersonation",
    description="Evaluates domain against known brands using Levenshtein distance, character substitutions, affixes, and subdomain abuse."
)
async def detect_lookalike_domain(domain: str):
    """
    Detects potential brand impersonation and lookalike techniques for a given domain name.
    """
    clean_domain = domain.strip().lower().rstrip(".")
    return global_lookalike_detector.detect_lookalike(clean_domain)


@router.post(
    "/analyze-url",
    response_model=URLAnalysisResult,
    summary="Statically analyze a single URL for forensic features and suspicion indicators",
    description="Extracts URL features, identifies brand lookalikes, detects link mismatches, and computes a static suspicion score without visiting the URL."
)
async def analyze_url_endpoint(request: URLAnalysisRequest):
    """
    Statically analyzes a single URL without fetching or visiting the remote host.
    """
    return global_url_analyzer.analyze_url(
        request.url,
        visible_text=request.visible_text
    )


@router.post(
    "/calculate-threat-score",
    response_model=ThreatScoreResult,
    summary="Calculate global deterministic threat score from email analysis",
    description="Combines authentication, lookalikes, URLs, domain age, intent keywords, attachments, and bounded ML assessment into an explainable threat score."
)
async def calculate_threat_score_endpoint(analysis: EmailAnalysisResponse):
    """
    Calculates global threat score for a given EmailAnalysisResponse object.
    """
    return global_threat_scorer.calculate_score(analysis)


@router.post(
    "/ml-classify",
    response_model=MLAssessmentResult,
    summary="Classify email subject and body text using NLP ML model",
    description="Applies text normalization, TF-IDF vectorization, and Logistic Regression to evaluate phishing probability."
)
async def classify_email_text(request: MLClassifyRequest):
    """
    Direct prediction endpoint for NLP-based phishing classification on subject and body text.
    """
    res = global_phishing_classifier.predict(subject=request.subject, body=request.body)
    return res


@router.post(
    "/ai-analyst",
    response_model=AIAnalystAssessment,
    summary="Generate AI Analyst structured assessment from forensic evidence",
    description="Synthesizes structured forensic findings (authentication, URLs, lookalikes, IP intel, threat score, ML probability) into concise executive findings, attack classification, and prescriptive guidance."
)
async def generate_ai_analyst_assessment(analysis: EmailAnalysisResponse):
    """
    Direct endpoint to generate AI Analyst assessment for a supplied EmailAnalysisResponse.
    """
    return await global_ai_analyst_service.analyze(analysis)


@router.post(
    "/investigation-graph",
    response_model=InvestigationGraphResponse,
    summary="Generate investigation relationship graph from email forensic telemetry",
    description="Constructs a directed forensic relationship graph connecting Email, Email Address, Domain, URL, IP, ASN, and Attachment entities with deduplication."
)
async def generate_investigation_graph(analysis: EmailAnalysisResponse):
    """
    Direct endpoint to generate relationship graph for a supplied EmailAnalysisResponse.
    """
    return global_graph_service.build_graph(analysis)


@router.post(
    "/investigation-graph/filter",
    response_model=InvestigationGraphResponse,
    summary="Filter investigation relationship graph by node types",
    description="Filters an existing graph by node types and prunes dangling edges."
)
async def filter_investigation_graph(request: GraphFilterRequest):
    """
    Filters graph nodes and cascading edges.
    """
    return global_graph_service.filter_graph(request.graph, allowed_types=request.node_types)


@router.post(
    "/analyze",
    response_model=EmailAnalysisResponse,
    responses={
        400: {"model": ErrorResponse, "description": "Malformed or invalid email file"},
        422: {"model": ErrorResponse, "description": "Unprocessable email entity"}
    },
    summary="Upload and analyze an .eml email file",
    description="Parses an uploaded .eml file and returns structured headers, plain-text body, HTML body, extracted URLs, attachment metadata, authentication, relay path, and IP intelligence."
)
async def analyze_email(
    file: UploadFile = File(...),
    user: Optional[str] = Header(None, alias="X-User"),
    db: Session = Depends(get_db)
):
    """
    Accepts an .eml file upload and parses headers, body, URLs, attachments, authentication, relay hops, and IP intelligence into structured JSON.
    """
    raw_filename = file.filename or "unknown.eml"
    safe_filename = UploadSecurityService.sanitize_filename(raw_filename)
    uploader_identity = (user or "SOC Analyst").strip()

    try:
        content_bytes = await file.read()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to read uploaded file stream: {str(e)}"
        )

    # Section 20: Validate upload security (file size limit <= 10MB, no executables, RFC-822 structure)
    UploadSecurityService.validate_email_upload(
        filename=safe_filename,
        content_type=file.content_type,
        content_bytes=content_bytes
    )

    # Section 18: Cryptographic evidence hash & persistence
    raw_sha256 = IOCExtractorService.calculate_sha256(content_bytes)
    evidence_record = AuditService.record_evidence(
        db=db,
        sha256=raw_sha256,
        original_filename=safe_filename,
        size=len(content_bytes),
        uploader=uploader_identity
    )

    # Persist authentic raw .eml bytes to disk storage
    try:
        from backend.services.eml_storage_service import EMLStorageService
        EMLStorageService.save_eml(
            evidence_id=evidence_record.evidence_id,
            sha256=raw_sha256,
            original_filename=safe_filename,
            content_bytes=content_bytes
        )
    except Exception:
        pass

    # Log EMAIL_UPLOADED audit event
    AuditService.log_audit(
        db=db,
        action="EMAIL_UPLOADED",
        resource_type="email",
        resource_id=evidence_record.evidence_id,
        user=uploader_identity,
        metadata={
            "evidence_id": evidence_record.evidence_id,
            "sha256": raw_sha256,
            "filename": safe_filename,
            "size": len(content_bytes)
        },
        details=f"Email file '{safe_filename}' ({len(content_bytes)} bytes) uploaded. SHA-256 recorded: {raw_sha256[:16]}..."
    )

    # Log ANALYSIS_STARTED audit event
    AuditService.log_audit(
        db=db,
        action="ANALYSIS_STARTED",
        resource_type="email",
        resource_id=evidence_record.evidence_id,
        user=uploader_identity,
        metadata={
            "evidence_id": evidence_record.evidence_id,
            "sha256": raw_sha256,
            "filename": safe_filename
        },
        details=f"Forensic analysis and threat evaluation started for evidence {evidence_record.evidence_id}."
    )

    try:
        analysis_result = EmailParserService.parse_eml_bytes(content_bytes, filename=safe_filename)

        # Section 20: Sanitize HTML body to block active scripts, iframes, objects, forms, and remote image beacons
        if analysis_result.html_body:
            analysis_result.html_body = HTMLSanitizerService.sanitize_html(analysis_result.html_body)

        # Enrich IP intelligence asynchronously
        ip_list = list(set(analysis_result.ips))
        if analysis_result.relay_analysis and analysis_result.relay_analysis.earliest_observable_node and analysis_result.relay_analysis.earliest_observable_node.earliest_observable_ip:
            ip_list.append(analysis_result.relay_analysis.earliest_observable_node.earliest_observable_ip)

        # Enrich Domain intelligence asynchronously
        domain_list = list(set(analysis_result.domains))
        if analysis_result.authentication and analysis_result.authentication.alignment:
            align = analysis_result.authentication.alignment
            if align.from_domain:
                domain_list.append(align.from_domain)
            if align.reply_to_domain:
                domain_list.append(align.reply_to_domain)
            if align.return_path_domain:
                domain_list.append(align.return_path_domain)

        # Run IP and Domain enrichment concurrently
        ip_intel_dict, domain_intel_dict = await asyncio.gather(
            global_ip_service.get_batch_ip_intelligence(ip_list),
            global_domain_service.enrich_domains_batch(domain_list)
        )
        analysis_result.ip_intelligence = ip_intel_dict
        analysis_result.domain_intelligence = domain_intel_dict
        analysis_result.lookalike_domains = global_lookalike_detector.detect_lookalikes_batch(domain_list)

        # Section 11: NLP-Based Phishing Classification
        try:
            body_text = analysis_result.plain_text_body
            if not body_text and analysis_result.html_body:
                import re
                body_text = re.sub(r'<[^>]+>', ' ', analysis_result.html_body)

            ml_pred = global_phishing_classifier.predict(
                subject=analysis_result.subject,
                body=body_text
            )
            analysis_result.ml_assessment = MLAssessmentResult(**ml_pred)
            analysis_result.ml_phishing_probability = ml_pred.get("probability") if ml_pred.get("available") else None
        except Exception:
            analysis_result.ml_assessment = None
            analysis_result.ml_phishing_probability = None

        analysis_result.threat_score = global_threat_scorer.calculate_score(analysis_result)

        # Section 12: AI Analyst Assistant
        try:
            analysis_result.ai_analyst = await global_ai_analyst_service.analyze(analysis_result)
        except Exception:
            analysis_result.ai_analyst = None

        # Attach Section 18 Evidence Integrity Metadata
        analysis_result.id = evidence_record.evidence_id
        analysis_result.evidence_id = evidence_record.evidence_id
        analysis_result.email_sha256 = raw_sha256
        analysis_result.original_filename = safe_filename
        analysis_result.upload_timestamp = evidence_record.upload_timestamp.isoformat()
        analysis_result.size = evidence_record.size
        analysis_result.uploader = evidence_record.uploader

        # Section 21: Probabilistic Threat Attribution Engine
        try:
            analysis_result.attribution = global_attribution_engine.attribute_email(analysis_result, db=db)
        except Exception:
            analysis_result.attribution = None

        # Section 13: Investigation Relationship Graph (includes Attribution linkages)
        try:
            analysis_result.investigation_graph = global_graph_service.build_graph(analysis_result)
        except Exception:
            analysis_result.investigation_graph = None

        # Log ANALYSIS_COMPLETED audit event
        score_val = analysis_result.threat_score.score if analysis_result.threat_score else 0.0
        sev_val = analysis_result.threat_score.severity if analysis_result.threat_score else "low"
        AuditService.log_audit(
            db=db,
            action="ANALYSIS_COMPLETED",
            resource_type="email",
            resource_id=evidence_record.evidence_id,
            user=uploader_identity,
            metadata={
                "evidence_id": evidence_record.evidence_id,
                "sha256": raw_sha256,
                "threat_score": score_val,
                "severity": sev_val,
                "urls_count": len(analysis_result.urls),
                "attachments_count": len(analysis_result.attachments)
            },
            details=f"Analysis completed for evidence {evidence_record.evidence_id}. Threat score: {score_val} ({sev_val.upper()})."
        )

        # Log ATTRIBUTION_GENERATED audit event if attribution produced
        if analysis_result.attribution:
            try:
                attr_obj = analysis_result.attribution
                AuditService.log_audit(
                    db=db,
                    action="ATTRIBUTION_GENERATED",
                    resource_type="attribution",
                    resource_id=attr_obj.attribution_id,
                    user=uploader_identity,
                    metadata={
                        "attribution_id": attr_obj.attribution_id,
                        "evidence_id": evidence_record.evidence_id,
                        "confidence_score": attr_obj.confidence_score,
                        "confidence_level": attr_obj.confidence_level,
                        "probable_origin_ip": attr_obj.probable_origin_ip,
                        "probable_origin_asn": attr_obj.probable_origin_asn,
                        "probable_infrastructure_country": attr_obj.probable_infrastructure_country,
                        "supporting_count": len(attr_obj.supporting_evidence),
                        "conflicting_count": len(attr_obj.conflicting_evidence)
                    },
                    details=f"Infrastructure attribution generated: {attr_obj.probable_origin_ip or 'Unknown'} "
                            f"({attr_obj.probable_origin_provider or 'Unknown Provider'}), "
                            f"Confidence: {attr_obj.confidence_score}% ({attr_obj.confidence_level})."
                )
            except Exception:
                pass

        # Evidence Confidence Engine Evaluation
        try:
            analysis_result.forensic_conclusions = global_confidence_engine.evaluate_email(analysis_result)
            AuditService.log_audit(
                db=db,
                action="CONFIDENCE_EVALUATED",
                resource_type="confidence",
                resource_id=f"CONF-{evidence_record.evidence_id}",
                user=uploader_identity,
                metadata={
                    "evidence_id": evidence_record.evidence_id,
                    "engine_version": global_confidence_engine.engine_version,
                    "conclusion_count": len(analysis_result.forensic_conclusions),
                    "conclusions": [
                        {
                            "id": c.conclusion_id,
                            "type": c.type.value,
                            "score": c.confidence_score,
                            "level": c.confidence_level
                        }
                        for c in analysis_result.forensic_conclusions
                    ]
                },
                details=f"Evaluated {len(analysis_result.forensic_conclusions)} evidence confidence conclusions across forensic domains. Engine version: {global_confidence_engine.engine_version}."
            )
        except Exception:
            pass

        # Section 19: Record in email_analyses for Analyst Dashboard and save full canonical payload
        try:
            from backend.services.dashboard_service import DashboardService
            from backend.db.models import AnalysisPayloadModel
            DashboardService.record_email_analysis(
                db=db,
                evidence_record=evidence_record,
                analysis_result=analysis_result,
                raw_sha256=raw_sha256
            )
            payload_json = analysis_result.model_dump_json(by_alias=True) if hasattr(analysis_result, "model_dump_json") else json.dumps(analysis_result)
            existing_payload = db.query(AnalysisPayloadModel).filter(AnalysisPayloadModel.evidence_id == evidence_record.evidence_id).first()
            if not existing_payload:
                existing_payload = AnalysisPayloadModel(
                    evidence_id=evidence_record.evidence_id,
                    analysis_json=payload_json
                )
                db.add(existing_payload)
            else:
                existing_payload.analysis_json = payload_json
            db.commit()

            # Register with dynamic Campaign Service and Cross-Email Inverted Index
            try:
                from backend.services.campaign_service import CampaignService
                analysis_dict = json.loads(payload_json)
                CampaignService.register_new_ingested_email(
                    db=db,
                    evidence_id=evidence_record.evidence_id,
                    email_sha256=raw_sha256,
                    analysis_dict=analysis_dict
                )
            except Exception:
                pass
        except Exception:
            db.rollback()

        return analysis_result
    except EmailParseException as e:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"detail": f"Malformed email file: {str(e)}", "error_code": "MALFORMED_EMAIL"}
        )
    except Exception as e:
        import traceback
        traceback.print_exc()
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"detail": f"An error occurred while parsing email: {str(e)}", "error_code": "PARSE_ERROR"}
        )


@router.get(
    "/{id}/analysis",
    summary="Get canonical stored analysis for an email by evidence ID, SHA-256, or record ID",
    description="Returns the exact immutable forensic analysis JSON generated at ingestion."
)
def get_canonical_email_analysis(
    id: str,
    db: Session = Depends(get_db)
):
    from backend.services.analysis_repository import load_analysis
    return load_analysis(db, id)


@router.get(
    "/{sha256:path}/timeline",
    response_model=InvestigationTimelineResponse,
    summary="Get investigation timeline for an email by SHA-256 or evidence ID",
    description="Returns ordered chain-of-custody chronological timeline events."
)
def get_email_investigation_timeline(
    sha256: str,
    db: Session = Depends(get_db)
):
    return AuditService.get_timeline(db, identifier=sha256)


@router.get(
    "/{id}/download",
    summary="Download original raw .eml file",
    description="Streams the authentic, cryptographically verified .eml file stored during ingestion."
)
def download_eml_file(
    id: str,
    db: Session = Depends(get_db)
):
    from backend.services.eml_storage_service import EMLStorageService
    from backend.db.models import EvidenceModel, EmailAnalysisModel

    clean_id = id.strip()
    EMLStorageService.ensure_all_evidence_stored(db)

    eml_path = EMLStorageService.get_eml_path(clean_id)
    if not eml_path or not eml_path.exists():
        raise HTTPException(status_code=404, detail=f"No stored .eml file found for '{clean_id}'.")

    # Determine original filename
    filename = f"{clean_id}.eml"
    evd = db.query(EvidenceModel).filter(
        (EvidenceModel.evidence_id == clean_id) | (EvidenceModel.sha256 == clean_id)
    ).first()
    if evd and evd.original_filename:
        filename = evd.original_filename if evd.original_filename.endswith(".eml") else f"{evd.original_filename}.eml"
    else:
        ea = db.query(EmailAnalysisModel).filter(
            (EmailAnalysisModel.evidence_id == clean_id) | (EmailAnalysisModel.id == clean_id)
        ).first()
        if ea and ea.subject:
            safe_sub = re.sub(r'[^a-zA-Z0-9_\-]', '_', ea.subject)[:32]
            filename = f"{safe_sub}.eml"

    content_bytes = EMLStorageService.get_eml_bytes(clean_id)
    return Response(
        content=content_bytes,
        media_type="message/rfc822",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Evidence-ID": clean_id
        }
    )


@router.get(
    "/{id}/raw-eml",
    summary="Get raw RFC-822 plain text content",
    description="Returns the unparsed RFC-822 raw email string."
)
def get_raw_eml_text(
    id: str,
    db: Session = Depends(get_db)
):
    from backend.services.eml_storage_service import EMLStorageService
    EMLStorageService.ensure_all_evidence_stored(db)
    text = EMLStorageService.get_eml_text(id)
    if not text:
        raise HTTPException(status_code=404, detail=f"Raw .eml text unavailable for '{id}'.")
    return Response(content=text, media_type="text/plain; charset=utf-8")


@router.get(
    "/stored-emls/inventory",
    summary="List all stored raw .eml files on disk",
    description="Returns filesystem inventory of preserved .eml evidence files."
)
def list_stored_emls_endpoint(db: Session = Depends(get_db)):
    from backend.services.eml_storage_service import EMLStorageService
    EMLStorageService.ensure_all_evidence_stored(db)
    return EMLStorageService.list_stored_emls()


