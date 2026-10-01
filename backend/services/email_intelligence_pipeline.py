"""
Email & Phishing Intelligence Pipeline Orchestration Engine (Section 6).
Coordinates modular email analyzers, enriches extracted observables via threat intelligence,
produces normalized canonical data models (AnalysisRun, Finding, EvidenceItem, Indicator,
Relationship, ThreatEvent), and maintains 100% backward compatibility with EmailAnalysisResponse.
"""
from __future__ import annotations

import asyncio
import json
import logging
import uuid
import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Set

from sqlalchemy.orm import Session

from backend.db.models import (
    ArtifactModel,
    AnalysisRunModel,
    FindingModel,
    EvidenceItemModel,
    FindingEvidenceModel,
    IndicatorModel,
    RelationshipModel,
    ThreatEventModel,
    ArtifactStorageRecordModel,
    IngestionRecordModel,
    generate_uuid,
    get_utc_now,
)
from backend.schemas.unified import (
    ArtifactTypeEnum,
    AnalysisStatusEnum,
    AnalysisTriggerEnum,
    FindingMethodEnum,
    IndicatorTypeEnum,
    RelationshipTypeEnum,
    SeverityEnum,
    normalize_domain,
    normalize_ip,
    normalize_url,
    normalize_email_address,
)
from backend.schemas.email import (
    EmailAnalysisResponse,
    HeaderInfo,
    BodyInfo,
    AttachmentInfo,
    FileMeta,
    IndicatorsGroup,
    URLIndicator,
    DomainIndicator,
    IPIndicator,
    EmailAddressIndicator,
    MLAssessmentResult,
)
from backend.services.evidence_storage import evidence_storage
from backend.services.email_analyzers import (
    AnalyzerExecutionResult,
    EmailParserAnalyzer,
    EmailAuthenticationAnalyzer,
    EmailHeaderAnalyzer,
    EmailRelayAnalyzer,
    EmailAttachmentDiscoveryAnalyzer,
    EmailIOCAnalyzer,
    EmailSocialEngineeringAnalyzer,
    EmailImpersonationAnalyzer,
    EmailPhishingAggregator,
)
from backend.services.ip_intelligence_service import global_ip_service
from backend.services.domain_intelligence_service import DomainIntelligenceService
from backend.services.lookalike_detector import LookalikeDetectorService
from backend.services.url_analyzer import URLAnalyzerService
from backend.services.threat_scorer import ThreatScorerService
from backend.services.ai_analyst_service import global_ai_analyst_service
from backend.services.graph_service import global_graph_service
from backend.services.attribution_engine import global_attribution_engine
from backend.services.evidence_confidence_engine import EvidenceConfidenceEngine
from backend.services.html_sanitizer import HTMLSanitizerService
from backend.services.audit_service import AuditService
from backend.services.auth_analyzer import AuthAnalyzerService
from backend.services.relay_reconstructor import RelayReconstructorService
from backend.services.ioc_extractor import IOCExtractorService

logger = logging.getLogger("cyberguard.email_pipeline")

global_lookalike_detector = LookalikeDetectorService()
global_domain_service = DomainIntelligenceService(lookalike_detector=global_lookalike_detector)
global_url_analyzer = URLAnalyzerService(lookalike_detector=global_lookalike_detector)
global_threat_scorer = ThreatScorerService()
global_confidence_engine = EvidenceConfidenceEngine()


class EmailIntelligencePipeline:
    """
    Unified Email & Phishing Intelligence Pipeline.
    Coordinates all modular analyzers, external intelligence queries, and persists
    evidence-backed findings into the canonical CyberGuard Security Knowledge Graph.
    """

    PIPELINE_VERSION = "2.0.0-orchestrated"

    @classmethod
    async def analyze_email_bytes(
        cls,
        db: Session,
        content_bytes: bytes,
        filename: str = "uploaded.eml",
        uploader: str = "SOC Analyst",
        existing_artifact_id: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> Tuple[EmailAnalysisResponse, AnalysisRunModel]:
        """
        Executes full email analysis pipeline against raw EML bytes.
        Returns both the legacy EmailAnalysisResponse and the canonical AnalysisRunModel.
        """
        raw_sha256 = hashlib.sha256(content_bytes).hexdigest()
        req_id = request_id or generate_uuid("req")

        # 1. Ensure Artifact exists for this email
        artifact = None
        if existing_artifact_id:
            artifact = db.query(ArtifactModel).filter(ArtifactModel.id == existing_artifact_id).first()

        if not artifact:
            # Store in content-addressed storage
            storage_res = evidence_storage.store_bytes(
                data=content_bytes,
                original_filename=filename,
                mime_type="message/rfc822",
            )
            artifact = db.query(ArtifactModel).filter(
                ArtifactModel.sha256 == raw_sha256,
                ArtifactModel.artifact_type == ArtifactTypeEnum.EMAIL.value,
            ).first()

            if not artifact:
                artifact = ArtifactModel(
                    id=generate_uuid("art"),
                    artifact_type=ArtifactTypeEnum.EMAIL.value,
                    name=filename,
                    source="UPLOAD",
                    mime_type="message/rfc822",
                    size=len(content_bytes),
                    sha256=raw_sha256,
                    sha1=storage_res.sha1,
                    md5=storage_res.md5,
                    storage_reference=storage_res.storage_key,
                    metadata_json=json.dumps({
                        "uploader": uploader,
                        "filename": filename,
                    }),
                )
                db.add(artifact)
                db.flush()

                # Record physical storage record
                st_rec = ArtifactStorageRecordModel(
                    id=generate_uuid("stor"),
                    artifact_id=artifact.id,
                    storage_key=storage_res.storage_key,
                    storage_backend="LOCAL",
                    sha256=raw_sha256,
                    size=len(content_bytes),
                    mime_type="message/rfc822",
                    original_filename=filename,
                    integrity_status="VERIFIED",
                )
                db.add(st_rec)

            # Record Ingestion
            ing_rec = IngestionRecordModel(
                id=generate_uuid("ing"),
                artifact_id=artifact.id,
                source="UPLOAD",
                submitted_by=uploader,
                original_filename=filename,
                request_id=req_id,
                context_json=json.dumps({"input_mode": "FILE_UPLOAD"}),
                metadata_json="{}",
            )
            db.add(ing_rec)
            db.flush()

        # 2. Create AnalysisRun record
        analysis_run = AnalysisRunModel(
            id=generate_uuid(),
            artifact_id=artifact.id,
            status=AnalysisStatusEnum.RUNNING.value,
            started_at=get_utc_now(),
            trigger=AnalysisTriggerEnum.AUTOMATIC.value,
            pipeline_version=cls.PIPELINE_VERSION,
            metadata_json=json.dumps({"analyzer_name": "email_pipeline", "analyzer_version": cls.PIPELINE_VERSION}),
            created_at=get_utc_now(),
        )
        db.add(analysis_run)
        db.flush()

        context: Dict[str, Any] = {
            "artifact_id": artifact.id,
            "analysis_run_id": analysis_run.id,
            "filename": filename,
            "uploader": uploader,
            "db": db,
        }

        # 3. Modular Analyzer Sequential Execution
        analyzer_results: List[AnalyzerExecutionResult] = []

        # Step 3.1: Parsing
        parser_analyzer = EmailParserAnalyzer()
        res_parse = parser_analyzer.analyze(content_bytes, context)
        analyzer_results.append(res_parse)
        context["parsed_email"] = res_parse.metadata.get("parsed_email", {})

        # Step 3.2: Authentication (SPF, DKIM, DMARC)
        auth_analyzer = EmailAuthenticationAnalyzer()
        res_auth = auth_analyzer.analyze(content_bytes, context)
        analyzer_results.append(res_auth)

        # Step 3.3: Headers & Sender Identity
        header_analyzer = EmailHeaderAnalyzer()
        res_header = header_analyzer.analyze(content_bytes, context)
        analyzer_results.append(res_header)

        # Step 3.4: SMTP Relay Path
        relay_analyzer = EmailRelayAnalyzer()
        res_relay = relay_analyzer.analyze(content_bytes, context)
        analyzer_results.append(res_relay)

        # Step 3.5: Attachments (Safe Discovery & Hash Persistence)
        att_analyzer = EmailAttachmentDiscoveryAnalyzer()
        res_att = att_analyzer.analyze(content_bytes, context)
        analyzer_results.append(res_att)

        # Step 3.6: IOC & URL Extraction (Strict Provenance, Zero SSRF)
        ioc_analyzer = EmailIOCAnalyzer()
        res_ioc = ioc_analyzer.analyze(content_bytes, context)
        analyzer_results.append(res_ioc)
        context["extracted_urls"] = res_ioc.metadata.get("extracted_urls", [])

        # Step 3.7: Social Engineering & NLP
        nlp_analyzer = EmailSocialEngineeringAnalyzer()
        res_nlp = nlp_analyzer.analyze(content_bytes, context)
        analyzer_results.append(res_nlp)

        # Step 3.8: Impersonation & Lookalike
        imp_analyzer = EmailImpersonationAnalyzer(lookalike_detector=global_lookalike_detector)
        res_imp = imp_analyzer.analyze(content_bytes, context)
        analyzer_results.append(res_imp)

        # Step 3.9: Phishing Aggregation & Signal Independence
        agg_summary = EmailPhishingAggregator.aggregate(analyzer_results, context)

        # 4. Asynchronous Intelligence Enrichment for Extracted Observables
        extracted_urls = res_ioc.metadata.get("extracted_urls", [])
        html_links = res_ioc.metadata.get("html_links", [])

        # Collect distinct IPs and Domains
        observed_ips: Set[str] = set()
        observed_domains: Set[str] = set()

        for ind in res_ioc.indicators:
            if ind["indicator_type"] == IndicatorTypeEnum.IP:
                observed_ips.add(ind["value"])
            elif ind["indicator_type"] == IndicatorTypeEnum.DOMAIN:
                observed_domains.add(ind["value"])

        relay_meta = res_relay.metadata.get("relay_analysis", {})
        earliest_node = relay_meta.get("earliest_observable_node", {})
        if earliest_node and earliest_node.get("earliest_observable_ip"):
            observed_ips.add(earliest_node["earliest_observable_ip"])

        auth_meta = res_auth.metadata.get("auth_analysis", {})
        align_meta = auth_meta.get("alignment", {})
        if align_meta:
            for k in ("from_domain", "reply_to_domain", "return_path_domain"):
                if align_meta.get(k):
                    observed_domains.add(align_meta[k])

        # Execute concurrent external intelligence lookups
        ip_list = list(observed_ips)
        domain_list = list(observed_domains)

        try:
            ip_intel_dict, domain_intel_dict = await asyncio.gather(
                global_ip_service.get_batch_ip_intelligence(ip_list),
                global_domain_service.enrich_domains_batch(domain_list),
            )
        except Exception as e:
            logger.warning(f"External intelligence gathering encountered warning: {e}")
            ip_intel_dict, domain_intel_dict = {}, {}

        # Static URL analysis
        analyzed_urls = global_url_analyzer.analyze_urls(extracted_urls, html_links=html_links)
        lookalikes_batch = global_lookalike_detector.detect_lookalikes_batch(domain_list)

        # 5. Persist All Canonical Unified Models (Findings, Evidence, Indicators, Relationships, ThreatEvents)
        created_findings: List[FindingModel] = []
        created_evidence: List[EvidenceItemModel] = []

        for a_res in analyzer_results:
            finding_models: List[FindingModel] = []
            for f_dict in a_res.findings:
                f_sev = f_dict.get("severity")
                sev_val = f_sev.value if isinstance(f_sev, SeverityEnum) else str(f_sev or "SAFE").upper()
                f_meth = f_dict.get("method")
                meth_val = f_meth.value if isinstance(f_meth, FindingMethodEnum) else str(f_meth or "DETERMINISTIC").upper()

                find_meta = dict(f_dict.get("metadata") or {})
                if f_dict.get("category"):
                    find_meta["category"] = f_dict["category"]
                if f_dict.get("remediation"):
                    find_meta["remediation"] = f_dict["remediation"]

                find_model = FindingModel(
                    id=generate_uuid(),
                    analysis_run_id=analysis_run.id,
                    analyzer=a_res.analyzer_name[:100],
                    finding_type=f_dict["finding_type"][:100],
                    title=f_dict["title"][:255],
                    description=f_dict["description"],
                    severity=sev_val,
                    confidence=f_dict.get("confidence", 1.0),
                    risk_contribution=f_dict.get("risk_contribution", 0.0),
                    method=meth_val,
                    rule_id=f_dict.get("mitre_technique_id"),
                    metadata_json=json.dumps(find_meta),
                    created_at=get_utc_now(),
                )
                db.add(find_model)
                db.flush()
                finding_models.append(find_model)
                created_findings.append(find_model)

            # Persist and link evidence items
            for link in a_res.finding_evidence_links:
                f_idx, e_idx = link[0], link[1]
                if f_idx < len(finding_models) and e_idx < len(a_res.evidence_items):
                    f_m = finding_models[f_idx]
                    e_dict = a_res.evidence_items[e_idx]
                    ev_meta = dict(e_dict.get("metadata") or {})
                    if len(link) > 2 and link[2] is not None:
                        ev_meta["relevance_score"] = link[2]
                    if len(link) > 3 and link[3]:
                        ev_meta["notes"] = link[3]
                    if e_dict.get("parsed_content"):
                        ev_meta["parsed_content"] = e_dict["parsed_content"]

                    val_str = e_dict.get("raw_content")
                    if not val_str and e_dict.get("parsed_content"):
                        val_str = json.dumps(e_dict["parsed_content"])
                    if not val_str:
                        val_str = e_dict.get("evidence_type", "")

                    ev_model = FindingEvidenceModel(
                        id=generate_uuid(),
                        finding_id=f_m.id,
                        artifact_id=artifact.id,
                        source=e_dict.get("source", "EMAIL")[:100],
                        evidence_type=e_dict.get("evidence_type", "GENERIC")[:50],
                        key=e_dict.get("key") or e_dict.get("evidence_type", "evidence")[:100],
                        value=val_str,
                        confidence=e_dict.get("confidence", 1.0),
                        timestamp=get_utc_now(),
                        metadata_json=json.dumps(ev_meta),
                        created_at=get_utc_now(),
                    )
                    db.add(ev_model)
                    db.flush()
                    created_evidence.append(ev_model)

            linked_e_indices = {link[1] for link in a_res.finding_evidence_links}
            for e_idx, e_dict in enumerate(a_res.evidence_items):
                if e_idx not in linked_e_indices:
                    target_finding = finding_models[0] if finding_models else None
                    if not target_finding:
                        target_finding = FindingModel(
                            id=generate_uuid(),
                            analysis_run_id=analysis_run.id,
                            analyzer=a_res.analyzer_name[:100],
                            finding_type="TELEMETRY_OBSERVED",
                            title=f"{a_res.analyzer_name} Telemetry",
                            description=f"Observed forensic evidence for {a_res.analyzer_name}.",
                            severity=SeverityEnum.SAFE.value,
                            confidence=1.0,
                            risk_contribution=0.0,
                            method=FindingMethodEnum.DETERMINISTIC.value,
                            metadata_json="{}",
                            created_at=get_utc_now(),
                        )
                        db.add(target_finding)
                        db.flush()
                        finding_models.append(target_finding)
                        created_findings.append(target_finding)

                    ev_meta = dict(e_dict.get("metadata") or {})
                    if e_dict.get("parsed_content"):
                        ev_meta["parsed_content"] = e_dict["parsed_content"]
                    val_str = e_dict.get("raw_content") or json.dumps(e_dict.get("parsed_content") or {}) or e_dict.get("evidence_type", "")
                    ev_model = FindingEvidenceModel(
                        id=generate_uuid(),
                        finding_id=target_finding.id,
                        artifact_id=artifact.id,
                        source=e_dict.get("source", "EMAIL")[:100],
                        evidence_type=e_dict.get("evidence_type", "GENERIC")[:50],
                        key=e_dict.get("key") or e_dict.get("evidence_type", "evidence")[:100],
                        value=val_str,
                        confidence=e_dict.get("confidence", 1.0),
                        timestamp=get_utc_now(),
                        metadata_json=json.dumps(ev_meta),
                        created_at=get_utc_now(),
                    )
                    db.add(ev_model)
                    db.flush()
                    created_evidence.append(ev_model)

            # Indicators
            for ind_dict in a_res.indicators:
                ind_type = ind_dict["indicator_type"]
                type_val = ind_type.value if isinstance(ind_type, IndicatorTypeEnum) else str(ind_type)
                val = ind_dict["value"]
                norm_val = ind_dict.get("normalized_value") or val

                existing_ind = db.query(IndicatorModel).filter(
                    IndicatorModel.indicator_type == type_val,
                    IndicatorModel.normalized_value == norm_val,
                ).first()

                if not existing_ind:
                    ind_meta = {}
                    if ind_dict.get("threat_types"):
                        ind_meta["threat_types"] = ind_dict["threat_types"]
                    if ind_dict.get("source"):
                        ind_meta["source"] = ind_dict["source"]
                    new_ind = IndicatorModel(
                        id=generate_uuid(),
                        indicator_type=type_val,
                        value=val,
                        normalized_value=norm_val,
                        reputation=ind_dict.get("reputation"),
                        metadata_json=json.dumps(ind_meta),
                    )
                    db.add(new_ind)
                    db.flush()

            # Derived Artifacts & Relationships
            for d_art in a_res.derived_artifacts:
                child_art = db.query(ArtifactModel).filter(
                    ArtifactModel.sha256 == d_art["sha256"],
                    ArtifactModel.artifact_type == d_art["artifact_type"].value,
                ).first()

                if not child_art:
                    child_art = ArtifactModel(
                        id=generate_uuid(),
                        artifact_type=d_art["artifact_type"].value,
                        name=d_art["name"],
                        source="EXTRACTED",
                        mime_type=d_art.get("mime_type"),
                        size=d_art.get("size"),
                        sha256=d_art["sha256"],
                        sha1=d_art.get("sha1"),
                        md5=d_art.get("md5"),
                        storage_reference=d_art.get("storage_reference"),
                        parent_artifact_id=artifact.id,
                    )
                    db.add(child_art)
                    db.flush()

                # Relationship: EMAIL -> CONTAINS -> ATTACHMENT
                rel_contains = RelationshipModel(
                    id=generate_uuid(),
                    source_id=artifact.id,
                    source_type="Artifact",
                    target_id=child_art.id,
                    target_type="Artifact",
                    relationship_type=RelationshipTypeEnum.CONTAINS.value,
                    confidence=1.0,
                    method="DETERMINISTIC",
                    analysis_run_id=analysis_run.id,
                )
                db.add(rel_contains)

        # Record relationships for URLs, Domains, IPs
        for u in extracted_urls:
            rel_u = RelationshipModel(
                id=generate_uuid(),
                source_id=artifact.id,
                source_type="Artifact",
                target_id=normalize_url(u),
                target_type="Indicator",
                relationship_type=RelationshipTypeEnum.REFERENCES.value,
                confidence=1.0,
                method="DETERMINISTIC",
                analysis_run_id=analysis_run.id,
            )
            db.add(rel_u)

        for d in observed_domains:
            rel_d = RelationshipModel(
                id=generate_uuid(),
                source_id=artifact.id,
                source_type="Artifact",
                target_id=normalize_domain(d),
                target_type="Indicator",
                relationship_type=RelationshipTypeEnum.REFERENCES.value,
                confidence=1.0,
                method="DETERMINISTIC",
                analysis_run_id=analysis_run.id,
            )
            db.add(rel_d)

        # ThreatEvent creation where justified by aggregated classification
        created_threat_event = None
        if agg_summary.get("threat_event_type"):
            evt_type = agg_summary["threat_event_type"]
            evt_sev = SeverityEnum.HIGH.value if evt_type == "PHISHING_ATTEMPT" else SeverityEnum.MEDIUM.value
            created_threat_event = ThreatEventModel(
                id=generate_uuid(),
                event_type=evt_type,
                severity=evt_sev,
                confidence=agg_summary.get("confidence", 1.0),
                source_artifact_id=artifact.id,
                analysis_run_id=analysis_run.id,
                summary=f"{agg_summary['classification']} detected for email '{filename}'. {agg_summary.get('distinct_suspicious_categories', 0)} suspicious categories corroborated.",
                metadata_json=json.dumps(agg_summary),
            )
            db.add(created_threat_event)
            db.flush()

        # 6. Build Backward-Compatible EmailAnalysisResponse
        parsed_email = context.get("parsed_email", {})
        plain_text_str = parsed_email.get("plain_text_body")
        html_str = parsed_email.get("html_body")
        if html_str:
            html_str = HTMLSanitizerService.sanitize_html(html_str)

        # Attachment Info schema objects
        att_infos: List[AttachmentInfo] = []
        for d_att in res_att.derived_artifacts:
            att_infos.append(AttachmentInfo(
                filename=d_att["name"],
                mime_type=d_att.get("mime_type") or "application/octet-stream",
                size=d_att.get("size") or 0,
                sha256=d_att["sha256"],
                sha1=d_att.get("sha1"),
                md5=d_att.get("md5"),
            ))

        # URL Indicator schema objects
        url_ind_objs = [URLIndicator(value=u, source="body") for u in extracted_urls]
        domain_ind_objs = [DomainIndicator(value=d, source="extracted") for d in observed_domains]
        ip_ind_objs = []
        for ip_val in observed_ips:
            ver, scope = IOCExtractorService.classify_ip_scope(ip_val)
            ip_ind_objs.append(IPIndicator(value=ip_val, version=ver, scope=scope, source="extracted"))

        email_ind_objs = [
            EmailAddressIndicator(value=parsed_email.get("from_address") or "", source="From")
        ] if parsed_email.get("from_address") else []

        # Reconstruct auth schema
        auth_analysis = AuthAnalyzerService.analyze_authentication(
            from_header=parsed_email.get("from_header"),
            reply_to=parsed_email.get("reply_to"),
            return_path=parsed_email.get("return_path"),
            auth_headers=parsed_email.get("auth_results_headers") or [],
            received_spf_headers=parsed_email.get("received_spf_headers") or [],
            raw_headers_text=content_bytes.decode("utf-8", errors="replace"),
        )

        relay_analysis = RelayReconstructorService.reconstruct_relay_path(
            parsed_email.get("received_headers") or []
        )

        headers_obj = HeaderInfo(
            from_header=parsed_email.get("from_header"),
            to=parsed_email.get("to_header"),
            cc=parsed_email.get("cc_header"),
            subject=parsed_email.get("subject"),
            date=parsed_email.get("date"),
            reply_to=parsed_email.get("reply_to"),
            return_path=parsed_email.get("return_path"),
            message_id=parsed_email.get("message_id"),
            received=parsed_email.get("received_headers") or [],
            authentication_results="; ".join(parsed_email.get("auth_results_headers") or []) or None,
        )

        body_obj = BodyInfo(plain_text=plain_text_str, html=html_str)
        file_meta = FileMeta(filename=filename, size_bytes=len(content_bytes))
        ind_group = IndicatorsGroup(
            ips=ip_ind_objs,
            domains=domain_ind_objs,
            urls=url_ind_objs,
            email_addresses=email_ind_objs,
            attachments=[],
        )

        legacy_response = EmailAnalysisResponse(
            id=req_id,
            evidence_id=req_id,
            email_sha256=raw_sha256,
            original_filename=filename,
            upload_timestamp=datetime.now(timezone.utc).isoformat(),
            size=len(content_bytes),
            uploader=uploader,
            headers=headers_obj,
            body=body_obj,
            subject=parsed_email.get("subject"),
            from_header=parsed_email.get("from_header"),
            to=parsed_email.get("to_header"),
            cc=parsed_email.get("cc_header"),
            date=parsed_email.get("date"),
            reply_to=parsed_email.get("reply_to"),
            return_path=parsed_email.get("return_path"),
            message_id=parsed_email.get("message_id"),
            received=parsed_email.get("received_headers") or [],
            authentication_results="; ".join(parsed_email.get("auth_results_headers") or []) or None,
            plain_text_body=plain_text_str,
            html_body=html_str,
            raw_email=content_bytes.decode("utf-8", errors="replace"),
            urls=extracted_urls,
            url_analysis=analyzed_urls,
            ips=observed_ips,
            domains=observed_domains,
            emails=[parsed_email.get("from_address")] if parsed_email.get("from_address") else [],
            attachments=att_infos,
            authentication=auth_analysis,
            relay_analysis=relay_analysis,
            file_info=file_meta,
            indicators=ind_group,
            threat_score=None,
            ip_intelligence=ip_intel_dict,
            domain_intelligence=domain_intel_dict,
            lookalike_domains=lookalikes_batch,
        )

        # Calculate threat score
        threat_score_res = global_threat_scorer.calculate_score(legacy_response)
        legacy_response.threat_score = threat_score_res

        # ML assessment
        ml_prediction = res_nlp.metadata.get("ml_prediction")
        if ml_prediction:
            legacy_response.ml_assessment = MLAssessmentResult(**ml_prediction)
            legacy_response.ml_phishing_probability = ml_prediction.get("probability")

        # AI Analyst
        try:
            legacy_response.ai_analyst = await global_ai_analyst_service.analyze(legacy_response)
        except Exception:
            legacy_response.ai_analyst = None

        # Threat Attribution
        try:
            legacy_response.attribution = global_attribution_engine.attribute_email(legacy_response, db=db)
        except Exception:
            legacy_response.attribution = None

        # Evidence Confidence conclusions
        try:
            legacy_response.forensic_conclusions = global_confidence_engine.evaluate_email(legacy_response)
        except Exception:
            legacy_response.forensic_conclusions = []

        # Graph
        try:
            legacy_response.investigation_graph = global_graph_service.build_graph(legacy_response)
        except Exception:
            legacy_response.investigation_graph = None

        # Metadata
        legacy_response.evidence_id = req_id
        legacy_response.email_sha256 = raw_sha256
        legacy_response.original_filename = filename
        legacy_response.upload_timestamp = datetime.now(timezone.utc).isoformat()
        legacy_response.size = len(content_bytes)
        legacy_response.uploader = uploader

        # 7. Finalize AnalysisRun record
        analysis_run.status = AnalysisStatusEnum.COMPLETED.value
        analysis_run.completed_at = get_utc_now()
        analysis_run.overall_risk_score = threat_score_res.score if threat_score_res else 0.0
        analysis_run.overall_severity = agg_summary.get("severity", SeverityEnum.LOW.value)
        analysis_run.confidence = agg_summary.get("confidence", 1.0)
        run_meta = {
            "findings_count": len(created_findings),
            "summary": f"Completed orchestrated email analysis: {agg_summary['classification']} (Threat Score: {analysis_run.overall_risk_score:.1f}, Findings: {len(created_findings)}).",
            "raw_output_json": legacy_response.model_dump_json(by_alias=True),
        }
        curr = json.loads(analysis_run.metadata_json or "{}")
        curr.update(run_meta)
        analysis_run.metadata_json = json.dumps(curr)

        db.commit()

        return legacy_response, analysis_run

    @classmethod
    async def analyze_artifact(
        cls,
        db: Session,
        artifact_id: str,
        uploader: str = "SOC Analyst",
    ) -> Tuple[EmailAnalysisResponse, AnalysisRunModel]:
        """
        Executes email intelligence pipeline against an existing Artifact by reading its
        durable bytes from evidence storage.
        """
        artifact = db.query(ArtifactModel).filter(ArtifactModel.id == artifact_id).first()
        if not artifact:
            raise ValueError(f"Artifact '{artifact_id}' not found.")

        if artifact.artifact_type != ArtifactTypeEnum.EMAIL.value:
            raise ValueError(f"Artifact '{artifact_id}' is not an EMAIL artifact (type: {artifact.artifact_type}).")

        # Read bytes from persistent storage
        if not artifact.storage_reference:
            raise ValueError(f"Artifact '{artifact_id}' has no storage reference.")

        raw_bytes = evidence_storage.retrieve_bytes(artifact.storage_reference)
        return await cls.analyze_email_bytes(
            db=db,
            content_bytes=raw_bytes,
            filename=artifact.name,
            uploader=uploader,
            existing_artifact_id=artifact.id,
        )
