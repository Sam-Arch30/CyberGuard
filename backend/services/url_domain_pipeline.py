"""
URL, Domain & Website Intelligence Pipeline Coordinator (Section 7).
Orchestrates passive-first analysis, domain intelligence, DNS relationship mapping,
and SSRF-defended active website inspection.
Guarantees canonical persistence across Artifacts, AnalysisRuns, Findings, Evidence,
Indicators, Relationships, and ThreatEvents with full historical re-analysis support.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlsplit

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
)
from backend.services.evidence_storage import evidence_storage
from backend.services.safe_http_client import SafeHttpClient
from backend.services.dns_service import DNSService
from backend.services.rdap_service import RDAPService
from backend.services.lookalike_detector import LookalikeDetectorService
from backend.services.threat_intelligence_service import ThreatIntelligenceService
from backend.services.url_domain_analyzers import (
    AnalyzerExecutionResult,
    PassiveURLAnalyzer,
    DomainIntelligenceAnalyzer,
    SafeWebsiteAnalyzer,
)

logger = logging.getLogger("cyberguard.url_domain_pipeline")


class URLDomainIntelligencePipeline:
    """
    Unified Pipeline Coordinator for URL, Domain, and Website Analysis.
    Integrates Section 2 Data Model, Section 3 Persistent Storage, and Section 5 Orchestrator.
    """

    PIPELINE_VERSION = "2.0.0"

    def __init__(
        self,
        safe_client: Optional[SafeHttpClient] = None,
        dns_service: Optional[DNSService] = None,
        rdap_service: Optional[RDAPService] = None,
        threat_intel_service: Optional[ThreatIntelligenceService] = None,
        lookalike_detector: Optional[LookalikeDetectorService] = None,
    ):
        self.safe_client = safe_client or SafeHttpClient()
        self.dns_service = dns_service or DNSService()
        self.rdap_service = rdap_service or RDAPService()
        self.threat_intel = threat_intel_service or ThreatIntelligenceService()
        self.lookalike_detector = lookalike_detector or LookalikeDetectorService()

    async def analyze_url(
        self,
        url: str,
        db: Session,
        active_analysis_enabled: bool = True,
        uploader: str = "ANALYST",
        request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Executes end-to-end URL and website investigation with canonical persistence.
        Always performs passive structural analysis first before any controlled active network fetch.
        """
        clean_url = url.strip()
        url_bytes = clean_url.encode("utf-8")
        sha256 = hashlib.sha256(url_bytes).hexdigest()

        # 1. Ingest or Retrieve Artifact
        artifact = db.query(ArtifactModel).filter(
            ArtifactModel.sha256 == sha256,
            ArtifactModel.artifact_type == ArtifactTypeEnum.URL.value,
        ).first()

        req_id = request_id or generate_uuid("req")

        if not artifact:
            # Store in evidence storage
            store_res = evidence_storage.store_bytes(
                data=url_bytes,
                original_filename=f"url_{sha256[:12]}.txt",
                mime_type="text/plain",
            )
            artifact = ArtifactModel(
                id=generate_uuid(),
                artifact_type=ArtifactTypeEnum.URL.value,
                name=clean_url[:255],
                source="URL_SUBMISSION",
                mime_type="text/plain",
                size=len(url_bytes),
                sha256=sha256,
                storage_reference=store_res.storage_key,
                created_at=get_utc_now(),
            )
            db.add(artifact)
            db.flush()

            st_rec = ArtifactStorageRecordModel(
                id=generate_uuid("stor"),
                artifact_id=artifact.id,
                storage_key=store_res.storage_key,
                storage_backend="LOCAL",
                sha256=sha256,
                size=len(url_bytes),
                mime_type="text/plain",
                original_filename=f"url_{sha256[:12]}.txt",
                integrity_status="VERIFIED",
            )
            db.add(st_rec)

            ing_rec = IngestionRecordModel(
                id=generate_uuid("ing"),
                artifact_id=artifact.id,
                source="URL_INPUT",
                submitted_by=uploader,
                original_filename=clean_url[:255],
                request_id=req_id,
                context_json=json.dumps({"input_mode": "URL", "active_analysis_enabled": active_analysis_enabled}),
                metadata_json="{}",
            )
            db.add(ing_rec)
            db.flush()

        # 2. Create AnalysisRun record (Append-Only History)
        analysis_run = AnalysisRunModel(
            id=generate_uuid(),
            artifact_id=artifact.id,
            status=AnalysisStatusEnum.RUNNING.value,
            started_at=get_utc_now(),
            trigger=AnalysisTriggerEnum.USER.value,
            pipeline_version=self.PIPELINE_VERSION,
            metadata_json=json.dumps({
                "analyzer_name": "url_domain_pipeline",
                "analyzer_version": self.PIPELINE_VERSION,
                "target_url": clean_url,
                "active_analysis_enabled": active_analysis_enabled,
            }),
            created_at=get_utc_now(),
        )
        db.add(analysis_run)
        db.flush()

        context: Dict[str, Any] = {
            "artifact_id": artifact.id,
            "analysis_run_id": analysis_run.id,
            "url_active_analysis_enabled": active_analysis_enabled,
            "db": db,
        }

        # 3. Sequential Multi-Stage Execution
        analyzer_results: List[AnalyzerExecutionResult] = []

        # Stage 3.1: Passive URL Structural Analysis (Zero network traffic)
        passive_analyzer = PassiveURLAnalyzer()
        res_passive = await passive_analyzer.analyze(clean_url, context)
        analyzer_results.append(res_passive)

        parsed_components = res_passive.metadata.get("parsed_components", {})
        extracted_host = parsed_components.get("hostname", "")

        # Stage 3.2: Domain Intelligence Analysis (DNS, RDAP, Lookalike, Threat Intel)
        domain_analyzer = DomainIntelligenceAnalyzer(
            dns_service=self.dns_service,
            rdap_service=self.rdap_service,
            threat_intel_service=self.threat_intel,
            lookalike_detector=self.lookalike_detector,
        )
        res_domain = await domain_analyzer.analyze(extracted_host, context)
        analyzer_results.append(res_domain)

        # Stage 3.3: Safe Controlled Website Inspection (SSRF-defended active fetch)
        website_analyzer = SafeWebsiteAnalyzer(
            safe_client=self.safe_client,
            active_analysis_enabled=active_analysis_enabled,
        )
        res_website = await website_analyzer.analyze(clean_url, context)
        analyzer_results.append(res_website)

        # 4. Aggregation and Risk Scoring
        all_findings = []
        for a_res in analyzer_results:
            all_findings.extend(a_res.findings)

        overall_score, overall_sev, confidence = self._compute_overall_risk(all_findings)

        # 5. Persist Normalized Models to Database
        self._persist_canonical_records(
            db=db,
            artifact=artifact,
            analysis_run=analysis_run,
            analyzer_results=analyzer_results,
            overall_score=overall_score,
            overall_sev=overall_sev,
            confidence=confidence,
        )

        db.commit()

        # Build Response Payload
        return self._build_pipeline_response(
            artifact_id=artifact.id,
            analysis_run_id=analysis_run.id,
            target=clean_url,
            target_type="URL",
            overall_score=overall_score,
            overall_severity=overall_sev,
            confidence=confidence,
            analyzer_results=analyzer_results,
            active_analysis_enabled=active_analysis_enabled,
        )

    async def analyze_domain(
        self,
        domain: str,
        db: Session,
        uploader: str = "ANALYST",
        request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Executes domain-only intelligence pipeline with canonical persistence.
        """
        clean_dom = domain.strip().lower().rstrip(".")
        dom_bytes = clean_dom.encode("utf-8")
        sha256 = hashlib.sha256(dom_bytes).hexdigest()

        # Ingest or Retrieve Domain Artifact
        artifact = db.query(ArtifactModel).filter(
            ArtifactModel.sha256 == sha256,
            ArtifactModel.artifact_type == ArtifactTypeEnum.DOMAIN.value,
        ).first()

        req_id = request_id or generate_uuid("req")

        if not artifact:
            store_res = evidence_storage.store_bytes(
                data=dom_bytes,
                original_filename=f"domain_{sha256[:12]}.txt",
                mime_type="text/plain",
            )
            artifact = ArtifactModel(
                id=generate_uuid(),
                artifact_type=ArtifactTypeEnum.DOMAIN.value,
                name=clean_dom[:255],
                source="DOMAIN_SUBMISSION",
                mime_type="text/plain",
                size=len(dom_bytes),
                sha256=sha256,
                storage_reference=store_res.storage_key,
                created_at=get_utc_now(),
            )
            db.add(artifact)
            db.flush()

            st_rec = ArtifactStorageRecordModel(
                id=generate_uuid("stor"),
                artifact_id=artifact.id,
                storage_key=store_res.storage_key,
                storage_backend="LOCAL",
                sha256=sha256,
                size=len(dom_bytes),
                mime_type="text/plain",
                original_filename=f"domain_{sha256[:12]}.txt",
                integrity_status="VERIFIED",
            )
            db.add(st_rec)

            ing_rec = IngestionRecordModel(
                id=generate_uuid("ing"),
                artifact_id=artifact.id,
                source="DOMAIN_INPUT",
                submitted_by=uploader,
                original_filename=clean_dom[:255],
                request_id=req_id,
                context_json=json.dumps({"input_mode": "DOMAIN"}),
                metadata_json="{}",
            )
            db.add(ing_rec)
            db.flush()

        # Create AnalysisRun record
        analysis_run = AnalysisRunModel(
            id=generate_uuid(),
            artifact_id=artifact.id,
            status=AnalysisStatusEnum.RUNNING.value,
            started_at=get_utc_now(),
            trigger=AnalysisTriggerEnum.USER.value,
            pipeline_version=self.PIPELINE_VERSION,
            metadata_json=json.dumps({
                "analyzer_name": "domain_pipeline",
                "analyzer_version": self.PIPELINE_VERSION,
                "target_domain": clean_dom,
            }),
            created_at=get_utc_now(),
        )
        db.add(analysis_run)
        db.flush()

        context = {
            "artifact_id": artifact.id,
            "analysis_run_id": analysis_run.id,
            "db": db,
        }

        # Domain Intelligence Analyzer
        domain_analyzer = DomainIntelligenceAnalyzer(
            dns_service=self.dns_service,
            rdap_service=self.rdap_service,
            threat_intel_service=self.threat_intel,
            lookalike_detector=self.lookalike_detector,
        )
        res_domain = await domain_analyzer.analyze(clean_dom, context)
        analyzer_results = [res_domain]

        all_findings = res_domain.findings
        overall_score, overall_sev, confidence = self._compute_overall_risk(all_findings)

        self._persist_canonical_records(
            db=db,
            artifact=artifact,
            analysis_run=analysis_run,
            analyzer_results=analyzer_results,
            overall_score=overall_score,
            overall_sev=overall_sev,
            confidence=confidence,
        )

        db.commit()

        return self._build_pipeline_response(
            artifact_id=artifact.id,
            analysis_run_id=analysis_run.id,
            target=clean_dom,
            target_type="DOMAIN",
            overall_score=overall_score,
            overall_severity=overall_sev,
            confidence=confidence,
            analyzer_results=analyzer_results,
            active_analysis_enabled=False,
        )

    async def analyze_artifact(
        self,
        artifact_id: str,
        db: Session,
        active_analysis_enabled: bool = True,
    ) -> Dict[str, Any]:
        """
        Re-analyzes an existing durable artifact loaded directly from storage.
        Always generates a new independent AnalysisRunModel record preserving historical observation lineage.
        """
        artifact = db.query(ArtifactModel).filter(ArtifactModel.id == artifact_id).first()
        if not artifact:
            raise ValueError(f"Artifact not found: {artifact_id}")

        storage_key = artifact.storage_reference or artifact.sha256
        content_bytes = evidence_storage.retrieve_bytes(storage_key)
        if not content_bytes:
            raise ValueError(f"Artifact content unretrievable for reference: {storage_key}")

        raw_str = content_bytes.decode("utf-8", errors="replace").strip()

        if artifact.artifact_type == ArtifactTypeEnum.DOMAIN.value:
            return await self.analyze_domain(domain=raw_str, db=db)
        else:
            return await self.analyze_url(url=raw_str, db=db, active_analysis_enabled=active_analysis_enabled)

    def _compute_overall_risk(self, findings: List[Dict[str, Any]]) -> Tuple[float, str, float]:
        """Calculates normalized threat score (0-100), severity enum string, and confidence."""
        if not findings:
            return 0.0, SeverityEnum.SAFE.value, 1.0

        score = 0.0
        severities = [f.get("severity") for f in findings]
        has_critical = any(s == SeverityEnum.CRITICAL or str(s).upper() == "CRITICAL" for s in severities)
        has_high = any(s == SeverityEnum.HIGH or str(s).upper() == "HIGH" for s in severities)
        has_medium = any(s == SeverityEnum.MEDIUM or str(s).upper() == "MEDIUM" for s in severities)
        has_low = any(s == SeverityEnum.LOW or str(s).upper() == "LOW" for s in severities)

        if has_critical:
            score = 92.0
            sev = SeverityEnum.CRITICAL.value
        elif has_high:
            score = 75.0
            sev = SeverityEnum.HIGH.value
        elif has_medium:
            score = 50.0
            sev = SeverityEnum.MEDIUM.value
        elif has_low:
            score = 25.0
            sev = SeverityEnum.LOW.value
        else:
            score = 0.0
            sev = SeverityEnum.SAFE.value

        confidences = [f.get("confidence", 1.0) for f in findings]
        avg_conf = sum(confidences) / len(confidences) if confidences else 1.0

        return score, sev, round(avg_conf, 2)

    def _persist_canonical_records(
        self,
        db: Session,
        artifact: ArtifactModel,
        analysis_run: AnalysisRunModel,
        analyzer_results: List[AnalyzerExecutionResult],
        overall_score: float,
        overall_sev: str,
        confidence: float,
    ):
        """Persists findings, evidence items, indicators, and relationships into canonical tables."""
        created_findings: List[FindingModel] = []

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
                        source=e_dict.get("source", "URL_ANALYZER")[:100],
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

            # Persist unlinked evidence items to the first finding
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
                            description=f"Observed evidence for {a_res.analyzer_name}.",
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
                        source=e_dict.get("source", "URL_ANALYZER")[:100],
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

            # Persist Indicators
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

            # Persist Relationships
            for rel_dict in a_res.relationships:
                rel_type = rel_dict["relationship_type"]
                rel_type_val = rel_type.value if isinstance(rel_type, RelationshipTypeEnum) else str(rel_type)

                rel_model = RelationshipModel(
                    id=generate_uuid(),
                    source_id=rel_dict["source_id"],
                    source_type=rel_dict["source_type"],
                    target_id=rel_dict["target_id"],
                    target_type=rel_dict["target_type"],
                    relationship_type=rel_type_val,
                    confidence=rel_dict.get("confidence", 1.0),
                    method=rel_dict.get("method", "DETERMINISTIC"),
                    created_at=get_utc_now(),
                )
                db.add(rel_model)
                db.flush()

        # Create ThreatEvent if significant threats discovered
        if overall_sev in (SeverityEnum.CRITICAL.value, SeverityEnum.HIGH.value):
            te_type = "PHISHING_ATTEMPT" if any(f.finding_type in ("CREDENTIAL_HARVESTING_INDICATORS", "LOOKALIKE_DOMAIN", "DECEPTIVE_SUBDOMAIN_HIERARCHY") for f in created_findings) else "SUSPICIOUS_URL"
            if any(f.finding_type == "BLOCKED_INTERNAL_DESTINATION" for f in created_findings):
                te_type = "SSRF_ATTEMPT"

            threat_event = ThreatEventModel(
                id=generate_uuid(),
                event_type=te_type,
                timestamp=get_utc_now(),
                severity=overall_sev,
                source="url_domain_pipeline",
                description=f"{te_type} detected for target {artifact.name}.",
                artifact_id=artifact.id,
                created_at=get_utc_now(),
            )
            db.add(threat_event)
            db.flush()

        # Finalize AnalysisRun record
        analysis_run.status = AnalysisStatusEnum.COMPLETED.value
        analysis_run.completed_at = get_utc_now()
        analysis_run.overall_score = overall_score
        analysis_run.overall_severity = overall_sev
        analysis_run.confidence = confidence

    def _build_pipeline_response(
        self,
        artifact_id: str,
        analysis_run_id: str,
        target: str,
        target_type: str,
        overall_score: float,
        overall_severity: str,
        confidence: float,
        analyzer_results: List[AnalyzerExecutionResult],
        active_analysis_enabled: bool,
    ) -> Dict[str, Any]:
        """Formats normalized pipeline result dictionary."""
        all_findings = []
        all_indicators = []
        all_relationships = []
        metadata_map: Dict[str, Any] = {}

        for a_res in analyzer_results:
            metadata_map[a_res.analyzer_name] = a_res.metadata
            for f in a_res.findings:
                f_sev = f.get("severity")
                sev_str = f_sev.value if isinstance(f_sev, SeverityEnum) else str(f_sev or "SAFE").upper()
                all_findings.append({
                    "analyzer": a_res.analyzer_name,
                    "title": f["title"],
                    "description": f["description"],
                    "finding_type": f["finding_type"],
                    "category": f.get("category", "GENERAL"),
                    "severity": sev_str,
                    "confidence": f.get("confidence", 1.0),
                    "mitre_technique_id": f.get("mitre_technique_id"),
                })
            for ind in a_res.indicators:
                itype = ind["indicator_type"]
                itype_str = itype.value if isinstance(itype, IndicatorTypeEnum) else str(itype)
                all_indicators.append({
                    "type": itype_str,
                    "value": ind["value"],
                    "normalized_value": ind.get("normalized_value"),
                })
            for rel in a_res.relationships:
                rtype = rel["relationship_type"]
                rtype_str = rtype.value if isinstance(rtype, RelationshipTypeEnum) else str(rtype)
                all_relationships.append({
                    "source_id": rel["source_id"],
                    "source_type": rel["source_type"],
                    "target_id": rel["target_id"],
                    "target_type": rel["target_type"],
                    "relationship_type": rtype_str,
                    "confidence": rel.get("confidence", 1.0),
                })

        return {
            "artifact_id": artifact_id,
            "analysis_run_id": analysis_run_id,
            "target": target,
            "target_type": target_type,
            "overall_score": overall_score,
            "overall_severity": overall_severity,
            "confidence": confidence,
            "status": "COMPLETED",
            "active_analysis_enabled": active_analysis_enabled,
            "findings_count": len(all_findings),
            "findings": all_findings,
            "indicators": all_indicators,
            "relationships": all_relationships,
            "analyzer_metadata": metadata_map,
        }
