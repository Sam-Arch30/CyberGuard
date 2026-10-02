"""
File Security Pipeline Coordinator (Section 8).
Orchestrates static file inspection, cryptographic identity, format verification,
document parsing, script heuristics, PE inspection, archive safety, and hash reputation.
Guarantees canonical persistence across Artifacts, AnalysisRuns, Findings, Evidence,
Indicators, and Relationships with full append-only re-analysis lineage.
"""
from __future__ import annotations

import io
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from sqlalchemy.orm import Session

from backend.db.models import (
    ArtifactModel,
    AnalysisRunModel,
    FindingModel,
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
from backend.services.upload_security import UploadSecurityService
from backend.services.threat_intelligence_service import ThreatIntelligenceService
from backend.services.file_security_analyzers import (
    AnalyzerExecutionResult,
    FileIdentityAnalyzer,
    FilenameSecurityAnalyzer,
    DocumentStaticAnalyzer,
    ExecutableStaticAnalyzer,
    ScriptStaticAnalyzer,
    ArchiveSecurityAnalyzer,
    FileIOCAnalyzer,
    FileReputationAnalyzer,
    FileClassificationService,
    HAS_PILLOW,
)
from backend.schemas.file_security import (
    FileIdentityInfo,
    FilenameSecurityInfo,
    EntropyEvaluation,
    PEMetadata,
    PDFStaticMetadata,
    OfficeStaticMetadata,
    ScriptStaticMetadata,
    ArchiveStaticMetadata,
    ImageStaticMetadata,
    ThreatIntelHashInfo,
    DerivedChildArtifact,
    FileSecurityAnalysisResponse,
)

if HAS_PILLOW:
    from PIL import Image as PILImage
    from PIL.ExifTags import TAGS as EXIF_TAGS

logger = logging.getLogger("cyberguard.file_security_pipeline")


class FileSecurityPipeline:
    """
    Unified Pipeline Coordinator for Static File and Attachment Security.
    Integrates Section 2 Data Model, Section 3 Persistent Storage, and Section 5 Orchestrator.
    """
    PIPELINE_VERSION = "2.0.0"

    MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB max input file
    MAX_RECURSION_DEPTH = 3

    def __init__(self, threat_intel_service: Optional[ThreatIntelligenceService] = None):
        self.threat_intel = threat_intel_service or ThreatIntelligenceService()
        self.identity_analyzer = FileIdentityAnalyzer()
        self.filename_analyzer = FilenameSecurityAnalyzer()
        self.document_analyzer = DocumentStaticAnalyzer()
        self.executable_analyzer = ExecutableStaticAnalyzer()
        self.script_analyzer = ScriptStaticAnalyzer()
        self.archive_analyzer = ArchiveSecurityAnalyzer()
        self.ioc_analyzer = FileIOCAnalyzer()
        self.reputation_analyzer = FileReputationAnalyzer(self.threat_intel)

    async def analyze_file(
        self,
        payload_bytes: bytes,
        filename: str,
        db: Session,
        reported_mime: Optional[str] = None,
        uploader: str = "ANALYST",
        request_id: Optional[str] = None,
        parent_artifact_id: Optional[str] = None,
        recursion_depth: int = 0,
    ) -> FileSecurityAnalysisResponse:
        """
        Executes complete static file investigation and persists canonical records.
        """
        if len(payload_bytes) > self.MAX_FILE_SIZE:
            raise ValueError(f"Payload size ({len(payload_bytes)} bytes) exceeds maximum file limit ({self.MAX_FILE_SIZE} bytes).")

        clean_filename = UploadSecurityService.sanitize_filename(filename or "file.bin")
        sha256_hash, sha1_hash, md5_hash = FileIdentityAnalyzer.calculate_streaming_hashes(payload_bytes)

        # 1. Ingest or Retrieve Artifact
        artifact = db.query(ArtifactModel).filter(
            ArtifactModel.sha256 == sha256_hash,
            ArtifactModel.artifact_type.in_([ArtifactTypeEnum.FILE.value, ArtifactTypeEnum.ATTACHMENT.value]),
        ).first()

        req_id = request_id or generate_uuid("req")

        if not artifact:
            store_res = evidence_storage.store_bytes(
                data=payload_bytes,
                original_filename=clean_filename,
                mime_type=reported_mime or "application/octet-stream",
            )
            artifact = ArtifactModel(
                id=generate_uuid(),
                artifact_type=ArtifactTypeEnum.FILE.value,
                name=clean_filename[:255],
                source="DIRECT_UPLOAD" if not parent_artifact_id else "ARCHIVE_EXTRACTION",
                mime_type=reported_mime or "application/octet-stream",
                size=len(payload_bytes),
                sha256=sha256_hash,
                sha1=sha1_hash,
                md5=md5_hash,
                storage_reference=store_res.storage_key,
                parent_artifact_id=parent_artifact_id,
                created_at=get_utc_now(),
            )
            db.add(artifact)
            db.flush()

            st_rec = ArtifactStorageRecordModel(
                id=generate_uuid("stor"),
                artifact_id=artifact.id,
                storage_key=store_res.storage_key,
                storage_backend="LOCAL",
                sha256=sha256_hash,
                size=len(payload_bytes),
                mime_type=reported_mime or "application/octet-stream",
                original_filename=clean_filename,
                integrity_status="VERIFIED",
            )
            db.add(st_rec)

            ing_rec = IngestionRecordModel(
                id=generate_uuid("ing"),
                artifact_id=artifact.id,
                source="FILE_INPUT",
                submitted_by=uploader,
                original_filename=clean_filename,
                request_id=req_id,
                context_json=json.dumps({"input_mode": "FILE_UPLOAD", "parent_artifact_id": parent_artifact_id}),
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
            trigger=AnalysisTriggerEnum.USER.value if recursion_depth == 0 else AnalysisTriggerEnum.AUTOMATIC.value,
            pipeline_version=self.PIPELINE_VERSION,
            metadata_json=json.dumps({
                "analyzer_name": "file_security_pipeline",
                "analyzer_version": self.PIPELINE_VERSION,
                "original_filename": clean_filename,
                "recursion_depth": recursion_depth,
            }),
            created_at=get_utc_now(),
        )
        db.add(analysis_run)
        db.flush()

        # 3. Modular Analyzer Execution
        analyzer_results: List[AnalyzerExecutionResult] = []

        # Stage 3.1: Identity & Signature Verification
        res_ident, identity_info = self.identity_analyzer.analyze(
            payload_bytes=payload_bytes,
            filename=clean_filename,
            reported_mime=reported_mime,
        )
        analyzer_results.append(res_ident)
        detected_type = identity_info.detected_file_type

        # Stage 3.2: Filename Security & Unicode Deception
        res_fn, filename_info = self.filename_analyzer.analyze(clean_filename)
        analyzer_results.append(res_fn)

        # Stage 3.3: Format-Specific Deep Static Inspection
        pe_metadata: Optional[PEMetadata] = None
        pdf_metadata: Optional[PDFStaticMetadata] = None
        office_metadata: Optional[OfficeStaticMetadata] = None
        script_metadata: Optional[ScriptStaticMetadata] = None
        archive_metadata: Optional[ArchiveStaticMetadata] = None
        image_metadata: Optional[ImageStaticMetadata] = None
        entropy_eval = EntropyEvaluation(
            entropy=ExecutableStaticAnalyzer.calculate_entropy(payload_bytes),
            level="normal",
            description="Evaluated entropy",
            is_high_entropy=False,
        )
        raw_child_entries: List[Dict[str, Any]] = []

        if "PDF" in detected_type or payload_bytes.startswith(b"%PDF-"):
            res_pdf, pdf_metadata = self.document_analyzer.parse_pdf(payload_bytes)
            analyzer_results.append(res_pdf)

        elif "Office" in detected_type or "Word" in detected_type or "Excel" in detected_type or "PowerPoint" in detected_type or "Macro" in detected_type or "OLE" in detected_type:
            res_office, office_metadata = self.document_analyzer.parse_office(payload_bytes, detected_type)
            analyzer_results.append(res_office)

        elif "Windows executable" in detected_type or "DOS Executable" in detected_type or payload_bytes.startswith(b"MZ"):
            res_exe, pe_metadata, entropy_eval = self.executable_analyzer.analyze(payload_bytes)
            analyzer_results.append(res_exe)

        elif "Script" in detected_type or "PowerShell" in detected_type or "Shell Script" in detected_type or "Batch Script" in detected_type:
            text_str = payload_bytes.decode("latin-1", errors="ignore")
            res_script, script_metadata = self.script_analyzer.analyze(text_str, detected_type)
            analyzer_results.append(res_script)

        elif "ZIP Archive" in detected_type or (payload_bytes.startswith(b"PK\x03\x04") and not office_metadata):
            res_arch, archive_metadata, raw_child_entries = self.archive_analyzer.analyze_zip(payload_bytes)
            analyzer_results.append(res_arch)

        elif "Image" in detected_type:
            img_res, image_metadata = self._inspect_image_safely(payload_bytes, detected_type)
            analyzer_results.append(img_res)

        # Stage 3.4: Observable IOC Extraction
        res_iocs, extracted_iocs = self.ioc_analyzer.analyze(payload_bytes)
        analyzer_results.append(res_iocs)

        # Merge URLs from deep format parsers into extracted_urls
        all_urls = list(extracted_iocs.get("urls", []))
        if pdf_metadata and pdf_metadata.external_uris:
            for u in pdf_metadata.external_uris:
                if u not in all_urls:
                    all_urls.append(u)
        if office_metadata and office_metadata.external_relationships:
            for u in office_metadata.external_relationships:
                if u not in all_urls:
                    all_urls.append(u)

        # Stage 3.5: Hash Reputation Lookup (Privacy-Preserving, NO MATCH != SAFE)
        res_rep, reputation_info = await self.reputation_analyzer.analyze(
            sha256=sha256_hash, sha1=sha1_hash, md5=md5_hash
        )
        analyzer_results.append(res_rep)

        # 4. Aggregation and Classification
        all_findings = []
        for a_res in analyzer_results:
            all_findings.extend(a_res.findings)

        classification, risk_score, overall_sev, confidence, summary = FileClassificationService.classify(
            findings=all_findings,
            hash_reputation=reputation_info,
            detected_type=detected_type,
        )

        # 5. Process and Register Derived Child Artifacts from Archive
        derived_child_models: List[DerivedChildArtifact] = []
        if raw_child_entries and recursion_depth < self.MAX_RECURSION_DEPTH:
            for entry in raw_child_entries:
                try:
                    c_name = entry["filename"]
                    c_bytes = entry["bytes"]
                    c_sha = entry["sha256"]

                    # Check or store child artifact
                    child_art = db.query(ArtifactModel).filter(
                        ArtifactModel.sha256 == c_sha,
                        ArtifactModel.artifact_type.in_([ArtifactTypeEnum.FILE.value, ArtifactTypeEnum.ATTACHMENT.value]),
                    ).first()

                    if not child_art:
                        c_store_res = evidence_storage.store_bytes(
                            data=c_bytes,
                            original_filename=c_name,
                            mime_type="application/octet-stream",
                        )
                        child_art = ArtifactModel(
                            id=generate_uuid(),
                            artifact_type=ArtifactTypeEnum.ATTACHMENT.value,
                            name=c_name[:255],
                            source="ARCHIVE_EXTRACTION",
                            mime_type=c_store_res.mime_type,
                            size=len(c_bytes),
                            sha256=c_sha,
                            storage_reference=c_store_res.storage_key,
                            parent_artifact_id=artifact.id,
                            created_at=get_utc_now(),
                        )
                        db.add(child_art)
                        db.flush()

                        db.add(ArtifactStorageRecordModel(
                            id=generate_uuid("stor"),
                            artifact_id=child_art.id,
                            storage_key=c_store_res.storage_key,
                            storage_backend="LOCAL",
                            sha256=c_sha,
                            size=len(c_bytes),
                            mime_type=c_store_res.mime_type,
                            original_filename=c_name,
                            integrity_status="VERIFIED",
                        ))
                        db.add(IngestionRecordModel(
                            id=generate_uuid("ing"),
                            artifact_id=child_art.id,
                            source="ARCHIVE_CHILD",
                            submitted_by=uploader,
                            original_filename=c_name,
                            request_id=req_id,
                            context_json=json.dumps({"parent_artifact_id": artifact.id}),
                            metadata_json="{}",
                        ))
                        db.flush()

                    # Create Relationship: ARCHIVE CONTAINS CHILD
                    rel_exists = db.query(RelationshipModel).filter(
                        RelationshipModel.source_id == artifact.id,
                        RelationshipModel.target_id == child_art.id,
                        RelationshipModel.relationship_type == RelationshipTypeEnum.CONTAINS.value,
                    ).first()

                    if not rel_exists:
                        db.add(RelationshipModel(
                            id=generate_uuid(),
                            source_id=artifact.id,
                            source_type="ARTIFACT",
                            target_id=child_art.id,
                            target_type="ARTIFACT",
                            relationship_type=RelationshipTypeEnum.CONTAINS.value,
                            confidence=1.0,
                            method="DETERMINISTIC",
                            created_at=get_utc_now(),
                        ))

                    derived_child_models.append(DerivedChildArtifact(
                        artifact_id=child_art.id,
                        name=c_name,
                        artifact_type="ATTACHMENT",
                        mime_type=child_art.mime_type,
                        size_bytes=len(c_bytes),
                        sha256=c_sha,
                        source="ARCHIVE_EXTRACTION",
                        relationship_type="CONTAINS",
                    ))
                except Exception as child_err:
                    logger.error(f"Error registering derived child entry '{entry.get('filename')}': {child_err}")

        # 6. Canonical Database Persistence
        self._persist_canonical_records(
            db=db,
            artifact=artifact,
            analysis_run=analysis_run,
            analyzer_results=analyzer_results,
            overall_score=risk_score,
            overall_sev=overall_sev.value,
            confidence=confidence,
            classification=classification,
            summary=summary,
            sha256_hash=sha256_hash,
            all_urls=all_urls,
            all_domains=extracted_iocs.get("domains", []),
            all_ips=extracted_iocs.get("ips", []),
        )

        db.commit()

        # 7. Build Canonical Response
        findings_payload = [
            {
                "title": f["title"],
                "description": f["description"],
                "finding_type": f["finding_type"],
                "severity": f["severity"].value if isinstance(f["severity"], SeverityEnum) else str(f["severity"]),
                "confidence": f.get("confidence", 1.0),
                "method": f.get("method").value if isinstance(f.get("method"), FindingMethodEnum) else str(f.get("method", "DETERMINISTIC")),
                "mitre_technique_id": f.get("mitre_technique_id"),
                "remediation": f.get("remediation"),
            }
            for f in all_findings
        ]

        total_ind_count = db.query(IndicatorModel).count()
        total_rel_count = db.query(RelationshipModel).filter(
            (RelationshipModel.source_id == artifact.id) | (RelationshipModel.target_id == artifact.id)
        ).count()

        return FileSecurityAnalysisResponse(
            artifact_id=artifact.id,
            analysis_run_id=analysis_run.id,
            pipeline_version=self.PIPELINE_VERSION,
            classification=classification,
            risk_score=risk_score,
            severity=overall_sev.value,
            confidence=confidence,
            summary=summary,
            identity=identity_info,
            filename_analysis=filename_info,
            entropy=entropy_eval,
            pe_metadata=pe_metadata,
            pdf_metadata=pdf_metadata,
            office_metadata=office_metadata,
            script_metadata=script_metadata,
            archive_metadata=archive_metadata,
            image_metadata=image_metadata,
            reputation=reputation_info,
            extracted_urls=all_urls,
            extracted_domains=extracted_iocs.get("domains", []),
            extracted_ips=extracted_iocs.get("ips", []),
            extracted_emails=extracted_iocs.get("emails", []),
            extracted_hashes=extracted_iocs.get("hashes", []),
            derived_artifacts=derived_child_models,
            findings_count=len(all_findings),
            findings=findings_payload,
            indicators_count=total_ind_count,
            relationships_count=total_rel_count,
            status=AnalysisStatusEnum.COMPLETED.value,
            created_at=get_utc_now().isoformat(),
        )

    async def reanalyze_artifact(
        self,
        artifact_id: str,
        db: Session,
        uploader: str = "ANALYST",
    ) -> FileSecurityAnalysisResponse:
        """
        Re-analyzes an existing durable artifact loaded directly from storage.
        Always creates a new independent AnalysisRunModel record preserving historical observation lineage.
        """
        artifact = db.query(ArtifactModel).filter(ArtifactModel.id == artifact_id).first()
        if not artifact:
            raise ValueError(f"Artifact not found: {artifact_id}")

        storage_key = artifact.storage_reference or artifact.sha256
        content_bytes = evidence_storage.retrieve_bytes(storage_key)
        if not content_bytes:
            raise ValueError(f"Artifact content unretrievable for reference: {storage_key}")

        return await self.analyze_file(
            payload_bytes=content_bytes,
            filename=artifact.name,
            db=db,
            reported_mime=artifact.mime_type,
            uploader=uploader,
            parent_artifact_id=artifact.parent_artifact_id,
        )

    def _inspect_image_safely(self, payload: bytes, detected_type: str) -> Tuple[AnalyzerExecutionResult, ImageStaticMetadata]:
        result = AnalyzerExecutionResult("image_static_analyzer", self.PIPELINE_VERSION)
        width = None
        height = None
        color_mode = None
        has_exif = False
        exif_fields: Dict[str, str] = {}
        warnings: List[str] = []

        if HAS_PILLOW:
            try:
                with PILImage.open(io.BytesIO(payload)) as img:
                    width, height = img.size
                    color_mode = img.mode

                    raw_exif = getattr(img, "_getexif", lambda: None)()
                    if raw_exif:
                        has_exif = True
                        for tag_id, value in raw_exif.items():
                            tag_name = EXIF_TAGS.get(tag_id, f"Tag_{tag_id}")
                            # Keep basic string or numeric properties safely
                            if isinstance(value, (str, int, float)):
                                exif_fields[str(tag_name)] = str(value)[:100]
                            if len(exif_fields) >= 15:
                                break
            except Exception as e:
                warnings.append(f"Image parsing warning: {str(e)}")

        img_meta = ImageStaticMetadata(
            is_image=True,
            image_format=detected_type.split()[0],
            width=width,
            height=height,
            color_mode=color_mode,
            has_exif=has_exif,
            exif_fields=exif_fields,
            warnings=warnings,
        )
        return result, img_meta

    def _persist_canonical_records(
        self,
        db: Session,
        artifact: ArtifactModel,
        analysis_run: AnalysisRunModel,
        analyzer_results: List[AnalyzerExecutionResult],
        overall_score: float,
        overall_sev: str,
        confidence: float,
        classification: str,
        summary: str,
        sha256_hash: str,
        all_urls: List[str],
        all_domains: List[str],
        all_ips: List[str],
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

                    val_str = e_dict.get("raw_content") or json.dumps(e_dict.get("parsed_content") or {}) or e_dict.get("evidence_type", "")

                    ev_model = FindingEvidenceModel(
                        id=generate_uuid(),
                        finding_id=f_m.id,
                        artifact_id=artifact.id,
                        source=e_dict.get("source", "FILE_ANALYZER")[:100],
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

            # Persist unlinked evidence items to first finding if any
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
                        source=e_dict.get("source", "FILE_ANALYZER")[:100],
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

        # Graph Edge: ATTACHMENT/FILE - HAS_HASH -> Indicator (SHA-256)
        hash_rel_exists = db.query(RelationshipModel).filter(
            RelationshipModel.source_id == artifact.id,
            RelationshipModel.target_id == sha256_hash,
            RelationshipModel.relationship_type == RelationshipTypeEnum.HAS_HASH.value,
        ).first()

        if not hash_rel_exists:
            db.add(RelationshipModel(
                id=generate_uuid(),
                source_id=artifact.id,
                source_type="ARTIFACT",
                target_id=sha256_hash,
                target_type="INDICATOR",
                relationship_type=RelationshipTypeEnum.HAS_HASH.value,
                confidence=1.0,
                method="DETERMINISTIC",
                created_at=get_utc_now(),
            ))

        # Graph Edges for Embedded URLs
        for u in all_urls:
            url_norm = normalize_url(u)
            url_rel_exists = db.query(RelationshipModel).filter(
                RelationshipModel.source_id == artifact.id,
                RelationshipModel.target_id == url_norm,
                RelationshipModel.relationship_type == RelationshipTypeEnum.REFERENCES.value,
            ).first()
            if not url_rel_exists:
                db.add(RelationshipModel(
                    id=generate_uuid(),
                    source_id=artifact.id,
                    source_type="ARTIFACT",
                    target_id=url_norm,
                    target_type="INDICATOR",
                    relationship_type=RelationshipTypeEnum.REFERENCES.value,
                    confidence=1.0,
                    method="DETERMINISTIC",
                    created_at=get_utc_now(),
                ))

        # ThreatEvent generation if high/critical severity or malware suspected/known
        if overall_sev in (SeverityEnum.HIGH.value, SeverityEnum.CRITICAL.value) or classification in ("KNOWN_MALICIOUS", "MALWARE_SUSPECTED"):
            event_type = "KNOWN_MALWARE_ATTACHMENT" if classification == "KNOWN_MALICIOUS" else "SUSPICIOUS_FILE_DELIVERY"
            db.add(ThreatEventModel(
                id=generate_uuid(),
                event_type=event_type,
                timestamp=get_utc_now(),
                source="FILE_SECURITY_PIPELINE",
                severity=overall_sev,
                description=summary,
                artifact_id=artifact.id,
                analysis_run_id=analysis_run.id,
                event_data_json=json.dumps({
                    "sha256": sha256_hash,
                    "filename": artifact.name,
                    "classification": classification,
                    "risk_score": overall_score,
                }),
                created_at=get_utc_now(),
            ))

        # Update AnalysisRun record
        analysis_run.status = AnalysisStatusEnum.COMPLETED.value
        analysis_run.completed_at = get_utc_now()
        analysis_run.summary = summary
        analysis_run.metadata_json = json.dumps({
            "analyzer_name": "file_security_pipeline",
            "analyzer_version": self.PIPELINE_VERSION,
            "classification": classification,
            "overall_score": overall_score,
            "overall_severity": overall_sev,
            "confidence": confidence,
            "findings_count": len(created_findings),
        })
