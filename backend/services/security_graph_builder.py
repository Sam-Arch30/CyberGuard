"""
Security Knowledge Graph Builder (Section 14).
Ingests normalized forensic evidence produced across detection engines (Sections 6–13)
into the canonical Security Knowledge Graph with strict idempotency, provenance, and direction.
"""
from datetime import datetime, timezone
import json
import logging
import urllib.parse
from typing import Any, Dict, List, Optional, Set, Union

from sqlalchemy.orm import Session

from backend.db.models import (
    EntityModel,
    RelationshipModel,
    ArtifactModel,
    AnalysisRunModel,
    FindingEvidenceModel,
    FindingModel,
    get_utc_now,
)
from backend.schemas.knowledge_graph import (
    GraphEntityType,
    GraphRelationshipType,
    RelationshipOrigin,
    RelationshipStatus,
    GraphBuildResponse,
    make_canonical_key,
    sanitize_graph_attributes,
)
from backend.services.security_graph_service import SecurityGraphService, global_security_graph_service

logger = logging.getLogger("cyberguard.graph_builder")


class SecurityGraphBuilder:
    """
    Consumes normalized pipeline outputs from Analyzers and persists them
    into the canonical Security Knowledge Graph.
    Ensures that observation history is preserved across re-analysis runs.
    """

    def __init__(self, graph_service: Optional[SecurityGraphService] = None):
        self.graph_service = graph_service or global_security_graph_service

    # =========================================================================
    # 1. EMAIL INTELLIGENCE (SECTION 6)
    # =========================================================================

    def ingest_email_analysis(
        self,
        db: Session,
        email_analysis: Dict[str, Any],
        artifact_id: Optional[str] = None,
        analysis_run_id: Optional[str] = None,
        incident_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
    ) -> GraphBuildResponse:
        """Ingests email analysis results into the Security Knowledge Graph."""
        if not email_analysis:
            return GraphBuildResponse()

        ent_created = 0
        ent_updated = 0
        rel_created = 0
        rel_updated = 0
        obs_created = 0

        now = get_utc_now()
        sha256 = email_analysis.get("email_sha256") or email_analysis.get("sha256") or ""
        email_id = str(email_analysis.get("id") or sha256 or "email-root")
        subject = email_analysis.get("subject") or "Analyzed Email"

        # 1. Root EMAIL Entity
        email_ent = self.graph_service.upsert_canonical_entity(
            db=db,
            entity_type=GraphEntityType.EMAIL,
            value=sha256 if sha256 else email_id,
            display_value=f"Email: {subject[:60]}",
            attributes={
                "subject": subject,
                "sha256": sha256,
                "date": email_analysis.get("date"),
                "threat_score": email_analysis.get("threat_score"),
            },
            timestamp=now,
            workspace_id=workspace_id,
        )

        # 2. Sender (From) & Domain
        from_header = email_analysis.get("from_header") or email_analysis.get("from")
        if from_header:
            from_clean = str(from_header).strip()
            # Extract plain email if format is 'Name <user@domain.com>'
            if "<" in from_clean and ">" in from_clean:
                from_addr = from_clean.split("<")[1].split(">")[0].strip()
            else:
                from_addr = from_clean

            if "@" in from_addr:
                sender_ent = self.graph_service.upsert_canonical_entity(
                    db=db,
                    entity_type=GraphEntityType.EMAIL_ADDRESS,
                    value=from_addr,
                    display_value=from_addr,
                    attributes={"role": "sender", "raw_header": from_clean},
                    timestamp=now,
                    workspace_id=workspace_id,
                )
                rel, obs = self.graph_service.record_relationship(
                    db=db,
                    source_id=email_ent.id,
                    target_id=sender_ent.id,
                    relationship_type=GraphRelationshipType.CONTAINS,
                    origin=RelationshipOrigin.OBSERVED,
                    confidence=1.0,
                    source_artifact_id=artifact_id,
                    analysis_run_id=analysis_run_id,
                    analyzer="EmailIntelligenceEngine",
                    evidence_reference="From header parsing",
                    workspace_id=workspace_id,
                )

                # Sender Domain
                sender_domain = from_addr.split("@")[-1].lower()
                dom_ent = self.graph_service.upsert_canonical_entity(
                    db=db,
                    entity_type=GraphEntityType.DOMAIN,
                    value=sender_domain,
                    display_value=sender_domain,
                    timestamp=now,
                    workspace_id=workspace_id,
                )
                self.graph_service.record_relationship(
                    db=db,
                    source_id=sender_ent.id,
                    target_id=dom_ent.id,
                    relationship_type=GraphRelationshipType.BELONGS_TO,
                    origin=RelationshipOrigin.DERIVED,
                    confidence=1.0,
                    source_artifact_id=artifact_id,
                    analysis_run_id=analysis_run_id,
                    analyzer="EmailIntelligenceEngine",
                    evidence_reference="Sender address domain decomposition",
                    workspace_id=workspace_id,
                )

        # 3. Recipients (To)
        to_data = email_analysis.get("to") or []
        to_list = to_data if isinstance(to_data, list) else [to_data]
        for rcpt in to_list:
            rcpt_clean = str(rcpt).strip()
            if "<" in rcpt_clean and ">" in rcpt_clean:
                rcpt_addr = rcpt_clean.split("<")[1].split(">")[0].strip()
            else:
                rcpt_addr = rcpt_clean

            if "@" in rcpt_addr:
                rcpt_ent = self.graph_service.upsert_canonical_entity(
                    db=db,
                    entity_type=GraphEntityType.EMAIL_ADDRESS,
                    value=rcpt_addr,
                    display_value=rcpt_addr,
                    attributes={"role": "recipient"},
                    timestamp=now,
                    workspace_id=workspace_id,
                )
                self.graph_service.record_relationship(
                    db=db,
                    source_id=email_ent.id,
                    target_id=rcpt_ent.id,
                    relationship_type=GraphRelationshipType.CONTAINS,
                    origin=RelationshipOrigin.OBSERVED,
                    confidence=1.0,
                    source_artifact_id=artifact_id,
                    analysis_run_id=analysis_run_id,
                    analyzer="EmailIntelligenceEngine",
                    evidence_reference="To header parsing",
                    workspace_id=workspace_id,
                )

        # 4. URLs & Domains
        urls = email_analysis.get("urls") or []
        for u in urls:
            u_str = u.get("url") if isinstance(u, dict) else str(u)
            clean_u = u_str.strip()
            if not clean_u:
                continue

            url_ent = self.graph_service.upsert_canonical_entity(
                db=db,
                entity_type=GraphEntityType.URL,
                value=clean_u,
                display_value=clean_u[:50],
                timestamp=now,
                workspace_id=workspace_id,
            )
            self.graph_service.record_relationship(
                db=db,
                source_id=email_ent.id,
                target_id=url_ent.id,
                relationship_type=GraphRelationshipType.CONTAINS,
                origin=RelationshipOrigin.OBSERVED,
                confidence=1.0,
                source_artifact_id=artifact_id,
                analysis_run_id=analysis_run_id,
                analyzer="EmailParser",
                evidence_reference="URL extracted from email body",
                workspace_id=workspace_id,
            )

            # URL HAS_HOST Domain
            try:
                parsed = urllib.parse.urlsplit(clean_u)
                host = parsed.netloc.split(":")[0].lower() if parsed.netloc else ""
                if host:
                    dom_ent = self.graph_service.upsert_canonical_entity(
                        db=db,
                        entity_type=GraphEntityType.DOMAIN,
                        value=host,
                        display_value=host,
                        timestamp=now,
                        workspace_id=workspace_id,
                    )
                    self.graph_service.record_relationship(
                        db=db,
                        source_id=url_ent.id,
                        target_id=dom_ent.id,
                        relationship_type=GraphRelationshipType.HAS_HOST,
                        origin=RelationshipOrigin.DERIVED,
                        confidence=1.0,
                        source_artifact_id=artifact_id,
                        analysis_run_id=analysis_run_id,
                        analyzer="UrlAnalyzer",
                        evidence_reference="Hostname parsed from URL",
                        workspace_id=workspace_id,
                    )
            except Exception:
                pass

        # 5. Domain Intelligence DNS -> IP Records
        dom_intel = email_analysis.get("domain_intelligence") or {}
        if isinstance(dom_intel, dict):
            for d_name, d_info in dom_intel.items():
                clean_d = d_name.strip().lower()
                dom_ent = self.graph_service.upsert_canonical_entity(
                    db=db,
                    entity_type=GraphEntityType.DOMAIN,
                    value=clean_d,
                    display_value=clean_d,
                    attributes={"domain_age_days": d_info.get("domain_age_days")},
                    timestamp=now,
                    workspace_id=workspace_id,
                )

                # DNS A/AAAA IPs
                dns_info = d_info.get("dns") or {}
                a_records = (dns_info.get("a") or []) + (dns_info.get("aaaa") or [])
                for ip in a_records:
                    if ip:
                        clean_ip = str(ip).strip()
                        ip_ent = self.graph_service.upsert_canonical_entity(
                            db=db,
                            entity_type=GraphEntityType.IP,
                            value=clean_ip,
                            display_value=clean_ip,
                            timestamp=now,
                            workspace_id=workspace_id,
                        )
                        self.graph_service.record_relationship(
                            db=db,
                            source_id=dom_ent.id,
                            target_id=ip_ent.id,
                            relationship_type=GraphRelationshipType.RESOLVES_TO,
                            origin=RelationshipOrigin.OBSERVED,
                            confidence=0.95,
                            source_artifact_id=artifact_id,
                            analysis_run_id=analysis_run_id,
                            analyzer="DnsTelemetryEngine",
                            evidence_reference=f"DNS resolution record for {clean_d}",
                            workspace_id=workspace_id,
                        )

        # 6. Attachments -> Hashes
        attachments = email_analysis.get("attachments") or []
        for att in attachments:
            fname = att.get("filename") or "unnamed_file"
            att_sha = att.get("sha256") or ""
            file_ent = self.graph_service.upsert_canonical_entity(
                db=db,
                entity_type=GraphEntityType.FILE,
                value=att_sha if att_sha else fname,
                display_value=fname,
                attributes={
                    "filename": fname,
                    "mime_type": att.get("mime_type"),
                    "size": att.get("size"),
                },
                timestamp=now,
                workspace_id=workspace_id,
            )
            self.graph_service.record_relationship(
                db=db,
                source_id=email_ent.id,
                target_id=file_ent.id,
                relationship_type=GraphRelationshipType.CONTAINS,
                origin=RelationshipOrigin.OBSERVED,
                confidence=1.0,
                source_artifact_id=artifact_id,
                analysis_run_id=analysis_run_id,
                analyzer="EmailAttachmentExtractor",
                evidence_reference=f"MIME multipart part: {fname}",
                workspace_id=workspace_id,
            )

            # FILE HAS_HASH HASH
            if att_sha:
                hash_ent = self.graph_service.upsert_canonical_entity(
                    db=db,
                    entity_type=GraphEntityType.HASH,
                    value=att_sha,
                    display_value=f"SHA256:{att_sha[:8]}...",
                    attributes={"algorithm": "SHA-256", "hash": att_sha},
                    timestamp=now,
                    workspace_id=workspace_id,
                )
                self.graph_service.record_relationship(
                    db=db,
                    source_id=file_ent.id,
                    target_id=hash_ent.id,
                    relationship_type=GraphRelationshipType.HAS_HASH,
                    origin=RelationshipOrigin.DERIVED,
                    confidence=1.0,
                    source_artifact_id=artifact_id,
                    analysis_run_id=analysis_run_id,
                    analyzer="CryptographicHasher",
                    evidence_reference="Cryptographic SHA-256 digest calculation",
                    workspace_id=workspace_id,
                )

        # 7. Impersonation / Lookalike domains
        lookalikes = email_analysis.get("lookalike_domains") or []
        for lk in lookalikes:
            suspect = (lk.get("domain") or "").strip().lower()
            brand = (lk.get("suspected_brand") or lk.get("brand_name") or "").strip().lower()
            if suspect and brand:
                s_dom = self.graph_service.upsert_canonical_entity(
                    db=db, entity_type=GraphEntityType.DOMAIN, value=suspect, display_value=suspect, workspace_id=workspace_id
                )
                b_dom = self.graph_service.upsert_canonical_entity(
                    db=db, entity_type=GraphEntityType.DOMAIN, value=brand, display_value=brand, workspace_id=workspace_id
                )
                self.graph_service.record_relationship(
                    db=db,
                    source_id=s_dom.id,
                    target_id=b_dom.id,
                    relationship_type=GraphRelationshipType.LOOKALIKE_OF,
                    origin=RelationshipOrigin.DERIVED,
                    confidence=float(lk.get("similarity", 0.9)),
                    source_artifact_id=artifact_id,
                    analysis_run_id=analysis_run_id,
                    analyzer="LookalikeDetector",
                    evidence_reference=f"Confusable distance metric: {lk.get('similarity')}",
                    workspace_id=workspace_id,
                )

        # 8. Incident Linkage
        if incident_id:
            self.graph_service.record_relationship(
                db=db,
                source_id=email_ent.id,
                target_id=incident_id,
                relationship_type=GraphRelationshipType.OBSERVED_IN,
                origin=RelationshipOrigin.OBSERVED,
                confidence=1.0,
                source_artifact_id=artifact_id,
                analysis_run_id=analysis_run_id,
                analyzer="IncidentManager",
                evidence_reference="Evidentiary artifact assigned to investigation",
                workspace_id=workspace_id,
            )

        db.commit()
        return GraphBuildResponse(
            entities_created=ent_created,
            entities_updated=ent_updated,
            relationships_created=rel_created,
            relationships_updated=rel_updated,
            observations_created=obs_created,
        )

    # =========================================================================
    # 2. FILE & ATTACHMENT INTELLIGENCE (SECTION 8)
    # =========================================================================

    def ingest_file_analysis(
        self,
        db: Session,
        file_data: Dict[str, Any],
        artifact_id: Optional[str] = None,
        analysis_run_id: Optional[str] = None,
        incident_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
    ) -> GraphBuildResponse:
        """Ingests file analysis and embedded artifact chains."""
        if not file_data:
            return GraphBuildResponse()

        now = get_utc_now()
        fname = file_data.get("filename") or "analyzed_file"
        sha256 = file_data.get("sha256") or ""
        val = sha256 if sha256 else fname

        parent_file_ent = self.graph_service.upsert_canonical_entity(
            db=db,
            entity_type=GraphEntityType.FILE,
            value=val,
            display_value=fname,
            attributes=file_data,
            timestamp=now,
            workspace_id=workspace_id,
        )

        # Hashes
        if sha256:
            hash_ent = self.graph_service.upsert_canonical_entity(
                db=db,
                entity_type=GraphEntityType.HASH,
                value=sha256,
                display_value=f"SHA256:{sha256[:8]}...",
                attributes={"algorithm": "SHA-256", "hash": sha256},
                timestamp=now,
                workspace_id=workspace_id,
            )
            self.graph_service.record_relationship(
                db=db,
                source_id=parent_file_ent.id,
                target_id=hash_ent.id,
                relationship_type=GraphRelationshipType.HAS_HASH,
                origin=RelationshipOrigin.DERIVED,
                confidence=1.0,
                source_artifact_id=artifact_id,
                analysis_run_id=analysis_run_id,
                analyzer="CryptographicHasher",
                evidence_reference="SHA-256 hash calculation",
                workspace_id=workspace_id,
            )

        # Embedded files (e.g. ZIP containing PDF)
        extracted_files = file_data.get("extracted_files") or []
        for ext in extracted_files:
            c_name = ext.get("filename") or "embedded_file"
            c_sha = ext.get("sha256") or ""
            child_ent = self.graph_service.upsert_canonical_entity(
                db=db,
                entity_type=GraphEntityType.FILE,
                value=c_sha if c_sha else c_name,
                display_value=c_name,
                attributes=ext,
                timestamp=now,
                workspace_id=workspace_id,
            )
            self.graph_service.record_relationship(
                db=db,
                source_id=parent_file_ent.id,
                target_id=child_ent.id,
                relationship_type=GraphRelationshipType.CONTAINS,
                origin=RelationshipOrigin.OBSERVED,
                confidence=1.0,
                source_artifact_id=artifact_id,
                analysis_run_id=analysis_run_id,
                analyzer="ArchiveExtractor",
                evidence_reference=f"Extracted archive entry: {c_name}",
                workspace_id=workspace_id,
            )

        # Embedded URLs
        embedded_urls = file_data.get("embedded_urls") or []
        for eu in embedded_urls:
            clean_eu = str(eu).strip()
            if not clean_eu:
                continue
            u_ent = self.graph_service.upsert_canonical_entity(
                db=db, entity_type=GraphEntityType.URL, value=clean_eu, display_value=clean_eu[:50], workspace_id=workspace_id
            )
            self.graph_service.record_relationship(
                db=db,
                source_id=parent_file_ent.id,
                target_id=u_ent.id,
                relationship_type=GraphRelationshipType.REFERENCES,
                origin=RelationshipOrigin.OBSERVED,
                confidence=1.0,
                source_artifact_id=artifact_id,
                analysis_run_id=analysis_run_id,
                analyzer="FileContentParser",
                evidence_reference="URL string extracted from file content",
                workspace_id=workspace_id,
            )
            # URL HAS_HOST Domain
            try:
                parsed = urllib.parse.urlsplit(clean_eu)
                h = parsed.netloc.split(":")[0].lower() if parsed.netloc else ""
                if h:
                    dom_ent = self.graph_service.upsert_canonical_entity(
                        db=db, entity_type=GraphEntityType.DOMAIN, value=h, display_value=h, workspace_id=workspace_id
                    )
                    self.graph_service.record_relationship(
                        db=db,
                        source_id=u_ent.id,
                        target_id=dom_ent.id,
                        relationship_type=GraphRelationshipType.HAS_HOST,
                        origin=RelationshipOrigin.DERIVED,
                        confidence=1.0,
                        source_artifact_id=artifact_id,
                        analysis_run_id=analysis_run_id,
                        analyzer="UrlAnalyzer",
                        evidence_reference="Extracted URL hostname component",
                        workspace_id=workspace_id,
                    )
            except Exception:
                pass

        db.commit()
        return GraphBuildResponse()

    # =========================================================================
    # 3. AUTHENTICATION & ATO INTELLIGENCE (SECTION 9)
    # =========================================================================

    def ingest_auth_event(
        self,
        db: Session,
        event: Dict[str, Any],
        artifact_id: Optional[str] = None,
        analysis_run_id: Optional[str] = None,
        incident_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
    ) -> GraphBuildResponse:
        """Ingests authentication events into the Knowledge Graph."""
        if not event:
            return GraphBuildResponse()

        now = get_utc_now()
        user_or_account = event.get("account_id") or event.get("user_id") or event.get("username")
        provider = event.get("provider") or event.get("idp") or "corporate_idp"

        if not user_or_account:
            return GraphBuildResponse()

        # Context-sensitive ACCOUNT entity
        acc_ent = self.graph_service.upsert_canonical_entity(
            db=db,
            entity_type=GraphEntityType.ACCOUNT,
            value=user_or_account,
            context=provider,
            display_value=f"{user_or_account} ({provider})",
            timestamp=now,
            workspace_id=workspace_id,
        )

        # Source IP -> ACCOUNT AUTHENTICATED_FROM IP
        src_ip = event.get("source_ip") or event.get("ip")
        if src_ip:
            clean_ip = str(src_ip).strip()
            ip_ent = self.graph_service.upsert_canonical_entity(
                db=db, entity_type=GraphEntityType.IP, value=clean_ip, display_value=clean_ip, workspace_id=workspace_id
            )
            self.graph_service.record_relationship(
                db=db,
                source_id=acc_ent.id,
                target_id=ip_ent.id,
                relationship_type=GraphRelationshipType.AUTHENTICATED_FROM,
                origin=RelationshipOrigin.OBSERVED,
                confidence=1.0,
                source_artifact_id=artifact_id,
                analysis_run_id=analysis_run_id,
                analyzer="AuthenticationSecurityEngine",
                evidence_reference=f"Auth event from IP {clean_ip}",
                workspace_id=workspace_id,
            )

        # Device -> ACCOUNT USED_DEVICE DEVICE
        device_id = event.get("device_id") or event.get("device")
        if device_id:
            dev_ent = self.graph_service.upsert_canonical_entity(
                db=db,
                entity_type=GraphEntityType.DEVICE,
                value=str(device_id),
                context=provider,
                display_value=f"Device: {device_id}",
                workspace_id=workspace_id,
            )
            self.graph_service.record_relationship(
                db=db,
                source_id=acc_ent.id,
                target_id=dev_ent.id,
                relationship_type=GraphRelationshipType.USED_DEVICE,
                origin=RelationshipOrigin.OBSERVED,
                confidence=1.0,
                source_artifact_id=artifact_id,
                analysis_run_id=analysis_run_id,
                analyzer="AuthenticationSecurityEngine",
                evidence_reference=f"Device telemetry identifier {device_id}",
                workspace_id=workspace_id,
            )

        # Session -> ACCOUNT HAS_SESSION SESSION
        session_id = event.get("session_id")
        if session_id:
            sess_ent = self.graph_service.upsert_canonical_entity(
                db=db,
                entity_type=GraphEntityType.SESSION,
                value=str(session_id),
                context=provider,
                display_value=f"Session: {str(session_id)[:16]}...",
                workspace_id=workspace_id,
            )
            self.graph_service.record_relationship(
                db=db,
                source_id=acc_ent.id,
                target_id=sess_ent.id,
                relationship_type=GraphRelationshipType.HAS_SESSION,
                origin=RelationshipOrigin.OBSERVED,
                confidence=1.0,
                source_artifact_id=artifact_id,
                analysis_run_id=analysis_run_id,
                analyzer="AuthenticationSecurityEngine",
                evidence_reference="Session established by authentication",
                workspace_id=workspace_id,
            )
            if src_ip:
                self.graph_service.record_relationship(
                    db=db,
                    source_id=sess_ent.id,
                    target_id=ip_ent.id,
                    relationship_type=GraphRelationshipType.ORIGINATED_FROM,
                    origin=RelationshipOrigin.OBSERVED,
                    confidence=1.0,
                    source_artifact_id=artifact_id,
                    analysis_run_id=analysis_run_id,
                    analyzer="AuthenticationSecurityEngine",
                    evidence_reference=f"Session ingress IP {src_ip}",
                    workspace_id=workspace_id,
                )

        db.commit()
        return GraphBuildResponse()

    # =========================================================================
    # 4. NETWORK & TRAFFIC ANOMALY INTELLIGENCE (SECTION 10)
    # =========================================================================

    def ingest_network_event(
        self,
        db: Session,
        event: Dict[str, Any],
        artifact_id: Optional[str] = None,
        analysis_run_id: Optional[str] = None,
        incident_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
    ) -> GraphBuildResponse:
        """Ingests network flow events into the Knowledge Graph."""
        if not event:
            return GraphBuildResponse()

        now = get_utc_now()
        device_id = event.get("device_id") or event.get("host_name") or event.get("source_ip")
        if not device_id:
            return GraphBuildResponse()

        dev_ent = self.graph_service.upsert_canonical_entity(
            db=db,
            entity_type=GraphEntityType.DEVICE,
            value=str(device_id),
            context=event.get("network_zone", "internal"),
            display_value=f"Device: {device_id}",
            timestamp=now,
            workspace_id=workspace_id,
        )

        # Destination IP -> DEVICE CONNECTS_TO IP
        dst_ip = event.get("destination_ip")
        if dst_ip:
            clean_dst = str(dst_ip).strip()
            ip_ent = self.graph_service.upsert_canonical_entity(
                db=db, entity_type=GraphEntityType.IP, value=clean_dst, display_value=clean_dst, workspace_id=workspace_id
            )
            self.graph_service.record_relationship(
                db=db,
                source_id=dev_ent.id,
                target_id=ip_ent.id,
                relationship_type=GraphRelationshipType.CONNECTS_TO,
                origin=RelationshipOrigin.OBSERVED,
                confidence=1.0,
                source_artifact_id=artifact_id,
                analysis_run_id=analysis_run_id,
                analyzer="NetworkSecurityPipeline",
                evidence_reference=f"Network flow to port {event.get('destination_port', 'unknown')}",
                workspace_id=workspace_id,
            )

        # Domain query / communication
        domain_val = event.get("domain") or event.get("dns_query")
        if domain_val:
            clean_dom = str(domain_val).strip().lower()
            dom_ent = self.graph_service.upsert_canonical_entity(
                db=db, entity_type=GraphEntityType.DOMAIN, value=clean_dom, display_value=clean_dom, workspace_id=workspace_id
            )
            self.graph_service.record_relationship(
                db=db,
                source_id=dev_ent.id,
                target_id=dom_ent.id,
                relationship_type=GraphRelationshipType.COMMUNICATES_WITH,
                origin=RelationshipOrigin.OBSERVED,
                confidence=1.0,
                source_artifact_id=artifact_id,
                analysis_run_id=analysis_run_id,
                analyzer="DnsTelemetryEngine",
                evidence_reference=f"DNS query / TLS SNI to {clean_dom}",
                workspace_id=workspace_id,
            )

            # If destination IP also present, DOMAIN RESOLVES_TO IP
            if dst_ip:
                self.graph_service.record_relationship(
                    db=db,
                    source_id=dom_ent.id,
                    target_id=ip_ent.id,
                    relationship_type=GraphRelationshipType.RESOLVES_TO,
                    origin=RelationshipOrigin.OBSERVED,
                    confidence=0.95,
                    source_artifact_id=artifact_id,
                    analysis_run_id=analysis_run_id,
                    analyzer="DnsTelemetryEngine",
                    evidence_reference="Observed DNS resolution in flow telemetry",
                    workspace_id=workspace_id,
                )

        db.commit()
        return GraphBuildResponse()

    # =========================================================================
    # 5. API ABUSE INTELLIGENCE (SECTION 11)
    # =========================================================================

    def ingest_api_event(
        self,
        db: Session,
        event: Dict[str, Any],
        artifact_id: Optional[str] = None,
        analysis_run_id: Optional[str] = None,
        incident_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
    ) -> GraphBuildResponse:
        """Ingests API audit events (Account -> Session -> Service/Resource)."""
        if not event:
            return GraphBuildResponse()

        now = get_utc_now()
        acc_id = event.get("account_id") or "api_principal"
        provider = event.get("service") or "cloud_api"

        acc_ent = self.graph_service.upsert_canonical_entity(
            db=db,
            entity_type=GraphEntityType.ACCOUNT,
            value=acc_id,
            context=provider,
            display_value=f"Account: {acc_id}",
            timestamp=now,
            workspace_id=workspace_id,
        )

        # Session
        session_id = event.get("session_id")
        sess_ent = None
        if session_id:
            sess_ent = self.graph_service.upsert_canonical_entity(
                db=db,
                entity_type=GraphEntityType.SESSION,
                value=str(session_id),
                context=provider,
                display_value=f"Session: {str(session_id)[:16]}...",
                workspace_id=workspace_id,
            )
            self.graph_service.record_relationship(
                db=db,
                source_id=acc_ent.id,
                target_id=sess_ent.id,
                relationship_type=GraphRelationshipType.HAS_SESSION,
                origin=RelationshipOrigin.OBSERVED,
                confidence=1.0,
                source_artifact_id=artifact_id,
                analysis_run_id=analysis_run_id,
                analyzer="ApiAbuseAnalyzer",
                evidence_reference="API token session bound to account",
                workspace_id=workspace_id,
            )

        # Service / Endpoint
        service_name = event.get("service")
        if service_name:
            svc_ent = self.graph_service.upsert_canonical_entity(
                db=db,
                entity_type=GraphEntityType.API_SERVICE,
                value=service_name,
                display_value=f"Service: {service_name}",
                workspace_id=workspace_id,
            )
            parent_caller_id = sess_ent.id if sess_ent else acc_ent.id
            self.graph_service.record_relationship(
                db=db,
                source_id=parent_caller_id,
                target_id=svc_ent.id,
                relationship_type=GraphRelationshipType.ACCESSED,
                origin=RelationshipOrigin.OBSERVED,
                confidence=1.0,
                source_artifact_id=artifact_id,
                analysis_run_id=analysis_run_id,
                analyzer="ApiAbuseAnalyzer",
                evidence_reference=f"HTTP API invocation on service {service_name}",
                workspace_id=workspace_id,
            )

        # Source IP
        src_ip = event.get("source_ip")
        if src_ip:
            clean_ip = str(src_ip).strip()
            ip_ent = self.graph_service.upsert_canonical_entity(
                db=db, entity_type=GraphEntityType.IP, value=clean_ip, display_value=clean_ip, workspace_id=workspace_id
            )
            parent_caller_id = sess_ent.id if sess_ent else acc_ent.id
            self.graph_service.record_relationship(
                db=db,
                source_id=parent_caller_id,
                target_id=ip_ent.id,
                relationship_type=GraphRelationshipType.ORIGINATED_FROM,
                origin=RelationshipOrigin.OBSERVED,
                confidence=1.0,
                source_artifact_id=artifact_id,
                analysis_run_id=analysis_run_id,
                analyzer="ApiAbuseAnalyzer",
                evidence_reference=f"Ingress IP {clean_ip}",
                workspace_id=workspace_id,
            )

        db.commit()
        return GraphBuildResponse()

    # =========================================================================
    # 6. DIGITAL IMPERSONATION & MULTIMEDIA (SECTIONS 12 & 13)
    # =========================================================================

    def ingest_impersonation_evidence(
        self,
        db: Session,
        evidence: Dict[str, Any],
        artifact_id: Optional[str] = None,
        analysis_run_id: Optional[str] = None,
        incident_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
    ) -> GraphBuildResponse:
        """
        Ingests impersonation findings.
        CRITICAL: CLAIMS_IDENTITY is never equivalent to IS_IDENTITY.
        """
        if not evidence:
            return GraphBuildResponse()

        source_val = evidence.get("source_identifier") or "adversary_artifact"
        source_type = evidence.get("source_type") or GraphEntityType.EMAIL
        claimed_identity = evidence.get("claimed_identity") or evidence.get("target_brand")

        if claimed_identity:
            s_ent = self.graph_service.upsert_canonical_entity(
                db=db, entity_type=source_type, value=source_val, display_value=source_val, workspace_id=workspace_id
            )
            id_ent = self.graph_service.upsert_canonical_entity(
                db=db,
                entity_type=GraphEntityType.IDENTITY,
                value=claimed_identity,
                display_value=f"Protected Identity: {claimed_identity}",
                workspace_id=workspace_id,
            )
            self.graph_service.record_relationship(
                db=db,
                source_id=s_ent.id,
                target_id=id_ent.id,
                relationship_type=GraphRelationshipType.CLAIMS_IDENTITY,
                origin=RelationshipOrigin.DERIVED,
                confidence=float(evidence.get("confidence", 0.9)),
                source_artifact_id=artifact_id,
                analysis_run_id=analysis_run_id,
                analyzer="DigitalImpersonationEngine",
                evidence_reference="Impersonation signature detected in header/body",
                workspace_id=workspace_id,
            )

        # Lookalike Domain
        lookalike_domain = evidence.get("lookalike_domain")
        legit_domain = evidence.get("legitimate_domain")
        if lookalike_domain and legit_domain:
            ld_ent = self.graph_service.upsert_canonical_entity(
                db=db, entity_type=GraphEntityType.DOMAIN, value=lookalike_domain, display_value=lookalike_domain, workspace_id=workspace_id
            )
            lg_ent = self.graph_service.upsert_canonical_entity(
                db=db, entity_type=GraphEntityType.DOMAIN, value=legit_domain, display_value=legit_domain, workspace_id=workspace_id
            )
            self.graph_service.record_relationship(
                db=db,
                source_id=ld_ent.id,
                target_id=lg_ent.id,
                relationship_type=GraphRelationshipType.LOOKALIKE_OF,
                origin=RelationshipOrigin.DERIVED,
                confidence=float(evidence.get("similarity", 0.95)),
                source_artifact_id=artifact_id,
                analysis_run_id=analysis_run_id,
                analyzer="DigitalImpersonationEngine",
                evidence_reference="Typosquatting/Homoglyph Confusable metric",
                workspace_id=workspace_id,
            )

        db.commit()
        return GraphBuildResponse()


global_security_graph_builder = SecurityGraphBuilder()
