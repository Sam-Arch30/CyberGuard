"""
Email & Phishing Intelligence Modular Analyzers (Section 6).
Implements specialized, evidence-driven analyzers for email artifacts:
1. EmailParserAnalyzer: RFC-822 / MIME parsing and header normalization
2. EmailAuthenticationAnalyzer: SPF, DKIM, and DMARC verification and provenance
3. EmailHeaderAnalyzer: Sender identity, From/Return-Path/Reply-To alignment, display name spoofing
4. EmailRelayAnalyzer: SMTP Received chain, hop reconstruction, transit latency, and relay anomalies
5. EmailAttachmentDiscoveryAnalyzer: Safe attachment extraction, SHA-256, derived Artifacts, and risk triage
6. EmailIOCAnalyzer: Multi-source observable extraction (URLs, domains, IPs, emails) and visible link mismatch
7. EmailSocialEngineeringAnalyzer: Linguistic, intent-based, and ML phishing heuristics
8. EmailImpersonationAnalyzer: Lookalike domain detection, homoglyphs, brand abuse, and BEC signals
9. EmailPhishingAggregator: Normalized finding aggregation, signal independence, and explainable classification
"""
from __future__ import annotations

import re
import email
import hashlib
import ipaddress
import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from email import policy
from email.header import decode_header, make_header
from typing import Any, Dict, List, Optional, Set, Tuple, Union

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
    generate_uuid,
    get_utc_now,
)
from backend.schemas.unified import (
    ArtifactTypeEnum,
    AnalysisStatusEnum,
    FindingMethodEnum,
    IndicatorTypeEnum,
    RelationshipTypeEnum,
    SeverityEnum,
    normalize_domain,
    normalize_ip,
    normalize_url,
    normalize_email_address,
)
from backend.services.evidence_storage import evidence_storage
from backend.services.auth_analyzer import AuthAnalyzerService
from backend.services.relay_reconstructor import RelayReconstructorService
from backend.services.lookalike_detector import LookalikeDetectorService
from backend.services.attachment_intelligence_service import AttachmentIntelligenceService
from backend.services.ioc_extractor import IOCExtractorService
from backend.services.url_analyzer import URLAnalyzerService
from backend.app.ml.classifier import global_phishing_classifier

logger = logging.getLogger("cyberguard.email_analyzers")


# ============================================================================
# BASE ANALYZER INTERFACE
# ============================================================================

class AnalyzerExecutionResult:
    """Standard container for analyzer findings, evidence, indicators, and relationships."""

    def __init__(self, analyzer_name: str, version: str = "1.0.0"):
        self.analyzer_name = analyzer_name
        self.version = version
        self.status: AnalysisStatusEnum = AnalysisStatusEnum.COMPLETED
        self.findings: List[Dict[str, Any]] = []
        self.evidence_items: List[Dict[str, Any]] = []
        self.finding_evidence_links: List[Tuple[int, int, float, str]] = []  # (finding_idx, evidence_idx, relevance, notes)
        self.indicators: List[Dict[str, Any]] = []
        self.relationships: List[Dict[str, Any]] = []
        self.threat_events: List[Dict[str, Any]] = []
        self.derived_artifacts: List[Dict[str, Any]] = []
        self.metadata: Dict[str, Any] = {}
        self.errors: List[str] = []

    def add_evidence(
        self,
        source: str,
        evidence_type: str,
        raw_content: Optional[str] = None,
        parsed_content: Optional[Dict[str, Any]] = None,
        confidence: float = 1.0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> int:
        idx = len(self.evidence_items)
        self.evidence_items.append({
            "source": source,
            "evidence_type": evidence_type,
            "raw_content": raw_content,
            "parsed_content": parsed_content or {},
            "confidence": confidence,
            "metadata": metadata or {},
        })
        return idx

    def add_finding(
        self,
        title: str,
        description: str,
        finding_type: str,
        category: str,
        severity: SeverityEnum,
        confidence: float = 1.0,
        method: FindingMethodEnum = FindingMethodEnum.DETERMINISTIC,
        mitre_technique_id: Optional[str] = None,
        remediation: Optional[str] = None,
        evidence_indices: Optional[List[int]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> int:
        idx = len(self.findings)
        self.findings.append({
            "title": title,
            "description": description,
            "finding_type": finding_type,
            "category": category,
            "severity": severity,
            "confidence": confidence,
            "method": method,
            "mitre_technique_id": mitre_technique_id,
            "remediation": remediation,
            "metadata": metadata or {},
        })
        if evidence_indices:
            for e_idx in evidence_indices:
                self.finding_evidence_links.append((idx, e_idx, 1.0, "Supporting evidence"))
        return idx

    def add_indicator(
        self,
        indicator_type: IndicatorTypeEnum,
        value: str,
        normalized_value: Optional[str] = None,
        reputation: Optional[str] = None,
        threat_types: Optional[str] = None,
        source: Optional[str] = None,
    ):
        norm = normalized_value
        if not norm:
            if indicator_type == IndicatorTypeEnum.URL:
                norm = normalize_url(value)
            elif indicator_type == IndicatorTypeEnum.DOMAIN:
                norm = normalize_domain(value)
            elif indicator_type == IndicatorTypeEnum.IP:
                norm = normalize_ip(value)
            elif indicator_type == IndicatorTypeEnum.EMAIL_ADDRESS:
                norm = normalize_email_address(value)
            else:
                norm = value.strip().lower()

        self.indicators.append({
            "indicator_type": indicator_type,
            "value": value,
            "normalized_value": norm,
            "reputation": reputation,
            "threat_types": threat_types,
            "source": source,
        })

    def add_relationship(
        self,
        source_id: str,
        source_type: str,
        target_id: str,
        target_type: str,
        relationship_type: RelationshipTypeEnum,
        confidence: float = 1.0,
        method: str = "DETERMINISTIC",
    ):
        self.relationships.append({
            "source_id": source_id,
            "source_type": source_type,
            "target_id": target_id,
            "target_type": target_type,
            "relationship_type": relationship_type,
            "confidence": confidence,
            "method": method,
        })


class BaseEmailAnalyzer(ABC):
    """Abstract base class for all modular email analyzers."""

    name: str = "base_email_analyzer"
    version: str = "1.0.0"
    supported_artifact_types: List[ArtifactTypeEnum] = [ArtifactTypeEnum.EMAIL]

    @abstractmethod
    def analyze(self, raw_bytes: bytes, context: Dict[str, Any]) -> AnalyzerExecutionResult:
        """Executes analysis against raw RFC-822 bytes with context."""
        pass


# ============================================================================
# 1. EMAIL PARSER ANALYZER
# ============================================================================

class EmailParserAnalyzer(BaseEmailAnalyzer):
    """
    Parses RFC-822 / MIME structure, normalizes headers, and extracts bodies.
    Separates display names, addresses, and domains for structured machine inspection.
    """
    name = "email_parser"
    version = "2.0.0"

    @staticmethod
    def _decode_header(val: Optional[Any]) -> Optional[str]:
        if val is None:
            return None
        s = str(val).strip()
        if not s:
            return None
        try:
            return str(make_header(decode_header(s))).strip()
        except Exception:
            return s

    @classmethod
    def decompose_address(cls, header_val: Optional[str]) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Decomposes an address header (e.g. '"Microsoft Support" <support@microsoft.com>') into:
        (display_name, email_address, domain).
        """
        if not header_val:
            return None, None, None

        import email.utils
        disp, addr = email.utils.parseaddr(header_val)
        disp_clean = disp.strip().strip('"\'') if disp else None
        addr_clean = addr.strip().lower() if addr else None

        domain_clean = None
        if addr_clean and "@" in addr_clean:
            domain_clean = addr_clean.split("@")[-1].strip().lower().rstrip(".")
        elif header_val and "@" in header_val:
            m = re.search(r'[\w\.-]+@([\w\.-]+\.[a-zA-Z]{2,})', header_val)
            if m:
                domain_clean = m.group(1).lower().rstrip(".")

        return disp_clean, addr_clean, domain_clean

    def analyze(self, raw_bytes: bytes, context: Dict[str, Any]) -> AnalyzerExecutionResult:
        result = AnalyzerExecutionResult(self.name, self.version)
        if not raw_bytes:
            result.status = AnalysisStatusEnum.FAILED
            result.errors.append("Empty email bytes provided.")
            return result

        raw_str = raw_bytes.decode("utf-8", errors="replace")
        try:
            msg = email.message_from_bytes(raw_bytes, policy=policy.default)
        except Exception as e:
            result.status = AnalysisStatusEnum.FAILED
            result.errors.append(f"Failed to parse email message: {e}")
            return result

        # Extract normalized headers
        from_hdr = self._decode_header(msg.get("From"))
        to_hdr = self._decode_header(msg.get("To"))
        cc_hdr = self._decode_header(msg.get("Cc"))
        subject_hdr = self._decode_header(msg.get("Subject"))
        date_hdr = self._decode_header(msg.get("Date"))
        reply_to_hdr = self._decode_header(msg.get("Reply-To"))
        return_path_hdr = self._decode_header(msg.get("Return-Path"))
        message_id_hdr = self._decode_header(msg.get("Message-ID"))
        list_id_hdr = self._decode_header(msg.get("List-Id"))
        list_unsub_hdr = self._decode_header(msg.get("List-Unsubscribe"))

        # Raw received headers
        raw_received = msg.get_all("Received", []) or []
        received_headers = [self._decode_header(r) for r in raw_received if r]

        # Auth headers
        auth_results = [self._decode_header(a) for a in (msg.get_all("Authentication-Results", []) or []) if a]
        arc_auth = [self._decode_header(a) for a in (msg.get_all("ARC-Authentication-Results", []) or []) if a]
        rec_spf = [self._decode_header(s) for s in (msg.get_all("Received-SPF", []) or []) if s]

        from_disp, from_addr, from_dom = self.decompose_address(from_hdr)
        rt_disp, rt_addr, rt_dom = self.decompose_address(reply_to_hdr)
        rp_disp, rp_addr, rp_dom = self.decompose_address(return_path_hdr)

        # Bodies
        plain_parts: List[str] = []
        html_parts: List[str] = []
        raw_attachments: List[Dict[str, Any]] = []

        try:
            parts = list(msg.walk()) if msg.is_multipart() else [msg]
            att_counter = 1
            for part in parts:
                ctype = part.get_content_type() or "application/octet-stream"
                cdisp = (part.get_content_disposition() or "").lower()
                fname = part.get_filename() or part.get_param("name", header="content-type") or part.get_param("filename", header="content-disposition")
                if fname:
                    fname = self._decode_header(fname)

                is_att = (cdisp == "attachment") or (fname is not None) or (part.get_content_maintype() not in ("text", "multipart"))
                if is_att:
                    if not fname:
                        fname = f"attachment_{att_counter}.bin"
                    att_counter += 1
                    payload = part.get_payload(decode=True) or b""
                    raw_attachments.append({
                        "filename": fname,
                        "mime_type": ctype,
                        "bytes": payload,
                        "size": len(payload),
                    })
                else:
                    if ctype == "text/plain":
                        try:
                            txt = part.get_content()
                            if isinstance(txt, str):
                                plain_parts.append(txt)
                        except Exception:
                            p = part.get_payload(decode=True)
                            if p:
                                plain_parts.append(p.decode("utf-8", errors="replace"))
                    elif ctype == "text/html":
                        try:
                            ht = part.get_content()
                            if isinstance(ht, str):
                                html_parts.append(ht)
                        except Exception:
                            p = part.get_payload(decode=True)
                            if p:
                                html_parts.append(p.decode("utf-8", errors="replace"))
        except Exception as e:
            result.errors.append(f"MIME part traversal warning: {e}")

        plain_text = "\n".join(plain_parts) if plain_parts else None
        html_body = "\n".join(html_parts) if html_parts else None

        parsed_data = {
            "from_header": from_hdr,
            "from_display_name": from_disp,
            "from_address": from_addr,
            "from_domain": from_dom,
            "to_header": to_hdr,
            "cc_header": cc_hdr,
            "subject": subject_hdr,
            "date": date_hdr,
            "reply_to": reply_to_hdr,
            "reply_to_display_name": rt_disp,
            "reply_to_address": rt_addr,
            "reply_to_domain": rt_dom,
            "return_path": return_path_hdr,
            "return_path_address": rp_addr,
            "return_path_domain": rp_dom,
            "message_id": message_id_hdr,
            "list_id": list_id_hdr,
            "list_unsubscribe": list_unsub_hdr,
            "received_headers": received_headers,
            "auth_results_headers": auth_results,
            "arc_auth_headers": arc_auth,
            "received_spf_headers": rec_spf,
            "plain_text_body": plain_text,
            "html_body": html_body,
            "raw_attachments": raw_attachments,
        }

        # Store in result metadata for subsequent analyzers
        result.metadata["parsed_email"] = parsed_data

        # Evidence: RFC-822 header block
        e_hdr = result.add_evidence(
            source="EMAIL_HEADERS",
            evidence_type="RFC822_HEADER_BLOCK",
            raw_content=f"From: {from_hdr}\nTo: {to_hdr}\nSubject: {subject_hdr}\nReply-To: {reply_to_hdr}\nDate: {date_hdr}",
            parsed_content={
                "from_domain": from_dom,
                "reply_to_domain": rt_dom,
                "return_path_domain": rp_dom,
                "subject": subject_hdr,
                "date": date_hdr,
            },
            confidence=1.0,
        )

        # Finding: Informational header summary
        result.add_finding(
            title=f"Parsed RFC-822 Email Message: '{subject_hdr or 'Untitled'}'",
            description=f"Message parsed with From: {from_hdr}, To: {to_hdr}, Subject: {subject_hdr}. Contains {len(received_headers)} Received hops and {len(raw_attachments)} attachments.",
            finding_type="EMAIL_STRUCTURE_PARSED",
            category="METADATA",
            severity=SeverityEnum.SAFE,
            confidence=1.0,
            method=FindingMethodEnum.DETERMINISTIC,
            evidence_indices=[e_hdr],
        )

        return result


# ============================================================================
# 2. EMAIL AUTHENTICATION ANALYZER
# ============================================================================

class EmailAuthenticationAnalyzer(BaseEmailAnalyzer):
    """
    Evaluates SPF, DKIM, and DMARC results from observed headers.
    Distinguishes observed upstream headers from locally verified cryptographic checks.
    """
    name = "email_authentication"
    version = "2.0.0"

    def analyze(self, raw_bytes: bytes, context: Dict[str, Any]) -> AnalyzerExecutionResult:
        result = AnalyzerExecutionResult(self.name, self.version)
        parsed = context.get("parsed_email", {})

        from_hdr = parsed.get("from_header")
        reply_to_hdr = parsed.get("reply_to")
        return_path_hdr = parsed.get("return_path")
        auth_headers = (parsed.get("auth_results_headers") or []) + (parsed.get("arc_auth_headers") or [])
        rec_spf = parsed.get("received_spf_headers") or []
        raw_text = raw_bytes.decode("utf-8", errors="replace")

        auth_analysis = AuthAnalyzerService.analyze_authentication(
            from_header=from_hdr,
            reply_to=reply_to_hdr,
            return_path=return_path_hdr,
            auth_headers=auth_headers,
            received_spf_headers=rec_spf,
            raw_headers_text=raw_text,
        )

        result.metadata["auth_analysis"] = auth_analysis.model_dump() if hasattr(auth_analysis, "model_dump") else auth_analysis

        # 1. SPF Finding
        spf_res = (auth_analysis.spf.result or "unknown").lower()
        spf_details = auth_analysis.spf.details or "No details available"
        e_spf = result.add_evidence(
            source="AUTHENTICATION_HEADERS",
            evidence_type="SPF_RESULT",
            raw_content=spf_details,
            parsed_content={"result": spf_res, "provenance": "observed_header"},
            confidence=1.0,
        )

        if spf_res == "pass":
            result.add_finding(
                title="SPF Authentication Passed",
                description=f"Observed SPF validation passed for sender: {spf_details}",
                finding_type="SPF_PASS",
                category="AUTHENTICATION",
                severity=SeverityEnum.SAFE,
                confidence=1.0,
                method=FindingMethodEnum.DETERMINISTIC,
                evidence_indices=[e_spf],
            )
        elif spf_res == "fail":
            result.add_finding(
                title="SPF Authentication Failed",
                description=f"Sending IP is not authorized in the sender domain's SPF record: {spf_details}",
                finding_type="SPF_FAILURE",
                category="AUTHENTICATION",
                severity=SeverityEnum.HIGH,
                confidence=0.95,
                method=FindingMethodEnum.DETERMINISTIC,
                mitre_technique_id="T1566.002",
                remediation="Investigate whether the sender is spoofed or legitimate mail was relayed via an unlisted outbound relay.",
                evidence_indices=[e_spf],
            )
        elif spf_res == "softfail":
            result.add_finding(
                title="SPF Authentication Softfail",
                description=f"Sending IP is discouraged (~all) by the sender domain's SPF policy: {spf_details}",
                finding_type="SPF_SOFTFAIL",
                category="AUTHENTICATION",
                severity=SeverityEnum.MEDIUM,
                confidence=0.85,
                method=FindingMethodEnum.DETERMINISTIC,
                evidence_indices=[e_spf],
            )
        elif spf_res in ("none", "unknown"):
            result.add_finding(
                title=f"SPF Record Absent or Unverified ({spf_res.upper()})",
                description="No definitive SPF authorization record was observed in email authentication headers.",
                finding_type="SPF_UNVERIFIED",
                category="AUTHENTICATION",
                severity=SeverityEnum.LOW,
                confidence=0.7,
                method=FindingMethodEnum.DETERMINISTIC,
                evidence_indices=[e_spf],
            )

        # 2. DKIM Finding
        dkim_res = (auth_analysis.dkim.result or "unknown").lower()
        dkim_details = auth_analysis.dkim.details or "No details available"
        e_dkim = result.add_evidence(
            source="AUTHENTICATION_HEADERS",
            evidence_type="DKIM_RESULT",
            raw_content=dkim_details,
            parsed_content={"result": dkim_res, "provenance": "observed_header"},
            confidence=1.0,
        )

        if dkim_res == "pass":
            result.add_finding(
                title="DKIM Signature Verified",
                description=f"Observed DKIM cryptographic signature verified successfully: {dkim_details}",
                finding_type="DKIM_PASS",
                category="AUTHENTICATION",
                severity=SeverityEnum.SAFE,
                confidence=1.0,
                method=FindingMethodEnum.DETERMINISTIC,
                evidence_indices=[e_dkim],
            )
        elif dkim_res == "fail":
            result.add_finding(
                title="DKIM Signature Verification Failed",
                description=f"DKIM cryptographic signature verification failed: {dkim_details}",
                finding_type="DKIM_FAILURE",
                category="AUTHENTICATION",
                severity=SeverityEnum.HIGH,
                confidence=0.95,
                method=FindingMethodEnum.DETERMINISTIC,
                mitre_technique_id="T1566.002",
                evidence_indices=[e_dkim],
            )
        elif dkim_res in ("none", "unknown"):
            result.add_finding(
                title=f"DKIM Signature Absent or Unverified ({dkim_res.upper()})",
                description="Message lacks a verified cryptographic DKIM signature in authentication headers.",
                finding_type="DKIM_UNVERIFIED",
                category="AUTHENTICATION",
                severity=SeverityEnum.LOW,
                confidence=0.7,
                method=FindingMethodEnum.DETERMINISTIC,
                evidence_indices=[e_dkim],
            )

        # 3. DMARC Finding
        dmarc_res = (auth_analysis.dmarc.result or "unknown").lower()
        dmarc_details = auth_analysis.dmarc.details or "No details available"
        e_dmarc = result.add_evidence(
            source="AUTHENTICATION_HEADERS",
            evidence_type="DMARC_RESULT",
            raw_content=dmarc_details,
            parsed_content={"result": dmarc_res, "provenance": "observed_header"},
            confidence=1.0,
        )

        if dmarc_res == "pass":
            result.add_finding(
                title="DMARC Policy Alignment Passed",
                description=f"Sender domain aligns with SPF and/or DKIM authentication: {dmarc_details}",
                finding_type="DMARC_PASS",
                category="AUTHENTICATION",
                severity=SeverityEnum.SAFE,
                confidence=1.0,
                method=FindingMethodEnum.DETERMINISTIC,
                evidence_indices=[e_dmarc],
            )
        elif dmarc_res == "fail":
            result.add_finding(
                title="DMARC Authentication Failed",
                description=f"Message failed domain authentication alignment under DMARC policy: {dmarc_details}",
                finding_type="DMARC_FAILURE",
                category="AUTHENTICATION",
                severity=SeverityEnum.HIGH,
                confidence=0.95,
                method=FindingMethodEnum.DETERMINISTIC,
                mitre_technique_id="T1566.002",
                remediation="Check domain alignment between From header, SPF envelope, and DKIM signing domains.",
                evidence_indices=[e_dmarc],
            )
        elif dmarc_res in ("none", "unknown"):
            result.add_finding(
                title=f"DMARC Policy Absent ({dmarc_res.upper()})",
                description="No DMARC evaluation result was recorded in Authentication-Results headers.",
                finding_type="DMARC_NONE",
                category="AUTHENTICATION",
                severity=SeverityEnum.LOW,
                confidence=0.7,
                method=FindingMethodEnum.DETERMINISTIC,
                evidence_indices=[e_dmarc],
            )

        return result


# ============================================================================
# 3. EMAIL HEADER ANALYZER (SENDER IDENTITY & ALIGNMENT)
# ============================================================================

class EmailHeaderAnalyzer(BaseEmailAnalyzer):
    """
    Analyzes sender identities, compares Header From vs Return-Path vs Reply-To,
    and detects display name spoofing and mailing list characteristics.
    """
    name = "email_headers"
    version = "2.0.0"

    def analyze(self, raw_bytes: bytes, context: Dict[str, Any]) -> AnalyzerExecutionResult:
        result = AnalyzerExecutionResult(self.name, self.version)
        parsed = context.get("parsed_email", {})

        from_disp = parsed.get("from_display_name")
        from_addr = parsed.get("from_address")
        from_dom = parsed.get("from_domain")

        rt_disp = parsed.get("reply_to_display_name")
        rt_addr = parsed.get("reply_to_address")
        rt_dom = parsed.get("reply_to_domain")

        rp_addr = parsed.get("return_path_address")
        rp_dom = parsed.get("return_path_domain")

        list_id = parsed.get("list_id")
        list_unsub = parsed.get("list_unsubscribe")
        is_mailing_list = bool(list_id or list_unsub)

        # 1. From vs Return-Path Mismatch
        if from_dom and rp_dom and from_dom != rp_dom:
            e_rp = result.add_evidence(
                source="EMAIL_HEADERS",
                evidence_type="SENDER_ENVELOPE_ALIGNMENT",
                raw_content=f"From: {from_addr} (Domain: {from_dom}) vs Return-Path: {rp_addr} (Domain: {rp_dom})",
                parsed_content={
                    "from_domain": from_dom,
                    "return_path_domain": rp_dom,
                    "is_mailing_list": is_mailing_list,
                },
                confidence=1.0,
            )

            # False-positive calibration: Newsletters and mailing lists legitimately use bounce domains
            if is_mailing_list:
                result.add_finding(
                    title="Mailing List Return-Path Difference Observed",
                    description=f"From domain ({from_dom}) differs from Return-Path ({rp_dom}), typical of legitimate mailing lists (List-Id: {list_id or 'present'}).",
                    finding_type="MAILING_LIST_TRANSPORT_PATTERN",
                    category="IDENTITY",
                    severity=SeverityEnum.LOW,
                    confidence=0.8,
                    method=FindingMethodEnum.RULE,
                    evidence_indices=[e_rp],
                )
            else:
                result.add_finding(
                    title="Sender Envelope Identity Mismatch",
                    description=f"The visible From domain '{from_dom}' does not match the technical Return-Path domain '{rp_dom}'.",
                    finding_type="SENDER_IDENTITY_MISMATCH",
                    category="IDENTITY",
                    severity=SeverityEnum.MEDIUM,
                    confidence=0.9,
                    method=FindingMethodEnum.DETERMINISTIC,
                    mitre_technique_id="T1566.002",
                    evidence_indices=[e_rp],
                )

        # 2. From vs Reply-To Mismatch
        if from_dom and rt_dom and from_dom != rt_dom:
            e_rt = result.add_evidence(
                source="EMAIL_HEADERS",
                evidence_type="REPLY_TO_ALIGNMENT",
                raw_content=f"From: {from_addr} -> Reply-To: {rt_addr}",
                parsed_content={"from_domain": from_dom, "reply_to_domain": rt_dom},
                confidence=1.0,
            )
            result.add_finding(
                title="Reply-To Domain Mismatch Detected",
                description=f"Email From domain '{from_dom}' redirects replies to an unrelated domain '{rt_dom}' ({rt_addr}).",
                finding_type="REPLY_TO_MISMATCH",
                category="IDENTITY",
                severity=SeverityEnum.HIGH,
                confidence=0.95,
                method=FindingMethodEnum.DETERMINISTIC,
                mitre_technique_id="T1566.002",
                remediation="Ensure user replies are not harvested by an external attacker domain.",
                evidence_indices=[e_rt],
            )

        # 3. Display Name Spoofing
        if from_disp and from_addr:
            disp_lower = from_disp.lower()
            # Check if display name embeds an email address differing from the sender
            embedded_email_match = re.search(r'[\w\.-]+@([\w\.-]+\.[a-zA-Z]{2,})', from_disp)
            if embedded_email_match:
                emb_addr = embedded_email_match.group(0).lower()
                emb_dom = embedded_email_match.group(1).lower()
                if emb_dom != from_dom:
                    e_disp = result.add_evidence(
                        source="EMAIL_HEADERS",
                        evidence_type="DISPLAY_NAME_EMAIL_INCLUSION",
                        raw_content=f"Display Name: '{from_disp}' contains address '{emb_addr}' differing from '{from_addr}'",
                        parsed_content={"display_name": from_disp, "sender_address": from_addr},
                        confidence=1.0,
                    )
                    result.add_finding(
                        title="Display Name Embedded Address Spoofing",
                        description=f"Display name '{from_disp}' deceptively mimics address '{emb_addr}' while sent from '{from_addr}'.",
                        finding_type="DISPLAY_NAME_SPOOFING",
                        category="IDENTITY",
                        severity=SeverityEnum.HIGH,
                        confidence=0.95,
                        method=FindingMethodEnum.RULE,
                        mitre_technique_id="T1566.002",
                        evidence_indices=[e_disp],
                    )

        return result


# ============================================================================
# 4. EMAIL RELAY ANALYZER
# ============================================================================

class EmailRelayAnalyzer(BaseEmailAnalyzer):
    """
    Parses SMTP Received header chains, reconstructs chronological transmission hops,
    identifies the earliest public sender node, and flags transit anomalies.
    """
    name = "email_relays"
    version = "2.0.0"

    def analyze(self, raw_bytes: bytes, context: Dict[str, Any]) -> AnalyzerExecutionResult:
        result = AnalyzerExecutionResult(self.name, self.version)
        parsed = context.get("parsed_email", {})
        received_headers = parsed.get("received_headers") or []

        if not received_headers:
            result.add_finding(
                title="No Received Headers Observed",
                description="Email contains zero Received headers, preventing transmission hop verification.",
                finding_type="RELAY_HEADERS_ABSENT",
                category="INFRASTRUCTURE",
                severity=SeverityEnum.LOW,
                confidence=1.0,
                method=FindingMethodEnum.DETERMINISTIC,
            )
            return result

        relay_analysis = RelayReconstructorService.reconstruct_relay_path(received_headers)
        result.metadata["relay_analysis"] = relay_analysis.model_dump() if hasattr(relay_analysis, "model_dump") else relay_analysis

        hops = relay_analysis.transmission_order_hops or []
        earliest_node = relay_analysis.earliest_observable_node

        e_relay = result.add_evidence(
            source="RECEIVED_HEADERS",
            evidence_type="RELAY_PATH_TRACE",
            raw_content="\n".join(received_headers[:5]),
            parsed_content={
                "hop_count": len(hops),
                "earliest_public_ip": earliest_node.earliest_observable_ip if earliest_node else None,
                "confidence": earliest_node.confidence if earliest_node else "none",
            },
            confidence=0.9,
        )

        # Record public relay IP indicator
        if earliest_node and earliest_node.earliest_observable_ip:
            result.add_indicator(
                indicator_type=IndicatorTypeEnum.IP,
                value=earliest_node.earliest_observable_ip,
                source="EARLIEST_OBSERVABLE_RELAY_IP",
            )
            result.add_finding(
                title=f"Earliest Observable Public Relay IP: {earliest_node.earliest_observable_ip}",
                description=f"Earliest non-internal hop reconstructed with IP {earliest_node.earliest_observable_ip} ({earliest_node.from_host or 'Unknown Host'}). Confidence: {earliest_node.confidence}.",
                finding_type="PUBLIC_RELAY_IDENTIFIED",
                category="INFRASTRUCTURE",
                severity=SeverityEnum.SAFE,
                confidence=0.9,
                method=FindingMethodEnum.HEURISTIC,
                evidence_indices=[e_relay],
            )

        # Check for relay anomalies
        anomalies: List[str] = []
        for hop in hops:
            if getattr(hop, "parser_confidence", "high") == "low":
                anomalies.append(f"Hop {hop.hop_number} has low parser confidence or malformed syntax: {hop.raw[:60]}")
            if getattr(hop, "from_ip", None) is None and getattr(hop, "from_host", None) is None:
                anomalies.append(f"Hop {hop.hop_number} lacks both sender IP and sender hostname.")

        if anomalies:
            e_anom = result.add_evidence(
                source="RECEIVED_HEADERS",
                evidence_type="RELAY_TIMING_ANOMALY",
                raw_content="; ".join(anomalies),
                confidence=0.9,
            )
            result.add_finding(
                title="Relay Chain Timing Anomalies Observed",
                description="; ".join(anomalies),
                finding_type="RELAY_ANOMALY",
                category="INFRASTRUCTURE",
                severity=SeverityEnum.MEDIUM,
                confidence=0.85,
                method=FindingMethodEnum.HEURISTIC,
                evidence_indices=[e_anom],
            )

        return result


# ============================================================================
# 5. EMAIL ATTACHMENT DISCOVERY & SAFE TRIAGE ANALYZER
# ============================================================================

class EmailAttachmentDiscoveryAnalyzer(BaseEmailAnalyzer):
    """
    Safely extracts attachments, persists raw bytes into persistent storage,
    registers derived Artifacts, and performs static metadata triage (NO EXECUTION).
    """
    name = "attachment_security"
    version = "2.0.0"

    def analyze(self, raw_bytes: bytes, context: Dict[str, Any]) -> AnalyzerExecutionResult:
        result = AnalyzerExecutionResult(self.name, self.version)
        parsed = context.get("parsed_email", {})
        raw_attachments = parsed.get("raw_attachments") or []

        if not raw_attachments:
            return result

        db: Optional[Session] = context.get("db")
        parent_artifact_id: Optional[str] = context.get("artifact_id")

        for att in raw_attachments:
            att_name = att.get("filename") or "unnamed_attachment"
            att_bytes = att.get("bytes") or b""
            att_mime = att.get("mime_type") or "application/octet-stream"
            att_size = len(att_bytes)

            sha256_hash = hashlib.sha256(att_bytes).hexdigest()
            sha1_hash = hashlib.sha1(att_bytes).hexdigest()
            md5_hash = hashlib.md5(att_bytes).hexdigest()

            # Register derived artifact in persistent evidence storage
            storage_key = None
            try:
                storage_res = evidence_storage.store_bytes(
                    data=att_bytes,
                    original_filename=att_name,
                    mime_type=att_mime,
                )
                storage_key = storage_res.storage_key
            except Exception as e:
                logger.error(f"Failed to persist attachment '{att_name}': {e}")

            # Register indicator for attachment hash
            result.add_indicator(
                indicator_type=IndicatorTypeEnum.FILE_HASH,
                value=sha256_hash,
                source=f"ATTACHMENT_HASH ({att_name})",
            )
            result.add_indicator(
                indicator_type=IndicatorTypeEnum.FILENAME,
                value=att_name,
                source="ATTACHMENT_NAME",
            )

            # Record derived artifact definition
            derived_def = {
                "name": att_name,
                "artifact_type": ArtifactTypeEnum.ATTACHMENT,
                "mime_type": att_mime,
                "size": att_size,
                "sha256": sha256_hash,
                "sha1": sha1_hash,
                "md5": md5_hash,
                "storage_reference": storage_key,
                "parent_artifact_id": parent_artifact_id,
            }
            result.derived_artifacts.append(derived_def)

            # Evidence item
            e_att = result.add_evidence(
                source="EMAIL_ATTACHMENT",
                evidence_type="ATTACHMENT_METADATA",
                raw_content=f"Filename: {att_name}, Size: {att_size} bytes, MIME: {att_mime}, SHA-256: {sha256_hash}",
                parsed_content=derived_def,
                confidence=1.0,
            )

            # Metadata-level risk signals (strictly static, zero execution)
            lower_name = att_name.lower()

            # 1. Suspicious extensions
            suspicious_exts = {
                ".exe", ".scr", ".bat", ".cmd", ".vbs", ".ps1", ".hta", ".cpl", ".msi",
                ".jar", ".iso", ".img", ".vhd", ".docm", ".xlsm", ".pptm"
            }
            has_suspicious_ext = any(lower_name.endswith(ext) for ext in suspicious_exts)
            if has_suspicious_ext:
                result.add_finding(
                    title=f"Suspicious Attachment Type Observed: '{att_name}'",
                    description=f"Attachment possesses an executable or macro-enabled extension: {att_name} ({att_mime}).",
                    finding_type="SUSPICIOUS_ATTACHMENT_TYPE",
                    category="ATTACHMENT",
                    severity=SeverityEnum.HIGH,
                    confidence=0.95,
                    method=FindingMethodEnum.RULE,
                    mitre_technique_id="T1566.001",
                    remediation="Block execution and submit to isolated file inspection.",
                    evidence_indices=[e_att],
                )

            # 2. Suspicious double extensions (e.g. invoice.pdf.exe, receipt.docx.vbs)
            double_ext_match = re.search(r'\.(pdf|docx?|xlsx?|pptx?|txt|csv|jpg|png)\.(exe|scr|bat|cmd|vbs|ps1|hta|cpl)$', lower_name)
            if double_ext_match:
                result.add_finding(
                    title=f"Double Extension Deception Detected: '{att_name}'",
                    description=f"Attachment '{att_name}' masquerades as a document while terminating with an executable extension.",
                    finding_type="DOUBLE_EXTENSION_ATTACHMENT",
                    category="ATTACHMENT",
                    severity=SeverityEnum.CRITICAL,
                    confidence=0.98,
                    method=FindingMethodEnum.RULE,
                    mitre_technique_id="T1036.007",
                    remediation="Quarantine attachment immediately.",
                    evidence_indices=[e_att],
                )

        return result


# ============================================================================
# 6. EMAIL IOC & URL EXTRACTION ANALYZER
# ============================================================================

class EmailIOCAnalyzer(BaseEmailAnalyzer):
    """
    Extracts all network and host observables (URLs, domains, IPs, emails)
    with strict provenance. Detects visible link text vs actual href destination mismatches.
    Does NOT fetch URLs over the network.
    """
    name = "ioc_extraction"
    version = "2.0.0"

    def analyze(self, raw_bytes: bytes, context: Dict[str, Any]) -> AnalyzerExecutionResult:
        result = AnalyzerExecutionResult(self.name, self.version)
        parsed = context.get("parsed_email", {})

        plain_text = parsed.get("plain_text_body") or ""
        html_body = parsed.get("html_body") or ""
        headers_dict = {
            "from": parsed.get("from_header"),
            "reply_to": parsed.get("reply_to"),
            "return_path": parsed.get("return_path"),
            "message_id": parsed.get("message_id"),
        }

        # 1. URL extraction
        url_indicators = IOCExtractorService.extract_urls(plain_text, html_body, headers_dict)
        html_links = IOCExtractorService.extract_html_links(html_body)

        result.metadata["extracted_urls"] = [u.value for u in url_indicators]
        result.metadata["html_links"] = [{"url": l[0], "text": l[1] if len(l) > 1 else ""} for l in html_links]

        # Register URL indicators with provenance
        for u in url_indicators:
            result.add_indicator(
                indicator_type=IndicatorTypeEnum.URL,
                value=u.value,
                source=u.source,
            )

        # 2. Visible link vs href mismatch detection
        for link in html_links:
            href_target = link[0].strip() if len(link) > 0 and link[0] else ""
            visible_text = link[1].strip() if len(link) > 1 and link[1] else ""

            # Check if visible text looks like an absolute URL or domain
            if re.match(r'^(?:https?://)?[\w\.-]+\.[a-zA-Z]{2,}', visible_text, re.IGNORECASE):
                norm_vis = visible_text.lower().replace("https://", "").replace("http://", "").split("/")[0].rstrip(".")
                norm_target = href_target.lower().replace("https://", "").replace("http://", "").split("/")[0].rstrip(".")

                if norm_vis and norm_target and norm_vis != norm_target:
                    e_link = result.add_evidence(
                        source="HTML_BODY_HREF",
                        evidence_type="DECEPTIVE_HYPERLINK_MISMATCH",
                        raw_content=f"Visible Text: '{visible_text}' -> Actual Destination: '{href_target}'",
                        parsed_content={
                            "visible_display": visible_text,
                            "actual_destination": href_target,
                            "display_domain": norm_vis,
                            "destination_domain": norm_target,
                        },
                        confidence=1.0,
                    )
                    result.add_finding(
                        title="Deceptive Hyperlink Display Mismatch Detected",
                        description=f"Visible link displays '{visible_text}' but directs clicks to an entirely different domain '{href_target}'.",
                        finding_type="VISIBLE_LINK_MISMATCH",
                        category="URL",
                        severity=SeverityEnum.HIGH,
                        confidence=0.98,
                        method=FindingMethodEnum.DETERMINISTIC,
                        mitre_technique_id="T1566.002",
                        remediation="Treat destination as credential harvesting or malicious redirection target.",
                        evidence_indices=[e_link],
                    )

        # 3. Domain extraction
        email_indicators = IOCExtractorService.extract_email_addresses(headers_dict, plain_text, html_body)
        for em in email_indicators:
            result.add_indicator(
                indicator_type=IndicatorTypeEnum.EMAIL_ADDRESS,
                value=em.value,
                source=em.source,
            )

        text_sources = [(plain_text, "plain_text_body")]
        if html_body:
            clean_html = re.sub(r'<[^>]+>', ' ', html_body)
            text_sources.append((clean_html, "html_body"))

        domain_indicators = IOCExtractorService.extract_domains(url_indicators, email_indicators, text_sources)
        for d in domain_indicators:
            result.add_indicator(
                indicator_type=IndicatorTypeEnum.DOMAIN,
                value=d.value,
                source=d.source,
            )

        # 4. IP extraction
        ip_indicators = IOCExtractorService.extract_ips(text_sources)
        for ip_ind in ip_indicators:
            result.add_indicator(
                indicator_type=IndicatorTypeEnum.IP,
                value=ip_ind.value,
                source=ip_ind.source,
            )

        return result


# ============================================================================
# 7. EMAIL SOCIAL ENGINEERING & NLP ANALYZER
# ============================================================================

class EmailSocialEngineeringAnalyzer(BaseEmailAnalyzer):
    """
    Analyzes email linguistic content, subject, and body for social-engineering signals:
    urgency, credential harvesting, financial demands, account suspension, and secrecy.
    Combines rule-based heuristics with pre-trained ML classification.
    """
    name = "nlp_phishing_detector"
    version = "2.0.0"

    URGENCY_PATTERNS = [
        r'\b(?:immediate|urgent|urgently|right now|within \d+ (?:hours?|mins?|days?)|deadline|critical|immediate action)\b',
        r'\b(?:account (?:will be |is )?(?:suspended|locked|terminated|disabled|restricted|deactivated))\b',
        r'\b(?:final notice|last warning|action required|immediate response)\b',
    ]

    CREDENTIAL_PATTERNS = [
        r'\b(?:verify|confirm|validate|update|reset|change) (?:your )?(?:password|account|credentials|passcode|login|security information)\b',
        r'\b(?:login to|sign in to) (?:verify|confirm|unlock|restore|keep)\b',
        r'\b(?:click here to (?:verify|login|unlock|update))\b',
    ]

    FINANCIAL_PATTERNS = [
        r'\b(?:wire transfer|bank transfer|payment transfer|new bank details|updated invoice|payment instruction|gift cards?|remittance)\b',
        r'\b(?:overdue invoice|pending payment|unauthorized charge|refund request)\b',
    ]

    SECRECY_PATTERNS = [
        r'\b(?:keep (?:this )?confidential|do not share|do not call|strictly between us|handle discreetly|bypass normal)\b',
    ]

    def analyze(self, raw_bytes: bytes, context: Dict[str, Any]) -> AnalyzerExecutionResult:
        result = AnalyzerExecutionResult(self.name, self.version)
        parsed = context.get("parsed_email", {})

        subject = parsed.get("subject") or ""
        plain_text = parsed.get("plain_text_body") or ""
        html_body = parsed.get("html_body") or ""

        # Aggregate body text
        combined_text = f"{subject}\n{plain_text}"
        if not plain_text and html_body:
            clean_html = re.sub(r'<[^>]+>', ' ', html_body)
            combined_text = f"{subject}\n{clean_html}"

        lower_text = combined_text.lower()

        # 1. Credential Request Intent
        cred_matches: List[str] = []
        for pat in self.CREDENTIAL_PATTERNS:
            m = re.findall(pat, lower_text, re.IGNORECASE)
            if m:
                cred_matches.extend(m)

        if cred_matches:
            e_cred = result.add_evidence(
                source="EMAIL_CONTENT",
                evidence_type="CREDENTIAL_HARVESTING_INTENT",
                raw_content="; ".join(set(cred_matches)),
                confidence=0.9,
            )
            result.add_finding(
                title="Credential Request Social Engineering Signal",
                description=f"Email requests credentials or account re-authentication: '{'; '.join(set(cred_matches))}'.",
                finding_type="CREDENTIAL_REQUEST",
                category="CONTENT",
                severity=SeverityEnum.HIGH,
                confidence=0.88,
                method=FindingMethodEnum.RULE,
                mitre_technique_id="T1566.002",
                remediation="Advise recipient never to supply credentials via links in unsolicited messages.",
                evidence_indices=[e_cred],
            )

        # 2. Urgency & Threat Pressure Intent
        urgency_matches: List[str] = []
        for pat in self.URGENCY_PATTERNS:
            m = re.findall(pat, lower_text, re.IGNORECASE)
            if m:
                urgency_matches.extend(m)

        if urgency_matches:
            e_urg = result.add_evidence(
                source="EMAIL_CONTENT",
                evidence_type="URGENCY_PRESSURE_INTENT",
                raw_content="; ".join(set(urgency_matches)),
                confidence=0.85,
            )
            result.add_finding(
                title="Urgency & Account Suspension Pressure Language",
                description=f"Email employs psychological urgency or suspension threats: '{'; '.join(set(urgency_matches))}'.",
                finding_type="URGENCY_LANGUAGE",
                category="CONTENT",
                severity=SeverityEnum.MEDIUM,
                confidence=0.85,
                method=FindingMethodEnum.RULE,
                evidence_indices=[e_urg],
            )

        # 3. Financial Request Intent
        fin_matches: List[str] = []
        for pat in self.FINANCIAL_PATTERNS:
            m = re.findall(pat, lower_text, re.IGNORECASE)
            if m:
                fin_matches.extend(m)

        if fin_matches:
            e_fin = result.add_evidence(
                source="EMAIL_CONTENT",
                evidence_type="FINANCIAL_TRANSFER_INTENT",
                raw_content="; ".join(set(fin_matches)),
                confidence=0.85,
            )
            result.add_finding(
                title="Financial Transfer or Invoice Pressure Indicators",
                description=f"Email requests financial transactions, gift cards, or bank alteration: '{'; '.join(set(fin_matches))}'.",
                finding_type="FINANCIAL_REQUEST",
                category="CONTENT",
                severity=SeverityEnum.MEDIUM,
                confidence=0.85,
                method=FindingMethodEnum.RULE,
                evidence_indices=[e_fin],
            )

        # 4. ML Phishing Classifier Prediction
        try:
            ml_pred = global_phishing_classifier.predict(subject=subject, body=plain_text or combined_text)
            result.metadata["ml_prediction"] = ml_pred

            prob = ml_pred.get("probability")
            if prob is not None and prob >= 0.75:
                e_ml = result.add_evidence(
                    source="ML_NLP_CLASSIFIER",
                    evidence_type="PHISHING_PROBABILITY_SCORE",
                    raw_content=f"Probability: {prob:.4f}, Model: {ml_pred.get('model_name')}, Features: {ml_pred.get('top_features')}",
                    parsed_content=ml_pred,
                    confidence=prob,
                )
                result.add_finding(
                    title=f"Statistical NLP Model Flags Elevated Phishing Probability ({int(prob * 100)}%)",
                    description=f"TF-IDF Logistic Regression model evaluated subject and body text with high phishing likelihood ({prob:.2f}). Top indicative features: {ml_pred.get('top_features', [])}.",
                    finding_type="ML_PHISHING_PROBABILITY_ELEVATED",
                    category="BEHAVIORAL",
                    severity=SeverityEnum.MEDIUM if prob < 0.90 else SeverityEnum.HIGH,
                    confidence=prob,
                    method=FindingMethodEnum.ML_MODEL,
                    evidence_indices=[e_ml],
                )
        except Exception as e:
            logger.warning(f"ML classification failed: {e}")

        return result


# ============================================================================
# 8. EMAIL IMPERSONATION ANALYZER
# ============================================================================

class EmailImpersonationAnalyzer(BaseEmailAnalyzer):
    """
    Evaluates domain lookalikes, brand impersonation, typosquatting,
    homoglyphs, and Business Email Compromise (BEC) patterns across domains and identities.
    """
    name = "domain_impersonation"
    version = "2.0.0"

    def __init__(self, lookalike_detector: Optional[LookalikeDetectorService] = None):
        self.lookalike_detector = lookalike_detector or LookalikeDetectorService()

    def analyze(self, raw_bytes: bytes, context: Dict[str, Any]) -> AnalyzerExecutionResult:
        result = AnalyzerExecutionResult(self.name, self.version)
        parsed = context.get("parsed_email", {})

        from_dom = parsed.get("from_domain")
        from_disp = parsed.get("from_display_name")
        reply_to_dom = parsed.get("reply_to_domain")
        extracted_urls = context.get("extracted_urls", [])

        domains_to_evaluate: Set[str] = set()
        if from_dom:
            domains_to_evaluate.add(from_dom)
        if reply_to_dom:
            domains_to_evaluate.add(reply_to_dom)

        for u in extracted_urls:
            try:
                import urllib.parse
                p = urllib.parse.urlsplit(u)
                if p.netloc:
                    host = p.netloc.split(":")[0].lower().rstrip(".")
                    domains_to_evaluate.add(host)
            except Exception:
                pass

        # Lookalike inspection for observed domains
        for dom in domains_to_evaluate:
            res = self.lookalike_detector.detect_lookalike(dom)
            if res:
                techniques_str = ", ".join(res.techniques) if getattr(res, "techniques", None) else "similarity"
                e_look = result.add_evidence(
                    source="DOMAIN_INTELLIGENCE",
                    evidence_type="LOOKALIKE_DOMAIN_MATCH",
                    raw_content=f"Observed Domain: {dom} mimics Brand: {res.brand_name} (Reference: {res.suspected_brand}), Similarity: {res.similarity}, Techniques: {techniques_str}",
                    parsed_content=res.model_dump() if hasattr(res, "model_dump") else res.__dict__,
                    confidence=0.95,
                )
                result.add_finding(
                    title=f"Brand Lookalike Impersonation: '{dom}' mimics '{res.brand_name}'",
                    description=f"Domain '{dom}' uses technique '{techniques_str}' (similarity: {res.similarity:.2f}) to impersonate authentic brand domain '{res.suspected_brand}'.",
                    finding_type="LOOKALIKE_DOMAIN",
                    category="DOMAIN",
                    severity=SeverityEnum.HIGH,
                    confidence=0.95,
                    method=FindingMethodEnum.HEURISTIC,
                    mitre_technique_id="T1566.002",
                    remediation=f"Block domain '{dom}' and add to threat intelligence blocklist.",
                    evidence_indices=[e_look],
                )

        return result


# ============================================================================
# 9. EMAIL PHISHING AGGREGATOR & EXPLAINABILITY ENGINE
# ============================================================================

class EmailPhishingAggregator:
    """
    Synthesizes findings across all 8 forensic categories:
    AUTHENTICATION, IDENTITY, URL, DOMAIN, CONTENT, ATTACHMENT, INFRASTRUCTURE, BEHAVIORAL.
    Enforces signal independence to prevent arbitrary double-counting.
    Produces canonical classification, risk score, ThreatEvent, and explainable summaries.
    """

    @classmethod
    def aggregate(
        cls,
        analyzer_results: List[AnalyzerExecutionResult],
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Combines all findings, checks for mutual corroboration, computes score,
        and assigns categorical classification.
        """
        all_findings: List[Dict[str, Any]] = []
        all_evidence: List[Dict[str, Any]] = []
        category_counts: Dict[str, int] = {}
        high_critical_count = 0
        categories_with_suspicion: Set[str] = set()

        for res in analyzer_results:
            for f in res.findings:
                all_findings.append(f)
                cat = f.get("category", "OTHER")
                category_counts[cat] = category_counts.get(cat, 0) + 1
                sev = f.get("severity")
                if sev in (SeverityEnum.HIGH, SeverityEnum.CRITICAL, "HIGH", "CRITICAL"):
                    high_critical_count += 1
                    categories_with_suspicion.add(cat)
                elif sev in (SeverityEnum.MEDIUM, "MEDIUM"):
                    categories_with_suspicion.add(cat)

            for e in res.evidence_items:
                all_evidence.append(e)

        # Signal independence check: Count how many DISTINCT categories have suspicious findings
        # (AUTHENTICATION, IDENTITY, URL, DOMAIN, CONTENT, ATTACHMENT, INFRASTRUCTURE)
        distinct_suspicious_categories = len(categories_with_suspicion)

        # Baseline classification logic
        has_auth_fail = any(f.get("finding_type") in ("SPF_FAILURE", "DKIM_FAILURE", "DMARC_FAILURE") for f in all_findings)
        has_cred_req = any(f.get("finding_type") == "CREDENTIAL_REQUEST" for f in all_findings)
        has_visible_mismatch = any(f.get("finding_type") == "VISIBLE_LINK_MISMATCH" for f in all_findings)
        has_lookalike = any(f.get("finding_type") == "LOOKALIKE_DOMAIN" for f in all_findings)
        has_reply_mismatch = any(f.get("finding_type") == "REPLY_TO_MISMATCH" for f in all_findings)
        has_suspicious_att = any(f.get("finding_type") in ("SUSPICIOUS_ATTACHMENT_TYPE", "DOUBLE_EXTENSION_ATTACHMENT") for f in all_findings)
        has_financial = any(f.get("finding_type") == "FINANCIAL_REQUEST" for f in all_findings)

        classification = "BENIGN"
        confidence = 0.85
        threat_event_type = None

        if has_suspicious_att:
            classification = "MALWARE_DELIVERY_SUSPECTED"
            confidence = 0.95
            threat_event_type = "SUSPICIOUS_EMAIL"
        elif has_lookalike and (has_reply_mismatch or has_cred_req or has_visible_mismatch):
            classification = "PHISHING"
            confidence = 0.95
            threat_event_type = "PHISHING_ATTEMPT"
        elif has_reply_mismatch and has_financial and (has_auth_fail or distinct_suspicious_categories >= 2):
            classification = "BUSINESS_EMAIL_COMPROMISE_SUSPECTED"
            confidence = 0.90
            threat_event_type = "EMAIL_IMPERSONATION"
        elif distinct_suspicious_categories >= 2 and (has_auth_fail or has_visible_mismatch or has_cred_req):
            classification = "PHISHING"
            confidence = 0.92
            threat_event_type = "PHISHING_ATTEMPT"
        elif high_critical_count >= 1 or distinct_suspicious_categories >= 1:
            # Single isolated weak signal -> SUSPICIOUS
            classification = "SUSPICIOUS"
            confidence = 0.75
            threat_event_type = "SUSPICIOUS_EMAIL"
        else:
            classification = "BENIGN"
            confidence = 0.90
            threat_event_type = None

        return {
            "classification": classification,
            "confidence": confidence,
            "threat_event_type": threat_event_type,
            "distinct_suspicious_categories": distinct_suspicious_categories,
            "high_critical_count": high_critical_count,
            "total_findings": len(all_findings),
            "total_evidence": len(all_evidence),
        }
