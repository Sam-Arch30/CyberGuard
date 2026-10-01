"""
URL, Domain & Website Intelligence Modular Analyzers (Section 7).
Implements specialized, evidence-driven, SSRF-defended analyzers:
1. PassiveURLAnalyzer: Standards-aware URL structure analysis, userinfo, IP hosts, non-standard ports,
   excessive subdomains, punycode, suspicious paths/extensions, deceptive subdomain hierarchy.
2. DomainIntelligenceAnalyzer: Registrable domain extraction (Public Suffix List aware), IDN/punycode,
   lookalike domain detection, DNS infrastructure resolution (A, AAAA, MX, NS, TXT), registration/RDAP age,
   and cached threat intelligence.
3. SafeWebsiteAnalyzer: Controlled active HTTP inspection with SSRF gate enforcement, per-hop redirect tracking,
   TLS certificate analysis, and static HTML form/password credential-harvesting inspection.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import re
import socket
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlsplit, urlunsplit

import idna
import tldextract

from backend.db.models import (
    ArtifactModel,
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
)
from backend.services.safe_http_client import SafeHttpClient, SafeHttpResponse
from backend.services.website_inspector import WebsiteInspector, WebsiteInspectionResult
from backend.services.lookalike_detector import LookalikeDetectorService
from backend.services.dns_service import DNSService
from backend.services.rdap_service import RDAPService
from backend.services.threat_intelligence_service import ThreatIntelligenceService

logger = logging.getLogger("cyberguard.url_domain_analyzers")

# Known URL shortener hostnames
KNOWN_SHORTENERS: Set[str] = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "cutt.ly", "rebrand.ly", "tiny.cc", "shorturl.at",
    "adf.ly", "bit.do", "rb.gy", "lnkd.in", "snip.ly", "bl.ink",
}

# Suspicious path tokens
SUSPICIOUS_PATH_TOKENS: Set[str] = {
    "login", "signin", "sign-in", "log-in", "admin", "wp-admin",
    "account", "verify", "verification", "secure", "security",
    "update", "password", "credential", "banking", "auth",
}

# Suspicious executable or archive file extensions
SUSPICIOUS_EXTENSIONS: Set[str] = {
    ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".hta",
    ".apk", ".msi", ".iso", ".dmg", ".jar", ".zip", ".rar",
}

# Protected reference domains for contextual lookalike impersonation detection
PROTECTED_REFERENCE_DOMAINS: List[str] = [
    "paypal.com",
    "microsoft.com",
    "office.com",
    "google.com",
    "apple.com",
    "amazon.com",
    "netflix.com",
    "chase.com",
    "bankofamerica.com",
    "wellsfargo.com",
    "citibank.com",
    "dropbox.com",
    "docusign.com",
]


# ============================================================================
# ANALYZER EXECUTION CONTAINER
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


class BaseURLDomainAnalyzer(ABC):
    """Abstract base class for URL and domain intelligence analyzers."""

    name: str = "base_url_domain_analyzer"
    version: str = "1.0.0"
    supported_artifact_types: List[ArtifactTypeEnum] = [ArtifactTypeEnum.URL, ArtifactTypeEnum.DOMAIN]

    @abstractmethod
    async def analyze(self, raw_input: str, context: Dict[str, Any]) -> AnalyzerExecutionResult:
        """Executes analysis against raw URL or domain string with context."""
        pass


# ============================================================================
# 1. PASSIVE URL ANALYZER
# ============================================================================

class PassiveURLAnalyzer(BaseURLDomainAnalyzer):
    """
    Performs purely syntactic and structural inspection of URLs.
    Extracts standards-aware components (scheme, hostname, port, path, query, fragment, userinfo),
    identifies IP hosts, excessive subdomains, punycode, non-standard ports, and deceptive hierarchies.
    CRITICAL: Never initiates network connections.
    """
    name = "passive_url_analyzer"
    version = "1.0.0"
    supported_artifact_types = [ArtifactTypeEnum.URL]

    def __init__(self):
        self.tld_extractor = tldextract.TLDExtract(cache_dir=None)

    async def analyze(self, raw_input: str, context: Dict[str, Any]) -> AnalyzerExecutionResult:
        result = AnalyzerExecutionResult(self.name, self.version)
        original_url = raw_input.strip()

        if not original_url:
            result.errors.append("Empty URL provided for passive analysis")
            return result

        # Standards-aware parsing
        has_scheme = bool(re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', original_url))
        url_to_parse = original_url if has_scheme else f"http://{original_url}"

        try:
            parsed = urlsplit(url_to_parse)
        except Exception as e:
            result.add_finding(
                title="Malformed URL Syntax",
                description=f"The supplied URL cannot be parsed by standards-aware URL parser: {e}",
                finding_type="MALFORMED_URL",
                category="SYNTAX",
                severity=SeverityEnum.MEDIUM,
                confidence=1.0,
            )
            return result

        scheme = parsed.scheme.lower() if parsed.scheme else "http"
        raw_netloc = parsed.netloc
        path = parsed.path or "/"
        query = parsed.query
        fragment = parsed.fragment

        # Check for userinfo (username:password@host)
        userinfo: Optional[str] = None
        authority = raw_netloc
        if "@" in raw_netloc:
            parts = raw_netloc.split("@", 1)
            userinfo = parts[0]
            authority = parts[1]

        # Extract hostname and port
        port: Optional[int] = None
        hostname = authority
        if authority.startswith("["):
            # IPv6 literal [2001:db8::1]:8080
            bracket_end = authority.find("]")
            if bracket_end != -1:
                hostname = authority[1:bracket_end]
                remainder = authority[bracket_end + 1:]
                if remainder.startswith(":"):
                    try:
                        port = int(remainder[1:])
                    except ValueError:
                        pass
        elif ":" in authority:
            host_parts = authority.split(":", 1)
            hostname = host_parts[0]
            try:
                port = int(host_parts[1])
            except ValueError:
                pass

        clean_host = hostname.strip().lower()

        # Public suffix extraction
        ext = self.tld_extractor(clean_host)
        registrable_domain = f"{ext.domain}.{ext.suffix}".lower() if ext.domain and ext.suffix else clean_host
        subdomain = ext.subdomain.lower() if ext.subdomain else ""

        # Normalize URL
        normalized_url = normalize_url(original_url)

        # Record Structural Evidence
        ev_idx = result.add_evidence(
            source="PassiveURLAnalyzer",
            evidence_type="URL_STRUCTURAL_METADATA",
            raw_content=original_url,
            parsed_content={
                "original_url": original_url,
                "normalized_url": normalized_url,
                "scheme": scheme,
                "hostname": clean_host,
                "port": port,
                "path": path,
                "query": query,
                "fragment": fragment,
                "userinfo": userinfo,
                "registrable_domain": registrable_domain,
                "subdomain": subdomain,
            },
            confidence=1.0,
        )

        # Indicators
        result.add_indicator(
            indicator_type=IndicatorTypeEnum.URL,
            value=original_url,
            normalized_value=normalized_url,
            source="PassiveURLAnalyzer",
        )
        if clean_host:
            result.add_indicator(
                indicator_type=IndicatorTypeEnum.DOMAIN,
                value=clean_host,
                normalized_value=normalize_domain(clean_host),
                source="PassiveURLAnalyzer",
            )
            # Relationship: URL HAS_HOST DOMAIN
            result.add_relationship(
                source_id=normalized_url,
                source_type="URL",
                target_id=clean_host,
                target_type="DOMAIN",
                relationship_type=RelationshipTypeEnum.HAS_HOST,
                confidence=1.0,
            )

        # 1. Userinfo / Embedded Credentials Check
        if userinfo:
            result.add_finding(
                title="URL Contains Embedded Userinfo Credentials",
                description=f"The URL contains embedded authentication credentials or userinfo '{userinfo}' prior to the host.",
                finding_type="URL_USERINFO_PRESENT",
                category="CREDENTIAL_HARVESTING",
                severity=SeverityEnum.HIGH,
                confidence=1.0,
                mitre_technique_id="T1566.002",
                evidence_indices=[ev_idx],
            )

        # 2. IP-Literal Host Check
        is_ip_host = False
        try:
            ip_obj = ipaddress.ip_address(clean_host)
            is_ip_host = True
            ip_type_str = f"IPv{ip_obj.version}"
            result.add_indicator(
                indicator_type=IndicatorTypeEnum.IP,
                value=str(ip_obj),
                normalized_value=normalize_ip(str(ip_obj)),
                source="PassiveURLAnalyzer",
            )
            result.add_finding(
                title=f"{ip_type_str} Literal Used As Hostname",
                description=f"The URL specifies a raw {ip_type_str} address '{clean_host}' directly as its host instead of a registered domain.",
                finding_type="IP_LITERAL_HOST",
                category="INFRASTRUCTURE",
                severity=SeverityEnum.MEDIUM,
                confidence=1.0,
                mitre_technique_id="T1566.002",
                evidence_indices=[ev_idx],
            )
        except ValueError:
            is_ip_host = False

        # 3. Non-Standard Port Check
        if port is not None:
            standard_port = (scheme == "https" and port == 443) or (scheme == "http" and port == 80)
            if not standard_port:
                result.add_finding(
                    title="Non-Standard Network Port Specified",
                    description=f"The URL targets non-standard port {port} for scheme '{scheme}'.",
                    finding_type="NON_STANDARD_PORT",
                    category="INFRASTRUCTURE",
                    severity=SeverityEnum.LOW,
                    confidence=1.0,
                    evidence_indices=[ev_idx],
                )

        # 4. Excessive Subdomains Check
        if subdomain:
            subdomain_labels = [s for s in subdomain.split(".") if s]
            if len(subdomain_labels) >= 3:
                result.add_finding(
                    title="Excessive Subdomain Depth",
                    description=f"The hostname contains {len(subdomain_labels)} subdomain levels: '{subdomain}'.",
                    finding_type="EXCESSIVE_SUBDOMAINS",
                    category="STRUCTURAL",
                    severity=SeverityEnum.LOW,
                    confidence=0.85,
                    evidence_indices=[ev_idx],
                )

        # 5. Deceptive Subdomain Hierarchy (e.g. paypal.com.attacker.com)
        if subdomain and registrable_domain:
            for protected in PROTECTED_REFERENCE_DOMAINS:
                prot_clean = protected.lower()
                # Check if protected domain appears in subdomain labels (e.g., paypal.com.evil.com or secure-paypal-com.evil.com)
                if prot_clean in subdomain or prot_clean.replace(".", "-") in subdomain:
                    if registrable_domain != prot_clean:
                        result.add_finding(
                            title=f"Deceptive Subdomain Hierarchy Impersonating {protected}",
                            description=(
                                f"The subdomain contains brand name '{protected}' while the actual registered "
                                f"base domain is '{registrable_domain}'. This is a deceptive hostname technique."
                            ),
                            finding_type="DECEPTIVE_SUBDOMAIN_HIERARCHY",
                            category="IMPERSONATION",
                            severity=SeverityEnum.HIGH,
                            confidence=0.95,
                            mitre_technique_id="T1566.002",
                            evidence_indices=[ev_idx],
                        )
                        break

        # 6. IDN / Punycode Host Check
        if clean_host.startswith("xn--") or ".xn--" in clean_host:
            try:
                unicode_host = idna.decode(clean_host)
            except Exception:
                unicode_host = clean_host

            result.add_finding(
                title="Internationalized Domain Name (Punycode) Host",
                description=f"The hostname uses Punycode encoding '{clean_host}' (Unicode: '{unicode_host}').",
                finding_type="PUNYCODE_DOMAIN",
                category="STRUCTURAL",
                severity=SeverityEnum.LOW,
                confidence=1.0,
                evidence_indices=[ev_idx],
            )

        # 7. Suspicious Path Tokens
        path_lower = path.lower()
        matched_tokens = [tok for tok in SUSPICIOUS_PATH_TOKENS if tok in path_lower]
        if matched_tokens:
            result.add_finding(
                title="Suspicious Credential or Administrative Path Tokens",
                description=f"URL path contains security-sensitive tokens: {matched_tokens}",
                finding_type="SUSPICIOUS_PATH_TOKENS",
                category="SUSPICIOUS_STRUCTURE",
                severity=SeverityEnum.LOW,
                confidence=0.7,
                evidence_indices=[ev_idx],
            )

        # 8. Suspicious File Extension
        _, ext_suffix = os.path.splitext(path_lower)
        if ext_suffix in SUSPICIOUS_EXTENSIONS:
            result.add_finding(
                title=f"Suspicious Executable or Archive Extension ({ext_suffix})",
                description=f"URL path targets a potentially hazardous downloadable file extension: '{ext_suffix}'",
                finding_type="SUSPICIOUS_DOWNLOAD_EXTENSION",
                category="MALWARE_DELIVERY",
                severity=SeverityEnum.HIGH,
                confidence=0.9,
                mitre_technique_id="T1204.002",
                evidence_indices=[ev_idx],
            )

        # 9. Known Shortener
        if clean_host in KNOWN_SHORTENERS:
            result.add_finding(
                title="Known URL Shortening Service",
                description=f"The URL uses a known link shortener '{clean_host}' which masks the final destination.",
                finding_type="KNOWN_URL_SHORTENER",
                category="STRUCTURAL",
                severity=SeverityEnum.LOW,
                confidence=1.0,
                evidence_indices=[ev_idx],
            )

        # 10. Non-Web Scheme Passive Warning
        if scheme not in ("http", "https"):
            result.add_finding(
                title=f"Non-Web URL Scheme ({scheme})",
                description=f"The URL uses scheme '{scheme}'. Active network inspection is not supported for non-HTTP schemes.",
                finding_type="NON_HTTP_SCHEME",
                category="POLICY",
                severity=SeverityEnum.LOW,
                confidence=1.0,
                evidence_indices=[ev_idx],
            )

        result.metadata["parsed_components"] = {
            "scheme": scheme,
            "hostname": clean_host,
            "registrable_domain": registrable_domain,
            "subdomain": subdomain,
            "port": port,
            "path": path,
            "query": query,
            "userinfo": userinfo,
        }

        return result


# ============================================================================
# 2. DOMAIN INTELLIGENCE ANALYZER
# ============================================================================

class DomainIntelligenceAnalyzer(BaseURLDomainAnalyzer):
    """
    Analyzes domain infrastructure, registrable domain boundaries, IDN representations,
    lookalike domain similarity against protected targets, DNS resolution (A, AAAA, MX, NS, TXT),
    registration/RDAP metadata (domain age, redaction), and cached threat intelligence.
    """
    name = "domain_intelligence_analyzer"
    version = "1.0.0"
    supported_artifact_types = [ArtifactTypeEnum.DOMAIN, ArtifactTypeEnum.URL]

    def __init__(
        self,
        dns_service: Optional[DNSService] = None,
        rdap_service: Optional[RDAPService] = None,
        threat_intel_service: Optional[ThreatIntelligenceService] = None,
        lookalike_detector: Optional[LookalikeDetectorService] = None,
        protected_domains: Optional[List[str]] = None,
    ):
        self.tld_extractor = tldextract.TLDExtract(cache_dir=None)
        self.dns_service = dns_service or DNSService()
        self.rdap_service = rdap_service or RDAPService()
        self.threat_intel = threat_intel_service or ThreatIntelligenceService()
        self.lookalike_detector = lookalike_detector or LookalikeDetectorService()
        self.protected_domains = protected_domains or PROTECTED_REFERENCE_DOMAINS

    async def analyze(self, raw_input: str, context: Dict[str, Any]) -> AnalyzerExecutionResult:
        result = AnalyzerExecutionResult(self.name, self.version)
        clean_input = raw_input.strip()

        # Extract domain from URL or direct domain
        hostname = clean_input
        if "://" in clean_input:
            try:
                hostname = urlsplit(clean_input).hostname or clean_input
            except Exception:
                hostname = clean_input

        # Remove port and userinfo if present
        if "@" in hostname:
            hostname = hostname.split("@")[-1]
        if ":" in hostname and not hostname.startswith("["):
            hostname = hostname.split(":")[0]

        clean_host = hostname.strip().lower().rstrip(".").strip("[]")
        if not clean_host:
            result.errors.append("No valid domain/host extracted for domain analysis")
            return result

        # Check if clean_host is an IP literal
        is_ip = False
        try:
            ipaddress.ip_address(clean_host)
            is_ip = True
        except ValueError:
            is_ip = False

        if is_ip:
            # IP literal: create IP indicator and skip domain-specific lookups
            result.add_indicator(
                indicator_type=IndicatorTypeEnum.IP,
                value=clean_host,
                normalized_value=normalize_ip(clean_host),
                source="DomainIntelligenceAnalyzer",
            )
            return result

        # 1. Registrable Domain & Subdomain Extraction
        ext = self.tld_extractor(clean_host)
        registrable_domain = f"{ext.domain}.{ext.suffix}".lower() if ext.domain and ext.suffix else clean_host
        subdomain = ext.subdomain.lower() if ext.subdomain else ""

        # Punycode / IDN encoding
        ascii_host, punycode_rep = self.dns_service.normalize_and_punycode(clean_host)
        try:
            unicode_host = idna.decode(ascii_host)
        except Exception:
            unicode_host = clean_host

        is_idn = (punycode_rep is not None or clean_host != unicode_host)

        # Record Domain Metadata Evidence
        dom_ev = result.add_evidence(
            source="DomainIntelligenceAnalyzer",
            evidence_type="DOMAIN_METADATA",
            raw_content=clean_host,
            parsed_content={
                "hostname": clean_host,
                "registrable_domain": registrable_domain,
                "subdomain": subdomain,
                "ascii_host": ascii_host,
                "unicode_host": unicode_host,
                "is_idn": is_idn,
            },
            confidence=1.0,
        )

        result.add_indicator(
            indicator_type=IndicatorTypeEnum.DOMAIN,
            value=clean_host,
            normalized_value=normalize_domain(clean_host),
            source="DomainIntelligenceAnalyzer",
        )
        if registrable_domain != clean_host:
            result.add_indicator(
                indicator_type=IndicatorTypeEnum.DOMAIN,
                value=registrable_domain,
                normalized_value=normalize_domain(registrable_domain),
                source="DomainIntelligenceAnalyzer",
            )

        # 2. Lookalike Domain Impersonation Detection
        # Analyzes registrable_domain against configured protected targets
        lookalike_res = self.lookalike_detector.detect_lookalike(registrable_domain)
        if lookalike_res is not None:
            result.add_finding(
                title=f"Lookalike Domain Detected Impersonating {lookalike_res.suspected_brand}",
                description=(
                    f"Domain '{registrable_domain}' is a lookalike of protected reference domain '{lookalike_res.suspected_brand}'. "
                    f"Techniques: {', '.join(lookalike_res.techniques)} "
                    f"(Similarity Score: {lookalike_res.similarity:.2f})."
                ),
                finding_type="LOOKALIKE_DOMAIN",
                category="IMPERSONATION",
                severity=SeverityEnum.HIGH,
                confidence=float(lookalike_res.similarity),
                mitre_technique_id="T1566.002",
                evidence_indices=[dom_ev],
                metadata={
                    "reference_domain": lookalike_res.suspected_brand,
                    "candidate_domain": registrable_domain,
                    "similarity_score": lookalike_res.similarity,
                    "techniques": lookalike_res.techniques,
                    "details": lookalike_res.details,
                },
            )

        # 3. DNS Analysis (A, AAAA, MX, NS, TXT)
        dns_records = await self.dns_service.resolve_all(clean_host)
        dns_ev = result.add_evidence(
            source="DNSService",
            evidence_type="DNS_RECORDS",
            raw_content=clean_host,
            parsed_content={
                "a": dns_records.a,
                "aaaa": dns_records.aaaa,
                "mx": dns_records.mx,
                "ns": dns_records.ns,
                "txt": dns_records.txt,
                "errors": getattr(dns_records, "errors", {}),
            },
            confidence=1.0,
        )

        # Process A / AAAA Records -> DOMAIN RESOLVES_TO IP
        resolved_ips = dns_records.a + dns_records.aaaa
        for ip in resolved_ips:
            norm_ip = normalize_ip(ip)
            result.add_indicator(
                indicator_type=IndicatorTypeEnum.IP,
                value=ip,
                normalized_value=norm_ip,
                source="DNSService",
            )
            result.add_relationship(
                source_id=clean_host,
                source_type="DOMAIN",
                target_id=norm_ip,
                target_type="IP",
                relationship_type=RelationshipTypeEnum.RESOLVES_TO,
                confidence=1.0,
            )

        # Process MX Records -> DOMAIN MAIL_EXCHANGER DOMAIN
        for mx in dns_records.mx:
            # mx is format "10 mail.example.com"
            parts = mx.strip().split()
            mx_host = parts[-1].rstrip(".").lower() if parts else ""
            if mx_host:
                result.add_indicator(
                    indicator_type=IndicatorTypeEnum.DOMAIN,
                    value=mx_host,
                    normalized_value=normalize_domain(mx_host),
                    source="DNSService_MX",
                )
                result.add_relationship(
                    source_id=clean_host,
                    source_type="DOMAIN",
                    target_id=mx_host,
                    target_type="DOMAIN",
                    relationship_type=RelationshipTypeEnum.MAIL_EXCHANGER,
                    confidence=1.0,
                )

        # Process NS Records -> DOMAIN USES_NAMESERVER DOMAIN
        for ns in dns_records.ns:
            ns_host = ns.strip().rstrip(".").lower()
            if ns_host:
                result.add_indicator(
                    indicator_type=IndicatorTypeEnum.DOMAIN,
                    value=ns_host,
                    normalized_value=normalize_domain(ns_host),
                    source="DNSService_NS",
                )
                result.add_relationship(
                    source_id=clean_host,
                    source_type="DOMAIN",
                    target_id=ns_host,
                    target_type="DOMAIN",
                    relationship_type=RelationshipTypeEnum.USES_NAMESERVER,
                    confidence=1.0,
                )

        # 4. Domain Registration Metadata (RDAP / WHOIS)
        try:
            reg_info = await self.rdap_service.lookup(registrable_domain)
            reg_ev = result.add_evidence(
                source="RDAPService",
                evidence_type="DOMAIN_REGISTRATION_DATA",
                raw_content=registrable_domain,
                parsed_content={
                    "registrar": reg_info.registrar,
                    "registration_date": reg_info.registration_date,
                    "expiration_date": reg_info.expiration_date,
                    "is_redacted": getattr(reg_info, "is_redacted", False),
                    "source": getattr(reg_info, "registration_source", getattr(reg_info, "source", "RDAP")),
                },
                confidence=0.9,
            )

            # Check domain age
            if reg_info.registration_date:
                # Calculate age
                age_days = self._calculate_age(reg_info.registration_date)
                if age_days is not None and age_days <= 30:
                    result.add_finding(
                        title=f"Recently Registered Domain ({age_days} Days Old)",
                        description=(
                            f"Domain '{registrable_domain}' was created recently on {reg_info.registration_date} "
                            f"({age_days} days old). Recently registered infrastructure is frequently abused in phishing."
                        ),
                        finding_type="RECENTLY_REGISTERED_DOMAIN",
                        category="INFRASTRUCTURE",
                        severity=SeverityEnum.MEDIUM,
                        confidence=0.85,
                        mitre_technique_id="T1583.001",
                        evidence_indices=[reg_ev],
                    )

            if getattr(reg_info, "is_redacted", False):
                result.add_finding(
                    title="Domain Registrant Privacy Redacted",
                    description=f"WHOIS/RDAP registrant information for '{registrable_domain}' is withheld by privacy protection service.",
                    finding_type="REGISTRATION_DATA_REDACTED",
                    category="OBSERVATION",
                    severity=SeverityEnum.SAFE,
                    confidence=1.0,
                    evidence_indices=[reg_ev],
                )

        except Exception as exc:
            logger.debug(f"RDAP lookup failed for {registrable_domain}: {exc}")

        # 5. Threat Intelligence
        threat_results = await self.threat_intel.lookup_domain(clean_host)
        for ti in threat_results:
            ti_ev = result.add_evidence(
                source=ti.provider,
                evidence_type="THREAT_INTELLIGENCE",
                raw_content=ti.query,
                parsed_content={
                    "provider": ti.provider,
                    "verdict": ti.verdict,
                    "confidence": ti.confidence,
                    "is_malicious": ti.is_malicious,
                    "is_rate_limited": ti.is_rate_limited,
                    "retrieved_at": ti.retrieved_at,
                    "expires_at": ti.expires_at,
                },
                confidence=ti.confidence,
            )

            if ti.is_rate_limited:
                result.add_finding(
                    title=f"Threat Intelligence Provider Rate Limited ({ti.provider})",
                    description=f"Threat intelligence query for '{clean_host}' was rate-limited by {ti.provider}.",
                    finding_type="THREAT_INTEL_RATE_LIMITED",
                    category="THREAT_INTELLIGENCE",
                    severity=SeverityEnum.LOW,
                    confidence=1.0,
                    evidence_indices=[ti_ev],
                )
            elif ti.is_malicious:
                result.add_finding(
                    title=f"Threat Intelligence Match: Known Malicious Domain ({ti.provider})",
                    description=f"Domain '{clean_host}' is flagged as {ti.verdict} by threat intelligence provider {ti.provider}.",
                    finding_type="THREAT_INTELLIGENCE_MATCH",
                    category="THREAT_INTELLIGENCE",
                    severity=SeverityEnum.CRITICAL,
                    confidence=ti.confidence,
                    mitre_technique_id="T1566.002",
                    evidence_indices=[ti_ev],
                )

        result.metadata["clean_host"] = clean_host
        result.metadata["registrable_domain"] = registrable_domain
        result.metadata["resolved_ips"] = resolved_ips
        return result

    @staticmethod
    def _calculate_age(date_str: str) -> Optional[int]:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z"):
            try:
                dt = datetime.strptime(date_str.strip().replace("Z", "+00:00"), fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                return max(0, (now - dt).days)
            except Exception:
                pass
        return None


# ============================================================================
# 3. SAFE WEBSITE ANALYZER
# ============================================================================

class SafeWebsiteAnalyzer(BaseURLDomainAnalyzer):
    """
    Performs controlled, observational HTTP inspection of safe external web targets.
    Enforces SSRF boundary defenses, inspects redirect chains, verifies TLS certificates,
    and runs static HTML parsing for login forms, password inputs, and cross-domain credential harvesting.
    CRITICAL: Never executes JavaScript or submits forms.
    """
    name = "safe_website_analyzer"
    version = "1.0.0"
    supported_artifact_types = [ArtifactTypeEnum.URL]

    def __init__(
        self,
        safe_client: Optional[SafeHttpClient] = None,
        active_analysis_enabled: bool = True,
    ):
        self.safe_client = safe_client or SafeHttpClient()
        self.active_analysis_enabled = active_analysis_enabled

    async def analyze(self, raw_input: str, context: Dict[str, Any]) -> AnalyzerExecutionResult:
        result = AnalyzerExecutionResult(self.name, self.version)
        url = raw_input.strip()

        # Check Active Analysis Configuration
        config_enabled = context.get("url_active_analysis_enabled", self.active_analysis_enabled)
        if not config_enabled:
            result.add_finding(
                title="Active Website Analysis Disabled by Policy",
                description="Active network HTTP fetching is disabled in the engine configuration. Passive analysis completed cleanly.",
                finding_type="ACTIVE_ANALYSIS_DISABLED",
                category="POLICY",
                severity=SeverityEnum.SAFE,
                confidence=1.0,
            )
            return result

        # Check scheme: only HTTP and HTTPS can be actively inspected
        try:
            parsed_scheme = urlsplit(url).scheme.lower()
        except Exception:
            parsed_scheme = ""

        if parsed_scheme not in ("http", "https"):
            result.add_finding(
                title=f"Scheme '{parsed_scheme}' Not Supported for Active Inspection",
                description=f"Active HTTP fetching is only permitted for HTTP and HTTPS schemes. Scheme '{parsed_scheme}' was skipped.",
                finding_type="ACTIVE_INSPECTION_SKIPPED_SCHEME",
                category="POLICY",
                severity=SeverityEnum.SAFE,
                confidence=1.0,
            )
            return result

        # Execute Controlled HTTP Inspection via SafeHttpClient
        logger.info(f"Initiating controlled active fetch for URL: {url}")
        http_resp: SafeHttpResponse = await self.safe_client.fetch_url(url, method="GET")

        # 1. SSRF Safety Gate Check
        if not http_resp.is_safe_destination:
            ev_ssrf = result.add_evidence(
                source="SafeHttpClient",
                evidence_type="SSRF_GATE_BLOCK",
                raw_content=url,
                parsed_content={
                    "blocked_reason": http_resp.blocked_reason,
                    "blocked_ip": http_resp.blocked_ip,
                    "url": url,
                    "final_url": http_resp.final_url,
                },
                confidence=1.0,
            )
            result.add_finding(
                title="Outbound Request Prohibited by SSRF Safety Gate",
                description=(
                    f"Outbound connection attempt to '{url}' was blocked by network safety controls. "
                    f"Reason: {http_resp.blocked_reason} (Target IP: {http_resp.blocked_ip or 'unresolved'})."
                ),
                finding_type="BLOCKED_INTERNAL_DESTINATION",
                category="SECURITY_BOUNDARY",
                severity=SeverityEnum.CRITICAL,
                confidence=1.0,
                mitre_technique_id="T1566.002",
                evidence_indices=[ev_ssrf],
            )
            return result

        # 2. Connection Failure / Timeout Handling
        if http_resp.error and http_resp.status_code == 0:
            result.add_finding(
                title="HTTP Connection Attempt Failed or Timed Out",
                description=f"Active inspection could not connect to '{url}': {http_resp.error}",
                finding_type="HTTP_CONNECTION_FAILED",
                category="INFRASTRUCTURE",
                severity=SeverityEnum.LOW,
                confidence=1.0,
            )
            return result

        # Record HTTP Response Evidence
        http_ev = result.add_evidence(
            source="SafeHttpClient",
            evidence_type="HTTP_RESPONSE_METADATA",
            raw_content=url,
            parsed_content={
                "initial_url": http_resp.url,
                "final_url": http_resp.final_url,
                "status_code": http_resp.status_code,
                "content_type": http_resp.content_type,
                "response_size": http_resp.response_size,
                "is_truncated": http_resp.is_truncated,
                "latency_ms": http_resp.latency_ms,
                "headers": {k: v for k, v in http_resp.headers.items() if k.lower() in ("server", "content-type", "location", "set-cookie")},
            },
            confidence=1.0,
        )

        # 3. Redirect Chain Analysis
        if http_resp.redirect_chain:
            chain_details = []
            for hop in http_resp.redirect_chain:
                chain_details.append({
                    "hop": hop.hop_index,
                    "source": hop.source_url,
                    "destination": hop.destination_url,
                    "status": hop.status_code,
                    "is_cross_domain": hop.is_cross_domain,
                })
                # Relationship: URL REDIRECTS_TO URL
                result.add_relationship(
                    source_id=hop.source_url,
                    source_type="URL",
                    target_id=hop.destination_url,
                    target_type="URL",
                    relationship_type=RelationshipTypeEnum.REDIRECTS_TO,
                    confidence=1.0,
                )

                if hop.is_cross_domain:
                    result.add_finding(
                        title=f"Redirect Across Different Domains (Hop {hop.hop_index})",
                        description=f"URL redirects from domain '{hop.source_domain}' to unrelated domain '{hop.destination_domain}'.",
                        finding_type="REDIRECT_TO_DIFFERENT_DOMAIN",
                        category="INFRASTRUCTURE",
                        severity=SeverityEnum.MEDIUM,
                        confidence=0.9,
                        mitre_technique_id="T1566.002",
                        evidence_indices=[http_ev],
                    )

            if len(http_resp.redirect_chain) >= 3:
                result.add_finding(
                    title=f"Multi-Hop Redirect Chain ({len(http_resp.redirect_chain)} Hops)",
                    description=f"Destination URL underwent {len(http_resp.redirect_chain)} redirection hops before reaching final content.",
                    finding_type="SUSPICIOUS_REDIRECT",
                    category="INFRASTRUCTURE",
                    severity=SeverityEnum.LOW,
                    confidence=0.8,
                    evidence_indices=[http_ev],
                )

        # 4. TLS Certificate Analysis
        if http_resp.tls:
            tls = http_resp.tls
            tls_ev = result.add_evidence(
                source="SafeHttpClient",
                evidence_type="TLS_CERTIFICATE_METADATA",
                raw_content=url,
                parsed_content={
                    "is_valid": tls.is_valid,
                    "subject_cn": tls.subject_cn,
                    "issuer_cn": tls.issuer_cn,
                    "valid_from": tls.valid_from,
                    "valid_until": tls.valid_until,
                    "has_expired": tls.has_expired,
                    "is_self_signed": tls.is_self_signed,
                    "protocol_version": tls.protocol_version,
                    "error_type": tls.error_type,
                },
                confidence=1.0,
            )

            if not tls.is_valid:
                err_type = tls.error_type or "TLS_VERIFICATION_FAILED"
                result.add_finding(
                    title=f"TLS Certificate Error: {err_type}",
                    description=f"TLS certificate validation failed for '{url}': {tls.error_message}",
                    finding_type="TLS_CERTIFICATE_ERROR",
                    category="INFRASTRUCTURE",
                    severity=SeverityEnum.HIGH if err_type != "EXPIRED_CERTIFICATE" else SeverityEnum.MEDIUM,
                    confidence=1.0,
                    evidence_indices=[tls_ev],
                )
            elif tls.is_self_signed:
                result.add_finding(
                    title="Self-Signed TLS Certificate Observed",
                    description=f"Destination presents a self-signed certificate issued to '{tls.subject_cn}'.",
                    finding_type="SELF_SIGNED_CERTIFICATE",
                    category="INFRASTRUCTURE",
                    severity=SeverityEnum.MEDIUM,
                    confidence=1.0,
                    evidence_indices=[tls_ev],
                )

        # 5. Static HTML & Form Analysis
        is_html = "text/html" in http_resp.content_type.lower() or http_resp.content_text.strip().lower().startswith(("<html", "<!doctype"))
        if is_html and http_resp.content_text:
            web_result: WebsiteInspectionResult = WebsiteInspector.inspect_html(http_resp.final_url, http_resp.content_text)

            html_ev = result.add_evidence(
                source="WebsiteInspector",
                evidence_type="STATIC_HTML_METADATA",
                raw_content=http_resp.final_url,
                parsed_content={
                    "title": web_result.title,
                    "has_login_form": web_result.has_login_form,
                    "has_password_field": web_result.has_password_field,
                    "has_cross_domain_form": web_result.has_cross_domain_form,
                    "cross_domain_form_actions": web_result.cross_domain_form_actions,
                    "external_links_count": web_result.external_links_count,
                    "brand_mentions": web_result.brand_mentions,
                    "download_count": len(web_result.download_candidates),
                },
                confidence=1.0,
            )

            # Password Field Presence
            if web_result.has_password_field:
                result.add_finding(
                    title="Password Input Field Detected on Webpage",
                    description="Static HTML inspection discovered one or more password input fields (`<input type='password'>`).",
                    finding_type="PASSWORD_FIELD_DETECTED",
                    category="CREDENTIAL_HARVESTING",
                    severity=SeverityEnum.MEDIUM,
                    confidence=1.0,
                    mitre_technique_id="T1056",
                    evidence_indices=[html_ev],
                )

            # Login Form Presence
            if web_result.has_login_form:
                result.add_finding(
                    title="Login Authentication Form Present",
                    description="Webpage contains an interactive login or authentication interface.",
                    finding_type="LOGIN_FORM_DETECTED",
                    category="CREDENTIAL_HARVESTING",
                    severity=SeverityEnum.LOW,
                    confidence=0.9,
                    evidence_indices=[html_ev],
                )

            # Cross-Domain Form Submission Destination
            if web_result.has_cross_domain_form:
                for action_url in web_result.cross_domain_form_actions:
                    result.add_finding(
                        title="Form Action Submits to Cross-Domain Target",
                        description=f"HTML form on domain '{web_result.base_domain}' posts credentials/data to an unrelated domain '{action_url}'.",
                        finding_type="CROSS_DOMAIN_FORM_ACTION",
                        category="CREDENTIAL_HARVESTING",
                        severity=SeverityEnum.HIGH,
                        confidence=0.95,
                        mitre_technique_id="T1056",
                        evidence_indices=[html_ev],
                    )
                    # Relationship: WEBPAGE SUBMITS_TO URL
                    result.add_relationship(
                        source_id=http_resp.final_url,
                        source_type="URL",
                        target_id=action_url,
                        target_type="URL",
                        relationship_type=RelationshipTypeEnum.SUBMITS_TO,
                        confidence=1.0,
                    )

            # Combined Credential Harvesting Indicator
            if web_result.has_password_field and (web_result.has_cross_domain_form or web_result.brand_mentions):
                brands = ", ".join(web_result.brand_mentions) if web_result.brand_mentions else "None"
                result.add_finding(
                    title="Strong Credential Harvesting Indicators Discovered",
                    description=(
                        f"Page exhibits high-confidence credential-harvesting characteristics: "
                        f"Password field present with brand mentions ({brands}) "
                        f"and/or cross-domain form submission."
                    ),
                    finding_type="CREDENTIAL_HARVESTING_INDICATORS",
                    category="CREDENTIAL_HARVESTING",
                    severity=SeverityEnum.CRITICAL if web_result.has_cross_domain_form else SeverityEnum.HIGH,
                    confidence=0.95,
                    mitre_technique_id="T1056",
                    evidence_indices=[html_ev],
                )

            # Download Candidates
            for dl in web_result.download_candidates:
                result.add_indicator(
                    indicator_type=IndicatorTypeEnum.URL,
                    value=dl.resolved_url,
                    normalized_value=normalize_url(dl.resolved_url),
                    source="WebsiteInspector_Download",
                )
                result.add_relationship(
                    source_id=http_resp.final_url,
                    source_type="URL",
                    target_id=dl.resolved_url,
                    target_type="URL",
                    relationship_type=RelationshipTypeEnum.REFERENCES,
                    confidence=1.0,
                )

        return result
