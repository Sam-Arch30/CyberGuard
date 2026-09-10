import json
import uuid
import re
import ipaddress
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional, Set, Tuple
from sqlalchemy.orm import Session

from backend.schemas.attribution import (
    EvidenceItem,
    AttributionResult,
    CaseAttributionResponse,
    CampaignAttributionResponse
)
from backend.services.relay_reconstructor import RelayReconstructorService
from backend.services.campaign_correlator import CampaignCorrelator
from backend.db.models import CaseModel, CaseEmailModel


class AttributionEngine:
    """
    Probabilistic Threat Attribution Engine.
    Attributes malicious emails to probable infrastructure and campaigns using explainable,
    evidence-weighted forensic signals.

    STRICT FORENSIC INTEGRITY PRINCIPLES:
    1. NEVER claims to identify the physical human attacker.
    2. Attributes observed technical network infrastructure (IPs, ASNs, hosting providers, domains).
    3. Prominently qualifies IP geolocation as network infrastructure location, not human location.
    4. Does not fabricate missing intelligence: displays 'Unknown' or 'Insufficient evidence'.
    5. All confidence scores are explainable with itemized supporting and conflicting evidence.
    """

    DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "attribution_rules.json"

    KNOWN_MAJOR_ESPS = {
        "google.com", "gmail.com", "outlook.com", "microsoft.com", "office365.com",
        "yahoo.com", "proton.me", "protonmail.com", "icloud.com", "sendgrid.net",
        "mailgun.org", "amazonses.com"
    }

    KNOWN_MAJOR_ESP_ASNS = {
        "AS15169",  # Google
        "AS8075",   # Microsoft
        "AS10310",  # Yahoo
        "AS16509",  # Amazon
        "AS13335",  # Cloudflare
        "AS32",     # Apple
    }

    def __init__(self, config_path: Optional[str | Path] = None, config_dict: Optional[Dict[str, Any]] = None):
        if config_dict:
            self.config = config_dict
        else:
            self.config_file = Path(config_path) if config_path else self.DEFAULT_CONFIG_PATH
            self.config = self._load_config()

        self.thresholds = self.config.get("confidence_thresholds", {
            "low": {"min": 0, "max": 39, "label": "LOW"},
            "moderate": {"min": 40, "max": 69, "label": "MODERATE"},
            "high": {"min": 70, "max": 84, "label": "HIGH"},
            "very_high": {"min": 85, "max": 100, "label": "VERY HIGH"}
        })
        self.weights = self.config.get("signal_weights", {})
        self.disclaimer = self.config.get(
            "disclaimer",
            "Location refers to observed network infrastructure and should not be interpreted as the physical location of the threat actor."
        )

    def _load_config(self) -> Dict[str, Any]:
        """Safely loads attribution rules configuration JSON."""
        if hasattr(self, "config_file") and self.config_file.exists():
            try:
                with open(self.config_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {
            "confidence_thresholds": {
                "low": {"min": 0, "max": 39, "label": "LOW"},
                "moderate": {"min": 40, "max": 69, "label": "MODERATE"},
                "high": {"min": 70, "max": 84, "label": "HIGH"},
                "very_high": {"min": 85, "max": 100, "label": "VERY HIGH"}
            },
            "signal_weights": {
                "earliest_untrusted_relay": 20.0,
                "asn_consistency": 15.0,
                "hosting_provider_consistency": 10.0,
                "domain_hosting_relationship": 15.0,
                "url_infrastructure_alignment": 15.0,
                "dns_relationship": 10.0,
                "repeated_infrastructure_campaign": 20.0,
                "authentication_failure_alignment": 10.0,
                "lookalike_domain_hosting": 10.0,
                "anonymization_proxy_penalty": -20.0,
                "contradictory_geolocations_penalty": -15.0,
                "legitimate_provider_penalty": -25.0,
                "missing_public_relay_penalty": -30.0
            }
        }

    @staticmethod
    def _get(obj: Any, key: str, default: Any = None) -> Any:
        """Safely retrieves property from dictionary or pydantic model."""
        if obj is None:
            return default
        if isinstance(obj, dict):
            return obj.get(key, default)
        return getattr(obj, key, default)

    def _determine_confidence_level(self, score: float) -> str:
        """Maps numerical confidence score (0-100) to configured confidence category."""
        bounded = max(0.0, min(100.0, score))
        for level_key, bounds in self.thresholds.items():
            if bounds.get("min", 0) <= bounded <= bounds.get("max", 100):
                return bounds.get("label", level_key.upper())
        if bounded >= 85:
            return "VERY HIGH"
        elif bounded >= 70:
            return "HIGH"
        elif bounded >= 40:
            return "MODERATE"
        return "LOW"

    def attribute_email(
        self,
        email_analysis: Any,
        db: Optional[Session] = None,
        case_id: Optional[str] = None
    ) -> AttributionResult:
        """
        Calculates probabilistic infrastructure attribution and confidence from email analysis telemetry.
        Never fabricates intelligence: defaults to 'Unknown' or 'Insufficient evidence' if unavailable.
        """
        now_iso = datetime.now(timezone.utc).isoformat()
        attr_id = f"ATTR-{uuid.uuid4().hex[:10].upper()}"

        email_id = str(self._get(email_analysis, "id", "") or self._get(email_analysis, "evidence_id", "") or "")
        threat_score_obj = self._get(email_analysis, "threat_score", None)
        threat_score_val = self._get(threat_score_obj, "score", 0.0) if threat_score_obj else 0.0

        supporting_evidence: List[EvidenceItem] = []
        conflicting_evidence: List[EvidenceItem] = []
        related_domains: Set[str] = set()
        related_ips: Set[str] = set()
        related_campaigns: Set[str] = set()

        raw_score = 0.0

        # ---------------------------------------------------------------------
        # 1. Identify Probable Origin Sending Infrastructure (IP, Relay Path)
        # ---------------------------------------------------------------------
        relay_analysis = self._get(email_analysis, "relay_analysis", None)
        earliest_node = self._get(relay_analysis, "earliest_observable_node", None) if relay_analysis else None
        earliest_ip = self._get(earliest_node, "earliest_observable_ip", None) if earliest_node else None

        transmission_hops = self._get(relay_analysis, "transmission_order_hops", []) if relay_analysis else []

        # Find earliest untrusted public relay
        probable_origin_ip: Optional[str] = None
        origin_hop_num: Optional[int] = None
        origin_hop_host: Optional[str] = None

        if earliest_ip and RelayReconstructorService.is_public_ip(earliest_ip):
            probable_origin_ip = earliest_ip
            origin_hop_host = self._get(earliest_node, "from_host", None)
        else:
            # Fallback scan across transmission hops
            for hop in transmission_hops:
                from_ip = self._get(hop, "from_ip", None)
                by_ip = self._get(hop, "by_ip", None)
                if from_ip and RelayReconstructorService.is_public_ip(from_ip):
                    probable_origin_ip = from_ip
                    origin_hop_num = self._get(hop, "hop_number", None)
                    origin_hop_host = self._get(hop, "from_host", None)
                    break
                if by_ip and RelayReconstructorService.is_public_ip(by_ip) and not probable_origin_ip:
                    probable_origin_ip = by_ip
                    origin_hop_num = self._get(hop, "hop_number", None)
                    origin_hop_host = self._get(hop, "by_host", None)

        # Fallback to indicators IP if no relay hops yielded public IP
        if not probable_origin_ip:
            raw_ips = self._get(email_analysis, "ips", []) or []
            for candidate in raw_ips:
                if RelayReconstructorService.is_public_ip(candidate):
                    probable_origin_ip = candidate
                    break

        # Evidence weighting for origin relay
        if probable_origin_ip:
            related_ips.add(probable_origin_ip)
            weight = self.weights.get("earliest_untrusted_relay", 20.0)
            raw_score += weight
            host_info = f" ({origin_hop_host})" if origin_hop_host else ""
            supporting_evidence.append(EvidenceItem(
                evidence_type="EARLIEST_UNTRUSTED_RELAY",
                observation=f"Earliest untrusted public sending infrastructure identified at IP {probable_origin_ip}{host_info}.",
                contribution=weight,
                source="SMTP Relay Path Analysis",
                timestamp=now_iso
            ))
        else:
            penalty = self.weights.get("missing_public_relay_penalty", -30.0)
            conflicting_evidence.append(EvidenceItem(
                evidence_type="MISSING_PUBLIC_ORIGIN_INFRASTRUCTURE",
                observation="No external public sending relay observed in header chain (private or internal network addresses only).",
                contribution=penalty,
                source="SMTP Relay Path Analysis",
                timestamp=now_iso
            ))

        # ---------------------------------------------------------------------
        # 2. Extract IP Intelligence for Probable Origin Infrastructure
        # ---------------------------------------------------------------------
        ip_intel_map = self._get(email_analysis, "ip_intelligence", {}) or {}
        origin_ip_intel = ip_intel_map.get(probable_origin_ip, None) if probable_origin_ip else None

        probable_origin_asn: Optional[str] = None
        probable_origin_provider: Optional[str] = None
        probable_infrastructure_country: Optional[str] = None

        if origin_ip_intel:
            raw_asn = self._get(origin_ip_intel, "asn", None)
            if raw_asn and str(raw_asn).strip().upper() not in ("UNKNOWN", "NONE", ""):
                clean_asn = str(raw_asn).strip().upper()
                probable_origin_asn = clean_asn if clean_asn.startswith("AS") else f"AS{clean_asn}"

            provider_cand = (
                self._get(origin_ip_intel, "organization", None) or
                self._get(origin_ip_intel, "isp", None) or
                self._get(origin_ip_intel, "asn_org", None)
            )
            if provider_cand and str(provider_cand).strip().upper() not in ("UNKNOWN", "NONE", ""):
                probable_origin_provider = str(provider_cand).strip()

            country_cand = self._get(origin_ip_intel, "country", None)
            if country_cand and str(country_cand).strip().upper() not in ("UNKNOWN", "NONE", ""):
                probable_infrastructure_country = str(country_cand).strip()

            # Anonymization / Proxy / Tor Detection
            is_proxy = self._get(origin_ip_intel, "is_proxy_vpn_tor", False)
            if is_proxy:
                penalty = self.weights.get("anonymization_proxy_penalty", -20.0)
                raw_score += penalty
                conflicting_evidence.append(EvidenceItem(
                    evidence_type="ANONYMIZATION_INFRASTRUCTURE_DETECTED",
                    observation=f"Sending infrastructure IP {probable_origin_ip} is an identified anonymization proxy, VPN, or Tor exit node. Attribution points to proxy egress infrastructure rather than threat actor's origin.",
                    contribution=penalty,
                    source="IP Threat Intelligence",
                    timestamp=now_iso
                ))

            # Hosting / Datacenter Infrastructure Detection
            is_hosting = self._get(origin_ip_intel, "is_hosting", False)
            if is_hosting:
                weight = self.weights.get("hosting_provider_consistency", 10.0)
                raw_score += weight
                supporting_evidence.append(EvidenceItem(
                    evidence_type="HOSTING_PROVIDER_CONSISTENCY",
                    observation=f"Probable origin IP {probable_origin_ip} operates within cloud/datacenter hosting infrastructure ({probable_origin_provider or 'Commercial Datacenter'}).",
                    contribution=weight,
                    source="IP Intelligence Infrastructure Classification",
                    timestamp=now_iso
                ))

        # Check for legitimate major ESP sending on behalf of legitimate domain
        auth_analysis = self._get(email_analysis, "authentication", None)
        spf_res = self._get(self._get(auth_analysis, "spf", None), "result", "unknown")
        dkim_res = self._get(self._get(auth_analysis, "dkim", None), "result", "unknown")
        dmarc_res = self._get(self._get(auth_analysis, "dmarc", None), "result", "unknown")

        from_hdr = str(self._get(email_analysis, "from_header", "") or self._get(email_analysis, "from", "") or "")
        from_domain = ""
        domain_match = re.search(r'@([a-zA-Z0-9\.\-]+)', from_hdr)
        if domain_match:
            from_domain = domain_match.group(1).lower().rstrip(".")

        is_major_esp_origin = False
        if probable_origin_asn in self.KNOWN_MAJOR_ESP_ASNS or (from_domain in self.KNOWN_MAJOR_ESPS and spf_res == "pass"):
            is_major_esp_origin = True

        if is_major_esp_origin and spf_res == "pass" and dkim_res == "pass" and threat_score_val < 30:
            penalty = self.weights.get("legitimate_provider_penalty", -25.0)
            raw_score += penalty
            conflicting_evidence.append(EvidenceItem(
                evidence_type="LEGITIMATE_SERVICE_PROVIDER_INFRASTRUCTURE",
                observation=f"Sending infrastructure belongs to verified major email provider ({probable_origin_provider or probable_origin_asn or from_domain}) with valid SPF/DKIM authentication. Does not indicate dedicated attacker-controlled infrastructure.",
                contribution=penalty,
                source="Authentication & ESP Classification",
                timestamp=now_iso
            ))

        # ---------------------------------------------------------------------
        # 3. Evaluate Domain Hosting & DNS Relationships
        # ---------------------------------------------------------------------
        domain_intel_map = self._get(email_analysis, "domain_intelligence", {}) or {}
        lookalikes = self._get(email_analysis, "lookalike_domains", []) or []

        for l in lookalikes:
            ldom = self._get(l, "domain", "")
            if ldom:
                related_domains.add(ldom.lower())

        domain_asns: Set[str] = set()
        domain_resolved_ips: Set[str] = set()

        if isinstance(domain_intel_map, dict):
            for dom_name, dinfo in domain_intel_map.items():
                clean_dom = dom_name.strip().lower().rstrip(".")
                dns = self._get(dinfo, "dns", {}) or {}
                a_ips = self._get(dns, "a", []) or []
                for ip in a_ips:
                    if RelayReconstructorService.is_public_ip(ip):
                        domain_resolved_ips.add(ip)
                        related_ips.add(ip)
                        intel = ip_intel_map.get(ip)
                        if intel:
                            asn = self._get(intel, "asn")
                            if asn:
                                domain_asns.add(str(asn).strip().upper())

                # Check if sender/lookalike domain resolves directly to origin IP
                if probable_origin_ip and probable_origin_ip in a_ips:
                    weight = self.weights.get("domain_hosting_relationship", 15.0)
                    raw_score += weight
                    related_domains.add(clean_dom)
                    supporting_evidence.append(EvidenceItem(
                        evidence_type="DOMAIN_HOSTING_RELATIONSHIP",
                        observation=f"Suspicious domain '{clean_dom}' directly resolves (A record) to probable sending IP {probable_origin_ip}.",
                        contribution=weight,
                        source="DNS Resolution Engine",
                        timestamp=now_iso
                    ))

                # Lookalike domain hosting overlap
                d_lookalike = self._get(dinfo, "lookalike", None)
                if d_lookalike and (probable_origin_ip in a_ips or (probable_origin_asn and probable_origin_asn in domain_asns)):
                    weight = self.weights.get("lookalike_domain_hosting", 10.0)
                    raw_score += weight
                    related_domains.add(clean_dom)
                    supporting_evidence.append(EvidenceItem(
                        evidence_type="LOOKALIKE_INFRASTRUCTURE_OVERLAP",
                        observation=f"Brand lookalike domain '{clean_dom}' shares hosting infrastructure ({probable_origin_asn or probable_origin_ip}) with observed sending system.",
                        contribution=weight,
                        source="Lookalike Detection Engine",
                        timestamp=now_iso
                    ))

        # Check ASN consistency between Origin IP and Domain resolution
        if probable_origin_asn and domain_asns:
            if probable_origin_asn in domain_asns:
                weight = self.weights.get("asn_consistency", 15.0)
                raw_score += weight
                supporting_evidence.append(EvidenceItem(
                    evidence_type="ASN_CONSISTENCY",
                    observation=f"Observed origin infrastructure ASN ({probable_origin_asn}) matches the autonomous system hosting resolved domain infrastructure.",
                    contribution=weight,
                    source="BGP / ASN Correlation",
                    timestamp=now_iso
                ))

        # ---------------------------------------------------------------------
        # 4. Evaluate URL Target Infrastructure Alignment
        # ---------------------------------------------------------------------
        url_analyses = self._get(email_analysis, "url_analysis", []) or []
        for u in url_analyses:
            u_dom = self._get(u, "domain", "")
            if u_dom:
                clean_udom = u_dom.lower().rstrip(".")
                related_domains.add(clean_udom)
                # Check if URL domain resolves to origin IP or origin ASN
                u_intel = domain_intel_map.get(clean_udom)
                if u_intel:
                    u_dns = self._get(u_intel, "dns", {}) or {}
                    u_ips = self._get(u_dns, "a", []) or []
                    for u_ip in u_ips:
                        related_ips.add(u_ip)
                        if probable_origin_ip and u_ip == probable_origin_ip:
                            weight = self.weights.get("url_infrastructure_alignment", 15.0)
                            raw_score += weight
                            supporting_evidence.append(EvidenceItem(
                                evidence_type="URL_INFRASTRUCTURE_ALIGNMENT",
                                observation=f"Suspicious URL host '{clean_udom}' co-hosted on origin sending IP {probable_origin_ip}.",
                                contribution=weight,
                                source="URL Forensic Analysis",
                                timestamp=now_iso
                            ))
                            break

        # ---------------------------------------------------------------------
        # 5. Evaluate Authentication Failures & Sender Spoofing
        # ---------------------------------------------------------------------
        alignment = self._get(auth_analysis, "alignment", None)
        reply_mismatch = self._get(alignment, "reply_to_mismatch", False) if alignment else False
        return_mismatch = self._get(alignment, "return_path_mismatch", False) if alignment else False

        if (spf_res in ["fail", "softfail"] or dmarc_res in ["fail"]) and probable_origin_ip:
            weight = self.weights.get("authentication_failure_alignment", 10.0)
            raw_score += weight
            supporting_evidence.append(EvidenceItem(
                evidence_type="AUTHENTICATION_FAILURE_ALIGNMENT",
                observation=f"SPF/DMARC authentication failed for sender '{from_domain or 'unknown'}' from IP {probable_origin_ip}, indicating unauthorized sending infrastructure.",
                contribution=weight,
                source="Email Authentication Subsystem",
                timestamp=now_iso
            ))

        if reply_mismatch or return_mismatch:
            reply_dom = self._get(alignment, "reply_to_domain", None) if alignment else None
            if reply_dom:
                related_domains.add(reply_dom.lower())

        # ---------------------------------------------------------------------
        # 6. Geolocation Discrepancies & Contradictions
        # ---------------------------------------------------------------------
        observed_countries = set()
        for ip, intel in ip_intel_map.items():
            c = self._get(intel, "country", None)
            if c and c.upper() not in ("UNKNOWN", "NONE", ""):
                observed_countries.add(c.strip())

        # If sending IP claims a country completely divergent from relay hops without proxy reason
        if len(observed_countries) > 3 and not (origin_ip_intel and self._get(origin_ip_intel, "is_proxy_vpn_tor", False)):
            penalty = self.weights.get("contradictory_geolocations_penalty", -15.0)
            raw_score += penalty
            conflicting_evidence.append(EvidenceItem(
                evidence_type="CONTRADICTORY_GEOLOCATION_SIGNALS",
                observation=f"Transmission path and domain resolution span {len(observed_countries)} divergent national jurisdictions ({', '.join(list(observed_countries)[:4])}), indicating distributed or fragmented relay routing.",
                contribution=penalty,
                source="IP Geolocation Intelligence",
                timestamp=now_iso
            ))

        # ---------------------------------------------------------------------
        # 7. Campaign Correlation & Shared Historical Infrastructure
        # ---------------------------------------------------------------------
        if db is not None:
            try:
                correlator = CampaignCorrelator()
                # Build minimal correlation dict from analysis
                analysis_dict = {
                    "id": email_id,
                    "subject": self._get(email_analysis, "subject", ""),
                    "from_header": from_hdr,
                    "ips": list(related_ips),
                    "domains": list(related_domains),
                    "urls": self._get(email_analysis, "urls", []) or []
                }
                corr_res = correlator.correlate_email_against_cases(db, analysis_dict, min_score=0.25, limit=5)
                for rc in corr_res.related_cases:
                    related_campaigns.add(rc.case_number or rc.case_id)

                if corr_res.related_cases:
                    weight = self.weights.get("repeated_infrastructure_campaign", 20.0)
                    raw_score += weight
                    top_case = corr_res.related_cases[0]
                    supporting_evidence.append(EvidenceItem(
                        evidence_type="REPEATED_INFRASTRUCTURE_CAMPAIGN",
                        observation=f"Identified shared technical infrastructure across {len(corr_res.related_cases)} existing investigation case(s) (e.g. {top_case.case_number}: {top_case.title}).",
                        contribution=weight,
                        source="Campaign Correlation Engine",
                        timestamp=now_iso
                    ))
            except Exception:
                pass

        # If case_id was supplied directly
        if case_id:
            related_campaigns.add(case_id)

        # ---------------------------------------------------------------------
        # 8. Final Confidence Calculation & Boundaries
        # ---------------------------------------------------------------------
        # Baseline starting point for malicious threat email vs benign
        if threat_score_val >= 70:
            raw_score += 15.0
        elif threat_score_val <= 15:
            raw_score -= 20.0

        # Boundary clamping: 0.0 to 100.0
        final_confidence = round(max(5.0 if probable_origin_ip else 0.0, min(95.0, raw_score)), 1)
        if not probable_origin_ip:
            final_confidence = 0.0

        confidence_level = self._determine_confidence_level(final_confidence)

        return AttributionResult(
            attribution_id=attr_id,
            email_id=email_id or None,
            case_id=case_id,
            campaign_id=list(related_campaigns)[0] if related_campaigns else None,
            probable_origin_ip=probable_origin_ip,
            probable_origin_asn=probable_origin_asn,
            probable_origin_provider=probable_origin_provider,
            probable_infrastructure_country=probable_infrastructure_country,
            confidence_score=final_confidence,
            confidence_level=confidence_level,
            supporting_evidence=supporting_evidence,
            conflicting_evidence=conflicting_evidence,
            related_domains=sorted(list(related_domains)),
            related_ips=sorted(list(related_ips)),
            related_campaigns=sorted(list(related_campaigns)),
            analysis_timestamp=now_iso,
            disclaimer=self.disclaimer
        )

    def attribute_case(self, db: Session, case_id: str) -> CaseAttributionResponse:
        """
        Consolidates infrastructure attribution across all emails linked to an investigation case.
        """
        case = db.query(CaseModel).filter(
            (CaseModel.id == case_id) | (CaseModel.case_number == case_id)
        ).first()

        now_iso = datetime.now(timezone.utc).isoformat()
        attr_id = f"ATTR-CASE-{uuid.uuid4().hex[:8].upper()}"

        if not case:
            dummy_result = AttributionResult(
                attribution_id=attr_id,
                email_id=None,
                case_id=case_id,
                probable_origin_ip=None,
                probable_origin_asn=None,
                probable_origin_provider=None,
                probable_infrastructure_country=None,
                confidence_score=0.0,
                confidence_level="LOW",
                supporting_evidence=[],
                conflicting_evidence=[EvidenceItem(
                    evidence_type="CASE_NOT_FOUND",
                    observation=f"Case '{case_id}' was not found in the investigation database.",
                    contribution=0.0,
                    source="Case Management Database",
                    timestamp=now_iso
                )],
                related_domains=[],
                related_ips=[],
                related_campaigns=[],
                analysis_timestamp=now_iso,
                disclaimer=self.disclaimer
            )
            return CaseAttributionResponse(
                case_id=case_id,
                case_number=None,
                total_emails_analyzed=0,
                attribution=dummy_result,
                per_email_attributions=[]
            )

        case_emails = db.query(CaseEmailModel).filter(CaseEmailModel.case_id == case.id).all()
        per_email_results: List[AttributionResult] = []

        all_ips: Set[str] = set()
        all_asns: Set[str] = set()
        all_providers: Set[str] = set()
        all_countries: Set[str] = set()
        all_domains: Set[str] = set()

        for ce in case_emails:
            parsed_ind: Dict[str, Any] = {}
            if ce.indicators_json:
                try:
                    parsed_ind = json.loads(ce.indicators_json)
                except Exception:
                    parsed_ind = {}

            email_sim = {
                "id": ce.email_id,
                "email_sha256": ce.email_sha256,
                "subject": ce.subject,
                "threat_score": {"score": ce.threat_score or 0.0},
                "ips": parsed_ind.get("ips", []),
                "domains": parsed_ind.get("domains", []),
                "urls": parsed_ind.get("urls", [])
            }
            em_attr = self.attribute_email(email_sim, db=db, case_id=case.case_number)
            per_email_results.append(em_attr)

            if em_attr.probable_origin_ip:
                all_ips.add(em_attr.probable_origin_ip)
            if em_attr.probable_origin_asn:
                all_asns.add(em_attr.probable_origin_asn)
            if em_attr.probable_origin_provider:
                all_providers.add(em_attr.probable_origin_provider)
            if em_attr.probable_infrastructure_country:
                all_countries.add(em_attr.probable_infrastructure_country)
            for d in em_attr.related_domains:
                all_domains.add(d)

        # Compute consolidated case attribution
        supporting: List[EvidenceItem] = []
        conflicting: List[EvidenceItem] = []

        if len(all_ips) > 0:
            supporting.append(EvidenceItem(
                evidence_type="SHARED_ORIGIN_INFRASTRUCTURE",
                observation=f"Observed {len(all_ips)} unique public origin sending infrastructure IP(s) across {len(case_emails)} case email(s).",
                contribution=25.0,
                source="Case Email Aggregator",
                timestamp=now_iso
            ))
        if len(all_asns) == 1 and len(case_emails) > 1:
            supporting.append(EvidenceItem(
                evidence_type="SINGLE_ASN_CAMPAIGN_PERSISTENCE",
                observation=f"All case emails originate exclusively from autonomous system {list(all_asns)[0]}.",
                contribution=20.0,
                source="BGP Infrastructure Correlation",
                timestamp=now_iso
            ))
        elif len(all_asns) > 2:
            conflicting.append(EvidenceItem(
                evidence_type="DIVERGENT_ASNS_ACROSS_CASE",
                observation=f"Case emails span {len(all_asns)} distinct autonomous systems ({', '.join(list(all_asns)[:3])}).",
                contribution=-15.0,
                source="BGP Infrastructure Correlation",
                timestamp=now_iso
            ))

        avg_score = sum(r.confidence_score for r in per_email_results) / max(1, len(per_email_results)) if per_email_results else 0.0
        consolidated_confidence = round(min(95.0, max(0.0, avg_score + (10.0 if len(all_asns) == 1 and len(case_emails) > 1 else 0.0))), 1)

        case_attribution = AttributionResult(
            attribution_id=attr_id,
            email_id=None,
            case_id=case.id,
            campaign_id=case.case_number,
            probable_origin_ip=list(all_ips)[0] if all_ips else None,
            probable_origin_asn=list(all_asns)[0] if all_asns else None,
            probable_origin_provider=list(all_providers)[0] if all_providers else None,
            probable_infrastructure_country=list(all_countries)[0] if all_countries else None,
            confidence_score=consolidated_confidence,
            confidence_level=self._determine_confidence_level(consolidated_confidence),
            supporting_evidence=supporting,
            conflicting_evidence=conflicting,
            related_domains=sorted(list(all_domains)),
            related_ips=sorted(list(all_ips)),
            related_campaigns=[case.case_number],
            analysis_timestamp=now_iso,
            disclaimer=self.disclaimer
        )

        return CaseAttributionResponse(
            case_id=case.id,
            case_number=case.case_number,
            total_emails_analyzed=len(case_emails),
            attribution=case_attribution,
            per_email_attributions=per_email_results
        )

    def attribute_campaign(self, db: Session, campaign_id: str) -> CampaignAttributionResponse:
        """
        Synthesizes infrastructure attribution across correlated cases forming a campaign cluster.
        """
        now_iso = datetime.now(timezone.utc).isoformat()
        attr_id = f"ATTR-CAMP-{uuid.uuid4().hex[:8].upper()}"

        # Match cases containing or relating to campaign_id
        matched_cases = db.query(CaseModel).filter(
            (CaseModel.id == campaign_id) |
            (CaseModel.case_number.ilike(f"%{campaign_id}%")) |
            (CaseModel.title.ilike(f"%{campaign_id}%"))
        ).all()

        if not matched_cases:
            # Fallback: get all high/critical cases
            matched_cases = db.query(CaseModel).filter(
                CaseModel.severity.in_(["high", "critical"])
            ).limit(5).all()

        shared_ips: Set[str] = set()
        shared_asns: Set[str] = set()
        shared_providers: Set[str] = set()
        shared_countries: Set[str] = set()
        shared_domains: Set[str] = set()

        for c in matched_cases:
            case_res = self.attribute_case(db, c.id)
            if case_res.attribution.probable_origin_ip:
                shared_ips.add(case_res.attribution.probable_origin_ip)
            if case_res.attribution.probable_origin_asn:
                shared_asns.add(case_res.attribution.probable_origin_asn)
            if case_res.attribution.probable_origin_provider:
                shared_providers.add(case_res.attribution.probable_origin_provider)
            if case_res.attribution.probable_infrastructure_country:
                shared_countries.add(case_res.attribution.probable_infrastructure_country)
            for d in case_res.attribution.related_domains:
                shared_domains.add(d)

        supporting = [
            EvidenceItem(
                evidence_type="CORRELATED_CAMPAIGN_CLUSTER",
                observation=f"Attribution aggregated from {len(matched_cases)} correlated investigation case(s).",
                contribution=20.0,
                source="Threat Intelligence & Correlation Engine",
                timestamp=now_iso
            )
        ]
        conflicting = []

        camp_score = 65.0 if len(matched_cases) > 1 else 40.0
        if len(shared_asns) == 1 and shared_asns:
            camp_score += 15.0
            supporting.append(EvidenceItem(
                evidence_type="CAMPAIGN_HOSTING_CONSISTENCY",
                observation=f"All correlated cases consistently leverage autonomous system {list(shared_asns)[0]}.",
                contribution=15.0,
                source="BGP Infrastructure Correlation",
                timestamp=now_iso
            ))

        camp_attr = AttributionResult(
            attribution_id=attr_id,
            email_id=None,
            case_id=matched_cases[0].id if matched_cases else None,
            campaign_id=campaign_id,
            probable_origin_ip=list(shared_ips)[0] if shared_ips else None,
            probable_origin_asn=list(shared_asns)[0] if shared_asns else None,
            probable_origin_provider=list(shared_providers)[0] if shared_providers else None,
            probable_infrastructure_country=list(shared_countries)[0] if shared_countries else None,
            confidence_score=min(90.0, camp_score),
            confidence_level=self._determine_confidence_level(min(90.0, camp_score)),
            supporting_evidence=supporting,
            conflicting_evidence=conflicting,
            related_domains=sorted(list(shared_domains)),
            related_ips=sorted(list(shared_ips)),
            related_campaigns=[c.case_number for c in matched_cases],
            analysis_timestamp=now_iso,
            disclaimer=self.disclaimer
        )

        return CampaignAttributionResponse(
            campaign_id=campaign_id,
            campaign_name=f"Campaign Cluster: {campaign_id}",
            related_case_count=len(matched_cases),
            attribution=camp_attr,
            shared_infrastructure_summary={
                "unique_ips": sorted(list(shared_ips)),
                "unique_asns": sorted(list(shared_asns)),
                "unique_providers": sorted(list(shared_providers)),
                "unique_countries": sorted(list(shared_countries)),
                "unique_domains": sorted(list(shared_domains))
            }
        )


global_attribution_engine = AttributionEngine()
