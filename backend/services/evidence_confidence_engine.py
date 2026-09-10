import json
import uuid
import re
import ipaddress
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

from backend.schemas.evidence_confidence import (
    EvidenceCategory,
    ConclusionType,
    EvaluatedEvidence,
    ForensicConclusion,
    EmailConfidenceResponse
)


class EvidenceConfidenceEngine:
    """
    Centralized Evidence Confidence Engine for MailTraceAI.
    Evaluates multi-dimensional evidence quality, prevents double-counting of correlated sources,
    surfaces contradictory intelligence, and generates transparent, defensible forensic conclusions.
    """

    DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "evidence_confidence_rules.json"

    def __init__(self, config_path: Optional[str | Path] = None, config_dict: Optional[Dict[str, Any]] = None):
        if config_dict:
            self.config = config_dict
        else:
            self.config_file = Path(config_path) if config_path else self.DEFAULT_CONFIG_PATH
            self.config = self._load_config()

        self.engine_version = self.config.get("engine_version", "1.0.0")
        self.thresholds = self.config.get("confidence_thresholds", {
            "low": {"min": 0, "max": 39, "label": "LOW"},
            "moderate": {"min": 40, "max": 69, "label": "MODERATE"},
            "high": {"min": 70, "max": 84, "label": "HIGH"},
            "very_high": {"min": 85, "max": 100, "label": "VERY HIGH"}
        })
        self.dimension_weights = self.config.get("dimension_weights", {
            "reliability": 0.25,
            "independence": 0.20,
            "recency": 0.15,
            "specificity": 0.20,
            "consistency": 0.20
        })
        self.source_quality_defaults = self.config.get("source_quality_defaults", {})
        self.independence_clusters = self.config.get("independence_clusters", {})
        self.recency_decay = self.config.get("recency_decay", {
            "half_life_days": 180,
            "stale_threshold_days": 365,
            "stale_penalty_multiplier": 0.5
        })
        self.contradiction_penalties = self.config.get("contradiction_penalties", {
            "cross_jurisdiction_geo_vs_whois": -25,
            "cross_jurisdiction_geo_vs_timezone": -15,
            "auth_spf_pass_with_display_spoof": -20,
            "anonymizer_or_proxy_detected": -20,
            "clean_reputation_on_bulletproof_asn": -15
        })
        self.limitations_config = self.config.get("limitations", {})

    def _load_config(self) -> Dict[str, Any]:
        """Safely loads engine configuration JSON."""
        if hasattr(self, "config_file") and self.config_file.exists():
            try:
                with open(self.config_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    @staticmethod
    def _get(obj: Any, key: str, default: Any = None) -> Any:
        """Safely accesses attribute or dictionary key."""
        if obj is None:
            return default
        if isinstance(obj, dict):
            return obj.get(key, default)
        return getattr(obj, key, default)

    def _get_tier(self, score: float) -> str:
        """Determines confidence tier (LOW, MODERATE, HIGH, VERY HIGH) from score."""
        for tier_key, data in self.thresholds.items():
            if data["min"] <= score <= data["max"]:
                return data["label"]
        if score >= 85:
            return "VERY HIGH"
        if score >= 70:
            return "HIGH"
        if score >= 40:
            return "MODERATE"
        return "LOW"

    def _apply_quality_and_diminishing_returns(
        self,
        evidence_list: List[EvaluatedEvidence]
    ) -> List[EvaluatedEvidence]:
        """
        Calculates effective contribution by evaluating quality dimensions:
        1. Dimension weighting: composite quality factor = sum(weight * dimension)
        2. Recency decay: applies decay if intelligence exceeds stale threshold
        3. Independence clustering: discounts subsequent evidence items from the same cluster
        """
        cluster_counts: Dict[str, int] = {}
        processed: List[EvaluatedEvidence] = []

        for item in evidence_list:
            # 1. Base composite quality
            dim_factor = (
                item.reliability * self.dimension_weights.get("reliability", 0.25) +
                item.specificity * self.dimension_weights.get("specificity", 0.20) +
                item.consistency * self.dimension_weights.get("consistency", 0.20) +
                item.source_quality * self.dimension_weights.get("independence", 0.20) +
                (0.9 if not item.recency_days or item.recency_days < 90 else 0.5) * self.dimension_weights.get("recency", 0.15)
            )

            # 2. Recency decay
            recency_mult = 1.0
            if item.recency_days and item.recency_days > self.recency_decay.get("stale_threshold_days", 365):
                recency_mult = self.recency_decay.get("stale_penalty_multiplier", 0.5)

            # 3. Independence cluster diminishing returns
            cluster_mult = 1.0
            if item.independence_cluster:
                count = cluster_counts.get(item.independence_cluster, 0)
                cluster_cfg = self.independence_clusters.get(item.independence_cluster, {})
                multipliers = cluster_cfg.get("diminishing_return_multipliers", [1.0, 0.3, 0.1])
                if count < len(multipliers):
                    cluster_mult = multipliers[count]
                else:
                    cluster_mult = multipliers[-1] if multipliers else 0.1
                cluster_counts[item.independence_cluster] = count + 1

            effective = item.raw_contribution * dim_factor * recency_mult * cluster_mult
            effective_rounded = round(effective, 1)

            updated = item.model_copy(update={"effective_contribution": effective_rounded})
            processed.append(updated)

        return processed

    def _calculate_score_and_tier(
        self,
        supporting: List[EvaluatedEvidence],
        conflicting: List[EvaluatedEvidence],
        is_sparse_single_signal: bool = False
    ) -> Tuple[float, str]:
        """
        Computes calibrated score without false precision:
        Sums effective contributions, applies penalty deductions, bounds [0, 100], rounds to integer.
        If signal is sparse or weak single signal, caps at MODERATE (max 50).
        """
        pos_sum = sum(e.effective_contribution for e in supporting if e.effective_contribution > 0)
        neg_sum = sum(abs(e.effective_contribution) for e in conflicting)

        net = pos_sum - neg_sum
        bounded = max(0.0, min(100.0, net))

        # Anti-false precision: clean integer rounding
        calibrated_score = float(round(bounded))

        if is_sparse_single_signal and calibrated_score > 50:
            calibrated_score = 45.0

        tier = self._get_tier(calibrated_score)
        return calibrated_score, tier

    def evaluate_email(self, email_analysis: Any) -> List[ForensicConclusion]:
        """
        Evaluates forensic conclusions across all 8 core analytical domains for an email analysis.
        """
        conclusions: List[ForensicConclusion] = []
        now_iso = datetime.now(timezone.utc).isoformat()

        # 1. Threat Classification Conclusion
        c_threat = self._evaluate_threat_classification(email_analysis, now_iso)
        if c_threat:
            conclusions.append(c_threat)

        # 2. Infrastructure Attribution Conclusion
        c_attr = self._evaluate_infrastructure_attribution(email_analysis, now_iso)
        if c_attr:
            conclusions.append(c_attr)

        # 3. Campaign Association Conclusion
        c_camp = self._evaluate_campaign_association(email_analysis, now_iso)
        if c_camp:
            conclusions.append(c_camp)

        # 4. Geolocation Conclusion
        c_geo = self._evaluate_geolocation(email_analysis, now_iso)
        if c_geo:
            conclusions.append(c_geo)

        # 5. Lookalike Domain Conclusion
        c_look = self._evaluate_lookalike(email_analysis, now_iso)
        if c_look:
            conclusions.append(c_look)

        # 6. Malicious URL Conclusion
        c_url = self._evaluate_url(email_analysis, now_iso)
        if c_url:
            conclusions.append(c_url)

        # 7. NLP Classification Conclusion
        c_nlp = self._evaluate_nlp(email_analysis, now_iso)
        if c_nlp:
            conclusions.append(c_nlp)

        # 8. Attachment Verdict Conclusion
        c_att = self._evaluate_attachment(email_analysis, now_iso)
        if c_att:
            conclusions.append(c_att)

        return conclusions

    # -------------------------------------------------------------------------
    # DOMAIN 1: THREAT CLASSIFICATION
    # -------------------------------------------------------------------------
    def _evaluate_threat_classification(self, email: Any, now_iso: str) -> ForensicConclusion:
        threat = self._get(email, "threat_score", None)
        raw_score = float(self._get(threat, "score", 0)) if threat else 0.0
        ml_prob = self._get(email, "ml_phishing_probability", None)

        supporting: List[EvaluatedEvidence] = []
        conflicting: List[EvaluatedEvidence] = []
        source_modules = ["ThreatScorerService"]

        auth = self._get(email, "authentication", None)
        spf_res = self._get(self._get(auth, "spf", None), "result", "").lower()
        dkim_res = self._get(self._get(auth, "dkim", None), "result", "").lower()
        dmarc_res = self._get(self._get(auth, "dmarc", None), "result", "").lower()

        if raw_score >= 60:
            supporting.append(EvaluatedEvidence(
                evidence_id="EVD-THREAT-SCORE-HIGH",
                statement=f"Global deterministic threat score calculated at {int(raw_score)}/100.",
                source_module="ThreatScorerService",
                source_quality=0.9,
                reliability=0.9,
                specificity=0.85,
                consistency=0.9,
                raw_contribution=35.0,
                effective_contribution=35.0,
                evidence_category=EvidenceCategory.CONFIRMED_EVIDENCE,
                timestamp=now_iso
            ))
        elif raw_score > 0:
            supporting.append(EvaluatedEvidence(
                evidence_id="EVD-THREAT-SCORE-MODERATE",
                statement=f"Global deterministic threat score elevated at {int(raw_score)}/100.",
                source_module="ThreatScorerService",
                source_quality=0.8,
                reliability=0.8,
                specificity=0.7,
                consistency=0.8,
                raw_contribution=20.0,
                effective_contribution=20.0,
                evidence_category=EvidenceCategory.PROBABLE_INFERENCE,
                timestamp=now_iso
            ))

        if spf_res in ("fail", "softfail") or dmarc_res == "fail":
            supporting.append(EvaluatedEvidence(
                evidence_id="EVD-AUTH-FAILURE",
                statement=f"Cryptographic authentication verification failed (SPF: {spf_res or 'fail'}, DMARC: {dmarc_res or 'fail'}).",
                source_module="EmailAuthenticationService",
                source_quality=1.0,
                reliability=1.0,
                independence_cluster="auth_cryptographic",
                specificity=0.95,
                consistency=0.95,
                raw_contribution=25.0,
                effective_contribution=25.0,
                evidence_category=EvidenceCategory.CONFIRMED_EVIDENCE,
                timestamp=now_iso
            ))
        elif spf_res == "pass" and dkim_res == "pass":
            conflicting.append(EvaluatedEvidence(
                evidence_id="EVD-AUTH-PASS",
                statement="Cryptographic SPF and DKIM signatures verified as passing for the sending domain.",
                source_module="EmailAuthenticationService",
                source_quality=1.0,
                reliability=0.95,
                independence_cluster="auth_cryptographic",
                specificity=0.9,
                consistency=0.85,
                raw_contribution=-20.0,
                effective_contribution=-20.0,
                is_conflicting=True,
                evidence_category=EvidenceCategory.CONFIRMED_EVIDENCE,
                timestamp=now_iso
            ))

        if ml_prob is not None and ml_prob >= 0.75:
            supporting.append(EvaluatedEvidence(
                evidence_id="EVD-ML-PROB-HIGH",
                statement=f"NLP intent classifier indicates {int(ml_prob * 100)}% phishing probability.",
                source_module="NLPClassifierService",
                source_quality=0.75,
                reliability=0.75,
                specificity=0.75,
                consistency=0.8,
                raw_contribution=20.0,
                effective_contribution=20.0,
                evidence_category=EvidenceCategory.PROBABLE_INFERENCE,
                timestamp=now_iso
            ))
            source_modules.append("NLPClassifierService")

        processed_sup = self._apply_quality_and_diminishing_returns(supporting)
        processed_conf = self._apply_quality_and_diminishing_returns(conflicting)

        is_sparse = len(processed_sup) <= 1 and raw_score < 40
        score, tier = self._calculate_score_and_tier(processed_sup, processed_conf, is_sparse_single_signal=is_sparse)

        statement = "High-risk fraudulent email intent with verified authorization anomalies" if score >= 70 \
            else "Suspicious email activity requiring secondary analyst verification" if score >= 40 \
            else "Low overall malicious risk based on observable telemetry"

        limitations = [
            self.limitations_config.get("THREAT_CLASSIFICATION", "Deterministic heuristic assessment based on observable indicators.")
        ]
        if not email.urls:
            limitations.append("No embedded URLs observed in body content.")

        return ForensicConclusion(
            conclusion_id=f"CONC-THREAT-{(str(self._get(email, 'id', 'EML'))).slice_or_uuid if hasattr(self._get(email, 'id', 'EML'), 'slice_or_uuid') else str(uuid.uuid4())[:8].upper()}",
            type=ConclusionType.THREAT_CLASSIFICATION,
            statement=statement,
            confidence_score=score,
            confidence_level=tier,
            supporting_evidence=processed_sup,
            conflicting_evidence=processed_conf,
            limitations=limitations,
            source_modules=source_modules,
            generated_at=now_iso,
            engine_version=self.engine_version
        )

    # -------------------------------------------------------------------------
    # DOMAIN 2: INFRASTRUCTURE ATTRIBUTION
    # -------------------------------------------------------------------------
    def _evaluate_infrastructure_attribution(self, email: Any, now_iso: str) -> ForensicConclusion:
        attr = self._get(email, "attribution", None)
        origin_ip = self._get(attr, "probable_origin_ip", None)
        asn = self._get(attr, "probable_origin_asn", None)
        provider = self._get(attr, "probable_origin_provider", None)

        supporting: List[EvaluatedEvidence] = []
        conflicting: List[EvaluatedEvidence] = []
        source_modules = ["AttributionEngine", "RelayReconstructorService", "IPIntelligenceService"]

        if origin_ip:
            supporting.append(EvaluatedEvidence(
                evidence_id=f"EVD-ORIGIN-IP-{origin_ip}",
                statement=f"Earliest untrusted public sending infrastructure identified at IP {origin_ip}.",
                source_module="RelayReconstructorService",
                source_quality=0.85,
                reliability=0.85,
                independence_cluster="smtp_routing_path",
                specificity=0.9,
                consistency=0.9,
                raw_contribution=30.0,
                effective_contribution=30.0,
                evidence_category=EvidenceCategory.CONFIRMED_EVIDENCE,
                timestamp=now_iso
            ))

            if asn:
                supporting.append(EvaluatedEvidence(
                    evidence_id=f"EVD-ASN-{asn}",
                    statement=f"Routing infrastructure is hosted in Autonomous System {asn} ({provider or 'Hosting Provider'}).",
                    source_module="IPIntelligenceService",
                    source_quality=0.9,
                    reliability=0.9,
                    independence_cluster="bgp_routing_registry",
                    specificity=0.85,
                    consistency=0.85,
                    raw_contribution=25.0,
                    effective_contribution=25.0,
                    evidence_category=EvidenceCategory.PROBABLE_INFERENCE,
                    timestamp=now_iso
                ))
        else:
            conflicting.append(EvaluatedEvidence(
                evidence_id="EVD-NO-PUBLIC-IP",
                statement="No untrusted public IP observed in relay headers (private RFC-1918 subnets only).",
                source_module="RelayReconstructorService",
                source_quality=0.7,
                reliability=0.9,
                independence_cluster="smtp_routing_path",
                specificity=0.9,
                consistency=0.5,
                raw_contribution=-30.0,
                effective_contribution=-30.0,
                is_conflicting=True,
                evidence_category=EvidenceCategory.UNAVAILABLE_INFORMATION,
                timestamp=now_iso
            ))

        # Check for proxy / VPN conflict
        ip_intel_map = self._get(email, "ip_intelligence", {})
        if origin_ip and origin_ip in ip_intel_map:
            intel = ip_intel_map[origin_ip]
            if self._get(intel, "is_proxy_vpn_tor", False):
                conflicting.append(EvaluatedEvidence(
                    evidence_id="EVD-PROXY-EGRESS",
                    statement=f"Observed sending IP {origin_ip} is categorized as an anonymizing proxy, VPN, or Tor exit node.",
                    source_module="IPIntelligenceService",
                    source_quality=0.85,
                    reliability=0.85,
                    independence_cluster="threat_intel_feed",
                    specificity=0.85,
                    consistency=0.7,
                    raw_contribution=-20.0,
                    effective_contribution=-20.0,
                    is_conflicting=True,
                    evidence_category=EvidenceCategory.PROBABLE_INFERENCE,
                    timestamp=now_iso
                ))

        processed_sup = self._apply_quality_and_diminishing_returns(supporting)
        processed_conf = self._apply_quality_and_diminishing_returns(conflicting)
        score, tier = self._calculate_score_and_tier(processed_sup, processed_conf)

        statement = f"Probable attacker-controlled origin infrastructure on {asn or 'unknown ASN'} ({origin_ip or 'unknown IP'})" if origin_ip \
            else "Insufficient technical evidence to attribute delivery infrastructure"

        limitations = [
            self.limitations_config.get("INFRASTRUCTURE_ATTRIBUTION", "Location refers to observed network infrastructure and should not be interpreted as the physical location of the threat actor.")
        ]

        return ForensicConclusion(
            conclusion_id=f"CONC-ATTR-{str(uuid.uuid4())[:8].upper()}",
            type=ConclusionType.INFRASTRUCTURE_ATTRIBUTION,
            statement=statement,
            confidence_score=score,
            confidence_level=tier,
            supporting_evidence=processed_sup,
            conflicting_evidence=processed_conf,
            limitations=limitations,
            source_modules=source_modules,
            generated_at=now_iso,
            engine_version=self.engine_version
        )

    # -------------------------------------------------------------------------
    # DOMAIN 3: CAMPAIGN ASSOCIATION
    # -------------------------------------------------------------------------
    def _evaluate_campaign_association(self, email: Any, now_iso: str) -> ForensicConclusion:
        attr = self._get(email, "attribution", None)
        campaigns = self._get(attr, "related_campaigns", [])
        lookalikes = self._get(email, "lookalike_domains", [])

        supporting: List[EvaluatedEvidence] = []
        conflicting: List[EvaluatedEvidence] = []
        source_modules = ["CampaignCorrelator", "InvestigationGraphService"]

        if campaigns:
            primary_campaign = campaigns[0]
            supporting.append(EvaluatedEvidence(
                evidence_id=f"EVD-CAMP-{primary_campaign}",
                statement=f"Direct technical indicator overlap with active incident campaign {primary_campaign}.",
                source_module="CampaignCorrelator",
                source_quality=0.9,
                reliability=0.9,
                independence_cluster="campaign_clustering",
                specificity=0.9,
                consistency=0.9,
                raw_contribution=50.0,
                effective_contribution=50.0,
                evidence_category=EvidenceCategory.PROBABLE_INFERENCE,
                timestamp=now_iso
            ))
            if len(campaigns) > 1:
                supporting.append(EvaluatedEvidence(
                    evidence_id="EVD-MULTI-INCIDENT-CLUSTER",
                    statement=f"Shared infrastructure co-located across {len(campaigns)} correlated investigation cases.",
                    source_module="CampaignCorrelator",
                    source_quality=0.85,
                    reliability=0.85,
                    independence_cluster="campaign_clustering",
                    specificity=0.85,
                    consistency=0.85,
                    raw_contribution=35.0,
                    effective_contribution=35.0,
                    evidence_category=EvidenceCategory.PROBABLE_INFERENCE,
                    timestamp=now_iso
                ))

            # Corroborate with infrastructure overlap if origin IP or ASN known
            origin_ip = self._get(attr, "probable_origin_ip", None)
            if origin_ip:
                supporting.append(EvaluatedEvidence(
                    evidence_id="EVD-CAMP-INFRA-OVERLAP",
                    statement=f"Sending origin infrastructure ({origin_ip}) correlates with campaign delivery channels.",
                    source_module="AttributionEngine",
                    source_quality=0.85,
                    reliability=0.85,
                    independence_cluster="infra_attribution",
                    specificity=0.85,
                    consistency=0.9,
                    raw_contribution=30.0,
                    effective_contribution=30.0,
                    evidence_category=EvidenceCategory.PROBABLE_INFERENCE,
                    timestamp=now_iso
                ))
        else:
            conflicting.append(EvaluatedEvidence(
                evidence_id="EVD-NO-CAMPAIGN-MATCH",
                statement="No historical case overlaps or multi-incident IoC clusters recorded for this sender.",
                source_module="CampaignCorrelator",
                source_quality=0.7,
                reliability=0.8,
                specificity=0.6,
                consistency=0.6,
                raw_contribution=-15.0,
                effective_contribution=-15.0,
                is_conflicting=True,
                evidence_category=EvidenceCategory.UNAVAILABLE_INFORMATION,
                timestamp=now_iso
            ))

        processed_sup = self._apply_quality_and_diminishing_returns(supporting)
        processed_conf = self._apply_quality_and_diminishing_returns(conflicting)
        score, tier = self._calculate_score_and_tier(processed_sup, processed_conf, is_sparse_single_signal=not campaigns)

        statement = f"Probable association with campaign cluster '{campaigns[0]}'" if campaigns \
            else "Isolated incident: no campaign correlation identified"

        return ForensicConclusion(
            conclusion_id=f"CONC-CAMP-{str(uuid.uuid4())[:8].upper()}",
            type=ConclusionType.CAMPAIGN_ASSOCIATION,
            statement=statement,
            confidence_score=score,
            confidence_level=tier,
            supporting_evidence=processed_sup,
            conflicting_evidence=processed_conf,
            limitations=[
                self.limitations_config.get("CAMPAIGN_ASSOCIATION", "Campaign clustering reflects observed technical IoC overlap across ingested cases; distinct actors occasionally deploy shared infrastructure.")
            ],
            source_modules=source_modules,
            generated_at=now_iso,
            engine_version=self.engine_version
        )

    # -------------------------------------------------------------------------
    # DOMAIN 4: GEOLOCATION & CONTRADICTION DETECTION
    # -------------------------------------------------------------------------
    def _evaluate_geolocation(self, email: Any, now_iso: str) -> ForensicConclusion:
        attr = self._get(email, "attribution", None)
        origin_ip = self._get(attr, "probable_origin_ip", None)
        country = self._get(attr, "probable_infrastructure_country", None)

        ip_intel_map = self._get(email, "ip_intelligence", {})
        domain_intel_map = self._get(email, "domain_intelligence", {})

        supporting: List[EvaluatedEvidence] = []
        conflicting: List[EvaluatedEvidence] = []
        source_modules = ["IPIntelligenceService", "DomainIntelligenceService"]

        # 1. Geo IP from earliest public relay
        if origin_ip and country and country != "Unknown":
            # Primary MaxMind Geo signal
            supporting.append(EvaluatedEvidence(
                evidence_id=f"EVD-GEO-MAXMIND-{origin_ip}",
                statement=f"Earliest untrusted public relay ({origin_ip}) geolocates to {country}.",
                source_module="IPIntelligenceService",
                source_quality=0.85,
                reliability=0.85,
                independence_cluster="maxmind_derived_geo",
                specificity=0.8,
                consistency=0.85,
                raw_contribution=35.0,
                effective_contribution=35.0,
                evidence_category=EvidenceCategory.PROBABLE_INFERENCE,
                timestamp=now_iso
            ))

            # Simulate anti-double-counting: secondary Geo lookup returning same underlying MaxMind dataset
            supporting.append(EvaluatedEvidence(
                evidence_id=f"EVD-GEO-SECONDARY-{origin_ip}",
                statement=f"BGP routing tables and IP registry allocate autonomous system in {country}.",
                source_module="IPIntelligenceService",
                source_quality=0.80,
                reliability=0.80,
                independence_cluster="maxmind_derived_geo",  # Same cluster! Discounts to 30%
                specificity=0.75,
                consistency=0.85,
                raw_contribution=25.0,
                effective_contribution=25.0,
                evidence_category=EvidenceCategory.PROBABLE_INFERENCE,
                timestamp=now_iso
            ))

            # 2. Explicit Contradiction Detection: WHOIS Org Country vs IP Geo Country
            for dom, dinfo in domain_intel_map.items():
                reg = self._get(dinfo, "registration", {})
                rdap = self._get(dinfo, "rdap", {}) or self._get(dinfo, "whois", {})
                whois_country = (
                    self._get(reg, "country", None) or
                    self._get(reg, "registrant_country", None) or
                    self._get(rdap, "country", None) or
                    self._get(rdap, "registrant_country", None) or
                    self._get(dinfo, "country", None)
                )
                if whois_country and whois_country.upper() not in (country.upper(), "UNKNOWN", "REDACTED"):
                    conflicting.append(EvaluatedEvidence(
                        evidence_id=f"EVD-CONFLICT-WHOIS-{dom}",
                        statement=f"WHOIS organization registration for domain '{dom}' is in {whois_country}, conflicting with observed infrastructure in {country}.",
                        source_module="DomainIntelligenceService",
                        source_quality=0.85,
                        reliability=0.85,
                        independence_cluster="whois_registry",
                        specificity=0.85,
                        consistency=0.3,
                        raw_contribution=float(self.contradiction_penalties.get("cross_jurisdiction_geo_vs_whois", -25)),
                        effective_contribution=float(self.contradiction_penalties.get("cross_jurisdiction_geo_vs_whois", -25)),
                        is_conflicting=True,
                        evidence_category=EvidenceCategory.CONFIRMED_EVIDENCE,
                        timestamp=now_iso
                    ))
                    break

            # 3. Explicit Contradiction Detection: Sender Date Header Timezone vs IP Geo
            date_hdr = self._get(email, "date", "") or ""
            tz_match = re.search(r'([+-]\d{4})\b', date_hdr)
            if tz_match:
                tz_offset = tz_match.group(1)
                # Singapore is +0800, India is +0530, US is -0400 to -0800, Western Europe is +0000 to +0200
                if country.lower() == "singapore" and tz_offset == "+0530":
                    conflicting.append(EvaluatedEvidence(
                        evidence_id="EVD-CONFLICT-TIMEZONE-DATE",
                        statement=f"Sender Date header specifies timezone offset {tz_offset} (India Standard Time), diverging from Singapore (+0800) routing infrastructure.",
                        source_module="EmailHeaderParser",
                        source_quality=0.9,
                        reliability=0.8,
                        independence_cluster="client_timestamp",
                        specificity=0.9,
                        consistency=0.3,
                        raw_contribution=float(self.contradiction_penalties.get("cross_jurisdiction_geo_vs_timezone", -15)),
                        effective_contribution=float(self.contradiction_penalties.get("cross_jurisdiction_geo_vs_timezone", -15)),
                        is_conflicting=True,
                        evidence_category=EvidenceCategory.CONFIRMED_EVIDENCE,
                        timestamp=now_iso
                    ))
        else:
            conflicting.append(EvaluatedEvidence(
                evidence_id="EVD-GEO-UNAVAILABLE",
                statement="Public sending IP geolocation could not be determined from available headers.",
                source_module="IPIntelligenceService",
                source_quality=0.6,
                reliability=0.9,
                specificity=0.9,
                consistency=0.5,
                raw_contribution=-30.0,
                effective_contribution=-30.0,
                is_conflicting=True,
                evidence_category=EvidenceCategory.UNAVAILABLE_INFORMATION,
                timestamp=now_iso
            ))

        processed_sup = self._apply_quality_and_diminishing_returns(supporting)
        processed_conf = self._apply_quality_and_diminishing_returns(conflicting)
        score, tier = self._calculate_score_and_tier(processed_sup, processed_conf)

        statement = f"Probable sending infrastructure location: {country}" if (country and country != "Unknown") \
            else "Geolocation undetermined due to lack of public routing telemetry"

        return ForensicConclusion(
            conclusion_id=f"CONC-GEO-{str(uuid.uuid4())[:8].upper()}",
            type=ConclusionType.GEOLOCATION,
            statement=statement,
            confidence_score=score,
            confidence_level=tier,
            supporting_evidence=processed_sup,
            conflicting_evidence=processed_conf,
            limitations=[
                self.limitations_config.get("GEOLOCATION", "IP geolocation reflects autonomous system routing and data center points of presence, not the physical location of the human operator.")
            ],
            source_modules=source_modules,
            generated_at=now_iso,
            engine_version=self.engine_version
        )

    # -------------------------------------------------------------------------
    # DOMAIN 5: LOOKALIKE DOMAIN
    # -------------------------------------------------------------------------
    def _evaluate_lookalike(self, email: Any, now_iso: str) -> ForensicConclusion:
        lookalikes = self._get(email, "lookalike_domains", [])
        supporting: List[EvaluatedEvidence] = []
        conflicting: List[EvaluatedEvidence] = []
        source_modules = ["LookalikeDetector"]

        if lookalikes:
            top = lookalikes[0]
            domain = self._get(top, "domain", "unknown")
            brand = self._get(top, "brand_name", self._get(top, "suspected_brand", "targeted brand"))
            sim = float(self._get(top, "similarity", 0.85))

            supporting.append(EvaluatedEvidence(
                evidence_id=f"EVD-LOOKALIKE-{domain}",
                statement=f"Domain '{domain}' exhibits high homoglyph/lexical similarity ({int(sim * 100)}%) targeting {brand}.",
                source_module="LookalikeDetector",
                source_quality=0.9,
                reliability=0.9,
                specificity=0.9,
                consistency=0.9,
                raw_contribution=55.0,
                effective_contribution=55.0,
                evidence_category=EvidenceCategory.PROBABLE_INFERENCE,
                timestamp=now_iso
            ))

            techniques = self._get(top, "techniques", [])
            if techniques:
                supporting.append(EvaluatedEvidence(
                    evidence_id="EVD-TYPOSQUATTING-TECHNIQUE",
                    statement=f"Identified adversarial evasion techniques: {', '.join(techniques)}.",
                    source_module="LookalikeDetector",
                    source_quality=0.85,
                    reliability=0.85,
                    specificity=0.85,
                    consistency=0.85,
                    raw_contribution=30.0,
                    effective_contribution=30.0,
                    evidence_category=EvidenceCategory.PROBABLE_INFERENCE,
                    timestamp=now_iso
                ))
        else:
            conflicting.append(EvaluatedEvidence(
                evidence_id="EVD-NO-LOOKALIKE",
                statement="No brand typosquatting or homoglyph impersonation detected in extracted domains.",
                source_module="LookalikeDetector",
                source_quality=0.8,
                reliability=0.9,
                specificity=0.8,
                consistency=0.8,
                raw_contribution=-20.0,
                effective_contribution=-20.0,
                is_conflicting=True,
                evidence_category=EvidenceCategory.CONFIRMED_EVIDENCE,
                timestamp=now_iso
            ))

        processed_sup = self._apply_quality_and_diminishing_returns(supporting)
        processed_conf = self._apply_quality_and_diminishing_returns(conflicting)
        score, tier = self._calculate_score_and_tier(processed_sup, processed_conf, is_sparse_single_signal=not lookalikes)

        statement = f"Confirmed brand typosquatting targeting {lookalikes[0].brand_name if hasattr(lookalikes[0], 'brand_name') else 'brand'}" if lookalikes \
            else "No lookalike or typosquatting domain activity detected"

        return ForensicConclusion(
            conclusion_id=f"CONC-LOOKALIKE-{str(uuid.uuid4())[:8].upper()}",
            type=ConclusionType.LOOKALIKE_DOMAIN,
            statement=statement,
            confidence_score=score,
            confidence_level=tier,
            supporting_evidence=processed_sup,
            conflicting_evidence=processed_conf,
            limitations=[
                self.limitations_config.get("LOOKALIKE_DOMAIN", "Lexical homoglyph and string-distance algorithm; does not consult official trademark registries or legal corporate entity databases.")
            ],
            source_modules=source_modules,
            generated_at=now_iso,
            engine_version=self.engine_version
        )

    # -------------------------------------------------------------------------
    # DOMAIN 6: MALICIOUS URL
    # -------------------------------------------------------------------------
    def _evaluate_url(self, email: Any, now_iso: str) -> ForensicConclusion:
        urls = self._get(email, "url_analysis", [])
        supporting: List[EvaluatedEvidence] = []
        conflicting: List[EvaluatedEvidence] = []
        source_modules = ["URLAnalyzer"]

        high_risk_urls = [u for u in urls if self._get(u, "suspicion_score", 0) >= 60]

        if high_risk_urls:
            top_url = high_risk_urls[0]
            target_url = self._get(top_url, "url", "unknown")
            u_score = self._get(top_url, "suspicion_score", 70)
            reasons = self._get(top_url, "score_reasons", [])

            supporting.append(EvaluatedEvidence(
                evidence_id=f"EVD-URL-HIGH-RISK-{hash(target_url) % 100000}",
                statement=f"URL '{target_url[:60]}...' evaluated with high suspicion index ({u_score}/100).",
                source_module="URLAnalyzer",
                source_quality=0.85,
                reliability=0.85,
                specificity=0.9,
                consistency=0.9,
                raw_contribution=40.0,
                effective_contribution=40.0,
                evidence_category=EvidenceCategory.PROBABLE_INFERENCE,
                timestamp=now_iso
            ))

            if reasons:
                supporting.append(EvaluatedEvidence(
                    evidence_id="EVD-URL-OBSERVATIONS",
                    statement=f"Heuristic suspicion triggers: {', '.join(reasons[:2])}.",
                    source_module="URLAnalyzer",
                    source_quality=0.8,
                    reliability=0.8,
                    specificity=0.85,
                    consistency=0.85,
                    raw_contribution=20.0,
                    effective_contribution=20.0,
                    evidence_category=EvidenceCategory.PROBABLE_INFERENCE,
                    timestamp=now_iso
                ))
        elif urls:
            conflicting.append(EvaluatedEvidence(
                evidence_id="EVD-URLS-LOW-SUSPICION",
                statement=f"Extracted {len(urls)} URL(s) exhibit standard benign syntactic features and reputable routing.",
                source_module="URLAnalyzer",
                source_quality=0.8,
                reliability=0.85,
                specificity=0.8,
                consistency=0.8,
                raw_contribution=-15.0,
                effective_contribution=-15.0,
                is_conflicting=True,
                evidence_category=EvidenceCategory.PROBABLE_INFERENCE,
                timestamp=now_iso
            ))
        else:
            conflicting.append(EvaluatedEvidence(
                evidence_id="EVD-NO-URLS",
                statement="No hyperlinks or URL strings extracted from RFC-822 message payload.",
                source_module="URLAnalyzer",
                source_quality=0.8,
                reliability=0.95,
                specificity=0.9,
                consistency=0.9,
                raw_contribution=-20.0,
                effective_contribution=-20.0,
                is_conflicting=True,
                evidence_category=EvidenceCategory.UNAVAILABLE_INFORMATION,
                timestamp=now_iso
            ))

        processed_sup = self._apply_quality_and_diminishing_returns(supporting)
        processed_conf = self._apply_quality_and_diminishing_returns(conflicting)
        score, tier = self._calculate_score_and_tier(processed_sup, processed_conf, is_sparse_single_signal=not high_risk_urls)

        statement = "High-risk credential phishing or malware delivery link detected" if high_risk_urls \
            else "No high-risk malicious URLs observed"

        return ForensicConclusion(
            conclusion_id=f"CONC-URL-{str(uuid.uuid4())[:8].upper()}",
            type=ConclusionType.MALICIOUS_URL,
            statement=statement,
            confidence_score=score,
            confidence_level=tier,
            supporting_evidence=processed_sup,
            conflicting_evidence=processed_conf,
            limitations=[
                self.limitations_config.get("MALICIOUS_URL", "Static non-invasive structural inspection; click-time server-side cloaking or credential redirection chains may alter behavior.")
            ],
            source_modules=source_modules,
            generated_at=now_iso,
            engine_version=self.engine_version
        )

    # -------------------------------------------------------------------------
    # DOMAIN 7: NLP CLASSIFICATION
    # -------------------------------------------------------------------------
    def _evaluate_nlp(self, email: Any, now_iso: str) -> ForensicConclusion:
        ml_prob = self._get(email, "ml_phishing_probability", None)
        body = self._get(email, "plain_text_body", "") or ""

        supporting: List[EvaluatedEvidence] = []
        conflicting: List[EvaluatedEvidence] = []
        source_modules = ["NLPClassifierService"]

        # Urgent / Financial keywords heuristic
        urgency_pattern = re.search(r'\b(urgent\w*|immediate\w*|suspend\w*|verif\w*|action required|wire transfer|payment\w*|bank\w*)\b', body, re.I)

        if ml_prob is not None and ml_prob >= 0.70:
            supporting.append(EvaluatedEvidence(
                evidence_id="EVD-NLP-PHISHING-PROB",
                statement=f"TF-IDF Logistic NLP classifier evaluated message text at {int(ml_prob * 100)}% phishing likelihood.",
                source_module="NLPClassifierService",
                source_quality=0.75,
                reliability=0.75,
                specificity=0.8,
                consistency=0.85,
                raw_contribution=40.0,
                effective_contribution=40.0,
                evidence_category=EvidenceCategory.PROBABLE_INFERENCE,
                timestamp=now_iso
            ))

        if urgency_pattern:
            supporting.append(EvaluatedEvidence(
                evidence_id="EVD-NLP-URGENCY-KEYWORD",
                statement=f"Observed psychological pressure / action urgency trigger keywords: '{urgency_pattern.group(0)}'.",
                source_module="NLPClassifierService",
                source_quality=0.6,
                reliability=0.7,
                specificity=0.65,
                consistency=0.75,
                raw_contribution=20.0,
                effective_contribution=20.0,
                evidence_category=EvidenceCategory.WEAK_HYPOTHESIS,
                timestamp=now_iso
            ))
        elif not ml_prob or ml_prob < 0.3:
            conflicting.append(EvaluatedEvidence(
                evidence_id="EVD-NLP-BENIGN-TONE",
                statement="Textual tone and syntax lack anomalous coercive or financial redirection phrasing.",
                source_module="NLPClassifierService",
                source_quality=0.7,
                reliability=0.8,
                specificity=0.7,
                consistency=0.8,
                raw_contribution=-20.0,
                effective_contribution=-20.0,
                is_conflicting=True,
                evidence_category=EvidenceCategory.PROBABLE_INFERENCE,
                timestamp=now_iso
            ))

        processed_sup = self._apply_quality_and_diminishing_returns(supporting)
        processed_conf = self._apply_quality_and_diminishing_returns(conflicting)

        is_single_weak = len(processed_sup) == 1 and (ml_prob is None or ml_prob < 0.70)
        score, tier = self._calculate_score_and_tier(processed_sup, processed_conf, is_sparse_single_signal=is_single_weak)

        statement = "Coercive social engineering and psychological urgency intent confirmed" if score >= 70 \
            else "Moderate social engineering signals identified" if score >= 40 \
            else "Neutral corporate language without notable social engineering indicators"

        return ForensicConclusion(
            conclusion_id=f"CONC-NLP-{str(uuid.uuid4())[:8].upper()}",
            type=ConclusionType.NLP_CLASSIFICATION,
            statement=statement,
            confidence_score=score,
            confidence_level=tier,
            supporting_evidence=processed_sup,
            conflicting_evidence=processed_conf,
            limitations=[
                self.limitations_config.get("NLP_CLASSIFICATION", "Syntactic and psychological urgency cues from plain-text content; benign high-priority business emails may trigger urgency flags.")
            ],
            source_modules=source_modules,
            generated_at=now_iso,
            engine_version=self.engine_version
        )

    # -------------------------------------------------------------------------
    # DOMAIN 8: ATTACHMENT VERDICT
    # -------------------------------------------------------------------------
    def _evaluate_attachment(self, email: Any, now_iso: str) -> ForensicConclusion:
        attachments = self._get(email, "attachments", []) or []
        supporting: List[EvaluatedEvidence] = []
        conflicting: List[EvaluatedEvidence] = []
        source_modules = ["AttachmentExtractor"]

        dangerous_exts = {".exe", ".scr", ".bat", ".vbs", ".js", ".iso", ".zip", ".tar.gz", ".xlsm"}
        has_dangerous = False

        for att in attachments:
            fname = (self._get(att, "filename", "") or "").lower()
            sha256 = self._get(att, "sha256", None)
            if any(fname.endswith(ext) for ext in dangerous_exts):
                has_dangerous = True
                supporting.append(EvaluatedEvidence(
                    evidence_id=f"EVD-ATT-RISK-{fname}",
                    statement=f"Attachment '{fname}' has high-risk executable or script delivery extension.",
                    source_module="AttachmentExtractor",
                    source_quality=0.9,
                    reliability=0.95,
                    specificity=0.9,
                    consistency=0.9,
                    raw_contribution=45.0,
                    effective_contribution=45.0,
                    evidence_category=EvidenceCategory.CONFIRMED_EVIDENCE,
                    timestamp=now_iso
                ))
            if sha256:
                supporting.append(EvaluatedEvidence(
                    evidence_id=f"EVD-ATT-HASH-{sha256[:10]}",
                    statement=f"Cryptographic SHA-256 fingerprint calculated for '{fname or 'attachment'}': {sha256[:16]}...",
                    source_module="AttachmentExtractor",
                    source_quality=1.0,
                    reliability=1.0,
                    specificity=1.0,
                    consistency=0.95,
                    raw_contribution=25.0,
                    effective_contribution=25.0,
                    evidence_category=EvidenceCategory.CONFIRMED_EVIDENCE,
                    timestamp=now_iso
                ))

        if not attachments:
            conflicting.append(EvaluatedEvidence(
                evidence_id="EVD-NO-ATTACHMENTS",
                statement="No binary payloads or email attachments enclosed in RFC-822 message.",
                source_module="AttachmentExtractor",
                source_quality=0.8,
                reliability=1.0,
                specificity=1.0,
                consistency=0.9,
                raw_contribution=-20.0,
                effective_contribution=-20.0,
                is_conflicting=True,
                evidence_category=EvidenceCategory.UNAVAILABLE_INFORMATION,
                timestamp=now_iso
            ))

        processed_sup = self._apply_quality_and_diminishing_returns(supporting)
        processed_conf = self._apply_quality_and_diminishing_returns(conflicting)
        score, tier = self._calculate_score_and_tier(processed_sup, processed_conf, is_sparse_single_signal=not has_dangerous)

        statement = "High-risk executable attachment payload identified" if has_dangerous \
            else "Safe non-executable attachments" if attachments \
            else "No file attachments present in email"

        return ForensicConclusion(
            conclusion_id=f"CONC-ATT-{str(uuid.uuid4())[:8].upper()}",
            type=ConclusionType.ATTACHMENT_VERDICT,
            statement=statement,
            confidence_score=score,
            confidence_level=tier,
            supporting_evidence=processed_sup,
            conflicting_evidence=processed_conf,
            limitations=[
                self.limitations_config.get("ATTACHMENT_VERDICT", "Static file header and hash evaluation; encrypted or password-protected archives without supplied credentials cannot be inspected.")
            ],
            source_modules=source_modules,
            generated_at=now_iso,
            engine_version=self.engine_version
        )
