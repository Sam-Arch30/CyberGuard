import os
import json
import re
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from pathlib import Path

from backend.schemas.threat_score import (
    ThreatScoreContribution,
    PositiveEvidence,
    ThreatSignalContribution,
    CategoryScoreBreakdown,
    ThreatScoreResult
)


CATEGORY_DISPLAY_NAMES = {
    "authentication": "Authentication Risk",
    "sender_identity": "Sender Identity Risk",
    "domain_intelligence": "Domain Risk",
    "lookalike_detection": "Lookalike Risk",
    "url_intelligence": "URL Risk",
    "infrastructure": "Infrastructure Risk",
    "email_content": "Content Risk",
    "campaign_intelligence": "Campaign Risk",
    "attachments": "Attachment Risk"
}


class ThreatScorerService:
    """
    Explainable Global Threat Scoring Engine (Section 10).
    Combines forensic signals across 9 risk categories into an explainable,
    transparent email risk score. Weights, mitigating factors, and thresholds
    are strictly configuration-driven and 100% auditable.
    """

    DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "scoring_rules.json"

    def __init__(self, config_path: Optional[str | Path] = None, config_dict: Optional[Dict[str, Any]] = None):
        self.config_file = Path(config_path) if config_path else self.DEFAULT_CONFIG_PATH
        base_config = self._load_config()
        if config_dict:
            for k, v in config_dict.items():
                if isinstance(v, dict) and isinstance(base_config.get(k), dict):
                    merged = dict(base_config[k])
                    merged.update(v)
                    base_config[k] = merged
                else:
                    base_config[k] = v
        self.config = base_config

        self.scoring_version = self.config.get("scoring_version", "2.0.0-explainable")
        self.weights = self.config.get("weights", {})
        self.thresholds = self.config.get("severity_thresholds", {})
        self.risk_thresholds = self.config.get("risk_thresholds", {})
        self.signal_metadata = self.config.get("signal_metadata", {})
        self.suspicious_extensions = [ext.lower() for ext in self.config.get("suspicious_extensions", [])]
        self.suspicious_tlds = [tld.lower() for tld in self.config.get("suspicious_tlds", [])]
        self.credential_keywords = [kw.lower() for kw in self.config.get("credential_keywords", [])]
        self.financial_keywords = [kw.lower() for kw in self.config.get("financial_keywords", [])]
        self.urgency_keywords = [kw.lower() for kw in self.config.get("urgency_keywords", [])]
        self.ml_scoring = self.config.get("ml_scoring", {
            "enabled": True,
            "probability_threshold": 0.75,
            "max_points": 10,
            "low_risk_threshold": 0.15
        })

    def _load_config(self) -> Dict[str, Any]:
        """Safely loads scoring configuration JSON with fallback defaults."""
        if hasattr(self, "config_file") and self.config_file.exists():
            try:
                with open(self.config_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {
            "scoring_version": "2.0.0-explainable",
            "weights": {
                "spf_fail": 8,
                "spf_softfail": 4,
                "dkim_fail": 8,
                "dmarc_fail": 12,
                "reply_to_mismatch": 8,
                "return_path_mismatch": 6,
                "brand_impersonation": 18,
                "url_high_risk": 15,
                "url_suspicious": 8,
                "html_link_mismatch": 15,
                "newly_registered_domain": 10,
                "credential_request": 12,
                "financial_language": 10,
                "suspicious_attachment_extension": 15,
                "attachment_macro_payload": 18,
                "executable_disguised_as_document": 25,
                "pdf_suspicious_actions": 18,
                "double_extension_detected": 18,
                "archive_with_hidden_executable": 20,
                "path_traversal_archive_exploit": 25,
                "password_protected_suspicious_archive": 15,
                "unsigned_executable": 12,
                "embedded_phishing_url_in_attachment": 15,
                "high_entropy_packed_binary": 10,
                "suspicious_ip_hosting_or_proxy": 8,
                "ml_phishing_signal": 10,
                "trusted_sender_history": -5
            },
            "severity_thresholds": {
                "low": {"min": 0, "max": 29},
                "suspicious": {"min": 30, "max": 59},
                "high": {"min": 60, "max": 79},
                "critical": {"min": 80, "max": 100}
            },
            "risk_thresholds": {
                "LOW": {"min": 0, "max": 24},
                "SUSPICIOUS": {"min": 25, "max": 49},
                "HIGH": {"min": 50, "max": 74},
                "CRITICAL": {"min": 75, "max": 100}
            }
        }

    def _get_signal_meta(self, signal_key: str, default_category: str, default_name: str, default_desc: str, default_source: str) -> Dict[str, str]:
        meta = self.signal_metadata.get(signal_key, {})
        return {
            "category": meta.get("category", default_category),
            "name": meta.get("name", default_name),
            "description": meta.get("description", default_desc),
            "why_it_matters": meta.get("why_it_matters", "Directly impacts email threat assessment and security posture."),
            "source": meta.get("source", default_source)
        }

    def calculate_score(self, email_analysis: Any) -> ThreatScoreResult:
        """
        Evaluates deterministic forensic signals from EmailAnalysisResponse,
        generating structured contributions across all 9 risk categories,
        positive/negative score breakdowns, evidence confidence, and audit metadata.
        """
        if isinstance(email_analysis, dict):
            class DictToObject:
                def __init__(self, d):
                    self._d = d
                    for k, v in d.items():
                        if isinstance(v, dict):
                            setattr(self, k, DictToObject(v))
                        elif isinstance(v, list):
                            setattr(self, k, [DictToObject(x) if isinstance(x, dict) else x for x in v])
                        else:
                            setattr(self, k, v)
                def get(self, k, default=None):
                    return getattr(self, k, default)
                def items(self):
                    return [(k, getattr(self, k)) for k in self._d.keys()]
                def keys(self):
                    return self._d.keys()
                def values(self):
                    return [getattr(self, k) for k in self._d.keys()]
                def __getattr__(self, k):
                    return None
            email_analysis = DictToObject(email_analysis)

        positive_contributions: List[ThreatSignalContribution] = []
        negative_contributions: List[ThreatSignalContribution] = []
        legacy_reasons: List[ThreatScoreContribution] = []
        legacy_positive: List[PositiveEvidence] = []
        signal_counter = 0

        def add_risk_signal(signal_key: str, default_cat: str, default_name: str, legacy_label: str,
                            default_desc: str, legacy_evidence: str, default_source: str,
                            raw_val: Any = None, norm_val: float = 1.0, conf: float = 1.0, ev_ref: Optional[str] = None):
            nonlocal signal_counter
            signal_counter += 1
            meta = self._get_signal_meta(signal_key, default_cat, default_name, default_desc, default_source)
            weight = self.weights.get(signal_key, 0)
            if weight <= 0:
                return

            contrib = ThreatSignalContribution(
                signal_id=f"SIG-{meta['category'].upper()[:4]}-{signal_counter:03d}",
                category=meta["category"],
                name=meta["name"],
                description=default_desc,
                why_it_matters=meta["why_it_matters"],
                raw_value=raw_val,
                normalized_value=norm_val,
                weight=weight,
                contribution=weight,
                direction="increase_risk",
                confidence=conf,
                evidence_reference=ev_ref,
                source=meta["source"]
            )
            positive_contributions.append(contrib)
            legacy_reasons.append(ThreatScoreContribution(
                signal=signal_key,
                label=legacy_label,
                points=weight,
                evidence=legacy_evidence
            ))

        def add_mitigating_signal(signal_key: str, default_cat: str, default_name: str, legacy_label: str,
                                  default_desc: str, legacy_evidence: str, default_source: str,
                                  raw_val: Any = None, norm_val: float = 0.0, conf: float = 1.0, ev_ref: Optional[str] = None):
            nonlocal signal_counter
            signal_counter += 1
            meta = self._get_signal_meta(signal_key, default_cat, default_name, default_desc, default_source)
            weight = self.weights.get(signal_key, 0)

            contrib = ThreatSignalContribution(
                signal_id=f"SIG-MIT-{signal_counter:03d}",
                category=meta["category"],
                name=meta["name"],
                description=default_desc,
                why_it_matters=meta["why_it_matters"],
                raw_value=raw_val,
                normalized_value=norm_val,
                weight=weight,
                contribution=weight,  # 0 or negative
                direction="decrease_risk",
                confidence=conf,
                evidence_reference=ev_ref,
                source=meta["source"]
            )
            negative_contributions.append(contrib)
            legacy_positive.append(PositiveEvidence(
                signal=signal_key,
                label=legacy_label,
                evidence=legacy_evidence
            ))

        # -------------------------------------------------------------
        # 1. AUTHENTICATION (SPF, DKIM, DMARC)
        # -------------------------------------------------------------
        auth = getattr(email_analysis, "authentication", None)
        has_auth_fail = False
        all_auth_pass = True

        if auth:
            # SPF
            spf = getattr(auth, "spf", None)
            spf_res = getattr(spf, "result", "").lower() if spf else ""
            spf_details = getattr(spf, "details", None) or "Observed SPF header indicated fail"
            if spf_res == "fail":
                has_auth_fail = True
                all_auth_pass = False
                add_risk_signal("spf_fail", "authentication", "SPF Authentication Failure",
                                "SPF authentication failed",
                                f"Originating mail server failed SPF authorization: {spf_details}",
                                spf_details, "Email Authentication Subsystem", raw_val="fail", ev_ref=spf_details)
            elif spf_res == "softfail":
                has_auth_fail = True
                all_auth_pass = False
                soft_details = getattr(spf, "details", None) or "Observed SPF header indicated softfail"
                add_risk_signal("spf_softfail", "authentication", "SPF Policy Softfail",
                                "SPF policy softfail",
                                f"Originating server discouraged by SPF policy: {soft_details}",
                                soft_details, "Email Authentication Subsystem", raw_val="softfail", ev_ref=soft_details)
            elif spf_res == "pass":
                pass_details = getattr(spf, "details", None) or "Originating mail server authorized by SPF"
                add_mitigating_signal("spf_pass", "authentication", "Verified SPF Authorization",
                                      "SPF authentication passed",
                                      f"Originating mail server authorized by SPF: {pass_details}",
                                      pass_details, "Email Authentication Subsystem", raw_val="pass", ev_ref=pass_details)
            else:
                all_auth_pass = False

            # DKIM
            dkim = getattr(auth, "dkim", None)
            dkim_res = getattr(dkim, "result", "").lower() if dkim else ""
            dkim_details = getattr(dkim, "details", None) or "Observed DKIM header indicated fail"
            if dkim_res == "fail":
                has_auth_fail = True
                all_auth_pass = False
                add_risk_signal("dkim_fail", "authentication", "DKIM Signature Verification Failed",
                                "DKIM cryptographic signature verification failed",
                                f"DKIM cryptographic signature verification failed: {dkim_details}",
                                dkim_details, "Cryptographic Signature Validator", raw_val="fail", ev_ref=dkim_details)
            elif dkim_res == "pass":
                pass_details = getattr(dkim, "details", None) or "Cryptographic DKIM signature validated"
                add_mitigating_signal("dkim_pass", "authentication", "Valid Cryptographic DKIM Signature",
                                      "DKIM signature verified",
                                      f"DKIM signature cryptographically validated: {pass_details}",
                                      pass_details, "Cryptographic Signature Validator", raw_val="pass", ev_ref=pass_details)
            else:
                all_auth_pass = False

            # DMARC
            dmarc = getattr(auth, "dmarc", None)
            dmarc_res = getattr(dmarc, "result", "").lower() if dmarc else ""
            dmarc_details = getattr(dmarc, "details", None) or "Observed DMARC policy check failed"
            if dmarc_res == "fail":
                has_auth_fail = True
                all_auth_pass = False
                add_risk_signal("dmarc_fail", "authentication", "DMARC Policy Alignment Failed",
                                "DMARC policy alignment failed",
                                f"DMARC policy check failed: {dmarc_details}",
                                dmarc_details, "DMARC Alignment Engine", raw_val="fail", ev_ref=dmarc_details)
            elif dmarc_res == "pass":
                pass_details = getattr(dmarc, "details", None) or "DMARC policy alignment succeeded"
                add_mitigating_signal("dmarc_pass", "authentication", "DMARC Policy Alignment Verified",
                                      "DMARC policy aligned and passed",
                                      f"DMARC policy aligned and passed: {pass_details}",
                                      pass_details, "DMARC Alignment Engine", raw_val="pass", ev_ref=dmarc_details)
            else:
                all_auth_pass = False

            # Sender Identity / Header Alignment
            align = getattr(auth, "alignment", None)
            has_identity_mismatch = False
            if align:
                from_d = getattr(align, "from_domain", "") or ""
                reply_d = getattr(align, "reply_to_domain", "") or ""
                return_d = getattr(align, "return_path_domain", "") or ""

                if getattr(align, "reply_to_mismatch", False) and reply_d:
                    has_identity_mismatch = True
                    ev_txt = f"From domain '{from_d}' differs from Reply-To destination '{reply_d}'"
                    add_risk_signal("reply_to_mismatch", "sender_identity", "Reply-To Destination Mismatch",
                                    "Reply-To header domain mismatch",
                                    ev_txt, ev_txt, "Header Alignment Subsystem", raw_val=f"{from_d} != {reply_d}", ev_ref=reply_d)

                if getattr(align, "return_path_mismatch", False) and return_d:
                    has_identity_mismatch = True
                    ev_txt = f"From domain '{from_d}' differs from Return-Path '{return_d}'"
                    add_risk_signal("return_path_mismatch", "sender_identity", "Return-Path Envelope Mismatch",
                                    "Return-Path envelope sender mismatch",
                                    ev_txt, ev_txt, "Header Alignment Subsystem", raw_val=f"{from_d} != {return_d}", ev_ref=return_d)

            # Display Name Spoofing
            from_hdr = getattr(email_analysis, "from_header", "") or getattr(email_analysis, "from", "") or ""
            target_brands = ["microsoft", "google", "paypal", "apple", "docusign", "netflix", "amazon"]
            if from_hdr and "<" in from_hdr:
                display_name = from_hdr.split("<")[0].lower()
                addr_part = from_hdr.split("<")[1].split(">")[0].lower()
                for b in target_brands:
                    if b in display_name and b not in addr_part:
                        has_identity_mismatch = True
                        ev_txt = f"Display name claims '{b.capitalize()}' identity while sending domain is '{addr_part}'"
                        add_risk_signal("display_name_spoof", "sender_identity", "Display Name Spoofing Detected",
                                        f"Display name spoofing targeting {b.capitalize()}",
                                        ev_txt, ev_txt, "Sender Identity Analyzer", raw_val=from_hdr, ev_ref=from_hdr)
                        break

            # Trusted sender history mitigating signal
            if all_auth_pass and not has_identity_mismatch and not has_auth_fail:
                add_mitigating_signal("trusted_sender_history", "sender_identity", "Consistent Sender Identity",
                                      "Sender identity verified and authentic",
                                      "Sender authentication (SPF/DKIM/DMARC) and headers are fully aligned without spoofing",
                                      "Sender identity verified and authentic", "Header Alignment Subsystem", raw_val="aligned_clean")
        else:
            all_auth_pass = False

        # -------------------------------------------------------------
        # 2. LOOKALIKE DETECTION & BRAND IMPERSONATION
        # -------------------------------------------------------------
        lookalikes = getattr(email_analysis, "lookalike_domains", []) or []
        seen_lookalike_brands = set()
        for lk in lookalikes:
            brand_key = getattr(lk, "suspected_brand", "") or getattr(lk, "domain", "")
            if brand_key not in seen_lookalike_brands:
                seen_lookalike_brands.add(brand_key)
                b_name = getattr(lk, "brand_name", "") or getattr(lk, "suspected_brand", "known brand")
                obs_dom = getattr(lk, "domain", "")
                sim = getattr(lk, "similarity", 0.9)
                techs = getattr(lk, "techniques", [])
                ev_txt = f"{obs_dom} (similarity: {int(sim * 100)}%, techniques: {', '.join(techs)})"
                add_risk_signal("brand_impersonation", "lookalike_detection", f"Possible {b_name} lookalike domain",
                                f"Possible {b_name} lookalike domain",
                                f"Domain '{obs_dom}' mimics protected brand '{b_name}' ({int(sim * 100)}% similarity)",
                                ev_txt, "Lookalike Detection Engine", raw_val=obs_dom, norm_val=float(sim), ev_ref=obs_dom)

        # -------------------------------------------------------------
        # 3. URL INTELLIGENCE
        # -------------------------------------------------------------
        url_analyses = getattr(email_analysis, "url_analysis", []) or []
        has_high_url = False
        has_susp_url = False
        has_link_mismatch = False

        for u_res in url_analyses:
            feat = getattr(u_res, "features", None)
            score = getattr(u_res, "suspicion_score", 0)
            u_str = getattr(u_res, "url", "")

            if not has_link_mismatch and feat and getattr(feat, "display_link_mismatch", False):
                has_link_mismatch = True
                vis_dom = getattr(feat, "visible_text_domain", None) or getattr(feat, "visible_text", "trusted site")
                dest_dom = getattr(u_res, "domain", "")
                ev_txt = f"Visible anchor text claimed '{vis_dom}' but links to '{dest_dom}'"
                add_risk_signal("html_link_mismatch", "url_intelligence", "HTML display link mismatch",
                                "HTML display link mismatch",
                                ev_txt, ev_txt, "HTML Body Parser", raw_val=f"{vis_dom} -> {dest_dom}", ev_ref=u_str)

            if not has_high_url and score >= 60:
                has_high_url = True
                ev_txt = f"{u_str} (suspicion score {score}/100)"
                add_risk_signal("url_high_risk", "url_intelligence", "High-risk URL structure detected",
                                "High-risk URL structure detected",
                                f"URL exhibits high suspicion score ({score}/100): {u_str}",
                                ev_txt, "Static URL Analyzer", raw_val=score, norm_val=min(1.0, score / 100.0), ev_ref=u_str)
            elif not has_high_url and not has_susp_url and score >= 25:
                has_susp_url = True
                ev_txt = f"{u_str} (suspicion score {score}/100)"
                add_risk_signal("url_suspicious", "url_intelligence", "Suspicious URL detected",
                                "Suspicious URL detected",
                                f"URL flagged for suspicious structure ({score}/100): {u_str}",
                                ev_txt, "Static URL Analyzer", raw_val=score, norm_val=min(1.0, score / 100.0), ev_ref=u_str)

        if url_analyses and not has_high_url and not has_susp_url and not has_link_mismatch:
            add_mitigating_signal("clean_urls", "url_intelligence", "Extracted URLs Exhibit Normal Baseline",
                                  "Extracted URLs exhibit normal structure",
                                  f"{len(url_analyses)} URL(s) inspected without anomalies",
                                  f"{len(url_analyses)} URL(s) inspected without anomalies",
                                  "Static URL Analyzer", raw_val=len(url_analyses))

        # -------------------------------------------------------------
        # 4. DOMAIN INTELLIGENCE (Age, TLD, DNS)
        # -------------------------------------------------------------
        domain_intel = getattr(email_analysis, "domain_intelligence", {}) or {}
        new_domains_flagged = set()
        established_domains = []
        dns_failed_domains = []
        suspicious_tld_flagged = set()

        domain_items = domain_intel.items() if hasattr(domain_intel, "items") else []
        for d_name, d_data in domain_items:
            age = getattr(d_data, "domain_age_days", None)
            is_new = getattr(d_data, "newly_registered_domain", False)
            is_resolvable = getattr(d_data, "is_resolvable", True)

            if (is_new or (age is not None and age < 30)) and d_name not in new_domains_flagged:
                new_domains_flagged.add(d_name)
                age_str = f"{age} days old" if age is not None else "< 30 days old"
                ev_txt = f"Domain '{d_name}' was registered recently ({age_str})"
                add_risk_signal("newly_registered_domain", "domain_intelligence", "Newly registered domain",
                                "Newly registered domain",
                                ev_txt, ev_txt, "Domain Intelligence Subsystem", raw_val=age, ev_ref=d_name)
            elif age is not None and age > 365:
                established_domains.append(f"{d_name} ({age} days)")

            # Suspicious TLD check
            for tld in self.suspicious_tlds:
                if d_name.lower().endswith(tld) and d_name not in suspicious_tld_flagged:
                    suspicious_tld_flagged.add(d_name)
                    ev_txt = f"Domain '{d_name}' operates under high-abuse TLD '{tld}'"
                    add_risk_signal("suspicious_tld", "domain_intelligence", "High-Risk Disposable TLD",
                                    "High-Risk Disposable TLD",
                                    ev_txt, ev_txt, "Domain Intelligence Subsystem", raw_val=tld, ev_ref=d_name)
                    break

            # DNS Anomaly
            if not is_resolvable:
                dns_failed_domains.append(d_name)

        if dns_failed_domains:
            ev_txt = f"Domain(s) failed authoritative DNS resolution: {', '.join(dns_failed_domains[:3])}"
            add_risk_signal("dns_anomaly", "domain_intelligence", "DNS Resolution Failure",
                            "DNS Resolution Failure",
                            ev_txt, ev_txt, "DNS Resolver Subsystem", raw_val="unresolvable", ev_ref=dns_failed_domains[0])

        if established_domains and not new_domains_flagged:
            ev_txt = ", ".join(established_domains[:2])
            add_mitigating_signal("established_domain", "domain_intelligence", "Well-Established Domain History",
                                  "Domain registration is well-established",
                                  f"Domain registration is well-established: {ev_txt}",
                                  ev_txt, "Domain Intelligence Subsystem", raw_val=established_domains)

        # -------------------------------------------------------------
        # 5. CONTENT INTENT & NLP CLASSIFICATION
        # -------------------------------------------------------------
        subject = getattr(email_analysis, "subject", "") or ""
        plain_text = getattr(email_analysis, "plain_text_body", "") or ""
        html_body = getattr(email_analysis, "html_body", "") or ""
        combined_text = f"{subject} {plain_text} {html_body}".lower()

        # Credential Harvesting
        matched_cred_kw = None
        for kw in self.credential_keywords:
            if re.search(rf'\b{re.escape(kw)}\b', combined_text):
                matched_cred_kw = kw
                break

        if matched_cred_kw:
            ev_txt = f"Detected pattern: '{matched_cred_kw}'"
            add_risk_signal("credential_request", "email_content", "Credential harvesting language detected",
                            "Credential harvesting or urgent security language",
                            f"Detected credential harvesting language: '{matched_cred_kw}'",
                            ev_txt, "Content Intent Analyzer", raw_val=matched_cred_kw)

        # Financial / Wire language
        matched_fin_kw = None
        for kw in self.financial_keywords:
            if re.search(rf'\b{re.escape(kw)}\b', combined_text):
                matched_fin_kw = kw
                break

        if matched_fin_kw:
            ev_txt = f"Detected pattern: '{matched_fin_kw}'"
            add_risk_signal("financial_language", "email_content", "Urgent financial language detected",
                            "Urgent financial or wire transfer language",
                            f"Detected urgent financial transfer language: '{matched_fin_kw}'",
                            ev_txt, "Content Intent Analyzer", raw_val=matched_fin_kw)

        # Urgency language
        matched_urg_kw = None
        for kw in self.urgency_keywords:
            if re.search(rf'\b{re.escape(kw)}\b', combined_text):
                matched_urg_kw = kw
                break

        if matched_urg_kw:
            ev_txt = f"Detected pattern: '{matched_urg_kw}'"
            add_risk_signal("urgency_language", "email_content", "Artificial Urgency Phrasing",
                            "Artificial Urgency Phrasing",
                            f"Detected psychological pressure phrasing: '{matched_urg_kw}'",
                            ev_txt, "Content Intent Analyzer", raw_val=matched_urg_kw)

        # NLP Phishing Classification
        if self.ml_scoring.get("enabled", True):
            ml_prob = getattr(email_analysis, "ml_phishing_probability", None)
            if ml_prob is None:
                ml_assessment = getattr(email_analysis, "ml_assessment", None)
                if ml_assessment:
                    ml_prob = getattr(ml_assessment, "probability", None)
                    if ml_prob is None and isinstance(ml_assessment, dict):
                        ml_prob = ml_assessment.get("probability")

            if ml_prob is not None:
                threshold = self.ml_scoring.get("probability_threshold", 0.75)
                low_threshold = self.ml_scoring.get("low_risk_threshold", 0.15)
                if ml_prob >= threshold:
                    ev_txt = f"ML model estimated {int(ml_prob * 100)}% phishing probability based on language and phrasing patterns"
                    add_risk_signal("ml_phishing_signal", "email_content", "NLP text classification flagged high phishing probability",
                                    "NLP text classification flagged high phishing probability",
                                    ev_txt, ev_txt, "ML Text Classifier", raw_val=ml_prob, norm_val=float(ml_prob))
                elif ml_prob <= low_threshold:
                    ev_txt = f"ML text classifier estimated low phishing risk ({int(ml_prob * 100)}%)"
                    add_mitigating_signal("ml_low_risk_content", "email_content", "NLP Content Assessment Indicates Benign Text",
                                          "NLP content assessment indicates benign language",
                                          ev_txt, ev_txt, "ML Text Classifier", raw_val=ml_prob, norm_val=float(ml_prob))

        # -------------------------------------------------------------
        # 6. ATTACHMENT RISK
        # -------------------------------------------------------------
        attachments = getattr(email_analysis, "attachments", []) or []
        suspicious_att_found = False
        for att in attachments:
            fname = getattr(att, "filename", "") or "unnamed_attachment"
            fname_lower = fname.lower()
            static_res = getattr(att, "static_analysis", None)

            # Check filename extension against suspicious list
            for ext in self.suspicious_extensions:
                if fname_lower.endswith(ext):
                    suspicious_att_found = True
                    ev_txt = f"Attachment '{fname}'"
                    add_risk_signal("suspicious_attachment_extension", "attachments", f"Dangerous executable or script attachment ({ext})",
                                    f"Dangerous executable or script attachment ({ext})",
                                    f"Dangerous attachment observed: '{fname}'",
                                    ev_txt, "Attachment Risk Inspector", raw_val=ext, ev_ref=fname)
                    break

            if static_res:
                # Disguised executable / extension mismatch
                if getattr(static_res, "extension_mismatch", False) and "Windows executable" in str(getattr(static_res, "detected_type", "") or ""):
                    suspicious_att_found = True
                    ev_txt = f"Executable disguised as document: '{fname}' (Detected: {getattr(static_res, 'detected_type', '')})"
                    add_risk_signal("executable_disguised_as_document", "attachments",
                                    "Executable Disguised as Document",
                                    "Attachment filename claims document format but payload is an executable binary",
                                    ev_txt, ev_txt, "Attachment Intelligence Engine", raw_val=fname, ev_ref=fname)

                # Double extension evasion
                if getattr(static_res, "double_extension", False):
                    suspicious_att_found = True
                    ev_txt = f"Double extension evasion detected: '{fname}'"
                    add_risk_signal("double_extension_detected", "attachments",
                                    "Double Extension Evasion",
                                    "Attachment employs dual extensions to conceal dangerous payload",
                                    ev_txt, ev_txt, "Attachment Intelligence Engine", raw_val=fname, ev_ref=fname)

                # Office Macros
                if getattr(static_res, "office_metadata", None) and getattr(static_res.office_metadata, "has_macros", False):
                    suspicious_att_found = True
                    ev_txt = f"Macro-enabled document: '{fname}' contains VBA macro project"
                    add_risk_signal("attachment_macro_payload", "attachments",
                                    "Macro-Enabled Office Document",
                                    "Office document contains executable VBA macros capable of remote code execution",
                                    ev_txt, ev_txt, "Attachment Intelligence Engine", raw_val=fname, ev_ref=fname)

                # PDF suspicious elements
                if getattr(static_res, "pdf_metadata", None) and getattr(static_res.pdf_metadata, "suspicious_elements", None):
                    suspicious_att_found = True
                    elems = getattr(static_res.pdf_metadata, "suspicious_elements", [])
                    elems_str = ", ".join(elems[:2]) if isinstance(elems, list) else str(elems)
                    ev_txt = f"PDF '{fname}' contains dangerous elements: {elems_str}"
                    add_risk_signal("pdf_suspicious_actions", "attachments",
                                    "PDF Suspicious Execution Elements",
                                    f"PDF contains active auto-execution elements: {elems_str}",
                                    ev_txt, ev_txt, "Attachment Intelligence Engine", raw_val=fname, ev_ref=fname)

                # Archive risks
                archive_meta = getattr(static_res, "archive_metadata", None)
                if archive_meta:
                    if getattr(archive_meta, "has_path_traversal", False):
                        suspicious_att_found = True
                        ev_txt = f"Archive '{fname}' contains path traversal exploit (Zip Slip)"
                        add_risk_signal("path_traversal_archive_exploit", "attachments",
                                        "Archive Path Traversal (Zip Slip)",
                                        "Archive contains directory traversal paths targeting arbitrary file overwrite",
                                        ev_txt, ev_txt, "Attachment Intelligence Engine", raw_val=fname, ev_ref=fname)

                    if getattr(archive_meta, "has_hidden_executables", False):
                        suspicious_att_found = True
                        ev_txt = f"Archive '{fname}' packages hidden executable payloads"
                        add_risk_signal("archive_with_hidden_executable", "attachments",
                                        "Archive Packaging Hidden Executables",
                                        "Archive packages concealed executable or script files",
                                        ev_txt, ev_txt, "Attachment Intelligence Engine", raw_val=fname, ev_ref=fname)

                    if getattr(archive_meta, "is_encrypted", False):
                        suspicious_att_found = True
                        ev_txt = f"Archive '{fname}' is password-protected"
                        add_risk_signal("password_protected_suspicious_archive", "attachments",
                                        "Password-Protected Archive Evasion",
                                        "Archive encryption prevents automated inspection",
                                        ev_txt, ev_txt, "Attachment Intelligence Engine", raw_val=fname, ev_ref=fname)

                # Unsigned executable
                pe_meta = getattr(static_res, "pe_metadata", None)
                if pe_meta and getattr(pe_meta, "is_pe", False) and getattr(pe_meta, "signature_status", "") == "Unsigned":
                    suspicious_att_found = True
                    ev_txt = f"Binary '{fname}' is unsigned"
                    add_risk_signal("unsigned_executable", "attachments",
                                    "Unsigned Windows Executable",
                                    "Executable binary lacks valid Authenticode code signing certificate",
                                    ev_txt, ev_txt, "Attachment Intelligence Engine", raw_val=fname, ev_ref=fname)

                # High entropy executable (packed) - Note: high entropy alone is NOT malware, only if executable
                ent = getattr(static_res, "entropy", None)
                if ent is not None and float(ent or 0.0) > 7.5 and "Windows executable" in str(getattr(static_res, "detected_type", "") or ""):
                    suspicious_att_found = True
                    ev_txt = f"Binary '{fname}' exhibits very high entropy ({float(ent):.2f}/8.00)"
                    add_risk_signal("high_entropy_packed_binary", "attachments",
                                    "High-Entropy Packed Binary",
                                    f"Executable exhibits high entropy ({float(ent):.2f}/8.00) indicating packing or cryptors",
                                    ev_txt, ev_txt, "Attachment Intelligence Engine", raw_val=ent, ev_ref=fname)

                # Embedded Phishing URLs in document
                embedded_urls = getattr(static_res, "embedded_urls", None)
                if embedded_urls:
                    suspicious_att_found = True
                    ev_txt = f"Attachment '{fname}' embeds {len(embedded_urls)} external URL(s)"
                    add_risk_signal("embedded_phishing_url_in_attachment", "attachments",
                                    "Embedded Phishing Links in Attachment",
                                    f"Attachment conceals external URLs ({len(embedded_urls)} found)",
                                    ev_txt, ev_txt, "Attachment Intelligence Engine", raw_val=len(embedded_urls), ev_ref=fname)

        if attachments and not suspicious_att_found:
            ev_txt = f"{len(attachments)} attachment(s) verified safe"
            add_mitigating_signal("safe_attachments", "attachments", "Attachments Free of Executables/Macros",
                                  "No executable or macro attachments detected",
                                  f"{len(attachments)} attachment(s) verified safe without executables or scripts",
                                  ev_txt, "Attachment Risk Inspector", raw_val=len(attachments))

        # -------------------------------------------------------------
        # 7. INFRASTRUCTURE RISK (Proxy, Tor, VPN)
        # -------------------------------------------------------------
        ip_intel = getattr(email_analysis, "ip_intelligence", {}) or {}
        for ip_addr, ip_data in ip_intel.items():
            if getattr(ip_data, "is_proxy_vpn_tor", False):
                ev_txt = f"Relay IP {ip_addr} flagged as proxy or VPN exit"
                add_risk_signal("suspicious_ip_hosting_or_proxy", "infrastructure", "Anonymized transmission node (Proxy/VPN/Tor)",
                                "Anonymized transmission node (Proxy/VPN/Tor)",
                                ev_txt, ev_txt, "IP Intelligence Engine", raw_val=ip_addr, ev_ref=ip_addr)
                break

        # -------------------------------------------------------------
        # 8. CAMPAIGN INTELLIGENCE
        # -------------------------------------------------------------
        attribution = getattr(email_analysis, "attribution", None)
        if attribution:
            camps = getattr(attribution, "related_campaigns", []) or []
            if camps:
                ev_txt = f"Infrastructure correlates with campaign: {', '.join(camps[:2])}"
                add_risk_signal("known_campaign_match", "campaign_intelligence", "Correlated Campaign Infrastructure",
                                "Correlated Campaign Infrastructure",
                                ev_txt, ev_txt, "Campaign Correlation Engine", raw_val=camps)

        # -------------------------------------------------------------
        # SCORE NORMALIZATION (0–100)
        # -------------------------------------------------------------
        total_positive = sum(c.contribution for c in positive_contributions)
        total_negative = sum(c.contribution for c in negative_contributions)
        raw_net = total_positive + total_negative
        final_score = max(0, min(100, raw_net))

        # Severity (Legacy) & Risk Level (Explainable)
        legacy_severity = self._determine_severity(final_score)
        risk_level = self._determine_risk_level(final_score)

        # Evidence Confidence
        active_categories = {c.category for c in positive_contributions}
        if len(active_categories) >= 3 or final_score >= 75:
            confidence = "VERY HIGH" if len(active_categories) >= 4 else "HIGH"
        elif len(active_categories) == 2 or final_score >= 45:
            confidence = "HIGH"
        elif len(active_categories) == 1:
            confidence = "MODERATE"
        else:
            confidence = "LOW"

        # Category Breakdowns
        category_breakdowns: Dict[str, CategoryScoreBreakdown] = {}
        all_signals = positive_contributions + negative_contributions
        for cat_id, cat_name in CATEGORY_DISPLAY_NAMES.items():
            cat_signals = [s for s in all_signals if s.category == cat_id]
            cat_score = sum(s.contribution for s in cat_signals)
            pos_count = sum(1 for s in cat_signals if s.direction == "increase_risk")
            mit_count = sum(1 for s in cat_signals if s.direction == "decrease_risk")
            category_breakdowns[cat_id] = CategoryScoreBreakdown(
                category=cat_id,
                display_name=cat_name,
                risk_score=cat_score,
                positive_signals_count=pos_count,
                mitigating_signals_count=mit_count,
                signals=cat_signals
            )

        # Executive Summary & Deterministic Narrative
        top_positive = sorted(positive_contributions, key=lambda x: abs(x.contribution), reverse=True)
        top_reasons = [f"{c.name} (+{c.contribution} pts)" for c in top_positive[:4]]

        if final_score == 0:
            summary = "No anomalous forensic indicators detected. Email exhibits normal baseline characteristics."
            why_flagged = "All inspected forensic layers (SPF/DKIM/DMARC authentication, URL features, sender identity, and attachments) conform to legitimate baselines without risk anomalies."
        elif positive_contributions:
            legacy_top = [f"{r.label} (+{r.points})" for r in legacy_reasons[:3]]
            summary = f"Email risk assessed as {legacy_severity.capitalize()} ({final_score}/100) driven by {len(legacy_reasons)} forensic signal(s): {', '.join(legacy_top)}."
            drivers_str = "; ".join([f"{c.name} (+{c.contribution} pts)" for c in top_positive[:3]])
            mitigating_str = ""
            if negative_contributions:
                mit_names = [f"{m.name} ({m.contribution} pts)" for m in negative_contributions[:2]]
                mitigating_str = f" Risk was partially mitigated by {', '.join(mit_names)}."
            why_flagged = (
                f"This email was flagged with a Threat Score of {final_score}/100 ({risk_level}) because it triggered "
                f"{len(positive_contributions)} positive threat signal(s) across {len(active_categories)} analytical category(ies). "
                f"Key forensic drivers: {drivers_str}.{mitigating_str}"
            )
        else:
            summary = f"Email risk assessed as {legacy_severity.capitalize()} ({final_score}/100)."
            why_flagged = f"Email evaluated with score {final_score}/100 ({risk_level}). Verified security controls mitigated baseline risk."

        # Audit Metadata Snapshot
        evidence_ids = [c.signal_id for c in all_signals]
        audit_metadata = {
            "scoring_version": self.scoring_version,
            "weights_snapshot": self.weights,
            "thresholds_snapshot": self.thresholds,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "evidence_ids": evidence_ids,
            "model_version": "v1.0-tfidf-logistic"
        }

        return ThreatScoreResult(
            score=final_score,
            risk_level=risk_level,
            severity=legacy_severity,
            confidence=confidence,
            positive_contributions=positive_contributions,
            negative_contributions=negative_contributions,
            top_reasons=top_reasons,
            reasons=legacy_reasons,
            positive_evidence=legacy_positive,
            summary=summary,
            why_flagged=why_flagged,
            category_breakdowns=category_breakdowns,
            model_version="v1.0-tfidf-logistic",
            scoring_version=self.scoring_version,
            audit_metadata=audit_metadata
        )

    def _determine_severity(self, score: int) -> str:
        """Determines legacy severity label based on configured thresholds."""
        for level, bounds in self.thresholds.items():
            if bounds.get("min", 0) <= score <= bounds.get("max", 100):
                return level.lower()
        if score >= 80:
            return "critical"
        if score >= 60:
            return "high"
        if score >= 30:
            return "suspicious"
        return "low"

    def _determine_risk_level(self, score: int) -> str:
        """Determines explainable risk level based on configured risk thresholds."""
        for level, bounds in self.risk_thresholds.items():
            if bounds.get("min", 0) <= score <= bounds.get("max", 100):
                return level.upper()
        if score >= 75:
            return "CRITICAL"
        if score >= 50:
            return "HIGH"
        if score >= 25:
            return "SUSPICIOUS"
        return "LOW"
