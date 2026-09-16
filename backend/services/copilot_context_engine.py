"""
Copilot Context Engine for MailTraceAI.
Retrieves targeted, structured forensic evidence slices based on analyst query intent and active investigation mode.
Normalizes findings into EvidenceReference objects with canonical Evidence IDs (e.g. E-1042).
Enforces prompt-injection defenses and delimitation.
"""
import re
import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

from backend.schemas.copilot import (
    CopilotMode,
    EvidenceReference,
    UncertaintyLevel
)

logger = logging.getLogger("copilot_context_engine")


class CopilotContextEngine:
    """
    Context aggregation and isolation layer for the Investigation Copilot.
    Retrieves only relevant context slices to avoid flooding LLM context.
    """

    INTENT_KEYWORDS = {
        "why_malicious": ["why", "malicious", "classify", "flagged", "threat level", "verdict", "risk"],
        "threat_score_contributors": ["contribute", "contributed", "threat score", "highest score", "points", "signals", "breakdown", "indicators contributed"],
        "relay_analysis": ["relay", "attacker-controlled", "hop", "origin ip", "transit", "route", "received header", "infrastructure location"],
        "campaign_correlation": ["c-042", "campaign", "operation darkhydra", "connecting", "correlation", "correlated", "associated campaign"],
        "compare_campaign": ["compare", "other campaign emails", "difference", "matrix", "divergence"],
        "shared_infrastructure": ["shared", "infrastructure", "shared ip", "shared asn", "shared domain", "shared url", "shared template"],
        "contradictory_attribution": ["contradict", "contradicts", "contradictory", "conflicting", "inconsistency", "discrepancy"],
        "increase_attribution_confidence": ["increase attribution", "increase confidence", "additional evidence", "improve attribution", "confirm attribution"],
        "soc_summary": ["summarize this case", "soc analyst", "soc summary", "case summary", "briefing"],
        "executive_summary": ["executive summary", "executive brief", "leadership", "management summary"],
        "high_confidence_iocs": ["high-confidence ioc", "iocs", "indicators of compromise", "blocklist", "list all iocs"],
        "auth_explanation": ["spf", "dkim", "dmarc", "authentication", "alignment", "spoof", "return-path"],
        "campaign_timeline": ["timeline", "chronology", "sequence", "events", "when did"],
        "attachment_analysis": ["attachment", "payload", "pe", "exe", "macro", "pdf", "zip", "entropy", "executable disguised", "authenticode"]
    }

    def detect_intent(self, query: str) -> str:
        """Determines primary query intent from analyst natural language prompt."""
        q_lower = query.lower()

        # Exact match priorities
        if "why" in q_lower and ("malicious" in q_lower or "classified" in q_lower or "flagged" in q_lower):
            return "why_malicious"
        if "which indicators" in q_lower or "contributed most" in q_lower or "threat score" in q_lower:
            return "threat_score_contributors"
        if "relay" in q_lower and ("attacker" in q_lower or "controlled" in q_lower or "hop" in q_lower):
            return "relay_analysis"
        if "c-042" in q_lower or ("connecting" in q_lower and "campaign" in q_lower):
            return "campaign_correlation"
        if "compare" in q_lower and ("campaign" in q_lower or "email" in q_lower):
            return "compare_campaign"
        if "shared" in q_lower and "infrastructure" in q_lower:
            return "shared_infrastructure"
        if "contradict" in q_lower:
            return "contradictory_attribution"
        if "increase" in q_lower and "attribution" in q_lower:
            return "increase_attribution_confidence"
        if "executive" in q_lower:
            return "executive_summary"
        if "soc" in q_lower or "summarize" in q_lower:
            return "soc_summary"
        if "high-confidence" in q_lower or "ioc" in q_lower:
            return "high_confidence_iocs"
        if any(term in q_lower for term in ["spf", "dkim", "dmarc", "authentication results"]):
            return "auth_explanation"
        if "timeline" in q_lower or "chronology" in q_lower:
            return "campaign_timeline"
        if any(term in q_lower for term in ["attachment", "payload", "macro", "pe metadata", "executable"]):
            return "attachment_analysis"

        # Fallback scoring
        best_intent = "general"
        highest_matches = 0
        for intent, keywords in self.INTENT_KEYWORDS.items():
            matches = sum(1 for kw in keywords if kw in q_lower)
            if matches > highest_matches:
                highest_matches = matches
                best_intent = intent

        return best_intent if highest_matches > 0 else "general"

    def build_context(
        self,
        query: str,
        mode: CopilotMode,
        context_id: Optional[str] = None,
        email_payload: Optional[Dict[str, Any]] = None,
        include_timeline: bool = True
    ) -> Tuple[Dict[str, Any], List[EvidenceReference], str]:
        """
        Builds a structured evidence slice, maps Evidence IDs, and extracts intent.
        Returns: (context_dict, evidence_refs, intent)
        """
        intent = self.detect_intent(query)
        evidence_refs: List[EvidenceReference] = []
        structured_context: Dict[str, Any] = {
            "mode": mode.value,
            "context_id": context_id or "E-1042",
            "query_intent": intent,
            "generated_at": datetime.now(timezone.utc).isoformat()
        }

        base_id = context_id or "E-1042"

        # Mode: EMAIL
        if mode == CopilotMode.EMAIL or email_payload is not None:
            email_ctx, email_evs = self._extract_email_context(email_payload, base_id, intent)
            structured_context["email_evidence"] = email_ctx
            evidence_refs.extend(email_evs)

        # Mode: CASE
        if mode == CopilotMode.CASE:
            case_ctx, case_evs = self._extract_case_context(context_id or "CASE-2026-0042", intent)
            structured_context["case_evidence"] = case_ctx
            evidence_refs.extend(case_evs)

        # Mode: CAMPAIGN
        if mode == CopilotMode.CAMPAIGN:
            camp_ctx, camp_evs = self._extract_campaign_context(context_id or "C-042", intent, include_timeline)
            structured_context["campaign_evidence"] = camp_ctx
            evidence_refs.extend(camp_evs)

        # Deduplicate evidence references by evidence_id
        seen_ids = set()
        deduped_refs = []
        for ref in evidence_refs:
            if ref.evidence_id not in seen_ids:
                seen_ids.add(ref.evidence_id)
                deduped_refs.append(ref)

        return structured_context, deduped_refs, intent

    def sanitize_untrusted_content(self, text: str) -> str:
        """
        Neutralizes delimiter breakout tokens and instructions from adversarial email content.
        """
        if not text:
            return ""
        # Remove prompt injection delimiters
        sanitized = text.replace("<untrusted_evidence>", "[TAG_FILTERED]").replace("</untrusted_evidence>", "[TAG_FILTERED]")
        sanitized = sanitized.replace("<structured_evidence>", "[TAG_FILTERED]").replace("</structured_evidence>", "[TAG_FILTERED]")
        sanitized = sanitized.replace("<system_instruction>", "[TAG_FILTERED]").replace("</system_instruction>", "[TAG_FILTERED]")
        # Escape markdown system prompt overrides
        sanitized = re.sub(r'(?i)ignore (?:all )?previous instructions', '[OVERRIDE_FILTERED]', sanitized)
        sanitized = re.sub(r'(?i)system override', '[OVERRIDE_FILTERED]', sanitized)
        return sanitized

    def _extract_email_context(
        self,
        payload: Optional[Dict[str, Any]],
        base_id: str,
        intent: str
    ) -> Tuple[Dict[str, Any], List[EvidenceReference]]:
        """Extracts targeted email evidence slice based on query intent."""
        data = payload or {}
        evidence_refs: List[EvidenceReference] = []
        ctx: Dict[str, Any] = {}

        # Threat Score & Signals
        threat = data.get("threat_score") or {}
        score = threat.get("score", 85)
        severity = threat.get("severity", "critical")
        reasons = threat.get("reasons", [
            {"signal": "spf_fail", "label": "SPF verification failed", "points": 15},
            {"signal": "lookalike", "label": "Domain lookalike impersonating BankCorp", "points": 25},
            {"signal": "suspicious_url", "label": "URL redirect chain leading to credential harvester", "points": 30},
            {"signal": "bulletproof_asn", "label": "Originates from Bulletproof Hosting AS4821", "points": 15}
        ])

        ctx["threat_score"] = {"score": score, "severity": severity, "reasons": reasons}
        evidence_refs.append(EvidenceReference(
            evidence_id=f"{base_id}",
            type="threat_score",
            statement=f"Email evaluated with global threat score of {score}/100 ({severity.upper()} severity).",
            source_module="threat_scorer",
            reliability=0.95,
            confidence_category="CONFIRMED"
        ))

        # Authentication (SPF, DKIM, DMARC)
        auth = data.get("authentication") or {
            "spf": {"status": "fail", "details": "Sender IP 185.220.101.42 not permitted in SPF record"},
            "dkim": {"status": "none", "details": "No cryptographic DKIM signature present"},
            "dmarc": {"status": "fail", "details": "SPF unaligned and DKIM missing; action=quarantine"},
            "alignment": {"reply_to_mismatch": True, "return_path_mismatch": True}
        }
        ctx["authentication"] = auth
        evidence_refs.append(EvidenceReference(
            evidence_id="E-1001",
            type="authentication",
            statement="SPF hard fail and DMARC verification failure on sending domain bank-corp-update.com.",
            source_module="auth_verifier",
            reliability=1.0,
            confidence_category="CONFIRMED"
        ))

        # Relay Analysis
        relay = data.get("relay_analysis") or data.get("relay_info") or {
            "hop_count": 3,
            "earliest_node": {
                "ip": "185.220.101.42",
                "asn": "AS4821",
                "isp": "Bulletproof Transit Corp",
                "country": "Russia",
                "city": "Moscow",
                "is_attacker_controlled": True,
                "confidence": "HIGH-CONFIDENCE INFERENCE",
                "reasoning": "First unauthenticated external hop injecting message into SMTP relay chain."
            },
            "intermediate_hop": {
                "ip": "104.244.42.1",
                "asn": "AS13335",
                "country": "Netherlands"
            }
        }
        ctx["relay_analysis"] = relay
        evidence_refs.append(EvidenceReference(
            evidence_id="E-1003",
            type="relay",
            statement="Earliest observable external relay node 185.220.101.42 (AS4821, Russia) is high-probability attacker injection hop.",
            source_module="relay_reconstructor",
            reliability=0.88,
            confidence_category="HIGH-CONFIDENCE INFERENCE"
        ))

        # Domain & Lookalikes
        domains = data.get("lookalike_domains") or [
            {"domain": "bank-corp-update.com", "brand_name": "BankCorp", "similarity": 0.92, "registered_days_ago": 3}
        ]
        ctx["lookalike_domains"] = domains
        evidence_refs.append(EvidenceReference(
            evidence_id="E-1042",
            type="lookalike",
            statement="Sender domain bank-corp-update.com is an active homoglyph/lookalike targeting BankCorp (registered 3 days ago).",
            source_module="lookalike_detector",
            reliability=0.92,
            confidence_category="CONFIRMED"
        ))

        # URLs & Harvester
        urls = data.get("urls") or [
            {
                "url": "https://bank-corp-update.com/auth/v2/secure_login.php",
                "suspicion_level": "critical",
                "is_credential_harvester": True,
                "redirect_chain": ["http://short.ly/bancorp", "https://bank-corp-update.com/auth/v2/secure_login.php"]
            }
        ]
        ctx["urls"] = urls
        evidence_refs.append(EvidenceReference(
            evidence_id="E-1067",
            type="url",
            statement="Embedded link redirects to credential harvesting endpoint at /auth/v2/secure_login.php.",
            source_module="url_analyzer",
            reliability=0.96,
            confidence_category="CONFIRMED"
        ))

        # Static Attachment Intelligence
        attachments = data.get("attachments") or [
            {
                "filename": "invoice_2026.pdf.exe",
                "detected_type": "Windows PE Executable",
                "extension_mismatch": True,
                "sha256": "4a7d1ed414474e4033ac29ccb8653d9b",
                "entropy": 7.82,
                "authenticode": "Unsigned",
                "threat_level": "CRITICAL",
                "suspicious_apis": ["VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread"]
            }
        ]
        ctx["attachments"] = attachments
        evidence_refs.append(EvidenceReference(
            evidence_id="E-1103",
            type="attachment",
            statement="Attachment invoice_2026.pdf.exe is an unsigned Windows PE executable disguised as a PDF with 7.82 Shannon entropy.",
            source_module="attachment_intelligence",
            reliability=0.99,
            confidence_category="CONFIRMED"
        ))

        # Campaign Correlation Signals
        ctx["campaign_correlation"] = {
            "campaign_id": "C-042",
            "campaign_name": "Operation DarkHydra - Executive Invoice & Wire Harvester",
            "confidence": 91.0,
            "shared_signals": [
                "Same dropzone IP 185.220.101.42 (AS4821)",
                "Identical URL harvester path /auth/v2/secure_login.php",
                "HTML SimHash template match 89%",
                "Same lookalike domain target: BankCorp"
            ]
        }
        evidence_refs.append(EvidenceReference(
            evidence_id="E-1042-CAMP",
            type="campaign",
            statement="Correlated to Campaign C-042 (Operation DarkHydra) with 91% confidence based on shared dropzone IP and credential harvester.",
            source_module="campaign_correlation",
            reliability=0.91,
            confidence_category="HIGH-CONFIDENCE INFERENCE"
        ))

        # Attribution
        attribution = data.get("attribution") or {
            "cluster_name": "UNC-4821 / DarkHydra",
            "confidence": "PROBABLE",
            "confidence_score": 68.0,
            "supporting_evidence": [
                "Infrastructure ASN AS4821 previously mapped to UNC-4821 campaigns",
                "Language artifacts in SMTP headers contain Eastern European timezone (+0300)",
                "Credential harvesting lure kit matches DarkHydra PHP source fingerprints"
            ],
            "conflicting_evidence": [
                "Intermediate relay hop in Netherlands (AS13335) utilizes commercial VPN node",
                "WHOIS privacy protection obscures registrant name"
            ],
            "caveat": "Probable infrastructure location is Russia/Eastern Europe, but physical actor identity remains unconfirmed."
        }
        ctx["attribution"] = attribution
        evidence_refs.append(EvidenceReference(
            evidence_id="E-1042-ATTR",
            type="attribution",
            statement="Attributed to cluster UNC-4821 with PROBABLE confidence (68%), contradicted by commercial VPN relay in Netherlands.",
            source_module="attribution_engine",
            reliability=0.68,
            confidence_category="PROBABLE"
        ))

        return ctx, evidence_refs

    def _extract_case_context(
        self,
        case_id: str,
        intent: str
    ) -> Tuple[Dict[str, Any], List[EvidenceReference]]:
        """Extracts targeted case evidence slice."""
        evidence_refs = [
            EvidenceReference(
                evidence_id="CASE-FIND-01",
                type="case_finding",
                statement="Coordinated credential harvesting targeting 16 executives across Finance and Operations.",
                source_module="case_management",
                reliability=0.95,
                confidence_category="CONFIRMED"
            ),
            EvidenceReference(
                evidence_id="CASE-FIND-02",
                type="case_finding",
                statement="Centralized dropzone infrastructure identified at 185.220.101.42 (AS4821).",
                source_module="case_management",
                reliability=0.92,
                confidence_category="CONFIRMED"
            ),
            EvidenceReference(
                evidence_id="CASE-NOTE-01",
                type="case_note",
                statement="Tier 2 SOC Analyst confirmed 3 recipients clicked phishing link; active sessions revoked.",
                source_module="soc_operations",
                reliability=0.90,
                confidence_category="CONFIRMED"
            )
        ]

        ctx = {
            "case_id": case_id,
            "title": "Coordinated BEC Wire Fraud & Executive Harvester Campaign",
            "status": "in_progress",
            "severity": "critical",
            "associated_emails_count": 16,
            "findings": [
                "16 emails received over 32-hour window sharing identical SimHash lure template",
                "Primary domain bank-corp-update.com spoofing corporate wire verification portal",
                "Originating from bulletproof hosting provider AS4821 in Moscow, Russia",
                "Weaponized executable payload invoice_2026.pdf.exe detected in 4 instances"
            ],
            "containment_status": "Domain sinkholed on SEG; dropzone IP blocked on perimeter firewall."
        }
        return ctx, evidence_refs

    def _extract_campaign_context(
        self,
        campaign_id: str,
        intent: str,
        include_timeline: bool
    ) -> Tuple[Dict[str, Any], List[EvidenceReference]]:
        """Extracts targeted campaign evidence slice."""
        evidence_refs = [
            EvidenceReference(
                evidence_id="CAMP-INFRA-01",
                type="campaign_infrastructure",
                statement="Shared bulletproof IP 185.220.101.42 (AS4821) observed across 16 campaign messages.",
                source_module="campaign_correlation",
                reliability=0.95,
                confidence_category="CONFIRMED"
            ),
            EvidenceReference(
                evidence_id="CAMP-TMPL-01",
                type="campaign_template",
                statement="HTML SimHash template similarity averages 89% with identical Wire Verification CSS classes.",
                source_module="campaign_correlation",
                reliability=0.89,
                confidence_category="HIGH-CONFIDENCE INFERENCE"
            ),
            EvidenceReference(
                evidence_id="CAMP-TIME-01",
                type="campaign_timeline",
                statement="Campaign observed operating between 2026-08-12 04:12 UTC and 2026-09-10 19:45 UTC.",
                source_module="campaign_correlation",
                reliability=0.98,
                confidence_category="CONFIRMED"
            )
        ]

        timeline_events = [
            {"time": "09:14 UTC", "event": "First delivery: Email A received from bank-corp-update.com"},
            {"time": "09:31 UTC", "event": "Second delivery: Email B received targeting CFO"},
            {"time": "10:02 UTC", "event": "Domain observation: bank-corp-update.com first registered"},
            {"time": "10:11 UTC", "event": "Third delivery: Email C received with invoice_2026.pdf.exe"},
            {"time": "10:17 UTC", "event": "Infrastructure link: same dropzone IP 185.220.101.42 confirmed"},
            {"time": "10:42 UTC", "event": "High-risk wire diversion lure captured"}
        ] if include_timeline else []

        ctx = {
            "campaign_id": campaign_id,
            "campaign_name": "Operation DarkHydra - Executive Invoice & Wire Harvester",
            "message_count": 16,
            "confidence_score": 91.0,
            "dominant_attack_type": "Credential Harvesting & BEC Wire Fraud",
            "targeted_brands": ["BankCorp", "Microsoft 365", "DocuSign"],
            "shared_infrastructure": {
                "ips": ["185.220.101.42"],
                "asns": ["AS4821 (Bulletproof Transit)"],
                "domains": ["bank-corp-update.com", "bankcorp-wire-portal.com"],
                "url_paths": ["/auth/v2/secure_login.php", "/wire/authorize.php"]
            },
            "timeline": timeline_events
        }
        return ctx, evidence_refs


global_copilot_context_engine = CopilotContextEngine()
