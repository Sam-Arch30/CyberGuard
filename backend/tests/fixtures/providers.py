import json
import re
from backend.services.ip_providers import BaseIPIntelligenceProvider, _validate_and_check_ip
from backend.services.llm_provider import BaseLLMProvider
from backend.schemas.ip_intelligence import IPIntelligence

class MockIPIntelligenceProvider(BaseIPIntelligenceProvider):
    """
    Fallback / Mock Provider for offline execution, unit tests, or keyless deployments.
    Generates realistic contextual data for test public IPs.
    """

    def get_provider_name(self) -> str:
        return "mock"

    def is_configured(self) -> bool:
        return True

    async def lookup(self, ip: str) -> IPIntelligence:
        is_public, clean_ip, early_res = _validate_and_check_ip(ip)
        if early_res:
            return early_res

        # Deterministic mock generation based on IP octets
        if clean_ip.startswith("203.0.113.") or clean_ip.startswith("198.51.100.") or clean_ip.startswith("192.0.2."):
            return IPIntelligence(
                ip=clean_ip,
                scope="public",
                enrichment_available=True,
                country="Netherlands",
                country_code="NL",
                region="North Holland",
                city="Amsterdam",
                latitude=52.3676,
                longitude=4.9041,
                timezone="Europe/Amsterdam",
                asn="AS12345",
                asn_org="Example Cloud Hosting BV",
                isp="Example Cloud Infrastructure",
                organization="Example Cloud Services",
                is_hosting=True,
                is_proxy_vpn_tor=False,
                infrastructure_type="Hosting infrastructure",
                source="mock",
                confidence=0.90,
                error=None
            )

        return IPIntelligence(
            ip=clean_ip,
            scope="public",
            enrichment_available=True,
            country="United States",
            country_code="US",
            region="California",
            city="Mountain View",
            latitude=37.3860,
            longitude=-122.0839,
            timezone="America/Los_Angeles",
            asn="AS15169",
            asn_org="Google LLC",
            isp="Google LLC",
            organization="Google Cloud Platform",
            is_hosting=True,
            is_proxy_vpn_tor=False,
            infrastructure_type="Hosting infrastructure",
            source="mock",
            confidence=0.90,
            error=None
        )

class MockLLMProvider(BaseLLMProvider):
    """
    Offline/local mock provider.
    Synthesizes structured forensic telemetry into a grounded, deterministic assessment
    without calling external third-party APIs.
    """

    def __init__(self, model: str = "mock-analyst-v1"):
        self.model = model

    async def generate_assessment(self, prompt: str, system_prompt: str) -> Optional[str]:
        # Extract the structured evidence block from the prompt
        evidence_match = re.search(r'<structured_forensic_evidence>(.*?)</structured_forensic_evidence>', prompt, re.DOTALL)
        evidence_str = evidence_match.group(1).strip() if evidence_match else "{}"

        try:
            ev = json.loads(evidence_str)
        except Exception:
            ev = {}

        threat = ev.get("threat_score", {})
        score = threat.get("score", 0)
        severity = threat.get("severity", "low").lower()
        reasons = threat.get("reasons", [])
        ml = ev.get("ml_content_assessment", {})
        ml_prob = ml.get("probability")
        lookalikes = ev.get("lookalike_domains", [])
        urls = ev.get("urls", [])
        auth = ev.get("authentication", {})
        attachments = ev.get("attachments_metadata", [])

        # Categorize likely attack type based strictly on supplied evidence
        has_lookalike = len(lookalikes) > 0
        has_suspicious_url = any(u.get("suspicion_level") in ("high", "suspicious") for u in urls)
        has_dmarc_fail = auth.get("dmarc") == "fail"
        has_dangerous_att = any(
            any(a.get("filename", "").lower().endswith(ext) for ext in [".exe", ".scr", ".bat", ".vbs", ".js", ".ps1", ".jar", ".iso", ".docm"])
            for a in attachments
        )
        is_wire_bec = any("financial" in r.lower() or "wire" in r.lower() for r in reasons)
        is_cred_harvest = any("credential" in r.lower() or "password" in r.lower() or "verify" in r.lower() for r in reasons)

        if has_dangerous_att:
            attack_type = "Malware Delivery via Malicious Attachment"
            objective = "Host compromise and code execution via weaponized attachment"
        elif is_wire_bec:
            attack_type = "Business Email Compromise (BEC) / Wire Transfer Fraud"
            objective = "Financial payment diversion to fraudulent bank or crypto destination"
        elif is_cred_harvest or has_lookalike or (ml_prob is not None and ml_prob >= 0.70):
            attack_type = "Credential Harvesting Phishing"
            objective = "Theft of corporate directory or single-sign-on credentials via spoofed interfaces"
        elif score >= 60:
            attack_type = "Suspicious Phishing Lure"
            objective = "Deceptive engagement or user coercion via untrusted infrastructure"
        else:
            attack_type = "Benign Communication / Low Risk Baseline"
            objective = "Routine organizational correspondence or transactional notice"

        # Build grounded key evidence
        key_evidence = []
        if score > 0:
            key_evidence.append(f"Global threat score evaluated at {score}/100 ({severity.upper()} severity).")
        for r in reasons[:4]:
            key_evidence.append(f"Forensic indicator: {r}")
        if has_lookalike:
            b = lookalikes[0]
            key_evidence.append(f"Brand lookalike detected: '{b.get('domain')}' targeting '{b.get('brand')}'.")
        if auth.get("spf") == "fail" or auth.get("dmarc") == "fail":
            key_evidence.append(f"Email authentication mismatch: SPF={auth.get('spf')}, DMARC={auth.get('dmarc')}.")
        if ml_prob is not None:
            key_evidence.append(f"NLP text assessment indicates {int(ml_prob * 100)}% phishing probability.")

        if not key_evidence:
            key_evidence.append("All observed authentication and content indicators match normal baseline.")

        # Build prescriptive actions
        recommended_actions = []
        if score >= 60:
            recommended_actions.append("Quarantine or purge email from recipient inboxes across mail infrastructure.")
            recommended_actions.append("Block originating IP and lookalike sender domain on secure email gateway (SEG).")
            if is_cred_harvest:
                recommended_actions.append("Force immediate password reset and invalidate active sessions for targeted user.")
            if urls:
                recommended_actions.append("Submit detected phishing URLs to web proxy and DNS sinkhole blocklists.")
        elif score >= 30:
            recommended_actions.append("Tag message header with [SUSPICIOUS] warning banner for internal recipient.")
            recommended_actions.append("Monitor user account for anomalous authentication or link traversal events.")
        else:
            recommended_actions.append("No containment action necessary; message conforms to normal operational profile.")

        # Build grounded limitations
        limitations = [
            "Analysis is bounded to static email telemetry and Received header topology.",
            "Dynamic sandbox detonation was not performed on embedded attachments.",
            "Attribution is limited to observable IP/DNS infrastructure without external threat actor correlation."
        ]

        summary = (
            f"The analyzed email presents characteristics of {attack_type} with a deterministic threat score of {score}/100 ({severity.upper()}). "
            f"Key driving indicators include {len(reasons)} forensic flag(s). "
            f"Adversary objective is assessed as: {objective}."
        )

        mock_result = {
            "summary": summary,
            "likely_attack_type": attack_type,
            "likely_objective": objective,
            "key_evidence": key_evidence,
            "recommended_actions": recommended_actions,
            "limitations": limitations
        }

        return json.dumps(mock_result)


