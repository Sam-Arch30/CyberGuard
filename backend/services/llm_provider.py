"""
LLM Provider Abstraction for Section 12: AI Analyst Assistant.
Defines BaseLLMProvider interface and implementations for Gemini, OpenAI, and Mock providers.
"""
import os
import re
import abc
import json
import logging
from typing import Optional, Dict, Any
import httpx

logger = logging.getLogger("llm_provider")


class BaseLLMProvider(abc.ABC):
    """Abstract Base Class for LLM inference providers."""

    @abc.abstractmethod
    async def generate_assessment(self, prompt: str, system_prompt: str) -> Optional[str]:
        """
        Submits prompt and system instructions to the LLM.
        Returns the raw string output (expected to be JSON), or None if generation failed.
        """
        pass


class GeminiProvider(BaseLLMProvider):
    """Google Gemini REST API implementation."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "gemini-1.5-flash",
        timeout_seconds: float = 10.0,
        temperature: float = 0.1
    ):
        self.api_key = api_key or os.getenv("GEMINI_API_KEY") or os.getenv("LLM_API_KEY")
        self.model = model or "gemini-1.5-flash"
        self.timeout_seconds = float(timeout_seconds)
        self.temperature = float(temperature)

    async def generate_assessment(self, prompt: str, system_prompt: str) -> Optional[str]:
        if not self.api_key:
            logger.warning("GeminiProvider: Missing API key. Cannot contact Google Gemini API.")
            return None

        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent?key={self.api_key}"
        payload = {
            "system_instruction": {
                "parts": [{"text": system_prompt}]
            },
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": prompt}]
                }
            ],
            "generationConfig": {
                "temperature": self.temperature,
                "response_mime_type": "application/json"
            }
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                res = await client.post(url, json=payload)
                if res.status_code != 200:
                    logger.error(f"GeminiProvider HTTP error {res.status_code}: {res.text}")
                    return None

                data = res.json()
                candidates = data.get("candidates", [])
                if not candidates:
                    logger.warning("GeminiProvider: No completion candidates returned.")
                    return None

                content_parts = candidates[0].get("content", {}).get("parts", [])
                if not content_parts:
                    return None

                return content_parts[0].get("text", "")
        except httpx.TimeoutException:
            logger.warning(f"GeminiProvider: Request timed out after {self.timeout_seconds}s.")
            return None
        except Exception as e:
            logger.error(f"GeminiProvider: Unexpected exception: {e}")
            return None


class OpenAIProvider(BaseLLMProvider):
    """OpenAI Chat Completion REST API implementation."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "gpt-4o-mini",
        timeout_seconds: float = 10.0,
        temperature: float = 0.1
    ):
        self.api_key = api_key or os.getenv("OPENAI_API_KEY") or os.getenv("LLM_API_KEY")
        self.model = model or "gpt-4o-mini"
        self.timeout_seconds = float(timeout_seconds)
        self.temperature = float(temperature)

    async def generate_assessment(self, prompt: str, system_prompt: str) -> Optional[str]:
        if not self.api_key:
            logger.warning("OpenAIProvider: Missing API key. Cannot contact OpenAI API.")
            return None

        url = "https://api.openai.com/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ],
            "temperature": self.temperature,
            "response_format": {"type": "json_object"}
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                res = await client.post(url, headers=headers, json=payload)
                if res.status_code != 200:
                    logger.error(f"OpenAIProvider HTTP error {res.status_code}: {res.text}")
                    return None

                data = res.json()
                choices = data.get("choices", [])
                if not choices:
                    return None

                return choices[0].get("message", {}).get("content", "")
        except httpx.TimeoutException:
            logger.warning(f"OpenAIProvider: Request timed out after {self.timeout_seconds}s.")
            return None
        except Exception as e:
            logger.error(f"OpenAIProvider: Unexpected exception: {e}")
            return None


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
        if not evidence_match:
            evidence_match = re.search(r'<untrusted_analyzed_content>(.*?)</untrusted_analyzed_content>', prompt, re.DOTALL)
        evidence_str = evidence_match.group(1).strip() if evidence_match else "{}"

        try:
            ev = json.loads(evidence_str)
        except Exception:
            ev = {}

        threat = ev.get("threat_score", {})
        ra = ev.get("risk_assessment", {})
        expl = ev.get("explanation", {})
        score = ra.get("risk_score") if (ra and ra.get("risk_score") is not None) else threat.get("score", 0)
        severity = (ra.get("risk_level") or threat.get("severity", "low")).lower()
        reasons = list(threat.get("reasons", []))
        if expl and expl.get("summary"):
            reasons.append(expl["summary"])
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


class LLMProviderFactory:
    """Factory creating configured LLM provider instances."""

    @classmethod
    def create_provider(cls, config: Dict[str, Any]) -> BaseLLMProvider:
        provider_type = (os.getenv("LLM_PROVIDER") or config.get("provider") or "mock").strip().lower()
        model = os.getenv("LLM_MODEL") or config.get("model") or "gemini-1.5-flash"
        timeout_seconds = float(os.getenv("LLM_TIMEOUT_SECONDS") or config.get("timeout_seconds") or 10.0)
        temperature = float(config.get("temperature", 0.1))

        if provider_type == "gemini":
            return GeminiProvider(model=model, timeout_seconds=timeout_seconds, temperature=temperature)
        elif provider_type == "openai":
            return OpenAIProvider(model=model, timeout_seconds=timeout_seconds, temperature=temperature)
        else:
            return MockLLMProvider(model=model)

    create = create_provider
