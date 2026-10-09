"""
LLM Explanation Layer and Grounding Validation Service for CyberGuard (Section 27).

Orchestrates:
1. Strict evidence grounding payload construction
2. Untrusted LLM output validation against authoritative ground-truth entities
3. Automatic fallback to deterministic templates on hallucination or LLM failure
4. Explainability Quality Metrics calculation
"""
from __future__ import annotations

import json
import logging
import os
import re
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from backend.schemas.explainable_ai import (
    ExplanationLayer,
    ExplanationQualityMetrics,
    ExplanationResponse,
    NarrativeGenerationResponse,
)
from backend.services.llm_provider import BaseLLMProvider, LLMProviderFactory

logger = logging.getLogger("cyberguard.xai.llm")


class LLMExplanationService:
    """Provides evidence-grounded natural language synthesis with hallucination rejection."""

    # Regex patterns to detect factual entities in generated text
    IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    DOMAIN_PATTERN = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|dev|biz|xyz|top|cc|ru|cn|in|app|ai|me)\b", re.IGNORECASE)
    HASH_PATTERN = re.compile(r"\b[a-fA-F0-9]{32,64}\b")
    MITRE_PATTERN = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
    SCORE_PATTERN = re.compile(r"\b(?:risk(?:\s+score)?[:\s]+(\d+(?:\.\d+)?)|(\d+(?:\.\d+)?)\s*/\s*100)\b", re.IGNORECASE)

    # Allowed general terms that look like domains or words
    SAFE_DOMAIN_WHITELIST = {
        "cyberguard.io", "example.com", "microsoft.com", "google.com", "mailtrace.ai"
    }

    SYSTEM_PROMPT = """You are CyberGuard's Explainable AI (XAI) Synthesis Engine.
Your role is to explain CyberGuard's security decision to human analysts and investigators based ONLY on the supplied structured ground truth.

CRITICAL ARCHITECTURAL CONSTRAINTS:
1. STRICT GROUNDING: You must ONLY reference factual entities (IPs, domains, hashes, techniques, scores) explicitly present in <structured_ground_truth>.
2. ABSOLUTELY NO HALLUCINATIONS: Do NOT invent IP addresses, domain names, file hashes, actor names, CVEs, or MITRE techniques not in the input.
3. PRESERVE AUTHORITATIVE SCORES: The Risk Score, Severity, and Confidence in the structured ground truth are final and authoritative. NEVER alter them or claim a different risk score.
4. EPISTEMIC HUMILITY:
   - Always state that infrastructure association does not prove human attribution.
   - Do not claim novelty is malicious without supporting indicators.
   - Use "temporally correlated" rather than "caused" unless direct causal evidence is cited.
5. NO CHAIN-OF-THOUGHT: Provide a direct, polished, professional forensic narrative.
"""

    def __init__(self, provider: Optional[BaseLLMProvider] = None, config: Optional[Dict[str, Any]] = None):
        self.config = config or {
            "enabled": True,
            "provider": os.getenv("LLM_PROVIDER", "mock"),
            "model": os.getenv("LLM_MODEL", "gemini-1.5-flash"),
            "temperature": 0.0,  # Zero temperature for maximum deterministic grounding
        }
        self.provider = provider or LLMProviderFactory.create_provider(self.config)

    def extract_ground_truth_entities(self, explanation: ExplanationResponse) -> Dict[str, Set[str]]:
        """Extracts all legitimate, authoritative factual entities from the structured explanation."""
        entities: Dict[str, Set[str]] = {
            "ips": set(),
            "domains": set(),
            "hashes": set(),
            "mitre_ids": set(),
            "scores": {f"{explanation.risk_score:.0f}", f"{explanation.risk_score:.1f}", str(int(explanation.risk_score))},
        }

        # Gather from claims
        for u in explanation.explanation_units:
            text = f"{u.claim} {' '.join(u.evidence_refs)} {' '.join(u.source_refs)}"
            for ip in self.IP_PATTERN.findall(text):
                entities["ips"].add(ip)
            for d in self.DOMAIN_PATTERN.findall(text):
                entities["domains"].add(d.lower())
            for h in self.HASH_PATTERN.findall(text):
                entities["hashes"].add(h.lower())

        # Gather from MITRE
        for m in explanation.mitre_explanations:
            entities["mitre_ids"].add(m.technique_id.upper())

        # Gather from contributors
        for c in explanation.contributors:
            text = str(c)
            for ip in self.IP_PATTERN.findall(text):
                entities["ips"].add(ip)
            for d in self.DOMAIN_PATTERN.findall(text):
                entities["domains"].add(d.lower())

        return entities

    def validate_narrative(
        self,
        narrative: str,
        ground_truth: Dict[str, Set[str]],
    ) -> Tuple[bool, List[str]]:
        """
        Validates that generated text does not introduce unsupported factual entities.
        Returns (is_valid, list_of_unsupported_entities).
        """
        unsupported: List[str] = []

        # 1. Validate IP addresses
        mentioned_ips = set(self.IP_PATTERN.findall(narrative))
        for ip in mentioned_ips:
            if ip not in ground_truth["ips"]:
                unsupported.append(f"Unsupported IP address: {ip}")

        # 2. Validate domains
        mentioned_domains = set(self.DOMAIN_PATTERN.findall(narrative))
        for d in mentioned_domains:
            d_clean = d.lower()
            if d_clean not in ground_truth["domains"] and d_clean not in self.SAFE_DOMAIN_WHITELIST:
                unsupported.append(f"Unsupported Domain: {d}")

        # 3. Validate hashes
        mentioned_hashes = set(self.HASH_PATTERN.findall(narrative))
        for h in mentioned_hashes:
            if h.lower() not in ground_truth["hashes"]:
                unsupported.append(f"Unsupported Hash: {h}")

        # 4. Validate MITRE techniques
        mentioned_mitre = set(self.MITRE_PATTERN.findall(narrative))
        for m in mentioned_mitre:
            if m.upper() not in ground_truth["mitre_ids"]:
                unsupported.append(f"Unsupported MITRE Technique: {m}")

        # 5. Validate risk scores
        score_matches = self.SCORE_PATTERN.findall(narrative)
        for m in score_matches:
            val = m[0] or m[1]
            if val:
                val_clean = str(float(val)) if "." in val else str(int(val))
                allowed_vals = {f"{float(s):.1f}" for s in ground_truth["scores"]} | {f"{float(s):.0f}" for s in ground_truth["scores"]}
                if val_clean not in allowed_vals:
                    unsupported.append(f"Altered Risk Score: {val} (expected {ground_truth['scores']})")

        is_valid = len(unsupported) == 0
        return is_valid, unsupported

    async def generate_grounded_narrative(
        self,
        explanation: ExplanationResponse,
        detail_level: ExplanationLayer = ExplanationLayer.ANALYST,
        strict_validation: bool = True,
    ) -> NarrativeGenerationResponse:
        """
        Generates an LLM-synthesized narrative strictly grounded in the explanation payload.
        Automatically falls back to deterministic explanation if validation fails or LLM errors.
        """
        start_time = time.time()
        ground_truth = self.extract_ground_truth_entities(explanation)

        # Deterministic fallback text
        fallback_text = (
            explanation.executive_summary
            if detail_level == ExplanationLayer.EXECUTIVE
            else explanation.analyst_summary
        )

        # Construct strict grounding payload
        payload = {
            "scope_type": explanation.scope_type.value,
            "scope_id": explanation.scope_id,
            "risk_score": explanation.risk_score,
            "risk_level": explanation.risk_level.value,
            "severity": explanation.severity.value,
            "confidence": explanation.confidence,
            "confidence_level": explanation.confidence_level.value,
            "uncertainty": explanation.uncertainty.value,
            "key_claims": [
                {"claim": u.claim, "type": u.claim_type.value, "support": u.support_level.value, "evidence": u.evidence_refs}
                for u in explanation.explanation_units[:8]
            ],
            "counter_evidence": [
                {"claim": c.claim, "interpretation": c.interpretation} for c in explanation.counter_evidence[:4]
            ],
            "contradictions": [
                {"claim": c.claim, "conflicting": c.conflicting_signal} for c in explanation.contradictions[:3]
            ],
            "mitre_techniques": [
                {"id": m.technique_id, "name": m.technique_name, "why": m.why_mapped} for m in explanation.mitre_explanations[:4]
            ],
            "limitations": explanation.limitations[:4],
        }

        user_prompt = (
            f"Explain the following CyberGuard security assessment at the {detail_level.value} level.\n"
            f"<structured_ground_truth>\n{json.dumps(payload, indent=2)}\n</structured_ground_truth>\n\n"
            f"Synthesize this into a clear, cohesive explanation without introducing any external entities."
        )

        raw_narrative = None
        used_fallback = False
        unsupported_entities: List[str] = []
        validation_passed = False

        try:
            raw_narrative = await self.provider.generate_assessment(
                prompt=user_prompt,
                system_prompt=self.SYSTEM_PROMPT,
            )
        except Exception as exc:
            logger.warning(f"LLM generation failed or timed out: {exc}. Falling back to deterministic summary.")

        if raw_narrative and raw_narrative.strip():
            # If provider returned valid text
            text_candidate = raw_narrative.strip()
            # If wrapped in JSON or markdown codeblocks, strip them
            if text_candidate.startswith("```"):
                text_candidate = re.sub(r"^```[a-zA-Z]*\n", "", text_candidate)
                text_candidate = re.sub(r"\n```$", "", text_candidate)

            # Validate against ground truth entities
            if strict_validation:
                is_valid, unsupp = self.validate_narrative(text_candidate, ground_truth)
                if is_valid:
                    final_narrative = text_candidate
                    validation_passed = True
                else:
                    logger.warning(f"LLM output rejected due to unsupported entities: {unsupp}. Using deterministic fallback.")
                    final_narrative = fallback_text
                    used_fallback = True
                    unsupported_entities = unsupp
            else:
                final_narrative = text_candidate
                validation_passed = True
        else:
            final_narrative = fallback_text
            used_fallback = True
            validation_passed = False

        duration_ms = (time.time() - start_time) * 1000.0

        return NarrativeGenerationResponse(
            explanation_id=explanation.id,
            narrative=final_narrative,
            validation_passed=validation_passed,
            used_fallback=used_fallback,
            unsupported_entities_detected=unsupported_entities,
            generation_duration_ms=round(duration_ms, 2),
            model_used=self.config.get("model", "mock"),
        )

    @classmethod
    def compute_quality_metrics(cls, explanation: ExplanationResponse) -> ExplanationQualityMetrics:
        """
        Computes explainability quality metrics (NOT security accuracy).
        Measures evidentiary grounding completeness and rigor.
        """
        total_claims = len(explanation.explanation_units)
        grounded_claims = sum(1 for u in explanation.explanation_units if len(u.evidence_refs) > 0)
        unsupported_claims = total_claims - grounded_claims

        grounding_rate = (grounded_claims / total_claims) if total_claims > 0 else 1.0
        unsupported_rate = (unsupported_claims / total_claims) if total_claims > 0 else 0.0

        indep_count = sum(1 for g in explanation.evidence_groups if g.is_independent)
        prov_resolved = sum(1 for u in explanation.explanation_units if u.provenance and len(u.provenance) > 0)
        prov_rate = (prov_resolved / total_claims) if total_claims > 0 else 1.0

        return ExplanationQualityMetrics(
            total_claims=total_claims,
            grounded_claims=grounded_claims,
            claim_grounding_rate=round(grounding_rate, 3),
            unsupported_claim_rate=round(unsupported_rate, 3),
            counter_evidence_count=len(explanation.counter_evidence),
            contradiction_count=len(explanation.contradictions),
            independent_evidence_families=indep_count,
            provenance_resolution_rate=round(prov_rate, 3),
            evidence_coverage=round(min(1.0, grounded_claims / max(1, total_claims)), 3),
            fallback_rate=0.0 if explanation.validation_status == "VALIDATED" else 1.0,
            validation_failure_count=0 if explanation.validation_status == "VALIDATED" else 1,
        )
