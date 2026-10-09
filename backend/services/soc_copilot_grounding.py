"""
Section 30: SOC Copilot Grounding, Claim Validation & Citation Engine.
Enforces:
1. Grounding against structured context snapshot.
2. Fact vs Inference vs Hypothesis vs Recommendation semantic separation.
3. Anti-hallucination validation: unsupported claims are flagged and caveats attached.
4. Structured citations linking claims to verified Evidence, Findings, RiskAssessments, etc.
5. Strict prevention of invented risk scores or fake confidence levels.
"""

from __future__ import annotations
import re
import json
import logging
from typing import Dict, Any, List, Optional, Tuple

from backend.schemas.soc_copilot import (
    CopilotCitation,
    CopilotClaim,
    SemanticTypeEnum,
    ValidationStatusEnum,
    CitationSourceTypeEnum
)

logger = logging.getLogger("soc_copilot_grounding")

# Canonical regex patterns for evidence and entity references
EVIDENCE_REGEX = re.compile(r'\b(EV(?:ID)?[-_]?[A-Za-z0-9]+|E[-_]\d{3,5})\b', re.IGNORECASE)
FINDING_REGEX = re.compile(r'\b(F[-_]\d+|FINDING[-_][A-Za-z0-9]+)\b', re.IGNORECASE)
RISK_REGEX = re.compile(r'\b(RA[-_][A-Za-z0-9]+)\b', re.IGNORECASE)
EXPLANATION_REGEX = re.compile(r'\b(EX[-_][A-Za-z0-9]+)\b', re.IGNORECASE)
REC_REGEX = re.compile(r'\b(REC[-_][A-Za-z0-9]+)\b', re.IGNORECASE)
PLAYBOOK_REGEX = re.compile(r'\b(PB[-_][A-Za-z0-9]+|phishing-containment|account-takeover-response|endpoint-containment)\b', re.IGNORECASE)
MITRE_REGEX = re.compile(r'\b(T\d{4}(?:\.\d{3})?)\b')


class SocCopilotGroundingEngine:
    """
    Validates LLM-generated claims, extracts structured citations,
    and flags unsupported assertions before responses are returned to analysts.
    """

    @classmethod
    def extract_and_verify_citations(
        cls,
        text: str,
        context_data: Dict[str, Any]
    ) -> List[CopilotCitation]:
        """
        Extracts entity references mentioned in generated text and confirms
        they genuinely exist in the retrieved context snapshot.
        """
        citations: List[CopilotCitation] = []
        seen_refs = set()

        # 1. Evidence citations
        for match in EVIDENCE_REGEX.finditer(text):
            ref = match.group(1).upper()
            if ref in seen_refs:
                continue
            seen_refs.add(ref)

            # Check if ref exists in context
            ev_list = context_data.get("evidence", [])
            matched_ev = next((e for e in ev_list if ref in str(e.get("evidence_id", "")).upper() or ref in str(e.get("id", "")).upper()), None)

            citations.append(CopilotCitation(
                citation_id=f"cit-ev-{len(citations)+1}",
                source_type=CitationSourceTypeEnum.EVIDENCE,
                source_id=matched_ev.get("evidence_id", ref) if matched_ev else ref,
                claim_span=match.group(0),
                title=matched_ev.get("filename", f"Evidence {ref}") if matched_ev else f"Evidence Reference {ref}",
                metadata={"verified_in_context": matched_ev is not None}
            ))

        # 2. Finding citations
        for match in FINDING_REGEX.finditer(text):
            ref = match.group(1).upper()
            if ref in seen_refs:
                continue
            seen_refs.add(ref)

            f_list = context_data.get("findings", [])
            matched_f = next((f for f in f_list if ref in str(f.get("finding_id", "")).upper() or ref in str(f.get("id", "")).upper()), None)

            citations.append(CopilotCitation(
                citation_id=f"cit-f-{len(citations)+1}",
                source_type=CitationSourceTypeEnum.FINDING,
                source_id=matched_f.get("finding_id", ref) if matched_f else ref,
                claim_span=match.group(0),
                title=matched_f.get("title", f"Finding {ref}") if matched_f else f"Finding Reference {ref}",
                metadata={"verified_in_context": matched_f is not None}
            ))

        # 3. MITRE Technique citations
        for match in MITRE_REGEX.finditer(text):
            t_id = match.group(1)
            if t_id in seen_refs:
                continue
            seen_refs.add(t_id)

            mitre_list = context_data.get("mitre_mappings", [])
            matched_m = next((m for m in mitre_list if m.get("technique_id") == t_id), None)

            citations.append(CopilotCitation(
                citation_id=f"cit-mitre-{len(citations)+1}",
                source_type=CitationSourceTypeEnum.MITRE_MAPPING,
                source_id=t_id,
                claim_span=t_id,
                title=matched_m.get("technique_name", f"MITRE Technique {t_id}") if matched_m else f"ATT&CK {t_id}",
                metadata={
                    "verified_in_context": matched_m is not None,
                    "mapping_status": matched_m.get("status", "UNMAPPED") if matched_m else "UNMAPPED"
                }
            ))

        # 4. Risk Assessment citation if mentioned
        ra = context_data.get("risk_assessment")
        if ra and ("risk score" in text.lower() or "risk assessment" in text.lower() or "critical" in text.lower()):
            if "RA-CURRENT" not in seen_refs:
                seen_refs.add("RA-CURRENT")
                citations.append(CopilotCitation(
                    citation_id=f"cit-ra-{len(citations)+1}",
                    source_type=CitationSourceTypeEnum.RISK_ASSESSMENT,
                    source_id=ra.get("id", "RA-01"),
                    claim_span=f"Risk Score {ra.get('risk_score', 'N/A')}",
                    title=f"Authoritative Risk Assessment (Level: {ra.get('risk_level', 'UNKNOWN')})",
                    metadata={"verified_in_context": True, "score": ra.get("risk_score")}
                ))

        return citations

    @classmethod
    def validate_claims_and_semantics(
        cls,
        text: str,
        context_data: Dict[str, Any]
    ) -> List[CopilotClaim]:
        """
        Deconstructs substantive assertions, classifies their semantic type,
        and verifies grounding against authoritative evidence.
        """
        claims: List[CopilotClaim] = []
        sentences = [s.strip() for s in re.split(r'[.\n]+', text) if len(s.strip()) > 15]

        for s in sentences:
            s_lower = s.lower()

            # Classify semantic type
            if any(term in s_lower for term in ["recommend", "should consider", "suggest", "advisable"]):
                sem_type = SemanticTypeEnum.RECOMMENDATION
            elif any(term in s_lower for term in ["block", "revoke", "isolate", "quarantine", "reset password"]):
                sem_type = SemanticTypeEnum.ACTION_OPTION
            elif any(term in s_lower for term in ["may be", "could be", "hypothesis", "possibly", "suspected to be part of"]):
                sem_type = SemanticTypeEnum.HYPOTHESIS
            elif any(term in s_lower for term in ["indicates", "suggests", "points to", "correlates", "increases likelihood"]):
                sem_type = SemanticTypeEnum.DERIVED_INFERENCE
            else:
                sem_type = SemanticTypeEnum.OBSERVED_FACT

            # Verification logic
            val_status = ValidationStatusEnum.SUPPORTED
            note = None
            evidence_ids: List[str] = []

            # Check SPF assertion
            if "spf fail" in s_lower or "spf failed" in s_lower:
                auth = context_data.get("auth_results", {})
                spf_status = str(auth.get("spf", {}).get("status", "")).upper()
                if spf_status == "FAIL":
                    val_status = ValidationStatusEnum.SUPPORTED
                    evidence_ids.append("EV-SPF-FAIL")
                else:
                    val_status = ValidationStatusEnum.UNSUPPORTED
                    note = f"SPF claim not supported by context auth telemetry (Found: {spf_status})."

            # Check Risk Score assertion
            if "risk score" in s_lower:
                ra = context_data.get("risk_assessment", {})
                true_score = ra.get("risk_score")
                if true_score is not None:
                    # Ensure LLM didn't invent competing score
                    score_matches = re.findall(r'\b\d{1,3}(?:\.\d+)?\b', s)
                    if score_matches and not any(abs(float(m) - float(true_score)) < 1.0 for m in score_matches):
                        val_status = ValidationStatusEnum.UNSUPPORTED
                        note = f"Risk score mismatch: claim cites unauthoritative score (Engine score: {true_score})."
                    else:
                        evidence_ids.append(str(ra.get("id", "RA-01")))

            # Check MITRE technique claim
            mitre_match = MITRE_REGEX.search(s)
            if mitre_match:
                t_id = mitre_match.group(1)
                mappings = context_data.get("mitre_mappings", [])
                mapped = next((m for m in mappings if m.get("technique_id") == t_id), None)
                if mapped:
                    if mapped.get("status") == "REJECTED":
                        val_status = ValidationStatusEnum.UNSUPPORTED
                        note = f"ATT&CK Technique {t_id} is marked REJECTED in deterministic mapping."
                    elif mapped.get("status") in ["PLAUSIBLE", "INSUFFICIENT"] and ("confirmed" in s_lower or "proven" in s_lower):
                        val_status = ValidationStatusEnum.PARTIALLY_SUPPORTED
                        note = f"Technique {t_id} is plausible but not confirmed by evidence."
                    evidence_ids.append(t_id)
                else:
                    val_status = ValidationStatusEnum.UNSUPPORTED
                    note = f"Technique {t_id} is unmapped in authoritative context."

            # Check Threat Memory assertion
            if "seen before" in s_lower or "previously observed" in s_lower:
                tm = context_data.get("threat_memory", {})
                count = tm.get("match_count", 0)
                if count > 0:
                    val_status = ValidationStatusEnum.SUPPORTED
                    evidence_ids.append("TM-HISTORICAL")
                else:
                    val_status = ValidationStatusEnum.UNSUPPORTED
                    note = "No historical threat memory match found in context for this entity."

            claims.append(CopilotClaim(
                claim_text=s,
                semantic_type=sem_type,
                validation_status=val_status,
                supporting_evidence_ids=evidence_ids,
                notes=note
            ))

        return claims[:12]

    @classmethod
    def sanitize_unsupported_assertions(
        cls,
        assessment_text: str,
        claims: List[CopilotClaim]
    ) -> Tuple[str, List[str]]:
        """
        Appends explicit uncertainty disclaimers if any critical claims were unsupported.
        """
        uncertainties: List[str] = []
        unsupported = [c for c in claims if c.validation_status == ValidationStatusEnum.UNSUPPORTED]

        if unsupported:
            for un in unsupported:
                if un.notes:
                    uncertainties.append(un.notes)
            disclaimer = (
                "\n\n> **[Forensic Note]**: Certain inferences could not be conclusively validated against "
                "authoritative evidence in CyberGuard and should be treated as unverified hypotheses."
            )
            assessment_text = assessment_text + disclaimer

        return assessment_text, uncertainties
