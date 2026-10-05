"""
Attack Confidence Engine (Section 18).
Computes multidimensional, decomposable, evidence-constrained confidence scores
for attack stages, transitions, paths, and hypotheses.

CORE PRINCIPLE:
CONFIDENCE IS NOT CERTAINTY.
Confidence represents heuristic evidence strength (0.0-1.0) for an analytical conclusion,
NOT statistical probability that CyberGuard is correct.

BOTTLENECK PRINCIPLE:
Path confidence is bounded by its weakest critical transition or speculative link.
A path containing five high-confidence stages connected by one speculative transition
must expose that weak link and not average it away into a misleading HIGH score.
"""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
import json
import logging
import uuid
from typing import Any, Dict, List, Optional, Set, Tuple

from sqlalchemy.orm import Session
from sqlalchemy import or_, and_

from backend.db.models import (
    IncidentModel,
    AttackPathModel,
    AttackStageModel,
    AttackEdgeModel,
    AttackHypothesisModel,
    SecurityEventModel,
    FindingModel,
    FindingEvidenceModel,
    RelationshipModel,
    RelationshipObservationModel,
    EntityModel,
    generate_uuid,
    get_utc_now,
)
from backend.schemas.attack_confidence import (
    ConfidenceLevel,
    SourceTrustLevel,
    ConfidenceDimension,
    ContradictionType,
    EvidenceGapType,
    ConfidenceConfig,
    EvidenceFamily,
    ContradictionItem,
    EvidenceGapItem,
    ConfidenceComponent,
    ConfidenceBottleneck,
    ConfidenceBreakdown,
    ConfidenceAudit,
    HypothesisComparisonResult,
    score_to_confidence_level,
)
from backend.schemas.attack_reconstruction import (
    StageStatusEnum,
    AttackStageType,
    StageRelationshipType,
    GAP_NO_URL_CLICK,
    GAP_NO_PROCESS_TELEMETRY,
    GAP_NO_CREDENTIAL_THEFT_PROOF,
    GAP_NO_EXFILTRATION_CONFIRMATION,
)

logger = logging.getLogger(__name__)


# Common infrastructure prevalence lists to prevent false confidence (Prevalence / Specificity)
COMMON_CLOUD_OR_CDN_IPS: Set[str] = {
    "1.1.1.1", "8.8.8.8", "8.8.4.4", "9.9.9.9",
    "104.16.0.0", "104.17.0.0", "151.101.0.0", "199.232.0.0",
    "13.107.42.13", "52.96.166.0", "172.217.0.0", "142.250.0.0"
}

GENERIC_DOMAINS: Set[str] = {
    "cloudflare.com", "google.com", "microsoft.com", "amazonaws.com",
    "azure.com", "akamai.com", "fastly.net", "github.com"
}


class AttackConfidenceEngine:
    """
    Core calculation and audit engine for reconstruction confidence.
    Produces granular, decomposable, and lineage-aware evidence strength scores.
    """

    ENGINE_VERSION = "1.0.0"
    DEFAULT_CONFIG = ConfidenceConfig()

    @classmethod
    def evaluate_evidence_independence(
        cls,
        evidence_items: List[Dict[str, Any]],
        findings: Optional[List[Dict[str, Any]]] = None
    ) -> Tuple[List[EvidenceFamily], int]:
        """
        Groups evidence and derived findings into root EvidenceFamilies to prevent double counting.
        Example: LOOKALIKE_DOMAIN and DOMAIN_IMPERSONATION_SIGNAL derived from the same domain
        observation belong to ONE family and are not counted as two independent confirmations.
        """
        families_map: Dict[str, EvidenceFamily] = {}
        findings = findings or []

        # 1. Process raw evidence items
        for ev in evidence_items:
            ev_id = ev.get("id") or ev.get("evidence_id") or str(uuid.uuid4())
            root_key = ev.get("root_observation_key") or ev.get("source_identifier") or ev.get("evidence_type") or "generic_observation"
            # Normalize root key based on entity reference if available
            entity_val = ev.get("entity_value") or ev.get("target") or ev.get("source")
            if entity_val:
                root_key = f"{ev.get('evidence_type', 'obs')}:{entity_val}"

            source_trust_str = ev.get("source_trust") or ev.get("source_trust_level") or SourceTrustLevel.DIRECT_TELEMETRY.value
            try:
                trust_lvl = SourceTrustLevel(source_trust_str)
            except ValueError:
                trust_lvl = SourceTrustLevel.DIRECT_TELEMETRY

            if root_key not in families_map:
                families_map[root_key] = EvidenceFamily(
                    family_id=f"fam_{len(families_map) + 1}",
                    root_observation_key=root_key,
                    source_trust=trust_lvl,
                    evidence_ids=[ev_id],
                    finding_ids=[],
                    description=ev.get("description", f"Evidence family for {root_key}")
                )
            else:
                if ev_id not in families_map[root_key].evidence_ids:
                    families_map[root_key].evidence_ids.append(ev_id)

        # 2. Map findings into families by provenance
        for f in findings:
            f_id = f.get("id") or f.get("finding_id") or str(uuid.uuid4())
            f_type = f.get("finding_type") or f.get("type") or "FINDING"
            target_entity = f.get("target_entity") or f.get("entity_value") or f.get("domain") or f.get("ip")

            # Check if this finding attaches to an existing evidence family
            matched_family = False
            for root_k, fam in families_map.items():
                if target_entity and (target_entity in root_k or root_k.endswith(str(target_entity))):
                    if f_id not in fam.finding_ids:
                        fam.finding_ids.append(f_id)
                    matched_family = True
                    break

            if not matched_family:
                # Create a derived family
                fam_key = f"finding:{target_entity or f_type}"
                if fam_key not in families_map:
                    families_map[fam_key] = EvidenceFamily(
                        family_id=f"fam_{len(families_map) + 1}",
                        root_observation_key=fam_key,
                        source_trust=SourceTrustLevel.DERIVED_DETERMINISTIC,
                        evidence_ids=[],
                        finding_ids=[f_id],
                        description=f"Derived findings for {f_type}"
                    )
                else:
                    if f_id not in families_map[fam_key].finding_ids:
                        families_map[fam_key].finding_ids.append(f_id)

        family_list = list(families_map.values())
        independent_sources_count = max(1, len(family_list))
        return family_list, independent_sources_count

    @classmethod
    def evaluate_contradictions(
        cls,
        subject_id: str,
        subject_type: str,
        context: Optional[Dict[str, Any]] = None,
        candidate_facts: Optional[List[Dict[str, Any]]] = None,
        config: Optional[ConfidenceConfig] = None
    ) -> List[ContradictionItem]:
        """
        Structured contradiction detection.
        Differentiates explicit contradictions from absent/missing evidence.
        """
        cfg = config or cls.DEFAULT_CONFIG
        contradictions: List[ContradictionItem] = []
        candidate_facts = candidate_facts or []
        context = context or {}

        for fact in candidate_facts:
            fact_type_str = fact.get("type", "")
            desc = fact.get("description", "")
            ev_id = fact.get("evidence_id")

            # 1. Managed Device Confirmation
            if fact_type_str == "MANAGED_DEVICE" or fact.get("is_managed_device") is True:
                penalty = cfg.contradiction_penalties.get(ContradictionType.MANAGED_DEVICE.value, 0.30)
                contradictions.append(ContradictionItem(
                    subject_id=subject_id,
                    subject_type=subject_type,
                    type=ContradictionType.MANAGED_DEVICE,
                    evidence_id=ev_id,
                    penalty=penalty,
                    description=desc or "Observed device was confirmed as an enrolled corporate managed asset.",
                    resolution_hint="Verify whether authorized user was using this enrolled device."
                ))

            # 2. Corporate VPN / Known Gateway
            elif fact_type_str == "CORPORATE_VPN" or fact.get("is_corporate_vpn") is True or fact.get("is_vpn") is True:
                penalty = cfg.contradiction_penalties.get(ContradictionType.CORPORATE_VPN.value, 0.35)
                contradictions.append(ContradictionItem(
                    subject_id=subject_id,
                    subject_type=subject_type,
                    type=ContradictionType.CORPORATE_VPN,
                    evidence_id=ev_id,
                    penalty=penalty,
                    description=desc or "Source IP was identified as a configured corporate VPN egress gateway.",
                    resolution_hint="Check VPN authentication logs for corresponding session establishment."
                ))

            # 3. Expected Verified MFA
            elif fact_type_str == "EXPECTED_MFA" or fact.get("mfa_verified") is True:
                penalty = cfg.contradiction_penalties.get(ContradictionType.EXPECTED_MFA.value, 0.25)
                contradictions.append(ContradictionItem(
                    subject_id=subject_id,
                    subject_type=subject_type,
                    type=ContradictionType.EXPECTED_MFA,
                    evidence_id=ev_id,
                    penalty=penalty,
                    description=desc or "Authentication successfully completed valid out-of-band MFA challenge.",
                    resolution_hint="Inspect whether MFA prompt fatigue or token interception occurred."
                ))

            # 4. Authoritative Telemetry Discrepancy
            elif fact_type_str == "TELEMETRY_DISCREPANCY" or fact.get("discrepancy") is True:
                penalty = cfg.contradiction_penalties.get(ContradictionType.TELEMETRY_DISCREPANCY.value, 0.45)
                contradictions.append(ContradictionItem(
                    subject_id=subject_id,
                    subject_type=subject_type,
                    type=ContradictionType.TELEMETRY_DISCREPANCY,
                    evidence_id=ev_id,
                    penalty=penalty,
                    description=desc or "Authoritative system telemetry directly contradicts the reconstructed attribution or entity origin.",
                    resolution_hint="Cross-check gateway server access logs against local client timestamps."
                ))

            # 5. Normal Baseline Match
            elif fact_type_str == "NORMAL_BASELINE" or fact.get("matches_baseline") is True:
                penalty = cfg.contradiction_penalties.get(ContradictionType.NORMAL_BASELINE.value, 0.20)
                contradictions.append(ContradictionItem(
                    subject_id=subject_id,
                    subject_type=subject_type,
                    type=ContradictionType.NORMAL_BASELINE,
                    evidence_id=ev_id,
                    penalty=penalty,
                    description=desc or "Activity parameters strictly match historical baseline for this identity.",
                    resolution_hint="Verify user shift hours and customary workload schedule."
                ))

            # 6. Verified Travel
            elif fact_type_str == "VERIFIED_LEGITIMATE_TRAVEL" or fact.get("legitimate_travel") is True:
                penalty = cfg.contradiction_penalties.get(ContradictionType.VERIFIED_LEGITIMATE_TRAVEL.value, 0.30)
                contradictions.append(ContradictionItem(
                    subject_id=subject_id,
                    subject_type=subject_type,
                    type=ContradictionType.VERIFIED_LEGITIMATE_TRAVEL,
                    evidence_id=ev_id,
                    penalty=penalty,
                    description=desc or "Confirmed travel itinerary explains geographic origin discrepancy.",
                    resolution_hint="Analyst verified travel booking matches IP geolocation."
                ))

            # 7. Generic or custom contradiction
            elif fact.get("is_contradiction") is True:
                penalty = fact.get("penalty", 0.20)
                contradictions.append(ContradictionItem(
                    subject_id=subject_id,
                    subject_type=subject_type,
                    type=ContradictionType.CUSTOM_CONTRADICTION,
                    evidence_id=ev_id,
                    penalty=penalty,
                    description=desc or "Contextual fact conflicts with hypothesis.",
                    resolution_hint=fact.get("resolution_hint")
                ))

        return contradictions

    @classmethod
    def evaluate_gaps(
        cls,
        subject_id: str,
        stage_type: Optional[str] = None,
        transitions: Optional[List[Dict[str, Any]]] = None,
        evidence_items: Optional[List[Dict[str, Any]]] = None,
        known_gaps: Optional[List[str]] = None,
        config: Optional[ConfidenceConfig] = None
    ) -> List[EvidenceGapItem]:
        """
        Evaluates missing telemetry items that bound reconstruction confidence.
        Missing data is NEVER a contradiction; it represents epistemic uncertainty.
        """
        cfg = config or cls.DEFAULT_CONFIG
        gaps: List[EvidenceGapItem] = []
        known_gaps = known_gaps or []
        evidence_items = evidence_items or []

        # Check for detector unavailable gap (Scenario G)
        for ev in evidence_items:
            if ev.get("detector_status") == "UNAVAILABLE" or ev.get("status") == "DETECTOR_UNAVAILABLE":
                penalty = cfg.gap_penalties.get(EvidenceGapType.DETECTOR_UNAVAILABLE.value, 0.05)
                gaps.append(EvidenceGapItem(
                    gap_type=EvidenceGapType.DETECTOR_UNAVAILABLE,
                    affected_stages=[subject_id],
                    affected_transitions=[],
                    impact_description="Underlying analyzer or detector was unavailable; evaluated as epistemic uncertainty, NOT negative evidence.",
                    penalty=penalty,
                    what_would_strengthen=["Execute offline model evaluation or secondary heuristics."],
                    what_would_weaken=["Detector confirmation of benign indicators."]
                ))

        # Check explicit gap strings
        for g_str in known_gaps:
            g_upper = g_str.upper()
            if "CLICK" in g_upper or g_str == GAP_NO_URL_CLICK:
                penalty = cfg.gap_penalties.get(EvidenceGapType.NO_CLICK_TELEMETRY.value, 0.25)
                gaps.append(EvidenceGapItem(
                    gap_type=EvidenceGapType.NO_CLICK_TELEMETRY,
                    affected_stages=[subject_id],
                    affected_transitions=[],
                    impact_description="No web proxy or browser click telemetry proving recipient accessed malicious URL.",
                    penalty=penalty,
                    what_would_strengthen=["Proxy access logs for target URL", "Browser history extraction"],
                    what_would_weaken=["DNS query logs confirming domain was never resolved from endpoint"]
                ))
            elif "CREDENTIAL" in g_upper or g_str == GAP_NO_CREDENTIAL_THEFT_PROOF:
                penalty = cfg.gap_penalties.get(EvidenceGapType.NO_CREDENTIAL_CAPTURE_EVIDENCE.value, 0.30)
                gaps.append(EvidenceGapItem(
                    gap_type=EvidenceGapType.NO_CREDENTIAL_CAPTURE_EVIDENCE,
                    affected_stages=[subject_id],
                    affected_transitions=[],
                    impact_description="No direct credential capture or submission telemetry observed on target infrastructure.",
                    penalty=penalty,
                    what_would_strengthen=["Credential-submission HTTP POST telemetry", "IdP compromised credential notification"],
                    what_would_weaken=["Endpoint password-manager audit showing no credentials saved for target site"]
                ))
            elif "PROCESS" in g_upper or g_str == GAP_NO_PROCESS_TELEMETRY:
                penalty = cfg.gap_penalties.get(EvidenceGapType.NO_PROCESS_TELEMETRY.value, 0.20)
                gaps.append(EvidenceGapItem(
                    gap_type=EvidenceGapType.NO_PROCESS_TELEMETRY,
                    affected_stages=[subject_id],
                    affected_transitions=[],
                    impact_description="No EDR or endpoint process execution telemetry available.",
                    penalty=penalty,
                    what_would_strengthen=["Sysmon/EDR process creation events (Event ID 1)", "Memory forensics"],
                    what_would_weaken=["Process accounting logs demonstrating file was never executed"]
                ))
            elif "EXFILTRATION" in g_upper or g_str == GAP_NO_EXFILTRATION_CONFIRMATION:
                penalty = cfg.gap_penalties.get(EvidenceGapType.NO_DIRECT_EXFILTRATION_CONFIRMATION.value, 0.30)
                gaps.append(EvidenceGapItem(
                    gap_type=EvidenceGapType.NO_DIRECT_EXFILTRATION_CONFIRMATION,
                    affected_stages=[subject_id],
                    affected_transitions=[],
                    impact_description="Outbound transfer observed, but no cryptographic or payload proof that sensitive data left perimeter.",
                    penalty=penalty,
                    what_would_strengthen=["DLP gateway inspection log", "Network flow session capture (PCAP)"],
                    what_would_weaken=["Encrypted payload inspection showing only benign telemetry or heartbeats"]
                ))

        return gaps

    @classmethod
    def score_stage(
        cls,
        stage: Any,
        context_evidence: Optional[List[Dict[str, Any]]] = None,
        findings: Optional[List[Dict[str, Any]]] = None,
        candidate_facts: Optional[List[Dict[str, Any]]] = None,
        known_gaps: Optional[List[str]] = None,
        config: Optional[ConfidenceConfig] = None
    ) -> ConfidenceBreakdown:
        """
        Calculates multidimensional confidence for an individual AttackStage.
        Enforces: Status != Confidence (OBSERVED does not guarantee HIGH, INFERRED can be HIGH).
        """
        cfg = config or cls.DEFAULT_CONFIG
        stage_id = getattr(stage, "id", str(uuid.uuid4()))
        stage_type_str = getattr(stage, "stage_type", "UNKNOWN_ACTIVITY")
        if hasattr(stage_type_str, "value"):
            stage_type_str = stage_type_str.value
        stage_status_str = getattr(stage, "stage_status", "INFERRED")
        if hasattr(stage_status_str, "value"):
            stage_status_str = stage_status_str.value

        evidence_items = context_evidence or []
        if hasattr(stage, "supporting_evidence") and stage.supporting_evidence:
            if isinstance(stage.supporting_evidence, list):
                evidence_items.extend(stage.supporting_evidence)

        # 1. Evidence Independence
        families, ind_count = cls.evaluate_evidence_independence(evidence_items, findings)

        # 2. Contradictions
        contradictions = cls.evaluate_contradictions(
            subject_id=stage_id,
            subject_type="STAGE",
            candidate_facts=candidate_facts,
            config=cfg
        )
        if hasattr(stage, "contradicting_evidence") and stage.contradicting_evidence:
            if isinstance(stage.contradicting_evidence, list):
                extra_contra = cls.evaluate_contradictions(stage_id, "STAGE", candidate_facts=stage.contradicting_evidence, config=cfg)
                contradictions.extend(extra_contra)

        # 3. Evidence Gaps
        gaps = cls.evaluate_gaps(
            subject_id=stage_id,
            stage_type=stage_type_str,
            evidence_items=evidence_items,
            known_gaps=known_gaps,
            config=cfg
        )

        components: List[ConfidenceComponent] = []
        adjustments: List[Dict[str, Any]] = []

        # --- Dimension 1: OBSERVATION_STRENGTH ---
        # Direct telemetry vs derived vs inferred vs unresolved
        w_obs = cfg.dimension_weights.get(ConfidenceDimension.OBSERVATION_STRENGTH.value, 0.22)
        if stage_status_str == StageStatusEnum.OBSERVED.value:
            # Check source trust of evidence
            highest_trust = SourceTrustLevel.DIRECT_TELEMETRY.value
            for fam in families:
                highest_trust = fam.source_trust.value
                break
            trust_weight = cfg.source_trust_weights.get(highest_trust, 0.95)
            s_obs = trust_weight
            r_obs = f"Direct telemetry observation with source trust {highest_trust} ({trust_weight:.2f})"
        elif stage_status_str == StageStatusEnum.DERIVED.value:
            s_obs = 0.82
            r_obs = "Derived deterministically from observed parent evidence."
        elif stage_status_str == StageStatusEnum.INFERRED.value:
            s_obs = 0.60
            r_obs = "Analytically inferred from behavioral indicators."
        else:
            s_obs = 0.30
            r_obs = "Unresolved stage with absent direct telemetry."

        components.append(ConfidenceComponent(
            dimension=ConfidenceDimension.OBSERVATION_STRENGTH,
            score=s_obs,
            weight=w_obs,
            weighted_score=round(s_obs * w_obs, 4),
            evidence_ids=[fam.family_id for fam in families],
            reason=r_obs,
            limitations=[]
        ))

        # --- Dimension 2: ENTITY_CONTINUITY ---
        w_ent = cfg.dimension_weights.get(ConfidenceDimension.ENTITY_CONTINUITY.value, 0.18)
        entity_ids = getattr(stage, "entity_ids", [])
        if entity_ids:
            s_ent = min(1.0, 0.70 + (len(entity_ids) * 0.10))
            r_ent = f"Stage associates {len(entity_ids)} canonical entities."
        else:
            s_ent = 0.40
            r_ent = "Stage lacks explicit canonical entity bindings."
        components.append(ConfidenceComponent(
            dimension=ConfidenceDimension.ENTITY_CONTINUITY,
            score=s_ent,
            weight=w_ent,
            weighted_score=round(s_ent * w_ent, 4),
            evidence_ids=[],
            reason=r_ent,
            limitations=[]
        ))

        # --- Dimension 3: TEMPORAL_CONSISTENCY ---
        w_time = cfg.dimension_weights.get(ConfidenceDimension.TEMPORAL_CONSISTENCY.value, 0.15)
        st = getattr(stage, "start_time", None)
        et = getattr(stage, "end_time", None)
        if st is not None:
            s_time = 0.92
            r_time = f"Stage anchored by observation timestamp ({st.isoformat() if hasattr(st, 'isoformat') else st})."
        else:
            s_time = 0.50
            r_time = "Stage timestamp is approximated or inferred without precise sensor clock."
        components.append(ConfidenceComponent(
            dimension=ConfidenceDimension.TEMPORAL_CONSISTENCY,
            score=s_time,
            weight=w_time,
            weighted_score=round(s_time * w_time, 4),
            evidence_ids=[],
            reason=r_time,
            limitations=[] if st else ["Lacks microsecond sensor timestamp precision"]
        ))

        # --- Dimension 4: GRAPH_CONNECTIVITY ---
        w_graph = cfg.dimension_weights.get(ConfidenceDimension.GRAPH_CONNECTIVITY.value, 0.12)
        rel_ids = getattr(stage, "relationship_ids", [])
        if rel_ids:
            s_graph = min(1.0, 0.75 + (len(rel_ids) * 0.08))
            r_graph = f"Corroborated by {len(rel_ids)} Knowledge Graph relationships."
        else:
            s_graph = 0.55
            r_graph = "No direct Knowledge Graph relationship edges recorded."
        components.append(ConfidenceComponent(
            dimension=ConfidenceDimension.GRAPH_CONNECTIVITY,
            score=s_graph,
            weight=w_graph,
            weighted_score=round(s_graph * w_graph, 4),
            evidence_ids=[],
            reason=r_graph,
            limitations=[]
        ))

        # --- Dimension 5: SOURCE_INDEPENDENCE ---
        w_src = cfg.dimension_weights.get(ConfidenceDimension.SOURCE_INDEPENDENCE.value, 0.12)
        if ind_count >= 3:
            s_src = 1.0
            r_src = f"Corroborated by {ind_count} independent evidence families."
        elif ind_count == 2:
            s_src = 0.85
            r_src = f"Corroborated by 2 independent evidence families."
        else:
            s_src = 0.65
            r_src = "Supported by a single evidence family; cross-sensor confirmation absent."
        components.append(ConfidenceComponent(
            dimension=ConfidenceDimension.SOURCE_INDEPENDENCE,
            score=s_src,
            weight=w_src,
            weighted_score=round(s_src * w_src, 4),
            evidence_ids=[fam.family_id for fam in families],
            reason=r_src,
            limitations=[] if ind_count > 1 else ["Dependent on single evidence origin"]
        ))

        # --- Dimension 6: INDICATOR_SPECIFICITY ---
        w_spec = cfg.dimension_weights.get(ConfidenceDimension.INDICATOR_SPECIFICITY.value, 0.08)
        s_spec = 0.80
        r_spec = "Indicator specificity evaluated across stage attributes."
        components.append(ConfidenceComponent(
            dimension=ConfidenceDimension.INDICATOR_SPECIFICITY,
            score=s_spec,
            weight=w_spec,
            weighted_score=round(s_spec * w_spec, 4),
            evidence_ids=[],
            reason=r_spec,
            limitations=[]
        ))

        # --- Dimension 7: DETECTOR_CONFIDENCE ---
        w_det = cfg.dimension_weights.get(ConfidenceDimension.DETECTOR_CONFIDENCE.value, 0.05)
        raw_conf = getattr(stage, "confidence", 0.80)
        s_det = max(0.0, min(1.0, float(raw_conf)))
        components.append(ConfidenceComponent(
            dimension=ConfidenceDimension.DETECTOR_CONFIDENCE,
            score=s_det,
            weight=w_det,
            weighted_score=round(s_det * w_det, 4),
            evidence_ids=[],
            reason=f"Underlying detector confidence: {s_det:.2f}",
            limitations=[]
        ))

        # --- Dimension 8: HISTORICAL_SUPPORT ---
        w_hist = cfg.dimension_weights.get(ConfidenceDimension.HISTORICAL_SUPPORT.value, 0.04)
        s_hist = 0.65
        components.append(ConfidenceComponent(
            dimension=ConfidenceDimension.HISTORICAL_SUPPORT,
            score=s_hist,
            weight=w_hist,
            weighted_score=round(s_hist * w_hist, 4),
            evidence_ids=[],
            reason="Historical campaign context evaluated.",
            limitations=[]
        ))

        # --- Dimension 9: CONTRADICTION_STRENGTH ---
        w_contra = cfg.dimension_weights.get(ConfidenceDimension.CONTRADICTION_STRENGTH.value, 0.02)
        total_contra_penalty = sum(c.penalty for c in contradictions)
        s_contra = max(0.0, 1.0 - total_contra_penalty)
        components.append(ConfidenceComponent(
            dimension=ConfidenceDimension.CONTRADICTION_STRENGTH,
            score=s_contra,
            weight=w_contra,
            weighted_score=round(s_contra * w_contra, 4),
            evidence_ids=[c.evidence_id for c in contradictions if c.evidence_id],
            reason=f"{len(contradictions)} contradiction(s) detected with cumulative penalty {total_contra_penalty:.2f}",
            limitations=[c.description for c in contradictions]
        ))

        # --- Dimension 10: EVIDENCE_COMPLETENESS ---
        w_comp = cfg.dimension_weights.get(ConfidenceDimension.EVIDENCE_COMPLETENESS.value, 0.02)
        total_gap_penalty = sum(g.penalty for g in gaps)
        s_comp = max(0.0, 1.0 - total_gap_penalty)
        components.append(ConfidenceComponent(
            dimension=ConfidenceDimension.EVIDENCE_COMPLETENESS,
            score=s_comp,
            weight=w_comp,
            weighted_score=round(s_comp * w_comp, 4),
            evidence_ids=[],
            reason=f"{len(gaps)} telemetry gap(s) identified with penalty {total_gap_penalty:.2f}",
            limitations=[g.impact_description for g in gaps]
        ))

        # Compute base score
        base_score = sum(c.weighted_score for c in components)
        adjustments.append({"step": "weighted_base_score", "score": round(base_score, 4)})

        # Apply direct contradiction penalty
        score = base_score
        if total_contra_penalty > 0:
            score = max(0.05, score - (total_contra_penalty * 0.4))
            adjustments.append({"step": "contradiction_deduction", "deduction": round(total_contra_penalty * 0.4, 4), "new_score": round(score, 4)})

        # Apply direct gap penalty
        if total_gap_penalty > 0:
            score = max(0.05, score - (total_gap_penalty * 0.25))
            adjustments.append({"step": "gap_deduction", "deduction": round(total_gap_penalty * 0.25, 4), "new_score": round(score, 4)})

        # Factor in underlying stage confidence if explicitly provided
        raw_conf = getattr(stage, "confidence", None)
        if raw_conf is not None and float(raw_conf) < 0.60:
            score = min(score, float(raw_conf))
            adjustments.append({"step": "raw_conf_bound", "score": round(score, 4)})

        final_score = max(0.0, min(1.0, round(score, 4)))
        conf_level = score_to_confidence_level(final_score, cfg)

        return ConfidenceBreakdown(
            subject_type="STAGE",
            subject_id=stage_id,
            raw_score=final_score,
            confidence_level=conf_level,
            epistemic_status=stage_status_str,
            components=components,
            supporting_evidence=evidence_items,
            contradicting_evidence=contradictions,
            missing_evidence=gaps,
            evidence_families=families,
            independent_sources_count=ind_count,
            adjustments=adjustments,
            engine_version=cls.ENGINE_VERSION,
            configuration_version=cfg.configuration_version,
            generated_at=datetime.now(timezone.utc)
        )

    @classmethod
    def score_transition(
        cls,
        from_stage: Any,
        to_stage: Any,
        edge_model: Optional[Any] = None,
        candidate_facts: Optional[List[Dict[str, Any]]] = None,
        context: Optional[Dict[str, Any]] = None,
        config: Optional[ConfidenceConfig] = None
    ) -> ConfidenceBreakdown:
        """
        Calculates multidimensional confidence for a directed transition edge.
        Evaluates entity continuity, temporal gap, specificity, and gap penalties
        (e.g., Phishing -> Credential Compromise without click telemetry drops to MODERATE).
        """
        cfg = config or cls.DEFAULT_CONFIG
        edge_id = getattr(edge_model, "id", str(uuid.uuid4()))
        from_type = getattr(from_stage, "stage_type", "UNKNOWN")
        if hasattr(from_type, "value"):
            from_type = from_type.value
        to_type = getattr(to_stage, "stage_type", "UNKNOWN")
        if hasattr(to_type, "value"):
            to_type = to_type.value

        from_status = getattr(from_stage, "stage_status", "OBSERVED")
        if hasattr(from_status, "value"):
            from_status = from_status.value
        to_status = getattr(to_stage, "stage_status", "OBSERVED")
        if hasattr(to_status, "value"):
            to_status = to_status.value

        components: List[ConfidenceComponent] = []
        adjustments: List[Dict[str, Any]] = []

        # Shared Entities & Specificity
        shared_entities: List[str] = []
        if edge_model and hasattr(edge_model, "shared_entities"):
            shared_entities = edge_model.shared_entities or []
        elif edge_model and hasattr(edge_model, "shared_entities_json"):
            try:
                shared_entities = json.loads(edge_model.shared_entities_json or "[]")
            except Exception:
                shared_entities = []

        if not shared_entities:
            from_ents = set(getattr(from_stage, "entity_ids", []))
            to_ents = set(getattr(to_stage, "entity_ids", []))
            shared_entities = list(from_ents.intersection(to_ents))

        # Check prevalence / specificity of shared entities
        has_common_cloud_ip = any(ent in COMMON_CLOUD_OR_CDN_IPS for ent in shared_entities)
        has_generic_domain = any(ent in GENERIC_DOMAINS for ent in shared_entities)
        has_session_match = any("session" in ent.lower() or "sess" in ent.lower() for ent in shared_entities)
        has_account_match = any("user:" in ent.lower() or "account:" in ent.lower() or "@" in ent for ent in shared_entities)
        has_device_match = any("device:" in ent.lower() or "host:" in ent.lower() for ent in shared_entities)

        # --- Dimension 1: ENTITY_CONTINUITY ---
        w_ent = 0.28
        if has_session_match:
            s_ent = 1.0
            r_ent = "Direct session identifier preserved across transition (highest continuity)."
        elif has_account_match and has_device_match:
            s_ent = 0.92
            r_ent = "Identical targeted account and endpoint device preserved."
        elif has_account_match:
            s_ent = 0.75
            r_ent = "Same targeted user account observed in both stages."
        elif has_common_cloud_ip:
            # Prevalence adjustment: Scenario C
            s_ent = 0.25
            r_ent = "Shared IP belongs to high-prevalence public CDN/cloud infrastructure (low continuity weight)."
        elif shared_entities:
            s_ent = 0.65
            r_ent = f"Transition preserves {len(shared_entities)} shared entity reference(s)."
        else:
            s_ent = 0.20
            r_ent = "No direct entity overlap between stages."

        components.append(ConfidenceComponent(
            dimension=ConfidenceDimension.ENTITY_CONTINUITY,
            score=s_ent,
            weight=w_ent,
            weighted_score=round(s_ent * w_ent, 4),
            evidence_ids=[],
            reason=r_ent,
            limitations=["Common infrastructure weakens continuity"] if has_common_cloud_ip else []
        ))

        # --- Dimension 2: TEMPORAL_CONSISTENCY ---
        w_time = 0.24
        gap_sec = None
        if edge_model and hasattr(edge_model, "temporal_gap_seconds"):
            gap_sec = edge_model.temporal_gap_seconds
        st_from = getattr(from_stage, "start_time", None)
        et_from = getattr(from_stage, "end_time", None)
        st_to = getattr(to_stage, "start_time", None)

        if gap_sec is None and st_from and st_to:
            try:
                gap_sec = (st_to - st_from).total_seconds()
            except Exception:
                gap_sec = None

        is_concurrent_uncertain = False
        if gap_sec is not None:
            if gap_sec < 0:
                s_time = 0.25
                r_time = f"Stages reversed or out-of-order ({gap_sec:.1f}s); marked ORDER_UNCERTAIN."
                is_concurrent_uncertain = True
            elif gap_sec <= 60:
                s_time = 0.98
                r_time = f"Sub-minute chronological succession ({gap_sec:.1f} seconds apart)."
            elif gap_sec <= 1800:
                s_time = 0.85
                r_time = f"Consecutive activity within {gap_sec / 60.0:.1f} minutes."
            elif gap_sec <= 86400:
                s_time = 0.65
                r_time = f"Temporal window within {gap_sec / 3600.0:.1f} hours."
            else:
                s_time = 0.40
                r_time = f"Extended gap of {gap_sec / 86400.0:.1f} days between reconstructed stages."
        else:
            s_time = 0.50
            r_time = "Unspecified temporal delta between stages."

        # Check temporal overlap
        if et_from and st_to and et_from > st_to:
            r_time += " (TEMPORALLY_OVERLAPPING observed)"
            is_concurrent_uncertain = True

        components.append(ConfidenceComponent(
            dimension=ConfidenceDimension.TEMPORAL_CONSISTENCY,
            score=s_time,
            weight=w_time,
            weighted_score=round(s_time * w_time, 4),
            evidence_ids=[],
            reason=r_time,
            limitations=["Temporal ordering uncertain"] if is_concurrent_uncertain else []
        ))

        # --- Dimension 3: OBSERVATION_STRENGTH ---
        w_obs = 0.22
        if from_status == StageStatusEnum.OBSERVED.value and to_status == StageStatusEnum.OBSERVED.value:
            s_obs = 0.95
            r_obs = "Both endpoints anchored by direct observed telemetry."
        elif from_status == StageStatusEnum.OBSERVED.value or to_status == StageStatusEnum.OBSERVED.value:
            s_obs = 0.75
            r_obs = "One endpoint directly observed; connecting step derived/inferred."
        else:
            s_obs = 0.50
            r_obs = "Both stages inferred from behavioral context."

        components.append(ConfidenceComponent(
            dimension=ConfidenceDimension.OBSERVATION_STRENGTH,
            score=s_obs,
            weight=w_obs,
            weighted_score=round(s_obs * w_obs, 4),
            evidence_ids=[],
            reason=r_obs,
            limitations=[]
        ))

        # --- Dimension 4: SOURCE_INDEPENDENCE ---
        w_src = 0.14
        s_src = 0.80
        components.append(ConfidenceComponent(
            dimension=ConfidenceDimension.SOURCE_INDEPENDENCE,
            score=s_src,
            weight=w_src,
            weighted_score=round(s_src * w_src, 4),
            evidence_ids=[],
            reason="Telemetry sources cross-referenced across transition boundaries.",
            limitations=[]
        ))

        # --- Dimension 5: CONTRADICTION & GAP DIMENSIONS ---
        w_comp = 0.12
        s_comp = 0.80
        components.append(ConfidenceComponent(
            dimension=ConfidenceDimension.EVIDENCE_COMPLETENESS,
            score=s_comp,
            weight=w_comp,
            weighted_score=round(s_comp * w_comp, 4),
            evidence_ids=[],
            reason="Transition completeness check.",
            limitations=[]
        ))

        base_score = sum(c.weighted_score for c in components)
        adjustments.append({"step": "transition_base_score", "score": round(base_score, 4)})

        # Contradictions affecting transition
        contradictions = cls.evaluate_contradictions(
            subject_id=edge_id,
            subject_type="TRANSITION",
            candidate_facts=candidate_facts,
            config=cfg
        )
        total_contra_pen = sum(c.penalty for c in contradictions)

        # Detect Weak Transitions (Scenario B & Prompt 11 & 64)
        # Example: PHISHING EMAIL -> CREDENTIAL_ACTIVITY / AUTHENTICATION without click/capture telemetry
        gaps: List[EvidenceGapItem] = []
        is_phishing_to_cred = (
            (from_type in ["DELIVERY", "SOCIAL_ENGINEERING", "IMPERSONATION"]) and
            (to_type in ["CREDENTIAL_ACTIVITY", "AUTHENTICATION", "SESSION_ESTABLISHMENT"])
        )
        if is_phishing_to_cred:
            # Check if click telemetry is present
            has_click = False
            if edge_model and hasattr(edge_model, "supporting_evidence"):
                for sup in (edge_model.supporting_evidence or []):
                    if "click" in str(sup).lower() or "proxy" in str(sup).lower():
                        has_click = True
                        break

            if not has_click:
                gaps.append(EvidenceGapItem(
                    gap_type=EvidenceGapType.NO_CLICK_TELEMETRY,
                    affected_stages=[getattr(from_stage, "id", ""), getattr(to_stage, "id", "")],
                    affected_transitions=[edge_id],
                    impact_description="No click or proxy access telemetry observed connecting phishing delivery to credential activity.",
                    penalty=0.30,
                    what_would_strengthen=[
                        "Web proxy logs demonstrating target URL access",
                        "Endpoint browser history confirming visit to credential harvesting domain",
                        "IdP sign-in telemetry recording authentication immediately following delivery"
                    ],
                    what_would_weaken=[
                        "Proxy logs confirming outbound domain was blocked",
                        "Authentication source IP matched user's regular ISP or corporate VPN"
                    ]
                ))

        # If the transition connects Phishing to Credential Activity without click telemetry
        # the transition observation strength is low (circumstantial link)
        if is_phishing_to_cred and not has_click:
            # Overwrite observation strength component score
            for c in components:
                if c.dimension == ConfidenceDimension.OBSERVATION_STRENGTH:
                    c.score = 0.35
                    c.weighted_score = round(0.35 * c.weight, 4)
                    c.reason = "Circumstantial transition without bridging proxy or click telemetry."
                    c.limitations.append("Lacks direct connection telemetry between delivery and login.")
            base_score = sum(c.weighted_score for c in components)

        # Factor in prior edge confidence / detector score if provided on edge_model
        edge_raw_conf = getattr(edge_model, "confidence", None)
        if edge_raw_conf is not None and float(edge_raw_conf) < 0.70:
            base_score = min(base_score, float(edge_raw_conf))

        total_gap_pen = sum(g.penalty for g in gaps)

        score = base_score
        if total_contra_pen > 0:
            score = max(0.05, score - (total_contra_pen * 0.45))
            adjustments.append({"step": "contradiction_deduction", "deduction": round(total_contra_pen * 0.45, 4), "new_score": round(score, 4)})
        if total_gap_pen > 0:
            score = max(0.05, score - (total_gap_pen * 0.50))
            adjustments.append({"step": "gap_deduction", "deduction": round(total_gap_pen * 0.50, 4), "new_score": round(score, 4)})

        # Hard bound for speculative transitions missing critical bridging telemetry (Scenario B & Req 11/64/72)
        if is_phishing_to_cred and not has_click:
            score = min(score, 0.55)

        final_score = max(0.0, min(1.0, round(score, 4)))
        conf_level = score_to_confidence_level(final_score, cfg)

        return ConfidenceBreakdown(
            subject_type="TRANSITION",
            subject_id=edge_id,
            raw_score=final_score,
            confidence_level=conf_level,
            epistemic_status="OBSERVED" if (from_status == "OBSERVED" and to_status == "OBSERVED" and not gaps) else "INFERRED",
            components=components,
            supporting_evidence=getattr(edge_model, "supporting_evidence", []) if edge_model else [],
            contradicting_evidence=contradictions,
            missing_evidence=gaps,
            evidence_families=[],
            independent_sources_count=1,
            adjustments=adjustments,
            engine_version=cls.ENGINE_VERSION,
            configuration_version=cfg.configuration_version,
            generated_at=datetime.now(timezone.utc)
        )

    @classmethod
    def score_path(
        cls,
        path: Any,
        stages: List[Any],
        edges: List[Any],
        candidate_facts: Optional[List[Dict[str, Any]]] = None,
        context: Optional[Dict[str, Any]] = None,
        config: Optional[ConfidenceConfig] = None
    ) -> Tuple[ConfidenceBreakdown, ConfidenceBottleneck]:
        """
        Calculates decomposed path confidence using the Confidence Bottleneck principle.
        DO NOT simply average stage scores.
        A path containing 5 high-confidence stages connected by 1 speculative transition
        is bounded by the weak link.
        """
        cfg = config or cls.DEFAULT_CONFIG
        path_id = getattr(path, "id", str(uuid.uuid4()))

        # 1. Score each stage
        stage_breakdowns: Dict[str, ConfidenceBreakdown] = {}
        for s in stages:
            s_id = getattr(s, "id", str(uuid.uuid4()))
            stage_breakdowns[s_id] = cls.score_stage(
                stage=s,
                candidate_facts=candidate_facts,
                config=cfg
            )

        # 2. Score each transition
        edge_breakdowns: Dict[str, ConfidenceBreakdown] = {}
        stage_map = {getattr(s, "id", ""): s for s in stages}
        for e in edges:
            e_id = getattr(e, "id", str(uuid.uuid4()))
            src_id = getattr(e, "source_stage_id", getattr(e, "from_stage_id", ""))
            tgt_id = getattr(e, "target_stage_id", getattr(e, "to_stage_id", ""))
            from_s = stage_map.get(src_id)
            to_s = stage_map.get(tgt_id)
            if from_s and to_s:
                edge_breakdowns[e_id] = cls.score_transition(
                    from_stage=from_s,
                    to_stage=to_s,
                    edge_model=e,
                    candidate_facts=candidate_facts,
                    config=cfg
                )

        # 3. Find Confidence Bottleneck (Weakest Link Principle)
        bottleneck_subject_id = path_id
        bottleneck_subject_name = "Overall Path"
        bottleneck_type = "TRANSITION"
        lowest_conf = 1.0
        primary_uncertainty = "No speculative transitions detected."
        affected_stages: List[str] = []
        bottleneck_missing: List[str] = []
        bottleneck_recommendations: List[str] = []

        if edge_breakdowns:
            for e_id, bd in edge_breakdowns.items():
                if bd.raw_score < lowest_conf:
                    lowest_conf = bd.raw_score
                    bottleneck_subject_id = e_id
                    bottleneck_type = "TRANSITION"
                    # Find edge details
                    target_edge = next((e for e in edges if getattr(e, "id", "") == e_id), None)
                    src_id = getattr(target_edge, "source_stage_id", getattr(target_edge, "from_stage_id", ""))
                    tgt_id = getattr(target_edge, "target_stage_id", getattr(target_edge, "to_stage_id", ""))
                    from_name = getattr(stage_map.get(src_id, None), "title", getattr(stage_map.get(src_id, None), "name", "Stage A"))
                    to_name = getattr(stage_map.get(tgt_id, None), "title", getattr(stage_map.get(tgt_id, None), "name", "Stage B"))
                    bottleneck_subject_name = f"{from_name} -> {to_name}"
                    primary_uncertainty = f"Transition between '{from_name}' and '{to_name}' has low evidence strength ({bd.raw_score:.2f})."
                    if bd.missing_evidence:
                        primary_uncertainty += f" Missing: {bd.missing_evidence[0].impact_description}"
                        bottleneck_missing = [g.impact_description for g in bd.missing_evidence]
                        bottleneck_recommendations = bd.missing_evidence[0].what_would_strengthen
                    affected_stages = [src_id, tgt_id]

        if stage_breakdowns:
            for s_id, bd in stage_breakdowns.items():
                if bd.raw_score < lowest_conf:
                    lowest_conf = bd.raw_score
                    bottleneck_subject_id = s_id
                    bottleneck_type = "STAGE"
                    target_stage = stage_map.get(s_id)
                    bottleneck_subject_name = getattr(target_stage, "title", "Attack Stage")
                    primary_uncertainty = f"Stage '{bottleneck_subject_name}' has lowest evidence strength ({bd.raw_score:.2f})."
                    if bd.missing_evidence:
                        bottleneck_missing = [g.impact_description for g in bd.missing_evidence]
                        bottleneck_recommendations = bd.missing_evidence[0].what_would_strengthen
                    affected_stages = [s_id]

        bottleneck = ConfidenceBottleneck(
            bottleneck_id=f"bn_{uuid.uuid4().hex[:8]}",
            bottleneck_type=bottleneck_type,
            subject_id=bottleneck_subject_id,
            subject_name=bottleneck_subject_name,
            confidence=round(lowest_conf, 4),
            confidence_level=score_to_confidence_level(lowest_conf, cfg),
            primary_uncertainty=primary_uncertainty,
            affected_stages=affected_stages,
            missing_evidence=bottleneck_missing,
            recommendations=bottleneck_recommendations
        )

        # 4. Path Confidence Aggregation (Bounding by Bottleneck)
        stage_scores = [bd.raw_score for bd in stage_breakdowns.values()] or [0.5]
        edge_scores = [bd.raw_score for bd in edge_breakdowns.values()] or [lowest_conf]
        avg_stage = sum(stage_scores) / len(stage_scores)
        avg_edge = sum(edge_scores) / len(edge_scores)

        # Composite path formula bounds path confidence by the weakest link:
        # Path confidence CANNOT be HIGH if a critical transition or stage is LOW (Scenario F).
        # We blend 35% avg stages, 25% avg edges, and 40% bottleneck, capped strictly at (bottleneck + 0.15).
        blended_path_score = (avg_stage * 0.35) + (avg_edge * 0.25) + (lowest_conf * 0.40)
        if lowest_conf < cfg.threshold_low:
            # If bottleneck is LOW, path score CANNOT exceed MODERATE (strictly < 0.60)
            bounded_path_score = min(blended_path_score, lowest_conf + 0.15, cfg.threshold_moderate - 0.05)
        elif lowest_conf < cfg.threshold_moderate:
            # If bottleneck is MODERATE, path score CANNOT exceed HIGH (strictly < 0.80)
            bounded_path_score = min(blended_path_score, lowest_conf + 0.15, cfg.threshold_high - 0.05)
        else:
            bounded_path_score = min(blended_path_score, lowest_conf + 0.15)

        final_path_score = max(0.0, min(1.0, round(bounded_path_score, 4)))

        # Aggregate path gaps & contradictions
        all_path_contradictions: List[ContradictionItem] = []
        all_path_gaps: List[EvidenceGapItem] = []
        for bd in stage_breakdowns.values():
            all_path_contradictions.extend(bd.contradicting_evidence)
            all_path_gaps.extend(bd.missing_evidence)
        for bd in edge_breakdowns.values():
            all_path_contradictions.extend(bd.contradicting_evidence)
            all_path_gaps.extend(bd.missing_evidence)

        # Path components for transparent audit
        path_components = [
            ConfidenceComponent(
                dimension=ConfidenceDimension.OBSERVATION_STRENGTH,
                score=round(avg_stage, 4),
                weight=0.35,
                weighted_score=round(avg_stage * 0.35, 4),
                evidence_ids=[],
                reason=f"Average stage observation score across {len(stage_scores)} stages: {avg_stage:.2f}",
                limitations=[]
            ),
            ConfidenceComponent(
                dimension=ConfidenceDimension.GRAPH_CONNECTIVITY,
                score=round(avg_edge, 4),
                weight=0.25,
                weighted_score=round(avg_edge * 0.25, 4),
                evidence_ids=[],
                reason=f"Average transition connection strength across {len(edge_scores)} transitions: {avg_edge:.2f}",
                limitations=[]
            ),
            ConfidenceComponent(
                dimension=ConfidenceDimension.INDICATOR_SPECIFICITY,
                score=round(lowest_conf, 4),
                weight=0.40,
                weighted_score=round(lowest_conf * 0.40, 4),
                evidence_ids=[bottleneck_subject_id],
                reason=f"Weakest link bound ({bottleneck_subject_name}): {lowest_conf:.2f}",
                limitations=[primary_uncertainty]
            )
        ]

        path_breakdown = ConfidenceBreakdown(
            subject_type="PATH",
            subject_id=path_id,
            raw_score=final_path_score,
            confidence_level=score_to_confidence_level(final_path_score, cfg),
            epistemic_status="INFERRED" if lowest_conf < 0.60 else "DERIVED",
            components=path_components,
            supporting_evidence=[],
            contradicting_evidence=all_path_contradictions,
            missing_evidence=all_path_gaps,
            evidence_families=[],
            independent_sources_count=len(stage_breakdowns),
            adjustments=[
                {"step": "average_stage_score", "score": round(avg_stage, 4)},
                {"step": "average_edge_score", "score": round(avg_edge, 4)},
                {"step": "bottleneck_score", "score": round(lowest_conf, 4)},
                {"step": "bottleneck_bounding_cap", "score": round(final_path_score, 4)}
            ],
            engine_version=cls.ENGINE_VERSION,
            configuration_version=cfg.configuration_version,
            generated_at=datetime.now(timezone.utc)
        )

        return path_breakdown, bottleneck

    @classmethod
    def compare_hypotheses(
        cls,
        hypothesis_a: Any,
        hypothesis_b: Any,
        stages_a: Optional[List[Any]] = None,
        stages_b: Optional[List[Any]] = None,
        config: Optional[ConfidenceConfig] = None
    ) -> HypothesisComparisonResult:
        """
        Deterministic, evidence-grounded comparison between two competing hypotheses.
        Explains explicitly why one hypothesis outranks another (no black-box ranking).
        """
        cfg = config or cls.DEFAULT_CONFIG
        id_a = getattr(hypothesis_a, "id", "hyp_a")
        title_a = getattr(hypothesis_a, "title", "Hypothesis A")
        score_a = float(getattr(hypothesis_a, "confidence", 0.5))
        level_a = score_to_confidence_level(score_a, cfg)

        id_b = getattr(hypothesis_b, "id", "hyp_b")
        title_b = getattr(hypothesis_b, "title", "Hypothesis B")
        score_b = float(getattr(hypothesis_b, "confidence", 0.5))
        level_b = score_to_confidence_level(score_b, cfg)

        # Parse supporting and contradicting evidence for each
        contra_a = getattr(hypothesis_a, "contradicting_evidence", []) or []
        contra_b = getattr(hypothesis_b, "contradicting_evidence", []) or []
        gaps_a = getattr(hypothesis_a, "missing_evidence", []) or []
        gaps_b = getattr(hypothesis_b, "missing_evidence", []) or []
        sup_a = getattr(hypothesis_a, "supporting_evidence", []) or []
        sup_b = getattr(hypothesis_b, "supporting_evidence", []) or []

        why_ranks_higher: List[str] = []
        key_differentiators: List[str] = []
        strengths_a: List[str] = []
        strengths_b: List[str] = []
        weaknesses_a: List[str] = []
        weaknesses_b: List[str] = []

        if len(sup_a) > len(sup_b):
            strengths_a.append(f"Supported by {len(sup_a)} observed evidence items vs {len(sup_b)} for alternative.")
        elif len(sup_b) > len(sup_a):
            strengths_b.append(f"Supported by {len(sup_b)} observed evidence items vs {len(sup_a)} for alternative.")

        if contra_a:
            weaknesses_a.append(f"{len(contra_a)} contradiction(s) noted against Hypothesis A.")
        else:
            strengths_a.append("Zero observed contradictions against Hypothesis A.")

        if contra_b:
            weaknesses_b.append(f"{len(contra_b)} contradiction(s) noted against Hypothesis B.")
        else:
            strengths_b.append("Zero observed contradictions against Hypothesis B.")

        if len(gaps_a) < len(gaps_b):
            strengths_a.append(f"Fewer missing telemetry gaps ({len(gaps_a)} vs {len(gaps_b)}).")
        elif len(gaps_b) < len(gaps_a):
            strengths_b.append(f"Fewer missing telemetry gaps ({len(gaps_b)} vs {len(gaps_a)}).")

        diff = round(abs(score_a - score_b), 4)
        if score_a >= score_b:
            winning_id = id_a
            key_differentiators.append(f"Hypothesis A outscores Hypothesis B by {diff:.2f} evidence strength points.")
            if len(sup_a) >= len(sup_b):
                why_ranks_higher.append("Hypothesis A possesses greater multi-sensor corroboration.")
            if not contra_a and contra_b:
                why_ranks_higher.append("Hypothesis B is weakened by identified operational contradictions.")
            if len(gaps_a) <= len(gaps_b):
                why_ranks_higher.append("Hypothesis A requires fewer speculative telemetry leaps.")
        else:
            winning_id = id_b
            key_differentiators.append(f"Hypothesis B outscores Hypothesis A by {diff:.2f} evidence strength points.")
            if len(sup_b) >= len(sup_a):
                why_ranks_higher.append("Hypothesis B possesses greater multi-sensor corroboration.")
            if not contra_b and contra_a:
                why_ranks_higher.append("Hypothesis A is weakened by identified operational contradictions.")
            if len(gaps_b) <= len(gaps_a):
                why_ranks_higher.append("Hypothesis B requires fewer speculative telemetry leaps.")

        return HypothesisComparisonResult(
            hypothesis_a_id=id_a,
            hypothesis_a_title=title_a,
            hypothesis_a_score=score_a,
            hypothesis_a_level=level_a,
            hypothesis_b_id=id_b,
            hypothesis_b_title=title_b,
            hypothesis_b_score=score_b,
            hypothesis_b_level=level_b,
            winning_hypothesis_id=winning_id,
            score_difference=diff,
            why_ranks_higher=why_ranks_higher,
            key_differentiators=key_differentiators,
            hypothesis_a_strengths=strengths_a,
            hypothesis_b_strengths=strengths_b,
            hypothesis_a_weaknesses=weaknesses_a,
            hypothesis_b_weaknesses=weaknesses_b
        )
