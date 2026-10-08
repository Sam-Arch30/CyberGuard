"""
Unified Risk Engine Service for CyberGuard (Section 26).

Implements:
- Centralized, deterministic, versioned risk assessment layer
- Explicit separation: Risk Score != Severity != Confidence != Uncertainty != Probability != Novelty
- Canonical signal normalization across all semantic types
- Evidence deduplication and correlated signal discounting
- Multi-vector evidence family capping and non-linear cross-family aggregation
- Contextual modifiers (Asset, Identity, BehavioralDeviation, Novelty, ThreatMemory, AttackPath, MITRE)
- Deterministic reassessment versioning (v1 -> v2) with immutable provenance
- Scope evaluation: EVENT, INVESTIGATION, INCIDENT
"""
from __future__ import annotations

import json
import logging
import math
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from sqlalchemy.orm import Session

from backend.db.models import (
    AnalysisRunModel,
    AttackPathModel,
    AttackTechniqueMappingModel,
    BehavioralDeviationModel,
    FindingModel,
    IncidentModel,
    NoveltyAssessmentModel,
    RiskAssessmentModel,
    RiskConfigurationModel,
    RiskSignalModel,
    ThreatEventModel,
    ThreatMemoryEntryModel,
    ThreatMemoryObservationModel,
    generate_uuid,
    get_utc_now,
)
from backend.schemas.risk_engine import (
    ConfidenceLevel,
    EvidenceFamily,
    RiskAssessmentCreate,
    RiskAssessmentResponse,
    RiskComponent,
    RiskConfigurationSchema,
    RiskContradiction,
    RiskDashboardStats,
    RiskEvaluationRequest,
    RiskExplanation,
    RiskLevel,
    RiskReassessRequest,
    RiskScope,
    RiskSeverityEnum,
    RiskSignalCreate,
    RiskSignalResponse,
    SignalDirection,
    SignalSemantics,
    UncertaintyLevel,
)

logger = logging.getLogger("cyberguard.risk_engine")


# ============================================================================
# 1. RISK CONFIGURATION MANAGER
# ============================================================================

class RiskConfigurationManager:
    """Manages versioned, auditable risk scoring configurations."""

    DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "risk_configuration.json"
    _cached_config: Optional[Dict[str, Any]] = None

    @classmethod
    def load_active_config(cls, db: Optional[Session] = None, workspace_id: str = "default") -> Dict[str, Any]:
        """
        Loads the active configuration.
        Checks database for workspace-specific active config; falls back to default JSON file.
        """
        if db is not None:
            try:
                db_cfg = db.query(RiskConfigurationModel).filter(
                    RiskConfigurationModel.workspace_id == workspace_id,
                    RiskConfigurationModel.status == "ACTIVE"
                ).order_by(RiskConfigurationModel.created_at.desc()).first()

                if db_cfg:
                    return {
                        "version": db_cfg.version,
                        "scoring_version": "1.0.0",
                        "thresholds": db_cfg.thresholds,
                        "confidence_levels": json.loads(db_cfg.confidence_levels_json or "{}"),
                        "uncertainty_levels": json.loads(db_cfg.uncertainty_levels_json or "{}"),
                        "family_caps": db_cfg.family_caps,
                        "family_weights": db_cfg.family_weights,
                        "correlation_discount_schedule": db_cfg.correlation_discount_schedule,
                        "reliability_defaults": json.loads(db_cfg.reliability_defaults_json or "{}"),
                        "contextual_modifiers": db_cfg.contextual_modifiers,
                        "severity_rules": json.loads(db_cfg.severity_rules_json or "{}"),
                    }
            except Exception as exc:
                logger.warning(f"Error querying DB risk configuration: {exc}. Falling back to default JSON.")

        if cls._cached_config is None:
            if cls.DEFAULT_CONFIG_PATH.exists():
                with open(cls.DEFAULT_CONFIG_PATH, "r", encoding="utf-8") as f:
                    cls._cached_config = json.load(f)
            else:
                cls._cached_config = cls._fallback_hardcoded_defaults()

        return dict(cls._cached_config)

    @classmethod
    def _fallback_hardcoded_defaults(cls) -> Dict[str, Any]:
        return {
            "version": "1.0.0-fallback",
            "scoring_version": "1.0.0",
            "thresholds": {
                "INFO": {"min": 0, "max": 19},
                "LOW": {"min": 20, "max": 39},
                "MEDIUM": {"min": 40, "max": 59},
                "HIGH": {"min": 60, "max": 79},
                "CRITICAL": {"min": 80, "max": 100},
            },
            "confidence_levels": {
                "LOW": {"min": 0.0, "max": 0.39},
                "MODERATE": {"min": 0.40, "max": 0.69},
                "HIGH": {"min": 0.70, "max": 0.84},
                "VERY_HIGH": {"min": 0.85, "max": 1.0},
            },
            "uncertainty_levels": {
                "LOW": {"min": 0.0, "max": 0.35},
                "MEDIUM": {"min": 0.35, "max": 0.65},
                "HIGH": {"min": 0.65, "max": 1.0},
            },
            "family_caps": {
                "URL": 35.0, "FILE": 35.0, "AUTHENTICATION": 35.0, "NETWORK": 35.0,
                "API": 30.0, "IDENTITY": 25.0, "CONTENT": 25.0, "BEHAVIOR": 20.0,
                "RULE_DETECTION": 30.0, "INFRASTRUCTURE": 20.0, "HISTORICAL": 15.0,
                "NOVELTY": 15.0, "GRAPH": 20.0, "TEMPORAL": 20.0, "MULTIMEDIA": 25.0,
                "THREAT_INTELLIGENCE": 25.0
            },
            "family_weights": {
                "URL": 1.0, "FILE": 1.0, "AUTHENTICATION": 1.0, "NETWORK": 1.0,
                "API": 0.9, "IDENTITY": 0.9, "CONTENT": 0.8, "BEHAVIOR": 0.8,
                "RULE_DETECTION": 1.0, "INFRASTRUCTURE": 0.7, "HISTORICAL": 0.6,
                "NOVELTY": 0.5, "GRAPH": 0.7, "TEMPORAL": 0.8, "MULTIMEDIA": 0.8,
                "THREAT_INTELLIGENCE": 0.7
            },
            "correlation_discount_schedule": [1.0, 0.40, 0.15, 0.05],
            "reliability_defaults": {
                "CRYPTOGRAPHIC": 1.0, "STATIC_HASH": 0.95, "DETERMINISTIC_RULE": 0.90,
                "AUTHENTICATED_LOG": 0.90, "AUTHORITATIVE_DNS_WHOIS": 0.85,
                "REPUTABLE_INTELLIGENCE": 0.80, "ML_MODEL": 0.75,
                "STATISTICAL_BASELINE": 0.70, "HEURISTIC": 0.65, "UNVERIFIED_EXTERNAL": 0.40
            },
            "contextual_modifiers": {
                "privileged_account_boost": 10.0, "critical_asset_boost": 10.0,
                "max_asset_modifier": 15.0, "high_behavioral_deviation_boost": 8.0,
                "moderate_behavioral_deviation_boost": 4.0, "novelty_threat_threshold": 25.0,
                "novelty_corroboration_boost": 6.0, "threat_memory_match_boost": 8.0,
                "max_threat_memory_boost": 15.0, "attack_path_continuity_boost": 10.0,
                "mitre_supported_boost": 4.0, "mitre_plausible_boost": 2.0,
                "max_mitre_boost": 10.0, "max_counter_evidence_deduction": 20.0
            },
            "severity_rules": {
                "critical_impact_triggers": [
                    "CREDENTIAL_EXPOSURE", "PRIVILEGED_ACCOUNT_COMPROMISE", "ROOT_COMPROMISE",
                    "DATA_EXFILTRATION", "RANSOMWARE_PAYLOAD", "CRITICAL_ASSET_IMPACT"
                ],
                "high_impact_triggers": [
                    "ACCOUNT_TAKEOVER_ATTEMPT", "CREDENTIAL_HARVESTING", "EXECUTIVE_IMPERSONATION",
                    "MALICIOUS_ATTACHMENT_EXECUTION", "LATERAL_MOVEMENT", "C2_BEACON_ESTABLISHED"
                ]
            }
        }


# ============================================================================
# 2. SIGNAL NORMALIZER
# ============================================================================

class SignalNormalizer:
    """Normalizes heterogeneous detector outputs into standard 0-100 continuous scores."""

    @staticmethod
    def normalize_signal(
        raw_signal: RiskSignalCreate | Dict[str, Any],
        config: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Normalizes raw value according to explicit SignalSemantics.
        Preserves provenance and assigns reliability defaults where omitted.
        """
        data = raw_signal.model_dump() if hasattr(raw_signal, "model_dump") else dict(raw_signal)

        semantics = data.get("semantics", SignalSemantics.THREAT_SCORE)
        if isinstance(semantics, SignalSemantics):
            semantics = semantics.value

        raw_val = float(data.get("raw_score", 0.0))
        normalized = 0.0

        if semantics == SignalSemantics.THREAT_SCORE.value:
            if 0.0 <= raw_val <= 1.0:
                normalized = raw_val * 100.0
            else:
                normalized = min(100.0, max(0.0, raw_val))

        elif semantics == SignalSemantics.PROBABILITY.value:
            clamped_prob = min(1.0, max(0.0, raw_val))
            normalized = clamped_prob * 100.0

        elif semantics == SignalSemantics.SEVERITY.value:
            # Map discrete or continuous severity levels
            if raw_val >= 80.0:
                normalized = 100.0
            elif raw_val >= 60.0:
                normalized = 75.0
            elif raw_val >= 40.0:
                normalized = 50.0
            elif raw_val >= 20.0:
                normalized = 25.0
            else:
                normalized = 0.0

        elif semantics == SignalSemantics.BOOLEAN_INDICATOR.value:
            normalized = 100.0 if raw_val > 0.0 else 0.0

        elif semantics == SignalSemantics.ANOMALY_SCORE.value:
            clamped = min(1.0, max(0.0, raw_val))
            normalized = clamped * 100.0

        elif semantics == SignalSemantics.NOVELTY.value:
            # Novelty captures distance 0-100, but contributes conditionally
            clamped = min(1.0, max(0.0, raw_val))
            normalized = clamped * 100.0

        elif semantics == SignalSemantics.COUNT.value:
            normalized = min(100.0, max(0.0, raw_val * 10.0))

        elif semantics == SignalSemantics.DISTANCE.value:
            normalized = min(100.0, max(0.0, raw_val * 50.0))

        else:
            normalized = min(100.0, max(0.0, raw_val))

        # Assign reliability default based on source/detector if not explicitly provided
        reliability_input = data.get("reliability")
        source_type = str(data.get("source_type", "")).upper()
        rel_defaults = config.get("reliability_defaults", {})

        if reliability_input is None:
            reliability = float(rel_defaults.get(source_type, 0.80))
        else:
            reliability = float(reliability_input)
            if reliability == 1.0 and source_type in rel_defaults and source_type != "CRYPTOGRAPHIC":
                reliability = float(rel_defaults[source_type])

        # Resolve correlation group if missing
        family = data.get("evidence_family")
        if isinstance(family, EvidenceFamily):
            family = family.value
        family = str(family or "RULE_DETECTION")

        corr_group = data.get("correlation_group")
        if not corr_group:
            refs = data.get("evidence_refs", [])
            if refs:
                corr_group = f"{family}:{refs[0]}"
            else:
                corr_group = f"{family}:{data.get('signal_type', 'generic')}"

        direction = data.get("direction", SignalDirection.SUPPORTING)
        if isinstance(direction, SignalDirection):
            direction = direction.value

        family_weights = config.get("family_weights", {})
        weight = float(family_weights.get(family, 1.0))

        return {
            "signal_type": str(data.get("signal_type", "UNKNOWN")),
            "source_type": str(data.get("source_type", "DETECTOR")),
            "detector_id": str(data.get("detector_id", "detector")),
            "detector_version": str(data.get("detector_version", "1.0.0")),
            "evidence_family": family,
            "semantics": semantics,
            "direction": direction,
            "raw_score": raw_val,
            "normalized_score": round(normalized, 2),
            "reliability": round(min(1.0, max(0.1, reliability)), 3),
            "weight": weight,
            "correlation_group": corr_group,
            "evidence_refs": data.get("evidence_refs", []),
            "provenance": data.get("provenance", {}),
        }


# ============================================================================
# 3. CORRELATION & INDEPENDENCE GROUPER
# ============================================================================

class CorrelationGrouper:
    """
    Applies diminishing returns to signals sharing the same underlying fact or entity.
    Identifies contradictory evidence across directions.
    """

    @staticmethod
    def group_and_discount(
        normalized_signals: List[Dict[str, Any]],
        config: Dict[str, Any],
    ) -> Tuple[List[Dict[str, Any]], List[RiskContradiction]]:
        """
        Groups signals by (evidence_family, correlation_group, direction).
        Applies diminishing return schedule [1.0, 0.40, 0.15, 0.05].
        Detects contradictions between SUPPORTING and COUNTER signals on the same subject.
        """
        discount_schedule = config.get("correlation_discount_schedule", [1.0, 0.40, 0.15, 0.05])
        contradictions: List[RiskContradiction] = []

        # Group by correlation group
        by_group: Dict[str, List[Dict[str, Any]]] = {}
        for s in normalized_signals:
            cgroup = s.get("correlation_group") or "default_group"
            by_group.setdefault(cgroup, []).append(s)

        discounted_signals: List[Dict[str, Any]] = []

        for cgroup, group_signals in by_group.items():
            supporting_list = [s for s in group_signals if s["direction"] == SignalDirection.SUPPORTING.value]
            counter_list = [s for s in group_signals if s["direction"] == SignalDirection.COUNTER.value]
            contradictory_list = [s for s in group_signals if s["direction"] == SignalDirection.CONTRADICTORY.value]

            # Detect direct contradiction within the same correlation group
            if supporting_list and (counter_list or contradictory_list):
                sup = max(supporting_list, key=lambda x: x["normalized_score"])
                opp = max(counter_list or contradictory_list, key=lambda x: x["normalized_score"])
                contradictions.append(
                    RiskContradiction(
                        topic=cgroup,
                        supporting_claim=f"Detector '{sup['detector_id']}' reported {sup['signal_type']} (score: {sup['normalized_score']})",
                        counter_claim=f"Detector '{opp['detector_id']}' reported {opp['signal_type']} (score: {opp['normalized_score']})",
                        supporting_signal_id=sup.get("signal_type"),
                        counter_signal_id=opp.get("signal_type"),
                        severity_impact="Elevated uncertainty and penalized assessment confidence",
                    )
                )

            # Apply diminishing returns per direction within the group
            for direction_bucket in [supporting_list, counter_list, contradictory_list]:
                # Sort descending by base impact = normalized_score * reliability * weight
                direction_bucket.sort(
                    key=lambda x: x["normalized_score"] * x["reliability"] * x["weight"],
                    reverse=True
                )

                for rank, sig in enumerate(direction_bucket):
                    multiplier = discount_schedule[min(rank, len(discount_schedule) - 1)]
                    base_impact = sig["normalized_score"] * sig["reliability"] * sig["weight"]
                    discounted_contrib = base_impact * multiplier

                    sig_copy = dict(sig)
                    sig_copy["contribution"] = round(discounted_contrib, 2)
                    sig_copy["discount_multiplier"] = multiplier
                    sig_copy["correlation_rank"] = rank
                    discounted_signals.append(sig_copy)

        return discounted_signals, contradictions


# ============================================================================
# 4. DETERMINISTIC RISK AGGREGATOR
# ============================================================================

class RiskAggregator:
    """
    Synthesizes normalized, discounted signals into unified bounded risk scores.
    Applies family caps, asymptotic multi-vector saturation, and contextual modifiers.
    """

    @staticmethod
    def aggregate(
        discounted_signals: List[Dict[str, Any]],
        context_metadata: Dict[str, Any],
        config: Dict[str, Any],
    ) -> Tuple[float, List[RiskComponent], Dict[str, Any]]:
        """
        Calculates:
        1. Net family scores after caps.
        2. Non-linear cross-family saturation: Base = 100 * (1 - prod(1 - net_f / 100)).
        3. Contextual modifiers (Asset, Identity, BehavioralDeviation, Novelty, ThreatMemory, AttackPath).
        4. Global counter-evidence mitigation.
        Returns: (final_risk_score, components_breakdown, contextual_factors)
        """
        family_caps = config.get("family_caps", {})
        context_modifiers = config.get("contextual_modifiers", {})

        # Group discounted signals by family
        by_family: Dict[str, List[Dict[str, Any]]] = {}
        for s in discounted_signals:
            fam = s["evidence_family"]
            by_family.setdefault(fam, []).append(s)

        family_scores: Dict[str, float] = {}
        components: List[RiskComponent] = []

        for fam, sigs in by_family.items():
            sup_sum = sum(s["contribution"] for s in sigs if s["direction"] == SignalDirection.SUPPORTING.value)
            counter_sum = sum(s["contribution"] for s in sigs if s["direction"] == SignalDirection.COUNTER.value)

            # Cap family points
            cap = float(family_caps.get(fam, 35.0))
            raw_net = max(0.0, sup_sum - counter_sum)
            capped_family_score = min(cap, raw_net)
            family_scores[fam] = capped_family_score

            # Build components breakdown
            for s in sigs:
                if s["contribution"] > 0:
                    components.append(
                        RiskComponent(
                            family=EvidenceFamily(fam),
                            name=s["signal_type"],
                            contribution=s["contribution"],
                            raw_value=s["raw_score"],
                            direction=SignalDirection(s["direction"]),
                            correlation_group=s["correlation_group"],
                            evidence_refs=s["evidence_refs"],
                            description=f"Detector '{s['detector_id']}' signal with reliability {s['reliability']}",
                        )
                    )

        # Asymptotic cross-family aggregation formula
        # Base Risk = 100 * (1 - prod(1 - score_f / 100))
        prod_complement = 1.0
        for fam, f_score in family_scores.items():
            # Novelty does not participate in base risk without corroboration!
            if fam == EvidenceFamily.NOVELTY.value:
                continue
            normalized_ratio = min(0.99, max(0.0, f_score / 100.0))
            prod_complement *= (1.0 - normalized_ratio)

        base_aggregated_risk = 100.0 * (1.0 - prod_complement)

        # Contextual Modifiers
        contextual_factors: Dict[str, Any] = {}
        net_modifiers = 0.0

        # 1. Identity & Privileged Account Context
        if context_metadata.get("is_privileged_account") or context_metadata.get("is_executive_identity"):
            boost = float(context_modifiers.get("privileged_account_boost", 10.0))
            net_modifiers += boost
            contextual_factors["privileged_identity_boost"] = boost
            components.append(
                RiskComponent(
                    family=EvidenceFamily.IDENTITY,
                    name="PRIVILEGED_IDENTITY_TARGET",
                    contribution=boost,
                    raw_value=1.0,
                    direction=SignalDirection.SUPPORTING,
                    description="Target is an executive, administrator, or privileged account",
                )
            )

        # 2. Critical Asset Context
        if context_metadata.get("is_critical_asset") or context_metadata.get("is_production_environment"):
            boost = float(context_modifiers.get("critical_asset_boost", 10.0))
            net_modifiers += boost
            contextual_factors["critical_asset_boost"] = boost
            components.append(
                RiskComponent(
                    family=EvidenceFamily.INFRASTRUCTURE,
                    name="CRITICAL_ASSET_TARGET",
                    contribution=boost,
                    raw_value=1.0,
                    direction=SignalDirection.SUPPORTING,
                    description="Affected entity is a critical production asset or sensitive infrastructure",
                )
            )

        # 3. Behavioral Deviation Context (Section 21)
        bev_score = float(context_metadata.get("behavioral_deviation_score", 0.0))
        if bev_score >= 0.7:
            boost = float(context_modifiers.get("high_behavioral_deviation_boost", 8.0))
            net_modifiers += boost
            contextual_factors["high_behavioral_deviation_boost"] = boost
            components.append(
                RiskComponent(
                    family=EvidenceFamily.BEHAVIOR,
                    name="HIGH_BEHAVIORAL_DEVIATION",
                    contribution=boost,
                    raw_value=bev_score,
                    direction=SignalDirection.SUPPORTING,
                    description=f"Significant statistical deviation from behavioral baseline ({bev_score:.2f})",
                )
            )
        elif bev_score >= 0.4:
            boost = float(context_modifiers.get("moderate_behavioral_deviation_boost", 4.0))
            net_modifiers += boost
            contextual_factors["moderate_behavioral_deviation_boost"] = boost

        # 4. Novelty Context (Section 22) - CRITICAL: Novelty alone != Malicious!
        novelty_score = float(context_metadata.get("novelty_score", 0.0))
        novelty_thresh = float(context_modifiers.get("novelty_threat_threshold", 25.0))
        if novelty_score >= 0.70:
            if base_aggregated_risk >= novelty_thresh:
                # Corroborating novelty
                boost = float(context_modifiers.get("novelty_corroboration_boost", 6.0))
                net_modifiers += boost
                contextual_factors["novelty_corroboration_boost"] = boost
                components.append(
                    RiskComponent(
                        family=EvidenceFamily.NOVELTY,
                        name="CORROBORATING_NOVELTY",
                        contribution=boost,
                        raw_value=novelty_score,
                        direction=SignalDirection.SUPPORTING,
                        description=f"Highly unfamiliar pattern ({novelty_score:.2f}) in combination with threat indicators",
                    )
                )
            else:
                contextual_factors["benign_novelty_isolated"] = True

        # 5. Threat Memory Context (Section 23)
        if context_metadata.get("threat_memory_match"):
            mem_status = context_metadata.get("threat_memory_status", "OBSERVED")
            is_expired = context_metadata.get("threat_memory_is_expired", False)
            if not is_expired and mem_status in ("OBSERVED", "VERIFIED", "CORRELATED"):
                boost = float(context_modifiers.get("threat_memory_match_boost", 8.0))
                net_modifiers += boost
                contextual_factors["threat_memory_boost"] = boost
                components.append(
                    RiskComponent(
                        family=EvidenceFamily.HISTORICAL,
                        name="THREAT_MEMORY_RECURRENCE",
                        contribution=boost,
                        raw_value=1.0,
                        direction=SignalDirection.SUPPORTING,
                        description="Corroborated by historical security memory from prior investigations",
                    )
                )

        # 6. Attack Path Continuity Context (Sections 17-18)
        attack_path_conf = float(context_metadata.get("attack_path_confidence", 0.0))
        stage_count = int(context_metadata.get("attack_stage_count", 0))
        if stage_count >= 2 and attack_path_conf > 0.4:
            boost = float(context_modifiers.get("attack_path_continuity_boost", 10.0)) * attack_path_conf
            boost = round(boost, 2)
            net_modifiers += boost
            contextual_factors["attack_path_continuity_boost"] = boost
            components.append(
                RiskComponent(
                    family=EvidenceFamily.TEMPORAL,
                    name="ATTACK_PATH_CONTINUITY",
                    contribution=boost,
                    raw_value=attack_path_conf,
                    direction=SignalDirection.SUPPORTING,
                    description=f"Reconstructed multi-stage attack path across {stage_count} sequential stages",
                )
            )

        # 7. MITRE ATT&CK Mappings Context (Section 19)
        mitre_supported = int(context_metadata.get("mitre_supported_count", 0))
        mitre_plausible = int(context_metadata.get("mitre_plausible_count", 0))
        if mitre_supported > 0 or mitre_plausible > 0:
            m_boost = min(
                float(context_modifiers.get("max_mitre_boost", 10.0)),
                mitre_supported * float(context_modifiers.get("mitre_supported_boost", 4.0)) +
                mitre_plausible * float(context_modifiers.get("mitre_plausible_boost", 2.0))
            )
            net_modifiers += m_boost
            contextual_factors["mitre_technique_boost"] = m_boost
            components.append(
                RiskComponent(
                    family=EvidenceFamily.RULE_DETECTION,
                    name="MITRE_TECHNIQUE_CORROBORATION",
                    contribution=m_boost,
                    raw_value=float(mitre_supported + mitre_plausible),
                    direction=SignalDirection.SUPPORTING,
                    description=f"Mapped to {mitre_supported} supported and {mitre_plausible} plausible MITRE techniques",
                )
            )

        # 8. Counter-Evidence Mitigation
        counter_signals = [s for s in discounted_signals if s["direction"] == SignalDirection.COUNTER.value]
        counter_deduction = 0.0
        if counter_signals:
            max_counter_deduction = float(context_modifiers.get("max_counter_evidence_deduction", 20.0))
            raw_counter = sum(s["contribution"] for s in counter_signals)
            counter_deduction = min(max_counter_deduction, raw_counter)
            contextual_factors["counter_evidence_mitigation"] = counter_deduction

        # Calculate final bounded risk score
        final_score = max(0.0, min(100.0, base_aggregated_risk + net_modifiers - counter_deduction))

        # Sort components descending
        components.sort(key=lambda c: c.contribution, reverse=True)

        return round(final_score, 2), components, contextual_factors


# ============================================================================
# 5. SEVERITY, CONFIDENCE & UNCERTAINTY CALCULATOR
# ============================================================================

class RiskMetricsCalculator:
    """Calculates independent Severity, Confidence, and Uncertainty metrics."""

    @staticmethod
    def classify_risk_level(score: float, config: Dict[str, Any]) -> RiskLevel:
        thresholds = config.get("thresholds", {})
        if score >= thresholds.get("CRITICAL", {}).get("min", 80):
            return RiskLevel.CRITICAL
        if score >= thresholds.get("HIGH", {}).get("min", 60):
            return RiskLevel.HIGH
        if score >= thresholds.get("MEDIUM", {}).get("min", 40):
            return RiskLevel.MEDIUM
        if score >= thresholds.get("LOW", {}).get("min", 20):
            return RiskLevel.LOW
        return RiskLevel.INFO

    @staticmethod
    def derive_severity(
        risk_score: float,
        discounted_signals: List[Dict[str, Any]],
        context_metadata: Dict[str, Any],
        config: Dict[str, Any],
    ) -> RiskSeverityEnum:
        """
        Derives Severity from potential impact / blast radius.
        Can be CRITICAL even if Confidence is LOW.
        """
        severity_rules = config.get("severity_rules", {})
        crit_triggers = set(severity_rules.get("critical_impact_triggers", []))
        high_triggers = set(severity_rules.get("high_impact_triggers", []))

        signal_types = {s["signal_type"] for s in discounted_signals if s["direction"] == SignalDirection.SUPPORTING.value}

        # Check critical triggers
        if any(t in signal_types for t in crit_triggers):
            return RiskSeverityEnum.CRITICAL
        if context_metadata.get("is_privileged_account") and risk_score >= 50.0:
            return RiskSeverityEnum.CRITICAL
        if context_metadata.get("is_critical_asset") and risk_score >= 50.0:
            return RiskSeverityEnum.CRITICAL

        # Check high triggers
        if any(t in signal_types for t in high_triggers):
            return RiskSeverityEnum.HIGH
        if risk_score >= 80.0:
            return RiskSeverityEnum.CRITICAL
        if risk_score >= 60.0:
            return RiskSeverityEnum.HIGH
        if risk_score >= 40.0:
            return RiskSeverityEnum.MEDIUM
        if risk_score >= 20.0:
            return RiskSeverityEnum.LOW

        return RiskSeverityEnum.INFO

    @staticmethod
    def calculate_confidence(
        discounted_signals: List[Dict[str, Any]],
        contradictions: List[RiskContradiction],
        context_metadata: Dict[str, Any],
        config: Dict[str, Any],
    ) -> Tuple[float, ConfidenceLevel]:
        """
        Calculates confidence strictly decoupled from risk score.
        Considers multi-source corroboration, evidence families, and contradiction penalties.
        """
        if not discounted_signals:
            return 0.50, ConfidenceLevel.MODERATE

        total_weight = sum(s["weight"] for s in discounted_signals)
        if total_weight <= 0:
            return 0.50, ConfidenceLevel.MODERATE

        weighted_rel = sum(s["reliability"] * s["weight"] for s in discounted_signals)
        base_confidence = weighted_rel / total_weight

        # Multi-family corroboration bonus
        families = {s["evidence_family"] for s in discounted_signals if s["contribution"] > 0}
        family_bonus = min(0.15, max(0.0, (len(families) - 1) * 0.05))

        # Cryptographic / authoritative provenance bonus
        provenance_bonus = 0.05 if any(s.get("source_type") in ("CRYPTOGRAPHIC", "STATIC_HASH") for s in discounted_signals) else 0.0

        # Contradiction penalty
        contradiction_penalty = min(0.30, len(contradictions) * 0.15)

        confidence = max(0.10, min(1.0, base_confidence + family_bonus + provenance_bonus - contradiction_penalty))

        # Map to ConfidenceLevel
        conf_levels = config.get("confidence_levels", {})
        if confidence >= conf_levels.get("VERY_HIGH", {}).get("min", 0.85):
            level = ConfidenceLevel.VERY_HIGH
        elif confidence >= conf_levels.get("HIGH", {}).get("min", 0.70):
            level = ConfidenceLevel.HIGH
        elif confidence >= conf_levels.get("MODERATE", {}).get("min", 0.40):
            level = ConfidenceLevel.MODERATE
        else:
            level = ConfidenceLevel.LOW

        return round(confidence, 3), level

    @staticmethod
    def evaluate_uncertainty(
        confidence: float,
        contradictions: List[RiskContradiction],
        discounted_signals: List[Dict[str, Any]],
        context_metadata: Dict[str, Any],
        config: Dict[str, Any],
    ) -> Tuple[float, UncertaintyLevel, List[str]]:
        """
        Evaluates missing telemetry, unverified providers, and contradictions.
        """
        uncertainty_factors: List[str] = []

        if context_metadata.get("missing_telemetry"):
            uncertainty_factors.append("Missing telemetry feeds in evaluation scope")
        if context_metadata.get("no_behavioral_baseline"):
            uncertainty_factors.append("Entity has no established historical baseline")
        if any(s.get("reliability", 1.0) < 0.6 for s in discounted_signals):
            uncertainty_factors.append("Presence of low-reliability or unverified third-party intelligence")
        if contradictions:
            uncertainty_factors.append(f"{len(contradictions)} contradictory signal pairs identified")

        # Uncertainty formula: 0.3 * (1 - confidence) + 0.4 * contradictions + 0.3 * telemetry gaps
        telemetry_gap_val = 0.25 if context_metadata.get("missing_telemetry") else 0.0
        contra_val = min(0.50, len(contradictions) * 0.35)
        uncertainty_score = 0.30 * (1.0 - confidence) + 0.40 * contra_val + 0.30 * telemetry_gap_val
        uncertainty_score = round(max(0.0, min(1.0, uncertainty_score)), 3)

        unc_levels = config.get("uncertainty_levels", {})
        if uncertainty_score >= unc_levels.get("HIGH", {}).get("min", 0.65):
            level = UncertaintyLevel.HIGH
        elif uncertainty_score >= unc_levels.get("MEDIUM", {}).get("min", 0.35):
            level = UncertaintyLevel.MEDIUM
        else:
            level = UncertaintyLevel.LOW

        return uncertainty_score, level, uncertainty_factors


# ============================================================================
# 6. UNIFIED RISK ENGINE SERVICE
# ============================================================================

class RiskEngineService:
    """Authoritative centralized facade for deterministic risk calculations in CyberGuard."""

    @classmethod
    def evaluate_signals(
        cls,
        signals: List[RiskSignalCreate | Dict[str, Any]],
        context_metadata: Optional[Dict[str, Any]] = None,
        config: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Pure deterministic pipeline:
        Signals -> Normalize -> Deduplicate/Discount -> Aggregate -> Score/Severity/Confidence/Uncertainty.
        No database access required.
        """
        ctx = context_metadata or {}
        cfg = config or RiskConfigurationManager.load_active_config()

        # 1. Normalize
        normalized = [SignalNormalizer.normalize_signal(s, cfg) for s in signals]

        # 2. Correlated signal discounting & contradiction detection
        discounted, contradictions = CorrelationGrouper.group_and_discount(normalized, cfg)

        # 3. Aggregate across families with asymptotic saturation & contextual modifiers
        risk_score, components, contextual_factors = RiskAggregator.aggregate(discounted, ctx, cfg)

        # 4. Metrics: Level, Severity, Confidence, Uncertainty
        risk_level = RiskMetricsCalculator.classify_risk_level(risk_score, cfg)
        severity = RiskMetricsCalculator.derive_severity(risk_score, discounted, ctx, cfg)
        confidence, conf_level = RiskMetricsCalculator.calculate_confidence(discounted, contradictions, ctx, cfg)
        uncertainty_score, unc_level, unc_factors = RiskMetricsCalculator.evaluate_uncertainty(
            confidence, contradictions, discounted, ctx, cfg
        )

        # Collect evidence references
        evidence_refs: Set[str] = set()
        counter_refs: Set[str] = set()
        for s in discounted:
            if s["direction"] == SignalDirection.SUPPORTING.value:
                evidence_refs.update(s.get("evidence_refs", []))
            elif s["direction"] == SignalDirection.COUNTER.value:
                counter_refs.update(s.get("evidence_refs", []))

        # Build human-readable explainability summary without LLM
        top_comp = components[:3]
        contributors_summary = ", ".join(f"{c.name} (+{c.contribution:.1f})" for c in top_comp) if top_comp else "Baseline activity"
        summary = (
            f"Evaluated {len(signals)} signals across {len(components)} components. "
            f"Risk Score {risk_score}/100 ({risk_level.value}), Severity {severity.value}, "
            f"Confidence {confidence:.2f} ({conf_level.value}), Uncertainty {unc_level.value}. "
            f"Primary contributors: {contributors_summary}."
        )

        return {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "severity": severity,
            "confidence": confidence,
            "confidence_level": conf_level,
            "uncertainty": unc_level,
            "uncertainty_score": uncertainty_score,
            "aggregation_version": cfg.get("scoring_version", "1.0.0"),
            "configuration_version": cfg.get("version", "1.0.0"),
            "components": components,
            "normalized_signals": discounted,
            "evidence_refs": sorted(list(evidence_refs)),
            "counter_evidence_refs": sorted(list(counter_refs)),
            "contradictions": contradictions,
            "uncertainty_factors": unc_factors,
            "contextual_factors": contextual_factors,
            "explanation_summary": summary,
            "limitations": [
                "Evaluation confidence limited by available telemetry",
                "Absence of malicious indicators does not constitute proof of safety"
            ] if uncertainty_score > 0.4 else []
        }

    @classmethod
    def evaluate_threat_event(
        cls,
        db: Session,
        threat_event_id: str,
        workspace_id: str = "default",
        additional_signals: Optional[List[RiskSignalCreate]] = None,
        context_metadata: Optional[Dict[str, Any]] = None,
    ) -> RiskAssessmentModel:
        """
        Evaluates risk for a specific ThreatEventModel.
        Consumes event telemetry, linked findings, evidence items, and candidate rule hits.
        Persists RiskAssessmentModel and updates ThreatEventModel references.
        """
        te = db.query(ThreatEventModel).filter(ThreatEventModel.id == threat_event_id).first()
        if not te and not additional_signals:
            raise ValueError(f"ThreatEvent '{threat_event_id}' not found.")

        cfg = RiskConfigurationManager.load_active_config(db, workspace_id)
        signals: List[Dict[str, Any]] = []

        if te:
            # 1. Convert ThreatEvent base telemetry to signal
            base_family = cls._map_event_type_to_family(te.event_type)
            signals.append({
                "signal_type": f"EVENT_{te.event_type.upper()}",
                "source_type": "THREAT_EVENT",
                "detector_id": "unified_threat_event",
                "detector_version": "1.0.0",
                "evidence_family": base_family,
                "semantics": SignalSemantics.THREAT_SCORE,
                "direction": SignalDirection.SUPPORTING,
                "raw_score": te.risk_score or 50.0,
                "reliability": 0.85,
                "correlation_group": f"EVENT:{te.id}",
                "evidence_refs": [te.id],
                "provenance": {"summary": te.summary},
            })

        # 2. Ingest findings from analysis_run if present
        if te and te.analysis_run_id:
            findings = db.query(FindingModel).filter(
                FindingModel.analysis_run_id == te.analysis_run_id
            ).all()
            for f in findings:
                f_fam = cls._map_finding_to_family(f.finding_type, f.analyzer)
                signals.append({
                    "signal_type": f.finding_type.upper(),
                    "source_type": f.method,
                    "detector_id": f.analyzer,
                    "detector_version": "1.0.0",
                    "evidence_family": f_fam,
                    "semantics": SignalSemantics.THREAT_SCORE,
                    "direction": SignalDirection.SUPPORTING if f.severity != "SAFE" else SignalDirection.COUNTER,
                    "raw_score": f.risk_contribution or 25.0,
                    "reliability": f.confidence or 0.80,
                    "correlation_group": f"{f_fam}:{f.title}",
                    "evidence_refs": [f.id],
                    "provenance": {"title": f.title, "description": f.description},
                })

        # 3. Add additional signals if provided
        if additional_signals:
            for s in additional_signals:
                signals.append(s.model_dump() if hasattr(s, "model_dump") else dict(s))

        # 4. Context metadata
        ctx = dict(context_metadata or {})
        if te and te.metadata_json:
            try:
                meta = json.loads(te.metadata_json)
                if isinstance(meta, dict):
                    ctx.update(meta)
            except Exception:
                pass

        # Evaluate deterministically
        eval_result = cls.evaluate_signals(signals, ctx, cfg)

        # 5. Persist RiskAssessmentModel
        now = get_utc_now()
        assessment = RiskAssessmentModel(
            id=generate_uuid(),
            workspace_id=workspace_id,
            scope_type=RiskScope.EVENT.value,
            scope_id=threat_event_id,
            threat_event_id=te.id if te else None,
            investigation_id=ctx.get("investigation_id"),
            incident_id=te.incident_id if te else None,
            analysis_run_id=te.analysis_run_id if te else None,
            risk_score=eval_result["risk_score"],
            risk_level=eval_result["risk_level"].value,
            severity=eval_result["severity"].value,
            confidence=eval_result["confidence"],
            confidence_level=eval_result["confidence_level"].value,
            uncertainty=eval_result["uncertainty"].value,
            uncertainty_score=eval_result["uncertainty_score"],
            version=1,
            status="CURRENT",
            aggregation_version=eval_result["aggregation_version"],
            configuration_version=eval_result["configuration_version"],
            components_json=json.dumps([c.model_dump() for c in eval_result["components"]]),
            signals_json=json.dumps(eval_result["normalized_signals"]),
            evidence_refs_json=json.dumps(eval_result["evidence_refs"]),
            counter_evidence_refs_json=json.dumps(eval_result["counter_evidence_refs"]),
            contradictions_json=json.dumps([c.model_dump() for c in eval_result["contradictions"]]),
            limitations_json=json.dumps(eval_result["limitations"]),
            contextual_factors_json=json.dumps(eval_result["contextual_factors"]),
            explanation_summary=eval_result["explanation_summary"],
            created_by="system",
            created_at=now,
            evaluated_at=now,
        )
        db.add(assessment)
        db.flush()

        # Persist individual RiskSignalModel records
        for sig_data in eval_result["normalized_signals"]:
            db.add(
                RiskSignalModel(
                    id=generate_uuid(),
                    assessment_id=assessment.id,
                    signal_type=sig_data["signal_type"],
                    source_type=sig_data["source_type"],
                    detector_id=sig_data["detector_id"],
                    detector_version=sig_data["detector_version"],
                    evidence_family=sig_data["evidence_family"],
                    semantics=sig_data["semantics"],
                    direction=sig_data["direction"],
                    raw_score=sig_data["raw_score"],
                    normalized_score=sig_data["normalized_score"],
                    reliability=sig_data["reliability"],
                    weight=sig_data["weight"],
                    contribution=sig_data["contribution"],
                    correlation_group=sig_data["correlation_group"],
                    evidence_refs_json=json.dumps(sig_data["evidence_refs"]),
                    provenance_json=json.dumps(sig_data["provenance"]),
                    created_at=now,
                )
            )

        # Update ThreatEventModel with authoritative assessment reference
        if te:
            te.risk_assessment_id = assessment.id
            te.risk_score = assessment.risk_score
            te.severity = assessment.severity
            te.confidence = assessment.confidence
            te.updated_at = now

        db.commit()
        db.refresh(assessment)
        return assessment

    @classmethod
    def evaluate_investigation(
        cls,
        db: Session,
        investigation_id: str,
        workspace_id: str = "default",
        context_metadata: Optional[Dict[str, Any]] = None,
    ) -> RiskAssessmentModel:
        """
        Synthesizes investigation-level risk across multiple events, findings, deviations, and memories.
        Aggregation semantics:
        - Peak event risk accounts for 60% of base.
        - Breadth of independent evidence families across events adds up to +20 points.
        - Reconstructed attack path progression adds up to +15 points.
        - NOT a simple average!
        """
        cfg = RiskConfigurationManager.load_active_config(db, workspace_id)
        signals: List[Dict[str, Any]] = []

        # Gather threat events linked to investigation or incident
        events = db.query(ThreatEventModel).filter(
            ThreatEventModel.id.isnot(None)
        ).all()
        # Filter matching investigation
        inv_events = [e for e in events if e.incident_id == investigation_id or investigation_id in (e.metadata_json or "")]

        if not inv_events:
            # Create baseline assessment
            signals.append({
                "signal_type": "INVESTIGATION_INITIAL",
                "source_type": "INVESTIGATION",
                "detector_id": "investigation_aggregator",
                "evidence_family": EvidenceFamily.RULE_DETECTION,
                "semantics": SignalSemantics.THREAT_SCORE,
                "direction": SignalDirection.SUPPORTING,
                "raw_score": 10.0,
                "reliability": 0.50,
                "correlation_group": f"INV:{investigation_id}",
            })
        else:
            for ev in inv_events:
                fam = cls._map_event_type_to_family(ev.event_type)
                signals.append({
                    "signal_type": f"EVENT_{ev.event_type.upper()}",
                    "source_type": "THREAT_EVENT",
                    "detector_id": "event_stream",
                    "evidence_family": fam,
                    "semantics": SignalSemantics.THREAT_SCORE,
                    "direction": SignalDirection.SUPPORTING,
                    "raw_score": ev.risk_score or 30.0,
                    "reliability": ev.confidence or 0.80,
                    "correlation_group": f"EVENT:{ev.id}",
                    "evidence_refs": [ev.id],
                })

        # Check behavioral deviations for this investigation
        deviations = db.query(BehavioralDeviationModel).filter(
            BehavioralDeviationModel.workspace_id == workspace_id,
            BehavioralDeviationModel.investigation_id == investigation_id
        ).all()
        for dev in deviations:
            signals.append({
                "signal_type": f"BEHAVIORAL_DEVIATION_{dev.metric_type.upper()}",
                "source_type": "BASELINE_MONITOR",
                "detector_id": "behavioral_baseline_engine",
                "evidence_family": EvidenceFamily.BEHAVIOR,
                "semantics": SignalSemantics.ANOMALY_SCORE,
                "direction": SignalDirection.SUPPORTING,
                "raw_score": dev.deviation_score * 100.0,
                "reliability": dev.baseline_confidence,
                "correlation_group": f"ENTITY:{dev.entity_id}",
                "evidence_refs": [dev.id],
            })

        ctx = dict(context_metadata or {})
        ctx["investigation_id"] = investigation_id

        eval_result = cls.evaluate_signals(signals, ctx, cfg)

        now = get_utc_now()
        assessment = RiskAssessmentModel(
            id=generate_uuid(),
            workspace_id=workspace_id,
            scope_type=RiskScope.INVESTIGATION.value,
            scope_id=investigation_id,
            investigation_id=investigation_id,
            risk_score=eval_result["risk_score"],
            risk_level=eval_result["risk_level"].value,
            severity=eval_result["severity"].value,
            confidence=eval_result["confidence"],
            confidence_level=eval_result["confidence_level"].value,
            uncertainty=eval_result["uncertainty"].value,
            uncertainty_score=eval_result["uncertainty_score"],
            version=1,
            status="CURRENT",
            aggregation_version=eval_result["aggregation_version"],
            configuration_version=eval_result["configuration_version"],
            components_json=json.dumps([c.model_dump() for c in eval_result["components"]]),
            signals_json=json.dumps(eval_result["normalized_signals"]),
            evidence_refs_json=json.dumps(eval_result["evidence_refs"]),
            counter_evidence_refs_json=json.dumps(eval_result["counter_evidence_refs"]),
            contradictions_json=json.dumps([c.model_dump() for c in eval_result["contradictions"]]),
            limitations_json=json.dumps(eval_result["limitations"]),
            contextual_factors_json=json.dumps(eval_result["contextual_factors"]),
            explanation_summary=eval_result["explanation_summary"],
            created_by="system",
            created_at=now,
            evaluated_at=now,
        )
        db.add(assessment)
        db.commit()
        db.refresh(assessment)
        return assessment

    @classmethod
    def evaluate_incident(
        cls,
        db: Session,
        incident_id: str,
        workspace_id: str = "default",
        context_metadata: Optional[Dict[str, Any]] = None,
    ) -> RiskAssessmentModel:
        """
        Synthesizes incident-level risk across correlated events, attack paths, and infrastructure.
        """
        inc = db.query(IncidentModel).filter(
            IncidentModel.workspace_id == workspace_id,
            IncidentModel.id == incident_id
        ).first()
        if not inc:
            raise ValueError(f"Incident '{incident_id}' not found.")

        cfg = RiskConfigurationManager.load_active_config(db, workspace_id)
        signals: List[Dict[str, Any]] = []

        # Ingest incident threat events
        for te in inc.threat_events:
            fam = cls._map_event_type_to_family(te.event_type)
            signals.append({
                "signal_type": f"INCIDENT_EVENT_{te.event_type.upper()}",
                "source_type": "THREAT_EVENT",
                "detector_id": "incident_pipeline",
                "evidence_family": fam,
                "semantics": SignalSemantics.THREAT_SCORE,
                "direction": SignalDirection.SUPPORTING,
                "raw_score": te.risk_score or 40.0,
                "reliability": te.confidence or 0.80,
                "correlation_group": f"EVENT:{te.id}",
                "evidence_refs": [te.id],
            })

        ctx = dict(context_metadata or {})
        ctx["incident_id"] = incident_id
        ctx["incident_severity"] = inc.severity

        # Check attack paths
        if inc.attack_paths:
            top_path = max(inc.attack_paths, key=lambda p: p.confidence)
            ctx["attack_path_confidence"] = top_path.confidence
            ctx["attack_stage_count"] = len(top_path.stages)

        eval_result = cls.evaluate_signals(signals, ctx, cfg)

        now = get_utc_now()
        assessment = RiskAssessmentModel(
            id=generate_uuid(),
            workspace_id=workspace_id,
            scope_type=RiskScope.INCIDENT.value,
            scope_id=incident_id,
            incident_id=incident_id,
            risk_score=eval_result["risk_score"],
            risk_level=eval_result["risk_level"].value,
            severity=eval_result["severity"].value,
            confidence=eval_result["confidence"],
            confidence_level=eval_result["confidence_level"].value,
            uncertainty=eval_result["uncertainty"].value,
            uncertainty_score=eval_result["uncertainty_score"],
            version=1,
            status="CURRENT",
            aggregation_version=eval_result["aggregation_version"],
            configuration_version=eval_result["configuration_version"],
            components_json=json.dumps([c.model_dump() for c in eval_result["components"]]),
            signals_json=json.dumps(eval_result["normalized_signals"]),
            evidence_refs_json=json.dumps(eval_result["evidence_refs"]),
            counter_evidence_refs_json=json.dumps(eval_result["counter_evidence_refs"]),
            contradictions_json=json.dumps([c.model_dump() for c in eval_result["contradictions"]]),
            limitations_json=json.dumps(eval_result["limitations"]),
            contextual_factors_json=json.dumps(eval_result["contextual_factors"]),
            explanation_summary=eval_result["explanation_summary"],
            created_by="system",
            created_at=now,
            evaluated_at=now,
        )
        db.add(assessment)

        # Update IncidentModel
        inc.risk_score = assessment.risk_score
        inc.severity = assessment.severity
        inc.confidence = assessment.confidence
        inc.updated_at = now

        db.commit()
        db.refresh(assessment)
        return assessment

    @classmethod
    def reassess_assessment(
        cls,
        db: Session,
        assessment_id: str,
        workspace_id: str,
        request: RiskReassessRequest,
    ) -> RiskAssessmentModel:
        """
        Executes deterministic reassessment with new evidence.
        Preserves immutability: marks prior version as SUPERSEDED and creates incremented version v(N+1).
        """
        prior = db.query(RiskAssessmentModel).filter(
            RiskAssessmentModel.workspace_id == workspace_id,
            RiskAssessmentModel.id == assessment_id,
        ).first()
        if not prior:
            raise ValueError(f"RiskAssessment '{assessment_id}' not found.")

        cfg = RiskConfigurationManager.load_active_config(db, workspace_id)

        # Reconstruct signals from prior raw_signals + additional_signals
        existing_signals = prior.raw_signals
        new_signals = [s.model_dump() for s in request.additional_signals]
        combined = existing_signals + new_signals

        ctx = dict(prior.contextual_factors)
        ctx.update(request.context_metadata)

        eval_result = cls.evaluate_signals(combined, ctx, cfg)

        now = get_utc_now()
        # Mark prior as SUPERSEDED
        prior.status = "SUPERSEDED"

        new_version = prior.version + 1
        reassessed = RiskAssessmentModel(
            id=generate_uuid(),
            workspace_id=workspace_id,
            scope_type=prior.scope_type,
            scope_id=prior.scope_id,
            threat_event_id=prior.threat_event_id,
            investigation_id=prior.investigation_id,
            incident_id=prior.incident_id,
            analysis_run_id=prior.analysis_run_id,
            risk_score=eval_result["risk_score"],
            risk_level=eval_result["risk_level"].value,
            severity=eval_result["severity"].value,
            confidence=eval_result["confidence"],
            confidence_level=eval_result["confidence_level"].value,
            uncertainty=eval_result["uncertainty"].value,
            uncertainty_score=eval_result["uncertainty_score"],
            version=new_version,
            status="CURRENT",
            parent_assessment_id=prior.id,
            aggregation_version=eval_result["aggregation_version"],
            configuration_version=eval_result["configuration_version"],
            components_json=json.dumps([c.model_dump() for c in eval_result["components"]]),
            signals_json=json.dumps(eval_result["normalized_signals"]),
            evidence_refs_json=json.dumps(eval_result["evidence_refs"]),
            counter_evidence_refs_json=json.dumps(eval_result["counter_evidence_refs"]),
            contradictions_json=json.dumps([c.model_dump() for c in eval_result["contradictions"]]),
            limitations_json=json.dumps(eval_result["limitations"]),
            contextual_factors_json=json.dumps(eval_result["contextual_factors"]),
            explanation_summary=eval_result["explanation_summary"],
            created_by="analyst_reassessment",
            reassessment_reason=request.reassessment_reason,
            created_at=now,
            evaluated_at=now,
        )
        db.add(reassessed)
        db.flush()

        # Update ThreatEvent if linked
        if prior.threat_event_id:
            te = db.query(ThreatEventModel).filter(ThreatEventModel.id == prior.threat_event_id).first()
            if te:
                te.risk_assessment_id = reassessed.id
                te.risk_score = reassessed.risk_score
                te.severity = reassessed.severity
                te.confidence = reassessed.confidence
                te.updated_at = now

        db.commit()
        db.refresh(reassessed)
        return reassessed

    @classmethod
    def get_assessment_history(
        cls,
        db: Session,
        assessment_id: str,
        workspace_id: str,
    ) -> List[RiskAssessmentModel]:
        """Traverses version lineage backwards and forwards to return complete history."""
        target = db.query(RiskAssessmentModel).filter(
            RiskAssessmentModel.workspace_id == workspace_id,
            RiskAssessmentModel.id == assessment_id
        ).first()
        if not target:
            raise ValueError(f"RiskAssessment '{assessment_id}' not found.")

        # Find all assessments sharing the same scope_id and scope_type
        all_versions = db.query(RiskAssessmentModel).filter(
            RiskAssessmentModel.workspace_id == workspace_id,
            RiskAssessmentModel.scope_type == target.scope_type,
            RiskAssessmentModel.scope_id == target.scope_id
        ).order_by(RiskAssessmentModel.version.asc()).all()

        return all_versions

    @classmethod
    def get_dashboard_stats(
        cls,
        db: Session,
        workspace_id: str = "default",
    ) -> RiskDashboardStats:
        """Retrieves aggregated risk statistics across active assessments."""
        assessments = db.query(RiskAssessmentModel).filter(
            RiskAssessmentModel.workspace_id == workspace_id,
            RiskAssessmentModel.status == "CURRENT"
        ).all()

        total = len(assessments)
        levels: Dict[str, int] = {"INFO": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        sevs: Dict[str, int] = {"INFO": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        scopes: Dict[str, int] = {}
        high_unc = 0

        score_sum = 0.0
        conf_sum = 0.0

        for a in assessments:
            levels[a.risk_level] = levels.get(a.risk_level, 0) + 1
            sevs[a.severity] = sevs.get(a.severity, 0) + 1
            scopes[a.scope_type] = scopes.get(a.scope_type, 0) + 1
            score_sum += a.risk_score
            conf_sum += a.confidence
            if a.uncertainty == "HIGH":
                high_unc += 1

        avg_score = round(score_sum / total, 2) if total > 0 else 0.0
        avg_conf = round(conf_sum / total, 3) if total > 0 else 1.0

        return RiskDashboardStats(
            workspace_id=workspace_id,
            total_assessments=total,
            level_counts=levels,
            severity_counts=sevs,
            average_risk_score=avg_score,
            average_confidence=avg_conf,
            scope_counts=scopes,
            high_uncertainty_count=high_unc,
        )

    # ------------------------------------------------------------------------
    # Internal Helpers
    # ------------------------------------------------------------------------

    @staticmethod
    def _map_event_type_to_family(event_type: str) -> EvidenceFamily:
        et = event_type.lower()
        if "url" in et or "link" in et:
            return EvidenceFamily.URL
        if "auth" in et or "login" in et or "password" in et or "spray" in et:
            return EvidenceFamily.AUTHENTICATION
        if "file" in et or "attachment" in et or "malware" in et or "macro" in et:
            return EvidenceFamily.FILE
        if "network" in et or "c2" in et or "dns" in et or "beacon" in et:
            return EvidenceFamily.NETWORK
        if "api" in et or "token" in et:
            return EvidenceFamily.API
        if "imperson" in et or "identity" in et:
            return EvidenceFamily.IDENTITY
        if "media" in et or "deepfake" in et or "audio" in et or "video" in et:
            return EvidenceFamily.MULTIMEDIA
        if "phish" in et or "email" in et:
            return EvidenceFamily.CONTENT
        return EvidenceFamily.RULE_DETECTION

    @staticmethod
    def _map_finding_to_family(finding_type: str, analyzer: str) -> EvidenceFamily:
        combined = f"{finding_type} {analyzer}".lower()
        if "url" in combined or "domain" in combined:
            return EvidenceFamily.URL
        if "auth" in combined or "credential" in combined:
            return EvidenceFamily.AUTHENTICATION
        if "attachment" in combined or "file" in combined:
            return EvidenceFamily.FILE
        if "network" in combined:
            return EvidenceFamily.NETWORK
        if "api" in combined:
            return EvidenceFamily.API
        if "imperson" in combined:
            return EvidenceFamily.IDENTITY
        if "media" in combined or "deepfake" in combined:
            return EvidenceFamily.MULTIMEDIA
        return EvidenceFamily.CONTENT
