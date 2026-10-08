"""
Baseline Poisoning & Contamination Guard (Section 21).

Filters out confirmed malicious, quarantined, and high-confidence anomalous
events from historical baseline calculations to prevent baseline poisoning attacks.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Set
from sqlalchemy.orm import Session

from backend.db.models import FindingModel, ThreatEventModel, ArtifactModel
from backend.schemas.behavioral_baseline import ExclusionCategory


class BaselinePoisoningGuard:
    """
    Guards baseline datasets from adversary poisoning and contamination.
    """

    EXCLUSION_RULE_PREFIXES = [
        "ATTACK_", "EXPLOIT_", "MALWARE_", "ATO_", "CREDENTIAL_THEFT_",
        "PHISHING_", "BRUTE_FORCE_", "PASSWORD_SPRAY_", "DATA_EXFILTRATION_"
    ]

    @classmethod
    def is_event_contaminated(
        cls,
        event: Any,
        finding_ids: Optional[List[str]] = None,
        threat_event_ids: Optional[List[str]] = None,
        session: Optional[Session] = None,
    ) -> Tuple[bool, Optional[ExclusionCategory], str]:
        """
        Determines whether a candidate telemetry event should be excluded from baseline calculation.
        Returns (is_contaminated: bool, category, reason).
        """
        # 1. Direct event attributes or observation context check
        ctx = getattr(event, "context", {}) if not isinstance(event, dict) else event
        if ctx.get("is_malicious") is True or getattr(event, "is_malicious", False) is True:
            return True, ExclusionCategory.CONFIRMED_MALICIOUS, "Event explicitly marked malicious"
        if ctx.get("quarantined") is True or getattr(event, "quarantined", False) is True:
            return True, ExclusionCategory.QUARANTINED_ACTIVITY, "Event quarantined"
        if ctx.get("threat_level") in ("HIGH", "CRITICAL") or getattr(event, "threat_level", None) in ("HIGH", "CRITICAL"):
            return True, ExclusionCategory.HIGH_CONFIDENCE_ANOMALY, "Event tagged with critical threat level"

        # 2. Check associated threat event IDs
        if threat_event_ids:
            return True, ExclusionCategory.KNOWN_ATTACK_ACTIVITY, f"Event linked to active threat event(s): {threat_event_ids[:2]}"

        # 3. Check finding IDs
        if finding_ids and session:
            try:
                findings = session.query(FindingModel).filter(FindingModel.id.in_(finding_ids)).all()
                for f in findings:
                    if f.severity in ("HIGH", "CRITICAL"):
                        return True, ExclusionCategory.HIGH_CONFIDENCE_ANOMALY, f"Event generated {f.severity} finding '{f.title}'"
                    if any(f.rule_id.startswith(p) for p in cls.EXCLUSION_RULE_PREFIXES if f.rule_id):
                        return True, ExclusionCategory.KNOWN_ATTACK_ACTIVITY, f"Event matched attack rule '{f.rule_id}'"
            except Exception:
                pass

        # 4. Check if event is linked to quarantined artifact
        artifact_id = getattr(event, "source_artifact_id", None) or (
            event.get("source_artifact_id") if isinstance(event, dict) else None
        )
        if artifact_id and session:
            try:
                art = session.query(ArtifactModel).filter(ArtifactModel.id == artifact_id).first()
                if art and getattr(art, "is_quarantined", False):
                    return True, ExclusionCategory.QUARANTINED_ACTIVITY, f"Artifact '{artifact_id}' is quarantined"
            except Exception:
                pass

        return False, None, ""

    @classmethod
    def filter_clean_observations(
        cls,
        observations: List[Any],
        session: Optional[Session] = None,
    ) -> Tuple[List[Any], List[Dict[str, Any]]]:
        """
        Filters a list of observations, dropping contaminated ones.
        Returns (clean_observations, rejected_observations_audit).
        """
        clean: List[Any] = []
        rejected: List[Dict[str, Any]] = []

        for obs in observations:
            event_id = getattr(obs, "event_id", "unknown")
            is_bad, category, reason = cls.is_event_contaminated(
                event=obs,
                session=session,
            )
            if is_bad:
                rejected.append({
                    "event_id": event_id,
                    "category": category.value if category else "UNKNOWN",
                    "reason": reason,
                })
            else:
                clean.append(obs)

        return clean, rejected
