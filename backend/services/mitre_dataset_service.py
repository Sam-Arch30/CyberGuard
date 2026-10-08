"""
Deterministic MITRE ATT&CK Dataset Service (Section 19).
Provides fast, offline, locally-validated access to the canonical ATT&CK Enterprise Matrix dataset.

CORE PRINCIPLES:
- Deterministic, versioned, local storage (backend/data/mitre_attack_enterprise_v15_1.json).
- Zero external web lookups per event/analysis. Never download arbitrary files at runtime.
- Strict startup validation of technique IDs, tactics, parent-child relationships, and deprecation flags.
- Fail safely with actionable errors if dataset is malformed.
"""
from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from backend.schemas.mitre_attack import AttackTactic, AttackTechnique

logger = logging.getLogger("cyberguard.mitre.dataset")

DEFAULT_DATASET_PATH = Path(__file__).resolve().parent.parent / "data" / "mitre_attack_enterprise_v15_1.json"


class MitreDatasetValidationError(ValueError):
    """Raised when an ATT&CK dataset fails structural, relationship, or version integrity validation."""
    pass


class MitreDatasetService:
    """
    In-memory indexed provider for MITRE ATT&CK tactics, techniques, and sub-techniques.
    """

    def __init__(self, dataset_path: Optional[Path] = None):
        self.dataset_path = dataset_path or DEFAULT_DATASET_PATH
        self.attack_version: str = "v15.1"
        self.matrix: str = "Enterprise ATT&CK"
        self._tactics: Dict[str, AttackTactic] = {}
        self._techniques: Dict[str, AttackTechnique] = {}
        self._subtechniques_by_parent: Dict[str, List[str]] = {}
        self._load_and_validate()

    def _load_and_validate(self) -> None:
        """
        Loads the JSON dataset from disk, executes comprehensive integrity checks,
        and builds memory-efficient lookup indexes.
        """
        if not self.dataset_path.exists():
            raise MitreDatasetValidationError(f"ATT&CK dataset file not found: {self.dataset_path}")

        try:
            with open(self.dataset_path, "r", encoding="utf-8") as f:
                raw_data = json.load(f)
        except Exception as exc:
            raise MitreDatasetValidationError(f"Failed to parse ATT&CK JSON dataset: {exc}")

        self.validate_dataset_structure(raw_data)

        self.attack_version = raw_data.get("attack_version", "v15.1")
        self.matrix = raw_data.get("matrix", "Enterprise ATT&CK")

        # Load tactics
        self._tactics.clear()
        for t_dict in raw_data.get("tactics", []):
            tactic = AttackTactic(**t_dict)
            self._tactics[tactic.tactic_id] = tactic

        # Load techniques and sub-techniques
        self._techniques.clear()
        self._subtechniques_by_parent.clear()
        for tech_dict in raw_data.get("techniques", []):
            tech = AttackTechnique(**tech_dict)
            self._techniques[tech.technique_id] = tech
            if tech.parent_technique_id:
                if tech.parent_technique_id not in self._subtechniques_by_parent:
                    self._subtechniques_by_parent[tech.parent_technique_id] = []
                self._subtechniques_by_parent[tech.parent_technique_id].append(tech.technique_id)

        # Validate tactic references and parent-child consistency
        for tech_id, tech in self._techniques.items():
            for tac_id in tech.tactic_ids:
                if tac_id not in self._tactics:
                    raise MitreDatasetValidationError(
                        f"Technique {tech_id} references nonexistent tactic {tac_id}"
                    )
            if tech.is_subtechnique:
                if not tech.parent_technique_id:
                    raise MitreDatasetValidationError(
                        f"Sub-technique {tech_id} is missing required parent_technique_id"
                    )
                if tech.parent_technique_id not in self._techniques:
                    raise MitreDatasetValidationError(
                        f"Sub-technique {tech_id} references unknown parent {tech.parent_technique_id}"
                    )
                parent = self._techniques[tech.parent_technique_id]
                if parent.is_subtechnique:
                    raise MitreDatasetValidationError(
                        f"Parent technique {parent.technique_id} cannot itself be a sub-technique"
                    )

        logger.info(
            f"Successfully loaded and validated MITRE ATT&CK {self.matrix} {self.attack_version}: "
            f"{len(self._tactics)} tactics, {len(self._techniques)} techniques/sub-techniques."
        )

    @classmethod
    def validate_dataset_structure(cls, raw_data: dict) -> None:
        """
        Validates raw dictionary structure against ATT&CK schema constraints.
        Fails safely if malformed.
        """
        if not isinstance(raw_data, dict):
            raise MitreDatasetValidationError("Dataset root must be a dictionary.")

        if "attack_version" not in raw_data or not raw_data["attack_version"]:
            raise MitreDatasetValidationError("Dataset missing required 'attack_version' string.")

        if "tactics" not in raw_data or not isinstance(raw_data["tactics"], list):
            raise MitreDatasetValidationError("Dataset missing required 'tactics' list.")

        if "techniques" not in raw_data or not isinstance(raw_data["techniques"], list):
            raise MitreDatasetValidationError("Dataset missing required 'techniques' list.")

        tactic_id_pattern = re.compile(r"^TA\d{4}$")
        for idx, tac in enumerate(raw_data["tactics"]):
            tid = tac.get("tactic_id", "")
            if not tactic_id_pattern.match(tid):
                raise MitreDatasetValidationError(f"Invalid tactic_id format at index {idx}: '{tid}'. Expected TA####.")

        tech_id_pattern = re.compile(r"^T\d{4}(\.\d{3})?$")
        for idx, tech in enumerate(raw_data["techniques"]):
            tid = tech.get("technique_id", "")
            if not tech_id_pattern.match(tid):
                raise MitreDatasetValidationError(
                    f"Invalid technique_id format at index {idx}: '{tid}'. Expected T#### or T####.###."
                )

    # ------------------------------------------------------------------------
    # QUERY METHODS
    # ------------------------------------------------------------------------

    def get_attack_version(self) -> str:
        """Returns the active dataset version (e.g. 'v15.1')."""
        return self.attack_version

    def get_technique(self, technique_id: str) -> Optional[AttackTechnique]:
        """Looks up a technique or sub-technique by exact ID (case-insensitive)."""
        clean_id = technique_id.strip().upper()
        return self._techniques.get(clean_id)

    def get_tactic(self, tactic_id: str) -> Optional[AttackTactic]:
        """Looks up a tactic by ID (e.g. TA0001)."""
        clean_id = tactic_id.strip().upper()
        return self._tactics.get(clean_id)

    def get_tactic_by_name(self, name: str) -> Optional[AttackTactic]:
        """Looks up a tactic by name (case-insensitive, e.g. 'Initial Access')."""
        clean_name = name.strip().lower()
        for tac in self._tactics.values():
            if tac.name.lower() == clean_name or tac.short_name.lower() == clean_name:
                return tac
        return None

    def list_tactics(self) -> List[AttackTactic]:
        """Returns all tactics ordered chronologically by matrix order."""
        return sorted(list(self._tactics.values()), key=lambda t: t.order)

    def list_techniques(
        self,
        tactic_id: Optional[str] = None,
        include_deprecated: bool = False,
        subtechniques_only: bool = False
    ) -> List[AttackTechnique]:
        """Returns techniques matching criteria."""
        results = []
        target_tactic = tactic_id.strip().upper() if tactic_id else None

        for tech in self._techniques.values():
            if not include_deprecated and (tech.is_deprecated or tech.is_revoked):
                continue
            if subtechniques_only and not tech.is_subtechnique:
                continue
            if target_tactic and target_tactic not in tech.tactic_ids:
                continue
            results.append(tech)

        return sorted(results, key=lambda t: t.technique_id)

    def get_subtechniques(self, parent_technique_id: str) -> List[AttackTechnique]:
        """Returns all sub-techniques for a parent technique."""
        clean_parent = parent_technique_id.strip().upper()
        sub_ids = self._subtechniques_by_parent.get(clean_parent, [])
        return [self._techniques[sid] for sid in sub_ids if sid in self._techniques]

    def get_parent_technique(self, subtechnique_id: str) -> Optional[AttackTechnique]:
        """Returns the parent technique for a given sub-technique."""
        tech = self.get_technique(subtechnique_id)
        if tech and tech.parent_technique_id:
            return self.get_technique(tech.parent_technique_id)
        return None

    def is_technique_valid(self, technique_id: str) -> bool:
        """True if technique exists in the dataset."""
        return technique_id.strip().upper() in self._techniques

    def is_technique_deprecated(self, technique_id: str) -> bool:
        """True if technique exists and is marked deprecated."""
        tech = self.get_technique(technique_id)
        return bool(tech and tech.is_deprecated)

    def is_technique_revoked(self, technique_id: str) -> Tuple[bool, Optional[str]]:
        """Returns (is_revoked, revoked_by_technique_id)."""
        tech = self.get_technique(technique_id)
        if tech and tech.is_revoked:
            return True, tech.revoked_by
        return False, None


# Global singleton instance loaded once
global_mitre_dataset_service = MitreDatasetService()
