"""
Section 61: Unified Entity Resolution Service.
Provides centralized, deterministic entity resolution across all CyberGuard telemetry,
persisting complete provenance, preserving ambiguity without destructive auto-merging,
and integrating with the Security Knowledge Graph.
"""
from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Union

from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, desc

from backend.db.models import (
    EntityModel,
    EntityResolutionRecordModel,
    generate_uuid,
    get_utc_now,
)
from backend.schemas.cross_source_correlation import (
    ResolutionMethodEnum,
    ResolutionStatusEnum,
    EntityResolutionRequest,
    EntityResolutionResult,
)
from backend.schemas.knowledge_graph import (
    GraphEntityType,
    make_canonical_key,
    sanitize_graph_attributes,
)
from backend.schemas.unified import (
    normalize_domain,
    normalize_email_address,
    normalize_hash,
    normalize_ip,
    normalize_url,
)
from backend.services.security_graph_service import SecurityGraphService

logger = logging.getLogger("cyberguard.entity_resolver")


class UnifiedEntityResolver:
    """
    Centralized, deterministic entity resolution engine for CyberGuard.
    Enforces preferred identity hierarchy:
    1. Stable Internal Entity ID
    2. Canonical External Identifier
    3. Normalized Identifier (IP/Domain/URL/Email/Hash)
    4. Deterministic Composite Key
    5. Controlled Fuzzy / Ambiguity Detection (never auto-merge ambiguous entities)
    """

    SUPPORTED_ENTITY_TYPES = {
        "USER",
        "ACCOUNT",
        "DEVICE",
        "ENDPOINT",
        "IP",
        "DOMAIN",
        "URL",
        "EMAIL",
        "EMAIL_ADDRESS",
        "HASH",
        "FILE",
        "PROCESS",
        "SESSION",
        "API_CLIENT",
        "IDENTITY",
        "INCIDENT",
        "CAMPAIGN",
    }

    @classmethod
    def normalize_entity_identifier(
        cls,
        entity_type: str,
        raw_identifier: str
    ) -> str:
        """
        Normalizes raw telemetry identifier based on entity type.
        """
        type_upper = (entity_type or "").strip().upper()
        raw = (raw_identifier or "").strip()

        if not raw:
            return ""

        try:
            if type_upper in ("IP", "IP_ADDRESS"):
                return normalize_ip(raw)
            elif type_upper == "DOMAIN":
                return normalize_domain(raw)
            elif type_upper == "URL":
                return normalize_url(raw)
            elif type_upper in ("EMAIL", "EMAIL_ADDRESS"):
                return normalize_email_address(raw)
            elif type_upper in ("HASH", "FILE"):
                if len(raw) in (32, 40, 64) and re.match(r"^[0-9a-fA-F]+$", raw):
                    return normalize_hash(raw)
                return raw.lower()
            elif type_upper in ("USER", "ACCOUNT", "IDENTITY"):
                return raw.lower()
            elif type_upper in ("ENDPOINT", "DEVICE"):
                # Clean hostnames or UUIDs, preserve case if UUID, lower if hostname
                if re.match(r"^[0-9a-fA-F-]{36}$", raw):
                    return raw.lower()
                return raw.strip().lower()
            elif type_upper in ("PROCESS", "API_CLIENT"):
                return raw.lower()
            return raw
        except Exception as e:
            logger.debug(f"Normalization fallback for {entity_type} '{raw}': {e}")
            return raw.strip()

    @classmethod
    def resolve_entity(
        cls,
        db: Session,
        entity_type: str,
        raw_identifier: str,
        workspace_id: str = "default",
        context: Optional[str] = None,
        allow_fuzzy: bool = False,
    ) -> EntityResolutionResult:
        """
        Deterministically resolves a raw identifier to an authoritative Knowledge Graph Entity.
        Preserves resolution provenance and audit trails in EntityResolutionRecordModel.
        """
        type_upper = (entity_type or "OTHER").strip().upper()
        if type_upper == "IP_ADDRESS":
            type_upper = "IP"
        elif type_upper == "EMAIL_ADDRESS":
            type_upper = "EMAIL"
        elif type_upper == "HOST":
            type_upper = "ENDPOINT"

        raw = (raw_identifier or "").strip()
        if not raw:
            return EntityResolutionResult(
                entity_type=type_upper,
                raw_identifier="",
                normalized_identifier="",
                canonical_entity_id=None,
                canonical_key=None,
                display_name="Unknown",
                resolution_method=ResolutionMethodEnum.UNRESOLVED,
                resolution_confidence=0.0,
                status=ResolutionStatusEnum.UNRESOLVED,
                matched_attributes={"error": "Empty identifier provided"},
                provenance={"reason": "Empty raw identifier"},
            )

        norm_val = cls.normalize_entity_identifier(type_upper, raw)
        canon_key = make_canonical_key(type_upper, norm_val, context=context)

        # ---------------------------------------------------------------------
        # Strategy 1: Stable Internal Entity ID Match
        # ---------------------------------------------------------------------
        if re.match(r"^[0-9a-fA-F-]{36}$", raw):
            entity_by_id = db.query(EntityModel).filter(
                EntityModel.id == raw,
                or_(EntityModel.workspace_id == workspace_id, EntityModel.workspace_id.is_(None))
            ).first()
            if entity_by_id:
                res = EntityResolutionResult(
                    entity_type=entity_by_id.entity_type,
                    raw_identifier=raw,
                    normalized_identifier=norm_val,
                    canonical_entity_id=entity_by_id.id,
                    canonical_key=entity_by_id.canonical_key or canon_key,
                    display_name=entity_by_id.name,
                    resolution_method=ResolutionMethodEnum.EXACT_ID,
                    resolution_confidence=1.0,
                    status=ResolutionStatusEnum.RESOLVED,
                    matched_attributes={"matched_field": "id", "entity_id": entity_by_id.id},
                    provenance={
                        "rule": "STABLE_INTERNAL_ENTITY_ID",
                        "timestamp": get_utc_now().isoformat(),
                    },
                )
                cls._persist_resolution_record(db, workspace_id, res)
                return res

        # ---------------------------------------------------------------------
        # Strategy 2: Canonical External Identifier Match
        # ---------------------------------------------------------------------
        if context:
            entity_by_ext = db.query(EntityModel).filter(
                EntityModel.entity_type == type_upper,
                EntityModel.external_id == context,
                or_(EntityModel.workspace_id == workspace_id, EntityModel.workspace_id.is_(None))
            ).first()
            if entity_by_ext:
                res = EntityResolutionResult(
                    entity_type=entity_by_ext.entity_type,
                    raw_identifier=raw,
                    normalized_identifier=norm_val,
                    canonical_entity_id=entity_by_ext.id,
                    canonical_key=entity_by_ext.canonical_key or canon_key,
                    display_name=entity_by_ext.name,
                    resolution_method=ResolutionMethodEnum.EXACT_ID,
                    resolution_confidence=1.0,
                    status=ResolutionStatusEnum.RESOLVED,
                    matched_attributes={"matched_field": "external_id", "external_id": context},
                    provenance={
                        "rule": "CANONICAL_EXTERNAL_IDENTIFIER",
                        "timestamp": get_utc_now().isoformat(),
                    },
                )
                cls._persist_resolution_record(db, workspace_id, res)
                return res

        # ---------------------------------------------------------------------
        # Strategy 3: Canonical Key Match in Knowledge Graph
        # ---------------------------------------------------------------------
        entity_by_key = db.query(EntityModel).filter(
            EntityModel.entity_type == type_upper,
            EntityModel.canonical_key == canon_key,
            or_(EntityModel.workspace_id == workspace_id, EntityModel.workspace_id.is_(None))
        ).first()

        if entity_by_key:
            res = EntityResolutionResult(
                entity_type=entity_by_key.entity_type,
                raw_identifier=raw,
                normalized_identifier=norm_val,
                canonical_entity_id=entity_by_key.id,
                canonical_key=entity_by_key.canonical_key,
                display_name=entity_by_key.name,
                resolution_method=ResolutionMethodEnum.CANONICAL_NORMALIZATION,
                resolution_confidence=1.0,
                status=ResolutionStatusEnum.RESOLVED,
                matched_attributes={"matched_field": "canonical_key", "canonical_key": canon_key},
                provenance={
                    "rule": "CANONICAL_NORMALIZATION_LOOKUP",
                    "timestamp": get_utc_now().isoformat(),
                },
            )
            cls._persist_resolution_record(db, workspace_id, res)
            return res

        # ---------------------------------------------------------------------
        # Strategy 4: Fuzzy / Ambiguity Detection
        # ---------------------------------------------------------------------
        if allow_fuzzy:
            # Check for multiple possible candidate entities with similar names
            candidates = db.query(EntityModel).filter(
                EntityModel.entity_type == type_upper,
                EntityModel.name.ilike(f"%{norm_val}%"),
                or_(EntityModel.workspace_id == workspace_id, EntityModel.workspace_id.is_(None))
            ).limit(5).all()

            if len(candidates) > 1:
                # Ambiguous collision: do NOT merge silently!
                res = EntityResolutionResult(
                    entity_type=type_upper,
                    raw_identifier=raw,
                    normalized_identifier=norm_val,
                    canonical_entity_id=None,
                    canonical_key=canon_key,
                    display_name=norm_val,
                    resolution_method=ResolutionMethodEnum.FUZZY_MATCH,
                    resolution_confidence=0.50,
                    status=ResolutionStatusEnum.AMBIGUOUS,
                    matched_attributes={
                        "candidate_ids": [c.id for c in candidates],
                        "candidate_names": [c.name for c in candidates],
                        "candidate_count": len(candidates),
                    },
                    provenance={
                        "rule": "AMBIGUOUS_MULTIPLE_CANDIDATES",
                        "caveat": "Ambiguity preserved; entities are NOT automatically merged",
                        "timestamp": get_utc_now().isoformat(),
                    },
                )
                cls._persist_resolution_record(db, workspace_id, res)
                return res
            elif len(candidates) == 1:
                candidate = candidates[0]
                res = EntityResolutionResult(
                    entity_type=candidate.entity_type,
                    raw_identifier=raw,
                    normalized_identifier=norm_val,
                    canonical_entity_id=candidate.id,
                    canonical_key=candidate.canonical_key or canon_key,
                    display_name=candidate.name,
                    resolution_method=ResolutionMethodEnum.FUZZY_MATCH,
                    resolution_confidence=0.85,
                    status=ResolutionStatusEnum.RESOLVED,
                    matched_attributes={"matched_candidate_id": candidate.id, "fuzzy_match": True},
                    provenance={
                        "rule": "SINGLE_CANDIDATE_FUZZY_MATCH",
                        "timestamp": get_utc_now().isoformat(),
                    },
                )
                cls._persist_resolution_record(db, workspace_id, res)
                return res

        # ---------------------------------------------------------------------
        # Strategy 5: Authoritative Knowledge Graph Registration
        # ---------------------------------------------------------------------
        # Entity does not exist yet; establish it deterministically in the graph
        new_entity = SecurityGraphService().upsert_canonical_entity(
            db=db,
            entity_type=type_upper,
            value=norm_val,
            display_value=norm_val,
            context=context,
            workspace_id=workspace_id,
            timestamp=get_utc_now(),
        )

        res = EntityResolutionResult(
            entity_type=new_entity.entity_type,
            raw_identifier=raw,
            normalized_identifier=norm_val,
            canonical_entity_id=new_entity.id,
            canonical_key=new_entity.canonical_key or canon_key,
            display_name=new_entity.name,
            resolution_method=ResolutionMethodEnum.COMPOSITE_KEY,
            resolution_confidence=1.0,
            status=ResolutionStatusEnum.RESOLVED,
            matched_attributes={"new_entity_created": True, "canonical_key": canon_key},
            provenance={
                "rule": "DETERMINISTIC_COMPOSITE_KEY_REGISTRATION",
                "timestamp": get_utc_now().isoformat(),
            },
        )
        cls._persist_resolution_record(db, workspace_id, res)
        return res

    @classmethod
    def _persist_resolution_record(
        cls,
        db: Session,
        workspace_id: str,
        res: EntityResolutionResult
    ) -> None:
        """
        Persists resolution provenance record in EntityResolutionRecordModel.
        """
        try:
            record = EntityResolutionRecordModel(
                id=generate_uuid(),
                workspace_id=workspace_id,
                entity_type=res.entity_type,
                canonical_entity_id=res.canonical_entity_id or f"unresolved:{res.normalized_identifier}",
                raw_identifier=res.raw_identifier,
                normalized_identifier=res.normalized_identifier,
                resolution_method=res.resolution_method.value,
                resolution_confidence=res.resolution_confidence,
                status=res.status.value,
                matched_attributes_json=json.dumps(res.matched_attributes),
                provenance_json=json.dumps(res.provenance),
                created_at=get_utc_now(),
            )
            db.add(record)
            db.flush()
        except Exception as e:
            logger.warning(f"Failed to persist entity resolution record: {e}")

    @classmethod
    def batch_resolve_entities(
        cls,
        db: Session,
        requests: List[EntityResolutionRequest],
        workspace_id: str = "default",
    ) -> List[EntityResolutionResult]:
        """
        Batch-resolves a list of entity resolution requests.
        """
        results: List[EntityResolutionResult] = []
        for req in requests:
            target_ws = req.workspace_id or workspace_id
            res = cls.resolve_entity(
                db=db,
                entity_type=req.entity_type,
                raw_identifier=req.raw_identifier,
                workspace_id=target_ws,
                context=req.context,
                allow_fuzzy=req.allow_fuzzy,
            )
            results.append(res)
        return results

    @classmethod
    def get_resolution_history(
        cls,
        db: Session,
        workspace_id: str = "default",
        entity_type: Optional[str] = None,
        canonical_entity_id: Optional[str] = None,
        limit: int = 50,
    ) -> List[EntityResolutionRecordModel]:
        """
        Queries immutable resolution history for auditability and verification.
        """
        q = db.query(EntityResolutionRecordModel).filter(
            EntityResolutionRecordModel.workspace_id == workspace_id
        )
        if entity_type:
            q = q.filter(EntityResolutionRecordModel.entity_type == entity_type.upper())
        if canonical_entity_id:
            q = q.filter(EntityResolutionRecordModel.canonical_entity_id == canonical_entity_id)

        return q.order_by(desc(EntityResolutionRecordModel.created_at)).limit(limit).all()
