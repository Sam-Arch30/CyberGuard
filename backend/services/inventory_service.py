"""
Section 63: Asset & Identity Inventory Service.
Authoritative management of enterprise assets, identities, source precedence,
provenance, attribute conflicts, and reconciliation.
"""

import json
import logging
import re
import time
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session
from sqlalchemy import or_, and_, desc

from backend.db.models import (
    AssetModel,
    ExposureModel,
    AssetServiceModel,
    IdentityModel,
    InventorySourceModel,
    InventoryConflictModel,
    InventoryOverrideModel,
    DeviceModel,
    EndpointAgentModel,
    ProtectedIdentityModel,
    IndicatorModel,
    EntityModel,
    AuditLogModel,
    get_utc_now,
)
from backend.services.unified_entity_resolver import UnifiedEntityResolver
from backend.services.attack_surface_service import AttackSurfaceService
from backend.services.security_graph_service import SecurityGraphService
from backend.schemas.inventory import (
    AssetCreate,
    AssetUpdate,
    AssetRead,
    AssetDetailRead,
    IdentityCreate,
    IdentityUpdate,
    IdentityRead,
    IdentityDetailRead,
    InventorySourceCreate,
    InventorySourceUpdate,
    InventorySourceRead,
    InventoryConflictRead,
    InventoryOverviewStats,
    InventorySyncRequest,
    InventorySyncResponse,
    InventoryReconciliationReport,
    OwnershipAssignRequest,
)

logger = logging.getLogger("cyberguard.inventory")


def _ensure_utc(dt: Optional[datetime]) -> Optional[datetime]:
    """Ensures datetime is timezone-aware in UTC for safe comparisons."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class InventoryService:
    """
    Authoritative Inventory Layer (Section 63).
    Unifies assets, identities, sources, and conflict resolution across CyberGuard.
    """

    # Deterministic Source Precedence Hierarchy (Section 10)
    DEFAULT_AUTHORITY_WEIGHTS: Dict[str, int] = {
        "CMDB": 100,
        "MANUAL_ANALYST": 90,
        "DIRECTORY": 80,
        "IDP": 80,
        "HR_SYSTEM": 75,
        "ENDPOINT_AGENT": 60,
        "CLOUD_PROVIDER": 50,
        "CLOUD_IAM": 50,
        "APPLICATION_REGISTRY": 45,
        "NETWORK_TELEMETRY": 40,
        "INTERNAL_DISCOVERY": 30,
        "INFERRED": 20,
        "UNKNOWN": 10,
    }

    # Stale and Dormancy Thresholds
    STALE_ASSET_THRESHOLD_DAYS = 30
    DORMANT_IDENTITY_THRESHOLD_DAYS = 90

    # ---------------------------------------------------------------------------
    # 1. OVERVIEW & METRICS
    # ---------------------------------------------------------------------------

    @classmethod
    def get_overview_stats(cls, db: Session, workspace_id: str = "default") -> InventoryOverviewStats:
        """Calculates aggregated inventory health, asset counts, and identity metrics."""
        cls._ensure_default_sources(db, workspace_id)

        now = datetime.now(timezone.utc)
        stale_cutoff = now - timedelta(days=cls.STALE_ASSET_THRESHOLD_DAYS)
        dormant_cutoff = now - timedelta(days=cls.DORMANT_IDENTITY_THRESHOLD_DAYS)

        # Asset metrics
        all_assets = db.query(AssetModel).filter(AssetModel.workspace_id == workspace_id).all()
        total_assets = len(all_assets)
        active_assets = sum(1 for a in all_assets if a.status == "ACTIVE")
        stale_assets = sum(
            1 for a in all_assets
            if a.status == "STALE" or a.is_stale or (_ensure_utc(a.last_seen_at) and _ensure_utc(a.last_seen_at) < stale_cutoff)
        )
        unmanaged_assets = sum(1 for a in all_assets if not a.is_managed)
        unowned_assets = sum(
            1 for a in all_assets
            if a.ownership_status in ("UNASSIGNED", "UNKNOWN") or a.owner in (None, "", "Unknown", "Unassigned")
        )

        # Identity metrics
        all_identities = db.query(IdentityModel).filter(IdentityModel.workspace_id == workspace_id).all()
        total_identities = len(all_identities)
        active_identities = sum(1 for i in all_identities if i.status == "ACTIVE")
        privileged_identities = sum(1 for i in all_identities if i.is_privileged)
        dormant_identities = sum(
            1 for i in all_identities
            if i.is_dormant or i.status == "DORMANT" or (i.last_authenticated_at and _ensure_utc(i.last_authenticated_at) < dormant_cutoff)
        )
        orphaned_identities = sum(1 for i in all_identities if i.is_orphaned)

        # Conflict & Source counts
        pending_conflicts = db.query(InventoryConflictModel).filter(
            InventoryConflictModel.workspace_id == workspace_id,
            InventoryConflictModel.status == "PENDING_REVIEW"
        ).count()
        active_sources = db.query(InventorySourceModel).filter(
            InventorySourceModel.workspace_id == workspace_id,
            InventorySourceModel.status == "ACTIVE"
        ).count()

        return InventoryOverviewStats(
            total_assets=total_assets,
            active_assets=active_assets,
            stale_assets=stale_assets,
            unmanaged_assets=unmanaged_assets,
            unowned_assets=unowned_assets,
            total_identities=total_identities,
            active_identities=active_identities,
            privileged_identities=privileged_identities,
            dormant_identities=dormant_identities,
            orphaned_identities=orphaned_identities,
            pending_conflicts=pending_conflicts,
            active_sources=active_sources,
            last_reconciliation_at=get_utc_now(),
        )

    # ---------------------------------------------------------------------------
    # 2. ASSET INVENTORY MANAGEMENT
    # ---------------------------------------------------------------------------

    @classmethod
    def list_assets(
        cls,
        db: Session,
        workspace_id: str = "default",
        asset_type: Optional[str] = None,
        status: Optional[str] = None,
        environment: Optional[str] = None,
        criticality: Optional[str] = None,
        ownership_status: Optional[str] = None,
        is_managed: Optional[bool] = None,
        is_stale: Optional[bool] = None,
        search: Optional[str] = None,
        skip: int = 0,
        limit: int = 50,
    ) -> Tuple[List[AssetRead], int]:
        """Returns paginated and filtered assets from the authoritative inventory."""
        q = db.query(AssetModel).filter(AssetModel.workspace_id == workspace_id)

        if asset_type and asset_type.upper() != "ALL":
            q = q.filter(AssetModel.asset_type == asset_type.upper())
        if status and status.upper() != "ALL":
            q = q.filter(AssetModel.status == status.upper())
        if environment and environment.upper() != "ALL":
            q = q.filter(AssetModel.environment == environment.upper())
        if criticality and criticality.upper() != "ALL":
            q = q.filter(AssetModel.criticality == criticality.upper())
        if ownership_status and ownership_status.upper() != "ALL":
            q = q.filter(AssetModel.ownership_status == ownership_status.upper())
        if is_managed is not None:
            q = q.filter(AssetModel.is_managed == is_managed)
        if is_stale is not None:
            q = q.filter(AssetModel.is_stale == is_stale)
        if search:
            s_clean = f"%{search.strip().lower()}%"
            q = q.filter(
                or_(
                    AssetModel.canonical_name.ilike(s_clean),
                    AssetModel.display_name.ilike(s_clean),
                    AssetModel.owner.ilike(s_clean),
                    AssetModel.team.ilike(s_clean),
                )
            )

        total = q.count()
        models = q.order_by(desc(AssetModel.risk_score), desc(AssetModel.last_seen_at)).offset(skip).limit(limit).all()

        results = []
        for m in models:
            item = AssetRead.model_validate(m)
            item.tags = m.tags_list
            results.append(item)

        return results, total

    @classmethod
    def get_asset_detail(
        cls,
        db: Session,
        workspace_id: str,
        asset_id: str
    ) -> Optional[AssetDetailRead]:
        """Fetches full progressive disclosure details for a single asset."""
        asset = db.query(AssetModel).filter(
            AssetModel.id == asset_id,
            AssetModel.workspace_id == workspace_id
        ).first()
        if not asset:
            return None

        # Associated exposures
        exposures_data = [
            {
                "id": exp.id,
                "exposure_type": exp.exposure_type,
                "severity": exp.severity,
                "status": exp.status,
                "remediation_guidance": exp.remediation_guidance,
                "first_detected_at": exp.first_detected_at.isoformat() if exp.first_detected_at else None,
            }
            for exp in asset.exposures
        ]

        # Associated services
        services_data = [
            {
                "id": svc.id,
                "service_name": svc.service_name,
                "port": svc.port,
                "protocol": svc.protocol,
                "is_public": svc.is_public,
                "banner": svc.banner,
            }
            for svc in asset.services
        ]

        # Associated attribute conflicts
        conflicts_data = []
        conflicts = db.query(InventoryConflictModel).filter(
            InventoryConflictModel.workspace_id == workspace_id,
            InventoryConflictModel.target_type == "ASSET",
            InventoryConflictModel.target_id == asset.id
        ).all()
        for c in conflicts:
            conflicts_data.append({
                "id": c.id,
                "field_name": c.field_name,
                "status": c.status,
                "resolved_value": c.resolved_value,
                "conflicting_values": c.conflicting_values_list,
                "resolution_reason": c.resolution_reason,
            })

        # Knowledge Graph neighbors
        graph_neighbors = []
        if asset.canonical_entity_id:
            try:
                subgraph = SecurityGraphService.get_subgraph(
                    db, asset.canonical_entity_id, max_depth=1, workspace_id=workspace_id
                )
                for node in subgraph.nodes:
                    if node.id != asset.canonical_entity_id:
                        graph_neighbors.append({
                            "id": node.id,
                            "type": node.type,
                            "name": node.display_value,
                            "canonical_key": node.canonical_key,
                        })
            except Exception as e:
                logger.debug(f"Knowledge Graph neighbor expansion failed for asset {asset.id}: {e}")

        # Audit timeline
        timeline = [
            {
                "event_type": "FIRST_SEEN",
                "title": "Asset First Observed",
                "timestamp": asset.first_seen_at.isoformat() if asset.first_seen_at else None,
                "description": f"Asset identified via {asset.source} ({asset.ownership_confidence})",
            },
            {
                "event_type": "LAST_SEEN",
                "title": "Recent Telemetry Verification",
                "timestamp": asset.last_seen_at.isoformat() if asset.last_seen_at else None,
                "description": f"Status: {asset.status}, Risk Score: {asset.risk_score:.1f}",
            }
        ]

        detail = AssetDetailRead.model_validate(asset)
        detail.tags = asset.tags_list
        detail.exposures = exposures_data
        detail.services = services_data
        detail.conflicts = conflicts_data
        detail.graph_neighbors = graph_neighbors
        detail.timeline = timeline
        return detail

    @classmethod
    def upsert_asset(
        cls,
        db: Session,
        workspace_id: str,
        payload: AssetCreate,
        source: Optional[str] = None,
        authority_weight: Optional[int] = None,
        actor: Optional[str] = None,
    ) -> Tuple[AssetModel, bool]:
        """
        Idempotently normalizes, resolves, reconciles conflicts, and stores an asset.
        Respects deterministic authority weights and manual overrides.
        """
        asset_type = payload.asset_type.strip().upper()
        norm_res = AttackSurfaceService.normalize_asset_identifier(asset_type, payload.canonical_name)
        norm_name = norm_res[0] if isinstance(norm_res, tuple) else norm_res
        default_display = norm_res[1] if isinstance(norm_res, tuple) else norm_name
        display_name = payload.display_name.strip() if payload.display_name else default_display
        src = source or payload.source or "INTERNAL_DISCOVERY"
        weight = authority_weight or cls.DEFAULT_AUTHORITY_WEIGHTS.get(src, 30)

        # 1. Resolve canonical entity in Knowledge Graph via Section 61
        resolution = UnifiedEntityResolver.resolve_entity(
            db,
            workspace_id=workspace_id,
            entity_type=asset_type,
            raw_identifier=norm_name,
            context=payload.external_id,
        )
        canonical_entity_id = resolution.canonical_entity_id

        # 2. Check for manual overrides for this asset's attributes
        overrides = {}
        existing = db.query(AssetModel).filter(
            AssetModel.workspace_id == workspace_id,
            AssetModel.asset_type == asset_type,
            AssetModel.canonical_name == norm_name,
        ).first()

        if existing:
            override_records = db.query(InventoryOverrideModel).filter(
                InventoryOverrideModel.workspace_id == workspace_id,
                InventoryOverrideModel.target_type == "ASSET",
                InventoryOverrideModel.target_id == existing.id,
                InventoryOverrideModel.is_active == True,
            ).all()
            for ov in override_records:
                overrides[ov.field_name] = ov.new_value

        now = get_utc_now()
        is_created = False

        if not existing:
            is_created = True
            owner_val = overrides.get("owner", payload.owner or "Unknown")
            team_val = overrides.get("team", payload.team or "")
            crit_val = overrides.get("criticality", payload.criticality or "MEDIUM")
            env_val = overrides.get("environment", payload.environment or "UNKNOWN")
            status_val = overrides.get("status", payload.status or "ACTIVE")

            ownership_status = "ASSIGNED" if owner_val not in ("Unknown", "Unassigned", "", None) else "UNASSIGNED"

            existing = AssetModel(
                workspace_id=workspace_id,
                asset_type=asset_type,
                canonical_name=norm_name,
                display_name=display_name,
                status=status_val,
                exposure_state=payload.exposure_state or "UNKNOWN",
                criticality=crit_val,
                owner=owner_val,
                team=team_val,
                business_unit=payload.business_unit or "",
                department=payload.department or "",
                ownership_status=ownership_status,
                classification=payload.classification,
                environment=env_val,
                ownership_confidence=payload.ownership_confidence or "UNKNOWN",
                source=src,
                external_id=payload.external_id,
                canonical_entity_id=canonical_entity_id,
                is_managed=payload.is_managed,
                is_stale=False,
                tags_json=json.dumps(payload.tags or []),
                first_seen_at=now,
                last_seen_at=now,
                last_observed_at=now,
                last_sync_at=now,
                metadata_json=json.dumps(payload.metadata or {}),
            )
            db.add(existing)
            db.flush()

        else:
            # Reconcile existing attributes against incoming source authority
            existing.last_seen_at = now
            existing.last_observed_at = now
            existing.last_sync_at = now
            if canonical_entity_id and not existing.canonical_entity_id:
                existing.canonical_entity_id = canonical_entity_id

            # Conflict Detection on Owner
            if payload.owner and payload.owner not in ("Unknown", "Unassigned") and payload.owner != existing.owner:
                cls._handle_attribute_conflict(
                    db,
                    workspace_id=workspace_id,
                    target_type="ASSET",
                    target_id=existing.id,
                    target_canonical_name=existing.canonical_name,
                    field_name="owner",
                    current_value=existing.owner or "Unknown",
                    current_source=existing.source,
                    incoming_value=payload.owner,
                    incoming_source=src,
                    incoming_weight=weight,
                    target_model=existing,
                    overridden="owner" in overrides,
                )

            # Conflict Detection on Team
            if payload.team and payload.team != existing.team:
                cls._handle_attribute_conflict(
                    db,
                    workspace_id=workspace_id,
                    target_type="ASSET",
                    target_id=existing.id,
                    target_canonical_name=existing.canonical_name,
                    field_name="team",
                    current_value=existing.team or "",
                    current_source=existing.source,
                    incoming_value=payload.team,
                    incoming_source=src,
                    incoming_weight=weight,
                    target_model=existing,
                    overridden="team" in overrides,
                )

            # Metadata merge
            merged_meta = existing.metadata_dict
            if payload.metadata:
                merged_meta.update(payload.metadata)
                existing.metadata_json = json.dumps(merged_meta)

            if payload.tags:
                curr_tags = set(existing.tags_list)
                curr_tags.update(payload.tags)
                existing.tags_json = json.dumps(list(curr_tags))

        db.commit()
        db.refresh(existing)
        return existing, is_created

    @classmethod
    def assign_asset_owner(
        cls,
        db: Session,
        workspace_id: str,
        asset_id: str,
        req: OwnershipAssignRequest,
        actor: str = "SOC Analyst",
    ) -> Optional[AssetModel]:
        """Manually assigns ownership and records an audit override."""
        asset = db.query(AssetModel).filter(
            AssetModel.id == asset_id,
            AssetModel.workspace_id == workspace_id
        ).first()
        if not asset:
            return None

        prev_owner = asset.owner
        asset.owner = req.owner
        asset.ownership_status = "ASSIGNED"
        asset.ownership_confidence = "MANUAL"
        if req.team:
            asset.team = req.team
        if req.department:
            asset.department = req.department
        if req.business_unit:
            asset.business_unit = req.business_unit
        asset.updated_at = get_utc_now()

        # Record manual override
        override = InventoryOverrideModel(
            workspace_id=workspace_id,
            target_type="ASSET",
            target_id=asset.id,
            field_name="owner",
            previous_value=prev_owner,
            new_value=req.owner,
            reason=req.reason or "Manual ownership assignment by analyst",
            actor=actor,
        )
        db.add(override)

        # Audit log entry
        audit = AuditLogModel(
            action="INVENTORY_ASSET_OWNER_ASSIGNED",
            resource_type="ASSET",
            resource_id=asset.id,
            user=actor,
            details=json.dumps({
                "canonical_name": asset.canonical_name,
                "previous_owner": prev_owner,
                "new_owner": req.owner,
                "team": req.team,
                "reason": req.reason,
            }),
        )
        db.add(audit)

        db.commit()
        db.refresh(asset)
        return asset

    # ---------------------------------------------------------------------------
    # 3. IDENTITY INVENTORY MANAGEMENT
    # ---------------------------------------------------------------------------

    @classmethod
    def list_identities(
        cls,
        db: Session,
        workspace_id: str = "default",
        identity_type: Optional[str] = None,
        status: Optional[str] = None,
        is_privileged: Optional[bool] = None,
        is_service_account: Optional[bool] = None,
        is_orphaned: Optional[bool] = None,
        is_dormant: Optional[bool] = None,
        criticality: Optional[str] = None,
        search: Optional[str] = None,
        skip: int = 0,
        limit: int = 50,
    ) -> Tuple[List[IdentityRead], int]:
        """Returns paginated and filtered identities from enterprise inventory."""
        q = db.query(IdentityModel).filter(IdentityModel.workspace_id == workspace_id)

        if identity_type and identity_type.upper() != "ALL":
            q = q.filter(IdentityModel.identity_type == identity_type.upper())
        if status and status.upper() != "ALL":
            q = q.filter(IdentityModel.status == status.upper())
        if is_privileged is not None:
            q = q.filter(IdentityModel.is_privileged == is_privileged)
        if is_service_account is not None:
            q = q.filter(IdentityModel.is_service_account == is_service_account)
        if is_orphaned is not None:
            q = q.filter(IdentityModel.is_orphaned == is_orphaned)
        if is_dormant is not None:
            q = q.filter(IdentityModel.is_dormant == is_dormant)
        if criticality and criticality.upper() != "ALL":
            q = q.filter(IdentityModel.criticality == criticality.upper())
        if search:
            s_clean = f"%{search.strip().lower()}%"
            q = q.filter(
                or_(
                    IdentityModel.canonical_identifier.ilike(s_clean),
                    IdentityModel.display_name.ilike(s_clean),
                    IdentityModel.email.ilike(s_clean),
                    IdentityModel.department.ilike(s_clean),
                )
            )

        total = q.count()
        models = q.order_by(desc(IdentityModel.is_privileged), desc(IdentityModel.last_seen_at)).offset(skip).limit(limit).all()

        results = []
        for m in models:
            item = IdentityRead.model_validate(m)
            item.tags = m.tags_list
            results.append(item)

        return results, total

    @classmethod
    def get_identity_detail(
        cls,
        db: Session,
        workspace_id: str,
        identity_id: str
    ) -> Optional[IdentityDetailRead]:
        """Fetches full details, associated devices, conflicts, and audit timeline for an identity."""
        identity = db.query(IdentityModel).filter(
            IdentityModel.id == identity_id,
            IdentityModel.workspace_id == workspace_id
        ).first()
        if not identity:
            return None

        # Associated assets (e.g. devices/laptops assigned to this user)
        associated_assets = []
        if identity.email or identity.username:
            assets = db.query(AssetModel).filter(
                AssetModel.workspace_id == workspace_id,
                or_(
                    AssetModel.owner == identity.email,
                    AssetModel.owner == identity.username,
                    AssetModel.owner == identity.display_name,
                )
            ).limit(20).all()
            for a in assets:
                associated_assets.append({
                    "id": a.id,
                    "canonical_name": a.canonical_name,
                    "display_name": a.display_name,
                    "asset_type": a.asset_type,
                    "criticality": a.criticality,
                    "status": a.status,
                })

        # Conflicts
        conflicts_data = []
        conflicts = db.query(InventoryConflictModel).filter(
            InventoryConflictModel.workspace_id == workspace_id,
            InventoryConflictModel.target_type == "IDENTITY",
            InventoryConflictModel.target_id == identity.id
        ).all()
        for c in conflicts:
            conflicts_data.append({
                "id": c.id,
                "field_name": c.field_name,
                "status": c.status,
                "resolved_value": c.resolved_value,
                "conflicting_values": c.conflicting_values_list,
                "resolution_reason": c.resolution_reason,
            })

        # Graph neighbors
        graph_neighbors = []
        if identity.canonical_entity_id:
            try:
                subgraph = SecurityGraphService.get_subgraph(
                    db, identity.canonical_entity_id, max_depth=1, workspace_id=workspace_id
                )
                for node in subgraph.nodes:
                    if node.id != identity.canonical_entity_id:
                        graph_neighbors.append({
                            "id": node.id,
                            "type": node.type,
                            "name": node.display_value,
                            "canonical_key": node.canonical_key,
                        })
            except Exception as e:
                logger.debug(f"Knowledge Graph expansion failed for identity {identity.id}: {e}")

        # Timeline
        timeline = [
            {
                "event_type": "FIRST_SEEN",
                "title": "Identity Profile Created",
                "timestamp": identity.first_seen_at.isoformat() if identity.first_seen_at else None,
                "description": f"Source: {identity.source}, Privileged: {identity.is_privileged}",
            },
            {
                "event_type": "LAST_AUTHENTICATED",
                "title": "Last Active Authentication",
                "timestamp": identity.last_authenticated_at.isoformat() if identity.last_authenticated_at else None,
                "description": "Authenticated session verified",
            } if identity.last_authenticated_at else {
                "event_type": "NO_AUTHENTICATION",
                "title": "No Recent Authentication",
                "timestamp": identity.last_seen_at.isoformat() if identity.last_seen_at else None,
                "description": "Identity observed in directory without recent interactive authentication",
            }
        ]

        detail = IdentityDetailRead.model_validate(identity)
        detail.tags = identity.tags_list
        detail.associated_assets = associated_assets
        detail.conflicts = conflicts_data
        detail.graph_neighbors = graph_neighbors
        detail.timeline = timeline
        return detail

    @classmethod
    def upsert_identity(
        cls,
        db: Session,
        workspace_id: str,
        payload: IdentityCreate,
        source: Optional[str] = None,
        authority_weight: Optional[int] = None,
    ) -> Tuple[IdentityModel, bool]:
        """
        Idempotently normalizes, resolves, and tracks an identity/account.
        Automatically flags dormant accounts, orphaned service accounts, and privileges.
        """
        canon_id = payload.canonical_identifier.strip().lower()
        display_name = payload.display_name.strip() or canon_id
        src = source or payload.source or "DIRECTORY"
        weight = authority_weight or cls.DEFAULT_AUTHORITY_WEIGHTS.get(src, 80)

        # 1. Resolve canonical entity via Section 61
        resolution = UnifiedEntityResolver.resolve_entity(
            db,
            workspace_id=workspace_id,
            entity_type=payload.identity_type.strip().upper(),
            raw_identifier=canon_id,
            context=payload.external_id,
        )
        canonical_entity_id = resolution.canonical_entity_id

        # 2. Check for manual overrides
        overrides = {}
        existing = db.query(IdentityModel).filter(
            IdentityModel.workspace_id == workspace_id,
            IdentityModel.canonical_identifier == canon_id,
        ).first()

        if existing:
            override_records = db.query(InventoryOverrideModel).filter(
                InventoryOverrideModel.workspace_id == workspace_id,
                InventoryOverrideModel.target_type == "IDENTITY",
                InventoryOverrideModel.target_id == existing.id,
                InventoryOverrideModel.is_active == True,
            ).all()
            for ov in override_records:
                overrides[ov.field_name] = ov.new_value

        now = get_utc_now()
        is_created = False

        # Evaluate dormancy and orphan conditions
        is_service = payload.is_service_account or payload.identity_type.upper() == "SERVICE_ACCOUNT"
        is_priv = payload.is_privileged or any(
            p in canon_id for p in ("admin", "root", "domain_admin", "administrator", "service_principal")
        )
        is_orph = payload.is_orphaned or (is_service and not payload.department and not payload.team and not payload.manager)

        if not existing:
            is_created = True
            crit_val = overrides.get("criticality", "CRITICAL" if is_priv else payload.criticality or "MEDIUM")
            status_val = overrides.get("status", payload.status or "ACTIVE")

            existing = IdentityModel(
                workspace_id=workspace_id,
                identity_type=payload.identity_type.strip().upper(),
                canonical_identifier=canon_id,
                display_name=display_name,
                email=payload.email.strip().lower() if payload.email else canon_id if "@" in canon_id else None,
                username=payload.username or canon_id.split("@")[0],
                department=overrides.get("department", payload.department),
                team=overrides.get("team", payload.team),
                business_unit=payload.business_unit,
                manager=payload.manager,
                status=status_val,
                criticality=crit_val,
                is_privileged=is_priv,
                is_service_account=is_service,
                is_orphaned=is_orph,
                is_dormant=payload.is_dormant,
                source=src,
                external_id=payload.external_id,
                canonical_entity_id=canonical_entity_id,
                tags_json=json.dumps(payload.tags or []),
                first_seen_at=now,
                last_seen_at=now,
                last_authenticated_at=now if not payload.is_dormant else None,
                last_sync_at=now,
                metadata_json=json.dumps(payload.metadata or {}),
            )
            db.add(existing)
            db.flush()

        else:
            existing.last_seen_at = now
            existing.last_sync_at = now
            if not payload.is_dormant:
                existing.last_authenticated_at = now
            if canonical_entity_id and not existing.canonical_entity_id:
                existing.canonical_entity_id = canonical_entity_id

            # Conflict Detection on Department
            if payload.department and payload.department != existing.department:
                cls._handle_attribute_conflict(
                    db,
                    workspace_id=workspace_id,
                    target_type="IDENTITY",
                    target_id=existing.id,
                    target_canonical_name=existing.canonical_identifier,
                    field_name="department",
                    current_value=existing.department or "",
                    current_source=existing.source,
                    incoming_value=payload.department,
                    incoming_source=src,
                    incoming_weight=weight,
                    target_model=existing,
                    overridden="department" in overrides,
                )

            # Metadata merge
            merged_meta = existing.metadata_dict
            if payload.metadata:
                merged_meta.update(payload.metadata)
                existing.metadata_json = json.dumps(merged_meta)

            if payload.tags:
                curr_tags = set(existing.tags_list)
                curr_tags.update(payload.tags)
                existing.tags_json = json.dumps(list(curr_tags))

        db.commit()
        db.refresh(existing)
        return existing, is_created

    # ---------------------------------------------------------------------------
    # 4. CONFLICT DETECTION & RESOLUTION WORKSPACE
    # ---------------------------------------------------------------------------

    @classmethod
    def _handle_attribute_conflict(
        cls,
        db: Session,
        workspace_id: str,
        target_type: str,
        target_id: str,
        target_canonical_name: str,
        field_name: str,
        current_value: str,
        current_source: str,
        incoming_value: str,
        incoming_source: str,
        incoming_weight: int,
        target_model: Any,
        overridden: bool = False,
    ) -> None:
        """
        Evaluates source precedence weights to auto-resolve or flag review conflicts.
        """
        curr_weight = cls.DEFAULT_AUTHORITY_WEIGHTS.get(current_source, 30)

        # If manually overridden, manual override holds authority
        if overridden:
            reason = f"Field '{field_name}' holds an active manual analyst override."
            status = "AUTO_RESOLVED"
            resolved_val = getattr(target_model, field_name)
            resolved_src = "MANUAL_OVERRIDE"
        elif incoming_weight > curr_weight:
            # Incoming source has higher precedence
            setattr(target_model, field_name, incoming_value)
            resolved_val = incoming_value
            resolved_src = incoming_source
            status = "AUTO_RESOLVED"
            reason = f"{incoming_source} (weight {incoming_weight}) took precedence over {current_source} (weight {curr_weight})."
        elif incoming_weight < curr_weight:
            # Current source has higher precedence
            resolved_val = current_value
            resolved_src = current_source
            status = "AUTO_RESOLVED"
            reason = f"{current_source} (weight {curr_weight}) holds higher precedence than {incoming_source} (weight {incoming_weight})."
        else:
            # Equal weight: flag for SOC analyst review
            status = "PENDING_REVIEW"
            resolved_val = current_value
            resolved_src = current_source
            reason = f"Equal source authority weights ({incoming_weight}) between {current_source} and {incoming_source}. Flagged for review."

        # Upsert or append to InventoryConflictModel
        conflict = db.query(InventoryConflictModel).filter(
            InventoryConflictModel.workspace_id == workspace_id,
            InventoryConflictModel.target_type == target_type,
            InventoryConflictModel.target_id == target_id,
            InventoryConflictModel.field_name == field_name,
        ).first()

        now_str = get_utc_now().isoformat()
        new_values = [
            {"source": current_source, "value": current_value, "authority_weight": curr_weight, "observed_at": now_str},
            {"source": incoming_source, "value": incoming_value, "authority_weight": incoming_weight, "observed_at": now_str},
        ]

        if not conflict:
            conflict = InventoryConflictModel(
                workspace_id=workspace_id,
                target_type=target_type,
                target_id=target_id,
                target_canonical_name=target_canonical_name,
                field_name=field_name,
                conflicting_values_json=json.dumps(new_values),
                resolved_value=resolved_val,
                resolved_source=resolved_src,
                resolution_reason=reason,
                status=status,
            )
            db.add(conflict)
        else:
            conflict.conflicting_values_json = json.dumps(new_values)
            conflict.resolved_value = resolved_val
            conflict.resolved_source = resolved_src
            conflict.resolution_reason = reason
            conflict.status = status
            conflict.updated_at = get_utc_now()

    @classmethod
    def list_conflicts(
        cls,
        db: Session,
        workspace_id: str = "default",
        status: Optional[str] = None,
        target_type: Optional[str] = None,
        skip: int = 0,
        limit: int = 50,
    ) -> Tuple[List[InventoryConflictRead], int]:
        """Lists attribute conflicts with explanation and resolution status."""
        q = db.query(InventoryConflictModel).filter(InventoryConflictModel.workspace_id == workspace_id)
        if status and status.upper() != "ALL":
            q = q.filter(InventoryConflictModel.status == status.upper())
        if target_type and target_type.upper() != "ALL":
            q = q.filter(InventoryConflictModel.target_type == target_type.upper())

        total = q.count()
        models = q.order_by(desc(InventoryConflictModel.updated_at)).offset(skip).limit(limit).all()

        results = []
        for m in models:
            item = InventoryConflictRead.model_validate(m)
            item.conflicting_values = m.conflicting_values_list
            results.append(item)
        return results, total

    @classmethod
    def resolve_conflict(
        cls,
        db: Session,
        workspace_id: str,
        conflict_id: str,
        selected_value: str,
        selected_source: str,
        resolution_reason: str,
        actor: str = "SOC Analyst",
    ) -> Optional[InventoryConflictModel]:
        """Applies manual conflict resolution, updating the target asset or identity."""
        conflict = db.query(InventoryConflictModel).filter(
            InventoryConflictModel.id == conflict_id,
            InventoryConflictModel.workspace_id == workspace_id
        ).first()
        if not conflict:
            return None

        conflict.resolved_value = selected_value
        conflict.resolved_source = selected_source
        conflict.resolution_reason = resolution_reason
        conflict.status = "MANUALLY_RESOLVED"
        conflict.resolved_by = actor
        conflict.resolved_at = get_utc_now()
        conflict.updated_at = get_utc_now()

        # Update target entity
        if conflict.target_type == "ASSET":
            asset = db.query(AssetModel).filter(
                AssetModel.id == conflict.target_id,
                AssetModel.workspace_id == workspace_id
            ).first()
            if asset and hasattr(asset, conflict.field_name):
                setattr(asset, conflict.field_name, selected_value)
                asset.updated_at = get_utc_now()
        elif conflict.target_type == "IDENTITY":
            identity = db.query(IdentityModel).filter(
                IdentityModel.id == conflict.target_id,
                IdentityModel.workspace_id == workspace_id
            ).first()
            if identity and hasattr(identity, conflict.field_name):
                setattr(identity, conflict.field_name, selected_value)
                identity.updated_at = get_utc_now()

        # Record manual override
        override = InventoryOverrideModel(
            workspace_id=workspace_id,
            target_type=conflict.target_type,
            target_id=conflict.target_id,
            field_name=conflict.field_name,
            previous_value=None,
            new_value=selected_value,
            reason=resolution_reason,
            actor=actor,
        )
        db.add(override)

        # Audit entry
        audit = AuditLogModel(
            action="INVENTORY_CONFLICT_RESOLVED",
            resource_type=conflict.target_type,
            resource_id=conflict.target_id,
            user=actor,
            details=json.dumps({
                "field_name": conflict.field_name,
                "selected_value": selected_value,
                "selected_source": selected_source,
                "reason": resolution_reason,
            }),
        )
        db.add(audit)

        db.commit()
        db.refresh(conflict)
        return conflict

    # ---------------------------------------------------------------------------
    # 5. SOURCE REGISTRY & SEEDING
    # ---------------------------------------------------------------------------

    @classmethod
    def _ensure_default_sources(cls, db: Session, workspace_id: str) -> None:
        """Seeds default authorized inventory sources if none exist for tenant."""
        count = db.query(InventorySourceModel).filter(InventorySourceModel.workspace_id == workspace_id).count()
        if count == 0:
            default_sources = [
                {
                    "source_type": "CMDB",
                    "name": "Enterprise CMDB (ServiceNow)",
                    "authority_weight": 100,
                    "capabilities": ["SERVER", "ENDPOINT", "APPLICATION", "DATABASE"],
                },
                {
                    "source_type": "DIRECTORY",
                    "name": "Corporate Okta / Active Directory",
                    "authority_weight": 80,
                    "capabilities": ["USER", "ACCOUNT", "GROUP", "SERVICE_ACCOUNT"],
                },
                {
                    "source_type": "ENDPOINT_AGENT",
                    "name": "CyberGuard Endpoint Telemetry Fleet",
                    "authority_weight": 60,
                    "capabilities": ["ENDPOINT", "DEVICE", "WORKSTATION", "LAPTOP"],
                },
                {
                    "source_type": "CLOUD_PROVIDER",
                    "name": "AWS / GCP Cloud Inventory IAM",
                    "authority_weight": 50,
                    "capabilities": ["CLOUD_RESOURCE", "SERVICE_ACCOUNT", "API_CLIENT"],
                },
            ]
            for s in default_sources:
                db.add(InventorySourceModel(
                    workspace_id=workspace_id,
                    source_type=s["source_type"],
                    name=s["name"],
                    authority_weight=s["authority_weight"],
                    capabilities_json=json.dumps(s["capabilities"]),
                    status="ACTIVE",
                    health_status="HEALTHY",
                ))
            db.commit()

    @classmethod
    def list_sources(cls, db: Session, workspace_id: str = "default") -> List[InventorySourceRead]:
        """Lists registered inventory sources and their health."""
        cls._ensure_default_sources(db, workspace_id)
        sources = db.query(InventorySourceModel).filter(
            InventorySourceModel.workspace_id == workspace_id
        ).order_by(desc(InventorySourceModel.authority_weight)).all()
        results = []
        for s in sources:
            item = InventorySourceRead.model_validate(s)
            item.capabilities = s.capabilities_list
            results.append(item)
        return results

    @classmethod
    def create_source(cls, db: Session, workspace_id: str, payload: InventorySourceCreate) -> InventorySourceModel:
        """Registers a new inventory source with deterministic authority weight."""
        src = InventorySourceModel(
            workspace_id=workspace_id,
            source_type=payload.source_type.strip().upper(),
            name=payload.name.strip(),
            status=payload.status,
            authority_weight=payload.authority_weight,
            sync_interval_seconds=payload.sync_interval_seconds,
            health_status=payload.health_status,
            capabilities_json=json.dumps(payload.capabilities or []),
            config_json=json.dumps(payload.config or {}),
        )
        db.add(src)
        db.commit()
        db.refresh(src)
        return src

    @classmethod
    def delete_source(cls, db: Session, workspace_id: str, source_id: str) -> bool:
        """Removes a source connector."""
        src = db.query(InventorySourceModel).filter(
            InventorySourceModel.id == source_id,
            InventorySourceModel.workspace_id == workspace_id
        ).first()
        if not src:
            return False
        db.delete(src)
        db.commit()
        return True

    # ---------------------------------------------------------------------------
    # 6. RECONCILIATION & SYNCHRONIZATION
    # ---------------------------------------------------------------------------

    @classmethod
    def run_reconciliation(
        cls,
        db: Session,
        workspace_id: str = "default"
    ) -> InventoryReconciliationReport:
        """
        Executes full inventory reconciliation:
        - Flags stale assets (> 30 days without observation)
        - Detects unmanaged endpoints (missing endpoint agent)
        - Identifies dormant identities (> 90 days without interactive authentication)
        - Identifies orphaned service accounts/accounts
        """
        start_time = time.time()
        now = datetime.now(timezone.utc)
        stale_cutoff = now - timedelta(days=cls.STALE_ASSET_THRESHOLD_DAYS)
        dormant_cutoff = now - timedelta(days=cls.DORMANT_IDENTITY_THRESHOLD_DAYS)

        stale_assets_count = 0
        unmanaged_endpoints_count = 0
        unowned_assets_count = 0
        dormant_identities_count = 0
        orphaned_accounts_count = 0

        # Reconcile Assets
        assets = db.query(AssetModel).filter(AssetModel.workspace_id == workspace_id).all()
        for a in assets:
            last_seen = _ensure_utc(a.last_seen_at)
            # Check Stale
            if last_seen and last_seen < stale_cutoff:
                if a.status != "RETIRED":
                    a.status = "STALE"
                    a.is_stale = True
                    stale_assets_count += 1
            elif a.status == "STALE":
                a.status = "ACTIVE"
                a.is_stale = False

            # Check Unmanaged Endpoints
            if a.asset_type in ("ENDPOINT", "DEVICE", "SERVER"):
                if a.external_id:
                    has_active_agent = db.query(EndpointAgentModel).filter(
                        EndpointAgentModel.workspace_id == workspace_id,
                        EndpointAgentModel.device_id == a.external_id,
                        EndpointAgentModel.status.in_(("ACTIVE", "ENROLLED"))
                    ).first()
                    a.is_managed = bool(has_active_agent)
                else:
                    a.is_managed = False

                if not a.is_managed:
                    unmanaged_endpoints_count += 1

            # Check Unowned
            if a.ownership_status in ("UNASSIGNED", "UNKNOWN") or a.owner in (None, "", "Unknown", "Unassigned"):
                unowned_assets_count += 1

        # Reconcile Identities
        identities = db.query(IdentityModel).filter(IdentityModel.workspace_id == workspace_id).all()
        for i in identities:
            last_auth = _ensure_utc(i.last_authenticated_at)
            # Check Dormancy
            if last_auth and last_auth < dormant_cutoff:
                i.is_dormant = True
                if i.status == "ACTIVE":
                    i.status = "DORMANT"
                dormant_identities_count += 1
            elif not last_auth:
                first_seen = _ensure_utc(i.first_seen_at)
                if first_seen and first_seen < dormant_cutoff:
                    i.is_dormant = True
                    dormant_identities_count += 1

            # Check Orphaned Accounts
            if i.is_service_account or i.identity_type.upper() == "SERVICE_ACCOUNT":
                if not i.department and not i.team and not i.manager:
                    i.is_orphaned = True
                    orphaned_accounts_count += 1

        db.commit()

        duration_ms = (time.time() - start_time) * 1000
        return InventoryReconciliationReport(
            timestamp=get_utc_now(),
            stale_assets_flagged=stale_assets_count,
            unmanaged_endpoints_flagged=unmanaged_endpoints_count,
            unowned_assets_flagged=unowned_assets_count,
            dormant_identities_flagged=dormant_identities_count,
            orphaned_accounts_flagged=orphaned_accounts_count,
            conflicts_auto_resolved=0,
            conflicts_pending_review=db.query(InventoryConflictModel).filter(
                InventoryConflictModel.workspace_id == workspace_id,
                InventoryConflictModel.status == "PENDING_REVIEW"
            ).count(),
            total_records_processed=len(assets) + len(identities),
            reconciliation_duration_ms=round(duration_ms, 2),
        )

    @classmethod
    def run_inventory_sync(
        cls,
        db: Session,
        workspace_id: str,
        req: InventorySyncRequest
    ) -> InventorySyncResponse:
        """
        Synchronizes authoritative inventory from internal subsystems:
        - Devices & Agents from Section 31
        - Identities from Section 21 ProtectedIdentities
        - Indicators from Section 52 Threat Intelligence
        """
        start_time = time.time()
        assets_synced = 0
        identities_synced = 0

        # 1. Sync from Section 31 Devices & Endpoint Agents
        if req.sync_endpoints:
            devices = db.query(DeviceModel).filter(DeviceModel.workspace_id == workspace_id).all()
            for dev in devices:
                asset_payload = AssetCreate(
                    asset_type="ENDPOINT",
                    canonical_name=dev.hostname or dev.device_uid,
                    display_name=f"{dev.hostname} ({dev.platform})",
                    status="ACTIVE" if dev.status == "ACTIVE" else "INACTIVE",
                    criticality="MEDIUM",
                    owner="Unassigned",
                    environment="CORP",
                    source="ENDPOINT_AGENT",
                    external_id=dev.id,
                    classification="WORKSTATION" if dev.platform in ("macos", "windows") else "SERVER",
                    is_managed=True,
                    tags=[dev.platform, dev.os_version] if dev.os_version else [dev.platform],
                    metadata={"device_uid": dev.device_uid, "platform": dev.platform},
                )
                _, created = cls.upsert_asset(db, workspace_id, asset_payload, source="ENDPOINT_AGENT")
                assets_synced += 1

        # 2. Sync from Section 21 Protected Identities (Executive / Institutional Identities)
        if req.sync_identities:
            protected = db.query(ProtectedIdentityModel).filter(ProtectedIdentityModel.is_active == True).all()
            for p in protected:
                trusted_emails = []
                try:
                    trusted_emails = json.loads(p.trusted_emails_json or "[]")
                except Exception:
                    pass

                for email_addr in trusted_emails:
                    ident_payload = IdentityCreate(
                        identity_type="USER",
                        canonical_identifier=email_addr,
                        display_name=p.display_name,
                        email=email_addr,
                        department="Executive Leadership" if p.entity_type == "EXECUTIVE" else "Corporate",
                        status="ACTIVE",
                        criticality="CRITICAL" if p.entity_type == "EXECUTIVE" else "HIGH",
                        is_privileged=True if p.entity_type == "EXECUTIVE" else False,
                        source="HR_SYSTEM",
                        external_id=p.id,
                        tags=["protected_identity", p.entity_type.lower()],
                    )
                    _, created = cls.upsert_identity(db, workspace_id, ident_payload, source="HR_SYSTEM")
                    identities_synced += 1

        # 3. Reconcile states
        cls.run_reconciliation(db, workspace_id)

        duration_ms = (time.time() - start_time) * 1000
        conflicts_count = db.query(InventoryConflictModel).filter(
            InventoryConflictModel.workspace_id == workspace_id,
            InventoryConflictModel.status == "PENDING_REVIEW"
        ).count()

        return InventorySyncResponse(
            assets_synced=assets_synced,
            identities_synced=identities_synced,
            conflicts_detected=conflicts_count,
            sync_duration_ms=round(duration_ms, 2),
            status="COMPLETED",
            message=f"Synced {assets_synced} assets and {identities_synced} identities.",
        )
