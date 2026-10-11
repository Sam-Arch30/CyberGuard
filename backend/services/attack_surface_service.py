"""
Section 62: Attack Surface Intelligence Service.
Discovers, normalizes, relates, monitors, and prioritizes observable organizational attack surface
using existing CyberGuard endpoints, telemetry, threat intelligence, and knowledge graph entities.
Strictly defends against SSRF and adheres to authorized discovery boundaries.
"""
from __future__ import annotations

import fnmatch
import ipaddress
import json
import logging
import re
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple

from sqlalchemy.orm import Session
from sqlalchemy import desc, func, or_, and_

from backend.db.models import (
    AssetModel,
    ExposureModel,
    AssetServiceModel,
    AttackSurfaceScopeModel,
    AttackSurfaceSnapshotModel,
    DeviceModel,
    EndpointAgentModel,
    ProtectedIdentityModel,
    IndicatorModel,
    SecurityEventModel,
    FindingModel,
    AuditLogModel,
    RelationshipModel,
    EntityModel,
    WatchedIndicatorModel,
    WatchlistModel,
    generate_uuid,
    get_utc_now,
)
from backend.schemas.attack_surface import (
    AssetTypeEnum,
    AssetStatusEnum,
    ExposureStateEnum,
    CriticalityEnum,
    OwnershipConfidenceEnum,
    AssetSourceEnum,
    ExposureTypeEnum,
    ExposureStatusEnum,
    ExposureSeverityEnum,
    ScopeTypeEnum,
    AssetCreateRequest,
    AssetUpdateRequest,
    AssetRead,
    AssetDetail,
    ExposureRead,
    ExposureResolveRequest,
    AssetServiceCreateRequest,
    AttackSurfaceScopeCreateRequest,
    AttackSurfaceOverviewStats,
    AttackSurfaceDiffResponse,
    UnknownAssetReviewRequest,
    AttackSurfaceDiscoveryRequest,
    AttackSurfaceDiscoveryResponse,
)
from backend.schemas.realtime import RealtimeEventTypeEnum, RealtimeResourceScopeEnum
from backend.schemas.notification import NotificationTypeEnum, NotificationSeverityEnum
from backend.services.dns_service import DNSService
from backend.services.notification_service import NotificationService
from backend.services.realtime_service import RealtimePublisher
from backend.services.security_graph_service import SecurityGraphService
from backend.services.ssrf_protector import SSRFProtector
from backend.services.unified_entity_resolver import UnifiedEntityResolver

logger = logging.getLogger("cyberguard.services.attack_surface")


def _ensure_utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


class AttackSurfaceService:
    """
    Authoritative service orchestrating Attack Surface Intelligence.
    """

    # ========================================================================
    # 1. NORMALIZATION & ASSET IDENTITY
    # ========================================================================

    @classmethod
    def normalize_asset_identifier(
        cls, asset_type: AssetTypeEnum | str, raw_name: str
    ) -> Tuple[str, str]:
        """
        Deterministically normalizes asset names according to type-specific security rules.
        Returns (canonical_name, display_name).
        """
        raw = raw_name.strip()
        type_str = asset_type.value if isinstance(asset_type, AssetTypeEnum) else str(asset_type)

        if type_str in (AssetTypeEnum.DOMAIN.value, AssetTypeEnum.SUBDOMAIN.value):
            # Clean domain
            clean = raw.lower()
            clean = re.sub(r"^https?://", "", clean)
            clean = clean.split("/")[0].split(":")[0].strip(".")
            # Ensure valid safe RFC-1123 punycode conversion
            ascii_dom, _ = DNSService.normalize_and_punycode(clean)
            return ascii_dom, clean

        elif type_str in (AssetTypeEnum.PUBLIC_IP.value, AssetTypeEnum.PRIVATE_IP.value):
            clean_ip = re.sub(r"^(?i:IPv6:)", "", raw.strip())
            # Strip port if present (e.g. 203.0.113.195:443 or [2001:db8::1]:8080)
            if clean_ip.startswith("[") and "]" in clean_ip:
                clean_ip = clean_ip.split("]")[0].lstrip("[")
            elif ":" in clean_ip and clean_ip.count(":") == 1:
                clean_ip = clean_ip.split(":")[0]
            try:
                ip_obj = ipaddress.ip_address(clean_ip)
                return str(ip_obj), str(ip_obj)
            except ValueError:
                return clean_ip.lower(), clean_ip

        elif type_str in (AssetTypeEnum.USER_ACCOUNT.value, AssetTypeEnum.IDENTITY.value, AssetTypeEnum.SERVICE_ACCOUNT.value):
            clean_email = raw.lower()
            return clean_email, raw

        elif type_str == AssetTypeEnum.CERTIFICATE.value:
            clean_hash = re.sub(r"[^a-fA-F0-9]", "", raw).lower()
            return clean_hash, f"SHA256:{clean_hash[:16]}..."

        elif type_str in (AssetTypeEnum.API.value, AssetTypeEnum.WEB_APPLICATION.value, AssetTypeEnum.APPLICATION.value):
            clean_url = raw.lower()
            clean_url = re.sub(r"^https?://", "", clean_url).rstrip("/")
            return clean_url, raw

        else:
            # ENDPOINT, SERVER, DEVICE, CLOUD_RESOURCE
            clean_host = raw.strip()
            return clean_host.lower(), clean_host

    @classmethod
    def upsert_asset(
        cls,
        db: Session,
        workspace_id: str,
        asset_type: Optional[AssetTypeEnum | str | AssetCreateRequest] = None,
        raw_name: Optional[str] = None,
        display_name: Optional[str] = None,
        criticality: CriticalityEnum | str = CriticalityEnum.MEDIUM,
        exposure_state: ExposureStateEnum | str = ExposureStateEnum.UNKNOWN,
        status: AssetStatusEnum | str = AssetStatusEnum.ACTIVE,
        owner: Optional[str] = None,
        team: Optional[str] = None,
        business_unit: Optional[str] = None,
        environment: str = "PRODUCTION",
        ownership_confidence: OwnershipConfidenceEnum | str = OwnershipConfidenceEnum.UNKNOWN,
        source: AssetSourceEnum | str = AssetSourceEnum.INTERNAL_DISCOVERY,
        external_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        req: Optional[AssetCreateRequest] = None,
    ) -> AssetModel:
        """
        Creates or updates a normalized asset with deterministic identity and KG linkage.
        Supports invocation via keyword args, an AssetCreateRequest object, or req=...
        """
        if req is not None:
            asset_type = req.asset_type
            raw_name = req.raw_name
            display_name = req.display_name
            criticality = req.criticality
            owner = req.owner
            team = req.team
            business_unit = req.business_unit
            environment = req.environment
            source = req.source
            metadata = req.metadata
        elif isinstance(asset_type, AssetCreateRequest):
            req_obj = asset_type
            asset_type = req_obj.asset_type
            raw_name = req_obj.raw_name
            display_name = req_obj.display_name
            criticality = req_obj.criticality
            owner = req_obj.owner
            team = req_obj.team
            business_unit = req_obj.business_unit
            environment = req_obj.environment
            source = req_obj.source
            metadata = req_obj.metadata

        if raw_name is None or asset_type is None:
            raise ValueError("Both raw_name and asset_type are required to upsert an asset.")

        type_str = asset_type.value if isinstance(asset_type, AssetTypeEnum) else str(asset_type)
        canon_name, auto_disp = cls.normalize_asset_identifier(type_str, raw_name)
        disp_name = display_name or auto_disp
        meta = metadata or {}
        now = get_utc_now()

        # Link with Knowledge Graph canonical entity using Section 61 UnifiedEntityResolver
        canonical_entity_id: Optional[str] = None
        try:
            # Map asset type to entity resolver type
            kg_type_map = {
                AssetTypeEnum.DOMAIN.value: "DOMAIN",
                AssetTypeEnum.SUBDOMAIN.value: "DOMAIN",
                AssetTypeEnum.PUBLIC_IP.value: "IP",
                AssetTypeEnum.PRIVATE_IP.value: "IP",
                AssetTypeEnum.ENDPOINT.value: "ENDPOINT",
                AssetTypeEnum.DEVICE.value: "DEVICE",
                AssetTypeEnum.USER_ACCOUNT.value: "USER",
                AssetTypeEnum.CERTIFICATE.value: "HASH",
            }
            mapped_kg_type = kg_type_map.get(type_str, "DOMAIN")
            res = UnifiedEntityResolver.resolve_entity(
                db=db,
                entity_type=mapped_kg_type,
                raw_identifier=canon_name,
                workspace_id=workspace_id,
                context="ATTACK_SURFACE",
            )
            canonical_entity_id = res.canonical_entity_id
        except Exception as e:
            logger.debug(f"Entity resolver non-blocking pass for asset {canon_name}: {e}")

        # Check existing asset
        existing = db.query(AssetModel).filter(
            AssetModel.workspace_id == workspace_id,
            AssetModel.asset_type == type_str,
            AssetModel.canonical_name == canon_name,
        ).first()

        crit_str = criticality.value if isinstance(criticality, CriticalityEnum) else str(criticality)
        exp_str = exposure_state.value if isinstance(exposure_state, ExposureStateEnum) else str(exposure_state)
        stat_str = status.value if isinstance(status, AssetStatusEnum) else str(status)
        own_conf_str = ownership_confidence.value if isinstance(ownership_confidence, OwnershipConfidenceEnum) else str(ownership_confidence)
        src_str = source.value if isinstance(source, AssetSourceEnum) else str(source)

        if owner in ("Unknown", None) or own_conf_str == OwnershipConfidenceEnum.UNKNOWN.value:
            stat_str = AssetStatusEnum.DISCOVERED.value

        if type_str == AssetTypeEnum.PUBLIC_IP.value and exp_str == ExposureStateEnum.UNKNOWN.value:
            exp_str = ExposureStateEnum.PUBLICLY_EXPOSED.value

        if existing:
            existing.last_seen_at = now
            if disp_name and existing.display_name != disp_name:
                existing.display_name = disp_name
            if crit_str and existing.criticality != crit_str:
                existing.criticality = crit_str
            if canonical_entity_id and not existing.canonical_entity_id:
                existing.canonical_entity_id = canonical_entity_id
            if external_id and not existing.external_id:
                existing.external_id = external_id
            if owner and (not existing.owner or existing.owner == "Unknown"):
                existing.owner = owner
                existing.ownership_confidence = own_conf_str
            if team and not existing.team:
                existing.team = team
            if business_unit and not existing.business_unit:
                existing.business_unit = business_unit
            if exp_str != ExposureStateEnum.UNKNOWN.value:
                existing.exposure_state = exp_str

            # Merge metadata
            if meta:
                curr_meta = dict(existing.metadata_dict)
                curr_meta.update(meta)
                existing.metadata_json = json.dumps(curr_meta)

            existing.updated_at = now
            db.flush()
            return existing

        # Create new asset
        new_asset = AssetModel(
            id=generate_uuid(),
            workspace_id=workspace_id,
            asset_type=type_str,
            canonical_name=canon_name,
            display_name=disp_name,
            status=stat_str,
            exposure_state=exp_str,
            criticality=crit_str,
            owner=owner or "Unknown",
            team=team,
            business_unit=business_unit,
            environment=environment,
            ownership_confidence=own_conf_str,
            source=src_str,
            external_id=external_id,
            canonical_entity_id=canonical_entity_id,
            risk_score=0.0,
            risk_level="LOW",
            active_finding_count=0,
            active_exposure_count=0,
            first_seen_at=now,
            last_seen_at=now,
            metadata_json=json.dumps(meta),
            created_at=now,
            updated_at=now,
        )
        db.add(new_asset)
        db.flush()

        # Emit Realtime Event
        try:
            RealtimePublisher.publish_event(
                event_type=RealtimeEventTypeEnum.ASSET_DISCOVERED,
                resource_scope=RealtimeResourceScopeEnum.ATTACK_SURFACE,
                resource_id=new_asset.id,
                workspace_id=workspace_id,
                payload={
                    "asset_id": new_asset.id,
                    "asset_type": new_asset.asset_type,
                    "canonical_name": new_asset.canonical_name,
                    "exposure_state": new_asset.exposure_state,
                },
            )
        except Exception:
            pass

        return new_asset

    # ========================================================================
    # 2. DISCOVERY SCOPE ENFORCEMENT & SSRF DEFENSES
    # ========================================================================

    @classmethod
    def is_target_in_authorized_scope(
        cls, db: Session, workspace_id: str, target: str
    ) -> bool:
        """
        Verifies that an asset or scan target is explicitly permitted by an authorized scope.
        Strictly defends against SSRF and prevents unapproved external scanning.
        """
        clean_target = target.strip().lower()

        # Check explicit authorized scopes in this workspace
        scopes = db.query(AttackSurfaceScopeModel).filter(
            AttackSurfaceScopeModel.workspace_id == workspace_id,
            AttackSurfaceScopeModel.is_authorized == True,
        ).all()

        if not scopes:
            return False

        for s in scopes:
            s_target = s.target.strip().lower()
            if s.scope_type == ScopeTypeEnum.DOMAIN.value:
                # Match wildcard *.example.com or exact example.com
                if s_target.startswith("*."):
                    base_dom = s_target[2:]
                    if clean_target == base_dom or clean_target.endswith("." + base_dom):
                        return True
                elif clean_target == s_target or clean_target.endswith("." + s_target):
                    return True

            elif s.scope_type == ScopeTypeEnum.CIDR.value:
                try:
                    net = ipaddress.ip_network(s_target, strict=False)
                    ip_obj = ipaddress.ip_address(clean_target)
                    if ip_obj in net:
                        return True
                except ValueError:
                    pass

            elif s.scope_type == ScopeTypeEnum.IP.value:
                if clean_target == s_target:
                    return True

        return False

    # ========================================================================
    # 3. SYNCHRONIZED DISCOVERY & ASSET MAPPING
    # ========================================================================

    @classmethod
    def run_discovery_sync(
        cls,
        db: Session,
        workspace_id: str,
        options: AttackSurfaceDiscoveryRequest,
    ) -> AttackSurfaceDiscoveryResponse:
        """
        Discovers and synchronizes attack surface assets from existing CyberGuard datastores:
        - Registered devices & enrolled agents
        - Protected corporate identities & trusted domains
        - Ingested indicators & observed telemetry
        - Safe DNS resolution for authorized corporate domains
        """
        start_time = datetime.now(timezone.utc)
        assets_discovered = 0
        assets_updated = 0
        unknown_flagged = 0
        exposures_created = 0
        scopes_count = db.query(AttackSurfaceScopeModel).filter(
            AttackSurfaceScopeModel.workspace_id == workspace_id,
            AttackSurfaceScopeModel.is_authorized == True,
        ).count()

        # 1. Sync from Registered Devices & Endpoints
        if options.sync_from_endpoints:
            devices = db.query(DeviceModel).filter(
                DeviceModel.workspace_id == workspace_id,
            ).limit(200).all()

            for dev in devices:
                is_new = db.query(AssetModel).filter(
                    AssetModel.workspace_id == workspace_id,
                    AssetModel.asset_type == AssetTypeEnum.ENDPOINT.value,
                    AssetModel.canonical_name == dev.hostname.lower(),
                ).first() is None

                asset = cls.upsert_asset(
                    db=db,
                    workspace_id=workspace_id,
                    asset_type=AssetTypeEnum.ENDPOINT,
                    raw_name=dev.hostname,
                    display_name=dev.hostname,
                    criticality=CriticalityEnum.HIGH if "prod" in dev.hostname.lower() else CriticalityEnum.MEDIUM,
                    exposure_state=ExposureStateEnum.INTERNALLY_REACHABLE,
                    status=AssetStatusEnum.ACTIVE if dev.status == "ACTIVE" else AssetStatusEnum.INACTIVE,
                    owner="IT / Endpoint Fleet",
                    environment="PRODUCTION" if "prod" in dev.hostname.lower() else "CORP",
                    ownership_confidence=OwnershipConfidenceEnum.ENDPOINT_AGENT,
                    source=AssetSourceEnum.ENDPOINT_AGENT,
                    external_id=dev.id,
                    metadata={"platform": dev.platform, "os_version": dev.os_version, "device_uid": dev.device_uid},
                )
                if is_new:
                    assets_discovered += 1
                else:
                    assets_updated += 1

        # 2. Sync from Protected Corporate Identities & Domains
        if options.sync_from_identities:
            identities = db.query(ProtectedIdentityModel).filter(
                ProtectedIdentityModel.is_active == True,
            ).limit(100).all()

            for ident in identities:
                try:
                    domains = json.loads(ident.trusted_domains_json or "[]")
                except Exception:
                    domains = []

                for dom in domains:
                    if not SSRFProtector.is_safe_public_domain(dom):
                        continue

                    is_new = db.query(AssetModel).filter(
                        AssetModel.workspace_id == workspace_id,
                        AssetModel.asset_type == AssetTypeEnum.DOMAIN.value,
                        AssetModel.canonical_name == dom.lower(),
                    ).first() is None

                    asset = cls.upsert_asset(
                        db=db,
                        workspace_id=workspace_id,
                        asset_type=AssetTypeEnum.DOMAIN,
                        raw_name=dom,
                        display_name=dom,
                        criticality=CriticalityEnum.CRITICAL,
                        exposure_state=ExposureStateEnum.PUBLICLY_EXPOSED,
                        status=AssetStatusEnum.ACTIVE,
                        owner=ident.display_name,
                        team="Security / Infrastructure",
                        environment="PRODUCTION",
                        ownership_confidence=OwnershipConfidenceEnum.DIRECTORY,
                        source=AssetSourceEnum.INTERNAL_DISCOVERY,
                        external_id=ident.id,
                        metadata={"identity_type": ident.entity_type},
                    )

                    # Ensure authorized scope exists for corporate domain
                    scope_exists = db.query(AttackSurfaceScopeModel).filter(
                        AttackSurfaceScopeModel.workspace_id == workspace_id,
                        AttackSurfaceScopeModel.target == dom.lower(),
                    ).first()
                    if not scope_exists:
                        scope = AttackSurfaceScopeModel(
                            id=generate_uuid(),
                            workspace_id=workspace_id,
                            scope_type=ScopeTypeEnum.DOMAIN.value,
                            target=dom.lower(),
                            is_authorized=True,
                            description=f"Auto-configured corporate domain from Protected Identity ({ident.display_name})",
                            created_by="system",
                            created_at=get_utc_now(),
                        )
                        db.add(scope)
                        scopes_count += 1

                    if is_new:
                        assets_discovered += 1
                    else:
                        assets_updated += 1

                    # 3. Optional Safe DNS resolution for authorized domain
                    if options.resolve_dns_records and cls.is_target_in_authorized_scope(db, workspace_id, dom):
                        dns_svc = DNSService(timeout_seconds=2.0)
                        # Query A records
                        try:
                            res_a = dns_svc._get_resolver().resolve(dom, "A")
                            for r in res_a:
                                ip_str = str(r)
                                if SSRFProtector.is_safe_public_ip(ip_str):
                                    ip_asset = cls.upsert_asset(
                                        db=db,
                                        workspace_id=workspace_id,
                                        asset_type=AssetTypeEnum.PUBLIC_IP,
                                        raw_name=ip_str,
                                        criticality=CriticalityEnum.HIGH,
                                        exposure_state=ExposureStateEnum.PUBLICLY_EXPOSED,
                                        owner=ident.display_name,
                                        source=AssetSourceEnum.EXTERNAL_DISCOVERY,
                                        metadata={"resolved_from_domain": dom},
                                    )
                                    # Create graph relationship in SecurityGraph
                                    SecurityGraphService().create_relationship(
                                        db=db,
                                        source_type="DOMAIN",
                                        source_id=asset.canonical_name,
                                        relationship_type="RESOLVES_TO",
                                        target_type="IP",
                                        target_id=ip_str,
                                        workspace_id=workspace_id,
                                    )
                        except Exception:
                            pass

        # 4. Sync from Observed Indicators (Network & API Telemetry)
        if options.sync_from_telemetry:
            indicators = db.query(IndicatorModel).order_by(
                desc(IndicatorModel.created_at)
            ).limit(150).all()

            for ind in indicators:
                if ind.indicator_type in ("DOMAIN", "IP"):
                    val = ind.normalized_value or ind.value
                    if ind.indicator_type == "DOMAIN":
                        if not SSRFProtector.is_safe_public_domain(val):
                            continue
                        atype = AssetTypeEnum.DOMAIN
                    else:
                        if not SSRFProtector.is_safe_public_ip(val):
                            continue
                        atype = AssetTypeEnum.PUBLIC_IP

                    # Check if asset matches authorized scope
                    in_scope = cls.is_target_in_authorized_scope(db, workspace_id, val)

                    # If not in scope, record as UNKNOWN / DISCOVERED
                    asset_status = AssetStatusEnum.ACTIVE if in_scope else AssetStatusEnum.DISCOVERED
                    owner_val = "Corporate Network" if in_scope else "Unknown"

                    is_new = db.query(AssetModel).filter(
                        AssetModel.workspace_id == workspace_id,
                        AssetModel.asset_type == atype.value,
                        AssetModel.canonical_name == val.lower(),
                    ).first() is None

                    asset = cls.upsert_asset(
                        db=db,
                        workspace_id=workspace_id,
                        asset_type=atype,
                        raw_name=val,
                        exposure_state=ExposureStateEnum.PUBLICLY_EXPOSED,
                        status=asset_status,
                        owner=owner_val,
                        source=AssetSourceEnum.NETWORK_TELEMETRY,
                        metadata={"reputation_score": ind.reputation_score, "verdict": ind.verdict},
                    )

                    if not in_scope:
                        unknown_flagged += 1

                    if is_new:
                        assets_discovered += 1
                    else:
                        assets_updated += 1

        db.flush()

        # 5. Evaluate Exposures across assets
        exp_count = cls.evaluate_all_exposures(db, workspace_id)
        exposures_created += exp_count

        # 6. Recompute Risk Scores across assets
        cls.recompute_all_asset_risks(db, workspace_id)

        # 7. Create Snapshot Diff
        cls.create_snapshot_diff(db, workspace_id, snapshot_name=f"Sync-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M')}")

        duration = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000.0
        db.commit()

        return AttackSurfaceDiscoveryResponse(
            status="COMPLETED",
            assets_discovered=assets_discovered,
            assets_updated=assets_updated,
            unknown_assets_flagged=unknown_flagged,
            exposures_created=exposures_created,
            scopes_evaluated=scopes_count,
            duration_ms=round(duration, 2),
            message=f"Attack surface discovery successfully synchronized {assets_discovered} new and {assets_updated} existing assets.",
        )

    # ========================================================================
    # 4. EXPOSURE ASSESSMENT & SHADOW ASSET IDENTIFICATION
    # ========================================================================

    @classmethod
    def evaluate_asset_exposures(cls, db: Session, workspace_id: str, asset: AssetModel) -> int:
        """
        Evaluates an asset for security exposures without speculative vulnerability scanning:
        - PUBLIC_ASSET: Confirmed external reachability.
        - UNKNOWN_ASSET: Asset observed without recognized owner or approval.
        - STALE_ASSET: Asset without observation in > 30 days.
        - UNMAPPED_DOMAIN: Subdomain without mapped application or owner.
        """
        now = get_utc_now()
        created_count = 0

        # Exposure 1: UNKNOWN_ASSET (Unmapped / Potential Shadow IT)
        if asset.status in (AssetStatusEnum.DISCOVERED.value, AssetStatusEnum.UNKNOWN.value) or asset.owner in ("Unknown", None):
            existing_exp = db.query(ExposureModel).filter(
                ExposureModel.asset_id == asset.id,
                ExposureModel.exposure_type == ExposureTypeEnum.UNKNOWN_ASSET.value,
                ExposureModel.status == ExposureStatusEnum.OPEN.value,
            ).first()

            if not existing_exp:
                exp = ExposureModel(
                    id=generate_uuid(),
                    workspace_id=workspace_id,
                    asset_id=asset.id,
                    exposure_type=ExposureTypeEnum.UNKNOWN_ASSET.value,
                    title=f"Unmapped / Unknown Asset: {asset.display_name}",
                    description=(
                        f"Asset '{asset.display_name}' ({asset.asset_type}) was observed in telemetry without "
                        "established organizational ownership, CMDB mapping, or explicit authorization scope."
                    ),
                    status=ExposureStatusEnum.OPEN.value,
                    severity=ExposureSeverityEnum.MEDIUM.value,
                    confidence=0.90,
                    remediation_guidance="Review the asset, verify operational legitimacy, and assign appropriate team ownership.",
                    evidence_refs_json=json.dumps([f"asset_canonical:{asset.canonical_name}", f"source:{asset.source}"]),
                    source_refs_json=json.dumps([asset.source]),
                    risk_context_json=json.dumps({"asset_criticality": asset.criticality, "exposure_state": asset.exposure_state}),
                    first_seen_at=asset.first_seen_at,
                    last_seen_at=now,
                    created_at=now,
                    updated_at=now,
                )
                db.add(exp)
                created_count += 1

        # Exposure 2: PUBLIC_ASSET (External Internet Exposure)
        if asset.exposure_state == ExposureStateEnum.PUBLICLY_EXPOSED.value or asset.asset_type == AssetTypeEnum.PUBLIC_IP.value:
            existing_exp = db.query(ExposureModel).filter(
                ExposureModel.asset_id == asset.id,
                ExposureModel.exposure_type == ExposureTypeEnum.PUBLIC_ASSET.value,
                ExposureModel.status == ExposureStatusEnum.OPEN.value,
            ).first()

            if not existing_exp:
                sev = ExposureSeverityEnum.HIGH.value if asset.criticality in (CriticalityEnum.CRITICAL.value, CriticalityEnum.HIGH.value) else ExposureSeverityEnum.MEDIUM.value
                exp = ExposureModel(
                    id=generate_uuid(),
                    workspace_id=workspace_id,
                    asset_id=asset.id,
                    exposure_type=ExposureTypeEnum.PUBLIC_ASSET.value,
                    title=f"Public Internet Exposure: {asset.display_name}",
                    description=(
                        f"Asset '{asset.display_name}' ({asset.asset_type}) is publicly accessible or resolved "
                        "on public network infrastructure."
                    ),
                    status=ExposureStatusEnum.OPEN.value,
                    severity=sev,
                    confidence=1.0,
                    remediation_guidance="Verify whether this asset requires public internet reachability or should be restricted behind VPN / WAF.",
                    evidence_refs_json=json.dumps([f"canonical:{asset.canonical_name}"]),
                    source_refs_json=json.dumps([asset.source]),
                    risk_context_json=json.dumps({"criticality": asset.criticality}),
                    first_seen_at=asset.first_seen_at,
                    last_seen_at=now,
                    created_at=now,
                    updated_at=now,
                )
                db.add(exp)
                created_count += 1

        # Exposure 3: STALE_ASSET (Decommissioned or Lost Visibility)
        last_seen = _ensure_utc(asset.last_seen_at) or now
        if last_seen < (now - timedelta(days=30)):
            existing_exp = db.query(ExposureModel).filter(
                ExposureModel.asset_id == asset.id,
                ExposureModel.exposure_type == ExposureTypeEnum.STALE_ASSET.value,
                ExposureModel.status == ExposureStatusEnum.OPEN.value,
            ).first()

            if not existing_exp:
                exp = ExposureModel(
                    id=generate_uuid(),
                    workspace_id=workspace_id,
                    asset_id=asset.id,
                    exposure_type=ExposureTypeEnum.STALE_ASSET.value,
                    title=f"Stale Asset Inactivity: {asset.display_name}",
                    description=f"Asset '{asset.display_name}' has not been observed in active telemetry for over 30 days.",
                    status=ExposureStatusEnum.OPEN.value,
                    severity=ExposureSeverityEnum.LOW.value,
                    confidence=0.85,
                    remediation_guidance="Confirm if the asset was decommissioned and update inventory status to RETIRED.",
                    evidence_refs_json=json.dumps([f"last_seen:{asset.last_seen_at.isoformat()}"]),
                    source_refs_json=json.dumps([asset.source]),
                    risk_context_json=json.dumps({}),
                    first_seen_at=now,
                    last_seen_at=now,
                    created_at=now,
                    updated_at=now,
                )
                db.add(exp)
                created_count += 1

        return created_count

    @classmethod
    def evaluate_all_exposures(cls, db: Session, workspace_id: str) -> int:
        """Evaluates exposures across all active assets."""
        assets = db.query(AssetModel).filter(AssetModel.workspace_id == workspace_id).all()
        total_created = 0
        for a in assets:
            total_created += cls.evaluate_asset_exposures(db, workspace_id, a)
            # Update asset active exposure count
            active_exp = db.query(ExposureModel).filter(
                ExposureModel.asset_id == a.id,
                ExposureModel.status == ExposureStatusEnum.OPEN.value,
            ).count()
            a.active_exposure_count = active_exp
        db.flush()
        return total_created

    # ========================================================================
    # 5. RISK ENGINE INTEGRATION & ASSET PRIORITIZATION
    # ========================================================================

    @classmethod
    def recompute_asset_risk(cls, db: Session, workspace_id: str, asset: AssetModel) -> float:
        """
        Recomputes bounded asset risk score adhering to Section 26 Unified Risk principles:
        - Criticality modifier
        - Open exposures count and severity
        - Active security findings on the asset's canonical entity
        """
        base_score = 0.0

        # Criticality contribution
        crit_weights = {
            CriticalityEnum.CRITICAL.value: 20.0,
            CriticalityEnum.HIGH.value: 12.0,
            CriticalityEnum.MEDIUM.value: 5.0,
            CriticalityEnum.LOW.value: 0.0,
            CriticalityEnum.UNKNOWN.value: 2.0,
        }
        base_score += crit_weights.get(asset.criticality, 5.0)

        # Exposure contributions
        open_exposures = db.query(ExposureModel).filter(
            ExposureModel.asset_id == asset.id,
            ExposureModel.status == ExposureStatusEnum.OPEN.value,
        ).all()

        sev_weights = {
            ExposureSeverityEnum.CRITICAL.value: 30.0,
            ExposureSeverityEnum.HIGH.value: 20.0,
            ExposureSeverityEnum.MEDIUM.value: 10.0,
            ExposureSeverityEnum.LOW.value: 5.0,
            ExposureSeverityEnum.INFO.value: 0.0,
        }
        for exp in open_exposures:
            base_score += sev_weights.get(exp.severity, 5.0)

        # Security Findings contribution (via Knowledge Graph canonical entity)
        active_findings = 0
        if asset.canonical_entity_id:
            findings = db.query(FindingModel).filter(
                FindingModel.workspace_id == workspace_id,
            ).limit(20).all()
            for f in findings:
                indicators = f.details.get("indicators", []) or []
                if asset.canonical_name in indicators or (f.title and asset.canonical_name in f.title.lower()):
                    active_findings += 1
                    base_score += (f.risk_contribution or 15.0) * 0.5

        if active_findings == 0 and (asset.active_finding_count or 0) > 0:
            active_findings = asset.active_finding_count
            base_score += active_findings * 8.0

        asset.active_finding_count = active_findings
        asset.active_exposure_count = len(open_exposures)

        # Bound to 0.0 - 100.0
        final_risk = min(100.0, max(0.0, round(base_score, 1)))
        asset.risk_score = final_risk

        if final_risk >= 75.0:
            asset.risk_level = "CRITICAL"
        elif final_risk >= 50.0:
            asset.risk_level = "HIGH"
        elif final_risk >= 25.0:
            asset.risk_level = "MEDIUM"
        else:
            asset.risk_level = "LOW"

        return final_risk

    @classmethod
    def recompute_all_asset_risks(cls, db: Session, workspace_id: str) -> None:
        """Recomputes risk across all assets in workspace."""
        assets = db.query(AssetModel).filter(AssetModel.workspace_id == workspace_id).all()
        for a in assets:
            cls.recompute_asset_risk(db, workspace_id, a)
        db.flush()

    # ========================================================================
    # 6. ATTACK SURFACE DIFF & HISTORICAL SNAPSHOTS
    # ========================================================================

    @classmethod
    def create_snapshot_diff(
        cls, db: Session, workspace_id: str, snapshot_name: str
    ) -> AttackSurfaceSnapshotModel:
        """
        Creates an immutable snapshot of the attack surface and computes changes vs previous snapshot.
        """
        now = get_utc_now()
        total_assets = db.query(AssetModel).filter(AssetModel.workspace_id == workspace_id).count()
        exposed_assets = db.query(AssetModel).filter(
            AssetModel.workspace_id == workspace_id,
            AssetModel.exposure_state == ExposureStateEnum.PUBLICLY_EXPOSED.value,
        ).count()
        unknown_assets = db.query(AssetModel).filter(
            AssetModel.workspace_id == workspace_id,
            or_(
                AssetModel.status == AssetStatusEnum.DISCOVERED.value,
                AssetModel.owner == "Unknown",
            ),
        ).count()
        open_exposures = db.query(ExposureModel).filter(
            ExposureModel.workspace_id == workspace_id,
            ExposureModel.status == ExposureStatusEnum.OPEN.value,
        ).count()
        critical_assets = db.query(AssetModel).filter(
            AssetModel.workspace_id == workspace_id,
            AssetModel.criticality == CriticalityEnum.CRITICAL.value,
        ).count()
        high_risk_assets = db.query(AssetModel).filter(
            AssetModel.workspace_id == workspace_id,
            AssetModel.risk_score >= 50.0,
        ).count()

        # Query previous snapshot for diff
        prev = db.query(AttackSurfaceSnapshotModel).filter(
            AttackSurfaceSnapshotModel.workspace_id == workspace_id
        ).order_by(desc(AttackSurfaceSnapshotModel.created_at)).first()

        assets_added = 0
        assets_removed = 0
        exposures_added = 0
        exposures_resolved = 0
        diff_summary: Dict[str, Any] = {}

        if prev:
            assets_added = max(0, total_assets - prev.total_assets)
            exposures_added = max(0, open_exposures - prev.open_exposures)
            new_assets = db.query(AssetModel.canonical_name).filter(
                AssetModel.workspace_id == workspace_id,
                AssetModel.created_at >= prev.created_at,
            ).limit(20).all()
            added_names = [a[0] for a in new_assets]
            diff_summary = {
                "previous_snapshot_time": prev.created_at.isoformat(),
                "asset_count_delta": total_assets - prev.total_assets,
                "open_exposure_delta": open_exposures - prev.open_exposures,
                "unknown_asset_delta": unknown_assets - prev.unknown_assets,
                "added_assets": added_names,
            }
        else:
            diff_summary = {"initial_baseline": True, "total_assets": total_assets}

        snapshot = AttackSurfaceSnapshotModel(
            id=generate_uuid(),
            workspace_id=workspace_id,
            snapshot_name=snapshot_name,
            total_assets=total_assets,
            exposed_assets=exposed_assets,
            unknown_assets=unknown_assets,
            open_exposures=open_exposures,
            critical_assets=critical_assets,
            high_risk_assets=high_risk_assets,
            assets_added=assets_added,
            assets_removed=assets_removed,
            exposures_added=exposures_added,
            exposures_resolved=exposures_resolved,
            diff_summary_json=json.dumps(diff_summary),
            created_at=now,
        )
        db.add(snapshot)
        db.flush()
        return snapshot

    @classmethod
    def get_latest_diff(cls, db: Session, workspace_id: str) -> AttackSurfaceDiffResponse:
        """Returns diff between current state and previous snapshot."""
        snapshots = db.query(AttackSurfaceSnapshotModel).filter(
            AttackSurfaceSnapshotModel.workspace_id == workspace_id
        ).order_by(desc(AttackSurfaceSnapshotModel.created_at)).limit(2).all()

        now = get_utc_now()
        if not snapshots:
            return AttackSurfaceDiffResponse(
                snapshot_name="Current Baseline",
                current_snapshot_time=now,
                assets_added=0,
                assets_removed=0,
                exposures_added=0,
                exposures_resolved=0,
                diff_summary={"status": "No historical snapshot exists"},
            )

        latest = snapshots[0]
        prev_time = snapshots[1].created_at if len(snapshots) > 1 else None

        # Sample recent added assets
        added_assets = db.query(AssetModel.canonical_name).filter(
            AssetModel.workspace_id == workspace_id,
            AssetModel.created_at >= (latest.created_at - timedelta(hours=24)),
        ).limit(10).all()

        return AttackSurfaceDiffResponse(
            snapshot_name=latest.snapshot_name,
            previous_snapshot_time=prev_time,
            current_snapshot_time=latest.created_at,
            assets_added=latest.assets_added,
            assets_removed=latest.assets_removed,
            exposures_added=latest.exposures_added,
            exposures_resolved=latest.exposures_resolved,
            added_asset_names=[a[0] for a in added_assets],
            removed_asset_names=[],
            new_exposure_titles=[],
            diff_summary=latest.diff_summary,
        )

    # ========================================================================
    # 7. UNKNOWN ASSET REVIEW WORKFLOW
    # ========================================================================

    @classmethod
    def review_unknown_asset(
        cls,
        db: Session,
        workspace_id: str,
        asset_id: str,
        req: UnknownAssetReviewRequest,
    ) -> AssetModel:
        """
        Executes analyst review on an unknown or shadow asset:
        - APPROVE: Marks asset ACTIVE and resolves UNKNOWN_ASSET exposure.
        - ASSIGN_OWNER: Assigns operational owner and team.
        - MAP_TO_EXISTING: Merges or links to existing approved asset ID.
        - MARK_UNAUTHORIZED: Flags asset as unapproved external infrastructure.
        - ADD_TO_WATCHLIST: Adds asset indicator to Section 53 Watchlist.
        """
        asset = db.query(AssetModel).filter(
            AssetModel.id == asset_id,
            AssetModel.workspace_id == workspace_id,
        ).first()

        if not asset:
            raise ValueError(f"Asset '{asset_id}' not found in workspace '{workspace_id}'.")

        action = req.action.upper()
        now = get_utc_now()

        if action == "APPROVE":
            asset.status = AssetStatusEnum.ACTIVE.value
            if req.owner:
                asset.owner = req.owner
                asset.ownership_confidence = OwnershipConfidenceEnum.MANUAL.value
            if req.team:
                asset.team = req.team
            if req.criticality:
                asset.criticality = req.criticality.value

            # Resolve UNKNOWN_ASSET exposure
            cls.resolve_asset_exposure(
                db=db,
                workspace_id=workspace_id,
                asset_id=asset.id,
                exposure_type=ExposureTypeEnum.UNKNOWN_ASSET.value,
                notes=req.notes,
                actor=req.actor,
            )

        elif action == "ASSIGN_OWNER":
            if not req.owner:
                raise ValueError("Owner name/email is required for ASSIGN_OWNER action.")
            asset.owner = req.owner
            asset.team = req.team or asset.team
            asset.status = AssetStatusEnum.ACTIVE.value
            asset.ownership_confidence = OwnershipConfidenceEnum.MANUAL.value
            if req.criticality:
                asset.criticality = req.criticality.value

        elif action == "MAP_TO_EXISTING":
            if not req.target_asset_id:
                raise ValueError("target_asset_id is required for MAP_TO_EXISTING action.")
            asset.external_id = req.target_asset_id
            asset.status = AssetStatusEnum.ACTIVE.value

        elif action == "MARK_UNAUTHORIZED":
            asset.status = AssetStatusEnum.DISCOVERED.value
            asset.criticality = CriticalityEnum.CRITICAL.value
            # Escalate or create exposure
            exp = db.query(ExposureModel).filter(
                ExposureModel.asset_id == asset.id,
                ExposureModel.exposure_type == ExposureTypeEnum.UNKNOWN_ASSET.value,
            ).first()
            if exp:
                exp.severity = ExposureSeverityEnum.CRITICAL.value
                exp.title = f"Unauthorized External Asset: {asset.display_name}"
            else:
                exp = ExposureModel(
                    id=generate_uuid(),
                    workspace_id=workspace_id,
                    asset_id=asset.id,
                    exposure_type=ExposureTypeEnum.UNKNOWN_ASSET.value,
                    title=f"Unauthorized External Asset: {asset.display_name}",
                    description=f"Asset '{asset.display_name}' was reviewed and explicitly marked UNAUTHORIZED.",
                    status=ExposureStatusEnum.OPEN.value,
                    severity=ExposureSeverityEnum.CRITICAL.value,
                    confidence=1.0,
                    remediation_guidance="Initiate immediate containment or firewall block rule.",
                    first_seen_at=now,
                    last_seen_at=now,
                    created_at=now,
                    updated_at=now,
                )
                db.add(exp)

        elif action == "ADD_TO_WATCHLIST":
            # Section 53 integration: Find or create attack surface watchlist
            wl = db.query(WatchlistModel).filter(
                WatchlistModel.workspace_id == workspace_id,
                WatchlistModel.name == "Attack Surface Watchlist",
            ).first()
            if not wl:
                wl = WatchlistModel(
                    id=generate_uuid(),
                    workspace_id=workspace_id,
                    name="Attack Surface Watchlist",
                    status="ACTIVE",
                    priority="HIGH",
                    created_by=req.actor,
                )
                db.add(wl)
                db.flush()

            watched = WatchedIndicatorModel(
                id=generate_uuid(),
                workspace_id=workspace_id,
                watchlist_id=wl.id,
                indicator_type="DOMAIN" if asset.asset_type in ("DOMAIN", "SUBDOMAIN") else "IP",
                raw_value=asset.canonical_name,
                display_value=asset.display_name,
                normalized_value=asset.canonical_name,
                monitoring_status="ACTIVE",
                priority="HIGH",
                created_by=req.actor,
            )
            db.add(watched)

        else:
            raise ValueError(f"Unsupported unknown asset review action '{action}'.")

        asset.updated_at = now
        cls.recompute_asset_risk(db, workspace_id, asset)

        # Audit log entry
        audit = AuditLogModel(
            id=generate_uuid(),
            action=f"ASSET_REVIEW_{action}",
            user=req.actor,
            resource_type="asset",
            resource_id=asset.id,
            details=json.dumps({"action": action, "notes": req.notes, "canonical_name": asset.canonical_name}),
            metadata_json=json.dumps({"action": action, "notes": req.notes}),
            timestamp=now,
        )
        db.add(audit)
        db.flush()
        return asset

    @classmethod
    def resolve_asset_exposure(
        cls,
        db: Session,
        workspace_id: str,
        asset_id: str,
        exposure_type: str,
        notes: str,
        actor: str,
    ) -> None:
        """Resolves an active exposure on an asset."""
        now = get_utc_now()
        exps = db.query(ExposureModel).filter(
            ExposureModel.workspace_id == workspace_id,
            ExposureModel.asset_id == asset_id,
            ExposureModel.exposure_type == exposure_type,
            ExposureModel.status == ExposureStatusEnum.OPEN.value,
        ).all()

        for exp in exps:
            exp.status = ExposureStatusEnum.RESOLVED.value
            exp.resolved_at = now
            exp.resolved_by = actor
            exp.resolution_notes = notes
            exp.updated_at = now

        db.flush()

    # ========================================================================
    # 8. OVERVIEW STATS & QUERY OPERATIONS
    # ========================================================================

    @classmethod
    def get_overview_stats(cls, db: Session, workspace_id: str) -> AttackSurfaceOverviewStats:
        """Retrieves high-level SOC Attack Surface intelligence metrics."""
        total_assets = db.query(AssetModel).filter(AssetModel.workspace_id == workspace_id).count()
        publicly_exposed = db.query(AssetModel).filter(
            AssetModel.workspace_id == workspace_id,
            AssetModel.exposure_state == ExposureStateEnum.PUBLICLY_EXPOSED.value,
        ).count()
        internally_reachable = db.query(AssetModel).filter(
            AssetModel.workspace_id == workspace_id,
            AssetModel.exposure_state == ExposureStateEnum.INTERNALLY_REACHABLE.value,
        ).count()
        unknown_assets = db.query(AssetModel).filter(
            AssetModel.workspace_id == workspace_id,
            or_(
                AssetModel.status == AssetStatusEnum.DISCOVERED.value,
                AssetModel.owner == "Unknown",
            ),
        ).count()
        critical_assets = db.query(AssetModel).filter(
            AssetModel.workspace_id == workspace_id,
            AssetModel.criticality == CriticalityEnum.CRITICAL.value,
        ).count()
        high_risk_assets = db.query(AssetModel).filter(
            AssetModel.workspace_id == workspace_id,
            AssetModel.risk_score >= 50.0,
        ).count()
        open_exposures = db.query(ExposureModel).filter(
            ExposureModel.workspace_id == workspace_id,
            ExposureModel.status == ExposureStatusEnum.OPEN.value,
        ).count()
        critical_exposures = db.query(ExposureModel).filter(
            ExposureModel.workspace_id == workspace_id,
            ExposureModel.status == ExposureStatusEnum.OPEN.value,
            ExposureModel.severity == ExposureSeverityEnum.CRITICAL.value,
        ).count()
        scopes_count = db.query(AttackSurfaceScopeModel).filter(
            AttackSurfaceScopeModel.workspace_id == workspace_id,
            AttackSurfaceScopeModel.is_authorized == True,
        ).count()

        # Group by asset type
        by_type_rows = db.query(
            AssetModel.asset_type, func.count(AssetModel.id)
        ).filter(AssetModel.workspace_id == workspace_id).group_by(AssetModel.asset_type).all()
        by_type = {r[0]: r[1] for r in by_type_rows}

        # Group by exposure state
        by_exp_rows = db.query(
            AssetModel.exposure_state, func.count(AssetModel.id)
        ).filter(AssetModel.workspace_id == workspace_id).group_by(AssetModel.exposure_state).all()
        by_exposure = {r[0]: r[1] for r in by_exp_rows}

        # Group by criticality
        by_crit_rows = db.query(
            AssetModel.criticality, func.count(AssetModel.id)
        ).filter(AssetModel.workspace_id == workspace_id).group_by(AssetModel.criticality).all()
        by_criticality = {r[0]: r[1] for r in by_crit_rows}

        # Recent exposures
        recent_exp = db.query(ExposureModel).filter(
            ExposureModel.workspace_id == workspace_id,
            ExposureModel.status == ExposureStatusEnum.OPEN.value,
        ).order_by(desc(ExposureModel.created_at)).limit(5).all()

        return AttackSurfaceOverviewStats(
            total_assets=total_assets,
            publicly_exposed_assets=publicly_exposed,
            internally_reachable_assets=internally_reachable,
            unknown_assets_count=unknown_assets,
            critical_assets_count=critical_assets,
            high_risk_assets_count=high_risk_assets,
            open_exposures_count=open_exposures,
            critical_exposures_count=critical_exposures,
            by_type=by_type,
            by_exposure=by_exposure,
            by_criticality=by_criticality,
            authorized_scopes_count=scopes_count,
            recent_exposures=[ExposureRead.model_validate(e) for e in recent_exp],
        )

    @classmethod
    def list_assets(
        cls,
        db: Session,
        workspace_id: str,
        asset_type: Optional[str] = None,
        status: Optional[str] = None,
        exposure_state: Optional[str] = None,
        criticality: Optional[str] = None,
        q: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[AssetModel], int]:
        """Queries paginated assets with server-side filters."""
        query = db.query(AssetModel).filter(AssetModel.workspace_id == workspace_id)

        if asset_type and asset_type.upper() != "ALL":
            query = query.filter(AssetModel.asset_type == asset_type.upper())
        if status and status.upper() != "ALL":
            query = query.filter(AssetModel.status == status.upper())
        if exposure_state and exposure_state.upper() != "ALL":
            query = query.filter(AssetModel.exposure_state == exposure_state.upper())
        if criticality and criticality.upper() != "ALL":
            query = query.filter(AssetModel.criticality == criticality.upper())
        if q and q.strip():
            term = f"%{q.strip().lower()}%"
            query = query.filter(
                or_(
                    AssetModel.canonical_name.ilike(term),
                    AssetModel.display_name.ilike(term),
                    AssetModel.owner.ilike(term),
                    AssetModel.team.ilike(term),
                )
            )

        total = query.count()
        items = query.order_by(
            desc(AssetModel.risk_score), desc(AssetModel.last_seen_at)
        ).offset(offset).limit(limit).all()
        return items, total

    @classmethod
    def get_asset_detail(
        cls, db: Session, workspace_id: str, asset_id: str
    ) -> AssetDetail:
        """Retrieves full forensic asset detail including exposures, services, and relationships."""
        asset = db.query(AssetModel).filter(
            AssetModel.id == asset_id,
            AssetModel.workspace_id == workspace_id,
        ).first()

        if not asset:
            raise ValueError(f"Asset '{asset_id}' not found in workspace '{workspace_id}'.")

        # Exposures
        exposures = [ExposureRead.model_validate(e) for e in (asset.exposures or [])]

        # Services
        services = [AssetServiceRead.model_validate(s) for s in (asset.services or [])]

        # Graph neighbors
        neighbors: List[Dict[str, Any]] = []
        try:
            rels = db.query(RelationshipModel).filter(
                RelationshipModel.workspace_id == workspace_id,
                or_(
                    RelationshipModel.source_id == asset.canonical_name,
                    RelationshipModel.target_id == asset.canonical_name,
                ),
            ).limit(15).all()
            for r in rels:
                neighbors.append({
                    "relationship_type": r.relationship_type,
                    "source_type": r.source_type,
                    "source_id": r.source_id,
                    "target_type": r.target_type,
                    "target_id": r.target_id,
                    "confidence": r.confidence,
                })
        except Exception:
            pass

        return AssetDetail(
            id=asset.id,
            workspace_id=asset.workspace_id,
            asset_type=AssetTypeEnum(asset.asset_type),
            canonical_name=asset.canonical_name,
            display_name=asset.display_name,
            status=AssetStatusEnum(asset.status),
            exposure_state=ExposureStateEnum(asset.exposure_state),
            criticality=CriticalityEnum(asset.criticality),
            owner=asset.owner,
            team=asset.team,
            business_unit=asset.business_unit,
            environment=asset.environment,
            ownership_confidence=OwnershipConfidenceEnum(asset.ownership_confidence),
            source=AssetSourceEnum(asset.source),
            external_id=asset.external_id,
            canonical_entity_id=asset.canonical_entity_id,
            risk_score=asset.risk_score,
            risk_level=asset.risk_level,
            active_finding_count=asset.active_finding_count,
            active_exposure_count=asset.active_exposure_count,
            first_seen_at=asset.first_seen_at,
            last_seen_at=asset.last_seen_at,
            last_scanned_at=asset.last_scanned_at,
            last_analyzed_at=asset.last_analyzed_at,
            metadata=asset.metadata_dict,
            created_at=asset.created_at,
            updated_at=asset.updated_at,
            exposures=exposures,
            services=services,
            graph_neighbors=neighbors,
        )

    @classmethod
    def update_asset(
        cls, db: Session, workspace_id: str, asset_id: str, req: AssetUpdateRequest
    ) -> AssetModel:
        """Updates asset ownership, criticality, environment, or status."""
        asset = db.query(AssetModel).filter(
            AssetModel.id == asset_id,
            AssetModel.workspace_id == workspace_id,
        ).first()
        if not asset:
            raise ValueError(f"Asset '{asset_id}' not found in workspace '{workspace_id}'.")

        now = get_utc_now()
        if req.display_name is not None:
            asset.display_name = req.display_name
        if req.status is not None:
            asset.status = req.status.value
        if req.exposure_state is not None:
            asset.exposure_state = req.exposure_state.value
        if req.criticality is not None:
            asset.criticality = req.criticality.value
        if req.owner is not None:
            asset.owner = req.owner
            if req.owner != "Unknown":
                asset.ownership_confidence = OwnershipConfidenceEnum.MANUAL.value
        if req.team is not None:
            asset.team = req.team
        if req.business_unit is not None:
            asset.business_unit = req.business_unit
        if req.environment is not None:
            asset.environment = req.environment
        if req.metadata is not None:
            curr = dict(asset.metadata_dict)
            curr.update(req.metadata)
            asset.metadata_json = json.dumps(curr)

        asset.updated_at = now
        cls.recompute_asset_risk(db, workspace_id, asset)
        db.flush()
        return asset

    @classmethod
    def list_exposures(
        cls,
        db: Session,
        workspace_id: str,
        asset_id: Optional[str] = None,
        exposure_type: Optional[str] = None,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[ExposureModel], int]:
        """Queries exposures across assets with filtering."""
        query = db.query(ExposureModel).filter(ExposureModel.workspace_id == workspace_id)
        if asset_id:
            query = query.filter(ExposureModel.asset_id == asset_id)
        if exposure_type and exposure_type.upper() != "ALL":
            query = query.filter(ExposureModel.exposure_type == exposure_type.upper())
        if status and status.upper() != "ALL":
            query = query.filter(ExposureModel.status == status.upper())
        if severity and severity.upper() != "ALL":
            query = query.filter(ExposureModel.severity == severity.upper())

        total = query.count()
        items = query.order_by(
            desc(ExposureModel.created_at)
        ).offset(offset).limit(limit).all()
        return items, total

    @classmethod
    def resolve_exposure_by_id(
        cls,
        db: Session,
        workspace_id: str,
        exposure_id: str,
        notes: str,
        actor: str,
    ) -> ExposureModel:
        """Resolves an exposure record by its unique ID."""
        now = get_utc_now()
        exp = db.query(ExposureModel).filter(
            ExposureModel.id == exposure_id,
            ExposureModel.workspace_id == workspace_id,
        ).first()
        if not exp:
            raise ValueError(f"Exposure '{exposure_id}' not found in workspace '{workspace_id}'.")

        exp.status = ExposureStatusEnum.RESOLVED.value
        exp.resolved_at = now
        exp.resolved_by = actor
        exp.resolution_notes = notes
        exp.updated_at = now

        # Update parent asset active_exposure_count
        asset = db.query(AssetModel).filter(AssetModel.id == exp.asset_id).first()
        if asset:
            asset.active_exposure_count = max(0, (asset.active_exposure_count or 1) - 1)
            cls.recompute_asset_risk(db, workspace_id, asset)

        db.flush()
        return exp

    @classmethod
    def get_unknown_asset_queue(
        cls,
        db: Session,
        workspace_id: str,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """Focused queue of unmapped/unknown assets requiring review."""
        query = db.query(AssetModel).filter(
            AssetModel.workspace_id == workspace_id,
            or_(
                AssetModel.status == AssetStatusEnum.DISCOVERED.value,
                AssetModel.owner == "Unknown",
                AssetModel.ownership_confidence == OwnershipConfidenceEnum.UNKNOWN.value,
            ),
        )
        total = query.count()
        assets = query.order_by(
            desc(AssetModel.risk_score), desc(AssetModel.last_seen_at)
        ).offset(offset).limit(limit).all()

        queue_items = []
        for a in assets:
            queue_items.append({
                "id": a.id,
                "asset_type": a.asset_type,
                "canonical_name": a.canonical_name,
                "display_name": a.display_name,
                "exposure_state": a.exposure_state,
                "criticality": a.criticality,
                "risk_score": a.risk_score,
                "risk_level": a.risk_level,
                "source": a.source,
                "first_seen_at": a.first_seen_at.isoformat() if a.first_seen_at else None,
                "last_seen_at": a.last_seen_at.isoformat() if a.last_seen_at else None,
                "reason": "Unapproved asset observed via telemetry or missing assigned corporate owner",
                "active_finding_count": a.active_finding_count,
                "active_exposure_count": a.active_exposure_count,
            })
        return queue_items, total

    @classmethod
    def list_scopes(cls, db: Session, workspace_id: str) -> List[AttackSurfaceScopeModel]:
        """Lists authorized discovery scopes for the workspace."""
        return db.query(AttackSurfaceScopeModel).filter(
            AttackSurfaceScopeModel.workspace_id == workspace_id
        ).order_by(desc(AttackSurfaceScopeModel.created_at)).all()

    @classmethod
    def create_scope(
        cls, db: Session, workspace_id: str, req: AttackSurfaceScopeCreateRequest, actor: str = "SOC Admin"
    ) -> AttackSurfaceScopeModel:
        """Registers a tenant-authorized discovery scope with SSRF verification."""
        target = req.target.strip().lower()
        scope_type = req.scope_type.value if hasattr(req.scope_type, "value") else str(req.scope_type)

        # Enforce strict SSRF protection on scope creation
        if scope_type in (ScopeTypeEnum.IP.value, ScopeTypeEnum.CIDR.value):
            ip_check = target.split("/")[0]
            if not SSRFProtector.is_safe_public_ip(ip_check):
                raise ValueError(f"IP target '{target}' violates SSRF safety controls (private/loopback/link-local address).")
        elif scope_type == ScopeTypeEnum.DOMAIN.value:
            dom_check = target.lstrip("*.")
            if dom_check in ("localhost", "127.0.0.1", "0.0.0.0", "::1", "169.254.169.254", "metadata.google.internal", "instance-data"):
                raise ValueError(f"Domain target '{target}' violates SSRF safety controls (loopback/metadata address).")
            if any(char in dom_check for char in ("/", "\\", "@", ":", "#", "?", " ", "\t", "\r", "\n")):
                raise ValueError(f"Domain target '{target}' contains invalid or prohibited URL characters.")

        existing = db.query(AttackSurfaceScopeModel).filter(
            AttackSurfaceScopeModel.workspace_id == workspace_id,
            AttackSurfaceScopeModel.target == target,
        ).first()
        if existing:
            existing.is_authorized = req.is_authorized
            existing.description = req.description
            existing.updated_at = get_utc_now()
            db.flush()
            return existing

        now = get_utc_now()
        scope = AttackSurfaceScopeModel(
            id=generate_uuid(),
            workspace_id=workspace_id,
            scope_type=req.scope_type.value,
            target=target,
            is_authorized=req.is_authorized,
            description=req.description,
            created_by=actor,
            created_at=now,
            updated_at=now,
        )
        db.add(scope)
        db.flush()
        return scope

    @classmethod
    def delete_scope(cls, db: Session, workspace_id: str, scope_id: str) -> bool:
        """Removes a discovery scope."""
        scope = db.query(AttackSurfaceScopeModel).filter(
            AttackSurfaceScopeModel.id == scope_id,
            AttackSurfaceScopeModel.workspace_id == workspace_id,
        ).first()
        if not scope:
            return False
        db.delete(scope)
        db.flush()
        return True

    @classmethod
    def get_asset_timeline(cls, db: Session, workspace_id: str, asset_id: str) -> List[Dict[str, Any]]:
        """Extracts chronological lifecycle events and exposures for an asset."""
        events: List[Dict[str, Any]] = []
        asset = db.query(AssetModel).filter(
            AssetModel.id == asset_id,
            AssetModel.workspace_id == workspace_id,
        ).first()
        if not asset:
            return []

        # Discovery event
        events.append({
            "timestamp": asset.first_seen_at.isoformat() if asset.first_seen_at else asset.created_at.isoformat(),
            "event_type": "ASSET_DISCOVERED",
            "title": f"Asset {asset.canonical_name} first observed",
            "description": f"Identified via {asset.source} with initial status {asset.status}",
            "severity": "INFO",
        })

        # Exposures
        for exp in (asset.exposures or []):
            events.append({
                "timestamp": exp.first_seen_at.isoformat() if exp.first_seen_at else exp.created_at.isoformat(),
                "event_type": f"EXPOSURE_{exp.exposure_type}",
                "title": f"Exposure flagged: {exp.title}",
                "description": exp.description,
                "severity": exp.severity,
            })
            if exp.status == ExposureStatusEnum.RESOLVED.value and exp.resolved_at:
                events.append({
                    "timestamp": exp.resolved_at.isoformat(),
                    "event_type": "EXPOSURE_RESOLVED",
                    "title": f"Exposure resolved: {exp.title}",
                    "description": f"Resolved by {exp.resolved_by or 'analyst'}: {exp.resolution_notes or ''}",
                    "severity": "INFO",
                })

        # Audit logs
        logs = db.query(AuditLogModel).filter(
            AuditLogModel.resource_type == "asset",
            AuditLogModel.resource_id == asset_id,
        ).order_by(desc(AuditLogModel.timestamp)).limit(20).all()
        for log in logs:
            events.append({
                "timestamp": log.timestamp.isoformat() if log.timestamp else get_utc_now().isoformat(),
                "event_type": log.action,
                "title": f"Analyst Action: {log.action}",
                "description": f"User {log.user}: {log.details}",
                "severity": "INFO",
            })

        events.sort(key=lambda x: x["timestamp"], reverse=True)
        return events
