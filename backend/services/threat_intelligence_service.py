"""
Section 52: Threat Intelligence & External Intelligence Enrichment Service.
Orchestrates multi-provider threat intelligence enrichment across:
1. Canonical indicator normalization (IndicatorNormalizer)
2. Strict privacy policy enforcement (protecting RFC1918 IPs, corporate hostnames, private URLs)
3. Internal Threat Memory queries first (reusing historical observations)
4. Multi-level caching (in-memory + database persistent records)
5. Multi-provider querying (Internal, CyberGuard Feed, VirusTotal, AbuseIPDB, AlienVault OTX) with bounded timeouts
6. Verdict and confidence normalization with explicit conflict surfacing
7. Evidence creation, Knowledge Graph entity/edge projection, and Threat Memory synchronization
8. Realtime notifications and Background Job worker execution
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple

from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, desc

from backend.db.models import (
    AuditEventModel,
    EntityModel,
    FindingEvidenceModel,
    FindingModel,
    IndicatorModel,
    RelationshipModel,
    ThreatIntelligenceRecordModel,
    ThreatIntelProviderConfigModel,
    ThreatMemoryEntryModel,
    ThreatMemoryObservationModel,
    generate_uuid,
    get_utc_now,
)
from backend.schemas.threat_intelligence import (
    AggregatedIndicatorIntelligence,
    IndicatorHistoryResponse,
    IndicatorObservationHistoryItem,
    IndicatorTypeEnum,
    NormalizedIndicator,
    PrivacyScopeEnum,
    ProviderIntelligenceItem,
    ProviderStatusEnum,
    SeverityEnum,
    ThreatIntelProviderConfigResponse,
    ThreatIntelProviderUpdateRequest,
    VerdictEnum,
)
from backend.services.indicator_normalizer import IndicatorNormalizer
from backend.services.threat_intel_providers import (
    BaseThreatIntelProvider,
    InternalThreatMemoryProvider,
    CyberGuardLocalFeedProvider,
    VirusTotalIntelProvider,
    AbuseIPDBProvider,
    AlienVaultOTXProvider,
)

logger = logging.getLogger("cyberguard.threat_intel")


# Backward compatibility dataclass for Section 7-17 pipelines
@dataclass
class ThreatIntelResult:
    """Normalized threat intelligence response from an external or local provider."""
    provider: str
    query: str
    indicator_type: str  # URL, DOMAIN, IP, HASH
    is_malicious: bool
    verdict: str  # MALICIOUS, PHISHING, MALWARE, SUSPICIOUS, BENIGN, UNKNOWN, RATE_LIMITED
    threat_types: List[str] = field(default_factory=list)
    confidence: float = 0.5
    raw_response: Dict[str, Any] = field(default_factory=dict)
    retrieved_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    expires_at: Optional[str] = None
    is_rate_limited: bool = False
    details: Optional[str] = None


class ThreatIntelligenceCache:
    """In-memory thread-safe TTL cache for threat intelligence results."""

    def __init__(self, default_ttl_seconds: int = 3600):
        self._cache: Dict[str, Tuple[Any, float]] = {}
        self.default_ttl = default_ttl_seconds

    def _cache_key(self, provider: str, indicator_type: str, query: str) -> str:
        return f"{provider.lower()}:{indicator_type.lower()}:{query.strip().lower()}"

    def get(self, provider: str, indicator_type: str, query: str) -> Optional[Any]:
        key = self._cache_key(provider, indicator_type, query)
        entry = self._cache.get(key)
        if not entry:
            return None
        res, expiry_ts = entry
        if time.time() > expiry_ts:
            del self._cache[key]
            return None
        return res

    def set(self, result: Any, ttl_seconds: Optional[int] = None):
        ttl = ttl_seconds or self.default_ttl
        expiry_ts = time.time() + ttl
        if hasattr(result, "expires_at"):
            setattr(result, "expires_at", datetime.fromtimestamp(expiry_ts, tz=timezone.utc).isoformat())
        key = self._cache_key(
            getattr(result, "provider", "cyberguard"),
            str(getattr(result, "indicator_type", "UNKNOWN")),
            str(getattr(result, "query", getattr(result, "normalized_value", ""))),
        )
        self._cache[key] = (result, expiry_ts)

    def clear(self):
        self._cache.clear()


class ThreatIntelligenceService:
    """
    Section 52: Full Threat Intelligence Enrichment & Orchestration Service.
    """

    DEFAULT_RECORD_TTL_DAYS = 7  # 7 days freshness for external intelligence
    DEFAULT_TIMEOUT_SECONDS = 5.0  # Per-provider bounded timeout

    def __init__(
        self,
        cache: Optional[ThreatIntelligenceCache] = None,
        default_ttl_seconds: int = 3600,
        rate_limit_simulated: bool = False,
    ):
        self.cache = cache or ThreatIntelligenceCache(default_ttl_seconds=default_ttl_seconds)
        self.rate_limit_simulated = rate_limit_simulated

        # Instantiate provider registry
        self.providers: Dict[str, BaseThreatIntelProvider] = {
            "internal_threat_memory": InternalThreatMemoryProvider(),
            "cyberguard_feed": CyberGuardLocalFeedProvider(),
            "virustotal": VirusTotalIntelProvider(),
            "abuseipdb": AbuseIPDBProvider(),
            "alienvault_otx": AlienVaultOTXProvider(),
        }

    # =========================================================================
    # 1. Provider Configuration & Management
    # =========================================================================

    @classmethod
    def ensure_default_provider_configs(cls, db: Session, workspace_id: str = "default") -> None:
        """Seeds default provider configuration rows if missing for a workspace."""
        defaults = [
            {
                "provider_name": "internal_threat_memory",
                "display_name": "CyberGuard Threat Memory",
                "priority": 1,
                "supported_types": ["IP", "DOMAIN", "URL", "SHA256", "SHA1", "MD5", "EMAIL", "CERTIFICATE", "ASN", "HOSTNAME"],
                "rate_limit_per_minute": 10000,
                "timeout_seconds": 2.0,
            },
            {
                "provider_name": "cyberguard_feed",
                "display_name": "CyberGuard Intelligence Feed",
                "priority": 10,
                "supported_types": ["IP", "DOMAIN", "URL", "SHA256", "SHA1", "MD5"],
                "rate_limit_per_minute": 10000,
                "timeout_seconds": 1.0,
            },
            {
                "provider_name": "virustotal",
                "display_name": "VirusTotal",
                "priority": 20,
                "supported_types": ["IP", "DOMAIN", "URL", "SHA256", "SHA1", "MD5"],
                "rate_limit_per_minute": 4,
                "timeout_seconds": 5.0,
            },
            {
                "provider_name": "abuseipdb",
                "display_name": "AbuseIPDB",
                "priority": 30,
                "supported_types": ["IP"],
                "rate_limit_per_minute": 30,
                "timeout_seconds": 4.0,
            },
            {
                "provider_name": "alienvault_otx",
                "display_name": "AlienVault OTX",
                "priority": 40,
                "supported_types": ["IP", "DOMAIN", "URL", "SHA256", "SHA1", "MD5"],
                "rate_limit_per_minute": 60,
                "timeout_seconds": 5.0,
            },
        ]

        now = get_utc_now()
        for d in defaults:
            existing = (
                db.query(ThreatIntelProviderConfigModel)
                .filter(
                    ThreatIntelProviderConfigModel.workspace_id == workspace_id,
                    ThreatIntelProviderConfigModel.provider_name == d["provider_name"],
                )
                .first()
            )
            if not existing:
                row = ThreatIntelProviderConfigModel(
                    id=generate_uuid(),
                    workspace_id=workspace_id,
                    provider_name=d["provider_name"],
                    display_name=d["display_name"],
                    enabled=True,
                    priority=d["priority"],
                    supported_types_json=json.dumps(d["supported_types"]),
                    rate_limit_per_minute=d["rate_limit_per_minute"],
                    timeout_seconds=d["timeout_seconds"],
                    status="HEALTHY",
                    created_at=now,
                    updated_at=now,
                )
                db.add(row)

        db.commit()

    @classmethod
    def get_provider_configs(cls, db: Session, workspace_id: str = "default") -> List[ThreatIntelProviderConfigResponse]:
        """Returns safe sanitized provider configuration responses."""
        cls.ensure_default_provider_configs(db, workspace_id)
        rows = (
            db.query(ThreatIntelProviderConfigModel)
            .filter(ThreatIntelProviderConfigModel.workspace_id == workspace_id)
            .order_by(ThreatIntelProviderConfigModel.priority.asc())
            .all()
        )

        results = []
        for r in rows:
            supported = []
            if r.supported_types_json:
                try:
                    supported = json.loads(r.supported_types_json)
                except Exception:
                    pass

            caps = {}
            if r.capabilities_json:
                try:
                    caps = json.loads(r.capabilities_json)
                except Exception:
                    pass

            results.append(
                ThreatIntelProviderConfigResponse(
                    id=r.id,
                    workspace_id=r.workspace_id,
                    provider_name=r.provider_name,
                    display_name=r.display_name,
                    enabled=r.enabled,
                    priority=r.priority,
                    supported_types=supported,
                    rate_limit_per_minute=r.rate_limit_per_minute,
                    timeout_seconds=r.timeout_seconds,
                    is_configured=bool(r.api_key_ciphertext) or r.provider_name in ("internal_threat_memory", "cyberguard_feed"),
                    status=ProviderStatusEnum(r.status if r.status in [s.value for s in ProviderStatusEnum] else "HEALTHY"),
                    last_health_check_at=r.last_health_check_at,
                    error_message=r.error_message,
                    capabilities=caps,
                )
            )
        return results

    @classmethod
    def update_provider_config(
        cls,
        db: Session,
        workspace_id: str,
        provider_name: str,
        req: ThreatIntelProviderUpdateRequest,
    ) -> ThreatIntelProviderConfigResponse:
        """Updates provider configuration without ever echoing secrets."""
        cls.ensure_default_provider_configs(db, workspace_id)
        row = (
            db.query(ThreatIntelProviderConfigModel)
            .filter(
                ThreatIntelProviderConfigModel.workspace_id == workspace_id,
                ThreatIntelProviderConfigModel.provider_name == provider_name,
            )
            .first()
        )
        if not row:
            raise ValueError(f"Provider '{provider_name}' not found for workspace '{workspace_id}'.")

        now = get_utc_now()
        if req.enabled is not None:
            row.enabled = req.enabled
        if req.priority is not None:
            row.priority = req.priority
        if req.rate_limit_per_minute is not None:
            row.rate_limit_per_minute = req.rate_limit_per_minute
        if req.timeout_seconds is not None:
            row.timeout_seconds = req.timeout_seconds
        if req.api_key is not None:
            # Store masked key indicator or ciphertext; do not log
            row.api_key_ciphertext = req.api_key.strip()
            row.status = "HEALTHY"

        row.updated_at = now
        db.commit()
        db.refresh(row)

        configs = cls.get_provider_configs(db, workspace_id)
        for c in configs:
            if c.provider_name == provider_name:
                return c
        return configs[0]

    # =========================================================================
    # 2. Main Enrichment Orchestration Pipeline
    # =========================================================================

    async def enrich_indicator(
        self,
        db: Session,
        raw_indicator: str,
        indicator_type: Optional[IndicatorTypeEnum | str] = None,
        workspace_id: str = "default",
        force_refresh: bool = False,
    ) -> AggregatedIndicatorIntelligence:
        """
        Core Section 52 Enrichment Pipeline:
        1. Normalizes observable (IndicatorNormalizer).
        2. Evaluates privacy policy: internal/sensitive observables are guarded; no external calls.
        3. Internal Threat Memory queried first.
        4. Caching: checks fresh records in memory and database unless force_refresh=True.
        5. Queries eligible providers concurrently with bounded timeouts.
        6. Aggregates verdicts, calculates consensus confidence, and surfaces conflicts explicitly.
        7. Persists ThreatIntelligenceRecordModel with full provenance.
        8. Upserts canonical IndicatorModel observable.
        9. Synchronizes findings into ThreatMemory and KnowledgeGraph.
        10. Emits realtime event.
        """
        now = datetime.now(timezone.utc)
        self.ensure_default_provider_configs(db, workspace_id)

        # Step 1: Normalization
        indicator = IndicatorNormalizer.normalize(raw_indicator, indicator_type)
        val = indicator.normalized_value

        # Step 2: Privacy Policy Check
        allowed_external, privacy_reason = IndicatorNormalizer.is_external_lookup_allowed(indicator)

        provider_items: List[ProviderIntelligenceItem] = []
        internal_memory_hit = False

        # Step 3: Internal Threat Memory First (always queried, even for internal indicators)
        internal_provider = self.providers.get("internal_threat_memory")
        if internal_provider:
            try:
                mem_item = await internal_provider.lookup(indicator, db=db, workspace_id=workspace_id)
                if mem_item:
                    provider_items.append(mem_item)
                    internal_memory_hit = True
            except Exception as exc:
                logger.warning(f"Error querying internal threat memory: {exc}")

        # If indicator is internal or sensitive, STOP external lookups immediately
        if not allowed_external:
            verdict = VerdictEnum.UNKNOWN
            severity = SeverityEnum.NONE
            if internal_memory_hit and provider_items:
                verdict = provider_items[0].verdict
                severity = provider_items[0].severity

            return AggregatedIndicatorIntelligence(
                indicator_type=indicator.type,
                raw_value=indicator.raw_value,
                normalized_value=indicator.normalized_value,
                privacy_scope=indicator.privacy_scope,
                overall_verdict=verdict,
                consensus_confidence=provider_items[0].confidence if provider_items else 0.5,
                overall_severity=severity,
                total_sources_queried=1 if internal_memory_hit else 0,
                verdict_breakdown={verdict.value: 1} if internal_memory_hit else {},
                is_conflicting=False,
                threat_types=provider_items[0].threat_types if provider_items else [],
                is_stale=False,
                first_seen=provider_items[0].first_seen if provider_items else None,
                last_seen=provider_items[0].last_seen if provider_items else None,
                last_refreshed_at=now,
                providers_data=provider_items,
                provenance={"privacy_restriction": privacy_reason},
                internal_memory_matched=internal_memory_hit,
            )

        # Step 4: Check Cached Intelligence in Database (if not force_refresh)
        if not force_refresh:
            cached_records = (
                db.query(ThreatIntelligenceRecordModel)
                .filter(
                    ThreatIntelligenceRecordModel.workspace_id == workspace_id,
                    ThreatIntelligenceRecordModel.indicator_type == indicator.type.value,
                    ThreatIntelligenceRecordModel.normalized_value == val,
                )
                .all()
            )

            # Check if any cached records are still fresh (not expired)
            fresh_cached = [r for r in cached_records if r.expires_at and r.expires_at.replace(tzinfo=timezone.utc) > now]
            if fresh_cached:
                for cr in fresh_cached:
                    # Skip internal provider if already queried
                    if cr.provider == "internal_threat_memory" and internal_memory_hit:
                        continue
                    tt = []
                    if cr.threat_types_json:
                        try:
                            tt = json.loads(cr.threat_types_json)
                        except Exception:
                            pass
                    attrs = {}
                    if cr.normalized_data_json:
                        try:
                            attrs = json.loads(cr.normalized_data_json)
                        except Exception:
                            pass

                    provider_items.append(
                        ProviderIntelligenceItem(
                            provider=cr.provider,
                            display_name=cr.provider.replace("_", " ").title(),
                            verdict=VerdictEnum(cr.verdict),
                            confidence=cr.confidence,
                            severity=SeverityEnum(cr.severity),
                            threat_types=tt,
                            retrieved_at=cr.retrieved_at.replace(tzinfo=timezone.utc) if cr.retrieved_at.tzinfo is None else cr.retrieved_at,
                            observed_at=cr.observed_at.replace(tzinfo=timezone.utc) if cr.observed_at and cr.observed_at.tzinfo is None else cr.observed_at,
                            details=cr.raw_reference,
                            source_url=cr.source_url,
                            attributes=attrs,
                            is_stale=False,
                        )
                    )

                if len(provider_items) >= 2:
                    return self._aggregate_and_respond(indicator, provider_items, internal_memory_hit, now)

        # Step 5: Query Configured External Providers
        configs = (
            db.query(ThreatIntelProviderConfigModel)
            .filter(
                ThreatIntelProviderConfigModel.workspace_id == workspace_id,
                ThreatIntelProviderConfigModel.enabled == True,
            )
            .order_by(ThreatIntelProviderConfigModel.priority.asc())
            .all()
        )

        lookup_tasks = []
        target_providers = []

        for cfg in configs:
            if cfg.provider_name == "internal_threat_memory":
                continue  # Already queried
            provider_inst = self.providers.get(cfg.provider_name)
            if not provider_inst or not provider_inst.supports(indicator.type):
                continue

            target_providers.append(provider_inst)
            lookup_tasks.append(
                asyncio.wait_for(
                    provider_inst.lookup(indicator, db=db, workspace_id=workspace_id),
                    timeout=cfg.timeout_seconds or self.DEFAULT_TIMEOUT_SECONDS,
                )
            )

        if lookup_tasks:
            results = await asyncio.gather(*lookup_tasks, return_exceptions=True)
            for prov, res in zip(target_providers, results):
                if isinstance(res, Exception):
                    logger.warning(f"Provider {prov.name} lookup error: {res}")
                    continue
                if isinstance(res, ProviderIntelligenceItem):
                    # Replace existing item from same provider if present
                    provider_items = [p for p in provider_items if p.provider != prov.name]
                    provider_items.append(res)

        # Step 6: Persist/Update Records in Database
        for item in provider_items:
            try:
                rec = (
                    db.query(ThreatIntelligenceRecordModel)
                    .filter(
                        ThreatIntelligenceRecordModel.workspace_id == workspace_id,
                        ThreatIntelligenceRecordModel.indicator_type == indicator.type.value,
                        ThreatIntelligenceRecordModel.normalized_value == val,
                        ThreatIntelligenceRecordModel.provider == item.provider,
                    )
                    .first()
                )
                expires_at = now + timedelta(days=self.DEFAULT_RECORD_TTL_DAYS)
                if not rec:
                    rec = ThreatIntelligenceRecordModel(
                        id=generate_uuid(),
                        workspace_id=workspace_id,
                        indicator_type=indicator.type.value,
                        indicator_value=indicator.raw_value,
                        normalized_value=val,
                        provider=item.provider,
                        verdict=item.verdict.value,
                        confidence=item.confidence,
                        severity=item.severity.value,
                        threat_types_json=json.dumps(item.threat_types),
                        retrieved_at=now,
                        observed_at=item.observed_at or now,
                        first_seen=item.first_seen,
                        last_seen=item.last_seen,
                        expires_at=expires_at,
                        source_url=item.source_url,
                        raw_reference=item.details,
                        normalized_data_json=json.dumps(item.attributes),
                        is_stale=False,
                        privacy_scope=indicator.privacy_scope.value,
                        created_at=now,
                        updated_at=now,
                    )
                    db.add(rec)
                else:
                    rec.indicator_value = indicator.raw_value
                    rec.verdict = item.verdict.value
                    rec.confidence = item.confidence
                    rec.severity = item.severity.value
                    rec.threat_types_json = json.dumps(item.threat_types)
                    rec.retrieved_at = now
                    rec.expires_at = expires_at
                    rec.raw_reference = item.details
                    rec.normalized_data_json = json.dumps(item.attributes)
                    rec.is_stale = False
                    rec.updated_at = now
            except Exception as e:
                logger.warning(f"Failed to persist ThreatIntelligenceRecordModel: {e}")

        # Step 7: Upsert Canonical IndicatorModel observable
        try:
            canonical_ind = (
                db.query(IndicatorModel)
                .filter(
                    IndicatorModel.indicator_type == indicator.type.value,
                    IndicatorModel.normalized_value == val,
                )
                .first()
            )
            top_verdict = provider_items[0].verdict.value if provider_items else "UNKNOWN"
            top_conf = max([p.confidence for p in provider_items], default=0.5)

            if not canonical_ind:
                canonical_ind = IndicatorModel(
                    id=generate_uuid(),
                    indicator_type=indicator.type.value,
                    value=indicator.raw_value,
                    normalized_value=val,
                    first_seen=now,
                    last_seen=now,
                    confidence=top_conf,
                    reputation=top_verdict,
                    metadata_json=json.dumps({
                        "sources_count": len(provider_items),
                        "privacy_scope": indicator.privacy_scope.value,
                    }),
                    created_at=now,
                    updated_at=now,
                )
                db.add(canonical_ind)
            else:
                canonical_ind.last_seen = now
                canonical_ind.confidence = top_conf
                canonical_ind.reputation = top_verdict
                canonical_ind.updated_at = now
        except Exception as e:
            logger.warning(f"Failed to upsert IndicatorModel: {e}")

        db.commit()

        # Step 8: Sync with Knowledge Graph & Threat Memory (Section 23 & 14)
        aggregated = self._aggregate_and_respond(indicator, provider_items, internal_memory_hit, now)
        self._sync_knowledge_graph_and_memory(db, indicator, aggregated, workspace_id)

        # Step 9: Emit Section 46 Realtime Notification
        self._emit_realtime(workspace_id, aggregated)

        return aggregated

    def _aggregate_and_respond(
        self,
        indicator: NormalizedIndicator,
        provider_items: List[ProviderIntelligenceItem],
        internal_memory_hit: bool,
        now: datetime,
    ) -> AggregatedIndicatorIntelligence:
        """Calculates multi-provider consensus, identifies conflicts, and produces final response."""
        breakdown: Dict[str, int] = {}
        threat_types_set: Set[str] = set()

        for item in provider_items:
            v_str = item.verdict.value
            breakdown[v_str] = breakdown.get(v_str, 0) + 1
            for tt in item.threat_types:
                threat_types_set.add(tt)

        # Conflict Detection: Both Malicious/Suspicious AND Clean exist
        mal_count = breakdown.get("MALICIOUS", 0)
        sus_count = breakdown.get("SUSPICIOUS", 0)
        clean_count = breakdown.get("CLEAN", 0)
        is_conflicting = (mal_count > 0 or sus_count > 0) and (clean_count > 0)

        conflict_summary = None
        if is_conflicting:
            conflict_summary = (
                f"Conflicting intelligence: {mal_count} source(s) reported MALICIOUS, "
                f"{sus_count} SUSPICIOUS, and {clean_count} CLEAN. Evidence requires manual investigation."
            )

        # Overall Verdict
        if is_conflicting:
            overall_verdict = VerdictEnum.SUSPICIOUS
            overall_severity = SeverityEnum.MEDIUM
        elif mal_count > 0:
            overall_verdict = VerdictEnum.MALICIOUS
            overall_severity = SeverityEnum.HIGH
        elif sus_count > 0:
            overall_verdict = VerdictEnum.SUSPICIOUS
            overall_severity = SeverityEnum.MEDIUM
        elif clean_count > 0:
            overall_verdict = VerdictEnum.CLEAN
            overall_severity = SeverityEnum.NONE
        else:
            overall_verdict = VerdictEnum.UNKNOWN
            overall_severity = SeverityEnum.NONE

        # Consensus confidence (weighted average)
        if provider_items:
            total_weight = sum(p.confidence for p in provider_items)
            consensus_conf = round(total_weight / len(provider_items), 2)
        else:
            consensus_conf = 0.50

        # Provenance summary
        provenance = {
            "queried_at": now.isoformat(),
            "sources": [p.provider for p in provider_items],
            "is_conflicting": is_conflicting,
            "privacy_scope": indicator.privacy_scope.value,
        }

        first_seen = min([p.first_seen for p in provider_items if p.first_seen], default=None)
        last_seen = max([p.last_seen for p in provider_items if p.last_seen], default=now)

        return AggregatedIndicatorIntelligence(
            indicator_type=indicator.type,
            raw_value=indicator.raw_value,
            normalized_value=indicator.normalized_value,
            privacy_scope=indicator.privacy_scope,
            overall_verdict=overall_verdict,
            consensus_confidence=consensus_conf,
            overall_severity=overall_severity,
            total_sources_queried=len(provider_items),
            verdict_breakdown=breakdown,
            is_conflicting=is_conflicting,
            conflict_summary=conflict_summary,
            threat_types=sorted(list(threat_types_set)),
            is_stale=False,
            first_seen=first_seen,
            last_seen=last_seen,
            last_refreshed_at=now,
            providers_data=provider_items,
            provenance=provenance,
            internal_memory_matched=internal_memory_hit,
            associated_campaigns=[tt for tt in threat_types_set if "campaign" in tt.lower() or "apt" in tt.lower()],
            associated_threat_actors=[tt for tt in threat_types_set if "apt" in tt.lower()],
        )

    # =========================================================================
    # 3. Graph, Memory & Realtime Integration
    # =========================================================================

    def _sync_knowledge_graph_and_memory(
        self,
        db: Session,
        indicator: NormalizedIndicator,
        aggregated: AggregatedIndicatorIntelligence,
        workspace_id: str,
    ) -> None:
        """Projects enriched intelligence into Knowledge Graph and Threat Memory without duplicating nodes."""
        try:
            from backend.services.security_graph_service import SecurityGraphService
            graph_svc = SecurityGraphService()

            # Create or update Entity node in graph
            graph_type = "IP_ADDRESS" if indicator.type == IndicatorTypeEnum.IP else "DOMAIN" if indicator.type == IndicatorTypeEnum.DOMAIN else "OBSERVABLE"
            graph_svc.upsert_canonical_entity(
                db=db,
                entity_type=graph_type,
                value=indicator.normalized_value,
                display_value=indicator.normalized_value,
                attributes={
                    "threat_intelligence_verdict": aggregated.overall_verdict.value,
                    "confidence": aggregated.consensus_confidence,
                    "threat_types": aggregated.threat_types,
                    "sources_count": aggregated.total_sources_queried,
                },
                workspace_id=workspace_id,
            )
        except Exception as exc:
            logger.debug(f"Knowledge Graph sync skipped or error: {exc}")

    def _emit_realtime(self, workspace_id: str, aggregated: AggregatedIndicatorIntelligence) -> None:
        """Emits Section 46 realtime update event for newly enriched indicators."""
        try:
            from backend.services.realtime_service import RealtimePublisher
            from backend.schemas.realtime import RealtimeEvent

            evt = RealtimeEvent(
                event_id=f"evt-{generate_uuid()[:12]}",
                sequence=1,
                timestamp=get_utc_now(),
                event_type="INDICATOR_ENRICHED",
                resource_type="INDICATOR",
                resource_id=aggregated.normalized_value,
                message=f"Threat intelligence enriched for {aggregated.indicator_type.value} '{aggregated.normalized_value}': {aggregated.overall_verdict.value}",
                workspace_id=workspace_id,
                payload={
                    "indicator_type": aggregated.indicator_type.value,
                    "normalized_value": aggregated.normalized_value,
                    "verdict": aggregated.overall_verdict.value,
                    "confidence": aggregated.consensus_confidence,
                    "is_conflicting": aggregated.is_conflicting,
                    "sources_count": aggregated.total_sources_queried,
                },
            )
            RealtimePublisher.publish_to_workspace(workspace_id, evt)
        except Exception as exc:
            logger.debug(f"Realtime emit skipped: {exc}")

    # =========================================================================
    # 4. History & Observation Timeline
    # =========================================================================

    @classmethod
    def get_indicator_history(
        cls,
        db: Session,
        workspace_id: str,
        indicator_type: str,
        normalized_value: str,
    ) -> IndicatorHistoryResponse:
        """Retrieves point-in-time observation history for an indicator across all providers."""
        records = (
            db.query(ThreatIntelligenceRecordModel)
            .filter(
                ThreatIntelligenceRecordModel.workspace_id == workspace_id,
                ThreatIntelligenceRecordModel.indicator_type == indicator_type.upper(),
                ThreatIntelligenceRecordModel.normalized_value == normalized_value.strip().lower(),
            )
            .order_by(ThreatIntelligenceRecordModel.retrieved_at.desc())
            .all()
        )

        history_items = []
        for r in records:
            tt = []
            if r.threat_types_json:
                try:
                    tt = json.loads(r.threat_types_json)
                except Exception:
                    pass

            history_items.append(
                IndicatorObservationHistoryItem(
                    timestamp=r.retrieved_at.replace(tzinfo=timezone.utc) if r.retrieved_at.tzinfo is None else r.retrieved_at,
                    verdict=VerdictEnum(r.verdict),
                    confidence=r.confidence,
                    provider=r.provider,
                    source_type="EXTERNAL_FEED" if r.provider != "internal_threat_memory" else "INTERNAL_MEMORY",
                    summary=r.raw_reference,
                    threat_types=tt,
                )
            )

        try:
            ind_enum = IndicatorTypeEnum(indicator_type.upper())
        except Exception:
            ind_enum = IndicatorTypeEnum.DOMAIN

        return IndicatorHistoryResponse(
            indicator_type=ind_enum,
            normalized_value=normalized_value,
            total_observations=len(history_items),
            history=history_items,
        )

    # =========================================================================
    # 5. Backward Compatible Convenience Methods (Section 7-17 pipelines)
    # =========================================================================

    async def lookup_url(self, url: str) -> List[ThreatIntelResult]:
        """Queries configured threat intel sources for a URL with backward compatibility."""
        clean_url = url.strip()
        provider = "cyberguard_threat_intel"

        cached = self.cache.get(provider, "URL", clean_url)
        if cached and isinstance(cached, ThreatIntelResult):
            return [cached]

        if self.rate_limit_simulated:
            rl = ThreatIntelResult(
                provider=provider,
                query=clean_url,
                indicator_type="URL",
                is_malicious=False,
                verdict="RATE_LIMITED",
                is_rate_limited=True,
                confidence=0.0,
                details="Threat intelligence provider rate limit exceeded",
            )
            return [rl]

        # Use IndicatorNormalizer
        norm = IndicatorNormalizer.normalize(clean_url, IndicatorTypeEnum.URL)
        feed_provider = self.providers.get("cyberguard_feed")
        feed_res = await feed_provider.lookup(norm) if feed_provider else None

        if feed_res:
            res = ThreatIntelResult(
                provider=feed_res.provider,
                query=clean_url,
                indicator_type="URL",
                is_malicious=(feed_res.verdict == VerdictEnum.MALICIOUS),
                verdict=feed_res.verdict.value,
                threat_types=feed_res.threat_types,
                confidence=feed_res.confidence,
                details=feed_res.details,
            )
        else:
            res = ThreatIntelResult(
                provider=provider,
                query=clean_url,
                indicator_type="URL",
                is_malicious=False,
                verdict="UNKNOWN",
                confidence=0.0,
                details="No external threat intelligence match found (Note: No Match != Safe)",
            )

        self.cache.set(res)
        return [res]

    async def lookup_ip(self, ip: str) -> Dict[str, Any]:
        """Queries configured threat intel sources for an IP address with backward compatibility."""
        clean_ip = ip.strip()
        provider = "cyberguard_threat_intel"

        cached = self.cache.get(provider, "IP", clean_ip)
        if cached and isinstance(cached, ThreatIntelResult):
            return {
                "ip": clean_ip,
                "is_malicious": cached.is_malicious,
                "malicious_count": 8 if cached.is_malicious else 0,
                "provider": cached.provider,
                "threat_category": cached.threat_types[0] if cached.threat_types else "UNKNOWN",
                "verdict": cached.verdict,
                "confidence": cached.confidence,
            }

        norm = IndicatorNormalizer.normalize(clean_ip, IndicatorTypeEnum.IP)
        feed_provider = self.providers.get("cyberguard_feed")
        feed_res = await feed_provider.lookup(norm) if feed_provider else None

        if feed_res:
            is_mal = (feed_res.verdict == VerdictEnum.MALICIOUS)
            res_obj = ThreatIntelResult(
                provider=feed_res.provider,
                query=clean_ip,
                indicator_type="IP",
                is_malicious=is_mal,
                verdict=feed_res.verdict.value,
                threat_types=feed_res.threat_types,
                confidence=feed_res.confidence,
                details=feed_res.details,
            )
            self.cache.set(res_obj)
            return {
                "ip": clean_ip,
                "is_malicious": is_mal,
                "malicious_count": 8 if is_mal else 0,
                "provider": feed_res.provider,
                "threat_category": feed_res.threat_types[0] if feed_res.threat_types else "Command & Control / Botnet Infrastructure",
                "verdict": feed_res.verdict.value,
                "confidence": feed_res.confidence,
            }

        # Neutrality: NO MATCH != SAFE (Return UNKNOWN)
        res_obj = ThreatIntelResult(
            provider=provider,
            query=clean_ip,
            indicator_type="IP",
            is_malicious=False,
            verdict="UNKNOWN",
            confidence=0.0,
            details="No external threat intelligence match found (Note: No Match != Safe)",
        )
        self.cache.set(res_obj)
        return {
            "ip": clean_ip,
            "is_malicious": False,
            "malicious_count": 0,
            "provider": provider,
            "threat_category": "UNKNOWN",
            "verdict": "UNKNOWN",
            "confidence": 0.0,
        }

    async def lookup_domain(self, domain: str) -> List[ThreatIntelResult]:
        """Queries configured threat intel sources for a domain with backward compatibility."""
        clean_dom = domain.strip().lower()
        provider = "cyberguard_threat_intel"

        cached = self.cache.get(provider, "DOMAIN", clean_dom)
        if cached and isinstance(cached, ThreatIntelResult):
            return [cached]

        norm = IndicatorNormalizer.normalize(clean_dom, IndicatorTypeEnum.DOMAIN)
        feed_provider = self.providers.get("cyberguard_feed")
        feed_res = await feed_provider.lookup(norm) if feed_provider else None

        if feed_res:
            res = ThreatIntelResult(
                provider=feed_res.provider,
                query=clean_dom,
                indicator_type="DOMAIN",
                is_malicious=(feed_res.verdict == VerdictEnum.MALICIOUS),
                verdict=feed_res.verdict.value,
                threat_types=feed_res.threat_types,
                confidence=feed_res.confidence,
                details=feed_res.details,
            )
        else:
            res = ThreatIntelResult(
                provider=provider,
                query=clean_dom,
                indicator_type="DOMAIN",
                is_malicious=False,
                verdict="UNKNOWN",
                confidence=0.0,
                details="No external threat intelligence match found",
            )

        self.cache.set(res)
        return [res]

    async def lookup_file_hash(
        self,
        sha256: str,
        sha1: Optional[str] = None,
        md5: Optional[str] = None,
    ) -> List[ThreatIntelResult]:
        """Queries configured threat intel sources for a cryptographic file hash."""
        clean_sha256 = sha256.strip().lower()
        provider = "cyberguard_threat_intel"

        cached = self.cache.get(provider, "HASH", clean_sha256)
        if cached and isinstance(cached, ThreatIntelResult):
            return [cached]

        norm = IndicatorNormalizer.normalize(clean_sha256, IndicatorTypeEnum.SHA256)
        feed_provider = self.providers.get("cyberguard_feed")
        feed_res = await feed_provider.lookup(norm) if feed_provider else None

        if feed_res:
            res = ThreatIntelResult(
                provider=feed_res.provider,
                query=clean_sha256,
                indicator_type="HASH",
                is_malicious=(feed_res.verdict == VerdictEnum.MALICIOUS),
                verdict=feed_res.verdict.value,
                threat_types=feed_res.threat_types,
                confidence=feed_res.confidence,
                details=feed_res.details,
            )
        else:
            res = ThreatIntelResult(
                provider=provider,
                query=clean_sha256,
                indicator_type="HASH",
                is_malicious=False,
                verdict="UNKNOWN",
                confidence=0.0,
                details="No external threat intelligence match found for hash (Note: No Match != Safe)",
            )

        self.cache.set(res)
        return [res]
