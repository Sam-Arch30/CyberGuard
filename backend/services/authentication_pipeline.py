"""
Authentication and Account-Takeover (ATO) Pipeline Coordinator.
Coordinates event normalization, IP geolocation enrichment, historical profile tracking,
pattern detection engines, ATO hypothesis aggregation, and canonical persistence.
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from collections import defaultdict

from sqlalchemy.orm import Session

from backend.db.models import (
    ArtifactModel,
    AnalysisRunModel,
    FindingModel,
    FindingEvidenceModel,
    IndicatorModel,
    EntityModel,
    RelationshipModel,
    ThreatEventModel,
    ArtifactStorageRecordModel,
    IngestionRecordModel,
    generate_uuid,
    get_utc_now,
)
from backend.schemas.unified import (
    ArtifactTypeEnum,
    AnalysisStatusEnum,
    AnalysisTriggerEnum,
    FindingMethodEnum,
    IndicatorTypeEnum,
    EntityTypeEnum,
    RelationshipTypeEnum,
    SeverityEnum,
    normalize_ip,
)
from backend.schemas.authentication_security import (
    AuthenticationResultEnum,
    BaselineStatusEnum,
    NormalizedAuthEvent,
    AccountSecurityProfile,
    AuthenticationFindingItem,
    FindingEvidenceItem,
    AuthConfigResponse,
    AuthSecurityAnalysisResponse,
)
from backend.services.authentication_analyzers import (
    SecretRedactor,
    global_adapter_registry,
    FailureAnalysisEngine,
    BruteForceDetector,
    PasswordSprayDetector,
    CredentialStuffingDetector,
    SuccessAfterFailuresDetector,
    DeviceAnalysisEngine,
    LocationAnalysisEngine,
    TemporalAnalysisEngine,
    MFAAnalysisEngine,
    SessionAnalysisEngine,
    AccountTakeoverAggregator,
)
from backend.services.evidence_storage import evidence_storage
from backend.services.geolocation_service import GeolocationService
from backend.services.ip_intelligence_service import IPIntelligenceService, global_ip_service

logger = logging.getLogger("cyberguard.auth_pipeline")


class AuthenticationSecurityPipeline:
    """
    Unified Pipeline for Authentication Telemetry and Account Takeover Detection.
    """
    PIPELINE_VERSION = "1.0.0"

    def __init__(
        self,
        config: Optional[AuthConfigResponse] = None,
        geolocation_service: Optional[GeolocationService] = None,
        ip_service: Optional[IPIntelligenceService] = None,
    ):
        self.config = config or AuthConfigResponse()
        self.geo_service = geolocation_service or GeolocationService()
        self.ip_service = ip_service or global_ip_service

    async def analyze_events(
        self,
        raw_events: List[Any],
        db: Session,
        provider_hint: Optional[str] = None,
        artifact_id: Optional[str] = None,
        historical_profiles: Optional[Dict[str, AccountSecurityProfile]] = None,
        trigger: AnalysisTriggerEnum = AnalysisTriggerEnum.USER,
    ) -> AuthSecurityAnalysisResponse:
        """
        Main pipeline entrypoint to analyze raw authentication event(s).
        """
        # 1. Normalize events via Adapter Registry
        normalized_events: List[NormalizedAuthEvent] = []
        for raw in raw_events:
            try:
                ev = global_adapter_registry.normalize(raw, hint=provider_hint)
                normalized_events.append(ev)
            except Exception as e:
                logger.warning(f"Failed to normalize auth event: {e}")

        # 2. Deduplicate events
        deduped_events = self._deduplicate_events(normalized_events)

        # 3. Sort chronologically (Out-of-order handling)
        sorted_events = sorted(deduped_events, key=lambda x: x.timestamp)

        # 4. Enrich missing IP Geolocation & ASN infrastructure
        enriched_events = await self._enrich_events(sorted_events)

        # 5. Build or retrieve Account Security Profiles
        account_profiles = self._build_account_profiles(enriched_events, db, historical_profiles)

        # 6. Run Detection Engines
        findings: List[AuthenticationFindingItem] = []
        findings.extend(FailureAnalysisEngine.analyze(enriched_events, self.config))
        findings.extend(BruteForceDetector.analyze(enriched_events, self.config))
        findings.extend(PasswordSprayDetector.analyze(enriched_events, self.config))
        findings.extend(CredentialStuffingDetector.analyze(enriched_events, self.config))
        findings.extend(SuccessAfterFailuresDetector.analyze(enriched_events, self.config))
        findings.extend(DeviceAnalysisEngine.analyze(enriched_events, account_profiles, self.config))
        findings.extend(LocationAnalysisEngine.analyze(enriched_events, account_profiles, self.config))
        findings.extend(TemporalAnalysisEngine.analyze(enriched_events, account_profiles, self.config))
        findings.extend(MFAAnalysisEngine.analyze(enriched_events, account_profiles, self.config))
        findings.extend(SessionAnalysisEngine.analyze(enriched_events))

        # 7. Aggregate Account Takeover Hypothesis
        ato_suspected, ato_summary, ato_finding = AccountTakeoverAggregator.aggregate(
            findings, enriched_events, self.config
        )
        if ato_finding:
            findings.append(ato_finding)

        # 8. Score Overall Risk and Severity
        overall_score, overall_sev, confidence, classification = self._calculate_overall_risk(
            findings, ato_suspected
        )

        # 9. Canonical Persistence
        analysis_run_id, threat_events_persisted = self._persist_analysis(
            db=db,
            events=enriched_events,
            findings=findings,
            profiles=account_profiles,
            overall_score=overall_score,
            overall_sev=overall_sev,
            confidence=confidence,
            artifact_id=artifact_id,
            ato_suspected=ato_suspected,
            ato_summary=ato_summary,
            trigger=trigger,
        )

        # 10. Construct Response
        unique_ips = len(set(e.source_ip for e in enriched_events))
        targeted_accounts = len(set(e.account_id for e in enriched_events))

        return AuthSecurityAnalysisResponse(
            analysis_run_id=analysis_run_id,
            artifact_id=artifact_id,
            events_analyzed_count=len(enriched_events),
            accounts_targeted_count=targeted_accounts,
            unique_source_ips_count=unique_ips,
            overall_risk_score=overall_score,
            overall_severity=overall_sev,
            confidence=confidence,
            classification=classification,
            findings=findings,
            corroborated_threat_events=threat_events_persisted,
            account_profiles=account_profiles,
            ato_suspected=ato_suspected,
            ato_summary=ato_summary,
            created_at=datetime.now(timezone.utc),
        )

    async def analyze_artifact(
        self,
        artifact_id: str,
        db: Session,
    ) -> AuthSecurityAnalysisResponse:
        """
        Re-analyze a stored AUTH_LOG artifact directly from evidence storage.
        Guarantees append-only re-analysis lineage by generating a new AnalysisRunModel.
        """
        artifact = db.query(ArtifactModel).filter(ArtifactModel.id == artifact_id).first()
        if not artifact:
            raise ValueError(f"Artifact {artifact_id} not found in database.")

        # Read stored payload from evidence storage
        raw_bytes = evidence_storage.retrieve_bytes(artifact.storage_reference or artifact.sha256)
        if not raw_bytes:
            raise ValueError(f"Stored evidence bytes missing for artifact {artifact_id}.")

        # Parse JSON array or single object or text lines
        try:
            parsed = json.loads(raw_bytes.decode("utf-8", errors="replace"))
            if isinstance(parsed, list):
                raw_events = parsed
            elif isinstance(parsed, dict) and "events" in parsed and isinstance(parsed["events"], list):
                raw_events = parsed["events"]
            else:
                raw_events = [parsed]
        except Exception:
            # Fallback: line-by-line log lines
            lines = raw_bytes.decode("utf-8", errors="replace").splitlines()
            raw_events = [line for line in lines if line.strip()]

        return await self.analyze_events(
            raw_events=raw_events,
            db=db,
            artifact_id=artifact_id,
            trigger=AnalysisTriggerEnum.REANALYSIS,
        )

    def _deduplicate_events(self, events: List[NormalizedAuthEvent]) -> List[NormalizedAuthEvent]:
        """Deduplicate events based on ID or deterministic fingerprint."""
        seen: Set[str] = set()
        deduped: List[NormalizedAuthEvent] = []

        for ev in events:
            # Fingerprint tuple: account_id, timestamp, source_ip, result, failure_reason
            fp = f"{ev.account_id}:{ev.timestamp.isoformat()}:{ev.source_ip}:{ev.result.value}:{ev.failure_reason.value if ev.failure_reason else ''}"
            if fp not in seen:
                seen.add(fp)
                deduped.append(ev)

        return deduped

    async def _enrich_events(self, events: List[NormalizedAuthEvent]) -> List[NormalizedAuthEvent]:
        """Enrich events with Geolocation and ASN infrastructure if missing."""
        ip_cache: Dict[str, Any] = {}

        for ev in events:
            ip = ev.source_ip
            if ip in ("127.0.0.1", "::1", "localhost", "0.0.0.0") or not ip:
                continue

            if ev.latitude is None or ev.location_country is None:
                if ip not in ip_cache:
                    try:
                        geo = await self.geo_service.get_geolocation(ip)
                        ip_cache[ip] = geo
                    except Exception as e:
                        logger.debug(f"Geo lookup error for {ip}: {e}")
                        ip_cache[ip] = None

                geo_res = ip_cache.get(ip)
                if geo_res and not getattr(geo_res, "error", None):
                    ev.location_city = ev.location_city or geo_res.city
                    ev.location_country = ev.location_country or geo_res.country
                    ev.location_country_code = ev.location_country_code or geo_res.country_code
                    ev.latitude = ev.latitude if ev.latitude is not None else geo_res.latitude
                    ev.longitude = ev.longitude if ev.longitude is not None else geo_res.longitude
                    ev.isp = ev.isp or geo_res.isp
                    ev.asn = ev.asn or geo_res.asn

        return events

    def _build_account_profiles(
        self,
        events: List[NormalizedAuthEvent],
        db: Session,
        explicit_profiles: Optional[Dict[str, AccountSecurityProfile]] = None,
    ) -> Dict[str, AccountSecurityProfile]:
        """
        Builds or updates AccountSecurityProfiles for each account involved.
        Merges explicit historical profiles with newly observed events.
        """
        profiles: Dict[str, AccountSecurityProfile] = dict(explicit_profiles or {})

        # Find all accounts in events
        all_accounts = set(e.account_id for e in events)

        for account_id in all_accounts:
            if account_id not in profiles:
                known_ips: List[str] = []
                known_devs: List[str] = []
                known_countries: List[str] = []
                typical_hours: List[int] = []
                total_samples = 0
                status = BaselineStatusEnum.INSUFFICIENT_HISTORY

                if db:
                    try:
                        from backend.db.models import BehavioralBaselineModel
                        baselines = db.query(BehavioralBaselineModel).filter(
                            BehavioralBaselineModel.entity_type.in_(["ACCOUNT", "USER"]),
                            BehavioralBaselineModel.entity_id == account_id.lower(),
                        ).all()
                        for b in baselines:
                            total_samples = max(total_samples, b.sample_count)
                            if b.quality_status == "STABLE":
                                status = BaselineStatusEnum.ESTABLISHED
                            if b.distribution_json:
                                try:
                                    d = json.loads(b.distribution_json)
                                    if b.metric_type == "LOGIN_SOURCE_IP":
                                        known_ips.extend(list(d.keys()))
                                    elif b.metric_type == "LOGIN_DEVICE":
                                        known_devs.extend(list(d.keys()))
                                    elif b.metric_type == "LOGIN_LOCATION":
                                        known_countries.extend(list(d.keys()))
                                    elif b.metric_type == "LOGIN_HOUR" and "active_hours" in d:
                                        typical_hours.extend(d["active_hours"])
                                except Exception:
                                    pass
                    except Exception as e:
                        logger.debug(f"Could not load behavioral baselines for {account_id}: {e}")

                profiles[account_id] = AccountSecurityProfile(
                    account_id=account_id,
                    baseline_status=status,
                    total_successful_logins=total_samples,
                    total_failed_logins=0,
                    known_source_ips=list(set(known_ips)),
                    known_devices=list(set(known_devs)),
                    known_countries=list(set(known_countries)),
                    known_client_profiles=[],
                    typical_login_hours=list(set(typical_hours)),
                )

        return profiles

    def _calculate_overall_risk(
        self,
        findings: List[AuthenticationFindingItem],
        ato_suspected: bool,
    ) -> Tuple[float, SeverityEnum, float, str]:
        """Calculates deterministic overall threat score, severity, and classification."""
        if ato_suspected:
            return 88.0, SeverityEnum.CRITICAL, 0.92, "ACCOUNT_TAKEOVER_SUSPECTED"

        max_risk = 0.0
        confidences = []
        for f in findings:
            if f.risk_contribution > max_risk:
                max_risk = f.risk_contribution
            confidences.append(f.confidence)

        avg_conf = sum(confidences) / len(confidences) if confidences else 1.0

        if max_risk >= 65.0:
            sev = SeverityEnum.HIGH
            classification = "CREDENTIAL_ATTACK_DETECTED"
        elif max_risk >= 35.0:
            sev = SeverityEnum.MEDIUM
            classification = "SUSPICIOUS_AUTHENTICATION_PATTERN"
        elif max_risk >= 15.0:
            sev = SeverityEnum.LOW
            classification = "ANOMALOUS_AUTHENTICATION_OBSERVED"
        else:
            sev = SeverityEnum.SAFE
            classification = "NORMAL_AUTHENTICATION"

        return min(max_risk, 100.0), sev, avg_conf, classification

    def _persist_analysis(
        self,
        db: Session,
        events: List[NormalizedAuthEvent],
        findings: List[AuthenticationFindingItem],
        profiles: Dict[str, AccountSecurityProfile],
        overall_score: float,
        overall_sev: SeverityEnum,
        confidence: float,
        artifact_id: Optional[str],
        ato_suspected: bool,
        ato_summary: Optional[str],
        trigger: AnalysisTriggerEnum,
    ) -> Tuple[str, List[Dict[str, Any]]]:
        """
        Durable canonical persistence in SQLite/PostgreSQL.
        """
        analysis_run_id = generate_uuid("run")

        # 1. Create ArtifactModel if not provided
        if not artifact_id and events:
            # Create container artifact for this batch of events
            artifact = ArtifactModel(
                id=generate_uuid("art"),
                artifact_type=ArtifactTypeEnum.AUTH_LOG.value,
                name=f"auth-batch-{events[0].account_id}-{int(datetime.now(timezone.utc).timestamp())}.json",
                source="API",
                mime_type="application/json",
                size=len(events),
                metadata_json=json.dumps({"event_count": len(events)}),
                ingested_at=get_utc_now(),
            )
            db.add(artifact)
            db.flush()
            artifact_id = artifact.id

        # 2. Create AnalysisRunModel
        run = AnalysisRunModel(
            id=analysis_run_id,
            artifact_id=artifact_id,
            status=AnalysisStatusEnum.COMPLETED.value,
            trigger=trigger.value,
            pipeline_version=self.PIPELINE_VERSION,
            overall_risk_score=overall_score,
            overall_severity=overall_sev.value,
            confidence=confidence,
            started_at=get_utc_now(),
            completed_at=get_utc_now(),
            metadata_json=json.dumps({
                "ato_suspected": ato_suspected,
                "ato_summary": ato_summary,
                "events_count": len(events),
            }),
        )
        db.add(run)
        db.flush()

        # 3. Persist Findings & Finding Evidence
        for f in findings:
            finding_id = generate_uuid("fnd")
            f_model = FindingModel(
                id=finding_id,
                analysis_run_id=analysis_run_id,
                analyzer="AuthenticationSecurityPipeline",
                finding_type=f.finding_type,
                title=f.title,
                description=f.description,
                severity=f.severity.value,
                confidence=f.confidence,
                risk_contribution=f.risk_contribution,
                method=f.method,
                rule_id=f.rule_id,
                metadata_json=json.dumps({
                    "category": f.category.value,
                    "target_account": f.target_account,
                    "mitre_attack_ids": f.mitre_attack_ids,
                }),
            )
            db.add(f_model)
            db.flush()

            for ev_item in f.evidence_items:
                ev_model = FindingEvidenceModel(
                    id=generate_uuid("evi"),
                    finding_id=finding_id,
                    evidence_type="OBSERVED_VALUE",
                    source=ev_item.source,
                    key=ev_item.key,
                    value=ev_item.value,
                    confidence=ev_item.confidence,
                    artifact_id=artifact_id,
                    timestamp=ev_item.timestamp,
                    metadata_json="{}",
                )
                db.add(ev_model)

        # 4. Persist Entities (ACCOUNT, USER, DEVICE, SESSION) & Indicators (IP)
        persisted_threat_events: List[Dict[str, Any]] = []
        unique_ips: Set[str] = set()

        for ev in events:
            # IP Indicator
            if ev.source_ip and ev.source_ip not in unique_ips:
                unique_ips.add(ev.source_ip)
                norm_ip = normalize_ip(ev.source_ip)
                ind = db.query(IndicatorModel).filter(
                    IndicatorModel.indicator_type == IndicatorTypeEnum.IP.value,
                    IndicatorModel.normalized_value == norm_ip,
                ).first()
                if not ind:
                    ind = IndicatorModel(
                        id=generate_uuid("ind"),
                        indicator_type=IndicatorTypeEnum.IP.value,
                        value=ev.source_ip,
                        normalized_value=norm_ip,
                        first_seen=ev.timestamp,
                        last_seen=ev.timestamp,
                        reputation="UNKNOWN",
                        metadata_json=json.dumps({"city": ev.location_city, "country": ev.location_country}),
                    )
                    db.add(ind)
                else:
                    ind.last_seen = get_utc_now()

            # Account Entity
            acc_entity = db.query(EntityModel).filter(
                EntityModel.entity_type == EntityTypeEnum.ACCOUNT.value,
                EntityModel.name == ev.account_id,
            ).first()
            if not acc_entity:
                acc_entity = EntityModel(
                    id=generate_uuid("ent"),
                    entity_type=EntityTypeEnum.ACCOUNT.value,
                    name=ev.account_id,
                    external_id=ev.user_id,
                    attributes_json=json.dumps({"provider": ev.provider}),
                    first_seen=ev.timestamp,
                    last_seen=ev.timestamp,
                )
                db.add(acc_entity)
            else:
                acc_entity.last_seen = get_utc_now()
            db.flush()

            # Relationships
            # ACCOUNT AUTHENTICATED_FROM IP
            db.add(RelationshipModel(
                id=generate_uuid("rel"),
                source_type="ENTITY",
                source_id=acc_entity.id,
                relationship_type=RelationshipTypeEnum.AUTHENTICATED_FROM.value,
                target_type="INDICATOR",
                target_id=ev.source_ip,
                confidence=1.0,
                analysis_run_id=analysis_run_id,
                method="OBSERVED_EVENT",
                evidence_reference=f"Event {ev.id} outcome {ev.result.value}",
                metadata_json=json.dumps({"result": ev.result.value, "timestamp": ev.timestamp.isoformat()}),
            ))

            # Device Entity
            if ev.device_id or ev.device_name:
                dev_name = ev.device_name or ev.device_id or "Unknown Device"
                dev_entity = db.query(EntityModel).filter(
                    EntityModel.entity_type == EntityTypeEnum.DEVICE.value,
                    EntityModel.name == dev_name,
                ).first()
                if not dev_entity:
                    dev_entity = EntityModel(
                        id=generate_uuid("ent"),
                        entity_type=EntityTypeEnum.DEVICE.value,
                        name=dev_name,
                        external_id=ev.device_id,
                        attributes_json=json.dumps({"platform": ev.client_platform, "browser": ev.client_browser}),
                        first_seen=ev.timestamp,
                        last_seen=ev.timestamp,
                    )
                    db.add(dev_entity)
                    db.flush()

                # ACCOUNT AUTHENTICATED_ON DEVICE
                db.add(RelationshipModel(
                    id=generate_uuid("rel"),
                    source_type="ENTITY",
                    source_id=acc_entity.id,
                    relationship_type=RelationshipTypeEnum.AUTHENTICATED_ON.value,
                    target_type="ENTITY",
                    target_id=dev_entity.id,
                    confidence=1.0,
                    analysis_run_id=analysis_run_id,
                    method="OBSERVED_EVENT",
                    evidence_reference=f"Event {ev.id}",
                    metadata_json="{}",
                ))

            # Session Entity
            if ev.session_id:
                sess_entity = db.query(EntityModel).filter(
                    EntityModel.entity_type == EntityTypeEnum.SESSION.value,
                    EntityModel.name == ev.session_id,
                ).first()
                if not sess_entity:
                    sess_entity = EntityModel(
                        id=generate_uuid("ent"),
                        entity_type=EntityTypeEnum.SESSION.value,
                        name=ev.session_id,
                        attributes_json="{}",
                        first_seen=ev.timestamp,
                        last_seen=ev.timestamp,
                    )
                    db.add(sess_entity)
                    db.flush()

                # ACCOUNT HAS_SESSION SESSION
                db.add(RelationshipModel(
                    id=generate_uuid("rel"),
                    source_type="ENTITY",
                    source_id=acc_entity.id,
                    relationship_type=RelationshipTypeEnum.HAS_SESSION.value,
                    target_type="ENTITY",
                    target_id=sess_entity.id,
                    confidence=1.0,
                    analysis_run_id=analysis_run_id,
                    method="OBSERVED_EVENT",
                    evidence_reference=f"Session creation {ev.id}",
                    metadata_json="{}",
                ))

        # 5. Persist ThreatEvents
        if ato_suspected:
            te = ThreatEventModel(
                id=generate_uuid("te"),
                event_type="ACCOUNT_TAKEOVER_SUSPECTED",
                timestamp=get_utc_now(),
                source_artifact_id=artifact_id,
                analysis_run_id=analysis_run_id,
                severity=SeverityEnum.CRITICAL.value if overall_score >= 80 else SeverityEnum.HIGH.value,
                risk_score=overall_score,
                confidence=confidence,
                status="OPEN",
                summary=ato_summary or "Account takeover pattern corroborated across multiple independent signals.",
                metadata_json=json.dumps({"targeted_accounts": list(set(e.account_id for e in events))}),
            )
            db.add(te)
            persisted_threat_events.append({
                "id": te.id,
                "event_type": te.event_type,
                "severity": te.severity,
                "summary": te.summary,
            })

        for f in findings:
            if f.finding_type in ("BRUTE_FORCE_PATTERN", "PASSWORD_SPRAY_PATTERN", "CREDENTIAL_STUFFING_SUSPECTED"):
                te = ThreatEventModel(
                    id=generate_uuid("te"),
                    event_type=f.finding_type.replace("_PATTERN", "_ATTACK"),
                    timestamp=get_utc_now(),
                    source_artifact_id=artifact_id,
                    analysis_run_id=analysis_run_id,
                    severity=f.severity.value,
                    risk_score=f.risk_contribution,
                    confidence=f.confidence,
                    status="OPEN",
                    summary=f.description,
                    metadata_json=json.dumps({"target_account": f.target_account}),
                )
                db.add(te)
                persisted_threat_events.append({
                    "id": te.id,
                    "event_type": te.event_type,
                    "severity": te.severity,
                    "summary": te.summary,
                })

        db.commit()
        return analysis_run_id, persisted_threat_events


# Global Pipeline Instance
global_auth_pipeline = AuthenticationSecurityPipeline()
