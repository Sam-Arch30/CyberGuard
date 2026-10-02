"""
Network and Traffic Security Pipeline Coordinator.
Coordinates telemetry normalization, IP classification, threat intelligence enrichment,
pattern detection engines, composite hypothesis aggregation, and canonical persistence.
"""
from __future__ import annotations

import csv
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
    generate_uuid,
    get_utc_now,
)
from backend.schemas.unified import (
    ArtifactTypeEnum,
    AnalysisStatusEnum,
    AnalysisTriggerEnum,
    IndicatorTypeEnum,
    EntityTypeEnum,
    RelationshipTypeEnum,
    SeverityEnum,
    normalize_ip,
    normalize_domain,
)
from backend.schemas.network_security import (
    NetworkEventTypeEnum,
    NetworkCategoryEnum,
    NormalizedNetworkEvent,
    DeviceNetworkProfile,
    NetworkFindingItem,
    NetworkFindingEvidenceItem,
    NetworkConfigResponse,
    NetworkSecurityAnalysisResponse,
)
from backend.services.network_analyzers import (
    IPClassifier,
    global_network_adapter_registry,
    ConnectionPatternEngine,
    PeriodicityEngine,
    DnsTelemetryEngine,
    TransferExfiltrationEngine,
    DestinationAnomalyEngine,
    NetworkPatternAggregator,
)
from backend.services.evidence_storage import evidence_storage
from backend.services.threat_intelligence_service import ThreatIntelligenceService
from backend.services.geolocation_service import GeolocationService

logger = logging.getLogger("cyberguard.network_pipeline")


class NetworkSecurityPipeline:
    """
    Unified Pipeline Coordinator for Network and Traffic Anomaly Security.
    """
    PIPELINE_VERSION = "1.0.0"

    def __init__(
        self,
        config: Optional[NetworkConfigResponse] = None,
        threat_intel_service: Optional[ThreatIntelligenceService] = None,
        geo_service: Optional[GeolocationService] = None,
    ):
        self.config = config or NetworkConfigResponse()
        self.threat_intel = threat_intel_service or ThreatIntelligenceService()
        self.geo_service = geo_service or GeolocationService()

    async def analyze_events(
        self,
        raw_events: List[Any],
        db: Session,
        provider_hint: Optional[str] = None,
        artifact_id: Optional[str] = None,
        historical_profiles: Optional[Dict[str, DeviceNetworkProfile]] = None,
        trigger: AnalysisTriggerEnum = AnalysisTriggerEnum.USER,
    ) -> NetworkSecurityAnalysisResponse:
        """
        Main pipeline entrypoint to analyze raw network event(s).
        """
        # 1. Normalize events via Adapter Registry
        normalized_events: List[NormalizedNetworkEvent] = []
        for raw in raw_events:
            try:
                ev = global_network_adapter_registry.normalize(
                    raw,
                    hint=provider_hint,
                    internal_cidrs=self.config.internal_networks_cidrs,
                )
                normalized_events.append(ev)
            except Exception as e:
                logger.warning(f"Failed to normalize network event: {e}")

        # 2. Deduplicate events
        deduped_events = self._deduplicate_events(normalized_events)

        # 3. Sort chronologically (Out-of-order handling)
        sorted_events = sorted(deduped_events, key=lambda x: x.timestamp)

        # 4. Build or retrieve Device Profiles
        device_profiles = self._build_device_profiles(sorted_events, historical_profiles)

        # 5. Run Threat Intelligence Lookups on unique external destinations
        threat_intel_findings = await self._check_threat_intelligence(sorted_events)

        # 6. Run Detection Engines
        findings: List[NetworkFindingItem] = []
        findings.extend(threat_intel_findings)
        findings.extend(ConnectionPatternEngine.analyze(sorted_events, self.config))
        findings.extend(PeriodicityEngine.analyze(sorted_events, self.config))
        findings.extend(DnsTelemetryEngine.analyze(sorted_events, self.config))
        findings.extend(TransferExfiltrationEngine.analyze(sorted_events, device_profiles, self.config))
        findings.extend(DestinationAnomalyEngine.analyze(sorted_events, device_profiles, self.config))

        # 7. Aggregate Multi-Category Hypotheses
        suspicious_comm, possible_exfil, composite_findings = NetworkPatternAggregator.aggregate(
            findings, sorted_events
        )
        findings.extend(composite_findings)

        # 8. Score Overall Risk and Severity
        overall_score, overall_sev, confidence, classification = self._calculate_overall_risk(
            findings, suspicious_comm, possible_exfil
        )

        # 9. Canonical Persistence
        analysis_run_id, threat_events_persisted = self._persist_analysis(
            db=db,
            events=sorted_events,
            findings=findings,
            profiles=device_profiles,
            overall_score=overall_score,
            overall_sev=overall_sev,
            confidence=confidence,
            artifact_id=artifact_id,
            suspicious_comm=suspicious_comm,
            possible_exfil=possible_exfil,
            trigger=trigger,
        )

        # 10. Construct Response
        unique_destinations = len(set(
            (e.destination_ip or e.domain) for e in sorted_events if (e.destination_ip or e.domain)
        ))
        devices_count = len(set(
            (e.device_id or e.source_ip) for e in sorted_events
        ))
        total_sent = sum(e.bytes_sent or 0 for e in sorted_events)
        total_recv = sum(e.bytes_received or 0 for e in sorted_events)

        return NetworkSecurityAnalysisResponse(
            analysis_run_id=analysis_run_id,
            artifact_id=artifact_id,
            events_analyzed_count=len(sorted_events),
            devices_observed_count=devices_count,
            unique_destinations_count=unique_destinations,
            total_bytes_sent=total_sent,
            total_bytes_received=total_recv,
            overall_risk_score=overall_score,
            overall_severity=overall_sev,
            confidence=confidence,
            classification=classification,
            findings=findings,
            corroborated_threat_events=threat_events_persisted,
            device_profiles=device_profiles,
            suspicious_communication_detected=suspicious_comm,
            possible_exfiltration_detected=possible_exfil,
            created_at=datetime.now(timezone.utc),
        )

    async def analyze_artifact(
        self,
        artifact_id: str,
        db: Session,
    ) -> NetworkSecurityAnalysisResponse:
        """
        Re-analyze a stored NETWORK_LOG artifact directly from evidence storage.
        """
        artifact = db.query(ArtifactModel).filter(ArtifactModel.id == artifact_id).first()
        if not artifact:
            raise ValueError(f"Artifact {artifact_id} not found in database.")

        raw_bytes = evidence_storage.retrieve_bytes(artifact.storage_reference or artifact.sha256)
        if not raw_bytes:
            raise ValueError(f"Stored evidence bytes missing for artifact {artifact_id}.")

        text_content = raw_bytes.decode("utf-8", errors="replace")
        raw_events: List[Any] = []

        # Try JSON
        try:
            parsed = json.loads(text_content)
            if isinstance(parsed, list):
                raw_events = parsed
            elif isinstance(parsed, dict) and "events" in parsed and isinstance(parsed["events"], list):
                raw_events = parsed["events"]
            else:
                raw_events = [parsed]
        except Exception:
            # Try CSV or line-by-line
            lines = text_content.splitlines()
            if lines and "," in lines[0]:
                reader = csv.DictReader(lines)
                raw_events = list(reader)
            else:
                raw_events = [line.strip() for line in lines if line.strip()]

        return await self.analyze_events(
            raw_events=raw_events,
            db=db,
            artifact_id=artifact_id,
            trigger=AnalysisTriggerEnum.REANALYSIS,
        )

    def _deduplicate_events(self, events: List[NormalizedNetworkEvent]) -> List[NormalizedNetworkEvent]:
        seen: Set[str] = set()
        deduped: List[NormalizedNetworkEvent] = []
        for ev in events:
            fp = f"{ev.source_ip}:{ev.destination_ip}:{ev.destination_port}:{ev.protocol.value}:{ev.timestamp.isoformat()}"
            if fp not in seen:
                seen.add(fp)
                deduped.append(ev)
        return deduped

    async def _check_threat_intelligence(
        self,
        events: List[NormalizedNetworkEvent],
    ) -> List[NetworkFindingItem]:
        findings: List[NetworkFindingItem] = []
        checked_ips: Set[str] = set()
        checked_domains: Set[str] = set()

        for ev in events:
            dst_ip = ev.destination_ip
            if dst_ip and dst_ip not in checked_ips:
                checked_ips.add(dst_ip)
                # Check external IP reputation
                if not IPClassifier.is_internal(dst_ip, self.config.internal_networks_cidrs):
                    try:
                        intel = await self.threat_intel.lookup_ip(dst_ip)
                        if isinstance(intel, dict) and (intel.get("is_malicious") or intel.get("malicious_count", 0) > 0):
                            findings.append(
                                NetworkFindingItem(
                                    finding_type="KNOWN_THREAT_INFRASTRUCTURE_MATCH",
                                    title=f"Destination {dst_ip} matches known threat intelligence",
                                    description=(
                                        f"External IP destination {dst_ip} matched threat intelligence records "
                                        f"({intel.get('malicious_count')} detections by {intel.get('provider', 'OSINT')}). "
                                        f"Threat category: {intel.get('threat_category', 'Command & Control / Malicious')}."
                                    ),
                                    severity=SeverityEnum.HIGH,
                                    confidence=0.92,
                                    risk_contribution=70.0,
                                    method="EXTERNAL_INTELLIGENCE",
                                    rule_id="NET_THREAT_INTEL_MATCH",
                                    category=NetworkCategoryEnum.INFRASTRUCTURE_REPUTATION,
                                    target_destination=dst_ip,
                                    mitre_attack_ids=["T1071"],
                                    evidence_items=[
                                        NetworkFindingEvidenceItem(key="destination_ip", value=dst_ip, source="ThreatIntelligenceService"),
                                        NetworkFindingEvidenceItem(key="provider", value=str(intel.get("provider")), source="ThreatIntelligenceService"),
                                        NetworkFindingEvidenceItem(key="detections", value=str(intel.get("malicious_count")), source="ThreatIntelligenceService"),
                                    ],
                                )
                            )
                    except Exception as e:
                        logger.debug(f"Threat intel error for {dst_ip}: {e}")

            # Check domain reputation
            dom = ev.domain or ev.dns_query
            if dom and dom not in checked_domains:
                checked_domains.add(dom)
                try:
                    dom_results = await self.threat_intel.lookup_domain(dom)
                    for r in dom_results:
                        if getattr(r, "is_malicious", False):
                            findings.append(
                                NetworkFindingItem(
                                    finding_type="KNOWN_THREAT_INFRASTRUCTURE_MATCH",
                                    title=f"Destination domain {dom} matches known threat intelligence",
                                    description=(
                                        f"Domain destination {dom} matched threat intelligence feed "
                                        f"({r.provider}). Classification: {getattr(r, 'verdict', 'MALICIOUS')}."
                                    ),
                                    severity=SeverityEnum.HIGH,
                                    confidence=0.92,
                                    risk_contribution=70.0,
                                    method="EXTERNAL_INTELLIGENCE",
                                    rule_id="NET_THREAT_INTEL_DOMAIN_MATCH",
                                    category=NetworkCategoryEnum.INFRASTRUCTURE_REPUTATION,
                                    target_destination=dom,
                                    mitre_attack_ids=["T1071"],
                                    evidence_items=[
                                        NetworkFindingEvidenceItem(key="destination_domain", value=dom, source="ThreatIntelligenceService"),
                                        NetworkFindingEvidenceItem(key="provider", value=str(r.provider), source="ThreatIntelligenceService"),
                                    ],
                                )
                            )
                except Exception as e:
                    logger.debug(f"Threat intel error for domain {dom}: {e}")

        return findings

    def _build_device_profiles(
        self,
        events: List[NormalizedNetworkEvent],
        explicit_profiles: Optional[Dict[str, DeviceNetworkProfile]] = None,
    ) -> Dict[str, DeviceNetworkProfile]:
        profiles: Dict[str, DeviceNetworkProfile] = dict(explicit_profiles or {})

        for ev in events:
            device_key = ev.device_id or ev.source_ip
            if device_key not in profiles:
                profiles[device_key] = DeviceNetworkProfile(
                    device_id=device_key,
                    total_connections_observed=0,
                    first_seen=ev.timestamp,
                    last_seen=ev.timestamp,
                    known_destinations=[],
                    known_ports=[],
                    known_domains=[],
                )

        return profiles

    def _calculate_overall_risk(
        self,
        findings: List[NetworkFindingItem],
        suspicious_comm: bool,
        possible_exfil: bool,
    ) -> Tuple[float, SeverityEnum, float, str]:
        if suspicious_comm or possible_exfil:
            score = 85.0 if possible_exfil else 75.0
            sev = SeverityEnum.HIGH
            classification = "POTENTIAL_INTRUSION_COMMUNICATION"
            return score, sev, 0.90, classification

        max_risk = 0.0
        confidences = []
        for f in findings:
            if f.risk_contribution > max_risk:
                max_risk = f.risk_contribution
            confidences.append(f.confidence)

        avg_conf = sum(confidences) / len(confidences) if confidences else 1.0

        if max_risk >= 65.0:
            sev = SeverityEnum.HIGH
            classification = "SUSPICIOUS_NETWORK_ACTIVITY"
        elif max_risk >= 35.0:
            sev = SeverityEnum.MEDIUM
            classification = "ANOMALOUS_NETWORK_TRAFFIC"
        elif max_risk >= 15.0:
            sev = SeverityEnum.LOW
            classification = "BENIGN_NETWORK_ANOMALY"
        else:
            sev = SeverityEnum.SAFE
            classification = "NORMAL_NETWORK_TRAFFIC"

        return min(max_risk, 100.0), sev, avg_conf, classification

    def _persist_analysis(
        self,
        db: Session,
        events: List[NormalizedNetworkEvent],
        findings: List[NetworkFindingItem],
        profiles: Dict[str, DeviceNetworkProfile],
        overall_score: float,
        overall_sev: SeverityEnum,
        confidence: float,
        artifact_id: Optional[str],
        suspicious_comm: bool,
        possible_exfil: bool,
        trigger: AnalysisTriggerEnum,
    ) -> Tuple[str, List[Dict[str, Any]]]:
        analysis_run_id = generate_uuid("run")

        # 1. Create ArtifactModel if not provided
        if not artifact_id and events:
            artifact = ArtifactModel(
                id=generate_uuid("art"),
                artifact_type=ArtifactTypeEnum.NETWORK_LOG.value,
                name=f"network-flow-{int(datetime.now(timezone.utc).timestamp())}.json",
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
                "suspicious_communication": suspicious_comm,
                "possible_exfiltration": possible_exfil,
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
                analyzer="NetworkSecurityPipeline",
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
                    "target_destination": f.target_destination,
                    "target_device": f.target_device,
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

        # 4. Persist Entities & Relationships
        persisted_threat_events: List[Dict[str, Any]] = []
        created_indicators: Set[str] = set()

        for ev in events:
            # Source Host / Device Entity
            dev_key = ev.device_id or ev.host_name or ev.source_ip
            dev_entity = db.query(EntityModel).filter(
                EntityModel.entity_type == EntityTypeEnum.DEVICE.value,
                EntityModel.name == dev_key,
            ).first()
            if not dev_entity:
                dev_entity = EntityModel(
                    id=generate_uuid("ent"),
                    entity_type=EntityTypeEnum.DEVICE.value,
                    name=dev_key,
                    external_id=ev.device_id,
                    attributes_json=json.dumps({"ip": ev.source_ip}),
                    first_seen=ev.timestamp,
                    last_seen=ev.timestamp,
                )
                db.add(dev_entity)
                db.flush()

            # Session Entity (if provided in telemetry)
            session_entity = None
            if ev.session_id:
                session_entity = db.query(EntityModel).filter(
                    EntityModel.entity_type == EntityTypeEnum.SESSION.value,
                    EntityModel.name == ev.session_id,
                ).first()
                if not session_entity:
                    session_entity = EntityModel(
                        id=generate_uuid("ent"),
                        entity_type=EntityTypeEnum.SESSION.value,
                        name=ev.session_id,
                        external_id=ev.session_id,
                        attributes_json=json.dumps({"device_id": dev_key}),
                        first_seen=ev.timestamp,
                        last_seen=ev.timestamp,
                    )
                    db.add(session_entity)
                    db.flush()

                db.add(RelationshipModel(
                    id=generate_uuid("rel"),
                    source_type="ENTITY",
                    source_id=dev_entity.id,
                    relationship_type=RelationshipTypeEnum.HAS_SESSION.value,
                    target_type="ENTITY",
                    target_id=session_entity.id,
                    confidence=1.0,
                    analysis_run_id=analysis_run_id,
                    method="OBSERVED_EVENT",
                    evidence_reference=f"Session observed on event {ev.id}",
                    metadata_json="{}",
                ))

            # User Entity (if provided in telemetry)
            if ev.user_id:
                user_entity = db.query(EntityModel).filter(
                    EntityModel.entity_type == EntityTypeEnum.USER.value,
                    EntityModel.name == ev.user_id,
                ).first()
                if not user_entity:
                    user_entity = EntityModel(
                        id=generate_uuid("ent"),
                        entity_type=EntityTypeEnum.USER.value,
                        name=ev.user_id,
                        external_id=ev.user_id,
                        attributes_json=json.dumps({"mapped_user": ev.user_id}),
                        first_seen=ev.timestamp,
                        last_seen=ev.timestamp,
                    )
                    db.add(user_entity)
                    db.flush()

                if session_entity:
                    db.add(RelationshipModel(
                        id=generate_uuid("rel"),
                        source_type="ENTITY",
                        source_id=user_entity.id,
                        relationship_type=RelationshipTypeEnum.HAS_SESSION.value,
                        target_type="ENTITY",
                        target_id=session_entity.id,
                        confidence=1.0,
                        analysis_run_id=analysis_run_id,
                        method="OBSERVED_EVENT",
                        evidence_reference=f"User session association on event {ev.id}",
                        metadata_json="{}",
                    ))

            # Destination IP Indicator
            if ev.destination_ip and ev.destination_ip not in created_indicators:
                created_indicators.add(ev.destination_ip)
                norm_ip = normalize_ip(ev.destination_ip)
                ind = db.query(IndicatorModel).filter(
                    IndicatorModel.indicator_type == IndicatorTypeEnum.IP.value,
                    IndicatorModel.normalized_value == norm_ip,
                ).first()
                if not ind:
                    ind = IndicatorModel(
                        id=generate_uuid("ind"),
                        indicator_type=IndicatorTypeEnum.IP.value,
                        value=ev.destination_ip,
                        normalized_value=norm_ip,
                        first_seen=ev.timestamp,
                        last_seen=ev.timestamp,
                        reputation="UNKNOWN",
                        metadata_json="{}",
                    )
                    db.add(ind)

                # DEVICE CONNECTS_TO IP
                db.add(RelationshipModel(
                    id=generate_uuid("rel"),
                    source_type="ENTITY",
                    source_id=dev_entity.id,
                    relationship_type=RelationshipTypeEnum.CONNECTS_TO.value,
                    target_type="INDICATOR",
                    target_id=ev.destination_ip,
                    confidence=1.0,
                    analysis_run_id=analysis_run_id,
                    method="OBSERVED_EVENT",
                    evidence_reference=f"Flow {ev.id} port {ev.destination_port}",
                    metadata_json=json.dumps({"port": ev.destination_port, "protocol": ev.protocol.value}),
                ))

            # DNS Query Domain Indicator
            query_domain = ev.domain or ev.dns_query
            if query_domain and query_domain not in created_indicators:
                created_indicators.add(query_domain)
                norm_dom = normalize_domain(query_domain)
                dom_ind = db.query(IndicatorModel).filter(
                    IndicatorModel.indicator_type == IndicatorTypeEnum.DOMAIN.value,
                    IndicatorModel.normalized_value == norm_dom,
                ).first()
                if not dom_ind:
                    dom_ind = IndicatorModel(
                        id=generate_uuid("ind"),
                        indicator_type=IndicatorTypeEnum.DOMAIN.value,
                        value=query_domain,
                        normalized_value=norm_dom,
                        first_seen=ev.timestamp,
                        last_seen=ev.timestamp,
                        reputation="UNKNOWN",
                        metadata_json="{}",
                    )
                    db.add(dom_ind)

                # DEVICE QUERIED_DNS DOMAIN
                db.add(RelationshipModel(
                    id=generate_uuid("rel"),
                    source_type="ENTITY",
                    source_id=dev_entity.id,
                    relationship_type=RelationshipTypeEnum.QUERIED_DNS.value,
                    target_type="INDICATOR",
                    target_id=query_domain,
                    confidence=1.0,
                    analysis_run_id=analysis_run_id,
                    method="OBSERVED_EVENT",
                    evidence_reference=f"DNS Query {ev.id}",
                    metadata_json="{}",
                ))

        # 5. Persist ThreatEvents
        for f in findings:
            if f.severity in (SeverityEnum.HIGH, SeverityEnum.CRITICAL):
                event_type = f.finding_type
                te = ThreatEventModel(
                    id=generate_uuid("te"),
                    event_type=event_type,
                    timestamp=get_utc_now(),
                    source_artifact_id=artifact_id,
                    analysis_run_id=analysis_run_id,
                    severity=f.severity.value,
                    risk_score=f.risk_contribution,
                    confidence=f.confidence,
                    status="OPEN",
                    summary=f.description,
                    metadata_json=json.dumps({"destination": f.target_destination}),
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
global_network_pipeline = NetworkSecurityPipeline()
