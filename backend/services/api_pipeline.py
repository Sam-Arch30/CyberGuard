"""
API Abuse Security Pipeline Coordinator.
Coordinates telemetry normalization, adapter resolution, secret redaction,
analytical detection engines, composite hypothesis aggregation, cross-module correlation,
and canonical database persistence.
"""
from __future__ import annotations

import csv
import json
import logging
import uuid
import hashlib
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
    normalize_url,
)
from backend.schemas.api_security import (
    HTTPMethodEnum,
    APIEventTypeEnum,
    APICategoryEnum,
    NormalizedAPIEvent,
    AccountAPIBaselineProfile,
    APIFindingItem,
    APIFindingEvidenceItem,
    APIConfigResponse,
    APISecurityAnalysisResponse,
)
from backend.services.api_analyzers import (
    ApiAdapterRegistry,
    APISecretRedactor,
    APIRateBurstEngine,
    APIEnumerationEngine,
    APIAuthFailureEngine,
    APIMethodPrivilegeEngine,
    APISessionAnomalyEngine,
    APIVolumeScrapingEngine,
    APIPatternAggregator,
)
from backend.services.evidence_storage import evidence_storage
from backend.services.ip_intelligence_service import IPIntelligenceService

logger = logging.getLogger("cyberguard.api_pipeline")


class APISecurityPipeline:
    """
    Unified Pipeline Coordinator for Defensive API Abuse Detection.
    """
    PIPELINE_VERSION = "1.0.0"

    def __init__(
        self,
        config: Optional[APIConfigResponse] = None,
        adapter_registry: Optional[ApiAdapterRegistry] = None,
    ):
        self.config = config or APIConfigResponse()
        self.adapter_registry = adapter_registry or ApiAdapterRegistry()
        self._in_memory_profiles: Dict[str, AccountAPIBaselineProfile] = {}

    def get_account_profile(self, account_id: str) -> Optional[AccountAPIBaselineProfile]:
        return self._in_memory_profiles.get(account_id)

    async def analyze_events(
        self,
        raw_events: List[Any],
        db: Session,
        provider_hint: Optional[str] = None,
        artifact_id: Optional[str] = None,
        historical_profiles: Optional[Dict[str, AccountAPIBaselineProfile]] = None,
        trigger: AnalysisTriggerEnum = AnalysisTriggerEnum.USER,
    ) -> APISecurityAnalysisResponse:
        """
        Main pipeline entrypoint to analyze raw API event(s).
        """
        if not raw_events:
            return APISecurityAnalysisResponse(
                analysis_run_id=generate_uuid(),
                artifact_id=artifact_id,
                events_analyzed_count=0,
                accounts_observed_count=0,
                sessions_observed_count=0,
                unique_endpoints_count=0,
                unique_source_ips_count=0,
                overall_risk_score=0.0,
                overall_severity=SeverityEnum.SAFE,
                confidence=1.0,
                classification="EMPTY_API_TELEMETRY",
            )

        # 1. Normalize events via Adapter Registry with secret redaction
        normalized_events: List[NormalizedAPIEvent] = []
        for raw in raw_events:
            try:
                adapter = self.adapter_registry.get_adapter(provider_hint, raw)
                if not adapter.can_handle(raw):
                    raise ValueError("API event lacks supported request fields.")
                ev = adapter.normalize(raw)
                normalized_events.append(ev)
            except Exception as e:
                logger.warning(f"Failed to normalize API event: {e}")

        if not normalized_events:
            return APISecurityAnalysisResponse(
                analysis_run_id=generate_uuid(),
                artifact_id=artifact_id,
                events_analyzed_count=0,
                accounts_observed_count=0,
                sessions_observed_count=0,
                unique_endpoints_count=0,
                unique_source_ips_count=0,
                overall_risk_score=0.0,
                overall_severity=SeverityEnum.SAFE,
                confidence=1.0,
                classification="MALFORMED_API_TELEMETRY",
            )

        # 2. Deduplicate events
        deduped_events = self._deduplicate_events(normalized_events)

        # 3. Sort chronologically (Out-of-order handling)
        sorted_events = sorted(deduped_events, key=lambda x: x.timestamp)

        # 4. Build or retrieve Account Baseline Profiles
        account_profiles = self._build_account_profiles(sorted_events, historical_profiles)

        # 5. Run Detection Engines
        findings: List[APIFindingItem] = []
        findings.extend(APIRateBurstEngine.analyze(sorted_events, self.config))
        findings.extend(APIEnumerationEngine.analyze(sorted_events, self.config))
        findings.extend(APIAuthFailureEngine.analyze(sorted_events, self.config))
        findings.extend(APIMethodPrivilegeEngine.analyze(sorted_events, self.config))
        findings.extend(APISessionAnomalyEngine.analyze(sorted_events, self.config, account_profiles))
        findings.extend(APIVolumeScrapingEngine.analyze(sorted_events, self.config))

        # 6. Check Cross-Module Correlations (Section 9 Auth ATO & Section 10 Network)
        cross_findings = self._check_cross_module_correlations(sorted_events, db)
        findings.extend(cross_findings)

        # 7. Aggregate Multi-Category Hypotheses
        (
            all_findings,
            corroborated_events,
            overall_score,
            overall_sev,
            classification,
        ) = APIPatternAggregator.aggregate(sorted_events, findings)

        abuse_suspected = any(f.finding_type == "API_ABUSE_SUSPECTED" for f in all_findings)
        exfil_detected = any(f.finding_type == "POSSIBLE_API_DATA_EXFILTRATION" for f in all_findings)

        # 8. Calculate Telemetry Summaries
        accounts_set = {e.account_id for e in sorted_events if e.account_id}
        sessions_set = {e.session_id for e in sorted_events if e.session_id}
        endpoints_set = {e.route_template or e.endpoint for e in sorted_events}
        ips_set = {e.source_ip for e in sorted_events if e.source_ip}
        total_req_bytes = sum(e.request_bytes or 0 for e in sorted_events)
        total_resp_bytes = sum(e.response_bytes or 0 for e in sorted_events)

        # 9. Canonical Database Persistence
        run_id, persisted_artifact_id = self._persist_analysis(
            raw_events=raw_events,
            normalized_events=sorted_events,
            findings=all_findings,
            corroborated_threat_events=corroborated_events,
            db=db,
            artifact_id=artifact_id,
            trigger=trigger,
            overall_score=overall_score,
            overall_severity=overall_sev,
        )

        return APISecurityAnalysisResponse(
            analysis_run_id=run_id,
            artifact_id=persisted_artifact_id or artifact_id,
            events_analyzed_count=len(sorted_events),
            accounts_observed_count=len(accounts_set),
            sessions_observed_count=len(sessions_set),
            unique_endpoints_count=len(endpoints_set),
            unique_source_ips_count=len(ips_set),
            total_request_bytes=total_req_bytes,
            total_response_bytes=total_resp_bytes,
            overall_risk_score=overall_score,
            overall_severity=overall_sev,
            confidence=0.92 if all_findings else 1.0,
            classification=classification,
            findings=all_findings,
            corroborated_threat_events=corroborated_events,
            account_profiles=account_profiles,
            api_abuse_suspected=abuse_suspected,
            possible_exfiltration_detected=exfil_detected,
        )

    def _deduplicate_events(self, events: List[NormalizedAPIEvent]) -> List[NormalizedAPIEvent]:
        """
        Deduplicates identical API events within the same ingestion payload.
        Key: (timestamp, source_ip, method, endpoint, status_code, account_id, session_id)
        """
        seen: Set[Tuple[str, str, str, str, int, Optional[str], Optional[str]]] = set()
        deduped: List[NormalizedAPIEvent] = []

        for e in events:
            sig = (
                e.timestamp.isoformat(),
                e.source_ip,
                e.method.value,
                e.endpoint,
                e.status_code,
                e.account_id,
                e.session_id,
            )
            if sig not in seen:
                seen.add(sig)
                deduped.append(e)

        return deduped

    def _build_account_profiles(
        self,
        events: List[NormalizedAPIEvent],
        historical: Optional[Dict[str, AccountAPIBaselineProfile]] = None,
    ) -> Dict[str, AccountAPIBaselineProfile]:
        """
        Builds or merges lightweight account baseline profiles.
        """
        profiles: Dict[str, AccountAPIBaselineProfile] = dict(historical or self._in_memory_profiles)

        for e in events:
            if not e.account_id:
                continue
            acc = e.account_id
            if acc not in profiles:
                profiles[acc] = AccountAPIBaselineProfile(
                    account_id=acc,
                    is_service_account=e.is_service_account,
                    first_seen=e.timestamp,
                    last_seen=e.timestamp,
                )

            prof = profiles[acc]
            prof.total_requests_observed += 1
            prof.total_response_bytes += (e.response_bytes or 0)

            if prof.first_seen is None or e.timestamp < prof.first_seen:
                prof.first_seen = e.timestamp
            if prof.last_seen is None or e.timestamp > prof.last_seen:
                prof.last_seen = e.timestamp

            route = e.route_template or e.endpoint
            if route not in prof.known_endpoints:
                prof.known_endpoints.append(route)
            if e.method.value not in prof.known_methods:
                prof.known_methods.append(e.method.value)
            if e.source_ip not in prof.known_source_ips:
                prof.known_source_ips.append(e.source_ip)
            if e.user_agent and e.user_agent not in prof.known_user_agents:
                prof.known_user_agents.append(e.user_agent)

        self._in_memory_profiles.update(profiles)
        return profiles

    def _check_cross_module_correlations(
        self,
        events: List[NormalizedAPIEvent],
        db: Session,
    ) -> List[APIFindingItem]:
        """
        Correlates API telemetry with Section 9 (Authentication ATO) and Section 10 (Network Anomaly)
        ThreatEvents in the database.
        """
        findings: List[APIFindingItem] = []
        if not db:
            return findings

        try:
            # Collect unique session IDs, account IDs, and source IPs
            sessions = {e.session_id for e in events if e.session_id}
            accounts = {e.account_id for e in events if e.account_id}
            ips = {e.source_ip for e in events if e.source_ip}

            # Query ThreatEvents from DB matching these actors
            threat_events = (
                db.query(ThreatEventModel)
                .filter(
                    ThreatEventModel.event_type.in_([
                        "ACCOUNT_TAKEOVER_SUSPECTED",
                        "BRUTE_FORCE_DETECTED",
                        "PASSWORD_SPRAY_DETECTED",
                        "SUSPICIOUS_EXTERNAL_COMMUNICATION",
                        "POSSIBLE_DATA_EXFILTRATION",
                    ])
                )
                .order_by(ThreatEventModel.created_at.desc())
                .limit(50)
                .all()
            )

            for te in threat_events:
                meta = {}
                try:
                    meta = json.loads(te.metadata_json or "{}")
                except Exception:
                    pass

                te_acc = getattr(te, "target_account", None) or meta.get("account_id") or meta.get("target_account")
                te_sess = meta.get("session_id")
                te_ip = meta.get("source_ip") or meta.get("destination_ip")

                # Match Section 9 ATO
                if te.event_type == "ACCOUNT_TAKEOVER_SUSPECTED" and (
                    (te_acc and te_acc in accounts) or (te_sess and te_sess in sessions)
                ):
                    findings.append(APIFindingItem(
                        finding_type="CORRELATED_ACCOUNT_TAKEOVER_ACTIVITY",
                        title=f"API Activity on Compromised Account/Session ({te_acc or te_sess})",
                        description=(
                            f"API requests were observed for account '{te_acc or 'unknown'}' / session '{te_sess or 'unknown'}' "
                            f"which was previously flagged for ACCOUNT_TAKEOVER_SUSPECTED (ThreatEvent ID: {te.id})."
                        ),
                        severity=SeverityEnum.HIGH,
                        confidence=0.94,
                        risk_contribution=35.0,
                        rule_id="API_CORR_001",
                        rule_version="1.0.0",
                        category=APICategoryEnum.SESSION_ANOMALY,
                        target_account=te_acc,
                        target_session=te_sess,
                        mitre_attack_ids=["T1078"],
                        limitation="A false positive in the upstream authentication engine will propagate into this correlation.",
                        evidence_items=[
                            APIFindingEvidenceItem(key="prior_threat_event_id", value=te.id, source="cross_module_correlator"),
                            APIFindingEvidenceItem(key="prior_event_type", value=te.event_type, source="cross_module_correlator"),
                            APIFindingEvidenceItem(key="matched_account", value=str(te_acc), source="cross_module_correlator"),
                        ]
                    ))

                # Match Section 10 Network Exfiltration / Suspicious Communication
                if te.event_type in ("SUSPICIOUS_EXTERNAL_COMMUNICATION", "POSSIBLE_DATA_EXFILTRATION") and te_ip and te_ip in ips:
                    findings.append(APIFindingItem(
                        finding_type="CORRELATED_NETWORK_THREAT_ACTIVITY",
                        title=f"API Telemetry Sourced from Suspicious Network IP ({te_ip})",
                        description=(
                            f"API requests originated from IP '{te_ip}', which was previously flagged in network telemetry "
                            f"for {te.event_type} (ThreatEvent ID: {te.id})."
                        ),
                        severity=SeverityEnum.HIGH,
                        confidence=0.90,
                        risk_contribution=30.0,
                        rule_id="API_CORR_002",
                        rule_version="1.0.0",
                        category=APICategoryEnum.SESSION_ANOMALY,
                        target_source_ip=te_ip,
                        mitre_attack_ids=["T1071.001"],
                        limitation="Shared NAT or proxy IP infrastructure can cause unrelated network alarms to correlate with API traffic.",
                        evidence_items=[
                            APIFindingEvidenceItem(key="network_threat_event_id", value=te.id, source="cross_module_correlator"),
                            APIFindingEvidenceItem(key="network_event_type", value=te.event_type, source="cross_module_correlator"),
                            APIFindingEvidenceItem(key="matched_ip", value=te_ip, source="cross_module_correlator"),
                        ]
                    ))

        except Exception as e:
            logger.warning(f"Error checking cross-module correlations: {e}")

        return findings

    def _persist_analysis(
        self,
        raw_events: List[Any],
        normalized_events: List[NormalizedAPIEvent],
        findings: List[APIFindingItem],
        corroborated_threat_events: List[Dict[str, Any]],
        db: Session,
        artifact_id: Optional[str] = None,
        trigger: AnalysisTriggerEnum = AnalysisTriggerEnum.USER,
        overall_score: float = 0.0,
        overall_severity: SeverityEnum = SeverityEnum.SAFE,
    ) -> Tuple[str, Optional[str]]:
        """
        Durable persistence of API logs, AnalysisRun, Findings, Evidence,
        ThreatEvents, Entities, Indicators, and Relationships using SQLAlchemy 2.0.
        """
        run_id = generate_uuid()
        if not db:
            return run_id, artifact_id

        try:
            # 1. Ensure or create Artifact record
            if not artifact_id:
                raw_payload_bytes = json.dumps(
                    [e.model_dump(mode="json") for e in normalized_events]
                ).encode("utf-8")
                raw_sha256 = hashlib.sha256(raw_payload_bytes).hexdigest()
                storage_res = evidence_storage.store_bytes(
                    data=raw_payload_bytes,
                    original_filename=f"api_telemetry_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json",
                    mime_type="application/json",
                )

                art = ArtifactModel(
                    id=generate_uuid(),
                    artifact_type=ArtifactTypeEnum.API_LOG.value,
                    name=f"api_telemetry_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json",
                    source="API_GATEWAY",
                    mime_type="application/json",
                    size=len(raw_payload_bytes),
                    sha256=raw_sha256,
                    storage_reference=storage_res.storage_key,
                    metadata_json=json.dumps({
                        "event_count": len(normalized_events),
                        "pipeline": "APISecurityPipeline",
                        "version": self.PIPELINE_VERSION,
                    }),
                )
                db.add(art)
                db.flush()
                artifact_id = art.id

            # 2. Create AnalysisRun record
            run = AnalysisRunModel(
                id=run_id,
                artifact_id=artifact_id,
                status=AnalysisStatusEnum.COMPLETED.value,
                started_at=get_utc_now(),
                completed_at=get_utc_now(),
                trigger=trigger.value,
                pipeline_version=self.PIPELINE_VERSION,
                overall_risk_score=overall_score,
                overall_severity=overall_severity.value,
                confidence=0.92 if findings else 1.0,
                metadata_json=json.dumps({
                    "analyzer_name": "api_abuse_analyzer",
                    "analyzer_version": self.PIPELINE_VERSION,
                    "summary": f"Analyzed {len(normalized_events)} API events. Evaluated {len(findings)} findings.",
                    "events_analyzed": len(normalized_events),
                    "finding_count": len(findings),
                    "corroborated_count": len(corroborated_threat_events),
                    "unique_accounts": len({e.account_id for e in normalized_events if e.account_id}),
                    "unique_sessions": len({e.session_id for e in normalized_events if e.session_id}),
                }),
            )
            db.add(run)
            db.flush()

            # 3. Persist Findings & Evidence Items
            for f in findings:
                finding_id = generate_uuid()
                f_model = FindingModel(
                    id=finding_id,
                    analysis_run_id=run_id,
                    analyzer="api_abuse_analyzer",
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
                        "rule_version": f.rule_version,
                        "mitre_attack_ids": f.mitre_attack_ids,
                        "limitation": f.limitation,
                        "target_account": f.target_account,
                        "target_session": f.target_session,
                        "target_source_ip": f.target_source_ip,
                        "target_endpoint": f.target_endpoint,
                    }),
                )
                db.add(f_model)

                for ev_item in f.evidence_items:
                    ev_model = FindingEvidenceModel(
                        id=generate_uuid(),
                        finding_id=finding_id,
                        evidence_type="API_TELEMETRY",
                        source=ev_item.source,
                        key=ev_item.key,
                        value=ev_item.value,
                        confidence=ev_item.confidence,
                        artifact_id=artifact_id,
                    )
                    db.add(ev_model)

            # 4. Persist Corroborated ThreatEvents
            for c_event in corroborated_threat_events:
                te_model = ThreatEventModel(
                    id=generate_uuid(),
                    event_type=c_event.get("event_type", "API_ABUSE_SUSPECTED"),
                    summary=c_event.get("description", "Corroborated API abuse pattern detected."),
                    severity=c_event.get("severity", "HIGH"),
                    source_artifact_id=artifact_id,
                    confidence=0.92,
                    metadata_json=json.dumps(c_event),
                )
                db.add(te_model)

            # 5. Graph Entities, Indicators & Relationships
            entity_map: Dict[str, EntityModel] = {}
            for e in normalized_events:
                # Account entity
                if e.account_id and e.account_id not in entity_map:
                    ent = EntityModel(
                        id=generate_uuid(),
                        entity_type=EntityTypeEnum.ACCOUNT.value,
                        name=e.account_id,
                        external_id=e.account_id,
                        attributes_json=json.dumps({"is_service_account": e.is_service_account}),
                    )
                    db.add(ent)
                    entity_map[e.account_id] = ent

                # Session entity
                if e.session_id and e.session_id not in entity_map:
                    ent = EntityModel(
                        id=generate_uuid(),
                        entity_type=EntityTypeEnum.SESSION.value,
                        name=f"session_{e.session_id[:16]}",
                        external_id=e.session_id,
                        attributes_json=json.dumps({"account_id": e.account_id}),
                    )
                    db.add(ent)
                    entity_map[e.session_id] = ent

                # Service entity
                if e.service and e.service not in entity_map:
                    ent = EntityModel(
                        id=generate_uuid(),
                        entity_type=EntityTypeEnum.SERVICE.value,
                        name=e.service,
                        external_id=e.service,
                        attributes_json=json.dumps({}),
                    )
                    db.add(ent)
                    entity_map[e.service] = ent

                # Source IP Indicator
                if e.source_ip and e.source_ip != "127.0.0.1":
                    norm_ip = normalize_ip(e.source_ip)
                    existing_ind = db.query(IndicatorModel).filter_by(
                        indicator_type=IndicatorTypeEnum.IP.value,
                        normalized_value=norm_ip,
                    ).first()
                    if not existing_ind:
                        ind = IndicatorModel(
                            id=generate_uuid(),
                            indicator_type=IndicatorTypeEnum.IP.value,
                            value=e.source_ip,
                            normalized_value=norm_ip,
                            metadata_json=json.dumps({"source": "api_telemetry"}),
                        )
                        db.add(ind)

            db.commit()
            return run_id, artifact_id

        except Exception as e:
            logger.error(f"Failed to persist API security analysis: {e}", exc_info=True)
            db.rollback()
            return run_id, artifact_id

    async def reanalyze_artifact(self, artifact_id: str, db: Session) -> APISecurityAnalysisResponse:
        """
        Re-analyzes an existing API log artifact, creating a brand new AnalysisRun
        without modifying or destroying historical runs.
        """
        artifact = db.query(ArtifactModel).filter(ArtifactModel.id == artifact_id).first()
        if not artifact:
            raise ValueError(f"Artifact {artifact_id} not found in database.")

        meta = {}
        try:
            meta = json.loads(artifact.metadata_json or "{}")
        except Exception:
            pass

        # Retrieve stored raw payload from evidence storage or fallback to metadata
        payload_events: List[Any] = []
        try:
            target_key = artifact.storage_reference or artifact.sha256
            if target_key:
                raw_bytes = evidence_storage.retrieve_bytes(target_key)
                payload_events = json.loads(raw_bytes.decode("utf-8"))
        except Exception as e:
            logger.warning(f"Could not load payload from evidence storage: {e}")

        if not payload_events:
            payload_events = meta.get("events", [])

        return await self.analyze_events(
            raw_events=payload_events,
            db=db,
            artifact_id=artifact_id,
            trigger=AnalysisTriggerEnum.REANALYSIS,
        )


global_api_pipeline = APISecurityPipeline()
