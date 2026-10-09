"""
Section 33: Evidence-Backed Device-to-Incident Correlation Service.
Connects endpoint telemetry with CyberGuard's Incident system, Security Knowledge Graph,
Temporal Correlation, Threat Memory, Behavioral Baseline, and Explainable AI.

CORE DESIGN PRINCIPLE:
"A device being connected to an incident is an evidence-backed association,
not an automatic declaration that the device is compromised."
"""

from __future__ import annotations

import json
import logging
import uuid
import ipaddress
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Set, Tuple

from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, desc, func

from backend.db.models import (
    DeviceModel,
    EndpointAgentModel,
    EndpointTelemetryEventModel,
    IncidentModel,
    ThreatEventModel,
    RelationshipModel,
    CaseEmailModel,
    ArtifactModel,
    EvidenceModel,
    BehavioralDeviationModel,
    NoveltyAssessmentModel,
    ThreatMemoryEntryModel,
    DeviceIncidentCorrelationModel,
    AuditLogModel,
    generate_uuid,
    get_utc_now,
)
from backend.schemas.device_incident_correlation import (
    DeviceCorrelationTypeEnum,
    DeviceAssociationStatusEnum,
    CorrelationReasonCodeEnum,
    AnalystReviewActionEnum,
    MatchedIndicatorItem,
    TemporalContextItem,
    CounterEvidenceItem,
    CorrelationExplanationFacts,
    DeviceIncidentCorrelationResponse,
    IncidentDevicesSummaryResponse,
    DeviceIncidentsHistoryResponse,
    DeviceTimelineItem,
    DeviceTimelineResponse,
)
from backend.services.security_graph_service import SecurityGraphService
from backend.services.threat_memory_service import ThreatMemoryService
from backend.services.audit_service import AuditService

logger = logging.getLogger("cyberguard.services.device_incident_correlation")

CORRELATION_ENGINE_VERSION = "1.0.0"
DEFAULT_RETENTION_NOTICE = "Evaluation constrained to available 30-day endpoint telemetry retention window."

# Common Operating System binaries that have low discriminative value
COMMON_SOFTWARE_NAMES = {
    "launchd", "systemd", "svchost.exe", "explorer.exe", "lsass.exe",
    "services.exe", "csrss.exe", "init", "kernel_task", "bash", "zsh", "sh"
}

# Known shared infrastructure / public resolver subnets
SHARED_RESOLVER_IPS = {
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "208.67.222.222", "208.67.220.220"
}


class DeviceIncidentCorrelationService:
    """
    Central service for calculating, persisting, and explaining bidirectional
    device-to-incident associations.
    """

    # =========================================================================
    # 1. CANDIDATE RETRIEVAL
    # =========================================================================

    @classmethod
    def find_candidate_incidents(
        cls,
        db: Session,
        device_id: str,
        workspace_id: str,
        window_hours: int = 72,
        limit: int = 50
    ) -> List[IncidentModel]:
        """
        Retrieves candidate incidents relevant to a given device based on:
        - Exact IOC overlap (hashes, domains, IPs, users)
        - ThreatEvents directly linked to the device
        - Knowledge Graph connectivity within the temporal window.
        """
        now = get_utc_now()
        window_start = now - timedelta(hours=window_hours)

        # 1. Extract recent telemetry indicators from device
        device_events = db.query(EndpointTelemetryEventModel).filter(
            and_(
                EndpointTelemetryEventModel.device_id == device_id,
                EndpointTelemetryEventModel.workspace_id == workspace_id,
                EndpointTelemetryEventModel.event_time >= window_start
            )
        ).limit(200).all()

        hashes: Set[str] = set()
        domains: Set[str] = set()
        ips: Set[str] = set()
        users: Set[str] = set()

        for ev in device_events:
            pld = json.loads(ev.payload_json or "{}")
            h = pld.get("sha256") or pld.get("executable_hash")
            if h and h not in ("UNKNOWN", "OVERSIZED_SKIPPED"):
                hashes.add(h.lower())
            d = pld.get("queried_domain")
            if d:
                domains.add(d.lower().rstrip("."))
            rem_ip = pld.get("remote_address")
            if rem_ip and rem_ip not in ("0.0.0.0", "127.0.0.1", "::1"):
                ips.add(rem_ip)
            u = pld.get("username")
            if u and u not in ("root", "SYSTEM", "nobody", "daemon"):
                users.add(u.lower())

        # 2. Query incidents overlapping with the temporal window
        incidents = db.query(IncidentModel).filter(
            and_(
                IncidentModel.workspace_id == workspace_id,
                IncidentModel.opened_at >= window_start - timedelta(days=7)
            )
        ).order_by(desc(IncidentModel.opened_at)).limit(limit).all()

        candidate_incidents: List[IncidentModel] = []
        for inc in incidents:
            # Check for direct ThreatEvent overlap
            has_overlap = False
            for te in inc.threat_events:
                meta = json.loads(te.metadata_json or "{}")
                if meta.get("device_id") == device_id:
                    has_overlap = True
                    break
                raw_pld = meta.get("raw_payload", {})
                te_h = (raw_pld.get("sha256") or raw_pld.get("executable_hash") or "").lower()
                if te_h and te_h in hashes:
                    has_overlap = True
                    break
                te_d = (raw_pld.get("queried_domain") or "").lower()
                if te_d and te_d in domains:
                    has_overlap = True
                    break
                te_ip = raw_pld.get("remote_address")
                if te_ip and te_ip in ips:
                    has_overlap = True
                    break

            if has_overlap:
                candidate_incidents.append(inc)
                continue

            # Fallback: check summary or description for matching indicator strings
            inc_text = f"{inc.title} {inc.description or ''}".lower()
            if any(h in inc_text for h in hashes if len(h) >= 32):
                candidate_incidents.append(inc)
                continue
            if any(d in inc_text for d in domains if len(d) >= 4):
                candidate_incidents.append(inc)
                continue

            # Check Knowledge Graph link
            edge_exists = db.query(RelationshipModel).filter(
                and_(
                    RelationshipModel.workspace_id == workspace_id,
                    RelationshipModel.source_id == device_id,
                    RelationshipModel.target_id == inc.id
                )
            ).first()
            if edge_exists:
                candidate_incidents.append(inc)

        return candidate_incidents[:limit]

    @classmethod
    def find_candidate_devices(
        cls,
        db: Session,
        incident_id: str,
        workspace_id: str,
        window_hours: int = 72,
        limit: int = 50
    ) -> List[DeviceModel]:
        """
        Retrieves candidate devices relevant to an incident.
        """
        incident = db.query(IncidentModel).filter(
            and_(
                IncidentModel.id == incident_id,
                IncidentModel.workspace_id == workspace_id
            )
        ).first()
        if not incident:
            return []

        # Find devices that have active telemetry in the incident window
        devices = db.query(DeviceModel).filter(
            DeviceModel.workspace_id == workspace_id
        ).order_by(desc(DeviceModel.last_seen_at)).limit(limit).all()

        return devices

    # =========================================================================
    # 2. CORE EVIDENCE-BACKED CORRELATION LOGIC
    # =========================================================================

    @classmethod
    def correlate_device_with_incident(
        cls,
        db: Session,
        device: Any,
        incident: Any,
        workspace_id: str,
        telemetry_events: Optional[List[EndpointTelemetryEventModel]] = None
    ) -> DeviceIncidentCorrelationModel:
        """
        Performs multi-vector evidence correlation between a single device and an incident.
        Evaluates exact identifiers, IOCs, temporal alignment, graph paths, behavioral deviations,
        and counter-evidence.
        """
        now = get_utc_now()

        # 0. Resolve string IDs to models if needed and enforce tenant boundaries
        if isinstance(device, str):
            dev_obj = db.query(DeviceModel).filter(
                and_(DeviceModel.id == device, DeviceModel.workspace_id == workspace_id)
            ).first()
            if not dev_obj:
                raise ValueError(f"Device '{device}' not found in workspace '{workspace_id}'.")
            device = dev_obj

        if isinstance(incident, str):
            inc_obj = db.query(IncidentModel).filter(
                and_(IncidentModel.id == incident, IncidentModel.workspace_id == workspace_id)
            ).first()
            if not inc_obj:
                raise ValueError(f"Incident '{incident}' not found in workspace '{workspace_id}'.")
            incident = inc_obj

        if device.workspace_id != workspace_id or incident.workspace_id != workspace_id:
            raise ValueError("Cross-tenant correlation rejected: workspace boundary violation.")

        # 1. Gather device telemetry if not provided
        if telemetry_events is None:
            telemetry_events = db.query(EndpointTelemetryEventModel).filter(
                and_(
                    EndpointTelemetryEventModel.device_id == device.id,
                    EndpointTelemetryEventModel.workspace_id == workspace_id
                )
            ).order_by(desc(EndpointTelemetryEventModel.event_time)).limit(200).all()

        # 2. Gather incident indicators and context
        incident_hashes: Set[str] = set()
        incident_domains: Set[str] = set()
        incident_ips: Set[str] = set()
        incident_users: Set[str] = set()
        incident_threat_event_ids: Set[str] = {te.id for te in incident.threat_events}

        # Check attached threat events
        for te in incident.threat_events:
            meta = json.loads(te.metadata_json or "{}")
            raw_pld = meta.get("raw_payload", {})
            h = (raw_pld.get("sha256") or raw_pld.get("executable_hash") or meta.get("sha256") or "").lower()
            if h and len(h) >= 32:
                incident_hashes.add(h)
            for art in (meta.get("target_artifacts") or meta.get("artifacts") or []):
                if isinstance(art, dict):
                    art_h = (art.get("sha256") or art.get("hash") or "").lower()
                    if art_h:
                        incident_hashes.add(art_h)
            d = (raw_pld.get("queried_domain") or meta.get("domain") or meta.get("queried_domain") or "").lower().rstrip(".")
            if d:
                incident_domains.add(d)
            for dom in (meta.get("target_domains") or meta.get("domains") or []):
                if isinstance(dom, str):
                    incident_domains.add(dom.lower().rstrip("."))
            ip = raw_pld.get("remote_address") or meta.get("remote_address") or meta.get("ip")
            if ip and ip not in ("0.0.0.0", "127.0.0.1"):
                incident_ips.add(ip)
            for item_ip in (meta.get("target_ips") or meta.get("ips") or []):
                if isinstance(item_ip, str) and item_ip not in ("0.0.0.0", "127.0.0.1"):
                    incident_ips.add(item_ip)
            u = (raw_pld.get("username") or meta.get("username") or meta.get("user") or "").lower()
            if u:
                incident_users.add(u)

        # Check legacy case emails / attachments if present
        if incident.legacy_case_id:
            emails = db.query(CaseEmailModel).filter(CaseEmailModel.case_id == incident.legacy_case_id).all()
            for em in emails:
                if em.email_sha256:
                    incident_hashes.add(em.email_sha256.lower())
                inds = json.loads(em.indicators_json or "{}")
                for h in inds.get("hashes", []):
                    incident_hashes.add(h.lower())
                for d in inds.get("domains", []):
                    incident_domains.add(d.lower().rstrip("."))
                for ip in inds.get("ips", []):
                    incident_ips.add(ip)

        # 3. Correlation Accumulators
        matched_indicators: List[Dict[str, Any]] = []
        reason_codes: List[str] = []
        counter_evidence: List[Dict[str, Any]] = []
        limitations: List[str] = [DEFAULT_RETENTION_NOTICE]
        supporting_event_ids: List[str] = []
        supporting_evidence_ids: List[str] = []
        supporting_entity_ids: List[str] = []
        supporting_relationship_ids: List[str] = []
        matched_behaviors: List[Dict[str, Any]] = []
        facts: List[str] = []
        positive_signals: List[str] = []
        negative_signals: List[str] = []

        base_score = 0.0
        confidence = 1.0
        correlation_type = DeviceCorrelationTypeEnum.OBSERVED
        primary_temporal_context: Dict[str, Any] = {}
        min_delta_seconds = float("inf")

        # 4. Multi-Vector Evaluation across Device Telemetry
        for ev in telemetry_events:
            pld = json.loads(ev.payload_json or "{}")
            ev_h = (pld.get("sha256") or pld.get("executable_hash") or pld.get("process_hash") or pld.get("hash") or "").lower()
            ev_d = (pld.get("queried_domain") or pld.get("domain") or "").lower().rstrip(".")
            ev_ip = pld.get("remote_address") or pld.get("destination_ip") or pld.get("dest_ip") or pld.get("ip")
            ev_u = (pld.get("username") or pld.get("user") or "").lower()
            ev_proc = pld.get("process_name") or pld.get("process") or ""

            # Check Temporal Delta against incident opened_at
            inc_time = incident.opened_at
            if inc_time.tzinfo is None:
                inc_time = inc_time.replace(tzinfo=timezone.utc)
            ev_time = ev.event_time
            if ev_time.tzinfo is None:
                ev_time = ev_time.replace(tzinfo=timezone.utc)
            delta_s = abs((inc_time - ev_time).total_seconds())
            if delta_s < min_delta_seconds:
                min_delta_seconds = delta_s
                primary_temporal_context = {
                    "delta_seconds": round(delta_s, 1),
                    "telemetry_time": ev_time.isoformat(),
                    "incident_time": inc_time.isoformat(),
                    "temporal_relationship": "TEMPORALLY_SUPPORTIVE" if delta_s <= 3600 else (
                        "CAUSALLY_SUPPORTED" if delta_s <= 900 else "TEMPORALLY_ADJACENT"
                    )
                }

            # A. Exact Binary / File Hash Match
            if ev_h and ev_h in incident_hashes:
                if ev.event_id not in supporting_event_ids:
                    supporting_event_ids.append(ev.event_id)
                supporting_entity_ids.append(f"hash:{ev_h}")
                matched_indicators.append({
                    "type": "SHA-256",
                    "value": ev_h,
                    "provenance": f"Collector {ev.collector_id}",
                    "confidence": 0.95,
                    "source": "process_executable_hash"
                })
                reason_codes.append(CorrelationReasonCodeEnum.EXACT_HASH_MATCH.value)
                facts.append(f"Process/file executable hash '{ev_h}' observed on {device.hostname} matches incident artifact.")
                positive_signals.append(f"Direct SHA-256 match ({ev_proc or 'binary'})")
                base_score = max(base_score, 0.90)
                correlation_type = DeviceCorrelationTypeEnum.FILE_HASH_MATCH if ev.event_type == "FILE_METADATA" else DeviceCorrelationTypeEnum.PROCESS_MATCH

            # B. Known Malicious Domain Match
            if ev_d and ev_d in incident_domains:
                if ev.event_id not in supporting_event_ids:
                    supporting_event_ids.append(ev.event_id)
                supporting_entity_ids.append(f"domain:{ev_d}")
                matched_indicators.append({
                    "type": "DOMAIN",
                    "value": ev_d,
                    "provenance": "DNS telemetry",
                    "confidence": 0.90,
                    "source": "dns_query"
                })
                reason_codes.append(CorrelationReasonCodeEnum.KNOWN_MALICIOUS_DOMAIN_OBSERVED.value)
                facts.append(f"DNS query for domain '{ev_d}' observed on {device.hostname} matches incident target domain.")
                positive_signals.append(f"Matching DNS query to incident domain '{ev_d}'")
                base_score = max(base_score, 0.80)
                if correlation_type not in (DeviceCorrelationTypeEnum.FILE_HASH_MATCH, DeviceCorrelationTypeEnum.PROCESS_MATCH):
                    correlation_type = DeviceCorrelationTypeEnum.DOMAIN_MATCH

            # C. Remote IP Match & Shared Infrastructure Handling
            if ev_ip and ev_ip in incident_ips:
                if ev.event_id not in supporting_event_ids:
                    supporting_event_ids.append(ev.event_id)
                supporting_entity_ids.append(f"ip:{ev_ip}")

                # Check if shared infrastructure / NAT / public DNS
                is_shared_infra = ev_ip in SHARED_RESOLVER_IPS
                if not is_shared_infra:
                    try:
                        ip_obj = ipaddress.ip_address(ev_ip)
                        if ip_obj.is_private or ip_obj.is_loopback:
                            is_shared_infra = True
                    except ValueError:
                        pass

                if is_shared_infra:
                    counter_evidence.append({
                        "code": CorrelationReasonCodeEnum.SHARED_NAT.value,
                        "description": f"Destination IP '{ev_ip}' is recognized as shared infrastructure / NAT or public resolver.",
                        "penalty": 0.45,
                        "severity": "HIGH"
                    })
                    reason_codes.append(CorrelationReasonCodeEnum.SHARED_NAT.value)
                    reason_codes.append(CorrelationReasonCodeEnum.COMMON_INFRASTRUCTURE.value)
                    negative_signals.append(f"Destination IP '{ev_ip}' is shared infrastructure")
                    facts.append(f"Connection to IP '{ev_ip}' observed, but IP is recognized as shared NAT/resolver infrastructure.")
                    base_score = max(base_score, 0.25)
                else:
                    matched_indicators.append({
                        "type": "IP",
                        "value": ev_ip,
                        "provenance": "Network telemetry",
                        "confidence": 0.85,
                        "source": "network_connection"
                    })
                    reason_codes.append(CorrelationReasonCodeEnum.INCIDENT_IP_OBSERVED.value)
                    facts.append(f"Network connection to incident remote address '{ev_ip}' observed on {device.hostname}.")
                    positive_signals.append(f"Network connection to incident IP '{ev_ip}'")
                    base_score = max(base_score, 0.70)
                    if correlation_type == DeviceCorrelationTypeEnum.OBSERVED:
                        correlation_type = DeviceCorrelationTypeEnum.IP_MATCH

            # D. Common Operating System Software Discounting
            if ev_proc and ev_proc.lower() in COMMON_SOFTWARE_NAMES:
                if ev_h not in incident_hashes:  # Only penalize if hash was NOT an exact match
                    counter_evidence.append({
                        "code": CorrelationReasonCodeEnum.COMMON_SOFTWARE.value,
                        "description": f"Process '{ev_proc}' is common benign operating system software.",
                        "penalty": 0.15,
                        "severity": "LOW"
                    })
                    reason_codes.append(CorrelationReasonCodeEnum.COMMON_SOFTWARE.value)
                    negative_signals.append(f"Process '{ev_proc}' is common system software")

            # E. User / Session Match
            if ev_u and ev_u in incident_users:
                reason_codes.append(CorrelationReasonCodeEnum.SAME_USER_SESSION.value)
                facts.append(f"User account '{ev_u}' active on {device.hostname} corresponds to target user in incident.")
                positive_signals.append(f"Target user account '{ev_u}' active on device")
                if base_score < 0.40:
                    base_score = 0.35
                    correlation_type = DeviceCorrelationTypeEnum.USER_MATCH

        # 5. Temporal Alignment Integration (Section 16)
        if min_delta_seconds != float("inf"):
            if min_delta_seconds <= 3600:
                reason_codes.append(CorrelationReasonCodeEnum.TEMPORALLY_ALIGNED_SEQUENCE.value)
                positive_signals.append(f"Observations temporally supportive (delta {round(min_delta_seconds / 60, 1)}m)")
                base_score = min(1.0, base_score + 0.05)
            elif min_delta_seconds > 72 * 3600:
                counter_evidence.append({
                    "code": CorrelationReasonCodeEnum.TEMPORAL_MISMATCH.value,
                    "description": f"Observation occurred {round(min_delta_seconds / 3600, 1)}h away from incident window.",
                    "penalty": 0.20,
                    "severity": "MEDIUM"
                })
                reason_codes.append(CorrelationReasonCodeEnum.TEMPORAL_MISMATCH.value)
                negative_signals.append(f"Telemetry delta is {round(min_delta_seconds / 3600, 1)} hours")

        # 6. Security Knowledge Graph Integration (Section 14)
        skg_edge = db.query(RelationshipModel).filter(
            and_(
                RelationshipModel.workspace_id == workspace_id,
                RelationshipModel.source_id == device.id,
                or_(
                    RelationshipModel.target_id == incident.id,
                    RelationshipModel.target_id.in_(list(incident_threat_event_ids) or ["none"])
                )
            )
        ).first()
        if skg_edge:
            supporting_relationship_ids.append(skg_edge.id)
            reason_codes.append(CorrelationReasonCodeEnum.GRAPH_PATH_SUPPORTED.value)
            facts.append(f"Direct Security Knowledge Graph edge '{skg_edge.relationship_type}' connects {device.hostname} to incident.")
            positive_signals.append("Direct edge in Security Knowledge Graph")
            base_score = min(1.0, base_score + 0.05)

        # 7. Behavioral Baseline & Novelty Integration (Sections 21 & 22)
        devs = db.query(BehavioralDeviationModel).filter(
            and_(
                BehavioralDeviationModel.incident_id == incident.id,
                BehavioralDeviationModel.workspace_id == workspace_id
            )
        ).all()
        if devs:
            reason_codes.append(CorrelationReasonCodeEnum.BEHAVIORAL_DEVIATION_ALIGNED.value)
            facts.append("Incident contains behavioral baseline deviations matching this entity context.")
            positive_signals.append("Behavioral baseline deviations aligned")
            matched_behaviors.append({"type": "BEHAVIORAL_DEVIATION", "count": len(devs)})
            base_score = min(1.0, base_score + 0.05)

        # 8. Threat Memory Integration (Section 23)
        for ind in matched_indicators:
            tm_entry = ThreatMemoryService.lookup_indicator(
                db=db,
                workspace_id=workspace_id,
                value=ind["value"]
            )
            if tm_entry:
                reason_codes.append(CorrelationReasonCodeEnum.THREAT_MEMORY_MATCH.value)
                facts.append(f"Indicator '{ind['value']}' verified in historical Threat Memory ({tm_entry.canonical_key}).")
                positive_signals.append("Matched verified Threat Memory entry")
                base_score = min(1.0, base_score + 0.05)
                break

        # 9. Deduplication and Multi-Signal Classification
        # Multiple distinct positive signal families elevate to MULTI_SIGNAL_CORRELATION
        distinct_signal_types = {
            r for r in reason_codes if r in (
                CorrelationReasonCodeEnum.EXACT_HASH_MATCH.value,
                CorrelationReasonCodeEnum.KNOWN_MALICIOUS_DOMAIN_OBSERVED.value,
                CorrelationReasonCodeEnum.INCIDENT_IP_OBSERVED.value,
                CorrelationReasonCodeEnum.TEMPORALLY_ALIGNED_SEQUENCE.value,
                CorrelationReasonCodeEnum.GRAPH_PATH_SUPPORTED.value,
                CorrelationReasonCodeEnum.THREAT_MEMORY_MATCH.value,
            )
        }
        if len(distinct_signal_types) >= 2:
            correlation_type = DeviceCorrelationTypeEnum.MULTI_SIGNAL_CORRELATION
            reason_codes.append(CorrelationReasonCodeEnum.MULTI_SIGNAL_SUPPORT.value)

        # Apply counter-evidence penalties
        total_penalty = sum(c.get("penalty", 0.0) for c in counter_evidence)
        net_score = max(0.0, min(1.0, round(base_score - total_penalty, 3)))
        confidence = max(0.1, min(1.0, round(1.0 - total_penalty, 2)))

        # Determine Association Status
        if net_score >= 0.80 and (CorrelationReasonCodeEnum.EXACT_HASH_MATCH.value in reason_codes or len(distinct_signal_types) >= 3):
            status = DeviceAssociationStatusEnum.CONFIRMED.value
        elif net_score >= 0.65:
            status = DeviceAssociationStatusEnum.SUPPORTED.value
        elif net_score >= 0.40:
            status = DeviceAssociationStatusEnum.SUSPECTED.value
        elif net_score >= 0.15:
            status = DeviceAssociationStatusEnum.RELATED.value
        else:
            status = DeviceAssociationStatusEnum.OBSERVED.value

        if not facts:
            facts.append(f"No direct matching telemetry observed between {device.hostname} and {incident.incident_number} in active retention window.")
            status = DeviceAssociationStatusEnum.OBSERVED.value

        # Build Explanation Narrative
        narrative = (
            f"Device '{device.hostname}' ({device.platform}) is associated with incident {incident.incident_number} "
            f"with status {status} (correlation strength {round(net_score * 100)}%). "
            f"Identified {len(positive_signals)} supporting observations and {len(negative_signals)} counter-evidence factors."
        )

        structured_explanation = {
            "device_name": device.hostname,
            "incident_number": incident.incident_number,
            "facts": facts,
            "positive_signals": positive_signals,
            "negative_signals": negative_signals,
            "narrative": narrative
        }

        # Deduplicate reason codes
        unique_reason_codes = list(dict.fromkeys(reason_codes))

        # 10. Persist or Version Correlation Record
        existing_corr = db.query(DeviceIncidentCorrelationModel).filter(
            and_(
                DeviceIncidentCorrelationModel.workspace_id == workspace_id,
                DeviceIncidentCorrelationModel.device_id == device.id,
                DeviceIncidentCorrelationModel.incident_id == incident.id,
                DeviceIncidentCorrelationModel.is_current == True
            )
        ).first()

        corr_record: DeviceIncidentCorrelationModel
        if existing_corr:
            # Check if material change requires new version
            if (existing_corr.status != status or
                abs(existing_corr.correlation_score - net_score) > 0.05 or
                existing_corr.correlation_type != correlation_type.value):
                # Archive old version
                existing_corr.is_current = False
                existing_corr.updated_at = now
                new_version = existing_corr.version + 1

                corr_record = DeviceIncidentCorrelationModel(
                    id=generate_uuid(),
                    workspace_id=workspace_id,
                    device_id=device.id,
                    incident_id=incident.id,
                    correlation_type=correlation_type.value,
                    correlation_score=net_score,
                    confidence=confidence,
                    status=status,
                    version=new_version,
                    is_current=True,
                    first_observed_at=existing_corr.first_observed_at,
                    last_observed_at=now,
                    supporting_event_ids_json=json.dumps(supporting_event_ids),
                    supporting_evidence_ids_json=json.dumps(supporting_evidence_ids),
                    supporting_entity_ids_json=json.dumps(supporting_entity_ids),
                    supporting_relationship_ids_json=json.dumps(supporting_relationship_ids),
                    matched_indicators_json=json.dumps(matched_indicators),
                    matched_behaviors_json=json.dumps(matched_behaviors),
                    temporal_context_json=json.dumps(primary_temporal_context),
                    reason_codes_json=json.dumps(unique_reason_codes),
                    counter_evidence_json=json.dumps(counter_evidence),
                    limitations_json=json.dumps(limitations),
                    structured_explanation_json=json.dumps(structured_explanation),
                    correlation_engine_version=CORRELATION_ENGINE_VERSION,
                    created_at=now,
                    updated_at=now
                )
                db.add(corr_record)
            else:
                # Update existing record timestamps
                existing_corr.last_observed_at = now
                existing_corr.updated_at = now
                existing_corr.supporting_event_ids_json = json.dumps(supporting_event_ids)
                existing_corr.structured_explanation_json = json.dumps(structured_explanation)
                corr_record = existing_corr
        else:
            # Create first version
            corr_record = DeviceIncidentCorrelationModel(
                id=generate_uuid(),
                workspace_id=workspace_id,
                device_id=device.id,
                incident_id=incident.id,
                correlation_type=correlation_type.value,
                correlation_score=net_score,
                confidence=confidence,
                status=status,
                version=1,
                is_current=True,
                first_observed_at=now,
                last_observed_at=now,
                supporting_event_ids_json=json.dumps(supporting_event_ids),
                supporting_evidence_ids_json=json.dumps(supporting_evidence_ids),
                supporting_entity_ids_json=json.dumps(supporting_entity_ids),
                supporting_relationship_ids_json=json.dumps(supporting_relationship_ids),
                matched_indicators_json=json.dumps(matched_indicators),
                matched_behaviors_json=json.dumps(matched_behaviors),
                temporal_context_json=json.dumps(primary_temporal_context),
                reason_codes_json=json.dumps(unique_reason_codes),
                counter_evidence_json=json.dumps(counter_evidence),
                limitations_json=json.dumps(limitations),
                structured_explanation_json=json.dumps(structured_explanation),
                correlation_engine_version=CORRELATION_ENGINE_VERSION,
                created_at=now,
                updated_at=now
            )
            db.add(corr_record)

        # 11. Security Knowledge Graph Edge Synchronization
        # DEVICE -> ASSOCIATED_WITH -> INCIDENT
        graph_edge = db.query(RelationshipModel).filter(
            and_(
                RelationshipModel.workspace_id == workspace_id,
                RelationshipModel.source_type == "DEVICE",
                RelationshipModel.source_id == device.id,
                RelationshipModel.relationship_type == "ASSOCIATED_WITH",
                RelationshipModel.target_type == "INCIDENT",
                RelationshipModel.target_id == incident.id
            )
        ).first()

        if not graph_edge:
            db.add(RelationshipModel(
                id=generate_uuid(),
                source_type="DEVICE",
                source_id=device.id,
                relationship_type="ASSOCIATED_WITH",
                target_type="INCIDENT",
                target_id=incident.id,
                confidence=confidence,
                origin="DERIVED",
                status="ACTIVE",
                workspace_id=workspace_id,
                first_seen=now,
                last_seen=now,
                evidence_reference=corr_record.id,
                method="DEVICE_INCIDENT_CORRELATION",
                metadata_json=json.dumps({
                    "correlation_score": net_score,
                    "status": status,
                    "reasons": unique_reason_codes
                }),
                created_at=now,
                updated_at=now
            ))
        else:
            graph_edge.confidence = confidence
            graph_edge.last_seen = now
            graph_edge.metadata_json = json.dumps({
                "correlation_score": net_score,
                "status": status,
                "reasons": unique_reason_codes
            })

        db.commit()
        db.refresh(corr_record)
        return corr_record

    # =========================================================================
    # 3. REASSESSMENT & EVENT INGESTION HOOK
    # =========================================================================

    @classmethod
    def reassess_for_telemetry_event(
        cls,
        db: Session,
        telemetry_event: EndpointTelemetryEventModel,
        workspace_id: str
    ) -> List[DeviceIncidentCorrelationModel]:
        """
        Called when new endpoint telemetry is ingested.
        Triggers targeted correlation reassessment against candidate incidents.
        """
        device = db.query(DeviceModel).filter(DeviceModel.id == telemetry_event.device_id).first()
        if not device:
            return []

        candidates = cls.find_candidate_incidents(
            db=db,
            device_id=device.id,
            workspace_id=workspace_id,
            window_hours=72,
            limit=20
        )

        results = []
        for inc in candidates:
            corr = cls.correlate_device_with_incident(
                db=db,
                device=device,
                incident=inc,
                workspace_id=workspace_id
            )
            results.append(corr)

        return results

    # =========================================================================
    # 4. ANALYST FEEDBACK & REVIEW
    # =========================================================================

    @classmethod
    def review_correlation(
        cls,
        db: Session,
        correlation_id: str,
        action: AnalystReviewActionEnum,
        reviewer: str,
        notes: Optional[str],
        workspace_id: str
    ) -> DeviceIncidentCorrelationModel:
        """
        Records human-in-the-loop analyst feedback on a device-incident correlation.
        Stores an auditable decision without modifying raw telemetry observations.
        """
        now = get_utc_now()
        corr = db.query(DeviceIncidentCorrelationModel).filter(
            and_(
                DeviceIncidentCorrelationModel.id == correlation_id,
                DeviceIncidentCorrelationModel.workspace_id == workspace_id
            )
        ).first()

        if not corr:
            raise ValueError(f"Correlation record '{correlation_id}' not found.")

        old_status = corr.status
        if action == AnalystReviewActionEnum.CONFIRM_ASSOCIATION:
            corr.status = DeviceAssociationStatusEnum.CONFIRMED.value
        elif action == AnalystReviewActionEnum.DISMISS_ASSOCIATION:
            corr.status = DeviceAssociationStatusEnum.DISMISSED.value
        elif action == AnalystReviewActionEnum.MARK_RELATED:
            corr.status = DeviceAssociationStatusEnum.RELATED.value
        elif action == AnalystReviewActionEnum.MARK_FALSE_ASSOCIATION:
            corr.status = DeviceAssociationStatusEnum.DISMISSED.value

        corr.reviewed_by = reviewer
        corr.reviewed_at = now
        corr.review_notes = notes
        corr.updated_at = now

        db.commit()
        db.refresh(corr)

        # Audit log
        AuditService.log_audit(
            db=db,
            action="DEVICE_CORRELATION_REVIEWED",
            resource_type="device_incident_correlation",
            resource_id=corr.id,
            user=reviewer,
            metadata={
                "action": action.value,
                "old_status": old_status,
                "new_status": corr.status,
                "device_id": corr.device_id,
                "incident_id": corr.incident_id
            },
            details=f"Analyst {reviewer} set status to {corr.status}: {notes or 'No notes provided'}"
        )

        return corr

    # =========================================================================
    # 5. DEVICE TIMELINE SYNTHESIS
    # =========================================================================

    @classmethod
    def get_device_timeline(
        cls,
        db: Session,
        device_id: str,
        workspace_id: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100
    ) -> DeviceTimelineResponse:
        """
        Synthesizes chronological timeline of all activities on the device.
        Preserves event_time vs received_at, source provenance, and confidence.
        """
        device = db.query(DeviceModel).filter(
            and_(
                DeviceModel.id == device_id,
                DeviceModel.workspace_id == workspace_id
            )
        ).first()

        if not device:
            raise ValueError(f"Device '{device_id}' not found in workspace '{workspace_id}'.")

        q = db.query(EndpointTelemetryEventModel).filter(
            and_(
                EndpointTelemetryEventModel.device_id == device_id,
                EndpointTelemetryEventModel.workspace_id == workspace_id
            )
        )
        if start_time:
            q = q.filter(EndpointTelemetryEventModel.event_time >= start_time)
        if end_time:
            q = q.filter(EndpointTelemetryEventModel.event_time <= end_time)

        events = q.order_by(desc(EndpointTelemetryEventModel.event_time)).limit(limit).all()

        timeline_items: List[DeviceTimelineItem] = []
        for ev in reversed(events):
            pld = json.loads(ev.payload_json or "{}")
            action_desc = pld.get("action") or pld.get("lifecycle_action") or ev.event_type

            desc_text = f"Endpoint {ev.event_type} event: {action_desc}"
            if pld.get("process_name"):
                desc_text += f" (Process: {pld['process_name']})"
            elif pld.get("queried_domain"):
                desc_text += f" (Domain: {pld['queried_domain']})"
            elif pld.get("remote_address"):
                desc_text += f" (Destination: {pld['remote_address']}:{pld.get('remote_port', 0)})"

            timeline_items.append(DeviceTimelineItem(
                timestamp=ev.event_time,
                event_type=ev.event_type,
                source=f"Collector:{ev.collector_id}",
                description=desc_text,
                priority=ev.priority,
                confidence=1.0,
                raw_event_id=ev.event_id,
                threat_event_id=ev.threat_event_id,
                metadata={
                    "received_at": ev.received_at.isoformat(),
                    "sequence_number": ev.sequence_number,
                    "payload": pld
                }
            ))

        return DeviceTimelineResponse(
            device_id=device.id,
            hostname=device.hostname,
            total_events=len(timeline_items),
            timeline=timeline_items,
            retention_notice="Displaying observations within available 30-day telemetry retention window."
        )

    # =========================================================================
    # 6. BIDIRECTIONAL LOOKUP QUERIES
    # =========================================================================

    @classmethod
    def get_incident_devices_summary(
        cls,
        db: Session,
        incident_id: str,
        workspace_id: str
    ) -> IncidentDevicesSummaryResponse:
        """
        Returns incident-centric view of all correlated devices with status breakdown.
        """
        incident = db.query(IncidentModel).filter(
            and_(
                IncidentModel.id == incident_id,
                IncidentModel.workspace_id == workspace_id
            )
        ).first()

        if not incident:
            raise ValueError(f"Incident '{incident_id}' not found.")

        corrs = db.query(DeviceIncidentCorrelationModel).filter(
            and_(
                DeviceIncidentCorrelationModel.incident_id == incident_id,
                DeviceIncidentCorrelationModel.workspace_id == workspace_id,
                DeviceIncidentCorrelationModel.is_current == True
            )
        ).order_by(desc(DeviceIncidentCorrelationModel.correlation_score)).all()

        device_items = []
        counts = {
            "CONFIRMED": 0,
            "SUPPORTED": 0,
            "SUSPECTED": 0,
            "RELATED": 0,
            "OBSERVED": 0,
            "DISMISSED": 0
        }

        for c in corrs:
            counts[c.status] = counts.get(c.status, 0) + 1
            dev = db.query(DeviceModel).filter(DeviceModel.id == c.device_id).first()
            device_items.append({
                "correlation_id": c.id,
                "device_id": c.device_id,
                "hostname": dev.hostname if dev else "Unknown",
                "platform": dev.platform if dev else "unknown",
                "status": c.status,
                "correlation_score": c.correlation_score,
                "confidence": c.confidence,
                "correlation_type": c.correlation_type,
                "first_observed_at": c.first_observed_at.isoformat(),
                "last_observed_at": c.last_observed_at.isoformat(),
                "reason_codes": json.loads(c.reason_codes_json or "[]"),
                "supporting_signals_count": len(json.loads(c.supporting_event_ids_json or "[]")),
                "counter_evidence_count": len(json.loads(c.counter_evidence_json or "[]")),
                "explanation": json.loads(c.structured_explanation_json or "{}")
            })

        return IncidentDevicesSummaryResponse(
            incident_id=incident.id,
            incident_number=incident.incident_number,
            total_devices=len(device_items),
            confirmed_count=counts["CONFIRMED"],
            supported_count=counts["SUPPORTED"],
            suspected_count=counts["SUSPECTED"],
            related_count=counts["RELATED"],
            observed_count=counts["OBSERVED"],
            dismissed_count=counts["DISMISSED"],
            devices=device_items,
            retention_notice=DEFAULT_RETENTION_NOTICE
        )

    @classmethod
    def get_device_incidents_history(
        cls,
        db: Session,
        device_id: str,
        workspace_id: str
    ) -> DeviceIncidentsHistoryResponse:
        """
        Returns device-centric view of all incidents associated with this device.
        """
        device = db.query(DeviceModel).filter(
            and_(
                DeviceModel.id == device_id,
                DeviceModel.workspace_id == workspace_id
            )
        ).first()

        if not device:
            raise ValueError(f"Device '{device_id}' not found.")

        corrs = db.query(DeviceIncidentCorrelationModel).filter(
            and_(
                DeviceIncidentCorrelationModel.device_id == device_id,
                DeviceIncidentCorrelationModel.workspace_id == workspace_id,
                DeviceIncidentCorrelationModel.is_current == True
            )
        ).order_by(desc(DeviceIncidentCorrelationModel.correlation_score)).all()

        incident_items = []
        for c in corrs:
            inc = db.query(IncidentModel).filter(IncidentModel.id == c.incident_id).first()
            incident_items.append({
                "correlation_id": c.id,
                "incident_id": c.incident_id,
                "incident_number": inc.incident_number if inc else "Unknown",
                "incident_title": inc.title if inc else "Unknown",
                "severity": inc.severity if inc else "UNKNOWN",
                "status": c.status,
                "correlation_score": c.correlation_score,
                "confidence": c.confidence,
                "correlation_type": c.correlation_type,
                "first_observed_at": c.first_observed_at.isoformat(),
                "last_observed_at": c.last_observed_at.isoformat(),
                "reason_codes": json.loads(c.reason_codes_json or "[]"),
                "supporting_signals_count": len(json.loads(c.supporting_event_ids_json or "[]")),
                "explanation": json.loads(c.structured_explanation_json or "{}")
            })

        return DeviceIncidentsHistoryResponse(
            device_id=device.id,
            hostname=device.hostname,
            platform=device.platform,
            total_incidents=len(incident_items),
            incidents=incident_items,
            retention_notice=DEFAULT_RETENTION_NOTICE
        )
