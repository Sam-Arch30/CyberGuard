"""
Canonical Temporal Correlation & Event Sequencing Engine (Section 16).
Provides timestamp normalization, clock skew correction, event projection,
sub-linear sequence candidate generation, timeline compression, and non-attribution temporal reasoning.
"""
from __future__ import annotations

import bisect
from datetime import datetime, timezone, timedelta
from email.utils import parsedate_to_datetime
import json
import logging
import math
import re
import uuid
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, desc, asc

from backend.db.models import (
    SecurityEventModel,
    TemporalSequenceCandidateModel,
    IncidentModel,
    CampaignModel,
    CampaignIncidentModel,
    EntityModel,
    RelationshipModel,
    RelationshipObservationModel,
    ThreatEventModel,
    FindingModel,
    FindingEvidenceModel,
    ArtifactModel,
    AnalysisRunModel,
    generate_uuid,
    get_utc_now,
)
from backend.schemas.temporal_correlation import (
    SecurityEventType,
    TimePrecision,
    TimestampTrust,
    SequenceStatus,
    TemporalRelationshipType,
    TimestampProvenance,
    SecurityEvent,
    TimelineBurstSummary,
    TimelineItem,
    IncidentTimelineResponse,
    EntityTimelineResponse,
    TemporalRule,
    TemporalSequenceCandidate,
    SequenceAnalysisResponse,
    CampaignTimelineResponse,
    sanitize_temporal_attributes,
)
from backend.services.log_sanitizer import sanitize_log_text

logger = logging.getLogger("cyberguard.temporal_engine")

ENGINE_VERSION = "1.0.0"
RULE_VERSION = "1.0.0"
DEFAULT_CLOCK_SKEW_TOLERANCE_SECONDS = 10.0


# ============================================================================
# 1. TIMESTAMP NORMALIZER & CLOCK SKEW SERVICE
# ============================================================================

class TimestampNormalizer:
    """
    Standardized timestamp parser and UTC normalizer.
    Preserves original representations, handles missing/adapter timezones,
    detects granularity precision, assigns source trust levels, and applies explicit sensor clock offsets.
    """

    @classmethod
    def normalize_timestamp(
        cls,
        raw_value: Any,
        default_timezone: Optional[Union[str, timezone, int]] = None,
        clock_offset_seconds: float = 0.0,
        trust_hint: Optional[TimestampTrust] = None,
        source_field: str = "telemetry_timestamp",
        notes: Optional[str] = None,
    ) -> Tuple[datetime, Optional[datetime], TimePrecision, TimestampProvenance]:
        """
        Parses raw timestamp into normalized UTC datetime and comprehensive provenance metadata.
        """
        original_str = str(raw_value).strip() if raw_value is not None else ""
        original_tz: Optional[str] = None
        precision = TimePrecision.SECOND
        dt_utc: datetime
        dt_end_utc: Optional[datetime] = None

        if not original_str:
            dt_utc = datetime.now(timezone.utc)
            return (
                dt_utc,
                None,
                TimePrecision.UNKNOWN,
                TimestampProvenance(
                    source_field=source_field,
                    original_value="",
                    original_timezone="UNKNOWN_TIMEZONE",
                    clock_offset_applied_seconds=0.0,
                    trust_level=TimestampTrust.LOW,
                    precision=TimePrecision.UNKNOWN,
                    notes="Missing raw timestamp; defaulted to ingestion clock",
                ),
            )

        # 1. Already a Python datetime object
        if isinstance(raw_value, datetime):
            if raw_value.tzinfo is not None and raw_value.tzinfo.utcoffset(raw_value) is not None:
                original_tz = str(raw_value.tzinfo)
                dt_utc = raw_value.astimezone(timezone.utc)
            else:
                original_tz = cls._resolve_default_timezone_name(default_timezone)
                tz_obj = cls._resolve_timezone_obj(default_timezone)
                if tz_obj:
                    dt_utc = raw_value.replace(tzinfo=tz_obj).astimezone(timezone.utc)
                else:
                    original_tz = "UNKNOWN_TIMEZONE"
                    dt_utc = raw_value.replace(tzinfo=timezone.utc)
                    notes = f"{notes or ''} Naive datetime assumed UTC by adapter policy.".strip()
            precision = cls._detect_precision_from_dt(raw_value)

        # 2. Integer or float timestamp (Epoch seconds or milliseconds)
        elif isinstance(raw_value, (int, float)) or (isinstance(raw_value, str) and re.match(r"^\d+(\.\d+)?$", raw_value)):
            val_f = float(raw_value)
            # If > 1e11, it's milliseconds
            if val_f > 1e11:
                dt_utc = datetime.fromtimestamp(val_f / 1000.0, tz=timezone.utc)
                precision = TimePrecision.MILLISECOND
            else:
                dt_utc = datetime.fromtimestamp(val_f, tz=timezone.utc)
                precision = TimePrecision.MILLISECOND if "." in str(raw_value) else TimePrecision.SECOND
            original_tz = "UTC_EPOCH"

        # 3. Date-only string (e.g. YYYY-MM-DD)
        elif re.match(r"^\d{4}-\d{2}-\d{2}$", original_str):
            parsed = datetime.strptime(original_str, "%Y-%m-%d")
            dt_utc = parsed.replace(tzinfo=timezone.utc)
            precision = TimePrecision.DATE_ONLY
            original_tz = "DATE_ONLY_ASSUMED_UTC"
            notes = f"{notes or ''} Date-only value; normalized to 00:00:00 UTC without false second precision.".strip()

        # 4. Standard ISO-8601 or RFC-2822 email format
        else:
            parsed_dt = None
            # Try email RFC-2822
            try:
                parsed_dt = parsedate_to_datetime(original_str)
            except Exception:
                pass

            # Try fromisoformat
            if parsed_dt is None:
                iso_clean = original_str.replace("Z", "+00:00")
                try:
                    parsed_dt = datetime.fromisoformat(iso_clean)
                except Exception:
                    pass

            # Try common log patterns (e.g. %Y-%m-%d %H:%M:%S, %Y/%m/%d %H:%M:%S)
            if parsed_dt is None:
                for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%d/%b/%Y:%H:%M:%S"):
                    try:
                        parsed_dt = datetime.strptime(original_str, fmt)
                        break
                    except Exception:
                        continue

            if parsed_dt is not None:
                precision = cls._detect_precision_from_str(original_str)
                if parsed_dt.tzinfo is not None and parsed_dt.tzinfo.utcoffset(parsed_dt) is not None:
                    original_tz = str(parsed_dt.tzinfo)
                    dt_utc = parsed_dt.astimezone(timezone.utc)
                else:
                    original_tz = cls._resolve_default_timezone_name(default_timezone)
                    tz_obj = cls._resolve_timezone_obj(default_timezone)
                    if tz_obj:
                        dt_utc = parsed_dt.replace(tzinfo=tz_obj).astimezone(timezone.utc)
                    else:
                        original_tz = "UNKNOWN_TIMEZONE"
                        dt_utc = parsed_dt.replace(tzinfo=timezone.utc)
                        notes = f"{notes or ''} Naive string assumed UTC by adapter policy.".strip()
            else:
                # Fallback to ingestion clock
                dt_utc = datetime.now(timezone.utc)
                precision = TimePrecision.UNKNOWN
                original_tz = "UNPARSEABLE_TIMEZONE"
                notes = f"{notes or ''} Unparseable timestamp '{original_str}'; used ingestion clock fallback.".strip()

        # Apply known clock offset correction if configured
        if clock_offset_seconds != 0.0:
            dt_utc = dt_utc - timedelta(seconds=clock_offset_seconds)
            notes = f"{notes or ''} Applied sensor clock offset correction of {clock_offset_seconds:+.3f}s.".strip()

        # Determine trust level
        trust = trust_hint or cls._infer_default_trust(source_field)

        provenance = TimestampProvenance(
            source_field=source_field,
            original_value=original_str,
            original_timezone=original_tz or "UNKNOWN_TIMEZONE",
            clock_offset_applied_seconds=clock_offset_seconds,
            trust_level=trust,
            precision=precision,
            notes=notes,
        )

        return dt_utc, dt_end_utc, precision, provenance

    @classmethod
    def compare_timestamps(
        cls,
        time_a: datetime,
        time_b: datetime,
        skew_tolerance_seconds: float = DEFAULT_CLOCK_SKEW_TOLERANCE_SECONDS,
        precision_a: TimePrecision = TimePrecision.SECOND,
        precision_b: TimePrecision = TimePrecision.SECOND,
    ) -> TemporalRelationshipType:
        """
        Compares two UTC datetimes with explicit clock-skew tolerance.
        If discrepancy is within tolerance, returns ORDER_UNCERTAIN rather than forcing precedence.
        """
        delta_sec = (time_b - time_a).total_seconds()

        # If either timestamp is DATE_ONLY or UNKNOWN, granularity is coarse
        if precision_a in (TimePrecision.DATE_ONLY, TimePrecision.UNKNOWN) or precision_b in (TimePrecision.DATE_ONLY, TimePrecision.UNKNOWN):
            if abs(delta_sec) < 86400.0:
                return TemporalRelationshipType.ORDER_UNCERTAIN

        if abs(delta_sec) <= skew_tolerance_seconds:
            return TemporalRelationshipType.ORDER_UNCERTAIN
        elif delta_sec > 0:
            return TemporalRelationshipType.BEFORE
        else:
            return TemporalRelationshipType.AFTER

    @classmethod
    def _detect_precision_from_dt(cls, dt: datetime) -> TimePrecision:
        if dt.microsecond > 0:
            return TimePrecision.MILLISECOND
        if dt.second > 0:
            return TimePrecision.SECOND
        if dt.minute > 0 or dt.hour > 0:
            return TimePrecision.MINUTE
        return TimePrecision.SECOND

    @classmethod
    def _detect_precision_from_str(cls, s: str) -> TimePrecision:
        if "." in s and re.search(r"\.\d{1,6}", s):
            return TimePrecision.MILLISECOND
        if re.search(r":\d{2}:\d{2}", s):
            return TimePrecision.SECOND
        if re.search(r":\d{2}", s):
            return TimePrecision.MINUTE
        if re.match(r"^\d{4}-\d{2}-\d{2}$", s):
            return TimePrecision.DATE_ONLY
        return TimePrecision.SECOND

    @classmethod
    def _infer_default_trust(cls, source_field: str) -> TimestampTrust:
        sf_lower = source_field.lower()
        if any(term in sf_lower for term in ("auth", "idp", "audit", "system", "kernel", "gateway", "server")):
            return TimestampTrust.HIGH
        if any(term in sf_lower for term in ("flow", "network", "sensor", "dns", "received[0]")):
            return TimestampTrust.MEDIUM
        if any(term in sf_lower for term in ("date", "mtime", "client", "user", "sender")):
            return TimestampTrust.LOW
        return TimestampTrust.MEDIUM

    @classmethod
    def _resolve_timezone_obj(cls, tz_hint: Optional[Union[str, timezone, int]]) -> Optional[timezone]:
        if isinstance(tz_hint, timezone):
            return tz_hint
        if isinstance(tz_hint, (int, float)):
            return timezone(timedelta(hours=tz_hint))
        if isinstance(tz_hint, str):
            tz_str = tz_hint.strip().upper()
            if tz_str in ("UTC", "Z"):
                return timezone.utc
            match = re.match(r"^([+-])(\d{1,2}):?(\d{2})?$", tz_str)
            if match:
                sign = 1 if match.group(1) == "+" else -1
                hours = int(match.group(2))
                minutes = int(match.group(3) or 0)
                return timezone(sign * timedelta(hours=hours, minutes=minutes))
        return None

    @classmethod
    def _resolve_default_timezone_name(cls, tz_hint: Optional[Union[str, timezone, int]]) -> str:
        if tz_hint is None:
            return "UNKNOWN_TIMEZONE"
        if isinstance(tz_hint, timezone):
            return str(tz_hint)
        return str(tz_hint)


# ============================================================================
# 2. CANONICAL EVENT PROJECTOR
# ============================================================================

class EventProjector:
    """
    Projects normalized security evidence records into canonical SecurityEvent projections.
    Does not duplicate forensic truth stores; references existing authoritative records.
    """

    @classmethod
    def project_auth_event(
        cls,
        event_dict: Dict[str, Any],
        incident_id: Optional[str] = None,
        workspace_id: str = "default",
        artifact_id: Optional[str] = None,
        analysis_run_id: Optional[str] = None,
    ) -> SecurityEvent:
        """Projects NormalizedAuthEvent or auth log dictionary into SecurityEvent."""
        raw_ts = event_dict.get("timestamp") or event_dict.get("event_time")
        event_time, event_end, precision, provenance = TimestampNormalizer.normalize_timestamp(
            raw_value=raw_ts,
            source_field="auth_log.timestamp",
            trust_hint=TimestampTrust.HIGH,
        )

        result_str = str(event_dict.get("result", "UNKNOWN")).upper()
        if "SUCCESS" in result_str:
            ev_type = SecurityEventType.AUTH_SUCCESS
        elif "FAIL" in result_str or "DENIED" in result_str or "LOCKED" in result_str:
            ev_type = SecurityEventType.AUTH_FAILURE
        elif "MFA" in result_str or "CHALLENGE" in result_str:
            ev_type = SecurityEventType.MFA_EVENT
        else:
            ev_type = SecurityEventType.AUTH_ATTEMPT

        account_id = (event_dict.get("account_id") or event_dict.get("username") or "").strip().lower()
        source_ip = (event_dict.get("source_ip") or "").strip()
        device_id = (event_dict.get("device_id") or event_dict.get("device_name") or "").strip()
        session_id = (event_dict.get("session_id") or "").strip()

        entity_ids: List[str] = []
        if account_id:
            entity_ids.append(f"account:{account_id}")
        if source_ip:
            entity_ids.append(f"ip:{source_ip}")
        if device_id:
            entity_ids.append(f"device:{device_id}")
        if session_id:
            entity_ids.append(f"session:{session_id}")

        attrs = {
            "account_id": account_id,
            "source_ip": source_ip,
            "device_id": device_id,
            "session_id": session_id,
            "destination_service": event_dict.get("destination_service"),
            "auth_method": str(event_dict.get("authentication_method", "UNKNOWN")),
            "result": result_str,
            "failure_reason": event_dict.get("failure_reason"),
        }

        return SecurityEvent(
            id=str(event_dict.get("id") or generate_uuid()),
            event_type=ev_type,
            event_time=event_time,
            event_time_end=event_end,
            event_time_precision=precision,
            event_time_confidence=1.0,
            ingested_at=get_utc_now(),
            analyzed_at=get_utc_now(),
            source_type="AUTH_LOG",
            source_artifact_id=artifact_id,
            analysis_run_id=analysis_run_id,
            incident_id=incident_id,
            workspace_id=workspace_id,
            entity_ids=entity_ids,
            provider=str(event_dict.get("provider", "auth_service")),
            adapter="auth_log_adapter",
            adapter_version=ENGINE_VERSION,
            attributes=sanitize_temporal_attributes(attrs),
            timestamp_provenance=provenance,
            summary=f"Authentication {ev_type.value} for {account_id or 'unknown'} from {source_ip or 'unknown'}",
        )

    @classmethod
    def project_network_event(
        cls,
        event_dict: Dict[str, Any],
        incident_id: Optional[str] = None,
        workspace_id: str = "default",
        artifact_id: Optional[str] = None,
        analysis_run_id: Optional[str] = None,
    ) -> SecurityEvent:
        """Projects NormalizedNetworkEvent into SecurityEvent."""
        raw_ts = event_dict.get("timestamp") or event_dict.get("event_time")
        duration_s = event_dict.get("duration_seconds")
        event_time, _, precision, provenance = TimestampNormalizer.normalize_timestamp(
            raw_value=raw_ts,
            source_field="network.flow_time",
            trust_hint=TimestampTrust.MEDIUM,
        )
        event_end = event_time + timedelta(seconds=float(duration_s)) if duration_s else None

        raw_type = str(event_dict.get("event_type", "CONNECTION")).upper()
        if "DNS_QUERY" in raw_type or event_dict.get("dns_query"):
            ev_type = SecurityEventType.DNS_QUERY
        elif "DNS_RESPONSE" in raw_type or event_dict.get("dns_answers"):
            ev_type = SecurityEventType.DNS_RESPONSE
        else:
            bytes_sent = event_dict.get("bytes_sent") or 0
            if bytes_sent > 10_000_000:
                ev_type = SecurityEventType.HIGH_OUTBOUND_DATA_VOLUME
            else:
                ev_type = SecurityEventType.NETWORK_CONNECTION

        src_ip = (event_dict.get("source_ip") or "").strip()
        dst_ip = (event_dict.get("destination_ip") or "").strip()
        domain = (event_dict.get("domain") or event_dict.get("dns_query") or "").strip().lower()
        device_id = (event_dict.get("device_id") or "").strip()

        entity_ids: List[str] = []
        if device_id:
            entity_ids.append(f"device:{device_id}")
        if src_ip:
            entity_ids.append(f"ip:{src_ip}")
        if dst_ip:
            entity_ids.append(f"ip:{dst_ip}")
        if domain:
            entity_ids.append(f"domain:{domain}")

        attrs = {
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "destination_port": event_dict.get("destination_port"),
            "domain": domain,
            "protocol": str(event_dict.get("protocol", "TCP")),
            "bytes_sent": event_dict.get("bytes_sent"),
            "bytes_received": event_dict.get("bytes_received"),
            "duration_seconds": duration_s,
        }

        return SecurityEvent(
            id=str(event_dict.get("id") or generate_uuid()),
            event_type=ev_type,
            event_time=event_time,
            event_time_end=event_end,
            event_time_precision=precision,
            event_time_confidence=1.0,
            ingested_at=get_utc_now(),
            analyzed_at=get_utc_now(),
            source_type="NETWORK_LOG",
            source_artifact_id=artifact_id,
            analysis_run_id=analysis_run_id,
            incident_id=incident_id,
            workspace_id=workspace_id,
            entity_ids=entity_ids,
            provider=str(event_dict.get("provider", "network_sensor")),
            adapter="network_telemetry_adapter",
            adapter_version=ENGINE_VERSION,
            attributes=sanitize_temporal_attributes(attrs),
            timestamp_provenance=provenance,
            summary=f"Network {ev_type.value}: {src_ip} -> {dst_ip or domain}",
        )

    @classmethod
    def project_api_event(
        cls,
        event_dict: Dict[str, Any],
        incident_id: Optional[str] = None,
        workspace_id: str = "default",
        artifact_id: Optional[str] = None,
        analysis_run_id: Optional[str] = None,
    ) -> SecurityEvent:
        """Projects NormalizedAPIEvent into SecurityEvent."""
        raw_ts = event_dict.get("timestamp") or event_dict.get("event_time")
        event_time, event_end, precision, provenance = TimestampNormalizer.normalize_timestamp(
            raw_value=raw_ts,
            source_field="api_gateway.timestamp",
            trust_hint=TimestampTrust.HIGH,
        )

        endpoint = str(event_dict.get("endpoint") or "").lower()
        method = str(event_dict.get("method") or "GET").upper()
        bytes_out = event_dict.get("response_bytes") or event_dict.get("bytes_sent") or 0

        if "export" in endpoint or "bulk" in endpoint or "download" in endpoint:
            ev_type = SecurityEventType.BULK_RESOURCE_ACCESS
        elif any(enum_pat in endpoint for enum_pat in ("users", "keys", "roles", "internal", "config")) and method == "GET":
            ev_type = SecurityEventType.API_ENUMERATION
        else:
            ev_type = SecurityEventType.API_REQUEST

        account_id = (event_dict.get("account_id") or "").strip().lower()
        session_id = (event_dict.get("session_id") or "").strip()
        device_id = (event_dict.get("device_id") or "").strip()
        src_ip = (event_dict.get("source_ip") or "").strip()

        entity_ids: List[str] = []
        if account_id:
            entity_ids.append(f"account:{account_id}")
        if session_id:
            entity_ids.append(f"session:{session_id}")
        if device_id:
            entity_ids.append(f"device:{device_id}")
        if src_ip:
            entity_ids.append(f"ip:{src_ip}")
        if endpoint:
            entity_ids.append(f"api_resource:{endpoint}")

        attrs = {
            "account_id": account_id,
            "session_id": session_id,
            "device_id": device_id,
            "source_ip": src_ip,
            "method": method,
            "endpoint": endpoint,
            "status_code": event_dict.get("status_code", 200),
            "response_bytes": bytes_out,
        }

        return SecurityEvent(
            id=str(event_dict.get("id") or generate_uuid()),
            event_type=ev_type,
            event_time=event_time,
            event_time_end=event_end,
            event_time_precision=precision,
            event_time_confidence=1.0,
            ingested_at=get_utc_now(),
            analyzed_at=get_utc_now(),
            source_type="API_LOG",
            source_artifact_id=artifact_id,
            analysis_run_id=analysis_run_id,
            incident_id=incident_id,
            workspace_id=workspace_id,
            entity_ids=entity_ids,
            provider=str(event_dict.get("provider", "api_gateway")),
            adapter="api_gateway_adapter",
            adapter_version=ENGINE_VERSION,
            attributes=sanitize_temporal_attributes(attrs),
            timestamp_provenance=provenance,
            summary=f"API {ev_type.value}: {method} {endpoint} by {session_id or account_id}",
        )

    @classmethod
    def project_email_received(
        cls,
        email_data: Dict[str, Any],
        incident_id: Optional[str] = None,
        workspace_id: str = "default",
        artifact_id: Optional[str] = None,
    ) -> SecurityEvent:
        """Projects email delivery event, prioritizing top Received header over sender Date."""
        received_ts = email_data.get("received_timestamp") or email_data.get("received_date")
        date_header_ts = email_data.get("date_header") or email_data.get("date")

        # Top received header is local MTA timestamp (trust MEDIUM), Date is sender-controlled (trust LOW)
        if received_ts:
            event_time, _, precision, provenance = TimestampNormalizer.normalize_timestamp(
                raw_value=received_ts,
                source_field="Received[0]",
                trust_hint=TimestampTrust.MEDIUM,
            )
        else:
            event_time, _, precision, provenance = TimestampNormalizer.normalize_timestamp(
                raw_value=date_header_ts,
                source_field="Date",
                trust_hint=TimestampTrust.LOW,
                notes="Used sender-controlled Date header; no Received header available.",
            )

        # Check for timestamp discrepancy between Received and Date headers
        inconsistency = None
        if received_ts and date_header_ts:
            date_dt, _, _, _ = TimestampNormalizer.normalize_timestamp(date_header_ts, source_field="Date")
            delta_sec = (date_dt - event_time).total_seconds()
            if delta_sec > 60.0:  # Sender claims sent in future relative to MTA receipt
                inconsistency = {
                    "type": "TIMESTAMP_INCONSISTENCY",
                    "description": f"Email Received header ({event_time.isoformat()}) precedes sender Date header ({date_dt.isoformat()}) by {delta_sec:.1f}s",
                    "delta_seconds": delta_sec,
                }

        target_acc = (email_data.get("recipient") or email_data.get("to") or "").strip().lower()
        sender_acc = (email_data.get("sender") or email_data.get("from") or "").strip().lower()
        sender_dom = sender_acc.split("@")[-1] if "@" in sender_acc else ""

        entity_ids: List[str] = []
        if target_acc:
            entity_ids.append(f"account:{target_acc}")
        if sender_dom:
            entity_ids.append(f"domain:{sender_dom}")

        attrs = {
            "recipient": target_acc,
            "sender": sender_acc,
            "subject": email_data.get("subject", ""),
            "sender_date_header": str(date_header_ts) if date_header_ts else None,
            "received_header": str(received_ts) if received_ts else None,
        }
        if inconsistency:
            attrs["timestamp_inconsistency"] = inconsistency

        return SecurityEvent(
            id=str(email_data.get("id") or generate_uuid()),
            event_type=SecurityEventType.EMAIL_RECEIVED,
            event_time=event_time,
            event_time_precision=precision,
            event_time_confidence=0.85 if inconsistency is None else 0.50,
            ingested_at=get_utc_now(),
            analyzed_at=get_utc_now(),
            source_type="EMAIL",
            source_artifact_id=artifact_id,
            incident_id=incident_id,
            workspace_id=workspace_id,
            entity_ids=entity_ids,
            provider="email_gateway",
            adapter="rfc822_parser",
            adapter_version=ENGINE_VERSION,
            attributes=sanitize_temporal_attributes(attrs),
            timestamp_provenance=provenance,
            summary=f"Email received for {target_acc} from {sender_acc}",
        )


# ============================================================================
# 3. TEMPORAL RULE REGISTRY
# ============================================================================

class TemporalRuleRegistry:
    """
    Standardized repository of versioned declarative temporal correlation rules.
    """

    @classmethod
    def get_default_rules(cls) -> List[TemporalRule]:
        return [
            TemporalRule(
                rule_id="RULE_AUTH_BURST_TO_SUCCESS",
                version="1.0.0",
                name="Authentication Failures Preceding Success",
                description="Repeated failed authentications followed rapidly by a successful login on the same account.",
                source_event_types=[SecurityEventType.AUTH_FAILURE],
                target_event_types=[SecurityEventType.AUTH_SUCCESS],
                min_delay_seconds=0.0,
                max_delay_seconds=1800.0,  # 30 minutes
                required_shared_entities=["account"],
                optional_shared_entities=["ip", "device"],
                resulting_status=SequenceStatus.POSSIBLE_SECURITY_SEQUENCE,
                base_confidence=0.85,
            ),
            TemporalRule(
                rule_id="RULE_AUTH_SUCCESS_TO_SESSION",
                version="1.0.0",
                name="Session Creation Following Authentication",
                description="Legitimate or compromised session establishment immediately following successful credentials verification.",
                source_event_types=[SecurityEventType.AUTH_SUCCESS],
                target_event_types=[SecurityEventType.SESSION_CREATED],
                min_delay_seconds=0.0,
                max_delay_seconds=300.0,  # 5 minutes
                required_shared_entities=["account"],
                optional_shared_entities=["ip", "session", "device"],
                resulting_status=SequenceStatus.OBSERVED_SEQUENCE,
                base_confidence=0.90,
            ),
            TemporalRule(
                rule_id="RULE_SESSION_TO_API",
                version="1.0.0",
                name="API Activity from New Session",
                description="API queries, enumeration, or access executed under a newly established session context.",
                source_event_types=[SecurityEventType.SESSION_CREATED],
                target_event_types=[SecurityEventType.API_REQUEST, SecurityEventType.API_ENUMERATION, SecurityEventType.BULK_RESOURCE_ACCESS],
                min_delay_seconds=0.0,
                max_delay_seconds=3600.0,  # 60 minutes
                required_shared_entities=["session"],
                optional_shared_entities=["account", "device"],
                resulting_status=SequenceStatus.OBSERVED_SEQUENCE,
                base_confidence=0.80,
            ),
            TemporalRule(
                rule_id="RULE_API_TO_BULK_EXPORT",
                version="1.0.0",
                name="Bulk Resource Access Preceding Data Transfer",
                description="Bulk resource or endpoint probing followed by heavy data egress within the same session or host.",
                source_event_types=[SecurityEventType.API_ENUMERATION, SecurityEventType.BULK_RESOURCE_ACCESS, SecurityEventType.API_REQUEST],
                target_event_types=[SecurityEventType.BULK_RESOURCE_ACCESS, SecurityEventType.HIGH_OUTBOUND_DATA_VOLUME],
                min_delay_seconds=0.0,
                max_delay_seconds=1800.0,  # 30 minutes
                required_shared_entities=["session"],
                optional_shared_entities=["device", "account"],
                resulting_status=SequenceStatus.POSSIBLE_SECURITY_SEQUENCE,
                base_confidence=0.75,
            ),
            TemporalRule(
                rule_id="RULE_DNS_TO_NETWORK_CONNECTION",
                version="1.0.0",
                name="Network Connection Following DNS Resolution",
                description="Direct outbound connection initiated after querying a destination domain.",
                source_event_types=[SecurityEventType.DNS_QUERY, SecurityEventType.DNS_RESPONSE],
                target_event_types=[SecurityEventType.NETWORK_CONNECTION],
                min_delay_seconds=0.0,
                max_delay_seconds=60.0,  # 60 seconds
                required_shared_entities=["device"],
                optional_shared_entities=["domain", "ip"],
                resulting_status=SequenceStatus.OBSERVED_SEQUENCE,
                base_confidence=0.85,
            ),
            TemporalRule(
                rule_id="RULE_EMAIL_TO_URL_ACCESS",
                version="1.0.0",
                name="URL Access Following Phishing Delivery",
                description="Endpoint access to a link originally delivered via email lure. Requires proven access telemetry.",
                source_event_types=[SecurityEventType.EMAIL_RECEIVED],
                target_event_types=[SecurityEventType.URL_ACCESSED],
                min_delay_seconds=0.0,
                max_delay_seconds=86400.0,  # 24 hours
                required_shared_entities=["url"],
                optional_shared_entities=["domain", "account"],
                resulting_status=SequenceStatus.TEMPORALLY_ASSOCIATED,
                base_confidence=0.75,
            ),
            TemporalRule(
                rule_id="RULE_EMAIL_TO_SUSPICIOUS_AUTH",
                version="1.0.0",
                name="Suspicious Authentication Following Targeted Email",
                description="Authentication anomaly targeting the same account that received a high-risk phishing delivery.",
                source_event_types=[SecurityEventType.EMAIL_RECEIVED],
                target_event_types=[SecurityEventType.AUTH_FAILURE, SecurityEventType.AUTH_SUCCESS],
                min_delay_seconds=0.0,
                max_delay_seconds=86400.0,  # 24 hours
                required_shared_entities=["account"],
                resulting_status=SequenceStatus.TEMPORALLY_ASSOCIATED,
                base_confidence=0.60,
            ),
            TemporalRule(
                rule_id="RULE_EMAIL_TO_FILE",
                version="1.0.0",
                name="File Observation Following Attachment Delivery",
                description="Attachment file extraction or local observation following email transport.",
                source_event_types=[SecurityEventType.EMAIL_RECEIVED],
                target_event_types=[SecurityEventType.FILE_EXTRACTED, SecurityEventType.FILE_OBSERVED],
                min_delay_seconds=0.0,
                max_delay_seconds=3600.0,  # 1 hour
                required_shared_entities=["file"],
                optional_shared_entities=["hash"],
                resulting_status=SequenceStatus.OBSERVED_SEQUENCE,
                base_confidence=0.90,
            ),
        ]


# ============================================================================
# 4. SUB-LINEAR CANDIDATE GENERATOR & SEQUENCE EVALUATOR
# ============================================================================

class CandidateGenerator:
    """
    Sub-linear O(K log K) candidate generator and sequence evaluator.
    Avoids O(N^2) all-pairs comparisons by indexing events by shared entity keys
    and using binary search (bisect) across sorted timestamp intervals.
    """

    @classmethod
    def evaluate_sequences(
        cls,
        events: List[SecurityEvent],
        rules: Optional[List[TemporalRule]] = None,
        incident_id: str = "INC-UNKNOWN",
        workspace_id: str = "default",
        clock_skew_tolerance: float = DEFAULT_CLOCK_SKEW_TOLERANCE_SECONDS,
    ) -> List[TemporalSequenceCandidate]:
        """
        Detects, validates, and chains temporal sequence candidates across incident events.
        """
        if not events or len(events) < 2:
            return []

        active_rules = rules or TemporalRuleRegistry.get_default_rules()

        # 1. Sort all events strictly by event_time UTC
        sorted_events = sorted(events, key=lambda e: e.event_time)

        # 2. Build multi-index: by entity_prefix:key and by event_type
        # e.g. entity_index["account:alice@company.com"] = [list of (event_time, event_idx)]
        entity_index: Dict[str, List[Tuple[datetime, int]]] = {}
        type_index: Dict[SecurityEventType, List[int]] = {}

        for idx, ev in enumerate(sorted_events):
            type_index.setdefault(ev.event_type, []).append(idx)
            for ek in ev.entity_ids:
                norm_ek = ek.lower().strip()
                entity_index.setdefault(norm_ek, []).append((ev.event_time, idx))

        candidates: List[TemporalSequenceCandidate] = []
        seen_event_tuples: Set[Tuple[str, ...]] = set()

        # 3. Evaluate each rule efficiently
        for rule in active_rules:
            # Check if any events exist for rule source and target
            source_indices = []
            for st in rule.source_event_types:
                source_indices.extend(type_index.get(st, []))
            if not source_indices:
                continue

            target_types_set = set(rule.target_event_types)

            for s_idx in source_indices:
                src_ev = sorted_events[s_idx]

                # Identify eligible shared entity keys matching rule.required_shared_entities
                candidate_entity_keys = []
                for ek in src_ev.entity_ids:
                    prefix = ek.split(":")[0].lower() if ":" in ek else ek.lower()
                    if not rule.required_shared_entities or prefix in rule.required_shared_entities:
                        candidate_entity_keys.append(ek.lower().strip())

                if rule.required_shared_entities and not candidate_entity_keys:
                    # Lacks required entity type
                    continue

                # Search target events using entity index
                matched_target_indices: Set[int] = set()

                if candidate_entity_keys:
                    for ek in candidate_entity_keys:
                        ent_timeline = entity_index.get(ek, [])
                        if len(ent_timeline) < 2:
                            continue

                        # Binary search for events in [min_time, max_time]
                        min_time = src_ev.event_time + timedelta(seconds=rule.min_delay_seconds)
                        max_time = src_ev.event_time + timedelta(seconds=rule.max_delay_seconds)

                        times = [t[0] for t in ent_timeline]
                        left_pos = bisect.bisect_left(times, min_time)
                        right_pos = bisect.bisect_right(times, max_time)

                        for pos in range(left_pos, right_pos):
                            t_idx = ent_timeline[pos][1]
                            if t_idx != s_idx and sorted_events[t_idx].event_type in target_types_set:
                                matched_target_indices.add(t_idx)
                else:
                    # No required entity filter; search global timeline in window
                    min_time = src_ev.event_time + timedelta(seconds=rule.min_delay_seconds)
                    max_time = src_ev.event_time + timedelta(seconds=rule.max_delay_seconds)
                    times = [e.event_time for e in sorted_events]
                    left_pos = bisect.bisect_left(times, min_time)
                    right_pos = bisect.bisect_right(times, max_time)
                    for t_idx in range(left_pos, right_pos):
                        if t_idx != s_idx and sorted_events[t_idx].event_type in target_types_set:
                            matched_target_indices.add(t_idx)

                # For each matched pair, construct candidate
                for t_idx in sorted(matched_target_indices):
                    tgt_ev = sorted_events[t_idx]
                    seq_key = (src_ev.id, tgt_ev.id)
                    if seq_key in seen_event_tuples:
                        continue
                    seen_event_tuples.add(seq_key)

                    cand = cls._build_sequence_candidate(
                        src_ev=src_ev,
                        tgt_ev=tgt_ev,
                        rule=rule,
                        incident_id=incident_id,
                        workspace_id=workspace_id,
                        clock_skew_tolerance=clock_skew_tolerance,
                    )
                    if cand:
                        candidates.append(cand)

        # 4. Chain compatible 2-step sequences into multi-step sequences
        chained = cls._chain_compatible_sequences(candidates, sorted_events, incident_id, workspace_id)
        return chained

    @classmethod
    def _build_sequence_candidate(
        cls,
        src_ev: SecurityEvent,
        tgt_ev: SecurityEvent,
        rule: TemporalRule,
        incident_id: str,
        workspace_id: str,
        clock_skew_tolerance: float,
    ) -> Optional[TemporalSequenceCandidate]:
        """Constructs an explainable sequence candidate with evidence and non-attribution guarantees."""
        delta_sec = (tgt_ev.event_time - src_ev.event_time).total_seconds()

        # Shared entities
        src_ents = set(e.lower().strip() for e in src_ev.entity_ids)
        tgt_ents = set(e.lower().strip() for e in tgt_ev.entity_ids)
        shared = sorted(list(src_ents.intersection(tgt_ents)))

        # Supporting evidence
        supporting = [
            {
                "type": "CHRONOLOGICAL_ORDER",
                "description": f"{src_ev.event_type.value} occurred at {src_ev.event_time.isoformat()} followed by {tgt_ev.event_type.value} at {tgt_ev.event_time.isoformat()} (delta: {delta_sec:.1f}s)",
                "delta_seconds": delta_sec,
            },
            {
                "type": "RULE_MATCH",
                "rule_id": rule.rule_id,
                "rule_name": rule.name,
                "description": rule.description,
            },
        ]
        if shared:
            supporting.append({
                "type": "SHARED_ENTITIES",
                "entities": shared,
                "description": f"Events share {len(shared)} canonical entity context(s): {', '.join(shared)}",
            })

        # Conflicting / Inconsistency evidence
        conflicting = []
        status = rule.resulting_status

        # Check for timestamp uncertainty / clock skew
        rel = TimestampNormalizer.compare_timestamps(src_ev.event_time, tgt_ev.event_time, skew_tolerance_seconds=clock_skew_tolerance)
        if rel == TemporalRelationshipType.ORDER_UNCERTAIN:
            conflicting.append({
                "type": "AMBIGUOUS_ORDER",
                "description": f"Delta of {abs(delta_sec):.2f}s is within configured clock-skew tolerance ({clock_skew_tolerance:.1f}s). True sequence ordering is uncertain.",
            })

        # Check for timestamp inconsistencies flagged in either event
        for ev in (src_ev, tgt_ev):
            incons = ev.attributes.get("timestamp_inconsistency")
            if incons:
                conflicting.append(incons)
                status = SequenceStatus.CONFLICTING_TIMESTAMPS

        # Non-attribution limitations
        limitations = [
            "Time order is not causation: temporal proximity does not prove that predecessor activity caused successor activity.",
            "CyberGuard reports observed multi-stage correlation strength and does not assert adversary group attribution.",
        ]
        if rule.rule_id == "RULE_EMAIL_TO_SUSPICIOUS_AUTH":
            limitations.append("CyberGuard has no direct telemetry proving the email lure was opened or credentials captured on that specific site.")
        if rule.rule_id == "RULE_API_TO_BULK_EXPORT":
            limitations.append("Bulk access followed by transfer may represent authorized administrative or backup workloads.")

        # Confidence calculation
        conf = rule.base_confidence
        # Weight by timestamp trust
        if src_ev.timestamp_provenance.trust_level == TimestampTrust.LOW or tgt_ev.timestamp_provenance.trust_level == TimestampTrust.LOW:
            conf *= 0.75
        if conflicting:
            conf *= 0.65

        # Check if false positive suppression applies (Scenario B: different accounts)
        if "account" in rule.required_shared_entities:
            shared_accounts = [e for e in shared if e.startswith("account:")]
            if not shared_accounts:
                return None  # Suppressed! Different accounts.

        summary = f"{rule.name}: {src_ev.event_type.value} -> {tgt_ev.event_type.value} across {', '.join(shared) or 'incident context'} ({delta_sec:.1f}s window)"

        return TemporalSequenceCandidate(
            id=f"seq-{generate_uuid()[:12]}",
            incident_id=incident_id,
            workspace_id=workspace_id,
            event_ids=[src_ev.id, tgt_ev.id],
            events=[src_ev, tgt_ev],
            rule_ids=[rule.rule_id],
            start_time=src_ev.event_time,
            end_time=tgt_ev.event_time,
            duration_seconds=delta_sec,
            shared_entities=shared,
            supporting_evidence=supporting,
            conflicting_evidence=conflicting,
            limitations=limitations,
            confidence=round(min(max(conf, 0.1), 0.99), 3),
            status=status,
            summary=summary,
            engine_version=ENGINE_VERSION,
            rule_version=RULE_VERSION,
        )

    @classmethod
    def _chain_compatible_sequences(
        cls,
        pair_candidates: List[TemporalSequenceCandidate],
        sorted_events: List[SecurityEvent],
        incident_id: str,
        workspace_id: str,
    ) -> List[TemporalSequenceCandidate]:
        """
        Chains overlapping 2-step sequences (e.g. A->B and B->C) into unified multi-stage candidates.
        """
        if len(pair_candidates) < 2:
            return pair_candidates

        event_lookup = {e.id: e for e in sorted_events}
        final_sequences: List[TemporalSequenceCandidate] = []
        used_pair_ids: Set[str] = set()

        # Build adjacency graph between pair candidates where cand1.end_event == cand2.start_event
        chains: List[List[TemporalSequenceCandidate]] = []
        for i, c1 in enumerate(pair_candidates):
            extended = False
            for j, c2 in enumerate(pair_candidates):
                if i != j and c1.event_ids[-1] == c2.event_ids[0]:
                    # Compatible link
                    chains.append([c1, c2])
                    used_pair_ids.add(c1.id)
                    used_pair_ids.add(c2.id)
                    extended = True

        for chain in chains:
            ev_ids = []
            rules = []
            supp = []
            conf = []
            lims = set()
            ents = set()
            for seg in chain:
                for eid in seg.event_ids:
                    if eid not in ev_ids:
                        ev_ids.append(eid)
                rules.extend(seg.rule_ids)
                supp.extend(seg.supporting_evidence)
                conf.extend(seg.conflicting_evidence)
                lims.update(seg.limitations)
                ents.update(seg.shared_entities)

            chained_events = [event_lookup[eid] for eid in ev_ids if eid in event_lookup]
            start_t = chained_events[0].event_time
            end_t = chained_events[-1].event_time
            duration = (end_t - start_t).total_seconds()

            summary = f"Multi-Stage Sequence: {' -> '.join(e.event_type.value for e in chained_events)} ({len(chained_events)} events, {duration:.1f}s)"

            final_sequences.append(
                TemporalSequenceCandidate(
                    id=f"seq-{generate_uuid()[:12]}",
                    incident_id=incident_id,
                    workspace_id=workspace_id,
                    event_ids=ev_ids,
                    events=chained_events,
                    rule_ids=list(dict.fromkeys(rules)),
                    start_time=start_t,
                    end_time=end_t,
                    duration_seconds=duration,
                    shared_entities=sorted(list(ents)),
                    supporting_evidence=supp,
                    conflicting_evidence=conf,
                    limitations=list(lims),
                    confidence=round(sum(c.confidence for c in chain) / len(chain), 3),
                    status=SequenceStatus.TEMPORALLY_ASSOCIATED if all(c.status != SequenceStatus.CONFLICTING_TIMESTAMPS for c in chain) else SequenceStatus.CONFLICTING_TIMESTAMPS,
                    summary=summary,
                    engine_version=ENGINE_VERSION,
                    rule_version=RULE_VERSION,
                )
            )

        # Include unchained pairs
        for p in pair_candidates:
            if p.id not in used_pair_ids:
                final_sequences.append(p)

        return final_sequences


# ============================================================================
# 5. TIMELINE COMPRESSOR (BURST SUMMARIZER)
# ============================================================================

class TimelineCompressor:
    """
    Presentation layer burst compressor. Summarizes dense repetitive events
    (e.g., >3 identical auth failures in <300 seconds) into a TimelineBurstSummary.
    """

    @classmethod
    def compress_timeline(
        cls,
        events: List[SecurityEvent],
        burst_threshold: int = 4,
        burst_window_seconds: float = 300.0,
    ) -> List[TimelineItem]:
        """Compresses repetitive consecutive events of identical type into burst summaries."""
        if not events:
            return []

        items: List[TimelineItem] = []
        i = 0
        n = len(events)

        while i < n:
            ev = events[i]
            # Check for a contiguous run of identical event_type
            run = [ev]
            j = i + 1
            while j < n:
                next_ev = events[j]
                if next_ev.event_type == ev.event_type:
                    gap = (next_ev.event_time - run[-1].event_time).total_seconds()
                    if gap <= burst_window_seconds:
                        run.append(next_ev)
                        j += 1
                        continue
                break

            if len(run) >= burst_threshold:
                start_t = run[0].event_time
                end_t = run[-1].event_time
                duration = (end_t - start_t).total_seconds()

                # Find entities common across the burst
                shared_ents = set(run[0].entity_ids)
                for item in run[1:]:
                    shared_ents.intersection_update(item.entity_ids)

                burst = TimelineBurstSummary(
                    event_type=ev.event_type,
                    count=len(run),
                    start_time=start_t,
                    end_time=end_t,
                    duration_seconds=duration,
                    representative_event_ids=[r.id for r in run[:3]],
                    shared_entities=sorted(list(shared_ents)),
                    summary=f"Burst: {len(run)} {ev.event_type.value} events ({duration:.1f}s)",
                )
                items.append(TimelineItem(item_type="BURST", burst=burst))
                i = j
            else:
                items.append(TimelineItem(item_type="EVENT", event=ev))
                i += 1

        return items


# ============================================================================
# 6. HIGH-LEVEL TEMPORAL CORRELATION SERVICE
# ============================================================================

class TemporalCorrelationService:
    """
    Authoritative service orchestrating event ingestion, indexed queries,
    incident/entity/campaign timelines, and sequence candidate discovery.
    """

    @classmethod
    def record_security_event(
        cls,
        db: Session,
        event: SecurityEvent,
    ) -> SecurityEventModel:
        """Persists a canonical SecurityEvent into the database projection index."""
        model = SecurityEventModel(
            id=event.id,
            event_type=event.event_type.value,
            event_time=event.event_time,
            event_time_end=event.event_time_end,
            event_time_precision=event.event_time_precision.value,
            event_time_confidence=event.event_time_confidence,
            ingested_at=event.ingested_at,
            analyzed_at=event.analyzed_at or get_utc_now(),
            source_type=event.source_type,
            source_artifact_id=event.source_artifact_id,
            analysis_run_id=event.analysis_run_id,
            incident_id=event.incident_id,
            workspace_id=event.workspace_id,
            entity_ids_json=json.dumps(event.entity_ids),
            finding_ids_json=json.dumps(event.finding_ids),
            threat_event_ids_json=json.dumps(event.threat_event_ids),
            provider=event.provider,
            adapter=event.adapter,
            adapter_version=event.adapter_version,
            attributes_json=json.dumps(event.attributes),
            timestamp_provenance_json=json.dumps(event.timestamp_provenance.model_dump()),
            summary=event.summary,
        )
        db.add(model)
        db.commit()
        db.refresh(model)
        return model

    @classmethod
    def get_incident_timeline(
        cls,
        db: Session,
        incident_id: str,
        workspace_id: str = "default",
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        event_types: Optional[List[str]] = None,
        entity_ids: Optional[List[str]] = None,
        page: int = 1,
        page_size: int = 50,
        compress_bursts: bool = True,
    ) -> IncidentTimelineResponse:
        """Retrieves chronologically sorted incident timeline with optional burst compression."""
        query = db.query(SecurityEventModel).filter(
            SecurityEventModel.incident_id == incident_id,
            SecurityEventModel.workspace_id == workspace_id,
        )

        if start_time:
            query = query.filter(SecurityEventModel.event_time >= start_time)
        if end_time:
            query = query.filter(SecurityEventModel.event_time <= end_time)
        if event_types:
            query = query.filter(SecurityEventModel.event_type.in_(event_types))

        models = query.order_by(asc(SecurityEventModel.event_time)).all()

        # In-memory entity filtering if requested
        if entity_ids:
            target_ents = set(e.lower().strip() for e in entity_ids)
            models = [
                m for m in models
                if any(e.lower().strip() in target_ents for e in json.loads(m.entity_ids_json or "[]"))
            ]

        total_count = len(models)
        events = [cls._model_to_schema(m) for m in models]

        # Apply burst compression if enabled
        timeline_items = TimelineCompressor.compress_timeline(events) if compress_bursts else [
            TimelineItem(item_type="EVENT", event=e) for e in events
        ]

        # Pagination over presentation items
        offset = max(0, (page - 1) * page_size)
        paginated_items = timeline_items[offset:offset + page_size]
        has_more = (offset + page_size) < len(timeline_items)

        start_dt = events[0].event_time if events else None
        end_dt = events[-1].event_time if events else None

        return IncidentTimelineResponse(
            incident_id=incident_id,
            workspace_id=workspace_id,
            total_events=total_count,
            returned_items=len(paginated_items),
            start_time=start_dt,
            end_time=end_dt,
            items=paginated_items,
            page=page,
            page_size=page_size,
            has_more=has_more,
        )

    @classmethod
    def get_entity_timeline(
        cls,
        db: Session,
        entity_id: str,
        workspace_id: str = "default",
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        event_types: Optional[List[str]] = None,
        page: int = 1,
        page_size: int = 50,
        compress_bursts: bool = False,
    ) -> EntityTimelineResponse:
        """Retrieves chronological timeline of all security events involving a specific entity."""
        query = db.query(SecurityEventModel).filter(
            SecurityEventModel.workspace_id == workspace_id,
        )
        if start_time:
            query = query.filter(SecurityEventModel.event_time >= start_time)
        if end_time:
            query = query.filter(SecurityEventModel.event_time <= end_time)
        if event_types:
            query = query.filter(SecurityEventModel.event_type.in_(event_types))

        target_ent = entity_id.lower().strip()
        query = query.filter(SecurityEventModel.entity_ids_json.contains(target_ent))
        models = query.order_by(asc(SecurityEventModel.event_time)).all()

        # Exact match verification against parsed entity list
        filtered = [
            m for m in models
            if target_ent in [e.lower().strip() for e in json.loads(m.entity_ids_json or "[]")]
        ]

        total_count = len(filtered)
        events = [cls._model_to_schema(m) for m in filtered]

        timeline_items = TimelineCompressor.compress_timeline(events) if compress_bursts else [
            TimelineItem(item_type="EVENT", event=e) for e in events
        ]

        offset = max(0, (page - 1) * page_size)
        paginated_items = timeline_items[offset:offset + page_size]
        has_more = (offset + page_size) < len(timeline_items)

        return EntityTimelineResponse(
            entity_id=entity_id,
            canonical_key=entity_id,
            entity_type=entity_id.split(":")[0].upper() if ":" in entity_id else "UNKNOWN",
            workspace_id=workspace_id,
            total_events=total_count,
            items=paginated_items,
            page=page,
            page_size=page_size,
            has_more=has_more,
        )

    @classmethod
    def get_campaign_timeline(
        cls,
        db: Session,
        campaign_id: str,
        workspace_id: str = "default",
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        page: int = 1,
        page_size: int = 50,
    ) -> CampaignTimelineResponse:
        """Aggregates chronological timeline across all incidents belonging to a campaign candidate."""
        # Find incidents linked to this campaign
        camp_inc_records = db.query(CampaignIncidentModel).filter(
            CampaignIncidentModel.campaign_id == campaign_id
        ).all()
        inc_ids = [r.incident_id for r in camp_inc_records]

        # If none via CampaignIncidentModel, check CampaignModel metadata
        if not inc_ids:
            camp = db.query(CampaignModel).filter(
                CampaignModel.id == campaign_id,
                CampaignModel.workspace_id == workspace_id,
            ).first()
            if camp:
                try:
                    inc_ids = json.loads(camp.supporting_evidence_json or "[]")
                except Exception:
                    pass

        if not inc_ids:
            return CampaignTimelineResponse(
                campaign_id=campaign_id,
                workspace_id=workspace_id,
                incidents=[],
                total_events=0,
                items=[],
            )

        query = db.query(SecurityEventModel).filter(
            SecurityEventModel.incident_id.in_(inc_ids),
            SecurityEventModel.workspace_id == workspace_id,
        )
        if start_time:
            query = query.filter(SecurityEventModel.event_time >= start_time)
        if end_time:
            query = query.filter(SecurityEventModel.event_time <= end_time)

        models = query.order_by(asc(SecurityEventModel.event_time)).all()
        events = [cls._model_to_schema(m) for m in models]
        timeline_items = TimelineCompressor.compress_timeline(events)

        offset = max(0, (page - 1) * page_size)
        paginated_items = timeline_items[offset:offset + page_size]

        first_t = events[0].event_time if events else None
        last_t = events[-1].event_time if events else None

        return CampaignTimelineResponse(
            campaign_id=campaign_id,
            workspace_id=workspace_id,
            incidents=inc_ids,
            total_events=len(events),
            first_observed_time=first_t,
            last_observed_time=last_t,
            items=paginated_items,
        )

    @classmethod
    def analyze_incident_sequences(
        cls,
        db: Session,
        incident_id: str,
        workspace_id: str = "default",
        persist: bool = True,
    ) -> SequenceAnalysisResponse:
        """
        Executes on-demand temporal sequence detection across an incident's security events.
        Idempotent: removes prior unreviewed sequence candidates for this incident.
        """
        import time
        start_mono = time.monotonic()

        models = db.query(SecurityEventModel).filter(
            SecurityEventModel.incident_id == incident_id,
            SecurityEventModel.workspace_id == workspace_id,
        ).order_by(asc(SecurityEventModel.event_time)).all()

        events = [cls._model_to_schema(m) for m in models]
        rules = TemporalRuleRegistry.get_default_rules()

        candidates = CandidateGenerator.evaluate_sequences(
            events=events,
            rules=rules,
            incident_id=incident_id,
            workspace_id=workspace_id,
        )

        if persist:
            # Idempotent cleanup of existing non-reviewed candidates for this incident
            db.query(TemporalSequenceCandidateModel).filter(
                TemporalSequenceCandidateModel.incident_id == incident_id,
                TemporalSequenceCandidateModel.workspace_id == workspace_id,
            ).delete()

            for cand in candidates:
                cand_model = TemporalSequenceCandidateModel(
                    id=cand.id,
                    incident_id=incident_id,
                    workspace_id=workspace_id,
                    event_ids_json=json.dumps(cand.event_ids),
                    rule_ids_json=json.dumps(cand.rule_ids),
                    start_time=cand.start_time,
                    end_time=cand.end_time,
                    duration_seconds=cand.duration_seconds,
                    shared_entities_json=json.dumps(cand.shared_entities),
                    supporting_evidence_json=json.dumps(cand.supporting_evidence),
                    conflicting_evidence_json=json.dumps(cand.conflicting_evidence),
                    limitations_json=json.dumps(cand.limitations),
                    confidence=cand.confidence,
                    status=cand.status.value,
                    summary=cand.summary,
                    engine_version=ENGINE_VERSION,
                    rule_version=RULE_VERSION,
                    metadata_json=json.dumps({"persisted_at": get_utc_now().isoformat()}),
                )
                db.add(cand_model)
            db.commit()

        duration_ms = (time.monotonic() - start_mono) * 1000.0

        return SequenceAnalysisResponse(
            incident_id=incident_id,
            workspace_id=workspace_id,
            candidates=candidates,
            total_candidates=len(candidates),
            events_analyzed=len(events),
            rules_evaluated=len(rules),
            analysis_duration_ms=round(duration_ms, 2),
        )

    @classmethod
    def get_sequence_by_id(
        cls,
        db: Session,
        sequence_id: str,
        workspace_id: str = "default",
    ) -> Optional[TemporalSequenceCandidate]:
        """Loads a persisted sequence candidate and hydrates its constituent events."""
        m = db.query(TemporalSequenceCandidateModel).filter(
            TemporalSequenceCandidateModel.id == sequence_id,
            TemporalSequenceCandidateModel.workspace_id == workspace_id,
        ).first()
        if not m:
            return None

        event_ids = json.loads(m.event_ids_json or "[]")
        event_models = db.query(SecurityEventModel).filter(
            SecurityEventModel.id.in_(event_ids)
        ).order_by(asc(SecurityEventModel.event_time)).all()
        events = [cls._model_to_schema(em) for em in event_models]

        return TemporalSequenceCandidate(
            id=m.id,
            incident_id=m.incident_id,
            workspace_id=m.workspace_id,
            event_ids=event_ids,
            events=events,
            rule_ids=json.loads(m.rule_ids_json or "[]"),
            start_time=m.start_time,
            end_time=m.end_time,
            duration_seconds=m.duration_seconds,
            shared_entities=json.loads(m.shared_entities_json or "[]"),
            supporting_evidence=json.loads(m.supporting_evidence_json or "[]"),
            conflicting_evidence=json.loads(m.conflicting_evidence_json or "[]"),
            limitations=json.loads(m.limitations_json or "[]"),
            confidence=m.confidence,
            status=SequenceStatus(m.status),
            summary=m.summary,
            engine_version=m.engine_version,
            rule_version=m.rule_version,
        )

    @classmethod
    def _model_to_schema(cls, model: SecurityEventModel) -> SecurityEvent:
        """Converts an ORM SecurityEventModel row into a validated SecurityEvent Pydantic model."""
        prov_dict = json.loads(model.timestamp_provenance_json or "{}")
        prov = TimestampProvenance(
            source_field=prov_dict.get("source_field", "unknown"),
            original_value=prov_dict.get("original_value", ""),
            original_timezone=prov_dict.get("original_timezone"),
            clock_offset_applied_seconds=float(prov_dict.get("clock_offset_applied_seconds", 0.0)),
            trust_level=TimestampTrust(prov_dict.get("trust_level", "MEDIUM")),
            precision=TimePrecision(prov_dict.get("precision", "SECOND")),
            notes=prov_dict.get("notes"),
        )

        return SecurityEvent(
            id=model.id,
            event_type=SecurityEventType(model.event_type),
            event_time=model.event_time.replace(tzinfo=timezone.utc) if model.event_time.tzinfo is None else model.event_time,
            event_time_end=model.event_time_end.replace(tzinfo=timezone.utc) if model.event_time_end and model.event_time_end.tzinfo is None else model.event_time_end,
            event_time_precision=TimePrecision(model.event_time_precision),
            event_time_confidence=model.event_time_confidence,
            ingested_at=model.ingested_at.replace(tzinfo=timezone.utc) if model.ingested_at.tzinfo is None else model.ingested_at,
            analyzed_at=model.analyzed_at.replace(tzinfo=timezone.utc) if model.analyzed_at and model.analyzed_at.tzinfo is None else model.analyzed_at,
            source_type=model.source_type,
            source_artifact_id=model.source_artifact_id,
            analysis_run_id=model.analysis_run_id,
            incident_id=model.incident_id,
            workspace_id=model.workspace_id,
            entity_ids=json.loads(model.entity_ids_json or "[]"),
            finding_ids=json.loads(model.finding_ids_json or "[]"),
            threat_event_ids=json.loads(model.threat_event_ids_json or "[]"),
            provider=model.provider,
            adapter=model.adapter,
            adapter_version=model.adapter_version,
            attributes=json.loads(model.attributes_json or "{}"),
            timestamp_provenance=prov,
            summary=model.summary,
        )
