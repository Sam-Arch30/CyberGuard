"""
Behavioral Feature Extractor (Section 21).

Extracts normalized, privacy-sanitized feature values from SecurityEventModel,
NormalizedAuthEvent, NormalizedNetworkEvent, and NormalizedAPIEvent.
Strictly prohibits credential, token, and raw secret retention.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import re
from typing import Any, Dict, List, Optional, Tuple, Union
from pydantic import BaseModel

from backend.schemas.behavioral_baseline import (
    BaselineEntityType,
    BaselineMetricType,
    EntityProfileCategory,
    validate_feature_privacy,
)
from backend.services.log_sanitizer import sanitize_log_text


class ExtractedFeatureObservation(BaseModel):
    """Normalized observation extracted from a single event for baseline tracking."""
    entity_type: BaselineEntityType
    entity_id: str
    entity_category: EntityProfileCategory
    metric_type: BaselineMetricType
    numeric_value: Optional[float] = None
    categorical_value: Optional[str] = None
    event_time: datetime
    event_id: str
    context: Dict[str, Any] = {}


class BehavioralFeatureExtractor:
    """
    Extracts time-aware, privacy-guaranteed statistical features across entity types.
    """

    SERVICE_ACCOUNT_PATTERNS = [
        re.compile(r"^svc[-_]", re.IGNORECASE),
        re.compile(r"^service[-_]", re.IGNORECASE),
        re.compile(r"[-_]service$", re.IGNORECASE),
        re.compile(r"^sa[-_]", re.IGNORECASE),
        re.compile(r"bot$", re.IGNORECASE),
        re.compile(r"^daemon", re.IGNORECASE),
        re.compile(r"^batch[-_]", re.IGNORECASE),
        re.compile(r"^cron[-_]", re.IGNORECASE),
        re.compile(r"@serviceaccount\.com$", re.IGNORECASE),
        re.compile(r"@gserviceaccount\.com$", re.IGNORECASE),
    ]

    ADMIN_PATTERNS = [
        re.compile(r"^admin[-_]?", re.IGNORECASE),
        re.compile(r"^root$", re.IGNORECASE),
        re.compile(r"[-_]admin$", re.IGNORECASE),
        re.compile(r"^secops[-_]?", re.IGNORECASE),
    ]

    @classmethod
    def infer_entity_category(cls, entity_id: str, is_service_account_hint: bool = False) -> EntityProfileCategory:
        """Determines whether an entity is a human user, service account, or administrator."""
        if is_service_account_hint:
            return EntityProfileCategory.SERVICE_ACCOUNT

        norm_id = (entity_id or "").strip().lower()
        for p in cls.SERVICE_ACCOUNT_PATTERNS:
            if p.search(norm_id):
                return EntityProfileCategory.SERVICE_ACCOUNT

        for p in cls.ADMIN_PATTERNS:
            if p.search(norm_id):
                return EntityProfileCategory.ADMINISTRATOR

        return EntityProfileCategory.HUMAN_USER

    @classmethod
    def extract_from_auth_event(cls, event: Any) -> List[ExtractedFeatureObservation]:
        """
        Extracts observations from NormalizedAuthEvent or dict.
        Guarantees that raw passwords, tokens, and MFA codes are NEVER extracted.
        """
        obs: List[ExtractedFeatureObservation] = []

        account_id = getattr(event, "account_id", None) or (event.get("account_id") if isinstance(event, dict) else None)
        if not account_id:
            return obs

        account_id = str(account_id).strip().lower()
        category = cls.infer_entity_category(account_id)

        ts = getattr(event, "timestamp", None) or (event.get("timestamp") if isinstance(event, dict) else None)
        if isinstance(ts, str):
            try:
                ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except Exception:
                ts = datetime.now(timezone.utc)
        elif not isinstance(ts, datetime):
            ts = datetime.now(timezone.utc)

        event_id = getattr(event, "id", None) or (event.get("id", "auth-ev") if isinstance(event, dict) else "auth-ev")
        is_mal = getattr(event, "is_malicious", False) or (event.get("is_malicious", False) if isinstance(event, dict) else False)
        quar = getattr(event, "quarantined", False) or (event.get("quarantined", False) if isinstance(event, dict) else False)
        th_lvl = getattr(event, "threat_level", None) or (event.get("threat_level") if isinstance(event, dict) else None)
        obs_ctx = {
            "is_malicious": bool(is_mal),
            "quarantined": bool(quar),
            "threat_level": th_lvl,
        }

        # 1. LOGIN_HOUR (0.0 - 23.0)
        hour_val = float(ts.hour + ts.minute / 60.0)
        obs.append(ExtractedFeatureObservation(
            entity_type=BaselineEntityType.ACCOUNT,
            entity_id=account_id,
            entity_category=category,
            metric_type=BaselineMetricType.LOGIN_HOUR,
            numeric_value=hour_val,
            categorical_value=str(ts.hour),
            event_time=ts,
            event_id=event_id,
            context=obs_ctx,
        ))

        # 2. LOGIN_DAY_PATTERN (0=Monday, 6=Sunday)
        obs.append(ExtractedFeatureObservation(
            entity_type=BaselineEntityType.ACCOUNT,
            entity_id=account_id,
            entity_category=category,
            metric_type=BaselineMetricType.LOGIN_DAY_PATTERN,
            numeric_value=float(ts.weekday()),
            categorical_value=str(ts.weekday()),
            event_time=ts,
            event_id=event_id,
            context=obs_ctx,
        ))

        # 3. LOGIN_SOURCE_IP
        source_ip = getattr(event, "source_ip", None) or (event.get("source_ip") if isinstance(event, dict) else None)
        if source_ip:
            clean_ip = str(source_ip).strip()
            validate_feature_privacy("source_ip", clean_ip)
            obs.append(ExtractedFeatureObservation(
                entity_type=BaselineEntityType.ACCOUNT,
                entity_id=account_id,
                entity_category=category,
                metric_type=BaselineMetricType.LOGIN_SOURCE_IP,
                categorical_value=clean_ip,
                event_time=ts,
                event_id=event_id,
                context=obs_ctx,
            ))

        # 4. LOGIN_DEVICE
        device_id = getattr(event, "device_id", None) or (event.get("device_id") if isinstance(event, dict) else None)
        client_platform = getattr(event, "client_platform", None) or (event.get("client_platform") if isinstance(event, dict) else None)
        client_browser = getattr(event, "client_browser", None) or (event.get("client_browser") if isinstance(event, dict) else None)
        device_val = device_id or f"{client_platform or 'Unknown'}/{client_browser or 'Unknown'}"
        if device_val and device_val != "Unknown/Unknown":
            validate_feature_privacy("device", device_val)
            obs.append(ExtractedFeatureObservation(
                entity_type=BaselineEntityType.ACCOUNT,
                entity_id=account_id,
                entity_category=category,
                metric_type=BaselineMetricType.LOGIN_DEVICE,
                categorical_value=sanitize_log_text(str(device_val)),
                event_time=ts,
                event_id=event_id,
                context=obs_ctx,
            ))

        # 5. LOGIN_LOCATION
        country = getattr(event, "location_country", None) or (event.get("location_country") if isinstance(event, dict) else None)
        if country:
            obs.append(ExtractedFeatureObservation(
                entity_type=BaselineEntityType.ACCOUNT,
                entity_id=account_id,
                entity_category=category,
                metric_type=BaselineMetricType.LOGIN_LOCATION,
                categorical_value=str(country).strip(),
                event_time=ts,
                event_id=event_id,
                context=obs_ctx,
            ))

        # 6. AUTH_METHOD
        auth_method = getattr(event, "authentication_method", None) or (event.get("authentication_method") if isinstance(event, dict) else None)
        if auth_method:
            method_str = getattr(auth_method, "value", str(auth_method))
            validate_feature_privacy("auth_method", method_str)
            obs.append(ExtractedFeatureObservation(
                entity_type=BaselineEntityType.ACCOUNT,
                entity_id=account_id,
                entity_category=category,
                metric_type=BaselineMetricType.AUTH_METHOD,
                categorical_value=method_str,
                event_time=ts,
                event_id=event_id,
                context=obs_ctx,
            ))

        # 7. AUTH_FAILURE_RATE (0.0 for success, 1.0 for failure)
        res = getattr(event, "result", None) or (event.get("result") if isinstance(event, dict) else None)
        res_str = getattr(res, "value", str(res)) if res else "UNKNOWN"
        is_failure = 1.0 if res_str in ("FAILURE", "DENIED", "LOCKED", "MFA_FAILURE") else 0.0
        obs.append(ExtractedFeatureObservation(
            entity_type=BaselineEntityType.ACCOUNT,
            entity_id=account_id,
            entity_category=category,
            metric_type=BaselineMetricType.AUTH_FAILURE_RATE,
            numeric_value=is_failure,
            event_time=ts,
            event_id=event_id,
            context=obs_ctx,
        ))

        return obs

    @classmethod
    def extract_from_network_event(cls, event: Any) -> List[ExtractedFeatureObservation]:
        """Extracts features from NormalizedNetworkEvent or network SecurityEvent."""
        obs: List[ExtractedFeatureObservation] = []

        source_ip = getattr(event, "source_ip", None) or (event.get("source_ip") if isinstance(event, dict) else None)
        if not source_ip:
            return obs

        entity_id = str(source_ip).strip()
        ts = getattr(event, "timestamp", None) or (event.get("timestamp") if isinstance(event, dict) else None)
        if not isinstance(ts, datetime):
            ts = datetime.now(timezone.utc)

        event_id = getattr(event, "id", None) or (event.get("id", "net-ev") if isinstance(event, dict) else "net-ev")

        # 1. NETWORK_DESTINATION_FREQUENCY
        dest_ip = getattr(event, "destination_ip", None) or (event.get("destination_ip") if isinstance(event, dict) else None)
        dest_domain = getattr(event, "domain", None) or (event.get("domain") if isinstance(event, dict) else None)
        dest_target = dest_domain or dest_ip
        if dest_target:
            obs.append(ExtractedFeatureObservation(
                entity_type=BaselineEntityType.NETWORK_ENTITY,
                entity_id=entity_id,
                entity_category=EntityProfileCategory.DEVICE,
                metric_type=BaselineMetricType.NETWORK_DESTINATION_FREQUENCY,
                categorical_value=str(dest_target).strip(),
                event_time=ts,
                event_id=event_id,
            ))

        # 2. NETWORK_PORT_FREQUENCY
        dest_port = getattr(event, "destination_port", None) or (event.get("destination_port") if isinstance(event, dict) else None)
        if dest_port is not None:
            obs.append(ExtractedFeatureObservation(
                entity_type=BaselineEntityType.NETWORK_ENTITY,
                entity_id=entity_id,
                entity_category=EntityProfileCategory.DEVICE,
                metric_type=BaselineMetricType.NETWORK_PORT_FREQUENCY,
                categorical_value=str(dest_port),
                numeric_value=float(dest_port),
                event_time=ts,
                event_id=event_id,
            ))

        # 3. OUTBOUND_BYTES / INBOUND_BYTES
        bytes_sent = getattr(event, "bytes_sent", None) or (event.get("bytes_sent") if isinstance(event, dict) else None)
        if bytes_sent is not None:
            obs.append(ExtractedFeatureObservation(
                entity_type=BaselineEntityType.NETWORK_ENTITY,
                entity_id=entity_id,
                entity_category=EntityProfileCategory.DEVICE,
                metric_type=BaselineMetricType.OUTBOUND_BYTES,
                numeric_value=float(bytes_sent),
                event_time=ts,
                event_id=event_id,
            ))

        dns_query = getattr(event, "dns_query", None) or (event.get("dns_query") if isinstance(event, dict) else None)
        if dns_query:
            obs.append(ExtractedFeatureObservation(
                entity_type=BaselineEntityType.NETWORK_ENTITY,
                entity_id=entity_id,
                entity_category=EntityProfileCategory.DEVICE,
                metric_type=BaselineMetricType.DNS_QUERY_FREQUENCY,
                categorical_value=str(dns_query).strip().lower(),
                event_time=ts,
                event_id=event_id,
            ))

        return obs

    @classmethod
    def extract_from_api_event(cls, event: Any) -> List[ExtractedFeatureObservation]:
        """Extracts features from NormalizedAPIEvent or API SecurityEvent."""
        obs: List[ExtractedFeatureObservation] = []

        account_id = getattr(event, "account_id", None) or (event.get("account_id") if isinstance(event, dict) else None)
        service = getattr(event, "service", None) or (event.get("service", "api_service") if isinstance(event, dict) else "api_service")
        entity_id = (account_id or service).strip().lower()
        entity_type = BaselineEntityType.API_CLIENT if account_id else BaselineEntityType.SERVICE

        is_svc_hint = getattr(event, "is_service_account", False) or (event.get("is_service_account", False) if isinstance(event, dict) else False)
        category = cls.infer_entity_category(entity_id, is_service_account_hint=is_svc_hint)

        ts = getattr(event, "timestamp", None) or (event.get("timestamp") if isinstance(event, dict) else None)
        if not isinstance(ts, datetime):
            ts = datetime.now(timezone.utc)

        event_id = getattr(event, "id", None) or (event.get("id", "api-ev") if isinstance(event, dict) else "api-ev")

        # 1. API_ENDPOINT_FREQUENCY
        route = getattr(event, "route_template", None) or getattr(event, "endpoint", None) or (
            event.get("route_template") or event.get("endpoint") if isinstance(event, dict) else None
        )
        if route:
            validate_feature_privacy("route", route)
            obs.append(ExtractedFeatureObservation(
                entity_type=entity_type,
                entity_id=entity_id,
                entity_category=category,
                metric_type=BaselineMetricType.API_ENDPOINT_FREQUENCY,
                categorical_value=str(route).strip(),
                event_time=ts,
                event_id=event_id,
            ))

        # 2. API_METHOD_FREQUENCY
        method = getattr(event, "method", None) or (event.get("method") if isinstance(event, dict) else None)
        if method:
            method_str = getattr(method, "value", str(method)).upper()
            obs.append(ExtractedFeatureObservation(
                entity_type=entity_type,
                entity_id=entity_id,
                entity_category=category,
                metric_type=BaselineMetricType.API_METHOD_FREQUENCY,
                categorical_value=method_str,
                event_time=ts,
                event_id=event_id,
            ))

        # 3. API_RESPONSE_VOLUME
        res_bytes = getattr(event, "response_bytes", None) or (event.get("response_bytes") if isinstance(event, dict) else None)
        if res_bytes is not None:
            obs.append(ExtractedFeatureObservation(
                entity_type=entity_type,
                entity_id=entity_id,
                entity_category=category,
                metric_type=BaselineMetricType.API_RESPONSE_VOLUME,
                numeric_value=float(res_bytes),
                event_time=ts,
                event_id=event_id,
            ))

        return obs

    @classmethod
    def extract_from_security_event_model(cls, sec_event: Any) -> List[ExtractedFeatureObservation]:
        """Extracts features from canonical SecurityEventModel."""
        attributes = {}
        if hasattr(sec_event, "attributes_json"):
            try:
                attributes = json.loads(sec_event.attributes_json or "{}")
            except Exception:
                attributes = {}

        event_type = getattr(sec_event, "event_type", "")
        ts = getattr(sec_event, "event_time", datetime.now(timezone.utc))
        event_id = getattr(sec_event, "id", "sec-ev")

        is_mal = attributes.get("is_malicious", False) or getattr(sec_event, "is_malicious", False)
        quar = attributes.get("quarantined", False) or getattr(sec_event, "quarantined", False)
        th_lvl = attributes.get("threat_level") or getattr(sec_event, "threat_level", None)

        if "AUTH" in event_type:
            account_id = attributes.get("account_id") or attributes.get("user") or attributes.get("username")
            if account_id:
                auth_dict = {
                    "id": event_id,
                    "timestamp": ts,
                    "account_id": account_id,
                    "source_ip": attributes.get("source_ip") or attributes.get("ip"),
                    "device_id": attributes.get("device_id") or attributes.get("device"),
                    "location_country": attributes.get("country") or attributes.get("location_country"),
                    "authentication_method": attributes.get("auth_method") or attributes.get("authentication_method"),
                    "result": "SUCCESS" if "SUCCESS" in event_type else "FAILURE",
                    "is_malicious": bool(is_mal),
                    "quarantined": bool(quar),
                    "threat_level": th_lvl,
                }
                return cls.extract_from_auth_event(auth_dict)

        elif "NETWORK" in event_type or "DNS" in event_type:
            net_dict = {
                "id": event_id,
                "timestamp": ts,
                "source_ip": attributes.get("source_ip") or attributes.get("client_ip"),
                "destination_ip": attributes.get("destination_ip") or attributes.get("dest_ip"),
                "domain": attributes.get("domain") or attributes.get("query"),
                "destination_port": attributes.get("destination_port") or attributes.get("port"),
                "bytes_sent": attributes.get("bytes_sent") or attributes.get("bytes_out"),
                "dns_query": attributes.get("dns_query") or attributes.get("query"),
            }
            return cls.extract_from_network_event(net_dict)

        elif "API" in event_type:
            api_dict = {
                "id": event_id,
                "timestamp": ts,
                "account_id": attributes.get("account_id") or attributes.get("user_id"),
                "service": attributes.get("service", "api_service"),
                "route_template": attributes.get("route_template") or attributes.get("endpoint"),
                "method": attributes.get("method", "GET"),
                "response_bytes": attributes.get("response_bytes") or attributes.get("bytes"),
                "is_service_account": attributes.get("is_service_account", False),
            }
            return cls.extract_from_api_event(api_dict)

        return []
