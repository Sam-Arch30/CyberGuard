"""
API Abuse Security Analyzers.
Provides secret redaction, token fingerprinting, conservative endpoint normalization,
adapter ingestion, rate & burst detection, endpoint & resource enumeration,
authentication & authorization failure analysis, session & source anomalies,
data volume & scraping detection, and composite API abuse aggregation.
"""
from __future__ import annotations

import csv
import io
import math
import re
import json
import uuid
import hmac
import hashlib
import ipaddress
import urllib.parse
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple, Set
from collections import defaultdict

from backend.schemas.unified import SeverityEnum
from backend.schemas.api_security import (
    HTTPMethodEnum,
    APIEventTypeEnum,
    ClientTypeEnum,
    APICategoryEnum,
    NormalizedAPIEvent,
    AccountAPIBaselineProfile,
    APIFindingItem,
    APIFindingEvidenceItem,
    APIConfigResponse,
)


# ============================================================================
# 1. SECRET REDACTOR & TOKEN FINGERPRINTER
# ============================================================================

class APISecretRedactor:
    """
    Safely redacts passwords, tokens, bearer authorizations, cookies, and API keys
    from API request paths, queries, headers, and auxiliary metadata.
    Never exposes raw secrets in telemetry, database, logs, or findings.
    """
    SECRET_PARAM_PATTERNS = [
        re.compile(r"^pass(word)?$", re.IGNORECASE),
        re.compile(r"^pwd$", re.IGNORECASE),
        re.compile(r"^secret$", re.IGNORECASE),
        re.compile(r"^token$", re.IGNORECASE),
        re.compile(r"^access_token$", re.IGNORECASE),
        re.compile(r"^refresh_token$", re.IGNORECASE),
        re.compile(r"^id_token$", re.IGNORECASE),
        re.compile(r"^bearer$", re.IGNORECASE),
        re.compile(r"^auth(orization)?$", re.IGNORECASE),
        re.compile(r"^api_?key$", re.IGNORECASE),
        re.compile(r"^x_?api_?key$", re.IGNORECASE),
        re.compile(r"^client_?secret$", re.IGNORECASE),
        re.compile(r"^cookie$", re.IGNORECASE),
        re.compile(r"^session_?secret$", re.IGNORECASE),
        re.compile(r"^signature$", re.IGNORECASE),
        re.compile(r"^code$", re.IGNORECASE),
    ]

    SENSITIVE_HEADERS = {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "api-key",
        "x-auth-token",
        "client-secret",
    }

    REPLACEMENT = "[REDACTED_BY_CYBERGUARD]"
    FINGERPRINT_SALT = "cyberguard-api-token-fingerprint-salt-v1"

    @classmethod
    def is_secret_param(cls, param_name: str) -> bool:
        clean = param_name.strip()
        return any(p.search(clean) for p in cls.SECRET_PARAM_PATTERNS)

    @classmethod
    def redact_query_string(cls, query_str: str) -> Tuple[str, Dict[str, Any]]:
        """
        Parses URL query string, redacts secret parameter values,
        and returns (sanitized_query_string, query_metadata_dict).
        """
        if not query_str:
            return "", {}
        try:
            parsed = urllib.parse.parse_qsl(query_str, keep_blank_values=True)
            sanitized_pairs = []
            query_meta: Dict[str, Any] = {}
            for k, v in parsed:
                if cls.is_secret_param(k):
                    sanitized_pairs.append((k, cls.REPLACEMENT))
                    query_meta[k] = cls.REPLACEMENT
                else:
                    sanitized_pairs.append((k, v))
                    query_meta[k] = v
            clean_query = urllib.parse.urlencode(sanitized_pairs)
            return clean_query, query_meta
        except Exception:
            return cls.REPLACEMENT, {"error": "unparseable_query"}

    @classmethod
    def redact_url_path_and_query(cls, raw_uri: str) -> Tuple[str, Dict[str, Any]]:
        """
        Splits path and query, redacting query parameters while preserving the path.
        """
        if not raw_uri:
            return "/", {}
        parts = urllib.parse.urlsplit(raw_uri)
        path = parts.path or "/"
        clean_query, query_meta = cls.redact_query_string(parts.query)
        if clean_query:
            sanitized_uri = f"{path}?{clean_query}"
        else:
            sanitized_uri = path
        return sanitized_uri, query_meta

    @classmethod
    def redact_dict(cls, data: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively redact dictionary keys matching secret patterns."""
        sanitized: Dict[str, Any] = {}
        for k, v in data.items():
            k_str = str(k).lower()
            if cls.is_secret_param(k_str) or k_str in cls.SENSITIVE_HEADERS:
                sanitized[k] = cls.REPLACEMENT
            elif isinstance(v, dict):
                sanitized[k] = cls.redact_dict(v)
            elif isinstance(v, list):
                sanitized[k] = [
                    cls.redact_dict(item) if isinstance(item, dict) else item
                    for item in v
                ]
            else:
                sanitized[k] = v
        return sanitized

    @classmethod
    def fingerprint_token(cls, raw_token: Optional[str]) -> Optional[str]:
        """
        Creates a deterministic HMAC-SHA256 fingerprint for token correlation.
        Never outputs or retains the raw token.
        """
        if not raw_token or not isinstance(raw_token, str):
            return None
        token_str = raw_token.strip()
        if token_str.lower().startswith("bearer "):
            token_str = token_str[7:].strip()
        if not token_str or token_str == cls.REPLACEMENT:
            return None
        h = hmac.new(
            cls.FINGERPRINT_SALT.encode("utf-8"),
            token_str.encode("utf-8"),
            hashlib.sha256
        )
        return f"tkfp_{h.hexdigest()[:32]}"


# ============================================================================
# 2. CONSERVATIVE ENDPOINT NORMALIZER
# ============================================================================

class EndpointNormalizer:
    """
    Normalizes variable URI paths into consistent route templates
    without over-normalizing unrelated functional endpoints.
    Examples:
      /api/v1/users/1001 -> /api/v1/users/{id}
      /api/v1/orders/550e8400-e29b-41d4-a716-446655440000 -> /api/v1/orders/{uuid}
      /api/v1/users/me -> /api/v1/users/me (preserved)
      /api/v1/export -> /api/v1/export (preserved)
    """
    UUID_REGEX = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
    INT_REGEX = re.compile(r"^\d+$")
    HEX_HASH_REGEX = re.compile(r"^[0-9a-fA-F]{16,64}$")
    DATE_REGEX = re.compile(r"^\d{4}-\d{2}-\d{2}$")

    @classmethod
    def normalize_endpoint(cls, raw_uri: str) -> Tuple[str, Optional[str], Optional[str]]:
        """
        Normalizes an API path into:
        (route_template, resource_type, resource_id_hash)
        """
        if not raw_uri:
            return "/", None, None

        # Extract only the path component
        path = urllib.parse.urlsplit(raw_uri).path or "/"
        segments = [s for s in path.split("/") if s]

        if not segments:
            return "/", None, None

        normalized_segments: List[str] = []
        resource_type: Optional[str] = None
        resource_id_raw: Optional[str] = None

        for idx, seg in enumerate(segments):
            if cls.UUID_REGEX.match(seg):
                normalized_segments.append("{uuid}")
                resource_id_raw = seg
                if idx > 0:
                    resource_type = segments[idx - 1]
            elif cls.INT_REGEX.match(seg):
                normalized_segments.append("{id}")
                resource_id_raw = seg
                if idx > 0:
                    resource_type = segments[idx - 1]
            elif cls.HEX_HASH_REGEX.match(seg):
                normalized_segments.append("{hash}")
                resource_id_raw = seg
                if idx > 0:
                    resource_type = segments[idx - 1]
            elif cls.DATE_REGEX.match(seg):
                normalized_segments.append("{date}")
                resource_id_raw = seg
                if idx > 0:
                    resource_type = segments[idx - 1]
            else:
                normalized_segments.append(seg)

        template = "/" + "/".join(normalized_segments)
        id_hash = None
        if resource_id_raw:
            id_hash = hashlib.sha256(resource_id_raw.encode("utf-8")).hexdigest()[:16]

        return template, resource_type, id_hash


# ============================================================================
# 3. HTTP METHOD & CLIENT TYPE NORMALIZERS
# ============================================================================

class MethodNormalizer:
    KNOWN_METHODS = {
        "GET": HTTPMethodEnum.GET,
        "POST": HTTPMethodEnum.POST,
        "PUT": HTTPMethodEnum.PUT,
        "PATCH": HTTPMethodEnum.PATCH,
        "DELETE": HTTPMethodEnum.DELETE,
        "HEAD": HTTPMethodEnum.HEAD,
        "OPTIONS": HTTPMethodEnum.OPTIONS,
        "CONNECT": HTTPMethodEnum.CONNECT,
        "TRACE": HTTPMethodEnum.TRACE,
    }

    @classmethod
    def normalize(cls, method_str: Optional[str]) -> Tuple[HTTPMethodEnum, str]:
        if not method_str:
            return HTTPMethodEnum.GET, "GET"
        raw = str(method_str).strip().upper()
        return cls.KNOWN_METHODS.get(raw, HTTPMethodEnum.OTHER), raw


class ClientClassifier:
    """Classifies client User-Agent into platform/automation categories."""
    BOT_PATTERNS = [re.compile(r"bot|crawler|spider|slurp|yandex", re.IGNORECASE)]
    AUTOMATION_PATTERNS = [
        re.compile(r"curl|postman|python-requests|httpx|go-http-client|axios|node-fetch|wget|aiohttp|apache-httpclient|java", re.IGNORECASE)
    ]
    MOBILE_PATTERNS = [re.compile(r"cfnetwork|android|iphone|ipad|mobile", re.IGNORECASE)]
    BROWSER_PATTERNS = [re.compile(r"mozilla|chrome|safari|firefox|edge|opera", re.IGNORECASE)]

    @classmethod
    def classify(cls, user_agent: Optional[str]) -> ClientTypeEnum:
        if not user_agent:
            return ClientTypeEnum.UNKNOWN
        ua = str(user_agent).strip()
        for p in cls.BOT_PATTERNS:
            if p.search(ua):
                return ClientTypeEnum.BOT
        for p in cls.AUTOMATION_PATTERNS:
            if p.search(ua):
                return ClientTypeEnum.AUTOMATION
        for p in cls.MOBILE_PATTERNS:
            if p.search(ua):
                return ClientTypeEnum.MOBILE
        for p in cls.BROWSER_PATTERNS:
            if p.search(ua):
                return ClientTypeEnum.BROWSER
        return ClientTypeEnum.UNKNOWN


# ============================================================================
# 4. ADAPTER ARCHITECTURE
# ============================================================================

class BaseApiAdapter:
    """Base class for defensive API log adapters."""
    provider_name: str = "generic"
    version: str = "1.0.0"

    def can_handle(self, raw_event: Any) -> bool:
        raise NotImplementedError

    def normalize(self, raw_event: Any) -> NormalizedAPIEvent:
        raise NotImplementedError

    @staticmethod
    def parse_timestamp(ts: Any) -> datetime:
        """Parses various timestamp representations into UTC datetime."""
        if isinstance(ts, datetime):
            if ts.tzinfo is None:
                return ts.replace(tzinfo=timezone.utc)
            return ts.astimezone(timezone.utc)
        if isinstance(ts, (int, float)):
            try:
                # Handle millisecond vs second timestamps
                val = float(ts)
                if val > 1e11:  # milliseconds
                    val = val / 1000.0
                return datetime.fromtimestamp(val, tz=timezone.utc)
            except Exception:
                return datetime.now(timezone.utc)
        if isinstance(ts, str):
            clean = ts.strip()
            # ISO format
            try:
                dt = datetime.fromisoformat(clean.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    return dt.replace(tzinfo=timezone.utc)
                return dt.astimezone(timezone.utc)
            except ValueError:
                pass
            # Common web log format: 02/Oct/2026:12:00:00 +0000
            for fmt in ("%d/%b/%Y:%H:%M:%S %z", "%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S"):
                try:
                    dt = datetime.strptime(clean, fmt)
                    if dt.tzinfo is None:
                        return dt.replace(tzinfo=timezone.utc)
                    return dt.astimezone(timezone.utc)
                except ValueError:
                    continue
        return datetime.now(timezone.utc)


class GenericJsonApiAdapter(BaseApiAdapter):
    """
    Adapters for standard JSON API telemetry events.
    Recognizes common API log fields: method, path/endpoint, status_code, ip, user, bytes.
    """
    provider_name = "generic_json"
    version = "1.0.0"

    def can_handle(self, raw_event: Any) -> bool:
        if not isinstance(raw_event, dict):
            return False
        keys = {k.lower() for k in raw_event.keys()}
        has_endpoint = any(k in keys for k in ("endpoint", "path", "uri", "url", "route"))
        has_method = any(k in keys for k in ("method", "http_method", "verb"))
        has_status = any(k in keys for k in ("status", "status_code", "http_status", "response_code"))
        return (has_endpoint and has_method) or (has_endpoint and has_status)

    def normalize(self, raw_event: Any) -> NormalizedAPIEvent:
        if isinstance(raw_event, str):
            raw_event = json.loads(raw_event)
        d = dict(raw_event)

        event_id = str(d.get("id") or d.get("event_id") or d.get("request_id") or uuid.uuid4())
        raw_ts = d.get("timestamp") or d.get("time") or d.get("@timestamp") or d.get("date")
        ts = self.parse_timestamp(raw_ts)

        raw_method = d.get("method") or d.get("http_method") or d.get("verb") or "GET"
        method_enum, raw_m = MethodNormalizer.normalize(raw_method)

        raw_uri = str(d.get("endpoint") or d.get("path") or d.get("uri") or d.get("url") or "/")
        sanitized_uri, query_meta = APISecretRedactor.redact_url_path_and_query(raw_uri)
        route_template, res_type, res_hash = EndpointNormalizer.normalize_endpoint(sanitized_uri)

        raw_status = d.get("status_code") or d.get("status") or d.get("http_status") or 200
        try:
            status_code = int(raw_status)
        except (ValueError, TypeError):
            status_code = 200

        source_ip = str(d.get("source_ip") or d.get("ip") or d.get("client_ip") or d.get("remote_addr") or "127.0.0.1")
        source_port = d.get("source_port") or d.get("port") or d.get("client_port")
        if source_port:
            try:
                source_port = int(source_port)
            except (ValueError, TypeError):
                source_port = None

        user_id = d.get("user_id") or d.get("user") or d.get("sub")
        account_id = d.get("account_id") or d.get("account") or d.get("username") or user_id
        session_id = d.get("session_id") or d.get("session") or d.get("sid")
        device_id = d.get("device_id") or d.get("device")

        # Token handling: fingerprint, never store raw secret
        raw_token = d.get("token") or d.get("access_token") or d.get("bearer_token") or d.get("auth_token") or d.get("api_key")
        token_fp = APISecretRedactor.fingerprint_token(raw_token)
        api_key_id = d.get("api_key_id") or d.get("key_id")

        is_svc = bool(
            d.get("is_service_account")
            or d.get("is_service")
            or (account_id and ("service" in str(account_id).lower() or "bot" in str(account_id).lower() or "svc_" in str(account_id).lower()))
        )

        req_bytes = d.get("request_bytes") or d.get("bytes_in") or d.get("body_bytes_sent")
        resp_bytes = d.get("response_bytes") or d.get("bytes_out") or d.get("bytes") or d.get("content_length")
        dur_ms = d.get("duration_ms") or d.get("latency_ms") or d.get("duration")

        ua = d.get("user_agent") or d.get("http_user_agent")
        client_type = ClientClassifier.classify(ua)

        # Derive auth/authz status from status code if not provided
        auth_status = d.get("authentication_status")
        authz_status = d.get("authorization_status")
        if status_code == 401:
            auth_status = auth_status or "FAILURE"
        elif status_code == 403:
            authz_status = authz_status or "DENIED"
        elif status_code < 400:
            if not auth_status and (account_id or token_fp or api_key_id):
                auth_status = "SUCCESS"
            if not authz_status and (account_id or token_fp or api_key_id):
                authz_status = "ALLOWED"

        # Sanitize metadata
        meta = APISecretRedactor.redact_dict(d.get("metadata") or {})

        return NormalizedAPIEvent(
            id=event_id,
            timestamp=ts,
            provider=self.provider_name,
            event_type=APIEventTypeEnum.REQUEST,
            service=str(d.get("service") or d.get("app") or "api_service"),
            application=d.get("application") or d.get("client_app"),
            source_ip=source_ip,
            source_port=source_port,
            account_id=str(account_id) if account_id else None,
            user_id=str(user_id) if user_id else None,
            session_id=str(session_id) if session_id else None,
            device_id=str(device_id) if device_id else None,
            token_fingerprint=token_fp,
            api_key_id=str(api_key_id) if api_key_id else None,
            is_service_account=is_svc,
            method=method_enum,
            raw_method=raw_m,
            endpoint=sanitized_uri,
            route_template=route_template,
            query_metadata=query_meta,
            status_code=status_code,
            request_bytes=int(req_bytes) if req_bytes is not None else None,
            response_bytes=int(resp_bytes) if resp_bytes is not None else None,
            duration_ms=float(dur_ms) if dur_ms is not None else None,
            authentication_status=auth_status,
            authorization_status=authz_status,
            resource_type=res_type or d.get("resource_type"),
            resource_id_hash=res_hash,
            user_agent=str(ua) if ua else None,
            client_type=client_type,
            metadata=meta,
        )


class GenericCsvApiAdapter(BaseApiAdapter):
    """
    Adapter for CSV-formatted API telemetry rows.
    """
    provider_name = "generic_csv"
    version = "1.0.0"

    def can_handle(self, raw_event: Any) -> bool:
        if isinstance(raw_event, dict):
            keys = {str(k).lower().strip() for k in raw_event.keys()}
            return any(k in keys for k in ("endpoint", "path", "uri")) and any(k in keys for k in ("method", "verb", "status", "status_code"))
        return False

    def normalize(self, raw_event: Any) -> NormalizedAPIEvent:
        row = {str(k).lower().strip(): v for k, v in raw_event.items()}
        # Delegate to GenericJsonApiAdapter with lowercased keys
        json_adapter = GenericJsonApiAdapter()
        event = json_adapter.normalize(row)
        return event.model_copy(update={"provider": self.provider_name})


class GatewayJsonApiAdapter(BaseApiAdapter):
    """
    Adapter for reverse-proxy / API gateway logs (e.g. Kong, AWS API Gateway, NGINX JSON).
    """
    provider_name = "gateway_json"
    version = "1.0.0"

    def can_handle(self, raw_event: Any) -> bool:
        if not isinstance(raw_event, dict):
            return False
        # Look for nested gateway structures
        keys = set(raw_event.keys())
        return ("request" in keys and "response" in keys) or ("latencies" in keys) or ("upstream_status" in keys)

    def normalize(self, raw_event: Any) -> NormalizedAPIEvent:
        d = dict(raw_event)
        req = d.get("request") or {}
        resp = d.get("response") or {}
        latencies = d.get("latencies") or {}

        event_id = str(d.get("id") or req.get("id") or uuid.uuid4())
        ts = self.parse_timestamp(d.get("started_at") or d.get("timestamp") or req.get("timestamp"))

        raw_method = req.get("method") or d.get("method") or "GET"
        method_enum, raw_m = MethodNormalizer.normalize(raw_method)

        raw_uri = str(req.get("uri") or req.get("url") or d.get("uri") or "/")
        sanitized_uri, query_meta = APISecretRedactor.redact_url_path_and_query(raw_uri)
        route_template, res_type, res_hash = EndpointNormalizer.normalize_endpoint(sanitized_uri)

        status_code = int(resp.get("status") or d.get("status") or 200)
        source_ip = str(d.get("client_ip") or req.get("client_ip") or d.get("source_ip") or "127.0.0.1")

        auth_entity = d.get("authenticated_entity") or {}
        account_id = auth_entity.get("consumer_id") or auth_entity.get("user_id") or d.get("account_id")
        session_id = d.get("session_id")

        headers = req.get("headers") or {}
        raw_token = headers.get("authorization") or headers.get("apikey") or d.get("api_key")
        token_fp = APISecretRedactor.fingerprint_token(raw_token)

        req_bytes = req.get("size")
        resp_bytes = resp.get("size")
        dur_ms = latencies.get("request") or d.get("duration_ms")
        ua = headers.get("user-agent") or d.get("user_agent")

        return NormalizedAPIEvent(
            id=event_id,
            timestamp=ts,
            provider=self.provider_name,
            event_type=APIEventTypeEnum.REQUEST,
            service=str(d.get("service", {}).get("name") if isinstance(d.get("service"), dict) else d.get("service") or "gateway_service"),
            source_ip=source_ip,
            account_id=str(account_id) if account_id else None,
            session_id=str(session_id) if session_id else None,
            token_fingerprint=token_fp,
            method=method_enum,
            raw_method=raw_m,
            endpoint=sanitized_uri,
            route_template=route_template,
            query_metadata=query_meta,
            status_code=status_code,
            request_bytes=int(req_bytes) if req_bytes is not None else None,
            response_bytes=int(resp_bytes) if resp_bytes is not None else None,
            duration_ms=float(dur_ms) if dur_ms is not None else None,
            resource_type=res_type,
            resource_id_hash=res_hash,
            user_agent=str(ua) if ua else None,
            client_type=ClientClassifier.classify(ua),
            metadata=APISecretRedactor.redact_dict(d),
        )


class ApiAdapterRegistry:
    """Registry managing defensive API telemetry adapters."""
    def __init__(self):
        self._adapters: List[BaseApiAdapter] = [
            GenericJsonApiAdapter(),
            GenericCsvApiAdapter(),
            GatewayJsonApiAdapter(),
        ]

    def get_adapter(self, provider_hint: Optional[str], raw_event: Any) -> BaseApiAdapter:
        if provider_hint:
            hint = provider_hint.strip().lower()
            for ad in self._adapters:
                if ad.provider_name == hint:
                    return ad
        for ad in self._adapters:
            if ad.can_handle(raw_event):
                return ad
        return self._adapters[0]  # default fallback


# ============================================================================
# 5. ANALYTICAL DETECTION ENGINES
# ============================================================================

class APIRateBurstEngine:
    """
    Evaluates request velocity and sudden traffic bursts across accounts,
    sessions, token fingerprints, and source IPs.
    """
    @classmethod
    def analyze(
        cls,
        events: List[NormalizedAPIEvent],
        config: APIConfigResponse,
    ) -> List[APIFindingItem]:
        findings: List[APIFindingItem] = []
        if not events:
            return findings

        # Group by actor key: account_id or session_id or token_fingerprint or source_ip
        actor_groups: Dict[str, List[NormalizedAPIEvent]] = defaultdict(list)
        for ev in events:
            key = ev.account_id or ev.session_id or ev.token_fingerprint or ev.source_ip
            actor_groups[key].append(ev)

        for actor_key, group in actor_groups.items():
            if len(group) < 2:
                continue

            # Sort chronologically
            sorted_events = sorted(group, key=lambda e: e.timestamp)
            is_service = any(e.is_service_account for e in sorted_events)
            threshold = config.rate_threshold_service if is_service else config.rate_threshold_human

            # 1. Sliding window rate check
            window_td = timedelta(seconds=config.rate_window_seconds)
            left = 0
            max_in_window = 0
            worst_window_events: List[NormalizedAPIEvent] = []

            for right in range(len(sorted_events)):
                while sorted_events[right].timestamp - sorted_events[left].timestamp > window_td:
                    left += 1
                cnt = right - left + 1
                if cnt > max_in_window:
                    max_in_window = cnt
                    worst_window_events = sorted_events[left:right + 1]

            if max_in_window >= threshold:
                duration_sec = max(
                    1.0,
                    (worst_window_events[-1].timestamp - worst_window_events[0].timestamp).total_seconds()
                )
                rate_per_min = (max_in_window / duration_sec) * 60.0
                endpoint_diversity = len({e.route_template or e.endpoint for e in worst_window_events})

                status_counts = defaultdict(int)
                for e in worst_window_events:
                    status_counts[e.status_code] += 1

                findings.append(APIFindingItem(
                    finding_type="HIGH_API_REQUEST_RATE",
                    title=f"Elevated API Request Rate for {actor_key} ({max_in_window} requests / {duration_sec:.0f}s)",
                    description=(
                        f"Actor '{actor_key}' generated {max_in_window} API requests in {duration_sec:.1f}s "
                        f"({rate_per_min:.1f} req/min), exceeding configured threshold of {threshold} req/min."
                    ),
                    severity=SeverityEnum.MEDIUM,
                    confidence=0.90,
                    risk_contribution=20.0,
                    rule_id="API_RATE_001",
                    rule_version="1.0.0",
                    category=APICategoryEnum.RATE_ANOMALY,
                    target_account=worst_window_events[0].account_id,
                    target_session=worst_window_events[0].session_id,
                    target_source_ip=worst_window_events[0].source_ip,
                    mitre_attack_ids=["T1499.003"],
                    limitation="Legitimate automation or bulk synchronization clients can generate elevated request rates.",
                    evidence_items=[
                        APIFindingEvidenceItem(key="actor_identifier", value=actor_key, source="rate_engine"),
                        APIFindingEvidenceItem(key="request_count_in_window", value=str(max_in_window), source="rate_engine"),
                        APIFindingEvidenceItem(key="window_duration_seconds", value=f"{duration_sec:.1f}", source="rate_engine"),
                        APIFindingEvidenceItem(key="rate_per_minute", value=f"{rate_per_min:.1f}", source="rate_engine"),
                        APIFindingEvidenceItem(key="endpoint_diversity", value=str(endpoint_diversity), source="rate_engine"),
                        APIFindingEvidenceItem(key="status_distribution", value=json.dumps(dict(status_counts)), source="rate_engine"),
                    ]
                ))

            # 2. Sudden burst check (shorter window)
            burst_td = timedelta(seconds=config.burst_window_seconds)
            b_left = 0
            max_burst = 0
            burst_events: List[NormalizedAPIEvent] = []

            for b_right in range(len(sorted_events)):
                while sorted_events[b_right].timestamp - sorted_events[b_left].timestamp > burst_td:
                    b_left += 1
                b_cnt = b_right - b_left + 1
                if b_cnt > max_burst:
                    max_burst = b_cnt
                    burst_events = sorted_events[b_left:b_right + 1]

            if max_burst >= config.burst_threshold:
                b_duration = max(0.5, (burst_events[-1].timestamp - burst_events[0].timestamp).total_seconds())
                findings.append(APIFindingItem(
                    finding_type="API_REQUEST_BURST",
                    title=f"Sudden API Request Burst for {actor_key} ({max_burst} requests in {b_duration:.1f}s)",
                    description=(
                        f"Actor '{actor_key}' exhibited an acute request burst of {max_burst} requests "
                        f"within {b_duration:.1f}s, surpassing burst threshold of {config.burst_threshold}."
                    ),
                    severity=SeverityEnum.LOW,  # Burst alone is not malicious
                    confidence=0.85,
                    risk_contribution=10.0,
                    rule_id="API_BURST_001",
                    rule_version="1.0.0",
                    category=APICategoryEnum.BURST_ANOMALY,
                    target_account=burst_events[0].account_id,
                    target_session=burst_events[0].session_id,
                    target_source_ip=burst_events[0].source_ip,
                    mitre_attack_ids=["T1499"],
                    limitation="Page loads with many parallel assets, webhooks, or retry bursts can trigger this pattern legitimately.",
                    evidence_items=[
                        APIFindingEvidenceItem(key="actor_identifier", value=actor_key, source="burst_engine"),
                        APIFindingEvidenceItem(key="burst_count", value=str(max_burst), source="burst_engine"),
                        APIFindingEvidenceItem(key="burst_duration_seconds", value=f"{b_duration:.1f}", source="burst_engine"),
                    ]
                ))

        return findings


class APIEnumerationEngine:
    """
    Identifies patterns of rapid traversal across distinct route templates (endpoint enumeration)
    or across distinct resource identifiers on the same route template (resource enumeration).
    """
    @classmethod
    def analyze(
        cls,
        events: List[NormalizedAPIEvent],
        config: APIConfigResponse,
    ) -> List[APIFindingItem]:
        findings: List[APIFindingItem] = []
        if not events:
            return findings

        actor_groups: Dict[str, List[NormalizedAPIEvent]] = defaultdict(list)
        for ev in events:
            key = ev.account_id or ev.session_id or ev.token_fingerprint or ev.source_ip
            actor_groups[key].append(ev)

        enum_td = timedelta(seconds=config.endpoint_enum_window_seconds)

        for actor_key, group in actor_groups.items():
            if len(group) < config.endpoint_enum_distinct_threshold:
                continue

            sorted_events = sorted(group, key=lambda e: e.timestamp)

            # 1. Distinct Route Template Enumeration
            routes_in_window = defaultdict(set)
            left = 0
            for right in range(len(sorted_events)):
                while sorted_events[right].timestamp - sorted_events[left].timestamp > enum_td:
                    left += 1
                window_events = sorted_events[left:right + 1]
                distinct_routes = {e.route_template or e.endpoint for e in window_events}
                if len(distinct_routes) >= config.endpoint_enum_distinct_threshold:
                    duration = max(1.0, (window_events[-1].timestamp - window_events[0].timestamp).total_seconds())
                    findings.append(APIFindingItem(
                        finding_type="API_ENDPOINT_ENUMERATION_PATTERN",
                        title=f"Endpoint Enumeration Pattern Detected for {actor_key} ({len(distinct_routes)} distinct routes)",
                        description=(
                            f"Actor '{actor_key}' traversed {len(distinct_routes)} distinct API route templates "
                            f"within {duration:.1f}s, consistent with automated endpoint discovery."
                        ),
                        severity=SeverityEnum.MEDIUM,
                        confidence=0.88,
                        risk_contribution=25.0,
                        rule_id="API_ENUM_001",
                        rule_version="1.0.0",
                        category=APICategoryEnum.ENUMERATION,
                        target_account=window_events[0].account_id,
                        target_session=window_events[0].session_id,
                        target_source_ip=window_events[0].source_ip,
                        mitre_attack_ids=["T1595.002"],
                        limitation="Automated API documentation testers, security scanners, or microservice gateways can systematically poll endpoints.",
                        evidence_items=[
                            APIFindingEvidenceItem(key="actor_identifier", value=actor_key, source="enum_engine"),
                            APIFindingEvidenceItem(key="distinct_routes_count", value=str(len(distinct_routes)), source="enum_engine"),
                            APIFindingEvidenceItem(key="sample_routes", value=", ".join(list(distinct_routes)[:5]), source="enum_engine"),
                            APIFindingEvidenceItem(key="traversal_duration_seconds", value=f"{duration:.1f}", source="enum_engine"),
                        ]
                    ))
                    break  # Emit once per actor

            # 2. Resource ID Enumeration on the Same Route Template
            # e.g., /api/v1/users/1001, /api/v1/users/1002, ...
            template_resources: Dict[str, Set[str]] = defaultdict(set)
            template_events: Dict[str, List[NormalizedAPIEvent]] = defaultdict(list)
            for ev in sorted_events:
                if ev.route_template and ("{id}" in ev.route_template or "{uuid}" in ev.route_template or "{hash}" in ev.route_template):
                    res_hash = ev.resource_id_hash or ev.endpoint
                    template_resources[ev.route_template].add(res_hash)
                    template_events[ev.route_template].append(ev)

            for template, res_hashes in template_resources.items():
                if len(res_hashes) >= config.resource_enum_distinct_threshold:
                    t_events = template_events[template]
                    t_duration = max(1.0, (t_events[-1].timestamp - t_events[0].timestamp).total_seconds())
                    success_count = sum(1 for e in t_events if e.status_code < 400)
                    failure_count = sum(1 for e in t_events if e.status_code >= 400)

                    findings.append(APIFindingItem(
                        finding_type="RESOURCE_ENUMERATION_PATTERN",
                        title=f"Resource ID Enumeration on {template} ({len(res_hashes)} distinct IDs)",
                        description=(
                            f"Actor '{actor_key}' queried {len(res_hashes)} distinct resource instances on route "
                            f"'{template}' within {t_duration:.1f}s ({success_count} success, {failure_count} denied/error)."
                        ),
                        severity=SeverityEnum.HIGH,
                        confidence=0.92,
                        risk_contribution=35.0,
                        rule_id="API_ENUM_002",
                        rule_version="1.0.0",
                        category=APICategoryEnum.ENUMERATION,
                        target_account=t_events[0].account_id,
                        target_session=t_events[0].session_id,
                        target_source_ip=t_events[0].source_ip,
                        target_endpoint=template,
                        mitre_attack_ids=["T1087", "T1005"],
                        limitation="Legitimate bulk ingestion ETL scripts or user directory synchronizers may sequentially iterate over resource identifiers.",
                        evidence_items=[
                            APIFindingEvidenceItem(key="actor_identifier", value=actor_key, source="enum_engine"),
                            APIFindingEvidenceItem(key="target_template", value=template, source="enum_engine"),
                            APIFindingEvidenceItem(key="distinct_resources_count", value=str(len(res_hashes)), source="enum_engine"),
                            APIFindingEvidenceItem(key="success_count", value=str(success_count), source="enum_engine"),
                            APIFindingEvidenceItem(key="failure_count", value=str(failure_count), source="enum_engine"),
                            APIFindingEvidenceItem(key="traversal_duration_seconds", value=f"{t_duration:.1f}", source="enum_engine"),
                        ]
                    ))

        return findings


class APIAuthFailureEngine:
    """
    Distinguishes between authentication failures (401 Unauthorized / missing creds)
    and authorization failures (403 Forbidden on privileged endpoints), as well as
    high missing resource (404) distributions.
    """
    @classmethod
    def analyze(
        cls,
        events: List[NormalizedAPIEvent],
        config: APIConfigResponse,
    ) -> List[APIFindingItem]:
        findings: List[APIFindingItem] = []
        if not events:
            return findings

        actor_groups: Dict[str, List[NormalizedAPIEvent]] = defaultdict(list)
        for ev in events:
            key = ev.account_id or ev.session_id or ev.token_fingerprint or ev.source_ip
            actor_groups[key].append(ev)

        for actor_key, group in actor_groups.items():
            sorted_events = sorted(group, key=lambda e: e.timestamp)

            # 1. 401 Authentication Failures
            auth_failures = [e for e in sorted_events if e.status_code == 401 or e.authentication_status == "FAILURE"]
            if len(auth_failures) >= config.auth_failure_threshold:
                af_dur = max(1.0, (auth_failures[-1].timestamp - auth_failures[0].timestamp).total_seconds())
                if af_dur <= config.auth_failure_window_seconds:
                    findings.append(APIFindingItem(
                        finding_type="REPEATED_API_AUTH_FAILURES",
                        title=f"Repeated API Authentication Failures for {actor_key} ({len(auth_failures)} failures)",
                        description=(
                            f"Observed {len(auth_failures)} repeated HTTP 401 / authentication failures from "
                            f"'{actor_key}' within {af_dur:.1f}s, indicating potential token brute-forcing or expired credentials."
                        ),
                        severity=SeverityEnum.MEDIUM,
                        confidence=0.88,
                        risk_contribution=25.0,
                        rule_id="API_AUTH_001",
                        rule_version="1.0.0",
                        category=APICategoryEnum.AUTHENTICATION_ANOMALY,
                        target_account=auth_failures[0].account_id,
                        target_session=auth_failures[0].session_id,
                        target_source_ip=auth_failures[0].source_ip,
                        mitre_attack_ids=["T1110"],
                        limitation="Misconfigured integration tokens, expired credentials, or client clock skew can produce consecutive 401s.",
                        evidence_items=[
                            APIFindingEvidenceItem(key="actor_identifier", value=actor_key, source="auth_failure_engine"),
                            APIFindingEvidenceItem(key="auth_failure_count", value=str(len(auth_failures)), source="auth_failure_engine"),
                            APIFindingEvidenceItem(key="duration_seconds", value=f"{af_dur:.1f}", source="auth_failure_engine"),
                        ]
                    ))

            # 2. 403 Authorization Failures (Permission probing)
            authz_failures = [e for e in sorted_events if e.status_code == 403 or e.authorization_status == "DENIED"]
            if len(authz_failures) >= config.authz_failure_threshold:
                az_dur = max(1.0, (authz_failures[-1].timestamp - authz_failures[0].timestamp).total_seconds())
                if az_dur <= config.authz_failure_window_seconds:
                    probed_routes = {e.route_template or e.endpoint for e in authz_failures}
                    findings.append(APIFindingItem(
                        finding_type="REPEATED_AUTHORIZATION_FAILURES",
                        title=f"Repeated Authorization Failures for {actor_key} ({len(authz_failures)} denials across {len(probed_routes)} routes)",
                        description=(
                            f"Observed {len(authz_failures)} HTTP 403 Forbidden responses for '{actor_key}' "
                            f"across {len(probed_routes)} distinct endpoints in {az_dur:.1f}s, suggesting privilege boundary probing."
                        ),
                        severity=SeverityEnum.HIGH,
                        confidence=0.90,
                        risk_contribution=35.0,
                        rule_id="API_AUTHZ_001",
                        rule_version="1.0.0",
                        category=APICategoryEnum.AUTHORIZATION_ANOMALY,
                        target_account=authz_failures[0].account_id,
                        target_session=authz_failures[0].session_id,
                        target_source_ip=authz_failures[0].source_ip,
                        mitre_attack_ids=["T1078"],
                        limitation="A user navigating a dashboard with revoked roles or partial permissions can receive clustered 403 responses.",
                        evidence_items=[
                            APIFindingEvidenceItem(key="actor_identifier", value=actor_key, source="auth_failure_engine"),
                            APIFindingEvidenceItem(key="authz_failure_count", value=str(len(authz_failures)), source="auth_failure_engine"),
                            APIFindingEvidenceItem(key="probed_routes_count", value=str(len(probed_routes)), source="auth_failure_engine"),
                            APIFindingEvidenceItem(key="sample_probed_routes", value=", ".join(list(probed_routes)[:4]), source="auth_failure_engine"),
                        ]
                    ))

            # 3. 404 Missing Endpoint Rate
            missing_failures = [e for e in sorted_events if e.status_code == 404]
            if len(missing_failures) >= config.missing_endpoint_threshold:
                mf_dur = max(1.0, (missing_failures[-1].timestamp - missing_failures[0].timestamp).total_seconds())
                if mf_dur <= config.missing_endpoint_window_seconds:
                    distinct_missing = {e.endpoint for e in missing_failures}
                    findings.append(APIFindingItem(
                        finding_type="HIGH_MISSING_ENDPOINT_RATE",
                        title=f"Elevated 404 Not Found Rate for {actor_key} ({len(missing_failures)} requests)",
                        description=(
                            f"Actor '{actor_key}' received {len(missing_failures)} HTTP 404 responses for {len(distinct_missing)} "
                            f"distinct endpoints in {mf_dur:.1f}s, indicative of directory brute-forcing or broken crawler traversal."
                        ),
                        severity=SeverityEnum.LOW,
                        confidence=0.82,
                        risk_contribution=12.0,
                        rule_id="API_404_001",
                        rule_version="1.0.0",
                        category=APICategoryEnum.MISSING_ENDPOINT_ANOMALY,
                        target_account=missing_failures[0].account_id,
                        target_session=missing_failures[0].session_id,
                        target_source_ip=missing_failures[0].source_ip,
                        mitre_attack_ids=["T1595.002"],
                        limitation="Broken hyperlinks, deprecated client version integrations, or crawler indexing can trigger 404 spikes.",
                        evidence_items=[
                            APIFindingEvidenceItem(key="actor_identifier", value=actor_key, source="auth_failure_engine"),
                            APIFindingEvidenceItem(key="missing_count", value=str(len(missing_failures)), source="auth_failure_engine"),
                            APIFindingEvidenceItem(key="distinct_missing_paths", value=str(len(distinct_missing)), source="auth_failure_engine"),
                        ]
                    ))

        return findings


class APIMethodPrivilegeEngine:
    """
    Detects unusual HTTP methods and access to sensitive/privileged routes.
    """
    @classmethod
    def analyze(
        cls,
        events: List[NormalizedAPIEvent],
        config: APIConfigResponse,
    ) -> List[APIFindingItem]:
        findings: List[APIFindingItem] = []
        if not events:
            return findings

        sensitive_set = {r.lower() for r in config.sensitive_routes}

        for ev in events:
            actor = ev.account_id or ev.session_id or ev.source_ip
            route = (ev.route_template or ev.endpoint).lower()

            # 1. Privileged Operation Signal
            is_sensitive = any(s in route for s in sensitive_set)
            if is_sensitive:
                findings.append(APIFindingItem(
                    finding_type="PRIVILEGED_API_OPERATION",
                    title=f"Privileged Endpoint Accessed by {actor} ({ev.method.value} {ev.endpoint})",
                    description=(
                        f"Actor '{actor}' accessed sensitive/administrative route '{ev.endpoint}' "
                        f"via {ev.method.value} (HTTP {ev.status_code})."
                    ),
                    severity=SeverityEnum.LOW if ev.status_code < 400 else SeverityEnum.MEDIUM,
                    confidence=0.85,
                    risk_contribution=10.0,
                    rule_id="API_PRIV_001",
                    rule_version="1.0.0",
                    category=APICategoryEnum.SENSITIVE_ENDPOINT,
                    target_account=ev.account_id,
                    target_session=ev.session_id,
                    target_source_ip=ev.source_ip,
                    target_endpoint=ev.endpoint,
                    mitre_attack_ids=["T1078"],
                    limitation="Authorized administrators and scheduled maintenance jobs routinely interact with privileged endpoints.",
                    evidence_items=[
                        APIFindingEvidenceItem(key="actor_identifier", value=actor, source="privilege_engine"),
                        APIFindingEvidenceItem(key="endpoint", value=ev.endpoint, source="privilege_engine"),
                        APIFindingEvidenceItem(key="method", value=ev.method.value, source="privilege_engine"),
                        APIFindingEvidenceItem(key="status_code", value=str(ev.status_code), source="privilege_engine"),
                    ]
                ))

        # 2. Cluster of Destructive Methods (DELETE / PUT)
        actor_groups: Dict[str, List[NormalizedAPIEvent]] = defaultdict(list)
        for ev in events:
            actor = ev.account_id or ev.session_id or ev.source_ip
            actor_groups[actor].append(ev)

        for actor, group in actor_groups.items():
            deletes = [e for e in group if e.method == HTTPMethodEnum.DELETE]
            if len(deletes) >= 5:
                findings.append(APIFindingItem(
                    finding_type="UNUSUAL_API_METHOD",
                    title=f"High Frequency of DELETE Requests for {actor} ({len(deletes)} delete operations)",
                    description=(
                        f"Actor '{actor}' executed {len(deletes)} HTTP DELETE operations across endpoints, "
                        f"deviating from standard retrieval behaviors."
                    ),
                    severity=SeverityEnum.MEDIUM,
                    confidence=0.85,
                    risk_contribution=20.0,
                    rule_id="API_METH_001",
                    rule_version="1.0.0",
                    category=APICategoryEnum.METHOD_ANOMALY,
                    target_account=deletes[0].account_id,
                    target_session=deletes[0].session_id,
                    target_source_ip=deletes[0].source_ip,
                    mitre_attack_ids=["T1485"],
                    limitation="Bulk purge routines, cache invalidation jobs, or cleanup scripts routinely issue mass DELETE requests.",
                    evidence_items=[
                        APIFindingEvidenceItem(key="actor_identifier", value=actor, source="method_engine"),
                        APIFindingEvidenceItem(key="delete_count", value=str(len(deletes)), source="method_engine"),
                    ]
                ))

        return findings


class APISessionAnomalyEngine:
    """
    Detects session hijacking indicators, token source shifts, rapid IP changes,
    client profile shifts, and new endpoints with baseline history enforcement.
    """
    @classmethod
    def analyze(
        cls,
        events: List[NormalizedAPIEvent],
        config: APIConfigResponse,
        account_profiles: Optional[Dict[str, AccountAPIBaselineProfile]] = None,
    ) -> List[APIFindingItem]:
        findings: List[APIFindingItem] = []
        if not events:
            return findings

        profiles = account_profiles or {}

        # 1. Session & Token Source Changes
        session_events: Dict[str, List[NormalizedAPIEvent]] = defaultdict(list)
        for ev in events:
            if ev.session_id:
                session_events[ev.session_id].append(ev)

        for sess_id, group in session_events.items():
            distinct_ips = list({e.source_ip for e in group})
            if len(distinct_ips) > 1:
                sorted_group = sorted(group, key=lambda e: e.timestamp)
                duration = (sorted_group[-1].timestamp - sorted_group[0].timestamp).total_seconds()

                # Rapid session source change (< rapid_source_change_window_seconds)
                is_rapid = duration <= config.rapid_source_change_window_seconds
                findings.append(APIFindingItem(
                    finding_type="RAPID_SESSION_SOURCE_CHANGE" if is_rapid else "SESSION_SOURCE_CHANGE",
                    title=(
                        f"Rapid Session Source Change for Session {sess_id} ({len(distinct_ips)} IPs in {duration:.1f}s)"
                        if is_rapid else
                        f"Session Source Change Observed for Session {sess_id} ({len(distinct_ips)} IPs)"
                    ),
                    description=(
                        f"Session '{sess_id}' was accessed from multiple distinct IP addresses "
                        f"({', '.join(distinct_ips)}) within {duration:.1f}s. "
                        f"{'This rapid relocation is consistent with token replay or session hijacking.' if is_rapid else 'May indicate mobile network handover or VPN reconnection.'}"
                    ),
                    severity=SeverityEnum.HIGH if is_rapid else SeverityEnum.LOW,
                    confidence=0.90 if is_rapid else 0.75,
                    risk_contribution=35.0 if is_rapid else 10.0,
                    rule_id="API_SESS_002" if is_rapid else "API_SESS_001",
                    rule_version="1.0.0",
                    category=APICategoryEnum.SESSION_ANOMALY,
                    target_session=sess_id,
                    target_account=group[0].account_id,
                    target_source_ip=distinct_ips[-1],
                    mitre_attack_ids=["T1539", "T1078"],
                    limitation="Mobile roaming (switching cellular tower to Wi-Fi), dynamic corporate NAT proxies, or multi-cloud egress gateways frequently rotate source IPs.",
                    evidence_items=[
                        APIFindingEvidenceItem(key="session_id", value=sess_id, source="session_engine"),
                        APIFindingEvidenceItem(key="source_ips", value=", ".join(distinct_ips), source="session_engine"),
                        APIFindingEvidenceItem(key="relocation_duration_seconds", value=f"{duration:.1f}", source="session_engine"),
                    ]
                ))

            # Client Profile / User-Agent Shift for Session
            uas = list({e.user_agent for e in group if e.user_agent})
            if len(uas) > 1:
                client_types = list({e.client_type.value for e in group})
                findings.append(APIFindingItem(
                    finding_type="API_CLIENT_PROFILE_CHANGE",
                    title=f"User-Agent Profile Shift in Session {sess_id} ({', '.join(client_types)})",
                    description=(
                        f"Session '{sess_id}' originated requests using multiple disparate User-Agent signatures "
                        f"({', '.join(client_types)}), suggesting session token transfer across environments."
                    ),
                    severity=SeverityEnum.MEDIUM,
                    confidence=0.84,
                    risk_contribution=20.0,
                    rule_id="API_CLIENT_001",
                    rule_version="1.0.0",
                    category=APICategoryEnum.SESSION_ANOMALY,
                    target_session=sess_id,
                    target_account=group[0].account_id,
                    mitre_attack_ids=["T1539"],
                    limitation="Dual-engine native clients, browser developer tools, or automated test suites may switch user-agents within a session.",
                    evidence_items=[
                        APIFindingEvidenceItem(key="session_id", value=sess_id, source="session_engine"),
                        APIFindingEvidenceItem(key="observed_client_types", value=", ".join(client_types), source="session_engine"),
                    ]
                ))

        # 2. Historical Baseline Evaluation: NEW_API_ENDPOINT vs INSUFFICIENT_HISTORY
        for ev in events:
            if not ev.account_id:
                continue
            acc = ev.account_id
            prof = profiles.get(acc)

            # If account has profile with sufficient history
            if prof and prof.total_requests_observed >= config.min_history_events_baseline:
                route = ev.route_template or ev.endpoint
                if route not in prof.known_endpoints:
                    findings.append(APIFindingItem(
                        finding_type="NEW_API_ENDPOINT",
                        title=f"New API Endpoint Accessed by {acc} ({route})",
                        description=(
                            f"Account '{acc}' accessed endpoint '{route}' for the first time "
                            f"(historical baseline includes {len(prof.known_endpoints)} known routes across {prof.total_requests_observed} requests)."
                        ),
                        severity=SeverityEnum.LOW,  # New is not malicious
                        confidence=0.75,
                        risk_contribution=8.0,
                        rule_id="API_NEW_001",
                        rule_version="1.0.0",
                        category=APICategoryEnum.SESSION_ANOMALY,
                        target_account=acc,
                        target_endpoint=route,
                        mitre_attack_ids=["T1078"],
                        limitation="Users routinely explore new product features, update workflows, or access updated UI versions.",
                        evidence_items=[
                            APIFindingEvidenceItem(key="account_id", value=acc, source="baseline_engine"),
                            APIFindingEvidenceItem(key="new_endpoint", value=route, source="baseline_engine"),
                            APIFindingEvidenceItem(key="baseline_request_count", value=str(prof.total_requests_observed), source="baseline_engine"),
                        ]
                    ))

        return findings


class APIVolumeScrapingEngine:
    """
    Evaluates response volume, bulk data export, scraping traversal,
    and automation periodicity.
    """
    @classmethod
    def analyze(
        cls,
        events: List[NormalizedAPIEvent],
        config: APIConfigResponse,
    ) -> List[APIFindingItem]:
        findings: List[APIFindingItem] = []
        if not events:
            return findings

        actor_groups: Dict[str, List[NormalizedAPIEvent]] = defaultdict(list)
        for ev in events:
            key = ev.account_id or ev.session_id or ev.token_fingerprint or ev.source_ip
            actor_groups[key].append(ev)

        for actor, group in actor_groups.items():
            total_resp_bytes = sum(e.response_bytes or 0 for e in group)

            # 1. High API Response Volume
            if total_resp_bytes >= config.high_response_volume_bytes:
                mb = total_resp_bytes / (1024 * 1024)
                findings.append(APIFindingItem(
                    finding_type="HIGH_API_RESPONSE_VOLUME",
                    title=f"High API Response Volume for {actor} ({mb:.1f} MB)",
                    description=(
                        f"Actor '{actor}' retrieved {mb:.1f} MB of data across {len(group)} requests, "
                        f"exceeding volume threshold of {config.high_response_volume_bytes / (1024 * 1024):.0f} MB."
                    ),
                    severity=SeverityEnum.MEDIUM,
                    confidence=0.88,
                    risk_contribution=25.0,
                    rule_id="API_VOL_001",
                    rule_version="1.0.0",
                    category=APICategoryEnum.DATA_VOLUME_ANOMALY,
                    target_account=group[0].account_id,
                    target_session=group[0].session_id,
                    target_source_ip=group[0].source_ip,
                    mitre_attack_ids=["T1567", "T1005"],
                    limitation="Authorized data exports, report generation, or database backups routinely produce high volume transfers.",
                    evidence_items=[
                        APIFindingEvidenceItem(key="actor_identifier", value=actor, source="volume_engine"),
                        APIFindingEvidenceItem(key="total_bytes", value=str(total_resp_bytes), source="volume_engine"),
                        APIFindingEvidenceItem(key="total_mb", value=f"{mb:.2f}", source="volume_engine"),
                        APIFindingEvidenceItem(key="request_count", value=str(len(group)), source="volume_engine"),
                    ]
                ))

            # 2. Bulk Export Activity
            export_events = [
                e for e in group
                if e.endpoint and any(k in e.endpoint.lower() for k in ("export", "download", "dump", "backup"))
            ]
            export_bytes = sum(e.response_bytes or 0 for e in export_events)
            if export_events and export_bytes >= config.bulk_export_min_bytes:
                mb = export_bytes / (1024 * 1024)
                findings.append(APIFindingItem(
                    finding_type="UNUSUAL_BULK_EXPORT_ACTIVITY",
                    title=f"Bulk Data Export Operation by {actor} ({mb:.1f} MB)",
                    description=(
                        f"Actor '{actor}' retrieved {mb:.1f} MB from export/download endpoint(s) "
                        f"across {len(export_events)} requests."
                    ),
                    severity=SeverityEnum.HIGH,
                    confidence=0.92,
                    risk_contribution=35.0,
                    rule_id="API_EXP_001",
                    rule_version="1.0.0",
                    category=APICategoryEnum.DATA_VOLUME_ANOMALY,
                    target_account=group[0].account_id,
                    target_session=group[0].session_id,
                    target_source_ip=group[0].source_ip,
                    target_endpoint=export_events[0].endpoint,
                    mitre_attack_ids=["T1567.002", "T1005"],
                    limitation="Regular scheduled reporting, user account takeout, or financial export jobs regularly pull bulk files.",
                    evidence_items=[
                        APIFindingEvidenceItem(key="actor_identifier", value=actor, source="volume_engine"),
                        APIFindingEvidenceItem(key="export_bytes", value=str(export_bytes), source="volume_engine"),
                        APIFindingEvidenceItem(key="export_mb", value=f"{mb:.2f}", source="volume_engine"),
                        APIFindingEvidenceItem(key="export_endpoint", value=export_events[0].endpoint, source="volume_engine"),
                    ]
                ))

            # 3. Scraping-Like Traversal Pattern
            # High GET volume + high distinct resources + rapid duration + low error rate
            gets = [e for e in group if e.method == HTTPMethodEnum.GET]
            if len(gets) >= config.scraping_min_requests:
                sorted_gets = sorted(gets, key=lambda e: e.timestamp)
                duration = max(1.0, (sorted_gets[-1].timestamp - sorted_gets[0].timestamp).total_seconds())
                if duration <= config.scraping_max_duration_seconds:
                    distinct_res = len({e.resource_id_hash or e.endpoint for e in sorted_gets})
                    if distinct_res >= config.scraping_min_resources:
                        successes = sum(1 for e in sorted_gets if e.status_code == 200)
                        success_rate = successes / len(sorted_gets)
                        if success_rate >= 0.80:
                            findings.append(APIFindingItem(
                                finding_type="SCRAPING_LIKE_API_ACTIVITY",
                                title=f"Scraping-Like Data Harvesting Pattern for {actor} ({distinct_res} resources in {duration:.1f}s)",
                                description=(
                                    f"Actor '{actor}' executed {len(gets)} rapid GET requests across {distinct_res} "
                                    f"distinct resource instances within {duration:.1f}s with an {success_rate:.0%} success rate, "
                                    f"characteristic of automated content scraping."
                                ),
                                severity=SeverityEnum.MEDIUM,
                                confidence=0.88,
                                risk_contribution=30.0,
                                rule_id="API_SCRAPE_001",
                                rule_version="1.0.0",
                                category=APICategoryEnum.SCRAPING_ANOMALY,
                                target_account=group[0].account_id,
                                target_session=group[0].session_id,
                                target_source_ip=group[0].source_ip,
                                mitre_attack_ids=["T1005", "T1119"],
                                limitation="Local web caching crawlers, indexing services, or frontend pre-fetching can generate high-speed GET iterations.",
                                evidence_items=[
                                    APIFindingEvidenceItem(key="actor_identifier", value=actor, source="scraping_engine"),
                                    APIFindingEvidenceItem(key="get_request_count", value=str(len(gets)), source="scraping_engine"),
                                    APIFindingEvidenceItem(key="distinct_resources_harvested", value=str(distinct_res), source="scraping_engine"),
                                    APIFindingEvidenceItem(key="duration_seconds", value=f"{duration:.1f}", source="scraping_engine"),
                                    APIFindingEvidenceItem(key="success_rate", value=f"{success_rate:.2f}", source="scraping_engine"),
                                ]
                            ))

            # 4. Periodicity / Automation Interval Analysis
            if len(group) >= config.periodicity_min_observations:
                sorted_group = sorted(group, key=lambda e: e.timestamp)
                intervals: List[float] = []
                for i in range(1, len(sorted_group)):
                    diff = (sorted_group[i].timestamp - sorted_group[i - 1].timestamp).total_seconds()
                    if diff > 0:
                        intervals.append(diff)

                if len(intervals) >= 4:
                    mean_int = sum(intervals) / len(intervals)
                    variance = sum((x - mean_int) ** 2 for x in intervals) / len(intervals)
                    std_dev = math.sqrt(variance)
                    cv = std_dev / mean_int if mean_int > 0 else 1.0

                    if cv <= config.periodicity_max_cv and mean_int >= 1.0:
                        findings.append(APIFindingItem(
                            finding_type="PERIODIC_API_ACTIVITY",
                            title=f"Periodic Automated API Activity for {actor} (Mean: {mean_int:.1f}s, CV: {cv:.3f})",
                            description=(
                                f"Observed regular periodic intervals from actor '{actor}' across {len(intervals)} connections "
                                f"with mean interval {mean_int:.1f}s and minimal jitter (CV: {cv:.3f}), consistent with automated scheduling."
                            ),
                            severity=SeverityEnum.LOW,  # Periodicity is normal in healthchecks/sync
                            confidence=0.85,
                            risk_contribution=8.0,
                            rule_id="API_PERIOD_001",
                            rule_version="1.0.0",
                            category=APICategoryEnum.PERIODICITY_ANOMALY,
                            target_account=group[0].account_id,
                            target_session=group[0].session_id,
                            target_source_ip=group[0].source_ip,
                            mitre_attack_ids=["T1059"],
                            limitation="Health check probes, cron sync daemons, and microservice status heartbeats regularly generate low-jitter periodic calls.",
                            evidence_items=[
                                APIFindingEvidenceItem(key="actor_identifier", value=actor, source="periodicity_engine"),
                                APIFindingEvidenceItem(key="mean_interval_seconds", value=f"{mean_int:.2f}", source="periodicity_engine"),
                                APIFindingEvidenceItem(key="coefficient_of_variation", value=f"{cv:.4f}", source="periodicity_engine"),
                            ]
                        ))

        return findings


# ============================================================================
# 6. COMPOSITE ABUSE AGGREGATOR
# ============================================================================

class APIPatternAggregator:
    """
    Evaluates multi-category corroboration to produce high-confidence composite hypotheses:
    - API_ABUSE_SUSPECTED (e.g. Session anomaly + Resource enumeration + Authz failures + Data retrieval)
    - POSSIBLE_API_DATA_EXFILTRATION (e.g. Bulk export + High response volume + Rapid traversal)
    """
    @classmethod
    def aggregate(
        cls,
        events: List[NormalizedAPIEvent],
        findings: List[APIFindingItem],
    ) -> Tuple[List[APIFindingItem], List[Dict[str, Any]], float, SeverityEnum, str]:
        all_findings = list(findings)
        corroborated_events: List[Dict[str, Any]] = []

        categories_present = {f.category for f in findings}

        # Composite Hypothesis 1: API Abuse Suspected
        # Corroborates: (Session or Auth or Authz) + (Enumeration or Rate) + (Data Volume or Sensitive Endpoint)
        has_auth_session = bool({
            APICategoryEnum.AUTHENTICATION_ANOMALY,
            APICategoryEnum.AUTHORIZATION_ANOMALY,
            APICategoryEnum.SESSION_ANOMALY
        }.intersection(categories_present))

        has_enumeration_rate = bool({
            APICategoryEnum.ENUMERATION,
            APICategoryEnum.RATE_ANOMALY,
            APICategoryEnum.BURST_ANOMALY
        }.intersection(categories_present))

        has_data_sensitive = bool({
            APICategoryEnum.DATA_VOLUME_ANOMALY,
            APICategoryEnum.SCRAPING_ANOMALY,
            APICategoryEnum.SENSITIVE_ENDPOINT
        }.intersection(categories_present))

        if has_auth_session and has_enumeration_rate and has_data_sensitive:
            ev_summary = [f"{f.finding_type} ({f.severity.value})" for f in findings]
            target_acc = next((f.target_account for f in findings if f.target_account), None)
            target_sess = next((f.target_session for f in findings if f.target_session), None)
            target_ip = next((f.target_source_ip for f in findings if f.target_source_ip), None)

            composite_finding = APIFindingItem(
                finding_type="API_ABUSE_SUSPECTED",
                title="Composite API Abuse Suspected: Multi-Vector Telemetry Corroboration",
                description=(
                    "Correlated multiple independent telemetry anomalies across authentication/session shifts, "
                    "endpoint/resource enumeration, and high-volume data retrieval. "
                    "Pattern is strongly characteristic of targeted API abuse or account exploitation."
                ),
                severity=SeverityEnum.HIGH,
                confidence=0.92,
                risk_contribution=45.0,
                rule_id="API_COMPOSITE_001",
                rule_version="1.0.0",
                category=APICategoryEnum.COMPOSITE_ABUSE,
                target_account=target_acc,
                target_session=target_sess,
                target_source_ip=target_ip,
                mitre_attack_ids=["T1078", "T1005", "T1595"],
                limitation="Multiple concurrent legitimate admin activities or misconfigured developer scripts could trigger multiple alarms coincidentally.",
                evidence_items=[
                    APIFindingEvidenceItem(key="corroborated_signals_count", value=str(len(findings)), source="aggregator"),
                    APIFindingEvidenceItem(key="signals_list", value=", ".join(ev_summary[:6]), source="aggregator"),
                ]
            )
            all_findings.append(composite_finding)

            corroborated_events.append({
                "event_type": "API_ABUSE_SUSPECTED",
                "severity": "HIGH",
                "description": composite_finding.description,
                "target_account": target_acc,
                "target_session": target_sess,
                "target_source_ip": target_ip,
                "contributing_finding_count": len(findings),
            })

        # Composite Hypothesis 2: Possible API Data Exfiltration
        has_bulk_export = any(f.finding_type == "UNUSUAL_BULK_EXPORT_ACTIVITY" for f in findings)
        has_high_volume = any(f.finding_type == "HIGH_API_RESPONSE_VOLUME" for f in findings)
        has_session_shift = any(f.category == APICategoryEnum.SESSION_ANOMALY for f in findings)

        if (has_bulk_export and (has_high_volume or has_session_shift)) or (has_high_volume and has_enumeration_rate):
            target_acc = next((f.target_account for f in findings if f.target_account), None)
            target_sess = next((f.target_session for f in findings if f.target_session), None)
            target_ip = next((f.target_source_ip for f in findings if f.target_source_ip), None)

            exfil_finding = APIFindingItem(
                finding_type="POSSIBLE_API_DATA_EXFILTRATION",
                title="Possible API-Based Data Exfiltration Pattern",
                description=(
                    "Observed bulk data export or high-volume data retrieval combined with session/enumeration anomalies. "
                    "Hypothesis: unauthorized bulk data extraction via API interface."
                ),
                severity=SeverityEnum.HIGH,
                confidence=0.90,
                risk_contribution=40.0,
                rule_id="API_COMPOSITE_002",
                rule_version="1.0.0",
                category=APICategoryEnum.COMPOSITE_ABUSE,
                target_account=target_acc,
                target_session=target_sess,
                target_source_ip=target_ip,
                mitre_attack_ids=["T1567", "T1005"],
                limitation="Planned compliance exports, offline analytics dumps, or authorized DB backups produce high volume transfers.",
                evidence_items=[
                    APIFindingEvidenceItem(key="hypothesis", value="POSSIBLE_API_DATA_EXFILTRATION", source="aggregator"),
                    APIFindingEvidenceItem(key="target_account", value=str(target_acc), source="aggregator"),
                    APIFindingEvidenceItem(key="target_session", value=str(target_sess), source="aggregator"),
                ]
            )
            all_findings.append(exfil_finding)

            corroborated_events.append({
                "event_type": "POSSIBLE_API_DATA_EXFILTRATION",
                "severity": "HIGH",
                "description": exfil_finding.description,
                "target_account": target_acc,
                "target_session": target_sess,
                "target_source_ip": target_ip,
            })

        # Calculate Calibrated Risk Score & Classification
        if not all_findings:
            return all_findings, corroborated_events, 0.0, SeverityEnum.SAFE, "BENIGN_API_TELEMETRY"

        # Severity-weighted score calculation
        severity_weights = {
            SeverityEnum.CRITICAL: 40.0,
            SeverityEnum.HIGH: 25.0,
            SeverityEnum.MEDIUM: 12.0,
            SeverityEnum.LOW: 5.0,
            SeverityEnum.SAFE: 0.0,
        }
        score = sum(severity_weights.get(f.severity, 0.0) for f in all_findings)
        score = min(100.0, max(0.0, score))

        if score >= 80.0 or any(f.severity == SeverityEnum.CRITICAL for f in all_findings):
            overall_sev = SeverityEnum.CRITICAL
            classification = "CRITICAL_API_THREAT"
        elif score >= 60.0 or any(f.severity == SeverityEnum.HIGH for f in all_findings):
            overall_sev = SeverityEnum.HIGH
            classification = "HIGH_RISK_API_ABUSE"
        elif score >= 30.0 or any(f.severity == SeverityEnum.MEDIUM for f in all_findings):
            overall_sev = SeverityEnum.MEDIUM
            classification = "SUSPICIOUS_API_BEHAVIOR"
        elif score > 0.0:
            overall_sev = SeverityEnum.LOW
            classification = "INFORMATIONAL_API_ANOMALY"
        else:
            overall_sev = SeverityEnum.SAFE
            classification = "BENIGN_API_TELEMETRY"

        return all_findings, corroborated_events, score, overall_sev, classification
