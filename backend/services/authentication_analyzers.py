"""
Authentication and Account-Takeover (ATO) Security Analyzers.
Provides safe, deterministic, explainable log normalization, pattern detection
(brute force, password spray, credential stuffing, impossible travel, new device),
and multi-category ATO evidence aggregation.
"""
from __future__ import annotations

import re
import math
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple, Set
from collections import defaultdict

from backend.schemas.unified import SeverityEnum
from backend.schemas.authentication_security import (
    AuthenticationResultEnum,
    AuthMethodEnum,
    MFAMethodEnum,
    FailureReasonEnum,
    ATOCategoryEnum,
    BaselineStatusEnum,
    NormalizedAuthEvent,
    AccountSecurityProfile,
    AuthenticationFindingItem,
    FindingEvidenceItem,
    AuthConfigResponse,
)


# ============================================================================
# SECRET REDACTOR
# ============================================================================

class SecretRedactor:
    """
    Safely redacts passwords, tokens, session cookies, and credentials from logs.
    Never exposes raw secrets in telemetry or persistence.
    """
    SECRET_KEY_PATTERNS = [
        re.compile(r"pass(word)?", re.IGNORECASE),
        re.compile(r"pwd", re.IGNORECASE),
        re.compile(r"secret", re.IGNORECASE),
        re.compile(r"token", re.IGNORECASE),
        re.compile(r"bearer", re.IGNORECASE),
        re.compile(r"auth(orization)?_code", re.IGNORECASE),
        re.compile(r"cookie", re.IGNORECASE),
        re.compile(r"api_?key", re.IGNORECASE),
        re.compile(r"otp", re.IGNORECASE),
        re.compile(r"mfa_?code", re.IGNORECASE),
        re.compile(r"session_?key", re.IGNORECASE),
    ]

    REPLACEMENT = "[REDACTED_BY_CYBERGUARD]"

    @classmethod
    def redact_dict(cls, data: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively redact dictionary keys matching secret patterns."""
        sanitized: Dict[str, Any] = {}
        for k, v in data.items():
            if any(pattern.search(str(k)) for pattern in cls.SECRET_KEY_PATTERNS):
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
    def redact_text(cls, text: str) -> str:
        """Redacts inline password=... or token=... patterns in text strings."""
        if not text:
            return ""
        pattern = re.compile(
            r'(password|passwd|pwd|token|secret|authorization)\s*[:=]\s*["\']?([^"\'\s,;]+)["\']?',
            re.IGNORECASE
        )
        return pattern.sub(r'\1=' + cls.REPLACEMENT, text)


# ============================================================================
# LOG ADAPTER ARCHITECTURE
# ============================================================================

class BaseAuthAdapter:
    """Base class for authentication telemetry log adapters."""
    provider_name: str = "generic"
    version: str = "1.0.0"

    def can_handle(self, raw_event: Any) -> bool:
        raise NotImplementedError

    def normalize(self, raw_event: Any) -> NormalizedAuthEvent:
        raise NotImplementedError


class GenericAuthAdapter(BaseAuthAdapter):
    """
    Universal adapter supporting common JSON / dict authentication log structures.
    """
    provider_name: str = "generic"
    version: str = "1.0.0"

    def can_handle(self, raw_event: Any) -> bool:
        return isinstance(raw_event, dict)

    def normalize(self, raw_event: Any) -> NormalizedAuthEvent:
        d = SecretRedactor.redact_dict(dict(raw_event)) if isinstance(raw_event, dict) else {}

        # 1. Event ID
        event_id = str(d.get("id") or d.get("event_id") or d.get("eventId") or str(uuid.uuid4()))

        # 2. Timestamp
        timestamp = self._parse_timestamp(d.get("timestamp") or d.get("time") or d.get("event_time") or d.get("date"))

        # 3. Account / Identity
        raw_account = (
            d.get("account_id") or
            d.get("username") or
            d.get("user") or
            d.get("userPrincipalName") or
            d.get("email") or
            d.get("login") or
            "unknown"
        )
        account_id = str(raw_account).strip().lower()
        username = str(d.get("username") or raw_account).strip()
        user_id = str(d.get("user_id") or d.get("userId") or "") or None

        # 4. Source IP and Port
        source_ip = str(
            d.get("source_ip") or
            d.get("ip") or
            d.get("client_ip") or
            d.get("ip_address") or
            d.get("ipAddress") or
            "127.0.0.1"
        ).strip()
        source_port = d.get("source_port") or d.get("port")
        try:
            source_port = int(source_port) if source_port is not None else None
        except (ValueError, TypeError):
            source_port = None

        # 5. Service / Destination
        destination_service = d.get("destination_service") or d.get("service") or d.get("app") or d.get("appDisplayName")

        # 6. Device & User Agent
        device_id = d.get("device_id") or d.get("deviceId")
        device_name = d.get("device_name") or d.get("deviceName") or d.get("hostname")
        user_agent = str(d.get("user_agent") or d.get("userAgent") or "").strip() or None
        platform, browser = self._parse_user_agent(user_agent)

        # 7. Session ID
        session_id = d.get("session_id") or d.get("sessionId") or d.get("session")

        # 8. Authentication Method
        auth_method = self._parse_auth_method(d.get("authentication_method") or d.get("auth_method") or d.get("method"))

        # 9. MFA Method
        mfa_method = self._parse_mfa_method(d.get("mfa_method") or d.get("mfa_type") or d.get("second_factor"))

        # 10. Result
        result = self._parse_result(d.get("result") or d.get("status") or d.get("outcome") or d.get("action"))

        # 11. Failure Reason
        failure_reason = self._parse_failure_reason(d.get("failure_reason") or d.get("reason") or d.get("error_code"))
        failure_detail = d.get("failure_detail") or d.get("message") or d.get("error_message")

        # 12. Location (if present)
        loc = d.get("location") if isinstance(d.get("location"), dict) else {}
        city = d.get("location_city") or d.get("city") or loc.get("city")
        country = d.get("location_country") or d.get("country") or loc.get("country")
        country_code = d.get("location_country_code") or d.get("country_code") or loc.get("country_code")
        lat = d.get("latitude") or loc.get("latitude")
        lon = d.get("longitude") or loc.get("longitude")

        return NormalizedAuthEvent(
            id=event_id,
            timestamp=timestamp,
            account_id=account_id,
            username=username,
            user_id=user_id,
            source_ip=source_ip,
            source_port=source_port,
            destination_service=str(destination_service) if destination_service else None,
            device_id=str(device_id) if device_id else None,
            device_name=str(device_name) if device_name else None,
            user_agent=user_agent,
            client_platform=platform,
            client_browser=browser,
            session_id=str(session_id) if session_id else None,
            authentication_method=auth_method,
            mfa_method=mfa_method,
            result=result,
            failure_reason=failure_reason,
            failure_detail=str(failure_detail) if failure_detail else None,
            location_city=str(city) if city else None,
            location_country=str(country) if country else None,
            location_country_code=str(country_code).upper() if country_code else None,
            latitude=float(lat) if lat is not None else None,
            longitude=float(lon) if lon is not None else None,
            isp=d.get("isp"),
            asn=d.get("asn"),
            is_vpn_or_proxy=d.get("is_vpn_or_proxy"),
            provider=self.provider_name,
            raw_artifact_id=d.get("raw_artifact_id"),
            metadata={**{k: v for k, v in d.items() if k not in ("id", "timestamp", "account_id")}, "timestamp_supplied": bool(d.get("timestamp") or d.get("time") or d.get("event_time") or d.get("date"))},
        )

    def _parse_timestamp(self, ts_raw: Any) -> datetime:
        if isinstance(ts_raw, datetime):
            return ts_raw.astimezone(timezone.utc)
        if isinstance(ts_raw, (int, float)):
            # Handle milliseconds vs seconds
            sec = ts_raw / 1000.0 if ts_raw > 1e11 else ts_raw
            return datetime.fromtimestamp(sec, tz=timezone.utc)
        if isinstance(ts_raw, str) and ts_raw.strip():
            clean = ts_raw.strip()
            try:
                # ISO 8601 parsing
                if clean.endswith("Z"):
                    clean = clean[:-1] + "+00:00"
                dt = datetime.fromisoformat(clean)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.astimezone(timezone.utc)
            except Exception:
                pass
        return datetime.now(timezone.utc)

    def _parse_result(self, raw: Any) -> AuthenticationResultEnum:
        s = str(raw or "").upper().strip()
        if s in ("SUCCESS", "OK", "PASS", "ALLOW", "AUTHORIZED", "ACCEPTED") or "SUCCESS" in s:
            return AuthenticationResultEnum.SUCCESS
        if s in ("FAILURE", "FAIL", "FAILED", "INVALID", "REJECTED", "ERROR", "BAD_PASSWORD") or "FAIL" in s or "INVALID" in s or "BAD_PASS" in s:
            return AuthenticationResultEnum.FAILURE
        if s in ("MFA_REQUIRED", "CHALLENGE", "MFA_PROMPT"):
            return AuthenticationResultEnum.MFA_REQUIRED
        if s in ("MFA_SUCCESS",):
            return AuthenticationResultEnum.MFA_SUCCESS
        if s in ("MFA_FAILURE", "MFA_REJECTED", "MFA_FAILED"):
            return AuthenticationResultEnum.MFA_FAILURE
        if s in ("LOCKED", "LOCKOUT", "ACCOUNT_LOCKED"):
            return AuthenticationResultEnum.LOCKED
        if s in ("DENIED", "BLOCKED", "IP_BLOCKED"):
            return AuthenticationResultEnum.DENIED
        return AuthenticationResultEnum.UNKNOWN

    def _parse_auth_method(self, raw: Any) -> AuthMethodEnum:
        s = str(raw or "").upper().strip()
        if "PASS" in s:
            return AuthMethodEnum.PASSWORD
        if "TOKEN" in s:
            return AuthMethodEnum.TOKEN
        if "SSO" in s or "SAML" in s or "OIDC" in s:
            return AuthMethodEnum.SSO
        if "CERT" in s or "PKI" in s:
            return AuthMethodEnum.CERTIFICATE
        if "KEY" in s:
            return AuthMethodEnum.API_KEY
        if "BIO" in s or "TOUCH" in s or "FACE" in s:
            return AuthMethodEnum.BIOMETRIC
        return AuthMethodEnum.UNKNOWN

    def _parse_mfa_method(self, raw: Any) -> MFAMethodEnum:
        s = str(raw or "").upper().strip()
        if "TOTP" in s or "AUTH_APP" in s or "AUTHENTICATOR" in s:
            return MFAMethodEnum.TOTP
        if "PUSH" in s:
            return MFAMethodEnum.PUSH
        if "SMS" in s:
            return MFAMethodEnum.SMS
        if "EMAIL" in s:
            return MFAMethodEnum.EMAIL
        if "FIDO" in s or "WEBAUTHN" in s:
            return MFAMethodEnum.FIDO2
        if "HARDWARE" in s or "YUBI" in s:
            return MFAMethodEnum.HARDWARE_KEY
        if not s or s in ("NONE", "FALSE", "0"):
            return MFAMethodEnum.NONE
        return MFAMethodEnum.OTHER

    def _parse_failure_reason(self, raw: Any) -> Optional[FailureReasonEnum]:
        s = str(raw or "").upper().strip()
        if not s:
            return None
        if "INVALID" in s or "BAD_PASSWORD" in s or "WRONG_PASSWORD" in s:
            return FailureReasonEnum.INVALID_CREDENTIALS
        if "NOT_FOUND" in s or "UNKNOWN_USER" in s:
            return FailureReasonEnum.USER_NOT_FOUND
        if "LOCK" in s:
            return FailureReasonEnum.ACCOUNT_LOCKED
        if "DISABLE" in s:
            return FailureReasonEnum.ACCOUNT_DISABLED
        if "EXPIRE" in s:
            return FailureReasonEnum.PASSWORD_EXPIRED
        if "MFA" in s and "REJECT" in s:
            return FailureReasonEnum.MFA_REJECTED
        if "MFA" in s and "TIMEOUT" in s:
            return FailureReasonEnum.MFA_TIMEOUT
        if "IP" in s and "BLOCK" in s:
            return FailureReasonEnum.IP_BLOCKED
        if "DEVICE" in s:
            return FailureReasonEnum.DEVICE_UNTRUSTED
        return FailureReasonEnum.OTHER

    def _parse_user_agent(self, ua: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
        if not ua:
            return None, None
        s = ua.lower()

        # Platform
        platform = None
        if "windows" in s:
            platform = "Windows"
        elif "macintosh" in s or "mac os" in s:
            platform = "macOS"
        elif "iphone" in s or "ipad" in s:
            platform = "iOS"
        elif "android" in s:
            platform = "Android"
        elif "linux" in s:
            platform = "Linux"

        # Browser
        browser = None
        if "edg/" in s:
            browser = "Edge"
        elif "chrome/" in s and "edg/" not in s:
            browser = "Chrome"
        elif "firefox/" in s:
            browser = "Firefox"
        elif "safari/" in s and "chrome/" not in s:
            browser = "Safari"
        elif "curl" in s:
            browser = "curl"
        elif "postman" in s:
            browser = "Postman"
        elif "python" in s:
            browser = "Python-Client"

        return platform, browser


class OktaAuthAdapter(BaseAuthAdapter):
    """
    Adapter for Okta System Log JSON events.
    """
    provider_name: str = "okta"
    version: str = "1.0.0"

    def can_handle(self, raw_event: Any) -> bool:
        if not isinstance(raw_event, dict):
            return False
        if str(raw_event.get("provider", "")).lower() == "okta":
            return True
        return (
            ("actor" in raw_event and isinstance(raw_event.get("actor"), dict) and ("alternateId" in raw_event["actor"] or "displayName" in raw_event["actor"])) or
            ("outcome" in raw_event and isinstance(raw_event.get("outcome"), dict) and "result" in raw_event["outcome"]) or
            "eventType" in raw_event
        )

    def normalize(self, raw_event: Any) -> NormalizedAuthEvent:
        d = SecretRedactor.redact_dict(dict(raw_event))
        actor = d.get("actor") if isinstance(d.get("actor"), dict) else {}
        outcome = d.get("outcome") if isinstance(d.get("outcome"), dict) else {}
        client = d.get("client") if isinstance(d.get("client"), dict) else {}
        geographical_context = client.get("geographicalContext") if isinstance(client.get("geographicalContext"), dict) else {}

        account_id = str(actor.get("alternateId") or actor.get("displayName") or d.get("user") or "unknown").strip().lower()
        source_ip = str(client.get("ipAddress") or d.get("ip") or "127.0.0.1").strip()
        user_agent = client.get("userAgent", {}).get("rawUserAgent") if isinstance(client.get("userAgent"), dict) else None

        # Outcome
        res_str = str(outcome.get("result") or "").upper()
        if res_str == "SUCCESS":
            result = AuthenticationResultEnum.SUCCESS
        elif res_str == "FAILURE":
            result = AuthenticationResultEnum.FAILURE
        elif res_str == "CHALLENGE":
            result = AuthenticationResultEnum.CHALLENGE
        elif res_str == "DENY":
            result = AuthenticationResultEnum.DENIED
        else:
            result = AuthenticationResultEnum.UNKNOWN

        # Timestamp
        published = d.get("published") or d.get("timestamp")
        gen = GenericAuthAdapter()
        ts = gen._parse_timestamp(published)
        plat, brow = gen._parse_user_agent(user_agent)

        return NormalizedAuthEvent(
            id=str(d.get("uuid") or d.get("id") or str(uuid.uuid4())),
            timestamp=ts,
            account_id=account_id,
            username=actor.get("displayName") or account_id,
            source_ip=source_ip,
            destination_service=d.get("target", [{}])[0].get("displayName") if isinstance(d.get("target"), list) and d.get("target") else None,
            device_id=client.get("device"),
            user_agent=user_agent,
            client_platform=plat,
            client_browser=brow,
            result=result,
            failure_reason=FailureReasonEnum.INVALID_CREDENTIALS if result == AuthenticationResultEnum.FAILURE else None,
            failure_detail=outcome.get("reason"),
            location_city=geographical_context.get("city"),
            location_country=geographical_context.get("country"),
            latitude=geographical_context.get("geolocation", {}).get("lat") if isinstance(geographical_context.get("geolocation"), dict) else None,
            longitude=geographical_context.get("geolocation", {}).get("lon") if isinstance(geographical_context.get("geolocation"), dict) else None,
            provider=self.provider_name,
            metadata=d,
        )


class EntraIdAuthAdapter(BaseAuthAdapter):
    """
    Adapter for Microsoft Entra ID (Azure AD) sign-in logs.
    """
    provider_name: str = "entra_id"
    version: str = "1.0.0"

    def can_handle(self, raw_event: Any) -> bool:
        if not isinstance(raw_event, dict):
            return False
        return (
            "userPrincipalName" in raw_event or
            "ipAddress" in raw_event and "status" in raw_event and isinstance(raw_event.get("status"), dict) or
            str(raw_event.get("provider", "")).lower() in ("entra_id", "azure_ad")
        )

    def normalize(self, raw_event: Any) -> NormalizedAuthEvent:
        d = SecretRedactor.redact_dict(dict(raw_event))
        status_info = d.get("status") if isinstance(d.get("status"), dict) else {}
        error_code = status_info.get("errorCode", 0)
        device_detail = d.get("deviceDetail") if isinstance(d.get("deviceDetail"), dict) else {}
        location_info = d.get("location") if isinstance(d.get("location"), dict) else {}

        if error_code == 0:
            result = AuthenticationResultEnum.SUCCESS
            failure_reason = None
        elif error_code in (50053, 50057):  # Account is locked or disabled
            result = AuthenticationResultEnum.LOCKED
            failure_reason = FailureReasonEnum.ACCOUNT_LOCKED
        elif error_code in (50126, 50034):  # Invalid credentials / User does not exist
            result = AuthenticationResultEnum.FAILURE
            failure_reason = FailureReasonEnum.INVALID_CREDENTIALS
        elif error_code in (50074, 50076):  # MFA required
            result = AuthenticationResultEnum.MFA_REQUIRED
            failure_reason = None
        else:
            result = AuthenticationResultEnum.FAILURE
            failure_reason = FailureReasonEnum.OTHER

        gen = GenericAuthAdapter()
        ts = gen._parse_timestamp(d.get("createdDateTime") or d.get("timestamp"))
        user_agent = d.get("userAgent")
        plat, brow = gen._parse_user_agent(user_agent)

        geo = location_info.get("geoCoordinates") if isinstance(location_info.get("geoCoordinates"), dict) else {}

        return NormalizedAuthEvent(
            id=str(d.get("id") or str(uuid.uuid4())),
            timestamp=ts,
            account_id=str(d.get("userPrincipalName") or d.get("user") or "unknown").strip().lower(),
            username=d.get("userDisplayName") or d.get("userPrincipalName"),
            user_id=d.get("userId"),
            source_ip=str(d.get("ipAddress") or "127.0.0.1"),
            destination_service=d.get("appDisplayName"),
            device_id=device_detail.get("deviceId"),
            device_name=device_detail.get("displayName"),
            user_agent=user_agent,
            client_platform=plat or device_detail.get("operatingSystem"),
            client_browser=brow or device_detail.get("browser"),
            result=result,
            failure_reason=failure_reason,
            failure_detail=status_info.get("failureReason"),
            location_city=location_info.get("city"),
            location_country=location_info.get("countryOrRegion"),
            latitude=geo.get("latitude"),
            longitude=geo.get("longitude"),
            provider=self.provider_name,
            metadata=d,
        )


class GoogleWorkspaceAuthAdapter(BaseAuthAdapter):
    """
    Adapter for Google Workspace login audit events.
    """
    provider_name: str = "google_workspace"
    version: str = "1.0.0"

    def can_handle(self, raw_event: Any) -> bool:
        if not isinstance(raw_event, dict):
            return False
        return (
            str(raw_event.get("provider", "")).lower() == "google_workspace" or
            ("events" in raw_event and isinstance(raw_event.get("events"), list) and "actor" in raw_event)
        )

    def normalize(self, raw_event: Any) -> NormalizedAuthEvent:
        d = SecretRedactor.redact_dict(dict(raw_event))
        actor = d.get("actor") if isinstance(d.get("actor"), dict) else {}
        events_list = d.get("events") if isinstance(d.get("events"), list) else [{}]
        first_event = events_list[0] if events_list else {}
        event_name = str(first_event.get("name") or d.get("name") or "").lower()

        if "login_success" in event_name or "success" in event_name:
            result = AuthenticationResultEnum.SUCCESS
            reason = None
        elif "login_failure" in event_name or "failure" in event_name:
            result = AuthenticationResultEnum.FAILURE
            reason = FailureReasonEnum.INVALID_CREDENTIALS
        else:
            result = AuthenticationResultEnum.UNKNOWN
            reason = None

        gen = GenericAuthAdapter()
        ts = gen._parse_timestamp(d.get("id", {}).get("time") if isinstance(d.get("id"), dict) else d.get("timestamp"))

        return NormalizedAuthEvent(
            id=str(d.get("id", {}).get("uniqueQualifier") if isinstance(d.get("id"), dict) else str(uuid.uuid4())),
            timestamp=ts,
            account_id=str(actor.get("email") or d.get("user") or "unknown").strip().lower(),
            username=actor.get("email"),
            source_ip=str(d.get("ipAddress") or "127.0.0.1"),
            result=result,
            failure_reason=reason,
            provider=self.provider_name,
            metadata=d,
        )


class LinuxAuthAdapter(BaseAuthAdapter):
    """
    Adapter for standard Linux SSH/Syslog authentication lines.
    """
    provider_name: str = "linux_auth"
    version: str = "1.0.0"

    # Regex for standard Linux auth.log / secure log formats
    FAILED_PATTERN = re.compile(
        r'Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)',
        re.IGNORECASE
    )
    ACCEPTED_PATTERN = re.compile(
        r'Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)',
        re.IGNORECASE
    )

    def can_handle(self, raw_event: Any) -> bool:
        if isinstance(raw_event, str):
            return "sshd" in raw_event or bool(self.FAILED_PATTERN.search(raw_event)) or bool(self.ACCEPTED_PATTERN.search(raw_event))
        if isinstance(raw_event, dict):
            raw_msg = str(raw_event.get("message") or raw_event.get("line") or "")
            return "sshd" in raw_msg or str(raw_event.get("provider", "")).lower() == "linux_auth"
        return False

    def normalize(self, raw_event: Any) -> NormalizedAuthEvent:
        line = raw_event if isinstance(raw_event, str) else str(raw_event.get("message") or raw_event.get("line") or "")
        line = SecretRedactor.redact_text(line)

        fail_match = self.FAILED_PATTERN.search(line)
        accept_match = self.ACCEPTED_PATTERN.search(line)

        if accept_match:
            user = accept_match.group("user")
            ip = accept_match.group("ip")
            port = int(accept_match.group("port"))
            result = AuthenticationResultEnum.SUCCESS
            reason = None
            method = AuthMethodEnum.CERTIFICATE if "publickey" in line else AuthMethodEnum.PASSWORD
        elif fail_match:
            user = fail_match.group("user")
            ip = fail_match.group("ip")
            port = int(fail_match.group("port"))
            result = AuthenticationResultEnum.FAILURE
            reason = FailureReasonEnum.INVALID_CREDENTIALS
            method = AuthMethodEnum.PASSWORD
        else:
            user = "unknown"
            ip = "127.0.0.1"
            port = None
            result = AuthenticationResultEnum.UNKNOWN
            reason = None
            method = AuthMethodEnum.UNKNOWN

        gen = GenericAuthAdapter()
        ts = gen._parse_timestamp(raw_event.get("timestamp") if isinstance(raw_event, dict) else None)

        return NormalizedAuthEvent(
            id=str(uuid.uuid4()),
            timestamp=ts,
            account_id=user.strip().lower(),
            username=user.strip(),
            source_ip=ip.strip(),
            source_port=port,
            destination_service="ssh",
            authentication_method=method,
            result=result,
            failure_reason=reason,
            provider=self.provider_name,
            metadata={"raw_line": line},
        )


class AdapterRegistry:
    """
    Central dispatcher selecting appropriate adapter to normalize incoming authentication events.
    """
    def __init__(self) -> None:
        self.adapters: List[BaseAuthAdapter] = [
            OktaAuthAdapter(),
            EntraIdAuthAdapter(),
            GoogleWorkspaceAuthAdapter(),
            LinuxAuthAdapter(),
            GenericAuthAdapter(),  # Fallback
        ]

    def normalize(self, raw: Any, hint: Optional[str] = None) -> NormalizedAuthEvent:
        if hint:
            hint_lower = hint.lower()
            for a in self.adapters:
                if a.provider_name == hint_lower and a.can_handle(raw):
                    return a.normalize(raw)

        for a in self.adapters:
            if a.can_handle(raw):
                return a.normalize(raw)

        # Final default fallback
        return GenericAuthAdapter().normalize(raw if isinstance(raw, dict) else {"raw": str(raw)})


# Global Adapter Registry instance
global_adapter_registry = AdapterRegistry()


# ============================================================================
# DETECTION ENGINES
# ============================================================================

class FailureAnalysisEngine:
    """
    Analyzes repeated authentication failures and account lockouts.
    """
    @staticmethod
    def analyze(
        events: List[NormalizedAuthEvent],
        config: AuthConfigResponse,
    ) -> List[AuthenticationFindingItem]:
        findings: List[AuthenticationFindingItem] = []

        # Group failures by account
        account_failures = defaultdict(list)
        for ev in events:
            if ev.result in (AuthenticationResultEnum.FAILURE, AuthenticationResultEnum.DENIED):
                account_failures[ev.account_id].append(ev)

        # Check repeated failures per account
        for account_id, fails in account_failures.items():
            if len(fails) >= config.brute_force_failure_threshold:
                # Check time window between first and last in sequence
                fails_sorted = sorted(fails, key=lambda x: x.timestamp)
                duration_sec = (fails_sorted[-1].timestamp - fails_sorted[0].timestamp).total_seconds()
                if duration_sec <= config.brute_force_window_seconds:
                    unique_ips = sorted(list(set(f.source_ip for f in fails_sorted)))
                    finding = AuthenticationFindingItem(
                        finding_type="REPEATED_LOGIN_FAILURES",
                        title=f"Repeated login failures detected for {account_id}",
                        description=(
                            f"Account '{account_id}' experienced {len(fails_sorted)} authentication failures "
                            f"within {int(duration_sec)}s across {len(unique_ips)} source IP(s). "
                            "This pattern indicates repeated incorrect credential attempts."
                        ),
                        severity=SeverityEnum.MEDIUM,
                        confidence=0.90,
                        risk_contribution=35.0,
                        method="DETERMINISTIC",
                        rule_id="AUTH_RULE_REPEATED_FAILURES",
                        category=ATOCategoryEnum.CREDENTIAL_ATTACK,
                        target_account=account_id,
                        mitre_attack_ids=["T1110"],
                        evidence_items=[
                            FindingEvidenceItem(
                                key="failure_count",
                                value=str(len(fails_sorted)),
                                source="FailureAnalysisEngine",
                                timestamp=fails_sorted[-1].timestamp,
                            ),
                            FindingEvidenceItem(
                                key="time_window_seconds",
                                value=str(int(duration_sec)),
                                source="FailureAnalysisEngine",
                                timestamp=fails_sorted[-1].timestamp,
                            ),
                            FindingEvidenceItem(
                                key="source_ips",
                                value=",".join(unique_ips),
                                source="FailureAnalysisEngine",
                                timestamp=fails_sorted[-1].timestamp,
                            ),
                        ],
                    )
                    findings.append(finding)

        # Check account lockout events
        for ev in events:
            if ev.result == AuthenticationResultEnum.LOCKED or ev.failure_reason == FailureReasonEnum.ACCOUNT_LOCKED:
                findings.append(
                    AuthenticationFindingItem(
                        finding_type="ACCOUNT_LOCKED",
                        title=f"Account locked defensive state observed for {ev.account_id}",
                        description=(
                            f"System defensive lockout triggered for account '{ev.account_id}' from source IP {ev.source_ip}. "
                            "Observed defensive state indicates login attempts exceeded provider policy thresholds."
                        ),
                        severity=SeverityEnum.MEDIUM,
                        confidence=1.0,
                        risk_contribution=25.0,
                        method="DETERMINISTIC",
                        rule_id="AUTH_RULE_ACCOUNT_LOCKED",
                        category=ATOCategoryEnum.CREDENTIAL_ATTACK,
                        target_account=ev.account_id,
                        mitre_attack_ids=["T1110"],
                        evidence_items=[
                            FindingEvidenceItem(
                                key="source_ip",
                                value=ev.source_ip,
                                source="FailureAnalysisEngine",
                                timestamp=ev.timestamp,
                            ),
                            FindingEvidenceItem(
                                key="lockout_timestamp",
                                value=ev.timestamp.isoformat(),
                                source="FailureAnalysisEngine",
                                timestamp=ev.timestamp,
                            ),
                        ],
                    )
                )

        return findings


class BruteForceDetector:
    """
    Detects targeted brute-force attacks: ONE account attacked by MANY failures
    from one or few source IPs in a short time window.
    """
    @staticmethod
    def analyze(
        events: List[NormalizedAuthEvent],
        config: AuthConfigResponse,
    ) -> List[AuthenticationFindingItem]:
        findings: List[AuthenticationFindingItem] = []

        # Group failures by account
        account_fails = defaultdict(list)
        for ev in events:
            if ev.result in (AuthenticationResultEnum.FAILURE, AuthenticationResultEnum.DENIED):
                account_fails[ev.account_id].append(ev)

        for account_id, fails in account_fails.items():
            if len(fails) < config.brute_force_failure_threshold:
                continue

            fails_sorted = sorted(fails, key=lambda x: x.timestamp)
            first_ts = fails_sorted[0].timestamp
            last_ts = fails_sorted[-1].timestamp
            duration_sec = max(1.0, (last_ts - first_ts).total_seconds())

            if duration_sec <= config.brute_force_window_seconds:
                unique_ips = set(f.source_ip for f in fails_sorted)
                # Targeted brute force typically originates from a concentrated set of IPs (1-3)
                if len(unique_ips) <= 3:
                    rate_per_min = (len(fails_sorted) / duration_sec) * 60.0
                    findings.append(
                        AuthenticationFindingItem(
                            finding_type="BRUTE_FORCE_PATTERN",
                            title=f"Brute-force credential guessing pattern targeted at {account_id}",
                            description=(
                                f"Observed concentrated credential guessing against account '{account_id}': "
                                f"{len(fails_sorted)} failures from {len(unique_ips)} IP(s) within {int(duration_sec)}s "
                                f"(rate: {rate_per_min:.1f} attempts/min). "
                                "This pattern matches deterministic password guessing activity."
                            ),
                            severity=SeverityEnum.HIGH,
                            confidence=0.92,
                            risk_contribution=60.0,
                            method="HEURISTIC",
                            rule_id="AUTH_RULE_BRUTE_FORCE",
                            category=ATOCategoryEnum.CREDENTIAL_ATTACK,
                            target_account=account_id,
                            mitre_attack_ids=["T1110.001"],
                            evidence_items=[
                                FindingEvidenceItem(key="target_account", value=account_id, source="BruteForceDetector", timestamp=last_ts),
                                FindingEvidenceItem(key="failure_count", value=str(len(fails_sorted)), source="BruteForceDetector", timestamp=last_ts),
                                FindingEvidenceItem(key="time_window_seconds", value=str(int(duration_sec)), source="BruteForceDetector", timestamp=last_ts),
                                FindingEvidenceItem(key="source_ips", value=",".join(sorted(unique_ips)), source="BruteForceDetector", timestamp=last_ts),
                                FindingEvidenceItem(key="attempt_rate_per_min", value=f"{rate_per_min:.2f}", source="BruteForceDetector", timestamp=last_ts),
                            ],
                        )
                    )

        return findings


class PasswordSprayDetector:
    """
    Detects password spraying: ONE source IP targeting MANY distinct accounts
    with relatively few attempts per account to avoid account lockout.
    """
    @staticmethod
    def analyze(
        events: List[NormalizedAuthEvent],
        config: AuthConfigResponse,
    ) -> List[AuthenticationFindingItem]:
        findings: List[AuthenticationFindingItem] = []

        # Group attempts by source IP
        ip_attempts = defaultdict(list)
        for ev in events:
            ip_attempts[ev.source_ip].append(ev)

        for ip, attempts in ip_attempts.items():
            if len(attempts) < config.password_spray_account_threshold:
                continue

            attempts_sorted = sorted(attempts, key=lambda x: x.timestamp)
            first_ts = attempts_sorted[0].timestamp
            last_ts = attempts_sorted[-1].timestamp
            duration_sec = max(1.0, (last_ts - first_ts).total_seconds())

            if duration_sec <= config.password_spray_window_seconds:
                # Count attempts per distinct account
                account_counts = defaultdict(int)
                for a in attempts_sorted:
                    account_counts[a.account_id] += 1

                distinct_accounts = len(account_counts)
                max_per_account = max(account_counts.values()) if account_counts else 0

                # Spray signature: High distinct accounts, low attempts per account
                if (
                    distinct_accounts >= config.password_spray_account_threshold and
                    max_per_account <= config.password_spray_max_per_account
                ):
                    findings.append(
                        AuthenticationFindingItem(
                            finding_type="PASSWORD_SPRAY_PATTERN",
                            title=f"Horizontal password-spray pattern detected from IP {ip}",
                            description=(
                                f"Source IP {ip} attempted authentication across {distinct_accounts} distinct accounts "
                                f"with at most {max_per_account} attempt(s) per account within {int(duration_sec)}s. "
                                "This low-and-slow horizontal distribution is a hallmark of password spraying to evade lockouts."
                            ),
                            severity=SeverityEnum.HIGH,
                            confidence=0.94,
                            risk_contribution=65.0,
                            method="HEURISTIC",
                            rule_id="AUTH_RULE_PASSWORD_SPRAY",
                            category=ATOCategoryEnum.CREDENTIAL_ATTACK,
                            mitre_attack_ids=["T1110.003"],
                            evidence_items=[
                                FindingEvidenceItem(key="source_ip", value=ip, source="PasswordSprayDetector", timestamp=last_ts),
                                FindingEvidenceItem(key="distinct_accounts_count", value=str(distinct_accounts), source="PasswordSprayDetector", timestamp=last_ts),
                                FindingEvidenceItem(key="max_attempts_per_account", value=str(max_per_account), source="PasswordSprayDetector", timestamp=last_ts),
                                FindingEvidenceItem(key="time_window_seconds", value=str(int(duration_sec)), source="PasswordSprayDetector", timestamp=last_ts),
                                FindingEvidenceItem(key="targeted_accounts_sample", value=",".join(list(account_counts.keys())[:10]), source="PasswordSprayDetector", timestamp=last_ts),
                            ],
                        )
                    )

        return findings


class CredentialStuffingDetector:
    """
    Detects credential stuffing: High-volume attempts across many accounts,
    often from distributed sources, with mixed failures and occasional successes.
    """
    @staticmethod
    def analyze(
        events: List[NormalizedAuthEvent],
        config: AuthConfigResponse,
    ) -> List[AuthenticationFindingItem]:
        findings: List[AuthenticationFindingItem] = []

        if len(events) < config.credential_stuffing_account_threshold:
            return findings

        events_sorted = sorted(events, key=lambda x: x.timestamp)
        first_ts = events_sorted[0].timestamp
        last_ts = events_sorted[-1].timestamp
        duration_sec = max(1.0, (last_ts - first_ts).total_seconds())

        if duration_sec <= config.credential_stuffing_window_seconds:
            distinct_accounts = len(set(e.account_id for e in events_sorted))
            unique_ips = len(set(e.source_ip for e in events_sorted))
            failures = sum(1 for e in events_sorted if e.result in (AuthenticationResultEnum.FAILURE, AuthenticationResultEnum.DENIED))
            successes = sum(1 for e in events_sorted if e.result == AuthenticationResultEnum.SUCCESS)

            # High account breadth with majority failures indicates credential stuffing list execution
            if distinct_accounts >= config.credential_stuffing_account_threshold and failures >= (0.7 * len(events_sorted)):
                findings.append(
                    AuthenticationFindingItem(
                        finding_type="CREDENTIAL_STUFFING_SUSPECTED",
                        title=f"Distributed credential-stuffing volume observed across {distinct_accounts} accounts",
                        description=(
                            f"Observed automated credential testing volume across {distinct_accounts} accounts "
                            f"from {unique_ips} IP(s) within {int(duration_sec)}s ({failures} failures, {successes} successes). "
                            "This pattern is consistent with automated playback of compromised credential dumps."
                        ),
                        severity=SeverityEnum.HIGH,
                        confidence=0.85,
                        risk_contribution=55.0,
                        method="STATISTICAL",
                        rule_id="AUTH_RULE_CREDENTIAL_STUFFING",
                        category=ATOCategoryEnum.CREDENTIAL_ATTACK,
                        mitre_attack_ids=["T1110.004"],
                        evidence_items=[
                            FindingEvidenceItem(key="distinct_accounts_count", value=str(distinct_accounts), source="CredentialStuffingDetector", timestamp=last_ts),
                            FindingEvidenceItem(key="source_ip_count", value=str(unique_ips), source="CredentialStuffingDetector", timestamp=last_ts),
                            FindingEvidenceItem(key="failure_count", value=str(failures), source="CredentialStuffingDetector", timestamp=last_ts),
                            FindingEvidenceItem(key="success_count", value=str(successes), source="CredentialStuffingDetector", timestamp=last_ts),
                        ],
                    )
                )

        return findings


class SuccessAfterFailuresDetector:
    """
    Detects sequence: FAIL -> FAIL -> FAIL -> SUCCESS for the same account.
    """
    @staticmethod
    def analyze(
        events: List[NormalizedAuthEvent],
        config: AuthConfigResponse,
    ) -> List[AuthenticationFindingItem]:
        findings: List[AuthenticationFindingItem] = []

        # Group by account in chronological order
        account_events = defaultdict(list)
        for ev in sorted(events, key=lambda x: x.timestamp):
            account_events[ev.account_id].append(ev)

        for account_id, ev_list in account_events.items():
            consecutive_failures: List[NormalizedAuthEvent] = []
            for ev in ev_list:
                if ev.result in (AuthenticationResultEnum.FAILURE, AuthenticationResultEnum.DENIED):
                    consecutive_failures.append(ev)
                elif ev.result == AuthenticationResultEnum.SUCCESS:
                    if len(consecutive_failures) >= config.success_after_failures_min_failures:
                        first_fail = consecutive_failures[0]
                        elapsed_sec = (ev.timestamp - first_fail.timestamp).total_seconds()
                        if elapsed_sec <= config.success_after_failures_window_seconds:
                            fail_ips = sorted(list(set(f.source_ip for f in consecutive_failures)))
                            findings.append(
                                AuthenticationFindingItem(
                                    finding_type="SUCCESS_AFTER_REPEATED_FAILURES",
                                    title=f"Authentication succeeded following {len(consecutive_failures)} consecutive failures for {account_id}",
                                    description=(
                                        f"Account '{account_id}' authenticated successfully from {ev.source_ip} "
                                        f"immediately after {len(consecutive_failures)} consecutive failures "
                                        f"within {int(elapsed_sec)}s. "
                                        "Interpretation: This pattern may indicate successful credential guessing, password recovery, "
                                        "or an attacker eventually entering the correct password. It does NOT independently prove compromise."
                                    ),
                                    severity=SeverityEnum.HIGH,
                                    confidence=0.88,
                                    risk_contribution=45.0,
                                    method="DETERMINISTIC",
                                    rule_id="AUTH_RULE_SUCCESS_AFTER_FAILURES",
                                    category=ATOCategoryEnum.CREDENTIAL_ATTACK,
                                    target_account=account_id,
                                    mitre_attack_ids=["T1110"],
                                    evidence_items=[
                                        FindingEvidenceItem(key="failure_count_prior", value=str(len(consecutive_failures)), source="SuccessAfterFailuresDetector", timestamp=ev.timestamp),
                                        FindingEvidenceItem(key="success_ip", value=ev.source_ip, source="SuccessAfterFailuresDetector", timestamp=ev.timestamp),
                                        FindingEvidenceItem(key="prior_failure_ips", value=",".join(fail_ips), source="SuccessAfterFailuresDetector", timestamp=ev.timestamp),
                                        FindingEvidenceItem(key="elapsed_time_seconds", value=str(int(elapsed_sec)), source="SuccessAfterFailuresDetector", timestamp=ev.timestamp),
                                    ],
                                )
                            )
                    consecutive_failures = []
                else:
                    # Non-auth outcomes like CHALLENGE don't reset failures
                    pass

        return findings


class DeviceAnalysisEngine:
    """
    Detects unfamiliar devices or substantial user-agent profile changes compared to history.
    Enforces minimum history requirements to prevent false positives on new accounts.
    """
    @staticmethod
    def analyze(
        events: List[NormalizedAuthEvent],
        profiles: Dict[str, AccountSecurityProfile],
        config: AuthConfigResponse,
    ) -> List[AuthenticationFindingItem]:
        findings: List[AuthenticationFindingItem] = []

        for ev in events:
            if ev.result != AuthenticationResultEnum.SUCCESS:
                continue

            profile = profiles.get(ev.account_id)
            if not profile or profile.total_successful_logins < config.min_history_events_device:
                # Insufficient history - do not flag
                continue

            # 1. New Device Identifier
            device_id = ev.device_id or ev.device_name
            if device_id and profile.known_devices and device_id not in profile.known_devices:
                findings.append(
                    AuthenticationFindingItem(
                        finding_type="NEW_DEVICE",
                        title=f"Authentication from historically unobserved device for {ev.account_id}",
                        description=(
                            f"Account '{ev.account_id}' authenticated using device '{device_id}', which has not been "
                            f"previously observed across {profile.total_successful_logins} historical logins. "
                            "Confidence reflects certainty that device is historically unseen, NOT certainty of compromise."
                        ),
                        severity=SeverityEnum.LOW,
                        confidence=0.85,
                        risk_contribution=20.0,
                        method="DETERMINISTIC",
                        rule_id="AUTH_RULE_NEW_DEVICE",
                        category=ATOCategoryEnum.DEVICE_ANOMALY,
                        target_account=ev.account_id,
                        mitre_attack_ids=["T1078"],
                        evidence_items=[
                            FindingEvidenceItem(key="observed_device", value=str(device_id), source="DeviceAnalysisEngine", timestamp=ev.timestamp),
                            FindingEvidenceItem(key="known_devices_count", value=str(len(profile.known_devices)), source="DeviceAnalysisEngine", timestamp=ev.timestamp),
                        ],
                    )
                )

            # 2. New Client Platform / Browser Profile
            client_profile = f"{ev.client_platform or 'Unknown'}/{ev.client_browser or 'Unknown'}"
            if (
                client_profile != "Unknown/Unknown" and
                profile.known_client_profiles and
                client_profile not in profile.known_client_profiles
            ):
                findings.append(
                    AuthenticationFindingItem(
                        finding_type="NEW_CLIENT_PROFILE",
                        title=f"New client platform/browser profile for {ev.account_id}",
                        description=(
                            f"Account '{ev.account_id}' authenticated using client profile '{client_profile}', which differs "
                            f"from established profiles {profile.known_client_profiles}."
                        ),
                        severity=SeverityEnum.LOW,
                        confidence=0.75,
                        risk_contribution=15.0,
                        method="DETERMINISTIC",
                        rule_id="AUTH_RULE_NEW_CLIENT_PROFILE",
                        category=ATOCategoryEnum.DEVICE_ANOMALY,
                        target_account=ev.account_id,
                        mitre_attack_ids=["T1078"],
                        evidence_items=[
                            FindingEvidenceItem(key="observed_profile", value=client_profile, source="DeviceAnalysisEngine", timestamp=ev.timestamp),
                            FindingEvidenceItem(key="known_profiles", value=",".join(profile.known_client_profiles), source="DeviceAnalysisEngine", timestamp=ev.timestamp),
                        ],
                    )
                )

        return findings


class LocationAnalysisEngine:
    """
    Evaluates source IP novelty, unusual geographic regions, and rapid location change
    (impossible travel velocity) between consecutive successful authentications.
    """
    @staticmethod
    def haversine_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """Calculate great-circle distance in kilometers using Haversine formula."""
        r = 6371.0  # Earth radius in km
        phi1 = math.radians(lat1)
        phi2 = math.radians(lat2)
        delta_phi = math.radians(lat2 - lat1)
        delta_lambda = math.radians(lon2 - lon1)

        a = math.sin(delta_phi / 2.0) ** 2 + math.cos(phi1) * math.cos(phi2) * (math.sin(delta_lambda / 2.0) ** 2)
        c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
        return r * c

    @classmethod
    def analyze(
        cls,
        events: List[NormalizedAuthEvent],
        profiles: Dict[str, AccountSecurityProfile],
        config: AuthConfigResponse,
    ) -> List[AuthenticationFindingItem]:
        findings: List[AuthenticationFindingItem] = []

        # Sort events chronologically
        events_sorted = sorted(events, key=lambda x: x.timestamp)

        # 1. Historical Comparison: New IP and Unusual Location
        for ev in events_sorted:
            if ev.result != AuthenticationResultEnum.SUCCESS:
                continue

            profile = profiles.get(ev.account_id)
            if profile and profile.total_successful_logins >= config.min_history_events_ip:
                # Check New IP
                if profile.known_source_ips and ev.source_ip not in profile.known_source_ips:
                    findings.append(
                        AuthenticationFindingItem(
                            finding_type="NEW_SOURCE_IP",
                            title=f"Authentication from historically unobserved IP for {ev.account_id}",
                            description=(
                                f"Account '{ev.account_id}' authenticated from IP {ev.source_ip}, which has not been "
                                f"previously observed across {profile.total_successful_logins} historical logins. "
                                "New IP addresses occur routinely with DHCP, VPNs, mobile roaming, or travel."
                            ),
                            severity=SeverityEnum.LOW,
                            confidence=0.85,
                            risk_contribution=15.0,
                            method="DETERMINISTIC",
                            rule_id="AUTH_RULE_NEW_IP",
                            category=ATOCategoryEnum.SOURCE_ANOMALY,
                            target_account=ev.account_id,
                            mitre_attack_ids=["T1078"],
                            evidence_items=[
                                FindingEvidenceItem(key="source_ip", value=ev.source_ip, source="LocationAnalysisEngine", timestamp=ev.timestamp),
                                FindingEvidenceItem(key="known_ips_count", value=str(len(profile.known_source_ips)), source="LocationAnalysisEngine", timestamp=ev.timestamp),
                            ],
                        )
                    )

                # Check Unusual Country
                if ev.location_country and profile.known_countries and ev.location_country not in profile.known_countries:
                    findings.append(
                        AuthenticationFindingItem(
                            finding_type="UNUSUAL_LOGIN_LOCATION",
                            title=f"Login from unfamiliar geographic country for {ev.account_id}",
                            description=(
                                f"Account '{ev.account_id}' authenticated from {ev.location_country} ({ev.location_city or 'Unknown City'}), "
                                f"which is outside previously observed countries {profile.known_countries}."
                            ),
                            severity=SeverityEnum.MEDIUM,
                            confidence=0.80,
                            risk_contribution=25.0,
                            method="HEURISTIC",
                            rule_id="AUTH_RULE_UNUSUAL_LOCATION",
                            category=ATOCategoryEnum.LOCATION_ANOMALY,
                            target_account=ev.account_id,
                            mitre_attack_ids=["T1078"],
                            evidence_items=[
                                FindingEvidenceItem(key="observed_country", value=ev.location_country, source="LocationAnalysisEngine", timestamp=ev.timestamp),
                                FindingEvidenceItem(key="known_countries", value=",".join(profile.known_countries), source="LocationAnalysisEngine", timestamp=ev.timestamp),
                            ],
                        )
                    )

        # 2. Rapid Location Change (Impossible Travel) between consecutive successful logins
        account_successes = defaultdict(list)
        for ev in events_sorted:
            if ev.result == AuthenticationResultEnum.SUCCESS and ev.latitude is not None and ev.longitude is not None:
                account_successes[ev.account_id].append(ev)

        for account_id, succ_list in account_successes.items():
            for i in range(len(succ_list) - 1):
                ev1 = succ_list[i]
                ev2 = succ_list[i + 1]

                delta_sec = (ev2.timestamp - ev1.timestamp).total_seconds()
                if delta_sec <= 0:
                    continue

                dist_km = cls.haversine_distance(ev1.latitude, ev1.longitude, ev2.latitude, ev2.longitude)
                if dist_km >= config.impossible_travel_min_distance_km:
                    hours = delta_sec / 3600.0
                    speed_kmh = dist_km / max(hours, 0.001)

                    if speed_kmh > config.impossible_travel_speed_kmh:
                        loc1 = f"{ev1.location_city or 'Lat/Lon'}, {ev1.location_country or ''}".strip(", ")
                        loc2 = f"{ev2.location_city or 'Lat/Lon'}, {ev2.location_country or ''}".strip(", ")
                        findings.append(
                            AuthenticationFindingItem(
                                finding_type="RAPID_LOCATION_CHANGE",
                                title=f"Rapid location change detected for {account_id}",
                                description=(
                                    f"Account '{account_id}' authenticated from {loc1} (IP {ev1.source_ip}) and then from "
                                    f"{loc2} (IP {ev2.source_ip}) {int(delta_sec)}s later. "
                                    f"Estimated distance: {dist_km:.1f} km; implied velocity: {speed_kmh:.0f} km/h "
                                    f"(exceeds threshold of {config.impossible_travel_speed_kmh} km/h). "
                                    "Caveat: Rapid location change detected based on IP geolocation. IP geolocation is approximate; "
                                    "VPNs, corporate proxies, and mobile carrier gateways can produce misleading location jumps."
                                ),
                                severity=SeverityEnum.HIGH,
                                confidence=0.88,
                                risk_contribution=50.0,
                                method="HEURISTIC",
                                rule_id="AUTH_RULE_RAPID_LOCATION_CHANGE",
                                category=ATOCategoryEnum.LOCATION_ANOMALY,
                                target_account=account_id,
                                mitre_attack_ids=["T1078"],
                                evidence_items=[
                                    FindingEvidenceItem(key="origin_location", value=loc1, source="LocationAnalysisEngine", timestamp=ev1.timestamp),
                                    FindingEvidenceItem(key="origin_ip", value=ev1.source_ip, source="LocationAnalysisEngine", timestamp=ev1.timestamp),
                                    FindingEvidenceItem(key="destination_location", value=loc2, source="LocationAnalysisEngine", timestamp=ev2.timestamp),
                                    FindingEvidenceItem(key="destination_ip", value=ev2.source_ip, source="LocationAnalysisEngine", timestamp=ev2.timestamp),
                                    FindingEvidenceItem(key="distance_km", value=f"{dist_km:.2f}", source="LocationAnalysisEngine", timestamp=ev2.timestamp),
                                    FindingEvidenceItem(key="elapsed_seconds", value=str(int(delta_sec)), source="LocationAnalysisEngine", timestamp=ev2.timestamp),
                                    FindingEvidenceItem(key="implied_speed_kmh", value=f"{speed_kmh:.1f}", source="LocationAnalysisEngine", timestamp=ev2.timestamp),
                                ],
                            )
                        )

        return findings


class TemporalAnalysisEngine:
    """
    Lightweight analysis of login timing compared to historical hours.
    Only active when account has sufficient history.
    """
    @staticmethod
    def analyze(
        events: List[NormalizedAuthEvent],
        profiles: Dict[str, AccountSecurityProfile],
        config: AuthConfigResponse,
    ) -> List[AuthenticationFindingItem]:
        findings: List[AuthenticationFindingItem] = []

        for ev in events:
            if ev.result != AuthenticationResultEnum.SUCCESS:
                continue

            profile = profiles.get(ev.account_id)
            if not profile or profile.total_successful_logins < config.min_history_events_temporal:
                continue

            login_hour = ev.timestamp.hour
            if profile.typical_login_hours and login_hour not in profile.typical_login_hours:
                findings.append(
                    AuthenticationFindingItem(
                        finding_type="UNUSUAL_LOGIN_TIME",
                        title=f"Authentication outside typical observed hours for {ev.account_id}",
                        description=(
                            f"Account '{ev.account_id}' authenticated at {login_hour:02d}:00 UTC, which falls outside "
                            f"the typical observed activity hours ({sorted(profile.typical_login_hours)}). "
                            "Unusual hours may occur during on-call, overtime, or international travel."
                        ),
                        severity=SeverityEnum.LOW,
                        confidence=0.70,
                        risk_contribution=15.0,
                        method="STATISTICAL",
                        rule_id="AUTH_RULE_UNUSUAL_LOGIN_TIME",
                        category=ATOCategoryEnum.TEMPORAL_ANOMALY,
                        target_account=ev.account_id,
                        mitre_attack_ids=["T1078"],
                        evidence_items=[
                            FindingEvidenceItem(key="observed_hour_utc", value=f"{login_hour:02d}:00", source="TemporalAnalysisEngine", timestamp=ev.timestamp),
                            FindingEvidenceItem(key="typical_hours_utc", value=",".join(str(h) for h in sorted(profile.typical_login_hours)), source="TemporalAnalysisEngine", timestamp=ev.timestamp),
                        ],
                    )
                )

        return findings


class MFAAnalysisEngine:
    """
    Analyzes multi-factor authentication anomalies: repeated MFA rejections or MFA expectation violations.
    """
    @staticmethod
    def analyze(
        events: List[NormalizedAuthEvent],
        profiles: Dict[str, AccountSecurityProfile],
        config: AuthConfigResponse,
    ) -> List[AuthenticationFindingItem]:
        findings: List[AuthenticationFindingItem] = []

        # 1. Repeated MFA Failures
        account_mfa_fails = defaultdict(list)
        for ev in events:
            if ev.result == AuthenticationResultEnum.MFA_FAILURE or ev.failure_reason == FailureReasonEnum.MFA_REJECTED:
                account_mfa_fails[ev.account_id].append(ev)

        for account_id, fails in account_mfa_fails.items():
            if len(fails) >= config.mfa_failure_threshold:
                fails_sorted = sorted(fails, key=lambda x: x.timestamp)
                duration = (fails_sorted[-1].timestamp - fails_sorted[0].timestamp).total_seconds()
                findings.append(
                    AuthenticationFindingItem(
                        finding_type="REPEATED_MFA_FAILURES",
                        title=f"Repeated MFA challenge failures for {account_id}",
                        description=(
                            f"Account '{account_id}' experienced {len(fails_sorted)} MFA failures/rejections within {int(duration)}s. "
                            "This may indicate credential compromise where the attacker lacks the second factor, or MFA fatigue attempts."
                        ),
                        severity=SeverityEnum.HIGH,
                        confidence=0.88,
                        risk_contribution=45.0,
                        method="DETERMINISTIC",
                        rule_id="AUTH_RULE_MFA_FAILURES",
                        category=ATOCategoryEnum.MFA_ANOMALY,
                        target_account=account_id,
                        mitre_attack_ids=["T1621"],
                        evidence_items=[
                            FindingEvidenceItem(key="mfa_failure_count", value=str(len(fails_sorted)), source="MFAAnalysisEngine", timestamp=fails_sorted[-1].timestamp),
                            FindingEvidenceItem(key="source_ips", value=",".join(set(f.source_ip for f in fails_sorted)), source="MFAAnalysisEngine", timestamp=fails_sorted[-1].timestamp),
                        ],
                    )
                )

        # 2. MFA Expectation Anomaly (Account normally requires MFA, but logged in without MFA)
        for ev in events:
            if ev.result == AuthenticationResultEnum.SUCCESS:
                profile = profiles.get(ev.account_id)
                if profile and profile.mfa_always_used and ev.mfa_method == MFAMethodEnum.NONE:
                    findings.append(
                        AuthenticationFindingItem(
                            finding_type="MFA_EXPECTATION_ANOMALY",
                            title=f"Authentication without MFA for enforced account {ev.account_id}",
                            description=(
                                f"Account '{ev.account_id}' completed single-factor authentication without MFA, "
                                "despite historically always requiring MFA. This may represent policy bypass or fallback."
                            ),
                            severity=SeverityEnum.MEDIUM,
                            confidence=0.82,
                            risk_contribution=30.0,
                            method="HEURISTIC",
                            rule_id="AUTH_RULE_MFA_EXPECTATION",
                            category=ATOCategoryEnum.MFA_ANOMALY,
                            target_account=ev.account_id,
                            mitre_attack_ids=["T1556"],
                            evidence_items=[
                                FindingEvidenceItem(key="auth_method", value=ev.authentication_method.value, source="MFAAnalysisEngine", timestamp=ev.timestamp),
                                FindingEvidenceItem(key="source_ip", value=ev.source_ip, source="MFAAnalysisEngine", timestamp=ev.timestamp),
                            ],
                        )
                    )

        return findings


class SessionAnalysisEngine:
    """
    Analyzes session identifiers for concurrent anomalous usage or session hijacking signals.
    """
    @staticmethod
    def analyze(
        events: List[NormalizedAuthEvent],
    ) -> List[AuthenticationFindingItem]:
        findings: List[AuthenticationFindingItem] = []

        # Group events by session_id
        session_events = defaultdict(list)
        for ev in events:
            if ev.session_id:
                session_events[ev.session_id].append(ev)

        for session_id, ev_list in session_events.items():
            if len(ev_list) < 2:
                continue

            unique_ips = set(e.source_ip for e in ev_list)
            if len(unique_ips) > 1:
                # Same session observed from multiple distinct IPs
                ev_sorted = sorted(ev_list, key=lambda x: x.timestamp)
                duration = (ev_sorted[-1].timestamp - ev_sorted[0].timestamp).total_seconds()
                if duration <= 1800:  # within 30 minutes
                    target_account = ev_sorted[0].account_id
                    findings.append(
                        AuthenticationFindingItem(
                            finding_type="SUSPICIOUS_SESSION_ACTIVITY",
                            title=f"Concurrent session reuse across multiple IPs for session {session_id[:8]}...",
                            description=(
                                f"Session identifier '{session_id[:16]}' associated with account '{target_account}' "
                                f"was active from {len(unique_ips)} distinct IPs ({', '.join(sorted(unique_ips))}) "
                                f"within {int(duration)}s. This may indicate session token sharing or token theft."
                            ),
                            severity=SeverityEnum.HIGH,
                            confidence=0.86,
                            risk_contribution=50.0,
                            method="DETERMINISTIC",
                            rule_id="AUTH_RULE_SESSION_ACTIVITY",
                            category=ATOCategoryEnum.SESSION_ANOMALY,
                            target_account=target_account,
                            mitre_attack_ids=["T1539"],
                            evidence_items=[
                                FindingEvidenceItem(key="session_id", value=session_id, source="SessionAnalysisEngine", timestamp=ev_sorted[-1].timestamp),
                                FindingEvidenceItem(key="source_ips", value=",".join(sorted(unique_ips)), source="SessionAnalysisEngine", timestamp=ev_sorted[-1].timestamp),
                                FindingEvidenceItem(key="time_span_seconds", value=str(int(duration)), source="SessionAnalysisEngine", timestamp=ev_sorted[-1].timestamp),
                            ],
                        )
                    )

        return findings


class AccountTakeoverAggregator:
    """
    Multi-category evidence aggregator for Account Takeover (ATO) hypothesis synthesis.
    Requires independent corroboration before raising high-severity ATO conclusions.
    """
    @staticmethod
    def aggregate(
        findings: List[AuthenticationFindingItem],
        events: List[NormalizedAuthEvent],
        config: AuthConfigResponse,
    ) -> Tuple[bool, Optional[str], Optional[AuthenticationFindingItem]]:
        """
        Evaluates whether findings and events corroborate an ATO hypothesis.
        Returns: (ato_suspected, summary, synthesized_finding)
        """
        # Determine which accounts have successful logins
        successful_accounts = set(
            e.account_id for e in events if e.result == AuthenticationResultEnum.SUCCESS
        )

        # Group findings by target account
        account_findings = defaultdict(list)
        for f in findings:
            if f.target_account:
                account_findings[f.target_account].append(f)

        for account_id, f_list in account_findings.items():
            if account_id not in successful_accounts:
                # Without a successful login, credential attacks remain attempts rather than completed ATO
                continue

            # Group findings into independent categories
            categories_present: Set[ATOCategoryEnum] = set(f.category for f in f_list)

            # ATO requires at least config.ato_min_categories_threshold distinct categories
            # e.g. CREDENTIAL_ATTACK (success after failures) + DEVICE_ANOMALY (new device) + LOCATION_ANOMALY (rapid location change)
            if len(categories_present) >= config.ato_min_categories_threshold:
                cat_names = sorted([c.value for c in categories_present])
                finding_types = [f.finding_type for f in f_list]

                summary = (
                    f"Account Takeover suspected for account '{account_id}': corroborated across {len(categories_present)} "
                    f"independent analytical categories ({', '.join(cat_names)}). "
                    f"Key observations: {', '.join(finding_types)} with successful authentication."
                )

                ato_finding = AuthenticationFindingItem(
                    finding_type="ACCOUNT_TAKEOVER_SUSPECTED",
                    title=f"Account takeover suspected for {account_id}",
                    description=summary,
                    severity=SeverityEnum.CRITICAL if len(categories_present) >= 3 else SeverityEnum.HIGH,
                    confidence=0.92 if len(categories_present) >= 3 else 0.82,
                    risk_contribution=85.0,
                    method="HYBRID",
                    rule_id="ATO_COMPOSITE_AGGREGATOR",
                    category=ATOCategoryEnum.CREDENTIAL_ATTACK,
                    target_account=account_id,
                    mitre_attack_ids=["T1078", "T1110"],
                    evidence_items=[
                        FindingEvidenceItem(
                            key="corroborated_categories",
                            value=",".join(cat_names),
                            source="AccountTakeoverAggregator",
                        ),
                        FindingEvidenceItem(
                            key="supporting_findings",
                            value=",".join(finding_types),
                            source="AccountTakeoverAggregator",
                        ),
                    ],
                )
                return True, summary, ato_finding

        return False, None, None
