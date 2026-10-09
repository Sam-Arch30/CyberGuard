"""
Authentication and Session Telemetry Collector for Section 32 Endpoint Telemetry.
Collects login, logout, session lifecycle, and privilege change events.

STRICT PRIVACY GUARANTEE:
Never collects passwords, hashes, MFA secrets, cookies, or session tokens.
"""

import time
import logging
from typing import Dict, Any, List, Optional, Set
from datetime import datetime, timezone

from backend.schemas.endpoint_agent import (
    EndpointEventTypeEnum,
    EventPriorityEnum,
    CollectorCapabilityStateEnum
)
from backend.agent.collectors.base import BaseTelemetryCollector
from backend.agent.collectors.platform_adapters import get_platform_adapter, PlatformAdapter

logger = logging.getLogger("cyberguard.agent.collectors.auth")


class AuthenticationTelemetryCollector(BaseTelemetryCollector):
    """
    Collects authorized host authentication and session lifecycle observations.
    """

    def __init__(
        self,
        collector_id: str = "authentication_telemetry_collector",
        adapter: Optional[PlatformAdapter] = None
    ):
        self.adapter = adapter or get_platform_adapter()
        platform_name = self.adapter.get_platform_name()
        cap_state = CollectorCapabilityStateEnum.AVAILABLE if self.adapter.is_supported() else CollectorCapabilityStateEnum.UNAVAILABLE

        super().__init__(
            collector_id=collector_id,
            collector_type="AUTHENTICATION",
            platform=platform_name,
            version="1.0.0",
            capability_state=cap_state,
            supported_event_types=[EndpointEventTypeEnum.AUTHENTICATION.value],
            required_permissions="STANDARD_USER",
            resource_cost="LOW",
            privacy_class="HIGH"
        )

        self._active_sessions: Set[str] = set()
        self._manual_events: List[Dict[str, Any]] = []

    def record_auth_event(
        self,
        action: str,  # LOGIN_SUCCESS, LOGIN_FAILURE, LOGOUT, PRIVILEGE_CHANGE, LOCKOUT, MFA_EVENT
        username: str,
        auth_method: str = "PASSWORD",
        status: str = "SUCCESS",
        session_id: Optional[str] = None,
        source_ip: Optional[str] = None,
        terminal: Optional[str] = None
    ) -> None:
        """Records an authentication observation from OS PAM or event log hook."""
        self._manual_events.append({
            "action": action.upper(),
            "username": username.strip(),
            "auth_method": auth_method.upper(),
            "status": status.upper(),
            "session_id": session_id or "unknown",
            "source_ip": source_ip or "local",
            "terminal": terminal or "console"
        })

    def collect(self) -> List[Dict[str, Any]]:
        if not self.is_running or self.capability_state != CollectorCapabilityStateEnum.AVAILABLE:
            return []

        events = []
        now_dt = datetime.now(timezone.utc)

        # 1. Inspect active OS sessions from platform adapter
        sessions = self.adapter.get_active_sessions()
        current_session_keys = set()

        for s in sessions:
            user = s.get("username", "unknown")
            term = s.get("terminal", "default")
            skey = f"{user}@{term}"
            current_session_keys.add(skey)

            if skey not in self._active_sessions:
                # Newly detected active session
                events.append({
                    "event_type": EndpointEventTypeEnum.AUTHENTICATION,
                    "collector_id": self.collector_id,
                    "priority": EventPriorityEnum.NORMAL,
                    "event_time": now_dt,
                    "payload": {
                        "action": "SESSION_START",
                        "username": user,
                        "terminal": term,
                        "session_type": s.get("session_type", "LOCAL"),
                        "status": "SUCCESS"
                    }
                })
                self.events_collected_total += 1

        # Check for ended sessions
        ended = self._active_sessions - current_session_keys
        for skey in ended:
            u, _, t = skey.partition("@")
            events.append({
                "event_type": EndpointEventTypeEnum.AUTHENTICATION,
                "collector_id": self.collector_id,
                "priority": EventPriorityEnum.NORMAL,
                "event_time": now_dt,
                "payload": {
                    "action": "SESSION_END",
                    "username": u,
                    "terminal": t,
                    "status": "COMPLETED"
                }
            })
            self.events_collected_total += 1

        self._active_sessions = current_session_keys

        # 2. Process discrete authentication log events
        while self._manual_events:
            ev = self._manual_events.pop(0)
            action = ev.get("action", "")

            # Security critical authentication events receive HIGH priority
            if action in ("LOGIN_FAILURE", "LOCKOUT", "PRIVILEGE_CHANGE") or ev.get("status") == "FAILURE":
                priority = EventPriorityEnum.HIGH
            else:
                priority = EventPriorityEnum.NORMAL

            events.append({
                "event_type": EndpointEventTypeEnum.AUTHENTICATION,
                "collector_id": self.collector_id,
                "priority": priority,
                "event_time": now_dt,
                "payload": ev
            })
            self.events_collected_total += 1

        self.last_collect_time = time.time()
        return events
