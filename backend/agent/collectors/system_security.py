"""
System Security Telemetry Collector for Section 32 Endpoint Telemetry.
Collects system security posture observations, integrity policy changes, and security events.
"""

import time
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from backend.schemas.endpoint_agent import (
    EndpointEventTypeEnum,
    EventPriorityEnum,
    CollectorCapabilityStateEnum
)
from backend.agent.collectors.base import BaseTelemetryCollector
from backend.agent.collectors.platform_adapters import get_platform_adapter, PlatformAdapter

logger = logging.getLogger("cyberguard.agent.collectors.system_security")


class SystemSecurityTelemetryCollector(BaseTelemetryCollector):
    """
    Collects operating system security posture and policy state observations.
    """

    def __init__(
        self,
        collector_id: str = "system_security_telemetry_collector",
        adapter: Optional[PlatformAdapter] = None
    ):
        self.adapter = adapter or get_platform_adapter()
        platform_name = self.adapter.get_platform_name()
        cap_state = CollectorCapabilityStateEnum.AVAILABLE if self.adapter.is_supported() else CollectorCapabilityStateEnum.UNAVAILABLE

        super().__init__(
            collector_id=collector_id,
            collector_type="SYSTEM_SECURITY",
            platform=platform_name,
            version="1.0.0",
            capability_state=cap_state,
            supported_event_types=[
                EndpointEventTypeEnum.SYSTEM.value,
                EndpointEventTypeEnum.SYSTEM_SECURITY.value
            ],
            required_permissions="STANDARD_USER",
            resource_cost="LOW",
            privacy_class="LOW"
        )

        self._last_posture: Optional[Dict[str, Any]] = None
        self._manual_security_events: List[Dict[str, Any]] = []

    def record_security_event(
        self,
        event_name: str,
        category: str = "POLICY_CHANGE",
        severity: str = "HIGH",
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """Allows feeding discrete system security incidents (e.g. crash report, policy update)."""
        self._manual_security_events.append({
            "event_name": event_name.upper(),
            "category": category.upper(),
            "severity": severity.upper(),
            "details": details or {}
        })

    def collect(self) -> List[Dict[str, Any]]:
        if not self.is_running or self.capability_state != CollectorCapabilityStateEnum.AVAILABLE:
            return []

        events = []
        now_dt = datetime.now(timezone.utc)

        # 1. System integrity posture check
        current_posture = self.adapter.get_system_security_posture()
        if self._last_posture is None or current_posture != self._last_posture:
            # Emit posture change
            sip = current_posture.get("system_integrity_protection", "UNKNOWN")
            is_compromised = sip == "DISABLED"
            priority = EventPriorityEnum.CRITICAL if is_compromised else EventPriorityEnum.NORMAL

            events.append({
                "event_type": EndpointEventTypeEnum.SYSTEM_SECURITY,
                "collector_id": self.collector_id,
                "priority": priority,
                "event_time": now_dt,
                "payload": {
                    "action": "SECURITY_POSTURE_BASELINE" if self._last_posture is None else "SECURITY_POSTURE_CHANGED",
                    **current_posture
                }
            })
            self._last_posture = dict(current_posture)
            self.events_collected_total += 1

        # 2. Process discrete system events
        while self._manual_security_events:
            sec_ev = self._manual_security_events.pop(0)
            priority = EventPriorityEnum.HIGH if sec_ev.get("severity") in ("HIGH", "CRITICAL") else EventPriorityEnum.NORMAL

            events.append({
                "event_type": EndpointEventTypeEnum.SYSTEM_SECURITY,
                "collector_id": self.collector_id,
                "priority": priority,
                "event_time": now_dt,
                "payload": sec_ev
            })
            self.events_collected_total += 1

        self.last_collect_time = time.time()
        return events
