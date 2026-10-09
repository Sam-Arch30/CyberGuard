"""
DNS Telemetry Collector for Section 32 Endpoint Telemetry.
Collects DNS resolution observations, queried domain normalization, and resolver configuration state.
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

logger = logging.getLogger("cyberguard.agent.collectors.dns")


class DNSTelemetryCollector(BaseTelemetryCollector):
    """
    Collects authorized DNS resolution metadata and resolver status.
    """

    def __init__(
        self,
        collector_id: str = "dns_telemetry_collector",
        adapter: Optional[PlatformAdapter] = None
    ):
        self.adapter = adapter or get_platform_adapter()
        platform_name = self.adapter.get_platform_name()
        cap_state = CollectorCapabilityStateEnum.AVAILABLE if self.adapter.is_supported() else CollectorCapabilityStateEnum.UNAVAILABLE

        super().__init__(
            collector_id=collector_id,
            collector_type="DNS",
            platform=platform_name,
            version="1.0.0",
            capability_state=cap_state,
            supported_event_types=[EndpointEventTypeEnum.DNS.value],
            required_permissions="STANDARD_USER",
            resource_cost="LOW",
            privacy_class="LOW"
        )

        self._last_nameservers: List[str] = []
        self._manual_observations: List[Dict[str, Any]] = []

    def record_observation(
        self,
        domain: str,
        query_type: str = "A",
        resolved_ips: Optional[List[str]] = None,
        response_status: str = "NOERROR",
        process_name: Optional[str] = None
    ) -> None:
        """Allows platform integration or DNS hook to feed observed DNS queries."""
        clean_domain = domain.strip().lower().rstrip(".")
        self._manual_observations.append({
            "queried_domain": clean_domain,
            "query_type": query_type.upper(),
            "resolved_addresses": resolved_ips or [],
            "response_status": response_status.upper(),
            "process_name": process_name or "unknown"
        })

    def collect(self) -> List[Dict[str, Any]]:
        if not self.is_running or self.capability_state != CollectorCapabilityStateEnum.AVAILABLE:
            return []

        events = []
        now_dt = datetime.now(timezone.utc)

        # 1. Check resolver configuration changes
        dns_cfg = self.adapter.get_dns_configuration()
        current_ns = dns_cfg.get("nameservers", [])
        if current_ns and current_ns != self._last_nameservers:
            events.append({
                "event_type": EndpointEventTypeEnum.DNS,
                "collector_id": self.collector_id,
                "priority": EventPriorityEnum.HIGH,
                "event_time": now_dt,
                "payload": {
                    "action": "RESOLVER_CONFIG_CHANGED",
                    "nameservers": current_ns,
                    "previous_nameservers": self._last_nameservers,
                    "search_domains": dns_cfg.get("search_domains", [])
                }
            })
            self._last_nameservers = list(current_ns)
            self.events_collected_total += 1

        # 2. Process recorded resolution queries
        while self._manual_observations:
            obs = self._manual_observations.pop(0)
            priority = EventPriorityEnum.HIGH if obs.get("response_status") == "NXDOMAIN" else EventPriorityEnum.NORMAL

            if not self.should_sample_event(priority):
                continue

            events.append({
                "event_type": EndpointEventTypeEnum.DNS,
                "collector_id": self.collector_id,
                "priority": priority,
                "event_time": now_dt,
                "payload": obs
            })
            self.events_collected_total += 1

        self.last_collect_time = time.time()
        return events
