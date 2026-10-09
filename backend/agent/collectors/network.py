"""
Network Connection Telemetry Collector for Section 32 Endpoint Telemetry.
Collects metadata-level TCP/UDP connection observations without packet inspection or sniffing.
"""

import time
import ipaddress
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

logger = logging.getLogger("cyberguard.agent.collectors.network")


class NetworkTelemetryCollector(BaseTelemetryCollector):
    """
    Collects authorized host-level network connection metadata.
    """

    def __init__(
        self,
        collector_id: str = "network_telemetry_collector",
        adapter: Optional[PlatformAdapter] = None
    ):
        self.adapter = adapter or get_platform_adapter()
        platform_name = self.adapter.get_platform_name()
        cap_state = CollectorCapabilityStateEnum.AVAILABLE if self.adapter.is_supported() else CollectorCapabilityStateEnum.UNAVAILABLE

        super().__init__(
            collector_id=collector_id,
            collector_type="NETWORK",
            platform=platform_name,
            version="1.0.0",
            capability_state=cap_state,
            supported_event_types=[EndpointEventTypeEnum.NETWORK.value],
            required_permissions="STANDARD_USER",
            resource_cost="LOW",
            privacy_class="LOW"
        )

    def _is_private_or_loopback(self, ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
            if ip.is_loopback:
                return True
            # Allow documentation subnets (RFC 5737 TEST-NET-1, 2, 3) to be treated as external synthetic endpoints
            if ip.version == 4:
                for doc_net in (
                    ipaddress.ip_network("192.0.2.0/24"),
                    ipaddress.ip_network("198.51.100.0/24"),
                    ipaddress.ip_network("203.0.113.0/24")
                ):
                    if ip in doc_net:
                        return False
            return ip.is_private
        except ValueError:
            return True

    def collect(self) -> List[Dict[str, Any]]:
        if not self.is_running or self.capability_state != CollectorCapabilityStateEnum.AVAILABLE:
            return []

        raw_conns = self.adapter.get_network_connections(max_count=self.max_events_per_cycle)
        events = []
        now_dt = datetime.now(timezone.utc)

        for c in raw_conns:
            rem_ip = c.get("remote_address", "")
            rem_port = c.get("remote_port", 0)
            local_ip = c.get("local_address", "")
            local_port = c.get("local_port", 0)
            proto = c.get("protocol", "TCP")
            state = c.get("connection_state", "ESTABLISHED")
            direction = c.get("direction", "OUTBOUND")

            # Avoid recording empty or 0.0.0.0 remote destinations
            if not rem_ip or rem_ip in ("0.0.0.0", "*", "::"):
                continue

            # Prioritize external / public connections over local loopback
            is_internal = self._is_private_or_loopback(rem_ip)
            priority = EventPriorityEnum.HIGH if not is_internal else EventPriorityEnum.NORMAL

            if not self.should_sample_event(priority):
                continue

            payload = {
                "protocol": proto,
                "local_address": local_ip,
                "local_port": local_port,
                "remote_address": rem_ip,
                "remote_port": rem_port,
                "connection_state": state,
                "direction": direction,
                "is_external": not is_internal
            }

            events.append({
                "event_type": EndpointEventTypeEnum.NETWORK,
                "collector_id": self.collector_id,
                "priority": priority,
                "event_time": now_dt,
                "payload": payload
            })
            self.events_collected_total += 1

        self.last_collect_time = time.time()
        return events
