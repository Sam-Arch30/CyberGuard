"""
Device Health Telemetry Collector for Section 32 Endpoint Telemetry.
Collects host resource metrics, disk availability, process memory usage,
and queue backpressure indicators.
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

logger = logging.getLogger("cyberguard.agent.collectors.device_health")


class DeviceHealthTelemetryCollector(BaseTelemetryCollector):
    """
    Collects endpoint operational health and resource metrics.
    """

    def __init__(
        self,
        collector_id: str = "device_health_telemetry_collector",
        adapter: Optional[PlatformAdapter] = None,
        agent_version: str = "1.0.0"
    ):
        self.adapter = adapter or get_platform_adapter()
        platform_name = self.adapter.get_platform_name()
        cap_state = CollectorCapabilityStateEnum.AVAILABLE if self.adapter.is_supported() else CollectorCapabilityStateEnum.UNAVAILABLE

        super().__init__(
            collector_id=collector_id,
            collector_type="DEVICE_HEALTH",
            platform=platform_name,
            version="1.0.0",
            capability_state=cap_state,
            supported_event_types=[EndpointEventTypeEnum.DEVICE_HEALTH.value],
            required_permissions="STANDARD_USER",
            resource_cost="LOW",
            privacy_class="LOW"
        )
        self.agent_version = agent_version
        self._start_time = time.time()

    def collect(self) -> List[Dict[str, Any]]:
        if not self.is_running or self.capability_state != CollectorCapabilityStateEnum.AVAILABLE:
            return []

        vitals = self.adapter.get_host_vitals()
        now_dt = datetime.now(timezone.utc)
        uptime_seconds = round(time.time() - self._start_time, 1)

        mem_mb = vitals.get("memory_usage_mb", 0.0)
        disk_free_mb = vitals.get("disk_free_mb", 1000)

        # Flag pressure if disk is below 500 MB or memory exceeds 250 MB
        under_pressure = disk_free_mb < 500 or mem_mb > 250.0
        priority = EventPriorityEnum.HIGH if under_pressure else EventPriorityEnum.LOW

        payload = {
            "agent_version": self.agent_version,
            "platform": self.platform,
            "agent_uptime_seconds": uptime_seconds,
            "memory_usage_mb": mem_mb,
            "disk_free_mb": disk_free_mb,
            "load_1m": vitals.get("load_1m", 0.0),
            "under_pressure": under_pressure
        }

        self.last_collect_time = time.time()
        self.events_collected_total += 1

        return [{
            "event_type": EndpointEventTypeEnum.DEVICE_HEALTH,
            "collector_id": self.collector_id,
            "priority": priority,
            "event_time": now_dt,
            "payload": payload
        }]
