"""
Base Collector Interface and Capability States for Section 32 Endpoint Telemetry.
Provides standardized telemetry collector contracts, capability state tracking,
resource-bounded sampling, and operational observability.
"""

import abc
import random
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from backend.schemas.endpoint_agent import (
    CollectorCapabilityStateEnum,
    EventPriorityEnum,
    EndpointEventTypeEnum
)
from backend.agent.collector_registry import EndpointCollector, CollectorCapability

logger = logging.getLogger("cyberguard.agent.collectors.base")


class BaseTelemetryCollector(EndpointCollector):
    """
    Standardized base class for all Section 32 platform telemetry collectors.
    Integrates capability state tracking, bounded rate limiting, and sampling.
    """

    def __init__(
        self,
        collector_id: str,
        collector_type: str,
        platform: str,
        version: str = "1.0.0",
        capability_state: CollectorCapabilityStateEnum = CollectorCapabilityStateEnum.AVAILABLE,
        supported_event_types: Optional[List[str]] = None,
        required_permissions: str = "STANDARD_USER",
        resource_cost: str = "LOW",
        privacy_class: str = "MEDIUM",
        sampling_rate: float = 1.0,
        max_events_per_cycle: int = 100
    ):
        self.collector_id = collector_id
        self.collector_type = collector_type
        self.platform = platform
        self.version = version
        self.capability_state = capability_state
        self.sampling_rate = sampling_rate
        self.max_events_per_cycle = max_events_per_cycle
        self.configuration: Dict[str, Any] = {}

        # Observability metrics
        self.events_collected_total = 0
        self.events_dropped_total = 0

        capability = CollectorCapability(
            collector_id=collector_id,
            collector_version=version,
            supported_platforms=[platform],
            required_permissions=required_permissions,
            supported_event_types=supported_event_types or [collector_type],
            resource_cost=resource_cost,
            privacy_class=privacy_class,
            enabled=True
        )
        super().__init__(capability)

    def initialize(self, config: Dict[str, Any]) -> bool:
        """Initializes collector configuration and evaluates capability."""
        self.configuration = config or {}
        self.sampling_rate = float(self.configuration.get("sampling_rate", self.sampling_rate))
        self.max_events_per_cycle = int(self.configuration.get("max_events_per_cycle", self.max_events_per_cycle))

        if not self.capability.enabled:
            self.capability_state = CollectorCapabilityStateEnum.DISABLED
            return False

        if self.capability_state == CollectorCapabilityStateEnum.UNAVAILABLE:
            return False

        return True

    def start(self) -> bool:
        if self.capability_state not in (
            CollectorCapabilityStateEnum.AVAILABLE,
            CollectorCapabilityStateEnum.DEGRADED
        ):
            logger.info(f"Collector {self.collector_id} cannot start (state: {self.capability_state.value})")
            self.is_running = False
            return False

        self.is_running = True
        logger.info(f"Started collector {self.collector_id} (type: {self.collector_type}, platform: {self.platform})")
        return True

    def stop(self) -> bool:
        self.is_running = False
        logger.info(f"Stopped collector {self.collector_id}")
        return True

    def should_sample_event(self, priority: EventPriorityEnum) -> bool:
        """
        Evaluates sampling policy:
        - CRITICAL and HIGH priority events are NEVER dropped.
        - NORMAL and LOW priority events are sampled according to sampling_rate.
        """
        if priority in (EventPriorityEnum.CRITICAL, EventPriorityEnum.HIGH):
            return True

        if self.sampling_rate >= 1.0:
            return True

        if self.sampling_rate <= 0.0:
            self.events_dropped_total += 1
            return False

        keep = random.random() < self.sampling_rate
        if not keep:
            self.events_dropped_total += 1
        return keep

    def health(self) -> Dict[str, Any]:
        """Provides rich operational health diagnostics."""
        base_health = super().health()
        base_health.update({
            "is_running": self.is_running,
            "collector_type": self.collector_type,
            "platform": self.platform,
            "capability_state": self.capability_state.value,
            "sampling_rate": self.sampling_rate,
            "max_events_per_cycle": self.max_events_per_cycle,
            "events_collected_total": self.events_collected_total,
            "events_dropped_total": self.events_dropped_total
        })
        return base_health

    @abc.abstractmethod
    def collect(self) -> List[Dict[str, Any]]:
        """Collects raw observations from authorized host APIs."""
        pass
