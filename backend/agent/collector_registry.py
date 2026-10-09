"""
Collector Registry and Capability Interface for Section 31 Endpoint Agent Architecture.
Defines platform-neutral collector contracts and isolated failure handling.
"""

import abc
import logging
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

logger = logging.getLogger("cyberguard.agent.collectors")


class CollectorCapability(BaseModel):
    """
    Metadata declaring supported platforms, required privileges, and privacy class.
    """
    collector_id: str
    collector_version: str = "1.0.0"
    supported_platforms: List[str] = Field(default_factory=lambda: ["macos", "windows", "linux"])
    required_permissions: str = "STANDARD_USER"  # STANDARD_USER, ELEVATED_AUDIT, SYSTEM
    supported_event_types: List[str] = Field(default_factory=list)
    resource_cost: str = "LOW"  # LOW, MEDIUM, HIGH
    privacy_class: str = "MEDIUM"  # LOW, MEDIUM, HIGH
    enabled: bool = True


class EndpointCollector(abc.ABC):
    """
    Platform-neutral abstract base class for endpoint telemetry collectors.
    Platform-specific collectors (macOS, Windows, Linux) are adapters behind this contract.
    Section 31 defines the contract; Section 32 will implement concrete telemetry collectors.
    """

    def __init__(self, capability: CollectorCapability):
        self.capability = capability
        self.is_running = False
        self.failure_count = 0
        self.last_error: Optional[str] = None
        self.last_collect_time: Optional[float] = None

    @abc.abstractmethod
    def initialize(self, config: Dict[str, Any]) -> bool:
        """Initializes collector with validated configuration."""
        pass

    @abc.abstractmethod
    def start(self) -> bool:
        """Starts background collection routine."""
        pass

    @abc.abstractmethod
    def stop(self) -> bool:
        """Gracefully halts collection routine."""
        pass

    @abc.abstractmethod
    def collect(self) -> List[Dict[str, Any]]:
        """Polls or yields collected telemetry events."""
        pass

    def health(self) -> Dict[str, Any]:
        """Reports collector operational state and error metrics."""
        return {
            "collector_id": self.capability.collector_id,
            "collector_version": self.capability.collector_version,
            "running": self.is_running,
            "failure_count": self.failure_count,
            "last_error": self.last_error,
            "last_collect_time": self.last_collect_time,
            "enabled": self.capability.enabled
        }


class CollectorRegistry:
    """
    Registry managing collector instances with strict fault isolation.
    If one collector fails or throws an exception, other collectors remain running.
    """

    def __init__(self):
        self._collectors: Dict[str, EndpointCollector] = {}

    def register(self, collector: EndpointCollector) -> None:
        """Registers a collector instance."""
        cid = collector.capability.collector_id
        self._collectors[cid] = collector
        logger.info(f"Registered endpoint collector: {cid} (v{collector.capability.collector_version})")

    def unregister(self, collector_id: str) -> None:
        """Unregisters and stops a collector."""
        if collector_id in self._collectors:
            try:
                self._collectors[collector_id].stop()
            except Exception as e:
                logger.warning(f"Error stopping collector {collector_id}: {e}")
            del self._collectors[collector_id]

    def get(self, collector_id: str) -> Optional[EndpointCollector]:
        return self._collectors.get(collector_id)

    def list_collectors(self) -> List[CollectorCapability]:
        return [c.capability for c in self._collectors.values()]

    def start_all(self, enabled_ids: Optional[List[str]] = None) -> Dict[str, bool]:
        """Starts all eligible collectors with failure isolation."""
        results = {}
        for cid, col in self._collectors.items():
            if enabled_ids is not None and cid not in enabled_ids:
                col.capability.enabled = False
                results[cid] = False
                continue

            col.capability.enabled = True
            try:
                ok = col.start()
                results[cid] = ok
            except Exception as err:
                col.failure_count += 1
                col.last_error = str(err)
                logger.error(f"Collector {cid} failed to start: {err}")
                results[cid] = False
        return results

    def stop_all(self) -> None:
        """Stops all running collectors."""
        for cid, col in self._collectors.items():
            try:
                col.stop()
            except Exception as err:
                logger.warning(f"Error stopping collector {cid}: {err}")

    def collect_all(self) -> List[Dict[str, Any]]:
        """
        Polls telemetry across all enabled collectors.
        Fault-isolated: an exception in one collector does not abort others.
        """
        all_events = []
        for cid, col in self._collectors.items():
            if not col.capability.enabled or not col.is_running:
                continue

            try:
                events = col.collect()
                if events:
                    all_events.extend(events)
            except Exception as err:
                col.failure_count += 1
                col.last_error = str(err)
                logger.error(f"Collector {cid} raised error during collect(): {err}")
        return all_events

    def get_health_summary(self) -> Dict[str, Any]:
        """Aggregates health reports across all registered collectors."""
        states = {}
        total_failures = 0
        running_count = 0

        for cid, col in self._collectors.items():
            h = col.health()
            states[cid] = h
            if h["running"]:
                running_count += 1
            total_failures += h["failure_count"]

        return {
            "total_registered": len(self._collectors),
            "total_running": running_count,
            "total_failures": total_failures,
            "collector_states": states
        }
