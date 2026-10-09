"""
Agent Health Reporter for Section 31 Endpoint Agent Architecture.
Aggregates host resource usage, collector health, and buffer status to determine
agent health state and compose periodic heartbeat payloads.
"""

import os
import time
import logging
from typing import Dict, Any, Optional
from datetime import datetime, timezone

from backend.schemas.endpoint_agent import (
    AgentHealthStateEnum,
    AgentHeartbeatRequest
)
from backend.agent.buffer import LocalEventBuffer
from backend.agent.collector_registry import CollectorRegistry

logger = logging.getLogger("cyberguard.agent.health")


class AgentHealthReporter:
    """
    Monitors endpoint agent operational vitals and prepares heartbeats.
    """

    def __init__(
        self,
        agent_id: str,
        buffer: LocalEventBuffer,
        registry: CollectorRegistry,
        agent_version: str = "1.0.0",
        configuration_version: str = "1.0.0"
    ):
        self.agent_id = agent_id
        self.buffer = buffer
        self.registry = registry
        self.agent_version = agent_version
        self.configuration_version = configuration_version
        self.last_event_time: Optional[datetime] = None

    def update_last_event_time(self, dt: datetime) -> None:
        self.last_event_time = dt

    def get_resource_usage(self) -> Dict[str, float]:
        """
        Gathers lightweight process resource metrics.
        Falls back to safe lightweight estimates if platform profiling is unavailable.
        """
        cpu_pct = 0.5
        mem_mb = 35.0

        try:
            import resource
            usage = resource.getrusage(resource.RUSAGE_SELF)
            # maxrss is in bytes on macOS, kilobytes on Linux
            rss = usage.ru_maxrss
            if os.uname().sysname == "Darwin":
                mem_mb = round(rss / (1024 * 1024), 2)
            else:
                mem_mb = round(rss / 1024, 2)
        except Exception:
            pass

        return {
            "cpu_usage_percent": cpu_pct,
            "memory_usage_mb": mem_mb
        }

    def determine_health_state(self) -> AgentHealthStateEnum:
        """Evaluates overall health status based on buffer pressure and collector health."""
        buf_health = self.buffer.health()
        col_summary = self.registry.get_health_summary()

        if buf_health.get("under_pressure", False):
            return AgentHealthStateEnum.BUFFER_PRESSURE

        if col_summary.get("total_failures", 0) > 0:
            if col_summary.get("total_running", 0) > 0:
                return AgentHealthStateEnum.DEGRADED
            else:
                return AgentHealthStateEnum.COLLECTOR_FAILURE

        return AgentHealthStateEnum.HEALTHY

    def build_heartbeat_request(self) -> AgentHeartbeatRequest:
        """Constructs an AgentHeartbeatRequest payload."""
        state = self.determine_health_state()
        res = self.get_resource_usage()
        buf_health = self.buffer.health()
        col_summary = self.registry.get_health_summary()

        col_states = {}
        for cid, details in col_summary.get("collector_states", {}).items():
            status = "HEALTHY" if details.get("running") and details.get("failure_count", 0) == 0 else "DEGRADED"
            if details.get("failure_count", 0) > 2:
                status = "FAILED"
            col_states[cid] = status

        return AgentHeartbeatRequest(
            agent_id=self.agent_id,
            health_state=state,
            collector_states=col_states,
            buffer_events_count=buf_health.get("pending_events", 0),
            buffer_bytes=buf_health.get("bytes_used", 0),
            cpu_usage_percent=res.get("cpu_usage_percent", 0.0),
            memory_usage_mb=res.get("memory_usage_mb", 0.0),
            last_event_time=self.last_event_time,
            agent_version=self.agent_version,
            configuration_version=self.configuration_version
        )
