"""
Process Telemetry Collector for Section 32 Endpoint Telemetry.
Collects process lifecycle observations, parent-child relationships, bounded binary SHA-256 hashes,
and sanitized command-line arguments.
"""

import os
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
from backend.agent.collectors.hashing import BinaryHashCache
from backend.agent.privacy import PrivacyFilter

logger = logging.getLogger("cyberguard.agent.collectors.process")


class ProcessTelemetryCollector(BaseTelemetryCollector):
    """
    Collects authorized process telemetry with bounded SHA-256 caching and secret-redacted command lines.
    """

    def __init__(
        self,
        collector_id: str = "process_telemetry_collector",
        adapter: Optional[PlatformAdapter] = None,
        hash_cache: Optional[BinaryHashCache] = None,
        privacy_filter: Optional[PrivacyFilter] = None,
        enable_hashing: bool = True
    ):
        self.adapter = adapter or get_platform_adapter()
        platform_name = self.adapter.get_platform_name()
        cap_state = CollectorCapabilityStateEnum.AVAILABLE if self.adapter.is_supported() else CollectorCapabilityStateEnum.UNAVAILABLE

        super().__init__(
            collector_id=collector_id,
            collector_type="PROCESS",
            platform=platform_name,
            version="1.0.0",
            capability_state=cap_state,
            supported_event_types=[EndpointEventTypeEnum.PROCESS.value],
            required_permissions="STANDARD_USER",
            resource_cost="LOW",
            privacy_class="MEDIUM"
        )

        self.hash_cache = hash_cache or BinaryHashCache()
        self.privacy = privacy_filter or PrivacyFilter()
        self.enable_hashing = enable_hashing
        self._seen_pids: Set[int] = set()

    def collect(self) -> List[Dict[str, Any]]:
        if not self.is_running or self.capability_state != CollectorCapabilityStateEnum.AVAILABLE:
            return []

        raw_processes = self.adapter.get_running_processes(max_count=self.max_events_per_cycle)
        events = []
        now_dt = datetime.now(timezone.utc)

        for p in raw_processes:
            pid = p.get("process_id", 0)
            cmdline = p.get("command_line", "")
            exec_path = p.get("executable_path", "")
            proc_name = p.get("process_name", "")
            user = p.get("username", "")

            # 1. Deterministic redaction on command line
            redacted_payload = self.privacy.sanitize_payload({
                "process_id": pid,
                "parent_process_id": p.get("parent_process_id", 1),
                "process_name": proc_name,
                "executable_path": exec_path,
                "command_line": cmdline,
                "username": user
            })

            # 2. Binary SHA-256 hash computation via bounded cache
            binary_hash = None
            if self.enable_hashing and exec_path and os.path.exists(exec_path):
                binary_hash = self.hash_cache.compute_sha256(exec_path)

            redacted_payload["executable_hash"] = binary_hash or "UNKNOWN"
            redacted_payload["lifecycle_action"] = "STARTED" if pid not in self._seen_pids else "RUNNING"
            self._seen_pids.add(pid)

            # Assign priority: elevated or sudo processes get HIGH priority
            is_elevated = user in ("root", "SYSTEM") or "sudo" in proc_name.lower()
            priority = EventPriorityEnum.HIGH if is_elevated else EventPriorityEnum.NORMAL

            if not self.should_sample_event(priority):
                continue

            events.append({
                "event_type": EndpointEventTypeEnum.PROCESS,
                "collector_id": self.collector_id,
                "priority": priority,
                "event_time": now_dt,
                "payload": redacted_payload
            })
            self.events_collected_total += 1

        self.last_collect_time = time.time()
        return events
