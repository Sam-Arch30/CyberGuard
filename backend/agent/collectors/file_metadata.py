"""
File Metadata Telemetry Collector for Section 32 Endpoint Telemetry.
Collects filesystem metadata observations (path, extension, size, mtime, hash)
without collecting or uploading document contents.

STRICT PRIVACY GUARANTEE:
Never collects document contents, personal emails, or excluded path materials.
"""

import os
import time
import fnmatch
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

logger = logging.getLogger("cyberguard.agent.collectors.file_metadata")


class FileMetadataTelemetryCollector(BaseTelemetryCollector):
    """
    Collects metadata-level filesystem telemetry with exclusion filters and bounded hashing.
    """

    def __init__(
        self,
        collector_id: str = "file_metadata_telemetry_collector",
        adapter: Optional[PlatformAdapter] = None,
        hash_cache: Optional[BinaryHashCache] = None,
        monitored_paths: Optional[List[str]] = None,
        excluded_paths: Optional[List[str]] = None,
        excluded_extensions: Optional[List[str]] = None,
        max_file_size_for_hashing: int = 20 * 1024 * 1024  # 20 MB
    ):
        self.adapter = adapter or get_platform_adapter()
        platform_name = self.adapter.get_platform_name()
        cap_state = CollectorCapabilityStateEnum.AVAILABLE if self.adapter.is_supported() else CollectorCapabilityStateEnum.UNAVAILABLE

        super().__init__(
            collector_id=collector_id,
            collector_type="FILE",
            platform=platform_name,
            version="1.0.0",
            capability_state=cap_state,
            supported_event_types=[
                EndpointEventTypeEnum.FILE_METADATA.value,
                EndpointEventTypeEnum.FILE.value
            ],
            required_permissions="STANDARD_USER",
            resource_cost="LOW",
            privacy_class="MEDIUM"
        )

        self.hash_cache = hash_cache or BinaryHashCache(max_file_size_bytes=max_file_size_for_hashing)
        self.monitored_paths = monitored_paths or ["/etc", "/usr/local/bin"]
        self.excluded_paths = excluded_paths or [
            "*/Documents/Personal/*",
            "*/.ssh/*",
            "*/Keychains/*",
            "*/AppData/*"
        ]
        self.excluded_extensions = {ext.lower() for ext in (excluded_extensions or [".tmp", ".swp", ".log"])}
        self._manual_file_events: List[Dict[str, Any]] = []

    def is_path_excluded(self, path: str) -> bool:
        norm = path.replace("\\", "/")
        for pat in self.excluded_paths:
            if fnmatch.fnmatch(norm, pat.replace("\\", "/")):
                return True
        ext = os.path.splitext(path)[1].lower()
        if ext in self.excluded_extensions:
            return True
        return False

    def record_file_event(
        self,
        action: str,  # FILE_CREATED, FILE_MODIFIED, FILE_RENAMED, FILE_DELETED
        file_path: str,
        process_name: Optional[str] = None,
        username: Optional[str] = None,
        calculate_hash: bool = True
    ) -> None:
        """Feeds a filesystem observation from OS watcher/event hook."""
        if self.is_path_excluded(file_path):
            return

        sha256 = None
        file_size = 0
        if calculate_hash and os.path.exists(file_path) and not os.path.isdir(file_path):
            try:
                file_size = os.path.getsize(file_path)
                sha256 = self.hash_cache.compute_sha256(file_path)
            except Exception:
                pass

        self._manual_file_events.append({
            "action": action.upper(),
            "file_path": os.path.abspath(file_path),
            "filename": os.path.basename(file_path),
            "extension": os.path.splitext(file_path)[1].lower(),
            "file_size": file_size,
            "sha256": sha256 or "UNKNOWN",
            "process_name": process_name or "unknown",
            "username": username or "unknown"
        })

    def collect(self) -> List[Dict[str, Any]]:
        if not self.is_running or self.capability_state != CollectorCapabilityStateEnum.AVAILABLE:
            return []

        events = []
        now_dt = datetime.now(timezone.utc)

        while self._manual_file_events:
            fev = self._manual_file_events.pop(0)

            # Assign priority: system path files or executable modifications are HIGH
            fpath = fev.get("file_path", "")
            is_sys = any(fpath.startswith(p) for p in ("/etc", "/usr", "/bin", "/sbin", "C:\\Windows"))
            priority = EventPriorityEnum.HIGH if is_sys else EventPriorityEnum.NORMAL

            if not self.should_sample_event(priority):
                continue

            events.append({
                "event_type": EndpointEventTypeEnum.FILE_METADATA,
                "collector_id": self.collector_id,
                "priority": priority,
                "event_time": now_dt,
                "payload": fev
            })
            self.events_collected_total += 1

        self.last_collect_time = time.time()
        return events
