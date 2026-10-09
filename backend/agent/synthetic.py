"""
Synthetic Test Collector and Harness for Section 31 Endpoint Agent Architecture.
Generates safe synthetic telemetry events to verify the end-to-end pipeline:
Synthetic Collector -> Normalization -> Local Buffer -> Transport -> Ingestion -> ThreatEvent.

STRICT RULE: Generates only benign, synthetic telemetry; NO exploit payloads,
NO real malware activity, and NO offensive actions.
"""

import time
import uuid
from typing import Dict, Any, List
from datetime import datetime, timezone

from backend.schemas.endpoint_agent import (
    EndpointEventTypeEnum,
    EventPriorityEnum
)
from backend.agent.collector_registry import (
    EndpointCollector,
    CollectorCapability
)


class SyntheticCollector(EndpointCollector):
    """
    Test harness collector producing safe simulated host events
    for end-to-end architecture validation.
    """

    def __init__(self, collector_id: str = "synthetic_harness_collector"):
        capability = CollectorCapability(
            collector_id=collector_id,
            collector_version="1.0.0",
            supported_platforms=["macos", "windows", "linux"],
            required_permissions="STANDARD_USER",
            supported_event_types=[
                EndpointEventTypeEnum.PROCESS.value,
                EndpointEventTypeEnum.NETWORK.value,
                EndpointEventTypeEnum.DNS.value,
                EndpointEventTypeEnum.AUTHENTICATION.value,
                EndpointEventTypeEnum.FILE_METADATA.value
            ],
            resource_cost="LOW",
            privacy_class="LOW",
            enabled=True
        )
        super().__init__(capability)
        self._sample_index = 0

    def initialize(self, config: Dict[str, Any]) -> bool:
        self.is_running = False
        self._sample_index = 0
        return True

    def start(self) -> bool:
        self.is_running = True
        return True

    def stop(self) -> bool:
        self.is_running = False
        return True

    def collect(self) -> List[Dict[str, Any]]:
        """Generates safe synthetic events across categories."""
        if not self.is_running:
            return []

        events = []
        now_iso = datetime.now(timezone.utc)

        # 1. Process Event
        events.append({
            "event_type": EndpointEventTypeEnum.PROCESS,
            "priority": EventPriorityEnum.NORMAL,
            "event_time": now_iso,
            "payload": {
                "process_name": "python3",
                "process_path": "/usr/local/bin/python3",
                "pid": 48192,
                "parent_pid": 1024,
                "command_line": "python3 /opt/cyberguard/agent/worker.py --status",
                "username": "service_user",
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "synthetic": True
            }
        })

        # 2. DNS Query Event
        events.append({
            "event_type": EndpointEventTypeEnum.DNS,
            "priority": EventPriorityEnum.LOW,
            "event_time": now_iso,
            "payload": {
                "query_name": "api.internal.corp",
                "query_type": "A",
                "response_code": "NOERROR",
                "answers": ["10.0.1.15", "10.0.1.16"],
                "process_name": "curl",
                "synthetic": True
            }
        })

        # 3. Network Connection Event
        events.append({
            "event_type": EndpointEventTypeEnum.NETWORK,
            "priority": EventPriorityEnum.NORMAL,
            "event_time": now_iso,
            "payload": {
                "src_ip": "10.0.2.45",
                "src_port": 51234,
                "dst_ip": "10.0.1.15",
                "dst_port": 443,
                "protocol": "TCP",
                "state": "ESTABLISHED",
                "bytes_sent": 1420,
                "bytes_received": 8940,
                "synthetic": True
            }
        })

        # 4. Authentication Event
        events.append({
            "event_type": EndpointEventTypeEnum.AUTHENTICATION,
            "priority": EventPriorityEnum.HIGH,
            "event_time": now_iso,
            "payload": {
                "action": "USER_LOGIN",
                "username": "secadmin",
                "status": "SUCCESS",
                "auth_method": "PAM_KEY",
                "terminal": "ttys001",
                "synthetic": True
            }
        })

        # 5. File Metadata Event
        events.append({
            "event_type": EndpointEventTypeEnum.FILE_METADATA,
            "priority": EventPriorityEnum.LOW,
            "event_time": now_iso,
            "payload": {
                "file_path": "/etc/hosts",
                "action": "ACCESSED",
                "file_size": 245,
                "sha256": "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
                "synthetic": True
            }
        })

        self.last_collect_time = time.time()
        self._sample_index += len(events)
        return events
