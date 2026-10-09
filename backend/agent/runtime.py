"""
Agent Runtime Engine for Section 31 Endpoint Agent Architecture.
Coordinates collectors, local buffering, privacy filtering, transport dispatch,
health heartbeats, configuration management, and graceful shutdown.

STRICT SECURITY INVARIANT:
The endpoint agent is an authorized telemetry observation component.
Arbitrary remote shell, script execution, or destructive operations are strictly prohibited.
"""

import time
import uuid
import hashlib
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone

from backend.schemas.endpoint_agent import (
    RawEndpointTelemetryEvent,
    BatchTelemetryIngestRequest,
    BatchTelemetryIngestResponse,
    AgentHeartbeatResponse,
    AgentConfigurationResponse,
    EventPriorityEnum
)
from backend.agent.collector_registry import CollectorRegistry
from backend.agent.buffer import LocalEventBuffer
from backend.agent.privacy import PrivacyFilter
from backend.agent.security import AgentSecurityController
from backend.agent.transport import AgentTransportClient
from backend.agent.health import AgentHealthReporter

logger = logging.getLogger("cyberguard.agent.runtime")


class SecurityViolationException(Exception):
    """Raised when an unauthorized command or execution action is attempted."""
    pass


class AgentRuntime:
    """
    Main runtime lifecycle coordinator for the CYBERGUARD endpoint agent.
    """

    def __init__(
        self,
        agent_id: str,
        device_id: str,
        transport_client: Optional[AgentTransportClient] = None,
        security_controller: Optional[AgentSecurityController] = None,
        buffer: Optional[LocalEventBuffer] = None,
        registry: Optional[CollectorRegistry] = None,
        privacy_filter: Optional[PrivacyFilter] = None,
        agent_version: str = "1.0.0",
        configuration_version: str = "1.0.0",
        batch_size: int = 50,
        flush_interval_seconds: float = 10.0
    ):
        self.agent_id = agent_id
        self.device_id = device_id
        self.agent_version = agent_version
        self.configuration_version = configuration_version
        self.batch_size = batch_size
        self.flush_interval = flush_interval_seconds

        self.buffer = buffer or LocalEventBuffer()
        self.registry = registry or CollectorRegistry()
        self.privacy = privacy_filter or PrivacyFilter()
        self.security = security_controller
        self.transport = transport_client

        self.health_reporter = AgentHealthReporter(
            agent_id=self.agent_id,
            buffer=self.buffer,
            registry=self.registry,
            agent_version=self.agent_version,
            configuration_version=self.configuration_version
        )

        self._sequence_counter = 0
        self._is_running = False
        self._last_flush_time = time.time()
        self._last_heartbeat_time = time.time()

    def start(self) -> None:
        """Starts agent runtime and registered collectors."""
        self._is_running = True
        self.registry.start_all()
        logger.info(f"AgentRuntime {self.agent_id} started on device {self.device_id}")

    def stop(self) -> None:
        """Gracefully halts agent runtime."""
        self._is_running = False
        self.registry.stop_all()
        # Attempt final flush of buffered events
        try:
            self.flush()
        except Exception as e:
            logger.warning(f"Error flushing buffer during shutdown: {e}")

        if self.transport:
            self.transport.close()
        logger.info(f"AgentRuntime {self.agent_id} stopped cleanly.")

    def run_collection_cycle(self) -> int:
        """
        Polls collectors, applies privacy filter, generates monotonic sequence numbers,
        and appends events to the local buffer.
        Returns count of new events buffered.
        """
        if not self._is_running:
            return 0

        raw_items = self.registry.collect_all()
        buffered_count = 0

        for item in raw_items:
            event_type = item.get("event_type")
            raw_payload = item.get("payload", {})
            priority = item.get("priority", EventPriorityEnum.NORMAL)
            event_time = item.get("event_time", datetime.now(timezone.utc))

            # 1. Privacy filter evaluation
            if not self.privacy.should_collect(str(event_type), raw_payload):
                continue

            # 2. Redaction
            sanitized_payload = self.privacy.sanitize_payload(raw_payload)

            # 3. Monotonic sequence number
            self._sequence_counter += 1
            seq = self._sequence_counter

            event_id = str(uuid.uuid4())
            collector_id = item.get("collector_id", "default_collector")

            # 4. Integrity hash
            payload_str = str(sorted(sanitized_payload.items()))
            integrity = hashlib.sha256(f"{self.agent_id}:{seq}:{payload_str}".encode("utf-8")).hexdigest()

            event = RawEndpointTelemetryEvent(
                event_id=event_id,
                sequence_number=seq,
                event_type=event_type,
                event_time=event_time,
                collector_id=collector_id,
                collector_version="1.0.0",
                configuration_version=self.configuration_version,
                agent_version=self.agent_version,
                priority=priority,
                payload=sanitized_payload,
                integrity_hash=integrity
            )

            if self.buffer.append(event):
                buffered_count += 1
                self.health_reporter.update_last_event_time(event_time)

        return buffered_count

    def flush(self) -> Optional[BatchTelemetryIngestResponse]:
        """
        Transmits pending buffered events to server in bounded batches.
        Handles server acknowledgments and retransmissions.
        """
        if not self.transport:
            return None

        events_batch = self.buffer.peek(max_count=self.batch_size)
        if not events_batch:
            return None

        batch_id = f"BATCH-{uuid.uuid4().hex[:12]}"
        req = BatchTelemetryIngestRequest(
            agent_id=self.agent_id,
            batch_id=batch_id,
            events=events_batch,
            timestamp=datetime.now(timezone.utc)
        )

        try:
            resp = self.transport.send_batch(req)

            # Acknowledge accepted events
            if resp.accepted_event_ids:
                self.buffer.acknowledge(resp.accepted_event_ids)

            # For rejected events: if quarantined/unsupported, remove; if retryable, return to buffer
            if resp.rejected_event_ids:
                to_retry = []
                for eid, reason in resp.rejected_event_ids.items():
                    if "TRANSIENT" in reason or "RETRY" in reason:
                        to_retry.append(eid)
                    else:
                        # Malformed or permanent rejection: drop from buffer to prevent deadlock
                        self.buffer.acknowledge([eid])
                        logger.warning(f"Quarantined event {eid} permanently rejected: {reason}")

                if to_retry:
                    self.buffer.retry(to_retry)

            self._last_flush_time = time.time()
            return resp

        except Exception as err:
            logger.error(f"Failed to transmit batch {batch_id}: {err}")
            # Return inflight events back to queue for retry
            self.buffer.retry([e.event_id for e in events_batch])
            raise

    def send_heartbeat(self) -> Optional[AgentHeartbeatResponse]:
        """Sends operational health heartbeat to server."""
        if not self.transport:
            return None

        req = self.health_reporter.build_heartbeat_request()
        resp = self.transport.heartbeat(req)
        self._last_heartbeat_time = time.time()

        if resp.reconfigure_required:
            logger.info("Server requested configuration refresh. Fetching active config...")
            self.fetch_and_apply_configuration()

        return resp

    def fetch_and_apply_configuration(self) -> Optional[AgentConfigurationResponse]:
        """Fetches, validates, and activates server configuration."""
        if not self.transport or not self.security:
            return None

        cfg = self.transport.fetch_configuration()

        # Cryptographic signature validation
        cfg_dict = cfg.model_dump(mode="json")
        if not self.security.verify_configuration_signature(cfg_dict, cfg.signature):
            logger.error("Configuration signature invalid! Rejecting configuration update.")
            return None

        # Apply safe configuration changes
        self.configuration_version = cfg.version
        self.health_reporter.configuration_version = cfg.version
        self.batch_size = cfg.batch_size
        self.flush_interval = cfg.flush_interval_seconds
        self.buffer.max_events = cfg.max_buffer_size_events
        self.buffer.max_bytes = cfg.max_buffer_size_bytes

        if cfg.privacy_policy:
            self.privacy.excluded_paths = cfg.privacy_policy.get("excluded_paths", self.privacy.excluded_paths)
            self.privacy.excluded_processes = cfg.privacy_policy.get("excluded_processes", self.privacy.excluded_processes)

        if cfg.enabled_collectors:
            self.registry.start_all(enabled_ids=cfg.enabled_collectors)

        logger.info(f"Agent {self.agent_id} activated configuration version {cfg.version}")
        return cfg

    # =========================================================================
    # STRICT SECURITY BOUNDARY ENFORCEMENT
    # =========================================================================

    def execute_command(self, *args, **kwargs):
        """
        STRICTLY FORBIDDEN: CYBERGUARD endpoint agents NEVER execute arbitrary commands.
        """
        raise SecurityViolationException(
            "Security Boundary Violation: CYBERGUARD endpoint agent does not support remote command execution."
        )

    def spawn_shell(self, *args, **kwargs):
        """
        STRICTLY FORBIDDEN: CYBERGUARD endpoint agents NEVER spawn remote shells.
        """
        raise SecurityViolationException(
            "Security Boundary Violation: Remote shell functionality is strictly prohibited."
        )
