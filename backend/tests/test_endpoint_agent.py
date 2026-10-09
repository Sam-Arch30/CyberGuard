"""
Unit tests for Section 31 Endpoint Agent Architecture Client Components:
- LocalEventBuffer (priority queueing, capacity limits, overflow policies, ACK/retry)
- PrivacyFilter (deterministic redaction, path/process exclusions, data minimization)
- AgentSecurityController (HMAC signatures, config verification, credential rotation)
- CollectorRegistry (isolated failure handling)
- SyntheticCollector (safe telemetry generation)
- AgentRuntime (monotonic sequence numbering, security invariants)
"""

import time
import pytest
from datetime import datetime, timezone, timedelta

from backend.schemas.endpoint_agent import (
    RawEndpointTelemetryEvent,
    EndpointEventTypeEnum,
    EventPriorityEnum,
    BufferOverflowPolicyEnum
)
from backend.agent.buffer import LocalEventBuffer
from backend.agent.privacy import PrivacyFilter
from backend.agent.security import AgentSecurityController
from backend.agent.collector_registry import (
    EndpointCollector,
    CollectorCapability,
    CollectorRegistry
)
from backend.agent.synthetic import SyntheticCollector
from backend.agent.runtime import AgentRuntime, SecurityViolationException
from backend.agent.health import AgentHealthReporter


# =============================================================================
# 1. LOCAL EVENT BUFFER TESTS
# =============================================================================

def test_buffer_append_peek_and_ack():
    buf = LocalEventBuffer(max_events=10)

    now = datetime.now(timezone.utc)
    ev1 = RawEndpointTelemetryEvent(
        event_id="ev-001",
        sequence_number=1,
        event_type=EndpointEventTypeEnum.PROCESS,
        event_time=now,
        collector_id="proc_col",
        priority=EventPriorityEnum.NORMAL,
        payload={"proc": "test"}
    )
    ev2 = RawEndpointTelemetryEvent(
        event_id="ev-002",
        sequence_number=2,
        event_type=EndpointEventTypeEnum.DNS,
        event_time=now + timedelta(seconds=1),
        collector_id="dns_col",
        priority=EventPriorityEnum.HIGH,
        payload={"query": "test.local"}
    )

    assert buf.append(ev1) is True
    assert buf.append(ev2) is True
    assert buf.pending_count() == 2

    # High priority should be peeked first
    peeked = buf.peek(max_count=1)
    assert len(peeked) == 1
    assert peeked[0].event_id == "ev-002"
    assert buf.pending_count() == 1
    assert buf.inflight_count() == 1

    # Acknowledge ev-002
    acked = buf.acknowledge(["ev-002"])
    assert acked == 1
    assert buf.inflight_count() == 0
    assert buf.size() == 1


def test_buffer_retry_semantics():
    buf = LocalEventBuffer(max_events=10)
    ev = RawEndpointTelemetryEvent(
        event_id="ev-retry",
        sequence_number=10,
        event_type=EndpointEventTypeEnum.NETWORK,
        event_time=datetime.now(timezone.utc),
        collector_id="net_col",
        priority=EventPriorityEnum.NORMAL,
        payload={"port": 80}
    )
    buf.append(ev)
    peeked = buf.peek(max_count=1)
    assert len(peeked) == 1
    assert buf.inflight_count() == 1

    # Server returned failure, retry event
    buf.retry(["ev-retry"])
    assert buf.inflight_count() == 0
    assert buf.pending_count() == 1


def test_buffer_overflow_drop_low_priority():
    buf = LocalEventBuffer(max_events=2, overflow_policy=BufferOverflowPolicyEnum.DROP_LOW_PRIORITY)
    now = datetime.now(timezone.utc)

    ev_low = RawEndpointTelemetryEvent(
        event_id="ev-low",
        sequence_number=1,
        event_type=EndpointEventTypeEnum.FILE_METADATA,
        event_time=now,
        collector_id="file_col",
        priority=EventPriorityEnum.LOW,
        payload={"f": 1}
    )
    ev_norm = RawEndpointTelemetryEvent(
        event_id="ev-norm",
        sequence_number=2,
        event_type=EndpointEventTypeEnum.DNS,
        event_time=now,
        collector_id="dns_col",
        priority=EventPriorityEnum.NORMAL,
        payload={"f": 2}
    )
    ev_crit = RawEndpointTelemetryEvent(
        event_id="ev-crit",
        sequence_number=3,
        event_type=EndpointEventTypeEnum.AUTHENTICATION,
        event_time=now,
        collector_id="auth_col",
        priority=EventPriorityEnum.CRITICAL,
        payload={"f": 3}
    )

    buf.append(ev_low)
    buf.append(ev_norm)
    assert buf.pending_count() == 2

    # Appending CRITICAL should drop LOW priority event
    buf.append(ev_crit)
    assert buf.pending_count() == 2
    h = buf.health()
    assert h["total_dropped"] == 1
    assert h["drops_by_priority"]["LOW"] == 1

    # Peek remaining: should have CRITICAL and NORMAL
    peeked = buf.peek(max_count=2)
    ids = [e.event_id for e in peeked]
    assert "ev-crit" in ids
    assert "ev-norm" in ids
    assert "ev-low" not in ids


def test_buffer_overflow_block_collector():
    buf = LocalEventBuffer(max_events=1, overflow_policy=BufferOverflowPolicyEnum.BLOCK_COLLECTOR)
    ev1 = RawEndpointTelemetryEvent(
        event_id="ev-1",
        sequence_number=1,
        event_type=EndpointEventTypeEnum.PROCESS,
        event_time=datetime.now(timezone.utc),
        collector_id="p",
        priority=EventPriorityEnum.NORMAL,
        payload={}
    )
    ev2 = RawEndpointTelemetryEvent(
        event_id="ev-2",
        sequence_number=2,
        event_type=EndpointEventTypeEnum.PROCESS,
        event_time=datetime.now(timezone.utc),
        collector_id="p",
        priority=EventPriorityEnum.NORMAL,
        payload={}
    )

    assert buf.append(ev1) is True
    # Second should be blocked / rejected
    assert buf.append(ev2) is False
    assert buf.pending_count() == 1


# =============================================================================
# 2. PRIVACY FILTER & REDACTION TESTS
# =============================================================================

def test_privacy_filter_redaction():
    pf = PrivacyFilter()

    sensitive_payload = {
        "user": "analyst1",
        "command": "curl -H 'Authorization: Bearer my-secret-jwt-token-123456789' https://api.internal",
        "env": {
            "DB_PASSWORD": "SuperSecretPassword123!",
            "API_KEY": "AKIA1234567890ABCDEF",
            "OTHER_VAR": "benign_value"
        },
        "session_cookie": "sess_9876543210abcdef"
    }

    sanitized = pf.sanitize_payload(sensitive_payload)

    # Key-level redaction
    assert sanitized["env"]["DB_PASSWORD"] == "[REDACTED]"
    assert sanitized["env"]["API_KEY"] == "[REDACTED]"
    assert sanitized["session_cookie"] == "[REDACTED]"
    assert sanitized["env"]["OTHER_VAR"] == "benign_value"

    # Pattern-level string redaction
    assert "my-secret-jwt-token" not in sanitized["command"]
    assert "Bearer [REDACTED]" in sanitized["command"]


def test_privacy_filter_exclusions():
    pf = PrivacyFilter(
        excluded_paths=["*/Documents/Personal/*"],
        excluded_processes=["1Password*"],
        excluded_users=["backup_daemon"]
    )

    # Excluded path
    assert pf.should_collect("FILE_METADATA", {"file_path": "/Users/alice/Documents/Personal/notes.txt"}) is False
    assert pf.should_collect("FILE_METADATA", {"file_path": "/etc/hosts"}) is True

    # Excluded process
    assert pf.should_collect("PROCESS", {"process_name": "1Password-Agent"}) is False
    assert pf.should_collect("PROCESS", {"process_name": "python3"}) is True

    # Excluded user
    assert pf.should_collect("AUTHENTICATION", {"username": "backup_daemon"}) is False
    assert pf.should_collect("AUTHENTICATION", {"username": "secadmin"}) is True


# =============================================================================
# 3. AGENT SECURITY CONTROLLER TESTS
# =============================================================================

def test_security_controller_signing_and_rotation():
    sec = AgentSecurityController(
        agent_id="AGT-TEST01",
        key_id="KEY-001",
        credential_secret="secret-key-material-123",
        server_public_or_hmac_key="server-hmac-key"
    )

    headers = sec.sign_request("POST", "/api/v1/endpoint/events", b'{"test": 1}')
    assert headers["X-CyberGuard-Agent-ID"] == "AGT-TEST01"
    assert headers["X-CyberGuard-Key-ID"] == "KEY-001"
    assert "X-CyberGuard-Signature" in headers
    assert "X-CyberGuard-Nonce" in headers

    # Credential rotation staging and commit
    sec.stage_rotated_credential("KEY-002", "new-secret-456")
    assert sec.key_id == "KEY-001"  # Not yet committed
    sec.commit_rotated_credential()
    assert sec.key_id == "KEY-002"
    assert sec.credential_secret == "new-secret-456"

    # Revocation wipes secret
    sec.revoke()
    assert sec.is_revoked is True
    with pytest.raises(PermissionError):
        sec.sign_request("GET", "/api/v1/endpoint/configuration")


# =============================================================================
# 4. COLLECTOR REGISTRY & FAULT ISOLATION TESTS
# =============================================================================

class FailingCollector(EndpointCollector):
    def initialize(self, config): return True
    def start(self):
        self.is_running = True
        return True
    def stop(self):
        self.is_running = False
        return True
    def collect(self):
        raise RuntimeError("Simulated collector hardware fault!")


def test_collector_registry_fault_isolation():
    reg = CollectorRegistry()

    synth = SyntheticCollector("synth_ok")
    synth.initialize({})
    synth.start()

    failing = FailingCollector(CollectorCapability(
        collector_id="faulty_col",
        collector_version="1.0.0",
        supported_platforms=["macos", "windows", "linux"],
        enabled=True
    ))
    failing.start()

    reg.register(synth)
    reg.register(failing)

    # Calling collect_all should NOT crash; synth should yield events while failing records error
    events = reg.collect_all()
    assert len(events) > 0
    assert failing.failure_count == 1
    assert "Simulated collector hardware fault" in failing.last_error

    h = reg.get_health_summary()
    assert h["total_failures"] == 1
    assert h["total_running"] == 2


# =============================================================================
# 5. SYNTHETIC COLLECTOR TESTS
# =============================================================================

def test_synthetic_collector_events():
    synth = SyntheticCollector()
    synth.initialize({})
    synth.start()

    events = synth.collect()
    assert len(events) == 5
    types = {e["event_type"].value for e in events}
    assert "PROCESS" in types
    assert "DNS" in types
    assert "NETWORK" in types
    assert "AUTHENTICATION" in types
    assert "FILE_METADATA" in types

    for ev in events:
        assert ev["payload"].get("synthetic") is True


# =============================================================================
# 6. AGENT RUNTIME & STRICT SECURITY BOUNDARY TESTS
# =============================================================================

def test_agent_runtime_collection_cycle():
    reg = CollectorRegistry()
    synth = SyntheticCollector()
    synth.initialize({})
    reg.register(synth)

    buf = LocalEventBuffer()
    runtime = AgentRuntime(
        agent_id="AGT-TEST",
        device_id="DEV-TEST",
        buffer=buf,
        registry=reg
    )
    runtime.start()

    new_events = runtime.run_collection_cycle()
    assert new_events == 5
    assert buf.pending_count() == 5

    # Events in buffer should have monotonic sequence numbers
    peeked = buf.peek(max_count=5)
    seqs = [e.sequence_number for e in peeked]
    assert sorted(seqs) == list(range(1, 6))

    runtime.stop()


def test_agent_runtime_security_boundary_enforcement():
    """
    CRITICAL: Verify that arbitrary execution or remote shells
    are strictly prohibited and raise SecurityViolationException.
    """
    runtime = AgentRuntime(agent_id="AGT-SAFE", device_id="DEV-SAFE")

    with pytest.raises(SecurityViolationException) as exc1:
        runtime.execute_command("rm -rf /")
    assert "remote command execution" in str(exc1.value)

    with pytest.raises(SecurityViolationException) as exc2:
        runtime.spawn_shell("/bin/bash")
    assert "Remote shell" in str(exc2.value)
