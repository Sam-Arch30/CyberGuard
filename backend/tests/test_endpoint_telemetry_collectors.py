"""
Unit tests for Section 32: Endpoint Telemetry Collectors.
Tests all 7 collectors, hashing cache, platform adapters, secret redaction,
exclusion rules, resource limits, and capability states.
"""

import os
import sys
import tempfile
import time
from datetime import datetime, timezone
import pytest

from backend.schemas.endpoint_agent import (
    CollectorCapabilityStateEnum,
    EventPriorityEnum,
    EndpointEventTypeEnum
)
from backend.agent.collectors.base import BaseTelemetryCollector
from backend.agent.collectors.hashing import BinaryHashCache
from backend.agent.collectors.platform_adapters import (
    MacOSAdapter,
    LinuxAdapter,
    WindowsAdapter,
    get_platform_adapter
)
from backend.agent.collectors.process import ProcessTelemetryCollector
from backend.agent.collectors.network import NetworkTelemetryCollector
from backend.agent.collectors.dns import DNSTelemetryCollector
from backend.agent.collectors.auth import AuthenticationTelemetryCollector
from backend.agent.collectors.system_security import SystemSecurityTelemetryCollector
from backend.agent.collectors.file_metadata import FileMetadataTelemetryCollector
from backend.agent.collectors.device_health import DeviceHealthTelemetryCollector
from backend.agent.privacy import PrivacyFilter


# ============================================================================
# 1. BINARY HASH CACHE TESTS
# ============================================================================

def test_binary_hash_cache_computation_and_caching():
    cache = BinaryHashCache(max_cache_entries=10, max_file_size_bytes=1024 * 1024)
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(b"CyberGuard binary telemetry test payload")
        tf.flush()
        temp_path = tf.name

    try:
        # First compute -> Cache Miss
        hash1 = cache.compute_sha256(temp_path)
        assert hash1 is not None
        assert len(hash1) == 64
        metrics = cache.get_metrics()
        assert metrics["cache_misses"] == 1
        assert metrics["cache_hits"] == 0

        # Second compute -> Cache Hit
        hash2 = cache.compute_sha256(temp_path)
        assert hash2 == hash1
        metrics = cache.get_metrics()
        assert metrics["cache_hits"] == 1

        # Modify file -> Invalidation & Cache Miss
        time.sleep(0.01)
        with open(temp_path, "wb") as f:
            f.write(b"Modified binary payload")
        hash3 = cache.compute_sha256(temp_path)
        assert hash3 is not None
        assert hash3 != hash1
        metrics = cache.get_metrics()
        assert metrics["cache_misses"] == 2
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def test_binary_hash_cache_oversized_file():
    # Max size 100 bytes
    cache = BinaryHashCache(max_file_size_bytes=100)
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(b"A" * 200)
        tf.flush()
        temp_path = tf.name

    try:
        result = cache.compute_sha256(temp_path)
        assert result == "OVERSIZED_SKIPPED"
        metrics = cache.get_metrics()
        assert metrics["oversized_skipped"] == 1
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def test_binary_hash_cache_nonexistent_and_invalid():
    cache = BinaryHashCache()
    assert cache.compute_sha256("/nonexistent/file/path.exe") is None
    assert cache.compute_sha256("") is None
    assert cache.compute_sha256(None) is None


# ============================================================================
# 2. BASE COLLECTOR & SAMPLING POLICY TESTS
# ============================================================================

class DummyCollector(BaseTelemetryCollector):
    def collect(self):
        return []


def test_base_collector_lifecycle_and_capability():
    c = DummyCollector(
        collector_id="dummy_test",
        collector_type="DUMMY",
        platform="macos",
        capability_state=CollectorCapabilityStateEnum.AVAILABLE
    )
    assert c.is_running is False
    assert c.start() is True
    assert c.is_running is True

    health = c.health()
    assert health["collector_id"] == "dummy_test"
    assert health["capability_state"] == "AVAILABLE"
    assert health["is_running"] is True

    assert c.stop() is True
    assert c.is_running is False


def test_base_collector_unavailable_state():
    c = DummyCollector(
        collector_id="dummy_unavail",
        collector_type="DUMMY",
        platform="windows",
        capability_state=CollectorCapabilityStateEnum.UNAVAILABLE
    )
    # Unavailable collector must refuse to start and never emit events
    assert c.start() is False
    assert c.is_running is False


def test_base_collector_sampling_policy():
    c = DummyCollector(
        collector_id="dummy_sample",
        collector_type="DUMMY",
        platform="macos",
        sampling_rate=0.0  # Drop all normal/low events
    )
    # CRITICAL and HIGH priority events must NEVER be dropped
    assert c.should_sample_event(EventPriorityEnum.CRITICAL) is True
    assert c.should_sample_event(EventPriorityEnum.HIGH) is True

    # NORMAL and LOW priority events are dropped when rate is 0.0
    assert c.should_sample_event(EventPriorityEnum.NORMAL) is False
    assert c.should_sample_event(EventPriorityEnum.LOW) is False
    assert c.events_dropped_total == 2


# ============================================================================
# 3. PLATFORM ADAPTER TESTS
# ============================================================================

def test_platform_adapter_darwin_detection():
    adapter = get_platform_adapter()
    if sys.platform == "darwin":
        assert isinstance(adapter, MacOSAdapter)
        assert adapter.is_supported() is True
        assert adapter.get_platform_name() == "macos"
    else:
        assert adapter.get_platform_name() in ("linux", "windows")


def test_platform_adapters_cross_platform_safety():
    # Linux and Windows adapters on macOS should cleanly report unsupported
    if sys.platform == "darwin":
        linux_adapter = LinuxAdapter()
        assert linux_adapter.is_supported() is False
        assert linux_adapter.get_running_processes() == []
        assert linux_adapter.get_network_connections() == []
        assert linux_adapter.get_system_security_posture()["status"] == "UNAVAILABLE"

        win_adapter = WindowsAdapter()
        assert win_adapter.is_supported() is False
        assert win_adapter.get_running_processes() == []
        assert win_adapter.get_host_vitals() == {"platform": "windows"}


def test_macos_adapter_live_inspections():
    if sys.platform != "darwin":
        pytest.skip("Test requires macOS Darwin host")

    adapter = MacOSAdapter()
    assert adapter.is_supported() is True

    # 1. Process table
    procs = adapter.get_running_processes(max_count=10)
    assert isinstance(procs, list)
    assert len(procs) > 0
    p0 = procs[0]
    assert "process_id" in p0
    assert "process_name" in p0
    assert "executable_path" in p0

    # 2. Network connections
    conns = adapter.get_network_connections(max_count=10)
    assert isinstance(conns, list)

    # 3. DNS configuration
    dns_cfg = adapter.get_dns_configuration()
    assert "nameservers" in dns_cfg
    assert isinstance(dns_cfg["nameservers"], list)

    # 4. Security posture
    posture = adapter.get_system_security_posture()
    assert posture["platform"] == "macos"
    assert "system_integrity_protection" in posture

    # 5. Host vitals
    vitals = adapter.get_host_vitals()
    assert vitals["platform"] == "macos"
    assert "memory_usage_mb" in vitals
    assert vitals["memory_usage_mb"] >= 0.0
    assert "disk_free_mb" in vitals


# ============================================================================
# 4. PROCESS TELEMETRY COLLECTOR TESTS
# ============================================================================

def test_process_collector_lifecycle_and_collection():
    collector = ProcessTelemetryCollector()
    collector.initialize({"sampling_rate": 1.0, "max_events_per_cycle": 5})
    assert collector.start() is True

    events = collector.collect()
    assert isinstance(events, list)
    if collector.capability_state == CollectorCapabilityStateEnum.AVAILABLE:
        assert len(events) > 0
        e0 = events[0]
        assert e0["event_type"] == EndpointEventTypeEnum.PROCESS
        assert e0["collector_id"] == "process_telemetry_collector"
        payload = e0["payload"]
        assert "process_id" in payload
        assert "parent_process_id" in payload
        assert "process_name" in payload
        assert "executable_hash" in payload
        assert payload["lifecycle_action"] in ("STARTED", "RUNNING")

    collector.stop()


def test_process_collector_secret_redaction_in_cmdline():
    collector = ProcessTelemetryCollector()
    collector.start()

    # Pass command line with embedded credential into privacy filter
    dirty_cmd = "/usr/bin/curl -u admin:SuperSecretP@ssword123 https://api.internal/data --header 'Authorization: Bearer my-top-secret-token'"
    redacted_payload = collector.privacy.sanitize_payload({"command_line": dirty_cmd})
    redacted_cmd = redacted_payload["command_line"]

    assert "SuperSecretP@ssword123" not in redacted_cmd
    assert "my-top-secret-token" not in redacted_cmd
    assert "[REDACTED]" in redacted_cmd


# ============================================================================
# 5. NETWORK TELEMETRY COLLECTOR TESTS
# ============================================================================

def test_network_collector_collection_and_priority():
    collector = NetworkTelemetryCollector()
    collector.initialize({"sampling_rate": 1.0})
    collector.start()

    # Verify loopback/private IP detection helper
    assert collector._is_private_or_loopback("127.0.0.1") is True
    assert collector._is_private_or_loopback("::1") is True
    assert collector._is_private_or_loopback("192.168.1.10") is True
    assert collector._is_private_or_loopback("10.0.0.5") is True
    assert collector._is_private_or_loopback("172.16.5.1") is True
    # Public IP
    assert collector._is_private_or_loopback("203.0.113.10") is False

    events = collector.collect()
    assert isinstance(events, list)
    collector.stop()


# ============================================================================
# 6. DNS TELEMETRY COLLECTOR TESTS
# ============================================================================

def test_dns_collector_domain_normalization_and_nxdomain():
    collector = DNSTelemetryCollector()
    collector.start()

    # Record observation with uppercase and trailing dot
    collector.record_observation(
        domain="Phishing-Site.EXAMPLE.COM.",
        query_type="A",
        resolved_ips=["203.0.113.10"],
        response_status="NOERROR",
        process_name="curl"
    )

    # Record NXDOMAIN query (should receive HIGH priority)
    collector.record_observation(
        domain="nonexistent-c2.example.",
        query_type="AAAA",
        resolved_ips=[],
        response_status="NXDOMAIN",
        process_name="malware_stub"
    )

    events = collector.collect()
    assert len(events) >= 2

    # Find the normal event
    e_normal = [e for e in events if e["payload"].get("queried_domain") == "phishing-site.example.com"][0]
    assert e_normal["payload"]["query_type"] == "A"
    assert e_normal["payload"]["resolved_addresses"] == ["203.0.113.10"]
    assert e_normal["priority"] == EventPriorityEnum.NORMAL

    # Find the NXDOMAIN event
    e_nx = [e for e in events if e["payload"].get("queried_domain") == "nonexistent-c2.example"][0]
    assert e_nx["priority"] == EventPriorityEnum.HIGH

    collector.stop()


# ============================================================================
# 7. AUTHENTICATION TELEMETRY COLLECTOR TESTS
# ============================================================================

def test_authentication_collector_events_and_privacy():
    collector = AuthenticationTelemetryCollector()
    collector.start()

    # Record login failure (HIGH priority)
    collector.record_auth_event(
        action="LOGIN_FAILURE",
        username="secops_analyst",
        auth_method="PASSWORD",
        status="FAILURE",
        source_ip="198.51.100.25",
        terminal="ssh"
    )

    # Record login success (NORMAL priority)
    collector.record_auth_event(
        action="LOGIN_SUCCESS",
        username="secops_analyst",
        auth_method="MFA_U2F",
        status="SUCCESS",
        source_ip="198.51.100.25",
        terminal="ssh"
    )

    events = collector.collect()
    assert len(events) >= 2

    fail_ev = [e for e in events if e["payload"].get("action") == "LOGIN_FAILURE"][0]
    assert fail_ev["priority"] == EventPriorityEnum.HIGH
    assert fail_ev["payload"]["username"] == "secops_analyst"
    # STRICT PRIVACY: verify no password fields exist
    assert "password" not in fail_ev["payload"]
    assert "secret" not in fail_ev["payload"]

    succ_ev = [e for e in events if e["payload"].get("action") == "LOGIN_SUCCESS"][0]
    assert succ_ev["priority"] == EventPriorityEnum.NORMAL
    assert succ_ev["payload"]["auth_method"] == "MFA_U2F"

    collector.stop()


# ============================================================================
# 8. SYSTEM SECURITY TELEMETRY COLLECTOR TESTS
# ============================================================================

def test_system_security_collector():
    collector = SystemSecurityTelemetryCollector()
    collector.start()

    # Record discrete security incident
    collector.record_security_event(
        event_name="SIP_CONFIGURATION_WARNING",
        category="POLICY_CHANGE",
        severity="CRITICAL",
        details={"reason": "Security control modification attempt detected"}
    )

    events = collector.collect()
    assert len(events) >= 1

    sec_ev = [e for e in events if e["payload"].get("event_name") == "SIP_CONFIGURATION_WARNING"][0]
    assert sec_ev["priority"] == EventPriorityEnum.HIGH
    assert sec_ev["payload"]["category"] == "POLICY_CHANGE"

    collector.stop()


# ============================================================================
# 9. FILE METADATA TELEMETRY COLLECTOR TESTS
# ============================================================================

def test_file_metadata_collector_hashing_and_exclusions():
    collector = FileMetadataTelemetryCollector(
        excluded_paths=["*/Documents/Personal/*", "*/.ssh/*"],
        excluded_extensions=[".tmp", ".swp"]
    )
    collector.start()

    # 1. Path exclusion check
    assert collector.is_path_excluded("/Users/alice/Documents/Personal/notes.txt") is True
    assert collector.is_path_excluded("/Users/alice/.ssh/id_rsa") is True
    assert collector.is_path_excluded("/tmp/test.tmp") is True
    assert collector.is_path_excluded("/etc/hosts") is False

    # 2. Record temporary file creation
    with tempfile.NamedTemporaryFile(suffix=".conf", delete=False) as tf:
        tf.write(b"Listen 8080\nServerName test.example")
        tf.flush()
        temp_file = tf.name

    try:
        collector.record_file_event(
            action="FILE_CREATED",
            file_path=temp_file,
            process_name="nginx",
            username="root",
            calculate_hash=True
        )

        events = collector.collect()
        assert len(events) == 1
        ev = events[0]
        assert ev["event_type"] == EndpointEventTypeEnum.FILE_METADATA
        payload = ev["payload"]
        assert payload["action"] == "FILE_CREATED"
        assert payload["filename"] == os.path.basename(temp_file)
        assert payload["extension"] == ".conf"
        assert payload["sha256"] != "UNKNOWN"
        assert len(payload["sha256"]) == 64
        # Verify no file contents collected
        assert "content" not in payload
        assert "body" not in payload
    finally:
        if os.path.exists(temp_file):
            os.remove(temp_file)

    collector.stop()


# ============================================================================
# 10. DEVICE HEALTH TELEMETRY COLLECTOR TESTS
# ============================================================================

def test_device_health_collector():
    collector = DeviceHealthTelemetryCollector(agent_version="1.0.0")
    collector.start()

    events = collector.collect()
    if collector.capability_state == CollectorCapabilityStateEnum.AVAILABLE:
        assert len(events) == 1
        ev = events[0]
        assert ev["event_type"] == EndpointEventTypeEnum.DEVICE_HEALTH
        payload = ev["payload"]
        assert payload["agent_version"] == "1.0.0"
        assert "agent_uptime_seconds" in payload
        assert "memory_usage_mb" in payload
        assert "disk_free_mb" in payload
        assert "under_pressure" in payload

    collector.stop()
