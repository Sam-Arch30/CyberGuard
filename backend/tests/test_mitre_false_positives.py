"""
Comprehensive False-Positive Guardrail Tests for MITRE ATT&CK Mapping (Section 72).
Verifies that benign behaviors, normal baselines, and incomplete signals
do NOT automatically become ATT&CK technique mappings.
"""
from __future__ import annotations

import pytest

from backend.schemas.mitre_attack import (
    AttackMappingStatus,
    EnvironmentContextConfig,
)
from backend.services.mitre_mapping_engine import MITREAttackMappingEngine


@pytest.fixture
def engine():
    return MITREAttackMappingEngine()


def test_fp_01_single_failed_login(engine):
    """FP 1: A single failed login must NOT trigger Brute Force or Password Spraying."""
    finding = {
        "id": "fp-single-fail",
        "finding_type": "AUTH_FAILURE",
        "metadata": {
            "account_count": 1,
            "failed_attempts": 1,  # isolated single mistyped password
            "source_ip": "192.168.1.50",
        }
    }
    mappings = engine.map_finding(finding)
    # Must have ZERO supported brute force or spraying mappings
    supported = [m for m in mappings if m.status == AttackMappingStatus.SUPPORTED]
    assert len(supported) == 0


def test_fp_02_normal_employee_login(engine):
    """FP 2: Normal successful login must NOT trigger any ATT&CK technique."""
    event = {
        "id": "fp-normal-login",
        "event_type": "AUTH_SUCCESS",
        "summary": "Normal user authentication",
        "attributes": {
            "user": "alice@corp.internal",
            "is_anomaly": False,
            "mfa_verified": True,
        }
    }
    mappings = engine.map_event(event)
    supported = [m for m in mappings if m.status == AttackMappingStatus.SUPPORTED]
    assert len(supported) == 0


def test_fp_03_ordinary_vpn_activity(engine):
    """FP 3: Ordinary corporate VPN connection must NOT trigger C2 or Lateral Movement."""
    config = EnvironmentContextConfig(corporate_vpn_ranges=["10.50.0.0/16"])
    engine.set_environment_config(config)

    event = {
        "id": "fp-vpn-egress",
        "event_type": "VPN_SESSION_START",
        "attributes": {
            "source_ip": "10.50.12.3",
            "is_corporate_vpn": True,
        }
    }
    mappings = engine.map_event(event)
    supported = [m for m in mappings if m.status == AttackMappingStatus.SUPPORTED]
    assert len(supported) == 0


def test_fp_04_common_cdn_ip(engine):
    """FP 4: Traffic to a common CDN (Cloudflare, Akamai) must NOT map to C2."""
    finding = {
        "id": "fp-cdn-traffic",
        "finding_type": "OUTBOUND_CONNECTION",
        "metadata": {
            "destination_ip": "104.16.123.96",
            "is_cdn": True,
            "is_confirmed_c2_beacon": False,
        }
    }
    mappings = engine.map_finding(finding)
    supported = [m for m in mappings if m.status == AttackMappingStatus.SUPPORTED]
    assert len(supported) == 0


def test_fp_05_periodic_health_checks(engine):
    """FP 5: Periodic HTTP health check traffic must NOT map to C2 beaconing."""
    config = EnvironmentContextConfig(monitoring_systems=["10.0.1.100"])
    engine.set_environment_config(config)

    finding = {
        "id": "fp-health-check",
        "finding_type": "PERIODIC_DNS_QUERY",
        "metadata": {
            "source_ip": "10.0.1.100",
            "domain": "healthz.internal.service",
            "is_confirmed_c2_beacon": False,
        }
    }
    mappings = engine.map_finding(finding)
    supported = [m for m in mappings if m.status == AttackMappingStatus.SUPPORTED]
    assert len(supported) == 0


def test_fp_06_legitimate_monitoring(engine):
    """FP 6: Prometheus / Datadog telemetry scraping must NOT map to Discovery or Collection."""
    config = EnvironmentContextConfig(monitoring_systems=["172.16.5.20"])
    engine.set_environment_config(config)

    finding = {
        "id": "fp-prometheus",
        "finding_type": "API_ENUMERATION",
        "metadata": {
            "source_ip": "172.16.5.20",
            "caller_identity": "prometheus-agent",
            "distinct_resources": 50,
        }
    }
    mappings = engine.map_finding(finding)
    supported = [m for m in mappings if m.status == AttackMappingStatus.SUPPORTED]
    assert len(supported) == 0


def test_fp_07_security_scanner_suppression(engine):
    """FP 7: Tenable / Nessus security scanner probes must NOT trigger Brute Force."""
    config = EnvironmentContextConfig(trusted_scanners=["10.200.1.5"])
    engine.set_environment_config(config)

    finding = {
        "id": "fp-nessus-probe",
        "finding_type": "PASSWORD_SPRAYING",
        "metadata": {
            "source_ip": "10.200.1.5",
            "distinct_accounts": 50,
            "attempt_count": 80,
        }
    }
    mappings = engine.map_finding(finding)
    # Must be marked REJECTED, never SUPPORTED
    for m in mappings:
        assert m.status == AttackMappingStatus.REJECTED


def test_fp_08_normal_api_pagination(engine):
    """FP 8: Normal API pagination (e.g. GET /items?page=1..10) must NOT map to Discovery."""
    finding = {
        "id": "fp-pagination",
        "finding_type": "HTTP_REQUESTS",
        "metadata": {
            "endpoint": "/api/v1/inventory",
            "is_api_enumeration": False,
            "error_count": 0,
            "distinct_resources": 10,
        }
    }
    mappings = engine.map_finding(finding)
    supported = [m for m in mappings if m.status == AttackMappingStatus.SUPPORTED]
    assert len(supported) == 0


def test_fp_09_authorized_bulk_export(engine):
    """FP 9: Normal bulk export by authorized service account must NOT map to Discovery."""
    config = EnvironmentContextConfig(authorized_service_accounts=["data-warehouse-sync@cloud.org"])
    engine.set_environment_config(config)

    finding = {
        "id": "fp-dw-export",
        "finding_type": "API_ENUMERATION",
        "metadata": {
            "caller_identity": "data-warehouse-sync@cloud.org",
            "distinct_resources": 1000,
            "error_count": 0,
        }
    }
    mappings = engine.map_finding(finding)
    supported = [m for m in mappings if m.status == AttackMappingStatus.SUPPORTED]
    assert len(supported) == 0


def test_fp_10_suspicious_filename_without_execution(engine):
    """FP 10: Suspicious filename on disk without execution telemetry must NOT map to Execution."""
    finding = {
        "id": "fp-filename",
        "finding_type": "SUSPICIOUS_SCRIPT_ATTACHMENT",
        "metadata": {
            "filename": "totally_legit_invoice.ps1",
            "state": "FILE_PRESENT",
            "process_created": False,
        }
    }
    mappings = engine.map_finding(finding)
    # T1059.001 must NOT be SUPPORTED
    supported_exec = [m for m in mappings if m.technique_id == "T1059.001" and m.status == AttackMappingStatus.SUPPORTED]
    assert len(supported_exec) == 0


def test_fp_11_brand_name_in_email_without_impersonation(engine):
    """FP 11: Simply mentioning 'Microsoft' or 'Google' in text must NOT map to T1656 Impersonation."""
    finding = {
        "id": "fp-brand-mention",
        "finding_type": "TEXT_ANALYSIS",
        "metadata": {
            "body_snippet": "We discussed our partnership with Google and Microsoft today.",
            "is_impersonation": False,
            "display_name_spoofed": False,
        }
    }
    mappings = engine.map_finding(finding)
    supported = [m for m in mappings if m.status == AttackMappingStatus.SUPPORTED]
    assert len(supported) == 0


def test_fp_12_deepfake_signal_without_adversarial_context(engine):
    """FP 12: Media synthesis signal alone without attack context remains CyberGuard finding, not forced into ATT&CK."""
    finding = {
        "id": "fp-deepfake",
        "finding_type": "MEDIA_SYNTHESIS_SIGNAL",
        "metadata": {
            "synthetic_score": 0.82,
            "has_adversarial_context": False,
        }
    }
    mappings = engine.map_finding(finding)
    # Custom CyberGuard signal is preserved without being forced into an ungrounded ATT&CK technique
    supported = [m for m in mappings if m.status == AttackMappingStatus.SUPPORTED]
    assert len(supported) == 0


def test_fp_13_high_outbound_traffic_alone(engine):
    """FP 13: High outbound network volume alone must NOT automatically become SUPPORTED exfiltration."""
    finding = {
        "id": "fp-high-transfer",
        "finding_type": "HIGH_OUTBOUND_DATA",
        "metadata": {
            "bytes_transferred": 200000000,
            "destination": "storage.googleapis.com",
            "sensitive_resource_accessed": False,  # Gap
        }
    }
    mappings = engine.map_finding(finding)
    # Must NOT be marked SUPPORTED
    supported = [m for m in mappings if m.technique_id in ("T1048", "T1041") and m.status == AttackMappingStatus.SUPPORTED]
    assert len(supported) == 0
    # Can remain PLAUSIBLE with limitations documented
    plausible = [m for m in mappings if m.technique_id == "T1048" and m.status == AttackMappingStatus.PLAUSIBLE]
    assert len(plausible) >= 1
