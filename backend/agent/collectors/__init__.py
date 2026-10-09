"""
Section 32: Endpoint Telemetry Collectors Package.
Exports all platform-aware telemetry collectors, adapters, and hashing utilities.
"""

from backend.agent.collectors.base import BaseTelemetryCollector
from backend.agent.collectors.process import ProcessTelemetryCollector
from backend.agent.collectors.network import NetworkTelemetryCollector
from backend.agent.collectors.dns import DNSTelemetryCollector
from backend.agent.collectors.auth import AuthenticationTelemetryCollector
from backend.agent.collectors.system_security import SystemSecurityTelemetryCollector
from backend.agent.collectors.file_metadata import FileMetadataTelemetryCollector
from backend.agent.collectors.device_health import DeviceHealthTelemetryCollector
from backend.agent.collectors.platform_adapters import (
    PlatformAdapter,
    MacOSAdapter,
    LinuxAdapter,
    WindowsAdapter,
    get_platform_adapter
)
from backend.agent.collectors.hashing import BinaryHashCache

__all__ = [
    "BaseTelemetryCollector",
    "ProcessTelemetryCollector",
    "NetworkTelemetryCollector",
    "DNSTelemetryCollector",
    "AuthenticationTelemetryCollector",
    "SystemSecurityTelemetryCollector",
    "FileMetadataTelemetryCollector",
    "DeviceHealthTelemetryCollector",
    "PlatformAdapter",
    "MacOSAdapter",
    "LinuxAdapter",
    "WindowsAdapter",
    "get_platform_adapter",
    "BinaryHashCache"
]
