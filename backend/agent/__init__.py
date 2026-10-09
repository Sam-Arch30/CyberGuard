"""
Section 31: Endpoint Agent Architecture Package.
"""

from backend.agent.collector_registry import (
    EndpointCollector,
    CollectorCapability,
    CollectorRegistry
)
from backend.agent.buffer import LocalEventBuffer
from backend.agent.privacy import PrivacyFilter
from backend.agent.security import AgentSecurityController
from backend.agent.transport import AgentTransportClient
from backend.agent.health import AgentHealthReporter
from backend.agent.synthetic import SyntheticCollector
from backend.agent.runtime import AgentRuntime, SecurityViolationException

from backend.agent.collectors import (
    BaseTelemetryCollector,
    ProcessTelemetryCollector,
    NetworkTelemetryCollector,
    DNSTelemetryCollector,
    AuthenticationTelemetryCollector,
    SystemSecurityTelemetryCollector,
    FileMetadataTelemetryCollector,
    DeviceHealthTelemetryCollector,
    PlatformAdapter,
    MacOSAdapter,
    LinuxAdapter,
    WindowsAdapter,
    get_platform_adapter,
    BinaryHashCache
)

__all__ = [
    "EndpointCollector",
    "CollectorCapability",
    "CollectorRegistry",
    "LocalEventBuffer",
    "PrivacyFilter",
    "AgentSecurityController",
    "AgentTransportClient",
    "AgentHealthReporter",
    "SyntheticCollector",
    "AgentRuntime",
    "SecurityViolationException",
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
