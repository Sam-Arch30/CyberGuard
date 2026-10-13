"""
Network and Traffic Anomaly Analyzers.
Provides IP scope classification, direction normalization, adapter ingestion,
connection pattern analysis, beaconing/periodicity metrics, DNS anomalies,
outbound volume / exfiltration signals, and multi-category pattern aggregation.
"""
from __future__ import annotations

import csv
import io
import math
import re
import uuid
import ipaddress
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple, Set
from collections import defaultdict

from backend.schemas.unified import SeverityEnum
from backend.schemas.network_security import (
    NetworkEventTypeEnum,
    NetworkProtocolEnum,
    TrafficDirectionEnum,
    IPScopeEnum,
    NetworkCategoryEnum,
    NormalizedNetworkEvent,
    PeriodicityMetrics,
    DeviceNetworkProfile,
    NetworkFindingItem,
    NetworkFindingEvidenceItem,
    NetworkConfigResponse,
)


# ============================================================================
# IP & DIRECTION CLASSIFIER
# ============================================================================

class IPClassifier:
    """
    Classifies IP scope and determines traffic direction relative to configured internal CIDRs.
    """
    @staticmethod
    def parse_ip(ip_str: Optional[str]) -> Optional[ipaddress.IPv4Address | ipaddress.IPv6Address]:
        if not ip_str:
            return None
        clean = ip_str.strip().split("%")[0]  # Strip IPv6 zone index if present
        try:
            return ipaddress.ip_address(clean)
        except ValueError:
            return None

    @classmethod
    def get_scope(cls, ip_str: Optional[str]) -> IPScopeEnum:
        ip = cls.parse_ip(ip_str)
        if not ip:
            return IPScopeEnum.UNKNOWN
        if ip.is_loopback:
            return IPScopeEnum.LOOPBACK
        if ip.is_link_local:
            return IPScopeEnum.LINK_LOCAL
        if ip.is_multicast:
            return IPScopeEnum.MULTICAST
        if ip.is_reserved:
            return IPScopeEnum.RESERVED
        if ip.is_private:
            return IPScopeEnum.PRIVATE
        if ip.is_global:
            return IPScopeEnum.PUBLIC
        return IPScopeEnum.UNKNOWN

    @classmethod
    def is_internal(cls, ip_str: Optional[str], internal_cidrs: List[str]) -> bool:
        ip = cls.parse_ip(ip_str)
        if not ip:
            return False
        for cidr in internal_cidrs:
            try:
                if ip in ipaddress.ip_network(cidr, strict=False):
                    return True
            except ValueError:
                continue
        return False

    @classmethod
    def get_direction(
        cls,
        src_ip: Optional[str],
        dst_ip: Optional[str],
        internal_cidrs: List[str],
    ) -> TrafficDirectionEnum:
        src_int = cls.is_internal(src_ip, internal_cidrs)
        dst_int = cls.is_internal(dst_ip, internal_cidrs) if dst_ip else None

        if dst_ip is None:
            return TrafficDirectionEnum.OUTBOUND if src_int else TrafficDirectionEnum.UNKNOWN

        if src_int and not dst_int:
            return TrafficDirectionEnum.OUTBOUND
        if not src_int and dst_int:
            return TrafficDirectionEnum.INBOUND
        if src_int and dst_int:
            return TrafficDirectionEnum.INTERNAL
        return TrafficDirectionEnum.UNKNOWN


# ============================================================================
# SOURCE ADAPTER ARCHITECTURE
# ============================================================================

class BaseNetworkAdapter:
    """Base class for network telemetry log adapters."""
    provider_name: str = "generic"
    version: str = "1.0.0"

    def can_handle(self, raw_event: Any) -> bool:
        raise NotImplementedError

    def normalize(self, raw_event: Any, internal_cidrs: Optional[List[str]] = None) -> NormalizedNetworkEvent:
        raise NotImplementedError

    @staticmethod
    def _parse_timestamp(ts_raw: Any) -> datetime:
        if isinstance(ts_raw, datetime):
            return ts_raw.astimezone(timezone.utc)
        if isinstance(ts_raw, (int, float)):
            sec = ts_raw / 1000.0 if ts_raw > 1e11 else ts_raw
            return datetime.fromtimestamp(sec, tz=timezone.utc)
        if isinstance(ts_raw, str) and ts_raw.strip():
            clean = ts_raw.strip()
            try:
                if clean.endswith("Z"):
                    clean = clean[:-1] + "+00:00"
                dt = datetime.fromisoformat(clean)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.astimezone(timezone.utc)
            except Exception:
                pass
        return datetime.now(timezone.utc)

    @staticmethod
    def _parse_protocol(proto_raw: Any) -> NetworkProtocolEnum:
        s = str(proto_raw or "").upper().strip()
        if "TCP" in s or s == "6":
            return NetworkProtocolEnum.TCP
        if "UDP" in s or s == "17":
            return NetworkProtocolEnum.UDP
        if "ICMP" in s or s == "1":
            return NetworkProtocolEnum.ICMP
        if "DNS" in s:
            return NetworkProtocolEnum.DNS
        if "HTTPS" in s or s == "443":
            return NetworkProtocolEnum.HTTPS
        if "HTTP" in s or s == "80":
            return NetworkProtocolEnum.HTTP
        if "SSH" in s or s == "22":
            return NetworkProtocolEnum.SSH
        if "TLS" in s:
            return NetworkProtocolEnum.TLS
        return NetworkProtocolEnum.OTHER


class GenericJsonNetworkAdapter(BaseNetworkAdapter):
    """
    Normalizes standard JSON network connection and flow records.
    """
    provider_name: str = "generic_json"
    version: str = "1.0.0"

    def can_handle(self, raw_event: Any) -> bool:
        if not isinstance(raw_event, dict):
            return False
        return (
            "source_ip" in raw_event or
            "src_ip" in raw_event or
            "src" in raw_event or
            "destination_ip" in raw_event or
            "dst_ip" in raw_event or
            "dst" in raw_event or
            "dns_query" in raw_event or
            "query" in raw_event
        )

    def normalize(self, raw_event: Any, internal_cidrs: Optional[List[str]] = None) -> NormalizedNetworkEvent:
        d = dict(raw_event) if isinstance(raw_event, dict) else {}
        cidrs = internal_cidrs or ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "::1", "fc00::/7"]

        src_ip = str(d.get("source_ip") or d.get("src_ip") or d.get("src") or d.get("client_ip") or "127.0.0.1").strip()
        dst_ip = d.get("destination_ip") or d.get("dst_ip") or d.get("dst") or d.get("server_ip")
        dst_ip = str(dst_ip).strip() if dst_ip else None

        src_port = d.get("source_port") or d.get("src_port") or d.get("sport")
        dst_port = d.get("destination_port") or d.get("dst_port") or d.get("dport")
        try:
            src_port = int(src_port) if src_port is not None else None
        except (ValueError, TypeError):
            src_port = None
        try:
            dst_port = int(dst_port) if dst_port is not None else None
        except (ValueError, TypeError):
            dst_port = None

        protocol = self._parse_protocol(d.get("protocol") or d.get("proto") or (dst_port if dst_port in (80, 443, 53, 22) else "TCP"))

        bytes_sent = d.get("bytes_sent") or d.get("bytes_out") or d.get("bytes_tx") or d.get("orig_bytes") or d.get("sent_bytes")
        bytes_recv = d.get("bytes_received") or d.get("bytes_recv") or d.get("bytes_rx") or d.get("bytes_in") or d.get("resp_bytes") or d.get("rcvd_bytes")
        try:
            bytes_sent = int(bytes_sent) if bytes_sent is not None else None
        except (ValueError, TypeError):
            bytes_sent = None
        try:
            bytes_recv = int(bytes_recv) if bytes_recv is not None else None
        except (ValueError, TypeError):
            bytes_recv = None

        duration = d.get("duration") or d.get("duration_seconds")
        try:
            duration = float(duration) if duration is not None else None
        except (ValueError, TypeError):
            duration = None

        domain = d.get("domain") or d.get("hostname") or d.get("sni")
        dns_query = d.get("dns_query") or d.get("query")
        dns_type = d.get("dns_query_type") or d.get("query_type") or d.get("qtype")
        dns_rcode = d.get("dns_response_code") or d.get("response_code") or d.get("rcode")
        answers = d.get("dns_answers") or d.get("answers") or []
        if isinstance(answers, str):
            answers = [answers]

        event_type = NetworkEventTypeEnum.CONNECTION
        if dns_query or dns_type or protocol == NetworkProtocolEnum.DNS or dst_port == 53:
            event_type = NetworkEventTypeEnum.DNS_QUERY
        elif bytes_sent is not None or bytes_recv is not None:
            event_type = NetworkEventTypeEnum.FLOW

        direction = IPClassifier.get_direction(src_ip, dst_ip, cidrs)
        src_scope = IPClassifier.get_scope(src_ip)
        dst_scope = IPClassifier.get_scope(dst_ip) if dst_ip else IPScopeEnum.UNKNOWN

        status = str(d.get("status") or d.get("state") or "").upper() or None
        action = str(d.get("action") or "").upper() or None

        return NormalizedNetworkEvent(
            id=str(d.get("id") or str(uuid.uuid4())),
            timestamp=self._parse_timestamp(d.get("timestamp") or d.get("time") or d.get("@timestamp")),
            event_type=event_type,
            source_ip=src_ip,
            source_port=src_port,
            destination_ip=dst_ip,
            destination_port=dst_port,
            protocol=protocol,
            direction=direction,
            source_scope=src_scope,
            destination_scope=dst_scope,
            bytes_sent=bytes_sent,
            bytes_received=bytes_recv,
            duration_seconds=duration,
            domain=str(domain).strip().lower() if domain else None,
            dns_query=str(dns_query).strip().lower() if dns_query else None,
            dns_query_type=str(dns_type).upper() if dns_type else None,
            dns_response_code=str(dns_rcode).upper() if dns_rcode else None,
            dns_answers=[str(a).strip() for a in answers if a],
            device_id=d.get("device_id") or d.get("host_id"),
            host_name=d.get("host_name") or d.get("hostname"),
            user_id=d.get("user_id") or d.get("user"),
            session_id=d.get("session_id"),
            action=action,
            status=status,
            provider=str(d.get("provider") or self.provider_name),
            metadata={k: v for k, v in d.items() if k not in ("id", "timestamp")},
        )


class GenericCsvNetworkAdapter(BaseNetworkAdapter):
    """
    Normalizes standard CSV network flow rows.
    """
    provider_name: str = "generic_csv"
    version: str = "1.0.0"

    def can_handle(self, raw_event: Any) -> bool:
        if isinstance(raw_event, dict):
            return (
                ("src_ip" in raw_event or "source_ip" in raw_event) and
                ("dst_ip" in raw_event or "destination_ip" in raw_event)
            )
        if isinstance(raw_event, str):
            # Check if comma-separated line containing IP-like structure
            return "," in raw_event and ("." in raw_event or ":" in raw_event)
        if isinstance(raw_event, list):
            return True
        return False

    def normalize(self, raw_event: Any, internal_cidrs: Optional[List[str]] = None) -> NormalizedNetworkEvent:
        if isinstance(raw_event, dict):
            ev = GenericJsonNetworkAdapter().normalize(raw_event, internal_cidrs=internal_cidrs)
            ev.provider = self.provider_name
            return ev
        if isinstance(raw_event, str):
            reader = csv.reader(io.StringIO(raw_event))
            row = next(reader, [])
        else:
            row = [str(x) for x in raw_event]

        # Best effort positional fallback: [timestamp, src_ip, src_port, dst_ip, dst_port, protocol, bytes_sent, bytes_recv]
        d: Dict[str, Any] = {}
        if len(row) >= 2:
            d["timestamp"] = row[0]
            d["src_ip"] = row[1]
        if len(row) >= 4:
            d["dst_ip"] = row[2]
            d["dst_port"] = row[3]
        if len(row) >= 5:
            d["protocol"] = row[4]
        if len(row) >= 7:
            d["bytes_sent"] = row[5]
            d["bytes_recv"] = row[6]

        return GenericJsonNetworkAdapter().normalize(d, internal_cidrs=internal_cidrs)


class DnsLogAdapter(BaseNetworkAdapter):
    """
    Normalizes DNS query and response telemetry.
    """
    provider_name: str = "dns_log"
    version: str = "1.0.0"

    def can_handle(self, raw_event: Any) -> bool:
        if isinstance(raw_event, dict):
            return (
                "query" in raw_event or
                "dns_query" in raw_event or
                str(raw_event.get("event_type", "")).upper() in ("DNS", "DNS_QUERY", "DNS_RESPONSE")
            )
        return False

    def normalize(self, raw_event: Any, internal_cidrs: Optional[List[str]] = None) -> NormalizedNetworkEvent:
        d = dict(raw_event)
        d["event_type"] = "DNS_QUERY"
        d["protocol"] = "DNS"
        d["destination_port"] = d.get("destination_port") or 53
        return GenericJsonNetworkAdapter().normalize(d, internal_cidrs=internal_cidrs)


class NetflowJsonAdapter(BaseNetworkAdapter):
    """
    Normalizes NetFlow v9 / IPFIX structured JSON records.
    """
    provider_name: str = "netflow_json"
    version: str = "1.0.0"

    def can_handle(self, raw_event: Any) -> bool:
        if isinstance(raw_event, dict):
            return (
                "IPV4_SRC_ADDR" in raw_event or
                "IPV6_SRC_ADDR" in raw_event or
                "in_bytes" in raw_event or
                "IN_BYTES" in raw_event
            )
        return False

    def normalize(self, raw_event: Any, internal_cidrs: Optional[List[str]] = None) -> NormalizedNetworkEvent:
        d = dict(raw_event)
        mapped = {
            "source_ip": d.get("IPV4_SRC_ADDR") or d.get("IPV6_SRC_ADDR") or d.get("src_ip"),
            "destination_ip": d.get("IPV4_DST_ADDR") or d.get("IPV6_DST_ADDR") or d.get("dst_ip"),
            "source_port": d.get("L4_SRC_PORT") or d.get("src_port"),
            "destination_port": d.get("L4_DST_PORT") or d.get("dst_port"),
            "protocol": d.get("PROTOCOL") or d.get("proto"),
            "bytes_sent": d.get("IN_BYTES") or d.get("bytes"),
            "bytes_received": d.get("OUT_BYTES") or 0,
            "packets_sent": d.get("IN_PKTS") or d.get("pkts"),
            "timestamp": d.get("FIRST_SWITCHED") or d.get("timestamp"),
            "provider": self.provider_name,
        }
        return GenericJsonNetworkAdapter().normalize(mapped, internal_cidrs=internal_cidrs)


class NetworkAdapterRegistry:
    """
    Central dispatcher normalizing incoming network telemetry events.
    """
    def __init__(self) -> None:
        self.adapters: List[BaseNetworkAdapter] = [
            DnsLogAdapter(),
            NetflowJsonAdapter(),
            GenericJsonNetworkAdapter(),
            GenericCsvNetworkAdapter(),
        ]

    def normalize(self, raw: Any, hint: Optional[str] = None, internal_cidrs: Optional[List[str]] = None) -> NormalizedNetworkEvent:
        if hint:
            hint_lower = hint.lower()
            for a in self.adapters:
                if a.provider_name == hint_lower and a.can_handle(raw):
                    return a.normalize(raw, internal_cidrs=internal_cidrs)

        for a in self.adapters:
            if a.can_handle(raw):
                return a.normalize(raw, internal_cidrs=internal_cidrs)

        raise ValueError('Network event lacks supported connection or DNS fields.')


# Global adapter registry
global_network_adapter_registry = NetworkAdapterRegistry()


# ============================================================================
# DETECTION ENGINES
# ============================================================================

class ConnectionPatternEngine:
    """
    Analyzes connection failure rates, scan-like sweeps, and volume bursts.
    """
    @staticmethod
    def analyze(
        events: List[NormalizedNetworkEvent],
        config: NetworkConfigResponse,
    ) -> List[NetworkFindingItem]:
        findings: List[NetworkFindingItem] = []

        # 1. Repeated Connection Failures (same source, failures >= threshold)
        source_failures = defaultdict(list)
        for ev in events:
            if ev.status in ("FAILURE", "TIMEOUT", "RESET", "DROP", "REJECT") or ev.action in ("BLOCK", "DROP", "REJECT"):
                source_failures[ev.source_ip].append(ev)

        for src, fails in source_failures.items():
            if len(fails) >= config.repeated_failures_threshold:
                fails_sorted = sorted(fails, key=lambda x: x.timestamp)
                duration = max(1.0, (fails_sorted[-1].timestamp - fails_sorted[0].timestamp).total_seconds())
                if duration <= config.repeated_failures_window_seconds:
                    unique_dsts = set(f.destination_ip for f in fails_sorted if f.destination_ip)
                    findings.append(
                        NetworkFindingItem(
                            finding_type="REPEATED_CONNECTION_FAILURES",
                            title=f"Repeated connection failures from {src}",
                            description=(
                                f"Observed {len(fails_sorted)} failed or dropped network connection attempts from {src} "
                                f"across {len(unique_dsts)} destination(s) within {int(duration)}s. "
                                "May indicate host unreachability, aggressive egress filtering, or reconnaissance attempts."
                            ),
                            severity=SeverityEnum.MEDIUM,
                            confidence=0.88,
                            risk_contribution=35.0,
                            method="DETERMINISTIC",
                            rule_id="NET_RULE_REPEATED_FAILURES",
                            category=NetworkCategoryEnum.CONNECTION_PATTERN,
                            target_device=fails_sorted[0].device_id or src,
                            evidence_items=[
                                NetworkFindingEvidenceItem(key="source_ip", value=src, source="ConnectionPatternEngine", timestamp=fails_sorted[-1].timestamp),
                                NetworkFindingEvidenceItem(key="failure_count", value=str(len(fails_sorted)), source="ConnectionPatternEngine", timestamp=fails_sorted[-1].timestamp),
                                NetworkFindingEvidenceItem(key="time_window_seconds", value=str(int(duration)), source="ConnectionPatternEngine", timestamp=fails_sorted[-1].timestamp),
                            ],
                        )
                    )

        # 2. Scan-like Pattern Detection (1 internal host -> many destination ports or many hosts)
        source_conns = defaultdict(list)
        for ev in events:
            source_conns[ev.source_ip].append(ev)

        for src, conns in source_conns.items():
            if len(conns) < config.scan_distinct_hosts_threshold:
                continue

            conns_sorted = sorted(conns, key=lambda x: x.timestamp)
            duration = max(1.0, (conns_sorted[-1].timestamp - conns_sorted[0].timestamp).total_seconds())
            if duration <= config.scan_window_seconds:
                unique_ports = set(c.destination_port for c in conns_sorted if c.destination_port is not None)
                unique_hosts = set(c.destination_ip for c in conns_sorted if c.destination_ip)

                # Port scan (vertical) or Host sweep (horizontal)
                is_port_scan = len(unique_ports) >= config.scan_distinct_ports_threshold
                is_host_sweep = len(unique_hosts) >= config.scan_distinct_hosts_threshold

                if is_port_scan or is_host_sweep:
                    pattern_type = "port scan" if is_port_scan else "network host sweep"
                    findings.append(
                        NetworkFindingItem(
                            finding_type="SCAN_LIKE_CONNECTION_PATTERN",
                            title=f"Scan-like {pattern_type} pattern detected from {src}",
                            description=(
                                f"Observed observational defensive scan pattern from {src}: contacted {len(unique_hosts)} "
                                f"distinct hosts across {len(unique_ports)} distinct ports within {int(duration)}s. "
                                "This pattern exhibits characteristics of defensive reconnaissance telemetry."
                            ),
                            severity=SeverityEnum.HIGH,
                            confidence=0.91,
                            risk_contribution=65.0,
                            method="HEURISTIC",
                            rule_id="NET_RULE_SCAN_PATTERN",
                            category=NetworkCategoryEnum.CONNECTION_PATTERN,
                            target_device=conns_sorted[0].device_id or src,
                            mitre_attack_ids=["T1046"],
                            evidence_items=[
                                NetworkFindingEvidenceItem(key="source_ip", value=src, source="ConnectionPatternEngine", timestamp=conns_sorted[-1].timestamp),
                                NetworkFindingEvidenceItem(key="distinct_ports_count", value=str(len(unique_ports)), source="ConnectionPatternEngine", timestamp=conns_sorted[-1].timestamp),
                                NetworkFindingEvidenceItem(key="distinct_hosts_count", value=str(len(unique_hosts)), source="ConnectionPatternEngine", timestamp=conns_sorted[-1].timestamp),
                                NetworkFindingEvidenceItem(key="time_window_seconds", value=str(int(duration)), source="ConnectionPatternEngine", timestamp=conns_sorted[-1].timestamp),
                            ],
                        )
                    )

        # 3. Connection Burst
        for src, conns in source_conns.items():
            if len(conns) >= config.connection_burst_threshold:
                conns_sorted = sorted(conns, key=lambda x: x.timestamp)
                duration = max(1.0, (conns_sorted[-1].timestamp - conns_sorted[0].timestamp).total_seconds())
                if duration <= config.connection_burst_window_seconds:
                    rate = (len(conns_sorted) / duration) * 60.0
                    findings.append(
                        NetworkFindingItem(
                            finding_type="CONNECTION_BURST",
                            title=f"High-frequency connection burst from {src}",
                            description=(
                                f"Source {src} generated {len(conns_sorted)} connections within {int(duration)}s "
                                f"({rate:.1f} conns/min). May represent batch synchronization, high load, or burst communication."
                            ),
                            severity=SeverityEnum.MEDIUM,
                            confidence=0.85,
                            risk_contribution=30.0,
                            method="STATISTICAL",
                            rule_id="NET_RULE_BURST",
                            category=NetworkCategoryEnum.CONNECTION_PATTERN,
                            target_device=conns_sorted[0].device_id or src,
                            evidence_items=[
                                NetworkFindingEvidenceItem(key="connection_count", value=str(len(conns_sorted)), source="ConnectionPatternEngine", timestamp=conns_sorted[-1].timestamp),
                                NetworkFindingEvidenceItem(key="duration_seconds", value=str(int(duration)), source="ConnectionPatternEngine", timestamp=conns_sorted[-1].timestamp),
                            ],
                        )
                    )

        return findings


class PeriodicityEngine:
    """
    Evaluates beaconing and regular periodic communication intervals between source and destination.
    """
    @staticmethod
    def calculate_metrics(timestamps: List[datetime]) -> PeriodicityMetrics:
        if len(timestamps) < 2:
            return PeriodicityMetrics(
                event_count=len(timestamps),
                mean_interval_seconds=0.0,
                median_interval_seconds=0.0,
                interval_variance=0.0,
                coefficient_of_variation=1.0,
                min_interval_seconds=0.0,
                max_interval_seconds=0.0,
                observation_duration_seconds=0.0,
                is_periodic=False,
            )

        ts_sorted = sorted(timestamps)
        intervals = [
            (ts_sorted[i] - ts_sorted[i - 1]).total_seconds()
            for i in range(1, len(ts_sorted))
        ]

        # Filter out 0 second intervals from simultaneous flows
        valid_intervals = [x for x in intervals if x > 0.1]
        if len(valid_intervals) < 3:
            return PeriodicityMetrics(
                event_count=len(timestamps),
                mean_interval_seconds=0.0,
                median_interval_seconds=0.0,
                interval_variance=0.0,
                coefficient_of_variation=1.0,
                min_interval_seconds=0.0,
                max_interval_seconds=0.0,
                observation_duration_seconds=(ts_sorted[-1] - ts_sorted[0]).total_seconds(),
                is_periodic=False,
            )

        mean_val = sum(valid_intervals) / len(valid_intervals)
        sorted_int = sorted(valid_intervals)
        n = len(sorted_int)
        median_val = (sorted_int[n // 2] + sorted_int[(n - 1) // 2]) / 2.0
        variance = sum((x - mean_val) ** 2 for x in valid_intervals) / max(1, len(valid_intervals) - 1)
        std_dev = math.sqrt(variance)
        cv = (std_dev / mean_val) if mean_val > 0 else 1.0

        is_periodic = (cv <= 0.20 and mean_val >= 5.0)

        return PeriodicityMetrics(
            event_count=len(timestamps),
            mean_interval_seconds=mean_val,
            median_interval_seconds=median_val,
            interval_variance=variance,
            coefficient_of_variation=cv,
            min_interval_seconds=min(valid_intervals),
            max_interval_seconds=max(valid_intervals),
            observation_duration_seconds=(ts_sorted[-1] - ts_sorted[0]).total_seconds(),
            is_periodic=is_periodic,
        )

    @classmethod
    def analyze(
        cls,
        events: List[NormalizedNetworkEvent],
        config: NetworkConfigResponse,
    ) -> List[NetworkFindingItem]:
        findings: List[NetworkFindingItem] = []

        # Group timestamps by (source_ip, destination)
        pair_events = defaultdict(list)
        for ev in events:
            dst = ev.destination_ip or ev.domain
            if dst:
                pair_events[(ev.source_ip, dst)].append(ev)

        for (src, dst), ev_list in pair_events.items():
            if len(ev_list) < config.periodicity_min_observations:
                continue

            timestamps = [e.timestamp for e in ev_list]
            metrics = cls.calculate_metrics(timestamps)

            if metrics.is_periodic and metrics.coefficient_of_variation <= config.periodicity_max_cv:
                findings.append(
                    NetworkFindingItem(
                        finding_type="PERIODIC_CONNECTION_PATTERN",
                        title=f"Beacon-like periodic communication to {dst} from {src}",
                        description=(
                            f"Source {src} established {metrics.event_count} connections to {dst} with highly regular "
                            f"intervals (mean: {metrics.mean_interval_seconds:.1f}s, median: {metrics.median_interval_seconds:.1f}s, "
                            f"jitter CV: {metrics.coefficient_of_variation:.2f}). "
                            "Limitation: Periodic communication is common in legitimate software, cloud agents, telemetry, "
                            "and health checks. Periodicity alone does not establish command-and-control activity."
                        ),
                        severity=SeverityEnum.MEDIUM,
                        confidence=0.82,
                        risk_contribution=40.0,
                        method="STATISTICAL",
                        rule_id="NET_RULE_BEACON_PERIODICITY",
                        category=NetworkCategoryEnum.CONNECTION_PATTERN,
                        target_device=ev_list[0].device_id or src,
                        target_destination=dst,
                        mitre_attack_ids=["T1071", "T1573"],
                        evidence_items=[
                            NetworkFindingEvidenceItem(key="destination", value=dst, source="PeriodicityEngine", timestamp=max(timestamps)),
                            NetworkFindingEvidenceItem(key="connection_count", value=str(metrics.event_count), source="PeriodicityEngine", timestamp=max(timestamps)),
                            NetworkFindingEvidenceItem(key="median_interval_seconds", value=f"{metrics.median_interval_seconds:.2f}", source="PeriodicityEngine", timestamp=max(timestamps)),
                            NetworkFindingEvidenceItem(key="coefficient_of_variation", value=f"{metrics.coefficient_of_variation:.3f}", source="PeriodicityEngine", timestamp=max(timestamps)),
                        ],
                    )
                )

        return findings


class DnsTelemetryEngine:
    """
    Inspects DNS telemetry for excessive NXDOMAIN failures, DGA-like lexical patterns,
    query bursts, and DNS tunneling characteristics.
    """
    @staticmethod
    def calculate_entropy(text: str) -> float:
        if not text:
            return 0.0
        counts = defaultdict(int)
        for char in text:
            counts[char] += 1
        entropy = 0.0
        length = len(text)
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    @classmethod
    def analyze(
        cls,
        events: List[NormalizedNetworkEvent],
        config: NetworkConfigResponse,
    ) -> List[NetworkFindingItem]:
        findings: List[NetworkFindingItem] = []

        dns_events = [e for e in events if e.event_type == NetworkEventTypeEnum.DNS_QUERY or e.dns_query]
        if not dns_events:
            return findings

        # 1. NXDOMAIN / SERVFAIL Failures
        failed_queries = [e for e in dns_events if e.dns_response_code in ("NXDOMAIN", "SERVFAIL")]
        client_fails = defaultdict(list)
        for e in failed_queries:
            client_fails[e.source_ip].append(e)

        for src, fails in client_fails.items():
            if len(fails) >= config.dns_nxdomain_burst_threshold:
                fails_sorted = sorted(fails, key=lambda x: x.timestamp)
                duration = max(1.0, (fails_sorted[-1].timestamp - fails_sorted[0].timestamp).total_seconds())
                if duration <= config.dns_nxdomain_window_seconds:
                    unique_names = set(f.dns_query for f in fails_sorted if f.dns_query)
                    findings.append(
                        NetworkFindingItem(
                            finding_type="EXCESSIVE_DNS_FAILURES",
                            title=f"Excessive DNS query failures (NXDOMAIN) from {src}",
                            description=(
                                f"Client {src} generated {len(fails_sorted)} failed DNS queries across {len(unique_names)} "
                                f"unique domain(s) within {int(duration)}s. "
                                "Possible causes include network misconfiguration, tracking blockers, or DGA domain probing."
                            ),
                            severity=SeverityEnum.MEDIUM,
                            confidence=0.86,
                            risk_contribution=35.0,
                            method="STATISTICAL",
                            rule_id="NET_RULE_DNS_FAILURES",
                            category=NetworkCategoryEnum.DNS_ANOMALY,
                            target_device=fails_sorted[0].device_id or src,
                            evidence_items=[
                                NetworkFindingEvidenceItem(key="failed_query_count", value=str(len(fails_sorted)), source="DnsTelemetryEngine", timestamp=fails_sorted[-1].timestamp),
                                NetworkFindingEvidenceItem(key="unique_failed_domains", value=str(len(unique_names)), source="DnsTelemetryEngine", timestamp=fails_sorted[-1].timestamp),
                            ],
                        )
                    )

        # 2. DNS Query Burst
        client_queries = defaultdict(list)
        for e in dns_events:
            client_queries[e.source_ip].append(e)

        for src, q_list in client_queries.items():
            if len(q_list) >= config.dns_query_burst_threshold:
                q_sorted = sorted(q_list, key=lambda x: x.timestamp)
                duration = max(1.0, (q_sorted[-1].timestamp - q_sorted[0].timestamp).total_seconds())
                if duration <= config.dns_query_burst_window_seconds:
                    rate = (len(q_sorted) / duration) * 60.0
                    findings.append(
                        NetworkFindingItem(
                            finding_type="DNS_QUERY_BURST",
                            title=f"High-frequency DNS query burst from {src}",
                            description=(
                                f"Client {src} generated {len(q_sorted)} DNS queries within {int(duration)}s "
                                f"({rate:.1f} queries/min). May represent DNS reconnaissance, cache flooding, or service storm."
                            ),
                            severity=SeverityEnum.MEDIUM,
                            confidence=0.84,
                            risk_contribution=25.0,
                            method="STATISTICAL",
                            rule_id="NET_RULE_DNS_BURST",
                            category=NetworkCategoryEnum.DNS_ANOMALY,
                            target_device=q_sorted[0].device_id or src,
                            evidence_items=[
                                NetworkFindingEvidenceItem(key="source_ip", value=src, source="DnsTelemetryEngine", timestamp=q_sorted[-1].timestamp),
                                NetworkFindingEvidenceItem(key="query_count", value=str(len(q_sorted)), source="DnsTelemetryEngine", timestamp=q_sorted[-1].timestamp),
                                NetworkFindingEvidenceItem(key="duration_seconds", value=str(int(duration)), source="DnsTelemetryEngine", timestamp=q_sorted[-1].timestamp),
                            ],
                        )
                    )

        # 3. DGA-like lexical structure
        observed_queries = set(e.dns_query for e in dns_events if e.dns_query)
        for query in observed_queries:
            labels = query.strip(".").split(".")
            if len(labels) >= 2:
                sub = labels[0]
                if len(sub) >= 16:
                    ent = cls.calculate_entropy(sub)
                    # Check digit and consonant ratios
                    digits = sum(1 for c in sub if c.isdigit())
                    digit_ratio = digits / len(sub)
                    vowels = sum(1 for c in sub if c.lower() in "aeiou")
                    vowel_ratio = vowels / len(sub)

                    if ent >= 3.4 and (vowel_ratio < 0.15 or digit_ratio > 0.35):
                        findings.append(
                            NetworkFindingItem(
                                finding_type="DGA_LIKE_DOMAIN_STRUCTURE",
                                title=f"DGA-like lexical structure detected: {query}",
                                description=(
                                    f"Domain query '{query}' exhibits high Shannon entropy ({ent:.2f}), unusual character distribution "
                                    f"(vowel ratio: {vowel_ratio:.2f}, digit ratio: {digit_ratio:.2f}, length: {len(sub)}). "
                                    "Limitation: Lexical analysis alone does NOT prove domain generation algorithm (DGA) activity; "
                                    "CDNs, anti-spam tokens, and tracking domains frequently use pseudo-random labels."
                                ),
                                severity=SeverityEnum.LOW,
                                confidence=0.75,
                                risk_contribution=20.0,
                                method="HEURISTIC",
                                rule_id="NET_RULE_DGA_LEXICAL",
                                category=NetworkCategoryEnum.DNS_ANOMALY,
                                target_destination=query,
                                mitre_attack_ids=["T1568.002"],
                                evidence_items=[
                                    NetworkFindingEvidenceItem(key="domain", value=query, source="DnsTelemetryEngine"),
                                    NetworkFindingEvidenceItem(key="entropy", value=f"{ent:.2f}", source="DnsTelemetryEngine"),
                                    NetworkFindingEvidenceItem(key="label_length", value=str(len(sub)), source="DnsTelemetryEngine"),
                                ],
                            )
                        )

        # 3. DNS Tunneling Defensive Indicators
        # Group queries by parent domain (e.g. *.exfil.example.com -> exfil.example.com)
        parent_subdomains = defaultdict(set)
        for e in dns_events:
            if e.dns_query:
                parts = e.dns_query.strip(".").split(".")
                if len(parts) >= 3:
                    parent = ".".join(parts[-2:])
                    sublabel = parts[0]
                    parent_subdomains[parent].add((sublabel, e.dns_query))

        for parent, sub_set in parent_subdomains.items():
            if len(sub_set) >= config.dns_tunneling_queries_threshold:
                # Check if sublabels are exceptionally long or high entropy
                long_sublabels = [s for s, q in sub_set if len(s) >= config.dns_tunneling_subdomain_len]
                high_ent_sublabels = [s for s, q in sub_set if cls.calculate_entropy(s) >= config.dns_tunneling_entropy_threshold]

                if len(long_sublabels) >= 5 or len(high_ent_sublabels) >= 10:
                    findings.append(
                        NetworkFindingItem(
                            finding_type="DNS_TUNNELING_INDICATORS",
                            title=f"Potential DNS tunneling indicators observed for parent domain {parent}",
                            description=(
                                f"Observed {len(sub_set)} unique subdomains queried for base domain '{parent}'. "
                                f"{len(long_sublabels)} queries exceeded {config.dns_tunneling_subdomain_len} characters and "
                                f"{len(high_ent_sublabels)} had Shannon entropy >= {config.dns_tunneling_entropy_threshold}. "
                                "Caveat: High-entropy DNS subdomains can arise from antivirus cloud lookups, legitimate DNS tunneling tools, "
                                "or software updates. Does NOT confirm data exfiltration without payload verification."
                            ),
                            severity=SeverityEnum.HIGH,
                            confidence=0.88,
                            risk_contribution=65.0,
                            method="HEURISTIC",
                            rule_id="NET_RULE_DNS_TUNNELING",
                            category=NetworkCategoryEnum.DNS_ANOMALY,
                            target_destination=parent,
                            mitre_attack_ids=["T1071.004", "T1048.003"],
                            evidence_items=[
                                NetworkFindingEvidenceItem(key="parent_domain", value=parent, source="DnsTelemetryEngine"),
                                NetworkFindingEvidenceItem(key="unique_subdomains_count", value=str(len(sub_set)), source="DnsTelemetryEngine"),
                                NetworkFindingEvidenceItem(key="long_sublabels_count", value=str(len(long_sublabels)), source="DnsTelemetryEngine"),
                            ],
                        )
                    )

        return findings


class TransferExfiltrationEngine:
    """
    Analyzes outbound data volume, asymmetric flows, long-lived connections,
    and multi-signal data exfiltration hypotheses.
    """
    @staticmethod
    def analyze(
        events: List[NormalizedNetworkEvent],
        profiles: Dict[str, DeviceNetworkProfile],
        config: NetworkConfigResponse,
    ) -> List[NetworkFindingItem]:
        findings: List[NetworkFindingItem] = []

        # 1. High Outbound Volume & Asymmetry
        for ev in events:
            if ev.bytes_sent and ev.bytes_sent >= config.high_outbound_volume_bytes:
                mb_sent = ev.bytes_sent / (1024 * 1024)
                dst = ev.destination_ip or ev.domain or "unknown"
                findings.append(
                    NetworkFindingItem(
                        finding_type="HIGH_OUTBOUND_DATA_VOLUME",
                        title=f"High outbound data volume ({mb_sent:.1f} MB) to {dst}",
                        description=(
                            f"Source {ev.source_ip} transferred {mb_sent:.1f} MB outbound to external destination {dst} "
                            f"(exceeds threshold of {config.high_outbound_volume_bytes / (1024 * 1024):.0f} MB). "
                            "May represent legitimate backups, large downloads, or potential data staging/transfer."
                        ),
                        severity=SeverityEnum.MEDIUM,
                        confidence=0.85,
                        risk_contribution=40.0,
                        method="DETERMINISTIC",
                        rule_id="NET_RULE_HIGH_VOLUME",
                        category=NetworkCategoryEnum.TRANSFER_ANOMALY,
                        target_device=ev.device_id or ev.source_ip,
                        target_destination=dst,
                        mitre_attack_ids=["T1048"],
                        evidence_items=[
                            NetworkFindingEvidenceItem(key="bytes_sent", value=str(ev.bytes_sent), source="TransferExfiltrationEngine", timestamp=ev.timestamp),
                            NetworkFindingEvidenceItem(key="destination", value=dst, source="TransferExfiltrationEngine", timestamp=ev.timestamp),
                        ],
                    )
                )

            # Asymmetry check (bytes sent >> bytes received)
            if (
                ev.bytes_sent and ev.bytes_sent >= (1024 * 1024) and
                ev.bytes_received is not None and ev.bytes_received > 0
            ):
                ratio = ev.bytes_sent / float(ev.bytes_received)
                if ratio >= config.asymmetry_ratio_threshold:
                    dst = ev.destination_ip or ev.domain or "unknown"
                    findings.append(
                        NetworkFindingItem(
                            finding_type="OUTBOUND_TRAFFIC_ASYMMETRY",
                            title=f"Outbound traffic asymmetry ({ratio:.1f}x) to {dst}",
                            description=(
                                f"Observed highly asymmetric outbound flow from {ev.source_ip} to {dst}: "
                                f"{ev.bytes_sent / 1024:.1f} KB sent vs {ev.bytes_received / 1024:.1f} KB received (ratio: {ratio:.1f}x). "
                                "Asymmetric upload ratios are typical in file uploads, telemetry pushing, or potential exfiltration."
                            ),
                            severity=SeverityEnum.LOW,
                            confidence=0.75,
                            risk_contribution=15.0,
                            method="STATISTICAL",
                            rule_id="NET_RULE_ASYMMETRY",
                            category=NetworkCategoryEnum.TRANSFER_ANOMALY,
                            target_device=ev.device_id or ev.source_ip,
                            target_destination=dst,
                            evidence_items=[
                                NetworkFindingEvidenceItem(key="ratio", value=f"{ratio:.2f}", source="TransferExfiltrationEngine", timestamp=ev.timestamp),
                                NetworkFindingEvidenceItem(key="bytes_sent", value=str(ev.bytes_sent), source="TransferExfiltrationEngine", timestamp=ev.timestamp),
                                NetworkFindingEvidenceItem(key="bytes_received", value=str(ev.bytes_received), source="TransferExfiltrationEngine", timestamp=ev.timestamp),
                            ],
                        )
                    )

            # Long-lived connection
            if ev.duration_seconds and ev.duration_seconds >= config.long_lived_connection_seconds:
                hours = ev.duration_seconds / 3600.0
                dst = ev.destination_ip or ev.domain or "unknown"
                findings.append(
                    NetworkFindingItem(
                        finding_type="LONG_LIVED_EXTERNAL_CONNECTION",
                        title=f"Long-lived persistent connection ({hours:.1f}h) to {dst}",
                        description=(
                            f"Connection from {ev.source_ip} to {dst} persisted for {hours:.1f} hours ({int(ev.duration_seconds)}s). "
                            "May represent SSH tunnels, remote desktop sessions, database links, or persistent C2 channels."
                        ),
                        severity=SeverityEnum.LOW,
                        confidence=0.80,
                        risk_contribution=20.0,
                        method="DETERMINISTIC",
                        rule_id="NET_RULE_LONG_LIVED",
                        category=NetworkCategoryEnum.CONNECTION_PATTERN,
                        target_device=ev.device_id or ev.source_ip,
                        target_destination=dst,
                        evidence_items=[
                            NetworkFindingEvidenceItem(key="duration_seconds", value=str(int(ev.duration_seconds)), source="TransferExfiltrationEngine", timestamp=ev.timestamp),
                            NetworkFindingEvidenceItem(key="destination", value=dst, source="TransferExfiltrationEngine", timestamp=ev.timestamp),
                        ],
                    )
                )

        return findings


class DestinationAnomalyEngine:
    """
    Evaluates destination novelty against historical device baselines.
    Enforces minimum history guards to prevent false positives on newly observed hosts.
    """
    @staticmethod
    def analyze(
        events: List[NormalizedNetworkEvent],
        profiles: Dict[str, DeviceNetworkProfile],
        config: NetworkConfigResponse,
    ) -> List[NetworkFindingItem]:
        findings: List[NetworkFindingItem] = []

        for ev in events:
            device_key = ev.device_id or ev.source_ip
            profile = profiles.get(device_key)

            if not profile or profile.total_connections_observed < config.min_history_events_device:
                # Insufficient history - do not flag
                continue

            # 1. New Network Destination
            dst = ev.destination_ip or ev.domain
            if dst and profile.known_destinations and dst not in profile.known_destinations:
                findings.append(
                    NetworkFindingItem(
                        finding_type="NEW_NETWORK_DESTINATION",
                        title=f"Communication to previously unseen destination {dst}",
                        description=(
                            f"Device '{device_key}' connected to destination '{dst}', which has not been observed across "
                            f"{profile.total_connections_observed} historical connections. "
                            "New destinations routinely appear with web browsing, CDNs, and dynamic cloud services."
                        ),
                        severity=SeverityEnum.LOW,
                        confidence=0.85,
                        risk_contribution=15.0,
                        method="DETERMINISTIC",
                        rule_id="NET_RULE_NEW_DESTINATION",
                        category=NetworkCategoryEnum.DESTINATION_ANOMALY,
                        target_device=device_key,
                        target_destination=dst,
                        evidence_items=[
                            NetworkFindingEvidenceItem(key="destination", value=dst, source="DestinationAnomalyEngine", timestamp=ev.timestamp),
                            NetworkFindingEvidenceItem(key="known_destinations_count", value=str(len(profile.known_destinations)), source="DestinationAnomalyEngine", timestamp=ev.timestamp),
                        ],
                    )
                )

            # 2. New Destination Port
            if ev.destination_port and profile.known_ports and ev.destination_port not in profile.known_ports:
                findings.append(
                    NetworkFindingItem(
                        finding_type="NEW_DESTINATION_PORT",
                        title=f"Communication to unobserved port {ev.destination_port} on {dst or 'remote'}",
                        description=(
                            f"Device '{device_key}' connected to port {ev.destination_port}, which is outside "
                            f"the device's known port profile ({sorted(profile.known_ports)})."
                        ),
                        severity=SeverityEnum.LOW,
                        confidence=0.80,
                        risk_contribution=15.0,
                        method="DETERMINISTIC",
                        rule_id="NET_RULE_NEW_PORT",
                        category=NetworkCategoryEnum.DESTINATION_ANOMALY,
                        target_device=device_key,
                        evidence_items=[
                            NetworkFindingEvidenceItem(key="destination_port", value=str(ev.destination_port), source="DestinationAnomalyEngine", timestamp=ev.timestamp),
                            NetworkFindingEvidenceItem(key="known_ports", value=",".join(str(p) for p in sorted(profile.known_ports)), source="DestinationAnomalyEngine", timestamp=ev.timestamp),
                        ],
                    )
                )

        # 3. Rare Destination Analysis
        # When evaluating across multiple devices (fleet context >= 3 devices), flag destinations seen by <= threshold devices
        if len(profiles) >= 3:
            dst_device_map = defaultdict(set)
            for d_id, prof in profiles.items():
                for d in prof.known_destinations:
                    dst_device_map[d].add(d_id)
            for ev in events:
                d_key = ev.device_id or ev.source_ip
                dst = ev.destination_ip or ev.domain
                if dst:
                    dst_device_map[dst].add(d_key)

            reported_rare: Set[str] = set()
            for ev in events:
                dst = ev.destination_ip or ev.domain
                d_key = ev.device_id or ev.source_ip
                if dst and dst not in reported_rare:
                    contacting_devs = dst_device_map.get(dst, set())
                    if len(contacting_devs) <= config.rare_destination_device_count_threshold:
                        reported_rare.add(dst)
                        findings.append(
                            NetworkFindingItem(
                                finding_type="RARE_DESTINATION",
                                title=f"Rare network destination {dst} contacted by only {len(contacting_devs)} device(s)",
                                description=(
                                    f"Destination '{dst}' has only been contacted by {len(contacting_devs)} device(s) "
                                    f"across the fleet ({len(profiles)} monitored devices). "
                                    "Rare destinations are common in legitimate niche services, personal tools, or developer hosts. "
                                    "Rare does NOT equal malicious."
                                ),
                                severity=SeverityEnum.LOW,
                                confidence=0.75,
                                risk_contribution=10.0,
                                method="STATISTICAL",
                                rule_id="NET_RULE_RARE_DESTINATION",
                                category=NetworkCategoryEnum.DESTINATION_ANOMALY,
                                target_device=d_key,
                                target_destination=dst,
                                evidence_items=[
                                    NetworkFindingEvidenceItem(key="destination", value=dst, source="DestinationAnomalyEngine", timestamp=ev.timestamp),
                                    NetworkFindingEvidenceItem(key="contacting_devices_count", value=str(len(contacting_devs)), source="DestinationAnomalyEngine", timestamp=ev.timestamp),
                                    NetworkFindingEvidenceItem(key="total_devices_monitored", value=str(len(profiles)), source="DestinationAnomalyEngine", timestamp=ev.timestamp),
                                ],
                            )
                        )

        return findings


class NetworkPatternAggregator:
    """
    Corroborates independent network evidence categories to synthesize higher-confidence findings.
    """
    @staticmethod
    def aggregate(
        findings: List[NetworkFindingItem],
        events: List[NormalizedNetworkEvent],
    ) -> Tuple[bool, bool, List[NetworkFindingItem]]:
        """
        Returns: (suspicious_communication_detected, possible_exfiltration_detected, additional_findings)
        """
        additional_findings: List[NetworkFindingItem] = []
        suspicious_comm = False
        possible_exfil = False

        # Group findings by destination
        dst_findings = defaultdict(list)
        for f in findings:
            if f.target_destination:
                dst_findings[f.target_destination].append(f)

        for dst, f_list in dst_findings.items():
            categories = set(f.category for f in f_list)
            types = set(f.finding_type for f in f_list)

            # 1. Suspicious Communication Corroboration:
            # e.g. PERIODIC_CONNECTION_PATTERN + (KNOWN_THREAT_INFRASTRUCTURE_MATCH or NEW_NETWORK_DESTINATION)
            if "PERIODIC_CONNECTION_PATTERN" in types and (
                "KNOWN_THREAT_INFRASTRUCTURE_MATCH" in types or
                "NEW_NETWORK_DESTINATION" in types or
                "DNS_TUNNELING_INDICATORS" in types
            ):
                suspicious_comm = True
                sev = SeverityEnum.CRITICAL if "KNOWN_THREAT_INFRASTRUCTURE_MATCH" in types else SeverityEnum.HIGH
                additional_findings.append(
                    NetworkFindingItem(
                        finding_type="SUSPICIOUS_EXTERNAL_COMMUNICATION",
                        title=f"Suspicious external communication pattern corroborated for destination {dst}",
                        description=(
                            f"Multi-signal network corroboration for destination '{dst}': combines beacon-like periodicity "
                            f"with {', '.join(sorted(types))}. Corroborated evidence elevates confidence."
                        ),
                        severity=sev,
                        confidence=0.91,
                        risk_contribution=80.0,
                        method="HYBRID",
                        rule_id="NET_COMPOSITE_SUSPICIOUS_COMM",
                        category=NetworkCategoryEnum.CONNECTION_PATTERN,
                        target_destination=dst,
                        mitre_attack_ids=["T1071", "T1573"],
                        evidence_items=[
                            NetworkFindingEvidenceItem(key="target_destination", value=dst, source="NetworkPatternAggregator"),
                            NetworkFindingEvidenceItem(key="supporting_findings", value=",".join(sorted(types)), source="NetworkPatternAggregator"),
                        ],
                    )
                )

            # 2. Possible Data Exfiltration Corroboration:
            # e.g. HIGH_OUTBOUND_DATA_VOLUME + NEW_NETWORK_DESTINATION
            if "HIGH_OUTBOUND_DATA_VOLUME" in types and ("NEW_NETWORK_DESTINATION" in types or "OUTBOUND_TRAFFIC_ASYMMETRY" in types):
                possible_exfil = True
                additional_findings.append(
                    NetworkFindingItem(
                        finding_type="POSSIBLE_DATA_EXFILTRATION",
                        title=f"Possible data exfiltration pattern corroborated to destination {dst}",
                        description=(
                            f"Observed substantial outbound data transfer to an unfamiliar external destination '{dst}' "
                            f"with asymmetric traffic ratios. Interpretation: Pattern is consistent with external data movement. "
                            "Limitation: Hypothesis only; does NOT confirm exfiltration without authorized payload verification."
                        ),
                        severity=SeverityEnum.HIGH,
                        confidence=0.86,
                        risk_contribution=75.0,
                        method="HYBRID",
                        rule_id="NET_COMPOSITE_EXFILTRATION",
                        category=NetworkCategoryEnum.TRANSFER_ANOMALY,
                        target_destination=dst,
                        mitre_attack_ids=["T1048", "T1041"],
                        evidence_items=[
                            NetworkFindingEvidenceItem(key="target_destination", value=dst, source="NetworkPatternAggregator"),
                            NetworkFindingEvidenceItem(key="supporting_findings", value=",".join(sorted(types)), source="NetworkPatternAggregator"),
                        ],
                    )
                )

        return suspicious_comm, possible_exfil, additional_findings
