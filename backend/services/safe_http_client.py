"""
Safe HTTP Client & Network Security Gate (Section 7).
Provides centralized, SSRF-defended HTTP fetching for active URL and website inspection.
Strictly blocks access to loopback, private RFC-1918, link-local, cloud metadata,
multicast, reserved, and unspecified network ranges across IPv4 and IPv6.
Enforces per-hop redirect validation, strict size limits, timeouts, and TLS certificate extraction.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import socket
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlsplit, urljoin

import certifi
import httpx

from backend.services.ssrf_protector import SSRFProtector

logger = logging.getLogger("cyberguard.safe_http_client")


class SSRFBlockedException(Exception):
    """Raised when an outbound connection attempt targets a prohibited destination."""
    def __init__(self, reason: str, destination: str, target_ip: Optional[str] = None):
        self.reason = reason
        self.destination = destination
        self.target_ip = target_ip
        super().__init__(f"SSRF Blocked: {reason} [destination={destination}, ip={target_ip}]")


@dataclass
class RedirectHop:
    """Record of an individual HTTP redirection step."""
    hop_index: int
    source_url: str
    destination_url: str
    status_code: int
    timestamp: str
    is_cross_domain: bool = False
    source_domain: str = ""
    destination_domain: str = ""


@dataclass
class TLSInspectionResult:
    """Extracted TLS certificate and cryptographic handshake metadata."""
    is_valid: bool
    subject_cn: Optional[str] = None
    subject_org: Optional[str] = None
    issuer_cn: Optional[str] = None
    issuer_org: Optional[str] = None
    valid_from: Optional[str] = None
    valid_until: Optional[str] = None
    san_list: List[str] = field(default_factory=list)
    has_expired: bool = False
    is_self_signed: bool = False
    protocol_version: Optional[str] = None
    error_type: Optional[str] = None
    error_message: Optional[str] = None


@dataclass
class SafeHttpResponse:
    """Result of a controlled, SSRF-defended HTTP inspection."""
    url: str
    final_url: str
    status_code: int
    headers: Dict[str, str] = field(default_factory=dict)
    content_bytes: bytes = b""
    content_text: str = ""
    content_type: str = ""
    response_size: int = 0
    is_truncated: bool = False
    redirect_chain: List[RedirectHop] = field(default_factory=list)
    tls: Optional[TLSInspectionResult] = None
    is_safe_destination: bool = True
    blocked_reason: Optional[str] = None
    blocked_ip: Optional[str] = None
    latency_ms: float = 0.0
    error: Optional[str] = None


class SafeHttpClient:
    """
    Centralized network safety gateway for CyberGuard active URL/website analysis.
    Guarantees that no arbitrary outbound HTTP connection reaches unauthorized internal networks.
    """

    ALLOWED_SCHEMES: Set[str] = {"http", "https"}
    DEFAULT_CONNECT_TIMEOUT: float = 3.0
    DEFAULT_READ_TIMEOUT: float = 5.0
    DEFAULT_TOTAL_TIMEOUT: float = 8.0
    DEFAULT_MAX_REDIRECTS: int = 5
    DEFAULT_MAX_SIZE_BYTES: int = 1048576  # 1 MB

    # Explicit cloud metadata hostnames & IP literals
    CLOUD_METADATA_TARGETS: Set[str] = {
        "169.254.169.254",
        "169.254.170.2",
        "fd00:ec2::254",
        "metadata.google.internal",
        "metadata.internal",
        "instance-data",
    }

    def __init__(
        self,
        connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
        read_timeout: float = DEFAULT_READ_TIMEOUT,
        total_timeout: float = DEFAULT_TOTAL_TIMEOUT,
        max_redirects: int = DEFAULT_MAX_REDIRECTS,
        max_size_bytes: int = DEFAULT_MAX_SIZE_BYTES,
        user_agent: str = "CyberGuard-Forensics/2.0 (+https://cyberguard.internal)",
    ):
        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout
        self.total_timeout = total_timeout
        self.max_redirects = max_redirects
        self.max_size_bytes = max_size_bytes
        self.user_agent = user_agent

    @classmethod
    def classify_ip_safety(cls, ip_str: str) -> Tuple[bool, str]:
        """
        Classifies whether an IP is an externally routable, safe public address.
        Returns (is_safe, failure_reason).
        """
        clean = re.sub(r'^(?i:IPv6:)', '', ip_str.strip().strip("[]"))
        try:
            ip_obj = ipaddress.ip_address(clean)
        except ValueError:
            return False, f"Invalid IP address format: {ip_str}"

        if ip_obj.is_loopback:
            return False, f"Loopback address prohibited ({clean})"
        if ip_obj.is_private:
            return False, f"Private RFC-1918/ULA address prohibited ({clean})"
        if ip_obj.is_link_local:
            return False, f"Link-local address prohibited ({clean})"
        if ip_obj.is_multicast:
            return False, f"Multicast address prohibited ({clean})"
        if ip_obj.is_reserved:
            return False, f"Reserved network range prohibited ({clean})"
        if ip_obj.is_unspecified:
            return False, f"Unspecified address prohibited ({clean})"

        # Check explicit cloud metadata
        if str(ip_obj) in cls.CLOUD_METADATA_TARGETS:
            return False, f"Cloud metadata destination prohibited ({clean})"

        # Carrier-grade NAT (100.64.0.0/10)
        cgnat = ipaddress.ip_network("100.64.0.0/10")
        if ip_obj.version == 4 and ip_obj in cgnat:
            return False, f"Carrier-Grade NAT range prohibited ({clean})"

        # Allow test documentation networks when used in simulated forensics test fixtures
        # (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32)
        return True, "Safe public IP"

    @classmethod
    def validate_url_syntax_and_scheme(cls, url: str) -> Tuple[bool, str, Any]:
        """
        Validates URL scheme and parses URL structure.
        Only http and https are permitted for active network fetching.
        """
        if not url or not isinstance(url, str):
            return False, "URL is empty or not a string", None

        clean_url = url.strip()
        try:
            parsed = urlsplit(clean_url)
        except Exception as e:
            return False, f"Malformed URL syntax: {e}", None

        scheme = parsed.scheme.lower() if parsed.scheme else ""
        if scheme not in cls.ALLOWED_SCHEMES:
            return False, f"Prohibited URL scheme '{scheme}'. Only HTTP and HTTPS are permitted for active fetching.", parsed

        if not parsed.hostname:
            return False, "URL contains no hostname or authority component", parsed

        return True, "Scheme and syntax valid", parsed

    @classmethod
    def resolve_and_verify_destination(cls, hostname: str, port: int = 80) -> Tuple[bool, str, List[str]]:
        """
        Resolves hostname to IP addresses and verifies that EVERY resolved IP
        is a safe, public, non-internal destination.
        Defends against dual-homed DNS and DNS rebinding to internal ranges.
        """
        clean_host = hostname.strip().lower().rstrip(".").strip("[]")

        # 1. Reject direct blocked hostnames (localhost, *.local, cloud metadata)
        if clean_host in cls.CLOUD_METADATA_TARGETS or clean_host in ("localhost", "0.0.0.0", "::1"):
            return False, f"Blocked internal hostname '{clean_host}'", []

        if not SSRFProtector.is_safe_public_domain(clean_host):
            # Check if clean_host is an IP literal
            is_ip = False
            try:
                ipaddress.ip_address(clean_host)
                is_ip = True
            except ValueError:
                pass

            if not is_ip:
                return False, f"Prohibited domain syntax or internal pattern '{clean_host}'", []

        # 2. Check if clean_host is already an IP address
        try:
            ip_obj = ipaddress.ip_address(clean_host)
            is_safe, reason = cls.classify_ip_safety(str(ip_obj))
            if not is_safe:
                return False, reason, [str(ip_obj)]
            return True, "IP literal verified", [str(ip_obj)]
        except ValueError:
            pass

        # 3. Resolve domain via system getaddrinfo
        resolved_ips: List[str] = []
        try:
            addr_info = socket.getaddrinfo(clean_host, port, proto=socket.IPPROTO_TCP)
            for item in addr_info:
                ip_addr = item[4][0]
                if ip_addr not in resolved_ips:
                    resolved_ips.append(ip_addr)
        except socket.gaierror as e:
            return False, f"DNS resolution failed for '{clean_host}': {e}", []
        except Exception as e:
            return False, f"Error resolving '{clean_host}': {e}", []

        if not resolved_ips:
            return False, f"No IP addresses resolved for '{clean_host}'", []

        # 4. Enforce that ALL resolved IPs must be safe
        for ip in resolved_ips:
            is_safe, reason = cls.classify_ip_safety(ip)
            if not is_safe:
                return False, f"Domain '{clean_host}' resolved to blocked destination: {reason}", resolved_ips

        return True, "All resolved destination IPs verified safe", resolved_ips

    @classmethod
    def inspect_tls(
        cls,
        hostname: str,
        target_ip: Optional[str] = None,
        port: int = 443,
        timeout: float = 3.0,
    ) -> Optional[TLSInspectionResult]:
        """
        Safely establishes a TLS handshake to extract server certificate metadata.
        Never executes payloads or sends HTTP data during certificate inspection.
        """
        clean_host = hostname.strip().lower().rstrip(".").strip("[]")
        connect_host = target_ip or clean_host

        ctx = ssl.create_default_context(cafile=certifi.where())
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED

        try:
            with socket.create_connection((connect_host, port), timeout=timeout) as raw_sock:
                with ctx.wrap_socket(raw_sock, server_hostname=clean_host) as ssock:
                    cert = ssock.getpeercert()
                    proto = ssock.version()
                    if not cert:
                        return TLSInspectionResult(
                            is_valid=False,
                            error_type="NO_CERTIFICATE",
                            error_message="Server returned an empty certificate."
                        )

                    # Extract Subject
                    subj_dict = dict(x[0] for x in cert.get("subject", []))
                    subject_cn = subj_dict.get("commonName")
                    subject_org = subj_dict.get("organizationName")

                    # Extract Issuer
                    iss_dict = dict(x[0] for x in cert.get("issuer", []))
                    issuer_cn = iss_dict.get("commonName")
                    issuer_org = iss_dict.get("organizationName")

                    # Dates
                    valid_from = cert.get("notBefore")
                    valid_until = cert.get("notAfter")
                    has_expired = False
                    if valid_until:
                        try:
                            exp_dt = datetime.strptime(valid_until, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                            has_expired = datetime.now(timezone.utc) > exp_dt
                        except Exception:
                            has_expired = False

                    # SANs
                    sans = [item[1] for item in cert.get("subjectAltName", []) if item[0] in ("DNS", "IP Address")]

                    # Self-signed check
                    is_self_signed = (subject_cn == issuer_cn and subject_org == issuer_org and subject_cn is not None)

                    return TLSInspectionResult(
                        is_valid=True,
                        subject_cn=subject_cn,
                        subject_org=subject_org,
                        issuer_cn=issuer_cn,
                        issuer_org=issuer_org,
                        valid_from=valid_from,
                        valid_until=valid_until,
                        san_list=sans,
                        has_expired=has_expired,
                        is_self_signed=is_self_signed,
                        protocol_version=proto,
                    )

        except ssl.SSLCertVerificationError as e:
            error_reason = "CERT_VERIFICATION_FAILED"
            msg = str(e)
            if "certificate has expired" in msg.lower():
                error_reason = "EXPIRED_CERTIFICATE"
            elif "hostname" in msg.lower() and "doesn't match" in msg.lower():
                error_reason = "HOSTNAME_MISMATCH"
            elif "self signed" in msg.lower():
                error_reason = "SELF_SIGNED_CERTIFICATE"

            return TLSInspectionResult(
                is_valid=False,
                error_type=error_reason,
                error_message=str(e),
                has_expired=("expired" in msg.lower()),
            )
        except Exception as e:
            return TLSInspectionResult(
                is_valid=False,
                error_type="TLS_CONNECTION_ERROR",
                error_message=str(e),
            )

    async def fetch_url(self, url, method="GET", inspect_certificate=True):
        try:
            return await asyncio.wait_for(self._fetch_url(url, method, inspect_certificate), timeout=self.total_timeout)
        except asyncio.TimeoutError:
            return SafeHttpResponse(url=url, final_url=url, status_code=0,
                is_safe_destination=False, error="HTTP request timed out: overall deadline exceeded.")

    async def _fetch_url(
        self,
        url: str,
        method: str = "GET",
        inspect_certificate: bool = True,
    ) -> SafeHttpResponse:
        """
        Executes a controlled, SSRF-defended HTTP fetch with step-by-step redirect validation.
        Limits downloaded payload size to self.max_size_bytes and enforces strict timeouts.
        """
        start_time = time.perf_counter()
        current_url = url.strip()
        redirect_chain: List[RedirectHop] = []
        final_response: Optional[SafeHttpResponse] = None

        for hop_idx in range(self.max_redirects + 1):
            # 1. Validate Scheme & Syntax
            is_valid_syntax, syntax_msg, parsed = self.validate_url_syntax_and_scheme(current_url)
            if not is_valid_syntax:
                latency = (time.perf_counter() - start_time) * 1000
                return SafeHttpResponse(
                    url=url,
                    final_url=current_url,
                    status_code=0,
                    is_safe_destination=False,
                    blocked_reason=syntax_msg,
                    redirect_chain=redirect_chain,
                    latency_ms=latency,
                    error=syntax_msg,
                )

            hostname = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == "https" else 80)

            # 2. Pre-flight SSRF Validation (DNS & Destination IP Verification)
            is_safe, ssrf_msg, resolved_ips = await asyncio.to_thread(self.resolve_and_verify_destination, hostname, port)
            if not is_safe:
                blocked_ip = resolved_ips[0] if resolved_ips else None
                latency = (time.perf_counter() - start_time) * 1000
                logger.warning(f"SSRF Gate Blocked URL '{current_url}': {ssrf_msg}")
                return SafeHttpResponse(
                    url=url,
                    final_url=current_url,
                    status_code=0,
                    is_safe_destination=False,
                    blocked_reason=ssrf_msg,
                    blocked_ip=blocked_ip,
                    redirect_chain=redirect_chain,
                    latency_ms=latency,
                    error=ssrf_msg,
                )

            # 3. Optional TLS certificate extraction on the initial or final hop
            tls_result = None
            if inspect_certificate and parsed.scheme == "https" and hop_idx == 0:
                first_ip = resolved_ips[0] if resolved_ips else None
                try:
                    tls_result = await asyncio.to_thread(
                        self.inspect_tls,
                        hostname,
                        first_ip,
                        port,
                        self.connect_timeout,
                    )
                except Exception as exc:
                    logger.debug(f"TLS inspection skipped for {hostname}: {exc}")

            # 4. Execute single non-redirecting HTTP request
            client_timeout = httpx.Timeout(
                self.total_timeout,
                connect=self.connect_timeout,
                read=self.read_timeout,
            )

            headers = {
                "User-Agent": self.user_agent,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
            }

            from httpcore._backends.anyio import AnyIOBackend
            target_ip = resolved_ips[0] if resolved_ips else None
            if not target_ip:
                return SafeHttpResponse(url=url, final_url=current_url, status_code=0,
                    is_safe_destination=False, error="DNS pinning failed: missing destination")
            class PinnedBackend(AnyIOBackend):
                async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
                    if host.lower().rstrip('.') != hostname.lower().rstrip('.'):
                        raise httpx.ConnectError("Unvalidated connection destination")
                    return await super().connect_tcp(host=target_ip, port=port, timeout=timeout,
                        local_address=local_address, socket_options=socket_options)
            try:
                transport = httpx.AsyncHTTPTransport(verify=ssl.create_default_context(cafile=certifi.where()))
                transport._pool._network_backend = PinnedBackend()
            except Exception:
                return SafeHttpResponse(url=url, final_url=current_url, status_code=0,
                    is_safe_destination=False, error="DNS pinning transport initialization failed.")
            try:
                async with httpx.AsyncClient(
                    transport=transport,
                    timeout=client_timeout,
                    follow_redirects=False,  # CRITICAL: Manual step-by-step redirect control
                ) as client:
                    async with client.stream(method=method, url=current_url, headers=headers) as resp:

                        status = resp.status_code
                        resp_headers = dict(resp.headers)
                        content_type = resp.headers.get("content-type", "")

                        # 5. Check if response is a redirect
                        if status in (301, 302, 303, 307, 308) and "location" in resp.headers:
                            location_raw = resp.headers["location"]
                            next_url = urljoin(current_url, location_raw)

                            source_dom = urlsplit(current_url).hostname or ""
                            dest_dom = urlsplit(next_url).hostname or ""
                            is_cross = (source_dom.lower() != dest_dom.lower())

                            hop = RedirectHop(
                                hop_index=hop_idx + 1,
                                source_url=current_url,
                                destination_url=next_url,
                                status_code=status,
                                timestamp=datetime.now(timezone.utc).isoformat(),
                                is_cross_domain=is_cross,
                                source_domain=source_dom,
                                destination_domain=dest_dom,
                            )
                            redirect_chain.append(hop)

                            if hop_idx >= self.max_redirects:
                                latency = (time.perf_counter() - start_time) * 1000
                                return SafeHttpResponse(
                                    url=url,
                                    final_url=current_url,
                                    status_code=status,
                                    headers=resp_headers,
                                    content_type=content_type,
                                    redirect_chain=redirect_chain,
                                    is_safe_destination=True,
                                    latency_ms=latency,
                                    error=f"Redirect chain limit exceeded ({self.max_redirects} hops)",
                                )

                            # Advance to next redirect URL and repeat SSRF validation loop
                            current_url = next_url
                            continue

                        # 6. Stream content up to max_size_bytes
                        raw_content = bytearray()
                        is_truncated = False
                        async for chunk in resp.aiter_bytes():
                            remaining = self.max_size_bytes - len(raw_content)
                            if remaining <= 0:
                                is_truncated = True
                                break
                            if len(chunk) > remaining:
                                raw_content.extend(chunk[:remaining])
                                is_truncated = True
                                break
                            raw_content.extend(chunk)

                        content_bytes = bytes(raw_content)
                        try:
                            content_text = content_bytes.decode(resp.encoding or "utf-8", errors="replace")
                        except Exception:
                            content_text = content_bytes.decode("latin-1", errors="replace")

                        latency = (time.perf_counter() - start_time) * 1000

                        return SafeHttpResponse(
                            url=url,
                            final_url=current_url,
                            status_code=status,
                            headers=resp_headers,
                            content_bytes=content_bytes,
                            content_text=content_text,
                            content_type=content_type,
                            response_size=len(content_bytes),
                            is_truncated=is_truncated,
                            redirect_chain=redirect_chain,
                            tls=tls_result,
                            is_safe_destination=True,
                            latency_ms=latency,
                        )

            except (httpx.ConnectTimeout, httpx.ReadTimeout, httpx.TimeoutException) as e:
                latency = (time.perf_counter() - start_time) * 1000
                return SafeHttpResponse(
                    url=url,
                    final_url=current_url,
                    status_code=0,
                    is_safe_destination=True,
                    redirect_chain=redirect_chain,
                    latency_ms=latency,
                    error=f"HTTP connection timed out: {e}",
                )
            except httpx.RequestError as e:
                latency = (time.perf_counter() - start_time) * 1000
                return SafeHttpResponse(
                    url=url,
                    final_url=current_url,
                    status_code=0,
                    is_safe_destination=True,
                    redirect_chain=redirect_chain,
                    latency_ms=latency,
                    error=f"HTTP network error: {e}",
                )

        latency = (time.perf_counter() - start_time) * 1000
        return SafeHttpResponse(
            url=url,
            final_url=current_url,
            status_code=0,
            is_safe_destination=True,
            redirect_chain=redirect_chain,
            latency_ms=latency,
            error="Exceeded redirect loop",
        )
