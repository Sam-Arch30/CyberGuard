import re
import ipaddress
from typing import List, Optional, Dict, Any
from backend.schemas.email import RelayHop, EarliestObservableNode, RelayPathAnalysis


class RelayReconstructorService:
    """
    Forensic service to parse email Received header chains, reconstruct transmission relay hops,
    and identify the earliest observable public sending infrastructure.
    """

    _PRIVATE_NETWORKS = [
        ipaddress.ip_network('10.0.0.0/8'),
        ipaddress.ip_network('172.16.0.0/12'),
        ipaddress.ip_network('192.168.0.0/16'),
        ipaddress.ip_network('100.64.0.0/10'),
        ipaddress.ip_network('fc00::/7'),
    ]

    @classmethod
    def is_public_ip(cls, ip_str: str) -> bool:
        """
        Check if an IP string is a valid public (externally routable) IPv4 or IPv6 address.
        Private (RFC1918/CGNAT/ULA), loopback, link-local, multicast, and unspecified IPs return False.
        Documentation IPs (e.g. 203.0.113.x, 198.51.100.x, 2001:db8::1) return True for forensic reconstruction.
        """
        if not ip_str:
            return False
        # Remove IPv6 prefix if present (e.g. IPv6:2001:db8::1)
        cleaned_ip = re.sub(r'^(?i:IPv6:)', '', ip_str.strip())
        try:
            ip_obj = ipaddress.ip_address(cleaned_ip)
            if ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_unspecified:
                return False
            return not any(ip_obj in net for net in cls._PRIVATE_NETWORKS)
        except ValueError:
            return False

    @staticmethod
    def extract_ip_from_text(text: Optional[str]) -> Optional[str]:
        """
        Safely extract IPv4 or IPv6 address from a header clause or parenthesis text.
        """
        if not text:
            return None

        # 1. Bracketed or parenthesized IP: [203.0.113.10], (203.0.113.10), [IPv6:2001:db8::1], (IPv6:2001:db8::1)
        for m in re.finditer(r'[\[\(]\s*(?:IPv6:)?\s*([0-9a-fA-F:.]+)\s*[\]\)]', text, re.IGNORECASE):
            cand = m.group(1).strip()
            try:
                ipaddress.ip_address(cand)
                return cand
            except ValueError:
                pass

        # 2. Standalone IPv4: 203.0.113.10
        ipv4_match = re.search(r'\b((?:\d{1,3}\.){3}\d{1,3})\b', text)
        if ipv4_match:
            cand = ipv4_match.group(1).strip()
            try:
                ipaddress.ip_address(cand)
                return cand
            except ValueError:
                pass

        # 3. Standalone IPv6 (prefixed or unprefixed)
        cleaned = re.sub(r'(?i)\bIPv6:\s*', '', text)
        for token in re.findall(r'[0-9a-fA-F:.]+', cleaned):
            cand = token.strip("[]():,; \t")
            if ":" in cand and len(cand) >= 2:
                try:
                    ipaddress.ip_address(cand)
                    return cand
                except ValueError:
                    pass

        return None

    @classmethod
    def parse_single_received_header(cls, header_str: str) -> Dict[str, Any]:
        """
        Parse a single Received header string into structured fields with raw preservation.
        """
        raw_header = header_str.strip()
        # Clean multiline whitespace to single space for regex matching
        clean_text = re.sub(r'\s+', ' ', raw_header)

        from_host: Optional[str] = None
        from_ip: Optional[str] = None
        by_host: Optional[str] = None
        by_ip: Optional[str] = None
        protocol: Optional[str] = None
        header_id: Optional[str] = None
        recipient: Optional[str] = None
        timestamp: Optional[str] = None

        # Separate body and timestamp (timestamp is after the last semicolon if present)
        body_text = clean_text
        if ';' in clean_text:
            parts = clean_text.rsplit(';', 1)
            body_text = parts[0].strip()
            timestamp = parts[1].strip()

        # Parse 'from' clause: "from <host> (<ip> or [<ip>])"
        from_match = re.search(r'\bfrom\s+(.*?)(?=\bby\b|\bwith\b|\bid\b|\bfor\b|$)', body_text, re.IGNORECASE)
        if from_match:
            from_clause = from_match.group(1).strip()
            from_ip = cls.extract_ip_from_text(from_clause)

            # Extract hostname from 'from' clause (first token before '(' or '[')
            token_match = re.search(r'^([^\s;()\[\]]+)', from_clause)
            if token_match:
                cand_host = token_match.group(1).strip()
                if not cls.extract_ip_from_text(cand_host):
                    from_host = cand_host

            if not from_host:
                host_in_paren = re.search(r'\b([a-zA-Z0-9\.\-]+\.[a-zA-Z]{2,})\b', from_clause)
                if host_in_paren and not cls.extract_ip_from_text(host_in_paren.group(1)):
                    from_host = host_in_paren.group(1)

        # Parse 'by' clause: "by <host> ([<ip>])"
        by_match = re.search(r'\bby\s+(.*?)(?=\bwith\b|\bid\b|\bfor\b|\bfrom\b|$)', body_text, re.IGNORECASE)
        if by_match:
            by_clause = by_match.group(1).strip()
            by_ip = cls.extract_ip_from_text(by_clause)

            token_match = re.search(r'^([^\s;()\[\]]+)', by_clause)
            if token_match:
                cand_host = token_match.group(1).strip()
                if not cls.extract_ip_from_text(cand_host):
                    by_host = cand_host

            if not by_host:
                host_in_paren = re.search(r'\b([a-zA-Z0-9\.\-]+\.[a-zA-Z]{2,})\b', by_clause)
                if host_in_paren and not cls.extract_ip_from_text(host_in_paren.group(1)):
                    by_host = host_in_paren.group(1)

        # Parse 'with' clause: "with <protocol>"
        with_match = re.search(r'\bwith\s+([A-Za-z0-9\-\_]+)', body_text, re.IGNORECASE)
        if with_match:
            protocol = with_match.group(1).strip()

        # Parse 'id' clause: "id <id_str>"
        id_match = re.search(r'\bid\s+([^\s;]+)', body_text, re.IGNORECASE)
        if id_match:
            header_id = id_match.group(1).strip()

        # Parse 'for' clause: "for <recipient>"
        for_match = re.search(r'\bfor\s+<?([^\s;>]+)>?', body_text, re.IGNORECASE)
        if for_match:
            recipient = for_match.group(1).strip()

        # Assess parser confidence
        extracted_fields_count = sum(1 for f in [from_host, from_ip, by_host, by_ip, protocol, header_id, recipient, timestamp] if f is not None)
        if extracted_fields_count >= 3:
            confidence = "high"
        elif extracted_fields_count >= 1:
            confidence = "medium"
        else:
            confidence = "low"

        return {
            "from_host": from_host,
            "from_ip": from_ip,
            "by_host": by_host,
            "by_ip": by_ip,
            "protocol": protocol,
            "id": header_id,
            "recipient": recipient,
            "timestamp": timestamp,
            "parser_confidence": confidence,
            "raw": raw_header
        }

    @classmethod
    def identify_earliest_observable_ip(cls, transmission_order_hops: List[RelayHop]) -> EarliestObservableNode:
        """
        Scan transmission order hops (from hop 1 origin to recipient gateway) to identify
        the earliest usable public sending infrastructure IP.
        """
        for hop in transmission_order_hops:
            # First check from_ip
            if hop.from_ip and cls.is_public_ip(hop.from_ip):
                return EarliestObservableNode(
                    earliest_observable_ip=hop.from_ip,
                    from_host=hop.from_host,
                    confidence="high",
                    reason=f"Earliest public IP found in Received chain at Hop #{hop.hop_number} (from {hop.from_host or 'unknown'})"
                )
            # If from_ip missing/private, check by_ip as fallback
            if hop.by_ip and cls.is_public_ip(hop.by_ip):
                return EarliestObservableNode(
                    earliest_observable_ip=hop.by_ip,
                    from_host=hop.by_host,
                    confidence="medium",
                    reason=f"Earliest public receiving server IP found at Hop #{hop.hop_number}"
                )

        return EarliestObservableNode(
            earliest_observable_ip=None,
            from_host=None,
            confidence="none",
            reason="No public IP address found in Received header chain"
        )

    @classmethod
    def reconstruct_relay_path(cls, received_headers: List[str]) -> RelayPathAnalysis:
        """
        Convert raw Received header list into header_order_hops, transmission_order_hops,
        and identify earliest observable sending infrastructure.
        """
        if not received_headers:
            return RelayPathAnalysis(
                header_order_hops=[],
                transmission_order_hops=[],
                earliest_observable_node=EarliestObservableNode(
                    earliest_observable_ip=None,
                    from_host=None,
                    confidence="none",
                    reason="No Received headers present in email"
                )
            )

        header_order_hops: List[RelayHop] = []
        for idx, raw_h in enumerate(received_headers, start=1):
            parsed = cls.parse_single_received_header(raw_h)
            hop = RelayHop(
                hop_number=idx,
                from_host=parsed["from_host"],
                from_ip=parsed["from_ip"],
                by_host=parsed["by_host"],
                by_ip=parsed["by_ip"],
                protocol=parsed["protocol"],
                id=parsed["id"],
                recipient=parsed["recipient"],
                timestamp=parsed["timestamp"],
                parser_confidence=parsed["parser_confidence"],
                raw=parsed["raw"]
            )
            header_order_hops.append(hop)

        # Derived chronological transmission order: reverse of header order
        # (Top header in .eml is recipient gateway, bottom header is origin sender)
        raw_transmission = list(reversed(received_headers))
        transmission_order_hops: List[RelayHop] = []
        for idx, raw_h in enumerate(raw_transmission, start=1):
            parsed = cls.parse_single_received_header(raw_h)
            hop = RelayHop(
                hop_number=idx,
                from_host=parsed["from_host"],
                from_ip=parsed["from_ip"],
                by_host=parsed["by_host"],
                by_ip=parsed["by_ip"],
                protocol=parsed["protocol"],
                id=parsed["id"],
                recipient=parsed["recipient"],
                timestamp=parsed["timestamp"],
                parser_confidence=parsed["parser_confidence"],
                raw=parsed["raw"]
            )
            transmission_order_hops.append(hop)

        earliest_node = cls.identify_earliest_observable_ip(transmission_order_hops)

        return RelayPathAnalysis(
            header_order_hops=header_order_hops,
            transmission_order_hops=transmission_order_hops,
            earliest_observable_node=earliest_node
        )
