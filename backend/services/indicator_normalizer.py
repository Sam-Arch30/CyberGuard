"""
Section 52: Canonical Indicator Normalization Engine & Privacy Policy Evaluator.
Normalizes heterogeneous observables (IP, DOMAIN, URL, HASH, EMAIL, ASN, CERTIFICATE)
into forensically faithful canonical representations while enforcing strict privacy
controls preventing leakage of internal RFC1918 IPs, corporate hostnames, and private URLs.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

from backend.schemas.threat_intelligence import (
    IndicatorTypeEnum,
    NormalizedIndicator,
    PrivacyScopeEnum,
)
from backend.services.ssrf_protector import SSRFProtector


class IndicatorNormalizer:
    """
    Authoritative indicator normalizer and privacy policy gatekeeper.
    Guarantees forensic integrity, case-insensitivity, and zero unintended external leakage.
    """

    INTERNAL_DOMAIN_SUFFIXES = (
        ".local", ".localhost", ".internal", ".corp", ".lan", ".home",
        ".arpa", ".intranet", ".priv", ".test", ".invalid",
    )

    NON_PUBLIC_TLDS = {
        "local", "localhost", "internal", "corp", "lan", "home", "arpa",
        "intranet", "priv", "test", "invalid", "example",
    }

    HEX_PATTERN = re.compile(r'^[0-9a-fA-F]+$')

    @classmethod
    def normalize(
        cls,
        raw_indicator: str,
        indicator_type: Optional[IndicatorTypeEnum | str] = None,
    ) -> NormalizedIndicator:
        """
        Normalizes a raw indicator value according to its type and evaluates privacy scope.
        """
        raw_clean = (raw_indicator or "").strip()
        if not raw_clean:
            return NormalizedIndicator(
                type=IndicatorTypeEnum.HOSTNAME,
                raw_value="",
                normalized_value="",
                privacy_scope=PrivacyScopeEnum.UNKNOWN,
                is_routable_public=False,
            )

        inferred_type = cls._infer_or_validate_type(raw_clean, indicator_type)

        if inferred_type == IndicatorTypeEnum.IP:
            return cls._normalize_ip(raw_clean)
        elif inferred_type == IndicatorTypeEnum.DOMAIN:
            return cls._normalize_domain(raw_clean)
        elif inferred_type == IndicatorTypeEnum.URL:
            return cls._normalize_url(raw_clean)
        elif inferred_type in (IndicatorTypeEnum.SHA256, IndicatorTypeEnum.SHA1, IndicatorTypeEnum.MD5):
            return cls._normalize_hash(raw_clean, inferred_type)
        elif inferred_type == IndicatorTypeEnum.EMAIL:
            return cls._normalize_email(raw_clean)
        elif inferred_type == IndicatorTypeEnum.CERTIFICATE:
            return cls._normalize_certificate(raw_clean)
        elif inferred_type == IndicatorTypeEnum.ASN:
            return cls._normalize_asn(raw_clean)
        else:
            return cls._normalize_hostname(raw_clean)

    @classmethod
    def _infer_or_validate_type(
        cls,
        raw_val: str,
        hint: Optional[IndicatorTypeEnum | str] = None,
    ) -> IndicatorTypeEnum:
        """Resolves indicator type using explicit hint or deterministic heuristics."""
        if hint:
            try:
                hint_str = hint.value if isinstance(hint, IndicatorTypeEnum) else str(hint).upper()
                return IndicatorTypeEnum(hint_str)
            except ValueError:
                pass

        val_lower = raw_val.lower()

        # URL
        if val_lower.startswith(("http://", "https://", "ftp://", "ftps://")):
            return IndicatorTypeEnum.URL

        # IP address check
        clean_ip = re.sub(r'^(?i:IPv6:)', '', raw_val.strip())
        try:
            ipaddress.ip_address(clean_ip)
            return IndicatorTypeEnum.IP
        except ValueError:
            pass

        # Email
        if "@" in raw_val and not raw_val.startswith(("http://", "https://")) and "/" not in raw_val:
            return IndicatorTypeEnum.EMAIL

        # ASN
        if re.match(r'^(?i:AS)?[0-9]{1,10}$', raw_val) and (raw_val.upper().startswith("AS") or raw_val.isdigit()):
            return IndicatorTypeEnum.ASN

        # Hashes
        hex_len = len(raw_val)
        if cls.HEX_PATTERN.match(raw_val):
            if hex_len == 64:
                return IndicatorTypeEnum.SHA256
            elif hex_len == 40:
                return IndicatorTypeEnum.SHA1
            elif hex_len == 32:
                return IndicatorTypeEnum.MD5

        # Domain vs Hostname
        if "." in raw_val and "/" not in raw_val:
            return IndicatorTypeEnum.DOMAIN

        return IndicatorTypeEnum.HOSTNAME

    # -------------------------------------------------------------------------
    # Normalizers
    # -------------------------------------------------------------------------

    @classmethod
    def _normalize_ip(cls, raw: str) -> NormalizedIndicator:
        clean = re.sub(r'^(?i:IPv6:)', '', raw.strip())
        # Strip port if present in IPv4 e.g. 1.2.3.4:8080
        if ":" in clean and "." in clean and clean.count(":") == 1:
            clean = clean.split(":")[0]

        try:
            ip_obj = ipaddress.ip_address(clean)
            norm_val = str(ip_obj)
            version = ip_obj.version

            # Check if internal / private / reserved
            is_internal = (
                ip_obj.is_loopback
                or ip_obj.is_private
                or ip_obj.is_link_local
                or ip_obj.is_reserved
                or ip_obj.is_multicast
                or ip_obj.is_unspecified
            )

            # Documentation test IPs (RFC 5737 / RFC 3849) used in lab environments
            is_doc_ip = (
                norm_val.startswith("198.51.100.")
                or norm_val.startswith("203.0.113.")
                or norm_val.startswith("192.0.2.")
                or norm_val.startswith("2001:db8:")
            )

            privacy_scope = PrivacyScopeEnum.INTERNAL if (is_internal and not is_doc_ip) else PrivacyScopeEnum.PUBLIC

            return NormalizedIndicator(
                type=IndicatorTypeEnum.IP,
                raw_value=raw,
                normalized_value=norm_val,
                privacy_scope=privacy_scope,
                is_routable_public=(privacy_scope == PrivacyScopeEnum.PUBLIC),
                metadata={
                    "version": version,
                    "is_loopback": ip_obj.is_loopback,
                    "is_private": ip_obj.is_private,
                    "is_link_local": ip_obj.is_link_local,
                    "is_doc_test": is_doc_ip,
                },
            )
        except ValueError:
            return NormalizedIndicator(
                type=IndicatorTypeEnum.IP,
                raw_value=raw,
                normalized_value=raw.strip(),
                privacy_scope=PrivacyScopeEnum.UNKNOWN,
                is_routable_public=False,
                metadata={"error": "Invalid IP format"},
            )

    @classmethod
    def _normalize_domain(cls, raw: str) -> NormalizedIndicator:
        clean = raw.strip().lower().rstrip(".")

        # Convert IDN to punycode
        try:
            ascii_domain = clean.encode('idna').decode('ascii').lower()
        except Exception:
            ascii_domain = clean

        # Evaluate privacy scope
        is_internal = False
        parts = ascii_domain.split(".")

        if any(ascii_domain.endswith(suffix) for suffix in cls.INTERNAL_DOMAIN_SUFFIXES):
            is_internal = True
        elif parts[-1] in cls.NON_PUBLIC_TLDS:
            is_internal = True
        elif len(parts) == 1 or ascii_domain in ("localhost", "local"):
            is_internal = True

        privacy_scope = PrivacyScopeEnum.INTERNAL if is_internal else PrivacyScopeEnum.PUBLIC

        return NormalizedIndicator(
            type=IndicatorTypeEnum.DOMAIN,
            raw_value=raw,
            normalized_value=ascii_domain,
            privacy_scope=privacy_scope,
            is_routable_public=(privacy_scope == PrivacyScopeEnum.PUBLIC),
            metadata={"ascii_punycode": ascii_domain, "labels_count": len(parts)},
        )

    @classmethod
    def _normalize_url(cls, raw: str) -> NormalizedIndicator:
        url_clean = raw.strip()
        val_lower = url_clean.lower()
        if not (
            val_lower.startswith("http://")
            or val_lower.startswith("https://")
            or val_lower.startswith("ftp://")
            or val_lower.startswith("ftps://")
        ):
            url_clean = "http://" + url_clean

        try:
            split = urlsplit(url_clean)
            scheme = split.scheme.lower()

            netloc = split.netloc.lower()
            hostname = split.hostname.lower() if split.hostname else ""
            port = split.port

            # Drop default ports
            if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
                netloc = hostname

            # Normalize path: collapse duplicate slashes
            path = re.sub(r'/{2,}', '/', split.path) or "/"

            # Normalize query string preserving key-values deterministically
            query = ""
            if split.query:
                try:
                    q_pairs = sorted(parse_qsl(split.query, keep_blank_values=True))
                    query = urlencode(q_pairs)
                except Exception:
                    query = split.query

            normalized_url = urlunsplit((scheme, netloc, path, query, ""))

            # Privacy scope evaluation based on host
            privacy_scope = PrivacyScopeEnum.PUBLIC
            if hostname:
                # Check if host is internal IP or domain
                try:
                    ip_obj = ipaddress.ip_address(hostname)
                    if (
                        ip_obj.is_loopback
                        or ip_obj.is_private
                        or ip_obj.is_link_local
                        or ip_obj.is_reserved
                    ):
                        privacy_scope = PrivacyScopeEnum.INTERNAL
                except ValueError:
                    if (
                        any(hostname.endswith(s) for s in cls.INTERNAL_DOMAIN_SUFFIXES)
                        or hostname.split(".")[-1] in cls.NON_PUBLIC_TLDS
                        or "." not in hostname
                    ):
                        privacy_scope = PrivacyScopeEnum.INTERNAL

            # Check for sensitive credentials in URL
            if split.username or split.password or "token=" in query.lower() or "auth=" in query.lower():
                privacy_scope = PrivacyScopeEnum.SENSITIVE

            return NormalizedIndicator(
                type=IndicatorTypeEnum.URL,
                raw_value=raw,
                normalized_value=normalized_url,
                privacy_scope=privacy_scope,
                is_routable_public=(privacy_scope == PrivacyScopeEnum.PUBLIC),
                metadata={"scheme": scheme, "hostname": hostname, "path": path},
            )
        except Exception:
            return NormalizedIndicator(
                type=IndicatorTypeEnum.URL,
                raw_value=raw,
                normalized_value=raw.strip(),
                privacy_scope=PrivacyScopeEnum.UNKNOWN,
                is_routable_public=False,
                metadata={"error": "Malformed URL"},
            )

    @classmethod
    def _normalize_hash(cls, raw: str, hash_type: IndicatorTypeEnum) -> NormalizedIndicator:
        clean = raw.strip().lower()
        valid = bool(cls.HEX_PATTERN.match(clean))

        expected_len = {
            IndicatorTypeEnum.SHA256: 64,
            IndicatorTypeEnum.SHA1: 40,
            IndicatorTypeEnum.MD5: 32,
        }.get(hash_type, 64)

        if valid and len(clean) == expected_len:
            scope = PrivacyScopeEnum.PUBLIC
        else:
            scope = PrivacyScopeEnum.UNKNOWN

        return NormalizedIndicator(
            type=hash_type,
            raw_value=raw,
            normalized_value=clean,
            privacy_scope=scope,
            is_routable_public=True,
            metadata={"length": len(clean), "expected_length": expected_len, "valid_hex": valid},
        )

    @classmethod
    def _normalize_email(cls, raw: str) -> NormalizedIndicator:
        clean = raw.strip().lower()
        if "@" in clean:
            user_part, domain_part = clean.split("@", 1)
            # Evaluate domain privacy
            dom_norm = cls._normalize_domain(domain_part)
            if dom_norm.privacy_scope == PrivacyScopeEnum.INTERNAL:
                scope = PrivacyScopeEnum.INTERNAL
            else:
                # User email addresses carry PII -> sensitive
                scope = PrivacyScopeEnum.SENSITIVE
            normalized_val = f"{user_part}@{dom_norm.normalized_value}"
        else:
            scope = PrivacyScopeEnum.UNKNOWN
            normalized_val = clean

        return NormalizedIndicator(
            type=IndicatorTypeEnum.EMAIL,
            raw_value=raw,
            normalized_value=normalized_val,
            privacy_scope=scope,
            is_routable_public=(scope != PrivacyScopeEnum.INTERNAL),
            metadata={"is_email": "@" in clean},
        )

    @classmethod
    def _normalize_certificate(cls, raw: str) -> NormalizedIndicator:
        # Strip colons and spaces from fingerprint e.g. "AA:BB:CC:..." -> "aabbcc..."
        clean = re.sub(r'[^0-9a-fA-F]', '', raw.strip()).lower()
        return NormalizedIndicator(
            type=IndicatorTypeEnum.CERTIFICATE,
            raw_value=raw,
            normalized_value=clean,
            privacy_scope=PrivacyScopeEnum.PUBLIC,
            is_routable_public=True,
            metadata={"fingerprint_len": len(clean)},
        )

    @classmethod
    def _normalize_asn(cls, raw: str) -> NormalizedIndicator:
        clean = raw.strip().upper()
        if clean.startswith("AS"):
            num_part = clean[2:]
        else:
            num_part = clean
        norm_val = f"AS{num_part}" if num_part.isdigit() else clean
        return NormalizedIndicator(
            type=IndicatorTypeEnum.ASN,
            raw_value=raw,
            normalized_value=norm_val,
            privacy_scope=PrivacyScopeEnum.PUBLIC,
            is_routable_public=True,
            metadata={"asn_number": num_part if num_part.isdigit() else None},
        )

    @classmethod
    def _normalize_hostname(cls, raw: str) -> NormalizedIndicator:
        clean = raw.strip().lower().rstrip(".")
        is_internal = (
            "." not in clean
            or any(clean.endswith(s) for s in cls.INTERNAL_DOMAIN_SUFFIXES)
            or clean in ("localhost", "local")
        )
        scope = PrivacyScopeEnum.INTERNAL if is_internal else PrivacyScopeEnum.PUBLIC

        return NormalizedIndicator(
            type=IndicatorTypeEnum.HOSTNAME,
            raw_value=raw,
            normalized_value=clean,
            privacy_scope=scope,
            is_routable_public=(scope == PrivacyScopeEnum.PUBLIC),
        )

    @classmethod
    def is_external_lookup_allowed(cls, indicator: NormalizedIndicator) -> Tuple[bool, str]:
        """
        Policy gate: returns (allowed: bool, reason: str).
        Strictly forbids querying external providers for INTERNAL or SENSITIVE indicators.
        """
        if indicator.privacy_scope == PrivacyScopeEnum.INTERNAL:
            return False, f"Indicator '{indicator.normalized_value}' is internal/private; external queries are prohibited by privacy policy."
        if indicator.privacy_scope == PrivacyScopeEnum.SENSITIVE:
            return False, f"Indicator '{indicator.normalized_value}' contains sensitive PII or credentials; external queries are blocked."
        if indicator.privacy_scope == PrivacyScopeEnum.UNKNOWN:
            return False, f"Indicator '{indicator.normalized_value}' has unknown/unverifiable structure."
        return True, "Indicator is public and eligible for external enrichment."
