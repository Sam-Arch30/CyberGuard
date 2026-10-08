"""
Novelty Fingerprinter Service (Section 22).

Constructs deterministic, compact, versioned pattern fingerprints from structured observations.
Strictly enforces privacy boundaries (no raw secrets, tokens, passwords, or PII)
and normalizes variable elements (e.g. dynamic IDs, ephemeral ports) to prevent state explosion.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse

from backend.schemas.novelty_detection import validate_novelty_privacy


class NoveltyFingerprinter:
    """Deterministic pattern fingerprinting for sub-linear matching and structural similarity."""

    UUID_REGEX = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
    NUMERIC_ID_REGEX = re.compile(r"^[0-9]+$")

    @classmethod
    def normalize_path_template(cls, path: str) -> Tuple[str, int, List[str]]:
        """
        Normalizes a URL or API path replacing dynamic numeric or UUID IDs with '{id}'.
        Returns: (normalized_template, path_depth, token_list)
        """
        if not path:
            return ("/", 0, [])

        clean_path = path.strip().split("?")[0].split("#")[0]
        segments = [s for s in clean_path.split("/") if s]
        normalized_segments: List[str] = []

        for seg in segments:
            if cls.UUID_REGEX.match(seg) or cls.NUMERIC_ID_REGEX.match(seg):
                normalized_segments.append("{id}")
            else:
                normalized_segments.append(seg.lower())

        depth = len(normalized_segments)
        template = "/" + "/".join(normalized_segments) if normalized_segments else "/"
        return (template, depth, normalized_segments)

    @classmethod
    def compute_hash(cls, canonical_dict: Dict[str, Any]) -> str:
        """Computes deterministic SHA-256 from sorted JSON representation."""
        canonical_json = json.dumps(canonical_dict, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

    @classmethod
    def calculate_entropy(cls, text: str) -> float:
        """Shannon entropy of a string."""
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in set(text)]
        return -sum(p * math.log2(p) for p in prob)

    # ------------------------------------------------------------------------
    # 1. API Route Fingerprint
    # ------------------------------------------------------------------------
    @classmethod
    def fingerprint_api_route(
        cls,
        method: str,
        path: str,
        resource_type: Optional[str] = None,
        is_privileged: bool = False,
        auth_context: str = "AUTHENTICATED",
    ) -> Tuple[str, str, Dict[str, Any]]:
        """
        Creates deterministic API fingerprint.
        Never includes request bodies, authorization headers, or secrets.
        """
        norm_method = (method or "GET").strip().upper()
        norm_template, depth, tokens = cls.normalize_path_template(path)
        norm_resource = (resource_type or (tokens[0] if tokens else "root")).lower()

        attributes = {
            "method": norm_method,
            "route_template": norm_template,
            "resource_type": norm_resource,
            "path_depth": depth,
            "is_privileged": bool(is_privileged),
            "auth_context": (auth_context or "AUTHENTICATED").upper(),
        }

        # Privacy check
        for k, v in attributes.items():
            validate_novelty_privacy(k, v)

        fingerprint_hash = cls.compute_hash(attributes)
        repr_str = f"API:{norm_method} {norm_template} | res={norm_resource} | priv={is_privileged}"
        return (fingerprint_hash, repr_str, attributes)

    # ------------------------------------------------------------------------
    # 2. URL Structure Fingerprint
    # ------------------------------------------------------------------------
    @classmethod
    def fingerprint_url_structure(
        cls,
        url: str,
        hostname_type: str = "DOMAIN",
        query_param_keys: Optional[List[str]] = None,
    ) -> Tuple[str, str, Dict[str, Any]]:
        """
        Fingerprints structural properties of a URL without recording query parameter values.
        """
        parsed = urlparse(url)
        scheme = (parsed.scheme or "http").lower()
        norm_template, depth, tokens = cls.normalize_path_template(parsed.path)

        sorted_param_keys: List[str] = []
        if query_param_keys is not None:
            sorted_param_keys = sorted([k.strip().lower() for k in query_param_keys if k])
        elif parsed.query:
            raw_params = parsed.query.split("&")
            for p in raw_params:
                k = p.split("=")[0].strip().lower()
                if k:
                    sorted_param_keys.append(k)
            sorted_param_keys = sorted(list(set(sorted_param_keys)))

        attributes = {
            "scheme": scheme,
            "hostname_type": hostname_type.upper(),
            "path_depth": depth,
            "path_template": norm_template,
            "param_key_count": len(sorted_param_keys),
            "param_keys": sorted_param_keys,
        }

        for k, v in attributes.items():
            validate_novelty_privacy(k, v)

        fingerprint_hash = cls.compute_hash(attributes)
        param_hint = ",".join(sorted_param_keys[:3]) + ("..." if len(sorted_param_keys) > 3 else "")
        repr_str = f"URL:{scheme}://[{hostname_type}]{norm_template} ?[{param_hint}]"
        return (fingerprint_hash, repr_str, attributes)

    # ------------------------------------------------------------------------
    # 3. Domain Pattern Fingerprint
    # ------------------------------------------------------------------------
    @classmethod
    def fingerprint_domain_pattern(
        cls,
        domain: str,
        is_ip: bool = False,
    ) -> Tuple[str, str, Dict[str, Any]]:
        """
        Fingerprints lexical and structural domain features.
        """
        norm_domain = (domain or "").strip().lower()
        subdomains = [s for s in norm_domain.split(".") if s]
        tld = subdomains[-1] if subdomains else "unknown"
        sub_depth = max(0, len(subdomains) - 2)

        entropy = cls.calculate_entropy(norm_domain)
        entropy_bracket = "LOW"
        if entropy > 4.2:
            entropy_bracket = "HIGH"
        elif entropy > 3.4:
            entropy_bracket = "MEDIUM"

        attributes = {
            "is_ip": bool(is_ip),
            "tld": tld,
            "subdomain_depth": sub_depth,
            "entropy_bracket": entropy_bracket,
            "label_count": len(subdomains),
        }

        for k, v in attributes.items():
            validate_novelty_privacy(k, v)

        fingerprint_hash = cls.compute_hash(attributes)
        repr_str = f"DOMAIN:.{tld} | depth={sub_depth} | ent={entropy_bracket} | labels={len(subdomains)}"
        return (fingerprint_hash, repr_str, attributes)

    # ------------------------------------------------------------------------
    # 4. Network Behavior Fingerprint
    # ------------------------------------------------------------------------
    @classmethod
    def fingerprint_network_behavior(
        cls,
        destination_category: str = "EXTERNAL",
        port: int = 443,
        protocol: str = "TCP",
        direction: str = "OUTBOUND",
        byte_volume: int = 1024,
    ) -> Tuple[str, str, Dict[str, Any]]:
        """
        Fingerprints network connection characteristics.
        """
        # Port bracket
        port_cat = "HIGH_PORT"
        if port in (80, 443, 8080, 8443):
            port_cat = "WEB"
        elif port in (53, 853):
            port_cat = "DNS"
        elif port in (22, 3389):
            port_cat = "REMOTE_ACCESS"
        elif port < 1024:
            port_cat = "SYSTEM_STANDARD"

        # Volume bracket
        vol_cat = "MODERATE"
        if byte_volume < 512:
            vol_cat = "TINY"
        elif byte_volume > 100 * 1024 * 1024:
            vol_cat = "MASSIVE"
        elif byte_volume > 10 * 1024 * 1024:
            vol_cat = "LARGE"

        attributes = {
            "destination_category": destination_category.upper(),
            "port_category": port_cat,
            "protocol": (protocol or "TCP").upper(),
            "direction": (direction or "OUTBOUND").upper(),
            "volume_bracket": vol_cat,
        }

        for k, v in attributes.items():
            validate_novelty_privacy(k, v)

        fingerprint_hash = cls.compute_hash(attributes)
        repr_str = f"NET:{direction} {protocol} -> [{destination_category}]:{port_cat} vol={vol_cat}"
        return (fingerprint_hash, repr_str, attributes)

    # ------------------------------------------------------------------------
    # 5. Authentication Pattern Fingerprint
    # ------------------------------------------------------------------------
    @classmethod
    def fingerprint_auth_pattern(
        cls,
        auth_method: str = "PASSWORD",
        source_network_class: str = "CORPORATE",
        is_mfa: bool = False,
        device_category: str = "MANAGED_WORKSTATION",
    ) -> Tuple[str, str, Dict[str, Any]]:
        """
        Fingerprints authentication context. Never stores credentials or OTP codes.
        """
        attributes = {
            "auth_method": (auth_method or "PASSWORD").upper(),
            "source_network_class": (source_network_class or "UNKNOWN").upper(),
            "is_mfa": bool(is_mfa),
            "device_category": (device_category or "UNKNOWN").upper(),
        }

        for k, v in attributes.items():
            validate_novelty_privacy(k, v)

        fingerprint_hash = cls.compute_hash(attributes)
        repr_str = f"AUTH:{attributes['auth_method']} via [{attributes['source_network_class']}] MFA={is_mfa} dev={attributes['device_category']}"
        return (fingerprint_hash, repr_str, attributes)

    # ------------------------------------------------------------------------
    # 6. Event Sequence Fingerprint
    # ------------------------------------------------------------------------
    @classmethod
    def fingerprint_event_sequence(
        cls,
        event_types: List[str],
    ) -> Tuple[str, str, Dict[str, Any]]:
        """
        Fingerprints an ordered sequence of event types or attack stages.
        """
        norm_seq = [str(e).strip().upper() for e in event_types if e]
        attributes = {
            "sequence": norm_seq,
            "length": len(norm_seq),
        }

        for k, v in attributes.items():
            validate_novelty_privacy(k, v)

        fingerprint_hash = cls.compute_hash(attributes)
        seq_str = " -> ".join(norm_seq[:5]) + (" -> ..." if len(norm_seq) > 5 else "")
        repr_str = f"SEQ[{len(norm_seq)}]: {seq_str}"
        return (fingerprint_hash, repr_str, attributes)

    # ------------------------------------------------------------------------
    # 7. Multi-Signal Combination Fingerprint
    # ------------------------------------------------------------------------
    @classmethod
    def fingerprint_combination_tuple(
        cls,
        attributes_dict: Dict[str, Any],
    ) -> Tuple[str, str, Dict[str, Any]]:
        """
        Fingerprints a combination of co-occurring contextual attributes.
        """
        clean_attrs = {}
        for k, v in sorted(attributes_dict.items()):
            validate_novelty_privacy(k, v)
            clean_attrs[k.lower()] = str(v).strip().upper() if isinstance(v, (str, bool, int, float)) else str(v)

        fingerprint_hash = cls.compute_hash(clean_attrs)
        items_summary = ", ".join(f"{k}={v}" for k, v in list(clean_attrs.items())[:4])
        repr_str = f"COMBO: ({items_summary})"
        return (fingerprint_hash, repr_str, clean_attrs)

    # ------------------------------------------------------------------------
    # 8. Cross-Entity Relationship Fingerprint
    # ------------------------------------------------------------------------
    @classmethod
    def fingerprint_relationship(
        cls,
        source_type: str,
        relationship_type: str,
        target_type: str,
    ) -> Tuple[str, str, Dict[str, Any]]:
        """
        Fingerprints structural schema of entity relationships.
        """
        attributes = {
            "source_type": source_type.upper(),
            "relationship_type": relationship_type.upper(),
            "target_type": target_type.upper(),
        }
        for k, v in attributes.items():
            validate_novelty_privacy(k, v)

        fingerprint_hash = cls.compute_hash(attributes)
        repr_str = f"REL: ({attributes['source_type']}) -[{attributes['relationship_type']}]-> ({attributes['target_type']})"
        return (fingerprint_hash, repr_str, attributes)
