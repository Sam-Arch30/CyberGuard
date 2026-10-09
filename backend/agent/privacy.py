"""
Privacy and Redaction Controller for Section 31 Endpoint Agent Architecture.
Enforces deterministic client-side redaction of sensitive credentials, tokens,
cookies, authorization headers, and applies path/process exclusions.
"""

import re
import fnmatch
from typing import Dict, Any, List, Optional, Set

# Sensitive key names to redact recursively in event payloads
SENSITIVE_KEY_PATTERNS = {
    re.compile(p, re.IGNORECASE) for p in [
        r"password",
        r"passwd",
        r"secret",
        r"token",
        r"api_?key",
        r"access_?token",
        r"auth_?token",
        r"authorization",
        r"cookie",
        r"session_?id",
        r"private_?key",
        r"client_?secret",
        r"credit_?card",
        r"ssn"
    ]
}

# Value-level pattern detectors for credentials inadvertently embedded in strings or command lines
SECRET_VALUE_PATTERNS = [
    # Command line credentials e.g. curl -u user:password
    (re.compile(r"(-u\s+[a-zA-Z0-9_\-\.]+):([^\s]+)", re.IGNORECASE), r"\1:[REDACTED]"),
    # Command line --password=secret or -p secret
    (re.compile(r"(--password(?:=|\s+)|-p(?:=|\s+))([^\s]+)", re.IGNORECASE), r"\1[REDACTED]"),
    # Bearer tokens
    (re.compile(r"Bearer\s+([a-zA-Z0-9_\-\.]{8,})", re.IGNORECASE), "Bearer [REDACTED]"),
    # Basic auth
    (re.compile(r"Basic\s+([a-zA-Z0-9+/=]{16,})", re.IGNORECASE), "Basic [REDACTED]"),
    # Private Key blocks
    (re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----.*?-----END [A-Z ]+ PRIVATE KEY-----", re.DOTALL), "[REDACTED_PRIVATE_KEY]"),
    # AWS/Cloud API Key patterns
    (re.compile(r"(AKIA[0-9A-Z]{16})"), "[REDACTED_AWS_KEY]"),
    # Generic API key / token / password assignments in command lines or URLs
    (re.compile(r"(key|secret|token|password|passwd|api_?key)=([^\s&]+)", re.IGNORECASE), r"\1=[REDACTED]"),
]


class PrivacyFilter:
    """
    Client-side deterministic privacy filter and data minimizer.
    Runs BEFORE events enter the local buffer or leave the endpoint.
    """

    def __init__(
        self,
        excluded_paths: Optional[List[str]] = None,
        excluded_processes: Optional[List[str]] = None,
        excluded_users: Optional[List[str]] = None,
        redact_sensitive_values: bool = True
    ):
        self.excluded_paths = excluded_paths or [
            "*/Documents/Personal/*",
            "*/.ssh/id_*",
            "*/Library/Keychains/*",
            "*/AppData/Local/Google/Chrome/User Data/*",
            "*/.config/google-chrome/*"
        ]
        self.excluded_processes = excluded_processes or [
            "1Password*",
            "Bitwarden*",
            "KeePass*"
        ]
        self.excluded_users = excluded_users or []
        self.redact_sensitive_values = redact_sensitive_values

    def is_path_excluded(self, path: Optional[str]) -> bool:
        """Checks if a given filesystem path matches excluded patterns."""
        if not path:
            return False
        normalized = path.replace("\\", "/")
        for pattern in self.excluded_paths:
            norm_pattern = pattern.replace("\\", "/")
            if fnmatch.fnmatch(normalized, norm_pattern):
                return True
        return False

    def is_process_excluded(self, process_name_or_path: Optional[str]) -> bool:
        """Checks if a process name or executable path matches excluded patterns."""
        if not process_name_or_path:
            return False
        base_name = process_name_or_path.replace("\\", "/").split("/")[-1]
        for pattern in self.excluded_processes:
            if fnmatch.fnmatch(base_name, pattern) or fnmatch.fnmatch(process_name_or_path, pattern):
                return True
        return False

    def is_user_excluded(self, username: Optional[str]) -> bool:
        """Checks if user account is excluded from telemetry collection."""
        if not username:
            return False
        return username.lower() in {u.lower() for u in self.excluded_users}

    def sanitize_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Recursively sanitizes dictionary payload, redacting secret keys and patterns.
        """
        if not self.redact_sensitive_values:
            return payload

        return self._sanitize_item(payload)

    def _sanitize_item(self, item: Any) -> Any:
        if isinstance(item, dict):
            sanitized = {}
            for k, v in item.items():
                # Check if key is sensitive
                is_secret_key = any(p.search(str(k)) for p in SENSITIVE_KEY_PATTERNS)
                if is_secret_key:
                    sanitized[k] = "[REDACTED]"
                else:
                    sanitized[k] = self._sanitize_item(v)
            return sanitized

        elif isinstance(item, list):
            return [self._sanitize_item(x) for x in item]

        elif isinstance(item, str):
            val = item
            for pattern, repl in SECRET_VALUE_PATTERNS:
                val = pattern.sub(repl, val)
            return val

        return item

    def should_collect(self, event_type: str, payload: Dict[str, Any]) -> bool:
        """
        Determines whether an event should be collected or dropped under privacy policy.
        """
        # Process check
        proc = payload.get("process_name") or payload.get("executable") or payload.get("process_path")
        if proc and self.is_process_excluded(str(proc)):
            return False

        # Path check
        fpath = payload.get("file_path") or payload.get("path") or payload.get("target_path")
        if fpath and self.is_path_excluded(str(fpath)):
            return False

        # User check
        user = payload.get("user") or payload.get("username")
        if user and self.is_user_excluded(str(user)):
            return False

        return True
