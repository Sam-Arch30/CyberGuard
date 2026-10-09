"""
Agent Security Controller for Section 31 Endpoint Agent Architecture.
Manages machine identity credentials, cryptographic request signing,
configuration signature verification, replay protection, and rotation lifecycle.
"""

import hmac
import hashlib
import time
import uuid
import json
import logging
from typing import Dict, Any, Optional, Tuple

logger = logging.getLogger("cyberguard.agent.security")


class AgentSecurityController:
    """
    Client-side cryptographic identity and message authenticator.
    Constructs tamper-evident HMAC-SHA256 request signatures and verifies
    server-signed configuration bundles.
    """

    def __init__(
        self,
        agent_id: str,
        key_id: str,
        credential_secret: str,
        server_public_or_hmac_key: Optional[str] = None
    ):
        self.agent_id = agent_id
        self.key_id = key_id
        self.credential_secret = credential_secret
        self.server_signing_key = server_public_or_hmac_key or credential_secret

        self._pending_key_id: Optional[str] = None
        self._pending_secret: Optional[str] = None
        self._is_revoked: bool = False

    @property
    def is_revoked(self) -> bool:
        return self._is_revoked

    def revoke(self) -> None:
        """Invalidates local credential and wipes secrets."""
        self._is_revoked = True
        self.credential_secret = "[REVOKED]"
        self._pending_secret = None
        logger.warning(f"Agent {self.agent_id} credential marked REVOKED locally.")

    def sign_request(
        self,
        method: str,
        path: str,
        body_bytes: bytes = b""
    ) -> Dict[str, str]:
        """
        Generates canonical authentication headers for outgoing HTTP requests.
        Canonical String:
            METHOD\nPATH\nTIMESTAMP\nNONCE\nBODY_SHA256
        """
        if self._is_revoked:
            raise PermissionError("Cannot sign request: Agent credential has been revoked.")

        timestamp_str = str(int(time.time()))
        nonce = uuid.uuid4().hex
        body_sha = hashlib.sha256(body_bytes).hexdigest()

        canonical_string = f"{method.upper()}\n{path}\n{timestamp_str}\n{nonce}\n{body_sha}"
        signature = hmac.new(
            self.credential_secret.encode("utf-8"),
            canonical_string.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()

        return {
            "Content-Type": "application/json",
            "X-CyberGuard-Agent-ID": self.agent_id,
            "X-CyberGuard-Key-ID": self.key_id,
            "X-CyberGuard-Timestamp": timestamp_str,
            "X-CyberGuard-Nonce": nonce,
            "X-CyberGuard-Signature": signature
        }

    def verify_configuration_signature(
        self,
        config_dict: Dict[str, Any],
        signature: Optional[str]
    ) -> bool:
        """
        Validates that server-delivered configuration was not tampered with.
        Calculates canonical JSON hash and matches against signature.
        """
        if not signature:
            logger.warning("Configuration payload missing signature.")
            return False

        # Build canonical payload omitting signature itself
        payload_copy = {k: v for k, v in config_dict.items() if k != "signature"}
        canonical_json = json.dumps(payload_copy, sort_keys=True).encode("utf-8")

        expected_sig = hmac.new(
            self.server_signing_key.encode("utf-8"),
            canonical_json,
            hashlib.sha256
        ).hexdigest()

        is_valid = hmac.compare_digest(expected_sig, signature)
        if not is_valid:
            logger.error(f"Configuration signature verification failed for agent {self.agent_id}")
        return is_valid

    def stage_rotated_credential(self, new_key_id: str, new_secret: str) -> None:
        """Stages a newly received credential pending successful handshake."""
        self._pending_key_id = new_key_id
        self._pending_secret = new_secret
        logger.info(f"Staged new key_id {new_key_id} for agent {self.agent_id}")

    def commit_rotated_credential(self) -> None:
        """Commits staged credential as the active identity."""
        if self._pending_key_id and self._pending_secret:
            self.key_id = self._pending_key_id
            self.credential_secret = self._pending_secret
            self._pending_key_id = None
            self._pending_secret = None
            logger.info(f"Committed new active key_id {self.key_id} for agent {self.agent_id}")

    def rollback_staged_credential(self) -> None:
        """Discards uncommitted staged credential upon failure."""
        self._pending_key_id = None
        self._pending_secret = None
