"""
Agent Transport Client for Section 31 Endpoint Agent Architecture.
Handles authenticated HTTPS transport, request signing, exponential backoff with jitter,
partial batch failure handling, and connection lifecycle.
"""

import time
import random
import logging
from typing import Dict, Any, Optional, List
import httpx

from backend.schemas.endpoint_agent import (
    BatchTelemetryIngestRequest,
    BatchTelemetryIngestResponse,
    AgentHeartbeatRequest,
    AgentHeartbeatResponse,
    AgentConfigurationResponse,
    CredentialRotateRequest,
    CredentialRotateResponse
)
from backend.agent.security import AgentSecurityController

logger = logging.getLogger("cyberguard.agent.transport")


class TransportError(Exception):
    """Raised when transport operations fail permanently."""
    pass


class AuthenticationFailureError(TransportError):
    """Raised when agent authentication is rejected by server."""
    pass


class AgentTransportClient:
    """
    Authenticated HTTPS transport client for communication with CYBERGUARD backend.
    """

    def __init__(
        self,
        base_url: str,
        security_controller: AgentSecurityController,
        verify_ssl: bool = True,
        ca_cert_path: Optional[str] = None,
        timeout_seconds: float = 10.0,
        max_retries: int = 3,
        initial_backoff_seconds: float = 0.5,
        max_backoff_seconds: float = 10.0
    ):
        self.base_url = base_url.rstrip("/")
        self.security = security_controller
        self.verify_ssl = verify_ssl
        self.ca_cert_path = ca_cert_path
        self.timeout = timeout_seconds
        self.max_retries = max_retries
        self.initial_backoff = initial_backoff_seconds
        self.max_backoff = max_backoff_seconds

        verify_param = ca_cert_path if ca_cert_path else verify_ssl
        self._client = httpx.Client(
            base_url=self.base_url,
            verify=verify_param,
            timeout=self.timeout
        )

    def close(self) -> None:
        """Closes the underlying HTTP client session."""
        try:
            self._client.close()
        except Exception:
            pass

    def _execute_with_retry(
        self,
        method: str,
        path: str,
        json_data: Optional[Dict[str, Any]] = None
    ) -> httpx.Response:
        """
        Executes an HTTP request with signature authentication, backoff, and jitter.
        """
        import json
        body_bytes = json.dumps(json_data).encode("utf-8") if json_data else b""
        url_path = f"{self.base_url}{path}" if path.startswith("/") else f"{self.base_url}/{path}"

        last_error = None
        for attempt in range(1, self.max_retries + 1):
            try:
                # Sign request dynamically before each attempt
                auth_headers = self.security.sign_request(
                    method=method,
                    path=path,
                    body_bytes=body_bytes
                )
                headers = {
                    "Content-Type": "application/json",
                    **auth_headers
                }

                response = self._client.request(
                    method=method,
                    url=path,
                    content=body_bytes,
                    headers=headers
                )

                if response.status_code == 401 or response.status_code == 403:
                    logger.error(f"Authentication failure ({response.status_code}): {response.text}")
                    raise AuthenticationFailureError(f"Server rejected credentials: {response.text}")

                if response.status_code in (429, 502, 503, 504):
                    # Transient server pressure - back off and retry
                    logger.warning(f"Transient HTTP {response.status_code} received from {path}. Attempt {attempt}/{self.max_retries}")
                else:
                    response.raise_for_status()
                    return response

            except AuthenticationFailureError:
                raise
            except (httpx.RequestError, httpx.HTTPStatusError) as exc:
                last_error = exc
                logger.warning(f"Transport attempt {attempt}/{self.max_retries} failed for {path}: {exc}")

            if attempt < self.max_retries:
                # Exponential backoff with full jitter
                backoff = min(self.max_backoff, self.initial_backoff * (2 ** (attempt - 1)))
                jitter = random.uniform(0.5, 1.5)
                sleep_time = backoff * jitter
                time.sleep(sleep_time)

        raise TransportError(f"Request to {path} failed after {self.max_retries} attempts: {last_error}")

    def send_batch(self, batch_request: BatchTelemetryIngestRequest) -> BatchTelemetryIngestResponse:
        """Transmits a batch of telemetry events to /api/v1/endpoint/events."""
        path = "/api/v1/endpoint/events"
        resp = self._execute_with_retry("POST", path, batch_request.model_dump(mode="json"))
        return BatchTelemetryIngestResponse.model_validate(resp.json())

    def heartbeat(self, heartbeat_request: AgentHeartbeatRequest) -> AgentHeartbeatResponse:
        """Sends periodic heartbeat to /api/v1/endpoint/heartbeat."""
        path = "/api/v1/endpoint/heartbeat"
        resp = self._execute_with_retry("POST", path, heartbeat_request.model_dump(mode="json"))
        return AgentHeartbeatResponse.model_validate(resp.json())

    def fetch_configuration(self) -> AgentConfigurationResponse:
        """Fetches active signed agent configuration from /api/v1/endpoint/configuration."""
        path = f"/api/v1/endpoint/configuration?agent_id={self.security.agent_id}"
        resp = self._execute_with_retry("GET", path)
        return AgentConfigurationResponse.model_validate(resp.json())

    def rotate_credential(self, rotate_request: CredentialRotateRequest) -> CredentialRotateResponse:
        """Rotates agent machine credentials via /api/v1/endpoint/credential/rotate."""
        path = "/api/v1/endpoint/credential/rotate"
        resp = self._execute_with_retry("POST", path, rotate_request.model_dump(mode="json"))
        return CredentialRotateResponse.model_validate(resp.json())
