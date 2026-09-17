import os
from typing import Optional, Dict, Any


class GeolocationConfig:
    """
    Centralized configuration loader for Geolocation & IP Intelligence providers.
    Enforces security guarantees:
    - Never exposes secret API credentials to client-side code, logs, or error responses.
    - Resolves provider-specific environment variables with clean fallback precedence.
    - Accurately distinguishes between configured (authenticated/pro) and unconfigured states.
    """

    SUPPORTED_PROVIDERS = {"ipapi", "ipinfo", "mock", "unconfigured", "none"}

    def __init__(
        self,
        provider: Optional[str] = None,
        api_key: Optional[str] = None
    ):
        raw_provider = provider or os.getenv("IP_INTELLIGENCE_PROVIDER", "ipapi")
        self.provider = raw_provider.strip().lower() if raw_provider else "ipapi"
        if self.provider not in self.SUPPORTED_PROVIDERS:
            self.provider = "unconfigured"

        self._api_key = self._resolve_api_key(self.provider, explicit_key=api_key)

    @classmethod
    def _resolve_api_key(cls, provider: str, explicit_key: Optional[str] = None) -> Optional[str]:
        """
        Resolves API credentials with clean precedence:
        1. Explicitly injected key (useful for dependency injection in unit tests)
        2. Provider-specific variable (IPAPI_KEY or IPINFO_TOKEN / IPINFO_API_KEY)
        3. Legacy variable (IP_INTELLIGENCE_API_KEY)
        4. Generic variable (GEOLOCATION_API_KEY)
        """
        if explicit_key and isinstance(explicit_key, str) and explicit_key.strip():
            return explicit_key.strip().strip("'\"")

        resolved: Optional[str] = None

        if provider == "ipinfo":
            resolved = (
                os.getenv("IPINFO_TOKEN") or
                os.getenv("IPINFO_API_KEY") or
                os.getenv("GEOLOCATION_API_KEY") or
                os.getenv("IP_INTELLIGENCE_API_KEY")
            )
        elif provider == "ipapi":
            resolved = (
                os.getenv("IPAPI_KEY") or
                os.getenv("IP_INTELLIGENCE_API_KEY") or
                os.getenv("GEOLOCATION_API_KEY")
            )
        elif provider == "mock":
            return None

        if resolved and isinstance(resolved, str):
            clean = resolved.strip().strip("'\"")
            # Discard placeholder values from templates
            if clean and not clean.startswith("your_") and clean != "placeholder":
                return clean

        return None

    @property
    def is_configured(self) -> bool:
        """True if a valid non-placeholder API credential is configured for the active provider."""
        if self.provider == "mock":
            return True
        return bool(self._api_key)

    def get_api_key(self) -> Optional[str]:
        """
        Internal secret accessor. STRICTLY for backend outbound HTTP clients.
        NEVER expose this return value in API payloads, logs, or UI models.
        """
        return self._api_key

    def get_provider_status(self) -> Dict[str, Any]:
        """
        Safe public status summary.
        STRICT SECURITY: Never exposes the key or partial key characters.
        """
        if self.provider == "mock":
            return {
                "provider": "mock",
                "status": "Configured",
                "tier": "offline_mock",
                "mode": "air_gapped"
            }

        if self.is_configured:
            return {
                "provider": self.provider,
                "status": "Configured",
                "tier": "authenticated_pro",
                "mode": "external_live"
            }

        require_key = os.getenv("GEOLOCATION_REQUIRE_API_KEY", "false").lower() == "true"
        if self.provider == "ipapi" and not require_key:
            return {
                "provider": "ipapi",
                "status": "Configured",
                "tier": "free_standard",
                "mode": "external_live"
            }

        return {
            "provider": self.provider,
            "status": "Not Configured",
            "tier": "unconfigured",
            "mode": "inactive"
        }


# Global default configuration instance
global_geolocation_config = GeolocationConfig()
