"""
Section 74: Centralized Deployment Configuration & Environment Validation.
Enforces strict environment separation (DEVELOPMENT, TESTING, STAGING, PRODUCTION),
strongly typed configuration categories, secret masking, and deterministic startup validation.
"""
from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger("cyberguard.deployment_config")


class EnvironmentEnum(str, Enum):
    DEVELOPMENT = "DEVELOPMENT"
    TESTING = "TESTING"
    STAGING = "STAGING"
    PRODUCTION = "PRODUCTION"


class ConfigurationValidationError(Exception):
    """Raised when application startup configuration violates security or operational requirements."""
    pass


@dataclass
class DatabaseConfig:
    url: str
    pool_size: int = 10
    max_overflow: int = 20
    pool_recycle_seconds: int = 1800
    is_sqlite: bool = False

    @classmethod
    def from_env(cls, env: EnvironmentEnum) -> DatabaseConfig:
        raw_url = os.getenv("DATABASE_URL", "").strip()
        if not raw_url:
            if env in (EnvironmentEnum.PRODUCTION, EnvironmentEnum.STAGING):
                raise ConfigurationValidationError(
                    "DATABASE_URL is required in STAGING and PRODUCTION environments. Ephemeral SQLite is forbidden."
                )
            raw_url = "sqlite:///backend/data/mailtrace.db"

        # Normalize postgres:// to postgresql://
        if raw_url.startswith("postgres://"):
            raw_url = raw_url.replace("postgres://", "postgresql://", 1)

        is_sqlite = raw_url.startswith("sqlite")
        if env == EnvironmentEnum.PRODUCTION and is_sqlite:
            raise ConfigurationValidationError(
                "SQLite is strictly forbidden in PRODUCTION. A managed PostgreSQL database is required."
            )

        pool_size = int(os.getenv("DB_POOL_SIZE", "10"))
        max_overflow = int(os.getenv("DB_MAX_OVERFLOW", "20"))
        pool_recycle = int(os.getenv("DB_POOL_RECYCLE", "1800"))

        return cls(
            url=raw_url,
            pool_size=pool_size,
            max_overflow=max_overflow,
            pool_recycle_seconds=pool_recycle,
            is_sqlite=is_sqlite,
        )


@dataclass
class AuthSecurityConfig:
    jwt_secret: str
    token_expire_minutes: int = 1440
    algorithm: str = "HS256"

    @classmethod
    def from_env(cls, env: EnvironmentEnum) -> AuthSecurityConfig:
        secret = os.getenv("CYBERGUARD_AUTH_SECRET", os.getenv("JWT_SECRET", "")).strip()
        insecure_defaults = {"", "secret", "changeme", "default_secret", "admin", "123456", "dev_insecure_ephemeral_jwt_secret_key_32chars_min"}

        if env in (EnvironmentEnum.PRODUCTION, EnvironmentEnum.STAGING):
            if not secret or secret.lower() in insecure_defaults or len(secret) < 32:
                raise ConfigurationValidationError(
                    f"Production/Staging requires a cryptographically strong CYBERGUARD_AUTH_SECRET (at least 32 characters). "
                    f"Found insecure or empty secret."
                )
        elif not secret:
            secret = "dev_insecure_ephemeral_jwt_secret_key_32chars_min"

        return cls(
            jwt_secret=secret,
            token_expire_minutes=int(os.getenv("AUTH_TOKEN_EXPIRE_MINUTES", "1440")),
            algorithm=os.getenv("AUTH_ALGORITHM", "HS256"),
        )


@dataclass
class StorageConfig:
    storage_root: str
    eml_store: str
    reports_dir: str
    max_upload_size_mb: int = 10

    @classmethod
    def from_env(cls, env: EnvironmentEnum) -> StorageConfig:
        root = os.getenv("CYBERGUARD_STORAGE_ROOT", "backend/data/storage").strip()
        eml = os.getenv("CYBERGUARD_EML_STORE", "backend/data/eml_store").strip()
        reports = os.getenv("CYBERGUARD_REPORTS_DIR", "backend/data/reports").strip()
        max_mb = int(os.getenv("MAX_UPLOAD_SIZE_MB", "10"))

        if max_mb > 100 and env == EnvironmentEnum.PRODUCTION:
            logger.warning("MAX_UPLOAD_SIZE_MB is set above 100MB in production. Ensure storage capacity and timeouts are configured.")

        return cls(
            storage_root=root,
            eml_store=eml,
            reports_dir=reports,
            max_upload_size_mb=max_mb,
        )


@dataclass
class WorkerQueueConfig:
    enabled: bool = True
    concurrency: int = 4
    poll_interval_seconds: float = 1.0

    @classmethod
    def from_env(cls, env: EnvironmentEnum) -> WorkerQueueConfig:
        enabled = os.getenv("BACKGROUND_WORKER_ENABLED", "true").lower() in ("true", "1", "yes")
        concurrency = int(os.getenv("WORKER_CONCURRENCY", "4"))
        poll_interval = float(os.getenv("WORKER_POLL_INTERVAL", "1.0"))

        if concurrency < 1:
            raise ConfigurationValidationError("WORKER_CONCURRENCY must be at least 1.")

        return cls(
            enabled=enabled,
            concurrency=concurrency,
            poll_interval_seconds=poll_interval,
        )


@dataclass
class CorsConfig:
    allowed_origins: List[str]
    has_wildcard: bool

    @classmethod
    def from_env(cls, env: EnvironmentEnum) -> CorsConfig:
        raw = os.getenv("CORS_ORIGINS", "").strip()
        if raw:
            origins = [o.strip() for o in raw.split(",") if o.strip()]
        else:
            origins = [
                "http://localhost:5173",
                "http://127.0.0.1:5173",
                "http://localhost:3000",
                "http://127.0.0.1:3000",
            ]

        has_wildcard = "*" in origins
        if env == EnvironmentEnum.PRODUCTION and has_wildcard:
            raise ConfigurationValidationError(
                "Wildcard ('*') in CORS_ORIGINS is strictly forbidden in PRODUCTION when credentials or sessions are enabled."
            )

        return cls(allowed_origins=origins, has_wildcard=has_wildcard)


@dataclass
class DeploymentConfig:
    environment: EnvironmentEnum
    debug_mode: bool
    version: str
    build_sha: str
    database: DatabaseConfig
    auth: AuthSecurityConfig
    storage: StorageConfig
    worker: WorkerQueueConfig
    cors: CorsConfig

    @classmethod
    def load(cls) -> DeploymentConfig:
        """Loads and deterministically validates environment configuration."""
        raw_env = os.getenv("CYBERGUARD_ENV", os.getenv("ENV", "DEVELOPMENT")).upper().strip()
        try:
            env = EnvironmentEnum(raw_env)
        except ValueError:
            logger.warning("Unrecognized CYBERGUARD_ENV '%s'. Defaulting to DEVELOPMENT.", raw_env)
            env = EnvironmentEnum.DEVELOPMENT

        debug_flag = os.getenv("DEBUG", "false").lower() in ("true", "1", "yes")
        if env == EnvironmentEnum.PRODUCTION and debug_flag:
            raise ConfigurationValidationError(
                "DEBUG mode cannot be enabled in PRODUCTION environment. Set DEBUG=false."
            )

        version = os.getenv("CYBERGUARD_VERSION", "1.0.0")
        build_sha = os.getenv("BUILD_SHA", os.getenv("GIT_COMMIT_SHA", "unknown-sha"))

        db_cfg = DatabaseConfig.from_env(env)
        auth_cfg = AuthSecurityConfig.from_env(env)
        storage_cfg = StorageConfig.from_env(env)
        worker_cfg = WorkerQueueConfig.from_env(env)
        cors_cfg = CorsConfig.from_env(env)

        return cls(
            environment=env,
            debug_mode=debug_flag,
            version=version,
            build_sha=build_sha,
            database=db_cfg,
            auth=auth_cfg,
            storage=storage_cfg,
            worker=worker_cfg,
            cors=cors_cfg,
        )

    def mask_secret(self, val: str) -> str:
        """Returns masked representation for safe observability."""
        if not val or len(val) < 8:
            return "******"
        return f"{val[:3]}...{val[-3:]}"

    def get_public_metadata(self) -> Dict[str, Any]:
        """Returns non-sensitive deployment metadata for health and diagnostics."""
        return {
            "service": "cyberguard",
            "environment": self.environment.value,
            "version": self.version,
            "build_sha": self.build_sha,
            "debug": self.debug_mode,
            "database_driver": "sqlite" if self.database.is_sqlite else "postgresql",
            "worker_concurrency": self.worker.concurrency,
            "worker_enabled": self.worker.enabled,
            "cors_origins_count": len(self.cors.allowed_origins),
            "max_upload_size_mb": self.storage.max_upload_size_mb,
        }


# Global validated configuration singleton
try:
    global_deployment_config = DeploymentConfig.load()
except Exception as cfg_err:
    logger.error("Startup Configuration Validation Failed: %s", cfg_err)
    # Re-raise to fail fast on invalid configurations
    raise
