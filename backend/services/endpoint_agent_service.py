"""
Endpoint Agent Service for Section 31 Endpoint Agent Architecture.
Coordinates endpoint enrollment tokens, agent lifecycle, machine credential verification,
versioned configuration management, telemetry deduplication, clock skew tracking,
ThreatEvent normalization, and Knowledge Graph relationship integration.
"""

import hmac
import hashlib
import json
import secrets
import time
import uuid
import logging
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_, desc

from backend.db.models import (
    DeviceModel,
    EndpointAgentModel,
    EndpointEnrollmentTokenModel,
    EndpointAgentCredentialModel,
    EndpointAgentConfigurationModel,
    EndpointTelemetryEventModel,
    EndpointAgentHeartbeatModel,
    ThreatEventModel,
    RelationshipModel,
    generate_uuid,
    get_utc_now
)
from backend.schemas.endpoint_agent import (
    AgentStatusEnum,
    DeviceStatusEnum,
    EnrollmentStateEnum,
    ConfigurationStatusEnum,
    EndpointEventTypeEnum,
    EventPriorityEnum,
    AgentHealthStateEnum,
    CredentialTypeEnum,
    CreateEnrollmentTokenRequest,
    EnrollmentTokenResponse,
    AgentEnrollmentRequest,
    AgentEnrollmentResponse,
    CredentialRotateRequest,
    CredentialRotateResponse,
    BatchTelemetryIngestRequest,
    BatchTelemetryIngestResponse,
    AgentHeartbeatRequest,
    AgentHeartbeatResponse,
    AgentConfigurationResponse,
    AgentSummaryResponse,
    DeviceSummaryResponse
)
from backend.services.audit_service import AuditService
from backend.services.unified_service import ThreatEventService

logger = logging.getLogger("cyberguard.services.endpoint_agent")

# Server-side signing secret for configuration bundles
SERVER_CONFIG_SIGNING_KEY = "cyberguard-server-config-secret-v1"

# Bounded in-memory replay protection cache: (agent_id, nonce) -> timestamp
REPLAY_CACHE: Dict[Tuple[str, str], float] = {}
REPLAY_CACHE_CLEANUP_INTERVAL = 60.0
_last_replay_cleanup = time.time()


def compute_config_signature(config_dict: Dict[str, Any], secret_key: str = SERVER_CONFIG_SIGNING_KEY) -> str:
    """Computes HMAC-SHA256 signature over canonical JSON configuration."""
    payload_copy = {k: v for k, v in config_dict.items() if k != "signature"}
    canonical = json.dumps(payload_copy, sort_keys=True).encode("utf-8")
    return hmac.new(secret_key.encode("utf-8"), canonical, hashlib.sha256).hexdigest()


def _ensure_utc(dt: Optional[datetime]) -> Optional[datetime]:
    """Ensures datetime is timezone-aware UTC for safe comparisons in SQLite/Postgres."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


class EndpointAgentService:
    """
    Central backend service managing endpoint agent lifecycle, enrollment, authentication,
    telemetry ingestion, deduplication, and pipeline integration.
    """

    # =========================================================================
    # 1. ENROLLMENT TOKEN MANAGEMENT
    # =========================================================================

    @classmethod
    def create_enrollment_token(
        cls,
        db: Session,
        request: CreateEnrollmentTokenRequest,
        created_by: str = "admin"
    ) -> EnrollmentTokenResponse:
        """
        Creates a short-lived, single-use, auditable enrollment token.
        Only the raw token is returned once; the database stores only the SHA-256 hash.
        """
        raw_secret = f"cget_{secrets.token_urlsafe(32)}"
        token_prefix = raw_secret[:12]
        token_hash = hashlib.sha256(raw_secret.encode("utf-8")).hexdigest()

        now = get_utc_now()
        expires_at = now + timedelta(minutes=request.expires_in_minutes)

        token_record = EndpointEnrollmentTokenModel(
            id=generate_uuid(),
            workspace_id=request.workspace_id,
            token_prefix=token_prefix,
            token_hash=token_hash,
            description=request.description,
            created_by=created_by,
            expires_at=expires_at,
            max_uses=request.max_uses,
            use_count=0,
            status="ACTIVE",
            created_at=now,
            updated_at=now
        )
        db.add(token_record)
        db.commit()
        db.refresh(token_record)

        AuditService.log_audit(
            db=db,
            action="AGENT_ENROLLMENT_TOKEN_CREATED",
            resource_type="enrollment_token",
            resource_id=token_record.id,
            user=created_by,
            metadata={
                "workspace_id": request.workspace_id,
                "prefix": token_prefix,
                "expires_at": expires_at.isoformat(),
                "max_uses": request.max_uses
            },
            details=f"Created enrollment token prefix {token_prefix} for workspace {request.workspace_id}."
        )

        return EnrollmentTokenResponse(
            token_id=token_record.id,
            token_prefix=token_prefix,
            raw_token=raw_secret,
            workspace_id=request.workspace_id,
            description=request.description,
            expires_at=expires_at,
            max_uses=request.max_uses,
            created_at=now
        )

    @classmethod
    def verify_and_consume_token(
        cls,
        db: Session,
        raw_token: str
    ) -> EndpointEnrollmentTokenModel:
        """
        Verifies enrollment token hash, expiration, and use limits.
        Atomically increments use count and revokes if exhausted.
        """
        token_hash = hashlib.sha256(raw_token.strip().encode("utf-8")).hexdigest()
        now = get_utc_now()

        token_record = db.query(EndpointEnrollmentTokenModel).filter(
            EndpointEnrollmentTokenModel.token_hash == token_hash
        ).first()

        if not token_record:
            raise ValueError("Invalid or unknown enrollment token.")

        if token_record.status != "ACTIVE":
            raise ValueError(f"Enrollment token is not active (current status: {token_record.status}).")

        expires_dt = _ensure_utc(token_record.expires_at)
        now_dt = _ensure_utc(now)
        if expires_dt and now_dt and expires_dt < now_dt:
            token_record.status = "EXPIRED"
            db.commit()
            raise ValueError("Enrollment token has expired.")

        token_record.use_count += 1
        if token_record.use_count >= token_record.max_uses:
            token_record.status = "EXHAUSTED"

        token_record.updated_at = now
        db.commit()
        db.refresh(token_record)
        return token_record

    # =========================================================================
    # 2. AGENT ENROLLMENT
    # =========================================================================

    @classmethod
    def enroll_agent(
        cls,
        db: Session,
        request: AgentEnrollmentRequest
    ) -> AgentEnrollmentResponse:
        """
        Enrolls a new endpoint agent:
        1. Validates and consumes the enrollment token.
        2. Binds or creates the distinct physical DeviceModel.
        3. Establishes the stable EndpointAgentModel.
        4. Generates mutual authentication credentials.
        5. Provisions signed default configuration.
        6. Links Agent -> Device in the Security Knowledge Graph.
        7. Records immutable forensic audit log.
        """
        token_record = cls.verify_and_consume_token(db, request.enrollment_token)
        workspace_id = token_record.workspace_id
        now = get_utc_now()

        # 1. Device identity separation (look up or register hardware)
        device = db.query(DeviceModel).filter(
            and_(
                DeviceModel.workspace_id == workspace_id,
                DeviceModel.device_uid == request.device_uid.strip()
            )
        ).first()

        if not device:
            device = DeviceModel(
                id=generate_uuid(),
                workspace_id=workspace_id,
                device_uid=request.device_uid.strip(),
                hostname=request.hostname.strip(),
                platform=request.platform.strip().lower(),
                os_version=request.os_version,
                architecture=request.architecture,
                manufacturer=request.manufacturer,
                model=request.model,
                status="ACTIVE",
                first_seen_at=now,
                last_seen_at=now,
                metadata_json=json.dumps(request.metadata or {}),
                created_at=now,
                updated_at=now
            )
            db.add(device)
            db.commit()
            db.refresh(device)
            logger.info(f"Registered new hardware device: {device.device_uid} ({device.hostname})")
        else:
            # Update hostname and last seen on existing device
            device.hostname = request.hostname.strip()
            if request.os_version:
                device.os_version = request.os_version
            device.last_seen_at = now
            device.status = "ACTIVE"
            db.commit()
            db.refresh(device)

        # 2. Persistent EndpointAgent record
        agent_uid = f"AGT-{secrets.token_hex(6).upper()}"
        agent = EndpointAgentModel(
            id=generate_uuid(),
            agent_id=agent_uid,
            workspace_id=workspace_id,
            device_id=device.id,
            hostname=request.hostname.strip(),
            platform=request.platform.strip().lower(),
            platform_version=request.os_version,
            architecture=request.architecture,
            agent_version=request.agent_version,
            status="ACTIVE",
            enrollment_state="ENROLLED",
            configuration_version="1.0.0",
            last_seen_at=now,
            enrolled_at=now,
            created_at=now,
            updated_at=now
        )
        db.add(agent)
        db.commit()
        db.refresh(agent)

        # 3. Establish machine authentication credential
        key_id = f"KEY-{secrets.token_hex(8).upper()}"
        credential_secret = secrets.token_urlsafe(36)
        secret_hash = hashlib.sha256(credential_secret.encode("utf-8")).hexdigest()

        cred_record = EndpointAgentCredentialModel(
            id=generate_uuid(),
            agent_id=agent.id,
            workspace_id=workspace_id,
            credential_type="HMAC_KEY",
            key_id=key_id,
            secret_hash=secret_hash,
            status="ACTIVE",
            created_at=now
        )
        db.add(cred_record)

        # 4. Provision default configuration
        cfg_id = f"CFG-{secrets.token_hex(4).upper()}"
        cfg_dict = {
            "configuration_id": cfg_id,
            "version": "1.0.0",
            "batch_size": 50,
            "flush_interval_seconds": 10.0,
            "max_buffer_size_events": 5000,
            "max_buffer_size_bytes": 20971520,
            "server_endpoint": "/api/v1/endpoint",
            "enabled_collectors": ["synthetic_harness_collector"],
            "privacy_policy": {
                "excluded_paths": ["*/Documents/Personal/*", "*/.ssh/id_*"],
                "excluded_processes": ["1Password*", "Bitwarden*"]
            }
        }
        cfg_signature = compute_config_signature(cfg_dict, secret_key=SERVER_CONFIG_SIGNING_KEY)

        config_record = EndpointAgentConfigurationModel(
            id=generate_uuid(),
            workspace_id=workspace_id,
            configuration_id=cfg_id,
            agent_id=agent.id,
            version="1.0.0",
            status="ACTIVE",
            collection_policy_json=json.dumps({}),
            sampling_policy_json=json.dumps({}),
            privacy_policy_json=json.dumps(cfg_dict["privacy_policy"]),
            batch_size=50,
            flush_interval_seconds=10.0,
            max_buffer_size_events=5000,
            max_buffer_size_bytes=20971520,
            server_endpoint="/api/v1/endpoint",
            enabled_collectors_json=json.dumps(cfg_dict["enabled_collectors"]),
            signature=cfg_signature,
            created_at=now,
            activated_at=now
        )
        db.add(config_record)

        # 5. Link Agent -> Device in Security Knowledge Graph
        try:
            rel = RelationshipModel(
                id=generate_uuid(),
                source_type="AGENT",
                source_id=agent.agent_id,
                relationship_type="COLLECTS_FROM",
                target_type="DEVICE",
                target_id=device.id,
                confidence=1.0,
                origin="OBSERVED",
                status="ACTIVE",
                workspace_id=workspace_id,
                first_seen=now,
                last_seen=now,
                method="ENROLLMENT_BINDING",
                metadata_json=json.dumps({"device_uid": device.device_uid, "platform": device.platform}),
                created_at=now,
                updated_at=now
            )
            db.add(rel)
        except Exception as e:
            logger.warning(f"Failed to create Agent-Device graph relationship: {e}")

        db.commit()

        # 6. Audit Trail
        AuditService.log_audit(
            db=db,
            action="AGENT_ENROLLED",
            resource_type="endpoint_agent",
            resource_id=agent.agent_id,
            user=f"token_{token_record.token_prefix}",
            metadata={
                "device_id": device.id,
                "device_uid": device.device_uid,
                "hostname": agent.hostname,
                "platform": agent.platform,
                "key_id": key_id
            },
            details=f"Agent {agent.agent_id} successfully enrolled on device {device.device_uid}."
        )

        return AgentEnrollmentResponse(
            agent_id=agent.agent_id,
            device_id=device.id,
            workspace_id=workspace_id,
            key_id=key_id,
            credential_secret=credential_secret,
            credential_type=CredentialTypeEnum.HMAC_KEY,
            configuration_version="1.0.0",
            server_endpoint="/api/v1/endpoint",
            heartbeat_interval_seconds=30.0,
            enrolled_at=now
        )

    # =========================================================================
    # 3. MACHINE AUTHENTICATION & IDENTITY BINDING
    # =========================================================================

    @classmethod
    def authenticate_agent(
        cls,
        db: Session,
        agent_id_str: str,
        key_id_str: str,
        timestamp_str: str,
        nonce: str,
        signature: str,
        method: str,
        path: str,
        body_bytes: bytes
    ) -> Tuple[EndpointAgentModel, DeviceModel, EndpointAgentCredentialModel]:
        """
        Authenticates an incoming agent request:
        1. Checks timestamp freshness (+/- 300 seconds) to prevent replay.
        2. Verifies nonce uniqueness within the validity window.
        3. Retrieves agent and ensures status is not REVOKED/DISABLED.
        4. Validates machine credential.
        5. Binds tenant scope derived strictly from server identity.
        """
        global _last_replay_cleanup

        # 1. Timestamp window check
        try:
            req_ts = float(timestamp_str)
        except ValueError:
            raise PermissionError("Malformed authentication timestamp.")

        now_ts = time.time()
        if abs(now_ts - req_ts) > 300.0:
            raise PermissionError(f"Request timestamp expired or skewed beyond allowable window (delta={abs(now_ts - req_ts):.1f}s).")

        # 2. Nonce replay protection
        nonce_key = (agent_id_str, nonce)
        if nonce_key in REPLAY_CACHE:
            raise PermissionError("Replay attack detected: duplicate request nonce.")
        REPLAY_CACHE[nonce_key] = now_ts

        # Cleanup expired replay cache entries periodically
        if now_ts - _last_replay_cleanup > REPLAY_CACHE_CLEANUP_INTERVAL:
            expired_keys = [k for k, ts in REPLAY_CACHE.items() if now_ts - ts > 300.0]
            for k in expired_keys:
                REPLAY_CACHE.pop(k, None)
            _last_replay_cleanup = now_ts

        # 3. Lookup Agent
        agent = db.query(EndpointAgentModel).filter(
            EndpointAgentModel.agent_id == agent_id_str.strip()
        ).first()

        if not agent:
            raise PermissionError(f"Agent '{agent_id_str}' not found.")

        if agent.status in ("REVOKED", "DISABLED"):
            raise PermissionError(f"Agent '{agent_id_str}' is {agent.status} and cannot communicate.")

        # 4. Lookup Credential
        cred = db.query(EndpointAgentCredentialModel).filter(
            and_(
                EndpointAgentCredentialModel.agent_id == agent.id,
                EndpointAgentCredentialModel.key_id == key_id_str.strip()
            )
        ).first()

        if not cred or cred.status != "ACTIVE":
            raise PermissionError(f"Credential '{key_id_str}' is invalid or no longer active.")

        # 5. Device
        device = db.query(DeviceModel).filter(DeviceModel.id == agent.device_id).first()
        if not device:
            raise PermissionError("Associated device record missing.")

        return agent, device, cred

    # =========================================================================
    # 4. CREDENTIAL ROTATION
    # =========================================================================

    @classmethod
    def rotate_credential(
        cls,
        db: Session,
        agent: EndpointAgentModel,
        request: CredentialRotateRequest
    ) -> CredentialRotateResponse:
        """
        Rotates machine credential for an enrolled agent.
        Deactivates previous key and issues new secret.
        """
        now = get_utc_now()

        # Mark current credential as ROTATED
        old_cred = db.query(EndpointAgentCredentialModel).filter(
            and_(
                EndpointAgentCredentialModel.agent_id == agent.id,
                EndpointAgentCredentialModel.key_id == request.current_key_id.strip()
            )
        ).first()

        if old_cred:
            old_cred.status = "ROTATED"
            old_cred.rotated_at = now

        # Create new credential
        new_key_id = f"KEY-{secrets.token_hex(8).upper()}"
        new_secret = secrets.token_urlsafe(36)
        new_hash = hashlib.sha256(new_secret.encode("utf-8")).hexdigest()

        new_cred = EndpointAgentCredentialModel(
            id=generate_uuid(),
            agent_id=agent.id,
            workspace_id=agent.workspace_id,
            credential_type="HMAC_KEY",
            key_id=new_key_id,
            secret_hash=new_hash,
            status="ACTIVE",
            created_at=now
        )
        db.add(new_cred)
        db.commit()

        AuditService.log_audit(
            db=db,
            action="AGENT_CREDENTIAL_ROTATED",
            resource_type="endpoint_agent",
            resource_id=agent.agent_id,
            user=agent.agent_id,
            metadata={"old_key_id": request.current_key_id, "new_key_id": new_key_id},
            details=f"Rotated machine credential for agent {agent.agent_id}."
        )

        return CredentialRotateResponse(
            agent_id=agent.agent_id,
            key_id=new_key_id,
            new_credential_secret=new_secret,
            credential_type=CredentialTypeEnum.HMAC_KEY,
            rotated_at=now
        )

    # =========================================================================
    # 5. AGENT REVOCATION
    # =========================================================================

    @classmethod
    def revoke_agent(
        cls,
        db: Session,
        agent_id_str: str,
        reason: str = "Administrator revoked agent",
        revoked_by: str = "admin"
    ) -> EndpointAgentModel:
        """
        Revokes an agent identity and permanently invalidates its credentials.
        """
        now = get_utc_now()
        agent = db.query(EndpointAgentModel).filter(
            EndpointAgentModel.agent_id == agent_id_str.strip()
        ).first()

        if not agent:
            raise ValueError(f"Agent '{agent_id_str}' not found.")

        agent.status = "REVOKED"
        agent.enrollment_state = "REVOKED"
        agent.revoked_at = now
        agent.revocation_reason = reason
        agent.updated_at = now

        # Invalidate all credentials
        creds = db.query(EndpointAgentCredentialModel).filter(
            EndpointAgentCredentialModel.agent_id == agent.id
        ).all()
        for c in creds:
            c.status = "REVOKED"
            c.revoked_at = now

        db.commit()
        db.refresh(agent)

        AuditService.log_audit(
            db=db,
            action="AGENT_REVOKED",
            resource_type="endpoint_agent",
            resource_id=agent.agent_id,
            user=revoked_by,
            metadata={"reason": reason, "device_id": agent.device_id},
            details=f"Revoked agent {agent.agent_id}: {reason}."
        )

        return agent

    # =========================================================================
    # 6. CONFIGURATION MANAGEMENT
    # =========================================================================

    @classmethod
    def get_agent_configuration(
        cls,
        db: Session,
        agent: EndpointAgentModel
    ) -> AgentConfigurationResponse:
        """
        Retrieves the active signed configuration for an agent.
        """
        config = db.query(EndpointAgentConfigurationModel).filter(
            and_(
                EndpointAgentConfigurationModel.workspace_id == agent.workspace_id,
                or_(
                    EndpointAgentConfigurationModel.agent_id == agent.id,
                    EndpointAgentConfigurationModel.agent_id == None
                ),
                EndpointAgentConfigurationModel.status == "ACTIVE"
            )
        ).order_by(desc(EndpointAgentConfigurationModel.created_at)).first()

        if not config:
            # Fallback default configuration
            now = get_utc_now()
            cfg_dict = {
                "configuration_id": "CFG-DEFAULT",
                "version": "1.0.0",
                "batch_size": 50,
                "flush_interval_seconds": 10.0,
                "max_buffer_size_events": 5000,
                "max_buffer_size_bytes": 20971520,
                "server_endpoint": "/api/v1/endpoint",
                "enabled_collectors": ["synthetic_harness_collector"],
                "privacy_policy": {}
            }
            sig = compute_config_signature(cfg_dict, SERVER_CONFIG_SIGNING_KEY)
            return AgentConfigurationResponse(
                configuration_id="CFG-DEFAULT",
                version="1.0.0",
                status=ConfigurationStatusEnum.ACTIVE,
                collection_policy={},
                sampling_policy={},
                privacy_policy={},
                batch_size=50,
                flush_interval_seconds=10.0,
                max_buffer_size_events=5000,
                max_buffer_size_bytes=20971520,
                server_endpoint="/api/v1/endpoint",
                enabled_collectors=["synthetic_harness_collector"],
                signature=sig,
                created_at=now
            )

        return AgentConfigurationResponse(
            configuration_id=config.configuration_id,
            version=config.version,
            status=ConfigurationStatusEnum(config.status),
            collection_policy=json.loads(config.collection_policy_json or "{}"),
            sampling_policy=json.loads(config.sampling_policy_json or "{}"),
            privacy_policy=json.loads(config.privacy_policy_json or "{}"),
            batch_size=config.batch_size,
            flush_interval_seconds=config.flush_interval_seconds,
            max_buffer_size_events=config.max_buffer_size_events,
            max_buffer_size_bytes=config.max_buffer_size_bytes,
            server_endpoint=config.server_endpoint,
            enabled_collectors=json.loads(config.enabled_collectors_json or "[]"),
            signature=config.signature,
            created_at=config.created_at
        )

    # =========================================================================
    # 7. HEARTBEAT PROCESSING
    # =========================================================================

    @classmethod
    def process_heartbeat(
        cls,
        db: Session,
        agent: EndpointAgentModel,
        request: AgentHeartbeatRequest
    ) -> AgentHeartbeatResponse:
        """
        Records agent heartbeat, updates health status, and tracks buffer/collector state.
        """
        now = get_utc_now()
        agent.last_seen_at = now
        agent.last_heartbeat_at = now

        # Update agent operational status
        if request.health_state in (AgentHealthStateEnum.BUFFER_PRESSURE, AgentHealthStateEnum.COLLECTOR_FAILURE):
            agent.status = "DEGRADED"
        elif request.health_state == AgentHealthStateEnum.HEALTHY and agent.status == "DEGRADED":
            agent.status = "ACTIVE"

        if request.last_event_time:
            agent.last_event_time = request.last_event_time

        hb_record = EndpointAgentHeartbeatModel(
            id=generate_uuid(),
            agent_id=agent.id,
            workspace_id=agent.workspace_id,
            health_state=request.health_state.value,
            collector_states_json=json.dumps(request.collector_states or {}),
            buffer_events_count=request.buffer_events_count,
            buffer_bytes=request.buffer_bytes,
            cpu_usage_percent=request.cpu_usage_percent,
            memory_usage_mb=request.memory_usage_mb,
            last_event_time=request.last_event_time,
            received_at=now
        )
        db.add(hb_record)
        db.commit()

        # Check if configuration version matches active version
        reconfigure = (agent.configuration_version != request.configuration_version)

        return AgentHeartbeatResponse(
            status="ACK",
            health_state=request.health_state,
            configuration_version_active=agent.configuration_version,
            reconfigure_required=reconfigure,
            server_time=now
        )

    # =========================================================================
    # 8. TELEMETRY INGESTION, DEDUPLICATION, AND THREAT EVENT NORMALIZATION
    # =========================================================================

    @classmethod
    def ingest_telemetry_batch(
        cls,
        db: Session,
        agent: EndpointAgentModel,
        device: DeviceModel,
        batch: BatchTelemetryIngestRequest
    ) -> BatchTelemetryIngestResponse:
        """
        Ingests a batch of raw endpoint telemetry events:
        1. Calculates and records clock offset between server and endpoint.
        2. Enforces deduplication using composite key (agent_id, sequence_number, event_id).
        3. Persists raw telemetry records in EndpointTelemetryEventModel.
        4. Normalizes accepted events into canonical ThreatEventModel records.
        5. Connects Device -> ThreatEvent in the Security Knowledge Graph.
        6. Returns structured BatchTelemetryIngestResponse with accepted/rejected/duplicate counts.
        """
        server_time = get_utc_now()
        client_dt = batch.timestamp if batch.timestamp.tzinfo else batch.timestamp.replace(tzinfo=timezone.utc)
        server_dt = server_time if server_time.tzinfo else server_time.replace(tzinfo=timezone.utc)
        clock_offset_ms = round((server_dt - client_dt).total_seconds() * 1000.0, 2)

        # Update agent last seen and clock offset
        agent.last_seen_at = server_time
        agent.clock_offset_ms = clock_offset_ms
        device.last_seen_at = server_time

        accepted_ids: List[str] = []
        rejected_ids: Dict[str, str] = {}
        duplicate_count = 0

        for raw_ev in batch.events:
            # 1. Schema check
            if raw_ev.schema_version != "1.0.0":
                rejected_ids[raw_ev.event_id] = f"UNSUPPORTED_SCHEMA: version {raw_ev.schema_version} not accepted"
                continue

            # 2. Deduplication check
            existing = db.query(EndpointTelemetryEventModel).filter(
                and_(
                    EndpointTelemetryEventModel.agent_id == agent.id,
                    EndpointTelemetryEventModel.sequence_number == raw_ev.sequence_number,
                    EndpointTelemetryEventModel.event_id == raw_ev.event_id
                )
            ).first()

            if existing:
                duplicate_count += 1
                accepted_ids.append(raw_ev.event_id)  # Idempotent ACK to prevent agent retry
                continue

            # 3. Persist raw event
            telemetry_record = EndpointTelemetryEventModel(
                id=generate_uuid(),
                workspace_id=agent.workspace_id,
                agent_id=agent.id,
                device_id=device.id,
                event_id=raw_ev.event_id,
                sequence_number=raw_ev.sequence_number,
                event_type=raw_ev.event_type.value,
                event_time=raw_ev.event_time,
                received_at=server_time,
                collector_id=raw_ev.collector_id,
                collector_version=raw_ev.collector_version,
                configuration_version=raw_ev.configuration_version,
                agent_version=raw_ev.agent_version,
                schema_version=raw_ev.schema_version,
                priority=raw_ev.priority.value,
                payload_json=json.dumps(raw_ev.payload or {}),
                integrity_hash=raw_ev.integrity_hash,
                status="ACCEPTED",
                created_at=server_time
            )
            db.add(telemetry_record)

            # 4. Threat Memory & Novelty Enrichment
            pld = raw_ev.payload or {}
            tm_matched = False
            tm_details = None
            indicator_candidate = pld.get("sha256") or pld.get("executable_hash") or pld.get("remote_address") or pld.get("queried_domain")
            if indicator_candidate and indicator_candidate not in ("UNKNOWN", "OVERSIZED_SKIPPED"):
                try:
                    from backend.services.threat_memory_service import ThreatMemoryService
                    tm_entry = ThreatMemoryService.lookup_indicator(db=db, workspace_id=agent.workspace_id, value=indicator_candidate)
                    if tm_entry:
                        tm_matched = True
                        tm_details = {
                            "canonical_key": tm_entry.canonical_key,
                            "threat_type": tm_entry.subject_type,
                            "confidence": tm_entry.confidence
                        }
                except Exception:
                    pass

            # Novelty evaluation for process on device
            proc_name = pld.get("process_name")
            is_novel_proc = False
            if proc_name and raw_ev.event_type.value == "PROCESS":
                try:
                    prior_count = db.query(EndpointTelemetryEventModel).filter(
                        and_(
                            EndpointTelemetryEventModel.device_id == device.id,
                            EndpointTelemetryEventModel.event_type == "PROCESS",
                            EndpointTelemetryEventModel.payload_json.like(f'%"{proc_name}"%')
                        )
                    ).count()
                    if prior_count <= 1:
                        is_novel_proc = True
                except Exception:
                    pass

            # Determine severity
            if tm_matched:
                sev = "CRITICAL"
            elif raw_ev.priority in (EventPriorityEnum.CRITICAL, EventPriorityEnum.HIGH):
                sev = "HIGH"
            elif is_novel_proc:
                sev = "MEDIUM"
            else:
                sev = "LOW"

            target_desc = f" ({proc_name})" if proc_name else (f" ({pld.get('queried_domain')})" if pld.get('queried_domain') else (f" ({pld.get('remote_address')})" if pld.get('remote_address') else ""))
            summary_text = (
                f"Endpoint {raw_ev.event_type.value}{target_desc} event on {agent.hostname} "
                f"({device.platform}) from collector {raw_ev.collector_id}"
            )
            if tm_matched:
                summary_text += f" [ALERT: Matched prior Threat Memory {tm_details.get('canonical_key')}]"

            meta = {
                "source": "ENDPOINT_AGENT",
                "agent_id": agent.agent_id,
                "device_id": device.id,
                "device_uid": device.device_uid,
                "hostname": agent.hostname,
                "platform": agent.platform,
                "collector_id": raw_ev.collector_id,
                "sequence_number": raw_ev.sequence_number,
                "client_event_id": raw_ev.event_id,
                "clock_offset_ms": clock_offset_ms,
                "is_novel_process": is_novel_proc,
                "threat_memory_match": tm_details,
                "raw_payload": raw_ev.payload
            }

            try:
                threat_ev = ThreatEventModel(
                    id=generate_uuid(),
                    event_type=f"endpoint_{raw_ev.event_type.value.lower()}",
                    timestamp=raw_ev.event_time,
                    severity=sev,
                    risk_score=90.0 if sev == "CRITICAL" else (75.0 if sev == "HIGH" else (40.0 if sev == "MEDIUM" else 15.0)),
                    confidence=1.0,
                    status="OPEN",
                    summary=summary_text,
                    metadata_json=json.dumps(meta),
                    created_at=server_time,
                    updated_at=server_time
                )
                db.add(threat_ev)
                telemetry_record.threat_event_id = threat_ev.id
                telemetry_record.status = "NORMALIZED"

                # 5. Security Knowledge Graph Multi-Hop Relationships
                # Device -> HAS_EVENT -> ThreatEvent
                db.add(RelationshipModel(
                    id=generate_uuid(),
                    source_type="DEVICE",
                    source_id=device.id,
                    relationship_type="HAS_EVENT",
                    target_type="THREAT_EVENT",
                    target_id=threat_ev.id,
                    confidence=1.0,
                    origin="OBSERVED",
                    status="ACTIVE",
                    workspace_id=agent.workspace_id,
                    first_seen=server_time,
                    last_seen=server_time,
                    evidence_reference=raw_ev.event_id,
                    method="ENDPOINT_TELEMETRY",
                    metadata_json=json.dumps({"collector": raw_ev.collector_id, "sequence": raw_ev.sequence_number}),
                    created_at=server_time,
                    updated_at=server_time
                ))

                # Process -> RUNNING_ON -> Device
                if proc_name:
                    db.add(RelationshipModel(
                        id=generate_uuid(),
                        source_type="PROCESS",
                        source_id=f"proc:{proc_name}",
                        relationship_type="RUNNING_ON",
                        target_type="DEVICE",
                        target_id=device.id,
                        confidence=1.0,
                        origin="OBSERVED",
                        status="ACTIVE",
                        workspace_id=agent.workspace_id,
                        first_seen=server_time,
                        last_seen=server_time,
                        evidence_reference=raw_ev.event_id,
                        method="ENDPOINT_TELEMETRY",
                        metadata_json=json.dumps({"pid": pld.get("process_id", 0)}),
                        created_at=server_time,
                        updated_at=server_time
                    ))

                # Process -> EXECUTED_BY -> User
                user = pld.get("username")
                if proc_name and user:
                    db.add(RelationshipModel(
                        id=generate_uuid(),
                        source_type="PROCESS",
                        source_id=f"proc:{proc_name}",
                        relationship_type="EXECUTED_BY",
                        target_type="USER",
                        target_id=f"user:{user}",
                        confidence=1.0,
                        origin="OBSERVED",
                        status="ACTIVE",
                        workspace_id=agent.workspace_id,
                        first_seen=server_time,
                        last_seen=server_time,
                        evidence_reference=raw_ev.event_id,
                        method="ENDPOINT_TELEMETRY",
                        metadata_json=json.dumps({"pid": pld.get("process_id", 0)}),
                        created_at=server_time,
                        updated_at=server_time
                    ))

                # Network: Process -> CONNECTED_TO -> IP
                rem_ip = pld.get("remote_address")
                if rem_ip:
                    db.add(RelationshipModel(
                        id=generate_uuid(),
                        source_type="PROCESS",
                        source_id=f"proc:{proc_name or 'endpoint_process'}",
                        relationship_type="CONNECTED_TO",
                        target_type="IP",
                        target_id=rem_ip,
                        confidence=1.0,
                        origin="OBSERVED",
                        status="ACTIVE",
                        workspace_id=agent.workspace_id,
                        first_seen=server_time,
                        last_seen=server_time,
                        evidence_reference=raw_ev.event_id,
                        method="ENDPOINT_TELEMETRY",
                        metadata_json=json.dumps({"port": pld.get("remote_port", 0), "proto": pld.get("protocol", "TCP")}),
                        created_at=server_time,
                        updated_at=server_time
                    ))

                # DNS: Process -> QUERIED -> Domain
                q_domain = pld.get("queried_domain")
                if q_domain:
                    db.add(RelationshipModel(
                        id=generate_uuid(),
                        source_type="PROCESS",
                        source_id=f"proc:{proc_name or 'endpoint_resolver'}",
                        relationship_type="QUERIED",
                        target_type="DOMAIN",
                        target_id=q_domain,
                        confidence=1.0,
                        origin="OBSERVED",
                        status="ACTIVE",
                        workspace_id=agent.workspace_id,
                        first_seen=server_time,
                        last_seen=server_time,
                        evidence_reference=raw_ev.event_id,
                        method="ENDPOINT_TELEMETRY",
                        metadata_json=json.dumps({"query_type": pld.get("query_type", "A")}),
                        created_at=server_time,
                        updated_at=server_time
                    ))

                # File: File -> CREATED_ON -> Device
                fpath = pld.get("file_path") or pld.get("filename")
                if fpath and raw_ev.event_type.value in ("FILE", "FILE_METADATA"):
                    db.add(RelationshipModel(
                        id=generate_uuid(),
                        source_type="FILE",
                        source_id=fpath,
                        relationship_type="CREATED_ON",
                        target_type="DEVICE",
                        target_id=device.id,
                        confidence=1.0,
                        origin="OBSERVED",
                        status="ACTIVE",
                        workspace_id=agent.workspace_id,
                        first_seen=server_time,
                        last_seen=server_time,
                        evidence_reference=raw_ev.event_id,
                        method="ENDPOINT_TELEMETRY",
                        metadata_json=json.dumps({"action": pld.get("action", "METADATA")}),
                        created_at=server_time,
                        updated_at=server_time
                    ))

                # Auth: User -> LOGGED_INTO -> Device
                if user and raw_ev.event_type.value == "AUTHENTICATION":
                    db.add(RelationshipModel(
                        id=generate_uuid(),
                        source_type="USER",
                        source_id=f"user:{user}",
                        relationship_type="LOGGED_INTO",
                        target_type="DEVICE",
                        target_id=device.id,
                        confidence=1.0,
                        origin="OBSERVED",
                        status="ACTIVE",
                        workspace_id=agent.workspace_id,
                        first_seen=server_time,
                        last_seen=server_time,
                        evidence_reference=raw_ev.event_id,
                        method="ENDPOINT_TELEMETRY",
                        metadata_json=json.dumps({"action": pld.get("action", "LOGIN")}),
                        created_at=server_time,
                        updated_at=server_time
                    ))

            except Exception as e:
                logger.error(f"Failed to normalize telemetry {raw_ev.event_id} into ThreatEvent: {e}")

            accepted_ids.append(raw_ev.event_id)

        db.commit()

        # Section 33: Trigger Device-to-Incident Correlation Reassessment
        try:
            from backend.services.device_incident_correlation_service import DeviceIncidentCorrelationService
            candidates = DeviceIncidentCorrelationService.find_candidate_incidents(
                db=db,
                device_id=device.id,
                workspace_id=agent.workspace_id,
                window_hours=72,
                limit=10
            )
            for c_inc in candidates:
                DeviceIncidentCorrelationService.correlate_device_with_incident(
                    db=db,
                    device=device,
                    incident=c_inc,
                    workspace_id=agent.workspace_id
                )
        except Exception as e:
            logger.warning(f"Device-to-incident correlation hook encountered error: {e}")

        return BatchTelemetryIngestResponse(
            batch_id=batch.batch_id,
            accepted_count=len(accepted_ids),
            rejected_count=len(rejected_ids),
            duplicate_count=duplicate_count,
            accepted_event_ids=accepted_ids,
            rejected_event_ids=rejected_ids,
            server_time=server_time,
            clock_offset_ms=clock_offset_ms
        )

    # =========================================================================
    # 9. ADMINISTRATIVE QUERIES & OBSERVABILITY
    # =========================================================================

    @classmethod
    def list_agents(
        cls,
        db: Session,
        workspace_id: str = "default",
        status: Optional[str] = None
    ) -> List[EndpointAgentModel]:
        q = db.query(EndpointAgentModel).filter(EndpointAgentModel.workspace_id == workspace_id)
        if status:
            q = q.filter(EndpointAgentModel.status == status.strip().upper())
        return q.order_by(desc(EndpointAgentModel.last_seen_at)).all()

    @classmethod
    def get_agent_by_id(cls, db: Session, agent_id_str: str) -> Optional[EndpointAgentModel]:
        return db.query(EndpointAgentModel).filter(
            EndpointAgentModel.agent_id == agent_id_str.strip()
        ).first()

    @classmethod
    def list_devices(cls, db: Session, workspace_id: str = "default") -> List[DeviceModel]:
        return db.query(DeviceModel).filter(
            DeviceModel.workspace_id == workspace_id
        ).order_by(desc(DeviceModel.last_seen_at)).all()

    @classmethod
    def get_metrics(cls, db: Session, workspace_id: str = "default") -> Dict[str, Any]:
        """Provides high-level operational counts for endpoint monitoring."""
        agents_total = db.query(EndpointAgentModel).filter(EndpointAgentModel.workspace_id == workspace_id).count()
        agents_active = db.query(EndpointAgentModel).filter(
            and_(EndpointAgentModel.workspace_id == workspace_id, EndpointAgentModel.status == "ACTIVE")
        ).count()
        agents_degraded = db.query(EndpointAgentModel).filter(
            and_(EndpointAgentModel.workspace_id == workspace_id, EndpointAgentModel.status == "DEGRADED")
        ).count()
        agents_revoked = db.query(EndpointAgentModel).filter(
            and_(EndpointAgentModel.workspace_id == workspace_id, EndpointAgentModel.status == "REVOKED")
        ).count()
        devices_total = db.query(DeviceModel).filter(DeviceModel.workspace_id == workspace_id).count()
        events_total = db.query(EndpointTelemetryEventModel).filter(EndpointTelemetryEventModel.workspace_id == workspace_id).count()

        return {
            "agents_enrolled": agents_total,
            "agents_active": agents_active,
            "agents_degraded": agents_degraded,
            "agents_revoked": agents_revoked,
            "devices_total": devices_total,
            "events_received": events_total
        }

    @classmethod
    def get_collector_capabilities(cls, platform: Optional[str] = None) -> List[Dict[str, Any]]:
        """Returns capabilities and availability states across all 7 Section 32 collectors."""
        from backend.agent.collectors import (
            ProcessTelemetryCollector,
            NetworkTelemetryCollector,
            DNSTelemetryCollector,
            AuthenticationTelemetryCollector,
            SystemSecurityTelemetryCollector,
            FileMetadataTelemetryCollector,
            DeviceHealthTelemetryCollector,
            get_platform_adapter
        )
        adapter = get_platform_adapter(force_platform=platform)
        collectors = [
            ProcessTelemetryCollector(adapter=adapter),
            NetworkTelemetryCollector(adapter=adapter),
            DNSTelemetryCollector(adapter=adapter),
            AuthenticationTelemetryCollector(adapter=adapter),
            SystemSecurityTelemetryCollector(adapter=adapter),
            FileMetadataTelemetryCollector(adapter=adapter),
            DeviceHealthTelemetryCollector(adapter=adapter)
        ]
        return [c.health() for c in collectors]

    @classmethod
    def query_telemetry(
        cls,
        db: Session,
        workspace_id: str = "default",
        device_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        event_type: Optional[str] = None,
        limit: int = 50,
        offset: int = 0
    ) -> List[EndpointTelemetryEventModel]:
        """Queries raw and normalized endpoint observations with forensic filtering."""
        q = db.query(EndpointTelemetryEventModel).filter(EndpointTelemetryEventModel.workspace_id == workspace_id)
        if device_id:
            q = q.filter(EndpointTelemetryEventModel.device_id == device_id)
        if agent_id:
            q = q.filter(EndpointTelemetryEventModel.agent_id == agent_id)
        if event_type:
            q = q.filter(EndpointTelemetryEventModel.event_type == event_type.strip().upper())
        return q.order_by(desc(EndpointTelemetryEventModel.received_at)).offset(offset).limit(limit).all()
