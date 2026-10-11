"""
Section 59: Unified Threat Detection Pipeline Service for CYBERGUARD.

Implements the complete production detection execution layer:
1. Normalization: Source adapters for Email, Endpoint, Network, Auth, API, Generic.
2. Tenant Isolation: Multi-tenant scoping per workspace.
3. Rule Applicability: Filters by deployment state (PRODUCTION/SHADOW/REPLAY),
   validation state (Section 58 gates), event type, data sources, and dependencies.
4. Execution: Invokes Section 56 AST Evaluator under bounded timeout SLA (5.0s).
5. Persistence: Reuses CandidateRuleExecutionModel and DetectionMatchModel with full provenance.
6. Downstream Handoff: Generates FindingModel, computes Risk, evaluates Alert Policy,
   and streams Realtime updates (Section 46) & Notifications (Section 47).
7. Operational Reliability: Idempotency deduplication, error isolation, dead-letter storage,
   safe historical replay, and Section 45 Background Jobs.
8. Rule Health Feedback: Feeds real execution telemetry back into Section 57.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import logging
import math
import time
from typing import Any, Dict, List, Optional, Set, Tuple
import uuid

from fastapi import HTTPException, status
from sqlalchemy import desc, func, or_, and_
from sqlalchemy.orm import Session

from backend.db.models import (
    AuditLogModel,
    CandidateRuleModel,
    CandidateRuleVersionModel,
    CandidateRuleExecutionModel,
    DetectionMatchModel,
    DetectionDeadLetterModel,
    FindingModel,
    FindingEvidenceModel,
    NotificationModel,
    SecurityEventModel,
    BackgroundJobModel,
    generate_uuid,
    get_utc_now,
)
from backend.schemas.candidate_rules import (
    RuleLifecycleStatus,
    RuleSeverity,
    RuleType,
)
from backend.schemas.detection_rules import (
    DATA_SOURCE_FIELD_REGISTRY,
    DeploymentStateEnum,
    RuleCategory,
    RuleDataSource,
    RuleDefinition,
    RuleScope,
    ValidationStatusEnum,
)
from backend.schemas.detection_pipeline import (
    BatchEventIngestRequest,
    BatchPipelineResponse,
    DeadLetterItem,
    DetectionMatchListItem,
    EvaluationOutcomeEnum,
    EventIngestRequest,
    NormalizedDetectionEvent,
    PipelineExecutionResponse,
    PipelineHealthStatusEnum,
    PipelineModeEnum,
    PipelineReplayRequest,
    PipelineStageEnum,
    PipelineMetricsResponse,
    RuleEvaluationDetail,
)
from backend.schemas.notification import (
    NotificationCategoryEnum,
    NotificationSeverityEnum,
    NotificationTypeEnum,
)
from backend.schemas.realtime import (
    RealtimeEvent,
    RealtimeEventTypeEnum,
    RealtimeResourceScopeEnum,
)
from backend.services.detection_rule_lifecycle_service import DetectionRuleLifecycleService
from backend.services.detection_rule_management_service import DetectionRuleManagementService
from backend.services.notification_service import NotificationService
from backend.services.realtime_service import RealtimePublisher

logger = logging.getLogger("cyberguard.services.detection_pipeline")

EXECUTION_TIMEOUT_SECONDS = 5.0
MAX_PAYLOAD_SIZE_BYTES = 1_048_576  # 1 MB


# ============================================================================
# 1. SOURCE ADAPTERS (NORMALIZATION LAYER)
# ============================================================================

class EmailSourceAdapter:
    """Normalizes email telemetry and parsed artifact analysis records."""

    @staticmethod
    def normalize(raw: Dict[str, Any]) -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[Dict[str, Any]]]:
        sender_domain = str(raw.get("sender_domain") or raw.get("domain") or raw.get("email.sender_domain") or "").strip().lower()
        sender_address = str(raw.get("sender_address") or raw.get("sender") or raw.get("from") or raw.get("sender_email") or raw.get("email.sender_address") or "").strip().lower()
        recipient_address = str(raw.get("recipient_address") or raw.get("recipient") or raw.get("to") or raw.get("recipient_email") or raw.get("email.recipient_address") or "").strip().lower()
        subject = str(raw.get("subject") or raw.get("email.subject") or "").strip()
        auth_result = str(raw.get("auth_result") or raw.get("spf_result") or raw.get("email.auth_result") or "PASS").upper()
        client_ip = str(raw.get("client_ip") or raw.get("ip_address") or raw.get("email.client_ip") or "").strip()
        has_attachments = bool(raw.get("has_attachments", False) or raw.get("attachment_count", 0) > 0)
        attachment_type = str(raw.get("attachment_type") or "").strip().lower()
        attachment_count = int(raw.get("attachment_count", 0))
        url_count = int(raw.get("url_count", 0))
        contains_login_url = bool(raw.get("contains_login_url", False))
        is_external = bool(raw.get("is_external", True))
        threat_verdict = str(raw.get("threat_verdict") or raw.get("verdict") or "CLEAN").upper()
        confidence = float(raw.get("confidence", 0.8))
        domain_age_days = int(raw.get("domain_age_days", 365))

        payload: Dict[str, Any] = {
            # Flat attributes
            "sender_domain": sender_domain,
            "sender_address": sender_address,
            "recipient_address": recipient_address,
            "subject": subject,
            "has_attachments": has_attachments,
            "attachment_type": attachment_type,
            "attachment_count": attachment_count,
            "url_count": url_count,
            "contains_login_url": contains_login_url,
            "is_external": is_external,
            "threat_verdict": threat_verdict,
            "confidence": confidence,
            "domain_age_days": domain_age_days,
            "auth_result": auth_result,
            "client_ip": client_ip,
            # Dotted aliases for AST evaluation
            "email.sender_domain": sender_domain,
            "email.sender_address": sender_address,
            "email.sender": sender_address,
            "email.recipient_address": recipient_address,
            "email.recipient": recipient_address,
            "email.subject": subject,
            "email.auth_result": auth_result,
            "email.spf_result": auth_result,
            "email.client_ip": client_ip,
            "email.has_attachments": has_attachments,
            "email.attachment_count": attachment_count,
            "email.url_count": url_count,
            "email.threat_verdict": threat_verdict,
            "email.is_external": is_external,
        }

        entities: List[Dict[str, Any]] = []
        if payload["sender_domain"]:
            entities.append({"type": "DOMAIN", "value": payload["sender_domain"]})
        if payload["sender_address"]:
            entities.append({"type": "EMAIL", "value": payload["sender_address"]})
        if payload["client_ip"]:
            entities.append({"type": "IP", "value": payload["client_ip"]})

        indicators: List[Dict[str, Any]] = []
        if payload["sender_domain"]:
            indicators.append({"type": "DOMAIN", "value": payload["sender_domain"]})
        if payload["sender_address"]:
            indicators.append({"type": "EMAIL", "value": payload["sender_address"]})
        for url in raw.get("urls", []):
            if isinstance(url, str):
                indicators.append({"type": "URL", "value": url})
        for sha in raw.get("attachment_hashes", []):
            if isinstance(sha, str):
                indicators.append({"type": "HASH", "value": sha})

        return payload, entities, indicators


class EndpointSourceAdapter:
    """Normalizes host, process, command line, and device telemetry."""

    @staticmethod
    def normalize(raw: Dict[str, Any]) -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[Dict[str, Any]]]:
        process_name = str(raw.get("process_name") or raw.get("process") or raw.get("process.name") or "").strip()
        command_line = str(raw.get("command_line") or raw.get("cmd") or raw.get("process.command_line") or "").strip()
        parent_process_name = str(raw.get("parent_process_name") or raw.get("parent_process") or raw.get("process.parent_name") or "").strip()
        sha256 = str(raw.get("sha256") or raw.get("file_hash") or raw.get("file.sha256") or "").strip().lower()
        file_path = str(raw.get("file_path") or raw.get("path") or raw.get("file.path") or "").strip()
        user_id = str(raw.get("user_id") or raw.get("user") or raw.get("user.id") or "").strip()
        username = str(raw.get("username") or raw.get("user") or raw.get("user.name") or "").strip()
        device_id = str(raw.get("device_id") or raw.get("host_id") or raw.get("endpoint.id") or "").strip()
        hostname = str(raw.get("hostname") or raw.get("endpoint.hostname") or "").strip()
        action = str(raw.get("action") or "PROCESS_START").upper()
        integrity_level = str(raw.get("integrity_level") or "MEDIUM").upper()

        payload: Dict[str, Any] = {
            # Flat attributes
            "process_name": process_name,
            "command_line": command_line,
            "parent_process_name": parent_process_name,
            "sha256": sha256,
            "file_path": file_path,
            "user_id": user_id,
            "username": username,
            "device_id": device_id,
            "hostname": hostname,
            "action": action,
            "integrity_level": integrity_level,
            # Dotted aliases for AST evaluation
            "process.name": process_name,
            "process.command_line": command_line,
            "process.parent_name": parent_process_name,
            "parent_process.name": parent_process_name,
            "file.sha256": sha256,
            "file.path": file_path,
            "user.id": user_id,
            "user.name": username,
            "endpoint.id": device_id,
            "endpoint.hostname": hostname,
            "endpoint.action": action,
        }

        entities: List[Dict[str, Any]] = []
        if payload["device_id"]:
            entities.append({"type": "DEVICE", "value": payload["device_id"]})
        if payload["user_id"]:
            entities.append({"type": "USER", "value": payload["user_id"]})

        indicators: List[Dict[str, Any]] = []
        if payload["sha256"]:
            indicators.append({"type": "HASH", "value": payload["sha256"]})

        return payload, entities, indicators


class NetworkSourceAdapter:
    """Normalizes network flows, DNS requests, and firewall connections."""

    @staticmethod
    def normalize(raw: Dict[str, Any]) -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[Dict[str, Any]]]:
        ip_address = str(raw.get("ip_address") or raw.get("dest_ip") or raw.get("dst_ip") or raw.get("network.destination_ip") or "").strip()
        source_ip = str(raw.get("source_ip") or raw.get("src_ip") or raw.get("network.source_ip") or "").strip()
        dest_port = int(raw.get("dest_port") or raw.get("dst_port") or raw.get("port") or raw.get("network.destination_port") or 0)
        src_port = int(raw.get("src_port") or raw.get("network.source_port") or 0)
        protocol = str(raw.get("protocol") or raw.get("network.protocol") or "TCP").upper()
        asn_number = int(raw.get("asn_number") or raw.get("asn") or 0)
        dns_query = str(raw.get("dns_query") or raw.get("domain") or raw.get("dns.query") or "").strip().lower()
        bytes_in = int(raw.get("bytes_in", 0))
        bytes_out = int(raw.get("bytes_out", 0))
        packets_count = int(raw.get("packets_count", 1))
        tls_version = str(raw.get("tls_version") or "").strip()
        ja3_hash = str(raw.get("ja3_hash") or "").strip()

        payload: Dict[str, Any] = {
            # Flat attributes
            "ip_address": ip_address,
            "source_ip": source_ip,
            "dest_port": dest_port,
            "src_port": src_port,
            "protocol": protocol,
            "asn_number": asn_number,
            "dns_query": dns_query,
            "bytes_in": bytes_in,
            "bytes_out": bytes_out,
            "packets_count": packets_count,
            "tls_version": tls_version,
            "ja3_hash": ja3_hash,
            # Dotted aliases for AST evaluation
            "network.destination_ip": ip_address,
            "network.dest_ip": ip_address,
            "network.source_ip": source_ip,
            "network.src_ip": source_ip,
            "network.destination_port": dest_port,
            "network.dest_port": dest_port,
            "network.source_port": src_port,
            "network.protocol": protocol,
            "dns.query": dns_query,
            "dns.domain": dns_query,
            "network.bytes_in": bytes_in,
            "network.bytes_out": bytes_out,
        }

        entities: List[Dict[str, Any]] = []
        if payload["ip_address"]:
            entities.append({"type": "IP", "value": payload["ip_address"]})
        if payload["dns_query"]:
            entities.append({"type": "DOMAIN", "value": payload["dns_query"]})

        indicators: List[Dict[str, Any]] = []
        if payload["ip_address"]:
            indicators.append({"type": "IP", "value": payload["ip_address"]})

        return payload, entities, indicators


class AuthSourceAdapter:
    """Normalizes identity authentication and logon events."""

    @staticmethod
    def normalize(raw: Dict[str, Any]) -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[Dict[str, Any]]]:
        auth_result = str(raw.get("auth_result") or raw.get("status") or raw.get("auth.status") or "SUCCESS").upper()
        user_id = str(raw.get("user_id") or raw.get("user") or raw.get("username") or "").strip()
        username = str(raw.get("username") or raw.get("user") or raw.get("user_id") or "").strip()
        ip_address = str(raw.get("ip_address") or raw.get("client_ip") or raw.get("auth.client_ip") or "").strip()
        auth_method = str(raw.get("auth_method") or "PASSWORD").upper()
        user_agent = str(raw.get("user_agent") or "").strip()
        failed_attempts = int(raw.get("failed_attempts", 0))
        is_new_location = bool(raw.get("is_new_location", False))

        payload: Dict[str, Any] = {
            # Flat attributes
            "auth_result": auth_result,
            "user_id": user_id,
            "username": username,
            "ip_address": ip_address,
            "auth_method": auth_method,
            "user_agent": user_agent,
            "failed_attempts": failed_attempts,
            "is_new_location": is_new_location,
            # Dotted aliases for AST evaluation
            "auth.status": auth_result,
            "auth.result": auth_result,
            "auth.user_id": user_id,
            "auth.username": username,
            "auth.client_ip": ip_address,
            "auth.method": auth_method,
            "auth.failed_attempts": failed_attempts,
            "user.id": user_id,
            "user.name": username,
        }

        entities: List[Dict[str, Any]] = []
        if payload["user_id"]:
            entities.append({"type": "USER", "value": payload["user_id"]})
        if payload["ip_address"]:
            entities.append({"type": "IP", "value": payload["ip_address"]})

        indicators: List[Dict[str, Any]] = []
        if payload["ip_address"]:
            indicators.append({"type": "IP", "value": payload["ip_address"]})

        return payload, entities, indicators


class ApiSourceAdapter:
    """Normalizes API access, rate limiting, and authorization telemetry."""

    @staticmethod
    def normalize(raw: Dict[str, Any]) -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[Dict[str, Any]]]:
        endpoint = str(raw.get("endpoint") or raw.get("path") or raw.get("api.endpoint") or "").strip()
        method = str(raw.get("method") or raw.get("api.method") or "GET").upper()
        response_code = int(raw.get("response_code") or raw.get("status_code") or raw.get("api.response_code") or 200)
        api_key_id = str(raw.get("api_key_id") or raw.get("api.key_id") or "").strip()
        rate_limit_exceeded = bool(raw.get("rate_limit_exceeded", False))
        user_id = str(raw.get("user_id") or raw.get("api.user_id") or "").strip()
        ip_address = str(raw.get("ip_address") or raw.get("api.client_ip") or "").strip()

        payload: Dict[str, Any] = {
            # Flat attributes
            "endpoint": endpoint,
            "method": method,
            "response_code": response_code,
            "api_key_id": api_key_id,
            "rate_limit_exceeded": rate_limit_exceeded,
            "user_id": user_id,
            "ip_address": ip_address,
            # Dotted aliases for AST evaluation
            "api.endpoint": endpoint,
            "api.method": method,
            "api.response_code": response_code,
            "api.key_id": api_key_id,
            "api.rate_limit_exceeded": rate_limit_exceeded,
            "api.user_id": user_id,
            "api.client_ip": ip_address,
        }

        entities: List[Dict[str, Any]] = []
        if payload["ip_address"]:
            entities.append({"type": "IP", "value": payload["ip_address"]})
        if payload["user_id"]:
            entities.append({"type": "USER", "value": payload["user_id"]})

        return payload, entities, []


class GenericSourceAdapter:
    """Pass-through adapter with type normalization and field sanitization."""

    @staticmethod
    def normalize(raw: Dict[str, Any]) -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[Dict[str, Any]]]:
        payload: Dict[str, Any] = {}
        entities: List[Dict[str, Any]] = []
        indicators: List[Dict[str, Any]] = []

        for k, v in raw.items():
            if isinstance(v, (str, int, float, bool)):
                payload[k] = v
            elif isinstance(v, (list, dict)):
                payload[k] = v

        if "ip_address" in payload:
            entities.append({"type": "IP", "value": str(payload["ip_address"])})
        if "sender_domain" in payload:
            entities.append({"type": "DOMAIN", "value": str(payload["sender_domain"])})

        return payload, entities, indicators


SOURCE_ADAPTER_MAP = {
    "EMAIL": EmailSourceAdapter,
    "EMAIL_EVENT": EmailSourceAdapter,
    "ENDPOINT": EndpointSourceAdapter,
    "ENDPOINT_EVENT": EndpointSourceAdapter,
    "NETWORK": NetworkSourceAdapter,
    "NETWORK_EVENT": NetworkSourceAdapter,
    "AUTH": AuthSourceAdapter,
    "AUTH_EVENT": AuthSourceAdapter,
    "AUTHENTICATION": AuthSourceAdapter,
    "API": ApiSourceAdapter,
    "API_EVENT": ApiSourceAdapter,
    "GENERIC": GenericSourceAdapter,
}


# ============================================================================
# 2. CORE DETECTION PIPELINE SERVICE
# ============================================================================

class UnifiedThreatDetectionPipelineService:
    """
    Section 59: Production Unified Threat Detection Pipeline.
    Coordinates the end-to-end lifecycle from raw security telemetry through
    applicable rule selection, AST evaluator execution, match persistence,
    and downstream Finding / Risk / Alert handoff.
    """

    # In-memory fast cache for active compiled rules: {workspace_id: (timestamp, rules)}
    _rule_cache: Dict[str, Tuple[float, List[CandidateRuleModel]]] = {}
    _cache_ttl_seconds: float = 60.0

    @classmethod
    def invalidate_rule_cache(cls, workspace_id: Optional[str] = None) -> None:
        """Evicts active rule cache when rules are updated, deployed, or validated."""
        if workspace_id:
            cls._rule_cache.pop(workspace_id, None)
        else:
            cls._rule_cache.clear()

    # =========================================================================
    # STAGE 1, 2 & 3: RECEIVE, VALIDATE & NORMALIZE
    # =========================================================================

    @classmethod
    def normalize_event(
        cls,
        db: Session,
        req: EventIngestRequest,
        workspace_id: Optional[str] = None,
    ) -> Tuple[NormalizedDetectionEvent, Optional[str]]:
        """
        Receives raw telemetry input, validates boundaries, applies the source adapter,
        and produces a canonical NormalizedDetectionEvent.
        """
        raw_json_str = json.dumps(req.payload)
        if len(raw_json_str.encode("utf-8")) > MAX_PAYLOAD_SIZE_BYTES:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"Payload exceeds maximum allowed size of {MAX_PAYLOAD_SIZE_BYTES} bytes.",
            )

        workspace_id = (workspace_id or req.workspace_id or "default").strip()
        source_type = req.source_type.upper().strip()
        event_type = req.event_type or f"{source_type}_EVENT"
        event_id = req.event_id or f"EVT-{generate_uuid()[:12]}"
        now = get_utc_now()
        occurred_at = req.occurred_at or now

        # Select Adapter
        adapter_cls = SOURCE_ADAPTER_MAP.get(source_type, GenericSourceAdapter)
        try:
            norm_payload, entities, indicators = adapter_cls.normalize(req.payload)
        except Exception as exc:
            logger.error("Failed normalizing event %s with adapter %s: %s", event_id, adapter_cls.__name__, exc)
            cls._record_dead_letter(
                db=db,
                workspace_id=workspace_id,
                event_id=event_id,
                source_type=source_type,
                failure_stage=PipelineStageEnum.NORMALIZE.value,
                error_code="NORMALIZATION_FAILED",
                error_message=str(exc),
                payload=req.payload,
            )
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Normalization failed: {exc}",
            )

        provenance = req.provenance or {}
        provenance.setdefault("adapter", adapter_cls.__name__)
        provenance.setdefault("ingested_at", now.isoformat())
        if req.source_id:
            provenance.setdefault("source_id", req.source_id)

        norm_event = NormalizedDetectionEvent(
            event_id=event_id,
            workspace_id=workspace_id,
            event_type=event_type,
            source_type=source_type,
            source_id=req.source_id,
            occurred_at=occurred_at,
            received_at=now,
            payload=norm_payload,
            entities=entities,
            indicators=indicators,
            provenance=provenance,
            schema_version="1.0",
        )

        # Persist normalized SecurityEventModel for traceability and replay
        sec_event = None
        try:
            sec_event = SecurityEventModel(
                id=event_id,
                workspace_id=workspace_id,
                event_type=event_type,
                event_time=occurred_at,
                source_type=source_type,
                provider="cyberguard_pipeline",
                adapter=adapter_cls.__name__,
                attributes_json=json.dumps(norm_payload),
                timestamp_provenance_json=json.dumps(provenance),
                summary=f"Normalized {source_type} event: {event_id}",
            )
            db.add(sec_event)
            db.flush()
        except Exception as exc:
            # If already exists (idempotent replay), ignore duplicate insert
            db.rollback()
            logger.debug("SecurityEvent %s already persisted or error: %s", event_id, exc)

        return norm_event, event_id

    # =========================================================================
    # STAGE 4 & 5: TENANT SCOPE & RESOLVE APPLICABLE RULES
    # =========================================================================

    @classmethod
    def select_applicable_rules(
        cls,
        db: Session,
        event: NormalizedDetectionEvent,
        mode: PipelineModeEnum = PipelineModeEnum.PRODUCTION,
        rule_ids_filter: Optional[Any] = None,
        workspace_id: Optional[str] = None,
    ) -> List[CandidateRuleModel]:
        """
        Determines eligible detection rules for evaluation against the event.
        Filters by:
        1. Tenant scope (workspace_id)
        2. Deployment State & Status (PRODUCTION/ACTIVE vs STAGING/SHADOW)
        3. Section 58 Validation State (excludes FAIL, BLOCKED, STALE)
        4. Data Source Applicability (matches event_type to rule's declared data sources)
        """
        if isinstance(rule_ids_filter, str):
            eff_workspace_id = rule_ids_filter
            eff_rule_filter = None
        else:
            eff_workspace_id = workspace_id or event.workspace_id
            eff_rule_filter = rule_ids_filter if isinstance(rule_ids_filter, list) else None

        # Query candidates
        query = db.query(CandidateRuleModel).filter(
            CandidateRuleModel.workspace_id == eff_workspace_id,
        )

        if eff_rule_filter:
            query = query.filter(
                (CandidateRuleModel.id.in_(eff_rule_filter)) |
                (CandidateRuleModel.rule_identifier.in_(eff_rule_filter))
            )
        elif mode == PipelineModeEnum.PRODUCTION:
            query = query.filter(
                CandidateRuleModel.deployment_state == DeploymentStateEnum.PRODUCTION.value,
                CandidateRuleModel.status == RuleLifecycleStatus.ACTIVE.value,
            )
        elif mode == PipelineModeEnum.SHADOW:
            query = query.filter(
                (CandidateRuleModel.deployment_state.in_([DeploymentStateEnum.STAGING.value, DeploymentStateEnum.PRODUCTION.value])) |
                (CandidateRuleModel.status.in_([RuleLifecycleStatus.STAGED.value, RuleLifecycleStatus.ACTIVE.value]))
            )
        elif mode == PipelineModeEnum.REPLAY:
            query = query.filter(
                CandidateRuleModel.deployment_state == DeploymentStateEnum.PRODUCTION.value,
                CandidateRuleModel.status == RuleLifecycleStatus.ACTIVE.value,
            )

        candidates = query.all()

        applicable: List[CandidateRuleModel] = []
        for rule in candidates:
            # 1. Section 58 Quality Gate check: exclude known failing or blocked rules
            val_status = getattr(rule, "validation_status", "NOT_RUN")
            if mode == PipelineModeEnum.PRODUCTION and val_status in (ValidationStatusEnum.FAIL.value, ValidationStatusEnum.BLOCKED.value):
                logger.debug("Skipping rule %s due to failing validation status %s", rule.id, val_status)
                continue

            # 2. Data Source applicability check
            rule_sources = rule.data_sources
            if not rule_sources:
                defn = rule.definition or {}
                if isinstance(defn, dict) and defn.get("source"):
                    rule_sources = [defn["source"]]
                else:
                    rule_sources = []

            # If rule specifies sources, require matching source category or event type
            if rule_sources:
                src_normalized = [s.upper().replace("_EVENT", "") for s in rule_sources]
                ev_src = event.source_type.upper().replace("_EVENT", "")
                source_matches = (
                    ev_src in src_normalized or
                    event.event_type.upper() in [s.upper() for s in rule_sources] or
                    RuleDataSource.INDICATOR.value in rule_sources or
                    RuleDataSource.THREAT_INTELLIGENCE.value in rule_sources
                )
                if not source_matches:
                    continue

            applicable.append(rule)

        return applicable

    # =========================================================================
    # STAGE 6: EXECUTE APPLICABLE RULES
    # =========================================================================

    @classmethod
    def evaluate_rules(
        cls,
        db: Session,
        event: NormalizedDetectionEvent,
        applicable_rules: List[CandidateRuleModel],
        mode: PipelineModeEnum = PipelineModeEnum.PRODUCTION,
    ) -> List[RuleEvaluationDetail]:
        """
        Executes applicable detection rules against the normalized event using
        Section 56's AST Evaluator.
        Records execution telemetry in CandidateRuleExecutionModel.
        """
        evaluations: List[RuleEvaluationDetail] = []
        now = get_utc_now()

        for rule in applicable_rules:
            # 1. Check Section 57 Suppression Exception
            suppression = DetectionRuleManagementService.check_suppression(db, rule.id, event.payload)
            if suppression is not None:
                eval_detail = RuleEvaluationDetail(
                    rule_id=rule.id,
                    rule_identifier=rule.rule_identifier,
                    rule_name=rule.name,
                    rule_version=str(rule.version),
                    category=rule.category,
                    severity=rule.severity,
                    outcome=EvaluationOutcomeEnum.SKIPPED,
                    matched=False,
                    execution_time_ms=0.0,
                    skip_reason=f"Suppressed by exception '{suppression.name}' ({suppression.reason}).",
                )
                evaluations.append(eval_detail)
                continue

            # 2. Execute Evaluator with Bounded Timeout SLA
            exec_start = time.perf_counter()
            outcome = EvaluationOutcomeEnum.NO_MATCH
            matched = False
            matched_conds: List[Dict[str, Any]] = []
            explanation = ""
            error_msg: Optional[str] = None
            exec_time_ms = 0.0

            try:
                # Ensure dictionary format for evaluator
                target_def = rule.definition if isinstance(rule.definition, dict) else json.loads(rule.definition_json or "{}")
                eval_res = DetectionRuleLifecycleService._evaluate_ast_against_record(target_def, event.payload)
                elapsed = time.perf_counter() - exec_start
                exec_time_ms = round(elapsed * 1000.0, 3)

                if elapsed > EXECUTION_TIMEOUT_SECONDS:
                    outcome = EvaluationOutcomeEnum.TIMEOUT
                    error_msg = f"Evaluation exceeded SLA timeout ({elapsed:.2f}s > {EXECUTION_TIMEOUT_SECONDS}s)."
                else:
                    matched = bool(eval_res.get("matched", False))
                    matched_conds = eval_res.get("matched_conditions", [])
                    explanation = eval_res.get("explanation", "")
                    outcome = EvaluationOutcomeEnum.MATCH if matched else EvaluationOutcomeEnum.NO_MATCH

            except Exception as exc:
                elapsed = time.perf_counter() - exec_start
                exec_time_ms = round(elapsed * 1000.0, 3)
                outcome = EvaluationOutcomeEnum.ERROR
                error_msg = f"Evaluator runtime exception: {exc}"
                logger.warning("Error evaluating rule %s on event %s: %s", rule.id, event.event_id, exc)

            detection_id: Optional[str] = None
            if matched:
                detection_id = f"DET-{generate_uuid()[:12]}"

            # 3. Record Execution Telemetry in CandidateRuleExecutionModel
            exec_model_mode = "PRODUCTION" if mode == PipelineModeEnum.PRODUCTION else ("SHADOW" if mode == PipelineModeEnum.SHADOW else "BACKTEST")
            exec_log = CandidateRuleExecutionModel(
                id=generate_uuid(),
                rule_id=rule.id,
                rule_version=str(rule.version),
                workspace_id=event.workspace_id,
                mode=exec_model_mode,
                matched=matched,
                matched_conditions_json=json.dumps(matched_conds),
                match_explanation_json=json.dumps({
                    "rule_identifier": rule.rule_identifier,
                    "rule_name": rule.name,
                    "explanation": explanation,
                    "outcome": outcome.value,
                    "error_message": error_msg,
                }),
                detection_id=detection_id,
                event_id=event.event_id,
                execution_time_ms=exec_time_ms,
                executed_at=now,
            )
            db.add(exec_log)
            db.flush()

            detail = RuleEvaluationDetail(
                rule_id=rule.id,
                rule_identifier=rule.rule_identifier,
                rule_name=rule.name,
                rule_version=str(rule.version),
                category=rule.category,
                severity=rule.severity,
                outcome=outcome,
                matched=matched,
                execution_time_ms=exec_time_ms,
                matched_conditions=matched_conds,
                explanation=explanation if matched else None,
                error_message=error_msg,
                detection_id=detection_id,
            )
            evaluations.append(detail)

        return evaluations

    # =========================================================================
    # STAGE 7, 8, 9, 10 & 11: PERSIST MATCH, FINDING, RISK, ALERT & REALTIME
    # =========================================================================

    @classmethod
    def handoff_downstream(
        cls,
        db: Session,
        event: NormalizedDetectionEvent,
        eval_detail: RuleEvaluationDetail,
        rule: CandidateRuleModel,
        mode: PipelineModeEnum = PipelineModeEnum.PRODUCTION,
    ) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Coordinates downstream handoff when a rule matches:
        1. Persists DetectionMatchModel
        2. Creates FindingModel
        3. Evaluates Risk Engine contribution
        4. Evaluates Alert Policy & creates NotificationModel (SECURITY_ALERT)
        5. Emits Realtime updates
        6. Updates Rule operational match telemetry
        """
        now = get_utc_now()

        # Idempotency check: if match was already recorded for this event and rule, do not duplicate
        existing_match = db.query(DetectionMatchModel).filter(
            DetectionMatchModel.workspace_id == event.workspace_id,
            DetectionMatchModel.rule_id == rule.id,
            DetectionMatchModel.event_id == event.event_id,
        ).first()
        if existing_match:
            logger.info("Match already recorded for event %s and rule %s, skipping duplicate creation.", event.event_id, rule.id)
            return existing_match.id, existing_match.finding_id, existing_match.alert_id

        detection_id = eval_detail.detection_id or f"DET-{generate_uuid()[:12]}"

        # 1. Persist First-Class DetectionMatchModel
        match_fields = [
            c.get("field", "") for c in eval_detail.matched_conditions if isinstance(c, dict)
        ]
        match_model = DetectionMatchModel(
            id=detection_id,
            workspace_id=event.workspace_id,
            rule_id=rule.id,
            rule_version=str(rule.version),
            event_id=event.event_id,
            mode=mode.value,
            status="MATCH",
            severity=rule.severity,
            confidence=rule.confidence,
            matched_at=now,
            matched_fields_json=json.dumps(match_fields),
            evidence_json=json.dumps({
                "matched_conditions": eval_detail.matched_conditions,
                "event_payload_sample": {k: event.payload[k] for k in match_fields if k in event.payload},
            }),
            provenance_json=json.dumps(event.provenance),
            explanation_text=eval_detail.explanation or f"Rule {rule.name} matched on {event.source_type} telemetry.",
            created_at=now,
        )
        db.add(match_model)

        # Replay and Shadow rules do NOT produce production findings or alerts
        if mode in (PipelineModeEnum.REPLAY, PipelineModeEnum.SHADOW):
            db.flush()
            return detection_id, None, None

        # 2. Generate FindingModel
        finding_id = generate_uuid()
        finding = FindingModel(
            id=finding_id,
            workspace_id=event.workspace_id,
            analyzer="detection_pipeline",
            source_type=event.source_type,
            rule_id=rule.id,
            finding_type=f"RULE_MATCH_{rule.category}",
            severity=rule.severity,
            confidence=rule.confidence,
            title=f"Detection Rule Triggered: {rule.name}",
            description=eval_detail.explanation or f"Rule '{rule.name}' conditions satisfied on {event.source_type} event.",
            metadata_json=json.dumps({
                "rule_id": rule.id,
                "rule_identifier": rule.rule_identifier,
                "rule_version": str(rule.version),
                "detection_id": detection_id,
                "event_id": event.event_id,
                "matched_conditions": eval_detail.matched_conditions,
                "provenance": event.provenance,
            }),
            created_at=now,
        )
        db.add(finding)
        match_model.finding_id = finding_id

        # 3. Associate FindingEvidenceModel for extracted observables
        for ind in event.indicators:
            ev_id = generate_uuid()
            f_ev = FindingEvidenceModel(
                id=ev_id,
                finding_id=finding_id,
                evidence_type=ind.get("type", "INDICATOR"),
                data_json=json.dumps(ind),
                created_at=now,
            )
            db.add(f_ev)

        # 4. Alert Policy Handoff: High/Critical severity rules emit Security Alerts
        alert_id: Optional[str] = None
        should_alert = (rule.severity in (RuleSeverity.HIGH.value, RuleSeverity.CRITICAL.value, "HIGH", "CRITICAL"))

        if should_alert:
            alert_dedup_key = f"ALERT-{event.workspace_id}-{rule.id}-{event.event_id}"
            notif = NotificationService.create_notification(
                db=db,
                workspace_id=event.workspace_id,
                category=NotificationCategoryEnum.SECURITY_ALERT.value,
                notification_type=NotificationTypeEnum.DETECTION_RULE_ALERT.value,
                severity=rule.severity,
                title=f"Threat Detected: {rule.name}",
                message=f"Detection rule '{rule.name}' ({rule.rule_identifier or rule.id[:8]}) fired on {event.source_type}. {eval_detail.explanation or ''}",
                source_type="DETECTION_RULE",
                source_id=rule.id,
                deduplication_key=alert_dedup_key,
                finding_id=finding_id,
                metadata={
                    "detection_id": detection_id,
                    "rule_id": rule.id,
                    "rule_identifier": rule.rule_identifier,
                    "event_id": event.event_id,
                    "matched_conditions": eval_detail.matched_conditions,
                },
            )
            if notif:
                alert_id = notif.id
                match_model.alert_id = alert_id

        # 5. Update Rule Operational Telemetry (Section 57)
        rule.total_match_count = (getattr(rule, "total_match_count", 0) or 0) + 1
        rule.last_matched_at = now

        db.flush()

        # 6. Stream Section 46 Realtime Event
        try:
            RealtimePublisher.publish_event(
                db=db,
                topic="detection_matches",
                event_type=RealtimeEventTypeEnum.DETECTION_MATCH_CREATED.value,
                resource_type=RealtimeResourceScopeEnum.WORKSPACE.value,
                resource_id=event.workspace_id,
                message=f"Detection match created for rule {rule.name} ({rule.rule_identifier})",
                workspace_id=event.workspace_id,
                payload={
                    "detection_id": detection_id,
                    "rule_id": rule.id,
                    "rule_identifier": rule.rule_identifier,
                    "rule_name": rule.name,
                    "event_id": event.event_id,
                    "severity": rule.severity,
                    "finding_id": finding_id,
                    "alert_id": alert_id,
                    "matched_at": now.isoformat(),
                },
            )
        except Exception as exc:
            logger.debug("Realtime dispatch non-fatal failure: %s", exc)

        return detection_id, finding_id, alert_id

    # =========================================================================
    # END-TO-END PIPELINE PROCESSING
    # =========================================================================

    @classmethod
    def process_event(
        cls,
        db: Session,
        req: Optional[EventIngestRequest] = None,
        request: Optional[EventIngestRequest] = None,
        user_id: str = "analyst",
        workspace_id: Optional[str] = None,
    ) -> PipelineExecutionResponse:
        """
        Executes the full Section 59 Threat Detection Pipeline for an incoming telemetry event.
        """
        req = req or request
        if not req:
            raise ValueError("No event ingest request provided.")
        if workspace_id:
            req.workspace_id = workspace_id

        pipeline_start = time.perf_counter()
        now = get_utc_now()

        # 1. Normalize
        norm_event, event_id = cls.normalize_event(db, req, req.workspace_id)

        # 2. Select Applicable Rules
        applicable_rules = cls.select_applicable_rules(db, norm_event, mode=req.mode)

        # 3. Evaluate Applicable Rules
        evaluations = cls.evaluate_rules(db, norm_event, applicable_rules, mode=req.mode)

        # 4. Downstream Handoff for Matches
        matches_summary: List[Dict[str, Any]] = []
        findings_count = 0
        alerts_count = 0
        matches_count = 0

        rule_map = {r.id: r for r in applicable_rules}
        for eval_item in evaluations:
            if eval_item.outcome == EvaluationOutcomeEnum.MATCH:
                matches_count += 1
                rule_obj = rule_map.get(eval_item.rule_id)
                if rule_obj:
                    det_id, f_id, a_id = cls.handoff_downstream(
                        db=db,
                        event=norm_event,
                        eval_detail=eval_item,
                        rule=rule_obj,
                        mode=req.mode,
                    )
                    eval_item.detection_id = det_id
                    eval_item.finding_id = f_id
                    eval_item.alert_id = a_id
                    if f_id:
                        findings_count += 1
                    if a_id:
                        alerts_count += 1

                    matches_summary.append({
                        "detection_id": det_id,
                        "rule_id": rule_obj.id,
                        "rule_identifier": rule_obj.rule_identifier,
                        "rule_name": rule_obj.name,
                        "severity": rule_obj.severity,
                        "finding_id": f_id,
                        "alert_id": a_id,
                    })

        db.commit()

        duration_ms = round((time.perf_counter() - pipeline_start) * 1000.0, 3)

        # Trace record
        trace = {
            "stages": [
                {"stage": "RECEIVE", "status": "COMPLETED"},
                {"stage": "NORMALIZE", "status": "COMPLETED", "adapter": norm_event.provenance.get("adapter")},
                {"stage": "RESOLVE_RULES", "status": "COMPLETED", "applicable_count": len(applicable_rules)},
                {"stage": "EXECUTE", "status": "COMPLETED", "evaluations_count": len(evaluations)},
                {"stage": "PERSIST_MATCH", "status": "COMPLETED", "matches_count": matches_count},
                {"stage": "DOWNSTREAM_HANDOFF", "status": "COMPLETED", "findings": findings_count, "alerts": alerts_count},
            ],
            "mode": req.mode.value,
        }

        return PipelineExecutionResponse(
            event_id=norm_event.event_id,
            workspace_id=norm_event.workspace_id,
            source_type=norm_event.source_type,
            event_type=norm_event.event_type,
            occurred_at=norm_event.occurred_at,
            processed_at=now,
            duration_ms=duration_ms,
            mode=req.mode,
            applicable_rules_count=len(applicable_rules),
            evaluated_rules_count=len(evaluations),
            matches_count=matches_count,
            findings_count=findings_count,
            alerts_count=alerts_count,
            evaluations=evaluations,
            matches=matches_summary,
            trace=trace,
        )

    # =========================================================================
    # BATCH & HISTORICAL REPLAY (SECTION 45 INTEGRATION)
    # =========================================================================

    @classmethod
    def process_batch(
        cls,
        db: Session,
        req: Optional[BatchEventIngestRequest] = None,
        batch_request: Optional[BatchEventIngestRequest] = None,
        user_id: str = "analyst",
        workspace_id: Optional[str] = None,
        job_id: Optional[str] = None,
    ) -> BatchPipelineResponse:
        """Processes a batch of events with partial failure isolation."""
        req = req or batch_request
        if not req:
            raise ValueError("No batch request provided.")
        if workspace_id:
            req.workspace_id = workspace_id

        batch_id = f"BATCH-{generate_uuid()[:8]}"
        workspace_id = req.workspace_id or "default"
        batch_start = time.perf_counter()

        results: List[PipelineExecutionResponse] = []
        processed_count = 0
        failed_count = 0
        total_matches = 0
        total_findings = 0
        total_alerts = 0

        for item in req.events:
            try:
                res = cls.process_event(db, item)
                results.append(res)
                processed_count += 1
                total_matches += res.matches_count
                total_findings += res.findings_count
                total_alerts += res.alerts_count
            except Exception as exc:
                failed_count += 1
                logger.error("Error processing event in batch %s: %s", batch_id, exc)

        duration_ms = round((time.perf_counter() - batch_start) * 1000.0, 3)

        return BatchPipelineResponse(
            batch_id=batch_id,
            workspace_id=workspace_id,
            total_events=len(req.events),
            processed_events=processed_count,
            failed_events=failed_count,
            total_matches=total_matches,
            total_findings=total_findings,
            total_alerts=total_alerts,
            duration_ms=duration_ms,
            results=results,
        )

    @classmethod
    def replay_historical_events(
        cls,
        db: Session,
        req: Optional[PipelineReplayRequest] = None,
        replay_request: Optional[PipelineReplayRequest] = None,
        actor: str = "analyst",
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        job_id: Optional[str] = None,
    ) -> BatchPipelineResponse:
        """
        Executes controlled replay over historical SecurityEventModel records.
        Strictly enforces mode=REPLAY (zero production alerts or finding flooding).
        """
        req = req or replay_request
        if not req:
            raise ValueError("No replay request provided.")
        if workspace_id:
            req.workspace_id = workspace_id

        workspace_id = req.workspace_id or "default"
        query = db.query(SecurityEventModel).filter(
            SecurityEventModel.workspace_id == workspace_id,
        )

        if req.start_time:
            query = query.filter(SecurityEventModel.event_time >= req.start_time)
        if req.end_time:
            query = query.filter(SecurityEventModel.event_time <= req.end_time)
        if req.source_type:
            query = query.filter(SecurityEventModel.source_type == req.source_type.upper())

        events_db = query.order_by(SecurityEventModel.event_time.asc()).limit(req.limit).all()

        ingest_items: List[EventIngestRequest] = []
        for e in events_db:
            try:
                payload = json.loads(e.attributes_json or "{}")
            except Exception:
                payload = {}

            ingest_items.append(
                EventIngestRequest(
                    workspace_id=workspace_id,
                    source_type=e.source_type,
                    event_type=e.event_type,
                    event_id=e.id,
                    occurred_at=e.event_time,
                    payload=payload,
                    source_id=e.source_artifact_id,
                    mode=PipelineModeEnum.REPLAY,
                )
            )

        batch_req = BatchEventIngestRequest(
            workspace_id=workspace_id,
            events=ingest_items,
            run_async=False,
        )

        resp = cls.process_batch(db, batch_req)

        # Audit Replay Operation
        try:
            audit = AuditLogModel(
                id=generate_uuid(),
                workspace_id=workspace_id,
                user_id=actor,
                action="DETECTION_PIPELINE_REPLAY",
                resource_type="DETECTION_PIPELINE",
                resource_id=resp.batch_id,
                details=json.dumps({
                    "events_replayed": len(ingest_items),
                    "matches_found": resp.total_matches,
                    "rule_filters": req.rule_ids,
                }),
                created_at=get_utc_now(),
            )
            db.add(audit)
            db.commit()
        except Exception:
            pass

        return resp

    # =========================================================================
    # OBSERVABILITY, METRICS & DEAD LETTERS
    # =========================================================================

    @classmethod
    def get_pipeline_metrics(cls, db: Session, workspace_id: str = "default") -> PipelineMetricsResponse:
        """
        Retrieves authoritative operational metrics for the detection pipeline.
        Calculates throughput, error rates, p95 latency, and health state from DB telemetry.
        """
        total_executions = db.query(func.count(CandidateRuleExecutionModel.id)).filter(
            CandidateRuleExecutionModel.workspace_id == workspace_id,
        ).scalar() or 0

        matches_count = db.query(func.count(DetectionMatchModel.id)).filter(
            DetectionMatchModel.workspace_id == workspace_id,
        ).scalar() or 0

        findings_count = db.query(func.count(FindingModel.id)).filter(
            FindingModel.workspace_id == workspace_id,
            FindingModel.analyzer == "detection_pipeline",
        ).scalar() or 0

        alerts_count = db.query(func.count(NotificationModel.id)).filter(
            NotificationModel.workspace_id == workspace_id,
            NotificationModel.notification_type == NotificationTypeEnum.DETECTION_RULE_ALERT.value,
        ).scalar() or 0

        dead_letters_count = db.query(func.count(DetectionDeadLetterModel.id)).filter(
            DetectionDeadLetterModel.workspace_id == workspace_id,
            DetectionDeadLetterModel.resolved == False,
        ).scalar() or 0

        events_count = db.query(func.count(SecurityEventModel.id)).filter(
            SecurityEventModel.workspace_id == workspace_id,
        ).scalar() or 0

        # Latency statistics
        durations = [
            row[0] for row in db.query(CandidateRuleExecutionModel.execution_time_ms)
            .filter(CandidateRuleExecutionModel.workspace_id == workspace_id)
            .limit(1000)
            .all()
        ]

        avg_latency = (sum(durations) / len(durations)) if durations else 0.0
        durations.sort()
        p95_idx = int(math.ceil(0.95 * len(durations))) - 1
        p95_latency = durations[max(0, p95_idx)] if durations else 0.0

        # Health assessment
        health = PipelineHealthStatusEnum.HEALTHY
        health_reason: Optional[str] = None

        if dead_letters_count >= 10:
            health = PipelineHealthStatusEnum.DEGRADED
            health_reason = f"Elevated dead letter count: {dead_letters_count} unresolved events."
        elif p95_latency > 2000.0:
            health = PipelineHealthStatusEnum.DEGRADED
            health_reason = f"Elevated p95 execution latency: {p95_latency:.1f}ms."

        active_rules = db.query(func.count(CandidateRuleModel.id)).filter(
            CandidateRuleModel.workspace_id == workspace_id,
            CandidateRuleModel.deployment_state == DeploymentStateEnum.PRODUCTION.value,
        ).scalar() or 0

        staged_rules = db.query(func.count(CandidateRuleModel.id)).filter(
            CandidateRuleModel.workspace_id == workspace_id,
            CandidateRuleModel.deployment_state == DeploymentStateEnum.STAGING.value,
        ).scalar() or 0

        no_matches_count = max(0, total_executions - matches_count)

        return PipelineMetricsResponse(
            workspace_id=workspace_id,
            events_received_total=events_count,
            events_processed_total=events_count,
            events_failed_total=dead_letters_count,
            rules_evaluated_total=total_executions,
            matches_total=matches_count,
            no_matches_total=no_matches_count,
            evaluation_errors_total=0,
            findings_created_total=findings_count,
            alerts_created_total=alerts_count,
            avg_latency_ms=round(avg_latency, 3),
            p95_latency_ms=round(p95_latency, 3),
            dead_letter_total=dead_letters_count,
            pipeline_health=health,
            health_reason=health_reason,
            active_rules_count=active_rules,
            staged_rules_count=staged_rules,
        )

    @classmethod
    def list_matches(
        cls,
        db: Session,
        workspace_id: str = "default",
        rule_id: Optional[str] = None,
        severity: Optional[str] = None,
        mode: Optional[str] = None,
        status: Optional[str] = None,
        event_id: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[DetectionMatchListItem]:
        """Queries first-class detection matches with associated rule metadata."""
        query = db.query(DetectionMatchModel).filter(
            DetectionMatchModel.workspace_id == workspace_id,
        )

        if rule_id:
            query = query.filter(DetectionMatchModel.rule_id == rule_id)
        if severity:
            query = query.filter(DetectionMatchModel.severity == severity.upper())
        if mode:
            query = query.filter(DetectionMatchModel.mode == mode.upper())
        if status:
            query = query.filter(DetectionMatchModel.status == status.upper())
        if event_id:
            query = query.filter(DetectionMatchModel.event_id == event_id)

        rows = query.order_by(DetectionMatchModel.matched_at.desc()).offset(offset).limit(limit).all()

        items: List[DetectionMatchListItem] = []
        for r in rows:
            rule_ident = r.rule.rule_identifier if r.rule else None
            rule_name = r.rule.name if r.rule else "Unknown Rule"

            items.append(
                DetectionMatchListItem(
                    id=r.id,
                    workspace_id=r.workspace_id,
                    rule_id=r.rule_id,
                    rule_identifier=rule_ident,
                    rule_name=rule_name,
                    rule_version=r.rule_version,
                    event_id=r.event_id,
                    execution_id=r.execution_id,
                    finding_id=r.finding_id,
                    alert_id=r.alert_id,
                    mode=r.mode,
                    status=r.status,
                    severity=r.severity,
                    confidence=r.confidence,
                    matched_at=r.matched_at,
                    matched_fields=r.matched_fields,
                    explanation=r.explanation_text,
                    evidence=r.evidence,
                    provenance=r.provenance,
                )
            )

        return items

    @classmethod
    def _record_dead_letter(
        cls,
        db: Session,
        workspace_id: str,
        event_id: str,
        source_type: str,
        failure_stage: str,
        error_code: str,
        error_message: str,
        payload: Dict[str, Any],
    ) -> None:
        """Persists failed telemetry to dead-letter repository."""
        try:
            dl = DetectionDeadLetterModel(
                id=generate_uuid(),
                workspace_id=workspace_id,
                event_id=event_id,
                source_type=source_type,
                failure_stage=failure_stage,
                error_code=error_code,
                error_message=error_message,
                payload_json=json.dumps(payload),
                provenance_json=json.dumps({"failed_at": get_utc_now().isoformat()}),
            )
            db.add(dl)
            db.commit()
        except Exception as exc:
            logger.error("Failed persisting dead-letter event %s: %s", event_id, exc)
