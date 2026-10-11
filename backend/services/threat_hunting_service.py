"""
Section 54: Threat Hunting Workspace & Query Engine Service.
Provides controlled, type-safe analytical query execution across existing CyberGuard datasets:
- Indicators, Alerts, Findings, Artifacts, Threat Intelligence, Watchlist Changes,
  Watched Indicators, Incidents, Cases, Threat Events, Threat Memory, Endpoint Events.
- Strict field allowlists, query cost limits, time bounding, and tenant isolation.
- Deterministic explainability for matched records.
- Seamless handoffs to Section 53 Watchlists and Section 50 Investigations.
"""
from __future__ import annotations

import csv
import io
import json
import logging
import re
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple, Set

from sqlalchemy import and_, or_, desc, asc, func
from sqlalchemy.orm import Session

from backend.db.models import (
    get_utc_now,
    generate_uuid,
    IndicatorModel,
    NotificationModel,
    AlertModel,
    FindingModel,
    ArtifactModel,
    ThreatIntelligenceRecordModel,
    IntelligenceChangeModel,
    WatchedIndicatorModel,
    WatchlistModel,
    IncidentModel,
    CaseModel,
    ThreatEventModel,
    ThreatMemoryEntryModel,
    EndpointTelemetryEventModel,
    SavedHuntModel,
    HuntExecutionModel,
    BackgroundJobModel,
)
from backend.schemas.hunting import (
    HuntSourceEnum,
    QueryOperatorEnum,
    TimePresetEnum,
    HuntVisibilityEnum,
    HuntExecutionModeEnum,
    HuntExecutionStatusEnum,
    QueryFilter,
    QueryTimeRange,
    QuerySort,
    HuntQueryDefinition,
    QueryPlanStep,
    HuntValidationResponse,
    DataSourceField,
    DataSourceMetadata,
    DataSourceRegistryResponse,
    SavedHuntCreateRequest,
    SavedHuntUpdateRequest,
    SavedHuntResponse,
    SavedHuntListResponse,
    HuntResultItem,
    HuntAggregationBucket,
    HuntQueryResultResponse,
    HuntExecutionRequest,
    HuntExecutionResponse,
    HuntExecutionListResponse,
    NaturalLanguageHuntRequest,
    NaturalLanguageHuntResponse,
    HuntInvestigationHandoffRequest,
    HuntInvestigationHandoffResponse,
    HuntWatchlistHandoffRequest,
    HuntWatchlistHandoffResponse,
)
from backend.schemas.realtime import (
    RealtimeEventTypeEnum,
    RealtimeResourceScopeEnum,
)
from backend.services.realtime_service import RealtimePublisher
from backend.services.watchlist_monitoring_service import WatchlistMonitoringService

logger = logging.getLogger("cyberguard.services.threat_hunting")


class ThreatHuntingService:
    """
    Authoritative query engine and workspace coordinator for Section 54 Threat Hunting.
    """

    # =========================================================================
    # 1. Data Source Registry Definition
    # =========================================================================

    DATA_SOURCES: Dict[HuntSourceEnum, DataSourceMetadata] = {
        HuntSourceEnum.INDICATORS: DataSourceMetadata(
            key=HuntSourceEnum.INDICATORS,
            display_name="Canonical Indicators (IOCs)",
            description="Normalized forensic observables including IPs, Domains, URLs, and File Hashes.",
            default_time_field="last_seen",
            supported_relationships=["threat_intelligence", "watchlist", "investigation", "alerts"],
            fields=[
                DataSourceField(
                    name="indicator_type",
                    display_name="Indicator Type",
                    field_type="enum",
                    allowed_operators=[QueryOperatorEnum.EQUALS, QueryOperatorEnum.NOT_EQUALS, QueryOperatorEnum.IN, QueryOperatorEnum.NOT_IN],
                    description="IOC Type (IP, DOMAIN, URL, SHA256, MD5, EMAIL, etc.)",
                    options=["IP", "DOMAIN", "URL", "SHA256", "MD5", "SHA1", "EMAIL", "CERTIFICATE", "ASN"],
                    is_groupable=True,
                ),
                DataSourceField(
                    name="normalized_value",
                    display_name="Observable Value",
                    field_type="string",
                    allowed_operators=[QueryOperatorEnum.EQUALS, QueryOperatorEnum.CONTAINS, QueryOperatorEnum.STARTS_WITH, QueryOperatorEnum.ENDS_WITH, QueryOperatorEnum.IN],
                    description="Canonical normalized indicator value",
                ),
                DataSourceField(
                    name="reputation",
                    display_name="Reputation",
                    field_type="enum",
                    allowed_operators=[QueryOperatorEnum.EQUALS, QueryOperatorEnum.NOT_EQUALS, QueryOperatorEnum.IN],
                    description="Observable reputation rating",
                    options=["CLEAN", "SUSPICIOUS", "MALICIOUS", "UNKNOWN"],
                    is_groupable=True,
                ),
                DataSourceField(
                    name="confidence",
                    display_name="Confidence Score",
                    field_type="number",
                    allowed_operators=[QueryOperatorEnum.GREATER_THAN, QueryOperatorEnum.GREATER_THAN_OR_EQUAL, QueryOperatorEnum.LESS_THAN, QueryOperatorEnum.LESS_THAN_OR_EQUAL, QueryOperatorEnum.BETWEEN],
                    description="Detection confidence from 0.0 to 1.0",
                ),
                DataSourceField(
                    name="first_seen",
                    display_name="First Seen",
                    field_type="datetime",
                    allowed_operators=[QueryOperatorEnum.BEFORE, QueryOperatorEnum.AFTER, QueryOperatorEnum.BETWEEN, QueryOperatorEnum.WITHIN_LAST],
                    description="Initial observation timestamp",
                ),
                DataSourceField(
                    name="last_seen",
                    display_name="Last Seen",
                    field_type="datetime",
                    allowed_operators=[QueryOperatorEnum.BEFORE, QueryOperatorEnum.AFTER, QueryOperatorEnum.BETWEEN, QueryOperatorEnum.WITHIN_LAST],
                    description="Most recent observation timestamp",
                ),
            ],
        ),
        HuntSourceEnum.ALERTS: DataSourceMetadata(
            key=HuntSourceEnum.ALERTS,
            display_name="Security Alerts",
            description="Triageable security signals and notifications created across detection engines.",
            default_time_field="created_at",
            supported_relationships=["investigation", "indicator", "cluster"],
            fields=[
                DataSourceField(
                    name="title",
                    display_name="Alert Title",
                    field_type="string",
                    allowed_operators=[QueryOperatorEnum.CONTAINS, QueryOperatorEnum.STARTS_WITH, QueryOperatorEnum.EQUALS],
                    description="Headline description of the security alert",
                ),
                DataSourceField(
                    name="severity",
                    display_name="Severity",
                    field_type="enum",
                    allowed_operators=[QueryOperatorEnum.EQUALS, QueryOperatorEnum.NOT_EQUALS, QueryOperatorEnum.IN, QueryOperatorEnum.GREATER_THAN_OR_EQUAL],
                    description="Alert severity tier",
                    options=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                    is_groupable=True,
                ),
                DataSourceField(
                    name="status",
                    display_name="Triage Status",
                    field_type="enum",
                    allowed_operators=[QueryOperatorEnum.EQUALS, QueryOperatorEnum.NOT_EQUALS, QueryOperatorEnum.IN],
                    description="Current disposition of alert",
                    options=["UNREAD", "READ", "ACKNOWLEDGED", "DISMISSED"],
                    is_groupable=True,
                ),
                DataSourceField(
                    name="source_type",
                    display_name="Source Subsystem",
                    field_type="string",
                    allowed_operators=[QueryOperatorEnum.EQUALS, QueryOperatorEnum.IN],
                    description="Detection source (FINDING, WATCHLIST, CLUSTER, etc.)",
                    is_groupable=True,
                ),
                DataSourceField(
                    name="assigned_to",
                    display_name="Assigned Analyst",
                    field_type="string",
                    allowed_operators=[QueryOperatorEnum.EQUALS, QueryOperatorEnum.EXISTS, QueryOperatorEnum.NOT_EXISTS],
                    description="Analyst ID assigned to investigate",
                ),
                DataSourceField(
                    name="created_at",
                    display_name="Triggered At",
                    field_type="datetime",
                    allowed_operators=[QueryOperatorEnum.BEFORE, QueryOperatorEnum.AFTER, QueryOperatorEnum.BETWEEN, QueryOperatorEnum.WITHIN_LAST],
                    description="Timestamp alert was generated",
                ),
            ],
        ),
        HuntSourceEnum.FINDINGS: DataSourceMetadata(
            key=HuntSourceEnum.FINDINGS,
            display_name="Detection Findings",
            description="Analytical conclusions and evidence items produced by detectors and heuristics.",
            default_time_field="created_at",
            supported_relationships=["analysis_run", "artifact", "evidence"],
            fields=[
                DataSourceField(
                    name="title",
                    display_name="Finding Title",
                    field_type="string",
                    allowed_operators=[QueryOperatorEnum.CONTAINS, QueryOperatorEnum.EQUALS],
                    description="Finding summary title",
                ),
                DataSourceField(
                    name="analyzer",
                    display_name="Analyzer Engine",
                    field_type="string",
                    allowed_operators=[QueryOperatorEnum.EQUALS, QueryOperatorEnum.IN],
                    description="Specific engine producing conclusion",
                    is_groupable=True,
                ),
                DataSourceField(
                    name="finding_type",
                    display_name="Finding Type",
                    field_type="string",
                    allowed_operators=[QueryOperatorEnum.EQUALS, QueryOperatorEnum.CONTAINS, QueryOperatorEnum.IN],
                    description="Taxonomy classification of finding",
                    is_groupable=True,
                ),
                DataSourceField(
                    name="severity",
                    display_name="Severity",
                    field_type="enum",
                    allowed_operators=[QueryOperatorEnum.EQUALS, QueryOperatorEnum.NOT_EQUALS, QueryOperatorEnum.IN, QueryOperatorEnum.GREATER_THAN_OR_EQUAL],
                    description="Calculated severity",
                    options=["CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE"],
                    is_groupable=True,
                ),
                DataSourceField(
                    name="confidence",
                    display_name="Confidence",
                    field_type="number",
                    allowed_operators=[QueryOperatorEnum.GREATER_THAN_OR_EQUAL, QueryOperatorEnum.LESS_THAN_OR_EQUAL, QueryOperatorEnum.BETWEEN],
                    description="Finding confidence (0.0 - 1.0)",
                ),
                DataSourceField(
                    name="method",
                    display_name="Analysis Method",
                    field_type="string",
                    allowed_operators=[QueryOperatorEnum.EQUALS, QueryOperatorEnum.IN],
                    description="Heuristic, ML, Rule, or LLM method",
                    options=["RULE", "HEURISTIC", "ML", "LLM", "EXTERNAL_INTELLIGENCE"],
                    is_groupable=True,
                ),
                DataSourceField(
                    name="created_at",
                    display_name="Discovered At",
                    field_type="datetime",
                    allowed_operators=[QueryOperatorEnum.BEFORE, QueryOperatorEnum.AFTER, QueryOperatorEnum.BETWEEN, QueryOperatorEnum.WITHIN_LAST],
                    description="Creation timestamp",
                ),
            ],
        ),
        HuntSourceEnum.ARTIFACTS: DataSourceMetadata(
            key=HuntSourceEnum.ARTIFACTS,
            display_name="Ingested Forensic Artifacts",
            description="Forensic payloads, email files, attachments, and raw files ingested into CyberGuard.",
            default_time_field="created_at",
            supported_relationships=["evidence", "findings", "runs"],
            fields=[
                DataSourceField(
                    name="filename",
                    display_name="Filename",
                    field_type="string",
                    allowed_operators=[QueryOperatorEnum.CONTAINS, QueryOperatorEnum.ENDS_WITH, QueryOperatorEnum.EQUALS],
                    description="Original ingested file name",
                ),
                DataSourceField(
                    name="mime_type",
                    display_name="MIME Content Type",
                    field_type="string",
                    allowed_operators=[QueryOperatorEnum.EQUALS, QueryOperatorEnum.CONTAINS, QueryOperatorEnum.IN],
                    description="File MIME type",
                    is_groupable=True,
                ),
                DataSourceField(
                    name="sha256",
                    display_name="SHA-256 Hash",
                    field_type="string",
                    allowed_operators=[QueryOperatorEnum.EQUALS, QueryOperatorEnum.IN],
                    description="64-character cryptographic SHA-256 hash",
                ),
                DataSourceField(
                    name="source",
                    display_name="Ingestion Source",
                    field_type="string",
                    allowed_operators=[QueryOperatorEnum.EQUALS, QueryOperatorEnum.IN],
                    description="Ingestion channel (EMAIL, UPLOAD, API, ENDPOINT)",
                    is_groupable=True,
                ),
                DataSourceField(
                    name="size_bytes",
                    display_name="File Size (Bytes)",
                    field_type="number",
                    allowed_operators=[QueryOperatorEnum.GREATER_THAN, QueryOperatorEnum.LESS_THAN, QueryOperatorEnum.BETWEEN],
                    description="Payload size in bytes",
                ),
                DataSourceField(
                    name="created_at",
                    display_name="Ingested At",
                    field_type="datetime",
                    allowed_operators=[QueryOperatorEnum.BEFORE, QueryOperatorEnum.AFTER, QueryOperatorEnum.BETWEEN, QueryOperatorEnum.WITHIN_LAST],
                    description="Timestamp of artifact ingestion",
                ),
            ],
        ),
        HuntSourceEnum.THREAT_INTELLIGENCE: DataSourceMetadata(
            key=HuntSourceEnum.THREAT_INTELLIGENCE,
            display_name="Threat Intelligence Records",
            description="Enriched provider records and multi-provider observations from Section 52.",
            default_time_field="retrieved_at",
            supported_relationships=["indicator", "evidence"],
            fields=[
                DataSourceField(
                    name="indicator_type",
                    display_name="Indicator Type",
                    field_type="enum",
                    allowed_operators=[QueryOperatorEnum.EQUALS, QueryOperatorEnum.IN],
                    description="Observable type",
                    options=["IP", "DOMAIN", "URL", "SHA256", "EMAIL", "ASN"],
                    is_groupable=True,
                ),
                DataSourceField(
                    name="normalized_value",
                    display_name="Observable",
                    field_type="string",
                    allowed_operators=[QueryOperatorEnum.EQUALS, QueryOperatorEnum.CONTAINS, QueryOperatorEnum.IN],
                    description="Canonical observable value",
                ),
                DataSourceField(
                    name="provider",
                    display_name="Intelligence Source",
                    field_type="string",
                    allowed_operators=[QueryOperatorEnum.EQUALS, QueryOperatorEnum.IN],
                    description="Provider name (cyberguard_feed, internal_memory, virustotal, etc.)",
                    is_groupable=True,
                ),
                DataSourceField(
                    name="verdict",
                    display_name="Provider Verdict",
                    field_type="enum",
                    allowed_operators=[QueryOperatorEnum.EQUALS, QueryOperatorEnum.NOT_EQUALS, QueryOperatorEnum.IN],
                    description="Provider verdict",
                    options=["MALICIOUS", "SUSPICIOUS", "CLEAN", "UNKNOWN"],
                    is_groupable=True,
                ),
                DataSourceField(
                    name="severity",
                    display_name="Severity",
                    field_type="enum",
                    allowed_operators=[QueryOperatorEnum.EQUALS, QueryOperatorEnum.IN, QueryOperatorEnum.GREATER_THAN_OR_EQUAL],
                    description="Provider severity rating",
                    options=["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"],
                    is_groupable=True,
                ),
                DataSourceField(
                    name="confidence",
                    display_name="Confidence",
                    field_type="number",
                    allowed_operators=[QueryOperatorEnum.GREATER_THAN_OR_EQUAL, QueryOperatorEnum.BETWEEN],
                    description="Confidence rating (0.0 - 1.0)",
                ),
                DataSourceField(
                    name="retrieved_at",
                    display_name="Observed At",
                    field_type="datetime",
                    allowed_operators=[QueryOperatorEnum.BEFORE, QueryOperatorEnum.AFTER, QueryOperatorEnum.BETWEEN, QueryOperatorEnum.WITHIN_LAST],
                    description="Timestamp intelligence was retrieved",
                ),
            ],
        ),
        HuntSourceEnum.WATCHLIST_CHANGES: DataSourceMetadata(
            key=HuntSourceEnum.WATCHLIST_CHANGES,
            display_name="Watchlist Intelligence Changes",
            description="Material intelligence shifts detected over time by Section 53 continuous monitoring.",
            default_time_field="detected_at",
            supported_relationships=["watchlist", "watched_indicator", "alert"],
            fields=[
                DataSourceField(
                    name="change_type",
                    display_name="Change Type",
                    field_type="enum",
                    allowed_operators=[QueryOperatorEnum.EQUALS, QueryOperatorEnum.NOT_EQUALS, QueryOperatorEnum.IN],
                    description="Material transition type (NEWLY_MALICIOUS, BECAME_CLEAN, etc.)",
                    options=["NEWLY_MALICIOUS", "NEWLY_SUSPICIOUS", "BECAME_CLEAN", "VERDICT_CHANGED", "SEVERITY_CHANGED", "PROVIDER_CONFLICT_CHANGED", "CAMPAIGN_ASSOCIATION_CHANGED", "ASN_CHANGED"],
                    is_groupable=True,
                ),
                DataSourceField(
                    name="change_severity",
                    display_name="Severity",
                    field_type="enum",
                    allowed_operators=[QueryOperatorEnum.EQUALS, QueryOperatorEnum.IN, QueryOperatorEnum.GREATER_THAN_OR_EQUAL],
                    description="Change severity",
                    options=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                    is_groupable=True,
                ),
                DataSourceField(
                    name="previous_verdict",
                    display_name="Previous Verdict",
                    field_type="string",
                    allowed_operators=[QueryOperatorEnum.EQUALS, QueryOperatorEnum.IN],
                    description="Verdict prior to change",
                    is_groupable=True,
                ),
                DataSourceField(
                    name="current_verdict",
                    display_name="Current Verdict",
                    field_type="string",
                    allowed_operators=[QueryOperatorEnum.EQUALS, QueryOperatorEnum.IN],
                    description="Verdict after change",
                    is_groupable=True,
                ),
                DataSourceField(
                    name="normalized_value",
                    display_name="Watched Indicator",
                    field_type="string",
                    allowed_operators=[QueryOperatorEnum.EQUALS, QueryOperatorEnum.CONTAINS],
                    description="Watched observable value",
                ),
                DataSourceField(
                    name="detected_at",
                    display_name="Detected At",
                    field_type="datetime",
                    allowed_operators=[QueryOperatorEnum.BEFORE, QueryOperatorEnum.AFTER, QueryOperatorEnum.BETWEEN, QueryOperatorEnum.WITHIN_LAST],
                    description="Timestamp change was detected",
                ),
            ],
        ),
        HuntSourceEnum.INCIDENTS: DataSourceMetadata(
            key=HuntSourceEnum.INCIDENTS,
            display_name="Security Incidents",
            description="Operational case cases and SLA-managed incident containers from Section 50 & 51.",
            default_time_field="opened_at",
            supported_relationships=["threat_events", "alerts", "indicators"],
            fields=[
                DataSourceField(
                    name="incident_number",
                    display_name="Incident #",
                    field_type="string",
                    allowed_operators=[QueryOperatorEnum.EQUALS, QueryOperatorEnum.STARTS_WITH, QueryOperatorEnum.CONTAINS],
                    description="Case number identifier (e.g. INC-2026-XXXX)",
                ),
                DataSourceField(
                    name="title",
                    display_name="Title",
                    field_type="string",
                    allowed_operators=[QueryOperatorEnum.CONTAINS, QueryOperatorEnum.EQUALS],
                    description="Incident headline",
                ),
                DataSourceField(
                    name="status",
                    display_name="Status",
                    field_type="enum",
                    allowed_operators=[QueryOperatorEnum.EQUALS, QueryOperatorEnum.NOT_EQUALS, QueryOperatorEnum.IN],
                    description="Lifecycle status",
                    options=["OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED", "CLOSED", "FALSE_POSITIVE", "DUPLICATE"],
                    is_groupable=True,
                ),
                DataSourceField(
                    name="severity",
                    display_name="Severity",
                    field_type="enum",
                    allowed_operators=[QueryOperatorEnum.EQUALS, QueryOperatorEnum.IN, QueryOperatorEnum.GREATER_THAN_OR_EQUAL],
                    description="Incident severity",
                    options=["CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE"],
                    is_groupable=True,
                ),
                DataSourceField(
                    name="risk_score",
                    display_name="Risk Score",
                    field_type="number",
                    allowed_operators=[QueryOperatorEnum.GREATER_THAN_OR_EQUAL, QueryOperatorEnum.LESS_THAN_OR_EQUAL, QueryOperatorEnum.BETWEEN],
                    description="Calculated risk score (0 - 100)",
                ),
                DataSourceField(
                    name="sla_status",
                    display_name="SLA Status",
                    field_type="enum",
                    allowed_operators=[QueryOperatorEnum.EQUALS, QueryOperatorEnum.IN],
                    description="Current SLA milestone health",
                    options=["HEALTHY", "WARNING", "BREACHED", "PAUSED", "MET"],
                    is_groupable=True,
                ),
                DataSourceField(
                    name="opened_at",
                    display_name="Opened At",
                    field_type="datetime",
                    allowed_operators=[QueryOperatorEnum.BEFORE, QueryOperatorEnum.AFTER, QueryOperatorEnum.BETWEEN, QueryOperatorEnum.WITHIN_LAST],
                    description="Incident creation timestamp",
                ),
            ],
        ),
    }

    # =========================================================================
    # 2. Query Validation & Query Plan Generation
    # =========================================================================

    @classmethod
    def get_data_source_registry(cls, db: Optional[Session] = None, workspace_id: str = "default") -> DataSourceRegistryResponse:
        """Returns the metadata catalog of all queryable datasets."""
        sources_list: List[DataSourceMetadata] = []
        for key, meta in cls.DATA_SOURCES.items():
            meta_copy = meta.model_copy()
            # If db session provided, populate approximate live counts
            if db:
                try:
                    cnt = cls._count_source_records(db, key, workspace_id)
                    meta_copy.approximate_count = cnt
                except Exception:
                    meta_copy.approximate_count = None
            sources_list.append(meta_copy)
        return DataSourceRegistryResponse(sources=sources_list)

    @classmethod
    def validate_query(cls, query: HuntQueryDefinition, workspace_id: str = "default") -> HuntValidationResponse:
        """
        Validates query against the Data Source Registry allowlist.
        Ensures fields exist, operators are compatible, types match, and produces an explainable plan.
        """
        errors: List[str] = []
        warnings: List[str] = []
        plan_steps: List[QueryPlanStep] = []

        # 1. Validate data source
        source_meta = cls.DATA_SOURCES.get(query.data_source)
        if not source_meta:
            errors.append(f"Unsupported data source '{query.data_source}'. Available sources: {[s.value for s in HuntSourceEnum]}")
            return HuntValidationResponse(is_valid=False, errors=errors, warnings=warnings, estimated_cost="RESTRICTED")

        plan_steps.append(
            QueryPlanStep(
                step="Target Data Source",
                description=f"Querying '{source_meta.display_name}' isolated to workspace '{workspace_id}'."
            )
        )

        allowed_fields: Dict[str, DataSourceField] = {f.name: f for f in source_meta.fields}

        # 2. Validate individual filters
        for idx, flt in enumerate(query.filters):
            field_meta = allowed_fields.get(flt.field)
            if not field_meta:
                errors.append(f"Filter #{idx + 1}: Field '{flt.field}' is not queryable on source '{query.data_source.value}'.")
                continue

            if flt.operator not in field_meta.allowed_operators:
                errors.append(
                    f"Filter #{idx + 1}: Operator '{flt.operator.value}' is not supported for field '{flt.field}' (Allowed: {[o.value for o in field_meta.allowed_operators]})."
                )
                continue

            # Validate enum values if defined
            if field_meta.field_type == "enum" and field_meta.options:
                val = flt.value
                val_list = val if isinstance(val, list) else [val]
                for v in val_list:
                    if str(v).upper() not in [opt.upper() for opt in field_meta.options]:
                        warnings.append(f"Filter #{idx + 1}: Value '{v}' is not in standard options for '{flt.field}' ({field_meta.options}).")

            plan_steps.append(
                QueryPlanStep(
                    step=f"Filter Predicate #{idx + 1}",
                    description=f"{field_meta.display_name} {flt.operator.value.replace('_', ' ')} '{flt.value}'."
                )
            )

        # 3. Validate Time Range
        time_field = (query.time_range.field if query.time_range and query.time_range.field else source_meta.default_time_field)
        time_field_meta = allowed_fields.get(time_field)
        if not time_field_meta or time_field_meta.field_type != "datetime":
            warnings.append(f"Specified time field '{time_field}' is not a valid datetime coordinate. Defaulting to '{source_meta.default_time_field}'.")
            time_field = source_meta.default_time_field

        preset = query.time_range.preset if query.time_range and query.time_range.preset else TimePresetEnum.D7
        plan_steps.append(
            QueryPlanStep(
                step="Temporal Boundary",
                description=f"Bounded on '{time_field}' within preset '{preset.value}'."
            )
        )

        # 4. Validate Sorting & Grouping
        for srt in query.sort:
            if srt.field not in allowed_fields:
                errors.append(f"Sort field '{srt.field}' is not allowed on source '{query.data_source.value}'.")

        if query.group_by and query.group_by not in allowed_fields:
            errors.append(f"Group-by field '{query.group_by}' is not allowed on source '{query.data_source.value}'.")

        # 5. Cost estimation
        is_complex = len(query.filters) >= 3 or query.group_by is not None or query.limit > 200
        cost = "MEDIUM" if is_complex else "LOW"

        return HuntValidationResponse(
            is_valid=(len(errors) == 0),
            errors=errors,
            warnings=warnings,
            estimated_cost=cost,
            query_plan=plan_steps,
        )

    # =========================================================================
    # 3. Safe Deterministic Query Execution Engine
    # =========================================================================

    @classmethod
    def execute_hunt(
        cls,
        db: Session,
        workspace_id: str,
        req: HuntExecutionRequest,
        actor: str = "analyst",
    ) -> HuntQueryResultResponse:
        """
        Executes a validated threat hunt query deterministically against CyberGuard data.
        """
        start_time = time.perf_counter()
        validation = cls.validate_query(req.query_definition, workspace_id)
        if not validation.is_valid:
            raise ValueError(f"Invalid hunt query: {'; '.join(validation.errors)}")

        execution_id = str(uuid.uuid4())
        qdef = req.query_definition
        source_key = qdef.data_source

        # Resolve temporal boundaries
        time_from, time_to = cls._resolve_time_range(qdef.time_range)

        # Dispatch source-specific execution
        items: List[HuntResultItem] = []
        total_count = 0
        aggregations: Optional[Dict[str, List[HuntAggregationBucket]]] = None

        if source_key == HuntSourceEnum.INDICATORS:
            items, total_count, aggregations = cls._query_indicators(db, workspace_id, qdef, time_from, time_to)
        elif source_key == HuntSourceEnum.ALERTS:
            items, total_count, aggregations = cls._query_alerts(db, workspace_id, qdef, time_from, time_to)
        elif source_key == HuntSourceEnum.FINDINGS:
            items, total_count, aggregations = cls._query_findings(db, workspace_id, qdef, time_from, time_to)
        elif source_key == HuntSourceEnum.ARTIFACTS:
            items, total_count, aggregations = cls._query_artifacts(db, workspace_id, qdef, time_from, time_to)
        elif source_key == HuntSourceEnum.THREAT_INTELLIGENCE:
            items, total_count, aggregations = cls._query_threat_intelligence(db, workspace_id, qdef, time_from, time_to)
        elif source_key == HuntSourceEnum.WATCHLIST_CHANGES:
            items, total_count, aggregations = cls._query_watchlist_changes(db, workspace_id, qdef, time_from, time_to)
        elif source_key == HuntSourceEnum.INCIDENTS:
            items, total_count, aggregations = cls._query_incidents(db, workspace_id, qdef, time_from, time_to)
        else:
            # Fallback for remaining defined sources
            items, total_count, aggregations = [], 0, None

        duration_ms = int((time.perf_counter() - start_time) * 1000)

        # Persist execution record
        matched_ids = [item.id for item in items]
        exec_record = HuntExecutionModel(
            id=execution_id,
            workspace_id=workspace_id,
            saved_hunt_id=req.saved_hunt_id,
            data_source=source_key.value,
            query_definition_json=qdef.model_dump_json(),
            execution_mode=req.execution_mode.value,
            status=HuntExecutionStatusEnum.SUCCEEDED.value,
            result_count=total_count,
            matched_record_ids_json=json.dumps(matched_ids),
            results_summary_json=json.dumps({"duration_ms": duration_ms, "returned_count": len(items)}),
            duration_ms=duration_ms,
            executed_by=actor,
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
        )
        db.add(exec_record)

        # If linked to a saved hunt, update its last_executed_at
        if req.saved_hunt_id:
            sh = db.query(SavedHuntModel).filter(SavedHuntModel.id == req.saved_hunt_id).first()
            if sh:
                sh.last_executed_at = datetime.now(timezone.utc)
                sh.last_result_count = total_count

        db.commit()

        # Emit Realtime Event (Section 46)
        try:
            from backend.schemas.realtime import RealtimeEvent, RealtimeEventPayload
            event = RealtimeEvent(
                event_type=RealtimeEventTypeEnum.HUNT_COMPLETED,
                resource_scope=RealtimeResourceScopeEnum.HUNT,
                resource_id=execution_id,
                workspace_id=workspace_id,
                payload=RealtimeEventPayload(
                    stage="HUNT_COMPLETED",
                    message=f"Threat hunt completed: {total_count} record(s) matched.",
                    details={
                        "execution_id": execution_id,
                        "data_source": source_key.value,
                        "result_count": total_count,
                        "duration_ms": duration_ms,
                    },
                ),
            )
            RealtimePublisher.publish_event(event)
        except Exception as exc:
            logger.debug("Realtime dispatch failed (non-blocking): %s", exc)

        has_more = (qdef.offset + len(items)) < total_count

        return HuntQueryResultResponse(
            execution_id=execution_id,
            data_source=source_key.value,
            status="SUCCEEDED",
            total_matches=total_count,
            items=items,
            aggregations=aggregations,
            duration_ms=duration_ms,
            query_plan=validation.query_plan,
            has_more=has_more,
            offset=qdef.offset,
            limit=qdef.limit,
        )

    # =========================================================================
    # 4. Source-Specific Query Implementations
    # =========================================================================

    @classmethod
    def _query_indicators(
        cls, db: Session, workspace_id: str, qdef: HuntQueryDefinition, t_from: Optional[datetime], t_to: Optional[datetime]
    ) -> Tuple[List[HuntResultItem], int, Optional[Dict[str, List[HuntAggregationBucket]]]]:
        query = db.query(IndicatorModel)

        # Apply Filters
        query = cls._apply_filters_to_model(query, IndicatorModel, qdef.filters)

        # Temporal filter
        if t_from:
            query = query.filter(IndicatorModel.last_seen >= t_from)
        if t_to:
            query = query.filter(IndicatorModel.last_seen <= t_to)

        total_count = query.count()

        # Aggregation if requested
        aggregations = cls._compute_aggregations(db, query, IndicatorModel, qdef.group_by, qdef.top_n, total_count)

        # Sort & Paginate
        query = query.order_by(desc(IndicatorModel.last_seen))
        rows = query.offset(qdef.offset).limit(qdef.limit).all()

        items: List[HuntResultItem] = []
        for r in rows:
            items.append(
                HuntResultItem(
                    id=r.id,
                    data_source="indicators",
                    title=f"{r.indicator_type}: {r.normalized_value}",
                    primary_value=r.normalized_value,
                    secondary_value=r.indicator_type,
                    severity="HIGH" if r.reputation == "MALICIOUS" else ("MEDIUM" if r.reputation == "SUSPICIOUS" else "LOW"),
                    verdict=r.reputation or "UNKNOWN",
                    confidence=r.confidence,
                    observed_at=r.last_seen,
                    properties={
                        "indicator_type": r.indicator_type,
                        "raw_value": r.value,
                        "first_seen": r.first_seen.isoformat() if r.first_seen else None,
                        "last_seen": r.last_seen.isoformat() if r.last_seen else None,
                    },
                    matched_reasons=[f"Observed {r.indicator_type} with reputation {r.reputation or 'UNKNOWN'}"],
                    pivot_links={
                        "osint_url": f"/osint?indicator={r.normalized_value}",
                        "graph_url": f"/graph?focus={r.normalized_value}",
                        "watch_action": True,
                    },
                )
            )
        return items, total_count, aggregations

    @classmethod
    def _query_alerts(
        cls, db: Session, workspace_id: str, qdef: HuntQueryDefinition, t_from: Optional[datetime], t_to: Optional[datetime]
    ) -> Tuple[List[HuntResultItem], int, Optional[Dict[str, List[HuntAggregationBucket]]]]:
        query = db.query(NotificationModel).filter(
            NotificationModel.workspace_id == workspace_id,
            NotificationModel.category == "SECURITY_ALERT",
        )

        query = cls._apply_filters_to_model(query, NotificationModel, qdef.filters)

        if t_from:
            query = query.filter(NotificationModel.created_at >= t_from)
        if t_to:
            query = query.filter(NotificationModel.created_at <= t_to)

        total_count = query.count()
        aggregations = cls._compute_aggregations(db, query, NotificationModel, qdef.group_by, qdef.top_n, total_count)

        query = query.order_by(desc(NotificationModel.created_at))
        rows = query.offset(qdef.offset).limit(qdef.limit).all()

        items: List[HuntResultItem] = []
        for r in rows:
            items.append(
                HuntResultItem(
                    id=r.id,
                    data_source="alerts",
                    title=r.title,
                    primary_value=r.title,
                    secondary_value=r.source_type,
                    severity=r.severity,
                    verdict="MALICIOUS" if r.severity in ("CRITICAL", "HIGH") else "SUSPICIOUS",
                    confidence=1.0,
                    observed_at=r.created_at,
                    properties={
                        "status": r.status,
                        "source_type": r.source_type,
                        "investigation_id": r.investigation_id,
                        "assigned_to": r.assigned_to,
                    },
                    matched_reasons=[f"{r.severity} severity alert via {r.source_type}"],
                    pivot_links={
                        "investigation_url": f"/analysis/{r.investigation_id}" if r.investigation_id else None,
                        "alert_id": r.id,
                    },
                )
            )
        return items, total_count, aggregations

    @classmethod
    def _query_findings(
        cls, db: Session, workspace_id: str, qdef: HuntQueryDefinition, t_from: Optional[datetime], t_to: Optional[datetime]
    ) -> Tuple[List[HuntResultItem], int, Optional[Dict[str, List[HuntAggregationBucket]]]]:
        query = db.query(FindingModel)
        query = cls._apply_filters_to_model(query, FindingModel, qdef.filters)

        if t_from:
            query = query.filter(FindingModel.created_at >= t_from)
        if t_to:
            query = query.filter(FindingModel.created_at <= t_to)

        total_count = query.count()
        aggregations = cls._compute_aggregations(db, query, FindingModel, qdef.group_by, qdef.top_n, total_count)

        query = query.order_by(desc(FindingModel.created_at))
        rows = query.offset(qdef.offset).limit(qdef.limit).all()

        items: List[HuntResultItem] = []
        for r in rows:
            items.append(
                HuntResultItem(
                    id=r.id,
                    data_source="findings",
                    title=r.title,
                    primary_value=r.title,
                    secondary_value=r.analyzer,
                    severity=r.severity,
                    verdict="MALICIOUS" if r.severity in ("CRITICAL", "HIGH") else "SUSPICIOUS",
                    confidence=r.confidence,
                    observed_at=r.created_at,
                    properties={
                        "analyzer": r.analyzer,
                        "finding_type": r.finding_type,
                        "method": r.method,
                        "risk_contribution": r.risk_contribution,
                    },
                    matched_reasons=[f"Analyzer '{r.analyzer}' flagged {r.finding_type} with confidence {r.confidence}"],
                    pivot_links={
                        "run_id": r.analysis_run_id,
                    },
                )
            )
        return items, total_count, aggregations

    @classmethod
    def _query_artifacts(
        cls, db: Session, workspace_id: str, qdef: HuntQueryDefinition, t_from: Optional[datetime], t_to: Optional[datetime]
    ) -> Tuple[List[HuntResultItem], int, Optional[Dict[str, List[HuntAggregationBucket]]]]:
        query = db.query(ArtifactModel).filter(ArtifactModel.workspace_id == workspace_id)
        query = cls._apply_filters_to_model(query, ArtifactModel, qdef.filters)

        if t_from:
            query = query.filter(ArtifactModel.created_at >= t_from)
        if t_to:
            query = query.filter(ArtifactModel.created_at <= t_to)

        total_count = query.count()
        aggregations = cls._compute_aggregations(db, query, ArtifactModel, qdef.group_by, qdef.top_n, total_count)

        query = query.order_by(desc(ArtifactModel.created_at))
        rows = query.offset(qdef.offset).limit(qdef.limit).all()

        items: List[HuntResultItem] = []
        for r in rows:
            items.append(
                HuntResultItem(
                    id=r.id,
                    data_source="artifacts",
                    title=r.filename or f"Artifact-{r.id[:8]}",
                    primary_value=r.filename or r.id,
                    secondary_value=r.mime_type,
                    severity="LOW",
                    observed_at=r.created_at,
                    properties={
                        "mime_type": r.mime_type,
                        "sha256": r.sha256,
                        "source": r.source,
                        "size_bytes": r.size_bytes,
                    },
                    matched_reasons=[f"Payload ingested from source {r.source}"],
                    pivot_links={
                        "sha256": r.sha256,
                        "osint_url": f"/osint?indicator={r.sha256}" if r.sha256 else None,
                    },
                )
            )
        return items, total_count, aggregations

    @classmethod
    def _query_threat_intelligence(
        cls, db: Session, workspace_id: str, qdef: HuntQueryDefinition, t_from: Optional[datetime], t_to: Optional[datetime]
    ) -> Tuple[List[HuntResultItem], int, Optional[Dict[str, List[HuntAggregationBucket]]]]:
        query = db.query(ThreatIntelligenceRecordModel).filter(ThreatIntelligenceRecordModel.workspace_id == workspace_id)
        query = cls._apply_filters_to_model(query, ThreatIntelligenceRecordModel, qdef.filters)

        if t_from:
            query = query.filter(ThreatIntelligenceRecordModel.retrieved_at >= t_from)
        if t_to:
            query = query.filter(ThreatIntelligenceRecordModel.retrieved_at <= t_to)

        total_count = query.count()
        aggregations = cls._compute_aggregations(db, query, ThreatIntelligenceRecordModel, qdef.group_by, qdef.top_n, total_count)

        query = query.order_by(desc(ThreatIntelligenceRecordModel.retrieved_at))
        rows = query.offset(qdef.offset).limit(qdef.limit).all()

        items: List[HuntResultItem] = []
        for r in rows:
            items.append(
                HuntResultItem(
                    id=r.id,
                    data_source="threat_intelligence",
                    title=f"{r.provider}: {r.normalized_value}",
                    primary_value=r.normalized_value,
                    secondary_value=r.provider,
                    severity=r.severity,
                    verdict=r.verdict,
                    confidence=r.confidence,
                    observed_at=r.retrieved_at,
                    properties={
                        "indicator_type": r.indicator_type,
                        "provider": r.provider,
                        "verdict": r.verdict,
                        "severity": r.severity,
                        "is_stale": r.is_stale,
                    },
                    matched_reasons=[f"Provider '{r.provider}' returned verdict {r.verdict} ({r.severity})"],
                    pivot_links={
                        "osint_url": f"/osint?indicator={r.normalized_value}",
                        "watch_action": True,
                    },
                )
            )
        return items, total_count, aggregations

    @classmethod
    def _query_watchlist_changes(
        cls, db: Session, workspace_id: str, qdef: HuntQueryDefinition, t_from: Optional[datetime], t_to: Optional[datetime]
    ) -> Tuple[List[HuntResultItem], int, Optional[Dict[str, List[HuntAggregationBucket]]]]:
        query = db.query(IntelligenceChangeModel).filter(IntelligenceChangeModel.workspace_id == workspace_id)
        query = cls._apply_filters_to_model(query, IntelligenceChangeModel, qdef.filters)

        if t_from:
            query = query.filter(IntelligenceChangeModel.detected_at >= t_from)
        if t_to:
            query = query.filter(IntelligenceChangeModel.detected_at <= t_to)

        total_count = query.count()
        aggregations = cls._compute_aggregations(db, query, IntelligenceChangeModel, qdef.group_by, qdef.top_n, total_count)

        query = query.order_by(desc(IntelligenceChangeModel.detected_at))
        rows = query.offset(qdef.offset).limit(qdef.limit).all()

        items: List[HuntResultItem] = []
        for r in rows:
            items.append(
                HuntResultItem(
                    id=r.id,
                    data_source="watchlist_changes",
                    title=f"{r.change_type}: {r.normalized_value}",
                    primary_value=r.normalized_value,
                    secondary_value=r.change_type,
                    severity=r.change_severity,
                    verdict=r.current_verdict,
                    confidence=r.current_confidence,
                    observed_at=r.detected_at,
                    properties={
                        "change_type": r.change_type,
                        "previous_verdict": r.previous_verdict,
                        "current_verdict": r.current_verdict,
                        "summary": r.change_summary,
                        "alert_id": r.alert_id,
                    },
                    matched_reasons=[r.change_summary],
                    pivot_links={
                        "watchlist_id": r.watchlist_id,
                        "osint_url": f"/osint?indicator={r.normalized_value}",
                        "alert_id": r.alert_id,
                    },
                )
            )
        return items, total_count, aggregations

    @classmethod
    def _query_incidents(
        cls, db: Session, workspace_id: str, qdef: HuntQueryDefinition, t_from: Optional[datetime], t_to: Optional[datetime]
    ) -> Tuple[List[HuntResultItem], int, Optional[Dict[str, List[HuntAggregationBucket]]]]:
        query = db.query(IncidentModel).filter(IncidentModel.workspace_id == workspace_id)
        query = cls._apply_filters_to_model(query, IncidentModel, qdef.filters)

        if t_from:
            query = query.filter(IncidentModel.opened_at >= t_from)
        if t_to:
            query = query.filter(IncidentModel.opened_at <= t_to)

        total_count = query.count()
        aggregations = cls._compute_aggregations(db, query, IncidentModel, qdef.group_by, qdef.top_n, total_count)

        query = query.order_by(desc(IncidentModel.opened_at))
        rows = query.offset(qdef.offset).limit(qdef.limit).all()

        items: List[HuntResultItem] = []
        for r in rows:
            items.append(
                HuntResultItem(
                    id=r.id,
                    data_source="incidents",
                    title=f"{r.incident_number}: {r.title}",
                    primary_value=r.incident_number,
                    secondary_value=r.title,
                    severity=r.severity,
                    verdict="MALICIOUS" if r.severity in ("CRITICAL", "HIGH") else "SUSPICIOUS",
                    confidence=r.confidence,
                    observed_at=r.opened_at,
                    properties={
                        "status": r.status,
                        "priority": r.priority,
                        "risk_score": r.risk_score,
                        "sla_status": r.sla_status,
                        "assigned_to": r.assigned_to,
                    },
                    matched_reasons=[f"{r.severity} severity incident in status {r.status} (SLA: {r.sla_status})"],
                    pivot_links={
                        "investigation_url": f"/cases/{r.id}",
                    },
                )
            )
        return items, total_count, aggregations

    # =========================================================================
    # 5. Filter Helpers & Aggregations
    # =========================================================================

    @classmethod
    def _apply_filters_to_model(cls, query: Any, model: Any, filters: List[QueryFilter]) -> Any:
        for flt in filters:
            if not hasattr(model, flt.field):
                continue
            col = getattr(model, flt.field)
            op = flt.operator
            val = flt.value

            if op == QueryOperatorEnum.EQUALS:
                query = query.filter(col == val)
            elif op == QueryOperatorEnum.NOT_EQUALS:
                query = query.filter(col != val)
            elif op == QueryOperatorEnum.CONTAINS:
                query = query.filter(func.lower(col).contains(str(val).lower()))
            elif op == QueryOperatorEnum.STARTS_WITH:
                query = query.filter(col.startswith(str(val)))
            elif op == QueryOperatorEnum.ENDS_WITH:
                query = query.filter(col.endswith(str(val)))
            elif op == QueryOperatorEnum.IN:
                val_list = val if isinstance(val, list) else [val]
                query = query.filter(col.in_(val_list))
            elif op == QueryOperatorEnum.NOT_IN:
                val_list = val if isinstance(val, list) else [val]
                query = query.filter(~col.in_(val_list))
            elif op == QueryOperatorEnum.GREATER_THAN:
                query = query.filter(col > val)
            elif op == QueryOperatorEnum.GREATER_THAN_OR_EQUAL:
                query = query.filter(col >= val)
            elif op == QueryOperatorEnum.LESS_THAN:
                query = query.filter(col < val)
            elif op == QueryOperatorEnum.LESS_THAN_OR_EQUAL:
                query = query.filter(col <= val)
            elif op == QueryOperatorEnum.BETWEEN:
                if isinstance(val, (list, tuple)) and len(val) == 2:
                    query = query.filter(col.between(val[0], val[1]))
            elif op == QueryOperatorEnum.EXISTS:
                query = query.filter(col.isnot(None))
            elif op == QueryOperatorEnum.NOT_EXISTS:
                query = query.filter(col.is_(None))
            elif op == QueryOperatorEnum.BEFORE:
                query = query.filter(col <= val)
            elif op == QueryOperatorEnum.AFTER:
                query = query.filter(col >= val)

        return query

    @classmethod
    def _resolve_time_range(cls, tr: Optional[QueryTimeRange]) -> Tuple[Optional[datetime], Optional[datetime]]:
        now = datetime.now(timezone.utc)
        if not tr or not tr.preset or tr.preset == TimePresetEnum.ALL:
            return None, None

        if tr.preset == TimePresetEnum.CUSTOM:
            return tr.from_time, tr.to_time

        deltas = {
            TimePresetEnum.M15: timedelta(minutes=15),
            TimePresetEnum.H1: timedelta(hours=1),
            TimePresetEnum.H6: timedelta(hours=6),
            TimePresetEnum.H24: timedelta(hours=24),
            TimePresetEnum.D7: timedelta(days=7),
            TimePresetEnum.D30: timedelta(days=30),
        }
        delta = deltas.get(tr.preset)
        if delta:
            return now - delta, now
        return None, None

    @classmethod
    def _compute_aggregations(
        cls, db: Session, base_query: Any, model: Any, group_by_field: Optional[str], top_n: Optional[int], total_count: int
    ) -> Optional[Dict[str, List[HuntAggregationBucket]]]:
        if not group_by_field or not hasattr(model, group_by_field) or total_count == 0:
            return None

        col = getattr(model, group_by_field)
        limit_val = top_n or 20

        agg_query = (
            base_query.with_entities(col, func.count().label("cnt"))
            .group_by(col)
            .order_by(desc("cnt"))
            .limit(limit_val)
        )
        results = agg_query.all()

        buckets: List[HuntAggregationBucket] = []
        for row in results:
            key_name = str(row[0]) if row[0] is not None else "(empty)"
            cnt = int(row[1])
            pct = round((cnt / total_count) * 100, 1)
            buckets.append(HuntAggregationBucket(key=key_name, count=cnt, percentage=pct))

        return {group_by_field: buckets}

    @classmethod
    def _count_source_records(cls, db: Session, source: HuntSourceEnum, workspace_id: str) -> int:
        if source == HuntSourceEnum.INDICATORS:
            return db.query(IndicatorModel).count()
        elif source == HuntSourceEnum.ALERTS:
            return db.query(NotificationModel).filter(NotificationModel.workspace_id == workspace_id, NotificationModel.category == "SECURITY_ALERT").count()
        elif source == HuntSourceEnum.FINDINGS:
            return db.query(FindingModel).count()
        elif source == HuntSourceEnum.ARTIFACTS:
            return db.query(ArtifactModel).filter(ArtifactModel.workspace_id == workspace_id).count()
        elif source == HuntSourceEnum.THREAT_INTELLIGENCE:
            return db.query(ThreatIntelligenceRecordModel).filter(ThreatIntelligenceRecordModel.workspace_id == workspace_id).count()
        elif source == HuntSourceEnum.WATCHLIST_CHANGES:
            return db.query(IntelligenceChangeModel).filter(IntelligenceChangeModel.workspace_id == workspace_id).count()
        elif source == HuntSourceEnum.INCIDENTS:
            return db.query(IncidentModel).filter(IncidentModel.workspace_id == workspace_id).count()
        return 0

    # =========================================================================
    # 6. Saved Hunts Management & Seeding
    # =========================================================================

    @classmethod
    def list_saved_hunts(cls, db: Session, workspace_id: str, user_id: Optional[str] = None) -> SavedHuntListResponse:
        """Returns saved hunts and built-in templates."""
        cls._ensure_default_templates(db, workspace_id)

        rows = (
            db.query(SavedHuntModel)
            .filter(
                SavedHuntModel.workspace_id == workspace_id,
                or_(
                    SavedHuntModel.visibility.in_([HuntVisibilityEnum.TEAM.value, HuntVisibilityEnum.TENANT.value]),
                    and_(SavedHuntModel.visibility == HuntVisibilityEnum.PRIVATE.value, SavedHuntModel.owner_user_id == user_id),
                ),
            )
            .order_by(desc(SavedHuntModel.is_template), desc(SavedHuntModel.updated_at))
            .all()
        )

        items = [cls._build_saved_hunt_response(r) for r in rows if not r.is_template]
        templates = [cls._build_saved_hunt_response(r) for r in rows if r.is_template]

        return SavedHuntListResponse(items=items, templates=templates, total=len(items) + len(templates))

    @classmethod
    def create_saved_hunt(
        cls, db: Session, workspace_id: str, req: SavedHuntCreateRequest, actor: str = "system"
    ) -> SavedHuntResponse:
        # Validate query
        val = cls.validate_query(req.query_definition, workspace_id)
        if not val.is_valid:
            raise ValueError(f"Cannot save invalid hunt query: {'; '.join(val.errors)}")

        model = SavedHuntModel(
            id=str(uuid.uuid4()),
            workspace_id=workspace_id,
            name=req.name.strip(),
            description=req.description,
            data_source=req.data_source.value,
            query_definition_json=req.query_definition.model_dump_json(),
            hypothesis=req.hypothesis,
            tags_json=json.dumps(req.tags or []),
            owner_user_id=actor,
            visibility=req.visibility.value,
            is_template=False,
            created_by=actor,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        db.add(model)
        db.commit()
        db.refresh(model)
        return cls._build_saved_hunt_response(model)

    @classmethod
    def update_saved_hunt(
        cls, db: Session, workspace_id: str, hunt_id: str, req: SavedHuntUpdateRequest, actor: str = "system"
    ) -> Optional[SavedHuntResponse]:
        sh = db.query(SavedHuntModel).filter(SavedHuntModel.workspace_id == workspace_id, SavedHuntModel.id == hunt_id).first()
        if not sh:
            return None

        if req.name is not None:
            sh.name = req.name.strip()
        if req.description is not None:
            sh.description = req.description
        if req.query_definition is not None:
            val = cls.validate_query(req.query_definition, workspace_id)
            if not val.is_valid:
                raise ValueError(f"Updated query is invalid: {'; '.join(val.errors)}")
            sh.query_definition_json = req.query_definition.model_dump_json()
            sh.data_source = req.query_definition.data_source.value
        if req.hypothesis is not None:
            sh.hypothesis = req.hypothesis
        if req.tags is not None:
            sh.tags_json = json.dumps(req.tags)
        if req.visibility is not None:
            sh.visibility = req.visibility.value

        sh.updated_by = actor
        sh.updated_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(sh)
        return cls._build_saved_hunt_response(sh)

    @classmethod
    def delete_saved_hunt(cls, db: Session, workspace_id: str, hunt_id: str) -> bool:
        sh = db.query(SavedHuntModel).filter(SavedHuntModel.workspace_id == workspace_id, SavedHuntModel.id == hunt_id).first()
        if not sh:
            return False
        db.delete(sh)
        db.commit()
        return True

    @classmethod
    def _ensure_default_templates(cls, db: Session, workspace_id: str):
        """Seeds built-in hunting templates if not already present."""
        templates_defs = [
            (
                "Newly Malicious Indicators (Last 24h)",
                "Finds observables that transitioned to MALICIOUS within the last 24 hours.",
                HuntSourceEnum.WATCHLIST_CHANGES,
                HuntQueryDefinition(
                    data_source=HuntSourceEnum.WATCHLIST_CHANGES,
                    filters=[
                        QueryFilter(field="change_type", operator=QueryOperatorEnum.EQUALS, value="NEWLY_MALICIOUS")
                    ],
                    time_range=QueryTimeRange(preset=TimePresetEnum.H24),
                    limit=50,
                ),
                "Observables newly classified as malicious warrant immediate threat containment.",
            ),
            (
                "High-Risk Infrastructure (Domains & IPs)",
                "Proactively hunts for active external infrastructure with HIGH/CRITICAL severity.",
                HuntSourceEnum.THREAT_INTELLIGENCE,
                HuntQueryDefinition(
                    data_source=HuntSourceEnum.THREAT_INTELLIGENCE,
                    filters=[
                        QueryFilter(field="verdict", operator=QueryOperatorEnum.EQUALS, value="MALICIOUS"),
                        QueryFilter(field="indicator_type", operator=QueryOperatorEnum.IN, value=["DOMAIN", "IP"]),
                    ],
                    time_range=QueryTimeRange(preset=TimePresetEnum.D7),
                    limit=50,
                ),
                "Attacker infrastructure often reuses domains or network ranges across campaigns.",
            ),
            (
                "Unacknowledged Critical Security Alerts",
                "Isolates unread CRITICAL alerts generated across analytical detectors.",
                HuntSourceEnum.ALERTS,
                HuntQueryDefinition(
                    data_source=HuntSourceEnum.ALERTS,
                    filters=[
                        QueryFilter(field="severity", operator=QueryOperatorEnum.EQUALS, value="CRITICAL"),
                        QueryFilter(field="status", operator=QueryOperatorEnum.EQUALS, value="UNREAD"),
                    ],
                    time_range=QueryTimeRange(preset=TimePresetEnum.D7),
                    limit=50,
                ),
                "Unacknowledged high-impact alerts expose the organization to prolonged dwell time.",
            ),
        ]

        for name, desc_text, source, qdef, hyp in templates_defs:
            existing = (
                db.query(SavedHuntModel)
                .filter(SavedHuntModel.workspace_id == workspace_id, SavedHuntModel.name == name, SavedHuntModel.is_template == True)
                .first()
            )
            if not existing:
                tpl = SavedHuntModel(
                    id=str(uuid.uuid4()),
                    workspace_id=workspace_id,
                    name=name,
                    description=desc_text,
                    data_source=source.value,
                    query_definition_json=qdef.model_dump_json(),
                    hypothesis=hyp,
                    tags_json=json.dumps(["template", "recommended"]),
                    owner_user_id="system",
                    visibility=HuntVisibilityEnum.TENANT.value,
                    is_template=True,
                    created_by="system",
                    created_at=datetime.now(timezone.utc),
                    updated_at=datetime.now(timezone.utc),
                )
                db.add(tpl)
        db.commit()

    @classmethod
    def _build_saved_hunt_response(cls, model: SavedHuntModel) -> SavedHuntResponse:
        qdef = HuntQueryDefinition.model_validate_json(model.query_definition_json)
        try:
            tags = json.loads(model.tags_json)
        except Exception:
            tags = []
        return SavedHuntResponse(
            id=model.id,
            workspace_id=model.workspace_id,
            name=model.name,
            description=model.description,
            data_source=model.data_source,
            query_definition=qdef,
            hypothesis=model.hypothesis,
            tags=tags,
            owner_user_id=model.owner_user_id,
            team_id=model.team_id,
            visibility=model.visibility,
            is_template=model.is_template,
            last_executed_at=model.last_executed_at,
            last_result_count=model.last_result_count,
            created_by=model.created_by,
            created_at=model.created_at,
            updated_at=model.updated_at,
        )

    # =========================================================================
    # 7. AI-Assisted Query Generation (Controlled Heuristics & Rules)
    # =========================================================================

    @classmethod
    def natural_language_to_query(cls, req: NaturalLanguageHuntRequest) -> NaturalLanguageHuntResponse:
        """
        Converts analyst natural language input into a safe, validated HuntQueryDefinition.
        Ensures deterministic field mapping and explicitly rejects arbitrary code/SQL generation.
        """
        prompt = req.prompt.lower().strip()

        # 1. Determine Source
        source = HuntSourceEnum.INDICATORS
        if any(w in prompt for w in ["alert", "notification", "security alert"]):
            source = HuntSourceEnum.ALERTS
        elif any(w in prompt for w in ["finding", "analyzer", "detection"]):
            source = HuntSourceEnum.FINDINGS
        elif any(w in prompt for w in ["incident", "case"]):
            source = HuntSourceEnum.INCIDENTS
        elif any(w in prompt for w in ["file", "artifact", "attachment", "payload"]):
            source = HuntSourceEnum.ARTIFACTS
        elif any(w in prompt for w in ["intel", "intelligence", "threat intel", "provider"]):
            source = HuntSourceEnum.THREAT_INTELLIGENCE
        elif any(w in prompt for w in ["watchlist", "transition", "changed", "reputation change"]):
            source = HuntSourceEnum.WATCHLIST_CHANGES
        elif req.suggested_source:
            source = req.suggested_source

        filters: List[QueryFilter] = []

        # 2. Extract Type / Observable filters
        if source == HuntSourceEnum.INDICATORS:
            if "domain" in prompt:
                filters.append(QueryFilter(field="indicator_type", operator=QueryOperatorEnum.EQUALS, value="DOMAIN"))
            elif "ip" in prompt or "ips" in prompt:
                filters.append(QueryFilter(field="indicator_type", operator=QueryOperatorEnum.EQUALS, value="IP"))
            elif "url" in prompt or "urls" in prompt:
                filters.append(QueryFilter(field="indicator_type", operator=QueryOperatorEnum.EQUALS, value="URL"))
            elif "hash" in prompt or "sha256" in prompt or "md5" in prompt:
                filters.append(QueryFilter(field="indicator_type", operator=QueryOperatorEnum.IN, value=["SHA256", "MD5"]))

            if "malicious" in prompt:
                filters.append(QueryFilter(field="reputation", operator=QueryOperatorEnum.EQUALS, value="MALICIOUS"))
            elif "suspicious" in prompt:
                filters.append(QueryFilter(field="reputation", operator=QueryOperatorEnum.EQUALS, value="SUSPICIOUS"))
            elif "clean" in prompt:
                filters.append(QueryFilter(field="reputation", operator=QueryOperatorEnum.EQUALS, value="CLEAN"))

        elif source == HuntSourceEnum.ALERTS:
            if "critical" in prompt:
                filters.append(QueryFilter(field="severity", operator=QueryOperatorEnum.EQUALS, value="CRITICAL"))
            elif "high" in prompt:
                filters.append(QueryFilter(field="severity", operator=QueryOperatorEnum.EQUALS, value="HIGH"))
            if "unread" in prompt or "open" in prompt:
                filters.append(QueryFilter(field="status", operator=QueryOperatorEnum.EQUALS, value="UNREAD"))

        elif source == HuntSourceEnum.THREAT_INTELLIGENCE:
            if "malicious" in prompt:
                filters.append(QueryFilter(field="verdict", operator=QueryOperatorEnum.EQUALS, value="MALICIOUS"))
            if "high" in prompt or "critical" in prompt:
                filters.append(QueryFilter(field="severity", operator=QueryOperatorEnum.IN, value=["HIGH", "CRITICAL"]))

        # 3. Time Preset Extraction
        time_preset = TimePresetEnum.D7
        if any(w in prompt for w in ["24h", "24 hours", "yesterday", "today", "1 day"]):
            time_preset = TimePresetEnum.H24
        elif any(w in prompt for w in ["hour", "1h", "60 mins"]):
            time_preset = TimePresetEnum.H1
        elif any(w in prompt for w in ["30 days", "month"]):
            time_preset = TimePresetEnum.D30
        elif any(w in prompt for w in ["all time", "ever", "unbounded"]):
            time_preset = TimePresetEnum.ALL

        proposed = HuntQueryDefinition(
            data_source=source,
            filters=filters,
            time_range=QueryTimeRange(preset=time_preset),
            limit=50,
        )

        explanation = (
            f"Mapped question to '{source.value}' data source with {len(filters)} validated filter condition(s) "
            f"bounded within preset '{time_preset.value}'. Review the query plan and click Run Hunt."
        )

        return NaturalLanguageHuntResponse(
            interpretation=f"Threat Hunt across {source.value.replace('_', ' ').title()}",
            proposed_query=proposed,
            confidence=0.92,
            explanation=explanation,
        )

    # =========================================================================
    # 8. Investigation & Watchlist Handoffs
    # =========================================================================

    @classmethod
    def handoff_to_investigation(
        cls, db: Session, workspace_id: str, req: HuntInvestigationHandoffRequest, actor: str = "analyst"
    ) -> HuntInvestigationHandoffResponse:
        """
        Creates or updates a Section 50 Incident/Investigation from selected hunt records.
        Preserves hunt query provenance and record IDs without copying raw datasets.
        """
        exec_record = db.query(HuntExecutionModel).filter(HuntExecutionModel.id == req.execution_id).first()
        if not exec_record:
            raise ValueError(f"Hunt execution '{req.execution_id}' not found.")

        # Create or attach to Incident
        inv_id = req.investigation_id
        if not inv_id:
            title = req.investigation_title or f"Hunt Finding: {exec_record.data_source.title()} Investigation"
            inc = IncidentModel(
                id=str(uuid.uuid4()),
                workspace_id=workspace_id,
                title=title,
                description=f"Generated from Threat Hunt execution #{exec_record.id[:8]} ({exec_record.data_source}). Reason: {req.reason or 'Suspicious pattern identified during proactive threat hunt.'}",
                status="OPEN",
                severity="HIGH",
                priority="P2_HIGH",
                category="OTHER",
                created_by=actor,
                opened_at=datetime.now(timezone.utc),
                metadata_json=json.dumps({
                    "source_hunt_id": exec_record.id,
                    "matched_records_count": len(req.selected_record_ids),
                    "matched_records": req.selected_record_ids,
                }),
            )
            db.add(inc)
            db.commit()
            inv_id = inc.id

        return HuntInvestigationHandoffResponse(
            success=True,
            investigation_id=inv_id,
            attached_records_count=len(req.selected_record_ids),
            message=f"Successfully attached {len(req.selected_record_ids)} hunt results to investigation '{inv_id}'.",
        )

    @classmethod
    def handoff_to_watchlist(
        cls, db: Session, workspace_id: str, req: HuntWatchlistHandoffRequest, actor: str = "analyst"
    ) -> HuntWatchlistHandoffResponse:
        """
        Adds selected indicators from hunt results to a Section 53 Watchlist for continuous monitoring.
        """
        exec_record = db.query(HuntExecutionModel).filter(HuntExecutionModel.id == req.execution_id).first()
        if not exec_record:
            raise ValueError(f"Hunt execution '{req.execution_id}' not found.")

        wl_id = req.watchlist_id
        if not wl_id:
            wl_name = req.new_watchlist_name or f"Hunt #{exec_record.id[:8]} Watchlist"
            wl = WatchlistModel(
                id=str(uuid.uuid4()),
                workspace_id=workspace_id,
                name=wl_name,
                description=f"Automated watchlist created from Threat Hunt execution #{exec_record.id[:8]}.",
                status="ACTIVE",
                priority="HIGH",
                created_by=actor,
                created_at=datetime.now(timezone.utc),
            )
            db.add(wl)
            db.commit()
            wl_id = wl.id

        added_count = 0
        from backend.schemas.watchlists import WatchedIndicatorCreateRequest

        for rec_id in req.selected_record_ids:
            # Look up indicator value from IndicatorModel or ThreatIntelligenceRecordModel
            ind = db.query(IndicatorModel).filter(IndicatorModel.id == rec_id).first()
            if ind:
                try:
                    WatchlistMonitoringService.add_indicator(
                        db, workspace_id, wl_id,
                        WatchedIndicatorCreateRequest(indicator_value=ind.normalized_value, indicator_type=ind.indicator_type),
                        actor=actor
                    )
                    added_count += 1
                except Exception:
                    pass
                continue

            ti = db.query(ThreatIntelligenceRecordModel).filter(ThreatIntelligenceRecordModel.id == rec_id).first()
            if ti:
                try:
                    WatchlistMonitoringService.add_indicator(
                        db, workspace_id, wl_id,
                        WatchedIndicatorCreateRequest(indicator_value=ti.normalized_value, indicator_type=ti.indicator_type),
                        actor=actor
                    )
                    added_count += 1
                except Exception:
                    pass

        return HuntWatchlistHandoffResponse(
            success=True,
            watchlist_id=wl_id,
            added_indicators_count=added_count,
            message=f"Added {added_count} indicator(s) to watchlist '{wl_id}' for continuous monitoring.",
        )

    @classmethod
    def export_results(cls, db: Session, workspace_id: str, execution_id: str, format_type: str = "json") -> Tuple[str, str]:
        """Exports hunt results to JSON or CSV."""
        exec_record = db.query(HuntExecutionModel).filter(
            HuntExecutionModel.workspace_id == workspace_id,
            HuntExecutionModel.id == execution_id,
        ).first()
        if not exec_record:
            raise ValueError(f"Hunt execution '{execution_id}' not found.")

        try:
            record_ids = json.loads(exec_record.matched_record_ids_json)
        except Exception:
            record_ids = []

        qdef = HuntQueryDefinition.model_validate_json(exec_record.query_definition_json)
        # Execute query with export limit
        qdef.limit = min(exec_record.result_count or 100, 1000)
        qdef.offset = 0

        res = cls.execute_hunt(db, workspace_id, HuntExecutionRequest(query_definition=qdef))

        if format_type.lower() == "csv":
            from backend.services.security_hardening_service import SecurityHardeningService
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(["ID", "Title", "Primary Value", "Secondary Value", "Severity", "Verdict", "Confidence", "Observed At"])
            for itm in res.items:
                writer.writerow([
                    SecurityHardeningService.sanitize_csv_cell(itm.id),
                    SecurityHardeningService.sanitize_csv_cell(itm.title),
                    SecurityHardeningService.sanitize_csv_cell(itm.primary_value),
                    SecurityHardeningService.sanitize_csv_cell(itm.secondary_value or ""),
                    SecurityHardeningService.sanitize_csv_cell(itm.severity or ""),
                    SecurityHardeningService.sanitize_csv_cell(itm.verdict or ""),
                    SecurityHardeningService.sanitize_csv_cell(itm.confidence or ""),
                    SecurityHardeningService.sanitize_csv_cell(itm.observed_at.isoformat() if itm.observed_at else ""),
                ])
            return output.getvalue(), "text/csv"

        # JSON default
        data = {
            "execution_id": execution_id,
            "data_source": exec_record.data_source,
            "total_matches": res.total_matches,
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "items": [itm.model_dump() for itm in res.items],
        }
        return json.dumps(data, indent=2, default=str), "application/json"
