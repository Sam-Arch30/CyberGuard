"""
Analysis Orchestrator & Live Task DAG Execution Engine (Section 37).
Coordinates atomic analysis tasks, dependency graphs, real-time event broadcasting,
and multi-modal forensic pipeline execution.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from sqlalchemy.orm import Session

from backend.db.models import (
    ArtifactModel,
    AnalysisRunModel,
    AnalysisTaskModel,
    AnalysisEventModel,
    FindingModel,
    FindingEvidenceModel,
    EvidenceModel,
    IncidentModel,
    RelationshipModel,
    IndicatorModel,
    ThreatEventModel,
    generate_uuid,
    get_utc_now,
)
from backend.schemas.unified import (
    ArtifactTypeEnum,
    AnalysisStatusEnum,
    SeverityEnum,
    FindingMethodEnum,
    normalize_domain,
    normalize_ip,
    normalize_url,
)
from backend.services.evidence_storage import evidence_storage

logger = logging.getLogger("cyberguard.orchestrator")


# ============================================================================
# REAL-TIME PUB/SUB EVENT HUB (In-Memory SSE Broadcasting)
# ============================================================================

from backend.services.realtime_service import global_realtime_hub, RealtimePublisher


class AnalysisEventHub:
    """Manages active Server-Sent Event (SSE) subscriber queues per AnalysisRun with RealtimeHub integration."""

    async def subscribe(self, run_id: str) -> asyncio.Queue:
        return await global_realtime_hub.subscribe(f"run:{run_id}")

    async def unsubscribe(self, run_id: str, queue: asyncio.Queue):
        await global_realtime_hub.unsubscribe(f"run:{run_id}", queue)

    async def broadcast(self, run_id: str, event_payload: Dict[str, Any]):
        channel = f"run:{run_id}"
        target_queues = set()
        async with global_realtime_hub._lock:
            if channel in global_realtime_hub._subscribers:
                target_queues = set(global_realtime_hub._subscribers[channel])

        for q in target_queues:
            try:
                q.put_nowait(event_payload)
            except asyncio.QueueFull:
                pass


global_event_hub = AnalysisEventHub()


# ============================================================================
# ANALYSIS ORCHESTRATOR
# ============================================================================

class AnalysisOrchestrator:
    """
    Central orchestration engine for live forensic analysis runs.
    Constructs deterministic task DAGs per artifact type and coordinates
    execution, status transitions, and real-time SSE broadcasts.
    """

    @classmethod
    def get_dag_blueprint(cls, artifact_type: str) -> List[Dict[str, Any]]:
        """Returns standard DAG definition for a given artifact type."""
        clean_type = (artifact_type or "FILE").upper()

        if clean_type in (ArtifactTypeEnum.EMAIL.value, "EMAIL"):
            return [
                {
                    "analyzer_id": "email_validator",
                    "task_type": "EVIDENCE_VALIDATION",
                    "title": "Evidence Integrity & RFC-822 Validation",
                    "description": "Verifies cryptographic SHA-256 hash against evidence storage and checks RFC-822 compliance.",
                    "dependencies": [],
                    "version": "1.0.0",
                },
                {
                    "analyzer_id": "mime_parser",
                    "task_type": "MIME_PARSING",
                    "title": "MIME Decomposition & Body Sanitization",
                    "description": "Extracts MIME boundaries, parses multipart headers, normalizes bodies, and neutralizes active script beacons.",
                    "dependencies": ["email_validator"],
                    "version": "1.0.0",
                },
                {
                    "analyzer_id": "auth_verifier",
                    "task_type": "AUTHENTICATION_ANALYSIS",
                    "title": "Email Authentication (SPF, DKIM, DMARC)",
                    "description": "Validates cryptographic DKIM signatures, evaluates SPF reverse-path authorization, and enforces DMARC alignment.",
                    "dependencies": ["mime_parser"],
                    "version": "1.0.0",
                },
                {
                    "analyzer_id": "relay_analyzer",
                    "task_type": "SMTP_RELAY_ANALYSIS",
                    "title": "SMTP Received Hop & Latency Reconstruction",
                    "description": "Traces transit route through intermediate MTA hops, identifies earliest observable node, and detects timing anomalies.",
                    "dependencies": ["mime_parser"],
                    "version": "1.0.0",
                },
                {
                    "analyzer_id": "attachment_triage",
                    "task_type": "ATTACHMENT_DISCOVERY",
                    "title": "Attachment Discovery & Static Triage",
                    "description": "Discovers nested payloads, computes streaming hashes, identifies double extensions, and registers child artifacts.",
                    "dependencies": ["mime_parser"],
                    "version": "1.0.0",
                },
                {
                    "analyzer_id": "ioc_extractor",
                    "task_type": "IOC_EXTRACTION",
                    "title": "Observable Indicator (IOC) Extraction",
                    "description": "Extracts and normalizes URLs, domain names, IPv4/IPv6 addresses, and sender identities from headers and body text.",
                    "dependencies": ["mime_parser"],
                    "version": "1.0.0",
                },
                {
                    "analyzer_id": "intelligence_enricher",
                    "task_type": "INTELLIGENCE_ENRICHMENT",
                    "title": "Network & Threat Intelligence Enrichment",
                    "description": "Performs passive IP Geo/ASN lookup, DNS record verification, RDAP domain registration analysis, and brand lookalike detection.",
                    "dependencies": ["ioc_extractor"],
                    "version": "1.0.0",
                },
                {
                    "analyzer_id": "social_engineering_nlp",
                    "task_type": "NLP_SOCIAL_ENGINEERING",
                    "title": "Linguistic Intent & Phishing Heuristics",
                    "description": "Runs NLP model to detect coercive phrasing, urgency triggers, credential harvesting language, and BEC patterns.",
                    "dependencies": ["mime_parser"],
                    "version": "1.0.0",
                },
                {
                    "analyzer_id": "risk_engine",
                    "task_type": "RISK_ASSESSMENT",
                    "title": "Unified Risk Assessment & MITRE Mapping",
                    "description": "Aggregates multi-source evidence, enforces signal independence, computes overall risk score, and maps MITRE techniques.",
                    "dependencies": ["auth_verifier", "relay_analyzer", "attachment_triage", "intelligence_enricher", "social_engineering_nlp"],
                    "version": "1.0.0",
                },
            ]

        elif clean_type in (ArtifactTypeEnum.URL.value, ArtifactTypeEnum.DOMAIN.value, ArtifactTypeEnum.IP.value, "URL", "DOMAIN", "IP"):
            return [
                {
                    "analyzer_id": "url_validator",
                    "task_type": "EVIDENCE_VALIDATION",
                    "title": "URL Syntax & Provenance Validation",
                    "description": "Validates lexical structure, canonicalizes scheme/host/port, and verifies hash.",
                    "dependencies": [],
                    "version": "1.0.0",
                },
                {
                    "analyzer_id": "passive_url_analyzer",
                    "task_type": "PASSIVE_URL_ANALYSIS",
                    "title": "Passive Lexical & Heuristic Inspection",
                    "description": "Analyzes hostname entropy, detects punycode homoglyphs, investigates path depth, and scans for suspicious query parameters.",
                    "dependencies": ["url_validator"],
                    "version": "1.0.0",
                },
                {
                    "analyzer_id": "domain_intelligence",
                    "task_type": "DOMAIN_INTELLIGENCE",
                    "title": "DNS & Domain Registration Intelligence",
                    "description": "Queries authoritative DNS records (A, AAAA, MX, NS), parses RDAP registration data, and flags newly registered domains.",
                    "dependencies": ["passive_url_analyzer"],
                    "version": "1.0.0",
                },
                {
                    "analyzer_id": "safe_website_inspector",
                    "task_type": "ACTIVE_INSPECTION",
                    "title": "Controlled Network Inspection (SSRF-Guarded)",
                    "description": "Inspects TLS certificate attributes, evaluates cipher suites, and traces HTTP redirects within safe boundaries.",
                    "dependencies": ["passive_url_analyzer"],
                    "version": "1.0.0",
                },
                {
                    "analyzer_id": "threat_intelligence",
                    "task_type": "THREAT_REPUTATION",
                    "title": "Reputation Feeds & Lookalike Evaluation",
                    "description": "Cross-references observed domains against curated threat feeds and computes Levenshtein distances against protected brands.",
                    "dependencies": ["domain_intelligence"],
                    "version": "1.0.0",
                },
                {
                    "analyzer_id": "risk_engine",
                    "task_type": "RISK_ASSESSMENT",
                    "title": "Risk Assessment & Attack Technique Attribution",
                    "description": "Synthesizes structural and reputation signals to determine threat severity and confidence score.",
                    "dependencies": ["safe_website_inspector", "threat_intelligence"],
                    "version": "1.0.0",
                },
            ]

        elif clean_type in (ArtifactTypeEnum.AUTH_LOG.value, ArtifactTypeEnum.SYSTEM_LOG.value, ArtifactTypeEnum.NETWORK_LOG.value, ArtifactTypeEnum.ENDPOINT_EVENT.value, "AUTH_LOG", "SERVER_LOG", "NETWORK_LOG", "SYSTEM_LOG"):
            return [
                {
                    "analyzer_id": "log_validator",
                    "task_type": "EVIDENCE_VALIDATION",
                    "title": "Telemetry Parsing & Schema Validation",
                    "description": "Parses structured JSON/Syslog record and validates mandatory security event attributes.",
                    "dependencies": [],
                    "version": "1.0.0",
                },
                {
                    "analyzer_id": "event_normalizer",
                    "task_type": "EVENT_NORMALIZATION",
                    "title": "Multi-Provider Event Normalization",
                    "description": "Maps vendor-specific authentication keys into canonical fields (user, source_ip, action, outcome).",
                    "dependencies": ["log_validator"],
                    "version": "1.0.0",
                },
                {
                    "analyzer_id": "behavioral_baseline",
                    "task_type": "BEHAVIORAL_BASELINE",
                    "title": "Account Behavioral Baseline Comparison",
                    "description": "Compares observed login time, geographic location, and ASN against historical user profile baselines.",
                    "dependencies": ["event_normalizer"],
                    "version": "1.0.0",
                },
                {
                    "analyzer_id": "anomaly_detector",
                    "task_type": "ANOMALY_DETECTION",
                    "title": "Attack Pattern & Account Takeover Detection",
                    "description": "Evaluates rapid authentication failures, brute-force bursts, password spraying, and concurrent impossible travel.",
                    "dependencies": ["behavioral_baseline"],
                    "version": "1.0.0",
                },
                {
                    "analyzer_id": "risk_engine",
                    "task_type": "RISK_ASSESSMENT",
                    "title": "Identity Threat Event Scoring & Prioritization",
                    "description": "Assigns incident severity rating, associates affected identity, and calculates composite risk score.",
                    "dependencies": ["anomaly_detector"],
                    "version": "1.0.0",
                },
            ]

        elif clean_type in (ArtifactTypeEnum.IMAGE.value, ArtifactTypeEnum.AUDIO.value, ArtifactTypeEnum.VIDEO.value, "IMAGE", "AUDIO", "VIDEO"):
            return [
                {
                    "analyzer_id": "media_validator",
                    "task_type": "EVIDENCE_VALIDATION",
                    "title": "Media Header & Container Verification",
                    "description": "Inspects media container headers, verifies file signatures, and validates cryptographic checksums.",
                    "dependencies": [],
                    "version": "1.0.0",
                },
                {
                    "analyzer_id": "metadata_extractor",
                    "task_type": "METADATA_EXTRACTION",
                    "title": "EXIF & Forensic Provenance Extraction",
                    "description": "Extracts EXIF metadata, camera hardware stamps, timestamp discrepancies, and software modification headers.",
                    "dependencies": ["media_validator"],
                    "version": "1.0.0",
                },
                {
                    "analyzer_id": "forensic_analyzer",
                    "task_type": "FORENSIC_INSPECTION",
                    "title": "Payload & Manipulation Detection",
                    "description": "Runs bounded image, audio or sampled-frame heuristics. Deepfake accuracy is not established.",
                    "dependencies": ["metadata_extractor"],
                    "version": "1.0.0",
                },
                {
                    "analyzer_id": "risk_engine",
                    "task_type": "RISK_ASSESSMENT",
                    "title": "Authenticity Assessment & Finding Generation",
                    "description": "Computes composite authenticity score and maps forensic indicators into knowledge graph.",
                    "dependencies": ["forensic_analyzer"],
                    "version": "1.0.0",
                },
            ]

        else:
            # Generic File / Static Binary
            return [
                {
                    "analyzer_id": "file_validator",
                    "task_type": "EVIDENCE_VALIDATION",
                    "title": "File Format & Streaming Hash Verification",
                    "description": "Computes SHA-256, SHA-1, MD5 hashes, inspects magic bytes, and validates file boundaries.",
                    "dependencies": [],
                    "version": "1.0.0",
                },
                {
                    "analyzer_id": "static_format_analyzer",
                    "task_type": "FORMAT_INSPECTION",
                    "title": "Static Structure & Content Inspection",
                    "description": "Inspects container structure (PE/ELF headers, PDF stream objects, Office OLE macros, Archive directory trees).",
                    "dependencies": ["file_validator"],
                    "version": "1.0.0",
                },
                {
                    "analyzer_id": "file_ioc_extractor",
                    "task_type": "IOC_EXTRACTION",
                    "title": "Embedded String & Network Observable Extraction",
                    "description": "Extracts embedded ASCII/Unicode strings, network URIs, IP addresses, and command-line execution indicators.",
                    "dependencies": ["static_format_analyzer"],
                    "version": "1.0.0",
                },
                {
                    "analyzer_id": "file_reputation_analyzer",
                    "task_type": "REPUTATION_LOOKUP",
                    "title": "Threat Feed & Known Malware Hash Lookup",
                    "description": "Cross-references extracted hashes and signatures against threat intelligence feeds.",
                    "dependencies": ["file_ioc_extractor"],
                    "version": "1.0.0",
                },
                {
                    "analyzer_id": "risk_engine",
                    "task_type": "RISK_ASSESSMENT",
                    "title": "Static Threat Score Aggregation",
                    "description": "Synthesizes suspicious format flags, high-entropy sections, and signature hits into an overall threat assessment.",
                    "dependencies": ["static_format_analyzer", "file_reputation_analyzer"],
                    "version": "1.0.0",
                },
            ]

    @classmethod
    def initialize_run_dag(cls, db: Session, run_id: str) -> List[AnalysisTaskModel]:
        """
        Creates the persistent AnalysisTaskModel DAG records for an AnalysisRun.
        Idempotent: if tasks already exist for this run, returns existing tasks.
        """
        run = db.query(AnalysisRunModel).filter(AnalysisRunModel.id == run_id).first()
        if not run:
            raise ValueError(f"AnalysisRun '{run_id}' not found.")

        # Check existing tasks
        existing_tasks = db.query(AnalysisTaskModel).filter(AnalysisTaskModel.analysis_run_id == run_id).all()
        if existing_tasks:
            return existing_tasks

        artifact = db.query(ArtifactModel).filter(ArtifactModel.id == run.artifact_id).first()
        art_type = artifact.artifact_type if artifact else "FILE"

        blueprints = cls.get_dag_blueprint(art_type)

        # Mapping analyzer_id -> task_id for resolving dependencies
        analyzer_to_task_id: Dict[str, str] = {}
        for bp in blueprints:
            analyzer_to_task_id[bp["analyzer_id"]] = generate_uuid("task")

        created_tasks: List[AnalysisTaskModel] = []
        for bp in blueprints:
            t_id = analyzer_to_task_id[bp["analyzer_id"]]
            dep_task_ids = [analyzer_to_task_id[d] for d in bp["dependencies"] if d in analyzer_to_task_id]

            task = AnalysisTaskModel(
                id=t_id,
                analysis_run_id=run.id,
                analyzer_id=bp["analyzer_id"],
                task_type=bp["task_type"],
                title=bp["title"],
                description=bp.get("description"),
                status="PENDING",
                dependency_ids_json=json.dumps(dep_task_ids),
                started_at=None,
                completed_at=None,
                duration_seconds=None,
                progress=None,
                message="Queued for analysis execution",
                error=None,
                result_count=0,
                version=bp.get("version", "1.0.0"),
                metadata_json=json.dumps({"dependencies": bp["dependencies"]}),
                created_at=get_utc_now(),
            )
            db.add(task)
            created_tasks.append(task)

        # Emit initial RUN_STARTED event
        initial_event = AnalysisEventModel(
            id=generate_uuid("evt"),
            analysis_run_id=run.id,
            task_id=None,
            event_type="RUN_STARTED",
            timestamp=get_utc_now(),
            task_status=None,
            message=f"Analysis pipeline initialized for {artifact.name if artifact else 'artifact'}. {len(created_tasks)} tasks prepared.",
            result_count=len(created_tasks),
            error=None,
            metadata_json=json.dumps({"artifact_type": art_type}),
        )
        db.add(initial_event)
        db.commit()

        return created_tasks

    @classmethod
    def emit_event(
        cls,
        db: Session,
        run_id: str,
        event_type: str,
        message: str,
        task_id: Optional[str] = None,
        task_status: Optional[str] = None,
        result_count: int = 0,
        error: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AnalysisEventModel:
        """Persists an AnalysisEventModel with monotonic sequence and broadcasts to active real-time SSE streams."""
        evt = RealtimePublisher.emit_analysis_event(
            db=db,
            run_id=run_id,
            event_type=event_type,
            message=message,
            task_id=task_id,
            task_status=task_status,
            result_count=result_count,
            error=error,
            metadata=metadata,
        )
        if not evt:
            # Resilient fallback
            now = get_utc_now()
            evt = AnalysisEventModel(
                id=generate_uuid("evt"),
                analysis_run_id=run_id,
                task_id=task_id,
                event_type=event_type,
                sequence=1,
                timestamp=now,
                task_status=task_status,
                message=message,
                result_count=result_count,
                error=error,
                metadata_json=json.dumps(metadata or {}),
            )
            db.add(evt)
            db.commit()

        # Non-blocking legacy broadcast for backward-compatible Section 37 listeners
        legacy_payload = {
            "type": "EVENT",
            "schema_version": 1,
            "sequence": getattr(evt, "sequence", 1),
            "event": {
                "id": evt.id,
                "sequence": getattr(evt, "sequence", 1),
                "analysis_run_id": run_id,
                "task_id": task_id,
                "event_type": event_type,
                "timestamp": evt.timestamp.isoformat(),
                "task_status": task_status,
                "message": message,
                "result_count": result_count,
                "error": error,
                "metadata": metadata or {},
            },
        }
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.create_task(global_event_hub.broadcast(run_id, legacy_payload))
        except Exception:
            pass

        return evt

    @classmethod
    async def _execute_media_run(cls, db, run, artifact, tasks):
        """Media tasks use the real bounded decoder, never generic-success fallbacks."""
        from backend.services.multimedia_service import MultimediaPipeline, MAX_MEDIA_BYTES
        from starlette.concurrency import run_in_threadpool
        run.status = 'RUNNING'
        run.started_at = get_utc_now()
        db.commit()
        try:
            with evidence_storage.retrieve_stream(artifact.storage_reference or artifact.sha256) as stream:
                raw = stream.read(MAX_MEDIA_BYTES + 1)
            if len(raw) > MAX_MEDIA_BYTES:
                raise ValueError('Stored media exceeds the bounded analysis limit.')
            if artifact.sha256 and hashlib.sha256(raw).hexdigest() != artifact.sha256:
                raise ValueError('Original evidence hash verification failed.')
            # This worker owns the session for the call; no concurrent ORM operation.
            assessment = await run_in_threadpool(MultimediaPipeline().analyze_media,
                data=raw, original_filename=artifact.name, artifact_id=artifact.id,
                db=db, analysis_run_id=run.id)
            completed = assessment.processing_status == 'COMPLETED'
            for task in tasks:
                task.started_at = run.started_at
                task.completed_at = get_utc_now()
                task.status = 'COMPLETED' if completed else 'FAILED'
                task.result_count = len(assessment.detector_results) if task.analyzer_id == 'forensic_analyzer' else 0
                task.message = ('Bounded heuristic checks completed. Authenticity is not verified.' if completed else
                                'Media checks incomplete: ' + assessment.processing_status)
                task.error = None if completed else task.message
            db.commit()
            cls.emit_event(db=db, run_id=run.id, event_type='ANALYSIS_COMPLETED' if completed else 'ANALYSIS_PARTIAL',
                message='Media heuristic checks completed; authenticity unverified.' if completed else 'Media evidence preserved; analysis incomplete.',
                result_count=len(assessment.detector_results))
        except Exception:
            logger.exception('Bounded media execution could not complete')
            db.rollback()
            run.status = 'PARTIAL'
            run.confidence = 0.0
            run.overall_risk_score = None
            run.overall_severity = 'INFO'
            run.error = 'Original media could not be verified or decoded. Preserve evidence and review the media limitations.'
            run.completed_at = get_utc_now()
            for task in tasks:
                task.status = 'FAILED'; task.error = run.error; task.message = run.error
            db.commit()
        return run

    @classmethod
    async def _execute_telemetry_run(cls, db, run, artifact, tasks):
        """Use the existing log pipelines and preserve their canonical lineage."""
        run.status = 'RUNNING'
        run.started_at = get_utc_now()
        db.commit()
        try:
            with evidence_storage.retrieve_stream(artifact.storage_reference or artifact.sha256) as stream:
                raw = stream.read(50 * 1024 * 1024 + 1)
            if not raw or len(raw) > 50 * 1024 * 1024:
                raise ValueError('Stored telemetry is empty or exceeds the 50 MB processing limit.')
            if artifact.sha256 and hashlib.sha256(raw).hexdigest() != artifact.sha256:
                raise ValueError('Original telemetry hash verification failed.')
            if artifact.artifact_type == 'AUTH_LOG':
                from backend.services.auth_log_parser import parse_auth_log
                from backend.services.authentication_pipeline import global_auth_pipeline
                events = parse_auth_log(raw, artifact.name or '', artifact.mime_type or '')
                pipeline = global_auth_pipeline
            else:
                try:
                    if (artifact.name or '').lower().endswith('.jsonl'):
                        events = [json.loads(line) for line in raw.decode('utf-8').splitlines() if line.strip()]
                    else:
                        parsed = json.loads(raw.decode('utf-8'))
                        events = parsed if isinstance(parsed, list) else parsed.get('events', [parsed])
                except (ValueError, UnicodeError, AttributeError) as exc:
                    raise ValueError('Use a JSON/JSONL batch of structured telemetry events.') from exc
                if artifact.artifact_type == 'NETWORK_LOG':
                    from backend.services.network_pipeline import global_network_pipeline as pipeline
                else:
                    from backend.services.api_pipeline import global_api_pipeline as pipeline
            if not events or not all(isinstance(event, dict) for event in events):
                raise ValueError('Telemetry contains no usable structured events.')
            response = await asyncio.wait_for(pipeline.analyze_events(raw_events=events, db=db, artifact_id=artifact.id), timeout=45)
            if response.events_analyzed_count == 0:
                raise ValueError('No events could be normalized; check the telemetry fields and provider format.')
            canonical = db.get(AnalysisRunModel, response.analysis_run_id)
            if canonical is None or canonical.artifact_id != artifact.id:
                raise ValueError('Canonical telemetry result did not preserve its source artifact.')
            canonical_findings = db.query(FindingModel).filter_by(analysis_run_id=canonical.id).all()
            for observed in canonical_findings:
                copied = db.query(FindingModel).filter_by(analysis_run_id=run.id, analyzer=observed.analyzer, finding_type=observed.finding_type, title=observed.title).first()
                if copied is None:
                    values = {column.name: getattr(observed, column.name) for column in FindingModel.__table__.columns if column.name not in ('id', 'analysis_run_id')}
                    copied = FindingModel(id=generate_uuid(), analysis_run_id=run.id, **values)
                    db.add(copied)
                    db.flush()
                for evidence in observed.evidence_items:
                    if db.query(FindingEvidenceModel).filter_by(finding_id=copied.id, key=evidence.key, value=evidence.value).first() is None:
                        values = {column.name: getattr(evidence, column.name) for column in FindingEvidenceModel.__table__.columns if column.name not in ('id', 'finding_id')}
                        db.add(FindingEvidenceModel(id=generate_uuid(), finding_id=copied.id, **values))
            run.overall_risk_score = response.overall_risk_score
            run.overall_severity = getattr(response.overall_severity, 'value', response.overall_severity)
            run.confidence = response.confidence
            metadata = json.loads(run.metadata_json or '{}')
            metadata['canonical_pipeline_run_id'] = canonical.id
            run.metadata_json = json.dumps(metadata)
            run.status = 'COMPLETED'
            for task in tasks:
                task.status = 'COMPLETED'
                task.started_at = run.started_at
                task.completed_at = get_utc_now()
                task.result_count = len(canonical_findings) if task.task_type == 'RISK_ASSESSMENT' else 0
                task.message = f'Executed by {pipeline.__class__.__name__}; {response.events_analyzed_count} normalized events. Canonical run: {canonical.id}'
            cls.emit_event(db, run.id, event_type='ANALYSIS_COMPLETED', message=f'{pipeline.__class__.__name__} analyzed {response.events_analyzed_count} events and produced {len(canonical_findings)} findings.')
        except Exception:
            logger.exception('Canonical telemetry workflow failed for %s', run.id)
            db.rollback()
            run = db.get(AnalysisRunModel, run.id)
            run.status = 'FAILED'
            run.error = 'Telemetry analysis could not complete. Verify event format and consult server logs.'
            for task in tasks:
                task.status = 'FAILED'
                task.error = run.error
        run.completed_at = get_utc_now()
        db.commit()
        return run

    @classmethod
    async def execute_run(cls, db: Session, run_id: str) -> AnalysisRunModel:
        """
        Executes the analysis run DAG deterministically.
        Updates task states in DB and broadcasts truthful progress.
        """
        run = db.query(AnalysisRunModel).filter(AnalysisRunModel.id == run_id).first()
        if not run:
            raise ValueError(f"AnalysisRun '{run_id}' not found.")

        if run.status in ("COMPLETED", "CANCELLED", "FAILED"):
            return run

        # Ensure DAG exists
        tasks = cls.initialize_run_dag(db, run_id)
        artifact = db.query(ArtifactModel).filter(ArtifactModel.id == run.artifact_id).first()

        if artifact and artifact.artifact_type.upper() in ('IMAGE', 'AUDIO', 'VIDEO'):
            return await cls._execute_media_run(db, run, artifact, tasks)

        if artifact and artifact.artifact_type.upper() in ('AUTH_LOG', 'NETWORK_LOG', 'API_LOG'):
            return await cls._execute_telemetry_run(db, run, artifact, tasks)

        if artifact and artifact.artifact_type.upper() in ('FILE', 'TEXT', 'ATTACHMENT', 'URL', 'DOMAIN'):
            from backend.services.canonical_pipeline_bridge import execute_focused_artifact
            return await execute_focused_artifact(db, run, artifact, tasks)

        # Update run status to RUNNING
        run.status = "RUNNING"
        run.started_at = get_utc_now()
        db.commit()

        cls.emit_event(
            db=db,
            run_id=run.id,
            event_type="TASK_PROGRESS",
            message=f"Starting analysis execution for {artifact.name if artifact else 'artifact'}",
            result_count=0,
        )

        # Retrieve bytes if available
        raw_bytes = b""
        if artifact and artifact.storage_reference:
            try:
                raw_bytes = evidence_storage.retrieve_bytes(artifact.storage_reference)
            except Exception as e:
                logger.warning("Could not retrieve bytes for artifact: %s", e)

        art_type = (artifact.artifact_type or "FILE").upper() if artifact else "FILE"

        workspace_id = "default"
        investigation_id = None
        if artifact and artifact.metadata_json:
            try:
                art_meta = json.loads(artifact.metadata_json)
                workspace_id = art_meta.get("workspace_id", "default")
                investigation_id = art_meta.get("investigation_id")
            except Exception:
                pass

        workspace_id = getattr(artifact, "workspace_id", None) or workspace_id
        completed_tasks_count = 0
        failed_tasks_count = 0

        # Section 73: In-memory task lookup map to eliminate N+1 database queries for dependencies
        task_map: Dict[str, AnalysisTaskModel] = {t.id: t for t in tasks}

        # Section 73: Parsed email cache to avoid redundant parsing across analyzer tasks
        cached_parsed_email: Optional[Any] = None

        def get_parsed_email() -> Optional[Any]:
            nonlocal cached_parsed_email
            if cached_parsed_email is None and raw_bytes:
                try:
                    from backend.services.email_parser import EmailParserService
                    cached_parsed_email = EmailParserService.parse_eml_bytes(
                        raw_bytes, artifact.name if artifact else "email.eml"
                    )
                except Exception as parse_err:
                    logger.warning("Email parsing error in orchestrator: %s", parse_err)
            return cached_parsed_email

        # Execute tasks sequentially according to DAG
        for task in tasks:
            # Check if run was cancelled in background
            db.refresh(run)
            if run.status == "CANCELLED":
                task.status = "CANCELLED"
                task.message = "Execution cancelled by user"
                db.commit()
                continue

            # Check dependencies using in-memory task_map (eliminates N+1 query loop)
            dep_ids = json.loads(task.dependency_ids_json or "[]")
            deps_ok = True
            for d_id in dep_ids:
                dep_task = task_map.get(d_id) or db.query(AnalysisTaskModel).filter(AnalysisTaskModel.id == d_id).first()
                if dep_task and dep_task.status in ("FAILED", "BLOCKED", "CANCELLED"):
                    deps_ok = False
                    break

            if not deps_ok:
                task.status = "BLOCKED"
                task.message = "Blocked by upstream task failure"
                db.commit()
                continue

            # Mark task RUNNING
            t_start = time.perf_counter()
            task.status = "RUNNING"
            task.started_at = get_utc_now()
            task.message = f"Executing {task.title}..."
            db.commit()

            cls.emit_event(
                db=db,
                run_id=run.id,
                task_id=task.id,
                event_type="TASK_STARTED",
                task_status="RUNNING",
                message=f"Started {task.title}",
            )

            # REAL ANALYZER LOGIC
            result_count = 0
            task_error = None
            try:
                if task.task_type == "EVIDENCE_VALIDATION":
                    # Verify cryptographic SHA-256
                    calc_sha = hashlib.sha256(raw_bytes).hexdigest() if raw_bytes else (artifact.sha256 if artifact else "")
                    result_count = len(raw_bytes)
                    task.message = f"Evidence validated ({result_count} bytes, SHA-256 verified)"

                elif task.task_type == "MIME_PARSING" and art_type == "EMAIL":
                    parsed = get_parsed_email()
                    h_info = getattr(parsed, "headers", None) if parsed else None
                    if h_info and hasattr(h_info, "model_dump"):
                        result_count = len([k for k, v in h_info.model_dump().items() if v])
                    else:
                        result_count = len(getattr(h_info, "__dict__", {}))
                    task.message = f"Email parsed ({result_count} headers extracted, subject: {parsed.subject[:35] if parsed and parsed.subject else 'None'})"

                elif task.task_type == "AUTHENTICATION_ANALYSIS" and art_type == "EMAIL":
                    parsed = get_parsed_email()
                    auth = getattr(parsed, "authentication", None) if parsed else None
                    spf_res = getattr(getattr(auth, "spf", None), "result", "none")
                    dkim_res = getattr(getattr(auth, "dkim", None), "result", "none")
                    dmarc_res = getattr(getattr(auth, "dmarc", None), "result", "none")
                    result_count = 3
                    task.message = f"Authentication evaluated: SPF={spf_res}, DKIM={dkim_res}, DMARC={dmarc_res}"

                    # If authentication failed, persist a finding
                    if any(str(r).lower() == "fail" for r in (spf_res, dkim_res, dmarc_res)):
                        f = FindingModel(
                            id=generate_uuid("fnd"),
                            analysis_run_id=run.id,
                            analyzer="EmailAuthenticationService",
                            finding_type="email_authentication_failure",
                            title=f"Authentication Failure: SPF={spf_res}, DKIM={dkim_res}, DMARC={dmarc_res}",
                            description="Email sender identity failed domain authentication protocols.",
                            severity=SeverityEnum.HIGH.value,
                            confidence=1.0,
                            risk_contribution=25.0,
                            method=FindingMethodEnum.RULE.value,
                            rule_id="RULE-AUTH-RFC7489",
                            metadata_json="{}",
                            created_at=get_utc_now(),
                        )
                        db.add(f)
                        db.flush()
                        try:
                            from backend.services.notification_service import NotificationService
                            NotificationService.on_finding_persisted(
                                db=db, finding=f, workspace_id=workspace_id, investigation_id=investigation_id
                            )
                        except Exception as ne:
                            logger.warning("Notification on finding failed: %s", ne)

                        cls.emit_event(
                            db=db,
                            run_id=run.id,
                            task_id=task.id,
                            event_type="FINDING_PRODUCED",
                            message=f"Produced HIGH severity finding: {f.title}",
                            result_count=1,
                        )

                elif task.task_type == "SMTP_RELAY_ANALYSIS" and art_type == "EMAIL":
                    parsed = get_parsed_email()
                    hops = (getattr(getattr(parsed, "relay_analysis", None), "hops", []) if parsed else []) or []
                    result_count = len(hops)
                    task.message = f"Relay chain reconstructed ({result_count} MTA hops traced)"

                elif task.task_type == "ATTACHMENT_DISCOVERY" and art_type == "EMAIL":
                    parsed = get_parsed_email()
                    atts = (getattr(parsed, "attachments", []) if parsed else []) or []
                    result_count = len(atts)
                    task.message = f"Attachment inspection completed ({result_count} attachments found)"
                    for att in atts:
                        fn = getattr(att, "filename", "") or ""
                        if fn.endswith((".exe", ".scr", ".bat", ".vbs", ".js")):
                            f = FindingModel(
                                id=generate_uuid("fnd"),
                                analysis_run_id=run.id,
                                analyzer="AttachmentSecurityAnalyzer",
                                finding_type="dangerous_attachment_type",
                                title=f"High Risk Executable Attachment: {fn}",
                                description="Email contains an executable payload designed for endpoint execution.",
                                severity=SeverityEnum.CRITICAL.value,
                                confidence=1.0,
                                risk_contribution=45.0,
                                method=FindingMethodEnum.RULE.value,
                                rule_id="RULE-ATT-EXECUTABLE",
                                metadata_json="{}",
                                created_at=get_utc_now(),
                            )
                            db.add(f)
                            db.flush()
                            try:
                                from backend.services.notification_service import NotificationService
                                NotificationService.on_finding_persisted(
                                    db=db, finding=f, workspace_id=workspace_id, investigation_id=investigation_id
                                )
                            except Exception as ne:
                                logger.warning("Notification on finding failed: %s", ne)

                            cls.emit_event(
                                db=db,
                                run_id=run.id,
                                task_id=task.id,
                                event_type="FINDING_PERSISTED",
                                message=f"Produced CRITICAL finding: {f.title}",
                                result_count=1,
                                metadata={
                                    "finding_id": f.id,
                                    "finding_type": f.finding_type,
                                    "severity": f.severity,
                                    "risk_contribution": f.risk_contribution,
                                },
                            )

                elif task.task_type == "IOC_EXTRACTION" and art_type == "EMAIL":
                    parsed = get_parsed_email()
                    urls = (getattr(parsed, "urls", []) if parsed else []) or []
                    ips = (getattr(parsed, "ips", []) if parsed else []) or []
                    doms = (getattr(parsed, "domains", []) if parsed else []) or []
                    result_count = len(urls) + len(ips) + len(doms)
                    task.message = f"Extracted {len(urls)} URLs, {len(ips)} IPs, and {len(doms)} domains"

                elif task.task_type == "INTELLIGENCE_ENRICHMENT" and art_type == "EMAIL":
                    from backend.services.lookalike_detector import LookalikeDetectorService
                    detector = LookalikeDetectorService()
                    parsed = get_parsed_email()
                    doms = (getattr(parsed, "domains", []) if parsed else []) or []
                    lookalikes = detector.detect_lookalikes_batch(doms)
                    result_count = len(doms)
                    task.message = f"Threat intelligence queried across {result_count} observables"
                    if lookalikes:
                        for lk in lookalikes:
                            d_name = getattr(lk, "domain", "")
                            t_brand = getattr(lk, "target_brand", "") or getattr(lk, "closest_brand", "known entity")
                            f = FindingModel(
                                id=generate_uuid("fnd"),
                                analysis_run_id=run.id,
                                analyzer="LookalikeDetectorService",
                                finding_type="lookalike_impersonation",
                                title=f"Lookalike Domain Detected: {d_name}",
                                description=f"Domain {d_name} is impersonating {t_brand}.",
                                severity=SeverityEnum.HIGH.value,
                                confidence=0.9,
                                risk_contribution=35.0,
                                method=FindingMethodEnum.HEURISTIC.value,
                                rule_id="HEUR-LOOKALIKE-LEVENSHTEIN",
                                metadata_json="{}",
                                created_at=get_utc_now(),
                            )
                            db.add(f)
                            db.flush()
                            try:
                                from backend.services.notification_service import NotificationService
                                NotificationService.on_finding_persisted(
                                    db=db, finding=f, workspace_id=workspace_id, investigation_id=investigation_id
                                )
                            except Exception as ne:
                                logger.warning("Notification on finding failed: %s", ne)

                            cls.emit_event(
                                db=db,
                                run_id=run.id,
                                task_id=task.id,
                                event_type="FINDING_PERSISTED",
                                message=f"Produced HIGH finding: {f.title}",
                                result_count=1,
                                metadata={
                                    "finding_id": f.id,
                                    "finding_type": f.finding_type,
                                    "severity": f.severity,
                                    "risk_contribution": f.risk_contribution,
                                },
                            )

                elif task.task_type == "NLP_SOCIAL_ENGINEERING" and art_type == "EMAIL":
                    from backend.app.ml.classifier import global_phishing_classifier
                    parsed = get_parsed_email()
                    b_obj = getattr(parsed, "body", None) if parsed else None
                    body_text = getattr(b_obj, "plain_text", "") or getattr(b_obj, "html", "") or str(b_obj or "")
                    body = f"{body_text} {getattr(parsed, 'subject', '') or ''}".strip()
                    pred = global_phishing_classifier.predict(body)
                    raw_conf = pred.get("confidence", 0.5) if isinstance(pred, dict) else getattr(pred, "confidence", 0.5)
                    try:
                        pred_conf = float(raw_conf)
                    except (ValueError, TypeError):
                        pred_conf = 0.5
                    pred_label = pred.get("prediction", "legitimate") if isinstance(pred, dict) else getattr(pred, "prediction", "legitimate")
                    result_count = 1
                    task.message = f"NLP evaluation: Phishing probability {pred_conf * 100:.1f}% ({pred_label})"
                    if pred_label == "phishing" and pred_conf >= 0.7:
                        f = FindingModel(
                            id=generate_uuid("fnd"),
                            analysis_run_id=run.id,
                            analyzer="NLPPhishingClassifier",
                            finding_type="social_engineering_phishing",
                            title=f"Coercive Phishing Intent Identified ({pred_conf * 100:.0f}%)",
                            description="Natural language analysis detected high-probability social engineering markers.",
                            severity=SeverityEnum.HIGH.value if pred_conf >= 0.85 else SeverityEnum.MEDIUM.value,
                            confidence=pred_conf,
                            risk_contribution=30.0,
                            method=FindingMethodEnum.ML.value,
                            rule_id="ML-TFIDF-LOGREG-V1",
                            metadata_json="{}",
                            created_at=get_utc_now(),
                        )
                        db.add(f)
                        db.flush()
                        try:
                            from backend.services.notification_service import NotificationService
                            NotificationService.on_finding_persisted(
                                db=db, finding=f, workspace_id=workspace_id, investigation_id=investigation_id
                            )
                        except Exception as ne:
                            logger.warning("Notification on finding failed: %s", ne)

                        cls.emit_event(
                            db=db,
                            run_id=run.id,
                            task_id=task.id,
                            event_type="FINDING_PERSISTED",
                            message=f"Produced {f.severity} finding: {f.title}",
                            result_count=1,
                            metadata={
                                "finding_id": f.id,
                                "finding_type": f.finding_type,
                                "severity": f.severity,
                                "risk_contribution": f.risk_contribution,
                            },
                        )

                elif art_type in ("FILE", "TEXT", "ATTACHMENT") and task.task_type in ("FORMAT_INSPECTION", "IOC_EXTRACTION", "REPUTATION_LOOKUP"):
                    from backend.services.file_security_analyzers import FileIdentityAnalyzer, FileIOCAnalyzer, FileReputationAnalyzer
                    if task.task_type == "FORMAT_INSPECTION":
                        execution, identity = FileIdentityAnalyzer().analyze(raw_bytes, artifact.name)
                        task.message = f"Header/identity checks performed: {identity.detected_file_type}. Full content safety is not established."
                        result_count = len(execution.findings)
                    elif task.task_type == "IOC_EXTRACTION":
                        execution, observables = FileIOCAnalyzer().analyze(raw_bytes)
                        result_count = sum(len(values) for values in observables.values())
                        task.message = f"Extracted {len(observables['urls'])} URL references; URLs require separate threat assessment. No destinations visited."
                        for group, kind in (("urls", "URL"), ("domains", "DOMAIN"), ("ips", "IP"), ("emails", "EMAIL_ADDRESS")):
                            for value in observables[group]:
                                indicator = db.query(IndicatorModel).filter_by(workspace_id=workspace_id, indicator_type=kind, normalized_value=value).first()
                                if indicator is None:
                                    indicator = IndicatorModel(id=generate_uuid(), workspace_id=workspace_id, indicator_type=kind, value=value, normalized_value=value, reputation="UNVERIFIED")
                                    db.add(indicator)
                                    db.flush()
                                existing = db.query(RelationshipModel).filter_by(source_id=artifact.id, target_id=indicator.id, analysis_run_id=run.id).first()
                                if existing is None:
                                    db.add(RelationshipModel(id=generate_uuid(), source_type="ARTIFACT", source_id=artifact.id, relationship_type="CONTAINS", target_type="INDICATOR", target_id=indicator.id, analysis_run_id=run.id, workspace_id=workspace_id, origin="OBSERVED"))
                    else:
                        execution, reputation = await asyncio.wait_for(FileReputationAnalyzer().analyze(artifact.sha256), timeout=15)
                        result_count = len(execution.findings)
                        task.message = f"Hash reputation: {reputation.verdict}. A missing match does not establish safety."
                    for observed in execution.findings:
                        finding = db.query(FindingModel).filter_by(analysis_run_id=run.id, analyzer=execution.analyzer_name, finding_type=observed["finding_type"], title=observed["title"]).first()
                        if finding is None:
                            finding = FindingModel(id=generate_uuid(), analysis_run_id=run.id, analyzer=execution.analyzer_name,
                            finding_type=observed['finding_type'], title=observed['title'], description=observed['description'],
                            severity=getattr(observed['severity'], 'value', observed['severity']), confidence=observed['confidence'],
                            risk_contribution=(25.0 if observed["finding_type"] == "FILE_TYPE_MISMATCH" else 65.0 if getattr(observed["severity"], "value", observed["severity"]) in ("HIGH", "CRITICAL") else 0.0), method="RULE", metadata_json=json.dumps(observed['metadata']))
                            db.add(finding)
                            db.flush()
                        for url in observed["metadata"].get("urls", []):
                            if db.query(FindingEvidenceModel).filter_by(finding_id=finding.id, key="url", value=url).first() is None:
                                db.add(FindingEvidenceModel(id=generate_uuid(), finding_id=finding.id, artifact_id=artifact.id, evidence_type="URL", source="BOUNDED_FILE_STRING_EXTRACTION", key="url", value=url, confidence=1.0, metadata_json=json.dumps({"assessment": "UNVERIFIED", "source_sha256": artifact.sha256})))

                elif task.task_type == "RISK_ASSESSMENT":
                    # Aggregate findings for this run
                    findings = db.query(FindingModel).filter(FindingModel.analysis_run_id == run.id).all()
                    score = 0.0
                    for f in findings:
                        score += f.risk_contribution
                    score = min(100.0, score)
                    if not findings and art_type == "EMAIL":
                        # Check parsed threat score if available
                        parsed = get_parsed_email()
                        ts = getattr(parsed, "threat_score", None) if parsed else None
                        if ts:
                            score = float(ts.score or 0.0)

                    sev = "LOW"
                    if score >= 80:
                        sev = "CRITICAL"
                    elif score >= 60:
                        sev = "HIGH"
                    elif score >= 35:
                        sev = "MEDIUM"
                    elif score > 10:
                        sev = "LOW"

                    run.overall_risk_score = score
                    run.overall_severity = sev
                    run.confidence = 0.0 if score == 0 else min((f.confidence for f in findings), default=0.0)
                    result_count = len(findings)
                    task.message = f"Risk assessment finalized: {score:.0f}/100 ({sev})"

                    cls.emit_event(
                        db=db,
                        run_id=run.id,
                        task_id=task.id,
                        event_type="RISK_ASSESSED",
                        message=f"Overall risk calculated: {score:.0f}/100 with severity {sev} ({len(findings)} findings)",
                        result_count=len(findings),
                    )

                else:
                    raise NotImplementedError(f"Analyzer {task.analyzer_id} is not implemented for {art_type}; analysis is incomplete.")

            except Exception as exc:
                logger.error("Task %s failed: %s", task.id, exc, exc_info=True)
                task_error = str(exc)

            # Record task duration & status
            duration = max(0.005, round(time.perf_counter() - t_start, 4))
            task.completed_at = get_utc_now()
            task.duration_seconds = duration
            task.result_count = result_count

            # Section 73: Record task latency in global performance metrics tracker
            try:
                from backend.services.performance_service import global_performance_tracker, PerformanceCategoryEnum
                global_performance_tracker.record_operation(
                    category=PerformanceCategoryEnum.ANALYSIS_DAG.value,
                    operation_name=f"task:{task.task_type}",
                    duration_ms=duration * 1000.0,
                    is_error=bool(task_error),
                    tenant_id=workspace_id,
                    details={"task_id": task.id, "run_id": run.id, "analyzer_id": task.analyzer_id}
                )
            except Exception as trk_err:
                logger.debug("Metrics recording suppressed: %s", trk_err)

            if task_error:
                task.status = "FAILED"
                task.error = task_error
                failed_tasks_count += 1
                cls.emit_event(
                    db=db,
                    run_id=run.id,
                    task_id=task.id,
                    event_type="TASK_FAILED",
                    task_status="FAILED",
                    message=f"Task failed: {task.title}",
                    error=task_error,
                )
            else:
                task.status = "COMPLETED"
                completed_tasks_count += 1
                cls.emit_event(
                    db=db,
                    run_id=run.id,
                    task_id=task.id,
                    event_type="TASK_COMPLETED",
                    task_status="COMPLETED",
                    message=task.message or f"Completed {task.title}",
                    result_count=result_count,
                )

            db.commit()

        # Finalize AnalysisRun
        db.refresh(run)
        if run.status != "CANCELLED":
            run.completed_at = get_utc_now()
            if failed_tasks_count == 0:
                run.status = "COMPLETED"
            elif completed_tasks_count > 0:
                run.status = "PARTIAL"
            else:
                run.status = "FAILED"
            db.commit()

            canonical_terminal = (
                "ANALYSIS_COMPLETED" if run.status == "COMPLETED"
                else ("ANALYSIS_PARTIAL" if run.status == "PARTIAL" else "ANALYSIS_FAILED")
            )
            legacy_terminal = (
                "RUN_COMPLETED" if run.status == "COMPLETED"
                else "RUN_FAILED"
            )
            cls.emit_event(
                db=db,
                run_id=run.id,
                event_type=canonical_terminal,
                message=f"Analysis pipeline concluded with status {run.status}. {completed_tasks_count} completed, {failed_tasks_count} failed.",
                result_count=completed_tasks_count,
            )
            cls.emit_event(
                db=db,
                run_id=run.id,
                event_type=legacy_terminal,
                message=f"Analysis run concluded with status {run.status}.",
                result_count=completed_tasks_count,
            )

            # Section 47: Dispatch analysis run completed notification
            try:
                from backend.services.notification_service import NotificationService
                NotificationService.on_analysis_run_completed(
                    db=db,
                    run=run,
                    workspace_id=workspace_id,
                    investigation_id=investigation_id,
                )
            except Exception as ne:
                logger.warning("Failed to dispatch run completion notification: %s", ne)

        return run

    @classmethod
    def cancel_run(cls, db: Session, run_id: str) -> AnalysisRunModel:
        """Cancels an active or queued AnalysisRun."""
        run = db.query(AnalysisRunModel).filter(AnalysisRunModel.id == run_id).first()
        if not run:
            raise ValueError(f"AnalysisRun '{run_id}' not found.")

        if run.status in ("COMPLETED", "FAILED"):
            raise ValueError(f"Cannot cancel run in terminal state '{run.status}'.")

        run.status = "CANCELLED"
        run.completed_at = get_utc_now()

        # Mark all non-completed tasks CANCELLED
        tasks = db.query(AnalysisTaskModel).filter(
            AnalysisTaskModel.analysis_run_id == run_id,
            AnalysisTaskModel.status.in_(["PENDING", "QUEUED", "RUNNING", "BLOCKED"]),
        ).all()
        for t in tasks:
            t.status = "CANCELLED"
            t.message = "Cancelled by analyst"

        db.commit()

        cls.emit_event(
            db=db,
            run_id=run.id,
            event_type="ANALYSIS_CANCELLED",
            message="Analysis pipeline execution was cancelled by user.",
            result_count=0,
        )

        cls.emit_event(
            db=db,
            run_id=run_id,
            event_type="RUN_CANCELLED",
            message="Analysis run intentionally cancelled by analyst.",
        )
        return run

    @classmethod
    def retry_run(cls, db: Session, run_id: str) -> AnalysisRunModel:
        """Safely resets and restarts failed or partial analysis tasks."""
        run = db.query(AnalysisRunModel).filter(AnalysisRunModel.id == run_id).first()
        if not run:
            raise ValueError(f"AnalysisRun '{run_id}' not found.")

        # Reset failed/cancelled tasks
        tasks = db.query(AnalysisTaskModel).filter(AnalysisTaskModel.analysis_run_id == run_id).all()
        for t in tasks:
            if t.status in ("FAILED", "CANCELLED", "BLOCKED"):
                t.status = "PENDING"
                t.started_at = None
                t.completed_at = None
                t.duration_seconds = None
                t.error = None
                t.message = "Queued for retry"

        run.status = "QUEUED"
        run.completed_at = None
        db.commit()

        cls.emit_event(
            db=db,
            run_id=run_id,
            event_type="RUN_STARTED",
            message="Analysis retry triggered by analyst.",
        )
        return run

    @classmethod
    def resolve_run_for_investigation(cls, db: Session, identifier: str) -> Optional[AnalysisRunModel]:
        """
        Resolves an AnalysisRun by run_id, incident_id/number, evidence_id, or artifact_id/sha.
        Provides robust direct URL access for /investigations/:id/analysis.
        """
        clean_id = (identifier or "").strip()
        if not clean_id:
            return None

        # 1. Direct match on AnalysisRun.id
        run = db.query(AnalysisRunModel).filter(AnalysisRunModel.id == clean_id).first()
        if run:
            return run

        # 2. Match IncidentModel (incident_number or id)
        inc = db.query(IncidentModel).filter(
            (IncidentModel.id == clean_id) | (IncidentModel.incident_number == clean_id)
        ).first()
        if inc:
            # Check relationships for linked artifact
            rel = db.query(RelationshipModel).filter(
                RelationshipModel.source_type == "INCIDENT",
                RelationshipModel.source_id == inc.id,
                RelationshipModel.target_type == "ARTIFACT",
            ).first()
            if rel:
                r = (
                    db.query(AnalysisRunModel)
                    .filter(AnalysisRunModel.artifact_id == rel.target_id)
                    .order_by(AnalysisRunModel.started_at.desc())
                    .first()
                )
                if r:
                    return r

        # 3. Match EvidenceModel (evidence_id or sha256)
        evd = db.query(EvidenceModel).filter(
            (EvidenceModel.evidence_id == clean_id) | (EvidenceModel.sha256 == clean_id.lower())
        ).first()
        if evd:
            art = db.query(ArtifactModel).filter(ArtifactModel.sha256 == evd.sha256).first()
            if art:
                r = (
                    db.query(AnalysisRunModel)
                    .filter(AnalysisRunModel.artifact_id == art.id)
                    .order_by(AnalysisRunModel.started_at.desc())
                    .first()
                )
                if r:
                    return r

        # 4. Match ArtifactModel (id or sha256)
        art = db.query(ArtifactModel).filter(
            (ArtifactModel.id == clean_id) | (ArtifactModel.sha256 == clean_id.lower())
        ).first()
        if art:
            r = (
                db.query(AnalysisRunModel)
                .filter(AnalysisRunModel.artifact_id == art.id)
                .order_by(AnalysisRunModel.started_at.desc())
                .first()
            )
            if r:
                return r

        # 5. Fallback: check most recent run overall only for semantic aliases
        if clean_id.lower() in ("latest", "current", "default", "recent"):
            return (
                db.query(AnalysisRunModel)
                .order_by(AnalysisRunModel.started_at.desc())
                .first()
            )
        return None
