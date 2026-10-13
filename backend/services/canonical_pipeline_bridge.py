"""Connect evidence-intake runs to implemented focused pipelines without deleting history."""
import asyncio
import hashlib
import json
import logging
from backend.db.models import AnalysisRunModel, ArtifactModel, FindingModel, FindingEvidenceModel, generate_uuid, get_utc_now
from backend.services.evidence_storage import evidence_storage

logger = logging.getLogger(__name__)

async def execute_focused_artifact(db, parent, artifact, tasks):
    parent.status = 'RUNNING'
    parent.started_at = get_utc_now()
    db.commit()
    try:
        with evidence_storage.retrieve_stream(artifact.storage_reference or artifact.sha256) as stream:
            raw = stream.read(50 * 1024 * 1024 + 1)
        if not raw or len(raw) > 50 * 1024 * 1024 or hashlib.sha256(raw).hexdigest() != artifact.sha256:
            raise ValueError('Evidence is empty, oversized or failed hash verification.')
        if artifact.artifact_type in ('URL', 'DOMAIN'):
            from backend.services.url_domain_pipeline import URLDomainIntelligencePipeline
            result = await asyncio.wait_for(URLDomainIntelligencePipeline().analyze_artifact(artifact.id, db, active_analysis_enabled=False), timeout=45)
            canonical_id = result['analysis_run_id']
        else:
            from backend.services.file_security_pipeline import FileSecurityPipeline
            result = await asyncio.wait_for(FileSecurityPipeline().reanalyze_artifact(artifact.id, db), timeout=45)
            canonical_id = result.analysis_run_id
        canonical = db.get(AnalysisRunModel, canonical_id)
        source = db.get(ArtifactModel, canonical.artifact_id) if canonical else None
        if source is None or source.sha256 != artifact.sha256 or source.workspace_id != artifact.workspace_id:
            raise ValueError('Focused result did not preserve original evidence identity and workspace.')
        findings = db.query(FindingModel).filter_by(analysis_run_id=canonical.id).all()
        for observed in findings:
            copied = db.query(FindingModel).filter_by(analysis_run_id=parent.id, analyzer=observed.analyzer, finding_type=observed.finding_type, title=observed.title).first()
            if copied is None:
                values = {column.name: getattr(observed, column.name) for column in FindingModel.__table__.columns if column.name not in ('id', 'analysis_run_id')}
                copied = FindingModel(id=generate_uuid(), analysis_run_id=parent.id, **values)
                db.add(copied); db.flush()
            for evidence in observed.evidence_items:
                if db.query(FindingEvidenceModel).filter_by(finding_id=copied.id, key=evidence.key, value=evidence.value).first() is None:
                    values = {column.name: getattr(evidence, column.name) for column in FindingEvidenceModel.__table__.columns if column.name not in ('id', 'finding_id')}
                    db.add(FindingEvidenceModel(id=generate_uuid(), finding_id=copied.id, **values))
        parent.overall_risk_score = canonical.overall_risk_score
        parent.overall_severity = canonical.overall_severity
        parent.confidence = canonical.confidence
        metadata = json.loads(parent.metadata_json or '{}')
        metadata['canonical_pipeline_run_id'] = canonical.id
        metadata['focused_pipeline_result'] = result if isinstance(result, dict) else result.model_dump(mode='json')
        parent.metadata_json = json.dumps(metadata)
        parent.status = 'COMPLETED'
        for task in tasks:
            task.status = 'COMPLETED'
            task.started_at = parent.started_at
            task.completed_at = get_utc_now()
            task.result_count = len(findings) if task.task_type == 'RISK_ASSESSMENT' else 0
            task.message = f'Executed by focused pipeline; canonical run {canonical.id}. Detailed observations are available in results.'
    except Exception:
        logger.exception('Focused artifact analysis failed')
        db.rollback()
        parent = db.get(AnalysisRunModel, parent.id)
        parent.status = 'FAILED'
        parent.error = 'Analysis could not complete. Verify input format and consult server logs.'
        for task in tasks:
            task.status = 'FAILED'; task.error = parent.error
    parent.completed_at = get_utc_now()
    db.commit()
    return parent
