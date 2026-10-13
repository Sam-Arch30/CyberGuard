import asyncio
import json
import uuid
from pathlib import Path
from backend.db.session import SessionLocal
from backend.db.models import ArtifactModel, AnalysisRunModel, AnalysisTaskModel
from backend.services.universal_ingestion import UniversalIngestionService
from backend.services.analysis_orchestrator import AnalysisOrchestrator
from backend.services.analysis_results_aggregator import AnalysisResultsAggregator

SAMPLES = Path(__file__).resolve().parents[2] / 'samples'


def test_media_background_dag_executes_real_decoder_in_the_original_run():
    with SessionLocal() as db:
        result = UniversalIngestionService.ingest_file(db, (SAMPLES / '05-video/synthetic-color-bars.mp4').read_bytes(), 'presentation-video.mp4')
        run = asyncio.run(AnalysisOrchestrator.execute_run(db, result.analysis_run_id))
        assert run.id == result.analysis_run_id
        assert run.status == 'COMPLETED'
        metadata = json.loads(run.metadata_json)
        assert metadata['processing_status'] == 'COMPLETED'
        assert len(metadata['detector_results']) == 2
        assert metadata['metadata']['container_tags']['decoded_sample']['sampled_frame_count'] > 0
        assert run.confidence == 0
        assert db.query(AnalysisRunModel).filter_by(artifact_id=run.artifact_id).count() == 1
        assert all(task.status == 'COMPLETED' for task in db.query(AnalysisTaskModel).filter_by(analysis_run_id=run.id))
        projected = AnalysisResultsAggregator.get_results_for_run(db, run.id)
        assert projected.media_assessment['processing_status'] == 'COMPLETED'
        assert projected.risk.level == 'UNVERIFIED'
        assert projected.risk.confidence is None
        assert 'Archive' not in projected.next_step_recommendation.action_title


def test_invalid_media_dag_is_not_generic_success():
    with SessionLocal() as db:
        result = UniversalIngestionService.ingest_file(db, b'\x00\x00\x00\x18ftypisomTRUNCATED', 'invalid-media.mp4')
        run = asyncio.run(AnalysisOrchestrator.execute_run(db, result.analysis_run_id))
        assert run.status == 'PARTIAL'
        assert json.loads(run.metadata_json)['processing_status'] == 'INVALID_CONTENT'
        assert not any(task.status == 'COMPLETED' for task in db.query(AnalysisTaskModel).filter_by(analysis_run_id=run.id))
        projected = AnalysisResultsAggregator.get_results_for_run(db, run.id)
        assert projected.analysis_completeness == 'PARTIAL'
        assert projected.risk.score is None
        assert projected.risk.level != 'SAFE'
        assert projected.risk.confidence is None
        assert projected.why_cyberguard_thinks_this == []


def test_legacy_media_safe_claims_are_not_trusted_or_rewritten():
    with SessionLocal() as db:
        identifier = str(uuid.uuid4())
        artifact = ArtifactModel(id=identifier, artifact_type='VIDEO', name='old-video.mp4', source='UPLOAD', size=10)
        run = AnalysisRunModel(id=str(uuid.uuid4()), artifact_id=identifier, status='COMPLETED', overall_risk_score=0, overall_severity='SAFE', confidence=0.85)
        db.add_all([artifact, run]); db.commit()
        projected = AnalysisResultsAggregator.get_results_for_run(db, run.id)
        assert projected.status == 'PARTIAL'
        assert projected.risk.score is None and projected.risk.confidence is None
        assert projected.classification == 'Media authenticity not assessed'
        assert projected.why_cyberguard_thinks_this == []
        assert 'resolved' not in projected.next_step_recommendation.action_title.lower()
        db.refresh(run)
        assert run.status == 'COMPLETED' and run.confidence == 0.85
