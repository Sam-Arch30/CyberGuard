"""Provenance boundary for complete, ingested analysis results."""
import json
from fastapi import HTTPException
from sqlalchemy import or_
from backend.db.models import AnalysisPayloadModel, EmailAnalysisModel


def reject_demo(data):
    if not isinstance(data, dict):
        return
    if data.get('is_demo') or data.get('is_synthetic') or str(data.get('id', '')).startswith('scenario-'):
        raise HTTPException(422, 'Synthetic demo evidence cannot enter production investigations.')


def load_analysis(db, identifier):
    row = db.query(AnalysisPayloadModel).filter(AnalysisPayloadModel.evidence_id == identifier).first()
    if not row:
        query = db.query(EmailAnalysisModel)
        if identifier == 'latest':
            record = query.order_by(EmailAnalysisModel.analyzed_at.desc()).first()
        else:
            record = query.filter(or_(EmailAnalysisModel.id == identifier,
                EmailAnalysisModel.evidence_id == identifier, EmailAnalysisModel.email_sha256 == identifier)).first()
        if record:
            row = db.get(AnalysisPayloadModel, record.evidence_id)
    if not row:
        raise HTTPException(404, 'No stored full analysis available for this email. Legacy summary records cannot reconstruct forensic findings.')
    return json.loads(row.analysis_json)


def require_stored_analysis(db, payload):
    reject_demo(payload)
    return load_analysis(db, payload.get('evidence_id') or payload.get('id') or payload.get('email_sha256') or '')
