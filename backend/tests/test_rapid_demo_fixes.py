import io,json,hashlib
from fastapi.testclient import TestClient
from backend.main import app
from backend.services.impersonation_service import IdentityComparisonService
from backend.schemas.impersonation import ProtectedIdentityProfile,ComparisonOutcomeEnum
client=TestClient(app)

def test_empty_and_truncated_pdf_do_not_receive_safe_verdicts():
    for name,payload,mime in [('empty.txt',b'','text/plain'),('broken.pdf',b'%PDF-1.7\ntruncated','application/pdf')]:
        response=client.post('/api/files/analyze',files={'file':(name,payload,mime)})
        assert response.status_code in (400,422)
        assert 'empty' in response.json()['detail'].lower() or 'truncated' in response.json()['detail'].lower()

def test_image_disguised_as_pdf_has_actual_mismatch_finding():
    from PIL import Image
    buffer=io.BytesIO();Image.new('RGB',(32,32),'white').save(buffer,'JPEG')
    response=client.post('/api/files/analyze',files={'file':('invoice.pdf',buffer.getvalue(),'application/pdf')})
    assert response.status_code==200
    result=response.json()
    assert any(f['finding_type']=='FILE_TYPE_MISMATCH' for f in result['findings'])
    assert result['risk_score']>=25
    assert result['classification']=='SUSPICIOUS'

def test_brand_role_suffixes_and_boundary_negative_control():
    profile=ProtectedIdentityProfile(id='test-ms',display_name='Microsoft',trusted_domains=['microsoft.com'])
    compare=IdentityComparisonService()
    assert compare.compare_name('Microsoft Account Team',profile)[0]==ComparisonOutcomeEnum.PARTIAL_MATCH
    assert compare.compare_name('NotMicrosoft Account Team',profile)[0]==ComparisonOutcomeEnum.MISMATCH
    profile.display_name='PayPal'
    assert compare.compare_name('PayPal Billing Department',profile)[0]==ComparisonOutcomeEnum.PARTIAL_MATCH

def test_unvalidated_model_withheld_without_research_mode(monkeypatch,tmp_path):
    import backend.services.deepfake_detector as detector
    payload=b'fixture';(tmp_path/'config.json').write_bytes(payload)
    monkeypatch.setattr(detector,'HASHES',{'config.json':hashlib.sha256(payload).hexdigest()})
    monkeypatch.setenv('CYBERGUARD_DEEPFAKE_ENABLED','true')
    monkeypatch.setenv('CYBERGUARD_DEEPFAKE_MODEL_DIR',str(tmp_path))
    monkeypatch.setenv('CYBERGUARD_DEEPFAKE_RESEARCH_MODE','false')
    result=detector.predict_faces(b'input','IMAGE',[])
    assert result['status']=='MODEL_NOT_VALIDATED'
    assert 'prediction' not in result and 'deepfake_score' not in result

def test_email_projection_does_not_invent_age_or_tls_counterevidence():
    from backend.services.analysis_results_aggregator import AnalysisResultsAggregator
    from backend.db.models import ArtifactModel,AnalysisRunModel
    artifact=ArtifactModel(id='unverified-email',artifact_type='EMAIL',name='test.eml')
    run=AnalysisRunModel(id='unverified-run',artifact_id=artifact.id)
    assert AnalysisResultsAggregator._build_counter_evidence([],run,artifact)==[]
