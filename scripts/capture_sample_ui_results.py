"""Capture actual database projections and real UI-contract calls, not invented detections."""
import json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'scripts'))
PACK=Path('C:/Users/bipin/Downloads/CyberGuard-Detection-Samples-2026-10-12');OUT=PACK/'test-results'
from sample_audit_runtime import configure,verify_unchanged
runtime=json.loads((OUT/'runtime.json').read_text());baseline=configure(Path(runtime['test_root']))
from fastapi.testclient import TestClient
from backend.main import app
from backend.db.session import SessionLocal
from backend.db.models import ArtifactModel,AnalysisRunModel,RelationshipModel
snapshots={};post=[];scenes={}
def get(client,path):
 r=client.get(path);snapshots[path]={'status':r.status_code,'content_type':r.headers.get('content-type','application/json'),'body':r.text};return r
with TestClient(app,raise_server_exceptions=False) as client:
 with SessionLocal() as db:
  artifacts=db.query(ArtifactModel).all()
  candidates=[]
  for a in artifacts:
   for run in db.query(AnalysisRunModel).filter(AnalysisRunModel.artifact_id==a.id).all():
    try:metadata=json.loads(run.metadata_json or '{}')
    except ValueError:continue
    trained=metadata.get('trained_detector') or {}
    if trained.get('status')=='COMPLETED':candidates.append((a,run,trained))
  fake=next((item for item in candidates if 'hemg-row-' in item[0].name and int(item[0].name.split('hemg-row-')[1].split('.')[0])<100000 and item[2].get('prediction')=='DEEPFAKE_LIKELY'),None)
  real=next((item for item in candidates if 'hemg-row-100' in item[0].name and item[2].get('prediction')=='REAL_LIKELY'),None)
  false_positive=next((item for item in candidates if 'hemg-row-100' in item[0].name and item[2].get('prediction')=='DEEPFAKE_LIKELY'),None)
  phishing=next((a for a in artifacts if a.name=='lab-2.eml'),None)
  selected=[('phishing',phishing,None)]
  selected += [(name,item[0],item[1]) for name,item in [('media_fake',fake),('media_real',real),('media_false_positive',false_positive)] if item is not None]
  for group,artifact,run in selected:
   if not artifact:continue
   relationship=db.query(RelationshipModel).filter(RelationshipModel.target_type=='ARTIFACT',RelationshipModel.target_id==artifact.id,RelationshipModel.source_type=='INCIDENT').first()
   if not relationship and group.startswith('media'):
    for peer in db.query(ArtifactModel).filter(ArtifactModel.sha256==artifact.sha256).all():
     rel=db.query(RelationshipModel).filter(RelationshipModel.target_type=='ARTIFACT',RelationshipModel.target_id==peer.id,RelationshipModel.source_type=='INCIDENT').first()
     if rel:
      actual=client.post('/api/multimedia/analyze',json={'artifact_id':peer.id})
      if actual.status_code!=200:raise RuntimeError(actual.text)
      post.append({'path':'/api/multimedia/analyze','request':{'artifact_id':peer.id},'status':actual.status_code,'response':actual.json()})
      artifact=peer;relationship=rel;break
   if not relationship:continue
   iid=relationship.source_id;scenes[group]={'investigation_id':iid,'artifact_id':artifact.id,'name':artifact.name,'run_id':run.id if run else None}
   for ending in ['summary','analysis','analysis/results','evidence','timeline','notes','report','reports']:
    response=get(client,f'/api/investigations/{iid}/{ending}')
    if ending=='analysis/results' and response.status_code==200:
     data=response.json();scenes[group]['results']=data
     rid=data.get('run_id')
     if rid:
      get(client,f'/api/analysis/{rid}');get(client,f'/api/analysis/{rid}/results')
   get(client,f'/api/emails/{iid}/analysis')
 for path in ['/api/dashboard/summary','/api/dashboard/overview','/api/alerts','/api/alerts/metrics','/api/reports','/api/impersonation/profiles','/api/jobs','/api/health','/api/dashboard/emails','/api/investigations']:
  get(client,path)
 reports=client.get('/api/reports').json().get('reports',[])
 for report in reports:
  rid=report['id'];get(client,f'/api/reports/{rid}');get(client,f'/api/reports/{rid}/json')
 if reports:scenes['report']={'id':reports[0]['id']}
 # These are actual batch API calls using the corrected frontend contract.
 for name,path in [('public_auth',PACK/'03-account-access/ready-to-upload/azure_ad_distributed_spray.json'),('password_spray',PACK/'10-local-controls/06-logs/password-spray.json'),('normal_auth',PACK/'10-local-controls/06-logs/normal-auth.json')]:
  payload={'events':json.loads(path.read_text()),'provider_hint':'generic'}
  r=client.post('/api/auth-security/analyze-batch',json=payload)
  post.append({'path':'/api/auth-security/analyze-batch','request':payload,'status':r.status_code,'response':r.json()});scenes[name]={'file':str(path),'request':payload,'response':r.json(),'http':r.status_code}
 profiles=client.get('/api/impersonation/profiles').json();profile=next((p for p in profiles if p['display_name']=='Example Finance'),None)
 if profile:
  payload={'artifact_type':'EMAIL','target_identity_hint':profile['id'],'email_data':{'from_address':'finance@lookalike-example.test','from_display_name':'Example Finance','reply_to_address':'collector@untrusted.example','subject':'Urgent payment approval','body_text':'Send the wire immediately and keep it secret.'}}
  r=client.post('/api/impersonation/analyze',json=payload);post.append({'path':'/api/impersonation/analyze','request':payload,'status':r.status_code,'response':r.json()});scenes['identity']={'request':payload,'response':r.json()}
(OUT/'ui-api-snapshot.json').write_text(json.dumps(snapshots,indent=2),encoding='utf-8');(OUT/'ui-post-snapshot.json').write_text(json.dumps(post,indent=2),encoding='utf-8');(OUT/'ui-scenes.json').write_text(json.dumps(scenes,indent=2),encoding='utf-8')
verify_unchanged(baseline)
print('Actual snapshot scenes:',list(scenes));print('GET snapshots:',len(snapshots),'Exact recorded POST cases:',len(post))
