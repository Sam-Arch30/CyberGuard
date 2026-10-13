"""Run collected corpus through actual APIs with isolated storage and truthful outcomes."""
import asyncio,csv,hashlib,html,io,json,mimetypes,os,sys,tempfile,time
from pathlib import Path
from collections import Counter
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'scripts'))
PACK=Path('C:/Users/bipin/Downloads/CyberGuard-Detection-Samples-2026-10-12')
OUT=Path(os.environ.get('CYBERGUARD_PACK_RESULTS_DIR',str(PACK/'test-results')));OUT.mkdir(exist_ok=True);(OUT/'responses').mkdir(exist_ok=True)
TEMP=Path(tempfile.mkdtemp(prefix='cyberguard-sample-audit-internet-'))
from sample_audit_runtime import configure,verify_unchanged
baseline=configure(TEMP)
os.environ['CYBERGUARD_DEEPFAKE_ENABLED']='true'
from backend.services.deepfake_model import MODEL_DIR
os.environ['CYBERGUARD_DEEPFAKE_MODEL_DIR']=str(MODEL_DIR)
from fastapi.testclient import TestClient
from backend.main import app
from backend.db.session import init_db,SessionLocal
from backend.services.analysis_orchestrator import AnalysisOrchestrator
init_db(max_retries=1)
manifest=json.loads((PACK/'manifest.json').read_text(encoding='utf-8'));entries=[];intakes={};selected={};snapshots={}
(OUT/'runtime.json').write_text(json.dumps({'test_root':str(TEMP),'scope':'Fresh temporary DB, original storage, EML, reports, benchmark and candidates. Actual API code; trained model enabled; no live backend requests.'},indent=2))
def score(data):
 if not isinstance(data,dict):return None
 for key in ['overall_risk_score','risk_score']:
  if key in data:return data[key]
 for key in ['threat_score','assessment','risk_assessment','file_risk','authentication_risk','media_assessment']:
  value=data.get(key)
  if isinstance(value,(float,int)):return value
  if isinstance(value,dict):
   for field in ['score','risk_score','overall_risk_score']:
    if field in value:return value[field]
 return None
def invoke(client,sample,stage,endpoint,body=None):
 started=time.perf_counter();data={};code=0;exception=''
 try:
  if body is None:
   path=PACK/sample;data_bytes=path.read_bytes()
   response=client.post(endpoint,files={'file':(path.name,data_bytes,mimetypes.guess_type(path.name)[0] or 'application/octet-stream')})
  else:response=client.post(endpoint,json=body)
  code=response.status_code
  try:data=response.json()
  except ValueError:data={'detail':response.text[:500]}
 except Exception as exc:exception=str(exc)[:500]
 assessment=data.get('assessment',{}) if isinstance(data,dict) else {};assessment=assessment if isinstance(assessment,dict) else {}
 finding_list=data.get('findings',assessment.get('supporting_findings',[])); finding_count=len(finding_list) if isinstance(finding_list,list) else 0
 verdict=data.get('classification',assessment.get('classification')); verdict=verdict if isinstance(verdict,str) else ''
 trained=assessment.get('trained_detector') or {}
 entry={'sample':sample,'stage':stage,'endpoint':endpoint,'http':code,'transport':'OK' if 200<=code<300 else 'REJECTED' if 400<=code<500 else 'ERROR','risk':score(data),'classification':verdict,'finding_count':finding_count,'processing_status':assessment.get('processing_status'),'trained_status':trained.get('status'),'trained_prediction':trained.get('prediction'),'deepfake_score':trained.get('deepfake_score'),'seconds':round(time.perf_counter()-started,3),'detail':exception or str(data.get('detail',''))[:500]}
 entries.append(entry);(OUT/'responses'/f'{len(entries):04d}.json').write_text(json.dumps(data,indent=2,default=str),encoding='utf-8')
 (OUT/'progress.json').write_text(json.dumps({'last':entry,'checks_completed':len(entries)},indent=2),encoding='utf-8')
 print(len(entries),stage,sample,code,entry['risk'],trained.get('prediction',''),flush=True)
 return data,entry

def capture_get(client,path):
 response=client.get(path)
 snapshots[path]={'status':response.status_code,'content_type':response.headers.get('content-type','application/json'),'body':response.text if 'application/json' in response.headers.get('content-type','') else None}
 return response

try:
 with TestClient(app,raise_server_exceptions=False) as client:
  # Every test input is preserved through intake, except documentation.
  for item in manifest:
   if item['category']=='documentation':continue
   sample=item['file'];p=PACK/sample
   try:actual=hashlib.sha256(p.read_bytes()).hexdigest()
   except OSError as exc:
    entries.append({'sample':sample,'stage':'Integrity','http':0,'transport':'UNAVAILABLE','detail':str(exc)});continue
   if actual!=item['sha256']:raise RuntimeError('Original sample hash changed: '+sample)
   data,entry=invoke(client,sample,'Intake','/api/ingest')
   if entry['transport']=='OK':intakes[sample]=data
  # Focused analyses. Raw unsupported provider formats are attempted and reported, not silently replaced.
  for item in manifest:
   sample=item['file'];category=item['category'];suffix=Path(sample).suffix.lower();local=item['kind']=='existing-local-synthetic'
   if category in ('documentation','urls','identity','media-image','media-video','media-audio'):continue
   if category=='phishing' or (local and '/01-email/' in sample):
    data,entry=invoke(client,sample,'Phishing','/api/emails/analyze')
    if entry['transport']=='OK':
     if sample in intakes:
      with SessionLocal() as db:asyncio.run(AnalysisOrchestrator.execute_run(db,intakes[sample]['analysis_run_id']))
      selected.setdefault('phishing',intakes[sample])
     report,r=invoke(client,sample,'Report','/api/reports/generate?format=json',body={'analysis':{'id':data.get('evidence_id') or data.get('id')},'analyst_name':'Isolated public sample test'})
     if r['transport']=='OK':
      download=client.get('/api/reports/'+report['id']+'/download')
      valid=download.status_code==200 and download.content.startswith(b'%PDF-')
      if valid:(OUT/(Path(sample).stem+'-report.pdf')).write_bytes(download.content)
      entries.append({'sample':sample,'stage':'PDF download','http':download.status_code,'transport':'OK' if valid else 'ERROR','detail':'PDF signature verified' if valid else 'Invalid report'})
      selected.setdefault('report',report)
   elif category=='authentication' or (local and any(x in sample for x in ['normal-auth.json','password-spray.json','authentication-events.jsonl','malformed.json'])):
    data,entry=invoke(client,sample,'Authentication','/api/auth-security/upload-log')
    if entry['transport']=='OK' and 'ready-to-upload/azure_ad' in sample:selected.setdefault('authentication',{'sample':sample,'response':data})
   elif category=='network' or (local and any(x in sample for x in ['network-connections.csv','sample-access.log'])):
    invoke(client,sample,'Network','/api/network-security/upload-log')
   elif local and 'api-events.json' in sample:invoke(client,sample,'API logs','/api/api-security/upload-log')
   elif local and ('/06-logs/' in sample or '/07-identity/' in sample):continue
   elif local and any(x in sample for x in ['/03-images/','/04-audio/','/05-video/','broken.mp4']):continue
   else:invoke(client,sample,'Static file','/api/files/analyze')
  # One reference per brand, with independently specified organizational domains.
  profile_ids={}
  for name,domain in [('Microsoft','microsoft.com'),('PayPal','paypal.com'),('Google','google.com'),('Apple','apple.com'),('Example Finance','example.test')]:
   data,e=invoke(client,'reference:'+name,'Create reference','/api/impersonation/profiles',body={'display_name':name,'trusted_domains':[domain],'trusted_sender_addresses':['finance@example.test'] if name=='Example Finance' else []})
   if e['transport']=='OK':profile_ids[name]=data['id']
  for item in manifest:
   if item['category']!='identity':continue
   claim=json.loads((PACK/item['file']).read_text());display,address=parseaddr(claim['from']);_,reply=parseaddr(claim['reply_to'])
   brand=next((name for name in profile_ids if name.lower() in (display+' '+claim['subject']).lower()),'Microsoft')
   body={'artifact_type':'EMAIL','target_identity_hint':profile_ids[brand],'email_data':{'from_address':address,'from_display_name':display,'reply_to_address':reply,'subject':claim['subject'],'body_text':''}}
   data,e=invoke(client,item['file'],'Identity','/api/impersonation/analyze',body=body)
   if e['transport']=='OK' and data.get('assessment',{}).get('risk_score',0)>0:selected.setdefault('identity',{'sample':item['file'],'request':body,'response':data})
  for label,sender,reply in [('trusted','finance@example.test','finance@example.test'),('suspicious','finance@lookalike-example.test','collector@untrusted.example')]:
   body={'artifact_type':'EMAIL','target_identity_hint':profile_ids['Example Finance'],'email_data':{'from_address':sender,'from_display_name':'Example Finance','reply_to_address':reply,'subject':'Meeting reminder' if label=='trusted' else 'Urgent payment approval','body_text':'Project meeting today.' if label=='trusted' else 'Send the wire immediately and keep it secret.'}}
   data,e=invoke(client,'local-identity-'+label,'Identity control','/api/impersonation/analyze',body=body)
   selected['identity_'+label]={'request':body,'response':data}
  # Actual media endpoint: record decoder/model limitations; normal verdicts remain quarantined.
  for item in manifest:
   sample=item['file'];category=item['category'];local=item['kind']=='existing-local-synthetic'
   is_media=category in ('media-image','media-video','media-audio') or (local and any(x in sample for x in ['/03-images/','/04-audio/','/05-video/','broken.mp4']))
   if not is_media or sample.endswith('.svg'):continue
   data,e=invoke(client,sample,'Media','/api/multimedia/upload')
   if e['transport']=='OK' and e.get('trained_status')=='COMPLETED':
    if item['label'] in ('FAKE','PUBLISHER_DEEPFAKE') and e.get('trained_prediction')=='DEEPFAKE_LIKELY':selected.setdefault('media_fake',{'sample':sample,'response':data,'intake':intakes.get(sample)})
    if item['label'] in ('REAL','REAL_PUBLIC_NASA_PHOTO') and e.get('trained_prediction')=='REAL_LIKELY':selected.setdefault('media_real',{'sample':sample,'response':data,'intake':intakes.get(sample)})
  # Passive URL analysis: no HTTP inspection of phishing destinations.
  feed=PACK/'09-url-indicators/openphish-50-defanged.txt'
  for i,line in enumerate(feed.read_text().splitlines()):
   restored=line.replace('hxxps://','https://').replace('hxxp://','http://').replace('[.]','.')
   invoke(client,f'OpenPhish indicator {i+1}','Passive URL','/api/urls/analyze',body={'url':restored,'active_analysis_enabled':False})
  # Store actual GET responses for a read-only presentation snapshot of this real run.
  for path in ['/api/dashboard/summary','/api/dashboard/overview','/api/alerts','/api/alerts/metrics','/api/reports','/api/impersonation/profiles','/api/jobs','/api/health','/api/dashboard/emails','/api/investigations']:
   capture_get(client,path)
  for group in ['phishing','media_fake','media_real']:
   record=selected.get(group,{});intake=record.get('intake') if group.startswith('media') else record
   if not intake:continue
   iid=intake.get('investigation_id')
   if not iid:continue
   for ending in ['summary','analysis/results','evidence','timeline','notes','report','reports']:
    capture_get(client,f'/api/investigations/{iid}/{ending}')
  if selected.get('report'):
   rid=selected['report']['id']
   for ending in ['', '/json']:capture_get(client,f'/api/reports/{rid}{ending}')
 (OUT/'selected-scenes.json').write_text(json.dumps(selected,indent=2,default=str),encoding='utf-8')
 (OUT/'api-snapshot.json').write_text(json.dumps(snapshots,indent=2),encoding='utf-8')
finally:
 (OUT/'results.json').write_text(json.dumps({'scope':'Actual synchronous API calls in a fresh temporary workspace. External LLM/threat intelligence disabled. Passive URL DNS/registration lookups may use network; active phishing-site HTTP disabled.','test_root':str(TEMP),'results':entries},indent=2,default=str),encoding='utf-8')
 verify_unchanged(baseline)
 print('LIVE_INTEGRITY_VERIFIED',flush=True)
print('DONE',len(entries),'checks',str(OUT),flush=True)
