"""Exercise the sample pack without adding test evidence to the live workspace."""
import os, tempfile, sqlite3, json, time, mimetypes, csv, io, html, sys
from pathlib import Path
from collections import Counter
from datetime import datetime, timezone, timedelta
AUDIT_DATE = datetime.now(timezone(timedelta(hours=5, minutes=30))).date().isoformat()
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
TEMP=Path(tempfile.mkdtemp(prefix='cyberguard-sample-audit-'))
OUTPUT=ROOT/'samples/test-results';OUTPUT.mkdir(exist_ok=True)
source=sqlite3.connect('file:'+str(ROOT/'backend/data/mailtrace.db')+'?mode=ro',uri=True)
target=sqlite3.connect(str(TEMP/'test.db'));source.backup(target);target.close();source.close()
from sample_audit_runtime import configure, verify_unchanged
LIVE_BASELINE=configure(TEMP)
from fastapi.testclient import TestClient
from backend.main import app
from backend.db.session import init_db
init_db(max_retries=1)
manifest=json.loads((ROOT/'samples/manifest.json').read_text())
results=[];email_results={}

def risk(data):
    if not isinstance(data,dict):return None
    value=data.get('overall_risk_score',data.get('risk_score'))
    if value is not None:return value
    for key in ['threat_score','assessment','risk_assessment','file_risk','authentication_risk','media_assessment']:
        nested=data.get(key)
        if isinstance(nested,dict):
            value=nested.get('score',nested.get('risk_score'))
            if value is not None:return value
    return None

def run(client,sample,stage,endpoint,*,body=None,expected_rejection=False):
    start=time.perf_counter()
    path=ROOT/'samples'/sample
    try:
        if body is None:
            response=client.post(endpoint,files={'file':(path.name,path.read_bytes(),mimetypes.guess_type(path.name)[0] or 'application/octet-stream')})
        else:response=client.post(endpoint,json=body)
        try:data=response.json()
        except Exception:data={}
        ok=400<=response.status_code<500 if expected_rejection else 200<=response.status_code<300
        status='PASS' if ok else 'FAIL'
        note=''
        if expected_rejection and response.status_code==200:status='FAIL';note='Malformed content accepted; expected explicit validation failure.'
        if response.status_code>=400:note=str(data.get('detail',response.text[:250]))
        if stage=='Ingestion' and response.status_code==200:
            note=str(data.get('classification',{}).get('support_status',''))
            if sample.startswith('10-invalid/') and not expected_rejection:
                status='WARN' if data.get('warnings') else 'FAIL'
                note='Invalid original evidence retained. '+ '; '.join(data.get('warnings', []))
        assessment=data.get('assessment',{}) if isinstance(data,dict) else {}
        verdict=data.get('classification') if isinstance(data.get('classification'),str) else assessment.get('classification','')
        if stage=='Media analysis' and response.status_code==200:
            note=assessment.get('processing_status','MISSING_STATUS')+'; heuristic assessment only; deepfake accuracy is not established.'
            if assessment.get('processing_status') != 'COMPLETED': status='WARN'
        entry={'sample':sample,'stage':stage,'endpoint':endpoint,'http':response.status_code,'status':status,'risk':risk(data),'classification':verdict,'seconds':round(time.perf_counter()-start,3),'note':note}
        results.append(entry)
        (OUTPUT/(str(len(results)).zfill(3)+'-response.json')).write_text(json.dumps(data,indent=2,default=str),encoding='utf-8')
        print(stage,sample,response.status_code,status,flush=True)
        return data,response
    except Exception as error:
        results.append({'sample':sample,'stage':stage,'endpoint':endpoint,'http':0,'status':'FAIL','risk':None,'classification':'','seconds':round(time.perf_counter()-start,3),'note':str(error)[:250]})
        return {},None

with TestClient(app,raise_server_exceptions=False) as client:
    for item in manifest:
        sample=item['file']
        run(client,sample,'Ingestion','/api/ingest',expected_rejection=sample=='10-invalid/empty.txt')
    for item in manifest:
        sample=item['file'];folder=sample.split('/')[0]
        if folder=='01-email':
            data,response=run(client,sample,'Email analysis','/api/emails/analyze')
            if response is not None and response.status_code==200:email_results[sample]=data
        elif folder in ('03-images','04-audio','05-video') and not sample.endswith('.svg'):
            run(client,sample,'Media analysis','/api/multimedia/upload')
        elif folder in ('02-documents','08-archives','09-binary') or sample.endswith('.svg'):
            run(client,sample,'File analysis','/api/files/analyze')
    for sample in ['06-logs/normal-auth.json','06-logs/password-spray.json','06-logs/authentication-events.jsonl']:
        run(client,sample,'Authentication analysis','/api/auth-security/upload-log')
    run(client,'06-logs/network-connections.csv','Network analysis','/api/network-security/upload-log')
    run(client,'06-logs/api-events.json','API analysis','/api/api-security/upload-log')
    run(client,'10-invalid/malformed.json','Invalid JSON validation','/api/auth-security/upload-log',expected_rejection=True)
    run(client,'10-invalid/broken.mp4','Invalid video analysis','/api/multimedia/upload',expected_rejection=True)
    profile,response=run(client,'07-identity/trusted-profile.json','Profile creation','/api/impersonation/profiles',body=json.loads((ROOT/'samples/07-identity/trusted-profile.json').read_text()))
    if response is not None and response.status_code==201:
        for label,sender,reply in [('Trusted identity','finance@example.test','finance@example.test'),('Suspicious identity','finance@lookalike-example.test','collector@untrusted.example')]:
            run(client,'07-identity/identity-claim.txt',label,'/api/impersonation/analyze',body={'artifact_type':'EMAIL','target_identity_hint':profile['id'],'email_data':{'from_address':sender,'from_display_name':'Example Finance','reply_to_address':reply,'subject':'Urgent payment approval' if label.startswith('Suspicious') else 'Meeting reminder','body_text':'Send the wire immediately and keep it secret.' if label.startswith('Suspicious') else 'Project meeting today.'}})
    for sample,data in email_results.items():
        identifier=data.get('evidence_id') or data.get('id')
        metadata,response=run(client,sample,'Report generation','/api/reports/generate?format=json',body={'analysis':{'id':identifier},'analyst_name':'Synthetic sample audit'})
        if response is not None and response.status_code==200 and metadata.get('id'):
            started=time.perf_counter();download=client.get('/api/reports/'+metadata['id']+'/download');valid=download.status_code==200 and download.content.startswith(b'%PDF-') and len(download.content)>500
            results.append({'sample':sample,'stage':'Report download','endpoint':'/api/reports/{id}/download','http':download.status_code,'status':'PASS' if valid else 'FAIL','risk':None,'classification':'','seconds':round(time.perf_counter()-started,3),'note':'Valid PDF header and nonempty download' if valid else 'Invalid/missing PDF'})
            if valid:(OUTPUT/(Path(sample).stem+'-report.pdf')).write_bytes(download.content)
counts=Counter(row['status'] for row in results)
summary={'date':AUDIT_DATE,'sample_files':len(manifest),'checks':len(results),'counts':{key:counts[key] for key in ('PASS','WARN','FAIL')},'test_root':str(TEMP),'scope':'Real local API code against an isolated database copy; external enrichment disabled; background worker disabled; no browser interaction or real-world accuracy validation.','results':results}
(OUTPUT/'results.json').write_text(json.dumps(summary,indent=2),encoding='utf-8')
stream=io.StringIO();writer=csv.DictWriter(stream,fieldnames=list(results[0]));writer.writeheader();writer.writerows(results);(OUTPUT/'results.csv').write_text(stream.getvalue(),encoding='utf-8')
lines=['# CyberGuard sample test report','', 'Date: '+AUDIT_DATE,'',f"Tested **{len(manifest)} files** with **{len(results)} checks**: **{counts['PASS']} PASS**, **{counts['WARN']} WARN**, **{counts['FAIL']} FAIL**.",'','## Verdict','', 'Core functions were exercised through actual API routes. See failures and warnings below before declaring the prototype fully working. Upload acceptance does not establish correct detection or successful media decoding.','', '## Scope','',summary['scope'],'','No test requests were sent to the live backend and all test storage paths were temporary. The live database was opened read-only for copying.','', '## Results','', '| Sample | Check | HTTP | Result | Risk | Detail |','| --- | --- | --- | --- | --- | --- |']
for row in results:lines.append('| '+ ' | '.join(str(row[key] if row[key] is not None else 'â€”').replace('|','/').replace('\n',' ') for key in ['sample','stage','http','status','risk','note'])+' |')
lines += ['', '## Important limitations','', '- Benign/suspicious sample risk scores are observed outputs, not assumed correct labels.','- Images contain no real faces; audio contains tones; videos contain color bars. These cannot validate deepfake accuracy.','- Background job execution and browser interactions are not validated by synchronous route checks.','- External intelligence and LLM integrations were disabled to avoid network dependency or accidental usage.','- Intentionally invalid samples should produce clear rejection or limitations, not HTTP 500.','- Report downloads were checked for status, PDF signature and size; visual report layout requires a separate review.']
(OUTPUT/'report.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
print('SUMMARY',dict(counts),'checks',len(results),'report',OUTPUT/'report.md',flush=True)

verify_unchanged(LIVE_BASELINE)
sys.exit(1 if counts['FAIL'] else 0)
