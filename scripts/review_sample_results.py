"""Review actual route outputs; quality controls are independent of HTTP success."""
import csv
import html
import io
import json
import sys
from collections import Counter
from pathlib import Path
from sample_audit_runtime import configure, verify_unchanged

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT = ROOT / 'samples/test-results'
summary = json.loads((OUT / 'results.json').read_text(encoding='utf-8'))
rows = [row for row in summary['results'] if row['stage'] != 'Detection control' and '(canonical fields)' not in row['stage']]
responses = {}
for index, row in enumerate(rows, 1):
    path = OUT / (str(index).zfill(3) + '-response.json')
    if path.exists() and row['stage'] != 'Report download':
        data = json.loads(path.read_text(encoding='utf-8'))
        responses[(row['stage'], row['sample'])] = data
        row['risk'] = data.get('overall_risk_score', row['risk'])

def find(stage, sample=None):
    return next(row for row in rows if row['stage'] == stage and (sample is None or row['sample'] == sample))

quality = []
def check(name, passed, note, warning=False):
    quality.append({'sample': name, 'stage': 'Detection control', 'endpoint': '—', 'http': '—',
                    'status': 'PASS' if passed else ('WARN' if warning else 'FAIL'), 'risk': None,
                    'classification': '', 'seconds': 0, 'note': note})

normal = find('Authentication analysis', '06-logs/normal-auth.json')
spray = find('Authentication analysis', '06-logs/password-spray.json')
jsonl = find('Authentication analysis', '06-logs/authentication-events.jsonl')
trusted = find('Trusted identity'); suspect = find('Suspicious identity')
invalid = find('Invalid JSON validation')
check('Normal authentication control', normal['classification'] == 'NORMAL_AUTHENTICATION' and normal['risk'] == 0,
      f"Observed {normal['classification']}, risk {normal['risk']}.")
check('Password-spray JSON control', spray['classification'] == 'CREDENTIAL_ATTACK_DETECTED' and spray['risk'] > 0,
      f"Observed {spray['classification']}, risk {spray['risk']}.")
json_result = responses[('Authentication analysis', spray['sample'])]
jsonl_result = responses[('Authentication analysis', jsonl['sample'])]
check('Equivalent JSONL control', jsonl['classification'] == spray['classification'] and jsonl['risk'] == spray['risk']
      and json_result.get('accounts_targeted_count') == jsonl_result.get('accounts_targeted_count') == 8
      and json_result.get('events_analyzed_count') == jsonl_result.get('events_analyzed_count') == 24
      and [f['finding_type'] for f in json_result.get('findings', [])] == [f['finding_type'] for f in jsonl_result.get('findings', [])],
      f"Same 24 events: JSON {spray['risk']} / {spray['classification']}; JSONL {jsonl['risk']} / {jsonl['classification']}. Account and finding equivalence also checked.")
check('Trusted identity through UI contract', trusted['risk'] is not None and trusted['risk'] < 20 and trusted['classification'] == 'NO_IMPERSONATION_EVIDENCE',
      f"Trusted sender: {trusted['classification']} at {trusted['risk']}. Uses exact frontend address fields; domains derived server-side.")
check('Identity discrimination through UI contract', suspect['risk'] is not None and trusted['risk'] is not None and suspect['risk'] > trusted['risk'] and suspect['classification'] != trusted['classification'],
      f"Trusted {trusted['risk']} / {trusted['classification']}; suspicious {suspect['risk']} / {suspect['classification']}.")
check('Malformed JSON log rejection', isinstance(invalid['http'], int) and 400 <= invalid['http'] < 500,
      f"Malformed .json returned HTTP {invalid['http']}: {invalid['note']}")
unknown = [row for row in rows if row['stage'] == 'Media analysis' and row['classification'] == 'INSUFFICIENT_EVIDENCE']
check('Media detection coverage', len(unknown) == 0,
      f"{len(unknown)} valid files remain inconclusive. Completed heuristic checks do not establish deepfake detection accuracy.", warning=True)
media = [(row, responses.get(('Media analysis', row['sample']), {}).get('assessment', {})) for row in rows if row['stage'] == 'Media analysis']
check('Valid media decoding control', all(row['http'] == 200 and assessment.get('processing_status') == 'COMPLETED'
      and any(r.get('status') == 'SUCCESS' for r in assessment.get('detector_results', [])) for row, assessment in media),
      f"Verified processing status and successful detector execution for {len(media)} valid image/audio/video samples.")
check('Deepfake accuracy evaluation', False, 'Synthetic graphics, tones and color bars contain no labelled real/fake faces or speech. Held-out deepfake accuracy remains unverified.', warning=True)

TEMP = Path(summary['test_root'])
LIVE_BASELINE = configure(TEMP)
from fastapi.testclient import TestClient
from backend.main import app
profile = responses[('Profile creation', '07-identity/trusted-profile.json')]['id']
canonical = []
with TestClient(app, raise_server_exceptions=False) as client:
    loaded = client.get('/api/impersonation/profiles/' + profile)
    check('Trusted sender profile persistence', loaded.status_code == 200 and loaded.json().get('trusted_sender_addresses') == ['finance@example.test'],
          'Reloaded protected profile must retain its configured trusted sender address.')
    for label, sender, reply in [('Trusted', 'finance@example.test', 'finance@example.test'), ('Suspicious', 'finance@lookalike-example.test', 'collector@untrusted.example')]:
        response = client.post('/api/impersonation/analyze', json={'artifact_type': 'EMAIL', 'target_identity_hint': profile,
            'email_data': {'from_display_name': 'Example Finance', 'from_address': sender, 'from_domain': sender.split('@')[1],
                           'reply_to_address': reply, 'reply_to_domain': reply.split('@')[1], 'subject': 'Payment approval', 'body_text': 'Payment message'}})
        data = response.json(); assessment = data.get('assessment', {}); canonical.append(assessment)
        rows.append({'sample': '07-identity/identity-claim.txt', 'stage': label + ' identity (canonical fields)', 'endpoint': '/api/impersonation/analyze',
                     'http': response.status_code, 'status': 'PASS' if response.status_code == 200 else 'FAIL', 'risk': assessment.get('risk_score'),
                     'classification': assessment.get('classification', ''), 'seconds': 0, 'note': 'Canonical domain fields validated against parsed addresses.'})
        (OUT / ('canonical-' + label.lower() + '.json')).write_text(json.dumps(data, indent=2), encoding='utf-8')
check('Canonical identity engine control', bool(canonical[0] and canonical[1]) and canonical[0]['risk_score'] < 20 and canonical[0]['classification'] == 'NO_IMPERSONATION_EVIDENCE' and canonical[1]['risk_score'] > canonical[0]['risk_score'] and canonical[1]['classification'] != canonical[0]['classification'],
      'Canonical fields: ' + str([(item.get('classification'), item.get('risk_score')) for item in canonical]))
rows += quality
counts = Counter(row['status'] for row in rows)
verdict = 'Sample controls pass; prototype capabilities remain limited.' if not counts['FAIL'] else 'Some sample controls still fail; see details.'
summary.update(checks=len(rows), counts={key: counts[key] for key in ('PASS', 'WARN', 'FAIL')}, results=rows, verdict=verdict)
(OUT / 'results.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')
stream = io.StringIO(); writer = csv.DictWriter(stream, fieldnames=list(rows[0])); writer.writeheader(); writer.writerows(rows)
(OUT / 'results.csv').write_text(stream.getvalue(), encoding='utf-8')
header = f"Tested {summary['sample_files']} files with {len(rows)} checks: {counts['PASS']} PASS, {counts['WARN']} WARN, {counts['FAIL']} FAIL."
limitations = [
    'Real FastAPI routes against an isolated database copy and temporary evidence/report/EML/benchmark/model candidate paths. Live investigation and model files are hashed before and after execution.',
    'No requests sent to the live backend. Background worker and external enrichment/LLM integrations disabled.',
    'Invalid originals can be retained at intake with explicit warnings; successful intake is not decoding or completed analysis.',
    'Media uses bounded decoded samples and heuristic checks. Scores are not calibrated deepfake probabilities; zero does not establish authenticity.',
    'Deepfake accuracy, browser interaction/visual accessibility, all background jobs and real-world threat accuracy remain unverified.',
    'PDF downloads checked for signature and nonempty bytes; generated report layout is not visually validated in this audit.',
]
lines = ['# CyberGuard sample test report', '', 'Date: ' + summary['date'], '', header, '', '## Verdict', '', verdict,
         '', '## Detection controls', '',
         f"Authentication: JSON {spray['risk']} / {spray['classification']}; equivalent JSONL {jsonl['risk']} / {jsonl['classification']}.",
         f"Identity frontend contract: trusted {trusted['risk']} / {trusted['classification']}; suspicious {suspect['risk']} / {suspect['classification']}.",
         f"Malformed authentication JSON: HTTP {invalid['http']}.", '', '## Scope and remaining limitations', '']
lines += ['- ' + value for value in limitations]
lines += ['', '## Detailed results', '', '| Sample | Check | HTTP | Result | Risk | Detail |', '| --- | --- | --- | --- | --- |']
for row in rows:
    lines.append('| ' + ' | '.join(str(row[key] if row[key] is not None else '—').replace('|', '/').replace('\n', ' ') for key in ['sample', 'stage', 'http', 'status', 'risk', 'note']) + ' |')
(OUT / 'report.md').write_text('\n'.join(lines) + '\n', encoding='utf-8')
body = ''.join('<tr>' + ''.join('<td>' + html.escape(str(row.get(key, '—'))) + '</td>' for key in ['sample', 'stage', 'http', 'status', 'risk', 'note']) + '</tr>' for row in rows)
(OUT / 'report.html').write_text('<!doctype html><html lang="en"><meta charset="utf-8"><title>CyberGuard sample test report</title><style>body{font:15px system-ui;color:#23312a;background:#f6f7f3;margin:40px auto;max-width:1200px;padding:24px}p,li{line-height:1.6}table{border-collapse:collapse;width:100%;background:white;font-size:12px}td,th{padding:10px;border:1px solid #d9dfd7;text-align:left;vertical-align:top}.table{overflow:auto}</style><h1>CyberGuard sample test report</h1><p>' + html.escape(header) + '</p><p><strong>' + html.escape(verdict) + '</strong></p><h2>Scope and limitations</h2><ul>' + ''.join('<li>' + html.escape(value) + '</li>' for value in limitations) + '</ul><h2>Detailed results</h2><div class="table"><table><thead><tr><th>Sample</th><th>Check</th><th>HTTP</th><th>Result</th><th>Risk</th><th>Details</th></tr></thead><tbody>' + body + '</tbody></table></div></html>', encoding='utf-8')
verify_unchanged(LIVE_BASELINE)
print(header); print(verdict)
sys.exit(1 if counts['FAIL'] else 0)
