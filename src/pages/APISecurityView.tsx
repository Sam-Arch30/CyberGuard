import { useState } from 'react';
import { apiFetch, extractErrorMessage } from '../utils/apiClient';

interface APIResult {events_analyzed_count: number; overall_risk_score: number; overall_severity: string; classification: string; findings: {title: string; description: string; severity: string}[];}

export function APISecurityView() {
  const [text, setText] = useState('');
  const [result, setResult] = useState<APIResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  async function analyze(file?: File) {
    setBusy(true); setError(''); setResult(null);
    try {
      let response: Response;
      if (file) {
        if (file.size > 50*1024*1024) throw new Error('Telemetry file exceeds the 50 MB limit.');
        const form = new FormData(); form.append('file', file);
        response = await apiFetch('/api/api-security/upload-log', {method: 'POST', body: form});
      } else {
        const events = JSON.parse(text);
        if (!Array.isArray(events) || !events.length) throw new Error('Paste a nonempty JSON array of API request events.');
        response = await apiFetch('/api/api-security/analyze-batch', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(events)});
      }
      if (!response.ok) throw new Error(await extractErrorMessage(response));
      const data = await response.json();
      if (!Number.isFinite(data.overall_risk_score) || !Array.isArray(data.findings) || !data.events_analyzed_count) throw new Error('No usable analysis result was returned.');
      setResult(data);
    } catch (err) {setError(err instanceof Error ? err.message : 'API telemetry analysis failed.');}
    finally {setBusy(false);}
  }
  return <div className="space-y-6"><header className="border-b border-border pb-6"><p className="cg-eyebrow">DETECTION / API TELEMETRY</p><h1 className="text-3xl font-semibold mt-3">API abuse analysis</h1><p className="text-sm text-foreground-muted mt-3 max-w-2xl">Review request bursts, enumeration, authentication failures, privilege changes and scraping patterns in submitted API logs. This is telemetry analysis, not automatic traffic blocking.</p></header>
    <section className="bg-surface border border-border rounded-xl p-5 space-y-4"><label className="text-sm block">API request events<textarea aria-label="API request events" value={text} onChange={e => setText(e.target.value)} rows={7} className="block w-full mt-2 rounded-lg border border-border bg-surface-secondary p-3 font-mono text-xs" placeholder={'[{"timestamp":"2026-10-13T10:00:00Z","method":"GET","path":"/api/orders","status_code":200,"source_ip":"192.0.2.10"}]'} /></label><div className="flex flex-wrap items-center justify-between gap-4"><label className="text-xs text-foreground-muted">Upload JSON, JSONL or CSV<input aria-label="Upload API telemetry" type="file" accept=".json,.jsonl,.ndjson,.csv" className="block mt-2 max-w-full" disabled={busy} onChange={e => {const file=e.target.files?.[0]; if (file) void analyze(file);}} /></label><button type="button" disabled={busy || !text.trim()} onClick={() => void analyze()} className="cg-button bg-primary text-primary-foreground disabled:opacity-50">{busy ? 'Analyzing…' : 'Analyze events'}</button></div></section>
    {error && <p role="alert" className="rounded-lg border border-danger-border p-4 text-sm text-danger">{error}</p>}
    {result && <section className="bg-surface border border-border rounded-xl p-5 space-y-5"><div className="flex flex-wrap justify-between gap-4"><div><h2 className="text-lg font-semibold">{result.classification.replaceAll('_',' ')}</h2><p className="text-sm text-foreground-muted mt-2">{result.events_analyzed_count} events assessed · {result.findings.length} findings</p></div><p className="text-2xl font-semibold">{result.overall_risk_score}<span className="text-xs text-foreground-muted"> / 100</span></p></div><p className="text-xs text-foreground-muted">Rule-based risk score, not a calibrated attack probability. Missing signals do not prove that every request is legitimate.</p><div className="divide-y divide-border">{result.findings.map((finding,index) => <div key={index} className="py-4"><p className="text-sm font-semibold">{finding.title}</p><p className="text-xs text-foreground-muted mt-2">{finding.description}</p></div>)}</div></section>}
  </div>;
}
