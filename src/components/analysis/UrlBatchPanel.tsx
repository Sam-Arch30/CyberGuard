import { useState } from 'react';
import { apiFetch, extractErrorMessage } from '../../utils/apiClient';

interface BatchItem {line: number; original: string; url: string; status: string; findings: {title: string; description: string; severity: string}[];}
interface BatchResult {urls_analyzed: number; results: BatchItem[]; limitations: string[];}

export function UrlBatchPanel({onInspect}: {onInspect: (url: string) => void}) {
  const [text, setText] = useState('');
  const [result, setResult] = useState<BatchResult | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  async function assess() {
    setBusy(true); setError(''); setResult(null);
    try {
      const response = await apiFetch('/api/urls/analyze-batch', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({text})});
      if (!response.ok) throw new Error(await extractErrorMessage(response));
      const data = await response.json();
      if (!Array.isArray(data.results) || !Array.isArray(data.limitations)) throw new Error('Incomplete URL batch response.');
      setResult(data);
    } catch (err) {setError(err instanceof Error ? err.message : 'Batch assessment failed.');}
    finally {setBusy(false);}
  }
  return <section className="cg-batch-panel bg-surface border border-border rounded-xl p-5 space-y-4">
    <div><h2 className="text-lg font-semibold">Assess a URL list</h2><p className="text-sm text-foreground-muted mt-2">Screen up to 50 URLs for structural indicators. Defanged links are supported. No destination websites are visited.</p></div>
    <label className="block text-sm">URLs, one per line<textarea aria-label="URL list" value={text} onChange={e => setText(e.target.value)} rows={5} className="block mt-2 w-full rounded-lg bg-surface-secondary border border-border p-3 font-mono text-xs" placeholder="hxxps://example[.]com/login" /></label>
    <div className="flex flex-wrap items-center justify-between gap-3"><label className="text-xs text-foreground-muted">Or choose a text list<input type="file" accept=".txt,text/plain" aria-label="Upload URL list" className="block mt-2 max-w-full" onChange={async e => {const file=e.target.files?.[0]; if (!file) return; if (file.size > 210000) {setError('URL list exceeds the 210 KB screening limit.'); return;} try {setText(await file.text()); setError('');} catch {setError('Unable to read this text list.');}}} /></label><button type="button" onClick={assess} disabled={busy || !text.trim()} className="cg-button bg-primary text-primary-foreground disabled:opacity-50">{busy ? 'Assessing…' : 'Assess URL list'}</button></div>
    {error && <p role="alert" className="text-sm text-danger">{error}</p>}
    {result && <div className="space-y-4"><p className="text-sm font-medium">{result.urls_analyzed} unique URLs assessed</p><div className="rounded-lg bg-surface-secondary p-3 text-xs text-foreground-muted space-y-1">{result.limitations.map(note => <p key={note}>{note}</p>)}</div><div className="divide-y divide-border">{result.results.map(item => <div key={item.url} className="py-4 space-y-2"><div className="flex flex-wrap justify-between gap-3"><p className="font-mono text-xs break-all">{item.url}</p><button type="button" onClick={() => onInspect(item.url)} className="text-xs text-primary">Inspect individually</button></div><p className="text-xs font-medium">{item.status === 'STRUCTURAL_SIGNALS_FOUND' ? 'Structural indicators found — review required' : 'No structural indicators — safety undetermined'}</p>{item.findings.map((finding, index) => <p key={`${finding.title}-${index}`} className="text-xs text-foreground-muted">{finding.title}: {finding.description}</p>)}</div>)}</div></div>}
  </section>;
}
