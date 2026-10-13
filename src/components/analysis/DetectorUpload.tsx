import { useState } from 'react';

type Props = { title: string; description: string; accept?: string; busy: boolean;
  onAnalyze: (file: File) => Promise<void>; maxBytes?: number; disabled?: boolean };

export function DetectorUpload({title, description, accept, busy, onAnalyze, maxBytes = 50 * 1024 * 1024, disabled}: Props) {
  const [file, setFile] = useState<File | null>(null);
  const [error, setError] = useState('');
  return <section className="bg-surface border border-border rounded-xl p-5 space-y-3">
    <h2 className="text-base font-semibold">{title}</h2>
    <p className="text-sm text-foreground-muted">{description}</p>
    <label className="block text-sm">Choose evidence
      <input aria-label={title} type="file" accept={accept} disabled={busy} className="block mt-2 max-w-full"
        onChange={event => {const selected = event.target.files?.[0] ?? null; setError(''); setFile(null);
          if (selected && (!selected.size || selected.size > maxBytes)) {setError(`Choose a nonempty file up to ${maxBytes / 1024 / 1024} MB.`); return;}
          setFile(selected);}} />
    </label>
    {file && <p className="text-xs text-foreground-muted break-all">{file.name} · {(file.size / 1024).toFixed(1)} KB</p>}
    {error && <p role="alert" className="text-sm text-danger">{error}</p>}
    <button type="button" disabled={busy || disabled || !file} className="cg-button bg-primary text-primary-foreground disabled:opacity-40"
      onClick={() => {if (file) void onAnalyze(file).catch(err => setError(err instanceof Error ? err.message : 'Upload analysis failed.'));}}>
      {busy ? 'Analyzing…' : 'Upload & analyze'}
    </button>
  </section>;
}
