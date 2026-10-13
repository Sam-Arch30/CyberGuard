import { useEffect, useState } from 'react';
import { FileImage, Film, AudioLines, Upload, ShieldQuestion, CheckCircle2, AlertCircle, Loader2 } from 'lucide-react';
import { apiFetch, extractErrorMessage } from '../../utils/apiClient';
import { IngestionService } from '../../services/ingestionService';

export type MediaAssessment = {
  trained_detector?: { status: string; prediction?: string; deepfake_score?: number; faces_analyzed?: number; model?: string; limitations?: string[] };
  processing_status: string; classification: string; risk_score: number;
  summary: string; analysis_scope: string; limitations: string[]; format?: string;
  detector_results: { detector_id: string; detector_name: string; status: string; evidence?: Record<string, unknown> }[];
};
type Props = { artifact?: { id: string; name: string }; initialAssessment?: MediaAssessment | null; onAnalysisComplete?: (id: string) => void };
const states: Record<string, string> = { COMPLETED: 'Heuristic checks complete', NOT_ANALYZED: 'Awaiting media analysis',
  DECODER_UNAVAILABLE: 'Decoder unavailable', UNSUPPORTED_FORMAT: 'Unsupported format', INVALID_CONTENT: 'Invalid media content',
  RESOURCE_LIMIT: 'Analysis limit reached', PROCESSING_TIMEOUT: 'Processing timed out', INSUFFICIENT_EVIDENCE: 'Insufficient evidence' };

export function MediaAnalysisPanel({ artifact, initialAssessment, onAnalysisComplete }: Props) {
  const [file, setFile] = useState<File | null>(null);
  const [preview, setPreview] = useState('');
  const [busy, setBusy] = useState(false);
  const [stage, setStage] = useState('');
  const [message, setMessage] = useState(artifact ? 'Original evidence is retained in this investigation.' : '');
  const [error, setError] = useState('');
  const [intakeWarnings, setIntakeWarnings] = useState<string[]>([]);
  const [result, setResult] = useState<MediaAssessment | null>(initialAssessment ?? null);
  useEffect(() => () => { if (preview) URL.revokeObjectURL(preview); }, [preview]);
  async function analyze() {
    if (!file && !artifact) return;
    setBusy(true); setError(''); setResult(null); setIntakeWarnings([]); setStage('Preserving original evidence');
    try {
      let identifier = artifact?.id;
      if (file) {
        const evidence = await IngestionService.ingestFile(file);
        identifier = evidence.artifact_id;
        setIntakeWarnings(evidence.warnings ?? []);
      }
      setMessage('Original evidence preserved. Decoding a bounded sample for analysis.');
      setStage('Decoding and inspecting media');
      const response = await apiFetch('/api/multimedia/analyze', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ artifact_id: identifier }), signal: AbortSignal.timeout(60000),
      });
      if (!response.ok) {
        setMessage('Original evidence is preserved. Analysis could not complete.');
        throw new Error(await extractErrorMessage(response));
      }
      const payload = await response.json();
      setResult(payload.assessment);
      setMessage('Original evidence preserved. Review the observations and their limits below.');
      onAnalysisComplete?.(payload.analysis_run_id);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Media analysis could not complete.');
    } finally { setBusy(false); setStage(''); }
  }
  const completed = result?.processing_status === 'COMPLETED';
  const input = file?.name ?? artifact?.name;
  return <section className="cg-media-panel" aria-labelledby="media-analysis-heading">
    <div className="cg-media-intro"><div><p className="cg-eyebrow">MEDIA AUTHENTICITY</p>
      <h2 id="media-analysis-heading" className="text-2xl font-semibold tracking-tight mt-2">Inspect the media. Review the evidence.</h2>
      <p className="text-sm text-foreground-muted mt-3 max-w-2xl">Image, audio and video checks for visible and structural manipulation signals.</p></div>
      <span className="cg-media-scope"><ShieldQuestion size={16}/> Bounded media checks</span>
    </div>
    <div className="cg-media-workspace">
      <div className="cg-media-input">
        <div className="flex flex-wrap gap-4 text-xs text-foreground-muted"><span className="flex gap-2 items-center"><FileImage size={16}/>Images</span><span className="flex gap-2 items-center"><AudioLines size={16}/>Audio</span><span className="flex gap-2 items-center"><Film size={16}/>Video</span></div>
        {artifact ? <div className="my-6"><p className="text-xs text-foreground-muted">STORED ORIGINAL</p><p className="text-sm mt-2 break-all">{artifact.name}</p></div> :
          <label className="cg-media-upload"><Upload size={24}/><strong>{input ?? 'Choose original media'}</strong><span>JPG, PNG, WEBP, GIF, BMP · WAV, MP3, OGG, FLAC · MP4, MOV, AVI, WEBM</span><span>Maximum 50 MB</span>
            <input type="file" aria-label="Choose media file" accept="image/jpeg,image/png,image/webp,image/gif,image/bmp,audio/*,video/*" disabled={busy} onChange={event => {
              const next = event.target.files?.[0] ?? null;
              setFile(next); setResult(null); setError(''); setMessage(''); setIntakeWarnings([]);
              setPreview(next ? URL.createObjectURL(next) : '');
            }}/>
          </label>}
        {file && preview && <div className="cg-media-preview">{file.type.startsWith('image/') ? <img src={preview} alt="Selected original media"/> : file.type.startsWith('video/') ? <video src={preview} controls preload="metadata"/> : <audio src={preview} controls preload="metadata"/>}</div>}
        <button className="cg-button w-full justify-center" disabled={busy || (!file && !artifact)} onClick={analyze}>{busy ? <Loader2 size={16} className="animate-spin"/> : <Upload size={16}/>} {busy ? stage : artifact ? 'Run media checks' : 'Preserve & analyze'}</button>
        <p role="status" className="text-xs text-foreground-muted mt-3 leading-relaxed">{message}</p>
        {error && <div role="alert" className="cg-media-notice mt-4"><AlertCircle size={18}/><p>{error}</p></div>}
        {intakeWarnings.length > 0 && <details className="text-xs text-foreground-muted mt-4"><summary className="cursor-pointer">Evidence intake limitations ({intakeWarnings.length})</summary><ul className="list-disc pl-5 mt-2 space-y-2">{intakeWarnings.map((value, i) => <li key={i}>{value}</li>)}</ul></details>}
      </div>
      <div className="cg-media-result" aria-live="polite">
        {result ? <>
          <div className="flex items-center gap-2 text-sm font-semibold">{completed ? <CheckCircle2 size={18}/> : <ShieldQuestion size={18}/>} {states[result.processing_status] ?? result.processing_status.replaceAll('_', ' ')}</div>
          {result.trained_detector && <div className="cg-media-notice mt-4"><ShieldQuestion size={18}/><div><strong>Trained face model</strong><p className="mt-2">{result.trained_detector.status === 'COMPLETED' ? `Research output: ${result.trained_detector.prediction?.replaceAll('_', ' ')} · ${((result.trained_detector.deepfake_score ?? 0) * 100).toFixed(1)}% model deepfake score` : result.trained_detector.status === 'MODEL_NOT_VALIDATED' ? 'Model withheld: sample validation failed' : result.trained_detector.status.replaceAll('_', ' ')}</p><p className="text-xs mt-2">{result.trained_detector.faces_analyzed ?? 0} face crops analyzed. Uncalibrated prediction; not proof of authenticity.</p><p className="text-xs mt-2 break-all">{result.trained_detector.model}</p></div></div>}
          <div className="cg-media-score"><span className="text-4xl font-semibold tracking-tight">{completed ? result.risk_score : 'â€”'}</span><div><p className="text-sm">{completed ? 'Heuristic signal score / 100' : 'No authenticity verdict'}</p><p className="text-xs text-foreground-muted mt-1">{completed ? 'Not a real/fake probability' : 'Analysis is incomplete'}</p></div></div>
          <p className="text-sm leading-relaxed">{result.summary}</p>
          <div className="mt-5 space-y-2">{result.detector_results.map(item => <div className="cg-media-detector" key={item.detector_id}><span>{item.detector_name}</span><span className="text-foreground-muted">{item.status === 'SUCCESS' ? 'Executed' : item.status.replaceAll('_', ' ')}</span></div>)}</div>
          <details className="text-xs text-foreground-muted mt-5"><summary className="cursor-pointer">Analysis scope & limitations</summary><p className="mt-3">{result.analysis_scope}</p><ul className="list-disc pl-5 space-y-2 mt-3">{result.limitations.map((value, i) => <li key={i}>{value}</li>)}</ul></details>
        </> : <div className="cg-media-empty"><ShieldQuestion size={32}/><h3 className="text-lg font-semibold mt-4">Authenticity starts with evidence</h3><p className="text-sm text-foreground-muted mt-3">Preserve the original, decode a bounded sample and inspect explainable observations.</p><p className="text-xs text-foreground-muted mt-4">No verdict is shown before analysis runs.</p></div>}
      </div>
    </div>
    <div className="cg-media-notice"><ShieldQuestion size={18}/><p><strong>Authenticity remains unverified.</strong> A zero score does not prove media is real or safe. The pretrained face classifier failed sample validation and is withheld from normal verdicts. Raw inference is available only in explicit research mode. Trained audio detection remains pending.</p></div>
  </section>;
}
