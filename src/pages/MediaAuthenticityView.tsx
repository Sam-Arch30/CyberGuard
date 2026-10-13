import { MediaAnalysisPanel } from '../components/dashboard/MediaAnalysisPanel';
export function MediaAuthenticityView() {
  return <div className="space-y-6"><header><p className="cg-eyebrow">DETECTION / MEDIA</p><h1 className="text-3xl font-semibold tracking-tight mt-3">Media authenticity</h1><p className="text-sm text-foreground-muted mt-3">Preserve original evidence and review manipulation signals across images, audio and video.</p></header><MediaAnalysisPanel/></div>;
}
