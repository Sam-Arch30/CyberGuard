import React, { useEffect, useState } from 'react';
import {
  FileText,
  Copy,
  Check,
  ShieldAlert,
  Clock,
  Cpu,
  Layers,
  Fingerprint,
  Link as LinkIcon,
  Code2,
} from 'lucide-react';
import { Drawer, Badge, LoadingState, ErrorState } from '../../ui';
import { ConfidenceIndicator } from '../../security';
import { analysisResultsService } from '../../../services/analysisResultsService';
import type { EvidenceDetailResponse, SupportingEvidencePreview } from '../../../types/analysisResults';

interface EvidenceDetailDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  runId?: string | null;
  evidenceId?: string | null;
  initialPreview?: SupportingEvidencePreview | null;
}

export const EvidenceDetailDrawer: React.FC<EvidenceDetailDrawerProps> = ({
  isOpen,
  onClose,
  runId,
  evidenceId,
  initialPreview,
}) => {
  const [detail, setDetail] = useState<EvidenceDetailResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [copiedValue, setCopiedValue] = useState<boolean>(false);
  const [showRawJson, setShowRawJson] = useState<boolean>(false);

  useEffect(() => {
    if (!isOpen || !evidenceId || !runId) {
      setDetail(null);
      setError(null);
      return;
    }

    let isMounted = true;
    setLoading(true);
    setError(null);

    analysisResultsService
      .getEvidenceDetail(runId, evidenceId)
      .then((res) => {
        if (isMounted) {
          setDetail(res);
          setLoading(false);
        }
      })
      .catch((err) => {
        if (isMounted) {
          setError(err instanceof Error ? err.message : 'Failed to load evidence details.');
          setLoading(false);
        }
      });

    return () => {
      isMounted = false;
    };
  }, [isOpen, runId, evidenceId]);

  const handleCopy = (text: string) => {
    if (!text) return;
    navigator.clipboard.writeText(text);
    setCopiedValue(true);
    setTimeout(() => setCopiedValue(false), 2000);
  };

  const currentType = detail?.evidence_type || initialPreview?.evidence_type || 'EVIDENCE';
  const currentKey = detail?.key || initialPreview?.key || 'Detail';
  const currentValue = detail?.value || initialPreview?.value || '';

  return (
    <Drawer
      isOpen={isOpen}
      onClose={onClose}
      size="lg"
      title={
        <div className="flex items-center space-x-2">
          <FileText className="w-4 h-4 text-primary" />
          <span className="font-mono text-sm font-bold text-foreground">Forensic Evidence Inspection</span>
          <Badge variant="outline" size="sm" className="font-mono text-[10px] uppercase">
            {currentType}
          </Badge>
        </div>
      }
      description={
        <span className="font-mono text-xs text-foreground-muted">
          Forensic audit item {evidenceId || ''}
        </span>
      }
    >
      <div className="space-y-6 text-xs font-mono">
        {/* VALUE CARD */}
        <div className="p-4 rounded-xl bg-surface border border-border shadow-xs space-y-2">
          <div className="flex items-center justify-between text-foreground-muted text-[11px]">
            <span className="font-semibold uppercase tracking-wider">{currentKey}</span>
            <button
              type="button"
              onClick={() => handleCopy(currentValue)}
              className="inline-flex items-center space-x-1 hover:text-foreground transition-colors cursor-pointer text-[10px]"
              title="Copy observed value"
            >
              {copiedValue ? <Check className="w-3.5 h-3.5 text-success" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copiedValue ? 'Copied' : 'Copy'}</span>
            </button>
          </div>
          <div className="p-3 rounded-lg bg-surface-secondary/70 border border-border/80 break-all text-foreground text-xs leading-relaxed select-all">
            {currentValue || <span className="text-foreground-subtle italic">No value recorded</span>}
          </div>
          <div className="flex items-center space-x-1.5 text-[10px] text-foreground-subtle pt-1">
            <ShieldAlert className="w-3 h-3 text-primary" />
            <span>Sensitive tokens and authentication secrets are automatically redacted.</span>
          </div>
        </div>

        {loading && (
          <div className="py-8">
            <LoadingState
              message="Loading verified forensic record..."
              subtext="Retrieving provenance and analyzer audit references"
            />
          </div>
        )}

        {error && (
          <ErrorState
            title="Failed to Load Evidence"
            message={error}
            onRetry={() => {
              if (runId && evidenceId) {
                setLoading(true);
                analysisResultsService
                  .getEvidenceDetail(runId, evidenceId)
                  .then((res) => {
                    setDetail(res);
                    setError(null);
                  })
                  .catch((e) => setError(e.message))
                  .finally(() => setLoading(false));
              }
            }}
          />
        )}

        {detail && !loading && (
          <div className="space-y-5">
            {/* AUDIT METRICS GRID */}
            <div className="grid grid-cols-2 gap-3">
              <div className="p-3 rounded-lg bg-surface border border-border space-y-1">
                <span className="text-[10px] text-foreground-subtle uppercase flex items-center gap-1">
                  <Layers className="w-3 h-3" />
                  Origin Source
                </span>
                <span className="text-xs font-semibold text-foreground block truncate">
                  {detail.source}
                </span>
              </div>

              <div className="p-3 rounded-lg bg-surface border border-border space-y-1">
                <span className="text-[10px] text-foreground-subtle uppercase flex items-center gap-1">
                  <Cpu className="w-3 h-3" />
                  Detected By
                </span>
                <span className="text-xs font-semibold text-foreground block truncate">
                  {detail.detected_by || 'Detection Engine'}
                </span>
              </div>

              <div className="p-3 rounded-lg bg-surface border border-border space-y-1">
                <span className="text-[10px] text-foreground-subtle uppercase flex items-center gap-1">
                  <Clock className="w-3 h-3" />
                  Observed At
                </span>
                <span className="text-xs text-foreground block truncate">
                  {detail.observed_at ? new Date(detail.observed_at).toLocaleString() : 'N/A'}
                </span>
              </div>

              <div className="p-3 rounded-lg bg-surface border border-border space-y-1">
                <span className="text-[10px] text-foreground-subtle uppercase flex items-center gap-1">
                  <ShieldAlert className="w-3 h-3" />
                  Evidence Confidence
                </span>
                <div className="pt-0.5">
                  <ConfidenceIndicator score={detail.confidence} size="sm" />
                </div>
              </div>
            </div>

            {/* LINKED FINDING */}
            {detail.linked_finding_title && (
              <div className="p-3 rounded-lg bg-surface border border-border space-y-1">
                <span className="text-[10px] text-foreground-subtle uppercase flex items-center gap-1">
                  <LinkIcon className="w-3 h-3 text-primary" />
                  Linked Finding
                </span>
                <p className="text-xs font-semibold text-foreground">
                  {detail.linked_finding_title}
                </p>
              </div>
            )}

            {/* FINGERPRINT */}
            {detail.sha256 && (
              <div className="p-3 rounded-lg bg-surface border border-border space-y-1">
                <span className="text-[10px] text-foreground-subtle uppercase flex items-center gap-1">
                  <Fingerprint className="w-3 h-3" />
                  SHA-256 Fingerprint
                </span>
                <div className="text-[11px] text-foreground font-mono select-all break-all">
                  {detail.sha256}
                </div>
              </div>
            )}

            {/* PROVENANCE CHAIN */}
            {detail.provenance_chain && detail.provenance_chain.length > 0 && (
              <div className="p-3 rounded-lg bg-surface border border-border space-y-2">
                <span className="text-[10px] text-foreground-subtle uppercase font-semibold block">
                  Provenance Trail
                </span>
                <div className="space-y-1">
                  {detail.provenance_chain.map((step, idx) => (
                    <div key={idx} className="flex items-center space-x-2 text-[11px] text-foreground-muted">
                      <span className="w-4 h-4 rounded-full bg-primary/10 text-primary flex items-center justify-center text-[9px] shrink-0 font-bold">
                        {idx + 1}
                      </span>
                      <span>{step}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* RAW RECORD PREVIEW */}
            <div className="border border-border rounded-xl overflow-hidden bg-surface">
              <button
                type="button"
                onClick={() => setShowRawJson(!showRawJson)}
                className="w-full flex items-center justify-between p-3 text-xs font-semibold text-foreground-muted hover:text-foreground transition-colors cursor-pointer select-none bg-surface-secondary/40"
              >
                <span className="flex items-center gap-1.5">
                  <Code2 className="w-3.5 h-3.5" />
                  Raw Evidence Object
                </span>
                <span className="text-[10px] text-primary">{showRawJson ? 'Hide JSON' : 'Inspect JSON'}</span>
              </button>

              {showRawJson && (
                <div className="p-3 bg-surface-secondary/80 border-t border-border overflow-x-auto max-h-60 text-[11px] leading-relaxed">
                  <pre className="text-foreground-muted font-mono select-all">
                    {JSON.stringify(detail.metadata || detail, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </Drawer>
  );
};
