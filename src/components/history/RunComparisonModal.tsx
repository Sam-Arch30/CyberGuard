import React from 'react';
import {
  GitCompare,
  ArrowRight,
  ExternalLink,
  CheckCircle2,
  XCircle,
  TrendingUp,
  TrendingDown,
  Minus,
  Clock
} from 'lucide-react';
import { Modal, ModalHeader, ModalTitle, ModalDescription, ModalBody } from '../ui/Modal';
import { Button } from '../ui/Button';
import { Badge } from '../ui/Badge';

export interface RunComparisonData {
  runNumber: number;
  id: string;
  evidence_id: string | null;
  sha256: string | null;
  timestamp: string;
  threat_score: number;
  severity: string;
  subject?: string;
  sender?: string;
  auth?: {
    spf?: string;
    dkim?: string;
    dmarc?: string;
  };
  iocCount?: {
    domains?: number;
    ips?: number;
    urls?: number;
    total?: number;
  };
  relayHopsCount?: number;
  lookalikeCount?: number;
}

interface RunComparisonModalProps {
  isOpen: boolean;
  onClose: () => void;
  runA: RunComparisonData | null;
  runB: RunComparisonData | null;
  onOpenRun: (id: string) => void;
}

export const RunComparisonModal: React.FC<RunComparisonModalProps> = ({
  isOpen,
  onClose,
  runA,
  runB,
  onOpenRun
}) => {
  if (!runA || !runB) return null;

  const scoreDiff = Math.round(runB.threat_score - runA.threat_score);

  const formatTimestamp = (ts: string) => {
    try {
      const d = new Date(ts);
      return d.toLocaleString('en-US', {
        month: 'short',
        day: 'numeric',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        timeZoneName: 'short'
      });
    } catch {
      return ts;
    }
  };

  const renderAuthBadge = (val?: string) => {
    const upper = (val || 'UNKNOWN').toUpperCase();
    if (upper === 'PASS') {
      return (
        <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded bg-success/15 text-success border border-success/30 font-mono text-[10px] font-bold">
          <CheckCircle2 className="w-3 h-3" />
          <span>PASS</span>
        </span>
      );
    }
    if (upper === 'FAIL' || upper === 'PERMERROR' || upper === 'TEMPERROR') {
      return (
        <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded bg-danger/15 text-danger border border-danger/30 font-mono text-[10px] font-bold">
          <XCircle className="w-3 h-3" />
          <span>{upper}</span>
        </span>
      );
    }
    return (
      <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded bg-surface-secondary text-foreground-muted border border-border font-mono text-[10px]">
        <span>{upper}</span>
      </span>
    );
  };

  return (
    <Modal isOpen={isOpen} onClose={onClose} size="xl">
      <ModalHeader>
        <div className="flex items-center space-x-2.5">
          <div className="p-2 rounded-xl bg-primary/10 text-primary border border-primary/20">
            <GitCompare className="w-5 h-5" />
          </div>
          <div>
            <ModalTitle>Forensic Analysis Run Comparison</ModalTitle>
            <ModalDescription>
              Differential inspection of scoring, authentication, IOCs, and telemetry across analysis iterations
            </ModalDescription>
          </div>
        </div>
      </ModalHeader>

      <ModalBody className="space-y-6">
        {/* Score Delta Banner */}
        <div className="p-4 rounded-xl bg-surface border border-border shadow-xs">
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
            <div>
              <span className="text-[10px] font-mono uppercase tracking-wider text-foreground-muted block mb-1">
                Threat Score Trajectory
              </span>
              <div className="flex items-center space-x-3 text-lg font-bold font-mono">
                <span className="text-foreground">
                  Run #{runA.runNumber}: <span className="text-primary">{Math.round(runA.threat_score)}</span>
                </span>
                <ArrowRight className="w-4 h-4 text-foreground-muted" />
                <span className="text-foreground">
                  Run #{runB.runNumber}: <span className="text-primary">{Math.round(runB.threat_score)}</span>
                </span>
              </div>
            </div>

            <div className="flex items-center space-x-2">
              <div className={`flex items-center space-x-1 px-3 py-1.5 rounded-lg border font-mono text-xs font-bold ${
                scoreDiff > 0
                  ? 'bg-danger/15 text-danger border-danger/30'
                  : scoreDiff < 0
                  ? 'bg-success/15 text-success border-success/30'
                  : 'bg-surface-secondary text-foreground-muted border-border'
              }`}>
                {scoreDiff > 0 ? (
                  <>
                    <TrendingUp className="w-4 h-4" />
                    <span>Δ +{scoreDiff} (Threat Increased)</span>
                  </>
                ) : scoreDiff < 0 ? (
                  <>
                    <TrendingDown className="w-4 h-4" />
                    <span>Δ {scoreDiff} (Threat Reduced)</span>
                  </>
                ) : (
                  <>
                    <Minus className="w-4 h-4" />
                    <span>Δ 0 (Unchanged)</span>
                  </>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* Side-by-Side Comparison Columns */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* RUN A */}
          <div className="p-4 rounded-xl bg-surface border border-border space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-border">
              <div>
                <Badge variant="outline" size="sm" className="mb-1">
                  Baseline Run #{runA.runNumber}
                </Badge>
                <div className="text-xs font-mono text-foreground-muted flex items-center space-x-1 mt-0.5">
                  <Clock className="w-3 h-3 text-primary" />
                  <span>{formatTimestamp(runA.timestamp)}</span>
                </div>
              </div>
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  onClose();
                  onOpenRun(runA.evidence_id || runA.id);
                }}
                className="flex items-center space-x-1 text-xs"
              >
                <span>Inspect</span>
                <ExternalLink className="w-3 h-3" />
              </Button>
            </div>

            {/* Run A Metrics */}
            <div className="space-y-3 font-mono text-xs">
              <div className="flex items-center justify-between p-2 rounded-lg bg-surface-secondary/50">
                <span className="text-foreground-muted">Threat Score:</span>
                <span className="font-bold text-foreground">
                  {Math.round(runA.threat_score)} / 100 ({runA.severity.toUpperCase()})
                </span>
              </div>

              <div className="flex items-center justify-between p-2 rounded-lg bg-surface-secondary/50">
                <span className="text-foreground-muted">SPF Authentication:</span>
                <div>{renderAuthBadge(runA.auth?.spf)}</div>
              </div>

              <div className="flex items-center justify-between p-2 rounded-lg bg-surface-secondary/50">
                <span className="text-foreground-muted">DKIM Authentication:</span>
                <div>{renderAuthBadge(runA.auth?.dkim)}</div>
              </div>

              <div className="flex items-center justify-between p-2 rounded-lg bg-surface-secondary/50">
                <span className="text-foreground-muted">DMARC Policy:</span>
                <div>{renderAuthBadge(runA.auth?.dmarc)}</div>
              </div>

              <div className="flex items-center justify-between p-2 rounded-lg bg-surface-secondary/50">
                <span className="text-foreground-muted">Extracted IOCs:</span>
                <span className="font-bold text-foreground">
                  {runA.iocCount?.total ?? (runA.iocCount ? ((runA.iocCount.domains || 0) + (runA.iocCount.ips || 0) + (runA.iocCount.urls || 0)) : 'Evaluated')}
                </span>
              </div>

              <div className="flex items-center justify-between p-2 rounded-lg bg-surface-secondary/50">
                <span className="text-foreground-muted">Relay Hops:</span>
                <span className="font-bold text-foreground">
                  {runA.relayHopsCount !== undefined ? `${runA.relayHopsCount} hops` : 'Reconstructed'}
                </span>
              </div>

              <div className="p-2 rounded-lg bg-surface-secondary/30 text-[11px] text-foreground-muted space-y-1">
                <span className="block text-[10px] uppercase text-foreground-subtle">Evidence Reference</span>
                <span className="font-bold text-primary truncate block">{runA.evidence_id || runA.id}</span>
              </div>
            </div>
          </div>

          {/* RUN B */}
          <div className="p-4 rounded-xl bg-surface border border-primary/30 space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-border">
              <div>
                <Badge variant="primary" size="sm" className="mb-1">
                  Target Run #{runB.runNumber}
                </Badge>
                <div className="text-xs font-mono text-foreground-muted flex items-center space-x-1 mt-0.5">
                  <Clock className="w-3 h-3 text-primary" />
                  <span>{formatTimestamp(runB.timestamp)}</span>
                </div>
              </div>
              <Button
                variant="primary"
                size="sm"
                onClick={() => {
                  onClose();
                  onOpenRun(runB.evidence_id || runB.id);
                }}
                className="flex items-center space-x-1 text-xs"
              >
                <span>Inspect</span>
                <ExternalLink className="w-3 h-3" />
              </Button>
            </div>

            {/* Run B Metrics */}
            <div className="space-y-3 font-mono text-xs">
              <div className="flex items-center justify-between p-2 rounded-lg bg-surface-secondary/50">
                <span className="text-foreground-muted">Threat Score:</span>
                <span className="font-bold text-foreground">
                  {Math.round(runB.threat_score)} / 100 ({runB.severity.toUpperCase()})
                </span>
              </div>

              <div className="flex items-center justify-between p-2 rounded-lg bg-surface-secondary/50">
                <span className="text-foreground-muted">SPF Authentication:</span>
                <div>{renderAuthBadge(runB.auth?.spf)}</div>
              </div>

              <div className="flex items-center justify-between p-2 rounded-lg bg-surface-secondary/50">
                <span className="text-foreground-muted">DKIM Authentication:</span>
                <div>{renderAuthBadge(runB.auth?.dkim)}</div>
              </div>

              <div className="flex items-center justify-between p-2 rounded-lg bg-surface-secondary/50">
                <span className="text-foreground-muted">DMARC Policy:</span>
                <div>{renderAuthBadge(runB.auth?.dmarc)}</div>
              </div>

              <div className="flex items-center justify-between p-2 rounded-lg bg-surface-secondary/50">
                <span className="text-foreground-muted">Extracted IOCs:</span>
                <span className="font-bold text-foreground">
                  {runB.iocCount?.total ?? (runB.iocCount ? ((runB.iocCount.domains || 0) + (runB.iocCount.ips || 0) + (runB.iocCount.urls || 0)) : 'Evaluated')}
                </span>
              </div>

              <div className="flex items-center justify-between p-2 rounded-lg bg-surface-secondary/50">
                <span className="text-foreground-muted">Relay Hops:</span>
                <span className="font-bold text-foreground">
                  {runB.relayHopsCount !== undefined ? `${runB.relayHopsCount} hops` : 'Reconstructed'}
                </span>
              </div>

              <div className="p-2 rounded-lg bg-surface-secondary/30 text-[11px] text-foreground-muted space-y-1">
                <span className="block text-[10px] uppercase text-foreground-subtle">Evidence Reference</span>
                <span className="font-bold text-primary truncate block">{runB.evidence_id || runB.id}</span>
              </div>
            </div>
          </div>
        </div>

        {/* Modal Actions */}
        <div className="flex items-center justify-end space-x-2 pt-3 border-t border-border">
          <Button variant="outline" size="sm" onClick={onClose}>
            Close Comparison
          </Button>
        </div>
      </ModalBody>
    </Modal>
  );
};
