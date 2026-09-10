import React, { useState } from 'react';
import {
  ShieldCheck,
  AlertTriangle,
  Info,
  CheckCircle2,
  Check,
  Layers,
  Sparkles,
  ExternalLink,
  HelpCircle,
  Crosshair,
  MapPin,
  Globe,
  FileText
} from 'lucide-react';
import { Modal, ModalHeader, ModalTitle, ModalDescription, ModalBody, ModalFooter } from '../ui/Modal';
import { Button } from '../ui/Button';
import type { ForensicConclusion, ConfidenceLevel } from '../../types/confidence';

interface EvidenceConfidencePanelProps {
  isOpen: boolean;
  onClose: () => void;
  conclusions?: ForensicConclusion[];
  selectedConclusionId?: string;
  onSelectConclusion?: (id: string) => void;
}

const TYPE_ICONS: Record<string, React.ReactNode> = {
  threat_classification: <ShieldCheck className="w-3.5 h-3.5 text-rose-400 shrink-0" />,
  infrastructure_attribution: <Crosshair className="w-3.5 h-3.5 text-cyan-400 shrink-0" />,
  geolocation: <MapPin className="w-3.5 h-3.5 text-emerald-400 shrink-0" />,
  campaign_association: <Layers className="w-3.5 h-3.5 text-purple-400 shrink-0" />,
  lookalike_determination: <Globe className="w-3.5 h-3.5 text-amber-400 shrink-0" />,
  malicious_url: <ExternalLink className="w-3.5 h-3.5 text-red-400 shrink-0" />,
  nlp_classification: <Sparkles className="w-3.5 h-3.5 text-blue-400 shrink-0" />,
  attachment_risk: <FileText className="w-3.5 h-3.5 text-orange-400 shrink-0" />
};

const TYPE_LABELS: Record<string, string> = {
  threat_classification: 'Threat Classification',
  infrastructure_attribution: 'Infrastructure Attribution',
  geolocation: 'Probable Infrastructure Geolocation',
  campaign_association: 'Campaign Association',
  lookalike_determination: 'Lookalike Domain Determination',
  malicious_url: 'Malicious URL Assessment',
  nlp_classification: 'NLP Behavioral Classification',
  attachment_risk: 'Attachment Threat Analysis'
};

export const EvidenceConfidencePanel: React.FC<EvidenceConfidencePanelProps> = ({
  isOpen,
  onClose,
  conclusions = [],
  selectedConclusionId,
  onSelectConclusion
}) => {
  const [activeId, setActiveId] = useState<string>(
    selectedConclusionId || (conclusions.length > 0 ? conclusions[0].conclusion_id : '')
  );

  // Sync activeId if selectedConclusionId changes
  React.useEffect(() => {
    if (selectedConclusionId) {
      setActiveId(selectedConclusionId);
    } else if (conclusions.length > 0) {
      setActiveId((prev) => prev || conclusions[0].conclusion_id);
    }
  }, [selectedConclusionId, conclusions]);

  const activeConclusion =
    conclusions.find((c) => c.conclusion_id === activeId) ||
    (conclusions.length > 0 ? conclusions[0] : null);

  const getLevelStyle = (level: ConfidenceLevel) => {
    switch (level) {
      case 'VERY HIGH':
        return {
          badge: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
          bar: 'bg-emerald-500',
          text: 'text-emerald-400',
          label: 'VERY HIGH CONFIDENCE'
        };
      case 'HIGH':
        return {
          badge: 'bg-cyan-500/15 text-cyan-400 border-cyan-500/30',
          bar: 'bg-cyan-500',
          text: 'text-cyan-400',
          label: 'HIGH CONFIDENCE'
        };
      case 'MODERATE':
        return {
          badge: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
          bar: 'bg-amber-500',
          text: 'text-amber-400',
          label: 'MODERATE CONFIDENCE'
        };
      case 'LOW':
      default:
        return {
          badge: 'bg-rose-500/15 text-rose-400 border-rose-500/30',
          bar: 'bg-rose-500',
          text: 'text-rose-400',
          label: 'LOW CONFIDENCE'
        };
    }
  };

  return (
    <Modal isOpen={isOpen} onClose={onClose} size="xl" className="max-w-4xl">
      <ModalHeader className="border-b border-border/80 pb-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2.5">
            <div className="p-2 rounded-lg bg-primary/10 border border-primary/20 text-primary">
              <ShieldCheck className="w-5 h-5 text-primary" />
            </div>
            <div>
              <ModalTitle className="text-base font-semibold tracking-tight text-foreground flex items-center gap-2">
                Evidence Confidence Engine
                <span className="text-[11px] font-mono font-normal px-2 py-0.5 rounded-full bg-surface-secondary border border-border text-foreground-muted">
                  v{activeConclusion?.engine_version || '1.0.0'}
                </span>
              </ModalTitle>
              <ModalDescription className="text-xs text-foreground-muted mt-0.5">
                Multi-dimensional forensic evaluation, anti-double-counting, and explicit conflict detection
              </ModalDescription>
            </div>
          </div>
        </div>

        {/* Conclusion selector pills if multiple conclusions */}
        {conclusions.length > 1 && (
          <div className="flex items-center gap-1.5 overflow-x-auto pt-3 pb-1 scrollbar-thin">
            {conclusions.map((c) => {
              const isSelected = c.conclusion_id === (activeConclusion?.conclusion_id || '');
              const icon = TYPE_ICONS[c.type] || <Info className="w-3.5 h-3.5" />;
              const label = TYPE_LABELS[c.type] || c.type.replace(/_/g, ' ');
              const style = getLevelStyle(c.confidence_level);

              return (
                <button
                  key={c.conclusion_id}
                  onClick={() => {
                    setActiveId(c.conclusion_id);
                    onSelectConclusion?.(c.conclusion_id);
                  }}
                  className={`px-2.5 py-1.5 rounded-md text-xs font-medium flex items-center space-x-1.5 transition-all whitespace-nowrap border ${
                    isSelected
                      ? 'bg-surface-secondary border-primary/40 text-foreground shadow-xs'
                      : 'bg-surface/60 border-border/60 text-foreground-muted hover:text-foreground hover:bg-surface-secondary/50'
                  }`}
                >
                  <span>{icon}</span>
                  <span>{label}</span>
                  <span
                    className={`text-[10px] font-mono px-1.5 py-0.2 rounded-full border ${style.badge}`}
                  >
                    {Math.round(c.confidence_score)}%
                  </span>
                </button>
              );
            })}
          </div>
        )}
      </ModalHeader>

      <ModalBody className="p-6 space-y-6">
        {!activeConclusion ? (
          <div className="py-12 text-center text-foreground-muted text-sm">
            No forensic conclusions available for this artifact.
          </div>
        ) : (
          <>
            {/* 1. WHAT DO WE BELIEVE & 2. HOW CONFIDENT ARE WE */}
            <div className="p-4 rounded-xl bg-surface-secondary/50 border border-border space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div className="flex items-center space-x-2">
                  <span className="p-1.5 rounded-md bg-surface border border-border">
                    {TYPE_ICONS[activeConclusion.type] || <ShieldCheck className="w-4 h-4 text-primary" />}
                  </span>
                  <div>
                    <span className="text-[11px] font-mono uppercase tracking-wider text-foreground-muted">
                      1. Forensic Assessment
                    </span>
                    <h3 className="text-sm font-semibold text-foreground">
                      {TYPE_LABELS[activeConclusion.type] || activeConclusion.type.replace(/_/g, ' ')}
                    </h3>
                  </div>
                </div>

                {/* Confidence Level Badge & Score Gauge */}
                <div className="flex items-center space-x-3 self-start sm:self-auto">
                  <div className="text-right">
                    <div className="text-[10px] font-mono uppercase tracking-wider text-foreground-muted">
                      Confidence Level
                    </div>
                    <div className="text-sm font-bold font-mono text-foreground flex items-center justify-end space-x-1.5">
                      <span>{Math.round(activeConclusion.confidence_score)}%</span>
                      <span className="text-foreground-muted font-normal">—</span>
                      <span className={getLevelStyle(activeConclusion.confidence_level).text}>
                        {activeConclusion.confidence_level}
                      </span>
                    </div>
                  </div>

                  <div className="w-16 sm:w-24 bg-surface rounded-full h-2.5 overflow-hidden border border-border/80">
                    <div
                      className={`h-full rounded-full transition-all duration-500 ${getLevelStyle(activeConclusion.confidence_level).bar}`}
                      style={{ width: `${Math.max(5, Math.min(100, Math.round(activeConclusion.confidence_score)))}%` }}
                    />
                  </div>
                </div>
              </div>

              {/* Statement box (What do we believe?) */}
              <div className="p-3.5 rounded-lg bg-surface border border-border/90">
                <div className="text-[10px] font-mono text-foreground-muted uppercase tracking-wider mb-1 flex items-center gap-1.5">
                  <HelpCircle className="w-3 h-3 text-primary" />
                  What do we believe?
                </div>
                <p className="text-sm text-foreground font-medium leading-relaxed">
                  {activeConclusion.statement}
                </p>
              </div>
            </div>

            {/* 3. WHICH EVIDENCE SUPPORTS IT? */}
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  <h4 className="text-xs font-semibold uppercase tracking-wider text-foreground">
                    3. Supporting Evidence ({activeConclusion.supporting_evidence.length})
                  </h4>
                </div>
                <span className="text-[11px] text-foreground-muted">
                  Weighted by Reliability &amp; Independence
                </span>
              </div>

              {activeConclusion.supporting_evidence.length === 0 ? (
                <div className="p-3.5 rounded-lg bg-surface border border-border/60 text-xs text-foreground-muted">
                  No affirmative supporting evidence recorded for this claim.
                </div>
              ) : (
                <div className="space-y-2">
                  {activeConclusion.supporting_evidence.map((ev, idx) => (
                    <div
                      key={ev.evidence_id || idx}
                      className="p-3 rounded-lg bg-surface border border-border/80 hover:border-border transition-colors space-y-2"
                    >
                      <div className="flex items-start justify-between gap-3">
                        <div className="flex items-start space-x-2">
                          <Check className="w-3.5 h-3.5 text-emerald-400 mt-0.5 shrink-0" />
                          <div>
                            <p className="text-xs text-foreground font-medium leading-snug">
                              {ev.statement}
                            </p>
                            <div className="flex flex-wrap items-center gap-2 mt-1.5 text-[10px] font-mono text-foreground-muted">
                              <span className="px-1.5 py-0.2 rounded bg-surface-secondary border border-border">
                                {ev.source_module}
                              </span>
                              <span className="px-1.5 py-0.2 rounded bg-surface-secondary border border-border">
                                Category: {ev.evidence_category.replace(/_/g, ' ')}
                              </span>
                              {ev.independence_cluster && (
                                <span className="px-1.5 py-0.2 rounded bg-amber-500/10 text-amber-300 border border-amber-500/20" title="Correlated feeds grouped to prevent double counting">
                                  Cluster: {ev.independence_cluster}
                                </span>
                              )}
                            </div>
                          </div>
                        </div>

                        <div className="text-right shrink-0">
                          <span className="text-xs font-mono font-semibold text-emerald-400">
                            +{Math.round(ev.effective_weight || ev.raw_score_contribution)} pts
                          </span>
                          <div className="text-[10px] text-foreground-muted font-mono">
                            Rel: {Math.round(ev.reliability * 100)}%
                          </div>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* 4. WHICH EVIDENCE CONTRADICTS IT? */}
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <AlertTriangle className="w-4 h-4 text-amber-400" />
                  <h4 className="text-xs font-semibold uppercase tracking-wider text-foreground">
                    4. Conflicting Evidence ({activeConclusion.conflicting_evidence.length})
                  </h4>
                </div>
                {activeConclusion.conflicting_evidence.length > 0 && (
                  <span className="text-[11px] font-mono text-amber-400 font-medium">
                    Explicitly surfaced contradictions
                  </span>
                )}
              </div>

              {activeConclusion.conflicting_evidence.length === 0 ? (
                <div className="p-3 rounded-lg bg-emerald-500/5 border border-emerald-500/20 text-xs text-emerald-300/80 flex items-center space-x-2">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                  <span>No contradictory evidence detected. All observed forensic signals align.</span>
                </div>
              ) : (
                <div className="space-y-2">
                  {activeConclusion.conflicting_evidence.map((ev, idx) => (
                    <div
                      key={ev.evidence_id || idx}
                      className="p-3 rounded-lg bg-amber-500/5 border border-amber-500/30 space-y-2"
                    >
                      <div className="flex items-start justify-between gap-3">
                        <div className="flex items-start space-x-2">
                          <AlertTriangle className="w-3.5 h-3.5 text-amber-400 mt-0.5 shrink-0" />
                          <div>
                            <p className="text-xs text-foreground font-medium leading-snug">
                              {ev.statement}
                            </p>
                            <div className="flex flex-wrap items-center gap-2 mt-1.5 text-[10px] font-mono text-foreground-muted">
                              <span className="px-1.5 py-0.2 rounded bg-surface-secondary border border-border">
                                {ev.source_module}
                              </span>
                              <span className="px-1.5 py-0.2 rounded bg-amber-500/10 text-amber-300 border border-amber-500/20">
                                Contradiction Penalty
                              </span>
                            </div>
                          </div>
                        </div>

                        <div className="text-right shrink-0">
                          <span className="text-xs font-mono font-semibold text-rose-400">
                            {Math.round(ev.effective_weight || ev.raw_score_contribution)} pts
                          </span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* 5. WHAT LIMITATIONS APPLY? */}
            <div className="space-y-2">
              <div className="flex items-center space-x-2">
                <Info className="w-4 h-4 text-foreground-muted" />
                <h4 className="text-xs font-semibold uppercase tracking-wider text-foreground">
                  5. Applicable Limitations &amp; Boundary Notices
                </h4>
              </div>

              <div className="p-3.5 rounded-lg bg-surface border border-border/80 space-y-1.5">
                {activeConclusion.limitations && activeConclusion.limitations.length > 0 ? (
                  activeConclusion.limitations.map((lim, idx) => (
                    <div key={idx} className="flex items-start space-x-2 text-xs text-foreground-muted leading-relaxed">
                      <span className="text-primary mt-0.5">•</span>
                      <span>{lim}</span>
                    </div>
                  ))
                ) : (
                  <p className="text-xs text-foreground-muted">
                    Standard probabilistic inference limitations apply. Telemetry is subject to upstream provider latency and adversary evasion techniques.
                  </p>
                )}
              </div>
            </div>

            {/* Source Modules & Engine Footer */}
            <div className="p-3 rounded-lg bg-surface-secondary/40 border border-border/60 flex flex-wrap items-center justify-between gap-3 text-[11px] font-mono text-foreground-muted">
              <div className="flex items-center space-x-2">
                <span>Contributing Modules:</span>
                <span className="text-foreground">
                  {activeConclusion.source_modules.join(', ')}
                </span>
              </div>
              <div className="flex items-center space-x-4">
                <span>ID: {activeConclusion.conclusion_id}</span>
                <span>Evaluated: {new Date(activeConclusion.generated_at).toLocaleTimeString()}</span>
              </div>
            </div>
          </>
        )}
      </ModalBody>

      <ModalFooter className="flex items-center justify-between border-t border-border">
        <div className="text-xs text-foreground-muted font-sans">
          Ground truth verification active &bull; Anti-double-counting enabled
        </div>
        <Button variant="secondary" size="sm" onClick={onClose}>
          Close Panel
        </Button>
      </ModalFooter>
    </Modal>
  );
};
