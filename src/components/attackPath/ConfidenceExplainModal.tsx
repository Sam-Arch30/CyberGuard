import React from 'react';
import {
  AlertTriangle,
  Info,
  X,
  Gauge,
} from 'lucide-react';
import { Badge, Button } from '../ui';
import type { AttackPathDetailResponse } from '../../types/attackPath';

interface ConfidenceExplainModalProps {
  isOpen: boolean;
  onClose: () => void;
  pathData: AttackPathDetailResponse;
}

export const ConfidenceExplainModal: React.FC<ConfidenceExplainModalProps> = ({
  isOpen,
  onClose,
  pathData,
}) => {
  if (!isOpen) return null;

  const scorePct = Math.round(pathData.confidence * 100);
  const components = pathData.confidence_components || {};
  const bottleneck = pathData.confidence_bottleneck;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-xs animate-in fade-in duration-150">
      <div className="bg-surface border border-border rounded-2xl max-w-lg w-full p-6 shadow-xl space-y-5 animate-in zoom-in-95 duration-150 max-h-[90vh] overflow-y-auto">
        {/* Modal Header */}
        <div className="flex items-start justify-between">
          <div className="space-y-1">
            <div className="flex items-center space-x-2">
              <span className="p-1.5 rounded-lg bg-accent/10 text-accent">
                <Gauge className="w-4 h-4" />
              </span>
              <h2 className="text-sm font-semibold text-foreground font-sans">
                Calibrated Path Confidence Explanation
              </h2>
            </div>
            <p className="text-xs font-mono text-foreground-muted">
              Section 18 Evidence-Constrained Explainability Projection
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="p-1 rounded-lg text-foreground-muted hover:text-foreground hover:bg-surface-secondary cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Big Score Box */}
        <div className="p-4 rounded-xl bg-surface-secondary/70 border border-border flex items-center justify-between">
          <div>
            <div className="text-[10px] font-mono uppercase text-foreground-muted">
              Overall Calibrated Score
            </div>
            <div className="text-2xl font-bold font-mono text-foreground mt-0.5">
              {scorePct}%
            </div>
          </div>
          <Badge
            variant={scorePct >= 75 ? 'success' : scorePct >= 40 ? 'primary' : 'warning'}
            size="md"
            className="font-mono text-xs uppercase font-bold"
          >
            {pathData.confidence_level} CONFIDENCE
          </Badge>
        </div>

        {/* Crucial Definition Callout */}
        <div className="p-3.5 rounded-xl bg-surface-secondary/40 border border-border text-xs font-mono text-foreground-muted flex items-start space-x-2.5">
          <Info className="w-4 h-4 text-accent shrink-0 mt-0.5" />
          <p className="leading-relaxed">
            Confidence measures the empirical strength of evidence supporting this reconstructed progression. It does not measure attacker probability, human identity certainty, or organizational risk score.
          </p>
        </div>

        {/* Confidence Bottleneck if identified */}
        {bottleneck && Object.keys(bottleneck).length > 0 && (
          <div className="p-3.5 rounded-xl bg-warning/10 border border-warning/30 text-xs font-mono space-y-1">
            <div className="text-[10px] font-bold uppercase tracking-wider text-warning flex items-center space-x-1.5">
              <AlertTriangle className="w-3.5 h-3.5" />
              <span>Primary Confidence Bottleneck</span>
            </div>
            <p className="text-foreground leading-relaxed">
              {bottleneck.reason || bottleneck.description || JSON.stringify(bottleneck)}
            </p>
          </div>
        )}

        {/* Contributing Factors & Components */}
        {Object.keys(components).length > 0 && (
          <div className="space-y-2">
            <h4 className="text-[11px] font-mono uppercase font-bold text-foreground-muted tracking-wider">
              Score Component Breakdown
            </h4>
            <div className="space-y-1.5">
              {Object.entries(components).map(([k, v]) => (
                <div
                  key={k}
                  className="p-2.5 rounded-lg bg-surface-secondary border border-border flex items-center justify-between text-xs font-mono"
                >
                  <span className="text-foreground-muted">{k.replace(/_/g, ' ').toUpperCase()}</span>
                  <span className="font-semibold text-foreground">
                    {typeof v === 'number' ? `${Math.round(v * 100)}%` : String(v)}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Analytical Limitations */}
        {pathData.limitations.length > 0 && (
          <div className="space-y-2">
            <h4 className="text-[11px] font-mono uppercase font-bold text-foreground-muted tracking-wider">
              Reconstruction Caveats & Boundaries
            </h4>
            <ul className="space-y-1 text-xs font-mono text-foreground-muted list-disc list-inside">
              {pathData.limitations.map((lim, i) => (
                <li key={i}>{lim}</li>
              ))}
            </ul>
          </div>
        )}

        {/* Footer */}
        <div className="pt-2 flex justify-end">
          <Button size="sm" variant="outline" onClick={onClose} className="font-mono text-xs">
            Close Explanation
          </Button>
        </div>
      </div>
    </div>
  );
};
