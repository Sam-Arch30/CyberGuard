import React from 'react';
import {
  GitBranch,
  Shield,
} from 'lucide-react';
import { Badge } from '../ui';
import type { AttackAlternativeProjection } from '../../types/attackPath';

interface AlternativeHypothesesPanelProps {
  alternatives: AttackAlternativeProjection[];
}

export const AlternativeHypothesesPanel: React.FC<AlternativeHypothesesPanelProps> = ({
  alternatives,
}) => {
  if (!alternatives || alternatives.length === 0) {
    return null;
  }

  return (
    <div className="bg-surface border border-border rounded-xl p-4 shadow-xs space-y-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-2">
          <span className="p-1 rounded-md bg-accent/10 text-accent">
            <GitBranch className="w-4 h-4" />
          </span>
          <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-foreground">
            Alternative Attack Hypotheses ({alternatives.length})
          </h3>
        </div>
        <Badge variant="outline" size="sm" className="font-mono text-[9px] uppercase">
          Section 17 Hypotheses
        </Badge>
      </div>

      <p className="text-[11px] font-mono text-foreground-muted leading-relaxed">
        The AI Attack Reconstruction Engine evaluated these competing scenarios based on available telemetry:
      </p>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {alternatives.map((alt) => (
            <div
              key={alt.id}
              className={`p-3.5 rounded-lg border text-left transition-all space-y-2 ${
                alt.is_primary
                  ? 'bg-accent/5 border-accent/30'
                  : 'bg-surface-secondary/60 border-border hover:border-border-focus'
              }`}
            >
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center space-x-1.5 min-w-0">
                  {alt.is_primary ? (
                    <Badge variant="primary" size="sm" className="font-mono text-[9px] uppercase font-bold shrink-0">
                      Primary Path
                    </Badge>
                  ) : (
                    <Badge variant="outline" size="sm" className="font-mono text-[9px] uppercase font-bold shrink-0">
                      Alternative
                    </Badge>
                  )}
                  <span className="text-[10px] font-mono text-foreground-muted uppercase">
                    Status: {alt.status}
                  </span>
                </div>
                <div className="flex items-center space-x-1 text-[10px] font-mono font-bold text-accent shrink-0">
                  <Shield className="w-3 h-3" />
                  <span>{Math.round(alt.confidence * 100)}% ({alt.confidence_level})</span>
                </div>
              </div>

              <h4 className="text-xs font-semibold font-sans text-foreground">
                {alt.title}
              </h4>

              {alt.description && (
                <p className="text-[11px] font-mono text-foreground-muted leading-relaxed">
                  {alt.description}
                </p>
              )}

              {/* Missing Telemetry for this hypothesis */}
              {alt.missing_evidence.length > 0 && (
                <div className="text-[10px] font-mono text-warning/90 space-y-0.5 pt-1 border-t border-border/50">
                  <span className="font-bold uppercase tracking-wider">Unverified Conditions:</span>
                  <ul className="list-disc list-inside">
                    {alt.missing_evidence.map((me, i) => (
                      <li key={i}>{me}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          ))}
      </div>
    </div>
  );
};
