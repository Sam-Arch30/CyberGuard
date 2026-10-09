import React from 'react';
import {
  HelpCircle,
  AlertTriangle,
  FileQuestion,
  AlertCircle,
} from 'lucide-react';
import { Badge } from '../ui';
import type {
  AttackGapProjection,
  AttackContradictionProjection,
} from '../../types/attackPath';

interface PathGapsAndContradictionsProps {
  gaps: AttackGapProjection[];
  contradictions: AttackContradictionProjection[];
}

export const PathGapsAndContradictions: React.FC<PathGapsAndContradictionsProps> = ({
  gaps,
  contradictions,
}) => {
  if (gaps.length === 0 && contradictions.length === 0) {
    return null;
  }

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
      {/* Evidence Gaps */}
      {gaps.length > 0 && (
        <div className="bg-surface border border-border rounded-xl p-4 shadow-xs space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <span className="p-1 rounded-md bg-warning/10 text-warning">
                <FileQuestion className="w-4 h-4" />
              </span>
              <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-foreground">
                Explicit Evidence Gaps ({gaps.length})
              </h3>
            </div>
            <Badge variant="warning" size="sm" className="font-mono text-[9px] uppercase">
              Telemetry Gap
            </Badge>
          </div>

          <p className="text-[11px] font-mono text-foreground-muted leading-relaxed">
            Missing telemetry prevents authoritative confirmation of these intermediate transitions:
          </p>

          <div className="space-y-2">
            {gaps.map((gap) => (
              <div
                key={gap.id}
                className="p-3 rounded-lg bg-surface-secondary/70 border border-border space-y-1.5 text-xs font-mono"
              >
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-foreground flex items-center space-x-1.5">
                    <HelpCircle className="w-3.5 h-3.5 text-warning shrink-0" />
                    <span>{gap.title}</span>
                  </span>
                  <span className="text-[10px] text-foreground-muted uppercase font-mono">
                    {gap.category}
                  </span>
                </div>
                <p className="text-[11px] text-foreground-muted leading-relaxed">
                  {gap.description}
                </p>
                <div className="text-[10px] text-warning/90 font-medium pt-1 border-t border-border/50">
                  Impact: {gap.impact}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Contradictory Evidence */}
      {contradictions.length > 0 && (
        <div className="bg-surface border border-border rounded-xl p-4 shadow-xs space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <span className="p-1 rounded-md bg-danger/10 text-danger">
                <AlertCircle className="w-4 h-4" />
              </span>
              <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-foreground">
                Contradictions & Conflicting Evidence ({contradictions.length})
              </h3>
            </div>
            <Badge variant="danger" size="sm" className="font-mono text-[9px] uppercase">
              Assessment Impact
            </Badge>
          </div>

          <p className="text-[11px] font-mono text-foreground-muted leading-relaxed">
            Telemetry features that contradict a straightforward kill-chain progression:
          </p>

          <div className="space-y-2">
            {contradictions.map((contra) => (
              <div
                key={contra.id}
                className="p-3 rounded-lg bg-danger/5 border border-danger/20 space-y-1.5 text-xs font-mono"
              >
                <div className="flex items-center space-x-1.5 font-semibold text-foreground">
                  <AlertTriangle className="w-3.5 h-3.5 text-danger shrink-0" />
                  <span>{contra.title}</span>
                </div>
                <p className="text-[11px] text-foreground-muted leading-relaxed">
                  {contra.description}
                </p>
                <div className="text-[10px] text-danger/90 font-medium pt-1 border-t border-danger/20">
                  Assessment impact: {contra.assessment_impact}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
