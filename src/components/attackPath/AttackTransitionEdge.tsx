import React, { useState } from 'react';
import {
  ArrowDown,
  Clock,
  Link2,
  CheckCircle2,
  HelpCircle,
  ChevronDown,
} from 'lucide-react';
import { Badge } from '../ui';
import type { AttackTransitionProjection } from '../../types/attackPath';

interface AttackTransitionEdgeProps {
  transition: AttackTransitionProjection;
  orientation?: 'vertical' | 'horizontal';
  sourceTitle?: string;
  targetTitle?: string;
}

export const AttackTransitionEdge: React.FC<AttackTransitionEdgeProps> = ({
  transition,
  orientation = 'vertical',
}) => {
  const [isExpanded, setIsExpanded] = useState(false);

  const isCausal = transition.is_causal;

  // Visual styling depending on causal vs temporal link
  const badgeVariant = isCausal ? 'success' : transition.relationship_type === 'TEMPORAL_LINK' ? 'outline' : 'primary';

  return (
    <div className={`my-2 flex flex-col items-center justify-center transition-all ${orientation === 'horizontal' ? 'px-2' : 'py-1'}`}>
      {/* Edge Connector Line & Arrow */}
      <div className="flex flex-col items-center">
        <div className={`w-0.5 h-3 ${isCausal ? 'bg-success' : 'bg-border'}`} />

        <button
          type="button"
          onClick={() => setIsExpanded(!isExpanded)}
          className={`px-2.5 py-1 rounded-full border text-[10px] font-mono transition-all flex items-center space-x-1.5 cursor-pointer shadow-2xs hover:scale-102 ${
            isCausal
              ? 'bg-success/10 border-success/30 text-success'
              : 'bg-surface-secondary border-border text-foreground-muted hover:border-border-focus'
          }`}
          title="Click to view transition provenance & temporal details"
        >
          {isCausal ? (
            <CheckCircle2 className="w-3 h-3 text-success shrink-0" />
          ) : (
            <Clock className="w-3 h-3 text-foreground-muted shrink-0" />
          )}

          <span className="font-semibold tracking-wider uppercase">
            {transition.relationship_label}
          </span>

          {transition.temporal_gap_formatted && (
            <span className="text-[9px] opacity-80">
              · {transition.temporal_gap_formatted}
            </span>
          )}

          <ChevronDown className={`w-3 h-3 transition-transform ${isExpanded ? 'rotate-180' : ''}`} />
        </button>

        <div className={`w-0.5 h-3 ${isCausal ? 'bg-success' : 'bg-border'}`} />
        <ArrowDown className={`w-3.5 h-3.5 -mt-1 ${isCausal ? 'text-success' : 'text-foreground-muted'}`} />
      </div>

      {/* Expandable Transition Details */}
      {isExpanded && (
        <div className="mt-2 w-full max-w-md p-3 rounded-lg bg-surface-secondary border border-border text-left shadow-xs space-y-2 z-10 animate-in fade-in slide-in-from-top-1 duration-150">
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-accent">
              Transition Provenance
            </span>
            <Badge variant={badgeVariant} size="sm" className="font-mono text-[9px]">
              Confidence: {Math.round(transition.confidence * 100)}%
            </Badge>
          </div>

          <p className="text-xs font-mono text-foreground leading-relaxed">
            {transition.relationship_description}
          </p>

          {/* Causal Warning Disclaimer */}
          {!isCausal && (
            <div className="p-2 rounded bg-surface border border-border text-[10px] font-mono text-foreground-muted flex items-start space-x-1.5">
              <HelpCircle className="w-3.5 h-3.5 text-warning shrink-0 mt-0.5" />
              <span>
                Temporal proximity alone does not prove execution causality. Transition is preserved as correlation.
              </span>
            </div>
          )}

          {/* Shared Entities */}
          {transition.shared_entities.length > 0 && (
            <div className="pt-1 border-t border-border/60">
              <div className="text-[10px] font-mono uppercase text-foreground-muted mb-1 flex items-center space-x-1">
                <Link2 className="w-3 h-3" />
                <span>Shared Correlation Entities ({transition.shared_entities.length})</span>
              </div>
              <div className="flex flex-wrap gap-1">
                {transition.shared_entities.map((ent, i) => (
                  <span
                    key={i}
                    className="px-1.5 py-0.5 rounded bg-surface border border-border font-mono text-[10px] text-foreground truncate max-w-[200px]"
                  >
                    {ent}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
