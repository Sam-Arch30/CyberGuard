import React from 'react';
import { ChevronRight, ArrowLeft, RotateCcw, Compass } from 'lucide-react';
import type { PivotHistoryStep } from '../../../types/pivots';

interface PivotBreadcrumbsProps {
  history: PivotHistoryStep[];
  currentIndex: number;
  onNavigate: (index: number) => void;
  onReset: () => void;
}

export const PivotBreadcrumbs: React.FC<PivotBreadcrumbsProps> = ({
  history,
  currentIndex,
  onNavigate,
  onReset,
}) => {
  if (history.length === 0) return null;

  return (
    <div className="flex items-center justify-between px-4 py-2.5 bg-surface-secondary/70 border-b border-border text-xs">
      <div className="flex items-center space-x-2 overflow-x-auto py-1 scrollbar-thin">
        <div className="flex items-center space-x-1.5 text-foreground-muted shrink-0 mr-1 font-mono text-[11px]">
          <Compass className="w-3.5 h-3.5 text-primary" />
          <span>Trail ({history.length} hops):</span>
        </div>

        {history.map((step, idx) => {
          const isCurrent = idx === currentIndex;
          return (
            <React.Fragment key={`${step.source_value}-${idx}`}>
              {idx > 0 && (
                <ChevronRight className="w-3.5 h-3.5 text-foreground-muted/40 shrink-0" />
              )}
              <button
                onClick={() => onNavigate(idx)}
                className={`flex items-center space-x-1.5 px-2.5 py-1 rounded-control text-xs font-mono transition-all cursor-pointer shrink-0 ${
                  isCurrent
                    ? 'bg-primary text-white font-medium shadow-xs'
                    : 'bg-surface hover:bg-surface-secondary text-foreground-muted hover:text-foreground border border-border'
                }`}
                title={`Hop ${idx}: ${step.source_type} -> ${step.source_value}`}
              >
                <span className="text-[10px] uppercase font-bold opacity-75">
                  {step.source_type}
                </span>
                <span className="truncate max-w-[140px]">{step.source_value}</span>
                {step.pivot_type && (
                  <span className="text-[9px] px-1 py-0.2 bg-black/20 rounded-xs">
                    {step.pivot_type.split('_').slice(0, 2).join(' ')}
                  </span>
                )}
              </button>
            </React.Fragment>
          );
        })}
      </div>

      <div className="flex items-center space-x-2 shrink-0 ml-3">
        <button
          onClick={() => currentIndex > 0 && onNavigate(currentIndex - 1)}
          disabled={currentIndex <= 0}
          className="p-1 text-foreground-muted hover:text-foreground disabled:opacity-30 disabled:cursor-not-allowed rounded-control hover:bg-surface border border-transparent hover:border-border transition-colors cursor-pointer"
          title="Back one hop"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
        </button>
        <button
          onClick={onReset}
          className="p-1 text-foreground-muted hover:text-threat-critical rounded-control hover:bg-surface border border-transparent hover:border-border transition-colors cursor-pointer"
          title="Reset trail to root"
        >
          <RotateCcw className="w-3.5 h-3.5" />
        </button>
      </div>
    </div>
  );
};
