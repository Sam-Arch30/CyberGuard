import React from 'react';
import { Sparkles, ArrowRight } from 'lucide-react';
import type { AIPivotRecommendationItem, PivotType } from '../../../types/pivots';

interface AIPivotRecommendationsProps {
  recommendations: AIPivotRecommendationItem[];
  onSelectPivot: (pivotType: PivotType) => void;
  isLoading: boolean;
}

export const AIPivotRecommendations: React.FC<AIPivotRecommendationsProps> = ({
  recommendations,
  onSelectPivot,
  isLoading,
}) => {
  if (recommendations.length === 0) {
    return (
      <div className="p-4 bg-surface border border-border rounded-panel text-center text-xs font-mono text-foreground-muted">
        No active heuristic recommendations generated for this observable.
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between text-xs font-mono text-foreground-muted">
        <div className="flex items-center space-x-1.5">
          <Sparkles className="w-3.5 h-3.5 text-primary" />
          <span className="font-semibold text-foreground">AI Guided Investigation Paths</span>
        </div>
        <span className="text-[10px]">Analyst-validated suggestions</span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
        {recommendations.map((rec) => (
          <div
            key={rec.pivot_type}
            className="p-3 bg-surface border border-border hover:border-primary/50 rounded-panel space-y-2 transition-all shadow-xs flex flex-col justify-between"
          >
            <div>
              <div className="flex items-center justify-between">
                <span className="font-mono text-xs font-bold text-foreground">
                  {rec.display_name}
                </span>
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded-control bg-primary/10 text-primary border border-primary/20">
                  {Math.round(rec.confidence * 100)}% Rec
                </span>
              </div>

              {/* Rationale */}
              <p className="text-xs text-foreground/80 mt-1 font-sans leading-relaxed">
                {rec.rationale}
              </p>

              {/* Expected Yield */}
              <div className="mt-2 text-[10px] font-mono text-foreground-muted">
                <span className="text-foreground-muted/80">Expected Yield:</span>{' '}
                <span className="text-foreground">{rec.expected_yield}</span>
              </div>
            </div>

            <div className="pt-2 border-t border-border/60 flex items-center justify-between">
              <span className="text-[9px] font-mono uppercase text-foreground-muted">
                Category: {rec.category}
              </span>

              <button
                onClick={() => onSelectPivot(rec.pivot_type)}
                disabled={isLoading}
                className="px-2.5 py-1 text-xs font-mono font-medium text-white bg-primary hover:bg-primary/90 disabled:opacity-50 rounded-control flex items-center space-x-1 cursor-pointer transition-colors shadow-xs"
              >
                <span>Follow Pivot</span>
                <ArrowRight className="w-3 h-3" />
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
