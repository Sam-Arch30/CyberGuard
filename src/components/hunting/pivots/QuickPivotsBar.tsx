import React, { useState } from 'react';
import {
  Server,
  Activity,
  ShieldAlert,
  Zap,
  Clock,
  Layers,
} from 'lucide-react';
import type { PivotDefinition, PivotType, PivotCategory, PivotCostClass } from '../../../types/pivots';

interface QuickPivotsBarProps {
  availablePivots: PivotDefinition[];
  activePivotType?: PivotType;
  onSelectPivot: (pivotType: PivotType) => void;
  isLoading: boolean;
}

export const QuickPivotsBar: React.FC<QuickPivotsBarProps> = ({
  availablePivots,
  activePivotType,
  onSelectPivot,
  isLoading,
}) => {
  const [selectedCategory, setSelectedCategory] = useState<PivotCategory>('INFRASTRUCTURE');

  const categories: { key: PivotCategory; label: string; icon: React.FC<{ className?: string }> }[] = [
    { key: 'INFRASTRUCTURE', label: 'Infrastructure', icon: Server },
    { key: 'ACTIVITY', label: 'Activity & Telemetry', icon: Activity },
    { key: 'SECURITY', label: 'Security & Graph', icon: ShieldAlert },
  ];

  const categoryPivots = availablePivots.filter((p) => p.category === selectedCategory);

  const getCostBadge = (cost: PivotCostClass) => {
    switch (cost) {
      case 'FAST':
        return (
          <span className="flex items-center text-[9px] px-1 py-0.5 rounded-control font-mono font-medium bg-emerald-500/10 text-emerald-500 border border-emerald-500/20">
            <Zap className="w-2.5 h-2.5 mr-0.5" /> Fast
          </span>
        );
      case 'NORMAL':
        return (
          <span className="flex items-center text-[9px] px-1 py-0.5 rounded-control font-mono font-medium bg-blue-500/10 text-blue-400 border border-blue-500/20">
            Normal
          </span>
        );
      case 'EXPENSIVE':
        return (
          <span className="flex items-center text-[9px] px-1 py-0.5 rounded-control font-mono font-medium bg-amber-500/10 text-amber-500 border border-amber-500/20">
            <Clock className="w-2.5 h-2.5 mr-0.5" /> Heavy
          </span>
        );
      case 'BACKGROUND':
        return (
          <span className="flex items-center text-[9px] px-1 py-0.5 rounded-control font-mono font-medium bg-purple-500/10 text-purple-400 border border-purple-500/20">
            <Layers className="w-2.5 h-2.5 mr-0.5" /> Async
          </span>
        );
    }
  };

  return (
    <div className="bg-surface border-b border-border p-3.5 space-y-3">
      {/* Category Tabs */}
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-1.5 p-0.5 bg-surface-secondary rounded-control border border-border">
          {categories.map((cat) => {
            const Icon = cat.icon;
            const count = availablePivots.filter((p) => p.category === cat.key).length;
            const isSelected = selectedCategory === cat.key;
            return (
              <button
                key={cat.key}
                onClick={() => setSelectedCategory(cat.key)}
                className={`flex items-center space-x-1.5 px-3 py-1 rounded-control text-xs font-mono transition-all cursor-pointer ${
                  isSelected
                    ? 'bg-surface text-primary font-semibold shadow-xs border border-border/80'
                    : 'text-foreground-muted hover:text-foreground hover:bg-surface/50 border border-transparent'
                }`}
              >
                <Icon className="w-3.5 h-3.5" />
                <span>{cat.label}</span>
                <span className="text-[10px] px-1.5 py-0.2 rounded-full bg-border text-foreground-muted">
                  {count}
                </span>
              </button>
            );
          })}
        </div>

        <div className="text-[11px] font-mono text-foreground-muted flex items-center space-x-1">
          <span>{availablePivots.length} pivots available</span>
        </div>
      </div>

      {/* Pivots Pills Grid */}
      <div className="flex flex-wrap gap-2">
        {categoryPivots.length === 0 ? (
          <div className="text-xs text-foreground-muted font-mono py-2 italic">
            No pivots defined in this category for the selected observable type.
          </div>
        ) : (
          categoryPivots.map((p) => {
            const isActive = activePivotType === p.pivot_type;
            return (
              <button
                key={p.pivot_type}
                onClick={() => onSelectPivot(p.pivot_type)}
                disabled={isLoading}
                className={`flex items-center space-x-2 px-3 py-2 rounded-control text-xs font-mono transition-all cursor-pointer border text-left ${
                  isActive
                    ? 'bg-primary/10 border-primary text-primary font-semibold shadow-xs ring-1 ring-primary/40'
                    : 'bg-surface hover:bg-surface-secondary/70 border-border text-foreground hover:border-foreground-muted/40'
                } ${isLoading ? 'opacity-50 cursor-not-allowed' : ''}`}
                title={p.description}
              >
                <div>
                  <div className="flex items-center space-x-1.5">
                    <span className="font-medium">{p.display_name}</span>
                    {getCostBadge(p.cost_class)}
                  </div>
                  <div className="text-[10px] text-foreground-muted font-normal mt-0.5">
                    → {p.target_type} ({p.relationship_name})
                  </div>
                </div>
              </button>
            );
          })
        )}
      </div>
    </div>
  );
};
