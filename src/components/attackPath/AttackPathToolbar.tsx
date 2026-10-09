import React from 'react';
import {
  SlidersHorizontal,
  RotateCcw,
  CheckCircle2,
  CircleDot,
  HelpCircle,
  LayoutGrid,
  ListOrdered,
} from 'lucide-react';
import { Button } from '../ui';
import type { AttackPathFilterState } from '../../types/attackPath';

interface AttackPathToolbarProps {
  filters: AttackPathFilterState;
  onFilterChange: (filters: AttackPathFilterState) => void;
  onResetFilters: () => void;
  activeFilterCount: number;
  tacticsList: string[];
  layoutMode: 'vertical' | 'grid';
  onLayoutModeChange: (mode: 'vertical' | 'grid') => void;
}

export const AttackPathToolbar: React.FC<AttackPathToolbarProps> = ({
  filters,
  onFilterChange,
  onResetFilters,
  activeFilterCount,
  tacticsList,
  layoutMode,
  onLayoutModeChange,
}) => {
  return (
    <div className="bg-surface-secondary/60 border border-border rounded-xl p-3.5 shadow-2xs space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-3 text-xs font-mono">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-[10px] uppercase font-bold text-foreground-muted tracking-wider flex items-center space-x-1">
            <SlidersHorizontal className="w-3 h-3" />
            <span>Certainty Filter:</span>
          </span>

          {/* Toggle Observed */}
          <button
            type="button"
            onClick={() => onFilterChange({ ...filters, showObserved: !filters.showObserved })}
            className={`px-2.5 py-1 rounded-lg border text-[11px] font-mono transition-all cursor-pointer flex items-center space-x-1.5 ${
              filters.showObserved
                ? 'bg-success/15 border-success/30 text-success font-semibold'
                : 'bg-surface border-border text-foreground-muted opacity-60'
            }`}
          >
            <CheckCircle2 className="w-3 h-3" />
            <span>Observed</span>
          </button>

          {/* Toggle Derived */}
          <button
            type="button"
            onClick={() => onFilterChange({ ...filters, showDerived: !filters.showDerived })}
            className={`px-2.5 py-1 rounded-lg border text-[11px] font-mono transition-all cursor-pointer flex items-center space-x-1.5 ${
              filters.showDerived
                ? 'bg-accent/15 border-accent/30 text-accent font-semibold'
                : 'bg-surface border-border text-foreground-muted opacity-60'
            }`}
          >
            <CircleDot className="w-3 h-3" />
            <span>Derived</span>
          </button>

          {/* Toggle Inferred */}
          <button
            type="button"
            onClick={() => onFilterChange({ ...filters, showInferred: !filters.showInferred })}
            className={`px-2.5 py-1 rounded-lg border text-[11px] font-mono transition-all cursor-pointer flex items-center space-x-1.5 ${
              filters.showInferred
                ? 'bg-warning/15 border-warning/30 text-warning font-semibold'
                : 'bg-surface border-border text-foreground-muted opacity-60'
            }`}
          >
            <HelpCircle className="w-3 h-3" />
            <span>Inferred</span>
          </button>
        </div>

        {/* Tactic Selector & Layout Mode */}
        <div className="flex flex-wrap items-center gap-2">
          {tacticsList.length > 0 && (
            <div className="flex items-center space-x-1.5">
              <span className="text-[10px] uppercase text-foreground-muted">Tactic:</span>
              <select
                aria-label="Filter by MITRE Tactic"
                value={filters.selectedTactic}
                onChange={(e) => onFilterChange({ ...filters, selectedTactic: e.target.value })}
                className="bg-surface border border-border rounded-lg px-2 py-1 text-[11px] font-mono text-foreground focus:outline-hidden focus:ring-1 focus:ring-accent"
              >
                <option value="ALL">All Tactics</option>
                {tacticsList.map((t) => (
                  <option key={t} value={t}>
                    {t}
                  </option>
                ))}
              </select>
            </div>
          )}

          {/* Layout Mode Toggle */}
          <div className="flex items-center bg-surface border border-border rounded-lg p-0.5">
            <button
              type="button"
              onClick={() => onLayoutModeChange('vertical')}
              className={`p-1 rounded text-xs transition-colors cursor-pointer ${
                layoutMode === 'vertical' ? 'bg-accent text-accent-foreground' : 'text-foreground-muted hover:text-foreground'
              }`}
              title="Sequential Vertical Flow"
            >
              <ListOrdered className="w-3.5 h-3.5" />
            </button>
            <button
              type="button"
              onClick={() => onLayoutModeChange('grid')}
              className={`p-1 rounded text-xs transition-colors cursor-pointer ${
                layoutMode === 'grid' ? 'bg-accent text-accent-foreground' : 'text-foreground-muted hover:text-foreground'
              }`}
              title="Stage Grid View"
            >
              <LayoutGrid className="w-3.5 h-3.5" />
            </button>
          </div>

          {/* Reset Filters */}
          {activeFilterCount > 0 && (
            <Button
              size="xs"
              variant="ghost"
              onClick={onResetFilters}
              leftIcon={<RotateCcw className="w-3 h-3" />}
              className="text-[10px] font-mono text-foreground-muted hover:text-foreground"
            >
              Reset ({activeFilterCount})
            </Button>
          )}
        </div>
      </div>
    </div>
  );
};
