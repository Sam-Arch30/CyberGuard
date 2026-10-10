import React, { useState, useMemo } from 'react';
import {
  Share2,
  GitFork,
  CheckCircle2,
  XCircle,
  HelpCircle,
  Search,
  Eye,
  ShieldAlert,
  Compass,
  CheckSquare,
  Square,
  Clock,
  Database,
  Layers,
} from 'lucide-react';
import type {
  PivotResultItem,
  EvidenceClassification,
} from '../../../types/pivots';

interface PivotResultsListProps {
  items: PivotResultItem[];
  selectedItemIds: string[];
  onToggleSelect: (id: string) => void;
  onSelectAll: () => void;
  onClearSelection: () => void;
  onHopPivot: (item: PivotResultItem) => void;
  onClassifyEvidence?: (item: PivotResultItem, classification: EvidenceClassification) => void;
  onPromoteInvestigation: (items: PivotResultItem[]) => void;
  onPromoteWatchlist: (items: PivotResultItem[]) => void;
  onPivotToHunt: (items: PivotResultItem[]) => void;
  isLoading: boolean;
}

export const PivotResultsList: React.FC<PivotResultsListProps> = ({
  items,
  selectedItemIds,
  onToggleSelect,
  onClearSelection,
  onHopPivot,
  onClassifyEvidence,
  onPromoteInvestigation,
  onPromoteWatchlist,
  onPivotToHunt,
  isLoading,
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [originFilter, setOriginFilter] = useState<string>('ALL');
  const [minConfidence, setMinConfidence] = useState<number>(0);

  // Available origins
  const origins = useMemo(() => {
    const set = new Set<string>();
    items.forEach((it) => {
      if (it.origin) set.add(it.origin);
    });
    return Array.from(set);
  }, [items]);

  // Filtered items
  const filteredItems = useMemo(() => {
    return items.filter((item) => {
      if (minConfidence > 0 && item.confidence < minConfidence / 100) return false;
      if (originFilter !== 'ALL' && item.origin !== originFilter) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchesVal = item.target_value.toLowerCase().includes(q);
        const matchesType = item.target_type.toLowerCase().includes(q);
        const matchesRel = item.relationship_type.toLowerCase().includes(q);
        const matchesDesc = item.relationship_description.toLowerCase().includes(q);
        if (!matchesVal && !matchesType && !matchesRel && !matchesDesc) return false;
      }
      return true;
    });
  }, [items, searchQuery, originFilter, minConfidence]);

  const selectedItems = useMemo(() => {
    return items.filter((it) => selectedItemIds.includes(it.id));
  }, [items, selectedItemIds]);

  const getOriginBadge = (origin: string) => {
    if (origin.includes('GRAPH')) {
      return (
        <span className="px-1.5 py-0.5 rounded-control text-[9px] font-mono bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 flex items-center space-x-1">
          <Share2 className="w-2.5 h-2.5" />
          <span>Knowledge Graph</span>
        </span>
      );
    }
    if (origin.includes('INTEL')) {
      return (
        <span className="px-1.5 py-0.5 rounded-control text-[9px] font-mono bg-blue-500/10 text-blue-400 border border-blue-500/20 flex items-center space-x-1">
          <Database className="w-2.5 h-2.5" />
          <span>Threat Intel</span>
        </span>
      );
    }
    if (origin.includes('TELEMETRY')) {
      return (
        <span className="px-1.5 py-0.5 rounded-control text-[9px] font-mono bg-amber-500/10 text-amber-500 border border-amber-500/20 flex items-center space-x-1">
          <Layers className="w-2.5 h-2.5" />
          <span>Telemetry Evidence</span>
        </span>
      );
    }
    return (
      <span className="px-1.5 py-0.5 rounded-control text-[9px] font-mono bg-surface-secondary text-foreground-muted border border-border">
        {origin}
      </span>
    );
  };

  return (
    <div className="space-y-3">
      {/* 1. Filter Toolbar */}
      <div className="flex flex-wrap items-center justify-between gap-2.5 p-3 bg-surface-secondary/40 border border-border rounded-panel text-xs">
        <div className="flex items-center space-x-2 flex-1 min-w-[200px]">
          <div className="relative flex-1">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-foreground-muted" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Filter results by value, relation, or description..."
              className="w-full pl-8 pr-3 py-1.5 bg-surface border border-border rounded-control text-xs font-mono text-foreground focus:outline-hidden focus:border-primary"
            />
          </div>

          <select
            value={originFilter}
            onChange={(e) => setOriginFilter(e.target.value)}
            className="px-2.5 py-1.5 bg-surface border border-border rounded-control text-xs font-mono text-foreground"
          >
            <option value="ALL">All Provenance ({items.length})</option>
            {origins.map((o) => (
              <option key={o} value={o}>
                {o}
              </option>
            ))}
          </select>
        </div>

        <div className="flex items-center space-x-3 text-xs font-mono text-foreground-muted">
          <div className="flex items-center space-x-1.5">
            <span>Min Conf:</span>
            <input
              type="range"
              min={0}
              max={100}
              step={5}
              value={minConfidence}
              onChange={(e) => setMinConfidence(Number(e.target.value))}
              className="w-16 accent-primary"
            />
            <span className="w-7 text-right font-semibold text-foreground">
              {minConfidence}%
            </span>
          </div>

          <div className="border-l border-border pl-3 flex items-center space-x-1">
            <span>Showing:</span>
            <span className="font-semibold text-foreground">{filteredItems.length}</span>
            <span>of {items.length}</span>
          </div>
        </div>
      </div>

      {/* 2. Bulk Action Bar */}
      {selectedItems.length > 0 && (
        <div className="p-2.5 bg-primary/10 border border-primary/30 rounded-panel flex items-center justify-between text-xs font-mono animate-in fade-in slide-in-from-top-1">
          <div className="flex items-center space-x-2 text-foreground">
            <CheckSquare className="w-4 h-4 text-primary" />
            <span className="font-semibold">{selectedItems.length} item(s) selected</span>
            <button
              onClick={onClearSelection}
              className="text-foreground-muted hover:text-foreground underline ml-2 cursor-pointer"
            >
              Clear
            </button>
          </div>

          <div className="flex items-center space-x-2">
            <button
              onClick={() => onPivotToHunt(selectedItems)}
              className="px-2.5 py-1 text-xs font-mono bg-surface hover:bg-surface-secondary text-foreground border border-border rounded-control flex items-center space-x-1.5 cursor-pointer shadow-xs"
              title="Formulate a new hunt query using these selected targets"
            >
              <Compass className="w-3.5 h-3.5 text-primary" />
              <span>Hunt From Targets</span>
            </button>
            <button
              onClick={() => onPromoteWatchlist(selectedItems)}
              className="px-2.5 py-1 text-xs font-mono bg-surface hover:bg-surface-secondary text-foreground border border-border rounded-control flex items-center space-x-1.5 cursor-pointer shadow-xs"
            >
              <Eye className="w-3.5 h-3.5 text-primary" />
              <span>Watch Targets</span>
            </button>
            <button
              onClick={() => onPromoteInvestigation(selectedItems)}
              className="px-2.5 py-1 text-xs font-mono text-white bg-threat-critical hover:bg-threat-critical/90 rounded-control flex items-center space-x-1.5 cursor-pointer shadow-xs"
            >
              <ShieldAlert className="w-3.5 h-3.5" />
              <span>Escalate / Link</span>
            </button>
          </div>
        </div>
      )}

      {/* 3. Items List */}
      {filteredItems.length === 0 ? (
        <div className="p-8 text-center bg-surface border border-border rounded-panel text-foreground-muted font-mono text-xs">
          {isLoading ? (
            <div className="flex flex-col items-center justify-center space-y-2 py-4">
              <Compass className="w-6 h-6 animate-spin text-primary" />
              <span>Executing pivot across intelligence & telemetry records...</span>
            </div>
          ) : (
            <div>No matching pivot results found for this observable and criteria.</div>
          )}
        </div>
      ) : (
        <div className="space-y-2">
          {filteredItems.map((item) => {
            const isSelected = selectedItemIds.includes(item.id);
            return (
              <div
                key={item.id}
                className={`p-3 bg-surface border rounded-panel transition-all hover:border-foreground-muted/40 shadow-xs ${
                  isSelected
                    ? 'border-primary ring-1 ring-primary/30 bg-primary/2'
                    : 'border-border'
                }`}
              >
                <div className="flex items-start justify-between gap-3">
                  {/* Select + Main Target Info */}
                  <div className="flex items-start space-x-2.5 min-w-0 flex-1">
                    <button
                      onClick={() => onToggleSelect(item.id)}
                      className="mt-0.5 cursor-pointer shrink-0"
                    >
                      {isSelected ? (
                        <CheckSquare className="w-4 h-4 text-primary" />
                      ) : (
                        <Square className="w-4 h-4 text-foreground-muted/60" />
                      )}
                    </button>

                    <div className="min-w-0 flex-1">
                      <div className="flex items-center space-x-2 flex-wrap gap-y-1">
                        <span className="text-[10px] uppercase font-mono font-bold px-1.5 py-0.5 rounded-control bg-surface-secondary text-foreground-muted border border-border">
                          {item.target_type}
                        </span>
                        <span className="font-mono font-semibold text-foreground text-xs select-all break-all">
                          {item.target_value}
                        </span>
                        {getOriginBadge(item.origin)}

                        <span className="text-[10px] font-mono font-medium px-1.5 py-0.5 rounded-control bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                          {Math.round(item.confidence * 100)}% Conf
                        </span>

                        {item.co_occurrence_count > 1 && (
                          <span
                            className="text-[10px] font-mono px-1.5 py-0.5 rounded-control bg-purple-500/10 text-purple-400 border border-purple-500/20"
                            title="Observed repeatedly across artifacts or events"
                          >
                            ×{item.co_occurrence_count} Co-occurred
                          </span>
                        )}
                      </div>

                      {/* Relationship & Provenance Description */}
                      <p className="mt-1.5 text-xs text-foreground/80 leading-relaxed font-sans">
                        <strong className="font-semibold text-foreground">
                          {item.relationship_type}:
                        </strong>{' '}
                        {item.relationship_description}
                      </p>

                      {/* Temporal Context */}
                      {(item.first_seen || item.last_seen || item.evidence_reference) && (
                        <div className="mt-2 flex items-center space-x-3 text-[10px] font-mono text-foreground-muted flex-wrap gap-y-1">
                          {item.first_seen && (
                            <span className="flex items-center space-x-1">
                              <Clock className="w-2.5 h-2.5" />
                              <span>First: {new Date(item.first_seen).toLocaleDateString()}</span>
                            </span>
                          )}
                          {item.last_seen && (
                            <span className="flex items-center space-x-1">
                              <Clock className="w-2.5 h-2.5" />
                              <span>Last: {new Date(item.last_seen).toLocaleDateString()}</span>
                            </span>
                          )}
                          {item.evidence_reference && (
                            <span className="text-primary/90 underline">
                              Ref: {item.evidence_reference}
                            </span>
                          )}
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Actions & Hop */}
                  <div className="flex flex-col items-end space-y-2 shrink-0">
                    <button
                      onClick={() => onHopPivot(item)}
                      className="px-2.5 py-1 text-xs font-mono font-medium text-white bg-primary hover:bg-primary/90 rounded-control flex items-center space-x-1.5 cursor-pointer shadow-xs transition-colors"
                      title="Make this entity the source and pivot deeper"
                    >
                      <GitFork className="w-3.5 h-3.5" />
                      <span>Pivot Hop</span>
                    </button>

                    {/* Evidence Classification Chips for Active Hypothesis */}
                    {onClassifyEvidence && (
                      <div className="flex items-center space-x-1 pt-1 border-t border-border/60">
                        <span className="text-[9px] font-mono text-foreground-muted mr-0.5">
                          Evidence:
                        </span>
                        <button
                          onClick={() => onClassifyEvidence(item, 'SUPPORTING')}
                          className="p-1 rounded-control hover:bg-emerald-500/15 text-foreground-muted hover:text-emerald-500 transition-colors cursor-pointer"
                          title="Classify as Supporting Evidence"
                        >
                          <CheckCircle2 className="w-3.5 h-3.5" />
                        </button>
                        <button
                          onClick={() => onClassifyEvidence(item, 'CONTRADICTING')}
                          className="p-1 rounded-control hover:bg-threat-critical/15 text-foreground-muted hover:text-threat-critical transition-colors cursor-pointer"
                          title="Classify as Contradicting Evidence"
                        >
                          <XCircle className="w-3.5 h-3.5" />
                        </button>
                        <button
                          onClick={() => onClassifyEvidence(item, 'NEUTRAL')}
                          className="p-1 rounded-control hover:bg-foreground-muted/20 text-foreground-muted hover:text-foreground transition-colors cursor-pointer"
                          title="Classify as Neutral Evidence"
                        >
                          <HelpCircle className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
