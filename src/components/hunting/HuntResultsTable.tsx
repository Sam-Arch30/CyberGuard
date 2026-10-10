import React, { useState } from 'react';
import {
  ExternalLink,
  ShieldAlert,
  Eye,
  Download,
  Share2,
  CheckSquare,
  Square,
  BarChart2,
  Compass,
} from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import type { HuntQueryResultResponse } from '../../types/hunting';
import { huntingService } from '../../services/huntingService';

interface HuntResultsTableProps {
  results: HuntQueryResultResponse;
  onOpenInvestigationModal: (selectedIds: string[]) => void;
  onOpenWatchlistModal: (selectedIds: string[]) => void;
}

export const HuntResultsTable: React.FC<HuntResultsTableProps> = ({
  results,
  onOpenInvestigationModal,
  onOpenWatchlistModal,
}) => {
  const navigate = useNavigate();
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [exporting, setExporting] = useState(false);

  const toggleSelectAll = () => {
    if (selectedIds.length === results.items.length) {
      setSelectedIds([]);
    } else {
      setSelectedIds(results.items.map((it) => it.id));
    }
  };

  const toggleSelectItem = (id: string) => {
    setSelectedIds((prev) =>
      prev.includes(id) ? prev.filter((i) => i !== id) : [...prev, id]
    );
  };

  const handleExport = async (format: 'json' | 'csv') => {
    setExporting(true);
    try {
      const content = await huntingService.exportResults(results.execution_id, format);
      const blob = new Blob([content], {
        type: format === 'csv' ? 'text/csv' : 'application/json',
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `hunt_results_${results.execution_id.slice(0, 8)}.${format}`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Export failed', err);
    } finally {
      setExporting(false);
    }
  };

  const getSeverityBadge = (sev?: string) => {
    if (!sev) return null;
    const s = sev.toUpperCase();
    if (s === 'CRITICAL') {
      return (
        <span className="px-1.5 py-0.5 rounded-control text-[9px] font-mono font-bold bg-threat-critical/15 text-threat-critical border border-threat-critical/30">
          CRITICAL
        </span>
      );
    }
    if (s === 'HIGH') {
      return (
        <span className="px-1.5 py-0.5 rounded-control text-[9px] font-mono font-bold bg-amber-500/15 text-amber-500 border border-amber-500/30">
          HIGH
        </span>
      );
    }
    if (s === 'MEDIUM') {
      return (
        <span className="px-1.5 py-0.5 rounded-control text-[9px] font-mono font-bold bg-yellow-500/15 text-yellow-600 border border-yellow-500/30">
          MEDIUM
        </span>
      );
    }
    return (
      <span className="px-1.5 py-0.5 rounded-control text-[9px] font-mono font-bold bg-surface-secondary text-foreground-muted border border-border">
        {s}
      </span>
    );
  };

  const getVerdictBadge = (verdict?: string) => {
    if (!verdict) return null;
    const v = verdict.toUpperCase();
    if (v === 'MALICIOUS') {
      return (
        <span className="px-1.5 py-0.5 rounded-control text-[9px] font-mono uppercase bg-threat-critical text-white font-bold">
          MALICIOUS
        </span>
      );
    }
    if (v === 'SUSPICIOUS') {
      return (
        <span className="px-1.5 py-0.5 rounded-control text-[9px] font-mono uppercase bg-amber-500/20 text-amber-500 font-bold border border-amber-500/30">
          SUSPICIOUS
        </span>
      );
    }
    if (v === 'CLEAN') {
      return (
        <span className="px-1.5 py-0.5 rounded-control text-[9px] font-mono uppercase bg-emerald-500/15 text-emerald-500 font-bold border border-emerald-500/30">
          CLEAN
        </span>
      );
    }
    return (
      <span className="px-1.5 py-0.5 rounded-control text-[9px] font-mono uppercase bg-surface-secondary text-foreground-muted border border-border">
        {v}
      </span>
    );
  };

  return (
    <div className="space-y-4">
      {/* 1. Results Summary Ribbon */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 p-3 bg-surface border border-border rounded-panel">
        <div className="flex items-center space-x-3">
          <div className="w-8 h-8 rounded-control bg-primary/10 text-primary flex items-center justify-center border border-primary/20 shrink-0">
            <Compass className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="text-sm font-sans font-bold text-foreground">
                {results.total_matches.toLocaleString()} Matches Identified
              </span>
              <span className="px-1.5 py-0.2 rounded-control text-[9px] font-mono bg-primary/15 text-primary border border-primary/20 uppercase">
                {results.data_source}
              </span>
            </div>
            <p className="text-[11px] font-mono text-foreground-muted">
              Execution duration: {results.duration_ms}ms • Query Execution ID #{results.execution_id.slice(0, 8)}
            </p>
          </div>
        </div>

        {/* Export & Actions */}
        <div className="flex items-center space-x-2 shrink-0">
          <button
            onClick={() => handleExport('csv')}
            disabled={exporting || results.items.length === 0}
            className="px-2.5 py-1.5 text-xs font-mono text-foreground-muted hover:text-foreground bg-surface-secondary border border-border rounded-control flex items-center space-x-1 hover:border-primary/40 transition-colors cursor-pointer disabled:opacity-50"
          >
            <Download className="w-3.5 h-3.5" />
            <span>CSV</span>
          </button>
          <button
            onClick={() => handleExport('json')}
            disabled={exporting || results.items.length === 0}
            className="px-2.5 py-1.5 text-xs font-mono text-foreground-muted hover:text-foreground bg-surface-secondary border border-border rounded-control flex items-center space-x-1 hover:border-primary/40 transition-colors cursor-pointer disabled:opacity-50"
          >
            <Download className="w-3.5 h-3.5" />
            <span>JSON</span>
          </button>
        </div>
      </div>

      {/* 2. Aggregations Facets Breakdown (if present) */}
      {results.aggregations && Object.keys(results.aggregations).length > 0 && (
        <div className="p-3.5 bg-surface border border-border rounded-panel space-y-2">
          <div className="flex items-center space-x-2 text-xs font-mono text-foreground-muted uppercase">
            <BarChart2 className="w-3.5 h-3.5 text-primary" />
            <span>Aggregated Facet Distribution</span>
          </div>
          {Object.entries(results.aggregations).map(([field, buckets]) => (
            <div key={field} className="space-y-1.5">
              <div className="flex flex-wrap gap-2">
                {buckets.map((b) => (
                  <div
                    key={b.key}
                    className="px-2.5 py-1 bg-surface-secondary border border-border rounded-control text-xs flex items-center space-x-2"
                  >
                    <span className="font-mono text-foreground-muted">{b.key}:</span>
                    <span className="font-bold text-foreground font-mono">{b.count}</span>
                    <span className="text-[10px] text-foreground-muted">({b.percentage}%)</span>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* 3. Bulk Handoff Action Bar */}
      {selectedIds.length > 0 && (
        <div className="p-2.5 bg-primary/10 border border-primary/30 rounded-panel flex items-center justify-between animate-in fade-in slide-in-from-top-2 duration-150">
          <div className="flex items-center space-x-2 text-xs font-mono text-foreground">
            <CheckSquare className="w-4 h-4 text-primary" />
            <span>{selectedIds.length} item(s) selected</span>
          </div>

          <div className="flex items-center space-x-2">
            <button
              onClick={() => onOpenWatchlistModal(selectedIds)}
              className="px-3 py-1.5 text-xs font-mono text-foreground bg-surface hover:bg-surface-secondary border border-border rounded-control flex items-center space-x-1.5 cursor-pointer shadow-xs"
            >
              <Eye className="w-3.5 h-3.5 text-primary" />
              <span>Add to Watchlist</span>
            </button>
            <button
              onClick={() => onOpenInvestigationModal(selectedIds)}
              className="px-3 py-1.5 text-xs font-mono text-white bg-threat-critical hover:bg-threat-critical/90 rounded-control flex items-center space-x-1.5 cursor-pointer shadow-xs"
            >
              <ShieldAlert className="w-3.5 h-3.5" />
              <span>Escalate to Investigation</span>
            </button>
          </div>
        </div>
      )}

      {/* 4. Results Table */}
      <div className="bg-surface border border-border rounded-panel overflow-hidden shadow-xs">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-surface-secondary border-b border-border text-[10px] font-mono text-foreground-muted uppercase">
              <tr>
                <th className="py-2.5 px-3 w-8 text-center">
                  <button onClick={toggleSelectAll} className="cursor-pointer">
                    {selectedIds.length > 0 && selectedIds.length === results.items.length ? (
                      <CheckSquare className="w-3.5 h-3.5 text-primary" />
                    ) : (
                      <Square className="w-3.5 h-3.5 text-foreground-muted" />
                    )}
                  </button>
                </th>
                <th className="py-2.5 px-3">Observable / Entity</th>
                <th className="py-2.5 px-3">Severity</th>
                <th className="py-2.5 px-3">Verdict</th>
                <th className="py-2.5 px-3">Confidence</th>
                <th className="py-2.5 px-3">Observed At</th>
                <th className="py-2.5 px-3">Analytical Reasoning</th>
                <th className="py-2.5 px-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {results.items.map((row) => {
                const isSelected = selectedIds.includes(row.id);
                return (
                  <tr
                    key={row.id}
                    className={`hover:bg-surface-secondary/60 transition-colors ${
                      isSelected ? 'bg-primary/5' : ''
                    }`}
                  >
                    <td className="py-2.5 px-3 text-center">
                      <button onClick={() => toggleSelectItem(row.id)} className="cursor-pointer">
                        {isSelected ? (
                          <CheckSquare className="w-3.5 h-3.5 text-primary" />
                        ) : (
                          <Square className="w-3.5 h-3.5 text-foreground-muted/60" />
                        )}
                      </button>
                    </td>

                    <td className="py-2.5 px-3">
                      <div className="flex flex-col">
                        <span className="font-mono font-medium text-foreground text-xs select-all">
                          {row.primary_value}
                        </span>
                        {row.secondary_value && (
                          <span className="text-[10px] text-foreground-muted font-mono">
                            {row.secondary_value}
                          </span>
                        )}
                      </div>
                    </td>

                    <td className="py-2.5 px-3">{getSeverityBadge(row.severity)}</td>
                    <td className="py-2.5 px-3">{getVerdictBadge(row.verdict)}</td>

                    <td className="py-2.5 px-3 font-mono text-[11px] text-foreground">
                      {row.confidence !== undefined && row.confidence !== null
                        ? `${Math.round(row.confidence * 100)}%`
                        : '—'}
                    </td>

                    <td className="py-2.5 px-3 font-mono text-[11px] text-foreground-muted whitespace-nowrap">
                      {row.observed_at ? new Date(row.observed_at).toLocaleString() : '—'}
                    </td>

                    <td className="py-2.5 px-3 max-w-xs truncate text-[11px] text-foreground-muted">
                      {row.matched_reasons.join('; ') || 'Matched filter query.'}
                    </td>

                    <td className="py-2.5 px-3 text-right whitespace-nowrap">
                      <div className="flex items-center justify-end space-x-1.5">
                        {row.pivot_links.osint_url && (
                          <button
                            onClick={() => navigate(row.pivot_links.osint_url)}
                            className="p-1 text-foreground-muted hover:text-primary rounded-control hover:bg-surface border border-transparent hover:border-border transition-colors cursor-pointer"
                            title="Inspect in Threat Intelligence (OSINT)"
                          >
                            <ExternalLink className="w-3.5 h-3.5" />
                          </button>
                        )}
                        {row.pivot_links.graph_url && (
                          <button
                            onClick={() => navigate(row.pivot_links.graph_url)}
                            className="p-1 text-foreground-muted hover:text-primary rounded-control hover:bg-surface border border-transparent hover:border-border transition-colors cursor-pointer"
                            title="Pivot in Knowledge Graph"
                          >
                            <Share2 className="w-3.5 h-3.5" />
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
