import React, { useState, useEffect } from 'react';
import {
  Shield,
  Eye,
  Plus,
  ArrowLeft,
  RefreshCw,
  Clock,
  AlertTriangle,
  Play,
  Pause,
  Trash2,
  Activity,
  CheckCircle2,
  Search,
} from 'lucide-react';
import type {
  WatchlistDetail,
  WatchedIndicator,
  IntelligenceChange,
  WatchlistMonitoringRun,
  WatchlistHealth,
} from '../../types/watchlist';
import { WatchlistService } from '../../services/watchlistService';

interface WatchlistDetailViewProps {
  watchlistId: string;
  onBack: () => void;
}

export const WatchlistDetailView: React.FC<WatchlistDetailViewProps> = ({
  watchlistId,
  onBack,
}) => {
  const [watchlist, setWatchlist] = useState<WatchlistDetail | null>(null);
  const [health, setHealth] = useState<WatchlistHealth | null>(null);
  const [indicators, setIndicators] = useState<WatchedIndicator[]>([]);
  const [changes, setChanges] = useState<IntelligenceChange[]>([]);
  const [runs, setRuns] = useState<WatchlistMonitoringRun[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<'indicators' | 'changes' | 'runs'>('indicators');

  // Modals & form state
  const [showAddModal, setShowAddModal] = useState(false);
  const [indicatorInput, setIndicatorInput] = useState('');
  const [indicatorTypeHint, setIndicatorTypeHint] = useState('');
  const [isBulk, setIsBulk] = useState(false);
  const [adding, setAdding] = useState(false);
  const [addError, setAddError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [actionItemId, setActionItemId] = useState<string | null>(null);
  const [searchFilter, setSearchFilter] = useState('');

  const loadAll = async () => {
    try {
      setLoading(true);
      const [wlData, healthData, itemsData, changesData, runsData] = await Promise.all([
        WatchlistService.getWatchlist(watchlistId),
        WatchlistService.getWatchlistHealth(watchlistId),
        WatchlistService.listWatchlistItems(watchlistId, { limit: 100 }),
        WatchlistService.listWatchlistChanges(watchlistId, { limit: 50 }),
        WatchlistService.listWatchlistRuns(watchlistId, 20),
      ]);
      setWatchlist(wlData);
      setHealth(healthData);
      setIndicators(itemsData.items);
      setChanges(changesData.items);
      setRuns(runsData.items);
    } catch (err) {
      console.error('Failed to load watchlist details:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAll();
  }, [watchlistId]);

  const handleRefreshWatchlist = async () => {
    try {
      setRefreshing(true);
      await WatchlistService.refreshWatchlist(watchlistId);
      await loadAll();
    } catch (err) {
      console.error('Failed to refresh:', err);
    } finally {
      setRefreshing(false);
    }
  };

  const handleToggleStatus = async () => {
    if (!watchlist) return;
    try {
      const target = watchlist.status === 'ACTIVE' ? 'PAUSED' : 'ACTIVE';
      await WatchlistService.updateWatchlist(watchlist.id, { status: target });
      await loadAll();
    } catch (err) {
      console.error('Failed to toggle status:', err);
    }
  };

  const handleAddIndicator = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!indicatorInput.trim()) return;
    setAdding(true);
    setAddError(null);

    try {
      if (isBulk) {
        const lines = indicatorInput
          .split(/[\n,]+/)
          .map((s) => s.trim())
          .filter(Boolean);
        const payloads = lines.map((val) => ({ indicator_value: val }));
        await WatchlistService.bulkAddWatchlistItems(watchlistId, payloads);
      } else {
        await WatchlistService.addWatchlistItem(watchlistId, {
          indicator_value: indicatorInput.trim(),
          indicator_type: indicatorTypeHint || undefined,
        });
      }
      setShowAddModal(false);
      setIndicatorInput('');
      setIndicatorTypeHint('');
      await loadAll();
    } catch (err) {
      setAddError(err instanceof Error ? err.message : 'Failed to add indicator.');
    } finally {
      setAdding(false);
    }
  };

  const handleRefreshSingleItem = async (itemId: string) => {
    setActionItemId(itemId);
    try {
      await WatchlistService.refreshSingleIndicator(itemId);
      await loadAll();
    } catch (err) {
      console.error('Failed to refresh item:', err);
    } finally {
      setActionItemId(null);
    }
  };

  const handleRemoveItem = async (itemId: string) => {
    setActionItemId(itemId);
    try {
      await WatchlistService.removeWatchlistItem(watchlistId, itemId);
      await loadAll();
    } catch (err) {
      console.error('Failed to remove item:', err);
    } finally {
      setActionItemId(null);
    }
  };

  if (loading && !watchlist) {
    return (
      <div className="py-24 text-center text-foreground-muted font-mono text-xs flex flex-col items-center justify-center space-y-2">
        <RefreshCw className="w-5 h-5 animate-spin text-primary" />
        <span>Loading watchlist workspace...</span>
      </div>
    );
  }

  if (!watchlist) {
    return (
      <div className="p-8 text-center text-foreground-muted space-y-3">
        <AlertTriangle className="w-8 h-8 text-danger mx-auto" />
        <div className="text-sm font-bold text-foreground">Watchlist Not Found</div>
        <button
          type="button"
          onClick={onBack}
          className="px-3 py-1.5 rounded-control bg-surface-secondary text-foreground text-xs"
        >
          Return to Watchlists
        </button>
      </div>
    );
  }

  const filteredIndicators = indicators.filter((item) => {
    if (!searchFilter) return true;
    const term = searchFilter.toLowerCase();
    return (
      item.normalized_value.toLowerCase().includes(term) ||
      item.indicator_type.toLowerCase().includes(term) ||
      item.last_verdict.toLowerCase().includes(term)
    );
  });

  return (
    <div className="space-y-4">
      {/* 1. Navigation & Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div className="flex items-center space-x-3">
          <button
            type="button"
            onClick={onBack}
            className="p-1.5 rounded-control border border-border text-foreground-muted hover:text-foreground hover:bg-surface-secondary cursor-pointer"
            title="Back to watchlists"
          >
            <ArrowLeft className="w-4 h-4" />
          </button>
          <div>
            <div className="flex items-center space-x-2">
              <h2 className="text-base font-bold text-foreground">{watchlist.name}</h2>
              <span
                className={`text-[10px] font-mono px-1.5 py-0.5 rounded-control border font-semibold ${
                  watchlist.priority === 'CRITICAL'
                    ? 'bg-danger-surface border-danger-border text-danger'
                    : watchlist.priority === 'HIGH'
                    ? 'bg-amber-500/10 border-amber-500/30 text-amber-400'
                    : 'bg-surface-secondary border-border text-foreground-muted'
                }`}
              >
                {watchlist.priority}
              </span>
              <span
                className={`text-[10px] font-mono px-1.5 py-0.5 rounded-control font-semibold ${
                  watchlist.status === 'ACTIVE'
                    ? 'bg-emerald-500/10 text-emerald-400'
                    : 'bg-surface-secondary text-foreground-muted'
                }`}
              >
                {watchlist.status}
              </span>
            </div>
            {watchlist.description && (
              <p className="text-xs text-foreground-muted mt-0.5">{watchlist.description}</p>
            )}
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex items-center space-x-2">
          <button
            type="button"
            onClick={handleToggleStatus}
            className="px-2.5 py-1.5 text-xs rounded-control border border-border hover:bg-surface-secondary text-foreground flex items-center space-x-1.5 cursor-pointer"
          >
            {watchlist.status === 'ACTIVE' ? (
              <>
                <Pause className="w-3.5 h-3.5 text-amber-400" />
                <span>Pause</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5 text-emerald-400" />
                <span>Resume</span>
              </>
            )}
          </button>

          <button
            type="button"
            onClick={handleRefreshWatchlist}
            disabled={refreshing || watchlist.status === 'PAUSED'}
            className="px-2.5 py-1.5 text-xs rounded-control border border-border hover:bg-surface-secondary text-foreground flex items-center space-x-1.5 cursor-pointer disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin text-primary' : ''}`} />
            <span>Check Now</span>
          </button>

          <button
            type="button"
            onClick={() => setShowAddModal(true)}
            className="px-3 py-1.5 text-xs rounded-control bg-primary hover:bg-primary-hover text-primary-foreground font-semibold flex items-center space-x-1.5 cursor-pointer shadow-xs"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Add Indicator</span>
          </button>
        </div>
      </div>

      {/* 2. Health & Telemetry Metrics Card */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <div className="p-3 bg-surface border border-border rounded-control space-y-1">
          <span className="text-[10px] uppercase font-mono tracking-wider text-foreground-muted block">
            Total Monitored
          </span>
          <span className="text-lg font-bold font-mono text-foreground">{health?.total_indicators ?? 0}</span>
        </div>

        <div className="p-3 bg-surface border border-border rounded-control space-y-1">
          <span className="text-[10px] uppercase font-mono tracking-wider text-foreground-muted block">
            Healthy Status
          </span>
          <span className="text-lg font-bold font-mono text-emerald-400">{health?.healthy_count ?? 0}</span>
        </div>

        <div className="p-3 bg-surface border border-border rounded-control space-y-1">
          <span className="text-[10px] uppercase font-mono tracking-wider text-foreground-muted block">
            Malicious Detected
          </span>
          <span className="text-lg font-bold font-mono text-danger">{health?.malicious_count ?? 0}</span>
        </div>

        <div className="p-3 bg-surface border border-border rounded-control space-y-1">
          <span className="text-[10px] uppercase font-mono tracking-wider text-foreground-muted block">
            Stale Items
          </span>
          <span className="text-lg font-bold font-mono text-amber-400">{health?.stale_count ?? 0}</span>
        </div>

        <div className="p-3 bg-surface border border-border rounded-control space-y-1">
          <span className="text-[10px] uppercase font-mono tracking-wider text-foreground-muted block">
            Check Frequency
          </span>
          <span className="text-lg font-mono text-foreground-muted">Every {watchlist.check_interval_minutes}m</span>
        </div>
      </div>

      {/* 3. Sub-Tab Navigation */}
      <div className="border-b border-border flex items-center space-x-4 text-xs">
        <button
          type="button"
          onClick={() => setActiveTab('indicators')}
          className={`pb-2.5 cursor-pointer transition-colors border-b-2 flex items-center space-x-1.5 ${
            activeTab === 'indicators'
              ? 'border-primary text-primary font-semibold'
              : 'border-transparent text-foreground-muted hover:text-foreground'
          }`}
        >
          <Eye className="w-3.5 h-3.5" />
          <span>Monitored Indicators ({indicators.length})</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('changes')}
          className={`pb-2.5 cursor-pointer transition-colors border-b-2 flex items-center space-x-1.5 ${
            activeTab === 'changes'
              ? 'border-primary text-primary font-semibold'
              : 'border-transparent text-foreground-muted hover:text-foreground'
          }`}
        >
          <Activity className="w-3.5 h-3.5" />
          <span>Intelligence Changes ({changes.length})</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('runs')}
          className={`pb-2.5 cursor-pointer transition-colors border-b-2 flex items-center space-x-1.5 ${
            activeTab === 'runs'
              ? 'border-primary text-primary font-semibold'
              : 'border-transparent text-foreground-muted hover:text-foreground'
          }`}
        >
          <Clock className="w-3.5 h-3.5" />
          <span>Execution Runs ({runs.length})</span>
        </button>
      </div>

      {/* 4. Tab Content: Indicators */}
      {activeTab === 'indicators' && (
        <div className="space-y-3">
          {/* Filter Bar */}
          <div className="flex items-center justify-between gap-2">
            <div className="relative flex-1 max-w-sm">
              <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-foreground-muted" />
              <input
                type="text"
                placeholder="Search indicators by value, type, verdict..."
                value={searchFilter}
                onChange={(e) => setSearchFilter(e.target.value)}
                className="w-full pl-8 pr-3 py-1.5 bg-surface border border-border rounded-control text-xs text-foreground placeholder:text-foreground-muted focus:outline-hidden focus:border-primary"
              />
            </div>
          </div>

          {filteredIndicators.length === 0 ? (
            <div className="p-8 text-center text-foreground-muted bg-surface rounded-control border border-border space-y-2">
              <Eye className="w-6 h-6 mx-auto opacity-50" />
              <div className="text-xs font-semibold">No monitored indicators found</div>
              <p className="text-[11px]">Add indicators to this watchlist to continuously monitor threat intelligence.</p>
            </div>
          ) : (
            <div className="bg-surface border border-border rounded-control overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full text-xs text-left">
                  <thead className="bg-surface-secondary border-b border-border text-[11px] font-mono text-foreground-muted uppercase">
                    <tr>
                      <th className="py-2.5 px-3">Type</th>
                      <th className="py-2.5 px-3">Observable Value</th>
                      <th className="py-2.5 px-3">Verdict</th>
                      <th className="py-2.5 px-3">Confidence</th>
                      <th className="py-2.5 px-3">Last Checked</th>
                      <th className="py-2.5 px-3">Status</th>
                      <th className="py-2.5 px-3 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {filteredIndicators.map((item) => {
                      const isItemLoading = actionItemId === item.id;
                      const verdict = item.last_verdict.toUpperCase();

                      return (
                        <tr key={item.id} className="hover:bg-surface-secondary/40 transition-colors">
                          <td className="py-2.5 px-3 font-mono text-[11px] text-foreground-muted">
                            <span className="px-1.5 py-0.5 rounded-control bg-surface-secondary border border-border">
                              {item.indicator_type}
                            </span>
                          </td>
                          <td className="py-2.5 px-3 font-mono font-semibold text-foreground max-w-xs truncate">
                            {item.normalized_value}
                          </td>
                          <td className="py-2.5 px-3">
                            <span
                              className={`text-[10px] font-mono px-2 py-0.5 rounded-control font-bold uppercase ${
                                verdict === 'MALICIOUS'
                                  ? 'bg-danger-surface text-danger border border-danger-border'
                                  : verdict === 'SUSPICIOUS'
                                  ? 'bg-amber-500/10 text-amber-400 border border-amber-500/30'
                                  : verdict === 'CLEAN'
                                  ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                                  : 'bg-surface-secondary text-foreground-muted border border-border'
                              }`}
                            >
                              {verdict}
                            </span>
                          </td>
                          <td className="py-2.5 px-3 font-mono text-foreground-muted">
                            {Math.round(item.last_confidence * 100)}%
                          </td>
                          <td className="py-2.5 px-3 text-foreground-muted font-mono text-[11px]">
                            {item.last_checked_at ? new Date(item.last_checked_at).toLocaleTimeString() : 'Pending'}
                          </td>
                          <td className="py-2.5 px-3 font-mono text-[11px]">
                            <span
                              className={`inline-flex items-center space-x-1 ${
                                item.monitoring_status === 'HEALTHY'
                                  ? 'text-emerald-400'
                                  : item.monitoring_status === 'ERROR'
                                  ? 'text-danger'
                                  : 'text-amber-400'
                              }`}
                            >
                              <span className="w-1.5 h-1.5 rounded-full bg-current" />
                              <span>{item.monitoring_status}</span>
                            </span>
                          </td>
                          <td className="py-2.5 px-3 text-right">
                            <div className="flex items-center justify-end space-x-1">
                              <button
                                type="button"
                                onClick={() => handleRefreshSingleItem(item.id)}
                                disabled={isItemLoading}
                                className="p-1 rounded-control text-foreground-muted hover:text-foreground hover:bg-surface-secondary cursor-pointer disabled:opacity-50"
                                title="Check observable now"
                              >
                                <RefreshCw className={`w-3.5 h-3.5 ${isItemLoading ? 'animate-spin text-primary' : ''}`} />
                              </button>
                              <button
                                type="button"
                                onClick={() => handleRemoveItem(item.id)}
                                disabled={isItemLoading}
                                className="p-1 rounded-control text-danger/80 hover:text-danger hover:bg-danger-surface cursor-pointer"
                                title="Remove from watchlist"
                              >
                                <Trash2 className="w-3.5 h-3.5" />
                              </button>
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {/* 5. Tab Content: Changes Timeline */}
      {activeTab === 'changes' && (
        <div className="space-y-3">
          {changes.length === 0 ? (
            <div className="p-8 text-center text-foreground-muted bg-surface rounded-control border border-border space-y-2">
              <CheckCircle2 className="w-6 h-6 mx-auto opacity-50" />
              <div className="text-xs font-semibold">No material intelligence changes detected</div>
              <p className="text-[11px]">Monitored observables have maintained stable intelligence states.</p>
            </div>
          ) : (
            <div className="space-y-2.5">
              {changes.map((chg) => (
                <div
                  key={chg.id}
                  className="p-3.5 bg-surface border border-border rounded-control shadow-xs flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs"
                >
                  <div className="space-y-1">
                    <div className="flex items-center space-x-2">
                      <span
                        className={`text-[10px] font-mono px-1.5 py-0.5 rounded-control font-bold uppercase ${
                          chg.change_severity === 'CRITICAL'
                            ? 'bg-danger-surface text-danger border border-danger-border'
                            : chg.change_severity === 'HIGH'
                            ? 'bg-amber-500/10 text-amber-400 border border-amber-500/30'
                            : 'bg-surface-secondary text-foreground-muted border border-border'
                        }`}
                      >
                        {chg.change_severity}
                      </span>
                      <span className="font-mono font-bold text-foreground">
                        {chg.normalized_value}
                      </span>
                      <span className="text-[11px] font-mono text-foreground-muted">
                        ({chg.change_type})
                      </span>
                    </div>
                    <p className="text-foreground-muted text-xs leading-relaxed">
                      {chg.change_summary}
                    </p>
                  </div>

                  <div className="flex sm:flex-col sm:items-end justify-between text-[11px] font-mono text-foreground-muted shrink-0">
                    <span>{new Date(chg.detected_at).toLocaleString()}</span>
                    {chg.alert_id && (
                      <span className="text-primary flex items-center space-x-1 mt-0.5">
                        <Shield className="w-3 h-3" />
                        <span>Security Alert Generated</span>
                      </span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* 6. Tab Content: Runs */}
      {activeTab === 'runs' && (
        <div className="space-y-3">
          {runs.length === 0 ? (
            <div className="p-8 text-center text-foreground-muted bg-surface rounded-control border border-border">
              <Clock className="w-6 h-6 mx-auto opacity-50 mb-2" />
              <div className="text-xs font-semibold">No monitoring runs logged yet</div>
            </div>
          ) : (
            <div className="bg-surface border border-border rounded-control overflow-hidden">
              <table className="w-full text-xs text-left">
                <thead className="bg-surface-secondary border-b border-border text-[11px] font-mono text-foreground-muted uppercase">
                  <tr>
                    <th className="py-2.5 px-3">Run Time</th>
                    <th className="py-2.5 px-3">Trigger</th>
                    <th className="py-2.5 px-3">Status</th>
                    <th className="py-2.5 px-3">Checked</th>
                    <th className="py-2.5 px-3">Changes</th>
                    <th className="py-2.5 px-3">Alerts Created</th>
                    <th className="py-2.5 px-3 text-right">Duration</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {runs.map((run) => (
                    <tr key={run.id} className="hover:bg-surface-secondary/40 transition-colors">
                      <td className="py-2.5 px-3 font-mono text-foreground">
                        {new Date(run.started_at).toLocaleString()}
                      </td>
                      <td className="py-2.5 px-3 font-mono text-[11px] text-foreground-muted">
                        {run.trigger_type}
                      </td>
                      <td className="py-2.5 px-3 font-mono text-[11px]">
                        <span
                          className={`px-1.5 py-0.5 rounded-control font-semibold ${
                            run.status === 'SUCCEEDED'
                              ? 'bg-emerald-500/10 text-emerald-400'
                              : run.status === 'PARTIALLY_SUCCEEDED'
                              ? 'bg-amber-500/10 text-amber-400'
                              : 'bg-danger-surface text-danger'
                          }`}
                        >
                          {run.status}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 font-mono">{run.items_checked}</td>
                      <td className="py-2.5 px-3 font-mono font-bold text-primary">{run.items_changed}</td>
                      <td className="py-2.5 px-3 font-mono">{run.alerts_created}</td>
                      <td className="py-2.5 px-3 text-right font-mono text-foreground-muted">
                        {run.duration_ms ? `${run.duration_ms}ms` : '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* 7. Add Indicator Modal */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4 animate-in fade-in duration-150">
          <div className="bg-surface border border-border rounded-control shadow-xl w-full max-w-md overflow-hidden flex flex-col">
            <div className="p-4 border-b border-border flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <Plus className="w-4 h-4 text-primary" />
                <h3 className="text-sm font-bold text-foreground">Add Observable to Watchlist</h3>
              </div>
              <button
                type="button"
                onClick={() => setShowAddModal(false)}
                className="text-foreground-muted hover:text-foreground p-1 rounded-control hover:bg-surface-secondary cursor-pointer"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleAddIndicator} className="p-4 space-y-4 text-xs">
              {addError && (
                <div className="p-3 bg-danger-surface border border-danger-border rounded-control text-danger flex items-center space-x-2">
                  <AlertTriangle className="w-4 h-4 shrink-0" />
                  <span>{addError}</span>
                </div>
              )}

              <div className="flex items-center justify-between">
                <span className="font-semibold text-foreground">Input Mode</span>
                <div className="flex items-center space-x-2">
                  <button
                    type="button"
                    onClick={() => setIsBulk(false)}
                    className={`px-2 py-0.5 rounded-control text-[11px] font-mono cursor-pointer ${
                      !isBulk ? 'bg-primary text-primary-foreground font-bold' : 'text-foreground-muted'
                    }`}
                  >
                    Single
                  </button>
                  <button
                    type="button"
                    onClick={() => setIsBulk(true)}
                    className={`px-2 py-0.5 rounded-control text-[11px] font-mono cursor-pointer ${
                      isBulk ? 'bg-primary text-primary-foreground font-bold' : 'text-foreground-muted'
                    }`}
                  >
                    Bulk Paste
                  </button>
                </div>
              </div>

              {!isBulk ? (
                <>
                  <div className="space-y-1">
                    <label className="font-semibold text-foreground">Observable Value *</label>
                    <input
                      type="text"
                      required
                      placeholder="e.g. 198.51.100.25, evil.com, https://phish.net, or sha256"
                      value={indicatorInput}
                      onChange={(e) => setIndicatorInput(e.target.value)}
                      className="w-full bg-surface-secondary border border-border rounded-control px-2.5 py-1.5 text-foreground text-xs focus:outline-hidden focus:border-primary font-mono"
                    />
                  </div>

                  <div className="space-y-1">
                    <label className="font-semibold text-foreground">Indicator Type (Optional)</label>
                    <select
                      value={indicatorTypeHint}
                      onChange={(e) => setIndicatorTypeHint(e.target.value)}
                      className="w-full bg-surface-secondary border border-border rounded-control px-2.5 py-1.5 text-foreground text-xs focus:outline-hidden focus:border-primary cursor-pointer"
                    >
                      <option value="">Auto-Detect Type</option>
                      <option value="IP">IP Address</option>
                      <option value="DOMAIN">Domain</option>
                      <option value="URL">URL</option>
                      <option value="SHA256">SHA-256 Hash</option>
                      <option value="SHA1">SHA-1 Hash</option>
                      <option value="MD5">MD5 Hash</option>
                      <option value="EMAIL">Email Address</option>
                      <option value="ASN">Autonomous System (ASN)</option>
                    </select>
                  </div>
                </>
              ) : (
                <div className="space-y-1">
                  <label className="font-semibold text-foreground">Observables (Newline or comma-separated)</label>
                  <textarea
                    rows={5}
                    required
                    placeholder="198.51.100.25&#10;evil-phish.com&#10;https://target.com/login"
                    value={indicatorInput}
                    onChange={(e) => setIndicatorInput(e.target.value)}
                    className="w-full bg-surface-secondary border border-border rounded-control px-2.5 py-1.5 text-foreground text-xs focus:outline-hidden focus:border-primary font-mono resize-none"
                  />
                </div>
              )}

              <div className="pt-2 border-t border-border flex items-center justify-end space-x-2">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="px-3 py-1.5 rounded-control border border-border text-foreground hover:bg-surface-secondary text-xs cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={adding}
                  className="px-3.5 py-1.5 rounded-control bg-primary text-primary-foreground font-semibold text-xs flex items-center space-x-1.5 cursor-pointer disabled:opacity-50"
                >
                  {adding ? (
                    <>
                      <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                      <span>Adding...</span>
                    </>
                  ) : (
                    <span>Add to Watchlist</span>
                  )}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
