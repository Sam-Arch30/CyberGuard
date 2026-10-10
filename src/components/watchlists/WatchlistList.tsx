import React, { useState } from 'react';
import {
  Eye,
  Plus,
  Search,
  RefreshCw,
  Clock,
  AlertTriangle,
  Play,
  Pause,
  ChevronRight,
  Sliders,
  Layers,
} from 'lucide-react';
import type { WatchlistSummary, WatchlistPriority, WatchlistStatus } from '../../types/watchlist';
import { WatchlistService } from '../../services/watchlistService';

interface WatchlistListProps {
  watchlists: WatchlistSummary[];
  loading: boolean;
  onSelectWatchlist: (id: string) => void;
  onRefreshList: () => void;
}

export const WatchlistList: React.FC<WatchlistListProps> = ({
  watchlists,
  loading,
  onSelectWatchlist,
  onRefreshList,
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [priorityFilter, setPriorityFilter] = useState<string>('ALL');
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [actionLoadingId, setActionLoadingId] = useState<string | null>(null);

  // New Watchlist Form State
  const [newName, setNewName] = useState('');
  const [newDesc, setNewDesc] = useState('');
  const [newPriority, setNewPriority] = useState<WatchlistPriority>('MEDIUM');
  const [newInterval, setNewInterval] = useState<number>(60);
  const [newAlertThreshold, setNewAlertThreshold] = useState<'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'>('HIGH');
  const [newCooldown, setNewCooldown] = useState<number>(360);
  const [newNotify, setNewNotify] = useState<boolean>(true);
  const [creating, setCreating] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);

  // Filter logic
  const filtered = watchlists.filter((wl) => {
    if (statusFilter !== 'ALL' && wl.status !== statusFilter) return false;
    if (priorityFilter !== 'ALL' && wl.priority !== priorityFilter) return false;
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      const matchName = wl.name.toLowerCase().includes(term);
      const matchDesc = wl.description?.toLowerCase().includes(term) ?? false;
      if (!matchName && !matchDesc) return false;
    }
    return true;
  });

  // Aggregate Metrics
  const totalIndicators = watchlists.reduce((acc, wl) => acc + wl.total_indicators_count, 0);
  const activeCount = watchlists.filter((wl) => wl.status === 'ACTIVE').length;
  const maliciousCount = watchlists.reduce((acc, wl) => acc + wl.malicious_indicators_count, 0);
  const staleCount = watchlists.reduce((acc, wl) => acc + wl.stale_indicators_count, 0);

  const handleToggleStatus = async (e: React.MouseEvent, wl: WatchlistSummary) => {
    e.stopPropagation();
    setActionLoadingId(wl.id);
    try {
      const targetStatus: WatchlistStatus = wl.status === 'ACTIVE' ? 'PAUSED' : 'ACTIVE';
      await WatchlistService.updateWatchlist(wl.id, { status: targetStatus });
      onRefreshList();
    } catch (err) {
      console.error('Failed to toggle status:', err);
    } finally {
      setActionLoadingId(null);
    }
  };

  const handleRefreshWatchlist = async (e: React.MouseEvent, wl: WatchlistSummary) => {
    e.stopPropagation();
    setActionLoadingId(wl.id);
    try {
      await WatchlistService.refreshWatchlist(wl.id);
      onRefreshList();
    } catch (err) {
      console.error('Failed to refresh watchlist:', err);
    } finally {
      setActionLoadingId(null);
    }
  };

  const handleCreateWatchlist = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreating(true);
    setCreateError(null);
    try {
      await WatchlistService.createWatchlist({
        name: newName,
        description: newDesc || undefined,
        priority: newPriority,
        check_interval_minutes: Number(newInterval),
        alert_threshold: newAlertThreshold,
        cooldown_minutes: Number(newCooldown),
        notify_on_change: newNotify,
      });
      setShowCreateModal(false);
      setNewName('');
      setNewDesc('');
      onRefreshList();
    } catch (err) {
      setCreateError(err instanceof Error ? err.message : 'Failed to create watchlist.');
    } finally {
      setCreating(false);
    }
  };

  return (
    <div className="space-y-4">
      {/* 1. Header Metrics Ribbon */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="p-3 bg-surface border border-border rounded-control shadow-xs space-y-1">
          <div className="text-[10px] uppercase font-mono tracking-wider text-foreground-muted flex items-center space-x-1.5">
            <Layers className="w-3.5 h-3.5 text-primary" />
            <span>Active Watchlists</span>
          </div>
          <div className="text-xl font-bold font-mono text-foreground">
            {activeCount} <span className="text-xs text-foreground-muted font-normal">/ {watchlists.length}</span>
          </div>
        </div>

        <div className="p-3 bg-surface border border-border rounded-control shadow-xs space-y-1">
          <div className="text-[10px] uppercase font-mono tracking-wider text-foreground-muted flex items-center space-x-1.5">
            <Eye className="w-3.5 h-3.5 text-primary" />
            <span>Monitored IOCs</span>
          </div>
          <div className="text-xl font-bold font-mono text-foreground">
            {totalIndicators}
          </div>
        </div>

        <div className="p-3 bg-surface border border-border rounded-control shadow-xs space-y-1">
          <div className="text-[10px] uppercase font-mono tracking-wider text-foreground-muted flex items-center space-x-1.5">
            <AlertTriangle className="w-3.5 h-3.5 text-danger" />
            <span>Malicious IOCs</span>
          </div>
          <div className="text-xl font-bold font-mono text-danger">
            {maliciousCount}
          </div>
        </div>

        <div className="p-3 bg-surface border border-border rounded-control shadow-xs space-y-1">
          <div className="text-[10px] uppercase font-mono tracking-wider text-foreground-muted flex items-center space-x-1.5">
            <Clock className="w-3.5 h-3.5 text-amber-400" />
            <span>Stale Items</span>
          </div>
          <div className="text-xl font-bold font-mono text-amber-400">
            {staleCount}
          </div>
        </div>
      </div>

      {/* 2. Controls & Search Toolbar */}
      <div className="p-3 bg-surface border border-border rounded-control shadow-xs flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2 flex-1">
          {/* Search */}
          <div className="relative flex-1 min-w-[200px] max-w-md">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-foreground-muted" />
            <input
              type="text"
              placeholder="Search watchlists..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-8 pr-3 py-1.5 bg-surface-secondary border border-border rounded-control text-xs text-foreground placeholder:text-foreground-muted focus:outline-hidden focus:border-primary"
            />
          </div>

          {/* Status Filter */}
          <div className="flex items-center space-x-1 bg-surface-secondary border border-border rounded-control p-0.5 text-xs">
            {['ALL', 'ACTIVE', 'PAUSED'].map((st) => (
              <button
                key={st}
                type="button"
                onClick={() => setStatusFilter(st)}
                className={`px-2 py-1 rounded-control text-[11px] font-mono transition-colors cursor-pointer ${
                  statusFilter === st
                    ? 'bg-primary text-primary-foreground font-bold'
                    : 'text-foreground-muted hover:text-foreground'
                }`}
              >
                {st}
              </button>
            ))}
          </div>

          {/* Priority Filter */}
          <select
            value={priorityFilter}
            onChange={(e) => setPriorityFilter(e.target.value)}
            className="bg-surface-secondary border border-border rounded-control px-2.5 py-1.5 text-xs text-foreground focus:outline-hidden focus:border-primary cursor-pointer"
          >
            <option value="ALL">All Priorities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
        </div>

        {/* Action Buttons */}
        <div className="flex items-center space-x-2">
          <button
            type="button"
            onClick={onRefreshList}
            disabled={loading}
            className="p-1.5 rounded-control border border-border text-foreground hover:bg-surface-secondary cursor-pointer disabled:opacity-50"
            title="Refresh list"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-primary' : ''}`} />
          </button>
          <button
            type="button"
            onClick={() => setShowCreateModal(true)}
            className="px-3 py-1.5 rounded-control bg-primary hover:bg-primary-hover text-primary-foreground font-semibold text-xs flex items-center space-x-1.5 shadow-xs cursor-pointer"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>New Watchlist</span>
          </button>
        </div>
      </div>

      {/* 3. Watchlists List Table / Cards */}
      {loading && watchlists.length === 0 ? (
        <div className="p-12 text-center text-foreground-muted font-mono text-xs flex flex-col items-center justify-center space-y-2 bg-surface rounded-control border border-border">
          <RefreshCw className="w-5 h-5 animate-spin text-primary" />
          <span>Loading watchlists...</span>
        </div>
      ) : filtered.length === 0 ? (
        <div className="p-12 text-center text-foreground-muted bg-surface rounded-control border border-border space-y-3">
          <Eye className="w-8 h-8 mx-auto text-foreground-muted opacity-50" />
          <div className="text-sm font-bold text-foreground">No watchlists found</div>
          <p className="text-xs max-w-sm mx-auto">
            {searchTerm || statusFilter !== 'ALL' || priorityFilter !== 'ALL'
              ? 'No watchlists match the current search filters. Try clearing your filters.'
              : 'Create a watchlist to continuously monitor important indicators and receive alerts when threat intelligence changes.'}
          </p>
          {!searchTerm && statusFilter === 'ALL' && (
            <button
              type="button"
              onClick={() => setShowCreateModal(true)}
              className="px-3.5 py-1.5 rounded-control bg-primary text-primary-foreground text-xs font-semibold inline-flex items-center space-x-1.5 cursor-pointer"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Create First Watchlist</span>
            </button>
          )}
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3.5">
          {filtered.map((wl) => {
            const isPaused = wl.status === 'PAUSED';
            const isActionLoading = actionLoadingId === wl.id;

            return (
              <div
                key={wl.id}
                onClick={() => onSelectWatchlist(wl.id)}
                className={`p-4 bg-surface border rounded-control shadow-xs hover:border-primary/50 transition-all cursor-pointer flex flex-col justify-between space-y-3.5 ${
                  isPaused ? 'border-border opacity-75' : 'border-border'
                }`}
              >
                {/* Header */}
                <div className="space-y-1.5">
                  <div className="flex items-start justify-between gap-2">
                    <h4 className="font-bold text-foreground text-sm flex items-center space-x-1.5 truncate">
                      <span className="truncate">{wl.name}</span>
                    </h4>
                    <span
                      className={`text-[10px] font-mono px-1.5 py-0.5 rounded-control border font-semibold ${
                        wl.priority === 'CRITICAL'
                          ? 'bg-danger-surface border-danger-border text-danger'
                          : wl.priority === 'HIGH'
                          ? 'bg-amber-500/10 border-amber-500/30 text-amber-400'
                          : 'bg-surface-secondary border-border text-foreground-muted'
                      }`}
                    >
                      {wl.priority}
                    </span>
                  </div>

                  {wl.description && (
                    <p className="text-xs text-foreground-muted line-clamp-2 leading-relaxed">
                      {wl.description}
                    </p>
                  )}
                </div>

                {/* Telemetry Stats Ribbon */}
                <div className="grid grid-cols-3 gap-1 py-2 px-2.5 bg-surface-secondary/60 rounded-control border border-border text-center">
                  <div>
                    <span className="text-[10px] text-foreground-muted block font-mono">IOCs</span>
                    <span className="text-xs font-bold font-mono text-foreground">{wl.total_indicators_count}</span>
                  </div>
                  <div>
                    <span className="text-[10px] text-foreground-muted block font-mono">Malicious</span>
                    <span className={`text-xs font-bold font-mono ${wl.malicious_indicators_count > 0 ? 'text-danger' : 'text-foreground-muted'}`}>
                      {wl.malicious_indicators_count}
                    </span>
                  </div>
                  <div>
                    <span className="text-[10px] text-foreground-muted block font-mono">Cycle</span>
                    <span className="text-xs font-mono text-foreground-muted">{wl.check_interval_minutes}m</span>
                  </div>
                </div>

                {/* Footer Controls */}
                <div className="pt-2 border-t border-border flex items-center justify-between text-xs">
                  <div className="flex items-center space-x-1.5">
                    <span
                      className={`w-2 h-2 rounded-full ${
                        wl.status === 'ACTIVE' ? 'bg-emerald-400 animate-pulse' : 'bg-foreground-muted'
                      }`}
                    />
                    <span className="text-[11px] font-mono text-foreground-muted">
                      {wl.status}
                    </span>
                  </div>

                  <div className="flex items-center space-x-1" onClick={(e) => e.stopPropagation()}>
                    <button
                      type="button"
                      onClick={(e) => handleRefreshWatchlist(e, wl)}
                      disabled={isActionLoading || isPaused}
                      className="p-1 text-foreground-muted hover:text-foreground rounded-control hover:bg-surface-secondary cursor-pointer disabled:opacity-40"
                      title="Run continuous check now"
                    >
                      <RefreshCw className={`w-3.5 h-3.5 ${isActionLoading ? 'animate-spin text-primary' : ''}`} />
                    </button>
                    <button
                      type="button"
                      onClick={(e) => handleToggleStatus(e, wl)}
                      disabled={isActionLoading}
                      className="p-1 text-foreground-muted hover:text-foreground rounded-control hover:bg-surface-secondary cursor-pointer"
                      title={isPaused ? 'Resume monitoring' : 'Pause monitoring'}
                    >
                      {isPaused ? <Play className="w-3.5 h-3.5 text-emerald-400" /> : <Pause className="w-3.5 h-3.5 text-amber-400" />}
                    </button>
                    <ChevronRight className="w-4 h-4 text-foreground-muted group-hover:text-foreground" />
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* 4. Create Watchlist Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4 animate-in fade-in duration-150">
          <div className="bg-surface border border-border rounded-control shadow-xl w-full max-w-lg overflow-hidden flex flex-col">
            <div className="p-4 border-b border-border flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <Sliders className="w-4 h-4 text-primary" />
                <h3 className="text-sm font-bold text-foreground">Create New Threat Watchlist</h3>
              </div>
              <button
                type="button"
                onClick={() => setShowCreateModal(false)}
                className="text-foreground-muted hover:text-foreground p-1 rounded-control hover:bg-surface-secondary cursor-pointer"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleCreateWatchlist} className="p-4 space-y-4 text-xs">
              {createError && (
                <div className="p-3 bg-danger-surface border border-danger-border rounded-control text-danger flex items-center space-x-2">
                  <AlertTriangle className="w-4 h-4 shrink-0" />
                  <span>{createError}</span>
                </div>
              )}

              <div className="space-y-1">
                <label className="font-semibold text-foreground">Watchlist Name *</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Critical C2 Infrastructure or Incident INC-042 IOCs"
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                  className="w-full bg-surface-secondary border border-border rounded-control px-2.5 py-1.5 text-foreground text-xs focus:outline-hidden focus:border-primary"
                />
              </div>

              <div className="space-y-1">
                <label className="font-semibold text-foreground">Description</label>
                <textarea
                  rows={2}
                  placeholder="Operational context and monitoring scope..."
                  value={newDesc}
                  onChange={(e) => setNewDesc(e.target.value)}
                  className="w-full bg-surface-secondary border border-border rounded-control px-2.5 py-1.5 text-foreground text-xs focus:outline-hidden focus:border-primary resize-none"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <label className="font-semibold text-foreground">Priority</label>
                  <select
                    value={newPriority}
                    onChange={(e) => setNewPriority(e.target.value as WatchlistPriority)}
                    className="w-full bg-surface-secondary border border-border rounded-control px-2.5 py-1.5 text-foreground text-xs focus:outline-hidden focus:border-primary cursor-pointer"
                  >
                    <option value="CRITICAL">Critical</option>
                    <option value="HIGH">High</option>
                    <option value="MEDIUM">Medium</option>
                    <option value="LOW">Low</option>
                  </select>
                </div>

                <div className="space-y-1">
                  <label className="font-semibold text-foreground">Check Interval</label>
                  <select
                    value={newInterval}
                    onChange={(e) => setNewInterval(Number(e.target.value))}
                    className="w-full bg-surface-secondary border border-border rounded-control px-2.5 py-1.5 text-foreground text-xs focus:outline-hidden focus:border-primary cursor-pointer"
                  >
                    <option value={15}>Every 15 minutes</option>
                    <option value={60}>Every 1 hour (Default)</option>
                    <option value={360}>Every 6 hours</option>
                    <option value={720}>Every 12 hours</option>
                    <option value={1440}>Daily (24 hours)</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <label className="font-semibold text-foreground">Alert Threshold</label>
                  <select
                    value={newAlertThreshold}
                    onChange={(e) => setNewAlertThreshold(e.target.value as any)}
                    className="w-full bg-surface-secondary border border-border rounded-control px-2.5 py-1.5 text-foreground text-xs focus:outline-hidden focus:border-primary cursor-pointer"
                  >
                    <option value="CRITICAL">Critical Changes Only</option>
                    <option value="HIGH">High & Critical Changes</option>
                    <option value="MEDIUM">Medium, High & Critical</option>
                    <option value="LOW">All Changes</option>
                  </select>
                </div>

                <div className="space-y-1">
                  <label className="font-semibold text-foreground">Alert Cooldown</label>
                  <select
                    value={newCooldown}
                    onChange={(e) => setNewCooldown(Number(e.target.value))}
                    className="w-full bg-surface-secondary border border-border rounded-control px-2.5 py-1.5 text-foreground text-xs focus:outline-hidden focus:border-primary cursor-pointer"
                  >
                    <option value={60}>1 hour</option>
                    <option value={360}>6 hours (Default)</option>
                    <option value={720}>12 hours</option>
                    <option value={1440}>24 hours</option>
                  </select>
                </div>
              </div>

              <div className="flex items-center space-x-2 pt-1">
                <input
                  type="checkbox"
                  id="notifyChange"
                  checked={newNotify}
                  onChange={(e) => setNewNotify(e.target.checked)}
                  className="rounded-control border-border text-primary cursor-pointer"
                />
                <label htmlFor="notifyChange" className="text-foreground cursor-pointer select-none">
                  Send in-app notifications when intelligence changes
                </label>
              </div>

              <div className="pt-3 border-t border-border flex items-center justify-end space-x-2">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-3 py-1.5 rounded-control border border-border text-foreground hover:bg-surface-secondary text-xs cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={creating}
                  className="px-3.5 py-1.5 rounded-control bg-primary text-primary-foreground font-semibold text-xs flex items-center space-x-1.5 cursor-pointer disabled:opacity-50"
                >
                  {creating ? (
                    <>
                      <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                      <span>Creating...</span>
                    </>
                  ) : (
                    <span>Create Watchlist</span>
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
