import React, { useState, useEffect } from 'react';
import { Shield, Eye, Check, X, AlertTriangle, RefreshCw } from 'lucide-react';
import { WatchlistService } from '../../services/watchlistService';
import type { WatchlistSummary } from '../../types/watchlist';

interface QuickWatchModalProps {
  isOpen: boolean;
  onClose: () => void;
  indicatorValue: string;
  indicatorType?: string;
  sourceIncidentId?: string;
  sourceInvestigationId?: string;
  onSuccess?: () => void;
}

export const QuickWatchModal: React.FC<QuickWatchModalProps> = ({
  isOpen,
  onClose,
  indicatorValue,
  indicatorType,
  sourceIncidentId,
  sourceInvestigationId,
  onSuccess,
}) => {
  const [watchlists, setWatchlists] = useState<WatchlistSummary[]>([]);
  const [selectedWatchlistId, setSelectedWatchlistId] = useState<string>('');
  const [newWatchlistName, setNewWatchlistName] = useState<string>('');
  const [reason, setReason] = useState<string>('Suspicious observable identified during triage.');
  const [loading, setLoading] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  useEffect(() => {
    if (isOpen) {
      setError(null);
      setSuccess(false);
      setLoading(true);
      WatchlistService.listWatchlists({ status: 'ACTIVE' })
        .then((res) => {
          setWatchlists(res.items);
          if (res.items.length > 0) {
            setSelectedWatchlistId(res.items[0].id);
          }
        })
        .catch((err) => {
          setError(err instanceof Error ? err.message : 'Failed to load watchlists.');
        })
        .finally(() => setLoading(false));
    }
  }, [isOpen]);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    setError(null);

    try {
      await WatchlistService.quickWatch({
        indicator_value: indicatorValue,
        indicator_type: indicatorType,
        watchlist_id: selectedWatchlistId || undefined,
        watchlist_name: !selectedWatchlistId && newWatchlistName ? newWatchlistName : undefined,
        source_incident_id: sourceIncidentId,
        source_investigation_id: sourceInvestigationId,
        reason,
      });
      setSuccess(true);
      setTimeout(() => {
        onSuccess?.();
        onClose();
      }, 1000);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to watch indicator.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4 animate-in fade-in duration-150">
      <div className="bg-surface border border-border rounded-control shadow-xl w-full max-w-md overflow-hidden flex flex-col">
        {/* Header */}
        <div className="p-4 border-b border-border flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <Eye className="w-4 h-4 text-primary" />
            <h3 className="text-sm font-bold text-foreground">Continuously Monitor Indicator</h3>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="text-foreground-muted hover:text-foreground p-1 rounded-control hover:bg-surface-secondary cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Content */}
        <form onSubmit={handleSubmit} className="p-4 space-y-4 text-xs">
          {error && (
            <div className="p-3 bg-danger-surface border border-danger-border rounded-control text-danger flex items-center space-x-2">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {success && (
            <div className="p-3 bg-emerald-500/10 border border-emerald-500/30 rounded-control text-emerald-400 flex items-center space-x-2">
              <Check className="w-4 h-4 shrink-0" />
              <span>Indicator added to continuous monitoring watchlist!</span>
            </div>
          )}

          {/* Observable Card */}
          <div className="p-3 bg-surface-secondary border border-border rounded-control space-y-1">
            <div className="text-[10px] uppercase font-mono tracking-wider text-foreground-muted">
              Target Observable
            </div>
            <div className="font-mono font-bold text-foreground break-all">
              {indicatorValue}
            </div>
            {indicatorType && (
              <span className="inline-block text-[10px] font-mono px-1.5 py-0.5 rounded-full bg-surface text-primary border border-border">
                {indicatorType}
              </span>
            )}
          </div>

          {/* Target Watchlist */}
          <div className="space-y-1.5">
            <label className="font-semibold text-foreground">Assign to Watchlist</label>
            {loading ? (
              <div className="py-2 text-foreground-muted text-center flex items-center justify-center space-x-2">
                <RefreshCw className="w-3.5 h-3.5 animate-spin text-primary" />
                <span>Loading available watchlists...</span>
              </div>
            ) : watchlists.length > 0 ? (
              <select
                value={selectedWatchlistId}
                onChange={(e) => setSelectedWatchlistId(e.target.value)}
                className="w-full bg-surface-secondary border border-border rounded-control px-2.5 py-1.5 text-foreground text-xs focus:outline-hidden focus:border-primary"
              >
                {watchlists.map((wl) => (
                  <option key={wl.id} value={wl.id}>
                    {wl.name} ({wl.priority} · {wl.total_indicators_count} items)
                  </option>
                ))}
                <option value="">+ Create new watchlist...</option>
              </select>
            ) : (
              <input
                type="text"
                placeholder="New Watchlist Name (e.g. Investigation Watchlist)"
                value={newWatchlistName}
                onChange={(e) => setNewWatchlistName(e.target.value)}
                className="w-full bg-surface-secondary border border-border rounded-control px-2.5 py-1.5 text-foreground text-xs focus:outline-hidden focus:border-primary"
              />
            )}

            {!selectedWatchlistId && watchlists.length > 0 && (
              <input
                type="text"
                placeholder="Enter new watchlist name"
                value={newWatchlistName}
                onChange={(e) => setNewWatchlistName(e.target.value)}
                required={!selectedWatchlistId}
                className="w-full mt-2 bg-surface-secondary border border-border rounded-control px-2.5 py-1.5 text-foreground text-xs focus:outline-hidden focus:border-primary"
              />
            )}
          </div>

          {/* Reason */}
          <div className="space-y-1.5">
            <label className="font-semibold text-foreground">Monitoring Context / Reason</label>
            <textarea
              rows={2}
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="Why is this observable important to monitor?"
              className="w-full bg-surface-secondary border border-border rounded-control px-2.5 py-1.5 text-foreground text-xs focus:outline-hidden focus:border-primary resize-none"
            />
          </div>

          <div className="text-[11px] text-foreground-muted flex items-start space-x-1.5">
            <Shield className="w-3.5 h-3.5 text-primary shrink-0 mt-0.5" />
            <span>
              CyberGuard will check threat intelligence providers on the configured schedule and notify you when intelligence materially changes.
            </span>
          </div>

          {/* Footer Controls */}
          <div className="pt-2 border-t border-border flex items-center justify-end space-x-2">
            <button
              type="button"
              onClick={onClose}
              disabled={submitting}
              className="px-3 py-1.5 rounded-control border border-border hover:bg-surface-secondary text-foreground text-xs cursor-pointer"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={submitting || success}
              className="px-3 py-1.5 rounded-control bg-primary hover:bg-primary-hover text-primary-foreground font-semibold text-xs flex items-center space-x-1.5 cursor-pointer disabled:opacity-50"
            >
              {submitting ? (
                <>
                  <RefreshCw className="w-3 h-3 animate-spin" />
                  <span>Scheduling...</span>
                </>
              ) : (
                <>
                  <Eye className="w-3 h-3" />
                  <span>Start Monitoring</span>
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
