import React, { useState } from 'react';
import { Eye, X, AlertTriangle, ArrowRight } from 'lucide-react';
import { huntingService } from '../../services/huntingService';

interface WatchlistHandoffModalProps {
  isOpen: boolean;
  onClose: () => void;
  executionId: string;
  selectedIds: string[];
  onSuccess: (watchlistId: string) => void;
}

export const WatchlistHandoffModal: React.FC<WatchlistHandoffModalProps> = ({
  isOpen,
  onClose,
  executionId,
  selectedIds,
  onSuccess,
}) => {
  const [watchlistName, setWatchlistName] = useState('');
  const [reason, setReason] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    setError(null);

    try {
      const res = await huntingService.handoffWatchlist({
        execution_id: executionId,
        selected_record_ids: selectedIds,
        new_watchlist_name: watchlistName.trim() || undefined,
        reason: reason.trim() || undefined,
      });

      onSuccess(res.watchlist_id);
      onClose();
    } catch (err: any) {
      setError(err.message || 'Failed to add indicators to Watchlist.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-xs flex items-center justify-center p-4">
      <div className="bg-surface border border-border rounded-panel w-full max-w-lg shadow-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-150">
        <div className="p-4 border-b border-border flex items-center justify-between bg-surface-secondary/50">
          <div className="flex items-center space-x-2.5">
            <div className="w-8 h-8 rounded-control bg-primary/10 text-primary flex items-center justify-center border border-primary/20">
              <Eye className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-sm font-sans font-bold text-foreground">Add to Continuous Monitoring</h3>
              <p className="text-xs text-foreground-muted">Watch {selectedIds.length} candidate observable(s) via Section 53</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 text-foreground-muted hover:text-foreground rounded-control hover:bg-surface border border-transparent hover:border-border transition-colors cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-5 space-y-4">
          {error && (
            <div className="p-3 bg-threat-critical/10 border border-threat-critical/20 rounded-control flex items-start space-x-2 text-xs text-threat-critical">
              <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          <div>
            <label className="block text-xs font-mono font-medium text-foreground-muted mb-1.5 uppercase">
              Target Watchlist Name
            </label>
            <input
              type="text"
              value={watchlistName}
              onChange={(e) => setWatchlistName(e.target.value)}
              placeholder="e.g. Proactive Hunt IOCs - Campaign Delta"
              className="w-full px-3 py-2 text-xs bg-surface-secondary border border-border rounded-control text-foreground focus:outline-hidden focus:border-primary"
            />
          </div>

          <div>
            <label className="block text-xs font-mono font-medium text-foreground-muted mb-1.5 uppercase">
              Monitoring Justification / Reason
            </label>
            <textarea
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              rows={2}
              placeholder="Why should CyberGuard continuously watch these observables for intelligence changes?"
              className="w-full px-3 py-2 text-xs bg-surface-secondary border border-border rounded-control text-foreground focus:outline-hidden focus:border-primary resize-none"
            />
          </div>

          <div className="p-3 bg-surface-secondary/60 border border-border rounded-control text-xs space-y-1">
            <div className="text-foreground-muted font-mono uppercase text-[10px]">Continuous Monitoring Integration</div>
            <p className="text-foreground text-[11px]">
              Once added, Section 53 will periodically query consensus threat intelligence providers and trigger alerts if material reputation shifts occur.
            </p>
          </div>

          <div className="pt-2 flex items-center justify-end space-x-3 border-t border-border">
            <button
              type="button"
              onClick={onClose}
              disabled={submitting}
              className="px-3.5 py-1.5 text-xs text-foreground-muted hover:text-foreground rounded-control border border-border bg-surface hover:bg-surface-secondary cursor-pointer"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={submitting}
              className="px-4 py-1.5 text-xs font-medium text-white bg-primary hover:bg-primary/90 rounded-control flex items-center space-x-1.5 cursor-pointer disabled:opacity-50"
            >
              {submitting ? (
                <span>Adding to Watchlist...</span>
              ) : (
                <>
                  <span>Add to Watchlist</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
