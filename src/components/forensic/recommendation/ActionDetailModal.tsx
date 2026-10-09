import React, { useState } from 'react';
import {
  X,
  ShieldAlert,
  AlertTriangle,
  Info,
  Play
} from 'lucide-react';
import type { ResponseRecommendation } from '../../../types/response_recommendation';
import { apiUrl } from '../../../utils/apiClient';
import { PlaybookExecutionModal } from './PlaybookExecutionModal';

interface ActionDetailModalProps {
  recommendation: ResponseRecommendation | null;
  onClose: () => void;
  onStatusUpdated?: (updated: ResponseRecommendation) => void;
}

export const ActionDetailModal: React.FC<ActionDetailModalProps> = ({
  recommendation,
  onClose,
  onStatusUpdated
}) => {
  const [reviewMode, setReviewMode] = useState<boolean>(false);
  const [disposition, setDisposition] = useState<'APPROVED' | 'REJECTED' | 'DEFERRED'>('APPROVED');
  const [notes, setNotes] = useState<string>('');
  const [submitting, setSubmitting] = useState<boolean>(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [showPlaybookModal, setShowPlaybookModal] = useState<boolean>(false);

  if (!recommendation) return null;

  const handleReviewSubmit = async () => {
    if (!notes.trim()) {
      setSubmitError('Reviewer justification note is required for audit trail.');
      return;
    }
    setSubmitting(true);
    setSubmitError(null);
    try {
      const endpoint = disposition.toLowerCase();
      const res = await fetch(apiUrl(`/api/v1/recommendations/${recommendation.id}/${endpoint}`), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          reviewer_id: 'current_analyst',
          disposition,
          notes: notes.trim()
        })
      });
      if (res.ok) {
        const updated: ResponseRecommendation = await res.json();
        if (onStatusUpdated) onStatusUpdated(updated);
        onClose();
      } else {
        const err = await res.json().catch(() => ({ detail: 'Failed to record decision' }));
        setSubmitError(err.detail || 'Review submission failed');
      }
    } catch (err: any) {
      setSubmitError(err?.message || 'Network error communicating with recommendation engine');
    } finally {
      setSubmitting(false);
    }
  };

  const getPriorityColor = (p: string) => {
    switch (p) {
      case 'P0':
        return 'bg-rose-500/10 text-rose-400 border-rose-500/30';
      case 'P1':
        return 'bg-amber-500/10 text-amber-400 border-amber-500/30';
      case 'P2':
        return 'bg-blue-500/10 text-blue-400 border-blue-500/30';
      default:
        return 'bg-slate-500/10 text-slate-400 border-slate-500/30';
    }
  };

  return (
    <>
      <div className="fixed inset-0 z-50 overflow-hidden flex items-center justify-center bg-black/70 backdrop-blur-xs p-4 animate-in fade-in duration-150">
      <div className="w-full max-w-2xl bg-surface border border-border rounded-xl shadow-2xl flex flex-col max-h-[90vh] overflow-hidden animate-in zoom-in-95 duration-200">
        {/* Header */}
        <div className="p-4 sm:p-5 border-b border-border bg-surface-secondary/40 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-lg bg-primary/10 border border-primary/20 text-primary">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className={`text-[10px] px-2 py-0.5 rounded font-mono font-bold border ${getPriorityColor(recommendation.priority)}`}>
                  {recommendation.priority}
                </span>
                <span className="text-[10px] px-2 py-0.5 rounded font-mono font-semibold bg-surface-tertiary text-foreground-muted border border-border">
                  {recommendation.category}
                </span>
                {recommendation.approval_required ? (
                  <span className="text-[10px] px-2 py-0.5 rounded font-mono font-bold bg-rose-500/10 text-rose-400 border border-rose-500/30">
                    APPROVAL REQUIRED
                  </span>
                ) : (
                  <span className="text-[10px] px-2 py-0.5 rounded font-mono font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                    ADVISORY / PRE-APPROVED
                  </span>
                )}
              </div>
              <h3 className="text-sm sm:text-base font-semibold text-foreground mt-1 line-clamp-1">
                {recommendation.title}
              </h3>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="p-1.5 rounded-lg text-foreground-muted hover:text-foreground hover:bg-surface-tertiary transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Scrollable Body */}
        <div className="p-4 sm:p-5 overflow-y-auto space-y-4 text-xs font-sans">
          {/* Action Overview */}
          <div className="p-3.5 rounded-xl border border-border bg-surface-secondary/30 space-y-2">
            <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-foreground-muted">
              Action Description
            </span>
            <p className="text-foreground leading-relaxed">
              {recommendation.description}
            </p>
          </div>

          {/* Rationale & Evidence Backing */}
          <div className="p-3.5 rounded-xl border border-blue-500/20 bg-blue-500/5 space-y-2">
            <div className="flex items-center space-x-2 text-blue-400">
              <Info className="w-4 h-4" />
              <span className="text-[10px] font-mono font-bold uppercase tracking-wider">
                Investigative Rationale & Evidence Grounding
              </span>
            </div>
            <p className="text-foreground-muted leading-relaxed">
              {recommendation.rationale}
            </p>
            {recommendation.evidence_refs.length > 0 && (
              <div className="pt-2 border-t border-blue-500/20 flex flex-wrap items-center gap-1.5 text-[11px] font-mono text-blue-300">
                <span>Linked Telemetry:</span>
                {recommendation.evidence_refs.map((ref, idx) => (
                  <span key={idx} className="px-1.5 py-0.5 rounded bg-blue-500/10 border border-blue-500/30">
                    {ref}
                  </span>
                ))}
              </div>
            )}
          </div>

          {/* Risk-Benefit Breakdown */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div className="p-3 rounded-xl border border-emerald-500/20 bg-emerald-500/5 space-y-1">
              <span className="text-[10px] font-mono font-bold text-emerald-400 uppercase">
                Expected Defensive Effect
              </span>
              <p className="text-foreground-muted leading-snug">
                {recommendation.expected_effect}
              </p>
            </div>
            <div className="p-3 rounded-xl border border-amber-500/20 bg-amber-500/5 space-y-1">
              <span className="text-[10px] font-mono font-bold text-amber-400 uppercase">
                Potential Operational Impact ({recommendation.impact})
              </span>
              <p className="text-foreground-muted leading-snug">
                Reversibility: <strong className="text-foreground">{recommendation.reversibility}</strong>. Operational impact classified as {recommendation.impact.toLowerCase()}.
              </p>
            </div>
          </div>

          {/* Affected Entities */}
          {recommendation.affected_entities.length > 0 && (
            <div className="space-y-1.5">
              <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-foreground-muted">
                Target Entities ({recommendation.affected_entities.length})
              </span>
              <div className="flex flex-wrap gap-2">
                {recommendation.affected_entities.map((e, idx) => (
                  <div key={idx} className="px-2.5 py-1 rounded-lg border border-border bg-surface-secondary text-xs font-mono flex items-center space-x-2">
                    <span className="text-[10px] text-foreground-muted">{e.entity_type}:</span>
                    <span className="font-semibold text-foreground">{e.identifier}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Prerequisites */}
          {recommendation.prerequisites.length > 0 && (
            <div className="space-y-1.5">
              <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-foreground-muted">
                Action Prerequisites & Readiness
              </span>
              <div className="space-y-1.5">
                {recommendation.prerequisites.map((p, idx) => (
                  <div key={idx} className="p-2.5 rounded-lg border border-border bg-surface-secondary/40 flex items-center justify-between text-xs">
                    <div className="space-y-0.5">
                      <div className="font-semibold text-foreground">{p.name}</div>
                      <div className="text-[11px] text-foreground-muted">{p.description}</div>
                    </div>
                    <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${
                      p.satisfied ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' : 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                    }`}>
                      {p.satisfied ? 'SATISFIED' : 'PENDING'}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Conflicts */}
          {recommendation.conflicts_with.length > 0 && (
            <div className="p-3 rounded-xl border border-amber-500/30 bg-amber-500/10 space-y-1.5">
              <div className="flex items-center space-x-2 text-amber-400">
                <AlertTriangle className="w-4 h-4" />
                <span className="text-[10px] font-mono font-bold uppercase">Operational Trade-off Conflict</span>
              </div>
              {recommendation.conflicts_with.map((cf, idx) => (
                <p key={idx} className="text-xs text-foreground-muted">
                  {cf.tradeoff_explanation}
                </p>
              ))}
            </div>
          )}

          {/* Review Disposition Form */}
          {reviewMode ? (
            <div className="p-4 rounded-xl border border-primary/30 bg-primary/5 space-y-3 pt-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono font-bold uppercase text-foreground">
                  Record Analyst Decision
                </span>
                <button
                  type="button"
                  onClick={() => setReviewMode(false)}
                  className="text-xs font-mono text-foreground-muted hover:text-foreground"
                >
                  Cancel
                </button>
              </div>

              {submitError && (
                <div className="p-2 rounded bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs font-mono">
                  {submitError}
                </div>
              )}

              <div className="grid grid-cols-3 gap-2">
                {(['APPROVED', 'REJECTED', 'DEFERRED'] as const).map((disp) => (
                  <button
                    key={disp}
                    type="button"
                    onClick={() => setDisposition(disp)}
                    className={`py-2 text-xs font-mono font-bold rounded-lg border transition-colors ${
                      disposition === disp
                        ? disp === 'APPROVED'
                          ? 'bg-emerald-500/20 text-emerald-400 border-emerald-500/50'
                          : disp === 'REJECTED'
                          ? 'bg-rose-500/20 text-rose-400 border-rose-500/50'
                          : 'bg-amber-500/20 text-amber-400 border-amber-500/50'
                        : 'bg-surface border-border text-foreground-muted hover:text-foreground'
                    }`}
                  >
                    {disp}
                  </button>
                ))}
              </div>

              <div className="space-y-1">
                <label className="text-[11px] font-mono text-foreground-muted">
                  Investigative Justification / Reason:
                </label>
                <textarea
                  rows={3}
                  value={notes}
                  onChange={(e) => setNotes(e.target.value)}
                  placeholder="e.g., Authorized blocking following verification of credential harvesting indicators."
                  className="w-full p-2.5 rounded-lg bg-surface border border-border text-foreground text-xs font-sans placeholder:text-foreground-muted/50"
                />
              </div>

              <button
                type="button"
                onClick={handleReviewSubmit}
                disabled={submitting || !notes.trim()}
                className="w-full py-2 rounded-lg bg-primary hover:bg-primary-hover text-primary-foreground font-mono font-bold text-xs transition-colors disabled:opacity-50"
              >
                {submitting ? 'Submitting...' : `Confirm ${disposition}`}
              </button>
            </div>
          ) : (
            <div className="p-3 rounded-lg border border-border bg-surface-secondary/20 flex flex-col sm:flex-row items-center justify-between gap-3">
              <div className="space-y-0.5">
                <div className="font-mono text-xs font-bold text-foreground">
                  Current Status: <span className="text-primary">{recommendation.status}</span>
                </div>
                {recommendation.reviewed_by && (
                  <div className="text-[11px] text-foreground-muted">
                    Reviewed by {recommendation.reviewed_by} {recommendation.reviewed_at ? `on ${new Date(recommendation.reviewed_at).toLocaleDateString()}` : ''}
                  </div>
                )}
              </div>
                <div className="flex items-center gap-2 shrink-0">
                  <button
                    type="button"
                    onClick={() => setShowPlaybookModal(true)}
                    className="px-3 py-1.5 rounded-lg border border-emerald-500/40 bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 font-mono font-bold text-xs transition-colors flex items-center gap-1.5 shrink-0"
                  >
                    <Play className="w-3.5 h-3.5" />
                    Launch Playbook
                  </button>
                  <button
                    type="button"
                    onClick={() => setReviewMode(true)}
                    className="px-3 py-1.5 rounded-lg bg-primary hover:bg-primary-hover text-primary-foreground font-mono font-semibold text-xs transition-colors shrink-0"
                  >
                    Change Disposition
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* Footer Warning */}
          <div className="p-3 border-t border-border bg-surface-secondary/60 text-[11px] font-mono text-foreground-muted flex items-center justify-between">
            <span>Deterministic Response Playbook · Section 29 Integration</span>
            <span className="text-primary font-bold">CyberGuard XAI</span>
          </div>
        </div>
      </div>

      {showPlaybookModal && (
        <PlaybookExecutionModal
          recommendation={recommendation}
          onClose={() => setShowPlaybookModal(false)}
        />
      )}
    </>
  );
};
