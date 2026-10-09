import React, { useState, useEffect, useRef } from 'react';
import {
  ShieldAlert,
  CheckCircle2,
  XCircle,
  Clock,
  AlertTriangle,
  RotateCcw,
  X,
  Target,
  FileText
} from 'lucide-react';
import type {
  ResponseRecommendationResponse,
  RecommendationReviewRequest,
  ReviewStatus
} from '../../../services/responseWorkspaceService';

interface ActionApprovalModalProps {
  isOpen: boolean;
  recommendation: ResponseRecommendationResponse | null;
  onClose: () => void;
  onSubmitReview: (req: RecommendationReviewRequest) => Promise<void>;
  analystId?: string;
}

export const ActionApprovalModal: React.FC<ActionApprovalModalProps> = ({
  isOpen,
  recommendation,
  onClose,
  onSubmitReview,
  analystId = 'analyst@cyberguard.local'
}) => {
  const [selectedStatus, setSelectedStatus] = useState<ReviewStatus>('APPROVED');
  const [reviewerNotes, setReviewerNotes] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const modalRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (isOpen) {
      setSelectedStatus('APPROVED');
      setReviewerNotes('');
      setError(null);
    }
  }, [isOpen, recommendation]);

  // Trap escape key
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isOpen && !isSubmitting) {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, isSubmitting, onClose]);

  if (!isOpen || !recommendation) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!reviewerNotes.trim()) {
      setError('A structured justification note is required for security review audit compliance.');
      return;
    }

    try {
      setIsSubmitting(true);
      setError(null);
      await onSubmitReview({
        recommendation_id: recommendation.id,
        status: selectedStatus,
        reviewer_id: analystId,
        reviewer_notes: reviewerNotes.trim()
      });
      onClose();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to submit review');
    } finally {
      setIsSubmitting(false);
    }
  };

  const isConsequential =
    recommendation.safety_class === 'CONTAINMENT' ||
    recommendation.safety_class === 'HIGH_IMPACT' ||
    recommendation.safety_class === 'DESTRUCTIVE';

  const targetIdentifier =
    recommendation.affected_entities?.[0]?.identifier ||
    (recommendation as any).target_entity ||
    'Target Scope';
  const isReversible =
    recommendation.reversibility === 'REVERSIBLE' || (recommendation as any).reversible === true;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm animate-in fade-in duration-150"
      role="dialog"
      aria-modal="true"
      aria-labelledby="approval-modal-title"
    >
      <div
        ref={modalRef}
        className="w-full max-w-xl bg-card border border-border rounded-xl shadow-2xl flex flex-col max-h-[90vh] overflow-hidden"
      >
        {/* Header */}
        <div className="flex items-center justify-between p-5 border-b border-border bg-card">
          <div className="flex items-center gap-3">
            <div
              className={`p-2 rounded-lg border ${
                selectedStatus === 'APPROVED'
                  ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                  : selectedStatus === 'REJECTED'
                  ? 'bg-rose-500/10 border-rose-500/30 text-rose-400'
                  : 'bg-amber-500/10 border-amber-500/30 text-amber-400'
              }`}
            >
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <h2 id="approval-modal-title" className="text-base font-bold text-foreground">
                Authoritative Response Action Review
              </h2>
              <p className="text-xs text-muted-foreground">
                Explicit analyst disposition for Recommendation #{recommendation.id}
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            disabled={isSubmitting}
            className="p-1.5 text-muted-foreground hover:text-foreground rounded-md hover:bg-muted/50 transition-colors"
            aria-label="Close modal"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <form onSubmit={handleSubmit} className="flex-1 overflow-y-auto p-5 space-y-5">
          {/* Action preview summary */}
          <div className="bg-muted/40 border border-border/80 rounded-lg p-4 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                Target Action
              </span>
              <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-primary/10 text-primary border border-primary/20">
                Priority: {recommendation.priority}
              </span>
            </div>

            <div className="text-sm font-bold text-foreground">{recommendation.title}</div>
            <p className="text-xs text-muted-foreground leading-relaxed">{recommendation.description}</p>

            <div className="grid grid-cols-2 gap-2 pt-2 border-t border-border/60 text-xs">
              <div className="flex items-center gap-1.5 text-foreground">
                <Target className="w-3.5 h-3.5 text-primary flex-shrink-0" />
                <span className="text-muted-foreground">Target:</span>
                <span className="font-mono truncate">{targetIdentifier}</span>
              </div>
              <div className="flex items-center gap-1.5 text-foreground">
                <RotateCcw className="w-3.5 h-3.5 text-muted-foreground flex-shrink-0" />
                <span className="text-muted-foreground">Reversibility:</span>
                <span className={isReversible ? 'text-emerald-400' : 'text-amber-400 font-semibold'}>
                  {isReversible ? 'Reversible' : 'Irreversible'}
                </span>
              </div>
            </div>
          </div>

          {/* Consequential warning if applicable */}
          {isConsequential && (
            <div className="p-3.5 rounded-lg border border-amber-500/30 bg-amber-500/10 flex items-start gap-3">
              <AlertTriangle className="w-5 h-5 text-amber-400 flex-shrink-0 mt-0.5" />
              <div className="text-xs space-y-1">
                <div className="font-semibold text-amber-300">Consequential Containment Boundary</div>
                <div className="text-amber-200/80 leading-relaxed">
                  This action is classified as <strong>{recommendation.safety_class}</strong>.
                  CyberGuard has recommended this action based on structured risk signals, but no execution
                  will occur until explicitly initiated through playbooks or authorized adapters.
                </div>
              </div>
            </div>
          )}


          {/* Disposition Selector */}
          <div className="space-y-2">
            <label className="text-xs font-bold text-foreground uppercase tracking-wider block">
              Analyst Disposition
            </label>
            <div className="grid grid-cols-3 gap-2">
              <button
                type="button"
                onClick={() => setSelectedStatus('APPROVED')}
                className={`p-3 rounded-lg border text-left flex flex-col gap-1 transition-all ${
                  selectedStatus === 'APPROVED'
                    ? 'border-emerald-500 bg-emerald-500/15 text-emerald-300 shadow-sm'
                    : 'border-border bg-card/60 hover:bg-muted/50 text-muted-foreground'
                }`}
              >
                <div className="flex items-center gap-1.5 font-bold text-xs">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  Approve
                </div>
                <span className="text-[10px] text-muted-foreground leading-tight">
                  Authorize action for playbook inclusion/execution
                </span>
              </button>

              <button
                type="button"
                onClick={() => setSelectedStatus('REJECTED')}
                className={`p-3 rounded-lg border text-left flex flex-col gap-1 transition-all ${
                  selectedStatus === 'REJECTED'
                    ? 'border-rose-500 bg-rose-500/15 text-rose-300 shadow-sm'
                    : 'border-border bg-card/60 hover:bg-muted/50 text-muted-foreground'
                }`}
              >
                <div className="flex items-center gap-1.5 font-bold text-xs">
                  <XCircle className="w-4 h-4 text-rose-400" />
                  Reject
                </div>
                <span className="text-[10px] text-muted-foreground leading-tight">
                  Decline action as inappropriate or false-positive
                </span>
              </button>

              <button
                type="button"
                onClick={() => setSelectedStatus('DEFERRED')}
                className={`p-3 rounded-lg border text-left flex flex-col gap-1 transition-all ${
                  selectedStatus === 'DEFERRED'
                    ? 'border-amber-500 bg-amber-500/15 text-amber-300 shadow-sm'
                    : 'border-border bg-card/60 hover:bg-muted/50 text-muted-foreground'
                }`}
              >
                <div className="flex items-center gap-1.5 font-bold text-xs">
                  <Clock className="w-4 h-4 text-amber-400" />
                  Defer
                </div>
                <span className="text-[10px] text-muted-foreground leading-tight">
                  Postpone decision pending further forensic telemetry
                </span>
              </button>
            </div>
          </div>

          {/* Reviewer justification */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <label htmlFor="reviewer-notes" className="text-xs font-bold text-foreground uppercase tracking-wider flex items-center gap-1.5">
                <FileText className="w-3.5 h-3.5 text-primary" />
                Review Justification (Mandatory Audit Requirement)
              </label>
              <span className="text-[10px] text-muted-foreground">Actor: {analystId}</span>
            </div>
            <textarea
              id="reviewer-notes"
              rows={3}
              value={reviewerNotes}
              onChange={(e) => setReviewerNotes(e.target.value)}
              placeholder={`Provide forensic rationale for ${selectedStatus.toLowerCase()}ing this defensive recommendation...`}
              className="w-full text-xs bg-background border border-border rounded-lg p-3 text-foreground placeholder:text-muted-foreground/60 focus:outline-none focus:ring-1 focus:ring-primary focus:border-primary resize-none font-sans"
              required
            />
          </div>

          {error && (
            <div className="p-3 rounded-lg border border-rose-500/30 bg-rose-500/10 text-rose-300 text-xs flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 flex-shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {/* Footer buttons */}
          <div className="pt-3 border-t border-border flex items-center justify-end gap-3">
            <button
              type="button"
              onClick={onClose}
              disabled={isSubmitting}
              className="px-4 py-2 text-xs font-medium text-foreground hover:bg-muted/60 border border-border rounded-lg transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isSubmitting || !reviewerNotes.trim()}
              className={`px-4 py-2 text-xs font-bold rounded-lg border transition-all flex items-center gap-2 shadow-sm ${
                selectedStatus === 'APPROVED'
                  ? 'bg-emerald-600 hover:bg-emerald-500 border-emerald-500 text-white'
                  : selectedStatus === 'REJECTED'
                  ? 'bg-rose-600 hover:bg-rose-500 border-rose-500 text-white'
                  : 'bg-amber-600 hover:bg-amber-500 border-amber-500 text-white'
              } disabled:opacity-50 disabled:cursor-not-allowed`}
            >
              {isSubmitting ? (
                <span>Recording Audit...</span>
              ) : (
                <span>
                  Confirm {selectedStatus === 'APPROVED' ? 'Approval' : selectedStatus === 'REJECTED' ? 'Rejection' : 'Deferral'}
                </span>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
