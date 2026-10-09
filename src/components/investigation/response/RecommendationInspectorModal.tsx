import React, { useState, useEffect } from 'react';
import {
  X,
  ShieldAlert,
  AlertTriangle,
  FileText,
  GitBranch,
  Layers,
  Shield,
  RotateCcw,
} from 'lucide-react';
import type { ResponseRecommendation } from '../../../types/response_recommendation';
import { Badge, Button } from '../../ui';


interface RecommendationInspectorModalProps {
  recommendation: ResponseRecommendation | null;
  isOpen: boolean;
  onClose: () => void;
  onApprove: (rec: ResponseRecommendation, notes: string) => Promise<void>;
  onReject: (rec: ResponseRecommendation, notes: string) => Promise<void>;
  onDefer: (rec: ResponseRecommendation, notes: string) => Promise<void>;
  onNavigateToEvidence?: (evidenceId: string) => void;
  onNavigateToAttackPath?: () => void;
}

export const RecommendationInspectorModal: React.FC<RecommendationInspectorModalProps> = ({
  recommendation,
  isOpen,
  onClose,
  onApprove,
  onReject,
  onDefer,
  onNavigateToEvidence,
  onNavigateToAttackPath,
}) => {
  const [reviewDisposition, setReviewDisposition] = useState<'APPROVE' | 'REJECT' | 'DEFER'>('APPROVE');
  const [justificationNotes, setJustificationNotes] = useState<string>('');
  const [submitting, setSubmitting] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    if (isOpen) {
      window.addEventListener('keydown', handleKeyDown);
      setJustificationNotes('');
      setErrorMessage(null);
    }
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen || !recommendation) return null;

  const handleSubmitDecision = async () => {
    if (!justificationNotes.trim()) {
      setErrorMessage('Analyst justification note is mandatory for immutable response audit trail.');
      return;
    }

    setSubmitting(true);
    setErrorMessage(null);
    try {
      if (reviewDisposition === 'APPROVE') {
        await onApprove(recommendation, justificationNotes);
      } else if (reviewDisposition === 'REJECT') {
        await onReject(recommendation, justificationNotes);
      } else {
        await onDefer(recommendation, justificationNotes);
      }
      onClose();
    } catch (err: any) {
      setErrorMessage(err?.message || 'Failed to record decision');
    } finally {
      setSubmitting(false);
    }
  };

  const isPending = recommendation.status === 'REVIEW_REQUIRED' || recommendation.status === 'GENERATED';

  return (
    <div
      className="fixed inset-0 z-50 overflow-y-auto bg-black/60 backdrop-blur-xs flex items-center justify-center p-4 animate-in fade-in duration-150"
      role="dialog"
      aria-modal="true"
      aria-labelledby="rec-inspector-title"
    >
      <div className="bg-surface border border-border rounded-xl shadow-2xl w-full max-w-3xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="p-4 sm:p-5 border-b border-border bg-surface-secondary/40 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-lg bg-primary/10 border border-primary/20 text-primary">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-danger/10 text-danger border border-danger/20">
                  {recommendation.priority}
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-surface border border-border text-foreground-muted">
                  {recommendation.category.replace(/_/g, ' ')}
                </span>
                <Badge variant={recommendation.status === 'APPROVED' ? 'success' : 'outline'} size="sm" className="font-mono text-[10px]">
                  {recommendation.status}
                </Badge>
              </div>
              <h2 id="rec-inspector-title" className="text-sm font-semibold text-foreground font-sans mt-1">
                {recommendation.title}
              </h2>
            </div>
          </div>

          <button
            type="button"
            onClick={onClose}
            className="p-1.5 rounded-lg text-foreground-muted hover:text-foreground hover:bg-surface-secondary transition-colors"
            aria-label="Close inspector modal"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Content Body */}
        <div className="p-5 sm:p-6 overflow-y-auto space-y-5 text-xs font-sans">
          {/* Description & Expected Effect */}
          <div className="space-y-2">
            <p className="text-foreground leading-relaxed">
              {recommendation.description}
            </p>
            <div className="p-3 rounded-lg bg-surface-secondary/60 border border-border/80">
              <span className="text-[10px] font-mono uppercase tracking-wider text-primary font-bold block mb-1">
                Expected Effect & Intended Outcome
              </span>
              <p className="text-foreground leading-relaxed">
                {recommendation.expected_effect}
              </p>
            </div>
          </div>

          {/* Rationale / "Why this recommendation exists" */}
          <div className="p-3.5 rounded-lg bg-surface-secondary/40 border border-border space-y-1.5">
            <span className="text-[10px] font-mono uppercase tracking-wider text-foreground-muted font-bold block">
              Why CyberGuard Recommends This Action
            </span>
            <p className="text-foreground leading-relaxed">
              {recommendation.rationale}
            </p>
          </div>

          {/* Grounded Evidence Chain */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-mono font-bold uppercase tracking-wider text-foreground flex items-center space-x-1.5">
                <FileText className="w-3.5 h-3.5 text-primary" />
                <span>Evidence Grounding & Provenance Chain</span>
              </span>
              {onNavigateToAttackPath && (
                <button
                  type="button"
                  onClick={onNavigateToAttackPath}
                  className="text-[11px] font-mono text-primary hover:text-primary-hover inline-flex items-center space-x-1 font-semibold"
                >
                  <GitBranch className="w-3 h-3" />
                  <span>View in Attack Path</span>
                </button>
              )}
            </div>

            <div className="p-3 rounded-lg bg-surface-secondary/30 border border-border font-mono text-[11px] space-y-2">
              <div className="flex items-center space-x-2 text-foreground-muted">
                <span className="text-primary font-bold">Trace:</span>
                <span>Recommendation</span>
                <span>→</span>
                <span>Risk Assessment #{recommendation.risk_assessment_id || 'ACTIVE'}</span>
                <span>→</span>
                <span>Evidence Items ({recommendation.evidence_refs?.length || 0})</span>
              </div>

              {recommendation.evidence_refs && recommendation.evidence_refs.length > 0 ? (
                <div className="flex flex-wrap gap-1.5 pt-1">
                  {recommendation.evidence_refs.map((ref) => (
                    <button
                      key={ref}
                      type="button"
                      onClick={() => onNavigateToEvidence && onNavigateToEvidence(ref)}
                      className="px-2 py-1 rounded bg-surface border border-border text-foreground hover:border-primary transition-colors flex items-center space-x-1 cursor-pointer"
                    >
                      <FileText className="w-3 h-3 text-primary" />
                      <span>{ref}</span>
                    </button>
                  ))}
                </div>
              ) : (
                <p className="text-foreground-muted italic text-[11px]">
                  Anchored to overall investigation evidence and telemetry scope.
                </p>
              )}
            </div>
          </div>

          {/* MITRE Mapping */}
          {recommendation.mitre_refs && recommendation.mitre_refs.length > 0 && (
            <div className="space-y-1.5">
              <span className="text-[10px] font-mono uppercase tracking-wider text-foreground-muted font-bold block">
                Related MITRE ATT&CK Techniques
              </span>
              <div className="flex flex-wrap gap-1.5">
                {recommendation.mitre_refs.map((tid) => (
                  <Badge key={tid} variant="outline" size="sm" className="font-mono text-[10px]">
                    {tid}
                  </Badge>
                ))}
              </div>
            </div>
          )}

          {/* Prerequisites Checklist */}
          {recommendation.prerequisites && recommendation.prerequisites.length > 0 && (
            <div className="space-y-2">
              <span className="text-[11px] font-mono font-bold uppercase tracking-wider text-foreground flex items-center space-x-1.5">
                <Layers className="w-3.5 h-3.5 text-primary" />
                <span>Execution Prerequisites & Pre-Conditions</span>
              </span>
              <div className="space-y-1.5">
                {recommendation.prerequisites.map((p, idx) => (
                  <div
                    key={idx}
                    className="p-2.5 rounded-lg bg-surface border border-border/80 flex items-start justify-between gap-2"
                  >
                    <div className="space-y-0.5">
                      <span className="font-semibold text-foreground font-mono text-[11px] block">
                        {p.name}
                      </span>
                      <p className="text-foreground-muted text-[11px]">{p.description}</p>
                    </div>
                    <span
                      className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold shrink-0 ${
                        p.satisfied
                          ? 'bg-success/10 text-success border border-success/20'
                          : 'bg-warning/10 text-warning border border-warning/20'
                      }`}
                    >
                      {p.satisfied ? 'Satisfied' : 'Pending'}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Impact & Reversibility */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-1">
            <div className="p-3 rounded-lg bg-surface border border-border space-y-1">
              <span className="text-[10px] font-mono uppercase tracking-wider text-foreground-muted block">
                Reversibility & Rollback
              </span>
              <div className="flex items-center space-x-1.5 font-mono text-xs font-semibold text-foreground">
                <RotateCcw className="w-3.5 h-3.5 text-primary" />
                <span>{recommendation.reversibility === 'REVERSIBLE' ? 'Reversible with Rollback' : 'Irreversible Change'}</span>
              </div>
              <p className="text-foreground-muted text-[11px]">
                {recommendation.reversibility === 'REVERSIBLE'
                  ? 'Compensating actions are tracked in audit history to reverse changes if misclassified.'
                  : 'Action permanently modifies state. Elevated analyst authorization required.'}
              </p>
            </div>

            <div className="p-3 rounded-lg bg-surface border border-border space-y-1">
              <span className="text-[10px] font-mono uppercase tracking-wider text-foreground-muted block">
                Operational Impact & Safety Class
              </span>
              <div className="flex items-center space-x-1.5 font-mono text-xs font-semibold text-foreground">
                <Shield className="w-3.5 h-3.5 text-warning" />
                <span>Impact: {recommendation.impact} ({recommendation.safety_class})</span>
              </div>
              <p className="text-foreground-muted text-[11px]">
                Targeted network or identity interruption scoped strictly to affected indicators.
              </p>
            </div>
          </div>

          {/* Analyst Disposition & Justification Panel */}
          {isPending && (
            <div className="p-4 rounded-xl bg-surface-secondary/70 border border-border-strong space-y-3 pt-4">
              <span className="text-xs font-mono font-bold uppercase tracking-wider text-foreground block">
                Record Analyst Authorization Disposition
              </span>

              <div className="flex items-center space-x-2">
                <button
                  type="button"
                  onClick={() => setReviewDisposition('APPROVE')}
                  className={`px-3 py-1.5 rounded-lg font-mono text-xs font-semibold border transition-all cursor-pointer ${
                    reviewDisposition === 'APPROVE'
                      ? 'bg-success/15 border-success text-success shadow-xs'
                      : 'bg-surface border-border text-foreground-muted hover:text-foreground'
                  }`}
                >
                  ✓ Approve Action
                </button>
                <button
                  type="button"
                  onClick={() => setReviewDisposition('REJECT')}
                  className={`px-3 py-1.5 rounded-lg font-mono text-xs font-semibold border transition-all cursor-pointer ${
                    reviewDisposition === 'REJECT'
                      ? 'bg-danger/15 border-danger text-danger shadow-xs'
                      : 'bg-surface border-border text-foreground-muted hover:text-foreground'
                  }`}
                >
                  ✗ Reject Action
                </button>
                <button
                  type="button"
                  onClick={() => setReviewDisposition('DEFER')}
                  className={`px-3 py-1.5 rounded-lg font-mono text-xs font-semibold border transition-all cursor-pointer ${
                    reviewDisposition === 'DEFER'
                      ? 'bg-warning/15 border-warning text-warning shadow-xs'
                      : 'bg-surface border-border text-foreground-muted hover:text-foreground'
                  }`}
                >
                  ⏱ Defer Action
                </button>
              </div>

              <div>
                <label className="text-[11px] font-mono text-foreground-muted block mb-1">
                  Analyst Justification & Audit Log Note <span className="text-danger">*</span>
                </label>
                <textarea
                  value={justificationNotes}
                  onChange={(e) => setJustificationNotes(e.target.value)}
                  placeholder="Document reason for approval, rejection, or deferral (required for Section 41 compliance)..."
                  rows={2}
                  className="w-full text-xs font-sans p-2.5 rounded-lg bg-surface border border-border text-foreground placeholder:text-foreground-muted focus:outline-hidden focus:ring-1 focus:ring-primary"
                />
              </div>

              {errorMessage && (
                <p className="text-xs font-mono text-danger flex items-center space-x-1.5">
                  <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                  <span>{errorMessage}</span>
                </p>
              )}

              <div className="flex justify-end pt-1">
                <Button
                  variant="primary"
                  size="sm"
                  onClick={handleSubmitDecision}
                  disabled={submitting}
                  className="font-mono text-xs font-semibold"
                >
                  {submitting ? 'Recording Audit...' : `Confirm ${reviewDisposition}`}
                </Button>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-border bg-surface-secondary/40 flex items-center justify-between">
          <span className="text-[11px] font-mono text-foreground-muted">
            Recommendation ID: <span className="text-foreground">{recommendation.id}</span>
          </span>
          <Button variant="secondary" size="sm" onClick={onClose} className="font-mono text-xs">
            Close Inspector
          </Button>
        </div>
      </div>
    </div>
  );
};
