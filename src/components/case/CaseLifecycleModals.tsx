import React, { useState } from 'react';
import {
  User,
  CheckCircle2,
  Lock,
  RotateCcw,
  AlertTriangle,
  X,
  RefreshCw,
} from 'lucide-react';
import type {
  CaseDetail,
  CaseResolutionCode,
  CaseAssignPayload,
  CaseResolvePayload,
  CaseClosePayload,
  CaseReopenPayload,
} from '../../types/case';
import { caseService } from '../../services/caseService';

/* ── 1. Assign Modal ── */
interface AssignModalProps {
  isOpen: boolean;
  onClose: () => void;
  caseData: CaseDetail;
  onSuccess: () => void;
  showToast: (msg: string) => void;
}

export const AssignCaseModal: React.FC<AssignModalProps> = ({
  isOpen,
  onClose,
  caseData,
  onSuccess,
  showToast,
}) => {
  const [ownerId, setOwnerId] = useState(caseData.owner_id || '');
  const [teamId, setTeamId] = useState(caseData.team_id || '');
  const [reason, setReason] = useState('');
  const [submitting, setSubmitting] = useState(false);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    try {
      const payload: CaseAssignPayload = {
        owner_id: ownerId.trim() || undefined,
        team_id: teamId.trim() || undefined,
        reason: reason.trim() || undefined,
      };
      await caseService.assignCase(caseData.id, payload);
      showToast(`Case ownership updated to ${ownerId || 'Unassigned'}`);
      onSuccess();
      onClose();
    } catch (err: any) {
      alert(`Failed to assign case: ${err.message}`);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4">
      <div className="bg-surface border border-border rounded-xl shadow-xl w-full max-w-md overflow-hidden animate-in fade-in zoom-in-95 duration-150">
        <div className="flex items-center justify-between px-5 py-4 border-b border-border bg-surface-secondary/40">
          <div className="flex items-center space-x-2">
            <User className="w-4 h-4 text-primary" />
            <h3 className="font-mono text-sm font-bold text-foreground">Assign Case Responsibility</h3>
          </div>
          <button type="button" onClick={onClose} className="text-foreground-muted hover:text-foreground cursor-pointer">
            <X className="w-4 h-4" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-5 space-y-4">
          <div>
            <label className="block text-xs font-mono font-medium text-foreground mb-1">Owner / Analyst ID</label>
            <input
              type="text"
              placeholder="e.g. analyst.jane"
              value={ownerId}
              onChange={e => setOwnerId(e.target.value)}
              className="w-full px-3 py-2 bg-surface-secondary rounded-lg border border-border text-xs font-mono text-foreground focus:outline-none focus:border-primary"
            />
          </div>

          <div>
            <label className="block text-xs font-mono font-medium text-foreground mb-1">Operational Team</label>
            <input
              type="text"
              placeholder="e.g. tier2-soc, incident-response"
              value={teamId}
              onChange={e => setTeamId(e.target.value)}
              className="w-full px-3 py-2 bg-surface-secondary rounded-lg border border-border text-xs font-mono text-foreground focus:outline-none focus:border-primary"
            />
          </div>

          <div>
            <label className="block text-xs font-mono font-medium text-foreground mb-1">Handoff / Assignment Notes</label>
            <textarea
              rows={2}
              placeholder="Context or escalation handover instructions..."
              value={reason}
              onChange={e => setReason(e.target.value)}
              className="w-full px-3 py-2 bg-surface-secondary rounded-lg border border-border text-xs font-mono text-foreground focus:outline-none focus:border-primary"
            />
          </div>

          <div className="flex items-center justify-end space-x-2 pt-3 border-t border-border">
            <button
              type="button"
              onClick={onClose}
              className="px-3.5 py-1.5 rounded-lg border border-border text-xs font-mono text-foreground-muted hover:text-foreground cursor-pointer"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={submitting}
              className="flex items-center space-x-1.5 px-4 py-1.5 rounded-lg bg-primary hover:bg-primary-hover text-primary-foreground font-mono text-xs font-semibold disabled:opacity-50 cursor-pointer"
            >
              {submitting && <RefreshCw className="w-3.5 h-3.5 animate-spin" />}
              <span>Save Assignment</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

/* ── 2. Resolve Modal ── */
interface ResolveModalProps {
  isOpen: boolean;
  onClose: () => void;
  caseData: CaseDetail;
  onSuccess: () => void;
  showToast: (msg: string) => void;
}

export const ResolveCaseModal: React.FC<ResolveModalProps> = ({
  isOpen,
  onClose,
  caseData,
  onSuccess,
  showToast,
}) => {
  const [resolutionCode, setResolutionCode] = useState<CaseResolutionCode>('TRUE_POSITIVE');
  const [resolutionSummary, setResolutionSummary] = useState('');
  const [submitting, setSubmitting] = useState(false);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!resolutionSummary.trim()) return;

    setSubmitting(true);
    try {
      const payload: CaseResolvePayload = {
        resolution_code: resolutionCode,
        resolution_summary: resolutionSummary.trim(),
      };
      await caseService.resolveCase(caseData.id, payload);
      showToast(`Case marked as RESOLVED (${resolutionCode})`);
      onSuccess();
      onClose();
    } catch (err: any) {
      alert(`Failed to resolve case: ${err.message}`);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4">
      <div className="bg-surface border border-border rounded-xl shadow-xl w-full max-w-md overflow-hidden animate-in fade-in zoom-in-95 duration-150">
        <div className="flex items-center justify-between px-5 py-4 border-b border-border bg-surface-secondary/40">
          <div className="flex items-center space-x-2">
            <CheckCircle2 className="w-4 h-4 text-success" />
            <h3 className="font-mono text-sm font-bold text-foreground">Resolve Operational Case</h3>
          </div>
          <button type="button" onClick={onClose} className="text-foreground-muted hover:text-foreground cursor-pointer">
            <X className="w-4 h-4" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-5 space-y-4">
          <div>
            <label className="block text-xs font-mono font-medium text-foreground mb-1">Resolution Disposition Code *</label>
            <select
              value={resolutionCode}
              onChange={e => setResolutionCode(e.target.value as CaseResolutionCode)}
              className="w-full px-3 py-2 bg-surface-secondary rounded-lg border border-border text-xs font-mono text-foreground focus:outline-none focus:border-primary"
            >
              <option value="TRUE_POSITIVE">True Positive (Incident Verified)</option>
              <option value="FALSE_POSITIVE">False Positive (Benign Activity)</option>
              <option value="BENIGN_ACTIVITY">Benign Authorized Test / Drill</option>
              <option value="RESOLVED">Resolved / Remediation Verified</option>
              <option value="MITIGATED">Mitigated with Compensating Controls</option>
              <option value="NO_EVIDENCE">No Evidence of Compromise</option>
              <option value="DUPLICATE">Duplicate of Prior Incident</option>
              <option value="RISK_ACCEPTED">Risk Accepted by Asset Owner</option>
            </select>
          </div>

          <div>
            <label className="block text-xs font-mono font-medium text-foreground mb-1">
              Resolution Summary / Root Cause Sign-off *
            </label>
            <textarea
              rows={3}
              required
              placeholder="Detail root cause, containment actions performed, and remediation verification..."
              value={resolutionSummary}
              onChange={e => setResolutionSummary(e.target.value)}
              className="w-full px-3 py-2 bg-surface-secondary rounded-lg border border-border text-xs font-mono text-foreground focus:outline-none focus:border-primary"
            />
          </div>

          <div className="flex items-center justify-end space-x-2 pt-3 border-t border-border">
            <button
              type="button"
              onClick={onClose}
              className="px-3.5 py-1.5 rounded-lg border border-border text-xs font-mono text-foreground-muted hover:text-foreground cursor-pointer"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={submitting || !resolutionSummary.trim()}
              className="flex items-center space-x-1.5 px-4 py-1.5 rounded-lg bg-success hover:bg-success/90 text-success-foreground font-mono text-xs font-semibold disabled:opacity-50 cursor-pointer"
            >
              {submitting && <RefreshCw className="w-3.5 h-3.5 animate-spin" />}
              <span>Confirm Resolution</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

/* ── 3. Close Modal ── */
interface CloseModalProps {
  isOpen: boolean;
  onClose: () => void;
  caseData: CaseDetail;
  onSuccess: () => void;
  showToast: (msg: string) => void;
}

export const CloseCaseModal: React.FC<CloseModalProps> = ({
  isOpen,
  onClose,
  caseData,
  onSuccess,
  showToast,
}) => {
  const [closureNotes, setClosureNotes] = useState('');
  const [forceCloseTasks, setForceCloseTasks] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  if (!isOpen) return null;

  const openTasks = (caseData.tasks || []).filter(t => t.status !== 'COMPLETED' && t.status !== 'CANCELLED');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    try {
      const payload: CaseClosePayload = {
        closure_notes: closureNotes.trim() || 'Case closed after operational sign-off.',
        force_close_tasks: forceCloseTasks,
      };
      await caseService.closeCase(caseData.id, payload);
      showToast('Case finalized and moved to CLOSED state');
      onSuccess();
      onClose();
    } catch (err: any) {
      alert(`Failed to close case: ${err.message}`);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4">
      <div className="bg-surface border border-border rounded-xl shadow-xl w-full max-w-md overflow-hidden animate-in fade-in zoom-in-95 duration-150">
        <div className="flex items-center justify-between px-5 py-4 border-b border-border bg-surface-secondary/40">
          <div className="flex items-center space-x-2">
            <Lock className="w-4 h-4 text-foreground-muted" />
            <h3 className="font-mono text-sm font-bold text-foreground">Finalize & Close Case</h3>
          </div>
          <button type="button" onClick={onClose} className="text-foreground-muted hover:text-foreground cursor-pointer">
            <X className="w-4 h-4" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-5 space-y-4">
          {openTasks.length > 0 && (
            <div className="p-3 rounded-lg bg-warning-surface border border-warning-border text-xs font-mono space-y-2">
              <div className="flex items-center space-x-2 text-warning font-bold">
                <AlertTriangle className="w-4 h-4 shrink-0" />
                <span>Notice: {openTasks.length} Open Tasks Remaining</span>
              </div>
              <p className="text-foreground-muted text-[11px]">
                Cases normally require all checklist tasks to be finished before final closure.
              </p>
              <label className="flex items-center space-x-2 text-foreground font-medium cursor-pointer pt-1">
                <input
                  type="checkbox"
                  checked={forceCloseTasks}
                  onChange={e => setForceCloseTasks(e.target.checked)}
                  className="rounded border-border text-warning focus:ring-0"
                />
                <span className="text-[11px]">Force closure and cancel remaining open tasks</span>
              </label>
            </div>
          )}

          <div>
            <label className="block text-xs font-mono font-medium text-foreground mb-1">
              Closure Notes & Retrospective Sign-off
            </label>
            <textarea
              rows={3}
              placeholder="Final operational notes, customer communication status, lessons learned..."
              value={closureNotes}
              onChange={e => setClosureNotes(e.target.value)}
              className="w-full px-3 py-2 bg-surface-secondary rounded-lg border border-border text-xs font-mono text-foreground focus:outline-none focus:border-primary"
            />
          </div>

          <div className="flex items-center justify-end space-x-2 pt-3 border-t border-border">
            <button
              type="button"
              onClick={onClose}
              className="px-3.5 py-1.5 rounded-lg border border-border text-xs font-mono text-foreground-muted hover:text-foreground cursor-pointer"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={submitting || (openTasks.length > 0 && !forceCloseTasks)}
              className="flex items-center space-x-1.5 px-4 py-1.5 rounded-lg bg-surface-secondary hover:bg-surface border border-border text-foreground font-mono text-xs font-semibold disabled:opacity-50 cursor-pointer"
            >
              {submitting && <RefreshCw className="w-3.5 h-3.5 animate-spin" />}
              <span>Close Case</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

/* ── 4. Reopen Modal ── */
interface ReopenModalProps {
  isOpen: boolean;
  onClose: () => void;
  caseData: CaseDetail;
  onSuccess: () => void;
  showToast: (msg: string) => void;
}

export const ReopenCaseModal: React.FC<ReopenModalProps> = ({
  isOpen,
  onClose,
  caseData,
  onSuccess,
  showToast,
}) => {
  const [reopenReason, setReopenReason] = useState('');
  const [submitting, setSubmitting] = useState(false);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!reopenReason.trim()) return;

    setSubmitting(true);
    try {
      const payload: CaseReopenPayload = {
        reopen_reason: reopenReason.trim(),
      };
      await caseService.reopenCase(caseData.id, payload);
      showToast('Case successfully reopened into IN_PROGRESS');
      onSuccess();
      onClose();
    } catch (err: any) {
      alert(`Failed to reopen case: ${err.message}`);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4">
      <div className="bg-surface border border-border rounded-xl shadow-xl w-full max-w-md overflow-hidden animate-in fade-in zoom-in-95 duration-150">
        <div className="flex items-center justify-between px-5 py-4 border-b border-border bg-surface-secondary/40">
          <div className="flex items-center space-x-2">
            <RotateCcw className="w-4 h-4 text-warning" />
            <h3 className="font-mono text-sm font-bold text-foreground">Reopen Operational Case</h3>
          </div>
          <button type="button" onClick={onClose} className="text-foreground-muted hover:text-foreground cursor-pointer">
            <X className="w-4 h-4" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-5 space-y-4">
          <p className="text-xs font-mono text-foreground-muted">
            Reopening requires a mandatory justification reason. The case status will transition back to IN_PROGRESS.
          </p>

          <div>
            <label className="block text-xs font-mono font-medium text-foreground mb-1">
              Reopening Justification *
            </label>
            <textarea
              rows={3}
              required
              placeholder="e.g. New suspicious beacons observed matching prior IOCs or recurring phishing telemetry..."
              value={reopenReason}
              onChange={e => setReopenReason(e.target.value)}
              className="w-full px-3 py-2 bg-surface-secondary rounded-lg border border-border text-xs font-mono text-foreground focus:outline-none focus:border-primary"
            />
          </div>

          <div className="flex items-center justify-end space-x-2 pt-3 border-t border-border">
            <button
              type="button"
              onClick={onClose}
              className="px-3.5 py-1.5 rounded-lg border border-border text-xs font-mono text-foreground-muted hover:text-foreground cursor-pointer"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={submitting || !reopenReason.trim()}
              className="flex items-center space-x-1.5 px-4 py-1.5 rounded-lg bg-warning hover:bg-warning/90 text-warning-foreground font-mono text-xs font-semibold disabled:opacity-50 cursor-pointer"
            >
              {submitting && <RefreshCw className="w-3.5 h-3.5 animate-spin" />}
              <span>Confirm Reopen</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
