import React, { useState, useEffect, useCallback } from 'react';
import {
  Clock,
  AlertTriangle,
  CheckCircle2,
  Pause,
  Play,
  ShieldAlert,
  ArrowUpRight,
  ChevronDown,
  ChevronUp,
  Info,
  History,
  RefreshCw,
  Check,
  X,
  AlertCircle,
} from 'lucide-react';
import { SlaClientService } from '../../services/slaService';
import type {
  IncidentSLADetailResponse,
  SLAMilestoneDetail,
  IncidentStatus,
} from '../../types';

interface IncidentSLABannerProps {
  incidentId: string;
  incidentStatus: IncidentStatus;
  assignedTo?: string | null;
  onUpdated?: () => void;
  onOpenWorkflowHistory?: () => void;
}

export const IncidentSLABanner: React.FC<IncidentSLABannerProps> = ({
  incidentId,
  incidentStatus: _incidentStatus,
  assignedTo: _assignedTo,
  onUpdated,
  onOpenWorkflowHistory,
}) => {
  const [slaDetail, setSlaDetail] = useState<IncidentSLADetailResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [actionLoading, setActionLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<boolean>(false);

  // Action Modals State
  const [showPauseModal, setShowPauseModal] = useState<boolean>(false);
  const [pauseReason, setPauseReason] = useState<string>('AWAITING_EXTERNAL_TELEMETRY');
  const [pauseCustomReason, setPauseCustomReason] = useState<string>('');

  const [showExemptModal, setShowExemptModal] = useState<boolean>(false);
  const [exemptReason, setExemptReason] = useState<string>('');

  const [showEscalateModal, setShowEscalateModal] = useState<boolean>(false);
  const [escalateReason, setEscalateReason] = useState<string>('');

  const loadSlaData = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await SlaClientService.getIncidentSLA(incidentId);
      setSlaDetail(res);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to fetch SLA telemetry');
    } finally {
      setLoading(false);
    }
  }, [incidentId]);

  useEffect(() => {
    loadSlaData();
  }, [loadSlaData]);

  const handlePause = async () => {
    const finalReason = pauseCustomReason.trim()
      ? `${pauseReason}: ${pauseCustomReason.trim()}`
      : pauseReason;
    try {
      setActionLoading(true);
      await SlaClientService.pauseIncidentSLA(incidentId, { reason: finalReason });
      setShowPauseModal(false);
      setPauseCustomReason('');
      await loadSlaData();
      onUpdated?.();
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'Failed to pause SLA clock');
    } finally {
      setActionLoading(false);
    }
  };

  const handleResume = async () => {
    try {
      setActionLoading(true);
      await SlaClientService.resumeIncidentSLA(incidentId);
      await loadSlaData();
      onUpdated?.();
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'Failed to resume SLA clock');
    } finally {
      setActionLoading(false);
    }
  };

  const handleExempt = async () => {
    if (!exemptReason.trim()) {
      alert('A forensic justification reason is mandatory for SLA exemption.');
      return;
    }
    try {
      setActionLoading(true);
      await SlaClientService.exemptIncidentSLA(incidentId, { reason: exemptReason.trim() });
      setShowExemptModal(false);
      setExemptReason('');
      await loadSlaData();
      onUpdated?.();
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'Failed to exempt SLA');
    } finally {
      setActionLoading(false);
    }
  };

  const handleEscalate = async () => {
    try {
      setActionLoading(true);
      await SlaClientService.escalateIncident(incidentId, {
        reason: escalateReason.trim() || 'Manual analyst escalation',
      });
      setShowEscalateModal(false);
      setEscalateReason('');
      await loadSlaData();
      onUpdated?.();
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'Failed to escalate incident');
    } finally {
      setActionLoading(false);
    }
  };

  const handleReevaluate = async () => {
    try {
      setActionLoading(true);
      await SlaClientService.evaluateIncidentSLA(incidentId);
      await loadSlaData();
      onUpdated?.();
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'Failed to evaluate SLA');
    } finally {
      setActionLoading(false);
    }
  };

  const formatDuration = (mins: number | null | undefined): string => {
    if (mins == null) return '—';
    if (mins < 60) return `${mins}m`;
    const h = Math.floor(mins / 60);
    const m = mins % 60;
    return m > 0 ? `${h}h ${m}m` : `${h}h`;
  };

  if (loading && !slaDetail) {
    return (
      <div className="p-3 bg-surface border border-border rounded-control flex items-center justify-between text-xs text-foreground-muted animate-pulse">
        <div className="flex items-center space-x-2">
          <Clock className="w-3.5 h-3.5 text-primary" />
          <span>Synchronizing server-side SLA clocks & operational policies...</span>
        </div>
        <RefreshCw className="w-3.5 h-3.5 animate-spin text-primary" />
      </div>
    );
  }

  if (error || !slaDetail) {
    return (
      <div className="p-3 bg-surface border border-border rounded-control flex items-center justify-between text-xs text-foreground-muted">
        <div className="flex items-center space-x-2 text-warning">
          <AlertCircle className="w-3.5 h-3.5 shrink-0" />
          <span>SLA Tracking: Policy unattached or evaluating</span>
        </div>
        <button
          type="button"
          onClick={loadSlaData}
          className="text-primary hover:underline flex items-center space-x-1 cursor-pointer"
        >
          <RefreshCw className="w-3 h-3" />
          <span>Retry</span>
        </button>
      </div>
    );
  }

  const { overall_sla_status, milestones, policy, escalation, is_paused, is_exempt } = slaDetail;

  const getStatusBadge = () => {
    if (is_exempt) {
      return {
        label: 'EXEMPT',
        className: 'bg-surface-secondary text-foreground-muted border-border font-mono',
        icon: ShieldAlert,
      };
    }
    if (is_paused) {
      return {
        label: 'PAUSED',
        className: 'bg-amber-500/15 text-amber-400 border-amber-500/30 font-mono font-bold',
        icon: Pause,
      };
    }
    switch (overall_sla_status) {
      case 'BREACHED':
        return {
          label: 'SLA BREACHED',
          className: 'bg-red-500/20 text-red-400 border-red-500/40 font-mono font-bold animate-pulse',
          icon: AlertTriangle,
        };
      case 'WARNING':
        return {
          label: 'APPROACHING SLA',
          className: 'bg-amber-500/20 text-amber-400 border-amber-500/40 font-mono font-bold',
          icon: Clock,
        };
      case 'MET':
        return {
          label: 'SLA MET',
          className: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30 font-mono',
          icon: CheckCircle2,
        };
      case 'ON_TRACK':
      default:
        return {
          label: 'ON TRACK',
          className: 'bg-blue-500/15 text-blue-400 border-blue-500/30 font-mono',
          icon: Clock,
        };
    }
  };

  const statusBadge = getStatusBadge();
  const StatusIcon = statusBadge.icon;

  const renderMilestoneCompact = (m: SLAMilestoneDetail) => {
    let icon = <Clock className="w-3 h-3 text-foreground-muted" />;
    let text = `${m.remaining_minutes != null ? formatDuration(m.remaining_minutes) : '—'} left`;
    let colorClass = 'text-foreground';

    if (m.status === 'MET') {
      icon = <CheckCircle2 className="w-3 h-3 text-emerald-400" />;
      text = `Met (${formatDuration(m.elapsed_minutes)})`;
      colorClass = 'text-emerald-400';
    } else if (m.status === 'BREACHED') {
      icon = <AlertTriangle className="w-3 h-3 text-red-400" />;
      text = `BREACHED (+${formatDuration(m.overdue_minutes || 0)})`;
      colorClass = 'text-red-400 font-bold';
    } else if (m.status === 'WARNING') {
      icon = <Clock className="w-3 h-3 text-amber-400" />;
      text = `⚠ ${formatDuration(m.remaining_minutes)} left`;
      colorClass = 'text-amber-400 font-semibold';
    } else if (m.status === 'PAUSED') {
      icon = <Pause className="w-3 h-3 text-amber-400" />;
      text = `Paused (${formatDuration(m.remaining_minutes)} left)`;
      colorClass = 'text-amber-300';
    } else if (m.status === 'EXEMPT') {
      icon = <Check className="w-3 h-3 text-foreground-muted" />;
      text = 'Exempt';
      colorClass = 'text-foreground-muted';
    }

    return (
      <div key={m.milestone} className="flex items-center space-x-1.5 text-xs">
        <span className="text-[11px] font-mono uppercase text-foreground-muted">
          {m.milestone.slice(0, 3)}:
        </span>
        {icon}
        <span className={`font-mono text-xs ${colorClass}`}>{text}</span>
      </div>
    );
  };

  return (
    <div className="bg-surface border border-border rounded-control overflow-hidden shadow-xs">
      {/* 1. Compact Header Strip */}
      <div className="p-3.5 flex flex-wrap items-center justify-between gap-3 border-b border-border/60 bg-surface-secondary/30">
        <div className="flex flex-wrap items-center gap-3">
          {/* Status Badge */}
          <div
            className={`px-2.5 py-1 rounded-control border text-xs flex items-center space-x-1.5 ${statusBadge.className}`}
          >
            <StatusIcon className="w-3.5 h-3.5" />
            <span>{statusBadge.label}</span>
          </div>

          {/* Escalation Level Badge */}
          <div className="px-2 py-0.5 rounded-xs border border-border bg-surface text-foreground font-mono text-xs flex items-center space-x-1">
            <span className="text-foreground-muted">Tier:</span>
            <span className="font-bold text-primary">L{escalation.current_level}</span>
            <span className="text-foreground-muted truncate max-w-[120px]">
              ({escalation.current_level_name})
            </span>
          </div>

          {/* Milestones in Compact View */}
          <div className="hidden sm:flex items-center space-x-4 pl-2 border-l border-border/60">
            {renderMilestoneCompact(milestones.acknowledgement)}
            {renderMilestoneCompact(milestones.containment)}
            {renderMilestoneCompact(milestones.resolution)}
          </div>
        </div>

        {/* Action Controls & Expander */}
        <div className="flex items-center space-x-2">
          {/* Pause / Resume Controls */}
          {!is_exempt && (
            <>
              {is_paused ? (
                <button
                  type="button"
                  onClick={handleResume}
                  disabled={actionLoading}
                  className="px-2.5 py-1 text-xs font-semibold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 hover:bg-emerald-500/25 rounded-control flex items-center space-x-1 cursor-pointer"
                  title="Resume SLA operational clocks"
                >
                  <Play className="w-3 h-3" />
                  <span>Resume Clocks</span>
                </button>
              ) : (
                <button
                  type="button"
                  onClick={() => setShowPauseModal(true)}
                  disabled={actionLoading}
                  className="px-2.5 py-1 text-xs font-medium bg-surface text-foreground-muted hover:text-foreground border border-border hover:bg-surface-secondary rounded-control flex items-center space-x-1 cursor-pointer"
                  title="Pause SLA clock with justified reason"
                >
                  <Pause className="w-3 h-3" />
                  <span>Pause SLA</span>
                </button>
              )}
            </>
          )}

          {/* Escalate Button */}
          <button
            type="button"
            onClick={() => setShowEscalateModal(true)}
            disabled={actionLoading}
            className="px-2.5 py-1 text-xs font-medium bg-rose-500/10 text-rose-400 border border-rose-500/25 hover:bg-rose-500/20 rounded-control flex items-center space-x-1 cursor-pointer"
            title="Escalate incident to next tier"
          >
            <ArrowUpRight className="w-3 h-3" />
            <span>Escalate</span>
          </button>

          {/* Workflow History Trigger */}
          {onOpenWorkflowHistory && (
            <button
              type="button"
              onClick={onOpenWorkflowHistory}
              className="p-1.5 text-foreground-muted hover:text-foreground hover:bg-surface-secondary rounded-control border border-border cursor-pointer"
              title="View full workflow execution audit trail"
            >
              <History className="w-3.5 h-3.5" />
            </button>
          )}

          {/* Reevaluate Trigger */}
          <button
            type="button"
            onClick={handleReevaluate}
            disabled={actionLoading}
            className="p-1.5 text-foreground-muted hover:text-foreground hover:bg-surface-secondary rounded-control border border-border cursor-pointer"
            title="Recalculate SLA clocks server-side"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${actionLoading ? 'animate-spin text-primary' : ''}`} />
          </button>

          {/* Expand Toggle */}
          <button
            type="button"
            onClick={() => setExpanded(!expanded)}
            className="px-2 py-1 text-xs text-foreground-muted hover:text-foreground hover:bg-surface-secondary rounded-control border border-border flex items-center space-x-1 cursor-pointer"
          >
            <span>{expanded ? 'Less' : 'Details'}</span>
            {expanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
          </button>
        </div>
      </div>

      {/* 2. Expanded Progressive Disclosure Grid */}
      {expanded && (
        <div className="p-4 bg-surface space-y-4 text-xs">
          {/* Policy & Authority Meta */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 p-3 bg-surface-secondary/40 rounded-control border border-border">
            <div>
              <span className="text-[10px] font-mono uppercase text-foreground-muted block">
                Active SLA Policy
              </span>
              <span className="font-semibold text-foreground">{policy.name}</span>
              <span className="text-[10px] text-foreground-muted font-mono block mt-0.5">
                Version {policy.version} · {policy.severity} / {policy.priority}
              </span>
            </div>
            <div>
              <span className="text-[10px] font-mono uppercase text-foreground-muted block">
                Escalation Hierarchy
              </span>
              <span className="font-semibold text-foreground">
                Tier {escalation.current_level} of {escalation.max_level}: {escalation.current_level_name}
              </span>
              <span className="text-[10px] text-foreground-muted font-mono block mt-0.5">
                Target: {escalation.current_target_name || 'SOC Operations Team'}
              </span>
            </div>
            <div>
              <span className="text-[10px] font-mono uppercase text-foreground-muted block">
                Clock Adjustment
              </span>
              <span className="font-semibold text-foreground">
                {slaDetail.total_paused_minutes > 0
                  ? `${slaDetail.total_paused_minutes}m accumulated pause`
                  : 'Zero accumulated pause'}
              </span>
              {is_exempt && (
                <span className="text-[10px] text-amber-400 font-mono block mt-0.5">
                  Reason: {slaDetail.exemption_reason || 'Administrative exclusion'}
                </span>
              )}
            </div>
          </div>

          {/* Milestones Matrix */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
            {[milestones.acknowledgement, milestones.investigation, milestones.containment, milestones.resolution].map(
              (m) => {
                const isOverdue = m.status === 'BREACHED';
                const isWarn = m.status === 'WARNING';
                const isMet = m.status === 'MET';

                return (
                  <div
                    key={m.milestone}
                    className={`p-3 rounded-control border ${
                      isOverdue
                        ? 'bg-red-500/10 border-red-500/30'
                        : isWarn
                        ? 'bg-amber-500/10 border-amber-500/30'
                        : isMet
                        ? 'bg-emerald-500/10 border-emerald-500/30'
                        : 'bg-surface border-border'
                    } flex flex-col justify-between space-y-2`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-[11px] font-bold uppercase text-foreground">
                        {m.milestone}
                      </span>
                      <span
                        className={`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded border ${
                          isOverdue
                            ? 'bg-red-500/20 text-red-400 border-red-500/40'
                            : isWarn
                            ? 'bg-amber-500/20 text-amber-400 border-amber-500/40'
                            : isMet
                            ? 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40'
                            : 'bg-surface-secondary text-foreground-muted border-border'
                        }`}
                      >
                        {m.status}
                      </span>
                    </div>

                    <div className="space-y-1 font-mono text-[11px]">
                      <div className="flex justify-between text-foreground-muted">
                        <span>Target:</span>
                        <span className="text-foreground font-semibold">
                          {formatDuration(m.target_minutes)}
                        </span>
                      </div>
                      <div className="flex justify-between text-foreground-muted">
                        <span>Elapsed:</span>
                        <span className="text-foreground">
                          {formatDuration(m.elapsed_minutes)}
                        </span>
                      </div>
                      {m.remaining_minutes != null && (
                        <div className="flex justify-between text-foreground-muted">
                          <span>Remaining:</span>
                          <span
                            className={
                              isOverdue
                                ? 'text-red-400 font-bold'
                                : isWarn
                                ? 'text-amber-400 font-bold'
                                : 'text-foreground'
                            }
                          >
                            {isOverdue
                              ? `-${formatDuration(m.overdue_minutes || 0)} (Overdue)`
                              : formatDuration(m.remaining_minutes)}
                          </span>
                        </div>
                      )}
                      {m.deadline && (
                        <div className="flex justify-between text-[10px] text-foreground-muted pt-1 border-t border-border/40">
                          <span>Deadline:</span>
                          <span>{new Date(m.deadline).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                        </div>
                      )}
                    </div>
                  </div>
                );
              }
            )}
          </div>

          {/* Administrative Exemption Control */}
          <div className="flex items-center justify-between pt-2 border-t border-border/50 text-[11px] text-foreground-muted">
            <span className="flex items-center space-x-1">
              <Info className="w-3.5 h-3.5 text-primary" />
              <span>
                SLA clocks dynamically account for approved forensic pause periods. Authoritative server timestamps govern breach transitions.
              </span>
            </span>

            {!is_exempt && (
              <button
                type="button"
                onClick={() => setShowExemptModal(true)}
                className="text-foreground-muted hover:text-danger hover:underline cursor-pointer"
              >
                Mark Incident SLA Exempt
              </button>
            )}
          </div>
        </div>
      )}

      {/* =========================================================================
          MODALS
          ========================================================================= */}

      {/* Pause Modal */}
      {showPauseModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4 animate-in fade-in">
          <div className="bg-surface border border-border rounded-control p-5 w-full max-w-md space-y-4 shadow-xl">
            <div className="flex items-center justify-between border-b border-border pb-3">
              <div className="flex items-center space-x-2 text-warning font-semibold text-sm">
                <Pause className="w-4 h-4" />
                <span>Pause Incident SLA Clock</span>
              </div>
              <button
                type="button"
                onClick={() => setShowPauseModal(false)}
                className="text-foreground-muted hover:text-foreground cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <p className="text-xs text-foreground-muted">
              Pausing stops the elapsed SLA duration from incrementing while awaiting critical external dependencies or customer feedback. Every pause action is immutably audited.
            </p>

            <div className="space-y-3">
              <div>
                <label className="text-xs font-semibold text-foreground block mb-1">
                  Reason Category
                </label>
                <select
                  value={pauseReason}
                  onChange={(e) => setPauseReason(e.target.value)}
                  className="w-full text-xs bg-surface-secondary border border-border rounded-control px-2.5 py-1.5 text-foreground"
                >
                  <option value="AWAITING_CUSTOMER_FEEDBACK">Awaiting Customer Feedback</option>
                  <option value="AWAITING_EXTERNAL_TELEMETRY">Awaiting External Telemetry / Vendor</option>
                  <option value="APPROVED_MAINTENANCE_WINDOW">Approved Maintenance Window</option>
                  <option value="LEGAL_FORENSIC_HOLD">Legal Forensic Hold</option>
                  <option value="THIRD_PARTY_ESCALATION">Third-Party Incident Escalation</option>
                </select>
              </div>

              <div>
                <label className="text-xs font-semibold text-foreground block mb-1">
                  Specific Justification Note
                </label>
                <textarea
                  value={pauseCustomReason}
                  onChange={(e) => setPauseCustomReason(e.target.value)}
                  placeholder="Ticket reference or reason for pausing operational clock..."
                  className="w-full text-xs bg-surface-secondary border border-border rounded-control p-2 text-foreground h-20"
                />
              </div>
            </div>

            <div className="flex items-center justify-end space-x-2 pt-2 border-t border-border">
              <button
                type="button"
                onClick={() => setShowPauseModal(false)}
                className="px-3 py-1.5 text-xs text-foreground bg-surface border border-border rounded-control hover:bg-surface-secondary cursor-pointer"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handlePause}
                disabled={actionLoading}
                className="px-3 py-1.5 text-xs font-semibold text-white bg-warning hover:bg-warning/90 rounded-control cursor-pointer"
              >
                {actionLoading ? 'Pausing...' : 'Confirm Pause'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Escalate Modal */}
      {showEscalateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4 animate-in fade-in">
          <div className="bg-surface border border-border rounded-control p-5 w-full max-w-md space-y-4 shadow-xl">
            <div className="flex items-center justify-between border-b border-border pb-3">
              <div className="flex items-center space-x-2 text-rose-400 font-semibold text-sm">
                <ArrowUpRight className="w-4 h-4" />
                <span>Manual Operational Escalation</span>
              </div>
              <button
                type="button"
                onClick={() => setShowEscalateModal(false)}
                className="text-foreground-muted hover:text-foreground cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-3 bg-surface-secondary rounded-control border border-border text-xs space-y-1">
              <div className="flex justify-between">
                <span className="text-foreground-muted">Current Tier:</span>
                <span className="font-bold text-foreground">
                  L{escalation.current_level} ({escalation.current_level_name})
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-foreground-muted">Target Next Tier:</span>
                <span className="font-bold text-rose-400">
                  L{Math.min(escalation.current_level + 1, escalation.max_level)}
                </span>
              </div>
            </div>

            <div>
              <label className="text-xs font-semibold text-foreground block mb-1">
                Escalation Rationale
              </label>
              <textarea
                value={escalateReason}
                onChange={(e) => setEscalateReason(e.target.value)}
                placeholder="Reason for manual escalation to SOC lead / management..."
                className="w-full text-xs bg-surface-secondary border border-border rounded-control p-2 text-foreground h-20"
              />
            </div>

            <div className="flex items-center justify-end space-x-2 pt-2 border-t border-border">
              <button
                type="button"
                onClick={() => setShowEscalateModal(false)}
                className="px-3 py-1.5 text-xs text-foreground bg-surface border border-border rounded-control hover:bg-surface-secondary cursor-pointer"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleEscalate}
                disabled={actionLoading}
                className="px-3 py-1.5 text-xs font-semibold text-white bg-rose-500 hover:bg-rose-600 rounded-control cursor-pointer"
              >
                {actionLoading ? 'Escalating...' : 'Confirm Escalation'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Exempt Modal */}
      {showExemptModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4 animate-in fade-in">
          <div className="bg-surface border border-border rounded-control p-5 w-full max-w-md space-y-4 shadow-xl">
            <div className="flex items-center justify-between border-b border-border pb-3">
              <div className="flex items-center space-x-2 text-danger font-semibold text-sm">
                <ShieldAlert className="w-4 h-4" />
                <span>Exempt Incident from SLA</span>
              </div>
              <button
                type="button"
                onClick={() => setShowExemptModal(false)}
                className="text-foreground-muted hover:text-foreground cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <p className="text-xs text-foreground-muted">
              Exempting an incident permanently removes active SLA clock evaluations and breach notifications for this incident. This requires explicit justification and is logged in the permanent audit trail.
            </p>

            <div>
              <label className="text-xs font-semibold text-foreground block mb-1">
                Forensic Justification (Mandatory)
              </label>
              <textarea
                value={exemptReason}
                onChange={(e) => setExemptReason(e.target.value)}
                placeholder="Authorizing manager / justification for forensic SLA exemption..."
                className="w-full text-xs bg-surface-secondary border border-border rounded-control p-2 text-foreground h-20"
              />
            </div>

            <div className="flex items-center justify-end space-x-2 pt-2 border-t border-border">
              <button
                type="button"
                onClick={() => setShowExemptModal(false)}
                className="px-3 py-1.5 text-xs text-foreground bg-surface border border-border rounded-control hover:bg-surface-secondary cursor-pointer"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleExempt}
                disabled={actionLoading}
                className="px-3 py-1.5 text-xs font-semibold text-white bg-danger hover:bg-danger-hover rounded-control cursor-pointer"
              >
                {actionLoading ? 'Exempting...' : 'Confirm Exemption'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
