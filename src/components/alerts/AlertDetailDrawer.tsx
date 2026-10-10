import React, { useState, useEffect, useCallback, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ShieldAlert,
  ExternalLink,
  X,
  User,
  FileCode,
  Layers,
  ArrowRight,
  HelpCircle,
  Send,
  Loader2,
  RefreshCw,
  GitBranch,
} from 'lucide-react';
import { cn } from '../../utils/cn';
import { AlertService } from '../../services/alertService';
import { AlertClusterService } from '../../services/alertClusterService';
import { IncidentService } from '../../services/incidentService';
import type { AlertDetail, AlertItem, AlertSeverity, AlertStatus } from '../../types/alert';
import type { AlertClusterDetail } from '../../types/alertCluster';
import { AlertClusterDetailModal } from './AlertClusterDetailModal';
import { useRealtimeSubscription } from '../../hooks/useRealtimeSubscription';
import type { RealtimeEvent } from '../../types/realtime';

interface AlertDetailDrawerProps {
  alertId: string | null;
  isOpen: boolean;
  onClose: () => void;
  onAlertUpdated?: (updated: AlertItem) => void;
}

export const AlertDetailDrawer: React.FC<AlertDetailDrawerProps> = ({
  alertId,
  isOpen,
  onClose,
  onAlertUpdated,
}) => {
  const navigate = useNavigate();
  const drawerRef = useRef<HTMLDivElement>(null);

  const [detail, setDetail] = useState<AlertDetail | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [actionLoading, setActionLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  // Modal / Input states
  const [activeModal, setActiveModal] = useState<
    'NONE' | 'RESOLVE' | 'FALSE_POSITIVE' | 'SUPPRESS' | 'ASSIGN'
  >('NONE');
  const [modalInput, setModalInput] = useState<string>('');
  const [modalSecondaryInput, setModalSecondaryInput] = useState<string>('THIS_ALERT');
  const [modalError, setModalError] = useState<string | null>(null);

  // Triage Note input state
  const [noteInput, setNoteInput] = useState<string>('');
  const [noteSubmitting, setNoteSubmitting] = useState<boolean>(false);

  // Section 49: Alert Correlation & Incident Clustering state
  const [cluster, setCluster] = useState<AlertClusterDetail | null>(null);
  const [clusterLoading, setClusterLoading] = useState<boolean>(false);
  const [correlating, setCorrelating] = useState<boolean>(false);
  const [selectedClusterId, setSelectedClusterId] = useState<string | null>(null);

  // Load alert details & cluster association
  const loadDetail = useCallback(async () => {
    if (!alertId) return;
    setLoading(true);
    setError(null);
    try {
      const data = await AlertService.getAlertDetail(alertId);
      setDetail(data);
    } catch (err: unknown) {
      console.error('Failed to load alert detail:', err);
      setError(err instanceof Error ? err.message : 'Failed to load alert detail');
    } finally {
      setLoading(false);
    }

    // Load Section 49 alert cluster association
    setClusterLoading(true);
    try {
      const clu = await AlertClusterService.getAlertCluster(alertId);
      setCluster(clu);
    } catch (err: unknown) {
      console.warn('Failed to check alert cluster association:', err);
    } finally {
      setClusterLoading(false);
    }
  }, [alertId]);

  const handleRunCorrelation = async () => {
    if (!alertId) return;
    setCorrelating(true);
    try {
      await AlertClusterService.triggerAlertCorrelation(alertId);
      await loadDetail();
    } catch (err: unknown) {
      console.error('Failed to trigger correlation:', err);
    } finally {
      setCorrelating(false);
    }
  };

  useEffect(() => {
    if (isOpen && alertId) {
      loadDetail();
    } else {
      setDetail(null);
      setCluster(null);
      setError(null);
      setActiveModal('NONE');
      setModalInput('');
      setSelectedClusterId(null);
    }
  }, [isOpen, alertId, loadDetail]);

  // Section 46 real-time update handler: refresh if current alert updated
  useRealtimeSubscription({
    url: isOpen && alertId ? `/api/events/stream` : null,
    onEvent: (event: RealtimeEvent) => {
      const isTargetAlert =
        event.resource_id === alertId ||
        (event.payload && (event.payload as Record<string, unknown>).id === alertId);
      if (
        isTargetAlert &&
        alertId &&
        [
          'ALERT_STATUS_CHANGED',
          'ALERT_ASSIGNED',
          'ALERT_RESOLVED',
          'ALERT_NOTE_ADDED',
          'ALERT_SUPPRESSED',
        ].includes(event.event_type)
      ) {
        // Silently reload detail without wiping dirty inputs
        const targetId = alertId;
        AlertService.getAlertDetail(targetId)
          .then((updated) => {
            setDetail(updated);
            if (onAlertUpdated) onAlertUpdated(updated);
          })
          .catch((e) => console.warn('Background alert refresh error:', e));
      }
    },
  });

  // Action handlers
  const handleAcknowledge = async () => {
    if (!detail) return;
    setActionLoading(true);
    try {
      const updated = await AlertService.acknowledgeAlert(detail.id, {
        analyst_name: 'SOC Analyst',
        note: 'Alert acknowledged during triage inspection.',
      });
      setDetail((prev) => (prev ? { ...prev, ...updated } : null));
      if (onAlertUpdated) onAlertUpdated(updated);
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'Failed to acknowledge alert');
    } finally {
      setActionLoading(false);
    }
  };

  const handleInvestigate = async () => {
    if (!detail) return;
    setActionLoading(true);
    try {
      const updated = await AlertService.investigateAlert(detail.id, 'SOC Analyst');
      setDetail((prev) => (prev ? { ...prev, ...updated } : null));
      if (onAlertUpdated) onAlertUpdated(updated);
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'Failed to start investigation');
    } finally {
      setActionLoading(false);
    }
  };

  const handlePromoteToIncident = async () => {
    if (!detail) return;
    setActionLoading(true);
    try {
      const inc = await IncidentService.promoteAlert({
        alert_id: detail.id,
        title: `Incident: ${detail.title}`,
      });
      navigate(`/incidents/${inc.id}`);
      onClose();
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'Failed to promote alert to incident');
    } finally {
      setActionLoading(false);
    }
  };

  const handleConfirmModal = async () => {
    if (!detail) return;
    if (!modalInput.trim()) {
      setModalError('Please enter a required justification or assignee.');
      return;
    }
    setActionLoading(true);
    setModalError(null);
    try {
      let updated: AlertItem | null = null;
      if (activeModal === 'RESOLVE') {
        updated = await AlertService.resolveAlert(detail.id, {
          resolution_reason: modalInput.trim(),
          analyst_name: 'SOC Analyst',
        });
      } else if (activeModal === 'FALSE_POSITIVE') {
        updated = await AlertService.markFalsePositive(detail.id, {
          reason: modalInput.trim(),
          analyst_name: 'SOC Analyst',
        });
      } else if (activeModal === 'SUPPRESS') {
        updated = await AlertService.suppressAlert(detail.id, {
          reason: modalInput.trim(),
          scope: modalSecondaryInput,
          analyst_name: 'SOC Analyst',
        });
      } else if (activeModal === 'ASSIGN') {
        updated = await AlertService.assignAlert(detail.id, {
          assigned_to: modalInput.trim(),
          analyst_name: 'SOC Analyst',
        });
      }

      if (updated) {
        setDetail((prev) => (prev ? { ...prev, ...updated } : null));
        if (onAlertUpdated) onAlertUpdated(updated);
      }
      setActiveModal('NONE');
      setModalInput('');
    } catch (err: unknown) {
      setModalError(err instanceof Error ? err.message : 'Action failed');
    } finally {
      setActionLoading(false);
    }
  };

  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!detail || !noteInput.trim()) return;
    setNoteSubmitting(true);
    try {
      const updatedDetail = await AlertService.addNote(detail.id, {
        note: noteInput.trim(),
        analyst_name: 'SOC Analyst',
      });
      setDetail(updatedDetail);
      setNoteInput('');
      if (onAlertUpdated) onAlertUpdated(updatedDetail);
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'Failed to add triage note');
    } finally {
      setNoteSubmitting(false);
    }
  };

  const getSeverityBadgeClass = (sev: AlertSeverity) => {
    switch (sev) {
      case 'CRITICAL':
        return 'bg-threat-critical/20 text-threat-critical border-threat-critical/40';
      case 'HIGH':
        return 'bg-threat-high/20 text-threat-high border-threat-high/40';
      case 'MEDIUM':
        return 'bg-threat-medium/20 text-threat-medium border-threat-medium/40';
      case 'LOW':
        return 'bg-threat-low/20 text-threat-low border-threat-low/40';
      default:
        return 'bg-surface-secondary text-foreground-muted border-border';
    }
  };

  const getStatusBadgeClass = (status: AlertStatus) => {
    switch (status) {
      case 'OPEN':
        return 'bg-threat-critical/15 text-threat-critical border-threat-critical/30';
      case 'ACKNOWLEDGED':
        return 'bg-threat-high/15 text-threat-high border-threat-high/30';
      case 'INVESTIGATING':
        return 'bg-primary/15 text-primary border-primary/30';
      case 'RESOLVED':
        return 'bg-threat-low/15 text-threat-low border-threat-low/30';
      case 'FALSE_POSITIVE':
        return 'bg-surface-secondary text-foreground-muted border-border';
      case 'SUPPRESSED':
        return 'bg-surface-secondary text-foreground-muted border-border line-through';
      default:
        return 'bg-surface-secondary text-foreground-muted border-border';
    }
  };

  if (!isOpen) return null;

  return (
    <div
      className="fixed inset-0 z-50 overflow-hidden bg-black/60 backdrop-blur-xs flex justify-end animate-in fade-in duration-200"
      onClick={onClose}
    >
      <div
        ref={drawerRef}
        role="dialog"
        aria-modal="true"
        onClick={(e) => e.stopPropagation()}
        className="w-full max-w-2xl bg-surface-elevated border-l border-border shadow-2xl flex flex-col h-full animate-in slide-in-from-right duration-300"
      >
        {/* Drawer Header */}
        <div className="px-6 py-4 border-b border-border flex items-center justify-between bg-surface/50 shrink-0">
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-md bg-threat-critical/10 border border-threat-critical/30 text-threat-critical">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="text-xs font-mono font-bold text-foreground">
                  Security Alert Triage
                </span>
                {detail && (
                  <span className="text-[11px] font-mono text-foreground-muted">
                    #{detail.id.slice(0, 8)}
                  </span>
                )}
              </div>
              <p className="text-[11px] font-mono text-foreground-muted">
                Authoritative signal with forensic provenance & explainability
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-2">
            <button
              type="button"
              onClick={loadDetail}
              disabled={loading}
              className="p-1.5 rounded-md text-foreground-muted hover:text-foreground hover:bg-surface-secondary cursor-pointer transition-colors"
              title="Refresh Alert Detail"
            >
              <RefreshCw className={cn('w-4 h-4', loading && 'animate-spin')} />
            </button>
            <button
              type="button"
              onClick={onClose}
              className="p-1.5 rounded-md text-foreground-muted hover:text-foreground hover:bg-surface-secondary cursor-pointer transition-colors"
              title="Close Drawer (Esc)"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Drawer Body */}
        <div className="flex-1 overflow-y-auto px-6 py-5 space-y-6">
          {loading && !detail ? (
            <div className="py-24 flex flex-col items-center justify-center space-y-3">
              <Loader2 className="w-7 h-7 text-primary animate-spin" />
              <p className="text-xs font-mono text-foreground-muted">
                Loading authoritative alert provenance...
              </p>
            </div>
          ) : error ? (
            <div className="p-4 rounded-lg bg-threat-critical/10 border border-threat-critical/30 text-threat-critical text-xs font-mono space-y-2">
              <p className="font-bold">Failed to load alert details</p>
              <p>{error}</p>
              <button
                type="button"
                onClick={loadDetail}
                className="px-3 py-1 bg-surface border border-threat-critical/40 rounded text-xs hover:bg-surface-secondary cursor-pointer"
              >
                Retry
              </button>
            </div>
          ) : detail ? (
            <>
              {/* Alert Title & Key Attributes */}
              <div className="space-y-3">
                <div className="flex flex-wrap items-center gap-2">
                  <span
                    className={cn(
                      'px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase tracking-wider border',
                      getSeverityBadgeClass(detail.severity)
                    )}
                  >
                    {detail.severity}
                  </span>
                  <span
                    className={cn(
                      'px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase tracking-wider border',
                      getStatusBadgeClass(detail.status)
                    )}
                  >
                    {detail.status}
                  </span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-surface-secondary text-foreground-muted border border-border">
                    {detail.alert_type}
                  </span>
                  {detail.assigned_to && (
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-primary/10 text-primary border border-primary/25 flex items-center space-x-1">
                      <User className="w-3 h-3" />
                      <span>{detail.assigned_to}</span>
                    </span>
                  )}
                </div>

                <h2 className="text-base font-bold text-foreground font-mono leading-tight">
                  {detail.title}
                </h2>
                <p className="text-xs text-foreground-muted font-mono leading-relaxed">
                  {detail.message}
                </p>

                {/* Risk & Confidence Badges */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-1">
                  <div className="p-2.5 rounded-md bg-surface border border-border space-y-0.5">
                    <span className="text-[10px] font-mono uppercase text-foreground-muted">
                      Risk Score
                    </span>
                    <p className="text-sm font-bold font-mono text-threat-critical">
                      {detail.risk_score.toFixed(1)} / 100
                    </p>
                  </div>
                  <div className="p-2.5 rounded-md bg-surface border border-border space-y-0.5">
                    <span className="text-[10px] font-mono uppercase text-foreground-muted">
                      Confidence
                    </span>
                    <p className="text-sm font-bold font-mono text-foreground">
                      {Math.round(detail.confidence * 100)}%
                    </p>
                  </div>
                  <div className="p-2.5 rounded-md bg-surface border border-border space-y-0.5">
                    <span className="text-[10px] font-mono uppercase text-foreground-muted">
                      Created
                    </span>
                    <p className="text-xs font-mono text-foreground truncate" title={detail.created_at}>
                      {new Date(detail.created_at).toLocaleTimeString([], {
                        hour: '2-digit',
                        minute: '2-digit',
                      })}
                    </p>
                  </div>
                  <div className="p-2.5 rounded-md bg-surface border border-border space-y-0.5">
                    <span className="text-[10px] font-mono uppercase text-foreground-muted">
                      Last Updated
                    </span>
                    <p className="text-xs font-mono text-foreground truncate" title={detail.updated_at}>
                      {new Date(detail.updated_at).toLocaleTimeString([], {
                        hour: '2-digit',
                        minute: '2-digit',
                      })}
                    </p>
                  </div>
                </div>
              </div>

              {/* SECTION 27: WHY THIS ALERT EXISTS (Explainable AI) */}
              <div className="p-4 rounded-lg bg-surface border border-border space-y-2.5">
                <div className="flex items-center space-x-2 text-foreground font-mono text-xs font-bold">
                  <HelpCircle className="w-3.5 h-3.5 text-primary" />
                  <span>Why This Alert Exists (Explainability)</span>
                </div>
                <ul className="space-y-1.5 pl-2">
                  {detail.why_created.map((item, idx) => (
                    <li
                      key={idx}
                      className="text-xs font-mono text-foreground-muted flex items-start space-x-2"
                    >
                      <span className="text-primary font-bold mt-0.5">•</span>
                      <span>{item}</span>
                    </li>
                  ))}
                </ul>
              </div>

              {/* PROVENANCE RELATIONSHIPS: Finding, Analysis Run, Investigation */}
              <div className="space-y-3">
                <h3 className="text-xs font-mono font-bold text-foreground uppercase tracking-wider">
                  Authoritative Provenance
                </h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {/* Finding Origin */}
                  {detail.finding_detail && (
                    <div className="p-3 rounded-lg bg-surface border border-border space-y-2">
                      <div className="flex items-center justify-between text-xs font-mono">
                        <span className="text-foreground-muted font-bold flex items-center space-x-1.5">
                          <FileCode className="w-3.5 h-3.5 text-threat-high" />
                          <span>Originating Finding</span>
                        </span>
                        <span className="text-[10px] text-foreground-subtle">
                          {detail.finding_detail.analyzer}
                        </span>
                      </div>
                      <p className="text-xs font-mono text-foreground font-semibold">
                        {detail.finding_detail.title}
                      </p>
                      <div className="text-[11px] font-mono text-foreground-muted space-y-0.5">
                        <p>Method: {detail.finding_detail.method}</p>
                        {detail.finding_detail.rule_id && (
                          <p>Rule: {detail.finding_detail.rule_id}</p>
                        )}
                        <p>Finding ID: {detail.finding_detail.id.slice(0, 13)}...</p>
                      </div>
                    </div>
                  )}

                  {/* Analysis Run */}
                  {detail.analysis_run_detail && (
                    <div className="p-3 rounded-lg bg-surface border border-border space-y-2">
                      <div className="flex items-center justify-between text-xs font-mono">
                        <span className="text-foreground-muted font-bold flex items-center space-x-1.5">
                          <Layers className="w-3.5 h-3.5 text-primary" />
                          <span>Analysis Run</span>
                        </span>
                        <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-threat-low/20 text-threat-low">
                          {detail.analysis_run_detail.status}
                        </span>
                      </div>
                      <p className="text-xs font-mono text-foreground font-semibold truncate">
                        {detail.analysis_run_detail.artifact_name || 'Artifact Inspection'}
                      </p>
                      <div className="text-[11px] font-mono text-foreground-muted space-y-0.5">
                        <p>Run ID: {detail.analysis_run_detail.id.slice(0, 13)}...</p>
                        {detail.analysis_run_detail.artifact_sha256 && (
                          <p className="truncate">
                            SHA256: {detail.analysis_run_detail.artifact_sha256.slice(0, 16)}...
                          </p>
                        )}
                      </div>
                    </div>
                  )}
                </div>

                {/* Investigation Deep Link */}
                <div className="p-3.5 rounded-lg bg-primary/5 border border-primary/20 flex items-center justify-between">
                  <div className="space-y-0.5">
                    <span className="text-[10px] font-mono uppercase text-foreground-muted">
                      Associated Investigation
                    </span>
                    <p className="text-xs font-mono font-bold text-foreground">
                      {detail.investigation_detail
                        ? `${detail.investigation_detail.incident_number} — ${detail.investigation_detail.title}`
                        : detail.investigation_id
                        ? `Investigation ${detail.investigation_id}`
                        : 'No investigation attached'}
                    </p>
                  </div>
                  {detail.investigation_id ? (
                    <button
                      type="button"
                      onClick={() => {
                        navigate(`/investigations/${detail.investigation_id}`);
                        onClose();
                      }}
                      className="px-3 py-1.5 bg-primary text-primary-foreground rounded-md text-xs font-mono font-bold flex items-center space-x-1.5 hover:bg-primary-hover transition-colors cursor-pointer"
                    >
                      <span>Open Workspace</span>
                      <ExternalLink className="w-3 h-3" />
                    </button>
                  ) : (
                    <button
                      type="button"
                      onClick={handleInvestigate}
                      disabled={actionLoading}
                      className="px-3 py-1.5 bg-surface border border-border hover:border-primary/50 text-foreground rounded-md text-xs font-mono font-bold flex items-center space-x-1.5 cursor-pointer transition-colors"
                    >
                      <span>Mark Investigating</span>
                    </button>
                  )}
                </div>
              </div>

              {/* SECTION 49: RELATED ACTIVITY & ALERT CLUSTER */}
              <div className="p-4 rounded-lg bg-surface border border-border space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <div className="p-1 rounded bg-primary/10 text-primary">
                      <GitBranch className="w-3.5 h-3.5" />
                    </div>
                    <span className="text-xs font-mono font-bold text-foreground uppercase tracking-wider">
                      Related Activity & Correlation
                    </span>
                  </div>
                  {cluster && (
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-primary/10 text-primary border border-primary/20 font-bold">
                      {Math.round(cluster.confidence * 100)}% Correlated
                    </span>
                  )}
                </div>

                {clusterLoading ? (
                  <div className="py-4 flex items-center justify-center space-x-2 text-xs font-mono text-foreground-muted">
                    <Loader2 className="w-4 h-4 animate-spin text-primary" />
                    <span>Evaluating correlation signals...</span>
                  </div>
                ) : cluster ? (
                  <div className="space-y-3">
                    <div className="flex items-start justify-between">
                      <div>
                        <div className="flex items-center space-x-2">
                          <span className="text-xs font-mono font-bold text-foreground">
                            {cluster.title}
                          </span>
                          <span className="text-[10px] font-mono text-foreground-muted">
                            ({cluster.cluster_number})
                          </span>
                        </div>
                        <p className="text-[11px] font-mono text-foreground-muted mt-0.5">
                          {cluster.alert_count} related alert{cluster.alert_count > 1 ? 's' : ''} • First seen {new Date(cluster.first_seen).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })} • Last seen {new Date(cluster.last_seen).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                        </p>
                      </div>
                      <button
                        type="button"
                        onClick={() => setSelectedClusterId(cluster.id)}
                        className="text-xs font-mono text-primary hover:underline flex items-center space-x-1 cursor-pointer"
                      >
                        <span>Cluster Context</span>
                        <ArrowRight className="w-3 h-3" />
                      </button>
                    </div>

                    {/* Sibling Alerts */}
                    <div className="space-y-1 divide-y divide-border/60 border border-border/60 rounded-md overflow-hidden bg-surface-secondary/20">
                      {cluster.members.map((mem) => {
                        const isCurrent = mem.alert_id === detail.id;
                        const signalsText = mem.signals.map(s => s.type.replace(/_/g, ' ').toLowerCase()).slice(0, 3).join(' · ');
                        return (
                          <div
                            key={mem.id}
                            className={cn(
                              "p-2.5 flex items-center justify-between text-xs font-mono transition-colors",
                              isCurrent ? "bg-primary/5 border-l-2 border-primary" : "hover:bg-surface-secondary/50 cursor-pointer"
                            )}
                            onClick={() => {
                              if (!isCurrent) {
                                onAlertUpdated?.({ id: mem.alert_id } as any);
                              }
                            }}
                          >
                            <div className="space-y-0.5 pr-2">
                              <div className="flex items-center space-x-2">
                                <span className={cn(
                                  "w-1.5 h-1.5 rounded-full",
                                  mem.alert_summary?.severity === 'CRITICAL' ? 'bg-threat-critical' :
                                  mem.alert_summary?.severity === 'HIGH' ? 'bg-threat-high' :
                                  mem.alert_summary?.severity === 'MEDIUM' ? 'bg-threat-medium' : 'bg-primary'
                                )} />
                                <span className={cn("font-semibold", isCurrent ? "text-primary" : "text-foreground")}>
                                  {mem.alert_summary?.title || `Alert #${mem.alert_id.slice(0, 8)}`}
                                </span>
                                {isCurrent && (
                                  <span className="text-[10px] text-primary bg-primary/10 px-1 rounded">Current</span>
                                )}
                              </div>
                              {signalsText && (
                                <p className="text-[10px] text-foreground-muted pl-3.5">
                                  {signalsText}
                                </p>
                              )}
                            </div>
                            <span className={cn(
                              "px-1.5 py-0.5 rounded text-[10px] font-bold uppercase",
                              getSeverityBadgeClass((mem.alert_summary?.severity as AlertSeverity) || 'HIGH')
                            )}>
                              {mem.alert_summary?.severity || 'HIGH'}
                            </span>
                          </div>
                        );
                      })}
                    </div>

                    <div className="pt-1 flex items-center justify-between">
                      <button
                        type="button"
                        onClick={() => setSelectedClusterId(cluster.id)}
                        className="px-2.5 py-1 text-xs font-mono bg-surface-secondary hover:bg-surface-secondary/80 border border-border rounded text-foreground cursor-pointer flex items-center space-x-1"
                      >
                        <Layers className="w-3 h-3 text-primary" />
                        <span>View All Cluster Evidence</span>
                      </button>

                      {cluster.investigation_id ? (
                        <button
                          type="button"
                          onClick={() => {
                            navigate(`/investigations/${cluster.investigation_id}`);
                            onClose();
                          }}
                          className="px-2.5 py-1 text-xs font-mono bg-primary text-primary-foreground font-bold rounded hover:bg-primary-hover cursor-pointer flex items-center space-x-1"
                        >
                          <span>Open Investigation</span>
                          <ExternalLink className="w-3 h-3" />
                        </button>
                      ) : (
                        <button
                          type="button"
                          onClick={async () => {
                            const res = await AlertClusterService.linkInvestigation(cluster.id, { create_if_missing: true });
                            if (res.investigation_id) {
                              navigate(`/investigations/${res.investigation_id}`);
                              onClose();
                            }
                          }}
                          className="px-2.5 py-1 text-xs font-mono bg-primary text-primary-foreground font-bold rounded hover:bg-primary-hover cursor-pointer flex items-center space-x-1"
                        >
                          <span>Escalate Cluster</span>
                          <ArrowRight className="w-3 h-3" />
                        </button>
                      )}
                    </div>
                  </div>
                ) : (
                  <div className="py-2 flex items-center justify-between text-xs font-mono text-foreground-muted">
                    <span>This alert is currently not associated with another alert cluster.</span>
                    <button
                      type="button"
                      onClick={handleRunCorrelation}
                      disabled={correlating}
                      className="px-2.5 py-1 bg-surface-secondary hover:bg-surface-secondary/80 border border-border rounded text-foreground text-xs font-mono cursor-pointer flex items-center space-x-1"
                    >
                      {correlating ? <Loader2 className="w-3 h-3 animate-spin" /> : <GitBranch className="w-3 h-3 text-primary" />}
                      <span>Run Correlation</span>
                    </button>
                  </div>
                )}
              </div>

              {/* EVIDENCE ITEMS */}
              {detail.evidence_items && detail.evidence_items.length > 0 && (
                <div className="space-y-2">
                  <h3 className="text-xs font-mono font-bold text-foreground uppercase tracking-wider">
                    Machine Evidence ({detail.evidence_items.length})
                  </h3>
                  <div className="divide-y divide-border border border-border rounded-lg overflow-hidden bg-surface">
                    {detail.evidence_items.map((ev) => (
                      <div key={ev.id} className="p-3 space-y-1">
                        <div className="flex items-center justify-between text-xs font-mono">
                          <span className="text-primary font-bold">{ev.evidence_type}</span>
                          <span className="text-foreground-muted text-[10px]">{ev.source}</span>
                        </div>
                        <p className="text-xs font-mono text-foreground break-all bg-surface-secondary/50 p-1.5 rounded">
                          {ev.indicator_value}
                        </p>
                        <p className="text-[11px] font-mono text-foreground-muted">
                          {ev.description}
                        </p>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* RESOLUTION / SUPPRESSION JUSTIFICATION DETAILS */}
              {detail.resolution_reason && (
                <div className="p-3 rounded-lg bg-threat-low/10 border border-threat-low/30 space-y-1">
                  <span className="text-[10px] font-mono font-bold uppercase text-threat-low">
                    Resolution Justification ({detail.resolved_by || 'SOC Analyst'})
                  </span>
                  <p className="text-xs font-mono text-foreground">{detail.resolution_reason}</p>
                </div>
              )}

              {detail.false_positive_reason && (
                <div className="p-3 rounded-lg bg-surface-secondary border border-border space-y-1">
                  <span className="text-[10px] font-mono font-bold uppercase text-foreground-muted">
                    False Positive Justification
                  </span>
                  <p className="text-xs font-mono text-foreground">{detail.false_positive_reason}</p>
                </div>
              )}

              {detail.suppression_reason && (
                <div className="p-3 rounded-lg bg-surface-secondary border border-border space-y-1">
                  <span className="text-[10px] font-mono font-bold uppercase text-foreground-muted">
                    Suppression Reason (Scope: {detail.suppression_scope || 'THIS_ALERT'})
                  </span>
                  <p className="text-xs font-mono text-foreground">{detail.suppression_reason}</p>
                </div>
              )}

              {/* AUDIT ACTIVITY TIMELINE */}
              <div className="space-y-2">
                <h3 className="text-xs font-mono font-bold text-foreground uppercase tracking-wider">
                  Audit Activity Timeline
                </h3>
                <div className="p-3 rounded-lg bg-surface border border-border space-y-3">
                  {detail.activity_timeline.map((act, idx) => (
                    <div key={idx} className="flex items-start space-x-3 text-xs font-mono">
                      <div className="w-1.5 h-1.5 rounded-full bg-primary mt-1.5 shrink-0" />
                      <div className="space-y-0.5 min-w-0 flex-1">
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-foreground">{act.action}</span>
                          <span className="text-[10px] text-foreground-muted">
                            {new Date(act.timestamp).toLocaleTimeString([], {
                              hour: '2-digit',
                              minute: '2-digit',
                            })}
                          </span>
                        </div>
                        <p className="text-[11px] text-foreground-muted truncate">
                          by {act.user}: {act.details}
                        </p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* TRIAGE OBSERVATION NOTES */}
              <div className="space-y-2">
                <h3 className="text-xs font-mono font-bold text-foreground uppercase tracking-wider">
                  Triage Case Notes
                </h3>
                <form onSubmit={handleAddNote} className="space-y-2">
                  <div className="flex items-center space-x-2">
                    <input
                      type="text"
                      value={noteInput}
                      onChange={(e) => setNoteInput(e.target.value)}
                      placeholder="Add an auditable analyst triage observation..."
                      className="flex-1 px-3 py-2 bg-surface border border-border rounded-md text-xs font-mono text-foreground placeholder:text-foreground-muted/60 focus:outline-none focus:border-primary"
                    />
                    <button
                      type="submit"
                      disabled={noteSubmitting || !noteInput.trim()}
                      className="px-3 py-2 bg-primary text-primary-foreground rounded-md text-xs font-mono font-bold hover:bg-primary-hover disabled:opacity-50 cursor-pointer flex items-center space-x-1"
                    >
                      {noteSubmitting ? (
                        <Loader2 className="w-3.5 h-3.5 animate-spin" />
                      ) : (
                        <Send className="w-3.5 h-3.5" />
                      )}
                      <span>Add</span>
                    </button>
                  </div>
                </form>
              </div>
            </>
          ) : null}
        </div>

        {/* Action Toolbar Footer */}
        {detail && (
          <div className="px-6 py-4 border-t border-border bg-surface/50 flex flex-wrap items-center justify-between gap-2 shrink-0">
            <div className="flex items-center space-x-2">
              {detail.status === 'OPEN' && (
                <button
                  type="button"
                  onClick={handleAcknowledge}
                  disabled={actionLoading}
                  className="px-3 py-1.5 bg-primary text-primary-foreground rounded-md text-xs font-mono font-bold hover:bg-primary-hover cursor-pointer transition-colors"
                >
                  Acknowledge
                </button>
              )}
              {detail.status !== 'RESOLVED' && detail.status !== 'FALSE_POSITIVE' && (
                <>
                  <button
                    type="button"
                    onClick={() => {
                      setActiveModal('ASSIGN');
                      setModalInput(detail.assigned_to || '');
                    }}
                    className="px-3 py-1.5 bg-surface border border-border text-foreground rounded-md text-xs font-mono font-bold hover:bg-surface-secondary cursor-pointer transition-colors"
                  >
                    Assign
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setActiveModal('RESOLVE');
                      setModalInput('');
                    }}
                    className="px-3 py-1.5 bg-threat-low/20 text-threat-low border border-threat-low/30 rounded-md text-xs font-mono font-bold hover:bg-threat-low/30 cursor-pointer transition-colors"
                  >
                    Resolve
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setActiveModal('FALSE_POSITIVE');
                      setModalInput('');
                    }}
                    className="px-3 py-1.5 bg-surface border border-border text-foreground-muted rounded-md text-xs font-mono font-bold hover:bg-surface-secondary cursor-pointer transition-colors"
                  >
                    False Positive
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setActiveModal('SUPPRESS');
                      setModalInput('');
                    }}
                    className="px-3 py-1.5 bg-surface border border-border text-foreground-muted rounded-md text-xs font-mono font-bold hover:bg-surface-secondary cursor-pointer transition-colors"
                  >
                    Suppress
                  </button>
                  <button
                    type="button"
                    onClick={handlePromoteToIncident}
                    disabled={actionLoading}
                    className="px-3 py-1.5 bg-danger-surface hover:bg-danger/20 border border-danger-border text-danger rounded-md text-xs font-mono font-bold flex items-center space-x-1 cursor-pointer transition-colors"
                    title="Promote this security alert to an operational Incident case"
                  >
                    <ShieldAlert className="w-3.5 h-3.5" />
                    <span>Promote to Incident</span>
                  </button>
                </>
              )}
            </div>

            {/* Deep Handoff Link to Response if investigation present */}
            {detail.investigation_id && (
              <button
                type="button"
                onClick={() => {
                  navigate(`/investigations/${detail.investigation_id}/response`);
                  onClose();
                }}
                className="px-3 py-1.5 text-xs font-mono text-primary hover:underline flex items-center space-x-1 cursor-pointer"
              >
                <span>Response Playbooks</span>
                <ArrowRight className="w-3 h-3" />
              </button>
            )}
          </div>
        )}

        {/* Modal for Action Confirmation */}
        {activeModal !== 'NONE' && (
          <div
            className="fixed inset-0 z-60 bg-black/70 flex items-center justify-center p-4"
            onClick={() => setActiveModal('NONE')}
          >
            <div
              className="w-full max-w-md bg-surface-elevated border border-border rounded-lg p-5 shadow-2xl space-y-4"
              onClick={(e) => e.stopPropagation()}
            >
              <div className="flex items-center justify-between border-b border-border pb-2">
                <h4 className="text-sm font-bold font-mono text-foreground uppercase">
                  {activeModal === 'RESOLVE' && 'Resolve Security Alert'}
                  {activeModal === 'FALSE_POSITIVE' && 'Mark as False Positive'}
                  {activeModal === 'SUPPRESS' && 'Suppress Security Alert'}
                  {activeModal === 'ASSIGN' && 'Assign Alert to Analyst'}
                </h4>
                <button
                  type="button"
                  onClick={() => setActiveModal('NONE')}
                  className="text-foreground-muted hover:text-foreground cursor-pointer"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              {activeModal === 'SUPPRESS' && (
                <div className="space-y-1">
                  <label className="text-xs font-mono text-foreground-muted">Suppression Scope</label>
                  <select
                    value={modalSecondaryInput}
                    onChange={(e) => setModalSecondaryInput(e.target.value)}
                    className="w-full px-3 py-2 bg-surface border border-border rounded-md text-xs font-mono text-foreground"
                  >
                    <option value="THIS_ALERT">This Specific Alert</option>
                    <option value="INDICATOR">Indicator / IOC Match</option>
                    <option value="PATTERN">Detection Pattern / Rule</option>
                  </select>
                </div>
              )}

              <div className="space-y-1">
                <label className="text-xs font-mono text-foreground-muted">
                  {activeModal === 'ASSIGN'
                    ? 'Assignee (Analyst ID or Team Name)'
                    : 'Deterministic Justification Reason (Required)'}
                </label>
                <textarea
                  value={modalInput}
                  onChange={(e) => setModalInput(e.target.value)}
                  placeholder={
                    activeModal === 'ASSIGN'
                      ? 'e.g. SOC Analyst 02 or Incident Team'
                      : 'Provide explicit operational reason...'
                  }
                  rows={3}
                  className="w-full px-3 py-2 bg-surface border border-border rounded-md text-xs font-mono text-foreground focus:outline-none focus:border-primary"
                />
              </div>

              {modalError && (
                <p className="text-xs font-mono text-threat-critical">{modalError}</p>
              )}

              <div className="flex items-center justify-end space-x-2 pt-2">
                <button
                  type="button"
                  onClick={() => setActiveModal('NONE')}
                  className="px-3 py-1.5 bg-surface border border-border text-foreground-muted rounded-md text-xs font-mono hover:bg-surface-secondary cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={handleConfirmModal}
                  disabled={actionLoading}
                  className="px-4 py-1.5 bg-primary text-primary-foreground rounded-md text-xs font-mono font-bold hover:bg-primary-hover disabled:opacity-50 cursor-pointer flex items-center space-x-1"
                >
                  {actionLoading && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
                  <span>Confirm Action</span>
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Section 49: Alert Cluster Deep Inspection Modal */}
        <AlertClusterDetailModal
          clusterId={selectedClusterId}
          isOpen={Boolean(selectedClusterId)}
          onClose={() => setSelectedClusterId(null)}
          onClusterUpdated={loadDetail}
          onSelectAlert={(targetAlertId) => {
            setSelectedClusterId(null);
            onAlertUpdated?.({ id: targetAlertId } as any);
          }}
        />
      </div>
    </div>
  );
};
