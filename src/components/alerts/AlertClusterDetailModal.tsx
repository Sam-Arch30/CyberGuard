import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Layers,
  X,
  ExternalLink,
  Clock,
  User,
  Globe,
  Hash,
  Laptop,
  CheckCircle,
  Loader2,
  RefreshCw,
  GitMerge,
  ArrowRight,
} from 'lucide-react';
import { cn } from '../../utils/cn';
import { AlertClusterService } from '../../services/alertClusterService';
import type { AlertClusterDetail, ClusterStatus } from '../../types/alertCluster';

interface AlertClusterDetailModalProps {
  clusterId: string | null;
  isOpen: boolean;
  onClose: () => void;
  onClusterUpdated?: () => void;
  onSelectAlert?: (alertId: string) => void;
}

export const AlertClusterDetailModal: React.FC<AlertClusterDetailModalProps> = ({
  clusterId,
  isOpen,
  onClose,
  onClusterUpdated,
  onSelectAlert,
}) => {
  const navigate = useNavigate();
  const [detail, setDetail] = useState<AlertClusterDetail | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [actionLoading, setActionLoading] = useState<boolean>(false);

  // Status Change State
  const [statusModalOpen, setStatusModalOpen] = useState<boolean>(false);
  const [selectedStatus, setSelectedStatus] = useState<ClusterStatus>('INVESTIGATING');
  const [statusReason, setStatusReason] = useState<string>('');

  // Merge State
  const [mergeModalOpen, setMergeModalOpen] = useState<boolean>(false);
  const [targetClusterId, setTargetClusterId] = useState<string>('');
  const [mergeReason, setMergeReason] = useState<string>('');

  const loadCluster = useCallback(async () => {
    if (!clusterId) return;
    setLoading(true);
    setError(null);
    try {
      const data = await AlertClusterService.getClusterDetail(clusterId);
      setDetail(data);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to load alert cluster');
    } finally {
      setLoading(false);
    }
  }, [clusterId]);

  useEffect(() => {
    if (isOpen && clusterId) {
      loadCluster();
    } else {
      setDetail(null);
      setError(null);
      setStatusModalOpen(false);
      setMergeModalOpen(false);
    }
  }, [isOpen, clusterId, loadCluster]);

  if (!isOpen) return null;

  const handleUpdateStatus = async () => {
    if (!clusterId) return;
    setActionLoading(true);
    try {
      await AlertClusterService.updateClusterStatus(clusterId, selectedStatus, statusReason);
      setStatusModalOpen(false);
      setStatusReason('');
      await loadCluster();
      onClusterUpdated?.();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to update status');
    } finally {
      setActionLoading(false);
    }
  };

  const handleMerge = async () => {
    if (!clusterId || !targetClusterId.trim()) return;
    setActionLoading(true);
    try {
      await AlertClusterService.mergeClusters(clusterId, targetClusterId.trim(), mergeReason);
      setMergeModalOpen(false);
      setTargetClusterId('');
      setMergeReason('');
      await loadCluster();
      onClusterUpdated?.();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to merge cluster');
    } finally {
      setActionLoading(false);
    }
  };

  const handleInvestigate = async () => {
    if (!clusterId) return;
    setActionLoading(true);
    try {
      const updated = await AlertClusterService.linkInvestigation(clusterId, {
        create_if_missing: true,
        investigation_title: detail?.title,
      });
      if (updated.investigation_id) {
        navigate(`/investigations/${updated.investigation_id}`);
        onClose();
      } else {
        await loadCluster();
        onClusterUpdated?.();
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to link investigation');
    } finally {
      setActionLoading(false);
    }
  };

  const getSeverityBadge = (sev: string) => {
    switch (sev.toUpperCase()) {
      case 'CRITICAL':
        return 'bg-threat-critical/15 text-threat-critical border-threat-critical/30';
      case 'HIGH':
        return 'bg-threat-high/15 text-threat-high border-threat-high/30';
      case 'MEDIUM':
        return 'bg-threat-medium/15 text-threat-medium border-threat-medium/30';
      case 'LOW':
        return 'bg-threat-low/15 text-threat-low border-threat-low/30';
      default:
        return 'bg-surface-secondary text-foreground-muted border-border';
    }
  };

  const getStatusBadge = (st: string) => {
    switch (st.toUpperCase()) {
      case 'OPEN':
        return 'bg-threat-critical/10 text-threat-critical border-threat-critical/20';
      case 'INVESTIGATING':
        return 'bg-primary/10 text-primary border-primary/30';
      case 'CONTAINED':
        return 'bg-amber-500/10 text-amber-400 border-amber-500/30';
      case 'RESOLVED':
        return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
      case 'MERGED':
        return 'bg-purple-500/10 text-purple-400 border-purple-500/30';
      default:
        return 'bg-surface-secondary text-foreground-muted border-border';
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-background/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div
        className="w-full max-w-4xl max-h-[90vh] bg-surface-elevated border border-border rounded-xl shadow-2xl flex flex-col overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="px-6 py-4 border-b border-border flex items-center justify-between bg-surface/70 shrink-0">
          <div className="flex items-center space-x-3">
            <div className="p-2.5 rounded-lg bg-primary/10 border border-primary/20 text-primary">
              <Layers className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="text-sm font-bold font-mono text-foreground">
                  Alert Cluster & Incident Context
                </span>
                {detail && (
                  <span className="text-xs font-mono px-2 py-0.5 rounded bg-surface border border-border text-foreground-muted">
                    {detail.cluster_number}
                  </span>
                )}
              </div>
              <p className="text-xs font-mono text-foreground-muted">
                Multi-signal correlated alert grouping with explainable evidence
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-2">
            <button
              type="button"
              onClick={loadCluster}
              disabled={loading}
              className="p-1.5 rounded-md text-foreground-muted hover:text-foreground hover:bg-surface-secondary transition-colors cursor-pointer"
              title="Refresh Cluster"
            >
              <RefreshCw className={cn('w-4 h-4', loading && 'animate-spin')} />
            </button>
            <button
              type="button"
              onClick={onClose}
              className="p-1.5 rounded-md text-foreground-muted hover:text-foreground hover:bg-surface-secondary transition-colors cursor-pointer"
              title="Close Modal"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto px-6 py-5 space-y-6">
          {loading && !detail ? (
            <div className="py-24 flex flex-col items-center justify-center space-y-3">
              <Loader2 className="w-8 h-8 text-primary animate-spin" />
              <p className="text-xs font-mono text-foreground-muted">
                Correlating forensic graph and cluster metadata...
              </p>
            </div>
          ) : error ? (
            <div className="p-4 rounded-lg bg-threat-critical/10 border border-threat-critical/30 text-threat-critical text-xs font-mono space-y-2">
              <p className="font-bold">Failed to load cluster details</p>
              <p>{error}</p>
              <button
                type="button"
                onClick={loadCluster}
                className="px-3 py-1 bg-surface border border-threat-critical/40 rounded text-xs hover:bg-surface-secondary cursor-pointer"
              >
                Retry
              </button>
            </div>
          ) : detail ? (
            <>
              {/* Cluster Overview Card */}
              <div className="p-5 rounded-lg bg-surface border border-border space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <span
                      className={cn(
                        'px-2.5 py-1 rounded text-xs font-mono font-bold uppercase border',
                        getSeverityBadge(detail.severity)
                      )}
                    >
                      {detail.severity}
                    </span>
                    <span
                      className={cn(
                        'px-2.5 py-1 rounded text-xs font-mono font-bold uppercase border',
                        getStatusBadge(detail.status)
                      )}
                    >
                      {detail.status}
                    </span>
                    <span className="px-2.5 py-1 rounded text-xs font-mono bg-surface-secondary border border-border text-foreground">
                      {detail.alert_count} Correlated Alerts
                    </span>
                  </div>

                  <div className="flex items-center space-x-2">
                    <button
                      type="button"
                      onClick={() => setStatusModalOpen(true)}
                      className="px-3 py-1.5 bg-surface-secondary hover:bg-surface-secondary/80 border border-border text-xs font-mono text-foreground rounded-md cursor-pointer transition-colors"
                    >
                      Change Status
                    </button>
                    <button
                      type="button"
                      onClick={() => setMergeModalOpen(true)}
                      className="px-3 py-1.5 bg-surface-secondary hover:bg-surface-secondary/80 border border-border text-xs font-mono text-foreground rounded-md flex items-center space-x-1 cursor-pointer transition-colors"
                    >
                      <GitMerge className="w-3.5 h-3.5 text-purple-400" />
                      <span>Merge</span>
                    </button>
                    {detail.investigation_id ? (
                      <button
                        type="button"
                        onClick={() => {
                          navigate(`/investigations/${detail.investigation_id}`);
                          onClose();
                        }}
                        className="px-3 py-1.5 bg-primary text-primary-foreground hover:bg-primary-hover rounded-md text-xs font-mono font-bold flex items-center space-x-1.5 transition-colors cursor-pointer"
                      >
                        <span>Open Investigation</span>
                        <ExternalLink className="w-3.5 h-3.5" />
                      </button>
                    ) : (
                      <button
                        type="button"
                        onClick={handleInvestigate}
                        disabled={actionLoading}
                        className="px-3 py-1.5 bg-primary text-primary-foreground hover:bg-primary-hover rounded-md text-xs font-mono font-bold flex items-center space-x-1.5 transition-colors cursor-pointer"
                      >
                        {actionLoading ? (
                          <Loader2 className="w-3.5 h-3.5 animate-spin" />
                        ) : (
                          <>
                            <span>Create Investigation</span>
                            <ArrowRight className="w-3.5 h-3.5" />
                          </>
                        )}
                      </button>
                    )}
                  </div>
                </div>

                <h2 className="text-lg font-bold font-mono text-foreground leading-snug">
                  {detail.title}
                </h2>
                <p className="text-xs font-mono text-foreground-muted leading-relaxed">
                  {detail.summary}
                </p>

                {/* Score Grid */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-2">
                  <div className="p-3 rounded-md bg-surface-secondary/60 border border-border">
                    <span className="text-[10px] font-mono uppercase text-foreground-muted">
                      Correlation Confidence
                    </span>
                    <p className="text-base font-bold font-mono text-primary">
                      {Math.round(detail.confidence * 100)}%
                    </p>
                  </div>
                  <div className="p-3 rounded-md bg-surface-secondary/60 border border-border">
                    <span className="text-[10px] font-mono uppercase text-foreground-muted">
                      Aggregated Risk
                    </span>
                    <p className="text-base font-bold font-mono text-threat-critical">
                      {detail.risk_score.toFixed(1)} / 100
                    </p>
                  </div>
                  <div className="p-3 rounded-md bg-surface-secondary/60 border border-border">
                    <span className="text-[10px] font-mono uppercase text-foreground-muted">
                      First Observed
                    </span>
                    <p className="text-xs font-mono text-foreground mt-1 truncate" title={detail.first_seen}>
                      {new Date(detail.first_seen).toLocaleTimeString([], {
                        hour: '2-digit',
                        minute: '2-digit',
                      })}
                    </p>
                  </div>
                  <div className="p-3 rounded-md bg-surface-secondary/60 border border-border">
                    <span className="text-[10px] font-mono uppercase text-foreground-muted">
                      Last Activity
                    </span>
                    <p className="text-xs font-mono text-foreground mt-1 truncate" title={detail.last_seen}>
                      {new Date(detail.last_seen).toLocaleTimeString([], {
                        hour: '2-digit',
                        minute: '2-digit',
                      })}
                    </p>
                  </div>
                </div>
              </div>

              {/* WHY RELATED: Correlation Signals Card */}
              <div className="p-5 rounded-lg bg-surface border border-border space-y-3">
                <div className="flex items-center space-x-2 text-foreground font-mono text-xs font-bold uppercase tracking-wider">
                  <CheckCircle className="w-4 h-4 text-emerald-400" />
                  <span>Why Are These Alerts Grouped Together? ({Math.round(detail.confidence * 100)}% Correlated)</span>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
                  {detail.aggregated_signals.map((sig, idx) => (
                    <div
                      key={idx}
                      className="p-3 rounded-md bg-surface-secondary/40 border border-border flex items-start space-x-2.5"
                    >
                      <span className="text-emerald-400 font-bold mt-0.5">✓</span>
                      <div className="space-y-0.5">
                        <div className="flex items-center space-x-2">
                          <span className="text-xs font-mono font-bold text-foreground">
                            {sig.type.replace(/_/g, ' ')}
                          </span>
                          <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-primary/10 text-primary border border-primary/20">
                            {Math.round(sig.strength * 100)}% weight
                          </span>
                        </div>
                        <p className="text-xs font-mono text-foreground-muted">{sig.description}</p>
                        {sig.matched_value && (
                          <p className="text-[11px] font-mono text-primary truncate max-w-sm">
                            Matched: {sig.matched_value}
                          </p>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Member Alerts Table */}
              <div className="space-y-3">
                <h3 className="text-xs font-mono font-bold text-foreground uppercase tracking-wider">
                  Correlated Member Alerts ({detail.members.length})
                </h3>
                <div className="border border-border rounded-lg overflow-hidden bg-surface divide-y divide-border">
                  {detail.members.map((mem) => (
                    <div
                      key={mem.id}
                      onClick={() => onSelectAlert?.(mem.alert_id)}
                      className="p-3.5 hover:bg-surface-secondary/60 transition-colors flex items-center justify-between cursor-pointer group"
                    >
                      <div className="space-y-1 pr-4">
                        <div className="flex items-center space-x-2">
                          {mem.alert_summary && (
                            <span
                              className={cn(
                                'px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border',
                                getSeverityBadge(mem.alert_summary.severity)
                              )}
                            >
                              {mem.alert_summary.severity}
                            </span>
                          )}
                          <span className="text-xs font-mono font-bold text-foreground group-hover:text-primary transition-colors">
                            {mem.alert_summary?.title || `Alert #${mem.alert_id.slice(0, 8)}`}
                          </span>
                        </div>
                        <div className="flex flex-wrap items-center gap-2 text-[11px] font-mono text-foreground-muted">
                          <span>{mem.alert_summary?.alert_type || 'SECURITY_ALERT'}</span>
                          <span>•</span>
                          <span>{new Date(mem.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                          <span>•</span>
                          <span className="text-primary font-semibold">
                            {Math.round(mem.membership_confidence * 100)}% membership fit
                          </span>
                        </div>
                      </div>

                      <div className="flex items-center space-x-2 shrink-0">
                        <span className="text-xs font-mono text-foreground-muted group-hover:text-foreground flex items-center space-x-1">
                          <span>Inspect Alert</span>
                          <ArrowRight className="w-3.5 h-3.5" />
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Extracted Affected Entities */}
              <div className="p-4 rounded-lg bg-surface border border-border space-y-3">
                <h3 className="text-xs font-mono font-bold text-foreground uppercase tracking-wider">
                  Affected Entities & Infrastructure
                </h3>
                <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
                  {detail.entities.users.length > 0 && (
                    <div className="p-3 rounded-md bg-surface-secondary/30 border border-border space-y-1">
                      <div className="flex items-center space-x-1.5 text-xs font-mono font-bold text-foreground-muted">
                        <User className="w-3.5 h-3.5 text-primary" />
                        <span>Identities ({detail.entities.users.length})</span>
                      </div>
                      <div className="space-y-0.5">
                        {detail.entities.users.slice(0, 3).map((u, i) => (
                          <p key={i} className="text-xs font-mono text-foreground truncate">{u}</p>
                        ))}
                      </div>
                    </div>
                  )}

                  {detail.entities.domains.length > 0 && (
                    <div className="p-3 rounded-md bg-surface-secondary/30 border border-border space-y-1">
                      <div className="flex items-center space-x-1.5 text-xs font-mono font-bold text-foreground-muted">
                        <Globe className="w-3.5 h-3.5 text-threat-high" />
                        <span>Threat Domains ({detail.entities.domains.length})</span>
                      </div>
                      <div className="space-y-0.5">
                        {detail.entities.domains.slice(0, 3).map((d, i) => (
                          <p key={i} className="text-xs font-mono text-foreground truncate">{d}</p>
                        ))}
                      </div>
                    </div>
                  )}

                  {detail.entities.endpoints.length > 0 && (
                    <div className="p-3 rounded-md bg-surface-secondary/30 border border-border space-y-1">
                      <div className="flex items-center space-x-1.5 text-xs font-mono font-bold text-foreground-muted">
                        <Laptop className="w-3.5 h-3.5 text-threat-critical" />
                        <span>Endpoints ({detail.entities.endpoints.length})</span>
                      </div>
                      <div className="space-y-0.5">
                        {detail.entities.endpoints.slice(0, 3).map((ep, i) => (
                          <p key={i} className="text-xs font-mono text-foreground truncate">{ep}</p>
                        ))}
                      </div>
                    </div>
                  )}

                  {detail.entities.hashes.length > 0 && (
                    <div className="p-3 rounded-md bg-surface-secondary/30 border border-border space-y-1">
                      <div className="flex items-center space-x-1.5 text-xs font-mono font-bold text-foreground-muted">
                        <Hash className="w-3.5 h-3.5 text-amber-400" />
                        <span>Payload Hashes ({detail.entities.hashes.length})</span>
                      </div>
                      <div className="space-y-0.5">
                        {detail.entities.hashes.slice(0, 2).map((h, i) => (
                          <p key={i} className="text-xs font-mono text-foreground truncate">{h.slice(0, 16)}...</p>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>

              {/* Attack Timeline */}
              {detail.timeline.length > 0 && (
                <div className="p-4 rounded-lg bg-surface border border-border space-y-3">
                  <div className="flex items-center space-x-2 text-foreground font-mono text-xs font-bold uppercase tracking-wider">
                    <Clock className="w-3.5 h-3.5 text-primary" />
                    <span>Attack Activity Timeline</span>
                  </div>
                  <div className="space-y-2 border-l-2 border-primary/30 ml-2 pl-3">
                    {detail.timeline.map((ev, i) => (
                      <div key={i} className="relative space-y-0.5">
                        <div className="absolute -left-[19px] top-1.5 w-2.5 h-2.5 rounded-full bg-primary border-2 border-surface" />
                        <div className="flex items-center space-x-2 text-xs font-mono">
                          <span className="text-foreground-muted font-bold">
                            {new Date(ev.timestamp).toLocaleTimeString([], {
                              hour: '2-digit',
                              minute: '2-digit',
                            })}
                          </span>
                          <span className="text-foreground font-semibold">{ev.title}</span>
                          <span
                            className={cn(
                              'px-1.5 py-0.2 rounded text-[10px] font-mono border',
                              getSeverityBadge(ev.severity)
                            )}
                          >
                            {ev.severity}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </>
          ) : null}
        </div>

        {/* Status Change Sub-Modal */}
        {statusModalOpen && (
          <div className="p-4 bg-surface border-t border-border flex items-center justify-between space-x-3 shrink-0">
            <div className="flex items-center space-x-3 flex-1">
              <select
                value={selectedStatus}
                onChange={(e) => setSelectedStatus(e.target.value as ClusterStatus)}
                className="px-2.5 py-1.5 bg-surface-secondary border border-border text-xs font-mono rounded text-foreground focus:outline-none"
              >
                <option value="OPEN">OPEN</option>
                <option value="INVESTIGATING">INVESTIGATING</option>
                <option value="CONTAINED">CONTAINED</option>
                <option value="RESOLVED">RESOLVED</option>
                <option value="FALSE_POSITIVE">FALSE_POSITIVE</option>
                <option value="SUPPRESSED">SUPPRESSED</option>
              </select>
              <input
                type="text"
                placeholder="Status change justification reason..."
                value={statusReason}
                onChange={(e) => setStatusReason(e.target.value)}
                className="flex-1 px-3 py-1.5 bg-surface-secondary border border-border text-xs font-mono rounded text-foreground focus:outline-none"
              />
            </div>
            <div className="flex items-center space-x-2">
              <button
                type="button"
                onClick={() => setStatusModalOpen(false)}
                className="px-3 py-1.5 border border-border rounded text-xs font-mono text-foreground-muted hover:text-foreground cursor-pointer"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleUpdateStatus}
                disabled={actionLoading}
                className="px-3 py-1.5 bg-primary text-primary-foreground font-mono rounded text-xs font-bold hover:bg-primary-hover cursor-pointer"
              >
                {actionLoading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : 'Confirm'}
              </button>
            </div>
          </div>
        )}

        {/* Merge Sub-Modal */}
        {mergeModalOpen && (
          <div className="p-4 bg-surface border-t border-border flex items-center justify-between space-x-3 shrink-0">
            <div className="flex items-center space-x-3 flex-1">
              <input
                type="text"
                placeholder="Target Destination Cluster ID..."
                value={targetClusterId}
                onChange={(e) => setTargetClusterId(e.target.value)}
                className="w-1/3 px-3 py-1.5 bg-surface-secondary border border-border text-xs font-mono rounded text-foreground focus:outline-none"
              />
              <input
                type="text"
                placeholder="Consolidation rationale / threat actor link..."
                value={mergeReason}
                onChange={(e) => setMergeReason(e.target.value)}
                className="flex-1 px-3 py-1.5 bg-surface-secondary border border-border text-xs font-mono rounded text-foreground focus:outline-none"
              />
            </div>
            <div className="flex items-center space-x-2">
              <button
                type="button"
                onClick={() => setMergeModalOpen(false)}
                className="px-3 py-1.5 border border-border rounded text-xs font-mono text-foreground-muted hover:text-foreground cursor-pointer"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleMerge}
                disabled={actionLoading || !targetClusterId.trim()}
                className="px-3 py-1.5 bg-purple-600 text-white font-mono rounded text-xs font-bold hover:bg-purple-700 cursor-pointer"
              >
                {actionLoading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : 'Merge Clusters'}
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
