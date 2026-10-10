import React, { useState, useEffect, useCallback } from 'react';
import {
  History,
  X,
  Clock,
  ArrowUpRight,
  UserCheck,
  Pause,
  Play,
  RefreshCw,
  Copy,
  Check,
  Shield,
  Layers,
} from 'lucide-react';
import { SlaClientService } from '../../services/slaService';
import type {
  IncidentWorkflowHistoryResponse,
  WorkflowExecutionItemModel,
  SLAPauseLogItemModel,
} from '../../types';

interface IncidentWorkflowHistoryModalProps {
  incidentId: string;
  incidentNumber: string;
  isOpen: boolean;
  onClose: () => void;
}

export const IncidentWorkflowHistoryModal: React.FC<IncidentWorkflowHistoryModalProps> = ({
  incidentId,
  incidentNumber,
  isOpen,
  onClose,
}) => {
  const [data, setData] = useState<IncidentWorkflowHistoryResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'executions' | 'pauses'>('executions');

  const loadHistory = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await SlaClientService.getWorkflowHistory(incidentId);
      setData(res);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to retrieve workflow history');
    } finally {
      setLoading(false);
    }
  }, [incidentId]);

  useEffect(() => {
    if (isOpen) {
      loadHistory();
    }
  }, [isOpen, loadHistory]);

  if (!isOpen) return null;

  const handleCopyKey = (key: string) => {
    navigator.clipboard.writeText(key);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const getActionBadge = (action: string) => {
    switch (action) {
      case 'ESCALATE_TIER':
        return { label: 'Escalate Tier', icon: ArrowUpRight, color: 'text-rose-400 bg-rose-500/10 border-rose-500/30' };
      case 'REASSIGN_INCIDENT':
      case 'ASSIGN_TO_USER':
      case 'ASSIGN_TO_TEAM':
        return { label: 'Reassign', icon: UserCheck, color: 'text-blue-400 bg-blue-500/10 border-blue-500/30' };
      case 'NOTIFY_OWNER':
      case 'NOTIFY_TEAM':
      case 'NOTIFY_SOC_LEAD':
        return { label: 'Notify Lead', icon: Clock, color: 'text-amber-400 bg-amber-500/10 border-amber-500/30' };
      case 'AUTO_ROUTE':
        return { label: 'Auto Routed', icon: Layers, color: 'text-purple-400 bg-purple-500/10 border-purple-500/30' };
      default:
        return { label: action, icon: Shield, color: 'text-foreground-muted bg-surface-secondary border-border' };
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-xs p-4 animate-in fade-in">
      <div className="bg-surface border border-border rounded-control p-5 w-full max-w-3xl space-y-4 shadow-2xl max-h-[85vh] flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-border pb-3 shrink-0">
          <div className="flex items-center space-x-2">
            <History className="w-4 h-4 text-primary" />
            <div>
              <h3 className="text-sm font-bold text-foreground">
                Automated Workflow Execution History
              </h3>
              <p className="text-[11px] font-mono text-foreground-muted">
                Incident {incidentNumber} · Immutable Audit Records & Idempotency Key Tracking
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-2">
            <button
              type="button"
              onClick={loadHistory}
              disabled={loading}
              className="p-1.5 text-foreground-muted hover:text-foreground hover:bg-surface-secondary rounded-control border border-border cursor-pointer"
              title="Refresh logs"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            </button>
            <button
              type="button"
              onClick={onClose}
              className="p-1.5 text-foreground-muted hover:text-foreground hover:bg-surface-secondary rounded-control border border-border cursor-pointer"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* Sub-tabs */}
        <div className="flex items-center space-x-2 border-b border-border/60 pb-2 shrink-0 text-xs">
          <button
            type="button"
            onClick={() => setActiveTab('executions')}
            className={`px-3 py-1 rounded-control font-medium cursor-pointer transition-colors ${
              activeTab === 'executions'
                ? 'bg-primary/15 text-primary border border-primary/30 font-semibold'
                : 'text-foreground-muted hover:text-foreground'
            }`}
          >
            Workflow Executions ({data?.executions.length ?? 0})
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('pauses')}
            className={`px-3 py-1 rounded-control font-medium cursor-pointer transition-colors ${
              activeTab === 'pauses'
                ? 'bg-primary/15 text-primary border border-primary/30 font-semibold'
                : 'text-foreground-muted hover:text-foreground'
            }`}
          >
            SLA Clock Pauses ({data?.pause_logs.length ?? 0})
          </button>
        </div>

        {/* Content Body */}
        <div className="overflow-y-auto flex-1 space-y-3 pr-1 text-xs">
          {loading ? (
            <div className="py-16 text-center text-foreground-muted flex flex-col items-center justify-center space-y-2">
              <RefreshCw className="w-5 h-5 animate-spin text-primary" />
              <span>Fetching workflow telemetry logs...</span>
            </div>
          ) : error ? (
            <div className="p-4 bg-danger-surface border border-danger-border rounded-control text-danger text-center">
              <span>{error}</span>
            </div>
          ) : activeTab === 'executions' ? (
            data?.executions.length === 0 ? (
              <div className="py-16 text-center text-foreground-muted space-y-1">
                <Shield className="w-8 h-8 text-foreground-muted/50 mx-auto" />
                <p className="font-semibold text-foreground">No automated workflows triggered</p>
                <p className="text-[11px]">
                  When SLA warning thresholds, breaches, or routing rules trigger, executed actions appear here.
                </p>
              </div>
            ) : (
              <div className="space-y-2.5">
                {data?.executions.map((exec: WorkflowExecutionItemModel) => {
                  const badge = getActionBadge(exec.action_type);
                  const BadgeIcon = badge.icon;
                  const isSuccess = exec.status === 'SUCCESS';
                  const isFailed = exec.status === 'FAILED';

                  return (
                    <div
                      key={exec.id}
                      className="p-3 bg-surface-secondary/40 border border-border rounded-control space-y-2 hover:border-border/80 transition-colors"
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex items-center space-x-2">
                          <span
                            className={`px-2 py-0.5 rounded-xs border text-[10px] font-mono flex items-center space-x-1 ${badge.color}`}
                          >
                            <BadgeIcon className="w-3 h-3" />
                            <span>{badge.label}</span>
                          </span>

                          <span className="text-[10px] font-mono text-foreground-muted">
                            Cond: <strong className="text-foreground">{exec.condition_type}</strong>
                          </span>

                          {exec.rule_name && (
                            <span className="text-[10px] text-foreground-muted">
                              ({exec.rule_name})
                            </span>
                          )}
                        </div>

                        <div className="flex items-center space-x-2 font-mono text-[10px] text-foreground-muted">
                          <span>{new Date(exec.executed_at).toLocaleString()}</span>
                          <span
                            className={`px-1.5 py-0.2 rounded border font-bold ${
                              isSuccess
                                ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30'
                                : isFailed
                                ? 'bg-red-500/15 text-red-400 border-red-500/30'
                                : 'bg-surface text-foreground-muted border-border'
                            }`}
                          >
                            {exec.status}
                          </span>
                        </div>
                      </div>

                      {/* Detail / Result */}
                      {exec.result && Object.keys(exec.result).length > 0 && (
                        <div className="bg-surface/80 p-2 rounded-xs border border-border font-mono text-[10px] text-foreground space-y-0.5">
                          {Object.entries(exec.result).map(([k, v]) => (
                            <div key={k} className="flex space-x-1">
                              <span className="text-foreground-muted">{k}:</span>
                              <span className="text-foreground font-semibold">{String(v)}</span>
                            </div>
                          ))}
                        </div>
                      )}

                      {exec.error && (
                        <div className="p-2 bg-red-500/10 border border-red-500/25 rounded-xs text-[10px] text-red-400 font-mono">
                          Error: {exec.error}
                        </div>
                      )}

                      {/* Idempotency Key */}
                      <div className="flex items-center justify-between text-[10px] font-mono text-foreground-muted pt-1 border-t border-border/40">
                        <span className="truncate max-w-md">Idempotency: {exec.idempotency_key}</span>
                        <button
                          type="button"
                          onClick={() => handleCopyKey(exec.idempotency_key)}
                          className="hover:text-primary transition-colors cursor-pointer ml-1 flex items-center space-x-1"
                        >
                          {copiedKey === exec.idempotency_key ? (
                            <Check className="w-3 h-3 text-emerald-400" />
                          ) : (
                            <Copy className="w-3 h-3" />
                          )}
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            )
          ) : (
            /* Pauses tab */
            data?.pause_logs.length === 0 ? (
              <div className="py-16 text-center text-foreground-muted space-y-1">
                <Pause className="w-8 h-8 text-foreground-muted/50 mx-auto" />
                <p className="font-semibold text-foreground">No SLA clock pause events</p>
                <p className="text-[11px]">The operational clock has run continuously without pauses.</p>
              </div>
            ) : (
              <div className="space-y-2.5">
                {data?.pause_logs.map((pause: SLAPauseLogItemModel) => (
                  <div
                    key={pause.id}
                    className="p-3 bg-surface-secondary/40 border border-border rounded-control space-y-2"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-2">
                        {pause.active ? (
                          <span className="px-2 py-0.5 rounded-xs border text-[10px] font-mono font-bold bg-amber-500/20 text-amber-400 border-amber-500/40 flex items-center space-x-1">
                            <Pause className="w-3 h-3" />
                            <span>Currently Active Pause</span>
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 rounded-xs border text-[10px] font-mono bg-surface text-foreground-muted border-border flex items-center space-x-1">
                            <Play className="w-3 h-3 text-emerald-400" />
                            <span>Resumed (+{pause.duration_minutes || 0}m adjusted)</span>
                          </span>
                        )}
                        <span className="text-xs font-semibold text-foreground">{pause.reason}</span>
                      </div>

                      <span className="text-[10px] font-mono text-foreground-muted">
                        by {pause.paused_by}
                      </span>
                    </div>

                    <div className="grid grid-cols-2 gap-2 text-[10px] font-mono text-foreground-muted bg-surface/80 p-2 rounded-xs border border-border">
                      <div>
                        <span className="block text-foreground-muted">Paused Timestamp:</span>
                        <span className="text-foreground">{new Date(pause.paused_at).toLocaleString()}</span>
                      </div>
                      <div>
                        <span className="block text-foreground-muted">Resumed Timestamp:</span>
                        <span className="text-foreground">
                          {pause.resumed_at ? new Date(pause.resumed_at).toLocaleString() : 'Pending Resume'}
                        </span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )
          )}
        </div>

        {/* Footer */}
        <div className="pt-2 border-t border-border flex justify-end shrink-0">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-1.5 text-xs font-semibold bg-surface-secondary border border-border rounded-control text-foreground hover:bg-surface cursor-pointer"
          >
            Close Audit Trail
          </button>
        </div>
      </div>
    </div>
  );
};
