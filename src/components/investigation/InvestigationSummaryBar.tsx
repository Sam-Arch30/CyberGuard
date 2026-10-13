import React, { useState, useRef, useEffect } from 'react';
import {
  ShieldAlert,
  AlertTriangle,
  ChevronDown,
  MessageSquare,
  RefreshCw,
  Clock,
  FileText,
  GitBranch,
  CheckCircle2,
  XCircle,
} from 'lucide-react';
import { ThreatScore } from '../security/ThreatScore';
import type {
  InvestigationWorkspaceSummary,
  InvestigationStatus,
} from '../../types/investigationWorkspace';
import type { RealtimeConnectionStatus } from '../../types/realtime';

interface InvestigationSummaryBarProps {
  summary: InvestigationWorkspaceSummary | null;
  loading?: boolean;
  connectionStatus?: RealtimeConnectionStatus;
  onStatusChange?: (newStatus: InvestigationStatus | string, reason?: string) => Promise<void>;
  onOpenNotes?: () => void;
  onRefresh?: () => Promise<void>;
}

const ALLOWED_STATUSES: { key: InvestigationStatus; label: string; color: string }[] = [
  { key: 'OPEN', label: 'Open', color: 'text-warning bg-warning/10 border-warning/30' },
  { key: 'INVESTIGATING', label: 'Investigating', color: 'text-primary bg-primary/10 border-primary/30' },
  { key: 'CONTAINED', label: 'Contained', color: 'text-accent bg-accent/10 border-accent/30' },
  { key: 'RESOLVED', label: 'Resolved', color: 'text-success bg-success/10 border-success/30' },
  { key: 'CLOSED', label: 'Closed', color: 'text-foreground-muted bg-surface-secondary border-border' },
];

export const InvestigationSummaryBar: React.FC<InvestigationSummaryBarProps> = ({
  summary,
  loading = false,
  connectionStatus,
  onStatusChange,
  onOpenNotes,
  onRefresh,
}) => {
  const [statusMenuOpen, setStatusMenuOpen] = useState(false);
  const [updatingStatus, setUpdatingStatus] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [statusError, setStatusError] = useState<string | null>(null);

  const statusRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (statusRef.current && !statusRef.current.contains(e.target as Node)) {
        setStatusMenuOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  if (!summary && loading) {
    return (
      <div className="bg-surface border border-border rounded-xl p-3 shadow-xs animate-pulse flex items-center justify-between text-xs font-mono text-foreground-muted">
        <div className="flex items-center space-x-3">
          <div className="w-8 h-8 rounded-lg bg-surface-secondary" />
          <div className="h-4 w-40 bg-surface-secondary rounded" />
          <div className="h-4 w-24 bg-surface-secondary rounded" />
        </div>
        <div className="flex items-center space-x-2">
          <div className="h-6 w-20 bg-surface-secondary rounded" />
          <div className="h-6 w-28 bg-surface-secondary rounded" />
        </div>
      </div>
    );
  }

  if (!summary) return null;

  const { investigation, risk, counts, attention_items, last_updated } = summary;
  const currentStatus = (summary.status || investigation.status || 'OPEN').toUpperCase();
  const currentStatusConfig = ALLOWED_STATUSES.find(s => s.key === currentStatus) || {
    key: currentStatus as InvestigationStatus,
    label: currentStatus,
    color: 'text-foreground-muted bg-surface-secondary border-border',
  };

  const handleSelectStatus = async (targetStatus: InvestigationStatus) => {
    if (targetStatus === currentStatus) {
      setStatusMenuOpen(false);
      return;
    }
    setStatusMenuOpen(false);
    if (!onStatusChange) return;

    setUpdatingStatus(true);
    setStatusError(null);
    try {
      await onStatusChange(targetStatus);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Status transition rejected';
      setStatusError(msg);
      setTimeout(() => setStatusError(null), 4000);
    } finally {
      setUpdatingStatus(false);
    }
  };

  const handleRefreshClick = async () => {
    if (!onRefresh || refreshing) return;
    setRefreshing(true);
    try {
      await onRefresh();
    } finally {
      setRefreshing(false);
    }
  };

  const formatTimeAgo = (ts?: string | null) => {
    if (!ts) return 'Just now';
    try {
      const d = new Date(ts);
      if (isNaN(d.getTime())) return ts;
      const now = new Date();
      const diffSec = Math.floor((now.getTime() - d.getTime()) / 1000);
      if (diffSec < 60) return `${diffSec}s ago`;
      const diffMin = Math.floor(diffSec / 60);
      if (diffMin < 60) return `${diffMin}m ago`;
      const diffHours = Math.floor(diffMin / 60);
      if (diffHours < 24) return `${diffHours}h ago`;
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    } catch {
      return ts;
    }
  };

  return (
    <div className="cg-investigation-summary bg-surface border border-border rounded-xl overflow-visible transition-colors mb-4">
      {/* Top Banner: Attention Items if any */}
      {attention_items && attention_items.length > 0 && (
        <div className="bg-warning/10 border-b border-warning/20 px-4 py-2 flex items-center justify-between gap-3 text-xs font-mono text-warning">
          <div className="flex items-center space-x-2 truncate">
            <AlertTriangle className="w-4 h-4 shrink-0 text-warning animate-pulse" />
            <span className="font-semibold uppercase tracking-wider text-[11px]">Attention Required:</span>
            <span className="truncate text-foreground font-medium">
              {attention_items.join(' · ')}
            </span>
          </div>
          <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-warning/20 text-warning shrink-0">
            {attention_items.length} Action{attention_items.length > 1 ? 's' : ''}
          </span>
        </div>
      )}

      {/* Main Bar */}
      <div className="px-4 py-3 flex flex-col xl:flex-row xl:items-center justify-between gap-3">
        {/* Left: Score Badge + Incident + Title */}
        <div className="flex items-center gap-3 min-w-0">
          <div className="shrink-0">
            <ThreatScore
              score={risk ? risk.score : investigation?.risk_score ?? null}
              severity={risk?.severity ?? investigation?.severity}
              confidenceScore={risk ? risk.confidence ?? undefined : investigation?.confidence ?? undefined}
              variant="compact"
              showConfidence={false}
            />
          </div>

          <div className="min-w-0">
            <div className="flex flex-col gap-1 min-w-0">
              <span className="font-mono text-xs font-bold text-primary tracking-wide break-all">
                {investigation.incident_number || investigation.investigation_id}
              </span>

              <h2
                className="text-xs sm:text-sm font-semibold text-foreground truncate max-w-[280px] sm:max-w-md lg:max-w-xl font-sans"
                title={investigation.title}
              >
                {investigation.title}
              </h2>
            </div>

            <div className="flex flex-wrap items-center gap-2 text-[11px] font-mono text-foreground-muted mt-0.5">
              <span className="break-all">{investigation.artifact_name || 'Evidence Artifact'}</span>
              <span>·</span>
              <span className="flex items-center space-x-1">
                <Clock className="w-3 h-3 text-foreground-muted" />
                <span>Updated {formatTimeAgo(last_updated || investigation.updated_at)}</span>
              </span>
            </div>
          </div>
        </div>

        {/* Right: Status Dropdown + Metric Pills + Actions */}
        <div className="flex items-center flex-wrap gap-2 self-start md:self-center shrink-0">
          {/* Status Badge with Backend Transition Selector */}
          <div className="relative" ref={statusRef}>
            <button
              type="button"
              disabled={updatingStatus}
              onClick={() => setStatusMenuOpen(!statusMenuOpen)}
              className={`flex items-center space-x-1.5 px-2.5 py-1 rounded-control text-xs font-mono font-semibold border transition-all cursor-pointer ${
                currentStatusConfig.color
              } hover:opacity-90`}
              title="Click to transition investigation status"
            >
              <span className="w-1.5 h-1.5 rounded-full bg-current" />
              <span>{updatingStatus ? 'Updating...' : currentStatusConfig.label}</span>
              <ChevronDown className="w-3.5 h-3.5 opacity-70" />
            </button>

            {statusMenuOpen && (
              <div className="absolute right-0 top-full mt-1.5 w-44 bg-surface-elevated border border-border rounded-xl shadow-xl z-50 p-1 animate-fadeIn text-xs font-mono">
                <div className="px-2 py-1 text-[10px] text-foreground-muted uppercase tracking-wider font-semibold">
                  Transition Status
                </div>
                {ALLOWED_STATUSES.map(opt => (
                  <button
                    key={opt.key}
                    type="button"
                    onClick={() => handleSelectStatus(opt.key)}
                    className={`w-full text-left px-2.5 py-1.5 rounded-lg flex items-center justify-between transition-colors cursor-pointer ${
                      opt.key === currentStatus
                        ? 'bg-primary/10 text-primary font-bold'
                        : 'hover:bg-surface-secondary text-foreground'
                    }`}
                  >
                    <span className="flex items-center space-x-2">
                      <span className="w-1.5 h-1.5 rounded-full bg-current" />
                      <span>{opt.label}</span>
                    </span>
                    {opt.key === currentStatus && <CheckCircle2 className="w-3.5 h-3.5 text-primary" />}
                  </button>
                ))}
              </div>
            )}
          </div>

          {/* Section 47: Security Alert Indicator */}
          {(investigation?.severity === 'CRITICAL' || investigation?.severity === 'HIGH' || (risk?.score && risk.score >= 60)) && (
            <div
              className="flex items-center space-x-1 px-2 py-1 rounded-control bg-threat-critical/10 border border-threat-critical/30 text-[11px] font-mono text-threat-critical font-bold animate-pulse"
              title="Active security alert registered for this investigation"
            >
              <ShieldAlert className="w-3.5 h-3.5 text-threat-critical shrink-0" />
              <span>ALERT</span>
            </div>
          )}

          {/* Metric Pill: Findings */}
          <div
            className="flex items-center space-x-1.5 px-2 py-1 rounded-control bg-surface-secondary border border-border text-[11px] font-mono text-foreground"
            title={`${counts.findings_count} verified findings`}
          >
            <ShieldAlert className="w-3.5 h-3.5 text-danger shrink-0" />
            <span>{counts.findings_count}</span>
            <span className="text-foreground-muted hidden sm:inline">findings</span>
          </div>

          {/* Metric Pill: Evidence */}
          <div
            className="flex items-center space-x-1.5 px-2 py-1 rounded-control bg-surface-secondary border border-border text-[11px] font-mono text-foreground"
            title={`${counts.evidence_count} evidence items`}
          >
            <FileText className="w-3.5 h-3.5 text-primary shrink-0" />
            <span>{counts.evidence_count}</span>
            <span className="text-foreground-muted hidden sm:inline">evidence</span>
          </div>

          {/* Metric Pill: Attack Paths */}
          {counts.attack_paths_count > 0 && (
            <div
              className="flex items-center space-x-1.5 px-2 py-1 rounded-control bg-surface-secondary border border-border text-[11px] font-mono text-foreground"
              title={`${counts.attack_paths_count} attack path hypotheses`}
            >
              <GitBranch className="w-3.5 h-3.5 text-accent shrink-0" />
              <span>{counts.attack_paths_count}</span>
              <span className="text-foreground-muted hidden sm:inline">paths</span>
            </div>
          )}

          {/* Notes Action Button */}
          <button
            type="button"
            onClick={onOpenNotes}
            className="flex items-center space-x-1.5 px-2.5 py-1 rounded-control bg-surface hover:bg-surface-secondary border border-border text-foreground hover:text-primary text-xs font-mono transition-colors cursor-pointer"
            title="Open analyst notes drawer"
          >
            <MessageSquare className="w-3.5 h-3.5 text-primary shrink-0" />
            <span>Notes</span>
            {counts.notes_count > 0 && (
              <span className="px-1.5 py-0.2 rounded-full bg-primary/15 text-primary text-[10px] font-bold">
                {counts.notes_count}
              </span>
            )}
          </button>

          {/* Real-time SSE Connection Status */}
          {connectionStatus && (
            <div
              className="flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] font-mono border bg-surface border-border text-foreground-muted"
              title="Real-time SSE event stream connection state"
            >
              {connectionStatus === 'CONNECTED' && (
                <>
                  <span className="w-1.5 h-1.5 rounded-full bg-success animate-pulse" />
                  <span className="text-foreground hidden sm:inline">Live</span>
                </>
              )}
              {connectionStatus === 'RECONNECTING' && (
                <>
                  <RefreshCw className="w-2.5 h-2.5 text-warning animate-spin" />
                  <span className="text-warning hidden sm:inline">Syncing</span>
                </>
              )}
              {connectionStatus === 'FALLBACK_POLLING' && (
                <>
                  <span className="w-1.5 h-1.5 rounded-full bg-info" />
                  <span className="text-foreground-muted hidden sm:inline">Polling</span>
                </>
              )}
              {connectionStatus === 'DISCONNECTED' && (
                <>
                  <span className="w-1.5 h-1.5 rounded-full bg-foreground-muted/40" />
                  <span className="text-foreground-muted hidden sm:inline">Idle</span>
                </>
              )}
            </div>
          )}

          {/* Refresh Revalidate Button */}
          {onRefresh && (
            <button
              type="button"
              disabled={refreshing}
              onClick={handleRefreshClick}
              className="p-1 rounded-control bg-surface hover:bg-surface-secondary border border-border text-foreground-muted hover:text-foreground transition-colors cursor-pointer"
              title="Refresh investigation summary"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin text-primary' : ''}`} />
            </button>
          )}
        </div>
      </div>

      {/* Error notification banner if status transition rejected */}
      {statusError && (
        <div className="bg-danger/10 border-t border-danger/20 px-4 py-1.5 flex items-center space-x-2 text-xs font-mono text-danger">
          <XCircle className="w-3.5 h-3.5 shrink-0" />
          <span>Status transition error: {statusError}</span>
        </div>
      )}
    </div>
  );
};
