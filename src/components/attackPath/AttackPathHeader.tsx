import React from 'react';
import {
  ShieldCheck,
  HelpCircle,
  AlertTriangle,
  GitBranch,
  RefreshCw,
  Layers,
  Clock,
  FileText,
  SlidersHorizontal,
  ChevronDown,
} from 'lucide-react';
import { Badge, Button } from '../ui';
import type {
  AttackPathDetailResponse,
  AttackPathStatus,
} from '../../types/attackPath';

interface AttackPathHeaderProps {
  pathData: AttackPathDetailResponse;
  onRefresh: () => void;
  isRefreshing: boolean;
  onSelectRun: (runId: string) => void;
  onOpenConfidenceModal: () => void;
  showFilters: boolean;
  onToggleFilters: () => void;
  activeFilterCount: number;
}

const STATUS_CONFIG: Record<
  AttackPathStatus,
  { label: string; badgeVariant: 'success' | 'warning' | 'primary' | 'outline' | 'danger'; icon: React.ReactNode; desc: string }
> = {
  ESTABLISHED: {
    label: 'ESTABLISHED RECONSTRUCTION',
    badgeVariant: 'success',
    icon: <ShieldCheck className="w-3.5 h-3.5" />,
    desc: 'Contiguous direct telemetry supports all major stages with no unresolved contradictions.',
  },
  PARTIAL: {
    label: 'PARTIAL RECONSTRUCTION',
    badgeVariant: 'warning',
    icon: <AlertTriangle className="w-3.5 h-3.5" />,
    desc: 'Beginning and/or terminal stages observed, but intermediate execution transitions remain unconfirmed.',
  },
  SUPPORTED_HYPOTHESIS: {
    label: 'SUPPORTED HYPOTHESIS',
    badgeVariant: 'primary',
    icon: <GitBranch className="w-3.5 h-3.5" />,
    desc: 'Sequence is evidence-backed but relies on circumstantial behavioral heuristics.',
  },
  LOW_CONFIDENCE: {
    label: 'LOW CONFIDENCE',
    badgeVariant: 'danger',
    icon: <AlertTriangle className="w-3.5 h-3.5" />,
    desc: 'Sparse telemetry yields low reconstruction certainty. Proceed with deep forensic review.',
  },
  INCONCLUSIVE: {
    label: 'INCONCLUSIVE',
    badgeVariant: 'outline',
    icon: <HelpCircle className="w-3.5 h-3.5" />,
    desc: 'Insufficient connected telemetry to establish a multi-stage progression.',
  },
};

export const AttackPathHeader: React.FC<AttackPathHeaderProps> = ({
  pathData,
  onRefresh,
  isRefreshing,
  onSelectRun,
  onOpenConfidenceModal,
  showFilters,
  onToggleFilters,
  activeFilterCount,
}) => {
  const statusCfg = STATUS_CONFIG[pathData.status] || STATUS_CONFIG.PARTIAL;

  // Format time span
  let timeSpanString = 'Time range unavailable';
  if (pathData.start_time) {
    const sDate = new Date(pathData.start_time);
    const sStr = sDate.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', timeZone: 'UTC' }) + ' UTC';
    if (pathData.end_time) {
      const eDate = new Date(pathData.end_time);
      const eStr = eDate.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', timeZone: 'UTC' }) + ' UTC';
      let durStr = '';
      if (pathData.duration_seconds !== null && pathData.duration_seconds !== undefined) {
        const m = Math.floor(pathData.duration_seconds / 60);
        durStr = m > 0 ? ` (${m}m duration)` : ` (${Math.round(pathData.duration_seconds)}s duration)`;
      }
      timeSpanString = `${sStr} → ${eStr}${durStr}`;
    } else {
      timeSpanString = `${sStr} (single timestamp)`;
    }
  }

  const confidenceScore = Math.round(pathData.confidence * 100);

  return (
    <div className="bg-surface border border-border rounded-xl p-5 shadow-xs space-y-4">
      {/* Top Bar: Title, Status, Run Selector, Actions */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="p-1.5 rounded-lg bg-accent/10 text-accent inline-flex">
              <GitBranch className="w-4 h-4" />
            </span>
            <h1 className="text-base font-semibold text-foreground font-sans tracking-tight">
              {pathData.name || 'Reconstructed Attack Progression'}
            </h1>
            <Badge
              variant={statusCfg.badgeVariant}
              size="sm"
              className="font-mono text-[10px] tracking-wider uppercase font-semibold flex items-center space-x-1"
            >
              {statusCfg.icon}
              <span>{statusCfg.label}</span>
            </Badge>
            {pathData.version > 1 && (
              <Badge variant="outline" size="sm" className="font-mono text-[10px]">
                v{pathData.version}
              </Badge>
            )}
          </div>
          <p className="text-xs text-foreground-muted font-mono leading-relaxed">
            {pathData.status_rationale || statusCfg.desc}
          </p>
        </div>

        {/* Action Controls */}
        <div className="flex flex-wrap items-center gap-2.5 shrink-0">
          {/* Analysis Run Selector */}
          {pathData.available_runs.length > 1 && (
            <div className="relative inline-block text-left">
              <select
                aria-label="Select Analysis Run"
                value={pathData.analysis_run_id || ''}
                onChange={(e) => onSelectRun(e.target.value)}
                className="text-xs font-mono bg-surface-secondary border border-border rounded-lg px-2.5 py-1.5 text-foreground hover:border-border-focus focus:outline-hidden focus:ring-1 focus:ring-accent cursor-pointer pr-7 appearance-none"
              >
                {pathData.available_runs.map((r, i) => (
                  <option key={r.run_id} value={r.run_id}>
                    Run #{pathData.available_runs.length - i} · {r.version || 'v1.0'}{r.is_current ? ' (Active)' : ''}
                  </option>
                ))}
              </select>
              <ChevronDown className="w-3 h-3 text-foreground-muted absolute right-2 top-2.5 pointer-events-none" />
            </div>
          )}

          {/* Filter Toggle Button */}
          <Button
            size="sm"
            variant={showFilters ? 'primary' : 'outline'}
            onClick={onToggleFilters}
            leftIcon={<SlidersHorizontal className="w-3.5 h-3.5" />}
            className="text-xs font-mono"
          >
            Filters{activeFilterCount > 0 ? ` (${activeFilterCount})` : ''}
          </Button>

          {/* Reconstruct / Refresh Button */}
          <Button
            size="sm"
            variant="outline"
            onClick={onRefresh}
            disabled={isRefreshing}
            leftIcon={<RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin' : ''}`} />}
            className="text-xs font-mono"
          >
            {isRefreshing ? 'Reconstructing…' : 'Re-evaluate'}
          </Button>
        </div>
      </div>

      {/* Metric Cards Bar */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-3 border-t border-border">
        {/* Calibrated Confidence */}
        <button
          type="button"
          onClick={onOpenConfidenceModal}
          className="p-3 rounded-lg bg-surface-secondary/60 border border-border text-left hover:border-accent hover:bg-surface-secondary transition-all cursor-pointer group"
        >
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-mono uppercase text-foreground-muted">
              Calibrated Confidence
            </span>
            <span className="text-[10px] font-mono text-accent underline opacity-0 group-hover:opacity-100 transition-opacity">
              Explain →
            </span>
          </div>
          <div className="flex items-baseline space-x-1.5 mt-1">
            <span className="text-base font-bold font-mono text-foreground">
              {confidenceScore}%
            </span>
            <span className="text-[10px] font-mono uppercase font-semibold text-accent">
              ({pathData.confidence_level})
            </span>
          </div>
          <div className="text-[10px] font-mono text-foreground-muted mt-0.5 truncate">
            {pathData.completeness_score > 0
              ? `${Math.round(pathData.completeness_score * 100)}% stages observed`
              : 'Evidence strength'}
          </div>
        </button>

        {/* Stages Count */}
        <div className="p-3 rounded-lg bg-surface-secondary/60 border border-border">
          <div className="text-[10px] font-mono uppercase text-foreground-muted flex items-center space-x-1">
            <Layers className="w-3 h-3" />
            <span>Path Stages</span>
          </div>
          <div className="text-base font-bold font-mono text-foreground mt-1">
            {pathData.stages.length}
          </div>
          <div className="text-[10px] font-mono text-foreground-muted mt-0.5">
            {pathData.stages.filter(s => s.stage_status === 'OBSERVED').length} direct · {pathData.stages.filter(s => s.stage_status === 'INFERRED').length} inferred
          </div>
        </div>

        {/* Evidence Items Backing Path */}
        <div className="p-3 rounded-lg bg-surface-secondary/60 border border-border">
          <div className="text-[10px] font-mono uppercase text-foreground-muted flex items-center space-x-1">
            <FileText className="w-3 h-3" />
            <span>Backing Evidence</span>
          </div>
          <div className="text-base font-bold font-mono text-foreground mt-1">
            {pathData.total_evidence_count > 0 ? `${pathData.total_evidence_count} Items` : 'Evidence unavailable'}
          </div>
          <div className="text-[10px] font-mono text-foreground-muted mt-0.5">
            {pathData.total_findings_count} findings · {pathData.total_entities_count} entities
          </div>
        </div>

        {/* Chronological Span */}
        <div className="p-3 rounded-lg bg-surface-secondary/60 border border-border">
          <div className="text-[10px] font-mono uppercase text-foreground-muted flex items-center space-x-1">
            <Clock className="w-3 h-3" />
            <span>Time Span</span>
          </div>
          <div className="text-xs font-mono font-semibold text-foreground mt-1 truncate" title={timeSpanString}>
            {timeSpanString}
          </div>
          <div className="text-[10px] font-mono text-foreground-muted mt-0.5">
            {pathData.generated_at ? `Reconstructed ${new Date(pathData.generated_at).toLocaleDateString()}` : 'UTC event timestamps'}
          </div>
        </div>
      </div>
    </div>
  );
};
