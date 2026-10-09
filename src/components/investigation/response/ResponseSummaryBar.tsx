import React from 'react';
import {
  ShieldAlert,
  Clock,
  CheckCircle,
  AlertCircle,
  RefreshCw,
  Server,
  Layers,
} from 'lucide-react';
import type { ResponseWorkspaceOverview, ResponseRecommendation } from '../../../types/response_recommendation';
import { Button } from '../../ui';

interface ResponseSummaryBarProps {
  overview?: ResponseWorkspaceOverview | null;
  recommendations: ResponseRecommendation[];
  loading?: boolean;
  onRefresh?: () => void;
  onOpenCapabilities?: () => void;
  lastUpdated?: string;
}

export const ResponseSummaryBar: React.FC<ResponseSummaryBarProps> = ({
  overview,
  recommendations,
  loading = false,
  onRefresh,
  onOpenCapabilities,
  lastUpdated,
}) => {
  const total = overview?.total_count ?? recommendations.length;
  const requiresApproval =
    overview?.pending_approval_count ??
    recommendations.filter(
      (r) => r.approval_required && (r.status === 'REVIEW_REQUIRED' || r.status === 'GENERATED')
    ).length;

  const approvedCount = recommendations.filter(r => r.status === 'APPROVED').length;
  const unavailableCount = recommendations.filter(r => r.applicability === 'NOT_APPLICABLE').length;
  const criticalCount = recommendations.filter(r => r.priority === 'P0' || r.priority === 'P1').length;

  const formattedTime = lastUpdated
    ? new Date(lastUpdated).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
    : new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

  return (
    <div className="bg-surface border border-border rounded-xl p-4 shadow-xs">
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        {/* Metric Badges */}
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center space-x-2 pr-3 border-r border-border">
            <span className="p-1 rounded bg-primary/10 text-primary">
              <Layers className="w-3.5 h-3.5" />
            </span>
            <div className="font-mono">
              <span className="text-[10px] text-foreground-muted uppercase tracking-wider block">Total</span>
              <span className="text-sm font-bold text-foreground">{total} Recommendations</span>
            </div>
          </div>

          <div className="flex items-center space-x-2 pr-3 border-r border-border">
            <span className="p-1 rounded bg-warning/10 text-warning">
              <Clock className="w-3.5 h-3.5" />
            </span>
            <div className="font-mono">
              <span className="text-[10px] text-foreground-muted uppercase tracking-wider block">Review Required</span>
              <span className="text-sm font-bold text-warning">{requiresApproval} Gated</span>
            </div>
          </div>

          <div className="flex items-center space-x-2 pr-3 border-r border-border">
            <span className="p-1 rounded bg-success/10 text-success">
              <CheckCircle className="w-3.5 h-3.5" />
            </span>
            <div className="font-mono">
              <span className="text-[10px] text-foreground-muted uppercase tracking-wider block">Approved</span>
              <span className="text-sm font-bold text-success">{approvedCount} Ready</span>
            </div>
          </div>

          <div className="flex items-center space-x-2 pr-3 border-r border-border">
            <span className="p-1 rounded bg-danger/10 text-danger">
              <ShieldAlert className="w-3.5 h-3.5" />
            </span>
            <div className="font-mono">
              <span className="text-[10px] text-foreground-muted uppercase tracking-wider block">Urgent Priority</span>
              <span className="text-sm font-bold text-danger">{criticalCount} Critical (P0/P1)</span>
            </div>
          </div>

          {unavailableCount > 0 && (
            <div className="flex items-center space-x-2">
              <span className="p-1 rounded bg-foreground-muted/10 text-foreground-muted">
                <AlertCircle className="w-3.5 h-3.5" />
              </span>
              <div className="font-mono">
                <span className="text-[10px] text-foreground-muted uppercase tracking-wider block">Not Applicable</span>
                <span className="text-sm font-semibold text-foreground-muted">{unavailableCount} Suppressed</span>
              </div>
            </div>
          )}
        </div>

        {/* Action Controls & Timestamps */}
        <div className="flex items-center space-x-3 shrink-0">
          <div className="text-right hidden sm:block font-mono text-[11px] text-foreground-muted">
            <span>Last evaluated: </span>
            <span className="text-foreground font-semibold">{formattedTime} UTC</span>
          </div>

          {onOpenCapabilities && (
            <Button
              variant="outline"
              size="sm"
              onClick={onOpenCapabilities}
              leftIcon={<Server className="w-3.5 h-3.5" />}
              className="font-mono text-xs"
            >
              Capability Registry
            </Button>
          )}

          {onRefresh && (
            <Button
              variant="secondary"
              size="sm"
              onClick={onRefresh}
              disabled={loading}
              leftIcon={<RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />}
              className="font-mono text-xs"
            >
              Re-evaluate
            </Button>
          )}
        </div>
      </div>
    </div>
  );
};
