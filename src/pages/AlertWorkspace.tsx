import React, { useState, useEffect, useCallback } from 'react';
import { useParams, useNavigate, useSearchParams } from 'react-router-dom';
import {
  ShieldAlert,
  Clock,
  Search,
  RefreshCw,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  ExternalLink,
  Radio,
  X,
  Layers,
  GitBranch,
  ArrowRight,
} from 'lucide-react';
import { cn } from '../utils/cn';
import { AlertService } from '../services/alertService';
import { AlertClusterService } from '../services/alertClusterService';
import type { AlertItem, AlertMetrics, AlertSeverity, AlertStatus } from '../types/alert';
import type { AlertClusterItem } from '../types/alertCluster';
import { AlertDetailDrawer } from '../components/alerts/AlertDetailDrawer';
import { AlertClusterDetailModal } from '../components/alerts/AlertClusterDetailModal';
import { useRealtimeSubscription } from '../hooks/useRealtimeSubscription';
import type { RealtimeEvent } from '../types/realtime';

export const AlertWorkspace: React.FC = () => {
  const { id: paramAlertId } = useParams<{ id?: string }>();
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();

  // Mode: Alerts Queue vs Incident Clusters
  const [viewMode, setViewMode] = useState<'ALERTS' | 'CLUSTERS'>('ALERTS');

  // Filters & Pagination State
  const [statusFilter, setStatusFilter] = useState<string>(
    searchParams.get('status') || 'OPEN'
  );
  const [severityFilter, setSeverityFilter] = useState<string>(
    searchParams.get('severity') || 'ALL'
  );
  const [searchQuery, setSearchQuery] = useState<string>(searchParams.get('q') || '');
  const [sortBy, setSortBy] = useState<string>('severity_first');
  const [page, setPage] = useState<number>(0);
  const pageSize = 25;

  // Data State
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [metrics, setMetrics] = useState<AlertMetrics | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [bulkSelected, setBulkSelected] = useState<string[]>([]);
  const [bulkActionLoading, setBulkActionLoading] = useState<boolean>(false);

  // Section 49: Clusters Data State
  const [clusters, setClusters] = useState<AlertClusterItem[]>([]);
  const [clusterTotal, setClusterTotal] = useState<number>(0);
  const [clusterLoading, setClusterLoading] = useState<boolean>(false);
  const [activeClusterId, setActiveClusterId] = useState<string | null>(null);
  const [isClusterModalOpen, setIsClusterModalOpen] = useState<boolean>(false);

  // Detail Drawer State
  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(paramAlertId || null);
  const [isDrawerOpen, setIsDrawerOpen] = useState<boolean>(!!paramAlertId);

  // Sync param alert id
  useEffect(() => {
    if (paramAlertId) {
      setSelectedAlertId(paramAlertId);
      setIsDrawerOpen(true);
    }
  }, [paramAlertId]);

  // Load metrics & alerts
  const loadMetrics = useCallback(async () => {
    try {
      const data = await AlertService.getAlertMetrics();
      setMetrics(data);
    } catch (e) {
      console.warn('Failed to load alert metrics:', e);
    }
  }, []);

  const loadAlerts = useCallback(async () => {
    setLoading(true);
    try {
      const res = await AlertService.getAlerts({
        status: statusFilter === 'ALL' ? undefined : statusFilter,
        severity: severityFilter === 'ALL' ? undefined : severityFilter,
        q: searchQuery.trim() ? searchQuery.trim() : undefined,
        sort_by: sortBy,
        limit: pageSize,
        offset: page * pageSize,
      });
      setAlerts(res.items);
      setTotal(res.total);
    } catch (e) {
      console.error('Failed to load security alerts:', e);
    } finally {
      setLoading(false);
    }
  }, [statusFilter, severityFilter, searchQuery, sortBy, page]);

  const loadClusters = useCallback(async () => {
    setClusterLoading(true);
    try {
      const res = await AlertClusterService.listClusters({
        status: statusFilter === 'ALL' ? undefined : statusFilter,
        severity: severityFilter === 'ALL' ? undefined : severityFilter,
        q: searchQuery.trim() ? searchQuery.trim() : undefined,
        limit: pageSize,
        offset: page * pageSize,
        sort_by: sortBy as any,
      });
      setClusters(res.items);
      setClusterTotal(res.total);
    } catch (e) {
      console.error('Failed to load alert clusters:', e);
    } finally {
      setClusterLoading(false);
    }
  }, [statusFilter, severityFilter, searchQuery, sortBy, page]);

  useEffect(() => {
    loadMetrics();
  }, [loadMetrics]);

  useEffect(() => {
    if (viewMode === 'ALERTS') {
      loadAlerts();
    } else {
      loadClusters();
    }
  }, [viewMode, loadAlerts, loadClusters]);

  // Section 46 real-time update subscription
  const { status: connectionStatus } = useRealtimeSubscription({
    url: '/api/events/stream',
    onEvent: (event: RealtimeEvent) => {
      if (
        [
          'ALERT_STATUS_CHANGED',
          'ALERT_ASSIGNED',
          'ALERT_RESOLVED',
          'ALERT_NOTE_ADDED',
          'ALERT_SUPPRESSED',
          'NOTIFICATION_CREATED',
        ].includes(event.event_type)
      ) {
        loadAlerts();
        loadMetrics();
      }

      if (
        [
          'ALERT_CLUSTER_CREATED',
          'ALERT_CLUSTER_UPDATED',
          'ALERT_ADDED_TO_CLUSTER',
          'ALERT_CLUSTER_MERGED',
          'ALERT_CLUSTER_INVESTIGATION_LINKED',
        ].includes(event.event_type)
      ) {
        loadClusters();
      }
    },
  });

  // Bulk acknowledge handler
  const handleBulkAcknowledge = async () => {
    if (bulkSelected.length === 0) return;
    setBulkActionLoading(true);
    try {
      await AlertService.bulkAcknowledge(bulkSelected, 'SOC Analyst');
      setBulkSelected([]);
      loadAlerts();
      loadMetrics();
    } catch (e: unknown) {
      alert(e instanceof Error ? e.message : 'Bulk acknowledge failed');
    } finally {
      setBulkActionLoading(false);
    }
  };

  const handleRowClick = (item: AlertItem) => {
    setSelectedAlertId(item.id);
    setIsDrawerOpen(true);
  };

  const handleQuickAcknowledge = async (item: AlertItem, e: React.MouseEvent) => {
    e.stopPropagation();
    try {
      const updated = await AlertService.acknowledgeAlert(item.id, {
        analyst_name: 'SOC Analyst',
        note: 'Quick acknowledged from Alert Queue',
      });
      setAlerts((prev) => prev.map((a) => (a.id === item.id ? updated : a)));
      loadMetrics();
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'Failed to acknowledge');
    }
  };

  const handleSelectAll = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.checked) {
      setBulkSelected(alerts.map((a) => a.id));
    } else {
      setBulkSelected([]);
    }
  };

  const handleToggleSelect = (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setBulkSelected((prev) =>
      prev.includes(id) ? prev.filter((i) => i !== id) : [...prev, id]
    );
  };

  const formatTimeAgo = (isoString: string) => {
    try {
      const diffSec = Math.floor((Date.now() - new Date(isoString).getTime()) / 1000);
      if (diffSec < 60) return `${Math.max(1, diffSec)}s ago`;
      const diffMin = Math.floor(diffSec / 60);
      if (diffMin < 60) return `${diffMin}m ago`;
      const diffHours = Math.floor(diffMin / 60);
      if (diffHours < 24) return `${diffHours}h ago`;
      return `${Math.floor(diffHours / 24)}d ago`;
    } catch {
      return 'recently';
    }
  };

  const getSeverityBadge = (sev: AlertSeverity) => {
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

  const getStatusBadge = (status: AlertStatus) => {
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

  const getClusterStatusBadge = (status: string) => {
    switch (status) {
      case 'OPEN':
        return 'bg-threat-critical/15 text-threat-critical border-threat-critical/30';
      case 'INVESTIGATING':
        return 'bg-primary/15 text-primary border-primary/30';
      case 'CONTAINED':
        return 'bg-threat-medium/15 text-threat-medium border-threat-medium/30';
      case 'RESOLVED':
        return 'bg-threat-low/15 text-threat-low border-threat-low/30';
      case 'MERGED':
        return 'bg-surface-secondary text-foreground-muted border-border line-through';
      default:
        return 'bg-surface-secondary text-foreground-muted border-border';
    }
  };

  const currentTotal = viewMode === 'ALERTS' ? total : clusterTotal;
  const totalPages = Math.ceil(currentTotal / pageSize) || 1;

  return (
    <div className="flex-1 flex flex-col min-h-screen bg-background text-foreground select-none">
      {/* 1. Header & Live Connection Status */}
      <div className="px-6 py-5 border-b border-border bg-surface/40 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-md bg-threat-critical/10 border border-threat-critical/30 text-threat-critical">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h1 className="text-lg font-bold font-mono tracking-tight text-foreground">
                  Security Alert Triage Workspace
                </h1>
                <div
                  className={cn(
                    'flex items-center space-x-1.5 px-2 py-0.5 rounded-full text-[10px] font-mono border',
                    connectionStatus === 'CONNECTED'
                      ? 'bg-threat-low/10 text-threat-low border-threat-low/30'
                      : 'bg-threat-high/10 text-threat-high border-threat-high/30'
                  )}
                  title={
                    connectionStatus === 'CONNECTED'
                      ? 'Section 46 Real-time SSE Active'
                      : 'Real-time updates reconnecting'
                  }
                >
                  <Radio className={cn('w-2.5 h-2.5', connectionStatus === 'CONNECTED' && 'animate-pulse')} />
                  <span>{connectionStatus === 'CONNECTED' ? 'Live SSE' : 'Offline'}</span>
                </div>
              </div>
              <p className="text-xs font-mono text-foreground-muted">
                Authoritative security alerts prioritized for acknowledgement, forensic correlation & resolution
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center space-x-3">
          {/* Section 49: Segmented View Switcher */}
          <div className="p-0.5 rounded-lg bg-surface border border-border flex items-center">
            <button
              type="button"
              onClick={() => {
                setViewMode('ALERTS');
                setPage(0);
              }}
              className={cn(
                'px-3 py-1.5 rounded-md text-xs font-mono font-semibold transition-colors cursor-pointer flex items-center space-x-1.5',
                viewMode === 'ALERTS'
                  ? 'bg-primary text-primary-foreground shadow-xs'
                  : 'text-foreground-muted hover:text-foreground'
              )}
            >
              <ShieldAlert className="w-3.5 h-3.5" />
              <span>Alerts Queue</span>
            </button>
            <button
              type="button"
              onClick={() => {
                setViewMode('CLUSTERS');
                setPage(0);
              }}
              className={cn(
                'px-3 py-1.5 rounded-md text-xs font-mono font-semibold transition-colors cursor-pointer flex items-center space-x-1.5',
                viewMode === 'CLUSTERS'
                  ? 'bg-primary text-primary-foreground shadow-xs'
                  : 'text-foreground-muted hover:text-foreground'
              )}
            >
              <Layers className="w-3.5 h-3.5" />
              <span>Incident Clusters</span>
              {clusterTotal > 0 && (
                <span className="px-1.5 py-0.2 text-[10px] rounded bg-white/20 text-white font-mono font-bold">
                  {clusterTotal}
                </span>
              )}
            </button>
          </div>

          <button
            type="button"
            onClick={() => {
              if (viewMode === 'ALERTS') {
                loadAlerts();
              } else {
                loadClusters();
              }
              loadMetrics();
            }}
            disabled={loading || clusterLoading}
            className="px-3 py-1.5 bg-surface border border-border hover:bg-surface-secondary text-foreground-muted hover:text-foreground rounded-md text-xs font-mono flex items-center space-x-1.5 cursor-pointer transition-colors"
          >
            <RefreshCw className={cn('w-3.5 h-3.5', (loading || clusterLoading) && 'animate-spin')} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* 2. Top-level Operational Metrics Banner (Section 36 & 44) */}
      <div className="px-6 py-3 border-b border-border bg-surface/20 grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-3">
        <div className="p-2.5 rounded-md bg-surface border border-border space-y-0.5">
          <span className="text-[10px] font-mono uppercase text-foreground-muted">Total Alerts</span>
          <p className="text-base font-bold font-mono text-foreground">{metrics?.total_alerts ?? '-'}</p>
        </div>
        <div
          onClick={() => {
            setStatusFilter('OPEN');
            setPage(0);
          }}
          className={cn(
            'p-2.5 rounded-md border space-y-0.5 cursor-pointer transition-all',
            statusFilter === 'OPEN'
              ? 'bg-threat-critical/10 border-threat-critical/50 shadow-xs'
              : 'bg-surface border-border hover:border-threat-critical/40'
          )}
        >
          <span className="text-[10px] font-mono uppercase text-threat-critical font-bold">Open</span>
          <p className="text-base font-bold font-mono text-threat-critical">{metrics?.open_count ?? '-'}</p>
        </div>
        <div className="p-2.5 rounded-md bg-surface border border-border space-y-0.5">
          <span className="text-[10px] font-mono uppercase text-threat-critical">Critical Open</span>
          <p className="text-base font-bold font-mono text-threat-critical">{metrics?.critical_open ?? '-'}</p>
        </div>
        <div className="p-2.5 rounded-md bg-surface border border-border space-y-0.5">
          <span className="text-[10px] font-mono uppercase text-threat-high">High Open</span>
          <p className="text-base font-bold font-mono text-threat-high">{metrics?.high_open ?? '-'}</p>
        </div>
        <div className="p-2.5 rounded-md bg-surface border border-border space-y-0.5">
          <span className="text-[10px] font-mono uppercase text-foreground-muted">Unacknowledged</span>
          <p className="text-base font-bold font-mono text-foreground">{metrics?.unacknowledged_count ?? '-'}</p>
        </div>
        <div
          onClick={() => {
            setStatusFilter('INVESTIGATING');
            setPage(0);
          }}
          className={cn(
            'p-2.5 rounded-md border space-y-0.5 cursor-pointer transition-all',
            statusFilter === 'INVESTIGATING'
              ? 'bg-primary/10 border-primary/50 shadow-xs'
              : 'bg-surface border-border hover:border-primary/40'
          )}
        >
          <span className="text-[10px] font-mono uppercase text-primary">Investigating</span>
          <p className="text-base font-bold font-mono text-primary">{metrics?.investigating_count ?? '-'}</p>
        </div>
        <div
          onClick={() => {
            setStatusFilter('RESOLVED');
            setPage(0);
          }}
          className={cn(
            'p-2.5 rounded-md border space-y-0.5 cursor-pointer transition-all',
            statusFilter === 'RESOLVED'
              ? 'bg-threat-low/10 border-threat-low/50 shadow-xs'
              : 'bg-surface border-border hover:border-threat-low/40'
          )}
        >
          <span className="text-[10px] font-mono uppercase text-threat-low">Resolved</span>
          <p className="text-base font-bold font-mono text-threat-low">{metrics?.resolved_count ?? '-'}</p>
        </div>
      </div>

      {/* 3. Triage Toolbar: Search, Filters, Bulk Action */}
      <div className="px-6 py-3 border-b border-border bg-surface/30 flex flex-col lg:flex-row items-stretch lg:items-center justify-between gap-3">
        {/* Status Filters */}
        <div className="flex flex-wrap items-center gap-1.5">
          {(['ALL', 'OPEN', 'ACKNOWLEDGED', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE', 'SUPPRESSED'] as const).map(
            (st) => (
              <button
                key={st}
                type="button"
                onClick={() => {
                  setStatusFilter(st);
                  setPage(0);
                }}
                className={cn(
                  'px-2.5 py-1 rounded text-xs font-mono font-semibold transition-colors cursor-pointer',
                  statusFilter === st
                    ? 'bg-primary text-primary-foreground'
                    : 'text-foreground-muted hover:text-foreground hover:bg-surface-secondary'
                )}
              >
                {st}
              </button>
            )
          )}
        </div>

        {/* Severity, Search, Sort */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Severity selector */}
          <select
            value={severityFilter}
            onChange={(e) => {
              setSeverityFilter(e.target.value);
              setPage(0);
            }}
            className="px-2.5 py-1.5 bg-surface border border-border rounded-md text-xs font-mono text-foreground focus:outline-none focus:border-primary"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>

          {/* Search Box */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-foreground-muted absolute left-2.5 top-2.5" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => {
                setSearchQuery(e.target.value);
                setPage(0);
              }}
              placeholder="Search alerts, indicators, IDs..."
              className="pl-8 pr-3 py-1.5 bg-surface border border-border rounded-md text-xs font-mono text-foreground placeholder:text-foreground-muted/60 focus:outline-none focus:border-primary w-52 sm:w-64"
            />
          </div>

          {/* Sort Selector */}
          <select
            value={sortBy}
            onChange={(e) => {
              setSortBy(e.target.value);
              setPage(0);
            }}
            className="px-2.5 py-1.5 bg-surface border border-border rounded-md text-xs font-mono text-foreground focus:outline-none focus:border-primary"
          >
            <option value="severity_first">Sort: Severity & Recency</option>
            <option value="newest">Sort: Newest First</option>
            <option value="risk_desc">Sort: Risk Score Desc</option>
          </select>
        </div>
      </div>

      {/* 4. Bulk Action Header (if items selected) */}
      {bulkSelected.length > 0 && (
        <div className="px-6 py-2 bg-primary/10 border-b border-primary/20 flex items-center justify-between animate-in fade-in">
          <span className="text-xs font-mono font-bold text-primary">
            {bulkSelected.length} alert{bulkSelected.length > 1 ? 's' : ''} selected
          </span>
          <div className="flex items-center space-x-2">
            <button
              type="button"
              onClick={handleBulkAcknowledge}
              disabled={bulkActionLoading}
              className="px-3 py-1 bg-primary text-primary-foreground rounded text-xs font-mono font-bold hover:bg-primary-hover cursor-pointer transition-colors"
            >
              {bulkActionLoading ? 'Acknowledging...' : 'Acknowledge Selected'}
            </button>
            <button
              type="button"
              onClick={() => setBulkSelected([])}
              className="p-1 text-foreground-muted hover:text-foreground cursor-pointer"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}

      {/* 5. Main Alert Queue / Incident Clusters View */}
      <div className="flex-1 overflow-x-auto p-6">
        {viewMode === 'ALERTS' ? (
          <>
            {loading && alerts.length === 0 ? (
              <div className="py-20 flex flex-col items-center justify-center space-y-3">
                <RefreshCw className="w-6 h-6 text-primary animate-spin" />
                <p className="text-xs font-mono text-foreground-muted">Loading authoritative alerts queue...</p>
              </div>
            ) : alerts.length === 0 ? (
              <div className="py-20 border border-dashed border-border rounded-lg flex flex-col items-center justify-center space-y-2 text-center">
                <CheckCircle2 className="w-8 h-8 text-threat-low" />
                <h3 className="text-sm font-bold font-mono text-foreground">No alerts matching filter</h3>
                <p className="text-xs font-mono text-foreground-muted max-w-sm">
                  CyberGuard has no unresolved security alerts within the selected status and severity scope.
                </p>
              </div>
            ) : (
              <div className="border border-border rounded-lg overflow-hidden bg-surface shadow-xs">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="border-b border-border bg-surface-secondary/60 text-[11px] font-mono text-foreground-muted uppercase tracking-wider">
                      <th className="py-3 px-4 w-10">
                        <input
                          type="checkbox"
                          checked={bulkSelected.length === alerts.length && alerts.length > 0}
                          onChange={handleSelectAll}
                          className="cursor-pointer"
                          title="Select all"
                        />
                      </th>
                      <th className="py-3 px-4 w-28">Severity</th>
                      <th className="py-3 px-4">Alert Title & Evidence Snippet</th>
                      <th className="py-3 px-4 w-24">Risk</th>
                      <th className="py-3 px-4 w-32">Status</th>
                      <th className="py-3 px-4 w-36">Investigation</th>
                      <th className="py-3 px-4 w-28">Created</th>
                      <th className="py-3 px-4 w-24 text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border text-xs font-mono">
                    {alerts.map((item) => {
                      const isSelected = bulkSelected.includes(item.id);
                      const isCurrent = selectedAlertId === item.id;
                      return (
                        <tr
                          key={item.id}
                          onClick={() => handleRowClick(item)}
                          className={cn(
                            'hover:bg-surface-secondary/70 cursor-pointer transition-colors group',
                            isSelected && 'bg-primary/5',
                            isCurrent && 'bg-primary/10'
                          )}
                        >
                          <td className="py-3 px-4" onClick={(e) => handleToggleSelect(item.id, e)}>
                            <input
                              type="checkbox"
                              checked={isSelected}
                              onChange={() => {}}
                              className="cursor-pointer"
                            />
                          </td>

                          <td className="py-3 px-4">
                            <span
                              className={cn(
                                'px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border',
                                getSeverityBadge(item.severity)
                              )}
                            >
                              {item.severity}
                            </span>
                          </td>

                          <td className="py-3 px-4">
                            <div className="space-y-0.5">
                              <p className="font-bold text-foreground group-hover:text-primary transition-colors">
                                {item.title}
                              </p>
                              <p className="text-[11px] text-foreground-muted line-clamp-1">
                                {item.message}
                              </p>
                            </div>
                          </td>

                          <td className="py-3 px-4">
                            <span className="font-bold text-threat-critical">
                              {item.risk_score.toFixed(0)} / 100
                            </span>
                          </td>

                          <td className="py-3 px-4">
                            <span
                              className={cn(
                                'px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border',
                                getStatusBadge(item.status)
                              )}
                            >
                              {item.status}
                            </span>
                          </td>

                          <td className="py-3 px-4">
                            {item.investigation_id ? (
                              <span className="text-primary font-bold hover:underline flex items-center space-x-1">
                                <span className="truncate max-w-[120px]">{item.investigation_id}</span>
                                <ExternalLink className="w-2.5 h-2.5" />
                              </span>
                            ) : (
                              <span className="text-foreground-subtle text-[11px]">—</span>
                            )}
                          </td>

                          <td className="py-3 px-4 text-foreground-muted">
                            <div className="flex items-center space-x-1" title={item.created_at}>
                              <Clock className="w-3 h-3" />
                              <span>{formatTimeAgo(item.created_at)}</span>
                            </div>
                          </td>

                          <td className="py-3 px-4 text-right">
                            {item.status === 'OPEN' ? (
                              <button
                                type="button"
                                onClick={(e) => handleQuickAcknowledge(item, e)}
                                className="px-2.5 py-1 bg-surface border border-border hover:border-primary text-foreground-muted hover:text-foreground rounded text-[10px] font-bold cursor-pointer transition-colors"
                              >
                                Ack
                              </button>
                            ) : (
                              <span className="text-[10px] text-foreground-subtle uppercase">View</span>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </>
        ) : (
          /* SECTION 49: INCIDENT CLUSTERS VIEW */
          <>
            {clusterLoading && clusters.length === 0 ? (
              <div className="py-20 flex flex-col items-center justify-center space-y-3">
                <RefreshCw className="w-6 h-6 text-primary animate-spin" />
                <p className="text-xs font-mono text-foreground-muted">Correlating multi-alert incident clusters...</p>
              </div>
            ) : clusters.length === 0 ? (
              <div className="py-20 border border-dashed border-border rounded-lg flex flex-col items-center justify-center space-y-2 text-center">
                <Layers className="w-8 h-8 text-foreground-muted" />
                <h3 className="text-sm font-bold font-mono text-foreground">No incident clusters matching filter</h3>
                <p className="text-xs font-mono text-foreground-muted max-w-sm">
                  CyberGuard has found no multi-alert correlated security incidents matching the current criteria.
                </p>
              </div>
            ) : (
              <div className="border border-border rounded-lg overflow-hidden bg-surface shadow-xs">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="border-b border-border bg-surface-secondary/60 text-[11px] font-mono text-foreground-muted uppercase tracking-wider">
                      <th className="py-3 px-4 w-32">Cluster ID</th>
                      <th className="py-3 px-4 w-28">Severity</th>
                      <th className="py-3 px-4">Correlated Incident Title & Summary</th>
                      <th className="py-3 px-4 w-24">Risk</th>
                      <th className="py-3 px-4 w-28">Confidence</th>
                      <th className="py-3 px-4 w-28 text-center">Alerts</th>
                      <th className="py-3 px-4 w-32">Status</th>
                      <th className="py-3 px-4 w-36">Investigation</th>
                      <th className="py-3 px-4 w-32">Timespan</th>
                      <th className="py-3 px-4 w-28 text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border text-xs font-mono">
                    {clusters.map((clu) => {
                      const isCurrent = activeClusterId === clu.id;
                      return (
                        <tr
                          key={clu.id}
                          onClick={() => {
                            setActiveClusterId(clu.id);
                            setIsClusterModalOpen(true);
                          }}
                          className={cn(
                            'hover:bg-surface-secondary/70 cursor-pointer transition-colors group',
                            isCurrent && 'bg-primary/10'
                          )}
                        >
                          <td className="py-3 px-4 font-bold text-foreground group-hover:text-primary transition-colors flex items-center space-x-1.5">
                            <Layers className="w-3.5 h-3.5 text-primary shrink-0" />
                            <span>{clu.cluster_number}</span>
                          </td>

                          <td className="py-3 px-4">
                            <span
                              className={cn(
                                'px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border',
                                getSeverityBadge(clu.severity as AlertSeverity)
                              )}
                            >
                              {clu.severity}
                            </span>
                          </td>

                          <td className="py-3 px-4">
                            <div className="space-y-0.5">
                              <p className="font-bold text-foreground group-hover:text-primary transition-colors">
                                {clu.title}
                              </p>
                              {clu.summary && (
                                <p className="text-[11px] text-foreground-muted line-clamp-1">
                                  {clu.summary}
                                </p>
                              )}
                            </div>
                          </td>

                          <td className="py-3 px-4">
                            <span className="font-bold text-threat-critical">
                              {clu.risk_score.toFixed(0)} / 100
                            </span>
                          </td>

                          <td className="py-3 px-4">
                            <span className="font-bold text-primary">
                              {Math.round(clu.confidence * 100)}%
                            </span>
                          </td>

                          <td className="py-3 px-4 text-center">
                            <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded bg-surface-secondary border border-border text-[11px] font-bold text-foreground">
                              <GitBranch className="w-3 h-3 text-primary" />
                              <span>{clu.alert_count}</span>
                            </span>
                          </td>

                          <td className="py-3 px-4">
                            <span
                              className={cn(
                                'px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border',
                                getClusterStatusBadge(clu.status)
                              )}
                            >
                              {clu.status}
                            </span>
                          </td>

                          <td className="py-3 px-4">
                            {clu.investigation_id ? (
                              <span className="text-primary font-bold hover:underline flex items-center space-x-1">
                                <span className="truncate max-w-[120px]">{clu.investigation_id}</span>
                                <ExternalLink className="w-2.5 h-2.5" />
                              </span>
                            ) : (
                              <span className="text-foreground-subtle text-[11px]">—</span>
                            )}
                          </td>

                          <td className="py-3 px-4 text-foreground-muted">
                            <div className="flex items-center space-x-1" title={clu.last_seen}>
                              <Clock className="w-3 h-3" />
                              <span>{formatTimeAgo(clu.last_seen)}</span>
                            </div>
                          </td>

                          <td className="py-3 px-4 text-right">
                            <button
                              type="button"
                              onClick={(e) => {
                                e.stopPropagation();
                                setActiveClusterId(clu.id);
                                setIsClusterModalOpen(true);
                              }}
                              className="px-2.5 py-1 bg-surface border border-border hover:border-primary text-foreground-muted hover:text-foreground rounded text-[10px] font-bold cursor-pointer transition-colors flex items-center space-x-1 ml-auto"
                            >
                              <span>Inspect</span>
                              <ArrowRight className="w-3 h-3 text-primary" />
                            </button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </>
        )}

        {/* 6. Pagination Footer */}
        {currentTotal > pageSize && (
          <div className="mt-4 flex items-center justify-between text-xs font-mono text-foreground-muted">
            <span>
              Showing {page * pageSize + 1}–{Math.min((page + 1) * pageSize, currentTotal)} of {currentTotal} {viewMode === 'ALERTS' ? 'alerts' : 'clusters'}
            </span>
            <div className="flex items-center space-x-2">
              <button
                type="button"
                disabled={page === 0}
                onClick={() => setPage((p) => Math.max(0, p - 1))}
                className="p-1.5 rounded bg-surface border border-border disabled:opacity-40 hover:bg-surface-secondary cursor-pointer"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>
              <span>
                Page {page + 1} of {totalPages}
              </span>
              <button
                type="button"
                disabled={page + 1 >= totalPages}
                onClick={() => setPage((p) => p + 1)}
                className="p-1.5 rounded bg-surface border border-border disabled:opacity-40 hover:bg-surface-secondary cursor-pointer"
              >
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}
      </div>

      {/* 7. Detailed Forensic Triage Drawer */}
      <AlertDetailDrawer
        alertId={selectedAlertId}
        isOpen={isDrawerOpen}
        onClose={() => {
          setIsDrawerOpen(false);
          setSelectedAlertId(null);
          if (paramAlertId) {
            navigate('/alerts');
          }
        }}
        onAlertUpdated={(updated) => {
          setAlerts((prev) => prev.map((a) => (a.id === updated.id ? updated : a)));
          loadMetrics();
        }}
      />

      {/* 8. Section 49: Alert Cluster Forensic Modal */}
      <AlertClusterDetailModal
        clusterId={activeClusterId}
        isOpen={isClusterModalOpen}
        onClose={() => {
          setIsClusterModalOpen(false);
          setActiveClusterId(null);
        }}
        onClusterUpdated={() => {
          loadClusters();
          loadAlerts();
        }}
        onSelectAlert={(alertId) => {
          setIsClusterModalOpen(false);
          setSelectedAlertId(alertId);
          setIsDrawerOpen(true);
        }}
      />
    </div>
  );
};
