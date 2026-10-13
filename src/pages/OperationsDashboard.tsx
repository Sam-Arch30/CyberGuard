import React, { useState, useEffect, useCallback, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ShieldAlert,
  ShieldCheck,
  RefreshCw,
  Activity,
  Layers,
  Server,
  Terminal,
  ChevronRight,
  FileCheck2,
  AlertTriangle,
  Clock,
  Globe,
  Radio,
  Flame,
  CheckCircle2,
  XCircle,
  ExternalLink,
} from 'lucide-react';
import { UniversalDropZone } from '../components/dashboard/UniversalDropZone';
import {
  Button,
} from '../components/ui';
import {
  SeverityIndicator,
  Timestamp,
  RiskBadge,
} from '../components/security';
import { useInvestigation } from '../context/InvestigationContext';
import { SocOverviewService } from '../services/socOverviewService';
import type {
  SocOverviewResponse,
  SocPriorityQueueItem,
} from '../types/socOverview';
import { IndicatorDetailDrawer } from '../components/search';
import { RealtimeService } from '../services/realtimeService';
import type { RealtimeConnectionStatus } from '../types/realtime';
import { NotificationClientService } from '../services/notificationService';

export const OperationsDashboard: React.FC = () => {
  const navigate = useNavigate();
  const { setActiveEmailId } = useInvestigation();

  // State
  const [timeWindow, setTimeWindow] = useState<'24h' | '7d' | '30d' | 'all'>('30d');
  const [data, setData] = useState<SocOverviewResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [refreshing, setRefreshing] = useState<boolean>(false);
  const [lastUpdated, setLastUpdated] = useState<Date>(new Date());
  const [secondsAgo, setSecondsAgo] = useState<number>(0);
  const [selectedIndicator, setSelectedIndicator] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [connectionStatus, setConnectionStatus] = useState<RealtimeConnectionStatus>('DISCONNECTED');
  const [unreadAlertsCount, setUnreadAlertsCount] = useState<number>(0);

  // Interval timer ref
  const timerRef = useRef<any>(null);
  const debounceTimerRef = useRef<any>(null);

  // Fetch SOC Overview data from authoritative backend aggregation
  const fetchSocData = useCallback(async (isManualRefresh: boolean = false) => {
    if (isManualRefresh) setRefreshing(true);
    try {
      setError(null);
      const res = await SocOverviewService.getOverview(timeWindow, 'default');
      setData(res);
      try {
        const notifCounts = await NotificationClientService.getUnreadCount();
        setUnreadAlertsCount(notifCounts.alerts_unread);
      } catch {
        // Suppress notification counter errors
      }
      setLastUpdated(new Date());
      setSecondsAgo(0);
    } catch (err: any) {
      console.error('Failed to load SOC Overview telemetry:', err);
      setError(err.message || 'Failed to connect to backend telemetry service');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [timeWindow]);

  // Initial load and timeWindow changes
  useEffect(() => {
    fetchSocData(false);
  }, [fetchSocData]);

  // Section 46: Real-time SOC dashboard stream updates
  useEffect(() => {
    const unsubscribe = RealtimeService.subscribe({
      url: `/api/dashboard/stream`,
      onEvent: () => {
        // Debounce refresh to avoid request flooding across rapid multi-worker events
        if (debounceTimerRef.current) clearTimeout(debounceTimerRef.current);
        debounceTimerRef.current = setTimeout(() => {
          fetchSocData(false);
        }, 1500);
      },
      onStatusChange: (status) => setConnectionStatus(status),
      onAuthoritativeRefetch: () => {
        fetchSocData(false);
      },
    });

    return () => {
      unsubscribe();
      if (debounceTimerRef.current) clearTimeout(debounceTimerRef.current);
    };
  }, [fetchSocData]);

  // Periodic fallback polling (30s) that respects document visibility
  useEffect(() => {
    const handleVisibilityChange = () => {
      if (document.visibilityState === 'visible') {
        fetchSocData(false);
      }
    };

    document.addEventListener('visibilitychange', handleVisibilityChange);

    timerRef.current = setInterval(() => {
      if (document.visibilityState === 'visible') {
        fetchSocData(false);
      }
    }, 30000);

    return () => {
      document.removeEventListener('visibilitychange', handleVisibilityChange);
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [fetchSocData]);

  // Freshness seconds counter
  useEffect(() => {
    const secTimer = setInterval(() => {
      setSecondsAgo((prev) => prev + 1);
    }, 1000);
    return () => clearInterval(secTimer);
  }, []);

  const handleManualRefresh = () => {
    fetchSocData(true);
  };

  const handleOpenItem = (item: SocPriorityQueueItem) => {
    if (item.investigation_id) {
      setActiveEmailId(item.investigation_id);
    }
    if (item.navigation_target) {
      navigate(item.navigation_target);
    } else if (item.investigation_id) {
      navigate(`/investigations/${item.investigation_id}/overview`);
    }
  };

  // Safe destructuring with truthful fallbacks
  const posture = data?.posture || {
    active_investigations: 0,
    high_risk_open: 0,
    pending_response_approvals: 0,
    failed_analysis_jobs: 0,
    new_findings_count: 0,
    active_endpoint_agents: 0,
    total_investigations: 0,
  };

  const riskDist = data?.risk_distribution || {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    safe: 0,
    total: 0,
  };

  const priorityQueue = data?.priority_queue || [];
  const activity = data?.recent_activity || [];
  const threatIntel = data?.threat_intel || [];
  const campaigns = data?.active_campaigns || [];
  const systemHealth = data?.system_health || {
    status: 'operational',
    api_status: 'healthy',
    database_status: 'connected',
    analysis_engine_status: 'operational',
    active_tasks: 0,
    failed_tasks: 0,
  };

  const fleet = systemHealth.endpoint_fleet;

  return (
    <div className="max-w-7xl w-full mx-auto py-6 px-4 sm:px-6 space-y-7 animate-fadeIn page-enter">
      {/* =========================================================================
          1. HEADER: SOC Operational Command Bar
          ========================================================================= */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-border/80">
        <div>
          <div className="flex items-center space-x-2 text-primary font-mono text-xs font-semibold uppercase tracking-wider">
            <Activity className="w-3.5 h-3.5 text-primary" />
            <span>SECURITY OPERATIONS CENTER</span>
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-foreground font-sans mt-0.5">
            SOC Overview
          </h1>
          <p className="text-xs text-foreground-muted font-mono mt-1">
            Authoritative operational security workstation, prioritized threat queue, and real-time fleet health.
          </p>
        </div>

        {/* Operational Controls: Time Window, Freshness, Refresh */}
        <div className="flex flex-wrap items-center gap-2.5">
          {/* Time Window Selector */}
          <div className="flex items-center space-x-1 p-0.5 rounded-lg bg-surface border border-border text-xs font-mono">
            {(['24h', '7d', '30d', 'all'] as const).map((tw) => (
              <button
                key={tw}
                type="button"
                onClick={() => setTimeWindow(tw)}
                className={`px-2.5 py-1 rounded-md transition-colors cursor-pointer uppercase ${
                  timeWindow === tw
                    ? 'bg-primary/15 text-primary font-bold'
                    : 'text-foreground-muted hover:text-foreground'
                }`}
              >
                {tw}
              </button>
            ))}
          </div>

          {/* Freshness & Live Transport Indicator */}
          <div
            className="flex items-center space-x-1.5 px-2.5 py-1 rounded-md bg-surface border border-border text-[11px] font-mono text-foreground-muted"
            title={`Real-time Stream: ${connectionStatus} · Last synchronized at ${lastUpdated.toLocaleTimeString()}`}
          >
            {connectionStatus === 'CONNECTED' ? (
              <>
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
                <span className="text-foreground">● Live Stream</span>
              </>
            ) : connectionStatus === 'RECONNECTING' ? (
              <>
                <RefreshCw className="w-2.5 h-2.5 text-warning animate-spin" />
                <span className="text-warning">Reconnecting</span>
              </>
            ) : connectionStatus === 'FALLBACK_POLLING' ? (
              <>
                <span className="w-1.5 h-1.5 rounded-full bg-info" />
                <span>⚡ Polling ({secondsAgo}s ago)</span>
              </>
            ) : (
              <>
                <span className="w-1.5 h-1.5 rounded-full bg-foreground-muted/40" />
                <span>{secondsAgo < 5 ? 'Sync' : `${secondsAgo}s ago`}</span>
              </>
            )}
            <span className="hidden sm:inline opacity-60">({lastUpdated.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })})</span>
          </div>

          {/* Section 47: Unread Security Alerts Pill */}
          {unreadAlertsCount > 0 && (
            <div
              className="flex items-center space-x-1 px-2.5 py-1 rounded-md bg-threat-critical/15 text-threat-critical border border-threat-critical/30 text-[11px] font-mono font-bold animate-pulse"
              title={`${unreadAlertsCount} unread security alert(s) requiring analyst attention`}
            >
              <ShieldAlert className="w-3.5 h-3.5" />
              <span>{unreadAlertsCount} Alert{unreadAlertsCount > 1 ? 's' : ''}</span>
            </div>
          )}

          {/* Refresh Button */}
          <Button
            variant="secondary"
            size="sm"
            onClick={handleManualRefresh}
            disabled={refreshing || loading}
            leftIcon={<RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin text-primary' : ''}`} />}
          >
            Refresh
          </Button>

          {/* Jump to Investigations */}
          <Button
            variant="secondary"
            size="sm"
            onClick={() => navigate('/investigations')}
            leftIcon={<Layers className="w-3.5 h-3.5 text-foreground-muted" />}
          >
            Investigations
          </Button>
        </div>
      </div>

      {/* Error banner if backend failed */}
      {error && (
        <div className="p-3.5 rounded-card bg-danger-surface border border-danger-border text-danger text-xs font-mono flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span><strong>Backend Telemetry Warning:</strong> {error}</span>
          </div>
          <Button variant="secondary" size="xs" onClick={handleManualRefresh}>
            Retry
          </Button>
        </div>
      )}

      {/* =========================================================================
          2. SECURITY POSTURE METRICS (Compact, Truthful Workload Cards)
          ========================================================================= */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        {/* Active Investigations */}
        <div
          onClick={() => navigate('/investigations?status=OPEN&status=INVESTIGATING')}
          className="p-3.5 rounded-card bg-surface border border-border hover:border-primary/50 transition-colors cursor-pointer shadow-xs flex flex-col justify-between"
          title="Click to view all active investigations"
        >
          <div className="flex items-center justify-between text-foreground-muted">
            <span className="text-[10px] font-mono uppercase tracking-wider font-semibold">Active Cases</span>
            <FileCheck2 className="w-3.5 h-3.5 text-primary" />
          </div>
          <div className="mt-2 flex items-baseline space-x-1.5">
            <span className="text-xl font-bold font-mono text-foreground">
              {posture.active_investigations}
            </span>
            <span className="text-[10px] font-mono text-foreground-muted">open</span>
          </div>
        </div>

        {/* Critical & High Risk */}
        <div
          onClick={() => navigate('/investigations?risk=HIGH&risk=CRITICAL')}
          className="p-3.5 rounded-card bg-surface border border-border hover:border-rose-500/50 transition-colors cursor-pointer shadow-xs flex flex-col justify-between"
          title="Click to filter critical and high risk threats"
        >
          <div className="flex items-center justify-between text-foreground-muted">
            <span className="text-[10px] font-mono uppercase tracking-wider font-semibold">High / Critical</span>
            <ShieldAlert className="w-3.5 h-3.5 text-rose-500" />
          </div>
          <div className="mt-2 flex items-baseline space-x-1.5">
            <span className="text-xl font-bold font-mono text-rose-500">
              {posture.high_risk_open}
            </span>
            <span className="text-[10px] font-mono text-foreground-muted">threats</span>
          </div>
        </div>

        {/* Pending Response Approvals */}
        <div
          onClick={() => navigate('/investigations')}
          className="p-3.5 rounded-card bg-surface border border-border hover:border-warning/50 transition-colors cursor-pointer shadow-xs flex flex-col justify-between"
          title="Defensive recommendations awaiting human review"
        >
          <div className="flex items-center justify-between text-foreground-muted">
            <span className="text-[10px] font-mono uppercase tracking-wider font-semibold">Approvals</span>
            <Flame className="w-3.5 h-3.5 text-amber-500" />
          </div>
          <div className="mt-2 flex items-baseline space-x-1.5">
            <span className="text-xl font-bold font-mono text-amber-500">
              {posture.pending_response_approvals}
            </span>
            <span className="text-[10px] font-mono text-foreground-muted">pending</span>
          </div>
        </div>

        {/* New Findings */}
        <div className="p-3.5 rounded-card bg-surface border border-border shadow-xs flex flex-col justify-between">
          <div className="flex items-center justify-between text-foreground-muted">
            <span className="text-[10px] font-mono uppercase tracking-wider font-semibold">New Findings</span>
            <ShieldCheck className="w-3.5 h-3.5 text-success" />
          </div>
          <div className="mt-2 flex items-baseline space-x-1.5">
            <span className="text-xl font-bold font-mono text-foreground">
              {posture.new_findings_count}
            </span>
            <span className="text-[10px] font-mono text-foreground-muted">in window</span>
          </div>
        </div>

        {/* Endpoint Fleet */}
        <div className="p-3.5 rounded-card bg-surface border border-border shadow-xs flex flex-col justify-between">
          <div className="flex items-center justify-between text-foreground-muted">
            <span className="text-[10px] font-mono uppercase tracking-wider font-semibold">Fleet Agents</span>
            <Terminal className="w-3.5 h-3.5 text-foreground-muted" />
          </div>
          <div className="mt-2 flex items-baseline space-x-1.5">
            <span className="text-xl font-bold font-mono text-foreground">
              {fleet ? fleet.active : posture.active_endpoint_agents}
            </span>
            <span className="text-[10px] font-mono text-foreground-muted">
              / {fleet ? fleet.enrolled : posture.active_endpoint_agents} active
            </span>
          </div>
        </div>

        {/* Analysis Engine Health */}
        <div className="p-3.5 rounded-card bg-surface border border-border shadow-xs flex flex-col justify-between">
          <div className="flex items-center justify-between text-foreground-muted">
            <span className="text-[10px] font-mono uppercase tracking-wider font-semibold">Engine Health</span>
            <Server className="w-3.5 h-3.5 text-foreground-muted" />
          </div>
          <div className="mt-2 flex items-center space-x-1.5">
            <span
              className={`w-2 h-2 rounded-full ${
                systemHealth.status === 'operational'
                  ? 'bg-emerald-500'
                  : systemHealth.status === 'degraded'
                  ? 'bg-amber-500'
                  : 'bg-rose-500'
              }`}
            />
            <span className="text-xs font-bold font-mono text-foreground capitalize">
              {systemHealth.status}
            </span>
            {posture.failed_analysis_jobs > 0 && (
              <span className="text-[10px] font-mono text-danger">({posture.failed_analysis_jobs} failed)</span>
            )}
          </div>
        </div>
      </div>

      {/* =========================================================================
          2B. SECTION 51: INCIDENT SLA & ESCALATION POSTURE RIBBON
          ========================================================================= */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
        <div
          onClick={() => navigate('/incidents?sla_status=BREACHED')}
          className="p-3 rounded-card bg-surface border border-red-500/30 hover:border-red-500/60 transition-colors cursor-pointer shadow-xs flex flex-col justify-between"
          title="Click to view all incidents with breached SLA targets"
        >
          <div className="flex items-center justify-between text-red-400">
            <span className="text-[10px] font-mono uppercase tracking-wider font-bold">SLA Breaches</span>
            <AlertTriangle className="w-3.5 h-3.5" />
          </div>
          <div className="mt-1 flex items-baseline space-x-1.5">
            <span className="text-xl font-bold font-mono text-red-400">
              {posture.sla_breaches ?? 0}
            </span>
            <span className="text-[10px] font-mono text-foreground-muted">overdue</span>
          </div>
        </div>

        <div
          onClick={() => navigate('/incidents?sla_status=WARNING')}
          className="p-3 rounded-card bg-surface border border-amber-500/30 hover:border-amber-500/60 transition-colors cursor-pointer shadow-xs flex flex-col justify-between"
          title="Click to view incidents approaching SLA warning threshold"
        >
          <div className="flex items-center justify-between text-amber-400">
            <span className="text-[10px] font-mono uppercase tracking-wider font-bold">Approaching SLA</span>
            <Clock className="w-3.5 h-3.5" />
          </div>
          <div className="mt-1 flex items-baseline space-x-1.5">
            <span className="text-xl font-bold font-mono text-amber-400">
              {posture.approaching_sla ?? 0}
            </span>
            <span className="text-[10px] font-mono text-foreground-muted">at risk</span>
          </div>
        </div>

        <div
          onClick={() => navigate('/incidents?severity=CRITICAL&status=OPEN')}
          className="p-3 rounded-card bg-surface border border-border hover:border-primary/50 transition-colors cursor-pointer shadow-xs flex flex-col justify-between"
          title="Unacknowledged critical cases requiring immediate triage"
        >
          <div className="flex items-center justify-between text-foreground-muted">
            <span className="text-[10px] font-mono uppercase tracking-wider font-semibold">Unacked Critical</span>
            <ShieldAlert className="w-3.5 h-3.5 text-danger" />
          </div>
          <div className="mt-1 flex items-baseline space-x-1.5">
            <span className="text-xl font-bold font-mono text-danger">
              {posture.unacknowledged_critical ?? 0}
            </span>
            <span className="text-[10px] font-mono text-foreground-muted">cases</span>
          </div>
        </div>

        <div
          onClick={() => navigate('/incidents')}
          className="p-3 rounded-card bg-surface border border-border hover:border-rose-500/50 transition-colors cursor-pointer shadow-xs flex flex-col justify-between"
          title="Active escalated incidents (Tier 2 / Lead)"
        >
          <div className="flex items-center justify-between text-foreground-muted">
            <span className="text-[10px] font-mono uppercase tracking-wider font-semibold">Escalated Cases</span>
            <Flame className="w-3.5 h-3.5 text-rose-400" />
          </div>
          <div className="mt-1 flex items-baseline space-x-1.5">
            <span className="text-xl font-bold font-mono text-rose-400">
              {posture.escalated_incidents ?? 0}
            </span>
            <span className="text-[10px] font-mono text-foreground-muted">tier 2+</span>
          </div>
        </div>

        <div
          onClick={() => navigate('/incidents?severity=CRITICAL')}
          className="p-3 rounded-card bg-surface border border-border hover:border-warning/50 transition-colors cursor-pointer shadow-xs flex flex-col justify-between"
          title="Unassigned critical incidents"
        >
          <div className="flex items-center justify-between text-foreground-muted">
            <span className="text-[10px] font-mono uppercase tracking-wider font-semibold">Unassigned Critical</span>
            <Activity className="w-3.5 h-3.5 text-amber-500" />
          </div>
          <div className="mt-1 flex items-baseline space-x-1.5">
            <span className="text-xl font-bold font-mono text-amber-500">
              {posture.unassigned_critical ?? 0}
            </span>
            <span className="text-[10px] font-mono text-foreground-muted">urgent</span>
          </div>
        </div>
      </div>

      {/* =========================================================================
          3. OPERATIONAL CORE: PRIORITY QUEUE & RISK DISTRIBUTION
          ========================================================================= */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column (2 Cols): Priority Queue */}
        <div className="lg:col-span-2 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <h2 className="text-xs font-mono font-semibold uppercase tracking-wider text-foreground-muted">
                Priority Queue
              </h2>
              {priorityQueue.length > 0 && (
                <span className="text-[10px] px-1.5 py-0.2 rounded bg-primary/10 text-primary font-mono font-bold">
                  {priorityQueue.length} ACTIONABLE
                </span>
              )}
            </div>
            <div className="flex items-center space-x-3">
              <button
                type="button"
                onClick={() => navigate('/alerts')}
                className="text-primary hover:underline text-[11px] font-mono font-bold flex items-center space-x-1 cursor-pointer"
              >
                <span>Alert Triage</span>
                <ChevronRight className="w-3 h-3" />
              </button>
              <span className="text-[11px] font-mono text-foreground-muted">
                Ranked by Urgency &amp; Risk
              </span>
            </div>
          </div>

          {priorityQueue.length === 0 ? (
            <div className="p-8 rounded-card bg-surface border border-border text-center space-y-2">
              <ShieldCheck className="w-8 h-8 text-emerald-500 mx-auto" />
              <h4 className="text-xs font-semibold font-mono text-foreground">Priority Queue Clear</h4>
              <p className="text-[11px] font-mono text-foreground-muted max-w-sm mx-auto">
                No unresolved critical threats, failed jobs, or pending response actions require immediate analyst triage.
              </p>
            </div>
          ) : (
            <div className="space-y-2.5">
              {priorityQueue.map((item) => {
                const urgencyBg =
                  item.urgency === 'P0'
                    ? 'bg-rose-500/15 text-rose-500 border-rose-500/30'
                    : item.urgency === 'P1'
                    ? 'bg-amber-500/15 text-amber-500 border-amber-500/30'
                    : 'bg-primary/15 text-primary border-primary/30';

                return (
                  <div
                    key={`${item.resource_type}-${item.id}`}
                    onClick={() => handleOpenItem(item)}
                    className="p-3.5 rounded-card bg-surface border border-border hover:border-primary/50 transition-all cursor-pointer group flex flex-col justify-between space-y-2.5 shadow-xs"
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div className="space-y-1 min-w-0 flex-1">
                        <div className="flex items-center space-x-2">
                          <span className={`text-[10px] font-mono font-bold px-1.5 py-0.2 rounded border ${urgencyBg}`}>
                            {item.urgency}
                          </span>
                          <span className="text-[10px] font-mono text-foreground-muted uppercase">
                            {item.resource_type}
                          </span>
                          <SeverityIndicator severity={item.severity} size="xs" showText />

                          {item.sla_status === 'BREACHED' && (
                            <span className="text-[10px] font-mono font-bold px-1.5 py-0.2 rounded bg-red-500/20 text-red-400 border border-red-500/40 flex items-center space-x-1">
                              <AlertTriangle className="w-2.5 h-2.5" />
                              <span>SLA BREACH</span>
                            </span>
                          )}

                          {item.sla_status === 'WARNING' && (
                            <span className="text-[10px] font-mono font-bold px-1.5 py-0.2 rounded bg-amber-500/20 text-amber-400 border border-amber-500/40 flex items-center space-x-1">
                              <Clock className="w-2.5 h-2.5" />
                              <span>SLA WARNING ({item.sla_remaining_minutes}m left)</span>
                            </span>
                          )}

                          {item.escalation_level && item.escalation_level > 1 && (
                            <span className="text-[9px] font-mono font-bold px-1 py-0.2 rounded bg-rose-500/20 text-rose-400 border border-rose-500/40">
                              L{item.escalation_level} ESCALATED
                            </span>
                          )}
                        </div>
                        <h3 className="text-xs font-semibold text-foreground group-hover:text-primary transition-colors truncate">
                          {item.title}
                        </h3>
                        <p className="text-[11px] font-mono text-foreground-muted">
                          {item.reason_for_inclusion}
                        </p>
                      </div>

                      <div className="shrink-0 flex flex-col items-end space-y-1">
                        <RiskBadge score={item.risk_score} severity={item.severity} size="xs" variant="minimal" />
                        <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-surface-secondary text-foreground-muted uppercase border border-border">
                          {item.status}
                        </span>
                      </div>
                    </div>

                    <div className="flex items-center justify-between text-[10px] font-mono text-foreground-muted pt-2 border-t border-border/50">
                      <div className="flex items-center space-x-1.5">
                        <Clock className="w-3 h-3 text-foreground-muted" />
                        <Timestamp date={item.updated_at} format="relative" />
                      </div>
                      <span className="text-primary flex items-center space-x-1 group-hover:translate-x-0.5 transition-transform font-bold">
                        <span>Triage</span>
                        <ChevronRight className="w-3 h-3" />
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Right Column (1 Col): Risk Distribution & System Health */}
        <div className="space-y-6">
          {/* Risk Distribution Card */}
          <div className="p-4 rounded-card bg-surface border border-border shadow-xs space-y-3.5">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-foreground-muted">
                Risk Distribution
              </h3>
              <span className="text-[10px] font-mono text-foreground-muted">
                {riskDist.total} evaluated
              </span>
            </div>

            {riskDist.total === 0 ? (
              <p className="text-xs font-mono text-foreground-muted py-2">
                No risk-scored records in current database scope.
              </p>
            ) : (
              <div className="space-y-2 text-xs font-mono">
                {/* Critical */}
                <div>
                  <div className="flex justify-between text-[11px] mb-0.5">
                    <span className="text-rose-500 font-semibold">Critical (80-100)</span>
                    <span className="font-bold text-foreground">{riskDist.critical}</span>
                  </div>
                  <div className="h-1.5 w-full bg-surface-secondary rounded-full overflow-hidden">
                    <div
                      className="h-full bg-rose-500 rounded-full transition-all"
                      style={{ width: `${(riskDist.critical / Math.max(1, riskDist.total)) * 100}%` }}
                    />
                  </div>
                </div>

                {/* High */}
                <div>
                  <div className="flex justify-between text-[11px] mb-0.5">
                    <span className="text-amber-500 font-semibold">High (60-79)</span>
                    <span className="font-bold text-foreground">{riskDist.high}</span>
                  </div>
                  <div className="h-1.5 w-full bg-surface-secondary rounded-full overflow-hidden">
                    <div
                      className="h-full bg-amber-500 rounded-full transition-all"
                      style={{ width: `${(riskDist.high / Math.max(1, riskDist.total)) * 100}%` }}
                    />
                  </div>
                </div>

                {/* Medium */}
                <div>
                  <div className="flex justify-between text-[11px] mb-0.5">
                    <span className="text-yellow-500 font-semibold">Medium (40-59)</span>
                    <span className="font-bold text-foreground">{riskDist.medium}</span>
                  </div>
                  <div className="h-1.5 w-full bg-surface-secondary rounded-full overflow-hidden">
                    <div
                      className="h-full bg-yellow-500 rounded-full transition-all"
                      style={{ width: `${(riskDist.medium / Math.max(1, riskDist.total)) * 100}%` }}
                    />
                  </div>
                </div>

                {/* Low */}
                <div>
                  <div className="flex justify-between text-[11px] mb-0.5">
                    <span className="text-blue-500 font-semibold">Low (20-39)</span>
                    <span className="font-bold text-foreground">{riskDist.low}</span>
                  </div>
                  <div className="h-1.5 w-full bg-surface-secondary rounded-full overflow-hidden">
                    <div
                      className="h-full bg-blue-500 rounded-full transition-all"
                      style={{ width: `${(riskDist.low / Math.max(1, riskDist.total)) * 100}%` }}
                    />
                  </div>
                </div>

                {/* Safe */}
                <div>
                  <div className="flex justify-between text-[11px] mb-0.5">
                    <span className="text-emerald-500 font-semibold">Safe (0-19)</span>
                    <span className="font-bold text-foreground">{riskDist.safe}</span>
                  </div>
                  <div className="h-1.5 w-full bg-surface-secondary rounded-full overflow-hidden">
                    <div
                      className="h-full bg-emerald-500 rounded-full transition-all"
                      style={{ width: `${(riskDist.safe / Math.max(1, riskDist.total)) * 100}%` }}
                    />
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* System & Fleet Health Card */}
          <div className="p-4 rounded-card bg-surface border border-border shadow-xs space-y-3">
            <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-foreground-muted">
              Subsystem Operations
            </h3>

            <div className="space-y-2 text-xs font-mono">
              <div className="flex items-center justify-between py-1 border-b border-border/50">
                <span className="text-foreground-muted">Core Database</span>
                <span className={`font-bold capitalize flex items-center space-x-1 ${systemHealth.database_status === 'connected' ? 'text-success' : 'text-danger'}`}>
                  {systemHealth.database_status === 'connected' ? <CheckCircle2 className="w-3 h-3" /> : <XCircle className="w-3 h-3" />}
                  <span>{systemHealth.database_status}</span>
                </span>
              </div>

              <div className="flex items-center justify-between py-1 border-b border-border/50">
                <span className="text-foreground-muted">API Routes</span>
                <span className="text-success font-bold capitalize flex items-center space-x-1">
                  <CheckCircle2 className="w-3 h-3" />
                  <span>{systemHealth.api_status}</span>
                </span>
              </div>

              <div className="flex items-center justify-between py-1 border-b border-border/50">
                <span className="text-foreground-muted">Analysis Engine</span>
                <span className="font-bold text-foreground capitalize">
                  {systemHealth.analysis_engine_status} ({systemHealth.active_tasks} active)
                </span>
              </div>

              {fleet && (
                <div className="pt-1 space-y-1">
                  <span className="text-[10px] uppercase text-foreground-muted font-bold block">Endpoint Fleet</span>
                  <div className="grid grid-cols-3 gap-1.5 text-[11px] text-center">
                    <div className="p-1.5 rounded bg-surface-secondary">
                      <span className="text-[10px] text-foreground-muted block">Online</span>
                      <strong className="text-success">{fleet.active}</strong>
                    </div>
                    <div className="p-1.5 rounded bg-surface-secondary">
                      <span className="text-[10px] text-foreground-muted block">Degraded</span>
                      <strong className={fleet.degraded > 0 ? 'text-warning' : 'text-foreground'}>{fleet.degraded}</strong>
                    </div>
                    <div className="p-1.5 rounded bg-surface-secondary">
                      <span className="text-[10px] text-foreground-muted block">Revoked</span>
                      <strong className="text-foreground-muted">{fleet.revoked}</strong>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* =========================================================================
          3B. SECTION 64: RISK-BASED ASSET PRIORITIZATION — HIGHEST PRIORITY ASSETS
          ========================================================================= */}
      <section className="space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <h2 className="text-xs font-mono font-semibold uppercase tracking-wider text-foreground-muted flex items-center gap-1.5">
              <Flame className="w-3.5 h-3.5 text-amber-500" />
              <span>Highest Priority Assets (Section 64)</span>
            </h2>
            {data?.highest_priority_assets && data.highest_priority_assets.length > 0 && (
              <span className="text-[10px] px-1.5 py-0.2 rounded bg-amber-500/10 text-amber-400 font-mono font-bold">
                {data.highest_priority_assets.length} ASSETS REQUIRE ATTENTION
              </span>
            )}
          </div>
          <button
            type="button"
            onClick={() => navigate('/assets')}
            className="text-primary hover:underline text-[11px] font-mono font-bold flex items-center space-x-1 cursor-pointer"
          >
            <span>Asset Inventory</span>
            <ChevronRight className="w-3 h-3" />
          </button>
        </div>

        {(!data?.highest_priority_assets || data.highest_priority_assets.length === 0) ? (
          <div className="p-4 rounded-card bg-surface border border-border text-center text-xs font-mono text-foreground-muted">
            No critical or high priority assets currently require immediate operational intervention.
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
            {data.highest_priority_assets.slice(0, 4).map((asset) => {
              const pBand = asset.effective_priority || 'P4';
              const pBg =
                pBand === 'P1'
                  ? 'bg-rose-500/15 text-rose-400 border-rose-500/30'
                  : pBand === 'P2'
                  ? 'bg-amber-500/15 text-amber-400 border-amber-500/30'
                  : pBand === 'P3'
                  ? 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30'
                  : 'bg-blue-500/15 text-blue-400 border-blue-500/30';

              return (
                <div
                  key={asset.id}
                  onClick={() => navigate(`/assets?id=${asset.id}`)}
                  className="p-3.5 rounded-card bg-surface border border-border hover:border-primary/50 transition-all cursor-pointer group flex flex-col justify-between space-y-2.5 shadow-xs"
                >
                  <div className="space-y-1.5 min-w-0">
                    <div className="flex items-center justify-between">
                      <span className={`text-[10px] font-mono font-bold px-1.5 py-0.2 rounded border ${pBg}`}>
                        {pBand} • {asset.priority_score?.toFixed(1) || '0.0'}
                      </span>
                      <span className="text-[10px] font-mono text-foreground-muted uppercase">
                        {asset.asset_type}
                      </span>
                    </div>
                    <h4 className="text-xs font-mono font-bold text-foreground group-hover:text-primary transition-colors truncate">
                      {asset.canonical_name}
                    </h4>
                    <p className="text-[11px] text-foreground-muted line-clamp-2">
                      {asset.primary_reason || `Criticality: ${asset.criticality} • Risk: ${asset.risk_score.toFixed(1)}`}
                    </p>
                  </div>

                  <div className="flex items-center justify-between pt-1 border-t border-border/50 text-[10px] font-mono text-foreground-muted">
                    <span>Risk: {asset.risk_score.toFixed(1)}</span>
                    <span className="text-primary flex items-center space-x-0.5 group-hover:translate-x-0.5 transition-transform font-bold">
                      <span>Inspect</span>
                      <ChevronRight className="w-2.5 h-2.5" />
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </section>

      {/* =========================================================================
          4. THREAT INTELLIGENCE & CORRELATION SUMMARY
          ========================================================================= */}
      <section className="space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="text-xs font-mono font-semibold uppercase tracking-wider text-foreground-muted flex items-center gap-2">
            <Globe className="w-3.5 h-3.5 text-primary" />
            <span>Threat Intelligence &amp; Emerging Campaigns</span>
          </h2>
          <span className="text-[11px] font-mono text-foreground-muted">
            Observed IOCs &amp; Correlated Campaign Clusters
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Top Repeated Observables */}
          <div className="p-4 rounded-card bg-surface border border-border shadow-xs space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono font-semibold text-foreground">Top Observed Indicators</span>
              <span className="text-[10px] font-mono text-foreground-muted">Click to inspect</span>
            </div>

            {threatIntel.length === 0 ? (
              <p className="text-xs font-mono text-foreground-muted py-4 text-center">
                No active indicators observed yet.
              </p>
            ) : (
              <div className="space-y-2">
                {threatIntel.map((ioc) => {
                  const provColor =
                    ioc.provenance === 'ANALYST_VERIFIED'
                      ? 'bg-accent/15 text-accent border-accent/30'
                      : ioc.provenance === 'HISTORICAL_MEMORY'
                      ? 'bg-indigo-500/15 text-indigo-400 border-indigo-500/30'
                      : 'bg-primary/15 text-primary border-primary/30';

                  return (
                    <div
                      key={ioc.indicator_value}
                      onClick={() => setSelectedIndicator(ioc.indicator_value)}
                      className="p-2.5 rounded-lg bg-surface-secondary/50 hover:bg-surface-secondary border border-border flex items-center justify-between cursor-pointer transition-colors"
                    >
                      <div className="min-w-0 flex-1 mr-2">
                        <div className="flex items-center space-x-2">
                          <span className="text-xs font-mono font-bold text-foreground truncate select-all">
                            {ioc.indicator_value}
                          </span>
                          <span className="text-[9px] font-mono px-1 py-0.2 rounded bg-surface text-foreground-muted border border-border uppercase">
                            {ioc.indicator_type}
                          </span>
                        </div>
                        <div className="flex items-center space-x-2 text-[10px] font-mono text-foreground-muted mt-0.5">
                          <span>Seen in {ioc.investigation_count} case{ioc.investigation_count !== 1 ? 's' : ''}</span>
                          <span>•</span>
                          <span className={`px-1 rounded text-[9px] font-bold border ${provColor}`}>
                            {ioc.provenance.replace('_', ' ')}
                          </span>
                        </div>
                      </div>

                      <ExternalLink className="w-3.5 h-3.5 text-foreground-muted shrink-0" />
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* Active Campaigns */}
          <div className="p-4 rounded-card bg-surface border border-border shadow-xs space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono font-semibold text-foreground">Active Campaigns</span>
              <span className="text-[10px] font-mono text-foreground-muted">{campaigns.length} correlated</span>
            </div>

            {campaigns.length === 0 ? (
              <p className="text-xs font-mono text-foreground-muted py-4 text-center">
                No campaign clusters active in current window.
              </p>
            ) : (
              <div className="space-y-2">
                {campaigns.map((cmp) => (
                  <div
                    key={cmp.id}
                    className="p-2.5 rounded-lg bg-surface-secondary/50 border border-border flex items-center justify-between"
                  >
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center space-x-2">
                        <span className="text-xs font-semibold text-foreground truncate">
                          {cmp.name}
                        </span>
                        <span className="text-[9px] font-mono px-1 py-0.2 rounded bg-primary/10 text-primary font-bold">
                          {cmp.campaign_id}
                        </span>
                      </div>
                      <div className="flex items-center space-x-2 text-[10px] font-mono text-foreground-muted mt-0.5">
                        <span>{cmp.incident_count} correlated incident{cmp.incident_count !== 1 ? 's' : ''}</span>
                        {cmp.dominant_attack_type && (
                          <>
                            <span>•</span>
                            <span className="text-foreground">{cmp.dominant_attack_type}</span>
                          </>
                        )}
                      </div>
                    </div>

                    <span className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-surface text-foreground-muted border border-border uppercase">
                      {cmp.status}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </section>

      {/* =========================================================================
          5. RECENT INVESTIGATION ACTIVITY FEED
          ========================================================================= */}
      <section className="space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="text-xs font-mono font-semibold uppercase tracking-wider text-foreground-muted flex items-center gap-2">
            <Radio className="w-3.5 h-3.5 text-primary" />
            <span>Investigation Activity Feed</span>
          </h2>
          <span className="text-[11px] font-mono text-foreground-muted">
            Auditable Timeline Events
          </span>
        </div>

        {activity.length === 0 ? (
          <div className="p-6 rounded-card bg-surface border border-border text-center text-xs font-mono text-foreground-muted">
            No audit log activity recorded in selected window.
          </div>
        ) : (
          <div className="rounded-card border border-border bg-surface overflow-hidden shadow-xs divide-y divide-border/60">
            {activity.slice(0, 8).map((ev) => (
              <div
                key={ev.id}
                onClick={() => ev.navigation_target && navigate(ev.navigation_target)}
                className={`p-3 flex items-center justify-between text-xs font-mono ${
                  ev.navigation_target ? 'hover:bg-surface-secondary/60 cursor-pointer transition-colors' : ''
                }`}
              >
                <div className="flex items-center space-x-3 min-w-0 flex-1">
                  <div className="w-2 h-2 rounded-full bg-primary/70 shrink-0" />
                  <div className="min-w-0 flex-1">
                    <span className="text-foreground font-medium truncate block">
                      {ev.description}
                    </span>
                    <span className="text-[10px] text-foreground-muted">
                      Target: {ev.resource_type.toUpperCase()} • By: {ev.user || 'System'}
                    </span>
                  </div>
                </div>

                <div className="shrink-0 ml-3 text-[10px] text-foreground-muted flex items-center space-x-1.5">
                  <Timestamp date={ev.timestamp} format="relative" />
                  {ev.navigation_target && <ChevronRight className="w-3 h-3 text-primary" />}
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      {/* =========================================================================
          6. UNIVERSAL INGESTION SURFACE (SECTION 36 GATEWAY PRESERVED)
          ========================================================================= */}
      <section className="space-y-2 pt-2">
        <div className="flex items-center justify-between">
          <h2 className="text-xs font-mono font-semibold uppercase tracking-wider text-foreground-muted flex items-center gap-2">
            <span>Universal Ingestion Gateway</span>
            <span className="text-[9px] px-1.5 py-0.2 rounded bg-primary/10 text-primary font-bold">
              MULTI-PAYLOAD
            </span>
          </h2>
          <span className="text-[11px] font-mono text-foreground-muted">
            Drop evidence, paste a URL, or upload file payloads
          </span>
        </div>

        <UniversalDropZone onIngestionSuccess={() => fetchSocData(true)} />
      </section>

      {/* Cross-Investigation Indicator Detail Drawer */}
      <IndicatorDetailDrawer
        indicatorValue={selectedIndicator}
        onClose={() => setSelectedIndicator(null)}
      />
    </div>
  );
};

export default OperationsDashboard;
