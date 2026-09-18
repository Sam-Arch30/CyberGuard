import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Mail,
  ShieldAlert,
  AlertTriangle,
  FolderLock,
  RefreshCw,
  Zap,
  ShieldCheck,
  Radio,
  Clock,
  ArrowUpRight
} from 'lucide-react';
import { Button, Skeleton } from '../components/ui';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  BarChart,
  Bar,
  Cell
} from 'recharts';
import type { DashboardSummary } from '../types/dashboard';
import { useTheme } from '../context/ThemeContext';
import { api } from '../services/api';

<<<<<<< Updated upstream
const STATUS_CONFIG: Record<string, { label: string; badge: string }> = {
  open: { label: 'Open', badge: 'bg-surface-secondary text-foreground border-border' },
  investigating: { label: 'Investigating', badge: 'bg-warning-surface text-warning border-warning-border' },
  escalated: { label: 'Escalated', badge: 'bg-danger-surface text-danger border-danger-border font-semibold' },
  resolved: { label: 'Resolved', badge: 'bg-success-surface text-success border-success-border' },
};

const SEVERITY_CONFIG: Record<string, { label: string; badge: string; color: string }> = {
  critical: { label: 'Critical', badge: 'bg-danger-surface text-danger border-danger-border font-bold', color: '#df5252' },
  high: { label: 'High', badge: 'bg-warning-surface text-warning border-warning-border font-semibold', color: '#d99538' },
  medium: { label: 'Medium', badge: 'bg-warning-surface/60 text-warning border-warning-border/70', color: '#e0a648' },
  low: { label: 'Low', badge: 'bg-surface-secondary text-foreground-muted border-border', color: '#889189' },
  suspicious: { label: 'Suspicious', badge: 'bg-warning-surface text-warning border-warning-border', color: '#d99538' },
};

const formatTimestamp = (isoString?: string): string => {
  if (!isoString) return 'Just now';
  try {
    const d = new Date(isoString);
    if (isNaN(d.getTime())) return isoString;
    return d.toLocaleString(undefined, {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      hour12: false
    });
  } catch {
    return isoString;
  }
};

const formatRelativeTime = (isoString?: string): string => {
  if (!isoString) return 'Just now';
  try {
    const d = new Date(isoString);
    const now = new Date();
    const diffMs = now.getTime() - d.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    const diffHours = Math.floor(diffMins / 60);
    if (diffHours < 24) return `${diffHours}h ago`;
    const diffDays = Math.floor(diffHours / 24);
    return `${diffDays}d ago`;
  } catch {
    return isoString;
  }
=======
const SEVERITY_COLORS: Record<string, string> = {
  critical: '#df5252',
  high: '#d99538',
  medium: '#e0a648',
  low: '#889189'
>>>>>>> Stashed changes
};

export const Dashboard: React.FC = () => {
  const navigate = useNavigate();
  const { theme } = useTheme();

  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [refreshing, setRefreshing] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const fetchDashboardData = useCallback(async (isManual = false) => {
    if (isManual) {
      setRefreshing(true);
    } else {
      setLoading(true);
    }
    setError(null);

    try {
<<<<<<< Updated upstream
      const res = await fetch('http://localhost:8000/api/dashboard/summary?days=30&recent_limit=5');
      if (!res.ok) {
        throw new Error(`Failed to load dashboard telemetry: HTTP ${res.status}`);
      }
      const data: DashboardSummary = await res.json();
      setSummary(data);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Unknown telemetry retrieval error';
      setError(message);
=======
      const data = await api.dashboard.getSummary(30, 8);
      setSummary(data);
    } catch (err: any) {
      setError(err?.message || 'Unable to connect to SOC dashboard service');
      setSummary(null);
>>>>>>> Stashed changes
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    fetchDashboardData();
  }, [fetchDashboardData]);

  const metrics = summary?.metrics;

  const getChartTheme = () => {
    switch (theme) {
      case 'blossom':
        return {
          grid: '#ede7eb',
          text: '#776e74',
          totalStroke: '#c8698a',
          totalFill: 'rgba(200, 105, 138, 0.12)',
          threatsStroke: '#d44343',
          threatsFill: 'rgba(212, 67, 67, 0.15)',
          tooltipBg: '#ffffff',
          tooltipBorder: '#e8e1e5'
        };
      case 'violet':
        return {
          grid: '#2a2540',
          text: '#8e86a8',
          totalStroke: '#8070e6',
          totalFill: 'rgba(128, 112, 230, 0.12)',
          threatsStroke: '#df5252',
          threatsFill: 'rgba(223, 82, 82, 0.15)',
          tooltipBg: '#181524',
          tooltipBorder: '#2a2540'
        };
      case 'paper':
        return {
          grid: '#ded7c9',
          text: '#6f6a5f',
          totalStroke: '#7a5f45',
          totalFill: 'rgba(122, 95, 69, 0.1)',
          threatsStroke: '#b83a3a',
          threatsFill: 'rgba(184, 58, 58, 0.12)',
          tooltipBg: '#fcfaf6',
          tooltipBorder: '#ded7c9'
        };
      case 'obsidian':
      default:
        return {
          grid: '#232924',
          text: '#8a948c',
          totalStroke: '#7d9456',
          totalFill: 'rgba(125, 148, 86, 0.12)',
          threatsStroke: '#df5252',
          threatsFill: 'rgba(223, 82, 82, 0.15)',
          tooltipBg: '#141715',
          tooltipBorder: '#232924'
        };
    }
  };

  const chartTheme = getChartTheme();

  return (
    <div className="space-y-5 pb-12 max-w-7xl mx-auto">
      {/* Compact Top Command Strip */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-4 rounded-card bg-surface border border-border shadow-card">
        <div className="flex items-center space-x-3">
          <div className="w-8 h-8 rounded-control bg-surface-secondary border border-border flex items-center justify-center text-primary">
            <Radio className="w-4 h-4 text-primary animate-pulse" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h1 className="text-base font-bold text-foreground font-sans tracking-tight">
                SOC Threat Telemetry & Operations
              </h1>
              <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-success-surface text-success border border-success-border font-medium">
                LIVE SENSOR
              </span>
            </div>
            <p className="text-xs text-foreground-muted font-mono">
              Operational overview of verified email analyses, attack distribution, and active investigations.
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => fetchDashboardData(true)}
            disabled={loading || refreshing}
            isLoading={refreshing}
            leftIcon={!refreshing ? <RefreshCw className="w-3.5 h-3.5" /> : undefined}
            className="font-mono text-xs"
          >
            {refreshing ? 'Syncing...' : 'Sync'}
          </Button>

          <Button
            variant="primary"
            size="sm"
            onClick={() => navigate('/analyze')}
            leftIcon={<Zap className="w-3.5 h-3.5" />}
            className="font-mono text-xs font-semibold"
          >
            Ingest EML
          </Button>
        </div>
      </div>

<<<<<<< Updated upstream
      {/* Error Banner */}
      {error && (
        <div className="p-3.5 rounded-control bg-danger-surface border border-danger-border text-danger flex items-center justify-between text-xs font-mono">
          <div className="flex items-center space-x-2">
            <AlertTriangle className="w-4 h-4 text-danger flex-shrink-0" />
            <span>Failed to connect to forensic telemetry service: {error}</span>
          </div>
          <Button
            variant="danger"
            size="xs"
            onClick={() => fetchDashboardData(true)}
          >
            Retry
=======
      {/* Error / Service Offline Banner */}
      {error && (
        <div className="p-3.5 rounded-control bg-danger-surface border border-danger-border flex items-center justify-between text-xs font-mono text-danger">
          <div className="flex items-center space-x-2">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span>Telemetry Service Offline: {error}. Start backend server on port 8000.</span>
          </div>
          <Button variant="danger" size="xs" onClick={() => fetchDashboardData(true)}>
            Retry Connection
>>>>>>> Stashed changes
          </Button>
        </div>
      )}

      {/* High-Density 4-KPI Metric Strip */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        {/* Metric 1: Analyzed */}
        <div className="p-4 rounded-card bg-surface border border-border hover:border-border-strong transition-colors shadow-xs">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-mono uppercase text-foreground-muted tracking-wider">
              Total Ingested
            </span>
            <Mail className="w-3.5 h-3.5 text-primary" />
          </div>
          <div className="mt-2 flex items-baseline justify-between">
            {loading ? (
              <Skeleton width={60} height={24} />
            ) : (
              <span className="text-2xl font-bold font-mono text-foreground">
                {(metrics?.emails_analyzed ?? 0).toLocaleString()}
              </span>
            )}
            <span className="text-[10px] font-mono text-foreground-muted">Verified RFC-822</span>
          </div>
        </div>

        {/* Metric 2: Malicious Rate */}
        <div className="p-4 rounded-card bg-surface border border-border hover:border-border-strong transition-colors shadow-xs">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-mono uppercase text-foreground-muted tracking-wider">
              Threats Detected
            </span>
            <ShieldAlert className="w-3.5 h-3.5 text-warning" />
          </div>
          <div className="mt-2 flex items-baseline justify-between">
            {loading ? (
              <Skeleton width={60} height={24} />
            ) : (
              <span className="text-2xl font-bold font-mono text-warning">
                {(metrics?.threats_detected ?? 0).toLocaleString()}
              </span>
            )}
            <span className="text-[10px] font-mono text-warning font-semibold">
              {metrics && metrics.emails_analyzed > 0
                ? `${((metrics.threats_detected / metrics.emails_analyzed) * 100).toFixed(0)}% Rate`
                : '0% Rate'}
            </span>
          </div>
        </div>

        {/* Metric 3: Critical Attacks */}
        <div className="p-4 rounded-card bg-surface border border-border hover:border-border-strong transition-colors shadow-xs">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-mono uppercase text-foreground-muted tracking-wider">
              Critical (Score ≥80)
            </span>
            <AlertTriangle className="w-3.5 h-3.5 text-danger" />
          </div>
          <div className="mt-2 flex items-baseline justify-between">
            {loading ? (
              <Skeleton width={60} height={24} />
            ) : (
              <span className="text-2xl font-bold font-mono text-danger">
                {(metrics?.critical_emails ?? 0).toLocaleString()}
              </span>
            )}
            <span className="text-[10px] font-mono text-danger font-semibold">Action Required</span>
          </div>
        </div>

        {/* Metric 4: Active Cases */}
        <div className="p-4 rounded-card bg-surface border border-border hover:border-border-strong transition-colors shadow-xs">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-mono uppercase text-foreground-muted tracking-wider">
              Open Investigations
            </span>
            <FolderLock className="w-3.5 h-3.5 text-foreground-muted" />
          </div>
          <div className="mt-2 flex items-baseline justify-between">
            {loading ? (
              <Skeleton width={60} height={24} />
            ) : (
              <span className="text-2xl font-bold font-mono text-foreground">
                {(metrics?.open_cases ?? 0).toLocaleString()}
              </span>
            )}
            <button
              type="button"
              onClick={() => navigate('/cases')}
              className="text-[10px] font-mono text-primary hover:underline"
            >
              View Cases →
            </button>
          </div>
        </div>
      </div>

      {/* Main Grid: Analysis Trend (Left 2/3) + Severity Breakdown (Right 1/3) */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Trend Area Chart */}
        <div className="lg:col-span-2 p-4 rounded-card bg-surface border border-border shadow-card space-y-3">
          <div className="flex items-center justify-between border-b border-border pb-2.5">
            <div className="flex items-center space-x-2">
              <Clock className="w-3.5 h-3.5 text-primary" />
              <h2 className="text-xs font-mono font-bold uppercase text-foreground">
                Forensic Analysis Volume (Last 30 Days)
              </h2>
            </div>
            <div className="flex items-center space-x-3 text-[11px] font-mono text-foreground-muted">
              <span className="flex items-center space-x-1">
                <span className="w-2 h-2 rounded-full bg-primary" />
                <span>Total Ingested</span>
              </span>
              <span className="flex items-center space-x-1">
                <span className="w-2 h-2 rounded-full bg-danger" />
                <span>Threats</span>
              </span>
            </div>
          </div>

          <div className="h-48 w-full">
            {loading ? (
              <div className="h-full flex items-center justify-center">
                <Skeleton width="100%" height="100%" />
              </div>
            ) : summary?.analysis_trend && summary.analysis_trend.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={summary.analysis_trend} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="trendTotalGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor={chartTheme.totalStroke} stopOpacity={0.3} />
                      <stop offset="95%" stopColor={chartTheme.totalStroke} stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="trendThreatsGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor={chartTheme.threatsStroke} stopOpacity={0.3} />
                      <stop offset="95%" stopColor={chartTheme.threatsStroke} stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="2 2" stroke={chartTheme.grid} />
                  <XAxis
                    dataKey="date"
                    stroke={chartTheme.text}
                    tick={{ fontSize: 10, fontFamily: 'monospace' }}
                    tickFormatter={(val) => val.slice(5)}
                  />
                  <YAxis
                    stroke={chartTheme.text}
                    tick={{ fontSize: 10, fontFamily: 'monospace' }}
                    allowDecimals={false}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: chartTheme.tooltipBg,
                      borderColor: chartTheme.tooltipBorder,
                      borderRadius: 6,
                      fontSize: 11,
                      fontFamily: 'monospace'
                    }}
                  />
                  <Area
                    type="monotone"
                    dataKey="total"
                    stroke={chartTheme.totalStroke}
                    fillOpacity={1}
                    fill="url(#trendTotalGrad)"
                    name="Total Ingested"
                  />
                  <Area
                    type="monotone"
                    dataKey="threats"
                    stroke={chartTheme.threatsStroke}
                    fillOpacity={1}
                    fill="url(#trendThreatsGrad)"
                    name="Threats Flagged"
                  />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-xs font-mono text-foreground-muted">
                No telemetry recorded in this period. Ingest an .eml to populate trend data.
              </div>
            )}
          </div>
        </div>

        {/* Severity Distribution */}
        <div className="p-4 rounded-card bg-surface border border-border shadow-card space-y-3">
          <div className="flex items-center justify-between border-b border-border pb-2.5">
            <div className="flex items-center space-x-2">
              <ShieldCheck className="w-3.5 h-3.5 text-primary" />
              <h2 className="text-xs font-mono font-bold uppercase text-foreground">
                Threat Classification
              </h2>
            </div>
            <span className="text-[10px] font-mono text-foreground-muted">Severity Bands</span>
          </div>

          <div className="h-48 w-full">
            {loading ? (
              <div className="h-full flex items-center justify-center">
                <Skeleton width="100%" height="100%" />
              </div>
            ) : summary?.severity_distribution && summary.severity_distribution.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={summary.severity_distribution} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="2 2" stroke={chartTheme.grid} />
                  <XAxis
                    dataKey="severity"
                    stroke={chartTheme.text}
                    tick={{ fontSize: 10, fontFamily: 'monospace' }}
                    tickFormatter={(s) => s.toUpperCase()}
                  />
                  <YAxis
                    stroke={chartTheme.text}
                    tick={{ fontSize: 10, fontFamily: 'monospace' }}
                    allowDecimals={false}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: chartTheme.tooltipBg,
                      borderColor: chartTheme.tooltipBorder,
                      borderRadius: 6,
                      fontSize: 11,
                      fontFamily: 'monospace'
                    }}
                  />
                  <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                    {summary.severity_distribution.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={SEVERITY_COLORS[entry.severity] || '#7d9456'} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-xs font-mono text-foreground-muted">
                No analyzed emails evaluated yet.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Bottom Row: Recent Ingested Emails (Triage Feed) */}
      <div className="p-4 rounded-card bg-surface border border-border shadow-card space-y-3">
        <div className="flex items-center justify-between border-b border-border pb-2.5">
          <div className="flex items-center space-x-2">
            <Radio className="w-3.5 h-3.5 text-primary" />
            <h2 className="text-xs font-mono font-bold uppercase text-foreground">
              Recent Forensic Triage Queue
            </h2>
          </div>
          <button
            type="button"
            onClick={() => navigate('/history')}
            className="text-xs font-mono text-primary hover:underline flex items-center space-x-1"
          >
            <span>Open Complete Archive ({metrics?.emails_analyzed ?? 0})</span>
            <ArrowUpRight className="w-3 h-3" />
          </button>
        </div>

        {loading ? (
          <div className="space-y-2 py-2">
            <Skeleton width="100%" height={32} />
            <Skeleton width="100%" height={32} />
            <Skeleton width="100%" height={32} />
          </div>
        ) : summary?.recent_emails && summary.recent_emails.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left data-table-compact">
              <thead>
                <tr>
                  <th className="w-20">Score</th>
                  <th>Subject</th>
                  <th>Sender</th>
                  <th className="w-32">Timestamp</th>
                  <th className="w-24 text-right">Action</th>
                </tr>
              </thead>
              <tbody>
                {summary.recent_emails.map((item) => (
                  <tr key={item.id} className="group transition-colors">
                    <td>
                      <span className={`px-2 py-0.5 rounded text-[11px] font-mono font-bold ${
                        item.threat_score >= 80
                          ? 'bg-danger-surface text-danger border border-danger-border'
                          : item.threat_score >= 50
                          ? 'bg-warning-surface text-warning border border-warning-border'
                          : 'bg-surface-secondary text-foreground-muted border border-border'
                      }`}>
                        {item.threat_score}
                      </span>
                    </td>
                    <td className="font-medium text-foreground max-w-xs truncate">
                      {item.subject || 'Untitled Email'}
                    </td>
                    <td className="font-mono text-foreground-muted max-w-xs truncate">
                      {item.sender || 'Unknown Sender'}
                    </td>
                    <td className="font-mono text-foreground-muted">
                      {item.timestamp ? new Date(item.timestamp).toLocaleDateString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : '-'}
                    </td>
                    <td className="text-right">
                      <button
                        type="button"
                        onClick={() => navigate(`/analysis/${item.id}`)}
                        className="px-2 py-1 rounded text-xs font-mono bg-surface-secondary hover:bg-primary hover:text-primary-foreground border border-border hover:border-primary transition-colors cursor-pointer"
                      >
                        Investigate
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="py-8 text-center text-xs font-mono text-foreground-muted space-y-2">
            <p>No email analysis records in database.</p>
            <Button variant="outline" size="xs" onClick={() => navigate('/analyze')}>
              Ingest First EML
            </Button>
          </div>
        )}
      </div>
    </div>
  );
};
