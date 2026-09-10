import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Mail,
  ShieldAlert,
  AlertTriangle,
  FolderLock,
  ArrowUpRight,
  RefreshCw,
  Globe,
  Radio,
  Zap,
  ChevronRight,
  ShieldX,
  Server,
  Activity,
  CheckCircle2,
  FileSearch,
  Plus
} from 'lucide-react';
import { Button, Skeleton, Badge } from '../components/ui';
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
};

const FALLBACK_DASHBOARD_SUMMARY: DashboardSummary = {
  metrics: {
    emails_analyzed: 18,
    threats_detected: 14,
    critical_emails: 7,
    open_cases: 4
  },
  severity_distribution: [
    { severity: 'critical', count: 7 },
    { severity: 'high', count: 7 },
    { severity: 'medium', count: 3 },
    { severity: 'low', count: 1 }
  ],
  analysis_trend: [
    { date: '2026-09-04', total: 2, threats: 1 },
    { date: '2026-09-05', total: 4, threats: 3 },
    { date: '2026-09-06', total: 3, threats: 2 },
    { date: '2026-09-07', total: 5, threats: 4 },
    { date: '2026-09-08', total: 3, threats: 3 },
    { date: '2026-09-09', total: 6, threats: 5 },
    { date: '2026-09-10', total: 4, threats: 3 }
  ],
  top_suspicious_domains: [
    { domain: 'bank-corp-update.com', count: 4 },
    { domain: 'micros0ft-security-verify.net', count: 3 },
    { domain: 'wire-transfer-gateway.ru', count: 3 },
    { domain: 'hr-payroll-portal.org', count: 2 },
    { domain: 'secure-login-attempt.xyz', count: 2 }
  ],
  top_countries: [
    { country: 'Russia', count: 5 },
    { country: 'Nigeria', count: 4 },
    { country: 'China', count: 3 },
    { country: 'United States', count: 3 },
    { country: 'Romania', count: 2 }
  ],
  auth_failures: {
    spf_failures: 12,
    dkim_failures: 14,
    dmarc_failures: 11,
    total_evaluated: 18
  },
  recent_cases: [
    {
      id: 'case-001',
      case_number: 'CASE-2026-000042',
      title: 'Active BEC Wire Redirection Campaign',
      severity: 'critical',
      status: 'investigating',
      emails_count: 3,
      updated_at: '2026-09-10T14:30:00Z'
    },
    {
      id: 'case-002',
      case_number: 'CASE-2026-000041',
      title: 'Credential Harvesting Target - Executive Accounts',
      severity: 'high',
      status: 'open',
      emails_count: 5,
      updated_at: '2026-09-10T11:15:00Z'
    }
  ],
  recent_emails: [
    {
      id: 'EML-2026-8819',
      evidence_id: 'EVD-97D4B2E811',
      sha256: '97d4b2e811c7520e5e79603f9050d268159b360b9432df03d4083d8e57ef228a',
      subject: 'URGENT: Executive Wire Transfer Instructions - Q3 Vendor Settlement #8819',
      sender: 'robert.vance@bank-corp-update.com',
      threat_score: 96,
      severity: 'critical',
      timestamp: '2026-09-10T16:20:00Z'
    },
    {
      id: 'EML-2026-8820',
      evidence_id: 'EVD-88F3A109C2',
      sha256: '88f3a109c2a1e765bd489f023412ea5418b76543210987654321098765432109',
      subject: 'Microsoft 365: Mandatory Password Expiration in 24 Hours',
      sender: 'security@micros0ft-security-verify.net',
      threat_score: 88,
      severity: 'high',
      timestamp: '2026-09-10T15:05:00Z'
    }
  ]
};

export const Dashboard: React.FC = () => {
  const navigate = useNavigate();
  const { theme } = useTheme();

  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [refreshing, setRefreshing] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [isOfflineFallback, setIsOfflineFallback] = useState<boolean>(false);

  const fetchDashboardData = useCallback(async (isManualRefresh = false) => {
    if (isManualRefresh) {
      setRefreshing(true);
    } else {
      setLoading(true);
    }
    setError(null);

    const endpoints = [
      '/api/dashboard/summary?days=30&recent_limit=5',
      'http://localhost:8000/api/dashboard/summary?days=30&recent_limit=5'
    ];

    let liveData: DashboardSummary | null = null;
    let lastError: string | null = null;

    for (const endpoint of endpoints) {
      try {
        const res = await fetch(endpoint);
        if (res.ok) {
          liveData = await res.json();
          break;
        } else {
          lastError = `HTTP ${res.status}`;
        }
      } catch (err: unknown) {
        lastError = err instanceof Error ? err.message : 'Connection refused';
      }
    }

    if (liveData) {
      setSummary(liveData);
      setIsOfflineFallback(false);
      setError(null);
    } else {
      // Gracefully use local sample telemetry so the dashboard remains functional
      setSummary(FALLBACK_DASHBOARD_SUMMARY);
      setIsOfflineFallback(true);
      setError(lastError || 'Backend service unreachable');
    }

    setLoading(false);
    setRefreshing(false);
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
          totalFill: '#c8698a',
          threatsStroke: '#d44343',
          threatsFill: '#d44343',
          tooltipBg: '#ffffff',
          tooltipBorder: '#e8e1e5',
          tooltipText: '#1e191c'
        };
      case 'violet':
        return {
          grid: '#2a2540',
          text: '#8e86a8',
          totalStroke: '#8070e6',
          totalFill: '#8070e6',
          threatsStroke: '#e05555',
          threatsFill: '#e05555',
          tooltipBg: '#181524',
          tooltipBorder: '#2a2540',
          tooltipText: '#edeaf5'
        };
      case 'paper':
        return {
          grid: '#ded7c9',
          text: '#6f6a5f',
          totalStroke: '#7a5f45',
          totalFill: '#7a5f45',
          threatsStroke: '#b83a3a',
          threatsFill: '#b83a3a',
          tooltipBg: '#fcfaf6',
          tooltipBorder: '#ded7c9',
          tooltipText: '#23201b'
        };
      case 'obsidian':
      default:
        return {
          grid: '#232924',
          text: '#8a948c',
          totalStroke: '#7d9456',
          totalFill: '#7d9456',
          threatsStroke: '#df5252',
          threatsFill: '#df5252',
          tooltipBg: '#141715',
          tooltipBorder: '#232924',
          tooltipText: '#e4e8e5'
        };
    }
  };

  const chartTheme = getChartTheme();

  return (
    <div className="space-y-6 pb-12 max-w-7xl mx-auto">
      {/* Top Banner & Quick Launcher */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-surface border border-border p-6 rounded-card shadow-card transition-colors">
        <div>
          <div className="flex items-center space-x-2 text-primary font-mono text-xs mb-1.5 font-semibold uppercase tracking-wider">
            <Radio className="w-3.5 h-3.5 text-primary" />
            <span>SECURITY OPERATIONS CENTER (SOC) PLATFORM</span>
            <span className="w-1.5 h-1.5 rounded-full bg-success animate-pulse" />
            <span className="text-success text-[11px] font-semibold">LIVE SENSOR</span>
          </div>
          <h1 className="text-2xl md:text-3xl font-bold text-foreground font-sans tracking-tight">
            Security Operations & Email Forensics
          </h1>
          <p className="text-xs md:text-sm text-foreground-muted mt-1 max-w-2xl font-mono">
            Automated RFC-822 header ingestion, SMTP relay reconstruction, intent heuristics, and forensic telemetry attribution.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          <Button
            variant="outline"
            size="sm"
            onClick={() => fetchDashboardData(true)}
            disabled={loading || refreshing}
            isLoading={refreshing}
            leftIcon={!refreshing ? <RefreshCw className="w-3.5 h-3.5 text-primary" /> : undefined}
            className="font-mono text-xs"
            title="Refresh dashboard telemetry"
          >
            {refreshing ? 'SYNCING...' : 'SYNC'}
          </Button>
          <Button
            variant="primary"
            size="sm"
            onClick={() => navigate('/analyze')}
            leftIcon={<Zap className="w-3.5 h-3.5" />}
            className="font-mono font-semibold tracking-wide text-xs"
          >
            ANALYZE SUSPICIOUS EML
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => navigate('/cases')}
            leftIcon={<FolderLock className="w-3.5 h-3.5 text-foreground-muted" />}
            className="font-mono text-xs"
          >
            INVESTIGATIONS
          </Button>
        </div>
      </div>

      {/* Error / Offline Advisory Banner */}
      {error && (
        <div className={`p-3.5 rounded-control border flex items-center justify-between text-xs font-mono transition-all ${
          isOfflineFallback
            ? 'bg-warning-surface/30 border-warning-border/70 text-warning'
            : 'bg-danger-surface border-danger-border text-danger'
        }`}>
          <div className="flex items-center space-x-2">
            <AlertTriangle className={`w-4 h-4 flex-shrink-0 ${isOfflineFallback ? 'text-warning' : 'text-danger'}`} />
            <span>
              {isOfflineFallback
                ? `Live backend telemetry offline (${error}). Displaying local sample telemetry. Start backend with 'uvicorn backend.main:app' or 'docker compose up' for live data.`
                : `Failed to connect to forensic telemetry service: ${error}`}
            </span>
          </div>
          <Button
            variant={isOfflineFallback ? 'secondary' : 'danger'}
            size="xs"
            onClick={() => fetchDashboardData(true)}
          >
            {isOfflineFallback ? 'Connect Live' : 'Retry'}
          </Button>
        </div>
      )}

      {/* 4 Summary Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Card 1: Emails Analyzed */}
        <div className="p-5 rounded-card bg-surface border border-border transition-all hover:border-primary/50 shadow-card">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-foreground-muted font-medium uppercase tracking-wider">
              Emails Analyzed
            </span>
            <div className="p-2 rounded-control bg-surface-secondary text-primary border border-border">
              <Mail className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline justify-between">
            {loading ? (
              <Skeleton width={80} height={32} />
            ) : (
              <span className="text-3xl font-bold font-mono text-foreground">
                {(metrics?.emails_analyzed ?? 0).toLocaleString()}
              </span>
            )}
            <Badge size="xs" variant="neutral">
              Total Ingested
            </Badge>
          </div>
          <p className="text-[11px] text-foreground-muted mt-2 font-mono">
            Verified RFC-822 evidence records
          </p>
        </div>

        {/* Card 2: Threats Detected */}
        <div className="p-5 rounded-card bg-surface border border-border transition-all hover:border-warning/50 shadow-card">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-foreground-muted font-medium uppercase tracking-wider">
              Threats Detected
            </span>
            <div className="p-2 rounded-control bg-warning-surface text-warning border border-warning-border">
              <ShieldAlert className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline justify-between">
            {loading ? (
              <Skeleton width={80} height={32} />
            ) : (
              <span className="text-3xl font-bold font-mono text-foreground">
                {(metrics?.threats_detected ?? 0).toLocaleString()}
              </span>
            )}
            <Badge size="xs" variant="warning">
              {metrics && metrics.emails_analyzed > 0
                ? `${((metrics.threats_detected / metrics.emails_analyzed) * 100).toFixed(1)}% Rate`
                : '0.0% Rate'}
            </Badge>
          </div>
          <p className="text-[11px] text-foreground-muted mt-2 font-mono">
            Phishing, BEC & lookalike domains
          </p>
        </div>

        {/* Card 3: Critical Emails */}
        <div className="p-5 rounded-card bg-surface border border-border transition-all hover:border-danger/50 shadow-card">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-foreground-muted font-medium uppercase tracking-wider">
              Critical Emails
            </span>
            <div className="p-2 rounded-control bg-danger-surface text-danger border border-danger-border">
              <AlertTriangle className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline justify-between">
            {loading ? (
              <Skeleton width={80} height={32} />
            ) : (
              <span className="text-3xl font-bold font-mono text-foreground">
                {(metrics?.critical_emails ?? 0).toLocaleString()}
              </span>
            )}
            <Badge size="xs" variant="danger">
              Score ≥ 80
            </Badge>
          </div>
          <p className="text-[11px] text-foreground-muted mt-2 font-mono">
            High-confidence malicious attacks
          </p>
        </div>

        {/* Card 4: Open Cases */}
        <div className="p-5 rounded-card bg-surface border border-border transition-all hover:border-primary/50 shadow-card">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-foreground-muted font-medium uppercase tracking-wider">
              Open Cases
            </span>
            <div className="p-2 rounded-control bg-surface-secondary text-primary border border-border">
              <FolderLock className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline justify-between">
            {loading ? (
              <Skeleton width={80} height={32} />
            ) : (
              <span className="text-3xl font-bold font-mono text-foreground">
                {(metrics?.open_cases ?? 0).toLocaleString()}
              </span>
            )}
            <Badge size="xs" variant="neutral">
              Active
            </Badge>
          </div>
          <p className="text-[11px] text-foreground-muted mt-2 font-mono">
            Investigations currently in progress
          </p>
        </div>
      </div>

      {/* Main Forensic Charts Section */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Recent Analysis Trend Chart */}
        <div className="lg:col-span-2 bg-surface border border-border rounded-xl p-5 flex flex-col justify-between shadow-xs">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-sm font-bold text-foreground font-sans flex items-center space-x-2">
                <Activity className="w-4 h-4 text-primary" />
                <span>Recent Analysis Trend</span>
              </h2>
              <p className="text-xs text-foreground-muted font-mono mt-0.5">
                Ingested email volume and detected threat activity over time
              </p>
            </div>
            <span className="text-[10px] font-mono text-foreground-muted font-medium px-2 py-0.5 rounded bg-surface-secondary border border-border">
              LAST 30 DAYS
            </span>
          </div>

          <div className="h-64 w-full">
            {loading ? (
              <div className="h-full w-full bg-surface-secondary/40 rounded-lg animate-pulse flex items-center justify-center">
                <span className="text-xs font-mono text-foreground-muted">Loading analysis timeline...</span>
              </div>
            ) : summary?.analysis_trend && summary.analysis_trend.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={summary.analysis_trend} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="trendTotal" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor={chartTheme.totalFill} stopOpacity={0.3} />
                      <stop offset="95%" stopColor={chartTheme.totalFill} stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="trendThreats" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor={chartTheme.threatsFill} stopOpacity={0.3} />
                      <stop offset="95%" stopColor={chartTheme.threatsFill} stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke={chartTheme.grid} />
                  <XAxis dataKey="date" stroke={chartTheme.text} tick={{ fontSize: 10, fontFamily: 'monospace' }} />
                  <YAxis stroke={chartTheme.text} tick={{ fontSize: 10, fontFamily: 'monospace' }} allowDecimals={false} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: chartTheme.tooltipBg,
                      borderColor: chartTheme.tooltipBorder,
                      borderRadius: '0.5rem',
                      fontSize: '11px',
                      color: chartTheme.tooltipText,
                      fontFamily: 'monospace',
                      boxShadow: '0 2px 8px rgba(0,0,0,0.15)'
                    }}
                  />
                  <Area
                    type="monotone"
                    dataKey="total"
                    name="Emails Analyzed"
                    stroke={chartTheme.totalStroke}
                    strokeWidth={2}
                    fillOpacity={1}
                    fill="url(#trendTotal)"
                  />
                  <Area
                    type="monotone"
                    dataKey="threats"
                    name="Threats Detected"
                    stroke={chartTheme.threatsStroke}
                    strokeWidth={2}
                    fillOpacity={1}
                    fill="url(#trendThreats)"
                  />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full w-full rounded-lg border border-dashed border-border flex flex-col items-center justify-center p-6 text-center">
                <FileSearch className="w-8 h-8 text-foreground-muted mb-2 opacity-50" />
                <span className="text-xs font-mono text-foreground font-medium">No Trend Telemetry Available</span>
                <span className="text-[11px] font-mono text-foreground-muted mt-1 max-w-sm">
                  Ingested emails will automatically populate the temporal analysis curve.
                </span>
              </div>
            )}
          </div>
        </div>

        {/* Threat Severity Distribution Chart */}
        <div className="bg-surface border border-border rounded-xl p-5 flex flex-col justify-between shadow-xs">
          <div>
            <div className="flex items-center justify-between mb-2">
              <h2 className="text-sm font-bold text-foreground font-sans flex items-center space-x-2">
                <ShieldAlert className="w-4 h-4 text-warning" />
                <span>Severity Distribution</span>
              </h2>
            </div>
            <p className="text-xs text-foreground-muted font-mono mb-4">
              Categorized risk posture across analyzed emails
            </p>

            {loading ? (
              <div className="h-56 bg-surface-secondary/40 rounded-lg animate-pulse" />
            ) : summary?.severity_distribution && summary.severity_distribution.length > 0 ? (
              <div className="space-y-3">
                <div className="h-44 w-full">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={summary.severity_distribution} margin={{ top: 5, right: 10, left: -25, bottom: 0 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke={chartTheme.grid} vertical={false} />
                      <XAxis dataKey="severity" stroke={chartTheme.text} tick={{ fontSize: 10, fontFamily: 'monospace' }} />
                      <YAxis stroke={chartTheme.text} tick={{ fontSize: 10, fontFamily: 'monospace' }} allowDecimals={false} />
                      <Tooltip
                        contentStyle={{
                          backgroundColor: chartTheme.tooltipBg,
                          borderColor: chartTheme.tooltipBorder,
                          borderRadius: '0.5rem',
                          fontSize: '11px',
                          color: chartTheme.tooltipText,
                          fontFamily: 'monospace'
                        }}
                      />
                      <Bar dataKey="count" name="Emails" radius={[4, 4, 0, 0]}>
                        {summary.severity_distribution.map((entry) => (
                          <Cell
                            key={entry.severity}
                            fill={SEVERITY_CONFIG[entry.severity.toLowerCase()]?.color || chartTheme.totalStroke}
                          />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>

                <div className="grid grid-cols-2 gap-2 pt-2 border-t border-border text-xs font-mono">
                  {summary.severity_distribution.map((item) => (
                    <div key={item.severity} className="flex items-center justify-between bg-surface-secondary p-2 rounded-md border border-border">
                      <span className="capitalize text-foreground-muted">{item.severity}</span>
                      <span className="font-semibold text-foreground">{item.count}</span>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <div className="h-56 rounded-lg border border-dashed border-border flex flex-col items-center justify-center p-6 text-center">
                <CheckCircle2 className="w-8 h-8 text-foreground-muted mb-2 opacity-50" />
                <span className="text-xs font-mono text-foreground font-medium">No Severity Telemetry</span>
                <span className="text-[11px] font-mono text-foreground-muted mt-1">
                  Evaluated risk scores will be categorized here.
                </span>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Secondary Forensic Indicators Grid: Domains, Countries, Authentication */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Top Suspicious Domains */}
        <div className="bg-surface border border-border rounded-xl p-5 flex flex-col justify-between shadow-xs">
          <div>
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center space-x-2">
                <Globe className="w-4 h-4 text-primary" />
                <h3 className="text-sm font-bold text-foreground font-sans">
                  Top Suspicious Domains
                </h3>
              </div>
              <span className="text-[10px] font-mono text-foreground-muted">OBSERVED</span>
            </div>
            <p className="text-xs text-foreground-muted font-mono mb-4">
              Lookalike & extracted hostnames from emails
            </p>

            {loading ? (
              <div className="space-y-2">
                {[1, 2, 3].map((i) => (
                  <div key={i} className="h-8 bg-surface-secondary/50 rounded animate-pulse" />
                ))}
              </div>
            ) : summary?.top_suspicious_domains && summary.top_suspicious_domains.length > 0 ? (
              <div className="space-y-2">
                {summary.top_suspicious_domains.map((item) => (
                  <div
                    key={item.domain}
                    className="flex items-center justify-between p-2 rounded-lg bg-surface-secondary border border-border text-xs font-mono"
                  >
                    <span className="text-foreground font-medium truncate max-w-[200px]" title={item.domain}>
                      {item.domain}
                    </span>
                    <span className="px-2 py-0.5 rounded bg-surface text-foreground-muted text-[11px] font-medium border border-border">
                      {item.count} {item.count === 1 ? 'hit' : 'hits'}
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="p-6 rounded-lg border border-dashed border-border text-center text-xs font-mono text-foreground-muted">
                No suspicious domains observed yet.
              </div>
            )}
          </div>
        </div>

        {/* Top Observed Infrastructure Countries */}
        <div className="bg-surface border border-border rounded-xl p-5 flex flex-col justify-between shadow-xs">
          <div>
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center space-x-2">
                <Server className="w-4 h-4 text-primary" />
                <h3 className="text-sm font-bold text-foreground font-sans">
                  Infrastructure Countries
                </h3>
              </div>
              <span className="text-[10px] font-mono text-foreground-muted">RELAY HOPS</span>
            </div>
            <p className="text-xs text-foreground-muted font-mono mb-4">
              Originating IP servers detected across hops
            </p>

            {loading ? (
              <div className="space-y-2">
                {[1, 2, 3].map((i) => (
                  <div key={i} className="h-8 bg-surface-secondary/50 rounded animate-pulse" />
                ))}
              </div>
            ) : summary?.top_countries && summary.top_countries.length > 0 ? (
              <div className="space-y-2">
                {summary.top_countries.map((item) => (
                  <div
                    key={item.country}
                    className="flex items-center justify-between p-2 rounded-lg bg-surface-secondary border border-border text-xs font-mono"
                  >
                    <span className="text-foreground font-medium truncate">
                      {item.country}
                    </span>
                    <span className="px-2 py-0.5 rounded bg-primary-subtle text-primary text-[11px] font-semibold border border-primary/20">
                      {item.count} {item.count === 1 ? 'node' : 'nodes'}
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="p-6 rounded-lg border border-dashed border-border text-center text-xs font-mono text-foreground-muted">
                No infrastructure nodes detected yet.
              </div>
            )}
          </div>
        </div>

        {/* Authentication Failure Breakdown */}
        <div className="bg-surface border border-border rounded-xl p-5 flex flex-col justify-between shadow-xs">
          <div>
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center space-x-2">
                <ShieldX className="w-4 h-4 text-danger" />
                <h3 className="text-sm font-bold text-foreground font-sans">
                  Authentication Failures
                </h3>
              </div>
              <span className="text-[10px] font-mono text-foreground-muted">PROTOCOL CHECKS</span>
            </div>
            <p className="text-xs text-foreground-muted font-mono mb-4">
              SPF, DKIM, and DMARC verification results
            </p>

            {loading ? (
              <div className="space-y-2">
                {[1, 2, 3].map((i) => (
                  <div key={i} className="h-8 bg-surface-secondary/50 rounded animate-pulse" />
                ))}
              </div>
            ) : summary?.auth_failures && summary.auth_failures.total_evaluated > 0 ? (
              <div className="space-y-2">
                {/* SPF Failures */}
                <div className="p-2 rounded-lg bg-surface-secondary border border-border flex items-center justify-between text-xs font-mono">
                  <div className="flex items-center space-x-2">
                    <span className="px-1.5 py-0.5 rounded bg-danger-surface text-danger text-[10px] font-bold border border-danger-border">
                      SPF
                    </span>
                    <span className="text-foreground">Sender Policy Failures</span>
                  </div>
                  <span className="font-bold text-danger">{summary.auth_failures.spf_failures}</span>
                </div>

                {/* DKIM Failures */}
                <div className="p-2 rounded-lg bg-surface-secondary border border-border flex items-center justify-between text-xs font-mono">
                  <div className="flex items-center space-x-2">
                    <span className="px-1.5 py-0.5 rounded bg-warning-surface text-warning text-[10px] font-bold border border-warning-border">
                      DKIM
                    </span>
                    <span className="text-foreground">Signature Failures</span>
                  </div>
                  <span className="font-bold text-warning">{summary.auth_failures.dkim_failures}</span>
                </div>

                {/* DMARC Failures */}
                <div className="p-2 rounded-lg bg-surface-secondary border border-border flex items-center justify-between text-xs font-mono">
                  <div className="flex items-center space-x-2">
                    <span className="px-1.5 py-0.5 rounded bg-danger-surface text-danger text-[10px] font-bold border border-danger-border">
                      DMARC
                    </span>
                    <span className="text-foreground">Alignment Failures</span>
                  </div>
                  <span className="font-bold text-danger">{summary.auth_failures.dmarc_failures}</span>
                </div>
              </div>
            ) : (
              <div className="p-6 rounded-lg border border-dashed border-border text-center text-xs font-mono text-foreground-muted">
                No authentication checks recorded yet.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Recent Investigations Table */}
      <div className="bg-surface border border-border rounded-xl p-6 shadow-xs">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-5 border-b border-border pb-4">
          <div>
            <h2 className="text-base font-bold text-foreground font-sans flex items-center space-x-2">
              <FolderLock className="w-4 h-4 text-primary" />
              <span>Recent Investigations</span>
            </h2>
            <p className="text-xs text-foreground-muted font-mono mt-0.5">
              Active forensic case tracking and evidentiary custody
            </p>
          </div>
          <div className="flex items-center space-x-3">
            <button
              type="button"
              onClick={() => navigate('/cases')}
              className="text-xs font-mono text-primary hover:text-primary-hover font-semibold flex items-center space-x-1 cursor-pointer"
            >
              <span>SEE ALL INVESTIGATIONS</span>
              <ChevronRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead>
              <tr className="border-b border-border text-foreground-muted uppercase tracking-wider">
                <th className="py-2.5 px-3">Case</th>
                <th className="py-2.5 px-3">Severity</th>
                <th className="py-2.5 px-3">Status</th>
                <th className="py-2.5 px-3 text-center">Emails</th>
                <th className="py-2.5 px-3">Updated</th>
                <th className="py-2.5 px-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/60">
              {loading ? (
                [1, 2, 3].map((i) => (
                  <tr key={i}>
                    <td colSpan={6} className="py-3 px-3">
                      <div className="h-6 bg-surface-secondary rounded animate-pulse" />
                    </td>
                  </tr>
                ))
              ) : summary?.recent_cases && summary.recent_cases.length > 0 ? (
                summary.recent_cases.map((c) => {
                  const sevStyle = SEVERITY_CONFIG[c.severity?.toLowerCase()] || SEVERITY_CONFIG.low;
                  const statStyle = STATUS_CONFIG[c.status?.toLowerCase()] || STATUS_CONFIG.open;
                  return (
                    <tr
                      key={c.id}
                      onClick={() => navigate('/cases')}
                      className="hover:bg-surface-secondary/50 transition-colors cursor-pointer"
                    >
                      <td className="py-3 px-3 max-w-[320px]">
                        <div className="font-semibold text-foreground truncate">{c.title}</div>
                        <div className="text-[11px] text-primary font-mono">{c.case_number}</div>
                      </td>
                      <td className="py-3 px-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] border ${sevStyle.badge}`}>
                          {sevStyle.label}
                        </span>
                      </td>
                      <td className="py-3 px-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] border ${statStyle.badge}`}>
                          {statStyle.label}
                        </span>
                      </td>
                      <td className="py-3 px-3 text-center">
                        <span className="px-2 py-0.5 rounded bg-surface-secondary text-foreground-muted border border-border">
                          {c.emails_count} {c.emails_count === 1 ? 'email' : 'emails'}
                        </span>
                      </td>
                      <td className="py-3 px-3 text-foreground-muted">
                        {formatRelativeTime(c.updated_at)}
                      </td>
                      <td className="py-3 px-3 text-right">
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            navigate('/cases');
                          }}
                          className="px-2.5 py-1 rounded bg-surface-secondary hover:bg-surface text-foreground border border-border text-xs font-semibold inline-flex items-center space-x-1 cursor-pointer btn-press"
                        >
                          <span>OPEN</span>
                          <ArrowUpRight className="w-3 h-3" />
                        </button>
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-foreground-muted font-mono">
                    <div className="flex flex-col items-center justify-center space-y-2">
                      <FolderLock className="w-6 h-6 text-foreground-muted opacity-50" />
                      <span>No active investigation cases recorded.</span>
                      <button
                        type="button"
                        onClick={() => navigate('/cases')}
                        className="mt-2 inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-primary text-primary-foreground text-xs font-medium transition-colors btn-press cursor-pointer"
                      >
                        <Plus className="w-3.5 h-3.5" />
                        <span>CREATE FIRST CASE</span>
                      </button>
                    </div>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Recent Email Analyses Table */}
      <div className="bg-surface border border-border rounded-xl p-6 shadow-xs">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-5 border-b border-border pb-4">
          <div>
            <h2 className="text-base font-bold text-foreground font-sans flex items-center space-x-2">
              <Mail className="w-4 h-4 text-primary" />
              <span>Recent Email Analyses</span>
            </h2>
            <p className="text-xs text-foreground-muted font-mono mt-0.5">
              Live suspicious emails processed by Fraudulent Email Detection Engine
            </p>
          </div>
          <button
            type="button"
            onClick={() => navigate('/analyze')}
            className="text-xs font-mono text-primary hover:text-primary-hover font-semibold flex items-center space-x-1 self-start sm:self-auto cursor-pointer"
          >
            <span>INGEST NEW EMAIL</span>
            <ChevronRight className="w-3.5 h-3.5" />
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead>
              <tr className="border-b border-border text-foreground-muted uppercase tracking-wider">
                <th className="py-2.5 px-3">Subject</th>
                <th className="py-2.5 px-3">Sender</th>
                <th className="py-2.5 px-3 text-center">Threat Score</th>
                <th className="py-2.5 px-3">Severity</th>
                <th className="py-2.5 px-3">Timestamp</th>
                <th className="py-2.5 px-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/60">
              {loading ? (
                [1, 2, 3].map((i) => (
                  <tr key={i}>
                    <td colSpan={6} className="py-3 px-3">
                      <div className="h-6 bg-surface-secondary rounded animate-pulse" />
                    </td>
                  </tr>
                ))
              ) : summary?.recent_emails && summary.recent_emails.length > 0 ? (
                summary.recent_emails.map((email) => {
                  const sevStyle = SEVERITY_CONFIG[email.severity?.toLowerCase()] || SEVERITY_CONFIG.low;
                  const score = email.threat_score ?? 0;
                  const scoreColor =
                    score >= 80 ? 'text-danger bg-danger-surface border-danger-border' :
                    score >= 50 ? 'text-warning bg-warning-surface border-warning-border' :
                    score >= 25 ? 'text-warning/80 bg-warning-surface/50 border-warning-border/50' :
                    'text-success bg-success-surface border-success-border';

                  return (
                    <tr
                      key={email.id}
                      onClick={() => navigate(`/analysis/${email.id}`)}
                      className="hover:bg-surface-secondary/50 transition-colors cursor-pointer"
                    >
                      <td className="py-3 px-3 max-w-[280px]">
                        <div className="font-semibold text-foreground truncate">{email.subject}</div>
                        {email.evidence_id && (
                          <div className="text-[10px] text-primary font-mono">{email.evidence_id}</div>
                        )}
                      </td>
                      <td className="py-3 px-3 max-w-[240px]">
                        <div className="text-foreground-muted truncate">{email.sender}</div>
                      </td>
                      <td className="py-3 px-3 text-center">
                        <span className={`inline-block px-2.5 py-0.5 rounded text-xs font-bold border ${scoreColor}`}>
                          {score.toFixed(0)} / 100
                        </span>
                      </td>
                      <td className="py-3 px-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] border ${sevStyle.badge}`}>
                          {sevStyle.label}
                        </span>
                      </td>
                      <td className="py-3 px-3 text-foreground-muted">
                        {formatTimestamp(email.timestamp)}
                      </td>
                      <td className="py-3 px-3 text-right">
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            navigate(`/analysis/${email.id}`);
                          }}
                          className="px-2.5 py-1 rounded bg-primary-subtle text-primary hover:bg-primary/20 border border-primary/25 text-xs font-semibold inline-flex items-center space-x-1 cursor-pointer btn-press"
                        >
                          <span>INSPECT</span>
                          <ArrowUpRight className="w-3 h-3" />
                        </button>
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-foreground-muted font-mono">
                    <div className="flex flex-col items-center justify-center space-y-2">
                      <Mail className="w-6 h-6 text-foreground-muted opacity-50" />
                      <span>No parsed email analyses recorded yet.</span>
                      <button
                        type="button"
                        onClick={() => navigate('/analyze')}
                        className="mt-2 inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-primary text-primary-foreground text-xs font-medium transition-colors btn-press cursor-pointer"
                      >
                        <Zap className="w-3.5 h-3.5" />
                        <span>INGEST SUSPICIOUS EML</span>
                      </button>
                    </div>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
