import React, { useState, useEffect, useCallback, useMemo } from 'react';
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
  HardDrive
} from 'lucide-react';
import type { DashboardSummary } from '../types/dashboard';
import { getAllAvailableAnalyses } from '../utils/forensicStore';
import {
  DashboardService,
  type SystemHealthStatus,
  type EnrolledAgentSummary
} from '../services/dashboardService';
import { UniversalDropZone } from '../components/dashboard/UniversalDropZone';
import {
  Button,
  SearchInput,
  Badge,
  EmptyState,
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell
} from '../components/ui';
import {
  SeverityIndicator,
  ThreatScore,
  Timestamp,
  SourceBadge
} from '../components/security';
import { useInvestigation } from '../context/InvestigationContext';

interface InvestigationRowItem {
  id: string;
  evidenceId?: string;
  title: string;
  source: string;
  riskScore: number;
  severity: string;
  status: string;
  updatedAt?: string;
}

export const Dashboard: React.FC = () => {
  const navigate = useNavigate();
  const { setActiveEmailId } = useInvestigation();

  // Operational server state
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [health, setHealth] = useState<SystemHealthStatus | null>(null);
  const [agents, setAgents] = useState<EnrolledAgentSummary[]>([]);
  const [investigations, setInvestigations] = useState<InvestigationRowItem[]>([]);
  const [refreshing, setRefreshing] = useState<boolean>(false);

  // Local UI state
  const [searchQuery, setSearchQuery] = useState<string>('');

  // Fetch all authentic operational data from backend
  const loadOperationalData = useCallback(async () => {
    try {
      const [summaryRes, healthRes, agentsRes] = await Promise.all([
        DashboardService.getSummary(30, 20),
        DashboardService.getHealth(),
        DashboardService.getEnrolledAgents()
      ]);

      setSummary(summaryRes);
      setHealth(healthRes);
      setAgents(agentsRes);

      const rowsMap = new Map<string, InvestigationRowItem>();

      // 1. Ingested local analyses (real only, excluding demo scenarios)
      const localAnalyses = getAllAvailableAnalyses(false);
      localAnalyses
        .filter((a) => !a.id?.startsWith('scenario-'))
        .forEach((a) => {
          const rowId = a.id || a.evidence_id || 'unknown';
          const score = a.threat_score?.score ?? 0;
          const sev = a.threat_score?.severity || (score >= 80 ? 'critical' : score >= 50 ? 'high' : 'low');
          rowsMap.set(rowId, {
            id: rowId,
            evidenceId: a.evidence_id || undefined,
            title: a.subject || a.original_filename || 'Forensic Investigation',
            source: 'EMAIL',
            riskScore: score,
            severity: sev.toLowerCase(),
            status: 'ANALYZED',
            updatedAt: a.upload_timestamp || a.date
          });
        });

      // 2. Real backend recent emails
      if (summaryRes?.recent_emails) {
        summaryRes.recent_emails
          .filter((be) => !be.id.startsWith('scenario-'))
          .forEach((be) => {
            if (!rowsMap.has(be.id)) {
              rowsMap.set(be.id, {
                id: be.id,
                evidenceId: be.evidence_id || undefined,
                title: be.subject || be.original_filename || 'Security Investigation',
                source: 'EMAIL',
                riskScore: be.threat_score,
                severity: be.severity.toLowerCase(),
                status: 'ANALYZED',
                updatedAt: be.timestamp
              });
            }
          });
      }

      // 3. Real backend cases/incidents
      if (summaryRes?.recent_cases) {
        summaryRes.recent_cases.forEach((bc) => {
          if (!rowsMap.has(bc.id)) {
            rowsMap.set(bc.id, {
              id: bc.id,
              title: bc.title || `Case ${bc.case_number}`,
              source: 'INCIDENT',
              riskScore: bc.severity === 'critical' ? 90 : bc.severity === 'high' ? 70 : 40,
              severity: bc.severity.toLowerCase(),
              status: bc.status.toUpperCase(),
              updatedAt: bc.updated_at
            });
          }
        });
      }

      setInvestigations(Array.from(rowsMap.values()));
    } catch {
      // Graceful fallback to empty
    } finally {
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    loadOperationalData();
  }, [loadOperationalData]);

  const handleRefresh = () => {
    setRefreshing(true);
    loadOperationalData();
  };

  const handleOpenInvestigation = (id: string) => {
    setActiveEmailId(id);
    navigate(`/investigations/${id}/overview`);
  };

  // Filtered investigations for search
  const filteredInvestigations = useMemo(() => {
    if (!searchQuery.trim()) return investigations;
    const q = searchQuery.toLowerCase();
    return investigations.filter(
      (inv) =>
        inv.title.toLowerCase().includes(q) ||
        inv.id.toLowerCase().includes(q) ||
        inv.source.toLowerCase().includes(q) ||
        inv.status.toLowerCase().includes(q)
    );
  }, [investigations, searchQuery]);

  // Active / Attention Required investigations
  const attentionRequired = useMemo(() => {
    return investigations.filter(
      (inv) =>
        inv.severity === 'critical' ||
        inv.severity === 'high' ||
        inv.riskScore >= 60 ||
        inv.status === 'OPEN' ||
        inv.status === 'INVESTIGATING'
    );
  }, [investigations]);

  return (
    <div className="max-w-6xl w-full mx-auto py-6 px-4 sm:px-6 space-y-7 animate-fadeIn">
      {/* =========================================================================
          1. HEADER: Professional Workstation Heading
          ========================================================================= */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-border/70">
        <div>
          <div className="flex items-center space-x-2 text-primary font-mono text-xs font-semibold uppercase tracking-wider">
            <Activity className="w-3.5 h-3.5 text-primary" />
            <span>OPERATIONAL WORKSTATION</span>
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-foreground font-sans mt-0.5">
            Dashboard
          </h1>
          <p className="text-xs text-foreground-muted font-mono mt-1">
            Analyze evidence, investigate threats, and track active cases.
          </p>
        </div>

        <div className="flex items-center space-x-3 text-xs font-mono">
          <Button
            variant="secondary"
            size="sm"
            onClick={handleRefresh}
            disabled={refreshing}
            className="flex items-center space-x-1.5 cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin text-primary' : ''}`} />
            <span>Refresh</span>
          </Button>

          <Button
            variant="secondary"
            size="sm"
            onClick={() => navigate('/investigations')}
            className="flex items-center space-x-1.5 cursor-pointer"
          >
            <Layers className="w-3.5 h-3.5 text-foreground-muted" />
            <span>All Investigations</span>
          </Button>
        </div>
      </div>

      {/* =========================================================================
          2. TRUTHFUL QUICK METRICS & SYSTEM HEALTH BAR
          ========================================================================= */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {/* Active Investigations */}
        <div className="p-3.5 rounded-card bg-surface border border-border shadow-xs flex flex-col justify-between">
          <div className="flex items-center justify-between text-foreground-muted">
            <span className="text-[11px] font-mono uppercase tracking-wider">Active Cases</span>
            <FileCheck2 className="w-3.5 h-3.5 text-primary" />
          </div>
          <div className="mt-2 flex items-baseline space-x-2">
            <span className="text-xl font-bold font-mono text-foreground">
              {summary ? summary.metrics.open_cases : investigations.length}
            </span>
            <span className="text-[10px] font-mono text-foreground-subtle">cases</span>
          </div>
        </div>

        {/* High / Critical Threats */}
        <div className="p-3.5 rounded-card bg-surface border border-border shadow-xs flex flex-col justify-between">
          <div className="flex items-center justify-between text-foreground-muted">
            <span className="text-[11px] font-mono uppercase tracking-wider">High / Critical</span>
            <ShieldAlert className="w-3.5 h-3.5 text-rose-500" />
          </div>
          <div className="mt-2 flex items-baseline space-x-2">
            <span className="text-xl font-bold font-mono text-rose-500">
              {summary
                ? summary.metrics.critical_emails
                : attentionRequired.length}
            </span>
            <span className="text-[10px] font-mono text-foreground-subtle">threats</span>
          </div>
        </div>

        {/* Endpoint Fleet Agents */}
        <div className="p-3.5 rounded-card bg-surface border border-border shadow-xs flex flex-col justify-between">
          <div className="flex items-center justify-between text-foreground-muted">
            <span className="text-[11px] font-mono uppercase tracking-wider">Fleet Agents</span>
            <Terminal className="w-3.5 h-3.5 text-foreground-muted" />
          </div>
          <div className="mt-2 flex items-baseline space-x-2">
            <span className="text-xl font-bold font-mono text-foreground">
              {agents.length}
            </span>
            <span className="text-[10px] font-mono text-foreground-subtle">enrolled</span>
          </div>
        </div>

        {/* System & Engine Health */}
        <div className="p-3.5 rounded-card bg-surface border border-border shadow-xs flex flex-col justify-between">
          <div className="flex items-center justify-between text-foreground-muted">
            <span className="text-[11px] font-mono uppercase tracking-wider">Analysis Engine</span>
            <Server className="w-3.5 h-3.5 text-foreground-muted" />
          </div>
          <div className="mt-2 flex items-center space-x-1.5">
            <span
              className={`w-2 h-2 rounded-full ${
                health?.status === 'ok'
                  ? 'bg-emerald-500'
                  : health?.status === 'degraded'
                  ? 'bg-amber-500'
                  : 'bg-rose-500'
              }`}
            />
            <span className="text-xs font-semibold font-mono text-foreground uppercase">
              {health?.status === 'ok'
                ? 'Operational'
                : health?.status === 'degraded'
                ? 'Degraded'
                : health?.status || 'Online'}
            </span>
          </div>
        </div>
      </div>

      {/* =========================================================================
          3. UNIVERSAL INGESTION SURFACE (VISUALLY DOMINATES THE LANDING PAGE)
          ========================================================================= */}
      <section className="space-y-2">
        <div className="flex items-center justify-between">
          <h2 className="text-xs font-mono font-semibold uppercase tracking-wider text-foreground-muted flex items-center gap-2">
            <span>Analyze something</span>
            <span className="text-[9px] px-1.5 py-0.2 rounded bg-primary/10 text-primary font-bold">
              UNIVERSAL GATEWAY
            </span>
          </h2>
          <span className="text-[11px] font-mono text-foreground-subtle">
            Drop evidence, paste a URL, or upload a file
          </span>
        </div>

        <UniversalDropZone onIngestionSuccess={loadOperationalData} />
      </section>

      {/* =========================================================================
          4. ACTIVE / ATTENTION REQUIRED
          ========================================================================= */}
      <section className="space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="text-xs font-mono font-semibold uppercase tracking-wider text-foreground-muted flex items-center gap-2">
            <span>Active / Attention Required</span>
            {attentionRequired.length > 0 && (
              <span className="text-[10px] px-1.5 py-0.2 rounded bg-rose-500/10 text-rose-500 font-mono font-bold">
                {attentionRequired.length} ITEMS
              </span>
            )}
          </h2>
        </div>

        {attentionRequired.length === 0 ? (
          <div className="p-4 rounded-card bg-surface border border-border text-center text-xs font-mono text-foreground-muted flex items-center justify-center space-x-2">
            <ShieldCheck className="w-4 h-4 text-emerald-500" />
            <span>Nothing requires attention</span>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {attentionRequired.slice(0, 4).map((item) => (
              <div
                key={item.id}
                onClick={() => handleOpenInvestigation(item.id)}
                className="p-4 rounded-card bg-surface border border-border hover:border-primary/50 transition-all cursor-pointer group flex flex-col justify-between space-y-3"
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="space-y-1 min-w-0">
                    <div className="flex items-center space-x-2">
                      <SourceBadge source={item.source} size="sm" />
                      <SeverityIndicator severity={item.severity} showText size="sm" />
                    </div>
                    <h3 className="text-xs font-semibold text-foreground group-hover:text-primary transition-colors truncate">
                      {item.title}
                    </h3>
                  </div>
                  <ThreatScore score={item.riskScore} variant="compact" />
                </div>

                <div className="flex items-center justify-between text-[11px] font-mono text-foreground-muted pt-2 border-t border-border/50">
                  <div className="flex items-center space-x-1.5">
                    <Timestamp date={item.updatedAt || new Date()} format="relative" />
                  </div>
                  <span className="text-primary flex items-center space-x-0.5 group-hover:translate-x-0.5 transition-transform">
                    <span>Investigate</span>
                    <ChevronRight className="w-3 h-3" />
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      {/* =========================================================================
          5. RECENT INVESTIGATIONS
          ========================================================================= */}
      <section className="space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <h2 className="text-xs font-mono font-semibold uppercase tracking-wider text-foreground-muted">
            Recent Investigations
          </h2>

          <div className="w-full sm:w-64">
            <SearchInput
              value={searchQuery}
              onChangeValue={(val) => setSearchQuery(val)}
              onClear={() => setSearchQuery('')}
              placeholder="Search investigations..."
              size="sm"
            />
          </div>
        </div>

        {filteredInvestigations.length === 0 ? (
          <EmptyState
            icon={<HardDrive className="w-6 h-6" />}
            title="No investigations yet"
            description="Drop an email, URL, file, log, or media artifact above to begin."
            className="py-12 bg-surface rounded-card border border-border"
          />
        ) : (
          <div className="rounded-card border border-border bg-surface overflow-hidden shadow-xs">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="font-mono text-xs">Investigation</TableHead>
                  <TableHead className="font-mono text-xs">Source</TableHead>
                  <TableHead className="font-mono text-xs">Threat Score</TableHead>
                  <TableHead className="font-mono text-xs">Severity</TableHead>
                  <TableHead className="font-mono text-xs">Status</TableHead>
                  <TableHead className="font-mono text-xs text-right">Updated</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredInvestigations.slice(0, 10).map((row) => (
                  <TableRow
                    key={row.id}
                    onClick={() => handleOpenInvestigation(row.id)}
                    className="cursor-pointer hover:bg-surface-secondary/50 transition-colors group"
                  >
                    <TableCell>
                      <div className="flex items-center space-x-2 min-w-0">
                        <div className="truncate">
                          <span className="text-xs font-medium text-foreground group-hover:text-primary transition-colors">
                            {row.title}
                          </span>
                          <span className="block text-[10px] font-mono text-foreground-subtle">
                            ID: {row.evidenceId || row.id}
                          </span>
                        </div>
                      </div>
                    </TableCell>
                    <TableCell>
                      <SourceBadge source={row.source} size="sm" />
                    </TableCell>
                    <TableCell>
                      <ThreatScore score={row.riskScore} variant="compact" />
                    </TableCell>
                    <TableCell>
                      <SeverityIndicator severity={row.severity} showText size="sm" />
                    </TableCell>
                    <TableCell>
                      <Badge variant="neutral" size="sm" className="font-mono text-[10px]">
                        {row.status}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="text-[11px] font-mono text-foreground-muted">
                        <Timestamp date={row.updatedAt || new Date()} format="relative" />
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </section>
    </div>
  );
};
