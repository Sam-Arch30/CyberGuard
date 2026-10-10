import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ShieldAlert,
  Search,
  Plus,
  RefreshCw,
  Clock,
  User,
  AlertTriangle,
  CheckCircle2,
  ChevronRight,
  Sparkles,
  Layers,
  ShieldCheck,
  XCircle,
  Copy,
  Check,
} from 'lucide-react';
import { IncidentService, type IncidentListParams } from '../../services/incidentService';
import type {
  IncidentItem,
  IncidentMetrics,
  IncidentStatus,
  IncidentSeverity,
  IncidentPriority,
  IncidentCategory,
} from '../../types/incident';

const STATUS_CONFIG: Record<IncidentStatus, { label: string; badge: string; border: string }> = {
  NEW: { label: 'New', badge: 'bg-primary-subtle text-primary border-primary/30', border: 'border-primary/40' },
  OPEN: { label: 'Open', badge: 'bg-surface-secondary text-foreground border-border', border: 'border-border' },
  ACKNOWLEDGED: { label: 'Acknowledged', badge: 'bg-info-surface text-info border-info-border', border: 'border-info-border' },
  INVESTIGATING: { label: 'Investigating', badge: 'bg-warning-surface text-warning border-warning-border', border: 'border-warning-border' },
  CONTAINED: { label: 'Contained', badge: 'bg-indigo-500/10 text-indigo-400 border-indigo-500/30', border: 'border-indigo-500/30' },
  RESOLVED: { label: 'Resolved', badge: 'bg-success-surface text-success border-success-border', border: 'border-success-border' },
  CLOSED: { label: 'Closed', badge: 'bg-surface-secondary text-foreground-muted border-border', border: 'border-border' },
  FALSE_POSITIVE: { label: 'False Positive', badge: 'bg-surface-secondary text-foreground-muted border-border line-through', border: 'border-border' },
  DUPLICATE: { label: 'Duplicate', badge: 'bg-surface-secondary text-foreground-muted border-border', border: 'border-border' },
  CANCELLED: { label: 'Cancelled', badge: 'bg-surface-secondary text-foreground-muted border-border', border: 'border-border' },
};

const SEVERITY_CONFIG: Record<IncidentSeverity, { label: string; badge: string }> = {
  CRITICAL: { label: 'Critical', badge: 'bg-danger-surface text-danger border-danger-border font-bold' },
  HIGH: { label: 'High', badge: 'bg-warning-surface text-warning border-warning-border font-semibold' },
  MEDIUM: { label: 'Medium', badge: 'bg-warning-surface/60 text-warning border-warning-border/60' },
  LOW: { label: 'Low', badge: 'bg-surface-secondary text-foreground-muted border-border' },
  INFO: { label: 'Info', badge: 'bg-surface-secondary text-foreground-muted border-border' },
};

const PRIORITY_CONFIG: Record<IncidentPriority, { label: string; badge: string }> = {
  P1_CRITICAL: { label: 'P1 - Critical', badge: 'bg-red-500/20 text-red-400 border-red-500/40 font-bold' },
  P2_HIGH: { label: 'P2 - High', badge: 'bg-amber-500/20 text-amber-400 border-amber-500/40 font-semibold' },
  P3_MEDIUM: { label: 'P3 - Medium', badge: 'bg-blue-500/20 text-blue-400 border-blue-500/40' },
  P4_LOW: { label: 'P4 - Low', badge: 'bg-surface-secondary text-foreground-muted border-border' },
};

export const IncidentListPage: React.FC = () => {
  const navigate = useNavigate();

  const [incidents, setIncidents] = useState<IncidentItem[]>([]);
  const [metrics, setMetrics] = useState<IncidentMetrics | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [metricsLoading, setMetricsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Filters
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [priorityFilter, setPriorityFilter] = useState<string>('ALL');
  const [categoryFilter, setCategoryFilter] = useState<string>('ALL');
  const [slaFilter, setSlaFilter] = useState<string>('ALL');
  const [sortBy, setSortBy] = useState<string>('default');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [page, setPage] = useState<number>(1);
  const limit = 20;
  const [totalCount, setTotalCount] = useState<number>(0);

  // Create Incident Modal State
  const [showCreateModal, setShowCreateModal] = useState<boolean>(false);
  const [newTitle, setNewTitle] = useState<string>('');
  const [newDescription, setNewDescription] = useState<string>('');
  const [newSeverity, setNewSeverity] = useState<IncidentSeverity>('MEDIUM');
  const [newPriority, setNewPriority] = useState<IncidentPriority>('P3_MEDIUM');
  const [newCategory, setNewCategory] = useState<IncidentCategory>('OTHER');
  const [creating, setCreating] = useState<boolean>(false);
  const [createError, setCreateError] = useState<string | null>(null);

  const loadMetrics = useCallback(async () => {
    try {
      setMetricsLoading(true);
      const res = await IncidentService.getMetrics();
      setMetrics(res);
    } catch {
      // Non-fatal if metrics fails
    } finally {
      setMetricsLoading(false);
    }
  }, []);

  const loadIncidents = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const params: IncidentListParams = {
        limit,
        offset: (page - 1) * limit,
      };
      if (statusFilter !== 'ALL') params.status = statusFilter as IncidentStatus;
      if (severityFilter !== 'ALL') params.severity = severityFilter as IncidentSeverity;
      if (priorityFilter !== 'ALL') params.priority = priorityFilter as IncidentPriority;
      if (categoryFilter !== 'ALL') params.category = categoryFilter as IncidentCategory;
      if (slaFilter !== 'ALL') params.sla_status = slaFilter as any;
      if (sortBy !== 'default') params.sort_by = sortBy;
      if (searchQuery.trim()) params.search = searchQuery.trim();

      const res = await IncidentService.listIncidents(params);
      setIncidents(res.items);
      setTotalCount(res.total);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to fetch incident queue.';
      setError(msg);
    } finally {
      setLoading(false);
    }
  }, [page, statusFilter, severityFilter, priorityFilter, categoryFilter, slaFilter, sortBy, searchQuery]);

  useEffect(() => {
    loadMetrics();
  }, [loadMetrics]);

  useEffect(() => {
    loadIncidents();
  }, [loadIncidents]);

  const handleCopy = (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(id);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleCreateSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTitle.trim()) {
      setCreateError('Incident title is required.');
      return;
    }
    try {
      setCreating(true);
      setCreateError(null);
      const created = await IncidentService.createIncident({
        title: newTitle.trim(),
        description: newDescription.trim() || undefined,
        severity: newSeverity,
        priority: newPriority,
        category: newCategory,
      });
      setShowCreateModal(false);
      setNewTitle('');
      setNewDescription('');
      loadMetrics();
      navigate(`/incidents/${created.id}`);
    } catch (err: unknown) {
      setCreateError(err instanceof Error ? err.message : 'Failed to create incident.');
    } finally {
      setCreating(false);
    }
  };

  const totalPages = Math.ceil(totalCount / limit) || 1;

  return (
    <div className="space-y-6">
      {/* 1. Header & Quick Actions */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-primary/10 border border-primary/20 rounded-control text-primary">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-foreground">Incident Management</h1>
              <p className="text-xs text-foreground-muted">
                Section 50 — Operational Security Case Lifecycle & Triage Queue
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center space-x-2">
          <button
            type="button"
            onClick={() => {
              loadIncidents();
              loadMetrics();
            }}
            disabled={loading}
            className="px-3 py-1.5 text-xs font-medium text-foreground bg-surface border border-border rounded-control hover:bg-surface-secondary flex items-center space-x-1.5 cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>

          <button
            type="button"
            onClick={() => setShowCreateModal(true)}
            className="px-3 py-1.5 text-xs font-semibold text-white bg-primary hover:bg-primary-hover rounded-control flex items-center space-x-1.5 cursor-pointer shadow-xs"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Escalate Case</span>
          </button>
        </div>
      </div>

      {/* 2. Operational Metrics Ribbon (Section 51 SLA telemetry integrated) */}
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-2.5">
        <div className="p-3 bg-surface border border-border rounded-control flex flex-col justify-between">
          <span className="text-[10px] font-mono uppercase text-foreground-muted">Open Cases</span>
          <span className="text-xl font-bold text-foreground mt-1">
            {metricsLoading ? '—' : metrics?.open_incidents ?? 0}
          </span>
          <span className="text-[10px] text-foreground-muted mt-0.5">Active SOC queue</span>
        </div>

        <div className="p-3 bg-surface border border-border rounded-control flex flex-col justify-between">
          <span className="text-[10px] font-mono uppercase text-danger">Critical Cases</span>
          <span className="text-xl font-bold text-danger mt-1">
            {metricsLoading ? '—' : metrics?.critical_incidents ?? 0}
          </span>
          <span className="text-[10px] text-foreground-muted mt-0.5">Urgent triage</span>
        </div>

        <div className="p-3 bg-surface border border-border rounded-control flex flex-col justify-between">
          <span className="text-[10px] font-mono uppercase text-red-400 font-bold">SLA Breaches</span>
          <span className="text-xl font-bold text-red-400 mt-1">
            {metricsLoading ? '—' : metrics?.sla_breaches ?? 0}
          </span>
          <span className="text-[10px] text-foreground-muted mt-0.5">Target overdue</span>
        </div>

        <div className="p-3 bg-surface border border-border rounded-control flex flex-col justify-between">
          <span className="text-[10px] font-mono uppercase text-amber-400 font-bold">Approaching SLA</span>
          <span className="text-xl font-bold text-amber-400 mt-1">
            {metricsLoading ? '—' : metrics?.approaching_sla ?? 0}
          </span>
          <span className="text-[10px] text-foreground-muted mt-0.5">Warning threshold</span>
        </div>

        <div className="p-3 bg-surface border border-border rounded-control flex flex-col justify-between">
          <span className="text-[10px] font-mono uppercase text-rose-400 font-bold">Escalated</span>
          <span className="text-xl font-bold text-rose-400 mt-1">
            {metricsLoading ? '—' : metrics?.escalated_incidents ?? 0}
          </span>
          <span className="text-[10px] text-foreground-muted mt-0.5">Tier 2+ Active</span>
        </div>

        <div className="p-3 bg-surface border border-border rounded-control flex flex-col justify-between">
          <span className="text-[10px] font-mono uppercase text-warning">Investigating</span>
          <span className="text-xl font-bold text-warning mt-1">
            {metricsLoading ? '—' : metrics?.investigating_incidents ?? 0}
          </span>
          <span className="text-[10px] text-foreground-muted mt-0.5">In deep analysis</span>
        </div>

        <div className="p-3 bg-surface border border-border rounded-control flex flex-col justify-between">
          <span className="text-[10px] font-mono uppercase text-indigo-400">Contained</span>
          <span className="text-xl font-bold text-indigo-400 mt-1">
            {metricsLoading ? '—' : metrics?.contained_incidents ?? 0}
          </span>
          <span className="text-[10px] text-foreground-muted mt-0.5">Threat isolated</span>
        </div>

        <div className="p-3 bg-surface border border-border rounded-control flex flex-col justify-between">
          <span className="text-[10px] font-mono uppercase text-foreground-muted">Unassigned</span>
          <span className="text-xl font-bold text-foreground mt-1">
            {metricsLoading ? '—' : metrics?.unassigned_incidents ?? 0}
          </span>
          <span className="text-[10px] text-foreground-muted mt-0.5">Needs ownership</span>
        </div>
      </div>

      {/* 3. Filters & Search Bar */}
      <div className="p-3 bg-surface border border-border rounded-control flex flex-wrap items-center gap-3">
        <div className="flex-1 min-w-[220px] relative">
          <Search className="w-3.5 h-3.5 text-foreground-muted absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => {
              setSearchQuery(e.target.value);
              setPage(1);
            }}
            placeholder="Search incident number, title, actor..."
            className="w-full pl-8 pr-3 py-1.5 text-xs bg-surface-secondary border border-border rounded-control text-foreground placeholder:text-foreground-muted focus:outline-hidden focus:border-primary"
          />
        </div>

        {/* Status Filter */}
        <select
          value={statusFilter}
          onChange={(e) => {
            setStatusFilter(e.target.value);
            setPage(1);
          }}
          className="px-2.5 py-1.5 text-xs bg-surface-secondary border border-border rounded-control text-foreground focus:outline-hidden focus:border-primary cursor-pointer"
        >
          <option value="ALL">All Statuses</option>
          <option value="NEW">New</option>
          <option value="OPEN">Open</option>
          <option value="ACKNOWLEDGED">Acknowledged</option>
          <option value="INVESTIGATING">Investigating</option>
          <option value="CONTAINED">Contained</option>
          <option value="RESOLVED">Resolved</option>
          <option value="CLOSED">Closed</option>
          <option value="FALSE_POSITIVE">False Positive</option>
          <option value="DUPLICATE">Duplicate</option>
        </select>

        {/* Severity Filter */}
        <select
          value={severityFilter}
          onChange={(e) => {
            setSeverityFilter(e.target.value);
            setPage(1);
          }}
          className="px-2.5 py-1.5 text-xs bg-surface-secondary border border-border rounded-control text-foreground focus:outline-hidden focus:border-primary cursor-pointer"
        >
          <option value="ALL">All Severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
          <option value="INFO">Info</option>
        </select>

        {/* Priority Filter */}
        <select
          value={priorityFilter}
          onChange={(e) => {
            setPriorityFilter(e.target.value);
            setPage(1);
          }}
          className="px-2.5 py-1.5 text-xs bg-surface-secondary border border-border rounded-control text-foreground focus:outline-hidden focus:border-primary cursor-pointer"
        >
          <option value="ALL">All Priorities</option>
          <option value="P1_CRITICAL">P1 - Critical</option>
          <option value="P2_HIGH">P2 - High</option>
          <option value="P3_MEDIUM">P3 - Medium</option>
          <option value="P4_LOW">P4 - Low</option>
        </select>

        {/* Category Filter */}
        <select
          value={categoryFilter}
          onChange={(e) => {
            setCategoryFilter(e.target.value);
            setPage(1);
          }}
          className="px-2.5 py-1.5 text-xs bg-surface-secondary border border-border rounded-control text-foreground focus:outline-hidden focus:border-primary cursor-pointer"
        >
          <option value="ALL">All Categories</option>
          <option value="PHISHING">Phishing</option>
          <option value="CREDENTIAL_COMPROMISE">Credential Compromise</option>
          <option value="MALWARE">Malware</option>
          <option value="ACCOUNT_TAKEOVER">Account Takeover</option>
          <option value="DATA_EXFILTRATION">Data Exfiltration</option>
          <option value="IMPERSONATION">Impersonation</option>
          <option value="NETWORK_INTRUSION">Network Intrusion</option>
          <option value="OTHER">Other</option>
        </select>

        {/* SLA Status Filter (Section 51) */}
        <select
          value={slaFilter}
          onChange={(e) => {
            setSlaFilter(e.target.value);
            setPage(1);
          }}
          className="px-2.5 py-1.5 text-xs bg-surface-secondary border border-border rounded-control text-foreground focus:outline-hidden focus:border-primary cursor-pointer font-mono"
        >
          <option value="ALL">All SLA States</option>
          <option value="BREACHED">Breached</option>
          <option value="WARNING">Approaching (Warning)</option>
          <option value="ON_TRACK">On Track</option>
          <option value="PAUSED">Paused</option>
          <option value="EXEMPT">Exempt</option>
        </select>

        {/* Sort By Dropdown (Section 51) */}
        <select
          value={sortBy}
          onChange={(e) => {
            setSortBy(e.target.value);
            setPage(1);
          }}
          className="px-2.5 py-1.5 text-xs bg-surface-secondary border border-border rounded-control text-foreground focus:outline-hidden focus:border-primary cursor-pointer font-mono"
        >
          <option value="default">Sort: Most Urgent</option>
          <option value="sla_breach_first">Sort: SLA Breach First</option>
          <option value="closest_deadline">Sort: Closest Deadline</option>
          <option value="severity">Sort: Highest Severity</option>
          <option value="priority">Sort: Highest Priority</option>
          <option value="newest">Sort: Newest</option>
          <option value="oldest">Sort: Oldest</option>
        </select>

        {(statusFilter !== 'ALL' ||
          severityFilter !== 'ALL' ||
          priorityFilter !== 'ALL' ||
          categoryFilter !== 'ALL' ||
          slaFilter !== 'ALL' ||
          sortBy !== 'default' ||
          searchQuery) && (
          <button
            type="button"
            onClick={() => {
              setStatusFilter('ALL');
              setSeverityFilter('ALL');
              setPriorityFilter('ALL');
              setCategoryFilter('ALL');
              setSlaFilter('ALL');
              setSortBy('default');
              setSearchQuery('');
              setPage(1);
            }}
            className="text-xs text-primary hover:underline cursor-pointer"
          >
            Clear Filters
          </button>
        )}
      </div>

      {/* 4. Incident Queue Table */}
      <div className="bg-surface border border-border rounded-control overflow-hidden">
        {error && (
          <div className="p-4 bg-danger-surface border-b border-danger-border text-xs text-danger flex items-center space-x-2">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-border bg-surface-secondary/50 font-mono text-[11px] uppercase text-foreground-muted">
                <th className="py-2.5 px-3">Case ID</th>
                <th className="py-2.5 px-3">Title & Category</th>
                <th className="py-2.5 px-3">Severity</th>
                <th className="py-2.5 px-3">Priority</th>
                <th className="py-2.5 px-3">Status</th>
                <th className="py-2.5 px-3">SLA &amp; Tier</th>
                <th className="py-2.5 px-3">Assigned To</th>
                <th className="py-2.5 px-3">Age</th>
                <th className="py-2.5 px-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {loading && incidents.length === 0 ? (
                <tr>
                  <td colSpan={9} className="py-12 text-center text-foreground-muted">
                    <div className="flex flex-col items-center justify-center space-y-2">
                      <RefreshCw className="w-5 h-5 animate-spin text-primary" />
                      <span>Loading operational cases...</span>
                    </div>
                  </td>
                </tr>
              ) : incidents.length === 0 ? (
                <tr>
                  <td colSpan={9} className="py-12 text-center text-foreground-muted">
                    <div className="flex flex-col items-center justify-center space-y-2">
                      <ShieldCheck className="w-8 h-8 text-foreground-muted/60" />
                      <p className="font-medium text-foreground">No incidents found matching criteria</p>
                      <p className="text-[11px] text-foreground-muted">
                        Alerts and Alert Clusters can be promoted directly from the Alert Workspace.
                      </p>
                    </div>
                  </td>
                </tr>
              ) : (
                incidents.map((inc) => {
                  const statusCfg = STATUS_CONFIG[inc.status] || STATUS_CONFIG.OPEN;
                  const sevCfg = SEVERITY_CONFIG[inc.severity] || SEVERITY_CONFIG.MEDIUM;
                  const prioCfg = PRIORITY_CONFIG[inc.priority] || PRIORITY_CONFIG.P3_MEDIUM;

                  return (
                    <tr
                      key={inc.id}
                      onClick={() => navigate(`/incidents/${inc.id}`)}
                      className="hover:bg-surface-secondary/40 transition-colors cursor-pointer group"
                    >
                      {/* Case ID */}
                      <td className="py-3 px-3 whitespace-nowrap">
                        <div className="flex items-center space-x-1.5 font-mono font-bold text-foreground group-hover:text-primary transition-colors">
                          <span>{inc.incident_number}</span>
                          <button
                            type="button"
                            onClick={(e) => handleCopy(inc.incident_number, e)}
                            className="text-foreground-muted hover:text-foreground opacity-0 group-hover:opacity-100 transition-opacity p-0.5"
                            title="Copy incident number"
                          >
                            {copiedId === inc.incident_number ? (
                              <Check className="w-3 h-3 text-success" />
                            ) : (
                              <Copy className="w-3 h-3" />
                            )}
                          </button>
                        </div>
                        {inc.primary_cluster_id && (
                          <div className="flex items-center space-x-1 text-[10px] text-indigo-400 mt-0.5">
                            <Layers className="w-2.5 h-2.5" />
                            <span>Clustered</span>
                          </div>
                        )}
                      </td>

                      {/* Title & Category */}
                      <td className="py-3 px-3">
                        <div className="font-semibold text-foreground line-clamp-1 max-w-sm">
                          {inc.title}
                        </div>
                        <div className="flex items-center space-x-2 mt-0.5 text-[10px] text-foreground-muted">
                          <span className="font-mono uppercase">{inc.category.replace(/_/g, ' ')}</span>
                          {inc.description && (
                            <>
                              <span>•</span>
                              <span className="truncate max-w-xs">{inc.description}</span>
                            </>
                          )}
                        </div>
                      </td>

                      {/* Severity */}
                      <td className="py-3 px-3 whitespace-nowrap">
                        <span className={`px-2 py-0.5 rounded-xs border text-[10px] ${sevCfg.badge}`}>
                          {sevCfg.label}
                        </span>
                      </td>

                      {/* Priority */}
                      <td className="py-3 px-3 whitespace-nowrap">
                        <span className={`px-2 py-0.5 rounded-xs border text-[10px] ${prioCfg.badge}`}>
                          {prioCfg.label}
                        </span>
                      </td>

                      {/* Status */}
                      <td className="py-3 px-3 whitespace-nowrap">
                        <span className={`px-2 py-0.5 rounded-xs border text-[10px] ${statusCfg.badge}`}>
                          {statusCfg.label}
                        </span>
                      </td>

                      {/* SLA Status & Escalation Tier (Section 51) */}
                      <td className="py-3 px-3 whitespace-nowrap">
                        <div className="flex items-center space-x-1.5 font-mono text-[10px]">
                          {inc.sla_status === 'BREACHED' ? (
                            <span className="px-1.5 py-0.5 rounded border bg-red-500/20 text-red-400 border-red-500/40 font-bold flex items-center space-x-1">
                              <AlertTriangle className="w-2.5 h-2.5" />
                              <span>{inc.overdue_display ? `+${inc.overdue_display}` : 'BREACHED'}</span>
                            </span>
                          ) : inc.sla_status === 'WARNING' ? (
                            <span className="px-1.5 py-0.5 rounded border bg-amber-500/20 text-amber-400 border-amber-500/40 font-bold flex items-center space-x-1">
                              <Clock className="w-2.5 h-2.5" />
                              <span>{inc.remaining_display ? `${inc.remaining_display}` : 'WARN'}</span>
                            </span>
                          ) : inc.sla_status === 'MET' ? (
                            <span className="px-1.5 py-0.5 rounded border bg-emerald-500/15 text-emerald-400 border-emerald-500/30">
                              MET
                            </span>
                          ) : inc.sla_status === 'PAUSED' ? (
                            <span className="px-1.5 py-0.5 rounded border bg-amber-500/10 text-amber-400 border-amber-500/20">
                              PAUSED
                            </span>
                          ) : inc.sla_status === 'EXEMPT' ? (
                            <span className="px-1.5 py-0.5 rounded border bg-surface-secondary text-foreground-muted border-border">
                              EXEMPT
                            </span>
                          ) : inc.sla_status === 'ON_TRACK' ? (
                            <span className="px-1.5 py-0.5 rounded border bg-blue-500/15 text-blue-400 border-blue-500/30">
                              {inc.remaining_display ? `${inc.remaining_display}` : 'ON TRACK'}
                            </span>
                          ) : (
                            <span className="text-foreground-muted text-[10px]">No SLA</span>
                          )}

                          {inc.escalation_level && inc.escalation_level > 1 && (
                            <span
                              className="px-1 py-0.2 rounded bg-rose-500/20 text-rose-400 border border-rose-500/40 font-bold text-[9px]"
                              title={`Escalated to Tier ${inc.escalation_level}`}
                            >
                              L{inc.escalation_level}
                            </span>
                          )}
                        </div>
                      </td>

                      {/* Assigned Analyst */}
                      <td className="py-3 px-3 whitespace-nowrap">
                        <div className="flex items-center space-x-1.5 text-foreground-muted">
                          <User className="w-3.5 h-3.5 text-foreground-muted/80" />
                          <span className={inc.assigned_to ? 'text-foreground font-medium' : 'italic'}>
                            {inc.assigned_to || 'Unassigned'}
                          </span>
                        </div>
                      </td>

                      {/* Age */}
                      <td className="py-3 px-3 whitespace-nowrap text-foreground-muted font-mono text-[11px]">
                        <div className="flex items-center space-x-1">
                          <Clock className="w-3 h-3 text-foreground-muted/70" />
                          <span>{inc.age_display}</span>
                        </div>
                      </td>

                      {/* Actions */}
                      <td className="py-3 px-3 whitespace-nowrap text-right">
                        <div className="flex items-center justify-end space-x-1">
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              navigate(`/incidents/${inc.id}`);
                            }}
                            className="p-1 text-foreground-muted hover:text-foreground hover:bg-surface-secondary rounded-control"
                            title="Open Incident Detail"
                          >
                            <ChevronRight className="w-4 h-4" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Footer */}
        <div className="p-3 border-t border-border flex items-center justify-between text-xs text-foreground-muted bg-surface">
          <div>
            Showing {incidents.length > 0 ? (page - 1) * limit + 1 : 0} to{' '}
            {Math.min(page * limit, totalCount)} of {totalCount} cases
          </div>
          <div className="flex items-center space-x-2">
            <button
              type="button"
              disabled={page <= 1}
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              className="px-2.5 py-1 bg-surface-secondary border border-border rounded-control text-foreground disabled:opacity-40 disabled:cursor-not-allowed hover:bg-surface cursor-pointer"
            >
              Previous
            </button>
            <span className="font-mono text-[11px]">
              Page {page} of {totalPages}
            </span>
            <button
              type="button"
              disabled={page >= totalPages}
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              className="px-2.5 py-1 bg-surface-secondary border border-border rounded-control text-foreground disabled:opacity-40 disabled:cursor-not-allowed hover:bg-surface cursor-pointer"
            >
              Next
            </button>
          </div>
        </div>
      </div>

      {/* 5. Escalate Case Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-surface border border-border rounded-control w-full max-w-lg shadow-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-150">
            <div className="p-4 border-b border-border flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <Sparkles className="w-4 h-4 text-primary" />
                <h3 className="text-sm font-bold text-foreground">Escalate New Operational Case</h3>
              </div>
              <button
                type="button"
                onClick={() => setShowCreateModal(false)}
                className="text-foreground-muted hover:text-foreground cursor-pointer"
              >
                <XCircle className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleCreateSubmit} className="p-4 space-y-4 text-xs">
              {createError && (
                <div className="p-2.5 bg-danger-surface border border-danger-border rounded-control text-danger text-[11px] flex items-center space-x-1.5">
                  <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                  <span>{createError}</span>
                </div>
              )}

              <div>
                <label className="block font-medium text-foreground mb-1">Incident Title *</label>
                <input
                  type="text"
                  required
                  value={newTitle}
                  onChange={(e) => setNewTitle(e.target.value)}
                  placeholder="e.g. Credential Phishing Campaign — Finance Department"
                  className="w-full px-3 py-2 bg-surface-secondary border border-border rounded-control text-foreground placeholder:text-foreground-muted focus:outline-hidden focus:border-primary text-xs"
                />
              </div>

              <div>
                <label className="block font-medium text-foreground mb-1">Description / Summary</label>
                <textarea
                  rows={3}
                  value={newDescription}
                  onChange={(e) => setNewDescription(e.target.value)}
                  placeholder="Summarize the threat indicators, affected users, and initial operational context..."
                  className="w-full px-3 py-2 bg-surface-secondary border border-border rounded-control text-foreground placeholder:text-foreground-muted focus:outline-hidden focus:border-primary text-xs"
                />
              </div>

              <div className="grid grid-cols-3 gap-3">
                <div>
                  <label className="block font-medium text-foreground mb-1">Severity</label>
                  <select
                    value={newSeverity}
                    onChange={(e) => setNewSeverity(e.target.value as IncidentSeverity)}
                    className="w-full px-2.5 py-1.5 bg-surface-secondary border border-border rounded-control text-foreground focus:outline-hidden focus:border-primary text-xs"
                  >
                    <option value="CRITICAL">Critical</option>
                    <option value="HIGH">High</option>
                    <option value="MEDIUM">Medium</option>
                    <option value="LOW">Low</option>
                    <option value="INFO">Info</option>
                  </select>
                </div>

                <div>
                  <label className="block font-medium text-foreground mb-1">Priority</label>
                  <select
                    value={newPriority}
                    onChange={(e) => setNewPriority(e.target.value as IncidentPriority)}
                    className="w-full px-2.5 py-1.5 bg-surface-secondary border border-border rounded-control text-foreground focus:outline-hidden focus:border-primary text-xs"
                  >
                    <option value="P1_CRITICAL">P1 - Critical</option>
                    <option value="P2_HIGH">P2 - High</option>
                    <option value="P3_MEDIUM">P3 - Medium</option>
                    <option value="P4_LOW">P4 - Low</option>
                  </select>
                </div>

                <div>
                  <label className="block font-medium text-foreground mb-1">Category</label>
                  <select
                    value={newCategory}
                    onChange={(e) => setNewCategory(e.target.value as IncidentCategory)}
                    className="w-full px-2.5 py-1.5 bg-surface-secondary border border-border rounded-control text-foreground focus:outline-hidden focus:border-primary text-xs"
                  >
                    <option value="PHISHING">Phishing</option>
                    <option value="CREDENTIAL_COMPROMISE">Credential Compromise</option>
                    <option value="MALWARE">Malware</option>
                    <option value="ACCOUNT_TAKEOVER">Account Takeover</option>
                    <option value="DATA_EXFILTRATION">Data Exfiltration</option>
                    <option value="IMPERSONATION">Impersonation</option>
                    <option value="NETWORK_INTRUSION">Network Intrusion</option>
                    <option value="OTHER">Other</option>
                  </select>
                </div>
              </div>

              <div className="pt-2 flex items-center justify-end space-x-2 border-t border-border">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-3 py-1.5 bg-surface-secondary border border-border rounded-control text-foreground hover:bg-surface cursor-pointer text-xs"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={creating}
                  className="px-4 py-1.5 bg-primary hover:bg-primary-hover text-white font-semibold rounded-control flex items-center space-x-1.5 cursor-pointer disabled:opacity-50 text-xs"
                >
                  {creating ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <CheckCircle2 className="w-3.5 h-3.5" />}
                  <span>{creating ? 'Creating...' : 'Create Case'}</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
