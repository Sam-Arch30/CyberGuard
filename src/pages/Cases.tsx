import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  FolderLock,
  Search,
  Plus,
  ArrowUpRight,
  ShieldAlert,
  AlertCircle,
  FileText,
  Mail,
  RefreshCw,
  X,
  Copy,
  Check,
  CheckSquare,
  GitMerge,
  User,
} from 'lucide-react';
import type {
  CaseListItem,
  CaseCreatePayload,
  CaseMetricsSummary,
} from '../types/case';
import { caseService } from '../services/caseService';

const STATUS_CONFIG: Record<string, { label: string; badge: string; border: string }> = {
  NEW: { label: 'New', badge: 'bg-primary-subtle text-primary border-primary/30', border: 'border-primary/40' },
  OPEN: { label: 'Open', badge: 'bg-surface-secondary text-foreground border-border', border: 'border-border' },
  IN_PROGRESS: { label: 'In Progress', badge: 'bg-warning-surface text-warning border-warning-border', border: 'border-border hover:border-warning-border' },
  PENDING: { label: 'Pending', badge: 'bg-surface-secondary text-foreground-muted border-border', border: 'border-border' },
  ON_HOLD: { label: 'On Hold', badge: 'bg-surface-secondary text-foreground-muted border-border', border: 'border-border' },
  RESOLVED: { label: 'Resolved', badge: 'bg-success-surface text-success border-success-border', border: 'border-border hover:border-success-border' },
  CLOSED: { label: 'Closed', badge: 'bg-surface-secondary text-foreground-muted border-border', border: 'border-border' },
  CANCELLED: { label: 'Cancelled', badge: 'bg-surface-secondary text-foreground-muted border-border line-through', border: 'border-border' },
  // Legacy lowercase compatibility
  open: { label: 'Open', badge: 'bg-surface-secondary text-foreground border-border', border: 'border-border' },
  investigating: { label: 'Investigating', badge: 'bg-warning-surface text-warning border-warning-border', border: 'border-border hover:border-warning-border' },
  escalated: { label: 'Escalated', badge: 'bg-danger-surface text-danger border-danger-border font-semibold', border: 'border-danger-border/60 hover:border-danger-border' },
  resolved: { label: 'Resolved', badge: 'bg-success-surface text-success border-success-border', border: 'border-border hover:border-success-border' },
};

const SEVERITY_CONFIG: Record<string, { label: string; badge: string }> = {
  LOW: { label: 'Low', badge: 'bg-surface-secondary text-foreground-muted border-border' },
  MEDIUM: { label: 'Medium', badge: 'bg-warning-surface/60 text-warning border-warning-border/60' },
  HIGH: { label: 'High', badge: 'bg-warning-surface text-warning border-warning-border font-medium' },
  CRITICAL: { label: 'Critical', badge: 'bg-danger-surface text-danger border-danger-border font-bold' },
  low: { label: 'Low', badge: 'bg-surface-secondary text-foreground-muted border-border' },
  medium: { label: 'Medium', badge: 'bg-warning-surface/60 text-warning border-warning-border/60' },
  high: { label: 'High', badge: 'bg-warning-surface text-warning border-warning-border font-medium' },
  critical: { label: 'Critical', badge: 'bg-danger-surface text-danger border-danger-border font-bold' },
};

const PRIORITY_CONFIG: Record<string, { label: string; badge: string }> = {
  P1_CRITICAL: { label: 'P1 Critical', badge: 'bg-danger-surface text-danger border-danger-border font-bold' },
  P2_HIGH: { label: 'P2 High', badge: 'bg-warning-surface text-warning border-warning-border font-semibold' },
  P3_MEDIUM: { label: 'P3 Medium', badge: 'bg-surface-secondary text-foreground border-border' },
  P4_LOW: { label: 'P4 Low', badge: 'bg-surface-secondary text-foreground-muted border-border' },
};

export const Cases: React.FC = () => {
  const navigate = useNavigate();

  const [cases, setCases] = useState<CaseListItem[]>([]);
  const [metrics, setMetrics] = useState<CaseMetricsSummary | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedStatus, setSelectedStatus] = useState<string>('ALL');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');
  const [selectedPriority, setSelectedPriority] = useState<string>('ALL');
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');

  const [showCreateModal, setShowCreateModal] = useState<boolean>(false);
  const [showMergeModal, setShowMergeModal] = useState<boolean>(false);
  const [selectedCaseIds, setSelectedCaseIds] = useState<string[]>([]);
  const [mergeTargetId, setMergeTargetId] = useState<string>('');
  const [mergeReason, setMergeReason] = useState<string>('');
  const [merging, setMerging] = useState<boolean>(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // New Case Form State
  const [newTitle, setNewTitle] = useState('');
  const [newDescription, setNewDescription] = useState('');
  const [newSeverity, setNewSeverity] = useState<string>('MEDIUM');
  const [newPriority, setNewPriority] = useState<string>('P3_MEDIUM');
  const [newCategory, setNewCategory] = useState<string>('PHISHING');
  const [newOwnerId, setNewOwnerId] = useState<string>('');
  const [newTags, setNewTags] = useState<string>('');
  const [creating, setCreating] = useState<boolean>(false);
  const [formError, setFormError] = useState<string | null>(null);

  const fetchCases = useCallback(async () => {
    setLoading(true);
    try {
      const [casesRes, metricsRes] = await Promise.all([
        caseService.listCases({
          status: selectedStatus,
          severity: selectedSeverity,
          priority: selectedPriority,
          category: selectedCategory,
          search: searchQuery.trim(),
        }),
        caseService.getCaseMetrics().catch(() => null),
      ]);
      setCases(casesRes.cases || []);
      if (metricsRes) setMetrics(metricsRes);
    } catch (err) {
      console.warn('Could not connect to backend cases endpoint', err);
    } finally {
      setLoading(false);
    }
  }, [selectedStatus, selectedSeverity, selectedPriority, selectedCategory, searchQuery]);

  useEffect(() => {
    fetchCases();
  }, [fetchCases]);

  const handleCreateCase = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTitle.trim()) {
      setFormError('Case title is required.');
      return;
    }

    setCreating(true);
    setFormError(null);

    const tagList = newTags
      .split(',')
      .map(t => t.trim())
      .filter(Boolean);

    const payload: CaseCreatePayload = {
      title: newTitle.trim(),
      description: newDescription.trim(),
      severity: newSeverity,
      priority: newPriority,
      category: newCategory,
      owner_id: newOwnerId.trim() || undefined,
      tags: tagList,
      status: 'OPEN',
    };

    try {
      const createdCase = await caseService.createCase(payload);
      setShowCreateModal(false);
      setNewTitle('');
      setNewDescription('');
      setNewOwnerId('');
      setNewTags('');
      navigate(`/cases/${createdCase.id}`);
    } catch (err: any) {
      setFormError(err.message || 'Error creating case');
    } finally {
      setCreating(false);
    }
  };

  const handleMergeCases = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!mergeTargetId || selectedCaseIds.length < 2 || !mergeReason.trim()) return;

    setMerging(true);
    try {
      const sourceIds = selectedCaseIds.filter(id => id !== mergeTargetId);
      await caseService.mergeCases(mergeTargetId, {
        source_case_ids: sourceIds,
        reason: mergeReason.trim(),
      });
      setShowMergeModal(false);
      setSelectedCaseIds([]);
      setMergeReason('');
      fetchCases();
    } catch (err: any) {
      alert(`Failed to merge cases: ${err.message}`);
    } finally {
      setMerging(false);
    }
  };

  const toggleSelectCase = (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setSelectedCaseIds(prev =>
      prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id]
    );
  };

  const copyCaseNumber = (caseNum: string, e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(caseNum);
    setCopiedId(caseNum);
    setTimeout(() => setCopiedId(null), 2000);
  };

  return (
    <div className="space-y-6 pb-12">
      {/* 1. HEADER & ACTION BAR */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2.5">
            <div className="p-2 rounded-lg bg-surface-secondary border border-border text-primary">
              <FolderLock className="w-4 h-4" />
            </div>
            <div>
              <h1 className="text-xl font-bold font-mono text-foreground flex items-center space-x-2">
                <span>SOC Case Management</span>
                <span className="text-[10px] px-2 py-0.5 rounded bg-surface-secondary text-foreground-muted border border-border">
                  Authoritative
                </span>
              </h1>
              <p className="text-xs font-mono text-foreground-muted">
                Authoritative operational hub coordinating incident response, tasks, evidence, and closure sign-offs.
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center space-x-2.5">
          {selectedCaseIds.length >= 2 && (
            <button
              type="button"
              onClick={() => {
                setMergeTargetId(selectedCaseIds[0]);
                setShowMergeModal(true);
              }}
              className="flex items-center space-x-1.5 px-3 py-2 rounded-lg bg-surface-secondary hover:bg-surface border border-border text-foreground font-mono text-xs font-medium transition-colors btn-press cursor-pointer"
            >
              <GitMerge className="w-3.5 h-3.5 text-warning" />
              <span>Merge ({selectedCaseIds.length})</span>
            </button>
          )}

          <button
            type="button"
            onClick={fetchCases}
            className="p-2 rounded-lg bg-surface hover:bg-surface-secondary border border-border text-foreground-muted hover:text-foreground transition-colors btn-press cursor-pointer"
            title="Refresh Cases"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-primary' : ''}`} />
          </button>
          <button
            type="button"
            onClick={() => setShowCreateModal(true)}
            className="flex items-center space-x-1.5 px-3.5 py-2 rounded-lg bg-primary hover:bg-primary-hover text-primary-foreground font-mono text-xs font-semibold transition-colors btn-press cursor-pointer"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Create Case</span>
          </button>
        </div>
      </div>

      {/* 2. METRIC CARDS */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
        <div className="p-3.5 rounded-xl bg-surface border border-border shadow-xs">
          <div className="text-[11px] font-mono text-foreground-muted font-medium">Total Cases</div>
          <div className="text-2xl font-mono font-bold text-foreground mt-1">
            {metrics ? metrics.total_cases : cases.length}
          </div>
        </div>
        <div className="p-3.5 rounded-xl bg-surface border border-border shadow-xs">
          <div className="text-[11px] font-mono text-foreground-muted font-medium">Open & Active</div>
          <div className="text-2xl font-mono font-bold text-foreground mt-1">
            {metrics ? metrics.open_cases + metrics.in_progress_cases : cases.filter(c => ['OPEN', 'open', 'IN_PROGRESS', 'investigating'].includes(c.status)).length}
          </div>
        </div>
        <div className="p-3.5 rounded-xl bg-surface border border-border shadow-xs">
          <div className="text-[11px] font-mono text-danger font-medium flex items-center space-x-1">
            <span>Critical P1</span>
          </div>
          <div className="text-2xl font-mono font-bold text-danger mt-1">
            {metrics ? metrics.critical_cases : cases.filter(c => (c.severity || '').toUpperCase() === 'CRITICAL').length}
          </div>
        </div>
        <div className="p-3.5 rounded-xl bg-surface border border-border shadow-xs">
          <div className="text-[11px] font-mono text-warning font-medium">SLA Breached / Warn</div>
          <div className="text-2xl font-mono font-bold text-warning mt-1">
            {metrics ? `${metrics.sla_breached_cases} / ${metrics.sla_warning_cases}` : cases.filter(c => c.sla_status === 'BREACHED').length}
          </div>
        </div>
        <div className="p-3.5 rounded-xl bg-surface border border-border shadow-xs col-span-2 sm:col-span-1">
          <div className="text-[11px] font-mono text-success font-medium">Resolved & Closed</div>
          <div className="text-2xl font-mono font-bold text-success mt-1">
            {metrics ? metrics.resolved_cases + metrics.closed_cases : cases.filter(c => ['RESOLVED', 'resolved', 'CLOSED'].includes(c.status)).length}
          </div>
        </div>
      </div>

      {/* 3. SEARCH & FILTERS BAR */}
      <div className="p-3.5 rounded-xl bg-surface border border-border shadow-xs flex flex-col md:flex-row md:items-center justify-between gap-3">
        {/* Search */}
        <div className="relative flex-1 max-w-md">
          <Search className="w-4 h-4 text-foreground-muted absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
          <input
            type="text"
            placeholder="Search by title, case number (e.g. CG-2026-000001)..."
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-4 py-1.5 bg-surface-secondary rounded-lg border border-border text-xs font-mono text-foreground placeholder:text-foreground-muted focus:outline-none focus:border-primary transition-colors"
          />
        </div>

        {/* Filters */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Status Pills */}
          <div className="flex items-center space-x-1 bg-surface-secondary p-1 rounded-lg border border-border text-xs font-mono">
            {['ALL', 'OPEN', 'IN_PROGRESS', 'RESOLVED', 'CLOSED'].map(st => (
              <button
                key={st}
                type="button"
                onClick={() => setSelectedStatus(st)}
                className={`px-2.5 py-1 rounded-md transition-colors capitalize cursor-pointer ${
                  selectedStatus === st
                    ? 'bg-primary-subtle text-primary border border-primary/30 font-semibold'
                    : 'text-foreground-muted hover:text-foreground'
                }`}
              >
                {st.replace('_', ' ').toLowerCase()}
              </button>
            ))}
          </div>

          {/* Priority Filter */}
          <select
            value={selectedPriority}
            onChange={e => setSelectedPriority(e.target.value)}
            className="bg-surface-secondary border border-border text-foreground font-mono text-xs px-2.5 py-1.5 rounded-lg focus:outline-none focus:border-primary"
          >
            <option value="ALL">All Priorities</option>
            <option value="P1_CRITICAL">P1 Critical</option>
            <option value="P2_HIGH">P2 High</option>
            <option value="P3_MEDIUM">P3 Medium</option>
            <option value="P4_LOW">P4 Low</option>
          </select>

          {/* Severity Filter */}
          <select
            value={selectedSeverity}
            onChange={e => setSelectedSeverity(e.target.value)}
            className="bg-surface-secondary border border-border text-foreground font-mono text-xs px-2.5 py-1.5 rounded-lg focus:outline-none focus:border-primary"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>

          {/* Category Filter */}
          <select
            value={selectedCategory}
            onChange={e => setSelectedCategory(e.target.value)}
            className="bg-surface-secondary border border-border text-foreground font-mono text-xs px-2.5 py-1.5 rounded-lg focus:outline-none focus:border-primary"
          >
            <option value="ALL">All Categories</option>
            <option value="PHISHING">Phishing</option>
            <option value="MALWARE">Malware</option>
            <option value="BEC">BEC</option>
            <option value="CREDENTIAL_HARVESTING">Credential Harvesting</option>
            <option value="IMPERSONATION">Impersonation</option>
            <option value="RANSOMWARE">Ransomware</option>
            <option value="INSIDER_THREAT">Insider Threat</option>
            <option value="DATA_EXFILTRATION">Data Exfiltration</option>
            <option value="GENERAL">General</option>
          </select>
        </div>
      </div>

      {/* 4. CASE LIST VIEW */}
      {loading && cases.length === 0 ? (
        <div className="flex flex-col items-center justify-center min-h-[300px] space-y-3 rounded-xl border border-border bg-surface">
          <RefreshCw className="w-6 h-6 text-primary animate-spin" />
          <p className="text-xs font-mono text-foreground-muted">Loading cases from database...</p>
        </div>
      ) : cases.length === 0 ? (
        <div className="flex flex-col items-center justify-center min-h-[300px] p-8 text-center rounded-xl border border-border bg-surface space-y-3">
          <div className="p-3 rounded-full bg-surface-secondary border border-border text-foreground-muted">
            <FolderLock className="w-6 h-6 opacity-50" />
          </div>
          <div className="space-y-1">
            <h3 className="text-sm font-bold font-mono text-foreground">No Operational Cases Found</h3>
            <p className="text-xs font-mono text-foreground-muted max-w-sm">
              {searchQuery || selectedStatus !== 'ALL' || selectedSeverity !== 'ALL'
                ? 'No cases match your filter criteria. Try adjusting your filters or search term.'
                : 'Create your first operational investigation case to coordinate response and tasks.'}
            </p>
          </div>
          <button
            type="button"
            onClick={() => setShowCreateModal(true)}
            className="px-3.5 py-1.5 rounded-lg bg-primary hover:bg-primary-hover text-primary-foreground font-mono text-xs font-semibold transition-colors btn-press cursor-pointer"
          >
            Create First Case
          </button>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {cases.map(caseItem => {
            const statusConfig = STATUS_CONFIG[caseItem.status] || STATUS_CONFIG.OPEN;
            const severityConfig = SEVERITY_CONFIG[(caseItem.severity || '').toUpperCase()] || SEVERITY_CONFIG.MEDIUM;
            const priorityConfig = caseItem.priority ? PRIORITY_CONFIG[caseItem.priority] : null;
            const isSelected = selectedCaseIds.includes(caseItem.id);

            return (
              <div
                key={caseItem.id}
                onClick={() => navigate(`/cases/${caseItem.id}`)}
                className={`p-5 rounded-xl bg-surface hover:bg-surface-secondary/40 border ${
                  isSelected ? 'border-primary ring-1 ring-primary/40' : statusConfig.border
                } cursor-pointer transition-all duration-150 shadow-xs hover:shadow-sm group flex flex-col justify-between space-y-3`}
              >
                <div className="space-y-2.5">
                  {/* Top Bar: Case Number, Checkbox, Badges */}
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center space-x-2">
                      <input
                        type="checkbox"
                        checked={isSelected}
                        onChange={e => toggleSelectCase(caseItem.id, e as any)}
                        onClick={e => e.stopPropagation()}
                        className="rounded border-border text-primary focus:ring-0 cursor-pointer"
                        title="Select for merge"
                      />
                      <span className="px-2 py-0.5 rounded bg-surface-secondary border border-border text-xs font-mono font-semibold text-primary flex items-center space-x-1.5">
                        <span>{caseItem.case_number}</span>
                        <button
                          type="button"
                          onClick={e => copyCaseNumber(caseItem.case_number, e)}
                          className="hover:text-foreground p-0.5 cursor-pointer"
                          title="Copy Case Number"
                        >
                          {copiedId === caseItem.case_number ? (
                            <Check className="w-3 h-3 text-success" />
                          ) : (
                            <Copy className="w-3 h-3 text-foreground-muted" />
                          )}
                        </button>
                      </span>

                      {caseItem.category && (
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-surface-secondary text-foreground-muted border border-border font-mono">
                          {caseItem.category}
                        </span>
                      )}
                    </div>

                    <div className="flex items-center space-x-1.5">
                      {priorityConfig && (
                        <span className={`px-2 py-0.5 rounded text-[10px] font-mono border ${priorityConfig.badge}`}>
                          {priorityConfig.label}
                        </span>
                      )}
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono border font-medium uppercase ${statusConfig.badge}`}>
                        {statusConfig.label}
                      </span>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono border uppercase ${severityConfig.badge}`}>
                        {severityConfig.label}
                      </span>
                    </div>
                  </div>

                  {/* Title & Description */}
                  <div>
                    <h3 className="text-sm font-semibold font-mono text-foreground group-hover:text-primary transition-colors line-clamp-1 flex items-center justify-between">
                      <span>{caseItem.title}</span>
                      <ArrowUpRight className="w-3.5 h-3.5 text-foreground-muted group-hover:text-primary transition-transform group-hover:translate-x-0.5 group-hover:-translate-y-0.5" />
                    </h3>
                    {caseItem.description ? (
                      <p className="text-xs font-mono text-foreground-muted line-clamp-2 mt-1">
                        {caseItem.description}
                      </p>
                    ) : (
                      <p className="text-xs font-mono text-foreground-muted/60 italic mt-1">
                        No description provided
                      </p>
                    )}
                  </div>
                </div>

                {/* Footer Metrics & Metadata */}
                <div className="pt-3 border-t border-border flex items-center justify-between text-xs font-mono text-foreground-muted">
                  <div className="flex items-center space-x-3">
                    <span className="flex items-center space-x-1" title="Linked Emails">
                      <Mail className="w-3 h-3 text-foreground-muted" />
                      <span>{caseItem.email_count || 0}</span>
                    </span>
                    <span className="flex items-center space-x-1" title="Notes">
                      <FileText className="w-3 h-3 text-foreground-muted" />
                      <span>{caseItem.note_count || 0}</span>
                    </span>
                    <span className="flex items-center space-x-1" title="Findings">
                      <ShieldAlert className="w-3 h-3 text-foreground-muted" />
                      <span>{caseItem.finding_count || 0}</span>
                    </span>
                    {(caseItem.task_count !== undefined) && (
                      <span className="flex items-center space-x-1" title="Tasks (Open / Total)">
                        <CheckSquare className="w-3 h-3 text-primary" />
                        <span>
                          {caseItem.open_task_count ?? 0}/{caseItem.task_count}
                        </span>
                      </span>
                    )}
                  </div>

                  <div className="flex items-center space-x-2">
                    {caseItem.owner_id && (
                      <span className="flex items-center space-x-1 text-[11px] text-foreground-muted">
                        <User className="w-3 h-3" />
                        <span>{caseItem.owner_id}</span>
                      </span>
                    )}
                    <span className="text-[11px] text-foreground-muted">
                      {new Date(caseItem.updated_at).toLocaleDateString()}
                    </span>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* 5. CREATE CASE MODAL */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4">
          <div className="bg-surface border border-border rounded-xl shadow-xl w-full max-w-lg overflow-hidden animate-in fade-in zoom-in-95 duration-150">
            <div className="flex items-center justify-between px-5 py-4 border-b border-border bg-surface-secondary/40">
              <div className="flex items-center space-x-2">
                <FolderLock className="w-4 h-4 text-primary" />
                <h3 className="font-mono text-sm font-bold text-foreground">Create Operational Case</h3>
              </div>
              <button
                type="button"
                onClick={() => setShowCreateModal(false)}
                className="text-foreground-muted hover:text-foreground cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleCreateCase} className="p-5 space-y-4">
              {formError && (
                <div className="p-3 rounded-lg bg-danger-surface border border-danger-border text-danger text-xs font-mono flex items-center space-x-2">
                  <AlertCircle className="w-4 h-4 shrink-0" />
                  <span>{formError}</span>
                </div>
              )}

              <div>
                <label className="block text-xs font-mono font-medium text-foreground mb-1">
                  Case Title *
                </label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Executive Phishing Outbreak - Payroll Theme"
                  value={newTitle}
                  onChange={e => setNewTitle(e.target.value)}
                  className="w-full px-3 py-2 bg-surface-secondary rounded-lg border border-border text-xs font-mono text-foreground focus:outline-none focus:border-primary"
                />
              </div>

              <div>
                <label className="block text-xs font-mono font-medium text-foreground mb-1">
                  Incident Description
                </label>
                <textarea
                  rows={3}
                  placeholder="Summarize context, affected entities, and initial scope of investigation..."
                  value={newDescription}
                  onChange={e => setNewDescription(e.target.value)}
                  className="w-full px-3 py-2 bg-surface-secondary rounded-lg border border-border text-xs font-mono text-foreground focus:outline-none focus:border-primary"
                />
              </div>

              <div className="grid grid-cols-3 gap-3">
                <div>
                  <label className="block text-xs font-mono font-medium text-foreground mb-1">
                    Priority
                  </label>
                  <select
                    value={newPriority}
                    onChange={e => setNewPriority(e.target.value)}
                    className="w-full px-2.5 py-1.5 bg-surface-secondary rounded-lg border border-border text-xs font-mono text-foreground focus:outline-none focus:border-primary"
                  >
                    <option value="P1_CRITICAL">P1 Critical</option>
                    <option value="P2_HIGH">P2 High</option>
                    <option value="P3_MEDIUM">P3 Medium</option>
                    <option value="P4_LOW">P4 Low</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-mono font-medium text-foreground mb-1">
                    Severity
                  </label>
                  <select
                    value={newSeverity}
                    onChange={e => setNewSeverity(e.target.value)}
                    className="w-full px-2.5 py-1.5 bg-surface-secondary rounded-lg border border-border text-xs font-mono text-foreground focus:outline-none focus:border-primary"
                  >
                    <option value="CRITICAL">Critical</option>
                    <option value="HIGH">High</option>
                    <option value="MEDIUM">Medium</option>
                    <option value="LOW">Low</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-mono font-medium text-foreground mb-1">
                    Category
                  </label>
                  <select
                    value={newCategory}
                    onChange={e => setNewCategory(e.target.value)}
                    className="w-full px-2.5 py-1.5 bg-surface-secondary rounded-lg border border-border text-xs font-mono text-foreground focus:outline-none focus:border-primary"
                  >
                    <option value="PHISHING">Phishing</option>
                    <option value="ACCOUNT_TAKEOVER">Account Takeover</option>
                    <option value="MALWARE">Malware</option>
                    <option value="IMPERSONATION">Impersonation</option>
                    <option value="CREDENTIAL_THEFT">Credential Theft</option>
                    <option value="DATA_EXFILTRATION">Data Exfiltration</option>
                    <option value="FRAUD">Fraud</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-mono font-medium text-foreground mb-1">
                    Assigned Owner
                  </label>
                  <input
                    type="text"
                    placeholder="analyst.id"
                    value={newOwnerId}
                    onChange={e => setNewOwnerId(e.target.value)}
                    className="w-full px-3 py-1.5 bg-surface-secondary rounded-lg border border-border text-xs font-mono text-foreground focus:outline-none focus:border-primary"
                  />
                </div>

                <div>
                  <label className="block text-xs font-mono font-medium text-foreground mb-1">
                    Tags (comma separated)
                  </label>
                  <input
                    type="text"
                    placeholder="phishing, ceo-fraud"
                    value={newTags}
                    onChange={e => setNewTags(e.target.value)}
                    className="w-full px-3 py-1.5 bg-surface-secondary rounded-lg border border-border text-xs font-mono text-foreground focus:outline-none focus:border-primary"
                  />
                </div>
              </div>

              <div className="flex items-center justify-end space-x-2 pt-3 border-t border-border">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-3.5 py-1.5 rounded-lg border border-border text-xs font-mono text-foreground-muted hover:text-foreground cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={creating}
                  className="flex items-center space-x-1.5 px-4 py-1.5 rounded-lg bg-primary hover:bg-primary-hover text-primary-foreground font-mono text-xs font-semibold disabled:opacity-50 cursor-pointer"
                >
                  {creating && <RefreshCw className="w-3.5 h-3.5 animate-spin" />}
                  <span>{creating ? 'Creating...' : 'Create Case'}</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* 6. MERGE CASES MODAL */}
      {showMergeModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4">
          <div className="bg-surface border border-border rounded-xl shadow-xl w-full max-w-md overflow-hidden animate-in fade-in zoom-in-95 duration-150">
            <div className="flex items-center justify-between px-5 py-4 border-b border-border bg-surface-secondary/40">
              <div className="flex items-center space-x-2">
                <GitMerge className="w-4 h-4 text-warning" />
                <h3 className="font-mono text-sm font-bold text-foreground">Merge Cases</h3>
              </div>
              <button
                type="button"
                onClick={() => setShowMergeModal(false)}
                className="text-foreground-muted hover:text-foreground cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleMergeCases} className="p-5 space-y-4">
              <p className="text-xs font-mono text-foreground-muted">
                Merging will absorb tasks, notes, findings, and evidence into the primary target case.
                Secondary cases will be marked as RESOLVED (DUPLICATE) with lineage preserved.
              </p>

              <div>
                <label className="block text-xs font-mono font-medium text-foreground mb-1">
                  Target Case (Surviving Primary)
                </label>
                <select
                  value={mergeTargetId}
                  onChange={e => setMergeTargetId(e.target.value)}
                  className="w-full px-3 py-2 bg-surface-secondary rounded-lg border border-border text-xs font-mono text-foreground focus:outline-none focus:border-primary"
                >
                  {selectedCaseIds.map(id => {
                    const c = cases.find(x => x.id === id);
                    return (
                      <option key={id} value={id}>
                        {c ? `${c.case_number} - ${c.title}` : id}
                      </option>
                    );
                  })}
                </select>
              </div>

              <div>
                <label className="block text-xs font-mono font-medium text-foreground mb-1">
                  Justification / Merge Rationale *
                </label>
                <textarea
                  rows={2}
                  required
                  placeholder="e.g. Verified duplicate reports from identical phishing email campaign."
                  value={mergeReason}
                  onChange={e => setMergeReason(e.target.value)}
                  className="w-full px-3 py-2 bg-surface-secondary rounded-lg border border-border text-xs font-mono text-foreground focus:outline-none focus:border-primary"
                />
              </div>

              <div className="flex items-center justify-end space-x-2 pt-3 border-t border-border">
                <button
                  type="button"
                  onClick={() => setShowMergeModal(false)}
                  className="px-3.5 py-1.5 rounded-lg border border-border text-xs font-mono text-foreground-muted hover:text-foreground cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={merging}
                  className="flex items-center space-x-1.5 px-4 py-1.5 rounded-lg bg-warning hover:bg-warning/90 text-warning-foreground font-mono text-xs font-semibold disabled:opacity-50 cursor-pointer"
                >
                  {merging && <RefreshCw className="w-3.5 h-3.5 animate-spin" />}
                  <span>{merging ? 'Merging...' : 'Confirm Merge'}</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
