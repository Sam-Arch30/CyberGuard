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
  Filter
} from 'lucide-react';
import type { CaseListItem, CaseStatus, CaseSeverity, CaseCreatePayload } from '../types/case';

const STATUS_CONFIG: Record<CaseStatus, { label: string; badge: string; border: string }> = {
  open: { label: 'Open', badge: 'bg-surface-secondary text-foreground border-border', border: 'border-border' },
  investigating: { label: 'Investigating', badge: 'bg-warning-surface text-warning border-warning-border', border: 'border-border hover:border-warning-border' },
  escalated: { label: 'Escalated', badge: 'bg-danger-surface text-danger border-danger-border font-semibold', border: 'border-danger-border/60 hover:border-danger-border' },
  resolved: { label: 'Resolved', badge: 'bg-success-surface text-success border-success-border', border: 'border-border hover:border-success-border' },
};

const SEVERITY_CONFIG: Record<CaseSeverity, { label: string; badge: string }> = {
  low: { label: 'Low', badge: 'bg-surface-secondary text-foreground-muted border-border' },
  medium: { label: 'Medium', badge: 'bg-warning-surface/60 text-warning border-warning-border/60' },
  high: { label: 'High', badge: 'bg-warning-surface text-warning border-warning-border font-medium' },
  critical: { label: 'Critical', badge: 'bg-danger-surface text-danger border-danger-border font-bold' },
};

export const Cases: React.FC = () => {
  const navigate = useNavigate();

  const [cases, setCases] = useState<CaseListItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedStatus, setSelectedStatus] = useState<string>('ALL');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');
  const [showCreateModal, setShowCreateModal] = useState<boolean>(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // New Case Form State
  const [newTitle, setNewTitle] = useState('');
  const [newDescription, setNewDescription] = useState('');
  const [newSeverity, setNewSeverity] = useState<CaseSeverity>('medium');
  const [newStatus, setNewStatus] = useState<CaseStatus>('open');
  const [creating, setCreating] = useState<boolean>(false);
  const [formError, setFormError] = useState<string | null>(null);

  const fetchCases = useCallback(() => {
    setLoading(true);
    const params = new URLSearchParams();
    if (selectedStatus !== 'ALL') params.append('status', selectedStatus);
    if (selectedSeverity !== 'ALL') params.append('severity', selectedSeverity);
    if (searchQuery.trim()) params.append('search', searchQuery.trim());

    fetch(`/api/cases?${params.toString()}`)
      .then(res => (res.ok ? res.json() : null))
      .then(data => {
        if (data && Array.isArray(data.cases)) {
          setCases(data.cases);
        }
      })
      .catch(err => {
        console.warn('Could not connect to backend cases endpoint', err);
      })
      .finally(() => {
        setLoading(false);
      });
  }, [selectedStatus, selectedSeverity, searchQuery]);

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

    const payload: CaseCreatePayload = {
      title: newTitle.trim(),
      description: newDescription.trim(),
      severity: newSeverity,
      status: newStatus
    };

    try {
      const res = await fetch('/api/cases', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      if (!res.ok) {
        throw new Error(`Failed to create case: ${res.statusText}`);
      }

      const createdCase = await res.json();
      setShowCreateModal(false);
      setNewTitle('');
      setNewDescription('');
      navigate(`/cases/${createdCase.id}`);
    } catch (err: any) {
      setFormError(err.message || 'Error creating case');
    } finally {
      setCreating(false);
    }
  };

  const copyCaseNumber = (caseNum: string, e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(caseNum);
    setCopiedId(caseNum);
    setTimeout(() => setCopiedId(null), 2000);
  };

  // Metrics computation
  const metrics = {
    total: cases.length,
    open: cases.filter(c => c.status === 'open').length,
    investigating: cases.filter(c => c.status === 'investigating').length,
    escalated: cases.filter(c => c.status === 'escalated').length,
    resolved: cases.filter(c => c.status === 'resolved').length,
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
                  Platform
                </span>
              </h1>
              <p className="text-xs font-mono text-foreground-muted">
                Transforming forensic telemetry into structured, collaborative incident investigations.
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center space-x-2.5">
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
          <div className="text-2xl font-mono font-bold text-foreground mt-1">{metrics.total}</div>
        </div>
        <div className="p-3.5 rounded-xl bg-surface border border-border shadow-xs">
          <div className="text-[11px] font-mono text-foreground-muted font-medium">Open</div>
          <div className="text-2xl font-mono font-bold text-foreground mt-1">{metrics.open}</div>
        </div>
        <div className="p-3.5 rounded-xl bg-surface border border-border shadow-xs">
          <div className="text-[11px] font-mono text-warning font-medium">Investigating</div>
          <div className="text-2xl font-mono font-bold text-warning mt-1">{metrics.investigating}</div>
        </div>
        <div className="p-3.5 rounded-xl bg-surface border border-border shadow-xs">
          <div className="text-[11px] font-mono text-danger font-medium">Escalated</div>
          <div className="text-2xl font-mono font-bold text-danger mt-1">{metrics.escalated}</div>
        </div>
        <div className="p-3.5 rounded-xl bg-surface border border-border shadow-xs col-span-2 sm:col-span-1">
          <div className="text-[11px] font-mono text-success font-medium">Resolved</div>
          <div className="text-2xl font-mono font-bold text-success mt-1">{metrics.resolved}</div>
        </div>
      </div>

      {/* 3. SEARCH & FILTERS BAR */}
      <div className="p-3.5 rounded-xl bg-surface border border-border shadow-xs flex flex-col md:flex-row md:items-center justify-between gap-3">
        {/* Search */}
        <div className="relative flex-1 max-w-md">
          <Search className="w-4 h-4 text-foreground-muted absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
          <input
            type="text"
            placeholder="Search by title, case number (e.g. CASE-2026-000001)..."
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-4 py-1.5 bg-surface-secondary rounded-lg border border-border text-xs font-mono text-foreground placeholder:text-foreground-muted focus:outline-none focus:border-primary transition-colors"
          />
        </div>

        {/* Status & Severity Filter Pills */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Status Pills */}
          <div className="flex items-center space-x-1 bg-surface-secondary p-1 rounded-lg border border-border text-xs font-mono">
            {['ALL', 'open', 'investigating', 'escalated', 'resolved'].map(st => (
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
                {st}
              </button>
            ))}
          </div>

          {/* Severity Dropdown */}
          <div className="flex items-center space-x-1">
            <Filter className="w-3.5 h-3.5 text-foreground-muted ml-1" />
            <select
              value={selectedSeverity}
              onChange={e => setSelectedSeverity(e.target.value)}
              className="bg-surface-secondary border border-border text-foreground font-mono text-xs px-2.5 py-1.5 rounded-lg focus:outline-none focus:border-primary"
            >
              <option value="ALL">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>
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
            <h3 className="text-sm font-bold font-mono text-foreground">No Investigation Cases Found</h3>
            <p className="text-xs font-mono text-foreground-muted max-w-sm">
              {searchQuery || selectedStatus !== 'ALL' || selectedSeverity !== 'ALL'
                ? 'No cases match your filter criteria. Try adjusting your filters or search term.'
                : 'Create your first investigation case or add analyzed emails to track security incidents.'}
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
            const statusConfig = STATUS_CONFIG[caseItem.status] || STATUS_CONFIG.open;
            const severityConfig = SEVERITY_CONFIG[caseItem.severity] || SEVERITY_CONFIG.medium;

            return (
              <div
                key={caseItem.id}
                onClick={() => navigate(`/cases/${caseItem.id}`)}
                className={`p-5 rounded-xl bg-surface hover:bg-surface-secondary/40 border ${statusConfig.border} cursor-pointer transition-all duration-150 shadow-xs hover:shadow-sm group flex flex-col justify-between space-y-3`}
              >
                <div className="space-y-2.5">
                  {/* Top Bar: Case Number & Badges */}
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center space-x-2">
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
                    </div>

                    <div className="flex items-center space-x-1.5">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono border font-medium uppercase ${statusConfig.badge}`}>
                        {statusConfig.label}
                      </span>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono border uppercase ${severityConfig.badge}`}>
                        {severityConfig.label}
                      </span>
                    </div>
                  </div>

                  {/* Title & Description */}
                  <div className="space-y-0.5">
                    <h3 className="text-sm font-bold font-mono text-foreground group-hover:text-primary transition-colors line-clamp-1">
                      {caseItem.title}
                    </h3>
                    <p className="text-xs font-mono text-foreground-muted line-clamp-2">
                      {caseItem.description || 'No description provided.'}
                    </p>
                  </div>
                </div>

                {/* Bottom Bar: Stats & Navigation */}
                <div className="pt-2.5 border-t border-border/70 flex items-center justify-between text-xs font-mono text-foreground-muted">
                  <div className="flex items-center space-x-3">
                    <span className="flex items-center space-x-1 text-foreground">
                      <Mail className="w-3.5 h-3.5 text-primary" />
                      <span>{caseItem.email_count}</span>
                    </span>
                    <span className="flex items-center space-x-1 text-foreground">
                      <FileText className="w-3.5 h-3.5 text-warning" />
                      <span>{caseItem.note_count}</span>
                    </span>
                    <span className="flex items-center space-x-1 text-foreground">
                      <ShieldAlert className="w-3.5 h-3.5 text-danger" />
                      <span>{caseItem.finding_count}</span>
                    </span>
                  </div>

                  <div className="flex items-center space-x-1 text-[11px] text-foreground-muted group-hover:text-primary transition-colors">
                    <span>Investigate</span>
                    <ArrowUpRight className="w-3 h-3 transform group-hover:translate-x-0.5 group-hover:-translate-y-0.5 transition-transform" />
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* 5. CREATE NEW CASE MODAL */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-xs animate-in fade-in duration-150">
          <div className="w-full max-w-lg rounded-xl bg-surface border border-border shadow-xl p-6 space-y-4 animate-in zoom-in-95 duration-150">
            <div className="flex items-center justify-between pb-3 border-b border-border">
              <div className="flex items-center space-x-2">
                <div className="p-1.5 rounded-lg bg-surface-secondary border border-border text-primary">
                  <Plus className="w-4 h-4" />
                </div>
                <h3 className="text-sm font-bold font-mono text-foreground">Create Investigation Case</h3>
              </div>
              <button
                type="button"
                onClick={() => setShowCreateModal(false)}
                className="p-1 rounded-md text-foreground-muted hover:text-foreground hover:bg-surface-secondary transition-colors cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {formError && (
              <div className="p-2.5 rounded-lg bg-danger-surface border border-danger-border text-danger text-xs font-mono flex items-center space-x-2">
                <AlertCircle className="w-4 h-4 flex-shrink-0" />
                <span>{formError}</span>
              </div>
            )}

            <form onSubmit={handleCreateCase} className="space-y-3.5">
              <div className="space-y-1">
                <label className="text-xs font-mono text-foreground font-semibold">
                  Case Title <span className="text-danger">*</span>
                </label>
                <input
                  type="text"
                  placeholder="e.g. Targeted Credential Harvesting Campaign - Microsoft O365"
                  value={newTitle}
                  onChange={e => setNewTitle(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-surface-secondary border border-border text-xs font-mono text-foreground placeholder:text-foreground-muted focus:outline-none focus:border-primary"
                  required
                />
              </div>

              <div className="space-y-1">
                <label className="text-xs font-mono text-foreground font-semibold">Description</label>
                <textarea
                  rows={3}
                  placeholder="Provide incident context, targeted departments, or initial telemetry observations..."
                  value={newDescription}
                  onChange={e => setNewDescription(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-surface-secondary border border-border text-xs font-mono text-foreground placeholder:text-foreground-muted focus:outline-none focus:border-primary"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <label className="text-xs font-mono text-foreground font-semibold">Initial Severity</label>
                  <select
                    value={newSeverity}
                    onChange={e => setNewSeverity(e.target.value as CaseSeverity)}
                    className="w-full px-3 py-2 rounded-lg bg-surface-secondary border border-border text-xs font-mono text-foreground focus:outline-none focus:border-primary"
                  >
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                </div>

                <div className="space-y-1">
                  <label className="text-xs font-mono text-foreground font-semibold">Initial Status</label>
                  <select
                    value={newStatus}
                    onChange={e => setNewStatus(e.target.value as CaseStatus)}
                    className="w-full px-3 py-2 rounded-lg bg-surface-secondary border border-border text-xs font-mono text-foreground focus:outline-none focus:border-primary"
                  >
                    <option value="open">Open</option>
                    <option value="investigating">Investigating</option>
                    <option value="escalated">Escalated</option>
                    <option value="resolved">Resolved</option>
                  </select>
                </div>
              </div>

              <div className="pt-3 border-t border-border flex items-center justify-end space-x-2.5">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-3.5 py-1.5 rounded-lg bg-surface hover:bg-surface-secondary text-foreground-muted hover:text-foreground border border-border font-mono text-xs transition-colors cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={creating}
                  className="flex items-center space-x-1.5 px-4 py-1.5 rounded-lg bg-primary hover:bg-primary-hover text-primary-foreground font-mono text-xs font-semibold transition-colors btn-press disabled:opacity-50 cursor-pointer"
                >
                  {creating ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Plus className="w-3.5 h-3.5" />}
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

export default Cases;
