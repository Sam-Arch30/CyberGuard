import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { api } from '../services/api';
import {
  History,
  Search,
  Filter,
  ChevronLeft,
  ChevronRight,
  ArrowUpDown,
  ArrowUp,
  ArrowDown,
  ExternalLink,
  RefreshCw,
  ShieldAlert,
  Mail,
  AlertTriangle,
  Loader2,
  Inbox,
  FileSearch,
  Clock,
  Hash,
  User,
  FileText,
  ChevronDown,
  X
} from 'lucide-react';
import { saveAnalysisResult } from '../utils/forensicStore';
import { resolveEmailIndicators } from '../utils/indicatorHelper';

/* ─── Types ──────────────────────────────────────────────── */
interface EmailHistoryItem {
  id: string;
  evidence_id: string | null;
  sha256: string | null;
  subject: string;
  sender: string;
  threat_score: number;
  severity: string;
  timestamp: string;
}

type SortField = 'timestamp' | 'threat_score' | 'subject' | 'sender' | 'severity';
type SortDirection = 'asc' | 'desc';
type SeverityFilter = 'all' | 'critical' | 'high' | 'medium' | 'low';

/* ─── Severity Config ─────────────────────────────────────── */
const SEVERITY_CONFIG: Record<string, { label: string; classes: string; dot: string }> = {
  critical: {
    label: 'Critical',
    classes: 'bg-danger-surface text-danger border-danger-border font-bold',
    dot: 'bg-danger'
  },
  high: {
    label: 'High',
    classes: 'bg-warning-surface text-warning border-warning-border font-semibold',
    dot: 'bg-warning'
  },
  medium: {
    label: 'Medium',
    classes: 'bg-warning-surface/60 text-warning border-warning-border/70',
    dot: 'bg-warning/70'
  },
  low: {
    label: 'Low',
    classes: 'bg-surface-secondary text-foreground-muted border-border',
    dot: 'bg-foreground-muted/40'
  },
};

const getThreatColor = (score: number): string => {
  if (score >= 80) return 'text-danger';
  if (score >= 50) return 'text-warning';
  if (score >= 25) return 'text-foreground';
  return 'text-foreground-muted';
};

const getThreatBg = (score: number): string => {
  if (score >= 80) return 'bg-danger/10 border-danger/25';
  if (score >= 50) return 'bg-warning/10 border-warning/25';
  if (score >= 25) return 'bg-surface-secondary border-border';
  return 'bg-surface border-border';
};

const formatTimestamp = (ts: string): string => {
  try {
    const d = new Date(ts);
    return d.toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  } catch {
    return ts;
  }
};

const formatRelativeTime = (ts: string): string => {
  try {
    const now = Date.now();
    const then = new Date(ts).getTime();
    const diffMs = now - then;
    const diffMin = Math.floor(diffMs / 60000);
    if (diffMin < 1) return 'Just now';
    if (diffMin < 60) return `${diffMin}m ago`;
    const diffHr = Math.floor(diffMin / 60);
    if (diffHr < 24) return `${diffHr}h ago`;
    const diffDay = Math.floor(diffHr / 24);
    if (diffDay < 7) return `${diffDay}d ago`;
    return formatTimestamp(ts);
  } catch {
    return ts;
  }
};

/* ─── Main Component ──────────────────────────────────────── */
export const InvestigationHistory: React.FC = () => {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();

  const [items, setItems] = useState<EmailHistoryItem[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const [pageSize] = useState(15);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState(searchParams.get('search') || '');
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>('all');
  const [sortField, setSortField] = useState<SortField>('timestamp');
  const [sortDirection, setSortDirection] = useState<SortDirection>('desc');
  const [openingId, setOpeningId] = useState<string | null>(null);
  const [showFilters, setShowFilters] = useState(false);

  /* ── Fetch data from backend ─── */
  const fetchHistory = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const skip = page * pageSize;
      const data = await api.dashboard.getEmails(skip, pageSize);
      setItems(data.items || []);
      setTotal(data.total || 0);
    } catch (err: any) {
      setError(err?.message || 'Failed to fetch investigation history');
      setItems([]);
      setTotal(0);
    } finally {
      setLoading(false);
    }
  }, [page, pageSize]);

  useEffect(() => {
    fetchHistory();
  }, [fetchHistory]);

  /* ── Open full forensic analysis ─── */
  const openAnalysis = async (item: EmailHistoryItem) => {
    const lookupId = item.evidence_id || item.sha256 || item.id;
    setOpeningId(item.id);
    try {
      const data = await api.email.getAnalysis(lookupId);
      if (data) {
        const resolved = resolveEmailIndicators(data);
        saveAnalysisResult(lookupId, resolved);
        navigate(`/analysis/${lookupId}`);
      } else {
        navigate(`/analysis/${lookupId}`);
      }
    } catch {
      navigate(`/analysis/${lookupId}`);
    } finally {
      setOpeningId(null);
    }
  };

  /* ── Client-side filtering and sorting ─── */
  const filteredItems = items
    .filter(item => {
      if (severityFilter !== 'all' && item.severity.toLowerCase() !== severityFilter) {
        return false;
      }
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        return (
          (item.subject || '').toLowerCase().includes(q) ||
          (item.sender || '').toLowerCase().includes(q) ||
          (item.evidence_id || '').toLowerCase().includes(q) ||
          (item.sha256 || '').toLowerCase().includes(q)
        );
      }
      return true;
    })
    .sort((a, b) => {
      const dir = sortDirection === 'asc' ? 1 : -1;
      switch (sortField) {
        case 'timestamp':
          return dir * (new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
        case 'threat_score':
          return dir * (a.threat_score - b.threat_score);
        case 'subject':
          return dir * (a.subject || '').localeCompare(b.subject || '');
        case 'sender':
          return dir * (a.sender || '').localeCompare(b.sender || '');
        case 'severity': {
          const order: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
          return dir * ((order[a.severity] || 0) - (order[b.severity] || 0));
        }
        default:
          return 0;
      }
    });

  const totalPages = Math.ceil(total / pageSize);

  /* ── Sort toggle ─── */
  const toggleSort = (field: SortField) => {
    if (sortField === field) {
      setSortDirection(prev => (prev === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortField(field);
      setSortDirection('desc');
    }
  };

  const SortIcon: React.FC<{ field: SortField }> = ({ field }) => {
    if (sortField !== field) {
      return <ArrowUpDown className="w-3 h-3 text-foreground-muted/50" />;
    }
    return sortDirection === 'asc'
      ? <ArrowUp className="w-3 h-3 text-primary" />
      : <ArrowDown className="w-3 h-3 text-primary" />;
  };

  /* ── Severity stats from current page ─── */
  const severityCounts = items.reduce<Record<string, number>>((acc, item) => {
    const sev = (item.severity || 'low').toLowerCase();
    acc[sev] = (acc[sev] || 0) + 1;
    return acc;
  }, {});

  /* ─── RENDER ─── */
  return (
    <div className="space-y-5 pb-12">
      {/* Page Header */}
      <div className="bg-surface p-6 rounded-xl border border-border">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center space-x-2 text-primary font-mono text-xs mb-1 font-semibold uppercase tracking-wider">
              <History className="w-3.5 h-3.5" />
              <span>PERSISTENT INVESTIGATION ARCHIVE</span>
            </div>
            <h1 className="text-xl font-bold text-foreground font-sans tracking-tight">
              Investigation History
            </h1>
            <p className="text-xs text-foreground-muted font-mono mt-1">
              Complete audit trail of all ingested and analyzed email evidence, persisted in the forensic database.
            </p>
          </div>

          <div className="flex items-center space-x-3">
            {/* Summary chips */}
            <div className="hidden md:flex items-center space-x-2">
              <div className="flex items-center space-x-1.5 px-2.5 py-1 rounded-lg bg-surface-secondary border border-border text-xs font-mono text-foreground">
                <Mail className="w-3 h-3 text-primary" />
                <span>{total}</span>
                <span className="text-foreground-muted">total</span>
              </div>
              {(severityCounts['critical'] || 0) > 0 && (
                <div className="flex items-center space-x-1.5 px-2.5 py-1 rounded-lg bg-danger-surface border border-danger-border text-xs font-mono text-danger">
                  <ShieldAlert className="w-3 h-3" />
                  <span>{severityCounts['critical']}</span>
                  <span>critical</span>
                </div>
              )}
              {(severityCounts['high'] || 0) > 0 && (
                <div className="flex items-center space-x-1.5 px-2.5 py-1 rounded-lg bg-warning-surface border border-warning-border text-xs font-mono text-warning">
                  <AlertTriangle className="w-3 h-3" />
                  <span>{severityCounts['high']}</span>
                  <span>high</span>
                </div>
              )}
            </div>

            <button
              onClick={fetchHistory}
              disabled={loading}
              className="p-2 rounded-lg bg-surface-secondary border border-border hover:bg-surface hover:border-primary/30 text-foreground-muted hover:text-primary transition-all cursor-pointer disabled:opacity-50"
              title="Refresh"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            </button>
          </div>
        </div>
      </div>

      {/* Search & Filter Bar */}
      <div className="bg-surface rounded-xl border border-border p-4">
        <div className="flex flex-col md:flex-row gap-3">
          {/* Search */}
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-foreground-muted" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search by subject, sender, evidence ID, or SHA-256..."
              className="w-full pl-9 pr-8 py-2 bg-surface-secondary border border-border rounded-lg text-xs font-mono text-foreground placeholder:text-foreground-muted focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary transition-colors"
            />
            {searchQuery && (
              <button
                onClick={() => setSearchQuery('')}
                className="absolute right-2.5 top-1/2 -translate-y-1/2 text-foreground-muted hover:text-foreground cursor-pointer"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            )}
          </div>

          {/* Filter toggle */}
          <button
            onClick={() => setShowFilters(!showFilters)}
            className={`flex items-center space-x-1.5 px-3 py-2 rounded-lg border text-xs font-mono font-medium transition-all cursor-pointer ${
              showFilters || severityFilter !== 'all'
                ? 'bg-primary-subtle text-primary border-primary/30'
                : 'bg-surface-secondary text-foreground-muted border-border hover:text-foreground'
            }`}
          >
            <Filter className="w-3.5 h-3.5" />
            <span>Filters</span>
            {severityFilter !== 'all' && (
              <span className="ml-1 px-1.5 py-0.5 rounded-badge bg-primary/20 text-primary text-[9px] font-bold uppercase">
                {severityFilter}
              </span>
            )}
            <ChevronDown className={`w-3 h-3 transition-transform ${showFilters ? 'rotate-180' : ''}`} />
          </button>
        </div>

        {/* Filter options row */}
        {showFilters && (
          <div className="mt-3 pt-3 border-t border-border flex flex-wrap items-center gap-2">
            <span className="text-[10px] font-mono text-foreground-muted uppercase tracking-wider mr-1">Severity:</span>
            {(['all', 'critical', 'high', 'medium', 'low'] as SeverityFilter[]).map(sev => (
              <button
                key={sev}
                onClick={() => setSeverityFilter(sev)}
                className={`px-2.5 py-1 rounded-lg border text-[10px] font-mono font-semibold uppercase tracking-wider transition-all cursor-pointer ${
                  severityFilter === sev
                    ? 'bg-primary text-primary-foreground border-primary'
                    : 'bg-surface-secondary text-foreground-muted border-border hover:text-foreground hover:border-border-hover'
                }`}
              >
                {sev === 'all' ? 'All' : sev}
              </button>
            ))}
          </div>
        )}
      </div>

      {/* Error State */}
      {error && (
        <div className="p-5 rounded-xl bg-danger-surface border border-danger-border flex items-start space-x-3 text-xs font-mono text-danger">
          <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
          <div>
            <strong className="block font-bold">Failed to Load Investigation History</strong>
            <span>{error}. Ensure the backend forensic engine is running.</span>
          </div>
        </div>
      )}

      {/* Loading State */}
      {loading && !error && (
        <div className="bg-surface rounded-xl border border-border p-12">
          <div className="flex flex-col items-center justify-center space-y-3">
            <Loader2 className="w-6 h-6 text-primary animate-spin" />
            <p className="text-xs font-mono text-foreground-muted">Loading investigation records from database...</p>
          </div>
        </div>
      )}

      {/* Empty State */}
      {!loading && !error && total === 0 && (
        <div className="bg-surface rounded-xl border border-border p-12">
          <div className="flex flex-col items-center justify-center space-y-4 max-w-sm mx-auto text-center">
            <div className="p-4 rounded-full bg-surface-secondary border border-border">
              <Inbox className="w-8 h-8 text-foreground-muted/50" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-foreground font-sans">
                No Investigations Yet
              </h3>
              <p className="text-xs text-foreground-muted font-mono mt-1.5 leading-relaxed">
                No email evidence has been ingested and analyzed. Upload an .eml file in the analysis console to begin building your investigation archive.
              </p>
            </div>
            <button
              onClick={() => navigate('/analyze')}
              className="flex items-center space-x-2 px-4 py-2 rounded-lg bg-primary hover:bg-primary-hover text-primary-foreground text-xs font-mono font-semibold transition-colors btn-press cursor-pointer"
            >
              <FileSearch className="w-3.5 h-3.5" />
              <span>Analyze First Email</span>
            </button>
          </div>
        </div>
      )}

      {/* Results Table */}
      {!loading && !error && filteredItems.length > 0 && (
        <div className="bg-surface rounded-xl border border-border overflow-hidden">
          {/* Table header */}
          <div className="grid grid-cols-[1fr_180px_100px_100px_140px_60px] gap-0 px-4 py-2.5 bg-surface-secondary/50 border-b border-border">
            <button
              onClick={() => toggleSort('subject')}
              className="flex items-center space-x-1.5 text-[10px] font-mono font-semibold text-foreground-muted uppercase tracking-wider hover:text-foreground transition-colors cursor-pointer text-left"
            >
              <FileText className="w-3 h-3" />
              <span>Subject</span>
              <SortIcon field="subject" />
            </button>
            <button
              onClick={() => toggleSort('sender')}
              className="flex items-center space-x-1.5 text-[10px] font-mono font-semibold text-foreground-muted uppercase tracking-wider hover:text-foreground transition-colors cursor-pointer text-left"
            >
              <User className="w-3 h-3" />
              <span>Sender</span>
              <SortIcon field="sender" />
            </button>
            <button
              onClick={() => toggleSort('threat_score')}
              className="flex items-center space-x-1.5 text-[10px] font-mono font-semibold text-foreground-muted uppercase tracking-wider hover:text-foreground transition-colors cursor-pointer text-left"
            >
              <ShieldAlert className="w-3 h-3" />
              <span>Score</span>
              <SortIcon field="threat_score" />
            </button>
            <button
              onClick={() => toggleSort('severity')}
              className="flex items-center space-x-1.5 text-[10px] font-mono font-semibold text-foreground-muted uppercase tracking-wider hover:text-foreground transition-colors cursor-pointer text-left"
            >
              <AlertTriangle className="w-3 h-3" />
              <span>Severity</span>
              <SortIcon field="severity" />
            </button>
            <button
              onClick={() => toggleSort('timestamp')}
              className="flex items-center space-x-1.5 text-[10px] font-mono font-semibold text-foreground-muted uppercase tracking-wider hover:text-foreground transition-colors cursor-pointer text-left"
            >
              <Clock className="w-3 h-3" />
              <span>Analyzed</span>
              <SortIcon field="timestamp" />
            </button>
            <span className="text-[10px] font-mono font-semibold text-foreground-muted uppercase tracking-wider text-right">
              Open
            </span>
          </div>

          {/* Table rows */}
          {filteredItems.map((item) => {
            const sevConfig = SEVERITY_CONFIG[item.severity?.toLowerCase()] || SEVERITY_CONFIG.low;
            const isOpening = openingId === item.id;
            return (
              <div
                key={item.id}
                onClick={() => !isOpening && openAnalysis(item)}
                className="grid grid-cols-[1fr_180px_100px_100px_140px_60px] gap-0 px-4 py-3 border-b border-border/50 hover:bg-surface-secondary/40 transition-colors cursor-pointer group"
              >
                {/* Subject + Evidence ID */}
                <div className="min-w-0 pr-3">
                  <p className="text-xs font-medium text-foreground truncate group-hover:text-primary transition-colors">
                    {item.subject || 'Untitled Email'}
                  </p>
                  <div className="flex items-center space-x-2 mt-0.5">
                    {item.evidence_id && (
                      <span className="text-[10px] font-mono text-foreground-muted flex items-center space-x-1">
                        <Hash className="w-2.5 h-2.5" />
                        <span>{item.evidence_id}</span>
                      </span>
                    )}
                    {item.sha256 && (
                      <span className="text-[10px] font-mono text-foreground-muted/60 truncate max-w-[120px]" title={item.sha256}>
                        {item.sha256.slice(0, 12)}...
                      </span>
                    )}
                  </div>
                </div>

                {/* Sender */}
                <div className="flex items-center min-w-0">
                  <span className="text-xs font-mono text-foreground-muted truncate" title={item.sender}>
                    {item.sender || 'unknown'}
                  </span>
                </div>

                {/* Threat Score */}
                <div className="flex items-center">
                  <span className={`inline-flex items-center px-2 py-0.5 rounded-md border text-xs font-mono font-bold ${getThreatBg(item.threat_score)} ${getThreatColor(item.threat_score)}`}>
                    {Math.round(item.threat_score)}
                  </span>
                </div>

                {/* Severity */}
                <div className="flex items-center">
                  <span className={`inline-flex items-center space-x-1 px-2 py-0.5 rounded-md border text-[10px] font-mono uppercase tracking-wider ${sevConfig.classes}`}>
                    <span className={`w-1.5 h-1.5 rounded-full ${sevConfig.dot}`} />
                    <span>{sevConfig.label}</span>
                  </span>
                </div>

                {/* Timestamp */}
                <div className="flex flex-col justify-center">
                  <span className="text-[11px] font-mono text-foreground-muted" title={formatTimestamp(item.timestamp)}>
                    {formatRelativeTime(item.timestamp)}
                  </span>
                </div>

                {/* Action */}
                <div className="flex items-center justify-end">
                  {isOpening ? (
                    <Loader2 className="w-3.5 h-3.5 text-primary animate-spin" />
                  ) : (
                    <ExternalLink className="w-3.5 h-3.5 text-foreground-muted/40 group-hover:text-primary transition-colors" />
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* No results after filter */}
      {!loading && !error && total > 0 && filteredItems.length === 0 && (
        <div className="bg-surface rounded-xl border border-border p-8 text-center">
          <Search className="w-6 h-6 text-foreground-muted/40 mx-auto mb-2" />
          <p className="text-xs font-mono text-foreground-muted">
            No emails match your current search or filter criteria.
          </p>
          <button
            onClick={() => { setSearchQuery(''); setSeverityFilter('all'); }}
            className="mt-2 text-xs font-mono text-primary hover:underline cursor-pointer"
          >
            Clear filters
          </button>
        </div>
      )}

      {/* Pagination */}
      {!loading && !error && total > pageSize && (
        <div className="flex items-center justify-between bg-surface rounded-xl border border-border px-4 py-3">
          <span className="text-[11px] font-mono text-foreground-muted">
            Showing {page * pageSize + 1}–{Math.min((page + 1) * pageSize, total)} of {total} records
          </span>
          <div className="flex items-center space-x-1.5">
            <button
              onClick={() => setPage(p => Math.max(0, p - 1))}
              disabled={page === 0}
              className="p-1.5 rounded-lg border border-border bg-surface-secondary text-foreground-muted hover:text-foreground hover:border-border-hover disabled:opacity-30 disabled:cursor-not-allowed transition-all cursor-pointer"
            >
              <ChevronLeft className="w-3.5 h-3.5" />
            </button>
            {Array.from({ length: Math.min(totalPages, 5) }, (_, i) => {
              let pageNum: number;
              if (totalPages <= 5) {
                pageNum = i;
              } else if (page < 3) {
                pageNum = i;
              } else if (page > totalPages - 4) {
                pageNum = totalPages - 5 + i;
              } else {
                pageNum = page - 2 + i;
              }
              return (
                <button
                  key={pageNum}
                  onClick={() => setPage(pageNum)}
                  className={`w-7 h-7 rounded-lg border text-[11px] font-mono font-medium transition-all cursor-pointer ${
                    page === pageNum
                      ? 'bg-primary text-primary-foreground border-primary'
                      : 'bg-surface-secondary text-foreground-muted border-border hover:text-foreground hover:border-border-hover'
                  }`}
                >
                  {pageNum + 1}
                </button>
              );
            })}
            <button
              onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))}
              disabled={page >= totalPages - 1}
              className="p-1.5 rounded-lg border border-border bg-surface-secondary text-foreground-muted hover:text-foreground hover:border-border-hover disabled:opacity-30 disabled:cursor-not-allowed transition-all cursor-pointer"
            >
              <ChevronRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      )}

      {/* Footer provenance notice */}
      <div className="p-3.5 rounded-xl bg-surface border border-border flex items-start space-x-2.5 text-[11px] font-mono text-foreground-muted">
        <History className="w-3.5 h-3.5 text-primary shrink-0 mt-0.5" />
        <p className="leading-relaxed">
          <strong className="text-foreground">Database-Driven Investigation Archive</strong> — All records displayed are retrieved from the persistent SQLite forensic database. Each entry represents a real, ingested .eml file with cryptographic SHA-256 evidence hashing. Click any row to rehydrate the full forensic analysis from the stored canonical payload.
        </p>
      </div>
    </div>
  );
};

export default InvestigationHistory;
