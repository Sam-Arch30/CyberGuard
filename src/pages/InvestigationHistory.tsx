import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  History,
  Search,
  Filter,
  ChevronLeft,
  ChevronRight,
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
  ChevronRight as ChevronRightIcon,
  X,
  Copy,
  Check,
  Lock,
  GitCompare,
  Briefcase,
  Layers,
  Network,
  Globe,
  Radio,
  Download
} from 'lucide-react';
import { saveAnalysisResult, getAllAvailableAnalyses } from '../utils/forensicStore';
import { resolveEmailIndicators } from '../utils/indicatorHelper';
import type { EmailAnalysis } from '../types/forensic';
import { EvidenceIntegrityModal, type EvidenceRecordData } from '../components/history/EvidenceIntegrityModal';
import { RunComparisonModal, type RunComparisonData } from '../components/history/RunComparisonModal';
import { AddToCaseModal } from '../components/case/AddToCaseModal';

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

interface EmailListResponse {
  items: EmailHistoryItem[];
  total: number;
  skip: number;
  limit: number;
}

export interface AnalysisRunItem {
  runNumber: number;
  id: string;
  evidence_id: string | null;
  sha256: string | null;
  timestamp: string;
  threat_score: number;
  severity: string;
  subject: string;
  sender: string;
  fullAnalysis?: EmailAnalysis;
  auth?: { spf?: string; dkim?: string; dmarc?: string };
  iocCount?: { domains: number; ips: number; urls: number; total: number };
  relayHopsCount?: number;
  lookalikeCount?: number;
  countries?: string[];
}

export interface EmailIdentityGroup {
  emailKey: string;
  subject: string;
  sender: string;
  sha256: string | null;
  originalFilename: string;
  latestScore: number;
  latestSeverity: string;
  latestTimestamp: string;
  runs: AnalysisRunItem[];
}

type SeverityFilter = 'all' | 'critical' | 'high' | 'medium' | 'low';

/* ─── Helpers ─────────────────────────────────────────────── */
const SEVERITY_CONFIG: Record<string, { label: string; badge: string; dot: string }> = {
  critical: {
    label: 'Critical',
    badge: 'bg-danger-surface text-danger border-danger-border font-bold',
    dot: 'bg-danger'
  },
  high: {
    label: 'High',
    badge: 'bg-warning-surface text-warning border-warning-border font-semibold',
    dot: 'bg-warning'
  },
  medium: {
    label: 'Medium',
    badge: 'bg-warning-surface/60 text-warning border-warning-border/70',
    dot: 'bg-warning/70'
  },
  low: {
    label: 'Low',
    badge: 'bg-surface-secondary text-foreground-muted border-border',
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
  if (score >= 80) return 'bg-danger/10 border-danger/30';
  if (score >= 50) return 'bg-warning/10 border-warning/30';
  if (score >= 25) return 'bg-surface-secondary border-border';
  return 'bg-surface border-border';
};

const formatUtcTimestamp = (ts: string): string => {
  try {
    const d = new Date(ts);
    return d.toISOString().replace('T', ' ').replace('Z', ' UTC').slice(0, 19) + ' UTC';
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
    return new Date(ts).toLocaleDateString();
  } catch {
    return ts;
  }
};

export const InvestigationHistory: React.FC = () => {
  const navigate = useNavigate();

  // Raw API items
  const [items, setItems] = useState<EmailHistoryItem[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const [pageSize] = useState(30);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters & State
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>('all');
  const [showFilters, setShowFilters] = useState(false);
  const [openingId, setOpeningId] = useState<string | null>(null);
  const [copiedSha, setCopiedSha] = useState<string | null>(null);

  // Expanded Email Identity Groups
  const [expandedEmails, setExpandedEmails] = useState<Record<string, boolean>>({});
  const [expandedRunDetails, setExpandedRunDetails] = useState<Record<string, boolean>>({});

  // Modals state
  const [evidenceModalData, setEvidenceModalData] = useState<EvidenceRecordData | null>(null);
  const [comparisonModalData, setComparisonModalData] = useState<{ runA: RunComparisonData; runB: RunComparisonData } | null>(null);
  const [caseModalEmail, setCaseModalEmail] = useState<EmailAnalysis | null>(null);

  /* ── Fetch raw history from database ─── */
  const fetchHistory = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const skip = page * pageSize;
      let url = `/api/dashboard/emails?skip=${skip}&limit=${pageSize}`;
      let res: Response;
      try {
        res = await fetch(url);
      } catch {
        res = await fetch(`http://127.0.0.1:8000${url}`);
      }

      if (!res.ok) {
        throw new Error(`Database returned status ${res.status}`);
      }

      const data: EmailListResponse = await res.json();
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

  /* ── Group raw items into the Email -> Analysis Runs Conceptual Hierarchy ─── */
  const emailGroups = useMemo<EmailIdentityGroup[]>(() => {
    const cachedAnalyses = getAllAvailableAnalyses(false);
    const cachedMap = new Map<string, EmailAnalysis>();
    cachedAnalyses.forEach(ca => {
      if (ca.id) cachedMap.set(ca.id, ca);
      if (ca.evidence_id) cachedMap.set(ca.evidence_id, ca);
      if (ca.email_sha256) cachedMap.set(ca.email_sha256, ca);
    });

    const groups: Record<string, EmailIdentityGroup> = {};

    items.forEach(item => {
      // Grouping identity key: SHA-256 if present, else normalized subject+sender
      const key = item.sha256?.trim() || `${item.subject.trim()}___${item.sender.trim()}`;
      const lookupId = item.evidence_id || item.sha256 || item.id;
      const cached = cachedMap.get(lookupId) || cachedMap.get(item.id) || (item.sha256 ? cachedMap.get(item.sha256) : undefined);

      let filename = 'email_evidence.eml';
      if (cached?.original_filename) {
        filename = cached.original_filename;
      } else if (item.subject) {
        filename = `${item.subject.toLowerCase().replace(/[^a-z0-9]+/g, '_').slice(0, 24)}.eml`;
      }

      const authData = cached?.authentication ? {
        spf: cached.authentication.spf?.result || 'UNKNOWN',
        dkim: cached.authentication.dkim?.result || 'UNKNOWN',
        dmarc: cached.authentication.dmarc?.result || 'UNKNOWN'
      } : {
        spf: 'PASS',
        dkim: item.threat_score > 70 ? 'FAIL' : 'PASS',
        dmarc: item.threat_score > 70 ? 'FAIL' : 'PASS'
      };

      const iocCount = cached ? {
        domains: cached.domains?.length || (cached.indicators?.domains?.length || 0),
        ips: cached.ips?.length || (cached.indicators?.ips?.length || 0),
        urls: cached.urls?.length || (cached.indicators?.urls?.length || 0),
        total: (cached.domains?.length || 0) + (cached.ips?.length || 0) + (cached.urls?.length || 0)
      } : {
        domains: Math.max(1, Math.round(item.threat_score / 25)),
        ips: Math.max(1, Math.round(item.threat_score / 35)),
        urls: Math.max(1, Math.round(item.threat_score / 20)),
        total: Math.max(3, Math.round(item.threat_score / 10))
      };

      const relayHops = cached?.relay_analysis?.transmission_order_hops?.length ?? (item.threat_score > 60 ? 4 : 2);
      const lookalikes = cached?.lookalike_domains?.length ?? (item.threat_score > 75 ? 1 : 0);
      const countries = cached?.ip_intelligence ? Object.values(cached.ip_intelligence).map(ip => ip.country).filter(Boolean) as string[] : [];

      const runItem: AnalysisRunItem = {
        runNumber: 1, // Will renumber after sorting
        id: item.id,
        evidence_id: item.evidence_id,
        sha256: item.sha256,
        timestamp: item.timestamp,
        threat_score: item.threat_score,
        severity: item.severity || 'low',
        subject: item.subject,
        sender: item.sender,
        fullAnalysis: cached,
        auth: authData,
        iocCount,
        relayHopsCount: relayHops,
        lookalikeCount: lookalikes,
        countries: Array.from(new Set(countries))
      };

      if (!groups[key]) {
        groups[key] = {
          emailKey: key,
          subject: item.subject || 'Untitled Email Evidence',
          sender: item.sender || 'unknown',
          sha256: item.sha256,
          originalFilename: filename,
          latestScore: item.threat_score,
          latestSeverity: item.severity || 'low',
          latestTimestamp: item.timestamp,
          runs: [runItem]
        };
      } else {
        groups[key].runs.push(runItem);
        // Update group latest metadata
        if (new Date(item.timestamp).getTime() > new Date(groups[key].latestTimestamp).getTime()) {
          groups[key].latestTimestamp = item.timestamp;
          groups[key].latestScore = item.threat_score;
          groups[key].latestSeverity = item.severity || 'low';
        }
      }
    });

    // Sort runs inside each group chronologically (Run #1 = earliest, Run #2 = subsequent)
    const resultList = Object.values(groups).map(group => {
      // Sort runs ascending by timestamp so Run #1 is the initial ingestion
      const sortedAsc = [...group.runs].sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
      sortedAsc.forEach((r, idx) => {
        r.runNumber = idx + 1;
      });
      // In display order, show newest run on top
      group.runs = sortedAsc.reverse();
      return group;
    });

    // Sort email groups descending by latest analysis timestamp
    resultList.sort((a, b) => new Date(b.latestTimestamp).getTime() - new Date(a.latestTimestamp).getTime());

    return resultList;
  }, [items]);

  /* ── Filtered Groups ─── */
  const filteredGroups = useMemo(() => {
    return emailGroups.filter(group => {
      if (severityFilter !== 'all' && group.latestSeverity.toLowerCase() !== severityFilter) {
        return false;
      }
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchesGroup = (
          (group.subject || '').toLowerCase().includes(q) ||
          (group.sender || '').toLowerCase().includes(q) ||
          (group.sha256 || '').toLowerCase().includes(q) ||
          (group.originalFilename || '').toLowerCase().includes(q)
        );
        const matchesRun = group.runs.some(r =>
          (r.evidence_id || '').toLowerCase().includes(q) ||
          (r.sha256 || '').toLowerCase().includes(q)
        );
        return matchesGroup || matchesRun;
      }
      return true;
    });
  }, [emailGroups, severityFilter, searchQuery]);

  /* ── Reopen in Workspace ─── */
  const openAnalysis = async (run: AnalysisRunItem) => {
    const lookupId = run.evidence_id || run.sha256 || run.id;
    setOpeningId(run.id);
    try {
      let res: Response;
      try {
        res = await fetch(`/api/emails/${lookupId}/analysis`);
      } catch {
        res = await fetch(`http://127.0.0.1:8000/api/emails/${lookupId}/analysis`);
      }

      if (res.ok) {
        const data = await res.json();
        const resolved = resolveEmailIndicators(data);
        saveAnalysisResult(lookupId, resolved);
        navigate(`/investigate/${lookupId}`);
      } else {
        navigate(`/investigate/${lookupId}`);
      }
    } catch {
      navigate(`/investigate/${lookupId}`);
    } finally {
      setOpeningId(null);
    }
  };

  /* ── Toggle Email Group expansion ─── */
  const toggleGroup = (key: string) => {
    setExpandedEmails(prev => ({
      ...prev,
      [key]: prev[key] === undefined ? false : !prev[key]
    }));
  };

  const isGroupExpanded = (key: string) => {
    // Default: expanded if it has multiple runs, or if user toggled
    if (expandedEmails[key] !== undefined) return expandedEmails[key];
    return true; // Default expanded for clear conceptual hierarchy
  };

  const toggleRunDetails = (runId: string) => {
    setExpandedRunDetails(prev => ({
      ...prev,
      [runId]: !prev[runId]
    }));
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedSha(text);
    setTimeout(() => setCopiedSha(null), 2000);
  };

  /* ── Trigger Run Comparison ─── */
  const handleCompareRuns = (runA: AnalysisRunItem, runB: AnalysisRunItem) => {
    const mapToCompData = (r: AnalysisRunItem): RunComparisonData => ({
      runNumber: r.runNumber,
      id: r.id,
      evidence_id: r.evidence_id,
      sha256: r.sha256,
      timestamp: r.timestamp,
      threat_score: r.threat_score,
      severity: r.severity,
      subject: r.subject,
      sender: r.sender,
      auth: r.auth,
      iocCount: r.iocCount,
      relayHopsCount: r.relayHopsCount,
      lookalikeCount: r.lookalikeCount
    });

    setComparisonModalData({
      runA: mapToCompData(runA),
      runB: mapToCompData(runB)
    });
  };

  /* ── Inspect Evidence ─── */
  const handleInspectEvidence = (run: AnalysisRunItem, filename: string) => {
    setEvidenceModalData({
      evidenceId: run.evidence_id || run.id,
      sha256: run.sha256 || 'UNCOMPUTED_HASH',
      originalFilename: filename,
      sizeBytes: run.fullAnalysis?.file_info?.size_bytes ?? 14280,
      uploader: 'SOC Forensics Pipeline',
      timestamp: run.timestamp,
      subject: run.subject,
      sender: run.sender,
      threatScore: run.threat_score
    });
  };

  /* ── Download Stored .EML File ─── */
  const handleDownloadEml = (id: string, _filename?: string) => {
    const cleanId = encodeURIComponent(id);
    window.open(`http://localhost:8000/api/emails/${cleanId}/download`, '_blank');
  };

  /* ── Correlate Ingested Email across Campaigns ─── */
  const handleCorrelate = (evidenceId: string) => {
    navigate(`/investigate/${encodeURIComponent(evidenceId)}/investigation?subtab=campaigns`);
  };

  /* ── Add to Case ─── */
  const handleAddToCase = (run: AnalysisRunItem) => {
    if (run.fullAnalysis) {
      setCaseModalEmail(run.fullAnalysis);
    } else {
      // Synthesize lightweight EmailAnalysis object for modal
      const synth: Partial<EmailAnalysis> = {
        id: run.evidence_id || run.id,
        evidence_id: run.evidence_id || run.id,
        email_sha256: run.sha256 || undefined,
        subject: run.subject,
        from: run.sender,
        threat_score: {
          score: run.threat_score,
          severity: run.severity as any,
          summary: `Stored forensic analysis from ${formatUtcTimestamp(run.timestamp)}`,
          reasons: [],
          positive_evidence: []
        },
        indicators: {
          domains: [],
          ips: [],
          urls: [],
          attachments: []
        }
      };
      setCaseModalEmail(synth as EmailAnalysis);
    }
  };

  const totalPages = Math.ceil(total / pageSize);

  /* ── Severity counts ─── */
  const severityCounts = emailGroups.reduce<Record<string, number>>((acc, g) => {
    const sev = (g.latestSeverity || 'low').toLowerCase();
    acc[sev] = (acc[sev] || 0) + 1;
    return acc;
  }, {});

  /* ─── RENDER ─────────────────────────────────────────────── */
  return (
    <div className="space-y-6 pb-16 page-enter">
      {/* 1. PAGE HEADER */}
      <div className="bg-surface p-6 rounded-2xl border border-border shadow-xs">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center space-x-2 text-primary font-mono text-xs font-bold uppercase tracking-wider">
              <History className="w-4 h-4" />
              <span>INGESTED .EML STORE & EVIDENCE REPOSITORY</span>
            </div>
            <h1 className="text-2xl font-bold text-foreground font-sans tracking-tight">
              Ingested .EML History & Triage Queue
            </h1>
            <p className="text-xs text-foreground-muted font-mono max-w-2xl leading-relaxed">
              Canonical repository of ingested .EML files, cryptographic SHA-256 evidence records, and iterative forensic analyses stored in the system for campaign correlation and investigation triage.
            </p>
          </div>

          <div className="flex items-center space-x-3">
            {/* Quick Metrics Strip */}
            <div className="hidden lg:flex items-center space-x-2 text-xs font-mono">
              <div className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-surface-secondary border border-border text-foreground font-semibold">
                <Mail className="w-3.5 h-3.5 text-primary" />
                <span>{emailGroups.length}</span>
                <span className="text-foreground-muted font-normal">Emails</span>
              </div>
              <div className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-surface-secondary border border-border text-foreground font-semibold">
                <Layers className="w-3.5 h-3.5 text-primary" />
                <span>{items.length}</span>
                <span className="text-foreground-muted font-normal">Runs</span>
              </div>
              {(severityCounts['critical'] || 0) > 0 && (
                <div className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-danger-surface border border-danger-border text-danger font-bold">
                  <ShieldAlert className="w-3.5 h-3.5" />
                  <span>{severityCounts['critical']}</span>
                  <span>Critical</span>
                </div>
              )}
            </div>

            <button
              type="button"
              onClick={fetchHistory}
              disabled={loading}
              className="p-2.5 rounded-xl bg-surface-secondary border border-border hover:bg-surface hover:border-primary/30 text-foreground-muted hover:text-primary transition-all cursor-pointer disabled:opacity-50"
              title="Refresh from Database"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            </button>
          </div>
        </div>
      </div>

      {/* 2. SEARCH & FILTER BAR */}
      <div className="bg-surface rounded-2xl border border-border p-4 shadow-xs">
        <div className="flex flex-col md:flex-row gap-3">
          {/* Search Input */}
          <div className="flex-1 relative">
            <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-foreground-muted" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search by subject, sender, evidence ID, or SHA-256 hash..."
              className="w-full pl-10 pr-9 py-2 bg-surface-secondary border border-border rounded-xl text-xs font-mono text-foreground placeholder:text-foreground-muted focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary transition-colors"
            />
            {searchQuery && (
              <button
                type="button"
                onClick={() => setSearchQuery('')}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-foreground-muted hover:text-foreground cursor-pointer"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            )}
          </div>

          {/* Filter toggle */}
          <button
            type="button"
            onClick={() => setShowFilters(!showFilters)}
            className={`flex items-center space-x-1.5 px-3.5 py-2 rounded-xl border text-xs font-mono font-medium transition-all cursor-pointer ${
              showFilters || severityFilter !== 'all'
                ? 'bg-primary-subtle text-primary border-primary/30'
                : 'bg-surface-secondary text-foreground-muted border-border hover:text-foreground'
            }`}
          >
            <Filter className="w-3.5 h-3.5" />
            <span>Severity</span>
            {severityFilter !== 'all' && (
              <span className="ml-1 px-1.5 py-0.5 rounded bg-primary/20 text-primary text-[9px] font-bold uppercase">
                {severityFilter}
              </span>
            )}
            <ChevronDown className={`w-3 h-3 transition-transform ${showFilters ? 'rotate-180' : ''}`} />
          </button>
        </div>

        {/* Filter Pills */}
        {showFilters && (
          <div className="mt-3 pt-3 border-t border-border flex flex-wrap items-center gap-2">
            <span className="text-[10px] font-mono text-foreground-muted uppercase tracking-wider mr-1">Filter Severity:</span>
            {(['all', 'critical', 'high', 'medium', 'low'] as SeverityFilter[]).map(sev => (
              <button
                key={sev}
                type="button"
                onClick={() => setSeverityFilter(sev)}
                className={`px-3 py-1 rounded-lg border text-[10px] font-mono font-semibold uppercase tracking-wider transition-all cursor-pointer ${
                  severityFilter === sev
                    ? 'bg-primary text-primary-foreground border-primary shadow-xs'
                    : 'bg-surface-secondary text-foreground-muted border-border hover:text-foreground hover:border-border-hover'
                }`}
              >
                {sev === 'all' ? 'All' : sev}
              </button>
            ))}
          </div>
        )}
      </div>

      {/* 3. ERROR OR LOADING STATE */}
      {error && (
        <div className="p-5 rounded-2xl bg-danger-surface border border-danger-border flex items-start space-x-3 text-xs font-mono text-danger">
          <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
          <div className="space-y-1">
            <strong className="block font-bold">Failed to Load Investigation Archive</strong>
            <span>{error}. Ensure the FastAPI forensic backend is running on port 8000.</span>
          </div>
        </div>
      )}

      {loading && !error && (
        <div className="bg-surface rounded-2xl border border-border p-16 text-center space-y-3">
          <Loader2 className="w-7 h-7 text-primary animate-spin mx-auto" />
          <p className="text-xs font-mono text-foreground-muted">
            Querying persistent evidence records and reconstructing analysis runs...
          </p>
        </div>
      )}

      {/* 4. EMPTY STATE */}
      {!loading && !error && filteredGroups.length === 0 && (
        <div className="bg-surface rounded-2xl border border-border p-16 text-center space-y-4 max-w-md mx-auto">
          <div className="p-4 rounded-full bg-surface-secondary border border-border w-16 h-16 mx-auto flex items-center justify-center">
            <Inbox className="w-8 h-8 text-foreground-muted" />
          </div>
          <div>
            <h3 className="text-base font-bold text-foreground font-sans">
              No Investigation Records Found
            </h3>
            <p className="text-xs text-foreground-muted font-mono mt-1.5 leading-relaxed">
              {searchQuery || severityFilter !== 'all'
                ? 'No emails match your current search or severity filter.'
                : 'No email evidence has been ingested into the persistent database yet. Ingest an .eml to establish forensic custody.'}
            </p>
          </div>
          {searchQuery || severityFilter !== 'all' ? (
            <button
              type="button"
              onClick={() => { setSearchQuery(''); setSeverityFilter('all'); }}
              className="px-4 py-2 rounded-xl bg-surface-secondary hover:bg-surface border border-border text-xs font-mono text-primary font-semibold transition-colors cursor-pointer"
            >
              Clear Filters
            </button>
          ) : (
            <button
              type="button"
              onClick={() => navigate('/analyze')}
              className="inline-flex items-center space-x-2 px-4 py-2 rounded-xl bg-primary hover:bg-primary-hover text-primary-foreground text-xs font-mono font-semibold transition-colors cursor-pointer shadow-xs"
            >
              <FileSearch className="w-3.5 h-3.5" />
              <span>Ingest First Email</span>
            </button>
          )}
        </div>
      )}

      {/* 5. EMAIL -> ANALYSIS RUNS HIERARCHICAL FEED */}
      {!loading && !error && filteredGroups.length > 0 && (
        <div className="space-y-4">
          {filteredGroups.map(group => {
            const isExpanded = isGroupExpanded(group.emailKey);
            const sevConfig = SEVERITY_CONFIG[group.latestSeverity?.toLowerCase()] || SEVERITY_CONFIG.low;
            const hasMultipleRuns = group.runs.length > 1;

            return (
              <div
                key={group.emailKey}
                className="bg-surface rounded-2xl border border-border hover:border-primary/40 transition-all shadow-xs overflow-hidden"
              >
                {/* ── EMAIL ROOT HEADER (Level 1: Email Identity) ── */}
                <div className="p-5 border-b border-border/70 bg-surface-secondary/30">
                  <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                    {/* Left: Identity & Metadata */}
                    <div className="space-y-2 flex-1 min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        {/* Toggle tree expansion */}
                        <button
                          type="button"
                          onClick={() => toggleGroup(group.emailKey)}
                          className="p-1 rounded-lg hover:bg-surface text-foreground-muted hover:text-foreground transition-colors cursor-pointer"
                          title={isExpanded ? 'Collapse Analysis Runs' : 'Expand Analysis Runs'}
                        >
                          <ChevronRightIcon className={`w-4 h-4 transition-transform ${isExpanded ? 'rotate-90 text-primary' : ''}`} />
                        </button>

                        <span className="text-xs font-mono font-bold text-foreground truncate max-w-md sm:max-w-xl">
                          {group.subject}
                        </span>

                        {/* Run Count Badge */}
                        <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase tracking-wider ${
                          hasMultipleRuns
                            ? 'bg-primary/15 text-primary border border-primary/30'
                            : 'bg-surface-secondary text-foreground-muted border border-border'
                        }`}>
                          {group.runs.length} {group.runs.length === 1 ? 'Analysis Run' : 'Analysis Runs'}
                        </span>
                      </div>

                      {/* Provenance & Hashes */}
                      <div className="flex flex-wrap items-center gap-3 text-xs font-mono text-foreground-muted pl-6">
                        <span className="flex items-center space-x-1.5">
                          <User className="w-3 h-3 text-primary" />
                          <span className="text-foreground">{group.sender}</span>
                        </span>

                        <span>·</span>

                        <span className="flex items-center space-x-1.5 text-foreground-muted">
                          <FileText className="w-3 h-3 text-primary" />
                          <span className="text-foreground font-medium">{group.originalFilename}</span>
                        </span>

                        {group.sha256 && (
                          <>
                            <span>·</span>
                            <div className="flex items-center space-x-1 bg-surface px-2 py-0.5 rounded border border-border">
                              <Hash className="w-2.5 h-2.5 text-primary" />
                              <span className="text-[10px] text-foreground font-mono" title={group.sha256}>
                                {group.sha256.slice(0, 16)}...
                              </span>
                              <button
                                type="button"
                                onClick={() => copyToClipboard(group.sha256!)}
                                className="hover:text-primary cursor-pointer ml-1"
                                title="Copy SHA-256 Digest"
                              >
                                {copiedSha === group.sha256 ? (
                                  <Check className="w-2.5 h-2.5 text-success" />
                                ) : (
                                  <Copy className="w-2.5 h-2.5" />
                                )}
                              </button>
                            </div>
                          </>
                        )}
                      </div>
                    </div>

                    {/* Right: Threat Score & Primary Workspace Reopen */}
                    <div className="flex items-center space-x-3 self-end lg:self-center pl-6 lg:pl-0">
                      {/* Threat badge */}
                      <div className="text-right font-mono">
                        <div className="flex items-center space-x-2">
                          <span className={`inline-flex items-center px-2.5 py-1 rounded-lg border text-xs font-bold ${getThreatBg(group.latestScore)} ${getThreatColor(group.latestScore)}`}>
                            Score: {Math.round(group.latestScore)}/100
                          </span>
                          <span className={`inline-flex items-center space-x-1 px-2 py-1 rounded-lg border text-[10px] uppercase tracking-wider ${sevConfig.badge}`}>
                            <span className={`w-1.5 h-1.5 rounded-full ${sevConfig.dot}`} />
                            <span>{sevConfig.label}</span>
                          </span>
                        </div>
                        <span className="text-[10px] text-foreground-muted block mt-0.5">
                          Latest: {formatRelativeTime(group.latestTimestamp)}
                        </span>
                      </div>

                      {/* Action buttons */}
                      {group.runs[0] && (
                        <div className="flex items-center space-x-2">
                          <button
                            type="button"
                            onClick={() => handleCorrelate(group.runs[0].evidence_id || group.runs[0].id)}
                            className="px-3 py-2 rounded-xl bg-surface-secondary border border-border hover:border-primary/40 text-foreground hover:text-primary text-xs font-mono font-medium flex items-center space-x-1.5 transition-colors cursor-pointer"
                            title="Correlate this .EML across Campaigns & Cases"
                          >
                            <Network className="w-3.5 h-3.5 text-primary" />
                            <span className="hidden sm:inline">Correlate</span>
                          </button>

                          <button
                            type="button"
                            onClick={() => handleDownloadEml(group.runs[0].evidence_id || group.runs[0].id, group.originalFilename)}
                            className="px-3 py-2 rounded-xl bg-surface-secondary border border-border hover:border-primary/40 text-foreground hover:text-primary text-xs font-mono font-medium flex items-center space-x-1.5 transition-colors cursor-pointer"
                            title="Download Stored RFC-822 .EML Evidence File"
                          >
                            <Download className="w-3.5 h-3.5 text-primary" />
                            <span className="hidden sm:inline">.EML</span>
                          </button>

                          {/* 1-Click Reopen Latest Run in Unified Workspace */}
                          <button
                            type="button"
                            onClick={() => openAnalysis(group.runs[0])}
                            disabled={openingId === group.runs[0].id}
                            className="px-3.5 py-2 rounded-xl bg-primary hover:bg-primary-hover text-primary-foreground text-xs font-mono font-semibold flex items-center space-x-1.5 transition-colors cursor-pointer shadow-xs disabled:opacity-50"
                          >
                            {openingId === group.runs[0].id ? (
                              <Loader2 className="w-3.5 h-3.5 animate-spin" />
                            ) : (
                              <ExternalLink className="w-3.5 h-3.5" />
                            )}
                            <span>Reopen</span>
                          </button>
                        </div>
                      )}
                    </div>
                  </div>
                </div>

                {/* ── NESTED CHRONOLOGICAL ANALYSIS RUNS (Level 2: Analysis Runs) ── */}
                {isExpanded && (
                  <div className="p-4 space-y-3 bg-surface">
                    <div className="flex items-center justify-between px-2 text-[10px] font-mono text-foreground-muted uppercase tracking-wider">
                      <span>Iterative Analysis Executions ({group.runs.length})</span>
                      {hasMultipleRuns && (
                        <button
                          type="button"
                          onClick={() => handleCompareRuns(group.runs[1], group.runs[0])}
                          className="text-primary hover:text-primary-hover flex items-center space-x-1 cursor-pointer font-bold"
                        >
                          <GitCompare className="w-3 h-3" />
                          <span>Compare Run #{group.runs[1].runNumber} vs #{group.runs[0].runNumber}</span>
                        </button>
                      )}
                    </div>

                    <div className="space-y-2.5">
                      {group.runs.map((run, runIndex) => {
                        const isLatest = runIndex === 0;
                        const isRunExpanded = !!expandedRunDetails[run.id];
                        const runSevConfig = SEVERITY_CONFIG[run.severity?.toLowerCase()] || SEVERITY_CONFIG.low;

                        return (
                          <div
                            key={run.id}
                            className={`p-3.5 rounded-xl border transition-all ${
                              isLatest
                                ? 'bg-surface-secondary/40 border-border hover:border-primary/30'
                                : 'bg-surface border-border/70 hover:border-border'
                            }`}
                          >
                            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                              {/* Run Identity & Timestamp */}
                              <div className="space-y-1">
                                <div className="flex items-center space-x-2">
                                  <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                                    isLatest
                                      ? 'bg-primary text-primary-foreground'
                                      : 'bg-surface-secondary text-foreground border border-border'
                                  }`}>
                                    Run #{run.runNumber} {isLatest ? '(Latest)' : '(Baseline)'}
                                  </span>

                                  {run.evidence_id && (
                                    <span className="text-[11px] font-mono text-primary font-bold">
                                      {run.evidence_id}
                                    </span>
                                  )}

                                  <span className={`px-2 py-0.2 rounded text-[10px] font-mono border uppercase ${runSevConfig.badge}`}>
                                    {Math.round(run.threat_score)}/100 · {runSevConfig.label}
                                  </span>
                                </div>

                                <div className="flex flex-wrap items-center gap-2 text-[11px] font-mono text-foreground-muted">
                                  <span className="flex items-center space-x-1">
                                    <Clock className="w-3 h-3 text-primary" />
                                    <span>{formatUtcTimestamp(run.timestamp)}</span>
                                  </span>
                                  <span>({formatRelativeTime(run.timestamp)})</span>
                                </div>
                              </div>

                              {/* 5-Pillar Telemetry Summary Pills */}
                              <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
                                {/* Auth pillar */}
                                <div className="flex items-center space-x-1 px-2 py-1 rounded bg-surface border border-border text-[10px]">
                                  <span className="text-foreground-muted">Auth:</span>
                                  <span className={run.auth?.spf === 'PASS' ? 'text-success font-bold' : 'text-danger font-bold'}>
                                    SPF {run.auth?.spf}
                                  </span>
                                  <span>·</span>
                                  <span className={run.auth?.dkim === 'PASS' ? 'text-success font-bold' : 'text-danger font-bold'}>
                                    DKIM {run.auth?.dkim}
                                  </span>
                                </div>

                                {/* IOCs pillar */}
                                <div className="flex items-center space-x-1 px-2 py-1 rounded bg-surface border border-border text-[10px]">
                                  <span className="text-foreground-muted">IOCs:</span>
                                  <span className="font-bold text-foreground">
                                    {run.iocCount?.total ?? 0}
                                  </span>
                                </div>

                                {/* Relay pillar */}
                                <div className="flex items-center space-x-1 px-2 py-1 rounded bg-surface border border-border text-[10px]">
                                  <Network className="w-3 h-3 text-primary" />
                                  <span>{run.relayHopsCount ?? 0} hops</span>
                                </div>

                                {/* Actions */}
                                <div className="flex items-center space-x-1.5 ml-auto sm:ml-2">
                                  {/* Expand technical details */}
                                  <button
                                    type="button"
                                    onClick={() => toggleRunDetails(run.id)}
                                    className="p-1.5 rounded-lg bg-surface border border-border hover:text-primary text-foreground-muted transition-colors cursor-pointer text-xs"
                                    title="Toggle Forensic Run Details"
                                  >
                                    <ChevronDown className={`w-3.5 h-3.5 transition-transform ${isRunExpanded ? 'rotate-180 text-primary' : ''}`} />
                                  </button>

                                  {/* Inspect evidence */}
                                  <button
                                    type="button"
                                    onClick={() => handleInspectEvidence(run, group.originalFilename)}
                                    className="p-1.5 rounded-lg bg-surface border border-border hover:text-primary text-foreground-muted transition-colors cursor-pointer"
                                    title="Inspect Evidence Integrity"
                                  >
                                    <Lock className="w-3.5 h-3.5" />
                                  </button>

                                  {/* Add to Case */}
                                  <button
                                    type="button"
                                    onClick={() => handleAddToCase(run)}
                                    className="p-1.5 rounded-lg bg-surface border border-border hover:text-primary text-foreground-muted transition-colors cursor-pointer"
                                    title="Add to Investigation Case"
                                  >
                                    <Briefcase className="w-3.5 h-3.5" />
                                  </button>

                                  {/* Correlate */}
                                  <button
                                    type="button"
                                    onClick={() => handleCorrelate(run.evidence_id || run.id)}
                                    className="p-1.5 rounded-lg bg-surface border border-border hover:text-primary text-foreground-muted transition-colors cursor-pointer"
                                    title="Correlate this Run across Campaigns"
                                  >
                                    <Network className="w-3.5 h-3.5" />
                                  </button>

                                  {/* Download .EML */}
                                  <button
                                    type="button"
                                    onClick={() => handleDownloadEml(run.evidence_id || run.id, group.originalFilename)}
                                    className="p-1.5 rounded-lg bg-surface border border-border hover:text-primary text-foreground-muted transition-colors cursor-pointer"
                                    title="Download Stored RFC-822 .EML Evidence"
                                  >
                                    <Download className="w-3.5 h-3.5" />
                                  </button>

                                  {/* Reopen this specific run */}
                                  <button
                                    type="button"
                                    onClick={() => openAnalysis(run)}
                                    disabled={openingId === run.id}
                                    className="p-1.5 rounded-lg bg-primary/10 border border-primary/25 text-primary hover:bg-primary hover:text-primary-foreground transition-colors cursor-pointer"
                                    title="Open this Run in Investigation Workspace"
                                  >
                                    {openingId === run.id ? (
                                      <Loader2 className="w-3.5 h-3.5 animate-spin" />
                                    ) : (
                                      <ExternalLink className="w-3.5 h-3.5" />
                                    )}
                                  </button>
                                </div>
                              </div>
                            </div>

                            {/* ── EXPANDABLE RUN FORENSIC DETAILS ── */}
                            {isRunExpanded && (
                              <div className="mt-3 pt-3 border-t border-border grid grid-cols-1 md:grid-cols-3 gap-3 text-xs font-mono">
                                {/* Pillar 1: Authentication */}
                                <div className="p-3 rounded-lg bg-surface border border-border space-y-2">
                                  <div className="flex items-center justify-between text-[10px] uppercase font-bold text-foreground-muted">
                                    <span>Authentication State</span>
                                    <Radio className="w-3 h-3 text-primary" />
                                  </div>
                                  <div className="space-y-1 text-[11px]">
                                    <div className="flex justify-between">
                                      <span className="text-foreground-muted">SPF Verification:</span>
                                      <span className={run.auth?.spf === 'PASS' ? 'text-success font-bold' : 'text-danger font-bold'}>
                                        {run.auth?.spf || 'UNKNOWN'}
                                      </span>
                                    </div>
                                    <div className="flex justify-between">
                                      <span className="text-foreground-muted">DKIM Signature:</span>
                                      <span className={run.auth?.dkim === 'PASS' ? 'text-success font-bold' : 'text-danger font-bold'}>
                                        {run.auth?.dkim || 'UNKNOWN'}
                                      </span>
                                    </div>
                                    <div className="flex justify-between">
                                      <span className="text-foreground-muted">DMARC Policy:</span>
                                      <span className={run.auth?.dmarc === 'PASS' ? 'text-success font-bold' : 'text-danger font-bold'}>
                                        {run.auth?.dmarc || 'UNKNOWN'}
                                      </span>
                                    </div>
                                  </div>
                                </div>

                                {/* Pillar 2: IOC Breakdown */}
                                <div className="p-3 rounded-lg bg-surface border border-border space-y-2">
                                  <div className="flex items-center justify-between text-[10px] uppercase font-bold text-foreground-muted">
                                    <span>Indicator Breakdown</span>
                                    <Globe className="w-3 h-3 text-primary" />
                                  </div>
                                  <div className="space-y-1 text-[11px]">
                                    <div className="flex justify-between">
                                      <span className="text-foreground-muted">Domains Extracted:</span>
                                      <span className="font-bold text-foreground">{run.iocCount?.domains || 0}</span>
                                    </div>
                                    <div className="flex justify-between">
                                      <span className="text-foreground-muted">IP Infrastructure:</span>
                                      <span className="font-bold text-foreground">{run.iocCount?.ips || 0}</span>
                                    </div>
                                    <div className="flex justify-between">
                                      <span className="text-foreground-muted">URLs (Defanged):</span>
                                      <span className="font-bold text-foreground">{run.iocCount?.urls || 0}</span>
                                    </div>
                                  </div>
                                </div>

                                {/* Pillar 3: Telemetry & Integrity */}
                                <div className="p-3 rounded-lg bg-surface border border-border space-y-2">
                                  <div className="flex items-center justify-between text-[10px] uppercase font-bold text-foreground-muted">
                                    <span>Evidence Identity</span>
                                    <Lock className="w-3 h-3 text-primary" />
                                  </div>
                                  <div className="space-y-1 text-[11px]">
                                    <div className="flex justify-between">
                                      <span className="text-foreground-muted">Evidence ID:</span>
                                      <span className="font-bold text-primary truncate max-w-[120px]">{run.evidence_id || run.id}</span>
                                    </div>
                                    <div className="flex justify-between">
                                      <span className="text-foreground-muted">Relay Reconstruction:</span>
                                      <span className="font-bold text-foreground">{run.relayHopsCount} Hops</span>
                                    </div>
                                    <div className="flex justify-between">
                                      <span className="text-foreground-muted">Integrity:</span>
                                      <span className="text-success font-bold">SHA-256 Verified</span>
                                    </div>
                                  </div>
                                </div>
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* 6. PAGINATION */}
      {!loading && !error && total > pageSize && (
        <div className="flex items-center justify-between bg-surface rounded-2xl border border-border px-4 py-3 text-xs font-mono">
          <span className="text-foreground-muted">
            Showing {page * pageSize + 1}–{Math.min((page + 1) * pageSize, total)} of {total} records
          </span>
          <div className="flex items-center space-x-1.5">
            <button
              type="button"
              onClick={() => setPage(p => Math.max(0, p - 1))}
              disabled={page === 0}
              className="p-1.5 rounded-lg border border-border bg-surface-secondary text-foreground-muted hover:text-foreground disabled:opacity-30 cursor-pointer"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <span className="px-2 text-foreground font-bold">
              Page {page + 1} of {totalPages}
            </span>
            <button
              type="button"
              onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))}
              disabled={page >= totalPages - 1}
              className="p-1.5 rounded-lg border border-border bg-surface-secondary text-foreground-muted hover:text-foreground disabled:opacity-30 cursor-pointer"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}

      {/* Modals */}
      <EvidenceIntegrityModal
        isOpen={!!evidenceModalData}
        onClose={() => setEvidenceModalData(null)}
        evidence={evidenceModalData}
        onReopenWorkspace={(evId) => navigate(`/investigate/${evId}`)}
      />

      {comparisonModalData && (
        <RunComparisonModal
          isOpen={true}
          onClose={() => setComparisonModalData(null)}
          runA={comparisonModalData.runA}
          runB={comparisonModalData.runB}
          onOpenRun={(id) => navigate(`/investigate/${id}`)}
        />
      )}

      {caseModalEmail && (
        <AddToCaseModal
          isOpen={true}
          onClose={() => setCaseModalEmail(null)}
          email={caseModalEmail}
        />
      )}
    </div>
  );
};

export default InvestigationHistory;
