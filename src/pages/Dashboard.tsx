import React, { useState, useEffect, useCallback, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Upload,
  FileText,
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  ArrowRight,
  Clock,
  RefreshCw,
  FileCode,
  Sparkles,
  Search,
  FolderLock,
  Layers,
  X,
  Download,
  Network
} from 'lucide-react';
import type { DashboardSummary } from '../types/dashboard';
import type { EmailAnalysis } from '../types/forensic';
import { getAllAvailableAnalyses, saveAnalysisResult } from '../utils/forensicStore';
import { decodeRfc2047 } from '../utils/indicatorHelper';
import {
  SCENARIO_1_LEGITIMATE,
  SCENARIO_2_PHISHING,
  SCENARIO_3_PRIMARY_EMAIL
} from '../data/sihScenariosData';

interface RecentRowItem {
  id: string;
  evidenceId?: string;
  originalFilename?: string;
  subject: string;
  sender: string;
  timestamp?: string;
  threatScore?: number;
  severity?: string;
  status: string;
}

const formatTimeAgo = (isoString?: string): string => {
  if (!isoString) return 'Recent';
  try {
    const d = new Date(isoString);
    if (isNaN(d.getTime())) return isoString;
    const now = new Date();
    const diffMs = now.getTime() - d.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    const diffHours = Math.floor(diffMins / 60);
    if (diffHours < 24) return `${diffHours}h ago`;
    const diffDays = Math.floor(diffHours / 24);
    if (diffDays < 7) return `${diffDays}d ago`;
    return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
  } catch {
    return isoString;
  }
};

export const Dashboard: React.FC = () => {
  const navigate = useNavigate();
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Ingestion state
  const [isAnalyzing, setIsAnalyzing] = useState<boolean>(false);
  const [dragOver, setDragOver] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [showPasteArea, setShowPasteArea] = useState<boolean>(false);
  const [pastedText, setPastedText] = useState<string>('');

  // Dashboard summary & recent rows
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [recentRows, setRecentRows] = useState<RecentRowItem[]>([]);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(true);

  // Load stored analyses and optional backend summary
  const loadRecentData = useCallback(async () => {
    setLoading(true);

    // 1. Local stored analyses (strictly real ingested emails)
    const localAnalyses = getAllAvailableAnalyses(false);
    const rowsMap = new Map<string, RecentRowItem>();

    localAnalyses
      .filter((a) => !a.id?.startsWith('scenario-'))
      .forEach((a) => {
        const rowId = a.id || a.evidence_id || 'unknown';
        rowsMap.set(rowId, {
          id: rowId,
          subject: a.subject || a.original_filename || 'Untitled Investigation',
          sender: a.from || 'Unknown sender',
          timestamp: a.upload_timestamp || a.date,
          threatScore: a.threat_score?.score,
          severity: a.threat_score?.severity || (a.threat_score?.score !== undefined ? (a.threat_score.score >= 80 ? 'critical' : a.threat_score.score >= 50 ? 'high' : 'low') : undefined),
          status: 'Analyzed'
        });
      });

    // 2. Fetch backend summary if available
    try {
      let res: Response | null = null;
      try {
        res = await fetch('/api/dashboard/summary?days=30&recent_limit=10');
      } catch {
        res = await fetch('http://127.0.0.1:8000/api/dashboard/summary?days=30&recent_limit=10');
      }

      if (res && res.ok) {
        const liveSummary: DashboardSummary = await res.json();
        setSummary(liveSummary);

        // Merge any recent backend emails not already in local store (filter out synthetic scenarios)
        if (liveSummary.recent_emails) {
          liveSummary.recent_emails
            .filter((be) => !be.id.startsWith('scenario-'))
            .forEach((be) => {
              if (!rowsMap.has(be.id)) {
                rowsMap.set(be.id, {
                  id: be.id,
                  evidenceId: be.evidence_id || be.id,
                  originalFilename: be.original_filename || `${be.evidence_id || be.id}.eml`,
                  subject: be.subject || 'Incident Target EML',
                  sender: be.sender || 'Unknown',
                  timestamp: be.timestamp,
                  threatScore: be.threat_score,
                  severity: be.severity,
                  status: 'Analyzed'
                });
              }
            });
        }
      }
    } catch {
      // Gracefully silent fallback to local analyses
    }

    setRecentRows(Array.from(rowsMap.values()));
    setLoading(false);
  }, []);

  useEffect(() => {
    loadRecentData();
  }, [loadRecentData]);

  // Ingestion pipeline: processes .eml file or raw blob
  const processEmailIngestion = async (fileOrBlob: Blob, filename: string, rawText?: string) => {
    setIsAnalyzing(true);
    setErrorMessage(null);
    const analysisId = `analysis-${Date.now()}`;

    try {
      const formData = new FormData();
      formData.append('file', fileOrBlob, filename);

      let res: Response | null = null;
      try {
        res = await fetch('/api/emails/analyze', { method: 'POST', body: formData });
      } catch {
        res = await fetch('http://127.0.0.1:8000/api/emails/analyze', { method: 'POST', body: formData });
      }

      if (res && res.ok) {
        const data = await res.json();
        const textFallback = rawText || '';
        const parsedAnalysis: EmailAnalysis = {
          id: analysisId,
          evidence_id: data.evidence_id || (data.email_sha256 ? `EVD-${data.email_sha256.slice(0, 10).toUpperCase()}` : `EVD-${analysisId.slice(-8).toUpperCase()}`),
          email_sha256: data.email_sha256,
          original_filename: data.original_filename || filename,
          upload_timestamp: data.upload_timestamp || new Date().toISOString(),
          size: data.size || fileOrBlob.size,
          uploader: data.uploader || 'SOC Analyst',
          authentication: data.authentication,
          relay_analysis: data.relay_analysis,
          indicators: data.indicators,
          subject: decodeRfc2047(data.subject || data.headers?.subject || filename),
          from: decodeRfc2047(data.from || data.from_header || data.headers?.from || ''),
          to: decodeRfc2047(Array.isArray(data.to) ? data.to.join(', ') : (data.to || data.headers?.to || '')),
          cc: decodeRfc2047(Array.isArray(data.cc) ? data.cc.join(', ') : (data.cc || data.headers?.cc || '')),
          date: decodeRfc2047(data.date || data.headers?.date || ''),
          reply_to: decodeRfc2047(data.reply_to || data.headers?.reply_to || ''),
          return_path: decodeRfc2047(data.return_path || data.headers?.return_path || ''),
          message_id: decodeRfc2047(data.message_id || data.headers?.message_id || ''),
          received: data.received || data.headers?.received || [],
          authentication_results: data.authentication_results || data.headers?.authentication_results || '',
          plain_text_body: data.plain_text_body || data.body?.plain_text || textFallback,
          html_body: data.html_body || data.body?.html || '',
          raw_email: data.raw_email || textFallback,
          urls: data.urls || [],
          ips: data.ips || [],
          domains: data.domains || [],
          emails: data.emails || [],
          attachments: data.attachments || [],
          ip_intelligence: data.ip_intelligence || {},
          domain_intelligence: data.domain_intelligence || {},
          lookalike_domains: data.lookalike_domains || [],
          url_analysis: data.url_analysis || [],
          threat_score: data.threat_score,
          ml_phishing_probability: data.ml_phishing_probability,
          ml_assessment: data.ml_assessment,
          ai_analyst: data.ai_analyst,
          attribution: data.attribution,
          investigation_graph: data.investigation_graph
        };

        saveAnalysisResult(analysisId, parsedAnalysis);
        navigate(`/investigate/${analysisId}/overview`);
        return;
      } else {
        const errText = res ? await res.text() : 'Analysis service unreachable.';
        setErrorMessage(`Forensic analysis failed: ${errText || 'Unprocessable email format'}`);
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Network error';
      setErrorMessage(`Error connecting to analysis engine: ${msg}`);
    } finally {
      setIsAnalyzing(false);
    }
  };

  // Drag and drop handlers
  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragOver(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragOver(false);
  };

  const handleDrop = async (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragOver(false);

    const files = Array.from(e.dataTransfer.files);
    if (files.length === 0) return;
    const file = files[0];
    let textContent = '';
    try {
      textContent = await file.text();
    } catch {
      // Binary blob fallback
    }
    await processEmailIngestion(file, file.name, textContent);
  };

  const handleFileInputChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    let textContent = '';
    try {
      textContent = await file.text();
    } catch {
      // Binary blob fallback
    }
    await processEmailIngestion(file, file.name, textContent);
  };

  const handlePasteSubmit = async () => {
    const text = pastedText.trim();
    if (!text) {
      setErrorMessage('Please paste raw RFC-822 email content or headers.');
      return;
    }
    const blob = new Blob([text], { type: 'message/rfc822' });
    await processEmailIngestion(blob, 'pasted_message.eml', text);
  };

  // Pre-loaded sample launch
  const handleLoadSample = (scenarioId: string) => {
    if (scenarioId === 'scenario-2-phish') {
      saveAnalysisResult('scenario-2-phish', { ...SCENARIO_2_PHISHING, is_demo: true });
      navigate('/investigate/scenario-2-phish/overview');
    } else if (scenarioId === 'scenario-3-campaign') {
      saveAnalysisResult('scenario-3-campaign', { ...SCENARIO_3_PRIMARY_EMAIL, is_demo: true });
      navigate('/investigate/scenario-3-campaign/overview');
    } else if (scenarioId === 'scenario-1-legit') {
      saveAnalysisResult('scenario-1-legit', { ...SCENARIO_1_LEGITIMATE, is_demo: true });
      navigate('/investigate/scenario-1-legit/overview');
    }
  };

  // Compute operational summary metrics without inventing data
  const totalAnalyzed = summary?.metrics?.emails_analyzed ?? recentRows.length;
  const highRiskCount = summary?.metrics?.critical_emails ?? recentRows.filter((r) => (r.threatScore ?? 0) >= 70 || r.severity === 'critical' || r.severity === 'high').length;
  const activeCasesCount = summary?.metrics?.open_cases ?? 0;

  // Filter recent investigations by query
  const filteredRows = searchQuery.trim()
    ? recentRows.filter((r) =>
        r.subject.toLowerCase().includes(searchQuery.toLowerCase()) ||
        r.sender.toLowerCase().includes(searchQuery.toLowerCase()) ||
        r.id.toLowerCase().includes(searchQuery.toLowerCase())
      )
    : recentRows;

  return (
    <div className="max-w-5xl lg:max-w-6xl w-full mx-auto py-6 px-4 sm:px-6 space-y-6 animate-fadeIn">
      {/* =========================================================================
          TOP: Minimal MailTraceAI Branding & Global Context
          ========================================================================= */}
      <header className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-border/60">
        <div className="space-y-1">
          <div className="flex items-center space-x-2.5">
            <div className="w-8 h-8 rounded-lg bg-primary/10 border border-primary/20 flex items-center justify-center text-primary">
              <Shield className="w-4 h-4" />
            </div>
            <div>
              <h1 className="text-xl font-bold tracking-tight text-foreground font-sans">
                MailTraceAI
              </h1>
              <p className="text-xs text-foreground-muted font-mono">
                Email Forensics & Incident Response
              </p>
            </div>
          </div>
        </div>

        {/* Minimal Navigation & Operational Status */}
        <div className="flex items-center space-x-3 text-xs font-mono">
          <button
            onClick={() => navigate('/history')}
            className="px-3 py-1.5 rounded-lg border border-border hover:bg-surface-secondary text-foreground-muted hover:text-foreground transition-colors flex items-center space-x-1.5 cursor-pointer"
          >
            <Layers className="w-3.5 h-3.5 text-primary" />
            <span>Triage Queue</span>
          </button>
          <button
            onClick={() => navigate('/cases')}
            className="px-3 py-1.5 rounded-lg border border-border hover:bg-surface-secondary text-foreground-muted hover:text-foreground transition-colors flex items-center space-x-1.5 cursor-pointer"
          >
            <FolderLock className="w-3.5 h-3.5 text-foreground-muted" />
            <span>Cases</span>
          </button>
        </div>
      </header>

      {/* =========================================================================
          OPTIONAL COMPACT SUMMARY: Single-Line Operational Context
          ========================================================================= */}
      {(totalAnalyzed > 0 || activeCasesCount > 0) && (
        <div className="flex flex-wrap items-center justify-between py-2.5 px-4 rounded-xl bg-surface-secondary/40 border border-border/50 text-xs font-mono text-foreground-muted">
          <div className="flex items-center space-x-4 divide-x divide-border/60">
            <div className="flex items-center space-x-1.5">
              <span className="w-2 h-2 rounded-full bg-primary" />
              <span className="font-semibold text-foreground">{totalAnalyzed}</span>
              <span>analyzed emails</span>
            </div>
            {highRiskCount > 0 && (
              <div className="pl-4 flex items-center space-x-1.5">
                <span className="w-2 h-2 rounded-full bg-danger" />
                <span className="font-semibold text-danger">{highRiskCount}</span>
                <span>high-risk threats</span>
              </div>
            )}
            {activeCasesCount > 0 && (
              <div className="pl-4 flex items-center space-x-1.5">
                <span className="w-2 h-2 rounded-full bg-warning" />
                <span className="font-semibold text-foreground">{activeCasesCount}</span>
                <span>active cases</span>
              </div>
            )}
          </div>

          <button
            onClick={loadRecentData}
            title="Refresh telemetry"
            className="text-[11px] text-foreground-muted hover:text-foreground flex items-center space-x-1 cursor-pointer transition-colors"
          >
            <RefreshCw className="w-3 h-3 text-foreground-muted" />
            <span>Synced</span>
          </button>
        </div>
      )}

      {/* =========================================================================
          PRIMARY ACTION: Ingestion / New Investigation Area
          ========================================================================= */}
      <section className="space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="text-xs font-mono font-semibold uppercase tracking-wider text-foreground-muted">
            New Investigation
          </h2>
          <button
            onClick={() => setShowPasteArea(!showPasteArea)}
            className="text-xs font-mono text-primary hover:underline flex items-center space-x-1 cursor-pointer"
          >
            <FileCode className="w-3.5 h-3.5" />
            <span>{showPasteArea ? 'Hide RFC-822 Text Input' : 'Paste Raw RFC-822'}</span>
          </button>
        </div>

        {/* Drag & Drop Target Area */}
        <div
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          onClick={() => !isAnalyzing && fileInputRef.current?.click()}
          className={`relative border-2 border-dashed rounded-2xl p-8 text-center transition-all cursor-pointer ${
            dragOver
              ? 'border-primary bg-primary/5 shadow-md ring-2 ring-primary/20'
              : 'border-border hover:border-primary/50 bg-surface hover:bg-surface-secondary/40'
          } ${isAnalyzing ? 'opacity-70 pointer-events-none' : ''}`}
        >
          <input
            type="file"
            ref={fileInputRef}
            onChange={handleFileInputChange}
            accept=".eml,.msg,message/rfc822,text/plain"
            className="hidden"
          />

          <div className="flex flex-col items-center justify-center space-y-3">
            <div className={`w-12 h-12 rounded-xl flex items-center justify-center transition-colors ${
              dragOver ? 'bg-primary text-primary-foreground' : 'bg-surface-secondary text-primary border border-border'
            }`}>
              {isAnalyzing ? (
                <RefreshCw className="w-5 h-5 animate-spin" />
              ) : (
                <Upload className="w-5 h-5" />
              )}
            </div>

            <div className="space-y-1">
              <p className="text-sm font-semibold text-foreground">
                {isAnalyzing
                  ? 'Analyzing MIME headers, IOCs, and threat signals...'
                  : dragOver
                  ? 'Drop .eml file to begin analysis'
                  : 'Drag and drop an .eml file here'}
              </p>
              <p className="text-xs font-mono text-foreground-muted">
                {isAnalyzing
                  ? 'Reconstructing transmission relay path and scoring risk'
                  : 'or click to browse your computer (.eml, RFC-822)'}
              </p>
            </div>

            {!isAnalyzing && (
              <button
                type="button"
                className="mt-2 px-4 py-1.5 rounded-lg bg-primary hover:bg-primary-hover text-primary-foreground text-xs font-semibold font-mono tracking-wide shadow-xs transition-colors"
              >
                Browse .EML File
              </button>
            )}
          </div>
        </div>

        {/* Optional Collapsible Paste Area */}
        {showPasteArea && (
          <div className="p-4 rounded-xl bg-surface border border-border space-y-3 animate-fadeIn">
            <div className="flex items-center justify-between text-xs font-mono text-foreground-muted">
              <span>Paste Raw Email Headers and Content</span>
              <button
                onClick={() => setShowPasteArea(false)}
                className="text-foreground-muted hover:text-foreground cursor-pointer"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </div>
            <textarea
              value={pastedText}
              onChange={(e) => setPastedText(e.target.value)}
              placeholder="Received: from mail.example.com ...&#10;From: sender@example.com&#10;To: victim@company.com&#10;Subject: Urgent..."
              rows={5}
              className="w-full text-xs font-mono p-3 rounded-lg bg-surface-secondary border border-border text-foreground placeholder:text-foreground-muted focus:outline-hidden focus:ring-1 focus:ring-primary resize-y"
            />
            <div className="flex justify-end">
              <button
                onClick={handlePasteSubmit}
                disabled={isAnalyzing || !pastedText.trim()}
                className="px-4 py-1.5 rounded-lg bg-primary hover:bg-primary-hover disabled:opacity-50 text-primary-foreground text-xs font-semibold font-mono flex items-center space-x-1.5 cursor-pointer transition-colors"
              >
                <FileText className="w-3.5 h-3.5" />
                <span>Begin Analysis</span>
              </button>
            </div>
          </div>
        )}

        {/* Error Feedback */}
        {errorMessage && (
          <div className="p-3 rounded-xl bg-danger-surface border border-danger-border text-danger text-xs font-mono flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              <span>{errorMessage}</span>
            </div>
            <button
              onClick={() => setErrorMessage(null)}
              className="text-danger hover:underline cursor-pointer ml-2"
            >
              Dismiss
            </button>
          </div>
        )}

        {/* Quick Sample Launchers */}
        <div className="flex flex-wrap items-center gap-2 pt-1">
          <span className="text-[11px] font-mono text-foreground-muted">
            Quick Scenarios:
          </span>
          <button
            onClick={() => handleLoadSample('scenario-2-phish')}
            className="px-2.5 py-1 rounded-md bg-surface-secondary hover:bg-surface-secondary/80 border border-border text-[11px] font-mono text-foreground hover:text-danger flex items-center space-x-1.5 transition-colors cursor-pointer"
          >
            <ShieldAlert className="w-3 h-3 text-danger" />
            <span>CEO Wire Redirection (Critical)</span>
          </button>
          <button
            onClick={() => handleLoadSample('scenario-3-campaign')}
            className="px-2.5 py-1 rounded-md bg-surface-secondary hover:bg-surface-secondary/80 border border-border text-[11px] font-mono text-foreground hover:text-warning flex items-center space-x-1.5 transition-colors cursor-pointer"
          >
            <Sparkles className="w-3 h-3 text-warning" />
            <span>Credential Phish (High)</span>
          </button>
          <button
            onClick={() => handleLoadSample('scenario-1-legit')}
            className="px-2.5 py-1 rounded-md bg-surface-secondary hover:bg-surface-secondary/80 border border-border text-[11px] font-mono text-foreground hover:text-success flex items-center space-x-1.5 transition-colors cursor-pointer"
          >
            <ShieldCheck className="w-3 h-3 text-success" />
            <span>Verified Memo (Benign)</span>
          </button>
        </div>
      </section>

      {/* =========================================================================
          SECONDARY AREA: Recent Investigations (Compact Rows)
          ========================================================================= */}
      <section className="space-y-3 pt-2">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div className="flex items-center space-x-2">
            <h2 className="text-xs font-mono font-semibold uppercase tracking-wider text-foreground-muted">
              Recent Investigations
            </h2>
            <span className="text-[11px] font-mono px-2 py-0.5 rounded-full bg-surface-secondary text-foreground-muted border border-border/60">
              {filteredRows.length}
            </span>
          </div>

          {/* Search Filter */}
          {recentRows.length > 3 && (
            <div className="relative w-full sm:w-56">
              <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-foreground-muted" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Filter investigations..."
                className="w-full text-xs font-mono pl-8 pr-3 py-1 rounded-lg bg-surface border border-border text-foreground placeholder:text-foreground-muted focus:outline-hidden focus:ring-1 focus:ring-primary"
              />
            </div>
          )}
        </div>

        {/* Compact Table Container */}
        <div className="rounded-xl border border-border bg-surface overflow-hidden shadow-xs">
          {loading ? (
            <div className="p-8 text-center text-xs font-mono text-foreground-muted">
              <RefreshCw className="w-4 h-4 animate-spin mx-auto mb-2 text-primary" />
              Loading investigations...
            </div>
          ) : filteredRows.length === 0 ? (
            <div className="p-10 text-center space-y-2">
              <FileText className="w-6 h-6 text-foreground-muted mx-auto" />
              <p className="text-xs font-semibold text-foreground">No investigations found</p>
              <p className="text-[11px] font-mono text-foreground-muted">
                {searchQuery ? 'No records match your filter criteria.' : 'Drop an .eml file above to initiate your first forensic analysis.'}
              </p>
            </div>
          ) : (
            <div className="divide-y divide-border/60">
              {filteredRows.slice(0, 10).map((row) => {
                const score = row.threatScore;
                const isCritical = (score !== undefined && score >= 80) || row.severity === 'critical';
                const isHigh = !isCritical && ((score !== undefined && score >= 50) || row.severity === 'high');
                const isBenign = score !== undefined && score < 20;

                return (
                  <div
                    key={row.id}
                    onClick={() => navigate(`/investigate/${row.id}/overview`)}
                    className="flex flex-col sm:flex-row sm:items-center justify-between p-3.5 hover:bg-surface-secondary/60 transition-colors cursor-pointer group gap-3"
                  >
                    {/* Left: Email Subject & Sender */}
                    <div className="min-w-0 flex-1 space-y-0.5">
                      <div className="flex items-center space-x-2">
                        <FileText className="w-3.5 h-3.5 text-primary shrink-0" />
                        <span className="text-xs font-semibold text-foreground truncate group-hover:text-primary transition-colors">
                          {row.subject}
                        </span>
                      </div>
                      <div className="text-[11px] font-mono text-foreground-muted truncate pl-5">
                        {row.sender}
                      </div>
                    </div>

                    {/* Right: Timestamp, Score Badge, and Action */}
                    <div className="flex items-center space-x-3 shrink-0 self-end sm:self-auto text-xs font-mono">
                      <div className="flex items-center space-x-1 text-[11px] text-foreground-muted">
                        <Clock className="w-3 h-3 text-foreground-muted" />
                        <span>{formatTimeAgo(row.timestamp)}</span>
                      </div>

                      {/* Threat Score / Risk Classification Badge */}
                      {score !== undefined ? (
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                            isCritical
                              ? 'bg-danger-surface text-danger border border-danger-border'
                              : isHigh
                              ? 'bg-warning-surface text-warning border border-warning-border'
                              : isBenign
                              ? 'bg-success-surface text-success border border-success-border'
                              : 'bg-surface-secondary text-foreground-muted border border-border'
                          }`}
                        >
                          {score}/100 {isCritical ? 'Critical' : isHigh ? 'High' : isBenign ? 'Clean' : 'Elevated'}
                        </span>
                      ) : (
                        <span className="px-2 py-0.5 rounded text-[10px] bg-surface-secondary text-foreground-muted border border-border">
                          {row.severity ? row.severity.toUpperCase() : 'Analyzed'}
                        </span>
                      )}

                      {/* Quick Actions: Correlate & Download .EML */}
                      <div className="flex items-center space-x-1" onClick={(e) => e.stopPropagation()}>
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            navigate(`/investigate/${encodeURIComponent(row.evidenceId || row.id)}/investigation?subtab=campaigns`);
                          }}
                          className="p-1 rounded bg-surface-secondary hover:bg-surface border border-border text-foreground-muted hover:text-primary transition-colors cursor-pointer"
                          title="Correlate this .EML across Campaigns & Cases"
                        >
                          <Network className="w-3 h-3 text-primary" />
                        </button>

                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            window.open(`http://localhost:8000/api/emails/${encodeURIComponent(row.evidenceId || row.id)}/download`, '_blank');
                          }}
                          className="p-1 rounded bg-surface-secondary hover:bg-surface border border-border text-foreground-muted hover:text-primary transition-colors cursor-pointer"
                          title="Download Stored RFC-822 .EML File"
                        >
                          <Download className="w-3 h-3 text-primary" />
                        </button>
                      </div>

                      {/* Open Action Arrow */}
                      <span className="text-foreground-muted group-hover:text-primary group-hover:translate-x-0.5 transition-all">
                        <ArrowRight className="w-3.5 h-3.5" />
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Footer Link to Full Triage Queue */}
        {recentRows.length > 5 && (
          <div className="flex justify-end pt-1">
            <button
              onClick={() => navigate('/history')}
              className="text-xs font-mono text-foreground-muted hover:text-primary flex items-center space-x-1 transition-colors cursor-pointer"
            >
              <span>View complete queue in Ingested .EML History</span>
              <ArrowRight className="w-3 h-3" />
            </button>
          </div>
        )}
      </section>
    </div>
  );
};
