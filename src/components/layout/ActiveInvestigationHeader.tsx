import React, { useState, useRef, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ShieldAlert,
  ShieldCheck,
  ChevronDown,
  Search,
  Plus,
  FolderPlus,
  FileDown,
  RefreshCw,
  MoreVertical,
  Copy,
  FileText,
  Printer,
  ExternalLink,
  Compass,
  Cpu,
  Globe2,
  FolderLock,
  FileCheck,
  CheckCircle2,
  Sparkles
} from 'lucide-react';
import { useInvestigation, INVESTIGATION_SECTIONS, type InvestigationSection } from '../../context/InvestigationContext';
import { AddToCaseModal } from '../case/AddToCaseModal';
import { CopyButton } from '../forensic/CopyButton';
import { truncateMiddle } from '../../utils/forensicFormatters';

const SECTION_ICONS: Record<InvestigationSection, React.FC<{ className?: string }>> = {
  overview: Compass,
  email: FileText,
  analysis: Cpu,
  intelligence: Globe2,
  investigation: FolderLock,
  report: FileCheck
};

const formatTimestamp = (dateStr?: string) => {
  if (!dateStr) return 'Recent';
  try {
    const d = new Date(dateStr);
    if (isNaN(d.getTime())) return dateStr;
    const formatted = d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
    const time = d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', hour12: false });
    return `${formatted}, ${time}`;
  } catch {
    return dateStr;
  }
};

export const ActiveInvestigationHeader: React.FC = () => {
  const {
    activeEmail,
    activeEmailId,
    activeSection,
    availableAnalyses,
    setActiveEmailId,
    setSection,
    stepGuidance,
    reanalyzeActiveEmail,
    openCopilotDrawer
  } = useInvestigation();

  const navigate = useNavigate();

  // Dropdown states
  const [switcherOpen, setSwitcherOpen] = useState(false);
  const [switcherSearch, setSwitcherSearch] = useState('');
  const [exportMenuOpen, setExportMenuOpen] = useState(false);
  const [overflowMenuOpen, setOverflowMenuOpen] = useState(false);
  const [caseModalOpen, setCaseModalOpen] = useState(false);
  const [reanalyzing, setReanalyzing] = useState(false);
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  const switcherRef = useRef<HTMLDivElement>(null);
  const exportRef = useRef<HTMLDivElement>(null);
  const overflowRef = useRef<HTMLDivElement>(null);

  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 3000);
  };

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (switcherRef.current && !switcherRef.current.contains(event.target as Node)) {
        setSwitcherOpen(false);
      }
      if (exportRef.current && !exportRef.current.contains(event.target as Node)) {
        setExportMenuOpen(false);
      }
      if (overflowRef.current && !overflowRef.current.contains(event.target as Node)) {
        setOverflowMenuOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  if (!activeEmail) return null;

  const score = activeEmail.threat_score?.score ?? 0;
  const severity = activeEmail.threat_score?.severity || (score >= 80 ? 'critical' : score >= 50 ? 'high' : 'low');
  const isMalicious = score >= 50;

  const filteredAnalyses = availableAnalyses.filter(item => {
    if (!switcherSearch.trim()) return true;
    const query = switcherSearch.toLowerCase();
    return (
      (item.subject && item.subject.toLowerCase().includes(query)) ||
      (item.from && item.from.toLowerCase().includes(query)) ||
      (item.id && item.id.toLowerCase().includes(query)) ||
      (item.original_filename && item.original_filename.toLowerCase().includes(query))
    );
  });

  const handleExportJSON = () => {
    setExportMenuOpen(false);
    const jsonStr = JSON.stringify(activeEmail, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `forensic_dossier_${activeEmail.evidence_id || activeEmail.id || 'email'}.json`;
    a.click();
    URL.revokeObjectURL(url);
    showToast('Exported structured forensic JSON');
  };

  const handleDownloadEML = () => {
    setExportMenuOpen(false);
    setOverflowMenuOpen(false);
    const raw = activeEmail.raw_email || activeEmail.plain_text_body || '';
    if (!raw) {
      showToast('No raw .eml content available for this email');
      return;
    }
    const blob = new Blob([raw], { type: 'message/rfc822' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = activeEmail.original_filename || `${activeEmail.id || 'email'}.eml`;
    a.click();
    URL.revokeObjectURL(url);
    showToast('Downloaded original .EML file');
  };

  const handleCopySha = () => {
    setOverflowMenuOpen(false);
    if (activeEmail.email_sha256) {
      navigator.clipboard.writeText(activeEmail.email_sha256);
      showToast('SHA-256 digest copied to clipboard');
    }
  };

  const handleTriggerReanalyze = async () => {
    setOverflowMenuOpen(false);
    setReanalyzing(true);
    try {
      await reanalyzeActiveEmail();
      showToast('Forensic analysis refreshed with latest telemetry');
    } catch {
      showToast('Failed to refresh analysis');
    } finally {
      setReanalyzing(false);
    }
  };

  return (
    <header className="bg-surface border border-border rounded-card shadow-xs overflow-visible transition-colors mb-6">
      {/* =========================================================================
          1. TOP CONTEXTUAL HEADER: Subject, Sender, Timestamp, Score, Status, Actions
          ========================================================================= */}
      <div className="p-4 border-b border-border bg-surface">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          {/* Left Side: Context Details & Switcher */}
          <div className="flex items-start space-x-3.5 min-w-0 flex-1">
            {/* Risk Indicator Icon */}
            <div
              className={`w-10 h-10 rounded-lg border flex items-center justify-center shrink-0 transition-colors shadow-xs ${
                severity === 'critical'
                  ? 'bg-danger-surface border-danger-border text-danger'
                  : severity === 'high'
                  ? 'bg-warning-surface border-warning-border text-warning'
                  : 'bg-success-surface border-success-border text-success'
              }`}
            >
              {isMalicious ? <ShieldAlert className="w-5 h-5" /> : <ShieldCheck className="w-5 h-5" />}
            </div>

            {/* Content & Metadata */}
            <div className="flex flex-col min-w-0 flex-1">
              {/* Target Switcher Chip & Status */}
              <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
                <div className="relative" ref={switcherRef}>
                  <button
                    type="button"
                    onClick={() => setSwitcherOpen(!switcherOpen)}
                    className="flex items-center space-x-1.5 px-2 py-0.5 rounded-md bg-surface-secondary hover:bg-surface-secondary/80 border border-border text-foreground text-[11px] font-semibold transition-colors cursor-pointer"
                    title="Switch active investigation target"
                  >
                    <span className="text-primary font-bold">Target:</span>
                    <span className="truncate max-w-[130px] sm:max-w-[180px]">{activeEmail.evidence_id || activeEmail.id}</span>
                    <ChevronDown className={`w-3 h-3 text-foreground-muted transition-transform ${switcherOpen ? 'rotate-180' : ''}`} />
                  </button>

                  {/* Switcher Dropdown */}
                  {switcherOpen && (
                    <div className="absolute left-0 top-full mt-2 w-80 sm:w-96 bg-surface-elevated border border-border rounded-card shadow-popover z-50 p-2 animate-fadeIn">
                      <div className="p-2 border-b border-border">
                        <div className="flex items-center justify-between mb-2">
                          <span className="text-[11px] font-mono font-semibold uppercase text-foreground">
                            Switch Active Target
                          </span>
                          <button
                            type="button"
                            onClick={() => {
                              setSwitcherOpen(false);
                              navigate('/history');
                            }}
                            className="text-[10px] font-mono text-primary hover:underline flex items-center space-x-1"
                          >
                            <span>Triage Queue</span>
                            <ExternalLink className="w-2.5 h-2.5" />
                          </button>
                        </div>

                        <div className="relative">
                          <Search className="w-3.5 h-3.5 text-foreground-muted absolute left-2.5 top-1/2 -translate-y-1/2 pointer-events-none" />
                          <input
                            type="text"
                            value={switcherSearch}
                            onChange={(e) => setSwitcherSearch(e.target.value)}
                            placeholder="Filter investigations..."
                            className="w-full pl-8 pr-2.5 py-1 bg-surface-secondary border border-border rounded-md text-xs font-mono text-foreground placeholder:text-foreground-muted focus:outline-hidden focus:ring-1 focus:ring-primary"
                            autoFocus
                          />
                        </div>
                      </div>

                      <div className="max-h-60 overflow-y-auto space-y-1 p-1">
                        {filteredAnalyses.length > 0 ? (
                          filteredAnalyses.map((item) => {
                            const isCurrent = item.id === activeEmailId;
                            const itemScore = item.threat_score?.score ?? 0;
                            return (
                              <button
                                key={item.id}
                                type="button"
                                onClick={() => {
                                  if (item.id) setActiveEmailId(item.id);
                                  setSwitcherOpen(false);
                                }}
                                className={`w-full text-left p-2 rounded-lg text-xs transition-colors cursor-pointer border ${
                                  isCurrent
                                    ? 'bg-primary/10 border-primary/40 text-primary font-semibold'
                                    : 'hover:bg-surface-secondary border-transparent text-foreground'
                                }`}
                              >
                                <div className="flex items-center justify-between space-x-2">
                                  <span className="truncate flex-1">{item.subject || 'Untitled Email'}</span>
                                  <span className={`text-[10px] font-mono font-bold px-1.5 py-0.2 rounded ${
                                    itemScore >= 80 ? 'bg-danger-surface text-danger' : itemScore >= 50 ? 'bg-warning-surface text-warning' : 'bg-success-surface text-success'
                                  }`}>
                                    {itemScore}
                                  </span>
                                </div>
                                <div className="flex items-center justify-between text-[10px] font-mono text-foreground-muted mt-0.5">
                                  <span className="truncate max-w-[200px]">{item.from || 'Unknown'}</span>
                                  <span>{item.id}</span>
                                </div>
                              </button>
                            );
                          })
                        ) : (
                          <div className="p-4 text-center text-xs font-mono text-foreground-muted">
                            No matching emails found
                          </div>
                        )}
                      </div>

                      <div className="p-1.5 border-t border-border mt-1">
                        <button
                          type="button"
                          onClick={() => {
                            setSwitcherOpen(false);
                            navigate('/analyze');
                          }}
                          className="w-full flex items-center justify-center space-x-2 py-1.5 rounded-lg bg-surface hover:bg-surface-secondary text-primary border border-border text-xs font-mono font-semibold transition-colors cursor-pointer"
                        >
                          <Plus className="w-3.5 h-3.5" />
                          <span>Ingest New .EML File</span>
                        </button>
                      </div>
                    </div>
                  )}
                </div>

                {/* Analysis Status Badge */}
                <span className="flex items-center space-x-1 text-[11px] text-foreground-muted">
                  <span className={`w-1.5 h-1.5 rounded-full ${reanalyzing ? 'bg-warning animate-spin' : 'bg-success'}`} />
                  <span className="text-foreground-subtle font-medium">
                    {reanalyzing ? 'Re-analyzing...' : 'Analyzed & Grounded'}
                  </span>
                </span>
              </div>

              {/* Subject Title */}
              <div className="flex items-center space-x-2 mt-1 min-w-0 max-w-full">
                <h1
                  title={activeEmail.subject || 'Untitled Incident Message'}
                  className="text-sm sm:text-base font-bold text-foreground font-sans truncate"
                >
                  {activeEmail.subject || 'Untitled Incident Message'}
                </h1>
                {activeEmail.subject && (
                  <CopyButton text={activeEmail.subject} iconOnly />
                )}
              </div>

              {/* Sender & Timestamp Subline */}
              <div className="flex flex-wrap items-center gap-x-2 sm:gap-x-3 gap-y-0.5 text-xs font-mono text-foreground-muted mt-0.5">
                <div className="flex items-center space-x-1.5 min-w-0">
                  <strong className="text-foreground-subtle font-medium shrink-0">From: </strong>
                  <span
                    title={activeEmail.from || 'Unknown'}
                    className="text-foreground font-semibold truncate max-w-[200px] sm:max-w-xs md:max-w-md"
                  >
                    {activeEmail.from || 'Unknown'}
                  </span>
                  {activeEmail.from && <CopyButton text={activeEmail.from} iconOnly />}
                </div>
                <span>·</span>
                <span className="shrink-0">
                  <strong className="text-foreground-subtle font-medium">Received: </strong>
                  <span>{formatTimestamp(activeEmail.date || activeEmail.upload_timestamp)}</span>
                </span>
                {activeEmail.email_sha256 && (
                  <>
                    <span className="hidden xl:inline">·</span>
                    <div className="hidden xl:flex items-center space-x-1">
                      <strong className="text-foreground-subtle font-medium">SHA-256: </strong>
                      <span
                        title={activeEmail.email_sha256}
                        className="font-mono text-[11px] text-foreground"
                      >
                        {truncateMiddle(activeEmail.email_sha256, 8, 8)}
                      </span>
                      <CopyButton text={activeEmail.email_sha256} iconOnly />
                    </div>
                  </>
                )}
              </div>
            </div>
          </div>

          {/* Right Side: Threat Score Badge & Restrained Actions */}
          <div className="flex items-center space-x-2.5 self-start lg:self-center shrink-0">
            {/* Threat Score & Risk Classification Badge */}
            <div
              className={`px-3 py-1.5 rounded-lg border text-xs font-mono flex items-center space-x-2 ${
                severity === 'critical'
                  ? 'bg-danger-surface text-danger border-danger-border'
                  : severity === 'high'
                  ? 'bg-warning-surface text-warning border-warning-border'
                  : 'bg-success-surface text-success border-success-border'
              }`}
            >
              <div className="flex flex-col text-right">
                <span className="text-[9px] uppercase tracking-wider font-semibold opacity-80">
                  Threat Score
                </span>
                <span className="text-sm font-bold leading-tight">
                  {score}/100 · {severity.toUpperCase()}
                </span>
              </div>
            </div>

            {/* Primary Action 0: Ask AI Copilot */}
            <button
              type="button"
              onClick={() => openCopilotDrawer()}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-primary/10 hover:bg-primary/20 text-primary border border-primary/30 text-xs font-mono font-semibold transition-colors cursor-pointer shadow-xs"
              title="Open contextual investigation AI drawer"
            >
              <Sparkles className="w-3.5 h-3.5" />
              <span>Ask AI</span>
            </button>

            {/* Primary Action 1: Add to Case */}
            <button
              type="button"
              onClick={() => setCaseModalOpen(true)}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-primary hover:bg-primary-hover text-primary-foreground text-xs font-mono font-semibold transition-colors cursor-pointer shadow-xs"
              title="Associate this email with an active incident case"
            >
              <FolderPlus className="w-3.5 h-3.5" />
              <span>Add to Case</span>
            </button>

            {/* Primary Action 2: Export Dropdown */}
            <div className="relative" ref={exportRef}>
              <button
                type="button"
                onClick={() => setExportMenuOpen(!exportMenuOpen)}
                className="flex items-center space-x-1.5 px-2.5 py-1.5 rounded-lg bg-surface hover:bg-surface-secondary border border-border text-foreground text-xs font-mono font-medium transition-colors cursor-pointer"
                title="Export forensic investigation data"
              >
                <FileDown className="w-3.5 h-3.5 text-primary" />
                <span>Export</span>
                <ChevronDown className="w-3 h-3 text-foreground-muted" />
              </button>

              {exportMenuOpen && (
                <div className="absolute right-0 top-full mt-1.5 w-52 bg-surface-elevated border border-border rounded-xl shadow-xl z-50 p-1 animate-fadeIn text-xs font-mono">
                  <button
                    type="button"
                    onClick={handleExportJSON}
                    className="w-full text-left px-3 py-2 rounded-lg hover:bg-surface-secondary text-foreground flex items-center space-x-2 transition-colors cursor-pointer"
                  >
                    <FileText className="w-3.5 h-3.5 text-primary" />
                    <span>Forensic JSON Dossier</span>
                  </button>
                  <button
                    type="button"
                    onClick={handleDownloadEML}
                    className="w-full text-left px-3 py-2 rounded-lg hover:bg-surface-secondary text-foreground flex items-center space-x-2 transition-colors cursor-pointer"
                  >
                    <FileDown className="w-3.5 h-3.5 text-foreground-muted" />
                    <span>Original .EML File</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setExportMenuOpen(false);
                      setSection('report');
                    }}
                    className="w-full text-left px-3 py-2 rounded-lg hover:bg-surface-secondary text-foreground flex items-center space-x-2 transition-colors cursor-pointer"
                  >
                    <Printer className="w-3.5 h-3.5 text-foreground-muted" />
                    <span>Generate PDF Report</span>
                  </button>
                </div>
              )}
            </div>

            {/* Compact Overflow Menu (...) */}
            <div className="relative" ref={overflowRef}>
              <button
                type="button"
                onClick={() => setOverflowMenuOpen(!overflowMenuOpen)}
                className="p-1.5 rounded-lg bg-surface hover:bg-surface-secondary border border-border text-foreground-muted hover:text-foreground transition-colors cursor-pointer"
                title="More investigation actions"
              >
                <MoreVertical className="w-4 h-4" />
              </button>

              {overflowMenuOpen && (
                <div className="absolute right-0 top-full mt-1.5 w-56 bg-surface-elevated border border-border rounded-xl shadow-xl z-50 p-1 animate-fadeIn text-xs font-mono">
                  <button
                    type="button"
                    onClick={() => {
                      setOverflowMenuOpen(false);
                      openCopilotDrawer();
                    }}
                    className="w-full text-left px-3 py-2 rounded-lg hover:bg-surface-secondary text-foreground flex items-center space-x-2 transition-colors cursor-pointer"
                  >
                    <Sparkles className="w-3.5 h-3.5 text-primary" />
                    <span>Ask AI Assistant</span>
                  </button>
                  <button
                    type="button"
                    onClick={handleTriggerReanalyze}
                    disabled={reanalyzing}
                    className="w-full text-left px-3 py-2 rounded-lg hover:bg-surface-secondary text-foreground flex items-center space-x-2 transition-colors cursor-pointer"
                  >
                    <RefreshCw className={`w-3.5 h-3.5 text-primary ${reanalyzing ? 'animate-spin' : ''}`} />
                    <span>Re-analyze Evidence</span>
                  </button>
                  <button
                    type="button"
                    onClick={handleCopySha}
                    className="w-full text-left px-3 py-2 rounded-lg hover:bg-surface-secondary text-foreground flex items-center space-x-2 transition-colors cursor-pointer"
                  >
                    <Copy className="w-3.5 h-3.5 text-foreground-muted" />
                    <span>Copy Evidence SHA-256</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setOverflowMenuOpen(false);
                      navigate('/history');
                    }}
                    className="w-full text-left px-3 py-2 rounded-lg hover:bg-surface-secondary text-foreground flex items-center space-x-2 transition-colors cursor-pointer"
                  >
                    <Search className="w-3.5 h-3.5 text-foreground-muted" />
                    <span>Browse Triage Queue</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setOverflowMenuOpen(false);
                      navigate('/analyze');
                    }}
                    className="w-full text-left px-3 py-2 rounded-lg hover:bg-surface-secondary text-primary flex items-center space-x-2 transition-colors cursor-pointer border-t border-border mt-1 pt-1.5"
                  >
                    <Plus className="w-3.5 h-3.5" />
                    <span>Ingest New Email</span>
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* =========================================================================
          2. COMPACT INVESTIGATION NAVIGATION: Overview, Email, Analysis, Intel, Investigate, Report
          ========================================================================= */}
      <nav className="bg-surface px-2 sm:px-4 py-1 flex items-center justify-between border-b border-border overflow-x-auto scrollbar-none">
        <div className="flex items-center space-x-1 min-w-max">
          {INVESTIGATION_SECTIONS.map((sec) => {
            const isActive = activeSection === sec.id;
            const Icon = SECTION_ICONS[sec.id];
            return (
              <button
                key={sec.id}
                type="button"
                onClick={() => setSection(sec.id)}
                className={`flex items-center space-x-1.5 px-2.5 py-1.5 rounded-control text-xs font-mono transition-all cursor-pointer ${
                  isActive
                    ? 'bg-primary/12 text-primary font-bold border border-primary/30 shadow-xs'
                    : 'text-foreground-muted hover:text-foreground hover:bg-surface-secondary border border-transparent'
                }`}
                title={sec.description}
              >
                <Icon className="w-3.5 h-3.5 shrink-0" />
                <span className="whitespace-nowrap">{sec.label}</span>
              </button>
            );
          })}
        </div>

        {/* Logical Next Investigation Step CTA */}
        <div className="hidden lg:flex items-center space-x-2 pl-4 shrink-0">
          <button
            type="button"
            onClick={stepGuidance.execute}
            className="flex items-center space-x-1.5 px-2.5 py-1 rounded-control bg-surface-secondary hover:bg-primary/10 border border-border hover:border-primary/40 text-primary text-xs font-mono font-medium transition-colors cursor-pointer"
            title={stepGuidance.guidanceText}
          >
            <span>{stepGuidance.buttonLabel}</span>
          </button>
        </div>
      </nav>

      {/* Toast Notification */}
      {toastMessage && (
        <div className="px-4 py-2 bg-primary text-primary-foreground text-xs font-mono font-semibold flex items-center space-x-2 animate-fadeIn">
          <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />
          <span>{toastMessage}</span>
        </div>
      )}

      {/* Add To Case Modal */}
      {caseModalOpen && (
        <AddToCaseModal
          email={activeEmail}
          isOpen={caseModalOpen}
          onClose={() => setCaseModalOpen(false)}
        />
      )}
    </header>
  );
};
