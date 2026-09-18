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
  ExternalLink,
  Compass,
  FileText,
  Cpu,
  Globe2,
  FolderLock,
  FileCheck
} from 'lucide-react';
import { useInvestigation, INVESTIGATION_SECTIONS, type InvestigationSection } from '../../context/InvestigationContext';
import { AddToCaseModal } from '../case/AddToCaseModal';

const SECTION_ICONS: Record<InvestigationSection, React.FC<{ className?: string }>> = {
  overview: Compass,
  email: FileText,
  analysis: Cpu,
  intelligence: Globe2,
  investigation: FolderLock,
  report: FileCheck
};

export const ActiveInvestigationHeader: React.FC = () => {
  const {
    activeEmail,
    activeEmailId,
    activeSection,
    availableAnalyses,
    setActiveEmailId,
    setSection,
    stepGuidance
  } = useInvestigation();

  const navigate = useNavigate();
  const [switcherOpen, setSwitcherOpen] = useState(false);
  const [switcherSearch, setSwitcherSearch] = useState('');
  const [caseModalOpen, setCaseModalOpen] = useState(false);
  const switcherRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (switcherRef.current && !switcherRef.current.contains(event.target as Node)) {
        setSwitcherOpen(false);
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

  return (
    <div className="bg-surface border border-border rounded-xl shadow-xs overflow-hidden transition-all duration-200 mb-6">
      {/* 1. TOP CONTEXT STRIP: WHICH EMAIL IS UNDER INVESTIGATION */}
      <div className="p-4 sm:p-5 border-b border-border bg-gradient-to-b from-surface-secondary/40 to-surface">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          {/* Left: Email Details & Switcher */}
          <div className="flex items-start space-x-3.5 min-w-0 flex-1">
            {/* Threat Gauge / Icon */}
            <div
              className={`w-11 h-11 rounded-lg border flex items-center justify-center flex-shrink-0 transition-colors shadow-xs ${
                severity === 'critical'
                  ? 'bg-danger/10 border-danger/30 text-danger'
                  : severity === 'high'
                  ? 'bg-warning/10 border-warning/30 text-warning'
                  : 'bg-success/10 border-success/30 text-success'
              }`}
            >
              {isMalicious ? <ShieldAlert className="w-5 h-5" /> : <ShieldCheck className="w-5 h-5" />}
            </div>

            {/* Email Metadata & Switcher Trigger */}
            <div className="flex flex-col min-w-0 flex-1">
              <div className="flex items-center space-x-2">
                <span className="text-[10px] font-mono uppercase tracking-wider text-foreground-muted">
                  Active Investigation
                </span>
                <span className="text-foreground-muted">·</span>
                <span className="text-[10px] font-mono text-primary font-semibold">
                  {activeEmail.evidence_id || activeEmail.id || 'E-1042'}
                </span>
                {activeEmail.email_sha256 && (
                  <span className="hidden sm:inline-block text-[9px] font-mono text-foreground-subtle truncate max-w-[120px]">
                    SHA: {activeEmail.email_sha256.slice(0, 10)}…
                  </span>
                )}
              </div>

              {/* Title / Subject with Switcher Dropdown */}
              <div className="relative mt-0.5" ref={switcherRef}>
                <button
                  type="button"
                  onClick={() => setSwitcherOpen(!switcherOpen)}
                  className="group flex items-center space-x-2 text-left cursor-pointer hover:opacity-90 max-w-full"
                  title="Click to switch investigation target"
                >
                  <h1 className="text-sm sm:text-base font-bold text-foreground font-sans truncate group-hover:text-primary transition-colors">
                    {activeEmail.subject || 'Untitled Incident Message'}
                  </h1>
                  <ChevronDown className={`w-4 h-4 text-foreground-muted group-hover:text-primary transition-transform flex-shrink-0 ${switcherOpen ? 'rotate-180' : ''}`} />
                </button>

                {/* Switcher Dropdown Menu */}
                {switcherOpen && (
                  <div className="absolute left-0 top-full mt-2 w-80 sm:w-96 bg-surface-elevated border border-border rounded-xl shadow-2xl z-50 p-2 animate-in fade-in slide-in-from-top-1 duration-150">
                    <div className="p-2 border-b border-border">
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-[11px] font-mono font-semibold uppercase text-foreground">
                          Switch Investigation Target
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

                      {/* Search box inside switcher */}
                      <div className="relative">
                        <Search className="w-3.5 h-3.5 text-foreground-muted absolute left-2.5 top-1/2 -translate-y-1/2 pointer-events-none" />
                        <input
                          type="text"
                          value={switcherSearch}
                          onChange={(e) => setSwitcherSearch(e.target.value)}
                          placeholder="Filter by subject, sender, or ID..."
                          className="w-full pl-8 pr-2.5 py-1 bg-surface-secondary border border-border rounded-md text-xs font-mono text-foreground placeholder:text-foreground-muted focus:outline-none focus:border-primary"
                          autoFocus
                        />
                      </div>
                    </div>

                    {/* Email List */}
                    <div className="max-h-64 overflow-y-auto space-y-1 p-1">
                      {filteredAnalyses.length > 0 ? (
                        filteredAnalyses.map((item) => {
                          const isCurrent = item.id === activeEmailId;
                          const itemScore = item.threat_score?.score ?? 0;
                          return (
                            <button
                              key={item.id}
                              type="button"
                              onClick={() => {
                                if (item.id) {
                                  setActiveEmailId(item.id);
                                }
                                setSwitcherOpen(false);
                              }}
                              className={`w-full text-left p-2 rounded-lg text-xs transition-colors cursor-pointer border ${
                                isCurrent
                                  ? 'bg-primary/10 border-primary/40 text-primary'
                                  : 'hover:bg-surface-secondary border-transparent text-foreground'
                              }`}
                            >
                              <div className="flex items-center justify-between space-x-2">
                                <span className="font-semibold truncate flex-1">
                                  {item.subject || 'Untitled Email'}
                                </span>
                                <span
                                  className={`text-[10px] font-mono font-bold px-1.5 py-0.2 rounded ${
                                    itemScore >= 80
                                      ? 'bg-danger/20 text-danger'
                                      : itemScore >= 50
                                      ? 'bg-warning/20 text-warning'
                                      : 'bg-success/20 text-success'
                                  }`}
                                >
                                  {itemScore}
                                </span>
                              </div>
                              <div className="flex items-center justify-between text-[10px] font-mono text-foreground-muted mt-1">
                                <span className="truncate max-w-[200px]">{item.from || 'Unknown Sender'}</span>
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

                    {/* Ingest action inside switcher */}
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

              {/* Sender & Recipient Details */}
              <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs font-mono text-foreground-muted mt-1">
                <span>
                  <strong className="text-foreground-subtle font-medium">From: </strong>
                  <span className="text-foreground">{activeEmail.from || 'Unknown'}</span>
                </span>
                {activeEmail.to && (
                  <span>
                    <strong className="text-foreground-subtle font-medium">To: </strong>
                    <span className="text-foreground">{activeEmail.to}</span>
                  </span>
                )}
                {activeEmail.date && (
                  <span className="hidden md:inline">
                    <strong className="text-foreground-subtle font-medium">Date: </strong>
                    <span>{new Date(activeEmail.date).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' })}</span>
                  </span>
                )}
              </div>
            </div>
          </div>

          {/* Right: Threat Score Badge & Fast Action Buttons */}
          <div className="flex items-center space-x-2.5 self-start lg:self-center flex-shrink-0">
            {/* Threat Badge */}
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

            {/* Add to Case Button */}
            <button
              type="button"
              onClick={() => setCaseModalOpen(true)}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-surface hover:bg-surface-secondary border border-border text-foreground text-xs font-mono font-medium transition-colors cursor-pointer"
              title="Associate this email with an incident case"
            >
              <FolderPlus className="w-3.5 h-3.5 text-primary" />
              <span className="hidden sm:inline">Add to Case</span>
            </button>

            {/* Quick Export / Report Button */}
            <button
              type="button"
              onClick={() => setSection('report')}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-surface hover:bg-surface-secondary border border-border text-foreground text-xs font-mono font-medium transition-colors cursor-pointer"
              title="Jump to incident report generation"
            >
              <FileDown className="w-3.5 h-3.5 text-primary" />
              <span className="hidden sm:inline">Report</span>
            </button>
          </div>
        </div>
      </div>

      {/* 2. THE 6 PRIMARY INVESTIGATION AREAS STEPPER */}
      <div className="bg-surface px-2 sm:px-4 py-2 flex items-center justify-between border-b border-border overflow-x-auto">
        <div className="flex items-center space-x-1 min-w-max">
          {INVESTIGATION_SECTIONS.map((sec, idx) => {
            const isActive = activeSection === sec.id;
            const Icon = SECTION_ICONS[sec.id];
            return (
              <React.Fragment key={sec.id}>
                <button
                  type="button"
                  onClick={() => setSection(sec.id)}
                  className={`flex items-center space-x-2 px-3 py-1.5 rounded-lg text-xs font-mono transition-all cursor-pointer ${
                    isActive
                      ? 'bg-primary text-primary-foreground font-bold shadow-xs'
                      : 'text-foreground-muted hover:text-foreground hover:bg-surface-secondary border border-transparent'
                  }`}
                  title={`${sec.number}. ${sec.label}: ${sec.description}`}
                >
                  <span
                    className={`text-[10px] font-mono px-1 rounded ${
                      isActive ? 'bg-black/20 text-white' : 'bg-surface-secondary text-foreground-subtle'
                    }`}
                  >
                    {sec.number}
                  </span>
                  <Icon className="w-3.5 h-3.5" />
                  <span>{sec.label}</span>
                </button>
                {idx < INVESTIGATION_SECTIONS.length - 1 && (
                  <span className="text-border text-xs px-0.5 select-none">›</span>
                )}
              </React.Fragment>
            );
          })}
        </div>

        {/* Next Step CTA Banner Button */}
        <div className="hidden xl:flex items-center space-x-2 pl-4 flex-shrink-0">
          <button
            type="button"
            onClick={stepGuidance.execute}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-primary-subtle text-primary border border-primary/30 hover:bg-primary hover:text-primary-foreground text-xs font-mono font-semibold transition-all shadow-xs cursor-pointer"
            title={stepGuidance.guidanceText}
          >
            <span>{stepGuidance.buttonLabel}</span>
          </button>
        </div>
      </div>

      {/* 3. CONTEXTUAL INVESTIGATION STAGE HINT STRIP */}
      <div className="px-4 py-1.5 bg-surface-secondary/50 flex flex-col sm:flex-row sm:items-center justify-between text-[11px] font-mono text-foreground-muted gap-2">
        <div className="flex items-center space-x-2">
          <span className="text-primary font-semibold uppercase tracking-wider">
            {INVESTIGATION_SECTIONS.find(s => s.id === activeSection)?.number} · {INVESTIGATION_SECTIONS.find(s => s.id === activeSection)?.label}:
          </span>
          <span className="text-foreground-subtle">
            {INVESTIGATION_SECTIONS.find(s => s.id === activeSection)?.description}
          </span>
        </div>

        <div className="flex items-center space-x-3">
          <span className="text-foreground-muted">
            Logical Investigation Progression:
          </span>
          <button
            type="button"
            onClick={stepGuidance.execute}
            className="text-primary hover:underline font-semibold flex items-center space-x-1 cursor-pointer"
          >
            <span>{stepGuidance.buttonLabel}</span>
          </button>
        </div>
      </div>

      {/* Add To Case Modal */}
      {caseModalOpen && (
        <AddToCaseModal
          email={activeEmail}
          isOpen={caseModalOpen}
          onClose={() => setCaseModalOpen(false)}
        />
      )}
    </div>
  );
};
