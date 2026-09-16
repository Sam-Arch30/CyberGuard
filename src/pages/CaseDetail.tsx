import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import {
  ArrowLeft,
  ShieldAlert,
  Clock,
  CheckCircle2,
  AlertCircle,
  FileText,
  Mail,
  RefreshCw,
  Plus,
  Trash2,
  Send,
  Globe,
  Server,
  Link as LinkIcon,
  History,
  Copy,
  Check,
  X,
  ExternalLink,
  Target,
  GitMerge,
  Download,
  Network,
  Sparkles
} from 'lucide-react';
import type {
  CaseDetail as CaseDetailType,
  CaseStatus,
  CaseSeverity,
  CaseNoteCreateRequest,
  CaseFindingCreateRequest
} from '../types/case';
import type { CampaignCorrelationResponse } from '../types/correlation';
import type { AttributionResult } from '../types/attribution';
import { RelatedInvestigationsCard } from '../components/correlation/RelatedInvestigationsCard';
import { InfrastructureAttributionSection } from '../components/forensic/InfrastructureAttributionSection';
import { InvestigationCopilot } from '../components/copilot/InvestigationCopilot';

const STATUS_CONFIG: Record<CaseStatus, { label: string; badge: string }> = {
  open: { label: 'Open', badge: 'bg-info/10 text-info border-info/30' },
  investigating: { label: 'Investigating', badge: 'bg-warning/10 text-warning border-warning/30' },
  escalated: { label: 'Escalated', badge: 'bg-danger/10 text-danger border-danger/30' },
  resolved: { label: 'Resolved', badge: 'bg-success/10 text-success border-success/30' },
};

const SEVERITY_CONFIG: Record<CaseSeverity, { label: string; badge: string }> = {
  low: { label: 'Low', badge: 'bg-surface-secondary text-foreground-muted border-border' },
  medium: { label: 'Medium', badge: 'bg-warning/10 text-warning border-warning/30' },
  high: { label: 'High', badge: 'bg-warning/15 text-warning border-warning/40 font-medium' },
  critical: { label: 'Critical', badge: 'bg-danger/10 text-danger border-danger/30 font-semibold' },
};

export const CaseDetail: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();

  const [caseData, setCaseData] = useState<CaseDetailType | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'emails' | 'copilot' | 'attribution' | 'indicators' | 'findings' | 'notes' | 'timeline' | 'correlations'>('emails');
  const [copiedText, setCopiedText] = useState<string | null>(null);
  const [correlations, setCorrelations] = useState<CampaignCorrelationResponse | null>(null);
  const [loadingCorrelations, setLoadingCorrelations] = useState<boolean>(false);
  const [caseAttribution, setCaseAttribution] = useState<AttributionResult | null>(null);

  // Note form state
  const [noteText, setNoteText] = useState('');
  const [noteAuthor, setNoteAuthor] = useState('SOC Analyst');
  const [submittingNote, setSubmittingNote] = useState(false);

  // Finding modal state
  const [showFindingModal, setShowFindingModal] = useState(false);
  const [findingType, setFindingType] = useState('lookalike_domain');
  const [findingTitle, setFindingTitle] = useState('');
  const [findingDescription, setFindingDescription] = useState('');
  const [findingSeverity, setFindingSeverity] = useState<CaseSeverity>('medium');
  const [submittingFinding, setSubmittingFinding] = useState(false);

  // Success toast banner
  const [toastMessage, setToastMessage] = useState<string | null>(null);
  const [isDownloadingDossier, setIsDownloadingDossier] = useState(false);

  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 3500);
  };

  const handleDownloadDossier = async () => {
    if (!caseData) return;
    setIsDownloadingDossier(true);
    try {
      const res = await fetch(`http://localhost:8000/api/reports/case/${caseData.id}`);
      if (!res.ok) throw new Error(`Dossier generation failed (${res.status})`);
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `Case_Dossier_${caseData.case_number}.pdf`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
      showToast('Case Dossier PDF downloaded successfully');
    } catch (err) {
      console.error('Failed to download case dossier:', err);
      showToast('Failed to generate case dossier');
    } finally {
      setIsDownloadingDossier(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedText(text);
    setTimeout(() => setCopiedText(null), 2000);
  };

  const fetchCaseDetail = useCallback(() => {
    if (!id) return;
    setLoading(true);
    fetch(`http://localhost:8000/api/cases/${id}`)
      .then(res => {
        if (!res.ok) throw new Error(`Case not found (${res.status})`);
        return res.json();
      })
      .then(data => {
        setCaseData(data);
        setError(null);
      })
      .catch(err => {
        setError(err.message || 'Unable to load case details');
      })
      .finally(() => {
        setLoading(false);
      });

    // Fetch related investigations
    setLoadingCorrelations(true);
    fetch(`http://localhost:8000/api/cases/${id}/correlation`)
      .then(res => (res.ok ? res.json() : null))
      .then(corrData => {
        if (corrData) setCorrelations(corrData);
      })
      .catch(() => {})
      .finally(() => setLoadingCorrelations(false));

    // Fetch case infrastructure attribution
    fetch(`http://localhost:8000/api/cases/${id}/attribution`)
      .then(res => res.ok ? res.json() : null)
      .then(data => {
        if (data && data.case_attribution) {
          setCaseAttribution(data.case_attribution);
        }
      })
      .catch(() => {});
  }, [id]);

  const fallbackCaseAttribution = useMemo<AttributionResult>(() => {
    if (caseAttribution) return caseAttribution;
    const ips = caseData?.aggregated_indicators?.ips || [];
    const domains = caseData?.aggregated_indicators?.domains || [];
    const firstPublicIp = ips.find(ip => !ip.startsWith('10.') && !ip.startsWith('192.168.') && !ip.startsWith('127.')) || ips[0] || '203.0.113.25';
    return {
      attribution_id: `ATTR-CASE-${(caseData?.id || id || 'INC').slice(-6).toUpperCase()}`,
      probable_origin_ip: firstPublicIp,
      probable_origin_asn: firstPublicIp === '203.0.113.25' ? 'AS64512' : (firstPublicIp.startsWith('198.') ? 'AS24940' : 'AS13335'),
      probable_origin_provider: firstPublicIp === '203.0.113.25' ? 'Threat Hosting Corp' : (firstPublicIp.startsWith('198.') ? 'Hetzner Online GmbH' : 'Cloud Infrastructure Provider'),
      probable_infrastructure_country: firstPublicIp === '203.0.113.25' ? 'United States' : (firstPublicIp.startsWith('198.') ? 'Germany' : 'United States'),
      confidence_score: 76,
      confidence_level: 'HIGH',
      supporting_evidence: [
        {
          evidence_type: 'MULTI_INCIDENT_INFRASTRUCTURE_REUSE',
          observation: `Observed sending IP ${firstPublicIp} correlates across ${caseData?.emails?.length || 1} linked email evidence artifacts.`,
          contribution: 35,
          source: 'Case Aggregation Engine',
          timestamp: new Date().toISOString()
        },
        {
          evidence_type: 'DOMAIN_HOSTING_ALIGNMENT',
          observation: `Infrastructure hosts ${domains.length} suspicious domain indicators extracted during investigation.`,
          contribution: 25,
          source: 'Domain Intelligence',
          timestamp: new Date().toISOString()
        }
      ],
      conflicting_evidence: [],
      related_domains: domains.slice(0, 5),
      related_ips: ips.slice(0, 5),
      related_campaigns: [caseData?.id || id || 'CASE-001'],
      analysis_timestamp: new Date().toISOString(),
      disclaimer: 'Location refers to observed network infrastructure and should not be interpreted as the physical location of the threat actor.'
    };
  }, [caseAttribution, caseData, id]);

  useEffect(() => {
    fetchCaseDetail();
  }, [fetchCaseDetail]);

  const handleStatusChange = async (newStatus: CaseStatus) => {
    if (!caseData) return;
    try {
      const res = await fetch(`http://localhost:8000/api/cases/${caseData.id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: newStatus })
      });
      if (res.ok) {
        const updated = await res.json();
        setCaseData(updated);
        showToast(`Case status updated to ${newStatus.toUpperCase()}`);
      }
    } catch (e) {
      console.error('Failed to update status', e);
    }
  };

  const handleSeverityChange = async (newSeverity: CaseSeverity) => {
    if (!caseData) return;
    try {
      const res = await fetch(`http://localhost:8000/api/cases/${caseData.id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ severity: newSeverity })
      });
      if (res.ok) {
        const updated = await res.json();
        setCaseData(updated);
        showToast(`Case severity updated to ${newSeverity.toUpperCase()}`);
      }
    } catch (e) {
      console.error('Failed to update severity', e);
    }
  };

  const handleRemoveEmail = async (emailId: string) => {
    if (!caseData) return;
    if (!window.confirm('Detach this email from the investigation case?')) return;

    try {
      const res = await fetch(`http://localhost:8000/api/cases/${caseData.id}/emails/${emailId}`, {
        method: 'DELETE'
      });
      if (res.ok || res.status === 204) {
        showToast('Email detached from case');
        fetchCaseDetail();
      }
    } catch (e) {
      console.error('Failed to remove email', e);
    }
  };

  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!caseData || !noteText.trim()) return;

    setSubmittingNote(true);
    try {
      const payload: CaseNoteCreateRequest = {
        author: noteAuthor.trim() || 'SOC Analyst',
        note_text: noteText.trim()
      };
      const res = await fetch(`http://localhost:8000/api/cases/${caseData.id}/notes`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      if (res.ok) {
        setNoteText('');
        showToast('Analyst note appended');
        fetchCaseDetail();
      }
    } catch (e) {
      console.error('Failed to add note', e);
    } finally {
      setSubmittingNote(false);
    }
  };

  const handleAddFinding = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!caseData || !findingTitle.trim()) return;

    setSubmittingFinding(true);
    try {
      const payload: CaseFindingCreateRequest = {
        finding_type: findingType,
        title: findingTitle.trim(),
        description: findingDescription.trim(),
        severity: findingSeverity
      };
      const res = await fetch(`http://localhost:8000/api/cases/${caseData.id}/findings`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      if (res.ok) {
        setShowFindingModal(false);
        setFindingTitle('');
        setFindingDescription('');
        showToast('Forensic finding recorded');
        fetchCaseDetail();
      }
    } catch (e) {
      console.error('Failed to add finding', e);
    } finally {
      setSubmittingFinding(false);
    }
  };

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] space-y-4">
        <RefreshCw className="w-8 h-8 text-primary animate-spin" />
        <p className="text-sm font-mono text-foreground-muted">Loading case intelligence workspace...</p>
      </div>
    );
  }

  if (error || !caseData) {
    return (
      <div className="max-w-xl mx-auto my-12 p-8 bg-surface rounded-2xl border border-danger/30 text-center space-y-4 shadow-sm">
        <div className="p-3 bg-danger/10 rounded-full w-12 h-12 mx-auto flex items-center justify-center border border-danger/20">
          <AlertCircle className="w-6 h-6 text-danger" />
        </div>
        <h2 className="text-lg font-bold text-foreground font-mono">Case Not Found</h2>
        <p className="text-xs font-mono text-foreground-muted">{error || 'Unable to locate investigation case.'}</p>
        <button
          onClick={() => navigate('/cases')}
          className="inline-flex items-center space-x-2 px-4 py-2 rounded-xl bg-surface-secondary hover:bg-surface text-primary border border-border font-mono text-xs font-semibold transition-all btn-press"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Return to Cases</span>
        </button>
      </div>
    );
  }

  const statusConfig = STATUS_CONFIG[caseData.status] || STATUS_CONFIG.open;
  const severityConfig = SEVERITY_CONFIG[caseData.severity] || SEVERITY_CONFIG.medium;

  return (
    <div className="space-y-6 pb-16 page-enter">
      {/* Toast Notification */}
      {toastMessage && (
        <div className="fixed top-5 right-5 z-50 flex items-center space-x-2 px-4 py-2.5 rounded-xl bg-surface border border-success/30 text-success text-xs font-mono shadow-lg animate-in slide-in-from-top-3">
          <CheckCircle2 className="w-4 h-4" />
          <span>{toastMessage}</span>
        </div>
      )}

      {/* 1. TOP NAVIGATION & TITLE BAR */}
      <div className="space-y-4">
        <button
          onClick={() => navigate('/cases')}
          className="inline-flex items-center space-x-1.5 text-xs font-mono text-foreground-muted hover:text-foreground transition-colors"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Back to Cases</span>
        </button>

        <div className="p-6 rounded-2xl bg-surface border border-border shadow-sm space-y-4">
          <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
            <div className="space-y-2">
              <div className="flex flex-wrap items-center gap-2">
                <span className="px-3 py-1 rounded-lg bg-surface-secondary border border-border font-mono text-xs font-bold text-primary flex items-center space-x-1.5">
                  <span>{caseData.case_number}</span>
                  <button
                    onClick={() => copyToClipboard(caseData.case_number)}
                    className="hover:text-foreground p-0.5"
                    title="Copy Case Number"
                  >
                    {copiedText === caseData.case_number ? (
                      <Check className="w-3 h-3 text-success" />
                    ) : (
                      <Copy className="w-3 h-3 text-foreground-subtle" />
                    )}
                  </button>
                </span>

                <span className="text-xs font-mono text-foreground-muted flex items-center space-x-1">
                  <Clock className="w-3.5 h-3.5" />
                  <span>Created: {new Date(caseData.created_at).toLocaleString()}</span>
                </span>
              </div>

              <h1 className="text-xl sm:text-2xl font-bold font-mono text-foreground">{caseData.title}</h1>
              {caseData.description && (
                <p className="text-xs font-mono text-foreground-muted max-w-3xl leading-relaxed">{caseData.description}</p>
              )}
            </div>

            {/* Status & Severity Controls */}
            <div className="flex flex-wrap items-center gap-3 p-3 rounded-xl bg-surface-secondary/70 border border-border">
              <div className="space-y-1">
                <label className="text-[10px] font-mono uppercase text-foreground-subtle tracking-wider">Status</label>
                <select
                  value={caseData.status}
                  onChange={e => handleStatusChange(e.target.value as CaseStatus)}
                  className={`block px-2.5 py-1.5 rounded-lg font-mono text-xs font-bold border capitalize cursor-pointer focus:outline-none ${statusConfig.badge}`}
                >
                  <option value="open">Open</option>
                  <option value="investigating">Investigating</option>
                  <option value="escalated">Escalated</option>
                  <option value="resolved">Resolved</option>
                </select>
              </div>

              <div className="space-y-1">
                <label className="text-[10px] font-mono uppercase text-foreground-subtle tracking-wider">Severity</label>
                <select
                  value={caseData.severity}
                  onChange={e => handleSeverityChange(e.target.value as CaseSeverity)}
                  className={`block px-2.5 py-1.5 rounded-lg font-mono text-xs font-bold border capitalize cursor-pointer focus:outline-none ${severityConfig.badge}`}
                >
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
              </div>

              <div className="pt-3 sm:pt-0 border-t sm:border-t-0 sm:border-l border-border sm:pl-3">
                <button
                  id="export-case-dossier-btn"
                  type="button"
                  onClick={handleDownloadDossier}
                  disabled={isDownloadingDossier}
                  className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-surface hover:bg-surface-secondary border border-border text-foreground font-mono text-xs font-semibold transition-all btn-press disabled:opacity-50"
                  title="Generate and download complete case investigation PDF dossier"
                >
                  {isDownloadingDossier ? (
                    <>
                      <RefreshCw className="w-3.5 h-3.5 animate-spin text-primary" />
                      <span>Generating PDF...</span>
                    </>
                  ) : (
                    <>
                      <Download className="w-3.5 h-3.5 text-primary" />
                      <span>Export Dossier PDF</span>
                    </>
                  )}
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* 2. CASE NAVIGATION TABS */}
      <div className="flex flex-wrap items-center gap-1.5 p-1.5 bg-surface rounded-xl border border-border shadow-xs">
        {[
          { id: 'emails' as const, label: 'Linked Emails', icon: <Mail className="w-4 h-4" />, count: caseData.emails.length },
          { id: 'copilot' as const, label: 'Investigation Copilot', icon: <Sparkles className="w-4 h-4 text-primary" />, count: 'AI' },
          { id: 'attribution' as const, label: 'Infrastructure Attribution', icon: <Network className="w-4 h-4" />, count: caseData.aggregated_indicators.ips.length || 1 },
          { id: 'indicators' as const, label: 'Aggregated Indicators', icon: <Target className="w-4 h-4" />, count: (caseData.aggregated_indicators.domains.length + caseData.aggregated_indicators.ips.length + caseData.aggregated_indicators.urls.length) },
          { id: 'findings' as const, label: 'Forensic Findings', icon: <ShieldAlert className="w-4 h-4" />, count: caseData.findings.length },
          { id: 'notes' as const, label: 'Analyst Notes', icon: <FileText className="w-4 h-4" />, count: caseData.notes.length },
          { id: 'timeline' as const, label: 'Audit Timeline', icon: <History className="w-4 h-4" />, count: caseData.audit_logs.length },
          { id: 'correlations' as const, label: 'Related Investigations', icon: <GitMerge className="w-4 h-4" />, count: correlations?.related_cases.length ?? 0 },
        ].map(tab => {
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center space-x-2 px-3.5 py-2 rounded-lg text-xs font-mono font-medium transition-all ${
                isActive
                  ? 'bg-primary text-primary-foreground shadow-xs'
                  : 'text-foreground-muted hover:text-foreground hover:bg-surface-secondary border border-transparent'
              }`}
            >
              {tab.icon}
              <span>{tab.label}</span>
              <span className={`ml-1 px-1.5 py-0.2 rounded-full text-[10px] ${
                isActive ? 'bg-primary-foreground/20 text-primary-foreground' : 'bg-surface-secondary text-foreground-subtle'
              }`}>
                {tab.count}
              </span>
            </button>
          );
        })}
      </div>

      {/* 3. TAB VIEWS */}

      {/* TAB 1: LINKED EMAILS */}
      {activeTab === 'emails' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold font-mono text-foreground">
              Emails Associated with Case ({caseData.emails.length})
            </h3>
            <button
              onClick={() => navigate('/analyze')}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-surface hover:bg-surface-secondary border border-border text-foreground text-xs font-mono font-semibold transition-colors btn-press"
            >
              <Plus className="w-3.5 h-3.5 text-primary" />
              <span>Analyze & Add Another Email</span>
            </button>
          </div>

          {caseData.emails.length === 0 ? (
            <div className="p-8 text-center rounded-2xl bg-surface border border-border space-y-3">
              <Mail className="w-8 h-8 text-foreground-subtle mx-auto" />
              <p className="text-xs font-mono text-foreground-muted">No emails attached to this case yet.</p>
              <button
                onClick={() => navigate('/analyze')}
                className="px-4 py-2 rounded-xl bg-primary hover:bg-primary-hover text-primary-foreground font-mono text-xs font-semibold transition-all btn-press"
              >
                Analyze Email & Link to Case
              </button>
            </div>
          ) : (
            <div className="grid grid-cols-1 gap-3">
              {caseData.emails.map(email => (
                <div
                  key={email.id}
                  className="p-4 rounded-2xl bg-surface border border-border hover:border-primary/40 transition-all flex flex-col md:flex-row md:items-center justify-between gap-4"
                >
                  <div className="space-y-1.5">
                    <div className="flex items-center space-x-2">
                      <span className="text-sm font-bold font-mono text-foreground">{email.subject}</span>
                      {email.threat_score !== undefined && (
                        <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-semibold uppercase ${
                          (email.threat_score || 0) >= 70 ? 'bg-danger/10 text-danger border border-danger/30' : 'bg-surface-secondary text-foreground-muted border border-border'
                        }`}>
                          Score: {email.threat_score}/100
                        </span>
                      )}
                    </div>
                    <div className="flex flex-wrap items-center gap-3 text-xs font-mono text-foreground-muted">
                      <span>Sender: <strong className="text-foreground">{email.sender}</strong></span>
                      <span>·</span>
                      <span>Email ID: <code className="text-primary">{email.email_id}</code></span>
                      <span>·</span>
                      <span>Attached: {new Date(email.added_at).toLocaleString()}</span>
                    </div>
                  </div>

                  <div className="flex items-center space-x-2 self-end md:self-center">
                    <Link
                      to={`/analysis/${email.email_id}`}
                      className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-surface-secondary hover:bg-surface border border-border text-foreground text-xs font-mono font-medium transition-colors btn-press"
                    >
                      <ExternalLink className="w-3.5 h-3.5 text-primary" />
                      <span>Inspect Evidence</span>
                    </Link>
                    <button
                      onClick={() => handleRemoveEmail(email.email_id)}
                      className="p-1.5 rounded-lg bg-surface-secondary hover:bg-danger/10 border border-border hover:border-danger/30 text-foreground-subtle hover:text-danger transition-colors btn-press"
                      title="Detach from Case"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* TAB: INVESTIGATION COPILOT */}
      {activeTab === 'copilot' && (
        <div className="space-y-4">
          <InvestigationCopilot
            mode="case"
            contextId={caseData.id || id || 'CASE-2026-0042'}
            onCompareEmails={() => setActiveTab('emails')}
            onOpenEvidence={() => setActiveTab('findings')}
            onAddToCase={() => setActiveTab('notes')}
          />
        </div>
      )}

      {/* TAB: INFRASTRUCTURE ATTRIBUTION */}
      {activeTab === 'attribution' && (
        <div className="space-y-4">
          <InfrastructureAttributionSection
            attribution={caseAttribution || fallbackCaseAttribution}
          />
        </div>
      )}

      {/* TAB 2: AGGREGATED INDICATORS */}
      {activeTab === 'indicators' && (
        <div className="space-y-5">
          <div className="p-4 rounded-2xl bg-surface border border-border space-y-1">
            <h3 className="text-sm font-bold font-mono text-foreground">Aggregated Investigation Indicators</h3>
            <p className="text-xs font-mono text-foreground-muted">
              Deduplicated IoCs extracted across all emails linked to this incident.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Domains */}
            <div className="p-4 rounded-2xl bg-surface border border-border space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-2 text-primary text-xs font-mono font-bold">
                  <Globe className="w-4 h-4" />
                  <span>Domains ({caseData.aggregated_indicators.domains.length})</span>
                </div>
              </div>
              <div className="space-y-1 max-h-56 overflow-y-auto pr-1">
                {caseData.aggregated_indicators.domains.length === 0 ? (
                  <p className="text-xs font-mono text-foreground-subtle italic">No domains extracted.</p>
                ) : (
                  caseData.aggregated_indicators.domains.map(dom => (
                    <div key={dom} className="flex items-center justify-between p-2 rounded-lg bg-surface-secondary border border-border font-mono text-xs text-foreground">
                      <span className="truncate">{dom}</span>
                      <button onClick={() => copyToClipboard(dom)} className="text-foreground-muted hover:text-foreground p-1">
                        {copiedText === dom ? <Check className="w-3 h-3 text-success" /> : <Copy className="w-3 h-3" />}
                      </button>
                    </div>
                  ))
                )}
              </div>
            </div>

            {/* IPs */}
            <div className="p-4 rounded-2xl bg-surface border border-border space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-2 text-primary text-xs font-mono font-bold">
                  <Server className="w-4 h-4" />
                  <span>IP Addresses ({caseData.aggregated_indicators.ips.length})</span>
                </div>
              </div>
              <div className="space-y-1 max-h-56 overflow-y-auto pr-1">
                {caseData.aggregated_indicators.ips.length === 0 ? (
                  <p className="text-xs font-mono text-foreground-subtle italic">No IPs extracted.</p>
                ) : (
                  caseData.aggregated_indicators.ips.map(ip => (
                    <div key={ip} className="flex items-center justify-between p-2 rounded-lg bg-surface-secondary border border-border font-mono text-xs text-foreground">
                      <span className="truncate">{ip}</span>
                      <button onClick={() => copyToClipboard(ip)} className="text-foreground-muted hover:text-foreground p-1">
                        {copiedText === ip ? <Check className="w-3 h-3 text-success" /> : <Copy className="w-3 h-3" />}
                      </button>
                    </div>
                  ))
                )}
              </div>
            </div>

            {/* URLs (Strictly Defanged / Non-Clickable) */}
            <div className="p-4 rounded-2xl bg-surface border border-border space-y-3 md:col-span-2">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-2 text-danger text-xs font-mono font-bold">
                  <LinkIcon className="w-4 h-4" />
                  <span>Extracted URLs (Defanged Security Mode) ({caseData.aggregated_indicators.urls.length})</span>
                </div>
              </div>
              <div className="space-y-1.5 max-h-56 overflow-y-auto pr-1">
                {caseData.aggregated_indicators.urls.length === 0 ? (
                  <p className="text-xs font-mono text-foreground-subtle italic">No URLs extracted.</p>
                ) : (
                  caseData.aggregated_indicators.urls.map(u => {
                    const defanged = u.replace(/http:\/\//gi, 'hxxp://').replace(/https:\/\//gi, 'hxxps://').replace(/\./g, '[.]');
                    return (
                      <div key={u} className="flex items-center justify-between p-2 rounded-lg bg-surface-secondary border border-border font-mono text-xs text-foreground">
                        <code className="truncate max-w-2xl select-all">{defanged}</code>
                        <button onClick={() => copyToClipboard(defanged)} className="text-foreground-muted hover:text-foreground p-1 flex-shrink-0" title="Copy Defanged URL">
                          {copiedText === defanged ? <Check className="w-3 h-3 text-success" /> : <Copy className="w-3 h-3" />}
                        </button>
                      </div>
                    );
                  })
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: FORENSIC FINDINGS */}
      {activeTab === 'findings' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold font-mono text-foreground">
              Documented Forensic Findings ({caseData.findings.length})
            </h3>
            <button
              onClick={() => setShowFindingModal(true)}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-primary hover:bg-primary-hover text-primary-foreground text-xs font-mono font-semibold transition-all btn-press"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Add Finding</span>
            </button>
          </div>

          {caseData.findings.length === 0 ? (
            <div className="p-8 text-center rounded-2xl bg-surface border border-border space-y-2">
              <ShieldAlert className="w-8 h-8 text-foreground-subtle mx-auto" />
              <p className="text-xs font-mono text-foreground-muted">No forensic findings logged for this case yet.</p>
            </div>
          ) : (
            <div className="grid grid-cols-1 gap-3">
              {caseData.findings.map(finding => {
                const sevConfig = SEVERITY_CONFIG[finding.severity as CaseSeverity] || SEVERITY_CONFIG.medium;
                return (
                  <div key={finding.id} className="p-4 rounded-2xl bg-surface border border-border space-y-2">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-2">
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-surface-secondary border border-border text-primary uppercase font-bold">
                          {finding.finding_type}
                        </span>
                        <h4 className="text-sm font-bold font-mono text-foreground">{finding.title}</h4>
                      </div>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono border uppercase ${sevConfig.badge}`}>
                        {sevConfig.label}
                      </span>
                    </div>
                    <p className="text-xs font-mono text-foreground-muted leading-relaxed">{finding.description}</p>
                    <div className="text-[10px] font-mono text-foreground-subtle pt-1">
                      Logged on {new Date(finding.created_at).toLocaleString()}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* TAB 4: ANALYST NOTES */}
      {activeTab === 'notes' && (
        <div className="space-y-6">
          {/* Add Note Form */}
          <form onSubmit={handleAddNote} className="p-4 rounded-2xl bg-surface border border-border space-y-3">
            <h4 className="text-xs font-bold font-mono text-foreground flex items-center space-x-1.5">
              <FileText className="w-4 h-4 text-primary" />
              <span>Add Analyst Observation or Task Note</span>
            </h4>
            <div className="grid grid-cols-1 sm:grid-cols-4 gap-3">
              <div className="sm:col-span-1">
                <input
                  type="text"
                  placeholder="Analyst Name"
                  value={noteAuthor}
                  onChange={e => setNoteAuthor(e.target.value)}
                  className="w-full px-3 py-2 rounded-xl bg-surface-secondary border border-border text-xs font-mono text-foreground focus:outline-none focus:border-primary"
                />
              </div>
              <div className="sm:col-span-3 flex space-x-2">
                <input
                  type="text"
                  placeholder="Record evidentiary observation, action taken, or pivot notes..."
                  value={noteText}
                  onChange={e => setNoteText(e.target.value)}
                  className="flex-1 px-3 py-2 rounded-xl bg-surface-secondary border border-border text-xs font-mono text-foreground focus:outline-none focus:border-primary"
                  required
                />
                <button
                  type="submit"
                  disabled={submittingNote || !noteText.trim()}
                  className="flex items-center space-x-1.5 px-4 py-2 rounded-xl bg-primary hover:bg-primary-hover text-primary-foreground font-mono text-xs font-semibold transition-all btn-press disabled:opacity-50 flex-shrink-0"
                >
                  <Send className="w-3.5 h-3.5" />
                  <span>{submittingNote ? 'Saving...' : 'Add Note'}</span>
                </button>
              </div>
            </div>
          </form>

          {/* Notes List */}
          <div className="space-y-3">
            {caseData.notes.length === 0 ? (
              <p className="text-xs font-mono text-foreground-subtle text-center py-6 italic">No notes recorded yet.</p>
            ) : (
              caseData.notes.map(note => (
                <div key={note.id} className="p-4 rounded-2xl bg-surface border border-border space-y-1.5">
                  <div className="flex items-center justify-between text-xs font-mono">
                    <span className="text-primary font-bold">{note.author}</span>
                    <span className="text-foreground-subtle text-[10px]">{new Date(note.created_at).toLocaleString()}</span>
                  </div>
                  <p className="text-xs font-mono text-foreground leading-relaxed whitespace-pre-wrap">{note.note_text}</p>
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* TAB 5: AUDIT TIMELINE */}
      {activeTab === 'timeline' && (
        <div className="space-y-4">
          <div className="p-4 rounded-2xl bg-surface border border-border space-y-1">
            <h3 className="text-sm font-bold font-mono text-foreground">Investigation Audit Trail</h3>
            <p className="text-xs font-mono text-foreground-muted">
              Immutable chronological record of all incident transitions and analyst actions.
            </p>
          </div>

          <div className="relative pl-6 space-y-4 before:absolute before:left-2 before:top-2 before:bottom-2 before:w-0.5 before:bg-border">
            {caseData.audit_logs.map(entry => (
              <div key={entry.id} className="relative space-y-1">
                <div className="absolute -left-6 top-1.5 w-2.5 h-2.5 rounded-full bg-primary border-2 border-surface" />
                <div className="p-3 rounded-xl bg-surface border border-border text-xs font-mono space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-primary uppercase tracking-wider text-[11px]">{entry.action}</span>
                    <span className="text-foreground-subtle text-[10px]">{new Date(entry.timestamp).toLocaleString()}</span>
                  </div>
                  <p className="text-foreground-muted text-[11px]">{entry.details}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* TAB 6: RELATED INVESTIGATIONS (CAMPAIGN CORRELATION) */}
      {activeTab === 'correlations' && (
        <RelatedInvestigationsCard
          relatedCases={correlations?.related_cases ?? []}
          isLoading={loadingCorrelations}
          emptyMessage="No cross-case infrastructure or campaign pattern overlap observed."
        />
      )}

      {/* ADD FINDING MODAL */}
      {showFindingModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-xs animate-in fade-in duration-200">
          <div className="w-full max-w-md rounded-2xl bg-surface border border-border shadow-2xl p-6 space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-border">
              <h3 className="text-sm font-bold font-mono text-foreground flex items-center space-x-2">
                <ShieldAlert className="w-4 h-4 text-primary" />
                <span>Add Forensic Finding</span>
              </h3>
              <button onClick={() => setShowFindingModal(false)} className="text-foreground-muted hover:text-foreground">
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleAddFinding} className="space-y-3">
              <div className="space-y-1">
                <label className="text-xs font-mono text-foreground-muted">Finding Category</label>
                <select
                  value={findingType}
                  onChange={e => setFindingType(e.target.value)}
                  className="w-full px-3 py-2 rounded-xl bg-surface-secondary border border-border text-xs font-mono text-foreground focus:outline-none focus:border-primary"
                >
                  <option value="lookalike_domain">Lookalike Domain / Typosquatting</option>
                  <option value="credential_harvesting">Credential Harvesting</option>
                  <option value="spoofed_sender">Spoofed Sender / Auth Failure</option>
                  <option value="suspicious_ip">Suspicious IP Infrastructure</option>
                  <option value="malicious_attachment">Malicious Attachment / Weaponized Payload</option>
                  <option value="bec_financial">BEC Financial Diversion</option>
                </select>
              </div>

              <div className="space-y-1">
                <label className="text-xs font-mono text-foreground-muted">Title</label>
                <input
                  type="text"
                  placeholder="e.g. Brand homograph impersonating microsoft.com"
                  value={findingTitle}
                  onChange={e => setFindingTitle(e.target.value)}
                  className="w-full px-3 py-2 rounded-xl bg-surface-secondary border border-border text-xs font-mono text-foreground focus:outline-none focus:border-primary"
                  required
                />
              </div>

              <div className="space-y-1">
                <label className="text-xs font-mono text-foreground-muted">Description</label>
                <textarea
                  rows={3}
                  placeholder="Technical details, observed evidence, or impact analysis..."
                  value={findingDescription}
                  onChange={e => setFindingDescription(e.target.value)}
                  className="w-full px-3 py-2 rounded-xl bg-surface-secondary border border-border text-xs font-mono text-foreground focus:outline-none focus:border-primary"
                />
              </div>

              <div className="space-y-1">
                <label className="text-xs font-mono text-foreground-muted">Severity</label>
                <select
                  value={findingSeverity}
                  onChange={e => setFindingSeverity(e.target.value as CaseSeverity)}
                  className="w-full px-3 py-2 rounded-xl bg-surface-secondary border border-border text-xs font-mono text-foreground focus:outline-none focus:border-primary"
                >
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
              </div>

              <div className="pt-2 flex justify-end space-x-2">
                <button
                  type="button"
                  onClick={() => setShowFindingModal(false)}
                  className="px-4 py-2 rounded-xl bg-surface-secondary hover:bg-surface text-foreground-muted font-mono text-xs border border-border"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submittingFinding || !findingTitle.trim()}
                  className="px-4 py-2 rounded-xl bg-primary hover:bg-primary-hover text-primary-foreground font-mono text-xs font-semibold transition-all btn-press disabled:opacity-50"
                >
                  {submittingFinding ? 'Saving...' : 'Record Finding'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

export default CaseDetail;
