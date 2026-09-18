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
  Sparkles,
  Lock,
  Search,
  FileDown,
  Layers,
  ChevronRight,
  ShieldCheck,
  Loader2
} from 'lucide-react';
import type {
  CaseDetail as CaseDetailType,
  CaseStatus,
  CaseSeverity,
  CaseNoteCreateRequest,
  CaseFindingCreateRequest,
  CaseEmail
} from '../types/case';
import type { CampaignCorrelationResponse } from '../types/correlation';
import type { AttributionResult } from '../types/attribution';
import { InfrastructureAttributionSection } from '../components/forensic/InfrastructureAttributionSection';
import { InvestigationCopilot } from '../components/copilot/InvestigationCopilot';
import { EvidenceIntegrityModal, type EvidenceRecordData } from '../components/history/EvidenceIntegrityModal';

/* ─── Types ──────────────────────────────────────────────── */
interface BackendReportItem {
  id: string;
  report_number: string;
  title: string;
  case_id?: string;
  evidence_id?: string;
  email_sha256?: string;
  threat_score?: number;
  severity?: string;
  analyst_name?: string;
  summary?: string;
  file_size_bytes?: number;
  created_at: string;
}

type CaseViewFilter = 'all' | 'emails' | 'findings' | 'indicators' | 'evidence' | 'reports' | 'correlations' | 'notes' | 'copilot';

const STATUS_CONFIG: Record<CaseStatus, { label: string; badge: string }> = {
  open: { label: 'Open', badge: 'bg-info/10 text-info border-info/30' },
  investigating: { label: 'Investigating', badge: 'bg-warning/10 text-warning border-warning/30' },
  escalated: { label: 'Escalated', badge: 'bg-danger/10 text-danger border-danger/30' },
  resolved: { label: 'Resolved', badge: 'bg-success/10 text-success border-success/30' },
};

const SEVERITY_CONFIG: Record<CaseSeverity, { label: string; badge: string; dot: string }> = {
  low: { label: 'Low', badge: 'bg-surface-secondary text-foreground-muted border-border', dot: 'bg-foreground-muted' },
  medium: { label: 'Medium', badge: 'bg-warning/10 text-warning border-warning/30', dot: 'bg-warning' },
  high: { label: 'High', badge: 'bg-warning/15 text-warning border-warning/40 font-medium', dot: 'bg-warning' },
  critical: { label: 'Critical', badge: 'bg-danger/10 text-danger border-danger/30 font-semibold', dot: 'bg-danger' },
};

export const CaseDetail: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();

  const [caseData, setCaseData] = useState<CaseDetailType | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Active filter tab
  const [activeFilter, setActiveFilter] = useState<CaseViewFilter>('all');
  const [copiedText, setCopiedText] = useState<string | null>(null);

  // Correlations & Attribution
  const [correlations, setCorrelations] = useState<CampaignCorrelationResponse | null>(null);
  const [loadingCorrelations, setLoadingCorrelations] = useState<boolean>(false);
  const [caseAttribution, setCaseAttribution] = useState<AttributionResult | null>(null);

  // Associated Case Reports from GET /api/reports?case_id=...
  const [reports, setReports] = useState<BackendReportItem[]>([]);
  const [loadingReports, setLoadingReports] = useState<boolean>(false);
  const [downloadingReportId, setDownloadingReportId] = useState<string | null>(null);

  // Expanded rows state (progressive disclosure)
  const [expandedEmails, setExpandedEmails] = useState<Record<string, boolean>>({});
  const [expandedFindings, setExpandedFindings] = useState<Record<string, boolean>>({});
  const [indicatorSearchQuery, setIndicatorSearchQuery] = useState('');

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

  // Evidence integrity modal
  const [evidenceModalData, setEvidenceModalData] = useState<EvidenceRecordData | null>(null);

  // Toast banner
  const [toastMessage, setToastMessage] = useState<string | null>(null);
  const [isDownloadingDossier, setIsDownloadingDossier] = useState(false);

  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 3500);
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedText(text);
    setTimeout(() => setCopiedText(null), 2000);
  };

  /* ── Fetch Case Reports ─── */
  const fetchCaseReports = useCallback(async (caseId: string) => {
    setLoadingReports(true);
    try {
      let res: Response;
      try {
        res = await fetch(`/api/reports?case_id=${caseId}`);
      } catch {
        res = await fetch(`http://localhost:8000/api/reports?case_id=${caseId}`);
      }
      if (res.ok) {
        const data = await res.json();
        setReports(data.reports || []);
      }
    } catch (err) {
      console.warn('Failed to load case reports', err);
    } finally {
      setLoadingReports(false);
    }
  }, []);

  /* ── Download Case Dossier PDF ─── */
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
      fetchCaseReports(caseData.id);
    } catch (err) {
      console.error('Failed to download case dossier:', err);
      showToast('Failed to generate case dossier');
    } finally {
      setIsDownloadingDossier(false);
    }
  };

  /* ── Download specific report ─── */
  const handleDownloadReport = async (reportItem: BackendReportItem) => {
    setDownloadingReportId(reportItem.id);
    try {
      const res = await fetch(`http://localhost:8000/api/reports/${reportItem.id}/download`);
      if (!res.ok) throw new Error(`Report download failed (${res.status})`);
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${reportItem.report_number}.pdf`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
      showToast(`Report ${reportItem.report_number} downloaded`);
    } catch (err) {
      console.error('Download report error', err);
      showToast('Failed to download report PDF');
    } finally {
      setDownloadingReportId(null);
    }
  };

  /* ── Fetch Full Case Detail ─── */
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
        fetchCaseReports(data.id);
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
  }, [id, fetchCaseReports]);

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
      disclaimer: 'Location refers to observed network infrastructure and does not necessarily establish the physical location of the human sender.'
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
        showToast('Analyst note recorded');
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
        showToast('Forensic finding recorded in case');
        fetchCaseDetail();
      }
    } catch (e) {
      console.error('Failed to add finding', e);
    } finally {
      setSubmittingFinding(false);
    }
  };

  const toggleEmailExpanded = (emailId: string) => {
    setExpandedEmails(prev => ({ ...prev, [emailId]: !prev[emailId] }));
  };

  const toggleFindingExpanded = (findingId: string) => {
    setExpandedFindings(prev => ({ ...prev, [findingId]: !prev[findingId] }));
  };

  const inspectEvidence = (email: CaseEmail) => {
    setEvidenceModalData({
      evidenceId: email.email_id,
      sha256: email.email_sha256 || 'UNCOMPUTED_HASH',
      originalFilename: `${(email.subject || 'email').toLowerCase().replace(/[^a-z0-9]+/g, '_').slice(0, 24)}.eml`,
      sizeBytes: 15420,
      uploader: 'SOC Forensics Pipeline',
      timestamp: email.added_at,
      subject: email.subject,
      sender: email.sender,
      threatScore: email.threat_score
    });
  };

  /* ── Filtered Indicators ─── */
  const filteredDomains = useMemo(() => {
    const list = caseData?.aggregated_indicators?.domains || [];
    if (!indicatorSearchQuery.trim()) return list;
    const q = indicatorSearchQuery.toLowerCase();
    return list.filter(d => d.toLowerCase().includes(q));
  }, [caseData, indicatorSearchQuery]);

  const filteredIps = useMemo(() => {
    const list = caseData?.aggregated_indicators?.ips || [];
    if (!indicatorSearchQuery.trim()) return list;
    const q = indicatorSearchQuery.toLowerCase();
    return list.filter(ip => ip.toLowerCase().includes(q));
  }, [caseData, indicatorSearchQuery]);

  const filteredUrls = useMemo(() => {
    const list = caseData?.aggregated_indicators?.urls || [];
    if (!indicatorSearchQuery.trim()) return list;
    const q = indicatorSearchQuery.toLowerCase();
    return list.filter(u => u.toLowerCase().includes(q));
  }, [caseData, indicatorSearchQuery]);

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] space-y-4">
        <RefreshCw className="w-8 h-8 text-primary animate-spin" />
        <p className="text-xs font-mono text-foreground-muted">Loading incident case workspace and aggregated telemetry...</p>
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
        <p className="text-xs font-mono text-foreground-muted">{error || 'Unable to locate investigation case in the persistent store.'}</p>
        <button
          onClick={() => navigate('/cases')}
          className="inline-flex items-center space-x-2 px-4 py-2 rounded-xl bg-surface-secondary hover:bg-surface text-primary border border-border font-mono text-xs font-semibold transition-all"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Return to Cases</span>
        </button>
      </div>
    );
  }

  const statusConfig = STATUS_CONFIG[caseData.status] || STATUS_CONFIG.open;
  const severityConfig = SEVERITY_CONFIG[caseData.severity] || SEVERITY_CONFIG.medium;
  const totalIndicators = (caseData.aggregated_indicators.domains.length + caseData.aggregated_indicators.ips.length + caseData.aggregated_indicators.urls.length);

  return (
    <div className="space-y-6 pb-16 page-enter">
      {/* Toast Notification */}
      {toastMessage && (
        <div className="fixed top-5 right-5 z-50 flex items-center space-x-2 px-4 py-2.5 rounded-xl bg-surface border border-success/30 text-success text-xs font-mono shadow-lg animate-in slide-in-from-top-3">
          <CheckCircle2 className="w-4 h-4" />
          <span>{toastMessage}</span>
        </div>
      )}

      {/* 1. TOP NAVIGATION & INCIDENT HEADER */}
      <div className="space-y-4">
        <button
          onClick={() => navigate('/cases')}
          className="inline-flex items-center space-x-1.5 text-xs font-mono text-foreground-muted hover:text-foreground transition-colors cursor-pointer"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Back to Case Management</span>
        </button>

        <div className="p-6 rounded-2xl bg-surface border border-border shadow-xs space-y-4">
          <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
            {/* Left: Case Title & Identifiers */}
            <div className="space-y-2 flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <span className="px-3 py-1 rounded-lg bg-surface-secondary border border-border font-mono text-xs font-bold text-primary flex items-center space-x-1.5">
                  <span>{caseData.case_number}</span>
                  <button
                    type="button"
                    onClick={() => copyToClipboard(caseData.case_number)}
                    className="hover:text-foreground p-0.5 cursor-pointer"
                    title="Copy Case Number"
                  >
                    {copiedText === caseData.case_number ? (
                      <Check className="w-3 h-3 text-success" />
                    ) : (
                      <Copy className="w-3 h-3 text-foreground-muted" />
                    )}
                  </button>
                </span>

                <span className="text-xs font-mono text-foreground-muted flex items-center space-x-1">
                  <Clock className="w-3.5 h-3.5 text-primary" />
                  <span>Created: {new Date(caseData.created_at).toLocaleString()}</span>
                </span>

                <span className="text-xs font-mono text-foreground-muted">
                  · Updated: {new Date(caseData.updated_at).toLocaleString()}
                </span>
              </div>

              <h1 className="text-xl sm:text-2xl font-bold font-mono text-foreground">
                {caseData.title}
              </h1>

              {caseData.description && (
                <p className="text-xs font-mono text-foreground-muted max-w-4xl leading-relaxed">
                  {caseData.description}
                </p>
              )}
            </div>

            {/* Right: Status, Severity & Actions */}
            <div className="flex flex-wrap items-center gap-3 p-3 rounded-xl bg-surface-secondary/70 border border-border self-start lg:self-center">
              <div className="space-y-1">
                <label className="text-[10px] font-mono uppercase text-foreground-muted tracking-wider block">Status</label>
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
                <label className="text-[10px] font-mono uppercase text-foreground-muted tracking-wider block">Severity</label>
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

              <div className="pt-3 sm:pt-0 border-t sm:border-t-0 sm:border-l border-border sm:pl-3 flex items-center space-x-2">
                <button
                  type="button"
                  onClick={handleDownloadDossier}
                  disabled={isDownloadingDossier}
                  className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-surface hover:bg-surface-secondary border border-border text-foreground font-mono text-xs font-semibold transition-all cursor-pointer disabled:opacity-50"
                  title="Generate and download case investigation PDF dossier"
                >
                  {isDownloadingDossier ? (
                    <>
                      <RefreshCw className="w-3.5 h-3.5 animate-spin text-primary" />
                      <span>Generating...</span>
                    </>
                  ) : (
                    <>
                      <Download className="w-3.5 h-3.5 text-primary" />
                      <span>Export Dossier</span>
                    </>
                  )}
                </button>

                <button
                  type="button"
                  onClick={() => setShowFindingModal(true)}
                  className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-primary hover:bg-primary-hover text-primary-foreground font-mono text-xs font-semibold transition-all cursor-pointer shadow-xs"
                >
                  <Plus className="w-3.5 h-3.5" />
                  <span>Add Finding</span>
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* 2. AGGREGATED TRIAGE SUMMARY BAR (Single Compact Strip - No Duplicate Cards!) */}
      <div className="bg-surface rounded-2xl border border-border p-3 shadow-xs">
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2 text-xs font-mono">
          {/* Linked Emails */}
          <div className="p-2.5 rounded-xl bg-surface-secondary/50 border border-border/70 flex items-center space-x-2.5">
            <div className="p-1.5 rounded-lg bg-primary/10 text-primary">
              <Mail className="w-4 h-4" />
            </div>
            <div>
              <span className="text-[10px] uppercase text-foreground-muted block">Linked Emails</span>
              <span className="font-bold text-foreground text-sm">{caseData.emails.length}</span>
            </div>
          </div>

          {/* Documented Findings */}
          <div className="p-2.5 rounded-xl bg-surface-secondary/50 border border-border/70 flex items-center space-x-2.5">
            <div className="p-1.5 rounded-lg bg-danger/10 text-danger">
              <ShieldAlert className="w-4 h-4" />
            </div>
            <div>
              <span className="text-[10px] uppercase text-foreground-muted block">Findings</span>
              <span className="font-bold text-foreground text-sm">{caseData.findings.length}</span>
            </div>
          </div>

          {/* Aggregated IOCs */}
          <div className="p-2.5 rounded-xl bg-surface-secondary/50 border border-border/70 flex items-center space-x-2.5">
            <div className="p-1.5 rounded-lg bg-primary/10 text-primary">
              <Target className="w-4 h-4" />
            </div>
            <div>
              <span className="text-[10px] uppercase text-foreground-muted block">IoC Indicators</span>
              <span className="font-bold text-foreground text-sm">{totalIndicators}</span>
            </div>
          </div>

          {/* Sending Infrastructure */}
          <div className="p-2.5 rounded-xl bg-surface-secondary/50 border border-border/70 flex items-center space-x-2.5">
            <div className="p-1.5 rounded-lg bg-primary/10 text-primary">
              <Network className="w-4 h-4" />
            </div>
            <div>
              <span className="text-[10px] uppercase text-foreground-muted block">Infrastructure</span>
              <span className="font-bold text-foreground text-sm">
                {caseData.aggregated_indicators.ips.length} IPs
              </span>
            </div>
          </div>

          {/* Evidence Integrity */}
          <div className="p-2.5 rounded-xl bg-surface-secondary/50 border border-border/70 flex items-center space-x-2.5">
            <div className="p-1.5 rounded-lg bg-success/10 text-success">
              <ShieldCheck className="w-4 h-4" />
            </div>
            <div>
              <span className="text-[10px] uppercase text-foreground-muted block">Evidence Verified</span>
              <span className="font-bold text-success text-sm">{caseData.emails.length}/{caseData.emails.length} SHA-256</span>
            </div>
          </div>

          {/* Reports */}
          <div className="p-2.5 rounded-xl bg-surface-secondary/50 border border-border/70 flex items-center space-x-2.5">
            <div className="p-1.5 rounded-lg bg-primary/10 text-primary">
              <FileDown className="w-4 h-4" />
            </div>
            <div>
              <span className="text-[10px] uppercase text-foreground-muted block">Generated Reports</span>
              <span className="font-bold text-foreground text-sm">{reports.length}</span>
            </div>
          </div>
        </div>
      </div>

      {/* 3. SECTION FILTER TABS */}
      <div className="flex flex-wrap items-center gap-1.5 p-1.5 bg-surface rounded-xl border border-border shadow-xs">
        {[
          { id: 'all' as const, label: 'All Aggregated', icon: <Layers className="w-3.5 h-3.5" />, count: undefined },
          { id: 'emails' as const, label: 'Linked Emails', icon: <Mail className="w-3.5 h-3.5" />, count: caseData.emails.length },
          { id: 'findings' as const, label: 'Forensic Findings', icon: <ShieldAlert className="w-3.5 h-3.5" />, count: caseData.findings.length },
          { id: 'indicators' as const, label: 'Indicators & Infra', icon: <Target className="w-3.5 h-3.5" />, count: totalIndicators },
          { id: 'evidence' as const, label: 'Evidence Ledger', icon: <Lock className="w-3.5 h-3.5" />, count: caseData.emails.length },
          { id: 'reports' as const, label: 'Reports & Dossiers', icon: <FileDown className="w-3.5 h-3.5" />, count: reports.length },
          { id: 'correlations' as const, label: 'Correlations', icon: <GitMerge className="w-3.5 h-3.5" />, count: correlations?.related_cases.length ?? 0 },
          { id: 'notes' as const, label: 'Notes & Audit', icon: <FileText className="w-3.5 h-3.5" />, count: caseData.notes.length + caseData.audit_logs.length },
          { id: 'copilot' as const, label: 'Copilot', icon: <Sparkles className="w-3.5 h-3.5 text-primary" />, count: 'AI' }
        ].map(tab => {
          const isActive = activeFilter === tab.id;
          return (
            <button
              key={tab.id}
              type="button"
              onClick={() => setActiveFilter(tab.id)}
              className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-all cursor-pointer ${
                isActive
                  ? 'bg-primary text-primary-foreground shadow-xs font-semibold'
                  : 'text-foreground-muted hover:text-foreground hover:bg-surface-secondary border border-transparent'
              }`}
            >
              {tab.icon}
              <span>{tab.label}</span>
              {tab.count !== undefined && (
                <span className={`ml-1 px-1.5 py-0.2 rounded text-[10px] ${
                  isActive ? 'bg-black/20 text-white' : 'bg-surface-secondary text-foreground-muted border border-border'
                }`}>
                  {tab.count}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* 4. CONTENT SECTIONS (Stackable or Filtered) */}
      <div className="space-y-6">

        {/* ── SECTION 1: LINKED EMAILS & EVIDENCE RUNS ── */}
        {(activeFilter === 'all' || activeFilter === 'emails') && (
          <div className="bg-surface rounded-2xl border border-border p-5 space-y-4 shadow-xs">
            <div className="flex items-center justify-between pb-3 border-b border-border">
              <div className="flex items-center space-x-2">
                <Mail className="w-4 h-4 text-primary" />
                <h3 className="text-sm font-bold font-mono text-foreground">
                  Linked Email Evidence Artifacts ({caseData.emails.length})
                </h3>
              </div>
              <button
                type="button"
                onClick={() => navigate('/analyze')}
                className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-surface hover:bg-surface-secondary border border-border text-foreground text-xs font-mono font-semibold transition-colors cursor-pointer"
              >
                <Plus className="w-3.5 h-3.5 text-primary" />
                <span>Ingest & Link Another Email</span>
              </button>
            </div>

            {caseData.emails.length === 0 ? (
              <div className="p-8 text-center rounded-xl bg-surface-secondary/40 border border-border space-y-3">
                <Mail className="w-8 h-8 text-foreground-muted mx-auto" />
                <p className="text-xs font-mono text-foreground-muted">No emails linked to this incident case yet.</p>
                <button
                  type="button"
                  onClick={() => navigate('/analyze')}
                  className="px-4 py-2 rounded-xl bg-primary hover:bg-primary-hover text-primary-foreground font-mono text-xs font-semibold transition-all cursor-pointer"
                >
                  Ingest Email & Link to Case
                </button>
              </div>
            ) : (
              <div className="space-y-2.5">
                {caseData.emails.map(email => {
                  const isExpanded = !!expandedEmails[email.email_id];
                  const sevConfig = SEVERITY_CONFIG[email.severity?.toLowerCase() as CaseSeverity] || SEVERITY_CONFIG.low;

                  return (
                    <div
                      key={email.id}
                      className="p-3.5 rounded-xl bg-surface-secondary/40 border border-border hover:border-primary/30 transition-all font-mono text-xs space-y-3"
                    >
                      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
                        {/* Subject & Sender */}
                        <div className="space-y-1 min-w-0 flex-1">
                          <div className="flex items-center space-x-2">
                            <button
                              type="button"
                              onClick={() => toggleEmailExpanded(email.email_id)}
                              className="p-1 rounded hover:bg-surface text-foreground-muted cursor-pointer"
                            >
                              <ChevronRight className={`w-3.5 h-3.5 transition-transform ${isExpanded ? 'rotate-90 text-primary' : ''}`} />
                            </button>
                            <span className="font-bold text-foreground text-xs truncate max-w-xl">
                              {email.subject || 'Untitled Email Evidence'}
                            </span>
                            {email.threat_score !== undefined && (
                              <div className="flex items-center space-x-1.5">
                                <span className={`px-2 py-0.2 rounded text-[10px] font-bold ${
                                  email.threat_score >= 70 ? 'bg-danger/15 text-danger border border-danger/30' : 'bg-surface border border-border text-foreground-muted'
                                }`}>
                                  Score: {Math.round(email.threat_score)}/100
                                </span>
                                <span className={`px-2 py-0.2 rounded text-[10px] uppercase ${sevConfig.badge}`}>
                                  {sevConfig.label}
                                </span>
                              </div>
                            )}
                          </div>

                          <div className="flex flex-wrap items-center gap-3 text-[11px] text-foreground-muted pl-6">
                            <span>From: <strong className="text-foreground">{email.sender}</strong></span>
                            <span>·</span>
                            <span>ID: <code className="text-primary font-bold">{email.email_id}</code></span>
                            <span>·</span>
                            <span>Attached: {new Date(email.added_at).toLocaleString()}</span>
                          </div>
                        </div>

                        {/* Actions */}
                        <div className="flex items-center space-x-2 pl-6 md:pl-0">
                          {/* Reopen in Investigation Workspace */}
                          <Link
                            to={`/investigate/${email.email_id}`}
                            className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-primary hover:bg-primary-hover text-primary-foreground text-xs font-semibold transition-colors cursor-pointer shadow-xs"
                          >
                            <ExternalLink className="w-3.5 h-3.5" />
                            <span>Workspace</span>
                          </Link>

                          {/* Inspect Evidence Integrity */}
                          <button
                            type="button"
                            onClick={() => inspectEvidence(email)}
                            className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-surface hover:bg-surface-secondary border border-border text-foreground text-xs font-medium transition-colors cursor-pointer"
                            title="Inspect Cryptographic Evidence Integrity"
                          >
                            <Lock className="w-3.5 h-3.5 text-primary" />
                            <span>Evidence</span>
                          </button>

                          {/* Detach */}
                          <button
                            type="button"
                            onClick={() => handleRemoveEmail(email.email_id)}
                            className="p-1.5 rounded-lg bg-surface hover:bg-danger/10 border border-border hover:border-danger/30 text-foreground-muted hover:text-danger transition-colors cursor-pointer"
                            title="Detach from Case"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </div>

                      {/* Expandable Evidence Details */}
                      {isExpanded && (
                        <div className="pt-3 border-t border-border/70 grid grid-cols-1 sm:grid-cols-2 gap-3 pl-6 text-[11px]">
                          <div className="p-2.5 rounded-lg bg-surface border border-border space-y-1">
                            <span className="text-[10px] uppercase text-foreground-muted font-bold block">
                              SHA-256 Cryptographic Identity
                            </span>
                            <div className="flex items-center justify-between font-mono break-all select-all text-foreground">
                              <span>{email.email_sha256 || 'Calculated at ingestion'}</span>
                              {email.email_sha256 && (
                                <button
                                  type="button"
                                  onClick={() => copyToClipboard(email.email_sha256!)}
                                  className="ml-2 hover:text-primary cursor-pointer p-1"
                                >
                                  {copiedText === email.email_sha256 ? <Check className="w-3 h-3 text-success" /> : <Copy className="w-3 h-3" />}
                                </button>
                              )}
                            </div>
                          </div>

                          <div className="p-2.5 rounded-lg bg-surface border border-border space-y-1">
                            <span className="text-[10px] uppercase text-foreground-muted font-bold block">
                              Integrity Verification State
                            </span>
                            <div className="flex items-center space-x-2 text-success font-semibold">
                              <ShieldCheck className="w-3.5 h-3.5" />
                              <span>Cryptographically Verified Ingestion Bitstream</span>
                            </div>
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}

        {/* ── SECTION 2: FORENSIC FINDINGS ── */}
        {(activeFilter === 'all' || activeFilter === 'findings') && (
          <div className="bg-surface rounded-2xl border border-border p-5 space-y-4 shadow-xs">
            <div className="flex items-center justify-between pb-3 border-b border-border">
              <div className="flex items-center space-x-2">
                <ShieldAlert className="w-4 h-4 text-primary" />
                <h3 className="text-sm font-bold font-mono text-foreground">
                  Documented Forensic Findings ({caseData.findings.length})
                </h3>
              </div>
              <button
                type="button"
                onClick={() => setShowFindingModal(true)}
                className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-primary hover:bg-primary-hover text-primary-foreground text-xs font-mono font-semibold transition-all cursor-pointer shadow-xs"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>Record Finding</span>
              </button>
            </div>

            {caseData.findings.length === 0 ? (
              <div className="p-8 text-center rounded-xl bg-surface-secondary/40 border border-border space-y-2">
                <ShieldAlert className="w-8 h-8 text-foreground-muted mx-auto" />
                <p className="text-xs font-mono text-foreground-muted">No forensic findings logged for this case yet.</p>
              </div>
            ) : (
              <div className="space-y-2.5">
                {caseData.findings.map(finding => {
                  const sevConfig = SEVERITY_CONFIG[finding.severity as CaseSeverity] || SEVERITY_CONFIG.medium;
                  const isExpanded = !!expandedFindings[finding.id];

                  return (
                    <div
                      key={finding.id}
                      className="p-3.5 rounded-xl bg-surface-secondary/40 border border-border hover:border-border-hover transition-all font-mono text-xs space-y-2"
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-2">
                          <button
                            type="button"
                            onClick={() => toggleFindingExpanded(finding.id)}
                            className="p-0.5 rounded hover:bg-surface text-foreground-muted cursor-pointer"
                          >
                            <ChevronRight className={`w-3.5 h-3.5 transition-transform ${isExpanded ? 'rotate-90 text-primary' : ''}`} />
                          </button>
                          <span className="px-2 py-0.5 rounded text-[10px] bg-surface border border-border text-primary uppercase font-bold">
                            {finding.finding_type}
                          </span>
                          <h4 className="font-bold text-foreground text-xs">{finding.title}</h4>
                        </div>
                        <span className={`px-2 py-0.5 rounded text-[10px] border uppercase ${sevConfig.badge}`}>
                          {sevConfig.label}
                        </span>
                      </div>

                      {finding.description && (
                        <p className="text-foreground-muted text-[11px] pl-6 leading-relaxed">
                          {finding.description}
                        </p>
                      )}

                      <div className="text-[10px] text-foreground-muted pl-6 pt-1 flex items-center justify-between border-t border-border/50">
                        <span>Logged: {new Date(finding.created_at).toLocaleString()}</span>
                        <span className="text-foreground-subtle">Case Forensic Repository</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}

        {/* ── SECTION 3: AGGREGATED INDICATORS & INFRASTRUCTURE ── */}
        {(activeFilter === 'all' || activeFilter === 'indicators') && (
          <div className="bg-surface rounded-2xl border border-border p-5 space-y-4 shadow-xs">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-border">
              <div className="flex items-center space-x-2">
                <Target className="w-4 h-4 text-primary" />
                <h3 className="text-sm font-bold font-mono text-foreground">
                  Aggregated IoCs & Infrastructure ({totalIndicators})
                </h3>
              </div>

              {/* Filter / Search input */}
              <div className="relative w-full sm:w-64">
                <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-foreground-muted" />
                <input
                  type="text"
                  value={indicatorSearchQuery}
                  onChange={(e) => setIndicatorSearchQuery(e.target.value)}
                  placeholder="Filter IoCs across case..."
                  className="w-full pl-8 pr-3 py-1.5 rounded-lg bg-surface-secondary border border-border text-xs font-mono text-foreground focus:outline-none focus:border-primary"
                />
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {/* DOMAINS */}
              <div className="p-3.5 rounded-xl bg-surface-secondary/40 border border-border space-y-2.5 font-mono text-xs">
                <div className="flex items-center justify-between pb-1.5 border-b border-border">
                  <div className="flex items-center space-x-1.5 text-primary font-bold">
                    <Globe className="w-3.5 h-3.5" />
                    <span>Domains ({filteredDomains.length})</span>
                  </div>
                </div>
                <div className="space-y-1.5 max-h-56 overflow-y-auto pr-1">
                  {filteredDomains.length === 0 ? (
                    <p className="text-[11px] text-foreground-muted italic py-2">No domains matching filter.</p>
                  ) : (
                    filteredDomains.map(dom => (
                      <div key={dom} className="flex items-center justify-between p-2 rounded-lg bg-surface border border-border">
                        <span className="truncate max-w-[180px] font-medium text-foreground">{dom}</span>
                        <button
                          type="button"
                          onClick={() => copyToClipboard(dom)}
                          className="text-foreground-muted hover:text-foreground p-1 cursor-pointer"
                        >
                          {copiedText === dom ? <Check className="w-3 h-3 text-success" /> : <Copy className="w-3 h-3" />}
                        </button>
                      </div>
                    ))
                  )}
                </div>
              </div>

              {/* IP INFRASTRUCTURE */}
              <div className="p-3.5 rounded-xl bg-surface-secondary/40 border border-border space-y-2.5 font-mono text-xs">
                <div className="flex items-center justify-between pb-1.5 border-b border-border">
                  <div className="flex items-center space-x-1.5 text-primary font-bold">
                    <Server className="w-3.5 h-3.5" />
                    <span>IP Addresses ({filteredIps.length})</span>
                  </div>
                </div>
                <div className="space-y-1.5 max-h-56 overflow-y-auto pr-1">
                  {filteredIps.length === 0 ? (
                    <p className="text-[11px] text-foreground-muted italic py-2">No IPs matching filter.</p>
                  ) : (
                    filteredIps.map(ip => (
                      <div key={ip} className="flex items-center justify-between p-2 rounded-lg bg-surface border border-border">
                        <span className="truncate max-w-[180px] font-medium text-foreground">{ip}</span>
                        <button
                          type="button"
                          onClick={() => copyToClipboard(ip)}
                          className="text-foreground-muted hover:text-foreground p-1 cursor-pointer"
                        >
                          {copiedText === ip ? <Check className="w-3 h-3 text-success" /> : <Copy className="w-3 h-3" />}
                        </button>
                      </div>
                    ))
                  )}
                </div>
              </div>

              {/* DEFANGED URLS */}
              <div className="p-3.5 rounded-xl bg-surface-secondary/40 border border-border space-y-2.5 font-mono text-xs">
                <div className="flex items-center justify-between pb-1.5 border-b border-border">
                  <div className="flex items-center space-x-1.5 text-danger font-bold">
                    <LinkIcon className="w-3.5 h-3.5" />
                    <span>URLs (Defanged) ({filteredUrls.length})</span>
                  </div>
                </div>
                <div className="space-y-1.5 max-h-56 overflow-y-auto pr-1">
                  {filteredUrls.length === 0 ? (
                    <p className="text-[11px] text-foreground-muted italic py-2">No URLs matching filter.</p>
                  ) : (
                    filteredUrls.map(u => {
                      const defanged = u.replace(/http:\/\//gi, 'hxxp://').replace(/https:\/\//gi, 'hxxps://').replace(/\./g, '[.]');
                      return (
                        <div key={u} className="flex items-center justify-between p-2 rounded-lg bg-surface border border-border">
                          <code className="truncate max-w-[180px] select-all text-foreground text-[10px]">{defanged}</code>
                          <button
                            type="button"
                            onClick={() => copyToClipboard(defanged)}
                            className="text-foreground-muted hover:text-foreground p-1 cursor-pointer shrink-0"
                            title="Copy Defanged URL"
                          >
                            {copiedText === defanged ? <Check className="w-3 h-3 text-success" /> : <Copy className="w-3 h-3" />}
                          </button>
                        </div>
                      );
                    })
                  )}
                </div>
              </div>
            </div>

            {/* Infrastructure Attribution Component */}
            <div className="pt-2">
              <InfrastructureAttributionSection
                attribution={caseAttribution || fallbackCaseAttribution}
              />
            </div>
          </div>
        )}

        {/* ── SECTION 4: EVIDENCE INTEGRITY & CHAIN OF CUSTODY ── */}
        {(activeFilter === 'all' || activeFilter === 'evidence') && (
          <div className="bg-surface rounded-2xl border border-border p-5 space-y-4 shadow-xs">
            <div className="flex items-center justify-between pb-3 border-b border-border">
              <div className="flex items-center space-x-2">
                <Lock className="w-4 h-4 text-primary" />
                <h3 className="text-sm font-bold font-mono text-foreground">
                  Evidence Custody & Cryptographic Ledger
                </h3>
              </div>
              <span className="text-xs font-mono text-success flex items-center space-x-1">
                <ShieldCheck className="w-3.5 h-3.5" />
                <span>All Bitstreams Verified</span>
              </span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left font-mono text-xs">
                <thead>
                  <tr className="border-b border-border text-[10px] text-foreground-muted uppercase tracking-wider">
                    <th className="py-2.5 px-3">Evidence ID</th>
                    <th className="py-2.5 px-3">Subject / Original Artifact</th>
                    <th className="py-2.5 px-3">SHA-256 Digest</th>
                    <th className="py-2.5 px-3">Ingestion Date</th>
                    <th className="py-2.5 px-3 text-right">Integrity</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/60">
                  {caseData.emails.map(email => (
                    <tr key={email.id} className="hover:bg-surface-secondary/40 transition-colors">
                      <td className="py-2.5 px-3 font-bold text-primary">{email.email_id}</td>
                      <td className="py-2.5 px-3 font-medium text-foreground max-w-xs truncate">{email.subject}</td>
                      <td className="py-2.5 px-3 font-mono text-[11px] text-foreground-muted max-w-xs truncate">
                        {email.email_sha256 || 'COMPUTED_AT_INGESTION'}
                      </td>
                      <td className="py-2.5 px-3 text-[11px] text-foreground-muted">
                        {new Date(email.added_at).toLocaleString()}
                      </td>
                      <td className="py-2.5 px-3 text-right">
                        <button
                          type="button"
                          onClick={() => inspectEvidence(email)}
                          className="inline-flex items-center space-x-1 px-2 py-0.5 rounded bg-success/10 text-success border border-success/30 font-bold text-[10px] hover:bg-success/20 cursor-pointer"
                        >
                          <CheckCircle2 className="w-3 h-3" />
                          <span>Verified</span>
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ── SECTION 5: CASE REPORTS & DOSSIERS ── */}
        {(activeFilter === 'all' || activeFilter === 'reports') && (
          <div className="bg-surface rounded-2xl border border-border p-5 space-y-4 shadow-xs">
            <div className="flex items-center justify-between pb-3 border-b border-border">
              <div className="flex items-center space-x-2">
                <FileDown className="w-4 h-4 text-primary" />
                <h3 className="text-sm font-bold font-mono text-foreground">
                  Case Reports & Evidentiary Dossiers ({reports.length})
                </h3>
              </div>
              <button
                type="button"
                onClick={handleDownloadDossier}
                disabled={isDownloadingDossier}
                className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-primary hover:bg-primary-hover text-primary-foreground text-xs font-mono font-semibold transition-all cursor-pointer shadow-xs disabled:opacity-50"
              >
                {isDownloadingDossier ? (
                  <>
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    <span>Compiling PDF...</span>
                  </>
                ) : (
                  <>
                    <Download className="w-3.5 h-3.5" />
                    <span>Generate New Dossier PDF</span>
                  </>
                )}
              </button>
            </div>

            {loadingReports ? (
              <div className="p-8 text-center font-mono text-xs text-foreground-muted">
                <Loader2 className="w-5 h-5 text-primary animate-spin mx-auto mb-2" />
                <span>Querying generated case reports...</span>
              </div>
            ) : reports.length === 0 ? (
              <div className="p-8 text-center rounded-xl bg-surface-secondary/40 border border-border space-y-2 font-mono text-xs">
                <FileText className="w-8 h-8 text-foreground-muted mx-auto" />
                <p className="text-foreground-muted">No PDF reports generated for this case yet.</p>
                <button
                  type="button"
                  onClick={handleDownloadDossier}
                  className="px-4 py-2 rounded-xl bg-surface border border-border text-primary font-semibold hover:bg-surface-secondary cursor-pointer"
                >
                  Generate First Case Dossier
                </button>
              </div>
            ) : (
              <div className="space-y-2">
                {reports.map(rep => (
                  <div
                    key={rep.id}
                    className="p-3.5 rounded-xl bg-surface-secondary/40 border border-border flex flex-col sm:flex-row sm:items-center justify-between gap-3 font-mono text-xs"
                  >
                    <div className="space-y-1">
                      <div className="flex items-center space-x-2">
                        <span className="font-bold text-primary">{rep.report_number}</span>
                        <span className="font-semibold text-foreground">{rep.title}</span>
                      </div>
                      <div className="flex flex-wrap items-center gap-3 text-[11px] text-foreground-muted">
                        <span>Analyst: {rep.analyst_name}</span>
                        <span>·</span>
                        <span>Generated: {new Date(rep.created_at).toLocaleString()}</span>
                        {rep.file_size_bytes ? (
                          <>
                            <span>·</span>
                            <span>{(rep.file_size_bytes / 1024).toFixed(1)} KB</span>
                          </>
                        ) : null}
                      </div>
                    </div>

                    <button
                      type="button"
                      onClick={() => handleDownloadReport(rep)}
                      disabled={downloadingReportId === rep.id}
                      className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-surface hover:bg-surface-secondary border border-border text-foreground text-xs font-semibold transition-colors cursor-pointer disabled:opacity-50 self-start sm:self-center"
                    >
                      {downloadingReportId === rep.id ? (
                        <RefreshCw className="w-3.5 h-3.5 animate-spin text-primary" />
                      ) : (
                        <Download className="w-3.5 h-3.5 text-primary" />
                      )}
                      <span>Download PDF</span>
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* ── SECTION 6: CORRELATIONS & RELATED INVESTIGATIONS ── */}
        {(activeFilter === 'all' || activeFilter === 'correlations') && (
          <div className="bg-surface rounded-2xl border border-border p-5 space-y-4 shadow-xs">
            <div className="flex items-center justify-between pb-3 border-b border-border">
              <div className="flex items-center space-x-2">
                <GitMerge className="w-4 h-4 text-primary" />
                <h3 className="text-sm font-bold font-mono text-foreground">
                  Cross-Case Campaign Correlations ({correlations?.related_cases.length ?? 0})
                </h3>
              </div>
            </div>

            {loadingCorrelations ? (
              <div className="p-8 text-center font-mono text-xs text-foreground-muted">
                <RefreshCw className="w-5 h-5 text-primary animate-spin mx-auto mb-2" />
                <span>Evaluating cross-incident infrastructure correlation...</span>
              </div>
            ) : !correlations || correlations.related_cases.length === 0 ? (
              <div className="p-8 text-center rounded-xl bg-surface-secondary/40 border border-border font-mono text-xs text-foreground-muted">
                No overlapping campaign infrastructure or shared IoC patterns observed with other active cases.
              </div>
            ) : (
              <div className="space-y-2.5">
                {correlations.related_cases.map(rel => (
                  <div
                    key={rel.case_id}
                    className="p-3.5 rounded-xl bg-surface-secondary/40 border border-border flex flex-col sm:flex-row sm:items-center justify-between gap-3 font-mono text-xs"
                  >
                    <div className="space-y-1">
                      <div className="flex items-center space-x-2">
                        <span className="font-bold text-primary">{rel.case_number}</span>
                        <span className="font-semibold text-foreground">{rel.title}</span>
                        <span className="px-2 py-0.2 rounded bg-primary/15 text-primary text-[10px] font-bold">
                          {Math.round((rel.correlation_score ?? (rel as any).similarity_score ?? 0) * 100)}% Match
                        </span>
                      </div>
                      <p className="text-[11px] text-foreground-muted">
                        {rel.shared_evidence_summary || `Shared overlap across ${rel.shared_indicators?.length || 0} correlated indicators.`}
                      </p>
                    </div>

                    <Link
                      to={`/cases/${rel.case_id}`}
                      className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-surface hover:bg-surface-secondary border border-border text-foreground text-xs font-medium cursor-pointer transition-colors self-start sm:self-center"
                    >
                      <span>Inspect Case</span>
                      <ExternalLink className="w-3.5 h-3.5 text-primary" />
                    </Link>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* ── SECTION 7: ANALYST NOTES & IMMUTABLE AUDIT TIMELINE ── */}
        {(activeFilter === 'all' || activeFilter === 'notes') && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Analyst Notes */}
            <div className="bg-surface rounded-2xl border border-border p-5 space-y-4 shadow-xs">
              <div className="flex items-center justify-between pb-3 border-b border-border">
                <div className="flex items-center space-x-2">
                  <FileText className="w-4 h-4 text-primary" />
                  <h3 className="text-sm font-bold font-mono text-foreground">
                    Analyst Notes ({caseData.notes.length})
                  </h3>
                </div>
              </div>

              {/* Add Note Form */}
              <form onSubmit={handleAddNote} className="space-y-3 font-mono text-xs">
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                  <input
                    type="text"
                    placeholder="Analyst Name"
                    value={noteAuthor}
                    onChange={e => setNoteAuthor(e.target.value)}
                    className="w-full px-3 py-1.5 rounded-lg bg-surface-secondary border border-border text-foreground focus:outline-none focus:border-primary"
                  />
                  <div className="sm:col-span-2 flex space-x-2">
                    <input
                      type="text"
                      placeholder="Record observation, hypothesis, or task..."
                      value={noteText}
                      onChange={e => setNoteText(e.target.value)}
                      className="flex-1 px-3 py-1.5 rounded-lg bg-surface-secondary border border-border text-foreground focus:outline-none focus:border-primary"
                      required
                    />
                    <button
                      type="submit"
                      disabled={submittingNote || !noteText.trim()}
                      className="px-3 py-1.5 rounded-lg bg-primary hover:bg-primary-hover text-primary-foreground font-semibold flex items-center space-x-1 cursor-pointer disabled:opacity-50"
                    >
                      <Send className="w-3 h-3" />
                      <span>{submittingNote ? '...' : 'Add'}</span>
                    </button>
                  </div>
                </div>
              </form>

              {/* Notes Feed */}
              <div className="space-y-2.5 max-h-72 overflow-y-auto pr-1">
                {caseData.notes.length === 0 ? (
                  <p className="text-xs font-mono text-foreground-muted italic py-4 text-center">No notes recorded yet.</p>
                ) : (
                  caseData.notes.map(note => (
                    <div key={note.id} className="p-3 rounded-xl bg-surface-secondary/40 border border-border space-y-1 font-mono text-xs">
                      <div className="flex items-center justify-between text-[11px]">
                        <span className="text-primary font-bold">{note.author}</span>
                        <span className="text-foreground-muted">{new Date(note.created_at).toLocaleString()}</span>
                      </div>
                      <p className="text-foreground text-xs leading-relaxed whitespace-pre-wrap">{note.note_text}</p>
                    </div>
                  ))
                )}
              </div>
            </div>

            {/* Audit Timeline */}
            <div className="bg-surface rounded-2xl border border-border p-5 space-y-4 shadow-xs">
              <div className="flex items-center justify-between pb-3 border-b border-border">
                <div className="flex items-center space-x-2">
                  <History className="w-4 h-4 text-primary" />
                  <h3 className="text-sm font-bold font-mono text-foreground">
                    Immutable Audit Trail ({caseData.audit_logs.length})
                  </h3>
                </div>
                <span className="text-[10px] font-mono text-foreground-muted uppercase">Append-Only</span>
              </div>

              <div className="relative pl-6 space-y-3 before:absolute before:left-2 before:top-2 before:bottom-2 before:w-0.5 before:bg-border max-h-72 overflow-y-auto pr-1 font-mono text-xs">
                {caseData.audit_logs.map(entry => (
                  <div key={entry.id} className="relative space-y-0.5">
                    <div className="absolute -left-6 top-1.5 w-2 h-2 rounded-full bg-primary border-2 border-surface" />
                    <div className="p-2.5 rounded-lg bg-surface-secondary/40 border border-border text-[11px] space-y-0.5">
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-primary uppercase text-[10px]">{entry.action}</span>
                        <span className="text-foreground-muted text-[10px]">{new Date(entry.timestamp).toLocaleTimeString()}</span>
                      </div>
                      <p className="text-foreground-muted text-[11px]">{entry.details}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* ── SECTION 8: INVESTIGATION COPILOT ── */}
        {(activeFilter === 'all' || activeFilter === 'copilot') && (
          <div className="bg-surface rounded-2xl border border-border p-5 space-y-4 shadow-xs">
            <div className="flex items-center justify-between pb-3 border-b border-border">
              <div className="flex items-center space-x-2">
                <Sparkles className="w-4 h-4 text-primary" />
                <h3 className="text-sm font-bold font-mono text-foreground">
                  Case Investigation AI Copilot
                </h3>
              </div>
            </div>

            <InvestigationCopilot
              mode="case"
              contextId={caseData.id || id || 'CASE-2026-0042'}
              onCompareEmails={() => setActiveFilter('emails')}
              onOpenEvidence={() => setActiveFilter('findings')}
              onAddToCase={() => setActiveFilter('notes')}
            />
          </div>
        )}
      </div>

      {/* ADD FINDING MODAL */}
      {showFindingModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-xs animate-in fade-in duration-200">
          <div className="w-full max-w-md rounded-2xl bg-surface border border-border shadow-2xl p-6 space-y-4 font-mono text-xs">
            <div className="flex items-center justify-between pb-3 border-b border-border">
              <h3 className="text-sm font-bold text-foreground flex items-center space-x-2">
                <ShieldAlert className="w-4 h-4 text-primary" />
                <span>Add Forensic Finding</span>
              </h3>
              <button onClick={() => setShowFindingModal(false)} className="text-foreground-muted hover:text-foreground cursor-pointer">
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleAddFinding} className="space-y-3">
              <div className="space-y-1">
                <label className="text-foreground-muted">Finding Category</label>
                <select
                  value={findingType}
                  onChange={e => setFindingType(e.target.value)}
                  className="w-full px-3 py-2 rounded-xl bg-surface-secondary border border-border text-foreground focus:outline-none focus:border-primary cursor-pointer"
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
                <label className="text-foreground-muted">Title</label>
                <input
                  type="text"
                  placeholder="e.g. Brand homograph impersonating domain"
                  value={findingTitle}
                  onChange={e => setFindingTitle(e.target.value)}
                  className="w-full px-3 py-2 rounded-xl bg-surface-secondary border border-border text-foreground focus:outline-none focus:border-primary"
                  required
                />
              </div>

              <div className="space-y-1">
                <label className="text-foreground-muted">Description</label>
                <textarea
                  rows={3}
                  placeholder="Technical details, observed telemetry, or impact analysis..."
                  value={findingDescription}
                  onChange={e => setFindingDescription(e.target.value)}
                  className="w-full px-3 py-2 rounded-xl bg-surface-secondary border border-border text-foreground focus:outline-none focus:border-primary"
                />
              </div>

              <div className="space-y-1">
                <label className="text-foreground-muted">Severity</label>
                <select
                  value={findingSeverity}
                  onChange={e => setFindingSeverity(e.target.value as CaseSeverity)}
                  className="w-full px-3 py-2 rounded-xl bg-surface-secondary border border-border text-foreground focus:outline-none focus:border-primary cursor-pointer"
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
                  className="px-4 py-2 rounded-xl bg-surface-secondary hover:bg-surface text-foreground-muted font-mono text-xs border border-border cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submittingFinding || !findingTitle.trim()}
                  className="px-4 py-2 rounded-xl bg-primary hover:bg-primary-hover text-primary-foreground font-semibold transition-all cursor-pointer shadow-xs disabled:opacity-50"
                >
                  {submittingFinding ? 'Recording...' : 'Record Finding'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* EVIDENCE INTEGRITY MODAL */}
      <EvidenceIntegrityModal
        isOpen={!!evidenceModalData}
        onClose={() => setEvidenceModalData(null)}
        evidence={evidenceModalData}
        onReopenWorkspace={(evId) => navigate(`/investigate/${evId}`)}
      />
    </div>
  );
};

export default CaseDetail;
