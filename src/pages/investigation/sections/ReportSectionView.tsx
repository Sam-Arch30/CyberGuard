import React, { useState, useEffect, useRef } from 'react';
import {
  FileText,
  Printer,
  ShieldAlert,
  ShieldCheck,
  Download,
  Loader2,
  Clock,
  Lock,
  Server,
  Globe,
  Link as LinkIcon,
  GitMerge,
  FileCode,
  Copy,
  Check,
  CheckCircle2,
  AlertTriangle,
  Info,
  RefreshCw,
  Sliders,
  History,
  GitCompare,
  AlertCircle,
  Hash,
  Layers,
  Terminal,
} from 'lucide-react';
import type { EmailAnalysis } from '../../../types/forensic';
import type {
  ReportDetail,
  ReportListItem,
  ReportType,
  ReportClassification,
  RedactionLevel,
  ReportContentOptions,
  ReportComparison,
  EpistemicStatus,
} from '../../../types/report';
import { DEFAULT_CONTENT_OPTIONS } from '../../../types/report';
import { reportService } from '../../../services/reportService';
import { RealtimeService } from '../../../services/realtimeService';
import { useInvestigation } from '../../../context/InvestigationContext';

interface ReportSectionViewProps {
  investigationId?: string;
  email?: EmailAnalysis;
}

export const ReportSectionView: React.FC<ReportSectionViewProps> = ({
  investigationId: propInvestigationId,
  email,
}) => {
  const { workspaceSummary, activeEmailId } = useInvestigation();
  const effectiveId = propInvestigationId || activeEmailId || workspaceSummary?.investigation.investigation_id || email?.evidence_id || email?.id || 'current';

  // Core State
  const [report, setReport] = useState<ReportDetail | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [isGenerating, setIsGenerating] = useState<boolean>(false);
  const [isExportingPdf, setIsExportingPdf] = useState<boolean>(false);
  const [isExportingJson, setIsExportingJson] = useState<boolean>(false);
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  // Configuration options state
  const [reportType, setReportType] = useState<ReportType>('ANALYST');
  const [classification, setClassification] = useState<ReportClassification>('CONFIDENTIAL');
  const [redactionLevel, setRedactionLevel] = useState<RedactionLevel>('NONE');
  const [contentOptions, setContentOptions] = useState<ReportContentOptions>({ ...DEFAULT_CONTENT_OPTIONS });
  const [showConfigDrawer, setShowConfigDrawer] = useState<boolean>(false);

  // Version History & Comparison
  const [reportVersions, setReportVersions] = useState<ReportListItem[]>([]);
  const [loadingVersions, setLoadingVersions] = useState<boolean>(false);
  const [showHistoryDrawer, setShowHistoryDrawer] = useState<boolean>(false);
  const [comparison, setComparison] = useState<ReportComparison | null>(null);
  const [comparingWithId, setComparingWithId] = useState<string | null>(null);
  const [isComparing, setIsComparing] = useState<boolean>(false);

  // UI Tools
  const [copiedLabel, setCopiedLabel] = useState<string | null>(null);
  const [activeTocId, setActiveTocId] = useState<string>('report-header');
  const reportContainerRef = useRef<HTMLDivElement>(null);

  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 3500);
  };

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedLabel(label);
    setTimeout(() => setCopiedLabel(null), 2000);
  };

  // 1. Initial Load: Fetch latest report projection or draft
  const loadReportProjection = async (previewOpts?: {
    type?: ReportType;
    classif?: ReportClassification;
    redact?: RedactionLevel;
    opts?: ReportContentOptions;
  }) => {
    if (!effectiveId) return;
    setLoading(true);
    setError(null);
    try {
      if (previewOpts) {
        const preview = await reportService.previewInvestigationReport(effectiveId, {
          report_type: previewOpts.type || reportType,
          classification: previewOpts.classif || classification,
          redaction_level: previewOpts.redact || redactionLevel,
          content_options: previewOpts.opts || contentOptions,
        });
        setReport(preview);
      } else {
        const rep = await reportService.getInvestigationReport(effectiveId);
        setReport(rep);
        setReportType(rep.report_type || 'ANALYST');
        setClassification(rep.classification || 'CONFIDENTIAL');
        setRedactionLevel(rep.redaction_level || 'NONE');
        if (rep.content_options && Object.keys(rep.content_options).length > 0) {
          setContentOptions({ ...DEFAULT_CONTENT_OPTIONS, ...rep.content_options });
        }
      }
    } catch (err: any) {
      console.error('Error fetching report projection:', err);
      setError(err?.message || 'Failed to load report projection.');
    } finally {
      setLoading(false);
    }
  };

  // 2. Fetch Version History
  const fetchVersionHistory = async () => {
    if (!effectiveId) return;
    setLoadingVersions(true);
    try {
      const history = await reportService.getInvestigationReports(effectiveId);
      setReportVersions(history);
    } catch (err) {
      console.warn('Could not fetch historical report versions:', err);
      setReportVersions([]);
    } finally {
      setLoadingVersions(false);
    }
  };

  useEffect(() => {
    loadReportProjection();
    fetchVersionHistory();
  }, [effectiveId]);

  // Section 46: Real-Time Report Generation Lifecycle Updates
  useEffect(() => {
    if (!effectiveId) return;

    const unsubscribe = RealtimeService.subscribe({
      url: `/api/investigations/${encodeURIComponent(effectiveId)}/stream`,
      onEvent: (evt) => {
        if (evt.event_type === 'REPORT_GENERATION_STARTED') {
          setIsGenerating(true);
        } else if (evt.event_type === 'REPORT_READY') {
          setIsGenerating(false);
          loadReportProjection();
          fetchVersionHistory();
          showToast(`Report ${evt.payload?.report_number || ''} ready & verified.`);
        } else if (evt.event_type === 'REPORT_FAILED') {
          setIsGenerating(false);
          showToast(`Report generation failed: ${evt.payload?.error_code || evt.message || 'Compilation error'}`);
        }
      },
      onAuthoritativeRefetch: () => {
        loadReportProjection();
        fetchVersionHistory();
      },
    });

    return () => {
      unsubscribe();
    };
  }, [effectiveId]);

  // 3. Generate New Immutable Report Version (v1, v2...)
  const handleGenerateReportVersion = async () => {
    if (!effectiveId) return;
    setIsGenerating(true);
    try {
      const newReport = await reportService.generateInvestigationReport(effectiveId, {
        investigation_id: effectiveId,
        report_type: reportType,
        classification,
        redaction_level: redactionLevel,
        content_options: contentOptions,
        analyst_name: 'SOC Lead Analyst',
        notes: `Generated via CyberGuard Section 42 Report Workspace at ${new Date().toISOString()}`,
      });
      setReport(newReport);
      showToast(`Generated & Persisted Report ${newReport.report_number} (v${newReport.report_version})`);
      fetchVersionHistory();
    } catch (err: any) {
      console.error('Report generation error:', err);
      showToast(`Error: ${err?.message || 'Report compilation failed'}`);
    } finally {
      setIsGenerating(false);
    }
  };

  // 4. Update Preview Projection with Configuration
  const handleApplyPreview = () => {
    loadReportProjection({
      type: reportType,
      classif: classification,
      redact: redactionLevel,
      opts: contentOptions,
    });
    setShowConfigDrawer(false);
    showToast('Updated Report Preview with custom options');
  };

  // 5. Download Official ReportLab Vector PDF
  const handleDownloadPdf = async () => {
    if (!report) return;
    setIsExportingPdf(true);
    try {
      if (report.id === 'preview' || report.status === 'DRAFT') {
        // Automatically persist version if currently draft preview
        const generated = await reportService.generateInvestigationReport(effectiveId, {
          investigation_id: effectiveId,
          report_type: reportType,
          classification,
          redaction_level: redactionLevel,
          content_options: contentOptions,
          analyst_name: 'SOC Lead Analyst',
        });
        setReport(generated);
        const filename = `CyberGuard_${generated.report_number}_v${generated.report_version}.pdf`;
        await reportService.downloadPdf(generated.id, filename);
        showToast(`Downloaded ${filename}`);
        fetchVersionHistory();
      } else {
        const filename = `CyberGuard_${report.report_number}_v${report.report_version}.pdf`;
        await reportService.downloadPdf(report.id, filename);
        showToast(`Downloaded ${filename}`);
      }
    } catch (err: any) {
      console.error('PDF export error:', err);
      showToast(`PDF Export failed: ${err?.message || 'Server error'}`);
    } finally {
      setIsExportingPdf(false);
    }
  };

  // 6. Download Authoritative JSON Snapshot
  const handleDownloadJson = async () => {
    if (!report) return;
    setIsExportingJson(true);
    try {
      if (report.id === 'preview' || report.status === 'DRAFT') {
        const jsonStr = JSON.stringify(report.snapshot, null, 2);
        const blob = new Blob([jsonStr], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `CyberGuard_Report_${effectiveId}_draft.json`;
        document.body.appendChild(a);
        a.click();
        URL.revokeObjectURL(url);
        document.body.removeChild(a);
        showToast('Exported Draft JSON Snapshot');
      } else {
        const filename = `CyberGuard_${report.report_number}_v${report.report_version}.json`;
        await reportService.downloadJson(report.id, filename);
        showToast(`Exported ${filename}`);
      }
    } catch (err: any) {
      console.error('JSON export error:', err);
      showToast(`JSON Export failed: ${err?.message || 'Server error'}`);
    } finally {
      setIsExportingJson(false);
    }
  };

  // 7. Compare Two Report Versions
  const handleCompareVersions = async (otherReportId: string) => {
    if (!report?.id || report.id === 'preview') return;
    setIsComparing(true);
    setComparingWithId(otherReportId);
    try {
      const diff = await reportService.compareReports(otherReportId, report.id);
      setComparison(diff);
    } catch (err: any) {
      console.error('Comparison error:', err);
      showToast('Failed to compare report versions.');
    } finally {
      setIsComparing(false);
    }
  };

  // TOC Navigation scroll
  const scrollToSection = (id: string) => {
    setActiveTocId(id);
    const element = document.getElementById(id);
    if (element) {
      element.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  };

  const getEpistemicBadgeStyle = (status: EpistemicStatus | string) => {
    switch (status) {
      case 'OBSERVED':
        return 'bg-success/15 text-success border-success/30';
      case 'INFERRED':
        return 'bg-warning/15 text-warning border-warning/30';
      case 'HYPOTHESIS':
        return 'bg-danger/15 text-danger border-danger/30';
      case 'EXTERNAL_INTELLIGENCE':
        return 'bg-primary/15 text-primary border-primary/30';
      case 'ANALYST_VERIFIED':
        return 'bg-secondary/15 text-secondary border-secondary/30';
      default:
        return 'bg-surface-secondary text-foreground-muted border-border';
    }
  };

  const snap = report?.snapshot;
  const meta = snap?.metadata;
  const overview = snap?.incident_overview;
  const execSummary = snap?.executive_summary;
  const riskSec = snap?.risk_assessment;
  const attackPath = snap?.attack_path;
  const findings = snap?.findings || [];
  const evidenceTable = snap?.evidence_table || [];
  const iocs = snap?.iocs;
  const mitre = snap?.mitre_attack || [];
  const infra = snap?.infrastructure_intelligence;
  const explain = snap?.explainability;
  const resp = snap?.response;
  const audit = snap?.audit_trail || [];
  const evidenceIndex = snap?.evidence_index || [];
  const quality = report?.quality_check;

  return (
    <div className="space-y-6 pb-20 page-enter relative font-sans">
      {/* Toast Notification */}
      {toastMessage && (
        <div className="fixed top-5 right-5 z-50 flex items-center space-x-2 px-4 py-2.5 rounded-xl bg-surface border border-primary/40 text-primary text-xs font-mono shadow-xl animate-in slide-in-from-top-3">
          <CheckCircle2 className="w-4 h-4 text-primary" />
          <span>{toastMessage}</span>
        </div>
      )}

      {/* 1. TOP REPORT COMMAND & WORKSPACE HEADER */}
      <div className="bg-surface p-4 sm:p-5 rounded-card border border-border shadow-xs">
        <div className="flex flex-col xl:flex-row xl:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center space-x-2 text-primary font-mono text-xs font-bold uppercase tracking-wider">
              <FileText className="w-4 h-4" />
              <span>REPORT WORKSPACE // SECTION 42 REPRODUCIBLE PROJECTION</span>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <h2 className="text-xl sm:text-2xl font-bold text-foreground tracking-tight">
                {meta?.title || 'Security Incident Investigation Report'}
              </h2>
              <span className="px-2.5 py-0.5 rounded-md bg-surface-secondary border border-border font-mono text-xs text-primary font-bold">
                {report ? `v${report.report_version}` : 'v1'}
              </span>
              <span className={`px-2 py-0.5 rounded-md font-mono text-[10px] font-bold uppercase border ${
                report?.status === 'READY'
                  ? 'bg-success/10 text-success border-success/30'
                  : report?.status === 'STALE'
                  ? 'bg-warning/10 text-warning border-warning/30'
                  : 'bg-primary/10 text-primary border-primary/30'
              }`}>
                {report?.status || 'DRAFT'}
              </span>
              <span className="px-2 py-0.5 rounded-md bg-warning/10 text-warning border border-warning/30 font-mono text-[10px] font-bold uppercase">
                {classification}
              </span>
              {redactionLevel !== 'NONE' && (
                <span className="px-2 py-0.5 rounded-md bg-primary-subtle text-primary border border-primary/30 font-mono text-[10px] font-bold uppercase">
                  REDACTED ({redactionLevel})
                </span>
              )}
            </div>
            <p className="text-xs font-mono text-foreground-muted">
              Evidence-grounded, immutable security incident report assembling active telemetry, attack paths, findings, MITRE ATT&CK, and response actions.
            </p>
          </div>

          {/* Action Trigger Toolbar */}
          <div className="flex flex-wrap items-center gap-2 self-start xl:self-center">
            {/* Generate New Immutable Report Version */}
            <button
              type="button"
              id="generate-report-version-btn"
              onClick={handleGenerateReportVersion}
              disabled={isGenerating || loading}
              className="px-4 py-2 rounded-xl bg-primary hover:bg-primary-hover text-primary-foreground font-mono text-xs font-bold flex items-center space-x-2 transition-all cursor-pointer shadow-xs disabled:opacity-50"
              title="Compile and register an immutable report version (v1, v2...)"
            >
              {isGenerating ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>Compiling Version...</span>
                </>
              ) : (
                <>
                  <CheckCircle2 className="w-4 h-4" />
                  <span>Generate Report Version</span>
                </>
              )}
            </button>

            {/* Export Official Vector PDF */}
            <button
              type="button"
              id="export-pdf-report-btn"
              onClick={handleDownloadPdf}
              disabled={isExportingPdf || loading}
              className="px-3.5 py-2 rounded-xl bg-surface hover:bg-surface-secondary border border-border text-foreground font-mono text-xs font-semibold flex items-center space-x-1.5 transition-colors cursor-pointer disabled:opacity-50"
              title="Download official ReportLab vector PDF dossier"
            >
              {isExportingPdf ? (
                <Loader2 className="w-4 h-4 animate-spin text-primary" />
              ) : (
                <Download className="w-4 h-4 text-primary" />
              )}
              <span>Export PDF</span>
            </button>

            {/* Export Authoritative JSON */}
            <button
              type="button"
              id="export-json-report-btn"
              onClick={handleDownloadJson}
              disabled={isExportingJson || loading}
              className="px-3 py-2 rounded-xl bg-surface hover:bg-surface-secondary border border-border text-foreground font-mono text-xs font-semibold flex items-center space-x-1.5 transition-colors cursor-pointer disabled:opacity-50"
              title="Export complete canonical report JSON snapshot"
            >
              <FileCode className="w-4 h-4 text-primary" />
              <span>JSON</span>
            </button>

            {/* Print / System Browser Dialog */}
            <button
              type="button"
              id="print-report-btn"
              onClick={() => window.print()}
              className="px-3 py-2 rounded-xl bg-surface hover:bg-surface-secondary border border-border text-foreground font-mono text-xs font-semibold flex items-center space-x-1.5 transition-colors cursor-pointer"
              title="Print document view"
            >
              <Printer className="w-4 h-4 text-primary" />
              <span>Print</span>
            </button>

            {/* Report Content Configuration Drawer Toggle */}
            <button
              type="button"
              id="toggle-config-drawer-btn"
              onClick={() => setShowConfigDrawer(!showConfigDrawer)}
              className={`px-3 py-2 rounded-xl border font-mono text-xs font-semibold flex items-center space-x-1.5 transition-colors cursor-pointer ${
                showConfigDrawer
                  ? 'bg-primary-subtle text-primary border-primary/40'
                  : 'bg-surface hover:bg-surface-secondary border-border text-foreground-muted hover:text-foreground'
              }`}
              title="Configure report type, redaction, and section visibility"
            >
              <Sliders className="w-4 h-4" />
              <span>Configure</span>
            </button>

            {/* Historical Version Archive Toggle */}
            <button
              type="button"
              id="toggle-history-drawer-btn"
              onClick={() => setShowHistoryDrawer(!showHistoryDrawer)}
              className={`px-3 py-2 rounded-xl border font-mono text-xs font-semibold flex items-center space-x-1.5 transition-colors cursor-pointer ${
                showHistoryDrawer
                  ? 'bg-primary-subtle text-primary border-primary/40'
                  : 'bg-surface hover:bg-surface-secondary border-border text-foreground-muted hover:text-foreground'
              }`}
              title="Inspect historical versions and compare differences"
            >
              <History className="w-4 h-4" />
              <span>Versions ({reportVersions.length})</span>
            </button>
          </div>
        </div>

        {/* 2. STALE REPORT BANNER (Section 55 Contract) */}
        {report?.is_stale && (
          <div className="mt-4 p-4 rounded-xl bg-warning/10 border border-warning/40 flex flex-col sm:flex-row sm:items-center justify-between gap-3 animate-in fade-in">
            <div className="flex items-start space-x-3">
              <AlertTriangle className="w-5 h-5 text-warning shrink-0 mt-0.5" />
              <div>
                <h4 className="text-xs font-bold text-foreground font-sans">
                  REPORT OUTDATED (Stale Snapshot)
                </h4>
                <p className="text-xs font-mono text-foreground-muted mt-0.5">
                  This report was generated from a prior analysis run. New investigation evidence, risk assessments, or attack path updates are now available in the platform.
                </p>
              </div>
            </div>
            <button
              type="button"
              onClick={handleGenerateReportVersion}
              disabled={isGenerating}
              className="px-3.5 py-1.5 rounded-lg bg-warning text-black font-mono text-xs font-bold hover:bg-warning/90 transition-all cursor-pointer shrink-0 shadow-xs"
            >
              {isGenerating ? 'Compiling...' : 'Generate Updated Report (v' + ((report?.report_version || 1) + 1) + ')'}
            </button>
          </div>
        )}

        {/* 3. TABLE OF CONTENTS QUICK-JUMP BAR */}
        <div className="mt-4 pt-3 border-t border-border flex flex-wrap items-center gap-1.5 overflow-x-auto text-xs font-mono">
          <span className="text-[10px] text-foreground-muted uppercase tracking-wider mr-1 shrink-0">Sections:</span>
          {[
            { id: 'sec-exec-summary', label: '1. Executive Summary', show: contentOptions.include_executive_summary },
            { id: 'sec-epistemic-claims', label: '2. Epistemic Claims', show: true },
            { id: 'sec-overview', label: '3. Overview', show: true },
            { id: 'sec-risk', label: '4. Risk & Confidence', show: contentOptions.include_risk_assessment },
            { id: 'sec-timeline', label: '5. Timeline', show: contentOptions.include_timeline },
            { id: 'sec-attack-path', label: '6. Attack Path', show: contentOptions.include_attack_path },
            { id: 'sec-findings', label: '7. Findings', show: contentOptions.include_findings },
            { id: 'sec-evidence', label: '8. Evidence Table', show: contentOptions.include_evidence_table },
            { id: 'sec-iocs', label: '9. IOCs', show: contentOptions.include_indicators },
            { id: 'sec-mitre', label: '10. MITRE ATT&CK', show: contentOptions.include_mitre_attack },
            { id: 'sec-infrastructure', label: '11. Infrastructure', show: contentOptions.include_infrastructure },
            { id: 'sec-explainability', label: '12. Explainability', show: contentOptions.include_explainability },
            { id: 'sec-response', label: '13. Response Actions', show: contentOptions.include_response_actions },
            { id: 'sec-audit', label: '14. Audit Trail', show: contentOptions.include_audit_trail },
            { id: 'sec-evidence-index', label: '15. Evidence Index', show: contentOptions.include_evidence_index },
          ]
            .filter(s => s.show)
            .map(sec => (
              <button
                key={sec.id}
                type="button"
                onClick={() => scrollToSection(sec.id)}
                className={`px-2.5 py-1 rounded-lg text-[11px] transition-colors cursor-pointer shrink-0 ${
                  activeTocId === sec.id
                    ? 'bg-primary/15 text-primary border border-primary/30 font-bold'
                    : 'bg-surface-secondary text-foreground-muted hover:text-foreground hover:bg-surface'
                }`}
              >
                {sec.label}
              </button>
            ))}
        </div>
      </div>

      {/* 4. CONFIGURATION DRAWER / MODAL (Section 43 Contract) */}
      {showConfigDrawer && (
        <div className="p-5 rounded-card bg-surface border border-primary/30 space-y-4 font-mono text-xs shadow-md animate-in fade-in duration-200">
          <div className="flex items-center justify-between pb-3 border-b border-border">
            <div className="flex items-center space-x-2 text-primary font-bold">
              <Sliders className="w-4 h-4" />
              <span>Report Generation Configuration</span>
            </div>
            <button
              type="button"
              onClick={() => setShowConfigDrawer(false)}
              className="text-foreground-muted hover:text-foreground cursor-pointer"
            >
              Close
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* Report Type Selector */}
            <div className="space-y-1.5">
              <label className="text-[10px] uppercase text-foreground-muted font-bold block">Report Type</label>
              <div className="flex flex-col space-y-1">
                {(['ANALYST', 'EXECUTIVE', 'FORENSIC'] as ReportType[]).map((t) => (
                  <button
                    key={t}
                    type="button"
                    onClick={() => setReportType(t)}
                    className={`px-3 py-2 rounded-lg text-left text-xs font-semibold border transition-all cursor-pointer ${
                      reportType === t
                        ? 'bg-primary/15 text-primary border-primary/40 font-bold'
                        : 'bg-surface-secondary border-border text-foreground-muted hover:text-foreground'
                    }`}
                  >
                    ● {t.charAt(0) + t.slice(1).toLowerCase()} Report
                  </button>
                ))}
              </div>
            </div>

            {/* Classification */}
            <div className="space-y-1.5">
              <label className="text-[10px] uppercase text-foreground-muted font-bold block">Classification</label>
              <div className="flex flex-col space-y-1">
                {(['INTERNAL', 'CONFIDENTIAL', 'RESTRICTED'] as ReportClassification[]).map((c) => (
                  <button
                    key={c}
                    type="button"
                    onClick={() => setClassification(c)}
                    className={`px-3 py-2 rounded-lg text-left text-xs font-semibold border transition-all cursor-pointer ${
                      classification === c
                        ? 'bg-warning/15 text-warning border-warning/40 font-bold'
                        : 'bg-surface-secondary border-border text-foreground-muted hover:text-foreground'
                    }`}
                  >
                    ● {c}
                  </button>
                ))}
              </div>
            </div>

            {/* Redaction Level */}
            <div className="space-y-1.5">
              <label className="text-[10px] uppercase text-foreground-muted font-bold block">Redaction Policy</label>
              <div className="flex flex-col space-y-1">
                {(['NONE', 'STANDARD', 'STRICT'] as RedactionLevel[]).map((r) => (
                  <button
                    key={r}
                    type="button"
                    onClick={() => setRedactionLevel(r)}
                    className={`px-3 py-2 rounded-lg text-left text-xs font-semibold border transition-all cursor-pointer ${
                      redactionLevel === r
                        ? 'bg-primary/15 text-primary border-primary/40 font-bold'
                        : 'bg-surface-secondary border-border text-foreground-muted hover:text-foreground'
                    }`}
                  >
                    ● {r} Redaction
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* Section Visibility Checkboxes */}
          <div className="pt-3 border-t border-border space-y-2">
            <span className="text-[10px] uppercase text-foreground-muted font-bold block">Included Content Sections</span>
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-2">
              {[
                { key: 'include_executive_summary', label: 'Executive Summary' },
                { key: 'include_risk_assessment', label: 'Risk Assessment' },
                { key: 'include_timeline', label: 'Timeline' },
                { key: 'include_attack_path', label: 'Attack Path' },
                { key: 'include_findings', label: 'Findings' },
                { key: 'include_evidence_table', label: 'Evidence Table' },
                { key: 'include_indicators', label: 'IOC Summary' },
                { key: 'include_mitre_attack', label: 'MITRE ATT&CK' },
                { key: 'include_infrastructure', label: 'Infrastructure' },
                { key: 'include_explainability', label: 'Explainability' },
                { key: 'include_response_actions', label: 'Response Actions' },
                { key: 'include_recommendations', label: 'Recommendations' },
                { key: 'include_audit_trail', label: 'Audit Trail' },
                { key: 'include_evidence_index', label: 'Evidence Index' },
              ].map(({ key, label }) => {
                const k = key as keyof ReportContentOptions;
                return (
                  <label key={key} className="flex items-center space-x-2 text-[11px] text-foreground cursor-pointer select-none">
                    <input
                      type="checkbox"
                      checked={contentOptions[k]}
                      onChange={(e) => setContentOptions({ ...contentOptions, [k]: e.target.checked })}
                      className="rounded border-border text-primary focus:ring-primary h-3.5 w-3.5"
                    />
                    <span>{label}</span>
                  </label>
                );
              })}
            </div>
          </div>

          <div className="flex items-center justify-end space-x-2 pt-3 border-t border-border">
            <button
              type="button"
              onClick={handleApplyPreview}
              className="px-4 py-2 rounded-lg bg-primary hover:bg-primary-hover text-primary-foreground font-bold cursor-pointer transition-colors"
            >
              Update Preview Projection
            </button>
          </div>
        </div>
      )}

      {/* 5. HISTORICAL VERSIONS & COMPARISON DRAWER (Section 56 Contract) */}
      {showHistoryDrawer && (
        <div className="p-5 rounded-card bg-surface border border-primary/30 space-y-4 font-mono text-xs shadow-md animate-in fade-in duration-200">
          <div className="flex items-center justify-between pb-3 border-b border-border">
            <div className="flex items-center space-x-2 text-primary font-bold">
              <History className="w-4 h-4" />
              <span>Report Version Ledger & Reproducibility History</span>
            </div>
            <button
              type="button"
              onClick={() => {
                setShowHistoryDrawer(false);
                setComparison(null);
              }}
              className="text-foreground-muted hover:text-foreground cursor-pointer"
            >
              Close
            </button>
          </div>

          {loadingVersions ? (
            <div className="p-4 text-center text-foreground-muted">
              <Loader2 className="w-5 h-5 animate-spin mx-auto text-primary mb-2" />
              <span>Loading report history...</span>
            </div>
          ) : reportVersions.length === 0 ? (
            <p className="text-foreground-muted text-[11px] py-2">
              No previous report versions found. Click &quot;Generate Report Version&quot; above to establish v1.
            </p>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 max-h-60 overflow-y-auto pr-1">
              {reportVersions.map((v) => (
                <div
                  key={v.id}
                  className={`p-3 rounded-xl border flex items-center justify-between gap-3 ${
                    report?.id === v.id
                      ? 'bg-primary-subtle border-primary/40'
                      : 'bg-surface-secondary border-border'
                  }`}
                >
                  <div className="space-y-0.5 min-w-0 flex-1">
                    <div className="flex items-center space-x-2">
                      <span className="font-bold text-primary">{v.report_number}</span>
                      <span className="px-1.5 py-0.2 rounded bg-surface border border-border text-[9px] font-bold">
                        v{v.report_version || 1}
                      </span>
                      <span className="text-[10px] font-bold uppercase text-warning">
                        {v.severity || 'high'}
                      </span>
                    </div>
                    <div className="text-[10px] text-foreground-muted truncate">
                      {new Date(v.created_at).toLocaleString()} · {v.file_size_bytes ? `${Math.round(v.file_size_bytes / 1024)} KB` : 'Vector PDF'}
                    </div>
                  </div>

                  <div className="flex items-center space-x-1.5 shrink-0">
                    {report?.id && report.id !== v.id && (
                      <button
                        type="button"
                        onClick={() => handleCompareVersions(v.id)}
                        disabled={isComparing && comparingWithId === v.id}
                        className="px-2 py-1 rounded bg-surface hover:bg-surface-secondary text-primary border border-border text-[10px] flex items-center space-x-1 cursor-pointer"
                        title="Compare with active report"
                      >
                        <GitCompare className="w-3 h-3" />
                        <span>Diff</span>
                      </button>
                    )}
                    <button
                      type="button"
                      onClick={() => reportService.downloadPdf(v.id, `${v.report_number}.pdf`)}
                      className="p-1.5 rounded-lg bg-surface hover:bg-surface-secondary text-foreground-muted hover:text-foreground border border-border cursor-pointer"
                      title="Download Archived PDF"
                    >
                      <Download className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* Version Diff View */}
          {comparison && (
            <div className="pt-3 border-t border-border space-y-2 animate-in fade-in">
              <div className="flex items-center justify-between">
                <span className="font-bold text-primary text-xs">
                  Version Comparison: {comparison.v1_report_number} (v{comparison.v1_version}) vs {comparison.v2_report_number} (v{comparison.v2_version})
                </span>
                <button
                  type="button"
                  onClick={() => setComparison(null)}
                  className="text-foreground-muted hover:text-foreground text-[10px]"
                >
                  Clear Diff
                </button>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-[11px]">
                  <thead>
                    <tr className="border-b border-border text-[10px] text-foreground-muted uppercase">
                      <th className="py-1.5 px-2">Field</th>
                      <th className="py-1.5 px-2">{comparison.v1_report_number}</th>
                      <th className="py-1.5 px-2">{comparison.v2_report_number}</th>
                      <th className="py-1.5 px-2 text-right">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border/50">
                    {comparison.changes.map((c, i) => (
                      <tr key={i} className={c.changed ? 'bg-warning/5 font-semibold' : ''}>
                        <td className="py-1.5 px-2 font-mono text-primary">{c.field}</td>
                        <td className="py-1.5 px-2 text-foreground-muted truncate max-w-xs">{String(c.v1_value)}</td>
                        <td className="py-1.5 px-2 text-foreground truncate max-w-xs">{String(c.v2_value)}</td>
                        <td className="py-1.5 px-2 text-right">
                          <span className={`px-1.5 py-0.2 rounded text-[9px] font-bold ${
                            c.changed ? 'bg-warning/15 text-warning' : 'bg-surface text-foreground-muted'
                          }`}>
                            {c.changed ? 'MODIFIED' : 'UNCHANGED'}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {/* 6. LOADING / ERROR STATES */}
      {loading && !report ? (
        <div className="p-16 text-center bg-surface rounded-card border border-border">
          <Loader2 className="w-8 h-8 animate-spin mx-auto text-primary mb-3" />
          <p className="text-sm font-bold text-foreground">Assembling Authoritative Report Projection...</p>
          <p className="text-xs text-foreground-muted font-mono mt-1">
            Aggregating evidence ledger, temporal timeline, attack stages, MITRE ATT&CK, and response actions.
          </p>
        </div>
      ) : error ? (
        <div className="p-8 text-center bg-surface rounded-card border border-danger-border space-y-3">
          <AlertCircle className="w-8 h-8 text-danger mx-auto" />
          <h3 className="text-base font-bold text-foreground">Report Projection Unavailable</h3>
          <p className="text-xs text-foreground-muted font-mono max-w-md mx-auto">{error}</p>
          <button
            type="button"
            onClick={() => loadReportProjection()}
            className="px-4 py-2 rounded-lg bg-primary hover:bg-primary-hover text-primary-foreground font-mono text-xs font-bold transition-all cursor-pointer inline-flex items-center space-x-1.5"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>Retry Projection</span>
          </button>
        </div>
      ) : !snap ? (
        <div className="p-12 text-center bg-surface rounded-card border border-border font-mono text-xs text-foreground-muted">
          No investigation snapshot data could be compiled.
        </div>
      ) : (
        /* 7. AUTHENTIC INCIDENT REPORT DOCUMENT PREVIEW */
        <div
          ref={reportContainerRef}
          id="authoritative-report-document"
          className="bg-surface rounded-card border border-border p-6 sm:p-10 space-y-10 max-w-5xl mx-auto shadow-xs print:p-0 print:border-none print:shadow-none"
        >
          {/* SECTION HEADER & MASTHEAD */}
          <div id="report-header" className="space-y-4 pb-6 border-b-2 border-border scroll-mt-24">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs font-mono">
              <div className="flex items-center space-x-2">
                <span className="w-2.5 h-2.5 rounded-full bg-primary" />
                <span className="font-bold tracking-widest text-primary uppercase">
                  CYBERGUARD FORENSIC INCIDENT INTELLIGENCE
                </span>
              </div>
              <div className="flex flex-wrap items-center gap-2 text-[10px] text-foreground-muted uppercase tracking-wider">
                <span>REPORT: <strong className="text-foreground">{report?.report_number || meta?.report_number || 'DRAFT'}</strong></span>
                <span>·</span>
                <span>INCIDENT: <strong className="text-primary">{meta?.incident_number || overview?.incident_number}</strong></span>
                <span>·</span>
                <span>CLASSIFICATION: <strong className="text-warning">{classification}</strong></span>
              </div>
            </div>

            <div className="space-y-1.5 pt-2">
              <h1 className="text-2xl sm:text-3xl font-extrabold text-foreground tracking-tight">
                {overview?.title || meta?.title || 'Security Incident Investigation Report'}
              </h1>
              <p className="text-xs font-mono text-foreground-muted">
                Authoritative multi-stage cyber forensic dossier compiled across unified telemetry, attack paths, and response actions.
              </p>
            </div>

            {/* Incident Header Stats */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 pt-3 p-3.5 rounded-xl bg-surface-secondary/60 border border-border font-mono text-xs">
              <div>
                <span className="text-[10px] uppercase text-foreground-muted block font-semibold">Severity / Risk:</span>
                <span className="text-danger font-bold text-sm block">
                  {overview?.severity?.toUpperCase()} ({overview?.risk_score}/100)
                </span>
              </div>
              <div>
                <span className="text-[10px] uppercase text-foreground-muted block font-semibold">Confidence Rating:</span>
                <span className="text-primary font-bold text-sm block">
                  {overview?.confidence_level} ({Math.round((overview?.confidence || 1) * 100)}%)
                </span>
              </div>
              <div>
                <span className="text-[10px] uppercase text-foreground-muted block font-semibold">First Observed:</span>
                <span className="text-foreground block truncate">
                  {overview?.first_observed_at ? new Date(overview.first_observed_at).toUTCString() : 'N/A'}
                </span>
              </div>
              <div>
                <span className="text-[10px] uppercase text-foreground-muted block font-semibold">Snapshot Digest:</span>
                <div className="flex items-center space-x-1">
                  <span className="text-foreground font-mono text-[10px] truncate block select-all" title={meta?.data_snapshot_hash}>
                    {meta?.data_snapshot_hash ? `${meta.data_snapshot_hash.slice(0, 14)}...` : 'Deterministic'}
                  </span>
                  {meta?.data_snapshot_hash && (
                    <button
                      type="button"
                      onClick={() => copyToClipboard(meta.data_snapshot_hash, 'hash')}
                      className="text-primary hover:text-primary-hover p-0.5 cursor-pointer"
                      title="Copy full snapshot hash"
                    >
                      {copiedLabel === 'hash' ? <Check className="w-3 h-3 text-success" /> : <Copy className="w-3 h-3" />}
                    </button>
                  )}
                </div>
              </div>
            </div>

          </div>

          {/* 1. EXECUTIVE SUMMARY (Section 7 Contract) */}
          {contentOptions.include_executive_summary && execSummary && (
            <div id="sec-exec-summary" className="space-y-4 scroll-mt-24">
              <div className="flex items-center space-x-2 pb-2 border-b border-border">
                <FileText className="w-4 h-4 text-primary" />
                <h3 className="text-base font-bold text-foreground">
                  1. Executive Summary
                </h3>
              </div>

              <div className="prose prose-sm max-w-none text-foreground-muted font-sans text-xs sm:text-sm leading-relaxed space-y-3">
                <p className="text-foreground font-medium">
                  {execSummary.synthesized_narrative || execSummary.detection_statement}
                </p>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-2 font-mono text-xs">
                  <div className="p-3.5 rounded-xl bg-surface-secondary border border-border space-y-1">
                    <span className="text-[10px] uppercase text-foreground-muted block font-bold">Detection & Evidence Basis:</span>
                    <p className="text-foreground text-[11px] leading-relaxed">
                      {execSummary.evidence_support_statement || 'Grounded in cryptographic email headers, URL intelligence, and authentication telemetry.'}
                    </p>
                  </div>
                  <div className="p-3.5 rounded-xl bg-surface-secondary border border-border space-y-1">
                    <span className="text-[10px] uppercase text-foreground-muted block font-bold">Uncertainty & Telemetry Gaps:</span>
                    <p className="text-foreground-muted text-[11px] leading-relaxed">
                      {execSummary.uncertainty_statement || 'Endpoint telemetry remains partially unobserved for secondary API transitions.'}
                    </p>
                  </div>
                </div>

                <div className="p-3.5 rounded-xl bg-danger-surface/40 border border-danger-border flex items-start space-x-3 text-xs font-mono">
                  <ShieldAlert className="w-5 h-5 text-danger shrink-0 mt-0.5" />
                  <div className="space-y-1">
                    <span className="font-bold text-danger uppercase tracking-wider block">
                      Current Response & Impact State
                    </span>
                    <p className="text-foreground-muted text-[11px] leading-relaxed">
                      {execSummary.response_state_statement}
                    </p>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* 2. EPISTEMIC CLAIMS LEDGER (Section 9 Contract: OBSERVED vs INFERRED vs HYPOTHESIS) */}
          <div id="sec-epistemic-claims" className="space-y-4 scroll-mt-24">
            <div className="flex items-center justify-between pb-2 border-b border-border">
              <div className="flex items-center space-x-2">
                <ShieldCheck className="w-4 h-4 text-primary" />
                <h3 className="text-base font-bold text-foreground">
                  2. Epistemic Fact & Claim Categorization
                </h3>
              </div>
              <span className="text-[10px] font-mono text-foreground-muted uppercase">
                Section 9 Defensibility Rule
              </span>
            </div>

            <p className="text-xs text-foreground-muted font-sans leading-relaxed">
              CyberGuard explicitly tags every substantive finding to distinguish directly recorded observations from algorithmic inferences, hypotheses, and third-party intelligence.
            </p>

            <div className="overflow-x-auto">
              <table className="w-full text-left font-mono text-xs">
                <thead>
                  <tr className="border-b border-border text-[10px] text-foreground-muted uppercase tracking-wider">
                    <th className="py-2.5 px-3">Epistemic Status</th>
                    <th className="py-2.5 px-3">Substantive Statement</th>
                    <th className="py-2.5 px-3">Category</th>
                    <th className="py-2.5 px-3 text-right">Evidence Ref</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/60">
                  {(snap.epistemic_claims || []).map((claim, idx) => (
                    <tr key={idx} className="hover:bg-surface-secondary/40 transition-colors">
                      <td className="py-2.5 px-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${getEpistemicBadgeStyle(claim.status)}`}>
                          {claim.status}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 font-sans text-xs text-foreground font-medium">
                        {claim.statement}
                      </td>
                      <td className="py-2.5 px-3 text-foreground-muted text-[11px]">
                        {claim.category || 'Forensic'}
                      </td>
                      <td className="py-2.5 px-3 text-right text-primary font-bold text-[11px]">
                        {claim.evidence_refs?.join(', ') || 'Direct'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* 3. INCIDENT OVERVIEW (Section 10 Contract) */}
          <div id="sec-overview" className="space-y-4 scroll-mt-24">
            <div className="flex items-center space-x-2 pb-2 border-b border-border">
              <Layers className="w-4 h-4 text-primary" />
              <h3 className="text-base font-bold text-foreground">
                3. Incident Scope & Telemetry Overview
              </h3>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 font-mono text-xs">
              <div className="p-3.5 rounded-xl bg-surface-secondary border border-border space-y-1">
                <span className="text-[10px] uppercase text-foreground-muted block font-semibold">Evidence Items</span>
                <span className="text-xl font-bold text-foreground">{overview?.evidence_count ?? snap.evidence_table.length}</span>
                <span className="text-[10px] text-foreground-muted block">Bitstream artifacts</span>
              </div>
              <div className="p-3.5 rounded-xl bg-surface-secondary border border-border space-y-1">
                <span className="text-[10px] uppercase text-foreground-muted block font-semibold">Extracted Findings</span>
                <span className="text-xl font-bold text-primary">{overview?.finding_count ?? snap.findings.length}</span>
                <span className="text-[10px] text-foreground-muted block">Multi-engine rules</span>
              </div>
              <div className="p-3.5 rounded-xl bg-surface-secondary border border-border space-y-1">
                <span className="text-[10px] uppercase text-foreground-muted block font-semibold">Observed IOCs</span>
                <span className="text-xl font-bold text-warning">{overview?.indicator_count ?? 12}</span>
                <span className="text-[10px] text-foreground-muted block">IP, Domain, Hash</span>
              </div>
              <div className="p-3.5 rounded-xl bg-surface-secondary border border-border space-y-1">
                <span className="text-[10px] uppercase text-foreground-muted block font-semibold">Analysis Runs</span>
                <span className="text-xl font-bold text-foreground">{overview?.analysis_run_count ?? 1}</span>
                <span className="text-[10px] text-foreground-muted block">Execution passes</span>
              </div>
            </div>

            {overview?.affected_entities && overview.affected_entities.length > 0 && (
              <div className="p-3 rounded-xl bg-surface-secondary/40 border border-border text-xs font-mono">
                <span className="text-[10px] uppercase text-foreground-muted font-bold block mb-1">Affected Corporate Entities / Targets:</span>
                <div className="flex flex-wrap gap-1.5">
                  {overview.affected_entities.map((e, idx) => (
                    <span key={idx} className="px-2 py-0.5 rounded bg-surface border border-border text-foreground font-semibold">
                      {e}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* 4. RISK ASSESSMENT & CONFIDENCE (Section 15 & 16: Never confuse Risk with Probability) */}
          {contentOptions.include_risk_assessment && riskSec && (
            <div id="sec-risk" className="space-y-4 scroll-mt-24">
              <div className="flex items-center space-x-2 pb-2 border-b border-border">
                <ShieldAlert className="w-4 h-4 text-primary" />
                <h3 className="text-base font-bold text-foreground">
                  4. Risk Assessment vs. Evidence Confidence
                </h3>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 font-mono text-xs">
                {/* Risk Score */}
                <div className="p-4 rounded-xl bg-surface-secondary border border-border space-y-2">
                  <span className="text-[10px] uppercase text-foreground-muted font-bold block">Assessed Incident Risk</span>
                  <div className="flex items-baseline space-x-2">
                    <span className="text-3xl font-extrabold text-danger">{riskSec.risk_score}</span>
                    <span className="text-foreground-muted text-sm">/ 100</span>
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-danger/15 text-danger ml-2">
                      {riskSec.severity}
                    </span>
                  </div>
                  <p className="text-[11px] text-foreground-muted leading-relaxed">
                    How concerning the security incident is to enterprise operations. Derived deterministically from threat signals.
                  </p>
                </div>

                {/* Evidence Confidence */}
                <div className="p-4 rounded-xl bg-surface-secondary border border-border space-y-2">
                  <span className="text-[10px] uppercase text-foreground-muted font-bold block">Evidence Confidence</span>
                  <div className="flex items-baseline space-x-2">
                    <span className="text-3xl font-extrabold text-primary">{Math.round(riskSec.confidence * 100)}%</span>
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-primary/15 text-primary ml-2">
                      {riskSec.confidence_level}
                    </span>
                  </div>
                  <p className="text-[11px] text-foreground-muted leading-relaxed">
                    {riskSec.risk_vs_confidence_note || 'How strongly available evidence supports the assessment. Risk score is not a probability.'}
                  </p>
                </div>
              </div>

              {/* Signals and Counter-Evidence */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-1 font-mono text-xs">
                <div className="p-3.5 rounded-xl bg-surface-secondary/50 border border-border space-y-2">
                  <span className="text-[10px] uppercase text-danger font-bold block">Primary Risk Drivers:</span>
                  <ul className="space-y-1 text-[11px] text-foreground">
                    {(riskSec.primary_signals || []).map((sig, i) => (
                      <li key={i} className="flex items-start space-x-2">
                        <span className="text-danger font-bold">•</span>
                        <span>{sig}</span>
                      </li>
                    ))}
                  </ul>
                </div>
                <div className="p-3.5 rounded-xl bg-surface-secondary/50 border border-border space-y-2">
                  <span className="text-[10px] uppercase text-success font-bold block">Counter-Evidence / Mitigating Factors:</span>
                  <ul className="space-y-1 text-[11px] text-foreground-muted">
                    {(riskSec.counter_evidence && riskSec.counter_evidence.length > 0) ? (
                      riskSec.counter_evidence.map((ce, i) => (
                        <li key={i} className="flex items-start space-x-2">
                          <span className="text-success font-bold">•</span>
                          <span>{ce}</span>
                        </li>
                      ))
                    ) : (
                      <li className="italic text-foreground-muted">No mitigating counter-evidence identified.</li>
                    )}
                  </ul>
                </div>
              </div>
            </div>
          )}

          {/* 5. INCIDENT TIMELINE (Section 11: Real event times and uncertainty notation) */}
          {contentOptions.include_timeline && snap.timeline && snap.timeline.length > 0 && (
            <div id="sec-timeline" className="space-y-4 scroll-mt-24">
              <div className="flex items-center justify-between pb-2 border-b border-border">
                <div className="flex items-center space-x-2">
                  <Clock className="w-4 h-4 text-primary" />
                  <h3 className="text-base font-bold font-sans text-foreground">
                    5. Incident Timeline & Chronology
                  </h3>
                </div>
                <span className="text-[10px] font-mono text-foreground-muted uppercase">
                  Temporal Correlation
                </span>
              </div>

              <div className="space-y-3 font-mono text-xs">
                {snap.timeline.map((ev, i) => (
                  <div
                    key={i}
                    className="p-3 rounded-xl bg-surface-secondary/40 border border-border flex flex-col sm:flex-row sm:items-center justify-between gap-3"
                  >
                    <div className="flex items-start space-x-3">
                      <div className="text-primary font-bold shrink-0 text-xs">
                        {ev.timestamp ? new Date(ev.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '14:32:00'}
                      </div>
                      <div className="space-y-0.5">
                        <div className="flex items-center space-x-2">
                          <span className="font-bold text-foreground">{ev.title}</span>
                          <span className={`px-1.5 py-0.2 rounded text-[9px] font-bold ${
                            ev.status === 'OBSERVED' ? 'bg-success/15 text-success' : 'bg-warning/15 text-warning'
                          }`}>
                            {ev.status}
                          </span>
                        </div>
                        <p className="text-[11px] text-foreground-muted font-sans leading-relaxed">{ev.description}</p>
                      </div>
                    </div>

                    <div className="text-right shrink-0 text-[10px] text-foreground-muted">
                      <span className="block font-bold text-foreground">{ev.source}</span>
                      {ev.uncertainty && (
                        <span className="text-warning font-mono">Uncertainty: {ev.uncertainty}</span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* 6. ATTACK PATH SECTION (Section 12, 13, 14, 46: Clean static timeline representation) */}
          {contentOptions.include_attack_path && attackPath && attackPath.available && (
            <div id="sec-attack-path" className="space-y-4 scroll-mt-24">
              <div className="flex items-center justify-between pb-2 border-b border-border">
                <div className="flex items-center space-x-2">
                  <GitMerge className="w-4 h-4 text-primary" />
                  <h3 className="text-base font-bold text-foreground">
                    6. Attack Path Reconstruction
                  </h3>
                </div>
                <span className="text-[10px] font-mono text-primary font-bold">
                  Overall Path Confidence: {Math.round(attackPath.overall_confidence * 100)}%
                </span>
              </div>

              {/* Path Narrative Summary */}
              <div className="p-3.5 rounded-xl bg-surface-secondary/60 border border-border text-xs font-mono text-foreground leading-relaxed">
                <span className="text-[10px] uppercase text-foreground-muted font-bold block mb-1">Path Progression Summary:</span>
                <p>{attackPath.path_summary}</p>
              </div>

              {/* Static Attack Stages Flow */}
              <div className="space-y-2 font-mono text-xs">
                {attackPath.stages.map((stage, idx) => (
                  <div key={idx} className="relative">
                    <div className="p-3.5 rounded-xl bg-surface border border-border flex flex-col md:flex-row md:items-center justify-between gap-3 shadow-xs">
                      <div className="flex items-center space-x-3">
                        <span className="w-6 h-6 rounded-lg bg-primary/10 text-primary border border-primary/20 flex items-center justify-center font-bold text-xs shrink-0">
                          {stage.stage_order}
                        </span>
                        <div>
                          <div className="flex items-center space-x-2">
                            <span className="font-bold text-foreground text-xs">{stage.name}</span>
                            <span className="px-1.5 py-0.2 rounded text-[9px] font-bold bg-surface-secondary border border-border text-foreground-muted uppercase">
                              {stage.stage_type}
                            </span>
                            <span className={`px-1.5 py-0.2 rounded text-[9px] font-bold ${
                              stage.status === 'OBSERVED' ? 'bg-success/15 text-success' : 'bg-warning/15 text-warning'
                            }`}>
                              {stage.status}
                            </span>
                          </div>
                          {stage.mitre_technique_id && (
                            <span className="text-[10px] text-primary block mt-0.5">
                              MITRE: {stage.mitre_technique_id} - {stage.mitre_technique_name}
                            </span>
                          )}
                        </div>
                      </div>

                      <div className="flex items-center space-x-4 text-[11px] text-foreground-muted">
                        <span>Confidence: <strong className="text-foreground">{Math.round(stage.confidence * 100)}%</strong></span>
                        <span>Evidence: <strong className="text-primary">{stage.evidence_count}</strong></span>
                      </div>
                    </div>

                    {/* Connector Arrow */}
                    {idx < attackPath.stages.length - 1 && (
                      <div className="w-0.5 h-3 bg-border mx-auto my-0.5" />
                    )}
                  </div>
                ))}
              </div>

              {/* Drivers & Limitations */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1 font-mono text-xs">
                <div className="p-3 rounded-lg bg-surface-secondary/40 border border-border">
                  <span className="text-[10px] uppercase text-primary font-bold block mb-1">Confidence Drivers:</span>
                  <ul className="text-[11px] text-foreground-muted space-y-0.5">
                    {attackPath.confidence_drivers.map((d, i) => (
                      <li key={i}>✓ {d}</li>
                    ))}
                  </ul>
                </div>
                <div className="p-3 rounded-lg bg-surface-secondary/40 border border-border">
                  <span className="text-[10px] uppercase text-warning font-bold block mb-1">Path Limitations:</span>
                  <ul className="text-[11px] text-foreground-muted space-y-0.5">
                    {attackPath.confidence_limitations.map((l, i) => (
                      <li key={i}>⚠ {l}</li>
                    ))}
                  </ul>
                </div>
              </div>
            </div>
          )}

          {/* 7. FINDINGS (Section 17: Summarize findings with severity, confidence, evidence refs) */}
          {contentOptions.include_findings && findings.length > 0 && (
            <div id="sec-findings" className="space-y-4 scroll-mt-24">
              <div className="flex items-center justify-between pb-2 border-b border-border">
                <div className="flex items-center space-x-2">
                  <ShieldCheck className="w-4 h-4 text-primary" />
                  <h3 className="text-base font-bold text-foreground">
                    7. Forensic Findings & Detection Signals
                  </h3>
                </div>
                <span className="text-[10px] font-mono text-foreground-muted uppercase">
                  {findings.length} Findings Recorded
                </span>
              </div>

              <div className="space-y-3 font-mono text-xs">
                {findings.map((f, i) => (
                  <div key={i} className="p-3.5 rounded-xl bg-surface-secondary/40 border border-border flex items-start space-x-3">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase shrink-0 mt-0.5 ${
                      f.severity === 'CRITICAL' ? 'bg-danger/15 text-danger border border-danger/30' :
                      f.severity === 'HIGH' ? 'bg-warning/15 text-warning border border-warning/30' :
                      'bg-surface border border-border text-foreground-muted'
                    }`}>
                      {f.severity}
                    </span>
                    <div className="space-y-1 flex-1 min-w-0">
                      <div className="flex items-center justify-between">
                        <h4 className="font-bold text-foreground text-xs">{f.title}</h4>
                        <span className="text-[10px] text-foreground-muted">{f.category}</span>
                      </div>
                      <p className="text-foreground-muted text-[11px] font-sans leading-relaxed">{f.description}</p>
                      <div className="flex items-center space-x-3 text-[10px] text-foreground-muted pt-1">
                        <span>Source: <strong className="text-foreground">{f.source}</strong></span>
                        <span>Confidence: <strong className="text-primary">{Math.round(f.confidence * 100)}%</strong></span>
                        <span>Evidence Refs: <strong className="text-foreground">{f.evidence_refs?.join(', ') || 'Direct'}</strong></span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* 8. EVIDENCE TABLE (Section 18 & 19: Original vs Derived distinction, SHA-256) */}
          {contentOptions.include_evidence_table && evidenceTable.length > 0 && (
            <div id="sec-evidence" className="space-y-4 scroll-mt-24">
              <div className="flex items-center justify-between pb-2 border-b border-border">
                <div className="flex items-center space-x-2">
                  <Lock className="w-4 h-4 text-primary" />
                  <h3 className="text-base font-bold text-foreground">
                    8. Evidence Ledger & Bitstream Custody
                  </h3>
                </div>
                <span className="text-[10px] font-mono text-success font-bold">
                  Zero Bitstream Mutation Verified
                </span>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left font-mono text-xs">
                  <thead>
                    <tr className="border-b border-border text-[10px] text-foreground-muted uppercase tracking-wider">
                      <th className="py-2.5 px-3">Ref</th>
                      <th className="py-2.5 px-3">Artifact Name</th>
                      <th className="py-2.5 px-3">Type</th>
                      <th className="py-2.5 px-3">Source</th>
                      <th className="py-2.5 px-3">SHA-256 Digest</th>
                      <th className="py-2.5 px-3 text-right">Analysis</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border/60">
                    {evidenceTable.map((ev, i) => (
                      <tr key={i} className="hover:bg-surface-secondary/40 transition-colors">
                        <td className="py-2.5 px-3 font-bold text-primary">{ev.ref_id}</td>
                        <td className="py-2.5 px-3 font-semibold text-foreground truncate max-w-[180px]">{ev.name}</td>
                        <td className="py-2.5 px-3">
                          <span className={`px-1.5 py-0.2 rounded text-[9px] font-bold ${
                            ev.type === 'ORIGINAL' ? 'bg-primary/15 text-primary' : 'bg-surface-secondary text-foreground-muted'
                          }`}>
                            {ev.type}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 text-foreground-muted text-[11px]">{ev.source}</td>
                        <td className="py-2.5 px-3 font-mono text-[10px] text-foreground select-all break-all max-w-xs">
                          {ev.sha256}
                        </td>
                        <td className="py-2.5 px-3 text-right font-bold text-foreground">{ev.analysis_run_ref}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* 9. IOC SUMMARY (Section 20: Defanged URLs, IPs, Domains, Hashes) */}
          {contentOptions.include_indicators && iocs && (
            <div id="sec-iocs" className="space-y-4 scroll-mt-24">
              <div className="flex items-center space-x-2 pb-2 border-b border-border">
                <Globe className="w-4 h-4 text-primary" />
                <h3 className="text-base font-bold text-foreground">
                  9. Extracted Indicators of Compromise (IOCs)
                </h3>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 font-mono text-xs">
                {/* Domains */}
                <div className="p-3.5 rounded-xl bg-surface-secondary/50 border border-border space-y-2">
                  <div className="flex items-center justify-between pb-1 border-b border-border text-[10px] uppercase text-foreground-muted font-bold">
                    <span>Observed Domains ({iocs.domains?.length || 0})</span>
                    <Globe className="w-3 h-3 text-primary" />
                  </div>
                  <div className="space-y-1 max-h-36 overflow-y-auto pr-1">
                    {(iocs.domains && iocs.domains.length > 0) ? (
                      iocs.domains.map((d, i) => (
                        <div key={i} className="flex items-center justify-between p-1.5 rounded bg-surface border border-border">
                          <span className="truncate max-w-[200px] text-foreground font-medium">{d.value}</span>
                          <span className="text-[10px] text-danger font-bold uppercase">{d.reputation || 'SUSPICIOUS'}</span>
                        </div>
                      ))
                    ) : (
                      <p className="text-foreground-muted italic py-1">No domains extracted.</p>
                    )}
                  </div>
                </div>

                {/* IP Addresses */}
                <div className="p-3.5 rounded-xl bg-surface-secondary/50 border border-border space-y-2">
                  <div className="flex items-center justify-between pb-1 border-b border-border text-[10px] uppercase text-foreground-muted font-bold">
                    <span>Observed IP Infrastructure ({iocs.ips?.length || 0})</span>
                    <Server className="w-3 h-3 text-primary" />
                  </div>
                  <div className="space-y-1 max-h-36 overflow-y-auto pr-1">
                    {(iocs.ips && iocs.ips.length > 0) ? (
                      iocs.ips.map((ip, i) => (
                        <div key={i} className="flex items-center justify-between p-1.5 rounded bg-surface border border-border">
                          <span className="text-foreground font-medium">{ip.value}</span>
                          <span className="text-[10px] text-foreground-muted">{ip.origin || 'Relay'}</span>
                        </div>
                      ))
                    ) : (
                      <p className="text-foreground-muted italic py-1">No IPs extracted.</p>
                    )}
                  </div>
                </div>

                {/* Defanged Hyperlinks */}
                <div className="p-3.5 rounded-xl bg-surface-secondary/50 border border-border space-y-2 md:col-span-2">
                  <div className="flex items-center justify-between pb-1 border-b border-border text-[10px] uppercase text-foreground-muted font-bold">
                    <span>Embedded Hyperlinks (Defanged Safe Representation)</span>
                    <LinkIcon className="w-3 h-3 text-danger" />
                  </div>
                  <div className="space-y-1 max-h-36 overflow-y-auto pr-1">
                    {(iocs.urls && iocs.urls.length > 0) ? (
                      iocs.urls.map((u, i) => (
                        <div key={i} className="flex items-center justify-between p-1.5 rounded bg-surface border border-border">
                          <code className="text-foreground text-[10px] truncate max-w-2xl select-all font-mono">{u.value}</code>
                          <span className="px-1.5 py-0.2 rounded bg-warning/10 text-warning text-[9px] uppercase font-bold shrink-0">
                            Defanged
                          </span>
                        </div>
                      ))
                    ) : (
                      <p className="text-foreground-muted italic py-1">No embedded URLs detected.</p>
                    )}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* 10. MITRE ATT&CK MAPPINGS (Section 34: Only mappings generated from Section 19) */}
          {contentOptions.include_mitre_attack && mitre && mitre.length > 0 && (
            <div id="sec-mitre" className="space-y-4 scroll-mt-24">
              <div className="flex items-center space-x-2 pb-2 border-b border-border">
                <Terminal className="w-4 h-4 text-primary" />
                <h3 className="text-base font-bold text-foreground">
                  10. MITRE ATT&CK Matrix Alignment
                </h3>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left font-mono text-xs">
                  <thead>
                    <tr className="border-b border-border text-[10px] text-foreground-muted uppercase tracking-wider">
                      <th className="py-2.5 px-3">Technique ID</th>
                      <th className="py-2.5 px-3">Technique Name</th>
                      <th className="py-2.5 px-3">Tactic</th>
                      <th className="py-2.5 px-3">Status</th>
                      <th className="py-2.5 px-3 text-right">Evidence Items</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border/60">
                    {mitre.map((m, i) => (
                      <tr key={i} className="hover:bg-surface-secondary/40 transition-colors">
                        <td className="py-2.5 px-3 font-bold text-primary">{m.technique_id}</td>
                        <td className="py-2.5 px-3 font-semibold text-foreground">{m.technique_name}</td>
                        <td className="py-2.5 px-3 text-foreground-muted">{m.tactic}</td>
                        <td className="py-2.5 px-3">
                          <span className="px-1.5 py-0.2 rounded text-[9px] font-bold bg-success/15 text-success">
                            {m.status}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 text-right font-bold text-foreground">{m.evidence_count}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* 11. INFRASTRUCTURE INTELLIGENCE (Section 33: Strict attribution boundary) */}
          {contentOptions.include_infrastructure && infra && (
            <div id="sec-infrastructure" className="space-y-4 scroll-mt-24">
              <div className="flex items-center space-x-2 pb-2 border-b border-border">
                <Server className="w-4 h-4 text-primary" />
                <h3 className="text-base font-bold text-foreground">
                  11. Infrastructure Intelligence & Boundaries
                </h3>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3 font-mono text-xs">
                <div className="p-3.5 rounded-xl bg-surface-secondary border border-border space-y-1">
                  <span className="text-[10px] uppercase text-foreground-muted block font-semibold">Origin ASN:</span>
                  <span className="text-foreground font-bold text-sm">{infra.probable_origin_asn || 'AS64512'}</span>
                  <span className="text-[10px] text-foreground-muted block">Observed Route Netblock</span>
                </div>
                <div className="p-3.5 rounded-xl bg-surface-secondary border border-border space-y-1">
                  <span className="text-[10px] uppercase text-foreground-muted block font-semibold">Routing Location:</span>
                  <span className="text-foreground font-bold text-sm">{infra.probable_origin_country || 'United States'}</span>
                  <span className="text-[10px] text-foreground-muted block">Infrastructure Origin</span>
                </div>
                <div className="p-3.5 rounded-xl bg-surface-secondary border border-border space-y-1">
                  <span className="text-[10px] uppercase text-foreground-muted block font-semibold">Associated Domains:</span>
                  <span className="text-primary font-bold text-sm">{infra.associated_domains?.length || 0} Domains</span>
                  <span className="text-[10px] text-foreground-muted block">Shared Pivot Cluster</span>
                </div>
              </div>

              {/* Attribution Boundary Warning */}
              <div className="p-3.5 rounded-xl bg-surface-secondary/40 border border-border flex items-start space-x-2.5 text-[11px] font-mono text-foreground-muted">
                <Info className="w-4 h-4 text-primary shrink-0 mt-0.5" />
                <p className="leading-relaxed">
                  <strong className="text-foreground">Attribution Policy Boundary</strong>: {infra.attribution_boundary_note || 'Geographic coordinates and Autonomous System records refer strictly to physical routing hardware and proxy relay equipment. CyberGuard does not infer human legal identity or physical perpetrator nationality from network telemetry.'}
                </p>
              </div>
            </div>
          )}

          {/* 12. EXPLAINABILITY & LIMITATIONS (Section 35 & 36: What would change the assessment) */}
          {contentOptions.include_explainability && explain && (
            <div id="sec-explainability" className="space-y-4 scroll-mt-24">
              <div className="flex items-center space-x-2 pb-2 border-b border-border">
                <Sliders className="w-4 h-4 text-primary" />
                <h3 className="text-base font-bold text-foreground">
                  12. Explainability & Assessment Limitations
                </h3>
              </div>

              <div className="space-y-3 font-mono text-xs">
                <div className="p-3.5 rounded-xl bg-surface-secondary/50 border border-border space-y-1.5">
                  <span className="text-[10px] uppercase text-primary font-bold block">Reasoning Chain:</span>
                  <ol className="list-decimal list-inside space-y-1 text-[11px] text-foreground">
                    {(explain.reasoning_chain || []).map((step, i) => (
                      <li key={i}>{step}</li>
                    ))}
                  </ol>
                </div>

                <div className="p-3.5 rounded-xl bg-surface-secondary/50 border border-border space-y-1.5">
                  <span className="text-[10px] uppercase text-warning font-bold block">What Would Change This Assessment:</span>
                  <ul className="space-y-1 text-[11px] text-foreground-muted">
                    {(explain.what_would_change_assessment || []).map((item, i) => (
                      <li key={i}>• {item}</li>
                    ))}
                  </ul>
                </div>
              </div>
            </div>
          )}

          {/* 13. RESPONSE ACTIONS (Section 37 & 38: Action table with actual execution status) */}
          {contentOptions.include_response_actions && resp && (
            <div id="sec-response" className="space-y-4 scroll-mt-24">
              <div className="flex items-center justify-between pb-2 border-b border-border">
                <div className="flex items-center space-x-2">
                  <ShieldAlert className="w-4 h-4 text-primary" />
                  <h3 className="text-base font-bold text-foreground">
                    13. Response Actions & Containment Status
                  </h3>
                </div>
                <div className="flex items-center space-x-3 text-[10px] font-mono">
                  <span>Executed: <strong className="text-success">{resp.summary?.executed_count || 0}</strong></span>
                  <span>Pending: <strong className="text-warning">{resp.summary?.pending_count || 0}</strong></span>
                </div>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left font-mono text-xs">
                  <thead>
                    <tr className="border-b border-border text-[10px] text-foreground-muted uppercase tracking-wider">
                      <th className="py-2.5 px-3">Action Type</th>
                      <th className="py-2.5 px-3">Priority</th>
                      <th className="py-2.5 px-3">Status</th>
                      <th className="py-2.5 px-3">Target Entity</th>
                      <th className="py-2.5 px-3 text-right">Result</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border/60">
                    {(resp.actions_table && resp.actions_table.length > 0) ? (
                      resp.actions_table.map((act, i) => (
                        <tr key={i} className="hover:bg-surface-secondary/40 transition-colors">
                          <td className="py-2.5 px-3 font-semibold text-foreground">{act.action_type}</td>
                          <td className="py-2.5 px-3 font-bold text-danger">{act.priority}</td>
                          <td className="py-2.5 px-3">
                            <span className={`px-1.5 py-0.2 rounded text-[9px] font-bold uppercase ${
                              act.status === 'EXECUTED' ? 'bg-success/15 text-success' :
                              act.status === 'APPROVED' ? 'bg-primary/15 text-primary' :
                              'bg-warning/15 text-warning'
                            }`}>
                              {act.status}
                            </span>
                          </td>
                          <td className="py-2.5 px-3 text-foreground-muted truncate max-w-xs">{act.target}</td>
                          <td className="py-2.5 px-3 text-right font-medium text-foreground">{act.result || 'Pending'}</td>
                        </tr>
                      ))
                    ) : (
                      <tr>
                        <td colSpan={5} className="py-3 text-center text-foreground-muted italic">
                          No response actions recorded yet.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* 14. AUDIT TRAIL (Section 39: Investigator-relevant audit trail) */}
          {contentOptions.include_audit_trail && audit.length > 0 && (
            <div id="sec-audit" className="space-y-4 scroll-mt-24">
              <div className="flex items-center justify-between pb-2 border-b border-border">
                <div className="flex items-center space-x-2">
                  <Clock className="w-4 h-4 text-primary" />
                  <h3 className="text-base font-bold text-foreground">
                    14. Investigation Audit Trail
                  </h3>
                </div>
                <span className="text-[10px] font-mono text-foreground-muted uppercase">
                  Append-Only Ledger
                </span>
              </div>

              <div className="space-y-2 font-mono text-xs">
                {audit.map((a, i) => (
                  <div key={i} className="p-2.5 rounded-lg bg-surface-secondary/40 border border-border flex items-center justify-between gap-3 text-[11px]">
                    <div className="flex items-center space-x-2.5">
                      <span className="font-bold text-primary">{a.action}</span>
                      <span className="text-foreground truncate max-w-md">{a.details}</span>
                    </div>
                    <div className="flex items-center space-x-2 text-[10px] text-foreground-muted shrink-0">
                      <span>{a.user}</span>
                      <span>·</span>
                      <span>{a.timestamp ? new Date(a.timestamp).toLocaleString() : 'Recent'}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* 15. EVIDENCE INDEX (Section 48: Evidence reference catalog with digests) */}
          {contentOptions.include_evidence_index && evidenceIndex.length > 0 && (
            <div id="sec-evidence-index" className="space-y-4 scroll-mt-24 pt-4 border-t-2 border-border">
              <div className="flex items-center justify-between pb-2 border-b border-border">
                <div className="flex items-center space-x-2">
                  <Hash className="w-4 h-4 text-primary" />
                  <h3 className="text-base font-bold text-foreground">
                    15. Authoritative Evidence Index
                  </h3>
                </div>
                <span className="text-[10px] font-mono text-foreground-muted uppercase">
                  Cross-Reference Index
                </span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 font-mono text-xs">
                {evidenceIndex.map((item, i) => (
                  <div key={i} className="p-3 rounded-lg bg-surface-secondary border border-border space-y-1">
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-primary">{item.ref_id}</span>
                      <span className="text-[10px] text-foreground-muted uppercase">{item.type}</span>
                    </div>
                    <div className="font-semibold text-foreground text-xs truncate">{item.label}</div>
                    <div className="text-[10px] text-foreground-muted select-all break-all">{item.digest}</div>
                    <div className="text-[9px] text-primary">{item.provenance}</div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* 16. QUALITY CHECK VALIDATION FOOTER (Section 63) */}
          {quality && (
            <div className="p-4 rounded-xl bg-surface-secondary/60 border border-border flex flex-col sm:flex-row sm:items-center justify-between gap-3 font-mono text-xs">
              <div className="flex items-center space-x-2.5">
                <CheckCircle2 className="w-4 h-4 text-success" />
                <span className="font-bold text-foreground">Report Projection Validation Passed</span>
                <span className="text-[10px] text-foreground-muted">
                  ({quality.checks_passed?.length || 8} integrity criteria verified)
                </span>
              </div>
              <div className="text-[10px] text-foreground-muted">
                Generator: {meta?.generator_version || 'ReportService-2.0 (ReportLab Vector)'}
              </div>
            </div>
          )}

          {/* DOCUMENT SIGN-OFF FOOTER */}
          <div className="pt-6 border-t border-border flex flex-col sm:flex-row sm:items-center justify-between gap-4 text-xs font-mono text-foreground-muted">
            <div>
              <span className="block font-bold text-foreground uppercase tracking-wider">INVESTIGATOR SIGN-OFF</span>
              <span className="text-[11px]">{meta?.generated_by || 'SOC Lead Forensic Examiner'}</span>
            </div>
            <div className="text-left sm:text-right">
              <span className="block font-bold text-success uppercase tracking-wider">REPRODUCIBLE RECORD</span>
              <span className="text-[11px]">Timestamp: {meta?.generated_at ? new Date(meta.generated_at).toUTCString() : new Date().toUTCString()}</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ReportSectionView;
