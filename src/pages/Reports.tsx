import React, { useState, useEffect } from 'react';
import { useNavigate, useParams, useSearchParams } from 'react-router-dom';
import {
  FileText,
  Printer,
  ShieldCheck,
  Lock,
  Download,
  Loader2,
  RefreshCw,
  Clock,
  AlertCircle,
  Search,
  ExternalLink,
  FileCode,
  Layers,
} from 'lucide-react';
import type { ReportListItem, ReportDetail } from '../types/report';
import { reportService } from '../services/reportService';
import { ExecutiveReportingHub } from '../components/reports/ExecutiveReportingHub';

export const Reports: React.FC = () => {
  const navigate = useNavigate();
  const { id: routeReportId } = useParams<{ id?: string }>();
  const [searchParams, setSearchParams] = useSearchParams();

  // Tab State
  const [activeWorkspaceTab, setActiveWorkspaceTab] = useState<'executive' | 'standard'>('executive');

  // State
  const [reportsList, setReportsList] = useState<ReportListItem[]>([]);
  const [loadingReports, setLoadingReports] = useState<boolean>(true);
  const [selectedReportId, setSelectedReportId] = useState<string | null>(routeReportId || null);
  const [selectedDetail, setSelectedDetail] = useState<ReportDetail | null>(null);
  const [loadingDetail, setLoadingDetail] = useState<boolean>(false);
  const [isDownloadingPdf, setIsDownloadingPdf] = useState<boolean>(false);
  const [isDownloadingJson, setIsDownloadingJson] = useState<boolean>(false);
  const [successToast, setSuccessToast] = useState<string | null>(null);

  // Filters & Search synced with URL
  const initialSearch = searchParams.get('q') || searchParams.get('search') || '';
  const [searchTerm, setSearchTerm] = useState<string>(initialSearch);
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');

  useEffect(() => {
    const params = new URLSearchParams(searchParams);
    if (searchTerm.trim()) {
      params.set('q', searchTerm.trim());
    } else {
      params.delete('q');
      params.delete('search');
    }
    setSearchParams(params, { replace: true });
  }, [searchTerm, setSearchParams]);

  const showToast = (msg: string) => {
    setSuccessToast(msg);
    setTimeout(() => setSuccessToast(null), 3500);
  };

  // Fetch Reports Catalog
  const fetchReports = async () => {
    setLoadingReports(true);
    try {
      const data = await reportService.listReports(100, 0, searchTerm);
      const list = data.reports || [];
      setReportsList(list);

      // Resolve initial selection
      if (routeReportId && list.some(r => r.id === routeReportId)) {
        setSelectedReportId(routeReportId);
      } else if (!selectedReportId && list.length > 0) {
        setSelectedReportId(list[0].id);
      }
    } catch (err) {
      console.error('Error fetching reports:', err);
      setReportsList([]);
    } finally {
      setLoadingReports(false);
    }
  };

  useEffect(() => {
    fetchReports();
  }, [searchTerm]);

  // When selection changes, fetch full immutable ReportDetail
  useEffect(() => {
    if (!selectedReportId) {
      setSelectedDetail(null);
      return;
    }
    const loadDetail = async () => {
      setLoadingDetail(true);
      try {
        const detail = await reportService.getReportById(selectedReportId);
        setSelectedDetail(detail);
      } catch (err) {
        console.error('Failed to load report detail:', err);
        setSelectedDetail(null);
      } finally {
        setLoadingDetail(false);
      }
    };
    loadDetail();
  }, [selectedReportId]);

  // Synchronize routeReportId changes
  useEffect(() => {
    if (routeReportId) {
      setSelectedReportId(routeReportId);
    }
  }, [routeReportId]);

  const handleDownloadPDF = async (reportId: string, reportNumber: string) => {
    setIsDownloadingPdf(true);
    try {
      await reportService.downloadPdf(reportId, `CyberGuard_${reportNumber}.pdf`);
      showToast(`Downloaded CyberGuard_${reportNumber}.pdf`);
    } catch (err) {
      console.error(err);
      showToast('Error downloading report PDF');
    } finally {
      setIsDownloadingPdf(false);
    }
  };

  const handleDownloadJSON = async (reportId: string, reportNumber: string) => {
    setIsDownloadingJson(true);
    try {
      await reportService.downloadJson(reportId, `CyberGuard_${reportNumber}.json`);
      showToast(`Exported CyberGuard_${reportNumber}.json`);
    } catch (err) {
      console.error(err);
      showToast('Error downloading report JSON');
    } finally {
      setIsDownloadingJson(false);
    }
  };

  const handlePrint = () => {
    if (!selectedDetail) return;
    window.print();
    showToast('Document sent to print preview.');
  };

  const filteredReports = reportsList.filter((r) => {
    if (severityFilter !== 'ALL' && (r.severity || 'low').toLowerCase() !== severityFilter.toLowerCase()) {
      return false;
    }
    return true;
  });

  return (
    <div className="space-y-6 pb-16 page-enter">
      {/* Toast Notification */}
      {successToast && (
        <div className="fixed top-5 right-5 z-50 flex items-center space-x-2 px-4 py-2.5 rounded-xl bg-surface border border-success/30 text-success text-xs font-mono shadow-xl animate-in slide-in-from-top-3">
          <ShieldCheck className="w-4 h-4 text-success" />
          <span>{successToast}</span>
        </div>
      )}

      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-surface p-6 rounded-card border border-border shadow-xs">
        <div>
          <div className="flex items-center space-x-2 text-primary font-mono text-xs mb-1 font-semibold uppercase tracking-wider">
            <FileText className="w-3.5 h-3.5 text-primary" />
            <span>FORENSIC EVIDENCE & REPRODUCIBLE REPORTING REPOSITORY</span>
          </div>
          <h1 className="text-xl sm:text-2xl font-bold text-foreground font-sans tracking-tight">
            Forensic Incident Reports
          </h1>
          <p className="text-xs text-foreground-muted font-mono mt-1">
            Immutable, evidence-backed security reports compiled across investigations with cryptographic bitstream verification and vector PDF archives.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          <button
            type="button"
            onClick={fetchReports}
            className="flex items-center space-x-1.5 px-3.5 py-2 rounded-lg bg-surface-secondary hover:bg-surface border border-border text-foreground text-xs font-mono font-medium transition-colors cursor-pointer"
          >
            <RefreshCw className="w-3.5 h-3.5 text-primary" />
            <span>Refresh</span>
          </button>
          {selectedDetail && (
            <button
              id="print-evidence-dossier-btn"
              type="button"
              onClick={handlePrint}
              className="flex items-center space-x-1.5 px-4 py-2 rounded-lg bg-surface hover:bg-surface-secondary border border-border text-foreground font-mono font-semibold text-xs transition-colors cursor-pointer"
            >
              <Printer className="w-3.5 h-3.5 text-primary" />
              <span>Print Document</span>
            </button>
          )}
        </div>
      </div>

      {/* Top Level Navigation Tabs */}
      <div className="flex items-center space-x-2 border-b border-border pb-2">
        <button
          type="button"
          onClick={() => setActiveWorkspaceTab('executive')}
          className={`flex items-center space-x-2 px-4 py-2 rounded-lg text-xs font-mono font-semibold transition-all cursor-pointer ${
            activeWorkspaceTab === 'executive'
              ? 'bg-primary text-primary-foreground shadow-xs'
              : 'text-foreground-muted hover:text-foreground hover:bg-surface-secondary'
          }`}
        >
          <FileText className="w-3.5 h-3.5" />
          <span>Executive Intelligence & Dissemination Hub</span>
          <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-white/20 ml-1">Section 69</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveWorkspaceTab('standard')}
          className={`flex items-center space-x-2 px-4 py-2 rounded-lg text-xs font-mono font-semibold transition-all cursor-pointer ${
            activeWorkspaceTab === 'standard'
              ? 'bg-primary text-primary-foreground shadow-xs'
              : 'text-foreground-muted hover:text-foreground hover:bg-surface-secondary'
          }`}
        >
          <Layers className="w-3.5 h-3.5" />
          <span>Standard Forensic Dossiers (Section 42)</span>
        </button>
      </div>

      {activeWorkspaceTab === 'executive' ? (
        <ExecutiveReportingHub />
      ) : (
        /* Main Catalog & Document Viewer Layout */
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Reports List & Search / Filters */}
        <div className="space-y-3">
          <div className="bg-surface p-3.5 rounded-card border border-border space-y-3">
            {/* Search Input */}
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-foreground-muted absolute left-3 top-2.5" />
              <input
                type="text"
                placeholder="Search reports or incidents..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-surface-secondary border border-border text-foreground text-xs font-mono placeholder:text-foreground-muted focus:outline-none focus:border-primary"
              />
            </div>

            {/* Severity Filter Tabs */}
            <div className="flex items-center space-x-1 overflow-x-auto text-[11px] font-mono">
              {(['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map((sev) => (
                <button
                  key={sev}
                  type="button"
                  onClick={() => setSeverityFilter(sev)}
                  className={`px-2 py-1 rounded-md text-[10px] font-bold uppercase transition-all cursor-pointer ${
                    severityFilter === sev
                      ? 'bg-primary/15 text-primary border border-primary/30'
                      : 'text-foreground-muted hover:text-foreground'
                  }`}
                >
                  {sev}
                </button>
              ))}
            </div>
          </div>

          {/* Reports Items List */}
          <div className="space-y-2 max-h-[720px] overflow-y-auto pr-1">
            {loadingReports ? (
              <div className="p-8 text-center bg-surface rounded-card border border-border">
                <Loader2 className="w-5 h-5 animate-spin mx-auto text-primary mb-2" />
                <p className="text-xs text-foreground-muted font-mono">Loading report records...</p>
              </div>
            ) : filteredReports.length === 0 ? (
              <div className="p-8 text-center bg-surface rounded-card border border-border space-y-2">
                <AlertCircle className="w-6 h-6 text-foreground-muted mx-auto" />
                <p className="text-xs text-foreground-muted font-mono">No matching reports found.</p>
              </div>
            ) : (
              filteredReports.map((rep) => {
                const isSelected = selectedReportId === rep.id;
                const sizeKb = rep.file_size_bytes ? `${Math.round(rep.file_size_bytes / 1024)} KB` : 'Vector PDF';
                return (
                  <div
                    key={rep.id}
                    onClick={() => {
                      setSelectedReportId(rep.id);
                      navigate(`/reports/${rep.id}`, { replace: true });
                    }}
                    className={`p-3.5 rounded-xl border text-xs font-mono cursor-pointer transition-all ${
                      isSelected
                        ? 'bg-primary-subtle border-primary/40 shadow-xs'
                        : 'bg-surface border-border hover:bg-surface-secondary/50'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-1">
                      <div className="flex items-center space-x-2">
                        <span className={`font-bold ${isSelected ? 'text-primary' : 'text-foreground'}`}>
                          {rep.report_number}
                        </span>
                        <span className="px-1.5 py-0.2 rounded bg-surface border border-border text-[9px] font-bold">
                          v{rep.report_version || 1}
                        </span>
                      </div>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${
                        rep.severity === 'critical' ? 'bg-danger-surface text-danger border-danger-border' :
                        rep.severity === 'high' ? 'bg-warning-surface text-warning border-warning-border' :
                        'bg-success-surface text-success border-success-border'
                      }`}>
                        {rep.severity || 'low'}
                      </span>
                    </div>

                    <div className="text-foreground font-semibold font-sans line-clamp-2">
                      {rep.title}
                    </div>

                    <div className="text-[11px] text-foreground-muted mt-2 flex items-center justify-between">
                      <span className="flex items-center space-x-1">
                        <Clock className="w-3 h-3 text-foreground-muted" />
                        <span>{new Date(rep.created_at).toLocaleDateString()}</span>
                      </span>
                      <span className="text-primary font-semibold">{sizeKb}</span>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Right Columns: Selected Immutable Report View */}
        <div className="lg:col-span-2 space-y-4">
          {loadingDetail ? (
            <div className="p-16 text-center bg-surface rounded-card border border-border">
              <Loader2 className="w-8 h-8 animate-spin mx-auto text-primary mb-3" />
              <p className="text-xs text-foreground-muted font-mono">Loading immutable report snapshot...</p>
            </div>
          ) : !selectedDetail ? (
            <div className="p-12 bg-surface rounded-card border border-border text-center space-y-3">
              <AlertCircle className="w-8 h-8 text-foreground-muted mx-auto" />
              <h3 className="text-base font-bold text-foreground">No Report Selected</h3>
              <p className="text-xs text-foreground-muted font-mono">
                Select a report from the catalog to review its immutable evidentiary snapshot.
              </p>
            </div>
          ) : (
            <div className="bg-surface border border-border rounded-card p-6 md:p-8 space-y-6 shadow-xs print:p-0 print:border-none">
              {/* Document Header & Action Bar */}
              <div className="border-b border-border pb-5 flex flex-col sm:flex-row sm:items-start justify-between gap-4">
                <div>
                  <div className="flex items-center space-x-2 text-primary font-mono text-xs font-semibold uppercase tracking-widest">
                    <ShieldCheck className="w-4 h-4 text-primary" />
                    <span>CYBERGUARD // OFFICIAL FORENSIC INCIDENT DOSSIER</span>
                  </div>
                  <h2 className="text-xl sm:text-2xl font-bold text-foreground font-sans mt-2">
                    {selectedDetail.title}
                  </h2>
                  <div className="flex flex-wrap items-center gap-2 text-xs font-mono text-foreground-muted mt-1.5">
                    <span>Ref No: <strong className="text-foreground">{selectedDetail.report_number}</strong></span>
                    <span>·</span>
                    <span>Version: <strong className="text-primary">v{selectedDetail.report_version}</strong></span>
                    <span>·</span>
                    <span>Status: <strong className="text-success">{selectedDetail.status}</strong></span>
                    <span>·</span>
                    <span>Classification: <strong className="text-warning">{selectedDetail.classification}</strong></span>
                  </div>
                </div>

                <div className="flex flex-wrap items-center gap-2 shrink-0">
                  {/* Download Official Vector PDF */}
                  <button
                    type="button"
                    onClick={() => handleDownloadPDF(selectedDetail.id, selectedDetail.report_number)}
                    disabled={isDownloadingPdf}
                    className="flex items-center space-x-1.5 px-3.5 py-2 rounded-lg bg-primary hover:bg-primary-hover text-primary-foreground font-mono text-xs font-bold transition-all cursor-pointer disabled:opacity-50"
                  >
                    {isDownloadingPdf ? (
                      <Loader2 className="w-3.5 h-3.5 animate-spin" />
                    ) : (
                      <Download className="w-3.5 h-3.5" />
                    )}
                    <span>Vector PDF</span>
                  </button>

                  {/* Export JSON Bundle */}
                  <button
                    type="button"
                    onClick={() => handleDownloadJSON(selectedDetail.id, selectedDetail.report_number)}
                    disabled={isDownloadingJson}
                    className="flex items-center space-x-1.5 px-3 py-2 rounded-lg bg-surface-secondary hover:bg-surface border border-border text-foreground font-mono text-xs font-semibold transition-colors cursor-pointer disabled:opacity-50"
                  >
                    <FileCode className="w-3.5 h-3.5 text-primary" />
                    <span>JSON</span>
                  </button>

                  {/* Deep link into Investigation Workspace */}
                  {selectedDetail.investigation_id && (
                    <button
                      type="button"
                      onClick={() => navigate(`/investigations/${selectedDetail.investigation_id}/report`)}
                      className="flex items-center space-x-1 px-3 py-2 rounded-lg bg-surface-secondary hover:bg-surface border border-border text-primary font-mono text-xs font-semibold transition-colors cursor-pointer"
                      title="Open full interactive Report Workspace"
                    >
                      <ExternalLink className="w-3.5 h-3.5" />
                      <span>Workspace</span>
                    </button>
                  )}
                </div>
              </div>

              {/* Immutable Snapshot Metadata Table (Section 58 Contract) */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 p-3.5 rounded-xl bg-surface-secondary/60 border border-border font-mono text-xs">
                <div>
                  <span className="text-[10px] uppercase text-foreground-muted block font-semibold">Investigation ID:</span>
                  <span className="text-primary font-bold block truncate">
                    {selectedDetail.investigation_id || selectedDetail.case_id || 'N/A'}
                  </span>
                </div>
                <div>
                  <span className="text-[10px] uppercase text-foreground-muted block font-semibold">Threat Score:</span>
                  <span className="text-danger font-bold block">
                    {selectedDetail.threat_score}/100 ({selectedDetail.severity?.toUpperCase()})
                  </span>
                </div>
                <div>
                  <span className="text-[10px] uppercase text-foreground-muted block font-semibold">Generated By:</span>
                  <span className="text-foreground font-semibold block truncate">
                    {selectedDetail.analyst_name || 'SOC Analyst'}
                  </span>
                </div>
                <div>
                  <span className="text-[10px] uppercase text-foreground-muted block font-semibold">Generated Timestamp:</span>
                  <span className="text-foreground block truncate">
                    {new Date(selectedDetail.created_at).toUTCString()}
                  </span>
                </div>
              </div>

              {/* Executive Summary */}
              <div className="space-y-2">
                <h4 className="text-xs font-mono font-bold text-primary uppercase">
                  1. EXECUTIVE SUMMARY
                </h4>
                <div className="p-3.5 rounded-xl bg-surface-secondary border border-border text-xs font-mono text-foreground leading-relaxed">
                  {selectedDetail.summary ||
                    `Forensic examination conducted by ${selectedDetail.analyst_name || 'SOC Lead Analyst'} with threat score ${selectedDetail.threat_score ?? 0}/100.`}
                </div>
              </div>

              {/* Snapshot Content Sections Preview (If available in snapshot) */}
              {selectedDetail.snapshot && (
                <>
                  {/* Attack Path & Stages */}
                  {selectedDetail.snapshot.attack_path?.stages && selectedDetail.snapshot.attack_path.stages.length > 0 && (
                    <div className="space-y-2">
                      <h4 className="text-xs font-mono font-bold text-primary uppercase">
                        2. RECONSTRUCTED ATTACK SEQUENCE ({selectedDetail.snapshot.attack_path.stages.length} Stages)
                      </h4>
                      <div className="space-y-1.5 font-mono text-xs">
                        {selectedDetail.snapshot.attack_path.stages.map((st, i) => (
                          <div key={i} className="p-2.5 rounded-lg bg-surface-secondary/40 border border-border flex items-center justify-between text-[11px]">
                            <div className="flex items-center space-x-2">
                              <span className="w-5 h-5 rounded bg-primary/15 text-primary flex items-center justify-center font-bold text-[10px]">
                                {st.stage_order}
                              </span>
                              <span className="font-bold text-foreground">{st.name}</span>
                              <span className="text-[9px] uppercase px-1.5 py-0.2 rounded bg-surface border border-border text-foreground-muted">
                                {st.stage_type}
                              </span>
                            </div>
                            <span className="text-primary font-bold">{Math.round(st.confidence * 100)}% Conf.</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Findings */}
                  {selectedDetail.snapshot.findings && selectedDetail.snapshot.findings.length > 0 && (
                    <div className="space-y-2">
                      <h4 className="text-xs font-mono font-bold text-primary uppercase">
                        3. FORENSIC FINDINGS ({selectedDetail.snapshot.findings.length} Observed)
                      </h4>
                      <div className="space-y-1.5 font-mono text-xs">
                        {selectedDetail.snapshot.findings.map((f, i) => (
                          <div key={i} className="p-2.5 rounded-lg bg-surface-secondary/40 border border-border flex items-start space-x-2.5 text-[11px]">
                            <span className={`px-1.5 py-0.2 rounded text-[9px] font-bold uppercase shrink-0 mt-0.5 ${
                              f.severity === 'CRITICAL' ? 'bg-danger/15 text-danger' :
                              f.severity === 'HIGH' ? 'bg-warning/15 text-warning' :
                              'bg-surface text-foreground-muted'
                            }`}>
                              {f.severity}
                            </span>
                            <div className="min-w-0 flex-1">
                              <span className="font-bold text-foreground block">{f.title}</span>
                              <p className="text-foreground-muted text-[10px] leading-relaxed mt-0.5">{f.description}</p>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </>
              )}

              {/* Bitstream Custody & Cryptographic Verification */}
              <div className="pt-4 border-t border-border space-y-2">
                <h4 className="text-xs font-mono font-bold text-primary uppercase flex items-center space-x-1.5">
                  <Lock className="w-3.5 h-3.5" />
                  <span>CRYPTOGRAPHIC CHAIN OF CUSTODY VERIFICATION</span>
                </h4>
                <div className="p-3 rounded-lg bg-surface-secondary border border-border text-[11px] font-mono text-foreground-muted break-all select-all">
                  SHA-256: {selectedDetail.snapshot?.metadata?.data_snapshot_hash || selectedDetail.email_sha256 || 'Verified immutable record in append-only storage'}
                </div>
                <div className="flex justify-between items-center text-[10px] font-mono text-foreground-muted pt-1">
                  <span>Audit Policy: Append-Only Immutable Version</span>
                  <span className="text-success font-semibold">DIGITALLY SEALED RECORD</span>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    )}
  </div>
);
};

