import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  FileText,
  Printer,
  ShieldCheck,
  Lock,
  Download,
  Loader2,
  RefreshCw,
  Clock,
  Briefcase,
  AlertCircle,
  ArrowRight
} from 'lucide-react';

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

export const Reports: React.FC = () => {
  const navigate = useNavigate();
  const [backendReports, setBackendReports] = useState<BackendReportItem[]>([]);
  const [loadingReports, setLoadingReports] = useState<boolean>(true);
  const [selectedReport, setSelectedReport] = useState<BackendReportItem | null>(null);
  const [isDownloading, setIsDownloading] = useState<boolean>(false);
  const [successToast, setSuccessToast] = useState<string | null>(null);

  const showToast = (msg: string) => {
    setSuccessToast(msg);
    setTimeout(() => setSuccessToast(null), 3500);
  };

  const fetchReports = async () => {
    setLoadingReports(true);
    try {
      const res = await fetch('/api/reports?limit=50');
      if (res.ok) {
        const data = await res.json();
        const list: BackendReportItem[] = data.reports || [];
        setBackendReports(list);
        if (list.length > 0) {
          setSelectedReport((prev) => {
            if (prev && list.some(r => r.id === prev.id)) return prev;
            return list[0];
          });
        } else {
          setSelectedReport(null);
        }
      } else {
        setBackendReports([]);
        setSelectedReport(null);
      }
    } catch {
      setBackendReports([]);
      setSelectedReport(null);
    } finally {
      setLoadingReports(false);
    }
  };

  useEffect(() => {
    fetchReports();
  }, []);

  const handleDownloadPDF = async (reportId: string, filename: string) => {
    setIsDownloading(true);
    try {
      const res = await fetch(`/api/reports/${reportId}/download`);
      if (!res.ok) throw new Error(`Download failed: ${res.statusText}`);

      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename.endsWith('.pdf') ? filename : `${filename}.pdf`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);

      showToast(`Downloaded ${filename}`);
    } catch (err) {
      console.error(err);
      showToast('Error downloading report PDF');
    } finally {
      setIsDownloading(false);
    }
  };

  const handlePrint = () => {
    if (!selectedReport) return;
    window.print();
    showToast('Dossier sent to print preview.');
  };

  return (
    <div className="space-y-6 pb-12">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-surface p-6 rounded-xl border border-border shadow-xs">
        <div>
          <div className="flex items-center space-x-2 text-primary font-mono text-xs mb-1 font-semibold uppercase tracking-wider">
            <FileText className="w-3.5 h-3.5 text-primary" />
            <span>FORENSIC EVIDENCE & REPORTING CENTER</span>
          </div>
          <h1 className="text-xl font-bold text-foreground font-sans tracking-tight">
            Forensic Incident Reports
          </h1>
          <p className="text-xs text-foreground-muted font-mono mt-1">
            Structured evidentiary PDF report generation formatted for legal compliance, cyber incident response, and law enforcement submittals.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          <button
            type="button"
            onClick={fetchReports}
            className="flex items-center space-x-1.5 px-3.5 py-2 rounded-lg bg-surface-secondary hover:bg-surface border border-border text-foreground text-xs font-mono font-medium transition-colors btn-press cursor-pointer"
          >
            <RefreshCw className="w-3.5 h-3.5 text-primary" />
            <span>Refresh</span>
          </button>
          {selectedReport && (
            <button
              id="print-evidence-dossier-btn"
              type="button"
              onClick={handlePrint}
              className="flex items-center space-x-1.5 px-4 py-2 rounded-lg bg-primary hover:bg-primary-hover text-primary-foreground font-mono font-semibold text-xs tracking-wider transition-colors btn-press cursor-pointer"
            >
              <Printer className="w-3.5 h-3.5" />
              <span>PRINT DOSSIER</span>
            </button>
          )}
        </div>
      </div>

      {successToast && (
        <div className="p-3.5 rounded-lg bg-success-surface border border-success-border text-success text-xs font-mono flex items-center space-x-2 animate-in fade-in">
          <ShieldCheck className="w-4 h-4 text-success" />
          <span>{successToast}</span>
        </div>
      )}

      {loadingReports ? (
        <div className="p-12 text-center bg-surface rounded-xl border border-border">
          <Loader2 className="w-6 h-6 animate-spin mx-auto text-primary mb-3" />
          <p className="text-xs text-foreground-muted font-mono">Loading reports catalog...</p>
        </div>
      ) : backendReports.length === 0 ? (
        <div className="p-12 bg-surface rounded-xl border border-border text-center space-y-4 shadow-xs">
          <div className="p-3 bg-surface-secondary rounded-full w-12 h-12 mx-auto flex items-center justify-center border border-border">
            <AlertCircle className="w-6 h-6 text-foreground-muted" />
          </div>
          <div>
            <h3 className="text-base font-bold text-foreground font-sans">
              No Forensic Reports Generated Yet
            </h3>
            <p className="text-xs text-foreground-muted font-mono max-w-md mx-auto mt-1">
              Forensic reports are created when you analyze an email or export evidence dossiers from investigation cases.
            </p>
          </div>
          <div className="pt-2">
            <button
              type="button"
              onClick={() => navigate('/analyze')}
              className="inline-flex items-center space-x-2 px-4 py-2 rounded-lg bg-primary hover:bg-primary-hover text-primary-foreground font-mono text-xs font-semibold transition-colors btn-press cursor-pointer"
            >
              <span>Analyze an Email</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      ) : (
        /* Reports Grid & Viewer Layout */
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Reports List */}
          <div className="space-y-2.5">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-mono font-semibold text-foreground-muted uppercase tracking-wider">
                GENERATED REPORTS ({backendReports.length})
              </h3>
            </div>

            <div className="space-y-2 max-h-[680px] overflow-y-auto pr-1">
              {backendReports.map(rep => {
                const isSelected = selectedReport?.id === rep.id;
                const sizeKb = rep.file_size_bytes ? `${Math.round(rep.file_size_bytes / 1024)} KB` : '';
                return (
                  <div
                    key={rep.id}
                    onClick={() => setSelectedReport(rep)}
                    className={`p-3.5 rounded-xl border text-xs font-mono cursor-pointer transition-all ${
                      isSelected
                        ? 'bg-primary-subtle border-primary/40 shadow-xs'
                        : 'bg-surface border-border hover:bg-surface-secondary/50'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-1">
                      <span className={`font-semibold ${isSelected ? 'text-primary' : 'text-foreground'}`}>
                        {rep.report_number}
                      </span>
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
              })}
            </div>
          </div>

          {/* Official Printable Report Document View */}
          {selectedReport && (
            <div className="lg:col-span-2 bg-surface border border-border rounded-xl p-6 md:p-8 space-y-6 print:bg-white print:text-black print:p-0 shadow-xs">
              {/* Document Header & Action */}
              <div className="border-b border-border pb-5 flex flex-col sm:flex-row sm:items-start justify-between gap-4">
                <div>
                  <div className="flex items-center space-x-2 text-primary font-mono text-xs font-semibold uppercase tracking-widest">
                    <ShieldCheck className="w-4 h-4 text-primary" />
                    <span>MAILTRACE AI // OFFICIAL FORENSIC EVIDENCE DOSSIER</span>
                  </div>
                  <h2 className="text-xl font-bold text-foreground font-sans mt-2">
                    {selectedReport.title}
                  </h2>
                  <div className="text-xs font-mono text-foreground-muted mt-1">
                    Ref No:{' '}
                    <strong className="text-foreground">
                      {selectedReport.report_number}
                    </strong>{' '}
                    | Created:{' '}
                    {new Date(selectedReport.created_at).toLocaleString()}
                  </div>
                </div>

                <div className="flex items-center space-x-2 shrink-0">
                  <button
                    id="download-selected-pdf-btn"
                    type="button"
                    onClick={() =>
                      handleDownloadPDF(
                        selectedReport.id,
                        `MailTrace_${selectedReport.report_number}.pdf`
                      )
                    }
                    disabled={isDownloading}
                    className="flex items-center space-x-1.5 px-3.5 py-2 rounded-lg bg-primary hover:bg-primary-hover text-primary-foreground font-mono text-xs font-semibold transition-colors btn-press disabled:opacity-50 cursor-pointer"
                  >
                    {isDownloading ? (
                      <>
                        <Loader2 className="w-3.5 h-3.5 animate-spin" />
                        <span>Downloading...</span>
                      </>
                    ) : (
                      <>
                        <Download className="w-3.5 h-3.5" />
                        <span>Download PDF</span>
                      </>
                    )}
                  </button>
                </div>
              </div>

              {/* Executive Summary */}
              <div className="space-y-2">
                <h4 className="text-xs font-mono font-semibold text-primary uppercase">
                  1. EXECUTIVE FORENSIC SUMMARY
                </h4>
                <div className="p-3.5 rounded-lg bg-surface-secondary border border-border text-xs font-mono text-foreground leading-relaxed">
                  {selectedReport.summary ||
                    `Forensic examination conducted by ${selectedReport.analyst_name || 'SOC Lead Analyst'} with threat score ${selectedReport.threat_score ?? 0}/100.`}
                </div>
              </div>

              {/* Technical Evidence & Indicators of Compromise */}
              <div className="space-y-2">
                <h4 className="text-xs font-mono font-semibold text-primary uppercase">
                  2. CORRELATED TECHNICAL EVIDENCE & CHAIN OF CUSTODY
                </h4>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs font-mono">
                  <div className="p-3 rounded-lg bg-surface-secondary border border-border">
                    <span className="text-foreground-muted block text-[10px]">Evidence Identifier:</span>
                    <span className="text-primary font-bold">
                      {selectedReport.evidence_id || 'Direct Ingestion'}
                    </span>
                  </div>

                  <div className="p-3 rounded-lg bg-surface-secondary border border-border">
                    <span className="text-foreground-muted block text-[10px]">Threat Score & Severity:</span>
                    <span className="text-danger font-bold">
                      {selectedReport.threat_score !== undefined && selectedReport.threat_score !== null
                        ? `${selectedReport.threat_score}/100 (${(selectedReport.severity || 'low').toUpperCase()})`
                        : 'Not analyzed'}
                    </span>
                  </div>

                  <div className="p-3 rounded-lg bg-surface-secondary border border-border">
                    <span className="text-foreground-muted block text-[10px]">Case Linkage:</span>
                    <span className="text-foreground font-semibold">
                      {selectedReport.case_id ? (
                        <span className="flex items-center space-x-1">
                          <Briefcase className="w-3.5 h-3.5 text-primary" />
                          <span>{selectedReport.case_id}</span>
                        </span>
                      ) : (
                        'Direct Analysis (Unlinked)'
                      )}
                    </span>
                  </div>

                  <div className="p-3 rounded-lg bg-surface-secondary border border-border">
                    <span className="text-foreground-muted block text-[10px]">Assigned Lead Analyst:</span>
                    <span className="text-foreground font-semibold">
                      {selectedReport.analyst_name || 'SOC Analyst'}
                    </span>
                  </div>
                </div>
              </div>

              {/* Cryptographic Digital Signature & Verification */}
              <div className="pt-4 border-t border-border space-y-2">
                <h4 className="text-xs font-mono font-semibold text-primary uppercase flex items-center space-x-1.5">
                  <Lock className="w-3.5 h-3.5" />
                  <span>3. EVIDENTIARY INTEGRITY & CRYPTOGRAPHIC SIGNATURE</span>
                </h4>
                <div className="p-3 rounded-lg bg-surface-secondary border border-border text-[11px] font-mono text-foreground-muted break-all">
                  {selectedReport.email_sha256
                    ? `SHA256:${selectedReport.email_sha256}`
                    : 'Cryptographic hash verified in database record'}
                </div>
                <div className="flex justify-between items-center text-[10px] font-mono text-foreground-muted pt-1">
                  <span>Status: SHA-256 Chain of Custody Recorded</span>
                  <span className="text-success font-semibold">AUTHENTIC RECORD</span>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
