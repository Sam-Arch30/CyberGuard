import React, { useState, useEffect } from 'react';
import {
  FileText,
  ShieldCheck,
  Lock,
  Share2,
  Copy,
  CheckCircle,
  Clock,
  Eye,
  Plus,
  RefreshCw,
  Search,
  Check,
  Layers,
  Sparkles,
  GitBranch,
} from 'lucide-react';
import type {
  ExecutiveReportListItem,
  ExecutiveReportDetail,
  ReportTemplate,
  ReportSnapshot,
  ReportShareLink,
  ExecutiveReportMetrics,
} from '../../types/executiveReport';
import { executiveReportService } from '../../services/executiveReportService';

export const ExecutiveReportingHub: React.FC = () => {
  // State
  const [reports, setReports] = useState<ExecutiveReportListItem[]>([]);
  const [metrics, setMetrics] = useState<ExecutiveReportMetrics | null>(null);
  const [templates, setTemplates] = useState<ReportTemplate[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [typeFilter, setTypeFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');

  // Modals
  const [showCreateModal, setShowCreateModal] = useState<boolean>(false);
  const [showPreviewModal, setShowPreviewModal] = useState<boolean>(false);
  const [showShareModal, setShowShareModal] = useState<boolean>(false);
  const [showSnapshotModal, setShowSnapshotModal] = useState<boolean>(false);
  const [showReviewModal, setShowReviewModal] = useState<boolean>(false);

  // Selected Report Data
  const [selectedReportId, setSelectedReportId] = useState<string | null>(null);
  const [reportDetail, setReportDetail] = useState<ExecutiveReportDetail | null>(null);
  const [previewHtml, setPreviewHtml] = useState<string>('');
  const [previewRedaction, setPreviewRedaction] = useState<string>('STANDARD');
  const [snapshots, setSnapshots] = useState<ReportSnapshot[]>([]);
  const [shareLinks, setShareLinks] = useState<ReportShareLink[]>([]);

  // Create Form State
  const [createTitle, setCreateTitle] = useState<string>('');
  const [createType, setCreateType] = useState<string>('EXECUTIVE_BRIEFING');
  const [createClassification, setCreateClassification] = useState<string>('CONFIDENTIAL');
  const [createRedaction, setCreateRedaction] = useState<string>('NONE');
  const [createSummary, setCreateSummary] = useState<string>('');
  const [createIncidentId, setCreateIncidentId] = useState<string>('');

  // Share Form State
  const [shareHours, setShareHours] = useState<number>(72);
  const [shareMaxUses, setShareMaxUses] = useState<number>(10);
  const [shareRedaction, setShareRedaction] = useState<string>('STANDARD');
  const [generatedShareToken, setGeneratedShareToken] = useState<string | null>(null);

  // Review Form State
  const [reviewNote, setReviewNote] = useState<string>('');
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 3500);
  };

  const loadData = async () => {
    setLoading(true);
    try {
      const [rData, mData, tData] = await Promise.all([
        executiveReportService.listReports(0, 100, statusFilter, typeFilter),
        executiveReportService.getMetrics(),
        executiveReportService.listTemplates(),
      ]);
      setReports(rData.items);
      setMetrics(mData);
      setTemplates(tData.items);
    } catch (err) {
      console.error('Failed to load executive reporting data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [statusFilter, typeFilter]);

  const handleOpenPreview = async (reportId: string) => {
    setSelectedReportId(reportId);
    try {
      const detail = await executiveReportService.getReport(reportId);
      setReportDetail(detail);
      setPreviewRedaction(detail.redaction_level || 'STANDARD');
      const html = await executiveReportService.getReportPreviewHtml(reportId, detail.redaction_level);
      setPreviewHtml(html);
      setShowPreviewModal(true);
    } catch (err) {
      showToast('Error loading report preview.');
    }
  };

  const handleChangePreviewRedaction = async (newRedaction: string) => {
    if (!selectedReportId) return;
    setPreviewRedaction(newRedaction);
    try {
      const html = await executiveReportService.getReportPreviewHtml(selectedReportId, newRedaction);
      setPreviewHtml(html);
    } catch (err) {
      showToast('Error refreshing preview redaction.');
    }
  };

  const handleOpenShare = async (reportId: string) => {
    setSelectedReportId(reportId);
    setGeneratedShareToken(null);
    try {
      const links = await executiveReportService.listShareLinks(reportId);
      setShareLinks(links.items);
      setShowShareModal(true);
    } catch (err) {
      showToast('Error loading share links.');
    }
  };

  const handleCreateShareLink = async () => {
    if (!selectedReportId) return;
    try {
      const link = await executiveReportService.createShareLink(selectedReportId, {
        expires_in_hours: shareHours,
        max_uses: shareMaxUses,
        redaction_level: shareRedaction,
      });
      if (link.share_token) {
        setGeneratedShareToken(link.share_token);
      }
      const refreshed = await executiveReportService.listShareLinks(selectedReportId);
      setShareLinks(refreshed.items);
      showToast('Cryptographic share link generated.');
    } catch (err) {
      showToast('Failed to create share link.');
    }
  };

  const handleRevokeShareLink = async (linkId: string) => {
    try {
      await executiveReportService.revokeShareLink(linkId);
      if (selectedReportId) {
        const refreshed = await executiveReportService.listShareLinks(selectedReportId);
        setShareLinks(refreshed.items);
      }
      showToast('Share link revoked.');
    } catch (err) {
      showToast('Failed to revoke link.');
    }
  };

  const handleOpenSnapshots = async (reportId: string) => {
    setSelectedReportId(reportId);
    try {
      const snList = await executiveReportService.getReportSnapshots(reportId);
      setSnapshots(snList);
      setShowSnapshotModal(true);
    } catch (err) {
      showToast('Error loading report snapshots.');
    }
  };

  const handleOpenReview = async (reportId: string) => {
    setSelectedReportId(reportId);
    try {
      const detail = await executiveReportService.getReport(reportId);
      setReportDetail(detail);
      setShowReviewModal(true);
    } catch (err) {
      showToast('Error loading report review details.');
    }
  };

  const handleApproveReport = async () => {
    if (!selectedReportId) return;
    try {
      const updated = await executiveReportService.approveReport(selectedReportId, reviewNote || 'Approved by Lead Analyst.');
      setReportDetail(updated);
      showToast('Report formally approved.');
      loadData();
    } catch (err) {
      showToast('Failed to approve report.');
    }
  };

  const handleFinalizeReport = async () => {
    if (!selectedReportId) return;
    try {
      const updated = await executiveReportService.finalizeReport(selectedReportId, reviewNote || 'Locked and finalized.');
      setReportDetail(updated);
      showToast('Report finalized & locked into immutable state.');
      loadData();
    } catch (err) {
      showToast('Failed to finalize report.');
    }
  };

  const handleBranchVersion = async (reportId: string) => {
    try {
      const child = await executiveReportService.createVersion(reportId);
      showToast(`Branched new version: ${child.report_number}`);
      loadData();
    } catch (err) {
      showToast('Failed to branch report version.');
    }
  };

  const handleCreateSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!createTitle.trim()) {
      showToast('Report title is required.');
      return;
    }
    try {
      const created = await executiveReportService.createReport({
        title: createTitle.trim(),
        report_type: createType,
        classification: createClassification,
        redaction_level: createRedaction,
        summary: createSummary.trim() || undefined,
        incident_id: createIncidentId.trim() || undefined,
      });
      setShowCreateModal(false);
      setCreateTitle('');
      setCreateSummary('');
      setCreateIncidentId('');
      showToast(`Created executive report: ${created.report_number}`);
      loadData();
    } catch (err) {
      showToast('Failed to create report.');
    }
  };

  const filteredReports = reports.filter((r) => {
    if (!searchQuery.trim()) return true;
    const q = searchQuery.toLowerCase();
    return (
      r.title.toLowerCase().includes(q) ||
      r.report_number.toLowerCase().includes(q) ||
      r.report_type.toLowerCase().includes(q)
    );
  });

  return (
    <div className="space-y-6">
      {/* Toast Notification */}
      {toastMessage && (
        <div className="fixed bottom-6 right-6 z-50 bg-slate-900 border border-sky-500/50 text-white px-5 py-3 rounded-lg shadow-xl flex items-center space-x-3 text-sm animate-in fade-in slide-in-from-bottom-2">
          <Sparkles className="w-4 h-4 text-sky-400" />
          <span>{toastMessage}</span>
        </div>
      )}

      {/* Header Metric Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-4 flex items-center justify-between">
          <div>
            <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Total Reports</div>
            <div className="text-2xl font-bold text-white mt-1">{metrics?.total_reports ?? 0}</div>
            <div className="text-xs text-slate-500 mt-1">Cross-incident dossiers</div>
          </div>
          <div className="w-10 h-10 rounded-lg bg-sky-500/10 border border-sky-500/20 flex items-center justify-center text-sky-400">
            <FileText className="w-5 h-5" />
          </div>
        </div>

        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-4 flex items-center justify-between">
          <div>
            <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider">In Review</div>
            <div className="text-2xl font-bold text-amber-400 mt-1">{metrics?.in_review_reports ?? 0}</div>
            <div className="text-xs text-slate-500 mt-1">Awaiting peer sign-off</div>
          </div>
          <div className="w-10 h-10 rounded-lg bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-amber-400">
            <Clock className="w-5 h-5" />
          </div>
        </div>

        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-4 flex items-center justify-between">
          <div>
            <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Finalized & Locked</div>
            <div className="text-2xl font-bold text-emerald-400 mt-1">{metrics?.finalized_reports ?? 0}</div>
            <div className="text-xs text-slate-500 mt-1">Immutable with zero drift</div>
          </div>
          <div className="w-10 h-10 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
            <Lock className="w-5 h-5" />
          </div>
        </div>

        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-4 flex items-center justify-between">
          <div>
            <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Active Share Links</div>
            <div className="text-2xl font-bold text-indigo-400 mt-1">{metrics?.active_share_links ?? 0}</div>
            <div className="text-xs text-slate-500 mt-1">Controlled dissemination</div>
          </div>
          <div className="w-10 h-10 rounded-lg bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400">
            <Share2 className="w-5 h-5" />
          </div>
        </div>
      </div>

      {/* Control Bar: Search, Filters & Action Button */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900/40 p-4 rounded-xl border border-slate-800">
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search reports or dossiers..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="bg-slate-950/80 border border-slate-700 text-slate-200 text-sm rounded-lg pl-9 pr-3 py-1.5 focus:outline-none focus:border-sky-500 w-64"
            />
          </div>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="bg-slate-950/80 border border-slate-700 text-slate-300 text-xs rounded-lg px-3 py-2 focus:outline-none focus:border-sky-500"
          >
            <option value="ALL">All Statuses</option>
            <option value="DRAFT">Draft</option>
            <option value="REVIEW_REQUESTED">Review Requested</option>
            <option value="APPROVED">Approved</option>
            <option value="FINALIZED">Finalized</option>
          </select>

          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className="bg-slate-950/80 border border-slate-700 text-slate-300 text-xs rounded-lg px-3 py-2 focus:outline-none focus:border-sky-500"
          >
            <option value="ALL">All Report Types</option>
            <option value="EXECUTIVE_BRIEFING">Executive Briefing</option>
            <option value="TECHNICAL_INCIDENT_DOSSIER">Technical Dossier</option>
            <option value="FORENSIC_CHAIN_OF_CUSTODY">Forensic Custody</option>
            <option value="REGULATORY_COMPLIANCE_DISCLOSURE">Regulatory Disclosure</option>
            <option value="THREAT_ACTOR_INTEL_DISSEMINATION">Threat Actor Intel</option>
          </select>

          <button
            onClick={loadData}
            title="Refresh Catalog"
            className="p-2 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition-colors"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>

        <button
          onClick={() => setShowCreateModal(true)}
          className="bg-sky-600 hover:bg-sky-500 text-white text-xs font-semibold px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors shadow-lg shadow-sky-600/20"
        >
          <Plus className="w-4 h-4" />
          <span>New Executive Report</span>
        </button>
      </div>

      {/* Reports Table */}
      <div className="bg-slate-900/40 border border-slate-800 rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm text-slate-300">
            <thead className="bg-slate-950/60 text-xs font-semibold uppercase tracking-wider text-slate-400 border-b border-slate-800">
              <tr>
                <th className="px-5 py-3.5">Report Number / Title</th>
                <th className="px-4 py-3.5">Type & Classification</th>
                <th className="px-4 py-3.5">Status & Lock</th>
                <th className="px-4 py-3.5">Threat Score</th>
                <th className="px-4 py-3.5">Created</th>
                <th className="px-5 py-3.5 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {loading ? (
                <tr>
                  <td colSpan={6} className="px-5 py-8 text-center text-slate-500">
                    <RefreshCw className="w-5 h-5 animate-spin mx-auto mb-2 text-sky-400" />
                    Loading executive dossiers...
                  </td>
                </tr>
              ) : filteredReports.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-5 py-8 text-center text-slate-500">
                    No executive reports found. Create a report or adjust filters.
                  </td>
                </tr>
              ) : (
                filteredReports.map((r) => {
                  const isFinal = r.status === 'FINALIZED' || r.is_immutable;
                  const isApproved = r.status === 'APPROVED';
                  const isReview = r.status === 'REVIEW_REQUESTED';

                  return (
                    <tr key={r.id} className="hover:bg-slate-800/30 transition-colors">
                      <td className="px-5 py-3.5">
                        <div className="flex items-center space-x-2.5">
                          <div className="p-2 rounded-lg bg-sky-500/10 border border-sky-500/20 text-sky-400">
                            <FileText className="w-4 h-4" />
                          </div>
                          <div>
                            <div className="font-medium text-white flex items-center space-x-2">
                              <span>{r.title}</span>
                              <span className="text-xs font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                                v{r.report_version}
                              </span>
                            </div>
                            <div className="text-xs font-mono text-slate-400 mt-0.5">{r.report_number}</div>
                          </div>
                        </div>
                      </td>

                      <td className="px-4 py-3.5">
                        <div className="space-y-1">
                          <div className="text-xs font-medium text-slate-300">
                            {r.report_type.replace(/_/g, ' ')}
                          </div>
                          <span className="inline-block text-[10px] font-semibold tracking-wider uppercase px-2 py-0.5 rounded-full bg-indigo-500/10 border border-indigo-500/30 text-indigo-300">
                            {r.classification}
                          </span>
                        </div>
                      </td>

                      <td className="px-4 py-3.5">
                        <div className="flex items-center space-x-1.5">
                          {isFinal ? (
                            <span className="inline-flex items-center space-x-1 px-2.5 py-1 rounded-full text-xs font-medium bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
                              <Lock className="w-3 h-3" />
                              <span>FINALIZED</span>
                            </span>
                          ) : isApproved ? (
                            <span className="inline-flex items-center space-x-1 px-2.5 py-1 rounded-full text-xs font-medium bg-sky-500/10 border border-sky-500/30 text-sky-400">
                              <ShieldCheck className="w-3 h-3" />
                              <span>APPROVED</span>
                            </span>
                          ) : isReview ? (
                            <span className="inline-flex items-center space-x-1 px-2.5 py-1 rounded-full text-xs font-medium bg-amber-500/10 border border-amber-500/30 text-amber-400">
                              <Clock className="w-3 h-3" />
                              <span>IN REVIEW</span>
                            </span>
                          ) : (
                            <span className="inline-flex items-center space-x-1 px-2.5 py-1 rounded-full text-xs font-medium bg-slate-800 border border-slate-700 text-slate-400">
                              <span>DRAFT</span>
                            </span>
                          )}
                        </div>
                      </td>

                      <td className="px-4 py-3.5">
                        <div className="flex items-center space-x-2">
                          <div className="text-xs font-bold text-white">
                            {r.threat_score.toFixed(1)}
                          </div>
                          <div className="w-16 h-1.5 rounded-full bg-slate-800 overflow-hidden">
                            <div
                              className={`h-full rounded-full ${
                                r.threat_score > 70
                                  ? 'bg-rose-500'
                                  : r.threat_score > 40
                                  ? 'bg-amber-500'
                                  : 'bg-emerald-500'
                              }`}
                              style={{ width: `${Math.min(100, r.threat_score)}%` }}
                            />
                          </div>
                        </div>
                      </td>

                      <td className="px-4 py-3.5 text-xs text-slate-400 font-mono">
                        {new Date(r.created_at).toLocaleDateString()}
                      </td>

                      <td className="px-5 py-3.5 text-right">
                        <div className="flex items-center justify-end space-x-1.5">
                          <button
                            onClick={() => handleOpenPreview(r.id)}
                            title="Interactive HTML Preview"
                            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white transition-colors"
                          >
                            <Eye className="w-4 h-4" />
                          </button>

                          <button
                            onClick={() => handleOpenSnapshots(r.id)}
                            title="Inspect Immutable Snapshot"
                            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-sky-400 transition-colors"
                          >
                            <Layers className="w-4 h-4" />
                          </button>

                          <button
                            onClick={() => handleOpenShare(r.id)}
                            title="Disseminate & Share Links"
                            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-indigo-400 transition-colors"
                          >
                            <Share2 className="w-4 h-4" />
                          </button>

                          <button
                            onClick={() => handleOpenReview(r.id)}
                            title="Review & Approval Gate"
                            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-amber-400 transition-colors"
                          >
                            <ShieldCheck className="w-4 h-4" />
                          </button>

                          {isFinal && (
                            <button
                              onClick={() => handleBranchVersion(r.id)}
                              title="Branch New Version (v+1)"
                              className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-emerald-400 transition-colors"
                            >
                              <GitBranch className="w-4 h-4" />
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* MODAL 1: Create Executive Report Wizard */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-lg p-6 space-y-5 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center space-x-2">
                <FileText className="w-5 h-5 text-sky-400" />
                <h3 className="text-base font-semibold text-white">Generate Executive Report</h3>
              </div>
              <button
                onClick={() => setShowCreateModal(false)}
                className="text-slate-400 hover:text-white text-sm"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleCreateSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Dossier Title</label>
                <input
                  type="text"
                  placeholder="e.g. Critical Intrusion Briefing: Q4 Supply Chain Breach"
                  value={createTitle}
                  onChange={(e) => setCreateTitle(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-sky-500"
                  required
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">Report Template</label>
                  <select
                    value={createType}
                    onChange={(e) => setCreateType(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-sky-500"
                  >
                    {templates.length > 0 ? (
                      templates.map((tpl) => (
                        <option key={tpl.id} value={tpl.report_type}>
                          {tpl.template_name}
                        </option>
                      ))
                    ) : (
                      <>
                        <option value="EXECUTIVE_BRIEFING">Executive Briefing</option>
                        <option value="TECHNICAL_INCIDENT_DOSSIER">Technical Dossier</option>
                        <option value="FORENSIC_CHAIN_OF_CUSTODY">Forensic Custody Ledger</option>
                        <option value="REGULATORY_COMPLIANCE_DISCLOSURE">Regulatory Disclosure (SEC/GDPR)</option>
                        <option value="THREAT_ACTOR_INTEL_DISSEMINATION">Threat Actor Intel</option>
                      </>
                    )}
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">Classification</label>
                  <select
                    value={createClassification}
                    onChange={(e) => setCreateClassification(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-sky-500"
                  >
                    <option value="CONFIDENTIAL">CONFIDENTIAL</option>
                    <option value="RESTRICTED">RESTRICTED</option>
                    <option value="INTERNAL">INTERNAL</option>
                    <option value="PUBLIC">PUBLIC</option>
                    <option value="TLP_AMBER">TLP:AMBER</option>
                    <option value="TLP_RED">TLP:RED</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">Redaction Level</label>
                  <select
                    value={createRedaction}
                    onChange={(e) => setCreateRedaction(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-sky-500"
                  >
                    <option value="NONE">None (Full Telemetry)</option>
                    <option value="STANDARD">Standard (Mask Emails & Secrets)</option>
                    <option value="STRICT">Strict (Mask IPs, Secrets & PII)</option>
                    <option value="LEGAL_PRIVILEGED">Attorney-Client Privileged</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">Incident Binding (Optional)</label>
                  <input
                    type="text"
                    placeholder="Incident UUID"
                    value={createIncidentId}
                    onChange={(e) => setCreateIncidentId(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-sky-500 font-mono"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Executive Summary</label>
                <textarea
                  rows={3}
                  placeholder="Key takeaways, business risk exposure, and recommended immediate action..."
                  value={createSummary}
                  onChange={(e) => setCreateSummary(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-sky-500"
                />
              </div>

              <div className="pt-2 flex justify-end space-x-2">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-lg bg-sky-600 hover:bg-sky-500 text-white text-xs font-semibold shadow-lg shadow-sky-600/20"
                >
                  Freeze Snapshot & Generate
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* MODAL 2: Interactive HTML Previewer */}
      {showPreviewModal && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-md flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-4xl h-[85vh] flex flex-col shadow-2xl overflow-hidden">
            <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-950/80">
              <div className="flex items-center space-x-3">
                <FileText className="w-5 h-5 text-sky-400" />
                <div>
                  <h3 className="text-sm font-semibold text-white">
                    {reportDetail?.report_number}: {reportDetail?.title}
                  </h3>
                  <div className="text-xs text-slate-400 font-mono">
                    Snapshot Hash: {reportDetail?.source_data_hash?.slice(0, 16)}...
                  </div>
                </div>
              </div>

              <div className="flex items-center space-x-3">
                <div className="flex items-center space-x-1 bg-slate-900 border border-slate-800 rounded-lg p-1">
                  <span className="text-[11px] text-slate-400 px-2 font-medium">Redaction:</span>
                  {(['NONE', 'STANDARD', 'STRICT'] as const).map((rLevel) => (
                    <button
                      key={rLevel}
                      onClick={() => handleChangePreviewRedaction(rLevel)}
                      className={`text-xs px-2.5 py-1 rounded-md transition-colors ${
                        previewRedaction === rLevel
                          ? 'bg-sky-600 text-white font-semibold'
                          : 'text-slate-400 hover:text-white'
                      }`}
                    >
                      {rLevel}
                    </button>
                  ))}
                </div>

                <button
                  onClick={() => setShowPreviewModal(false)}
                  className="text-slate-400 hover:text-white p-1 text-sm"
                >
                  ✕
                </button>
              </div>
            </div>

            <div className="flex-1 overflow-auto bg-slate-950 p-4">
              <iframe
                title="Report Preview"
                srcDoc={previewHtml}
                className="w-full h-full rounded-xl border border-slate-800 shadow-inner bg-slate-900"
              />
            </div>
          </div>
        </div>
      )}

      {/* MODAL 3: Share Links & External Dissemination */}
      {showShareModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-xl p-6 space-y-5 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center space-x-2">
                <Share2 className="w-5 h-5 text-indigo-400" />
                <h3 className="text-base font-semibold text-white">External Dissemination & Share Links</h3>
              </div>
              <button
                onClick={() => setShowShareModal(false)}
                className="text-slate-400 hover:text-white text-sm"
              >
                ✕
              </button>
            </div>

            {/* Generated Token Alert */}
            {generatedShareToken && (
              <div className="p-3 rounded-lg bg-indigo-500/10 border border-indigo-500/30 text-indigo-200 text-xs space-y-2">
                <div className="font-semibold flex items-center space-x-1 text-indigo-300">
                  <CheckCircle className="w-4 h-4 text-emerald-400" />
                  <span>Secure Share Token Generated (Shown Only Once)</span>
                </div>
                <div className="bg-slate-950 p-2 rounded border border-slate-800 font-mono text-xs break-all flex items-center justify-between">
                  <span>{generatedShareToken}</span>
                  <button
                    onClick={() => {
                      navigator.clipboard.writeText(
                        `${window.location.origin}/api/executive-reports/public/share/${generatedShareToken}/html`
                      );
                      showToast('Copied public URL to clipboard.');
                    }}
                    className="p-1 hover:text-white text-indigo-400"
                    title="Copy Public Link"
                  >
                    <Copy className="w-4 h-4" />
                  </button>
                </div>
              </div>
            )}

            {/* Create Share Link Parameters */}
            <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-3">
              <div className="text-xs font-semibold text-slate-300">Issue New Cryptographic Share Link</div>
              <div className="grid grid-cols-3 gap-2">
                <div>
                  <label className="block text-[11px] text-slate-400 mb-1">Expires In</label>
                  <select
                    value={shareHours}
                    onChange={(e) => setShareHours(Number(e.target.value))}
                    className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 text-xs text-white"
                  >
                    <option value={24}>24 Hours</option>
                    <option value={72}>72 Hours</option>
                    <option value={168}>7 Days</option>
                    <option value={720}>30 Days</option>
                  </select>
                </div>

                <div>
                  <label className="block text-[11px] text-slate-400 mb-1">Max Uses</label>
                  <input
                    type="number"
                    min={1}
                    max={100}
                    value={shareMaxUses}
                    onChange={(e) => setShareMaxUses(Number(e.target.value))}
                    className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 text-xs text-white"
                  />
                </div>

                <div>
                  <label className="block text-[11px] text-slate-400 mb-1">Redaction</label>
                  <select
                    value={shareRedaction}
                    onChange={(e) => setShareRedaction(e.target.value)}
                    className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 text-xs text-white"
                  >
                    <option value="STANDARD">Standard</option>
                    <option value="STRICT">Strict</option>
                    <option value="NONE">None</option>
                  </select>
                </div>
              </div>

              <button
                onClick={handleCreateShareLink}
                className="w-full py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-xs font-semibold shadow-lg shadow-indigo-600/20"
              >
                Generate Time-Bounded Share Token
              </button>
            </div>

            {/* Existing Links List */}
            <div className="space-y-2">
              <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Active Links</div>
              {shareLinks.length === 0 ? (
                <div className="text-xs text-slate-500 py-3 text-center">No active share links issued yet.</div>
              ) : (
                <div className="max-h-48 overflow-y-auto space-y-2 pr-1">
                  {shareLinks.map((lnk) => (
                    <div
                      key={lnk.id}
                      className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between text-xs"
                    >
                      <div>
                        <div className="text-slate-200 font-medium flex items-center space-x-2">
                          <span>Uses: {lnk.use_count} / {lnk.max_uses}</span>
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-400">
                            {lnk.redaction_level}
                          </span>
                          {lnk.is_revoked && (
                            <span className="text-[10px] px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-400">
                              REVOKED
                            </span>
                          )}
                        </div>
                        <div className="text-slate-500 text-[10px] mt-0.5">
                          Expires: {new Date(lnk.expires_at).toLocaleString()}
                        </div>
                      </div>

                      {!lnk.is_revoked && (
                        <button
                          onClick={() => handleRevokeShareLink(lnk.id)}
                          className="px-2 py-1 rounded bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 text-[11px] font-medium transition-colors"
                        >
                          Revoke
                        </button>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* MODAL 4: Point-in-Time Snapshot Inspector */}
      {showSnapshotModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-xl p-6 space-y-5 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center space-x-2">
                <Layers className="w-5 h-5 text-sky-400" />
                <h3 className="text-base font-semibold text-white">Immutable Snapshot & Lineage</h3>
              </div>
              <button
                onClick={() => setShowSnapshotModal(false)}
                className="text-slate-400 hover:text-white text-sm"
              >
                ✕
              </button>
            </div>

            <div className="space-y-3">
              {snapshots.length === 0 ? (
                <div className="text-xs text-slate-500 text-center py-6">No snapshots recorded for this report.</div>
              ) : (
                snapshots.map((sn, idx) => (
                  <div key={sn.id} className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-semibold text-sky-400">Snapshot #{idx + 1}</span>
                      <span className="text-[11px] font-mono text-slate-500">
                        {new Date(sn.created_at).toLocaleString()}
                      </span>
                    </div>

                    <div>
                      <div className="text-[11px] text-slate-400 uppercase font-semibold">Cryptographic Digest (SHA-256)</div>
                      <div className="text-xs font-mono text-slate-300 break-all bg-slate-900 p-2 rounded mt-1 border border-slate-800">
                        {sn.snapshot_hash}
                      </div>
                    </div>

                    <div className="grid grid-cols-2 gap-2 text-xs">
                      <div className="p-2 rounded bg-slate-900 border border-slate-800">
                        <div className="text-[10px] text-slate-400">Data Drift Guard</div>
                        <div className="text-emerald-400 font-semibold mt-0.5">ACTIVE (100% Frozen)</div>
                      </div>
                      <div className="p-2 rounded bg-slate-900 border border-slate-800">
                        <div className="text-[10px] text-slate-400">Epistemic Status</div>
                        <div className="text-sky-400 font-semibold mt-0.5">AUTHORITATIVE FACT</div>
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}

      {/* MODAL 5: Review & Approval Gate */}
      {showReviewModal && reportDetail && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-lg p-6 space-y-5 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center space-x-2">
                <ShieldCheck className="w-5 h-5 text-amber-400" />
                <h3 className="text-base font-semibold text-white">
                  Review & Approval Gate: {reportDetail.report_number}
                </h3>
              </div>
              <button
                onClick={() => setShowReviewModal(false)}
                className="text-slate-400 hover:text-white text-sm"
              >
                ✕
              </button>
            </div>

            <div className="space-y-4">
              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 text-xs space-y-1.5">
                <div className="text-slate-400">
                  Current Status: <strong className="text-white">{reportDetail.status}</strong>
                </div>
                <div className="text-slate-400">
                  Approved By:{' '}
                  <strong className="text-emerald-400">{reportDetail.approved_by || 'Awaiting Approval'}</strong>
                </div>
                <div className="text-slate-400">
                  Finalized Lock:{' '}
                  <strong className={reportDetail.is_immutable ? 'text-emerald-400' : 'text-amber-400'}>
                    {reportDetail.is_immutable ? 'IMMUTABLE (LOCKED)' : 'MUTABLE DRAFT'}
                  </strong>
                </div>
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Sign-off / Reviewer Attestation Notes
                </label>
                <textarea
                  rows={3}
                  placeholder="Attest findings, confirm containment verification, or note recommendations..."
                  value={reviewNote}
                  onChange={(e) => setReviewNote(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs text-white focus:outline-none focus:border-amber-500"
                />
              </div>

              <div className="flex items-center justify-end space-x-2 pt-2 border-t border-slate-800">
                {!reportDetail.is_immutable && (
                  <>
                    <button
                      onClick={handleApproveReport}
                      className="px-3.5 py-2 rounded-lg bg-sky-600 hover:bg-sky-500 text-white text-xs font-semibold flex items-center space-x-1.5 shadow-lg shadow-sky-600/20"
                    >
                      <Check className="w-4 h-4" />
                      <span>Formal Sign-off</span>
                    </button>

                    <button
                      onClick={handleFinalizeReport}
                      className="px-3.5 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold flex items-center space-x-1.5 shadow-lg shadow-emerald-600/20"
                    >
                      <Lock className="w-4 h-4" />
                      <span>Finalize & Lock</span>
                    </button>
                  </>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
