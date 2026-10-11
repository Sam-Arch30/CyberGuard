/**
 * Section 68: Evidence & Forensics Workspace.
 * Authoritative analyst workspace for forensic evidence management, cryptographic integrity verification,
 * immutable chain-of-custody ledgers, provenance lineage trees, safe bounded previews, and legal exports.
 */
import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  ShieldCheck,
  ShieldAlert,
  Search,
  Upload,
  RefreshCw,
  FileText,
  Lock,
  GitBranch,
  Download,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Clock,
  Hash,
  Copy,
  Check,
  ArrowRight,
  Plus,
  Scale,
  FileCode,
  Eye,
  Info,
} from 'lucide-react';
import { evidenceWorkspaceService } from '../services/evidenceWorkspaceService';
import type {
  EvidenceListItem,
  EvidenceDetail,
  EvidenceMetrics,
  EvidencePreviewResponse,
  EvidenceExportManifestResponse,
  EvidenceIntegrityVerificationResponse,
  EvidenceSourceType,
  EvidenceClassification,
  CustodyEventType,
} from '../types/evidenceWorkspace';

export const EvidenceWorkspace: React.FC = () => {
  const { id: routeEvidenceId } = useParams<{ id: string }>();
  const navigate = useNavigate();

  // State
  const [evidenceList, setEvidenceList] = useState<EvidenceListItem[]>([]);
  const [metrics, setMetrics] = useState<EvidenceMetrics | null>(null);
  const [selectedEvidence, setSelectedEvidence] = useState<EvidenceDetail | null>(null);
  const [previewData, setPreviewData] = useState<EvidencePreviewResponse | null>(null);
  const [manifestData, setManifestData] = useState<EvidenceExportManifestResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [loadingDetail, setLoadingDetail] = useState<boolean>(false);
  const [loadingPreview, setLoadingPreview] = useState<boolean>(false);
  const [actionMessage, setActionMessage] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Filters
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [sourceFilter, setSourceFilter] = useState<string>('');
  const [integrityFilter, setIntegrityFilter] = useState<string>('');
  const [preservationFilter, setPreservationFilter] = useState<string>('');
  const [activeTab, setActiveTab] = useState<'overview' | 'custody' | 'preview' | 'lineage' | 'manifest' | 'notes'>('overview');

  // Modals
  const [showUploadModal, setShowUploadModal] = useState<boolean>(false);
  const [showPreserveModal, setShowPreserveModal] = useState<boolean>(false);
  const [showCustodyModal, setShowCustodyModal] = useState<boolean>(false);
  const [showDeriveModal, setShowDeriveModal] = useState<boolean>(false);

  // Modal Forms
  const [uploadFilename, setUploadFilename] = useState<string>('');
  const [uploadSourceType, setUploadSourceType] = useState<EvidenceSourceType>('FILE');
  const [uploadClassification, setUploadClassification] = useState<EvidenceClassification>('INTERNAL');
  const [uploadContentText, setUploadContentText] = useState<string>('');
  const [uploadNotes, setUploadNotes] = useState<string>('');

  const [preserveStatus, setPreserveStatus] = useState<'NORMAL' | 'PRESERVED' | 'ON_HOLD'>('ON_HOLD');
  const [preserveReason, setPreserveReason] = useState<string>('');
  const [preserveNotes, setPreserveNotes] = useState<string>('');

  const [custodyType, setCustodyType] = useState<CustodyEventType>('TRANSFERRED');
  const [custodySource, setCustodySource] = useState<string>('');
  const [custodyDestination, setCustodyDestination] = useState<string>('');
  const [custodyReason, setCustodyReason] = useState<string>('');

  const [deriveTool, setDeriveTool] = useState<string>('Forensic String Extractor');
  const [deriveToolVersion, setDeriveToolVersion] = useState<string>('1.0');
  const [deriveDesc, setDeriveDesc] = useState<string>('Extracted decoded strings and active indicators.');
  const [deriveFilename, setDeriveFilename] = useState<string>('extracted_strings.txt');
  const [deriveContent, setDeriveContent] = useState<string>('');

  // Initial Fetch
  const fetchList = async () => {
    try {
      setLoading(true);
      const res = await evidenceWorkspaceService.listEvidence({
        query: searchQuery || undefined,
        source_type: sourceFilter || undefined,
        integrity_status: integrityFilter || undefined,
        preservation_status: preservationFilter || undefined,
      });
      setEvidenceList(res.items);
      setMetrics(res.metrics);

      // Select item if requested via URL or first item
      if (routeEvidenceId) {
        loadDetail(routeEvidenceId);
      } else if (res.items.length > 0 && !selectedEvidence) {
        loadDetail(res.items[0].id);
      }
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to fetch forensic evidence.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchList();
  }, [searchQuery, sourceFilter, integrityFilter, preservationFilter]);

  const loadDetail = async (id: string) => {
    try {
      setLoadingDetail(true);
      setPreviewData(null);
      setManifestData(null);
      const detail = await evidenceWorkspaceService.getDetail(id);
      setSelectedEvidence(detail);
      if (activeTab === 'preview') {
        loadPreview(detail.id);
      }
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to load evidence details.');
    } finally {
      setLoadingDetail(false);
    }
  };

  const loadPreview = async (id: string) => {
    try {
      setLoadingPreview(true);
      const prev = await evidenceWorkspaceService.getPreview(id);
      setPreviewData(prev);
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to load preview.');
    } finally {
      setLoadingPreview(false);
    }
  };

  const handleTabChange = (tab: typeof activeTab) => {
    setActiveTab(tab);
    if (tab === 'preview' && selectedEvidence && !previewData) {
      loadPreview(selectedEvidence.id);
    }
  };

  const handleVerifyIntegrity = async () => {
    if (!selectedEvidence) return;
    try {
      setActionMessage('Re-verifying cryptographic hash against physical disk bytes...');
      const res: EvidenceIntegrityVerificationResponse = await evidenceWorkspaceService.verifyIntegrity(selectedEvidence.id);
      setActionMessage(`Integrity check completed: ${res.status}. ${res.message}`);
      loadDetail(selectedEvidence.id);
      fetchList();
    } catch (err: any) {
      setErrorMessage(err.message || 'Integrity reverification failed.');
    }
  };

  const handlePreservationSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedEvidence || !preserveReason) return;
    try {
      await evidenceWorkspaceService.setPreservation(selectedEvidence.id, {
        preservation_status: preserveStatus,
        reason: preserveReason,
        notes: preserveNotes,
      });
      setShowPreserveModal(false);
      setPreserveReason('');
      setActionMessage(`Preservation status updated to ${preserveStatus}.`);
      loadDetail(selectedEvidence.id);
      fetchList();
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to update preservation status.');
    }
  };

  const handleCustodySubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedEvidence || !custodyReason) return;
    try {
      await evidenceWorkspaceService.addCustodyEvent(selectedEvidence.id, {
        event_type: custodyType,
        source: custodySource || undefined,
        destination: custodyDestination || undefined,
        reason: custodyReason,
      });
      setShowCustodyModal(false);
      setCustodyReason('');
      setActionMessage(`Chain of custody event recorded: ${custodyType}.`);
      loadDetail(selectedEvidence.id);
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to record custody transaction.');
    }
  };

  const handleDeriveSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedEvidence) return;
    try {
      await evidenceWorkspaceService.deriveEvidence(selectedEvidence.id, {
        transformation_tool: deriveTool,
        tool_version: deriveToolVersion,
        transformation_description: deriveDesc,
        child_filename: deriveFilename,
        child_raw_text: deriveContent,
      });
      setShowDeriveModal(false);
      setActionMessage('Child derivative artifact created and linked to parent lineage.');
      loadDetail(selectedEvidence.id);
      fetchList();
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to create child derivative.');
    }
  };

  const handleUploadSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const created = await evidenceWorkspaceService.registerJson({
        original_filename: uploadFilename,
        source_type: uploadSourceType,
        classification: uploadClassification,
        raw_content_utf8: uploadContentText,
        notes: uploadNotes,
      });
      setShowUploadModal(false);
      setUploadFilename('');
      setUploadContentText('');
      setActionMessage(`Evidence registered successfully: ${created.evidence_id}`);
      fetchList();
      loadDetail(created.id);
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to register evidence.');
    }
  };

  const handleExportManifest = async () => {
    if (!selectedEvidence) return;
    try {
      const manifest = await evidenceWorkspaceService.exportManifest(selectedEvidence.id);
      setManifestData(manifest);
      setActiveTab('manifest');
      setActionMessage(`Forensic export manifest ${manifest.manifest_id} generated.`);
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to generate export manifest.');
    }
  };

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  return (
    <div className="flex flex-col min-h-screen bg-slate-950 text-slate-100 font-sans">
      {/* Workspace Header */}
      <header className="border-b border-slate-800 bg-slate-900/60 backdrop-blur px-6 py-4">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
              <ShieldCheck className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-xl font-bold tracking-tight text-white">Evidence & Forensics Workspace</h1>
                <span className="px-2 py-0.5 text-xs font-mono font-medium rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                  SECTION 68
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Cryptographic integrity, immutable chain-of-custody, provenance lineage & legal export packages
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => {
                setActionMessage('Running scheduled workspace integrity sweep...');
                fetchList();
              }}
              className="px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-800/80 hover:bg-slate-700 text-xs font-medium text-slate-200 transition flex items-center gap-1.5"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              Sweep Integrity
            </button>
            <button
              onClick={() => setShowUploadModal(true)}
              className="px-3.5 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-semibold shadow-sm transition flex items-center gap-1.5"
            >
              <Upload className="w-3.5 h-3.5" />
              Acquire Evidence
            </button>
          </div>
        </div>

        {/* Status Banners */}
        {actionMessage && (
          <div className="mt-3 px-3 py-2 rounded-lg bg-cyan-950/60 border border-cyan-800 text-cyan-300 text-xs flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Info className="w-4 h-4 text-cyan-400" />
              <span>{actionMessage}</span>
            </div>
            <button onClick={() => setActionMessage(null)} className="text-cyan-400 hover:text-cyan-200">
              <XCircle className="w-3.5 h-3.5" />
            </button>
          </div>
        )}
        {errorMessage && (
          <div className="mt-3 px-3 py-2 rounded-lg bg-rose-950/60 border border-rose-800 text-rose-300 text-xs flex items-center justify-between">
            <div className="flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-rose-400" />
              <span>{errorMessage}</span>
            </div>
            <button onClick={() => setErrorMessage(null)} className="text-rose-400 hover:text-rose-200">
              <XCircle className="w-3.5 h-3.5" />
            </button>
          </div>
        )}

        {/* Metrics Row */}
        {metrics && (
          <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-5 gap-3 mt-4">
            <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800">
              <span className="text-xs text-slate-400 block font-medium">Total Evidence Items</span>
              <span className="text-lg font-bold text-white font-mono">{metrics.total_evidence}</span>
            </div>
            <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800">
              <span className="text-xs text-emerald-400 block font-medium flex items-center gap-1">
                <CheckCircle2 className="w-3 h-3" /> Verified Authentic
              </span>
              <span className="text-lg font-bold text-emerald-400 font-mono">{metrics.verified_count}</span>
            </div>
            <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800">
              <span className="text-xs text-rose-400 block font-medium flex items-center gap-1">
                <AlertTriangle className="w-3 h-3" /> Hash Mismatches
              </span>
              <span className="text-lg font-bold text-rose-400 font-mono">{metrics.mismatch_count}</span>
            </div>
            <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800">
              <span className="text-xs text-purple-400 block font-medium flex items-center gap-1">
                <Lock className="w-3 h-3" /> Legal / Preserved Holds
              </span>
              <span className="text-lg font-bold text-purple-400 font-mono">{metrics.preserved_count}</span>
            </div>
            <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800 col-span-2 sm:col-span-1">
              <span className="text-xs text-slate-400 block font-medium">Pending Verifications</span>
              <span className="text-lg font-bold text-amber-400 font-mono">{metrics.pending_count}</span>
            </div>
          </div>
        )}
      </header>

      {/* Main Workspace Body: Split View */}
      <div className="flex-1 flex overflow-hidden">
        {/* Left Pane: Evidence Inventory & Filters */}
        <section className="w-full lg:w-5/12 border-r border-slate-800 flex flex-col bg-slate-950/80">
          {/* Search & Filters */}
          <div className="p-4 border-b border-slate-800/80 space-y-3">
            <div className="relative">
              <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search by filename, Evidence ID, or SHA-256..."
                className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
              />
            </div>
            <div className="grid grid-cols-3 gap-2">
              <select
                value={sourceFilter}
                onChange={(e) => setSourceFilter(e.target.value)}
                className="px-2 py-1 rounded bg-slate-900 border border-slate-800 text-xs text-slate-300 focus:outline-none"
              >
                <option value="">All Sources</option>
                <option value="EMAIL">Email</option>
                <option value="ATTACHMENT">Attachment</option>
                <option value="FILE">File</option>
                <option value="MEMORY_DUMP">Memory Dump</option>
                <option value="NETWORK_FLOW">Network Flow</option>
                <option value="TELEMETRY">Telemetry</option>
              </select>
              <select
                value={integrityFilter}
                onChange={(e) => setIntegrityFilter(e.target.value)}
                className="px-2 py-1 rounded bg-slate-900 border border-slate-800 text-xs text-slate-300 focus:outline-none"
              >
                <option value="">All Integrity</option>
                <option value="VERIFIED">Verified</option>
                <option value="MISMATCH">Mismatch</option>
                <option value="PENDING">Pending</option>
              </select>
              <select
                value={preservationFilter}
                onChange={(e) => setPreservationFilter(e.target.value)}
                className="px-2 py-1 rounded bg-slate-900 border border-slate-800 text-xs text-slate-300 focus:outline-none"
              >
                <option value="">All Holds</option>
                <option value="ON_HOLD">On Hold</option>
                <option value="PRESERVED">Preserved</option>
                <option value="NORMAL">Normal</option>
              </select>
            </div>
          </div>

          {/* Evidence List */}
          <div className="flex-1 overflow-y-auto divide-y divide-slate-800/60">
            {loading ? (
              <div className="p-8 text-center text-slate-500 text-xs flex items-center justify-center gap-2">
                <RefreshCw className="w-4 h-4 animate-spin text-cyan-400" />
                Loading forensic evidence records...
              </div>
            ) : evidenceList.length === 0 ? (
              <div className="p-8 text-center text-slate-500 text-xs">
                No forensic evidence matches criteria.
              </div>
            ) : (
              evidenceList.map((item) => {
                const isSelected = selectedEvidence?.id === item.id;
                return (
                  <div
                    key={item.id}
                    onClick={() => {
                      loadDetail(item.id);
                      navigate(`/evidence/${item.evidence_id}`, { replace: true });
                    }}
                    className={`p-3.5 cursor-pointer transition flex flex-col gap-2 ${
                      isSelected
                        ? 'bg-slate-900 border-l-2 border-cyan-400'
                        : 'hover:bg-slate-900/50'
                    }`}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div className="flex items-center gap-2 truncate">
                        <FileCode className="w-4 h-4 text-cyan-400 shrink-0" />
                        <span className="font-semibold text-xs text-slate-200 truncate">
                          {item.original_filename}
                        </span>
                      </div>
                      <span className="font-mono text-[11px] text-cyan-400 bg-cyan-950/60 border border-cyan-800/60 px-1.5 py-0.5 rounded shrink-0">
                        {item.evidence_id}
                      </span>
                    </div>

                    <div className="flex items-center gap-2 text-[11px] text-slate-400 font-mono truncate">
                      <span className="truncate">SHA-256: {item.sha256.slice(0, 16)}...</span>
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          copyToClipboard(item.sha256, `hash-${item.id}`);
                        }}
                        className="text-slate-500 hover:text-slate-300"
                        title="Copy SHA-256"
                      >
                        {copiedKey === `hash-${item.id}` ? (
                          <Check className="w-3 h-3 text-emerald-400" />
                        ) : (
                          <Copy className="w-3 h-3" />
                        )}
                      </button>
                    </div>

                    <div className="flex flex-wrap items-center gap-1.5 mt-1">
                      {/* Integrity Badge */}
                      <span
                        className={`text-[10px] font-medium px-2 py-0.5 rounded-full flex items-center gap-1 ${
                          item.integrity_status === 'VERIFIED'
                            ? 'bg-emerald-950/80 text-emerald-300 border border-emerald-800/60'
                            : item.integrity_status === 'MISMATCH'
                            ? 'bg-rose-950/80 text-rose-300 border border-rose-800/60'
                            : 'bg-amber-950/80 text-amber-300 border border-amber-800/60'
                        }`}
                      >
                        {item.integrity_status === 'VERIFIED' ? (
                          <CheckCircle2 className="w-2.5 h-2.5" />
                        ) : (
                          <AlertTriangle className="w-2.5 h-2.5" />
                        )}
                        {item.integrity_status}
                      </span>

                      {/* Source Type */}
                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">
                        {item.source_type}
                      </span>

                      {/* Preservation Hold Badge */}
                      {item.preservation_status !== 'NORMAL' && (
                        <span className="text-[10px] font-medium px-2 py-0.5 rounded-full bg-purple-950/80 text-purple-300 border border-purple-800/60 flex items-center gap-1">
                          <Lock className="w-2.5 h-2.5" />
                          {item.preservation_status}
                        </span>
                      )}

                      <span className="text-[10px] text-slate-500 ml-auto">
                        {(item.size / 1024).toFixed(1)} KB
                      </span>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </section>

        {/* Right Pane: Selected Evidence Detail */}
        <main className="w-full lg:w-7/12 flex flex-col bg-slate-900/30 overflow-y-auto">
          {loadingDetail ? (
            <div className="flex-1 flex items-center justify-center text-slate-500 text-xs gap-2">
              <RefreshCw className="w-4 h-4 animate-spin text-cyan-400" />
              Loading forensic record...
            </div>
          ) : !selectedEvidence ? (
            <div className="flex-1 flex flex-col items-center justify-center text-slate-500 p-8 text-center text-xs">
              <ShieldAlert className="w-8 h-8 text-slate-600 mb-2" />
              Select an evidence artifact from the inventory list to inspect chain-of-custody, cryptographic hashes,
              and safe content preview.
            </div>
          ) : (
            <div className="flex flex-col flex-1">
              {/* Top Banner / Detail Header */}
              <div className="border-b border-slate-800 p-6 bg-slate-900/60 backdrop-blur">
                <div className="flex flex-wrap items-start justify-between gap-4">
                  <div>
                    <div className="flex items-center gap-2">
                      <h2 className="text-lg font-bold text-white">{selectedEvidence.original_filename}</h2>
                      <span className="font-mono text-xs px-2 py-0.5 rounded bg-cyan-950/80 border border-cyan-800 text-cyan-400">
                        {selectedEvidence.evidence_id}
                      </span>
                    </div>
                    <div className="flex items-center gap-3 mt-1 text-xs text-slate-400">
                      <span>MIME: {selectedEvidence.mime_type}</span>
                      <span>•</span>
                      <span>Collected: {new Date(selectedEvidence.collected_at).toLocaleString()}</span>
                      <span>•</span>
                      <span>By: {selectedEvidence.collected_by}</span>
                    </div>
                  </div>

                  {/* Top Action Buttons */}
                  <div className="flex items-center gap-2 flex-wrap">
                    <button
                      onClick={handleVerifyIntegrity}
                      className="px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-800 hover:bg-slate-700 text-xs font-medium text-slate-200 transition flex items-center gap-1.5"
                    >
                      <RefreshCw className="w-3.5 h-3.5 text-cyan-400" />
                      Verify Integrity
                    </button>
                    <button
                      onClick={() => {
                        setPreserveStatus(selectedEvidence.preservation_status);
                        setShowPreserveModal(true);
                      }}
                      className="px-3 py-1.5 rounded-lg border border-purple-800/80 bg-purple-950/60 hover:bg-purple-900/80 text-xs font-medium text-purple-300 transition flex items-center gap-1.5"
                    >
                      <Lock className="w-3.5 h-3.5" />
                      Legal Hold
                    </button>
                    <button
                      onClick={handleExportManifest}
                      className="px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-800 hover:bg-slate-700 text-xs font-medium text-slate-200 transition flex items-center gap-1.5"
                    >
                      <Download className="w-3.5 h-3.5 text-emerald-400" />
                      Export Package
                    </button>
                    <a
                      href={evidenceWorkspaceService.getDownloadUrl(selectedEvidence.id)}
                      download
                      className="px-3 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-semibold transition flex items-center gap-1.5"
                    >
                      <Download className="w-3.5 h-3.5" />
                      Download
                    </a>
                  </div>
                </div>

                {/* Tabs */}
                <div className="flex items-center gap-2 mt-6 border-b border-slate-800">
                  {(
                    [
                      { id: 'overview', label: 'Hashes & Metadata', icon: Hash },
                      { id: 'custody', label: `Chain of Custody (${selectedEvidence.custody_events.length})`, icon: Clock },
                      { id: 'preview', label: 'Safe Preview', icon: Eye },
                      { id: 'lineage', label: `Lineage (${selectedEvidence.provenance_lineage.length})`, icon: GitBranch },
                      { id: 'notes', label: `Notes (${selectedEvidence.forensic_notes.length})`, icon: FileText },
                      { id: 'manifest', label: 'Export Manifest', icon: Scale },
                    ] as const
                  ).map((tab) => {
                    const Icon = tab.icon;
                    return (
                      <button
                        key={tab.id}
                        onClick={() => handleTabChange(tab.id)}
                        className={`px-3 py-2 text-xs font-medium transition flex items-center gap-1.5 border-b-2 -mb-px ${
                          activeTab === tab.id
                            ? 'border-cyan-400 text-cyan-400'
                            : 'border-transparent text-slate-400 hover:text-slate-200'
                        }`}
                      >
                        <Icon className="w-3.5 h-3.5" />
                        {tab.label}
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Tab Contents */}
              <div className="p-6 space-y-6 flex-1">
                {/* 1. OVERVIEW & HASHES TAB */}
                {activeTab === 'overview' && (
                  <div className="space-y-6">
                    {/* Cryptographic Digests Box */}
                    <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
                          <Hash className="w-3.5 h-3.5 text-cyan-400" /> Cryptographic Integrity Digests
                        </span>
                        <span
                          className={`text-xs px-2 py-0.5 rounded-full font-mono flex items-center gap-1 ${
                            selectedEvidence.integrity_status === 'VERIFIED'
                              ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                              : 'bg-rose-950 text-rose-400 border border-rose-800'
                          }`}
                        >
                          {selectedEvidence.integrity_status}
                        </span>
                      </div>

                      <div className="space-y-2 font-mono text-xs">
                        <div>
                          <span className="text-slate-500 block text-[10px]">SHA-256 (Primary Digest)</span>
                          <div className="flex items-center justify-between bg-slate-950 p-2 rounded border border-slate-800/80">
                            <span className="text-slate-200 break-all select-all">{selectedEvidence.sha256}</span>
                            <button
                              onClick={() => copyToClipboard(selectedEvidence.sha256, 'main-sha256')}
                              className="ml-2 text-slate-400 hover:text-white"
                            >
                              {copiedKey === 'main-sha256' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                            </button>
                          </div>
                        </div>

                        {selectedEvidence.sha1 && (
                          <div>
                            <span className="text-slate-500 block text-[10px]">SHA-1</span>
                            <div className="flex items-center justify-between bg-slate-950 p-2 rounded border border-slate-800/80">
                              <span className="text-slate-300 break-all select-all">{selectedEvidence.sha1}</span>
                              <button
                                onClick={() => copyToClipboard(selectedEvidence.sha1!, 'main-sha1')}
                                className="ml-2 text-slate-400 hover:text-white"
                              >
                                {copiedKey === 'main-sha1' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                              </button>
                            </div>
                          </div>
                        )}

                        {selectedEvidence.md5 && (
                          <div>
                            <span className="text-slate-500 block text-[10px]">MD5</span>
                            <div className="flex items-center justify-between bg-slate-950 p-2 rounded border border-slate-800/80">
                              <span className="text-slate-300 break-all select-all">{selectedEvidence.md5}</span>
                              <button
                                onClick={() => copyToClipboard(selectedEvidence.md5!, 'main-md5')}
                                className="ml-2 text-slate-400 hover:text-white"
                              >
                                {copiedKey === 'main-md5' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                              </button>
                            </div>
                          </div>
                        )}
                      </div>
                    </div>

                    {/* Metadata Grid */}
                    <div className="grid grid-cols-2 gap-4">
                      <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
                        <span className="text-xs text-slate-400 font-medium">Acquisition Details</span>
                        <div className="text-xs space-y-1">
                          <div className="flex justify-between">
                            <span className="text-slate-500">Source Type:</span>
                            <span className="font-mono text-slate-200">{selectedEvidence.source_type}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-slate-500">Method:</span>
                            <span className="font-mono text-slate-200">{selectedEvidence.collection_method}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-slate-500">Byte Size:</span>
                            <span className="font-mono text-slate-200">{selectedEvidence.size.toLocaleString()} bytes</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-slate-500">Storage Ref:</span>
                            <span className="font-mono text-slate-400 truncate max-w-[150px]">{selectedEvidence.storage_reference}</span>
                          </div>
                        </div>
                      </div>

                      <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
                        <span className="text-xs text-slate-400 font-medium">Compliance & Policy</span>
                        <div className="text-xs space-y-1">
                          <div className="flex justify-between">
                            <span className="text-slate-500">Classification:</span>
                            <span className="font-mono text-slate-200">{selectedEvidence.classification}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-slate-500">Retention:</span>
                            <span className="font-mono text-slate-200">{selectedEvidence.retention_policy}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-slate-500">Preservation:</span>
                            <span className="font-mono text-purple-400">{selectedEvidence.preservation_status}</span>
                          </div>
                          {selectedEvidence.preservation_reason && (
                            <div className="text-[11px] text-slate-400 pt-1 border-t border-slate-800">
                              Reason: {selectedEvidence.preservation_reason}
                            </div>
                          )}
                        </div>
                      </div>
                    </div>
                  </div>
                )}

                {/* 2. CHAIN OF CUSTODY TAB */}
                {activeTab === 'custody' && (
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
                        Append-Only Chain of Custody Ledger
                      </h3>
                      <button
                        onClick={() => setShowCustodyModal(true)}
                        className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-200 font-medium flex items-center gap-1 transition"
                      >
                        <Plus className="w-3.5 h-3.5 text-cyan-400" />
                        Append Custody Event
                      </button>
                    </div>

                    <div className="relative pl-6 space-y-6 before:content-[''] before:absolute before:left-2 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-800">
                      {selectedEvidence.custody_events.map((event, idx) => (
                        <div key={event.id || idx} className="relative group">
                          {/* Dot indicator */}
                          <div className="absolute -left-6 top-1 w-2.5 h-2.5 rounded-full bg-cyan-500 ring-4 ring-slate-950" />
                          <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
                            <div className="flex items-center justify-between">
                              <span className="text-xs font-semibold text-cyan-400 font-mono">
                                {event.event_type}
                              </span>
                              <span className="text-[10px] text-slate-500 font-mono">
                                {new Date(event.timestamp).toLocaleString()}
                              </span>
                            </div>

                            <div className="text-xs text-slate-300">
                              <span className="text-slate-400">Actor:</span>{' '}
                              <span className="font-medium text-slate-200">{event.actor_id}</span>
                            </div>

                            {event.source && event.destination && (
                              <div className="text-xs text-slate-400 flex items-center gap-2 font-mono">
                                <span>{event.source}</span>
                                <ArrowRight className="w-3 h-3 text-cyan-400" />
                                <span>{event.destination}</span>
                              </div>
                            )}

                            {event.reason && (
                              <div className="text-xs text-slate-400 italic bg-slate-950/60 p-2 rounded border border-slate-800/40">
                                "{event.reason}"
                              </div>
                            )}

                            <div className="text-[10px] font-mono text-slate-500">
                              Integrity Digest: {event.integrity_hash.slice(0, 24)}...
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* 3. SAFE PREVIEW TAB */}
                {activeTab === 'preview' && (
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
                          Bounded Content Preview
                        </span>
                        {previewData && (
                          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400">
                            {previewData.preview_type.toUpperCase()} ({previewData.total_preview_bytes} bytes)
                          </span>
                        )}
                      </div>
                      <button
                        onClick={() => loadPreview(selectedEvidence.id)}
                        className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-300 flex items-center gap-1"
                      >
                        <RefreshCw className="w-3 h-3 text-cyan-400" />
                        Reload
                      </button>
                    </div>

                    {loadingPreview ? (
                      <div className="p-8 text-center text-slate-500 text-xs flex items-center justify-center gap-2">
                        <RefreshCw className="w-4 h-4 animate-spin text-cyan-400" />
                        Loading safe preview stream...
                      </div>
                    ) : !previewData ? (
                      <div className="p-8 text-center text-slate-500 text-xs">
                        Preview not available for this artifact.
                      </div>
                    ) : (
                      <div className="rounded-xl border border-slate-800 bg-slate-950 overflow-hidden">
                        <div className="p-3 bg-slate-900 border-b border-slate-800 flex items-center justify-between text-xs text-slate-400">
                          <span className="font-mono">{previewData.filename}</span>
                          {previewData.truncated && (
                            <span className="text-amber-400 text-[10px] bg-amber-950 px-2 py-0.5 rounded border border-amber-800">
                              Preview Truncated (8KB bounded limit)
                            </span>
                          )}
                        </div>
                        <pre className="p-4 text-xs font-mono text-slate-200 overflow-x-auto whitespace-pre leading-relaxed select-text max-h-[500px]">
                          {previewData.preview_content}
                        </pre>
                      </div>
                    )}
                  </div>
                )}

                {/* 4. PROVENANCE & LINEAGE TAB */}
                {activeTab === 'lineage' && (
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
                        Artifact Provenance & Transformation Lineage
                      </h3>
                      <button
                        onClick={() => setShowDeriveModal(true)}
                        className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-200 font-medium flex items-center gap-1 transition"
                      >
                        <Plus className="w-3.5 h-3.5 text-cyan-400" />
                        Derive Child Evidence
                      </button>
                    </div>

                    <div className="space-y-3">
                      {selectedEvidence.provenance_lineage.map((item, idx) => (
                        <div
                          key={idx}
                          className={`p-4 rounded-xl border flex items-center justify-between gap-4 ${
                            item.relation === 'SELF'
                              ? 'bg-slate-900 border-cyan-500/40 ring-1 ring-cyan-500/20'
                              : 'bg-slate-950 border-slate-800'
                          }`}
                        >
                          <div className="flex items-center gap-3">
                            <div className="p-2 rounded-lg bg-slate-800 text-cyan-400">
                              {item.relation === 'PARENT' ? (
                                <GitBranch className="w-4 h-4 rotate-180" />
                              ) : item.relation === 'CHILD' ? (
                                <GitBranch className="w-4 h-4" />
                              ) : (
                                <CheckCircle2 className="w-4 h-4 text-cyan-400" />
                              )}
                            </div>
                            <div>
                              <div className="flex items-center gap-2">
                                <span className="font-semibold text-xs text-white">{item.filename}</span>
                                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-400">
                                  {item.evidence_id}
                                </span>
                                <span
                                  className={`text-[10px] font-medium px-1.5 py-0.5 rounded ${
                                    item.relation === 'SELF'
                                      ? 'bg-cyan-950 text-cyan-400'
                                      : item.relation === 'PARENT'
                                      ? 'bg-purple-950 text-purple-400'
                                      : 'bg-blue-950 text-blue-400'
                                  }`}
                                >
                                  {item.relation}
                                </span>
                              </div>
                              <div className="text-[11px] text-slate-400 font-mono mt-0.5">
                                SHA-256: {item.sha256.slice(0, 24)}...
                              </div>
                              {item.tool && (
                                <div className="text-[11px] text-slate-400 mt-1">
                                  Tool: <span className="text-slate-200">{item.tool}</span> •{' '}
                                  <span>{item.transformation}</span>
                                </div>
                              )}
                            </div>
                          </div>

                          {item.relation !== 'SELF' && (
                            <button
                              onClick={() => loadDetail(item.evidence_id)}
                              className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-300"
                            >
                              Inspect
                            </button>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* 5. FORENSIC NOTES TAB */}
                {activeTab === 'notes' && (
                  <div className="space-y-4">
                    <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
                      Analyst Forensic Observations
                    </h3>
                    <div className="space-y-3">
                      {selectedEvidence.forensic_notes.length === 0 ? (
                        <div className="p-8 text-center text-slate-500 text-xs">
                          No forensic analyst notes added yet.
                        </div>
                      ) : (
                        selectedEvidence.forensic_notes.map((note) => (
                          <div key={note.note_id} className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 space-y-1">
                            <div className="flex items-center justify-between text-xs">
                              <span className="font-semibold text-cyan-400">{note.actor}</span>
                              <span className="text-slate-500 font-mono text-[10px]">
                                {new Date(note.timestamp).toLocaleString()}
                              </span>
                            </div>
                            <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 uppercase font-mono">
                              {note.category}
                            </span>
                            <p className="text-xs text-slate-200 mt-2">{note.text}</p>
                          </div>
                        ))
                      )}
                    </div>
                  </div>
                )}

                {/* 6. EXPORT MANIFEST TAB */}
                {activeTab === 'manifest' && (
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
                        Signed Legal & Forensic Export Manifest
                      </h3>
                      <button
                        onClick={handleExportManifest}
                        className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-200 font-medium flex items-center gap-1"
                      >
                        <RefreshCw className="w-3.5 h-3.5 text-cyan-400" />
                        Regenerate Package
                      </button>
                    </div>

                    {!manifestData ? (
                      <div className="p-8 text-center text-slate-500 text-xs">
                        Click "Export Package" above to compile a signed manifest package.
                      </div>
                    ) : (
                      <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
                        <div className="flex items-center justify-between">
                          <span className="font-mono text-xs text-emerald-400 font-bold">
                            {manifestData.manifest_id}
                          </span>
                          <span className="text-xs text-slate-400 font-mono">
                            Exported: {new Date(manifestData.exported_at).toLocaleString()}
                          </span>
                        </div>

                        <div className="p-3 rounded bg-slate-950 border border-slate-800 font-mono text-xs space-y-1">
                          <div className="text-slate-400">
                            Package SHA-256 Digest: <span className="text-emerald-400">{manifestData.package_hash_sha256}</span>
                          </div>
                          <div className="text-slate-400">
                            Custody Records Included: <span className="text-white">{manifestData.custody_events_count}</span>
                          </div>
                        </div>

                        <pre className="p-3 rounded bg-slate-950 border border-slate-800 text-xs font-mono text-slate-300 max-h-80 overflow-y-auto">
                          {JSON.stringify(manifestData.manifest_json, null, 2)}
                        </pre>
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
          )}
        </main>
      </div>

      {/* MODAL 1: Upload / Register Evidence */}
      {showUploadModal && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-lg p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Upload className="w-4 h-4 text-cyan-400" /> Acquire & Ingest Forensic Evidence
              </h3>
              <button onClick={() => setShowUploadModal(false)} className="text-slate-400 hover:text-white">
                <XCircle className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleUploadSubmit} className="space-y-4 text-xs">
              <div>
                <label className="block text-slate-400 mb-1">Original Artifact Filename</label>
                <input
                  type="text"
                  required
                  value={uploadFilename}
                  onChange={(e) => setUploadFilename(e.target.value)}
                  placeholder="e.g. suspicious_macro_payload.vbs"
                  className="w-full px-3 py-2 rounded bg-slate-950 border border-slate-800 text-white focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1">Source Type</label>
                  <select
                    value={uploadSourceType}
                    onChange={(e) => setUploadSourceType(e.target.value as EvidenceSourceType)}
                    className="w-full px-3 py-2 rounded bg-slate-950 border border-slate-800 text-white focus:outline-none"
                  >
                    <option value="FILE">File</option>
                    <option value="EMAIL">Email</option>
                    <option value="ATTACHMENT">Attachment</option>
                    <option value="MEMORY_DUMP">Memory Dump</option>
                    <option value="NETWORK_FLOW">Network Flow</option>
                    <option value="URL">URL</option>
                  </select>
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Classification</label>
                  <select
                    value={uploadClassification}
                    onChange={(e) => setUploadClassification(e.target.value as EvidenceClassification)}
                    className="w-full px-3 py-2 rounded bg-slate-950 border border-slate-800 text-white focus:outline-none"
                  >
                    <option value="INTERNAL">Internal</option>
                    <option value="CONFIDENTIAL">Confidential</option>
                    <option value="RESTRICTED">Restricted</option>
                    <option value="LEGAL_PRIVILEGED">Legal Privileged</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Artifact Payload (UTF-8 Text Content)</label>
                <textarea
                  rows={4}
                  required
                  value={uploadContentText}
                  onChange={(e) => setUploadContentText(e.target.value)}
                  placeholder="Paste raw string, decoded script, or log content..."
                  className="w-full px-3 py-2 rounded bg-slate-950 border border-slate-800 text-white font-mono focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Acquisition Notes & Context</label>
                <input
                  type="text"
                  value={uploadNotes}
                  onChange={(e) => setUploadNotes(e.target.value)}
                  placeholder="Acquired from compromised endpoint WS-09."
                  className="w-full px-3 py-2 rounded bg-slate-950 border border-slate-800 text-white focus:outline-none"
                />
              </div>

              <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowUploadModal(false)}
                  className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 rounded bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold"
                >
                  Compute Hashes & Ingest
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* MODAL 2: Legal Hold / Preservation */}
      {showPreserveModal && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-md p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Lock className="w-4 h-4 text-purple-400" /> Preservation & Legal Hold Control
              </h3>
              <button onClick={() => setShowPreserveModal(false)} className="text-slate-400 hover:text-white">
                <XCircle className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handlePreservationSubmit} className="space-y-4 text-xs">
              <div>
                <label className="block text-slate-400 mb-1">Preservation Status</label>
                <select
                  value={preserveStatus}
                  onChange={(e) => setPreserveStatus(e.target.value as any)}
                  className="w-full px-3 py-2 rounded bg-slate-950 border border-slate-800 text-white focus:outline-none"
                >
                  <option value="ON_HOLD">ON_HOLD (Litigation / Regulatory Hold)</option>
                  <option value="PRESERVED">PRESERVED (Retention Lock)</option>
                  <option value="NORMAL">NORMAL (Standard Policy)</option>
                </select>
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Mandatory Justification / Order Reference</label>
                <textarea
                  rows={3}
                  required
                  value={preserveReason}
                  onChange={(e) => setPreserveReason(e.target.value)}
                  placeholder="Specify legal counsel notice, subpoena ID, or regulatory directive..."
                  className="w-full px-3 py-2 rounded bg-slate-950 border border-slate-800 text-white focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Additional Retention Notes (Optional)</label>
                <input
                  type="text"
                  value={preserveNotes}
                  onChange={(e) => setPreserveNotes(e.target.value)}
                  placeholder="Case filing details or external ticket ref..."
                  className="w-full px-3 py-2 rounded bg-slate-950 border border-slate-800 text-white focus:outline-none"
                />
              </div>

              <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowPreserveModal(false)}
                  className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 rounded bg-purple-600 hover:bg-purple-500 text-white font-semibold"
                >
                  Confirm Preservation
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* MODAL 3: Append Custody Event */}
      {showCustodyModal && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-md p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Clock className="w-4 h-4 text-cyan-400" /> Record Custody Transaction
              </h3>
              <button onClick={() => setShowCustodyModal(false)} className="text-slate-400 hover:text-white">
                <XCircle className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleCustodySubmit} className="space-y-4 text-xs">
              <div>
                <label className="block text-slate-400 mb-1">Transaction Type</label>
                <select
                  value={custodyType}
                  onChange={(e) => setCustodyType(e.target.value as CustodyEventType)}
                  className="w-full px-3 py-2 rounded bg-slate-950 border border-slate-800 text-white focus:outline-none"
                >
                  <option value="TRANSFERRED">Transferred</option>
                  <option value="ACCESSED">Accessed / Inspected</option>
                  <option value="COPIED">Bitstream Copied</option>
                  <option value="PRESERVED">Preserved</option>
                  <option value="EXPORTED">Exported for Trial</option>
                </select>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1">Source Location</label>
                  <input
                    type="text"
                    value={custodySource}
                    onChange={(e) => setCustodySource(e.target.value)}
                    placeholder="Evidence Vault A"
                    className="w-full px-3 py-2 rounded bg-slate-950 border border-slate-800 text-white focus:outline-none"
                  />
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Destination Location</label>
                  <input
                    type="text"
                    value={custodyDestination}
                    onChange={(e) => setCustodyDestination(e.target.value)}
                    placeholder="Forensics Lab 2"
                    className="w-full px-3 py-2 rounded bg-slate-950 border border-slate-800 text-white focus:outline-none"
                  />
                </div>
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Mandatory Reason</label>
                <textarea
                  rows={2}
                  required
                  value={custodyReason}
                  onChange={(e) => setCustodyReason(e.target.value)}
                  placeholder="State operational or forensic reason..."
                  className="w-full px-3 py-2 rounded bg-slate-950 border border-slate-800 text-white focus:outline-none"
                />
              </div>

              <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowCustodyModal(false)}
                  className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 rounded bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold"
                >
                  Record Transaction
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* MODAL 4: Child Derivation */}
      {showDeriveModal && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-lg p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <GitBranch className="w-4 h-4 text-cyan-400" /> Derive Child Forensic Artifact
              </h3>
              <button onClick={() => setShowDeriveModal(false)} className="text-slate-400 hover:text-white">
                <XCircle className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleDeriveSubmit} className="space-y-4 text-xs">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1">Transformation Tool</label>
                  <input
                    type="text"
                    required
                    value={deriveTool}
                    onChange={(e) => setDeriveTool(e.target.value)}
                    placeholder="e.g. Volatility 3"
                    className="w-full px-3 py-2 rounded bg-slate-950 border border-slate-800 text-white focus:outline-none"
                  />
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Tool Version</label>
                  <input
                    type="text"
                    value={deriveToolVersion}
                    onChange={(e) => setDeriveToolVersion(e.target.value)}
                    placeholder="2.5.0"
                    className="w-full px-3 py-2 rounded bg-slate-950 border border-slate-800 text-white focus:outline-none"
                  />
                </div>
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Child Filename</label>
                <input
                  type="text"
                  required
                  value={deriveFilename}
                  onChange={(e) => setDeriveFilename(e.target.value)}
                  placeholder="carved_strings.txt"
                  className="w-full px-3 py-2 rounded bg-slate-950 border border-slate-800 text-white focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Transformation Description</label>
                <input
                  type="text"
                  required
                  value={deriveDesc}
                  onChange={(e) => setDeriveDesc(e.target.value)}
                  placeholder="Carved process memory strings using regex filter."
                  className="w-full px-3 py-2 rounded bg-slate-950 border border-slate-800 text-white focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Derived Artifact Content</label>
                <textarea
                  rows={4}
                  required
                  value={deriveContent}
                  onChange={(e) => setDeriveContent(e.target.value)}
                  placeholder="Paste derived text, strings, or logs..."
                  className="w-full px-3 py-2 rounded bg-slate-950 border border-slate-800 text-white font-mono focus:outline-none"
                />
              </div>

              <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowDeriveModal(false)}
                  className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 rounded bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold"
                >
                  Derive & Link Provenance
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
