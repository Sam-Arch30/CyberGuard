import React, { useState, useRef, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Upload,
  Link2,
  File,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  ArrowRight,
  Info,
  Copy,
  Check,
  ChevronDown,
  ChevronUp,
  X,
  RefreshCw,
  Shield,
  Layers
} from 'lucide-react';
import {
  Button,
  Badge,
  Modal,
  ModalHeader,
  ModalTitle,
  ModalBody,
  ModalFooter,
  Progress,
  Alert
} from '../ui';
import { IngestionService } from '../../services/ingestionService';
import type {
  IngestionResult,
  IngestionQueueItem,
  DetectedInput,
  AnalyzerCapabilityRead,
  ArtifactType
} from '../../types/ingestion';
import { useInvestigation } from '../../context/InvestigationContext';
import { saveAnalysisResult } from '../../utils/forensicStore';
import type { EmailAnalysis } from '../../types/forensic';
import { decodeRfc2047 } from '../../utils/indicatorHelper';

interface UniversalDropZoneProps {
  onIngestionSuccess?: (result: IngestionResult) => void;
  className?: string;
}

export const UniversalDropZone: React.FC<UniversalDropZoneProps> = ({
  onIngestionSuccess,
  className = ''
}) => {
  const navigate = useNavigate();
  const { setActiveEmailId } = useInvestigation();
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Drag state
  const [isDragging, setIsDragging] = useState<boolean>(false);
  const dragCounter = useRef<number>(0);

  // Ingestion Queue State
  const [queue, setQueue] = useState<IngestionQueueItem[]>([]);

  // Paste Dialog State
  const [isPasteOpen, setIsPasteOpen] = useState<boolean>(false);
  const [pasteInput, setPasteInput] = useState<string>('');
  const [pasteNotes, setPasteNotes] = useState<string>('');
  const [detectedPreview, setDetectedPreview] = useState<DetectedInput | null>(null);
  const [detecting, setDetecting] = useState<boolean>(false);
  const [isSubmittingPaste, setIsSubmittingPaste] = useState<boolean>(false);
  const [pasteError, setPasteError] = useState<string | null>(null);

  // Capabilities Helper Modal State
  const [isCapsOpen, setIsCapsOpen] = useState<boolean>(false);
  const [capabilities, setCapabilities] = useState<AnalyzerCapabilityRead[]>([]);
  const [capsLoading, setCapsLoading] = useState<boolean>(false);

  // Progressive disclosure of forensic internals
  const [expandedItems, setExpandedItems] = useState<Set<string>>(new Set());
  const [copiedSha, setCopiedSha] = useState<string | null>(null);

  // Global error banner
  const [globalError, setGlobalError] = useState<string | null>(null);

  // Load capabilities when modal opens
  useEffect(() => {
    if (isCapsOpen && capabilities.length === 0) {
      setCapsLoading(true);
      IngestionService.getCapabilities()
        .then((caps) => setCapabilities(caps))
        .catch(() => setCapabilities([]))
        .finally(() => setCapsLoading(false));
    }
  }, [isCapsOpen, capabilities.length]);

  // Debounced input detection for Paste modal
  useEffect(() => {
    const text = pasteInput.trim();
    if (!text || text.length < 3) {
      setDetectedPreview(null);
      return;
    }

    const timer = setTimeout(() => {
      setDetecting(true);
      IngestionService.detectInput(text)
        .then((det) => setDetectedPreview(det))
        .catch(() => setDetectedPreview(null))
        .finally(() => setDetecting(false));
    }, 300);

    return () => clearTimeout(timer);
  }, [pasteInput]);

  // Handle Drag Events
  const handleDragEnter = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    dragCounter.current += 1;
    if (e.dataTransfer.items && e.dataTransfer.items.length > 0) {
      setIsDragging(true);
    }
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    dragCounter.current -= 1;
    if (dragCounter.current === 0) {
      setIsDragging(false);
    }
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
    dragCounter.current = 0;

    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleFiles(Array.from(e.dataTransfer.files));
    }
  };

  // Handle file input selection
  const handleFileInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      handleFiles(Array.from(e.target.files));
    }
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const queueCounter = useRef<number>(0);

  // Process files through queue
  const handleFiles = (files: File[]) => {
    setGlobalError(null);
    const newItems: IngestionQueueItem[] = files.map((file) => {
      queueCounter.current += 1;
      return {
        id: `queue-${Date.now()}-${queueCounter.current}`,
        file,
        displayName: file.name,
        status: 'queued',
        progress: 0
      };
    });

    setQueue((prev) => [...prev, ...newItems]);

    newItems.forEach((item) => {
      processQueueItem(item);
    });
  };

  const processQueueItem = async (item: IngestionQueueItem) => {
    if (!item.file) return;

    setQueue((prev) =>
      prev.map((q) => (q.id === item.id ? { ...q, status: 'uploading', progress: 10 } : q))
    );

    try {
      const result = await IngestionService.ingestFile(
        item.file,
        undefined,
        (progressPercent) => {
          setQueue((prev) =>
            prev.map((q) =>
              q.id === item.id ? { ...q, progress: progressPercent } : q
            )
          );
        }
      );

      // Ingestion accepted by backend
      setQueue((prev) =>
        prev.map((q) =>
          q.id === item.id
            ? {
                ...q,
                status: 'accepted',
                detectedType: result.artifact_type,
                progress: 100,
                result,
                warnings: result.warnings,
                duplicate: result.duplicate
              }
            : q
        )
      );

      // If EMAIL artifact, persist to local forensicStore for zero-latency workspace loading
      if (result.artifact_type === 'EMAIL' && item.file) {
        try {
          const content = await item.file.text();
          const targetId = result.evidence_id || result.artifact_id;
          const emailRecord: EmailAnalysis = {
            id: targetId,
            evidence_id: result.evidence_id || undefined,
            email_sha256: result.sha256 || undefined,
            original_filename: result.name || item.file.name,
            upload_timestamp: result.created_at,
            size: result.size || item.file.size,
            uploader: 'SOC Analyst',
            raw_email: content,
            subject: decodeRfc2047(result.name || item.file.name),
            from: '',
            to: '',
            date: result.created_at,
            urls: [],
            ips: [],
            domains: [],
            emails: [],
            attachments: [],
            threat_score: {
              score: 0,
              severity: 'low',
              reasons: [],
              positive_evidence: [],
              summary: 'Initial automated ingestion record.'
            }
          };
          saveAnalysisResult(targetId, emailRecord);
        } catch {
          // Non-critical local cache fallback
        }
      }

      if (onIngestionSuccess) {
        onIngestionSuccess(result);
      }
    } catch (err: unknown) {
      const errorMsg = err instanceof Error ? err.message : 'Upload failed';
      setQueue((prev) =>
        prev.map((q) =>
          q.id === item.id ? { ...q, status: 'failed', error: errorMsg } : q
        )
      );
    }
  };

  // Submit Text / URL / Log from Paste modal
  const handlePasteSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!pasteInput.trim()) return;

    setIsSubmittingPaste(true);
    setPasteError(null);

    const queueId = `queue-text-${Date.now()}`;
    const displayName =
      pasteInput.trim().slice(0, 48) + (pasteInput.trim().length > 48 ? '...' : '');

    const newItem: IngestionQueueItem = {
      id: queueId,
      text: pasteInput.trim(),
      displayName,
      status: 'uploading',
      progress: 50
    };

    setQueue((prev) => [newItem, ...prev]);

    try {
      const result = await IngestionService.ingestText(pasteInput.trim(), {
        notes: pasteNotes.trim() || undefined
      });

      setQueue((prev) =>
        prev.map((q) =>
          q.id === queueId
            ? {
                ...q,
                status: 'accepted',
                detectedType: result.artifact_type,
                progress: 100,
                result,
                warnings: result.warnings,
                duplicate: result.duplicate
              }
            : q
        )
      );

      setIsPasteOpen(false);
      setPasteInput('');
      setPasteNotes('');
      setDetectedPreview(null);

      if (onIngestionSuccess) {
        onIngestionSuccess(result);
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Ingestion failed';
      setPasteError(msg);
      setQueue((prev) =>
        prev.map((q) => (q.id === queueId ? { ...q, status: 'failed', error: msg } : q))
      );
    } finally {
      setIsSubmittingPaste(false);
    }
  };

  const handleRemoveQueueItem = (id: string) => {
    setQueue((prev) => prev.filter((item) => item.id !== id));
  };

  const handleOpenInvestigation = (result: IngestionResult) => {
    const targetId = result.investigation_id || result.evidence_id || result.artifact_id;
    if (targetId) {
      setActiveEmailId(targetId);
      navigate(`/investigations/${targetId}/analysis`);
    } else {
      navigate('/investigations');
    }
  };

  const handleCopySha = (sha: string) => {
    navigator.clipboard.writeText(sha);
    setCopiedSha(sha);
    setTimeout(() => setCopiedSha(null), 2000);
  };

  const toggleExpand = (id: string) => {
    setExpandedItems((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  const getArtifactTypeLabel = (type?: ArtifactType): string => {
    switch (type) {
      case 'EMAIL':
        return 'Email (RFC-822)';
      case 'URL':
        return 'URL';
      case 'DOMAIN':
        return 'Domain';
      case 'IP':
        return 'IP Address';
      case 'FILE':
        return 'File';
      case 'IMAGE':
        return 'Image';
      case 'AUDIO':
        return 'Audio';
      case 'VIDEO':
        return 'Video';
      case 'AUTH_LOG':
        return 'Authentication Log';
      case 'NETWORK_LOG':
        return 'Network Log';
      case 'API_LOG':
        return 'API Log';
      case 'ENDPOINT_EVENT':
        return 'Endpoint Telemetry';
      default:
        return type || 'Artifact';
    }
  };

  return (
    <div className={`space-y-4 ${className}`}>
      {/* =========================================================================
          UNIVERSAL INGESTION DROP ZONE
          ========================================================================= */}
      <div
        id="universal-drop-zone"
        role="region"
        aria-label="Universal Evidence Ingestion Drop Zone"
        tabIndex={0}
        onDragEnter={handleDragEnter}
        onDragLeave={handleDragLeave}
        onDragOver={handleDragOver}
        onDrop={handleDrop}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            fileInputRef.current?.click();
          }
        }}
        className={`relative overflow-hidden rounded-card border-2 transition-all duration-200 outline-none focus-visible:ring-2 focus-visible:ring-primary focus-visible:ring-offset-2 ${
          isDragging
            ? 'border-primary bg-primary/5 shadow-lg scale-[1.005]'
            : 'border-dashed border-border hover:border-primary/50 bg-surface hover:bg-surface-secondary/40 shadow-sm'
        }`}
      >
        <input
          ref={fileInputRef}
          type="file"
          multiple
          className="hidden"
          onChange={handleFileInputChange}
          aria-hidden="true"
        />

        <div className="p-6 sm:p-8 flex flex-col items-center justify-center text-center space-y-4">
          <div
            className={`w-14 h-14 rounded-full flex items-center justify-center transition-all duration-300 ${
              isDragging
                ? 'bg-primary text-primary-foreground scale-110 animate-bounce'
                : 'bg-primary/10 text-primary border border-primary/20'
            }`}
          >
            <Upload className="w-6 h-6" />
          </div>

          <div className="space-y-1 max-w-md">
            <h3 className="text-base sm:text-lg font-bold text-foreground font-sans tracking-tight">
              {isDragging ? 'Release to analyze' : 'Drop evidence to analyze'}
            </h3>
            <p className="text-xs text-foreground-muted font-mono">
              File • Email • URL • Logs • Media
            </p>
          </div>

          <div className="flex flex-wrap items-center justify-center gap-2.5 pt-1">
            <Button
              id="btn-browse-files"
              variant="primary"
              size="sm"
              onClick={() => fileInputRef.current?.click()}
              className="flex items-center space-x-1.5 cursor-pointer font-medium"
            >
              <File className="w-3.5 h-3.5" />
              <span>Browse files</span>
            </Button>

            <Button
              id="btn-paste-evidence"
              variant="secondary"
              size="sm"
              onClick={() => setIsPasteOpen(true)}
              className="flex items-center space-x-1.5 cursor-pointer font-medium"
            >
              <Link2 className="w-3.5 h-3.5" />
              <span>Paste URL / Text / Log</span>
            </Button>
          </div>

          <div className="pt-2">
            <button
              id="btn-supported-types"
              type="button"
              onClick={() => setIsCapsOpen(true)}
              className="inline-flex items-center space-x-1 text-[11px] font-mono text-foreground-muted hover:text-primary transition-colors cursor-pointer underline-offset-4 hover:underline"
            >
              <Info className="w-3 h-3 text-primary/70" />
              <span>Supported evidence types & analyzer capabilities</span>
            </button>
          </div>
        </div>
      </div>

      {globalError && (
        <Alert
          variant="danger"
          title="Ingestion Error"
          onDismiss={() => setGlobalError(null)}
          className="text-xs"
        >
          {globalError}
        </Alert>
      )}

      {/* =========================================================================
          INGESTION QUEUE & ACTIVE RESULTS
          ========================================================================= */}
      {queue.length > 0 && (
        <div className="space-y-2.5">
          <div className="flex items-center justify-between text-xs font-mono text-foreground-muted px-1">
            <span className="font-semibold uppercase tracking-wider flex items-center gap-1.5">
              <Layers className="w-3.5 h-3.5 text-primary" />
              <span>Ingestion Queue & Processing ({queue.length})</span>
            </span>
            <button
              onClick={() => setQueue([])}
              className="text-[11px] text-foreground-subtle hover:text-foreground transition-colors cursor-pointer"
            >
              Clear completed
            </button>
          </div>

          <div className="space-y-2">
            {queue.map((item) => (
              <div
                key={item.id}
                className="p-3.5 rounded-card bg-surface border border-border shadow-xs flex flex-col gap-2 transition-all"
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="flex items-center space-x-2.5 min-w-0">
                    <div className="w-7 h-7 rounded-md bg-surface-secondary flex items-center justify-center text-foreground-muted shrink-0">
                      {item.status === 'accepted' ? (
                        <CheckCircle2 className="w-4 h-4 text-emerald-500" />
                      ) : item.status === 'failed' ? (
                        <XCircle className="w-4 h-4 text-rose-500" />
                      ) : (
                        <RefreshCw className="w-4 h-4 text-primary animate-spin" />
                      )}
                    </div>
                    <div className="min-w-0">
                      <div className="text-xs font-medium text-foreground truncate">
                        {item.displayName}
                      </div>
                      <div className="flex items-center space-x-2 text-[10px] font-mono text-foreground-muted mt-0.5">
                        <span>{getArtifactTypeLabel(item.detectedType)}</span>
                        {item.file && (
                          <>
                            <span>•</span>
                            <span>{(item.file.size / 1024).toFixed(1)} KB</span>
                          </>
                        )}
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center space-x-2 shrink-0">
                    {item.status === 'uploading' && (
                      <Badge variant="neutral" size="sm" className="font-mono text-[10px]">
                        Uploading {item.progress !== undefined ? `${item.progress}%` : ''}
                      </Badge>
                    )}
                    {item.status === 'queued' && (
                      <Badge variant="neutral" size="sm" className="font-mono text-[10px]">
                        Queued
                      </Badge>
                    )}
                    {item.status === 'accepted' && (
                      <Badge variant="success" size="sm" className="font-mono text-[10px]">
                        Accepted
                      </Badge>
                    )}
                    {item.status === 'failed' && (
                      <Badge variant="danger" size="sm" className="font-mono text-[10px]">
                        Failed
                      </Badge>
                    )}

                    {item.status === 'accepted' && item.result && (
                      <Button
                        variant="primary"
                        size="xs"
                        onClick={() => handleOpenInvestigation(item.result!)}
                        className="flex items-center space-x-1 cursor-pointer"
                      >
                        <span>Open Investigation</span>
                        <ArrowRight className="w-3 h-3" />
                      </Button>
                    )}

                    <button
                      type="button"
                      onClick={() => handleRemoveQueueItem(item.id)}
                      className="p-1 rounded hover:bg-surface-secondary text-foreground-muted hover:text-foreground cursor-pointer"
                      aria-label="Dismiss item"
                    >
                      <X className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>

                {item.status === 'uploading' && item.progress !== undefined && (
                  <Progress value={item.progress} size="sm" />
                )}

                {item.status === 'failed' && item.error && (
                  <div className="p-2 rounded bg-rose-500/10 border border-rose-500/20 text-rose-500 text-xs font-mono">
                    {item.error}
                  </div>
                )}

                {item.duplicate && (
                  <div className="p-2 rounded bg-amber-500/10 border border-amber-500/20 text-amber-500 text-xs font-mono flex items-center justify-between">
                    <span className="flex items-center gap-1.5">
                      <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                      <span>Previously observed artifact. Lineage and new analysis run created.</span>
                    </span>
                    {item.result?.sha256 && (
                      <button
                        onClick={() => handleCopySha(item.result!.sha256!)}
                        className="text-[10px] underline ml-2 cursor-pointer"
                      >
                        {copiedSha === item.result.sha256 ? 'Copied' : 'Copy Hash'}
                      </button>
                    )}
                  </div>
                )}

                {item.warnings && item.warnings.length > 0 && (
                  <div className="p-2 rounded bg-surface-secondary text-foreground-muted text-[11px] font-mono">
                    {item.warnings.join(' • ')}
                  </div>
                )}

                {item.result && (
                  <div className="pt-1 border-t border-border/40">
                    <button
                      type="button"
                      onClick={() => toggleExpand(item.id)}
                      className="flex items-center space-x-1 text-[10px] font-mono text-foreground-muted hover:text-foreground cursor-pointer"
                    >
                      {expandedItems.has(item.id) ? (
                        <>
                          <ChevronUp className="w-3 h-3" />
                          <span>Hide technical forensics</span>
                        </>
                      ) : (
                        <>
                          <ChevronDown className="w-3 h-3" />
                          <span>Show technical forensics (SHA-256, Artifact ID, Analyzers)</span>
                        </>
                      )}
                    </button>

                    {expandedItems.has(item.id) && (
                      <div className="mt-2 p-2.5 rounded bg-surface-secondary/70 border border-border/60 text-[11px] font-mono space-y-1.5 text-foreground-muted">
                        <div className="flex items-center justify-between">
                          <span>Artifact ID:</span>
                          <span className="text-foreground">{item.result.artifact_id}</span>
                        </div>
                        {item.result.evidence_id && (
                          <div className="flex items-center justify-between">
                            <span>Evidence ID:</span>
                            <span className="text-foreground">{item.result.evidence_id}</span>
                          </div>
                        )}
                        {item.result.investigation_id && (
                          <div className="flex items-center justify-between">
                            <span>Investigation ID:</span>
                            <span className="text-foreground">{item.result.investigation_id}</span>
                          </div>
                        )}
                        {item.result.sha256 && (
                          <div className="flex items-center justify-between gap-2">
                            <span>SHA-256:</span>
                            <div className="flex items-center space-x-1 text-foreground truncate">
                              <span className="truncate max-w-[220px]">{item.result.sha256}</span>
                              <button
                                onClick={() => handleCopySha(item.result!.sha256!)}
                                className="p-0.5 hover:text-primary cursor-pointer"
                                title="Copy SHA-256"
                              >
                                {copiedSha === item.result.sha256 ? (
                                  <Check className="w-3 h-3 text-emerald-500" />
                                ) : (
                                  <Copy className="w-3 h-3" />
                                )}
                              </button>
                            </div>
                          </div>
                        )}
                        {item.result.candidate_analyzers.length > 0 && (
                          <div className="pt-1">
                            <span className="text-foreground-subtle">Candidate Analyzers: </span>
                            <span className="text-primary font-medium">
                              {item.result.candidate_analyzers.join(', ')}
                            </span>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* =========================================================================
          PASTE TEXT / URL / LOG MODAL
          ========================================================================= */}
      <Modal
        isOpen={isPasteOpen}
        onClose={() => setIsPasteOpen(false)}
        size="lg"
      >
        <ModalHeader>
          <ModalTitle>Paste Evidence for Universal Analysis</ModalTitle>
        </ModalHeader>
        <form onSubmit={handlePasteSubmit}>
          <ModalBody className="space-y-4">
            <div className="space-y-1.5">
              <label
                htmlFor="paste-input-area"
                className="text-xs font-semibold text-foreground font-mono flex items-center justify-between"
              >
                <span>Evidence Input (URL, Domain, IP, Authentication Logs, Telemetry)</span>
                {detecting ? (
                  <span className="text-[10px] text-foreground-muted flex items-center gap-1 font-normal">
                    <RefreshCw className="w-2.5 h-2.5 animate-spin" /> Detecting...
                  </span>
                ) : detectedPreview ? (
                  <Badge variant="primary" size="sm" className="font-mono text-[9px]">
                    Detected: {detectedPreview.artifact_type} ({Math.round(detectedPreview.confidence * 100)}%)
                  </Badge>
                ) : null}
              </label>
              <textarea
                id="paste-input-area"
                rows={6}
                value={pasteInput}
                onChange={(e) => setPasteInput(e.target.value)}
                placeholder="Paste evidence string, e.g.:&#10;• URL: https://secure-account-verification.example.com/login&#10;• Domain: evil-phish-domain.com&#10;• IP: 198.51.100.42&#10;• Auth Log JSON: { &quot;event_type&quot;: &quot;failed_login&quot;, &quot;user&quot;: &quot;admin&quot;, ... }&#10;• Suspicious message text or email headers"
                className="w-full p-3 rounded-md bg-surface border border-border text-foreground font-mono text-xs focus:outline-none focus:ring-1 focus:ring-primary focus:border-primary resize-y"
                required
              />
            </div>

            <div className="p-2.5 rounded bg-surface-secondary border border-border/60 text-[11px] font-mono text-foreground-muted flex items-start space-x-2">
              <Shield className="w-3.5 h-3.5 text-primary shrink-0 mt-0.5" />
              <span>
                <strong>SSRF-Safe Boundary:</strong> URLs are transmitted strictly to the CyberGuard
                isolated backend sandbox. The browser will never initiate direct requests to
                arbitrary user-supplied addresses.
              </span>
            </div>

            <div className="space-y-1">
              <label
                htmlFor="paste-notes-input"
                className="text-xs font-mono text-foreground-muted"
              >
                Optional Notes / Case Context
              </label>
              <input
                id="paste-notes-input"
                type="text"
                value={pasteNotes}
                onChange={(e) => setPasteNotes(e.target.value)}
                placeholder="e.g. Sourced from user report ticket #4912"
                className="w-full px-3 py-1.5 rounded-md bg-surface border border-border text-foreground font-mono text-xs focus:outline-none focus:ring-1 focus:ring-primary focus:border-primary"
              />
            </div>

            {pasteError && (
              <div className="p-2.5 rounded bg-rose-500/10 border border-rose-500/20 text-rose-500 text-xs font-mono">
                {pasteError}
              </div>
            )}
          </ModalBody>

          <ModalFooter>
            <Button
              type="button"
              variant="secondary"
              size="sm"
              onClick={() => setIsPasteOpen(false)}
            >
              Cancel
            </Button>
            <Button
              type="submit"
              variant="primary"
              size="sm"
              disabled={isSubmittingPaste || !pasteInput.trim()}
              className="cursor-pointer"
            >
              {isSubmittingPaste ? 'Ingesting Evidence...' : 'Ingest & Analyze'}
            </Button>
          </ModalFooter>
        </form>
      </Modal>

      {/* =========================================================================
          CAPABILITIES & SUPPORTED EVIDENCE TYPES MODAL
          ========================================================================= */}
      <Modal
        isOpen={isCapsOpen}
        onClose={() => setIsCapsOpen(false)}
        size="lg"
      >
        <ModalHeader>
          <ModalTitle>CyberGuard Platform Analyzer Capabilities</ModalTitle>
        </ModalHeader>
        <ModalBody className="space-y-4 max-h-[60vh] overflow-y-auto">
          <p className="text-xs text-foreground-muted font-sans">
            CyberGuard employs a universal ingestion pipeline that deterministically classifies
            evidence artifacts and dynamically routes them to authorized analyzers.
          </p>

          {capsLoading ? (
            <div className="p-8 text-center text-xs font-mono text-foreground-muted flex items-center justify-center space-x-2">
              <RefreshCw className="w-4 h-4 animate-spin text-primary" />
              <span>Querying backend capability registry...</span>
            </div>
          ) : (
            <div className="divide-y divide-border/60 border border-border rounded-md overflow-hidden">
              {capabilities.map((cap) => (
                <div key={cap.name} className="p-3 bg-surface hover:bg-surface-secondary/40 transition-colors">
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center space-x-2">
                      <span className="text-xs font-semibold text-foreground font-mono">
                        {cap.name}
                      </span>
                      <span className="text-[10px] font-mono text-foreground-subtle">
                        v{cap.version}
                      </span>
                    </div>
                    <Badge
                      variant={
                        cap.status === 'AVAILABLE'
                          ? 'success'
                          : cap.status === 'NOT_CONFIGURED'
                          ? 'warning'
                          : 'neutral'
                      }
                      size="sm"
                      className="font-mono text-[9px]"
                    >
                      {cap.status}
                    </Badge>
                  </div>
                  <p className="text-xs text-foreground-muted mt-1 font-sans">
                    {cap.description}
                  </p>
                  <div className="flex flex-wrap gap-1 mt-2">
                    {cap.supported_artifact_types.map((type) => (
                      <span
                        key={type}
                        className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-surface-secondary border border-border text-foreground-subtle"
                      >
                        {type}
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </ModalBody>
        <ModalFooter>
          <Button
            type="button"
            variant="secondary"
            size="sm"
            onClick={() => setIsCapsOpen(false)}
          >
            Close
          </Button>
        </ModalFooter>
      </Modal>
    </div>
  );
};
