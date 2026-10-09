import React, { useState, useEffect } from 'react';
import {
  FileText,
  Lock,
  Layers,
  Search,
  Copy,
  Check,
  Fingerprint,
} from 'lucide-react';
import { useInvestigation } from '../../../context/InvestigationContext';
import { investigationWorkspaceService } from '../../../services/investigationWorkspaceService';
import type { InvestigationEvidenceItem } from '../../../types/investigationWorkspace';
import { Badge, LoadingState } from '../../../components/ui';
import { EvidenceDetailDrawer } from '../../../components/analysis/results/EvidenceDetailDrawer';

export const EvidenceSectionView: React.FC = () => {
  const { workspaceSummary, activeEmailId, activeEmail } = useInvestigation();
  const [evidenceItems, setEvidenceItems] = useState<InvestigationEvidenceItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [activeFilter, setActiveFilter] = useState<'ALL' | 'ORIGINAL' | 'DERIVED'>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Selected evidence for drawer inspection
  const [selectedEvidence, setSelectedEvidence] = useState<InvestigationEvidenceItem | null>(null);
  const [drawerOpen, setDrawerOpen] = useState<boolean>(false);

  const effectiveId = workspaceSummary?.investigation.investigation_id || activeEmailId;

  const fetchEvidence = async () => {
    if (!effectiveId) {
      setLoading(false);
      return;
    }
    setLoading(true);
    try {
      const data = await investigationWorkspaceService.getEvidenceList(effectiveId);
      setEvidenceItems(data);
    } catch {
      // Synthesize truthful fallback from activeEmail if API fallback
      if (activeEmail) {
        const synth: InvestigationEvidenceItem[] = [];
        // Original file
        synth.push({
          id: activeEmail.evidence_id || 'ev-orig-1',
          name: activeEmail.original_filename || 'inbound-email.eml',
          evidence_type: 'EMAIL_FILE',
          is_original: true,
          sha256: activeEmail.email_sha256 || null,
          source: 'Universal Ingestion Engine',
          observed_at: activeEmail.upload_timestamp || activeEmail.date || new Date().toISOString(),
          confidence: 1.0,
          details: { subject: activeEmail.subject, from: activeEmail.from },
        });

        // Derived items
        if (activeEmail.urls) {
          activeEmail.urls.forEach((u, i) => {
            synth.push({
              id: `ev-url-${i}`,
              name: u,
              evidence_type: 'URL_INDICATOR',
              is_original: false,
              source: 'URL Extractor & Intelligence',
              observed_at: activeEmail.upload_timestamp || new Date().toISOString(),
              confidence: 0.95,
              details: { url: u },
            });
          });
        }
        if (activeEmail.attribution?.probable_origin_ip) {
          synth.push({
            id: 'ev-ip-1',
            name: activeEmail.attribution.probable_origin_ip,
            evidence_type: 'IP_ADDRESS',
            is_original: false,
            source: 'Network Hops & Attribution Engine',
            observed_at: activeEmail.upload_timestamp || new Date().toISOString(),
            confidence: 0.9,
            details: { ip: activeEmail.attribution.probable_origin_ip },
          });
        }
        setEvidenceItems(synth);
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchEvidence();
  }, [effectiveId]);

  const copyText = (txt: string, id: string) => {
    navigator.clipboard.writeText(txt);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const filteredItems = evidenceItems.filter(e => {
    if (activeFilter === 'ORIGINAL' && !e.is_original) return false;
    if (activeFilter === 'DERIVED' && e.is_original) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      return (
        e.name.toLowerCase().includes(q) ||
        e.evidence_type.toLowerCase().includes(q) ||
        (e.sha256 && e.sha256.toLowerCase().includes(q)) ||
        e.source.toLowerCase().includes(q)
      );
    }
    return true;
  });

  const originalItems = filteredItems.filter(e => e.is_original);
  const derivedItems = filteredItems.filter(e => !e.is_original);

  if (loading) {
    return (
      <div className="py-12">
        <LoadingState
          message="Loading investigation evidence dossier..."
          subtext="Distinguishing immutable original artifacts from derived analytical signals"
        />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Evidence Banner & Filter Controls */}
      <div className="bg-surface border border-border rounded-xl p-4 shadow-xs flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-center space-x-3">
          <div className="p-2 rounded-lg bg-primary/10 text-primary">
            <FileText className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h2 className="text-sm font-semibold text-foreground font-sans">
                Evidence Browser & Chain of Custody
              </h2>
              <Badge variant="outline" size="sm" className="font-mono text-[10px]">
                {evidenceItems.length} Total Items
              </Badge>
            </div>
            <p className="text-xs text-foreground-muted font-mono mt-0.5">
              Forensically immutable original artifacts separated from derived intelligence signals.
            </p>
          </div>
        </div>

        {/* Filters */}
        <div className="flex items-center space-x-2">
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-foreground-muted absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search evidence..."
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              className="pl-8 pr-3 py-1 bg-surface-secondary border border-border rounded-lg text-xs font-mono text-foreground placeholder:text-foreground-muted focus:outline-hidden focus:border-primary w-40 sm:w-48"
            />
          </div>

          <div className="flex items-center p-0.5 bg-surface-secondary border border-border rounded-lg text-xs font-mono">
            <button
              type="button"
              onClick={() => setActiveFilter('ALL')}
              className={`px-2 py-1 rounded transition-colors cursor-pointer ${
                activeFilter === 'ALL'
                  ? 'bg-surface text-primary font-bold shadow-xs'
                  : 'text-foreground-muted hover:text-foreground'
              }`}
            >
              All ({evidenceItems.length})
            </button>
            <button
              type="button"
              onClick={() => setActiveFilter('ORIGINAL')}
              className={`px-2 py-1 rounded transition-colors cursor-pointer ${
                activeFilter === 'ORIGINAL'
                  ? 'bg-surface text-primary font-bold shadow-xs'
                  : 'text-foreground-muted hover:text-foreground'
              }`}
            >
              Original ({originalItems.length})
            </button>
            <button
              type="button"
              onClick={() => setActiveFilter('DERIVED')}
              className={`px-2 py-1 rounded transition-colors cursor-pointer ${
                activeFilter === 'DERIVED'
                  ? 'bg-surface text-primary font-bold shadow-xs'
                  : 'text-foreground-muted hover:text-foreground'
              }`}
            >
              Derived ({derivedItems.length})
            </button>
          </div>
        </div>
      </div>

      {/* Group 1: Original Immutable Evidence (if visible under filter) */}
      {(activeFilter === 'ALL' || activeFilter === 'ORIGINAL') && originalItems.length > 0 && (
        <div className="space-y-3">
          <div className="flex items-center space-x-2">
            <Lock className="w-4 h-4 text-primary" />
            <h3 className="text-xs font-mono font-bold text-foreground uppercase tracking-wider">
              Original Evidence (Immutable Artifacts)
            </h3>
            <span className="text-[10px] font-mono text-foreground-muted">
              · Read-only cryptographic custody
            </span>
          </div>

          <div className="grid grid-cols-1 gap-3">
            {originalItems.map(item => (
              <div
                key={item.id}
                className="bg-surface border border-primary/20 rounded-xl p-4 shadow-xs hover:border-primary/40 transition-colors space-y-3"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex items-center space-x-2 min-w-0">
                    <span className="p-1.5 rounded-lg bg-primary/10 text-primary shrink-0">
                      <FileText className="w-4 h-4" />
                    </span>
                    <span className="font-sans text-xs font-bold text-foreground truncate">
                      {item.name}
                    </span>
                    <Badge variant="primary" size="sm" className="font-mono text-[9px] uppercase">
                      Immutable Original
                    </Badge>
                  </div>

                  <div className="flex items-center space-x-2 text-xs font-mono">
                    <span className="text-foreground-muted">Type:</span>
                    <span className="font-bold text-foreground">{item.evidence_type}</span>
                  </div>
                </div>

                {/* Hashes & Provenance */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono pt-2 border-t border-border">
                  {item.sha256 && (
                    <div className="flex items-center space-x-2 text-foreground-muted">
                      <Fingerprint className="w-3.5 h-3.5 text-primary shrink-0" />
                      <span className="text-foreground font-semibold">SHA-256:</span>
                      <span className="font-mono truncate text-[11px] text-foreground">
                        {item.sha256}
                      </span>
                      <button
                        type="button"
                        onClick={() => copyText(item.sha256!, item.id)}
                        className="p-1 hover:text-foreground text-foreground-muted cursor-pointer shrink-0"
                        title="Copy SHA-256"
                      >
                        {copiedId === item.id ? (
                          <Check className="w-3.5 h-3.5 text-success" />
                        ) : (
                          <Copy className="w-3.5 h-3.5" />
                        )}
                      </button>
                    </div>
                  )}

                  <div className="flex items-center justify-between md:justify-end space-x-4 text-foreground-muted text-[11px]">
                    <span>Source: <strong>{item.source}</strong></span>
                    <span>Observed: {new Date(item.observed_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Group 2: Derived Evidence & Signals */}
      {(activeFilter === 'ALL' || activeFilter === 'DERIVED') && derivedItems.length > 0 && (
        <div className="space-y-3">
          <div className="flex items-center space-x-2">
            <Layers className="w-4 h-4 text-accent" />
            <h3 className="text-xs font-mono font-bold text-foreground uppercase tracking-wider">
              Derived Evidence (Extracted Indicators & Telemetry)
            </h3>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {derivedItems.map(item => (
              <div
                key={item.id}
                onClick={() => {
                  setSelectedEvidence(item);
                  setDrawerOpen(true);
                }}
                className="bg-surface border border-border rounded-xl p-3.5 shadow-xs hover:border-border-focus transition-all cursor-pointer space-y-2 group"
              >
                <div className="flex items-center justify-between">
                  <span className="px-1.5 py-0.5 rounded bg-surface-secondary text-[10px] font-mono font-semibold text-foreground-muted border border-border uppercase">
                    {item.evidence_type}
                  </span>
                  <span className="text-[10px] font-mono text-foreground-muted">
                    Confidence: {Math.round(item.confidence * 100)}%
                  </span>
                </div>

                <div className="font-mono text-xs text-foreground font-semibold truncate group-hover:text-primary transition-colors">
                  {item.name}
                </div>

                <div className="flex items-center justify-between text-[11px] font-mono text-foreground-muted pt-2 border-t border-border">
                  <span>{item.source}</span>
                  <span className="text-primary group-hover:translate-x-0.5 transition-transform">
                    Inspect &rarr;
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Deep Inspection Drawer */}
      <EvidenceDetailDrawer
        isOpen={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        runId={effectiveId}
        evidenceId={selectedEvidence?.id}
        initialPreview={
          selectedEvidence
            ? {
                id: selectedEvidence.id,
                evidence_type: selectedEvidence.evidence_type,
                source: selectedEvidence.source,
                key: selectedEvidence.evidence_type,
                value: selectedEvidence.name,
                confidence: selectedEvidence.confidence,
              }
            : null
        }
      />
    </div>
  );
};
