import React, { useState } from 'react';
import type { EmailAnalysis, LookalikeDetectionResult } from '../../../types/forensic';
import {
  AlertOctagon,
  ShieldAlert,
  ExternalLink,
  Info,
  CheckCircle2,
  Sparkles
} from 'lucide-react';
import { ExpandableSection, DetailDrawer, MetadataRow } from '../../common/progressive';
import { CopyButton } from '../CopyButton';

interface AnalysisLookalikesSectionProps {
  email: EmailAnalysis;
}

const defang = (val?: string): string => {
  if (!val) return '';
  return val
    .replace(/\./g, '[.]')
    .replace(/http:\/\//g, 'hxxp://')
    .replace(/https:\/\//g, 'hxxps://');
};

export const AnalysisLookalikesSection: React.FC<AnalysisLookalikesSectionProps> = ({ email }) => {
  const [selectedRawLookalike, setSelectedRawLookalike] = useState<LookalikeDetectionResult | null>(null);

  const lookalikes: LookalikeDetectionResult[] = email.lookalike_domains || [];

  return (
    <div className="space-y-4 font-mono">
      <ExpandableSection
        title={`Domain Similarity & Lookalike Detection (${lookalikes.length})`}
        subtitle="Algorithmic typosquatting, homoglyph character substitution, and visual brand imitation"
        icon={AlertOctagon}
        defaultExpanded={true}
        badge={
          lookalikes.length > 0 ? (
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-danger-surface text-danger border border-danger-border flex items-center gap-1">
              <ShieldAlert className="w-3 h-3" />
              <span>{lookalikes.length} Impersonation{lookalikes.length !== 1 ? 's' : ''} Flagged</span>
            </span>
          ) : (
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-success-surface text-success border border-success-border flex items-center gap-1">
              <CheckCircle2 className="w-3 h-3" />
              <span>No Lookalikes Detected</span>
            </span>
          )
        }
      >
        <div className="space-y-4">
          {lookalikes.length === 0 ? (
            <div className="p-6 rounded-xl bg-surface-secondary/40 border border-border text-center text-xs text-foreground-muted space-y-1">
              <p className="font-bold text-foreground">No brand imitation detected</p>
              <p className="text-[11px]">
                Analyzed domains did not match known high-value brand spoofing or homoglyph patterns.
              </p>
            </div>
          ) : (
            <div className="space-y-3">
              {lookalikes.map((item, idx) => {
                const similarityPct = Math.round((item.similarity || 0) * 100);
                const techniques = item.techniques || [];

                return (
                  <div
                    key={`lookalike-${idx}-${item.domain}`}
                    className="p-4 rounded-xl bg-danger-surface/15 border border-danger-border/60 space-y-3 hover:border-danger-border transition-colors"
                  >
                    {/* Header: Domain, Brand, Similarity */}
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-2 border-b border-danger-border/30">
                      <div className="flex items-center space-x-2 flex-wrap">
                        <span className="text-[10px] uppercase font-bold text-danger flex items-center gap-1">
                          <AlertOctagon className="w-3.5 h-3.5" />
                          <span>Suspicious Lookalike:</span>
                        </span>
                        <span className="font-bold text-foreground text-sm break-all select-all">
                          {defang(item.domain)}
                        </span>
                        <CopyButton text={item.domain} iconOnly />
                      </div>

                      <div className="flex items-center space-x-2">
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-surface text-danger border border-danger-border">
                          {similarityPct}% Visual Resemblance
                        </span>
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-danger-surface text-danger border border-danger-border">
                          {item.confidence_label || 'High'} Confidence
                        </span>
                      </div>
                    </div>

                    {/* Why Detected Explanation */}
                    <div className="p-3 rounded-xl bg-surface/80 border border-border space-y-2 text-xs">
                      <div className="flex items-center space-x-1.5 text-foreground font-bold">
                        <Sparkles className="w-3.5 h-3.5 text-warning" />
                        <span>Why This Domain Was Flagged:</span>
                      </div>
                      <p className="text-foreground-muted text-[11px] leading-relaxed">
                        {item.details ||
                          `Domain "${item.domain}" intentionally mimics legitimate brand "${item.brand_name || item.suspected_brand}". An adversary likely registered this domain to deceive email recipients into believing communications originate from ${item.brand_name || item.suspected_brand}.`}
                      </p>

                      {/* Detection Techniques Badges */}
                      {techniques.length > 0 && (
                        <div className="pt-1 flex flex-wrap items-center gap-1.5">
                          <span className="text-[10px] uppercase font-bold text-foreground-muted mr-1">
                            Detection Vectors:
                          </span>
                          {techniques.map((tech, tIdx) => (
                            <span
                              key={tIdx}
                              className="px-2 py-0.5 rounded text-[10px] bg-warning-surface text-warning border border-warning-border font-semibold"
                            >
                              {tech.replace(/_/g, ' ')}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>

                    {/* Target Brand Comparison Grid */}
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
                      <MetadataRow
                        label="Target Brand Impersonated"
                        value={item.brand_name || item.suspected_brand || 'Recognized Brand'}
                      />
                      <MetadataRow
                        label="Apex Domain Analyzed"
                        value={defang(item.domain)}
                      />
                    </div>

                    {/* Level 3 Trigger */}
                    <div className="pt-2 flex items-center justify-between border-t border-danger-border/30 text-xs">
                      <span className="text-[11px] text-foreground-muted flex items-center gap-1">
                        <Info className="w-3 h-3 text-primary" />
                        <span>Algorithmic brand dictionary matching and homoglyph transformation matrix</span>
                      </span>
                      <button
                        type="button"
                        onClick={() => setSelectedRawLookalike(item)}
                        className="px-2.5 py-1 rounded-lg bg-surface border border-border hover:border-primary/50 text-foreground text-xs font-semibold flex items-center space-x-1 transition-colors cursor-pointer"
                      >
                        <ExternalLink className="w-3 h-3 text-primary" />
                        <span>View technical details</span>
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </ExpandableSection>

      {/* Level 3 Raw Drawer */}
      {selectedRawLookalike && (
        <DetailDrawer
          isOpen={Boolean(selectedRawLookalike)}
          onClose={() => setSelectedRawLookalike(null)}
          title="Domain Lookalike Detection Heuristics"
          subtitle={defang(selectedRawLookalike.domain)}
          data={selectedRawLookalike}
          format="json"
        />
      )}
    </div>
  );
};
