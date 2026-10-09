import React from 'react';
import {
  X,
  ShieldCheck,
  AlertTriangle,
  FileText,
  Layers,
  Clock,
  Hash,
  Database,
  Info
} from 'lucide-react';
import type { ExplanationUnit } from '../../../types/explainable_ai';

interface EvidenceDrawerProps {
  unit: ExplanationUnit | null;
  onClose: () => void;
}

export const EvidenceDrawer: React.FC<EvidenceDrawerProps> = ({ unit, onClose }) => {
  if (!unit) return null;

  return (
    <div className="fixed inset-0 z-50 overflow-hidden flex justify-end bg-black/60 backdrop-blur-xs animate-in fade-in duration-200">
      <div className="w-full max-w-xl bg-surface border-l border-border h-full shadow-2xl flex flex-col overflow-hidden animate-in slide-in-from-right duration-300">
        {/* Header */}
        <div className="p-5 border-b border-border flex items-center justify-between bg-surface-secondary/40">
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-lg bg-primary/10 border border-primary/20 text-primary">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="text-xs font-mono font-bold text-primary">{unit.id}</span>
                <span className="text-[10px] px-2 py-0.5 rounded-full font-mono font-semibold bg-surface-tertiary text-foreground-muted border border-border">
                  {unit.claim_type}
                </span>
                <span
                  className={`text-[10px] px-2 py-0.5 rounded-full font-mono font-bold ${
                    unit.support_level === 'CONFIRMED' || unit.support_level === 'VERY_HIGH'
                      ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                      : unit.support_level === 'HIGH'
                      ? 'bg-blue-500/10 text-blue-400 border border-blue-500/30'
                      : 'bg-amber-500/10 text-amber-400 border border-amber-500/30'
                  }`}
                >
                  {unit.support_level}
                </span>
              </div>
              <h3 className="text-sm font-semibold text-foreground mt-0.5">Forensic Evidence Inspection</h3>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="p-1.5 rounded-lg text-foreground-muted hover:text-foreground hover:bg-surface-tertiary transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-5 space-y-6">
          {/* Grounded Claim Card */}
          <div className="bg-surface-secondary rounded-xl p-4 border border-border space-y-2">
            <div className="text-xs font-mono font-semibold text-foreground-muted flex items-center space-x-1.5">
              <FileText className="w-3.5 h-3.5 text-primary" />
              <span>ASSERTED SECURITY CONCLUSION</span>
            </div>
            <p className="text-sm text-foreground font-medium leading-relaxed">
              {unit.claim}
            </p>
            <div className="pt-2 flex items-center space-x-4 text-xs font-mono text-foreground-muted border-t border-border/60">
              <div>
                Confidence: <span className="text-foreground font-bold">{Math.round(unit.confidence * 100)}%</span>
              </div>
              <div>
                Band: <span className="text-foreground font-bold">{unit.confidence_level}</span>
              </div>
            </div>
          </div>

          {/* Evidence References */}
          <div className="space-y-3">
            <div className="text-xs font-mono font-semibold text-foreground-muted flex items-center justify-between">
              <span className="flex items-center space-x-1.5">
                <Database className="w-3.5 h-3.5 text-primary" />
                <span>TRACEABLE EVIDENCE IDENTIFIERS ({unit.evidence_refs.length})</span>
              </span>
              <span className="text-[10px] text-foreground-subtle">Cryptographic & Telemetry IDs</span>
            </div>

            <div className="space-y-2">
              {unit.evidence_refs.length > 0 ? (
                unit.evidence_refs.map((ref, idx) => (
                  <div
                    key={idx}
                    className="p-3 bg-surface-tertiary/60 border border-border rounded-lg flex items-center justify-between text-xs font-mono group hover:border-primary/40 transition-colors"
                  >
                    <div className="flex items-center space-x-2">
                      <Hash className="w-3.5 h-3.5 text-foreground-muted group-hover:text-primary transition-colors" />
                      <span className="font-semibold text-foreground">{ref}</span>
                    </div>
                    <span className="text-[10px] px-2 py-0.5 rounded bg-surface border border-border text-foreground-muted">
                      Ground Truth
                    </span>
                  </div>
                ))
              ) : (
                <div className="p-3 text-xs text-foreground-muted bg-surface-secondary rounded-lg border border-border italic">
                  Direct sensor telemetry observation
                </div>
              )}
            </div>
          </div>

          {/* Source Artifacts */}
          {unit.source_refs && unit.source_refs.length > 0 && (
            <div className="space-y-3">
              <div className="text-xs font-mono font-semibold text-foreground-muted flex items-center space-x-1.5">
                <Layers className="w-3.5 h-3.5 text-primary" />
                <span>SOURCE ARTIFACTS & SENSORS</span>
              </div>
              <div className="flex flex-wrap gap-2">
                {unit.source_refs.map((src, idx) => (
                  <span
                    key={idx}
                    className="px-2.5 py-1 rounded-md text-xs font-mono bg-surface-secondary border border-border text-foreground"
                  >
                    {src}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Technical Provenance */}
          {unit.provenance && Object.keys(unit.provenance).length > 0 && (
            <div className="space-y-3">
              <div className="text-xs font-mono font-semibold text-foreground-muted flex items-center space-x-1.5">
                <Clock className="w-3.5 h-3.5 text-primary" />
                <span>DETECTOR PROVENANCE METADATA</span>
              </div>
              <div className="bg-surface-secondary/70 rounded-xl p-3 border border-border text-xs font-mono space-y-1.5">
                {Object.entries(unit.provenance).map(([key, value]) => (
                  <div key={key} className="flex items-start justify-between">
                    <span className="text-foreground-muted">{key}:</span>
                    <span className="text-foreground font-semibold text-right max-w-[65%] truncate">
                      {String(value)}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Limitations and Caveats */}
          {unit.limitations && unit.limitations.length > 0 && (
            <div className="p-3.5 rounded-xl bg-amber-500/10 border border-amber-500/20 text-xs space-y-1.5">
              <div className="font-semibold font-mono text-amber-400 flex items-center space-x-1.5">
                <AlertTriangle className="w-3.5 h-3.5" />
                <span>EVIDENTIARY BOUNDARIES & LIMITATIONS</span>
              </div>
              <ul className="list-disc list-inside text-foreground-muted space-y-1">
                {unit.limitations.map((lim, idx) => (
                  <li key={idx}>{lim}</li>
                ))}
              </ul>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-border bg-surface-secondary/30 flex items-center justify-between text-xs font-mono text-foreground-muted">
          <span className="flex items-center space-x-1.5">
            <Info className="w-3.5 h-3.5 text-primary" />
            <span>Deterministic Grounding Verified</span>
          </span>
          <button
            type="button"
            onClick={onClose}
            className="px-3 py-1.5 rounded-lg bg-surface-tertiary hover:bg-border text-foreground transition-colors font-sans font-medium"
          >
            Close Drawer
          </button>
        </div>
      </div>
    </div>
  );
};
