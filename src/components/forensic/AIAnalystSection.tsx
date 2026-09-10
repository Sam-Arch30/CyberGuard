import React from 'react';
import type { AIAnalystAssessment } from '../../types/forensic';
import type { ForensicConclusion } from '../../types/confidence';
import { ConfidenceBadge } from '../common/ConfidenceBadge';
import {
  Sparkles,
  Target,
  ShieldAlert,
  CheckCircle2,
  ListOrdered,
  AlertTriangle,
  Info,
  Layers
} from 'lucide-react';

interface AIAnalystSectionProps {
  aiAnalyst?: AIAnalystAssessment;
  conclusions?: ForensicConclusion[];
}

export const AIAnalystSection: React.FC<AIAnalystSectionProps> = ({ aiAnalyst, conclusions = [] }) => {
  const nlpOrThreatConclusion =
    conclusions.find((c) => c.type === 'nlp_classification') ||
    conclusions.find((c) => c.type === 'threat_classification');
  if (!aiAnalyst || !aiAnalyst.available) {
    return (
      <div className="rounded-card border border-border bg-surface p-5 shadow-xs space-y-3">
        <div className="flex items-center justify-between pb-2 border-b border-border">
          <div className="flex items-center space-x-2">
            <Sparkles className="w-4 h-4 text-foreground-muted" />
            <h3 className="text-xs font-mono font-bold tracking-wider uppercase text-foreground-muted">
              AI Analyst Assessment
            </h3>
          </div>
          <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-surface-secondary border border-border text-foreground-subtle">
            Section 12 Copilot
          </span>
        </div>

        <div className="p-4 rounded-xl bg-surface-secondary/40 border border-border flex items-start space-x-3 text-xs font-mono text-foreground-muted">
          <Info className="w-4 h-4 text-primary shrink-0 mt-0.5" />
          <div className="space-y-1">
            <div className="text-foreground font-bold">
              AI analyst summary unavailable
            </div>
            <p className="text-[11px] text-foreground-muted leading-relaxed">
              {aiAnalyst?.error || 'The LLM provider is currently offline or disabled in backend configuration. All deterministic forensic signals and scoring remain 100% active and uncompromised.'}
            </p>
          </div>
        </div>
      </div>
    );
  }

  const {
    summary,
    likely_attack_type,
    likely_objective,
    key_evidence = [],
    recommended_actions = [],
    limitations = [],
    provider,
    model
  } = aiAnalyst;

  const isHighRisk = likely_attack_type.toLowerCase().includes('phishing') ||
                     likely_attack_type.toLowerCase().includes('harvest') ||
                     likely_attack_type.toLowerCase().includes('bec') ||
                     likely_attack_type.toLowerCase().includes('malware');

  return (
    <div className="rounded-card border border-border bg-surface p-6 shadow-sm space-y-6 transition-all">
      {/* Top Header Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-border">
        <div className="flex items-center space-x-2.5">
          <div className="p-2 rounded-xl bg-primary/10 border border-primary/20 text-primary">
            <Sparkles className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="text-[10px] font-mono font-bold tracking-widest uppercase text-primary">
                AI ANALYST ASSISTANT
              </span>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-surface-secondary border border-border text-foreground-muted">
                {model || provider || 'LLM Synthesis'}
              </span>
            </div>
            <h2 className="text-lg sm:text-xl font-bold font-sans text-foreground tracking-tight">
              Executive Threat Assessment
            </h2>
          </div>
        </div>

        <div className="flex items-center space-x-2">
          {nlpOrThreatConclusion && (
            <ConfidenceBadge
              conclusion={nlpOrThreatConclusion}
              allConclusions={conclusions}
              size="md"
            />
          )}
          <span className={`px-3 py-1 rounded-full text-xs font-mono font-extrabold uppercase tracking-wide border ${
            isHighRisk
              ? 'bg-danger/10 border-danger/30 text-danger'
              : 'bg-success/10 border-success/30 text-success'
          }`}>
            {likely_attack_type}
          </span>
        </div>
      </div>

      {/* Narrative Summary */}
      <div className="p-4 rounded-xl bg-surface-secondary/50 border border-border space-y-2">
        <div className="text-[10px] font-mono uppercase tracking-wider text-foreground-muted font-bold flex items-center space-x-1.5">
          <Layers className="w-3.5 h-3.5 text-primary" />
          <span>Forensic Summary</span>
        </div>
        <p className="text-xs sm:text-sm font-sans text-foreground leading-relaxed">
          {summary}
        </p>
      </div>

      {/* Two Column Grid: Attack Type & Objective */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Likely Attack Type */}
        <div className="p-4 rounded-xl bg-surface-secondary/40 border border-border space-y-1.5">
          <div className="flex items-center space-x-2 text-danger text-xs font-mono font-bold uppercase tracking-wider">
            <ShieldAlert className="w-4 h-4 text-danger" />
            <span>Likely Attack Type</span>
          </div>
          <p className="text-xs font-mono text-foreground font-semibold">
            {likely_attack_type}
          </p>
        </div>

        {/* Likely Objective */}
        <div className="p-4 rounded-xl bg-surface-secondary/40 border border-border space-y-1.5">
          <div className="flex items-center space-x-2 text-warning text-xs font-mono font-bold uppercase tracking-wider">
            <Target className="w-4 h-4 text-warning" />
            <span>Likely Objective</span>
          </div>
          <p className="text-xs font-mono text-foreground">
            {likely_objective}
          </p>
        </div>
      </div>

      {/* Key Evidence Corroboration */}
      {key_evidence.length > 0 && (
        <div className="space-y-3">
          <div className="flex items-center space-x-2">
            <CheckCircle2 className="w-4 h-4 text-primary" />
            <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-foreground-muted">
              Key Evidentiary Signals ({key_evidence.length})
            </h3>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
            {key_evidence.map((ev, idx) => (
              <div
                key={idx}
                className="p-3 rounded-xl bg-surface-secondary/40 border border-border flex items-start space-x-2.5"
              >
                <div className="w-1.5 h-1.5 rounded-full bg-primary mt-1.5 shrink-0" />
                <span className="text-xs font-mono text-foreground-muted leading-relaxed">
                  {ev}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Recommended SOC Actions */}
      {recommended_actions.length > 0 && (
        <div className="space-y-3">
          <div className="flex items-center space-x-2">
            <ListOrdered className="w-4 h-4 text-success" />
            <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-foreground-muted">
              Recommended SOC Response ({recommended_actions.length})
            </h3>
          </div>

          <div className="space-y-2">
            {recommended_actions.map((act, aIdx) => (
              <div
                key={aIdx}
                className="p-3 rounded-xl bg-surface-secondary/40 border border-border flex items-start space-x-3 hover:border-success/60 transition-colors"
              >
                <div className="flex items-center justify-center w-5 h-5 rounded-md bg-success/10 border border-success/30 text-success text-[11px] font-mono font-bold shrink-0">
                  {aIdx + 1}
                </div>
                <span className="text-xs font-mono text-foreground leading-relaxed">
                  {act}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Analytic Limitations & Boundaries */}
      {limitations.length > 0 && (
        <div className="p-3.5 rounded-xl bg-warning-surface border border-warning-border space-y-2">
          <div className="flex items-center space-x-2 text-warning text-xs font-mono font-bold uppercase tracking-wider">
            <AlertTriangle className="w-3.5 h-3.5 text-warning shrink-0" />
            <span>Analytic Limitations &amp; Blindspots</span>
          </div>
          <ul className="space-y-1 pl-4 list-disc text-[11px] font-mono text-foreground-muted">
            {limitations.map((lim, lIdx) => (
              <li key={lIdx}>{lim}</li>
            ))}
          </ul>
        </div>
      )}

      {/* Transparency / Non-Authoritative Disclaimer */}
      <div className="p-2.5 rounded-lg bg-surface-secondary/60 border border-border text-[11px] font-mono text-foreground-muted flex items-start space-x-2">
        <Info className="w-3.5 h-3.5 text-foreground-muted shrink-0 mt-0.5" />
        <span>
          <strong className="text-foreground">Analyst Advisory:</strong> The AI Analyst Assistant generates contextual narrative interpretations from structured evidence. It is not the source of truth and does not override deterministic SPF/DKIM/DMARC authentication or forensic network scoring.
        </span>
      </div>
    </div>
  );
};
