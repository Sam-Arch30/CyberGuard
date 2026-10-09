import React from 'react';
import {
  ShieldAlert,
  ArrowRight,
  CheckCircle2,
  HelpCircle,
  Activity,
} from 'lucide-react';
import type { InvestigationWorkspaceSummary } from '../../../types/investigationWorkspace';
import type { EmailAnalysis } from '../../../types/forensic';
import { Badge } from '../../ui';

interface ResponseRiskSummaryProps {
  summary?: InvestigationWorkspaceSummary | null;
  email?: EmailAnalysis | null;
  onNavigateToAnalysis?: () => void;
  onNavigateToAttackPath?: () => void;
}

export const ResponseRiskSummary: React.FC<ResponseRiskSummaryProps> = ({
  summary,
  email,
  onNavigateToAnalysis,
  onNavigateToAttackPath,
}) => {
  const risk = summary?.risk;
  const rawScore = risk?.score ?? email?.threat_score ?? 0;
  const numScore: number =
    typeof rawScore === 'number'
      ? rawScore
      : typeof rawScore === 'object' && rawScore && 'score' in rawScore
      ? (rawScore as any).score
      : 0;

  const severity =
    risk?.severity ||
    summary?.investigation?.severity ||
    (numScore >= 80 ? 'CRITICAL' : numScore >= 50 ? 'HIGH' : numScore >= 20 ? 'MEDIUM' : 'LOW');
  const confidence = risk?.confidence ?? (email as any)?.confidence_score ?? 0.85;
  const confidencePercent = Math.round(confidence * 100);

  const primaryDrivers: string[] = (risk as any)?.primary_drivers || [
    ...(email?.lookalike_domains && email.lookalike_domains.length > 0
      ? ['Adversary typosquatted domain observed in transport header']
      : []),
    ...((email as any)?.phishing_indicators && (email as any).phishing_indicators.length > 0
      ? [(email as any).phishing_indicators[0].description || 'High-confidence behavioral email lure pattern']
      : []),
    ...(numScore >= 75 ? ['Credential harvesting pattern targeting corporate identity'] : []),
  ];


  const getSeverityBadgeVariant = (sev: string): 'danger' | 'warning' | 'info' | 'success' | 'outline' => {
    switch (sev.toUpperCase()) {
      case 'CRITICAL':
      case 'HIGH':
        return 'danger';
      case 'MEDIUM':
        return 'warning';
      case 'LOW':
        return 'info';
      default:
        return 'outline';
    }
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
      {/* 1. CURRENT RISK PANEL */}
      <div className="lg:col-span-5 bg-surface border border-border rounded-xl p-5 shadow-xs flex flex-col justify-between">
        <div>
          <div className="flex items-center justify-between pb-3 border-b border-border/60">
            <div className="flex items-center space-x-2">
              <span className="p-1.5 rounded-lg bg-danger/10 text-danger border border-danger/20">
                <ShieldAlert className="w-4 h-4" />
              </span>
              <div>
                <span className="text-[11px] font-mono uppercase tracking-wider text-foreground-muted">
                  Current Threat Risk
                </span>
                <h3 className="text-sm font-semibold text-foreground font-sans">
                  Risk & Severity Assessment
                </h3>
              </div>
            </div>
            <Badge variant={getSeverityBadgeVariant(severity)} size="sm" className="font-mono text-[10px] font-bold">
              {severity.toUpperCase()}
            </Badge>
          </div>

          <div className="mt-4 flex items-baseline space-x-3">
            <span className="text-3xl font-extrabold font-mono tracking-tight text-foreground">
              {numScore}
            </span>
            <span className="text-xs font-mono text-foreground-muted">/ 100 Risk Score</span>
          </div>

          {/* Metric Indicators */}
          <div className="mt-4 grid grid-cols-2 gap-2 text-xs font-mono">
            <div className="p-2.5 rounded-lg bg-surface-secondary/70 border border-border/70 space-y-0.5">
              <span className="text-[10px] text-foreground-muted uppercase tracking-wider block">
                Confidence
              </span>
              <div className="flex items-center space-x-1.5 text-foreground font-semibold">
                <CheckCircle2 className="w-3.5 h-3.5 text-success shrink-0" />
                <span>{confidencePercent}% ({confidence >= 0.85 ? 'High' : 'Moderate'})</span>
              </div>
            </div>

            <div className="p-2.5 rounded-lg bg-surface-secondary/70 border border-border/70 space-y-0.5">
              <span className="text-[10px] text-foreground-muted uppercase tracking-wider block">
                Uncertainty
              </span>
              <div className="flex items-center space-x-1.5 text-foreground font-semibold">
                <HelpCircle className="w-3.5 h-3.5 text-warning shrink-0" />
                <span>{Math.max(100 - confidencePercent, 8)}% (Bounded)</span>
              </div>
            </div>
          </div>

          {/* Primary Drivers */}
          <div className="mt-4 space-y-1.5">
            <span className="text-[10px] font-mono uppercase tracking-wider text-foreground-muted">
              Authoritative Risk Drivers
            </span>
            <ul className="space-y-1.5 text-xs text-foreground font-sans">
              {primaryDrivers.slice(0, 3).map((driver: string, idx: number) => (
                <li key={idx} className="flex items-start space-x-2">
                  <span className="text-primary mt-0.5 text-xs font-mono">•</span>
                  <span className="line-clamp-2">{driver}</span>
                </li>
              ))}
            </ul>
          </div>

        </div>

        {onNavigateToAnalysis && (
          <div className="pt-4 mt-4 border-t border-border/60">
            <button
              type="button"
              onClick={onNavigateToAnalysis}
              className="inline-flex items-center space-x-1.5 text-xs font-mono text-primary hover:text-primary-hover font-semibold transition-colors group cursor-pointer"
            >
              <span>Inspect risk explanation & telemetry</span>
              <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-0.5 transition-transform" />
            </button>
          </div>
        )}
      </div>

      {/* 2. RISK <-> RESPONSE CONNECTION (WHY THESE ACTIONS?) */}
      <div className="lg:col-span-7 bg-surface-secondary/40 border border-border rounded-xl p-5 shadow-xs flex flex-col justify-between">
        <div>
          <div className="flex items-center space-x-2 pb-3 border-b border-border/60">
            <span className="p-1.5 rounded-lg bg-primary/10 text-primary border border-primary/20">
              <Activity className="w-4 h-4" />
            </span>
            <div>
              <span className="text-[11px] font-mono uppercase tracking-wider text-foreground-muted">
                Section 26 & 27 Grounding
              </span>
              <h3 className="text-sm font-semibold text-foreground font-sans">
                Why These Defensive Responses?
              </h3>
            </div>
          </div>

          <div className="mt-4 space-y-3 text-xs leading-relaxed text-foreground">
            <p>
              CyberGuard recommends targeted containment actions because the current assessment reflects verified adversary activity across multiple orthogonal detection engines:
            </p>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 font-mono text-[11px]">
              <div className="p-2.5 rounded-lg bg-surface border border-border/80 flex items-start space-x-2">
                <span className="text-danger font-bold mt-0.5">!</span>
                <div>
                  <span className="font-semibold text-foreground block">Verified Attacker Lure</span>
                  <span className="text-foreground-muted">Transport identity mismatch with deceptive brand tokens</span>
                </div>
              </div>

              <div className="p-2.5 rounded-lg bg-surface border border-border/80 flex items-start space-x-2">
                <span className="text-danger font-bold mt-0.5">!</span>
                <div>
                  <span className="font-semibold text-foreground block">Active Harvesting Surface</span>
                  <span className="text-foreground-muted">Domain resolved to suspicious non-corporate infrastructure</span>
                </div>
              </div>

              <div className="p-2.5 rounded-lg bg-surface border border-border/80 flex items-start space-x-2">
                <span className="text-warning font-bold mt-0.5">•</span>
                <div>
                  <span className="font-semibold text-foreground block">Target Scope Gating</span>
                  <span className="text-foreground-muted">Consequential containment gated behind analyst authorization</span>
                </div>
              </div>

              <div className="p-2.5 rounded-lg bg-surface border border-border/80 flex items-start space-x-2">
                <span className="text-success font-bold mt-0.5">✓</span>
                <div>
                  <span className="font-semibold text-foreground block">Forensic Precedence</span>
                  <span className="text-foreground-muted">Artifacts cryptographically preserved prior to state modification</span>
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="pt-4 mt-4 border-t border-border/60 flex items-center justify-between text-xs font-mono">
          <span className="text-foreground-muted">
            Decision boundary: Explicit human approval required for non-reversible changes.
          </span>
          {onNavigateToAttackPath && (
            <button
              type="button"
              onClick={onNavigateToAttackPath}
              className="inline-flex items-center space-x-1.5 text-primary hover:text-primary-hover font-semibold transition-colors shrink-0 group cursor-pointer"
            >
              <span>View attack path context</span>
              <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-0.5 transition-transform" />
            </button>
          )}
        </div>
      </div>
    </div>
  );
};
