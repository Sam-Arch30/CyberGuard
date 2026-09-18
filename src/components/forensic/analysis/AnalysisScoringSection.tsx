import React, { useState } from 'react';
import type { ThreatScoreResult } from '../../../types/forensic';
import {
  TrendingUp,
  TrendingDown,
  Info,
  Activity
} from 'lucide-react';
import { ExpandableSection, DetailDrawer } from '../../common/progressive';

interface AnalysisScoringSectionProps {
  threatScore?: ThreatScoreResult;
}

const CATEGORY_MAP: Record<string, string> = {
  authentication: 'Authentication',
  sender_identity: 'Sender Identity',
  domain_intelligence: 'Domain Intelligence',
  lookalike_detection: 'Lookalike Domain',
  url_intelligence: 'URL Telemetry',
  infrastructure: 'Infrastructure & Routing',
  email_content: 'Content & Language',
  attachments: 'Attachment Security'
};

export const AnalysisScoringSection: React.FC<AnalysisScoringSectionProps> = ({ threatScore }) => {
  const [selectedCategory, setSelectedCategory] = useState<string>('all');
  const [showAuditModal, setShowAuditModal] = useState<boolean>(false);

  const score = threatScore?.score ?? 0;
  const severity = (threatScore?.risk_level || threatScore?.severity || 'low').toUpperCase();
  const confidence = (threatScore?.confidence || (score >= 70 ? 'VERY HIGH' : score >= 40 ? 'HIGH' : 'MODERATE')).toUpperCase();

  // Real contributory signals
  const positiveContributions = threatScore?.positive_contributions || [];
  const negativeContributions = threatScore?.negative_contributions || [];
  const rawReasons = threatScore?.reasons || [];
  const rawMitigations = threatScore?.positive_evidence || [];

  // Normalize positive signals (drivers that increase risk)
  const riskDrivers = positiveContributions.length > 0
    ? positiveContributions.map((sig) => ({
        id: sig.signal_id,
        name: sig.name,
        category: sig.category,
        evidence: sig.description || sig.why_it_matters || 'Detected threat indicator elevating overall score.',
        points: typeof sig.contribution === 'number' ? sig.contribution : undefined,
        weight: typeof sig.weight === 'number' ? sig.weight : undefined,
        direction: 'increase' as const
      }))
    : rawReasons.map((r, i) => ({
        id: `reason-${i}`,
        name: r.label || r.signal,
        category: 'Threat Signal',
        evidence: r.evidence,
        points: typeof r.points === 'number' ? r.points : undefined,
        weight: undefined,
        direction: 'increase' as const
      }));

  // Normalize mitigating signals (factors that reduce risk)
  const mitigatingFactors = negativeContributions.length > 0
    ? negativeContributions.map((sig) => ({
        id: sig.signal_id,
        name: sig.name,
        category: sig.category,
        evidence: sig.description || sig.why_it_matters || 'Authentic security factor reducing threat assessment.',
        points: typeof sig.contribution === 'number' ? sig.contribution : undefined,
        weight: typeof sig.weight === 'number' ? sig.weight : undefined,
        direction: 'decrease' as const
      }))
    : rawMitigations.map((m, i) => ({
        id: `mitigation-${i}`,
        name: m.label || m.signal,
        category: 'Mitigating Factor',
        evidence: m.evidence,
        points: undefined,
        weight: undefined,
        direction: 'decrease' as const
      }));

  const allSignals = [...riskDrivers, ...mitigatingFactors];

  const filteredSignals = allSignals.filter((sig) => {
    if (selectedCategory === 'all') return true;
    if (selectedCategory === 'risk_only') return sig.direction === 'increase';
    if (selectedCategory === 'mitigating_only') return sig.direction === 'decrease';
    return sig.category.toLowerCase().includes(selectedCategory.toLowerCase());
  });

  const categoryBreakdowns = threatScore?.category_breakdowns || {};
  const hasCategories = Object.keys(categoryBreakdowns).length > 0;

  return (
    <div className="space-y-4 font-mono">
      <ExpandableSection
        title="Threat Scoring Engine & Real Signal Attribution"
        subtitle="Transparent audit-grounded breakdown of real forensic signals contributing to score evaluation"
        icon={Activity}
        defaultExpanded={true}
        badge={
          <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${
            severity === 'CRITICAL'
              ? 'bg-danger-surface text-danger border-danger-border'
              : severity === 'HIGH'
              ? 'bg-danger-surface text-danger border-danger-border'
              : severity === 'SUSPICIOUS'
              ? 'bg-warning-surface text-warning border-warning-border'
              : 'bg-success-surface text-success border-success-border'
          }`}>
            {score}/100 · {severity}
          </span>
        }
      >
        <div className="space-y-4">
          {/* 1. COMPACT SCORE HERO CARD */}
          <div className="p-4 rounded-xl bg-surface-secondary/40 border border-border flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="flex items-center space-x-4">
              <div className={`w-14 h-14 rounded-2xl flex flex-col items-center justify-center font-bold text-lg border shrink-0 ${
                severity === 'CRITICAL' || severity === 'HIGH'
                  ? 'bg-danger-surface text-danger border-danger-border shadow-xs'
                  : severity === 'SUSPICIOUS'
                  ? 'bg-warning-surface text-warning border-warning-border'
                  : 'bg-success-surface text-success border-success-border'
              }`}>
                <span>{score}</span>
                <span className="text-[9px] uppercase font-normal opacity-80">Score</span>
              </div>

              <div className="space-y-1 min-w-0">
                <div className="flex items-center space-x-2 flex-wrap">
                  <span className={`text-xs font-bold uppercase tracking-wider ${
                    severity === 'CRITICAL' || severity === 'HIGH' ? 'text-danger' : severity === 'SUSPICIOUS' ? 'text-warning' : 'text-success'
                  }`}>
                    {severity} Risk Classification
                  </span>
                  <span className="text-[10px] text-foreground-muted">
                    · Confidence: {confidence}
                  </span>
                </div>
                <p className="text-xs text-foreground-muted leading-relaxed font-sans max-w-2xl">
                  {threatScore?.summary ||
                    (score >= 70
                      ? 'High-confidence indicators confirm weaponized intent across authentication failure, lookalike domains, and social engineering lures.'
                      : score >= 40
                      ? 'Elevated suspicion detected. Several anomalies warrant analyst verification.'
                      : 'Authentic baseline confirmed. Zero critical security penalties identified.')}
                </p>
              </div>
            </div>

            <div className="flex items-center space-x-2 shrink-0 self-start md:self-auto text-xs">
              <div className="text-right hidden sm:block">
                <span className="text-[10px] uppercase font-bold text-foreground-muted block">
                  Scoring Pipeline
                </span>
                <span className="text-foreground text-[11px] font-semibold">
                  {threatScore?.scoring_version || 'v2.0-Explainable'}
                </span>
              </div>

              <button
                type="button"
                onClick={() => setShowAuditModal(true)}
                className="px-3 py-1.5 rounded-lg bg-surface border border-border hover:border-primary/50 text-foreground text-xs font-semibold flex items-center space-x-1.5 transition-colors cursor-pointer"
              >
                <Info className="w-3.5 h-3.5 text-primary" />
                <span>Audit Trail</span>
              </button>
            </div>
          </div>

          {/* 2. REAL CATEGORY BREAKDOWNS (If provided by backend) */}
          {hasCategories && (
            <div className="space-y-2">
              <span className="text-[10px] uppercase font-bold text-foreground-muted tracking-wider block">
                Category Risk Breakdown:
              </span>
              <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-2.5">
                {Object.entries(categoryBreakdowns).map(([key, cat]) => (
                  <div
                    key={key}
                    className="p-3 rounded-xl bg-surface border border-border space-y-1"
                  >
                    <div className="flex items-center justify-between text-[10px] text-foreground-muted uppercase font-bold">
                      <span className="truncate">{cat.display_name || CATEGORY_MAP[key] || key}</span>
                      <span className={cat.risk_score > 0 ? 'text-danger font-bold' : 'text-success font-bold'}>
                        {cat.risk_score}
                      </span>
                    </div>
                    <div className="w-full bg-surface-secondary rounded-full h-1.5 overflow-hidden">
                      <div
                        className={`h-full ${cat.risk_score >= 50 ? 'bg-danger' : cat.risk_score > 0 ? 'bg-warning' : 'bg-success'}`}
                        style={{ width: `${Math.min(cat.risk_score, 100)}%` }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* 3. CONTRIBUTING SIGNALS (Real signals explained) */}
          <div className="space-y-3 pt-1">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <span className="text-[10px] uppercase font-bold text-foreground-muted tracking-wider">
                Contributing Forensic Signals ({filteredSignals.length}):
              </span>

              {/* Filter controls */}
              <div className="flex flex-wrap items-center gap-1.5 text-xs">
                <button
                  type="button"
                  onClick={() => setSelectedCategory('all')}
                  className={`px-2 py-0.5 rounded text-[11px] font-semibold transition-colors cursor-pointer ${
                    selectedCategory === 'all'
                      ? 'bg-primary text-primary-foreground font-bold'
                      : 'bg-surface-secondary text-foreground-muted hover:text-foreground'
                  }`}
                >
                  All Signals ({allSignals.length})
                </button>
                <button
                  type="button"
                  onClick={() => setSelectedCategory('risk_only')}
                  className={`px-2 py-0.5 rounded text-[11px] font-semibold transition-colors cursor-pointer ${
                    selectedCategory === 'risk_only'
                      ? 'bg-danger-surface text-danger border border-danger-border font-bold'
                      : 'bg-surface-secondary text-foreground-muted hover:text-foreground'
                  }`}
                >
                  Penalties ({riskDrivers.length})
                </button>
                {mitigatingFactors.length > 0 && (
                  <button
                    type="button"
                    onClick={() => setSelectedCategory('mitigating_only')}
                    className={`px-2 py-0.5 rounded text-[11px] font-semibold transition-colors cursor-pointer ${
                      selectedCategory === 'mitigating_only'
                        ? 'bg-success-surface text-success border border-success-border font-bold'
                        : 'bg-surface-secondary text-foreground-muted hover:text-foreground'
                    }`}
                  >
                    Mitigations ({mitigatingFactors.length})
                  </button>
                )}
              </div>
            </div>

            {filteredSignals.length === 0 ? (
              <div className="p-6 text-center rounded-xl bg-surface-secondary/40 border border-border text-foreground-muted text-xs">
                No signals match the selected filter.
              </div>
            ) : (
              <div className="space-y-2">
                {filteredSignals.map((sig) => {
                  const isIncrease = sig.direction === 'increase';

                  return (
                    <div
                      key={sig.id}
                      className={`p-3 rounded-xl border flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 transition-colors ${
                        isIncrease
                          ? 'bg-surface border-border hover:border-danger-border/70'
                          : 'bg-success-surface/20 border-success-border/60'
                      }`}
                    >
                      {/* Left: Direction icon + Name + Real Evidence */}
                      <div className="flex items-start space-x-2.5 min-w-0 flex-1">
                        <div className="mt-0.5 shrink-0">
                          {isIncrease ? (
                            <TrendingUp className="w-4 h-4 text-danger" />
                          ) : (
                            <TrendingDown className="w-4 h-4 text-success" />
                          )}
                        </div>

                        <div className="space-y-0.5 min-w-0 flex-1">
                          <div className="flex items-center space-x-2 flex-wrap">
                            <span className="font-bold text-foreground text-xs">
                              {sig.name}
                            </span>
                            <span className="px-1.5 py-0.2 rounded text-[9px] bg-surface-secondary text-foreground-subtle border border-border uppercase">
                              {sig.category}
                            </span>
                          </div>

                          <p className="text-[11.5px] text-foreground-muted leading-relaxed font-sans">
                            {sig.evidence}
                          </p>
                        </div>
                      </div>

                      {/* Right: Points Impact (if provided by backend) */}
                      <div className="shrink-0 sm:text-right">
                        {typeof sig.points === 'number' ? (
                          <span className={`px-2.5 py-1 rounded-lg text-xs font-bold uppercase border ${
                            isIncrease
                              ? 'bg-danger-surface text-danger border-danger-border'
                              : 'bg-success-surface text-success border-success-border'
                          }`}>
                            {isIncrease ? `+${sig.points} pts` : `-${Math.abs(sig.points)} pts`}
                          </span>
                        ) : (
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${
                            isIncrease
                              ? 'bg-danger-surface text-danger border-danger-border'
                              : 'bg-success-surface text-success border-success-border'
                          }`}>
                            {isIncrease ? 'Elevates Risk' : 'Mitigates Risk'}
                          </span>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      </ExpandableSection>

      {/* Audit Modal */}
      {showAuditModal && (
        <DetailDrawer
          isOpen={showAuditModal}
          onClose={() => setShowAuditModal(false)}
          title="Threat Scoring Calculation Audit"
          subtitle={`Engine version: ${threatScore?.scoring_version || '2.0.0-explainable'}`}
          data={{
            score,
            severity,
            confidence,
            scoring_version: threatScore?.scoring_version,
            model_version: threatScore?.model_version,
            positive_signals: threatScore?.positive_contributions || threatScore?.reasons,
            mitigating_signals: threatScore?.negative_contributions || threatScore?.positive_evidence,
            category_breakdowns: threatScore?.category_breakdowns,
            audit_metadata: threatScore?.audit_metadata
          }}
          format="json"
        />
      )}
    </div>
  );
};
