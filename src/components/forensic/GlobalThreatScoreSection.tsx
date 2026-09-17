import React, { useState, useMemo } from 'react';
import {
  ShieldCheck,
  AlertTriangle,
  Info,
  HelpCircle,
  ChevronDown,
  ChevronUp,
  Activity,
  BrainCircuit,
  Scale,
  Layers,
  TrendingUp,
  TrendingDown,
  Copy,
  Check
} from 'lucide-react';
import { Modal, ModalHeader, ModalTitle, ModalDescription, ModalBody, ModalFooter } from '../ui/Modal';
import { Button } from '../ui/Button';
import type {
  ThreatScoreResult,
  MLAssessmentResult,
  ThreatSignalContribution
} from '../../types/forensic';
import type { ForensicConclusion } from '../../types/confidence';
import { ConfidenceBadge } from '../common/ConfidenceBadge';

interface GlobalThreatScoreSectionProps {
  threatScore?: ThreatScoreResult;
  mlAssessment?: MLAssessmentResult;
  mlProbability?: number | null;
  conclusions?: ForensicConclusion[];
}

const CATEGORY_DISPLAY_MAP: Record<string, string> = {
  authentication: 'Authentication Risk',
  sender_identity: 'Sender Identity Risk',
  domain_intelligence: 'Domain Risk',
  lookalike_detection: 'Lookalike Risk',
  url_intelligence: 'URL Risk',
  infrastructure: 'Infrastructure Risk',
  email_content: 'Content Risk',
  campaign_intelligence: 'Campaign Risk',
  attachments: 'Attachment Risk'
};

export const GlobalThreatScoreSection: React.FC<GlobalThreatScoreSectionProps> = ({
  threatScore,
  mlAssessment,
  mlProbability,
  conclusions = []
}) => {
  const [expandedSignals, setExpandedSignals] = useState<Record<string, boolean>>({});
  const [selectedCategory, setSelectedCategory] = useState<string>('all');
  const [directionFilter, setDirectionFilter] = useState<'all' | 'increase_risk' | 'decrease_risk'>('all');
  const [showAuditModal, setShowAuditModal] = useState<boolean>(false);

  const {
    score = 0,
    severity = 'low',
    risk_level,
    confidence: rawConfidence,
    positive_contributions = [],
    negative_contributions = [],
    top_reasons = [],
    reasons = [],
    positive_evidence = [],
    summary = '',
    why_flagged = [],
    category_breakdowns = {},
    scoring_version = '2.0.0-explainable',
    model_version = 'v1.0-tfidf-logistic',
    audit_metadata
  } = threatScore || {};

  // Derive active risk level: explainable risk_level takes precedence, fallback to severity
  const effectiveRiskLevel: 'CRITICAL' | 'HIGH' | 'SUSPICIOUS' | 'LOW' =
    risk_level ||
    (severity === 'critical'
      ? 'CRITICAL'
      : severity === 'high'
      ? 'HIGH'
      : severity === 'suspicious'
      ? 'SUSPICIOUS'
      : 'LOW');

  // Evidence Confidence: explainable engine confidence takes precedence
  const effectiveConfidence = (
    rawConfidence ||
    (score >= 70 ? 'VERY HIGH' : score >= 40 ? 'HIGH' : score >= 20 ? 'MODERATE' : 'LOW')
  ).toUpperCase();

  const threatConclusion = conclusions.find((c) => c.type === 'threat_classification');

  const DEFAULT_WEIGHTS_SNAPSHOT: Record<string, number> = {
    brand_impersonation: 18,
    html_link_mismatch: 15,
    url_high_risk: 15,
    url_suspicious: 8,
    dmarc_fail: 12,
    credential_request: 12,
    domain_age_under_7d: 14,
    newly_registered_domain: 10,
    financial_language: 10,
    urgency_language: 8,
    spf_fail: 8,
    dkim_fail: 8,
    reply_to_mismatch: 8,
    return_path_mismatch: 6,
    suspicious_ip_hosting_or_proxy: 8,
    suspicious_attachment_extension: 15,
    known_campaign_match: 14,
    shared_malicious_infrastructure: 12,
    ml_phishing_signal: 10,
    trusted_sender_history: -5
  };

  const DEFAULT_THRESHOLDS_SNAPSHOT: Record<string, { min: number; max: number }> = {
    LOW: { min: 0, max: 24 },
    SUSPICIOUS: { min: 25, max: 49 },
    HIGH: { min: 50, max: 74 },
    CRITICAL: { min: 75, max: 100 }
  };

  const effectiveWeightsSnapshot =
    audit_metadata?.weights_snapshot && Object.keys(audit_metadata.weights_snapshot).length > 0
      ? audit_metadata.weights_snapshot
      : DEFAULT_WEIGHTS_SNAPSHOT;

  const effectiveThresholdsSnapshot =
    audit_metadata?.thresholds_snapshot && Object.keys(audit_metadata.thresholds_snapshot).length > 0
      ? audit_metadata.thresholds_snapshot
      : DEFAULT_THRESHOLDS_SNAPSHOT;

  const [copiedAuditJson, setCopiedAuditJson] = useState<boolean>(false);

  // Resolve effective probability from mlProbability or mlAssessment
  const resolvedProbability =
    typeof mlProbability === 'number'
      ? mlProbability
      : mlAssessment && typeof mlAssessment.probability === 'number'
      ? mlAssessment.probability
      : null;

  // Build unified structured contributions with backward-compatibility fallback
  const allContributions: ThreatSignalContribution[] = useMemo(() => {
    if (positive_contributions.length > 0 || negative_contributions.length > 0) {
      return [...positive_contributions, ...negative_contributions];
    }
    // Fallback: construct contributions from legacy reasons and positive_evidence
    const legacyList: ThreatSignalContribution[] = [];
    reasons.forEach((r, idx) => {
      legacyList.push({
        signal_id: `SIG-LEGACY-${idx + 1}`,
        category: r.signal.includes('url')
          ? 'url_intelligence'
          : r.signal.includes('spf') || r.signal.includes('dkim') || r.signal.includes('dmarc')
          ? 'authentication'
          : r.signal.includes('domain')
          ? 'domain_intelligence'
          : r.signal.includes('lookalike') || r.signal.includes('brand')
          ? 'lookalike_detection'
          : r.signal.includes('ip')
          ? 'infrastructure'
          : 'email_content',
        name: r.label,
        description: r.evidence,
        why_it_matters: 'Forensic risk signal contributing to aggregate threat severity score.',
        raw_value: r.points,
        normalized_value: 1.0,
        weight: r.points,
        contribution: r.points,
        direction: 'increase_risk',
        confidence: 0.9,
        evidence_reference: r.evidence,
        source: 'Forensic Analysis Engine'
      });
    });
    positive_evidence.forEach((p, idx) => {
      legacyList.push({
        signal_id: `SIG-MIT-LEGACY-${idx + 1}`,
        category: p.signal.includes('domain') ? 'domain_intelligence' : 'authentication',
        name: p.label,
        description: p.evidence,
        why_it_matters: 'Verified security control mitigating baseline email risk.',
        raw_value: p.evidence,
        normalized_value: 0.0,
        weight: 0,
        contribution: 0,
        direction: 'decrease_risk',
        confidence: 1.0,
        evidence_reference: p.evidence,
        source: 'Security Controls Verifier'
      });
    });
    return legacyList;
  }, [positive_contributions, negative_contributions, reasons, positive_evidence]);

  const handleCopyAuditJson = () => {
    const auditPayload = {
      scoring_version,
      model_version,
      timestamp: audit_metadata?.timestamp || new Date().toISOString(),
      score,
      risk_level: effectiveRiskLevel,
      evidence_ids: audit_metadata?.evidence_ids || allContributions.map(c => c.signal_id),
      weights_snapshot: effectiveWeightsSnapshot,
      thresholds_snapshot: effectiveThresholdsSnapshot
    };
    navigator.clipboard.writeText(JSON.stringify(auditPayload, null, 2));
    setCopiedAuditJson(true);
    setTimeout(() => setCopiedAuditJson(false), 2000);
  };

  // Filtered contributions list
  const filteredContributions = useMemo(() => {
    return allContributions.filter((c) => {
      const matchCat = selectedCategory === 'all' || c.category === selectedCategory;
      const matchDir = directionFilter === 'all' || c.direction === directionFilter;
      return matchCat && matchDir;
    });
  }, [allContributions, selectedCategory, directionFilter]);

  // Aggregate category stats
  const categoryStats = useMemo(() => {
    const stats: Record<string, { totalPoints: number; count: number }> = {};
    Object.keys(CATEGORY_DISPLAY_MAP).forEach((k) => {
      stats[k] = { totalPoints: 0, count: 0 };
    });
    allContributions.forEach((c) => {
      if (!stats[c.category]) {
        stats[c.category] = { totalPoints: 0, count: 0 };
      }
      stats[c.category].totalPoints += c.contribution;
      stats[c.category].count += 1;
    });
    return stats;
  }, [allContributions]);

  // Toggle card expansion
  const toggleSignal = (id: string) => {
    setExpandedSignals((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const getRiskStyle = (risk: string) => {
    switch (risk) {
      case 'CRITICAL':
        return {
          border: 'border-danger-border',
          bg: 'bg-danger-surface',
          badgeBg: 'bg-danger/10 border border-danger/30 text-danger',
          barColor: 'bg-danger',
          textColor: 'text-danger',
          gradientText: 'from-danger to-rose-400'
        };
      case 'HIGH':
        return {
          border: 'border-warning-border',
          bg: 'bg-warning-surface',
          badgeBg: 'bg-warning/15 border border-warning/30 text-warning',
          barColor: 'bg-warning',
          textColor: 'text-warning',
          gradientText: 'from-warning to-amber-400'
        };
      case 'SUSPICIOUS':
        return {
          border: 'border-warning-border',
          bg: 'bg-warning-surface',
          badgeBg: 'bg-warning/10 border border-warning/20 text-warning',
          barColor: 'bg-warning',
          textColor: 'text-warning',
          gradientText: 'from-amber-400 to-yellow-300'
        };
      default:
        return {
          border: 'border-success-border',
          bg: 'bg-success-surface',
          badgeBg: 'bg-success/10 border border-success/30 text-success',
          barColor: 'bg-success',
          textColor: 'text-success',
          gradientText: 'from-success to-emerald-400'
        };
    }
  };

  if (!threatScore) return null;

  const style = getRiskStyle(effectiveRiskLevel);

  return (
    <div
      id="explainable-threat-scoring-engine"
      className={`rounded-card border ${style.border} ${style.bg} p-6 shadow-sm space-y-6 transition-all`}
    >
      {/* Engine Header & Audit Action */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-5 border-b border-border">
        <div className="space-y-1.5">
          <div className="flex flex-wrap items-center gap-2">
            <Activity className={`w-5 h-5 ${style.textColor}`} />
            <span className="text-xs font-mono font-bold tracking-widest uppercase text-foreground-muted">
              EXPLAINABLE THREAT SCORING ENGINE
            </span>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-primary/10 border border-primary/25 text-primary font-semibold">
              ETSE {scoring_version}
            </span>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-surface-secondary border border-border text-foreground-muted">
              {model_version}
            </span>
          </div>

          <h2 className="text-xl sm:text-2xl font-bold font-sans tracking-tight text-foreground">
            Multi-Signal Threat Attribution &amp; Score Decomposition
          </h2>

          <p className="text-xs font-mono text-foreground-muted leading-relaxed max-w-3xl">
            {summary ||
              'Comprehensive multi-vector forensic evaluation deconstructing threat contributions across 9 analytical categories.'}
          </p>
        </div>

        {/* Audit / Reproducibility Button */}
        <button
          onClick={() => setShowAuditModal(true)}
          className="inline-flex items-center space-x-2 px-3.5 py-2 rounded-lg bg-surface border border-border hover:bg-surface-secondary text-xs font-mono text-foreground transition-all shrink-0 cursor-pointer shadow-xs group"
          title="Inspect scoring weights snapshot, threshold boundaries, and audit reproducibility metadata"
        >
          <Scale className="w-4 h-4 text-primary group-hover:rotate-12 transition-transform" />
          <span>Audit Snapshot</span>
        </button>
      </div>

      {/* Hero Dual Metrics: Threat Score & Evidence Confidence */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Left Hero Card: Threat Score */}
        <div className="p-5 rounded-xl bg-surface border border-border shadow-xs flex items-center justify-between gap-4">
          <div className="space-y-2">
            <div className="text-[11px] font-mono uppercase text-foreground-muted tracking-wider font-semibold">
              Threat Score
            </div>
            <div className="flex items-baseline space-x-2">
              <span className={`text-5xl font-extrabold font-mono tracking-tight ${style.textColor}`}>
                {score}
              </span>
              <span className="text-lg font-mono text-foreground-muted">/ 100</span>
            </div>
            <div className="text-[11px] font-mono text-foreground-muted">
              Calculated from net positive &amp; mitigating contributions
            </div>
          </div>

          <div className="text-right space-y-2 shrink-0">
            <div className="text-[10px] font-mono uppercase text-foreground-muted tracking-wider">
              Risk Level
            </div>
            <span
              className={`inline-block px-4 py-1.5 rounded-full text-xs font-mono font-extrabold shadow-xs ${style.badgeBg}`}
            >
              {effectiveRiskLevel}
            </span>
            <div className="text-[10px] font-mono text-foreground-muted">
              {effectiveRiskLevel === 'CRITICAL'
                ? '75–100 CRITICAL'
                : effectiveRiskLevel === 'HIGH'
                ? '50–74 HIGH'
                : effectiveRiskLevel === 'SUSPICIOUS'
                ? '25–49 SUSPICIOUS'
                : '0–24 LOW'}
            </div>
          </div>
        </div>

        {/* Right Hero Card: Evidence Confidence */}
        <div className="p-5 rounded-xl bg-surface border border-border shadow-xs flex items-center justify-between gap-4">
          <div className="space-y-2">
            <div className="text-[11px] font-mono uppercase text-foreground-muted tracking-wider font-semibold flex items-center space-x-1.5">
              <span>Evidence Confidence</span>
              <Info className="w-3.5 h-3.5 text-foreground-muted" />
            </div>
            <div className="flex items-center space-x-3">
              {threatConclusion ? (
                <ConfidenceBadge
                  conclusion={threatConclusion}
                  allConclusions={conclusions}
                  size="lg"
                  level={effectiveConfidence}
                />
              ) : (
                <span
                  className={`inline-block px-3.5 py-1.5 rounded-full text-sm font-mono font-extrabold ${
                    effectiveConfidence === 'VERY HIGH' || effectiveConfidence === 'HIGH'
                      ? 'bg-success/15 border border-success/30 text-success'
                      : effectiveConfidence === 'MODERATE'
                      ? 'bg-warning/15 border border-warning/30 text-warning'
                      : 'bg-surface-secondary border border-border text-foreground-muted'
                  }`}
                >
                  {effectiveConfidence}
                </span>
              )}
            </div>
            <p className="text-[11px] font-mono text-foreground-muted">
              Distinct from threat score: measures corroboration across independent sensors
            </p>
          </div>

          <div className="text-right space-y-1.5 max-w-[140px] shrink-0 border-l border-border pl-4">
            <div className="text-[10px] font-mono uppercase text-foreground-muted">
              Active Signals
            </div>
            <div className="text-xl font-mono font-bold text-foreground">
              {allContributions.length}
            </div>
            <div className="text-[10px] font-mono text-foreground-muted">
              +{positive_contributions.length || reasons.length} / -{negative_contributions.length || positive_evidence.length}
            </div>
          </div>
        </div>
      </div>

      {/* Progress Bar with Configurable Range Tiers */}
      <div className="space-y-2 bg-surface p-4 rounded-xl border border-border">
        <div className="flex items-center justify-between text-xs font-mono">
          <span className="text-foreground-muted">Normalized Risk Continuum (0–100):</span>
          <span className="font-bold text-foreground">{score} / 100 ({effectiveRiskLevel})</span>
        </div>

        <div className="w-full bg-surface-secondary rounded-full h-3 overflow-hidden border border-border flex relative">
          <div
            className={`h-full ${style.barColor} transition-all duration-500 rounded-full`}
            style={{ width: `${Math.max(score, 2)}%` }}
          />
        </div>

        <div className="grid grid-cols-4 text-[10px] font-mono text-foreground-muted pt-1 text-center border-t border-border/50 mt-1.5">
          <div className={`py-0.5 ${score <= 24 ? 'text-success font-bold' : ''}`}>
            0–24 LOW
          </div>
          <div className={`py-0.5 border-l border-border/40 ${score >= 25 && score <= 49 ? 'text-warning font-bold' : ''}`}>
            25–49 SUSPICIOUS
          </div>
          <div className={`py-0.5 border-l border-border/40 ${score >= 50 && score <= 74 ? 'text-warning font-bold' : ''}`}>
            50–74 HIGH
          </div>
          <div className={`py-0.5 border-l border-border/40 ${score >= 75 ? 'text-danger font-bold' : ''}`}>
            75–100 CRITICAL
          </div>
        </div>
      </div>

      {/* "Why was this flagged?" Dedicated Explanatory Section */}
      <div className="p-5 rounded-xl bg-surface border border-border space-y-3.5 shadow-xs">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-border">
          <div className="flex items-center space-x-2">
            <HelpCircle className="w-5 h-5 text-primary" />
            <h3 className="text-sm font-mono font-bold text-foreground uppercase tracking-wider">
              Why was this flagged?
            </h3>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-primary/10 border border-primary/20 text-primary">
              Structured Evidence Narrative
            </span>
          </div>

          <span className="text-[10px] font-mono text-foreground-muted">
            Deterministic forensic attribution
          </span>
        </div>

        <div className="p-3.5 rounded-lg bg-surface-secondary/70 border border-border text-xs font-mono text-foreground leading-relaxed">
          {why_flagged ||
            (score === 0
              ? 'All inspected forensic layers (SPF/DKIM/DMARC authentication, URL features, sender identity, and attachments) conform to legitimate baselines without risk anomalies.'
              : `This email was flagged with a Threat Score of ${score}/100 (${effectiveRiskLevel}) based on ${
                  positive_contributions.length || reasons.length
                } corroborated risk indicators.`)}
        </div>

        {/* Top Reasons / Key Forensic Drivers Pills */}
        {top_reasons.length > 0 && (
          <div className="space-y-1.5">
            <div className="text-[10px] font-mono uppercase text-foreground-muted font-bold tracking-wider">
              Key Forensic Drivers:
            </div>
            <div className="flex flex-wrap gap-2">
              {top_reasons.map((reason, idx) => (
                <div
                  key={idx}
                  className="px-2.5 py-1 rounded-md text-xs font-mono bg-danger/10 border border-danger/25 text-danger font-medium flex items-center space-x-1.5"
                >
                  <TrendingUp className="w-3.5 h-3.5" />
                  <span>{reason}</span>
                </div>
              ))}
              {negative_contributions.length > 0 && (
                negative_contributions.map((neg, nIdx) => (
                  <div
                    key={`neg-${nIdx}`}
                    className="px-2.5 py-1 rounded-md text-xs font-mono bg-success/10 border border-success/25 text-success font-medium flex items-center space-x-1.5"
                  >
                    <TrendingDown className="w-3.5 h-3.5" />
                    <span>{neg.name} ({neg.contribution} pts)</span>
                  </div>
                ))
              )}
            </div>
          </div>
        )}
      </div>

      {/* Category Breakdowns Filter Grid */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <Layers className="w-4 h-4 text-primary" />
            <h3 className="text-xs font-mono font-bold text-foreground uppercase tracking-wider">
              Category Risk Decomposition ({Object.keys(CATEGORY_DISPLAY_MAP).length} Categories)
            </h3>
          </div>
          <span className="text-[11px] font-mono text-foreground-muted">
            Click category to filter contributions
          </span>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-2.5">
          {/* "All" button */}
          <button
            onClick={() => setSelectedCategory('all')}
            className={`p-3 rounded-lg border text-left transition-all cursor-pointer ${
              selectedCategory === 'all'
                ? 'bg-primary/10 border-primary text-primary font-bold shadow-xs'
                : 'bg-surface border-border text-foreground hover:bg-surface-secondary'
            }`}
          >
            <div className="text-[10px] font-mono uppercase text-foreground-muted">Overview</div>
            <div className="text-xs font-mono font-bold mt-0.5 truncate">All Categories</div>
            <div className="text-[10px] font-mono text-foreground-muted mt-1">
              {allContributions.length} signals total
            </div>
          </button>

          {/* Each category button */}
          {Object.entries(CATEGORY_DISPLAY_MAP).map(([catKey, catDisplayName]) => {
            const catScoreObj = category_breakdowns[catKey];
            const catScore = catScoreObj ? catScoreObj.risk_score : (categoryStats[catKey]?.totalPoints || 0);
            const count = catScoreObj
              ? catScoreObj.positive_signals_count + catScoreObj.mitigating_signals_count
              : (categoryStats[catKey]?.count || 0);
            const isSelected = selectedCategory === catKey;

            return (
              <button
                key={catKey}
                onClick={() => setSelectedCategory(catKey)}
                className={`p-3 rounded-lg border text-left transition-all cursor-pointer ${
                  isSelected
                    ? 'bg-primary/10 border-primary text-primary font-bold shadow-xs'
                    : 'bg-surface border-border text-foreground hover:bg-surface-secondary'
                }`}
              >
                <div className="flex items-center justify-between gap-1">
                  <span className="text-[10px] font-mono uppercase text-foreground-muted truncate">
                    {catDisplayName.replace(' Risk', '')}
                  </span>
                  <span
                    className={`text-[10px] font-mono font-bold px-1.5 py-0.2 rounded ${
                      catScore > 0
                        ? 'bg-danger/10 text-danger'
                        : catScore < 0
                        ? 'bg-success/10 text-success'
                        : 'bg-surface-secondary text-foreground-muted'
                    }`}
                  >
                    {catScore > 0 ? `+${catScore}` : `${catScore}`}
                  </span>
                </div>

                <div className="text-xs font-mono font-bold mt-0.5 truncate">
                  {catDisplayName}
                </div>

                <div className="text-[10px] font-mono text-foreground-muted mt-1">
                  {count} {count === 1 ? 'signal' : 'signals'}
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Visual Contribution Breakdown (Waterfall / Stream) */}
      <div className="space-y-4 pt-2">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-2 border-b border-border">
          <div className="flex items-center space-x-2">
            <TrendingUp className="w-4 h-4 text-primary" />
            <h3 className="text-sm font-mono font-bold text-foreground uppercase tracking-wider">
              Signal Contributions Breakdown
            </h3>
            <span className="text-xs font-mono text-foreground-muted">
              ({filteredContributions.length} of {allContributions.length} shown)
            </span>
          </div>

          {/* Direction Filter Tabs */}
          <div className="flex items-center space-x-1.5 p-1 bg-surface rounded-lg border border-border text-xs font-mono">
            <button
              onClick={() => setDirectionFilter('all')}
              className={`px-2.5 py-1 rounded cursor-pointer transition-colors ${
                directionFilter === 'all'
                  ? 'bg-surface-secondary text-foreground font-bold shadow-2xs'
                  : 'text-foreground-muted hover:text-foreground'
              }`}
            >
              All Signals
            </button>
            <button
              onClick={() => setDirectionFilter('increase_risk')}
              className={`px-2.5 py-1 rounded cursor-pointer transition-colors ${
                directionFilter === 'increase_risk'
                  ? 'bg-danger/15 text-danger font-bold shadow-2xs'
                  : 'text-foreground-muted hover:text-foreground'
              }`}
            >
              + Risk Increases
            </button>
            <button
              onClick={() => setDirectionFilter('decrease_risk')}
              className={`px-2.5 py-1 rounded cursor-pointer transition-colors ${
                directionFilter === 'decrease_risk'
                  ? 'bg-success/15 text-success font-bold shadow-2xs'
                  : 'text-foreground-muted hover:text-foreground'
              }`}
            >
              - Mitigating Factors
            </button>
          </div>
        </div>

        {/* Contribution Cards List */}
        {filteredContributions.length === 0 ? (
          <div className="p-6 rounded-xl border border-border bg-surface text-center space-y-2">
            <ShieldCheck className="w-8 h-8 text-success mx-auto" />
            <div className="text-xs font-mono font-bold text-foreground">
              No matching signals for current filter
            </div>
            <p className="text-[11px] font-mono text-foreground-muted">
              No signals found for category "{selectedCategory}" and direction "{directionFilter}".
            </p>
          </div>
        ) : (
          <div className="space-y-3">
            {filteredContributions.map((contrib) => {
              const isExpanded = !!expandedSignals[contrib.signal_id];
              const isRiskIncrease = contrib.direction === 'increase_risk';

              return (
                <div
                  key={contrib.signal_id}
                  className="rounded-xl border border-border bg-surface hover:border-border-hover transition-all shadow-xs overflow-hidden"
                >
                  {/* Card Header Row */}
                  <div
                    onClick={() => toggleSignal(contrib.signal_id)}
                    className="p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 cursor-pointer select-none hover:bg-surface-secondary/40 transition-colors"
                  >
                    <div className="flex items-start space-x-3.5 min-w-0 flex-1">
                      {/* Signed Points Badge */}
                      <div
                        className={`px-2.5 py-1.5 rounded-lg text-xs font-mono font-bold shrink-0 text-center min-w-[65px] ${
                          isRiskIncrease
                            ? 'bg-danger/10 border border-danger/30 text-danger'
                            : contrib.contribution < 0
                            ? 'bg-success/10 border border-success/30 text-success'
                            : 'bg-surface-secondary border border-border text-foreground-muted'
                        }`}
                      >
                        {isRiskIncrease
                          ? `+${contrib.contribution} pts`
                          : contrib.contribution < 0
                          ? `${contrib.contribution} pts`
                          : '0 pts'}
                      </div>

                      <div className="space-y-1 min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="text-xs font-mono font-bold text-foreground">
                            {contrib.name}
                          </span>
                          <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-surface-secondary border border-border text-foreground-muted font-medium">
                            {CATEGORY_DISPLAY_MAP[contrib.category] || contrib.category}
                          </span>
                          <span className="text-[10px] font-mono text-foreground-muted">
                            {contrib.signal_id}
                          </span>
                        </div>

                        <p className="text-xs font-mono text-foreground-muted truncate">
                          {contrib.description}
                        </p>
                      </div>
                    </div>

                    <div className="flex items-center space-x-3 shrink-0 self-end sm:self-center">
                      <span className="text-[10px] font-mono text-foreground-muted hidden md:inline">
                        Source: <span className="text-foreground">{contrib.source}</span>
                      </span>

                      <button
                        className="p-1 rounded hover:bg-surface-secondary text-foreground-muted hover:text-foreground transition-colors"
                        aria-label={isExpanded ? 'Collapse signal details' : 'Expand signal details'}
                      >
                        {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                      </button>
                    </div>
                  </div>

                  {/* Expandable Forensic Details */}
                  {isExpanded && (
                    <div className="px-4 pb-4 pt-1 border-t border-border/60 bg-surface-secondary/30 space-y-3.5 text-xs font-mono">
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-2">
                        {/* What was detected */}
                        <div className="p-3 rounded-lg bg-surface border border-border space-y-1">
                          <div className="text-[10px] font-mono uppercase text-foreground-muted font-bold flex items-center space-x-1.5">
                            <Info className="w-3.5 h-3.5 text-primary" />
                            <span>What Was Detected</span>
                          </div>
                          <p className="text-foreground text-xs leading-relaxed">
                            {contrib.description}
                          </p>
                          {contrib.raw_value !== undefined && contrib.raw_value !== null && (
                            <div className="pt-1 text-[11px] text-foreground-muted">
                              <span className="text-foreground font-semibold">Observed Value:</span>{' '}
                              <code className="bg-surface-secondary px-1.5 py-0.5 rounded text-foreground font-mono">
                                {typeof contrib.raw_value === 'object'
                                  ? JSON.stringify(contrib.raw_value)
                                  : String(contrib.raw_value)}
                              </code>
                            </div>
                          )}
                        </div>

                        {/* Why it matters */}
                        <div className="p-3 rounded-lg bg-surface border border-border space-y-1">
                          <div className="text-[10px] font-mono uppercase text-foreground-muted font-bold flex items-center space-x-1.5">
                            <AlertTriangle className="w-3.5 h-3.5 text-warning" />
                            <span>Why It Matters</span>
                          </div>
                          <p className="text-foreground text-xs leading-relaxed">
                            {contrib.why_it_matters ||
                              'Directly impacts email threat assessment and security posture.'}
                          </p>
                        </div>
                      </div>

                      {/* Evidence Source & Reference Meta Bar */}
                      <div className="p-3 rounded-lg bg-surface border border-border flex flex-wrap items-center justify-between gap-3 text-[11px] text-foreground-muted">
                        <div className="flex flex-wrap items-center gap-3">
                          <div>
                            <span className="font-semibold text-foreground">Subsystem Source:</span>{' '}
                            <span>{contrib.source}</span>
                          </div>
                          {contrib.evidence_reference && (
                            <div>
                              <span className="font-semibold text-foreground">Evidence Ref:</span>{' '}
                              <span className="text-foreground">{contrib.evidence_reference}</span>
                            </div>
                          )}
                        </div>

                        <div className="flex items-center space-x-3">
                          <div>
                            <span className="font-semibold text-foreground">Weight:</span>{' '}
                            <span>{contrib.weight > 0 ? `+${contrib.weight}` : contrib.weight}</span>
                          </div>
                          <div>
                            <span className="font-semibold text-foreground">Direction:</span>{' '}
                            <span className={contrib.direction === 'increase_risk' ? 'text-danger font-bold' : 'text-success font-bold'}>
                              {contrib.direction === 'increase_risk' ? 'Risk (+)' : 'Mitigating (-)'}
                            </span>
                          </div>
                          <div>
                            <span className="font-semibold text-foreground">Confidence:</span>{' '}
                            <span>{Math.round((contrib.confidence || 1.0) * 100)}%</span>
                          </div>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Section 11: Content ML Assessment Display */}
      <div className="p-4 rounded-xl bg-surface border border-border space-y-3 shadow-xs">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-2 border-b border-border">
          <div className="flex items-center space-x-2">
            <BrainCircuit className="w-4 h-4 text-primary" />
            <h3 className="text-xs font-mono font-bold text-foreground uppercase tracking-wider">
              Content ML Assessment
            </h3>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-primary/10 border border-primary/20 text-primary">
              TF-IDF + Logistic Regression
            </span>
          </div>

          <div className="flex items-center space-x-2">
            <span className="text-[10px] font-mono text-foreground-muted uppercase">
              NLP Phishing Probability
            </span>
          </div>
        </div>

        {resolvedProbability !== null ? (
          <div className="space-y-3">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div className="flex items-baseline space-x-3">
                <span className="text-xs font-mono text-foreground-muted">
                  Phishing probability:
                </span>
                <span
                  className={`text-2xl font-bold font-mono ${
                    resolvedProbability >= 0.7
                      ? 'text-danger'
                      : resolvedProbability >= 0.4
                      ? 'text-warning'
                      : 'text-success'
                  }`}
                >
                  {Math.round(resolvedProbability * 100)}%
                </span>

                <span
                  className={`px-2.5 py-0.5 rounded-full text-[11px] font-mono font-bold uppercase ${
                    resolvedProbability >= 0.5
                      ? 'bg-danger/10 border border-danger/30 text-danger'
                      : 'bg-success/10 border border-success/30 text-success'
                  }`}
                >
                  {mlAssessment?.classification || (resolvedProbability >= 0.5 ? 'phishing' : 'legitimate')}
                </span>

                {mlAssessment?.confidence && (
                  <span className="text-[10px] font-mono text-foreground-muted">
                    ({mlAssessment.confidence} confidence)
                  </span>
                )}
              </div>

              {mlAssessment?.top_features && mlAssessment.top_features.length > 0 && (
                <div className="flex flex-wrap items-center gap-1.5">
                  <span className="text-[10px] font-mono text-foreground-muted">Key tokens:</span>
                  {mlAssessment.top_features.slice(0, 4).map((token, tIdx) => (
                    <span
                      key={tIdx}
                      className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-surface-secondary border border-border text-foreground font-medium"
                    >
                      {token}
                    </span>
                  ))}
                </div>
              )}
            </div>

            {/* Probability visual gauge */}
            <div className="space-y-1">
              <div className="w-full bg-surface-secondary rounded-full h-1.5 overflow-hidden border border-border">
                <div
                  className={`h-full transition-all duration-500 ${
                    resolvedProbability >= 0.7
                      ? 'bg-danger'
                      : resolvedProbability >= 0.4
                      ? 'bg-warning'
                      : 'bg-success'
                  }`}
                  style={{ width: `${Math.max(resolvedProbability * 100, 2)}%` }}
                />
              </div>
            </div>

            {/* Explanatory banner distinguishing ML content assessment from Overall threat score */}
            <div className="p-2.5 rounded-lg bg-surface-secondary/60 border border-border text-[11px] font-mono text-foreground-muted flex items-start space-x-2">
              <Info className="w-3.5 h-3.5 text-primary mt-0.5 shrink-0" />
              <span>
                <strong className="text-foreground">Model Scope Notice:</strong> "ML content assessment" ({Math.round(resolvedProbability * 100)}%) evaluates textual and semantic patterns in email text only. The "Overall threat score" ({score}/100) is the primary deterministic evaluation that combines network routing, SPF/DKIM/DMARC authentication, lookalike domains, URLs, and attachment risks, with bounded ML weighting (+10 max).
              </span>
            </div>
          </div>
        ) : (
          <div className="p-3 rounded-lg bg-surface-secondary/40 border border-border text-xs font-mono text-foreground-muted flex items-center space-x-2">
            <Info className="w-4 h-4 text-foreground-muted shrink-0" />
            <span>
              ML Content Assessment unavailable or email body empty. Deterministic forensic analysis continues unimpeded.
            </span>
          </div>
        )}
      </div>

      {/* Auditability & Historical Reproducibility Modal */}
      <Modal
        isOpen={showAuditModal}
        onClose={() => setShowAuditModal(false)}
        size="lg"
        className="font-mono text-xs max-h-[85vh] flex flex-col"
      >
        <ModalHeader className="pb-3">
          <div className="flex items-center justify-between gap-3 pr-6">
            <div className="flex items-center space-x-2.5">
              <div className="p-2 rounded-lg bg-primary/10 border border-primary/20 text-primary">
                <Scale className="w-5 h-5" />
              </div>
              <div>
                <ModalTitle>Scoring Engine Audit &amp; Reproducibility Snapshot</ModalTitle>
                <ModalDescription className="font-mono text-[11px] text-foreground-muted">
                  Immutable weight snapshot, registered evidence IDs, and active risk thresholds.
                </ModalDescription>
              </div>
            </div>
          </div>
        </ModalHeader>

        <ModalBody className="space-y-4 py-4 overflow-y-auto">
          <div className="p-3 rounded-lg bg-primary/5 border border-primary/20 text-foreground leading-relaxed flex items-start space-x-2">
            <Info className="w-4 h-4 text-primary shrink-0 mt-0.5" />
            <span>
              All scoring executions record immutable weight snapshots and registered evidence IDs.
              Historical cases remain 100% reproducible even if future engine weights or model thresholds change.
            </span>
          </div>

          {/* Engine Parameters Grid */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
            <div className="p-2.5 rounded-lg bg-surface-secondary border border-border">
              <div className="text-[10px] uppercase text-foreground-muted font-bold">Scoring Version</div>
              <div className="text-xs font-bold text-foreground mt-0.5">{scoring_version}</div>
            </div>
            <div className="p-2.5 rounded-lg bg-surface-secondary border border-border">
              <div className="text-[10px] uppercase text-foreground-muted font-bold">Model Version</div>
              <div className="text-xs font-bold text-foreground mt-0.5">{model_version}</div>
            </div>
            <div className="p-2.5 rounded-lg bg-surface-secondary border border-border col-span-2">
              <div className="text-[10px] uppercase text-foreground-muted font-bold">Audit Timestamp</div>
              <div className="text-xs font-bold text-foreground mt-0.5 truncate">
                {audit_metadata?.timestamp || new Date().toISOString()}
              </div>
            </div>
          </div>

          {/* Registered Evidence IDs */}
          <div className="space-y-1.5">
            <div className="text-[11px] font-bold uppercase text-foreground-muted flex items-center justify-between">
              <span>Registered Forensic Evidence IDs ({(audit_metadata?.evidence_ids?.length || allContributions.length)}):</span>
              <span className="text-[10px] text-foreground-muted font-normal">Linked to verifiable telemetry</span>
            </div>
            <div className="flex flex-wrap gap-1.5 max-h-24 overflow-y-auto p-2.5 rounded-lg bg-surface-secondary/50 border border-border">
              {(audit_metadata?.evidence_ids || allContributions.map((c) => c.signal_id)).map((id, idx) => (
                <span
                  key={idx}
                  className="px-2 py-0.5 rounded text-[10px] bg-surface border border-border text-foreground font-mono font-medium shadow-2xs"
                >
                  {id}
                </span>
              ))}
            </div>
          </div>

          {/* Active Risk Thresholds */}
          <div className="space-y-1.5">
            <div className="text-[11px] font-bold uppercase text-foreground-muted">
              Active Risk Thresholds Continuum:
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
              {Object.entries(effectiveThresholdsSnapshot).map(([tier, bounds]: [string, any]) => {
                const isCurrent = tier.toUpperCase() === effectiveRiskLevel;
                return (
                  <div
                    key={tier}
                    className={`p-2 rounded-lg border text-center ${
                      isCurrent
                        ? 'bg-primary/15 border-primary text-primary font-bold shadow-2xs'
                        : 'bg-surface-secondary border border-border text-foreground-muted'
                    }`}
                  >
                    <div className="text-[10px] uppercase">{tier}</div>
                    <div className="text-xs font-bold mt-0.5">
                      {bounds.min} – {bounds.max} pts
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Weights Snapshot Table */}
          <div className="space-y-1.5">
            <div className="text-[11px] font-bold uppercase text-foreground-muted flex items-center justify-between">
              <span>Configured Weights Snapshot ({Object.keys(effectiveWeightsSnapshot).length} rules):</span>
              <span className="text-[10px] text-foreground-muted font-normal">Signed Risk Weighting Matrix</span>
            </div>
            <div className="max-h-52 overflow-y-auto rounded-lg border border-border shadow-inner">
              <table className="w-full text-left border-collapse">
                <thead className="bg-surface-secondary text-[10px] text-foreground-muted uppercase sticky top-0 z-10 border-b border-border">
                  <tr>
                    <th className="p-2">Forensic Signal</th>
                    <th className="p-2 text-center">Status</th>
                    <th className="p-2 text-right">Configured Weight</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border text-[11px]">
                  {Object.entries(effectiveWeightsSnapshot).map(([sigKey, wVal]) => {
                    const isTriggered =
                      reasons.some((r) => r.signal === sigKey) ||
                      allContributions.some((c) => c.signal_id.toLowerCase().includes(sigKey) || c.name.toLowerCase().includes(sigKey.replace(/_/g, ' ')));
                    return (
                      <tr key={sigKey} className="hover:bg-surface-secondary/40">
                        <td className="p-2 font-mono text-foreground font-medium">
                          {sigKey}
                        </td>
                        <td className="p-2 text-center">
                          {isTriggered ? (
                            <span className="px-1.5 py-0.5 rounded text-[9px] font-mono bg-danger/15 text-danger font-bold border border-danger/30">
                              TRIGGERED
                            </span>
                          ) : (
                            <span className="text-[10px] font-mono text-foreground-muted">
                              Baseline
                            </span>
                          )}
                        </td>
                        <td
                          className={`p-2 text-right font-mono font-bold ${
                            wVal > 0 ? 'text-danger' : wVal < 0 ? 'text-success' : 'text-foreground-muted'
                          }`}
                        >
                          {wVal > 0 ? `+${wVal} pts` : `${wVal} pts`}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </ModalBody>

        <ModalFooter className="flex items-center justify-between">
          <Button
            variant="outline"
            size="sm"
            onClick={handleCopyAuditJson}
            leftIcon={copiedAuditJson ? <Check className="w-3.5 h-3.5 text-success" /> : <Copy className="w-3.5 h-3.5" />}
          >
            {copiedAuditJson ? 'Audit JSON Copied!' : 'Copy Audit Record (JSON)'}
          </Button>

          <Button
            variant="secondary"
            size="sm"
            onClick={() => setShowAuditModal(false)}
          >
            Close Audit View
          </Button>
        </ModalFooter>
      </Modal>
    </div>
  );
};
