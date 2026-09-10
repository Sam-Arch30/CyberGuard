import React, { useState } from 'react';
import {
  ShieldCheck,
  CheckCircle2,
  Info,
  HelpCircle,
  ChevronDown,
  ChevronUp,
  Activity
} from 'lucide-react';
import type { ThreatScoreResult, MLAssessmentResult } from '../../types/forensic';
import type { ForensicConclusion } from '../../types/confidence';
import { ConfidenceBadge } from '../common/ConfidenceBadge';
import { BrainCircuit } from 'lucide-react';

interface GlobalThreatScoreSectionProps {
  threatScore?: ThreatScoreResult;
  mlAssessment?: MLAssessmentResult;
  mlProbability?: number | null;
  conclusions?: ForensicConclusion[];
}

export const GlobalThreatScoreSection: React.FC<GlobalThreatScoreSectionProps> = ({
  threatScore,
  mlAssessment,
  mlProbability,
  conclusions = []
}) => {
  const [showDetails, setShowDetails] = useState(true);
  const threatConclusion = conclusions.find((c) => c.type === 'threat_classification');

  if (!threatScore) return null;

  const { score, severity, reasons, positive_evidence, summary } = threatScore;

  // Resolve effective probability from mlProbability or mlAssessment
  const resolvedProbability = typeof mlProbability === 'number'
    ? mlProbability
    : (mlAssessment && typeof mlAssessment.probability === 'number')
      ? mlAssessment.probability
      : null;

  const getSeverityStyle = (sev: string) => {
    switch (sev) {
      case 'critical':
        return {
          border: 'border-danger-border',
          bg: 'bg-danger-surface',
          badgeBg: 'bg-danger/10 border border-danger/30 text-danger',
          barColor: 'bg-danger',
          textColor: 'text-danger',
          label: 'CRITICAL'
        };
      case 'high':
        return {
          border: 'border-warning-border',
          bg: 'bg-warning-surface',
          badgeBg: 'bg-warning/15 border border-warning/30 text-warning',
          barColor: 'bg-warning',
          textColor: 'text-warning',
          label: 'HIGH'
        };
      case 'suspicious':
        return {
          border: 'border-warning-border',
          bg: 'bg-warning-surface',
          badgeBg: 'bg-warning/10 border border-warning/20 text-warning',
          barColor: 'bg-warning',
          textColor: 'text-warning',
          label: 'SUSPICIOUS'
        };
      default:
        return {
          border: 'border-success-border',
          bg: 'bg-success-surface',
          badgeBg: 'bg-success/10 border border-success/30 text-success',
          barColor: 'bg-success',
          textColor: 'text-success',
          label: 'LOW'
        };
    }
  };

  const style = getSeverityStyle(severity);

  return (
    <div className={`rounded-card border ${style.border} ${style.bg} p-6 shadow-sm space-y-6 transition-all`}>
      {/* Top Banner: Threat Score Gauge & Summary */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 pb-6 border-b border-border">
        <div className="space-y-2 max-w-xl">
          <div className="flex items-center space-x-2">
            <Activity className={`w-5 h-5 ${style.textColor}`} />
            <span className="text-xs font-mono font-bold tracking-widest uppercase text-foreground-muted">
              GLOBAL THREAT SCORING ENGINE
            </span>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-surface-secondary border border-border text-foreground-muted">
              Deterministic V1
            </span>
          </div>

          <h2 className="text-xl sm:text-2xl font-bold font-sans tracking-tight text-foreground">
            Threat Score Evaluation
          </h2>

          <p className="text-xs font-mono text-foreground-muted leading-relaxed">
            {summary}
          </p>
        </div>

        {/* Hero Score Display */}
        <div className="flex items-center space-x-6 p-4 rounded-xl bg-surface border border-border shrink-0 shadow-xs">
          <div className="space-y-1 text-center">
            <div className="text-[10px] font-mono uppercase text-foreground-muted tracking-wider">
              Threat Score
            </div>
            <div className="flex items-baseline justify-center space-x-1">
              <span className={`text-4xl font-extrabold font-mono tracking-tight ${style.textColor}`}>
                {score}
              </span>
              <span className="text-sm font-mono text-foreground-muted">/100</span>
            </div>
          </div>

          <div className="h-10 w-px bg-border" />

          <div className="space-y-1 text-center">
            <div className="text-[10px] font-mono uppercase text-foreground-muted tracking-wider">
              Classification
            </div>
            <span className={`inline-block px-3 py-1 rounded-full text-xs font-mono font-extrabold ${style.badgeBg}`}>
              {style.label}
            </span>
          </div>

          {threatConclusion && (
            <>
              <div className="h-10 w-px bg-border" />
              <div className="space-y-1 text-center">
                <div className="text-[10px] font-mono uppercase text-foreground-muted tracking-wider">
                  Evidence Confidence
                </div>
                <ConfidenceBadge
                  conclusion={threatConclusion}
                  allConclusions={conclusions}
                  size="md"
                />
              </div>
            </>
          )}
        </div>
      </div>

      {/* Progress Bar with Severity Ranges */}
      <div className="space-y-2">
        <div className="w-full bg-surface-secondary rounded-full h-2.5 overflow-hidden border border-border flex">
          <div
            className={`h-full ${style.barColor} transition-all duration-500`}
            style={{ width: `${Math.max(score, 2)}%` }}
          />
        </div>
        <div className="flex justify-between text-[10px] font-mono text-foreground-muted px-1">
          <span className={score < 30 ? 'text-success font-bold' : ''}>0–29 Low</span>
          <span className={score >= 30 && score < 60 ? 'text-warning font-bold' : ''}>30–59 Suspicious</span>
          <span className={score >= 60 && score < 80 ? 'text-warning font-bold' : ''}>60–79 High</span>
          <span className={score >= 80 ? 'text-danger font-bold' : ''}>80–100 Critical</span>
        </div>
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
              ML content assessment
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
                <span className={`text-2xl font-bold font-mono ${
                  resolvedProbability >= 0.70
                    ? 'text-danger'
                    : resolvedProbability >= 0.40
                      ? 'text-warning'
                      : 'text-success'
                }`}>
                  {Math.round(resolvedProbability * 100)}%
                </span>

                <span className={`px-2.5 py-0.5 rounded-full text-[11px] font-mono font-bold uppercase ${
                  resolvedProbability >= 0.50
                    ? 'bg-danger/10 border border-danger/30 text-danger'
                    : 'bg-success/10 border border-success/30 text-success'
                }`}>
                  {mlAssessment?.classification || (resolvedProbability >= 0.50 ? 'phishing' : 'legitimate')}
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
                    resolvedProbability >= 0.70
                      ? 'bg-danger'
                      : resolvedProbability >= 0.40
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
            <span>ML Content Assessment unavailable or email body empty. Deterministic forensic analysis continues unimpeded.</span>
          </div>
        )}
      </div>

      {/* "Why this score?" Section */}
      <div className="space-y-4 pt-2">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <HelpCircle className="w-4 h-4 text-primary" />
            <h3 className="text-sm font-mono font-bold text-foreground uppercase tracking-wider">
              Why this score?
            </h3>
            <span className="text-[11px] font-mono text-foreground-muted hidden sm:inline">
              ({reasons.length} risk signal{reasons.length === 1 ? '' : 's'} contributed)
            </span>
          </div>

          <button
            onClick={() => setShowDetails(!showDetails)}
            className="flex items-center space-x-1 text-xs font-mono text-foreground-muted hover:text-foreground transition-colors cursor-pointer"
          >
            <span>{showDetails ? 'Hide details' : 'Show details'}</span>
            {showDetails ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
          </button>
        </div>

        {showDetails && (
          <>
            {reasons.length === 0 ? (
              <div className="p-4 rounded-xl border border-success-border bg-success-surface text-success text-xs font-mono flex items-center space-x-2.5">
                <ShieldCheck className="w-4 h-4 text-success shrink-0" />
                <span>No risk signals were triggered. All inspected forensic layers conform to legitimate baselines.</span>
              </div>
            ) : (
              <div className="space-y-2.5">
                {reasons.map((reason, idx) => (
                  <div
                    key={idx}
                    className="p-3 rounded-xl border border-border bg-surface hover:bg-surface-secondary/70 transition-colors flex flex-col sm:flex-row sm:items-center justify-between gap-3 shadow-xs"
                  >
                    <div className="flex items-start space-x-3 min-w-0 flex-1">
                      <div className="px-2 py-1 rounded bg-danger/10 border border-danger/30 text-danger text-xs font-mono font-bold shrink-0">
                        +{reason.points} pts
                      </div>
                      <div className="min-w-0 space-y-0.5">
                        <div className="flex flex-wrap items-center gap-1.5">
                          <span className="text-xs font-mono font-bold text-foreground">
                            {reason.label}
                          </span>
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-surface-secondary border border-border text-foreground-muted">
                            {reason.signal}
                          </span>
                        </div>
                        <p className="text-xs font-mono text-foreground-muted break-words">
                          <span className="text-foreground font-semibold">Evidence:</span> {reason.evidence}
                        </p>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </>
        )}
      </div>

      {/* Positive / Neutral Evidence Section */}
      {positive_evidence.length > 0 && (
        <div className="space-y-3 pt-2 border-t border-border">
          <div className="flex items-center space-x-2">
            <ShieldCheck className="w-4 h-4 text-success" />
            <h4 className="text-xs font-mono font-bold text-foreground uppercase tracking-wider">
              Verified Security Controls &amp; Mitigating Evidence ({positive_evidence.length})
            </h4>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
            {positive_evidence.map((pos, pIdx) => (
              <div
                key={pIdx}
                className="p-2.5 rounded-lg border border-success-border bg-success-surface flex items-start space-x-2.5"
              >
                <CheckCircle2 className="w-3.5 h-3.5 text-success mt-0.5 shrink-0" />
                <div className="space-y-0.5 min-w-0">
                  <div className="text-xs font-mono font-bold text-success">
                    {pos.label}
                  </div>
                  <div className="text-[11px] font-mono text-foreground-muted truncate">
                    {pos.evidence}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Forensic Multi-Signal Assurance Note */}
      <div className="p-3 rounded-xl border border-border bg-surface-secondary/60 flex items-start space-x-2.5 text-[11px] font-mono text-foreground-muted">
        <Info className="w-4 h-4 text-primary shrink-0 mt-0.5" />
        <div>
          <strong className="text-foreground">Forensic Rule Policy:</strong> Authentication failures alone (SPF/DKIM/DMARC) contribute at most 28 points and cannot classify an email as suspicious or critical on their own. High risk determinations strictly require corroboration across multiple independent forensic signals (such as brand typosquatting, HTML link mismatches, high-risk URLs, and credential harvesting).
        </div>
      </div>
    </div>
  );
};
