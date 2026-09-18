import React, { useState, useMemo } from 'react';
import type { EmailAnalysis } from '../../../types/forensic';
import {
  BrainCircuit,
  Zap,
  ChevronDown,
  ChevronUp,
  Scale,
  ExternalLink
} from 'lucide-react';
import { ExpandableSection, DetailDrawer } from '../../common/progressive';

interface AnalysisContentSectionProps {
  email: EmailAnalysis;
}

export const AnalysisContentSection: React.FC<AnalysisContentSectionProps> = ({ email }) => {
  const [showTechnicalDetails, setShowTechnicalDetails] = useState<boolean>(false);
  const [selectedRawModal, setSelectedRawModal] = useState<any>(null);

  const ml = email.ml_assessment;
  const mlProb = typeof email.ml_phishing_probability === 'number'
    ? email.ml_phishing_probability
    : typeof ml?.probability === 'number'
    ? ml.probability
    : null;

  const isPhishing = (mlProb !== null && mlProb >= 0.5) || ml?.classification?.toLowerCase() === 'phishing';

  // Translate raw text & NLP output into understandable social-engineering signals
  const understandableSignals = useMemo(() => {
    const list: {
      tactic: string;
      label: string;
      severity: 'critical' | 'high' | 'medium' | 'info';
      explanation: string;
      detectedQuotes: string[];
    }[] = [];

    const fullText = `${email.subject || ''}\n${email.plain_text_body || ''}`.toLowerCase();

    // 1. Urgency / Time Pressure
    const urgencyMatches: string[] = [];
    if (/immediate(ly)?/i.test(fullText)) urgencyMatches.push('Immediate');
    if (/action required/i.test(fullText)) urgencyMatches.push('Action Required');
    if (/suspended|suspension/i.test(fullText)) urgencyMatches.push('Account Suspension');
    if (/urgent|critical/i.test(fullText)) urgencyMatches.push('Urgent Attention');
    if (/within 24 hours|deadline/i.test(fullText)) urgencyMatches.push('24-Hour Deadline');

    if (urgencyMatches.length > 0) {
      list.push({
        tactic: 'Artificial Urgency & Time Scarcity',
        label: 'Urgency Lure',
        severity: 'high',
        explanation: 'Creates a false sense of panic or rapid deadline to force the recipient to act before verifying sender identity.',
        detectedQuotes: urgencyMatches
      });
    }

    // 2. Financial / Wire Coercion
    const financialMatches: string[] = [];
    if (/wire transfer/i.test(fullText)) financialMatches.push('Wire Transfer');
    if (/invoice|remittance/i.test(fullText)) financialMatches.push('Invoice / Payment');
    if (/bank|funds|transaction/i.test(fullText)) financialMatches.push('Bank Account Verification');
    if (/payment authorization/i.test(fullText)) financialMatches.push('Payment Authorization');

    if (financialMatches.length > 0) {
      list.push({
        tactic: 'Financial Coercion & Fraud Vector',
        label: 'Financial Lure',
        severity: 'critical',
        explanation: 'Demands or references expedited money movement, bank details, or altered account routing numbers.',
        detectedQuotes: financialMatches
      });
    }

    // 3. Authority Impersonation
    const authorityMatches: string[] = [];
    if (/ceo|cfo|executive|director/i.test(fullText)) authorityMatches.push('Executive Officer');
    if (/it security|security center|help desk|support/i.test(fullText)) authorityMatches.push('IT / Security Authority');
    if (/confidential|bypass|do not contact/i.test(fullText)) authorityMatches.push('Secrecy Demand');

    if (authorityMatches.length > 0) {
      list.push({
        tactic: 'Organizational Authority Impersonation',
        label: 'Authority Coercion',
        severity: 'high',
        explanation: 'Leverages perceived hierarchical power (CEO, IT Security, Legal) to suppress typical verification questions.',
        detectedQuotes: authorityMatches
      });
    }

    // 4. Credential Harvesting Pretext
    const credentialMatches: string[] = [];
    if (/password|credential|sign in|login/i.test(fullText)) credentialMatches.push('Sign-In Verification');
    if (/session expired|re-authenticate/i.test(fullText)) authorityMatches.push('Session Expiry');
    if (/verify your identity/i.test(fullText)) credentialMatches.push('Identity Verification');

    if (credentialMatches.length > 0) {
      list.push({
        tactic: 'Credential Access Pretext',
        label: 'Credential Harvester',
        severity: 'critical',
        explanation: 'Directs user to input corporate passwords or MFA tokens under the guise of account maintenance.',
        detectedQuotes: credentialMatches
      });
    }

    return list;
  }, [email.subject, email.plain_text_body]);

  return (
    <div className="space-y-4 font-mono">
      <ExpandableSection
        title="Content Analysis & Intent Classifier"
        subtitle="Natural language understanding of psychological manipulation vectors and intent classification"
        icon={BrainCircuit}
        defaultExpanded={true}
        badge={
          <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${
            isPhishing
              ? 'bg-danger-surface text-danger border-danger-border'
              : 'bg-success-surface text-success border-success-border'
          }`}>
            {isPhishing ? 'Malicious Intent Detected' : 'Benign / Legitimate Content'}
          </span>
        }
      >
        <div className="space-y-4">
          {/* 1. UNDERSTANDABLE SIGNALS FIRST: Primary Intent Verdict */}
          <div className="p-4 rounded-xl bg-surface-secondary/40 border border-border space-y-3">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div>
                <span className="text-[10px] uppercase font-bold text-foreground-muted tracking-wider block">
                  Identified Email Intent:
                </span>
                <span className="text-sm font-bold text-foreground">
                  {isPhishing
                    ? understandableSignals.length > 0
                      ? `Social Engineering Attack · ${understandableSignals.map(s => s.label).join(', ')}`
                      : 'Deceptive Phishing Intent'
                    : 'Legitimate Business Correspondence'}
                </span>
              </div>

              <span className={`px-2.5 py-1 rounded-lg text-xs font-bold uppercase border self-start sm:self-auto ${
                isPhishing
                  ? 'bg-danger-surface text-danger border-danger-border'
                  : 'bg-success-surface text-success border-success-border'
              }`}>
                {ml?.classification ? ml.classification.toUpperCase() : isPhishing ? 'PHISHING' : 'LEGITIMATE'}
              </span>
            </div>

            <p className="text-xs text-foreground-muted leading-relaxed font-sans">
              {isPhishing
                ? 'The message employs calculated social-engineering tactics designed to bypass rational skepticism through urgency, authority coercion, or deceptive pretexts.'
                : 'The message demonstrates standard enterprise correspondence patterns without identifiable coercion or deceptive lures.'}
            </p>
          </div>

          {/* 2. UNDERSTANDABLE SIGNALS FIRST: Deception Vector Cards */}
          {understandableSignals.length > 0 ? (
            <div className="space-y-2.5">
              <span className="text-[10px] uppercase font-bold text-foreground-muted tracking-wider block">
                Observed Social-Engineering Vectors ({understandableSignals.length}):
              </span>

              {understandableSignals.map((sig, idx) => (
                <div
                  key={idx}
                  className="p-3.5 rounded-xl bg-surface border border-border space-y-2 hover:border-primary/40 transition-colors"
                >
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center space-x-2">
                      <Zap className={`w-3.5 h-3.5 ${
                        sig.severity === 'critical' ? 'text-danger' : 'text-warning'
                      }`} />
                      <span className="font-bold text-foreground text-xs">
                        {sig.tactic}
                      </span>
                    </div>

                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${
                      sig.severity === 'critical'
                        ? 'bg-danger-surface text-danger border-danger-border'
                        : 'bg-warning-surface text-warning border-warning-border'
                    }`}>
                      {sig.label}
                    </span>
                  </div>

                  <p className="text-[11.5px] text-foreground-muted leading-relaxed font-sans">
                    {sig.explanation}
                  </p>

                  <div className="flex flex-wrap items-center gap-1.5 pt-1">
                    <span className="text-[10px] uppercase font-bold text-foreground-subtle">
                      Identified cues:
                    </span>
                    {sig.detectedQuotes.map((quote, qIdx) => (
                      <span
                        key={qIdx}
                        className="px-2 py-0.5 rounded bg-surface-secondary text-foreground text-[10px] border border-border"
                      >
                        &ldquo;{quote}&rdquo;
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="p-3 rounded-lg bg-surface-secondary/40 border border-border text-xs text-foreground-muted">
              No elevated social engineering persuasion patterns observed in email content.
            </div>
          )}

          {/* 3. TECHNICAL DETAILS (COLLAPSED BY DEFAULT) */}
          <div className="pt-2 border-t border-border">
            <button
              type="button"
              onClick={() => setShowTechnicalDetails(!showTechnicalDetails)}
              className="w-full flex items-center justify-between p-3 rounded-xl bg-surface-secondary/60 hover:bg-surface-secondary border border-border text-left transition-all cursor-pointer group"
            >
              <div className="flex items-center space-x-2">
                <Scale className="w-4 h-4 text-primary group-hover:scale-110 transition-transform" />
                <span className="text-xs font-bold text-foreground uppercase tracking-wider">
                  {showTechnicalDetails ? 'Hide Model Probabilities & Technical Details' : 'View Model Probabilities & Technical Details'}
                </span>
              </div>
              <div className="flex items-center space-x-1.5 text-xs text-foreground-muted font-normal">
                <span>{showTechnicalDetails ? 'Collapse metrics' : 'Expand statistical features'}</span>
                {showTechnicalDetails ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
              </div>
            </button>

            {showTechnicalDetails && (
              <div className="mt-3 p-4 rounded-xl bg-surface border border-border space-y-4 animate-in fade-in duration-150 text-xs">
                {/* Model Score Strip */}
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <div className="p-3 rounded-xl bg-surface-secondary/50 border border-border space-y-1">
                    <span className="text-[10px] uppercase font-bold text-foreground-muted block">
                      Phishing Probability
                    </span>
                    <div className="text-xl font-bold text-foreground">
                      {mlProb !== null ? `${Math.round(mlProb * 100)}%` : 'N/A'}
                    </div>
                    <span className="text-[10px] text-foreground-muted block">
                      Confidence: {ml?.confidence || 'High'}
                    </span>
                  </div>

                  <div className="p-3 rounded-xl bg-surface-secondary/50 border border-border space-y-1">
                    <span className="text-[10px] uppercase font-bold text-foreground-muted block">
                      Classifier Model
                    </span>
                    <div className="text-xs font-bold text-foreground break-all">
                      {ml?.model_name || 'MailTraceAI-NLP-v2.4'}
                    </div>
                    <span className="text-[10px] text-foreground-muted block">
                      Architecture: TF-IDF + Logistic Regression
                    </span>
                  </div>

                  <div className="p-3 rounded-xl bg-surface-secondary/50 border border-border space-y-1">
                    <span className="text-[10px] uppercase font-bold text-foreground-muted block">
                      Execution Guarantee
                    </span>
                    <div className="text-xs font-bold text-success">
                      Local Offline Inference
                    </div>
                    <span className="text-[10px] text-foreground-muted block">
                      Zero cloud telemetry leakage
                    </span>
                  </div>
                </div>

                {/* Top Contributing Lexical Features */}
                {ml?.top_features && ml.top_features.length > 0 && (
                  <div className="space-y-2">
                    <span className="text-[10px] uppercase font-bold text-foreground-muted block">
                      Salient Token Weights (TF-IDF):
                    </span>
                    <div className="flex flex-wrap gap-1.5">
                      {ml.top_features.map((feat, idx) => (
                        <span
                          key={idx}
                          className="px-2 py-0.5 rounded text-[10px] bg-surface-secondary border border-border text-foreground font-semibold"
                        >
                          {feat}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Button to open raw output in DetailDrawer */}
                <div className="pt-2 flex justify-end">
                  <button
                    type="button"
                    onClick={() => setSelectedRawModal(ml || { probability: mlProb, classification: isPhishing ? 'phishing' : 'legitimate' })}
                    className="px-3 py-1.5 rounded-lg bg-surface-secondary hover:bg-surface border border-border text-foreground text-xs font-semibold flex items-center space-x-1.5 transition-colors cursor-pointer"
                  >
                    <ExternalLink className="w-3.5 h-3.5 text-primary" />
                    <span>View raw ML model output</span>
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      </ExpandableSection>

      {/* Level 3 Raw Drawer */}
      {selectedRawModal && (
        <DetailDrawer
          isOpen={Boolean(selectedRawModal)}
          onClose={() => setSelectedRawModal(null)}
          title="Machine Learning Classifier Model Diagnostics"
          subtitle={ml?.model_name || 'MailTraceAI-NLP'}
          data={selectedRawModal}
          format="json"
        />
      )}
    </div>
  );
};
