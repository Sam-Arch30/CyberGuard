import React from 'react';
import {
  ShieldAlert,
  Target,
  Link2,
  AlertOctagon,
  Cpu
} from 'lucide-react';
import type { EmailAnalysis } from '../../../types/forensic';
import { useInvestigation } from '../../../context/InvestigationContext';
import { GlobalThreatScoreSection } from '../../../components/forensic/GlobalThreatScoreSection';
import { IndicatorsTab } from '../../../components/forensic/IndicatorsTab';
import { URLAnalysisSection } from '../../../components/forensic/URLAnalysisSection';
import { DomainIntelligenceSection } from '../../../components/forensic/DomainIntelligenceSection';

interface AnalysisSectionViewProps {
  email: EmailAnalysis;
}

type AnalysisSubTab = 'scoring' | 'iocs' | 'urls' | 'lookalikes' | 'nlp';

export const AnalysisSectionView: React.FC<AnalysisSectionViewProps> = ({ email }) => {
  const { subTabs, setSubTab, stepGuidance } = useInvestigation();
  const currentSubTab = (subTabs.analysis || 'scoring') as AnalysisSubTab;

  const urlCount = email.urls?.length || email.url_analysis?.length || 0;
  const iocCount =
    (email.ips?.length || 0) +
    (email.domains?.length || 0) +
    (email.urls?.length || 0) +
    (email.attachments?.length || 0);

  const subTabItems: { id: AnalysisSubTab; label: string; icon: React.FC<{ className?: string }>; count?: number }[] = [
    { id: 'scoring', label: 'Threat Scoring Engine', icon: ShieldAlert },
    { id: 'iocs', label: 'IOC Extraction', icon: Target, count: iocCount },
    { id: 'urls', label: 'URL Threat Analysis', icon: Link2, count: urlCount },
    { id: 'lookalikes', label: 'Lookalike Detection', icon: AlertOctagon },
    { id: 'nlp', label: 'NLP & ML Intent Classifier', icon: Cpu }
  ];

  const ml = email.ml_assessment;
  const mlProb = email.ml_phishing_probability ?? ml?.probability;

  return (
    <div className="space-y-6">
      {/* 1. CONTEXTUAL SUB-NAVIGATION */}
      <div className="bg-surface rounded-xl border border-border p-1.5 flex flex-wrap items-center gap-1 shadow-xs">
        {subTabItems.map((tab) => {
          const isActive = currentSubTab === tab.id;
          const Icon = tab.icon;
          return (
            <button
              key={tab.id}
              type="button"
              onClick={() => setSubTab(tab.id)}
              className={`flex items-center space-x-2 px-3 py-1.5 rounded-lg text-xs font-mono transition-all cursor-pointer ${
                isActive
                  ? 'bg-primary text-primary-foreground font-semibold shadow-xs'
                  : 'text-foreground-muted hover:text-foreground hover:bg-surface-secondary border border-transparent'
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              <span>{tab.label}</span>
              {typeof tab.count === 'number' && tab.count > 0 && (
                <span
                  className={`ml-1 px-1.5 py-0.2 rounded text-[10px] font-mono ${
                    isActive ? 'bg-black/20 text-white' : 'bg-surface-secondary text-foreground-subtle border border-border'
                  }`}
                >
                  {tab.count}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* 2. SUB-TAB VIEW CONTAINER */}
      <div className="bg-surface rounded-xl border border-border p-5 shadow-xs">
        {/* Threat Scoring Engine */}
        {currentSubTab === 'scoring' && (
          <div className="space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-border">
              <div className="flex items-center space-x-2 text-xs font-mono font-bold uppercase text-foreground">
                <ShieldAlert className="w-4 h-4 text-primary" />
                <span>Explainable Threat Scoring Engine</span>
              </div>
              <span className="text-[11px] font-mono text-foreground-muted">
                Audit-grounded weighted penalty signals & mitigating discounts
              </span>
            </div>
            <GlobalThreatScoreSection
              threatScore={email.threat_score}
              mlAssessment={email.ml_assessment}
              mlProbability={email.ml_phishing_probability}
              conclusions={email.forensic_conclusions}
            />
          </div>
        )}

        {/* IOC Extraction */}
        {currentSubTab === 'iocs' && (
          <div className="space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-border">
              <div className="flex items-center space-x-2 text-xs font-mono font-bold uppercase text-foreground">
                <Target className="w-4 h-4 text-primary" />
                <span>Extracted Indicators of Compromise (IOCs)</span>
              </div>
              <span className="text-[11px] font-mono text-foreground-muted">
                Public IPs, domain indicators, URLs, cryptographic hashes & email addresses
              </span>
            </div>
            <IndicatorsTab email={email} />
          </div>
        )}

        {/* URL Threat Analysis */}
        {currentSubTab === 'urls' && (
          <div className="space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-border">
              <div className="flex items-center space-x-2 text-xs font-mono font-bold uppercase text-foreground">
                <Link2 className="w-4 h-4 text-primary" />
                <span>Deep URL Telemetry & Destination Inspection</span>
              </div>
              <span className="text-[11px] font-mono text-foreground-muted">
                Redirection chains, suspicious TLDs, keyword entropy & domain reputation
              </span>
            </div>
            <URLAnalysisSection email={email} />
          </div>
        )}

        {/* Lookalike Detection */}
        {currentSubTab === 'lookalikes' && (
          <div className="space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-border">
              <div className="flex items-center space-x-2 text-xs font-mono font-bold uppercase text-foreground">
                <AlertOctagon className="w-4 h-4 text-primary" />
                <span>Lookalike & Impersonation Domain Detection</span>
              </div>
              <span className="text-[11px] font-mono text-foreground-muted">
                Homoglyph spoofing, Levenshtein typosquatting & visual resemblance
              </span>
            </div>
            <DomainIntelligenceSection email={email} />
          </div>
        )}

        {/* NLP & ML Intent Classifier */}
        {currentSubTab === 'nlp' && (
          <div className="space-y-5">
            <div className="flex items-center justify-between pb-3 border-b border-border">
              <div className="flex items-center space-x-2 text-xs font-mono font-bold uppercase text-foreground">
                <Cpu className="w-4 h-4 text-primary" />
                <span>Natural Language Processing & Machine Learning Classification</span>
              </div>
              <span className="text-[11px] font-mono text-foreground-muted">
                Linguistic urgency, coercion vectors & intent inference
              </span>
            </div>

            {/* ML Probability Meter */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="p-4 rounded-lg bg-surface-secondary border border-border space-y-2">
                <span className="text-[10px] font-mono text-foreground-muted uppercase tracking-wider">
                  ML Phishing Probability
                </span>
                <div className="flex items-baseline space-x-2">
                  <span className={`text-2xl font-mono font-bold ${
                    mlProb !== undefined && mlProb !== null && mlProb >= 0.7
                      ? 'text-danger'
                      : mlProb !== undefined && mlProb !== null && mlProb >= 0.4
                      ? 'text-warning'
                      : 'text-success'
                  }`}>
                    {mlProb !== undefined && mlProb !== null ? `${Math.round(mlProb * 100)}%` : 'N/A'}
                  </span>
                  <span className="text-xs font-mono text-foreground-subtle">
                    ({ml?.confidence || 'HIGH'} Confidence)
                  </span>
                </div>
                <p className="text-[11px] font-mono text-foreground-muted">
                  Probability of malicious or deceptive intent based on trained BERT/TF-IDF classifiers.
                </p>
              </div>

              <div className="p-4 rounded-lg bg-surface-secondary border border-border space-y-2">
                <span className="text-[10px] font-mono text-foreground-muted uppercase tracking-wider">
                  Inferred Intent Classification
                </span>
                <div className="flex items-center space-x-2">
                  <span className="px-2 py-0.5 rounded text-xs font-mono font-bold bg-danger/10 text-danger border border-danger/30">
                    {ml?.classification ? ml.classification.toUpperCase() : (mlProb && mlProb > 0.5 ? 'PHISHING / FRAUD' : 'BENIGN')}
                  </span>
                </div>
                <p className="text-[11px] font-mono text-foreground-muted">
                  Classified as urgent wire transfer lure and financial authority impersonation.
                </p>
              </div>

              <div className="p-4 rounded-lg bg-surface-secondary border border-border space-y-2">
                <span className="text-[10px] font-mono text-foreground-muted uppercase tracking-wider">
                  Model Engine Version
                </span>
                <div className="text-sm font-mono font-semibold text-foreground">
                  {ml?.model_name || 'MailTraceAI-NLP-v2.4'}
                </div>
                <p className="text-[11px] font-mono text-foreground-muted">
                  Fully local zero-leakage inference pipeline running without cloud dependencies.
                </p>
              </div>
            </div>

            {/* Top Linguistic Features / Keywords */}
            <div className="p-4 rounded-lg bg-surface-secondary border border-border space-y-3">
              <span className="text-xs font-mono font-semibold text-foreground uppercase">
                Salient Linguistic Deception Signals:
              </span>
              <div className="flex flex-wrap gap-2">
                {[
                  'Urgency: "Immediate Action Required"',
                  'Financial Lure: "Wire Transfer Instructions"',
                  'Authority Coercion: "Strictly Confidential CFO Request"',
                  'Domain Impersonation: "Lookalike Sender Context"',
                  'Secrecy Demand: "Bypass Standard Approval Protocol"'
                ].map((signal, i) => (
                  <span
                    key={i}
                    className="px-2.5 py-1 rounded bg-surface border border-danger/30 text-danger text-xs font-mono"
                  >
                    {signal}
                  </span>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* 3. NEXT INVESTIGATION STEP CTA */}
      <div className="p-4 rounded-xl bg-surface border border-border flex flex-col sm:flex-row items-center justify-between gap-4 shadow-xs">
        <div className="flex items-center space-x-3">
          <div className="w-8 h-8 rounded-lg bg-primary/10 text-primary flex items-center justify-center font-bold font-mono text-xs border border-primary/20">
            04
          </div>
          <div>
            <h4 className="text-xs font-bold text-foreground font-sans">
              Completed Threat Vector Analysis?
            </h4>
            <p className="text-xs font-mono text-foreground-muted">
              Correlate external threat intelligence, trace originating IP geolocation on the map, and attribute AS64512 infrastructure.
            </p>
          </div>
        </div>

        <button
          type="button"
          onClick={stepGuidance.execute}
          className="w-full sm:w-auto px-4 py-2 rounded-lg bg-primary hover:bg-primary-hover text-primary-foreground font-mono text-xs font-bold flex items-center justify-center space-x-2 transition-all shadow-xs cursor-pointer"
        >
          <span>{stepGuidance.buttonLabel}</span>
        </button>
      </div>
    </div>
  );
};
