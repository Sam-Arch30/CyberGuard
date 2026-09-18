import React from 'react';
import {
  ShieldAlert,
  Target,
  Link2,
  AlertOctagon,
  BrainCircuit,
  Layers,
  ArrowRight
} from 'lucide-react';
import type { EmailAnalysis } from '../../../types/forensic';
import { useInvestigation } from '../../../context/InvestigationContext';
import {
  AnalysisSummaryCard,
  AnalysisIndicatorsSection,
  AnalysisURLsSection,
  AnalysisLookalikesSection,
  AnalysisContentSection,
  AnalysisScoringSection
} from '../../../components/forensic/analysis';

interface AnalysisSectionViewProps {
  email: EmailAnalysis;
}

type AnalysisSubTab = 'all' | 'indicators' | 'urls' | 'lookalikes' | 'content' | 'scoring';

export const AnalysisSectionView: React.FC<AnalysisSectionViewProps> = ({ email }) => {
  const { subTabs, setSubTab, stepGuidance } = useInvestigation();

  // Normalize legacy tab IDs (e.g. 'iocs' -> 'indicators', 'nlp' -> 'content')
  const rawSubTab = subTabs.analysis || 'all';
  let currentSubTab: AnalysisSubTab = 'all';
  if (rawSubTab === 'indicators' || rawSubTab === 'iocs') currentSubTab = 'indicators';
  else if (rawSubTab === 'urls') currentSubTab = 'urls';
  else if (rawSubTab === 'lookalikes') currentSubTab = 'lookalikes';
  else if (rawSubTab === 'content' || rawSubTab === 'nlp') currentSubTab = 'content';
  else if (rawSubTab === 'scoring') currentSubTab = 'scoring';
  else currentSubTab = 'all';

  const indicators = email.indicators || {};
  const totalIocs =
    (indicators.ips?.length || email.ips?.length || 0) +
    (indicators.domains?.length || email.domains?.length || 0) +
    (indicators.urls?.length || email.urls?.length || 0) +
    (indicators.email_addresses?.length || email.emails?.length || 0) +
    (indicators.attachments?.length || email.attachments?.length || 0);

  const urlCount = email.url_analysis?.length || email.urls?.length || 0;
  const lookalikeCount = email.lookalike_domains?.length || 0;

  const subTabItems: {
    id: AnalysisSubTab;
    label: string;
    icon: React.FC<{ className?: string }>;
    count?: number;
  }[] = [
    { id: 'all', label: 'All Sections', icon: Layers },
    { id: 'indicators', label: 'Indicators', icon: Target, count: totalIocs },
    { id: 'urls', label: 'URLs', icon: Link2, count: urlCount },
    { id: 'lookalikes', label: 'Domain Similarity', icon: AlertOctagon, count: lookalikeCount },
    { id: 'content', label: 'Content Analysis', icon: BrainCircuit },
    { id: 'scoring', label: 'Scoring Breakdown', icon: ShieldAlert }
  ];

  return (
    <div className="space-y-6">
      {/* 1. SUBSECTION FILTER BAR */}
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
                    isActive
                      ? 'bg-black/20 text-white'
                      : 'bg-surface-secondary text-foreground-subtle border border-border'
                  }`}
                >
                  {tab.count}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* 2. TOP ANALYSIS SUMMARY CARD (Surfaced in 'All Sections' overview mode) */}
      {currentSubTab === 'all' && (
        <AnalysisSummaryCard
          email={email}
          onJumpToSection={(sec) => setSubTab(sec)}
        />
      )}

      {/* 3. COLLAPSIBLE FORENSIC SECTIONS */}
      <div className="space-y-6">
        {/* SECTION 1: INDICATORS */}
        {(currentSubTab === 'all' || currentSubTab === 'indicators') && (
          <div id="section-indicators">
            <AnalysisIndicatorsSection email={email} />
          </div>
        )}

        {/* SECTION 2: URLS */}
        {(currentSubTab === 'all' || currentSubTab === 'urls') && (
          <div id="section-urls">
            <AnalysisURLsSection email={email} />
          </div>
        )}

        {/* SECTION 3: DOMAIN SIMILARITY */}
        {(currentSubTab === 'all' || currentSubTab === 'lookalikes') && (
          <div id="section-lookalikes">
            <AnalysisLookalikesSection email={email} />
          </div>
        )}

        {/* SECTION 4: CONTENT ANALYSIS */}
        {(currentSubTab === 'all' || currentSubTab === 'content') && (
          <div id="section-content">
            <AnalysisContentSection email={email} />
          </div>
        )}

        {/* SECTION 5: SCORING BREAKDOWN */}
        {(currentSubTab === 'all' || currentSubTab === 'scoring') && (
          <div id="section-scoring">
            <AnalysisScoringSection threatScore={email.threat_score} />
          </div>
        )}
      </div>

      {/* 4. NEXT INVESTIGATION STEP CTA */}
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
              Pivot into external threat intelligence, trace originating IP geolocation on the map, and attribute infrastructure.
            </p>
          </div>
        </div>

        <button
          type="button"
          onClick={stepGuidance.execute}
          className="w-full sm:w-auto px-4 py-2 rounded-lg bg-primary hover:bg-primary-hover text-primary-foreground font-mono text-xs font-bold flex items-center justify-center space-x-2 transition-all shadow-xs cursor-pointer"
        >
          <span>{stepGuidance.buttonLabel}</span>
          <ArrowRight className="w-3.5 h-3.5" />
        </button>
      </div>
    </div>
  );
};
