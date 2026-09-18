import React from 'react';
import {
  Mail,
  ShieldCheck,
  GitCommit,
  FileCode,
  Archive,
  Layers,
  Code,
  ArrowRight
} from 'lucide-react';
import type { EmailAnalysis } from '../../../types/forensic';
import { useInvestigation } from '../../../context/InvestigationContext';
import {
  EmailIdentitySubsection,
  EmailAuthSubsection,
  EmailRelaySubsection,
  EmailHeadersSubsection,
  EmailOriginalEvidenceSubsection
} from '../../../components/forensic/email';
import { ContentTab } from '../../../components/forensic/ContentTab';

interface EmailSectionViewProps {
  email: EmailAnalysis;
}

type EmailSubTab = 'all' | 'identity' | 'auth' | 'relay' | 'headers' | 'evidence' | 'content';

export const EmailSectionView: React.FC<EmailSectionViewProps> = ({ email }) => {
  const { subTabs, setSubTab, stepGuidance } = useInvestigation();

  // Normalize legacy tab IDs (e.g. 'metadata' -> 'identity', 'raw' -> 'evidence', 'body' -> 'content')
  const rawSubTab = subTabs.email || 'all';
  let currentSubTab: EmailSubTab = 'all';
  if (rawSubTab === 'identity' || rawSubTab === 'metadata') currentSubTab = 'identity';
  else if (rawSubTab === 'auth') currentSubTab = 'auth';
  else if (rawSubTab === 'relay') currentSubTab = 'relay';
  else if (rawSubTab === 'headers') currentSubTab = 'headers';
  else if (rawSubTab === 'evidence' || rawSubTab === 'raw') currentSubTab = 'evidence';
  else if (rawSubTab === 'content' || rawSubTab === 'body') currentSubTab = 'content';
  else currentSubTab = 'all';

  const relayHopCount =
    email.relay_analysis?.transmission_order_hops?.length ||
    email.received?.length ||
    0;

  const subTabItems: {
    id: EmailSubTab;
    label: string;
    icon: React.FC<{ className?: string }>;
    count?: number;
  }[] = [
    { id: 'all', label: 'All Subsections', icon: Layers },
    { id: 'identity', label: 'Email Identity', icon: Mail },
    { id: 'auth', label: 'Authentication', icon: ShieldCheck },
    { id: 'relay', label: 'Relay Path', icon: GitCommit, count: relayHopCount },
    { id: 'headers', label: 'Headers', icon: FileCode, count: email.received?.length || 0 },
    { id: 'evidence', label: 'Original Evidence', icon: Archive },
    { id: 'content', label: 'Rendered Content', icon: Code }
  ];

  return (
    <div className="space-y-6">
      {/* 1. COMPACT SUBSECTION FILTER BAR */}
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

      {/* 2. SUBSECTION DISPLAY AREA */}
      <div className="space-y-6">
        {/* SUBSECTION 1: EMAIL IDENTITY */}
        {(currentSubTab === 'all' || currentSubTab === 'identity') && (
          <div id="section-identity">
            <EmailIdentitySubsection email={email} />
          </div>
        )}

        {/* SUBSECTION 2: AUTHENTICATION */}
        {(currentSubTab === 'all' || currentSubTab === 'auth') && (
          <div id="section-auth">
            <EmailAuthSubsection authentication={email.authentication} />
          </div>
        )}

        {/* SUBSECTION 3: RELAY PATH */}
        {(currentSubTab === 'all' || currentSubTab === 'relay') && (
          <div id="section-relay">
            <EmailRelaySubsection
              relayAnalysis={email.relay_analysis}
              ipIntelligence={email.ip_intelligence}
              rawReceived={email.received}
            />
          </div>
        )}

        {/* SUBSECTION 4: HEADERS */}
        {(currentSubTab === 'all' || currentSubTab === 'headers') && (
          <div id="section-headers">
            <EmailHeadersSubsection email={email} />
          </div>
        )}

        {/* SUBSECTION 5: ORIGINAL EVIDENCE */}
        {(currentSubTab === 'all' || currentSubTab === 'evidence') && (
          <div id="section-evidence">
            <EmailOriginalEvidenceSubsection email={email} />
          </div>
        )}

        {/* OPTIONAL: RENDERED CONTENT (MIME Multipart Preview) */}
        {currentSubTab === 'content' && (
          <div className="bg-surface rounded-xl border border-border p-5 shadow-xs space-y-4 font-mono">
            <div className="flex items-center justify-between pb-3 border-b border-border">
              <div className="flex items-center space-x-2 text-xs font-bold uppercase text-foreground">
                <Code className="w-4 h-4 text-primary" />
                <span>Rendered Email Content & Message Structure</span>
              </div>
              <span className="text-[11px] text-foreground-muted">
                Sanitized HTML / Plain-text decomposition
              </span>
            </div>
            <ContentTab email={email} />
          </div>
        )}
      </div>

      {/* 3. NEXT INVESTIGATION STEP CTA */}
      <div className="p-4 rounded-xl bg-surface border border-border flex flex-col sm:flex-row items-center justify-between gap-4 shadow-xs">
        <div className="flex items-center space-x-3">
          <div className="w-8 h-8 rounded-lg bg-primary/10 text-primary flex items-center justify-center font-bold font-mono text-xs border border-primary/20">
            03
          </div>
          <div>
            <h4 className="text-xs font-bold text-foreground font-sans">
              Completed Email Inspection?
            </h4>
            <p className="text-xs font-mono text-foreground-muted">
              Pivot into extracted IOCs, suspicious URLs, lookalike domains, and NLP threat scoring.
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
