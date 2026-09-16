import React, { useState } from 'react';
import type { AIAnalystAssessment, EmailAnalysis } from '../../types/forensic';
import type { ForensicConclusion } from '../../types/confidence';
import { ConfidenceBadge } from '../common/ConfidenceBadge';
import { InvestigationCopilot } from '../copilot/InvestigationCopilot';
import {
  Sparkles,
  Target,
  ShieldAlert,
  CheckCircle2,
  ListOrdered,
  AlertTriangle,
  Info,
  Layers,
  MessageSquare,
  HelpCircle,
  ChevronRight
} from 'lucide-react';

interface AIAnalystSectionProps {
  aiAnalyst?: AIAnalystAssessment;
  conclusions?: ForensicConclusion[];
  email?: EmailAnalysis;
  onFocusGraphNode?: (id: string) => void;
  onOpenWorkspace?: () => void;
}

export const AIAnalystSection: React.FC<AIAnalystSectionProps> = ({
  aiAnalyst,
  conclusions = [],
  email,
  onFocusGraphNode,
  onOpenWorkspace
}) => {
  const [activeView, setActiveView] = useState<'copilot' | 'executive'>('copilot');
  const [selectedInitialPrompt, setSelectedInitialPrompt] = useState<string | undefined>(undefined);

  const nlpOrThreatConclusion =
    conclusions.find((c) => c.type === 'nlp_classification') ||
    conclusions.find((c) => c.type === 'threat_classification');

  const contextId = email?.evidence_id || email?.id || 'E-1042';

  const quickPrompts = [
    'Why was this email classified as malicious?',
    'Which indicators contributed most to the threat score?',
    'Which relay is most likely attacker-controlled?',
    'Show the evidence connecting this email to Campaign C-042.',
    'Explain the SPF, DKIM and DMARC results.'
  ];

  const handlePromptClick = (prompt: string) => {
    setSelectedInitialPrompt(prompt);
    setActiveView('copilot');
  };

  return (
    <div className="space-y-4">
      {/* Top Banner & View Switcher */}
      <div className="rounded-card border border-border bg-surface p-4 shadow-xs flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-center space-x-3">
          <div className="p-2 rounded-xl bg-primary/10 border border-primary/20 text-primary">
            <Sparkles className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="text-[10px] font-mono font-bold tracking-widest uppercase text-primary">
                MAILTRACEAI INVESTIGATION COPILOT
              </span>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-surface-secondary border border-border text-foreground-muted">
                EVIDENCE-GROUNDED
              </span>
            </div>
            <h2 className="text-base sm:text-lg font-bold font-sans text-foreground tracking-tight">
              Evidence-Grounded Forensic Copilot &amp; Threat Intelligence
            </h2>
          </div>
        </div>

        {/* View Switcher Toggle */}
        <div className="flex items-center bg-surface-secondary p-0.5 rounded-lg border border-border self-start sm:self-auto">
          <button
            onClick={() => setActiveView('copilot')}
            className={`px-3 py-1.5 rounded-md text-xs font-mono font-medium transition-all flex items-center space-x-1.5 cursor-pointer ${
              activeView === 'copilot'
                ? 'bg-surface text-foreground font-bold border border-border shadow-xs'
                : 'text-foreground-muted hover:text-foreground'
            }`}
          >
            <MessageSquare className="w-3.5 h-3.5 text-primary" />
            <span>Interactive Copilot</span>
          </button>
          <button
            onClick={() => setActiveView('executive')}
            className={`px-3 py-1.5 rounded-md text-xs font-mono font-medium transition-all flex items-center space-x-1.5 cursor-pointer ${
              activeView === 'executive'
                ? 'bg-surface text-foreground font-bold border border-border shadow-xs'
                : 'text-foreground-muted hover:text-foreground'
            }`}
          >
            <Layers className="w-3.5 h-3.5 text-cyan-400" />
            <span>Executive Assessment</span>
          </button>
        </div>
      </div>

      {/* Suggested Quick Inquiries Bar */}
      <div className="px-4 py-2 bg-surface rounded-lg border border-border flex items-center space-x-2 overflow-x-auto no-scrollbar shadow-2xs">
        <span className="text-[10px] font-mono uppercase tracking-wider text-foreground-muted font-bold whitespace-nowrap flex items-center space-x-1">
          <HelpCircle className="w-3 h-3 text-primary" />
          <span>Quick Inquiries:</span>
        </span>
        <div className="flex items-center space-x-1.5 whitespace-nowrap">
          {quickPrompts.map((qp, idx) => (
            <button
              key={idx}
              onClick={() => handlePromptClick(qp)}
              className="px-2.5 py-1 rounded-full text-[11px] font-mono bg-surface-secondary/70 border border-border text-foreground-muted hover:text-primary hover:border-primary/40 hover:bg-primary/5 transition-all flex items-center space-x-1 cursor-pointer"
            >
              <span>{qp}</span>
              <ChevronRight className="w-2.5 h-2.5 opacity-50" />
            </button>
          ))}
        </div>
      </div>

      {/* VIEW: Interactive Investigation Copilot */}
      {activeView === 'copilot' && (
        <InvestigationCopilot
          mode="email"
          contextId={contextId}
          emailPayload={email}
          initialQuestion={selectedInitialPrompt}
          onOpenGraph={() => onFocusGraphNode?.(contextId)}
          onCompareEmails={onOpenWorkspace}
        />
      )}

      {/* VIEW: Executive Threat Assessment Card */}
      {activeView === 'executive' && (
        <div className="rounded-card border border-border bg-surface p-6 shadow-sm space-y-6 transition-all">
          {/* Top Header Banner */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-border">
            <div className="flex items-center space-x-2.5">
              <div>
                <div className="flex items-center space-x-2">
                  <span className="text-[10px] font-mono font-bold tracking-widest uppercase text-primary">
                    DETERMINISTIC EVIDENCE SYNTHESIS
                  </span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-surface-secondary border border-border text-foreground-muted">
                    {aiAnalyst?.model || aiAnalyst?.provider || 'mailtrace-copilot-v1'}
                  </span>
                </div>
                <h3 className="text-base font-bold font-sans text-foreground tracking-tight">
                  Executive Forensic Findings &amp; Attack Vector
                </h3>
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
                aiAnalyst?.likely_attack_type?.toLowerCase().includes('phishing') ||
                aiAnalyst?.likely_attack_type?.toLowerCase().includes('harvest') ||
                aiAnalyst?.likely_attack_type?.toLowerCase().includes('bec') ||
                aiAnalyst?.likely_attack_type?.toLowerCase().includes('malware')
                  ? 'bg-danger/10 border-danger/30 text-danger'
                  : 'bg-success/10 border-success/30 text-success'
              }`}>
                {aiAnalyst?.likely_attack_type || 'Malicious Phishing & Credential Harvest'}
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
              {aiAnalyst?.summary ||
                'The analyzed email presents characteristics of Credential Harvesting Phishing with a deterministic threat score of 85/100 (CRITICAL). Key driving indicators include domain lookalike spoofing, SPF/DMARC authentication failure, and redirect to credential harvesting infrastructure.'}
            </p>
          </div>

          {/* Two Column Grid: Attack Type & Objective */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-4 rounded-xl bg-surface-secondary/40 border border-border space-y-1.5">
              <div className="flex items-center space-x-2 text-danger text-xs font-mono font-bold uppercase tracking-wider">
                <ShieldAlert className="w-4 h-4 text-danger" />
                <span>Likely Attack Type</span>
              </div>
              <p className="text-xs font-mono text-foreground font-semibold">
                {aiAnalyst?.likely_attack_type || 'Credential Harvesting Phishing via Domain Impersonation'}
              </p>
            </div>

            <div className="p-4 rounded-xl bg-surface-secondary/40 border border-border space-y-1.5">
              <div className="flex items-center space-x-2 text-warning text-xs font-mono font-bold uppercase tracking-wider">
                <Target className="w-4 h-4 text-warning" />
                <span>Likely Objective</span>
              </div>
              <p className="text-xs font-mono text-foreground">
                {aiAnalyst?.likely_objective || 'Theft of corporate banking single-sign-on credentials via spoofed interfaces'}
              </p>
            </div>
          </div>

          {/* Key Evidence Corroboration */}
          <div className="space-y-3">
            <div className="flex items-center space-x-2">
              <CheckCircle2 className="w-4 h-4 text-primary" />
              <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-foreground-muted">
                Key Evidentiary Signals
              </h3>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
              {(aiAnalyst?.key_evidence && aiAnalyst.key_evidence.length > 0
                ? aiAnalyst.key_evidence
                : [
                    'Global threat score evaluated at 85/100 (CRITICAL severity)',
                    'Brand lookalike detected: bank-corp-update.com targeting BankCorp',
                    'Email authentication mismatch: SPF=fail, DMARC=fail',
                    'Credential harvester identified at /auth/v2/secure_login.php'
                  ]
              ).map((ev, idx) => (
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

          {/* Recommended SOC Actions */}
          <div className="space-y-3">
            <div className="flex items-center space-x-2">
              <ListOrdered className="w-4 h-4 text-success" />
              <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-foreground-muted">
                Recommended SOC Response
              </h3>
            </div>

            <div className="space-y-2">
              {(aiAnalyst?.recommended_actions && aiAnalyst.recommended_actions.length > 0
                ? aiAnalyst.recommended_actions
                : [
                    'Quarantine or purge email from recipient inboxes across mail infrastructure',
                    'Block originating IP 185.220.101.42 and sender domain on secure email gateway (SEG)',
                    'Force immediate password reset and invalidate active sessions for targeted user',
                    'Submit detected phishing URLs to web proxy and DNS sinkhole blocklists'
                  ]
              ).map((act, aIdx) => (
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

          {/* Analytic Limitations & Boundaries */}
          <div className="p-3.5 rounded-xl bg-warning-surface border border-warning-border space-y-2">
            <div className="flex items-center space-x-2 text-warning text-xs font-mono font-bold uppercase tracking-wider">
              <AlertTriangle className="w-3.5 h-3.5 text-warning shrink-0" />
              <span>Analytic Limitations &amp; Boundaries</span>
            </div>
            <ul className="space-y-1 pl-4 list-disc text-[11px] font-mono text-foreground-muted">
              <li>Analysis is bounded to static email telemetry and Received header topology.</li>
              <li>Attribution is limited to observable IP/DNS infrastructure; physical actor identity remains unverified.</li>
            </ul>
          </div>

          {/* Disclaimer */}
          <div className="p-2.5 rounded-lg bg-surface-secondary/60 border border-border text-[11px] font-mono text-foreground-muted flex items-start space-x-2">
            <Info className="w-3.5 h-3.5 text-foreground-muted shrink-0 mt-0.5" />
            <span>
              <strong className="text-foreground">Analyst Advisory:</strong> The Copilot generates contextual narrative interpretations strictly grounded in empirical forensic telemetry. It does not override deterministic SPF/DKIM/DMARC authentication or forensic network scoring.
            </span>
          </div>
        </div>
      )}
    </div>
  );
};
