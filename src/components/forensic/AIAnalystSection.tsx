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
  Layers,
  MessageSquare,
  HelpCircle,
  ChevronRight
} from 'lucide-react';
import { StatusRow, DetailDrawer, ExpandableSection } from '../common/progressive';

interface AIAnalystSectionProps {
  aiAnalyst?: AIAnalystAssessment;
  conclusions?: ForensicConclusion[];
  email?: EmailAnalysis;
  onFocusGraphNode?: (id: string) => void;
  onOpenWorkspace?: () => void;
  onSelectEmail?: (email: EmailAnalysis) => void;
}

export const AIAnalystSection: React.FC<AIAnalystSectionProps> = ({
  aiAnalyst,
  conclusions = [],
  email,
  onFocusGraphNode,
  onOpenWorkspace,
  onSelectEmail
}) => {
  const [activeView, setActiveView] = useState<'copilot' | 'executive'>('copilot');
  const [selectedInitialPrompt, setSelectedInitialPrompt] = useState<string | undefined>(undefined);
  const [rawModelModalOpen, setRawModelModalOpen] = useState(false);

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

  const isMalicious = Boolean(
    aiAnalyst?.likely_attack_type?.toLowerCase().includes('phish') ||
    aiAnalyst?.likely_attack_type?.toLowerCase().includes('harvest') ||
    aiAnalyst?.likely_attack_type?.toLowerCase().includes('bec') ||
    aiAnalyst?.likely_attack_type?.toLowerCase().includes('malware') ||
    (email?.threat_score?.score && email.threat_score.score >= 50)
  );

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
          onSelectEmail={onSelectEmail}
        />
      )}

      {/* VIEW: Executive Threat Assessment Card with Progressive Disclosure */}
      {activeView === 'executive' && (
        <div className="space-y-4">
          <ExpandableSection
            title="Executive Forensic Synthesis"
            subtitle={`Deterministic attack categorization from ${aiAnalyst?.model || aiAnalyst?.provider || 'mailtrace-copilot-v1'}`}
            icon={Layers}
            defaultExpanded={true}
            badge={
              <div className="flex items-center space-x-2">
                {nlpOrThreatConclusion && (
                  <ConfidenceBadge
                    conclusion={nlpOrThreatConclusion}
                    allConclusions={conclusions}
                    size="sm"
                  />
                )}
                <span className={`px-2.5 py-0.5 rounded-full text-xs font-mono font-bold uppercase border ${
                  isMalicious
                    ? 'bg-danger-surface text-danger border-danger-border'
                    : 'bg-success-surface text-success border-success-border'
                }`}>
                  {aiAnalyst?.likely_attack_type || (isMalicious ? 'Malicious Phish' : 'Benign Baseline')}
                </span>
              </div>
            }
          >
            <StatusRow
              title="Forensic Threat Assessment Verdict"
              status={isMalicious ? 'CRITICAL' : 'PASS'}
              statusLabel={aiAnalyst?.likely_attack_type || (isMalicious ? 'MALICIOUS' : 'BENIGN')}
              subtitle={`Attack vector classification and operational objective synthesis`}
              defaultExpanded={false}
              onViewRaw={() => setRawModelModalOpen(true)}
              rawButtonLabel="View model prompt & inference trace"
            >
              <div className="space-y-4">
                {/* Narrative Summary */}
                <div className="p-3.5 rounded-xl bg-surface border border-border space-y-1.5">
                  <span className="text-[10px] font-mono uppercase font-bold text-foreground-muted block">
                    Forensic Narrative Summary
                  </span>
                  <p className="text-xs sm:text-sm font-sans text-foreground leading-relaxed">
                    {aiAnalyst?.summary ||
                      'The analyzed email presents characteristics of Credential Harvesting Phishing with a high-confidence threat classification. Key driving indicators include domain lookalike spoofing and cryptographic authentication mismatch.'}
                  </p>
                </div>

                {/* Grid: Attack Type & Objective */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
                  <div className="p-3 rounded-lg bg-surface border border-border space-y-1">
                    <span className="text-[10px] font-bold uppercase text-danger flex items-center gap-1">
                      <ShieldAlert className="w-3.5 h-3.5 text-danger" /> Likely Attack Type
                    </span>
                    <p className="text-foreground font-semibold">
                      {aiAnalyst?.likely_attack_type || 'Credential Harvesting Phishing via Domain Impersonation'}
                    </p>
                  </div>

                  <div className="p-3 rounded-lg bg-surface border border-border space-y-1">
                    <span className="text-[10px] font-bold uppercase text-warning flex items-center gap-1">
                      <Target className="w-3.5 h-3.5 text-warning" /> Likely Objective
                    </span>
                    <p className="text-foreground">
                      {aiAnalyst?.likely_objective || 'Unauthorized credential capture via spoofed interface'}
                    </p>
                  </div>
                </div>

                {/* Key Evidence Corroboration */}
                <div className="space-y-2">
                  <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-foreground-muted flex items-center gap-1.5">
                    <CheckCircle2 className="w-3.5 h-3.5 text-primary" />
                    <span>Key Evidentiary Signals</span>
                  </span>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-mono">
                    {(aiAnalyst?.key_evidence && aiAnalyst.key_evidence.length > 0
                      ? aiAnalyst.key_evidence
                      : [
                          'Global threat score evaluated at 85/100 (CRITICAL severity)',
                          'Brand lookalike detected mimicking recognizable institution',
                          'Authentication mismatch: SPF/DMARC failed alignment',
                          'Credential harvester destination identified'
                        ]
                    ).map((ev, idx) => (
                      <div key={idx} className="p-2.5 rounded-lg bg-surface border border-border flex items-start space-x-2">
                        <div className="w-1.5 h-1.5 rounded-full bg-primary mt-1.5 shrink-0" />
                        <span className="text-foreground-muted leading-relaxed text-[11px]">{ev}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Recommended Response */}
                <div className="space-y-2">
                  <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-foreground-muted flex items-center gap-1.5">
                    <ListOrdered className="w-3.5 h-3.5 text-success" />
                    <span>Recommended SOC Response</span>
                  </span>
                  <div className="space-y-1.5 text-xs font-mono">
                    {(aiAnalyst?.recommended_actions && aiAnalyst.recommended_actions.length > 0
                      ? aiAnalyst.recommended_actions
                      : [
                          'Quarantine or purge email from recipient inboxes across mail infrastructure',
                          'Block originating IP and sender domain on secure email gateway (SEG)',
                          'Force immediate password reset and invalidate active sessions for targeted user',
                          'Submit detected phishing URLs to web proxy blocklists'
                        ]
                    ).map((act, aIdx) => (
                      <div key={aIdx} className="p-2.5 rounded-lg bg-surface border border-border flex items-start space-x-2.5">
                        <span className="w-4 h-4 rounded bg-success/10 text-success text-[10px] font-bold flex items-center justify-center shrink-0">
                          {aIdx + 1}
                        </span>
                        <span className="text-foreground text-[11px]">{act}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Limitations */}
                <div className="p-3 rounded-lg bg-warning-surface border border-warning-border space-y-1 text-xs font-mono">
                  <div className="flex items-center space-x-1.5 text-warning font-bold text-[11px]">
                    <AlertTriangle className="w-3 h-3" />
                    <span>Analytic Boundaries</span>
                  </div>
                  <p className="text-[11px] text-foreground-muted">
                    Analysis is bounded to static email telemetry and Received header topology. Attribution is limited to observable IP/DNS infrastructure.
                  </p>
                </div>
              </div>
            </StatusRow>
          </ExpandableSection>

          {/* Level 3 Raw Drawer */}
          {rawModelModalOpen && (
            <DetailDrawer
              isOpen={rawModelModalOpen}
              onClose={() => setRawModelModalOpen(false)}
              title="Copilot Model Synthesis Dossier"
              subtitle="Full evidence-grounding trace and LLM response payload"
              data={{
                model: aiAnalyst?.model || 'mailtrace-copilot-v1',
                likely_attack_type: aiAnalyst?.likely_attack_type,
                likely_objective: aiAnalyst?.likely_objective,
                confidence: email?.threat_score?.confidence ?? email?.attribution?.confidence_score ?? 'Calibrated',
                evidence_grounding_citations: aiAnalyst?.key_evidence,
                recommended_actions: aiAnalyst?.recommended_actions,
                raw_synthesis_summary: aiAnalyst?.summary
              }}
              format="json"
            />
          )}
        </div>
      )}
    </div>
  );
};
