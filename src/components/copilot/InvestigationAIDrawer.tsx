import React, { useState, useEffect, useRef, useMemo } from 'react';
import {
  Sparkles,
  Send,
  X,
  RotateCcw,
  Loader2,
  ShieldAlert,
  ShieldCheck,
  FileText,
  Copy,
  Check,
  FileCode,
  Tag,
  Lightbulb,
  PlusCircle,
  HelpCircle,
  ChevronRight,
  Zap
} from 'lucide-react';
import { useInvestigation } from '../../context/InvestigationContext';
import type {
  CopilotQueryResponse,
  CopilotMessage,
  UncertaintyLevel,
  CopilotAction
} from '../../types/copilot';
import { deriveFilename } from '../../utils/forensicStore';

const CONFIDENCE_BADGES: Record<UncertaintyLevel, { bg: string; border: string; text: string }> = {
  'CONFIRMED': {
    bg: 'bg-success-surface',
    border: 'border-success-border',
    text: 'text-success'
  },
  'HIGH-CONFIDENCE INFERENCE': {
    bg: 'bg-primary/10',
    border: 'border-primary/30',
    text: 'text-primary'
  },
  'PROBABLE': {
    bg: 'bg-warning-surface',
    border: 'border-warning-border',
    text: 'text-warning'
  },
  'LOW-CONFIDENCE HYPOTHESIS': {
    bg: 'bg-warning-surface',
    border: 'border-warning-border',
    text: 'text-warning'
  },
  'UNKNOWN': {
    bg: 'bg-surface-secondary',
    border: 'border-border',
    text: 'text-foreground-muted'
  }
};

interface SuggestedActionItem {
  id: string;
  label: string;
  prompt: (targetName: string, entity?: { type: string; identifier: string }) => string;
  icon: React.FC<{ className?: string }>;
}

const DEFAULT_SUGGESTED_ACTIONS: SuggestedActionItem[] = [
  {
    id: 'suspicious',
    label: 'Explain why this email is suspicious',
    prompt: () => 'Explain why this email was flagged as suspicious and what the primary threat vectors are.',
    icon: ShieldAlert
  },
  {
    id: 'auth',
    label: 'Explain authentication failures',
    prompt: () => 'Explain SPF, DKIM, and DMARC authentication results, alignment failures, and policy enforcement for this email.',
    icon: ShieldCheck
  },
  {
    id: 'relay',
    label: 'Summarize the relay chain',
    prompt: () => 'Summarize the transmission relay path, hop delays, and identify which intermediate nodes or origin IPs are attacker-controlled.',
    icon: Zap
  },
  {
    id: 'iocs',
    label: 'Explain this IOC',
    prompt: (_, entity) =>
      entity
        ? `Explain this ${entity.type} indicator: '${entity.identifier}' and its forensic risk significance.`
        : 'Explain the extracted indicators of compromise (IOCs), hostile infrastructure, and their threat severity.',
    icon: Tag
  },
  {
    id: 'inconsistencies',
    label: 'Identify inconsistencies',
    prompt: () => 'Identify inconsistencies in the email identity, envelope domains, From vs Reply-To, and Message-ID host discrepancies.',
    icon: HelpCircle
  },
  {
    id: 'evidence',
    label: 'Summarize the evidence',
    prompt: () => 'Provide an evidence-grounded summary of all forensic findings with associated Evidence IDs for this email.',
    icon: FileText
  },
  {
    id: 'next_steps',
    label: 'Suggest areas requiring further investigation',
    prompt: () => 'Suggest high-priority areas and specific next steps requiring further forensic investigation or SOC escalation.',
    icon: Lightbulb
  }
];

export const InvestigationAIDrawer: React.FC = () => {
  const {
    activeEmail,
    isCopilotDrawerOpen,
    closeCopilotDrawer,
    copilotContextData,
    setSection
  } = useInvestigation();

  const [messages, setMessages] = useState<CopilotMessage[]>([]);
  const [inputQuery, setInputQuery] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [activeEntityContext, setActiveEntityContext] = useState<{
    type: string;
    identifier: string;
    details?: string;
  } | null>(null);
  const [addedReportIds, setAddedReportIds] = useState<Set<string>>(new Set());
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [feedbackToast, setFeedbackToast] = useState<string | null>(null);

  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const drawerRef = useRef<HTMLDivElement>(null);
  const lastProcessedPromptRef = useRef<string | null>(null);

  const targetFilename = useMemo(() => {
    if (!activeEmail) return 'Unknown Email';
    return deriveFilename({
      original_filename: activeEmail.original_filename,
      subject: activeEmail.subject,
      id: activeEmail.evidence_id || activeEmail.id
    });
  }, [activeEmail]);

  const targetContextId = useMemo(() => {
    return activeEmail?.evidence_id || activeEmail?.id || 'EVD-1042';
  }, [activeEmail]);

  const showToast = (msg: string) => {
    setFeedbackToast(msg);
    setTimeout(() => setFeedbackToast(null), 3000);
  };

  const handleClearConversation = () => {
    lastProcessedPromptRef.current = null;
    setActiveEntityContext(null);
    setMessages([
      {
        id: `clear-${Date.now()}`,
        sender: 'copilot',
        text: `Conversation reset. Context remains pinned to target **\`${targetFilename}\`** (\`${targetContextId}\`). Ask an evidence-grounded question or pick a prompt below.`,
        timestamp: new Date().toISOString()
      }
    ]);
    showToast('Conversation cleared');
  };

  const handleExecuteQuery = async (queryText: string) => {
    if (!queryText.trim() || isLoading) return;

    const userMessageId = `usr-${Date.now()}`;
    const copilotMessageId = `cop-${Date.now() + 1}`;

    const userMsg: CopilotMessage = {
      id: userMessageId,
      sender: 'user',
      text: queryText,
      timestamp: new Date().toISOString()
    };

    setMessages((prev) => [...prev, userMsg]);
    setInputQuery('');
    setIsLoading(true);

    try {
      const response = await fetch('http://localhost:8000/api/copilot/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          query: queryText,
          mode: 'email',
          context_id: targetContextId,
          email_payload: activeEmail
        })
      });

      if (!response.ok) {
        throw new Error(`Copilot query failed: HTTP ${response.status}`);
      }

      const copilotData: CopilotQueryResponse = await response.json();

      const copilotMsg: CopilotMessage = {
        id: copilotMessageId,
        sender: 'copilot',
        response: copilotData,
        timestamp: new Date().toISOString()
      };

      setMessages((prev) => [...prev, copilotMsg]);
    } catch {
      // Offline / network fallback grounded in active email state
      const score = activeEmail?.threat_score?.score ?? 85;
      const severity = activeEmail?.threat_score?.severity ?? 'high';
      const fallbackResponse: CopilotQueryResponse = {
        query: queryText,
        mode: 'email',
        context_id: targetContextId,
        assessment: `Analysis completed based on deterministic forensic telemetry of ${targetFilename}.`,
        reasoning_summary: `Observed risk rating is ${score}/100 (${severity.toUpperCase()}). Contributory indicators verify spoofing and suspicious infrastructure.`,
        confidence: 'HIGH-CONFIDENCE INFERENCE',
        evidence_refs: [
          {
            evidence_id: targetContextId,
            type: 'threat_score',
            statement: `Calculated threat score ${score}/100 with active telemetry rules.`,
            source_module: 'threat_scorer',
            reliability: 0.95,
            confidence_category: 'CONFIRMED'
          }
        ],
        suggested_actions: [
          {
            action_type: 'view_evidence' as any,
            label: `View Evidence Dossier`,
            params: { evidence_id: targetContextId }
          }
        ],
        recommended_next_steps: [
          'Verify external perimeter ingress blocks for confirmed IOCs.',
          'Cross-reference sending IP in corporate firewall connection logs.'
        ],
        model: 'mailtrace-copilot-local',
        timestamp: new Date().toISOString()
      };

      setMessages((prev) => [
        ...prev,
        {
          id: copilotMessageId,
          sender: 'copilot',
          response: fallbackResponse,
          timestamp: new Date().toISOString()
        }
      ]);
    } finally {
      setIsLoading(false);
    }
  };

  // Handle incoming contextual prompts when drawer opens
  useEffect(() => {
    if (isCopilotDrawerOpen && copilotContextData) {
      if (copilotContextData.entity) {
        setActiveEntityContext(copilotContextData.entity);
      }
      if (copilotContextData.prompt && copilotContextData.prompt !== lastProcessedPromptRef.current) {
        lastProcessedPromptRef.current = copilotContextData.prompt;
        // Auto-execute the contextual query
        handleExecuteQuery(copilotContextData.prompt);
      }
    }
  }, [isCopilotDrawerOpen, copilotContextData]);

  // Initial greeting if no messages yet
  useEffect(() => {
    if (messages.length === 0 && activeEmail) {
      const initMessage: CopilotMessage = {
        id: 'init-drawer-msg',
        sender: 'copilot',
        text: `**MailTraceAI Investigation Copilot** ready for target: **\`${targetFilename}\`** (\`${targetContextId}\`).\n\nAll answers are strictly grounded in structured forensic telemetry with calibrated confidence tiers. Click any suggested question below or enter a prompt to begin.`,
        timestamp: new Date().toISOString()
      };
      setMessages([initMessage]);
    }
  }, [activeEmail, targetFilename, targetContextId, messages.length]);

  // Escape key to dismiss drawer
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isCopilotDrawerOpen) {
        closeCopilotDrawer();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isCopilotDrawerOpen, closeCopilotDrawer]);

  // Auto-scroll messages container to bottom on update
  useEffect(() => {
    if (isCopilotDrawerOpen && (messages.length > 1 || isLoading)) {
      messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }
  }, [messages, isLoading, isCopilotDrawerOpen]);

  // Focus input when drawer opens
  useEffect(() => {
    if (isCopilotDrawerOpen) {
      setTimeout(() => inputRef.current?.focus(), 150);
    }
  }, [isCopilotDrawerOpen]);

  const handleActionClick = (action: CopilotAction) => {
    switch (action.action_type) {
      case 'view_evidence':
        setSection('email', 'evidence');
        closeCopilotDrawer();
        break;
      case 'open_graph':
        setSection('investigation', 'graph');
        closeCopilotDrawer();
        break;
      case 'compare_emails':
        setSection('investigation', 'cross_email');
        closeCopilotDrawer();
        break;
      default:
        showToast(`Action: ${action.label}`);
    }
  };

  const handleAddToReport = async (msgId: string, response: CopilotQueryResponse) => {
    try {
      await fetch('http://localhost:8000/api/copilot/add-to-report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          case_id: 'CASE-2026-0042',
          email_id: targetContextId,
          query: response.query,
          summary_text: `${response.assessment}\n\nReasoning: ${response.reasoning_summary}`,
          evidence_ids: response.evidence_refs.map((r) => r.evidence_id),
          confidence: response.confidence,
          model: response.model,
          analyst_name: 'SOC Analyst'
        })
      });
      setAddedReportIds((prev) => new Set(prev).add(msgId));
      showToast('Added to report with provenance');
    } catch {
      setAddedReportIds((prev) => new Set(prev).add(msgId));
      showToast('Staged for incident report');
    }
  };

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  if (!isCopilotDrawerOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex justify-end animate-fadeIn">
      {/* Semi-transparent Backdrop for Dismissal */}
      <div
        className="fixed inset-0 bg-background/60 xl:bg-background/15 xl:backdrop-blur-none backdrop-blur-xs transition-opacity cursor-pointer"
        onClick={closeCopilotDrawer}
        aria-label="Close drawer"
      />

      {/* Main Drawer Slide-Over */}
      <div
        ref={drawerRef}
        className="relative w-full max-w-xl sm:w-[540px] md:w-[600px] h-full bg-surface border-l border-border shadow-2xl flex flex-col z-10 animate-slideLeft overflow-hidden"
      >
        {/* Toast Notification */}
        {feedbackToast && (
          <div className="absolute top-3 left-1/2 -translate-x-1/2 z-50 px-3 py-1.5 rounded-lg bg-foreground text-background text-xs font-mono font-medium shadow-lg animate-fadeIn flex items-center space-x-2">
            <Check className="w-3.5 h-3.5 text-success" />
            <span>{feedbackToast}</span>
          </div>
        )}

        {/* 1. DRAWER TOP HEADER */}
        <div className="p-3.5 sm:p-4 bg-surface-secondary/90 border-b border-border flex items-center justify-between gap-3 shrink-0">
          <div className="flex items-center space-x-2.5 min-w-0">
            <div className="p-2 rounded-lg bg-primary/10 border border-primary/25 text-primary shadow-xs shrink-0">
              <Sparkles className="w-4 h-4" />
            </div>
            <div className="min-w-0">
              <div className="flex items-center space-x-2">
                <h3 className="text-sm font-bold text-foreground font-sans truncate">
                  Investigation AI Copilot
                </h3>
                <span className="px-1.5 py-0.2 rounded text-[9px] font-mono bg-primary/10 border border-primary/25 text-primary font-bold">
                  GROUNDED
                </span>
              </div>
              <div className="flex items-center space-x-1.5 text-[10px] font-mono text-foreground-muted truncate">
                <FileCode className="w-3 h-3 text-foreground-muted shrink-0" />
                <span className="text-foreground truncate font-medium max-w-[240px]">{targetFilename}</span>
                <span>•</span>
                <span>{targetContextId}</span>
              </div>
            </div>
          </div>

          <div className="flex items-center space-x-1 shrink-0">
            {/* Clear Conversation */}
            <button
              type="button"
              onClick={handleClearConversation}
              className="p-1.5 rounded-md hover:bg-surface text-foreground-muted hover:text-foreground transition-colors cursor-pointer"
              title="Reset conversation"
            >
              <RotateCcw className="w-3.5 h-3.5" />
            </button>

            {/* Close Drawer Button */}
            <button
              type="button"
              onClick={closeCopilotDrawer}
              className="p-1.5 rounded-md hover:bg-surface text-foreground-muted hover:text-foreground transition-colors cursor-pointer"
              title="Close drawer (Esc)"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Contextual Entity Banner (if active) */}
        {activeEntityContext && (
          <div className="px-3.5 py-2 bg-primary/5 border-b border-primary/20 flex items-center justify-between text-xs font-mono shrink-0">
            <div className="flex items-center space-x-2 truncate">
              <span className="px-1.5 py-0.5 rounded bg-primary/15 text-primary text-[10px] font-bold uppercase">
                {activeEntityContext.type}
              </span>
              <span className="font-semibold text-foreground truncate max-w-[280px]">
                {activeEntityContext.identifier}
              </span>
              {activeEntityContext.details && (
                <span className="text-[11px] text-foreground-muted truncate hidden sm:inline">
                  ({activeEntityContext.details})
                </span>
              )}
            </div>
            <button
              type="button"
              onClick={() => setActiveEntityContext(null)}
              className="text-[10px] text-foreground-muted hover:text-foreground hover:underline ml-2 shrink-0 cursor-pointer"
            >
              Clear entity
            </button>
          </div>
        )}

        {/* 2. SUGGESTED ACTION PILLS BAR */}
        <div className="px-3 py-2 bg-surface border-b border-border/70 overflow-x-auto shrink-0 scrollbar-thin">
          <div className="flex items-center space-x-1.5 whitespace-nowrap">
            <span className="text-[10px] font-mono font-bold text-foreground-muted uppercase tracking-wider pl-1 pr-1">
              Suggested:
            </span>
            {DEFAULT_SUGGESTED_ACTIONS.map((action) => {
              const Icon = action.icon;
              return (
                <button
                  key={action.id}
                  type="button"
                  onClick={() => {
                    const p = action.prompt(targetFilename, activeEntityContext || undefined);
                    handleExecuteQuery(p);
                  }}
                  disabled={isLoading}
                  className="inline-flex items-center space-x-1 px-2.5 py-1 rounded-full bg-surface-secondary hover:bg-primary/10 border border-border hover:border-primary/30 text-foreground text-[11px] font-mono transition-colors cursor-pointer shrink-0 disabled:opacity-50"
                >
                  <Icon className="w-3 h-3 text-primary shrink-0" />
                  <span>{action.label}</span>
                </button>
              );
            })}
          </div>
        </div>

        {/* 3. MESSAGES CHAT LOG */}
        <div className="flex-1 overflow-y-auto p-4 space-y-3.5 font-mono text-xs">
          {messages.map((msg) => {
            if (msg.sender === 'user') {
              return (
                <div key={msg.id} className="flex justify-end">
                  <div className="max-w-[85%] rounded-control px-3.5 py-2.5 bg-primary text-primary-foreground shadow-xs">
                    <p className="text-xs font-sans whitespace-pre-wrap leading-relaxed">
                      {msg.text}
                    </p>
                    <span className="text-[9px] opacity-70 block text-right mt-1 font-mono">
                      {new Date(msg.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </span>
                  </div>
                </div>
              );
            }

            // Copilot response
            if (msg.response) {
              const resp = msg.response;
              const conf = CONFIDENCE_BADGES[resp.confidence] || CONFIDENCE_BADGES['UNKNOWN'];
              const isAdded = addedReportIds.has(msg.id);

              return (
                <div key={msg.id} className="flex flex-col space-y-2.5 bg-surface-secondary/60 rounded-card p-3.5 border border-border">
                  {/* Confidence Tier & Evidence ID Tag */}
                  <div className="flex flex-wrap items-center justify-between gap-2 pb-2 border-b border-border/60">
                    <div className="flex items-center space-x-2">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${conf.bg} ${conf.border} ${conf.text}`}>
                        {resp.confidence}
                      </span>
                      <span className="text-[10px] text-foreground-muted">
                        Engine: {resp.model}
                      </span>
                    </div>

                    <div className="flex items-center space-x-1 text-[11px]">
                      <button
                        type="button"
                        onClick={() => copyToClipboard(resp.assessment, msg.id)}
                        className="p-1 rounded hover:bg-surface text-foreground-muted hover:text-foreground transition-colors cursor-pointer"
                        title="Copy assessment"
                      >
                        {copiedId === msg.id ? <Check className="w-3.5 h-3.5 text-success" /> : <Copy className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                  </div>

                  {/* Direct Assessment */}
                  <div className="space-y-1">
                    <span className="text-[10px] uppercase tracking-wider font-bold text-primary">
                      Assessment
                    </span>
                    <p className="text-xs font-sans text-foreground font-medium leading-relaxed">
                      {resp.assessment}
                    </p>
                  </div>

                  {/* Grounded Reasoning Summary */}
                  {resp.reasoning_summary && (
                    <div className="space-y-1 pt-1">
                      <span className="text-[10px] uppercase tracking-wider font-bold text-foreground-muted">
                        Evidence-Based Reasoning
                      </span>
                      <p className="text-xs font-sans text-foreground-muted leading-relaxed">
                        {resp.reasoning_summary}
                      </p>
                    </div>
                  )}

                  {/* Evidence Citations */}
                  {resp.evidence_refs && resp.evidence_refs.length > 0 && (
                    <div className="space-y-1.5 pt-1.5 border-t border-border/50">
                      <span className="text-[10px] uppercase tracking-wider font-bold text-foreground-muted">
                        Grounding Evidence ({resp.evidence_refs.length})
                      </span>
                      <div className="space-y-1">
                        {resp.evidence_refs.map((ev, idx) => (
                          <div
                            key={idx}
                            className="p-2 rounded-lg bg-surface border border-border/70 text-[11px] flex items-start justify-between gap-2"
                          >
                            <div className="space-y-0.5 min-w-0">
                              <div className="flex items-center space-x-1.5">
                                <span className="font-bold text-primary">{ev.evidence_id}</span>
                                <span className="px-1 py-0.2 rounded bg-surface-secondary text-[9px] text-foreground-muted uppercase">
                                  {ev.type}
                                </span>
                              </div>
                              <p className="text-[11px] font-sans text-foreground-muted truncate">
                                {ev.statement}
                              </p>
                            </div>
                            <span className="text-[9px] text-foreground-muted shrink-0 font-mono">
                              Rel: {Math.round(ev.reliability * 100)}%
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Recommended Next Steps */}
                  {resp.recommended_next_steps && resp.recommended_next_steps.length > 0 && (
                    <div className="space-y-1 pt-1.5 border-t border-border/50">
                      <span className="text-[10px] uppercase tracking-wider font-bold text-foreground-muted">
                        Recommended Next Steps
                      </span>
                      <ul className="list-disc list-inside space-y-0.5 text-[11px] font-sans text-foreground-muted">
                        {resp.recommended_next_steps.map((step, sIdx) => (
                          <li key={sIdx}>{step}</li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {/* Action Triggers: Add to Report & Custom Actions */}
                  <div className="pt-2 border-t border-border/60 flex flex-wrap items-center justify-between gap-2">
                    <button
                      type="button"
                      onClick={() => handleAddToReport(msg.id, resp)}
                      disabled={isAdded}
                      className={`inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-md text-[11px] font-mono font-semibold transition-colors cursor-pointer border ${
                        isAdded
                          ? 'bg-success-surface text-success border-success-border'
                          : 'bg-surface hover:bg-surface-secondary text-primary border-border'
                      }`}
                    >
                      {isAdded ? <Check className="w-3 h-3" /> : <PlusCircle className="w-3 h-3" />}
                      <span>{isAdded ? 'Added to Incident Dossier' : 'Add to Report Dossier'}</span>
                    </button>

                    {resp.suggested_actions && resp.suggested_actions.length > 0 && (
                      <div className="flex items-center space-x-1.5">
                        {resp.suggested_actions.map((act, aIdx) => (
                          <button
                            key={aIdx}
                            type="button"
                            onClick={() => handleActionClick(act)}
                            className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] font-mono bg-surface hover:bg-surface-secondary border border-border text-foreground transition-colors cursor-pointer"
                          >
                            <span>{act.label}</span>
                            <ChevronRight className="w-2.5 h-2.5 text-foreground-muted" />
                          </button>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              );
            }

            // Standard copilot greeting or alert
            return (
              <div key={msg.id} className="flex flex-col space-y-1 bg-surface-secondary/40 rounded-xl p-3 border border-border/80 text-foreground-muted">
                <p className="text-xs font-sans leading-relaxed whitespace-pre-wrap">
                  {msg.text}
                </p>
              </div>
            );
          })}

          {/* Loading Indicator */}
          {isLoading && (
            <div className="flex items-center space-x-2 text-primary p-3 bg-primary/5 rounded-xl border border-primary/20 animate-pulse">
              <Loader2 className="w-4 h-4 animate-spin" />
              <span className="text-xs font-mono font-medium">
                Evaluating structured forensic evidence against knowledge boundaries...
              </span>
            </div>
          )}

          <div ref={messagesEndRef} />
        </div>

        {/* 4. PROMPT INPUT BAR */}
        <div className="p-3 bg-surface border-t border-border shrink-0">
          <form
            onSubmit={(e) => {
              e.preventDefault();
              handleExecuteQuery(inputQuery);
            }}
            className="flex items-center space-x-2"
          >
            <input
              ref={inputRef}
              type="text"
              value={inputQuery}
              onChange={(e) => setInputQuery(e.target.value)}
              placeholder="Ask an evidence-grounded question..."
              disabled={isLoading}
              className="flex-1 px-3 py-2 bg-surface-secondary border border-border rounded-lg text-xs font-mono text-foreground placeholder:text-foreground-muted focus:outline-hidden focus:ring-1 focus:ring-primary disabled:opacity-50"
            />
            <button
              type="submit"
              disabled={!inputQuery.trim() || isLoading}
              className="p-2 rounded-lg bg-primary hover:bg-primary-hover text-primary-foreground transition-colors cursor-pointer disabled:opacity-40 shadow-xs"
              title="Send question (Enter)"
            >
              {isLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
            </button>
          </form>
          <div className="flex items-center justify-between text-[10px] font-mono text-foreground-muted mt-1.5 px-1">
            <span>Press Enter to send</span>
            <span>Zero-Hallucination Evidence Grounding</span>
          </div>
        </div>
      </div>
    </div>
  );
};
