import { apiFetch } from '../../../utils/apiClient';
import React, { useState, useEffect, useCallback } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Info,
  Layers,
  Sparkles,
  RefreshCw,
  GitBranch,
  ChevronRight,
  ChevronDown,
  ChevronUp,
  Download,
  MessageSquare,
  Lock,
  Cpu,
  FileText,
  CheckCircle2,
  HelpCircle,
  Sliders,
  Hash,
  AlertOctagon
} from 'lucide-react';
import type {
  ExplanationResponse,
  ExplanationUnit,
  ExplanationLayer,
  ExplanationFeedbackCreate
} from '../../../types/explainable_ai';
import { EvidenceDrawer } from './EvidenceDrawer';
import { apiUrl } from '../../../utils/apiClient';

interface ExplainableAIPanelProps {
  scopeType?: string;
  scopeId?: string;
  workspaceId?: string;
  initialExplanation?: ExplanationResponse | null;
  riskScore?: number;
  riskLevel?: string;
  confidence?: string;
  className?: string;
}

export const ExplainableAIPanel: React.FC<ExplainableAIPanelProps> = ({
  scopeType = 'EVENT',
  scopeId,
  workspaceId = 'default',
  initialExplanation = null,
  riskScore,
  riskLevel,
  confidence,
  className = ''
}) => {
  const [explanation, setExplanation] = useState<ExplanationResponse | null>(initialExplanation);
  const [loading, setLoading] = useState<boolean>(!initialExplanation);
  const [error, setError] = useState<string | null>(null);
  const [activeLayer, setActiveLayer] = useState<ExplanationLayer>('EXECUTIVE');
  const [selectedUnit, setSelectedUnit] = useState<ExplanationUnit | null>(null);

  // Narrative generation state
  const [narrativeLoading, setNarrativeLoading] = useState<boolean>(false);
  const [narrativeNotice, setNarrativeNotice] = useState<string | null>(null);

  // Feedback modal state
  const [showFeedbackModal, setShowFeedbackModal] = useState<boolean>(false);
  const [feedbackType, setFeedbackType] = useState<string>('ANALYST_CONFIRMED');
  const [feedbackNotes, setFeedbackNotes] = useState<string>('');
  const [feedbackSubmitting, setFeedbackSubmitting] = useState<boolean>(false);
  const [feedbackSuccess, setFeedbackSuccess] = useState<string | null>(null);

  // Snapshot state
  const [snapshotSuccess, setSnapshotSuccess] = useState<string | null>(null);
  const [snapshotLoading, setSnapshotLoading] = useState<boolean>(false);

  // Expanded sections in lower layers
  const [expandedSections, setExpandedSections] = useState<Record<string, boolean>>({
    contributors: true,
    counterEvidence: true,
    contradictions: true,
    uncertainty: true,
    families: true,
    detectors: false,
    rules: false,
    mitre: true,
    attackPath: true,
    provenance: false
  });

  const toggleSection = (key: string) => {
    setExpandedSections((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  const fetchExplanation = useCallback(async () => {
    if (!scopeId) return;
    setLoading(true);
    setError(null);
    try {
      const res = await apiFetch(apiUrl(`/api/v1/explanation/${encodeURIComponent(scopeType)}/${encodeURIComponent(scopeId)}?workspace_id=${encodeURIComponent(workspaceId)}`));
      if (res.ok) {
        const data: ExplanationResponse = await res.json();
        setExplanation(data);
      } else if (res.status === 404) {
        setError('No structured risk assessment is available for this record. Review the source evidence and analysis findings.');
      } else {
        setError(`Failed to retrieve explanation (${res.statusText})`);
      }
    } catch (err: any) {
      setError(err?.message || 'Error communicating with explanation service');
    } finally {
      setLoading(false);
    }
  }, [scopeId, scopeType, workspaceId]);

  useEffect(() => {
    if (!explanation && scopeId) {
      fetchExplanation();
    }
  }, [fetchExplanation, explanation, scopeId]);

  const handleGenerateNarrative = async () => {
    if (!explanation || !scopeId) return;
    setNarrativeLoading(true);
    setNarrativeNotice(null);
    try {
      const res = await apiFetch(apiUrl(`/api/v1/explanation/${encodeURIComponent(scopeType)}/${encodeURIComponent(scopeId)}/generate-narrative?workspace_id=${encodeURIComponent(workspaceId)}`), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          explanation_id: explanation.id,
          scope_type: scopeType, scope_id: scopeId, detail_level: activeLayer
        })
      });
      if (res.ok) {
        const data = await res.json();
        setExplanation((prev) =>
          prev
            ? {
                ...prev,
                generated_text: data.narrative,
                executive_summary:
                  activeLayer === 'EXECUTIVE' ? data.narrative : prev.executive_summary,
                analyst_summary:
                  activeLayer === 'ANALYST' ? data.narrative : prev.analyst_summary
              }
            : null
        );
        if (data.used_fallback) {
          setNarrativeNotice(
            `Safe Fallback: ${data.fallback_reason || 'LLM introduced unsupported entities; safe deterministic explanation preserved.'}`
          );
        } else {
          setNarrativeNotice('Narrative synthesized and strictly verified against ground evidence.');
        }
      } else {
        setNarrativeNotice('Narrative generation failed; deterministic explanation is active.');
      }
    } catch {
      setNarrativeNotice('Failed to reach LLM synthesis service; deterministic explanation retained.');
    } finally {
      setNarrativeLoading(false);
      setTimeout(() => setNarrativeNotice(null), 6000);
    }
  };

  const handleCreateSnapshot = async () => {
    if (!explanation || !scopeId) return;
    setSnapshotLoading(true);
    setError(null);
    try {
      const res = await apiFetch(apiUrl(`/api/v1/explanation/${encodeURIComponent(scopeType)}/${encodeURIComponent(scopeId)}/snapshots?workspace_id=${encodeURIComponent(workspaceId)}`), {
        method: 'POST'
      });
      if (res.ok) {
        const snap = await res.json();
        setSnapshotSuccess(`Forensic snapshot #${snap.explanation_version} saved.`);
        setTimeout(() => setSnapshotSuccess(null), 4000);
      } else {
        setError('Snapshot could not be saved. Retry after checking the explanation service.');
      }
    } catch {
      setError('Unable to reach the explanation service to save this snapshot.');
    } finally {
      setSnapshotLoading(false);
    }
  };

  const handleSubmitFeedback = async () => {
    if (!explanation || !scopeId || !feedbackNotes.trim()) return;
    setFeedbackSubmitting(true);
    setError(null);
    try {
      const payload: ExplanationFeedbackCreate = {
        analyst_id: 'current_analyst',
        feedback_type: feedbackType,
        notes: feedbackNotes.trim()
      };
      const res = await apiFetch(apiUrl(`/api/v1/explanation/${encodeURIComponent(scopeType)}/${encodeURIComponent(scopeId)}/feedback?workspace_id=${encodeURIComponent(workspaceId)}`), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      if (res.ok) {
        setFeedbackSuccess('Analyst feedback recorded. Historical explanation preserved.');
        setShowFeedbackModal(false);
        setFeedbackNotes('');
        setTimeout(() => setFeedbackSuccess(null), 4000);
      } else {
        setError('Feedback could not be recorded. Your notes have been retained for retry.');
      }
    } catch {
      setError('Unable to reach the explanation service. Your feedback notes have been retained.');
    } finally {
      setFeedbackSubmitting(false);
    }
  };

  const effectiveScore = explanation?.risk_score ?? riskScore ?? 0;
  const effectiveLevel = (explanation?.risk_level ?? riskLevel ?? 'LOW').toUpperCase();
  const effectiveConfidence = (explanation?.confidence_level ?? confidence ?? 'UNAVAILABLE').toUpperCase();

  const getScoreColor = (lvl: string) => {
    switch (lvl) {
      case 'CRITICAL':
        return 'text-rose-400 bg-rose-500/10 border-rose-500/30';
      case 'HIGH':
        return 'text-amber-400 bg-amber-500/10 border-amber-500/30';
      case 'MEDIUM':
        return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30';
      default:
        return 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30';
    }
  };

  return (
    <div className={`bg-surface rounded-xl border border-border overflow-hidden shadow-sm ${className}`}>
      {/* ---------------------------------------------------------------------
          HEADER: Decision vs Explanation separation badge & controls
          --------------------------------------------------------------------- */}
      <div className="p-4 sm:p-5 border-b border-border bg-surface-secondary/40 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-start sm:items-center space-x-3">
          <div className="p-2.5 rounded-lg bg-primary/10 border border-primary/20 text-primary shrink-0">
            <Sparkles className="w-5 h-5" />
          </div>
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <h2 className="text-sm sm:text-base font-semibold text-foreground tracking-tight">
                Explainable AI (XAI)
              </h2>
              <span className="text-[10px] px-2 py-0.5 rounded font-mono font-bold bg-surface-tertiary text-foreground-muted border border-border">
                {explanation ? `v${explanation.explanation_version}` : 'LAYER'}
              </span>
              <span className="text-[10px] px-2 py-0.5 rounded font-mono font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                Authoritative Decisions Preserved
              </span>
            </div>
            <p className="text-xs text-foreground-muted mt-0.5">
              Traceable, evidence-backed reasoning answering why CyberGuard flagged this event.
            </p>
          </div>
        </div>

        {/* Authoritative Risk Summary Pill & Actions */}
        <div className="flex flex-wrap items-center gap-2 self-start md:self-auto">
          <div className={`px-3 py-1.5 rounded-lg border flex items-center space-x-2 font-mono text-xs ${getScoreColor(effectiveLevel)}`}>
            <span className="font-bold">{effectiveLevel}</span>
            <span className="opacity-40">|</span>
            <span>Score: <strong className="font-bold">{effectiveScore}</strong></span>
            <span className="opacity-40">|</span>
            <span className="text-[11px] opacity-80">{effectiveConfidence} Conf.</span>
          </div>

          <button
            type="button"
            onClick={fetchExplanation}
            disabled={loading}
            title="Refresh explanation"
            className="p-1.5 rounded-lg border border-border bg-surface hover:bg-surface-secondary text-foreground-muted hover:text-foreground transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          </button>

          {explanation && (
            <>
              <button
                type="button"
                onClick={handleCreateSnapshot}
                disabled={snapshotLoading}
                title="Save historical snapshot"
                className="px-2.5 py-1.5 rounded-lg border border-border bg-surface hover:bg-surface-secondary text-foreground text-xs font-mono font-medium flex items-center space-x-1.5 transition-colors"
              >
                <Download className="w-3.5 h-3.5 text-primary" />
                <span className="hidden sm:inline">Snapshot</span>
              </button>

              <button
                type="button"
                onClick={() => setShowFeedbackModal(true)}
                title="Provide analyst feedback"
                className="px-2.5 py-1.5 rounded-lg border border-border bg-surface hover:bg-surface-secondary text-foreground text-xs font-mono font-medium flex items-center space-x-1.5 transition-colors"
              >
                <MessageSquare className="w-3.5 h-3.5 text-amber-400" />
                <span className="hidden sm:inline">Feedback</span>
              </button>
            </>
          )}
        </div>
      </div>

      {/* Notifications / Alerts */}
      {snapshotSuccess && (
        <div className="bg-emerald-500/10 border-b border-emerald-500/20 px-4 py-2 text-xs text-emerald-400 flex items-center space-x-2 font-mono">
          <CheckCircle2 className="w-4 h-4 shrink-0" />
          <span>{snapshotSuccess}</span>
        </div>
      )}
      {feedbackSuccess && (
        <div className="bg-blue-500/10 border-b border-blue-500/20 px-4 py-2 text-xs text-blue-400 flex items-center space-x-2 font-mono">
          <CheckCircle2 className="w-4 h-4 shrink-0" />
          <span>{feedbackSuccess}</span>
        </div>
      )}
      {narrativeNotice && (
        <div className="bg-primary/10 border-b border-primary/20 px-4 py-2 text-xs text-primary flex items-center space-x-2 font-mono">
          <Info className="w-4 h-4 shrink-0" />
          <span>{narrativeNotice}</span>
        </div>
      )}

      {/* ---------------------------------------------------------------------
          PROGRESSIVE DISCLOSURE LAYER TABS (Executive -> Analyst -> Investigator -> Forensic)
          --------------------------------------------------------------------- */}
      <div className="flex border-b border-border bg-surface-secondary/20 px-4 pt-2 gap-1 overflow-x-auto">
        {(
          [
            { id: 'EXECUTIVE', label: 'Level 1: Executive', desc: 'Summary & Core Drivers' },
            { id: 'ANALYST', label: 'Level 2: Analyst', desc: 'Contributors & Disagreements' },
            { id: 'INVESTIGATOR', label: 'Level 3: Investigator', desc: 'Signals, Rules & Path' },
            { id: 'FORENSIC', label: 'Level 4: Forensic', desc: 'Traceability & Provenance' }
          ] as const
        ).map((tab) => (
          <button
            key={tab.id}
            type="button"
            onClick={() => setActiveLayer(tab.id)}
            className={`px-3.5 py-2 text-xs font-mono font-medium rounded-t-lg transition-colors border-b-2 whitespace-nowrap cursor-pointer flex items-center space-x-2 ${
              activeLayer === tab.id
                ? 'border-primary text-primary bg-surface font-semibold shadow-xs'
                : 'border-transparent text-foreground-muted hover:text-foreground hover:bg-surface-secondary/40'
            }`}
          >
            <span>{tab.label}</span>
          </button>
        ))}
      </div>

      {/* Loading & Error States */}
      {loading && !explanation && (
        <div className="p-8 text-center space-y-2">
          <RefreshCw className="w-6 h-6 animate-spin mx-auto text-primary" />
          <p className="text-xs font-mono text-foreground-muted">Composing grounded explanation graph...</p>
        </div>
      )}

      {error && !explanation && (
        <div className="p-6 text-center space-y-3">
          <AlertCircleIcon className="w-8 h-8 text-amber-400 mx-auto" />
          <p className="text-xs text-foreground-muted max-w-md mx-auto">{error}</p>
          <button
            type="button"
            onClick={fetchExplanation}
            className="px-3 py-1.5 rounded-lg bg-surface-secondary hover:bg-surface-secondary/80 border border-border text-xs font-mono text-foreground"
          >
            Retry Explanation Retrieval
          </button>
        </div>
      )}

      {/* Main Content Area */}
      {explanation && (
        <div className="p-4 sm:p-5 space-y-6">
          {/* -----------------------------------------------------------------
              LEVEL 1 — EXECUTIVE (1-2 sentences, key drivers, change guidance)
              ----------------------------------------------------------------- */}
          {activeLayer === 'EXECUTIVE' && (
            <div className="space-y-5 animate-in fade-in duration-150">
              {/* Executive Summary Card */}
              <div className="p-4 rounded-xl bg-surface-secondary/60 border border-border space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <FileText className="w-4 h-4 text-primary" />
                    <span className="text-xs font-mono font-semibold uppercase tracking-wider text-foreground">
                      Executive Briefing
                    </span>
                  </div>
                  <button
                    type="button"
                    onClick={handleGenerateNarrative}
                    disabled={narrativeLoading}
                    className="text-xs font-mono text-primary hover:underline flex items-center space-x-1 disabled:opacity-50"
                  >
                    <Sparkles className={`w-3 h-3 ${narrativeLoading ? 'animate-spin' : ''}`} />
                    <span>{narrativeLoading ? 'Verifying Grounding...' : 'Synthesize Grounded Narrative'}</span>
                  </button>
                </div>
                <p className="text-sm text-foreground leading-relaxed font-sans font-medium">
                  {explanation.executive_summary || explanation.summary}
                </p>
              </div>

              {/* Primary Supported Findings / Claims */}
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-foreground-muted">
                    Primary Reasons Flagged ({explanation.explanation_units.length} Grounded Claims)
                  </h3>
                  <span className="text-[11px] text-foreground-muted font-mono">
                    Click any claim to view original artifact
                  </span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {explanation.explanation_units.slice(0, 4).map((unit) => (
                    <div
                      key={unit.id}
                      onClick={() => setSelectedUnit(unit)}
                      className="p-3.5 rounded-xl border border-border bg-surface-secondary/30 hover:bg-surface-secondary/70 hover:border-primary/40 transition-all cursor-pointer group flex flex-col justify-between space-y-3"
                    >
                      <div className="space-y-1.5">
                        <div className="flex items-center justify-between">
                          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-surface border border-border text-foreground-muted font-semibold">
                            {unit.claim_type}
                          </span>
                          <span className="text-[10px] font-mono font-bold text-emerald-400">
                            {unit.support_level}
                          </span>
                        </div>
                        <p className="text-xs font-sans text-foreground font-medium group-hover:text-primary transition-colors">
                          {unit.claim}
                        </p>
                      </div>

                      <div className="flex items-center justify-between text-[11px] font-mono text-foreground-muted pt-2 border-t border-border/60">
                        <span>{unit.evidence_refs.length} Evidence Ref{unit.evidence_refs.length !== 1 ? 's' : ''}</span>
                        <span className="flex items-center space-x-1 text-primary group-hover:translate-x-0.5 transition-transform">
                          <span>Inspect</span>
                          <ChevronRight className="w-3 h-3" />
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Assessment Change Guidance ("What Would Change This Assessment?") */}
              {explanation.assessment_change_guidance && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
                  <div className="p-4 rounded-xl border border-rose-500/20 bg-rose-500/5 space-y-2">
                    <div className="flex items-center space-x-2 text-rose-400">
                      <ShieldAlert className="w-4 h-4" />
                      <h4 className="text-xs font-mono font-semibold uppercase tracking-wider">
                        Assessment Would Become Stronger If:
                      </h4>
                    </div>
                    <ul className="space-y-1.5 text-xs text-foreground-muted font-sans list-disc list-inside">
                      {explanation.assessment_change_guidance.what_would_strengthen.map((item, idx) => (
                        <li key={idx} className="leading-snug">{item}</li>
                      ))}
                    </ul>
                  </div>

                  <div className="p-4 rounded-xl border border-blue-500/20 bg-blue-500/5 space-y-2">
                    <div className="flex items-center space-x-2 text-blue-400">
                      <ShieldCheck className="w-4 h-4" />
                      <h4 className="text-xs font-mono font-semibold uppercase tracking-wider">
                        Assessment Would Become Weaker If:
                      </h4>
                    </div>
                    <ul className="space-y-1.5 text-xs text-foreground-muted font-sans list-disc list-inside">
                      {explanation.assessment_change_guidance.what_would_weaken.map((item, idx) => (
                        <li key={idx} className="leading-snug">{item}</li>
                      ))}
                    </ul>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* -----------------------------------------------------------------
              LEVEL 2 — ANALYST (Risk contributors, counter-evidence, contradictions, unknowns)
              ----------------------------------------------------------------- */}
          {activeLayer === 'ANALYST' && (
            <div className="space-y-5 animate-in fade-in duration-150">
              {/* Analyst Summary */}
              <div className="p-4 rounded-xl bg-surface-secondary/40 border border-border space-y-2">
                <span className="text-xs font-mono font-semibold uppercase tracking-wider text-foreground-muted">
                  Analyst Synthesized Overview
                </span>
                <p className="text-xs sm:text-sm text-foreground leading-relaxed font-sans">
                  {explanation.analyst_summary || explanation.summary}
                </p>
              </div>

              {/* 1. Risk Contributors */}
              <div className="border border-border rounded-xl bg-surface overflow-hidden">
                <button
                  type="button"
                  onClick={() => toggleSection('contributors')}
                  className="w-full p-3.5 bg-surface-secondary/30 flex items-center justify-between text-left hover:bg-surface-secondary/50 transition-colors"
                >
                  <div className="flex items-center space-x-2">
                    <Sliders className="w-4 h-4 text-primary" />
                    <span className="text-xs font-mono font-semibold uppercase tracking-wider text-foreground">
                      Structured Risk Contributors ({explanation.contributors.length})
                    </span>
                  </div>
                  {expandedSections.contributors ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                </button>

                {expandedSections.contributors && (
                  <div className="divide-y divide-border">
                    {explanation.contributors.map((c, idx) => (
                      <div key={idx} className="p-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3 hover:bg-surface-secondary/20">
                        <div className="space-y-1">
                          <div className="flex items-center space-x-2">
                            <span className="text-xs font-semibold text-foreground">{c.contributor}</span>
                            <span className="text-[10px] px-2 py-0.5 rounded font-mono bg-surface-tertiary text-foreground-muted border border-border">
                              {c.source}
                            </span>
                            {c.correlation_group && (
                              <span className="text-[10px] px-1.5 py-0.2 rounded font-mono bg-blue-500/10 text-blue-400">
                                {c.correlation_group}
                              </span>
                            )}
                          </div>
                          <p className="text-xs text-foreground-muted font-sans leading-snug">{c.reason}</p>
                        </div>
                        <div className="flex items-center space-x-3 shrink-0 self-end sm:self-center">
                          <div className="text-right">
                            <span className="text-xs font-mono font-bold text-amber-400">
                              {c.relative_contribution > 0 ? `+${c.relative_contribution}` : c.relative_contribution} pts
                            </span>
                            <div className="text-[10px] font-mono text-foreground-muted">{c.confidence}</div>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* 2. Counter-Evidence (Disagreements & Mitigating Signals) */}
              <div className="border border-border rounded-xl bg-surface overflow-hidden">
                <button
                  type="button"
                  onClick={() => toggleSection('counterEvidence')}
                  className="w-full p-3.5 bg-surface-secondary/30 flex items-center justify-between text-left hover:bg-surface-secondary/50 transition-colors"
                >
                  <div className="flex items-center space-x-2">
                    <ShieldCheck className="w-4 h-4 text-emerald-400" />
                    <span className="text-xs font-mono font-semibold uppercase tracking-wider text-foreground">
                      Counter-Evidence & Mitigating Signals ({explanation.counter_evidence.length})
                    </span>
                  </div>
                  {expandedSections.counterEvidence ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                </button>

                {expandedSections.counterEvidence && (
                  <div className="p-4 space-y-3">
                    {explanation.counter_evidence.length === 0 ? (
                      <p className="text-xs font-mono text-foreground-muted">No mitigating counter-evidence detected for this event.</p>
                    ) : (
                      explanation.counter_evidence.map((ce, idx) => (
                        <div key={idx} className="p-3 rounded-lg border border-emerald-500/20 bg-emerald-500/5 flex flex-col sm:flex-row justify-between gap-2">
                          <div className="space-y-1">
                            <div className="flex items-center space-x-2">
                              <span className="text-xs font-semibold text-emerald-400 font-sans">{ce.claim}</span>
                              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-surface border border-emerald-500/30 text-emerald-300">
                                {ce.source}
                              </span>
                            </div>
                            <p className="text-xs text-foreground-muted">{ce.interpretation}</p>
                          </div>
                          <span className="text-[11px] font-mono font-bold text-emerald-400 shrink-0">
                            Strength: {ce.mitigation_strength}
                          </span>
                        </div>
                      ))
                    )}
                  </div>
                )}
              </div>

              {/* 3. Contradictions Record */}
              <div className="border border-border rounded-xl bg-surface overflow-hidden">
                <button
                  type="button"
                  onClick={() => toggleSection('contradictions')}
                  className="w-full p-3.5 bg-surface-secondary/30 flex items-center justify-between text-left hover:bg-surface-secondary/50 transition-colors"
                >
                  <div className="flex items-center space-x-2">
                    <AlertTriangle className="w-4 h-4 text-amber-400" />
                    <span className="text-xs font-mono font-semibold uppercase tracking-wider text-foreground">
                      Signal Contradictions & Disagreements ({explanation.contradictions.length})
                    </span>
                  </div>
                  {expandedSections.contradictions ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                </button>

                {expandedSections.contradictions && (
                  <div className="p-4 space-y-3">
                    {explanation.contradictions.length === 0 ? (
                      <p className="text-xs font-mono text-foreground-muted">No unresolved signal contradictions identified.</p>
                    ) : (
                      explanation.contradictions.map((c) => (
                        <div key={c.id} className="p-3.5 rounded-lg border border-amber-500/20 bg-amber-500/5 space-y-2">
                          <div className="flex items-center justify-between">
                            <span className="text-xs font-semibold text-amber-400">{c.claim}</span>
                            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-surface border border-amber-500/30 text-amber-300 font-bold">
                              {c.resolution_status}
                            </span>
                          </div>
                          <div className="text-xs text-foreground-muted font-sans space-y-1">
                            <div><strong className="text-foreground">Conflicting Signal:</strong> {c.conflicting_signal}</div>
                            {c.resolution_notes && (
                              <div><strong className="text-foreground">Resolution Analysis:</strong> {c.resolution_notes}</div>
                            )}
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                )}
              </div>

              {/* 4. Uncertainty, Unknowns & Missing Telemetry */}
              <div className="border border-border rounded-xl bg-surface overflow-hidden">
                <button
                  type="button"
                  onClick={() => toggleSection('uncertainty')}
                  className="w-full p-3.5 bg-surface-secondary/30 flex items-center justify-between text-left hover:bg-surface-secondary/50 transition-colors"
                >
                  <div className="flex items-center space-x-2">
                    <HelpCircle className="w-4 h-4 text-blue-400" />
                    <span className="text-xs font-mono font-semibold uppercase tracking-wider text-foreground">
                      Epistemic Unknowns & Missing Information ({explanation.uncertainty_items.length + explanation.missing_information.length})
                    </span>
                  </div>
                  {expandedSections.uncertainty ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                </button>

                {expandedSections.uncertainty && (
                  <div className="p-4 space-y-4">
                    {/* Unknowns */}
                    {explanation.uncertainty_items.length > 0 && (
                      <div className="space-y-2">
                        <span className="text-[11px] font-mono font-semibold text-foreground-muted uppercase">
                          System Unknowns (What CyberGuard Cannot Assert)
                        </span>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                          {explanation.uncertainty_items.map((u, idx) => (
                            <div key={idx} className="p-3 rounded-lg border border-border bg-surface-secondary/40 space-y-1 text-xs">
                              <div className="font-semibold text-foreground font-sans">{u.unknown}</div>
                              <div className="text-foreground-muted"><strong className="text-foreground">Reason:</strong> {u.reason}</div>
                              <div className="text-blue-400 font-mono text-[11px]"><strong className="text-foreground">Impact:</strong> {u.impact}</div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Missing Information */}
                    {explanation.missing_information.length > 0 && (
                      <div className="space-y-2 pt-2 border-t border-border">
                        <span className="text-[11px] font-mono font-semibold text-foreground-muted uppercase">
                          Missing Telemetry & Data Sources
                        </span>
                        <div className="space-y-2">
                          {explanation.missing_information.map((m, idx) => (
                            <div key={idx} className="p-2.5 rounded-lg border border-border bg-surface text-xs flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                              <div className="space-y-0.5">
                                <span className="font-mono text-primary text-[11px] font-semibold">{m.telemetry_source}</span>
                                <p className="text-foreground-muted">{m.description}</p>
                              </div>
                              <span className="text-[11px] font-mono text-amber-400 shrink-0">Impact: {m.impact}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* -----------------------------------------------------------------
              LEVEL 3 — INVESTIGATOR (Families, Detectors, Models, Rules, MITRE, Attack Path)
              ----------------------------------------------------------------- */}
          {activeLayer === 'INVESTIGATOR' && (
            <div className="space-y-5 animate-in fade-in duration-150">
              {/* Evidence Families */}
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-foreground">
                    Independent vs. Correlated Evidence Families ({explanation.evidence_groups.length})
                  </h3>
                  <span className="text-[11px] font-mono text-foreground-muted">
                    Prevents evidence inflation
                  </span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {explanation.evidence_groups.map((group, idx) => (
                    <div key={idx} className="p-4 rounded-xl border border-border bg-surface-secondary/30 space-y-3">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-mono font-bold text-primary">{group.name}</span>
                        <span
                          className={`text-[10px] font-mono px-2 py-0.5 rounded-full font-bold ${
                            group.is_independent
                              ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                              : 'bg-amber-500/10 text-amber-400 border border-amber-500/30'
                          }`}
                        >
                          {group.is_independent ? 'INDEPENDENT FAMILY' : `CORRELATED (${group.correlation_group})`}
                        </span>
                      </div>
                      <p className="text-xs text-foreground-muted font-sans leading-relaxed">{group.summary}</p>
                      
                      {group.claims.length > 0 && (
                        <div className="pt-2 border-t border-border/60 space-y-1.5">
                          {group.claims.map((cl) => (
                            <button
                              key={cl.id}
                              type="button"
                              onClick={() => setSelectedUnit(cl)}
                              className="w-full text-left p-1.5 rounded hover:bg-surface-secondary text-xs text-foreground font-sans flex items-center justify-between group cursor-pointer"
                            >
                              <span className="truncate pr-2">{cl.claim}</span>
                              <ChevronRight className="w-3.5 h-3.5 text-primary shrink-0 group-hover:translate-x-0.5 transition-transform" />
                            </button>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>

              {/* MITRE ATT&CK Mappings */}
              {explanation.mitre_explanations.length > 0 && (
                <div className="border border-border rounded-xl bg-surface overflow-hidden">
                  <div className="p-3.5 bg-surface-secondary/40 border-b border-border flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <Hash className="w-4 h-4 text-primary" />
                      <span className="text-xs font-mono font-semibold uppercase tracking-wider text-foreground">
                        MITRE ATT&CK Technique Grounding ({explanation.mitre_explanations.length})
                      </span>
                    </div>
                    <span className="text-[11px] font-mono text-emerald-400">Strictly Evidence-Backed</span>
                  </div>
                  <div className="divide-y divide-border">
                    {explanation.mitre_explanations.map((m, idx) => (
                      <div key={idx} className="p-3.5 space-y-1 text-xs">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center space-x-2">
                            <span className="font-mono font-bold text-primary">{m.technique_id}</span>
                            <span className="text-foreground font-semibold font-sans">{m.technique_name}</span>
                            <span className="text-[10px] font-mono px-2 py-0.2 rounded bg-surface-secondary text-foreground-muted">
                              {m.tactic}
                            </span>
                          </div>
                          <span className="text-[10px] font-mono font-bold text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
                            {m.mapping_status}
                          </span>
                        </div>
                        <p className="text-foreground-muted font-sans pt-0.5"><strong className="text-foreground">Why mapped:</strong> {m.why_mapped}</p>
                        <div className="text-[11px] font-mono text-foreground-muted pt-1 flex items-center space-x-2">
                          <span>Evidence: {m.evidence_refs.join(', ') || 'Observed telemetry'}</span>
                          <span>|</span>
                          <span>Method: {m.mapping_method}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Attack Path Reconstruction & Continuity */}
              {explanation.attack_path_explanation && (
                <div className="border border-border rounded-xl bg-surface overflow-hidden">
                  <div className="p-3.5 bg-surface-secondary/40 border-b border-border flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <GitBranch className="w-4 h-4 text-primary" />
                      <span className="text-xs font-mono font-semibold uppercase tracking-wider text-foreground">
                        Attack Path Reconstruction & Transition Continuity
                      </span>
                    </div>
                    <span className="text-[10px] font-mono font-bold text-blue-400 bg-blue-500/10 px-2 py-0.5 rounded border border-blue-500/20">
                      Continuity: {explanation.attack_path_explanation.evidence_continuity}
                    </span>
                  </div>
                  <div className="p-4 space-y-3">
                    <div className="flex items-center space-x-2 overflow-x-auto pb-2">
                      {explanation.attack_path_explanation.stage_sequence.map((stg, idx) => (
                        <React.Fragment key={idx}>
                          <div className="p-2.5 rounded-lg border border-border bg-surface-secondary/40 shrink-0 min-w-32 text-center">
                            <span className="text-[10px] font-mono text-primary font-bold">Step {stg.stage_order || idx + 1}</span>
                            <div className="text-xs font-semibold text-foreground font-sans mt-0.5">{stg.stage_name}</div>
                            <span className="text-[9px] font-mono text-foreground-muted">{stg.tactic || 'ATTACK'}</span>
                          </div>
                          {idx < explanation.attack_path_explanation.stage_sequence.length - 1 && (
                            <ChevronRight className="w-4 h-4 text-foreground-muted shrink-0" />
                          )}
                        </React.Fragment>
                      ))}
                    </div>

                    {explanation.attack_path_explanation.bottleneck_summary && (
                      <p className="text-xs text-foreground-muted font-sans border-t border-border pt-2">
                        <strong className="text-foreground">Path Insight:</strong> {explanation.attack_path_explanation.bottleneck_summary}
                      </p>
                    )}
                  </div>
                </div>
              )}

              {/* Contributing Detectors & Rules */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* Detectors */}
                <div className="border border-border rounded-xl bg-surface overflow-hidden">
                  <div className="p-3 bg-surface-secondary/40 border-b border-border flex items-center space-x-2">
                    <Cpu className="w-4 h-4 text-primary" />
                    <span className="text-xs font-mono font-semibold uppercase text-foreground">
                      Detector Systems ({explanation.detector_contributions.length})
                    </span>
                  </div>
                  <div className="divide-y divide-border max-h-56 overflow-y-auto">
                    {explanation.detector_contributions.map((d, idx) => (
                      <div key={idx} className="p-3 text-xs space-y-1">
                        <div className="flex items-center justify-between">
                          <span className="font-semibold text-foreground">{d.detector_name}</span>
                          <span className="font-mono text-[10px] text-foreground-muted">v{d.detector_version}</span>
                        </div>
                        <p className="text-foreground-muted font-sans">{d.finding}</p>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Rules & Models */}
                <div className="border border-border rounded-xl bg-surface overflow-hidden">
                  <div className="p-3 bg-surface-secondary/40 border-b border-border flex items-center space-x-2">
                    <Lock className="w-4 h-4 text-primary" />
                    <span className="text-xs font-mono font-semibold uppercase text-foreground">
                      Matched Rules & ML Models ({explanation.rule_contributions.length + explanation.model_contributions.length})
                    </span>
                  </div>
                  <div className="divide-y divide-border max-h-56 overflow-y-auto">
                    {explanation.rule_contributions.map((r, idx) => (
                      <div key={idx} className="p-3 text-xs space-y-1">
                        <div className="flex items-center justify-between">
                          <span className="font-mono font-bold text-primary">{r.rule_id}</span>
                          <span className="font-mono text-[10px] text-emerald-400">{r.rule_type}</span>
                        </div>
                        <p className="text-foreground-muted font-sans">{r.rule_name}</p>
                      </div>
                    ))}
                    {explanation.model_contributions.map((m, idx) => (
                      <div key={idx} className="p-3 text-xs space-y-1">
                        <div className="flex items-center justify-between">
                          <span className="font-mono font-bold text-foreground">{m.model_name}</span>
                          <span className="font-mono text-[10px] text-blue-400">Conf: {m.confidence_label}</span>
                        </div>
                        <p className="text-foreground-muted font-sans">Output: {m.output_label}</p>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* -----------------------------------------------------------------
              LEVEL 4 — FORENSIC (Evidence chain, graph nodes, technical provenance, caveats)
              ----------------------------------------------------------------- */}
          {activeLayer === 'FORENSIC' && (
            <div className="space-y-5 animate-in fade-in duration-150">
              {/* Evidence Graph Summary */}
              <div className="p-4 rounded-xl border border-border bg-surface-secondary/30 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <Layers className="w-4 h-4 text-primary" />
                    <span className="text-xs font-mono font-semibold uppercase tracking-wider text-foreground">
                      Traceable Evidence Graph Topology
                    </span>
                  </div>
                  <span className="text-[11px] font-mono text-foreground-muted">
                    {explanation.evidence_graph.nodes.length} Nodes · {explanation.evidence_graph.edges.length} Directed Links
                  </span>
                </div>
                
                <div className="flex flex-wrap items-center gap-2 pt-2 border-t border-border">
                  {explanation.evidence_graph.nodes.map((node) => (
                    <div
                      key={node.id}
                      className="px-2.5 py-1.5 rounded-lg border border-border bg-surface font-mono text-xs flex items-center space-x-2"
                    >
                      <span className={`w-2 h-2 rounded-full ${
                        node.node_type === 'CONCLUSION' ? 'bg-rose-400' :
                        node.node_type === 'FINDING' ? 'bg-amber-400' :
                        node.node_type === 'EVIDENCE' ? 'bg-primary' : 'bg-blue-400'
                      }`} />
                      <span className="text-foreground-muted text-[10px]">{node.node_type}:</span>
                      <span className="text-foreground font-semibold">{node.label}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Complete Traceable Claims List */}
              <div className="border border-border rounded-xl bg-surface overflow-hidden">
                <div className="p-3.5 bg-surface-secondary/40 border-b border-border flex items-center justify-between">
                  <span className="text-xs font-mono font-semibold uppercase tracking-wider text-foreground">
                    Complete Forensic Claims Registry ({explanation.explanation_units.length})
                  </span>
                  <span className="text-[11px] font-mono text-foreground-muted">Strict Grounding</span>
                </div>
                <div className="divide-y divide-border">
                  {explanation.explanation_units.map((unit) => (
                    <div
                      key={unit.id}
                      onClick={() => setSelectedUnit(unit)}
                      className="p-3.5 hover:bg-surface-secondary/30 transition-colors cursor-pointer flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs"
                    >
                      <div className="space-y-1">
                        <div className="flex items-center space-x-2">
                          <span className="font-mono font-bold text-primary">{unit.id}</span>
                          <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-surface border border-border text-foreground-muted">
                            {unit.claim_type}
                          </span>
                          <span className="font-semibold text-foreground font-sans">{unit.claim}</span>
                        </div>
                        <div className="text-[11px] font-mono text-foreground-muted flex items-center space-x-2">
                          <span>Evidence: {unit.evidence_refs.join(', ') || 'N/A'}</span>
                          <span>|</span>
                          <span>Source: {unit.source_refs.join(', ') || 'System'}</span>
                        </div>
                      </div>
                      <div className="flex items-center space-x-3 shrink-0 self-end sm:self-center">
                        <span className="font-mono text-[10px] font-bold text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
                          {unit.support_level}
                        </span>
                        <ChevronRight className="w-4 h-4 text-primary" />
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Technical Limitations & Caveats */}
              {explanation.limitations.length > 0 && (
                <div className="p-4 rounded-xl border border-border bg-surface-secondary/20 space-y-2">
                  <div className="flex items-center space-x-2 text-foreground-muted">
                    <AlertOctagon className="w-4 h-4" />
                    <span className="text-xs font-mono font-semibold uppercase tracking-wider text-foreground">
                      Forensic Defensibility Limitations ({explanation.limitations.length})
                    </span>
                  </div>
                  <ul className="space-y-1 text-xs text-foreground-muted font-sans list-disc list-inside">
                    {explanation.limitations.map((lim, idx) => (
                      <li key={idx}>{lim}</li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Raw Provenance Details */}
              <div className="p-4 rounded-xl border border-border bg-surface space-y-2">
                <span className="text-xs font-mono font-semibold uppercase tracking-wider text-foreground-muted">
                  Technical Provenance Snapshot
                </span>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs font-mono">
                  <div className="p-2 rounded bg-surface-secondary border border-border">
                    <div className="text-[10px] text-foreground-muted">SCOPE ID</div>
                    <div className="text-foreground truncate">{explanation.scope_id}</div>
                  </div>
                  <div className="p-2 rounded bg-surface-secondary border border-border">
                    <div className="text-[10px] text-foreground-muted">VERSION</div>
                    <div className="text-foreground">v{explanation.explanation_version}</div>
                  </div>
                  <div className="p-2 rounded bg-surface-secondary border border-border">
                    <div className="text-[10px] text-foreground-muted">VALIDATION</div>
                    <div className="text-emerald-400">{explanation.validation_status}</div>
                  </div>
                  <div className="p-2 rounded bg-surface-secondary border border-border">
                    <div className="text-[10px] text-foreground-muted">GENERATED AT</div>
                    <div className="text-foreground truncate">{new Date(explanation.created_at).toLocaleTimeString()}</div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ---------------------------------------------------------------------
          MODALS & SLIDE-OVERS
          --------------------------------------------------------------------- */}
      {/* Evidence Drawer */}
      <EvidenceDrawer unit={selectedUnit} onClose={() => setSelectedUnit(null)} />

      {/* Analyst Feedback Modal */}
      {showFeedbackModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4 animate-in fade-in">
          <div className="w-full max-w-md bg-surface border border-border rounded-xl shadow-2xl p-5 space-y-4 animate-in zoom-in-95">
            <div className="flex items-center justify-between border-b border-border pb-3">
              <div className="flex items-center space-x-2">
                <MessageSquare className="w-5 h-5 text-amber-400" />
                <h3 className="text-sm font-semibold text-foreground font-sans">Record Analyst Feedback</h3>
              </div>
              <button
                type="button"
                onClick={() => setShowFeedbackModal(false)}
                className="text-foreground-muted hover:text-foreground text-sm"
              >
                ✕
              </button>
            </div>

            <div className="space-y-3 text-xs font-sans">
              <p className="text-foreground-muted">
                Feedback preserves analyst dispute or confirmation alongside the historical explanation without silently modifying evidence.
              </p>

              <div className="space-y-1">
                <label className="font-mono text-foreground font-semibold">Feedback Disposition</label>
                <select
                  value={feedbackType}
                  onChange={(e) => setFeedbackType(e.target.value)}
                  className="w-full p-2 rounded-lg bg-surface-secondary border border-border text-foreground font-mono"
                >
                  <option value="ANALYST_CONFIRMED">ANALYST_CONFIRMED (Agree with assessment)</option>
                  <option value="ANALYST_DISMISSED">ANALYST_DISMISSED (False positive / benign context)</option>
                  <option value="ANALYST_CORRECTED">ANALYST_CORRECTED (Factual correction required)</option>
                  <option value="ANALYST_COMMENT">ANALYST_COMMENT (Investigative note)</option>
                </select>
              </div>

              <div className="space-y-1">
                <label className="font-mono text-foreground font-semibold">Investigative Justification / Notes</label>
                <textarea
                  rows={4}
                  value={feedbackNotes}
                  onChange={(e) => setFeedbackNotes(e.target.value)}
                  placeholder="e.g., Domain is a newly approved internal SSO mirror; verified with IT ops."
                  className="w-full p-2 rounded-lg bg-surface-secondary border border-border text-foreground font-sans placeholder:text-foreground-muted/60"
                />
              </div>
            </div>

            <div className="flex items-center justify-end space-x-2 pt-2 border-t border-border">
              <button
                type="button"
                onClick={() => setShowFeedbackModal(false)}
                className="px-3 py-1.5 rounded-lg border border-border text-xs font-mono text-foreground hover:bg-surface-secondary"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleSubmitFeedback}
                disabled={feedbackSubmitting || !feedbackNotes.trim()}
                className="px-3 py-1.5 rounded-lg bg-primary hover:bg-primary-hover text-primary-foreground text-xs font-mono font-semibold disabled:opacity-50"
              >
                {feedbackSubmitting ? 'Recording...' : 'Submit Feedback'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

const AlertCircleIcon: React.FC<{ className?: string }> = ({ className }) => (
  <svg
    className={className}
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="2"
    strokeLinecap="round"
    strokeLinejoin="round"
  >
    <circle cx="12" cy="12" r="10" />
    <line x1="12" y1="8" x2="12" y2="12" />
    <line x1="12" y1="16" x2="12.01" y2="16" />
  </svg>
);

export default ExplainableAIPanel;
