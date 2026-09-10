import React, { useState, useEffect } from 'react';
import type { EmailAnalysis } from '../../types/forensic';
import { MetadataRow } from './MetadataRow';
import { AuthenticationSection } from './AuthenticationSection';
import { TransmissionPathSection } from './TransmissionPathSection';
import { IPIntelligenceSection } from './IPIntelligenceSection';
import { GlobalThreatScoreSection } from './GlobalThreatScoreSection';
import { AIAnalystSection } from './AIAnalystSection';
import { InfrastructureAttributionSection } from './InfrastructureAttributionSection';
import { EvidenceIntegritySection } from './EvidenceIntegritySection';
import { RelatedInvestigationsCard } from '../correlation/RelatedInvestigationsCard';
import type { CampaignCorrelationResponse } from '../../types/correlation';
import { resolveAttribution } from '../../utils/indicatorHelper';
import { resolveConfidenceConclusions } from '../../utils/confidenceResolver';
import { ConfidenceBadge } from '../common/ConfidenceBadge';
import { EvidenceConfidencePanel } from './EvidenceConfidencePanel';
import { User, Info, Layers, Activity, ShieldCheck, AlertTriangle, CheckCircle2, HelpCircle } from 'lucide-react';

interface OverviewTabProps {
  email: EmailAnalysis;
  onFocusGraphNode?: (nodeId: string) => void;
}

export const OverviewTab: React.FC<OverviewTabProps> = ({ email, onFocusGraphNode }) => {
  const [correlations, setCorrelations] = useState<CampaignCorrelationResponse | null>(null);
  const [loadingCorrelations, setLoadingCorrelations] = useState<boolean>(false);
  const [isConfidencePanelOpen, setIsConfidencePanelOpen] = useState<boolean>(false);

  const conclusions =
    email.forensic_conclusions && email.forensic_conclusions.length > 0
      ? email.forensic_conclusions
      : resolveConfidenceConclusions(email);

  const emailKey = email?.id || email?.evidence_id || email?.email_sha256;

  useEffect(() => {
    if (!emailKey || !email) return;
    setLoadingCorrelations(true);
    fetch('http://localhost:8000/api/correlation/email?min_score=0.15', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(email)
    })
      .then(res => (res.ok ? res.json() : null))
      .then(data => {
        if (data) setCorrelations(data);
      })
      .catch(() => {})
      .finally(() => setLoadingCorrelations(false));
  }, [emailKey]);

  const receivedHopsCount = email.received?.length || 0;
  const urlsCount = email.urls?.length || 0;
  const attachmentsCount = email.attachments?.length || email.indicators?.attachments?.length || 0;

  const ipsCount = email.ips?.length || 0;
  const domainsCount = email.domains?.length || 0;
  const emailsCount = email.emails?.length || 0;

  // Check if any conclusion has conflicting evidence
  const totalConflicts = conclusions.reduce(
    (acc, curr) => acc + (curr.conflicting_evidence?.length || 0),
    0
  );

  return (
    <div className="space-y-6">
      {/* Evidence Confidence Engine Summary Banner */}
      <div className="rounded-card border border-border bg-surface p-5 shadow-xs space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-border">
          <div className="flex items-center space-x-2.5">
            <div className="p-2 rounded-lg bg-primary/10 border border-primary/20 text-primary">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h3 className="text-sm font-bold font-mono text-foreground uppercase tracking-wider">
                  Evidence Confidence Engine
                </h3>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-surface-secondary border border-border text-foreground-muted">
                  v1.0.0 Centralized
                </span>
              </div>
              <p className="text-xs text-foreground-muted mt-0.5">
                Multi-dimensional quality scoring, anti-double-counting, and explicit contradiction detection
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-2">
            {totalConflicts > 0 ? (
              <span className="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-mono bg-amber-500/15 text-amber-400 border border-amber-500/30 gap-1.5">
                <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                <span>{totalConflicts} Contradiction{totalConflicts !== 1 ? 's' : ''} Surfaced</span>
              </span>
            ) : (
              <span className="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-mono bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />
                <span>Signals Aligned</span>
              </span>
            )}
            <button
              onClick={() => setIsConfidencePanelOpen(true)}
              className="px-3 py-1.5 rounded-lg text-xs font-medium bg-primary/10 hover:bg-primary/20 text-primary border border-primary/30 transition-colors flex items-center space-x-1.5"
            >
              <HelpCircle className="w-3.5 h-3.5" />
              <span>Inspect All Conclusions</span>
            </button>
          </div>
        </div>

        {/* Conclusion Badges Row */}
        <div className="space-y-1.5">
          <div className="text-[10px] font-mono text-foreground-muted uppercase tracking-wider">
            Active Forensic Conclusions ({conclusions.length}):
          </div>
          <div className="flex flex-wrap gap-2">
            {conclusions.map((c) => (
              <ConfidenceBadge
                key={c.conclusion_id}
                conclusion={c}
                allConclusions={conclusions}
                size="sm"
              />
            ))}
          </div>
        </div>
      </div>

      {/* Section 10: Global Threat Scoring Engine */}
      <GlobalThreatScoreSection
        threatScore={email.threat_score}
        mlAssessment={email.ml_assessment}
        mlProbability={email.ml_phishing_probability}
        conclusions={conclusions}
      />

      {/* Section 12: AI Analyst Assistant Assessment */}
      <AIAnalystSection
        aiAnalyst={email.ai_analyst}
        conclusions={conclusions}
      />

      {/* Section 21: Probabilistic Threat Attribution Engine */}
      <InfrastructureAttributionSection
        attribution={email.attribution || resolveAttribution(email)}
        conclusions={conclusions}
        onFocusGraphNode={onFocusGraphNode}
      />

      {/* Section 15: Campaign Correlation & Related Investigations */}
      <RelatedInvestigationsCard
        relatedCases={correlations?.related_cases ?? []}
        isLoading={loadingCorrelations}
        emptyMessage="No existing investigation cases currently share technical infrastructure with this email."
      />

      {/* Section 18: Evidence Integrity & Chain-of-Custody Audit Trail */}
      <EvidenceIntegritySection email={email} />

      {/* Authentication & Alignment Section */}
      <AuthenticationSection authentication={email.authentication} />

      {/* Relay Transmission Path Reconstruction Section */}
      <TransmissionPathSection relayAnalysis={email.relay_analysis} />

      {/* Section 6: IP Intelligence & Map Section */}
      <IPIntelligenceSection email={email} />
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Section A: Sender Information */}
        <div className="bg-surface p-5 rounded-card border border-border space-y-4 shadow-xs">
          <div className="flex items-center space-x-2 pb-2 border-b border-border">
            <User className="w-4 h-4 text-primary" />
            <h3 className="text-sm font-mono font-bold text-foreground uppercase tracking-wider">
              A. Sender Information
            </h3>
          </div>
          <div className="space-y-2">
            <MetadataRow label="From" value={email.from} allowCopy />
            <MetadataRow
              label="Reply-To"
              value={email.reply_to || (email.from ? `Not specified in headers (defaults to sender)` : undefined)}
              allowCopy={Boolean(email.reply_to)}
            />
            <MetadataRow label="Return-Path" value={email.return_path} allowCopy />
          </div>
        </div>

        {/* Section B: Message Information */}
        <div className="bg-surface p-5 rounded-card border border-border space-y-4 shadow-xs">
          <div className="flex items-center space-x-2 pb-2 border-b border-border">
            <Info className="w-4 h-4 text-info" />
            <h3 className="text-sm font-mono font-bold text-foreground uppercase tracking-wider">
              B. Message Information
            </h3>
          </div>
          <div className="space-y-2">
            <MetadataRow label="Subject" value={email.subject} isMonospace={false} />
            <MetadataRow label="Date" value={email.date} />
            <MetadataRow label="Message-ID" value={email.message_id} allowCopy />
            <MetadataRow label="To" value={email.to} />
            <MetadataRow label="Cc" value={email.cc} />
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Section C: Email Structure Summary */}
        <div className="bg-surface p-5 rounded-card border border-border space-y-4 shadow-xs">
          <div className="flex items-center space-x-2 pb-2 border-b border-border">
            <Layers className="w-4 h-4 text-primary" />
            <h3 className="text-sm font-mono font-bold text-foreground uppercase tracking-wider">
              C. Email Structure
            </h3>
          </div>
          <div className="grid grid-cols-3 gap-3 pt-1">
            <div className="p-3 bg-surface-secondary/60 rounded-control border border-border text-center">
              <span className="text-2xl font-bold font-mono text-primary">{receivedHopsCount}</span>
              <p className="text-[11px] font-mono text-foreground-muted mt-1 uppercase tracking-wider">
                Received Hops
              </p>
            </div>

            <div className="p-3 bg-surface-secondary/60 rounded-control border border-border text-center">
              <span className="text-2xl font-bold font-mono text-info">{urlsCount}</span>
              <p className="text-[11px] font-mono text-foreground-muted mt-1 uppercase tracking-wider">
                URLs Detected
              </p>
            </div>

            <div className="p-3 bg-surface-secondary/60 rounded-control border border-border text-center">
              <span className="text-2xl font-bold font-mono text-success">{attachmentsCount}</span>
              <p className="text-[11px] font-mono text-foreground-muted mt-1 uppercase tracking-wider">
                Attachments
              </p>
            </div>
          </div>
        </div>

        {/* Section D: Quick Indicator Summary */}
        <div className="bg-surface p-5 rounded-card border border-border space-y-4 shadow-xs">
          <div className="flex items-center space-x-2 pb-2 border-b border-border">
            <Activity className="w-4 h-4 text-primary" />
            <h3 className="text-sm font-mono font-bold text-foreground uppercase tracking-wider">
              D. Quick Indicator Summary
            </h3>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-1">
            <div className="p-3 bg-surface-secondary/60 rounded-control border border-border text-center">
              <span className="text-xl font-bold font-mono text-foreground">{ipsCount}</span>
              <p className="text-[10px] font-mono text-foreground-muted mt-1 uppercase tracking-wider">IPs</p>
            </div>

            <div className="p-3 bg-surface-secondary/60 rounded-control border border-border text-center">
              <span className="text-xl font-bold font-mono text-foreground">{domainsCount}</span>
              <p className="text-[10px] font-mono text-foreground-muted mt-1 uppercase tracking-wider">Domains</p>
            </div>

            <div className="p-3 bg-surface-secondary/60 rounded-control border border-border text-center">
              <span className="text-xl font-bold font-mono text-foreground">{urlsCount}</span>
              <p className="text-[10px] font-mono text-foreground-muted mt-1 uppercase tracking-wider">URLs</p>
            </div>

            <div className="p-3 bg-surface-secondary/60 rounded-control border border-border text-center">
              <span className="text-xl font-bold font-mono text-foreground">{emailsCount}</span>
              <p className="text-[10px] font-mono text-foreground-muted mt-1 uppercase tracking-wider">Emails</p>
            </div>
          </div>
        </div>
      </div>

      {/* Evidence Confidence Modal Panel */}
      <EvidenceConfidencePanel
        isOpen={isConfidencePanelOpen}
        onClose={() => setIsConfidencePanelOpen(false)}
        conclusions={conclusions}
      />
    </div>
  );
};
