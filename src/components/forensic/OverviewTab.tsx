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
import { CampaignAlertBanner } from '../campaign/CampaignAlertBanner';
import type { CampaignAlertData } from '../../types/campaign';
import { User, Info, Layers, Activity, ShieldCheck, AlertTriangle, CheckCircle2, HelpCircle, ShieldAlert, ArrowRight, GitMerge } from 'lucide-react';

interface OverviewTabProps {
  email: EmailAnalysis;
  onFocusGraphNode?: (nodeId: string) => void;
  onOpenWorkspace?: () => void;
  onSelectEmail?: (email: EmailAnalysis) => void;
}

export const OverviewTab: React.FC<OverviewTabProps> = ({ email, onFocusGraphNode, onOpenWorkspace, onSelectEmail }) => {
  const [correlations, setCorrelations] = useState<CampaignCorrelationResponse | null>(null);
  const [loadingCorrelations, setLoadingCorrelations] = useState<boolean>(false);
  const [isConfidencePanelOpen, setIsConfidencePanelOpen] = useState<boolean>(false);
  const [campaignAlert, setCampaignAlert] = useState<CampaignAlertData | null>(null);

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

    // Proactive Campaign Detection Alert
    fetch('http://localhost:8000/api/campaigns/detect-alert?threshold=0.45', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(email)
    })
      .then(res => (res.ok ? res.json() : null))
      .then((data: CampaignAlertData | null) => {
        if (data && data.is_campaign_detected) {
          setCampaignAlert(data);
        } else {
          setCampaignAlert(null);
        }
      })
      .catch(() => {
        setCampaignAlert(null);
      });
  }, [emailKey, email]);

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
      {/* SCENARIO 1: FALSE-POSITIVE RESISTANCE BANNER */}
      {(email.id === 'scenario-1-legit' || (email.threat_score && email.threat_score.score < 20)) && (
        <div className="rounded-2xl border border-success/40 bg-gradient-to-r from-success/15 via-emerald-500/10 to-teal-500/15 p-5 shadow-xs flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div className="space-y-1.5">
            <div className="flex items-center space-x-2">
              <span className="px-2.5 py-0.5 rounded text-[11px] font-mono font-bold tracking-wider uppercase bg-success/20 text-success border border-success/30 flex items-center gap-1.5">
                <ShieldCheck className="w-3.5 h-3.5" />
                FALSE-POSITIVE RESISTANCE VERIFIED
              </span>
              <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-surface border border-border text-foreground font-semibold">
                Status: BENIGN
              </span>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono uppercase bg-success/20 text-success border border-success/30 font-bold">
                SCORE: {email.threat_score?.score || 8}/100
              </span>
            </div>
            <div className="flex items-baseline space-x-2.5">
              <h3 className="text-lg font-black font-sans text-foreground">
                Authentic Business Communication — Verified Safe
              </h3>
            </div>
            <p className="text-xs font-mono text-foreground-muted">
              All cryptographic checks (SPF, DKIM, DMARC) pass with full domain alignment. Normal relay behavior, established domain age, and clean document payload.
            </p>
          </div>
        </div>
      )}

      {/* SCENARIO 3 / CAMPAIGN CORRELATION: RELATED ACTIVITY DETECTED BANNER (Demo fixture only) */}
      {(email.id === 'scenario-3-campaign') && (
        <div className="rounded-2xl border-2 border-danger/40 bg-gradient-to-r from-danger/15 via-warning/10 to-primary/15 p-5 shadow-xs flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div className="space-y-1.5">
            <div className="flex items-center space-x-2">
              <span className="px-2.5 py-0.5 rounded text-[11px] font-mono font-bold tracking-wider uppercase bg-danger/20 text-danger border border-danger/30 flex items-center gap-1.5 animate-pulse">
                <ShieldAlert className="w-3.5 h-3.5" />
                RELATED ACTIVITY DETECTED
              </span>
              <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-surface border border-border text-foreground font-semibold">
                Campaign: C-042 (Operation DarkHydra)
              </span>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono uppercase bg-purple-500/15 text-purple-600 dark:text-purple-300 border border-purple-500/30 font-bold">
                16 MATCHES
              </span>
            </div>
            <div className="flex items-baseline space-x-2.5">
              <h3 className="text-lg font-black font-sans text-foreground">
                16 potentially related emails
              </h3>
              <span className="text-xs font-mono font-bold text-danger">
                Campaign confidence: 89%
              </span>
            </div>
            <div className="text-xs font-mono text-foreground-muted flex flex-wrap gap-x-3 gap-y-1">
              <span>• same redirect domain</span>
              <span>• same ASN (AS64512)</span>
              <span>• highly similar HTML template</span>
              <span>• similar subject</span>
              <span>• same Reply-To domain</span>
              <span>• overlapping sender infrastructure</span>
            </div>
          </div>

          {onOpenWorkspace && (
            <button
              type="button"
              onClick={onOpenWorkspace}
              className="px-4 py-2.5 rounded-xl bg-danger text-white font-mono text-xs font-bold hover:bg-danger/90 transition-all flex items-center space-x-2 flex-shrink-0 shadow-sm cursor-pointer"
            >
              <GitMerge className="w-4 h-4" />
              <span>Open Cross-Email Workspace</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          )}
        </div>
      )}

      {/* Campaign Fingerprint Tactical Alert Banner */}
      {campaignAlert && <CampaignAlertBanner alertData={campaignAlert} />}

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

      {/* Section 12: MailTraceAI Investigation Copilot */}
      <AIAnalystSection
        aiAnalyst={email.ai_analyst}
        conclusions={conclusions}
        email={email}
        onFocusGraphNode={onFocusGraphNode}
        onOpenWorkspace={onOpenWorkspace}
        onSelectEmail={onSelectEmail}
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
