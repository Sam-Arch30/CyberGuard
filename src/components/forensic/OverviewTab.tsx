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
import { User, Info, Layers, Activity } from 'lucide-react';

interface OverviewTabProps {
  email: EmailAnalysis;
  onFocusGraphNode?: (nodeId: string) => void;
}

export const OverviewTab: React.FC<OverviewTabProps> = ({ email, onFocusGraphNode }) => {
  const [correlations, setCorrelations] = useState<CampaignCorrelationResponse | null>(null);
  const [loadingCorrelations, setLoadingCorrelations] = useState<boolean>(false);

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

  return (
    <div className="space-y-6">
      {/* Section 10: Global Threat Scoring Engine */}
      <GlobalThreatScoreSection
        threatScore={email.threat_score}
        mlAssessment={email.ml_assessment}
        mlProbability={email.ml_phishing_probability}
      />

      {/* Section 12: AI Analyst Assistant Assessment */}
      <AIAnalystSection aiAnalyst={email.ai_analyst} />

      {/* Section 21: Probabilistic Threat Attribution Engine */}
      <InfrastructureAttributionSection
        attribution={email.attribution || resolveAttribution(email)}
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
    </div>
  );
};
