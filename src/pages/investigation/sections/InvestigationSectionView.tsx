import React, { useState, useEffect } from 'react';
import {
  Share2,
  Network,
  GitMerge,
  ShieldCheck,
  Briefcase,
  Sparkles,
  Plus,
  ArrowRight
} from 'lucide-react';
import type { EmailAnalysis } from '../../../types/forensic';
import type { CampaignAlertData, CampaignDetail } from '../../../types/campaign';
import { useInvestigation } from '../../../context/InvestigationContext';
import {
  InvestigationRelationshipSummary,
  ProgressiveInvestigationGraph,
  CampaignCorrelationPanel
} from '../../../components/forensic/investigation';
import { CrossEmailWorkspace } from '../../../components/forensic/CrossEmailWorkspace';
import { EvidenceIntegritySection } from '../../../components/forensic/EvidenceIntegritySection';
import { InvestigationCopilot } from '../../../components/copilot/InvestigationCopilot';
import { AddToCaseModal } from '../../../components/case/AddToCaseModal';
import { CampaignGraphView } from '../../../components/campaign/CampaignGraphView';
import { CampaignTimeline } from '../../../components/campaign/CampaignTimeline';

interface InvestigationSectionViewProps {
  email: EmailAnalysis;
}

type InvestigationSubTab = 'graph' | 'campaigns' | 'cross_email' | 'evidence' | 'cases' | 'copilot';

export const InvestigationSectionView: React.FC<InvestigationSectionViewProps> = ({ email }) => {
  const {
    subTabs,
    setSubTab,
    setSection,
    setActiveEmailId,
    stepGuidance
  } = useInvestigation();

  const currentSubTab = (subTabs.investigation || 'graph') as InvestigationSubTab;
  const [caseModalOpen, setCaseModalOpen] = useState(false);
  const [campaignAlert, setCampaignAlert] = useState<CampaignAlertData | null>(null);
  const [campaignDetail, setCampaignDetail] = useState<CampaignDetail | null>(null);

  useEffect(() => {
    // Check if current email triggers a campaign alert
    fetch('http://localhost:8000/api/campaigns/detect-alert?threshold=0.45', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(email)
    })
      .then(res => (res.ok ? res.json() : null))
      .then((data: CampaignAlertData | null) => {
        if (data && data.is_campaign_detected) {
          setCampaignAlert(data);
        }
      })
      .catch(() => {});

    // Fetch active campaign detail
    fetch('http://localhost:8000/api/campaigns/C-042')
      .then(res => (res.ok ? res.json() : null))
      .then((data: CampaignDetail | null) => {
        if (data) setCampaignDetail(data);
      })
      .catch(() => {});
  }, [email]);

  const subTabItems: { id: InvestigationSubTab; label: string; icon: React.FC<{ className?: string }>; count?: number | string; badgeColor?: string }[] = [
    { id: 'graph', label: 'Relationship Graph', icon: Share2 },
    { id: 'campaigns', label: 'Campaign Correlation', icon: Network, count: 'CLUSTERS' },
    { id: 'cross_email', label: 'Related Emails Workspace', icon: GitMerge, count: 16 },
    { id: 'evidence', label: 'Evidence & Audit Chain', icon: ShieldCheck },
    { id: 'cases', label: 'Case Relationships', icon: Briefcase },
    { id: 'copilot', label: 'Investigation Copilot', icon: Sparkles, count: 'AI', badgeColor: 'text-primary bg-primary/10 border-primary/30' }
  ];

  const handlePivotToSection = (sectionId: string, subTabId?: string) => {
    setSection(sectionId as any);
    if (subTabId) {
      setSubTab(subTabId);
    }
  };

  return (
    <div className="space-y-6">
      {/* 1. CONTEXTUAL SUB-NAVIGATION */}
      <div className="bg-surface rounded-xl border border-border p-1.5 flex flex-wrap items-center justify-between gap-2 shadow-xs">
        <div className="flex flex-wrap items-center gap-1">
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
                {tab.count !== undefined && (
                  <span
                    className={`ml-1 px-1.5 py-0.2 rounded text-[10px] font-mono ${
                      isActive
                        ? 'bg-black/20 text-white'
                        : tab.badgeColor || 'bg-surface-secondary text-foreground-subtle border border-border'
                    }`}
                  >
                    {tab.count}
                  </span>
                )}
              </button>
            );
          })}
        </div>

        <div className="hidden sm:flex items-center space-x-2 text-[11px] font-mono text-foreground-muted pr-2">
          <span>Relationship Investigation Workspace</span>
        </div>
      </div>

      {/* 2. SUB-TAB VIEW CONTAINER */}
      <div>
        {/* Unified Relationship Workspace (Graph + Progressive Controls + Correlation) */}
        {currentSubTab === 'graph' && (
          <div className="space-y-6">
            {/* Top Relationship Summary */}
            <InvestigationRelationshipSummary
              email={email}
              campaignAlert={campaignAlert}
              visibleNodeCount={5}
              totalNodeCount={11}
            />

            {/* Main Progressive Investigation Graph */}
            <div className="bg-surface rounded-xl border border-border p-5 shadow-xs space-y-4">
              <div className="flex items-center justify-between pb-3 border-b border-border">
                <div className="flex items-center space-x-2 text-xs font-mono font-bold uppercase text-foreground">
                  <Share2 className="w-4 h-4 text-primary" />
                  <span>Progressive Entity Relationship Graph</span>
                </div>
                <span className="text-[11px] font-mono text-foreground-muted">
                  Simplified core entities initially · Click controls to progressively expand topology
                </span>
              </div>

              <ProgressiveInvestigationGraph
                email={email}
                campaignData={campaignAlert || campaignDetail}
                onPivotToSection={handlePivotToSection}
                onAddToCase={() => setCaseModalOpen(true)}
              />
            </div>

            {/* Explainable Campaign Correlation Section Below Graph */}
            <div className="bg-surface rounded-xl border border-border p-5 shadow-xs">
              <CampaignCorrelationPanel
                email={email}
                campaignAlert={campaignAlert}
                campaignDetail={campaignDetail}
                onOpenEmail={(targetId) => setActiveEmailId(targetId)}
                onSelectSubTab={(sub) => setSubTab(sub)}
              />
            </div>
          </div>
        )}

        {/* Dedicated Campaign Correlation SubTab */}
        {currentSubTab === 'campaigns' && (
          <div className="bg-surface rounded-xl border border-border p-5 shadow-xs space-y-6">
            <CampaignCorrelationPanel
              email={email}
              campaignAlert={campaignAlert}
              campaignDetail={campaignDetail}
              onOpenEmail={(targetId) => setActiveEmailId(targetId)}
              onSelectSubTab={(sub) => setSubTab(sub)}
            />

            {/* Campaign Multi-Target Cluster Graph & Timeline */}
            {campaignDetail && (
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 pt-4 border-t border-border">
                <div className="space-y-3">
                  <h4 className="text-xs font-mono font-bold text-foreground uppercase">
                    Campaign Multi-Target Cluster Graph ({campaignDetail.campaign_id}):
                  </h4>
                  <div className="h-96 rounded-xl border border-border overflow-hidden bg-surface-secondary">
                    <CampaignGraphView campaign={campaignDetail} />
                  </div>
                </div>

                <div className="space-y-3">
                  <h4 className="text-xs font-mono font-bold text-foreground uppercase">
                    Campaign Dissemination Timeline:
                  </h4>
                  <div className="h-96 rounded-xl border border-border overflow-hidden bg-surface-secondary p-4 overflow-y-auto">
                    <CampaignTimeline events={campaignDetail.timeline || []} />
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Cross-Email Related Emails Workspace */}
        {currentSubTab === 'cross_email' && (
          <div className="bg-surface rounded-xl border border-border p-5 shadow-xs space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-border">
              <div className="flex items-center space-x-2 text-xs font-mono font-bold uppercase text-foreground">
                <GitMerge className="w-4 h-4 text-primary" />
                <span>Cross-Email Investigation Workspace</span>
              </div>
              <span className="text-[11px] font-mono text-foreground-muted">
                Multi-message pivot, overlap analysis & side-by-side comparison
              </span>
            </div>
            <CrossEmailWorkspace
              email={email}
              onOpenEmail={(targetId) => {
                setActiveEmailId(targetId);
              }}
            />
          </div>
        )}

        {/* Evidence & Chain of Custody */}
        {currentSubTab === 'evidence' && (
          <div className="bg-surface rounded-xl border border-border p-5 shadow-xs space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-border">
              <div className="flex items-center space-x-2 text-xs font-mono font-bold uppercase text-foreground">
                <ShieldCheck className="w-4 h-4 text-primary" />
                <span>Evidence Integrity & Forensic Chain of Custody</span>
              </div>
              <span className="text-[11px] font-mono text-foreground-muted">
                Cryptographic SHA-256 proof, tamper verification & timestamped audit log
              </span>
            </div>
            <EvidenceIntegritySection email={email} />
          </div>
        )}

        {/* Case Relationships */}
        {currentSubTab === 'cases' && (
          <div className="bg-surface rounded-xl border border-border p-5 shadow-xs space-y-5">
            <div className="flex items-center justify-between pb-3 border-b border-border">
              <div className="flex items-center space-x-2 text-xs font-mono font-bold uppercase text-foreground">
                <Briefcase className="w-4 h-4 text-primary" />
                <span>Case Relationships & Incident Association</span>
              </div>
              <button
                type="button"
                onClick={() => setCaseModalOpen(true)}
                className="px-3 py-1.5 rounded-lg bg-primary hover:bg-primary-hover text-primary-foreground font-mono text-xs font-semibold flex items-center space-x-1.5 transition-colors cursor-pointer"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>Link to Incident Case</span>
              </button>
            </div>

            {/* Linked Case Information */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="p-4 rounded-xl bg-surface-secondary border border-border space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono font-bold text-foreground uppercase">
                    Primary Associated Case:
                  </span>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-warning/10 text-warning border border-warning/30 font-bold">
                    ACTIVE INVESTIGATION
                  </span>
                </div>
                <div className="space-y-1">
                  <h4 className="text-sm font-bold text-foreground font-sans">
                    CASE-2026-089: Targeted CFO Wire Transfer Phishing Attack
                  </h4>
                  <p className="text-xs font-mono text-foreground-muted">
                    Opened Sep 17, 2026 · Assigned to SOC Incident Responder · Priority High
                  </p>
                </div>
                <div className="pt-2 flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => handlePivotToSection('report')}
                    className="px-3 py-1.5 rounded-lg bg-surface border border-border text-foreground font-mono text-xs hover:bg-surface-secondary transition-colors cursor-pointer"
                  >
                    View Case Dossier
                  </button>
                </div>
              </div>

              <div className="p-4 rounded-xl bg-surface-secondary border border-border space-y-3">
                <span className="text-xs font-mono font-bold text-foreground uppercase block">
                  Connected Threat Incidents:
                </span>
                <div className="space-y-2 text-xs font-mono">
                  <div className="p-2.5 rounded bg-surface border border-border flex items-center justify-between">
                    <div>
                      <span className="font-bold text-foreground block">CASE-2026-042</span>
                      <span className="text-foreground-muted text-[11px]">DarkHydra Executive Impersonation</span>
                    </div>
                    <span className="text-danger font-bold text-[10px]">94% SIMILARITY</span>
                  </div>
                  <div className="p-2.5 rounded bg-surface border border-border flex items-center justify-between">
                    <div>
                      <span className="font-bold text-foreground block">CASE-2026-015</span>
                      <span className="text-foreground-muted text-[11px]">Bulletproof Host Bulletins AS64511</span>
                    </div>
                    <span className="text-warning font-bold text-[10px]">INFRASTRUCTURE OVERLAP</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* AI Investigation Copilot */}
        {currentSubTab === 'copilot' && (
          <div className="bg-surface rounded-xl border border-border p-5 shadow-xs space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-border">
              <div className="flex items-center space-x-2 text-xs font-mono font-bold uppercase text-foreground">
                <Sparkles className="w-4 h-4 text-primary" />
                <span>AI Forensic Copilot Assistant</span>
              </div>
              <span className="text-[11px] font-mono text-foreground-muted">
                Zero data leakage model grounded in current investigation evidence
              </span>
            </div>
            <InvestigationCopilot
              contextId={email.id || email.evidence_id}
              emailPayload={email as any}
            />
          </div>
        )}
      </div>

      {/* 3. NEXT INVESTIGATION STEP CTA */}
      <div className="p-4 rounded-xl bg-surface border border-border flex flex-col sm:flex-row items-center justify-between gap-4 shadow-xs">
        <div className="flex items-center space-x-3">
          <div className="w-8 h-8 rounded-lg bg-primary/10 text-primary flex items-center justify-center font-bold font-mono text-xs border border-primary/20">
            06
          </div>
          <div>
            <h4 className="text-xs font-bold text-foreground font-sans">
              Completed Relationship & Campaign Investigation?
            </h4>
            <p className="text-xs font-mono text-foreground-muted">
              Generate the executive forensic dossier, compile MITRE ATT&CK technique alignments, and export court-admissible PDF reports.
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

      {/* Add To Case Modal */}
      <AddToCaseModal
        isOpen={caseModalOpen}
        onClose={() => setCaseModalOpen(false)}
        email={email}
      />
    </div>
  );
};
