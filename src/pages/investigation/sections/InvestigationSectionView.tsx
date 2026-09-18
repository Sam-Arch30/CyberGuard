import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import {
  Share2,
  Network,
  GitMerge,
  ShieldCheck,
  Briefcase,
  Sparkles,
  Plus,
  ArrowRight,
  RefreshCw
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
    stepGuidance,
    openCopilotDrawer
  } = useInvestigation();

  const currentSubTab = (subTabs.investigation || 'graph') as InvestigationSubTab;
  const [caseModalOpen, setCaseModalOpen] = useState(false);
  const [campaignAlert, setCampaignAlert] = useState<CampaignAlertData | null>(null);
  const [campaignDetail, setCampaignDetail] = useState<CampaignDetail | null>(null);
  const [allCases, setAllCases] = useState<any[]>([]);
  const [loadingCases, setLoadingCases] = useState<boolean>(false);

  useEffect(() => {
    // Fetch cases to associate with this email
    setLoadingCases(true);
    fetch('http://localhost:8000/api/cases?limit=50')
      .then(res => res.ok ? res.json() : null)
      .then(data => {
        if (data && data.cases) {
          setAllCases(data.cases);
        }
      })
      .catch(() => {})
      .finally(() => setLoadingCases(false));
  }, [email, caseModalOpen]);

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

  useEffect(() => {
    if (currentSubTab === 'copilot') {
      openCopilotDrawer();
      setSubTab('graph');
    }
  }, [currentSubTab, openCopilotDrawer, setSubTab]);

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
                onClick={() => {
                  if (tab.id === 'copilot') {
                    openCopilotDrawer();
                  } else {
                    setSubTab(tab.id);
                  }
                }}
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
                <span>Incident Case Association & Workspace Integration</span>
              </div>
              <button
                type="button"
                onClick={() => setCaseModalOpen(true)}
                className="px-3 py-1.5 rounded-lg bg-primary hover:bg-primary-hover text-primary-foreground font-mono text-xs font-semibold flex items-center space-x-1.5 transition-colors cursor-pointer shadow-xs"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>Link to Incident Case</span>
              </button>
            </div>

            {loadingCases ? (
              <div className="p-8 text-center font-mono text-xs text-foreground-muted">
                <RefreshCw className="w-5 h-5 text-primary animate-spin mx-auto mb-2" />
                <span>Checking incident case associations in persistent database...</span>
              </div>
            ) : allCases.length === 0 ? (
              <div className="p-8 text-center rounded-xl bg-surface-secondary/40 border border-border space-y-3 font-mono text-xs">
                <Briefcase className="w-8 h-8 text-foreground-muted mx-auto" />
                <p className="text-foreground-muted">No investigation cases created yet in the database.</p>
                <button
                  type="button"
                  onClick={() => setCaseModalOpen(true)}
                  className="px-4 py-2 rounded-xl bg-primary text-primary-foreground font-semibold cursor-pointer"
                >
                  Create Case & Link This Email
                </button>
              </div>
            ) : (
              <div className="space-y-4 font-mono text-xs">
                <div className="text-[11px] text-foreground-muted flex items-center justify-between">
                  <span>Active SOC incident cases in database ({allCases.length}):</span>
                  <Link to="/cases" className="text-primary hover:underline font-semibold flex items-center space-x-1">
                    <span>View All Cases</span>
                    <ArrowRight className="w-3 h-3" />
                  </Link>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {allCases.slice(0, 6).map((c: any) => (
                    <div
                      key={c.id}
                      className="p-3.5 rounded-xl bg-surface-secondary/40 border border-border hover:border-primary/40 transition-all flex flex-col justify-between gap-3"
                    >
                      <div className="space-y-1">
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-primary">{c.case_number}</span>
                          <span className={`px-2 py-0.2 rounded text-[10px] uppercase font-bold ${
                            c.severity === 'critical' ? 'bg-danger/10 text-danger border border-danger/30' :
                            c.severity === 'high' ? 'bg-warning/10 text-warning border border-warning/30' :
                            'bg-surface border border-border text-foreground-muted'
                          }`}>
                            {c.severity} · {c.status}
                          </span>
                        </div>
                        <h4 className="font-bold text-foreground text-xs">{c.title}</h4>
                        {c.description && (
                          <p className="text-[11px] text-foreground-muted line-clamp-2">{c.description}</p>
                        )}
                      </div>

                      <div className="flex items-center justify-between pt-2 border-t border-border/50 text-[10px] text-foreground-muted">
                        <span>{c.email_count ?? 0} linked emails</span>
                        <Link
                          to={`/cases/${c.id}`}
                          className="inline-flex items-center space-x-1 text-primary hover:underline font-semibold"
                        >
                          <span>Open Case Workspace</span>
                          <ArrowRight className="w-3 h-3" />
                        </Link>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* AI Investigation Copilot Drawer Launcher */}
        {currentSubTab === 'copilot' && (
          <div className="bg-surface rounded-card border border-border p-6 sm:p-8 space-y-5 text-center max-w-2xl mx-auto my-6">
            <div className="w-12 h-12 rounded-control bg-primary/10 border border-primary/25 text-primary flex items-center justify-center mx-auto">
              <Sparkles className="w-6 h-6" />
            </div>

            <div className="space-y-2">
              <h3 className="text-base font-bold font-sans text-foreground">
                Contextual Investigation AI Copilot
              </h3>
              <p className="text-xs font-mono text-foreground-muted max-w-md mx-auto leading-relaxed">
                The AI assistant operates as a non-intrusive, persistent slide-over drawer accessible across all sections of the workspace.
              </p>
            </div>

            <div className="pt-2 flex flex-col sm:flex-row items-center justify-center gap-3">
              <button
                type="button"
                onClick={() => openCopilotDrawer()}
                className="px-4 py-2 rounded-lg bg-primary hover:bg-primary-hover text-primary-foreground text-xs font-mono font-semibold flex items-center space-x-2 transition-colors cursor-pointer shadow-xs"
              >
                <Sparkles className="w-4 h-4" />
                <span>Open AI Copilot Drawer</span>
              </button>

              <button
                type="button"
                onClick={() => setSubTab('graph')}
                className="px-4 py-2 rounded-lg bg-surface-secondary hover:bg-surface border border-border text-foreground text-xs font-mono transition-colors cursor-pointer"
              >
                <span>Return to Relationship Graph</span>
              </button>
            </div>

            <div className="pt-4 border-t border-border grid grid-cols-1 sm:grid-cols-2 gap-2 text-left text-xs font-mono">
              <div className="p-3 rounded-lg bg-surface-secondary/40 border border-border/60">
                <span className="font-bold text-foreground block mb-1">Persistent Context</span>
                <span className="text-[11px] text-foreground-muted">Always pinned to target {email.evidence_id || email.id} with calibrated confidence tiers.</span>
              </div>
              <div className="p-3 rounded-lg bg-surface-secondary/40 border border-border/60">
                <span className="font-bold text-foreground block mb-1">Contextual Triggers</span>
                <span className="text-[11px] text-foreground-muted">Click "Ask AI about this" on any finding, IOC, IP, domain, or graph node.</span>
              </div>
            </div>
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
