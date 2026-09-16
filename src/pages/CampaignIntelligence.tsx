import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  Network,
  Search,
  Server,
  Globe,
  Link as LinkIcon,
  Users,
  Clock,
  Share2,
  FileCode,
  Layers,
  Target,
  Copy,
  Check,
  ArrowUpRight,
  Info,
  FileText,
  Sparkles
} from 'lucide-react';
import type { CampaignClusterItem, CampaignDetail } from '../types/campaign';
import { CampaignTimeline } from '../components/campaign/CampaignTimeline';
import { CampaignGraphView } from '../components/campaign/CampaignGraphView';
import { InvestigationCopilot } from '../components/copilot/InvestigationCopilot';

export const CampaignIntelligence: React.FC = () => {
  const { id: routeCampId } = useParams<{ id: string }>();
  const navigate = useNavigate();

  const [campaigns, setCampaigns] = useState<CampaignClusterItem[]>([]);
  const [selectedCampId, setSelectedCampId] = useState<string>(routeCampId || 'C-042');
  const [campaignDetail, setCampaignDetail] = useState<CampaignDetail | null>(null);
  const [loadingList, setLoadingList] = useState<boolean>(true);
  const [loadingDetail, setLoadingDetail] = useState<boolean>(false);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [activeTab, setActiveTab] = useState<
    'overview' | 'copilot' | 'emails' | 'infrastructure' | 'domains' | 'urls' | 'recipients' | 'timeline' | 'graph' | 'evidence'
  >('overview');
  const [copiedValue, setCopiedValue] = useState<string | null>(null);

  const handleCopy = (val: string, e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(val);
    setCopiedValue(val);
    setTimeout(() => setCopiedValue(null), 2000);
  };

  // Fetch campaign cards list
  useEffect(() => {
    setLoadingList(true);
    fetch('http://localhost:8000/api/campaigns')
      .then(res => (res.ok ? res.json() : []))
      .then((data: CampaignClusterItem[]) => {
        if (data && data.length > 0) {
          setCampaigns(data);
          if (!routeCampId) {
            setSelectedCampId(data[0].campaign_id);
          }
        }
      })
      .catch(() => {})
      .finally(() => setLoadingList(false));
  }, []);

  // Fetch single campaign detail
  useEffect(() => {
    if (!selectedCampId) return;
    setLoadingDetail(true);
    fetch(`http://localhost:8000/api/campaigns/${selectedCampId}`)
      .then(res => (res.ok ? res.json() : null))
      .then((detail: CampaignDetail) => {
        if (detail) {
          setCampaignDetail(detail);
        }
      })
      .catch(() => {})
      .finally(() => setLoadingDetail(false));
  }, [selectedCampId]);

  const filteredCampaigns = campaigns.filter(c => {
    if (!searchQuery.trim()) return true;
    const q = searchQuery.toLowerCase();
    return (
      c.campaign_id.toLowerCase().includes(q) ||
      c.name.toLowerCase().includes(q) ||
      c.dominant_attack_type.toLowerCase().includes(q) ||
      c.targeted_brands.some(b => b.toLowerCase().includes(q))
    );
  });

  const getConfidenceBadge = (conf: number) => {
    if (conf >= 85) {
      return 'bg-danger/15 text-danger border-danger/30';
    } else if (conf >= 65) {
      return 'bg-warning/15 text-warning border-warning/30';
    } else {
      return 'bg-primary/15 text-primary border-primary/30';
    }
  };

  const tabs = [
    { id: 'overview', label: 'Overview', icon: Target },
    { id: 'copilot', label: 'Investigation Copilot', icon: Sparkles },
    { id: 'emails', label: 'Emails', icon: MailIcon, count: campaignDetail?.email_count },
    { id: 'infrastructure', label: 'Infrastructure', icon: Server, count: campaignDetail?.ip_count },
    { id: 'domains', label: 'Domains', icon: Globe, count: campaignDetail?.domain_count },
    { id: 'urls', label: 'URLs', icon: LinkIcon, count: campaignDetail?.url_summary?.normalized_urls?.length },
    { id: 'recipients', label: 'Recipients', icon: Users, count: campaignDetail?.recipient_count },
    { id: 'timeline', label: 'Timeline', icon: Clock, count: campaignDetail?.timeline?.length },
    { id: 'graph', label: 'Graph', icon: Share2 },
    { id: 'evidence', label: 'Evidence', icon: FileCode }
  ];

  function MailIcon(props: any) {
    return (
      <svg {...props} fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
        <rect width="20" height="16" x="2" y="4" rx="2" />
        <path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7" />
      </svg>
    );
  }

  return (
    <div className="space-y-6 pb-16">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-surface p-6 rounded-2xl border border-border shadow-xs">
        <div>
          <div className="flex items-center space-x-2 text-primary font-mono text-xs mb-1 font-semibold uppercase tracking-wider">
            <Network className="w-4 h-4 text-primary" />
            <span>ADVANCED CAMPAIGN FINGERPRINTING ENGINE</span>
          </div>
          <h1 className="text-2xl font-extrabold text-foreground font-sans tracking-tight">
            Campaign Intelligence Workspace
          </h1>
          <p className="text-xs text-foreground-muted font-mono mt-1">
            Correlate unrelated email incidents into multidimensional campaign clusters using infrastructure, domain, URL, template, and content fingerprints.
          </p>
        </div>

        <div className="flex items-center space-x-3 self-start md:self-auto">
          <div className="flex items-center space-x-2 px-3 py-1.5 rounded-lg bg-surface-secondary border border-border text-xs font-mono text-foreground">
            <span className="w-2 h-2 rounded-full bg-success animate-pulse" />
            <span>Clustering Engine: <strong className="text-primary">ACTIVE</strong></span>
          </div>
        </div>
      </div>

      {/* Campaign Cards Section */}
      <div className="space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <h2 className="text-sm font-bold font-mono text-foreground uppercase tracking-wider flex items-center space-x-2">
            <span>Tracked Campaign Clusters</span>
            <span className="px-2 py-0.5 rounded-full text-xs bg-primary/10 border border-primary/20 text-primary">
              {campaigns.length}
            </span>
          </h2>

          <div className="relative w-full sm:w-80">
            <Search className="w-3.5 h-3.5 text-foreground-muted absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
            <input
              type="text"
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              placeholder="Search campaigns, brands, IOCs..."
              className="w-full pl-8 pr-3 py-1.5 bg-surface border border-border rounded-lg text-xs font-mono text-foreground placeholder:text-foreground-muted focus:outline-none focus:border-primary"
            />
          </div>
        </div>

        {loadingList && (
          <div className="text-xs font-mono text-foreground-muted animate-pulse py-1">
            Querying campaign clustering engine...
          </div>
        )}

        {/* Campaign Cards Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-2 gap-4">
          {filteredCampaigns.map(camp => {
            const isSelected = selectedCampId === camp.campaign_id;
            const badgeClass = getConfidenceBadge(camp.overall_confidence);

            return (
              <div
                key={camp.campaign_id}
                onClick={() => {
                  setSelectedCampId(camp.campaign_id);
                  navigate(`/campaigns/${camp.campaign_id}`, { replace: true });
                }}
                className={`p-5 rounded-2xl border text-xs font-mono cursor-pointer transition-all duration-150 space-y-4 relative ${
                  isSelected
                    ? 'bg-surface border-primary ring-2 ring-primary/20 shadow-md'
                    : 'bg-surface hover:bg-surface-secondary/50 border-border hover:border-primary/40'
                }`}
              >
                {/* Card Top Row */}
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <div className="flex items-center space-x-2 mb-1">
                      <span className="font-extrabold text-sm text-primary tracking-wider font-mono">
                        Campaign {camp.campaign_id}
                      </span>
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-surface-secondary border border-border text-foreground-muted">
                        {camp.dominant_attack_type}
                      </span>
                    </div>
                    <h3 className="text-base font-bold text-foreground font-sans leading-tight">
                      {camp.name}
                    </h3>
                  </div>

                  <div className="flex flex-col items-end shrink-0">
                    <span className="text-[10px] uppercase text-foreground-muted">Confidence</span>
                    <span className={`px-2.5 py-1 rounded-full border text-xs font-bold ${badgeClass}`}>
                      {camp.overall_confidence}%
                    </span>
                  </div>
                </div>

                {/* 6 Key Metrics Chips Specified in Goal */}
                <div className="grid grid-cols-3 sm:grid-cols-6 gap-2 pt-1 border-t border-border">
                  <div className="p-2 rounded-lg bg-surface-secondary/70 border border-border text-center">
                    <span className="text-sm font-bold text-primary block">{camp.email_count}</span>
                    <span className="text-[9px] uppercase text-foreground-muted block leading-tight">Related Emails</span>
                  </div>
                  <div className="p-2 rounded-lg bg-surface-secondary/70 border border-border text-center">
                    <span className="text-sm font-bold text-info block">{camp.sender_count}</span>
                    <span className="text-[9px] uppercase text-foreground-muted block leading-tight">Sender Identities</span>
                  </div>
                  <div className="p-2 rounded-lg bg-surface-secondary/70 border border-border text-center">
                    <span className="text-sm font-bold text-purple-400 block">{camp.domain_count}</span>
                    <span className="text-[9px] uppercase text-foreground-muted block leading-tight">Domains</span>
                  </div>
                  <div className="p-2 rounded-lg bg-surface-secondary/70 border border-border text-center">
                    <span className="text-sm font-bold text-amber-400 block">{camp.ip_count}</span>
                    <span className="text-[9px] uppercase text-foreground-muted block leading-tight">IP Addresses</span>
                  </div>
                  <div className="p-2 rounded-lg bg-surface-secondary/70 border border-border text-center">
                    <span className="text-sm font-bold text-blue-400 block">{camp.asn_count}</span>
                    <span className="text-[9px] uppercase text-foreground-muted block leading-tight">ASNs</span>
                  </div>
                  <div className="p-2 rounded-lg bg-surface-secondary/70 border border-border text-center">
                    <span className="text-sm font-bold text-success block">{camp.recipient_count}</span>
                    <span className="text-[9px] uppercase text-foreground-muted block leading-tight">Recipients</span>
                  </div>
                </div>

                {/* First Seen & Last Seen Dates */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between text-[11px] text-foreground-muted pt-2 border-t border-border gap-1">
                  <div>
                    <span>First seen: </span>
                    <strong className="text-foreground">{camp.first_seen}</strong>
                  </div>
                  <div>
                    <span>Last seen: </span>
                    <strong className="text-foreground">{camp.last_seen}</strong>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Selected Campaign Detailed 9-Tab Workspace */}
      {campaignDetail && (
        <div className="bg-surface rounded-2xl border border-border p-6 shadow-xs space-y-6">
          {/* Header of Active Campaign */}
          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-4 border-b border-border">
            <div>
              <div className="flex items-center space-x-2">
                <span className="text-xs font-mono font-extrabold text-primary tracking-wider">
                  ACTIVE INVESTIGATION: {campaignDetail.campaign_id}
                </span>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-danger/10 text-danger border border-danger/30">
                  {campaignDetail.dominant_attack_type}
                </span>
              </div>
              <h2 className="text-xl font-extrabold text-foreground font-sans mt-1">
                {campaignDetail.name}
              </h2>
            </div>

            <div className="flex items-center space-x-3">
              <div className="text-right font-mono">
                <span className="text-[10px] uppercase text-foreground-muted block">Composite Confidence</span>
                <span className="text-base font-extrabold text-warning">
                  {campaignDetail.overall_confidence}% Defensible Match
                </span>
              </div>
            </div>
          </div>

          {loadingDetail && (
            <div className="text-xs font-mono text-primary animate-pulse pb-1">
              Synchronizing cluster forensic telemetry...
            </div>
          )}

          {/* 9 TABS NAVIGATION */}
          <div className="flex overflow-x-auto pb-1 border-b border-border gap-1 scrollbar-none">
            {tabs.map(tab => {
              const Icon = tab.icon;
              const isActive = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  type="button"
                  onClick={() => setActiveTab(tab.id as any)}
                  className={`px-3.5 py-2 rounded-xl text-xs font-mono font-medium transition-all flex items-center space-x-2 cursor-pointer shrink-0 border ${
                    isActive
                      ? 'bg-primary-subtle text-primary border-primary/30 font-bold shadow-xs'
                      : 'text-foreground-muted hover:text-foreground hover:bg-surface-secondary border-transparent'
                  }`}
                >
                  <Icon className="w-3.5 h-3.5" />
                  <span>{tab.label}</span>
                  {tab.count !== undefined && (
                    <span className={`text-[10px] px-1.5 py-0.2 rounded-full ${
                      isActive ? 'bg-primary/20 text-primary font-bold' : 'bg-surface-secondary text-foreground-muted'
                    }`}>
                      {tab.count}
                    </span>
                  )}
                </button>
              );
            })}
          </div>

          {/* TAB: COPILOT */}
          {activeTab === 'copilot' && (
            <div className="space-y-6 animate-in fade-in duration-150">
              <InvestigationCopilot
                mode="campaign"
                contextId={selectedCampId || 'C-042'}
                onCompareEmails={() => setActiveTab('emails')}
                onOpenEvidence={() => setActiveTab('evidence')}
              />
            </div>
          )}

          {/* TAB 1: OVERVIEW */}
          {activeTab === 'overview' && (
            <div className="space-y-6 animate-in fade-in duration-150">
              {/* Category Similarity Grid */}
              <div className="space-y-2">
                <h3 className="text-xs font-mono font-bold uppercase text-foreground-muted tracking-wider">
                  Category Similarity Breakdown
                </h3>
                <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
                  <div className="p-4 rounded-xl bg-surface-secondary/50 border border-border space-y-2">
                    <span className="text-[11px] uppercase text-foreground-muted font-mono flex items-center space-x-1.5">
                      <Server className="w-3.5 h-3.5 text-primary" />
                      <span>Infrastructure</span>
                    </span>
                    <div className="text-2xl font-bold font-mono text-primary">
                      {campaignDetail.category_scores?.infrastructure_similarity || 92}%
                    </div>
                    <div className="w-full bg-surface h-1.5 rounded-full overflow-hidden">
                      <div className="bg-primary h-full" style={{ width: `${campaignDetail.category_scores?.infrastructure_similarity || 92}%` }} />
                    </div>
                  </div>

                  <div className="p-4 rounded-xl bg-surface-secondary/50 border border-border space-y-2">
                    <span className="text-[11px] uppercase text-foreground-muted font-mono flex items-center space-x-1.5">
                      <Globe className="w-3.5 h-3.5 text-info" />
                      <span>Domain</span>
                    </span>
                    <div className="text-2xl font-bold font-mono text-info">
                      {campaignDetail.category_scores?.domain_similarity || 78}%
                    </div>
                    <div className="w-full bg-surface h-1.5 rounded-full overflow-hidden">
                      <div className="bg-info h-full" style={{ width: `${campaignDetail.category_scores?.domain_similarity || 78}%` }} />
                    </div>
                  </div>

                  <div className="p-4 rounded-xl bg-surface-secondary/50 border border-border space-y-2">
                    <span className="text-[11px] uppercase text-foreground-muted font-mono flex items-center space-x-1.5">
                      <LinkIcon className="w-3.5 h-3.5 text-danger" />
                      <span>URL Similarity</span>
                    </span>
                    <div className="text-2xl font-bold font-mono text-danger">
                      {campaignDetail.category_scores?.url_similarity || 96}%
                    </div>
                    <div className="w-full bg-surface h-1.5 rounded-full overflow-hidden">
                      <div className="bg-danger h-full" style={{ width: `${campaignDetail.category_scores?.url_similarity || 96}%` }} />
                    </div>
                  </div>

                  <div className="p-4 rounded-xl bg-surface-secondary/50 border border-border space-y-2">
                    <span className="text-[11px] uppercase text-foreground-muted font-mono flex items-center space-x-1.5">
                      <FileText className="w-3.5 h-3.5 text-warning" />
                      <span>Content Similarity</span>
                    </span>
                    <div className="text-2xl font-bold font-mono text-warning">
                      {campaignDetail.category_scores?.content_similarity || 81}%
                    </div>
                    <div className="w-full bg-surface h-1.5 rounded-full overflow-hidden">
                      <div className="bg-warning h-full" style={{ width: `${campaignDetail.category_scores?.content_similarity || 81}%` }} />
                    </div>
                  </div>

                  <div className="p-4 rounded-xl bg-surface-secondary/50 border border-border space-y-2 col-span-2 sm:col-span-1">
                    <span className="text-[11px] uppercase text-foreground-muted font-mono flex items-center space-x-1.5">
                      <Layers className="w-3.5 h-3.5 text-emerald-400" />
                      <span>Template SimHash</span>
                    </span>
                    <div className="text-2xl font-bold font-mono text-emerald-400">
                      {campaignDetail.category_scores?.template_similarity || 89}%
                    </div>
                    <div className="w-full bg-surface h-1.5 rounded-full overflow-hidden">
                      <div className="bg-emerald-400 h-full" style={{ width: `${campaignDetail.category_scores?.template_similarity || 89}%` }} />
                    </div>
                  </div>
                </div>
              </div>

              {/* Targeted Brands & Organizations */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="p-4 rounded-xl bg-surface-secondary/50 border border-border space-y-2">
                  <h4 className="text-xs font-mono font-bold uppercase text-foreground-muted">
                    Targeted Brands (Lookalike Lures)
                  </h4>
                  <div className="flex flex-wrap gap-2">
                    {campaignDetail.targeted_brands.map((b, i) => (
                      <span key={i} className="px-2.5 py-1 rounded-lg bg-surface border border-border text-xs font-mono text-foreground font-semibold">
                        {b}
                      </span>
                    ))}
                  </div>
                </div>

                <div className="p-4 rounded-xl bg-surface-secondary/50 border border-border space-y-2">
                  <h4 className="text-xs font-mono font-bold uppercase text-foreground-muted">
                    Targeted Internal Organizations & Units
                  </h4>
                  <div className="flex flex-wrap gap-2">
                    {campaignDetail.targeted_organizations.map((org, i) => (
                      <span key={i} className="px-2.5 py-1 rounded-lg bg-surface border border-border text-xs font-mono text-primary font-semibold">
                        {org}
                      </span>
                    ))}
                  </div>
                </div>
              </div>

              {/* Strongest Correlation Reasons */}
              <div className="p-4 rounded-xl bg-surface-secondary/50 border border-border space-y-2.5">
                <h4 className="text-xs font-mono font-bold uppercase text-foreground-muted">
                  Strongest Correlation Reasons
                </h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                  {(campaignDetail.category_scores?.strongest_signals || []).map((sig, i) => (
                    <div key={i} className="p-2.5 bg-surface rounded-lg border border-border text-xs font-mono text-foreground flex items-center space-x-2">
                      <span className="w-2 h-2 rounded-full bg-warning shrink-0" />
                      <span>{sig}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: EMAILS */}
          {activeTab === 'emails' && (
            <div className="space-y-3 animate-in fade-in duration-150">
              <h3 className="text-xs font-mono font-bold uppercase text-foreground-muted">
                Correlated Email Incidents ({campaignDetail.emails.length})
              </h3>
              <div className="space-y-2.5">
                {campaignDetail.emails.map(em => (
                  <div
                    key={em.id}
                    className="p-4 rounded-xl bg-surface-secondary/40 border border-border hover:border-primary/40 transition-all flex flex-col md:flex-row md:items-center justify-between gap-3 text-xs font-mono"
                  >
                    <div className="space-y-1 min-w-0">
                      <div className="flex items-center space-x-2">
                        <span className="font-bold text-primary">{em.id}</span>
                        <span className="text-foreground-muted">|</span>
                        <span className="text-foreground font-semibold truncate">{em.subject}</span>
                      </div>
                      <div className="text-[11px] text-foreground-muted flex flex-wrap items-center gap-3">
                        <span>From: <strong className="text-foreground">{em.sender}</strong></span>
                        {em.recipient && <span>To: <strong className="text-foreground">{em.recipient}</strong></span>}
                        <span>Date: <strong>{em.date}</strong></span>
                      </div>
                    </div>

                    <div className="flex items-center space-x-3 shrink-0">
                      <span className="px-2.5 py-1 rounded-full text-xs font-mono font-bold bg-warning/15 text-warning border border-warning/30">
                        {em.similarity || 95}% Match
                      </span>
                      <button
                        type="button"
                        onClick={() => navigate(`/analysis/${em.id}`)}
                        className="px-3 py-1.5 rounded-lg bg-surface hover:bg-surface-secondary text-primary border border-border text-xs font-mono transition-colors flex items-center space-x-1 cursor-pointer"
                      >
                        <span>Forensic View</span>
                        <ArrowUpRight className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* TAB 3: INFRASTRUCTURE */}
          {activeTab === 'infrastructure' && (
            <div className="space-y-4 animate-in fade-in duration-150 text-xs font-mono">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="p-4 rounded-xl bg-surface-secondary/50 border border-border space-y-2.5">
                  <span className="text-[10px] uppercase text-foreground-muted block font-semibold">Origin & Relay IP Addresses:</span>
                  <div className="flex flex-wrap gap-2">
                    {[
                      campaignDetail.infrastructure_summary.origin_ip,
                      ...(campaignDetail.infrastructure_summary.relay_ips || [])
                    ].filter(Boolean).map((ip, i) => (
                      <span key={i} className="px-2.5 py-1 rounded-lg bg-surface border border-border text-primary font-bold">
                        {ip}
                      </span>
                    ))}
                  </div>
                </div>

                <div className="p-4 rounded-xl bg-surface-secondary/50 border border-border space-y-2.5">
                  <span className="text-[10px] uppercase text-foreground-muted block font-semibold">Autonomous System Numbers (ASNs):</span>
                  <div className="flex flex-wrap gap-2">
                    {(campaignDetail.infrastructure_summary.asns || []).map((asn, i) => (
                      <span key={i} className="px-2.5 py-1 rounded-lg bg-surface border border-border text-blue-400 font-bold">
                        {asn}
                      </span>
                    ))}
                  </div>
                </div>

                <div className="p-4 rounded-xl bg-surface-secondary/50 border border-border space-y-2.5">
                  <span className="text-[10px] uppercase text-foreground-muted block font-semibold">Hosting Providers & ISPs:</span>
                  <div className="flex flex-wrap gap-2">
                    {(campaignDetail.infrastructure_summary.hosting_providers || []).map((p, i) => (
                      <span key={i} className="px-2.5 py-1 rounded-lg bg-surface border border-border text-foreground font-semibold">
                        {p}
                      </span>
                    ))}
                  </div>
                </div>

                <div className="p-4 rounded-xl bg-surface-secondary/50 border border-border space-y-2.5">
                  <span className="text-[10px] uppercase text-foreground-muted block font-semibold">Authoritative Nameservers:</span>
                  <div className="flex flex-wrap gap-2">
                    {(campaignDetail.infrastructure_summary.nameservers || []).map((ns, i) => (
                      <span key={i} className="px-2.5 py-1 rounded-lg bg-surface border border-border text-purple-400 font-medium">
                        {ns}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 4: DOMAINS */}
          {activeTab === 'domains' && (
            <div className="space-y-4 animate-in fade-in duration-150 text-xs font-mono">
              <div className="p-4 rounded-xl bg-surface-secondary/50 border border-border space-y-3">
                <span className="text-[11px] uppercase text-foreground-muted block font-bold">Associated Infrastructure Domains:</span>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
                  {(campaignDetail.domain_summary.linked_domains || []).map((dom, idx) => (
                    <div key={idx} className="p-3 bg-surface rounded-xl border border-border flex items-center justify-between">
                      <div className="flex items-center space-x-2.5 min-w-0">
                        <Globe className="w-4 h-4 text-info shrink-0" />
                        <span className="font-semibold text-foreground truncate">{dom}</span>
                      </div>
                      <button
                        type="button"
                        onClick={(e) => handleCopy(dom, e)}
                        className="p-1 text-foreground-muted hover:text-foreground transition-colors"
                        title="Copy Domain"
                      >
                        {copiedValue === dom ? <Check className="w-3.5 h-3.5 text-success" /> : <Copy className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* TAB 5: URLS */}
          {activeTab === 'urls' && (
            <div className="space-y-4 animate-in fade-in duration-150 text-xs font-mono">
              <div className="p-4 rounded-xl bg-surface-secondary/50 border border-border space-y-3">
                <span className="text-[11px] uppercase text-foreground-muted block font-bold">Normalized URL Lures & Phishing Links:</span>
                <div className="space-y-2">
                  {(campaignDetail.url_summary.normalized_urls || []).map((url, idx) => {
                    const defanged = url.replace(/http:\/\//gi, 'hxxp://').replace(/https:\/\//gi, 'hxxps://').replace(/\./g, '[.]');
                    return (
                      <div key={idx} className="p-3 bg-surface rounded-xl border border-border flex items-center justify-between gap-2">
                        <div className="flex items-center space-x-2.5 min-w-0">
                          <LinkIcon className="w-4 h-4 text-danger shrink-0" />
                          <span className="font-mono text-danger font-medium break-all">{defanged}</span>
                        </div>
                        <button
                          type="button"
                          onClick={(e) => handleCopy(url, e)}
                          className="p-1 text-foreground-muted hover:text-foreground transition-colors shrink-0"
                          title="Copy Link"
                        >
                          {copiedValue === url ? <Check className="w-3.5 h-3.5 text-success" /> : <Copy className="w-3.5 h-3.5" />}
                        </button>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          )}

          {/* TAB 6: RECIPIENTS */}
          {activeTab === 'recipients' && (
            <div className="space-y-4 animate-in fade-in duration-150 text-xs font-mono">
              <div className="p-4 rounded-xl bg-surface-secondary/50 border border-border space-y-3">
                <span className="text-[11px] uppercase text-foreground-muted block font-bold">
                  Targeted Internal Personnel & Victims ({campaignDetail.recipient_summary.recipients?.length || 0}):
                </span>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
                  {(campaignDetail.recipient_summary.recipients || []).map((rcpt, idx) => (
                    <div key={idx} className="p-2.5 bg-surface rounded-lg border border-border flex items-center space-x-2">
                      <Users className="w-3.5 h-3.5 text-primary shrink-0" />
                      <span className="text-foreground truncate">{rcpt}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* TAB 7: TIMELINE */}
          {activeTab === 'timeline' && (
            <div className="animate-in fade-in duration-150">
              <CampaignTimeline events={campaignDetail.timeline || []} />
            </div>
          )}

          {/* TAB 8: GRAPH */}
          {activeTab === 'graph' && (
            <div className="animate-in fade-in duration-150">
              <CampaignGraphView campaign={campaignDetail} />
            </div>
          )}

          {/* TAB 9: EVIDENCE */}
          {activeTab === 'evidence' && (
            <div className="space-y-4 animate-in fade-in duration-150 text-xs font-mono">
              <div className="p-4 rounded-xl bg-surface-secondary/50 border border-border space-y-3">
                <span className="text-[11px] uppercase text-foreground-muted block font-bold">Associated Technical IOCs ({campaignDetail.associated_iocs.length}):</span>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                  {campaignDetail.associated_iocs.map((ioc, idx) => (
                    <div key={idx} className="p-2.5 bg-surface rounded-lg border border-border flex items-center justify-between gap-2">
                      <div className="min-w-0">
                        <span className="text-[10px] uppercase text-foreground-muted block">{ioc.type}</span>
                        <span className="text-foreground font-semibold truncate block">{ioc.value}</span>
                      </div>
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-primary/10 text-primary border border-primary/20 shrink-0">
                        {Math.round(ioc.confidence * 100)}%
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Raw Multidimensional Fingerprint JSON */}
              <div className="p-4 rounded-xl bg-surface-secondary/50 border border-border space-y-2">
                <span className="text-[11px] uppercase text-foreground-muted block font-bold">CampaignFingerprint Object:</span>
                <pre className="p-3 bg-surface rounded-lg border border-border text-[11px] text-foreground font-mono overflow-x-auto max-h-96">
                  {JSON.stringify(campaignDetail.fingerprint, null, 2)}
                </pre>
              </div>

              {/* Governance disclaimer */}
              <div className="p-3 rounded-lg bg-surface border border-border text-[11px] text-foreground-muted flex items-start space-x-2">
                <Info className="w-4 h-4 shrink-0 text-primary mt-0.5" />
                <span>
                  Campaign Fingerprinting relies entirely on technical indicators, tactical infrastructure, and behavioral heuristics. Strictly adheres to non-attribution governance policy.
                </span>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
