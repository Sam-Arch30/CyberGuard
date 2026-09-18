import React, { useState } from 'react';
import {
  Server,
  Globe,
  MapPin,
  Search,
  Loader2,
  Layers,
  ArrowRight
} from 'lucide-react';
import type { EmailAnalysis } from '../../../types/forensic';
import { useInvestigation } from '../../../context/InvestigationContext';
import {
  IntelligenceSummaryCard,
  InfrastructureIPSection,
  DomainRelationshipsSection,
  GeographicSummarySection
} from '../../../components/forensic/intelligence';

interface IntelligenceSectionViewProps {
  email: EmailAnalysis;
}

type IntelligenceFilterGroup = 'all' | 'infrastructure' | 'domains' | 'geography' | 'osint';

export const IntelligenceSectionView: React.FC<IntelligenceSectionViewProps> = ({ email }) => {
  const { subTabs, setSubTab, stepGuidance } = useInvestigation();
  
  // Normalize legacy sub-tab keys to the 3 primary groups
  const rawSubTab = (subTabs.intelligence || 'all').toLowerCase();
  const currentSubTab: IntelligenceFilterGroup = 
    rawSubTab === 'ip_intel' || rawSubTab === 'attribution'
      ? 'infrastructure'
      : rawSubTab === 'domain_intel'
      ? 'domains'
      : rawSubTab === 'map'
      ? 'geography'
      : (['all', 'infrastructure', 'domains', 'geography', 'osint'].includes(rawSubTab)
          ? (rawSubTab as IntelligenceFilterGroup)
          : 'all');

  // Cross-entity linkage states
  const [selectedIpForDrawer, setSelectedIpForDrawer] = useState<string | null>(null);
  const [selectedDomainForFocus, setSelectedDomainForFocus] = useState<string | null>(null);

  // OSINT on-demand lookup state
  const [queryInput, setQueryInput] = useState('');
  const [isQuerying, setIsQuerying] = useState(false);
  const [queryResult, setQueryResult] = useState<any>(null);
  const [queryError, setQueryError] = useState<string | null>(null);

  // Counts for tabs
  const ipCount = (email.ips?.length || 0) + (email.indicators?.ips?.length || 0);
  const domainCount = (email.domains?.length || 0) + (email.indicators?.domains?.length || 0);

  const subTabItems: { id: IntelligenceFilterGroup; label: string; icon: React.FC<{ className?: string }>; count?: number }[] = [
    { id: 'all', label: 'All Groups', icon: Layers },
    { id: 'infrastructure', label: 'Infrastructure', icon: Server, count: ipCount },
    { id: 'domains', label: 'Domains', icon: Globe, count: domainCount },
    { id: 'geography', label: 'Geography', icon: MapPin },
    { id: 'osint', label: 'OSINT Query Console', icon: Search }
  ];

  const handleSelectGroup = (group: 'infrastructure' | 'domains' | 'geography') => {
    setSubTab(group);
    // Smooth scroll to group if in 'all' view
    const el = document.getElementById(`group-${group}`);
    if (el) {
      el.scrollIntoView({ behavior: 'smooth' });
    }
  };

  const handleRunOSINT = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!queryInput.trim()) return;
    setIsQuerying(true);
    setQueryError(null);
    setQueryResult(null);

    try {
      const q = queryInput.trim();
      const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(q);
      const url = isIp
        ? `/api/emails/lookup-ip/${encodeURIComponent(q)}`
        : `/api/emails/lookup-domain/${encodeURIComponent(q)}`;

      const res = await fetch(url);
      if (!res.ok) throw new Error(`Lookup returned HTTP ${res.status}`);
      const data = await res.json();
      setQueryResult(data);
    } catch (err: any) {
      setQueryError(err?.message || 'Failed to query threat intelligence service');
    } finally {
      setIsQuerying(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* 1. SUB-NAVIGATION FILTER BAR */}
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
                {typeof tab.count === 'number' && tab.count > 0 && (
                  <span
                    className={`ml-1 px-1.5 py-0.2 rounded text-[10px] font-mono ${
                      isActive ? 'bg-black/20 text-white' : 'bg-surface-secondary text-foreground-subtle border border-border'
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
          <span>Infrastructure Investigation Workspace</span>
        </div>
      </div>

      {/* 2. TOP TRIAGE SUMMARY CARD (Surfaced in 'All Groups' overview mode) */}
      {currentSubTab === 'all' && (
        <IntelligenceSummaryCard
          email={email}
          onSelectGroup={handleSelectGroup}
        />
      )}

      {/* 3. PRIMARY GROUPS CONTAINER */}
      <div className="space-y-6">
        {/* GROUP 1: INFRASTRUCTURE */}
        {(currentSubTab === 'all' || currentSubTab === 'infrastructure') && (
          <div id="group-infrastructure" className="bg-surface rounded-xl border border-border p-5 shadow-xs">
            <InfrastructureIPSection
              email={email}
              selectedIpExternal={selectedIpForDrawer}
              onClearSelectedIp={() => setSelectedIpForDrawer(null)}
              onSelectDomain={(domain) => {
                setSelectedDomainForFocus(domain);
                handleSelectGroup('domains');
              }}
            />
          </div>
        )}

        {/* GROUP 2: DOMAINS */}
        {(currentSubTab === 'all' || currentSubTab === 'domains') && (
          <div id="group-domains" className="bg-surface rounded-xl border border-border p-5 shadow-xs">
            <DomainRelationshipsSection
              email={email}
              selectedDomainExternal={selectedDomainForFocus}
              onClearSelectedDomain={() => setSelectedDomainForFocus(null)}
              onSelectIp={(ip) => {
                setSelectedIpForDrawer(ip);
                handleSelectGroup('infrastructure');
              }}
            />
          </div>
        )}

        {/* GROUP 3: GEOGRAPHY */}
        {(currentSubTab === 'all' || currentSubTab === 'geography') && (
          <div id="group-geography" className="bg-surface rounded-xl border border-border p-5 shadow-xs">
            <GeographicSummarySection
              email={email}
              onSelectIp={(ip) => {
                setSelectedIpForDrawer(ip);
                handleSelectGroup('infrastructure');
              }}
            />
          </div>
        )}

        {/* ACCESSORY TOOL: OSINT QUERY CONSOLE */}
        {currentSubTab === 'osint' && (
          <div className="bg-surface rounded-xl border border-border p-5 shadow-xs space-y-5">
            <div className="flex items-center justify-between pb-3 border-b border-border">
              <div className="flex items-center space-x-2 text-xs font-mono font-bold uppercase text-foreground">
                <Search className="w-4 h-4 text-primary" />
                <span>On-Demand OSINT Threat Intelligence Query Console</span>
              </div>
              <span className="text-[11px] font-mono text-foreground-muted">
                Direct lookup against external RDAP, WHOIS, and DNS resolvers
              </span>
            </div>

            {/* Query Form */}
            <form onSubmit={handleRunOSINT} className="flex gap-2">
              <div className="relative flex-1">
                <Search className="w-4 h-4 text-foreground-muted absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
                <input
                  type="text"
                  value={queryInput}
                  onChange={(e) => setQueryInput(e.target.value)}
                  placeholder="Enter IP address (e.g. 198.51.100.22) or domain (e.g. micros0ft-support.example)..."
                  className="w-full pl-9 pr-3 py-2 bg-surface-secondary border border-border rounded-lg text-xs font-mono text-foreground placeholder:text-foreground-muted focus:outline-none focus:border-primary"
                />
              </div>
              <button
                type="submit"
                disabled={isQuerying || !queryInput.trim()}
                className="px-4 py-2 rounded-lg bg-primary hover:bg-primary-hover text-primary-foreground font-mono text-xs font-bold transition-colors disabled:opacity-50 flex items-center space-x-1.5 cursor-pointer"
              >
                {isQuerying ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Search className="w-3.5 h-3.5" />}
                <span>Query OSINT</span>
              </button>
            </form>

            {/* Quick Pivot Chips */}
            <div className="flex flex-wrap items-center gap-2 text-xs font-mono text-foreground-muted">
              <span>Quick Pivots:</span>
              {email.relay_analysis?.earliest_observable_node?.earliest_observable_ip && (
                <button
                  type="button"
                  onClick={() => setQueryInput(email.relay_analysis!.earliest_observable_node!.earliest_observable_ip!)}
                  className="px-2 py-0.5 rounded bg-surface-secondary hover:bg-surface border border-border text-primary cursor-pointer"
                >
                  Origin IP: {email.relay_analysis.earliest_observable_node.earliest_observable_ip}
                </button>
              )}
              {email.authentication?.alignment?.from_domain && (
                <button
                  type="button"
                  onClick={() => setQueryInput(email.authentication!.alignment!.from_domain!)}
                  className="px-2 py-0.5 rounded bg-surface-secondary hover:bg-surface border border-border text-primary cursor-pointer"
                >
                  From Domain: {email.authentication.alignment.from_domain}
                </button>
              )}
            </div>

            {/* Query Results */}
            {queryError && (
              <div className="p-3.5 rounded-lg bg-danger/10 border border-danger/30 text-danger text-xs font-mono">
                {queryError}
              </div>
            )}

            {queryResult && (
              <div className="p-4 rounded-lg bg-surface-secondary border border-border space-y-3 font-mono text-xs">
                <div className="flex items-center justify-between border-b border-border pb-2">
                  <span className="font-bold text-foreground">Query Result: {queryInput}</span>
                  <span className="text-[10px] text-success">Live External Lookup Verified</span>
                </div>
                <pre className="p-3 bg-surface rounded border border-border text-[11px] overflow-x-auto text-foreground max-h-72">
                  {JSON.stringify(queryResult, null, 2)}
                </pre>
              </div>
            )}
          </div>
        )}
      </div>

      {/* 4. NEXT INVESTIGATION STEP CTA */}
      <div className="p-4 rounded-xl bg-surface border border-border flex flex-col sm:flex-row items-center justify-between gap-4 shadow-xs">
        <div className="flex items-center space-x-3">
          <div className="w-8 h-8 rounded-lg bg-primary/10 text-primary flex items-center justify-center font-bold font-mono text-xs border border-primary/20">
            05
          </div>
          <div>
            <h4 className="text-xs font-bold text-foreground font-sans">
              Completed Infrastructure Intelligence Investigation?
            </h4>
            <p className="text-xs font-mono text-foreground-muted">
              Pivot into the interactive knowledge graph, uncover campaign correlation clusters, and engage the AI copilot.
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
    </div>
  );
};
