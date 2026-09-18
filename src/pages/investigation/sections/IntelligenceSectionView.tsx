import React, { useState } from 'react';
import {
  Globe2,
  Server,
  MapPin,
  Network,
  Search,
  Loader2
} from 'lucide-react';
import type { EmailAnalysis } from '../../../types/forensic';
import { useInvestigation } from '../../../context/InvestigationContext';
import { IPIntelligenceSection } from '../../../components/forensic/IPIntelligenceSection';
import { DomainIntelligenceSection } from '../../../components/forensic/DomainIntelligenceSection';
import { InvestigationMapTab } from '../../../components/forensic/InvestigationMapTab';
import { InfrastructureAttributionSection } from '../../../components/forensic/InfrastructureAttributionSection';
import { resolveAttribution } from '../../../utils/indicatorHelper';

interface IntelligenceSectionViewProps {
  email: EmailAnalysis;
}

type IntelligenceSubTab = 'ip_intel' | 'domain_intel' | 'map' | 'attribution' | 'osint';

export const IntelligenceSectionView: React.FC<IntelligenceSectionViewProps> = ({ email }) => {
  const { subTabs, setSubTab, focusGraphNode, stepGuidance } = useInvestigation();
  const currentSubTab = (subTabs.intelligence || 'ip_intel') as IntelligenceSubTab;

  // OSINT query state
  const [queryInput, setQueryInput] = useState('');
  const [isQuerying, setIsQuerying] = useState(false);
  const [queryResult, setQueryResult] = useState<any>(null);
  const [queryError, setQueryError] = useState<string | null>(null);

  const ipCount = (email.ips?.length || 0) + (email.indicators?.ips?.length || 0);
  const domainCount = (email.domains?.length || 0) + (email.indicators?.domains?.length || 0);

  const subTabItems: { id: IntelligenceSubTab; label: string; icon: React.FC<{ className?: string }>; count?: number }[] = [
    { id: 'ip_intel', label: 'IP Intelligence', icon: Server, count: ipCount },
    { id: 'domain_intel', label: 'Domain & DNS Intelligence', icon: Globe2, count: domainCount },
    { id: 'map', label: 'Geolocation & GeoTrace Map', icon: MapPin },
    { id: 'attribution', label: 'Infrastructure Attribution', icon: Network },
    { id: 'osint', label: 'OSINT Query Console', icon: Search }
  ];

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

  const attribution = email.attribution || resolveAttribution(email);

  return (
    <div className="space-y-6">
      {/* 1. CONTEXTUAL SUB-NAVIGATION */}
      <div className="bg-surface rounded-xl border border-border p-1.5 flex flex-wrap items-center gap-1 shadow-xs">
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

      {/* 2. SUB-TAB VIEW CONTAINER */}
      <div className="bg-surface rounded-xl border border-border p-5 shadow-xs">
        {/* IP Intelligence */}
        {currentSubTab === 'ip_intel' && (
          <div className="space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-border">
              <div className="flex items-center space-x-2 text-xs font-mono font-bold uppercase text-foreground">
                <Server className="w-4 h-4 text-primary" />
                <span>Internet Protocol (IP) Intelligence & Telemetry</span>
              </div>
              <span className="text-[11px] font-mono text-foreground-muted">
                Bogon check, ISP/ASN ownership, proxy detection & reputation
              </span>
            </div>
            <IPIntelligenceSection email={email} />
          </div>
        )}

        {/* Domain Intelligence */}
        {currentSubTab === 'domain_intel' && (
          <div className="space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-border">
              <div className="flex items-center space-x-2 text-xs font-mono font-bold uppercase text-foreground">
                <Globe2 className="w-4 h-4 text-primary" />
                <span>Domain WHOIS, DNS Records & Registration Age</span>
              </div>
              <span className="text-[11px] font-mono text-foreground-muted">
                A, MX, NS, TXT record resolution & newly registered domain warnings
              </span>
            </div>
            <DomainIntelligenceSection email={email} />
          </div>
        )}

        {/* Geolocation & Map */}
        {currentSubTab === 'map' && (
          <div className="space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-border">
              <div className="flex items-center space-x-2 text-xs font-mono font-bold uppercase text-foreground">
                <MapPin className="w-4 h-4 text-primary" />
                <span>Geographic Route Trace & Infrastructure Map</span>
              </div>
              <span className="text-[11px] font-mono text-foreground-muted">
                Physical transit hops, origin country coordinates & Leaflet trajectory
              </span>
            </div>
            <InvestigationMapTab email={email} />
          </div>
        )}

        {/* Infrastructure Attribution */}
        {currentSubTab === 'attribution' && (
          <div className="space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-border">
              <div className="flex items-center space-x-2 text-xs font-mono font-bold uppercase text-foreground">
                <Network className="w-4 h-4 text-primary" />
                <span>Hostile Infrastructure Attribution Engine</span>
              </div>
              <span className="text-[11px] font-mono text-foreground-muted">
                Autonomous System (ASN) clustering, subnet CIDRs & threat actor correlation
              </span>
            </div>
            <InfrastructureAttributionSection
              attribution={attribution}
              conclusions={email.forensic_conclusions}
              onFocusGraphNode={focusGraphNode}
            />
          </div>
        )}

        {/* OSINT Query Console */}
        {currentSubTab === 'osint' && (
          <div className="space-y-5">
            <div className="flex items-center justify-between pb-3 border-b border-border">
              <div className="flex items-center space-x-2 text-xs font-mono font-bold uppercase text-foreground">
                <Search className="w-4 h-4 text-primary" />
                <span>On-Demand OSINT Threat Intelligence Query Console</span>
              </div>
              <span className="text-[11px] font-mono text-foreground-muted">
                Query external threat feeds, WHOIS databases & DNS records
              </span>
            </div>

            {/* Query Input Bar */}
            <form onSubmit={handleRunOSINT} className="flex gap-2">
              <div className="relative flex-1">
                <Search className="w-4 h-4 text-foreground-muted absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
                <input
                  type="text"
                  value={queryInput}
                  onChange={(e) => setQueryInput(e.target.value)}
                  placeholder="Enter IP address (e.g., 203.0.113.88) or Domain (e.g., secure-update.com)..."
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

            {/* Quick Pivot Buttons from Current Email */}
            <div className="flex flex-wrap items-center gap-2 text-xs font-mono text-foreground-muted">
              <span>Quick Pivot:</span>
              {attribution?.probable_origin_ip && (
                <button
                  type="button"
                  onClick={() => setQueryInput(attribution.probable_origin_ip!)}
                  className="px-2 py-0.5 rounded bg-surface-secondary hover:bg-surface border border-border text-primary cursor-pointer"
                >
                  Origin IP: {attribution.probable_origin_ip}
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

            {/* Query Results Display */}
            {queryError && (
              <div className="p-3.5 rounded-lg bg-danger/10 border border-danger/30 text-danger text-xs font-mono">
                {queryError}
              </div>
            )}

            {queryResult && (
              <div className="p-4 rounded-lg bg-surface-secondary border border-border space-y-3 font-mono text-xs">
                <div className="flex items-center justify-between border-b border-border pb-2">
                  <span className="font-bold text-foreground">Query Result: {queryInput}</span>
                  <span className="text-[10px] text-success">Verified Live Lookup</span>
                </div>
                <pre className="p-3 bg-surface rounded border border-border text-[11px] overflow-x-auto text-foreground max-h-72">
                  {JSON.stringify(queryResult, null, 2)}
                </pre>
              </div>
            )}
          </div>
        )}
      </div>

      {/* 3. NEXT INVESTIGATION STEP CTA */}
      <div className="p-4 rounded-xl bg-surface border border-border flex flex-col sm:flex-row items-center justify-between gap-4 shadow-xs">
        <div className="flex items-center space-x-3">
          <div className="w-8 h-8 rounded-lg bg-primary/10 text-primary flex items-center justify-center font-bold font-mono text-xs border border-primary/20">
            05
          </div>
          <div>
            <h4 className="text-xs font-bold text-foreground font-sans">
              Completed Threat Intelligence Correlation?
            </h4>
            <p className="text-xs font-mono text-foreground-muted">
              Open the interactive investigation graph, identify campaign clusters, compare related emails, and query the copilot.
            </p>
          </div>
        </div>

        <button
          type="button"
          onClick={stepGuidance.execute}
          className="w-full sm:w-auto px-4 py-2 rounded-lg bg-primary hover:bg-primary-hover text-primary-foreground font-mono text-xs font-bold flex items-center justify-center space-x-2 transition-all shadow-xs cursor-pointer"
        >
          <span>{stepGuidance.buttonLabel}</span>
        </button>
      </div>
    </div>
  );
};
