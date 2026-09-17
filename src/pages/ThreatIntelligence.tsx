import React, { useState, useEffect } from 'react';
import {
  Globe2,
  Search,
  Database,
  Radio,
  ShieldAlert,
  AlertTriangle,
  Info
} from 'lucide-react';
import { RiskBadge } from '../components/common/RiskBadge';

interface CampaignCluster {
  campaign_id: string;
  name: string;
  first_seen: string;
  last_seen: string;
  email_count: number;
  recipient_count: number;
  sender_count: number;
  domain_count: number;
  ip_count: number;
  asn_count: number;
  overall_confidence: number;
  dominant_attack_type: string;
  targeted_brands: string[];
  targeted_organizations: string[];
}

export const ThreatIntelligence: React.FC = () => {
  const [lookupQuery, setLookupQuery] = useState('');
  const [isSearching, setIsSearching] = useState(false);
  const [lookupResult, setLookupResult] = useState<any>(null);
  const [lookupError, setLookupError] = useState<string | null>(null);
  const [hasSearched, setHasSearched] = useState(false);

  const [clusters, setClusters] = useState<CampaignCluster[]>([]);
  const [activeCluster, setActiveCluster] = useState<CampaignCluster | null>(null);
  const [loadingClusters, setLoadingClusters] = useState(true);
  const [providerStatus, setProviderStatus] = useState<{ configured: boolean; provider: string; error?: string } | null>(null);

  useEffect(() => {
    // Fetch provider status
    fetch('/api/intelligence/geolocation/status')
      .then(res => res.ok ? res.json() : null)
      .then(data => {
        if (data) setProviderStatus(data);
      })
      .catch(() => {});

    // Fetch actual tracked campaigns
    setLoadingClusters(true);
    fetch('/api/campaigns')
      .then(res => res.ok ? res.json() : [])
      .then((data: CampaignCluster[]) => {
        setClusters(data || []);
        if (data && data.length > 0) {
          setActiveCluster(data[0]);
        }
      })
      .catch(() => {
        setClusters([]);
      })
      .finally(() => {
        setLoadingClusters(false);
      });
  }, []);

  const handleLookup = async (e: React.FormEvent) => {
    e.preventDefault();
    const query = lookupQuery.trim();
    if (!query) return;

    setIsSearching(true);
    setLookupError(null);
    setLookupResult(null);
    setHasSearched(true);

    const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(query) || query.includes(':');
    const endpoint = isIp
      ? `/api/emails/lookup/${encodeURIComponent(query)}`
      : `/api/emails/lookup-domain/${encodeURIComponent(query)}`;

    try {
      const res = await fetch(endpoint);
      if (!res.ok) {
        if (res.status === 404) {
          setLookupError(`No threat intelligence record found for '${query}'.`);
        } else {
          setLookupError(`Lookup request failed with status ${res.status}.`);
        }
      } else {
        const data = await res.json();
        setLookupResult(data);
      }
    } catch (err: any) {
      setLookupError('Unable to contact threat intelligence service.');
    } finally {
      setIsSearching(false);
    }
  };

  return (
    <div className="space-y-6 pb-12">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-surface p-6 rounded-xl border border-border">
        <div>
          <div className="flex items-center space-x-2 text-primary font-mono text-xs mb-1 font-semibold uppercase tracking-wider">
            <Globe2 className="w-3.5 h-3.5 text-primary" />
            <span>GLOBAL THREAT INTELLIGENCE & INFRASTRUCTURE MATRIX</span>
          </div>
          <h1 className="text-xl font-bold text-foreground font-sans tracking-tight">
            Threat Intelligence & Domain Profiling
          </h1>
          <p className="text-xs text-foreground-muted font-mono mt-1">
            Correlate domain registration WHOIS, IP subnet reputation, BGP routing anomalies, and threat actor campaign clusters.
          </p>
        </div>

        <div className="flex items-center space-x-2 px-3 py-1.5 rounded-lg bg-surface-secondary border border-border text-xs font-mono text-foreground">
          <Radio className={`w-3.5 h-3.5 ${providerStatus?.configured ? 'text-success animate-pulse' : 'text-foreground-muted'}`} />
          <span>
            {providerStatus?.configured
              ? <>Provider: <strong className="text-primary font-medium">{providerStatus.provider}</strong> (Active)</>
              : <span className="text-foreground-muted">Threat intelligence provider not configured</span>
            }
          </span>
        </div>
      </div>

      {/* Domain / IP WHOIS & Reputation Search */}
      <div className="bg-surface border border-border rounded-xl p-5 space-y-3">
        <form onSubmit={handleLookup} className="flex flex-col sm:flex-row items-center gap-2.5">
          <div className="relative flex-grow w-full">
            <Search className="w-4 h-4 text-foreground-muted absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
            <input
              type="text"
              value={lookupQuery}
              onChange={(e) => setLookupQuery(e.target.value)}
              placeholder="Enter Domain Name (e.g. evil-corp.com) or IP Address (e.g. 198.51.100.25)..."
              className="w-full pl-9 pr-4 py-2 bg-surface-secondary border border-border rounded-lg text-xs font-mono text-foreground placeholder:text-foreground-muted focus:outline-none focus:border-primary"
            />
          </div>
          <button
            type="submit"
            disabled={isSearching || !lookupQuery.trim()}
            className="w-full sm:w-auto px-4 py-2 rounded-lg bg-primary hover:bg-primary-hover text-primary-foreground font-mono font-semibold text-xs tracking-wider transition-colors btn-press cursor-pointer flex items-center justify-center space-x-1.5 disabled:opacity-50"
          >
            {isSearching ? (
              <div className="w-3.5 h-3.5 border-2 border-primary-foreground border-t-transparent rounded-full animate-spin" />
            ) : (
              <Database className="w-3.5 h-3.5" />
            )}
            <span>QUERY INTELLIGENCE</span>
          </button>
        </form>

        {/* Search Result View */}
        {hasSearched ? (
          lookupError ? (
            <div className="p-3.5 rounded-lg bg-danger-surface border border-danger-border flex items-center space-x-2 text-xs font-mono text-danger">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              <span>{lookupError}</span>
            </div>
          ) : lookupResult ? (
            <div className="p-3.5 rounded-lg bg-surface-secondary border border-border grid grid-cols-1 md:grid-cols-4 gap-3 text-xs font-mono">
              <div>
                <span className="text-foreground-muted block text-[10px]">Queried Artifact:</span>
                <span className="text-primary font-semibold">{lookupQuery}</span>
              </div>
              <div>
                <span className="text-foreground-muted block text-[10px]">Classification / ASN:</span>
                <span className="text-foreground font-semibold">
                  {lookupResult.asn || lookupResult.autonomous_system || 'Unclassified / None'}
                </span>
              </div>
              <div>
                <span className="text-foreground-muted block text-[10px]">Country / Geolocation:</span>
                <span className="text-foreground">
                  {lookupResult.country ? `${lookupResult.city ? lookupResult.city + ', ' : ''}${lookupResult.country}` : 'Not available'}
                </span>
              </div>
              <div>
                <span className="text-foreground-muted block text-[10px]">Enrichment Status:</span>
                <span className={`font-bold px-2 py-0.5 rounded border inline-block mt-0.5 ${
                  lookupResult.enrichment_available || lookupResult.available
                    ? 'bg-success-surface border-success-border text-success'
                    : 'bg-surface border-border text-foreground-muted'
                }`}>
                  {lookupResult.enrichment_available || lookupResult.available ? 'Enriched' : 'Provider unconfigured'}
                </span>
              </div>
            </div>
          ) : null
        ) : (
          <div className="p-3.5 rounded-lg bg-surface-secondary/40 border border-border/60 text-xs font-mono text-foreground-muted flex items-center space-x-2">
            <Info className="w-3.5 h-3.5 text-primary shrink-0" />
            <span>Enter an IP address or domain name above to perform live threat intelligence lookup.</span>
          </div>
        )}
      </div>

      {/* Threat Actor Campaign Clusters */}
      <div className="space-y-3">
        <h3 className="text-xs font-mono font-semibold text-foreground-muted uppercase tracking-wider">
          TRACKED THREAT CAMPAIGN CLUSTERS ({clusters.length})
        </h3>

        {loadingClusters ? (
          <div className="p-8 bg-surface rounded-xl border border-border text-center text-xs font-mono text-foreground-muted">
            Loading campaigns from database...
          </div>
        ) : clusters.length === 0 ? (
          <div className="p-10 bg-surface rounded-xl border border-border text-center space-y-3">
            <div className="p-3 bg-surface-secondary rounded-full w-12 h-12 mx-auto flex items-center justify-center border border-border">
              <ShieldAlert className="w-6 h-6 text-foreground-muted" />
            </div>
            <h4 className="text-sm font-bold text-foreground font-sans">
              No Tracked Threat Campaigns Detected
            </h4>
            <p className="text-xs text-foreground-muted font-mono max-w-md mx-auto">
              Real campaigns are established automatically when multi-signal correlation across analyzed emails exceeds detection thresholds.
            </p>
          </div>
        ) : (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Left Column: Cluster Selection List */}
            <div className="space-y-2.5">
              {clusters.map((cluster) => {
                const isSelected = activeCluster?.campaign_id === cluster.campaign_id;
                return (
                  <div
                    key={cluster.campaign_id}
                    onClick={() => setActiveCluster(cluster)}
                    className={`p-3.5 rounded-xl border text-xs font-mono cursor-pointer transition-all ${
                      isSelected
                        ? 'bg-primary-subtle border-primary/40 shadow-xs'
                        : 'bg-surface border-border hover:bg-surface-secondary/50'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-1">
                      <span className={`font-semibold ${isSelected ? 'text-primary' : 'text-foreground'}`}>
                        {cluster.name}
                      </span>
                      <RiskBadge severity={cluster.overall_confidence > 75 ? 'CRITICAL' : 'HIGH'} size="sm" />
                    </div>
                    <div className="text-foreground font-sans font-medium mt-1">
                      {cluster.dominant_attack_type}
                    </div>
                    <div className="text-[11px] text-foreground-muted mt-2 flex justify-between">
                      <span>First Seen: {cluster.first_seen}</span>
                      <span className="text-warning font-semibold">{cluster.email_count} Emails</span>
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Right Column: Cluster Detail Inspector */}
            {activeCluster && (
              <div className="lg:col-span-2 bg-surface border border-border rounded-xl p-5 space-y-4">
                <div className="flex items-center justify-between border-b border-border pb-3">
                  <div>
                    <span className="text-xs font-mono text-primary font-semibold">
                      CLUSTER ID: {activeCluster.campaign_id}
                    </span>
                    <h2 className="text-lg font-bold text-foreground font-sans mt-0.5">
                      {activeCluster.name}
                    </h2>
                  </div>
                  <RiskBadge severity={activeCluster.overall_confidence > 75 ? 'CRITICAL' : 'HIGH'} size="md" />
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs font-mono">
                  <div className="p-3 rounded-lg bg-surface-secondary border border-border space-y-1">
                    <span className="text-foreground-muted text-[10px] block">Attack Classification:</span>
                    <span className="text-foreground font-bold text-sm">{activeCluster.dominant_attack_type}</span>
                  </div>

                  <div className="p-3 rounded-lg bg-surface-secondary border border-border space-y-1">
                    <span className="text-foreground-muted text-[10px] block">Confidence Rating:</span>
                    <span className="text-primary font-semibold">{activeCluster.overall_confidence.toFixed(1)}%</span>
                  </div>
                </div>

                {activeCluster.targeted_brands.length > 0 && (
                  <div className="space-y-1.5">
                    <h4 className="text-xs font-mono font-semibold text-foreground-muted uppercase">
                      TARGETED BRANDS
                    </h4>
                    <div className="flex flex-wrap gap-1.5">
                      {activeCluster.targeted_brands.map((brand) => (
                        <span
                          key={brand}
                          className="px-2 py-0.5 rounded bg-surface-secondary border border-border text-foreground text-xs font-mono"
                        >
                          {brand}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {activeCluster.targeted_organizations.length > 0 && (
                  <div className="space-y-1.5">
                    <h4 className="text-xs font-mono font-semibold text-foreground-muted uppercase">
                      TARGETED ORGANIZATIONS
                    </h4>
                    <div className="flex flex-wrap gap-1.5">
                      {activeCluster.targeted_organizations.map((org) => (
                        <span
                          key={org}
                          className="px-2 py-0.5 rounded bg-danger-surface border border-danger-border text-danger text-xs font-mono"
                        >
                          {org}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
