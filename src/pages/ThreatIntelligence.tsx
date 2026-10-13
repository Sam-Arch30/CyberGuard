import { apiFetch } from '../utils/apiClient';
import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import {
  Globe2,
  Search,
  Database,
  Radio,
  ShieldAlert,
  AlertTriangle,
  Eye,
  Compass,
} from 'lucide-react';
import type {
  AggregatedIndicatorIntelligence,
  ThreatIntelProviderConfig,
} from '../types/threatIntelligence';
import { threatIntelligenceService } from '../services/threatIntelligenceService';
import { IndicatorIntelligencePanel } from '../components/intelligence/IndicatorIntelligencePanel';

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
  const [selectedType, setSelectedType] = useState('AUTO');
  const [isSearching, setIsSearching] = useState(false);
  const [intelligenceResult, setIntelligenceResult] = useState<AggregatedIndicatorIntelligence | null>(null);
  const [lookupError, setLookupError] = useState<string | null>(null);
  const [hasSearched, setHasSearched] = useState(false);

  const [clusters, setClusters] = useState<CampaignCluster[]>([]);
  const [activeCluster, setActiveCluster] = useState<CampaignCluster | null>(null);
  const [loadingClusters, setLoadingClusters] = useState(true);
  const [providers, setProviders] = useState<ThreatIntelProviderConfig[]>([]);

  useEffect(() => {
    // Fetch provider configurations
    threatIntelligenceService
      .listProviders()
      .then((data) => setProviders(data || []))
      .catch(() => {});

    // Fetch actual tracked campaigns
    setLoadingClusters(true);
    apiFetch('/api/campaigns')
      .then((res) => (res.ok ? res.json() : []))
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

  const handleLookup = async (e?: React.FormEvent, customQuery?: string, customType?: string) => {
    if (e) e.preventDefault();
    const query = (customQuery || lookupQuery).trim();
    if (!query) return;

    const indType = customType || selectedType;
    setIsSearching(true);
    setLookupError(null);
    setIntelligenceResult(null);
    setHasSearched(true);

    try {
      const typeParam = indType === 'AUTO' ? 'HOSTNAME' : indType;
      const res = await threatIntelligenceService.getIndicatorIntelligence(typeParam, query);
      setIntelligenceResult(res);
    } catch (err: any) {
      setLookupError(err.message || 'Unable to contact threat intelligence service.');
    } finally {
      setIsSearching(false);
    }
  };

  const handleQuickSample = (val: string, type: string) => {
    setLookupQuery(val);
    setSelectedType(type);
    handleLookup(undefined, val, type);
  };

  return (
    <div className="space-y-6 pb-12">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-surface p-6 rounded-xl border border-border">
        <div>
          <div className="flex items-center space-x-2 text-primary font-mono text-xs mb-1 font-semibold uppercase tracking-wider">
            <Globe2 className="w-3.5 h-3.5 text-primary" />
            <span>SECTION 52 — THREAT INTELLIGENCE & EXTERNAL ENRICHMENT</span>
          </div>
          <h1 className="text-xl font-bold text-foreground font-sans tracking-tight">
            Threat Intelligence & Indicator Profiling
          </h1>
          <p className="text-xs text-foreground-muted font-mono mt-1">
            Query multi-provider intelligence for IPs, domains, URLs, and hashes with privacy safeguards and provenance tracking.
          </p>
        </div>

        {/* Provider Operational Status Ribbon */}
        <div className="flex flex-wrap items-center gap-1.5 p-2 bg-surface-secondary border border-border rounded-lg text-xs font-mono">
          <Radio className="w-3.5 h-3.5 text-success animate-pulse mr-1" />
          <span className="text-foreground-muted text-[11px] mr-1">Active Providers:</span>
          {providers.map((p) => (
            <span
              key={p.id}
              className={`px-1.5 py-0.5 rounded text-[10px] font-semibold border ${
                p.enabled
                  ? 'bg-surface text-primary border-border'
                  : 'bg-surface/50 text-foreground-muted border-border/50 line-through'
              }`}
              title={`${p.display_name} (Priority: #${p.priority})`}
            >
              {p.display_name}
            </span>
          ))}
          <Link
            to="/watchlists"
            className="ml-2 px-2 py-1 bg-surface border border-border text-foreground font-semibold rounded text-[11px] inline-flex items-center space-x-1 hover:bg-surface-secondary transition-colors"
          >
            <Eye className="w-3 h-3 text-primary" />
            <span>Watchlists</span>
          </Link>
          <Link
            to="/hunting"
            className="px-2 py-1 bg-primary text-primary-foreground font-semibold rounded text-[11px] inline-flex items-center space-x-1 hover:bg-primary-hover transition-colors"
          >
            <Compass className="w-3 h-3" />
            <span>Threat Hunting</span>
          </Link>
        </div>
      </div>

      {/* Multi-Indicator Intelligence Search Form */}
      <div className="bg-surface border border-border rounded-xl p-5 space-y-4">
        <form onSubmit={handleLookup} className="flex flex-col sm:flex-row items-center gap-2.5">
          {/* Indicator Type Select */}
          <select
            value={selectedType}
            onChange={(e) => setSelectedType(e.target.value)}
            className="w-full sm:w-36 px-2.5 py-2 bg-surface-secondary border border-border rounded-lg text-xs font-mono text-foreground focus:outline-none focus:border-primary"
          >
            <option value="AUTO">Auto-Detect</option>
            <option value="IP">IP Address</option>
            <option value="DOMAIN">Domain</option>
            <option value="URL">URL</option>
            <option value="SHA256">SHA-256 Hash</option>
            <option value="MD5">MD5 Hash</option>
            <option value="EMAIL">Email</option>
            <option value="ASN">ASN</option>
          </select>

          {/* Input field */}
          <div className="relative flex-grow w-full">
            <Search className="w-4 h-4 text-foreground-muted absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
            <input
              type="text"
              value={lookupQuery}
              onChange={(e) => setLookupQuery(e.target.value)}
              placeholder="Enter IP (e.g. 185.220.101.42), domain (bank-corp-update.com), URL, or file hash..."
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
            <span>ENRICH INDICATOR</span>
          </button>
        </form>

        {/* Quick Sample Observables */}
        <div className="flex flex-wrap items-center gap-1.5 text-xs font-mono">
          <span className="text-[10px] text-foreground-muted">Quick Presets:</span>
          <button
            type="button"
            onClick={() => handleQuickSample('bank-corp-update.com', 'DOMAIN')}
            className="px-2 py-0.5 rounded bg-surface-secondary hover:bg-surface-secondary/80 text-foreground border border-border text-[10px] transition-colors cursor-pointer"
          >
            bank-corp-update.com (Phish Domain)
          </button>
          <button
            type="button"
            onClick={() => handleQuickSample('185.220.101.42', 'IP')}
            className="px-2 py-0.5 rounded bg-surface-secondary hover:bg-surface-secondary/80 text-foreground border border-border text-[10px] transition-colors cursor-pointer"
          >
            185.220.101.42 (C2 IP)
          </button>
          <button
            type="button"
            onClick={() => handleQuickSample('192.168.1.1', 'IP')}
            className="px-2 py-0.5 rounded bg-surface-secondary hover:bg-surface-secondary/80 text-warning border border-border text-[10px] transition-colors cursor-pointer"
          >
            192.168.1.1 (Internal Blocked Test)
          </button>
          <button
            type="button"
            onClick={() => handleQuickSample('4a7d1ed414474e4033ac29ccb8653d9b', 'MD5')}
            className="px-2 py-0.5 rounded bg-surface-secondary hover:bg-surface-secondary/80 text-foreground border border-border text-[10px] transition-colors cursor-pointer"
          >
            4a7d1ed... (Malware Hash)
          </button>
        </div>

        {/* Search Result View */}
        {hasSearched && (
          <div className="pt-2">
            {lookupError ? (
              <div className="p-3.5 rounded-lg bg-danger-surface border border-danger-border flex items-center space-x-2 text-xs font-mono text-danger">
                <AlertTriangle className="w-4 h-4 shrink-0" />
                <span>{lookupError}</span>
              </div>
            ) : intelligenceResult ? (
              <IndicatorIntelligencePanel
                intelligence={intelligenceResult}
                onRefresh={(updated) => setIntelligenceResult(updated)}
                defaultExpanded={true}
              />
            ) : null}
          </div>
        )}
      </div>

      {/* Tracked Threat Campaign Clusters */}
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
            <p className="text-xs text-foreground-muted max-w-sm mx-auto font-mono">
              Campaigns are automatically created when multiple indicators share common infrastructure, subject patterns, and ASN associations.
            </p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {clusters.map((c) => (
              <div
                key={c.campaign_id}
                onClick={() => setActiveCluster(c)}
                className={`p-4 bg-surface border rounded-xl space-y-2 cursor-pointer transition-all hover:border-primary ${
                  activeCluster?.campaign_id === c.campaign_id
                    ? 'border-primary ring-1 ring-primary'
                    : 'border-border'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="font-bold text-xs text-foreground font-sans">{c.name}</span>
                  <span className="text-[10px] font-mono font-bold text-primary px-1.5 py-0.5 rounded bg-surface-secondary border border-border">
                    {Math.round(c.overall_confidence * 100)}% Conf
                  </span>
                </div>
                <div className="text-[11px] font-mono text-foreground-muted">
                  Attack Type: <strong className="text-foreground">{c.dominant_attack_type}</strong>
                </div>
                <div className="flex items-center justify-between text-[10px] font-mono text-foreground-muted/80 pt-1 border-t border-border/50">
                  <span>Emails: {c.email_count}</span>
                  <span>Domains: {c.domain_count}</span>
                  <span>IPs: {c.ip_count}</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
