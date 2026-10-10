import React, { useState, useEffect } from 'react';
import {
  Globe2,
  Shield,
  CheckCircle2,
  RefreshCw,
  Key,
  Check,
} from 'lucide-react';
import type {
  ThreatIntelProviderConfig,
  PrivacyPolicyClassification,
} from '../../types/threatIntelligence';
import { threatIntelligenceService } from '../../services/threatIntelligenceService';

export const ThreatIntelligenceSettings: React.FC = () => {
  const [providers, setProviders] = useState<ThreatIntelProviderConfig[]>([]);
  const [loading, setLoading] = useState(true);
  const [editingProvider, setEditingProvider] = useState<ThreatIntelProviderConfig | null>(null);
  const [apiKeyInput, setApiKeyInput] = useState('');
  const [saveSuccess, setSaveSuccess] = useState(false);
  const [healthStatus, setHealthStatus] = useState<Record<string, string>>({});
  const [testingHealth, setTestingHealth] = useState<Record<string, boolean>>({});

  // Privacy Policy test classifier
  const [testIndicator, setTestIndicator] = useState('192.168.1.1');
  const [classification, setClassification] = useState<PrivacyPolicyClassification | null>(null);

  useEffect(() => {
    loadProviders();
    testPrivacyRule('192.168.1.1');
  }, []);

  const loadProviders = async () => {
    try {
      setLoading(true);
      const res = await threatIntelligenceService.listProviders();
      setProviders(res);
    } catch (err) {
      console.error('Failed to load providers:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleToggle = async (provider: ThreatIntelProviderConfig) => {
    try {
      const updated = await threatIntelligenceService.updateProvider(provider.provider_name, {
        enabled: !provider.enabled,
      });
      setProviders((prev) =>
        prev.map((p) => (p.provider_name === updated.provider_name ? updated : p))
      );
    } catch (err) {
      console.error('Failed to toggle provider:', err);
    }
  };

  const handleTestHealth = async (providerName: string) => {
    try {
      setTestingHealth((prev) => ({ ...prev, [providerName]: true }));
      const res = await threatIntelligenceService.checkProviderHealth(providerName);
      setHealthStatus((prev) => ({ ...prev, [providerName]: res.status }));
    } catch (err: any) {
      setHealthStatus((prev) => ({ ...prev, [providerName]: 'ERROR' }));
    } finally {
      setTestingHealth((prev) => ({ ...prev, [providerName]: false }));
    }
  };

  const handleSaveApiKey = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingProvider) return;
    try {
      const updated = await threatIntelligenceService.updateProvider(editingProvider.provider_name, {
        api_key: apiKeyInput,
      });
      setProviders((prev) =>
        prev.map((p) => (p.provider_name === updated.provider_name ? updated : p))
      );
      setEditingProvider(null);
      setApiKeyInput('');
      setSaveSuccess(true);
      setTimeout(() => setSaveSuccess(false), 3000);
    } catch (err) {
      console.error('Failed to save API key:', err);
    }
  };

  const testPrivacyRule = async (val: string) => {
    if (!val.trim()) return;
    try {
      const res = await threatIntelligenceService.classifyPrivacy(val.trim());
      setClassification(res);
    } catch (err) {
      console.error('Privacy classification error:', err);
    }
  };

  return (
    <div className="space-y-6">
      {saveSuccess && (
        <div className="p-3.5 rounded-lg bg-success-surface border border-success-border text-success text-xs font-mono flex items-center space-x-2 animate-in fade-in">
          <CheckCircle2 className="w-4 h-4 text-success shrink-0" />
          <span>Provider credentials saved successfully on the secure server-side vault.</span>
        </div>
      )}

      {/* Provider Matrix Card */}
      <div className="bg-surface border border-border rounded-xl p-5 space-y-4">
        <div className="flex items-center justify-between border-b border-border pb-3">
          <div className="flex items-center space-x-2">
            <Globe2 className="w-4 h-4 text-primary" />
            <h3 className="text-xs font-mono font-bold text-foreground uppercase tracking-wide">
              External Threat Intelligence Providers
            </h3>
          </div>
          <button
            onClick={loadProviders}
            className="text-foreground-muted hover:text-foreground text-xs font-mono flex items-center space-x-1 cursor-pointer"
          >
            <RefreshCw className="w-3 h-3" />
            <span>Reload</span>
          </button>
        </div>

        <p className="text-xs text-foreground-muted font-mono">
          Configure external reputation feeds, execution priority, rate limits, and server-side API keys.
          Internal Threat Memory is evaluated first before any external queries are dispatched.
        </p>

        {loading ? (
          <div className="p-6 text-center text-xs font-mono text-foreground-muted">
            Loading threat intelligence providers...
          </div>
        ) : (
          <div className="divide-y divide-border/60">
            {providers.map((prov) => (
              <div
                key={prov.id}
                className="py-3 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs font-mono"
              >
                <div className="space-y-1">
                  <div className="flex items-center space-x-2">
                    <span className="font-bold text-foreground">{prov.display_name}</span>
                    <span className="text-[10px] text-foreground-muted">
                      (Priority: #{prov.priority})
                    </span>
                    <span
                      className={`px-1.5 py-0.2 rounded text-[10px] font-bold ${
                        prov.status === 'HEALTHY'
                          ? 'bg-success-surface text-success border border-success-border'
                          : 'bg-warning-surface text-warning border border-warning-border'
                      }`}
                    >
                      {healthStatus[prov.provider_name] || prov.status}
                    </span>
                    {prov.is_configured && (
                      <span className="text-[10px] text-primary flex items-center">
                        <Check className="w-2.5 h-2.5 mr-0.5" /> Credential Set
                      </span>
                    )}
                  </div>
                  <div className="text-[10px] text-foreground-muted flex flex-wrap gap-1">
                    <span>Types:</span>
                    {prov.supported_types.map((t, idx) => (
                      <span key={idx} className="bg-surface-secondary px-1 rounded border border-border">
                        {t}
                      </span>
                    ))}
                    <span className="ml-2">Rate: {prov.rate_limit_per_minute}/min</span>
                    <span className="ml-1">Timeout: {prov.timeout_seconds}s</span>
                  </div>
                </div>

                <div className="flex items-center space-x-2 shrink-0">
                  <button
                    onClick={() => handleTestHealth(prov.provider_name)}
                    disabled={testingHealth[prov.provider_name]}
                    className="px-2.5 py-1 rounded bg-surface-secondary hover:bg-surface-secondary/80 text-foreground-muted hover:text-foreground border border-border text-[11px] transition-colors cursor-pointer"
                  >
                    {testingHealth[prov.provider_name] ? 'Testing...' : 'Test Health'}
                  </button>

                  {prov.provider_name !== 'internal_threat_memory' && prov.provider_name !== 'cyberguard_feed' && (
                    <button
                      onClick={() => {
                        setEditingProvider(prov);
                        setApiKeyInput('');
                      }}
                      className="px-2.5 py-1 rounded bg-surface-secondary hover:bg-surface-secondary/80 text-primary border border-border text-[11px] flex items-center space-x-1 cursor-pointer"
                    >
                      <Key className="w-3 h-3" />
                      <span>{prov.is_configured ? 'Update Key' : 'Configure Key'}</span>
                    </button>
                  )}

                  <button
                    onClick={() => handleToggle(prov)}
                    className={`px-2.5 py-1 rounded font-bold text-[11px] transition-colors cursor-pointer ${
                      prov.enabled
                        ? 'bg-primary text-primary-foreground'
                        : 'bg-surface-secondary text-foreground-muted border border-border'
                    }`}
                  >
                    {prov.enabled ? 'Enabled' : 'Disabled'}
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* API Key Modal */}
      {editingProvider && (
        <div className="fixed inset-0 z-50 bg-background/80 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-surface border border-border rounded-xl max-w-md w-full p-5 space-y-4 shadow-xl font-mono text-xs">
            <div className="flex items-center justify-between border-b border-border pb-3">
              <div className="flex items-center space-x-2">
                <Key className="w-4 h-4 text-primary" />
                <h3 className="font-bold text-foreground">
                  Configure API Key: {editingProvider.display_name}
                </h3>
              </div>
              <button
                onClick={() => setEditingProvider(null)}
                className="text-foreground-muted hover:text-foreground cursor-pointer text-sm"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleSaveApiKey} className="space-y-3">
              <div>
                <label className="block text-foreground-muted text-[11px] mb-1">
                  Secret Provider API Key
                </label>
                <input
                  type="password"
                  value={apiKeyInput}
                  onChange={(e) => setApiKeyInput(e.target.value)}
                  placeholder="Enter secret API key or token..."
                  className="w-full p-2 bg-surface-secondary border border-border rounded-lg text-foreground text-xs focus:outline-none focus:border-primary"
                  required
                />
                <span className="text-[10px] text-foreground-muted block mt-1">
                  Guaranteed security: Credentials are stored server-side and never returned to the frontend.
                </span>
              </div>

              <div className="flex justify-end space-x-2 pt-2">
                <button
                  type="button"
                  onClick={() => setEditingProvider(null)}
                  className="px-3 py-1.5 rounded bg-surface-secondary text-foreground-muted hover:text-foreground border border-border cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-3 py-1.5 rounded bg-primary text-primary-foreground font-bold hover:bg-primary-hover transition-colors cursor-pointer"
                >
                  Save Credential
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Privacy Policy Gatekeeper & Interactive Classifier */}
      <div className="bg-surface border border-border rounded-xl p-5 space-y-4 font-mono text-xs">
        <div className="flex items-center space-x-2 border-b border-border pb-3">
          <Shield className="w-4 h-4 text-primary" />
          <h3 className="font-bold text-foreground uppercase tracking-wide">
            Indicator Privacy Policy & SSRF Safeguards
          </h3>
        </div>

        <p className="text-foreground-muted leading-relaxed">
          CyberGuard enforces mandatory security safeguards to prevent data leakage and Server-Side Request Forgery (SSRF).
          Private RFC-1918 subnets, internal active directory domains, and sensitive credentials are automatically blocked from external queries.
        </p>

        {/* Interactive Classifier Test */}
        <div className="bg-surface-secondary/40 border border-border rounded-lg p-3.5 space-y-2.5">
          <label className="text-[11px] font-bold text-foreground block">
            Test Privacy Classification (Live Policy Simulator):
          </label>
          <div className="flex items-center space-x-2">
            <input
              type="text"
              value={testIndicator}
              onChange={(e) => {
                setTestIndicator(e.target.value);
                testPrivacyRule(e.target.value);
              }}
              placeholder="e.g. 10.0.0.5, evil-phish.com, corp.internal"
              className="flex-grow p-2 bg-surface border border-border rounded text-xs text-foreground focus:outline-none focus:border-primary"
            />
            <button
              type="button"
              onClick={() => testPrivacyRule(testIndicator)}
              className="px-3 py-2 rounded bg-surface border border-border hover:bg-surface/80 text-foreground font-semibold cursor-pointer"
            >
              Classify
            </button>
          </div>

          {classification && (
            <div className="p-2.5 rounded bg-surface border border-border flex items-center justify-between text-[11px]">
              <div>
                <span className="text-foreground-muted mr-1">Scope:</span>
                <span
                  className={`font-bold px-1.5 py-0.5 rounded border ${
                    classification.privacy_scope === 'INTERNAL'
                      ? 'bg-warning-surface text-warning border-warning-border'
                      : 'bg-success-surface text-success border-success-border'
                  }`}
                >
                  {classification.privacy_scope}
                </span>
                <span className="text-foreground-muted ml-2">External Query:</span>
                <strong className={`ml-1 ${classification.external_lookup_permitted ? 'text-success' : 'text-danger'}`}>
                  {classification.external_lookup_permitted ? 'ALLOWED' : 'BLOCKED'}
                </strong>
              </div>
              <span className="text-foreground-muted text-[10px]">{classification.reason}</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
