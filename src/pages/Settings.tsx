import React, { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  Sliders,
  Shield,
  CheckCircle2,
  Save,
  Cpu,
  Palette,
  Check,
  Share2,
  ExternalLink,
  Laptop
} from 'lucide-react';
import { INITIAL_SETTINGS } from '../config/systemSettings';
import type { SystemSettings } from '../types';
import { useTheme, THEME_OPTIONS, type AppTheme } from '../context/ThemeContext';
import { cn } from '../utils/cn';

export const Settings: React.FC = () => {
  const { tab } = useParams<{ tab?: string }>();
  const navigate = useNavigate();
  const [settings, setSettings] = useState<SystemSettings>(INITIAL_SETTINGS);
  const [saveSuccess, setSaveSuccess] = useState(false);
  const { theme, setTheme } = useTheme();

  // Active sub-tab state
  const activeTab = tab?.toLowerCase() || 'appearance';

  const SETTINGS_TABS = [
    { id: 'appearance', label: 'Appearance', icon: Palette },
    { id: 'detection', label: 'Detection', icon: Cpu },
    { id: 'integrations', label: 'Integrations', icon: Share2 },
    { id: 'agents', label: 'Agents', icon: Laptop },
    { id: 'security', label: 'Security', icon: Shield },
  ];

  const handleSelectTab = (tabId: string) => {
    navigate(`/settings/${tabId}`);
  };

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    setSaveSuccess(true);
    setTimeout(() => setSaveSuccess(false), 3000);
  };

  return (
    <div className="space-y-6 pb-12">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-surface p-6 rounded-xl border border-border">
        <div>
          <div className="flex items-center space-x-2 text-primary font-mono text-xs mb-1 font-semibold uppercase tracking-wider">
            <Sliders className="w-3.5 h-3.5 text-primary" />
            <span>SOC SYSTEM CONFIGURATION & PRIVACY SAFEGUARDS</span>
          </div>
          <h1 className="text-xl font-bold text-foreground font-sans tracking-tight">
            Platform & Visual Settings
          </h1>
          <p className="text-xs text-foreground-muted font-mono mt-1">
            Configure visual themes, PII data masking, legal retention schedules, and automated alert triggers.
          </p>
        </div>

        <button
          type="button"
          onClick={handleSave}
          className="flex items-center space-x-2 px-4 py-2 rounded-lg bg-primary hover:bg-primary-hover text-primary-foreground font-mono font-semibold text-xs tracking-wider transition-colors btn-press cursor-pointer"
        >
          <Save className="w-3.5 h-3.5" />
          <span>SAVE CONFIGURATION</span>
        </button>
      </div>

      {saveSuccess && (
        <div className="p-3.5 rounded-lg bg-success-surface border border-success-border text-success text-xs font-mono flex items-center space-x-2 animate-in fade-in">
          <CheckCircle2 className="w-4 h-4 text-success flex-shrink-0" />
          <span>System configuration saved successfully. All privacy masking and retention rules updated.</span>
        </div>
      )}

      {/* Settings Navigation Tabs */}
      <div className="flex items-center gap-1.5 p-1 bg-surface-secondary/70 border border-border rounded-lg overflow-x-auto">
        {SETTINGS_TABS.map((t) => {
          const Icon = t.icon;
          const isCurrent = activeTab === t.id;
          return (
            <button
              key={t.id}
              type="button"
              onClick={() => handleSelectTab(t.id)}
              className={cn(
                'flex items-center space-x-2 px-3.5 py-1.5 rounded-md text-xs font-mono font-medium transition-all cursor-pointer whitespace-nowrap',
                isCurrent
                  ? 'bg-surface text-primary shadow-xs font-semibold border border-border'
                  : 'text-foreground-muted hover:text-foreground hover:bg-surface/50'
              )}
            >
              <Icon className="w-3.5 h-3.5" />
              <span>{t.label}</span>
            </button>
          );
        })}
      </div>

      {/* Tab 1: Appearance */}
      {(activeTab === 'appearance' || !tab) && (
        <div className="bg-surface border border-border rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-border pb-3">
            <div className="flex items-center space-x-2">
              <Palette className="w-4 h-4 text-primary" />
              <h3 className="text-xs font-mono font-bold text-foreground uppercase tracking-wide">
                Interface Theme & Visual Appearance
              </h3>
            </div>
            <span className="text-[11px] font-mono text-foreground-muted">
              4 Calibrated Palettes • Instant Live Preview
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
            {THEME_OPTIONS.map((opt) => {
              const isSelected = theme === opt.id;
              return (
                <button
                  key={opt.id}
                  type="button"
                  onClick={() => setTheme(opt.id as AppTheme)}
                  className={`flex flex-col text-left p-3.5 rounded-xl border transition-all cursor-pointer btn-press ${
                    isSelected
                      ? 'border-primary bg-primary-subtle ring-1 ring-primary'
                      : 'border-border bg-surface-secondary/60 hover:bg-surface-secondary hover:border-foreground-muted'
                  }`}
                >
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center space-x-2">
                      <span
                        className="w-3.5 h-3.5 rounded-full border border-border shadow-xs"
                        style={{ backgroundColor: opt.previewAccent }}
                      />
                      <span className="font-sans font-bold text-xs text-foreground">
                        {opt.name}
                      </span>
                    </div>
                    {isSelected && (
                      <span className="flex items-center justify-center w-4 h-4 rounded-full bg-primary text-primary-foreground text-[10px]">
                        <Check className="w-2.5 h-2.5" />
                      </span>
                    )}
                  </div>

                  {/* Color swatches preview bar */}
                  <div className="flex items-center space-x-1.5 p-1 rounded bg-surface border border-border mb-2.5">
                    <span
                      className="flex-1 h-3 rounded-xs border border-border"
                      style={{ backgroundColor: opt.previewBg }}
                      title="Background"
                    />
                    <span
                      className="flex-1 h-3 rounded-xs border border-border"
                      style={{ backgroundColor: opt.previewSurface }}
                      title="Surface Card"
                    />
                    <span
                      className="flex-1 h-3 rounded-xs"
                      style={{ backgroundColor: opt.previewAccent }}
                      title="Accent Primary"
                    />
                  </div>

                  <p className="text-[11px] text-foreground-muted leading-relaxed font-sans line-clamp-2">
                    {opt.description}
                  </p>

                  <div className="mt-2.5 pt-2 border-t border-border/60 flex items-center justify-between text-[10px] font-mono text-foreground-muted">
                    <span>{opt.accentLabel}</span>
                    <span className="capitalize">{opt.isDark ? 'Dark' : 'Light'}</span>
                  </div>
                </button>
              );
            })}
          </div>
        </div>
      )}

      {/* Tab 2: Detection */}
      {(activeTab === 'detection' || !tab) && (
        <div className="bg-surface border border-border rounded-xl p-5 space-y-4">
          <div className="flex items-center space-x-2 border-b border-border pb-3">
            <Cpu className="w-4 h-4 text-primary" />
            <h3 className="text-xs font-mono font-bold text-foreground uppercase tracking-wide">
              AI Detection Thresholds & Threat Escalation
            </h3>
          </div>

          <div className="space-y-4 text-xs font-mono max-w-2xl">
            {/* Auto Escalate Threshold Slider */}
            <div>
              <div className="flex justify-between mb-1.5">
                <span className="text-foreground font-semibold">Auto-Escalation Risk Threshold:</span>
                <span className="text-primary font-bold">{settings.autoEscalateThreshold}%</span>
              </div>
              <input
                type="range"
                min="50"
                max="95"
                value={settings.autoEscalateThreshold}
                onChange={(e) => setSettings({ ...settings, autoEscalateThreshold: Number(e.target.value) })}
                className="w-full h-1.5 bg-surface-secondary rounded-lg appearance-none cursor-pointer accent-primary"
              />
              <span className="text-[10px] text-foreground-muted mt-1 block">
                Emails scoring above {settings.autoEscalateThreshold}% will trigger immediate SOC alert dispatch and quarantine.
              </span>
            </div>
          </div>
        </div>
      )}

      {/* Tab 3: Integrations */}
      {(activeTab === 'integrations' || !tab) && (
        <div className="bg-surface border border-border rounded-xl p-5 space-y-4">
          <div className="flex items-center space-x-2 border-b border-border pb-3">
            <Share2 className="w-4 h-4 text-primary" />
            <h3 className="text-xs font-mono font-bold text-foreground uppercase tracking-wide">
              External SIEM & Webhook Integrations
            </h3>
          </div>

          <div className="space-y-4 text-xs font-mono max-w-2xl">
            {/* Webhook Endpoint Input */}
            <div>
              <label className="block text-foreground font-semibold mb-1.5">
                SIEM / SOC Alert Webhook Endpoint
              </label>
              <input
                type="text"
                value={settings.webhookUrl}
                onChange={(e) => setSettings({ ...settings, webhookUrl: e.target.value })}
                className="w-full p-2 bg-surface-secondary border border-border rounded-lg text-foreground focus:outline-none focus:border-primary text-xs"
              />
            </div>

            {/* Allowed Subnets */}
            <div>
              <label className="block text-foreground font-semibold mb-1.5">
                Internal Gateway Allowed IP Subnets
              </label>
              <input
                type="text"
                value={settings.allowedIpSubnets}
                onChange={(e) => setSettings({ ...settings, allowedIpSubnets: e.target.value })}
                className="w-full p-2 bg-surface-secondary border border-border rounded-lg text-foreground focus:outline-none focus:border-primary text-xs"
              />
            </div>
          </div>
        </div>
      )}

      {/* Tab 4: Agents */}
      {(activeTab === 'agents' || !tab) && (
        <div className="bg-surface border border-border rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-border pb-3">
            <div className="flex items-center space-x-2">
              <Laptop className="w-4 h-4 text-primary" />
              <h3 className="text-xs font-mono font-bold text-foreground uppercase tracking-wide">
                Endpoint Telemetry Agents Status & Configuration
              </h3>
            </div>
            <button
              type="button"
              onClick={() => navigate('/endpoints')}
              className="flex items-center space-x-1.5 text-xs font-mono text-primary hover:underline cursor-pointer"
            >
              <span>Manage Endpoints</span>
              <ExternalLink className="w-3 h-3" />
            </button>
          </div>

          <div className="p-4 rounded-lg bg-surface-secondary border border-border text-xs font-mono space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-foreground font-semibold">Endpoint Telemetry Ingestion Service</span>
              <span className="text-success font-bold flex items-center space-x-1">
                <span className="w-2 h-2 rounded-full bg-success inline-block" />
                <span>ONLINE</span>
              </span>
            </div>
            <p className="text-[11px] text-foreground-muted leading-relaxed">
              CyberGuard ingests real-time endpoint telemetry from registered Windows, macOS, and Linux sensor daemons. Device telemetry correlates automatically with incident dossiers.
            </p>
          </div>
        </div>
      )}

      {/* Tab 5: Security & Compliance */}
      {(activeTab === 'security' || !tab) && (
        <div className="bg-surface border border-border rounded-xl p-5 space-y-4">
          <div className="flex items-center space-x-2 border-b border-border pb-3">
            <Shield className="w-4 h-4 text-primary" />
            <h3 className="text-xs font-mono font-bold text-foreground uppercase tracking-wide">
              Privacy, Legal & Compliance Safeguards
            </h3>
          </div>

          <div className="space-y-3.5 text-xs font-mono max-w-2xl">
            {/* Toggle 1: PII Anonymization */}
            <div className="flex items-center justify-between p-3 rounded-lg bg-surface-secondary border border-border">
              <div>
                <span className="text-foreground font-semibold block">PII Target Email Anonymization</span>
                <span className="text-foreground-muted text-[11px] block mt-0.5">
                  Mask personal names and internal email addresses in external reports
                </span>
              </div>
              <button
                type="button"
                onClick={() => setSettings({ ...settings, anonymizeTargetPII: !settings.anonymizeTargetPII })}
                className={`w-11 h-6 rounded-full transition-colors relative cursor-pointer ${
                  settings.anonymizeTargetPII ? 'bg-primary' : 'bg-surface border border-border'
                }`}
                aria-label="Toggle PII anonymization"
              >
                <div
                  className={`w-4 h-4 rounded-full absolute top-1 transition-transform ${
                    settings.anonymizeTargetPII
                      ? 'right-1 bg-primary-foreground'
                      : 'left-1 bg-foreground-muted'
                  }`}
                />
              </button>
            </div>

            {/* Toggle 2: SHA-256 Chain of Custody */}
            <div className="flex items-center justify-between p-3 rounded-lg bg-surface-secondary border border-border">
              <div>
                <span className="text-foreground font-semibold block">SHA-256 Cryptographic Chain of Custody</span>
                <span className="text-foreground-muted text-[11px] block mt-0.5">
                  Generate immutable evidentiary hash signatures for all analyst audit logs
                </span>
              </div>
              <button
                type="button"
                onClick={() => setSettings({ ...settings, sha256ChainOfCustody: !settings.sha256ChainOfCustody })}
                className={`w-11 h-6 rounded-full transition-colors relative cursor-pointer ${
                  settings.sha256ChainOfCustody ? 'bg-primary' : 'bg-surface border border-border'
                }`}
                aria-label="Toggle SHA-256 chain of custody"
              >
                <div
                  className={`w-4 h-4 rounded-full absolute top-1 transition-transform ${
                    settings.sha256ChainOfCustody
                      ? 'right-1 bg-primary-foreground'
                      : 'left-1 bg-foreground-muted'
                  }`}
                />
              </button>
            </div>

            {/* Retention Period Dropdown */}
            <div>
              <label className="block text-foreground font-semibold mb-1.5">
                Evidence & Header Retention Schedule
              </label>
              <select
                value={settings.retentionPeriodDays}
                onChange={(e) => setSettings({ ...settings, retentionPeriodDays: Number(e.target.value) })}
                className="w-full p-2 bg-surface-secondary border border-border rounded-lg text-foreground focus:outline-none focus:border-primary text-xs"
              >
                <option value={30}>30 Days (Standard Corporate Policy)</option>
                <option value={90}>90 Days (Extended Regulatory Audit)</option>
                <option value={365}>365 Days (Legal Investigation Compliance)</option>
              </select>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
