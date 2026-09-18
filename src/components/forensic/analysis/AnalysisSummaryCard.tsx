import React, { useMemo } from 'react';
import type { EmailAnalysis } from '../../../types/forensic';
import {
  ShieldAlert,
  Target,
  Link2,
  AlertTriangle,
  BrainCircuit,
  FileSearch,
  ArrowDownRight
} from 'lucide-react';

interface AnalysisSummaryCardProps {
  email: EmailAnalysis;
  onJumpToSection?: (sectionId: string) => void;
}

export const AnalysisSummaryCard: React.FC<AnalysisSummaryCardProps> = ({
  email,
  onJumpToSection
}) => {
  const indicators = email.indicators || {};

  // 1. Extracted Indicators Metrics
  const totalIps = (indicators.ips?.length || email.ips?.length || 0);
  const totalDomains = (indicators.domains?.length || email.domains?.length || 0);
  const totalUrls = (indicators.urls?.length || email.urls?.length || email.url_analysis?.length || 0);
  const totalEmails = (indicators.email_addresses?.length || email.emails?.length || 0);
  const totalAttachments = (indicators.attachments?.length || email.attachments?.length || 0);
  const totalExtracted = totalIps + totalDomains + totalUrls + totalEmails + totalAttachments;

  // 2. Suspicious Indicators Count
  const suspiciousUrlsCount = (email.url_analysis || []).filter(
    (u) => u.suspicion_score >= 25 || u.features?.display_link_mismatch
  ).length;

  const lookalikesCount = email.lookalike_domains?.length || 0;

  const suspiciousAttachmentsCount = (email.attachments || []).filter(
    (att) =>
      att.filename?.match(/\.(exe|scr|bat|cmd|vbs|js|ps1|hta|iso|zip|rar)$/i) ||
      att.mime_type?.includes('executable') ||
      att.static_analysis?.extension_mismatch ||
      att.static_analysis?.double_extension ||
      att.static_analysis?.entropy_level === 'very_high'
  ).length;

  const publicIpsCount = (indicators.ips || []).filter(
    (ip) => ip.scope === 'public'
  ).length;

  const totalSuspicious =
    suspiciousUrlsCount +
    lookalikesCount +
    suspiciousAttachmentsCount +
    (email.authentication?.alignment?.reply_to_mismatch ? 1 : 0);

  // 3. Domain Anomalies
  const topLookalike = email.lookalike_domains && email.lookalike_domains.length > 0
    ? email.lookalike_domains[0]
    : null;

  // 4. Social Engineering / Linguistic Signals
  const linguisticSignals = useMemo(() => {
    const list: string[] = [];
    const text = `${email.subject || ''} ${email.plain_text_body || ''}`.toLowerCase();

    if (/urgent|immediately|action required|suspended|24 hours|deadline/i.test(text)) {
      list.push('Linguistic Urgency / Artificial Time Pressure');
    }
    if (/wire|transfer|payment|invoice|remittance|bank|funds|cfo/i.test(text)) {
      list.push('Financial Wire Lure / Transaction Coercion');
    }
    if (/password|credential|login|verify account|sign-in|reset/i.test(text)) {
      list.push('Credential Harvesting Pretext');
    }
    if (/confidential|private|do not tell|bypass|executive request/i.test(text)) {
      list.push('Authority Coercion & Secrecy Demand');
    }
    if (list.length === 0 && email.ml_assessment?.classification === 'phishing') {
      list.push('Social Engineering Persuasion Vector');
    }
    return list;
  }, [email.subject, email.plain_text_body, email.ml_assessment]);

  return (
    <div className="p-4 rounded-xl bg-surface border border-border space-y-4 shadow-xs font-mono">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-border">
        <div className="flex items-center space-x-2">
          <FileSearch className="w-4 h-4 text-primary" />
          <h3 className="text-xs font-bold text-foreground uppercase tracking-wider">
            Analysis Triage Summary
          </h3>
        </div>
        <span className="text-[11px] text-foreground-muted">
          Consolidated threat telemetry across 5 forensic dimensions
        </span>
      </div>

      {/* 5-Column Compact Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
        {/* Metric 1: Extracted Indicators */}
        <button
          type="button"
          onClick={() => onJumpToSection?.('indicators')}
          className="p-3 rounded-xl bg-surface-secondary/50 hover:bg-surface-secondary border border-border text-left transition-all cursor-pointer group flex flex-col justify-between"
        >
          <div>
            <div className="flex items-center justify-between text-foreground-muted text-[10px] uppercase font-bold tracking-wider mb-1">
              <span className="flex items-center gap-1">
                <Target className="w-3 h-3 text-primary" />
                <span>Extracted IOCs</span>
              </span>
              <ArrowDownRight className="w-3 h-3 text-foreground-subtle group-hover:text-primary transition-colors" />
            </div>
            <div className="text-xl font-bold text-foreground">
              {totalExtracted}
            </div>
          </div>
          <div className="text-[10px] text-foreground-muted truncate pt-1">
            {totalIps} IPs · {totalDomains} Dom · {totalUrls} URLs
          </div>
        </button>

        {/* Metric 2: Suspicious Indicators */}
        <button
          type="button"
          onClick={() => onJumpToSection?.('indicators')}
          className={`p-3 rounded-xl border text-left transition-all cursor-pointer group flex flex-col justify-between ${
            totalSuspicious > 0
              ? 'bg-warning-surface/30 border-warning-border/80 hover:bg-warning-surface/50'
              : 'bg-surface-secondary/50 border-border hover:bg-surface-secondary'
          }`}
        >
          <div>
            <div className="flex items-center justify-between text-[10px] uppercase font-bold tracking-wider mb-1">
              <span className={`flex items-center gap-1 ${totalSuspicious > 0 ? 'text-warning' : 'text-foreground-muted'}`}>
                <ShieldAlert className="w-3 h-3" />
                <span>Suspicious IOCs</span>
              </span>
              <ArrowDownRight className="w-3 h-3 text-foreground-subtle group-hover:text-warning transition-colors" />
            </div>
            <div className={`text-xl font-bold ${totalSuspicious > 0 ? 'text-warning' : 'text-foreground'}`}>
              {totalSuspicious}
            </div>
          </div>
          <div className="text-[10px] text-foreground-muted truncate pt-1">
            {suspiciousUrlsCount > 0 ? `${suspiciousUrlsCount} URLs flagged` : publicIpsCount > 0 ? `${publicIpsCount} Public IPs` : 'No IOC anomalies'}
          </div>
        </button>

        {/* Metric 3: URLs */}
        <button
          type="button"
          onClick={() => onJumpToSection?.('urls')}
          className={`p-3 rounded-xl border text-left transition-all cursor-pointer group flex flex-col justify-between ${
            suspiciousUrlsCount > 0
              ? 'bg-danger-surface/20 border-danger-border/80 hover:bg-danger-surface/40'
              : 'bg-surface-secondary/50 border-border hover:bg-surface-secondary'
          }`}
        >
          <div>
            <div className="flex items-center justify-between text-[10px] uppercase font-bold tracking-wider mb-1">
              <span className={`flex items-center gap-1 ${suspiciousUrlsCount > 0 ? 'text-danger' : 'text-foreground-muted'}`}>
                <Link2 className="w-3 h-3" />
                <span>URLs</span>
              </span>
              <ArrowDownRight className="w-3 h-3 text-foreground-subtle group-hover:text-danger transition-colors" />
            </div>
            <div className={`text-xl font-bold ${suspiciousUrlsCount > 0 ? 'text-danger' : 'text-foreground'}`}>
              {totalUrls}
            </div>
          </div>
          <div className="text-[10px] text-foreground-muted truncate pt-1">
            {suspiciousUrlsCount > 0 ? `${suspiciousUrlsCount} Risky / Mismatch` : 'Clean link telemetry'}
          </div>
        </button>

        {/* Metric 4: Domain Anomalies */}
        <button
          type="button"
          onClick={() => onJumpToSection?.('lookalikes')}
          className={`p-3 rounded-xl border text-left transition-all cursor-pointer group flex flex-col justify-between ${
            lookalikesCount > 0
              ? 'bg-danger-surface/20 border-danger-border/80 hover:bg-danger-surface/40'
              : 'bg-surface-secondary/50 border-border hover:bg-surface-secondary'
          }`}
        >
          <div>
            <div className="flex items-center justify-between text-[10px] uppercase font-bold tracking-wider mb-1">
              <span className={`flex items-center gap-1 ${lookalikesCount > 0 ? 'text-danger' : 'text-foreground-muted'}`}>
                <AlertTriangle className="w-3 h-3" />
                <span>Domain Anomalies</span>
              </span>
              <ArrowDownRight className="w-3 h-3 text-foreground-subtle group-hover:text-danger transition-colors" />
            </div>
            <div className={`text-xl font-bold ${lookalikesCount > 0 ? 'text-danger' : 'text-foreground'}`}>
              {lookalikesCount}
            </div>
          </div>
          <div className="text-[10px] text-foreground-muted truncate pt-1" title={topLookalike ? `Mimics ${topLookalike.brand_name || topLookalike.suspected_brand}` : 'No lookalikes'}>
            {topLookalike ? `Mimics ${topLookalike.brand_name || topLookalike.suspected_brand}` : 'Legitimate domains'}
          </div>
        </button>

        {/* Metric 5: Language & Social Engineering */}
        <button
          type="button"
          onClick={() => onJumpToSection?.('content')}
          className={`p-3 rounded-xl border text-left transition-all cursor-pointer group flex flex-col justify-between ${
            linguisticSignals.length > 0
              ? 'bg-primary/10 border-primary/40 hover:bg-primary/20'
              : 'bg-surface-secondary/50 border-border hover:bg-surface-secondary'
          }`}
        >
          <div>
            <div className="flex items-center justify-between text-[10px] uppercase font-bold tracking-wider mb-1">
              <span className="flex items-center gap-1 text-primary">
                <BrainCircuit className="w-3 h-3" />
                <span>Social Eng.</span>
              </span>
              <ArrowDownRight className="w-3 h-3 text-foreground-subtle group-hover:text-primary transition-colors" />
            </div>
            <div className="text-xl font-bold text-foreground">
              {linguisticSignals.length}
            </div>
          </div>
          <div className="text-[10px] text-foreground-muted truncate pt-1">
            {linguisticSignals.length > 0 ? 'Urgency & Lures' : 'Neutral tone'}
          </div>
        </button>
      </div>

      {/* Dynamic Summary Strip */}
      <div className="p-3 rounded-lg bg-surface-secondary/40 border border-border flex flex-wrap items-center justify-between gap-2 text-xs text-foreground-muted">
        <div className="flex items-center space-x-2 min-w-0">
          <span className="text-[10px] uppercase font-bold text-foreground">Key Vectors:</span>
          <div className="flex flex-wrap items-center gap-1.5 min-w-0">
            {lookalikesCount > 0 && (
              <span className="px-2 py-0.5 rounded text-[10px] bg-danger-surface text-danger border border-danger-border font-bold">
                Lookalike Impersonation
              </span>
            )}
            {suspiciousUrlsCount > 0 && (
              <span className="px-2 py-0.5 rounded text-[10px] bg-warning-surface text-warning border border-warning-border font-bold">
                Credential Harvester URL
              </span>
            )}
            {linguisticSignals.map((sig, i) => (
              <span
                key={i}
                className="px-2 py-0.5 rounded text-[10px] bg-primary/10 text-primary border border-primary/20"
              >
                {sig}
              </span>
            ))}
            {lookalikesCount === 0 && suspiciousUrlsCount === 0 && linguisticSignals.length === 0 && (
              <span className="text-success text-[11px]">
                No elevated threat indicators detected across analyzed vectors.
              </span>
            )}
          </div>
        </div>

        <span className="text-[10px] text-foreground-subtle hidden md:inline-block">
          Select any dimension below to inspect contextual evidence.
        </span>
      </div>
    </div>
  );
};
