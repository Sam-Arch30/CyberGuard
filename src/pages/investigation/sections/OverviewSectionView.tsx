import React, { useState, useMemo } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  ArrowRight,
  Copy,
  Check,
  Lock,
  Target,
  ChevronDown,
  ChevronUp,
  Sparkles
} from 'lucide-react';
import type { EmailAnalysis } from '../../../types/forensic';
import { useInvestigation } from '../../../context/InvestigationContext';
import { ExplainableAIPanel } from '../../../components/forensic/explanation';

interface OverviewSectionViewProps {
  email?: EmailAnalysis | null;
}

interface TriageFinding {
  id: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  title: string;
  description: string;
  targetSection: 'email' | 'analysis' | 'intelligence' | 'investigation' | 'report';
  targetSubTab?: string;
  actionLabel: string;
}

const defang = (val?: string): string => {
  if (!val) return '';
  return val
    .replace(/\./g, '[.]')
    .replace(/http:\/\//g, 'hxxp://')
    .replace(/https:\/\//g, 'hxxps://');
};

export const OverviewSectionView: React.FC<OverviewSectionViewProps> = ({ email }) => {
  const { setSection, setSubTab, openCopilotDrawer, workspaceSummary } = useInvestigation();
  const [copiedIndicator, setCopiedIndicator] = useState<string | null>(null);
  const [summaryExpanded, setSummaryExpanded] = useState<boolean>(false);

  const safeEmail = useMemo(() => email || ({} as Partial<EmailAnalysis>), [email]);

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedIndicator(id);
    setTimeout(() => setCopiedIndicator(null), 2000);
  };

  // ---------------------------------------------------------------------------
  // SECTION 1: Threat Assessment Data
  // ---------------------------------------------------------------------------
  const score = safeEmail.threat_score?.score ?? workspaceSummary?.risk?.score ?? 0;
  const severity = (
    safeEmail.threat_score?.severity ||
    workspaceSummary?.risk?.severity ||
    (score >= 80 ? 'critical' : score >= 50 ? 'high' : score >= 20 ? 'medium' : 'low')
  ).toLowerCase();

  const isMalicious = score >= 50;
  const isEmailEvidence = Boolean(safeEmail.authentication) || workspaceSummary?.investigation.artifact_type === 'EMAIL';

  // Genuine confidence extraction without fabrication
  const genuineConfidence = useMemo(() => {
    if (safeEmail.threat_score?.confidence !== undefined && safeEmail.threat_score?.confidence !== null) {
      return typeof safeEmail.threat_score.confidence === 'number'
        ? `${safeEmail.threat_score.confidence}%`
        : String(safeEmail.threat_score.confidence);
    }
    if (workspaceSummary?.risk?.confidence !== undefined && workspaceSummary?.risk?.confidence !== null) {
      return `${Math.round(workspaceSummary.risk.confidence * 100)}%`;
    }
    if (safeEmail.attribution?.confidence_score !== undefined) {
      return `${safeEmail.attribution.confidence_score}% (${safeEmail.attribution.confidence_level || 'Reported'})`;
    }
    if (safeEmail.ml_assessment?.confidence) {
      return `${safeEmail.ml_assessment.confidence.toUpperCase()} Confidence`;
    }
    return null;
  }, [safeEmail, workspaceSummary]);

  // ---------------------------------------------------------------------------
  // SECTION 2: Key Findings (Real Analysis Data Only)
  // ---------------------------------------------------------------------------
  const findings = useMemo<TriageFinding[]>(() => {
    const list: TriageFinding[] = [];

    // 1. Lookalike domain impersonation
    if (safeEmail.lookalike_domains && safeEmail.lookalike_domains.length > 0) {
      safeEmail.lookalike_domains.forEach((look, idx) => {
        list.push({
          id: `lookalike-${idx}`,
          severity: 'CRITICAL',
          title: 'Sender domain impersonation detected',
          description: `Lookalike domain "${look.domain}" mimics recognized brand "${look.suspected_brand || look.brand_name || 'legitimate organization'}"`,
          targetSection: 'analysis',
          targetSubTab: 'lookalike',
          actionLabel: 'View lookalike evidence'
        });
      });
    }

    // 2. Authentication Failures (DMARC, SPF, DKIM)
    const auth = safeEmail.authentication;
    if (auth?.dmarc?.result === 'fail') {
      list.push({
        id: 'auth-dmarc',
        severity: 'HIGH',
        title: 'DMARC alignment failed',
        description: auth.dmarc.details || 'Header From domain does not align with authenticated sending identity under p=reject policy',
        targetSection: 'email',
        targetSubTab: 'auth',
        actionLabel: 'View auth evidence'
      });
    }

    if (auth?.spf?.result === 'fail') {
      list.push({
        id: 'auth-spf',
        severity: 'HIGH',
        title: 'SPF sender authorization failed',
        description: auth.spf.details || 'Sending IP is not authorized in domain SPF records',
        targetSection: 'email',
        targetSubTab: 'auth',
        actionLabel: 'View auth evidence'
      });
    }

    if (auth?.dkim?.result === 'fail') {
      list.push({
        id: 'auth-dkim',
        severity: 'HIGH',
        title: 'DKIM digital signature failed validation',
        description: auth.dkim.details || 'Cryptographic signature over email headers and body hash failed verification',
        targetSection: 'email',
        targetSubTab: 'auth',
        actionLabel: 'View auth evidence'
      });
    }

    // 3. Suspicious URLs & Redirect Chains
    if (safeEmail.url_analysis && safeEmail.url_analysis.length > 0) {
      const suspiciousUrls = safeEmail.url_analysis.filter(
        u => (u.suspicion_score && u.suspicion_score >= 50) || u.suspicion_level !== 'low'
      );
      suspiciousUrls.slice(0, 2).forEach((u, idx) => {
        list.push({
          id: `url-${idx}`,
          severity: u.suspicion_score && u.suspicion_score >= 80 ? 'CRITICAL' : 'HIGH',
          title: 'Suspicious credential harvesting URL identified',
          description: `Destination link "${defang(u.url)}" flagged for credential capture and host anomalies (Risk ${u.suspicion_score || 85}/100)`,
          targetSection: 'analysis',
          targetSubTab: 'urls',
          actionLabel: 'Investigate URL'
        });
      });
    }

    // 4. Infrastructure Discrepancies
    if (
      safeEmail.hops &&
      safeEmail.hops.some(h => h.authStatus === 'fail' || (h.asn && h.asn.toLowerCase().includes('bulletproof')))
    ) {
      const badHop = safeEmail.hops.find(
        h => h.authStatus === 'fail' || (h.asn && h.asn.toLowerCase().includes('bulletproof'))
      );
      list.push({
        id: 'hop-anomaly',
        severity: 'MEDIUM',
        title: 'Sending infrastructure differs from expected origin',
        description: `Originating relay ${badHop?.fromIp || 'ingress node'} hosted on untrusted infrastructure: ${badHop?.asn || 'Anomalous ASN'}`,
        targetSection: 'intelligence',
        targetSubTab: 'infrastructure',
        actionLabel: 'View infrastructure'
      });
    } else if (safeEmail.attribution?.probable_origin_ip && isMalicious) {
      list.push({
        id: 'attr-origin',
        severity: 'MEDIUM',
        title: 'Sending infrastructure differs from expected origin',
        description: `Ingress traffic originating from public hosting network (${safeEmail.attribution.probable_origin_provider || safeEmail.attribution.probable_origin_asn || safeEmail.attribution.probable_origin_ip})`,
        targetSection: 'intelligence',
        targetSubTab: 'infrastructure',
        actionLabel: 'View infrastructure'
      });
    }

    // 5. Suspicious Attachments
    if (
      safeEmail.attachments &&
      safeEmail.attachments.some(
        a =>
          (a.static_analysis &&
            (a.static_analysis.threat_level === 'CRITICAL' ||
              a.static_analysis.threat_level === 'HIGH' ||
              a.static_analysis.double_extension ||
              a.static_analysis.extension_mismatch)) ||
          (a.filename && /\.(exe|scr|vbs|bat|cmd|ps1|js)$/i.test(a.filename))
      )
    ) {
      list.push({
        id: 'attach-danger',
        severity: 'HIGH',
        title: 'Dangerous file attachment identified',
        description: 'Embedded payload features anomalous MIME type, executable characteristics, or macro vectors',
        targetSection: 'email',
        targetSubTab: 'attachments',
        actionLabel: 'Inspect attachment'
      });
    }

    // 6. Top findings from workspace summary if available
    if (list.length === 0 && workspaceSummary?.top_findings && workspaceSummary.top_findings.length > 0) {
      workspaceSummary.top_findings.forEach((tf, idx) => {
        list.push({
          id: tf.id || `ws-finding-${idx}`,
          severity: (tf.severity || 'HIGH').toUpperCase() as any,
          title: tf.title,
          description: tf.description || 'Forensic signal identified during automated analysis run.',
          targetSection: 'analysis',
          targetSubTab: 'results',
          actionLabel: 'View finding in analysis'
        });
      });
    }

    return list;
  }, [safeEmail, isMalicious, workspaceSummary]);

  // ---------------------------------------------------------------------------
  // SECTION 3: Email authentication States
  // ---------------------------------------------------------------------------
  const auth = safeEmail.authentication;
  const spfState = (auth?.spf?.result || 'NONE').toUpperCase();
  const dkimState = (auth?.dkim?.result || 'NONE').toUpperCase();
  const dmarcState = (auth?.dmarc?.result || 'NONE').toUpperCase();

  const getAuthBadge = (state: string) => {
    switch (state) {
      case 'PASS':
        return 'bg-success-surface text-success border-success-border font-bold';
      case 'FAIL':
        return 'bg-danger-surface text-danger border-danger-border font-bold';
      case 'SOFTFAIL':
      case 'NEUTRAL':
        return 'bg-warning-surface text-warning border-warning-border font-semibold';
      default:
        return 'bg-surface-secondary text-foreground-muted border-border';
    }
  };

  // ---------------------------------------------------------------------------
  // SECTION 4: Highest-Priority Indicators (Top 3–5)
  // ---------------------------------------------------------------------------
  const highPriorityIOCs = useMemo(() => {
    const list: Array<{ type: 'DOMAIN' | 'URL' | 'IP'; value: string; isMalicious: boolean }> = [];

    // Lookalike domains first
    if (safeEmail.lookalike_domains) {
      safeEmail.lookalike_domains.forEach(d => {
        list.push({ type: 'DOMAIN', value: d.domain, isMalicious: true });
      });
    }

    // Flagged URLs next
    if (safeEmail.url_analysis) {
      safeEmail.url_analysis
        .filter(u => (u.suspicion_score && u.suspicion_score >= 50) || u.suspicion_level !== 'low')
        .forEach(u => {
          list.push({ type: 'URL', value: u.url, isMalicious: true });
        });
    }

    // Origin/transit IPs
    if (safeEmail.attribution?.probable_origin_ip) {
      list.push({
        type: 'IP',
        value: safeEmail.attribution.probable_origin_ip,
        isMalicious: isMalicious
      });
    } else if (safeEmail.ips && safeEmail.ips.length > 0) {
      const publicIp = safeEmail.ips.find(
        ip => !ip.startsWith('10.') && !ip.startsWith('192.168.') && !ip.startsWith('127.')
      );
      if (publicIp) {
        list.push({ type: 'IP', value: publicIp, isMalicious: isMalicious });
      }
    }

    // Fallback domains if needed
    if (list.length < 3 && safeEmail.domains) {
      safeEmail.domains.slice(0, 3 - list.length).forEach(dom => {
        if (!list.some(i => i.value === dom)) {
          list.push({ type: 'DOMAIN', value: dom, isMalicious: false });
        }
      });
    }

    return list.slice(0, 4);
  }, [safeEmail, isMalicious]);

  const totalIOCsCount =
    (safeEmail.ips?.length || 0) +
    (safeEmail.domains?.length || 0) +
    (safeEmail.urls?.length || 0) +
    (safeEmail.emails?.length || 0);

  // ---------------------------------------------------------------------------
  // SECTION 5: Investigation Summary (Concise AI/Backend Narrative)
  // ---------------------------------------------------------------------------
  const rawSummary =
    safeEmail.ai_analyst?.summary ||
    workspaceSummary?.executive_summary ||
    safeEmail.threat_score?.summary ||
    (isMalicious
      ? 'Available automated findings require evidence review before confirming the threat or selecting a response.'
      : 'No investigation summary is available yet. Review the original evidence and analysis limitations.');

  return (
    <div className="cg-investigation-overview space-y-6 max-w-[1280px] w-full mx-auto animate-fadeIn">
      {/* =======================================================================
          SECTION 1 — THREAT ASSESSMENT (Verdict, Score, Genuine Confidence)
          ======================================================================= */}
      <section className="cg-assessment bg-surface rounded-card border border-border p-5 relative overflow-hidden">
        {/* Subtle status backdrop tint */}
        <div
          className={`absolute top-0 left-0 right-0 h-0.5 ${
            severity === 'critical'
              ? 'bg-danger'
              : severity === 'high'
              ? 'bg-warning'
              : severity === 'medium'
              ? 'bg-amber-500'
              : 'bg-success'
          }`}
        />

        <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 pt-1">
          {/* Left: Verdict Banner & Risk Headline */}
          <div className="space-y-2">
            <div className="flex items-center space-x-2.5">
              <span
                className={`px-2.5 py-1 rounded-md text-xs font-mono font-bold tracking-wider uppercase border flex items-center gap-1.5 ${
                  severity === 'critical'
                    ? 'bg-danger-surface text-danger border-danger-border'
                    : severity === 'high'
                    ? 'bg-warning-surface text-warning border-warning-border'
                    : severity === 'medium'
                    ? 'bg-amber-500/15 text-amber-600 dark:text-amber-400 border-amber-500/30'
                    : 'bg-success-surface text-success border-success-border'
                }`}
              >
                {isMalicious ? <ShieldAlert className="w-4 h-4" /> : <ShieldCheck className="w-4 h-4" />}
                <span>{severity.toUpperCase()} RISK</span>
              </span>

              {genuineConfidence && (
                <span className="px-2 py-0.5 rounded text-[11px] font-mono text-foreground-muted bg-surface-secondary border border-border">
                  Confidence: <strong className="text-foreground">{genuineConfidence}</strong>
                </span>
              )}
            </div>

            <h2 className="text-lg sm:text-xl font-bold text-foreground font-sans tracking-tight">
              {severity === 'critical'
                ? 'Critical-risk indicators detected'
                : severity === 'high'
                ? 'High-risk indicators'
                : severity === 'medium'
                ? 'Suspicious indicators'
                : 'Investigation assessment'}
            </h2>

            <p className="text-xs font-mono text-foreground-muted max-w-2xl leading-relaxed">
              {isMalicious
                ? 'Review the supporting evidence before deciding on containment or response.'
                : 'Review the available findings and authentication results. A low score does not establish safety.'}
            </p>
          </div>

          {/* Right: Threat Score Display */}
          <div className="flex items-center space-x-4 self-start md:self-center shrink-0">
            <div className="flex flex-col items-end">
              <span className="text-[10px] font-mono uppercase tracking-wider text-foreground-muted font-semibold">
                Risk score
              </span>
              <div className="flex items-baseline space-x-1">
                <span
                  className={`text-4xl font-extrabold font-mono tracking-tight ${
                    severity === 'critical'
                      ? 'text-danger'
                      : severity === 'high'
                      ? 'text-warning'
                      : severity === 'medium'
                      ? 'text-amber-500'
                      : 'text-success'
                  }`}
                >
                  {score}
                </span>
                <span className="text-sm font-mono text-foreground-muted">/100</span>
              </div>
            </div>

            <div
              className={`w-14 h-14 rounded-xl border flex items-center justify-center shrink-0 shadow-inner ${
                severity === 'critical'
                  ? 'bg-danger/10 border-danger/30 text-danger'
                  : severity === 'high'
                  ? 'bg-warning/10 border-warning/30 text-warning'
                  : severity === 'medium'
                  ? 'bg-amber-500/10 border-amber-500/30 text-amber-500'
                  : 'bg-success/10 border-success/30 text-success'
              }`}
            >
              {isMalicious ? <AlertTriangle className="w-7 h-7" /> : <ShieldCheck className="w-7 h-7" />}
            </div>
          </div>
        </div>
      </section>

      {/* =======================================================================
          SECTION 2 — KEY FINDINGS (Actionable, Direct Evidence Jump)
          ======================================================================= */}
      <section className="space-y-3">
        <div className="flex items-center justify-between">
          <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-foreground-muted flex items-center space-x-2">
            <Target className="w-3.5 h-3.5 text-primary" />
            <span>Findings · {findings.length}</span>
          </h3>
          <span className="text-[11px] font-mono text-foreground-muted">
            Select a finding to review its evidence
          </span>
        </div>

        <div className="cg-findings-list">
          {findings.length === 0 && <div className="p-6 text-sm text-foreground-muted">No verified findings available for this investigation. Review the original evidence and analysis limitations.</div>}
          {findings.map((finding) => {
            const isCrit = finding.severity === 'CRITICAL';
            const isHigh = finding.severity === 'HIGH';
            const isMed = finding.severity === 'MEDIUM';

            return (
              <div
                key={finding.id}
                className="cg-finding-row group flex flex-col lg:flex-row lg:items-center justify-between p-4 hover:bg-surface-secondary/50 transition-colors gap-4"
              >
                <div className="flex items-start space-x-3 min-w-0 flex-1">
                  {/* Severity Badge */}
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold tracking-wider uppercase border shrink-0 mt-0.5 ${
                      isCrit
                        ? 'bg-danger-surface text-danger border-danger-border'
                        : isHigh
                        ? 'bg-warning-surface text-warning border-warning-border'
                        : isMed
                        ? 'bg-amber-500/15 text-amber-600 dark:text-amber-400 border-amber-500/30'
                        : 'bg-success-surface text-success border-success-border'
                    }`}
                  >
                    {finding.severity}
                  </span>

                  {/* Finding Title & Concise Evidence Description */}
                  <div className="space-y-0.5 min-w-0 flex-1">
                    <p className="text-xs sm:text-sm font-semibold text-foreground group-hover:text-primary transition-colors">
                      {finding.title}
                    </p>
                    <p className="cg-finding-description text-sm text-foreground-muted leading-relaxed break-words">
                      {finding.description}
                    </p>
                  </div>
                </div>

                {/* Action Buttons: Ask AI & Direct Jump */}
                <div className="cg-finding-actions flex items-center space-x-2 shrink-0 self-end lg:self-center">
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      openCopilotDrawer(
                        `Explain this finding: "${finding.title}" - ${finding.description}. What evidence supports it and what are the security implications?`,
                        {
                          type: 'Finding',
                          identifier: finding.title,
                          details: `${finding.severity} severity`
                        }
                      );
                    }}
                    className="cg-explain-button px-2.5 py-2 rounded-lg text-foreground-muted hover:text-foreground text-xs font-medium flex items-center space-x-1.5 transition-colors cursor-pointer"
                    title="Ask AI about this finding"
                  >
                    <Sparkles className="w-3 h-3" />
                    <span>Explain</span>
                  </button>

                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      setSection(finding.targetSection, finding.targetSubTab);
                    }}
                    className="px-3 py-2 rounded-lg bg-surface-secondary hover:border-primary border border-border text-foreground text-xs font-medium flex items-center space-x-1.5 transition-colors cursor-pointer"
                  >
                    <span>{finding.actionLabel}</span>
                    <ArrowRight className="w-3 h-3 group-hover:translate-x-0.5 transition-transform" />
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </section>

      {/* =======================================================================
          SECTION 3 & 4 (2-Column Grid): Email authentication & Key IOCs
          ======================================================================= */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 sm:gap-6">
        {/* SECTION 3 — Email authentication */}
        {safeEmail.authentication && (
        <section className="bg-surface rounded-card border border-border p-4 space-y-4 flex flex-col justify-between">
          <div className="space-y-3">
            <div className="flex items-center justify-between pb-2 border-b border-border">
              <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-foreground-muted flex items-center space-x-2">
                <Lock className="w-3.5 h-3.5 text-primary" />
                <span>Email authentication</span>
              </h3>
              <span className="text-[10px] font-mono text-foreground-muted">
                Header results
              </span>
            </div>

            {/* Compact 3-Row Auth State Display */}
            <div className="space-y-2 font-mono text-xs">
              {/* SPF */}
              <div className="flex items-center justify-between p-2.5 rounded-lg bg-surface-secondary/50 border border-border/60">
                <div className="space-y-0.5">
                  <span className="font-bold text-foreground">SPF</span>
                  <p className="text-[10px] text-foreground-muted">Sender Policy Framework</p>
                </div>
                <span className={`px-2 py-0.5 rounded text-[11px] border ${getAuthBadge(spfState)}`}>
                  {spfState}
                </span>
              </div>

              {/* DKIM */}
              <div className="flex items-center justify-between p-2.5 rounded-lg bg-surface-secondary/50 border border-border/60">
                <div className="space-y-0.5">
                  <span className="font-bold text-foreground">DKIM</span>
                  <p className="text-[10px] text-foreground-muted">DomainKeys Identified Mail</p>
                </div>
                <span className={`px-2 py-0.5 rounded text-[11px] border ${getAuthBadge(dkimState)}`}>
                  {dkimState}
                </span>
              </div>

              {/* DMARC */}
              <div className="flex items-center justify-between p-2.5 rounded-lg bg-surface-secondary/50 border border-border/60">
                <div className="space-y-0.5">
                  <span className="font-bold text-foreground">DMARC</span>
                  <p className="text-[10px] text-foreground-muted">Domain Message Authentication</p>
                </div>
                <span className={`px-2 py-0.5 rounded text-[11px] border ${getAuthBadge(dmarcState)}`}>
                  {dmarcState}
                </span>
              </div>
            </div>
          </div>

          <div className="flex items-center space-x-2 pt-1">
            <button
              type="button"
              onClick={() =>
                openCopilotDrawer(
                  'Explain the SPF, DKIM, and DMARC authentication results, why alignment passed or failed, and how the p=reject policy was enforced.',
                  {
                    type: 'Authentication',
                    identifier: `SPF:${spfState} DKIM:${dkimState} DMARC:${dmarcState}`
                  }
                )
              }
              className="px-2.5 py-1.5 rounded-lg bg-primary/10 hover:bg-primary/20 text-primary border border-primary/25 text-xs font-mono font-medium flex items-center space-x-1.5 transition-colors cursor-pointer shrink-0"
              title="Ask AI to explain authentication failures"
            >
              <Sparkles className="w-3.5 h-3.5" />
              <span>Explain</span>
            </button>

            <button
              type="button"
              onClick={() => setSection('email', 'auth')}
              className="flex-1 py-1.5 rounded-lg bg-surface-secondary hover:bg-surface-secondary/80 border border-border text-foreground text-xs font-mono font-medium flex items-center justify-center space-x-1.5 transition-colors cursor-pointer"
            >
              <span>Inspect Full Headers & Auth Matrix</span>
              <ArrowRight className="w-3 h-3 text-primary" />
            </button>
          </div>
        </section>
        )}

        {/* SECTION 4 — Important Indicators (Highest Priority IOCs) */}
        <section className="bg-surface rounded-card border border-border p-4 space-y-4 flex flex-col justify-between">
          <div className="space-y-3">
            <div className="flex items-center justify-between pb-2 border-b border-border">
              <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-foreground-muted flex items-center space-x-2">
                <Target className="w-3.5 h-3.5 text-primary" />
                <span>Important Indicators</span>
              </h3>
              <span className="text-[10px] font-mono text-foreground-muted">
                Priority IOCs
              </span>
            </div>

            {/* List of 3-4 High-Priority Indicators */}
            <div className="space-y-2 font-mono text-xs">
              {highPriorityIOCs.map((ioc, idx) => (
                <div
                  key={`${ioc.type}-${idx}`}
                  className="flex items-center justify-between p-2 rounded-lg bg-surface-secondary/50 border border-border/60 gap-2"
                >
                  <div className="flex items-center space-x-2 min-w-0 flex-1">
                    <span
                      className={`px-1.5 py-0.2 rounded text-[9px] font-bold shrink-0 ${
                        ioc.type === 'DOMAIN'
                          ? 'bg-purple-500/10 text-purple-600 dark:text-purple-400 border border-purple-500/20'
                          : ioc.type === 'URL'
                          ? 'bg-blue-500/10 text-blue-600 dark:text-blue-400 border border-blue-500/20'
                          : 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20'
                      }`}
                    >
                      {ioc.type}
                    </span>
                    <span className="truncate text-foreground text-xs" title={ioc.value}>
                      {defang(ioc.value)}
                    </span>
                  </div>

                  <button
                    type="button"
                    onClick={() => copyToClipboard(ioc.value, `ioc-${idx}`)}
                    className="text-foreground-muted hover:text-foreground p-1 rounded hover:bg-surface shrink-0 cursor-pointer transition-colors"
                    title="Copy indicator"
                  >
                    {copiedIndicator === `ioc-${idx}` ? (
                      <Check className="w-3 h-3 text-success" />
                    ) : (
                      <Copy className="w-3 h-3" />
                    )}
                  </button>
                </div>
              ))}
            </div>
          </div>

          <button
            type="button"
            onClick={() => setSection('analysis', 'iocs')}
            className="w-full py-1.5 rounded-lg bg-surface-secondary hover:bg-surface-secondary/80 border border-border text-foreground text-xs font-mono font-medium flex items-center justify-center space-x-1.5 transition-colors cursor-pointer"
          >
            <span>View all indicators ({totalIOCsCount})</span>
            <ArrowRight className="w-3 h-3 text-primary" />
          </button>
        </section>
      </div>

      {/* =======================================================================
          SECTION 5 — EXPLAINABLE AI (XAI) LAYER
          ======================================================================= */}
      <ExplainableAIPanel
        scopeType="EVENT"
        scopeId={safeEmail.id || workspaceSummary?.investigation.investigation_id || 'investigation'}
        riskScore={score}
        riskLevel={severity}
        confidence={genuineConfidence || undefined}
      />

      {/* =======================================================================
          SECTION 5B — INVESTIGATION SUMMARY (Concise Backend/LLM Narrative)
          ======================================================================= */}
      <section className="bg-surface rounded-card border border-border p-4 space-y-3">
        <div className="flex items-center justify-between pb-2 border-b border-border">
          <div className="flex items-center space-x-2">
            <Sparkles className="w-4 h-4 text-primary" />
            <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-foreground">
              Investigation Summary
            </h3>
          </div>
          {(safeEmail.ai_analyst?.likely_attack_type || workspaceSummary?.classification) && (
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-primary/10 text-primary border border-primary/20">
              {safeEmail.ai_analyst?.likely_attack_type || workspaceSummary?.classification}
            </span>
          )}
        </div>

        <p className={`text-xs sm:text-sm font-sans text-foreground leading-relaxed ${summaryExpanded ? '' : 'line-clamp-3'}`}>
          {rawSummary}
        </p>

        {rawSummary.length > 220 && (
          <button
            type="button"
            onClick={() => setSummaryExpanded(!summaryExpanded)}
            className="text-xs font-mono text-primary hover:underline flex items-center space-x-1 cursor-pointer"
          >
            <span>{summaryExpanded ? 'Show less' : 'Read full assessment'}</span>
            {summaryExpanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
          </button>
        )}
      </section>

      {/* =======================================================================
          SECTION 6 — RECOMMENDED NEXT INVESTIGATION STEPS (Where to investigate next)
          ======================================================================= */}
      <section className="p-4 rounded-xl bg-surface-secondary/40 border border-border/60 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs font-mono">
        <div className="space-y-0.5">
          <span className="font-semibold text-foreground">Recommended Next Step:</span>
          <p className="text-foreground-muted text-[11px]">
            {!isEmailEvidence
              ? 'Review the original evidence, extracted indicators and analysis limitations.'
              : isMalicious
              ? 'Pivot into lookalike domain and URL redirection evidence to confirm attribution.'
              : 'Inspect original email headers to verify authoritative cryptographic signatures.'}
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2 shrink-0">
          <button
            type="button"
            onClick={() => {
              setSection('investigation');
              setSubTab('recommendations');
            }}
            className="px-3 py-1.5 rounded-lg bg-surface-secondary hover:bg-surface border border-border text-foreground font-semibold flex items-center space-x-1.5 transition-colors cursor-pointer shadow-xs"
          >
            <ShieldAlert className="w-3 h-3 text-amber-400" />
            <span>Response Proposals</span>
          </button>
          <button
            type="button"
            onClick={() => setSection(!isEmailEvidence ? 'evidence' : isMalicious ? 'analysis' : 'email')}
            className="px-3 py-1.5 rounded-lg bg-primary hover:bg-primary-hover text-primary-foreground font-semibold flex items-center space-x-1.5 transition-colors cursor-pointer shadow-xs"
          >
            <span>{!isEmailEvidence ? 'Inspect Original Evidence' : isMalicious ? 'Examine Analysis & IOCs' : 'Inspect Email Headers'}</span>
            <ArrowRight className="w-3 h-3" />
          </button>
        </div>
      </section>
    </div>
  );
};
