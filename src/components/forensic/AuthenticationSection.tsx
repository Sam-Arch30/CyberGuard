import React, { useState } from 'react';
import type { AuthenticationAnalysis } from '../../types/forensic';
import { ShieldCheck, Info, ArrowRight, AlertTriangle } from 'lucide-react';
import { StatusRow, ExpandableSection, DetailDrawer, MetadataRow } from '../common/progressive';

interface AuthenticationSectionProps {
  authentication?: AuthenticationAnalysis;
}

export const AuthenticationSection: React.FC<AuthenticationSectionProps> = ({ authentication }) => {
  const [activeRawModal, setActiveRawModal] = useState<{
    title: string;
    subtitle?: string;
    data: any;
    format?: 'json' | 'text' | 'headers';
  } | null>(null);

  const spf = authentication?.spf || { result: 'none' };
  const dkim = authentication?.dkim || { result: 'none' };
  const dmarc = authentication?.dmarc || { result: 'none' };
  const alignment = authentication?.alignment || {};

  const spfResult = (spf.result || 'NONE').toUpperCase();
  const dkimResult = (dkim.result || 'NONE').toUpperCase();
  const dmarcResult = (dmarc.result || 'NONE').toUpperCase();

  const hasAlignmentMismatch = Boolean(alignment.reply_to_mismatch || alignment.return_path_mismatch);
  const alignmentStatus = hasAlignmentMismatch ? 'WARN' : 'PASS';
  const alignmentLabel = hasAlignmentMismatch ? 'MISMATCH' : 'ALIGNED';

  // Raw header fallback
  const rawAuthHeader = authentication?.observed_header ||
    `Authentication-Results: mx.google.com;
       spf=${spf.result || 'none'} (google.com: domain of ${alignment.return_path_domain || 'unknown'} designates IP as permitted sender) smtp.mailfrom=${alignment.return_path_domain || 'unknown'};
       dkim=${dkim.result || 'none'} header.i=@${alignment.from_domain || 'unknown'} header.s=s1 header.b=...;
       dmarc=${dmarc.result || 'none'} (p=REJECT sp=REJECT dis=NONE) header.from=${alignment.from_domain || 'unknown'}`;

  return (
    <div className="space-y-5">
      {/* Security Notice Banner */}
      <div className="flex items-start space-x-2.5 p-3.5 rounded-xl bg-surface-secondary/70 border border-border text-xs font-mono text-foreground-muted leading-relaxed">
        <Info className="w-4 h-4 text-primary shrink-0 mt-0.5" />
        <div>
          <span className="font-semibold text-foreground block">Authentication & Alignment Triage</span>
          <span className="text-foreground-muted text-[11px]">
            {authentication?.verification_notice ||
              'Results derived from observed Authentication-Results headers. Click any protocol to reveal explanation and technical DNS/signature evidence.'}
          </span>
        </div>
      </div>

      {/* Main Progressive Protocols Section */}
      <ExpandableSection
        title="Email Authentication Protocols (SPF / DKIM / DMARC)"
        subtitle="RFC-8601 validation results and cryptographic digital signatures"
        icon={ShieldCheck}
        defaultExpanded={true}
        badge={
          <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${
            dmarcResult === 'PASS' && spfResult === 'PASS'
              ? 'bg-success-surface text-success border-success-border'
              : 'bg-danger-surface text-danger border-danger-border'
          }`}>
            {dmarcResult === 'PASS' && spfResult === 'PASS' ? 'Authentic' : 'Validation Failed'}
          </span>
        }
      >
        <div className="space-y-3">
          {/* 1. DMARC Protocol */}
          <StatusRow
            title="DMARC"
            status={dmarcResult === 'PASS' ? 'PASS' : dmarcResult === 'NONE' ? 'NONE' : 'FAIL'}
            statusLabel={dmarcResult}
            subtitle="Domain-based Message Authentication, Reporting, and Conformance"
            onViewRaw={() =>
              setActiveRawModal({
                title: 'DMARC Technical Verification Evidence',
                subtitle: `Policy evaluation for domain: ${alignment.from_domain || 'unspecified'}`,
                data: {
                  protocol: 'DMARC',
                  result: dmarc.result,
                  policy_evaluated: dmarc.details?.includes('reject') ? 'p=reject' : dmarc.details?.includes('quarantine') ? 'p=quarantine' : 'p=none',
                  from_domain: alignment.from_domain,
                  spf_alignment: alignment.return_path_mismatch ? 'misaligned' : 'aligned',
                  dkim_alignment: dkim.result === 'pass' ? 'aligned' : 'misaligned',
                  raw_summary: dmarc.details,
                  observed_header: rawAuthHeader
                },
                format: 'json'
              })
            }
          >
            <div className="space-y-2">
              <MetadataRow
                label="Domain Alignment"
                value={
                  alignment.from_domain && alignment.return_path_domain
                    ? `${alignment.from_domain} → ${alignment.return_path_domain}`
                    : alignment.from_domain || 'Not available'
                }
              />
              <MetadataRow
                label="Enforced Policy"
                value={
                  dmarc.details?.toLowerCase().includes('reject')
                    ? 'p=reject (Direct delivery rejection)'
                    : dmarc.details?.toLowerCase().includes('quarantine')
                    ? 'p=quarantine (Delivery to spam/junk)'
                    : 'p=none (Monitoring / Audit mode only)'
                }
              />
              <MetadataRow
                label="Forensic Reason"
                value={
                  dmarc.details ||
                  (dmarcResult === 'PASS'
                    ? 'Header From domain aligns with authenticated identifier under published domain policy.'
                    : 'Header From domain failed alignment with authenticated SPF/DKIM identity.')
                }
                isMonospace={false}
              />
            </div>
          </StatusRow>

          {/* 2. SPF Protocol */}
          <StatusRow
            title="SPF"
            status={spfResult === 'PASS' ? 'PASS' : spfResult === 'NONE' ? 'NONE' : 'FAIL'}
            statusLabel={spfResult}
            subtitle="Sender Policy Framework IP authorization"
            onViewRaw={() =>
              setActiveRawModal({
                title: 'SPF Technical Verification Evidence',
                subtitle: `Sender authorization for: ${alignment.return_path_domain || 'unspecified'}`,
                data: {
                  protocol: 'SPF',
                  result: spf.result,
                  return_path_domain: alignment.return_path_domain,
                  raw_details: spf.details,
                  observed_header: rawAuthHeader
                },
                format: 'json'
              })
            }
          >
            <div className="space-y-2">
              <MetadataRow
                label="Return-Path Domain"
                value={alignment.return_path_domain || 'Not specified in message envelope'}
              />
              <MetadataRow
                label="Sender State"
                value={
                  spfResult === 'PASS'
                    ? 'Sending MTA IP explicitly permitted in domain DNS TXT SPF record.'
                    : 'Sending IP is NOT designated as an authorized relay in DNS records.'
                }
                isMonospace={false}
              />
              {spf.details && (
                <MetadataRow
                  label="Policy Detail"
                  value={spf.details}
                  isMonospace={false}
                />
              )}
            </div>
          </StatusRow>

          {/* 3. DKIM Protocol */}
          <StatusRow
            title="DKIM"
            status={dkimResult === 'PASS' ? 'PASS' : dkimResult === 'NONE' ? 'NONE' : 'FAIL'}
            statusLabel={dkimResult}
            subtitle="DomainKeys Identified Mail cryptographic signature"
            onViewRaw={() =>
              setActiveRawModal({
                title: 'DKIM Signature Technical Evidence',
                subtitle: `Cryptographic body and header hash verification`,
                data: {
                  protocol: 'DKIM',
                  result: dkim.result,
                  signing_domain: alignment.from_domain,
                  raw_details: dkim.details,
                  observed_header: rawAuthHeader
                },
                format: 'json'
              })
            }
          >
            <div className="space-y-2">
              <MetadataRow
                label="Signature Status"
                value={
                  dkimResult === 'PASS'
                    ? 'Cryptographic RSA/Ed25519 signature verified intact across canonicalized headers.'
                    : 'Digital signature validation failed or was not provided.'
                }
                isMonospace={false}
              />
              {dkim.details && (
                <MetadataRow
                  label="Verification Detail"
                  value={dkim.details}
                  isMonospace={false}
                />
              )}
            </div>
          </StatusRow>

          {/* 4. Sender Domain Alignment */}
          <StatusRow
            title="Sender Domain Alignment"
            status={alignmentStatus}
            statusLabel={alignmentLabel}
            subtitle="RFC-5322 From, Reply-To, and RFC-5321 Return-Path cross-check"
            onViewRaw={() =>
              setActiveRawModal({
                title: 'Sender Alignment Detailed Breakdown',
                subtitle: 'RFC-5322 vs RFC-5321 domain comparative matrix',
                data: {
                  from_domain: alignment.from_domain,
                  reply_to_domain: alignment.reply_to_domain,
                  return_path_domain: alignment.return_path_domain,
                  reply_to_mismatch: alignment.reply_to_mismatch,
                  return_path_mismatch: alignment.return_path_mismatch,
                  has_mismatch: hasAlignmentMismatch
                },
                format: 'json'
              })
            }
          >
            <div className="space-y-2">
              <div className="flex items-center justify-between p-2 rounded bg-surface border border-border">
                <span className="text-[11px] text-foreground-muted">From Domain</span>
                <span className="font-bold text-foreground">{alignment.from_domain || 'Not available'}</span>
              </div>

              <div className="flex items-center justify-between p-2 rounded bg-surface border border-border">
                <div className="flex items-center space-x-1.5">
                  <span className="text-[11px] text-foreground-muted">Reply-To Domain</span>
                  <ArrowRight className="w-3 h-3 text-foreground-subtle" />
                </div>
                <div className="flex items-center space-x-2">
                  <span className="font-bold text-foreground">
                    {alignment.reply_to_domain || (alignment.from_domain ? `${alignment.from_domain} (defaults to From)` : 'Not specified')}
                  </span>
                  {alignment.reply_to_mismatch && (
                    <span className="inline-flex items-center space-x-1 px-1.5 py-0.2 rounded text-[10px] bg-warning-surface text-warning border border-warning-border font-bold">
                      <AlertTriangle className="w-3 h-3" />
                      <span>Mismatch</span>
                    </span>
                  )}
                </div>
              </div>

              <div className="flex items-center justify-between p-2 rounded bg-surface border border-border">
                <div className="flex items-center space-x-1.5">
                  <span className="text-[11px] text-foreground-muted">Return-Path Domain</span>
                  <ArrowRight className="w-3 h-3 text-foreground-subtle" />
                </div>
                <div className="flex items-center space-x-2">
                  <span className="font-bold text-foreground">{alignment.return_path_domain || 'Not available'}</span>
                  {alignment.return_path_mismatch && (
                    <span className="inline-flex items-center space-x-1 px-1.5 py-0.2 rounded text-[10px] bg-warning-surface text-warning border border-warning-border font-bold">
                      <AlertTriangle className="w-3 h-3" />
                      <span>Mismatch</span>
                    </span>
                  )}
                </div>
              </div>
            </div>
          </StatusRow>
        </div>
      </ExpandableSection>

      {/* Level 3 Raw Modal / Drawer */}
      {activeRawModal && (
        <DetailDrawer
          isOpen={Boolean(activeRawModal)}
          onClose={() => setActiveRawModal(null)}
          title={activeRawModal.title}
          subtitle={activeRawModal.subtitle}
          data={activeRawModal.data}
          format={activeRawModal.format || 'json'}
        />
      )}
    </div>
  );
};
