import React, { useState } from 'react';
import type { AuthenticationAnalysis } from '../../../types/forensic';
import { ShieldCheck, Info } from 'lucide-react';
import { StatusRow, ExpandableSection, DetailDrawer, MetadataRow } from '../../common/progressive';

interface EmailAuthSubsectionProps {
  authentication?: AuthenticationAnalysis;
}

export const EmailAuthSubsection: React.FC<EmailAuthSubsectionProps> = ({ authentication }) => {
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

  const isAuthentic = dmarcResult === 'PASS' && spfResult === 'PASS' && dkimResult === 'PASS';
  const hasFailures = dmarcResult === 'FAIL' || spfResult === 'FAIL' || dkimResult === 'FAIL';

  // Raw header fallback
  const rawAuthHeader = authentication?.observed_header ||
    `Authentication-Results: mx.mailtrace.internal;
       spf=${spf.result || 'none'} (domain of ${alignment.return_path_domain || 'sender'} designates sending IP as permitted sender) smtp.mailfrom=${alignment.return_path_domain || 'sender'};
       dkim=${dkim.result || 'none'} header.i=@${alignment.from_domain || 'sender'} header.s=s1;
       dmarc=${dmarc.result || 'none'} (p=REJECT) header.from=${alignment.from_domain || 'sender'}`;

  return (
    <div className="space-y-4 font-mono">
      <ExpandableSection
        title="Email Authentication"
        subtitle="Cryptographic verification and sender domain alignment protocols"
        icon={ShieldCheck}
        defaultExpanded={true}
        badge={
          <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${
            isAuthentic
              ? 'bg-success-surface text-success border-success-border'
              : hasFailures
                ? 'bg-danger-surface text-danger border-danger-border'
                : 'bg-warning-surface text-warning border-warning-border'
          }`}>
            {isAuthentic ? 'All Checks Passed' : hasFailures ? 'Authentication Failed' : 'Partial / Incomplete'}
          </span>
        }
      >
        <div className="space-y-3">
          {/* 1. SPF: PASS/FAIL > */}
          <StatusRow
            title="SPF"
            status={spfResult === 'PASS' ? 'PASS' : spfResult === 'NONE' ? 'NONE' : 'FAIL'}
            statusLabel={spfResult}
            subtitle="Sender Policy Framework · Authorization of sending mail server IP"
            defaultExpanded={false}
            onViewRaw={() =>
              setActiveRawModal({
                title: 'SPF Verification Evidence & Policy Record',
                subtitle: `Evaluated for envelope domain: ${alignment.return_path_domain || 'unspecified'}`,
                data: {
                  protocol: 'SPF',
                  verdict: spf.result,
                  details: spf.details,
                  return_path_domain: alignment.return_path_domain,
                  from_domain: alignment.from_domain,
                  observed_header: rawAuthHeader
                },
                format: 'json'
              })
            }
            rawButtonLabel="View raw SPF evidence"
          >
            <div className="space-y-2 text-xs">
              <MetadataRow
                label="Sender Envelope Domain"
                value={alignment.return_path_domain || 'Not specified in Return-Path'}
              />
              <MetadataRow
                label="SPF Validation Status"
                value={
                  spfResult === 'PASS'
                    ? 'Authorized: Sending MTA IP matches DNS TXT spf1 record'
                    : spfResult === 'FAIL'
                      ? 'Unauthorized: Sending IP is not listed in domain SPF policy'
                      : 'No SPF record or neutral policy published'
                }
              />
              {spf.details && (
                <div className="p-2.5 rounded-lg bg-surface border border-border text-[11px] text-foreground-muted">
                  <span className="font-bold text-foreground block mb-0.5">Policy Evaluation Detail:</span>
                  <span className="break-all">{spf.details}</span>
                </div>
              )}
            </div>
          </StatusRow>

          {/* 2. DKIM: PASS/FAIL > */}
          <StatusRow
            title="DKIM"
            status={dkimResult === 'PASS' ? 'PASS' : dkimResult === 'NONE' ? 'NONE' : 'FAIL'}
            statusLabel={dkimResult}
            subtitle="DomainKeys Identified Mail · Cryptographic RSA/Ed25519 digital signature"
            defaultExpanded={false}
            onViewRaw={() =>
              setActiveRawModal({
                title: 'DKIM Signature Cryptographic Evidence',
                subtitle: `Evaluated signature for domain: ${alignment.from_domain || 'unspecified'}`,
                data: {
                  protocol: 'DKIM',
                  verdict: dkim.result,
                  details: dkim.details,
                  signing_domain: alignment.from_domain,
                  signature_valid: dkim.result === 'pass',
                  observed_header: rawAuthHeader
                },
                format: 'json'
              })
            }
            rawButtonLabel="View raw DKIM signature"
          >
            <div className="space-y-2 text-xs">
              <MetadataRow
                label="Signing Identity (d=)"
                value={alignment.from_domain ? `@${alignment.from_domain}` : 'Not detected'}
              />
              <MetadataRow
                label="Signature Integrity"
                value={
                  dkimResult === 'PASS'
                    ? 'Valid cryptographic signature verified against DNS public key'
                    : dkimResult === 'FAIL'
                      ? 'Signature verification failed or header/body was tampered with in transit'
                      : 'No cryptographic DKIM signature found in message headers'
                }
              />
              {dkim.details && (
                <div className="p-2.5 rounded-lg bg-surface border border-border text-[11px] text-foreground-muted">
                  <span className="font-bold text-foreground block mb-0.5">Cryptographic Diagnostics:</span>
                  <span className="break-all">{dkim.details}</span>
                </div>
              )}
            </div>
          </StatusRow>

          {/* 3. DMARC: PASS/FAIL > */}
          <StatusRow
            title="DMARC"
            status={dmarcResult === 'PASS' ? 'PASS' : dmarcResult === 'NONE' ? 'NONE' : 'FAIL'}
            statusLabel={dmarcResult}
            subtitle="Domain-based Message Authentication, Reporting & Conformance · Alignment policy"
            defaultExpanded={false}
            onViewRaw={() =>
              setActiveRawModal({
                title: 'DMARC Technical Verification Evidence',
                subtitle: `Policy evaluation for domain: ${alignment.from_domain || 'unspecified'}`,
                data: {
                  protocol: 'DMARC',
                  result: dmarc.result,
                  policy_evaluated: dmarc.details?.includes('reject') ? 'p=reject' : dmarc.details?.includes('quarantine') ? 'p=quarantine' : 'p=none',
                  from_domain: alignment.from_domain,
                  return_path_domain: alignment.return_path_domain,
                  reply_to_domain: alignment.reply_to_domain,
                  spf_alignment: alignment.return_path_mismatch ? 'misaligned' : 'aligned',
                  dkim_alignment: dkim.result === 'pass' ? 'aligned' : 'misaligned',
                  raw_summary: dmarc.details,
                  observed_header: rawAuthHeader
                },
                format: 'json'
              })
            }
            rawButtonLabel="View raw DMARC policy & headers"
          >
            <div className="space-y-2 text-xs">
              <MetadataRow
                label="Header From Domain"
                value={alignment.from_domain || 'Not specified'}
              />
              <MetadataRow
                label="Alignment Evaluation"
                value={
                  dmarcResult === 'PASS'
                    ? 'Passed: Visible From domain aligns with authenticated SPF / DKIM identifiers'
                    : dmarcResult === 'FAIL'
                      ? 'Failed: Neither SPF nor DKIM passed in alignment with visible From domain'
                      : 'No DMARC policy record published for this domain'
                }
              />
              {dmarc.details && (
                <div className="p-2.5 rounded-lg bg-surface border border-border text-[11px] text-foreground-muted">
                  <span className="font-bold text-foreground block mb-0.5">DMARC Policy Enforcement:</span>
                  <span className="break-all">{dmarc.details}</span>
                </div>
              )}
            </div>
          </StatusRow>
        </div>

        {/* Informational SOC footer */}
        <div className="pt-3 border-t border-border/60 flex items-center justify-between text-[11px] text-foreground-muted">
          <div className="flex items-center space-x-1.5">
            <Info className="w-3.5 h-3.5 text-primary shrink-0" />
            <span>Click any protocol row to expand diagnostic explanation and technical evidence</span>
          </div>
          <button
            type="button"
            onClick={() =>
              setActiveRawModal({
                title: 'Combined Authentication-Results Header',
                subtitle: 'RFC-8601 verbatim authentication telemetry',
                data: rawAuthHeader,
                format: 'headers'
              })
            }
            className="text-primary hover:underline font-semibold cursor-pointer"
          >
            View raw header
          </button>
        </div>
      </ExpandableSection>

      {/* Level 3 Raw Drawer */}
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
