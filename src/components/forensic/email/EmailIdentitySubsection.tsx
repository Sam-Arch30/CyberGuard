import React, { useMemo } from 'react';
import type { EmailAnalysis } from '../../../types/forensic';
import { Mail, AlertTriangle, CheckCircle2, ShieldAlert } from 'lucide-react';
import { CopyButton } from '../CopyButton';
import { ExpandableSection } from '../../common/progressive';
import { TruncatedForensicValue } from '../TruncatedForensicValue';

interface EmailIdentitySubsectionProps {
  email: EmailAnalysis;
}

const extractEmailAndDomain = (raw?: string): { displayName?: string; address?: string; domain?: string } => {
  if (!raw) return {};
  const match = raw.match(/^(?:["']?([^"']*)["']?\s*)?<?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})>?$/);
  if (match) {
    const displayName = match[1]?.trim() || undefined;
    const address = match[2];
    const domain = address.split('@')[1]?.toLowerCase();
    return { displayName, address, domain };
  }
  // Simple fallback
  if (raw.includes('@')) {
    const parts = raw.split('@');
    const domain = parts[1]?.replace(/[>\])]/g, '').trim().toLowerCase();
    return { address: raw, domain };
  }
  return { address: raw };
};

export const EmailIdentitySubsection: React.FC<EmailIdentitySubsectionProps> = ({ email }) => {
  const alignment = email.authentication?.alignment;

  const parsedFrom = useMemo(() => extractEmailAndDomain(email.from), [email.from]);
  const parsedReplyTo = useMemo(() => extractEmailAndDomain(email.reply_to), [email.reply_to]);
  const parsedReturnPath = useMemo(() => extractEmailAndDomain(email.return_path), [email.return_path]);

  const fromDomain = alignment?.from_domain?.toLowerCase() || parsedFrom.domain;
  const replyToDomain = alignment?.reply_to_domain?.toLowerCase() || parsedReplyTo.domain;
  const returnPathDomain = alignment?.return_path_domain?.toLowerCase() || parsedReturnPath.domain;

  // Inconsistency checks
  const replyToMismatch = Boolean(
    alignment?.reply_to_mismatch ||
    (parsedReplyTo.address && replyToDomain && fromDomain && replyToDomain !== fromDomain)
  );

  const returnPathMismatch = Boolean(
    alignment?.return_path_mismatch ||
    (parsedReturnPath.address && returnPathDomain && fromDomain && returnPathDomain !== fromDomain)
  );

  // Display name brand spoofing heuristic (e.g. "Microsoft Support" with a non-microsoft domain)
  const isDisplayNameSpoofing = useMemo(() => {
    if (!parsedFrom.displayName || !fromDomain) return false;
    const nameLower = parsedFrom.displayName.toLowerCase();
    const commonBrands = ['microsoft', 'paypal', 'apple', 'google', 'amazon', 'netflix', 'chase', 'bank of america'];
    for (const brand of commonBrands) {
      if (nameLower.includes(brand) && !fromDomain.includes(brand)) {
        return brand;
      }
    }
    return false;
  }, [parsedFrom.displayName, fromDomain]);

  // Message-ID domain extraction
  const parsedMsgIdDomain = useMemo(() => {
    if (!email.message_id) return null;
    const atSplit = email.message_id.split('@');
    if (atSplit.length > 1) {
      return atSplit[1].replace(/[>]/g, '').trim().toLowerCase();
    }
    return null;
  }, [email.message_id]);

  const msgIdMismatch = Boolean(
    parsedMsgIdDomain &&
    fromDomain &&
    parsedMsgIdDomain !== fromDomain &&
    !parsedMsgIdDomain.endsWith(`.${fromDomain}`)
  );

  const totalInconsistencies =
    (replyToMismatch ? 1 : 0) +
    (returnPathMismatch ? 1 : 0) +
    (isDisplayNameSpoofing ? 1 : 0);

  return (
    <ExpandableSection
      title="Email Identity & Addressing"
      subtitle="RFC-5322 message header envelope, sender alignment, and routing addresses"
      icon={Mail}
      defaultExpanded={true}
      badge={
        totalInconsistencies > 0 ? (
          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-warning-surface text-warning border border-warning-border flex items-center gap-1">
            <AlertTriangle className="w-3 h-3" />
            <span>{totalInconsistencies} Inconsistenc{totalInconsistencies !== 1 ? 'ies' : 'y'}</span>
          </span>
        ) : (
          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-success-surface text-success border border-success-border flex items-center gap-1">
            <CheckCircle2 className="w-3 h-3" />
            <span>Identity Aligned</span>
          </span>
        )
      }
    >
      <div className="space-y-4">
        {/* Inconsistency Status Banner */}
        {totalInconsistencies > 0 ? (
          <div className="p-3 rounded-xl bg-warning-surface/50 border border-warning-border/80 flex items-start space-x-2.5 text-xs font-mono">
            <AlertTriangle className="w-4 h-4 text-warning shrink-0 mt-0.5" />
            <div className="space-y-1">
              <span className="font-bold text-foreground block">
                Sender Identity Misalignment Detected
              </span>
              <p className="text-foreground-muted text-[11px] leading-relaxed">
                {replyToMismatch && '• Reply-To address directs responses to a separate domain from the visible sender. '}
                {returnPathMismatch && '• Envelope Return-Path domain differs from RFC-5322 From identity. '}
                {isDisplayNameSpoofing && `• Display name claims "${parsedFrom.displayName}" but originates from unaligned domain "${fromDomain}".`}
              </p>
            </div>
          </div>
        ) : (
          <div className="p-2.5 rounded-xl bg-surface-secondary/40 border border-border flex items-center space-x-2 text-xs font-mono text-foreground-muted">
            <CheckCircle2 className="w-3.5 h-3.5 text-success shrink-0" />
            <span>Sender alignment confirmed: From, Reply-To, and Return-Path align under standard domain policies.</span>
          </div>
        )}

        {/* Structured Field Rows */}
        <div className="space-y-2 font-mono text-xs">
          {/* 1. From */}
          <div className="p-3 rounded-xl bg-surface-secondary/40 border border-border flex flex-col sm:flex-row sm:items-center justify-between gap-2 hover:border-primary/40 transition-colors">
            <div className="flex items-center space-x-2 text-foreground-muted min-w-[120px] shrink-0">
              <span className="font-bold uppercase text-[11px]">From:</span>
            </div>
            <div className="flex-1 flex flex-wrap items-center justify-between gap-2 min-w-0">
              <div className="flex flex-wrap items-center gap-2 min-w-0">
                <TruncatedForensicValue
                  value={email.from || 'Not specified'}
                  type="email"
                  maxWidth="max-w-[240px] sm:max-w-md lg:max-w-xl"
                />
                {isDisplayNameSpoofing && (
                  <span className="px-2 py-0.5 rounded text-[10px] bg-danger-surface text-danger border border-danger-border font-bold flex items-center gap-1">
                    <ShieldAlert className="w-3 h-3" />
                    <span>Spoofed Brand Display Name</span>
                  </span>
                )}
              </div>
              {email.from && <CopyButton text={email.from} iconOnly />}
            </div>
          </div>

          {/* 2. Reply-To */}
          <div className={`p-3 rounded-xl border flex flex-col sm:flex-row sm:items-center justify-between gap-2 transition-colors ${
            replyToMismatch
              ? 'bg-warning-surface/20 border-warning-border/70'
              : 'bg-surface-secondary/40 border border-border hover:border-primary/40'
          }`}>
            <div className="flex items-center space-x-2 text-foreground-muted min-w-[120px] shrink-0">
              <span className="font-bold uppercase text-[11px]">Reply-To:</span>
            </div>
            <div className="flex-1 flex flex-wrap items-center justify-between gap-2 min-w-0">
              <div className="flex flex-wrap items-center gap-2 min-w-0">
                <TruncatedForensicValue
                  value={email.reply_to || (email.from ? `${email.from} (Defaults to From)` : 'Not specified')}
                  type="email"
                  maxWidth="max-w-[240px] sm:max-w-md lg:max-w-xl"
                  className={replyToMismatch ? 'text-warning font-bold' : 'text-foreground'}
                />
                {replyToMismatch && (
                  <span className="px-2 py-0.5 rounded text-[10px] bg-warning-surface text-warning border border-warning-border font-bold flex items-center gap-1">
                    <AlertTriangle className="w-3 h-3" />
                    <span>Domain Mismatch ({replyToDomain || 'external'})</span>
                  </span>
                )}
              </div>
              {email.reply_to && <CopyButton text={email.reply_to} iconOnly />}
            </div>
          </div>

          {/* 3. Return-Path */}
          <div className={`p-3 rounded-xl border flex flex-col sm:flex-row sm:items-center justify-between gap-2 transition-colors ${
            returnPathMismatch
              ? 'bg-warning-surface/20 border-warning-border/70'
              : 'bg-surface-secondary/40 border border-border hover:border-primary/40'
          }`}>
            <div className="flex items-center space-x-2 text-foreground-muted min-w-[120px] shrink-0">
              <span className="font-bold uppercase text-[11px]">Return-Path:</span>
            </div>
            <div className="flex-1 flex flex-wrap items-center justify-between gap-2 min-w-0">
              <div className="flex flex-wrap items-center gap-2 min-w-0">
                <TruncatedForensicValue
                  value={email.return_path || 'Not specified in message envelope'}
                  type="email"
                  maxWidth="max-w-[240px] sm:max-w-md lg:max-w-xl"
                  className={returnPathMismatch ? 'text-warning font-bold' : 'text-foreground'}
                />
                {returnPathMismatch && (
                  <span className="px-2 py-0.5 rounded text-[10px] bg-warning-surface text-warning border border-warning-border font-bold flex items-center gap-1">
                    <AlertTriangle className="w-3 h-3" />
                    <span>Envelope Mismatch ({returnPathDomain || 'different MTA'})</span>
                  </span>
                )}
              </div>
              {email.return_path && <CopyButton text={email.return_path} iconOnly />}
            </div>
          </div>

          {/* 4. To */}
          <div className="p-3 rounded-xl bg-surface-secondary/40 border border-border flex flex-col sm:flex-row sm:items-center justify-between gap-2 hover:border-primary/40 transition-colors">
            <div className="flex items-center space-x-2 text-foreground-muted min-w-[120px] shrink-0">
              <span className="font-bold uppercase text-[11px]">To:</span>
            </div>
            <div className="flex-1 flex flex-wrap items-center justify-between gap-2 min-w-0">
              <TruncatedForensicValue
                value={Array.isArray(email.to) ? email.to.join(', ') : email.to || 'Undisclosed recipients'}
                type="email"
                maxWidth="max-w-[240px] sm:max-w-md lg:max-w-xl"
              />
              {email.to && (
                <CopyButton
                  text={Array.isArray(email.to) ? email.to.join(', ') : String(email.to)}
                  iconOnly
                />
              )}
            </div>
          </div>

          {/* 5. Subject */}
          <div className="p-3 rounded-xl bg-surface-secondary/40 border border-border flex flex-col sm:flex-row sm:items-center justify-between gap-2 hover:border-primary/40 transition-colors">
            <div className="flex items-center space-x-2 text-foreground-muted min-w-[120px] shrink-0">
              <span className="font-bold uppercase text-[11px]">Subject:</span>
            </div>
            <div className="flex-1 flex flex-wrap items-center justify-between gap-2 min-w-0">
              <TruncatedForensicValue
                value={email.subject || '(No Subject)'}
                type="subject"
                maxWidth="max-w-[240px] sm:max-w-md lg:max-w-xl"
                className="font-sans font-bold text-foreground text-sm"
              />
              {email.subject && <CopyButton text={email.subject} iconOnly />}
            </div>
          </div>

          {/* 6. Date */}
          <div className="p-3 rounded-xl bg-surface-secondary/40 border border-border flex flex-col sm:flex-row sm:items-center justify-between gap-2 hover:border-primary/40 transition-colors">
            <div className="flex items-center space-x-2 text-foreground-muted min-w-[120px] shrink-0">
              <span className="font-bold uppercase text-[11px]">Date:</span>
            </div>
            <div className="flex-1 flex flex-wrap items-center justify-between gap-2 min-w-0">
              <span className="font-semibold text-foreground break-all select-all">
                {email.date || 'Timestamp not present in headers'}
              </span>
              {email.date && <CopyButton text={email.date} iconOnly />}
            </div>
          </div>

          {/* 7. Message-ID */}
          <div className="p-3 rounded-xl bg-surface-secondary/40 border border-border flex flex-col sm:flex-row sm:items-center justify-between gap-2 hover:border-primary/40 transition-colors">
            <div className="flex items-center space-x-2 text-foreground-muted min-w-[120px] shrink-0">
              <span className="font-bold uppercase text-[11px]">Message-ID:</span>
            </div>
            <div className="flex-1 flex flex-wrap items-center justify-between gap-2 min-w-0">
              <div className="flex flex-wrap items-center gap-2 min-w-0">
                <TruncatedForensicValue
                  value={email.message_id || 'Not present'}
                  type="hash"
                  maxWidth="max-w-[240px] sm:max-w-md lg:max-w-xl"
                  className="text-[11px]"
                />
                {msgIdMismatch && (
                  <span className="px-2 py-0.5 rounded text-[10px] bg-surface-secondary text-foreground-muted border border-border font-mono">
                    Host: {parsedMsgIdDomain}
                  </span>
                )}
              </div>
              {email.message_id && <CopyButton text={email.message_id} iconOnly />}
            </div>
          </div>
        </div>
      </div>
    </ExpandableSection>
  );
};
