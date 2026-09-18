import React, { useState, useMemo } from 'react';
import type { EmailAnalysis } from '../../../types/forensic';
import {
  FileCode,
  Search,
  ChevronDown,
  ChevronUp,
  Key,
  Copy,
  Check,
  WrapText,
  Filter
} from 'lucide-react';
import { ExpandableSection } from '../../common/progressive';
import { CopyButton } from '../CopyButton';

interface EmailHeadersSubsectionProps {
  email: EmailAnalysis;
}

interface ParsedHeaderItem {
  key: string;
  value: string;
  isImportant: boolean;
}

const IMPORTANT_HEADER_KEYS = [
  'from',
  'to',
  'cc',
  'subject',
  'date',
  'message-id',
  'reply-to',
  'return-path',
  'authentication-results',
  'received-spf',
  'dkim-signature',
  'content-type',
  'x-mailer',
  'user-agent',
  'mime-version'
];

export const EmailHeadersSubsection: React.FC<EmailHeadersSubsectionProps> = ({ email }) => {
  const [showAllHeaders, setShowAllHeaders] = useState<boolean>(false);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [lineWrap, setLineWrap] = useState<boolean>(true);
  const [copiedAll, setCopiedAll] = useState<boolean>(false);

  // 1. Extract raw header string from email.raw_email or synthesize
  const rawHeaderString = useMemo(() => {
    if (email.raw_email) {
      // Headers precede first blank line
      const headerBodySplit = email.raw_email.split(/(?:\r?\n){2}/);
      if (headerBodySplit.length > 0 && headerBodySplit[0].trim()) {
        return headerBodySplit[0].trim();
      }
    }

    // Synthesize standard headers if raw_email not available
    const lines: string[] = [];
    if (email.return_path) lines.push(`Return-Path: <${email.return_path}>`);
    (email.received || []).forEach((r) => lines.push(`Received: ${r}`));
    if (email.date) lines.push(`Date: ${email.date}`);
    if (email.from) lines.push(`From: ${email.from}`);
    if (email.reply_to) lines.push(`Reply-To: ${email.reply_to}`);
    if (email.to) lines.push(`To: ${Array.isArray(email.to) ? email.to.join(', ') : email.to}`);
    if (email.cc) lines.push(`Cc: ${Array.isArray(email.cc) ? email.cc.join(', ') : email.cc}`);
    if (email.subject) lines.push(`Subject: ${email.subject}`);
    if (email.message_id) lines.push(`Message-ID: ${email.message_id}`);
    if (email.authentication_results) lines.push(`Authentication-Results: ${email.authentication_results}`);
    return lines.join('\n');
  }, [email]);

  // 2. Parse RFC-822 headers into structured key-value list with folding support
  const parsedHeaders = useMemo<ParsedHeaderItem[]>(() => {
    const items: ParsedHeaderItem[] = [];
    const lines = rawHeaderString.split(/\r?\n/);
    let currentKey = '';
    let currentValue = '';

    for (const line of lines) {
      // Continuation line (starts with space or tab)
      if (/^[ \t]/.test(line) && currentKey) {
        currentValue += ` ${line.trim()}`;
      } else {
        if (currentKey) {
          items.push({
            key: currentKey,
            value: currentValue,
            isImportant: IMPORTANT_HEADER_KEYS.includes(currentKey.toLowerCase())
          });
        }
        const match = line.match(/^([A-Za-z0-9_-]+):\s*(.*)$/);
        if (match) {
          currentKey = match[1];
          currentValue = match[2];
        } else {
          currentKey = '';
          currentValue = '';
        }
      }
    }

    if (currentKey) {
      items.push({
        key: currentKey,
        value: currentValue,
        isImportant: IMPORTANT_HEADER_KEYS.includes(currentKey.toLowerCase())
      });
    }

    return items;
  }, [rawHeaderString]);

  // Important headers to show first
  const importantHeaders = useMemo(() => {
    // If parsedHeaders has important ones, use them
    const found = parsedHeaders.filter((h) => h.isImportant);
    if (found.length > 0) return found;

    // Fallback if rawHeaderString was sparse
    const manual: ParsedHeaderItem[] = [
      { key: 'From', value: email.from || 'Not specified', isImportant: true },
      { key: 'To', value: Array.isArray(email.to) ? email.to.join(', ') : email.to || 'Not specified', isImportant: true },
      { key: 'Subject', value: email.subject || '(No subject)', isImportant: true },
      { key: 'Date', value: email.date || 'Not recorded', isImportant: true },
      { key: 'Message-ID', value: email.message_id || 'Not present', isImportant: true },
      { key: 'Reply-To', value: email.reply_to || 'Defaults to From', isImportant: true },
      { key: 'Return-Path', value: email.return_path || 'Not specified', isImportant: true }
    ];
    if (email.cc) manual.push({ key: 'Cc', value: Array.isArray(email.cc) ? email.cc.join(', ') : email.cc, isImportant: true });
    if (email.authentication_results) manual.push({ key: 'Authentication-Results', value: email.authentication_results, isImportant: true });
    return manual;
  }, [parsedHeaders, email]);

  // Filtered raw header lines based on searchQuery
  const filteredRawHeaders = useMemo(() => {
    if (!searchQuery.trim()) return rawHeaderString;
    const q = searchQuery.toLowerCase();
    const lines = rawHeaderString.split(/\r?\n/);
    const matchedLines: string[] = [];

    let isCapturingFolded = false;
    for (const line of lines) {
      if (/^[ \t]/.test(line)) {
        if (isCapturingFolded) {
          matchedLines.push(line);
        } else if (line.toLowerCase().includes(q)) {
          matchedLines.push(line);
        }
      } else {
        if (line.toLowerCase().includes(q)) {
          matchedLines.push(line);
          isCapturingFolded = true;
        } else {
          isCapturingFolded = false;
        }
      }
    }
    return matchedLines.join('\n');
  }, [rawHeaderString, searchQuery]);

  const handleCopyAll = () => {
    navigator.clipboard.writeText(rawHeaderString);
    setCopiedAll(true);
    setTimeout(() => setCopiedAll(false), 2000);
  };

  return (
    <div className="space-y-4 font-mono">
      <ExpandableSection
        title="Email Headers"
        subtitle="RFC-5322 Internet Message Headers, delivery hops, and security metadata"
        icon={FileCode}
        defaultExpanded={true}
        badge={
          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-surface-secondary text-foreground-muted border border-border">
            {parsedHeaders.length} Header{parsedHeaders.length !== 1 ? 's' : ''} Parsed
          </span>
        }
      >
        <div className="space-y-4">
          {/* 1. IMPORTANT HEADERS FIRST */}
          <div className="space-y-2">
            <div className="flex items-center justify-between pb-1">
              <span className="text-[11px] font-bold uppercase tracking-wider text-foreground-muted">
                Important Essential Headers
              </span>
              <span className="text-[10px] text-foreground-subtle">
                Showing {importantHeaders.length} high-priority envelope fields
              </span>
            </div>

            <div className="space-y-2 text-xs">
              {importantHeaders.map((header, idx) => (
                <div
                  key={`important-${header.key}-${idx}`}
                  className="p-2.5 rounded-xl bg-surface-secondary/40 border border-border flex flex-col sm:flex-row sm:items-center justify-between gap-2 hover:border-primary/40 transition-colors"
                >
                  <div className="flex items-center space-x-2 text-foreground-muted min-w-[140px] shrink-0">
                    <span className="font-bold uppercase text-[11px]">{header.key}:</span>
                  </div>
                  <div className="flex-1 flex items-center justify-between gap-2 min-w-0">
                    <span className="text-foreground break-all select-all font-mono">
                      {header.value}
                    </span>
                    <CopyButton text={header.value} iconOnly />
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* 2. "VIEW ALL HEADERS" PROGRESSIVE DISCLOSURE TOGGLE */}
          <div className="pt-2 border-t border-border">
            <button
              type="button"
              onClick={() => setShowAllHeaders(!showAllHeaders)}
              className="w-full flex items-center justify-between p-3 rounded-xl bg-surface-secondary/60 hover:bg-surface-secondary border border-border text-left transition-all cursor-pointer group"
            >
              <div className="flex items-center space-x-2">
                <Key className="w-4 h-4 text-primary group-hover:scale-110 transition-transform" />
                <span className="text-xs font-bold text-foreground uppercase tracking-wider">
                  {showAllHeaders ? 'Hide All Parsed Headers' : `View All Parsed Headers (${parsedHeaders.length})`}
                </span>
              </div>
              <div className="flex items-center space-x-1.5 text-xs text-foreground-muted font-normal">
                <span>{showAllHeaders ? 'Collapse list' : 'Expand full key-value table'}</span>
                {showAllHeaders ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
              </div>
            </button>

            {showAllHeaders && (
              <div className="mt-3 p-3 rounded-xl bg-surface-secondary/20 border border-border space-y-2 animate-in fade-in duration-150 max-h-[380px] overflow-y-auto">
                {parsedHeaders.length === 0 ? (
                  <p className="text-xs text-foreground-muted italic text-center p-3">
                    No parsed headers available.
                  </p>
                ) : (
                  parsedHeaders.map((header, idx) => (
                    <div
                      key={`all-${header.key}-${idx}`}
                      className="p-2 rounded-lg bg-surface border border-border/70 flex flex-col sm:flex-row sm:items-start justify-between gap-2 text-xs"
                    >
                      <div className="min-w-[150px] shrink-0 font-bold text-primary text-[11px] pt-0.5">
                        {header.key}:
                      </div>
                      <div className="flex-1 min-w-0 text-foreground break-all select-all font-mono text-[11px] leading-relaxed">
                        {header.value}
                      </div>
                      <CopyButton text={`${header.key}: ${header.value}`} iconOnly />
                    </div>
                  ))
                )}
              </div>
            )}
          </div>

          {/* 3. SEARCHABLE RAW HEADER VIEWER */}
          <div className="pt-3 border-t border-border space-y-3">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div className="flex items-center space-x-2">
                <Filter className="w-3.5 h-3.5 text-primary" />
                <span className="text-xs font-bold uppercase tracking-wider text-foreground">
                  Searchable Raw Header Stream
                </span>
              </div>

              <div className="flex items-center space-x-2">
                <button
                  type="button"
                  onClick={() => setLineWrap(!lineWrap)}
                  className={`px-2.5 py-1 rounded-lg text-[11px] font-semibold flex items-center space-x-1.5 border transition-all cursor-pointer ${
                    lineWrap
                      ? 'bg-surface text-primary border-primary/40'
                      : 'bg-surface-secondary text-foreground-muted border-border hover:text-foreground'
                  }`}
                  title="Toggle line wrapping"
                >
                  <WrapText className="w-3.5 h-3.5" />
                  <span>Wrap lines</span>
                </button>

                <button
                  type="button"
                  onClick={handleCopyAll}
                  className="px-2.5 py-1 rounded-lg bg-surface-secondary hover:bg-surface border border-border text-foreground-muted hover:text-foreground text-[11px] font-semibold flex items-center space-x-1.5 transition-all cursor-pointer"
                >
                  {copiedAll ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-success" />
                      <span className="text-success font-bold">Copied!</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5" />
                      <span>Copy raw headers</span>
                    </>
                  )}
                </button>
              </div>
            </div>

            {/* Real-time search bar */}
            <div className="relative">
              <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-foreground-muted" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search raw headers by key, value, IP, DKIM tag, or server..."
                className="w-full pl-9 pr-20 py-2 rounded-xl bg-surface border border-border text-xs text-foreground placeholder-foreground-subtle focus:outline-none focus:border-primary font-mono transition-colors"
              />
              {searchQuery && (
                <button
                  type="button"
                  onClick={() => setSearchQuery('')}
                  className="absolute right-2.5 top-1/2 -translate-y-1/2 px-1.5 py-0.5 rounded text-[10px] text-foreground-muted hover:text-foreground bg-surface-secondary cursor-pointer"
                >
                  Clear
                </button>
              )}
            </div>

            {/* Syntax Monospace Viewer */}
            <div className="relative rounded-xl border border-border bg-neutral-950 text-neutral-200 overflow-hidden shadow-inner">
              <div className="px-3.5 py-2 bg-neutral-900 border-b border-neutral-800 flex items-center justify-between text-[10px] text-neutral-400">
                <span>RFC-822 verbatim header stream</span>
                {searchQuery ? (
                  <span className="text-warning">
                    Filtered by: &ldquo;{searchQuery}&rdquo;
                  </span>
                ) : (
                  <span>Unfiltered stream</span>
                )}
              </div>

              <pre
                className={`p-4 text-[11.5px] leading-relaxed max-h-[340px] overflow-y-auto select-all ${
                  lineWrap ? 'whitespace-pre-wrap break-all' : 'whitespace-pre overflow-x-auto'
                }`}
              >
                {filteredRawHeaders || (
                  <span className="text-neutral-500 italic">
                    No headers matching search query &ldquo;{searchQuery}&rdquo;.
                  </span>
                )}
              </pre>
            </div>
          </div>
        </div>
      </ExpandableSection>
    </div>
  );
};
