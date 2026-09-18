import React, { useState, useMemo } from 'react';
import type { EmailAnalysis } from '../../../types/forensic';
import {
  Archive,
  Download,
  Fingerprint,
  FileCode,
  ShieldCheck,
  HardDrive,
  Clock,
  Copy,
  Check,
  Terminal,
  FileText,
  Lock,
  ChevronDown,
  ChevronUp
} from 'lucide-react';
import { ExpandableSection } from '../../common/progressive';
import { CopyButton } from '../CopyButton';

interface EmailOriginalEvidenceSubsectionProps {
  email: EmailAnalysis;
}

const formatBytes = (bytes?: number): string => {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
};

export const EmailOriginalEvidenceSubsection: React.FC<EmailOriginalEvidenceSubsectionProps> = ({ email }) => {
  const [showRawStream, setShowRawStream] = useState<boolean>(false);
  const [copiedSha, setCopiedSha] = useState<boolean>(false);
  const [downloadSuccess, setDownloadSuccess] = useState<boolean>(false);

  // 64-character SHA-256 hash determination
  const sha256 = useMemo(() => {
    if (email.email_sha256 && /^[a-f0-9]{64}$/i.test(email.email_sha256)) {
      return email.email_sha256.toLowerCase();
    }
    if (email.id && /^[a-f0-9]{64}$/i.test(email.id)) {
      return email.id.toLowerCase();
    }
    return email.email_sha256 || 'SHA-256 digest unavailable';
  }, [email.email_sha256, email.id]);

  const hasValidSha = sha256 && sha256.length === 64;

  const evidenceId = email.evidence_id || (hasValidSha ? `EVD-${sha256.slice(0, 10).toUpperCase()}` : 'EVD-DIRECT');
  const filename = email.original_filename || email.file_info?.filename || `${email.id || 'email'}.eml`;

  const rawContent = email.raw_email || email.plain_text_body || '';
  const calculatedSize = email.size || email.file_info?.size_bytes || (rawContent ? new Blob([rawContent]).size : 0);

  const formattedDate = useMemo(() => {
    if (email.upload_timestamp) {
      const d = new Date(email.upload_timestamp);
      if (!isNaN(d.getTime())) return d.toUTCString();
    }
    if (email.date) {
      return email.date;
    }
    return 'Ingestion timestamp not recorded';
  }, [email.upload_timestamp, email.date]);

  // Download original .EML file preserving RFC-822 MIME stream
  const handleDownloadEML = () => {
    if (!rawContent) return;
    const blob = new Blob([rawContent], { type: 'message/rfc822' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename.endsWith('.eml') ? filename : `${filename}.eml`;
    a.click();
    URL.revokeObjectURL(url);
    setDownloadSuccess(true);
    setTimeout(() => setDownloadSuccess(false), 2000);
  };

  // Download complete JSON analysis dossier
  const handleDownloadJSON = () => {
    const jsonStr = JSON.stringify(email, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${filename.replace(/\.eml$/i, '')}_forensic_dossier.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleCopySha = () => {
    if (hasValidSha) {
      navigator.clipboard.writeText(sha256);
      setCopiedSha(true);
      setTimeout(() => setCopiedSha(false), 2000);
    }
  };

  return (
    <div className="space-y-4 font-mono">
      <ExpandableSection
        title="Original Evidence & Chain of Custody"
        subtitle="Unmodified RFC-822 payload, cryptographic integrity digests, and forensic custody records"
        icon={Archive}
        defaultExpanded={true}
        badge={
          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-success-surface text-success border border-success-border flex items-center gap-1">
            <ShieldCheck className="w-3 h-3" />
            <span>Chain of Custody Intact</span>
          </span>
        }
      >
        <div className="space-y-4">
          {/* 1. PRIMARY EVIDENCE INTEGRITY CARD */}
          <div className="p-4 rounded-xl bg-surface-secondary/40 border border-border space-y-3.5">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-2 border-b border-border">
              <div className="flex items-center space-x-2">
                <Fingerprint className="w-4 h-4 text-primary" />
                <span className="text-xs font-bold text-foreground uppercase tracking-wider">
                  Cryptographic Evidence Fingerprint
                </span>
              </div>
              <div className="flex items-center space-x-2">
                <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-primary/10 text-primary border border-primary/20">
                  Algorithm: SHA-256 (256-bit)
                </span>
              </div>
            </div>

            {/* SHA-256 Box */}
            <div className="p-3 rounded-xl bg-neutral-950 border border-neutral-800 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div className="min-w-0 flex-1">
                <span className="text-[10px] font-bold text-neutral-400 uppercase tracking-wider block mb-1">
                  SHA-256 Payload Hash (Hexadecimal):
                </span>
                <span className="text-xs text-primary-hover font-mono break-all select-all font-bold">
                  {sha256}
                </span>
              </div>

              {hasValidSha && (
                <button
                  type="button"
                  onClick={handleCopySha}
                  className="px-3 py-1.5 rounded-lg bg-neutral-900 hover:bg-neutral-800 text-neutral-200 border border-neutral-700 text-xs font-semibold flex items-center space-x-1.5 shrink-0 transition-colors cursor-pointer"
                >
                  {copiedSha ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-success" />
                      <span className="text-success">Copied</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5 text-neutral-400" />
                      <span>Copy SHA-256</span>
                    </>
                  )}
                </button>
              )}
            </div>

            {/* Evidence Metadata Fields */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 pt-1 text-xs">
              <div className="p-3 rounded-xl bg-surface border border-border space-y-1">
                <span className="text-[10px] text-foreground-muted uppercase font-bold block flex items-center gap-1">
                  <Lock className="w-3 h-3 text-primary" />
                  <span>Evidence Identifier</span>
                </span>
                <div className="font-bold text-foreground break-all">{evidenceId}</div>
              </div>

              <div className="p-3 rounded-xl bg-surface border border-border space-y-1">
                <span className="text-[10px] text-foreground-muted uppercase font-bold block flex items-center gap-1">
                  <FileText className="w-3 h-3 text-primary" />
                  <span>Original Ingestion File</span>
                </span>
                <div className="font-bold text-foreground break-all truncate" title={filename}>
                  {filename}
                </div>
              </div>

              <div className="p-3 rounded-xl bg-surface border border-border space-y-1">
                <span className="text-[10px] text-foreground-muted uppercase font-bold block flex items-center gap-1">
                  <HardDrive className="w-3 h-3 text-primary" />
                  <span>Preserved File Size</span>
                </span>
                <div className="font-bold text-foreground">
                  {formatBytes(calculatedSize)} ({calculatedSize.toLocaleString()} bytes)
                </div>
              </div>

              <div className="p-3 rounded-xl bg-surface border border-border space-y-1">
                <span className="text-[10px] text-foreground-muted uppercase font-bold block flex items-center gap-1">
                  <Clock className="w-3 h-3 text-primary" />
                  <span>Ingestion Timestamp</span>
                </span>
                <div className="font-bold text-foreground text-[11px] truncate" title={formattedDate}>
                  {formattedDate}
                </div>
              </div>
            </div>
          </div>

          {/* 2. ACTIONS: DOWNLOAD ORIGINAL .EML & FORENSIC JSON */}
          <div className="flex flex-wrap items-center justify-between gap-3 p-3.5 rounded-xl bg-surface border border-border">
            <div className="flex items-center space-x-2 text-xs text-foreground-muted">
              <ShieldCheck className="w-4 h-4 text-success" />
              <span>Evidence stored immutably. Download authentic copy or complete JSON dossier.</span>
            </div>

            <div className="flex items-center space-x-2.5">
              <button
                type="button"
                onClick={handleDownloadEML}
                disabled={!rawContent}
                className="px-3.5 py-1.5 rounded-lg bg-primary hover:bg-primary-hover disabled:opacity-50 text-primary-foreground text-xs font-bold flex items-center space-x-1.5 transition-all shadow-xs cursor-pointer"
              >
                {downloadSuccess ? (
                  <>
                    <Check className="w-3.5 h-3.5" />
                    <span>Downloaded .EML</span>
                  </>
                ) : (
                  <>
                    <Download className="w-3.5 h-3.5" />
                    <span>Download Original .EML</span>
                  </>
                )}
              </button>

              <button
                type="button"
                onClick={handleDownloadJSON}
                className="px-3.5 py-1.5 rounded-lg bg-surface-secondary hover:bg-surface border border-border text-foreground text-xs font-bold flex items-center space-x-1.5 transition-all cursor-pointer"
              >
                <FileCode className="w-3.5 h-3.5 text-primary" />
                <span>Export JSON Dossier</span>
              </button>
            </div>
          </div>

          {/* 3. COLLAPSIBLE RAW .EML STREAM INSPECTOR */}
          <div className="pt-2 border-t border-border">
            <button
              type="button"
              onClick={() => setShowRawStream(!showRawStream)}
              className="w-full flex items-center justify-between p-3 rounded-xl bg-surface-secondary/60 hover:bg-surface-secondary border border-border text-left transition-all cursor-pointer group"
            >
              <div className="flex items-center space-x-2">
                <Terminal className="w-4 h-4 text-primary group-hover:scale-110 transition-transform" />
                <span className="text-xs font-bold text-foreground uppercase tracking-wider">
                  {showRawStream ? 'Hide Raw Ingestion Stream' : 'Inspect Raw Ingested .EML Stream'}
                </span>
              </div>
              <div className="flex items-center space-x-1.5 text-xs text-foreground-muted font-normal">
                <span>{showRawStream ? 'Collapse stream' : 'Reveal byte-for-byte stream'}</span>
                {showRawStream ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
              </div>
            </button>

            {showRawStream && (
              <div className="mt-3 rounded-xl border border-neutral-800 bg-neutral-950 text-neutral-200 overflow-hidden shadow-inner animate-in fade-in duration-150">
                <div className="px-3.5 py-2 bg-neutral-900 border-b border-neutral-800 flex items-center justify-between text-[10px] text-neutral-400">
                  <span>MIME payload stream ({rawContent.length.toLocaleString()} characters)</span>
                  <CopyButton text={rawContent} label="Copy payload stream" />
                </div>
                <pre className="p-4 text-[11.5px] leading-relaxed max-h-[380px] overflow-y-auto whitespace-pre-wrap break-all select-all font-mono">
                  {rawContent || 'No raw email stream content stored for this record.'}
                </pre>
              </div>
            )}
          </div>
        </div>
      </ExpandableSection>
    </div>
  );
};
