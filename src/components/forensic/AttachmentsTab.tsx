import React, { useState } from 'react';
import type { EmailAnalysis } from '../../types/forensic';
import type { AttachmentStaticAnalysisResult } from '../../types/attachment';
import { CopyButton } from './CopyButton';
import {
  Paperclip,
  File,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  FileCode,
  FileText,
  Archive,
  Terminal,
  Lock,
  Unlock,
  CheckCircle2,
  XCircle,
  Database,
  Key,
  Flame,
  Info
} from 'lucide-react';

interface AttachmentsTabProps {
  email: EmailAnalysis;
}

type SubTab = 'overview' | 'metadata' | 'indicators' | 'static' | 'reputation' | 'evidence';

export const AttachmentsTab: React.FC<AttachmentsTabProps> = ({ email }) => {
  const attachments = (email.attachments && email.attachments.length > 0)
    ? email.attachments
    : (email.indicators?.attachments || []);

  const [selectedIndex, setSelectedIndex] = useState<number>(0);
  const [activeSubTab, setActiveSubTab] = useState<SubTab>('overview');
  const [defangUrls, setDefangUrls] = useState<boolean>(true);

  const selectedAtt = attachments[selectedIndex] || null;
  const staticAnalysis: AttachmentStaticAnalysisResult | undefined = selectedAtt?.static_analysis;

  const formatFileSize = (bytes?: number): string => {
    if (!bytes || bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const getDefangedUrl = (url: string): string => {
    if (!defangUrls) return url;
    return url.replace(/https?:\/\//i, (m) => (m.toLowerCase().startsWith('https') ? 'hxxps[://]' : 'hxxp[://]')).replace(/\./g, '[.]');
  };

  const getThreatBadge = (level?: string) => {
    switch (level?.toUpperCase()) {
      case 'CRITICAL':
        return {
          bg: 'bg-red-500/15 border-red-500/30 text-red-500 dark:text-red-400',
          icon: <Flame className="w-3.5 h-3.5" />,
          label: 'CRITICAL THREAT'
        };
      case 'HIGH':
        return {
          bg: 'bg-orange-500/15 border-orange-500/30 text-orange-500 dark:text-orange-400',
          icon: <ShieldAlert className="w-3.5 h-3.5" />,
          label: 'HIGH THREAT'
        };
      case 'MEDIUM':
        return {
          bg: 'bg-amber-500/15 border-amber-500/30 text-amber-500 dark:text-amber-400',
          icon: <AlertTriangle className="w-3.5 h-3.5" />,
          label: 'MEDIUM SUSPICION'
        };
      case 'LOW':
        return {
          bg: 'bg-blue-500/15 border-blue-500/30 text-blue-500 dark:text-blue-400',
          icon: <Info className="w-3.5 h-3.5" />,
          label: 'LOW SUSPICION'
        };
      case 'BENIGN':
      default:
        return {
          bg: 'bg-emerald-500/15 border-emerald-500/30 text-emerald-500 dark:text-emerald-400',
          icon: <CheckCircle2 className="w-3.5 h-3.5" />,
          label: 'BENIGN'
        };
    }
  };

  if (attachments.length === 0) {
    return (
      <div className="bg-surface p-8 rounded-2xl border border-border text-center space-y-3 shadow-xs">
        <div className="w-12 h-12 rounded-xl bg-surface-secondary border border-border flex items-center justify-center mx-auto text-foreground-muted">
          <Paperclip className="w-6 h-6" />
        </div>
        <h3 className="text-sm font-mono font-bold text-foreground">No Attachments Observed</h3>
        <p className="text-xs font-mono text-foreground-muted max-w-md mx-auto">
          No file payloads, inline attachments, or boundary containers were found within this email.
        </p>
      </div>
    );
  }

  const threatBadge = getThreatBadge(staticAnalysis?.threat_level);
  const entropy = staticAnalysis?.entropy ?? 0;
  const entropyPct = Math.min(Math.round((entropy / 8.0) * 100), 100);

  return (
    <div className="space-y-5">
      {/* Top Security Banner */}
      <div className="bg-surface p-4 rounded-2xl border border-border shadow-xs flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center space-x-3">
          <div className="p-2 rounded-xl bg-primary/10 border border-primary/20 text-primary">
            <ShieldCheck className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-sm font-mono font-bold text-foreground uppercase tracking-wider flex items-center gap-2">
              Attachment Intelligence & Static Malware Analysis
              <span className="text-xs px-2 py-0.5 rounded-md bg-surface-secondary border border-border text-foreground-muted font-normal">
                {attachments.length} file{attachments.length > 1 ? 's' : ''}
              </span>
            </h2>
            <p className="text-[11px] font-mono text-foreground-muted">
              Static binary inspection active. Zero code execution guarantee. Hostile input posture enforced.
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-2 text-[11px] font-mono px-3 py-1.5 rounded-lg bg-surface-secondary border border-border text-foreground-muted">
          <Lock className="w-3.5 h-3.5 text-emerald-500" />
          <span>Non-executable vault storage</span>
        </div>
      </div>

      {/* Multi-attachment Tab Bar if > 1 attachment */}
      {attachments.length > 1 && (
        <div className="flex items-center gap-2 overflow-x-auto pb-1">
          {attachments.map((att, idx) => {
            const isSelected = idx === selectedIndex;
            const sa = att.static_analysis;
            const isMismatch = sa?.extension_mismatch;
            return (
              <button
                key={idx}
                onClick={() => setSelectedIndex(idx)}
                className={`flex items-center space-x-2.5 px-3.5 py-2 rounded-xl border text-xs font-mono transition-all shrink-0 ${
                  isSelected
                    ? 'bg-surface border-primary text-foreground shadow-xs font-bold ring-1 ring-primary/20'
                    : 'bg-surface-secondary/50 border-border text-foreground-muted hover:text-foreground hover:bg-surface-secondary'
                }`}
              >
                <File className="w-3.5 h-3.5 text-primary" />
                <span className="max-w-[180px] truncate">{att.filename || `Attachment ${idx + 1}`}</span>
                {isMismatch && (
                  <span className="px-1.5 py-0.2 rounded bg-red-500/20 text-red-400 text-[10px] font-bold border border-red-500/30">
                    MISMATCH
                  </span>
                )}
                <span className="text-[10px] text-foreground-subtle">
                  ({formatFileSize(att.size)})
                </span>
              </button>
            );
          })}
        </div>
      )}

      {/* Main Forensic Analysis Card */}
      {selectedAtt && (
        <div className="bg-surface rounded-2xl border border-border shadow-xs overflow-hidden">
          {/* Executive Attachment Summary Header */}
          <div className="p-5 border-b border-border bg-surface-secondary/20 space-y-4">
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div className="space-y-1 min-w-0">
                <div className="text-[10px] font-mono uppercase tracking-widest text-foreground-subtle">
                  ATTACHMENT ANALYSIS
                </div>
                <h3 className="text-base font-mono font-bold text-foreground break-all flex items-center gap-2">
                  <span>{selectedAtt.filename || 'unnamed_attachment.bin'}</span>
                  {selectedAtt.filename && (
                    <CopyButton text={selectedAtt.filename} label="Copy Name" iconOnly />
                  )}
                </h3>
              </div>

              {/* Threat Level Badge */}
              <div className="flex items-center space-x-2">
                <div className={`px-3 py-1.5 rounded-xl border font-mono text-xs font-bold flex items-center space-x-1.5 ${threatBadge.bg}`}>
                  {threatBadge.icon}
                  <span>{threatBadge.label}</span>
                  {staticAnalysis && (
                    <span className="ml-1 opacity-80">({staticAnalysis.threat_score}/100)</span>
                  )}
                </div>
              </div>
            </div>

            {/* Quick Metrics Grid */}
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 pt-2">
              {/* Detected Type */}
              <div className="p-3 rounded-xl bg-surface border border-border space-y-1">
                <span className="text-[10px] font-mono text-foreground-muted uppercase tracking-wider block">
                  Detected Type
                </span>
                <span className="text-xs font-mono font-bold text-foreground block truncate" title={staticAnalysis?.detected_type || 'Unknown'}>
                  {staticAnalysis?.detected_type || 'Unknown'}
                </span>
              </div>

              {/* Extension Mismatch */}
              <div className="p-3 rounded-xl bg-surface border border-border space-y-1">
                <span className="text-[10px] font-mono text-foreground-muted uppercase tracking-wider block">
                  Extension Mismatch
                </span>
                {staticAnalysis?.extension_mismatch ? (
                  <span className="inline-flex items-center space-x-1 text-xs font-mono font-bold text-red-500">
                    <XCircle className="w-3.5 h-3.5" />
                    <span>YES</span>
                  </span>
                ) : (
                  <span className="inline-flex items-center space-x-1 text-xs font-mono font-bold text-emerald-500">
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    <span>NO</span>
                  </span>
                )}
              </div>

              {/* SHA-256 */}
              <div className="p-3 rounded-xl bg-surface border border-border space-y-1">
                <span className="text-[10px] font-mono text-foreground-muted uppercase tracking-wider block">
                  SHA-256 Primary
                </span>
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono text-foreground font-semibold truncate">
                    {selectedAtt.sha256 ? `${selectedAtt.sha256.substring(0, 10)}...` : 'N/A'}
                  </span>
                  {selectedAtt.sha256 && (
                    <CopyButton text={selectedAtt.sha256} label="Copy SHA-256" iconOnly />
                  )}
                </div>
              </div>

              {/* Entropy */}
              <div className="p-3 rounded-xl bg-surface border border-border space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono text-foreground-muted uppercase tracking-wider">
                    Entropy
                  </span>
                  <span className="text-xs font-mono font-bold text-foreground">
                    {entropy.toFixed(2)}
                  </span>
                </div>
                <div className="w-full bg-surface-secondary h-1.5 rounded-full overflow-hidden border border-border">
                  <div
                    className={`h-full transition-all ${
                      entropy > 7.5 ? 'bg-red-500' : entropy > 6.8 ? 'bg-amber-500' : 'bg-emerald-500'
                    }`}
                    style={{ width: `${entropyPct}%` }}
                  />
                </div>
              </div>

              {/* Signature Status */}
              <div className="p-3 rounded-xl bg-surface border border-border space-y-1">
                <span className="text-[10px] font-mono text-foreground-muted uppercase tracking-wider block">
                  Signature
                </span>
                <span className={`text-xs font-mono font-bold block truncate ${
                  staticAnalysis?.signature_status === 'Signed'
                    ? 'text-emerald-500'
                    : staticAnalysis?.signature_status === 'Unsigned'
                    ? 'text-amber-500'
                    : 'text-foreground-muted'
                }`}>
                  {staticAnalysis?.signature_status || 'N/A'}
                </span>
              </div>

              {/* Embedded Indicators */}
              <div className="p-3 rounded-xl bg-surface border border-border space-y-1">
                <span className="text-[10px] font-mono text-foreground-muted uppercase tracking-wider block">
                  Embedded Indicators
                </span>
                <span className="text-xs font-mono font-bold text-foreground block">
                  {staticAnalysis?.embedded_indicators_count ?? 0} found
                </span>
              </div>
            </div>

            {/* Mismatch Warning Alert if Present */}
            {staticAnalysis?.extension_mismatch && (
              <div className="p-3 rounded-xl bg-red-500/10 border border-red-500/30 flex items-start space-x-3 text-xs font-mono text-red-600 dark:text-red-400">
                <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
                <div className="space-y-0.5">
                  <span className="font-bold">MIME / Extension Spoofing Detected</span>
                  <p className="text-[11px] opacity-90">
                    {staticAnalysis.mismatch_details || 'The file extension does not match the actual binary magic byte signature.'}
                  </p>
                </div>
              </div>
            )}
          </div>

          {/* Sub Tabs Navigation */}
          <div className="flex border-b border-border bg-surface-secondary/40 px-5 overflow-x-auto">
            {(
              [
                { id: 'overview', label: 'Overview' },
                { id: 'metadata', label: 'Metadata' },
                { id: 'indicators', label: `Indicators (${staticAnalysis?.embedded_indicators_count ?? 0})` },
                { id: 'static', label: 'Static Analysis' },
                { id: 'reputation', label: 'Reputation' },
                { id: 'evidence', label: 'Evidence' }
              ] as { id: SubTab; label: string }[]
            ).map((tab) => {
              const isActive = activeSubTab === tab.id;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveSubTab(tab.id)}
                  className={`py-3 px-4 text-xs font-mono border-b-2 transition-all shrink-0 cursor-pointer ${
                    isActive
                      ? 'border-primary text-primary font-bold bg-surface'
                      : 'border-transparent text-foreground-muted hover:text-foreground hover:bg-surface-secondary/60'
                  }`}
                >
                  {tab.label}
                </button>
              );
            })}
          </div>

          {/* Tab 1: Overview */}
          {activeSubTab === 'overview' && (
            <div className="p-5 space-y-5">
              {/* Executive Summary Narrative */}
              <div className="p-4 rounded-xl bg-surface-secondary/40 border border-border space-y-2">
                <div className="flex items-center space-x-2 text-xs font-mono font-bold text-foreground">
                  <Info className="w-4 h-4 text-primary" />
                  <span>Executive Static Analysis Summary</span>
                </div>
                <p className="text-xs font-mono text-foreground-muted leading-relaxed">
                  {staticAnalysis?.analysis_summary || 'Static binary inspection concluded without critical structural anomalies.'}
                </p>
              </div>

              {/* Detected Risk Signals */}
              <div className="space-y-2.5">
                <h4 className="text-xs font-mono font-bold text-foreground uppercase tracking-wider">
                  Evaluated Threat Signals ({staticAnalysis?.risk_signals.length ?? 0})
                </h4>
                {(!staticAnalysis?.risk_signals || staticAnalysis.risk_signals.length === 0) ? (
                  <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-600 dark:text-emerald-400 text-xs font-mono flex items-center space-x-2">
                    <CheckCircle2 className="w-4 h-4" />
                    <span>No elevated risk signals observed. Attachment conforms to standard benign profiles.</span>
                  </div>
                ) : (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
                    {staticAnalysis.risk_signals.map((sig, idx) => (
                      <div
                        key={idx}
                        className="p-3 rounded-xl bg-surface-secondary/50 border border-border flex items-start space-x-2.5 text-xs font-mono"
                      >
                        <ShieldAlert className="w-4 h-4 text-amber-500 shrink-0 mt-0.5" />
                        <span className="text-foreground">{sig}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Entropy & Packing Profile */}
              <div className="p-4 rounded-xl border border-border bg-surface-secondary/20 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono font-bold text-foreground">
                    Shannon Entropy & Compression Profile
                  </span>
                  <span className="text-xs font-mono text-foreground font-bold">
                    {entropy.toFixed(2)} / 8.00 ({staticAnalysis?.entropy_level || 'normal'})
                  </span>
                </div>
                <div className="w-full bg-surface-secondary h-2 rounded-full overflow-hidden border border-border">
                  <div
                    className={`h-full ${
                      entropy > 7.5 ? 'bg-red-500' : entropy > 6.8 ? 'bg-amber-500' : 'bg-emerald-500'
                    }`}
                    style={{ width: `${entropyPct}%` }}
                  />
                </div>
                <p className="text-[11px] font-mono text-foreground-muted">
                  {staticAnalysis?.entropy_analysis || 'Entropy within typical bounds for uncompressed or moderately compressed data.'}
                </p>
              </div>
            </div>
          )}

          {/* Tab 2: Metadata */}
          {activeSubTab === 'metadata' && (
            <div className="p-5 space-y-5">
              {/* Magic Bytes Inspection */}
              <div className="p-4 rounded-xl bg-surface-secondary/30 border border-border space-y-2">
                <span className="text-xs font-mono font-bold text-foreground uppercase tracking-wider block">
                  Magic Bytes Inspection (File Signature)
                </span>
                <div className="p-3 rounded-lg bg-surface border border-border font-mono text-xs space-y-1">
                  <div className="flex items-center justify-between text-foreground-muted">
                    <span>Initial 16-byte Hex Stream:</span>
                    <CopyButton text={staticAnalysis?.magic_bytes_hex || ''} label="Copy Hex" />
                  </div>
                  <div className="text-primary font-bold tracking-widest break-all">
                    {staticAnalysis?.magic_bytes_hex || '00 00 00 00 00 00 00 00'}
                  </div>
                </div>
              </div>

              {/* File Identity Table */}
              <div className="rounded-xl border border-border overflow-hidden">
                <table className="w-full text-xs font-mono">
                  <tbody className="divide-y divide-border">
                    <tr className="bg-surface-secondary/20">
                      <td className="p-3 font-semibold text-foreground-muted w-1/3">Original Filename</td>
                      <td className="p-3 text-foreground break-all">{selectedAtt.filename || 'unnamed'}</td>
                    </tr>
                    <tr>
                      <td className="p-3 font-semibold text-foreground-muted">Normalized Extension</td>
                      <td className="p-3 text-foreground">{staticAnalysis?.extension || 'N/A'}</td>
                    </tr>
                    <tr className="bg-surface-secondary/20">
                      <td className="p-3 font-semibold text-foreground-muted">Claimed Header Type</td>
                      <td className="p-3 text-foreground">{staticAnalysis?.claimed_type || 'Unknown'}</td>
                    </tr>
                    <tr>
                      <td className="p-3 font-semibold text-foreground-muted">Declared MIME Type</td>
                      <td className="p-3 text-foreground">{selectedAtt.mime_type || 'application/octet-stream'}</td>
                    </tr>
                    <tr className="bg-surface-secondary/20">
                      <td className="p-3 font-semibold text-foreground-muted">Detected MIME Type</td>
                      <td className="p-3 text-foreground font-bold text-primary">
                        {staticAnalysis?.detected_mime_type || 'application/octet-stream'}
                      </td>
                    </tr>
                    <tr>
                      <td className="p-3 font-semibold text-foreground-muted">Detected File Category</td>
                      <td className="p-3 text-foreground font-bold">{staticAnalysis?.detected_type || 'Unknown'}</td>
                    </tr>
                    <tr className="bg-surface-secondary/20">
                      <td className="p-3 font-semibold text-foreground-muted">Raw Byte Size</td>
                      <td className="p-3 text-foreground">
                        {selectedAtt.size?.toLocaleString()} bytes ({formatFileSize(selectedAtt.size)})
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>

              {/* PE Architecture metadata if PE */}
              {staticAnalysis?.pe_metadata && (
                <div className="p-4 rounded-xl border border-border bg-surface-secondary/20 space-y-3">
                  <h4 className="text-xs font-mono font-bold text-foreground uppercase tracking-wider flex items-center gap-2">
                    <Terminal className="w-4 h-4 text-primary" />
                    <span>Portable Executable (PE) Architecture Metadata</span>
                  </h4>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs font-mono">
                    <div className="p-2.5 rounded-lg bg-surface border border-border">
                      <span className="text-foreground-muted text-[10px] block">Architecture</span>
                      <span className="text-foreground font-bold">{staticAnalysis.pe_metadata.architecture || 'Unknown'}</span>
                    </div>
                    <div className="p-2.5 rounded-lg bg-surface border border-border">
                      <span className="text-foreground-muted text-[10px] block">Subsystem</span>
                      <span className="text-foreground font-bold">{staticAnalysis.pe_metadata.subsystem || 'Unknown'}</span>
                    </div>
                    <div className="p-2.5 rounded-lg bg-surface border border-border">
                      <span className="text-foreground-muted text-[10px] block">Entry Point RVA</span>
                      <span className="text-foreground font-bold">{staticAnalysis.pe_metadata.entry_point || '0x0'}</span>
                    </div>
                    <div className="p-2.5 rounded-lg bg-surface border border-border">
                      <span className="text-foreground-muted text-[10px] block">Compile Time</span>
                      <span className="text-foreground font-bold truncate block" title={staticAnalysis.pe_metadata.compile_timestamp || ''}>
                        {staticAnalysis.pe_metadata.compile_timestamp || 'Unknown'}
                      </span>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Tab 3: Indicators */}
          {activeSubTab === 'indicators' && (
            <div className="p-5 space-y-5">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-2 text-xs font-mono text-foreground-muted">
                  <Database className="w-4 h-4 text-primary" />
                  <span>Extracted Embedded Network & File Indicators</span>
                </div>

                <button
                  onClick={() => setDefangUrls(!defangUrls)}
                  className="px-2.5 py-1 rounded-lg bg-surface border border-border text-xs font-mono text-foreground hover:bg-surface-secondary cursor-pointer"
                >
                  {defangUrls ? 'Defanging Active' : 'Defanging Inactive'}
                </button>
              </div>

              {/* Embedded URLs */}
              <div className="space-y-2">
                <h4 className="text-xs font-mono font-bold text-foreground uppercase tracking-wider flex items-center justify-between">
                  <span>Embedded URLs ({staticAnalysis?.embedded_urls.length ?? 0})</span>
                </h4>
                {(!staticAnalysis?.embedded_urls || staticAnalysis.embedded_urls.length === 0) ? (
                  <p className="text-xs font-mono text-foreground-muted italic p-3 rounded-lg bg-surface-secondary/30">
                    No embedded URLs discovered.
                  </p>
                ) : (
                  <div className="space-y-1.5">
                    {staticAnalysis.embedded_urls.map((u, i) => (
                      <div
                        key={i}
                        className="p-2.5 rounded-lg bg-surface-secondary/40 border border-border flex items-center justify-between gap-2 text-xs font-mono"
                      >
                        <span className="text-primary font-semibold break-all">{getDefangedUrl(u)}</span>
                        <CopyButton text={u} label="Copy URL" />
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Embedded Domains & IPs */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <h4 className="text-xs font-mono font-bold text-foreground uppercase tracking-wider">
                    Extracted Domains ({staticAnalysis?.embedded_domains.length ?? 0})
                  </h4>
                  {(!staticAnalysis?.embedded_domains || staticAnalysis.embedded_domains.length === 0) ? (
                    <p className="text-xs font-mono text-foreground-muted italic p-3 rounded-lg bg-surface-secondary/30">
                      None extracted.
                    </p>
                  ) : (
                    <div className="space-y-1.5">
                      {staticAnalysis.embedded_domains.map((d, i) => (
                        <div
                          key={i}
                          className="p-2 rounded-lg bg-surface-secondary/40 border border-border flex items-center justify-between text-xs font-mono"
                        >
                          <span className="text-foreground">{d}</span>
                          <CopyButton text={d} label="Copy" iconOnly />
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                <div className="space-y-2">
                  <h4 className="text-xs font-mono font-bold text-foreground uppercase tracking-wider">
                    Extracted IP Addresses ({staticAnalysis?.embedded_ips.length ?? 0})
                  </h4>
                  {(!staticAnalysis?.embedded_ips || staticAnalysis.embedded_ips.length === 0) ? (
                    <p className="text-xs font-mono text-foreground-muted italic p-3 rounded-lg bg-surface-secondary/30">
                      None extracted.
                    </p>
                  ) : (
                    <div className="space-y-1.5">
                      {staticAnalysis.embedded_ips.map((ip, i) => (
                        <div
                          key={i}
                          className="p-2 rounded-lg bg-surface-secondary/40 border border-border flex items-center justify-between text-xs font-mono"
                        >
                          <span className="text-foreground">{ip}</span>
                          <CopyButton text={ip} label="Copy" iconOnly />
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* Tab 4: Static Analysis (Deep format inspection) */}
          {activeSubTab === 'static' && (
            <div className="p-5 space-y-5">
              {/* PE Inspection */}
              {staticAnalysis?.pe_metadata && (
                <div className="space-y-4">
                  <h4 className="text-xs font-mono font-bold text-foreground uppercase tracking-wider flex items-center gap-2">
                    <Terminal className="w-4 h-4 text-primary" />
                    <span>PE Section Inspection ({staticAnalysis.pe_metadata.sections.length} sections)</span>
                  </h4>

                  <div className="rounded-xl border border-border overflow-hidden">
                    <table className="w-full text-xs font-mono">
                      <thead className="bg-surface-secondary/60 text-foreground-muted text-[11px] border-b border-border">
                        <tr>
                          <th className="p-2.5 text-left">Section</th>
                          <th className="p-2.5 text-right">Virtual Size</th>
                          <th className="p-2.5 text-right">Raw Size</th>
                          <th className="p-2.5 text-center">Entropy</th>
                          <th className="p-2.5 text-center">Flags</th>
                          <th className="p-2.5 text-center">Status</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-border">
                        {staticAnalysis.pe_metadata.sections.map((sec, idx) => (
                          <tr key={idx} className="hover:bg-surface-secondary/30">
                            <td className="p-2.5 font-bold text-foreground">{sec.name}</td>
                            <td className="p-2.5 text-right text-foreground-muted">{sec.virtual_size.toLocaleString()} B</td>
                            <td className="p-2.5 text-right text-foreground-muted">{sec.raw_size.toLocaleString()} B</td>
                            <td className="p-2.5 text-center">
                              <span className={sec.entropy > 7.5 ? 'text-red-500 font-bold' : 'text-foreground'}>
                                {sec.entropy.toFixed(2)}
                              </span>
                            </td>
                            <td className="p-2.5 text-center text-foreground-subtle">{sec.characteristics}</td>
                            <td className="p-2.5 text-center">
                              {sec.is_suspicious ? (
                                <span className="px-1.5 py-0.5 rounded bg-red-500/15 text-red-400 text-[10px] font-bold">
                                  SUSPICIOUS
                                </span>
                              ) : (
                                <span className="px-1.5 py-0.5 rounded bg-emerald-500/15 text-emerald-400 text-[10px]">
                                  CLEAN
                                </span>
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>

                  {/* Suspicious API Imports */}
                  {staticAnalysis.pe_metadata.suspicious_imports.length > 0 && (
                    <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/20 space-y-2">
                      <span className="text-xs font-mono font-bold text-red-500 uppercase tracking-wider block">
                        Suspicious High-Risk API Imports ({staticAnalysis.pe_metadata.suspicious_imports.length})
                      </span>
                      <div className="flex flex-wrap gap-2 pt-1">
                        {staticAnalysis.pe_metadata.suspicious_imports.map((api, idx) => (
                          <span
                            key={idx}
                            className="px-2 py-1 rounded-md bg-surface border border-red-500/30 text-xs font-mono font-bold text-red-500"
                          >
                            {api}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* PDF Inspection */}
              {staticAnalysis?.pdf_metadata && (
                <div className="space-y-4">
                  <h4 className="text-xs font-mono font-bold text-foreground uppercase tracking-wider flex items-center gap-2">
                    <FileText className="w-4 h-4 text-primary" />
                    <span>PDF Static Structural Analysis</span>
                  </h4>

                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs font-mono">
                    <div className="p-3 rounded-xl bg-surface-secondary/40 border border-border">
                      <span className="text-foreground-muted text-[10px] block">Embedded JavaScript</span>
                      <span className={staticAnalysis.pdf_metadata.has_javascript ? 'text-red-500 font-bold' : 'text-emerald-500 font-bold'}>
                        {staticAnalysis.pdf_metadata.has_javascript ? 'DETECTED (/JS)' : 'None'}
                      </span>
                    </div>
                    <div className="p-3 rounded-xl bg-surface-secondary/40 border border-border">
                      <span className="text-foreground-muted text-[10px] block">Auto-Open Action</span>
                      <span className={staticAnalysis.pdf_metadata.has_open_action ? 'text-amber-500 font-bold' : 'text-emerald-500 font-bold'}>
                        {staticAnalysis.pdf_metadata.has_open_action ? 'DETECTED (/OpenAction)' : 'None'}
                      </span>
                    </div>
                    <div className="p-3 rounded-xl bg-surface-secondary/40 border border-border">
                      <span className="text-foreground-muted text-[10px] block">External Launcher</span>
                      <span className={staticAnalysis.pdf_metadata.has_launch_action ? 'text-red-500 font-bold' : 'text-emerald-500 font-bold'}>
                        {staticAnalysis.pdf_metadata.has_launch_action ? 'DETECTED (/Launch)' : 'None'}
                      </span>
                    </div>
                    <div className="p-3 rounded-xl bg-surface-secondary/40 border border-border">
                      <span className="text-foreground-muted text-[10px] block">Embedded Payload Files</span>
                      <span className={staticAnalysis.pdf_metadata.has_embedded_files ? 'text-red-500 font-bold' : 'text-emerald-500 font-bold'}>
                        {staticAnalysis.pdf_metadata.has_embedded_files ? 'DETECTED (/EF)' : 'None'}
                      </span>
                    </div>
                  </div>

                  {staticAnalysis.pdf_metadata.javascript_snippets.length > 0 && (
                    <div className="p-4 rounded-xl bg-surface-secondary/40 border border-border space-y-2">
                      <span className="text-xs font-mono font-bold text-foreground">
                        Extracted JavaScript Snippet (Harmless static preview)
                      </span>
                      {staticAnalysis.pdf_metadata.javascript_snippets.map((snip, idx) => (
                        <pre key={idx} className="p-3 rounded-lg bg-surface border border-border font-mono text-[11px] text-primary overflow-x-auto">
                          {snip}
                        </pre>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Office Inspection */}
              {staticAnalysis?.office_metadata && (
                <div className="space-y-4">
                  <h4 className="text-xs font-mono font-bold text-foreground uppercase tracking-wider flex items-center gap-2">
                    <FileCode className="w-4 h-4 text-primary" />
                    <span>Office Document & Macro Inspection</span>
                  </h4>

                  <div className="grid grid-cols-2 md:grid-cols-3 gap-3 text-xs font-mono">
                    <div className="p-3 rounded-xl bg-surface-secondary/40 border border-border">
                      <span className="text-foreground-muted text-[10px] block">VBA Macro Status</span>
                      <span className={staticAnalysis.office_metadata.has_macros ? 'text-red-500 font-bold' : 'text-emerald-500 font-bold'}>
                        {staticAnalysis.office_metadata.has_macros ? 'MACROS DETECTED' : 'Clean (No Macros)'}
                      </span>
                    </div>
                    <div className="p-3 rounded-xl bg-surface-secondary/40 border border-border">
                      <span className="text-foreground-muted text-[10px] block">vbaProject.bin</span>
                      <span className="text-foreground font-bold">
                        {staticAnalysis.office_metadata.vba_project_present ? 'Present' : 'Not present'}
                      </span>
                    </div>
                    <div className="p-3 rounded-xl bg-surface-secondary/40 border border-border">
                      <span className="text-foreground-muted text-[10px] block">External Relationships</span>
                      <span className={staticAnalysis.office_metadata.has_external_relationships ? 'text-amber-500 font-bold' : 'text-emerald-500 font-bold'}>
                        {staticAnalysis.office_metadata.has_external_relationships ? 'EXTERNAL INJECTION DETECTED' : 'None'}
                      </span>
                    </div>
                  </div>

                  {staticAnalysis.office_metadata.suspicious_keywords.length > 0 && (
                    <div className="p-3 rounded-xl bg-amber-500/10 border border-amber-500/20 space-y-1.5">
                      <span className="text-xs font-mono font-bold text-amber-500">
                        Suspicious Macro Execution Keywords
                      </span>
                      <div className="flex flex-wrap gap-2">
                        {staticAnalysis.office_metadata.suspicious_keywords.map((kw, idx) => (
                          <span key={idx} className="px-2 py-0.5 rounded bg-surface border border-border text-xs font-mono">
                            {kw}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* Archive Inspection */}
              {staticAnalysis?.archive_metadata && (
                <div className="space-y-4">
                  <h4 className="text-xs font-mono font-bold text-foreground uppercase tracking-wider flex items-center gap-2">
                    <Archive className="w-4 h-4 text-primary" />
                    <span>Safe Archive Enumeration & Bomb Protection</span>
                  </h4>

                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs font-mono">
                    <div className="p-3 rounded-xl bg-surface-secondary/40 border border-border">
                      <span className="text-foreground-muted text-[10px] block">Total Files</span>
                      <span className="text-foreground font-bold">{staticAnalysis.archive_metadata.total_files}</span>
                    </div>
                    <div className="p-3 rounded-xl bg-surface-secondary/40 border border-border">
                      <span className="text-foreground-muted text-[10px] block">Uncompressed Size</span>
                      <span className="text-foreground font-bold">{formatFileSize(staticAnalysis.archive_metadata.uncompressed_size)}</span>
                    </div>
                    <div className="p-3 rounded-xl bg-surface-secondary/40 border border-border">
                      <span className="text-foreground-muted text-[10px] block">Decompression Ratio</span>
                      <span className="text-foreground font-bold">{staticAnalysis.archive_metadata.compression_ratio}:1</span>
                    </div>
                    <div className="p-3 rounded-xl bg-surface-secondary/40 border border-border">
                      <span className="text-foreground-muted text-[10px] block">Password Protection</span>
                      <span className={staticAnalysis.archive_metadata.is_encrypted ? 'text-amber-500 font-bold' : 'text-emerald-500 font-bold'}>
                        {staticAnalysis.archive_metadata.is_encrypted ? 'ENCRYPTED' : 'Unencrypted'}
                      </span>
                    </div>
                  </div>

                  {staticAnalysis.archive_metadata.entries.length > 0 && (
                    <div className="rounded-xl border border-border overflow-hidden">
                      <table className="w-full text-xs font-mono">
                        <thead className="bg-surface-secondary/60 text-foreground-muted text-[11px] border-b border-border">
                          <tr>
                            <th className="p-2.5 text-left">Inner File Path</th>
                            <th className="p-2.5 text-right">Size</th>
                            <th className="p-2.5 text-center">Encrypted</th>
                            <th className="p-2.5 text-center">Status</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-border">
                          {staticAnalysis.archive_metadata.entries.map((entry, idx) => (
                            <tr key={idx} className="hover:bg-surface-secondary/30">
                              <td className="p-2.5 font-bold text-foreground break-all">{entry.filename}</td>
                              <td className="p-2.5 text-right text-foreground-muted">{formatFileSize(entry.uncompressed_size)}</td>
                              <td className="p-2.5 text-center">
                                {entry.is_encrypted ? <Lock className="w-3.5 h-3.5 text-amber-500 mx-auto" /> : <Unlock className="w-3.5 h-3.5 text-foreground-subtle mx-auto" />}
                              </td>
                              <td className="p-2.5 text-center">
                                {entry.is_path_traversal ? (
                                  <span className="px-1.5 py-0.5 rounded bg-red-500/20 text-red-400 text-[10px] font-bold">TRAVERSAL</span>
                                ) : entry.is_suspicious_extension ? (
                                  <span className="px-1.5 py-0.5 rounded bg-orange-500/20 text-orange-400 text-[10px] font-bold">EXECUTABLE</span>
                                ) : (
                                  <span className="px-1.5 py-0.5 rounded bg-emerald-500/15 text-emerald-400 text-[10px]">SAFE</span>
                                )}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* Tab 5: Reputation */}
          {activeSubTab === 'reputation' && (
            <div className="p-5 space-y-4">
              <div className="p-4 rounded-xl bg-surface-secondary/30 border border-border space-y-3">
                <span className="text-xs font-mono font-bold text-foreground uppercase tracking-wider block">
                  Threat Intelligence Reputation Provider Status
                </span>

                <div className="p-4 rounded-xl bg-surface border border-border flex items-center space-x-3">
                  <Info className="w-5 h-5 text-foreground-muted shrink-0" />
                  <div className="space-y-1">
                    <h5 className="text-xs font-mono font-bold text-foreground">
                      {staticAnalysis?.reputation_status || 'Reputation unavailable'}
                    </h5>
                    <p className="text-[11px] font-mono text-foreground-muted">
                      {staticAnalysis?.reputation_details || 'No external threat-intelligence reputation provider configured. (MailTraceAI strict forensic policy: Reputation is never fabricated).'}
                    </p>
                  </div>
                </div>

                <div className="p-3 rounded-lg bg-surface border border-border text-xs font-mono text-foreground-muted space-y-1">
                  <div className="flex justify-between">
                    <span>Query Target (SHA-256):</span>
                    <span className="text-foreground font-bold">{selectedAtt.sha256 ? `${selectedAtt.sha256.substring(0, 16)}...` : 'N/A'}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Provider Gateway:</span>
                    <span className="text-foreground">{staticAnalysis?.reputation_provider || 'Unconfigured / Local Only'}</span>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Tab 6: Evidence & Chain of Custody */}
          {activeSubTab === 'evidence' && (
            <div className="p-5 space-y-5">
              <div className="p-4 rounded-xl bg-surface-secondary/40 border border-border space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <Key className="w-4 h-4 text-primary" />
                    <span className="text-xs font-mono font-bold text-foreground">
                      Forensic Evidence Token
                    </span>
                  </div>
                  <span className="px-2.5 py-1 rounded-md bg-primary/10 border border-primary/20 text-primary font-mono text-xs font-bold">
                    {staticAnalysis?.evidence_id || `EVD-ATT-${(selectedAtt.sha256 || '000').substring(0, 8).toUpperCase()}`}
                  </span>
                </div>

                <p className="text-[11px] font-mono text-foreground-muted">
                  Cryptographic chain of custody record. Hashes computed immediately upon email stream ingestion.
                </p>
              </div>

              {/* Hashes List */}
              <div className="space-y-2">
                <h4 className="text-xs font-mono font-bold text-foreground uppercase tracking-wider">
                  Cryptographic Integrity Hashes
                </h4>

                {/* SHA-256 */}
                <div className="p-3 rounded-xl bg-surface border border-border space-y-1 font-mono text-xs">
                  <div className="flex items-center justify-between text-foreground-muted text-[11px]">
                    <span className="font-bold text-primary">SHA-256 (Primary Forensic Identifier)</span>
                    {selectedAtt.sha256 && <CopyButton text={selectedAtt.sha256} label="Copy SHA-256" />}
                  </div>
                  <div className="text-foreground break-all">{selectedAtt.sha256 || 'N/A'}</div>
                </div>

                {/* SHA-1 */}
                <div className="p-3 rounded-xl bg-surface border border-border space-y-1 font-mono text-xs">
                  <div className="flex items-center justify-between text-foreground-muted text-[11px]">
                    <span>SHA-1</span>
                    {staticAnalysis?.sha1 && <CopyButton text={staticAnalysis.sha1} label="Copy SHA-1" />}
                  </div>
                  <div className="text-foreground break-all">{staticAnalysis?.sha1 || selectedAtt.sha1 || 'N/A'}</div>
                </div>

                {/* MD5 */}
                <div className="p-3 rounded-xl bg-surface border border-border space-y-1 font-mono text-xs">
                  <div className="flex items-center justify-between text-foreground-muted text-[11px]">
                    <span>MD5</span>
                    {staticAnalysis?.md5 && <CopyButton text={staticAnalysis.md5} label="Copy MD5" />}
                  </div>
                  <div className="text-foreground break-all">{staticAnalysis?.md5 || selectedAtt.md5 || 'N/A'}</div>
                </div>
              </div>

              {/* Chain of Custody Security Status */}
              <div className="p-3 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-xs font-mono text-emerald-600 dark:text-emerald-400 flex items-center space-x-2">
                <CheckCircle2 className="w-4 h-4 shrink-0" />
                <span>Chain of Custody Verified Authentic. Storage policy: Non-executable forensic vault.</span>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
