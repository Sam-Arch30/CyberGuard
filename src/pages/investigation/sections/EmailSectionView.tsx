import React from 'react';
import {
  FileText,
  Code,
  ShieldCheck,
  GitCommit,
  Terminal,
  Paperclip,
  Info
} from 'lucide-react';
import type { EmailAnalysis } from '../../../types/forensic';
import { useInvestigation } from '../../../context/InvestigationContext';
import { ContentTab } from '../../../components/forensic/ContentTab';
import { MetadataRow } from '../../../components/forensic/MetadataRow';
import { HeadersTab } from '../../../components/forensic/HeadersTab';
import { AuthenticationSection } from '../../../components/forensic/AuthenticationSection';
import { TransmissionPathSection } from '../../../components/forensic/TransmissionPathSection';
import { RawEmailTab } from '../../../components/forensic/RawEmailTab';
import { AttachmentsTab } from '../../../components/forensic/AttachmentsTab';

interface EmailSectionViewProps {
  email: EmailAnalysis;
}

type EmailSubTab = 'body' | 'metadata' | 'headers' | 'auth' | 'relay' | 'raw' | 'attachments';

export const EmailSectionView: React.FC<EmailSectionViewProps> = ({ email }) => {
  const { subTabs, setSubTab, stepGuidance } = useInvestigation();
  const currentSubTab = (subTabs.email || 'body') as EmailSubTab;

  const subTabItems: { id: EmailSubTab; label: string; icon: React.FC<{ className?: string }>; count?: number }[] = [
    { id: 'body', label: 'Rendered Body & Content', icon: Code },
    { id: 'metadata', label: 'Sender & Metadata', icon: Info },
    { id: 'headers', label: 'RFC-822 Headers', icon: FileText, count: email.received?.length || 0 },
    { id: 'auth', label: 'SPF / DKIM / DMARC Auth', icon: ShieldCheck },
    { id: 'relay', label: 'Transmission Relay Path', icon: GitCommit, count: email.relay_analysis?.transmission_order_hops?.length || email.received?.length || 0 },
    { id: 'attachments', label: 'Attachments', icon: Paperclip, count: email.attachments?.length || email.indicators?.attachments?.length || 0 },
    { id: 'raw', label: 'Raw .EML Stream', icon: Terminal }
  ];

  return (
    <div className="space-y-6">
      {/* 1. CONTEXTUAL SUB-NAVIGATION BAR */}
      <div className="bg-surface rounded-xl border border-border p-1.5 flex flex-wrap items-center gap-1 shadow-xs">
        {subTabItems.map((tab) => {
          const isActive = currentSubTab === tab.id;
          const Icon = tab.icon;
          return (
            <button
              key={tab.id}
              type="button"
              onClick={() => setSubTab(tab.id)}
              className={`flex items-center space-x-2 px-3 py-1.5 rounded-lg text-xs font-mono transition-all cursor-pointer ${
                isActive
                  ? 'bg-primary text-primary-foreground font-semibold shadow-xs'
                  : 'text-foreground-muted hover:text-foreground hover:bg-surface-secondary border border-transparent'
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              <span>{tab.label}</span>
              {typeof tab.count === 'number' && tab.count > 0 && (
                <span
                  className={`ml-1 px-1.5 py-0.2 rounded text-[10px] font-mono ${
                    isActive ? 'bg-black/20 text-white' : 'bg-surface-secondary text-foreground-subtle border border-border'
                  }`}
                >
                  {tab.count}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* 2. SUB-TAB VIEW CONTAINER */}
      <div className="bg-surface rounded-xl border border-border p-5 shadow-xs">
        {currentSubTab === 'body' && (
          <div className="space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-border">
              <div className="flex items-center space-x-2 text-xs font-mono font-bold uppercase text-foreground">
                <Code className="w-4 h-4 text-primary" />
                <span>Rendered Email Content & Message Structure</span>
              </div>
              <span className="text-[11px] font-mono text-foreground-muted">
                Standard MIME multipart decomposition
              </span>
            </div>
            <ContentTab email={email} />
          </div>
        )}

        {currentSubTab === 'metadata' && (
          <div className="space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-border">
              <div className="flex items-center space-x-2 text-xs font-mono font-bold uppercase text-foreground">
                <Info className="w-4 h-4 text-primary" />
                <span>Message Identity & Sender Alignment</span>
              </div>
              <span className="text-[11px] font-mono text-foreground-muted">
                RFC 5322 From vs Return-Path verification
              </span>
            </div>
            <div className="space-y-2">
              <MetadataRow label="Subject" value={email.subject} allowCopy />
              <MetadataRow label="From" value={email.from} allowCopy />
              <MetadataRow label="To" value={email.to} allowCopy />
              {email.cc && <MetadataRow label="CC" value={email.cc} allowCopy />}
              <MetadataRow label="Date" value={email.date} allowCopy />
              <MetadataRow label="Message-ID" value={email.message_id} allowCopy />
              <MetadataRow label="Return-Path" value={email.return_path} allowCopy />
              {email.reply_to && <MetadataRow label="Reply-To" value={email.reply_to} allowCopy />}
              <MetadataRow label="Evidence SHA-256" value={email.email_sha256} allowCopy />
              <MetadataRow label="Original Filename" value={email.original_filename || email.file_info?.filename} allowCopy />
            </div>
          </div>
        )}

        {currentSubTab === 'headers' && (
          <div className="space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-border">
              <div className="flex items-center space-x-2 text-xs font-mono font-bold uppercase text-foreground">
                <FileText className="w-4 h-4 text-primary" />
                <span>Complete Header Analysis Table</span>
              </div>
              <span className="text-[11px] font-mono text-foreground-muted">
                Searchable key-value pair breakdown
              </span>
            </div>
            <HeadersTab email={email} />
          </div>
        )}

        {currentSubTab === 'auth' && (
          <div className="space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-border">
              <div className="flex items-center space-x-2 text-xs font-mono font-bold uppercase text-foreground">
                <ShieldCheck className="w-4 h-4 text-primary" />
                <span>Cryptographic Protocol Validation</span>
              </div>
              <span className="text-[11px] font-mono text-foreground-muted">
                SPF, DKIM & DMARC alignment status
              </span>
            </div>
            <AuthenticationSection authentication={email.authentication} />
          </div>
        )}

        {currentSubTab === 'relay' && (
          <div className="space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-border">
              <div className="flex items-center space-x-2 text-xs font-mono font-bold uppercase text-foreground">
                <GitCommit className="w-4 h-4 text-primary" />
                <span>Reconstructed Hop Transmission Path</span>
              </div>
              <span className="text-[11px] font-mono text-foreground-muted">
                Chronological relay latency and earliest observable IP
              </span>
            </div>
            <TransmissionPathSection relayAnalysis={email.relay_analysis} />
          </div>
        )}

        {currentSubTab === 'attachments' && (
          <div className="space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-border">
              <div className="flex items-center space-x-2 text-xs font-mono font-bold uppercase text-foreground">
                <Paperclip className="w-4 h-4 text-primary" />
                <span>Attachment Intelligence & Static Malware Analysis</span>
              </div>
              <span className="text-[11px] font-mono text-foreground-muted">
                MIME validation, SHA-256 hashes & entropy
              </span>
            </div>
            <AttachmentsTab email={email} />
          </div>
        )}

        {currentSubTab === 'raw' && (
          <div className="space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-border">
              <div className="flex items-center space-x-2 text-xs font-mono font-bold uppercase text-foreground">
                <Terminal className="w-4 h-4 text-primary" />
                <span>Raw RFC-822 Stream Inspection</span>
              </div>
              <span className="text-[11px] font-mono text-foreground-muted">
                Unmodified byte-for-byte ingestion evidence
              </span>
            </div>
            <RawEmailTab email={email} />
          </div>
        )}
      </div>

      {/* 3. NEXT INVESTIGATION STEP CTA */}
      <div className="p-4 rounded-xl bg-surface border border-border flex flex-col sm:flex-row items-center justify-between gap-4 shadow-xs">
        <div className="flex items-center space-x-3">
          <div className="w-8 h-8 rounded-lg bg-primary/10 text-primary flex items-center justify-center font-bold font-mono text-xs border border-primary/20">
            03
          </div>
          <div>
            <h4 className="text-xs font-bold text-foreground font-sans">
              Completed Email Inspection?
            </h4>
            <p className="text-xs font-mono text-foreground-muted">
              Pivot into extracted IOCs, suspicious URLs, lookalike domains, and NLP threat scoring.
            </p>
          </div>
        </div>

        <button
          type="button"
          onClick={stepGuidance.execute}
          className="w-full sm:w-auto px-4 py-2 rounded-lg bg-primary hover:bg-primary-hover text-primary-foreground font-mono text-xs font-bold flex items-center justify-center space-x-2 transition-all shadow-xs cursor-pointer"
        >
          <span>{stepGuidance.buttonLabel}</span>
        </button>
      </div>
    </div>
  );
};
