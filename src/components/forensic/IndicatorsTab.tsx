import React, { useState } from 'react';
import type {
  EmailAnalysis,
  EmailAddressIndicator,
  AttachmentIndicator
} from '../../types/forensic';
import { CopyButton } from './CopyButton';
import { IPIntelligenceSection } from './IPIntelligenceSection';
import { DomainIntelligenceSection } from './DomainIntelligenceSection';
import { URLAnalysisSection } from './URLAnalysisSection';
import { Mail, Hash, Paperclip, Shield } from 'lucide-react';
import { StatusRow, ExpandableSection, DetailDrawer, MetadataRow } from '../common/progressive';

interface IndicatorsTabProps {
  email: EmailAnalysis;
}

export const IndicatorsTab: React.FC<IndicatorsTabProps> = ({ email }) => {
  const [selectedRawEvidence, setSelectedRawEvidence] = useState<{
    title: string;
    subtitle?: string;
    data: any;
  } | null>(null);

  const indicators = email.indicators || {};

  // Resolve Email indicators
  const emailList: EmailAddressIndicator[] = indicators.email_addresses && indicators.email_addresses.length > 0
    ? indicators.email_addresses
    : (email.emails || []).map(e => ({ value: e, source: 'header' }));

  // Resolve Attachment indicators
  const attachmentList: AttachmentIndicator[] = indicators.attachments && indicators.attachments.length > 0
    ? indicators.attachments
    : (email.attachments || []).map(att => ({
        filename: att.filename,
        mime_type: att.mime_type,
        size: att.size,
        sha256: att.sha256 || 'N/A',
        static_analysis: att.static_analysis
      }));

  const evidenceSha256 = email.email_sha256 || 'Not available';

  const formatFileSize = (bytes?: number): string => {
    if (!bytes || bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  return (
    <div className="space-y-6">
      {/* Evidence Hash Card */}
      <div className="bg-surface p-5 rounded-2xl border border-border space-y-3 shadow-xs">
        <div className="flex items-center justify-between pb-2 border-b border-border">
          <div className="flex items-center space-x-2">
            <Hash className="w-4 h-4 text-primary" />
            <h3 className="text-sm font-mono font-bold text-foreground uppercase tracking-wider">
              Evidence Cryptographic Root Digest
            </h3>
          </div>
          {email.email_sha256 && (
            <CopyButton text={email.email_sha256} label="Copy Hash" />
          )}
        </div>

        <div className="p-3.5 rounded-xl border border-border bg-surface-secondary/60 flex items-center justify-between gap-3">
          <div className="flex items-center space-x-2 min-w-0">
            <Shield className="w-4 h-4 text-primary shrink-0" />
            <span className="text-xs font-mono text-foreground break-all select-all font-semibold">
              {evidenceSha256}
            </span>
          </div>
        </div>
      </div>

      {/* IP Addresses Intelligence & Infrastructure */}
      <IPIntelligenceSection email={email} />

      {/* Domain Infrastructure & Registration Intelligence */}
      <DomainIntelligenceSection email={email} />

      {/* Static URL Forensic Analysis */}
      <URLAnalysisSection email={email} />

      {/* Extracted Email Addresses */}
      <ExpandableSection
        title={`Extracted Email Identities (${emailList.length})`}
        subtitle="Participant and routing email addresses discovered in message headers and content"
        icon={Mail}
        defaultExpanded={false}
      >
        {emailList.length === 0 ? (
          <p className="text-xs font-mono text-foreground-subtle italic p-2">
            No email addresses detected.
          </p>
        ) : (
          <div className="space-y-2.5">
            {emailList.map((emailObj, idx) => (
              <StatusRow
                key={idx}
                title={emailObj.value}
                status="INFO"
                statusLabel={emailObj.source?.toUpperCase() || 'EXTRACTED'}
                subtitle={`Extracted from message ${emailObj.source || 'headers'}`}
                defaultExpanded={false}
                onViewRaw={() =>
                  setSelectedRawEvidence({
                    title: `Email Identity Evidence — ${emailObj.value}`,
                    subtitle: `Observed context in ${emailObj.source || 'headers'}`,
                    data: emailObj
                  })
                }
              >
                <div className="space-y-2">
                  <MetadataRow label="Email Address" value={emailObj.value} allowCopy={true} />
                  <MetadataRow label="Extraction Source" value={emailObj.source || 'Header metadata'} />
                  <MetadataRow
                    label="Domain"
                    value={emailObj.value.split('@')[1] || 'Unknown domain'}
                  />
                </div>
              </StatusRow>
            ))}
          </div>
        )}
      </ExpandableSection>

      {/* Attachment Hashes & Static Inspection */}
      <ExpandableSection
        title={`File Attachments & Cryptographic Hashes (${attachmentList.length})`}
        subtitle="Static file heuristics, mime-type verification, and cryptographic digest verification"
        icon={Paperclip}
        defaultExpanded={false}
      >
        {attachmentList.length === 0 ? (
          <p className="text-xs font-mono text-foreground-subtle italic p-2">
            No attachments detected.
          </p>
        ) : (
          <div className="space-y-2.5">
            {attachmentList.map((att, idx) => {
              const threatLevel = att.static_analysis?.threat_level || 'LOW';
              const statusState = threatLevel === 'CRITICAL' ? 'FAIL' : threatLevel === 'HIGH' ? 'WARN' : 'PASS';

              return (
                <StatusRow
                  key={idx}
                  title={att.filename || 'Unnamed Attachment'}
                  status={statusState}
                  statusLabel={threatLevel}
                  subtitle={`${formatFileSize(att.size)} · ${att.mime_type || 'Unknown MIME'}`}
                  defaultExpanded={false}
                  onViewRaw={() =>
                    setSelectedRawEvidence({
                      title: `Attachment Dossier — ${att.filename || 'Attachment'}`,
                      subtitle: `Static inspection and cryptographic digests`,
                      data: att
                    })
                  }
                >
                  <div className="space-y-2">
                    <MetadataRow label="Filename" value={att.filename || 'N/A'} />
                    <MetadataRow label="File Size" value={formatFileSize(att.size)} />
                    <MetadataRow label="MIME Type" value={att.mime_type || 'unspecified'} />
                    <MetadataRow label="SHA-256 Digest" value={att.sha256 || 'N/A'} allowCopy={true} />
                    {att.md5 && <MetadataRow label="MD5 Digest" value={att.md5} allowCopy={true} />}
                    {att.sha1 && <MetadataRow label="SHA-1 Digest" value={att.sha1} allowCopy={true} />}
                    {att.static_analysis?.threat_level && (
                      <MetadataRow
                        label="Static Heuristics"
                        value={`${att.static_analysis.threat_level} threat level — ${att.static_analysis.extension_mismatch ? 'Extension mismatch detected!' : 'No extension mismatch'}`}
                        isMonospace={false}
                      />
                    )}
                  </div>
                </StatusRow>
              );
            })}
          </div>
        )}
      </ExpandableSection>

      {/* Level 3 Raw Drawer */}
      {selectedRawEvidence && (
        <DetailDrawer
          isOpen={Boolean(selectedRawEvidence)}
          onClose={() => setSelectedRawEvidence(null)}
          title={selectedRawEvidence.title}
          subtitle={selectedRawEvidence.subtitle}
          data={selectedRawEvidence.data}
          format="json"
        />
      )}
    </div>
  );
};
