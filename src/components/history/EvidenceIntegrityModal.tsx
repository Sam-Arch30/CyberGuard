import React, { useState } from 'react';
import {
  ShieldCheck,
  Hash,
  FileText,
  Clock,
  User,
  Copy,
  Check,
  Lock,
  Download,
  ExternalLink
} from 'lucide-react';
import { Modal, ModalHeader, ModalTitle, ModalDescription, ModalBody } from '../ui/Modal';
import { Button } from '../ui/Button';
import { Badge } from '../ui/Badge';

export interface EvidenceRecordData {
  evidenceId: string;
  sha256: string;
  originalFilename: string;
  sizeBytes?: number;
  uploader?: string;
  timestamp: string;
  subject?: string;
  sender?: string;
  threatScore?: number;
}

interface EvidenceIntegrityModalProps {
  isOpen: boolean;
  onClose: () => void;
  evidence: EvidenceRecordData | null;
  onReopenWorkspace?: (evidenceId: string) => void;
}

export const EvidenceIntegrityModal: React.FC<EvidenceIntegrityModalProps> = ({
  isOpen,
  onClose,
  evidence,
  onReopenWorkspace
}) => {
  const [copiedSha, setCopiedSha] = useState(false);
  const [copiedId, setCopiedId] = useState(false);

  if (!evidence) return null;

  const copyToClipboard = (text: string, type: 'sha' | 'id') => {
    navigator.clipboard.writeText(text);
    if (type === 'sha') {
      setCopiedSha(true);
      setTimeout(() => setCopiedSha(false), 2000);
    } else {
      setCopiedId(true);
      setTimeout(() => setCopiedId(false), 2000);
    }
  };

  const formatBytes = (bytes?: number): string => {
    if (!bytes || bytes <= 0) return 'Unknown size';
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  };

  return (
    <Modal isOpen={isOpen} onClose={onClose} size="lg">
      <ModalHeader>
        <div className="flex items-center space-x-2.5">
          <div className="p-2 rounded-xl bg-primary/10 text-primary border border-primary/20">
            <Lock className="w-5 h-5" />
          </div>
          <div>
            <ModalTitle>Evidence Integrity & Chain of Custody</ModalTitle>
            <ModalDescription>
              Cryptographic verification record and forensic provenance metadata
            </ModalDescription>
          </div>
        </div>
      </ModalHeader>

      <ModalBody className="space-y-5">
        {/* Verification Status Banner */}
        <div className="p-4 rounded-xl bg-success-surface/40 border border-success-border flex items-start space-x-3 text-xs font-mono">
          <ShieldCheck className="w-5 h-5 text-success shrink-0 mt-0.5" />
          <div className="space-y-1">
            <div className="flex items-center space-x-2">
              <span className="font-bold text-success uppercase tracking-wider">
                Cryptographic Digest Verified
              </span>
              <Badge variant="success" size="sm">Immutable Record</Badge>
            </div>
            <p className="text-foreground-muted text-[11px] leading-relaxed">
              This evidence artifact is cryptographically hashed at ingestion using SHA-256. 
              The canonical hash identifies this exact raw email bitstream in the persistent forensic store.
            </p>
          </div>
        </div>

        {/* Evidence Identifiers */}
        <div className="space-y-3 bg-surface-secondary/40 p-4 rounded-xl border border-border">
          {/* SHA-256 */}
          <div>
            <div className="flex items-center justify-between mb-1">
              <span className="text-[10px] font-mono uppercase tracking-wider text-foreground-muted flex items-center space-x-1">
                <Hash className="w-3 h-3 text-primary" />
                <span>SHA-256 Digest (Evidence Identity)</span>
              </span>
              <button
                type="button"
                onClick={() => copyToClipboard(evidence.sha256, 'sha')}
                className="text-[11px] font-mono text-primary hover:text-primary-hover flex items-center space-x-1 cursor-pointer"
              >
                {copiedSha ? (
                  <>
                    <Check className="w-3 h-3 text-success" />
                    <span className="text-success">Copied</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3 h-3" />
                    <span>Copy Hash</span>
                  </>
                )}
              </button>
            </div>
            <div className="p-2.5 rounded-lg bg-surface border border-border font-mono text-xs text-foreground break-all select-all font-semibold">
              {evidence.sha256}
            </div>
          </div>

          {/* Evidence ID */}
          <div className="pt-2 border-t border-border/60">
            <div className="flex items-center justify-between mb-1">
              <span className="text-[10px] font-mono uppercase tracking-wider text-foreground-muted">
                Evidence ID / Tracking Identifier
              </span>
              <button
                type="button"
                onClick={() => copyToClipboard(evidence.evidenceId, 'id')}
                className="text-[11px] font-mono text-primary hover:text-primary-hover flex items-center space-x-1 cursor-pointer"
              >
                {copiedId ? (
                  <>
                    <Check className="w-3 h-3 text-success" />
                    <span className="text-success">Copied</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3 h-3" />
                    <span>Copy ID</span>
                  </>
                )}
              </button>
            </div>
            <div className="p-2 rounded-lg bg-surface border border-border font-mono text-xs text-primary font-bold">
              {evidence.evidenceId}
            </div>
          </div>
        </div>

        {/* Provenance Metadata Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs font-mono">
          <div className="p-3 rounded-xl bg-surface border border-border space-y-1">
            <span className="text-[10px] uppercase tracking-wider text-foreground-muted flex items-center space-x-1.5">
              <FileText className="w-3 h-3 text-primary" />
              <span>Original Filename</span>
            </span>
            <p className="font-semibold text-foreground truncate" title={evidence.originalFilename}>
              {evidence.originalFilename || 'unnamed.eml'}
            </p>
          </div>

          <div className="p-3 rounded-xl bg-surface border border-border space-y-1">
            <span className="text-[10px] uppercase tracking-wider text-foreground-muted flex items-center space-x-1.5">
              <Download className="w-3 h-3 text-primary" />
              <span>Raw Ingested Size</span>
            </span>
            <p className="font-semibold text-foreground">
              {formatBytes(evidence.sizeBytes)}
            </p>
          </div>

          <div className="p-3 rounded-xl bg-surface border border-border space-y-1">
            <span className="text-[10px] uppercase tracking-wider text-foreground-muted flex items-center space-x-1.5">
              <Clock className="w-3 h-3 text-primary" />
              <span>Ingestion Timestamp</span>
            </span>
            <p className="font-semibold text-foreground text-[11px]">
              {new Date(evidence.timestamp).toUTCString()}
            </p>
          </div>

          <div className="p-3 rounded-xl bg-surface border border-border space-y-1">
            <span className="text-[10px] uppercase tracking-wider text-foreground-muted flex items-center space-x-1.5">
              <User className="w-3 h-3 text-primary" />
              <span>Uploader / SOC Custodian</span>
            </span>
            <p className="font-semibold text-foreground">
              {evidence.uploader || 'SOC Ingestion Pipeline'}
            </p>
          </div>
        </div>

        {/* Associated Email Context */}
        {evidence.subject && (
          <div className="p-3.5 rounded-xl bg-surface-secondary/60 border border-border space-y-1.5 text-xs font-mono">
            <div className="text-[10px] uppercase tracking-wider text-foreground-muted font-bold">
              Parsed Email Subject
            </div>
            <div className="font-semibold text-foreground text-sm">
              {evidence.subject}
            </div>
            {evidence.sender && (
              <div className="text-[11px] text-foreground-muted">
                From: <span className="text-foreground">{evidence.sender}</span>
              </div>
            )}
          </div>
        )}

        {/* Modal Actions */}
        <div className="pt-2 flex flex-col sm:flex-row items-center justify-between gap-3 border-t border-border">
          <span className="text-[10px] font-mono text-foreground-muted">
            Stored in local forensic database · Append-only audit logging
          </span>
          <div className="flex items-center space-x-2 w-full sm:w-auto">
            <Button
              variant="outline"
              size="sm"
              onClick={onClose}
              className="w-full sm:w-auto"
            >
              Close
            </Button>
            {onReopenWorkspace && (
              <Button
                variant="primary"
                size="sm"
                onClick={() => {
                  onClose();
                  onReopenWorkspace(evidence.evidenceId);
                }}
                className="w-full sm:w-auto flex items-center space-x-1.5"
              >
                <ExternalLink className="w-3.5 h-3.5" />
                <span>Open in Workspace</span>
              </Button>
            )}
          </div>
        </div>
      </ModalBody>
    </Modal>
  );
};
