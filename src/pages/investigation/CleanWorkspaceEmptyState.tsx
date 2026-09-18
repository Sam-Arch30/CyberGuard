import React, { useState, useRef } from 'react';
import {
  Upload,
  Shield,
  Sparkles,
  AlertCircle,
  RefreshCw,
  FileCode,
  Terminal
} from 'lucide-react';
import { useInvestigation } from '../../context/InvestigationContext';

export const CleanWorkspaceEmptyState: React.FC = () => {
  const { ingestEmail } = useInvestigation();
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [dragOver, setDragOver] = useState(false);
  const [isUploading, setIsUploading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [showPasteBox, setShowPasteBox] = useState(false);
  const [rawPastedContent, setRawPastedContent] = useState('');

  const handleFileProcess = async (file: File) => {
    setIsUploading(true);
    setErrorMessage(null);
    try {
      let rawText = '';
      try {
        rawText = await file.text();
      } catch {
        // Fallback for binary blobs
      }
      await ingestEmail(file, file.name, rawText);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to ingest email file';
      setErrorMessage(msg);
      setIsUploading(false);
    }
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragOver(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragOver(false);
  };

  const handleDrop = async (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragOver(false);

    const files = Array.from(e.dataTransfer.files);
    if (files.length === 0) return;
    await handleFileProcess(files[0]);
  };

  const handleFileInputChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    await handleFileProcess(file);
  };

  const handlePasteSubmit = async () => {
    if (!rawPastedContent.trim()) return;
    setIsUploading(true);
    setErrorMessage(null);
    try {
      const blob = new Blob([rawPastedContent], { type: 'message/rfc822' });
      const filename = `manual_ingest_${Date.now()}.eml`;
      await ingestEmail(blob, filename, rawPastedContent);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to parse raw email headers';
      setErrorMessage(msg);
      setIsUploading(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto py-8 px-4 space-y-8 animate-fadeIn">
      {/* 1. Header Banner */}
      <div className="text-center space-y-3">
        <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full bg-primary/10 border border-primary/25 text-primary text-xs font-mono font-medium">
          <Shield className="w-3.5 h-3.5" />
          <span>STANDBY FOR ARTIFACT INGESTION</span>
        </div>

        <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-foreground font-sans">
          Clean Forensic Investigation Workspace
        </h1>
        <p className="text-sm text-foreground-muted max-w-xl mx-auto leading-relaxed">
          No email artifact is currently loaded. Ingest an RFC-822 formatted <code className="text-foreground font-mono bg-surface-secondary px-1.5 py-0.5 rounded border border-border text-xs">.eml</code> file to launch forensic header analysis, hop-by-hop relay reconstruction, and threat scoring.
        </p>
      </div>

      {/* 2. Drag & Drop Upload Zone */}
      <div
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        onClick={() => !isUploading && fileInputRef.current?.click()}
        className={`relative border-2 border-dashed rounded-2xl p-10 text-center transition-all cursor-pointer select-none ${
          dragOver
            ? 'border-primary bg-primary/5 shadow-lg ring-2 ring-primary/20 scale-[1.01]'
            : 'border-border hover:border-primary/50 bg-surface hover:bg-surface-secondary/40 shadow-xs'
        } ${isUploading ? 'opacity-70 pointer-events-none' : ''}`}
      >
        <input
          type="file"
          ref={fileInputRef}
          onChange={handleFileInputChange}
          accept=".eml,.msg,message/rfc822,text/plain"
          className="hidden"
        />

        <div className="flex flex-col items-center justify-center space-y-4">
          <div
            className={`w-14 h-14 rounded-2xl flex items-center justify-center transition-all ${
              dragOver
                ? 'bg-primary text-primary-foreground shadow-md scale-110'
                : 'bg-surface-secondary text-primary border border-border/80 shadow-xs'
            }`}
          >
            {isUploading ? (
              <RefreshCw className="w-6 h-6 animate-spin" />
            ) : (
              <Upload className="w-6 h-6" />
            )}
          </div>

          <div className="space-y-1.5">
            <h3 className="text-base font-semibold text-foreground">
              {isUploading
                ? 'Analyzing MIME headers, IOCs, and relay trajectory...'
                : dragOver
                ? 'Drop .EML file to begin forensic triage'
                : 'Drag and drop an .eml email file here'}
            </h3>
            <p className="text-xs text-foreground-muted font-mono">
              {isUploading
                ? 'Validating cryptographic SPF / DKIM / DMARC signatures'
                : 'Supports standard RFC-822, .eml, or raw MIME messages'}
            </p>
          </div>

          {!isUploading && (
            <div className="flex flex-wrap items-center justify-center gap-3 pt-2">
              <button
                type="button"
                className="px-5 py-2 rounded-xl bg-primary hover:bg-primary-hover text-primary-foreground text-xs font-semibold font-mono tracking-wide shadow-xs transition-colors cursor-pointer"
              >
                Browse Local .EML File
              </button>
              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation();
                  setShowPasteBox(prev => !prev);
                }}
                className="px-4 py-2 rounded-xl bg-surface-secondary hover:bg-surface-secondary/80 border border-border text-foreground text-xs font-mono transition-colors cursor-pointer"
              >
                {showPasteBox ? 'Hide Raw Input' : 'Paste RFC-822 Headers'}
              </button>
            </div>
          )}
        </div>
      </div>

      {/* 3. Error Feedback */}
      {errorMessage && (
        <div className="p-4 rounded-xl bg-danger-surface border border-danger-border text-danger text-xs font-mono flex items-center justify-between">
          <div className="flex items-center space-x-2.5">
            <AlertCircle className="w-4 h-4 shrink-0" />
            <span>{errorMessage}</span>
          </div>
          <button
            onClick={() => setErrorMessage(null)}
            className="text-danger hover:underline cursor-pointer ml-3 font-semibold"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* 4. Collapsible Raw Email / Headers Paste Area */}
      {showPasteBox && (
        <div className="p-5 rounded-2xl bg-surface border border-border space-y-3.5 animate-fadeIn shadow-xs">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2 text-xs font-mono font-semibold text-foreground">
              <FileCode className="w-4 h-4 text-primary" />
              <span>Direct MIME Header / Envelope Ingestion</span>
            </div>
            <span className="text-[11px] font-mono text-foreground-muted">RFC-822 Syntax</span>
          </div>

          <textarea
            value={rawPastedContent}
            onChange={(e) => setRawPastedContent(e.target.value)}
            placeholder="Received: from mail.attacker-domain.com ...&#10;From: attacker@domain.com&#10;To: target@victim.org&#10;Subject: Urgent Security Verification&#10;&#10;Please verify your credentials..."
            rows={7}
            className="w-full text-xs font-mono p-3.5 rounded-xl bg-surface-secondary border border-border text-foreground placeholder:text-foreground-muted focus:outline-hidden focus:ring-1 focus:ring-primary resize-y"
          />

          <div className="flex items-center justify-between pt-1">
            <span className="text-[11px] font-mono text-foreground-muted">
              {rawPastedContent.length > 0 ? `${rawPastedContent.length} bytes loaded` : 'Awaiting pasted content'}
            </span>
            <button
              onClick={handlePasteSubmit}
              disabled={isUploading || !rawPastedContent.trim()}
              className="px-5 py-2 rounded-xl bg-primary hover:bg-primary-hover disabled:opacity-50 text-primary-foreground text-xs font-semibold font-mono flex items-center space-x-2 cursor-pointer transition-colors shadow-xs"
            >
              <Terminal className="w-3.5 h-3.5" />
              <span>Parse & Investigate Envelope</span>
            </button>
          </div>
        </div>
      )}

      {/* 5. What Happens Upon Ingestion (Operational Pipeline Card) */}
      <div className="p-6 rounded-2xl bg-surface-secondary/40 border border-border/60 space-y-4">
        <h4 className="text-xs font-mono font-semibold uppercase tracking-wider text-foreground-muted flex items-center space-x-2">
          <Sparkles className="w-3.5 h-3.5 text-primary" />
          <span>Automated 6-Stage Forensic Pipeline</span>
        </h4>

        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3 text-xs">
          <div className="p-3 rounded-xl bg-surface border border-border/60 space-y-1">
            <div className="font-semibold text-foreground flex items-center space-x-1.5">
              <span className="w-5 h-5 rounded-md bg-primary/10 text-primary text-[10px] font-mono font-bold flex items-center justify-center">01</span>
              <span>Overview</span>
            </div>
            <p className="text-[11px] text-foreground-muted leading-relaxed">
              Calculates threat score, risk severity, and AI forensic executive briefing.
            </p>
          </div>

          <div className="p-3 rounded-xl bg-surface border border-border/60 space-y-1">
            <div className="font-semibold text-foreground flex items-center space-x-1.5">
              <span className="w-5 h-5 rounded-md bg-primary/10 text-primary text-[10px] font-mono font-bold flex items-center justify-center">02</span>
              <span>Email & Headers</span>
            </div>
            <p className="text-[11px] text-foreground-muted leading-relaxed">
              Validates SPF, DKIM, and DMARC alignment and reconstructs transmission relay hops.
            </p>
          </div>

          <div className="p-3 rounded-xl bg-surface border border-border/60 space-y-1">
            <div className="font-semibold text-foreground flex items-center space-x-1.5">
              <span className="w-5 h-5 rounded-md bg-primary/10 text-primary text-[10px] font-mono font-bold flex items-center justify-center">03</span>
              <span>Threat Analysis</span>
            </div>
            <p className="text-[11px] text-foreground-muted leading-relaxed">
              Extracts URLs, detects domain lookalike homoglyphs, and scans attachments.
            </p>
          </div>

          <div className="p-3 rounded-xl bg-surface border border-border/60 space-y-1">
            <div className="font-semibold text-foreground flex items-center space-x-1.5">
              <span className="w-5 h-5 rounded-md bg-primary/10 text-primary text-[10px] font-mono font-bold flex items-center justify-center">04</span>
              <span>Threat Intelligence</span>
            </div>
            <p className="text-[11px] text-foreground-muted leading-relaxed">
              Correlates originating IP telemetry, ASN ownership, and geo-transit hops.
            </p>
          </div>

          <div className="p-3 rounded-xl bg-surface border border-border/60 space-y-1">
            <div className="font-semibold text-foreground flex items-center space-x-1.5">
              <span className="w-5 h-5 rounded-md bg-primary/10 text-primary text-[10px] font-mono font-bold flex items-center justify-center">05</span>
              <span>Graph & Investigation</span>
            </div>
            <p className="text-[11px] text-foreground-muted leading-relaxed">
              Interactive threat graph, campaign clustering, and evidence-grounded AI copilot.
            </p>
          </div>

          <div className="p-3 rounded-xl bg-surface border border-border/60 space-y-1">
            <div className="font-semibold text-foreground flex items-center space-x-1.5">
              <span className="w-5 h-5 rounded-md bg-primary/10 text-primary text-[10px] font-mono font-bold flex items-center justify-center">06</span>
              <span>Incident Report</span>
            </div>
            <p className="text-[11px] text-foreground-muted leading-relaxed">
              Exports audit-proof dossiers with SHA-256 chain of custody and MITRE mappings.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
