import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  SearchCode,
  Zap,
  Upload,
  AlertCircle,
  FileText,
  Shield,
  ArrowRight
} from 'lucide-react';
import type { EmailAnalysis } from '../types/forensic';
import { saveAnalysisResult } from '../utils/forensicStore';
import { decodeRfc2047 } from '../utils/indicatorHelper';

export const AnalyzeEmail: React.FC = () => {
  const navigate = useNavigate();
  const [rawInput, setRawInput] = useState<string>('');
  const [isAnalyzing, setIsAnalyzing] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [dragOver, setDragOver] = useState<boolean>(false);

  const processEmailContent = async (fileOrBlob: Blob, filename: string, rawText?: string) => {
    setIsAnalyzing(true);
    setErrorMessage(null);
    const analysisId = `analysis-${Date.now()}`;

    try {
      const formData = new FormData();
      formData.append('file', fileOrBlob, filename);

      let res: Response | null = null;
      try {
        res = await fetch('/api/emails/analyze', { method: 'POST', body: formData });
      } catch {
        res = await fetch('http://127.0.0.1:8000/api/emails/analyze', { method: 'POST', body: formData });
      }

      if (res && res.ok) {
        const data = await res.json();
        const textFallback = rawText || '';
        const parsedAnalysis: EmailAnalysis = {
          id: analysisId,
          evidence_id: data.evidence_id || (data.email_sha256 ? `EVD-${data.email_sha256.slice(0, 10).toUpperCase()}` : `EVD-${analysisId.slice(-8).toUpperCase()}`),
          email_sha256: data.email_sha256,
          original_filename: data.original_filename || filename,
          upload_timestamp: data.upload_timestamp || new Date().toISOString(),
          size: data.size || fileOrBlob.size,
          uploader: data.uploader || 'SOC Analyst',
          authentication: data.authentication,
          relay_analysis: data.relay_analysis,
          indicators: data.indicators,
          subject: decodeRfc2047(data.subject || data.headers?.subject || filename),
          from: decodeRfc2047(data.from || data.from_header || data.headers?.from || ''),
          to: decodeRfc2047(Array.isArray(data.to) ? data.to.join(', ') : (data.to || data.headers?.to || '')),
          cc: decodeRfc2047(Array.isArray(data.cc) ? data.cc.join(', ') : (data.cc || data.headers?.cc || '')),
          date: decodeRfc2047(data.date || data.headers?.date || ''),
          reply_to: decodeRfc2047(data.reply_to || data.headers?.reply_to || ''),
          return_path: decodeRfc2047(data.return_path || data.headers?.return_path || ''),
          message_id: decodeRfc2047(data.message_id || data.headers?.message_id || ''),
          received: data.received || data.headers?.received || [],
          authentication_results: data.authentication_results || data.headers?.authentication_results || '',
          plain_text_body: data.plain_text_body || data.body?.plain_text || textFallback,
          html_body: data.html_body || data.body?.html || '',
          raw_email: data.raw_email || textFallback,
          urls: data.urls || [],
          ips: data.ips || [],
          domains: data.domains || [],
          emails: data.emails || [],
          attachments: data.attachments || [],
          ip_intelligence: data.ip_intelligence || {},
          domain_intelligence: data.domain_intelligence || {},
          lookalike_domains: data.lookalike_domains || [],
          url_analysis: data.url_analysis || [],
          threat_score: data.threat_score,
          ml_phishing_probability: data.ml_phishing_probability,
          ml_assessment: data.ml_assessment,
          ai_analyst: data.ai_analyst,
          attribution: data.attribution,
          investigation_graph: data.investigation_graph
        };

        saveAnalysisResult(analysisId, parsedAnalysis);
        navigate(`/analysis/${analysisId}`);
        return;
      } else {
        const errText = res ? await res.text() : 'Server did not respond.';
        setErrorMessage(`Forensic analysis failed: ${errText || 'Unprocessable email format'}`);
      }
    } catch (err: any) {
      setErrorMessage(`Error connecting to analysis engine: ${err?.message || 'Network error'}`);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleRunAnalysis = async () => {
    const text = rawInput.trim();
    if (!text) {
      setErrorMessage('Please paste RFC-822 raw email content or upload an .eml file to analyze.');
      return;
    }
    const blob = new Blob([text], { type: 'message/rfc822' });
    await processEmailContent(blob, 'pasted_email.eml', text);
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    let textContent = '';
    try {
      textContent = await file.text();
      setRawInput(textContent);
    } catch {
      // Binary or raw blob
    }
    await processEmailContent(file, file.name, textContent);
  };

  const handleDrop = async (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer.files?.[0];
    if (!file) return;
    let textContent = '';
    try {
      textContent = await file.text();
      setRawInput(textContent);
    } catch {
      // Binary or raw blob
    }
    await processEmailContent(file, file.name, textContent);
  };

  return (
    <div className="space-y-6 pb-12">
      {/* Top Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-surface p-6 rounded-xl border border-border">
        <div>
          <div className="flex items-center space-x-2 text-primary font-mono text-xs mb-1 font-semibold uppercase tracking-wider">
            <SearchCode className="w-3.5 h-3.5 text-primary" />
            <span>AI EMAIL FORENSIC ANALYSIS ENGINE</span>
          </div>
          <h1 className="text-xl font-bold text-foreground font-sans tracking-tight">
            Deep Email Threat & Origin Analysis
          </h1>
          <p className="text-xs text-foreground-muted font-mono mt-1">
            Ingest raw RFC-822 email content, parse routing relay chains, analyze SPF/DKIM/DMARC headers, and extract IOCs.
          </p>
        </div>
      </div>

      {errorMessage && (
        <div className="p-4 rounded-xl bg-danger-surface border border-danger-border flex items-start space-x-3 text-xs font-mono text-danger animate-in fade-in">
          <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
          <div className="flex-1">
            <strong className="block font-bold">Analysis Error</strong>
            <span>{errorMessage}</span>
          </div>
        </div>
      )}

      {/* Upload Zone */}
      <div
        onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
        onDragLeave={() => setDragOver(false)}
        onDrop={handleDrop}
        className={`bg-surface border-2 border-dashed rounded-xl p-8 text-center transition-all ${
          dragOver ? 'border-primary bg-primary-subtle/30' : 'border-border hover:border-border-hover'
        }`}
      >
        <div className="max-w-md mx-auto space-y-4">
          <div className="p-3.5 bg-surface-secondary rounded-full w-14 h-14 mx-auto flex items-center justify-center border border-border">
            <Upload className="w-6 h-6 text-primary" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-foreground font-sans">
              Upload an RFC-822 .eml file
            </h3>
            <p className="text-xs text-foreground-muted font-mono mt-1">
              Drag and drop an .eml or .txt email file here, or browse from your system.
            </p>
          </div>
          <div>
            <label className="inline-flex items-center space-x-2 px-4 py-2 rounded-lg bg-primary hover:bg-primary-hover text-primary-foreground text-xs font-mono font-semibold transition-colors btn-press cursor-pointer">
              <Upload className="w-3.5 h-3.5" />
              <span>Browse File</span>
              <input type="file" accept=".eml,.txt,.msg" onChange={handleFileUpload} className="hidden" />
            </label>
          </div>
        </div>
      </div>

      {/* Direct Raw Content Ingestion Console */}
      <div className="bg-surface border border-border rounded-xl p-5 space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2 text-xs font-mono font-semibold text-foreground uppercase">
            <FileText className="w-3.5 h-3.5 text-primary" />
            <span>OR PASTE RAW RFC-822 EMAIL HEADERS AND BODY:</span>
          </div>
          {rawInput && (
            <button
              type="button"
              onClick={() => setRawInput('')}
              className="text-[11px] font-mono text-foreground-muted hover:text-danger cursor-pointer"
            >
              Clear
            </button>
          )}
        </div>

        <div className="relative">
          <textarea
            value={rawInput}
            onChange={(e) => setRawInput(e.target.value)}
            rows={8}
            placeholder="From: sender@example.com&#10;To: recipient@example.com&#10;Subject: Security Notification&#10;Date: Mon, 15 Sep 2026 12:00:00 +0000&#10;Received: from mail.example.com...&#10;&#10;Email body content here..."
            className="w-full p-3.5 bg-surface-secondary border border-border rounded-lg font-mono text-xs text-foreground placeholder:text-foreground-muted focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary leading-relaxed"
          />
        </div>

        <div className="flex justify-end">
          <button
            type="button"
            onClick={handleRunAnalysis}
            disabled={isAnalyzing || !rawInput.trim()}
            className="flex items-center space-x-2 px-5 py-2.5 rounded-lg bg-primary hover:bg-primary-hover text-primary-foreground font-mono font-semibold text-xs tracking-wider transition-colors btn-press disabled:opacity-50 cursor-pointer"
          >
            {isAnalyzing ? (
              <>
                <div className="w-3.5 h-3.5 border-2 border-primary-foreground border-t-transparent rounded-full animate-spin" />
                <span>EXECUTING FORENSIC PIPELINE...</span>
              </>
            ) : (
              <>
                <Zap className="w-3.5 h-3.5" />
                <span>RUN FORENSIC ANALYSIS</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </>
            )}
          </button>
        </div>
      </div>

      {/* Forensic Verification Notice */}
      <div className="p-4 rounded-xl bg-surface border border-border flex items-start space-x-3 text-xs font-mono text-foreground-muted">
        <Shield className="w-4 h-4 text-primary shrink-0 mt-0.5" />
        <p className="leading-relaxed">
          <strong className="text-foreground">Evidence Integrity Guarantee:</strong> Ingested emails are immutably hashed (SHA-256) upon upload. All authentication evaluations (SPF, DKIM, DMARC), network routing hops, and indicator extractions are derived exclusively from actual email content without synthetic fallbacks.
        </p>
      </div>
    </div>
  );
};
