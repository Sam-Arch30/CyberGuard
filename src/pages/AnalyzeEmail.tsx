<<<<<<< Updated upstream
import React, { useState, useEffect } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
=======
import React, { useState, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
>>>>>>> Stashed changes
import {
  Upload,
<<<<<<< Updated upstream
  Radio,
  Hash,
  ExternalLink,
  FolderPlus,
  CheckCircle2,
  Copy
=======
  FileText,
  Shield,
  ArrowRight,
  AlertCircle,
  FileCode,
  Lock,
  Layers,
  Inbox
>>>>>>> Stashed changes
} from 'lucide-react';
import { SAMPLE_EMAILS } from '../data/mockData';
import type { EmailAnalysisData } from '../types';
import type { EmailAnalysis } from '../types/forensic';
import { saveAnalysisResult } from '../utils/forensicStore';
import { decodeRfc2047 } from '../utils/indicatorHelper';
<<<<<<< Updated upstream
import { RiskBadge } from '../components/common/RiskBadge';
import { HeaderProtocolStatus } from '../components/common/HeaderProtocolStatus';
import { GeoTraceMap } from '../components/common/GeoTraceMap';
import { AttributionGraph } from '../components/common/AttributionGraph';
=======
import { api, ApiError } from '../services/api';
>>>>>>> Stashed changes

export const AnalyzeEmail: React.FC = () => {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
<<<<<<< Updated upstream

  const emailIdParam = searchParams.get('id');
  const initialEmail = SAMPLE_EMAILS.find(e => e.id === emailIdParam) || SAMPLE_EMAILS[0];

  const [selectedSampleId, setSelectedSampleId] = useState<string>(initialEmail.id);
  const [currentEmail, setCurrentEmail] = useState<EmailAnalysisData>(initialEmail);
  const [rawInput, setRawInput] = useState<string>(initialEmail.rawHeaders + '\n\n' + initialEmail.bodyText);
  const [isAnalyzing, setIsAnalyzing] = useState<boolean>(false);
  const [activeTab, setActiveTab] = useState<'OVERVIEW' | 'HEADERS' | 'RELAY_TRACE' | 'IOCS' | 'GRAPH'>('OVERVIEW');
  const [copySuccess, setCopySuccess] = useState<boolean>(false);

  useEffect(() => {
    const found = SAMPLE_EMAILS.find(e => e.id === selectedSampleId);
    if (found) {
      setCurrentEmail(found);
      setRawInput(found.rawHeaders + '\n\n' + found.bodyText);
    }
  }, [selectedSampleId]);

  const handleRunAnalysis = async () => {
    if (!rawInput.trim()) return;
    setIsAnalyzing(true);
    const analysisId = `analysis-${Date.now()}`;

    try {
      const blob = new Blob([rawInput], { type: 'message/rfc822' });
      const formData = new FormData();
      formData.append('file', blob, 'pasted_email.eml');
=======
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [activeMode, setActiveMode] = useState<'upload' | 'paste'>('upload');
  const [rawInput, setRawInput] = useState<string>('');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState<boolean>(false);
  const [analysisStep, setAnalysisStep] = useState<string>('');
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [dragOver, setDragOver] = useState<boolean>(false);

  const processEmailStream = async (fileOrBlob: Blob, filename: string, rawText?: string) => {
    setIsAnalyzing(true);
    setErrorMessage(null);
    setAnalysisStep('Ingesting RFC-822 stream & verifying evidence integrity...');

    const tempId = `analysis-${Date.now()}`;

    try {
      setAnalysisStep('Parsing email headers, MIME parts & relay hop path...');
      const data = await api.email.analyze(fileOrBlob, filename, 'SOC Analyst');
>>>>>>> Stashed changes

      setAnalysisStep('Normalizing IOCs, threat scores & relationship graph...');
      const textFallback = rawText || '';
      const parsedAnalysis: EmailAnalysis = {
        id: data.evidence_id || data.id || tempId,
        evidence_id: data.evidence_id || (data.email_sha256 ? `EVD-${data.email_sha256.slice(0, 10).toUpperCase()}` : `EVD-${tempId.slice(-8).toUpperCase()}`),
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

<<<<<<< Updated upstream
      if (res && res.ok) {
        const data = await res.json();
        const parsedAnalysis: EmailAnalysis = {
          id: analysisId,
          evidence_id: data.evidence_id || (data.email_sha256 ? `EVD-${data.email_sha256.slice(0, 10).toUpperCase()}` : `EVD-${analysisId.slice(-8).toUpperCase()}`),
          email_sha256: data.email_sha256,
          original_filename: data.original_filename || 'pasted_email.eml',
          upload_timestamp: data.upload_timestamp || new Date().toISOString(),
          size: data.size || rawInput.length,
          uploader: data.uploader || 'SOC Analyst',
          authentication: data.authentication,
          relay_analysis: data.relay_analysis,
          indicators: data.indicators,
          subject: decodeRfc2047(data.subject || data.headers?.subject || 'Pasted Email Analysis'),
          from: decodeRfc2047(data.from || data.from_header || data.headers?.from || ''),
          to: decodeRfc2047(Array.isArray(data.to) ? data.to.join(', ') : (data.to || data.headers?.to || '')),
          cc: decodeRfc2047(Array.isArray(data.cc) ? data.cc.join(', ') : (data.cc || data.headers?.cc || '')),
          date: decodeRfc2047(data.date || data.headers?.date || ''),
          reply_to: decodeRfc2047(data.reply_to || data.headers?.reply_to || ''),
          return_path: decodeRfc2047(data.return_path || data.headers?.return_path || ''),
          message_id: decodeRfc2047(data.message_id || data.headers?.message_id || ''),
          received: data.received || data.headers?.received || [],
          authentication_results: data.authentication_results || data.headers?.authentication_results || '',
          plain_text_body: data.plain_text_body || data.body?.plain_text || rawInput,
          html_body: data.html_body || data.body?.html || '',
          raw_email: data.raw_email || rawInput,
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
          investigation_graph: data.investigation_graph
        };

        saveAnalysisResult(analysisId, parsedAnalysis);
        navigate(`/analysis/${analysisId}`);
        return;
      }
    } catch (err) {
      console.warn('Backend parse failed, fallback to local analysis:', err);
=======
      const finalId = parsedAnalysis.id || tempId;
      saveAnalysisResult(finalId, parsedAnalysis);
      setAnalysisStep('Analysis complete. Directing to forensic workbench...');
      navigate(`/analysis/${finalId}`);
    } catch (err: any) {
      if (err instanceof ApiError) {
        setErrorMessage(`Forensic pipeline rejected file: ${err.message}`);
      } else {
        setErrorMessage(`Error connecting to analysis engine: ${err?.message || 'Network error'}`);
      }
>>>>>>> Stashed changes
    } finally {
      setIsAnalyzing(false);
      setAnalysisStep('');
    }

    // Fallback: parse headers locally and save
    const getHeaderVal = (name: string): string => {
      const match = rawInput.match(new RegExp(`^${name}:[ \\t]*([^\\r\\n]+(?:\\r?\\n[ \\t]+[^\\r\\n]+)*)`, 'im'));
      return match ? decodeRfc2047(match[1].replace(/\s+/g, ' ').trim()) : '';
    };

    const extractReceivedHeaders = (text: string): string[] => {
      const matches = Array.from(text.matchAll(/^Received:[ \t]*(.+?)(?=\r?\n\S|\r?\n\r?\n|$)/gms));
      return matches.map(m => m[1].replace(/\s+/g, ' ').trim()).filter(Boolean);
    };

    const fallbackAnalysis: EmailAnalysis = {
      id: analysisId,
      evidence_id: `EVD-${analysisId.slice(-8).toUpperCase()}`,
      original_filename: 'pasted_email.eml',
      upload_timestamp: new Date().toISOString(),
      size: rawInput.length,
      uploader: 'SOC Analyst',
      subject: getHeaderVal('Subject') || currentEmail.subject || 'Forensic Analysis',
      from: getHeaderVal('From') || currentEmail.senderEmail || '',
      to: getHeaderVal('To') || currentEmail.recipientEmail || '',
      cc: getHeaderVal('Cc') || '',
      date: getHeaderVal('Date') || new Date().toUTCString(),
      reply_to: getHeaderVal('Reply-To') || '',
      return_path: getHeaderVal('Return-Path') || '',
      message_id: getHeaderVal('Message-ID') || '',
      received: extractReceivedHeaders(rawInput),
      authentication_results: getHeaderVal('Authentication-Results') || '',
      raw_email: rawInput,
      plain_text_body: currentEmail.bodyText || rawInput,
      urls: currentEmail.iocs.urls.map(u => u.url),
      attachments: currentEmail.iocs.hashes.map(h => ({
        filename: h.filename,
        mime_type: 'application/octet-stream',
        size: 24500,
        sha256: h.sha256
      }))
    };

    saveAnalysisResult(analysisId, fallbackAnalysis);
    navigate(`/analysis/${analysisId}`);
  };

<<<<<<< Updated upstream
  const handleCopyEvidence = () => {
    navigator.clipboard.writeText(JSON.stringify(currentEmail, null, 2));
    setCopySuccess(true);
    setTimeout(() => setCopySuccess(false), 2000);
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setIsAnalyzing(true);
    let textContent = '';
    try {
      textContent = await file.text();
      setRawInput(textContent);
    } catch {
      // Failed reading file
    }

    const analysisId = `upload-${Date.now()}`;
    try {
      const formData = new FormData();
      formData.append('file', file);

      let res: Response | null = null;
      try {
        res = await fetch('/api/emails/analyze', { method: 'POST', body: formData });
      } catch {
        res = await fetch('http://127.0.0.1:8000/api/emails/analyze', { method: 'POST', body: formData });
      }

      if (res && res.ok) {
        const data = await res.json();
        const parsedAnalysis: EmailAnalysis = {
          id: analysisId,
          evidence_id: data.evidence_id || (data.email_sha256 ? `EVD-${data.email_sha256.slice(0, 10).toUpperCase()}` : `EVD-${analysisId.slice(-8).toUpperCase()}`),
          email_sha256: data.email_sha256,
          original_filename: data.original_filename || file.name,
          upload_timestamp: data.upload_timestamp || new Date().toISOString(),
          size: data.size || file.size,
          uploader: data.uploader || 'SOC Analyst',
          authentication: data.authentication,
          relay_analysis: data.relay_analysis,
          indicators: data.indicators,
          subject: decodeRfc2047(data.subject || data.headers?.subject || file.name),
          from: decodeRfc2047(data.from || data.from_header || data.headers?.from || ''),
          to: decodeRfc2047(Array.isArray(data.to) ? data.to.join(', ') : (data.to || data.headers?.to || '')),
          cc: decodeRfc2047(Array.isArray(data.cc) ? data.cc.join(', ') : (data.cc || data.headers?.cc || '')),
          date: decodeRfc2047(data.date || data.headers?.date || ''),
          reply_to: decodeRfc2047(data.reply_to || data.headers?.reply_to || ''),
          return_path: decodeRfc2047(data.return_path || data.headers?.return_path || ''),
          message_id: decodeRfc2047(data.message_id || data.headers?.message_id || ''),
          received: data.received || data.headers?.received || [],
          authentication_results: data.authentication_results || data.headers?.authentication_results || '',
          plain_text_body: data.plain_text_body || data.body?.plain_text || '',
          html_body: data.html_body || data.body?.html || '',
          raw_email: data.raw_email || textContent || '',
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
          investigation_graph: data.investigation_graph
        };

        saveAnalysisResult(analysisId, parsedAnalysis);
        navigate(`/analysis/${analysisId}`);
        return;
      }
    } catch (err) {
      console.warn('Backend API offline, constructing client-side fallback analysis', err);
    } finally {
      setIsAnalyzing(false);
    }

    // Dynamic header extraction fallback if backend is offline
    const getHeaderVal = (name: string): string => {
      const match = textContent.match(new RegExp(`^${name}:[ \\t]*([^\\r\\n]+(?:\\r?\\n[ \\t]+[^\\r\\n]+)*)`, 'im'));
      return match ? decodeRfc2047(match[1].replace(/\s+/g, ' ').trim()) : '';
    };

    const extractReceivedHeaders = (text: string): string[] => {
      const matches = Array.from(text.matchAll(/^Received:[ \t]*(.+?)(?=\r?\n\S|\r?\n\r?\n|$)/gms));
      return matches.map(m => m[1].replace(/\s+/g, ' ').trim()).filter(Boolean);
    };

    const fallbackAttachments: { filename: string; mime_type: string; size: number; sha256: string }[] = [];
    const attRegex = /(?:Content-Disposition:\s*(?:attachment|inline)[^;\r\n]*;\s*filename=["']?([^"'\r\n;]+)["']?|Content-Type:\s*([^;\r\n]+)[^;\r\n]*;\s*name=["']?([^"'\r\n;]+)["']?)/gi;
    let am;
    const seenNames = new Set<string>();
    while ((am = attRegex.exec(textContent || rawInput)) !== null) {
      const rawName = am[1] || am[3];
      const rawMime = am[2] || 'application/octet-stream';
      if (rawName) {
        const cleanName = decodeRfc2047(rawName.trim().replace(/^["']|["']$/g, ''));
        if (cleanName && !seenNames.has(cleanName.toLowerCase())) {
          seenNames.add(cleanName.toLowerCase());
          fallbackAttachments.push({
            filename: cleanName,
            mime_type: rawMime.trim(),
            size: 0,
            sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
          });
        }
      }
    }

    const fallbackAnalysis: EmailAnalysis = {
      id: analysisId,
      evidence_id: `EVD-${analysisId.slice(-8).toUpperCase()}`,
      original_filename: file.name,
      upload_timestamp: new Date().toISOString(),
      size: file.size,
      uploader: 'SOC Analyst',
      subject: getHeaderVal('Subject') || file.name,
      from: getHeaderVal('From') || '',
      to: getHeaderVal('To') || '',
      cc: getHeaderVal('Cc') || '',
      date: getHeaderVal('Date') || new Date().toUTCString(),
      reply_to: getHeaderVal('Reply-To') || '',
      return_path: getHeaderVal('Return-Path') || '',
      message_id: getHeaderVal('Message-ID') || '',
      received: extractReceivedHeaders(textContent || rawInput),
      authentication_results: getHeaderVal('Authentication-Results') || '',
      raw_email: textContent || rawInput,
      plain_text_body: textContent || rawInput,
      urls: [],
      attachments: fallbackAttachments
    };
    saveAnalysisResult(analysisId, fallbackAnalysis);
    navigate(`/analysis/${analysisId}`);
=======
  const handleRunTextAnalysis = async () => {
    const text = rawInput.trim();
    if (!text) {
      setErrorMessage('Please paste raw RFC-822 email headers and body content.');
      return;
    }
    const blob = new Blob([text], { type: 'message/rfc822' });
    await processEmailStream(blob, 'pasted_message.eml', text);
  };

  const handleFileSelection = async (file: File) => {
    setSelectedFile(file);
    let textContent = '';
    try {
      textContent = await file.text();
    } catch {
      // Binary .eml
    }
    await processEmailStream(file, file.name, textContent);
  };

  const handleDrop = async (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer.files?.[0];
    if (file) {
      await handleFileSelection(file);
    }
>>>>>>> Stashed changes
  };

  return (
    <div className="space-y-6 max-w-5xl mx-auto pb-12">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-5 rounded-card bg-surface border border-border shadow-card">
        <div>
          <div className="flex items-center space-x-2 text-primary font-mono text-[11px] font-semibold uppercase tracking-wider mb-1">
            <Inbox className="w-3.5 h-3.5" />
            <span>STAGE 01 • EVIDENCE INGESTION</span>
          </div>
          <h1 className="text-xl font-bold text-foreground font-sans tracking-tight">
            Ingest & Parse Suspicious Email
          </h1>
          <p className="text-xs text-foreground-muted font-mono mt-0.5">
            Accepts raw RFC-822 (.eml, .txt) files. Computes SHA-256 evidence seals, reconstructs SMTP relays, and extracts network IOCs.
          </p>
        </div>
<<<<<<< Updated upstream

        <div className="flex items-center space-x-2.5">
          <button
            type="button"
            onClick={handleCopyEvidence}
            className="flex items-center space-x-1.5 px-3.5 py-2 rounded-lg bg-surface hover:bg-surface-secondary text-foreground border border-border text-xs font-mono font-medium transition-colors btn-press cursor-pointer"
          >
            {copySuccess ? <CheckCircle2 className="w-3.5 h-3.5 text-success" /> : <Copy className="w-3.5 h-3.5 text-foreground-muted" />}
            <span>{copySuccess ? 'COPIED JSON' : 'EXPORT EVIDENCE JSON'}</span>
          </button>
          <button
            type="button"
            onClick={() => navigate('/cases')}
            className="flex items-center space-x-1.5 px-3.5 py-2 rounded-lg bg-primary hover:bg-primary-hover text-primary-foreground text-xs font-mono font-semibold transition-colors btn-press cursor-pointer"
          >
            <FolderPlus className="w-3.5 h-3.5" />
            <span>CONVERT TO CASE</span>
          </button>
=======

        {/* Ingest Mode Switcher */}
        <div className="flex items-center p-1 rounded-control bg-surface-secondary border border-border self-start md:self-auto">
          <button
            type="button"
            onClick={() => setActiveMode('upload')}
            className={`px-3 py-1.5 rounded-control text-xs font-mono font-medium transition-all cursor-pointer ${
              activeMode === 'upload'
                ? 'bg-surface text-foreground shadow-xs font-semibold'
                : 'text-foreground-muted hover:text-foreground'
            }`}
          >
            File Upload
          </button>
          <button
            type="button"
            onClick={() => setActiveMode('paste')}
            className={`px-3 py-1.5 rounded-control text-xs font-mono font-medium transition-all cursor-pointer ${
              activeMode === 'paste'
                ? 'bg-surface text-foreground shadow-xs font-semibold'
                : 'text-foreground-muted hover:text-foreground'
            }`}
          >
            Raw Headers & Text
          </button>
        </div>
      </div>

      {/* Error Banner */}
      {errorMessage && (
        <div className="p-3.5 rounded-control bg-danger-surface border border-danger-border flex items-start space-x-3 text-xs font-mono text-danger animate-in fade-in">
          <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
          <div className="flex-1">
            <strong className="block font-bold">Ingestion Rejected</strong>
            <span>{errorMessage}</span>
          </div>
        </div>
      )}

      {/* Mode 1: File Drag & Drop Zone */}
      {activeMode === 'upload' && (
        <div
          onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
          onDragLeave={() => setDragOver(false)}
          onDrop={handleDrop}
          className={`p-10 rounded-card border-2 border-dashed text-center transition-all bg-surface ${
            dragOver
              ? 'border-primary bg-primary-subtle/30 scale-[0.99]'
              : 'border-border hover:border-primary/50'
          }`}
        >
          <div className="max-w-md mx-auto space-y-4">
            <div className="w-12 h-12 rounded-full bg-surface-secondary border border-border mx-auto flex items-center justify-center text-primary">
              <Upload className="w-5 h-5" />
            </div>

            <div>
              <h3 className="text-sm font-semibold text-foreground font-sans">
                Drop RFC-822 / .eml file here
              </h3>
              <p className="text-xs text-foreground-muted font-mono mt-1">
                Supports standard RFC-822, MIME, .eml, or text headers up to 10 MB.
              </p>
            </div>

            <div>
              <input
                ref={fileInputRef}
                type="file"
                accept=".eml,.txt,.msg"
                onChange={(e) => {
                  const f = e.target.files?.[0];
                  if (f) handleFileSelection(f);
                }}
                className="hidden"
              />
              <button
                type="button"
                disabled={isAnalyzing}
                onClick={() => fileInputRef.current?.click()}
                className="px-4 py-2 rounded-control bg-primary hover:bg-primary-hover text-primary-foreground font-mono text-xs font-semibold transition-colors btn-press cursor-pointer disabled:opacity-50"
              >
                {selectedFile ? 'Choose Another File' : 'Browse Local Disk'}
              </button>
            </div>

            {selectedFile && (
              <div className="p-2.5 rounded-control bg-surface-secondary border border-border inline-flex items-center space-x-2 text-xs font-mono text-foreground">
                <FileCode className="w-4 h-4 text-primary" />
                <span className="font-semibold">{selectedFile.name}</span>
                <span className="text-foreground-muted">({(selectedFile.size / 1024).toFixed(1)} KB)</span>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Mode 2: Direct RFC-822 Text Paste */}
      {activeMode === 'paste' && (
        <div className="p-5 rounded-card bg-surface border border-border shadow-card space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2 text-xs font-mono font-semibold text-foreground uppercase">
              <FileText className="w-3.5 h-3.5 text-primary" />
              <span>PASTE COMPLETE RFC-822 EMAIL (HEADERS + BODY):</span>
            </div>
            {rawInput && (
              <button
                type="button"
                onClick={() => setRawInput('')}
                className="text-[11px] font-mono text-foreground-muted hover:text-danger cursor-pointer"
              >
                Clear Input
              </button>
            )}
          </div>

          <textarea
            value={rawInput}
            onChange={(e) => setRawInput(e.target.value)}
            rows={10}
            placeholder={`From: billing@external-vendor.com\nTo: finance-ops@corporation.internal\nSubject: Urgent Invoice Update\nDate: Mon, 14 Sep 2026 10:00:00 +0000\nReceived: from relay01.external-vendor.com...\n\nHello, please find updated wire instructions attached...`}
            className="w-full p-3.5 bg-surface-secondary border border-border rounded-control font-mono text-xs text-foreground placeholder:text-foreground-muted focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary leading-relaxed"
          />

          <div className="flex items-center justify-between pt-1">
            <span className="text-[11px] font-mono text-foreground-muted">
              {rawInput.length > 0 ? `${rawInput.length.toLocaleString()} characters` : 'Ready for RFC-822 stream'}
            </span>

            <button
              type="button"
              onClick={handleRunTextAnalysis}
              disabled={isAnalyzing || !rawInput.trim()}
              className="flex items-center space-x-2 px-4 py-2 rounded-control bg-primary hover:bg-primary-hover text-primary-foreground font-mono font-semibold text-xs transition-colors btn-press disabled:opacity-50 cursor-pointer"
            >
              <span>EXECUTE FORENSIC ANALYSIS</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      )}

      {/* In-Flight Pipeline Loading State */}
      {isAnalyzing && (
        <div className="p-5 rounded-card bg-surface border border-primary/40 shadow-md space-y-3 animate-in fade-in">
          <div className="flex items-center space-x-3">
            <div className="w-4 h-4 border-2 border-primary border-t-transparent rounded-full animate-spin" />
            <div className="flex flex-col">
              <span className="text-xs font-mono font-bold text-foreground">
                Executing Automated Forensic Pipeline
              </span>
              <span className="text-[11px] font-mono text-primary animate-pulse">
                {analysisStep}
              </span>
            </div>
          </div>
        </div>
      )}

      {/* Forensic Guarantees & Chain-of-Custody Footer */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        <div className="p-3.5 rounded-control bg-surface border border-border flex items-start space-x-2.5">
          <Lock className="w-4 h-4 text-primary shrink-0 mt-0.5" />
          <div className="text-[11px] font-mono">
            <strong className="block text-foreground font-semibold">Cryptographic Hash</strong>
            <span className="text-foreground-muted">Raw stream is SHA-256 hashed immediately upon intake.</span>
          </div>
        </div>

        <div className="p-3.5 rounded-control bg-surface border border-border flex items-start space-x-2.5">
          <Layers className="w-4 h-4 text-primary shrink-0 mt-0.5" />
          <div className="text-[11px] font-mono">
            <strong className="block text-foreground font-semibold">Deterministic Scoring</strong>
            <span className="text-foreground-muted">Explainable weighted signals; zero synthetic data invention.</span>
          </div>
>>>>>>> Stashed changes
        </div>

<<<<<<< Updated upstream
      {/* Preset Selector & Input Console */}
      <div className="bg-surface border border-border rounded-xl p-5 space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
          <div className="flex items-center space-x-2">
            <Radio className="w-3.5 h-3.5 text-primary" />
            <label className="text-xs font-mono font-semibold text-foreground uppercase">
              SELECT PRESET THREAT SAMPLE OR PASTE EML HEADERS:
            </label>
          </div>

          <div className="flex items-center space-x-2.5">
            <select
              value={selectedSampleId}
              onChange={(e) => setSelectedSampleId(e.target.value)}
              className="bg-surface-secondary border border-border rounded-lg px-3 py-1.5 text-xs font-mono text-foreground focus:outline-none focus:border-primary"
            >
              {SAMPLE_EMAILS.map((sample) => (
                <option key={sample.id} value={sample.id}>
                  {sample.id} - {sample.category} ({sample.severity})
                </option>
              ))}
            </select>

            <label className="cursor-pointer flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-surface-secondary hover:bg-surface text-xs font-mono text-foreground border border-border transition-colors btn-press">
              <Upload className="w-3.5 h-3.5 text-primary" />
              <span>UPLOAD .EML</span>
              <input type="file" accept=".eml,.txt" onChange={handleFileUpload} className="hidden" />
            </label>
          </div>
        </div>

        {/* Input Textarea */}
        <div className="relative">
          <textarea
            value={rawInput}
            onChange={(e) => setRawInput(e.target.value)}
            rows={5}
            placeholder="Paste raw email headers and body text here..."
            className="w-full p-3.5 bg-surface-secondary border border-border rounded-lg font-mono text-xs text-foreground placeholder:text-foreground-muted focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary leading-relaxed"
          />
          <button
            type="button"
            onClick={handleRunAnalysis}
            disabled={isAnalyzing}
            className="absolute bottom-3 right-3 flex items-center space-x-1.5 px-3.5 py-1.5 rounded-md bg-primary hover:bg-primary-hover text-primary-foreground font-mono font-semibold text-xs tracking-wider transition-colors btn-press disabled:opacity-50 cursor-pointer"
          >
            {isAnalyzing ? (
              <div className="w-3.5 h-3.5 border-2 border-primary-foreground border-t-transparent rounded-full animate-spin" />
            ) : (
              <Zap className="w-3.5 h-3.5" />
            )}
            <span>{isAnalyzing ? 'PARSING...' : 'RUN FORENSIC ANALYSIS'}</span>
          </button>
        </div>
      </div>

      {/* Main Analysis Results Console */}
      <div className="space-y-6">
        {/* Risk Score & Threat Summary Header Card */}
        <div className="bg-surface border border-border rounded-xl p-6 grid grid-cols-1 lg:grid-cols-4 gap-6 items-center">
          {/* Risk Gauge */}
          <div className="flex flex-col items-center justify-center p-4 rounded-lg bg-surface-secondary border border-border text-center">
            <span className="text-[10px] font-mono text-foreground-muted uppercase tracking-widest font-semibold">
              FRAUD RISK SCORE
            </span>
            <div className="relative my-2 flex items-center justify-center">
              <div
                className={`text-3xl font-bold font-mono ${
                  currentEmail.riskScore > 80
                    ? 'text-danger'
                    : currentEmail.riskScore > 50
                    ? 'text-warning'
                    : 'text-success'
                }`}
              >
                {currentEmail.riskScore}%
              </div>
            </div>
            <RiskBadge severity={currentEmail.severity} size="md" />
          </div>

          {/* Email Subject & Threat Overview */}
          <div className="lg:col-span-3 space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border pb-2">
              <span className="text-xs font-mono text-primary font-semibold">
                ANALYSIS REF: {currentEmail.id}
              </span>
              <span className="text-xs font-mono text-foreground-muted">
                Timestamp: {currentEmail.timestamp}
              </span>
            </div>

            <div>
              <h3 className="text-base font-bold text-foreground font-sans">
                {currentEmail.subject}
              </h3>
              <p className="text-xs text-foreground-muted mt-1 leading-relaxed">
                {currentEmail.summary}
              </p>
            </div>

            {/* NLP Sentiment Cues */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-1">
              <div
                className={`p-2 rounded-lg border text-[10px] font-mono flex items-center justify-between ${
                  currentEmail.nlpFlags.urgencyCues
                    ? 'bg-danger-surface border-danger-border text-danger font-semibold'
                    : 'bg-surface-secondary border-border text-foreground-muted'
                }`}
              >
                <span>Urgency Cues</span>
                <span>{currentEmail.nlpFlags.urgencyCues ? 'DETECTED' : 'NONE'}</span>
              </div>

              <div
                className={`p-2 rounded-lg border text-[10px] font-mono flex items-center justify-between ${
                  currentEmail.nlpFlags.financialDiversionLanguage
                    ? 'bg-danger-surface border-danger-border text-danger font-semibold'
                    : 'bg-surface-secondary border-border text-foreground-muted'
                }`}
              >
                <span>Payment Diversion</span>
                <span>{currentEmail.nlpFlags.financialDiversionLanguage ? 'DETECTED' : 'NONE'}</span>
              </div>

              <div
                className={`p-2 rounded-lg border text-[10px] font-mono flex items-center justify-between ${
                  currentEmail.nlpFlags.credentialHarvestingKeywords
                    ? 'bg-danger-surface border-danger-border text-danger font-semibold'
                    : 'bg-surface-secondary border-border text-foreground-muted'
                }`}
              >
                <span>Credential Harvest</span>
                <span>{currentEmail.nlpFlags.credentialHarvestingKeywords ? 'DETECTED' : 'NONE'}</span>
              </div>

              <div
                className={`p-2 rounded-lg border text-[10px] font-mono flex items-center justify-between ${
                  currentEmail.nlpFlags.authorityImpersonation
                    ? 'bg-danger-surface border-danger-border text-danger font-semibold'
                    : 'bg-surface-secondary border-border text-foreground-muted'
                }`}
              >
                <span>Executive Impersonation</span>
                <span>{currentEmail.nlpFlags.authorityImpersonation ? 'DETECTED' : 'NONE'}</span>
              </div>
            </div>
          </div>
        </div>

        {/* Tab Navigation Menu */}
        <div className="flex space-x-1.5 border-b border-border pb-1 overflow-x-auto">
          {[
            { id: 'OVERVIEW', label: 'PROTOCOL BREAKDOWN' },
            { id: 'RELAY_TRACE', label: 'ORIGIN GEOLOCATION TRACE' },
            { id: 'IOCS', label: 'EXTRACTED IOCS & HASHES' },
            { id: 'GRAPH', label: 'ATTRIBUTION TOPOLOGY GRAPH' },
            { id: 'HEADERS', label: 'RAW HEADERS' },
          ].map((tab) => {
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                type="button"
                onClick={() => setActiveTab(tab.id as typeof activeTab)}
                className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-colors cursor-pointer ${
                  isActive
                    ? 'bg-surface text-foreground font-semibold border border-border shadow-xs'
                    : 'text-foreground-muted hover:text-foreground hover:bg-surface/50 border border-transparent'
                }`}
              >
                {tab.label}
              </button>
            );
          })}
        </div>

        {/* Tab 1: Protocol Breakdown & Key Identity Specs */}
        {activeTab === 'OVERVIEW' && (
          <div className="space-y-6">
            <HeaderProtocolStatus protocols={currentEmail.protocols} />

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="p-4 rounded-xl bg-surface border border-border space-y-2">
                <h4 className="text-xs font-mono font-semibold text-primary uppercase">
                  DISPLAY NAME vs SENDER DOMAIN ALIGNMENT
                </h4>
                <div className="text-xs font-mono space-y-1 text-foreground-muted">
                  <div>Display Name: <strong className="text-foreground">{currentEmail.senderName}</strong></div>
                  <div>Header From: <strong className="text-danger">{currentEmail.senderEmail}</strong></div>
                  <div>Return-Path: <strong className="text-danger">{currentEmail.returnPath}</strong></div>
                  <div>Reply-To: <strong className="text-warning">{currentEmail.replyTo}</strong></div>
                </div>
              </div>

              <div className="p-4 rounded-xl bg-surface border border-border space-y-2">
                <h4 className="text-xs font-mono font-semibold text-primary uppercase">
                  BODY TEXT CONTENT FORENSICS
                </h4>
                <div className="p-3 bg-surface-secondary rounded-lg text-xs font-mono text-foreground whitespace-pre-wrap max-h-40 overflow-y-auto">
                  {currentEmail.bodyText}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Tab 2: Geolocation & Hop Trajectory */}
        {activeTab === 'RELAY_TRACE' && (
          <GeoTraceMap originGeo={currentEmail.originGeo} hops={currentEmail.hops} />
        )}

        {/* Tab 3: Extracted Indicators of Compromise (IOCs) */}
        {activeTab === 'IOCS' && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Obfuscated Links */}
            <div className="p-4 rounded-xl bg-surface border border-border space-y-3">
              <div className="flex items-center space-x-2 text-xs font-mono font-semibold text-primary uppercase">
                <ExternalLink className="w-3.5 h-3.5" />
                <span>Extracted Obfuscated URLs ({currentEmail.iocs.urls.length})</span>
              </div>
              <div className="space-y-2">
                {currentEmail.iocs.urls.map((urlObj, i) => (
                  <div key={i} className="p-3 rounded-lg bg-surface-secondary border border-border text-xs font-mono">
                    <div className="text-danger font-semibold break-all">{urlObj.url}</div>
                    <div className="flex justify-between text-[10px] text-foreground-muted mt-1">
                      <span>Target Domain: {urlObj.domain}</span>
                      <span className="text-danger font-bold">{urlObj.riskScore}% Malicious Risk</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Hashes & File Attachments */}
            <div className="p-4 rounded-xl bg-surface border border-border space-y-3">
              <div className="flex items-center space-x-2 text-xs font-mono font-semibold text-primary uppercase">
                <Hash className="w-3.5 h-3.5" />
                <span>Payload Executable & Attachment Hashes</span>
              </div>
              {currentEmail.iocs.hashes.length > 0 ? (
                <div className="space-y-2">
                  {currentEmail.iocs.hashes.map((h, i) => (
                    <div key={i} className="p-3 rounded-lg bg-surface-secondary border border-border text-xs font-mono space-y-1">
                      <div className="text-foreground font-semibold flex items-center justify-between">
                        <span>{h.filename}</span>
                        <span className="px-1.5 py-0.2 rounded bg-danger-surface text-danger text-[10px] border border-danger-border">
                          MALICIOUS EXECUTABLE
                        </span>
                      </div>
                      <div className="text-[10px] text-foreground-muted truncate">MD5: {h.md5}</div>
                      <div className="text-[10px] text-primary truncate">SHA256: {h.sha256}</div>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-xs font-mono text-foreground-muted">No file attachments detected in this message.</p>
              )}
            </div>
          </div>
        )}

        {/* Tab 4: Graph Topology */}
        {activeTab === 'GRAPH' && (
          <AttributionGraph
            senderDomain={currentEmail.senderEmail.split('@')[1] || 'unknown'}
            originIp={currentEmail.originGeo.ip}
            targetEmail={currentEmail.recipientEmail}
            campaignName={currentEmail.campaignName}
            hashes={currentEmail.iocs.hashes.map(h => h.sha256)}
          />
        )}

        {/* Tab 5: Raw Email Headers */}
        {activeTab === 'HEADERS' && (
          <div className="p-4 rounded-xl bg-surface border border-border">
            <h4 className="text-xs font-mono font-semibold text-primary uppercase mb-2">
              RFC-822 RAW MAIL HEADERS
            </h4>
            <pre className="p-4 bg-surface-secondary rounded-lg text-[11px] font-mono text-foreground overflow-x-auto leading-relaxed border border-border">
              {currentEmail.rawHeaders}
            </pre>
          </div>
        )}
=======
        <div className="p-3.5 rounded-control bg-surface border border-border flex items-start space-x-2.5">
          <Shield className="w-4 h-4 text-primary shrink-0 mt-0.5" />
          <div className="text-[11px] font-mono">
            <strong className="block text-foreground font-semibold">Persistent History</strong>
            <span className="text-foreground-muted">Canonical results stored in SQLite for replay and correlation.</span>
          </div>
        </div>
>>>>>>> Stashed changes
      </div>
    </div>
  );
};
