import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  SearchCode,
  Zap,
  Upload,
  FileText,
  Shield,
  ArrowRight,
  Clock,
  Download,
  Network,
  ExternalLink,
  History
} from 'lucide-react';
import type { EmailAnalysis } from '../types/forensic';
import { saveAnalysisResult } from '../utils/forensicStore';
import { decodeRfc2047 } from '../utils/indicatorHelper';
import { AnalysisPipelineProgress, type PipelineOverallStatus } from '../components/forensic/AnalysisPipelineProgress';

const SAMPLE_PHISHING = `Received: from edge-relay.security-gateway.net (194.165.16.88) by mx01.enterprise.corp with ESMTPS id p4102 for <security.ops@enterprise.corp>; Tue, 15 Sep 2026 10:41:45 +0000
Received: from smtp-origin.shadow-node.ru (185.220.101.42) by edge-relay.security-gateway.net with ESMTP id r9182; Tue, 15 Sep 2026 10:41:02 +0000
From: IT Security Team <security-alert@m1crosoft-auth-verify.com>
To: security.ops@enterprise.corp
Subject: Urgent: Password Expiration Notification Required
Date: Tue, 15 Sep 2026 10:40:55 +0000
Message-ID: <20260915104055.8921@m1crosoft-auth-verify.com>
Authentication-Results: mx01.enterprise.corp; spf=fail smtp.mailfrom=m1crosoft-auth-verify.com; dkim=fail; dmarc=fail
Content-Type: text/plain; charset="UTF-8"

Your enterprise account credentials are set to expire within 24 hours.
Please authenticate your identity immediately at:
https://login.m1crosoft-auth-verify.com/portal/login?id=8829

Failure to re-verify will result in administrative account revocation.

Internal IT Helpdesk
Support ID: 9812-B`;

const SAMPLE_CEO_FRAUD = `Received: from mx.outbound-route.org (185.100.85.10) by mx01.enterprise.corp with ESMTP id m4402; Tue, 15 Sep 2026 08:15:30 +0000
From: Jonathan Vance <ceo.vance@executive-board-global.net>
To: finance@enterprise.corp
Subject: Urgent: Confidential Wire Transaction Request
Date: Tue, 15 Sep 2026 08:14:20 +0000
Message-ID: <ceo-confidential-99120@executive-board-global.net>
Authentication-Results: mx01.enterprise.corp; spf=softfail; dkim=pass; dmarc=fail
Content-Type: text/plain; charset="UTF-8"

Hi Team,

I am currently in meetings with overseas acquisition partners. 
Please expedite an international wire transfer of $142,500 for legal retainer fees.
Wiring instructions are accessible at:
https://portal-secure-vault.net/invoices/INV-2026-9812.pdf

Please handle this with strict confidentiality.

Jonathan Vance
Chief Executive Officer`;

export const AnalyzeEmail: React.FC = () => {
  const navigate = useNavigate();
  const [rawInput, setRawInput] = useState<string>('');
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [dragOver, setDragOver] = useState<boolean>(false);

  // Real Pipeline Progress Lifecycle State
  const [pipelineStatus, setPipelineStatus] = useState<PipelineOverallStatus>('idle');
  const [activeFilename, setActiveFilename] = useState<string>('');
  const [activeFileSize, setActiveFileSize] = useState<number>(0);
  const [analysisData, setAnalysisData] = useState<any>(null);
  const [targetAnalysisId, setTargetAnalysisId] = useState<string | null>(null);
  const [recentIngested, setRecentIngested] = useState<any[]>([]);

  const fetchRecent = async () => {
    try {
      const res = await fetch('/api/dashboard/emails?limit=5');
      if (res.ok) {
        const data = await res.json();
        if (data && data.items) {
          setRecentIngested(data.items);
        }
      }
    } catch {
      try {
        const fallbackRes = await fetch('http://127.0.0.1:8000/api/dashboard/emails?limit=5');
        if (fallbackRes.ok) {
          const data = await fallbackRes.json();
          if (data && data.items) {
            setRecentIngested(data.items);
          }
        }
      } catch {
        // ignore
      }
    }
  };

  useEffect(() => {
    fetchRecent();
  }, []);

  const processEmailContent = async (fileOrBlob: Blob, filename: string, rawText?: string) => {
    setActiveFilename(filename);
    setActiveFileSize(fileOrBlob.size);
    setPipelineStatus('uploading');
    setErrorMessage(null);
    const analysisId = `analysis-${Date.now()}`;
    setTargetAnalysisId(analysisId);

    try {
      const formData = new FormData();
      formData.append('file', fileOrBlob, filename);

      // Server in-flight processing
      setPipelineStatus('processing');

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
        setAnalysisData(data);
        setPipelineStatus('completed');

        // Allow user a restrained moment to perceive completed pipeline stages before workspace entry
        setTimeout(() => {
          navigate(`/investigate/${parsedAnalysis.evidence_id || analysisId}/overview`);
        }, 500);
        return;
      } else {
        const errText = res ? await res.text() : 'Server did not respond.';
        setErrorMessage(`Forensic analysis failed: ${errText || 'Unprocessable email format'}`);
        setPipelineStatus('error');
      }
    } catch (err: any) {
      setErrorMessage(`Error connecting to analysis engine: ${err?.message || 'Network error'}`);
      setPipelineStatus('error');
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

  const isBusy = pipelineStatus === 'uploading' || pipelineStatus === 'processing';

  return (
    <div className="space-y-6 pb-12 max-w-5xl mx-auto page-enter">
      {/* Top Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-surface p-5 rounded-card border border-border">
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

      {/* REAL PIPELINE PROGRESS DISPLAY (Active while analyzing or recently completed) */}
      {pipelineStatus !== 'idle' && (
        <div className="animate-in fade-in duration-150">
          <AnalysisPipelineProgress
            status={pipelineStatus}
            filename={activeFilename}
            fileSizeBytes={activeFileSize}
            analysisData={analysisData}
            errorMessage={errorMessage || undefined}
            onRetry={() => {
              setPipelineStatus('idle');
              setErrorMessage(null);
            }}
            onViewResults={() => {
              if (targetAnalysisId) {
                navigate(`/investigate/${analysisData?.evidence_id || targetAnalysisId}/overview`);
              }
            }}
          />
        </div>
      )}

      {/* Upload Zone (Hidden while actively analyzing to prevent state conflict) */}
      {!isBusy && (
        <>
          <div
            onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
            onDragLeave={() => setDragOver(false)}
            onDrop={handleDrop}
            className={`bg-surface border-2 border-dashed rounded-card p-6 sm:p-8 text-center transition-all ${
              dragOver ? 'border-primary bg-primary-subtle/30' : 'border-border hover:border-primary/40'
            }`}
          >
            <div className="max-w-md mx-auto space-y-3.5">
              <div className="p-3 bg-surface-secondary rounded-control w-12 h-12 mx-auto flex items-center justify-center border border-border text-primary">
                <Upload className="w-5 h-5" />
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
                <label className="inline-flex items-center space-x-2 px-4 py-2 rounded-control bg-primary hover:bg-primary-hover text-primary-foreground text-xs font-mono font-semibold transition-colors btn-press cursor-pointer shadow-xs">
                  <Upload className="w-3.5 h-3.5" />
                  <span>Browse File</span>
                  <input type="file" accept=".eml,.txt,.msg" onChange={handleFileUpload} className="hidden" />
                </label>
              </div>
            </div>
          </div>

          {/* Direct Raw Content Ingestion Console */}
          <div className="bg-surface border border-border rounded-card p-5 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div className="flex items-center space-x-2 text-xs font-mono font-semibold text-foreground uppercase">
                <FileText className="w-3.5 h-3.5 text-primary" />
                <span>OR PASTE RAW RFC-822 EMAIL HEADERS AND BODY:</span>
              </div>
              <div className="flex items-center space-x-2 flex-wrap">
                <button
                  type="button"
                  onClick={() => setRawInput(SAMPLE_PHISHING)}
                  className="text-[11px] font-mono px-2 py-0.5 rounded bg-surface-secondary hover:bg-surface border border-border text-primary hover:text-primary-hover cursor-pointer transition-colors"
                >
                  Load Phishing Sample
                </button>
                <button
                  type="button"
                  onClick={() => setRawInput(SAMPLE_CEO_FRAUD)}
                  className="text-[11px] font-mono px-2 py-0.5 rounded bg-surface-secondary hover:bg-surface border border-border text-foreground-muted hover:text-foreground cursor-pointer transition-colors"
                >
                  Load Executive Impersonation
                </button>
                {rawInput && (
                  <button
                    type="button"
                    onClick={() => setRawInput('')}
                    className="text-[11px] font-mono text-foreground-muted hover:text-danger cursor-pointer ml-1 transition-colors"
                  >
                    Clear
                  </button>
                )}
              </div>
            </div>

            <div className="relative">
              <textarea
                value={rawInput}
                onChange={(e) => setRawInput(e.target.value)}
                rows={8}
                placeholder="From: sender@example.com&#10;To: recipient@example.com&#10;Subject: Security Notification&#10;Date: Mon, 15 Sep 2026 12:00:00 +0000&#10;Received: from mail.example.com...&#10;&#10;Email body content here..."
                className="w-full p-3 bg-surface-secondary border border-border rounded-control font-mono text-xs text-foreground placeholder:text-foreground-muted focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary leading-relaxed"
              />
            </div>

            <div className="flex justify-end">
              <button
                type="button"
                onClick={handleRunAnalysis}
                disabled={isBusy || !rawInput.trim()}
                className="flex items-center space-x-2 px-4 py-2 rounded-control bg-primary hover:bg-primary-hover text-primary-foreground font-mono font-semibold text-xs tracking-wider transition-colors btn-press disabled:opacity-50 cursor-pointer shadow-xs"
              >
                <Zap className="w-3.5 h-3.5" />
                <span>RUN FORENSIC PIPELINE</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>

          {/* Recently Ingested .EML Files Quick-Access Section */}
          {recentIngested.length > 0 && (
            <div className="bg-surface border border-border rounded-card p-5 space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <Clock className="w-4 h-4 text-primary" />
                  <h3 className="text-xs font-mono font-bold text-foreground uppercase tracking-wider">
                    Recently Ingested .EML Files in Storage ({recentIngested.length})
                  </h3>
                </div>
                <button
                  type="button"
                  onClick={() => navigate('/history')}
                  className="text-xs font-mono text-primary hover:text-primary-hover flex items-center space-x-1 cursor-pointer"
                >
                  <History className="w-3.5 h-3.5" />
                  <span>View All Ingested Evidence &rarr;</span>
                </button>
              </div>

              <div className="divide-y divide-border">
                {recentIngested.map((item) => {
                  const evId = item.evidence_id || item.id;
                  const threatScore = Math.round(item.threat_score || 0);
                  const isHigh = threatScore >= 70;
                  const isMed = threatScore >= 40 && threatScore < 70;
                  return (
                    <div
                      key={item.id}
                      className="py-2.5 flex flex-col sm:flex-row sm:items-center justify-between gap-2 hover:bg-surface-secondary/50 px-2 rounded-lg transition-colors"
                    >
                      <div className="flex items-start space-x-2.5 min-w-0">
                        <FileText className="w-4 h-4 text-primary shrink-0 mt-0.5" />
                        <div className="min-w-0 space-y-0.5">
                          <div className="flex items-center space-x-2 flex-wrap">
                            <span className="text-xs font-mono font-semibold text-foreground truncate max-w-xs sm:max-w-md">
                              {item.original_filename || `${evId}.eml`}
                            </span>
                            <span
                              className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${
                                isHigh
                                  ? 'bg-danger-surface text-danger border-danger-border font-bold'
                                  : isMed
                                  ? 'bg-warning-surface text-warning border-warning-border'
                                  : 'bg-surface-secondary text-foreground-muted border-border'
                              }`}
                            >
                              Score: {threatScore}
                            </span>
                          </div>
                          <p className="text-[11px] font-mono text-foreground-muted truncate max-w-sm sm:max-w-lg">
                            {item.subject || 'No Subject'} &middot; <span className="text-foreground">{item.sender}</span>
                          </p>
                        </div>
                      </div>

                      <div className="flex items-center space-x-2 shrink-0 self-end sm:self-center">
                        <button
                          type="button"
                          onClick={() => navigate(`/investigate/${encodeURIComponent(evId)}/investigation?subtab=campaigns`)}
                          className="px-2.5 py-1 rounded-md bg-surface-secondary border border-border hover:border-primary/40 text-foreground hover:text-primary text-[11px] font-mono flex items-center space-x-1 cursor-pointer transition-colors"
                          title="Correlate this .EML across Campaigns"
                        >
                          <Network className="w-3 h-3 text-primary" />
                          <span>Correlate</span>
                        </button>
                        <button
                          type="button"
                          onClick={() => window.open(`http://localhost:8000/api/emails/${encodeURIComponent(evId)}/download`, '_blank')}
                          className="px-2.5 py-1 rounded-md bg-surface-secondary border border-border hover:border-primary/40 text-foreground hover:text-primary text-[11px] font-mono flex items-center space-x-1 cursor-pointer transition-colors"
                          title="Download RFC-822 .EML"
                        >
                          <Download className="w-3 h-3 text-primary" />
                          <span>.EML</span>
                        </button>
                        <button
                          type="button"
                          onClick={() => navigate(`/investigate/${encodeURIComponent(evId)}`)}
                          className="px-2.5 py-1 rounded-md bg-primary/10 border border-primary/25 hover:bg-primary hover:text-primary-foreground text-primary text-[11px] font-mono flex items-center space-x-1 cursor-pointer transition-colors font-medium"
                          title="Open in Workspace"
                        >
                          <ExternalLink className="w-3 h-3" />
                          <span>Open</span>
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </>
      )}

      {/* Forensic Verification Notice */}
      <div className="p-4 rounded-card bg-surface border border-border flex items-start space-x-3 text-xs font-mono text-foreground-muted">
        <Shield className="w-4 h-4 text-primary shrink-0 mt-0.5" />
        <p className="leading-relaxed">
          <strong className="text-foreground">Evidence Integrity Guarantee:</strong> Ingested emails are immutably hashed (SHA-256) upon upload. All authentication evaluations (SPF, DKIM, DMARC), network routing hops, and indicator extractions are derived exclusively from actual email content without synthetic fallbacks.
        </p>
      </div>
    </div>
  );
};

