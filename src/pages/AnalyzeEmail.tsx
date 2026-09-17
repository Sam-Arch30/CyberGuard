import React, { useState, useEffect, useMemo } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import {
  SearchCode,
  Zap,
  Upload,
  Radio,
  Hash,
  ExternalLink,
  FolderPlus,
  CheckCircle2,
  Copy,
  Network
} from 'lucide-react';
import { SAMPLE_EMAILS } from '../data/mockData';
import type { EmailAnalysisData } from '../types';
import type { EmailAnalysis } from '../types/forensic';
import { saveAnalysisResult } from '../utils/forensicStore';
import { decodeRfc2047, resolveEmailIndicators, resolveAttribution } from '../utils/indicatorHelper';
import { RiskBadge } from '../components/common/RiskBadge';
import { HeaderProtocolStatus } from '../components/common/HeaderProtocolStatus';
import { GeoTraceMap } from '../components/common/GeoTraceMap';
import { AttributionGraph } from '../components/common/AttributionGraph';
import { InfrastructureAttributionSection } from '../components/forensic/InfrastructureAttributionSection';
import { CampaignAlertBanner } from '../components/campaign/CampaignAlertBanner';

export const AnalyzeEmail: React.FC = () => {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();

  const emailIdParam = searchParams.get('id');
  const initialEmail = SAMPLE_EMAILS.find(e => e.id === emailIdParam) || SAMPLE_EMAILS[0];

  const [selectedSampleId, setSelectedSampleId] = useState<string>(initialEmail.id);
  const [currentEmail, setCurrentEmail] = useState<EmailAnalysisData>(initialEmail);
  const [rawInput, setRawInput] = useState<string>(initialEmail.rawHeaders + '\n\n' + initialEmail.bodyText);
  const [isAnalyzing, setIsAnalyzing] = useState<boolean>(false);
  const [activeTab, setActiveTab] = useState<'OVERVIEW' | 'ATTRIBUTION' | 'HEADERS' | 'RELAY_TRACE' | 'IOCS' | 'GRAPH'>('OVERVIEW');
  const [copySuccess, setCopySuccess] = useState<boolean>(false);

  useEffect(() => {
    const found = SAMPLE_EMAILS.find(e => e.id === selectedSampleId);
    if (found) {
      setCurrentEmail(found);
      setRawInput(found.rawHeaders + '\n\n' + found.bodyText);
    }
  }, [selectedSampleId]);

  const currentEmailAsAnalysis = useMemo<EmailAnalysis>(() => {
    const fromDomain = currentEmail.senderEmail?.includes('@') ? currentEmail.senderEmail.split('@')[1] : '';
    const receivedHeaders = (currentEmail.hops || []).map(h => `from ${h.fromHost || ''} (${h.fromIp || ''}) by ${h.byHost || ''}; ${h.timestamp}`);
    const rawHeadersLines = currentEmail.rawHeaders ? currentEmail.rawHeaders.split('\n').filter(l => l.toLowerCase().startsWith('received:')) : [];
    const hopIps = (currentEmail.hops || []).flatMap(h => [h.fromIp, h.byIp]).filter(Boolean);
    const originIp = currentEmail.originGeo?.ip;
    const allIps = Array.from(new Set([originIp, ...hopIps].filter(Boolean))) as string[];

    return resolveEmailIndicators({
      id: currentEmail.id,
      evidence_id: `EVD-${currentEmail.id.toUpperCase()}`,
      subject: currentEmail.subject,
      from: `${currentEmail.senderName} <${currentEmail.senderEmail}>`,
      to: currentEmail.recipientEmail,
      reply_to: currentEmail.replyTo,
      return_path: currentEmail.returnPath,
      date: currentEmail.timestamp,
      received: receivedHeaders.length > 0 ? receivedHeaders : rawHeadersLines,
      raw_email: currentEmail.rawHeaders + '\n\n' + currentEmail.bodyText,
      plain_text_body: currentEmail.bodyText,
      ips: allIps,
      domains: fromDomain ? [fromDomain] : [],
      urls: (currentEmail.iocs?.urls || []).map(u => u.url),
      attachments: (currentEmail.iocs?.hashes || []).map(h => ({
        filename: h.filename,
        mime_type: 'application/octet-stream',
        size: 15000,
        sha256: h.sha256
      })),
      threat_score: {
        score: currentEmail.riskScore,
        severity: currentEmail.severity === 'CRITICAL' ? 'critical' : currentEmail.severity === 'HIGH' ? 'high' : 'low',
        reasons: [],
        positive_evidence: [],
        summary: currentEmail.summary || 'Threat score analysis'
      },
      ip_intelligence: (() => {
        const intel: Record<string, any> = {};
        if (currentEmail.originGeo?.ip) {
          intel[currentEmail.originGeo.ip] = {
            ip: currentEmail.originGeo.ip,
            country: currentEmail.originGeo.country,
            city: currentEmail.originGeo.city,
            latitude: currentEmail.originGeo.latitude,
            longitude: currentEmail.originGeo.longitude,
            asn: currentEmail.originGeo.asn,
            isp: currentEmail.originGeo.isp,
            is_proxy_vpn_tor: currentEmail.originGeo.isVpn || currentEmail.originGeo.isTor,
            is_hosting: true,
            infrastructure_type: 'Observed Infrastructure Location'
          };
        }
        (currentEmail.hops || []).forEach((hop, idx) => {
          const hIp = hop.fromIp;
          if (hIp && !intel[hIp]) {
            intel[hIp] = {
              ip: hIp,
              country: hop.country || 'United States',
              city: hop.city || 'Mountain View',
              latitude: hop.isOrigin && currentEmail.originGeo?.latitude ? currentEmail.originGeo.latitude : (37.3860 + (idx + 1) * 2.1),
              longitude: hop.isOrigin && currentEmail.originGeo?.longitude ? currentEmail.originGeo.longitude : (-122.0839 + (idx + 1) * 2.8),
              asn: (hop as any).asn || 'AS64512',
              isp: hop.org,
              is_hosting: true,
              infrastructure_type: 'Observed Infrastructure Location'
            };
          }
        });
        return intel;
      })(),
      authentication: {
        spf: { result: (typeof currentEmail.protocols?.spf === 'string' ? currentEmail.protocols.spf : 'neutral').toLowerCase() },
        dkim: { result: (typeof currentEmail.protocols?.dkim === 'string' ? currentEmail.protocols.dkim : 'neutral').toLowerCase() },
        dmarc: { result: (typeof currentEmail.protocols?.dmarc === 'string' ? currentEmail.protocols.dmarc : 'neutral').toLowerCase() }
      }
    });
  }, [currentEmail]);

  const resolvedAttribution = useMemo(() => {
    return currentEmailAsAnalysis.attribution || resolveAttribution(currentEmailAsAnalysis);
  }, [currentEmailAsAnalysis]);

  const handleRunAnalysis = async () => {
    if (!rawInput.trim()) return;
    setIsAnalyzing(true);
    const analysisId = `analysis-${Date.now()}`;

    try {
      const blob = new Blob([rawInput], { type: 'message/rfc822' });
      const formData = new FormData();
      formData.append('file', blob, 'pasted_email.eml');

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
          attribution: data.attribution,
          investigation_graph: data.investigation_graph
        };

        saveAnalysisResult(analysisId, parsedAnalysis);
        navigate(`/analysis/${analysisId}`);
        return;
      }
    } catch (err) {
      console.warn('Backend parse failed, fallback to local analysis:', err);
    } finally {
      setIsAnalyzing(false);
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
          attribution: data.attribution,
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
        </div>
      </div>

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
        {/* Campaign Fingerprinting Alert */}
        {(currentEmail.riskScore > 60 || currentEmail.id === 'email-001') && (
          <CampaignAlertBanner
            alertData={{
              is_campaign_detected: true,
              campaign_id: 'C-042',
              campaign_name: 'Operation DarkHydra - Executive Invoice & Wire Harvester',
              correlated_message_count: 16,
              overall_confidence: 91,
              strongest_reasons: [
                'Shared dropzone IP 185.220.101.42 (Russia / Bulletproof Node AS4821)',
                'URL redirect chain leading to /auth/v2/secure_login.php credential harvester',
                'HTML SimHash template match 89% across executive invoice lures',
                'Lookalike domain target: bank-corp-update.com impersonating BankCorp'
              ],
              category_scores: {
                infrastructure_similarity: 92,
                domain_similarity: 78,
                url_similarity: 96,
                content_similarity: 81,
                template_similarity: 89,
                authentication_similarity: 75,
                attachment_similarity: 85,
                overall_confidence: 91
              },
              alert_headline: 'Potential campaign detected',
              alert_subtext: 'This email shares infrastructure or behavioral characteristics with 16 previously analyzed messages.',
              first_seen: '2026-08-12T04:12:00Z',
              last_seen: '2026-09-10T19:45:00Z',
              dominant_attack_type: 'Credential Harvesting & BEC Wire Fraud',
              targeted_brands: ['BankCorp', 'Microsoft 365', 'DocuSign']
            }}
          />
        )}

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
            { id: 'ATTRIBUTION', label: 'INFRASTRUCTURE ATTRIBUTION', icon: Network },
            { id: 'RELAY_TRACE', label: 'ORIGIN GEOLOCATION TRACE' },
            { id: 'IOCS', label: 'EXTRACTED IOCS & HASHES' },
            { id: 'GRAPH', label: 'ATTRIBUTION TOPOLOGY GRAPH' },
            { id: 'HEADERS', label: 'RAW HEADERS' },
          ].map((tab) => {
            const isActive = activeTab === tab.id;
            const Icon = 'icon' in tab ? tab.icon : null;
            return (
              <button
                key={tab.id}
                type="button"
                onClick={() => setActiveTab(tab.id as typeof activeTab)}
                className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-colors cursor-pointer ${
                  isActive
                    ? 'bg-surface text-foreground font-semibold border border-border shadow-xs'
                    : 'text-foreground-muted hover:text-foreground hover:bg-surface/50 border border-transparent'
                }`}
              >
                {Icon && <Icon className="w-3.5 h-3.5 text-primary" />}
                <span>{tab.label}</span>
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

            {/* Section: Probabilistic Threat Attribution Engine */}
            <div className="pt-2">
              <InfrastructureAttributionSection
                attribution={resolvedAttribution}
                onFocusGraphNode={() => setActiveTab('GRAPH')}
              />
            </div>
          </div>
        )}

        {/* Tab: Dedicated Infrastructure Attribution Section */}
        {activeTab === 'ATTRIBUTION' && (
          <div className="space-y-6">
            <InfrastructureAttributionSection
              attribution={resolvedAttribution}
              onFocusGraphNode={() => setActiveTab('GRAPH')}
            />
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
      </div>
    </div>
  );
};
