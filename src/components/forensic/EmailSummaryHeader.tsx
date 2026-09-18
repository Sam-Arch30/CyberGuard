import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Shield,
  Mail,
  Calendar,
  User,
  Hash,
  Briefcase,
  FileText,
  Loader2,
  CheckCircle2,
  GitMerge,
  ArrowLeft,
  CornerDownLeft
} from 'lucide-react';
import type { EmailAnalysis } from '../../types/forensic';
import { CopyButton } from './CopyButton';
import { AddToCaseModal } from '../case/AddToCaseModal';
import { api } from '../../services/api';

interface EmailSummaryHeaderProps {
  email: EmailAnalysis;
  onOpenCopilot?: () => void;
}

export const EmailSummaryHeader: React.FC<EmailSummaryHeaderProps> = ({ email }) => {
  const navigate = useNavigate();
  const [isCaseModalOpen, setIsCaseModalOpen] = useState(false);
  const [isGeneratingReport, setIsGeneratingReport] = useState(false);
  const [reportSuccess, setReportSuccess] = useState(false);

  const handleGenerateReport = async () => {
    setIsGeneratingReport(true);
    try {
      const blob = await api.reports.generate({
        analysis: email,
        analyst_name: 'SOC Lead Analyst'
      });

      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      const sha = email.email_sha256 || email.id || 'forensic';
      a.download = `MailTrace_Forensic_Report_${sha.slice(0, 10)}.pdf`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);

      setReportSuccess(true);
      setTimeout(() => setReportSuccess(false), 4000);
    } catch (err) {
      console.error('Failed to generate report:', err);
    } finally {
      setIsGeneratingReport(false);
    }
  };

  const toDisplay = Array.isArray(email.to) ? email.to.join(', ') : email.to;
  const scoreVal = email.threat_score?.score ?? 0;
  const sevVal = (email.threat_score?.severity || 'low').toLowerCase();

  return (
    <div className="command-strip p-4 sm:p-5 space-y-4">
      {/* Top Strip: Status, Threat Score, & Actions */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-border">
        <div className="flex flex-wrap items-center gap-2.5">
          <div className="flex items-center space-x-1.5 text-xs font-mono font-semibold uppercase text-primary">
            <Shield className="w-4 h-4 text-primary" />
            <span>Forensic Evidence Record</span>
          </div>

          {email.threat_score && (
            <div className={`px-2 py-0.5 rounded text-xs font-mono font-bold flex items-center space-x-1.5 ${
              scoreVal >= 80 ? 'bg-danger-surface text-danger border border-danger-border' :
              scoreVal >= 50 ? 'bg-warning-surface text-warning border border-warning-border' :
              'bg-surface-secondary text-foreground-muted border border-border'
            }`}>
              <span className={`w-1.5 h-1.5 rounded-full ${
                scoreVal >= 80 ? 'bg-danger' : scoreVal >= 50 ? 'bg-warning' : 'bg-foreground-muted'
              }`} />
              <span>Score: {scoreVal}/100</span>
              <span className="uppercase text-[10px] opacity-80">({sevVal})</span>
            </div>
          )}

          {email.evidence_id && (
            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-surface-secondary border border-border text-foreground-muted">
              {email.evidence_id}
            </span>
          )}
        </div>

        {/* Action Controls */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Correlate Button */}
          <button
            type="button"
            onClick={() => navigate(`/cross-investigation/${email.id || 'demo'}`)}
            className="flex items-center space-x-1 px-2.5 py-1.5 rounded-control bg-surface-secondary hover:bg-surface border border-border text-foreground font-mono text-xs font-medium transition-colors btn-press cursor-pointer"
            title="Correlate with historical emails and campaign clusters"
          >
            <GitMerge className="w-3.5 h-3.5 text-primary" />
            <span>Correlate</span>
          </button>

          {/* Add to Case */}
          <button
            type="button"
            id="add-to-case-button"
            onClick={() => setIsCaseModalOpen(true)}
            className="flex items-center space-x-1 px-2.5 py-1.5 rounded-control bg-surface-secondary hover:bg-surface border border-border text-foreground font-mono text-xs font-medium transition-colors btn-press cursor-pointer"
          >
            <Briefcase className="w-3.5 h-3.5 text-primary" />
            <span>Add to Case</span>
          </button>

          {/* Export Report */}
          <button
            type="button"
            id="generate-forensic-report-btn"
            onClick={handleGenerateReport}
            disabled={isGeneratingReport}
            className="flex items-center space-x-1 px-2.5 py-1.5 rounded-control bg-surface-secondary hover:bg-surface border border-border text-foreground font-mono text-xs font-medium transition-colors btn-press disabled:opacity-50 cursor-pointer"
            title="Generate forensic PDF report"
          >
            {isGeneratingReport ? (
              <>
                <Loader2 className="w-3.5 h-3.5 animate-spin text-primary" />
                <span>Exporting...</span>
              </>
            ) : reportSuccess ? (
              <>
                <CheckCircle2 className="w-3.5 h-3.5 text-success" />
                <span>Downloaded</span>
              </>
            ) : (
              <>
                <FileText className="w-3.5 h-3.5 text-primary" />
                <span>Export PDF</span>
              </>
            )}
          </button>

          {/* Ingest Another */}
          <button
            type="button"
            onClick={() => navigate('/analyze')}
            className="flex items-center space-x-1 px-3 py-1.5 rounded-control bg-primary hover:bg-primary-hover text-primary-foreground font-mono text-xs font-semibold transition-colors btn-press cursor-pointer"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            <span>New Ingest</span>
          </button>
        </div>
      </div>

      {/* Modal Dialog */}
      <AddToCaseModal
        email={email}
        isOpen={isCaseModalOpen}
        onClose={() => setIsCaseModalOpen(false)}
      />

      {/* Subject Line */}
      <div>
        <h1 className="text-lg sm:text-xl font-bold text-foreground font-sans tracking-tight break-words">
          {email.subject || '(No Subject)'}
        </h1>
      </div>

      {/* Primary Metadata Matrix */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3 p-3 rounded-control bg-surface-secondary/40 border border-border text-xs font-mono">
        {/* Sender */}
        <div className="flex items-start space-x-2 min-w-0">
          <User className="w-3.5 h-3.5 text-primary shrink-0 mt-0.5" />
          <div className="min-w-0 flex-1">
            <span className="text-[10px] text-foreground-subtle uppercase tracking-wider block">From</span>
            <p className="text-foreground truncate mt-0.5" title={email.from}>
              {email.from || 'Not available'}
            </p>
          </div>
        </div>

        {/* Recipient */}
        <div className="flex items-start space-x-2 min-w-0">
          <Mail className="w-3.5 h-3.5 text-info shrink-0 mt-0.5" />
          <div className="min-w-0 flex-1">
            <span className="text-[10px] text-foreground-subtle uppercase tracking-wider block">To</span>
            <p className="text-foreground truncate mt-0.5" title={toDisplay}>
              {toDisplay || 'Not available'}
            </p>
          </div>
        </div>

        {/* Date */}
        <div className="flex items-start space-x-2 min-w-0">
          <Calendar className="w-3.5 h-3.5 text-foreground-muted shrink-0 mt-0.5" />
          <div className="min-w-0 flex-1">
            <span className="text-[10px] text-foreground-subtle uppercase tracking-wider block">Received Date</span>
            <p className="text-foreground truncate mt-0.5">
              {email.date || 'Not available'}
            </p>
          </div>
        </div>
      </div>

      {/* Secondary Evidence Row: Message-ID, SHA-256, Reply-To */}
      <div className="flex flex-wrap items-center justify-between gap-2 pt-1 text-[11px] font-mono text-foreground-muted">
        <div className="flex flex-wrap items-center gap-3">
          {email.email_sha256 && (
            <div className="flex items-center space-x-1">
              <span className="text-foreground-subtle">SHA-256:</span>
              <span className="text-foreground font-mono">{email.email_sha256.slice(0, 16)}...</span>
              <CopyButton text={email.email_sha256} label="" className="p-0.5 hover:text-primary" />
            </div>
          )}

          {email.reply_to && email.reply_to !== email.from && (
            <div className="flex items-center space-x-1">
              <CornerDownLeft className="w-3 h-3 text-warning" />
              <span className="text-foreground-subtle">Reply-To mismatch:</span>
              <span className="text-warning truncate max-w-xs">{email.reply_to}</span>
            </div>
          )}
        </div>

        {email.message_id && (
          <div className="flex items-center space-x-1 max-w-md truncate">
            <Hash className="w-3 h-3 text-foreground-subtle shrink-0" />
            <span className="text-foreground-subtle shrink-0">ID:</span>
            <span className="truncate">{email.message_id}</span>
            <CopyButton text={email.message_id} label="" className="p-0.5 hover:text-primary" />
          </div>
        )}
      </div>
    </div>
  );
};
