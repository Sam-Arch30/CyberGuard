import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ArrowLeft, Shield, Mail, Calendar, User, CornerDownLeft, Repeat, Hash, Briefcase, FileText, Loader2, CheckCircle2 } from 'lucide-react';
import type { EmailAnalysis } from '../../types/forensic';
import { CopyButton } from './CopyButton';
import { AddToCaseModal } from '../case/AddToCaseModal';
import { apiUrl } from '../../utils/apiClient';

interface EmailSummaryHeaderProps {
  email: EmailAnalysis;
}

export const EmailSummaryHeader: React.FC<EmailSummaryHeaderProps> = ({ email }) => {
  const navigate = useNavigate();
  const [isCaseModalOpen, setIsCaseModalOpen] = useState(false);
  const [isGeneratingReport, setIsGeneratingReport] = useState(false);
  const [reportSuccess, setReportSuccess] = useState(false);

  const handleGenerateReport = async () => {
    setIsGeneratingReport(true);
    try {
      const res = await fetch(apiUrl('/api/reports/generate'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          analysis: email,
          analyst_name: 'SOC Lead Analyst'
        })
      });

      if (!res.ok) {
        throw new Error(`Report generation failed (${res.status})`);
      }

      const blob = await res.blob();
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

  return (
    <div className="bg-surface rounded-card border border-border p-6 shadow-sm space-y-6">
      {/* Action Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-border">
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center space-x-2">
            <Shield className="w-5 h-5 text-primary" />
            <span className="text-xs font-mono font-bold tracking-widest text-primary uppercase">
              Forensic Evidence Analysis
            </span>
          </div>

          {email.threat_score && (
            <div className={`px-2.5 py-1 rounded-full border text-xs font-mono font-semibold flex items-center space-x-1.5 ${
              email.threat_score.score >= 80 ? 'bg-danger/10 border-danger/30 text-danger' :
              email.threat_score.score >= 60 ? 'bg-warning/15 border-warning/30 text-warning' :
              email.threat_score.score >= 30 ? 'bg-warning/10 border-warning/20 text-warning' :
              'bg-success/10 border-success/30 text-success'
            }`}>
              <span className={`w-2 h-2 rounded-full ${
                email.threat_score.score >= 80 ? 'bg-danger' :
                email.threat_score.score >= 60 ? 'bg-warning' :
                email.threat_score.score >= 30 ? 'bg-warning' :
                'bg-success'
              }`} />
              <span>Threat Score: {email.threat_score.score}/100</span>
              <span className="opacity-80 uppercase text-[10px]">({email.threat_score.severity})</span>
            </div>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          <button
            id="generate-forensic-report-btn"
            type="button"
            onClick={handleGenerateReport}
            disabled={isGeneratingReport}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-control bg-surface-secondary hover:bg-surface border border-border text-foreground font-mono text-xs font-semibold transition-all btn-press disabled:opacity-50 cursor-pointer"
            title="Generate and download official PDF forensic evidence dossier"
          >
            {isGeneratingReport ? (
              <>
                <Loader2 className="w-3.5 h-3.5 animate-spin text-primary" />
                <span>Generating PDF...</span>
              </>
            ) : reportSuccess ? (
              <>
                <CheckCircle2 className="w-3.5 h-3.5 text-success" />
                <span>Report Downloaded</span>
              </>
            ) : (
              <>
                <FileText className="w-3.5 h-3.5 text-primary" />
                <span>Forensic Report</span>
              </>
            )}
          </button>
          <button
            id="add-to-case-button"
            type="button"
            onClick={() => setIsCaseModalOpen(true)}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-control bg-surface hover:bg-surface-secondary border border-border text-foreground font-mono text-xs font-semibold transition-all btn-press cursor-pointer"
          >
            <Briefcase className="w-3.5 h-3.5 text-primary" />
            <span>Add to Case</span>
          </button>
          {email.message_id && (
            <CopyButton
              text={email.message_id}
              label="Copy Message ID"
              className="px-3 py-1.5 bg-surface-secondary border border-border text-foreground hover:bg-surface rounded-control"
            />
          )}
          <button
            type="button"
            onClick={() => navigate('/analyze')}
            className="flex items-center space-x-2 px-3.5 py-1.5 rounded-control bg-primary hover:bg-primary-hover text-primary-foreground font-mono text-xs font-semibold transition-all btn-press cursor-pointer"
          >
            <ArrowLeft className="w-4 h-4" />
            <span>Analyze Another</span>
          </button>
        </div>
      </div>

      <AddToCaseModal
        email={email}
        isOpen={isCaseModalOpen}
        onClose={() => setIsCaseModalOpen(false)}
      />

      {/* Main Header Info */}
      <div className="space-y-4">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold text-foreground font-sans tracking-tight break-words">
            {email.subject || 'Not available'}
          </h1>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 bg-surface-secondary/50 p-4 rounded-control border border-border">
          {/* From */}
          <div className="flex items-start space-x-3 min-w-0">
            <User className="w-4 h-4 text-primary mt-0.5 shrink-0" />
            <div className="min-w-0 flex-1">
              <span className="text-[11px] font-mono font-semibold text-foreground-subtle uppercase tracking-wider block">
                From
              </span>
              <p className="text-xs font-mono text-foreground break-all mt-0.5">
                {email.from || 'Not available'}
              </p>
            </div>
          </div>

          {/* To */}
          <div className="flex items-start space-x-3 min-w-0">
            <Mail className="w-4 h-4 text-info mt-0.5 shrink-0" />
            <div className="min-w-0 flex-1">
              <span className="text-[11px] font-mono font-semibold text-foreground-subtle uppercase tracking-wider block">
                To
              </span>
              <p className="text-xs font-mono text-foreground break-all mt-0.5">
                {toDisplay || 'Not available'}
              </p>
            </div>
          </div>

          {/* Date */}
          <div className="flex items-start space-x-3 min-w-0">
            <Calendar className="w-4 h-4 text-foreground-muted mt-0.5 shrink-0" />
            <div className="min-w-0 flex-1">
              <span className="text-[11px] font-mono font-semibold text-foreground-subtle uppercase tracking-wider block">
                Date
              </span>
              <p className="text-xs font-mono text-foreground break-all mt-0.5">
                {email.date || 'Not available'}
              </p>
            </div>
          </div>
        </div>

        {/* Smaller Metadata */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-2 text-xs font-mono border-t border-border">
          <div className="flex flex-col">
            <span className="text-foreground-subtle text-[11px] flex items-center space-x-1">
              <CornerDownLeft className="w-3 h-3 text-primary" />
              <span>Reply-To:</span>
            </span>
            <span className="text-foreground break-all mt-0.5 font-medium">
              {email.reply_to || (email.from ? `None (defaults to From)` : 'Not available')}
            </span>
          </div>

          <div className="flex flex-col">
            <span className="text-foreground-subtle text-[11px] flex items-center space-x-1">
              <Repeat className="w-3 h-3 text-primary" />
              <span>Return-Path:</span>
            </span>
            <span className="text-foreground break-all mt-0.5 font-medium">
              {email.return_path || 'Not available'}
            </span>
          </div>

          <div className="flex flex-col">
            <span className="text-foreground-subtle text-[11px] flex items-center space-x-1">
              <Hash className="w-3 h-3 text-primary" />
              <span>Message-ID:</span>
            </span>
            <span className="text-foreground break-all mt-0.5 font-medium">
              {email.message_id || 'Not available'}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};
