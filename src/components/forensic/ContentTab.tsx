import React, { useState } from 'react';
import type { EmailAnalysis } from '../../types/forensic';
import { CopyButton } from './CopyButton';
import { FileText, Code, ShieldAlert, Eye, BrainCircuit } from 'lucide-react';
import { useTheme } from '../../context/ThemeContext';
import { StatusRow, DetailDrawer, MetadataRow, ExpandableSection } from '../common/progressive';

interface ContentTabProps {
  email: EmailAnalysis;
}

export const ContentTab: React.FC<ContentTabProps> = ({ email }) => {
  const { isDark } = useTheme();
  const [activeSubTab, setActiveSubTab] = useState<'preview' | 'source'>('preview');
  const [rawMlModalOpen, setRawMlModalOpen] = useState(false);

  const plainText = email.plain_text_body || 'No plain text content detected.';
  const htmlBody = email.html_body;

  // Resolve ML phishing probability
  const resolvedProbability = typeof email.ml_phishing_probability === 'number'
    ? email.ml_phishing_probability
    : (email.ml_assessment && typeof email.ml_assessment.probability === 'number')
      ? email.ml_assessment.probability
      : null;

  // Sanitize HTML body for sandboxed preview
  const createSafeSandboxDoc = (html: string, isDarkMode: boolean): string => {
    const sanitized = html
      .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
      .replace(/<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi, '')
      .replace(/<object\b[^<]*(?:(?!<\/object>)<[^<]*)*<\/object>/gi, '')
      .replace(/<embed\b[^>]*>/gi, '')
      .replace(/<applet\b[^<]*(?:(?!<\/applet>)<[^<]*)*<\/applet>/gi, '')
      .replace(/<form\b[^<]*(?:(?!<\/form>)<[^<]*)*<\/form>/gi, '')
      .replace(/<base\b[^>]*>/gi, '')
      .replace(/<meta\b[^>]*>/gi, '')
      .replace(/<\/?(?:script|iframe|object|embed|applet|form|base|meta)\b[^>]*>/gi, '')
      .replace(/\bon\w+\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)/gi, '')
      .replace(/(?:href|src|action)\s*=\s*["']?\s*(?:javascript|vbscript):[^"'>]+["']?/gi, 'href="#"')
      .replace(/<img\b([^>]*?)\bsrc\s*=\s*["'](https?:\/\/[^"']+)["']([^>]*?)>/gi, '<div class="blocked-image">[Remote Image Blocked: $2]</div>');

    return `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src 'none' data:; style-src 'unsafe-inline'; form-action 'none';">
<style>
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    color: ${isDarkMode ? '#e2e8f0' : '#1e293b'};
    background-color: ${isDarkMode ? '#0b0f17' : '#ffffff'};
    padding: 16px;
    line-height: 1.6;
    word-break: break-word;
  }
  a {
    color: ${isDarkMode ? '#38bdf8' : '#0284c7'} !important;
    text-decoration: underline !important;
    pointer-events: none !important;
    cursor: not-allowed !important;
  }
  .blocked-image {
    display: inline-block;
    padding: 4px 8px;
    margin: 4px 0;
    border: 1px dashed ${isDarkMode ? '#475569' : '#94a3b8'};
    border-radius: 4px;
    background: ${isDarkMode ? 'rgba(30, 41, 59, 0.5)' : 'rgba(241, 245, 249, 0.8)'};
    color: ${isDarkMode ? '#94a3b8' : '#64748b'};
    font-size: 11px;
    font-family: monospace;
  }
  img {
    display: none !important;
  }
</style>
</head>
<body>
${sanitized}
</body>
</html>`;
  };

  const statusState = resolvedProbability !== null
    ? resolvedProbability >= 0.70
      ? 'CRITICAL'
      : resolvedProbability >= 0.40
      ? 'WARN'
      : 'PASS'
    : 'NONE';

  const statusLabel = resolvedProbability !== null
    ? `${Math.round(resolvedProbability * 100)}% PHISH PROBABILITY`
    : 'UNAVAILABLE';

  return (
    <div className="space-y-6">
      {/* Progressive Content ML Assessment */}
      <ExpandableSection
        title="Content Natural Language Processing (NLP) Assessment"
        subtitle="Lexical TF-IDF feature analysis and logistic regression classification"
        icon={BrainCircuit}
        defaultExpanded={true}
        badge={
          resolvedProbability !== null ? (
            <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${
              resolvedProbability >= 0.50
                ? 'bg-danger-surface text-danger border-danger-border'
                : 'bg-success-surface text-success border-success-border'
            }`}>
              {email.ml_assessment?.classification || (resolvedProbability >= 0.50 ? 'phishing' : 'legitimate')}
            </span>
          ) : undefined
        }
      >
        {resolvedProbability !== null ? (
          <StatusRow
            title="Statistical Phishing Classifier"
            status={statusState}
            statusLabel={statusLabel}
            subtitle={`TF-IDF + Logistic Regression · Confidence: ${email.ml_assessment?.confidence || 'Standard'}`}
            defaultExpanded={false}
            onViewRaw={() => setRawMlModalOpen(true)}
            rawButtonLabel="View model weights & tokens"
          >
            <div className="space-y-3">
              {/* Visual Probability Bar */}
              <div className="space-y-1">
                <div className="flex items-center justify-between text-xs text-foreground-muted">
                  <span>Probability Distribution</span>
                  <span className="font-bold text-foreground">{Math.round(resolvedProbability * 100)}%</span>
                </div>
                <div className="w-full bg-surface-secondary rounded-full h-2 overflow-hidden border border-border">
                  <div
                    className={`h-full transition-all duration-500 ${
                      resolvedProbability >= 0.70
                        ? 'bg-danger'
                        : resolvedProbability >= 0.40
                        ? 'bg-warning'
                        : 'bg-success'
                    }`}
                    style={{ width: `${Math.max(resolvedProbability * 100, 2)}%` }}
                  />
                </div>
              </div>

              {/* Top Features */}
              {email.ml_assessment?.top_features && email.ml_assessment.top_features.length > 0 && (
                <div>
                  <span className="text-[10px] uppercase font-bold text-foreground-muted block mb-1">
                    Top Contributing Lexical Features
                  </span>
                  <div className="flex flex-wrap gap-1.5">
                    {email.ml_assessment.top_features.map((feat, idx) => (
                      <span
                        key={idx}
                        className="px-2 py-0.5 rounded text-[10px] font-mono bg-surface border border-border text-foreground font-semibold"
                      >
                        {feat}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-mono">
                <MetadataRow label="Model Architecture" value="TF-IDF N-grams + L2 Logistic Regression" />
                <MetadataRow label="Classification" value={email.ml_assessment?.classification || 'Phishing'} />
                <MetadataRow label="Confidence" value={email.ml_assessment?.confidence || 'High'} />
                <MetadataRow label="Signal Type" value="Auxiliary Lexical Signal (Unbounded from network heuristics)" />
              </div>
            </div>
          </StatusRow>
        ) : (
          <div className="p-3 rounded-lg bg-surface-secondary/40 border border-border text-xs font-mono text-foreground-muted">
            ML Content Assessment unavailable or email body empty. Forensic inspection remains fully functional.
          </div>
        )}
      </ExpandableSection>

      {/* Sub-Section 1: Plain Text Body */}
      <ExpandableSection
        title="Plain Text Message Body"
        subtitle="Normalized ASCII / UTF-8 representation of message text"
        icon={FileText}
        defaultExpanded={false}
        actions={
          email.plain_text_body ? (
            <CopyButton text={email.plain_text_body} label="Copy Plain Text" />
          ) : undefined
        }
      >
        <div className="p-4 rounded-xl bg-surface-secondary/50 border border-border font-mono text-xs text-foreground whitespace-pre-wrap leading-relaxed max-h-96 overflow-y-auto">
          {plainText}
        </div>
      </ExpandableSection>

      {/* Sub-Section 2: HTML Body */}
      <ExpandableSection
        title="HTML Body Content"
        subtitle="Sandboxed client-side render and literal HTML source"
        icon={Code}
        defaultExpanded={false}
        actions={
          <div className="flex items-center space-x-2">
            <div className="flex items-center bg-surface-secondary p-1 rounded-control border border-border text-xs font-mono">
              <button
                type="button"
                onClick={() => setActiveSubTab('preview')}
                className={`flex items-center space-x-1 px-3 py-1 rounded-control transition-colors cursor-pointer ${
                  activeSubTab === 'preview'
                    ? 'bg-primary text-primary-foreground font-semibold shadow-xs'
                    : 'text-foreground-muted hover:text-foreground'
                }`}
              >
                <Eye className="w-3.5 h-3.5" />
                <span>Preview</span>
              </button>
              <button
                type="button"
                onClick={() => setActiveSubTab('source')}
                className={`flex items-center space-x-1 px-3 py-1 rounded-control transition-colors cursor-pointer ${
                  activeSubTab === 'source'
                    ? 'bg-primary text-primary-foreground font-semibold shadow-xs'
                    : 'text-foreground-muted hover:text-foreground'
                }`}
              >
                <Code className="w-3.5 h-3.5" />
                <span>HTML Source</span>
              </button>
            </div>

            {htmlBody && <CopyButton text={htmlBody} label="Copy HTML" />}
          </div>
        }
      >
        {/* Security Warning Notice */}
        <div className="flex items-center space-x-2 p-2.5 rounded-lg bg-surface-secondary border border-border text-[11px] font-mono text-foreground-muted mb-3">
          <ShieldAlert className="w-4 h-4 text-warning shrink-0" />
          <span>
            Security Active: HTML scripts, event handlers, and automatic remote image fetches are strictly isolated.
          </span>
        </div>

        {!htmlBody ? (
          <p className="text-xs font-mono text-foreground-subtle italic p-3">
            No HTML body content present in this email.
          </p>
        ) : activeSubTab === 'preview' ? (
          <div className="rounded-xl border border-border overflow-hidden bg-surface-secondary/70 min-h-[250px]">
            <iframe
              title="Safe Email HTML Preview"
              srcDoc={createSafeSandboxDoc(htmlBody, isDark)}
              sandbox=""
              className="w-full h-80 border-0"
            />
          </div>
        ) : (
          <pre className="p-4 rounded-xl bg-surface-secondary/70 border border-border font-mono text-xs text-foreground whitespace-pre-wrap break-all leading-relaxed max-h-96 overflow-y-auto">
            {htmlBody}
          </pre>
        )}
      </ExpandableSection>

      {/* Level 3 Raw Drawer */}
      {rawMlModalOpen && (
        <DetailDrawer
          isOpen={rawMlModalOpen}
          onClose={() => setRawMlModalOpen(false)}
          title="Content NLP Model Inference Dossier"
          subtitle="Model hyperparameters, token dictionary weights, and raw inference payload"
          data={{
            ml_phishing_probability: resolvedProbability,
            ml_assessment: email.ml_assessment,
            token_count: plainText.split(/\s+/).length,
            character_count: plainText.length
          }}
          format="json"
        />
      )}
    </div>
  );
};
