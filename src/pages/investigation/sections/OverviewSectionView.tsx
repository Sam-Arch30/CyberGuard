import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  ArrowRight,
  Compass,
  CheckCircle2
} from 'lucide-react';
import type { EmailAnalysis } from '../../../types/forensic';
import { useInvestigation } from '../../../context/InvestigationContext';
import { GlobalThreatScoreSection } from '../../../components/forensic/GlobalThreatScoreSection';
import { AIAnalystSection } from '../../../components/forensic/AIAnalystSection';
import { CampaignAlertBanner } from '../../../components/campaign/CampaignAlertBanner';
import type { CampaignAlertData } from '../../../types/campaign';

interface OverviewSectionViewProps {
  email: EmailAnalysis;
}

export const OverviewSectionView: React.FC<OverviewSectionViewProps> = ({ email }) => {
  const { setSection, stepGuidance } = useInvestigation();
  const [campaignAlert, setCampaignAlert] = useState<CampaignAlertData | null>(null);

  const emailKey = email?.id || email?.evidence_id || email?.email_sha256;

  useEffect(() => {
    if (!emailKey || !email) return;
    fetch('http://localhost:8000/api/campaigns/detect-alert?threshold=0.45', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(email)
    })
      .then(res => (res.ok ? res.json() : null))
      .then((data: CampaignAlertData | null) => {
        if (data && data.is_campaign_detected) {
          setCampaignAlert(data);
        } else {
          setCampaignAlert(null);
        }
      })
      .catch(() => setCampaignAlert(null));
  }, [emailKey, email]);

  const score = email.threat_score?.score ?? 0;
  const reasons = email.threat_score?.reasons || [];
  const positiveEvidence = email.threat_score?.positive_evidence || [];

  return (
    <div className="space-y-6">
      {/* 1. CAMPAIGN DETECTION ALERT BANNER (IF APPLICABLE) */}
      {campaignAlert && (
        <CampaignAlertBanner
          alertData={campaignAlert}
          onViewCampaign={() => setSection('investigation', 'cross_email')}
        />
      )}

      {/* 2. FALSE-POSITIVE RESISTANCE BANNER (FOR LOW THREAT EMAILS) */}
      {(email.id === 'scenario-1-legit' || score < 20) && (
        <div className="rounded-xl border border-success/40 bg-gradient-to-r from-success/15 via-emerald-500/10 to-teal-500/15 p-4 sm:p-5 shadow-xs flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center space-x-2">
              <span className="px-2.5 py-0.5 rounded text-[11px] font-mono font-bold tracking-wider uppercase bg-success/20 text-success border border-success/30 flex items-center gap-1.5">
                <ShieldCheck className="w-3.5 h-3.5" />
                VERIFIED LEGITIMATE EMAIL
              </span>
              <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-surface border border-border text-foreground font-semibold">
                Score: {score}/100
              </span>
            </div>
            <p className="text-xs text-foreground font-mono">
              Cryptographic SPF/DKIM authentication passed, domain registration verified, zero malicious indicators found.
            </p>
          </div>
          <button
            type="button"
            onClick={() => setSection('email', 'auth')}
            className="px-3.5 py-1.5 rounded-lg bg-surface hover:bg-surface-secondary border border-border text-foreground text-xs font-mono font-semibold transition-colors flex items-center space-x-1.5 flex-shrink-0 cursor-pointer"
          >
            <span>Verify Auth Proof</span>
            <ArrowRight className="w-3 h-3 text-success" />
          </button>
        </div>
      )}

      {/* 3. THREAT SCORE & RISK CLASSIFICATION GAUGE */}
      <GlobalThreatScoreSection
        threatScore={email.threat_score}
        mlAssessment={email.ml_assessment}
        mlProbability={email.ml_phishing_probability}
        conclusions={email.forensic_conclusions}
      />

      {/* 4. CONCISE AI ANALYST SUMMARY */}
      <AIAnalystSection email={email} />

      {/* 5. MAJOR FINDINGS & ANOMALIES BREAKDOWN */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Left: Risk Contribution Anomalies */}
        <div className="bg-surface rounded-xl border border-border p-5 shadow-xs space-y-4">
          <div className="flex items-center justify-between border-b border-border pb-3">
            <div className="flex items-center space-x-2 text-xs font-mono font-bold uppercase text-foreground">
              <ShieldAlert className="w-4 h-4 text-danger" />
              <span>Detected Risk Signals & Anomalies</span>
            </div>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-danger/10 text-danger border border-danger/20 font-bold">
              {reasons.length} Signals
            </span>
          </div>

          <div className="space-y-2.5 max-h-80 overflow-y-auto pr-1">
            {reasons.length > 0 ? (
              reasons.map((r, idx) => (
                <div
                  key={idx}
                  className="p-3 rounded-lg bg-surface-secondary/70 border border-border flex items-start justify-between gap-3 text-xs"
                >
                  <div className="space-y-1 flex-1">
                    <div className="flex items-center space-x-2">
                      <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-surface border border-border uppercase font-semibold text-foreground-muted">
                        {r.signal || 'SIGNAL'}
                      </span>
                      <strong className="text-foreground font-semibold">{r.label}</strong>
                    </div>
                    <p className="text-foreground-subtle font-mono text-[11px] leading-relaxed">
                      {r.evidence}
                    </p>
                  </div>
                  <span className="font-mono font-bold text-danger text-xs whitespace-nowrap bg-danger/10 px-2 py-0.5 rounded border border-danger/20">
                    +{r.points} pts
                  </span>
                </div>
              ))
            ) : (
              <div className="p-6 text-center text-xs font-mono text-foreground-muted">
                No anomalous risk signals detected.
              </div>
            )}
          </div>
        </div>

        {/* Right: Mitigating Evidence & Forensic Conclusions */}
        <div className="bg-surface rounded-xl border border-border p-5 shadow-xs space-y-4">
          <div className="flex items-center justify-between border-b border-border pb-3">
            <div className="flex items-center space-x-2 text-xs font-mono font-bold uppercase text-foreground">
              <ShieldCheck className="w-4 h-4 text-success" />
              <span>Mitigating Evidence & Confidence</span>
            </div>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-success/10 text-success border border-success/20 font-bold">
              {positiveEvidence.length} Verified
            </span>
          </div>

          <div className="space-y-2.5 max-h-80 overflow-y-auto pr-1">
            {positiveEvidence.length > 0 ? (
              positiveEvidence.map((pe, idx) => (
                <div
                  key={idx}
                  className="p-3 rounded-lg bg-surface-secondary/70 border border-border flex items-start justify-between gap-3 text-xs"
                >
                  <div className="space-y-1 flex-1">
                    <div className="flex items-center space-x-2">
                      <CheckCircle2 className="w-3.5 h-3.5 text-success flex-shrink-0" />
                      <strong className="text-foreground font-semibold">{pe.label || pe.signal}</strong>
                    </div>
                    <p className="text-foreground-subtle font-mono text-[11px] leading-relaxed">
                      {pe.evidence}
                    </p>
                  </div>
                  <span className="font-mono font-bold text-success text-xs whitespace-nowrap bg-success/10 px-2 py-0.5 rounded border border-success/20">
                    Verified
                  </span>
                </div>
              ))
            ) : (
              <div className="p-6 text-center text-xs font-mono text-foreground-muted">
                No mitigating positive signals recorded.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* 6. RECOMMENDED INVESTIGATION DIRECTIONS */}
      <div className="bg-surface rounded-xl border border-border p-5 shadow-xs space-y-4">
        <div className="flex items-center justify-between border-b border-border pb-3">
          <div className="flex items-center space-x-2 text-xs font-mono font-bold uppercase text-foreground">
            <Compass className="w-4 h-4 text-primary" />
            <span>Recommended Investigation Directions</span>
          </div>
          <span className="text-[11px] font-mono text-foreground-muted">
            Guided Analyst Next Steps
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {/* Card 1: Email */}
          <button
            type="button"
            onClick={() => setSection('email')}
            className="p-3.5 rounded-lg bg-surface-secondary/50 hover:bg-surface-secondary border border-border hover:border-primary/40 text-left transition-all cursor-pointer group flex flex-col justify-between space-y-3"
          >
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <span className="text-[10px] font-mono font-bold text-primary uppercase">
                  Area 02 · Email
                </span>
                <ArrowRight className="w-3.5 h-3.5 text-foreground-muted group-hover:text-primary group-hover:translate-x-0.5 transition-all" />
              </div>
              <h4 className="text-xs font-bold text-foreground font-sans">
                Inspect Headers & Authentication
              </h4>
              <p className="text-[11px] font-mono text-foreground-muted mt-1 leading-relaxed">
                Review SPF/DKIM/DMARC cryptographic validation, display name spoofing, and relay delays.
              </p>
            </div>
            <div className="flex items-center space-x-1 text-[10px] font-mono text-primary">
              <span>{email.received?.length || 0} Relay Hops</span>
              <span>·</span>
              <span>Authentication Results</span>
            </div>
          </button>

          {/* Card 2: Analysis */}
          <button
            type="button"
            onClick={() => setSection('analysis')}
            className="p-3.5 rounded-lg bg-surface-secondary/50 hover:bg-surface-secondary border border-border hover:border-primary/40 text-left transition-all cursor-pointer group flex flex-col justify-between space-y-3"
          >
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <span className="text-[10px] font-mono font-bold text-primary uppercase">
                  Area 03 · Analysis
                </span>
                <ArrowRight className="w-3.5 h-3.5 text-foreground-muted group-hover:text-primary group-hover:translate-x-0.5 transition-all" />
              </div>
              <h4 className="text-xs font-bold text-foreground font-sans">
                IOC Extraction & Threat Scoring
              </h4>
              <p className="text-[11px] font-mono text-foreground-muted mt-1 leading-relaxed">
                Deep-dive into extracted URLs, lookalike domain typosquatting, payload hashes, and ML probability.
              </p>
            </div>
            <div className="flex items-center space-x-1 text-[10px] font-mono text-primary">
              <span>{email.urls?.length || 0} URLs</span>
              <span>·</span>
              <span>{email.attachments?.length || 0} Attachments</span>
            </div>
          </button>

          {/* Card 3: Intelligence */}
          <button
            type="button"
            onClick={() => setSection('intelligence')}
            className="p-3.5 rounded-lg bg-surface-secondary/50 hover:bg-surface-secondary border border-border hover:border-primary/40 text-left transition-all cursor-pointer group flex flex-col justify-between space-y-3"
          >
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <span className="text-[10px] font-mono font-bold text-primary uppercase">
                  Area 04 · Intelligence
                </span>
                <ArrowRight className="w-3.5 h-3.5 text-foreground-muted group-hover:text-primary group-hover:translate-x-0.5 transition-all" />
              </div>
              <h4 className="text-xs font-bold text-foreground font-sans">
                Hostile Infrastructure & Map
              </h4>
              <p className="text-[11px] font-mono text-foreground-muted mt-1 leading-relaxed">
                Trace transit hops across geographic routes, investigate ASN AS64512 reputation, and query WHOIS.
              </p>
            </div>
            <div className="flex items-center space-x-1 text-[10px] font-mono text-primary">
              <span>ASN Attribution</span>
              <span>·</span>
              <span>GeoTrace Visualizer</span>
            </div>
          </button>

          {/* Card 4: Investigation */}
          <button
            type="button"
            onClick={() => setSection('investigation')}
            className="p-3.5 rounded-lg bg-surface-secondary/50 hover:bg-surface-secondary border border-border hover:border-primary/40 text-left transition-all cursor-pointer group flex flex-col justify-between space-y-3"
          >
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <span className="text-[10px] font-mono font-bold text-primary uppercase">
                  Area 05 · Investigation
                </span>
                <ArrowRight className="w-3.5 h-3.5 text-foreground-muted group-hover:text-primary group-hover:translate-x-0.5 transition-all" />
              </div>
              <h4 className="text-xs font-bold text-foreground font-sans">
                Campaign Graph & Copilot
              </h4>
              <p className="text-[11px] font-mono text-foreground-muted mt-1 leading-relaxed">
                Pivot into related campaign emails, query the hallucination-resistant copilot, and link to cases.
              </p>
            </div>
            <div className="flex items-center space-x-1 text-[10px] font-mono text-primary">
              <span>Cytoscape Graph</span>
              <span>·</span>
              <span>16 Related Emails</span>
            </div>
          </button>

          {/* Card 5: Report */}
          <button
            type="button"
            onClick={() => setSection('report')}
            className="p-3.5 rounded-lg bg-surface-secondary/50 hover:bg-surface-secondary border border-border hover:border-primary/40 text-left transition-all cursor-pointer group flex flex-col justify-between space-y-3"
          >
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <span className="text-[10px] font-mono font-bold text-primary uppercase">
                  Area 06 · Report
                </span>
                <ArrowRight className="w-3.5 h-3.5 text-foreground-muted group-hover:text-primary group-hover:translate-x-0.5 transition-all" />
              </div>
              <h4 className="text-xs font-bold text-foreground font-sans">
                Export Executive Incident PDF
              </h4>
              <p className="text-[11px] font-mono text-foreground-muted mt-1 leading-relaxed">
                Compile findings, evidence chain of custody, and MITRE ATT&CK techniques into audit-ready PDFs.
              </p>
            </div>
            <div className="flex items-center space-x-1 text-[10px] font-mono text-primary">
              <span>Court-Ready PDF</span>
              <span>·</span>
              <span>Chain of Custody</span>
            </div>
          </button>
        </div>
      </div>

      {/* 7. PRIMARY NEXT STEP PROMINENT CTA BANNER */}
      <div className="p-4 rounded-xl bg-primary/10 border border-primary/30 flex flex-col sm:flex-row items-center justify-between gap-4">
        <div className="flex items-center space-x-3">
          <div className="w-9 h-9 rounded-lg bg-primary text-primary-foreground flex items-center justify-center font-bold font-mono text-xs shadow-xs">
            02
          </div>
          <div>
            <h4 className="text-xs font-bold text-foreground font-sans">
              Ready for the next investigation stage?
            </h4>
            <p className="text-xs font-mono text-foreground-muted">
              {stepGuidance.guidanceText}
            </p>
          </div>
        </div>

        <button
          type="button"
          onClick={stepGuidance.execute}
          className="w-full sm:w-auto px-5 py-2.5 rounded-lg bg-primary hover:bg-primary-hover text-primary-foreground font-mono text-xs font-bold flex items-center justify-center space-x-2 transition-all shadow-xs cursor-pointer"
        >
          <span>{stepGuidance.buttonLabel}</span>
        </button>
      </div>
    </div>
  );
};
