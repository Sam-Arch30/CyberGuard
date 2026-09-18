import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import type { EmailAnalysis } from '../types/forensic';
import { getAnalysisResult, saveAnalysisResult, getAllAvailableAnalyses } from '../utils/forensicStore';
import { resolveEmailIndicators, resolveAttribution } from '../utils/indicatorHelper';
import { resolveConfidenceConclusions } from '../utils/confidenceResolver';

export type InvestigationSection =
  | 'overview'
  | 'email'
  | 'analysis'
  | 'intelligence'
  | 'investigation'
  | 'report';

export interface SectionMetadata {
  id: InvestigationSection;
  number: string;
  label: string;
  shortLabel: string;
  description: string;
  defaultSubTab: string;
}

export const INVESTIGATION_SECTIONS: SectionMetadata[] = [
  {
    id: 'overview',
    number: '01',
    label: 'Overview',
    shortLabel: 'Overview',
    description: 'Threat score, risk rating, major findings & AI summary',
    defaultSubTab: 'executive'
  },
  {
    id: 'email',
    number: '02',
    label: 'Email',
    shortLabel: 'Email',
    description: 'Original content, metadata, headers, authentication & relay',
    defaultSubTab: 'body'
  },
  {
    id: 'analysis',
    number: '03',
    label: 'Analysis',
    shortLabel: 'Analysis',
    description: 'IOC extraction, URL analysis, lookalike detection & NLP scoring',
    defaultSubTab: 'scoring'
  },
  {
    id: 'intelligence',
    number: '04',
    label: 'Intelligence',
    shortLabel: 'Intelligence',
    description: 'IP & domain intelligence, WHOIS, DNS, map & infrastructure',
    defaultSubTab: 'ip_intel'
  },
  {
    id: 'investigation',
    number: '05',
    label: 'Investigation',
    shortLabel: 'Investigation',
    description: 'Investigation graph, campaign correlation, related emails & copilot',
    defaultSubTab: 'graph'
  },
  {
    id: 'report',
    number: '06',
    label: 'Report',
    shortLabel: 'Report',
    description: 'Findings summary, evidence dossier, report generation & PDF export',
    defaultSubTab: 'generate'
  }
];

export interface StepGuidance {
  nextSection: InvestigationSection;
  nextSectionLabel: string;
  buttonLabel: string;
  guidanceText: string;
  execute: () => void;
}

interface InvestigationContextType {
  activeEmailId: string;
  activeEmail: EmailAnalysis | null;
  loading: boolean;
  error: string | null;
  activeSection: InvestigationSection;
  activeSubTab: string;
  subTabs: Record<InvestigationSection, string>;
  availableAnalyses: EmailAnalysis[];
  focusedGraphNodeId: string | null;
  refreshAnalyses: () => void;
  setActiveEmailId: (id: string) => void;
  setSection: (section: InvestigationSection, subTab?: string) => void;
  setSubTab: (subTab: string) => void;
  focusGraphNode: (nodeId: string) => void;
  stepGuidance: StepGuidance;
  reloadActiveEmail: () => Promise<void>;
}

const InvestigationContext = createContext<InvestigationContextType | null>(null);

const DEFAULT_EMAIL_ID = 'scenario-3-campaign';
const LAST_INVESTIGATED_KEY = 'mailtrace_active_investigation_id';

export const InvestigationProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const navigate = useNavigate();
  const location = useLocation();

  // Determine active email ID
  const [activeEmailId, setActiveEmailIdState] = useState<string>(() => {
    // Check URL first
    const pathParts = location.pathname.split('/').filter(Boolean);
    if (pathParts[0] === 'investigate' && pathParts[1] && !INVESTIGATION_SECTIONS.some(s => s.id === pathParts[1])) {
      return pathParts[1];
    }
    if (pathParts[0] === 'analysis' && pathParts[1]) {
      return pathParts[1];
    }
    // Check localStorage
    const saved = localStorage.getItem(LAST_INVESTIGATED_KEY);
    if (saved) return saved;
    return DEFAULT_EMAIL_ID;
  });

  const [activeEmail, setActiveEmail] = useState<EmailAnalysis | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [availableAnalyses, setAvailableAnalyses] = useState<EmailAnalysis[]>([]);
  const [focusedGraphNodeId, setFocusedGraphNodeId] = useState<string | null>(null);

  // Sub-tabs state per section
  const [subTabs, setSubTabs] = useState<Record<InvestigationSection, string>>({
    overview: 'executive',
    email: 'body',
    analysis: 'scoring',
    intelligence: 'ip_intel',
    investigation: 'graph',
    report: 'generate'
  });

  // Determine current active section from URL
  const determineActiveSection = useCallback((): InvestigationSection => {
    const path = location.pathname;
    if (path.includes('/investigate/')) {
      const parts = path.split('/').filter(Boolean);
      const lastPart = parts[parts.length - 1];
      const match = INVESTIGATION_SECTIONS.find(s => s.id === lastPart);
      if (match) return match.id;
      // Maybe /investigate/:section
      if (parts[1] && INVESTIGATION_SECTIONS.some(s => s.id === parts[1])) {
        return parts[1] as InvestigationSection;
      }
    }
    // Check top-level shortcut routes
    for (const s of INVESTIGATION_SECTIONS) {
      if (path === `/${s.id}` || path.startsWith(`/${s.id}/`)) {
        return s.id;
      }
    }
    return 'overview';
  }, [location.pathname]);

  const activeSection = determineActiveSection();
  const activeSubTab = subTabs[activeSection] || INVESTIGATION_SECTIONS.find(s => s.id === activeSection)?.defaultSubTab || 'overview';

  // Load available analyses list
  const refreshAnalyses = useCallback(() => {
    const items = getAllAvailableAnalyses(true);
    setAvailableAnalyses(items);
  }, []);

  useEffect(() => {
    refreshAnalyses();
  }, [refreshAnalyses]);

  // Sync activeEmailId when URL parameter changes
  useEffect(() => {
    const pathParts = location.pathname.split('/').filter(Boolean);
    if (pathParts[0] === 'investigate') {
      if (pathParts[1] && !INVESTIGATION_SECTIONS.some(s => s.id === pathParts[1])) {
        if (pathParts[1] !== activeEmailId) {
          setActiveEmailIdState(pathParts[1]);
          localStorage.setItem(LAST_INVESTIGATED_KEY, pathParts[1]);
        }
      }
    } else if (pathParts[0] === 'analysis' && pathParts[1]) {
      if (pathParts[1] !== activeEmailId) {
        setActiveEmailIdState(pathParts[1]);
        localStorage.setItem(LAST_INVESTIGATED_KEY, pathParts[1]);
      }
    }
  }, [location.pathname, activeEmailId]);

  // Load and enrich active email
  const loadEmailData = useCallback(async (targetId: string) => {
    setLoading(true);
    setError(null);

    try {
      let resolved = getAnalysisResult(targetId);

      // If not in local/demo store, try backend API
      if (!resolved && targetId && targetId !== 'latest') {
        try {
          const res = await fetch(`/api/emails/${targetId}/analysis`);
          if (res.ok) {
            const apiData = await res.json();
            resolved = resolveEmailIndicators(apiData);
            saveAnalysisResult(targetId, resolved);
          }
        } catch {
          // Backend unreachable or not found
        }
      }

      // If still not found, fallback to default scenario
      if (!resolved) {
        resolved = getAnalysisResult(DEFAULT_EMAIL_ID);
      }

      if (!resolved) {
        setError(`Unable to locate email analysis for ID: ${targetId}`);
        setLoading(false);
        return;
      }

      // Ensure attribution and conclusions exist
      if (!resolved.attribution || !resolved.attribution.probable_origin_ip) {
        resolved.attribution = resolveAttribution(resolved);
      }
      if (!resolved.forensic_conclusions || resolved.forensic_conclusions.length === 0) {
        resolved.forensic_conclusions = resolveConfidenceConclusions(resolved);
      }

      setActiveEmail(resolved);
      setLoading(false);

      // Dynamic asynchronous enrichments in background:
      // 1. ML classification
      const hasML = resolved.ml_phishing_probability !== undefined &&
                    resolved.ml_phishing_probability !== null &&
                    Boolean(resolved.ml_assessment);
      if (!hasML) {
        const textToAnalyze = resolved.plain_text_body || (resolved.html_body ? resolved.html_body.replace(/<[^>]+>/g, ' ') : '');
        if (resolved.subject || textToAnalyze) {
          fetch('/api/emails/ml-classify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              subject: resolved.subject || '',
              body: textToAnalyze || ''
            })
          })
            .then(res => (res.ok ? res.json() : null))
            .then(mlData => {
              if (mlData && mlData.available) {
                setActiveEmail(prev => {
                  if (!prev) return prev;
                  const updated: EmailAnalysis = {
                    ...prev,
                    ml_phishing_probability: mlData.probability,
                    ml_assessment: mlData
                  };
                  saveAnalysisResult(targetId, updated);
                  return updated;
                });
              }
            })
            .catch(() => {});
        }
      }

      // 2. AI Analyst
      if (!resolved.ai_analyst) {
        fetch('/api/emails/ai-analyst', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(resolved)
        })
          .then(res => (res.ok ? res.json() : null))
          .then(aiData => {
            if (aiData) {
              setActiveEmail(prev => {
                if (!prev) return prev;
                const updated: EmailAnalysis = {
                  ...prev,
                  ai_analyst: aiData
                };
                saveAnalysisResult(targetId, updated);
                return updated;
              });
            }
          })
          .catch(() => {});
      }

      // 3. Investigation Graph
      if (!resolved.investigation_graph) {
        fetch('/api/emails/investigation-graph', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(resolved)
        })
          .then(res => (res.ok ? res.json() : null))
          .then(graphData => {
            if (graphData && graphData.nodes) {
              setActiveEmail(prev => {
                if (!prev) return prev;
                const updated: EmailAnalysis = {
                  ...prev,
                  investigation_graph: graphData
                };
                saveAnalysisResult(targetId, updated);
                return updated;
              });
            }
          })
          .catch(() => {});
      }

      // 4. Threat Score with audit metadata
      if (!resolved.threat_score?.scoring_version || !resolved.threat_score?.audit_metadata) {
        fetch('/api/emails/calculate-threat-score', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(resolved)
        })
          .then(res => (res.ok ? res.json() : null))
          .then(scoreData => {
            if (scoreData) {
              setActiveEmail(prev => {
                if (!prev) return prev;
                const updated: EmailAnalysis = {
                  ...prev,
                  threat_score: scoreData
                };
                saveAnalysisResult(targetId, updated);
                return updated;
              });
            }
          })
          .catch(() => {});
      }
    } catch (err: any) {
      console.error('Error loading investigation email:', err);
      setError(err?.message || 'Failed to load analysis record');
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadEmailData(activeEmailId);
  }, [activeEmailId, loadEmailData]);

  const setActiveEmailId = useCallback((newId: string) => {
    setActiveEmailIdState(newId);
    localStorage.setItem(LAST_INVESTIGATED_KEY, newId);
    navigate(`/investigate/${newId}/${activeSection}`);
  }, [navigate, activeSection]);

  const setSection = useCallback((section: InvestigationSection, subTab?: string) => {
    if (subTab) {
      setSubTabs(prev => ({ ...prev, [section]: subTab }));
    }
    navigate(`/investigate/${activeEmailId}/${section}`);
  }, [navigate, activeEmailId]);

  const setSubTab = useCallback((subTab: string) => {
    setSubTabs(prev => ({ ...prev, [activeSection]: subTab }));
  }, [activeSection]);

  const focusGraphNode = useCallback((nodeId: string) => {
    setFocusedGraphNodeId(nodeId);
    setSubTabs(prev => ({ ...prev, investigation: 'graph' }));
    navigate(`/investigate/${activeEmailId}/investigation`);
  }, [navigate, activeEmailId]);

  // Compute Next Step Guidance based on current section
  const getStepGuidance = (): StepGuidance => {
    switch (activeSection) {
      case 'overview':
        return {
          nextSection: 'email',
          nextSectionLabel: 'Email Forensics',
          buttonLabel: 'Next: Inspect Email & Headers →',
          guidanceText: 'Review original email content, SPF/DKIM/DMARC alignment, and transmission relay hops.',
          execute: () => setSection('email')
        };
      case 'email':
        return {
          nextSection: 'analysis',
          nextSectionLabel: 'Threat Analysis',
          buttonLabel: 'Next: Run Threat & IOC Analysis →',
          guidanceText: 'Examine extracted indicators of compromise, suspicious URLs, lookalikes, and NLP classification.',
          execute: () => setSection('analysis')
        };
      case 'analysis':
        return {
          nextSection: 'intelligence',
          nextSectionLabel: 'Threat Intelligence',
          buttonLabel: 'Next: Correlate IP & Domain Intel →',
          guidanceText: 'Trace originating IP telemetry, domain age, transit hops on the map, and AS64512 attribution.',
          execute: () => setSection('intelligence')
        };
      case 'intelligence':
        return {
          nextSection: 'investigation',
          nextSectionLabel: 'Investigation Workspace',
          buttonLabel: 'Next: Explore Graph & Campaigns →',
          guidanceText: 'Pivot into the multi-node investigation graph, campaign clusters, cross-email correlation, and AI copilot.',
          execute: () => setSection('investigation')
        };
      case 'investigation':
        return {
          nextSection: 'report',
          nextSectionLabel: 'Incident Report',
          buttonLabel: 'Next: Generate Incident Report →',
          guidanceText: 'Produce executive briefings, verify chain-of-custody hashes, and export audit-ready PDF dossiers.',
          execute: () => setSection('report')
        };
      case 'report':
      default:
        return {
          nextSection: 'overview',
          nextSectionLabel: 'Overview',
          buttonLabel: 'Return to Investigation Overview ↺',
          guidanceText: 'Review top-level telemetry, risk classification, and verify complete evidence audit integrity.',
          execute: () => setSection('overview')
        };
    }
  };

  const stepGuidance = getStepGuidance();

  return (
    <InvestigationContext.Provider
      value={{
        activeEmailId,
        activeEmail,
        loading,
        error,
        activeSection,
        activeSubTab,
        subTabs,
        availableAnalyses,
        focusedGraphNodeId,
        refreshAnalyses,
        setActiveEmailId,
        setSection,
        setSubTab,
        focusGraphNode,
        stepGuidance,
        reloadActiveEmail: () => loadEmailData(activeEmailId)
      }}
    >
      {children}
    </InvestigationContext.Provider>
  );
};

export const useInvestigation = (): InvestigationContextType => {
  const context = useContext(InvestigationContext);
  if (!context) {
    throw new Error('useInvestigation must be used within an InvestigationProvider');
  }
  return context;
};
