import React, { createContext, useContext, useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { resetDemoStore } from '../utils/forensicStore';

export interface TourStep {
  stepNumber: number;
  title: string;
  targetSection?: string;
  targetTab?: string;
  targetPath?: string;
  description: string;
  actionGuidance: string;
  nextButtonLabel: string;
}

export const TOUR_STEPS: TourStep[] = [
  {
    stepNumber: 1,
    title: 'Step 1: Analyze Suspicious Email',
    targetSection: 'overview',
    targetTab: 'executive',
    targetPath: '/investigate/scenario-3-campaign/overview',
    description: 'MailTraceAI dynamically parses RFC-822 headers, MIME structure, and body text without relying on external cloud APIs.',
    actionGuidance: 'Observe parsed headers, sender identity, and clean execution under local sandbox isolation.',
    nextButtonLabel: 'Next: View Threat Score →'
  },
  {
    stepNumber: 2,
    title: 'Step 2: Show Threat Score',
    targetSection: 'overview',
    targetTab: 'executive',
    targetPath: '/investigate/scenario-3-campaign/overview',
    description: 'Multi-factor threat scoring engine computes an audit-grounded score of 96/100 (CRITICAL Severity).',
    actionGuidance: 'Observe the Threat Score meter, risk level badge, and confidence rating (VERY HIGH).',
    nextButtonLabel: 'Next: Show "Why Flagged?" →'
  },
  {
    stepNumber: 3,
    title: 'Step 3: Show "Why Flagged?"',
    targetSection: 'overview',
    targetTab: 'executive',
    targetPath: '/investigate/scenario-3-campaign/overview',
    description: 'Full explainability breakdown shows exact risk contributions: wire fraud urgency (+25), disguised executable (+30), and lookalike C2 (+18).',
    actionGuidance: 'Review the explainable signal audit trail and positive/negative evidence contributions.',
    nextButtonLabel: 'Next: Show Auth & IOC Evidence →'
  },
  {
    stepNumber: 4,
    title: 'Step 4: Show Authentication & IOC Evidence',
    targetSection: 'email',
    targetTab: 'auth',
    targetPath: '/investigate/scenario-3-campaign/email',
    description: 'SPF, DKIM, and DMARC cryptographic validation failed. Extracted indicators include C2 URLs, IP addresses, and executable payload SHA-256.',
    actionGuidance: 'Inspect the cryptographic integrity results and extracted IOC indicators table.',
    nextButtonLabel: 'Next: Reconstruct Relay Path →'
  },
  {
    stepNumber: 5,
    title: 'Step 5: Reconstruct Relay Path',
    targetSection: 'email',
    targetTab: 'relay',
    targetPath: '/investigate/scenario-3-campaign/email',
    description: 'Hop-by-hop relay reconstruction computes transmission delays and flags untrusted adversary infrastructure (203.0.113.88).',
    actionGuidance: 'Examine transit hops, relay latency intervals, and originating IP attribution.',
    nextButtonLabel: 'Next: Show Infrastructure Attribution →'
  },
  {
    stepNumber: 6,
    title: 'Step 6: Show Infrastructure Attribution',
    targetSection: 'intelligence',
    targetTab: 'attribution',
    targetPath: '/investigate/scenario-3-campaign/intelligence',
    description: 'Adversary infrastructure attribution links the originating relay to ASN AS64512 (Threat Hosting Corp) and subnet 203.0.113.0/24.',
    actionGuidance: 'Review ASN telemetry, ISP reputation, and threat infrastructure correlation.',
    nextButtonLabel: 'Next: Reveal Related Emails →'
  },
  {
    stepNumber: 7,
    title: 'Step 7: Reveal Related Emails',
    targetSection: 'investigation',
    targetTab: 'cross_email',
    targetPath: '/investigate/scenario-3-campaign/investigation',
    description: 'Cross-Email Investigation Workspace reveals "RELATED ACTIVITY DETECTED: 16 potentially related emails, Campaign confidence: 89%".',
    actionGuidance: 'Inspect the sortable table of 16 related campaign emails and strongest relationship indicators.',
    nextButtonLabel: 'Next: Open Campaign Graph →'
  },
  {
    stepNumber: 8,
    title: 'Step 8: Open Campaign Graph',
    targetSection: 'investigation',
    targetTab: 'graph',
    targetPath: '/investigate/scenario-3-campaign/investigation',
    description: 'Force-directed investigation graph reveals the coordinated multi-email cluster around ASN AS64512 and payload hash.',
    actionGuidance: 'Explore interactive graph nodes connecting related emails, C2 domains, and SHA-256 binary payloads.',
    nextButtonLabel: 'Next: Ask Investigation Copilot →'
  },
  {
    stepNumber: 9,
    title: 'Step 9: Ask Investigation Copilot',
    targetSection: 'investigation',
    targetTab: 'copilot',
    targetPath: '/investigate/scenario-3-campaign/investigation',
    description: 'Consult the evidence-grounded copilot with the query: "Explain why these emails are believed to belong to the same campaign."',
    actionGuidance: 'Review hallucination-resistant copilot analysis quoting specific shared ASN, subnet, and payload hashes.',
    nextButtonLabel: 'Next: Generate Investigation Report →'
  },
  {
    stepNumber: 10,
    title: 'Step 10: Generate Investigation Report',
    targetSection: 'report',
    targetTab: 'generate',
    targetPath: '/investigate/scenario-3-campaign/report',
    description: 'Generate SOC incident investigation briefing complete with chain-of-custody hashes, MITRE ATT&CK mappings, and remediation guidance.',
    actionGuidance: 'Export comprehensive incident documentation ready for executive and legal review.',
    nextButtonLabel: 'Complete Demonstration ✓'
  }
];

interface DemoTourContextType {
  isTourActive: boolean;
  currentStep: number;
  currentScenario: string;
  isResetting: boolean;
  activeTabOverride: string | null;
  startTour: (scenarioId?: string, step?: number) => void;
  nextStep: () => void;
  prevStep: () => void;
  goToStep: (step: number) => void;
  endTour: () => void;
  selectScenario: (scenarioId: string) => void;
  resetDemo: () => Promise<boolean>;
  setActiveTabOverride: (tab: string | null) => void;
}

const DemoTourContext = createContext<DemoTourContextType | null>(null);

export const DemoTourProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [isTourActive, setIsTourActive] = useState(false);
  const [currentStep, setCurrentStep] = useState(1);
  const [currentScenario, setCurrentScenario] = useState('scenario-3-campaign');
  const [isResetting, setIsResetting] = useState(false);
  const [activeTabOverride, setActiveTabOverride] = useState<string | null>(null);
  const navigate = useNavigate();

  const applyStepNavigation = useCallback((stepIdx: number, scenarioId: string) => {
    const step = TOUR_STEPS[stepIdx - 1];
    if (!step) return;

    if (step.targetSection) {
      navigate(`/investigate/${scenarioId}/${step.targetSection}`);
    } else if (step.targetPath) {
      const path = step.targetPath.includes('scenario-')
        ? `/investigate/${scenarioId}/overview`
        : step.targetPath;
      navigate(path);
    }

    if (step.targetTab) {
      setActiveTabOverride(step.targetTab);
    }
  }, [navigate]);

  const startTour = useCallback((scenarioId = 'scenario-3-campaign', step = 1) => {
    setIsTourActive(true);
    setCurrentStep(step);
    setCurrentScenario(scenarioId);
    applyStepNavigation(step, scenarioId);
  }, [applyStepNavigation]);

  const nextStep = useCallback(() => {
    if (currentStep >= TOUR_STEPS.length) {
      setIsTourActive(false);
      return;
    }
    const next = currentStep + 1;
    setCurrentStep(next);
    applyStepNavigation(next, currentScenario);
  }, [currentStep, currentScenario, applyStepNavigation]);

  const prevStep = useCallback(() => {
    if (currentStep <= 1) return;
    const prev = currentStep - 1;
    setCurrentStep(prev);
    applyStepNavigation(prev, currentScenario);
  }, [currentStep, currentScenario, applyStepNavigation]);

  const goToStep = useCallback((step: number) => {
    const bounded = Math.max(1, Math.min(TOUR_STEPS.length, step));
    setCurrentStep(bounded);
    applyStepNavigation(bounded, currentScenario);
  }, [currentScenario, applyStepNavigation]);

  const endTour = useCallback(() => {
    setIsTourActive(false);
    setActiveTabOverride(null);
  }, []);

  const selectScenario = useCallback((scenarioId: string) => {
    setCurrentScenario(scenarioId);
    navigate(`/analysis/${scenarioId}`);
    setActiveTabOverride('overview');
  }, [navigate]);

  const resetDemo = useCallback(async (): Promise<boolean> => {
    setIsResetting(true);
    try {
      const ok = await resetDemoStore();
      // Re-navigate to refresh current view
      if (isTourActive) {
        applyStepNavigation(1, 'scenario-3-campaign');
        setCurrentStep(1);
      }
      return ok;
    } finally {
      setIsResetting(false);
    }
  }, [isTourActive, applyStepNavigation]);

  return (
    <DemoTourContext.Provider
      value={{
        isTourActive,
        currentStep,
        currentScenario,
        isResetting,
        activeTabOverride,
        startTour,
        nextStep,
        prevStep,
        goToStep,
        endTour,
        selectScenario,
        resetDemo,
        setActiveTabOverride
      }}
    >
      {children}
    </DemoTourContext.Provider>
  );
};

export const useDemoTour = (): DemoTourContextType => {
  const context = useContext(DemoTourContext);
  if (!context) {
    throw new Error('useDemoTour must be used within a DemoTourProvider');
  }
  return context;
};
