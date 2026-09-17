import React, { useState } from 'react';
import { useDemoTour, TOUR_STEPS } from '../../context/DemoTourContext';
import {
  Sparkles,
  ChevronRight,
  ChevronLeft,
  RotateCcw,
  X,
  Compass,
  CheckCircle2,
  AlertTriangle,
  ShieldCheck,
  Zap,
  Info
} from 'lucide-react';

export const SIHGuidedTour: React.FC = () => {
  const {
    isTourActive,
    currentStep,
    currentScenario,
    isResetting,
    nextStep,
    prevStep,
    goToStep,
    endTour,
    selectScenario,
    resetDemo
  } = useDemoTour();

  const [minimized, setMinimized] = useState(false);
  const [resetSuccess, setResetSuccess] = useState(false);

  if (!isTourActive) return null;

  const currentStepData = TOUR_STEPS[currentStep - 1] || TOUR_STEPS[0];
  const progressPercent = Math.round((currentStep / TOUR_STEPS.length) * 100);

  const handleReset = async () => {
    const ok = await resetDemo();
    if (ok) {
      setResetSuccess(true);
      setTimeout(() => setResetSuccess(false), 3000);
    }
  };

  return (
    <div className="fixed bottom-4 left-1/2 -translate-x-1/2 z-50 w-11/12 max-w-5xl transition-all duration-300 pointer-events-auto">
      <div className="relative overflow-hidden rounded-2xl bg-surface/95 backdrop-blur-xl border border-primary/30 shadow-2xl shadow-primary/10">
        {/* Glowing Top Progress Indicator */}
        <div className="h-1 bg-surface-secondary w-full overflow-hidden">
          <div
            className="h-full bg-gradient-to-r from-primary via-cyan-400 to-indigo-500 transition-all duration-300"
            style={{ width: `${progressPercent}%` }}
          />
        </div>

        {/* Minimized View Bar */}
        {minimized ? (
          <div className="px-5 py-2.5 flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <span className="flex h-2.5 w-2.5 relative">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-primary opacity-75" />
                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-primary" />
              </span>
              <span className="text-xs font-mono font-bold text-primary">
                SIH DEMO TOUR — {currentStepData.title}
              </span>
            </div>
            <div className="flex items-center space-x-2">
              <button
                type="button"
                onClick={() => setMinimized(false)}
                className="px-2.5 py-1 text-xs font-mono bg-surface-secondary hover:bg-surface text-foreground rounded-lg border border-border transition-colors cursor-pointer"
              >
                Expand HUD
              </button>
              <button
                type="button"
                onClick={endTour}
                className="p-1 text-foreground-muted hover:text-foreground transition-colors cursor-pointer"
                title="Close Tour"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>
        ) : (
          /* Full HUD Tour Container */
          <div className="p-4 md:p-5 space-y-3">
            {/* Top Row: Badges, Scenario Switcher, Reset, and Minimize */}
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border/60 pb-3">
              <div className="flex items-center space-x-2.5">
                <span className="inline-flex items-center space-x-1.5 px-2.5 py-0.5 rounded-full bg-primary/15 border border-primary/40 text-primary text-[11px] font-mono font-bold tracking-wide">
                  <Sparkles className="w-3.5 h-3.5 text-primary animate-pulse" />
                  <span>SIH LIVE DEMONSTRATION</span>
                </span>
                <span className="text-xs font-mono font-semibold text-foreground-muted">
                  Step {currentStep} of {TOUR_STEPS.length} ({progressPercent}%)
                </span>
              </div>

              {/* Scenario Switcher Buttons */}
              <div className="flex items-center space-x-1.5">
                <span className="text-[11px] font-mono text-foreground-muted hidden sm:inline">Scenario:</span>
                <button
                  type="button"
                  onClick={() => selectScenario('scenario-1-legit')}
                  className={`px-2 py-1 rounded-md text-[11px] font-mono transition-colors cursor-pointer border ${
                    currentScenario === 'scenario-1-legit'
                      ? 'bg-success/20 text-success border-success/40 font-bold'
                      : 'bg-surface-secondary text-foreground-muted hover:text-foreground border-border'
                  }`}
                  title="Scenario 1: Legitimate Business Email (False-Positive Resistance)"
                >
                  <ShieldCheck className="w-3 h-3 inline mr-1" />
                  1: Legit (Score 8)
                </button>
                <button
                  type="button"
                  onClick={() => selectScenario('scenario-2-phish')}
                  className={`px-2 py-1 rounded-md text-[11px] font-mono transition-colors cursor-pointer border ${
                    currentScenario === 'scenario-2-phish'
                      ? 'bg-danger/20 text-danger border-danger/40 font-bold'
                      : 'bg-surface-secondary text-foreground-muted hover:text-foreground border-border'
                  }`}
                  title="Scenario 2: Obvious Phishing Attack with Disguised Executable"
                >
                  <AlertTriangle className="w-3 h-3 inline mr-1" />
                  2: Phish (Score 88)
                </button>
                <button
                  type="button"
                  onClick={() => selectScenario('scenario-3-campaign')}
                  className={`px-2 py-1 rounded-md text-[11px] font-mono transition-colors cursor-pointer border ${
                    currentScenario === 'scenario-3-campaign'
                      ? 'bg-primary/20 text-primary border-primary/40 font-bold'
                      : 'bg-surface-secondary text-foreground-muted hover:text-foreground border-border'
                  }`}
                  title="Scenario 3: Coordinated Campaign (Operation DarkHydra - 16 emails)"
                >
                  <Zap className="w-3 h-3 inline mr-1" />
                  3: Campaign (C-042)
                </button>
              </div>

              {/* Reset & Dismiss Controls */}
              <div className="flex items-center space-x-1.5">
                <button
                  type="button"
                  onClick={handleReset}
                  disabled={isResetting}
                  className="flex items-center space-x-1 px-2.5 py-1 rounded-md text-[11px] font-mono bg-surface-secondary hover:bg-surface text-foreground-muted hover:text-foreground border border-border transition-colors cursor-pointer disabled:opacity-50"
                  title="Reset demo data to clean synthetic baseline without affecting production"
                >
                  <RotateCcw className={`w-3 h-3 ${isResetting ? 'animate-spin text-primary' : ''}`} />
                  <span>{isResetting ? 'Resetting...' : resetSuccess ? 'Reset!' : 'Reset Demo'}</span>
                </button>
                <button
                  type="button"
                  onClick={() => setMinimized(true)}
                  className="p-1 text-foreground-muted hover:text-foreground transition-colors cursor-pointer"
                  title="Minimize Tour HUD"
                >
                  <Compass className="w-4 h-4" />
                </button>
                <button
                  type="button"
                  onClick={endTour}
                  className="p-1 text-foreground-muted hover:text-foreground transition-colors cursor-pointer"
                  title="Exit Tour"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
            </div>

            {/* Middle Row: Step Details and Guidance */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 items-center">
              <div className="md:col-span-2 space-y-1">
                <div className="flex items-center space-x-2">
                  <h3 className="text-sm md:text-base font-bold text-foreground font-mono">
                    {currentStepData.title}
                  </h3>
                </div>
                <p className="text-xs text-foreground font-sans leading-relaxed">
                  {currentStepData.description}
                </p>
                <p className="text-[11px] font-mono text-primary flex items-center space-x-1.5 pt-0.5">
                  <Info className="w-3 h-3 inline flex-shrink-0" />
                  <span>{currentStepData.actionGuidance}</span>
                </p>
              </div>

              {/* Step Navigation Controls */}
              <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-end gap-2">
                <button
                  type="button"
                  onClick={prevStep}
                  disabled={currentStep <= 1}
                  className="px-3 py-2 rounded-xl bg-surface border border-border text-foreground-muted hover:text-foreground hover:bg-surface-secondary text-xs font-mono font-medium disabled:opacity-40 disabled:cursor-not-allowed transition-colors flex items-center justify-center space-x-1 cursor-pointer"
                >
                  <ChevronLeft className="w-4 h-4" />
                  <span>Back</span>
                </button>

                <button
                  type="button"
                  onClick={nextStep}
                  className="px-4 py-2 rounded-xl bg-primary hover:bg-primary/90 text-primary-foreground text-xs font-mono font-bold shadow-md shadow-primary/20 transition-all flex items-center justify-center space-x-1.5 cursor-pointer btn-press"
                >
                  <span>{currentStepData.nextButtonLabel}</span>
                  {currentStep < TOUR_STEPS.length ? (
                    <ChevronRight className="w-4 h-4" />
                  ) : (
                    <CheckCircle2 className="w-4 h-4" />
                  )}
                </button>
              </div>
            </div>

            {/* Bottom Row: 10 Step Interactive Indicator Pills */}
            <div className="flex items-center justify-between pt-1">
              <div className="flex items-center space-x-1.5 overflow-x-auto py-1 max-w-full">
                {TOUR_STEPS.map((step) => {
                  const isCurrent = step.stepNumber === currentStep;
                  const isPast = step.stepNumber < currentStep;
                  return (
                    <button
                      key={step.stepNumber}
                      type="button"
                      onClick={() => goToStep(step.stepNumber)}
                      className={`h-6 px-2 rounded-md text-[10px] font-mono transition-all cursor-pointer flex items-center space-x-1 ${
                        isCurrent
                          ? 'bg-primary text-primary-foreground font-bold shadow-xs'
                          : isPast
                          ? 'bg-surface-secondary text-primary border border-primary/20 hover:bg-primary/10'
                          : 'bg-surface-secondary/60 text-foreground-muted hover:text-foreground border border-border/40'
                      }`}
                      title={step.title}
                    >
                      <span>{step.stepNumber}</span>
                    </button>
                  );
                })}
              </div>
              <span className="text-[10px] font-mono text-foreground-muted hidden lg:inline">
                Live interactive walkthrough • Real forensic pipeline
              </span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
