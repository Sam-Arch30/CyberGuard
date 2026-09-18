import { useState, useEffect } from 'react';
import { HashRouter as Router, Routes, Route, useLocation, Navigate } from 'react-router-dom';
import { ThemeProvider } from './context/ThemeContext';
import { DemoTourProvider } from './context/DemoTourContext';
import { InvestigationProvider } from './context/InvestigationContext';
import { SIHGuidedTour } from './components/demo/SIHGuidedTour';
import { Sidebar } from './components/layout/Sidebar';
import { Navbar } from './components/layout/Navbar';
import { InvestigationWorkspace } from './pages/investigation/InvestigationWorkspace';
import { Dashboard } from './pages/Dashboard';
import { AnalyzeEmail } from './pages/AnalyzeEmail';
import { Cases } from './pages/Cases';
import { CaseDetail } from './pages/CaseDetail';
import { ThreatIntelligence } from './pages/ThreatIntelligence';
import { CampaignIntelligence } from './pages/CampaignIntelligence';
import { Reports } from './pages/Reports';
import { Settings } from './pages/Settings';
import { CrossInvestigationWorkspacePage } from './pages/CrossInvestigationWorkspacePage';
import { BenchmarkEvaluation } from './pages/BenchmarkEvaluation';
import { InvestigationHistory } from './pages/InvestigationHistory';

function AppContent() {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [mobileSidebarOpen, setMobileSidebarOpen] = useState(false);
  const location = useLocation();

  // Automatically close mobile sidebar when route changes
  useEffect(() => {
    setMobileSidebarOpen(false);
  }, [location.pathname]);

  return (
    <div className="min-h-screen bg-background text-foreground flex transition-colors duration-200">
      {/* Collapsible Sidebar with 6 Primary Investigation Areas */}
      <Sidebar
        collapsed={sidebarCollapsed}
        onToggleCollapse={() => setSidebarCollapsed(!sidebarCollapsed)}
        mobileOpen={mobileSidebarOpen}
        onCloseMobile={() => setMobileSidebarOpen(false)}
      />

      {/* Main Content Workspace Area */}
      <div
        className={`flex-1 flex flex-col min-w-0 transition-all duration-200 pl-0 ${
          sidebarCollapsed ? 'md:pl-20' : 'md:pl-64'
        }`}
      >
        <Navbar onToggleMobileSidebar={() => setMobileSidebarOpen(!mobileSidebarOpen)} />

        <main className="flex-1 p-3 sm:p-5 lg:p-6 max-w-[1600px] w-full mx-auto">
          <div key={location.pathname} className="page-enter">
            <Routes>
              {/* Primary 6-Stage Investigation Routes */}
              <Route path="/investigate" element={<InvestigationWorkspace />} />
              <Route path="/investigate/:section" element={<InvestigationWorkspace />} />
              <Route path="/investigate/:id/:section" element={<InvestigationWorkspace />} />
              <Route path="/overview" element={<InvestigationWorkspace />} />
              <Route path="/email" element={<InvestigationWorkspace />} />
              <Route path="/analysis" element={<InvestigationWorkspace />} />
              <Route path="/intelligence" element={<InvestigationWorkspace />} />
              <Route path="/investigation" element={<InvestigationWorkspace />} />
              <Route path="/report" element={<InvestigationWorkspace />} />

              {/* Backward-Compatible & Direct Target Analysis */}
              <Route path="/analysis/:id" element={<InvestigationWorkspace />} />

              {/* Platform & Intake Tools */}
              <Route path="/" element={<Dashboard />} />
              <Route path="/dashboard" element={<Dashboard />} />
              <Route path="/analyze" element={<AnalyzeEmail />} />
              <Route path="/history" element={<InvestigationHistory />} />
              <Route path="/cross-investigation" element={<CrossInvestigationWorkspacePage />} />
              <Route path="/cross-investigation/:id" element={<CrossInvestigationWorkspacePage />} />
              <Route path="/cases" element={<Cases />} />
              <Route path="/cases/:id" element={<CaseDetail />} />
              <Route path="/campaigns" element={<CampaignIntelligence />} />
              <Route path="/campaigns/:id" element={<CampaignIntelligence />} />
              <Route path="/osint" element={<ThreatIntelligence />} />
              <Route path="/reports" element={<Reports />} />
              <Route path="/benchmarks" element={<BenchmarkEvaluation />} />
              <Route path="/settings" element={<Settings />} />

              {/* Fallback */}
              <Route path="*" element={<Navigate to="/investigate/overview" replace />} />
            </Routes>
          </div>
        </main>

        {/* Persistent SIH Guided Tour HUD */}
        <SIHGuidedTour />
      </div>
    </div>
  );
}

export function App() {
  return (
    <ThemeProvider>
      <Router>
        <InvestigationProvider>
          <DemoTourProvider>
            <AppContent />
          </DemoTourProvider>
        </InvestigationProvider>
      </Router>
    </ThemeProvider>
  );
}

export default App;
