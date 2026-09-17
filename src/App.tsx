import { useState } from 'react';
import { HashRouter as Router, Routes, Route, useLocation } from 'react-router-dom';
import { ThemeProvider } from './context/ThemeContext';
import { DemoTourProvider } from './context/DemoTourContext';
import { SIHGuidedTour } from './components/demo/SIHGuidedTour';
import { Sidebar } from './components/layout/Sidebar';
import { Navbar } from './components/layout/Navbar';
import { Dashboard } from './pages/Dashboard';
import { AnalyzeEmail } from './pages/AnalyzeEmail';
import { EmailForensicView } from './pages/EmailForensicView';
import { Cases } from './pages/Cases';
import { CaseDetail } from './pages/CaseDetail';
import { ThreatIntelligence } from './pages/ThreatIntelligence';
import { CampaignIntelligence } from './pages/CampaignIntelligence';
import { Reports } from './pages/Reports';
import { Settings } from './pages/Settings';
import { CrossInvestigationWorkspacePage } from './pages/CrossInvestigationWorkspacePage';
import { BenchmarkEvaluation } from './pages/BenchmarkEvaluation';

function AppContent() {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const location = useLocation();

  return (
    <div className="min-h-screen bg-background text-foreground flex transition-colors duration-200">
      {/* Collapsible Sidebar */}
      <Sidebar
        collapsed={sidebarCollapsed}
        onToggleCollapse={() => setSidebarCollapsed(!sidebarCollapsed)}
      />

      {/* Main Content Workspace Area */}
      <div
        className={`flex-1 flex flex-col min-w-0 transition-all duration-250 ${
          sidebarCollapsed ? 'pl-20' : 'pl-64'
        }`}
      >
        <Navbar />

        <main className="flex-1 p-6 max-w-7xl w-full mx-auto">
          <div key={location.pathname} className="page-enter">
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/analyze" element={<AnalyzeEmail />} />
              <Route path="/analysis" element={<EmailForensicView />} />
              <Route path="/analysis/:id" element={<EmailForensicView />} />
              <Route path="/cross-investigation" element={<CrossInvestigationWorkspacePage />} />
              <Route path="/cross-investigation/:id" element={<CrossInvestigationWorkspacePage />} />
              <Route path="/cases" element={<Cases />} />
              <Route path="/cases/:id" element={<CaseDetail />} />
              <Route path="/campaigns" element={<CampaignIntelligence />} />
              <Route path="/campaigns/:id" element={<CampaignIntelligence />} />
              <Route path="/intelligence" element={<ThreatIntelligence />} />
              <Route path="/reports" element={<Reports />} />
              <Route path="/benchmarks" element={<BenchmarkEvaluation />} />
              <Route path="/settings" element={<Settings />} />
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
        <DemoTourProvider>
          <AppContent />
        </DemoTourProvider>
      </Router>
    </ThemeProvider>
  );
}

export default App;

