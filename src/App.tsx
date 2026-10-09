import { HashRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { ThemeProvider } from './context/ThemeContext';
import { DemoTourProvider } from './context/DemoTourContext';
import { InvestigationProvider } from './context/InvestigationContext';
import { AppShell } from './components/layout/AppShell';

// Canonical Views
import { Dashboard } from './pages/Dashboard';
import { InvestigationsListPage } from './pages/InvestigationsListPage';
import { InvestigationWorkspace } from './pages/investigation/InvestigationWorkspace';
import { Reports } from './pages/Reports';
import { Settings } from './pages/Settings';

// Fallback & Security Pages
import { NotFoundPage } from './pages/NotFoundPage';
import { AccessDeniedPage } from './pages/AccessDeniedPage';

// Contextual Investigation Tools
import { AnalyzeEmail } from './pages/AnalyzeEmail';
import { Cases } from './pages/Cases';
import { CaseDetail } from './pages/CaseDetail';
import { ThreatIntelligence } from './pages/ThreatIntelligence';
import { CampaignIntelligence } from './pages/CampaignIntelligence';
import { CrossInvestigationWorkspacePage } from './pages/CrossInvestigationWorkspacePage';
import { BenchmarkEvaluation } from './pages/BenchmarkEvaluation';
import { InvestigationHistory } from './pages/InvestigationHistory';
import { NetworkSecurityView } from './pages/NetworkSecurityView';
import { AuthSecurityView } from './pages/AuthSecurityView';
import { FileSecurityView } from './pages/FileSecurityView';
import { UrlSecurityView } from './pages/UrlSecurityView';
import { EndpointAgentView } from './pages/EndpointAgentView';
import { DesignSystemPreview } from './pages/DesignSystemPreview';

function AppContent() {
  return (
    <AppShell>
      <Routes>
        {/* Canonical Level-1 Navigation Routes */}
        <Route path="/" element={<Navigate to="/dashboard" replace />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/investigations" element={<InvestigationsListPage />} />
        <Route path="/reports" element={<Reports />} />
        <Route path="/reports/:id" element={<Reports />} />
        <Route path="/settings" element={<Settings />} />
        <Route path="/settings/:tab" element={<Settings />} />

        {/* Canonical Investigation Workspace Routes */}
        <Route path="/investigations/:id" element={<InvestigationWorkspace />} />
        <Route path="/investigations/:id/:section" element={<InvestigationWorkspace />} />
        <Route path="/investigations/:section" element={<InvestigationWorkspace />} />

        {/* Legacy Investigation Aliases & Forwarding */}
        <Route path="/investigate" element={<Navigate to="/investigations" replace />} />
        <Route path="/investigate/:section" element={<InvestigationWorkspace />} />
        <Route path="/investigate/:id/:section" element={<InvestigationWorkspace />} />
        <Route path="/overview" element={<InvestigationWorkspace />} />
        <Route path="/email" element={<InvestigationWorkspace />} />
        <Route path="/analysis" element={<InvestigationWorkspace />} />
        <Route path="/analysis/:id" element={<InvestigationWorkspace />} />
        <Route path="/intelligence" element={<InvestigationWorkspace />} />
        <Route path="/investigation" element={<InvestigationWorkspace />} />
        <Route path="/report" element={<InvestigationWorkspace />} />

        {/* Contextual Security Tools (Deep Links & Sub-Workflows) */}
        <Route path="/analyze" element={<AnalyzeEmail />} />
        <Route path="/cases" element={<Cases />} />
        <Route path="/cases/:id" element={<CaseDetail />} />
        <Route path="/history" element={<InvestigationHistory />} />
        <Route path="/network-security" element={<NetworkSecurityView />} />
        <Route path="/auth-security" element={<AuthSecurityView />} />
        <Route path="/file-security" element={<FileSecurityView />} />
        <Route path="/url-intelligence" element={<UrlSecurityView />} />
        <Route path="/endpoints" element={<EndpointAgentView />} />
        <Route path="/cross-investigation" element={<CrossInvestigationWorkspacePage />} />
        <Route path="/cross-investigation/:id" element={<CrossInvestigationWorkspacePage />} />
        <Route path="/campaigns" element={<CampaignIntelligence />} />
        <Route path="/campaigns/:id" element={<CampaignIntelligence />} />
        <Route path="/osint" element={<ThreatIntelligence />} />
        <Route path="/benchmarks" element={<BenchmarkEvaluation />} />
        <Route path="/design-system" element={<DesignSystemPreview />} />

        {/* Access Restricted & Error Handling */}
        <Route path="/access-denied" element={<AccessDeniedPage />} />
        <Route path="*" element={<NotFoundPage />} />
      </Routes>
    </AppShell>
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
