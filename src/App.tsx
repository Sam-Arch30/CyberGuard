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
import { AlertWorkspace } from './pages/AlertWorkspace';
import { IncidentListPage } from './pages/incidents/IncidentListPage';
import { IncidentDetailPage } from './pages/incidents/IncidentDetailPage';
import { Watchlists } from './pages/Watchlists';
import { ThreatHunting } from './pages/ThreatHunting';
import { DetectionRules } from './pages/DetectionRules';
import { CrossSourceCorrelationPage } from './pages/CrossSourceCorrelationPage';
import { AttackSurfacePage } from './pages/AttackSurfacePage';
import { InventoryPage } from './pages/InventoryPage';
import { ThreatActorWorkspace } from './pages/ThreatActorWorkspace';
import { EvidenceWorkspace } from './pages/EvidenceWorkspace';
import { AutomationPage } from './pages/AutomationPage';
import { AdminPage } from './pages/AdminPage';

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

        {/* Section 71: Platform Administration & Governance */}
        <Route path="/admin" element={<AdminPage />} />
        <Route path="/admin/:tab" element={<AdminPage />} />

        {/* Section 50: Incident Management & Case Lifecycle */}
        <Route path="/incidents" element={<IncidentListPage />} />
        <Route path="/incidents/:id" element={<IncidentDetailPage />} />

        {/* Section 48: Alert Management & Triage Workspace */}
        <Route path="/alerts" element={<AlertWorkspace />} />
        <Route path="/alerts/:id" element={<AlertWorkspace />} />
        <Route path="/security-alerts" element={<Navigate to="/alerts" replace />} />

        {/* Section 61: Cross-Source Correlation & Unified Entity Correlation */}
        <Route path="/correlations" element={<CrossSourceCorrelationPage />} />
        <Route path="/correlations/:id" element={<CrossSourceCorrelationPage />} />
        <Route path="/cross-source-correlation" element={<Navigate to="/correlations" replace />} />

        {/* Section 62: Attack Surface Intelligence */}
        <Route path="/attack-surface" element={<AttackSurfacePage />} />
        <Route path="/attack-surface/:id" element={<AttackSurfacePage />} />

        {/* Section 63: Asset & Identity Inventory */}
        <Route path="/inventory" element={<InventoryPage />} />
        <Route path="/inventory/:id" element={<InventoryPage />} />
        <Route path="/assets" element={<InventoryPage />} />
        <Route path="/assets/:id" element={<InventoryPage />} />
        <Route path="/identities" element={<InventoryPage />} />
        <Route path="/identities/:id" element={<InventoryPage />} />

        {/* Canonical Investigation Workspace Routes */}
        <Route path="/investigations/:id" element={<InvestigationWorkspace />} />
        <Route path="/investigations/:id/:section" element={<InvestigationWorkspace />} />
        <Route path="/investigations/:section" element={<InvestigationWorkspace />} />

        {/* Legacy Investigation Aliases & Forwarding */}
        <Route path="/investigate" element={<Navigate to="/investigations" replace />} />
        <Route path="/investigate/:section" element={<InvestigationWorkspace />} />
        <Route path="/investigate/:id/:section" element={<InvestigationWorkspace />} />
        <Route path="/overview" element={<InvestigationWorkspace />} />
        <Route path="/analysis" element={<InvestigationWorkspace />} />
        <Route path="/analysis/:id" element={<InvestigationWorkspace />} />
        <Route path="/attack-path" element={<InvestigationWorkspace />} />
        <Route path="/graph" element={<InvestigationWorkspace />} />
        <Route path="/timeline" element={<InvestigationWorkspace />} />
        <Route path="/evidence" element={<EvidenceWorkspace />} />
        <Route path="/evidence/:id" element={<EvidenceWorkspace />} />
        <Route path="/forensics" element={<EvidenceWorkspace />} />
        <Route path="/forensics/:id" element={<EvidenceWorkspace />} />
        <Route path="/intelligence" element={<InvestigationWorkspace />} />
        <Route path="/response" element={<InvestigationWorkspace />} />
        <Route path="/report" element={<InvestigationWorkspace />} />
        <Route path="/email" element={<InvestigationWorkspace />} />
        <Route path="/investigation" element={<InvestigationWorkspace />} />

        {/* Section 70: Security Operations Automation (SOAR) & Workflow Orchestration */}
        <Route path="/automation" element={<AutomationPage />} />
        <Route path="/automation/:id" element={<AutomationPage />} />
        <Route path="/soar" element={<Navigate to="/automation" replace />} />

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
        <Route path="/actors" element={<ThreatActorWorkspace />} />
        <Route path="/actors/:id" element={<ThreatActorWorkspace />} />
        <Route path="/threat-actors" element={<ThreatActorWorkspace />} />
        <Route path="/threat-actors/:id" element={<ThreatActorWorkspace />} />
        <Route path="/osint" element={<ThreatIntelligence />} />
        <Route path="/watchlists" element={<Watchlists />} />
        <Route path="/watchlists/:id" element={<Watchlists />} />
        <Route path="/hunting" element={<ThreatHunting />} />
        <Route path="/threat-hunting" element={<ThreatHunting />} />
        <Route path="/detections" element={<DetectionRules />} />
        <Route path="/detections/:id" element={<DetectionRules />} />
        <Route path="/pipeline" element={<DetectionRules defaultTab="pipeline" />} />
        <Route path="/detection-pipeline" element={<DetectionRules defaultTab="pipeline" />} />
        <Route path="/behavioral" element={<DetectionRules defaultTab="behavioral" />} />
        <Route path="/behavioral-analytics" element={<DetectionRules defaultTab="behavioral" />} />
        <Route path="/anomalies" element={<DetectionRules defaultTab="behavioral" />} />
        <Route path="/rules" element={<Navigate to="/detections" replace />} />
        <Route path="/detection-rules" element={<Navigate to="/detections" replace />} />
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
