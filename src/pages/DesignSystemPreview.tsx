import React, { useState } from 'react';
import {
  Shield,
  Sliders,
  AlertTriangle,
  Copy,
  ExternalLink,
  Cpu,
} from 'lucide-react';
import { useTheme, THEME_OPTIONS, type AppTheme } from '../context/ThemeContext';
import {
  Button,
  IconButton,
  Input,
  SearchInput,
  Textarea,
  Select,
  Checkbox,
  Switch,
  Radio,
  RadioGroup,
  Badge,
  Tag,
  Tooltip,
  Card,
  Panel,
  Divider,
  Tabs,
  Accordion,
  AccordionItem,
  Modal,
  ModalHeader,
  ModalTitle,
  ModalBody,
  ModalFooter,
  Drawer,
  Alert,
  Progress,
  Skeleton,
  EmptyState,
  ErrorState,
  LoadingState,
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
  DataList,
  Metric,
  TimelineItem,
  StatusIndicator,
} from '../components/ui';
import {
  SeverityIndicator,
  ConfidenceIndicator,
  RiskBadge,
  EvidenceCount,
  ThreatScore,
  EntityChip,
  IndicatorValue,
  Timestamp,
  SourceBadge,
  TechnicalValue,
} from '../components/security';

export const DesignSystemPreview: React.FC = () => {
  const { theme, setTheme, themeMeta } = useTheme();

  // Interactive component test states
  const [modalOpen, setModalOpen] = useState(false);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [checkboxVal, setCheckboxVal] = useState(true);
  const [switchVal, setSwitchVal] = useState(true);
  const [radioVal, setRadioVal] = useState('agent');
  const [searchVal, setSearchVal] = useState('');
  const [notesVal, setNotesVal] = useState('');
  const [activeTab, setActiveTab] = useState('tokens');
  const [denseMode, setDenseMode] = useState(false);
  const [tags, setTags] = useState(['APT29', 'COZY_BEAR', 'SPEAR_PHISH', 'T1566.001']);

  // Table demo columns and rows
  const tableColumns = [
    'Severity',
    'Security Event',
    'Telemetry Source',
    'Target Entity',
    'Confidence',
    'Timestamp (UTC)',
  ];

  const tableData = [
    {
      severity: <SeverityIndicator severity="CRITICAL" size="xs" pulse />,
      event: (
        <div className="flex flex-col">
          <span className="font-semibold text-foreground">LSASS Memory Dump Attempt</span>
          <span className="text-[10px] text-foreground-muted font-mono">T1003.001 • OS Credential Dumping</span>
        </div>
      ),
      source: <SourceBadge source="Sysmon" detector="ProcInjection" version="14.1" size="xs" />,
      target: <TechnicalValue value="svchost.exe (PID: 884)" type="command" size="xs" />,
      confidence: <ConfidenceIndicator tier="VERY_HIGH" score={0.96} size="xs" />,
      timestamp: <Timestamp date="2026-10-09T14:22:00Z" size="xs" />,
    },
    {
      severity: <SeverityIndicator severity="HIGH" size="xs" />,
      event: (
        <div className="flex flex-col">
          <span className="font-semibold text-foreground">Suspicious Outbound C2 Beacon</span>
          <span className="text-[10px] text-foreground-muted font-mono">T1071.001 • Web Protocols</span>
        </div>
      ),
      source: <SourceBadge source="Suricata" type="network" size="xs" />,
      target: <IndicatorValue value="198.51.100.42:8443" type="IP:Port" reputation="suspicious" size="xs" />,
      confidence: <ConfidenceIndicator tier="HIGH" score={0.82} size="xs" />,
      timestamp: <Timestamp date="2026-10-09T14:18:30Z" size="xs" />,
    },
    {
      severity: <SeverityIndicator severity="MEDIUM" size="xs" />,
      event: (
        <div className="flex flex-col">
          <span className="font-semibold text-foreground">Unusual PowerShell Encoded Command</span>
          <span className="text-[10px] text-foreground-muted font-mono">T1059.001 • PowerShell Execution</span>
        </div>
      ),
      source: <SourceBadge source="Endpoint Agent" type="agent" size="xs" />,
      target: <TechnicalValue value="powershell.exe -enc JABz..." truncate="middle" size="xs" />,
      confidence: <ConfidenceIndicator tier="MEDIUM" score={0.62} size="xs" />,
      timestamp: <Timestamp date="2026-10-09T14:15:10Z" size="xs" />,
    },
    {
      severity: <SeverityIndicator severity="SAFE" size="xs" />,
      event: (
        <div className="flex flex-col">
          <span className="font-semibold text-foreground">Verified Domain Controller Sync</span>
          <span className="text-[10px] text-foreground-muted font-mono">Baseline AD Replication</span>
        </div>
      ),
      source: <SourceBadge source="Auditd" type="system" size="xs" />,
      target: <EntityChip type="host" value="DC-PRIMARY-01" size="xs" />,
      confidence: <ConfidenceIndicator tier="VERY_HIGH" score={0.99} size="xs" />,
      timestamp: <Timestamp date="2026-10-09T14:10:00Z" size="xs" />,
    },
    {
      severity: <SeverityIndicator severity="UNKNOWN" size="xs" />,
      event: (
        <div className="flex flex-col">
          <span className="font-semibold text-foreground">Anomalous Pipe Name Created</span>
          <span className="text-[10px] text-foreground-muted font-mono">Insufficient baseline samples</span>
        </div>
      ),
      source: <SourceBadge source="Sysmon" detector="NamedPipe" size="xs" />,
      target: <TechnicalValue value="\\pipe\\agent_pipe_89a" size="xs" />,
      confidence: <ConfidenceIndicator tier="UNCALIBRATED" size="xs" />,
      timestamp: <Timestamp date="2026-10-09T14:05:00Z" size="xs" />,
    },
  ];

  return (
    <div className="space-y-8 pb-20">
      {/* Header Banner */}
      <div className="bg-surface p-6 rounded-xl border border-border flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2 text-primary font-mono text-xs mb-1 font-semibold uppercase tracking-wider">
            <Sliders className="w-3.5 h-3.5 text-primary" />
            <span>SECTION 34 • DESIGN SYSTEM & THEME ENGINE SPECIFICATION</span>
          </div>
          <h1 className="text-2xl font-bold text-foreground font-sans tracking-tight">
            Design System Verification Lab
          </h1>
          <p className="text-xs text-foreground-muted font-mono mt-1">
            Deterministic validation surface for calibrated themes, design tokens, UI primitives, and security-specific components.
          </p>
        </div>

        {/* Global Quick Theme Switcher */}
        <div className="flex items-center space-x-2 bg-surface-secondary p-1.5 rounded-lg border border-border">
          {THEME_OPTIONS.map((opt) => (
            <button
              key={opt.id}
              type="button"
              onClick={() => setTheme(opt.id as AppTheme)}
              className={`flex items-center space-x-1.5 px-3 py-1.5 rounded text-xs font-mono transition-all cursor-pointer ${
                theme === opt.id
                  ? 'bg-surface font-semibold text-foreground shadow-xs border border-border'
                  : 'text-foreground-muted hover:text-foreground'
              }`}
            >
              <span
                className="w-2.5 h-2.5 rounded-full border border-border"
                style={{ backgroundColor: opt.previewAccent }}
              />
              <span>{opt.name}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Tabs Navigation for Sections */}
      <Tabs
        activeId={activeTab}
        onChange={setActiveTab}
        items={[
          { id: 'tokens', label: '1. Themes & Tokens' },
          { id: 'security', label: '2. Security Primitives' },
          { id: 'ui', label: '3. UI Primitives' },
          { id: 'tables', label: '4. Tables & Density' },
          { id: 'states', label: '5. States & Feedback' },
        ]}
      />

      {/* TAB 1: THEMES & TOKENS */}
      {activeTab === 'tokens' && (
        <div className="space-y-8">
          {/* Active Theme Metadata Card */}
          <Panel
            title={`Active Theme Identity: ${themeMeta.name.toUpperCase()}`}
            subtitle={themeMeta.description}
            actions={
              <Badge variant="primary" size="sm">
                ACTIVE IDENTITY
              </Badge>
            }
          >
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mt-2 font-mono text-xs">
              <div className="p-3 rounded-lg bg-background border border-border">
                <span className="text-[10px] text-foreground-muted block mb-1">--color-background</span>
                <span className="font-semibold text-foreground">{themeMeta.previewBg}</span>
              </div>
              <div className="p-3 rounded-lg bg-surface border border-border">
                <span className="text-[10px] text-foreground-muted block mb-1">--color-surface</span>
                <span className="font-semibold text-foreground">{themeMeta.previewSurface}</span>
              </div>
              <div className="p-3 rounded-lg bg-surface-elevated border border-border">
                <span className="text-[10px] text-foreground-muted block mb-1">--color-surface-elevated</span>
                <span className="font-semibold text-foreground">Elevated</span>
              </div>
              <div className="p-3 rounded-lg bg-primary-subtle border border-primary/30">
                <span className="text-[10px] text-primary block mb-1">--color-accent ({themeMeta.accentLabel})</span>
                <span className="font-semibold text-primary">{themeMeta.previewAccent}</span>
              </div>
            </div>
          </Panel>

          {/* Semantic Threat Color Hierarchy */}
          <Panel
            title="Semantic Threat Hierarchy (Theme-Independent)"
            subtitle="Security severity tokens remain calibrated for both dark and light modes, preserving recognized meaning."
          >
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 mt-2">
              <div className="p-3 rounded-lg bg-threat-critical-surface border border-threat-critical-border text-threat-critical-foreground">
                <div className="flex items-center justify-between mb-1 font-mono font-bold text-xs">
                  <span>CRITICAL</span>
                  <span className="w-2.5 h-2.5 rounded-full bg-threat-critical" />
                </div>
                <p className="text-[11px] font-sans opacity-90">Severe exploit or confirmed compromise.</p>
              </div>

              <div className="p-3 rounded-lg bg-threat-high-surface border border-threat-high-border text-threat-high-foreground">
                <div className="flex items-center justify-between mb-1 font-mono font-bold text-xs">
                  <span>HIGH</span>
                  <span className="w-2.5 h-2.5 rounded-full bg-threat-high" />
                </div>
                <p className="text-[11px] font-sans opacity-90">Probable lateral movement or credential attack.</p>
              </div>

              <div className="p-3 rounded-lg bg-threat-medium-surface border border-threat-medium-border text-threat-medium-foreground">
                <div className="flex items-center justify-between mb-1 font-mono font-bold text-xs">
                  <span>MEDIUM</span>
                  <span className="w-2.5 h-2.5 rounded-full bg-threat-medium" />
                </div>
                <p className="text-[11px] font-sans opacity-90">Suspicious anomaly requiring triage.</p>
              </div>

              <div className="p-3 rounded-lg bg-threat-low-surface border border-threat-low-border text-threat-low-foreground">
                <div className="flex items-center justify-between mb-1 font-mono font-bold text-xs">
                  <span>LOW</span>
                  <span className="w-2.5 h-2.5 rounded-full bg-threat-low" />
                </div>
                <p className="text-[11px] font-sans opacity-90">Low-risk policy aberration or tracking event.</p>
              </div>

              <div className="p-3 rounded-lg bg-threat-safe-surface border border-threat-safe-border text-threat-safe-foreground">
                <div className="flex items-center justify-between mb-1 font-mono font-bold text-xs">
                  <span>SAFE</span>
                  <span className="w-2.5 h-2.5 rounded-full bg-threat-safe" />
                </div>
                <p className="text-[11px] font-sans opacity-90">Cryptographically authentic, verified benign.</p>
              </div>

              <div className="p-3 rounded-lg bg-threat-info-surface border border-threat-info-border text-threat-info-foreground">
                <div className="flex items-center justify-between mb-1 font-mono font-bold text-xs">
                  <span>INFO</span>
                  <span className="w-2.5 h-2.5 rounded-full bg-threat-info" />
                </div>
                <p className="text-[11px] font-sans opacity-90">Informational event or standard telemetry stream.</p>
              </div>

              <div className="p-3 rounded-lg bg-threat-unknown-surface border border-threat-unknown-border text-threat-unknown-foreground">
                <div className="flex items-center justify-between mb-1 font-mono font-bold text-xs">
                  <span>UNKNOWN</span>
                  <span className="w-2.5 h-2.5 rounded-full bg-threat-unknown" />
                </div>
                <p className="text-[11px] font-sans opacity-90">Insufficient observations (never converted to safe).</p>
              </div>

              <div className="p-3 rounded-lg bg-surface-secondary border border-border text-foreground">
                <div className="flex items-center justify-between mb-1 font-mono font-bold text-xs">
                  <span>CHART BASELINE</span>
                  <span className="w-2.5 h-2.5 rounded-full bg-chart-baseline" />
                </div>
                <p className="text-[11px] font-sans text-foreground-muted">Normative telemetry and historical reference.</p>
              </div>
            </div>
          </Panel>

          {/* Typography Scale */}
          <Panel title="Typography & Numerical Clarity">
            <div className="space-y-4">
              <div>
                <span className="text-[10px] font-mono uppercase text-foreground-muted block mb-1">Display (Sans)</span>
                <div className="text-3xl font-extrabold text-foreground tracking-tight">
                  CYBERGUARD SOC PLATFORM v4.2
                </div>
              </div>
              <Divider />
              <div>
                <span className="text-[10px] font-mono uppercase text-foreground-muted block mb-1">Page Title & Section Title</span>
                <div className="text-xl font-bold text-foreground">Active Forensic Incident: INC-2026-9041</div>
                <div className="text-sm font-semibold text-foreground-secondary mt-1">Observed Attack Path & MITRE TTP Vectors</div>
              </div>
              <Divider />
              <div>
                <span className="text-[10px] font-mono uppercase text-foreground-muted block mb-1">Numerical Monospace Technical Readouts</span>
                <div className="flex flex-wrap gap-4 font-mono text-xs">
                  <span className="p-2 rounded bg-surface-secondary border border-border">Risk: 92.4%</span>
                  <span className="p-2 rounded bg-surface-secondary border border-border">Confidence: 0.985</span>
                  <span className="p-2 rounded bg-surface-secondary border border-border">Port: 443/TCP</span>
                  <span className="p-2 rounded bg-surface-secondary border border-border">Duration: 142ms</span>
                  <span className="p-2 rounded bg-surface-secondary border border-border">Throughput: 42.1 MB/s</span>
                </div>
              </div>
            </div>
          </Panel>
        </div>
      )}

      {/* TAB 2: SECURITY PRIMITIVES */}
      {activeTab === 'security' && (
        <div className="space-y-8">
          {/* ThreatScore Component Variants */}
          <Panel title="Threat Score & Risk Assessment Primitives (Section 47)">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <span className="text-xs font-mono font-semibold text-foreground-muted block mb-2">
                  Detailed Card Representation:
                </span>
                <ThreatScore
                  score={84}
                  severity="CRITICAL"
                  confidence="VERY_HIGH"
                  confidenceScore={0.94}
                  variant="card"
                />
              </div>

              <div>
                <span className="text-xs font-mono font-semibold text-foreground-muted block mb-2">
                  Unknown / Inconclusive State (Section 49):
                </span>
                <ThreatScore
                  score={null}
                  severity="UNKNOWN"
                  confidence="UNCALIBRATED"
                  variant="card"
                />
              </div>
            </div>

            <div className="mt-4 pt-4 border-t border-border flex flex-wrap items-center gap-3">
              <span className="text-xs font-mono text-foreground-muted">Compact Strip:</span>
              <ThreatScore score={72} severity="HIGH" confidence="HIGH" confidenceScore={0.81} variant="compact" />
              <ThreatScore score={15} severity="SAFE" confidence="VERY_HIGH" confidenceScore={0.98} variant="compact" />
            </div>
          </Panel>

          {/* Severity & Confidence Indicators */}
          <Panel title="Severity Indicators & Confidence Tiers (Icon + Text WCAG AA)">
            <div className="space-y-4">
              <div>
                <span className="text-xs font-mono text-foreground-muted block mb-2">Severity Tiers (Pulse on High/Critical):</span>
                <div className="flex flex-wrap gap-2.5">
                  <SeverityIndicator severity="CRITICAL" pulse />
                  <SeverityIndicator severity="HIGH" pulse />
                  <SeverityIndicator severity="MEDIUM" />
                  <SeverityIndicator severity="LOW" />
                  <SeverityIndicator severity="SAFE" />
                  <SeverityIndicator severity="INFO" />
                  <SeverityIndicator severity="UNKNOWN" />
                </div>
              </div>

              <Divider />

              <div>
                <span className="text-xs font-mono text-foreground-muted block mb-2">Confidence Tiers (Visually Secondary):</span>
                <div className="flex flex-wrap gap-2.5">
                  <ConfidenceIndicator tier="VERY_HIGH" score={0.95} />
                  <ConfidenceIndicator tier="HIGH" score={0.78} />
                  <ConfidenceIndicator tier="MEDIUM" score={0.55} />
                  <ConfidenceIndicator tier="LOW" score={0.3} />
                  <ConfidenceIndicator tier="UNCALIBRATED" />
                </div>
              </div>

              <Divider />

              <div>
                <span className="text-xs font-mono text-foreground-muted block mb-2">Risk Badges (Section 24 & 46):</span>
                <div className="flex flex-wrap items-center gap-2.5">
                  <RiskBadge score={92} severity="CRITICAL" pulse variant="detailed" />
                  <RiskBadge score={74} severity="HIGH" variant="compact" />
                  <RiskBadge score={45} severity="MEDIUM" variant="compact" />
                  <RiskBadge score={12} severity="SAFE" variant="minimal" />
                  <RiskBadge severity="UNKNOWN" variant="compact" />
                </div>
              </div>
            </div>
          </Panel>

          {/* IOCs, Entity Chips, Provenance, & Identifiers */}
          <Panel title="Forensic Indicators & Technical Values (Section 50–52)">
            <div className="space-y-4">
              <div>
                <span className="text-xs font-mono text-foreground-muted block mb-2">Entity Chips:</span>
                <div className="flex flex-wrap gap-2">
                  <EntityChip type="user" value="alex.vance@defense.gov" copyable />
                  <EntityChip type="ip" value="192.168.1.105" copyable />
                  <EntityChip type="domain" value="update.microsoft-security-auth.top" copyable />
                  <EntityChip type="host" value="WKSTN-FIN-09" copyable />
                  <EntityChip type="process" value="rundll32.exe" copyable />
                  <EntityChip type="mitre" value="T1566.002" label="MITRE" copyable />
                </div>
              </div>

              <Divider />

              <div>
                <span className="text-xs font-mono text-foreground-muted block mb-2">Defanged IOC Values with Reputation:</span>
                <div className="flex flex-wrap gap-2">
                  <IndicatorValue
                    value="http://evil-c2-server.com/beacon.php"
                    type="URL"
                    reputation="malicious"
                    defang
                  />
                  <IndicatorValue
                    value="45.142.214.18"
                    type="IPv4"
                    reputation="suspicious"
                    defang
                  />
                  <IndicatorValue
                    value="1.1.1.1"
                    type="DNS"
                    reputation="benign"
                  />
                </div>
              </div>

              <Divider />

              <div>
                <span className="text-xs font-mono text-foreground-muted block mb-2">Telemetry Provenance & Evidence Counts:</span>
                <div className="flex flex-wrap items-center gap-3">
                  <SourceBadge source="Sysmon" detector="ProcessCreate" version="14.1" />
                  <SourceBadge source="AWS CloudTrail" type="cloud" detector="GuardDuty" />
                  <SourceBadge source="Zeek Network" type="network" />
                  <EvidenceCount total={14} variant="detailed" />
                  <EvidenceCount supporting={12} refuting={2} variant="split" />
                  <Timestamp date="2026-10-09T14:30:00Z" copyable />
                </div>
              </div>

              <Divider />

              <div>
                <span className="text-xs font-mono text-foreground-muted block mb-2">Technical Value Display (Monospace, Truncated, Copyable):</span>
                <div className="flex flex-wrap items-center gap-3">
                  <TechnicalValue
                    value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                    type="hash"
                    truncateLength={24}
                  />
                  <TechnicalValue
                    value="7f3a8b19-2045-4bb8-8687-f823a9d2c180"
                    type="uuid"
                    truncate="middle"
                  />
                  <TechnicalValue
                    value="api_key_hidden_secret_12345"
                    mask
                  />
                </div>
              </div>
            </div>
          </Panel>
        </div>
      )}

      {/* TAB 3: UI PRIMITIVES */}
      {activeTab === 'ui' && (
        <div className="space-y-8">
          {/* Button System */}
          <Panel title="Button System & States (Section 20)">
            <div className="space-y-4">
              <div className="flex flex-wrap items-center gap-3">
                <Button variant="primary">Primary Action</Button>
                <Button variant="secondary">Secondary Action</Button>
                <Button variant="outline">Outline Action</Button>
                <Button variant="ghost">Ghost Action</Button>
                <Button variant="danger">Danger Action</Button>
                <Button variant="primary" isLoading>Processing</Button>
                <Button variant="secondary" disabled>Disabled Action</Button>
              </div>

              <div className="flex items-center gap-3">
                <IconButton icon={<Copy className="w-4 h-4" />} aria-label="Copy item" />
                <IconButton icon={<ExternalLink className="w-4 h-4" />} variant="primary" aria-label="Open link" />
                <IconButton icon={<AlertTriangle className="w-4 h-4" />} variant="danger" aria-label="Warning action" />
                <Tooltip content="Tooltip helper text preview">
                  <Button variant="secondary" size="sm">Hover for Tooltip</Button>
                </Tooltip>
              </div>
            </div>
          </Panel>

          {/* Metrics & Cards */}
          <Panel title="Metrics & Cards (Section 19)">
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <Metric
                label="Observed Telemetry Throughput"
                value="48.2 MB/s"
                icon={<Cpu className="w-4 h-4" />}
                change={{ value: '+12%', trend: 'up', label: 'vs baseline' }}
              />
              <Metric
                label="Active Threat Alerts"
                value="14"
                change={{ value: '-4', trend: 'down', label: 'mitigated' }}
              />
              <Metric
                label="Target Enrolled Endpoints"
                value="128"
              />
            </div>

            <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-4">
              <Card>
                <div className="text-sm font-semibold text-foreground mb-1">Forensic Memory Analysis Card</div>
                <div className="text-[11px] font-mono text-foreground-muted mb-3">Automated inspection result</div>
                <p className="text-xs text-foreground-secondary leading-relaxed">
                  Memory mapping completed with zero unhandled memory violations. 1 anomalous thread injected into Explorer PID 482.
                </p>
              </Card>

              <Card>
                <div className="text-sm font-semibold text-foreground mb-1">Timeline Sequence Preview</div>
                <div className="text-[11px] font-mono text-foreground-muted mb-3">Ordered forensic events</div>
                <div className="space-y-1">
                  <TimelineItem
                    timestamp="14:22:00"
                    title="Process Injected"
                    subtitle="lsass.exe targeted by unverified DLL"
                  />
                  <TimelineItem
                    timestamp="14:22:15"
                    title="Credential Dump"
                    subtitle="Encrypted payload sent over port 8443"
                    isLast
                  />
                </div>
              </Card>
            </div>
          </Panel>

          {/* Form Controls */}
          <Panel title="Form Controls & Inputs (Section 22)">
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              <Input
                label="Target IP / Hostname"
                placeholder="10.0.0.1 or domain.corp"
                helperText="IPv4, IPv6, or FQDN acceptable"
              />

              <SearchInput
                value={searchVal}
                onChangeValue={setSearchVal}
                placeholder="Search threat memory..."
              />

              <Select
                label="Classification Tier"
                options={[
                  { value: 'critical', label: 'Tier 1 - Critical Severity' },
                  { value: 'high', label: 'Tier 2 - High Risk' },
                  { value: 'triage', label: 'Tier 3 - Standard Triage' },
                ]}
              />

              <div className="space-y-2">
                <span className="text-xs font-semibold text-foreground-secondary block">Checkboxes & Switches:</span>
                <Checkbox
                  id="chk1"
                  label="Enforce Cryptographic Verification"
                  description="Block unsigned executables from execution"
                  checked={checkboxVal}
                  onChange={(e) => setCheckboxVal(e.target.checked)}
                />
                <Switch
                  checked={switchVal}
                  onChange={(e) => setSwitchVal(e.target.checked)}
                  label="Real-time Stream Interception"
                  description="Forward events immediately to SOC"
                />
              </div>

              <div className="space-y-2">
                <RadioGroup label="Telemetry Ingress Mode">
                  <Radio
                    id="r1"
                    name="source_mode"
                    checked={radioVal === 'agent'}
                    onChange={() => setRadioVal('agent')}
                    label="CyberGuard Agent Telemetry"
                    description="Encrypted mTLS host events"
                  />
                  <Radio
                    id="r2"
                    name="source_mode"
                    checked={radioVal === 'syslog'}
                    onChange={() => setRadioVal('syslog')}
                    label="Remote RFC-5424 Syslog"
                    description="Standard network perimeter relay"
                  />
                </RadioGroup>
              </div>

              <div className="space-y-2">
                <span className="text-xs font-semibold text-foreground-secondary block">Metadata Tags:</span>
                <div className="flex flex-wrap gap-1.5">
                  {tags.map((tag) => (
                    <Tag
                      key={tag}
                      onRemove={() => setTags(tags.filter((t) => t !== tag))}
                    >
                      {tag}
                    </Tag>
                  ))}
                </div>
              </div>

              <div className="md:col-span-2 lg:col-span-3">
                <Textarea
                  label="Analyst Investigation Log"
                  placeholder="Record forensic notes, hypotheses, and indicators..."
                  value={notesVal}
                  onChange={(e) => setNotesVal(e.target.value)}
                  rows={2}
                />
              </div>
            </div>
          </Panel>

          {/* Accordion & Progressive Disclosure */}
          <Panel title="Progressive Disclosure & Drawers (Section 44–45)">
            <div className="flex gap-4 mb-4">
              <Button variant="secondary" onClick={() => setModalOpen(true)}>
                Test Modal Dialog
              </Button>
              <Button variant="secondary" onClick={() => setDrawerOpen(true)}>
                Test Forensic Drawer
              </Button>
            </div>

            <Accordion>
              <AccordionItem id="item-1" title="1. What Happened? (Executive Summary)" defaultOpen>
                <p className="text-xs text-foreground-secondary leading-relaxed">
                  Host WKSTN-FIN-09 generated an anomalous memory-injection event targeting process lsass.exe.
                  Attack behavior matches MITRE ATT&CK T1003.001.
                </p>
              </AccordionItem>
              <AccordionItem id="item-2" title="2. How Serious? (Risk & Blast Radius)">
                <p className="text-xs text-foreground-secondary leading-relaxed">
                  Calculated Risk Score: 88/100 (CRITICAL). 3 secondary endpoints within subnet 10.0.12.0/24 show matching network beacon patterns.
                </p>
              </AccordionItem>
              <AccordionItem id="item-3" title="3. Forensic Evidence (Low-Level Indicators)">
                <p className="text-xs text-foreground-secondary leading-relaxed font-mono">
                  SHA-256: 4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a
                  Parent PID: 1248 (powershell.exe) &rarr; Target PID: 884 (lsass.exe)
                </p>
              </AccordionItem>
            </Accordion>
          </Panel>
        </div>
      )}

      {/* TAB 4: TABLES & DENSITY */}
      {activeTab === 'tables' && (
        <div className="space-y-8">
          <Panel
            title="SOC Forensic Table (Section 25–26)"
            subtitle="Dense security layout maximizing information signal-to-noise ratio."
            actions={
              <div className="flex items-center space-x-2">
                <Switch
                  checked={denseMode}
                  onChange={(e) => setDenseMode(e.target.checked)}
                  label="Dense Mode"
                  size="sm"
                />
              </div>
            }
          >
            <Table compact={denseMode}>
              <TableHeader>
                <TableRow>
                  {tableColumns.map((col) => (
                    <TableHead key={col}>{col}</TableHead>
                  ))}
                </TableRow>
              </TableHeader>
              <TableBody>
                {tableData.map((row, idx) => (
                  <TableRow key={idx}>
                    <TableCell>{row.severity}</TableCell>
                    <TableCell>{row.event}</TableCell>
                    <TableCell>{row.source}</TableCell>
                    <TableCell>{row.target}</TableCell>
                    <TableCell>{row.confidence}</TableCell>
                    <TableCell>{row.timestamp}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </Panel>

          {/* Key-Value DataList */}
          <Panel title="Structured Forensics Key-Value Inspector (DataList)">
            <DataList
              dense={denseMode}
              items={[
                { label: 'Incident Identifier', value: <TechnicalValue value="INC-2026-10492" type="id" /> },
                { label: 'Assigned Analyst', value: 'Security Operator 04' },
                { label: 'Containment Action', value: <StatusIndicator status="warning" label="ISOLATING HOST" /> },
                { label: 'Observed Telemetry Records', value: '42,891 events' },
              ]}
            />
          </Panel>
        </div>
      )}

      {/* TAB 5: STATES & FEEDBACK */}
      {activeTab === 'states' && (
        <div className="space-y-8">
          {/* Alerts & Notifications */}
          <Panel title="Inline Alerts & System Feedback">
            <div className="space-y-3">
              <Alert variant="danger" title="Active Host Compromise">
                Immediate remediation required: An unauthorized token was generated by an unverified binary.
              </Alert>
              <Alert variant="warning" title="Elevated Activity Spike">
                Telemetry ingestion rate exceeded 12,000 events/sec. Rate throttling applied.
              </Alert>
              <Alert variant="info" title="Threat Intelligence Sync Complete">
                4,200 new C2 domain signatures updated from AlienVault OTX and MISP feeds.
              </Alert>
              <Alert variant="success" title="Endpoint Isolation Succeeded">
                Device WKSTN-FIN-09 successfully contained from external network communications.
              </Alert>
            </div>
          </Panel>

          {/* Progress & Loading States */}
          <Panel title="Progress & Local Loading UI (Section 40)">
            <div className="space-y-4">
              <div>
                <span className="text-xs font-mono text-foreground-muted block mb-1">Investigation Progress (72%):</span>
                <Progress value={72} variant="danger" />
              </div>
              <div>
                <span className="text-xs font-mono text-foreground-muted block mb-1">Baseline Modeling (Indeterminate):</span>
                <Progress indeterminate variant="primary" />
              </div>
              <Divider />
              <div>
                <span className="text-xs font-mono text-foreground-muted block mb-2">Skeleton Placeholder Loaders:</span>
                <div className="space-y-2">
                  <Skeleton className="h-4 w-3/4" />
                  <Skeleton className="h-4 w-1/2" />
                </div>
              </div>
              <Divider />
              <LoadingState message="Synchronizing threat memory from distributed nodes..." size="sm" />
            </div>
          </Panel>

          {/* Empty & Error States */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <Panel title="Empty State (Section 41)">
              <EmptyState
                icon={<Shield className="w-8 h-8 text-foreground-muted" />}
                title="No Active Threats Observed"
                description="All telemetry feeds are within normal behavioral baselines."
              />
            </Panel>

            <Panel title="Error State with Progressive Disclosure (Section 42)">
              <ErrorState
                title="Failed to Reach Telemetry Pipeline"
                message="Unable to establish WebSocket connection to Kafka ingress broker."
                onRetry={() => alert('Retrying connection...')}
              />
            </Panel>
          </div>
        </div>
      )}

      {/* Test Modal */}
      <Modal
        isOpen={modalOpen}
        onClose={() => setModalOpen(false)}
      >
        <ModalHeader>
          <ModalTitle>Forensic Confirmation</ModalTitle>
        </ModalHeader>
        <ModalBody>
          <div className="space-y-3 text-xs">
            <p className="text-foreground-secondary">
              Are you sure you want to isolate endpoint <strong className="text-foreground">WKSTN-FIN-09</strong> from the network?
              This will terminate all non-management socket connections.
            </p>
          </div>
        </ModalBody>
        <ModalFooter>
          <Button variant="ghost" onClick={() => setModalOpen(false)}>
            Cancel
          </Button>
          <Button variant="danger" onClick={() => setModalOpen(false)}>
            Confirm Isolation
          </Button>
        </ModalFooter>
      </Modal>

      {/* Test Drawer */}
      <Drawer
        isOpen={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        title="Forensic Evidence Detail"
        size="md"
      >
        <div className="space-y-4 text-xs font-mono">
          <div className="p-3 rounded bg-surface-secondary border border-border">
            <span className="text-[10px] text-foreground-muted uppercase block mb-1">Memory Offset</span>
            <span className="text-foreground">0x00007FF7B40A1000</span>
          </div>
          <div className="p-3 rounded bg-surface-secondary border border-border">
            <span className="text-[10px] text-foreground-muted uppercase block mb-1">Process Tree</span>
            <span className="text-foreground">explorer.exe (482) &rarr; cmd.exe (1094) &rarr; powershell.exe (1248)</span>
          </div>
        </div>
      </Drawer>
    </div>
  );
};

export default DesignSystemPreview;
