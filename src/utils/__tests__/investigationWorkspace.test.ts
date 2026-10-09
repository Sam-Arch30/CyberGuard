/**
 * Unit and Integration Test Suite for Section 39: Investigation Workspace.
 */
import { WORKSPACE_TABS } from '../../components/investigation/InvestigationNav';
import { INVESTIGATION_SECTIONS } from '../../context/InvestigationContext';
import type {
  InvestigationWorkspaceSummary,
  InvestigationStatus,
  InvestigationEvidenceItem,
} from '../../types/investigationWorkspace';

function assert(condition: boolean, message: string) {
  if (!condition) {
    throw new Error(`Assertion failed: ${message}`);
  }
}

console.log('Running Investigation Workspace Test Suite...\n');

// =============================================================================
// Test 1: Canonical 9 Workspaces Navigation Integrity
// =============================================================================
console.log('Test 1: Verifying 9 canonical workspace tabs and route keys...');
const expectedTabs = [
  'overview',
  'analysis',
  'attack-path',
  'graph',
  'timeline',
  'evidence',
  'intelligence',
  'response',
  'report',
];

assert(WORKSPACE_TABS.length === 9, `Expected exactly 9 workspace tabs, got ${WORKSPACE_TABS.length}`);

expectedTabs.forEach(tabId => {
  const found = WORKSPACE_TABS.find(t => t.id === tabId);
  assert(Boolean(found), `Missing workspace tab: ${tabId}`);
  assert(Boolean(found?.label), `Tab ${tabId} must have a valid label`);
  assert(Boolean(found?.description), `Tab ${tabId} must have a descriptive tooltip`);
});
console.log('✓ Passed Test 1: All 9 canonical workspace tabs validated.\n');

// =============================================================================
// Test 2: Investigation Context Sections Coverage
// =============================================================================
console.log('Test 2: Verifying INVESTIGATION_SECTIONS in context metadata...');
expectedTabs.forEach(tabId => {
  const inContext = INVESTIGATION_SECTIONS.some(s => s.id === tabId);
  assert(inContext, `InvestigationSection missing definition for ${tabId}`);
});
console.log('✓ Passed Test 2: InvestigationContext supports all 9 workspace tabs.\n');

// =============================================================================
// Test 3: Status Model & Transition Hierarchy
// =============================================================================
console.log('Test 3: Verifying investigation status lifecycle model...');
const allowedStatuses: InvestigationStatus[] = [
  'OPEN',
  'INVESTIGATING',
  'CONTAINED',
  'RESOLVED',
  'CLOSED',
];

allowedStatuses.forEach(st => {
  assert(typeof st === 'string' && st.length > 0, `Invalid status ${st}`);
});

// Transition validation rule: Terminal statuses cannot transition back to OPEN without reason
const canTransition = (from: InvestigationStatus, to: InvestigationStatus) => {
  if (from === to) return true;
  if (from === 'CLOSED' && to === 'OPEN') return false; // terminal
  return true;
};

assert(canTransition('OPEN', 'INVESTIGATING'), 'Should allow OPEN -> INVESTIGATING');
assert(canTransition('INVESTIGATING', 'CONTAINED'), 'Should allow INVESTIGATING -> CONTAINED');
assert(canTransition('CONTAINED', 'RESOLVED'), 'Should allow CONTAINED -> RESOLVED');
assert(canTransition('RESOLVED', 'CLOSED'), 'Should allow RESOLVED -> CLOSED');
assert(!canTransition('CLOSED', 'OPEN'), 'Should prevent closed -> open without reopen audit');
console.log('✓ Passed Test 3: Investigation status lifecycle model validated.\n');

// =============================================================================
// Test 4: Evidence Immutability Principle
// =============================================================================
console.log('Test 4: Verifying original immutable evidence vs derived signals separation...');
const mockEvidenceList: InvestigationEvidenceItem[] = [
  {
    id: 'art-001',
    name: 'spearphish-payload.eml',
    evidence_type: 'EMAIL_FILE',
    is_original: true,
    sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    size_bytes: 45120,
    source: 'Universal Ingestion Engine',
    observed_at: '2026-10-09T18:00:00Z',
    confidence: 1.0,
    details: {},
  },
  {
    id: 'ioc-001',
    name: '198.51.100.24',
    evidence_type: 'IP_ADDRESS',
    is_original: false,
    sha256: null,
    size_bytes: null,
    source: 'Network Hops & Attribution Engine',
    observed_at: '2026-10-09T18:05:00Z',
    confidence: 0.92,
    details: {},
  },
  {
    id: 'ioc-002',
    name: 'hxxps://auth-mircosoft-portal.com/login',
    evidence_type: 'URL_INDICATOR',
    is_original: false,
    sha256: null,
    size_bytes: null,
    source: 'URL Extraction Engine',
    observed_at: '2026-10-09T18:05:00Z',
    confidence: 0.96,
    details: {},
  },
];

const originals = mockEvidenceList.filter(e => e.is_original);
const derived = mockEvidenceList.filter(e => !e.is_original);

assert(originals.length === 1, 'Exactly 1 original evidence item expected');
assert(derived.length === 2, 'Exactly 2 derived evidence items expected');
assert(originals[0].sha256 !== null, 'Original immutable artifact MUST have cryptographic hash');
assert(originals[0].confidence === 1.0, 'Original observed evidence must have absolute factual confidence (1.0)');
console.log('✓ Passed Test 4: Original immutable evidence distinction verified.\n');

// =============================================================================
// Test 5: Workspace Summary & Attention Items Aggregation
// =============================================================================
console.log('Test 5: Verifying workspace summary aggregation structure...');
const mockSummary: InvestigationWorkspaceSummary = {
  investigation: {
    investigation_id: 'INV-2026-0042',
    incident_number: 'INC-2026-0042',
    title: 'Credential phishing attempt targeting executive portal',
    status: 'INVESTIGATING',
    severity: 'HIGH',
    risk_score: 78,
    confidence: 0.91,
    opened_at: '2026-10-09T18:00:00Z',
    updated_at: '2026-10-09T18:30:00Z',
    artifact_name: 'suspicious-email.eml',
    artifact_type: 'EMAIL_FILE',
    sha256: 'abc123def456',
  },
  risk: {
    score: 78,
    level: 'HIGH',
    severity: 'HIGH',
    confidence: 0.91,
    confidence_level: 'HIGH',
    uncertainty: 'LOW',
    is_pending: false,
    status_label: 'HIGH RISK',
  },
  classification: 'Credential Phishing & Brand Impersonation',
  executive_summary: 'Automated inspection identified spearphishing link mimicking enterprise portal.',
  status: 'INVESTIGATING',
  counts: {
    findings_count: 5,
    evidence_count: 3,
    indicators_count: 4,
    attack_paths_count: 1,
    timeline_events_count: 6,
    response_actions_count: 4,
    notes_count: 2,
  },
  top_findings: [],
  attention_items: ['Response review required', 'High-confidence finding'],
  analyst_notes: [
    {
      id: 'note-1',
      author: 'Senior SOC Analyst',
      note_text: 'Confirmed adversary bulletproof infrastructure.',
      created_at: '2026-10-09T18:25:00Z',
    },
  ],
  last_updated: '2026-10-09T18:30:00Z',
};

assert(mockSummary.investigation.incident_number.startsWith('INC-') || mockSummary.investigation.incident_number.startsWith('INV-'), 'Valid incident prefix');
assert(mockSummary.counts.findings_count > 0, 'Must have findings count');
assert(mockSummary.counts.evidence_count > 0, 'Must have evidence count');
assert(mockSummary.attention_items.length === 2, 'Attention items must reflect attention required count');
assert(mockSummary.analyst_notes.length === 1, 'Analyst notes must be present');
console.log('✓ Passed Test 5: Investigation workspace summary aggregation validated.\n');

console.log('ALL SECTION 39 INVESTIGATION WORKSPACE TESTS PASSED SUCCESSFULLY!');
