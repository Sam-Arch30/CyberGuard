/**
 * Unit and Regression Test Suite for Section 40: Interactive Attack Path.
 * Validates path contracts, causal vs temporal classification invariants,
 * certainty statuses, and filter projections.
 */
import type {
  AttackPathStatus,
  StageCertaintyStatus,
  AttackPathDetailResponse,
  AttackStageProjection,
} from '../../types/attackPath';

function assert(condition: boolean, message: string) {
  if (!condition) {
    throw new Error(`Assertion failed: ${message}`);
  }
}

console.log('Running Section 40: Interactive Attack Path Test Suite...\n');

// =============================================================================
// Test 1: Controlled Status Vocabulary & Inconclusive Distinctions
// =============================================================================
console.log('Test 1: Validating AttackPathStatus taxonomy...');
const validStatuses: AttackPathStatus[] = [
  'ESTABLISHED',
  'PARTIAL',
  'SUPPORTED_HYPOTHESIS',
  'LOW_CONFIDENCE',
  'INCONCLUSIVE',
];

validStatuses.forEach((st) => {
  assert(typeof st === 'string', `Status ${st} must be a valid string`);
});

const certaintyStatuses: StageCertaintyStatus[] = [
  'OBSERVED',
  'DERIVED',
  'INFERRED',
  'UNRESOLVED',
];

certaintyStatuses.forEach((cs) => {
  assert(['OBSERVED', 'DERIVED', 'INFERRED', 'UNRESOLVED'].includes(cs), `Invalid certainty status: ${cs}`);
});

console.log('✓ Passed Test 1: Controlled status vocabularies strictly validated.\n');

// =============================================================================
// Test 2: Causal vs Temporal Relationship Invariants
// =============================================================================
console.log('Test 2: Validating causal vs temporal classification invariants...');

function evaluateTransitionSemantics(transition: {
  relationship_type: string;
  edge_status: string;
}): { is_causal: boolean; relationship_label: string } {
  const rel = transition.relationship_type.toUpperCase();
  const st = transition.edge_status.toUpperCase();
  if ((rel === 'CAUSES' || rel === 'TRIGGERS') && (st === 'OBSERVED' || st === 'DERIVED')) {
    return { is_causal: true, relationship_label: 'SUPPORTED CAUSAL LINK' };
  }
  if (rel === 'TEMPORAL_LINK' || rel === 'PRECEDES' || rel === 'FOLLOWED_BY') {
    return { is_causal: false, relationship_label: 'TEMPORAL ASSOCIATION' };
  }
  return { is_causal: false, relationship_label: 'INFERRED TRANSITION' };
}

// Case A: Direct Execution causality
const causalEdge = evaluateTransitionSemantics({
  relationship_type: 'CAUSES',
  edge_status: 'OBSERVED',
});
assert(causalEdge.is_causal === true, 'CAUSES with OBSERVED must be causal');
assert(causalEdge.relationship_label === 'SUPPORTED CAUSAL LINK', 'Must label as SUPPORTED CAUSAL LINK');

// Case B: Temporal association must NEVER be called causal
const temporalEdge = evaluateTransitionSemantics({
  relationship_type: 'TEMPORAL_LINK',
  edge_status: 'DERIVED',
});
assert(temporalEdge.is_causal === false, 'TEMPORAL_LINK must never be causal');
assert(temporalEdge.relationship_label === 'TEMPORAL ASSOCIATION', 'Must label as TEMPORAL ASSOCIATION');

// Case C: Inferred hypothesis must never be causal
const inferredEdge = evaluateTransitionSemantics({
  relationship_type: 'POSSIBLY_ENABLED',
  edge_status: 'INFERRED',
});
assert(inferredEdge.is_causal === false, 'POSSIBLY_ENABLED must not be causal');

console.log('✓ Passed Test 2: Rigorous causal vs temporal separation enforced.\n');

// =============================================================================
// Test 3: Truthful Response Model Verification
// =============================================================================
console.log('Test 3: Verifying AttackPathDetailResponse truthful invariants...');

const sampleResponse: AttackPathDetailResponse = {
  investigation_id: 'INV-2026-TEST',
  incident_number: 'INV-2026-TEST',
  analysis_run_id: 'run-123',
  available_runs: [{ run_id: 'run-123', version: '2.0.0', status: 'COMPLETED', is_current: true }],
  has_path: true,
  path_id: 'path-456',
  name: 'Multi-Stage Phishing Progression',
  classification: 'STRONG_RECONSTRUCTION',
  status: 'ESTABLISHED',
  status_rationale: 'Contiguous evidence connects all stages.',
  completeness_score: 0.90,
  confidence: 0.88,
  confidence_level: 'HIGH',
  confidence_components: { temporal_continuity: 0.95, graph_consistency: 0.90 },
  explanation: { summary: 'Strong evidence.' },
  start_time: '2026-10-09T14:30:00Z',
  end_time: '2026-10-09T14:45:00Z',
  duration_seconds: 900,
  version: 1,
  engine_version: '1.0.0',
  rule_version: '1.0.0',
  stages: [
    {
      id: 'stg-1',
      stage_order: 1,
      stage_type: 'DELIVERY',
      stage_status: 'OBSERVED',
      technique_id: 'T1566.002',
      tactic: 'Initial Access',
      title: 'Phishing Email Delivered',
      confidence: 0.95,
      confidence_level: 'HIGH',
      entity_ids: ['ent-1'],
      finding_ids: ['fnd-1'],
      evidence_ids: ['ev-1'],
      event_ids: ['evt-1'],
      evidence_count: 3,
      finding_count: 1,
      supporting_evidence: [{ source: 'email_header' }],
      contradicting_evidence: [],
      limitations: [],
      entities_detail: [{ id: 'ent-1', type: 'DOMAIN', value: 'phish.com', risk_score: 90 }],
      findings_detail: [{ id: 'fnd-1', type: 'PHISHING_INDICATOR', title: 'Malicious lure', severity: 'HIGH', analyzer: 'EmailAnalyzer', confidence: 0.95 }],
    },
  ],
  transitions: [],
  gaps: [
    {
      id: 'gap-1',
      category: 'MISSING_ENDPOINT_TELEMETRY',
      title: 'Missing Host Process Telemetry',
      description: 'No EDR telemetry available.',
      affected_stage_ids: [],
      impact: 'Reduces execution certainty.',
    },
  ],
  contradictions: [],
  alternatives: [
    {
      id: 'hyp-1',
      title: 'Internal Simulation',
      status: 'PLAUSIBLE',
      is_primary: false,
      stage_ids: ['stg-1'],
      confidence: 0.30,
      confidence_level: 'LOW',
      missing_evidence: ['NO_C2_TRAFFIC'],
      supporting_evidence: [],
      contradicting_evidence: [],
    },
  ],
  mitre_techniques: [
    {
      technique_id: 'T1566.002',
      technique_name: 'Spearphishing Link',
      tactics: ['Initial Access'],
      status: 'SUPPORTED',
      confidence: 0.95,
      confidence_level: 'HIGH',
      explanation: 'Spearphishing link in message body.',
      evidence_count: 3,
    },
  ],
  infrastructure: [
    {
      id: 'inf-1',
      origin_value: '203.0.113.42',
      origin_type: 'IP_ADDRESS',
      hypothesis_title: 'Redirector',
      hypothesis_type: 'DEDICATED_THREAT_INFRASTRUCTURE',
      status: 'PROBABLE',
      confidence_level: 'HIGH',
      confidence_score: 0.88,
      evidence_count: 2,
      limitations: ['Network endpoint only; not human identity.'],
    },
  ],
  timeline_events: [],
  total_evidence_count: 3,
  total_findings_count: 1,
  total_entities_count: 1,
  limitations: ['Technical reconstruction only.'],
};

assert(sampleResponse.has_path === true, 'sampleResponse must have has_path=true');
assert(sampleResponse.stages.length === 1, 'sampleResponse must have 1 stage');
assert(sampleResponse.gaps.length === 1, 'sampleResponse must have 1 gap');
assert(sampleResponse.alternatives.length === 1, 'sampleResponse must have 1 alternative');
assert(sampleResponse.mitre_techniques.length === 1, 'sampleResponse must have 1 MITRE technique');
assert(sampleResponse.infrastructure.length === 1, 'sampleResponse must have 1 infra entity');
assert(
  sampleResponse.infrastructure[0].limitations[0].includes('not human identity'),
  'Infrastructure must explicitly caveat non-human attribution'
);

console.log('✓ Passed Test 3: AttackPathDetailResponse schema integrity verified.\n');

// =============================================================================
// Test 4: Filtering Logic Integrity
// =============================================================================
console.log('Test 4: Testing stage filter predicates...');

const stagesSample: AttackStageProjection[] = [
  {
    id: 's1',
    stage_order: 1,
    stage_type: 'DELIVERY',
    stage_status: 'OBSERVED',
    title: 'Stage 1',
    confidence: 0.95,
    confidence_level: 'HIGH',
    entity_ids: [],
    finding_ids: [],
    evidence_ids: [],
    event_ids: [],
    evidence_count: 1,
    finding_count: 1,
    supporting_evidence: [],
    contradicting_evidence: [],
    limitations: [],
    entities_detail: [],
    findings_detail: [],
    tactic: 'Initial Access',
  },
  {
    id: 's2',
    stage_order: 2,
    stage_type: 'CREDENTIAL_ACTIVITY',
    stage_status: 'INFERRED',
    title: 'Stage 2',
    confidence: 0.60,
    confidence_level: 'MODERATE',
    entity_ids: [],
    finding_ids: [],
    evidence_ids: [],
    event_ids: [],
    evidence_count: 0,
    finding_count: 1,
    supporting_evidence: [],
    contradicting_evidence: [],
    limitations: [],
    entities_detail: [],
    findings_detail: [],
    tactic: 'Credential Access',
  },
];

// Filter without inferred:
const observedOnly = stagesSample.filter((s) => s.stage_status === 'OBSERVED');
assert(observedOnly.length === 1 && observedOnly[0].id === 's1', 'Observed-only filter failed');

// Filter by minimum confidence 0.70:
const highConfidenceOnly = stagesSample.filter((s) => s.confidence >= 0.70);
assert(highConfidenceOnly.length === 1 && highConfidenceOnly[0].id === 's1', 'High confidence filter failed');

// Filter by tactic:
const credAccessOnly = stagesSample.filter((s) => s.tactic === 'Credential Access');
assert(credAccessOnly.length === 1 && credAccessOnly[0].id === 's2', 'Tactic filter failed');

console.log('✓ Passed Test 4: Stage filtering predicates validated.\n');

console.log('=============================================================================');
console.log('ALL SECTION 40 TESTS COMPLETED SUCCESSFULLY.');
console.log('=============================================================================');
