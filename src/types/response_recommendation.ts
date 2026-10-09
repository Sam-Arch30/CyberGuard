/**
 * TypeScript Interfaces for Section 28: Response Recommendation Engine.
 */

export type ActionCategory =
  | 'IMMEDIATE'
  | 'CONTAINMENT'
  | 'INVESTIGATION'
  | 'EVIDENCE_PRESERVATION'
  | 'IDENTITY_SECURITY'
  | 'NETWORK_SECURITY'
  | 'ENDPOINT_SECURITY'
  | 'COMMUNICATION'
  | 'RECOVERY'
  | 'FOLLOW_UP';

export type ActionType =
  // Investigation
  | 'REVIEW_EVIDENCE'
  | 'REVIEW_HEADERS'
  | 'INSPECT_URL'
  | 'INSPECT_ATTACHMENT'
  | 'REVIEW_AUTHENTICATION'
  | 'REVIEW_ENDPOINT_TELEMETRY'
  | 'REVIEW_NETWORK_ACTIVITY'
  | 'EXPAND_ATTACK_PATH'
  | 'CORRELATE_RELATED_EVENTS'
  // Containment
  | 'QUARANTINE_FILE'
  | 'ISOLATE_DEVICE'
  | 'BLOCK_URL'
  | 'BLOCK_DOMAIN'
  | 'BLOCK_IP'
  | 'DISABLE_ACCOUNT'
  | 'REVOKE_SESSION'
  | 'REVOKE_CREDENTIAL'
  // Credential / Identity
  | 'FORCE_PASSWORD_RESET'
  | 'REQUIRE_MFA_REAUTHENTICATION'
  | 'REVIEW_MFA_SETTINGS'
  | 'REVIEW_PRIVILEGED_ACCESS'
  // Communication
  | 'NOTIFY_USER'
  | 'NOTIFY_SECURITY_TEAM'
  | 'ESCALATE_INCIDENT'
  | 'NOTIFY_SYSTEM_OWNER'
  // Recovery
  | 'RESTORE_FROM_KNOWN_GOOD_STATE'
  | 'REMOVE_MALICIOUS_ARTIFACT'
  | 'REVERSE_UNAUTHORIZED_CHANGE'
  // Evidence Preservation
  | 'PRESERVE_ARTIFACT'
  | 'PRESERVE_LOGS'
  | 'PRESERVE_NETWORK_TELEMETRY'
  | 'PRESERVE_EMAIL'
  | 'PRESERVE_FORENSIC_SNAPSHOT';

export type RecommendationPriority = 'P0' | 'P1' | 'P2' | 'P3' | 'P4';

export type RecommendationUrgency = 'IMMEDIATE' | 'URGENT' | 'SOON' | 'NORMAL' | 'DEFERRED';

export type Applicability = 'APPLICABLE' | 'NOT_APPLICABLE' | 'UNKNOWN' | 'NOT_READY';

export type Reversibility = 'REVERSIBLE' | 'PARTIALLY_REVERSIBLE' | 'IRREVERSIBLE' | 'UNKNOWN';

export type OperationalImpact = 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'UNKNOWN';

export type SafetyClass = 'INFORMATIONAL' | 'LOW_IMPACT' | 'REVERSIBLE' | 'CONTAINMENT' | 'HIGH_IMPACT' | 'DESTRUCTIVE';

export type ExecutionMode = 'MANUAL' | 'AUTOMATED_VIA_PLAYBOOK' | 'HUMAN_IN_THE_LOOP';

export type RecommendationStatus =
  | 'GENERATED'
  | 'REVIEW_REQUIRED'
  | 'APPROVED'
  | 'REJECTED'
  | 'EXPIRED'
  | 'SUPERSEDED'
  | 'DEFERRED';

export type CapabilityState = 'AVAILABLE' | 'UNAVAILABLE' | 'UNKNOWN' | 'DISABLED' | 'REQUIRES_CONFIGURATION';

export interface AffectedEntity {
  entity_type: string;
  identifier: string;
  role: string;
  evidence_ref?: string;
}

export interface PrerequisiteItem {
  name: string;
  description: string;
  satisfied: boolean;
  remedy?: string;
}

export interface ConflictItem {
  conflicting_recommendation_id: string;
  conflicting_action_type: string;
  tradeoff_explanation: string;
}

export interface ResponseRecommendation {
  id: string;
  workspace_id: string;
  scope_type: string;
  scope_id: string;
  incident_id?: string;
  threat_event_id?: string;
  risk_assessment_id?: string;
  explanation_id?: string;

  action_type: ActionType;
  category: ActionCategory;
  title: string;
  description: string;
  rationale: string;

  priority: RecommendationPriority;
  urgency: RecommendationUrgency;
  expected_effect: string;

  prerequisites: PrerequisiteItem[];
  affected_entities: AffectedEntity[];
  evidence_refs: string[];
  risk_refs: string[];
  attack_path_refs: string[];
  mitre_refs: string[];

  confidence: number;
  confidence_level: string;

  applicability: Applicability;
  applicability_reason: string;

  reversibility: Reversibility;
  impact: OperationalImpact;

  approval_required: boolean;
  safety_class: SafetyClass;
  execution_mode: ExecutionMode;

  status: RecommendationStatus;
  status_reason?: string;
  reviewed_by?: string;
  reviewed_at?: string;

  recommendation_version: number;
  superseded_by_id?: string;

  depends_on: string[];
  conflicts_with: ConflictItem[];
  metadata: Record<string, any>;

  created_at: string;
  updated_at: string;
  expires_at?: string;
}

export interface ResponseCapability {
  id: string;
  workspace_id: string;
  action_type: ActionType;
  provider: string;
  environment: string;
  enabled: boolean;
  reversible: boolean;
  approval_required: boolean;
  capability_state: CapabilityState;
  state_reason?: string;
  configuration: Record<string, any>;
  created_at: string;
  updated_at: string;
}

export interface ResponseWorkspaceOverview {
  workspace_id: string;
  scope_type: string;
  scope_id: string;
  total_count: number;
  by_priority: Record<string, number>;
  by_category: Record<string, number>;
  by_status: Record<string, number>;
  pending_approval_count: number;
  recommendations: ResponseRecommendation[];
}
