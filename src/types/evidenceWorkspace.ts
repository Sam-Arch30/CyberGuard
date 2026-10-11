/**
 * Section 68: Evidence & Forensics Workspace Frontend Type Definitions.
 * Authoritative types for forensic evidence lifecycle, cryptographic integrity,
 * chain-of-custody, provenance lineage, safe previews, and legal export packages.
 */

export type EvidenceSourceType =
  | 'EMAIL'
  | 'ATTACHMENT'
  | 'URL'
  | 'FILE'
  | 'NETWORK_FLOW'
  | 'MEMORY_DUMP'
  | 'PROCESS_TRACE'
  | 'TELEMETRY'
  | 'LOG_SEGMENT'
  | 'API_ARTIFACT'
  | 'OTHER';

export type EvidenceCollectionMethod =
  | 'INGESTION_PIPELINE'
  | 'SENSOR_COLLECTOR'
  | 'EDR_AGENT'
  | 'MANUAL_UPLOAD'
  | 'PIVOT_EXTRACTION'
  | 'CARVED_STREAM'
  | 'API';

export type EvidenceClassification =
  | 'PUBLIC'
  | 'INTERNAL'
  | 'CONFIDENTIAL'
  | 'RESTRICTED'
  | 'PII_SENSITIVE'
  | 'LEGAL_PRIVILEGED';

export type EvidenceIntegrityStatus =
  | 'VERIFIED'
  | 'MISMATCH'
  | 'PENDING'
  | 'UNKNOWN';

export type EvidencePreservationStatus =
  | 'NORMAL'
  | 'PRESERVED'
  | 'ON_HOLD';

export type CustodyEventType =
  | 'ACQUIRED'
  | 'TRANSFERRED'
  | 'ACCESSED'
  | 'COPIED'
  | 'MODIFIED_COPY'
  | 'PRESERVED'
  | 'RELEASED'
  | 'VERIFIED'
  | 'EXPORTED'
  | 'DISPOSED';

export interface EvidenceCustodyEvent {
  id: string;
  evidence_id: string;
  event_type: CustodyEventType;
  actor_id: string;
  timestamp: string;
  source?: string | null;
  destination?: string | null;
  reason?: string | null;
  integrity_hash: string;
  metadata?: Record<string, any>;
}

export interface EvidenceProvenanceLineageItem {
  evidence_id: string;
  filename: string;
  sha256: string;
  relation: 'PARENT' | 'CHILD' | 'SELF';
  transformation?: string | null;
  tool?: string | null;
  timestamp: string;
}

export interface EvidenceListItem {
  id: string;
  evidence_id: string;
  sha256: string;
  sha1?: string | null;
  md5?: string | null;
  original_filename: string;
  mime_type: string;
  size: number;
  source_type: EvidenceSourceType;
  collection_method: EvidenceCollectionMethod;
  collector: string;
  collected_at: string;
  classification: EvidenceClassification;
  preservation_status: EvidencePreservationStatus;
  integrity_status: EvidenceIntegrityStatus;
  case_id?: string | null;
  investigation_id?: string | null;
  parent_evidence_id?: string | null;
  findings_count: number;
  last_verified_at?: string | null;
}

export interface EvidenceMetrics {
  total_evidence: number;
  verified_count: number;
  mismatch_count: number;
  pending_count: number;
  preserved_count: number;
  source_distribution: Record<string, number>;
  classification_distribution: Record<string, number>;
}

export interface EvidenceListResponse {
  items: EvidenceListItem[];
  total: number;
  page: number;
  page_size: number;
  metrics: EvidenceMetrics;
}

export interface LinkedFindingItem {
  id: string;
  title: string;
  severity: string;
  status: string;
  finding_type: string;
}

export interface EvidenceDetail {
  id: string;
  evidence_id: string;
  sha256: string;
  sha1?: string | null;
  md5?: string | null;
  original_filename: string;
  mime_type: string;
  size: number;
  storage_reference: string;
  source_type: EvidenceSourceType;
  collection_method: EvidenceCollectionMethod;
  source_reference?: string | null;
  collected_by: string;
  collected_at: string;
  classification: EvidenceClassification;
  retention_policy: string;
  preservation_status: EvidencePreservationStatus;
  preservation_reason?: string | null;
  preservation_actor?: string | null;
  preservation_timestamp?: string | null;
  integrity_status: EvidenceIntegrityStatus;
  last_verified_at?: string | null;
  case_id?: string | null;
  investigation_id?: string | null;
  parent_evidence_id?: string | null;
  derivation_metadata: Record<string, any>;
  metadata: Record<string, any>;
  custody_events: EvidenceCustodyEvent[];
  provenance_lineage: EvidenceProvenanceLineageItem[];
  linked_findings: LinkedFindingItem[];
  forensic_notes: Array<{
    note_id: string;
    actor: string;
    timestamp: string;
    category: string;
    text: string;
  }>;
  evidence_gaps: string[];
}

export interface EvidencePreviewResponse {
  evidence_id: string;
  filename: string;
  mime_type: string;
  size: number;
  preview_type: 'text' | 'hex';
  preview_content: string;
  truncated: boolean;
  byte_offset: number;
  total_preview_bytes: number;
}

export interface EvidenceIntegrityVerificationResponse {
  evidence_id: string;
  match: boolean;
  status: EvidenceIntegrityStatus;
  expected_sha256: string;
  computed_sha256: string;
  verified_at: string;
  verified_by: string;
  message: string;
}

export interface EvidenceExportManifestResponse {
  manifest_id: string;
  evidence_id: string;
  filename: string;
  sha256: string;
  sha1?: string | null;
  md5?: string | null;
  size: number;
  exported_at: string;
  exported_by: string;
  package_hash_sha256: string;
  custody_events_count: number;
  manifest_json: Record<string, any>;
}

export interface EvidenceRegistrationPayload {
  original_filename: string;
  source_type?: EvidenceSourceType;
  collection_method?: EvidenceCollectionMethod;
  source_reference?: string;
  collector?: string;
  classification?: EvidenceClassification;
  case_id?: string;
  investigation_id?: string;
  retention_policy?: string;
  notes?: string;
  raw_content_utf8?: string;
  content_base64?: string;
}

export interface EvidenceDerivationPayload {
  transformation_tool: string;
  tool_version?: string;
  transformation_description: string;
  child_filename: string;
  child_bytes_base64?: string;
  child_raw_text?: string;
  notes?: string;
}
