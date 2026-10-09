/**
 * Universal Evidence Ingestion Types for CyberGuard.
 * Strictly aligned with backend schemas in backend/schemas/unified.py.
 */

export type ArtifactType =
  | 'EMAIL'
  | 'URL'
  | 'DOMAIN'
  | 'IP'
  | 'FILE'
  | 'IMAGE'
  | 'AUDIO'
  | 'VIDEO'
  | 'QR'
  | 'AUTH_LOG'
  | 'SERVER_LOG'
  | 'NETWORK_LOG'
  | 'API_LOG'
  | 'TEXT'
  | 'SYSTEM_LOG'
  | 'ENDPOINT_EVENT'
  | 'ATTACHMENT';

export type InputMode = 'FILE_UPLOAD' | 'TEXT_INPUT' | 'STRUCTURED_EVENT';

export type SupportStatus = 'SUPPORTED' | 'PARTIALLY_SUPPORTED' | 'NOT_SUPPORTED';

export type CapabilityStatus = 'AVAILABLE' | 'NOT_CONFIGURED' | 'NOT_IMPLEMENTED';

export type IngestionQueueStatus =
  | 'idle'
  | 'uploading'
  | 'validating'
  | 'accepted'
  | 'queued'
  | 'running'
  | 'completed'
  | 'failed'
  | 'rejected';

export interface DetectedInput {
  input_mode: InputMode;
  artifact_type: ArtifactType;
  detected_mime?: string | null;
  reported_mime?: string | null;
  confidence: number;
  detector: string;
  support_status: SupportStatus;
  warnings: string[];
  candidate_analyzers: string[];
  metadata: Record<string, unknown>;
}

export interface AnalyzerCapabilityRead {
  name: string;
  version: string;
  supported_artifact_types: ArtifactType[];
  status: CapabilityStatus;
  description: string;
}

export interface IngestionResult {
  ingestion_id: string;
  artifact_id: string;
  artifact_type: ArtifactType;
  detected_type?: string;
  input_mode: InputMode;
  name: string;
  original_value?: string | null;
  normalized_value?: string | null;
  sha256?: string | null;
  size?: number | null;
  mime_type?: string | null;
  classification: DetectedInput;
  storage_status: string;
  storage_key?: string | null;
  analysis_status: string;
  candidate_analyzers: string[];
  warnings: string[];
  validation_errors: string[];
  metadata: Record<string, unknown>;
  created_at: string;
  evidence_id?: string | null;
  investigation_id?: string | null;
  analysis_run_id?: string | null;
  duplicate?: boolean;
}

export interface IngestionQueueItem {
  id: string;
  file?: File;
  text?: string;
  displayName: string;
  detectedType?: ArtifactType;
  status: IngestionQueueStatus;
  progress?: number; // 0-100 or undefined for indeterminate
  result?: IngestionResult;
  error?: string;
  warnings?: string[];
  duplicate?: boolean;
}
