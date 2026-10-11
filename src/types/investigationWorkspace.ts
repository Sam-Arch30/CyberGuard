/**
 * TypeScript Contracts for Section 39: Investigation Workspace.
 * Matches backend Pydantic schemas in backend/schemas/investigation_workspace.py.
 */

import type {
  RiskHeaderSummary,
  FindingResultDetail,
} from './analysisResults';

export type InvestigationWorkspaceSection =
  | 'overview'
  | 'analysis'
  | 'attack-path'
  | 'graph'
  | 'timeline'
  | 'evidence'
  | 'intelligence'
  | 'response'
  | 'report'
  | 'automation';

export type InvestigationStatus =
  | 'NEW'
  | 'OPEN'
  | 'INVESTIGATING'
  | 'CONTAINED'
  | 'RESOLVED'
  | 'CLOSED'
  | 'FALSE_POSITIVE'
  | 'ARCHIVED';

export interface InvestigationSummaryModel {
  investigation_id: string;
  incident_number: string;
  title: string;
  description?: string | null;
  status: InvestigationStatus | string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'SAFE' | 'INFO' | string;
  risk_score?: number | null;
  confidence?: number | null;
  opened_at?: string | null;
  updated_at?: string | null;
  assigned_to?: string | null;
  artifact_name: string;
  artifact_type: string;
  artifact_id?: string | null;
  sha256?: string | null;
}

export interface InvestigationCountsModel {
  findings_count: number;
  evidence_count: number;
  indicators_count: number;
  attack_paths_count: number;
  timeline_events_count: number;
  response_actions_count: number;
  notes_count: number;
}

export interface AnalystNoteModel {
  id: string;
  author: string;
  note_text: string;
  created_at: string;
}

export interface InvestigationWorkspaceSummary {
  investigation: InvestigationSummaryModel;
  risk: RiskHeaderSummary;
  classification: string;
  executive_summary: string;
  status: InvestigationStatus | string;
  counts: InvestigationCountsModel;
  top_findings: FindingResultDetail[];
  attention_items: string[];
  analyst_notes: AnalystNoteModel[];
  last_updated: string;
}

export interface InvestigationStatusUpdate {
  status: InvestigationStatus | string;
  reason?: string;
  analyst?: string;
}

export interface InvestigationNoteCreate {
  note_text: string;
  author?: string;
}

export interface InvestigationEvidenceItem {
  id: string;
  name: string;
  evidence_type: string;
  is_original: boolean;
  sha256?: string | null;
  size_bytes?: number | null;
  source: string;
  observed_at: string;
  confidence: number;
  details: Record<string, unknown>;
}

export interface InvestigationTimelineEventItem {
  id: string;
  timestamp: string;
  event_type: string;
  title: string;
  description: string;
  severity: string;
  source: string;
  confidence: number;
  evidence_ref?: string | null;
}
