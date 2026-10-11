/**
 * Section 68: Evidence & Forensics Workspace Client Service.
 * Provides typed HTTP communication with backend forensic APIs:
 * - Evidence inventory, cryptographic hashes, and integrity checks
 * - Safe bounded previews (Text & Hex Dump)
 * - Chain of Custody ledger & preservation hold management
 * - Child derivative evidence lineage & signed export manifest packaging
 */
import { apiUrl } from '../utils/apiClient';
import type {
  EvidenceDetail,
  EvidenceExportManifestResponse,
  EvidenceIntegrityVerificationResponse,
  EvidenceListResponse,
  EvidenceMetrics,
  EvidencePreviewResponse,
  EvidenceRegistrationPayload,
  EvidenceDerivationPayload,
  CustodyEventType,
} from '../types/evidenceWorkspace';

const BASE_PREFIX = '/api/v1/evidence';

const defaultHeaders = (workspaceId = 'default', role = 'analyst'): HeadersInit => ({
  'Content-Type': 'application/json',
  'X-Workspace-Id': workspaceId,
  'X-Role': role,
});

export const evidenceWorkspaceService = {
  /**
   * Lists forensic evidence with search, pagination, and multi-dimensional filters.
   */
  async listEvidence(params?: {
    source_type?: string;
    integrity_status?: string;
    classification?: string;
    preservation_status?: string;
    case_id?: string;
    investigation_id?: string;
    query?: string;
    page?: number;
    page_size?: number;
    workspaceId?: string;
  }): Promise<EvidenceListResponse> {
    const sp = new URLSearchParams();
    if (params?.source_type) sp.set('source_type', params.source_type);
    if (params?.integrity_status) sp.set('integrity_status', params.integrity_status);
    if (params?.classification) sp.set('classification', params.classification);
    if (params?.preservation_status) sp.set('preservation_status', params.preservation_status);
    if (params?.case_id) sp.set('case_id', params.case_id);
    if (params?.investigation_id) sp.set('investigation_id', params.investigation_id);
    if (params?.query) sp.set('q', params.query);
    if (params?.page) sp.set('page', String(params.page));
    if (params?.page_size) sp.set('page_size', String(params.page_size));

    const queryStr = sp.toString() ? `?${sp.toString()}` : '';
    const res = await fetch(apiUrl(`${BASE_PREFIX}${queryStr}`), {
      headers: defaultHeaders(params?.workspaceId),
    });
    if (!res.ok) {
      const err = await res.text();
      throw new Error(`Failed to list evidence: ${err}`);
    }
    return res.json();
  },

  /**
   * Retrieves aggregate metrics for evidence distribution, verification and preservation.
   */
  async getMetrics(workspaceId = 'default'): Promise<EvidenceMetrics> {
    const res = await fetch(apiUrl(`${BASE_PREFIX}/metrics/summary`), {
      headers: defaultHeaders(workspaceId),
    });
    if (!res.ok) {
      const err = await res.text();
      throw new Error(`Failed to fetch evidence metrics: ${err}`);
    }
    return res.json();
  },

  /**
   * Retrieves authoritative detail of a specific evidence record.
   */
  async getDetail(evidenceId: string, workspaceId = 'default'): Promise<EvidenceDetail> {
    const res = await fetch(apiUrl(`${BASE_PREFIX}/${encodeURIComponent(evidenceId)}`), {
      headers: defaultHeaders(workspaceId),
    });
    if (!res.ok) {
      const err = await res.text();
      throw new Error(`Failed to fetch evidence detail: ${err}`);
    }
    return res.json();
  },

  /**
   * Safely previews evidence content without risk of browser execution.
   */
  async getPreview(evidenceId: string, maxBytes = 8192, workspaceId = 'default'): Promise<EvidencePreviewResponse> {
    const res = await fetch(apiUrl(`${BASE_PREFIX}/${encodeURIComponent(evidenceId)}/preview?max_bytes=${maxBytes}`), {
      headers: defaultHeaders(workspaceId),
    });
    if (!res.ok) {
      const err = await res.text();
      throw new Error(`Failed to preview evidence: ${err}`);
    }
    return res.json();
  },

  /**
   * Triggers cryptographic hash reverification on demand.
   */
  async verifyIntegrity(evidenceId: string, workspaceId = 'default'): Promise<EvidenceIntegrityVerificationResponse> {
    const res = await fetch(apiUrl(`${BASE_PREFIX}/${encodeURIComponent(evidenceId)}/verify`), {
      method: 'POST',
      headers: defaultHeaders(workspaceId),
    });
    if (!res.ok) {
      const err = await res.text();
      throw new Error(`Failed to verify evidence integrity: ${err}`);
    }
    return res.json();
  },

  /**
   * Updates preservation hold status with required justification.
   */
  async setPreservation(
    evidenceId: string,
    payload: { preservation_status: 'NORMAL' | 'PRESERVED' | 'ON_HOLD'; reason: string; notes?: string },
    workspaceId = 'default'
  ): Promise<EvidenceDetail> {
    const res = await fetch(apiUrl(`${BASE_PREFIX}/${encodeURIComponent(evidenceId)}/preserve`), {
      method: 'POST',
      headers: defaultHeaders(workspaceId),
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.text();
      throw new Error(`Failed to set preservation status: ${err}`);
    }
    return res.json();
  },

  /**
   * Appends an immutable chain of custody record.
   */
  async addCustodyEvent(
    evidenceId: string,
    payload: {
      event_type: CustodyEventType;
      source?: string;
      destination?: string;
      reason: string;
      notes?: string;
    },
    workspaceId = 'default'
  ): Promise<any> {
    const res = await fetch(apiUrl(`${BASE_PREFIX}/${encodeURIComponent(evidenceId)}/custody`), {
      method: 'POST',
      headers: defaultHeaders(workspaceId),
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.text();
      throw new Error(`Failed to add custody event: ${err}`);
    }
    return res.json();
  },

  /**
   * Links evidence to a Case or Investigation.
   */
  async linkEvidence(
    evidenceId: string,
    payload: { case_id?: string; investigation_id?: string; reason?: string },
    workspaceId = 'default'
  ): Promise<EvidenceDetail> {
    const res = await fetch(apiUrl(`${BASE_PREFIX}/${encodeURIComponent(evidenceId)}/link`), {
      method: 'POST',
      headers: defaultHeaders(workspaceId),
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.text();
      throw new Error(`Failed to link evidence: ${err}`);
    }
    return res.json();
  },

  /**
   * Adds an analyst forensic note to the evidence.
   */
  async addNote(
    evidenceId: string,
    payload: { note_text: string; category?: string },
    workspaceId = 'default'
  ): Promise<EvidenceDetail> {
    const res = await fetch(apiUrl(`${BASE_PREFIX}/${encodeURIComponent(evidenceId)}/notes`), {
      method: 'POST',
      headers: defaultHeaders(workspaceId),
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.text();
      throw new Error(`Failed to add forensic note: ${err}`);
    }
    return res.json();
  },

  /**
   * Creates derived child evidence preserving provenance lineage.
   */
  async deriveEvidence(
    evidenceId: string,
    payload: EvidenceDerivationPayload,
    workspaceId = 'default'
  ): Promise<EvidenceDetail> {
    const res = await fetch(apiUrl(`${BASE_PREFIX}/${encodeURIComponent(evidenceId)}/derive`), {
      method: 'POST',
      headers: defaultHeaders(workspaceId),
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.text();
      throw new Error(`Failed to derive evidence: ${err}`);
    }
    return res.json();
  },

  /**
   * Generates a signed legal/forensic export manifest package.
   */
  async exportManifest(evidenceId: string, workspaceId = 'default'): Promise<EvidenceExportManifestResponse> {
    const res = await fetch(apiUrl(`${BASE_PREFIX}/${encodeURIComponent(evidenceId)}/export-manifest`), {
      headers: defaultHeaders(workspaceId),
    });
    if (!res.ok) {
      const err = await res.text();
      throw new Error(`Failed to generate export manifest: ${err}`);
    }
    return res.json();
  },

  /**
   * Registers evidence via JSON payload.
   */
  async registerJson(payload: EvidenceRegistrationPayload, workspaceId = 'default'): Promise<EvidenceDetail> {
    const res = await fetch(apiUrl(`${BASE_PREFIX}/register`), {
      method: 'POST',
      headers: defaultHeaders(workspaceId),
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.text();
      throw new Error(`Failed to register evidence: ${err}`);
    }
    return res.json();
  },

  /**
   * Uploads an artifact file directly via multipart form-data.
   */
  async uploadFile(formData: FormData, workspaceId = 'default'): Promise<EvidenceDetail> {
    const res = await fetch(apiUrl(`${BASE_PREFIX}/upload`), {
      method: 'POST',
      headers: {
        'X-Workspace-Id': workspaceId,
        'X-Role': 'analyst',
      },
      body: formData,
    });
    if (!res.ok) {
      const err = await res.text();
      throw new Error(`Failed to upload evidence file: ${err}`);
    }
    return res.json();
  },

  /**
   * Generates direct download URL with safety attachment parameters.
   */
  getDownloadUrl(evidenceId: string): string {
    return apiUrl(`${BASE_PREFIX}/${encodeURIComponent(evidenceId)}/download`);
  },
};
