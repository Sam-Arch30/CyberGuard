import { apiFetch } from '../utils/apiClient';
/**
 * Universal Ingestion Service.
 * Centralized API client for submitting files, URLs, text, and security telemetry
 * to the CyberGuard Universal Ingestion Gateway.
 *
 * Security Guarantee:
 * Never performs outbound network fetching of user-provided URLs in the browser.
 * Relies strictly on backend SSRF-safe analysis boundaries.
 */

import { apiUrl, extractErrorMessage, getAuthToken, getWorkspaceId } from '../utils/apiClient';
import type {
  IngestionResult,
  DetectedInput,
  AnalyzerCapabilityRead,
} from '../types/ingestion';

export interface IngestionOptions {
  notes?: string;
  caseId?: string;
  incidentId?: string;
  source?: string;
  submittedBy?: string;
}

export class IngestionService {
  /**
   * Submits a single file to the Universal Ingestion Gateway.
   * Supports .eml, PDF, binaries, images, audio, video, archives, and log dumps.
   */
  static async ingestFile(
    file: File,
    options?: IngestionOptions,
    onProgress?: (percent: number) => void
  ): Promise<IngestionResult> {
    const formData = new FormData();
    formData.append('file', file, file.name);

    if (options?.notes) formData.append('notes', options.notes);
    if (options?.caseId) formData.append('case_id', options.caseId);
    if (options?.incidentId) formData.append('incident_id', options.incidentId);
    if (options?.source) formData.append('source', options.source);

    // If XMLHttpRequest is supported and onProgress is provided, use it for genuine upload progress tracking
    if (onProgress && typeof XMLHttpRequest !== 'undefined') {
      return new Promise<IngestionResult>((resolve, reject) => {
        const xhr = new XMLHttpRequest();
        xhr.open('POST', apiUrl('/api/ingest'));
        xhr.setRequestHeader('X-Workspace-ID', getWorkspaceId());
        const token = getAuthToken();
        if (token) xhr.setRequestHeader('Authorization', `Bearer ${token}`);
        xhr.timeout = 120000;
        xhr.ontimeout = () => reject(new Error('Upload processing timed out. Check the backend before retrying.'));
        xhr.onabort = () => reject(new Error('Upload was cancelled.'));

        xhr.upload.onprogress = (event) => {
          if (event.lengthComputable) {
            const percent = Math.round((event.loaded / event.total) * 100);
            onProgress(percent);
          }
        };

        xhr.onload = () => {
          if (xhr.status >= 200 && xhr.status < 300) {
            try {
              const data = JSON.parse(xhr.responseText);
              resolve(data as IngestionResult);
            } catch (err) {
              reject(new Error(`Failed to parse ingestion response: ${String(err)}`));
            }
          } else {
            let errorMsg = `HTTP ${xhr.status}: Upload failed`;
            try {
              const errJson = JSON.parse(xhr.responseText);
              if (errJson.detail) {
                errorMsg = typeof errJson.detail === 'string' ? errJson.detail : JSON.stringify(errJson.detail);
              }
            } catch {
              if (xhr.responseText) errorMsg = xhr.responseText.slice(0, 200);
            }
            reject(new Error(errorMsg));
          }
        };

        xhr.onerror = () => {
          reject(new Error('Network failure: Unable to reach CyberGuard ingestion gateway.'));
        };

        xhr.send(formData);
      });
    }

    // Standard fetch fallback
    const res = await apiFetch(apiUrl('/api/ingest'), {
      method: 'POST',
      body: formData,
    });

    if (!res.ok) {
      const detail = await extractErrorMessage(res, 'File ingestion failed');
      throw new Error(detail);
    }

    return (await res.json()) as IngestionResult;
  }

  /**
   * Ingests raw text, URLs, domains, IPs, or structured JSON events.
   * SSRF-safe: URL string is sent to backend for isolated processing.
   */
  static async ingestText(
    text: string,
    options?: IngestionOptions
  ): Promise<IngestionResult> {
    const trimmed = text.trim();
    if (!trimmed) {
      throw new Error('Input text cannot be empty.');
    }

    // Check if input is a structured JSON event
    let payload: Record<string, unknown> = {
      text: trimmed,
      source: options?.source || 'TEXT_INPUT',
      notes: options?.notes,
      case_id: options?.caseId,
      incident_id: options?.incidentId,
    };

    if (
      (trimmed.startsWith('{') && trimmed.endsWith('}')) ||
      (trimmed.startsWith('[') && trimmed.endsWith(']'))
    ) {
      try {
        const parsed = JSON.parse(trimmed);
        if (typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)) {
          payload = {
            event: parsed,
            source: options?.source || 'STRUCTURED_EVENT',
            notes: options?.notes,
            case_id: options?.caseId,
            incident_id: options?.incidentId,
          };
        }
      } catch {
        // Not valid JSON, keep as standard text
      }
    }

    const res = await apiFetch(apiUrl('/api/ingest'), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      const detail = await extractErrorMessage(res, 'Text ingestion failed');
      throw new Error(detail);
    }

    return (await res.json()) as IngestionResult;
  }

  /**
   * Pre-flight classification query without persistence.
   * Used for reactive UI type badge hints before submission.
   */
  static async detectInput(text: string): Promise<DetectedInput> {
    const res = await apiFetch(apiUrl('/api/ingest/detect'), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ text }),
    });

    if (!res.ok) {
      const detail = await extractErrorMessage(res, 'Input detection failed');
      throw new Error(detail);
    }

    return (await res.json()) as DetectedInput;
  }

  /**
   * Retrieves platform analyzer capabilities and their operational status.
   */
  static async getCapabilities(): Promise<AnalyzerCapabilityRead[]> {
    const res = await apiFetch(apiUrl('/api/ingest/capabilities'));
    if (!res.ok) {
      return [];
    }
    return (await res.json()) as AnalyzerCapabilityRead[];
  }
}
