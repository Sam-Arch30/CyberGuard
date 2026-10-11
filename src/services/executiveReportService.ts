/**
 * Section 69: Executive Reporting & Intelligence Dissemination Client Service.
 */
import { apiUrl, extractErrorMessage } from '../utils/apiClient';
import type {
  ReportTemplate,
  ReportSnapshot,
  ReportShareLink,
  ExecutiveReportDetail,
  ExecutiveReportListItem,
  ExecutiveReportMetrics,
} from '../types/executiveReport';

const API_BASE = '/api/executive-reports';

export const executiveReportService = {
  // Templates
  async listTemplates(reportType?: string): Promise<{ items: ReportTemplate[]; total: number }> {
    const query = reportType ? `?report_type=${encodeURIComponent(reportType)}` : '';
    const res = await fetch(apiUrl(`${API_BASE}/templates${query}`));
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to list templates (${res.status})`);
    }
    return res.json();
  },

  async getTemplate(templateId: string): Promise<ReportTemplate> {
    const res = await fetch(apiUrl(`${API_BASE}/templates/${encodeURIComponent(templateId)}`));
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to fetch template '${templateId}' (${res.status})`);
    }
    return res.json();
  },

  async createTemplate(data: Partial<ReportTemplate>): Promise<ReportTemplate> {
    const res = await fetch(apiUrl(`${API_BASE}/templates`), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to create template (${res.status})`);
    }
    return res.json();
  },

  async updateTemplate(templateId: string, data: Partial<ReportTemplate>): Promise<ReportTemplate> {
    const res = await fetch(apiUrl(`${API_BASE}/templates/${encodeURIComponent(templateId)}`), {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to update template '${templateId}' (${res.status})`);
    }
    return res.json();
  },

  async deleteTemplate(templateId: string): Promise<void> {
    const res = await fetch(apiUrl(`${API_BASE}/templates/${encodeURIComponent(templateId)}`), {
      method: 'DELETE',
    });
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to delete template '${templateId}' (${res.status})`);
    }
  },

  // Reports
  async listReports(
    skip: number = 0,
    limit: number = 50,
    statusFilter?: string,
    reportType?: string,
    severity?: string
  ): Promise<{ items: ExecutiveReportListItem[]; total: number }> {
    const params = new URLSearchParams({
      skip: String(skip),
      limit: String(limit),
    });
    if (statusFilter && statusFilter !== 'ALL') params.set('status', statusFilter);
    if (reportType && reportType !== 'ALL') params.set('report_type', reportType);
    if (severity && severity !== 'ALL') params.set('severity', severity);

    const res = await fetch(apiUrl(`${API_BASE}/reports?${params.toString()}`));
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to list reports (${res.status})`);
    }
    return res.json();
  },

  async getReport(reportId: string): Promise<ExecutiveReportDetail> {
    const res = await fetch(apiUrl(`${API_BASE}/reports/${encodeURIComponent(reportId)}`));
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to fetch report '${reportId}' (${res.status})`);
    }
    return res.json();
  },

  async createReport(data: {
    title: string;
    report_type: string;
    template_key?: string;
    incident_id?: string;
    case_id?: string;
    classification?: string;
    redaction_level?: string;
    summary?: string;
  }): Promise<ExecutiveReportDetail> {
    const res = await fetch(apiUrl(`${API_BASE}/reports`), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to create report (${res.status})`);
    }
    return res.json();
  },

  async updateReport(reportId: string, data: Partial<ExecutiveReportDetail>): Promise<ExecutiveReportDetail> {
    const res = await fetch(apiUrl(`${API_BASE}/reports/${encodeURIComponent(reportId)}`), {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to update report '${reportId}' (${res.status})`);
    }
    return res.json();
  },

  async getReportPreviewHtml(reportId: string, redactionLevel?: string): Promise<string> {
    const query = redactionLevel ? `?redaction_level=${encodeURIComponent(redactionLevel)}` : '';
    const res = await fetch(apiUrl(`${API_BASE}/reports/${encodeURIComponent(reportId)}/preview${query}`));
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to fetch preview for '${reportId}' (${res.status})`);
    }
    return res.text();
  },

  async getReportSnapshots(reportId: string): Promise<ReportSnapshot[]> {
    const res = await fetch(apiUrl(`${API_BASE}/reports/${encodeURIComponent(reportId)}/snapshots`));
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to fetch snapshots for '${reportId}' (${res.status})`);
    }
    return res.json();
  },

  async requestReview(reportId: string, reviewers: string[], note?: string): Promise<ExecutiveReportDetail> {
    const res = await fetch(apiUrl(`${API_BASE}/reports/${encodeURIComponent(reportId)}/review`), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ reviewers, note }),
    });
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to request review for '${reportId}' (${res.status})`);
    }
    return res.json();
  },

  async addReviewNote(reportId: string, note: string, statusText: string = 'COMMENT'): Promise<ExecutiveReportDetail> {
    const res = await fetch(apiUrl(`${API_BASE}/reports/${encodeURIComponent(reportId)}/review-note`), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ note, status: statusText }),
    });
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to add review note for '${reportId}' (${res.status})`);
    }
    return res.json();
  },

  async approveReport(reportId: string, approvalNotes?: string): Promise<ExecutiveReportDetail> {
    const res = await fetch(apiUrl(`${API_BASE}/reports/${encodeURIComponent(reportId)}/approve`), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ approval_notes: approvalNotes }),
    });
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to approve report '${reportId}' (${res.status})`);
    }
    return res.json();
  },

  async finalizeReport(reportId: string, finalizationNotes?: string): Promise<ExecutiveReportDetail> {
    const res = await fetch(apiUrl(`${API_BASE}/reports/${encodeURIComponent(reportId)}/finalize`), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ finalization_notes: finalizationNotes }),
    });
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to finalize report '${reportId}' (${res.status})`);
    }
    return res.json();
  },

  async createVersion(reportId: string): Promise<ExecutiveReportDetail> {
    const res = await fetch(apiUrl(`${API_BASE}/reports/${encodeURIComponent(reportId)}/version`), {
      method: 'POST',
    });
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to create version for '${reportId}' (${res.status})`);
    }
    return res.json();
  },

  // Share Links
  async listShareLinks(reportId: string): Promise<{ items: ReportShareLink[]; total: number }> {
    const res = await fetch(apiUrl(`${API_BASE}/reports/${encodeURIComponent(reportId)}/share-links`));
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to list share links for '${reportId}' (${res.status})`);
    }
    return res.json();
  },

  async createShareLink(
    reportId: string,
    data: {
      format?: string;
      classification?: string;
      redaction_level?: string;
      expires_in_hours?: number;
      max_uses?: number;
    }
  ): Promise<ReportShareLink> {
    const res = await fetch(apiUrl(`${API_BASE}/reports/${encodeURIComponent(reportId)}/share-links`), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to create share link for '${reportId}' (${res.status})`);
    }
    return res.json();
  },

  async revokeShareLink(linkId: string): Promise<ReportShareLink> {
    const res = await fetch(apiUrl(`${API_BASE}/share-links/${encodeURIComponent(linkId)}/revoke`), {
      method: 'POST',
    });
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to revoke share link '${linkId}' (${res.status})`);
    }
    return res.json();
  },

  // Metrics
  async getMetrics(): Promise<ExecutiveReportMetrics> {
    const res = await fetch(apiUrl(`${API_BASE}/metrics`));
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to fetch report metrics (${res.status})`);
    }
    return res.json();
  },
};
