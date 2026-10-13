import { apiFetch } from '../utils/apiClient';
/**
 * Frontend client service for Section 42: Report Workspace.
 * Interacts with /api/investigations/:id/report and /api/reports endpoints.
 */
import { apiUrl, extractErrorMessage } from '../utils/apiClient';
import type {
  ReportDetail,
  ReportListItem,
  ReportComparison,
  InvestigationReportGenerateRequest,
  InvestigationReportPreviewRequest,
} from '../types/report';

export const reportService = {
  /**
   * Retrieves the current report projection for an investigation.
   * Returns latest persisted report or a live draft projection.
   */
  async getInvestigationReport(investigationId: string): Promise<ReportDetail> {
    const res = await apiFetch(apiUrl(`/api/investigations/${encodeURIComponent(investigationId)}/report`));
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to fetch report for investigation '${investigationId}' (${res.status})`);
    }
    return res.json();
  },

  /**
   * Generates a new immutable, reproducible report version (e.g. v1, v2) for an investigation.
   */
  async generateInvestigationReport(
    investigationId: string,
    req: InvestigationReportGenerateRequest
  ): Promise<ReportDetail> {
    const res = await apiFetch(
      apiUrl(`/api/investigations/${encodeURIComponent(investigationId)}/report/generate`),
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(req),
      }
    );
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to generate report for investigation '${investigationId}' (${res.status})`);
    }
    return res.json();
  },

  /**
   * Generates an ephemeral preview report projection with custom options without persisting.
   */
  async previewInvestigationReport(
    investigationId: string,
    req: InvestigationReportPreviewRequest
  ): Promise<ReportDetail> {
    const res = await apiFetch(
      apiUrl(`/api/investigations/${encodeURIComponent(investigationId)}/report/preview`),
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(req),
      }
    );
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to preview report for investigation '${investigationId}' (${res.status})`);
    }
    return res.json();
  },

  /**
   * Lists all historical report versions (v1, v2...) generated for an investigation.
   */
  async getInvestigationReports(investigationId: string): Promise<ReportListItem[]> {
    const res = await apiFetch(
      apiUrl(`/api/investigations/${encodeURIComponent(investigationId)}/reports`)
    );
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to fetch report history for '${investigationId}' (${res.status})`);
    }
    return res.json();
  },

  /**
   * Lists all reports in the platform catalog.
   */
  async listReports(limit = 50, offset = 0, search = '', severity = ''): Promise<{ reports: ReportListItem[]; total: number }> {
    const params = new URLSearchParams({
      limit: String(limit),
      offset: String(offset),
    });
    if (search) params.set('search', search);
    if (severity) params.set('severity', severity);

    const res = await apiFetch(apiUrl(`/api/reports?${params.toString()}`));
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to fetch reports (${res.status})`);
    }
    return res.json();
  },

  /**
   * Retrieves full details and snapshot of a specific report by ID.
   */
  async getReportById(reportId: string): Promise<ReportDetail> {
    const res = await apiFetch(apiUrl(`/api/reports/${encodeURIComponent(reportId)}`));
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to fetch report '${reportId}' (${res.status})`);
    }
    return res.json();
  },

  /**
   * Downloads official ReportLab vector PDF report.
   */
  async downloadPdf(reportId: string, filename?: string): Promise<void> {
    const res = await apiFetch(apiUrl(`/api/reports/${encodeURIComponent(reportId)}/download`));
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to download PDF for report '${reportId}' (${res.status})`);
    }
    const blob = await res.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename || `CyberGuard_Report_${reportId}.pdf`;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
  },

  /**
   * Downloads authoritative JSON snapshot bundle.
   */
  async downloadJson(reportId: string, filename?: string): Promise<void> {
    const res = await apiFetch(apiUrl(`/api/reports/${encodeURIComponent(reportId)}/json`));
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to download JSON for report '${reportId}' (${res.status})`);
    }
    const blob = await res.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename || `CyberGuard_Report_${reportId}.json`;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
  },

  /**
   * Compares two report versions to expose diffs in risk, findings, stages, etc.
   */
  async compareReports(r1Id: string, r2Id: string): Promise<ReportComparison> {
    const res = await apiFetch(
      apiUrl(`/api/reports/${encodeURIComponent(r1Id)}/compare/${encodeURIComponent(r2Id)}`)
    );
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to compare reports (${res.status})`);
    }
    return res.json();
  },
};
