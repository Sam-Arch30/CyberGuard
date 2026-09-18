/**
 * MailTraceAI - Unified Enterprise API Client
 *
 * Provides standardized, typed HTTP access to all backend FastAPI endpoints.
 * Uses relative paths (/api/...) that work across development proxies and production builds.
 * Preserves strict data integrity with ZERO mock fallbacks.
 */

export class ApiError extends Error {
  status: number;
  errorCode?: string;
  detail?: any;

  constructor(message: string, status: number, errorCode?: string, detail?: any) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.errorCode = errorCode;
    this.detail = detail;
  }
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const url = path.startsWith('http') ? path : path.startsWith('/') ? path : `/${path}`;
  const headers = new Headers(options.headers || {});

  if (!headers.has('Accept')) {
    headers.set('Accept', 'application/json');
  }

  // Set Content-Type to application/json only if not FormData or explicitly set
  if (options.body && !(options.body instanceof FormData) && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }

  let response: Response;
  try {
    response = await fetch(url, { ...options, headers });
  } catch (netErr: any) {
    throw new ApiError(
      netErr?.message ? `Network request failed: ${netErr.message}` : 'Network error connecting to forensic API',
      0
    );
  }

  if (!response.ok) {
    let errorDetail: any = null;
    let errorCode: string | undefined;
    let message = `API request failed with status ${response.status}`;

    try {
      const errorJson = await response.json();
      errorDetail = errorJson;
      if (typeof errorJson.detail === 'string') {
        message = errorJson.detail;
      } else if (errorJson.message) {
        message = errorJson.message;
      }
      errorCode = errorJson.error_code;
    } catch {
      try {
        const text = await response.text();
        if (text) message = text;
      } catch {
        // Fallback to generic message
      }
    }

    throw new ApiError(message, response.status, errorCode, errorDetail);
  }

  // Handle empty responses (204 No Content, etc.)
  if (response.status === 204) {
    return {} as T;
  }

  const contentType = response.headers.get('content-type') || '';
  if (contentType.includes('application/json')) {
    return (await response.json()) as T;
  }

  return (await response.text()) as unknown as T;
}

export const api = {
  /* ── Dashboard & Metrics ────────────────────────────────── */
  dashboard: {
    getSummary: (days = 30, recentLimit = 5) =>
      request<any>(`/api/dashboard/summary?days=${days}&recent_limit=${recentLimit}`),
    getEmails: (skip = 0, limit = 20) =>
      request<{ items: any[]; total: number; skip: number; limit: number }>(
        `/api/dashboard/emails?skip=${skip}&limit=${limit}`
      ),
  },

  /* ── Email Ingestion & Analysis ─────────────────────────── */
  email: {
    analyze: async (fileOrBlob: Blob, filename = 'email.eml', user = 'SOC Analyst') => {
      const formData = new FormData();
      formData.append('file', fileOrBlob, filename);
      return request<any>('/api/emails/analyze', {
        method: 'POST',
        headers: {
          'X-User': user,
        },
        body: formData,
      });
    },
    getAnalysis: (id: string) => request<any>(`/api/emails/${encodeURIComponent(id)}/analysis`),
    getTimeline: (identifier: string) => request<any>(`/api/emails/${encodeURIComponent(identifier)}/timeline`),
    mlClassify: (subject: string, body: string) =>
      request<any>('/api/emails/ml-classify', {
        method: 'POST',
        body: JSON.stringify({ subject, body }),
      }),
    aiAnalyst: (analysis: any) =>
      request<any>('/api/emails/ai-analyst', {
        method: 'POST',
        body: JSON.stringify(analysis),
      }),
    calculateThreatScore: (analysis: any) =>
      request<any>('/api/emails/calculate-threat-score', {
        method: 'POST',
        body: JSON.stringify(analysis),
      }),
    getInvestigationGraph: (analysis: any) =>
      request<any>('/api/emails/investigation-graph', {
        method: 'POST',
        body: JSON.stringify(analysis),
      }),
    filterInvestigationGraph: (graph: any, nodeTypes: string[]) =>
      request<any>('/api/emails/investigation-graph/filter', {
        method: 'POST',
        body: JSON.stringify({ graph, node_types: nodeTypes }),
      }),
    lookupIp: (ip: string) => request<any>(`/api/emails/lookup/${encodeURIComponent(ip.trim())}`),
    lookupDomain: (domain: string) =>
      request<any>(`/api/emails/lookup-domain/${encodeURIComponent(domain.trim().toLowerCase())}`),
    detectLookalike: (domain: string) =>
      request<any>(`/api/emails/detect-lookalike/${encodeURIComponent(domain.trim().toLowerCase())}`),
    analyzeUrl: (url: string, visibleText?: string) =>
      request<any>('/api/emails/analyze-url', {
        method: 'POST',
        body: JSON.stringify({ url, visible_text: visibleText }),
      }),
  },

  /* ── Attribution ────────────────────────────────────────── */
  attribution: {
    evaluate: (analysis: any) =>
      request<any>('/api/attribution/evaluate', {
        method: 'POST',
        body: JSON.stringify(analysis),
      }),
  },

  /* ── Cross-Investigation & Correlation ──────────────────── */
  crossInvestigation: {
    analyze: (payload: any) =>
      request<any>('/api/cross-investigation/analyze', {
        method: 'POST',
        body: JSON.stringify(payload),
      }),
    compare: (payload: any) =>
      request<any>('/api/cross-investigation/compare', {
        method: 'POST',
        body: JSON.stringify(payload),
      }),
    recordDecision: (payload: any) =>
      request<any>('/api/cross-investigation/decision', {
        method: 'POST',
        body: JSON.stringify(payload),
      }),
    getDecisions: () => request<any[]>('/api/cross-investigation/decisions'),
    getCorrelation: (minScore = 0.15) =>
      request<any>(`/api/correlation/email?min_score=${minScore}`),
  },

  /* ── Campaign Intelligence ──────────────────────────────── */
  campaigns: {
    getAll: () => request<any[]>('/api/campaigns'),
    getById: (id: string) => request<any>(`/api/campaigns/${encodeURIComponent(id)}`),
    detectAlert: (threshold = 0.45) =>
      request<any>(`/api/campaigns/detect-alert?threshold=${threshold}`),
  },

  /* ── Case Management ────────────────────────────────────── */
  cases: {
    getAll: (params?: { status?: string; severity?: string; search?: string; limit?: number }) => {
      const sp = new URLSearchParams();
      if (params?.status && params.status !== 'ALL') sp.append('status', params.status);
      if (params?.severity && params.severity !== 'ALL') sp.append('severity', params.severity);
      if (params?.search?.trim()) sp.append('search', params.search.trim());
      if (params?.limit) sp.append('limit', String(params.limit));
      const qs = sp.toString();
      return request<any>(`/api/cases${qs ? `?${qs}` : ''}`);
    },
    create: (payload: any) =>
      request<any>('/api/cases', {
        method: 'POST',
        body: JSON.stringify(payload),
      }),
    getById: (id: string) => request<any>(`/api/cases/${encodeURIComponent(id)}`),
    update: (id: string, payload: any) =>
      request<any>(`/api/cases/${encodeURIComponent(id)}`, {
        method: 'PUT',
        body: JSON.stringify(payload),
      }),
    addEmail: (caseId: string, emailId: string) =>
      request<any>(`/api/cases/${encodeURIComponent(caseId)}/emails`, {
        method: 'POST',
        body: JSON.stringify({ email_id: emailId }),
      }),
    removeEmail: (caseId: string, emailId: string) =>
      request<any>(`/api/cases/${encodeURIComponent(caseId)}/emails/${encodeURIComponent(emailId)}`, {
        method: 'DELETE',
      }),
    addNote: (caseId: string, notePayload: any) =>
      request<any>(`/api/cases/${encodeURIComponent(caseId)}/notes`, {
        method: 'POST',
        body: JSON.stringify(notePayload),
      }),
    addFinding: (caseId: string, findingPayload: any) =>
      request<any>(`/api/cases/${encodeURIComponent(caseId)}/findings`, {
        method: 'POST',
        body: JSON.stringify(findingPayload),
      }),
    getCorrelation: (caseId: string) =>
      request<any>(`/api/cases/${encodeURIComponent(caseId)}/correlation`),
    getAttribution: (caseId: string) =>
      request<any>(`/api/cases/${encodeURIComponent(caseId)}/attribution`),
  },

  /* ── Reports ────────────────────────────────────────────── */
  reports: {
    getAll: (limit = 50) => request<any>(`/api/reports?limit=${limit}`),
    generate: (payload: any) =>
      request<any>('/api/reports/generate', {
        method: 'POST',
        body: JSON.stringify(payload),
      }),
    generateCaseReport: (caseId: string) =>
      request<any>(`/api/reports/case/${encodeURIComponent(caseId)}`),
    getDownloadUrl: (reportId: string) => `/api/reports/${encodeURIComponent(reportId)}/download`,
    getPdfUrl: (reportId: string) => `/api/reports/${encodeURIComponent(reportId)}/pdf`,
  },

  /* ── Threat Intelligence & OSINT ────────────────────────── */
  intelligence: {
    getGeolocationStatus: () => request<any>('/api/intelligence/geolocation/status'),
  },

  /* ── Investigation Copilot ──────────────────────────────── */
  copilot: {
    getSuggestedQuestions: (mode = 'email') =>
      request<string[]>(`/api/copilot/suggested-questions?mode=${encodeURIComponent(mode)}`),
    query: (payload: any) =>
      request<any>('/api/copilot/query', {
        method: 'POST',
        body: JSON.stringify(payload),
      }),
    addToReport: (payload: any) =>
      request<any>('/api/copilot/add-to-report', {
        method: 'POST',
        body: JSON.stringify(payload),
      }),
  },

  /* ── Benchmark & Evaluation ─────────────────────────────── */
  benchmark: {
    getLatest: () => request<any>('/api/benchmark/latest'),
    run: (suite = 'standard') =>
      request<any>(`/api/benchmark/run?suite=${encodeURIComponent(suite)}`, {
        method: 'POST',
      }),
    reset: () =>
      request<any>('/api/benchmark/reset', {
        method: 'POST',
      }),
  },
};
