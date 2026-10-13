/**
 * MailTraceAI - Centralized Production API Configuration & Client
 *
 * Supports production deployments (e.g. Vercel frontend + Render/Railway backend)
 * via the `VITE_API_BASE_URL` environment variable without hard-coding localhost.
 */

// Resolves base API URL, removing trailing slashes.
// In local Vite development without VITE_API_BASE_URL, defaults to empty string so requests
// hit the relative path (e.g. '/api/...'), which Vite's dev server proxies to the backend.
const rawBase = (typeof import.meta !== 'undefined' && import.meta.env ? (import.meta.env.VITE_API_BASE_URL as string | undefined) : '') || '';
export const LOCAL_DEMO = import.meta.env.DEV || import.meta.env.VITE_LOCAL_DEMO === 'true';
export const API_BASE_URL: string = rawBase.trim().replace(/\/+$/, '');

/**
 * Constructs a fully-qualified API URL for an endpoint.
 *
 * Examples:
 * - apiUrl('/api/cases') -> 'https://api.mailtrace.com/api/cases' (when VITE_API_BASE_URL is set)
 * - apiUrl('/api/cases') -> '/api/cases' (when VITE_API_BASE_URL is empty, uses local proxy)
 * - apiUrl('api/cases')  -> '/api/cases' (automatically formats leading slash)
 */
export const apiUrl = (endpoint: string): string => {
  if (/^https?:\/\//.test(endpoint)) return endpoint;
  const cleanEndpoint = endpoint.startsWith('/') ? endpoint : `/${endpoint}`;
  return API_BASE_URL ? `${API_BASE_URL}${cleanEndpoint}` : cleanEndpoint;
};

/**
 * Standard fetch wrapper that automatically prefixes API_BASE_URL.
 */
export const apiFetch = async (endpoint: string, init?: RequestInit): Promise<Response> => {
  const target = new URL(apiUrl(endpoint), window.location.origin);
  const allowed = new URL(API_BASE_URL || window.location.origin, window.location.origin);
  if (target.origin !== allowed.origin) throw new Error('Refusing to forward credentials to another origin.');
  const headers = new Headers(init?.headers);
  const token = getAuthToken();
  if (token) headers.set('Authorization', `Bearer ${token}`);
  if (!headers.has('X-Workspace-ID')) headers.set('X-Workspace-ID', getWorkspaceId());
  // Roles and caller identity are always established on the server.
  for (const key of ['X-Role','X-User-Role','X-User','X-Actor-ID','X-User-ID','X-User-Name']) headers.delete(key);
  return fetch(target.toString(), {...init, headers});
};

/**
 * Safely extracts human-readable error messages from fetch responses,
 * handling JSON responses, proxy errors, offline servers, and fallbacks.
 */
export const extractErrorMessage = async (
  res: Response | null,
  defaultMsg: string = 'Analysis request failed'
): Promise<string> => {
  if (!res) {
    return 'Backend server is unreachable. Please verify that the CyberGuard API server is running on http://127.0.0.1:8000.';
  }

  // Clone response so callers can still inspect it if needed
  try {
    const cloned = res.clone();
    const data = await cloned.json();
    if (data) {
      if (typeof data.detail === 'string' && data.detail.trim()) {
        return data.detail.trim();
      }
      if (Array.isArray(data.detail) && data.detail.length > 0) {
        return data.detail.map((d: any) => d.msg || JSON.stringify(d)).join(', ');
      }
      if (typeof data.message === 'string' && data.message.trim()) {
        return data.message.trim();
      }
      if (typeof data.error === 'string' && data.error.trim()) {
        return data.error.trim();
      }
    }
  } catch {
    // Not JSON
  }

  try {
    const text = await res.text();
    if (text && text.trim()) {
      if (text.includes('ECONNREFUSED')) {
        return 'Backend server is not running on http://127.0.0.1:8000 (ECONNREFUSED). Please start the backend.';
      }
      return text.trim();
    }
  } catch {
    // Text extraction failed
  }

  if (res.status === 502 || res.status === 503 || res.status === 504 || res.status === 500) {
    return `Backend server unreachable on port 8000 (HTTP ${res.status}). Please ensure the FastAPI backend is running.`;
  }

  return res.statusText ? `HTTP ${res.status}: ${res.statusText}` : defaultMsg;
};

export default {
  API_BASE_URL,
  apiUrl,
  apiFetch,
  extractErrorMessage,
};

export const getAuthToken = (): string | null => LOCAL_DEMO ? null : sessionStorage.getItem('cyberguard_auth_token');
export const getWorkspaceId = (): string => LOCAL_DEMO ? 'default' : localStorage.getItem('cyberguard_workspace_id') || 'default';
export const setAuthToken = (token: string): void => { sessionStorage.setItem('cyberguard_auth_token', token.trim()); };
export const clearAuthToken = (): void => { sessionStorage.removeItem('cyberguard_auth_token'); };
export const setWorkspaceId = (workspace: string): void => { localStorage.setItem('cyberguard_workspace_id', workspace.trim()); };

export async function apiDownload(endpoint: string): Promise<void> {
  const response = await apiFetch(endpoint);
  if (!response.ok) throw new Error(await extractErrorMessage(response, 'Download failed'));
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  const name = response.headers.get('Content-Disposition')?.match(/filename="([^"\r\n]+)"/)?.[1] || 'CyberGuard_evidence.eml';
  anchor.download = name.replace(/[\\/]/g, '_');
  document.body.appendChild(anchor); anchor.click(); anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}
