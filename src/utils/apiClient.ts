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
  const cleanEndpoint = endpoint.startsWith('/') ? endpoint : `/${endpoint}`;
  return API_BASE_URL ? `${API_BASE_URL}${cleanEndpoint}` : cleanEndpoint;
};

/**
 * Standard fetch wrapper that automatically prefixes API_BASE_URL.
 */
export const apiFetch = async (endpoint: string, init?: RequestInit): Promise<Response> => {
  return fetch(apiUrl(endpoint), init);
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
