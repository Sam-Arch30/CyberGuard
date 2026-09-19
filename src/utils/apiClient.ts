/**
 * MailTraceAI - Centralized Production API Configuration & Client
 *
 * Supports production deployments (e.g. Vercel frontend + Render/Railway backend)
 * via the `VITE_API_BASE_URL` environment variable without hard-coding localhost.
 */

// Resolves base API URL, removing trailing slashes.
// In local Vite development without VITE_API_BASE_URL, defaults to empty string so requests
// hit the relative path (e.g. '/api/...'), which Vite's dev server proxies to the backend.
const rawBase = (import.meta.env.VITE_API_BASE_URL as string | undefined) || '';
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

export default {
  API_BASE_URL,
  apiUrl,
  apiFetch
};
