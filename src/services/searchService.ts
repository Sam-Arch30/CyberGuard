import { apiFetch } from '../utils/apiClient';
/**
 * Frontend client service for Section 43: History & Search.
 * Interacts with /api/search and /api/investigations endpoints.
 */
import { apiUrl, extractErrorMessage } from '../utils/apiClient';
import type {
  SearchResponse,
  CrossInvestigationIndicatorResponse,
  InvestigationListResponse,
} from '../types/search';

export interface SearchOptions {
  q?: string;
  types?: string[];
  risk?: string[];
  severity?: string[];
  status?: string[];
  source?: string[];
  fromTime?: string;
  toTime?: string;
  limit?: number;
  offset?: number;
}

export interface InvestigationListOptions {
  q?: string;
  risk?: string | string[];
  severity?: string | string[];
  status?: string | string[];
  source_type?: string | string[];
  source?: string | string[];
  classification?: string | string[];
  time_range?: string;
  fromTime?: string;
  toTime?: string;
  sort_by?: string;
  sort_order?: 'asc' | 'desc';
  sort?: string;
  page?: number;
  page_size?: number;
  limit?: number;
  offset?: number;
}

export const searchService = {
  /**
   * Executes unified global search across investigations, reports, indicators, evidence, and threat memory.
   */
  async search(
    queryOrOptions: string | SearchOptions,
    options: SearchOptions = {}
  ): Promise<SearchResponse> {
    let q = '';
    let opts = options;
    if (typeof queryOrOptions === 'string') {
      q = queryOrOptions;
    } else {
      q = queryOrOptions.q || '';
      opts = { ...queryOrOptions, ...options };
    }

    const params = new URLSearchParams();
    if (q) params.set('q', q);

    if (opts.types && opts.types.length > 0) {
      opts.types.forEach((t) => params.append('types', t));
    }
    if (opts.risk && opts.risk.length > 0) {
      opts.risk.forEach((r) => params.append('risk', r));
    }
    if (opts.severity && opts.severity.length > 0) {
      opts.severity.forEach((s) => params.append('severity', s));
    }
    if (opts.status && opts.status.length > 0) {
      opts.status.forEach((st) => params.append('status', st));
    }
    if (opts.source && opts.source.length > 0) {
      opts.source.forEach((src) => params.append('source', src));
    }
    if (opts.fromTime) params.set('from_time', opts.fromTime);
    if (opts.toTime) params.set('to_time', opts.toTime);
    if (opts.limit !== undefined) params.set('limit', String(opts.limit));
    if (opts.offset !== undefined) params.set('offset', String(opts.offset));

    const res = await apiFetch(apiUrl(`/api/search?${params.toString()}`));
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Search failed (${res.status})`);
    }
    const data = await res.json();
    return data;
  },

  /**
   * Performs deep cross-investigation lookup for any indicator with Threat Memory and provenance.
   */
  async lookupIndicator(value: string): Promise<CrossInvestigationIndicatorResponse> {
    const res = await apiFetch(apiUrl(`/api/search/indicator/${encodeURIComponent(value)}`));
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Indicator lookup failed (${res.status})`);
    }
    return res.json();
  },

  /**
   * Lists historical investigations with query, filters, facets, and pagination.
   */
  async listInvestigations(options: InvestigationListOptions = {}): Promise<InvestigationListResponse> {
    const params = new URLSearchParams();
    if (options.q) params.set('q', options.q);

    // Support single string or array of filters
    const appendMulti = (key: string, val?: string | string[]) => {
      if (!val) return;
      if (Array.isArray(val)) {
        val.forEach((v) => {
          if (v && v !== 'ALL') params.append(key, v);
        });
      } else if (val !== 'ALL') {
        params.set(key, val);
      }
    };

    appendMulti('risk', options.risk);
    appendMulti('severity', options.severity);
    appendMulti('status', options.status);
    appendMulti('source', options.source_type || options.source);
    appendMulti('classification', options.classification);

    // Time window
    if (options.time_range && options.time_range !== 'all') {
      const now = new Date();
      let fromDate: Date | null = null;
      if (options.time_range === '24h') {
        fromDate = new Date(now.getTime() - 24 * 60 * 60 * 1000);
      } else if (options.time_range === '7d') {
        fromDate = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
      } else if (options.time_range === '30d') {
        fromDate = new Date(now.getTime() - 30 * 24 * 60 * 1000);
      } else if (options.time_range === '90d') {
        fromDate = new Date(now.getTime() - 90 * 24 * 60 * 1000);
      }
      if (fromDate) {
        params.set('from_time', fromDate.toISOString());
      }
    } else if (options.fromTime) {
      params.set('from_time', options.fromTime);
    }
    if (options.toTime) params.set('to_time', options.toTime);

    // Sorting
    if (options.sort) {
      params.set('sort', options.sort);
    } else if (options.sort_by) {
      params.set('sort', `${options.sort_by}:${options.sort_order || 'desc'}`);
    }

    // Pagination
    const pageSize = options.page_size || options.limit || 15;
    const pageNum = options.page || 1;
    const offset = options.offset !== undefined ? options.offset : (pageNum - 1) * pageSize;

    params.set('limit', String(pageSize));
    params.set('offset', String(offset));

    const res = await apiFetch(apiUrl(`/api/investigations?${params.toString()}`));
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to fetch investigations (${res.status})`);
    }
    const data: InvestigationListResponse = await res.json();
    data.page = pageNum;
    data.page_size = pageSize;
    data.total_pages = Math.max(1, Math.ceil((data.total || 0) / pageSize));
    return data;
  },
};
