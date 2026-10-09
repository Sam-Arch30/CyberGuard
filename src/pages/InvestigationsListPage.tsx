import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import {
  ShieldAlert,
  Plus,
  Briefcase,
  Clock,
  ArrowRight,
  RefreshCw,
  FolderLock,
  X,
  ChevronLeft,
  ChevronRight,
  SlidersHorizontal,
  AlertTriangle,
} from 'lucide-react';
import {
  Button,
  SearchInput,
  Select,
  Panel,
  EmptyState,
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from '../components/ui';
import {
  RiskBadge,
  Timestamp,
} from '../components/security';
import { useInvestigation } from '../context/InvestigationContext';
import { searchService } from '../services/searchService';
import type { InvestigationListItem, SearchFacets } from '../types/search';
import { IndicatorDetailDrawer } from '../components/search';

export const InvestigationsListPage: React.FC = () => {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const { setActiveEmailId, activeEmailId } = useInvestigation();

  // Read URL query params
  const initialQuery = searchParams.get('q') || '';
  const initialRisk = searchParams.getAll('risk');
  const initialStatus = searchParams.getAll('status');
  const initialSource = searchParams.getAll('source');
  const initialSeverity = searchParams.getAll('severity');
  const initialTimeRange = searchParams.get('time_range') || 'all';
  const initialSortBy = searchParams.get('sort_by') || 'updated_at';
  const initialSortOrder = (searchParams.get('sort_order') as 'asc' | 'desc') || 'desc';
  const initialPage = parseInt(searchParams.get('page') || '1', 10);

  // Search & Filter State
  const [query, setQuery] = useState(initialQuery);
  const [debouncedQuery, setDebouncedQuery] = useState(initialQuery);
  const [selectedRisks, setSelectedRisks] = useState<string[]>(initialRisk);
  const [selectedStatuses, setSelectedStatuses] = useState<string[]>(initialStatus);
  const [selectedSources, setSelectedSources] = useState<string[]>(initialSource);
  const [selectedSeverities, setSelectedSeverities] = useState<string[]>(initialSeverity);
  const [timeRange, setTimeRange] = useState<string>(initialTimeRange);
  const [sortBy, setSortBy] = useState<string>(initialSortBy);
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>(initialSortOrder);
  const [page, setPage] = useState<number>(initialPage);
  const pageSize = 15;

  const [showFilters, setShowFilters] = useState<boolean>(false);
  const [drawerIndicator, setDrawerIndicator] = useState<string | null>(null);

  // Response State
  const [items, setItems] = useState<InvestigationListItem[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [totalPages, setTotalPages] = useState<number>(1);
  const [facets, setFacets] = useState<Partial<SearchFacets>>({});
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Debounce query typing
  useEffect(() => {
    const timer = setTimeout(() => {
      setDebouncedQuery(query);
      setPage(1);
    }, 300);
    return () => clearTimeout(timer);
  }, [query]);

  // Synchronize state with URL search params
  const updateUrlParams = useCallback(() => {
    const params = new URLSearchParams();
    if (debouncedQuery.trim()) params.set('q', debouncedQuery.trim());
    selectedRisks.forEach((r) => params.append('risk', r));
    selectedStatuses.forEach((s) => params.append('status', s));
    selectedSources.forEach((src) => params.append('source', src));
    selectedSeverities.forEach((sev) => params.append('severity', sev));
    if (timeRange !== 'all') params.set('time_range', timeRange);
    if (sortBy !== 'updated_at') params.set('sort_by', sortBy);
    if (sortOrder !== 'desc') params.set('sort_order', sortOrder);
    if (page > 1) params.set('page', String(page));

    setSearchParams(params, { replace: true });
  }, [debouncedQuery, selectedRisks, selectedStatuses, selectedSources, selectedSeverities, timeRange, sortBy, sortOrder, page, setSearchParams]);

  // Fetch investigations from backend
  const fetchData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const resp = await searchService.listInvestigations({
        q: debouncedQuery.trim() || undefined,
        risk: selectedRisks.length > 0 ? selectedRisks : undefined,
        severity: selectedSeverities.length > 0 ? selectedSeverities : undefined,
        status: selectedStatuses.length > 0 ? selectedStatuses : undefined,
        source_type: selectedSources.length > 0 ? selectedSources : undefined,
        time_range: timeRange !== 'all' ? timeRange : undefined,
        sort_by: sortBy,
        sort_order: sortOrder,
        page,
        page_size: pageSize,
      });

      setItems(resp.items || []);
      setTotal(resp.total || 0);
      setTotalPages(resp.total_pages || 1);
      setFacets(resp.facets || {});
    } catch (err: any) {
      console.error('Failed to list investigations:', err);
      setError(err.message || 'Failed to load investigations from server');
      setItems([]);
      setTotal(0);
    } finally {
      setLoading(false);
    }
  }, [debouncedQuery, selectedRisks, selectedSeverities, selectedStatuses, selectedSources, timeRange, sortBy, sortOrder, page]);

  useEffect(() => {
    fetchData();
    updateUrlParams();
  }, [fetchData, updateUrlParams]);

  const handleOpenInvestigation = (id: string) => {
    setActiveEmailId(id);
    navigate(`/investigations/${encodeURIComponent(id)}/overview`);
  };

  const handleClearFilters = () => {
    setQuery('');
    setSelectedRisks([]);
    setSelectedStatuses([]);
    setSelectedSources([]);
    setSelectedSeverities([]);
    setTimeRange('all');
    setPage(1);
  };

  const hasActiveFilters = Boolean(
    debouncedQuery ||
    selectedRisks.length > 0 ||
    selectedStatuses.length > 0 ||
    selectedSources.length > 0 ||
    selectedSeverities.length > 0 ||
    timeRange !== 'all'
  );

  return (
    <div className="space-y-6 pb-16 page-enter">
      {/* 1. Header Banner */}
      <div className="bg-surface p-5 sm:p-6 rounded-card border border-border flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2 text-primary font-mono text-xs mb-1 font-semibold uppercase tracking-wider">
            <ShieldAlert className="w-3.5 h-3.5 text-primary" />
            <span>HISTORICAL INVESTIGATION BROWSER & DISCOVERY</span>
          </div>
          <h1 className="text-xl sm:text-2xl font-bold text-foreground font-sans tracking-tight">
            Investigations
          </h1>
          <p className="text-xs text-foreground-muted font-mono mt-1">
            Authoritative persistent records of cyber threat investigations, correlated indicators, and response lifecycles.
          </p>
        </div>

        {/* Action Controls */}
        <div className="flex items-center flex-wrap gap-2.5">
          <Button
            variant="secondary"
            size="sm"
            onClick={() => navigate('/cases')}
            leftIcon={<Briefcase className="w-3.5 h-3.5" />}
          >
            Incident Cases
          </Button>

          <Button
            variant="secondary"
            size="sm"
            onClick={() => navigate('/reports')}
            leftIcon={<Clock className="w-3.5 h-3.5" />}
          >
            Forensic Reports
          </Button>

          <Button
            variant="primary"
            size="sm"
            onClick={() => navigate('/analyze')}
            leftIcon={<Plus className="w-3.5 h-3.5" />}
          >
            Ingest Telemetry
          </Button>
        </div>
      </div>

      {/* 2. Search & Controls Bar */}
      <div className="bg-surface p-3.5 rounded-card border border-border space-y-3">
        <div className="flex flex-col sm:flex-row items-center justify-between gap-3">
          {/* Search Box */}
          <div className="w-full sm:flex-1 relative">
            <SearchInput
              value={query}
              onChangeValue={(v) => setQuery(v)}
              placeholder="Search investigations, indicators, entities, or IDs (e.g. INV-..., domain, SHA-256)..."
              size="sm"
            />
          </div>

          {/* Controls: Filter Toggle, Sort, Refresh */}
          <div className="flex items-center space-x-2 w-full sm:w-auto justify-end">
            <Button
              variant={showFilters ? 'primary' : 'secondary'}
              size="sm"
              onClick={() => setShowFilters(!showFilters)}
              leftIcon={<SlidersHorizontal className="w-3.5 h-3.5" />}
            >
              Filters {hasActiveFilters && '•'}
            </Button>

            <Select
              value={`${sortBy}:${sortOrder}`}
              onChange={(e) => {
                const [sb, so] = e.target.value.split(':');
                setSortBy(sb);
                setSortOrder(so as 'asc' | 'desc');
                setPage(1);
              }}
              options={[
                { value: 'updated_at:desc', label: 'Updated (Recent First)' },
                { value: 'updated_at:asc', label: 'Updated (Oldest First)' },
                { value: 'created_at:desc', label: 'Created (Recent First)' },
                { value: 'risk_score:desc', label: 'Highest Risk' },
              ]}
            />

            <Button
              variant="ghost"
              size="sm"
              onClick={fetchData}
              title="Refresh Records"
              aria-label="Refresh Records"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            </Button>
          </div>
        </div>

        {/* 3. Progressive Disclosure: Filter Dropdowns Panel */}
        {showFilters && (
          <div className="pt-3 border-t border-border grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3 animate-in fade-in duration-150">
            {/* Risk Filter */}
            <div>
              <label className="block text-[11px] font-mono text-foreground-muted mb-1 font-semibold uppercase">
                Risk Level
              </label>
              <div className="flex flex-wrap gap-1.5">
                {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((lvl) => {
                  const count = facets.risk?.[lvl] || 0;
                  const isChecked = selectedRisks.includes(lvl);
                  return (
                    <button
                      key={lvl}
                      type="button"
                      onClick={() => {
                        setSelectedRisks((prev) =>
                          prev.includes(lvl) ? prev.filter((x) => x !== lvl) : [...prev, lvl]
                        );
                        setPage(1);
                      }}
                      className={`px-2 py-0.5 rounded text-[11px] font-mono border transition-colors cursor-pointer ${
                        isChecked
                          ? 'bg-primary/20 border-primary text-primary font-bold'
                          : 'bg-surface-secondary/70 border-border text-foreground-muted hover:text-foreground'
                      }`}
                    >
                      {lvl} {count > 0 && <span className="opacity-70">({count})</span>}
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Status Filter */}
            <div>
              <label className="block text-[11px] font-mono text-foreground-muted mb-1 font-semibold uppercase">
                Status
              </label>
              <div className="flex flex-wrap gap-1.5">
                {['OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'CLOSED'].map((st) => {
                  const count = facets.status?.[st] || 0;
                  const isChecked = selectedStatuses.includes(st);
                  return (
                    <button
                      key={st}
                      type="button"
                      onClick={() => {
                        setSelectedStatuses((prev) =>
                          prev.includes(st) ? prev.filter((x) => x !== st) : [...prev, st]
                        );
                        setPage(1);
                      }}
                      className={`px-2 py-0.5 rounded text-[11px] font-mono border transition-colors cursor-pointer ${
                        isChecked
                          ? 'bg-accent/20 border-accent text-accent font-bold'
                          : 'bg-surface-secondary/70 border-border text-foreground-muted hover:text-foreground'
                      }`}
                    >
                      {st} {count > 0 && <span className="opacity-70">({count})</span>}
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Source Type Filter */}
            <div>
              <label className="block text-[11px] font-mono text-foreground-muted mb-1 font-semibold uppercase">
                Source Type
              </label>
              <div className="flex flex-wrap gap-1.5">
                {['EMAIL', 'URL', 'FILE', 'AUTHENTICATION', 'NETWORK'].map((src) => {
                  const count = facets.source_type?.[src] || 0;
                  const isChecked = selectedSources.includes(src);
                  return (
                    <button
                      key={src}
                      type="button"
                      onClick={() => {
                        setSelectedSources((prev) =>
                          prev.includes(src) ? prev.filter((x) => x !== src) : [...prev, src]
                        );
                        setPage(1);
                      }}
                      className={`px-2 py-0.5 rounded text-[11px] font-mono border transition-colors cursor-pointer ${
                        isChecked
                          ? 'bg-success/20 border-success text-success font-bold'
                          : 'bg-surface-secondary/70 border-border text-foreground-muted hover:text-foreground'
                      }`}
                    >
                      {src} {count > 0 && <span className="opacity-70">({count})</span>}
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Time Range Filter */}
            <div>
              <label className="block text-[11px] font-mono text-foreground-muted mb-1 font-semibold uppercase">
                Time Window
              </label>
              <Select
                value={timeRange}
                onChange={(e) => {
                  setTimeRange(e.target.value);
                  setPage(1);
                }}
                options={[
                  { value: 'all', label: 'All Ingestion History' },
                  { value: '24h', label: 'Past 24 Hours' },
                  { value: '7d', label: 'Past 7 Days' },
                  { value: '30d', label: 'Past 30 Days' },
                  { value: '90d', label: 'Past 90 Days' },
                ]}
              />
            </div>
          </div>
        )}

        {/* 4. Active Filter Chips */}
        {hasActiveFilters && (
          <div className="pt-2 border-t border-border flex items-center flex-wrap gap-1.5 text-xs font-mono">
            <span className="text-[11px] text-foreground-muted mr-1">Active Filters:</span>
            {debouncedQuery && (
              <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded-full bg-surface-secondary border border-border text-foreground text-[11px]">
                <span>q: &quot;{debouncedQuery}&quot;</span>
                <button type="button" onClick={() => setQuery('')} className="hover:text-danger ml-1">
                  <X className="w-3 h-3" />
                </button>
              </span>
            )}
            {selectedRisks.map((r) => (
              <span key={r} className="inline-flex items-center space-x-1 px-2 py-0.5 rounded-full bg-primary/10 border border-primary/30 text-primary text-[11px]">
                <span>Risk: {r}</span>
                <button type="button" onClick={() => setSelectedRisks((p) => p.filter((x) => x !== r))} className="hover:text-danger ml-1">
                  <X className="w-3 h-3" />
                </button>
              </span>
            ))}
            {selectedStatuses.map((s) => (
              <span key={s} className="inline-flex items-center space-x-1 px-2 py-0.5 rounded-full bg-accent/10 border border-accent/30 text-accent text-[11px]">
                <span>Status: {s}</span>
                <button type="button" onClick={() => setSelectedStatuses((p) => p.filter((x) => x !== s))} className="hover:text-danger ml-1">
                  <X className="w-3 h-3" />
                </button>
              </span>
            ))}
            {selectedSources.map((src) => (
              <span key={src} className="inline-flex items-center space-x-1 px-2 py-0.5 rounded-full bg-success/10 border border-success/30 text-success text-[11px]">
                <span>Source: {src}</span>
                <button type="button" onClick={() => setSelectedSources((p) => p.filter((x) => x !== src))} className="hover:text-danger ml-1">
                  <X className="w-3 h-3" />
                </button>
              </span>
            ))}
            {timeRange !== 'all' && (
              <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded-full bg-surface-secondary border border-border text-foreground text-[11px]">
                <span>Time: {timeRange}</span>
                <button type="button" onClick={() => setTimeRange('all')} className="hover:text-danger ml-1">
                  <X className="w-3 h-3" />
                </button>
              </span>
            )}

            <button
              type="button"
              onClick={handleClearFilters}
              className="text-[11px] font-semibold text-danger hover:underline ml-2 cursor-pointer"
            >
              Clear all
            </button>
          </div>
        )}
      </div>

      {/* 5. Error Banner */}
      {error && (
        <div className="p-4 rounded-card bg-danger-surface border border-danger-border text-danger flex items-center justify-between text-xs font-mono">
          <div className="flex items-center space-x-2">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span>{error}</span>
          </div>
          <Button variant="secondary" size="xs" onClick={fetchData}>
            Retry
          </Button>
        </div>
      )}

      {/* 6. Investigations Table */}
      <Panel
        title={`Investigation Records (${total})`}
        subtitle="Forensic evidence dossiers and threat telemetry"
      >
        {loading ? (
          <div className="p-12 text-center text-xs font-mono text-foreground-muted space-y-2">
            <div className="inline-block w-5 h-5 border-2 border-primary border-t-transparent rounded-full animate-spin mb-2" />
            <div>Querying authoritative persistent telemetry...</div>
          </div>
        ) : items.length === 0 ? (
          <EmptyState
            icon={<FolderLock className="w-8 h-8 text-foreground-muted" />}
            title={hasActiveFilters ? 'No Investigations Match Filter Criteria' : 'No Investigations Yet'}
            description={
              hasActiveFilters
                ? 'Try widening the time window, removing specific risk or status filters, or searching an exact indicator.'
                : 'Upload an email, URL, file, log, or media artifact from the Dashboard or Ingest Telemetry to begin.'
            }
            action={
              hasActiveFilters ? (
                <Button variant="secondary" size="sm" onClick={handleClearFilters}>
                  Clear Filters
                </Button>
              ) : (
                <Button
                  variant="primary"
                  size="sm"
                  onClick={() => navigate('/analyze')}
                  leftIcon={<Plus className="w-3.5 h-3.5" />}
                >
                  Ingest New Telemetry
                </Button>
              )
            }
          />
        ) : (
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-24">Risk</TableHead>
                  <TableHead>Investigation / Subject</TableHead>
                  <TableHead className="w-32">Classification</TableHead>
                  <TableHead className="w-24">Source</TableHead>
                  <TableHead className="w-40">Findings & IOCs</TableHead>
                  <TableHead className="w-28">Status</TableHead>
                  <TableHead className="w-36">Last Updated</TableHead>
                  <TableHead className="w-24 text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((inv) => {
                  const isActive = inv.id === activeEmailId;
                  const riskLevel = inv.risk_level || inv.severity || 'LOW';
                  const score = inv.risk_score || 0;

                  return (
                    <TableRow
                      key={inv.id}
                      className={`cursor-pointer transition-colors ${
                        isActive ? 'bg-primary-subtle/40' : 'hover:bg-surface-secondary/60'
                      }`}
                      onClick={() => handleOpenInvestigation(inv.id)}
                    >
                      {/* Risk Badge */}
                      <TableCell>
                        <RiskBadge score={score} severity={riskLevel} size="xs" variant="minimal" />
                      </TableCell>

                      {/* Investigation Subject & ID */}
                      <TableCell>
                        <div className="flex flex-col min-w-0 max-w-sm sm:max-w-md">
                          <div className="flex items-center space-x-2">
                            <span className="font-semibold text-foreground truncate">
                              {inv.title || 'Untitled Investigation'}
                            </span>
                            {isActive && (
                              <span className="text-[9px] font-mono font-bold px-1 rounded bg-primary/20 text-primary">
                                ACTIVE
                              </span>
                            )}
                          </div>
                          <div className="flex items-center space-x-2 text-[10px] font-mono text-foreground-muted mt-0.5">
                            <span className="truncate">ID: {inv.id}</span>
                            {inv.sender && (
                              <span className="truncate hidden sm:inline">• {inv.sender}</span>
                            )}
                          </div>
                        </div>
                      </TableCell>

                      {/* Classification */}
                      <TableCell>
                        <span className="text-[11px] font-mono font-semibold text-foreground px-2 py-0.5 rounded bg-surface-secondary border border-border">
                          {inv.classification || 'UNCLASSIFIED'}
                        </span>
                      </TableCell>

                      {/* Source */}
                      <TableCell>
                        <span className="text-[10px] font-mono text-foreground-muted uppercase">
                          {inv.source_type || 'TELEMETRY'}
                        </span>
                      </TableCell>

                      {/* Findings & Indicators */}
                      <TableCell>
                        <div className="flex flex-col space-y-1">
                          <div className="text-[11px] font-mono text-foreground">
                            <strong>{inv.findings_count}</strong> finding{inv.findings_count !== 1 ? 's' : ''} • <strong>{inv.indicators_count}</strong> IOC{inv.indicators_count !== 1 ? 's' : ''}
                          </div>
                          {inv.sample_indicators && inv.sample_indicators.length > 0 && (
                            <div className="flex flex-wrap gap-1">
                              {inv.sample_indicators.slice(0, 2).map((ioc: string) => (
                                <button
                                  key={ioc}
                                  type="button"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    setDrawerIndicator(ioc);
                                  }}
                                  className="text-[9px] font-mono px-1 py-0.2 rounded bg-surface-secondary/90 hover:bg-surface-secondary text-primary border border-border truncate max-w-[130px] cursor-pointer"
                                  title={`Inspect cross-investigation history for ${ioc}`}
                                >
                                  {ioc}
                                </button>
                              ))}
                            </div>
                          )}
                        </div>
                      </TableCell>

                      {/* Status */}
                      <TableCell>
                        <span
                          className={`text-[9px] font-mono font-bold px-2 py-0.5 rounded-full border ${
                            inv.status === 'INVESTIGATING'
                              ? 'bg-primary/10 border-primary/30 text-primary'
                              : inv.status === 'CONTAINED'
                              ? 'bg-warning/10 border-warning/30 text-warning'
                              : inv.status === 'RESOLVED'
                              ? 'bg-success/10 border-success/30 text-success'
                              : 'bg-surface-secondary border-border text-foreground-muted'
                          }`}
                        >
                          {inv.status}
                        </span>
                      </TableCell>

                      {/* Last Updated */}
                      <TableCell>
                        <Timestamp date={inv.updated_at || inv.created_at} size="xs" />
                      </TableCell>

                      {/* Actions */}
                      <TableCell className="text-right">
                        <Button
                          variant="ghost"
                          size="xs"
                          onClick={(e) => {
                            e.stopPropagation();
                            handleOpenInvestigation(inv.id);
                          }}
                          rightIcon={<ArrowRight className="w-3 h-3" />}
                        >
                          Open
                        </Button>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </div>
        )}

        {/* 7. Server-Side Pagination Bar */}
        {totalPages > 1 && (
          <div className="p-3 border-t border-border flex items-center justify-between text-xs font-mono text-foreground-muted bg-surface-secondary/20">
            <div>
              Showing {items.length > 0 ? (page - 1) * pageSize + 1 : 0}–
              {Math.min(page * pageSize, total)} of {total} records
            </div>

            <div className="flex items-center space-x-2">
              <Button
                variant="secondary"
                size="xs"
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page <= 1 || loading}
                leftIcon={<ChevronLeft className="w-3 h-3" />}
              >
                Previous
              </Button>

              <span className="px-2 py-1 text-[11px] font-mono">
                Page {page} of {totalPages}
              </span>

              <Button
                variant="secondary"
                size="xs"
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                disabled={page >= totalPages || loading}
                rightIcon={<ChevronRight className="w-3 h-3" />}
              >
                Next
              </Button>
            </div>
          </div>
        )}
      </Panel>

      {/* Cross-Investigation Indicator Detail Drawer */}
      <IndicatorDetailDrawer
        indicatorValue={drawerIndicator}
        onClose={() => setDrawerIndicator(null)}
      />
    </div>
  );
};

export default InvestigationsListPage;
