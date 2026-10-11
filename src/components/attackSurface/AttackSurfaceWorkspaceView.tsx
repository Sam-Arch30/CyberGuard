import React, { useState, useEffect, useCallback } from 'react';
import {
  Globe,
  Shield,
  AlertTriangle,
  Search,
  RefreshCw,
  Plus,
  Trash2,
  CheckCircle2,
  Clock,
  ChevronRight,
  Server,
  Layers,
  HelpCircle,
  Activity,
  X,
  Radio,
  Network,
} from 'lucide-react';
import type {
  Asset,
  AssetDetail,
  Exposure,
  AttackSurfaceScope,
  AttackSurfaceOverviewStats,
  AttackSurfaceDiffResponse,
  UnknownAssetQueueItem,
  AssetTimelineItem,
  AssetType,
} from '../../types/attackSurface';
import { AttackSurfaceService } from '../../services/attackSurfaceService';
import {
  Button,
  Badge,
  Card,
  Modal,
  ModalHeader,
  ModalTitle,
  ModalBody,
  ModalFooter,
} from '../ui';
import { cn } from '../../utils/cn';

interface AttackSurfaceWorkspaceViewProps {
  initialAssetId?: string;
}

export const AttackSurfaceWorkspaceView: React.FC<AttackSurfaceWorkspaceViewProps> = ({
  initialAssetId,
}) => {
  // Navigation Tabs
  const [activeTab, setActiveTab] = useState<'inventory' | 'exposures' | 'unknown' | 'diff' | 'scopes'>('inventory');

  // Overview Stats
  const [overview, setOverview] = useState<AttackSurfaceOverviewStats | null>(null);
  const [loadingOverview, setLoadingOverview] = useState(false);

  // Asset Inventory State
  const [assets, setAssets] = useState<Asset[]>([]);
  const [totalAssets, setTotalAssets] = useState(0);
  const [loadingAssets, setLoadingAssets] = useState(false);
  const [assetSearch, setAssetSearch] = useState('');
  const [filterType, setFilterType] = useState<string>('ALL');
  const [filterExposure, setFilterExposure] = useState<string>('ALL');
  const [filterCriticality, setFilterCriticality] = useState<string>('ALL');
  const [filterStatus, setFilterStatus] = useState<string>('ALL');

  // Asset Detail Modal / Drawer
  const [selectedAssetId, setSelectedAssetId] = useState<string | null>(initialAssetId || null);
  const [selectedAssetDetail, setSelectedAssetDetail] = useState<AssetDetail | null>(null);
  const [timelineItems, setTimelineItems] = useState<AssetTimelineItem[]>([]);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [detailTab, setDetailTab] = useState<'overview' | 'exposures' | 'services' | 'neighbors' | 'timeline'>('overview');

  // Exposures Tab State
  const [exposures, setExposures] = useState<Exposure[]>([]);
  const [totalExposures, setTotalExposures] = useState(0);
  const [loadingExposures, setLoadingExposures] = useState(false);
  const [exposureFilterSeverity, setExposureFilterSeverity] = useState<string>('ALL');
  const [exposureFilterStatus, setExposureFilterStatus] = useState<string>('OPEN');

  // Unknown Queue State
  const [unknownQueue, setUnknownQueue] = useState<UnknownAssetQueueItem[]>([]);
  const [totalUnknown, setTotalUnknown] = useState(0);
  const [loadingUnknown, setLoadingUnknown] = useState(false);

  // Discovery Scopes State
  const [scopes, setScopes] = useState<AttackSurfaceScope[]>([]);
  const [loadingScopes, setLoadingScopes] = useState(false);

  // Snapshot Diff State
  const [diff, setDiff] = useState<AttackSurfaceDiffResponse | null>(null);
  const [loadingDiff, setLoadingDiff] = useState(false);

  // Action Modals
  const [isDiscovering, setIsDiscovering] = useState(false);
  const [discoverySuccessMsg, setDiscoverySuccessMsg] = useState<string | null>(null);

  // Add Scope Modal State
  const [isScopeModalOpen, setIsScopeModalOpen] = useState(false);
  const [scopeTypeInput, setScopeTypeInput] = useState<'DOMAIN' | 'CIDR' | 'IP'>('DOMAIN');
  const [scopeTargetInput, setScopeTargetInput] = useState('');
  const [scopeDescInput, setScopeDescInput] = useState('');
  const [scopeError, setScopeError] = useState<string | null>(null);
  const [isSavingScope, setIsSavingScope] = useState(false);

  // Resolve Exposure Modal State
  const [resolvingExposure, setResolvingExposure] = useState<Exposure | null>(null);
  const [resolveNotesInput, setResolveNotesInput] = useState('');
  const [isResolving, setIsResolving] = useState(false);

  // Review Unknown Asset Modal State
  const [reviewingAsset, setReviewingAsset] = useState<UnknownAssetQueueItem | null>(null);
  const [reviewAction, setReviewAction] = useState<'APPROVE' | 'ASSIGN_OWNER' | 'MARK_UNAUTHORIZED' | 'ADD_TO_WATCHLIST'>('APPROVE');
  const [reviewOwnerInput, setReviewOwnerInput] = useState('');
  const [reviewTeamInput, setReviewTeamInput] = useState('');
  const [reviewNotesInput, setReviewNotesInput] = useState('');
  const [isReviewing, setIsReviewing] = useState(false);

  // -------------------------------------------------------------------------
  // Fetch Functions
  // -------------------------------------------------------------------------

  const fetchOverview = useCallback(async () => {
    setLoadingOverview(true);
    try {
      const data = await AttackSurfaceService.getOverview();
      setOverview(data);
    } catch (err) {
      console.error('Failed to load attack surface overview:', err);
    } finally {
      setLoadingOverview(false);
    }
  }, []);

  const fetchAssets = useCallback(async () => {
    setLoadingAssets(true);
    try {
      const res = await AttackSurfaceService.listAssets({
        asset_type: filterType,
        exposure_state: filterExposure,
        criticality: filterCriticality,
        status: filterStatus,
        q: assetSearch,
        limit: 50,
      });
      setAssets(res.items);
      setTotalAssets(res.total);
    } catch (err) {
      console.error('Failed to list assets:', err);
    } finally {
      setLoadingAssets(false);
    }
  }, [filterType, filterExposure, filterCriticality, filterStatus, assetSearch]);

  const fetchExposures = useCallback(async () => {
    setLoadingExposures(true);
    try {
      const res = await AttackSurfaceService.listExposures({
        severity: exposureFilterSeverity,
        status: exposureFilterStatus,
        limit: 50,
      });
      setExposures(res.items);
      setTotalExposures(res.total);
    } catch (err) {
      console.error('Failed to list exposures:', err);
    } finally {
      setLoadingExposures(false);
    }
  }, [exposureFilterSeverity, exposureFilterStatus]);

  const fetchUnknownQueue = useCallback(async () => {
    setLoadingUnknown(true);
    try {
      const res = await AttackSurfaceService.getUnknownQueue(50, 0);
      setUnknownQueue(res.items);
      setTotalUnknown(res.total);
    } catch (err) {
      console.error('Failed to load unknown asset queue:', err);
    } finally {
      setLoadingUnknown(false);
    }
  }, []);

  const fetchScopes = useCallback(async () => {
    setLoadingScopes(true);
    try {
      const res = await AttackSurfaceService.listScopes();
      setScopes(res);
    } catch (err) {
      console.error('Failed to list discovery scopes:', err);
    } finally {
      setLoadingScopes(false);
    }
  }, []);

  const fetchDiff = useCallback(async () => {
    setLoadingDiff(true);
    try {
      const res = await AttackSurfaceService.getDiff();
      setDiff(res);
    } catch (err) {
      console.error('Failed to load snapshot diff:', err);
    } finally {
      setLoadingDiff(false);
    }
  }, []);

  const fetchAssetDetail = useCallback(async (id: string) => {
    setLoadingDetail(true);
    try {
      const [detail, timeline] = await Promise.all([
        AttackSurfaceService.getAssetDetail(id),
        AttackSurfaceService.getAssetTimeline(id),
      ]);
      setSelectedAssetDetail(detail);
      setTimelineItems(timeline);
    } catch (err) {
      console.error('Failed to fetch asset detail:', err);
    } finally {
      setLoadingDetail(false);
    }
  }, []);

  // Initial Data Load
  useEffect(() => {
    fetchOverview();
    fetchAssets();
    fetchExposures();
    fetchUnknownQueue();
    fetchScopes();
    fetchDiff();
  }, [fetchOverview, fetchAssets, fetchExposures, fetchUnknownQueue, fetchScopes, fetchDiff]);

  // Handle selected asset change
  useEffect(() => {
    if (selectedAssetId) {
      fetchAssetDetail(selectedAssetId);
    } else {
      setSelectedAssetDetail(null);
      setTimelineItems([]);
    }
  }, [selectedAssetId, fetchAssetDetail]);

  // -------------------------------------------------------------------------
  // Handlers
  // -------------------------------------------------------------------------

  const handleRunDiscovery = async () => {
    setIsDiscovering(true);
    setDiscoverySuccessMsg(null);
    try {
      const res = await AttackSurfaceService.runDiscovery();
      setDiscoverySuccessMsg(`Discovery sweep completed: ${res.assets_discovered} assets synced, ${res.exposures_created} exposures identified.`);
      await Promise.all([fetchOverview(), fetchAssets(), fetchExposures(), fetchUnknownQueue(), fetchDiff()]);
      setTimeout(() => setDiscoverySuccessMsg(null), 5000);
    } catch (err: any) {
      alert(`Discovery failed: ${err.message}`);
    } finally {
      setIsDiscovering(false);
    }
  };

  const handleCreateScope = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!scopeTargetInput.trim()) return;
    setIsSavingScope(true);
    setScopeError(null);
    try {
      await AttackSurfaceService.createScope({
        scope_type: scopeTypeInput,
        target: scopeTargetInput.trim(),
        description: scopeDescInput.trim(),
      });
      setIsScopeModalOpen(false);
      setScopeTargetInput('');
      setScopeDescInput('');
      await fetchScopes();
      await fetchOverview();
    } catch (err: any) {
      setScopeError(err.message);
    } finally {
      setIsSavingScope(false);
    }
  };

  const handleDeleteScope = async (scopeId: string) => {
    if (!window.confirm('Remove this discovery scope? Targets in this scope will no longer be monitored.')) return;
    try {
      await AttackSurfaceService.deleteScope(scopeId);
      await fetchScopes();
      await fetchOverview();
    } catch (err: any) {
      alert(`Failed to delete scope: ${err.message}`);
    }
  };

  const handleResolveExposure = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!resolvingExposure) return;
    setIsResolving(true);
    try {
      await AttackSurfaceService.resolveExposure(resolvingExposure.id, resolveNotesInput.trim() || 'Validated and resolved by analyst');
      setResolvingExposure(null);
      setResolveNotesInput('');
      await Promise.all([fetchExposures(), fetchOverview(), selectedAssetId ? fetchAssetDetail(selectedAssetId) : Promise.resolve()]);
    } catch (err: any) {
      alert(`Failed to resolve exposure: ${err.message}`);
    } finally {
      setIsResolving(false);
    }
  };

  const handleReviewUnknownAsset = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!reviewingAsset) return;
    setIsReviewing(true);
    try {
      await AttackSurfaceService.reviewUnknownAsset(reviewingAsset.id, {
        action: reviewAction,
        owner: reviewOwnerInput.trim() || undefined,
        team: reviewTeamInput.trim() || undefined,
        notes: reviewNotesInput.trim() || `Analyst triage: ${reviewAction}`,
        actor: 'SOC Analyst',
      });
      setReviewingAsset(null);
      setReviewNotesInput('');
      setReviewOwnerInput('');
      setReviewTeamInput('');
      await Promise.all([fetchUnknownQueue(), fetchAssets(), fetchOverview()]);
    } catch (err: any) {
      alert(`Review action failed: ${err.message}`);
    } finally {
      setIsReviewing(false);
    }
  };

  // -------------------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------------------

  const getSeverityBadgeClass = (severity: string) => {
    switch (severity.toUpperCase()) {
      case 'CRITICAL':
        return 'bg-red-950/70 text-red-300 border-red-800/60 font-semibold';
      case 'HIGH':
        return 'bg-amber-950/70 text-amber-300 border-amber-800/60 font-semibold';
      case 'MEDIUM':
        return 'bg-yellow-950/70 text-yellow-300 border-yellow-800/60';
      case 'LOW':
        return 'bg-emerald-950/70 text-emerald-300 border-emerald-800/60';
      default:
        return 'bg-slate-900/70 text-slate-300 border-slate-700/60';
    }
  };

  const getExposureStateBadge = (state: string) => {
    switch (state) {
      case 'PUBLICLY_EXPOSED':
        return <Badge className="bg-cyan-950/80 text-cyan-300 border-cyan-800/60 flex items-center gap-1"><Globe className="w-3 h-3 text-cyan-400" /> Public</Badge>;
      case 'INTERNALLY_REACHABLE':
        return <Badge className="bg-indigo-950/80 text-indigo-300 border-indigo-800/60 flex items-center gap-1"><Network className="w-3 h-3 text-indigo-400" /> Internal</Badge>;
      case 'INTERNALLY_ONLY':
        return <Badge className="bg-slate-900/80 text-slate-300 border-slate-700/60">Airgapped</Badge>;
      default:
        return <Badge className="bg-zinc-900/80 text-zinc-400 border-zinc-700/60">Unknown</Badge>;
    }
  };

  const getAssetTypeIcon = (type: AssetType) => {
    switch (type) {
      case 'DOMAIN':
      case 'SUBDOMAIN':
        return <Globe className="w-4 h-4 text-cyan-400" />;
      case 'PUBLIC_IP':
      case 'PRIVATE_IP':
        return <Server className="w-4 h-4 text-amber-400" />;
      case 'ENDPOINT':
      case 'DEVICE':
        return <Activity className="w-4 h-4 text-indigo-400" />;
      case 'API':
      case 'APPLICATION':
        return <Layers className="w-4 h-4 text-purple-400" />;
      default:
        return <Shield className="w-4 h-4 text-slate-400" />;
    }
  };

  return (
    <div className="flex flex-col gap-6 p-6 min-h-screen bg-slate-950 text-slate-100">
      {/* 1. Header Bar */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800/80 pb-5">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-gradient-to-br from-cyan-950 via-slate-900 to-indigo-950 border border-cyan-800/50 shadow-inner">
              <Globe className="w-6 h-6 text-cyan-400 animate-pulse" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-slate-50 flex items-center gap-2">
                Attack Surface Intelligence
                <Badge className="bg-cyan-900/40 text-cyan-300 border-cyan-700/50 text-xs">Section 62</Badge>
              </h1>
              <p className="text-sm text-slate-400">
                Continuous asset inventory discovery, exposure identification, and risk prioritization.
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <Button
            variant="outline"
            size="sm"
            onClick={fetchOverview}
            className="border-slate-800 hover:bg-slate-900 text-slate-300"
          >
            <RefreshCw className={cn("w-4 h-4 mr-2", loadingOverview && "animate-spin")} />
            Refresh
          </Button>

          <Button
            variant="outline"
            size="sm"
            onClick={() => setIsScopeModalOpen(true)}
            className="border-cyan-800/60 text-cyan-300 hover:bg-cyan-950/40"
          >
            <Plus className="w-4 h-4 mr-1.5" />
            Add Scope
          </Button>

          <Button
            size="sm"
            onClick={handleRunDiscovery}
            disabled={isDiscovering}
            className="bg-cyan-600 hover:bg-cyan-500 text-white shadow-lg shadow-cyan-950 font-medium"
          >
            <RefreshCw className={cn("w-4 h-4 mr-2", isDiscovering && "animate-spin")} />
            {isDiscovering ? 'Discovering...' : 'Discovery Sweep'}
          </Button>
        </div>
      </div>

      {/* Discovery Success Notification Banner */}
      {discoverySuccessMsg && (
        <div className="flex items-center justify-between px-4 py-3 rounded-lg bg-emerald-950/70 border border-emerald-800/60 text-emerald-200 text-sm animate-in fade-in duration-300">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-5 h-5 text-emerald-400" />
            <span>{discoverySuccessMsg}</span>
          </div>
          <button onClick={() => setDiscoverySuccessMsg(null)} className="text-emerald-400 hover:text-emerald-200">
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* 2. Top KPI Cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        {/* Total Assets */}
        <Card className="p-4 bg-slate-900/60 border-slate-800/80 backdrop-blur-sm relative overflow-hidden">
          <div className="text-xs font-medium text-slate-400 uppercase tracking-wider">Total Assets</div>
          <div className="text-2xl font-bold text-slate-100 mt-1.5 flex items-baseline gap-2">
            {overview?.total_assets ?? 0}
            <span className="text-xs font-normal text-slate-500">observed</span>
          </div>
          <div className="mt-2 text-xs text-slate-500">
            {overview?.authorized_scopes_count ?? 0} authorized scopes
          </div>
        </Card>

        {/* Publicly Exposed */}
        <Card className="p-4 bg-slate-900/60 border-cyan-900/40 backdrop-blur-sm relative overflow-hidden">
          <div className="text-xs font-medium text-cyan-400 uppercase tracking-wider flex items-center gap-1.5">
            <Globe className="w-3.5 h-3.5 text-cyan-400" />
            Publicly Exposed
          </div>
          <div className="text-2xl font-bold text-cyan-200 mt-1.5">
            {overview?.publicly_exposed_assets ?? 0}
          </div>
          <div className="mt-2 text-xs text-cyan-500/80">External attack surface</div>
        </Card>

        {/* Unknown / Unmapped */}
        <Card className="p-4 bg-slate-900/60 border-amber-900/40 backdrop-blur-sm relative overflow-hidden">
          <div className="text-xs font-medium text-amber-400 uppercase tracking-wider flex items-center gap-1.5">
            <HelpCircle className="w-3.5 h-3.5 text-amber-400" />
            Unknown Assets
          </div>
          <div className="text-2xl font-bold text-amber-200 mt-1.5">
            {overview?.unknown_assets_count ?? 0}
          </div>
          <div className="mt-2 text-xs text-amber-500/80">Requires triage review</div>
        </Card>

        {/* Critical Business Assets */}
        <Card className="p-4 bg-slate-900/60 border-indigo-900/40 backdrop-blur-sm relative overflow-hidden">
          <div className="text-xs font-medium text-indigo-400 uppercase tracking-wider flex items-center gap-1.5">
            <Shield className="w-3.5 h-3.5 text-indigo-400" />
            Critical Assets
          </div>
          <div className="text-2xl font-bold text-indigo-200 mt-1.5">
            {overview?.critical_assets_count ?? 0}
          </div>
          <div className="mt-2 text-xs text-indigo-500/80">Tier-1 business impact</div>
        </Card>

        {/* High Risk Assets */}
        <Card className="p-4 bg-slate-900/60 border-red-900/40 backdrop-blur-sm relative overflow-hidden">
          <div className="text-xs font-medium text-red-400 uppercase tracking-wider flex items-center gap-1.5">
            <AlertTriangle className="w-3.5 h-3.5 text-red-400" />
            High Threat Risk
          </div>
          <div className="text-2xl font-bold text-red-200 mt-1.5">
            {overview?.high_risk_assets_count ?? 0}
          </div>
          <div className="mt-2 text-xs text-red-500/80">Risk Score &gt;= 50</div>
        </Card>

        {/* Open Exposures */}
        <Card className="p-4 bg-slate-900/60 border-orange-900/40 backdrop-blur-sm relative overflow-hidden">
          <div className="text-xs font-medium text-orange-400 uppercase tracking-wider flex items-center gap-1.5">
            <Activity className="w-3.5 h-3.5 text-orange-400" />
            Open Exposures
          </div>
          <div className="text-2xl font-bold text-orange-200 mt-1.5">
            {overview?.open_exposures_count ?? 0}
          </div>
          <div className="mt-2 text-xs text-orange-500/80">
            {overview?.critical_exposures_count ?? 0} critical severity
          </div>
        </Card>
      </div>

      {/* 3. Primary Navigation Tabs */}
      <div className="flex border-b border-slate-800/90 gap-1">
        <button
          onClick={() => setActiveTab('inventory')}
          className={cn(
            'px-4 py-2.5 text-sm font-medium border-b-2 flex items-center gap-2 transition-colors',
            activeTab === 'inventory'
              ? 'border-cyan-500 text-cyan-400 bg-slate-900/40'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          )}
        >
          <Server className="w-4 h-4" />
          Asset Inventory
          <span className="ml-1 px-1.5 py-0.5 rounded-full bg-slate-800 text-xs text-slate-300 font-mono">
            {totalAssets}
          </span>
        </button>

        <button
          onClick={() => setActiveTab('exposures')}
          className={cn(
            'px-4 py-2.5 text-sm font-medium border-b-2 flex items-center gap-2 transition-colors',
            activeTab === 'exposures'
              ? 'border-cyan-500 text-cyan-400 bg-slate-900/40'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          )}
        >
          <AlertTriangle className="w-4 h-4 text-orange-400" />
          Active Exposures
          <span className="ml-1 px-1.5 py-0.5 rounded-full bg-slate-800 text-xs text-slate-300 font-mono">
            {totalExposures}
          </span>
        </button>

        <button
          onClick={() => setActiveTab('unknown')}
          className={cn(
            'px-4 py-2.5 text-sm font-medium border-b-2 flex items-center gap-2 transition-colors',
            activeTab === 'unknown'
              ? 'border-cyan-500 text-cyan-400 bg-slate-900/40'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          )}
        >
          <HelpCircle className="w-4 h-4 text-amber-400" />
          Unknown Assets Queue
          {totalUnknown > 0 && (
            <span className="ml-1 px-1.5 py-0.5 rounded-full bg-amber-950 text-amber-300 border border-amber-800/70 text-xs font-mono">
              {totalUnknown}
            </span>
          )}
        </button>

        <button
          onClick={() => setActiveTab('diff')}
          className={cn(
            'px-4 py-2.5 text-sm font-medium border-b-2 flex items-center gap-2 transition-colors',
            activeTab === 'diff'
              ? 'border-cyan-500 text-cyan-400 bg-slate-900/40'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          )}
        >
          <Radio className="w-4 h-4 text-emerald-400" />
          Surface Diff
        </button>

        <button
          onClick={() => setActiveTab('scopes')}
          className={cn(
            'px-4 py-2.5 text-sm font-medium border-b-2 flex items-center gap-2 transition-colors',
            activeTab === 'scopes'
              ? 'border-cyan-500 text-cyan-400 bg-slate-900/40'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          )}
        >
          <Shield className="w-4 h-4 text-indigo-400" />
          Authorized Scopes ({scopes.length})
        </button>
      </div>

      {/* 4. Tab Content Panels */}

      {/* TAB 1: ASSET INVENTORY */}
      {activeTab === 'inventory' && (
        <div className="flex flex-col gap-4">
          {/* Filters Bar */}
          <div className="flex flex-wrap items-center gap-3 p-3.5 rounded-xl bg-slate-900/40 border border-slate-800/80">
            <div className="relative flex-1 min-w-[240px]">
              <Search className="w-4 h-4 absolute left-3 top-3 text-slate-400" />
              <input
                type="text"
                placeholder="Search asset name, domain, IP, owner, team..."
                value={assetSearch}
                onChange={(e) => setAssetSearch(e.target.value)}
                className="w-full pl-9 pr-4 py-1.5 rounded-lg bg-slate-950/80 border border-slate-800 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
              />
            </div>

            {/* Asset Type Filter */}
            <select
              value={filterType}
              onChange={(e) => setFilterType(e.target.value)}
              className="px-3 py-1.5 rounded-lg bg-slate-950/80 border border-slate-800 text-sm text-slate-300 focus:outline-none focus:border-cyan-500"
            >
              <option value="ALL">All Asset Types</option>
              <option value="DOMAIN">Domains</option>
              <option value="SUBDOMAIN">Subdomains</option>
              <option value="PUBLIC_IP">Public IPs</option>
              <option value="ENDPOINT">Endpoints</option>
              <option value="API">APIs</option>
              <option value="APPLICATION">Applications</option>
              <option value="IDENTITY">Identities</option>
              <option value="CERTIFICATE">Certificates</option>
            </select>

            {/* Exposure State Filter */}
            <select
              value={filterExposure}
              onChange={(e) => setFilterExposure(e.target.value)}
              className="px-3 py-1.5 rounded-lg bg-slate-950/80 border border-slate-800 text-sm text-slate-300 focus:outline-none focus:border-cyan-500"
            >
              <option value="ALL">All Exposure States</option>
              <option value="PUBLICLY_EXPOSED">Publicly Exposed</option>
              <option value="INTERNALLY_REACHABLE">Internally Reachable</option>
              <option value="INTERNALLY_ONLY">Internally Only</option>
              <option value="UNKNOWN">Unknown Exposure</option>
            </select>

            {/* Criticality Filter */}
            <select
              value={filterCriticality}
              onChange={(e) => setFilterCriticality(e.target.value)}
              className="px-3 py-1.5 rounded-lg bg-slate-950/80 border border-slate-800 text-sm text-slate-300 focus:outline-none focus:border-cyan-500"
            >
              <option value="ALL">All Criticalities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>

            {/* Status Filter */}
            <select
              value={filterStatus}
              onChange={(e) => setFilterStatus(e.target.value)}
              className="px-3 py-1.5 rounded-lg bg-slate-950/80 border border-slate-800 text-sm text-slate-300 focus:outline-none focus:border-cyan-500"
            >
              <option value="ALL">All Statuses</option>
              <option value="ACTIVE">Active</option>
              <option value="DISCOVERED">Discovered (Unapproved)</option>
              <option value="STALE">Stale</option>
              <option value="RETIRED">Retired</option>
            </select>
          </div>

          {/* Assets Table */}
          <div className="rounded-xl border border-slate-800 overflow-hidden bg-slate-900/30">
            <table className="w-full text-left text-sm text-slate-300">
              <thead className="bg-slate-900/70 border-b border-slate-800 text-xs font-semibold uppercase text-slate-400">
                <tr>
                  <th className="py-3 px-4">Asset / Canonical Name</th>
                  <th className="py-3 px-4">Type</th>
                  <th className="py-3 px-4">Exposure</th>
                  <th className="py-3 px-4">Owner & Team</th>
                  <th className="py-3 px-4">Criticality</th>
                  <th className="py-3 px-4">Risk Score</th>
                  <th className="py-3 px-4">Active Exposures</th>
                  <th className="py-3 px-4">Last Seen</th>
                  <th className="py-3 px-4 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-normal">
                {loadingAssets ? (
                  <tr>
                    <td colSpan={9} className="py-12 text-center text-slate-500">
                      <RefreshCw className="w-6 h-6 animate-spin mx-auto mb-2 text-cyan-500" />
                      Loading organizational assets...
                    </td>
                  </tr>
                ) : assets.length === 0 ? (
                  <tr>
                    <td colSpan={9} className="py-12 text-center text-slate-500">
                      No assets found matching the selected filters.
                    </td>
                  </tr>
                ) : (
                  assets.map((asset) => (
                    <tr
                      key={asset.id}
                      className="hover:bg-slate-800/40 transition-colors cursor-pointer group"
                      onClick={() => setSelectedAssetId(asset.id)}
                    >
                      <td className="py-3 px-4">
                        <div className="flex items-center gap-2.5">
                          <div className="p-1.5 rounded-md bg-slate-950 border border-slate-800">
                            {getAssetTypeIcon(asset.asset_type)}
                          </div>
                          <div>
                            <div className="font-semibold text-slate-100 group-hover:text-cyan-300 transition-colors font-mono text-xs">
                              {asset.canonical_name}
                            </div>
                            {asset.display_name !== asset.canonical_name && (
                              <div className="text-xs text-slate-400">{asset.display_name}</div>
                            )}
                          </div>
                        </div>
                      </td>

                      <td className="py-3 px-4">
                        <Badge className="bg-slate-800/60 text-slate-300 border-slate-700/60 text-[11px]">
                          {asset.asset_type}
                        </Badge>
                      </td>

                      <td className="py-3 px-4">
                        {getExposureStateBadge(asset.exposure_state)}
                      </td>

                      <td className="py-3 px-4">
                        <div className="text-xs text-slate-200">
                          {asset.owner && asset.owner !== 'Unknown' ? (
                            <span>{asset.owner}</span>
                          ) : (
                            <span className="text-amber-400 italic">Unassigned</span>
                          )}
                        </div>
                        {asset.team && (
                          <div className="text-[11px] text-slate-400">{asset.team}</div>
                        )}
                      </td>

                      <td className="py-3 px-4">
                        <Badge className={cn('text-[11px]', getSeverityBadgeClass(asset.criticality))}>
                          {asset.criticality}
                        </Badge>
                      </td>

                      <td className="py-3 px-4 font-mono font-medium">
                        <span
                          className={cn(
                            'px-2 py-0.5 rounded text-xs',
                            asset.risk_score >= 70
                              ? 'bg-red-950 text-red-300 border border-red-800/60'
                              : asset.risk_score >= 40
                              ? 'bg-amber-950 text-amber-300 border border-amber-800/60'
                              : 'bg-emerald-950 text-emerald-300 border border-emerald-800/60'
                          )}
                        >
                          {asset.risk_score.toFixed(1)}
                        </span>
                      </td>

                      <td className="py-3 px-4 font-mono text-xs">
                        {asset.active_exposure_count > 0 ? (
                          <span className="text-orange-400 font-semibold flex items-center gap-1">
                            <AlertTriangle className="w-3 h-3" />
                            {asset.active_exposure_count}
                          </span>
                        ) : (
                          <span className="text-slate-500">0</span>
                        )}
                      </td>

                      <td className="py-3 px-4 text-xs text-slate-400 whitespace-nowrap">
                        {new Date(asset.last_seen_at).toLocaleString([], {
                          month: 'short',
                          day: 'numeric',
                          hour: '2-digit',
                          minute: '2-digit',
                        })}
                      </td>

                      <td className="py-3 px-4 text-right">
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedAssetId(asset.id);
                          }}
                          className="text-cyan-400 hover:text-cyan-300 hover:bg-slate-800 p-1.5"
                        >
                          <ChevronRight className="w-4 h-4" />
                        </Button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB 2: ACTIVE EXPOSURES */}
      {activeTab === 'exposures' && (
        <div className="flex flex-col gap-4">
          <div className="flex flex-wrap items-center justify-between gap-3 p-3.5 rounded-xl bg-slate-900/40 border border-slate-800/80">
            <div className="flex items-center gap-3">
              <select
                value={exposureFilterSeverity}
                onChange={(e) => setExposureFilterSeverity(e.target.value)}
                className="px-3 py-1.5 rounded-lg bg-slate-950/80 border border-slate-800 text-sm text-slate-300 focus:outline-none focus:border-cyan-500"
              >
                <option value="ALL">All Severities</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
              </select>

              <select
                value={exposureFilterStatus}
                onChange={(e) => setExposureFilterStatus(e.target.value)}
                className="px-3 py-1.5 rounded-lg bg-slate-950/80 border border-slate-800 text-sm text-slate-300 focus:outline-none focus:border-cyan-500"
              >
                <option value="OPEN">Open Exposures</option>
                <option value="RESOLVED">Resolved Exposures</option>
                <option value="ALL">All Statuses</option>
              </select>
            </div>

            <div className="text-xs text-slate-400">
              Showing {exposures.length} actionable exposures
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {loadingExposures ? (
              <div className="col-span-2 py-12 text-center text-slate-500">
                <RefreshCw className="w-6 h-6 animate-spin mx-auto mb-2 text-cyan-500" />
                Loading security exposures...
              </div>
            ) : exposures.length === 0 ? (
              <div className="col-span-2 py-12 text-center text-slate-500">
                No exposures matching the selected criteria.
              </div>
            ) : (
              exposures.map((exp) => (
                <Card
                  key={exp.id}
                  className="p-5 bg-slate-900/50 border-slate-800/80 hover:border-slate-700 transition-colors flex flex-col justify-between"
                >
                  <div>
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <div className="flex items-center gap-2 mb-1.5">
                          <Badge className={cn('text-xs', getSeverityBadgeClass(exp.severity))}>
                            {exp.severity}
                          </Badge>
                          <Badge className="bg-slate-800 text-slate-300 text-xs">
                            {exp.exposure_type}
                          </Badge>
                          <Badge
                            className={cn(
                              'text-xs',
                              exp.status === 'OPEN'
                                ? 'bg-orange-950/80 text-orange-300 border-orange-800/60'
                                : 'bg-emerald-950/80 text-emerald-300 border-emerald-800/60'
                            )}
                          >
                            {exp.status}
                          </Badge>
                        </div>
                        <h3 className="text-base font-semibold text-slate-100">{exp.title}</h3>
                      </div>

                      {exp.status === 'OPEN' && (
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => setResolvingExposure(exp)}
                          className="border-emerald-800/60 text-emerald-300 hover:bg-emerald-950/50 text-xs"
                        >
                          Resolve
                        </Button>
                      )}
                    </div>

                    <p className="text-sm text-slate-300 mt-2.5 leading-relaxed">{exp.description}</p>

                    {exp.remediation_guidance && (
                      <div className="mt-3 p-2.5 rounded bg-slate-950/80 border border-slate-800/80 text-xs text-slate-300">
                        <strong className="text-cyan-400 font-medium">Remediation:</strong>{' '}
                        {exp.remediation_guidance}
                      </div>
                    )}

                    {exp.evidence_refs && exp.evidence_refs.length > 0 && (
                      <div className="mt-3 flex flex-wrap gap-1.5">
                        {exp.evidence_refs.map((ref, idx) => (
                          <span
                            key={idx}
                            className="px-2 py-0.5 rounded bg-slate-950 text-slate-400 border border-slate-800 text-[11px] font-mono"
                          >
                            {ref}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>

                  <div className="mt-4 pt-3 border-t border-slate-800/60 flex items-center justify-between text-xs text-slate-500">
                    <div>
                      First seen:{' '}
                      <span className="text-slate-400">
                        {new Date(exp.first_seen_at).toLocaleDateString()}
                      </span>
                    </div>
                    {exp.resolved_at && (
                      <div className="text-emerald-400">
                        Resolved by {exp.resolved_by} on{' '}
                        {new Date(exp.resolved_at).toLocaleDateString()}
                      </div>
                    )}
                  </div>
                </Card>
              ))
            )}
          </div>
        </div>
      )}

      {/* TAB 3: UNKNOWN ASSETS REVIEW QUEUE */}
      {activeTab === 'unknown' && (
        <div className="flex flex-col gap-4">
          <div className="p-4 rounded-xl bg-amber-950/30 border border-amber-900/60 text-amber-200 text-sm flex items-start gap-3">
            <HelpCircle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
            <div>
              <strong className="font-semibold text-amber-100">Unknown Assets Triage Queue:</strong>{' '}
              These entities were observed in incoming telemetry without an explicit authorized owner, CMDB record, or known team mapping.
              Review operational validity and assign ownership to eliminate shadow attack surface.
            </div>
          </div>

          <div className="rounded-xl border border-slate-800 overflow-hidden bg-slate-900/30">
            <table className="w-full text-left text-sm text-slate-300">
              <thead className="bg-slate-900/70 border-b border-slate-800 text-xs font-semibold uppercase text-slate-400">
                <tr>
                  <th className="py-3 px-4">Unmapped Asset</th>
                  <th className="py-3 px-4">Type</th>
                  <th className="py-3 px-4">Exposure State</th>
                  <th className="py-3 px-4">Source</th>
                  <th className="py-3 px-4">Risk Context</th>
                  <th className="py-3 px-4">Observation Reason</th>
                  <th className="py-3 px-4 text-right">Triage Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-normal">
                {loadingUnknown ? (
                  <tr>
                    <td colSpan={7} className="py-12 text-center text-slate-500">
                      <RefreshCw className="w-6 h-6 animate-spin mx-auto mb-2 text-cyan-500" />
                      Loading unknown asset queue...
                    </td>
                  </tr>
                ) : unknownQueue.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="py-12 text-center text-slate-500">
                      All observed assets have verified owners and authorizations. Zero unmapped assets!
                    </td>
                  </tr>
                ) : (
                  unknownQueue.map((item) => (
                    <tr key={item.id} className="hover:bg-slate-800/40 transition-colors">
                      <td className="py-3 px-4 font-mono font-medium text-slate-100">
                        {item.canonical_name}
                      </td>

                      <td className="py-3 px-4">
                        <Badge className="bg-slate-800 text-slate-300 text-xs">{item.asset_type}</Badge>
                      </td>

                      <td className="py-3 px-4">{getExposureStateBadge(item.exposure_state)}</td>

                      <td className="py-3 px-4 text-xs text-slate-400">{item.source}</td>

                      <td className="py-3 px-4">
                        <Badge className={cn('text-xs', getSeverityBadgeClass(item.criticality))}>
                          {item.criticality}
                        </Badge>
                      </td>

                      <td className="py-3 px-4 text-xs text-slate-300 max-w-xs">{item.reason}</td>

                      <td className="py-3 px-4 text-right">
                        <Button
                          size="sm"
                          onClick={() => {
                            setReviewingAsset(item);
                            setReviewAction('APPROVE');
                          }}
                          className="bg-cyan-700 hover:bg-cyan-600 text-white text-xs mr-2"
                        >
                          Review &amp; Classify
                        </Button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB 4: SURFACE DIFF */}
      {activeTab === 'diff' && (
        <div className="flex flex-col gap-4">
          <Card className="p-5 bg-slate-900/40 border-slate-800">
            {loadingDiff ? (
              <div className="py-12 text-center text-slate-500">
                <RefreshCw className="w-6 h-6 animate-spin mx-auto mb-2 text-cyan-500" />
                Comparing attack surface snapshots...
              </div>
            ) : (
              <>
                <div className="flex items-center justify-between border-b border-slate-800 pb-4 mb-4">
                  <div>
                    <h3 className="text-base font-semibold text-slate-100 flex items-center gap-2">
                      <Activity className="w-5 h-5 text-emerald-400" />
                      Attack Surface Diff &amp; Historical Comparison
                    </h3>
                    <p className="text-xs text-slate-400 mt-1">
                      Snapshot: {diff?.snapshot_name || 'Baseline'} &bull; Compared against:{' '}
                      {diff?.previous_snapshot_time ? new Date(diff.previous_snapshot_time).toLocaleString() : 'Initial'}
                    </p>
                  </div>

                  <div className="text-right font-mono text-xs text-slate-400">
                    Current:{' '}
                    {diff?.current_snapshot_time ? new Date(diff.current_snapshot_time).toLocaleTimeString() : 'N/A'}
                  </div>
                </div>

                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                  <div className="p-4 rounded-xl bg-slate-950 border border-slate-800/80">
                    <div className="text-xs text-slate-400">Assets Added</div>
                    <div className="text-xl font-bold text-emerald-400 mt-1">+{diff?.assets_added ?? 0}</div>
                  </div>
                  <div className="p-4 rounded-xl bg-slate-950 border border-slate-800/80">
                    <div className="text-xs text-slate-400">Assets Removed / Retired</div>
                    <div className="text-xl font-bold text-slate-400 mt-1">-{diff?.assets_removed ?? 0}</div>
                  </div>
                  <div className="p-4 rounded-xl bg-slate-950 border border-slate-800/80">
                    <div className="text-xs text-slate-400">New Exposures Flagged</div>
                    <div className="text-xl font-bold text-orange-400 mt-1">+{diff?.exposures_added ?? 0}</div>
                  </div>
                  <div className="p-4 rounded-xl bg-slate-950 border border-slate-800/80">
                    <div className="text-xs text-slate-400">Exposures Resolved</div>
                    <div className="text-xl font-bold text-cyan-400 mt-1">+{diff?.exposures_resolved ?? 0}</div>
                  </div>
                </div>

                {diff?.added_asset_names && diff.added_asset_names.length > 0 ? (
                  <div className="mt-4">
                    <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">
                      Recently Discovered Assets ({diff.added_asset_names.length})
                    </h4>
                    <div className="flex flex-wrap gap-2">
                      {diff.added_asset_names.map((name, idx) => (
                        <span
                          key={idx}
                          className="px-2.5 py-1 rounded bg-slate-950 border border-emerald-800/60 text-emerald-300 font-mono text-xs flex items-center gap-1.5"
                        >
                          <Plus className="w-3 h-3 text-emerald-400" />
                          {name}
                        </span>
                      ))}
                    </div>
                  </div>
                ) : (
                  <div className="text-sm text-slate-500 italic">No asset additions in latest delta comparison.</div>
                )}
              </>
            )}
          </Card>
        </div>
      )}

      {/* TAB 5: AUTHORIZED DISCOVERY SCOPES */}
      {activeTab === 'scopes' && (
        <div className="flex flex-col gap-4">
          <div className="p-4 rounded-xl bg-indigo-950/30 border border-indigo-900/60 text-indigo-200 text-sm flex items-start gap-3">
            <Shield className="w-5 h-5 text-indigo-400 shrink-0 mt-0.5" />
            <div>
              <strong className="font-semibold text-indigo-100">Authorized Target Boundary Enforcement:</strong>{' '}
              CyberGuard strictly enforces authorized discovery scopes. Scanning or querying targets outside
              tenant-configured boundaries is prohibited. SSRF defenses prevent resolution to loopback, RFC-1918, or cloud metadata IP ranges.
            </div>
          </div>

          <div className="rounded-xl border border-slate-800 overflow-hidden bg-slate-900/30">
            <table className="w-full text-left text-sm text-slate-300">
              <thead className="bg-slate-900/70 border-b border-slate-800 text-xs font-semibold uppercase text-slate-400">
                <tr>
                  <th className="py-3 px-4">Target Scope</th>
                  <th className="py-3 px-4">Type</th>
                  <th className="py-3 px-4">Authorization</th>
                  <th className="py-3 px-4">Description / Justification</th>
                  <th className="py-3 px-4">Created By</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-normal">
                {loadingScopes ? (
                  <tr>
                    <td colSpan={6} className="py-12 text-center text-slate-500">
                      <RefreshCw className="w-6 h-6 animate-spin mx-auto mb-2 text-cyan-500" />
                      Loading authorized discovery scopes...
                    </td>
                  </tr>
                ) : scopes.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="py-12 text-center text-slate-500">
                      No authorized discovery scopes configured. Click "Add Scope" to define tenant boundaries.
                    </td>
                  </tr>
                ) : (
                  scopes.map((s) => (
                    <tr key={s.id} className="hover:bg-slate-800/40 transition-colors">
                      <td className="py-3 px-4 font-mono font-medium text-slate-100">{s.target}</td>
                      <td className="py-3 px-4">
                        <Badge className="bg-slate-800 text-slate-300 text-xs">{s.scope_type}</Badge>
                      </td>
                      <td className="py-3 px-4">
                        <Badge className="bg-emerald-950/80 text-emerald-300 border-emerald-800/60 text-xs">
                          Authorized
                        </Badge>
                      </td>
                      <td className="py-3 px-4 text-xs text-slate-300">{s.description || '—'}</td>
                      <td className="py-3 px-4 text-xs text-slate-400">{s.created_by}</td>
                      <td className="py-3 px-4 text-right">
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => handleDeleteScope(s.id)}
                          className="text-red-400 hover:text-red-300 hover:bg-red-950/40 p-1.5"
                        >
                          <Trash2 className="w-4 h-4" />
                        </Button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* 5. MODALS & DRAWERS */}

      {/* Progressive Disclosure Asset Detail Modal */}
      {selectedAssetId && (
        <Modal
          isOpen={Boolean(selectedAssetId)}
          onClose={() => {
            setSelectedAssetId(null);
            setSelectedAssetDetail(null);
          }}
          size="xl"
        >
          {loadingDetail || !selectedAssetDetail ? (
            <ModalBody className="py-16 text-center text-slate-500">
              <RefreshCw className="w-8 h-8 animate-spin mx-auto mb-3 text-cyan-500" />
              <p className="text-sm">Loading asset details &amp; graph connections...</p>
            </ModalBody>
          ) : (
            <>
              <ModalHeader>
                <ModalTitle className="flex items-center gap-2">
                  {getAssetTypeIcon(selectedAssetDetail.asset_type)}
                  <span className="font-mono text-base">{selectedAssetDetail.canonical_name}</span>
                  <Badge className={cn('text-xs ml-2', getSeverityBadgeClass(selectedAssetDetail.criticality))}>
                    {selectedAssetDetail.criticality} Criticality
                  </Badge>
                </ModalTitle>
              </ModalHeader>
              <ModalBody className="max-h-[70vh] overflow-y-auto">
            {/* Detail Tabs */}
            <div className="flex border-b border-slate-800 gap-4 mb-4 text-sm font-medium">
              <button
                onClick={() => setDetailTab('overview')}
                className={cn('pb-2 border-b-2 transition-colors', detailTab === 'overview' ? 'border-cyan-500 text-cyan-400' : 'border-transparent text-slate-400 hover:text-slate-200')}
              >
                Overview
              </button>
              <button
                onClick={() => setDetailTab('exposures')}
                className={cn('pb-2 border-b-2 transition-colors', detailTab === 'exposures' ? 'border-cyan-500 text-cyan-400' : 'border-transparent text-slate-400 hover:text-slate-200')}
              >
                Exposures ({selectedAssetDetail.exposures.length})
              </button>
              <button
                onClick={() => setDetailTab('services')}
                className={cn('pb-2 border-b-2 transition-colors', detailTab === 'services' ? 'border-cyan-500 text-cyan-400' : 'border-transparent text-slate-400 hover:text-slate-200')}
              >
                Services &amp; Ports ({selectedAssetDetail.services.length})
              </button>
              <button
                onClick={() => setDetailTab('neighbors')}
                className={cn('pb-2 border-b-2 transition-colors', detailTab === 'neighbors' ? 'border-cyan-500 text-cyan-400' : 'border-transparent text-slate-400 hover:text-slate-200')}
              >
                Graph Relationships ({selectedAssetDetail.graph_neighbors.length})
              </button>
              <button
                onClick={() => setDetailTab('timeline')}
                className={cn('pb-2 border-b-2 transition-colors', detailTab === 'timeline' ? 'border-cyan-500 text-cyan-400' : 'border-transparent text-slate-400 hover:text-slate-200')}
              >
                Timeline ({timelineItems.length})
              </button>
            </div>

            {/* Sub-tab: Overview */}
            {detailTab === 'overview' && (
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                  <div className="text-xs text-slate-400">Owner</div>
                  <div className="text-slate-200 font-medium mt-1">{selectedAssetDetail.owner || 'Unknown'}</div>
                </div>
                <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                  <div className="text-xs text-slate-400">Team / Department</div>
                  <div className="text-slate-200 font-medium mt-1">{selectedAssetDetail.team || 'Unassigned'}</div>
                </div>
                <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                  <div className="text-xs text-slate-400">Exposure State</div>
                  <div className="mt-1">{getExposureStateBadge(selectedAssetDetail.exposure_state)}</div>
                </div>
                <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                  <div className="text-xs text-slate-400">Threat Risk Score</div>
                  <div className="text-slate-100 font-bold font-mono mt-1">{selectedAssetDetail.risk_score.toFixed(1)} / 100 ({selectedAssetDetail.risk_level})</div>
                </div>
                <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                  <div className="text-xs text-slate-400">Discovery Source</div>
                  <div className="text-slate-200 font-mono text-xs mt-1">{selectedAssetDetail.source}</div>
                </div>
                <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                  <div className="text-xs text-slate-400">Ownership Confidence</div>
                  <div className="text-slate-200 text-xs mt-1">{selectedAssetDetail.ownership_confidence}</div>
                </div>
                <div className="col-span-2 p-3 rounded-lg bg-slate-900 border border-slate-800">
                  <div className="text-xs text-slate-400 mb-1">Knowledge Graph Entity ID</div>
                  <div className="text-xs font-mono text-cyan-400">{selectedAssetDetail.canonical_entity_id || 'Not linked'}</div>
                </div>
              </div>
            )}

            {/* Sub-tab: Exposures */}
            {detailTab === 'exposures' && (
              <div className="flex flex-col gap-3">
                {selectedAssetDetail.exposures.length === 0 ? (
                  <div className="text-sm text-slate-500 text-center py-6">No exposures flagged on this asset.</div>
                ) : (
                  selectedAssetDetail.exposures.map((exp) => (
                    <div key={exp.id} className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                      <div className="flex items-center justify-between">
                        <Badge className={cn('text-xs', getSeverityBadgeClass(exp.severity))}>{exp.severity}</Badge>
                        <Badge className="bg-slate-800 text-slate-300 text-xs">{exp.status}</Badge>
                      </div>
                      <div className="font-semibold text-slate-100 text-sm mt-1">{exp.title}</div>
                      <p className="text-xs text-slate-400 mt-1">{exp.description}</p>
                    </div>
                  ))
                )}
              </div>
            )}

            {/* Sub-tab: Services */}
            {detailTab === 'services' && (
              <div className="flex flex-col gap-3">
                {selectedAssetDetail.services.length === 0 ? (
                  <div className="text-sm text-slate-500 text-center py-6">No active network port observations on record.</div>
                ) : (
                  selectedAssetDetail.services.map((svc) => (
                    <div key={svc.id} className="p-3 rounded-lg bg-slate-900 border border-slate-800 flex items-center justify-between">
                      <div>
                        <div className="font-mono text-sm text-cyan-300 font-semibold">
                          {svc.port ? `${svc.port}/${svc.protocol}` : svc.protocol}
                        </div>
                        <div className="text-xs text-slate-400">{svc.service_name} {svc.service_version || ''}</div>
                      </div>
                      <Badge className="bg-slate-800 text-slate-300 text-xs">{svc.exposure}</Badge>
                    </div>
                  ))
                )}
              </div>
            )}

            {/* Sub-tab: Graph Relationships */}
            {detailTab === 'neighbors' && (
              <div className="flex flex-col gap-2">
                {selectedAssetDetail.graph_neighbors.length === 0 ? (
                  <div className="text-sm text-slate-500 text-center py-6">No Knowledge Graph relationships established.</div>
                ) : (
                  selectedAssetDetail.graph_neighbors.map((r, idx) => (
                    <div key={idx} className="p-2.5 rounded bg-slate-900 border border-slate-800 text-xs flex items-center justify-between">
                      <div className="flex items-center gap-2 font-mono">
                        <span className="text-slate-300">{r.source_id}</span>
                        <span className="text-cyan-400 font-bold">&rarr; {r.relationship_type} &rarr;</span>
                        <span className="text-slate-300">{r.target_id}</span>
                      </div>
                      <Badge className="bg-slate-800 text-slate-400 text-[11px]">
                        {(r.confidence * 100).toFixed(0)}% conf
                      </Badge>
                    </div>
                  ))
                )}
              </div>
            )}

            {/* Sub-tab: Timeline */}
            {detailTab === 'timeline' && (
              <div className="flex flex-col gap-3">
                {timelineItems.length === 0 ? (
                  <div className="text-sm text-slate-500 text-center py-6">No historical events recorded.</div>
                ) : (
                  timelineItems.map((evt, idx) => (
                    <div key={idx} className="p-3 rounded bg-slate-900 border border-slate-800 flex items-start gap-3">
                      <Clock className="w-4 h-4 text-cyan-400 mt-0.5 shrink-0" />
                      <div>
                        <div className="font-semibold text-slate-200 text-xs">{evt.title}</div>
                        <p className="text-xs text-slate-400 mt-0.5">{evt.description}</p>
                        <div className="text-[11px] text-slate-500 mt-1 font-mono">{new Date(evt.timestamp).toLocaleString()}</div>
                      </div>
                    </div>
                  ))
                )}
              </div>
            )}
          </ModalBody>
          <ModalFooter>
            <Button
              variant="outline"
              onClick={() => {
                setSelectedAssetId(null);
                setSelectedAssetDetail(null);
              }}
            >
              Close
            </Button>
          </ModalFooter>
            </>
          )}
        </Modal>
      )}

      {/* Add Scope Modal */}
      <Modal isOpen={isScopeModalOpen} onClose={() => setIsScopeModalOpen(false)}>
        <form onSubmit={handleCreateScope}>
          <ModalHeader>
            <ModalTitle>Add Authorized Discovery Scope</ModalTitle>
          </ModalHeader>
          <ModalBody className="flex flex-col gap-4">
            {scopeError && (
              <div className="p-3 rounded bg-red-950/60 border border-red-800 text-red-200 text-xs">
                {scopeError}
              </div>
            )}

            <div>
              <label className="text-xs font-semibold text-slate-300 uppercase">Scope Type</label>
              <select
                value={scopeTypeInput}
                onChange={(e) => setScopeTypeInput(e.target.value as any)}
                className="w-full mt-1.5 px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-sm text-slate-200 focus:outline-none focus:border-cyan-500"
              >
                <option value="DOMAIN">Domain / Wildcard (*.domain.com)</option>
                <option value="CIDR">Network CIDR Range</option>
                <option value="IP">Public IPv4 / IPv6 Address</option>
              </select>
            </div>

            <div>
              <label className="text-xs font-semibold text-slate-300 uppercase">Target Pattern</label>
              <input
                type="text"
                placeholder="e.g. *.corp.example.com or 203.0.113.0/24"
                value={scopeTargetInput}
                onChange={(e) => setScopeTargetInput(e.target.value)}
                required
                className="w-full mt-1.5 px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
              />
              <p className="text-[11px] text-slate-500 mt-1">
                Strict SSRF Guardrail: Internal loopback (127.0.0.1) and cloud metadata (169.254.169.254) are rejected.
              </p>
            </div>

            <div>
              <label className="text-xs font-semibold text-slate-300 uppercase">Business Justification</label>
              <input
                type="text"
                placeholder="e.g. Primary corporate cloud DNS zone"
                value={scopeDescInput}
                onChange={(e) => setScopeDescInput(e.target.value)}
                className="w-full mt-1.5 px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
              />
            </div>
          </ModalBody>
          <ModalFooter>
            <Button variant="outline" type="button" onClick={() => setIsScopeModalOpen(false)}>Cancel</Button>
            <Button type="submit" disabled={isSavingScope} className="bg-cyan-600 hover:bg-cyan-500 text-white">
              {isSavingScope ? 'Validating...' : 'Authorize Scope'}
            </Button>
          </ModalFooter>
        </form>
      </Modal>

      {/* Resolve Exposure Modal */}
      {resolvingExposure && (
        <Modal isOpen={Boolean(resolvingExposure)} onClose={() => setResolvingExposure(null)}>
          <form onSubmit={handleResolveExposure}>
            <ModalHeader>
              <ModalTitle>Resolve Security Exposure</ModalTitle>
            </ModalHeader>
            <ModalBody className="flex flex-col gap-3">
              <div className="p-3 rounded bg-slate-900 border border-slate-800 text-sm text-slate-300">
                <div className="font-semibold text-slate-100">{resolvingExposure.title}</div>
                <div className="text-xs text-slate-400 mt-1">{resolvingExposure.description}</div>
              </div>

              <div>
                <label className="text-xs font-semibold text-slate-300 uppercase">Resolution Notes &amp; Audit Rationale</label>
                <textarea
                  rows={3}
                  required
                  placeholder="Explain why exposure was closed (e.g., ingress port blocked by firewall, WAF configured)..."
                  value={resolveNotesInput}
                  onChange={(e) => setResolveNotesInput(e.target.value)}
                  className="w-full mt-1.5 px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                />
              </div>
            </ModalBody>
            <ModalFooter>
              <Button variant="outline" type="button" onClick={() => setResolvingExposure(null)}>Cancel</Button>
              <Button type="submit" disabled={isResolving} className="bg-emerald-600 hover:bg-emerald-500 text-white">
                {isResolving ? 'Resolving...' : 'Confirm Resolution'}
              </Button>
            </ModalFooter>
          </form>
        </Modal>
      )}

      {/* Review Unknown Asset Modal */}
      {reviewingAsset && (
        <Modal isOpen={Boolean(reviewingAsset)} onClose={() => setReviewingAsset(null)}>
          <form onSubmit={handleReviewUnknownAsset}>
            <ModalHeader>
              <ModalTitle>Triage &amp; Review Unknown Asset</ModalTitle>
            </ModalHeader>
            <ModalBody className="flex flex-col gap-4">
              <div className="p-3 rounded bg-slate-900 border border-slate-800 text-sm">
                <div className="font-mono text-cyan-400 font-semibold">{reviewingAsset.canonical_name}</div>
                <div className="text-xs text-slate-400 mt-0.5">{reviewingAsset.asset_type} &bull; {reviewingAsset.reason}</div>
              </div>

              <div>
                <label className="text-xs font-semibold text-slate-300 uppercase">Triage Action</label>
                <select
                  value={reviewAction}
                  onChange={(e) => setReviewAction(e.target.value as any)}
                  className="w-full mt-1.5 px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-sm text-slate-200 focus:outline-none focus:border-cyan-500"
                >
                  <option value="APPROVE">Approve as Legitimate Corporate Asset</option>
                  <option value="ASSIGN_OWNER">Assign Owner &amp; Team</option>
                  <option value="MARK_UNAUTHORIZED">Mark Unauthorized (Flag Shadow IT)</option>
                  <option value="ADD_TO_WATCHLIST">Add Indicator to Threat Watchlist</option>
                </select>
              </div>

              {reviewAction === 'ASSIGN_OWNER' && (
                <>
                  <div>
                    <label className="text-xs font-semibold text-slate-300 uppercase">Owner Email / Name</label>
                    <input
                      type="text"
                      required
                      placeholder="e.g. devops-lead@company.com"
                      value={reviewOwnerInput}
                      onChange={(e) => setReviewOwnerInput(e.target.value)}
                      className="w-full mt-1.5 px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-sm text-slate-200 focus:outline-none focus:border-cyan-500"
                    />
                  </div>
                  <div>
                    <label className="text-xs font-semibold text-slate-300 uppercase">Team / Unit</label>
                    <input
                      type="text"
                      placeholder="e.g. Infrastructure Engineering"
                      value={reviewTeamInput}
                      onChange={(e) => setReviewTeamInput(e.target.value)}
                      className="w-full mt-1.5 px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-sm text-slate-200 focus:outline-none focus:border-cyan-500"
                    />
                  </div>
                </>
              )}

              <div>
                <label className="text-xs font-semibold text-slate-300 uppercase">Review Notes / Audit Trail</label>
                <textarea
                  rows={2}
                  required
                  placeholder="Record rationale for this decision..."
                  value={reviewNotesInput}
                  onChange={(e) => setReviewNotesInput(e.target.value)}
                  className="w-full mt-1.5 px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-sm text-slate-200 focus:outline-none focus:border-cyan-500"
                />
              </div>
            </ModalBody>
            <ModalFooter>
              <Button variant="outline" type="button" onClick={() => setReviewingAsset(null)}>Cancel</Button>
              <Button type="submit" disabled={isReviewing} className="bg-cyan-600 hover:bg-cyan-500 text-white">
                {isReviewing ? 'Saving...' : 'Submit Triage'}
              </Button>
            </ModalFooter>
          </form>
        </Modal>
      )}
    </div>
  );
};
