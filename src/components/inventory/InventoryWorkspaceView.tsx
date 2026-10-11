import React, { useState, useEffect, useCallback } from 'react';
import {
  Boxes,
  Server,
  UserCheck,
  ShieldAlert,
  AlertTriangle,
  Search,
  RefreshCw,
  Plus,
  Trash2,
  CheckCircle2,
  Clock,
  ChevronRight,
  Shield,
  Layers,
  Database,
  Radio,
  Network,
  Users,
  KeyRound,
  FileCheck2,
  Flame,
  Sliders,
  History,
  Sparkles,
  Info,
} from 'lucide-react';
import type {
  InventoryAsset,
  InventoryAssetDetail,
  InventoryIdentity,
  InventoryIdentityDetail,
  InventorySource,
  InventoryConflict,
  InventoryOverviewStats,
  AssetType,
  IdentityType,
} from '../../types/inventory';
import type {
  PriorityBand,
  PriorityExplanation,
  PriorityHistoryItem,
} from '../../types/assetPrioritization';
import { InventoryService } from '../../services/inventoryService';
import { AssetPrioritizationService } from '../../services/assetPrioritizationService';
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

interface InventoryWorkspaceViewProps {
  initialAssetId?: string;
  initialTab?: 'assets' | 'identities' | 'sources' | 'conflicts';
}

export const InventoryWorkspaceView: React.FC<InventoryWorkspaceViewProps> = ({
  initialAssetId,
  initialTab,
}) => {
  // Tabs
  const [activeTab, setActiveTab] = useState<'assets' | 'identities' | 'sources' | 'conflicts'>(initialTab || 'assets');

  // Overview Stats
  const [overview, setOverview] = useState<InventoryOverviewStats | null>(null);
  const [loadingOverview, setLoadingOverview] = useState(false);

  // Asset Inventory State
  const [assets, setAssets] = useState<InventoryAsset[]>([]);
  const [totalAssets, setTotalAssets] = useState(0);
  const [loadingAssets, setLoadingAssets] = useState(false);
  const [assetSearch, setAssetSearch] = useState('');
  const [filterAssetType, setFilterAssetType] = useState('ALL');
  const [filterAssetStatus, setFilterAssetStatus] = useState('ALL');
  const [filterEnvironment, setFilterEnvironment] = useState('ALL');
  const [filterCriticality, setFilterCriticality] = useState('ALL');
  const [filterPriority, setFilterPriority] = useState('ALL');
  const [filterOwnershipStatus, setFilterOwnershipStatus] = useState('ALL');
  const [filterManagedOnly, setFilterManagedOnly] = useState<boolean | undefined>(undefined);
  const [filterStaleOnly, setFilterStaleOnly] = useState<boolean | undefined>(undefined);

  // Identity Inventory State
  const [identities, setIdentities] = useState<InventoryIdentity[]>([]);
  const [totalIdentities, setTotalIdentities] = useState(0);
  const [loadingIdentities, setLoadingIdentities] = useState(false);
  const [identitySearch, setIdentitySearch] = useState('');
  const [filterIdentityType, setFilterIdentityType] = useState('ALL');
  const [filterPrivilegedOnly, setFilterPrivilegedOnly] = useState<boolean | undefined>(undefined);
  const [filterDormantOnly, setFilterDormantOnly] = useState<boolean | undefined>(undefined);
  const [filterOrphanedOnly, setFilterOrphanedOnly] = useState<boolean | undefined>(undefined);

  // Sources State
  const [sources, setSources] = useState<InventorySource[]>([]);
  const [loadingSources, setLoadingSources] = useState(false);

  // Conflicts State
  const [conflicts, setConflicts] = useState<InventoryConflict[]>([]);
  const [totalConflicts, setTotalConflicts] = useState(0);
  const [loadingConflicts, setLoadingConflicts] = useState(false);
  const [filterConflictStatus, setFilterConflictStatus] = useState('ALL');

  // Detail Drawers & Section 64 Priority State
  const [selectedAssetId, setSelectedAssetId] = useState<string | null>(initialAssetId || null);
  const [selectedAssetDetail, setSelectedAssetDetail] = useState<InventoryAssetDetail | null>(null);
  const [loadingAssetDetail, setLoadingAssetDetail] = useState(false);
  const [assetDetailTab, setAssetDetailTab] = useState<'overview' | 'priority' | 'exposures' | 'services' | 'neighbors' | 'timeline'>('overview');
  const [priorityExplanation, setPriorityExplanation] = useState<PriorityExplanation | null>(null);
  const [priorityHistory, setPriorityHistory] = useState<PriorityHistoryItem[]>([]);
  const [loadingPriority, setLoadingPriority] = useState(false);
  const [isRecalculatingPriority, setIsRecalculatingPriority] = useState(false);

  // Section 64 Manual Override Modal State
  const [isOverrideModalOpen, setIsOverrideModalOpen] = useState(false);
  const [overrideBand, setOverrideBand] = useState<PriorityBand>('P1');
  const [overrideReason, setOverrideReason] = useState('');
  const [overrideDurationHours, setOverrideDurationHours] = useState<number | undefined>(24);
  const [isSubmittingOverride, setIsSubmittingOverride] = useState(false);

  const [selectedIdentityId, setSelectedIdentityId] = useState<string | null>(null);
  const [selectedIdentityDetail, setSelectedIdentityDetail] = useState<InventoryIdentityDetail | null>(null);
  const [loadingIdentityDetail, setLoadingIdentityDetail] = useState(false);

  // Action Modals
  const [assigningAsset, setAssigningAsset] = useState<InventoryAsset | null>(null);
  const [ownerInput, setOwnerInput] = useState('');
  const [teamInput, setTeamInput] = useState('');
  const [departmentInput, setDepartmentInput] = useState('');
  const [assignReasonInput, setAssignReasonInput] = useState('');

  const [resolvingConflict, setResolvingConflict] = useState<InventoryConflict | null>(null);
  const [conflictResolvedValue, setConflictResolvedValue] = useState('');
  const [conflictReasonInput, setConflictReasonInput] = useState('');

  const [isAddSourceOpen, setIsAddSourceOpen] = useState(false);
  const [newSourceType, setNewSourceType] = useState('CMDB');
  const [newSourceName, setNewSourceName] = useState('');
  const [newSourceWeight, setNewSourceWeight] = useState(80);

  const [isSyncing, setIsSyncing] = useState(false);
  const [isReconciling, setIsReconciling] = useState(false);
  const [operationMsg, setOperationMsg] = useState<string | null>(null);

  // ---------------------------------------------------------------------------
  // Data Fetchers
  // ---------------------------------------------------------------------------

  const fetchOverview = useCallback(async () => {
    setLoadingOverview(true);
    try {
      const stats = await InventoryService.getOverviewStats();
      setOverview(stats);
    } catch (err) {
      console.error('Failed to load inventory stats:', err);
    } finally {
      setLoadingOverview(false);
    }
  }, []);

  const fetchAssets = useCallback(async () => {
    setLoadingAssets(true);
    try {
      const res = await InventoryService.listAssets({
        asset_type: filterAssetType,
        status: filterAssetStatus,
        environment: filterEnvironment,
        criticality: filterCriticality,
        ownership_status: filterOwnershipStatus,
        is_managed: filterManagedOnly,
        is_stale: filterStaleOnly,
        search: assetSearch || undefined,
        limit: 50,
      });
      setAssets(res.items);
      setTotalAssets(res.total);
    } catch (err) {
      console.error('Failed to list assets:', err);
    } finally {
      setLoadingAssets(false);
    }
  }, [
    filterAssetType,
    filterAssetStatus,
    filterEnvironment,
    filterCriticality,
    filterOwnershipStatus,
    filterManagedOnly,
    filterStaleOnly,
    assetSearch,
  ]);

  const fetchIdentities = useCallback(async () => {
    setLoadingIdentities(true);
    try {
      const res = await InventoryService.listIdentities({
        identity_type: filterIdentityType,
        is_privileged: filterPrivilegedOnly,
        is_dormant: filterDormantOnly,
        is_orphaned: filterOrphanedOnly,
        search: identitySearch || undefined,
        limit: 50,
      });
      setIdentities(res.items);
      setTotalIdentities(res.total);
    } catch (err) {
      console.error('Failed to list identities:', err);
    } finally {
      setLoadingIdentities(false);
    }
  }, [
    filterIdentityType,
    filterPrivilegedOnly,
    filterDormantOnly,
    filterOrphanedOnly,
    identitySearch,
  ]);

  const fetchSources = useCallback(async () => {
    setLoadingSources(true);
    try {
      const res = await InventoryService.listSources();
      setSources(res);
    } catch (err) {
      console.error('Failed to list sources:', err);
    } finally {
      setLoadingSources(false);
    }
  }, []);

  const fetchConflicts = useCallback(async () => {
    setLoadingConflicts(true);
    try {
      const res = await InventoryService.listConflicts({
        status: filterConflictStatus,
        limit: 50,
      });
      setConflicts(res.items);
      setTotalConflicts(res.total);
    } catch (err) {
      console.error('Failed to list conflicts:', err);
    } finally {
      setLoadingConflicts(false);
    }
  }, [filterConflictStatus]);

  const fetchAssetDetail = useCallback(async (id: string) => {
    setLoadingAssetDetail(true);
    try {
      const detail = await InventoryService.getAssetDetail(id);
      setSelectedAssetDetail(detail);
    } catch (err) {
      console.error('Failed to get asset detail:', err);
    } finally {
      setLoadingAssetDetail(false);
    }
  }, []);

  const fetchAssetPriorityData = useCallback(async (id: string) => {
    setLoadingPriority(true);
    try {
      const [explanation, historyRes] = await Promise.all([
        AssetPrioritizationService.getPriorityExplanation(id).catch(() => null),
        AssetPrioritizationService.getPriorityHistory(id, 20).catch(() => ({ items: [], total: 0 })),
      ]);
      setPriorityExplanation(explanation);
      setPriorityHistory(historyRes.items || []);
    } catch (err) {
      console.error('Failed to get priority data:', err);
    } finally {
      setLoadingPriority(false);
    }
  }, []);

  const fetchIdentityDetail = useCallback(async (id: string) => {
    setLoadingIdentityDetail(true);
    try {
      const detail = await InventoryService.getIdentityDetail(id);
      setSelectedIdentityDetail(detail);
    } catch (err) {
      console.error('Failed to get identity detail:', err);
    } finally {
      setLoadingIdentityDetail(false);
    }
  }, []);

  useEffect(() => {
    fetchOverview();
    fetchAssets();
    fetchIdentities();
    fetchSources();
    fetchConflicts();
  }, [fetchOverview, fetchAssets, fetchIdentities, fetchSources, fetchConflicts]);

  useEffect(() => {
    if (selectedAssetId) {
      fetchAssetDetail(selectedAssetId);
      fetchAssetPriorityData(selectedAssetId);
    } else {
      setSelectedAssetDetail(null);
      setPriorityExplanation(null);
      setPriorityHistory([]);
    }
  }, [selectedAssetId, fetchAssetDetail, fetchAssetPriorityData]);

  useEffect(() => {
    if (selectedIdentityId) {
      fetchIdentityDetail(selectedIdentityId);
    } else {
      setSelectedIdentityDetail(null);
    }
  }, [selectedIdentityId, fetchIdentityDetail]);

  const handleRecalculatePriority = async () => {
    if (!selectedAssetId) return;
    setIsRecalculatingPriority(true);
    try {
      await AssetPrioritizationService.recalculate([selectedAssetId], true);
      await Promise.all([
        fetchAssetDetail(selectedAssetId),
        fetchAssetPriorityData(selectedAssetId),
        fetchAssets(),
        fetchOverview(),
      ]);
    } catch (err) {
      console.error('Failed to recalculate priority:', err);
    } finally {
      setIsRecalculatingPriority(false);
    }
  };

  const handleApplyOverrideSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedAssetId || !overrideReason.trim()) return;
    setIsSubmittingOverride(true);
    try {
      await AssetPrioritizationService.applyOverride(
        selectedAssetId,
        overrideBand,
        overrideReason.trim(),
        overrideDurationHours
      );
      setIsOverrideModalOpen(false);
      setOverrideReason('');
      await Promise.all([
        fetchAssetDetail(selectedAssetId),
        fetchAssetPriorityData(selectedAssetId),
        fetchAssets(),
      ]);
    } catch (err) {
      console.error('Failed to apply override:', err);
    } finally {
      setIsSubmittingOverride(false);
    }
  };

  const handleRemoveOverride = async () => {
    if (!selectedAssetId) return;
    if (!window.confirm('Remove manual priority override and revert to calculated priority?')) return;
    try {
      await AssetPrioritizationService.removeOverride(selectedAssetId);
      await Promise.all([
        fetchAssetDetail(selectedAssetId),
        fetchAssetPriorityData(selectedAssetId),
        fetchAssets(),
      ]);
    } catch (err) {
      console.error('Failed to remove override:', err);
    }
  };

  // ---------------------------------------------------------------------------
  // Action Handlers
  // ---------------------------------------------------------------------------

  const handleRunSync = async () => {
    setIsSyncing(true);
    setOperationMsg(null);
    try {
      const res = await InventoryService.runSync();
      setOperationMsg(`Synchronization completed: ${res.assets_synced} assets, ${res.identities_synced} identities synchronized.`);
      await Promise.all([fetchOverview(), fetchAssets(), fetchIdentities(), fetchConflicts()]);
      setTimeout(() => setOperationMsg(null), 5000);
    } catch (err) {
      console.error('Sync failed:', err);
      setOperationMsg('Synchronization sweep encountered an error.');
    } finally {
      setIsSyncing(false);
    }
  };

  const handleRunReconciliation = async () => {
    setIsReconciling(true);
    setOperationMsg(null);
    try {
      const report = await InventoryService.runReconciliation();
      setOperationMsg(`Reconciliation finished: ${report.stale_assets_flagged} stale assets flagged, ${report.dormant_identities_flagged} dormant identities.`);
      await Promise.all([fetchOverview(), fetchAssets(), fetchIdentities(), fetchConflicts()]);
      setTimeout(() => setOperationMsg(null), 5000);
    } catch (err) {
      console.error('Reconciliation failed:', err);
      setOperationMsg('Reconciliation sweep encountered an error.');
    } finally {
      setIsReconciling(false);
    }
  };

  const handleAssignOwnerSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!assigningAsset || !ownerInput.trim()) return;

    try {
      await InventoryService.assignAssetOwner(assigningAsset.id, {
        owner: ownerInput.trim(),
        team: teamInput.trim() || undefined,
        department: departmentInput.trim() || undefined,
        reason: assignReasonInput.trim() || undefined,
      });
      setAssigningAsset(null);
      setOwnerInput('');
      setTeamInput('');
      setDepartmentInput('');
      setAssignReasonInput('');
      await Promise.all([fetchOverview(), fetchAssets()]);
    } catch (err) {
      console.error('Failed to assign owner:', err);
    }
  };

  const handleResolveConflictSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!resolvingConflict || !conflictResolvedValue.trim()) return;

    try {
      await InventoryService.resolveConflict(resolvingConflict.id, {
        selected_value: conflictResolvedValue.trim(),
        resolution_reason: conflictReasonInput.trim() || 'Manual resolution by analyst',
      });
      setResolvingConflict(null);
      setConflictResolvedValue('');
      setConflictReasonInput('');
      await Promise.all([fetchOverview(), fetchConflicts(), fetchAssets(), fetchIdentities()]);
    } catch (err) {
      console.error('Failed to resolve conflict:', err);
    }
  };

  const handleCreateSourceSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newSourceName.trim()) return;

    try {
      await InventoryService.createSource({
        source_type: newSourceType,
        name: newSourceName.trim(),
        authority_weight: Number(newSourceWeight),
      });
      setIsAddSourceOpen(false);
      setNewSourceName('');
      await fetchSources();
    } catch (err) {
      console.error('Failed to create source:', err);
    }
  };

  const handleDeleteSource = async (id: string) => {
    if (!window.confirm('Are you sure you want to delete this inventory source?')) return;
    try {
      await InventoryService.deleteSource(id);
      await fetchSources();
    } catch (err) {
      console.error('Failed to delete source:', err);
    }
  };

  // Helper formatting badges
  const getCriticalityBadgeClass = (crit: string) => {
    switch (crit.toUpperCase()) {
      case 'CRITICAL':
        return 'bg-red-950/80 text-red-300 border-red-800/60';
      case 'HIGH':
        return 'bg-orange-950/80 text-orange-300 border-orange-800/60';
      case 'MEDIUM':
        return 'bg-amber-950/80 text-amber-300 border-amber-800/60';
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  const getPriorityBadgeClass = (priority?: string) => {
    switch (priority?.toUpperCase()) {
      case 'P1':
        return 'bg-rose-950/80 text-rose-300 border-rose-700/80 font-bold';
      case 'P2':
        return 'bg-orange-950/80 text-orange-300 border-orange-700/80 font-bold';
      case 'P3':
        return 'bg-amber-950/80 text-amber-300 border-amber-700/80 font-medium';
      case 'P4':
        return 'bg-blue-950/80 text-blue-300 border-blue-700/80 font-medium';
      default:
        return 'bg-slate-800 text-slate-400 border-slate-700';
    }
  };

  const getAssetTypeIcon = (type: AssetType) => {
    switch (type) {
      case 'SERVER':
      case 'ENDPOINT':
      case 'DEVICE':
        return <Server className="w-4 h-4 text-cyan-400" />;
      case 'DATABASE':
        return <Database className="w-4 h-4 text-emerald-400" />;
      case 'APPLICATION':
      case 'WEB_APPLICATION':
      case 'API':
        return <Layers className="w-4 h-4 text-indigo-400" />;
      default:
        return <Boxes className="w-4 h-4 text-slate-400" />;
    }
  };

  const getIdentityTypeIcon = (type: IdentityType) => {
    switch (type) {
      case 'USER':
        return <Users className="w-4 h-4 text-cyan-400" />;
      case 'SERVICE_ACCOUNT':
        return <KeyRound className="w-4 h-4 text-amber-400" />;
      default:
        return <UserCheck className="w-4 h-4 text-indigo-400" />;
    }
  };

  return (
    <div className="flex flex-col gap-6 p-6 max-w-[1600px] mx-auto text-slate-100 min-h-screen">
      {/* 1. HEADER & ACTIONS */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-cyan-950/80 border border-cyan-800/60 text-cyan-400">
              <Boxes className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-slate-100 flex items-center gap-2">
                Asset &amp; Identity Inventory
                <Badge className="bg-cyan-950/90 text-cyan-300 border-cyan-800/60 text-xs">Section 63</Badge>
              </h1>
              <p className="text-sm text-slate-400 mt-0.5">
                Authoritative organizational inventory, identity governance &amp; source precedence reconciliation
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2.5">
          <Button
            variant="outline"
            size="sm"
            onClick={handleRunReconciliation}
            disabled={isReconciling}
            className="border-slate-700 hover:border-cyan-500/50"
          >
            <RefreshCw className={cn('w-4 h-4 mr-2 text-cyan-400', isReconciling && 'animate-spin')} />
            Reconcile States
          </Button>

          <Button
            variant="outline"
            size="sm"
            onClick={handleRunSync}
            disabled={isSyncing}
            className="border-slate-700 hover:border-emerald-500/50"
          >
            <Radio className={cn('w-4 h-4 mr-2 text-emerald-400', isSyncing && 'animate-pulse')} />
            Sync Sources
          </Button>

          <Button
            size="sm"
            onClick={() => setIsAddSourceOpen(true)}
            className="bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold"
          >
            <Plus className="w-4 h-4 mr-1.5" />
            Add Source
          </Button>
        </div>
      </div>

      {operationMsg && (
        <div className="p-3.5 rounded-xl bg-cyan-950/50 border border-cyan-800 text-cyan-200 text-sm flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 text-cyan-400 shrink-0" />
          <span>{operationMsg}</span>
        </div>
      )}

      {/* 2. KPI METRIC CARDS */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3.5">
        <Card className="p-4 bg-slate-900/60 border-slate-800 flex flex-col justify-between">
          <div className="text-xs font-medium text-slate-400 flex items-center justify-between">
            <span>Total Assets</span>
            <Boxes className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="mt-2">
            <div className="text-2xl font-bold font-mono text-slate-100">
              {loadingOverview ? '...' : overview?.total_assets ?? 0}
            </div>
            <div className="text-[11px] text-slate-400 mt-1">
              Active: <span className="text-emerald-400 font-semibold">{overview?.active_assets ?? 0}</span>
            </div>
          </div>
        </Card>

        <Card className="p-4 bg-slate-900/60 border-slate-800 flex flex-col justify-between">
          <div className="text-xs font-medium text-slate-400 flex items-center justify-between">
            <span>Unmanaged Fleet</span>
            <ShieldAlert className="w-4 h-4 text-amber-400" />
          </div>
          <div className="mt-2">
            <div className="text-2xl font-bold font-mono text-amber-400">
              {loadingOverview ? '...' : overview?.unmanaged_assets ?? 0}
            </div>
            <div className="text-[11px] text-slate-400 mt-1">
              Endpoints lacking agent
            </div>
          </div>
        </Card>

        <Card className="p-4 bg-slate-900/60 border-slate-800 flex flex-col justify-between">
          <div className="text-xs font-medium text-slate-400 flex items-center justify-between">
            <span>Stale Assets</span>
            <Clock className="w-4 h-4 text-orange-400" />
          </div>
          <div className="mt-2">
            <div className="text-2xl font-bold font-mono text-orange-400">
              {loadingOverview ? '...' : overview?.stale_assets ?? 0}
            </div>
            <div className="text-[11px] text-slate-400 mt-1">
              No telemetry &gt; 30d
            </div>
          </div>
        </Card>

        <Card className="p-4 bg-slate-900/60 border-slate-800 flex flex-col justify-between">
          <div className="text-xs font-medium text-slate-400 flex items-center justify-between">
            <span>Identities</span>
            <Users className="w-4 h-4 text-indigo-400" />
          </div>
          <div className="mt-2">
            <div className="text-2xl font-bold font-mono text-slate-100">
              {loadingOverview ? '...' : overview?.total_identities ?? 0}
            </div>
            <div className="text-[11px] text-slate-400 mt-1">
              Privileged: <span className="text-cyan-400 font-semibold">{overview?.privileged_identities ?? 0}</span>
            </div>
          </div>
        </Card>

        <Card className="p-4 bg-slate-900/60 border-slate-800 flex flex-col justify-between">
          <div className="text-xs font-medium text-slate-400 flex items-center justify-between">
            <span>Dormant &amp; Orphaned</span>
            <AlertTriangle className="w-4 h-4 text-red-400" />
          </div>
          <div className="mt-2">
            <div className="text-2xl font-bold font-mono text-red-400">
              {loadingOverview ? '...' : (overview?.dormant_identities ?? 0) + (overview?.orphaned_identities ?? 0)}
            </div>
            <div className="text-[11px] text-slate-400 mt-1">
              Orphaned: <span className="text-rose-400">{overview?.orphaned_identities ?? 0}</span>
            </div>
          </div>
        </Card>

        <Card className="p-4 bg-slate-900/60 border-slate-800 flex flex-col justify-between">
          <div className="text-xs font-medium text-slate-400 flex items-center justify-between">
            <span>Source Conflicts</span>
            <Network className="w-4 h-4 text-violet-400" />
          </div>
          <div className="mt-2">
            <div className="text-2xl font-bold font-mono text-violet-400">
              {loadingOverview ? '...' : overview?.pending_conflicts ?? 0}
            </div>
            <div className="text-[11px] text-slate-400 mt-1">
              Discrepancies pending review
            </div>
          </div>
        </Card>
      </div>

      {/* 3. NAVIGATION TABS */}
      <div className="flex border-b border-slate-800 gap-6 text-sm font-medium">
        <button
          onClick={() => setActiveTab('assets')}
          className={cn(
            'pb-3 border-b-2 transition-colors flex items-center gap-2',
            activeTab === 'assets'
              ? 'border-cyan-500 text-cyan-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          )}
        >
          <Boxes className="w-4 h-4" />
          Asset Inventory ({totalAssets})
        </button>

        <button
          onClick={() => setActiveTab('identities')}
          className={cn(
            'pb-3 border-b-2 transition-colors flex items-center gap-2',
            activeTab === 'identities'
              ? 'border-cyan-500 text-cyan-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          )}
        >
          <Users className="w-4 h-4" />
          Identity &amp; Accounts ({totalIdentities})
        </button>

        <button
          onClick={() => setActiveTab('sources')}
          className={cn(
            'pb-3 border-b-2 transition-colors flex items-center gap-2',
            activeTab === 'sources'
              ? 'border-cyan-500 text-cyan-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          )}
        >
          <FileCheck2 className="w-4 h-4" />
          Source Precedence ({sources.length})
        </button>

        <button
          onClick={() => setActiveTab('conflicts')}
          className={cn(
            'pb-3 border-b-2 transition-colors flex items-center gap-2',
            activeTab === 'conflicts'
              ? 'border-cyan-500 text-cyan-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          )}
        >
          <Network className="w-4 h-4" />
          Conflict Workspace
          {totalConflicts > 0 && (
            <Badge className="bg-amber-950 text-amber-300 border-amber-800 text-[10px] ml-1">
              {totalConflicts}
            </Badge>
          )}
        </button>
      </div>

      {/* TAB 1: ASSET INVENTORY */}
      {activeTab === 'assets' && (
        <div className="flex flex-col gap-4">
          {/* Filters */}
          <div className="flex flex-wrap items-center justify-between gap-3 p-3.5 rounded-xl bg-slate-900/40 border border-slate-800">
            <div className="flex items-center gap-2.5 flex-1 min-w-[280px]">
              <Search className="w-4 h-4 text-slate-400 shrink-0" />
              <input
                type="text"
                placeholder="Search by asset name, owner, team, IP, or hostname..."
                value={assetSearch}
                onChange={(e) => setAssetSearch(e.target.value)}
                className="bg-transparent text-sm text-slate-200 placeholder-slate-500 focus:outline-none w-full"
              />
            </div>

            <div className="flex flex-wrap items-center gap-2 text-xs">
              <select
                value={filterAssetType}
                onChange={(e) => setFilterAssetType(e.target.value)}
                className="bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-slate-300 focus:outline-none"
              >
                <option value="ALL">All Asset Types</option>
                <option value="ENDPOINT">Endpoint / Host</option>
                <option value="SERVER">Server</option>
                <option value="APPLICATION">Application</option>
                <option value="API">API Gateway</option>
                <option value="DATABASE">Database</option>
                <option value="DOMAIN">Domain</option>
                <option value="CLOUD_RESOURCE">Cloud Resource</option>
              </select>

              <select
                value={filterCriticality}
                onChange={(e) => setFilterCriticality(e.target.value)}
                className="bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-slate-300 focus:outline-none"
              >
                <option value="ALL">All Criticalities</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
              </select>

              <select
                value={filterPriority}
                onChange={(e) => setFilterPriority(e.target.value)}
                className="bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-slate-300 focus:outline-none"
              >
                <option value="ALL">All Priorities</option>
                <option value="P1">P1 — Critical Attention</option>
                <option value="P2">P2 — High Attention</option>
                <option value="P3">P3 — Medium Attention</option>
                <option value="P4">P4 — Low Attention</option>
                <option value="OVERRIDDEN">Manual Override Only</option>
              </select>

              <select
                value={filterEnvironment}
                onChange={(e) => setFilterEnvironment(e.target.value)}
                className="bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-slate-300 focus:outline-none"
              >
                <option value="ALL">All Environments</option>
                <option value="PRODUCTION">Production</option>
                <option value="STAGING">Staging</option>
                <option value="DEVELOPMENT">Development</option>
                <option value="TEST">Test / QA</option>
                <option value="LAB">Lab / Sandbox</option>
              </select>

              <select
                value={filterAssetStatus}
                onChange={(e) => setFilterAssetStatus(e.target.value)}
                className="bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-slate-300 focus:outline-none"
              >
                <option value="ALL">All Statuses</option>
                <option value="ACTIVE">Active</option>
                <option value="INACTIVE">Inactive</option>
                <option value="STALE">Stale</option>
                <option value="RETIRED">Retired</option>
                <option value="UNKNOWN">Unknown</option>
              </select>

              <select
                value={filterOwnershipStatus}
                onChange={(e) => setFilterOwnershipStatus(e.target.value)}
                className="bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-slate-300 focus:outline-none"
              >
                <option value="ALL">All Ownership</option>
                <option value="ASSIGNED">Assigned Owner</option>
                <option value="UNASSIGNED">Unassigned / Shadow IT</option>
                <option value="CONFLICTED">Conflicted</option>
              </select>

              <label className="flex items-center gap-1.5 cursor-pointer ml-1 text-slate-400">
                <input
                  type="checkbox"
                  checked={filterManagedOnly === true}
                  onChange={(e) => setFilterManagedOnly(e.target.checked ? true : undefined)}
                  className="rounded border-slate-700 bg-slate-900"
                />
                Managed Only
              </label>

              <label className="flex items-center gap-1.5 cursor-pointer ml-1 text-slate-400">
                <input
                  type="checkbox"
                  checked={filterStaleOnly === true}
                  onChange={(e) => setFilterStaleOnly(e.target.checked ? true : undefined)}
                  className="rounded border-slate-700 bg-slate-900"
                />
                Stale Only
              </label>
            </div>
          </div>

          {/* Asset Table */}
          <div className="rounded-xl border border-slate-800 overflow-hidden bg-slate-900/30">
            <table className="w-full text-left text-sm text-slate-300">
              <thead className="bg-slate-900/70 border-b border-slate-800 text-xs font-semibold uppercase text-slate-400">
                <tr>
                  <th className="py-3 px-4">Asset Canonical Name</th>
                  <th className="py-3 px-4">Type</th>
                  <th className="py-3 px-4">Owner &amp; Team</th>
                  <th className="py-3 px-4">Environment</th>
                  <th className="py-3 px-4">Criticality</th>
                  <th className="py-3 px-4">Priority (SOC)</th>
                  <th className="py-3 px-4">Status &amp; Management</th>
                  <th className="py-3 px-4">Risk</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-normal">
                {loadingAssets ? (
                  <tr>
                    <td colSpan={9} className="py-12 text-center text-slate-500">
                      <RefreshCw className="w-6 h-6 animate-spin mx-auto mb-2 text-cyan-500" />
                      Loading asset inventory...
                    </td>
                  </tr>
                ) : assets.filter((asset) => {
                    if (filterPriority === 'ALL') return true;
                    if (filterPriority === 'OVERRIDDEN') return Boolean(asset.priority_override);
                    const eff = asset.effective_priority || asset.priority_band || 'P4';
                    return eff === filterPriority;
                  }).length === 0 ? (
                  <tr>
                    <td colSpan={9} className="py-12 text-center text-slate-500">
                      No assets found matching selected filters.
                    </td>
                  </tr>
                ) : (
                  assets
                    .filter((asset) => {
                      if (filterPriority === 'ALL') return true;
                      if (filterPriority === 'OVERRIDDEN') return Boolean(asset.priority_override);
                      const eff = asset.effective_priority || asset.priority_band || 'P4';
                      return eff === filterPriority;
                    })
                    .map((asset) => (
                    <tr
                      key={asset.id}
                      className="hover:bg-slate-800/40 transition-colors cursor-pointer"
                      onClick={() => setSelectedAssetId(asset.id)}
                    >
                      <td className="py-3 px-4 font-mono font-medium text-slate-100 flex items-center gap-2">
                        {getAssetTypeIcon(asset.asset_type)}
                        <span>{asset.canonical_name}</span>
                      </td>

                      <td className="py-3 px-4">
                        <Badge className="bg-slate-800 text-slate-300 text-xs">{asset.asset_type}</Badge>
                      </td>

                      <td className="py-3 px-4">
                        <div className="font-medium text-slate-200">
                          {asset.owner && asset.owner !== 'Unknown' ? (
                            asset.owner
                          ) : (
                            <span className="text-amber-400 italic">Unassigned</span>
                          )}
                        </div>
                        {asset.team && <div className="text-[11px] text-slate-400">{asset.team}</div>}
                      </td>

                      <td className="py-3 px-4">
                        <Badge className="bg-slate-900 border border-slate-700 text-slate-300 text-xs">
                          {asset.environment}
                        </Badge>
                      </td>

                      <td className="py-3 px-4">
                        <Badge className={cn('text-xs', getCriticalityBadgeClass(asset.criticality))}>
                          {asset.criticality}
                        </Badge>
                      </td>

                      <td className="py-3 px-4">
                        <div className="flex items-center gap-1.5 flex-wrap">
                          <Badge className={cn('text-xs font-mono font-bold', getPriorityBadgeClass(asset.effective_priority || asset.priority_band))}>
                            {asset.effective_priority || asset.priority_band || 'P4'}
                          </Badge>
                          {asset.priority_score !== undefined && (
                            <span className="text-[11px] font-mono text-slate-400">
                              {asset.priority_score.toFixed(1)}
                            </span>
                          )}
                          {asset.priority_override && (
                            <Badge className="bg-purple-950/80 text-purple-300 border-purple-800 text-[9px] px-1 py-0">
                              OVERRIDE
                            </Badge>
                          )}
                        </div>
                      </td>

                      <td className="py-3 px-4">
                        <div className="flex items-center gap-1.5 flex-wrap">
                          {asset.is_stale ? (
                            <Badge className="bg-orange-950/80 text-orange-300 border-orange-800 text-[10px]">
                              STALE
                            </Badge>
                          ) : (
                            <Badge className="bg-emerald-950/80 text-emerald-300 border-emerald-800 text-[10px]">
                              {asset.status}
                            </Badge>
                          )}
                          {!asset.is_managed && (
                            <Badge className="bg-amber-950/80 text-amber-300 border-amber-800 text-[10px]">
                              UNMANAGED
                            </Badge>
                          )}
                        </div>
                      </td>

                      <td className="py-3 px-4 font-mono font-medium">
                        <span
                          className={cn(
                            asset.risk_score >= 70
                              ? 'text-red-400'
                              : asset.risk_score >= 40
                              ? 'text-amber-400'
                              : 'text-emerald-400'
                          )}
                        >
                          {asset.risk_score.toFixed(1)}
                        </span>
                      </td>

                      <td className="py-3 px-4 text-right">
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={(e) => {
                            e.stopPropagation();
                            setAssigningAsset(asset);
                            setOwnerInput(asset.owner && asset.owner !== 'Unknown' ? asset.owner : '');
                            setTeamInput(asset.team || '');
                            setDepartmentInput(asset.department || '');
                          }}
                          className="text-cyan-400 hover:text-cyan-300 text-xs py-1"
                        >
                          Assign Owner
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

      {/* TAB 2: IDENTITY INVENTORY */}
      {activeTab === 'identities' && (
        <div className="flex flex-col gap-4">
          <div className="flex flex-wrap items-center justify-between gap-3 p-3.5 rounded-xl bg-slate-900/40 border border-slate-800">
            <div className="flex items-center gap-2.5 flex-1 min-w-[280px]">
              <Search className="w-4 h-4 text-slate-400 shrink-0" />
              <input
                type="text"
                placeholder="Search by identity email, username, department, or manager..."
                value={identitySearch}
                onChange={(e) => setIdentitySearch(e.target.value)}
                className="bg-transparent text-sm text-slate-200 placeholder-slate-500 focus:outline-none w-full"
              />
            </div>

            <div className="flex flex-wrap items-center gap-2 text-xs">
              <select
                value={filterIdentityType}
                onChange={(e) => setFilterIdentityType(e.target.value)}
                className="bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-slate-300 focus:outline-none"
              >
                <option value="ALL">All Identity Classes</option>
                <option value="USER">Human User</option>
                <option value="ACCOUNT">Credentialed Account</option>
                <option value="SERVICE_ACCOUNT">Service Account</option>
                <option value="APPLICATION_IDENTITY">Application Identity</option>
                <option value="API_CLIENT">API Client</option>
              </select>

              <label className="flex items-center gap-1.5 cursor-pointer ml-1 text-slate-400">
                <input
                  type="checkbox"
                  checked={filterPrivilegedOnly === true}
                  onChange={(e) => setFilterPrivilegedOnly(e.target.checked ? true : undefined)}
                  className="rounded border-slate-700 bg-slate-900"
                />
                Privileged Only
              </label>

              <label className="flex items-center gap-1.5 cursor-pointer ml-1 text-slate-400">
                <input
                  type="checkbox"
                  checked={filterDormantOnly === true}
                  onChange={(e) => setFilterDormantOnly(e.target.checked ? true : undefined)}
                  className="rounded border-slate-700 bg-slate-900"
                />
                Dormant Only
              </label>

              <label className="flex items-center gap-1.5 cursor-pointer ml-1 text-slate-400">
                <input
                  type="checkbox"
                  checked={filterOrphanedOnly === true}
                  onChange={(e) => setFilterOrphanedOnly(e.target.checked ? true : undefined)}
                  className="rounded border-slate-700 bg-slate-900"
                />
                Orphaned Only
              </label>
            </div>
          </div>

          <div className="rounded-xl border border-slate-800 overflow-hidden bg-slate-900/30">
            <table className="w-full text-left text-sm text-slate-300">
              <thead className="bg-slate-900/70 border-b border-slate-800 text-xs font-semibold uppercase text-slate-400">
                <tr>
                  <th className="py-3 px-4">Canonical Identifier</th>
                  <th className="py-3 px-4">Class</th>
                  <th className="py-3 px-4">Department &amp; Team</th>
                  <th className="py-3 px-4">Privilege &amp; Roles</th>
                  <th className="py-3 px-4">Status &amp; Inactivity</th>
                  <th className="py-3 px-4">Criticality</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-normal">
                {loadingIdentities ? (
                  <tr>
                    <td colSpan={7} className="py-12 text-center text-slate-500">
                      <RefreshCw className="w-6 h-6 animate-spin mx-auto mb-2 text-cyan-500" />
                      Loading enterprise identities...
                    </td>
                  </tr>
                ) : identities.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="py-12 text-center text-slate-500">
                      No identities matching filters.
                    </td>
                  </tr>
                ) : (
                  identities.map((ident) => (
                    <tr
                      key={ident.id}
                      className="hover:bg-slate-800/40 transition-colors cursor-pointer"
                      onClick={() => setSelectedIdentityId(ident.id)}
                    >
                      <td className="py-3 px-4 font-mono font-medium text-slate-100 flex items-center gap-2">
                        {getIdentityTypeIcon(ident.identity_type)}
                        <div>
                          <div>{ident.canonical_identifier}</div>
                          <div className="text-[11px] text-slate-400 font-sans">{ident.display_name}</div>
                        </div>
                      </td>

                      <td className="py-3 px-4">
                        <Badge className="bg-slate-800 text-slate-300 text-xs">{ident.identity_type}</Badge>
                      </td>

                      <td className="py-3 px-4 text-xs text-slate-300">
                        {ident.department || '—'} {ident.team && `(${ident.team})`}
                      </td>

                      <td className="py-3 px-4">
                        {ident.is_privileged ? (
                          <Badge className="bg-red-950/80 text-red-300 border-red-800/60 text-xs flex items-center gap-1 w-fit">
                            <KeyRound className="w-3 h-3 text-red-400" />
                            Privileged Admin
                          </Badge>
                        ) : (
                          <span className="text-slate-500 text-xs">Standard</span>
                        )}
                      </td>

                      <td className="py-3 px-4">
                        <div className="flex items-center gap-1 flex-wrap">
                          {ident.is_dormant && (
                            <Badge className="bg-orange-950/80 text-orange-300 border-orange-800 text-[10px]">
                              DORMANT
                            </Badge>
                          )}
                          {ident.is_orphaned && (
                            <Badge className="bg-rose-950/80 text-rose-300 border-rose-800 text-[10px]">
                              ORPHANED
                            </Badge>
                          )}
                          {!ident.is_dormant && !ident.is_orphaned && (
                            <Badge className="bg-emerald-950/80 text-emerald-300 border-emerald-800 text-[10px]">
                              {ident.status}
                            </Badge>
                          )}
                        </div>
                      </td>

                      <td className="py-3 px-4">
                        <Badge className={cn('text-xs', getCriticalityBadgeClass(ident.criticality))}>
                          {ident.criticality}
                        </Badge>
                      </td>

                      <td className="py-3 px-4 text-right">
                        <ChevronRight className="w-4 h-4 text-slate-500 inline" />
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB 3: SOURCE PRECEDENCE & HEALTH */}
      {activeTab === 'sources' && (
        <div className="flex flex-col gap-4">
          <div className="p-4 rounded-xl bg-indigo-950/30 border border-indigo-900/60 text-indigo-200 text-sm flex items-start gap-3">
            <Shield className="w-5 h-5 text-indigo-400 shrink-0 mt-0.5" />
            <div>
              <strong className="font-semibold text-indigo-100">Deterministic Source Authority:</strong>{' '}
              When multiple inventory sources provide differing metadata (e.g. owner or environment),
              CyberGuard automatically resolves conflicts using configured authority weights. CMDB (weight 100)
              takes precedence over Directory (80), which takes precedence over Endpoint Fleet (60).
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {loadingSources ? (
              <div className="col-span-2 py-12 text-center text-slate-500">
                <RefreshCw className="w-6 h-6 animate-spin mx-auto mb-2 text-cyan-500" />
                Loading sources...
              </div>
            ) : (
              sources.map((src) => (
                <Card key={src.id} className="p-5 bg-slate-900/50 border-slate-800 flex flex-col justify-between">
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <Badge className="bg-slate-800 text-slate-200 text-xs">{src.source_type}</Badge>
                        <Badge
                          className={cn(
                            'text-xs',
                            src.health_status === 'HEALTHY'
                              ? 'bg-emerald-950 text-emerald-300 border-emerald-800'
                              : 'bg-red-950 text-red-300 border-red-800'
                          )}
                        >
                          {src.health_status}
                        </Badge>
                      </div>
                      <span className="font-mono text-sm font-semibold text-cyan-400">
                        Weight: {src.authority_weight} / 100
                      </span>
                    </div>

                    <h3 className="text-base font-semibold text-slate-100">{src.name}</h3>

                    <div className="mt-3 flex flex-wrap gap-1.5">
                      {src.capabilities.map((cap, idx) => (
                        <span
                          key={idx}
                          className="px-2 py-0.5 rounded text-[11px] font-mono bg-slate-950 text-slate-400 border border-slate-800"
                        >
                          {cap}
                        </span>
                      ))}
                    </div>
                  </div>

                  <div className="border-t border-slate-800/80 pt-3 mt-4 flex items-center justify-between text-xs text-slate-400">
                    <div>
                      Last sync:{' '}
                      {src.last_sync_at ? new Date(src.last_sync_at).toLocaleString() : 'Never'}
                    </div>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => handleDeleteSource(src.id)}
                      className="text-red-400 hover:text-red-300 hover:bg-red-950/40 p-1"
                    >
                      <Trash2 className="w-4 h-4" />
                    </Button>
                  </div>
                </Card>
              ))
            )}
          </div>
        </div>
      )}

      {/* TAB 4: CONFLICT WORKSPACE */}
      {activeTab === 'conflicts' && (
        <div className="flex flex-col gap-4">
          <div className="flex items-center justify-between p-3.5 rounded-xl bg-slate-900/40 border border-slate-800">
            <span className="text-sm text-slate-300">
              Attribute discrepancy triage across authoritative sources:
            </span>
            <select
              value={filterConflictStatus}
              onChange={(e) => setFilterConflictStatus(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none"
            >
              <option value="ALL">All Statuses</option>
              <option value="PENDING_REVIEW">Pending Review</option>
              <option value="AUTO_RESOLVED">Auto-Resolved</option>
              <option value="MANUALLY_RESOLVED">Manually Resolved</option>
            </select>
          </div>

          <div className="rounded-xl border border-slate-800 overflow-hidden bg-slate-900/30">
            <table className="w-full text-left text-sm text-slate-300">
              <thead className="bg-slate-900/70 border-b border-slate-800 text-xs font-semibold uppercase text-slate-400">
                <tr>
                  <th className="py-3 px-4">Target Entity</th>
                  <th className="py-3 px-4">Field</th>
                  <th className="py-3 px-4">Conflicting Values</th>
                  <th className="py-3 px-4">Current Resolution</th>
                  <th className="py-3 px-4">Status &amp; Justification</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-normal">
                {loadingConflicts ? (
                  <tr>
                    <td colSpan={6} className="py-12 text-center text-slate-500">
                      <RefreshCw className="w-6 h-6 animate-spin mx-auto mb-2 text-cyan-500" />
                      Loading conflicts...
                    </td>
                  </tr>
                ) : conflicts.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="py-12 text-center text-slate-500">
                      Zero unresolved conflicts. All sources are in deterministic agreement!
                    </td>
                  </tr>
                ) : (
                  conflicts.map((c) => (
                    <tr key={c.id} className="hover:bg-slate-800/40 transition-colors">
                      <td className="py-3 px-4 font-mono font-medium text-slate-100">
                        {c.target_canonical_name}
                      </td>

                      <td className="py-3 px-4 font-mono text-cyan-400 text-xs">
                        {c.field_name}
                      </td>

                      <td className="py-3 px-4">
                        <div className="flex flex-col gap-1 text-xs">
                          {c.conflicting_values.map((v, i) => (
                            <span key={i} className="font-mono text-slate-300">
                              <span className="text-slate-500">{v.source} ({v.authority_weight}):</span> {v.value}
                            </span>
                          ))}
                        </div>
                      </td>

                      <td className="py-3 px-4 font-medium text-emerald-400 font-mono text-xs">
                        {c.resolved_value || 'None'}
                      </td>

                      <td className="py-3 px-4 text-xs text-slate-400 max-w-xs">
                        <Badge
                          className={cn(
                            'text-[10px] mb-1 block w-fit',
                            c.status === 'PENDING_REVIEW'
                              ? 'bg-amber-950 text-amber-300 border-amber-800'
                              : 'bg-emerald-950 text-emerald-300 border-emerald-800'
                          )}
                        >
                          {c.status}
                        </Badge>
                        <p className="line-clamp-2">{c.resolution_reason}</p>
                      </td>

                      <td className="py-3 px-4 text-right">
                        <Button
                          size="sm"
                          onClick={() => {
                            setResolvingConflict(c);
                            setConflictResolvedValue(c.resolved_value || '');
                          }}
                          className="text-xs"
                        >
                          Resolve
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

      {/* 4. MODALS & DRAWERS */}

      {/* ASSET DETAIL MODAL */}
      {selectedAssetId && (
        <Modal
          isOpen={Boolean(selectedAssetId)}
          onClose={() => {
            setSelectedAssetId(null);
            setSelectedAssetDetail(null);
          }}
          size="xl"
        >
          {loadingAssetDetail || !selectedAssetDetail ? (
            <ModalBody className="py-16 text-center text-slate-500">
              <RefreshCw className="w-8 h-8 animate-spin mx-auto mb-3 text-cyan-500" />
              <p className="text-sm">Loading asset details &amp; graph connections...</p>
            </ModalBody>
          ) : (
            <>
              <ModalHeader>
                <ModalTitle className="flex items-center gap-2 flex-wrap">
                  {getAssetTypeIcon(selectedAssetDetail.asset_type)}
                  <span className="font-mono text-base">{selectedAssetDetail.canonical_name}</span>
                  <Badge className={cn('text-xs ml-2', getCriticalityBadgeClass(selectedAssetDetail.criticality))}>
                    {selectedAssetDetail.criticality} Criticality
                  </Badge>
                  <Badge className={cn('text-xs ml-1 font-bold', getPriorityBadgeClass(selectedAssetDetail.effective_priority || selectedAssetDetail.priority_band))}>
                    {selectedAssetDetail.effective_priority || selectedAssetDetail.priority_band || 'P4'} Priority
                  </Badge>
                  {selectedAssetDetail.priority_override && (
                    <Badge className="bg-purple-950/80 text-purple-300 border-purple-800 text-[10px]">
                      OVERRIDE: {selectedAssetDetail.priority_override}
                    </Badge>
                  )}
                </ModalTitle>
              </ModalHeader>
              <ModalBody className="max-h-[70vh] overflow-y-auto">
                <div className="flex border-b border-slate-800 gap-4 mb-4 text-sm font-medium">
                  <button
                    onClick={() => setAssetDetailTab('overview')}
                    className={cn('pb-2 border-b-2', assetDetailTab === 'overview' ? 'border-cyan-500 text-cyan-400' : 'border-transparent text-slate-400')}
                  >
                    Overview
                  </button>
                  <button
                    onClick={() => setAssetDetailTab('priority')}
                    className={cn(
                      'pb-2 border-b-2 flex items-center gap-1.5',
                      assetDetailTab === 'priority' ? 'border-cyan-500 text-cyan-400 font-semibold' : 'border-transparent text-slate-400 hover:text-slate-200'
                    )}
                  >
                    <Flame className="w-3.5 h-3.5 text-amber-400" />
                    Priority &amp; Attention (S64)
                  </button>
                  <button
                    onClick={() => setAssetDetailTab('exposures')}
                    className={cn('pb-2 border-b-2', assetDetailTab === 'exposures' ? 'border-cyan-500 text-cyan-400' : 'border-transparent text-slate-400')}
                  >
                    Exposures ({selectedAssetDetail.exposures.length})
                  </button>
                  <button
                    onClick={() => setAssetDetailTab('services')}
                    className={cn('pb-2 border-b-2', assetDetailTab === 'services' ? 'border-cyan-500 text-cyan-400' : 'border-transparent text-slate-400')}
                  >
                    Services ({selectedAssetDetail.services.length})
                  </button>
                  <button
                    onClick={() => setAssetDetailTab('neighbors')}
                    className={cn('pb-2 border-b-2', assetDetailTab === 'neighbors' ? 'border-cyan-500 text-cyan-400' : 'border-transparent text-slate-400')}
                  >
                    Graph Neighbors ({selectedAssetDetail.graph_neighbors.length})
                  </button>
                  <button
                    onClick={() => setAssetDetailTab('timeline')}
                    className={cn('pb-2 border-b-2', assetDetailTab === 'timeline' ? 'border-cyan-500 text-cyan-400' : 'border-transparent text-slate-400')}
                  >
                    Timeline
                  </button>
                </div>

                {assetDetailTab === 'overview' && (
                  <div className="grid grid-cols-2 gap-4 text-sm">
                    <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                      <div className="text-xs text-slate-400">Owner</div>
                      <div className="text-slate-100 font-medium mt-1">{selectedAssetDetail.owner || 'Unassigned'}</div>
                    </div>
                    <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                      <div className="text-xs text-slate-400">Team / Department</div>
                      <div className="text-slate-100 font-medium mt-1">
                        {selectedAssetDetail.team || 'None'} {selectedAssetDetail.department && `(${selectedAssetDetail.department})`}
                      </div>
                    </div>
                    <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                      <div className="text-xs text-slate-400">Environment</div>
                      <div className="text-slate-100 font-medium mt-1">{selectedAssetDetail.environment}</div>
                    </div>
                    <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                      <div className="text-xs text-slate-400">Management Status</div>
                      <div className="mt-1">
                        {selectedAssetDetail.is_managed ? (
                          <Badge className="bg-emerald-950 text-emerald-300 border-emerald-800 text-xs">Managed</Badge>
                        ) : (
                          <Badge className="bg-amber-950 text-amber-300 border-amber-800 text-xs">Unmanaged</Badge>
                        )}
                      </div>
                    </div>
                  </div>
                )}

                {assetDetailTab === 'priority' && (
                  <div className="flex flex-col gap-5 text-sm">
                    {/* Top Status Cards */}
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                      <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 flex flex-col justify-between">
                        <div className="text-xs text-slate-400 flex items-center justify-between">
                          <span>Effective Priority</span>
                          <Flame className="w-4 h-4 text-amber-400" />
                        </div>
                        <div className="mt-2 flex items-baseline gap-2">
                          <Badge className={cn('text-sm font-mono font-bold px-2 py-0.5', getPriorityBadgeClass(selectedAssetDetail.effective_priority || selectedAssetDetail.priority_band))}>
                            {selectedAssetDetail.effective_priority || selectedAssetDetail.priority_band || 'P4'}
                          </Badge>
                          <span className="text-xs font-mono text-slate-400">
                            Score: {(selectedAssetDetail.priority_score ?? 0).toFixed(1)} / 100
                          </span>
                        </div>
                        <div className="text-[11px] text-slate-500 mt-1">
                          {selectedAssetDetail.priority_override ? 'Driven by manual analyst override' : 'Calculated by operational policy'}
                        </div>
                      </div>

                      <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 flex flex-col justify-between">
                        <div className="text-xs text-slate-400 flex items-center justify-between">
                          <span>Baseline Engine Calculation</span>
                          <Sliders className="w-4 h-4 text-cyan-400" />
                        </div>
                        <div className="mt-2 flex items-baseline gap-2">
                          <span className="font-mono font-bold text-slate-200">
                            {selectedAssetDetail.priority_band || 'P4'}
                          </span>
                          <span className="text-xs font-mono text-slate-400">
                            ({(selectedAssetDetail.priority_score ?? 0).toFixed(1)} pts)
                          </span>
                        </div>
                        <div className="text-[11px] text-slate-500 mt-1 truncate">
                          Policy: {priorityExplanation?.policy_id || 'production-prioritization-v1'} (v{priorityExplanation?.policy_version || 1})
                        </div>
                      </div>

                      <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 flex flex-col justify-between">
                        <div className="text-xs text-slate-400 flex items-center justify-between">
                          <span>Telemetry Quality &amp; Freshness</span>
                          <Info className="w-4 h-4 text-indigo-400" />
                        </div>
                        <div className="mt-2 flex items-center gap-2">
                          {priorityExplanation?.data_quality?.status === 'GOOD' || selectedAssetDetail.priority_data_quality === 'GOOD' ? (
                            <Badge className="bg-emerald-950 text-emerald-300 border-emerald-800 text-xs">
                              GOOD (Fresh)
                            </Badge>
                          ) : priorityExplanation?.data_quality?.status === 'DEGRADED' || selectedAssetDetail.priority_data_quality === 'DEGRADED' ? (
                            <Badge className="bg-amber-950 text-amber-300 border-amber-800 text-xs">
                              DEGRADED
                            </Badge>
                          ) : (
                            <Badge className="bg-orange-950 text-orange-300 border-orange-800 text-xs">
                              {priorityExplanation?.data_quality?.status || selectedAssetDetail.priority_data_quality || 'STALE'}
                            </Badge>
                          )}
                        </div>
                        <div className="text-[11px] text-slate-500 mt-1">
                          Evaluated: {selectedAssetDetail.priority_calculated_at ? new Date(selectedAssetDetail.priority_calculated_at).toLocaleTimeString() : 'Recent'}
                        </div>
                      </div>
                    </div>

                    {/* Manual Override Banner if Active */}
                    {selectedAssetDetail.priority_override && (
                      <div className="p-3 rounded-xl bg-purple-950/40 border border-purple-800/60 flex items-start justify-between gap-3">
                        <div>
                          <div className="flex items-center gap-2 text-xs font-bold text-purple-300">
                            <Badge className="bg-purple-900 text-purple-200 border-purple-700 text-[10px]">
                              ACTIVE OVERRIDE: {selectedAssetDetail.priority_override}
                            </Badge>
                            <span>Overridden by {selectedAssetDetail.priority_override_by || 'analyst'}</span>
                          </div>
                          <p className="text-xs text-purple-200/90 mt-1">
                            <strong>Reason:</strong> {selectedAssetDetail.priority_override_reason}
                          </p>
                          {selectedAssetDetail.priority_override_expires_at && (
                            <div className="text-[11px] text-purple-300/70 font-mono mt-0.5">
                              Expires: {new Date(selectedAssetDetail.priority_override_expires_at).toLocaleString()}
                            </div>
                          )}
                        </div>
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={handleRemoveOverride}
                          className="border-purple-700 text-purple-300 hover:bg-purple-900/50 text-xs shrink-0"
                        >
                          Revert to Calculated
                        </Button>
                      </div>
                    )}

                    {/* Analyst Operational Action Bar */}
                    <div className="flex items-center justify-between p-3 rounded-xl bg-slate-900/60 border border-slate-800">
                      <span className="text-xs text-slate-300 font-medium">
                        Analyst Prioritization Controls:
                      </span>
                      <div className="flex items-center gap-2">
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => setIsOverrideModalOpen(true)}
                          className="text-xs border-slate-700 hover:border-cyan-500 text-slate-300"
                        >
                          <Sliders className="w-3.5 h-3.5 mr-1 text-cyan-400" />
                          Set Manual Override
                        </Button>
                        <Button
                          size="sm"
                          onClick={handleRecalculatePriority}
                          disabled={isRecalculatingPriority}
                          className="text-xs bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold"
                        >
                          <RefreshCw className={cn('w-3.5 h-3.5 mr-1', isRecalculatingPriority && 'animate-spin')} />
                          Recalculate Priority Now
                        </Button>
                      </div>
                    </div>

                    {/* "Why Prioritized?" Explainable Breakdown */}
                    <div className="space-y-3">
                      <div className="flex items-center justify-between">
                        <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                          <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
                          <span>Why is this asset prioritized at {selectedAssetDetail.effective_priority || selectedAssetDetail.priority_band || 'P4'}?</span>
                        </h4>
                        <span className="text-[11px] text-slate-500">
                          Non-arbitrary deterministic attribution
                        </span>
                      </div>

                      {/* Contributors Breakdown Cards */}
                      {loadingPriority ? (
                        <div className="p-6 text-center text-slate-500">
                          <RefreshCw className="w-5 h-5 animate-spin mx-auto mb-2 text-cyan-500" />
                          Loading priority contributors...
                        </div>
                      ) : !priorityExplanation || priorityExplanation.contributors.length === 0 ? (
                        <div className="p-4 rounded bg-slate-900/30 border border-slate-800 text-xs text-slate-500 text-center">
                          Prioritization engine details pending first evaluation pass.
                        </div>
                      ) : (
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
                          {priorityExplanation.contributors.map((c, i) => (
                            <div key={i} className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1.5">
                              <div className="flex items-center justify-between">
                                <span className="font-semibold text-slate-200 text-xs">
                                  {c.label || c.factor.replace(/_/g, ' ')}
                                </span>
                                <Badge className="bg-slate-800 text-slate-300 text-[10px] font-mono">
                                  +{c.weighted_points.toFixed(1)} pts ({Math.round(c.weight * 100)}%)
                                </Badge>
                              </div>
                              <p className="text-xs text-slate-400">
                                {c.description}
                              </p>
                              <div className="flex items-center justify-between pt-1 border-t border-slate-900 text-[10px] text-slate-500 font-mono">
                                <span>Source: {c.source}</span>
                                <span className="text-slate-400">Value: {String(c.value)}</span>
                              </div>
                            </div>
                          ))}
                        </div>
                      )}

                      {/* Uncertainty & Freshness Penalties Note */}
                      {priorityExplanation?.data_quality && ((priorityExplanation.data_quality.issues && priorityExplanation.data_quality.issues.length > 0) || (priorityExplanation.data_quality.stale_sources && priorityExplanation.data_quality.stale_sources.length > 0)) && (
                        <div className="p-3 rounded-lg bg-amber-950/30 border border-amber-800/50 space-y-1">
                          <div className="text-xs font-semibold text-amber-300 flex items-center gap-1.5">
                            <AlertTriangle className="w-3.5 h-3.5" />
                            <span>Uncertainty &amp; Stale Data Safeguards (Missing Telemetry ≠ Safe)</span>
                          </div>
                          {priorityExplanation.data_quality.issues.map((pen, i) => (
                            <p key={i} className="text-xs text-amber-200/80">
                              • {pen}
                            </p>
                          ))}
                          {priorityExplanation.data_quality.stale_sources.length > 0 && (
                            <p className="text-xs text-amber-200/80">
                              • Stale telemetry sources detected: {priorityExplanation.data_quality.stale_sources.join(', ')}
                            </p>
                          )}
                        </div>
                      )}
                    </div>

                    {/* Historical Timeline */}
                    <div className="space-y-3 pt-2">
                      <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                        <History className="w-3.5 h-3.5 text-cyan-400" />
                        <span>Priority Transition History</span>
                      </h4>
                      {priorityHistory.length === 0 ? (
                        <div className="p-4 rounded bg-slate-950 border border-slate-800 text-xs text-slate-500 text-center">
                          No historical priority transitions recorded yet.
                        </div>
                      ) : (
                        <div className="space-y-2">
                          {priorityHistory.map((snap) => (
                            <div key={snap.id} className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 flex items-start justify-between gap-3 text-xs">
                              <div className="space-y-0.5">
                                <div className="flex items-center gap-2">
                                  <Badge className={cn('text-[10px] font-mono font-bold', getPriorityBadgeClass(snap.priority_band))}>
                                    {snap.priority_band}
                                  </Badge>
                                  <span className="font-semibold text-slate-200">
                                    {snap.transition_type}
                                  </span>
                                  {snap.previous_priority_band && (
                                    <span className="text-[11px] text-slate-500 font-mono">
                                      ({snap.previous_priority_band} → {snap.priority_band})
                                    </span>
                                  )}
                                </div>
                                <p className="text-slate-400 text-xs">
                                  {snap.transition_reason || 'Evaluated against policy configuration'}
                                </p>
                              </div>
                              <div className="text-[10px] font-mono text-slate-500 shrink-0 text-right">
                                <div>{new Date(snap.calculated_at).toLocaleTimeString()}</div>
                                <div>{new Date(snap.calculated_at).toLocaleDateString()}</div>
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {assetDetailTab === 'exposures' && (
                  <div className="flex flex-col gap-2">
                    {selectedAssetDetail.exposures.length === 0 ? (
                      <div className="text-sm text-slate-500 py-6 text-center">No active exposures detected.</div>
                    ) : (
                      selectedAssetDetail.exposures.map((exp) => (
                        <div key={exp.id} className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                          <div className="font-semibold text-slate-200 text-xs">{exp.exposure_type}</div>
                          <p className="text-xs text-slate-400 mt-1">{exp.remediation_guidance}</p>
                        </div>
                      ))
                    )}
                  </div>
                )}

                {assetDetailTab === 'services' && (
                  <div className="flex flex-col gap-2">
                    {selectedAssetDetail.services.length === 0 ? (
                      <div className="text-sm text-slate-500 py-6 text-center">No services observed.</div>
                    ) : (
                      selectedAssetDetail.services.map((svc) => (
                        <div key={svc.id} className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex justify-between">
                          <div>
                            <div className="font-mono text-xs text-slate-200">{svc.service_name} (Port {svc.port}/{svc.protocol})</div>
                            {svc.banner && <div className="text-[11px] text-slate-400 mt-0.5">{svc.banner}</div>}
                          </div>
                          {svc.is_public && <Badge className="bg-orange-950 text-orange-300 border-orange-800 text-[10px]">PUBLIC</Badge>}
                        </div>
                      ))
                    )}
                  </div>
                )}

                {assetDetailTab === 'neighbors' && (
                  <div className="flex flex-col gap-2">
                    {selectedAssetDetail.graph_neighbors.length === 0 ? (
                      <div className="text-sm text-slate-500 py-6 text-center">No Knowledge Graph neighbors.</div>
                    ) : (
                      selectedAssetDetail.graph_neighbors.map((r, i) => (
                        <div key={i} className="p-2.5 rounded bg-slate-950 border border-slate-800 flex items-center justify-between">
                          <span className="font-mono text-xs text-slate-200">{r.name}</span>
                          <Badge className="bg-slate-800 text-slate-400 text-[10px]">{r.type}</Badge>
                        </div>
                      ))
                    )}
                  </div>
                )}

                {assetDetailTab === 'timeline' && (
                  <div className="flex flex-col gap-3">
                    {selectedAssetDetail.timeline.map((evt, i) => (
                      <div key={i} className="p-3 rounded bg-slate-950 border border-slate-800 flex items-start gap-2.5">
                        <Clock className="w-4 h-4 text-cyan-400 mt-0.5 shrink-0" />
                        <div>
                          <div className="text-xs font-semibold text-slate-200">{evt.title}</div>
                          <p className="text-xs text-slate-400 mt-0.5">{evt.description}</p>
                          <div className="text-[10px] text-slate-500 font-mono mt-1">{evt.timestamp}</div>
                        </div>
                      </div>
                    ))}
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

      {/* IDENTITY DETAIL MODAL */}
      {selectedIdentityId && (
        <Modal
          isOpen={Boolean(selectedIdentityId)}
          onClose={() => {
            setSelectedIdentityId(null);
            setSelectedIdentityDetail(null);
          }}
          size="lg"
        >
          {loadingIdentityDetail || !selectedIdentityDetail ? (
            <ModalBody className="py-16 text-center text-slate-500">
              <RefreshCw className="w-8 h-8 animate-spin mx-auto mb-3 text-cyan-500" />
              <p className="text-sm">Loading identity profile...</p>
            </ModalBody>
          ) : (
            <>
              <ModalHeader>
                <ModalTitle className="flex items-center gap-2">
                  {getIdentityTypeIcon(selectedIdentityDetail.identity_type)}
                  <span className="font-mono text-base">{selectedIdentityDetail.canonical_identifier}</span>
                </ModalTitle>
              </ModalHeader>
              <ModalBody className="flex flex-col gap-4">
                <div className="grid grid-cols-2 gap-3 text-sm">
                  <div className="p-3 rounded bg-slate-950 border border-slate-800">
                    <div className="text-xs text-slate-400">Display Name</div>
                    <div className="text-slate-100 font-medium mt-1">{selectedIdentityDetail.display_name}</div>
                  </div>
                  <div className="p-3 rounded bg-slate-950 border border-slate-800">
                    <div className="text-xs text-slate-400">Privilege Level</div>
                    <div className="mt-1">
                      {selectedIdentityDetail.is_privileged ? (
                        <Badge className="bg-red-950 text-red-300 border-red-800 text-xs">Privileged Admin</Badge>
                      ) : (
                        <span className="text-slate-400 text-xs">Standard Account</span>
                      )}
                    </div>
                  </div>
                  <div className="p-3 rounded bg-slate-950 border border-slate-800">
                    <div className="text-xs text-slate-400">Department / Team</div>
                    <div className="text-slate-100 text-xs mt-1">
                      {selectedIdentityDetail.department || 'None'} {selectedIdentityDetail.team && `(${selectedIdentityDetail.team})`}
                    </div>
                  </div>
                  <div className="p-3 rounded bg-slate-950 border border-slate-800">
                    <div className="text-xs text-slate-400">Activity &amp; Dormancy</div>
                    <div className="text-xs mt-1">
                      {selectedIdentityDetail.is_dormant ? (
                        <span className="text-amber-400">Dormant (&gt; 90d inactive)</span>
                      ) : (
                        <span className="text-emerald-400">Active</span>
                      )}
                    </div>
                  </div>
                </div>

                <div>
                  <h4 className="text-xs font-semibold text-slate-300 uppercase mb-2">
                    Associated Assets ({selectedIdentityDetail.associated_assets.length})
                  </h4>
                  {selectedIdentityDetail.associated_assets.length === 0 ? (
                    <div className="text-xs text-slate-500 italic">No assigned endpoints or servers.</div>
                  ) : (
                    <div className="flex flex-col gap-1.5">
                      {selectedIdentityDetail.associated_assets.map((a) => (
                        <div key={a.id} className="p-2.5 rounded bg-slate-950 border border-slate-800 flex justify-between items-center text-xs">
                          <span className="font-mono text-slate-200">{a.canonical_name}</span>
                          <Badge className="bg-slate-800 text-slate-400 text-[10px]">{a.asset_type}</Badge>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </ModalBody>
              <ModalFooter>
                <Button
                  variant="outline"
                  onClick={() => {
                    setSelectedIdentityId(null);
                    setSelectedIdentityDetail(null);
                  }}
                >
                  Close
                </Button>
              </ModalFooter>
            </>
          )}
        </Modal>
      )}

      {/* ASSIGN OWNER MODAL */}
      <Modal isOpen={Boolean(assigningAsset)} onClose={() => setAssigningAsset(null)}>
        <form onSubmit={handleAssignOwnerSubmit}>
          <ModalHeader>
            <ModalTitle>Assign Asset Ownership</ModalTitle>
          </ModalHeader>
          <ModalBody className="flex flex-col gap-4">
            <div className="text-xs text-slate-400">
              Target Asset: <strong className="text-slate-100 font-mono">{assigningAsset?.canonical_name}</strong>
            </div>

            <div>
              <label className="text-xs font-medium text-slate-300 block mb-1.5">Owner Name or Email *</label>
              <input
                type="text"
                required
                placeholder="e.g. platform-leads@corp.com"
                value={ownerInput}
                onChange={(e) => setOwnerInput(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-sm text-slate-100 focus:outline-none"
              />
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-xs font-medium text-slate-300 block mb-1.5">Managing Team</label>
                <input
                  type="text"
                  placeholder="e.g. Infrastructure"
                  value={teamInput}
                  onChange={(e) => setTeamInput(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-sm text-slate-100 focus:outline-none"
                />
              </div>

              <div>
                <label className="text-xs font-medium text-slate-300 block mb-1.5">Department</label>
                <input
                  type="text"
                  placeholder="e.g. Engineering"
                  value={departmentInput}
                  onChange={(e) => setDepartmentInput(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-sm text-slate-100 focus:outline-none"
                />
              </div>
            </div>

            <div>
              <label className="text-xs font-medium text-slate-300 block mb-1.5">Audit Justification</label>
              <textarea
                placeholder="Reason for assignment / reorganization..."
                value={assignReasonInput}
                onChange={(e) => setAssignReasonInput(e.target.value)}
                rows={2}
                className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-sm text-slate-100 focus:outline-none"
              />
            </div>
          </ModalBody>
          <ModalFooter>
            <Button variant="outline" type="button" onClick={() => setAssigningAsset(null)}>Cancel</Button>
            <Button type="submit" className="bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold">Save Ownership</Button>
          </ModalFooter>
        </form>
      </Modal>

      {/* RESOLVE CONFLICT MODAL */}
      <Modal isOpen={Boolean(resolvingConflict)} onClose={() => setResolvingConflict(null)}>
        <form onSubmit={handleResolveConflictSubmit}>
          <ModalHeader>
            <ModalTitle>Resolve Attribute Conflict</ModalTitle>
          </ModalHeader>
          <ModalBody className="flex flex-col gap-4">
            <div className="text-xs text-slate-400">
              Entity: <strong className="text-slate-100 font-mono">{resolvingConflict?.target_canonical_name}</strong> &bull; Field: <strong className="text-cyan-400 font-mono">{resolvingConflict?.field_name}</strong>
            </div>

            <div>
              <label className="text-xs font-medium text-slate-300 block mb-1.5">Choose Conflicting Value</label>
              <div className="flex flex-col gap-2">
                {resolvingConflict?.conflicting_values.map((v, i) => (
                  <button
                    key={i}
                    type="button"
                    onClick={() => setConflictResolvedValue(v.value)}
                    className={cn(
                      'p-2.5 rounded text-left border text-xs flex justify-between items-center transition-colors',
                      conflictResolvedValue === v.value
                        ? 'bg-cyan-950/60 border-cyan-500 text-cyan-200'
                        : 'bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700'
                    )}
                  >
                    <span>{v.value}</span>
                    <span className="text-[11px] font-mono text-slate-500">{v.source} (Weight {v.authority_weight})</span>
                  </button>
                ))}
              </div>
            </div>

            <div>
              <label className="text-xs font-medium text-slate-300 block mb-1.5">Or Enter Custom Resolution Value</label>
              <input
                type="text"
                required
                value={conflictResolvedValue}
                onChange={(e) => setConflictResolvedValue(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-sm text-slate-100 focus:outline-none font-mono"
              />
            </div>

            <div>
              <label className="text-xs font-medium text-slate-300 block mb-1.5">Resolution Justification *</label>
              <textarea
                required
                placeholder="Explain why this resolution is authoritative..."
                value={conflictReasonInput}
                onChange={(e) => setConflictReasonInput(e.target.value)}
                rows={2}
                className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-sm text-slate-100 focus:outline-none"
              />
            </div>
          </ModalBody>
          <ModalFooter>
            <Button variant="outline" type="button" onClick={() => setResolvingConflict(null)}>Cancel</Button>
            <Button type="submit" className="bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold">Confirm Resolution</Button>
          </ModalFooter>
        </form>
      </Modal>

      {/* ADD SOURCE MODAL */}
      <Modal isOpen={isAddSourceOpen} onClose={() => setIsAddSourceOpen(false)}>
        <form onSubmit={handleCreateSourceSubmit}>
          <ModalHeader>
            <ModalTitle>Add Inventory Source Connector</ModalTitle>
          </ModalHeader>
          <ModalBody className="flex flex-col gap-4">
            <div>
              <label className="text-xs font-medium text-slate-300 block mb-1.5">Source Type</label>
              <select
                value={newSourceType}
                onChange={(e) => setNewSourceType(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-sm text-slate-100 focus:outline-none"
              >
                <option value="CMDB">CMDB (ServiceNow / Jira)</option>
                <option value="DIRECTORY">Directory (Okta / Azure AD)</option>
                <option value="ENDPOINT_AGENT">Endpoint Telemetry Fleet</option>
                <option value="CLOUD_PROVIDER">Cloud Infrastructure IAM</option>
                <option value="APPLICATION_REGISTRY">Application Registry</option>
              </select>
            </div>

            <div>
              <label className="text-xs font-medium text-slate-300 block mb-1.5">Source Display Name</label>
              <input
                type="text"
                required
                placeholder="e.g. Corporate Okta IdP"
                value={newSourceName}
                onChange={(e) => setNewSourceName(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-sm text-slate-100 focus:outline-none"
              />
            </div>

            <div>
              <label className="text-xs font-medium text-slate-300 block mb-1.5">
                Authority Weight (1 - 100): <span className="text-cyan-400 font-mono">{newSourceWeight}</span>
              </label>
              <input
                type="range"
                min="10"
                max="100"
                step="5"
                value={newSourceWeight}
                onChange={(e) => setNewSourceWeight(Number(e.target.value))}
                className="w-full accent-cyan-500"
              />
              <div className="flex justify-between text-[11px] text-slate-500 mt-1">
                <span>Low Precedence</span>
                <span>Authoritative</span>
              </div>
            </div>
          </ModalBody>
          <ModalFooter>
            <Button variant="outline" type="button" onClick={() => setIsAddSourceOpen(false)}>Cancel</Button>
            <Button type="submit" className="bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold">Add Source</Button>
          </ModalFooter>
        </form>
      </Modal>

      {/* SECTION 64 MANUAL PRIORITY OVERRIDE MODAL */}
      <Modal isOpen={isOverrideModalOpen} onClose={() => setIsOverrideModalOpen(false)}>
        <form onSubmit={handleApplyOverrideSubmit}>
          <ModalHeader>
            <ModalTitle className="flex items-center gap-2">
              <Sliders className="w-5 h-5 text-cyan-400" />
              <span>Apply Manual Priority Override</span>
            </ModalTitle>
          </ModalHeader>
          <ModalBody className="flex flex-col gap-4 text-sm">
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-300">
              <span className="text-slate-400 block mb-0.5">Target Asset:</span>
              <span className="font-mono font-bold text-slate-100">{selectedAssetDetail?.canonical_name}</span>
            </div>

            <div>
              <label className="text-xs font-medium text-slate-300 block mb-1.5">
                Override Priority Level
              </label>
              <div className="grid grid-cols-4 gap-2">
                {(['P1', 'P2', 'P3', 'P4'] as PriorityBand[]).map((p) => (
                  <button
                    key={p}
                    type="button"
                    onClick={() => setOverrideBand(p)}
                    className={cn(
                      'py-2 px-3 rounded-lg border font-mono font-bold text-xs transition-all text-center',
                      overrideBand === p
                        ? 'border-cyan-500 bg-cyan-950 text-cyan-300 ring-1 ring-cyan-500'
                        : 'border-slate-800 bg-slate-950 text-slate-400 hover:border-slate-700'
                    )}
                  >
                    {p}
                  </button>
                ))}
              </div>
            </div>

            <div>
              <label className="text-xs font-medium text-slate-300 block mb-1.5">
                Justification &amp; Operational Rationale <span className="text-red-400">*</span>
              </label>
              <textarea
                required
                rows={3}
                placeholder="Explain why this asset requires urgent manual escalation or de-escalation (e.g., Active incident INC-8492, payment gateway downtime impact)..."
                value={overrideReason}
                onChange={(e) => setOverrideReason(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div>
              <label className="text-xs font-medium text-slate-300 block mb-1.5">
                Override Expiration Window
              </label>
              <select
                value={overrideDurationHours === undefined ? 'PERMANENT' : String(overrideDurationHours)}
                onChange={(e) => {
                  const val = e.target.value;
                  setOverrideDurationHours(val === 'PERMANENT' ? undefined : Number(val));
                }}
                className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-xs text-slate-100 focus:outline-none"
              >
                <option value="1">1 Hour (Immediate investigation)</option>
                <option value="4">4 Hours (Shift window)</option>
                <option value="24">24 Hours (Next business day review)</option>
                <option value="72">72 Hours (Weekend maintenance window)</option>
                <option value="168">7 Days (Weekly review)</option>
                <option value="PERMANENT">Indefinite / Until manually removed</option>
              </select>
            </div>
          </ModalBody>
          <ModalFooter>
            <Button
              variant="outline"
              type="button"
              onClick={() => setIsOverrideModalOpen(false)}
            >
              Cancel
            </Button>
            <Button
              type="submit"
              disabled={isSubmittingOverride || !overrideReason.trim()}
              className="bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold"
            >
              {isSubmittingOverride ? (
                <RefreshCw className="w-4 h-4 animate-spin mr-1" />
              ) : null}
              Confirm Override
            </Button>
          </ModalFooter>
        </form>
      </Modal>
    </div>
  );
};
