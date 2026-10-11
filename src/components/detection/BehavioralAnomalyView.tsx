import React, { useState, useEffect } from 'react';
import {
  AlertTriangle,
  Clock,
  Layers,
  RefreshCw,
  Search,
  ShieldAlert,
  ShieldCheck,
  TrendingUp,
  User,
  Monitor,
  Server,
  Globe,
  Sliders,
  XCircle,
  Info,
  RotateCcw,
} from 'lucide-react';
import type {
  BehaviorProfile,
  BehaviorProfileDetail,
  BehavioralAnomalyDetail,
  LearningQuarantineItem,
  BehavioralOverviewStats,
  ProfileStatus,
  BaselineQualityStatus,
} from '../../types/detectionRules';
import { detectionRuleService } from '../../services/detectionRuleService';

export const BehavioralAnomalyView: React.FC = () => {
  const [activeSubTab, setActiveSubTab] = useState<'profiles' | 'anomalies' | 'quarantine' | 'lifecycle'>('profiles');

  // Overview stats
  const [stats, setStats] = useState<BehavioralOverviewStats | null>(null);
  const [loadingStats, setLoadingStats] = useState(false);

  // Profiles tab state
  const [profiles, setProfiles] = useState<BehaviorProfile[]>([]);
  const [totalProfiles, setTotalProfiles] = useState(0);
  const [loadingProfiles, setLoadingProfiles] = useState(false);
  const [profileSearch, setProfileSearch] = useState('');
  const [profileStatusFilter, setProfileStatusFilter] = useState<string>('ALL');
  const [profileQualityFilter, setProfileQualityFilter] = useState<string>('ALL');
  const [profileTypeFilter, setProfileTypeFilter] = useState<string>('ALL');
  const [selectedProfileId, setSelectedProfileId] = useState<string | null>(null);
  const [profileDetail, setProfileDetail] = useState<BehaviorProfileDetail | null>(null);
  const [loadingDetail, setLoadingDetail] = useState(false);

  // Anomalies tab state
  const [anomalies, setAnomalies] = useState<BehavioralAnomalyDetail[]>([]);
  const [totalAnomalies, setTotalAnomalies] = useState(0);
  const [loadingAnomalies, setLoadingAnomalies] = useState(false);
  const [anomalySeverityFilter, setAnomalySeverityFilter] = useState<string>('ALL');
  const [anomalyTypeFilter, setAnomalyTypeFilter] = useState<string>('ALL');

  // Quarantine tab state
  const [quarantines, setQuarantines] = useState<LearningQuarantineItem[]>([]);
  const [totalQuarantines, setTotalQuarantines] = useState(0);
  const [loadingQuarantines, setLoadingQuarantines] = useState(false);
  const [quarantineDispFilter, setQuarantineDispFilter] = useState<string>('ALL');
  const [reviewModalItem, setReviewModalItem] = useState<LearningQuarantineItem | null>(null);
  const [reviewNotes, setReviewNotes] = useState('');
  const [submittingReview, setSubmittingReview] = useState(false);

  // Lifecycle tab state
  const [refreshEntityId, setRefreshEntityId] = useState('');
  const [refreshEntityType, setRefreshEntityType] = useState('ALL');
  const [refreshingBaselines, setRefreshingBaselines] = useState(false);
  const [rollbackBaselineId, setRollbackBaselineId] = useState('');
  const [rollbackReason, setRollbackReason] = useState('');
  const [rollingBack, setRollingBack] = useState(false);

  // Feedback toast
  const [toastMessage, setToastMessage] = useState<string | null>(null);
  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 4000);
  };

  // --------------------------------------------------------------------------
  // Data Loaders
  // --------------------------------------------------------------------------
  const loadOverviewStats = async () => {
    setLoadingStats(true);
    try {
      const data = await detectionRuleService.getBehavioralOverview();
      setStats(data);
    } catch (err: any) {
      console.error('Failed to load behavioral overview stats:', err);
    } finally {
      setLoadingStats(false);
    }
  };

  const loadProfiles = async () => {
    setLoadingProfiles(true);
    try {
      const res = await detectionRuleService.listBehaviorProfiles({
        status: profileStatusFilter,
        quality: profileQualityFilter,
        entity_type: profileTypeFilter,
        search: profileSearch,
        limit: 50,
      });
      setProfiles(res.items || []);
      setTotalProfiles(res.total || 0);
    } catch (err: any) {
      console.error('Failed to load profiles:', err);
    } finally {
      setLoadingProfiles(false);
    }
  };

  const loadAnomalies = async () => {
    setLoadingAnomalies(true);
    try {
      const res = await detectionRuleService.listBehavioralDeviations({
        entity_type: anomalyTypeFilter,
        severity: anomalySeverityFilter,
        limit: 50,
      });
      setAnomalies(res.items || []);
      setTotalAnomalies(res.total || 0);
    } catch (err: any) {
      console.error('Failed to load deviations:', err);
    } finally {
      setLoadingAnomalies(false);
    }
  };

  const loadQuarantines = async () => {
    setLoadingQuarantines(true);
    try {
      const res = await detectionRuleService.listLearningQuarantine({
        disposition: quarantineDispFilter,
        limit: 50,
      });
      setQuarantines(res.items || []);
      setTotalQuarantines(res.total || 0);
    } catch (err: any) {
      console.error('Failed to load quarantine items:', err);
    } finally {
      setLoadingQuarantines(false);
    }
  };

  const loadProfileDetail = async (id: string) => {
    setSelectedProfileId(id);
    setLoadingDetail(true);
    try {
      const det = await detectionRuleService.getBehaviorProfileDetail(id);
      setProfileDetail(det);
    } catch (err: any) {
      showToast(err.message || 'Failed to load profile detail');
      setSelectedProfileId(null);
    } finally {
      setLoadingDetail(false);
    }
  };

  useEffect(() => {
    loadOverviewStats();
  }, []);

  useEffect(() => {
    if (activeSubTab === 'profiles') loadProfiles();
    else if (activeSubTab === 'anomalies') loadAnomalies();
    else if (activeSubTab === 'quarantine') loadQuarantines();
  }, [
    activeSubTab,
    profileStatusFilter,
    profileQualityFilter,
    profileTypeFilter,
    profileSearch,
    anomalySeverityFilter,
    anomalyTypeFilter,
    quarantineDispFilter,
  ]);

  // --------------------------------------------------------------------------
  // Quarantine Review Actions
  // --------------------------------------------------------------------------
  const handleReviewQuarantine = async (disposition: 'APPROVED' | 'REJECTED') => {
    if (!reviewModalItem) return;
    setSubmittingReview(true);
    try {
      await detectionRuleService.reviewQuarantineItem(reviewModalItem.id, disposition, reviewNotes);
      showToast(`Quarantine observation marked ${disposition}`);
      setReviewModalItem(null);
      setReviewNotes('');
      loadQuarantines();
      loadOverviewStats();
    } catch (err: any) {
      showToast(err.message || 'Quarantine review failed');
    } finally {
      setSubmittingReview(false);
    }
  };

  // --------------------------------------------------------------------------
  // Lifecycle Management Actions
  // --------------------------------------------------------------------------
  const handleRefreshBaselines = async () => {
    setRefreshingBaselines(true);
    try {
      const res = await detectionRuleService.refreshBaselines({
        entity_id: refreshEntityId.trim() || undefined,
        entity_type: refreshEntityType !== 'ALL' ? refreshEntityType : undefined,
      });
      showToast(`Recalculated ${res.result?.refreshed_baselines || 0} baselines successfully.`);
      loadOverviewStats();
      if (activeSubTab === 'profiles') loadProfiles();
    } catch (err: any) {
      showToast(err.message || 'Baseline refresh failed');
    } finally {
      setRefreshingBaselines(false);
    }
  };

  const handleRollbackBaseline = async () => {
    if (!rollbackBaselineId.trim() || !rollbackReason.trim()) {
      showToast('Baseline ID and justification reason are required for rollback.');
      return;
    }
    setRollingBack(true);
    try {
      const res = await detectionRuleService.rollbackBaseline(rollbackBaselineId.trim(), rollbackReason.trim());
      showToast(`Baseline ${res.baseline_id} rolled back to version ${res.new_version}.`);
      setRollbackBaselineId('');
      setRollbackReason('');
      loadOverviewStats();
    } catch (err: any) {
      showToast(err.message || 'Baseline rollback failed');
    } finally {
      setRollingBack(false);
    }
  };

  // --------------------------------------------------------------------------
  // Badges & Color Helpers
  // --------------------------------------------------------------------------
  const getStatusBadge = (status: ProfileStatus) => {
    switch (status) {
      case 'ACTIVE':
        return <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">Active</span>;
      case 'LEARNING':
        return <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-sky-500/10 text-sky-400 border border-sky-500/30">Learning</span>;
      case 'INSUFFICIENT_DATA':
        return <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/30">Cold Start</span>;
      case 'STALE':
        return <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-slate-500/10 text-slate-400 border border-slate-500/30">Stale</span>;
      case 'DEGRADED':
        return <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/30">Degraded</span>;
      default:
        return <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-slate-800 text-slate-300">{status}</span>;
    }
  };

  const getQualityBadge = (q: BaselineQualityStatus | string) => {
    switch (q) {
      case 'STABLE':
        return <span className="text-xs font-medium text-emerald-400">Stable</span>;
      case 'DEVELOPING':
        return <span className="text-xs font-medium text-sky-400">Developing</span>;
      case 'INSUFFICIENT_HISTORY':
        return <span className="text-xs font-medium text-amber-400">Insufficient History</span>;
      case 'STALE':
        return <span className="text-xs font-medium text-slate-400">Stale</span>;
      case 'DEGRADED':
        return <span className="text-xs font-medium text-rose-400">Degraded</span>;
      default:
        return <span className="text-xs font-medium text-slate-300">{q}</span>;
    }
  };

  const getSeverityBadge = (sev: string) => {
    switch (sev.toUpperCase()) {
      case 'HIGH':
        return <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-bold bg-rose-500/15 text-rose-400 border border-rose-500/30">HIGH</span>;
      case 'MEDIUM':
        return <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-bold bg-amber-500/15 text-amber-400 border border-amber-500/30">MEDIUM</span>;
      default:
        return <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-slate-700 text-slate-300">LOW</span>;
    }
  };

  const getEntityIcon = (type: string) => {
    switch (type.toUpperCase()) {
      case 'USER':
      case 'ACCOUNT':
        return <User className="w-4 h-4 text-sky-400" />;
      case 'DEVICE':
      case 'ENDPOINT':
        return <Monitor className="w-4 h-4 text-emerald-400" />;
      case 'API_CLIENT':
      case 'SERVICE':
        return <Server className="w-4 h-4 text-purple-400" />;
      case 'IP':
      case 'DOMAIN':
        return <Globe className="w-4 h-4 text-cyan-400" />;
      default:
        return <Layers className="w-4 h-4 text-slate-400" />;
    }
  };

  return (
    <div className="space-y-6">
      {/* Toast Notification */}
      {toastMessage && (
        <div className="fixed bottom-6 right-6 z-50 px-4 py-3 rounded-lg shadow-xl bg-slate-800 border border-slate-700 text-slate-100 flex items-center space-x-3 text-sm animate-fade-in">
          <Info className="w-5 h-5 text-sky-400 flex-shrink-0" />
          <span>{toastMessage}</span>
        </div>
      )}

      {/* Header & Sub-Tabs */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <div className="flex items-center space-x-3">
            <div className="p-2.5 rounded-xl bg-gradient-to-br from-indigo-500/20 to-sky-500/20 border border-indigo-500/30">
              <TrendingUp className="w-6 h-6 text-indigo-400" />
            </div>
            <div>
              <h2 className="text-xl font-bold text-white flex items-center gap-2">
                Section 60: Behavioral Detection & Anomaly Analytics
                <span className="px-2 py-0.5 text-xs font-mono font-medium rounded-full bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
                  Production Engine
                </span>
              </h2>
              <p className="text-sm text-slate-400">
                Multi-dimensional baseline modeling, cold-start lifecycle states, poisoning quarantine, and evidence-backed deviations.
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center space-x-2">
          <button
            onClick={() => {
              loadOverviewStats();
              if (activeSubTab === 'profiles') loadProfiles();
              else if (activeSubTab === 'anomalies') loadAnomalies();
              else if (activeSubTab === 'quarantine') loadQuarantines();
            }}
            className="flex items-center space-x-2 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loadingStats ? 'animate-spin' : ''}`} />
            <span>Refresh All</span>
          </button>
        </div>
      </div>

      {/* Operational Executive KPI Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 backdrop-blur-md">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
            <span>Total Profiles</span>
            <Layers className="w-4 h-4 text-indigo-400" />
          </div>
          <div className="text-2xl font-bold text-white">{stats ? stats.total_profiles : '-'}</div>
          <div className="text-xs text-slate-500 mt-1">Multi-tenant monitored</div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 backdrop-blur-md">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
            <span>Active Baselines</span>
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold text-emerald-400">{stats ? stats.active_profiles : '-'}</div>
          <div className="text-xs text-slate-500 mt-1">Stable statistical bounds</div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 backdrop-blur-md">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
            <span>Learning Profiles</span>
            <Clock className="w-4 h-4 text-sky-400" />
          </div>
          <div className="text-2xl font-bold text-sky-400">{stats ? stats.learning_profiles : '-'}</div>
          <div className="text-xs text-slate-500 mt-1">Acquiring historical bounds</div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 backdrop-blur-md">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
            <span>Cold-Start Guard</span>
            <Sliders className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold text-amber-400">{stats ? stats.insufficient_profiles : '-'}</div>
          <div className="text-xs text-slate-500 mt-1">Zero false alert fatigue</div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 backdrop-blur-md">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
            <span>Anomalies (24h)</span>
            <AlertTriangle className="w-4 h-4 text-rose-400" />
          </div>
          <div className="text-2xl font-bold text-rose-400">{stats ? stats.anomalies_today : '-'}</div>
          <div className="text-xs text-slate-500 mt-1">
            <span className="font-semibold text-rose-400">{stats ? stats.high_severity_anomalies_today : 0}</span> high severity
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 backdrop-blur-md">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
            <span>Learning Quarantine</span>
            <ShieldAlert className="w-4 h-4 text-purple-400" />
          </div>
          <div className="text-2xl font-bold text-purple-400">{stats ? stats.pending_quarantines : '-'}</div>
          <div className="text-xs text-slate-500 mt-1">Poisoning defense pending</div>
        </div>
      </div>

      {/* Sub-Navigation Bar */}
      <div className="flex space-x-1 border-b border-slate-800">
        <button
          onClick={() => setActiveSubTab('profiles')}
          className={`px-4 py-2.5 text-sm font-medium border-b-2 transition-all flex items-center space-x-2 ${
            activeSubTab === 'profiles'
              ? 'border-indigo-500 text-indigo-400 bg-indigo-500/5'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Layers className="w-4 h-4" />
          <span>Entity Profiles ({totalProfiles})</span>
        </button>

        <button
          onClick={() => setActiveSubTab('anomalies')}
          className={`px-4 py-2.5 text-sm font-medium border-b-2 transition-all flex items-center space-x-2 ${
            activeSubTab === 'anomalies'
              ? 'border-indigo-500 text-indigo-400 bg-indigo-500/5'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <AlertTriangle className="w-4 h-4" />
          <span>Anomaly Feed ({totalAnomalies})</span>
        </button>

        <button
          onClick={() => setActiveSubTab('quarantine')}
          className={`px-4 py-2.5 text-sm font-medium border-b-2 transition-all flex items-center space-x-2 ${
            activeSubTab === 'quarantine'
              ? 'border-indigo-500 text-indigo-400 bg-indigo-500/5'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <ShieldAlert className="w-4 h-4" />
          <span>Learning Quarantine ({totalQuarantines})</span>
        </button>

        <button
          onClick={() => setActiveSubTab('lifecycle')}
          className={`px-4 py-2.5 text-sm font-medium border-b-2 transition-all flex items-center space-x-2 ${
            activeSubTab === 'lifecycle'
              ? 'border-indigo-500 text-indigo-400 bg-indigo-500/5'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <RotateCcw className="w-4 h-4" />
          <span>Baseline Lifecycle & Rollback</span>
        </button>
      </div>

      {/* ==================================================================== */}
      {/* 1. ENTITY PROFILES VIEW */}
      {/* ==================================================================== */}
      {activeSubTab === 'profiles' && (
        <div className="space-y-4">
          {/* Controls Bar */}
          <div className="flex flex-wrap items-center justify-between gap-3 p-3 rounded-xl bg-slate-900/60 border border-slate-800">
            <div className="flex items-center space-x-3 flex-1 min-w-[240px]">
              <div className="relative flex-1 max-w-sm">
                <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
                <input
                  type="text"
                  placeholder="Search user, device, or endpoint ID..."
                  value={profileSearch}
                  onChange={(e) => setProfileSearch(e.target.value)}
                  className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-sm text-slate-200 focus:outline-none focus:border-indigo-500"
                />
              </div>

              <select
                value={profileTypeFilter}
                onChange={(e) => setProfileTypeFilter(e.target.value)}
                className="px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-sm text-slate-200 focus:outline-none focus:border-indigo-500"
              >
                <option value="ALL">All Entity Types</option>
                <option value="USER">User / Account</option>
                <option value="DEVICE">Device</option>
                <option value="ENDPOINT">Endpoint</option>
                <option value="API_CLIENT">API Client</option>
                <option value="IP">IP Address</option>
                <option value="DOMAIN">Domain</option>
              </select>

              <select
                value={profileStatusFilter}
                onChange={(e) => setProfileStatusFilter(e.target.value)}
                className="px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-sm text-slate-200 focus:outline-none focus:border-indigo-500"
              >
                <option value="ALL">All Lifecycle States</option>
                <option value="ACTIVE">Active</option>
                <option value="LEARNING">Learning</option>
                <option value="INSUFFICIENT_DATA">Cold Start (Insufficient)</option>
                <option value="STALE">Stale</option>
                <option value="DEGRADED">Degraded</option>
              </select>

              <select
                value={profileQualityFilter}
                onChange={(e) => setProfileQualityFilter(e.target.value)}
                className="px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-sm text-slate-200 focus:outline-none focus:border-indigo-500"
              >
                <option value="ALL">All Baseline Quality</option>
                <option value="STABLE">Stable</option>
                <option value="DEVELOPING">Developing</option>
                <option value="INSUFFICIENT_HISTORY">Insufficient History</option>
                <option value="STALE">Stale</option>
              </select>
            </div>
          </div>

          {/* Profiles Table */}
          <div className="rounded-xl border border-slate-800 bg-slate-900/60 overflow-hidden">
            <table className="w-full text-left text-sm text-slate-300">
              <thead className="bg-slate-950/70 text-xs uppercase text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="px-4 py-3">Entity Identifier</th>
                  <th className="px-4 py-3">Type</th>
                  <th className="px-4 py-3">Lifecycle State</th>
                  <th className="px-4 py-3">Quality</th>
                  <th className="px-4 py-3">Samples</th>
                  <th className="px-4 py-3">Confidence</th>
                  <th className="px-4 py-3">Active Metrics</th>
                  <th className="px-4 py-3">Last Observed</th>
                  <th className="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {loadingProfiles ? (
                  <tr>
                    <td colSpan={9} className="px-4 py-8 text-center text-slate-400">
                      Loading behavioral profiles...
                    </td>
                  </tr>
                ) : profiles.length === 0 ? (
                  <tr>
                    <td colSpan={9} className="px-4 py-8 text-center text-slate-500">
                      No behavioral profiles found matching current filters.
                    </td>
                  </tr>
                ) : (
                  profiles.map((p) => (
                    <tr key={p.id} className="hover:bg-slate-800/30 transition-colors">
                      <td className="px-4 py-3 font-mono text-sm font-semibold text-white">
                        <div className="flex items-center space-x-2">
                          {getEntityIcon(p.entity_type)}
                          <span className="truncate max-w-xs">{p.entity_id}</span>
                        </div>
                      </td>
                      <td className="px-4 py-3 text-xs text-slate-400">{p.entity_type}</td>
                      <td className="px-4 py-3">{getStatusBadge(p.profile_status)}</td>
                      <td className="px-4 py-3">{getQualityBadge(p.quality_status)}</td>
                      <td className="px-4 py-3 text-xs font-mono text-slate-300">{p.sample_count}</td>
                      <td className="px-4 py-3">
                        <div className="flex items-center space-x-2">
                          <div className="w-16 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                            <div
                              className="h-full bg-indigo-500 rounded-full"
                              style={{ width: `${Math.round(p.confidence_score * 100)}%` }}
                            />
                          </div>
                          <span className="text-xs font-mono text-slate-400">
                            {(p.confidence_score * 100).toFixed(0)}%
                          </span>
                        </div>
                      </td>
                      <td className="px-4 py-3 text-xs text-slate-400">
                        {p.active_metrics && p.active_metrics.length > 0 ? (
                          <div className="flex flex-wrap gap-1">
                            {p.active_metrics.slice(0, 2).map((m, idx) => (
                              <span key={idx} className="px-1.5 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300">
                                {m}
                              </span>
                            ))}
                            {p.active_metrics.length > 2 && (
                              <span className="text-[10px] text-slate-500">+{p.active_metrics.length - 2}</span>
                            )}
                          </div>
                        ) : (
                          <span className="text-slate-600">-</span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-xs text-slate-400">
                        {new Date(p.last_observed_at).toLocaleDateString()} {new Date(p.last_observed_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                      </td>
                      <td className="px-4 py-3 text-right">
                        <button
                          onClick={() => loadProfileDetail(p.id)}
                          className="px-2.5 py-1 rounded text-xs font-medium bg-indigo-600/20 hover:bg-indigo-600/30 text-indigo-300 border border-indigo-500/30 transition-colors"
                        >
                          View Detail
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ==================================================================== */}
      {/* 2. ANOMALY FEED VIEW */}
      {/* ==================================================================== */}
      {activeSubTab === 'anomalies' && (
        <div className="space-y-4">
          {/* Filter Bar */}
          <div className="flex items-center space-x-3 p-3 rounded-xl bg-slate-900/60 border border-slate-800">
            <select
              value={anomalySeverityFilter}
              onChange={(e) => setAnomalySeverityFilter(e.target.value)}
              className="px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-sm text-slate-200 focus:outline-none focus:border-indigo-500"
            >
              <option value="ALL">All Severities</option>
              <option value="HIGH">High Severity Only</option>
              <option value="MEDIUM">Medium Severity Only</option>
              <option value="LOW">Low Severity Only</option>
            </select>

            <select
              value={anomalyTypeFilter}
              onChange={(e) => setAnomalyTypeFilter(e.target.value)}
              className="px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-sm text-slate-200 focus:outline-none focus:border-indigo-500"
            >
              <option value="ALL">All Entity Types</option>
              <option value="ACCOUNT">User / Account</option>
              <option value="ENDPOINT">Endpoint / Device</option>
              <option value="API_CLIENT">API Client</option>
            </select>
          </div>

          {/* Anomaly Feed Cards */}
          <div className="space-y-3">
            {loadingAnomalies ? (
              <div className="p-8 text-center text-slate-400">Loading behavioral anomalies...</div>
            ) : anomalies.length === 0 ? (
              <div className="p-8 text-center text-slate-500 bg-slate-900/40 rounded-xl border border-slate-800">
                No behavioral deviations recorded under current criteria.
              </div>
            ) : (
              anomalies.map((a) => (
                <div
                  key={a.id}
                  className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-slate-700 transition-all space-y-3"
                >
                  <div className="flex items-start justify-between">
                    <div className="flex items-center space-x-3">
                      {getEntityIcon(a.entity_type)}
                      <div>
                        <div className="text-sm font-bold text-white flex items-center space-x-2">
                          <span>{a.entity_id}</span>
                          <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono">
                            {a.metric_type}
                          </span>
                        </div>
                        <div className="text-xs text-slate-400">
                          {new Date(a.created_at).toLocaleDateString()} at{' '}
                          {new Date(a.created_at).toLocaleTimeString()}
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center space-x-2">
                      {getSeverityBadge(a.severity_hint)}
                      <div className="text-right">
                        <div className="text-xs font-mono font-bold text-rose-400">
                          Score: {(a.deviation_score * 100).toFixed(0)}%
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Visual Baseline Comparison */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 p-3 rounded-lg bg-slate-950/70 border border-slate-800/80 text-xs">
                    <div>
                      <span className="text-slate-500 block mb-0.5">Observed Value</span>
                      <span className="font-mono font-semibold text-rose-300">{a.observed_value}</span>
                    </div>
                    <div>
                      <span className="text-slate-500 block mb-0.5">Established Baseline Range</span>
                      <span className="font-mono text-emerald-400">{a.baseline_expected_range || 'Normal profile'}</span>
                    </div>
                  </div>

                  {/* Explanation Text */}
                  <div className="text-xs text-slate-300 bg-slate-800/20 p-2.5 rounded border border-slate-800/50">
                    <span className="font-semibold text-indigo-400 mr-1.5">Evidence:</span>
                    {a.explanation}
                  </div>

                  {/* Finding / Alert Links */}
                  <div className="flex items-center justify-between text-[11px] text-slate-500 pt-1">
                    <div className="flex items-center space-x-3">
                      {a.finding_id && (
                        <span className="text-indigo-400">
                          Finding: <span className="font-mono text-slate-300">{a.finding_id.slice(0, 8)}...</span>
                        </span>
                      )}
                      {a.alert_id && (
                        <span className="text-rose-400 font-semibold">
                          Alert Raised: <span className="font-mono text-slate-300">{a.alert_id.slice(0, 8)}...</span>
                        </span>
                      )}
                    </div>
                    {a.limitations && a.limitations.length > 0 && (
                      <span className="text-slate-500 italic">Limitation: {a.limitations[0]}</span>
                    )}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* ==================================================================== */}
      {/* 3. LEARNING QUARANTINE (POISONING DEFENSE) */}
      {/* ==================================================================== */}
      {activeSubTab === 'quarantine' && (
        <div className="space-y-4">
          <div className="p-4 rounded-xl bg-purple-950/20 border border-purple-800/30 text-xs text-purple-200 flex items-center justify-between">
            <div>
              <span className="font-bold text-sm block text-purple-300 mb-0.5">
                Baseline Contamination & Poisoning Defense Active
              </span>
              Observations exhibiting extreme deviation, sudden bursts, or suspicious origins are isolated here.
              Approved observations enter the clean baseline training set; rejected observations are permanently excluded.
            </div>
            <select
              value={quarantineDispFilter}
              onChange={(e) => setQuarantineDispFilter(e.target.value)}
              className="px-3 py-1.5 rounded-lg bg-slate-900 border border-purple-700/50 text-xs text-purple-100"
            >
              <option value="ALL">All Dispositions</option>
              <option value="PENDING">Pending Review Only</option>
              <option value="APPROVED">Approved Only</option>
              <option value="REJECTED">Rejected Only</option>
            </select>
          </div>

          <div className="rounded-xl border border-slate-800 bg-slate-900/60 overflow-hidden">
            <table className="w-full text-left text-sm text-slate-300">
              <thead className="bg-slate-950/70 text-xs uppercase text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="px-4 py-3">Entity</th>
                  <th className="px-4 py-3">Metric</th>
                  <th className="px-4 py-3">Observed Value</th>
                  <th className="px-4 py-3">Quarantine Reason</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Reviewer</th>
                  <th className="px-4 py-3">Timestamp</th>
                  <th className="px-4 py-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {loadingQuarantines ? (
                  <tr>
                    <td colSpan={8} className="px-4 py-8 text-center text-slate-400">
                      Loading quarantine queue...
                    </td>
                  </tr>
                ) : quarantines.length === 0 ? (
                  <tr>
                    <td colSpan={8} className="px-4 py-8 text-center text-slate-500">
                      No quarantined observations found. Baselines are clean.
                    </td>
                  </tr>
                ) : (
                  quarantines.map((q) => (
                    <tr key={q.id} className="hover:bg-slate-800/30 transition-colors">
                      <td className="px-4 py-3 font-mono text-xs font-semibold text-white">
                        <div className="flex items-center space-x-2">
                          {getEntityIcon(q.entity_type)}
                          <span>{q.entity_id}</span>
                        </div>
                      </td>
                      <td className="px-4 py-3 text-xs text-slate-400">{q.metric_type}</td>
                      <td className="px-4 py-3 font-mono text-xs text-amber-300 truncate max-w-xs">{q.observed_value}</td>
                      <td className="px-4 py-3 text-xs">
                        <span className="px-2 py-0.5 rounded bg-purple-500/10 text-purple-400 border border-purple-500/30">
                          {q.quarantine_reason}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-xs">
                        {q.disposition === 'PENDING' && (
                          <span className="px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/30">
                            Pending
                          </span>
                        )}
                        {q.disposition === 'APPROVED' && (
                          <span className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                            Approved
                          </span>
                        )}
                        {q.disposition === 'REJECTED' && (
                          <span className="px-2 py-0.5 rounded bg-rose-500/10 text-rose-400 border border-rose-500/30">
                            Rejected (Excluded)
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-xs text-slate-400">{q.reviewed_by || '-'}</td>
                      <td className="px-4 py-3 text-xs text-slate-400">
                        {new Date(q.created_at).toLocaleDateString()} {new Date(q.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                      </td>
                      <td className="px-4 py-3 text-right">
                        {q.disposition === 'PENDING' ? (
                          <button
                            onClick={() => {
                              setReviewModalItem(q);
                              setReviewNotes('');
                            }}
                            className="px-2.5 py-1 rounded text-xs font-medium bg-purple-600/20 hover:bg-purple-600/30 text-purple-300 border border-purple-500/30 transition-colors"
                          >
                            Review
                          </button>
                        ) : (
                          <span className="text-xs text-slate-500 italic">Completed</span>
                        )}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ==================================================================== */}
      {/* 4. BASELINE LIFECYCLE & ROLLBACK */}
      {/* ==================================================================== */}
      {activeSubTab === 'lifecycle' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Baseline Recalculation Card */}
          <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-4">
            <div className="flex items-center space-x-3">
              <div className="p-2 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
                <RefreshCw className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-base font-bold text-white">Controlled Baseline Recalculation</h3>
                <p className="text-xs text-slate-400">
                  Recomputes entity baselines over clean historical observation windows, excluding rejected quarantine data.
                </p>
              </div>
            </div>

            <div className="space-y-3 text-sm">
              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1">Entity Identifier (Optional)</label>
                <input
                  type="text"
                  placeholder="e.g. alice@cyberguard.local or leave blank for all"
                  value={refreshEntityId}
                  onChange={(e) => setRefreshEntityId(e.target.value)}
                  className="w-full px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-sm text-slate-200 focus:outline-none focus:border-indigo-500"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1">Entity Type</label>
                <select
                  value={refreshEntityType}
                  onChange={(e) => setRefreshEntityType(e.target.value)}
                  className="w-full px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-sm text-slate-200 focus:outline-none focus:border-indigo-500"
                >
                  <option value="ALL">All Entity Types</option>
                  <option value="USER">User / Account</option>
                  <option value="DEVICE">Device</option>
                  <option value="ENDPOINT">Endpoint</option>
                  <option value="API_CLIENT">API Client</option>
                </select>
              </div>

              <button
                onClick={handleRefreshBaselines}
                disabled={refreshingBaselines}
                className="w-full mt-2 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-medium text-xs transition-colors flex items-center justify-center space-x-2"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${refreshingBaselines ? 'animate-spin' : ''}`} />
                <span>{refreshingBaselines ? 'Recalculating...' : 'Trigger Baseline Recalculation'}</span>
              </button>
            </div>
          </div>

          {/* Baseline Version Rollback Card */}
          <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-4">
            <div className="flex items-center space-x-3">
              <div className="p-2 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-400">
                <RotateCcw className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-base font-bold text-white">Audited Baseline Rollback</h3>
                <p className="text-xs text-slate-400">
                  Reverts a compromised baseline version to a recalibration state with mandatory justification audit.
                </p>
              </div>
            </div>

            <div className="space-y-3 text-sm">
              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1">Baseline ID</label>
                <input
                  type="text"
                  placeholder="e.g. base-dave-hour"
                  value={rollbackBaselineId}
                  onChange={(e) => setRollbackBaselineId(e.target.value)}
                  className="w-full px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-sm text-slate-200 focus:outline-none focus:border-indigo-500"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1">Justification Reason</label>
                <textarea
                  rows={2}
                  placeholder="Explain why this baseline version is being rolled back..."
                  value={rollbackReason}
                  onChange={(e) => setRollbackReason(e.target.value)}
                  className="w-full px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-sm text-slate-200 focus:outline-none focus:border-indigo-500"
                />
              </div>

              <button
                onClick={handleRollbackBaseline}
                disabled={rollingBack}
                className="w-full mt-2 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-medium text-xs transition-colors flex items-center justify-center space-x-2"
              >
                <RotateCcw className={`w-3.5 h-3.5 ${rollingBack ? 'animate-spin' : ''}`} />
                <span>{rollingBack ? 'Rolling Back...' : 'Execute Baseline Rollback'}</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ==================================================================== */}
      {/* PROFILE DETAIL MODAL */}
      {/* ==================================================================== */}
      {selectedProfileId && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          {loadingDetail && !profileDetail ? (
            <div className="p-8 rounded-2xl bg-slate-900 border border-slate-800 text-slate-300 flex items-center space-x-3 shadow-2xl">
              <RefreshCw className="w-5 h-5 animate-spin text-indigo-400" />
              <span>Loading profile baseline details...</span>
            </div>
          ) : profileDetail ? (
            <div className="w-full max-w-4xl max-h-[90vh] bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl overflow-hidden flex flex-col">
              {/* Modal Header */}
              <div className="p-4 px-6 border-b border-slate-800 flex items-center justify-between bg-slate-950/60">
                <div className="flex items-center space-x-3">
                {getEntityIcon(profileDetail.entity_type)}
                <div>
                  <h3 className="text-base font-bold text-white flex items-center space-x-2">
                    <span>{profileDetail.entity_id}</span>
                    <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                      {profileDetail.entity_category}
                    </span>
                  </h3>
                  <div className="text-xs text-slate-400">
                    Version: {profileDetail.baseline_version} | Status: {profileDetail.profile_status}
                  </div>
                </div>
              </div>
              <button
                onClick={() => {
                  setSelectedProfileId(null);
                  setProfileDetail(null);
                }}
                className="text-slate-400 hover:text-white"
              >
                <XCircle className="w-5 h-5" />
              </button>
            </div>

            {/* Modal Body */}
            <div className="p-6 overflow-y-auto space-y-6">
              {/* Profile Metrics Summary */}
              <div className="grid grid-cols-4 gap-3 text-xs">
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="text-slate-500 block mb-1">Lifecycle Status</span>
                  {getStatusBadge(profileDetail.profile_status)}
                </div>
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="text-slate-500 block mb-1">Baseline Quality</span>
                  {getQualityBadge(profileDetail.quality_status)}
                </div>
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="text-slate-500 block mb-1">Total Samples</span>
                  <span className="font-mono font-bold text-white text-sm">{profileDetail.sample_count}</span>
                </div>
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="text-slate-500 block mb-1">Total Anomalies</span>
                  <span className="font-mono font-bold text-rose-400 text-sm">{profileDetail.anomaly_count}</span>
                </div>
              </div>

              {/* Active Baselines for this Entity */}
              <div>
                <h4 className="text-xs uppercase font-bold text-slate-400 mb-2">Active Established Baselines</h4>
                <div className="rounded-xl border border-slate-800 bg-slate-950/60 overflow-hidden">
                  <table className="w-full text-left text-xs text-slate-300">
                    <thead className="bg-slate-900 text-slate-400 border-b border-slate-800">
                      <tr>
                        <th className="px-3 py-2">Metric</th>
                        <th className="px-3 py-2">Expected Range</th>
                        <th className="px-3 py-2">Quality</th>
                        <th className="px-3 py-2">Samples</th>
                        <th className="px-3 py-2">Version</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60">
                      {profileDetail.active_baselines.length === 0 ? (
                        <tr>
                          <td colSpan={5} className="px-3 py-4 text-center text-slate-500">
                            No baselines established yet. Entity is in cold-start learning.
                          </td>
                        </tr>
                      ) : (
                        profileDetail.active_baselines.map((b) => (
                          <tr key={b.id}>
                            <td className="px-3 py-2 font-mono font-semibold text-white">{b.metric_type}</td>
                            <td className="px-3 py-2 text-emerald-400 font-mono">{b.expected_range_summary}</td>
                            <td className="px-3 py-2">{getQualityBadge(b.quality_status)}</td>
                            <td className="px-3 py-2 font-mono">{b.sample_count}</td>
                            <td className="px-3 py-2 font-mono text-slate-400">{b.metric_version}</td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Recent Deviations for this Entity */}
              <div>
                <h4 className="text-xs uppercase font-bold text-slate-400 mb-2">Recent Deviations</h4>
                <div className="space-y-2">
                  {profileDetail.recent_deviations.length === 0 ? (
                    <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-500 text-center">
                      No historical deviations recorded for this entity.
                    </div>
                  ) : (
                    profileDetail.recent_deviations.map((d) => (
                      <div key={d.id} className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs space-y-1.5">
                        <div className="flex items-center justify-between">
                          <span className="font-mono font-bold text-indigo-300">{d.metric_type}</span>
                          <div className="flex items-center space-x-2">
                            {getSeverityBadge(d.severity_hint)}
                            <span className="font-mono text-rose-400">{(d.deviation_score * 100).toFixed(0)}%</span>
                          </div>
                        </div>
                        <div className="text-slate-300">{d.explanation}</div>
                        <div className="text-slate-500 text-[11px] font-mono">
                          Observed: {d.observed_value} | Expected: {d.expected_range}
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>
            </div>
          </div>
        ) : null}
      </div>
    )}

      {/* ==================================================================== */}
      {/* QUARANTINE REVIEW MODAL */}
      {/* ==================================================================== */}
      {reviewModalItem && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="w-full max-w-lg bg-slate-900 border border-purple-800/40 rounded-2xl shadow-2xl p-6 space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2 text-purple-400">
                <ShieldAlert className="w-5 h-5" />
                <h3 className="text-base font-bold text-white">Review Quarantined Observation</h3>
              </div>
              <button onClick={() => setReviewModalItem(null)} className="text-slate-400 hover:text-white">
                <XCircle className="w-5 h-5" />
              </button>
            </div>

            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1.5 text-xs">
              <div className="text-slate-400">
                Entity: <span className="font-mono text-white font-bold">{reviewModalItem.entity_id}</span>
              </div>
              <div className="text-slate-400">
                Metric: <span className="font-mono text-slate-300">{reviewModalItem.metric_type}</span>
              </div>
              <div className="text-slate-400">
                Observed: <span className="font-mono text-rose-400 font-bold">{reviewModalItem.observed_value}</span>
              </div>
              <div className="text-slate-400">
                Reason: <span className="text-purple-300">{reviewModalItem.quarantine_reason}</span>
              </div>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-400 mb-1">Analyst Notes</label>
              <textarea
                rows={3}
                placeholder="Reason for disposition (e.g. Legitimate business trip vs Confirmed credential stuffing)..."
                value={reviewNotes}
                onChange={(e) => setReviewNotes(e.target.value)}
                className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200 focus:outline-none focus:border-purple-500"
              />
            </div>

            <div className="flex items-center justify-end space-x-3 pt-2">
              <button
                onClick={() => handleReviewQuarantine('REJECTED')}
                disabled={submittingReview}
                className="px-4 py-2 rounded-lg bg-rose-600/20 hover:bg-rose-600/30 text-rose-300 border border-rose-500/30 text-xs font-semibold transition-colors"
              >
                Reject & Exclude (Poisoning Defense)
              </button>
              <button
                onClick={() => handleReviewQuarantine('APPROVED')}
                disabled={submittingReview}
                className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold transition-colors"
              >
                Approve (Admit to Baseline)
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
