/**
 * Section 65: Threat Actor Workspace.
 * Authoritative analyst workspace for threat actor profiles, aliases with source provenance,
 * observed techniques, supporting/contradicting evidence, and auditable attribution assessments.
 */
import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  ShieldAlert,
  Search,
  Plus,
  RefreshCw,
  AlertTriangle,
  CheckCircle,
  HelpCircle,
  X,
  Award,
} from 'lucide-react';
import { threatWorkspaceService } from '../services/threatWorkspaceService';
import type {
  ThreatActor,
  AttributionAssessmentResponse,
  AttributionState,
  ActorType,
} from '../types/threatWorkspace';

export const ThreatActorWorkspace: React.FC = () => {
  const { id: routeActorId } = useParams<{ id: string }>();
  const navigate = useNavigate();

  const [actors, setActors] = useState<ThreatActor[]>([]);
  const [selectedActor, setSelectedActor] = useState<ThreatActor | null>(null);
  const [assessments, setAssessments] = useState<AttributionAssessmentResponse[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [loadingAssessments, setLoadingAssessments] = useState<boolean>(false);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [attrFilter, setAttrFilter] = useState<string>('');
  const [activeTab, setActiveTab] = useState<'overview' | 'aliases' | 'techniques' | 'evidence' | 'assessments'>('overview');

  // Modals
  const [showAssessmentModal, setShowAssessmentModal] = useState<boolean>(false);
  const [showCreateModal, setShowCreateModal] = useState<boolean>(false);
  const [assessmentState, setAssessmentState] = useState<AttributionState>('POSSIBLE');
  const [assessmentConfidence, setAssessmentConfidence] = useState<number>(0.7);
  const [assessmentJustification, setAssessmentJustification] = useState<string>('');
  const [assessmentError, setAssessmentError] = useState<string | null>(null);
  const [submittingAssessment, setSubmittingAssessment] = useState<boolean>(false);

  // New Actor Form
  const [newActorName, setNewActorName] = useState<string>('');
  const [newActorType, setNewActorType] = useState<ActorType>('CYBERCRIME');
  const [newActorMotivation, setNewActorMotivation] = useState<string>('FINANCIAL');
  const [newActorDescription, setNewActorDescription] = useState<string>('');
  const [newActorAttrState, setNewActorAttrState] = useState<AttributionState>('SUSPECTED');
  const [newActorAliases, setNewActorAliases] = useState<string>('');
  const [creatingActor, setCreatingActor] = useState<boolean>(false);

  // Load actors
  const fetchActors = async () => {
    try {
      setLoading(true);
      const res = await threatWorkspaceService.getActors({
        query: searchQuery || undefined,
        status: statusFilter || undefined,
        attribution_state: attrFilter || undefined,
      });
      setActors(res.items);
      if (res.items.length > 0) {
        const toSelect = routeActorId
          ? res.items.find(a => a.id === routeActorId || a.actor_id === routeActorId) || res.items[0]
          : res.items[0];
        setSelectedActor(toSelect);
        loadAssessments(toSelect.id);
      } else {
        setSelectedActor(null);
      }
    } catch (err) {
      console.error('Failed to load actors:', err);
    } finally {
      setLoading(false);
    }
  };

  const loadAssessments = async (actorId: string) => {
    try {
      setLoadingAssessments(true);
      const res = await threatWorkspaceService.getActorAssessments(actorId);
      setAssessments(res);
    } catch (err) {
      console.error('Failed to load assessments:', err);
    } finally {
      setLoadingAssessments(false);
    }
  };

  useEffect(() => {
    fetchActors();
  }, [searchQuery, statusFilter, attrFilter]);

  const handleSelectActor = (actor: ThreatActor) => {
    setSelectedActor(actor);
    navigate(`/actors/${actor.actor_id}`);
    loadAssessments(actor.id);
  };

  const handleRecordAssessment = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedActor) return;
    if (assessmentState === 'CONFIRMED' && assessmentJustification.trim().length < 10) {
      setAssessmentError('CONFIRMED attribution requires substantive justification (minimum 10 characters).');
      return;
    }

    try {
      setSubmittingAssessment(true);
      setAssessmentError(null);
      await threatWorkspaceService.recordActorAssessment(selectedActor.id, {
        subject_id: selectedActor.id,
        new_attribution_state: assessmentState,
        confidence: assessmentConfidence,
        justification: assessmentJustification.trim(),
      });
      setShowAssessmentModal(false);
      setAssessmentJustification('');
      fetchActors();
    } catch (err: any) {
      setAssessmentError(err.message || 'Failed to submit assessment');
    } finally {
      setSubmittingAssessment(false);
    }
  };

  const handleCreateActor = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newActorName.trim()) return;

    try {
      setCreatingActor(true);
      const aliasList = newActorAliases
        .split(',')
        .map(a => a.trim())
        .filter(Boolean)
        .map(a => ({ alias: a, source: 'Analyst Initial Import', confidence: 0.7 }));

      await threatWorkspaceService.createActor({
        name: newActorName.trim(),
        actor_type: newActorType,
        motivation: newActorMotivation,
        description: newActorDescription.trim() || undefined,
        attribution_state: newActorAttrState,
        attribution_confidence: 0.6,
        aliases: aliasList,
      });
      setShowCreateModal(false);
      setNewActorName('');
      setNewActorDescription('');
      setNewActorAliases('');
      fetchActors();
    } catch (err: any) {
      console.error('Failed to create actor:', err);
    } finally {
      setCreatingActor(false);
    }
  };

  const getAttributionBadge = (state: AttributionState) => {
    const config: Record<AttributionState, { bg: string; text: string; border: string }> = {
      CONFIRMED: { bg: 'bg-red-500/10', text: 'text-red-400', border: 'border-red-500/30' },
      ASSESSED: { bg: 'bg-purple-500/10', text: 'text-purple-400', border: 'border-purple-500/30' },
      PROBABLE: { bg: 'bg-orange-500/10', text: 'text-orange-400', border: 'border-orange-500/30' },
      POSSIBLE: { bg: 'bg-yellow-500/10', text: 'text-yellow-400', border: 'border-yellow-500/30' },
      SUSPECTED: { bg: 'bg-blue-500/10', text: 'text-blue-400', border: 'border-blue-500/30' },
      DISPUTED: { bg: 'bg-amber-500/10', text: 'text-amber-400', border: 'border-amber-500/30' },
      REJECTED: { bg: 'bg-zinc-500/10', text: 'text-zinc-400', border: 'border-zinc-500/30' },
      UNKNOWN: { bg: 'bg-zinc-800', text: 'text-zinc-400', border: 'border-zinc-700' },
    };
    const c = config[state] || config.UNKNOWN;
    return (
      <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold border ${c.bg} ${c.text} ${c.border}`}>
        {state}
      </span>
    );
  };

  return (
    <div className="flex flex-col h-full bg-[#0d1117] text-zinc-100 font-sans">
      {/* Top Header */}
      <header className="border-b border-zinc-800 bg-[#161b22] px-6 py-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2 bg-purple-500/10 border border-purple-500/30 rounded-lg text-purple-400">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-white tracking-tight">Threat Actor Intelligence Workspace</h1>
              <p className="text-xs text-zinc-400">
                Track adversary groups, source-provenanced aliases, observed MITRE techniques, and auditable attribution assessments.
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3 w-full sm:w-auto">
          <button
            onClick={() => threatWorkspaceService.triggerSync()}
            className="flex items-center gap-2 px-3 py-2 text-xs font-medium rounded-lg bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 text-zinc-200 transition-colors"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Sync Workspace
          </button>
          <button
            onClick={() => setShowCreateModal(true)}
            className="flex items-center gap-2 px-3.5 py-2 text-xs font-semibold rounded-lg bg-purple-600 hover:bg-purple-500 text-white shadow-sm transition-colors"
          >
            <Plus className="w-3.5 h-3.5" />
            New Threat Actor Profile
          </button>
        </div>
      </header>

      {/* Main Content: Split Layout */}
      <div className="flex-1 flex overflow-hidden">
        {/* Left Sidebar: Actor Directory */}
        <aside className="w-full sm:w-80 md:w-96 border-r border-zinc-800 flex flex-col bg-[#0d1117] overflow-hidden">
          {/* Filters Bar */}
          <div className="p-4 border-b border-zinc-800 space-y-3 bg-[#161b22]/50">
            <div className="relative">
              <Search className="w-4 h-4 text-zinc-400 absolute left-3 top-2.5" />
              <input
                type="text"
                placeholder="Search actor name, alias, ID..."
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                className="w-full pl-9 pr-3 py-1.5 text-xs rounded-lg bg-[#0d1117] border border-zinc-700 text-zinc-200 placeholder-zinc-500 focus:outline-none focus:border-purple-500"
              />
            </div>
            <div className="grid grid-cols-2 gap-2">
              <select
                value={attrFilter}
                onChange={e => setAttrFilter(e.target.value)}
                className="text-xs rounded-lg bg-[#0d1117] border border-zinc-700 text-zinc-300 py-1.5 px-2 focus:outline-none"
              >
                <option value="">All Attribution States</option>
                <option value="CONFIRMED">CONFIRMED</option>
                <option value="ASSESSED">ASSESSED</option>
                <option value="PROBABLE">PROBABLE</option>
                <option value="POSSIBLE">POSSIBLE</option>
                <option value="SUSPECTED">SUSPECTED</option>
                <option value="DISPUTED">DISPUTED</option>
              </select>
              <select
                value={statusFilter}
                onChange={e => setStatusFilter(e.target.value)}
                className="text-xs rounded-lg bg-[#0d1117] border border-zinc-700 text-zinc-300 py-1.5 px-2 focus:outline-none"
              >
                <option value="">All Statuses</option>
                <option value="ACTIVE">ACTIVE</option>
                <option value="MONITORING">MONITORING</option>
                <option value="DORMANT">DORMANT</option>
              </select>
            </div>
          </div>

          {/* Actor Cards List */}
          <div className="flex-1 overflow-y-auto divide-y divide-zinc-800/60 p-2 space-y-1">
            {loading ? (
              <div className="p-6 text-center text-xs text-zinc-400">Loading threat actors...</div>
            ) : actors.length === 0 ? (
              <div className="p-8 text-center text-xs text-zinc-500">
                No threat actor profiles found matching criteria.
              </div>
            ) : (
              actors.map(actor => {
                const isSelected = selectedActor?.id === actor.id;
                return (
                  <div
                    key={actor.id}
                    onClick={() => handleSelectActor(actor)}
                    className={`p-3 rounded-lg cursor-pointer transition-all ${
                      isSelected
                        ? 'bg-purple-950/20 border border-purple-500/40 shadow-sm'
                        : 'hover:bg-[#161b22] border border-transparent'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2 mb-1">
                      <span className="font-semibold text-xs text-white truncate">{actor.name}</span>
                      <span className="text-[10px] text-zinc-400 font-mono px-1.5 py-0.5 rounded bg-zinc-800">
                        {actor.actor_id}
                      </span>
                    </div>
                    <div className="flex items-center justify-between gap-2 mt-2">
                      <div className="flex items-center gap-1.5">
                        {getAttributionBadge(actor.attribution_state)}
                        <span className="text-[10px] text-zinc-400 font-mono">{actor.actor_type}</span>
                      </div>
                      <div className="text-[10px] text-zinc-400">
                        Conf: {(actor.attribution_confidence * 100).toFixed(0)}%
                      </div>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </aside>

        {/* Right Detail Pane */}
        <main className="flex-1 flex flex-col bg-[#0d1117] overflow-y-auto">
          {selectedActor ? (
            <div className="p-6 space-y-6 max-w-6xl">
              {/* Profile Header */}
              <div className="bg-[#161b22] border border-zinc-800 rounded-xl p-6">
                <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 border-b border-zinc-800/80 pb-5">
                  <div>
                    <div className="flex items-center gap-3">
                      <h2 className="text-2xl font-bold text-white tracking-tight">{selectedActor.name}</h2>
                      <span className="text-xs font-mono px-2 py-0.5 rounded bg-zinc-800 text-purple-400 border border-purple-500/20">
                        {selectedActor.actor_id}
                      </span>
                      {getAttributionBadge(selectedActor.attribution_state)}
                    </div>
                    <p className="text-xs text-zinc-400 mt-1">
                      Canonical Key: <span className="text-zinc-300 font-mono">{selectedActor.canonical_name}</span> • Type: {selectedActor.actor_type} • Status: {selectedActor.status}
                    </p>
                  </div>

                  <div className="flex items-center gap-3">
                    <button
                      onClick={() => setShowAssessmentModal(true)}
                      className="flex items-center gap-2 px-3 py-2 text-xs font-semibold rounded-lg bg-purple-600 hover:bg-purple-500 text-white transition-colors"
                    >
                      <Award className="w-3.5 h-3.5" />
                      Record Attribution Assessment
                    </button>
                  </div>
                </div>

                {/* Attribution Principle Banner */}
                <div className="mt-4 p-3 rounded-lg bg-zinc-900 border border-zinc-800 flex items-start gap-3">
                  <HelpCircle className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
                  <div className="text-xs text-zinc-400 leading-relaxed">
                    <span className="font-semibold text-zinc-200">Attribution Principle:</span> CyberGuard never presents attribution as fact. Confidence ({ (selectedActor.attribution_confidence * 100).toFixed(0) }%) represents assessment strength and is strictly independent from risk severity.
                  </div>
                </div>

                {/* Metrics Row */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mt-5">
                  <div className="p-3 rounded-lg bg-[#0d1117] border border-zinc-800/80">
                    <div className="text-[11px] text-zinc-400">Associated Campaigns</div>
                    <div className="text-lg font-bold text-white mt-1">{selectedActor.associated_campaigns_count}</div>
                  </div>
                  <div className="p-3 rounded-lg bg-[#0d1117] border border-zinc-800/80">
                    <div className="text-[11px] text-zinc-400">Observed Techniques</div>
                    <div className="text-lg font-bold text-purple-400 mt-1">{selectedActor.observed_techniques.length}</div>
                  </div>
                  <div className="p-3 rounded-lg bg-[#0d1117] border border-zinc-800/80">
                    <div className="text-[11px] text-zinc-400">Attribution Confidence</div>
                    <div className="text-lg font-bold text-yellow-400 mt-1">{(selectedActor.attribution_confidence * 100).toFixed(0)}%</div>
                  </div>
                  <div className="p-3 rounded-lg bg-[#0d1117] border border-zinc-800/80">
                    <div className="text-[11px] text-zinc-400">Known Aliases</div>
                    <div className="text-lg font-bold text-blue-400 mt-1">{selectedActor.aliases.length}</div>
                  </div>
                </div>
              </div>

              {/* Navigation Tabs */}
              <div className="border-b border-zinc-800 flex gap-6 text-xs font-medium">
                {(['overview', 'aliases', 'techniques', 'evidence', 'assessments'] as const).map(tab => (
                  <button
                    key={tab}
                    onClick={() => setActiveTab(tab)}
                    className={`pb-3 capitalize transition-colors border-b-2 ${
                      activeTab === tab
                        ? 'border-purple-500 text-white font-semibold'
                        : 'border-transparent text-zinc-400 hover:text-zinc-200'
                    }`}
                  >
                    {tab}
                  </button>
                ))}
              </div>

              {/* Tab Contents */}
              {activeTab === 'overview' && (
                <div className="space-y-6">
                  <div className="bg-[#161b22] border border-zinc-800 rounded-xl p-5 space-y-3">
                    <h3 className="text-sm font-semibold text-white">Analyst Threat Profile</h3>
                    <p className="text-xs text-zinc-300 leading-relaxed">
                      {selectedActor.description || 'No profile description authored yet for this threat actor.'}
                    </p>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="bg-[#161b22] border border-zinc-800 rounded-xl p-5 space-y-2">
                      <h4 className="text-xs font-semibold text-zinc-200">Motivation & Sophistication</h4>
                      <div className="text-xs text-zinc-400">
                        Motivation: <span className="text-zinc-200 font-medium">{selectedActor.motivation || 'UNKNOWN'}</span>
                      </div>
                      <div className="text-xs text-zinc-400">
                        Sophistication: <span className="text-zinc-200 font-medium">{selectedActor.sophistication}</span>
                      </div>
                    </div>

                    <div className="bg-[#161b22] border border-zinc-800 rounded-xl p-5 space-y-2">
                      <h4 className="text-xs font-semibold text-zinc-200">Targeting Profile</h4>
                      {selectedActor.primary_targets.length > 0 ? (
                        <div className="flex flex-wrap gap-1.5">
                          {selectedActor.primary_targets.map((tgt, i) => (
                            <span key={i} className="px-2 py-0.5 rounded text-[11px] bg-zinc-800 text-zinc-300 border border-zinc-700">
                              {tgt}
                            </span>
                          ))}
                        </div>
                      ) : (
                        <p className="text-xs text-zinc-500">No specific industry or regional targets recorded.</p>
                      )}
                    </div>
                  </div>
                </div>
              )}

              {activeTab === 'aliases' && (
                <div className="bg-[#161b22] border border-zinc-800 rounded-xl p-5 space-y-4">
                  <div className="flex items-center justify-between">
                    <h3 className="text-sm font-semibold text-white">External Vendor Aliases & Source Provenance</h3>
                    <span className="text-xs text-zinc-400">{selectedActor.aliases.length} recorded</span>
                  </div>
                  {selectedActor.aliases.length === 0 ? (
                    <p className="text-xs text-zinc-500">No external intelligence aliases associated with this actor.</p>
                  ) : (
                    <div className="divide-y divide-zinc-800">
                      {selectedActor.aliases.map((al, idx) => (
                        <div key={idx} className="py-2.5 flex items-center justify-between text-xs">
                          <div className="flex items-center gap-3">
                            <span className="font-semibold text-white">{al.alias}</span>
                            <span className="px-2 py-0.5 rounded text-[10px] bg-purple-950/40 text-purple-300 border border-purple-800/40">
                              Source: {al.source}
                            </span>
                          </div>
                          <span className="text-zinc-400 font-mono text-[11px]">
                            Confidence: {(al.confidence * 100).toFixed(0)}%
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {activeTab === 'techniques' && (
                <div className="bg-[#161b22] border border-zinc-800 rounded-xl p-5 space-y-4">
                  <h3 className="text-sm font-semibold text-white">Observed MITRE ATT&CK Techniques</h3>
                  {selectedActor.observed_techniques.length === 0 ? (
                    <p className="text-xs text-zinc-500">No technique identifiers mapped to this actor profile.</p>
                  ) : (
                    <div className="grid grid-cols-2 sm:grid-cols-3 gap-2.5">
                      {selectedActor.observed_techniques.map((tech, idx) => (
                        <div key={idx} className="p-2.5 rounded-lg bg-zinc-900 border border-zinc-800 flex items-center justify-between">
                          <span className="font-mono text-xs text-purple-400 font-semibold">{tech}</span>
                          <span className="text-[10px] text-zinc-500">ATT&CK</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {activeTab === 'evidence' && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="bg-[#161b22] border border-zinc-800 rounded-xl p-5 space-y-3">
                    <h3 className="text-sm font-semibold text-emerald-400 flex items-center gap-2">
                      <CheckCircle className="w-4 h-4" /> Supporting Evidence ({selectedActor.supporting_evidence.length})
                    </h3>
                    {selectedActor.supporting_evidence.length === 0 ? (
                      <p className="text-xs text-zinc-500">No direct supporting evidence recorded.</p>
                    ) : (
                      <div className="space-y-2">
                        {selectedActor.supporting_evidence.map((ev, i) => (
                          <div key={i} className="p-2.5 rounded-lg bg-zinc-900/60 border border-zinc-800 text-xs space-y-1">
                            <div className="text-zinc-200">{ev.description}</div>
                            <div className="text-[10px] text-zinc-400 flex justify-between">
                              <span>Source: {ev.source}</span>
                              <span className="font-mono">{ev.semantic_class}</span>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  <div className="bg-[#161b22] border border-zinc-800 rounded-xl p-5 space-y-3">
                    <h3 className="text-sm font-semibold text-red-400 flex items-center gap-2">
                      <AlertTriangle className="w-4 h-4" /> Contradicting Evidence ({selectedActor.contradicting_evidence.length})
                    </h3>
                    {selectedActor.contradicting_evidence.length === 0 ? (
                      <p className="text-xs text-zinc-500">No contradicting evidence observed.</p>
                    ) : (
                      <div className="space-y-2">
                        {selectedActor.contradicting_evidence.map((ev, i) => (
                          <div key={i} className="p-2.5 rounded-lg bg-zinc-900/60 border border-zinc-800 text-xs space-y-1">
                            <div className="text-zinc-200">{ev.description}</div>
                            <div className="text-[10px] text-zinc-400 flex justify-between">
                              <span>Source: {ev.source}</span>
                              <span className="font-mono">{ev.semantic_class}</span>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              )}

              {activeTab === 'assessments' && (
                <div className="bg-[#161b22] border border-zinc-800 rounded-xl p-5 space-y-4">
                  <div className="flex items-center justify-between">
                    <h3 className="text-sm font-semibold text-white">Attribution Assessment History</h3>
                    <span className="text-xs text-zinc-400">{assessments.length} logged assessments</span>
                  </div>
                  {loadingAssessments ? (
                    <p className="text-xs text-zinc-500">Loading historical assessments...</p>
                  ) : assessments.length === 0 ? (
                    <p className="text-xs text-zinc-500">No historical attribution transitions recorded.</p>
                  ) : (
                    <div className="relative pl-6 space-y-6 before:absolute before:left-2 before:top-2 before:bottom-2 before:w-0.5 before:bg-zinc-800">
                      {assessments.map(ass => (
                        <div key={ass.id} className="relative">
                          <div className="absolute -left-6 top-1 w-2.5 h-2.5 rounded-full bg-purple-500 ring-4 ring-[#161b22]" />
                          <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-3.5 space-y-2">
                            <div className="flex items-center justify-between text-xs">
                              <div className="flex items-center gap-2">
                                <span className="text-zinc-400 line-through">{ass.prior_attribution_state}</span>
                                <span className="text-zinc-500">→</span>
                                {getAttributionBadge(ass.new_attribution_state as AttributionState)}
                              </div>
                              <span className="text-zinc-400 text-[11px]">{new Date(ass.assessed_at).toLocaleString()}</span>
                            </div>
                            <p className="text-xs text-zinc-300 leading-relaxed">{ass.justification}</p>
                            <div className="text-[10px] text-zinc-400 flex justify-between pt-1 border-t border-zinc-800/60">
                              <span>Analyst: {ass.assessed_by}</span>
                              <span>Confidence: {(ass.confidence * 100).toFixed(0)}%</span>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          ) : (
            <div className="flex-1 flex flex-col items-center justify-center p-8 text-center text-zinc-500">
              <ShieldAlert className="w-12 h-12 mb-3 text-zinc-600" />
              <p className="text-sm">Select a Threat Actor from the directory or create a new profile.</p>
            </div>
          )}
        </main>
      </div>

      {/* Modal: Record Attribution Assessment */}
      {showAssessmentModal && selectedActor && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="bg-[#161b22] border border-zinc-800 rounded-xl w-full max-w-lg overflow-hidden shadow-2xl">
            <div className="p-5 border-b border-zinc-800 flex items-center justify-between">
              <h3 className="text-base font-semibold text-white">Record Attribution Assessment</h3>
              <button onClick={() => setShowAssessmentModal(false)} className="text-zinc-400 hover:text-white">
                <X className="w-5 h-5" />
              </button>
            </div>
            <form onSubmit={handleRecordAssessment} className="p-5 space-y-4 text-xs">
              {assessmentError && (
                <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400">
                  {assessmentError}
                </div>
              )}
              <div>
                <label className="block text-zinc-300 font-medium mb-1">New Attribution State</label>
                <select
                  value={assessmentState}
                  onChange={e => setAssessmentState(e.target.value as AttributionState)}
                  className="w-full rounded-lg bg-zinc-900 border border-zinc-700 p-2 text-white"
                >
                  <option value="SUSPECTED">SUSPECTED</option>
                  <option value="POSSIBLE">POSSIBLE</option>
                  <option value="PROBABLE">PROBABLE</option>
                  <option value="ASSESSED">ASSESSED</option>
                  <option value="CONFIRMED">CONFIRMED (Authoritative intelligence required)</option>
                  <option value="DISPUTED">DISPUTED</option>
                  <option value="REJECTED">REJECTED</option>
                </select>
              </div>

              <div>
                <label className="block text-zinc-300 font-medium mb-1">
                  Confidence Score: {(assessmentConfidence * 100).toFixed(0)}% (Separate from Risk)
                </label>
                <input
                  type="range"
                  min="0"
                  max="1"
                  step="0.05"
                  value={assessmentConfidence}
                  onChange={e => setAssessmentConfidence(parseFloat(e.target.value))}
                  className="w-full"
                />
              </div>

              <div>
                <label className="block text-zinc-300 font-medium mb-1">
                  Substantive Justification & Rationale <span className="text-red-400">*</span>
                </label>
                <textarea
                  rows={3}
                  placeholder="State observable evidence, external flash alerts, or corroborating forensic clusters..."
                  value={assessmentJustification}
                  onChange={e => setAssessmentJustification(e.target.value)}
                  className="w-full rounded-lg bg-zinc-900 border border-zinc-700 p-2 text-white placeholder-zinc-500 focus:outline-none"
                  required
                />
              </div>

              <div className="flex justify-end gap-2 pt-3 border-t border-zinc-800">
                <button
                  type="button"
                  onClick={() => setShowAssessmentModal(false)}
                  className="px-4 py-2 rounded-lg bg-zinc-800 text-zinc-300 hover:bg-zinc-700"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submittingAssessment}
                  className="px-4 py-2 rounded-lg bg-purple-600 hover:bg-purple-500 text-white font-semibold"
                >
                  {submittingAssessment ? 'Saving...' : 'Save Assessment'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Modal: Create Threat Actor */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="bg-[#161b22] border border-zinc-800 rounded-xl w-full max-w-lg overflow-hidden shadow-2xl">
            <div className="p-5 border-b border-zinc-800 flex items-center justify-between">
              <h3 className="text-base font-semibold text-white">Create Threat Actor Profile</h3>
              <button onClick={() => setShowCreateModal(false)} className="text-zinc-400 hover:text-white">
                <X className="w-5 h-5" />
              </button>
            </div>
            <form onSubmit={handleCreateActor} className="p-5 space-y-4 text-xs">
              <div>
                <label className="block text-zinc-300 font-medium mb-1">Actor Name <span className="text-red-400">*</span></label>
                <input
                  type="text"
                  placeholder="e.g. Storm-0492 or Volt Typhoon"
                  value={newActorName}
                  onChange={e => setNewActorName(e.target.value)}
                  className="w-full rounded-lg bg-zinc-900 border border-zinc-700 p-2 text-white"
                  required
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-zinc-300 font-medium mb-1">Actor Type</label>
                  <select
                    value={newActorType}
                    onChange={e => setNewActorType(e.target.value as ActorType)}
                    className="w-full rounded-lg bg-zinc-900 border border-zinc-700 p-2 text-white"
                  >
                    <option value="CYBERCRIME">CYBERCRIME</option>
                    <option value="NATION_STATE">NATION_STATE</option>
                    <option value="HACKTIVIST">HACKTIVIST</option>
                    <option value="INSIDER">INSIDER</option>
                    <option value="OPPORTUNISTIC">OPPORTUNISTIC</option>
                    <option value="UNKNOWN">UNKNOWN</option>
                  </select>
                </div>
                <div>
                  <label className="block text-zinc-300 font-medium mb-1">Initial Attribution</label>
                  <select
                    value={newActorAttrState}
                    onChange={e => setNewActorAttrState(e.target.value as AttributionState)}
                    className="w-full rounded-lg bg-zinc-900 border border-zinc-700 p-2 text-white"
                  >
                    <option value="SUSPECTED">SUSPECTED</option>
                    <option value="POSSIBLE">POSSIBLE</option>
                    <option value="UNKNOWN">UNKNOWN</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-zinc-300 font-medium mb-1">Primary Motivation</label>
                <input
                  type="text"
                  placeholder="e.g. FINANCIAL, ESPIONAGE, SABOTAGE"
                  value={newActorMotivation}
                  onChange={e => setNewActorMotivation(e.target.value)}
                  className="w-full rounded-lg bg-zinc-900 border border-zinc-700 p-2 text-white"
                />
              </div>

              <div>
                <label className="block text-zinc-300 font-medium mb-1">Known Aliases (Comma separated)</label>
                <input
                  type="text"
                  placeholder="e.g. UNC2452, DarkHalo, NOBELIUM"
                  value={newActorAliases}
                  onChange={e => setNewActorAliases(e.target.value)}
                  className="w-full rounded-lg bg-zinc-900 border border-zinc-700 p-2 text-white"
                />
              </div>

              <div>
                <label className="block text-zinc-300 font-medium mb-1">Profile Summary</label>
                <textarea
                  rows={3}
                  placeholder="Operational background, targeting, and initial assessment..."
                  value={newActorDescription}
                  onChange={e => setNewActorDescription(e.target.value)}
                  className="w-full rounded-lg bg-zinc-900 border border-zinc-700 p-2 text-white"
                />
              </div>

              <div className="flex justify-end gap-2 pt-3 border-t border-zinc-800">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-4 py-2 rounded-lg bg-zinc-800 text-zinc-300 hover:bg-zinc-700"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={creatingActor}
                  className="px-4 py-2 rounded-lg bg-purple-600 hover:bg-purple-500 text-white font-semibold"
                >
                  {creatingActor ? 'Creating...' : 'Create Profile'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
