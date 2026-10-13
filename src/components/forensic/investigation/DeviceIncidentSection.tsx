import { apiFetch } from '../../../utils/apiClient';
import React, { useState, useEffect } from 'react';
import {
  Laptop,
  AlertTriangle,
  RefreshCw,
  CheckCircle2,
  Info
} from 'lucide-react';
import { apiUrl } from '../../../utils/apiClient';

interface DeviceIncidentSectionProps {
  incidentId?: string;
  emailId?: string;
}

interface CorrelatedDevice {
  correlation_id: string;
  device_id: string;
  hostname: string;
  platform: string;
  status: 'CONFIRMED' | 'SUPPORTED' | 'SUSPECTED' | 'RELATED' | 'OBSERVED' | 'DISMISSED';
  correlation_score: number;
  confidence: number;
  correlation_type: string;
  first_observed_at: string;
  last_observed_at: string;
  reason_codes: string[];
  supporting_signals_count: number;
  counter_evidence_count: number;
  explanation: {
    device_name?: string;
    incident_number?: string;
    facts?: string[];
    positive_signals?: string[];
    negative_signals?: string[];
    narrative?: string;
  };
}

interface TimelineItem {
  timestamp: string;
  event_type: string;
  source: string;
  description: string;
  priority: string;
  confidence: number;
  raw_event_id?: string;
  metadata?: any;
}

export const DeviceIncidentSection: React.FC<DeviceIncidentSectionProps> = ({ incidentId, emailId }) => {
  const [devices, setDevices] = useState<CorrelatedDevice[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [selectedDevice, setSelectedDevice] = useState<CorrelatedDevice | null>(null);
  const [activeTab, setActiveTab] = useState<'evidence' | 'timeline' | 'history'>('evidence');
  const [timeline, setTimeline] = useState<TimelineItem[]>([]);
  const [loadingTimeline, setLoadingTimeline] = useState<boolean>(false);
  const [reviewing, setReviewing] = useState<boolean>(false);
  const [reviewNote, setReviewNote] = useState<string>('');

  const targetIncidentId = incidentId || emailId || 'default-incident';

  const fetchCorrelations = async () => {
    setLoading(true);
    try {
      const res = await apiFetch(apiUrl(`/api/v1/incidents/${targetIncidentId}/devices`));
      if (res.ok) {
        const data = await res.json();
        setDevices(data.devices || []);
        if (data.devices && data.devices.length > 0 && !selectedDevice) {
          setSelectedDevice(data.devices[0]);
        }
      } else if (res.status === 404) {
        // Fallback: fetch fleet devices if incident not specifically established
        const fleetRes = await apiFetch(apiUrl('/api/v1/endpoint/devices'));
        if (fleetRes.ok) {
          const fleetData = await fleetRes.json();
          if (fleetData && fleetData.length > 0) {
            // Attempt on-demand correlation for first device
            const firstDev = fleetData[0];
            const corrRes = await apiFetch(apiUrl(`/api/v1/devices/${firstDev.id}/correlations`));
            if (corrRes.ok) {
              const corrs = await corrRes.json();
              setDevices(corrs);
              if (corrs.length > 0) setSelectedDevice(corrs[0]);
            }
          }
        }
      }
    } catch (err: any) {
      console.warn('Unable to load correlated devices:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchCorrelations();
  }, [targetIncidentId]);

  useEffect(() => {
    if (selectedDevice && activeTab === 'timeline') {
      setLoadingTimeline(true);
      apiFetch(apiUrl(`/api/v1/devices/${selectedDevice.device_id}/timeline?limit=50`))
        .then(res => res.ok ? res.json() : null)
        .then(data => {
          if (data && data.timeline) {
            setTimeline(data.timeline);
          }
        })
        .finally(() => setLoadingTimeline(false));
    }
  }, [selectedDevice, activeTab]);

  const handleReview = async (action: string) => {
    if (!selectedDevice) return;
    setReviewing(true);
    try {
      const res = await apiFetch(apiUrl(`/api/v1/correlations/${selectedDevice.correlation_id}/review`), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action,
          reviewer: 'SOC Lead Analyst',
          notes: reviewNote || `Analyst set status to ${action}`
        })
      });
      if (res.ok) {
        const updated = await res.json();
        setSelectedDevice(prev => prev ? { ...prev, status: updated.status } : null);
        fetchCorrelations();
        setReviewNote('');
      }
    } catch (err) {
      console.error('Failed to submit review:', err);
    } finally {
      setReviewing(false);
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'CONFIRMED':
        return <span className="px-2 py-0.5 text-xs font-semibold rounded bg-emerald-950/80 text-emerald-400 border border-emerald-800">CONFIRMED</span>;
      case 'SUPPORTED':
        return <span className="px-2 py-0.5 text-xs font-semibold rounded bg-blue-950/80 text-blue-400 border border-blue-800">SUPPORTED</span>;
      case 'SUSPECTED':
        return <span className="px-2 py-0.5 text-xs font-semibold rounded bg-amber-950/80 text-amber-400 border border-amber-800">SUSPECTED</span>;
      case 'RELATED':
        return <span className="px-2 py-0.5 text-xs font-semibold rounded bg-purple-950/80 text-purple-400 border border-purple-800">RELATED</span>;
      case 'DISMISSED':
        return <span className="px-2 py-0.5 text-xs font-semibold rounded bg-rose-950/80 text-rose-400 border border-rose-800">DISMISSED</span>;
      default:
        return <span className="px-2 py-0.5 text-xs font-semibold rounded bg-slate-800 text-slate-300 border border-slate-700">OBSERVED</span>;
    }
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 text-slate-200">
      <div className="flex items-center justify-between pb-4 border-b border-slate-800 mb-5">
        <div>
          <h2 className="text-base font-semibold text-slate-100 flex items-center gap-2">
            <Laptop className="w-5 h-5 text-indigo-400" />
            Device-to-Incident Correlation
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Evidence-backed correlation linking host endpoint telemetry with incident intelligence.
          </p>
        </div>
        <button
          onClick={fetchCorrelations}
          disabled={loading}
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {devices.length === 0 ? (
        <div className="bg-slate-950/60 border border-slate-800/80 rounded-lg p-8 text-center">
          <Laptop className="w-10 h-10 text-slate-600 mx-auto mb-3" />
          <h3 className="text-sm font-medium text-slate-300">No Correlated Devices</h3>
          <p className="text-xs text-slate-500 max-w-md mx-auto mt-1">
            No matching telemetry was observed between active endpoints and this incident within the 30-day retention window.
          </p>
          <div className="mt-4 flex items-center justify-center gap-2 text-xs text-slate-400">
            <Info className="w-4 h-4 text-slate-500" />
            <span>Telemetry is evaluated automatically upon agent ingestion.</span>
          </div>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
          {/* Left Column: Correlated Devices List */}
          <div className="lg:col-span-5 space-y-2.5">
            <div className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-2">
              Associated Endpoints ({devices.length})
            </div>
            {devices.map(dev => {
              const isSelected = selectedDevice?.device_id === dev.device_id;
              return (
                <div
                  key={dev.correlation_id || dev.device_id}
                  onClick={() => setSelectedDevice(dev)}
                  className={`cursor-pointer rounded-lg p-3.5 border transition ${
                    isSelected
                      ? 'bg-indigo-950/30 border-indigo-700/80 shadow-sm'
                      : 'bg-slate-950/40 border-slate-800/80 hover:bg-slate-800/50'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="font-medium text-sm text-slate-200 flex items-center gap-2">
                      <Laptop className="w-4 h-4 text-indigo-400" />
                      {dev.hostname}
                    </span>
                    {getStatusBadge(dev.status)}
                  </div>

                  <div className="flex items-center justify-between text-xs text-slate-400 mt-2">
                    <span>Platform: <strong className="text-slate-300 capitalize">{dev.platform}</strong></span>
                    <span>Strength: <strong className="text-indigo-400">{Math.round(dev.correlation_score * 100)}%</strong></span>
                  </div>

                  {/* Signals Indicator */}
                  <div className="flex items-center gap-2 mt-2 pt-2 border-t border-slate-800/60 text-xs text-slate-400">
                    <span className="text-emerald-400 font-medium">{dev.supporting_signals_count} supporting signals</span>
                    {dev.counter_evidence_count > 0 && (
                      <span className="text-amber-400 font-medium">• {dev.counter_evidence_count} counter-factors</span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>

          {/* Right Column: Progressive Disclosure Detail Panel */}
          <div className="lg:col-span-7 bg-slate-950/50 border border-slate-800 rounded-lg p-4">
            {selectedDevice ? (
              <div>
                {/* Header */}
                <div className="flex items-center justify-between pb-3 border-b border-slate-800 mb-3">
                  <div>
                    <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                      <Laptop className="w-4 h-4 text-indigo-400" />
                      {selectedDevice.hostname}
                    </h3>
                    <span className="text-xs text-slate-400">
                      Correlation Type: <strong className="text-slate-300">{selectedDevice.correlation_type}</strong>
                    </span>
                  </div>
                  {getStatusBadge(selectedDevice.status)}
                </div>

                {/* Sub-tabs */}
                <div className="flex gap-2 border-b border-slate-800/80 pb-2 mb-4 text-xs font-medium">
                  <button
                    onClick={() => setActiveTab('evidence')}
                    className={`px-3 py-1 rounded transition ${
                      activeTab === 'evidence'
                        ? 'bg-indigo-900/60 text-indigo-300 font-semibold'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    Evidence & Narrative
                  </button>
                  <button
                    onClick={() => setActiveTab('timeline')}
                    className={`px-3 py-1 rounded transition ${
                      activeTab === 'timeline'
                        ? 'bg-indigo-900/60 text-indigo-300 font-semibold'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    Host Timeline
                  </button>
                </div>

                {/* Tab: Evidence */}
                {activeTab === 'evidence' && (
                  <div className="space-y-3 text-xs">
                    {/* Narrative Summary */}
                    {selectedDevice.explanation?.narrative && (
                      <div className="p-3 bg-slate-900/80 border border-slate-800 rounded text-slate-300 leading-relaxed">
                        {selectedDevice.explanation.narrative}
                      </div>
                    )}

                    {/* Factual Premises */}
                    {selectedDevice.explanation?.facts && selectedDevice.explanation.facts.length > 0 && (
                      <div>
                        <h4 className="font-semibold text-slate-300 mb-1.5 flex items-center gap-1.5">
                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                          Supported Forensic Facts:
                        </h4>
                        <ul className="space-y-1 pl-4 list-disc text-slate-400">
                          {selectedDevice.explanation.facts.map((fact, idx) => (
                            <li key={idx}>{fact}</li>
                          ))}
                        </ul>
                      </div>
                    )}

                    {/* Counter Evidence & Limitations */}
                    {selectedDevice.explanation?.negative_signals && selectedDevice.explanation.negative_signals.length > 0 && (
                      <div className="p-2.5 bg-amber-950/30 border border-amber-900/40 rounded text-amber-300">
                        <h4 className="font-semibold flex items-center gap-1.5 mb-1">
                          <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                          Counter-Evidence & Discounts:
                        </h4>
                        <ul className="space-y-0.5 pl-4 list-disc text-xs text-amber-200/90">
                          {selectedDevice.explanation.negative_signals.map((neg, idx) => (
                            <li key={idx}>{neg}</li>
                          ))}
                        </ul>
                      </div>
                    )}

                    {/* Analyst Review Override */}
                    <div className="pt-3 border-t border-slate-800">
                      <span className="text-xs font-semibold text-slate-300 block mb-2">
                        Analyst Verification & Decision:
                      </span>
                      <input
                        type="text"
                        value={reviewNote}
                        onChange={e => setReviewNote(e.target.value)}
                        placeholder="Optional analyst rationale / notes..."
                        className="w-full mb-2 px-2.5 py-1 text-xs bg-slate-900 border border-slate-700 rounded text-slate-200 placeholder-slate-500 focus:outline-none focus:border-indigo-500"
                      />
                      <div className="flex gap-2">
                        <button
                          onClick={() => handleReview('CONFIRM_ASSOCIATION')}
                          disabled={reviewing}
                          className="px-2.5 py-1 rounded bg-emerald-900/60 hover:bg-emerald-800/80 text-emerald-300 border border-emerald-700/60 text-xs font-medium transition"
                        >
                          Confirm Association
                        </button>
                        <button
                          onClick={() => handleReview('MARK_RELATED')}
                          disabled={reviewing}
                          className="px-2.5 py-1 rounded bg-purple-900/60 hover:bg-purple-800/80 text-purple-300 border border-purple-700/60 text-xs font-medium transition"
                        >
                          Mark as Related
                        </button>
                        <button
                          onClick={() => handleReview('DISMISS_ASSOCIATION')}
                          disabled={reviewing}
                          className="px-2.5 py-1 rounded bg-rose-900/60 hover:bg-rose-800/80 text-rose-300 border border-rose-700/60 text-xs font-medium transition"
                        >
                          Dismiss Association
                        </button>
                      </div>
                    </div>
                  </div>
                )}

                {/* Tab: Timeline */}
                {activeTab === 'timeline' && (
                  <div className="space-y-2 text-xs">
                    {loadingTimeline ? (
                      <div className="text-center py-6 text-slate-500">Loading timeline observations...</div>
                    ) : timeline.length === 0 ? (
                      <div className="text-center py-6 text-slate-500">No events observed in current window.</div>
                    ) : (
                      <div className="max-h-72 overflow-y-auto space-y-2 pr-1">
                        {timeline.map((item, idx) => (
                          <div key={idx} className="p-2 bg-slate-900 border border-slate-800 rounded">
                            <div className="flex items-center justify-between text-slate-400 mb-1">
                              <span className="font-medium text-slate-300">{item.event_type}</span>
                              <span className="text-slate-500">{new Date(item.timestamp).toLocaleTimeString()}</span>
                            </div>
                            <p className="text-slate-300">{item.description}</p>
                            <span className="text-slate-500 text-[10px] block mt-1">Source: {item.source}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>
            ) : (
              <div className="text-center py-12 text-slate-500 text-xs">
                Select an associated device to inspect forensic evidence.
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
