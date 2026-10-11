import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Link as LinkIcon,
  Plus,
  ExternalLink,
  ShieldAlert,
  Search,
  Server,
  User,
  Flag,
  X,
  RefreshCw,
} from 'lucide-react';
import type { CaseDetail, CaseLinkPayload } from '../../types/case';
import { caseService } from '../../services/caseService';

interface CaseLinkedEntitiesSectionProps {
  caseData: CaseDetail;
  onEntityLinked: () => void;
  showToast: (msg: string) => void;
}

export const CaseLinkedEntitiesSection: React.FC<CaseLinkedEntitiesSectionProps> = ({
  caseData,
  onEntityLinked,
  showToast,
}) => {
  const [showLinkModal, setShowLinkModal] = useState(false);
  const [entityType, setEntityType] = useState('INCIDENT');
  const [entityId, setEntityId] = useState('');
  const [details, setDetails] = useState('');
  const [linking, setLinking] = useState(false);

  const handleLink = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!entityId.trim()) return;

    setLinking(true);
    try {
      const payload: CaseLinkPayload = {
        entity_type: entityType,
        entity_id: entityId.trim(),
        details: details.trim() || undefined,
      };
      await caseService.linkEntity(caseData.id, payload);
      setShowLinkModal(false);
      setEntityId('');
      setDetails('');
      showToast(`Linked ${entityType} ${payload.entity_id} to case`);
      onEntityLinked();
    } catch (err: any) {
      alert(`Failed to link entity: ${err.message}`);
    } finally {
      setLinking(false);
    }
  };

  const hasAnyEntities =
    caseData.incident_id ||
    caseData.primary_investigation_id ||
    caseData.campaign_id ||
    (caseData.affected_assets && caseData.affected_assets.length > 0) ||
    (caseData.affected_identities && caseData.affected_identities.length > 0) ||
    (caseData.related_alerts && caseData.related_alerts.length > 0);

  return (
    <div className="bg-surface rounded-2xl border border-border p-5 space-y-5 shadow-xs">
      <div className="flex items-center justify-between pb-3 border-b border-border">
        <div className="flex items-center space-x-2">
          <LinkIcon className="w-4 h-4 text-primary" />
          <h3 className="text-sm font-bold font-mono text-foreground">
            Authoritative Linked Entities & Context
          </h3>
        </div>
        <button
          type="button"
          onClick={() => setShowLinkModal(true)}
          className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-surface hover:bg-surface-secondary border border-border text-foreground font-mono text-xs font-semibold transition-all cursor-pointer shadow-xs"
        >
          <Plus className="w-3.5 h-3.5 text-primary" />
          <span>Link Entity</span>
        </button>
      </div>

      {!hasAnyEntities ? (
        <div className="text-center py-8 text-xs font-mono text-foreground-muted">
          No external incident, investigation, or campaign entities linked to this case yet.
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
          {/* Linked Incident */}
          {caseData.incident_id && (
            <div className="p-3.5 rounded-xl bg-surface-secondary/50 border border-border space-y-2">
              <div className="flex items-center justify-between text-xs font-mono">
                <span className="text-foreground-muted font-medium flex items-center space-x-1.5">
                  <ShieldAlert className="w-3.5 h-3.5 text-danger" />
                  <span>Authoritative Incident</span>
                </span>
                <span className="px-1.5 py-0.5 rounded bg-danger-surface text-danger text-[10px] font-bold">
                  CANONICAL
                </span>
              </div>
              <p className="text-xs font-mono font-bold text-foreground truncate">
                {caseData.incident_id}
              </p>
              <Link
                to={`/incidents/${caseData.incident_id}`}
                className="inline-flex items-center space-x-1 text-[11px] font-mono text-primary hover:underline"
              >
                <span>View Incident Workspace</span>
                <ExternalLink className="w-3 h-3" />
              </Link>
            </div>
          )}

          {/* Primary Investigation */}
          {caseData.primary_investigation_id && (
            <div className="p-3.5 rounded-xl bg-surface-secondary/50 border border-border space-y-2">
              <div className="flex items-center justify-between text-xs font-mono">
                <span className="text-foreground-muted font-medium flex items-center space-x-1.5">
                  <Search className="w-3.5 h-3.5 text-primary" />
                  <span>Root Investigation</span>
                </span>
                <span className="px-1.5 py-0.5 rounded bg-primary-subtle text-primary text-[10px]">
                  SECTION 66
                </span>
              </div>
              <p className="text-xs font-mono font-bold text-foreground truncate">
                {caseData.primary_investigation_id}
              </p>
              <Link
                to={`/investigate/${caseData.primary_investigation_id}`}
                className="inline-flex items-center space-x-1 text-[11px] font-mono text-primary hover:underline"
              >
                <span>Open Forensic Workspace</span>
                <ExternalLink className="w-3 h-3" />
              </Link>
            </div>
          )}

          {/* Threat Campaign */}
          {caseData.campaign_id && (
            <div className="p-3.5 rounded-xl bg-surface-secondary/50 border border-border space-y-2">
              <div className="flex items-center justify-between text-xs font-mono">
                <span className="text-foreground-muted font-medium flex items-center space-x-1.5">
                  <Flag className="w-3.5 h-3.5 text-warning" />
                  <span>Threat Campaign</span>
                </span>
                <span className="px-1.5 py-0.5 rounded bg-warning-surface text-warning text-[10px]">
                  SECTION 65
                </span>
              </div>
              <p className="text-xs font-mono font-bold text-foreground truncate">
                {caseData.campaign_id}
              </p>
              <Link
                to="/campaigns"
                className="inline-flex items-center space-x-1 text-[11px] font-mono text-primary hover:underline"
              >
                <span>Threat Campaign Intelligence</span>
                <ExternalLink className="w-3 h-3" />
              </Link>
            </div>
          )}

          {/* Affected Assets */}
          {caseData.affected_assets && caseData.affected_assets.length > 0 && (
            <div className="p-3.5 rounded-xl bg-surface-secondary/50 border border-border space-y-2 col-span-1 md:col-span-2 lg:col-span-1">
              <div className="flex items-center space-x-1.5 text-xs font-mono text-foreground-muted font-medium">
                <Server className="w-3.5 h-3.5 text-primary" />
                <span>Affected Assets ({caseData.affected_assets.length})</span>
              </div>
              <div className="flex flex-wrap gap-1.5">
                {caseData.affected_assets.map(asset => (
                  <span
                    key={asset}
                    className="px-2 py-0.5 rounded bg-surface border border-border text-[11px] font-mono text-foreground"
                  >
                    {asset}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Affected Identities */}
          {caseData.affected_identities && caseData.affected_identities.length > 0 && (
            <div className="p-3.5 rounded-xl bg-surface-secondary/50 border border-border space-y-2 col-span-1 md:col-span-2 lg:col-span-1">
              <div className="flex items-center space-x-1.5 text-xs font-mono text-foreground-muted font-medium">
                <User className="w-3.5 h-3.5 text-primary" />
                <span>Affected Identities ({caseData.affected_identities.length})</span>
              </div>
              <div className="flex flex-wrap gap-1.5">
                {caseData.affected_identities.map(identity => (
                  <span
                    key={identity}
                    className="px-2 py-0.5 rounded bg-surface border border-border text-[11px] font-mono text-foreground"
                  >
                    {identity}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Related Alerts */}
          {caseData.related_alerts && caseData.related_alerts.length > 0 && (
            <div className="p-3.5 rounded-xl bg-surface-secondary/50 border border-border space-y-2 col-span-1 md:col-span-2 lg:col-span-1">
              <div className="flex items-center space-x-1.5 text-xs font-mono text-foreground-muted font-medium">
                <ShieldAlert className="w-3.5 h-3.5 text-warning" />
                <span>Related Alerts ({caseData.related_alerts.length})</span>
              </div>
              <div className="flex flex-wrap gap-1.5">
                {caseData.related_alerts.map(alt => (
                  <span
                    key={alt}
                    className="px-2 py-0.5 rounded bg-surface border border-border text-[11px] font-mono text-foreground"
                  >
                    {alt}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* LINK ENTITY MODAL */}
      {showLinkModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4">
          <div className="bg-surface border border-border rounded-xl shadow-xl w-full max-w-md overflow-hidden animate-in fade-in zoom-in-95 duration-150">
            <div className="flex items-center justify-between px-5 py-4 border-b border-border bg-surface-secondary/40">
              <div className="flex items-center space-x-2">
                <LinkIcon className="w-4 h-4 text-primary" />
                <h3 className="font-mono text-sm font-bold text-foreground">Link Entity to Case</h3>
              </div>
              <button
                type="button"
                onClick={() => setShowLinkModal(false)}
                className="text-foreground-muted hover:text-foreground cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleLink} className="p-5 space-y-4">
              <div>
                <label className="block text-xs font-mono font-medium text-foreground mb-1">
                  Entity Type *
                </label>
                <select
                  value={entityType}
                  onChange={e => setEntityType(e.target.value)}
                  className="w-full px-3 py-2 bg-surface-secondary rounded-lg border border-border text-xs font-mono text-foreground focus:outline-none focus:border-primary"
                >
                  <option value="INCIDENT">Incident</option>
                  <option value="INVESTIGATION">Investigation</option>
                  <option value="CAMPAIGN">Threat Campaign</option>
                  <option value="ALERT">Alert</option>
                  <option value="ASSET">Asset Host / IP</option>
                  <option value="IDENTITY">User Identity / Email</option>
                  <option value="EVIDENCE">Evidence Artifact</option>
                </select>
              </div>

              <div>
                <label className="block text-xs font-mono font-medium text-foreground mb-1">
                  Entity Identifier *
                </label>
                <input
                  type="text"
                  required
                  placeholder="e.g. INC-2026-00042, INV-9923, or user@corp.com"
                  value={entityId}
                  onChange={e => setEntityId(e.target.value)}
                  className="w-full px-3 py-2 bg-surface-secondary rounded-lg border border-border text-xs font-mono text-foreground focus:outline-none focus:border-primary"
                />
              </div>

              <div>
                <label className="block text-xs font-mono font-medium text-foreground mb-1">
                  Operational Linking Notes (Optional)
                </label>
                <textarea
                  rows={2}
                  placeholder="Reason for linking or observed relationship..."
                  value={details}
                  onChange={e => setDetails(e.target.value)}
                  className="w-full px-3 py-2 bg-surface-secondary rounded-lg border border-border text-xs font-mono text-foreground focus:outline-none focus:border-primary"
                />
              </div>

              <div className="flex items-center justify-end space-x-2 pt-3 border-t border-border">
                <button
                  type="button"
                  onClick={() => setShowLinkModal(false)}
                  className="px-3.5 py-1.5 rounded-lg border border-border text-xs font-mono text-foreground-muted hover:text-foreground cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={linking}
                  className="flex items-center space-x-1.5 px-4 py-1.5 rounded-lg bg-primary hover:bg-primary-hover text-primary-foreground font-mono text-xs font-semibold disabled:opacity-50 cursor-pointer"
                >
                  {linking && <RefreshCw className="w-3.5 h-3.5 animate-spin" />}
                  <span>{linking ? 'Linking...' : 'Link Entity'}</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
