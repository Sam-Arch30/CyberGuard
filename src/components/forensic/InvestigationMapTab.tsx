import React, { useState, useEffect, useRef, useMemo } from 'react';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';
import {
  Globe,
  MapPin,
  Server,
  Search,
  Copy,
  Check,
  Info,
  Cloud,
  Lock,
  Maximize2
} from 'lucide-react';
import type { EmailAnalysis } from '../../types/forensic';
import type { InfrastructureMapNode } from '../../types/map';
import { extractInfrastructureMapData } from '../../utils/mapHelper';
import { useTheme } from '../../context/ThemeContext';

interface InvestigationMapTabProps {
  email: EmailAnalysis;
}

interface GeolocationStatus {
  provider: string;
  status: string;
  tier: string;
  mode: string;
}

export const InvestigationMapTab: React.FC<InvestigationMapTabProps> = ({ email }) => {
  const { isDark } = useTheme();
  const mapContainerRef = useRef<HTMLDivElement>(null);
  const mapInstanceRef = useRef<L.Map | null>(null);
  const tileLayerRef = useRef<L.TileLayer | null>(null);
  const markersMapRef = useRef<Map<string, L.Marker>>(new Map());
  const routeLayerRef = useRef<L.Polyline | null>(null);

  const [activeFilter, setActiveFilter] = useState<'all' | 'earliest' | 'relay' | 'indicator'>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [showRoute, setShowRoute] = useState(true);
  const [copiedIp, setCopiedIp] = useState<string | null>(null);
  const [providerStatus, setProviderStatus] = useState<GeolocationStatus | null>(null);

  // Fetch safe configuration status
  useEffect(() => {
    let isMounted = true;
    const fetchStatus = async () => {
      try {
        const res = await fetch('http://127.0.0.1:8000/api/intelligence/geolocation/status');
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        if (isMounted) setProviderStatus(data);
      } catch (err: any) {
        if (isMounted) {
          try {
            const fallbackRes = await fetch('/api/intelligence/geolocation/status');
            if (fallbackRes.ok) {
              const data = await fallbackRes.json();
              if (isMounted) setProviderStatus(data);
              return;
            }
          } catch {
            // ignore
          }
        }
      }
    };
    fetchStatus();
    return () => {
      isMounted = false;
    };
  }, []);

  // Extract infrastructure nodes and route path from email
  const mapData = useMemo(() => extractInfrastructureMapData(email), [email]);

  // Filter nodes based on role and text search
  const filteredNodes = useMemo(() => {
    return mapData.nodes.filter(node => {
      // Role filter
      if (activeFilter === 'earliest' && !node.is_earliest) return false;
      if (activeFilter === 'relay' && node.role !== 'relay_node') return false;
      if (activeFilter === 'indicator' && node.role !== 'indicator_ip') return false;

      // Text query
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase().trim();
        const matchIp = node.ip.toLowerCase().includes(q);
        const matchCountry = (node.country || '').toLowerCase().includes(q);
        const matchCity = (node.city || '').toLowerCase().includes(q);
        const matchOrg = (node.organization || '').toLowerCase().includes(q);
        const matchAsn = (node.asn || '').toLowerCase().includes(q);
        return matchIp || matchCountry || matchCity || matchOrg || matchAsn;
      }
      return true;
    });
  }, [mapData, activeFilter, searchQuery]);

  // Copy IP handler
  const handleCopy = (ip: string, e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(ip);
    setCopiedIp(ip);
    setTimeout(() => setCopiedIp(null), 2000);
  };

  // Fly map to node when clicked from the panel
  const handleSelectNode = (node: InfrastructureMapNode) => {
    setSelectedNodeId(node.id);
    const map = mapInstanceRef.current;
    if (map) {
      map.flyTo([node.latitude, node.longitude], Math.max(map.getZoom(), 6), { duration: 1 });
      const marker = markersMapRef.current.get(node.id);
      if (marker) {
        marker.openPopup();
      }
    }
  };

  // Reset map view to fit all filtered nodes
  const handleResetBounds = () => {
    const map = mapInstanceRef.current;
    if (!map) return;
    if (filteredNodes.length === 0) {
      map.setView([20, 0], 2);
    } else if (filteredNodes.length === 1) {
      map.setView([filteredNodes[0].latitude, filteredNodes[0].longitude], 6);
    } else {
      const bounds = L.latLngBounds(filteredNodes.map(n => [n.latitude, n.longitude]));
      map.fitBounds(bounds, { padding: [40, 40] });
    }
  };

  // Initialize Leaflet Map once
  useEffect(() => {
    if (!mapContainerRef.current || mapInstanceRef.current) return;

    const map = L.map(mapContainerRef.current, {
      center: [20, 0],
      zoom: 2,
      zoomControl: true,
      attributionControl: true
    });

    const initialTileUrl = isDark
      ? 'https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}'
      : 'https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Light_Gray_Base/MapServer/tile/{z}/{y}/{x}';

    const tileLayer = L.tileLayer(initialTileUrl, {
      maxZoom: 16,
      attribution: '&copy; <a href="https://www.esri.com/">Esri</a> &copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>'
    }).addTo(map);

    tileLayerRef.current = tileLayer;
    mapInstanceRef.current = map;

    return () => {
      map.remove();
      mapInstanceRef.current = null;
      tileLayerRef.current = null;
    };
  }, []);

  // Update tile layer whenever theme mode changes
  useEffect(() => {
    if (!mapInstanceRef.current || !tileLayerRef.current) return;
    const tileUrl = isDark
      ? 'https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}'
      : 'https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Light_Gray_Base/MapServer/tile/{z}/{y}/{x}';
    tileLayerRef.current.setUrl(tileUrl);
  }, [isDark]);

  // Update Markers and Route on data or filter or theme change
  useEffect(() => {
    const map = mapInstanceRef.current;
    if (!map) return;

    // Remove existing markers
    markersMapRef.current.forEach(m => map.removeLayer(m));
    markersMapRef.current.clear();

    // Remove existing route layer
    if (routeLayerRef.current) {
      map.removeLayer(routeLayerRef.current);
      routeLayerRef.current = null;
    }

    // 1. Draw Polyline for Observed Infrastructure Route
    if (showRoute && mapData.route_path.length >= 2) {
      const polyline = L.polyline(mapData.route_path, {
        color: '#06b6d4', // Primary Cyan
        weight: 3,
        opacity: 0.85,
        dashArray: '6, 8',
        lineCap: 'round',
        lineJoin: 'round'
      }).addTo(map);

      polyline.bindTooltip(
        `<div style="font-family: ui-monospace, monospace; font-size: 11px; font-weight: 700; color: ${isDark ? '#06b6d4' : '#0891b2'}; background: ${isDark ? '#020617' : '#ffffff'}; padding: 3px 8px; border-radius: 6px; border: 1px solid ${isDark ? '#0891b2' : '#06b6d4'};">Observed infrastructure route</div>`,
        { sticky: true, className: 'route-tooltip' }
      );

      routeLayerRef.current = polyline;
    }

    // 2. Add Markers for Filtered Nodes
    if (filteredNodes.length === 0) {
      map.setView([20, 0], 2);
      return;
    }

    const bounds = L.latLngBounds([]);
    const campaignName = (email as any)?.campaign_id || email.attribution?.campaign_id || email.attribution?.related_campaigns?.[0] || 'Individual Case';

    filteredNodes.forEach(node => {
      bounds.extend([node.latitude, node.longitude]);

      // Marker badge styling based on role
      let bgStyle = 'background: rgba(6, 182, 212, 0.95); border: 2px solid #67e8f9; color: #020617;';
      let iconInner = '•';

      if (node.is_earliest) {
        bgStyle = 'background: rgba(225, 29, 72, 0.95); border: 2px solid #fecdd3; color: #ffffff; box-shadow: 0 0 14px rgba(225,29,72,0.8);';
        iconInner = '★';
      } else if (node.role === 'relay_node') {
        bgStyle = 'background: rgba(37, 99, 235, 0.95); border: 2px solid #93c5fd; color: #ffffff; box-shadow: 0 0 10px rgba(37,99,235,0.7);';
        iconInner = node.hop_number !== undefined ? `${node.hop_number}` : 'R';
      }

      const markerHtml = `
        <div style="
          width: 28px;
          height: 28px;
          ${bgStyle}
          border-radius: 50%;
          display: flex;
          align-items: center;
          justify-content: center;
          font-family: ui-monospace, monospace;
          font-weight: 800;
          font-size: 11px;
          cursor: pointer;
          transition: transform 0.15s ease-in-out;
        ">
          ${iconInner}
        </div>
      `;

      const customIcon = L.divIcon({
        html: markerHtml,
        className: 'investigation-map-marker',
        iconSize: [28, 28],
        iconAnchor: [14, 14],
        popupAnchor: [0, -14]
      });

      // HTML Popup content adapting to theme with complete forensic metadata
      const popupBg = isDark ? '#0b0f17' : '#ffffff';
      const popupBorder = isDark ? '#1e293b' : '#e2e8f0';
      const popupText = isDark ? '#f1f5f9' : '#0f172a';
      const popupMuted = isDark ? '#94a3b8' : '#64748b';
      const popupIp = isDark ? '#38bdf8' : '#0284c7';
      const popupSubBorder = isDark ? '#1e293b' : '#f1f5f9';

      const threatStatusLabel = node.is_earliest
        ? 'Probable Origin Infrastructure'
        : node.is_proxy_vpn_tor
        ? 'Suspicious (Proxy/VPN/Tor Node)'
        : 'Observed Infrastructure Node';

      const relayRoleLabel = node.role === 'relay_node' && node.hop_number !== undefined
        ? `Relay Hop #${node.hop_number}`
        : node.role_label;

      const popupHtml = `
        <div style="color: ${popupText}; background: ${popupBg}; font-family: ui-sans-serif, system-ui, sans-serif; font-size: 12px; min-width: 250px; padding: 10px; border-radius: 8px; border: 1px solid ${popupBorder}; box-shadow: 0 4px 14px rgba(0,0,0,0.25);">
          <div style="display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid ${popupSubBorder}; padding-bottom: 6px; margin-bottom: 6px;">
            <span style="font-family: ui-monospace, monospace; font-weight: 700; font-size: 13px; color: ${popupIp};">${node.ip}</span>
            <span style="font-family: ui-monospace, monospace; font-size: 9px; text-transform: uppercase; font-weight: 700; padding: 2px 6px; border-radius: 4px; ${
              node.is_earliest ? 'background: rgba(225, 29, 72, 0.15); color: #e11d48; border: 1px solid rgba(225, 29, 72, 0.3);' :
              node.role === 'relay_node' ? 'background: rgba(37, 99, 235, 0.15); color: #2563eb; border: 1px solid rgba(37, 99, 235, 0.3);' :
              'background: rgba(8, 145, 178, 0.15); color: #0891b2; border: 1px solid rgba(8, 145, 178, 0.3);'
            }">
              ${relayRoleLabel}
            </span>
          </div>

          <div style="display: flex; flex-direction: column; gap: 4px; font-size: 11px; color: ${popupText};">
            <div><strong style="color: ${popupMuted};">Infrastructure:</strong> Observed Infrastructure Location</div>
            <div><strong style="color: ${popupMuted};">Location:</strong> ${[node.city, node.region, node.country].filter(Boolean).join(', ') || 'Unknown'}</div>
            <div><strong style="color: ${popupMuted};">Country:</strong> ${node.country || 'N/A'} ${node.country_code ? `(${node.country_code})` : ''}</div>
            <div><strong style="color: ${popupMuted};">ASN:</strong> <span style="font-family: ui-monospace, monospace; color: ${popupIp};">${node.asn || 'N/A'}</span></div>
            <div><strong style="color: ${popupMuted};">ISP / Provider:</strong> <span style="max-width: 170px; overflow: hidden; text-overflow: ellipsis; display: inline-block; vertical-align: bottom;">${node.organization || 'N/A'}</span></div>
            <div><strong style="color: ${popupMuted};">Threat Status:</strong> <span style="color: ${node.is_earliest ? '#e11d48' : node.is_proxy_vpn_tor ? '#f59e0b' : '#10b981'}; font-weight: 600;">${threatStatusLabel}</span></div>
            <div><strong style="color: ${popupMuted};">Campaign:</strong> ${campaignName}</div>
          </div>

          <div style="margin-top: 8px; padding-top: 6px; border-top: 1px solid ${popupSubBorder}; font-family: ui-monospace, monospace; font-size: 9px; color: ${popupMuted}; display: flex; justify-content: space-between;">
            <span>Estimated coords:</span>
            <span>${node.latitude.toFixed(4)}, ${node.longitude.toFixed(4)}</span>
          </div>
        </div>
      `;

      const marker = L.marker([node.latitude, node.longitude], { icon: customIcon }).addTo(map);
      marker.bindPopup(popupHtml, { className: 'theme-leaflet-popup' });

      marker.on('click', () => {
        setSelectedNodeId(node.id);
      });

      markersMapRef.current.set(node.id, marker);
    });

    if (filteredNodes.length === 1) {
      map.setView([filteredNodes[0].latitude, filteredNodes[0].longitude], 6);
    } else {
      map.fitBounds(bounds, { padding: [40, 40] });
    }
  }, [filteredNodes, showRoute, mapData, isDark, email]);

  return (
    <div className="space-y-4">
      {/* Header Controls Bar */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 p-5 rounded-card bg-surface border border-border shadow-sm">
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 rounded-control bg-primary/10 border border-primary/20 flex items-center justify-center text-primary">
            <Globe className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center space-x-2.5">
              <h2 className="text-base font-bold text-foreground">
                Investigation Infrastructure Map
              </h2>
              <span className="px-2 py-0.5 rounded-full text-xs font-mono font-bold bg-primary/10 text-primary border border-primary/20">
                {mapData.total_geolocated} of {mapData.total_public_ips} Public IPs Geolocated
              </span>
              <span className="px-2 py-0.5 rounded-full text-xs font-mono font-bold flex items-center space-x-1.5 border bg-success/10 text-success border-success/30">
                <span className="w-1.5 h-1.5 rounded-full bg-success" />
                <span>Provider: {providerStatus?.status === 'Configured' ? `${providerStatus.provider?.toUpperCase()} (Live)` : 'Active'}</span>
              </span>
            </div>
            <p className="text-xs text-foreground-muted font-mono">
              Observed infrastructure locations and network transmission topology
            </p>
          </div>
        </div>

        {/* Route Path Toggle and Reset Controls */}
        <div className="flex flex-wrap items-center gap-3">
          {mapData.route_path.length >= 2 && (
            <label className="flex items-center space-x-2 px-3 py-1.5 rounded-control bg-surface-secondary border border-border text-xs font-mono text-foreground cursor-pointer hover:border-primary/40 transition-colors select-none">
              <input
                type="checkbox"
                checked={showRoute}
                onChange={e => setShowRoute(e.target.checked)}
                className="w-3.5 h-3.5 rounded bg-surface border-border text-primary focus:ring-0 cursor-pointer"
              />
              <span className="flex items-center space-x-1.5">
                <span className="w-2 h-0.5 bg-primary inline-block" />
                <span>Observed infrastructure route</span>
              </span>
            </label>
          )}

          <button
            type="button"
            onClick={handleResetBounds}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-control bg-surface-secondary hover:bg-surface border border-border text-xs font-mono text-foreground transition-colors cursor-pointer"
          >
            <Maximize2 className="w-3.5 h-3.5 text-primary" />
            <span>Fit Bounds</span>
          </button>
        </div>
      </div>

      {/* Main Workspace: Left Map + Right Infrastructure Panel */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* MAP CONTAINER (Left 8 cols on lg) */}
        <div className="lg:col-span-8 bg-surface rounded-card border border-border overflow-hidden shadow-sm flex flex-col relative min-h-[540px]">
          <div className="relative w-full h-[540px]">
            <div ref={mapContainerRef} className="w-full h-full z-0" />

            {/* Map Overlay Badge */}
            {mapData.nodes.length > 0 ? (
              <div className="absolute top-3 left-12 z-10 bg-surface/95 border border-border px-3 py-1.5 rounded-control backdrop-blur-md shadow-md flex items-center space-x-3 text-xs font-mono">
                <div className="flex items-center space-x-1.5">
                  <span className="w-2.5 h-2.5 rounded-full bg-danger" />
                  <span className="text-[10px] text-foreground-muted">Probable Origin Node</span>
                </div>
                <div className="flex items-center space-x-1.5">
                  <span className="w-2.5 h-2.5 rounded-full bg-blue-500" />
                  <span className="text-[10px] text-foreground-muted">Relay Node</span>
                </div>
                <div className="flex items-center space-x-1.5">
                  <span className="w-2.5 h-2.5 rounded-full bg-primary" />
                  <span className="text-[10px] text-foreground-muted">Indicator IP</span>
                </div>
              </div>
            ) : (
              <div className="absolute top-4 left-1/2 -translate-x-1/2 z-10 bg-surface/95 border border-border px-4 py-2 rounded-control backdrop-blur-md shadow-lg flex items-center space-x-2 text-xs font-mono text-foreground-muted">
                <Globe className="w-4 h-4 text-primary shrink-0" />
                <span>No geolocated infrastructure available.</span>
              </div>
            )}
          </div>
        </div>

        {/* RIGHT INFRASTRUCTURE INSPECTOR PANEL (Right 4 cols on lg) */}
        <div className="lg:col-span-4 bg-surface rounded-card border border-border p-4 shadow-sm flex flex-col h-[540px] space-y-3.5">
          {/* Panel Header & Filter Buttons */}
          <div className="space-y-2.5">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono font-bold text-foreground uppercase tracking-wider flex items-center space-x-1.5">
                <Server className="w-3.5 h-3.5 text-primary" />
                <span>Observed Nodes</span>
              </span>
              <span className="text-[11px] font-mono text-foreground-muted">
                {filteredNodes.length} shown
              </span>
            </div>

            {/* Filter Pills */}
            <div className="flex rounded-control bg-surface-secondary p-1 border border-border text-[11px] font-mono">
              {[
                { id: 'all' as const, label: 'All' },
                { id: 'earliest' as const, label: 'Origin' },
                { id: 'relay' as const, label: 'Relays' },
                { id: 'indicator' as const, label: 'Indicators' }
              ].map(tab => (
                <button
                  key={tab.id}
                  type="button"
                  onClick={() => setActiveFilter(tab.id)}
                  className={`flex-1 py-1 rounded-control transition-all text-center cursor-pointer ${
                    activeFilter === tab.id
                      ? 'bg-surface text-primary font-bold border border-border shadow-xs'
                      : 'text-foreground-muted hover:text-foreground'
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>

            {/* Search Input */}
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-foreground-muted absolute left-3 top-2.5" />
              <input
                type="text"
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                placeholder="Filter by IP, country, or org..."
                className="w-full pl-8 pr-3 py-1.5 bg-surface-secondary border border-border rounded-control text-xs text-foreground placeholder:text-foreground-subtle font-mono focus:outline-none focus:border-primary"
              />
            </div>
          </div>

          {/* Node Cards Scrollable List */}
          <div className="flex-1 overflow-y-auto space-y-2.5 pr-1">
            {filteredNodes.length === 0 ? (
              <div className="py-12 text-center text-foreground-muted text-xs font-mono">
                No nodes match the selected criteria.
              </div>
            ) : (
              filteredNodes.map(node => {
                const isSelected = selectedNodeId === node.id;
                return (
                  <div
                    key={node.id}
                    onClick={() => handleSelectNode(node)}
                    className={`p-3 rounded-control border cursor-pointer transition-all space-y-2 ${
                      isSelected
                        ? 'bg-primary/10 border-primary shadow-xs'
                        : 'bg-surface-secondary/40 border-border hover:bg-surface-secondary/80'
                    }`}
                  >
                    {/* Node Card Header */}
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center space-x-1.5 min-w-0">
                        <span className="font-mono text-xs font-bold text-foreground truncate">
                          {node.ip}
                        </span>
                        <button
                          type="button"
                          onClick={e => handleCopy(node.ip, e)}
                          className="p-1 text-foreground-muted hover:text-foreground rounded cursor-pointer"
                          title="Copy IP"
                        >
                          {copiedIp === node.ip ? (
                            <Check className="w-3 h-3 text-success" />
                          ) : (
                            <Copy className="w-3 h-3" />
                          )}
                        </button>
                      </div>

                      <span className={`px-2 py-0.5 rounded-control text-[9px] font-mono font-bold uppercase tracking-wider shrink-0 ${
                        node.is_earliest
                          ? 'bg-danger-surface text-danger border border-danger-border'
                          : node.role === 'relay_node'
                          ? 'bg-blue-500/10 text-blue-500 border border-blue-500/20'
                          : 'bg-primary/10 text-primary border border-primary/20'
                      }`}>
                        {node.role_label}
                      </span>
                    </div>

                    {/* Geolocation Details */}
                    <div className="text-[11px] text-foreground-muted font-mono space-y-0.5">
                      <div className="flex items-center space-x-1 truncate">
                        <MapPin className="w-3 h-3 text-primary shrink-0" />
                        <span className="truncate">
                          {[node.city, node.country].filter(Boolean).join(', ') || 'Unknown Location'}
                        </span>
                      </div>
                      <div className="flex items-center justify-between text-[10px] text-foreground-subtle">
                        <span>{node.asn || 'ASN: N/A'}</span>
                        <span className="truncate max-w-[140px] text-right">{node.organization || 'N/A'}</span>
                      </div>
                    </div>

                    {/* Infrastructure Badges */}
                    {(node.is_hosting || node.is_proxy_vpn_tor) && (
                      <div className="flex items-center gap-1.5 pt-1">
                        {node.is_hosting && (
                          <span className="px-1.5 py-0.2 rounded-control text-[9px] font-mono bg-blue-500/10 text-blue-500 border border-blue-500/20 flex items-center space-x-1">
                            <Cloud className="w-2.5 h-2.5" />
                            <span>Hosting</span>
                          </span>
                        )}
                        {node.is_proxy_vpn_tor && (
                          <span className="px-1.5 py-0.2 rounded-control text-[9px] font-mono bg-danger-surface text-danger border border-danger-border flex items-center space-x-1">
                            <Lock className="w-2.5 h-2.5" />
                            <span>VPN/Tor</span>
                          </span>
                        )}
                      </div>
                    )}
                  </div>
                );
              })
            )}
          </div>
        </div>
      </div>

      {/* Forensic Accuracy & Geolocation Disclaimer Notice */}
      <div className="p-4 rounded-card bg-surface border border-border flex items-start gap-3 shadow-xs text-xs text-foreground-muted font-mono">
        <Info className="w-4 h-4 text-primary shrink-0 mt-0.5" />
        <div className="space-y-1">
          <div className="flex items-center space-x-2">
            <span className="font-bold text-foreground">
              Forensic Intelligence Notice — IP Geolocation Accuracy:
            </span>
          </div>
          <p className="text-[11px] leading-relaxed text-foreground-muted">
            <strong className="text-foreground font-semibold">
              IP geolocation represents the estimated location of observed network infrastructure and does not establish the physical location of the threat actor.
            </strong>{' '}
            Coordinates represent coarse regional estimates based on public network allocations and BGP routing nodes. Observed transmission routes sequence email relay hops exclusively as an <strong className="text-primary font-bold">observed infrastructure route</strong>.
          </p>
        </div>
      </div>
    </div>
  );
};
