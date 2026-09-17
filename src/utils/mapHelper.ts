import type { EmailAnalysis, IPIntelligence } from '../types/forensic';
import type { InfrastructureMapNode, InfrastructureRole, InvestigationMapData } from '../types/map';
import { resolveIPIntelligence } from './indicatorHelper';

/**
 * Checks whether an IP address is public or internal/reserved.
 */
export const isPublicIP = (ip: string): boolean => {
  if (!ip || typeof ip !== 'string') return false;
  const clean = ip.trim();

  // IPv4 basic checks
  if (clean === '127.0.0.1' || clean === '0.0.0.0' || clean.startsWith('10.')) return false;
  if (clean.startsWith('192.168.')) return false;
  if (clean.startsWith('169.254.')) return false; // Link-local
  if (clean.startsWith('127.')) return false;

  // 172.16.0.0 - 172.31.255.255
  if (clean.startsWith('172.')) {
    const parts = clean.split('.');
    if (parts.length >= 2) {
      const secondOctet = parseInt(parts[1], 10);
      if (secondOctet >= 16 && secondOctet <= 31) return false;
    }
  }

  // 100.64.0.0/10 (Carrier grade NAT)
  if (clean.startsWith('100.')) {
    const parts = clean.split('.');
    if (parts.length >= 2) {
      const secondOctet = parseInt(parts[1], 10);
      if (secondOctet >= 64 && secondOctet <= 127) return false;
    }
  }

  // IPv6 loopback / unique local
  if (clean === '::1' || clean.toLowerCase().startsWith('fc') || clean.toLowerCase().startsWith('fd') || clean.toLowerCase().startsWith('fe80')) {
    return false;
  }

  return true;
};

/**
 * Applies a deterministic circular offset if multiple distinct IPs share identical coordinates.
 */
export const deconflictCoordinates = (nodes: InfrastructureMapNode[]): InfrastructureMapNode[] => {
  const coordGroups: Record<string, InfrastructureMapNode[]> = {};

  nodes.forEach(node => {
    const key = `${node.latitude.toFixed(4)},${node.longitude.toFixed(4)}`;
    if (!coordGroups[key]) coordGroups[key] = [];
    coordGroups[key].push(node);
  });

  const result: InfrastructureMapNode[] = [];

  Object.values(coordGroups).forEach(group => {
    if (group.length === 1) {
      result.push(group[0]);
    } else {
      group.forEach((node, idx) => {
        if (idx === 0) {
          result.push(node);
        } else {
          // Golden ratio spiral offset (~0.008 degrees)
          const angle = idx * 2.39996;
          const radius = 0.006 * Math.sqrt(idx);
          result.push({
            ...node,
            latitude: Number((node.latitude + radius * Math.cos(angle)).toFixed(6)),
            longitude: Number((node.longitude + radius * Math.sin(angle)).toFixed(6))
          });
        }
      });
    }
  });

  return result;
};

/**
 * Extracts all observed infrastructure nodes, route paths, and metadata from an EmailAnalysis.
 */
export const extractInfrastructureMapData = (email: EmailAnalysis): InvestigationMapData => {
  const ipIntelMap: Record<string, IPIntelligence> = email.ip_intelligence || {};
  const earliestIp = email.relay_analysis?.earliest_observable_node?.earliest_observable_ip;

  // Track transmission order from relay hops
  // Prefer transmission_order_hops (chronological order: sender -> recipient)
  const relayHops = email.relay_analysis?.transmission_order_hops || email.relay_analysis?.header_order_hops || [];
  const relayIpOrderMap = new Map<string, number>(); // ip -> transmission sequence
  const relayHopNumberMap = new Map<string, number>(); // ip -> hop number

  relayHops.forEach((hop, idx) => {
    const fromIp = hop.from_ip?.trim();
    if (fromIp && isPublicIP(fromIp) && !relayIpOrderMap.has(fromIp)) {
      relayIpOrderMap.set(fromIp, idx + 1);
      relayHopNumberMap.set(fromIp, hop.hop_number);
    }
    const byIp = hop.by_ip?.trim();
    if (byIp && isPublicIP(byIp) && !relayIpOrderMap.has(byIp)) {
      relayIpOrderMap.set(byIp, idx + 1.5);
      relayHopNumberMap.set(byIp, hop.hop_number);
    }
  });

  // Collect all unique public IPs across relays, indicators, and DNS
  const candidateIps = new Set<string>();

  if (earliestIp && isPublicIP(earliestIp)) candidateIps.add(earliestIp);
  relayIpOrderMap.forEach((_, ip) => candidateIps.add(ip));

  (email.indicators?.ips || []).forEach(i => {
    const val = typeof i === 'string' ? i : i.value;
    if (val && isPublicIP(val)) candidateIps.add(val.trim());
  });

  (email.ips || []).forEach(ip => {
    if (ip && isPublicIP(ip)) candidateIps.add(ip.trim());
  });

  // Also include IP addresses from domain intelligence DNS records if present
  if (email.domain_intelligence) {
    Object.values(email.domain_intelligence).forEach(domIntel => {
      (domIntel.dns?.a || []).forEach(dnsIp => {
        if (dnsIp && isPublicIP(dnsIp)) candidateIps.add(dnsIp.trim());
      });
    });
  }

  const rawNodes: InfrastructureMapNode[] = [];
  let earliestNode: InfrastructureMapNode | undefined;

  candidateIps.forEach(ip => {
    let intel = ipIntelMap[ip];
    if (!intel || typeof intel.latitude !== 'number' || typeof intel.longitude !== 'number') {
      intel = resolveIPIntelligence(ip, ipIntelMap);
    }
    if (intel && typeof intel.latitude === 'number' && typeof intel.longitude === 'number') {
      const isEarliest = ip === earliestIp;
      const isRelay = relayIpOrderMap.has(ip);

      let role: InfrastructureRole = 'indicator_ip';
      let roleLabel = 'Observed Indicator IP';

      if (isEarliest) {
        role = 'earliest_node';
        roleLabel = 'Earliest Observable Node';
      } else if (isRelay) {
        role = 'relay_node';
        const hopNum = relayHopNumberMap.get(ip);
        roleLabel = hopNum !== undefined ? `Relay Hop #${hopNum}` : 'Relay Infrastructure Node';
      }

      const node: InfrastructureMapNode = {
        id: `node-${ip}`,
        ip,
        role,
        role_label: roleLabel,
        latitude: intel.latitude,
        longitude: intel.longitude,
        city: intel.city || undefined,
        region: intel.region || undefined,
        country: intel.country || undefined,
        country_code: intel.country_code || undefined,
        asn: intel.asn || undefined,
        asn_org: intel.asn_org || undefined,
        organization: intel.organization || intel.isp || intel.asn_org || undefined,
        is_earliest: isEarliest,
        hop_number: relayHopNumberMap.get(ip),
        transmission_order: relayIpOrderMap.get(ip),
        infrastructure_type: intel.infrastructure_type,
        is_hosting: intel.is_hosting,
        is_proxy_vpn_tor: intel.is_proxy_vpn_tor
      };

      rawNodes.push(node);
      if (isEarliest) {
        earliestNode = node;
      }
    }
  });

  // Apply deconfliction so nodes at identical coordinates don't completely overlap
  const deconflictedNodes = deconflictCoordinates(rawNodes);

  // Build sequential route polyline coordinates for geolocated relay nodes
  const geolocatedRelayNodes = deconflictedNodes
    .filter(n => n.transmission_order !== undefined)
    .sort((a, b) => (a.transmission_order || 0) - (b.transmission_order || 0));

  const routePath: [number, number][] = geolocatedRelayNodes.map(n => [n.latitude, n.longitude]);

  return {
    nodes: deconflictedNodes,
    route_path: routePath.length >= 2 ? routePath : [],
    earliest_node: earliestNode,
    total_public_ips: candidateIps.size,
    total_geolocated: deconflictedNodes.length
  };
};
