"""
Investigation Relationship Graph Service (Section 13).
Builds a directed, deduplicated relationship graph connecting Email, Email Address,
Domain, URL, IP, ASN, Attachment, and Case entities.
"""
import re
import hashlib
import urllib.parse
from typing import Dict, Any, List, Optional, Set

from backend.schemas.graph import (
    NodeType,
    GraphNode,
    GraphEdge,
    GraphSummary,
    InvestigationGraphResponse
)


class InvestigationGraphService:
    """
    Constructs and manages the forensic investigation relationship graph.
    Guarantees entity deduplication, shared node merging, relationship integrity,
    and type-based filtering.
    """

    @staticmethod
    def _get(obj: Any, key: str, default: Any = None) -> Any:
        """Safely retrieves property from dictionary or object."""
        if obj is None:
            return default
        if isinstance(obj, dict):
            return obj.get(key, default)
        return getattr(obj, key, default)

    @staticmethod
    def _defang_url(url: str) -> str:
        """Safely defangs URLs for safe preview and labeling."""
        if not url:
            return ""
        defanged = url.replace("http://", "hxxp://").replace("https://", "hxxps://")
        defanged = defanged.replace(".", "[.]")
        return defanged

    def build_graph(
        self,
        email_analysis: Any,
        case_id: Optional[str] = None,
        max_nodes: int = 150
    ) -> InvestigationGraphResponse:
        """
        Extracts entities and constructs the investigation relationship graph.
        Handles empty or partial payloads gracefully.
        """
        if not email_analysis:
            return InvestigationGraphResponse(
                nodes=[],
                edges=[],
                summary=GraphSummary(total_nodes=0, total_edges=0, node_type_counts={})
            )

        # Storage with deduplication by canonical ID
        nodes: Dict[str, GraphNode] = {}
        edges: Dict[str, GraphEdge] = {}

        def add_node(node_id: str, node_type: NodeType, label: str, metadata: Optional[Dict[str, Any]] = None) -> str:
            if not node_id or not label:
                return ""
            meta = metadata or {}
            if node_id in nodes:
                # Merge metadata
                existing_meta = nodes[node_id].metadata
                for k, v in meta.items():
                    if v is not None and (k not in existing_meta or not existing_meta[k]):
                        existing_meta[k] = v
            else:
                nodes[node_id] = GraphNode(
                    id=node_id,
                    type=node_type,
                    label=label[:80],
                    metadata=meta
                )
            return node_id

        def add_edge(source: str, target: str, label: str, metadata: Optional[Dict[str, Any]] = None) -> Optional[str]:
            if not source or not target or source == target:
                return None
            if source not in nodes or target not in nodes:
                return None
            edge_id = f"edge:{source}->{label}->{target}"
            if edge_id not in edges:
                edges[edge_id] = GraphEdge(
                    id=edge_id,
                    source=source,
                    target=target,
                    label=label,
                    metadata=metadata or {}
                )
            return edge_id

        # -----------------------------------------------------------------
        # 1. EMAIL NODE (Root anchor)
        # -----------------------------------------------------------------
        email_sha = self._get(email_analysis, "email_sha256", "") or ""
        email_id_str = self._get(email_analysis, "id", "") or ""
        subject = self._get(email_analysis, "subject", "") or "Analyzed Email"
        date = self._get(email_analysis, "date", "")
        threat_score_obj = self._get(email_analysis, "threat_score", None)
        score_val = self._get(threat_score_obj, "score", 0) if threat_score_obj else 0
        severity_val = self._get(threat_score_obj, "severity", "low") if threat_score_obj else "low"
        ml_prob = self._get(email_analysis, "ml_phishing_probability", None)

        email_node_id = f"email:{email_id_str if email_id_str else (email_sha[:16] if email_sha else 'main')}"
        add_node(
            node_id=email_node_id,
            node_type=NodeType.EMAIL,
            label=f"Email: {subject[:45]}..." if len(subject) > 45 else f"Email: {subject}",
            metadata={
                "subject": subject,
                "email_sha256": email_sha,
                "date": date,
                "threat_score": score_val,
                "severity": severity_val,
                "ml_probability": ml_prob,
                "from": self._get(email_analysis, "from_header", ""),
                "to": self._get(email_analysis, "to", "")
            }
        )

        # -----------------------------------------------------------------
        # 2. EMAIL ADDRESS NODES & SENDER / RECIPIENT RELATIONSHIPS
        # -----------------------------------------------------------------
        def extract_clean_email(raw_val: Any) -> Optional[str]:
            if not raw_val:
                return None
            s = str(raw_val)
            match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', s)
            return match.group(0).lower().strip() if match else None

        # From
        from_raw = self._get(email_analysis, "from_header", None) or self._get(email_analysis, "from", None)
        from_clean = extract_clean_email(from_raw)
        if from_clean:
            from_node_id = f"email_addr:{from_clean}"
            add_node(
                node_id=from_node_id,
                node_type=NodeType.EMAIL_ADDRESS,
                label=from_clean,
                metadata={"role": "sender", "raw_header": from_raw}
            )
            add_edge(email_node_id, from_node_id, "SENT_FROM")

            # Domain from From address
            from_domain = from_clean.split("@")[-1].lower() if "@" in from_clean else ""
            if from_domain:
                dom_node_id = f"domain:{from_domain}"
                add_node(dom_node_id, NodeType.DOMAIN, from_domain, {"source": "sender_header"})
                add_edge(from_node_id, dom_node_id, "BELONGS_TO_DOMAIN")

        # To
        to_raw = self._get(email_analysis, "to", None)
        to_list = to_raw if isinstance(to_raw, list) else ([to_raw] if to_raw else [])
        for item in to_list:
            to_clean = extract_clean_email(item)
            if to_clean:
                to_node_id = f"email_addr:{to_clean}"
                add_node(
                    node_id=to_node_id,
                    node_type=NodeType.EMAIL_ADDRESS,
                    label=to_clean,
                    metadata={"role": "recipient", "raw_header": str(item)}
                )
                add_edge(email_node_id, to_node_id, "SENT_TO")

        # Reply-To
        reply_to_raw = self._get(email_analysis, "reply_to", None)
        reply_to_clean = extract_clean_email(reply_to_raw)
        if reply_to_clean:
            reply_node_id = f"email_addr:{reply_to_clean}"
            add_node(
                node_id=reply_node_id,
                node_type=NodeType.EMAIL_ADDRESS,
                label=reply_to_clean,
                metadata={"role": "reply_to", "raw_header": reply_to_raw}
            )
            add_edge(email_node_id, reply_node_id, "REPLY_TO")

        # -----------------------------------------------------------------
        # 3. DOMAIN INTELLIGENCE & LOOKALIKE NODES
        # -----------------------------------------------------------------
        domain_intel_map = self._get(email_analysis, "domain_intelligence", {}) or {}
        lookalikes = self._get(email_analysis, "lookalike_domains", []) or []

        # Index lookalikes by domain name
        lookalike_by_domain = {}
        for l in lookalikes:
            ldom = (self._get(l, "domain", "") or "").lower().rstrip(".")
            if ldom:
                lookalike_by_domain[ldom] = l

        # Process domain intelligence
        dns_ip_records: Dict[str, List[str]] = {}
        if isinstance(domain_intel_map, dict):
            for dom_name, dinfo in domain_intel_map.items():
                clean_dom = dom_name.strip().lower().rstrip(".")
                if not clean_dom:
                    continue
                dom_node_id = f"domain:{clean_dom}"
                d_lookalike = lookalike_by_domain.get(clean_dom) or self._get(dinfo, "lookalike", None)
                reg = self._get(dinfo, "registration", {}) or {}
                dns = self._get(dinfo, "dns", {}) or {}

                dom_meta = {
                    "domain": clean_dom,
                    "domain_age_days": self._get(dinfo, "domain_age_days", None),
                    "newly_registered": self._get(dinfo, "newly_registered_domain", False),
                    "registrar": self._get(reg, "registrar", None),
                    "status_message": self._get(dinfo, "status_message", ""),
                    "is_resolvable": self._get(dinfo, "is_resolvable", True)
                }
                if d_lookalike:
                    dom_meta["is_lookalike"] = True
                    dom_meta["suspected_brand"] = self._get(d_lookalike, "brand_name", self._get(d_lookalike, "suspected_brand", ""))
                    dom_meta["similarity"] = self._get(d_lookalike, "similarity", 0)
                    dom_meta["confidence_label"] = self._get(d_lookalike, "confidence_label", "")

                add_node(dom_node_id, NodeType.DOMAIN, clean_dom, dom_meta)

                # Collect DNS A/AAAA IPs for subsequent IP node creation
                a_records = self._get(dns, "a", []) or []
                aaaa_records = self._get(dns, "aaaa", []) or []
                dns_ip_records[clean_dom] = [ip for ip in (a_records + aaaa_records) if ip]

        # -----------------------------------------------------------------
        # 4. URL NODES & DOMAIN RESOLUTION RELATIONSHIPS
        # -----------------------------------------------------------------
        raw_urls = self._get(email_analysis, "urls", []) or []
        url_analysis_list = self._get(email_analysis, "url_analysis", []) or []

        # Merge URL items
        url_objects = {}
        for u in url_analysis_list:
            u_str = self._get(u, "url", "")
            if u_str:
                url_objects[u_str] = u
        for u_str in raw_urls:
            if isinstance(u_str, str) and u_str not in url_objects:
                url_objects[u_str] = {"url": u_str}

        for u_str, u_obj in list(url_objects.items())[:15]:
            clean_u = u_str.strip()
            if not clean_u:
                continue
            u_hash = hashlib.sha256(clean_u.encode()).hexdigest()[:10]
            url_node_id = f"url:{u_hash}"
            suspicion = self._get(u_obj, "suspicion_level", "low")
            reasons = self._get(u_obj, "score_reasons", [])

            # Extract domain from URL
            parsed_dom = ""
            try:
                parsed = urllib.parse.urlparse(clean_u)
                parsed_dom = (parsed.hostname or "").lower().rstrip(".")
            except Exception:
                pass

            display_url = self._defang_url(clean_u)
            if len(display_url) > 40:
                display_url = display_url[:37] + "..."

            add_node(
                node_id=url_node_id,
                node_type=NodeType.URL,
                label=f"URL: {display_url}",
                metadata={
                    "url": clean_u,
                    "defanged_url": self._defang_url(clean_u),
                    "domain": parsed_dom,
                    "suspicion_level": suspicion,
                    "score_reasons": reasons
                }
            )
            add_edge(email_node_id, url_node_id, "CONTAINS_URL")

            # Link URL to Domain node
            if parsed_dom:
                dom_node_id = f"domain:{parsed_dom}"
                add_node(dom_node_id, NodeType.DOMAIN, parsed_dom, {"domain": parsed_dom})
                add_edge(url_node_id, dom_node_id, "RESOLVES_TO_DOMAIN")

        # -----------------------------------------------------------------
        # 5. IP INTELLIGENCE, ASNs, & DOMAIN DNS RESOLUTION
        # -----------------------------------------------------------------
        ip_intel_map = self._get(email_analysis, "ip_intelligence", {}) or {}
        processed_ips: Set[str] = set()

        # Connect Domain -> IP from DNS records
        for dom, ip_list in dns_ip_records.items():
            dom_node_id = f"domain:{dom}"
            for ip_addr in ip_list[:3]:  # Limit IPs per domain
                clean_ip = ip_addr.strip()
                if not clean_ip:
                    continue
                ip_node_id = f"ip:{clean_ip}"
                ip_meta = ip_intel_map.get(clean_ip, {}) if isinstance(ip_intel_map, dict) else {}
                add_node(
                    node_id=ip_node_id,
                    node_type=NodeType.IP,
                    label=clean_ip,
                    metadata={
                        "ip": clean_ip,
                        "country": self._get(ip_meta, "country", "Unknown"),
                        "asn": self._get(ip_meta, "asn", "Unknown"),
                        "org": self._get(ip_meta, "org", "Unknown"),
                        "scope": self._get(ip_meta, "scope", "public"),
                        "is_proxy_vpn_tor": self._get(ip_meta, "is_proxy_vpn_tor", False)
                    }
                )
                add_edge(dom_node_id, ip_node_id, "RESOLVES_TO_IP")
                processed_ips.add(clean_ip)

        # Process all other enriched IPs
        if isinstance(ip_intel_map, dict):
            for ip_addr, ip_data in list(ip_intel_map.items())[:12]:
                clean_ip = ip_addr.strip()
                if not clean_ip:
                    continue
                ip_node_id = f"ip:{clean_ip}"
                add_node(
                    node_id=ip_node_id,
                    node_type=NodeType.IP,
                    label=clean_ip,
                    metadata={
                        "ip": clean_ip,
                        "country": self._get(ip_data, "country", "Unknown"),
                        "asn": self._get(ip_data, "asn", "Unknown"),
                        "org": self._get(ip_data, "org", "Unknown"),
                        "scope": self._get(ip_data, "scope", "public"),
                        "is_proxy_vpn_tor": self._get(ip_data, "is_proxy_vpn_tor", False)
                    }
                )
                processed_ips.add(clean_ip)

        # Connect Email -> IP for relay hops / earliest observable node
        relay_analysis = self._get(email_analysis, "relay_analysis", None)
        earliest_node = self._get(relay_analysis, "earliest_observable_node", None) if relay_analysis else None
        earliest_ip = self._get(earliest_node, "earliest_observable_ip", None) if earliest_node else None
        if earliest_ip and f"ip:{earliest_ip}" in nodes:
            add_edge(email_node_id, f"ip:{earliest_ip}", "ROUTED_THROUGH", {"hop_role": "earliest_observable_sender"})

        # Attribution Integration: Email -> Probable Origin IP
        attribution = self._get(email_analysis, "attribution", None)
        origin_ip = self._get(attribution, "probable_origin_ip", None) if attribution else earliest_ip
        if origin_ip:
            origin_ip_clean = origin_ip.strip()
            origin_node_id = f"ip:{origin_ip_clean}"
            if origin_node_id not in nodes:
                add_node(origin_node_id, NodeType.IP, origin_ip_clean, {
                    "ip": origin_ip_clean,
                    "role": "probable_origin_infrastructure"
                })
            add_edge(email_node_id, origin_node_id, "ORIGIN_INFRASTRUCTURE", {
                "confidence": self._get(attribution, "confidence_score", None) if attribution else None,
                "role": "probable_origin_infrastructure"
            })

        # Link IPs to ASN nodes and Country nodes
        for ip_id, node in list(nodes.items()):
            if node.type == NodeType.IP:
                asn_val = node.metadata.get("asn")
                if asn_val and str(asn_val).strip().upper() not in ("UNKNOWN", "NONE", ""):
                    asn_clean = str(asn_val).strip().upper()
                    if not asn_clean.startswith("AS"):
                        asn_clean = f"AS{asn_clean}"
                    asn_org = node.metadata.get("org", "Autonomous System")
                    asn_node_id = f"asn:{asn_clean}"
                    add_node(
                        node_id=asn_node_id,
                        node_type=NodeType.ASN,
                        label=f"{asn_clean} ({asn_org[:20]})" if asn_org else asn_clean,
                        metadata={"asn": asn_clean, "org": asn_org, "country": node.metadata.get("country")}
                    )
                    add_edge(ip_id, asn_node_id, "BELONGS_TO_ASN")

                # Link IP -> Country node
                country_val = node.metadata.get("country")
                if country_val and str(country_val).strip().upper() not in ("UNKNOWN", "NONE", ""):
                    country_clean = str(country_val).strip()
                    country_slug = re.sub(r'[^a-zA-Z0-9]+', '_', country_clean.lower()).strip('_')
                    country_node_id = f"country:{country_slug}"
                    add_node(
                        node_id=country_node_id,
                        node_type=NodeType.COUNTRY,
                        label=country_clean,
                        metadata={
                            "country": country_clean,
                            "disclaimer": "Location refers to observed network infrastructure and should not be interpreted as the physical location of the threat actor."
                        }
                    )
                    add_edge(ip_id, country_node_id, "HOSTED_IN_COUNTRY")

        # -----------------------------------------------------------------
        # 6. ATTACHMENT NODES & FORENSIC LINKAGES
        # -----------------------------------------------------------------
        attachments = self._get(email_analysis, "attachments", []) or []
        created_att_node_ids: List[str] = []
        for att in attachments:
            fname = self._get(att, "filename", "unnamed_attachment") or "unnamed_attachment"
            sha = self._get(att, "sha256", "") or ""
            att_node_id = f"attachment:{sha[:16] if sha else fname}"
            mime = self._get(att, "mime_type", "application/octet-stream")
            size = self._get(att, "size", 0)
            static_res = self._get(att, "static_analysis", None)

            # Flag dangerous extensions
            is_suspicious_ext = any(fname.lower().endswith(ext) for ext in [
                ".exe", ".scr", ".bat", ".vbs", ".js", ".ps1", ".jar", ".iso", ".docm", ".xlsm"
            ])

            add_node(
                node_id=att_node_id,
                node_type=NodeType.ATTACHMENT,
                label=fname,
                metadata={
                    "filename": fname,
                    "mime_type": mime,
                    "size_bytes": size,
                    "sha256": sha,
                    "is_dangerous_extension": is_suspicious_ext,
                    "threat_level": self._get(static_res, "threat_level", "UNKNOWN") if static_res else "UNKNOWN"
                }
            )
            add_edge(email_node_id, att_node_id, "HAS_ATTACHMENT")
            created_att_node_ids.append(att_node_id)

            # Graph Linkage: Attachment -> Hash
            if sha:
                hash_node_id = f"hash:{sha[:16]}"
                add_node(
                    node_id=hash_node_id,
                    node_type=NodeType.HASH,
                    label=f"SHA-256: {sha[:8]}...",
                    metadata={
                        "sha256": sha,
                        "algorithm": "SHA-256",
                        "attachment": fname
                    }
                )
                add_edge(att_node_id, hash_node_id, "HAS_HASH")

            # Graph Linkage: Attachment -> URL & Attachment -> Domain
            if static_res:
                emb_urls = self._get(static_res, "embedded_urls", []) or []
                for u in emb_urls:
                    u_slug = re.sub(r'[^a-zA-Z0-9]+', '_', u.lower()).strip('_')[:40]
                    u_node_id = f"url:{u_slug}"
                    add_node(
                        node_id=u_node_id,
                        node_type=NodeType.URL,
                        label=u[:40] + ("..." if len(u) > 40 else ""),
                        metadata={"url": u, "source": f"attachment:{fname}"}
                    )
                    add_edge(att_node_id, u_node_id, "CONTAINS_URL")

                emb_domains = self._get(static_res, "embedded_domains", []) or []
                for d in emb_domains:
                    d_node_id = f"domain:{d.lower()}"
                    add_node(
                        node_id=d_node_id,
                        node_type=NodeType.DOMAIN,
                        label=d,
                        metadata={"domain": d, "source": f"attachment:{fname}"}
                    )
                    add_edge(att_node_id, d_node_id, "CONTAINS_DOMAIN")

        # -----------------------------------------------------------------
        # 7. CASE & CAMPAIGN NODES (Attribution & Infrastructure Linkage)
        # -----------------------------------------------------------------
        if case_id:
            case_node_id = f"case:{case_id}"
            add_node(
                node_id=case_node_id,
                node_type=NodeType.CASE,
                label=f"Case: {case_id}",
                metadata={"case_id": case_id}
            )
            add_edge(email_node_id, case_node_id, "ASSOCIATED_WITH_CASE")

        # Campaign -> Infrastructure Linkage
        camp_list: List[str] = []
        if attribution:
            cid = self._get(attribution, "campaign_id", None)
            if cid:
                camp_list.append(str(cid))
            for rc in (self._get(attribution, "related_campaigns", []) or []):
                if rc and str(rc) not in camp_list:
                    camp_list.append(str(rc))

        for camp in camp_list:
            camp_clean = camp.strip()
            camp_slug = re.sub(r'[^a-zA-Z0-9]+', '_', camp_clean.lower()).strip('_')
            camp_node_id = f"campaign:{camp_slug}"
            add_node(
                node_id=camp_node_id,
                node_type=NodeType.CAMPAIGN,
                label=f"Campaign: {camp_clean}",
                metadata={"campaign_id": camp_clean}
            )
            add_edge(email_node_id, camp_node_id, "ASSOCIATED_WITH_CAMPAIGN")

            # Graph Linkage: Attachment -> Campaign
            for a_id in created_att_node_ids:
                add_edge(a_id, camp_node_id, "LINKED_TO_CAMPAIGN")

            if origin_ip and f"ip:{origin_ip}" in nodes:
                add_edge(camp_node_id, f"ip:{origin_ip}", "UTILIZES_INFRASTRUCTURE")
            origin_asn = self._get(attribution, "probable_origin_asn", None) if attribution else None
            if origin_asn:
                clean_asn_tag = origin_asn.upper() if origin_asn.upper().startswith("AS") else f"AS{origin_asn.upper()}"
                if f"asn:{clean_asn_tag}" in nodes:
                    add_edge(camp_node_id, f"asn:{clean_asn_tag}", "UTILIZES_INFRASTRUCTURE")

        # -----------------------------------------------------------------
        # 8. OVERLOAD PREVENTION / NODE CAPPING
        # -----------------------------------------------------------------
        final_nodes = list(nodes.values())
        if len(final_nodes) > max_nodes:
            # Sort to preserve high-priority nodes first
            priority_order = {
                NodeType.EMAIL: 0,
                NodeType.ATTACHMENT: 1,
                NodeType.URL: 2,
                NodeType.DOMAIN: 3,
                NodeType.IP: 4,
                NodeType.ASN: 5,
                NodeType.EMAIL_ADDRESS: 6,
                NodeType.CASE: 7,
                NodeType.CAMPAIGN: 8,
                NodeType.COUNTRY: 9,
                NodeType.HASH: 10
            }
            final_nodes.sort(key=lambda n: priority_order.get(n.type, 10))
            final_nodes = final_nodes[:max_nodes]
            allowed_ids = {n.id for n in final_nodes}
            final_edges = [e for e in edges.values() if e.source in allowed_ids and e.target in allowed_ids]
        else:
            final_edges = list(edges.values())

        # -----------------------------------------------------------------
        # 9. SUMMARY COMPUTATION
        # -----------------------------------------------------------------
        counts: Dict[str, int] = {}
        for n in final_nodes:
            counts[n.type.value] = counts.get(n.type.value, 0) + 1

        has_high_risk = score_val >= 70 or any(
            n.metadata.get("is_lookalike") or n.metadata.get("suspicion_level") == "high" or n.metadata.get("is_dangerous_extension")
            for n in final_nodes
        )

        return InvestigationGraphResponse(
            nodes=final_nodes,
            edges=final_edges,
            summary=GraphSummary(
                total_nodes=len(final_nodes),
                total_edges=len(final_edges),
                node_type_counts=counts,
                has_high_risk_entities=has_high_risk
            )
        )

    def filter_graph(
        self,
        graph: InvestigationGraphResponse,
        allowed_types: Optional[List[NodeType]] = None
    ) -> InvestigationGraphResponse:
        """
        Filters a graph by retaining only nodes matching allowed_types,
        and cleanly cascades removal of edges whose source or target is pruned.
        """
        if not graph or not graph.nodes:
            return InvestigationGraphResponse(
                nodes=[],
                edges=[],
                summary=GraphSummary(total_nodes=0, total_edges=0, node_type_counts={})
            )

        if not allowed_types:
            return graph

        allowed_type_values = {t.value if isinstance(t, NodeType) else str(t) for t in allowed_types}
        filtered_nodes = [n for n in graph.nodes if n.type.value in allowed_type_values]
        allowed_ids = {n.id for n in filtered_nodes}
        filtered_edges = [e for e in graph.edges if e.source in allowed_ids and e.target in allowed_ids]

        counts: Dict[str, int] = {}
        for n in filtered_nodes:
            counts[n.type.value] = counts.get(n.type.value, 0) + 1

        return InvestigationGraphResponse(
            nodes=filtered_nodes,
            edges=filtered_edges,
            summary=GraphSummary(
                total_nodes=len(filtered_nodes),
                total_edges=len(filtered_edges),
                node_type_counts=counts,
                has_high_risk_entities=graph.summary.has_high_risk_entities
            )
        )

    def build_campaign_graph(
        self,
        campaign: Dict[str, Any],
        max_nodes: int = 150
    ) -> InvestigationGraphResponse:
        """
        Builds a dedicated relationship graph for a Campaign cluster where the Campaign
        is a first-class central node connecting to Emails, Domains, IPs, URLs, and Recipients.
        """
        if not campaign:
            return InvestigationGraphResponse(
                nodes=[],
                edges=[],
                summary=GraphSummary(total_nodes=0, total_edges=0, node_type_counts={})
            )

        nodes: Dict[str, GraphNode] = {}
        edges: Dict[str, GraphEdge] = {}

        def add_node(node_id: str, node_type: NodeType, label: str, metadata: Optional[Dict[str, Any]] = None) -> str:
            if not node_id or not label:
                return ""
            meta = metadata or {}
            if node_id not in nodes:
                nodes[node_id] = GraphNode(
                    id=node_id,
                    type=node_type,
                    label=label[:80],
                    metadata=meta
                )
            else:
                nodes[node_id].metadata.update(meta)
            return node_id

        def add_edge(source: str, target: str, label: str, metadata: Optional[Dict[str, Any]] = None) -> Optional[str]:
            if not source or not target or source == target:
                return None
            if source not in nodes or target not in nodes:
                return None
            edge_id = f"edge:{source}->{label}->{target}"
            if edge_id not in edges:
                edges[edge_id] = GraphEdge(
                    id=edge_id,
                    source=source,
                    target=target,
                    label=label,
                    metadata=metadata or {}
                )
            return edge_id

        # 1. CAMPAIGN NODE (Central Hub)
        camp_id = str(campaign.get("campaign_id") or campaign.get("id") or "CAMP-001")
        camp_name = str(campaign.get("name") or f"Campaign {camp_id}")
        camp_node_id = f"campaign:{camp_id}"

        add_node(
            node_id=camp_node_id,
            node_type=NodeType.CAMPAIGN,
            label=f"Campaign: {camp_name[:40]}",
            metadata={
                "campaign_id": camp_id,
                "name": camp_name,
                "overall_confidence": campaign.get("overall_confidence", 0),
                "dominant_attack_type": campaign.get("dominant_attack_type", "Phishing"),
                "email_count": campaign.get("email_count", 0),
                "first_seen": campaign.get("first_seen", ""),
                "last_seen": campaign.get("last_seen", "")
            }
        )

        fp = campaign.get("fingerprint") or {}
        if hasattr(fp, "model_dump"):
            fp = fp.model_dump()

        # 2. CAMPAIGN -> EMAIL NODES
        emails = campaign.get("emails") or []
        for em in emails[:20]:
            e_id = str(em.get("id") or em.get("email_id") or em.get("email_sha256") or "eml")
            e_sub = str(em.get("subject") or "Campaign Email")
            e_node_id = f"email:{e_id[:16]}"
            add_node(
                node_id=e_node_id,
                node_type=NodeType.EMAIL,
                label=f"Email: {e_sub[:35]}...",
                metadata={"subject": e_sub, "email_id": e_id, "from": em.get("from") or em.get("sender")}
            )
            add_edge(camp_node_id, e_node_id, "INCLUDES_EMAIL")

        # 3. CAMPAIGN -> DOMAIN NODES
        domains = set()
        for d in campaign.get("domains") or []:
            domains.add(str(d).lower().strip())
        dom_summary = campaign.get("domain_summary") or {}
        for d in dom_summary.get("linked_domains") or []:
            domains.add(str(d).lower().strip())
        if dom_summary.get("sender_domain"):
            domains.add(str(dom_summary["sender_domain"]).lower().strip())
        if dom_summary.get("reply_to_domain"):
            domains.add(str(dom_summary["reply_to_domain"]).lower().strip())

        for d in list(domains)[:15]:
            if d:
                dom_node_id = f"domain:{d}"
                add_node(dom_node_id, NodeType.DOMAIN, d, {"domain": d})
                add_edge(camp_node_id, dom_node_id, "UTILIZES_DOMAIN")

        # 4. CAMPAIGN -> IP NODES
        ips = set()
        for ip in campaign.get("ips") or []:
            ips.add(str(ip).strip())
        infra_summary = campaign.get("infrastructure_summary") or {}
        if infra_summary.get("origin_ip"):
            ips.add(str(infra_summary["origin_ip"]).strip())
        for r_ip in infra_summary.get("relay_ips") or []:
            ips.add(str(r_ip).strip())

        for ip in list(ips)[:12]:
            if ip:
                ip_node_id = f"ip:{ip}"
                add_node(ip_node_id, NodeType.IP, ip, {"ip": ip})
                add_edge(camp_node_id, ip_node_id, "HOSTED_ON_IP")

        # 5. CAMPAIGN -> URL NODES
        urls = set()
        for u in campaign.get("urls") or []:
            u_val = u.get("url") if isinstance(u, dict) else str(u)
            urls.add(u_val.strip())
        url_summary = campaign.get("url_summary") or {}
        for u in url_summary.get("normalized_urls") or []:
            urls.add(str(u).strip())

        for u_str in list(urls)[:12]:
            if u_str:
                u_hash = hashlib.sha256(u_str.encode()).hexdigest()[:10]
                url_node_id = f"url:{u_hash}"
                display_u = self._defang_url(u_str)
                add_node(
                    node_id=url_node_id,
                    node_type=NodeType.URL,
                    label=f"URL: {display_u[:32]}...",
                    metadata={"url": u_str, "defanged_url": display_u}
                )
                add_edge(camp_node_id, url_node_id, "DEPLOYS_URL")

                # Cross edge: URL -> Domain
                try:
                    parsed = urllib.parse.urlparse(u_str)
                    host = (parsed.hostname or "").lower().rstrip(".")
                    if host and f"domain:{host}" in nodes:
                        add_edge(url_node_id, f"domain:{host}", "RESOLVES_TO_DOMAIN")
                except Exception:
                    pass

        # 6. CAMPAIGN -> RECIPIENT NODES
        recipients = set()
        rcpt_summary = campaign.get("recipient_summary") or {}
        for r in rcpt_summary.get("recipients") or []:
            recipients.add(str(r).lower().strip())
        for em in emails:
            rc = em.get("to") or em.get("recipient")
            if rc:
                recipients.add(str(rc).lower().strip())

        for rcpt in list(recipients)[:15]:
            if "@" in rcpt:
                rcpt_node_id = f"email_addr:{rcpt}"
                add_node(
                    node_id=rcpt_node_id,
                    node_type=NodeType.EMAIL_ADDRESS,
                    label=rcpt,
                    metadata={"role": "victim_recipient", "email": rcpt}
                )
                add_edge(camp_node_id, rcpt_node_id, "TARGETS_RECIPIENT")

        # 7. CAPPING AND SUMMARY
        final_nodes = list(nodes.values())[:max_nodes]
        allowed_ids = {n.id for n in final_nodes}
        final_edges = [e for e in edges.values() if e.source in allowed_ids and e.target in allowed_ids]

        counts: Dict[str, int] = {}
        for n in final_nodes:
            counts[n.type.value] = counts.get(n.type.value, 0) + 1

        return InvestigationGraphResponse(
            nodes=final_nodes,
            edges=final_edges,
            summary=GraphSummary(
                total_nodes=len(final_nodes),
                total_edges=len(final_edges),
                node_type_counts=counts,
                has_high_risk_entities=True
            )
        )


global_graph_service = InvestigationGraphService()

