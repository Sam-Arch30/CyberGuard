"""
Security Knowledge Graph Service (Section 14).
Provides central query, traversal, canonical entity management, relationship persistence,
multi-observation tracking, bounded path discovery, and edge evidence explanation.
"""
from datetime import datetime, timezone
import json
import logging
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from collections import deque

from sqlalchemy.orm import Session
from sqlalchemy import or_, and_, desc

from backend.db.models import (
    EntityModel,
    RelationshipModel,
    RelationshipObservationModel,
    ArtifactModel,
    AnalysisRunModel,
    FindingEvidenceModel,
    FindingModel,
    ThreatEventModel,
    IncidentModel,
    generate_uuid,
    get_utc_now,
)
from backend.schemas.knowledge_graph import (
    GraphEntityType,
    GraphRelationshipType,
    RelationshipOrigin,
    RelationshipStatus,
    GraphNode,
    GraphEdge,
    RelationshipObservationResponse,
    EdgeEvidenceResponse,
    GraphSubgraphResponse,
    GraphPathResponse,
    TimelineEventItem,
    EntityTimelineResponse,
    EntitySearchResponse,
    make_canonical_key,
    sanitize_graph_attributes,
)
from backend.schemas.unified import normalize_confidence

logger = logging.getLogger("cyberguard.graph_service")


class SecurityGraphService:
    """
    Core service powering CyberGuard's Security Knowledge Graph.
    Enforces deterministic identity, observation provenance, traversal boundaries,
    and tenant/workspace isolation.
    """

    # Traversal Safety Guards
    MAX_DEPTH_LIMIT = 5
    MAX_NODES_LIMIT = 500
    MAX_EDGES_LIMIT = 1000

    @staticmethod
    def _safe_min_dt(dt1: Optional[datetime], dt2: Optional[datetime]) -> Optional[datetime]:
        if dt1 is None:
            return dt2
        if dt2 is None:
            return dt1
        n1 = dt1.replace(tzinfo=timezone.utc) if dt1.tzinfo is None else dt1
        n2 = dt2.replace(tzinfo=timezone.utc) if dt2.tzinfo is None else dt2
        return dt1 if n1 <= n2 else dt2

    @staticmethod
    def _safe_max_dt(dt1: Optional[datetime], dt2: Optional[datetime]) -> Optional[datetime]:
        if dt1 is None:
            return dt2
        if dt2 is None:
            return dt1
        n1 = dt1.replace(tzinfo=timezone.utc) if dt1.tzinfo is None else dt1
        n2 = dt2.replace(tzinfo=timezone.utc) if dt2.tzinfo is None else dt2
        return dt1 if n1 >= n2 else dt2

    @classmethod
    def _entity_to_graph_node(cls, entity: EntityModel) -> GraphNode:
        attrs = {}
        if entity.attributes_json:
            try:
                attrs = json.loads(entity.attributes_json)
            except Exception:
                attrs = {}
        return GraphNode(
            id=entity.id,
            type=entity.entity_type,
            canonical_key=entity.canonical_key or entity.name,
            display_value=entity.name,
            first_seen=entity.first_seen,
            last_seen=entity.last_seen,
            attributes=sanitize_graph_attributes(attrs),
            workspace_id=getattr(entity, "workspace_id", None),
        )

    @classmethod
    def _rel_to_graph_edge(cls, rel: RelationshipModel, obs_count: int = 1) -> GraphEdge:
        attrs = {}
        if rel.metadata_json:
            try:
                attrs = json.loads(rel.metadata_json)
            except Exception:
                attrs = {}
        return GraphEdge(
            id=rel.id,
            source=rel.source_id,
            target=rel.target_id,
            type=rel.relationship_type,
            origin=getattr(rel, "origin", RelationshipOrigin.OBSERVED),
            status=getattr(rel, "status", RelationshipStatus.ACTIVE),
            confidence=rel.confidence,
            first_seen=rel.first_seen,
            last_seen=rel.last_seen,
            observation_count=obs_count,
            attributes=sanitize_graph_attributes(attrs),
            evidence_reference=rel.evidence_reference,
            workspace_id=getattr(rel, "workspace_id", None),
        )

    # =========================================================================
    # 1. CANONICAL ENTITY MANAGEMENT
    # =========================================================================

    def upsert_canonical_entity(
        self,
        db: Session,
        entity_type: Union[GraphEntityType, str],
        value: str,
        context: Optional[str] = None,
        display_value: Optional[str] = None,
        attributes: Optional[Dict[str, Any]] = None,
        timestamp: Optional[datetime] = None,
        workspace_id: Optional[str] = None,
    ) -> EntityModel:
        """
        Creates or updates a canonical entity.
        Deduplication is based on (entity_type, canonical_key, workspace_id).
        """
        type_str = (
            entity_type.value if isinstance(entity_type, GraphEntityType) else str(entity_type)
        ).upper()
        canon_key = make_canonical_key(type_str, value, context=context)
        disp_name = (display_value or value or canon_key).strip()
        now = timestamp or get_utc_now()
        clean_attrs = sanitize_graph_attributes(attributes or {})

        # Query existing by type + canonical_key + workspace_id
        q = db.query(EntityModel).filter(
            EntityModel.entity_type == type_str,
            EntityModel.canonical_key == canon_key,
        )
        if workspace_id:
            q = q.filter(EntityModel.workspace_id == workspace_id)
        else:
            q = q.filter(EntityModel.workspace_id.is_(None))

        existing = q.first()
        if not existing:
            # Fallback check on name if canonical_key was unset on legacy rows
            q_name = db.query(EntityModel).filter(
                EntityModel.entity_type == type_str,
                EntityModel.name == disp_name,
            )
            if workspace_id:
                q_name = q_name.filter(EntityModel.workspace_id == workspace_id)
            existing = q_name.first()

        if existing:
            existing.first_seen = self._safe_min_dt(existing.first_seen, now) or now
            existing.last_seen = self._safe_max_dt(existing.last_seen, now) or now

            if not existing.canonical_key:
                existing.canonical_key = canon_key

            # Merge attributes
            if clean_attrs:
                curr = {}
                if existing.attributes_json:
                    try:
                        curr = json.loads(existing.attributes_json)
                    except Exception:
                        pass
                curr.update(clean_attrs)
                existing.attributes_json = json.dumps(curr)

            existing.updated_at = get_utc_now()
            db.flush()
            return existing

        # Create new canonical entity
        entity = EntityModel(
            id=generate_uuid(),
            entity_type=type_str,
            name=disp_name,
            external_id=context,
            canonical_key=canon_key,
            workspace_id=workspace_id,
            attributes_json=json.dumps(clean_attrs),
            first_seen=now,
            last_seen=now,
            created_at=now,
            updated_at=now,
        )
        db.add(entity)
        db.flush()
        return entity

    # =========================================================================
    # 2. CANONICAL RELATIONSHIPS & OBSERVATIONS
    # =========================================================================

    def record_relationship(
        self,
        db: Session,
        source_id: str,
        target_id: str,
        relationship_type: Union[GraphRelationshipType, str],
        source_type: Optional[str] = None,
        target_type: Optional[str] = None,
        confidence: float = 1.0,
        origin: Union[RelationshipOrigin, str] = RelationshipOrigin.OBSERVED,
        observed_at: Optional[datetime] = None,
        source_artifact_id: Optional[str] = None,
        analysis_run_id: Optional[str] = None,
        evidence_id: Optional[str] = None,
        analyzer: Optional[str] = None,
        analyzer_version: Optional[str] = None,
        attributes: Optional[Dict[str, Any]] = None,
        evidence_reference: Optional[str] = None,
        workspace_id: Optional[str] = None,
    ) -> Tuple[RelationshipModel, RelationshipObservationModel]:
        """
        Records a canonical relationship edge and an evidence-backed observation.
        If the canonical edge already exists, updates its first_seen, last_seen, and confidence,
        while recording the discrete observation with full provenance.
        """
        rel_type_str = (
            relationship_type.value
            if isinstance(relationship_type, GraphRelationshipType)
            else str(relationship_type)
        ).upper()
        origin_str = (
            origin.value if isinstance(origin, RelationshipOrigin) else str(origin)
        ).upper()
        now = observed_at or get_utc_now()
        clean_conf = normalize_confidence(confidence)
        clean_attrs = sanitize_graph_attributes(attributes or {})

        # Query existing canonical relationship
        q = db.query(RelationshipModel).filter(
            RelationshipModel.relationship_type == rel_type_str,
            RelationshipModel.source_id == str(source_id),
            RelationshipModel.target_id == str(target_id),
        )
        if workspace_id:
            q = q.filter(RelationshipModel.workspace_id == workspace_id)
        else:
            q = q.filter(RelationshipModel.workspace_id.is_(None))

        rel = q.first()
        if rel:
            rel.first_seen = self._safe_min_dt(rel.first_seen, now) or now
            rel.last_seen = self._safe_max_dt(rel.last_seen, now) or now

            rel.confidence = max(rel.confidence, clean_conf)
            if evidence_reference and not rel.evidence_reference:
                rel.evidence_reference = evidence_reference
            if clean_attrs:
                curr_meta = {}
                if rel.metadata_json:
                    try:
                        curr_meta = json.loads(rel.metadata_json)
                    except Exception:
                        pass
                curr_meta.update(clean_attrs)
                rel.metadata_json = json.dumps(curr_meta)
            rel.updated_at = get_utc_now()
            db.flush()
        else:
            rel = RelationshipModel(
                id=generate_uuid(),
                source_type=(source_type or "ENTITY").upper(),
                source_id=str(source_id),
                relationship_type=rel_type_str,
                target_type=(target_type or "ENTITY").upper(),
                target_id=str(target_id),
                confidence=clean_conf,
                origin=origin_str,
                status=RelationshipStatus.ACTIVE.value,
                workspace_id=workspace_id,
                first_seen=now,
                last_seen=now,
                evidence_reference=evidence_reference,
                analysis_run_id=analysis_run_id,
                method="OBSERVED" if origin_str == "OBSERVED" else "HEURISTIC",
                metadata_json=json.dumps(clean_attrs),
                created_at=now,
                updated_at=now,
            )
            db.add(rel)
            db.flush()

        # Idempotency check for observation
        obs = None
        if analysis_run_id or evidence_id or analyzer:
            obs_q = db.query(RelationshipObservationModel).filter(
                RelationshipObservationModel.relationship_id == rel.id,
            )
            if analysis_run_id:
                obs_q = obs_q.filter(RelationshipObservationModel.analysis_run_id == analysis_run_id)
            if evidence_id:
                obs_q = obs_q.filter(RelationshipObservationModel.evidence_id == evidence_id)
            if analyzer:
                obs_q = obs_q.filter(RelationshipObservationModel.analyzer == analyzer)
            obs = obs_q.first()

        if not obs:
            obs = RelationshipObservationModel(
                id=generate_uuid(),
                relationship_id=rel.id,
                observed_at=now,
                source_artifact_id=source_artifact_id,
                analysis_run_id=analysis_run_id,
                evidence_id=evidence_id,
                analyzer=analyzer,
                analyzer_version=analyzer_version,
                confidence=clean_conf,
                origin=origin_str,
                attributes_json=json.dumps(clean_attrs),
                created_at=get_utc_now(),
            )
            db.add(obs)
            db.flush()

        return rel, obs

    # =========================================================================
    # 3. QUERY LAYER: ENTITY & NEIGHBORHOOD TRAVERSAL
    # =========================================================================

    def get_entity(self, db: Session, entity_id: str, workspace_id: Optional[str] = None) -> Optional[GraphNode]:
        """Fetches a single entity by ID or canonical key with workspace filtering."""
        q = db.query(EntityModel).filter(
            or_(EntityModel.id == entity_id, EntityModel.canonical_key == entity_id)
        )
        if workspace_id:
            q = q.filter(or_(EntityModel.workspace_id == workspace_id, EntityModel.workspace_id.is_(None)))
        ent = q.first()
        return self._entity_to_graph_node(ent) if ent else None

    def get_neighbors(
        self,
        db: Session,
        entity_id: str,
        relationship_types: Optional[List[str]] = None,
        direction: str = "both",
        depth: int = 1,
        time_range: Optional[Tuple[datetime, datetime]] = None,
        max_nodes: int = 100,
        max_edges: int = 200,
        workspace_id: Optional[str] = None,
    ) -> GraphSubgraphResponse:
        """
        Discovers neighbors up to specified depth (1-3) with bounded limits.
        Uses breadth-first traversal with cycle prevention.
        """
        clamped_depth = max(1, min(depth, self.MAX_DEPTH_LIMIT))
        node_limit = max(1, min(max_nodes, self.MAX_NODES_LIMIT))
        edge_limit = max(1, min(max_edges, self.MAX_EDGES_LIMIT))

        # Resolve root entity
        root = self.get_entity(db, entity_id, workspace_id=workspace_id)
        if not root:
            return GraphSubgraphResponse(nodes=[], edges=[], total_nodes=0, total_edges=0, truncated=False)

        discovered_nodes: Dict[str, GraphNode] = {root.id: root}
        discovered_edges: Dict[str, GraphEdge] = {}
        visited_ids: Set[str] = {root.id}
        current_level_ids: Set[str] = {root.id}
        truncated = False

        rel_filter = [r.upper() for r in relationship_types] if relationship_types else None

        for _ in range(clamped_depth):
            if not current_level_ids or len(discovered_nodes) >= node_limit or len(discovered_edges) >= edge_limit:
                break

            next_level_ids: Set[str] = set()
            level_list = list(current_level_ids)

            # Query edges connected to current level
            edge_q = db.query(RelationshipModel)
            if direction == "outgoing":
                edge_q = edge_q.filter(RelationshipModel.source_id.in_(level_list))
            elif direction == "incoming":
                edge_q = edge_q.filter(RelationshipModel.target_id.in_(level_list))
            else:
                edge_q = edge_q.filter(
                    or_(
                        RelationshipModel.source_id.in_(level_list),
                        RelationshipModel.target_id.in_(level_list)
                    )
                )

            if rel_filter:
                edge_q = edge_q.filter(RelationshipModel.relationship_type.in_(rel_filter))
            if workspace_id:
                edge_q = edge_q.filter(
                    or_(RelationshipModel.workspace_id == workspace_id, RelationshipModel.workspace_id.is_(None))
                )
            if time_range:
                start_t, end_t = time_range
                edge_q = edge_q.filter(RelationshipModel.last_seen >= start_t, RelationshipModel.first_seen <= end_t)

            edges = edge_q.limit(edge_limit - len(discovered_edges)).all()

            # Batch fetch observation counts
            edge_ids = [e.id for e in edges if e.id not in discovered_edges]
            obs_counts: Dict[str, int] = {}
            if edge_ids:
                from sqlalchemy import func
                cnt_q = (
                    db.query(
                        RelationshipObservationModel.relationship_id,
                        func.count(RelationshipObservationModel.id)
                    )
                    .filter(RelationshipObservationModel.relationship_id.in_(edge_ids))
                    .group_by(RelationshipObservationModel.relationship_id)
                    .all()
                )
                obs_counts = {r_id: count for r_id, count in cnt_q}

            neighbor_entity_ids_to_fetch: Set[str] = set()
            for e in edges:
                if len(discovered_edges) >= edge_limit:
                    truncated = True
                    break
                if e.id not in discovered_edges:
                    discovered_edges[e.id] = self._rel_to_graph_edge(e, obs_counts.get(e.id, 1))

                for peer in (e.source_id, e.target_id):
                    if peer not in visited_ids:
                        next_level_ids.add(peer)
                        if peer not in discovered_nodes:
                            neighbor_entity_ids_to_fetch.add(peer)

            # Batch fetch newly discovered entity models
            if neighbor_entity_ids_to_fetch:
                ents = (
                    db.query(EntityModel)
                    .filter(
                        or_(
                            EntityModel.id.in_(list(neighbor_entity_ids_to_fetch)),
                            EntityModel.canonical_key.in_(list(neighbor_entity_ids_to_fetch))
                        )
                    )
                    .all()
                )
                for ent in ents:
                    if len(discovered_nodes) >= node_limit:
                        truncated = True
                        break
                    gnode = self._entity_to_graph_node(ent)
                    discovered_nodes[gnode.id] = gnode
                    if ent.canonical_key:
                        discovered_nodes[ent.canonical_key] = gnode

            visited_ids.update(next_level_ids)
            current_level_ids = next_level_ids

        # Filter out nodes not in discovered_nodes or fallback placeholders
        final_nodes = list({n.id: n for n in discovered_nodes.values()}.values())[:node_limit]
        allowed_ids = {n.id for n in final_nodes} | {n.canonical_key for n in final_nodes}
        final_edges = [
            e for e in discovered_edges.values()
            if (e.source in allowed_ids and e.target in allowed_ids)
        ][:edge_limit]

        return GraphSubgraphResponse(
            nodes=final_nodes,
            edges=final_edges,
            total_nodes=len(final_nodes),
            total_edges=len(final_edges),
            truncated=truncated or len(final_nodes) >= node_limit or len(final_edges) >= edge_limit,
        )

    # =========================================================================
    # 4. BOUNDED PATH QUERY
    # =========================================================================

    def find_paths(
        self,
        db: Session,
        source_id: str,
        target_id: str,
        max_depth: int = 4,
        max_paths: int = 10,
        relationship_types: Optional[List[str]] = None,
        workspace_id: Optional[str] = None,
    ) -> GraphPathResponse:
        """
        Finds bounded multi-hop paths between source and target entities.
        Exposes full edge evidence for every discovered path.
        NOTE: Graph paths are evidence chains, NOT automatically attack paths.
        """
        depth_limit = max(1, min(max_depth, self.MAX_DEPTH_LIMIT))
        rel_filter = [r.upper() for r in relationship_types] if relationship_types else None

        # Resolve source & target
        src_node = self.get_entity(db, source_id, workspace_id=workspace_id)
        tgt_node = self.get_entity(db, target_id, workspace_id=workspace_id)

        target_identifiers = {target_id}
        if tgt_node:
            target_identifiers.add(tgt_node.id)
            if tgt_node.canonical_key:
                target_identifiers.add(tgt_node.canonical_key)

        source_identifiers = {source_id}
        if src_node:
            source_identifiers.add(src_node.id)
            if src_node.canonical_key:
                source_identifiers.add(src_node.canonical_key)

        # BFS Queue holds: (current_entity_id, path_of_edges, visited_entities)
        queue = deque([(sid, [], {sid}) for sid in source_identifiers])
        discovered_paths: List[List[GraphEdge]] = []
        all_edge_ids: Set[str] = set()
        all_node_ids: Set[str] = set(source_identifiers) | set(target_identifiers)

        while queue and len(discovered_paths) < max_paths:
            curr_id, edge_path, visited = queue.popleft()

            if len(edge_path) >= depth_limit:
                continue

            # Query outgoing edges from curr_id
            eq = db.query(RelationshipModel).filter(
                or_(RelationshipModel.source_id == curr_id, RelationshipModel.target_id == curr_id)
            )
            if rel_filter:
                eq = eq.filter(RelationshipModel.relationship_type.in_(rel_filter))
            if workspace_id:
                eq = eq.filter(
                    or_(RelationshipModel.workspace_id == workspace_id, RelationshipModel.workspace_id.is_(None))
                )

            connected_edges = eq.limit(50).all()

            for edge_model in connected_edges:
                edge_obj = self._rel_to_graph_edge(edge_model)
                next_id = edge_model.target_id if edge_model.source_id == curr_id else edge_model.source_id

                if next_id in visited:
                    continue  # Cycle prevention

                new_edge_path = edge_path + [edge_obj]
                new_visited = visited | {next_id}

                if next_id in target_identifiers:
                    discovered_paths.append(new_edge_path)
                    for e in new_edge_path:
                        all_edge_ids.add(e.id)
                        all_node_ids.add(e.source)
                        all_node_ids.add(e.target)
                    if len(discovered_paths) >= max_paths:
                        break
                else:
                    if len(new_edge_path) < depth_limit:
                        queue.append((next_id, new_edge_path, new_visited))

        # Batch resolve all entities along the paths
        all_nodes: List[GraphNode] = []
        if all_node_ids:
            ents = (
                db.query(EntityModel)
                .filter(
                    or_(
                        EntityModel.id.in_(list(all_node_ids)),
                        EntityModel.canonical_key.in_(list(all_node_ids))
                    )
                )
                .all()
            )
            all_nodes = [self._entity_to_graph_node(e) for e in ents]

        # Deduplicate edges
        edge_map: Dict[str, GraphEdge] = {}
        for p in discovered_paths:
            for e in p:
                edge_map[e.id] = e

        # Build step-by-step path provenance summary
        provenance: List[Dict[str, Any]] = []
        for idx, path in enumerate(discovered_paths):
            steps = []
            for hop in path:
                steps.append({
                    "source": hop.source,
                    "relationship": hop.type,
                    "target": hop.target,
                    "origin": hop.origin,
                    "confidence": hop.confidence,
                    "evidence_reference": hop.evidence_reference,
                })
            provenance.append({"path_index": idx + 1, "hops": steps})

        return GraphPathResponse(
            paths=discovered_paths,
            nodes=all_nodes,
            edges=list(edge_map.values()),
            depth=depth_limit,
            total_paths=len(discovered_paths),
            provenance_summary=provenance,
        )

    # =========================================================================
    # 5. INCIDENT SUBGRAPH
    # =========================================================================

    def get_incident_subgraph(
        self,
        db: Session,
        incident_id: str,
        max_nodes: int = 200,
        max_edges: int = 400,
        workspace_id: Optional[str] = None,
    ) -> GraphSubgraphResponse:
        """
        Retrieves the bounded graph of entities and relationships directly participating
        in an incident/investigation.
        """
        # Resolve incident
        inc = (
            db.query(IncidentModel)
            .filter(or_(IncidentModel.id == incident_id, IncidentModel.incident_number == incident_id))
            .first()
        )
        if not inc:
            return GraphSubgraphResponse(nodes=[], edges=[], total_nodes=0, total_edges=0, truncated=False)

        # 1. Identify direct incident entities
        incident_entity_ids: Set[str] = {inc.id, inc.incident_number}

        # 2. Collect edges explicitly linked to the incident
        edge_q = db.query(RelationshipModel).filter(
            or_(
                RelationshipModel.source_id.in_(list(incident_entity_ids)),
                RelationshipModel.target_id.in_(list(incident_entity_ids))
            )
        )
        if workspace_id:
            edge_q = edge_q.filter(
                or_(RelationshipModel.workspace_id == workspace_id, RelationshipModel.workspace_id.is_(None))
            )

        direct_edges = edge_q.limit(max_edges).all()
        for e in direct_edges:
            incident_entity_ids.add(e.source_id)
            incident_entity_ids.add(e.target_id)

        # 3. Include threat events & their artifacts
        for te in inc.threat_events:
            if te.source_artifact_id:
                incident_entity_ids.add(te.source_artifact_id)

        # 4. Perform 1-hop expansion around incident entities
        expansion_q = db.query(RelationshipModel).filter(
            or_(
                RelationshipModel.source_id.in_(list(incident_entity_ids)),
                RelationshipModel.target_id.in_(list(incident_entity_ids))
            )
        )
        if workspace_id:
            expansion_q = expansion_q.filter(
                or_(RelationshipModel.workspace_id == workspace_id, RelationshipModel.workspace_id.is_(None))
            )

        all_edges_raw = expansion_q.limit(max_edges).all()

        edge_map: Dict[str, GraphEdge] = {}
        node_ids_to_fetch: Set[str] = set(incident_entity_ids)

        for e in all_edges_raw:
            edge_map[e.id] = self._rel_to_graph_edge(e)
            node_ids_to_fetch.add(e.source_id)
            node_ids_to_fetch.add(e.target_id)

        # Fetch entities
        nodes: List[GraphNode] = []
        if node_ids_to_fetch:
            ents = (
                db.query(EntityModel)
                .filter(
                    or_(
                        EntityModel.id.in_(list(node_ids_to_fetch)),
                        EntityModel.canonical_key.in_(list(node_ids_to_fetch))
                    )
                )
                .limit(max_nodes)
                .all()
            )
            nodes = [self._entity_to_graph_node(e) for e in ents]

        # Add incident node itself if not already represented
        inc_node_exists = any(n.id == inc.id for n in nodes)
        if not inc_node_exists:
            nodes.append(
                GraphNode(
                    id=inc.id,
                    type="INCIDENT",
                    canonical_key=f"incident:{inc.incident_number}",
                    display_value=f"Incident: {inc.incident_number}",
                    first_seen=inc.opened_at,
                    last_seen=inc.updated_at,
                    attributes={
                        "title": inc.title,
                        "status": inc.status,
                        "severity": inc.severity,
                        "risk_score": inc.risk_score,
                    },
                )
            )

        return GraphSubgraphResponse(
            nodes=nodes,
            edges=list(edge_map.values()),
            total_nodes=len(nodes),
            total_edges=len(edge_map),
            truncated=len(nodes) >= max_nodes or len(edge_map) >= max_edges,
        )

    # =========================================================================
    # 6. EDGE EVIDENCE DISCLOSURE ("WHY DOES THIS EDGE EXIST?")
    # =========================================================================

    def get_edge_evidence(
        self,
        db: Session,
        edge_id: str,
        workspace_id: Optional[str] = None
    ) -> EdgeEvidenceResponse:
        """
        Discloses full forensic provenance, observations, and supporting findings/evidence
        for a specific graph edge.
        """
        rel_q = db.query(RelationshipModel).filter(RelationshipModel.id == edge_id)
        if workspace_id:
            rel_q = rel_q.filter(
                or_(RelationshipModel.workspace_id == workspace_id, RelationshipModel.workspace_id.is_(None))
            )
        rel = rel_q.first()
        if not rel:
            raise KeyError(f"Graph edge with ID '{edge_id}' not found.")

        # Query observations
        obs_models = (
            db.query(RelationshipObservationModel)
            .filter(RelationshipObservationModel.relationship_id == rel.id)
            .order_by(desc(RelationshipObservationModel.observed_at))
            .all()
        )

        obs_responses: List[RelationshipObservationResponse] = []
        finding_ids: Set[str] = set()
        artifact_ids: Set[str] = set()

        for o in obs_models:
            attrs = {}
            if o.attributes_json:
                try:
                    attrs = json.loads(o.attributes_json)
                except Exception:
                    pass
            obs_responses.append(
                RelationshipObservationResponse(
                    id=o.id,
                    relationship_id=o.relationship_id,
                    observed_at=o.observed_at,
                    source_artifact_id=o.source_artifact_id,
                    analysis_run_id=o.analysis_run_id,
                    evidence_id=o.evidence_id,
                    analyzer=o.analyzer,
                    analyzer_version=o.analyzer_version,
                    confidence=o.confidence,
                    origin=o.origin,
                    attributes=sanitize_graph_attributes(attrs),
                )
            )
            if o.source_artifact_id:
                artifact_ids.add(o.source_artifact_id)

        # Collect supporting finding evidence
        findings_data: List[Dict[str, Any]] = []
        ev_ids = [o.evidence_id for o in obs_models if o.evidence_id]
        if ev_ids:
            ev_records = db.query(FindingEvidenceModel).filter(FindingEvidenceModel.id.in_(ev_ids)).all()
            for ev in ev_records:
                findings_data.append({
                    "evidence_id": ev.id,
                    "finding_id": ev.finding_id,
                    "key": ev.key,
                    "value": ev.value,
                    "source": ev.source,
                    "confidence": ev.confidence,
                })

        # Fetch source and target entities
        src_node = self.get_entity(db, rel.source_id, workspace_id=workspace_id)
        tgt_node = self.get_entity(db, rel.target_id, workspace_id=workspace_id)

        # Build natural explanation
        analyzers_used = {o.analyzer for o in obs_models if o.analyzer}
        analyzer_str = ", ".join(analyzers_used) if analyzers_used else rel.method
        explanation = (
            f"Relationship '{rel.relationship_type}' between '{rel.source_id}' and '{rel.target_id}' "
            f"was observed {len(obs_models)} time(s) with confidence {rel.confidence:.2f} "
            f"via analyzer(s): {analyzer_str}. Origin classified as {rel.origin}."
        )

        return EdgeEvidenceResponse(
            edge=self._rel_to_graph_edge(rel, obs_count=len(obs_models)),
            observations=obs_responses,
            findings=findings_data,
            threat_events=[],
            source_entity=src_node,
            target_entity=tgt_node,
            explanation=explanation,
        )

    # =========================================================================
    # 7. ENTITY TIMELINE
    # =========================================================================

    def get_entity_timeline(
        self,
        db: Session,
        entity_id: str,
        limit: int = 100,
        workspace_id: Optional[str] = None
    ) -> EntityTimelineResponse:
        """
        Produces a chronological timeline of security observations involving an entity.
        """
        ent = self.get_entity(db, entity_id, workspace_id=workspace_id)
        if not ent:
            raise KeyError(f"Entity '{entity_id}' not found.")

        # Find relationships where entity is source or target
        rel_q = db.query(RelationshipModel).filter(
            or_(RelationshipModel.source_id == ent.id, RelationshipModel.target_id == ent.id)
        )
        if ent.canonical_key:
            rel_q = db.query(RelationshipModel).filter(
                or_(
                    RelationshipModel.source_id.in_([ent.id, ent.canonical_key]),
                    RelationshipModel.target_id.in_([ent.id, ent.canonical_key])
                )
            )
        if workspace_id:
            rel_q = rel_q.filter(
                or_(RelationshipModel.workspace_id == workspace_id, RelationshipModel.workspace_id.is_(None))
            )

        rels = rel_q.all()
        rel_ids = [r.id for r in rels]
        rel_by_id = {r.id: r for r in rels}

        events: List[TimelineEventItem] = []
        if rel_ids:
            obs_list = (
                db.query(RelationshipObservationModel)
                .filter(RelationshipObservationModel.relationship_id.in_(rel_ids))
                .order_by(desc(RelationshipObservationModel.observed_at))
                .limit(limit)
                .all()
            )

            for o in obs_list:
                parent_rel = rel_by_id.get(o.relationship_id)
                if not parent_rel:
                    continue

                is_source = (parent_rel.source_id in [ent.id, ent.canonical_key])
                peer_id = parent_rel.target_id if is_source else parent_rel.source_id
                peer_type = parent_rel.target_type if is_source else parent_rel.source_type
                role = "SOURCE" if is_source else "TARGET"

                desc_text = (
                    f"{ent.display_value} {parent_rel.relationship_type} {peer_id}"
                    if is_source
                    else f"{peer_id} {parent_rel.relationship_type} {ent.display_value}"
                )

                events.append(
                    TimelineEventItem(
                        id=o.id,
                        timestamp=o.observed_at,
                        event_type=parent_rel.relationship_type,
                        description=desc_text,
                        role=role,
                        relationship_type=parent_rel.relationship_type,
                        peer_entity_id=peer_id,
                        peer_entity_type=peer_type,
                        peer_entity_key=peer_id,
                        origin=o.origin,
                        analyzer=o.analyzer,
                        confidence=o.confidence,
                        artifact_id=o.source_artifact_id,
                        incident_id=None,
                    )
                )

        events.sort(key=lambda x: x.timestamp)

        return EntityTimelineResponse(
            entity_id=ent.id,
            canonical_key=ent.canonical_key,
            entity_type=ent.type,
            display_value=ent.display_value,
            total_events=len(events),
            events=events,
        )

    # =========================================================================
    # 8. SEARCH ENTITIES
    # =========================================================================

    def search_entities(
        self,
        db: Session,
        query: str,
        entity_types: Optional[List[str]] = None,
        limit: int = 20,
        workspace_id: Optional[str] = None
    ) -> EntitySearchResponse:
        """Searches entities by keyword matching name, external_id, or canonical_key."""
        clean = (query or "").strip()
        if not clean:
            return EntitySearchResponse(entities=[], total=0)

        q = db.query(EntityModel).filter(
            or_(
                EntityModel.name.ilike(f"%{clean}%"),
                EntityModel.canonical_key.ilike(f"%{clean}%"),
                EntityModel.external_id.ilike(f"%{clean}%")
            )
        )
        if entity_types:
            q = q.filter(EntityModel.entity_type.in_([t.upper() for t in entity_types]))
        if workspace_id:
            q = q.filter(or_(EntityModel.workspace_id == workspace_id, EntityModel.workspace_id.is_(None)))

        ents = q.limit(limit).all()
        nodes = [self._entity_to_graph_node(e) for e in ents]
        return EntitySearchResponse(entities=nodes, total=len(nodes))


global_security_graph_service = SecurityGraphService()
