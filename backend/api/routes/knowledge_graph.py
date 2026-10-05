"""
Canonical Security Knowledge Graph API Endpoints (Section 14).
Provides query endpoints for incident subgraphs, neighborhood expansions,
bounded multi-hop paths, entity timelines, edge evidence disclosure, and entity search.
"""
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.db.models import AnalysisRunModel, ArtifactModel, IncidentModel
from backend.schemas.knowledge_graph import (
    GraphNode,
    GraphEdge,
    EdgeEvidenceResponse,
    GraphSubgraphResponse,
    GraphPathResponse,
    EntityTimelineResponse,
    EntitySearchResponse,
    GraphBuildRequest,
    GraphBuildResponse,
)
from backend.services.security_graph_service import global_security_graph_service
from backend.services.security_graph_builder import global_security_graph_builder

router = APIRouter(prefix="/api/graph", tags=["Security Knowledge Graph"])


@router.get(
    "/entities/{id}",
    response_model=GraphNode,
    summary="Get entity by ID or canonical key",
    description="Returns canonical graph node with redacted attributes and observation timestamps."
)
def get_graph_entity_endpoint(
    id: str,
    workspace_id: Optional[str] = Query(None, description="Workspace isolation ID"),
    db: Session = Depends(get_db)
):
    node = global_security_graph_service.get_entity(db, entity_id=id, workspace_id=workspace_id)
    if not node:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Entity '{id}' not found."
        )
    return node


@router.get(
    "/entities/{id}/neighbors",
    response_model=GraphSubgraphResponse,
    summary="Expand entity neighborhood",
    description="Returns bounded neighboring nodes and edges up to depth 3 with cycle prevention."
)
def get_graph_neighbors_endpoint(
    id: str,
    depth: int = Query(1, ge=1, le=3, description="Expansion traversal depth"),
    direction: str = Query("both", pattern="^(outgoing|incoming|both)$"),
    relationship_types: Optional[List[str]] = Query(None, description="Filter by relationship types"),
    max_nodes: int = Query(100, ge=1, le=500),
    max_edges: int = Query(200, ge=1, le=1000),
    workspace_id: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    return global_security_graph_service.get_neighbors(
        db=db,
        entity_id=id,
        relationship_types=relationship_types,
        direction=direction,
        depth=depth,
        max_nodes=max_nodes,
        max_edges=max_edges,
        workspace_id=workspace_id
    )


@router.get(
    "/entities/{id}/timeline",
    response_model=EntityTimelineResponse,
    summary="Get chronological entity timeline",
    description="Returns chronological sequence of security observations involving this entity."
)
def get_entity_timeline_endpoint(
    id: str,
    limit: int = Query(100, ge=1, le=500),
    workspace_id: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    try:
        return global_security_graph_service.get_entity_timeline(
            db=db, entity_id=id, limit=limit, workspace_id=workspace_id
        )
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


@router.get(
    "/edges/{id}/evidence",
    response_model=EdgeEvidenceResponse,
    summary="Why does this edge exist?",
    description="Returns complete forensic provenance, observations, analyzer metadata, and supporting findings for a relationship edge."
)
def get_edge_evidence_endpoint(
    id: str,
    workspace_id: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    try:
        return global_security_graph_service.get_edge_evidence(
            db=db, edge_id=id, workspace_id=workspace_id
        )
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


@router.get(
    "/paths",
    response_model=GraphPathResponse,
    summary="Find bounded multi-hop paths between entities",
    description="Discovers bounded evidence paths connecting source and target entities with hop-by-hop provenance."
)
def find_graph_paths_endpoint(
    source: str = Query(..., description="Source entity ID or canonical key"),
    target: str = Query(..., description="Target entity ID or canonical key"),
    max_depth: int = Query(4, ge=1, le=5, description="Maximum traversal depth"),
    max_paths: int = Query(10, ge=1, le=25, description="Maximum paths to return"),
    relationship_types: Optional[List[str]] = Query(None),
    workspace_id: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    return global_security_graph_service.find_paths(
        db=db,
        source_id=source,
        target_id=target,
        max_depth=max_depth,
        max_paths=max_paths,
        relationship_types=relationship_types,
        workspace_id=workspace_id
    )


@router.get(
    "/incidents/{incident_id}",
    response_model=GraphSubgraphResponse,
    summary="Get incident investigation subgraph",
    description="Returns the bounded graph of entities and relationships directly participating in an incident."
)
def get_incident_subgraph_endpoint(
    incident_id: str,
    max_nodes: int = Query(200, ge=1, le=500),
    max_edges: int = Query(400, ge=1, le=1000),
    workspace_id: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    return global_security_graph_service.get_incident_subgraph(
        db=db,
        incident_id=incident_id,
        max_nodes=max_nodes,
        max_edges=max_edges,
        workspace_id=workspace_id
    )


@router.post(
    "/search",
    response_model=EntitySearchResponse,
    summary="Search entities in knowledge graph",
    description="Searches canonical entities by keyword across names, canonical keys, and identifiers."
)
def search_entities_endpoint(
    query: str = Query(..., description="Search keyword"),
    entity_types: Optional[List[str]] = Query(None, description="Optional entity category filter"),
    limit: int = Query(20, ge=1, le=100),
    workspace_id: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    return global_security_graph_service.search_entities(
        db=db,
        query=query,
        entity_types=entity_types,
        limit=limit,
        workspace_id=workspace_id
    )


@router.post(
    "/build",
    response_model=GraphBuildResponse,
    summary="Trigger graph construction from AnalysisRun or Artifact",
    description="Processes normalized findings and indicators into the canonical graph store idempotently."
)
def build_graph_endpoint(
    request: GraphBuildRequest,
    db: Session = Depends(get_db)
):
    if not request.analysis_run_id and not request.artifact_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Either 'analysis_run_id' or 'artifact_id' must be provided."
        )

    run = None
    if request.analysis_run_id:
        run = db.query(AnalysisRunModel).filter(AnalysisRunModel.id == request.analysis_run_id).first()
        if not run:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"AnalysisRun '{request.analysis_run_id}' not found.")

    artifact_id = request.artifact_id or (run.artifact_id if run else None)
    artifact = None
    if artifact_id:
        artifact = db.query(ArtifactModel).filter(ArtifactModel.id == artifact_id).first()

    # Determine artifact type and trigger appropriate ingestion
    payload_dict = {}
    if run and run.summary_json:
        try:
            payload_dict = json.loads(run.summary_json)
        except Exception:
            payload_dict = {}

    art_type = artifact.artifact_type if artifact else "EMAIL"
    if art_type in ("EMAIL", "EML"):
        return global_security_graph_builder.ingest_email_analysis(
            db=db,
            email_analysis=payload_dict,
            artifact_id=artifact_id,
            analysis_run_id=run.id if run else None,
            incident_id=request.incident_id,
            workspace_id=request.workspace_id,
        )
    elif art_type in ("FILE", "ATTACHMENT", "PDF", "ZIP", "BINARY"):
        return global_security_graph_builder.ingest_file_analysis(
            db=db,
            file_data=payload_dict,
            artifact_id=artifact_id,
            analysis_run_id=run.id if run else None,
            incident_id=request.incident_id,
            workspace_id=request.workspace_id,
        )
    elif art_type == "NETWORK_LOG":
        events = payload_dict.get("events") or []
        for ev in events:
            global_security_graph_builder.ingest_network_event(
                db=db,
                event=ev,
                artifact_id=artifact_id,
                analysis_run_id=run.id if run else None,
                incident_id=request.incident_id,
                workspace_id=request.workspace_id,
            )
        return GraphBuildResponse()
    elif art_type == "API_LOG":
        events = payload_dict.get("events") or []
        for ev in events:
            global_security_graph_builder.ingest_api_event(
                db=db,
                event=ev,
                artifact_id=artifact_id,
                analysis_run_id=run.id if run else None,
                incident_id=request.incident_id,
                workspace_id=request.workspace_id,
            )
        return GraphBuildResponse()
    else:
        return GraphBuildResponse()
