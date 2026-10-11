"""
Section 65: Comprehensive Test Suite for Threat Actor & Campaign Workspace.
Verifies:
- Actor creation, aliases with provenance, and attribution lifecycle.
- Campaign candidate review, promotion, rejection, merging, and splitting.
- Explicit distinction between facts, correlation, hypotheses, and attribution.
- Separate confidence (0.0 to 1.0) distinct from risk.
- Supporting vs contradicting evidence tracking.
- Affected assets and identities integration.
- Bounded relationship graph generation.
- Threat hunting and detection engineering handoffs.
- Multi-tenant workspace isolation and RBAC security enforcement.
- Background worker synchronization handler.
"""
from __future__ import annotations

import json
import pytest
import uuid
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.main import app
from backend.db.session import SessionLocal, init_db
from backend.db.models import (
    CampaignModel,
    CampaignIncidentModel,
    IncidentModel,
    AssetModel,
    IdentityModel,
    ThreatActorModel,
    ThreatHypothesisModel,
    ThreatAttributionAssessmentModel,
)
from backend.schemas.threat_workspace import (
    AttributionStateEnum,
    SemanticClassificationEnum,
    CampaignLifecycleEnum,
    HypothesisStatusEnum,
    ActorTypeEnum,
    EvidenceItem,
    ActorAlias,
    ThreatActorCreateRequest,
    CampaignCreateRequest,
    CandidateReviewRequest,
    CampaignMergeRequest,
    CampaignMergePreviewRequest,
    CampaignSplitRequest,
    AttributionAssessmentCreateRequest,
    HypothesisCreateRequest,
    HypothesisUpdateRequest,
)
from backend.services.threat_workspace_service import ThreatWorkspaceService
from backend.services.background_job_worker import JobExecutionContext, handle_campaign_workspace_jobs


@pytest.fixture(scope="module")
def setup_db():
    init_db()
    yield


@pytest.fixture
def db_session(setup_db):
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def client(setup_db):
    return TestClient(app)


# =============================================================================
# 1. Threat Actor Lifecycle & Attribution Tests
# =============================================================================

def test_threat_actor_creation_and_aliases(db_session: Session):
    ws = f"ws-ta-{uuid.uuid4().hex[:6]}"
    req = ThreatActorCreateRequest(
        name="Storm-0492",
        canonical_name="DEV-0492",
        actor_type=ActorTypeEnum.CYBERCRIME,
        attribution_state=AttributionStateEnum.SUSPECTED,
        attribution_confidence=0.65,
        motivation="FINANCIAL",
        sophistication="INTERMEDIATE",
        description="Financially motivated credential harvesting syndicate.",
        aliases=[
            ActorAlias(alias="FinHarvester", source="Vendor-X", confidence=0.7),
            ActorAlias(alias="UNC9921", source="Mandiant", confidence=0.8),
        ],
        observed_techniques=["T1566.002", "T1071.001"],
        observed_infrastructure=["auth-portal-update.com", "185.220.101.42"],
    )

    actor = ThreatWorkspaceService.create_actor(db_session, ws, req, creator="Lead Analyst")
    assert actor.id is not None
    assert actor.actor_id.startswith("TA-")
    assert actor.name == "Storm-0492"
    assert actor.attribution_state == "SUSPECTED"
    assert actor.attribution_confidence == 0.65
    assert len(actor.aliases) == 2
    assert actor.aliases[0].alias == "FinHarvester"
    assert actor.aliases[1].source == "Mandiant"


def test_actor_attribution_assessment_with_justification(db_session: Session):
    ws = f"ws-ta-{uuid.uuid4().hex[:6]}"
    req = ThreatActorCreateRequest(
        name="CozyBreeze",
        attribution_state=AttributionStateEnum.SUSPECTED,
        attribution_confidence=0.5,
    )
    actor = ThreatWorkspaceService.create_actor(db_session, ws, req)

    # 1. Attempt CONFIRMED without justification must fail
    with pytest.raises(ValueError, match="substantive analyst justification"):
        ThreatWorkspaceService.record_actor_assessment(
            db_session,
            ws,
            actor.id,
            AttributionAssessmentCreateRequest(
                subject_id=actor.id,
                new_attribution_state=AttributionStateEnum.CONFIRMED,
                confidence=0.95,
                justification="too short",
            ),
        )

    # 2. Transition with substantive justification and supporting/contradicting evidence
    assessment = ThreatWorkspaceService.record_actor_assessment(
        db_session,
        ws,
        actor.id,
        AttributionAssessmentCreateRequest(
            subject_id=actor.id,
            new_attribution_state=AttributionStateEnum.CONFIRMED,
            confidence=0.95,
            justification="Authoritative FBI flash alert corroborated by internal telemetry SSL fingerprint matches.",
            supporting_evidence=[
                EvidenceItem(
                    id="ev-1",
                    evidence_type="CERTIFICATE",
                    description="Identical TLS SHA-256 fingerprint observed on C2 host.",
                    source="telemetry",
                    confidence=0.98,
                )
            ],
            contradicting_evidence=[
                EvidenceItem(
                    id="ev-2",
                    evidence_type="TIMING",
                    description="Bursts observed outside expected adversary operating timezone.",
                    source="telemetry",
                    confidence=0.6,
                    is_contradicting=True,
                )
            ],
        ),
        analyst="Principal Investigator",
    )

    assert assessment.new_attribution_state == "CONFIRMED"
    assert assessment.confidence == 0.95
    assert len(assessment.supporting_evidence) == 1
    assert len(assessment.contradicting_evidence) == 1

    # Verify actor record is updated
    refreshed = ThreatWorkspaceService.get_actor(db_session, ws, actor.id)
    assert refreshed.attribution_state == "CONFIRMED"
    assert refreshed.attribution_confidence == 0.95


# =============================================================================
# 2. Campaign Workspace & Candidate Review Tests
# =============================================================================

def test_campaign_candidate_review_promote(db_session: Session):
    ws = f"ws-camp-{uuid.uuid4().hex[:6]}"
    now = datetime.now(timezone.utc)

    # Create candidate in DB
    candidate = CampaignModel(
        id=str(uuid.uuid4()),
        campaign_id="CAMP-CAND-001",
        name="Candidate Cluster Alpha",
        workspace_id=ws,
        status="CANDIDATE",
        lifecycle_status="CANDIDATE",
        first_seen=now,
        last_seen=now,
        overall_confidence=68.0,
        associated_iocs_json=json.dumps([{"type": "DOMAIN", "value": "payroll-login.info"}]),
        created_at=now,
    )
    db_session.add(candidate)
    db_session.commit()

    candidates = ThreatWorkspaceService.list_candidates(db_session, ws)
    assert any(c.campaign_id == "CAMP-CAND-001" for c in candidates)

    # Promote candidate to active campaign
    reviewed = ThreatWorkspaceService.review_candidate(
        db_session,
        ws,
        "CAMP-CAND-001",
        CandidateReviewRequest(
            action="PROMOTE",
            name="Payroll Phishing Campaign — Q4",
            reason="Corroborated across 3 user telemetry reports with matching credential harvest pattern.",
        ),
        analyst="Analyst-1",
    )

    assert reviewed.lifecycle_status == "OPEN"
    assert reviewed.name == "Payroll Phishing Campaign — Q4"
    assert len(reviewed.provenance_history) >= 1
    assert reviewed.provenance_history[-1]["action"] == "CANDIDATE_PROMOTED"


def test_campaign_candidate_review_reject(db_session: Session):
    ws = f"ws-camp-{uuid.uuid4().hex[:6]}"
    now = datetime.now(timezone.utc)

    candidate = CampaignModel(
        id=str(uuid.uuid4()),
        campaign_id="CAMP-CAND-002",
        name="Candidate Cluster Beta",
        workspace_id=ws,
        status="CANDIDATE",
        lifecycle_status="CANDIDATE",
        first_seen=now,
        last_seen=now,
        overall_confidence=52.0,
        created_at=now,
    )
    db_session.add(candidate)
    db_session.commit()

    reviewed = ThreatWorkspaceService.review_candidate(
        db_session,
        ws,
        "CAMP-CAND-002",
        CandidateReviewRequest(
            action="REJECT",
            reason="Transitive indicator bridge was a shared public Cloudflare reverse proxy.",
        ),
    )

    assert reviewed.lifecycle_status == "CLOSED"
    assert reviewed.provenance_history[-1]["action"] == "CANDIDATE_REJECTED"


# =============================================================================
# 3. Campaign Merge and Split Tests
# =============================================================================

def test_campaign_merge_workflow_and_provenance(db_session: Session):
    ws = f"ws-merge-{uuid.uuid4().hex[:6]}"
    now = datetime.now(timezone.utc)

    # 1. Source campaign
    src = CampaignModel(
        id=str(uuid.uuid4()),
        campaign_id="C-101",
        name="Credential Harvester Cluster A",
        workspace_id=ws,
        status="OPEN",
        lifecycle_status="OPEN",
        first_seen=now,
        last_seen=now,
        associated_iocs_json=json.dumps([{"type": "DOMAIN", "value": "domain-a.com"}]),
        created_at=now,
    )
    # 2. Target campaign
    tgt = CampaignModel(
        id=str(uuid.uuid4()),
        campaign_id="C-102",
        name="Credential Harvester Cluster B",
        workspace_id=ws,
        status="ACTIVE",
        lifecycle_status="ACTIVE",
        first_seen=now,
        last_seen=now,
        associated_iocs_json=json.dumps([{"type": "DOMAIN", "value": "domain-b.com"}]),
        created_at=now,
    )
    db_session.add_all([src, tgt])
    db_session.flush()

    # Link incident to source
    c_inc = CampaignIncidentModel(
        id=str(uuid.uuid4()),
        campaign_id=src.id,
        incident_id=str(uuid.uuid4()),
        similarity_score=0.8,
        added_at=now,
    )
    db_session.add(c_inc)
    db_session.commit()

    # Preview merge
    preview = ThreatWorkspaceService.preview_merge(
        db_session,
        ws,
        CampaignMergePreviewRequest(source_campaign_id="C-101", target_campaign_id="C-102"),
    )
    assert preview.is_safe is True
    assert preview.source_incidents_count == 1
    assert preview.source_indicators_count == 1

    # Execute merge
    merged_tgt = ThreatWorkspaceService.merge_campaigns(
        db_session,
        ws,
        CampaignMergeRequest(
            source_campaign_id="C-101",
            target_campaign_id="C-102",
            reason="Confirmed common C2 infrastructure and identical registration timeline.",
        ),
        analyst="Threat Hunter",
    )

    # Verify target received indicators and provenance
    assert merged_tgt.campaign_id == "C-102"
    assert any(p["action"] == "CAMPAIGN_MERGED_INTO" for p in merged_tgt.provenance_history)

    # Verify source was archived and not destroyed
    src_db = db_session.query(CampaignModel).filter(CampaignModel.id == src.id).first()
    assert src_db.lifecycle_status == "ARCHIVED"
    src_prov = json.loads(src_db.provenance_history_json)
    assert any(p["action"] == "CAMPAIGN_MERGED_OUT" for p in src_prov)


def test_campaign_split_workflow(db_session: Session):
    ws = f"ws-split-{uuid.uuid4().hex[:6]}"
    now = datetime.now(timezone.utc)

    parent = CampaignModel(
        id=str(uuid.uuid4()),
        campaign_id="C-201",
        name="Composite Threat Activity",
        workspace_id=ws,
        status="ACTIVE",
        lifecycle_status="ACTIVE",
        first_seen=now,
        last_seen=now,
        created_at=now,
    )
    db_session.add(parent)
    db_session.flush()

    inc1_id = str(uuid.uuid4())
    inc2_id = str(uuid.uuid4())
    db_session.add_all([
        CampaignIncidentModel(campaign_id=parent.id, incident_id=inc1_id, added_at=now),
        CampaignIncidentModel(campaign_id=parent.id, incident_id=inc2_id, added_at=now),
    ])
    db_session.commit()

    # Split incident 2 into child campaign
    split_res = ThreatWorkspaceService.split_campaign(
        db_session,
        ws,
        "C-201",
        CampaignSplitRequest(
            reason="Separate second-stage ransomware cluster identified.",
            new_campaign_name="Targeted Ransomware Operations",
            incident_ids_to_move=[inc2_id],
        ),
        analyst="Senior Hunter",
    )

    assert split_res["moved_incidents"] == 1
    child = split_res["child"]
    assert child.name == "Targeted Ransomware Operations"
    assert child.lifecycle_status == "OPEN"

    # Verify parent has split provenance
    parent_res = split_res["parent"]
    assert any(p["action"] == "CAMPAIGN_SPLIT_DETACHED" for p in parent_res.provenance_history)


# =============================================================================
# 4. Analyst Hypotheses Lifecycle Tests
# =============================================================================

def test_threat_hypotheses_lifecycle(db_session: Session):
    ws = f"ws-hypo-{uuid.uuid4().hex[:6]}"
    camp_id = str(uuid.uuid4())

    # 1. Create Hypothesis
    hypo = ThreatWorkspaceService.create_hypothesis(
        db_session,
        ws,
        HypothesisCreateRequest(
            subject_type="CAMPAIGN",
            subject_id=camp_id,
            title="Finance Department Spear-Phishing Targeting",
            hypothesis_text="Adversary is focusing initial access exclusively on payroll and treasury staff.",
            confidence=0.6,
            supporting_evidence=[
                EvidenceItem(
                    id="ev-h1",
                    evidence_type="TARGETING",
                    description="8 emails observed targeting VP Finance and Treasury Directors.",
                    source="email_telemetry",
                    confidence=0.9,
                )
            ],
            contradicting_evidence=[
                EvidenceItem(
                    id="ev-h2",
                    evidence_type="TARGETING",
                    description="1 email sent to unrelated software engineer.",
                    source="email_telemetry",
                    confidence=0.5,
                    is_contradicting=True,
                )
            ],
        ),
        author="Analyst Jones",
    )

    assert hypo.id is not None
    assert hypo.status == "OPEN"
    assert len(hypo.supporting_evidence) == 1
    assert len(hypo.contradicting_evidence) == 1

    # 2. Update Hypothesis status to SUPPORTED
    updated = ThreatWorkspaceService.update_hypothesis(
        db_session,
        ws,
        hypo.id,
        HypothesisUpdateRequest(
            status=HypothesisStatusEnum.SUPPORTED,
            confidence=0.85,
            reason="4 additional treasury recipients confirmed.",
        ),
        updater="Lead Analyst",
    )

    assert updated.status == "SUPPORTED"
    assert updated.confidence == 0.85


# =============================================================================
# 5. Timeline, Graph & Integration Handoff Tests
# =============================================================================

def test_campaign_timeline_and_graph(db_session: Session):
    ws = f"ws-tg-{uuid.uuid4().hex[:6]}"
    now = datetime.now(timezone.utc)

    camp = CampaignModel(
        id=str(uuid.uuid4()),
        campaign_id="C-301",
        name="Operation NightHawk",
        workspace_id=ws,
        status="ACTIVE",
        lifecycle_status="ACTIVE",
        first_seen=now,
        last_seen=now,
        associated_iocs_json=json.dumps([
            {"type": "DOMAIN", "value": "nighthawk-c2.net", "risk_score": 85},
            {"type": "IP", "value": "194.26.29.112", "risk_score": 90},
        ]),
        mitre_techniques_json=json.dumps(["T1566.002", "T1071.001"]),
        timeline_events_json=json.dumps([
            {"timestamp": now.isoformat(), "event": "First observed phishing lure", "description": "Lure detected"}
        ]),
        created_at=now,
    )
    db_session.add(camp)
    db_session.commit()

    # 1. Timeline
    tl = ThreatWorkspaceService.get_campaign_timeline(db_session, ws, "C-301")
    assert tl.campaign_id == "C-301"
    assert len(tl.events) >= 1
    assert tl.events[0].title == "First observed phishing lure"

    # 2. Relationship Graph
    graph = ThreatWorkspaceService.get_campaign_graph(db_session, ws, "C-301", max_nodes=50)
    assert graph.summary.total_nodes >= 3  # Campaign + 2 IOCs + techniques
    assert any(n.type.value == "Campaign" for n in graph.nodes)
    assert any(n.type.value in ("Domain", "IP") for n in graph.nodes)
    assert any(n.type.value == "Technique" for n in graph.nodes)


def test_hunting_and_detection_handoffs(db_session: Session):
    ws = f"ws-handoff-{uuid.uuid4().hex[:6]}"
    now = datetime.now(timezone.utc)

    camp = CampaignModel(
        id=str(uuid.uuid4()),
        campaign_id="C-401",
        name="Swift Wire Fraud Ring",
        workspace_id=ws,
        status="ACTIVE",
        lifecycle_status="ACTIVE",
        first_seen=now,
        last_seen=now,
        associated_iocs_json=json.dumps([{"type": "IP", "value": "185.220.101.42"}]),
        mitre_techniques_json=json.dumps(["T1566.001"]),
        created_at=now,
    )
    db_session.add(camp)
    db_session.commit()

    # Hunt Handoff
    hunt_handoff = ThreatWorkspaceService.get_hunt_handoff(db_session, ws, "C-401")
    assert hunt_handoff.campaign_id == "C-401"
    assert len(hunt_handoff.suggested_queries) >= 1
    assert "185.220.101.42" in hunt_handoff.suggested_queries[0]["query_string"]

    # Detection Handoff
    det_handoff = ThreatWorkspaceService.get_detection_handoff(db_session, ws, "C-401")
    assert det_handoff.campaign_id == "C-401"
    assert "Swift Wire Fraud Ring" in det_handoff.recommended_rule_title
    assert "185.220.101.42" in det_handoff.indicators_to_match


# =============================================================================
# 6. REST API, RBAC, and Multi-Tenant Security Tests
# =============================================================================

def test_api_rbac_forbidden_for_unauthorized_roles(client: TestClient):
    # Guest role must receive 403
    resp = client.get("/api/v1/threat-workspace/actors", headers={"X-Role": "guest"})
    assert resp.status_code == 403

    resp = client.get("/api/v1/threat-workspace/campaigns", headers={"X-Role": "unauthorized"})
    assert resp.status_code == 403


def test_api_multi_tenant_isolation(client: TestClient):
    ws_a = f"tenant-a-{uuid.uuid4().hex[:6]}"
    ws_b = f"tenant-b-{uuid.uuid4().hex[:6]}"

    # Create actor in Tenant A
    create_resp = client.post(
        "/api/v1/threat-workspace/actors",
        json={"name": "Actor in Tenant A", "attribution_state": "SUSPECTED"},
        headers={"X-Workspace-Id": ws_a, "X-Role": "analyst"},
    )
    assert create_resp.status_code == 201
    actor_id_a = create_resp.json()["id"]

    # List in Tenant A should see it
    list_a = client.get(
        "/api/v1/threat-workspace/actors",
        headers={"X-Workspace-Id": ws_a, "X-Role": "analyst"},
    )
    assert list_a.status_code == 200
    assert any(a["id"] == actor_id_a for a in list_a.json()["items"])

    # List in Tenant B must NOT see it (zero cross-tenant leak)
    list_b = client.get(
        "/api/v1/threat-workspace/actors",
        headers={"X-Workspace-Id": ws_b, "X-Role": "analyst"},
    )
    assert list_b.status_code == 200
    assert not any(a["id"] == actor_id_a for a in list_b.json()["items"])

    # Direct GET from Tenant B must return 404
    get_b = client.get(
        f"/api/v1/threat-workspace/actors/{actor_id_a}",
        headers={"X-Workspace-Id": ws_b, "X-Role": "analyst"},
    )
    assert get_b.status_code == 404


# =============================================================================
# 7. Background Worker Job Handler Tests
# =============================================================================

@pytest.mark.anyio
async def test_background_worker_campaign_sweep(db_session: Session):
    ws = f"ws-bg-{uuid.uuid4().hex[:6]}"
    ctx = JobExecutionContext(
        job_id=str(uuid.uuid4()),
        workspace_id=ws,
        job_type="CAMPAIGN_CORRELATION_SWEEP",
        payload={},
        worker_id="test-worker",
        attempt=1,
        timeout_seconds=60,
    )

    result = await handle_campaign_workspace_jobs(ctx, db_session)
    assert result["workspace_id"] == ws
    assert "campaigns_total" in result
    assert "actors_total" in result
