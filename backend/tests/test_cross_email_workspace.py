import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.db.session import SessionLocal, init_db
from backend.db.models import CaseModel, AnalystDecisionModel, AuditLogModel

client = TestClient(app)


@pytest.fixture(scope="module", autouse=True)
def setup_database():
    init_db()


def test_cross_email_analyze_triggers_related_activity():
    """
    Test that analyzing the primary demo email triggers:
    - RELATED ACTIVITY DETECTED
    - 16 potentially related emails
    - Campaign confidence: 89%
    - 6 strongest relationship explanations
    """
    payload = {
        "id": "EML-2026-8819",
        "subject": "URGENT: Executive Wire Transfer Instructions - Q3 Vendor Settlement #8819",
        "sender": "robert.vance@bank-corp-update.com",
        "from": "robert.vance@bank-corp-update.com",
        "reply_to": "financial-operations-secure@wire-transfer-node.ru",
        "ips": ["185.220.101.42"],
        "urls": ["https://bank-corp-update.com/auth/v2/secure_login.php?client=token9912"],
        "domains": ["bank-corp-update.com", "wire-transfer-node.ru"],
        "campaign": "C-042"
    }

    response = client.post("/api/cross-investigation/analyze", json=payload)
    assert response.status_code == 200, response.text
    data = response.json()

    assert data["related_activity_detected"] is True
    assert data["related_count"] == 16
    assert data["campaign_confidence"] == 89.0
    assert data["campaign_id"] == "C-042"
    assert data["is_synthetic"] is True

    # Validate the 6 required strongest relationship explanations
    strongest = data["strongest_relationships"]
    assert "same redirect domain" in strongest
    assert "same ASN" in strongest
    assert "highly similar HTML template" in strongest
    assert "similar subject" in strongest
    assert "same Reply-To domain" in strongest
    assert "overlapping sender infrastructure" in strongest

    # Validate related emails list
    emails = data["related_emails"]
    assert len(emails) == 16
    first = emails[0]
    assert "subject" in first
    assert "sender" in first
    assert "recipient" in first
    assert "threat_score" in first
    assert "similarity" in first
    assert "status" in first
    assert first["is_synthetic"] is True

    # Validate attack timeline
    timeline = data["timeline"]
    assert len(timeline) >= 5
    assert timeline[0]["time_display"] == "09:14"
    assert "Email A delivered" in timeline[0]["title"]


def test_comparison_mode_for_selected_emails():
    """
    Test comparison mode on 3 selected emails:
    - Verifies 10 forensic categories
    - Verifies identical, similar, conflicting, and unique highlights
    - Tests validation constraint (must be 2-5 emails)
    """
    # Test invalid count (<2 emails)
    bad_req = client.post("/api/cross-investigation/compare", json={"email_ids": ["EML-2026-8819"]})
    assert bad_req.status_code in (400, 422)

    # Test valid comparison of 3 emails
    req_payload = {
        "email_ids": ["EML-2026-8819", "EML-2026-8812", "EML-2026-8805"]
    }
    response = client.post("/api/cross-investigation/compare", json=req_payload)
    assert response.status_code == 200, response.text
    data = response.json()

    assert len(data["emails"]) == 3
    categories = {c["category_id"]: c for c in data["categories"]}
    expected_categories = [
        "headers", "auth", "relay", "domains", "ips",
        "urls", "content", "attachments", "threat_scores", "fingerprints"
    ]
    for exp_cat in expected_categories:
        assert exp_cat in categories, f"Missing category: {exp_cat}"

    # Summary verification
    summary = data["summary"]
    assert "identical" in summary
    assert "similar" in summary
    assert "conflicting" in summary
    assert "unique" in summary
    assert summary["identical"] > 0
    assert data["overall_alignment_percentage"] > 70.0


def test_focused_investigation_graph_generation():
    """
    Test that the cross-email investigation graph generates:
    - Email A -> URL X, Email B -> URL X
    - Email A -> IP Y
    - Domain A -> ASN Z, Domain B -> ASN Z
    - Node filtering by type
    """
    graph_req = {
        "email_ids": ["EML-2026-8819", "EML-2026-8812"],
        "node_types": ["Email", "Domain", "IP", "URL", "ASN", "Campaign"]
    }
    response = client.post("/api/cross-investigation/graph", json=graph_req)
    assert response.status_code == 200, response.text
    graph_data = response.json()

    nodes = {n["id"]: n for n in graph_data["nodes"]}
    assert "email:EML-2026-8819" in nodes
    assert "email:EML-2026-8812" in nodes
    assert "url:https://bank-corp-update.com/auth/v2/secure_login.php" in nodes
    assert "asn:AS49281" in nodes
    assert "campaign:C-042" in nodes

    edges = graph_data["edges"]
    edge_pairs = {(e["source"], e["target"]) for e in edges}

    # Verify Email -> URL X
    assert ("email:EML-2026-8819", "url:https://bank-corp-update.com/auth/v2/secure_login.php") in edge_pairs
    assert ("email:EML-2026-8812", "url:https://bank-corp-update.com/auth/v2/secure_login.php") in edge_pairs

    # Verify Domain -> ASN Z
    assert ("domain:bank-corp-update.com", "asn:AS49281") in edge_pairs
    assert ("domain:wire-transfer-node.ru", "asn:AS49281") in edge_pairs


def test_false_positive_feedback_persistence():
    """
    Test false positive feedback loop:
    - Marking two emails unrelated persists the decision
    - Verifies record is written to analyst_decisions table
    - Verifies subsequent correlation updates status to Unrelated
    """
    decision_req = {
        "email_id_a": "EML-2026-8819",
        "email_id_b": "EML-2026-8714",
        "decision": "mark_unrelated",
        "analyst": "SOC Lead Analyst",
        "notes": "Analyst determined EML-8714 belongs to different legitimate test batch"
    }

    response = client.post("/api/cross-investigation/decision", json=decision_req)
    assert response.status_code == 200, response.text
    saved = response.json()
    assert saved["decision"] == "unrelated"
    assert saved["analyst"] == "SOC Lead Analyst"

    # Verify decision listing endpoint
    list_res = client.get("/api/cross-investigation/decisions")
    assert list_res.status_code == 200
    decisions = list_res.json()
    assert any(d["email_id_b"] == "EML-2026-8714" and d["decision"] == "unrelated" for d in decisions)

    # Re-run correlation and check status is updated to Unrelated
    analyze_payload = {
        "id": "EML-2026-8819",
        "subject": "URGENT: Executive Wire Transfer Instructions - Q3 Vendor Settlement #8819",
        "campaign": "C-042"
    }
    re_res = client.post("/api/cross-investigation/analyze", json=analyze_payload)
    assert re_res.status_code == 200
    re_data = re_res.json()
    eml_8714 = next((e for e in re_data["related_emails"] if e["id"] == "EML-2026-8714"), None)
    assert eml_8714 is not None
    assert eml_8714["status"] == "Unrelated"


def test_case_integration_action():
    """
    Test adding related emails to an investigation case.
    """
    import uuid
    db = SessionLocal()
    case_num = f"CASE-T-{uuid.uuid4().hex[:8]}"
    try:
        # Create test case
        case = CaseModel(
            case_number=case_num,
            title="Cross-Email Investigation Test Case",
            severity="high",
            status="open"
        )
        db.add(case)
        db.commit()
        db.refresh(case)
        case_id = case.id
    finally:
        db.close()

    decision_req = {
        "email_id_a": "EML-2026-8819",
        "email_id_b": "EML-2026-8812",
        "decision": "added_to_case",
        "case_id": case_id,
        "analyst": "SOC Tier 2",
        "notes": "Added correlated wire lure to active incident case"
    }
    res = client.post("/api/cross-investigation/decision", json=decision_req)
    assert res.status_code == 200
    assert res.json()["decision"] == "added_to_case"
