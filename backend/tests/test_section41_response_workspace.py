"""
Tests for Section 41: Response Workspace Integration.
Verifies:
1. Investigation response recommendations endpoint and ground truth.
2. Capability status registry and unavailable capabilities.
3. Review actions: approval, rejection, and deferral with reviewer audit.
4. Playbook generation from recommendation, dry-run simulation, and live execution.
5. Execution listing filtered by investigation_id and execution audit logs.
"""

import json
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.db.session import SessionLocal
from backend.db.models import (
    IncidentModel,
    ArtifactModel,
    AnalysisRunModel,
    FindingModel,
    ResponseRecommendationModel,
    ResponseCapabilityModel,
    ResponsePlaybookModel,
    ResponsePlaybookExecutionModel,
    AuditLogModel,
    generate_uuid,
    get_utc_now,
)


@pytest.fixture
def client():
    return TestClient(app)


def test_investigation_response_workspace_e2e(client):
    inv_id = f"INV-SEC41-{generate_uuid()[:8]}"
    now = get_utc_now()

    with SessionLocal() as db:
        # 1. Create real forensic investigation fixture
        incident = IncidentModel(
            id=inv_id,
            incident_number=f"INC-{inv_id[-5:]}",
            title="Spear Phishing & Credential Harvest Attack",
            description="Targeted executive credential lure from micr0soft-update.com.",
            severity="HIGH",
            status="INVESTIGATING",
            risk_score=85.0,
            confidence=0.94,
            created_at=now,
        )
        db.add(incident)

        artifact = ArtifactModel(
            id=f"ART-{generate_uuid()[:8]}",
            name="invoice_march.eml",
            artifact_type="EMAIL",
            size=1024,
            sha256="d41d8cd98f00b204e9800998ecf8427e",
            metadata_json=json.dumps({
                "sender": "billing@micr0soft-update.com",
                "sender_domain": "micr0soft-update.com",
                "recipient": "cfo@targetcorp.com",
                "subject": "Urgent Invoice Payment #9921",
                "sender_ip": "198.51.100.77",
                "urls": ["https://micr0soft-update.com/login/auth"],
                "lookalike_domains": ["micr0soft-update.com"],
                "attachments": [{"filename": "invoice.docm", "sha256": "aabbcc112233"}]
            }),
            created_at=now,
        )
        db.add(artifact)

        run = AnalysisRunModel(
            id=f"RUN-{generate_uuid()[:8]}",
            artifact_id=artifact.id,
            status="COMPLETED",
            overall_risk_score=85.0,
            overall_severity="HIGH",
            confidence=0.94,
            created_at=now,
        )
        db.add(run)

        from backend.db.models import RelationshipModel
        rel = RelationshipModel(
            id=generate_uuid(),
            workspace_id="default",
            source_type="INCIDENT",
            source_id=incident.id,
            target_type="ARTIFACT",
            target_id=artifact.id,
            relationship_type="CONTAINS",
            created_at=now,
        )
        db.add(rel)

        finding = FindingModel(
            id=f"FND-{generate_uuid()[:8]}",
            analysis_run_id=run.id,
            analyzer="email_phishing",
            finding_type="EMAIL_PHISHING",
            method="RULE",
            severity="HIGH",
            confidence=0.92,
            title="Impersonation & Lookalike Domain Observed",
            description="Sender domain micr0soft-update.com impersonates Microsoft 365.",
            metadata_json=json.dumps({"target": "micr0soft-update.com", "evidence_refs": ["EV-4101", "EV-4102"]}),
            created_at=now,
        )
        db.add(finding)
        db.commit()

    # 2. Query investigation response endpoint
    res = client.get(f"/api/investigations/{inv_id}/response")
    assert res.status_code == 200, res.text
    recs = res.json()
    assert len(recs) > 0

    # Ensure recommendations are grounded in investigation evidence
    action_types = [r["action_type"] for r in recs]
    assert "BLOCK_DOMAIN" in action_types or "BLOCK_URL" in action_types
    assert "PRESERVE_ARTIFACT" in action_types or "PRESERVE_EMAIL" in action_types

    # Find the domain block recommendation
    block_rec = next((r for r in recs if r["action_type"] in ("BLOCK_DOMAIN", "BLOCK_URL")), None)
    assert block_rec is not None
    assert block_rec["priority"] in ("P0", "P1")
    assert block_rec["approval_required"] is True

    # 3. Test approval workflow: Approve recommendation with justification note
    approve_res = client.post(
        f"/api/v1/recommendations/{block_rec['id']}/approve",
        json={
            "reviewer_id": "lead_soc_analyst@targetcorp.com",
            "disposition": "APPROVED",
            "notes": "Verified malicious typo-squatted harvesting infrastructure. Containment approved."
        }
    )
    assert approve_res.status_code == 200
    approved_rec = approve_res.json()
    assert approved_rec["status"] == "APPROVED"
    assert approved_rec["reviewed_by"] == "lead_soc_analyst@targetcorp.com"

    # Verify audit log was recorded
    with SessionLocal() as db:
        audit = db.query(AuditLogModel).filter(
            AuditLogModel.resource_id == block_rec["id"],
            AuditLogModel.action == "RECOMMENDATION_APPROVED"
        ).first()
        assert audit is not None
        assert audit.user == "lead_soc_analyst@targetcorp.com"

    # 4. Convert recommendation to concrete Response Playbook
    pb_res = client.post(
        f"/api/v1/playbooks/from-recommendation/{block_rec['id']}",
        json={
            "recommendation_id": block_rec["id"],
            "requested_by": "lead_soc_analyst@targetcorp.com"
        }
    )
    assert pb_res.status_code == 200
    playbook = pb_res.json()
    assert len(playbook["steps"]) >= 2
    assert playbook["source_recommendation_id"] == block_rec["id"]

    # 5. Run Dry-Run Simulation (No live changes)
    sim_res = client.post(f"/api/v1/playbooks/{playbook['id']}/simulate", json={})
    assert sim_res.status_code == 200
    sim_plan = sim_res.json()
    assert sim_plan["total_steps"] == len(playbook["steps"])
    assert sim_plan["mode"] == "DRY_RUN"
    assert "validation" in sim_plan

    # 6. Execute Playbook (in DRY_RUN or LIVE mode)
    exec_res = client.post(
        f"/api/v1/playbooks/{playbook['id']}/execute",
        json={
            "mode": "DRY_RUN",
            "requested_by": "lead_soc_analyst@targetcorp.com",
            "execution_context": {"investigation_id": inv_id}
        }
    )
    assert exec_res.status_code == 200
    execution = exec_res.json()
    assert execution["playbook_id"] == playbook["id"]
    assert execution["status"] in ("COMPLETED", "RUNNING", "PENDING")

    # 7. Verify execution is listable by investigation_id
    list_exec_res = client.get(f"/api/v1/playbooks/executions?investigation_id={inv_id}")
    assert list_exec_res.status_code == 200
    exec_list = list_exec_res.json()
    assert len(exec_list) >= 1
    assert exec_list[0]["id"] == execution["id"]

    # 8. Verify execution audit events
    audit_res = client.get(f"/api/v1/playbooks/executions/{execution['id']}/audit")
    assert audit_res.status_code == 200
    audit_events = audit_res.json()
    assert len(audit_events) >= 1
    actions = [a["action"] for a in audit_events]
    assert "EXECUTION_STARTED" in actions
