"""
Section 68: Evidence & Forensics Workspace Test Suite.
Validates:
- Evidence registration with SHA-256, SHA-1, MD5 and MIME detection.
- Cryptographic integrity verification & mismatch detection.
- Safe bounded text and hex previews.
- Preservation and legal-hold lifecycle management with justification.
- Immutable chain-of-custody ledger records.
- Parent-to-child derivation lineage and tool provenance.
- Signed forensic export package manifest with package digest.
- Case and investigation linkage.
- Multi-tenant isolation and RBAC.
- Background job worker handler.
"""
from __future__ import annotations

import base64
import hashlib
import json
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.db.models import (
    Base,
    EvidenceCustodyEventModel,
    EvidenceModel,
    FindingEvidenceModel,
    FindingModel,
)
from backend.db.session import get_db
from backend.main import app
from backend.schemas.evidence_workspace import (
    CustodyEventTypeEnum,
    EvidenceClassificationEnum,
    EvidenceCollectionMethodEnum,
    EvidenceCustodyAddRequest,
    EvidenceDerivationRequest,
    EvidenceNoteAddRequest,
    EvidencePreservationRequest,
    EvidencePreservationStatusEnum,
    EvidenceRegistrationRequest,
    EvidenceRetentionPolicyEnum,
    EvidenceSourceTypeEnum,
)
from backend.schemas.jobs import JobTypeEnum
from backend.services.background_job_worker import (
    JobExecutionContext,
    handle_evidence_workspace_jobs,
)
from backend.services.evidence_service import EvidenceService
from backend.services.evidence_storage import evidence_storage


# In-memory test DB
@pytest.fixture(scope="function")
def db_session():
    test_engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=test_engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=test_engine)


@pytest.fixture(scope="function")
def client(db_session):
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    test_client = TestClient(app)
    yield test_client
    app.dependency_overrides.clear()


# =============================================================================
# Test Cases
# =============================================================================

def test_evidence_registration_hashes_and_custody(db_session):
    """Verifies SHA-256, SHA-1, MD5 calculation and initial ACQUIRED chain-of-custody event."""
    sample_data = b"CyberGuard Forensic Evidence Acquisition Sample Data 2026"
    expected_sha256 = hashlib.sha256(sample_data).hexdigest()
    expected_sha1 = hashlib.sha1(sample_data).hexdigest()
    expected_md5 = hashlib.md5(sample_data).hexdigest()

    req = EvidenceRegistrationRequest(
        original_filename="memory_dump_segment.raw",
        source_type=EvidenceSourceTypeEnum.FILE,
        collection_method=EvidenceCollectionMethodEnum.MANUAL_UPLOAD,
        source_reference="WORKSTATION-SEC-09",
        collector="Lead Investigator",
        classification=EvidenceClassificationEnum.RESTRICTED,
        retention_policy=EvidenceRetentionPolicyEnum.LEGAL_HOLD,
        notes="Carved memory segment from compromised endpoint.",
    )

    detail = EvidenceService.register_evidence(
        db=db_session,
        raw_bytes=sample_data,
        filename="memory_dump_segment.raw",
        req=req,
        current_user="Analyst Alpha",
        tenant_id="tenant-alpha",
    )

    assert detail.sha256 == expected_sha256
    assert detail.sha1 == expected_sha1
    assert detail.md5 == expected_md5
    assert detail.size == len(sample_data)
    assert detail.classification == "RESTRICTED"
    assert detail.integrity_status == "VERIFIED"
    assert detail.evidence_id.startswith("EVD-")

    # Verify custody event
    assert len(detail.custody_events) == 1
    c_event = detail.custody_events[0]
    assert c_event.event_type == "ACQUIRED"
    assert c_event.actor_id == "Analyst Alpha"
    assert c_event.integrity_hash == expected_sha256


def test_evidence_list_and_metrics(db_session):
    """Verifies evidence listing, search query, and metrics calculation."""
    for i in range(3):
        EvidenceService.register_evidence(
            db=db_session,
            raw_bytes=f"Test evidence content {i}".encode(),
            filename=f"artifact_{i}.log",
            req=EvidenceRegistrationRequest(
                original_filename=f"artifact_{i}.log",
                source_type=EvidenceSourceTypeEnum.FILE,
                classification=EvidenceClassificationEnum.INTERNAL,
            ),
            tenant_id="tenant-test",
        )

    res = EvidenceService.list_evidence(db=db_session, tenant_id="tenant-test", page=1, page_size=10)
    assert res.total == 3
    assert len(res.items) == 3
    assert res.metrics.total_evidence == 3
    assert res.metrics.verified_count == 3


def test_integrity_reverification_pass_and_mismatch(db_session):
    """Verifies on-demand integrity verification detecting authentic vs tampered artifacts."""
    content = b"Authentic payload for chain of custody verification"
    req = EvidenceRegistrationRequest(original_filename="payload.bin")
    detail = EvidenceService.register_evidence(
        db=db_session,
        raw_bytes=content,
        filename="payload.bin",
        req=req,
        tenant_id="tenant-audit",
    )

    # 1. Normal verification should match
    res_pass = EvidenceService.verify_integrity(
        db=db_session,
        identifier=detail.id,
        current_user="Auditor",
        tenant_id="tenant-audit",
    )
    assert res_pass.match is True
    assert res_pass.status == "VERIFIED"

    # 2. Tamper stored bytes directly in storage to simulate corruption/tampering
    record = db_session.query(EvidenceModel).filter(EvidenceModel.id == detail.id).first()
    storage_key = record.storage_reference
    tampered_bytes = b"TAMPERED CORRUPTED CONTENT BYPASS"
    evidence_storage.store_bytes(data=tampered_bytes, custom_key=storage_key)

    res_fail = EvidenceService.verify_integrity(
        db=db_session,
        identifier=detail.id,
        current_user="Auditor",
        tenant_id="tenant-audit",
    )
    assert res_fail.match is False
    assert res_fail.status == "MISMATCH"
    assert "CRITICAL ALERT" in res_fail.message


def test_safe_preview_text_and_hex(db_session):
    """Verifies safe text preview for readable logs and formatted hex dump for binary files."""
    # Text artifact
    text_content = b"GET /admin/login.php HTTP/1.1\r\nHost: evil.com\r\nUser-Agent: AttackBot\r\n"
    text_detail = EvidenceService.register_evidence(
        db=db_session,
        raw_bytes=text_content,
        filename="access.log",
        req=EvidenceRegistrationRequest(original_filename="access.log"),
        tenant_id="tenant-preview",
    )
    text_prev = EvidenceService.get_preview(db=db_session, identifier=text_detail.id, tenant_id="tenant-preview")
    assert text_prev.preview_type == "text"
    assert "GET /admin/login.php" in text_prev.preview_content

    # Binary artifact
    bin_content = bytes([0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    bin_detail = EvidenceService.register_evidence(
        db=db_session,
        raw_bytes=bin_content,
        filename="malware.elf",
        req=EvidenceRegistrationRequest(original_filename="malware.elf"),
        tenant_id="tenant-preview",
    )
    bin_prev = EvidenceService.get_preview(db=db_session, identifier=bin_detail.id, tenant_id="tenant-preview")
    assert bin_prev.preview_type == "hex"
    assert "7f 45 4c 46" in bin_prev.preview_content


def test_preservation_and_legal_hold(db_session):
    """Verifies updating preservation status with mandatory justification and custody logging."""
    detail = EvidenceService.register_evidence(
        db=db_session,
        raw_bytes=b"Litigation sample evidence",
        filename="contract_dispute.pdf",
        req=EvidenceRegistrationRequest(original_filename="contract_dispute.pdf"),
        tenant_id="tenant-preservation",
    )

    # Set Legal Hold
    updated = EvidenceService.set_preservation(
        db=db_session,
        identifier=detail.id,
        req=EvidencePreservationRequest(
            preservation_status=EvidencePreservationStatusEnum.ON_HOLD,
            reason="Formal preservation hold ordered by Legal Counsel (Ref: LC-9981).",
            notes="Do not destroy or purge.",
        ),
        current_user="Legal Analyst",
        tenant_id="tenant-preservation",
    )
    assert updated.preservation_status == "ON_HOLD"
    assert updated.preservation_actor == "Legal Analyst"
    assert len(updated.custody_events) == 2
    assert updated.custody_events[-1].event_type == "PRESERVED"


def test_chain_of_custody_append_event(db_session):
    """Verifies appending immutable chain-of-custody transactions."""
    detail = EvidenceService.register_evidence(
        db=db_session,
        raw_bytes=b"Hard drive bitstream image segment",
        filename="hdd.img",
        req=EvidenceRegistrationRequest(original_filename="hdd.img"),
        tenant_id="tenant-custody",
    )

    custody_resp = EvidenceService.add_custody_event(
        db=db_session,
        identifier=detail.id,
        req=EvidenceCustodyAddRequest(
            event_type=CustodyEventTypeEnum.TRANSFERRED,
            source="Evidence Locker 4B",
            destination="Digital Forensics Lab - Station 2",
            reason="Transferred for deep malware unpacking.",
            notes="Courier: Officer Jones",
        ),
        current_user="Forensic Specialist",
        tenant_id="tenant-custody",
    )

    assert custody_resp.event_type == "TRANSFERRED"
    assert custody_resp.source == "Evidence Locker 4B"
    assert custody_resp.destination == "Digital Forensics Lab - Station 2"

    refreshed = EvidenceService.get_evidence_detail(db=db_session, identifier=detail.id, tenant_id="tenant-custody")
    assert len(refreshed.custody_events) == 2


def test_child_evidence_derivation_lineage(db_session):
    """Verifies child evidence creation preserving parent-child lineage and tool provenance."""
    parent_bytes = b"Parent raw pcap capture containing embedded executable"
    parent = EvidenceService.register_evidence(
        db=db_session,
        raw_bytes=parent_bytes,
        filename="capture.pcap",
        req=EvidenceRegistrationRequest(original_filename="capture.pcap"),
        tenant_id="tenant-deriv",
    )

    child_payload = b"Carved payload executable extracted from stream"
    child_b64 = base64.b64encode(child_payload).decode("utf-8")

    derived = EvidenceService.derive_evidence(
        db=db_session,
        parent_identifier=parent.id,
        req=EvidenceDerivationRequest(
            transformation_tool="NetworkMiner Stream Carve",
            tool_version="2.7.3",
            transformation_description="Carved HTTP POST byte stream payload.",
            child_filename="carved_payload.bin",
            child_bytes_base64=child_b64,
        ),
        current_user="Malware Analyst",
        tenant_id="tenant-deriv",
    )

    assert derived.parent_evidence_id == parent.id
    assert derived.derivation_metadata.get("tool") == "NetworkMiner Stream Carve"

    # Lineage must link parent and child
    assert any(p.relation == "PARENT" and p.evidence_id == parent.evidence_id for p in derived.provenance_lineage)

    # Check parent detail has child in lineage
    parent_refreshed = EvidenceService.get_evidence_detail(db=db_session, identifier=parent.id, tenant_id="tenant-deriv")
    assert any(p.relation == "CHILD" and p.evidence_id == derived.evidence_id for p in parent_refreshed.provenance_lineage)


def test_forensic_export_manifest(db_session):
    """Verifies generating a signed forensic export manifest package with package hash."""
    detail = EvidenceService.register_evidence(
        db=db_session,
        raw_bytes=b"Exportable forensic artifact bytes",
        filename="court_evidence.raw",
        req=EvidenceRegistrationRequest(original_filename="court_evidence.raw"),
        tenant_id="tenant-export",
    )

    manifest = EvidenceService.export_evidence_manifest(
        db=db_session,
        identifier=detail.id,
        current_user="Senior Forensic Examiner",
        tenant_id="tenant-export",
    )

    assert manifest.manifest_id.startswith("MNF-")
    assert manifest.sha256 == detail.sha256
    assert len(manifest.package_hash_sha256) == 64
    assert manifest.custody_events_count >= 1
    assert "custody_chain" in manifest.manifest_json


def test_api_rest_endpoints(client, db_session):
    """Tests FastAPI REST routes for listing, upload, detail, and preview."""
    # 1. Register evidence via JSON
    reg_payload = {
        "original_filename": "api_test.json",
        "source_type": "FILE",
        "collection_method": "API",
        "classification": "INTERNAL",
        "raw_content_utf8": '{"status": "incident_detected", "severity": "HIGH"}',
    }
    resp = client.post("/api/v1/evidence/register", json=reg_payload, headers={"X-Workspace-ID": "default"})
    assert resp.status_code == 200
    data = resp.json()
    evidence_id = data["evidence_id"]
    ev_uuid = data["id"]
    assert evidence_id.startswith("EVD-")

    # 2. List evidence
    list_resp = client.get("/api/v1/evidence", headers={"X-Workspace-ID": "default"})
    assert list_resp.status_code == 200
    assert list_resp.json()["total"] >= 1

    # 3. Get detail
    det_resp = client.get(f"/api/v1/evidence/{evidence_id}", headers={"X-Workspace-ID": "default"})
    assert det_resp.status_code == 200
    assert det_resp.json()["original_filename"] == "api_test.json"

    # 4. Preview
    prev_resp = client.get(f"/api/v1/evidence/{evidence_id}/preview", headers={"X-Workspace-ID": "default"})
    assert prev_resp.status_code == 200
    assert prev_resp.json()["preview_type"] == "text"

    # 5. Verify integrity
    ver_resp = client.post(f"/api/v1/evidence/{evidence_id}/verify", headers={"X-Workspace-ID": "default"})
    assert ver_resp.status_code == 200
    assert ver_resp.json()["match"] is True

    # 6. Add forensic note
    note_resp = client.post(
        f"/api/v1/evidence/{evidence_id}/notes",
        json={"note_text": "Reviewed payload, confirmed high-severity beacon signature.", "category": "ANALYSIS"},
        headers={"X-Workspace-ID": "default"},
    )
    assert note_resp.status_code == 200
    assert len(note_resp.json()["forensic_notes"]) >= 1

    # 7. Export manifest
    man_resp = client.get(f"/api/v1/evidence/{evidence_id}/export-manifest", headers={"X-Workspace-ID": "default"})
    assert man_resp.status_code == 200
    assert man_resp.json()["manifest_id"].startswith("MNF-")


def test_tenant_isolation_and_rbac(client, db_session):
    """Verifies strict tenant data segregation and RBAC rejection of unauthorized requests."""
    # Register in Tenant A
    EvidenceService.register_evidence(
        db=db_session,
        raw_bytes=b"Tenant A secret evidence",
        filename="tenant_a.bin",
        req=EvidenceRegistrationRequest(original_filename="tenant_a.bin"),
        tenant_id="tenant-a",
    )

    # Query from Tenant B -> Should return 0 items
    resp_b = client.get("/api/v1/evidence", headers={"X-Workspace-ID": "tenant-b"})
    assert resp_b.status_code == 200
    assert resp_b.json()["total"] == 0

    # Unauthorized role -> 403 Forbidden
    unauth_resp = client.get("/api/v1/evidence", headers={"X-Role": "unauthorized"})
    assert unauth_resp.status_code == 403


def test_evidence_background_jobs(db_session):
    """Verifies execution of background integrity sweeps and forensic manifest packages."""
    import asyncio

    ev = EvidenceService.register_evidence(
        db=db_session,
        raw_bytes=b"Job worker background testing payload",
        filename="worker_sample.bin",
        req=EvidenceRegistrationRequest(original_filename="worker_sample.bin"),
        tenant_id="tenant-job",
    )

    ctx_sweep = JobExecutionContext(
        job_id="job-sweep-1",
        workspace_id="tenant-job",
        job_type=JobTypeEnum.EVIDENCE_INTEGRITY_SWEEP.value,
        payload={},
        worker_id="worker-01",
        attempt=1,
        timeout_seconds=60,
    )

    sweep_res = asyncio.run(handle_evidence_workspace_jobs(ctx_sweep, db_session))
    assert sweep_res["total_audited"] >= 1
    assert sweep_res["verified"] >= 1

    ctx_pkg = JobExecutionContext(
        job_id="job-pkg-1",
        workspace_id="tenant-job",
        job_type=JobTypeEnum.EVIDENCE_FORENSIC_PACKAGE.value,
        payload={"evidence_id": ev.evidence_id},
        worker_id="worker-01",
        attempt=1,
        timeout_seconds=60,
    )

    pkg_res = asyncio.run(handle_evidence_workspace_jobs(ctx_pkg, db_session))
    assert pkg_res["manifest_id"].startswith("MNF-")
    assert pkg_res["evidence_id"] == ev.evidence_id
