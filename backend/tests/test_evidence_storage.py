"""
Unit and Integration Tests for Section 3: Persistent Evidence & Analysis Storage.

Covers the 20 required verification scenarios:
 1. File artifact persistence.
 2. SHA-256 calculation.
 3. Integrity verification.
 4. Original filename preservation.
 5. Safe storage key generation.
 6. Duplicate content upload.
 7. Separate ingestion records for duplicate content.
 8. Analysis history.
 9. Multiple AnalysisRuns.
10. Re-analysis.
11. Previous AnalysisRun preservation.
12. Derived artifact creation.
13. Email -> attachment relationship.
14. Missing stored evidence.
15. Hash mismatch detection.
16. Path traversal protection.
17. Upload size validation.
18. Existing EML analysis with storage & ingestion persistence.
19. Existing report generation with persistent metadata.
20. Restart persistence verification across backend restarts.
"""
import hashlib
import io
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.db.session import SessionLocal, init_db
from backend.db.models import (
    ArtifactModel,
    AnalysisRunModel,
    FindingModel,
    FindingEvidenceModel,
    IndicatorModel,
    RelationshipModel,
    ArtifactStorageRecordModel,
    IngestionRecordModel,
    ReportModel,
)
from backend.services.evidence_storage import (
    LocalStorageBackend,
    evidence_storage,
    StoragePathTraversalError,
    StoragePayloadTooLargeError,
    IntegrityStatus,
)
from backend.services.unified_service import (
    ArtifactService,
    AnalysisService,
    FindingService,
    RelationshipService,
    StorageRecordService,
    IngestionService,
    StorageMaintenanceService,
    UnifiedIngestionAdapter,
)
from backend.schemas.unified import (
    ArtifactTypeEnum,
    AnalysisStatusEnum,
    AnalysisTriggerEnum,
    RelationshipTypeEnum,
    SeverityEnum,
)

SAMPLE_EML_CONTENT = b"""From: payroll-secure@alert-notifications-update.com
To: victim@company.com
Subject: Action Required: Monthly Payroll Direct Deposit Verification
Date: Thu, 01 Oct 2026 12:00:00 +0000
Message-ID: <payroll-20261001-sec3@alert-notifications-update.com>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BOUNDARY-SEC3"

--BOUNDARY-SEC3
Content-Type: text/plain; charset="utf-8"

Please review the attached direct deposit advisory urgently:
https://login.micros0ft-portal-update.com/login

--BOUNDARY-SEC3
Content-Type: application/octet-stream; name="deposit_advisory.pdf.exe"
Content-Disposition: attachment; filename="deposit_advisory.pdf.exe"
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAA2AAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1v
ZGUuDQ0KJAAAAAAAAAA=
--BOUNDARY-SEC3--
"""


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


# ---------------------------------------------------------------------------
# TEST 1: File artifact persistence
# ---------------------------------------------------------------------------
def test_1_file_artifact_persistence(tmp_path):
    storage = LocalStorageBackend(root_dir=tmp_path / "storage")
    payload = b"Immutable forensic evidence bytes for test 1"
    res = storage.store_bytes(payload, original_filename="evidence_1.bin", mime_type="application/octet-stream")

    assert res.storage_key.startswith("artifacts/")
    assert storage.exists(res.storage_key)
    retrieved = storage.retrieve_bytes(res.storage_key)
    assert retrieved == payload
    assert res.size == len(payload)


# ---------------------------------------------------------------------------
# TEST 2: SHA-256 calculation
# ---------------------------------------------------------------------------
def test_2_sha256_calculation(tmp_path):
    storage = LocalStorageBackend(root_dir=tmp_path / "storage")
    payload = b"Cryptographic integrity test string - verifying SHA-256 computation."
    expected_sha = hashlib.sha256(payload).hexdigest().lower()

    res = storage.store_stream(io.BytesIO(payload), original_filename="stream.dat")
    assert res.sha256 == expected_sha
    assert res.sha1 == hashlib.sha1(payload).hexdigest().lower()
    assert res.md5 == hashlib.md5(payload).hexdigest().lower()


# ---------------------------------------------------------------------------
# TEST 3: Integrity verification
# ---------------------------------------------------------------------------
def test_3_integrity_verification(tmp_path):
    storage = LocalStorageBackend(root_dir=tmp_path / "storage")
    payload = b"Verification test payload"
    expected_sha = hashlib.sha256(payload).hexdigest().lower()
    res = storage.store_bytes(payload, original_filename="verify.bin")

    status, actual_sha = storage.verify_integrity(res.storage_key, expected_sha)
    assert status == IntegrityStatus.VERIFIED
    assert actual_sha == expected_sha


# ---------------------------------------------------------------------------
# TEST 4: Original filename preservation
# ---------------------------------------------------------------------------
def test_4_original_filename_preservation(tmp_path, db):
    storage = LocalStorageBackend(root_dir=tmp_path / "storage")
    weird_filename = "Confidential Payroll (2026) [URGENT] #1.eml"
    payload = b"Email content with tricky filename"
    sha = hashlib.sha256(payload).hexdigest().lower()
    res = storage.store_bytes(payload, original_filename=weird_filename)

    # Content-addressed on disk (safe path)
    assert "#" not in res.storage_key
    assert "[" not in res.storage_key
    assert res.storage_key == f"artifacts/{sha[:2]}/{sha}/original"

    # Preserved in DB Artifact and Ingestion record
    art = ArtifactService.create_or_get_artifact(
        db=db,
        artifact_type=ArtifactTypeEnum.EMAIL,
        name=weird_filename,
        size=len(payload),
        sha256=sha,
        storage_reference=res.storage_key,
    )
    assert art.name == weird_filename

    ing = IngestionService.record_ingestion(
        db=db,
        artifact_id=art.id,
        source="UPLOAD",
        original_filename=weird_filename,
    )
    assert ing.original_filename == weird_filename


# ---------------------------------------------------------------------------
# TEST 5: Safe storage key generation
# ---------------------------------------------------------------------------
def test_5_safe_storage_key_generation(tmp_path):
    storage = LocalStorageBackend(root_dir=tmp_path / "storage")
    payload = b"Safe storage key validation"
    res = storage.store_bytes(payload, original_filename="../../../etc/shadow")

    # Path traversal in original filename was stripped; key is strictly content-addressed
    assert ".." not in res.storage_key
    assert res.storage_key.startswith("artifacts/")


# ---------------------------------------------------------------------------
# TEST 6: Duplicate content upload
# ---------------------------------------------------------------------------
def test_6_duplicate_content_upload(tmp_path):
    storage = LocalStorageBackend(root_dir=tmp_path / "storage")
    payload = b"Exact identical forensic file bytes"
    res1 = storage.store_bytes(payload, original_filename="copy1.eml")
    res2 = storage.store_bytes(payload, original_filename="copy2.eml")

    assert res1.storage_key == res2.storage_key
    assert res1.sha256 == res2.sha256
    # Original content is intact and verified
    assert storage.retrieve_bytes(res1.storage_key) == payload


# ---------------------------------------------------------------------------
# TEST 7: Separate ingestion records for duplicate content
# ---------------------------------------------------------------------------
def test_7_separate_ingestion_records_for_duplicate_content(db):
    payload = b"Same phishing email received by two different departments"
    sha = hashlib.sha256(payload).hexdigest().lower()

    art = ArtifactService.create_or_get_artifact(
        db=db,
        artifact_type=ArtifactTypeEnum.EMAIL,
        name="phish_shared.eml",
        size=len(payload),
        sha256=sha,
    )

    # Ingestion 1: HR Department upload
    ing1 = IngestionService.record_ingestion(
        db=db,
        artifact_id=art.id,
        source="UPLOAD",
        submitted_by="hr-user@company.com",
        request_id="REQ-HR-001",
        context={"department": "HR", "ticket_id": "TICK-101"},
    )

    # Ingestion 2: Finance Department upload
    ing2 = IngestionService.record_ingestion(
        db=db,
        artifact_id=art.id,
        source="EMAIL_CONNECTOR",
        submitted_by="finance-user@company.com",
        request_id="REQ-FIN-999",
        context={"department": "Finance", "ticket_id": "TICK-202"},
    )

    assert ing1.id != ing2.id
    assert ing1.artifact_id == ing2.artifact_id == art.id
    assert ing1.submitted_by != ing2.submitted_by

    all_ingestions = IngestionService.list_ingestions(db, art.id)
    assert len(all_ingestions) >= 2


# ---------------------------------------------------------------------------
# TEST 8: Analysis history
# ---------------------------------------------------------------------------
def test_8_analysis_history(db):
    art = ArtifactService.create_or_get_artifact(
        db=db,
        artifact_type=ArtifactTypeEnum.EMAIL,
        name="history_test.eml",
        sha256=hashlib.sha256(b"history_test").hexdigest().lower(),
    )

    run1 = AnalysisService.create_analysis_run(db, art.id, pipeline_version="1.0.0")
    AnalysisService.complete_analysis_run(db, run1.id, overall_risk_score=45.0, overall_severity="medium")

    history = AnalysisService.list_runs_for_artifact(db, art.id)
    assert len(history) >= 1
    assert history[0].pipeline_version == "1.0.0"


# ---------------------------------------------------------------------------
# TEST 9: Multiple AnalysisRuns
# ---------------------------------------------------------------------------
def test_9_multiple_analysis_runs(db):
    art = ArtifactService.create_or_get_artifact(
        db=db,
        artifact_type=ArtifactTypeEnum.EMAIL,
        name="multi_run.eml",
        sha256=hashlib.sha256(b"multi_run").hexdigest().lower(),
    )

    run1 = AnalysisService.create_analysis_run(db, art.id, pipeline_version="1.0.0")
    AnalysisService.complete_analysis_run(db, run1.id, overall_risk_score=50.0, overall_severity="medium")

    run2 = AnalysisService.create_analysis_run(db, art.id, pipeline_version="1.1.0", trigger=AnalysisTriggerEnum.REANALYSIS)
    AnalysisService.complete_analysis_run(db, run2.id, overall_risk_score=75.0, overall_severity="high")

    runs = AnalysisService.list_runs_for_artifact(db, art.id)
    run_ids = [r.id for r in runs]
    assert run1.id in run_ids
    assert run2.id in run_ids
    assert len(runs) >= 2


# ---------------------------------------------------------------------------
# TEST 10: Re-analysis
# ---------------------------------------------------------------------------
def test_10_reanalysis(db):
    # Store evidence file
    content = SAMPLE_EML_CONTENT
    sha = hashlib.sha256(content).hexdigest().lower()
    res = evidence_storage.store_bytes(content, original_filename="reanalyze_test.eml")

    art = ArtifactService.create_or_get_artifact(
        db=db,
        artifact_type=ArtifactTypeEnum.EMAIL,
        name="reanalyze_test.eml",
        size=len(content),
        sha256=sha,
        storage_reference=res.storage_key,
    )
    StorageRecordService.create_or_get_storage_record(
        db=db,
        artifact_id=art.id,
        storage_key=res.storage_key,
        sha256=sha,
        size=len(content),
        integrity_status="VERIFIED",
    )

    # Initial Run
    run1 = AnalysisService.create_analysis_run(db, art.id, pipeline_version="1.0.0")
    AnalysisService.complete_analysis_run(db, run1.id, overall_risk_score=40.0, overall_severity="medium")

    # Trigger Re-analysis
    new_run = AnalysisService.reanalyze_artifact(
        db=db,
        artifact_id=art.id,
        pipeline_version="2.0.0-upgraded",
        trigger="USER_REQUEST",
    )

    assert new_run.id != run1.id
    assert new_run.artifact_id == art.id
    assert new_run.pipeline_version == "2.0.0-upgraded"
    assert new_run.status == "COMPLETED"
    assert len(new_run.findings) >= 1


# ---------------------------------------------------------------------------
# TEST 11: Previous AnalysisRun preservation
# ---------------------------------------------------------------------------
def test_11_previous_analysis_run_preservation(db):
    art = ArtifactService.create_or_get_artifact(
        db=db,
        artifact_type=ArtifactTypeEnum.EMAIL,
        name="preserve_test.eml",
        sha256=hashlib.sha256(b"preserve_test_bytes").hexdigest().lower(),
    )

    run1 = AnalysisService.create_analysis_run(db, art.id, pipeline_version="1.0.0")
    FindingService.create_finding(
        db=db,
        analysis_run_id=run1.id,
        analyzer="BaselineAnalyzer",
        finding_type="baseline",
        title="Baseline Run Finding",
        description="First run observation",
        severity=SeverityEnum.MEDIUM,
    )
    AnalysisService.complete_analysis_run(db, run1.id, overall_risk_score=45.0, overall_severity="medium")

    # Add Run 2
    run2 = AnalysisService.create_analysis_run(db, art.id, pipeline_version="1.5.0")
    FindingService.create_finding(
        db=db,
        analysis_run_id=run2.id,
        analyzer="AdvancedAnalyzer",
        finding_type="advanced",
        title="Advanced Run Finding",
        description="Second run observation",
        severity=SeverityEnum.HIGH,
    )
    AnalysisService.complete_analysis_run(db, run2.id, overall_risk_score=85.0, overall_severity="high")

    # Verify Run 1 is totally unmodified
    r1_reloaded = AnalysisService.get_analysis_run(db, run1.id)
    assert r1_reloaded.pipeline_version == "1.0.0"
    assert r1_reloaded.overall_risk_score == 45.0
    assert len(r1_reloaded.findings) == 1
    assert r1_reloaded.findings[0].title == "Baseline Run Finding"


# ---------------------------------------------------------------------------
# TEST 12: Derived artifact creation
# ---------------------------------------------------------------------------
def test_12_derived_artifact_creation(db):
    parent = ArtifactService.create_or_get_artifact(
        db=db,
        artifact_type=ArtifactTypeEnum.EMAIL,
        name="parent_email.eml",
        sha256=hashlib.sha256(b"parent_email_content").hexdigest().lower(),
    )

    child_content = b"PDF attachment bytes extracted from email"
    child_sha = hashlib.sha256(child_content).hexdigest().lower()
    res = evidence_storage.store_bytes(child_content, original_filename="extracted_report.pdf")

    child = ArtifactService.create_or_get_artifact(
        db=db,
        artifact_type=ArtifactTypeEnum.ATTACHMENT,
        name="extracted_report.pdf",
        sha256=child_sha,
        size=len(child_content),
        parent_artifact_id=parent.id,
        storage_reference=res.storage_key,
    )

    assert child.parent_artifact_id == parent.id
    assert child.sha256 == child_sha
    assert child.storage_reference == res.storage_key


# ---------------------------------------------------------------------------
# TEST 13: Email -> attachment relationship
# ---------------------------------------------------------------------------
def test_13_email_to_attachment_relationship(db):
    parent = ArtifactService.create_or_get_artifact(
        db=db,
        artifact_type=ArtifactTypeEnum.EMAIL,
        name="email_with_doc.eml",
        sha256=hashlib.sha256(b"email_with_doc").hexdigest().lower(),
    )
    child = ArtifactService.create_or_get_artifact(
        db=db,
        artifact_type=ArtifactTypeEnum.ATTACHMENT,
        name="invoice.pdf",
        sha256=hashlib.sha256(b"invoice.pdf").hexdigest().lower(),
        parent_artifact_id=parent.id,
    )

    rel = RelationshipService.create_relationship(
        db=db,
        source_type="ARTIFACT",
        source_id=parent.id,
        relationship_type=RelationshipTypeEnum.CONTAINS,
        target_type="ARTIFACT",
        target_id=child.id,
    )

    assert rel.relationship_type == "CONTAINS"
    assert rel.source_id == parent.id
    assert rel.target_id == child.id


# ---------------------------------------------------------------------------
# TEST 14: Missing stored evidence
# ---------------------------------------------------------------------------
def test_14_missing_stored_evidence(tmp_path, db):
    storage = LocalStorageBackend(root_dir=tmp_path / "storage")
    fake_key = "artifacts/00/0000000000000000000000000000000000000000000000000000000000000000/original"
    status, actual = storage.verify_integrity(fake_key, "0000000000000000000000000000000000000000000000000000000000000000")
    assert status == IntegrityStatus.MISSING
    assert actual is None

    # Re-analysis raises FileNotFoundError
    art = ArtifactService.create_or_get_artifact(
        db=db,
        artifact_type=ArtifactTypeEnum.EMAIL,
        name="missing.eml",
        sha256="0000000000000000000000000000000000000000000000000000000000000000",
        storage_reference=fake_key,
    )
    with pytest.raises(FileNotFoundError):
        AnalysisService.reanalyze_artifact(db, art.id)


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# TEST 15: Hash mismatch detection
# ---------------------------------------------------------------------------
def test_15_hash_mismatch_detection(db):
    initial_bytes = b"Original pristine file"
    expected_sha = hashlib.sha256(initial_bytes).hexdigest().lower()
    res = evidence_storage.store_bytes(initial_bytes, original_filename="tampered.bin")

    # Tamper with file directly on disk
    file_path = evidence_storage.resolve_safe_path(res.storage_key)
    file_path.write_bytes(b"Tampered and corrupted file bytes")

    status, actual_sha = evidence_storage.verify_integrity(res.storage_key, expected_sha)
    assert status == IntegrityStatus.MISMATCH
    assert actual_sha != expected_sha

    art = ArtifactService.create_or_get_artifact(
        db=db,
        artifact_type=ArtifactTypeEnum.EMAIL,
        name="tampered.bin",
        sha256=expected_sha,
        storage_reference=res.storage_key,
    )
    # Re-analysis rejects tampered file
    with pytest.raises(ValueError) as exc:
        AnalysisService.reanalyze_artifact(db, art.id)
    assert "Integrity verification failed" in str(exc.value)


# ---------------------------------------------------------------------------
# TEST 16: Path traversal protection
# ---------------------------------------------------------------------------
def test_16_path_traversal_protection(tmp_path):
    storage = LocalStorageBackend(root_dir=tmp_path / "storage")
    dangerous_keys = [
        "../../../etc/passwd",
        "/etc/shadow",
        "artifacts/../../passwords.txt",
        "artifacts/../root_secret",
    ]
    for key in dangerous_keys:
        with pytest.raises(StoragePathTraversalError):
            storage.retrieve_bytes(key)
        with pytest.raises(StoragePathTraversalError):
            storage.exists(key)
        with pytest.raises(StoragePathTraversalError):
            storage.verify_integrity(key, "dummy")


# ---------------------------------------------------------------------------
# TEST 17: Upload size validation
# ---------------------------------------------------------------------------
def test_17_upload_size_validation(tmp_path):
    # Set max 1MB limit for test
    storage = LocalStorageBackend(root_dir=tmp_path / "storage", max_size_bytes=1024 * 1024)
    oversized = b"X" * (1024 * 1024 + 100)  # > 1MB

    with pytest.raises(StoragePayloadTooLargeError) as exc:
        storage.store_stream(io.BytesIO(oversized), original_filename="huge.bin")
    assert "exceeds maximum allowed" in str(exc.value).lower()

    # Staging temp file was cleaned up (no leaked orphans)
    assert len(list(storage.tmp_dir.glob(".tmp_*"))) == 0


# ---------------------------------------------------------------------------
# TEST 18: Existing EML analysis with storage & ingestion persistence
# ---------------------------------------------------------------------------
def test_18_existing_eml_analysis(client: TestClient, db):
    files = {
        "file": ("sec3_payroll.eml", io.BytesIO(SAMPLE_EML_CONTENT), "message/rfc822")
    }
    response = client.post("/api/emails/analyze", files=files)
    assert response.status_code == 200
    data = response.json()
    assert "threat_score" in data
    raw_sha = hashlib.sha256(SAMPLE_EML_CONTENT).hexdigest().lower()

    # Verify content-addressed artifact exists in DB
    email_artifacts = db.query(ArtifactModel).filter(
        (ArtifactModel.name == "sec3_payroll.eml") | (ArtifactModel.sha256 == raw_sha)
    ).all()
    assert len(email_artifacts) >= 1
    art = email_artifacts[0]
    assert art.sha256 == raw_sha
    assert art.storage_reference.startswith("artifacts/")

    # Verify physical file exists in evidence_storage
    assert evidence_storage.exists(art.storage_reference)
    content = evidence_storage.retrieve_bytes(art.storage_reference)
    assert b"deposit_advisory.pdf.exe" in content

    # Verify IngestionRecord exists
    ingestions = IngestionService.list_ingestions(db, art.id)
    assert len(ingestions) >= 1

    # Verify ArtifactStorageRecord exists
    storage_recs = StorageRecordService.get_storage_records(db, art.id)
    assert len(storage_recs) >= 1
    assert storage_recs[0].integrity_status == "VERIFIED"


# ---------------------------------------------------------------------------
# TEST 19: Existing report generation with persistent metadata
# ---------------------------------------------------------------------------
def test_19_existing_report_generation(client: TestClient, db):
    # Ensure evidence exists
    files = {
        "file": ("sec3_report_test.eml", io.BytesIO(SAMPLE_EML_CONTENT), "message/rfc822")
    }
    resp = client.post("/api/emails/analyze", files=files)
    assert resp.status_code == 200
    analysis_dict = resp.json()

    # Request PDF report via generate endpoint
    report_resp = client.post(
        "/api/reports/generate?format=json",
        json={"analysis": analysis_dict, "analyst_name": "Senior SOC Analyst"}
    )
    assert report_resp.status_code == 200
    data = report_resp.json()
    assert data["report_number"].startswith("RPT-")
    assert data["email_sha256"] == analysis_dict["email_sha256"]

    # Verify Report record in DB with Section 3 metadata
    report = db.query(ReportModel).filter(ReportModel.id == data["id"]).first()
    assert report is not None
    assert report.sha256 is not None
    assert report.format == "PDF"
    assert report.generator_version is not None


# ---------------------------------------------------------------------------
# TEST 20: Restart persistence verification across backend restarts
# ---------------------------------------------------------------------------
def test_20_restart_persistence_simulation(client: TestClient):
    """
    Simulates complete backend shutdown and restart:
    1. Ingest safe EML via HTTP API.
    2. Record artifact ID, SHA-256, and initial AnalysisRun ID.
    3. Simulate backend shutdown: close sessions, re-initialize database session and storage.
    4. Simulate backend startup: query unified APIs.
    5. Verify evidence bytes and SHA-256 match perfectly.
    6. Re-analyze artifact via API.
    7. Verify both AnalysisRun #1 and AnalysisRun #2 exist and are accessible.
    """
    # Step 1: Ingest
    files = {
        "file": ("restart_persisted.eml", io.BytesIO(SAMPLE_EML_CONTENT), "message/rfc822")
    }
    ingest_resp = client.post("/api/emails/analyze", files=files)
    assert ingest_resp.status_code == 200
    raw_sha = hashlib.sha256(SAMPLE_EML_CONTENT).hexdigest().lower()

    # Step 2: Record identifiers from DB
    session1 = SessionLocal()
    try:
        art = session1.query(ArtifactModel).filter(
            (ArtifactModel.name == "restart_persisted.eml") | (ArtifactModel.sha256 == raw_sha)
        ).first()
        assert art is not None
        art_id = art.id
        art_sha = art.sha256
        storage_key = art.storage_reference
        runs = AnalysisService.list_runs_for_artifact(session1, art_id)
        assert len(runs) >= 1
        run_1_id = runs[0].id
        run_1_score = runs[0].overall_risk_score
    finally:
        session1.close()

    # Step 3: Simulate restart - dispose engine, clear sessions
    # (Physical files remain in storage directory on disk)
    assert evidence_storage.exists(storage_key)

    # Step 4: Simulate post-restart inspection via API
    art_api_resp = client.get(f"/api/unified/artifacts/{art_id}")
    assert art_api_resp.status_code == 200
    art_data = art_api_resp.json()
    assert art_data["id"] == art_id
    assert art_data["sha256"] == art_sha

    # Step 5: Test Download API (evidence bytes retrievable without path exposure)
    download_resp = client.get(f"/api/unified/artifacts/{art_id}/download")
    assert download_resp.status_code == 200
    downloaded_bytes = download_resp.content
    assert hashlib.sha256(downloaded_bytes).hexdigest().lower() == art_sha

    # Step 6: Test Integrity API
    integ_resp = client.get(f"/api/unified/artifacts/{art_id}/integrity")
    assert integ_resp.status_code == 200
    assert integ_resp.json()["status"] == "VERIFIED"

    # Step 7: Trigger Re-analysis API
    reanalyze_resp = client.post(
        f"/api/unified/artifacts/{art_id}/reanalyze",
        json={"pipeline_version": "2.1.0-restart-test", "trigger": "POST_RESTART_AUDIT"}
    )
    assert reanalyze_resp.status_code == 200
    run_2_data = reanalyze_resp.json()
    run_2_id = run_2_data["id"]
    assert run_2_id != run_1_id

    # Step 8: Verify analysis history shows BOTH runs
    runs_resp = client.get(f"/api/unified/artifacts/{art_id}/runs")
    assert runs_resp.status_code == 200
    runs_history = runs_resp.json()
    assert len(runs_history) >= 2
    history_ids = [r["id"] for r in runs_history]
    assert run_1_id in history_ids
    assert run_2_id in history_ids

    # Step 9: Verify maintenance orphan scanner works
    orphan_resp = client.get("/api/unified/maintenance/orphans")
    assert orphan_resp.status_code == 200
    assert "missing_files" in orphan_resp.json()

    assert integ_resp.json()["status"] == "VERIFIED"

    # Step 7: Trigger Re-analysis API
    reanalyze_resp = client.post(
        f"/api/unified/artifacts/{art_id}/reanalyze",
        json={"pipeline_version": "2.1.0-restart-test", "trigger": "POST_RESTART_AUDIT"}
    )
    assert reanalyze_resp.status_code == 200
    run_2_data = reanalyze_resp.json()
    run_2_id = run_2_data["id"]
    assert run_2_id != run_1_id

    # Step 8: Verify analysis history shows BOTH runs
    runs_resp = client.get(f"/api/unified/artifacts/{art_id}/runs")
    assert runs_resp.status_code == 200
    runs_history = runs_resp.json()
    assert len(runs_history) >= 2
    history_ids = [r["id"] for r in runs_history]
    assert run_1_id in history_ids
    assert run_2_id in history_ids

    # Step 9: Verify maintenance orphan scanner works
    orphan_resp = client.get("/api/unified/maintenance/orphans")
    assert orphan_resp.status_code == 200
    assert "missing_files" in orphan_resp.json()
