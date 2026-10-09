"""
Unit and Integration Tests for Section 2: Unified CyberGuard Data Model.
Validates:
1. Artifact creation and hierarchical child attachments
2. SHA-256 cryptographic preservation
3. AnalysisRun creation and lifecycle
4. Multiple AnalysisRuns for a single Artifact
5. Finding creation with provenance method
6. Machine-readable Evidence association with Findings
7. Indicator normalization across IPs, domains, URLs, hashes, and emails
8. Indicator deduplication on (type, normalized_value)
9. Knowledge graph Relationship creation and querying
10. Normalized ThreatEvent creation
11. Incident and ThreatEvent bi-directional linkage
12. ResponseAction creation and states
13. Risk-score boundary validation (0.0 - 100.0)
14. Confidence boundary standardization (0.0 - 1.0)
15. EML ingestion continues working flawlessly
16. Existing analysis remains accessible
17. New normalized records are produced from real EML ingestion (dual-write)
18. Existing PDF report generation still functions correctly
19. Unified Inspection API endpoints
"""
import io
import json
import hashlib
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from backend.main import app
from backend.db.session import SessionLocal
from backend.db.models import (
    ArtifactModel,
    AnalysisRunModel,
    FindingModel,
    FindingEvidenceModel,
    IndicatorModel,
    EntityModel,
    RelationshipModel,
    IncidentModel,
    ThreatEventModel,
    ResponseActionModel,
    ModelVersionModel,
    EvidenceModel,
    AnalysisPayloadModel,
    ReportModel,
)
from backend.schemas.unified import (
    ArtifactTypeEnum,
    AnalysisStatusEnum,
    AnalysisTriggerEnum,
    FindingMethodEnum,
    IndicatorTypeEnum,
    RelationshipTypeEnum,
    IncidentStatusEnum,
    ResponseStatusEnum,
    SeverityEnum,
    normalize_confidence,
    normalize_domain,
    normalize_email_address,
    normalize_hash,
    normalize_indicator,
    normalize_ip,
    normalize_risk_score,
    normalize_severity,
    normalize_url,
)
from backend.services.unified_service import (
    ArtifactService,
    AnalysisService,
    FindingService,
    IndicatorService,
    EntityService,
    RelationshipService,
    ThreatEventService,
    IncidentService,
    ModelVersionService,
    UnifiedIngestionAdapter,
)


@pytest.fixture
def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def client():
    return TestClient(app)


SAMPLE_SAFE_RFC822_EML = b"""Received: from relay1.internal.example (relay1.internal.example [198.51.100.22])
    by mx.target-corp.example (Postfix) with ESMTP id 9ABC1234
    for <employee@target-corp.example>; Mon, 21 Sep 2026 10:15:00 +0000
From: "Billing Security" <billing@secure-payroll.example>
Reply-To: <support@secure-payroll.example>
To: <employee@target-corp.example>
Subject: Verification Required: Quarterly Payroll Statement
Date: Mon, 21 Sep 2026 10:14:30 +0000
Message-ID: <payroll-notice-101@secure-payroll.example>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BOUNDARY-SAMPLE-TEST"

--BOUNDARY-SAMPLE-TEST
Content-Type: text/plain; charset="utf-8"

Please review the attached statement and verify your credentials at:
http://verify.secure-payroll.example/login?token=abc123xyz

--BOUNDARY-SAMPLE-TEST
Content-Type: application/octet-stream; name="statement.pdf.exe"
Content-Disposition: attachment; filename="statement.pdf.exe"
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAA4AAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1v
ZGUuDQ0KJAAAAAAAAABQRQAATAEDAAAAAAAAAAAAAAAAAAAAAAAA
--BOUNDARY-SAMPLE-TEST--
"""


# ============================================================================
# TESTS 1 - 4: ARTIFACT & ANALYSIS RUNS
# ============================================================================

def test_1_artifact_creation(db):
    """Verifies canonical Artifact creation with metadata and timestamps."""
    artifact = ArtifactService.create_or_get_artifact(
        db=db,
        artifact_type=ArtifactTypeEnum.FILE,
        name="suspect_script.ps1",
        source="ENDPOINT_AGENT",
        mime_type="text/plain",
        size=1024,
        metadata={"host": "WS-FINANCE-01"},
    )
    assert artifact.id is not None
    assert artifact.artifact_type == "FILE"
    assert artifact.name == "suspect_script.ps1"
    assert artifact.source == "ENDPOINT_AGENT"
    assert artifact.ingested_at is not None


def test_2_sha256_preservation(db):
    """Verifies cryptographic SHA-256 integrity and retrieval by hash."""
    test_sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    artifact = ArtifactService.create_or_get_artifact(
        db=db,
        artifact_type=ArtifactTypeEnum.ATTACHMENT,
        name="payload.bin",
        sha256=test_sha.upper(),  # Should be normalized to lowercase
        size=0,
    )
    assert artifact.sha256 == test_sha.lower()

    # Retrieve by SHA-256
    retrieved = ArtifactService.get_artifact(db, test_sha.upper())
    assert retrieved is not None
    assert retrieved.id == artifact.id


def test_3_analysis_run_creation(db):
    """Verifies AnalysisRun lifecycle from QUEUED to COMPLETED."""
    artifact = ArtifactService.create_or_get_artifact(
        db=db,
        artifact_type=ArtifactTypeEnum.URL,
        name="https://suspicious.example/login",
    )
    run = AnalysisService.create_analysis_run(
        db=db,
        artifact_id=artifact.id,
        trigger=AnalysisTriggerEnum.AUTOMATIC,
        pipeline_version="2.0.0",
    )
    assert run.status == "QUEUED"
    assert run.trigger == "AUTOMATIC"
    assert run.artifact_id == artifact.id

    # Complete analysis run
    completed = AnalysisService.complete_analysis_run(
        db=db,
        run_id=run.id,
        overall_risk_score=78.5,
        overall_severity=SeverityEnum.HIGH,
        confidence=0.92,
    )
    assert completed.status == "COMPLETED"
    assert completed.overall_risk_score == 78.5
    assert completed.overall_severity == "HIGH"
    assert completed.confidence == 0.92
    assert completed.completed_at is not None


def test_4_multiple_analysis_runs_for_one_artifact(db):
    """Verifies that an Artifact can be analyzed multiple times across versions."""
    artifact = ArtifactService.create_or_get_artifact(
        db=db,
        artifact_type=ArtifactTypeEnum.IP,
        name="198.51.100.77",
    )
    run1 = AnalysisService.create_analysis_run(
        db=db, artifact_id=artifact.id, trigger=AnalysisTriggerEnum.USER, pipeline_version="1.0"
    )
    run2 = AnalysisService.create_analysis_run(
        db=db, artifact_id=artifact.id, trigger=AnalysisTriggerEnum.REANALYSIS, pipeline_version="2.0"
    )
    runs = AnalysisService.list_runs_for_artifact(db, artifact.id)
    assert len(runs) >= 2
    run_ids = [r.id for r in runs]
    assert run1.id in run_ids
    assert run2.id in run_ids


# ============================================================================
# TESTS 5 - 6: FINDINGS & EVIDENCE ASSOCIATION
# ============================================================================

def test_5_finding_creation(db):
    """Verifies Finding creation with explicit method provenance."""
    artifact = ArtifactService.create_or_get_artifact(
        db=db, artifact_type=ArtifactTypeEnum.DOMAIN, name="evil-secure.example"
    )
    run = AnalysisService.create_analysis_run(db, artifact.id)

    finding = FindingService.create_finding(
        db=db,
        analysis_run_id=run.id,
        analyzer="DomainReputationScanner",
        finding_type="newly_registered_domain",
        title="Domain Registered Less Than 48 Hours Ago",
        description="Domain was registered within 48h and is hosting active login forms.",
        severity=SeverityEnum.HIGH,
        confidence=0.95,
        risk_contribution=40.0,
        method=FindingMethodEnum.EXTERNAL_INTELLIGENCE,
        rule_id="RULE-WHOIS-AGE",
    )
    assert finding.id is not None
    assert finding.method == "EXTERNAL_INTELLIGENCE"
    assert finding.severity == "HIGH"
    assert finding.risk_contribution == 40.0
    assert finding.rule_id == "RULE-WHOIS-AGE"


def test_6_evidence_association(db):
    """Verifies attaching machine-readable Evidence items to a Finding."""
    artifact = ArtifactService.create_or_get_artifact(
        db=db, artifact_type=ArtifactTypeEnum.DOMAIN, name="micros0ft.example"
    )
    run = AnalysisService.create_analysis_run(db, artifact.id)
    finding = FindingService.create_finding(
        db=db,
        analysis_run_id=run.id,
        analyzer="LookalikeDetector",
        finding_type="lookalike_domain",
        title="Impersonation Lookalike Detected",
        description="Domain mimics Microsoft corporate domain.",
        severity=SeverityEnum.HIGH,
        method=FindingMethodEnum.HEURISTIC,
    )

    ev1 = FindingService.attach_evidence(
        db=db,
        finding_id=finding.id,
        evidence_type="OBSERVED_DOMAIN",
        source="LOOKALIKE_DETECTOR",
        key="domain",
        value="micros0ft.example",
        confidence=1.0,
        artifact_id=artifact.id,
    )
    ev2 = FindingService.attach_evidence(
        db=db,
        finding_id=finding.id,
        evidence_type="SIMILARITY_SCORE",
        source="LOOKALIKE_DETECTOR",
        key="similarity",
        value=0.91,
        confidence=0.95,
    )

    findings = FindingService.get_findings_for_run(db, run.id)
    assert len(findings) == 1
    target_finding = findings[0]
    assert len(target_finding.evidence_items) == 2
    keys = [e.key for e in target_finding.evidence_items]
    assert "domain" in keys
    assert "similarity" in keys


# ============================================================================
# TESTS 7 - 8: INDICATOR NORMALIZATION & DEDUPLICATION
# ============================================================================

def test_7_indicator_normalization():
    """Verifies canonical normalization across different indicator types."""
    # Domains
    raw_d, norm_d = normalize_indicator(IndicatorTypeEnum.DOMAIN, "  EXAMPLE.COM.  ")
    assert norm_d == "example.com"
    assert raw_d == "EXAMPLE.COM."

    # URLs
    raw_u, norm_u = normalize_indicator(IndicatorTypeEnum.URL, "HTTPS://ExAmPlE.CoM/Path/To/Page?token=123#frag")
    assert norm_u == "https://example.com/Path/To/Page?token=123#frag"

    # IPs
    raw_ip, norm_ip = normalize_indicator(IndicatorTypeEnum.IP, " 192.002.001.001 ")
    # ipaddress collapses/normalizes
    assert norm_ip == "192.2.1.1"

    # Hashes
    raw_h, norm_h = normalize_indicator(IndicatorTypeEnum.FILE_HASH, " E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855 ")
    assert norm_h == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    # Emails
    raw_em, norm_em = normalize_indicator(IndicatorTypeEnum.EMAIL_ADDRESS, " User.Name@SUB.EXAMPLE.COM ")
    assert norm_em == "User.Name@sub.example.com"


def test_8_indicator_deduplication(db):
    """Verifies that duplicate indicator inputs resolve to the same record and update last_seen."""
    ind1 = IndicatorService.upsert_indicator(
        db=db,
        indicator_type=IndicatorTypeEnum.DOMAIN,
        value="Target-Corp.Example",
        reputation="NEUTRAL",
    )
    ind2 = IndicatorService.upsert_indicator(
        db=db,
        indicator_type=IndicatorTypeEnum.DOMAIN,
        value="target-corp.example.",  # Trailing dot & lowercase variant
        reputation="SUSPICIOUS",
    )
    assert ind1.id == ind2.id
    assert ind2.normalized_value == "target-corp.example"
    assert ind2.reputation == "SUSPICIOUS"


# ============================================================================
# TESTS 9 - 12: RELATIONSHIPS, THREAT EVENTS, INCIDENTS, RESPONSE ACTIONS
# ============================================================================

def test_9_relationship_creation(db):
    """Verifies polymorphic Knowledge Graph relationship creation and querying."""
    rel = RelationshipService.create_relationship(
        db=db,
        source_type="INDICATOR",
        source_id="phish-link.example",
        relationship_type=RelationshipTypeEnum.RESOLVES_TO,
        target_type="INDICATOR",
        target_id="203.0.113.88",
        confidence=0.99,
        method="DNS_QUERY",
    )
    assert rel.id is not None
    assert rel.relationship_type == "RESOLVES_TO"

    results = RelationshipService.list_relationships(db, source_id="phish-link.example")
    assert len(results) >= 1
    assert results[0].target_id == "203.0.113.88"


def test_10_threat_event_creation(db):
    """Verifies normalized ThreatEvent creation from normalized telemetry."""
    event = ThreatEventService.create_threat_event(
        db=db,
        event_type="credential_harvesting",
        summary="User submitted corporate credentials to unauthenticated external portal.",
        severity=SeverityEnum.HIGH,
        risk_score=85.0,
        confidence=0.90,
    )
    assert event.id is not None
    assert event.event_type == "credential_harvesting"
    assert event.risk_score == 85.0
    assert event.severity == "HIGH"


def test_11_incident_threat_event_relationship(db):
    """Verifies linking multiple ThreatEvents to an Incident."""
    incident = IncidentService.create_incident(
        db=db,
        title="Q3 Phishing Impersonation Campaign Investigation",
        description="Targeted spear-phishing campaign impersonating VP of HR.",
        severity=SeverityEnum.CRITICAL,
        risk_score=92.0,
    )
    assert incident.incident_number.startswith("INC-")

    te1 = ThreatEventService.create_threat_event(
        db=db,
        event_type="phishing_email_delivered",
        summary="Spear-phishing email delivered to inbox.",
        severity=SeverityEnum.MEDIUM,
    )
    te2 = ThreatEventService.create_threat_event(
        db=db,
        event_type="malicious_link_clicked",
        summary="Recipient clicked credential harvesting link.",
        severity=SeverityEnum.HIGH,
    )

    IncidentService.attach_threat_event(db, incident.id, te1.id)
    IncidentService.attach_threat_event(db, incident.id, te2.id)

    db.refresh(incident)
    assert len(incident.threat_events) == 2
    event_ids = [e.id for e in incident.threat_events]
    assert te1.id in event_ids
    assert te2.id in event_ids


def test_12_response_action_creation(db):
    """Verifies ResponseAction lifecycle and link to incident."""
    incident = IncidentService.create_incident(
        db=db,
        title="Compromised Account Remediation",
        severity=SeverityEnum.HIGH,
    )
    action = IncidentService.create_response_action(
        db=db,
        incident_id=incident.id,
        action_type="RESET_CREDENTIALS",
        description="Trigger Active Directory user credential reset and invalidate current OAuth tokens.",
        priority="HIGH",
        recommended_by="CyberGuard Threat Engine",
    )
    assert action.id is not None
    assert action.action_type == "RESET_CREDENTIALS"
    assert action.status == "RECOMMENDED"

    db.refresh(incident)
    assert len(incident.response_actions) == 1
    assert incident.response_actions[0].id == action.id


# ============================================================================
# TESTS 13 - 14: BOUNDARY VALIDATIONS
# ============================================================================

def test_13_risk_score_validation():
    """Verifies that risk scores are strictly clamped/validated between 0.0 and 100.0."""
    assert normalize_risk_score(-10) == 0.0
    assert normalize_risk_score(150) == 100.0
    assert normalize_risk_score(75.4) == 75.4
    assert normalize_risk_score(None) is None


def test_14_confidence_validation():
    """Verifies standardization of confidence to 0.0 - 1.0 from floats, percents, and labels."""
    assert normalize_confidence(0.85) == 0.85
    assert normalize_confidence(85) == 0.85  # Legacy percentage as int
    assert normalize_confidence("90%") == 0.90  # String percentage
    assert normalize_confidence("HIGH") == 0.85  # Discrete label
    assert normalize_confidence("CONFIRMED") == 1.0
    assert normalize_confidence(1.5) == 1.0  # Clamped


# ============================================================================
# TESTS 15 - 18: REAL DATA FLOW & LEGACY COMPATIBILITY
# ============================================================================

def test_15_eml_ingestion_still_works(client: TestClient):
    """Verifies that the existing /api/emails/analyze route ingests EML and returns expected shape."""
    files = {
        "file": ("test_payroll.eml", io.BytesIO(SAMPLE_SAFE_RFC822_EML), "message/rfc822")
    }
    response = client.post("/api/emails/analyze", files=files)
    assert response.status_code == 200, f"Analysis failed: {response.text}"
    data = response.json()
    assert "Verification Required: Quarterly Payroll Statement" in data["subject"]
    assert data["evidence_id"].startswith("EVD-")
    assert "threat_score" in data
    assert "urls" in data


def test_16_existing_analysis_remains_accessible(client: TestClient, db):
    """Verifies that previously ingested analyses remain accessible via /api/emails/{id}/analysis."""
    sample_sha = hashlib.sha256(SAMPLE_SAFE_RFC822_EML).hexdigest().lower()
    evd = db.query(EvidenceModel).filter(EvidenceModel.sha256 == sample_sha).first()
    assert evd is not None, "Evidence should exist from previous ingestion test"

    response = client.get(f"/api/emails/{evd.evidence_id}/analysis")
    assert response.status_code == 200
    data = response.json()
    assert data["evidence_id"] == evd.evidence_id


def test_17_new_normalized_records_produced_from_eml(db):
    """
    Verifies that real EML ingestion produced all canonical unified records:
    Artifact(EMAIL) -> Artifact(ATTACHMENT) -> AnalysisRun -> Findings -> Evidence -> Indicators -> Relationships
    """
    # 1. Check Artifact
    sample_sha = hashlib.sha256(SAMPLE_SAFE_RFC822_EML).hexdigest().lower()
    art = db.query(ArtifactModel).filter(ArtifactModel.sha256 == sample_sha).first()
    assert art is not None
    assert art.storage_reference is not None

    # 2. Check Child Attachment Artifact
    att_artifacts = db.query(ArtifactModel).filter(
        ArtifactModel.artifact_type == "ATTACHMENT",
        ArtifactModel.parent_artifact_id == art.id
    ).all()
    assert len(att_artifacts) >= 1
    child = att_artifacts[0]
    assert child.name == "statement.pdf.exe"

    # 3. Check AnalysisRun
    runs = db.query(AnalysisRunModel).filter(AnalysisRunModel.artifact_id == art.id).all()
    assert len(runs) >= 1
    run = runs[0]
    assert run.status == "COMPLETED"
    assert run.overall_risk_score is not None

    # 4. Check Findings & Evidence
    findings = db.query(FindingModel).filter(FindingModel.analysis_run_id == run.id).all()
    assert len(findings) >= 1
    auth_findings = [f for f in findings if f.analyzer == "AuthenticationAnalyzer"]
    assert len(auth_findings) >= 1
    f_auth = auth_findings[0]
    assert len(f_auth.evidence_items) >= 1

    # 5. Check Indicators
    indicators = db.query(IndicatorModel).all()
    assert len(indicators) >= 1
    ind_types = {i.indicator_type for i in indicators}
    assert "DOMAIN" in ind_types or "EMAIL_ADDRESS" in ind_types

    # 6. Check Relationships
    rels = db.query(RelationshipModel).filter(RelationshipModel.source_id == art.id).all()
    assert len(rels) >= 1
    rel_types = {r.relationship_type for r in rels}
    assert "CONTAINS" in rel_types or "REFERENCES" in rel_types


def test_18_existing_report_generation_still_works(client: TestClient, db):
    """Verifies that PDF report generation endpoint continues functioning normally."""
    sample_sha = hashlib.sha256(SAMPLE_SAFE_RFC822_EML).hexdigest().lower()
    evd = db.query(EvidenceModel).filter(EvidenceModel.sha256 == sample_sha).first()
    assert evd is not None

    payload_rec = db.query(AnalysisPayloadModel).filter(AnalysisPayloadModel.evidence_id == evd.evidence_id).first()
    assert payload_rec is not None, "Canonical analysis payload must exist for ingested evidence"
    analysis_dict = json.loads(payload_rec.analysis_json)

    req_payload = {
        "analysis": analysis_dict,
        "analyst_name": "Senior SOC Analyst",
        "notes": "Forensic examination completed with verified security protocols.",
    }
    response = client.post("/api/reports/generate?format=json", json=req_payload)
    assert response.status_code == 200, f"Report generation failed: {response.text}"
    data = response.json()
    assert data["report_number"].startswith("RPT-")
    assert data["email_sha256"] == evd.sha256
    
    # Also verify database persistence of the report record
    saved_report = db.query(ReportModel).filter(ReportModel.id == data["id"]).first()
    assert saved_report is not None
    assert saved_report.evidence_id == evd.evidence_id


def test_19_unified_inspection_endpoints(client: TestClient, db):
    """Verifies minimal API endpoints for inspecting the unified data model."""
    art = db.query(ArtifactModel).filter(
        ArtifactModel.artifact_type == "EMAIL",
        ArtifactModel.analysis_runs.any(AnalysisRunModel.findings.any())
    ).first()
    assert art is not None

    # GET /api/unified/artifacts/{id}
    res1 = client.get(f"/api/unified/artifacts/{art.id}")
    assert res1.status_code == 200
    data1 = res1.json()
    assert data1["id"] == art.id
    assert data1["artifact_type"] == "EMAIL"

    # GET /api/unified/artifacts/{id}/analysis
    res2 = client.get(f"/api/unified/artifacts/{art.id}/analysis")
    assert res2.status_code == 200
    runs_data = res2.json()
    assert len(runs_data) >= 1
    run_id = runs_data[0]["id"]

    # GET /api/unified/analysis/{id}/findings
    res3 = client.get(f"/api/unified/analysis/{run_id}/findings")
    assert res3.status_code == 200
    findings_data = res3.json()
    assert len(findings_data) >= 1
    assert "evidence_items" in findings_data[0]

    # GET /api/unified/relationships
    res4 = client.get("/api/unified/relationships?limit=10")
    assert res4.status_code == 200
    rels_data = res4.json()
    assert isinstance(rels_data, list)
