"""
Unit and integration tests for Section 4: Universal Ingestion Gateway.

Validates:
1. Valid EML upload
2. Generic file upload
3. Image upload (PNG/JPEG)
4. Audio upload (WAV/MP3)
5. Video upload (MP4)
6. URL text input
7. Domain text input
8. IPv4 input
9. IPv6 input
10. Email-address text input
11. Plain suspicious message text
12. Structured JSON security event
13. Invalid JSON error handling
14. Empty input error handling
15. Oversized upload rejection
16. Filename path traversal sanitization
17. MIME/extension disagreement handling
18. Duplicate content ingestion (content identity vs ingestion provenance)
19. Original value preservation
20. Normalized value generation
21. Durable artifact persistence in storage
22. Ingestion record creation
23. Candidate analyzer routing generation
24. Existing EML analysis endpoint compatibility
25. SSRF safety test: no automatic URL fetching during ingestion
26. Multi-input integration test (5 heterogeneous inputs)
27. Capabilities registry endpoint
28. Pre-flight detection endpoint
29. Derived artifact registration
"""
import io
import json
import hashlib
import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.main import app
from backend.db.session import SessionLocal
from backend.db.models import (
    ArtifactModel,
    ArtifactStorageRecordModel,
    IngestionRecordModel,
    IndicatorModel,
    RelationshipModel,
    ThreatEventModel,
)
from backend.schemas.unified import (
    ArtifactTypeEnum,
    InputModeEnum,
    SupportStatusEnum,
    CapabilityStatusEnum,
    RelationshipTypeEnum,
)
from backend.services.evidence_storage import evidence_storage
from backend.services.universal_ingestion import (
    global_capability_registry,
    UniversalIngestionService,
    TypeDetector,
    InvalidInputError,
    FileTooLargeError,
)

client = TestClient(app)


@pytest.fixture
def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


SAMPLE_EML_BYTES = b"""From: alerts@paypal-notification.example
To: victim@target-corp.example
Subject: Security Alert: Unauthorized Login Detected
Date: Thu, 01 Oct 2026 12:00:00 +0000
Message-ID: <sec-alert-441@paypal-notification.example>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

Please verify your identity at http://secure-portal.example/login to prevent suspension.
"""

SAMPLE_PNG_BYTES = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x10\x00\x00\x00\x10\x08\x06\x00\x00\x00\x1f\xf3\xffa"
    b"\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82"
)

SAMPLE_WAV_BYTES = b"RIFF$\x00\x00\x00WAVEfmt \x10\x00\x00\x00\x01\x00\x01\x00D\xac\x00\x00\x88X\x01\x00\x02\x00\x10\x00data\x00\x00\x00\x00"

SAMPLE_MP4_BYTES = b"\x00\x00\x00\x1cftypisom\x00\x00\x02\x00isomiso2mp41\x00\x00\x00\x08free"


# ---------------------------------------------------------------------------
# TEST 1: Valid EML file upload via /api/ingest
# ---------------------------------------------------------------------------
def test_1_valid_eml_upload():
    files = {"file": ("suspicious_billing.eml", io.BytesIO(SAMPLE_EML_BYTES), "message/rfc822")}
    response = client.post("/api/ingest", files=files, data={"source": "UPLOAD", "notes": "Phishing inquiry"})
    assert response.status_code == 200, f"Error: {response.text}"
    data = response.json()
    assert data["artifact_type"] == "EMAIL"
    assert data["input_mode"] == "FILE_UPLOAD"
    assert "email_forensics" in data["candidate_analyzers"]
    assert "auth_analyzer" in data["candidate_analyzers"]
    assert data["storage_status"] == "STORED"
    assert data["sha256"] == hashlib.sha256(SAMPLE_EML_BYTES).hexdigest().lower()


# ---------------------------------------------------------------------------
# TEST 2: Generic file upload (PDF/Text)
# ---------------------------------------------------------------------------
def test_2_generic_file_upload():
    pdf_bytes = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF"
    files = {"file": ("q3_financial_notice.pdf", io.BytesIO(pdf_bytes), "application/pdf")}
    response = client.post("/api/ingest", files=files)
    assert response.status_code == 200
    data = response.json()
    assert data["artifact_type"] == "FILE"
    assert data["classification"]["detected_mime"] == "application/pdf"
    assert "attachment_intelligence" in data["candidate_analyzers"]
    assert "file_metadata" in data["candidate_analyzers"]


# ---------------------------------------------------------------------------
# TEST 3: Image upload (PNG signature)
# ---------------------------------------------------------------------------
def test_3_image_upload():
    files = {"file": ("qr_invoice.png", io.BytesIO(SAMPLE_PNG_BYTES), "image/png")}
    response = client.post("/api/ingest", files=files)
    assert response.status_code == 200
    data = response.json()
    assert data["artifact_type"] == "IMAGE"
    assert data["classification"]["detected_mime"] == "image/png"
    assert data["classification"]["detector"] == "image_signature"
    assert data["classification"]["metadata"]["width"] == 16
    assert data["classification"]["metadata"]["height"] == 16


# ---------------------------------------------------------------------------
# TEST 4: Audio upload
# ---------------------------------------------------------------------------
def test_4_audio_upload():
    files = {"file": ("voicemail_scam.wav", io.BytesIO(SAMPLE_WAV_BYTES), "audio/wav")}
    response = client.post("/api/ingest", files=files)
    assert response.status_code == 200
    data = response.json()
    assert data["artifact_type"] == "AUDIO"
    assert data["classification"]["support_status"] == "PARTIALLY_SUPPORTED"
    # Verify no fake deepfake completion
    assert "deepfake_audio" not in data["candidate_analyzers"]
    assert any("NOT_IMPLEMENTED" in w for w in data["warnings"])


# ---------------------------------------------------------------------------
# TEST 5: Video upload
# ---------------------------------------------------------------------------
def test_5_video_upload():
    files = {"file": ("ceo_announcement.mp4", io.BytesIO(SAMPLE_MP4_BYTES), "video/mp4")}
    response = client.post("/api/ingest", files=files)
    assert response.status_code == 200
    data = response.json()
    assert data["artifact_type"] == "VIDEO"
    assert data["classification"]["support_status"] == "PARTIALLY_SUPPORTED"
    assert "deepfake_video" not in data["candidate_analyzers"]
    assert any("NOT_IMPLEMENTED" in w for w in data["warnings"])


# ---------------------------------------------------------------------------
# TEST 6: URL text input
# ---------------------------------------------------------------------------
def test_6_url_text_input(db):
    payload = {"text": "https://secure-login.micros0ft-verify.example/auth?token=99281"}
    response = client.post("/api/ingest", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["artifact_type"] == "URL"
    assert data["input_mode"] == "TEXT_INPUT"
    assert "url_analyzer" in data["candidate_analyzers"]
    assert data["original_value"] == payload["text"]
    assert data["normalized_value"] == payload["text"]

    # Verify Indicator created
    ind = db.query(IndicatorModel).filter(IndicatorModel.indicator_type == "URL").first()
    assert ind is not None


# ---------------------------------------------------------------------------
# TEST 7: Domain text input (including defanged domains)
# ---------------------------------------------------------------------------
def test_7_domain_text_input(db):
    payload = {"text": "evil-phish[.]example.org"}
    response = client.post("/api/ingest", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["artifact_type"] == "DOMAIN"
    assert data["normalized_value"] == "evil-phish.example.org"
    assert "domain_intelligence" in data["candidate_analyzers"]

    # Verify Indicator created
    ind = db.query(IndicatorModel).filter(IndicatorModel.normalized_value == "evil-phish.example.org").first()
    assert ind is not None


# ---------------------------------------------------------------------------
# TEST 8: IPv4 input
# ---------------------------------------------------------------------------
def test_8_ipv4_input():
    payload = {"text": "198.51.100.45"}
    response = client.post("/api/ingest", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["artifact_type"] == "IP"
    assert data["normalized_value"] == "198.51.100.45"
    assert data["classification"]["metadata"]["ip_version"] == 4
    assert "ip_intelligence" in data["candidate_analyzers"]


# ---------------------------------------------------------------------------
# TEST 9: IPv6 input
# ---------------------------------------------------------------------------
def test_9_ipv6_input():
    payload = {"text": "2001:0db8:85a3:0000:0000:8a2e:0370:7334"}
    response = client.post("/api/ingest", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["artifact_type"] == "IP"
    assert data["classification"]["metadata"]["ip_version"] == 6
    assert data["normalized_value"] == "2001:db8:85a3::8a2e:370:7334"


# ---------------------------------------------------------------------------
# TEST 10: Email-address input (distinguished from EML file)
# ---------------------------------------------------------------------------
def test_10_email_address_input(db):
    payload = {"text": "fraudster.attacker@suspicious-host.example"}
    response = client.post("/api/ingest", json=payload)
    assert response.status_code == 200
    data = response.json()
    # Classified as TEXT with subtype EMAIL_ADDRESS (NOT an EMAIL .eml artifact)
    assert data["artifact_type"] == "TEXT"
    assert data["classification"]["metadata"]["subtype"] == "EMAIL_ADDRESS"
    assert data["normalized_value"] == "fraudster.attacker@suspicious-host.example"

    # Verify Indicator of type EMAIL_ADDRESS was created
    ind = db.query(IndicatorModel).filter(IndicatorModel.indicator_type == "EMAIL_ADDRESS", IndicatorModel.normalized_value == "fraudster.attacker@suspicious-host.example").first()
    assert ind is not None


# ---------------------------------------------------------------------------
# TEST 11: Plain suspicious message text
# ---------------------------------------------------------------------------
def test_11_plain_suspicious_message_text():
    msg = "Your corporate payroll account has been frozen due to security irregularity. Contact support immediately."
    response = client.post("/api/ingest", json={"text": msg})
    assert response.status_code == 200
    data = response.json()
    assert data["artifact_type"] == "TEXT"
    assert "nlp_classifier" in data["candidate_analyzers"]
    assert data["classification"]["metadata"]["word_count"] >= 10


# ---------------------------------------------------------------------------
# TEST 12: Structured JSON security event
# ---------------------------------------------------------------------------
def test_12_structured_json_event(db):
    event_payload = {
        "event": {
            "source_type": "AUTH_LOG",
            "event_type": "failed_login_burst",
            "user": "finance_admin",
            "source_ip": "203.0.113.88",
            "failed_attempts": 15,
            "status": "failure"
        }
    }
    response = client.post("/api/ingest", json=event_payload)
    assert response.status_code == 200
    data = response.json()
    assert data["artifact_type"] == "AUTH_LOG"
    assert data["input_mode"] == "STRUCTURED_EVENT"
    assert "auth_event_parser" in data["candidate_analyzers"]

    # Verify ThreatEvent was created from the auth event
    te = db.query(ThreatEventModel).filter(ThreatEventModel.event_type == "failed_login_burst").first()
    assert te is not None
    assert te.severity == "HIGH"


# ---------------------------------------------------------------------------
# TEST 13: Invalid JSON error handling
# ---------------------------------------------------------------------------
def test_13_invalid_json():
    response = client.post(
        "/api/ingest",
        content="{\"bad_json\": ",
        headers={"Content-Type": "application/json"}
    )
    assert response.status_code == 400
    data = response.json()
    assert "Malformed JSON" in data["detail"]


# ---------------------------------------------------------------------------
# TEST 14: Empty input error handling
# ---------------------------------------------------------------------------
def test_14_empty_input():
    # Empty text
    res1 = client.post("/api/ingest", json={"text": "   "})
    assert res1.status_code in (400, 422)

    # Empty file
    res2 = client.post("/api/ingest", files={"file": ("empty.txt", io.BytesIO(b""), "text/plain")})
    assert res2.status_code in (400, 422)


# ---------------------------------------------------------------------------
# TEST 15: Oversized upload rejection
# ---------------------------------------------------------------------------
def test_15_oversized_upload():
    # Attempt upload of 11MB file (limit is 10MB)
    huge_bytes = b"A" * (11 * 1024 * 1024)
    response = client.post("/api/ingest", files={"file": ("huge.bin", io.BytesIO(huge_bytes), "application/octet-stream")})
    assert response.status_code == 413


# ---------------------------------------------------------------------------
# TEST 16: Filename path traversal attempt
# ---------------------------------------------------------------------------
def test_16_filename_path_traversal():
    files = {"file": ("../../../../etc/shadow.eml", io.BytesIO(SAMPLE_EML_BYTES), "message/rfc822")}
    response = client.post("/api/ingest", files=files)
    assert response.status_code == 200
    data = response.json()
    # Safe sanitized name, traversal stripped
    assert ".." not in data["name"]
    assert "/" not in data["name"]
    assert "etc" not in data["name"] or "shadow" in data["name"]


# ---------------------------------------------------------------------------
# TEST 17: MIME / Extension disagreement handling
# ---------------------------------------------------------------------------
def test_17_mime_extension_disagreement():
    # Claimed to be PNG image, but bytes are pure RFC-822 email text
    files = {"file": ("fake_image.png", io.BytesIO(SAMPLE_EML_BYTES), "image/png")}
    response = client.post("/api/ingest", files=files)
    assert response.status_code == 200
    data = response.json()
    # Deep content inspection identifies genuine email format despite .png extension
    assert data["artifact_type"] == "EMAIL"
    assert data["classification"]["detector"] == "rfc822_header_tokens"


# ---------------------------------------------------------------------------
# TEST 18: Duplicate file ingestion (content identity vs ingestion provenance)
# ---------------------------------------------------------------------------
def test_18_duplicate_file_ingestion(db):
    file_bytes = b"DURABLE_TEST_PAYLOAD_FOR_DEDUPLICATION_CHECK_991823"
    files1 = {"file": ("case_a_evidence.bin", io.BytesIO(file_bytes), "application/octet-stream")}
    res1 = client.post("/api/ingest", files=files1, data={"uploader": "Analyst Alice"})
    assert res1.status_code == 200
    data1 = res1.json()

    files2 = {"file": ("case_b_evidence.bin", io.BytesIO(file_bytes), "application/octet-stream")}
    res2 = client.post("/api/ingest", files=files2, data={"uploader": "Analyst Bob"})
    assert res2.status_code == 200
    data2 = res2.json()

    # Content identity is shared
    assert data1["artifact_id"] == data2["artifact_id"]
    assert data1["sha256"] == data2["sha256"]

    # Ingestion provenance is discrete
    assert data1["ingestion_id"] != data2["ingestion_id"]
    
    ingestions = db.query(IngestionRecordModel).filter(IngestionRecordModel.artifact_id == data1["artifact_id"]).all()
    assert len(ingestions) >= 2


# ---------------------------------------------------------------------------
# TEST 19: Original value preservation
# ---------------------------------------------------------------------------
def test_19_original_value_preservation():
    raw_url = "hxxps://phish-login[.]evil-portal.example:8443/auth/index.php?user=admin#login"
    response = client.post("/api/ingest", json={"text": raw_url})
    assert response.status_code == 200
    data = response.json()
    assert data["original_value"] == raw_url
    assert data["normalized_value"].startswith("https://")
    assert "[.]" not in data["normalized_value"]


# ---------------------------------------------------------------------------
# TEST 20: Normalized value generation (Domain, IP, URL)
# ---------------------------------------------------------------------------
def test_20_normalized_value_generation():
    # URL normalization
    res_url = client.post("/api/ingest", json={"text": "HTTP://Example.COM:80/path/test"})
    assert res_url.status_code == 200
    assert res_url.json()["normalized_value"] == "http://example.com:80/path/test"

    # Domain normalization
    res_dom = client.post("/api/ingest", json={"text": "SUB.CORP-DOMAIN.EXAMPLE."})
    assert res_dom.status_code == 200
    assert res_dom.json()["normalized_value"] == "sub.corp-domain.example"

    # IP normalization (leading zero strip)
    res_ip = client.post("/api/ingest", json={"text": "192.168.001.010"})
    assert res_ip.status_code == 200
    assert res_ip.json()["normalized_value"] == "192.168.1.10"


# ---------------------------------------------------------------------------
# TEST 21: Artifact persistence in storage & DB
# ---------------------------------------------------------------------------
def test_21_artifact_persistence(db):
    test_bytes = b"VERIFY_PERSISTENCE_BYTES_12345"
    files = {"file": ("persist_test.txt", io.BytesIO(test_bytes), "text/plain")}
    response = client.post("/api/ingest", files=files)
    assert response.status_code == 200
    art_id = response.json()["artifact_id"]
    storage_key = response.json()["storage_key"]

    # Verify in DB
    art = db.get(ArtifactModel, art_id)
    assert art is not None
    assert art.size == len(test_bytes)

    # Verify physical bytes in storage
    assert evidence_storage.exists(storage_key)
    stored_bytes = evidence_storage.retrieve_bytes(storage_key)
    assert stored_bytes == test_bytes


# ---------------------------------------------------------------------------
# TEST 22: Ingestion record creation
# ---------------------------------------------------------------------------
def test_22_ingestion_record_creation(db):
    res = client.post("/api/ingest", json={"text": "10.0.0.1", "source": "FIREWALL_ALERT", "submitted_by": "Sensor-01"})
    assert res.status_code == 200
    ing_id = res.json()["ingestion_id"]
    art_id = res.json()["artifact_id"]

    ing = db.get(IngestionRecordModel, ing_id)
    assert ing is not None
    assert ing.artifact_id == art_id
    assert ing.source == "FIREWALL_ALERT"
    assert ing.submitted_by == "Sensor-01"


# ---------------------------------------------------------------------------
# TEST 23: Routing candidate generation
# ---------------------------------------------------------------------------
def test_23_routing_candidate_generation():
    # URL routes to url_analyzer
    res_url = client.post("/api/ingest", json={"text": "https://threat.example/login"})
    assert "url_analyzer" in res_url.json()["candidate_analyzers"]

    # IP routes to ip_intelligence
    res_ip = client.post("/api/ingest", json={"text": "203.0.113.19"})
    assert "ip_intelligence" in res_ip.json()["candidate_analyzers"]

    # Domain routes to domain_intelligence
    res_dom = client.post("/api/ingest", json={"text": "attacker.example"})
    assert "domain_intelligence" in res_dom.json()["candidate_analyzers"]


# ---------------------------------------------------------------------------
# TEST 24: Existing EML analysis compatibility
# ---------------------------------------------------------------------------
def test_24_existing_eml_analysis_compatibility():
    """Verifies that legacy /api/emails/analyze continues to operate 100% normally."""
    files = {"file": ("legacy_test.eml", io.BytesIO(SAMPLE_EML_BYTES), "message/rfc822")}
    response = client.post("/api/emails/analyze", files=files)
    assert response.status_code == 200
    data = response.json()
    assert "threat_score" in data
    assert "evidence_id" in data
    assert data["subject"] == "Security Alert: Unauthorized Login Detected"


# ---------------------------------------------------------------------------
# TEST 25: SSRF Safety — No automatic URL fetching during ingestion
# ---------------------------------------------------------------------------
def test_25_no_automatic_url_fetching_ssrf():
    """
    Critical SSRF test: Ingesting loopback, internal IPs, and cloud metadata
    must classify and store them without making ANY outbound network requests.
    """
    internal_urls = [
        "http://127.0.0.1/admin",
        "http://localhost:8080/internal",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.1/router/config",
    ]

    with patch("httpx.AsyncClient.get") as mock_get, patch("urllib.request.urlopen") as mock_url:
        for u in internal_urls:
            response = client.post("/api/ingest", json={"text": u})
            assert response.status_code == 200
            data = response.json()
            assert data["artifact_type"] == "URL"
            assert data["analysis_status"] == "INGESTED"
            # SSRF warning was flagged
            assert any("SSRF" in w or "restricted" in w for w in data["warnings"])
            assert data["classification"]["metadata"]["is_internal_network"] is True

        # Assert no network calls were made
        assert mock_get.call_count == 0
        assert mock_url.call_count == 0


# ---------------------------------------------------------------------------
# TEST 26: Multi-input integration test (5 heterogeneous inputs)
# ---------------------------------------------------------------------------
def test_26_multi_input_heterogeneous_integration(db):
    """
    Integration test demonstrating the 5 prompt inputs:
    INPUT 1: safe test .eml -> detected EMAIL -> persisted -> email pipeline available
    INPUT 2: https://example.com/test -> detected URL -> normalized -> persisted -> url analyzer listed
    INPUT 3: 8.8.8.8 -> detected IP -> persisted -> ip analyzer listed
    INPUT 4: "This account will be suspended..." -> detected TEXT -> persisted -> NLP analyzer listed
    INPUT 5: authentication JSON event -> structured event accepted -> no fake threat classification
    """
    # INPUT 1: EML
    res1 = client.post("/api/ingest", files={"file": ("sec.eml", io.BytesIO(SAMPLE_EML_BYTES), "message/rfc822")})
    assert res1.status_code == 200
    assert res1.json()["artifact_type"] == "EMAIL"
    assert "email_forensics" in res1.json()["candidate_analyzers"]

    # INPUT 2: URL
    res2 = client.post("/api/ingest", json={"text": "https://example.com/test"})
    assert res2.status_code == 200
    assert res2.json()["artifact_type"] == "URL"
    assert "url_analyzer" in res2.json()["candidate_analyzers"]

    # INPUT 3: IP
    res3 = client.post("/api/ingest", json={"text": "8.8.8.8"})
    assert res3.status_code == 200
    assert res3.json()["artifact_type"] == "IP"
    assert "ip_intelligence" in res3.json()["candidate_analyzers"]

    # INPUT 4: Social engineering message
    res4 = client.post("/api/ingest", json={"text": "This account will be suspended. Verify immediately at our customer portal."})
    assert res4.status_code == 200
    assert res4.json()["artifact_type"] == "TEXT"
    assert "nlp_classifier" in res4.json()["candidate_analyzers"]

    # INPUT 5: Authentication JSON event
    res5 = client.post("/api/ingest", json={
        "event": {
            "source_type": "AUTH_LOG",
            "event_type": "user_mfa_challenge",
            "user": "sec_ops",
            "ip": "198.51.100.9",
            "mfa_result": "success"
        }
    })
    assert res5.status_code == 200
    assert res5.json()["artifact_type"] == "AUTH_LOG"
    assert "auth_event_parser" in res5.json()["candidate_analyzers"]
    # No fake threat classification
    assert res5.json()["analysis_status"] == "INGESTED"


# ---------------------------------------------------------------------------
# TEST 27: Capabilities registry inspection
# ---------------------------------------------------------------------------
def test_27_capabilities_endpoint():
    response = client.get("/api/ingest/capabilities")
    assert response.status_code == 200
    caps = response.json()
    assert len(caps) >= 10
    names = {c["name"] for c in caps}
    assert "email_forensics" in names
    assert "url_analyzer" in names
    assert "ip_intelligence" in names
    assert "domain_intelligence" in names
    assert "deepfake_audio" in names

    # Verify deepfake is explicitly NOT_IMPLEMENTED
    df_audio = next(c for c in caps if c["name"] == "deepfake_audio")
    assert df_audio["status"] == "NOT_IMPLEMENTED"


# ---------------------------------------------------------------------------
# TEST 28: Pre-flight detection endpoint
# ---------------------------------------------------------------------------
def test_28_preflight_detect_endpoint():
    # URL preflight
    res1 = client.post("/api/ingest/detect", json={"text": "https://malicious-login.example/auth"})
    assert res1.status_code == 200
    assert res1.json()["artifact_type"] == "URL"

    # IP preflight
    res2 = client.post("/api/ingest/detect", json={"text": "203.0.113.5"})
    assert res2.status_code == 200
    assert res2.json()["artifact_type"] == "IP"


# ---------------------------------------------------------------------------
# TEST 29: Derived artifact registration
# ---------------------------------------------------------------------------
def test_29_derived_artifact_registration(db):
    # Ingest parent
    parent_res = UniversalIngestionService.ingest_text(db=db, text="Parent investigation dossier")
    parent_id = parent_res.artifact_id

    # Register child derived artifact
    child_bytes = b"CHILD_PAYLOAD_PDF_DOCUMENT_123"
    child = UniversalIngestionService.register_derived_artifact(
        db=db,
        parent_artifact_id=parent_id,
        artifact_type=ArtifactTypeEnum.ATTACHMENT,
        name="extracted_invoice.pdf",
        data_bytes=child_bytes,
        mime_type="application/pdf",
        relationship_type=RelationshipTypeEnum.CONTAINS,
    )
    assert child.id is not None
    assert child.parent_artifact_id == parent_id
    assert child.name == "extracted_invoice.pdf"

    # Verify relationship in knowledge graph
    rel = db.query(RelationshipModel).filter(
        RelationshipModel.source_id == parent_id,
        RelationshipModel.target_id == child.id,
        RelationshipModel.relationship_type == "CONTAINS"
    ).first()
    assert rel is not None
