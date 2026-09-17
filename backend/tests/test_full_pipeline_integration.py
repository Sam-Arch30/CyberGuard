import io
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.main import app
from backend.db.session import SessionLocal


SAMPLE_RFC822_EML = b"""Received: from mail.attacker-domain.example (mail.attacker-domain.example [203.0.113.19])
    by mx.target-corp.example (Postfix) with ESMTP id 4X9kL82Z
    for <victim@target-corp.example>; Tue, 16 Sep 2026 14:22:10 +0000
Received: from internal-node.local (10.0.0.5)
    by mail.attacker-domain.example with SMTP id 99A12BC;
    Tue, 16 Sep 2026 14:21:45 +0000
From: "Executive Support" <support@micros0ft-update.example>
Reply-To: <collector@untrusted-drop.example>
To: <victim@target-corp.example>
Subject: CRITICAL: Immediate Wire Transfer & Password Verification Required #8821
Date: Tue, 16 Sep 2026 14:21:30 +0000
Message-ID: <threat-8821@micros0ft-update.example>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BOUNDARY-INT-TEST"

--BOUNDARY-INT-TEST
Content-Type: text/plain; charset="utf-8"

URGENT: Please verify your account credentials immediately at http://login-security.micros0ft-update.example/verify
Failure to respond within 24 hours will result in wire transfer suspension.

--BOUNDARY-INT-TEST
Content-Type: application/octet-stream; name="invoice_document.pdf.exe"
Content-Disposition: attachment; filename="invoice_document.pdf.exe"
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAA4AAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1v
ZGUuDQ0KJAAAAAAAAABQRQAATAEDAAAAAAAAAAAAAAAAAAAAAAAA
--BOUNDARY-INT-TEST--
"""


@pytest.fixture
def client():
    return TestClient(app)


def test_full_investigation_pipeline_e2e(client: TestClient):
    """
    End-to-end integration test validating the complete 20-stage pipeline:
    1. Ingestion & upload validation
    2. RFC-822 Parsing & MIME dissection
    3. IOC Extraction (IPs, domains, URLs, email addresses)
    4. Attachment static analysis (disguised double extension, PE header)
    5. Authentication & sender alignment (From vs Reply-To mismatch)
    6. Relay path reconstruction & earliest untrusted hop identification
    7. Lookalike domain detection (micros0ft-update)
    8. Deterministic explainable threat scoring
    9. Cryptographic evidence registration & audit trail
    10. Infrastructure attribution engine
    11. Investigation relationship graph construction
    12. Evidence-grounded Copilot query
    """
    # 1. Ingestion via POST /api/emails/analyze
    files = {
        "file": ("test_phish.eml", io.BytesIO(SAMPLE_RFC822_EML), "message/rfc822")
    }
    response = client.post("/api/emails/analyze", files=files)
    assert response.status_code == 200, f"Analysis failed: {response.text}"
    data = response.json()

    # 2. Verify Parsed Metadata
    assert data["subject"] == "CRITICAL: Immediate Wire Transfer & Password Verification Required #8821"
    assert "victim@target-corp.example" in str(data["to"])
    sender = data.get("from") or data.get("from_header") or ""
    assert "support@micros0ft-update.example" in sender
    assert data["reply_to"] == "collector@untrusted-drop.example"

    # 3. Verify IOC Extraction
    assert "203.0.113.19" in data["ips"]
    assert any("micros0ft-update.example" in d for d in data["domains"])
    assert any("login-security.micros0ft-update.example" in u for u in data["urls"])

    # 4. Verify Attachment Static Analysis
    attachments = data.get("attachments", [])
    assert len(attachments) >= 1
    att = attachments[0]
    assert att["filename"] == "invoice_document.pdf.exe"
    assert att["sha256"] is not None and len(att["sha256"]) == 64
    static_analysis = att.get("static_analysis")
    assert static_analysis is not None
    assert static_analysis.get("double_extension") is True
    assert static_analysis.get("threat_level") in ("CRITICAL", "HIGH")

    # 5. Verify Authentication & Alignment
    auth = data.get("authentication")
    assert auth is not None
    alignment = auth.get("alignment")
    assert alignment is not None
    assert alignment["reply_to_mismatch"] is True

    # 6. Verify Relay Reconstruction
    relay = data.get("relay_analysis")
    assert relay is not None
    earliest_node = relay.get("earliest_observable_node")
    assert earliest_node is not None
    assert earliest_node["earliest_observable_ip"] == "203.0.113.19"

    # 7. Verify Lookalike Detection
    lookalikes = data.get("lookalike_domains", [])
    assert len(lookalikes) > 0
    assert any("microsoft" in (lk.get("brand_name", "") or lk.get("suspected_brand", "")).lower() for lk in lookalikes)

    # 8. Verify Threat Scoring
    threat_score = data.get("threat_score")
    assert threat_score is not None
    assert threat_score["score"] >= 75
    assert threat_score["severity"].lower() == "critical"
    assert len(threat_score["top_reasons"]) > 0

    # 9. Verify Evidence Traceability & Audit Logging
    evidence_id = data.get("evidence_id")
    assert evidence_id is not None
    assert evidence_id.startswith("EVD-")

    sha256_val = data.get("email_sha256") or data.get("sha256") or evidence_id
    timeline_resp = client.get(f"/api/emails/{sha256_val}/timeline")
    assert timeline_resp.status_code == 200
    timeline = timeline_resp.json()
    assert len(timeline.get("events", [])) >= 2  # EMAIL_UPLOADED, ANALYSIS_COMPLETED

    # 10. Verify Infrastructure Attribution
    attribution = data.get("attribution")
    assert attribution is not None
    assert attribution["probable_origin_ip"] == "203.0.113.19"
    assert len(attribution["supporting_evidence"]) > 0

    # 11. Verify Investigation Graph
    graph = data.get("investigation_graph")
    assert graph is not None
    assert len(graph.get("nodes", [])) >= 4
    assert len(graph.get("edges", [])) >= 3
    node_types = {n["type"].lower() for n in graph["nodes"]}
    assert "email" in node_types
    assert "ip" in node_types
    assert "domain" in node_types
    assert "attachment" in node_types

    # 12. Verify Investigation Copilot Grounded Query
    copilot_query = {
        "query": "Why was this email classified as malicious?",
        "mode": "email",
        "context_id": evidence_id,
        "email_payload": data
    }
    copilot_resp = client.post("/api/copilot/query", json=copilot_query)
    assert copilot_resp.status_code == 200
    copilot_data = copilot_resp.json()
    assert copilot_data["assessment"] is not None
    assert len(copilot_data["evidence_refs"]) > 0
    assert copilot_data["confidence"] in ("CONFIRMED", "HIGH-CONFIDENCE INFERENCE", "PROBABLE")
    answer_text = (copilot_data["assessment"] + " " + copilot_data.get("reasoning_summary", "")).lower()
    assert "critical" in answer_text or "threat" in answer_text or "score" in answer_text


def test_malformed_email_graceful_handling(client: TestClient):
    """
    Ensures that corrupted/malformed input degrades gracefully with HTTP 400
    and a structured error response, rather than crashing with an unhandled 500.
    """
    corrupted_data = b"This is not a valid email file at all! No headers here."
    files = {
        "file": ("corrupted.eml", io.BytesIO(corrupted_data), "message/rfc822")
    }
    response = client.post("/api/emails/analyze", files=files)
    assert response.status_code == 400
    err = response.json()
    assert "detail" in err
