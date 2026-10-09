"""
Test Suite for Section 43: History & Search.
Verifies unified search, cross-investigation indicator lookup, ranking, filters,
pagination, and historical investigations list.
"""
import uuid
from datetime import datetime, timezone, timedelta
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.main import app
from backend.db.session import get_db, SessionLocal
from backend.db.models import (
    IncidentModel,
    CaseModel,
    ReportModel,
    ArtifactModel,
    IndicatorModel,
    ThreatMemoryEntryModel,
)


@pytest.fixture
def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        # Prevent immutable audit log cleanup assertion error in tests
        setattr(db.connection(), "_allow_audit_cleanup", True)
        db.close()


@pytest.fixture
def client(db_session: Session):
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def test_unified_search_exact_id(client: TestClient, db_session: Session):
    """Verifies exact lookup for investigation ID and report ID."""
    unique_inc_num = f"INV-2026-{uuid.uuid4().hex[:6].upper()}"
    inc = IncidentModel(
        id=str(uuid.uuid4()),
        incident_number=unique_inc_num,
        title="Spearphishing Targeting CFO",
        severity="CRITICAL",
        status="OPEN",
        risk_score=92.0,
        confidence=0.95,
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(inc)

    unique_rpt_num = f"RPT-2026-{uuid.uuid4().hex[:6].upper()}"
    rpt = ReportModel(
        id=str(uuid.uuid4()),
        report_number=unique_rpt_num,
        title="Executive Threat Dossier",
        investigation_id=inc.id,
        threat_score=92.0,
        severity="critical",
        status="READY",
        report_version=1,
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(rpt)
    db_session.commit()

    # Search for exact incident ID
    res1 = client.get(f"/api/search?q={unique_inc_num}")
    assert res1.status_code == 200
    data1 = res1.json()
    assert data1["total"] >= 1
    assert data1["results"][0]["id"] == inc.id
    assert data1["results"][0]["relevance"] == 100.0

    # Search for exact report ID
    res2 = client.get(f"/api/search?q={unique_rpt_num}")
    assert res2.status_code == 200
    data2 = res2.json()
    assert data2["total"] >= 1
    assert data2["results"][0]["id"] == rpt.id
    assert data2["results"][0]["type"] == "report"


def test_unified_search_exact_hash_and_indicator(client: TestClient, db_session: Session):
    """Verifies SHA-256 normalization and domain indicator search."""
    test_sha = uuid.uuid4().hex + uuid.uuid4().hex  # 64-char hex
    art = ArtifactModel(
        id=str(uuid.uuid4()),
        artifact_type="FILE",
        name="invoice_payload.pdf",
        sha256=test_sha.lower(),
        mime_type="application/pdf",
        size=4096,
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(art)


    unique_domain = f"login-{uuid.uuid4().hex[:6]}.secure-portal.com"
    ind = IndicatorModel(
        id=str(uuid.uuid4()),
        indicator_type="DOMAIN",
        value=unique_domain,
        normalized_value=unique_domain.lower(),
        confidence=0.98,
        reputation="MALICIOUS",
        first_seen=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
    )
    db_session.add(ind)
    db_session.commit()

    # Search hash with sha256: prefix and uppercase
    res_hash = client.get(f"/api/search?q=sha256:{test_sha.upper()}")
    assert res_hash.status_code == 200
    data_hash = res_hash.json()
    assert any(r["id"] == art.id and r["type"] == "evidence" for r in data_hash["results"])

    # Search defanged domain
    defanged_q = unique_domain.replace(".", "[.]")
    res_dom = client.get(f"/api/search?q={defanged_q}")
    assert res_dom.status_code == 200
    data_dom = res_dom.json()
    assert any(r["id"] == ind.id and r["type"] == "indicator" for r in data_dom["results"])


def test_search_deterministic_ranking(client: TestClient, db_session: Session):
    """Verifies that an exact ID match ranks higher than a text substring match."""
    exact_id = f"INV-2026-{uuid.uuid4().hex[:6].upper()}"
    inc_exact = IncidentModel(
        id=str(uuid.uuid4()),
        incident_number=exact_id,
        title="Normal Incident",
        severity="LOW",
        status="OPEN",
        risk_score=20.0,
        confidence=0.8,
        created_at=datetime.now(timezone.utc),
    )
    inc_partial = IncidentModel(
        id=str(uuid.uuid4()),
        incident_number=f"INV-2026-{uuid.uuid4().hex[:6].upper()}",
        title=f"Incident mentioning {exact_id} in title",
        severity="HIGH",
        status="OPEN",
        risk_score=70.0,
        confidence=0.9,
        created_at=datetime.now(timezone.utc),
    )
    db_session.add_all([inc_exact, inc_partial])
    db_session.commit()

    res = client.get(f"/api/search?q={exact_id}")
    assert res.status_code == 200
    results = res.json()["results"]
    assert len(results) >= 1
    # First result must be the exact match
    assert results[0]["id"] == inc_exact.id
    assert results[0]["relevance"] > results[1]["relevance"] if len(results) > 1 else True


def test_cross_investigation_indicator_lookup(client: TestClient, db_session: Session):
    """Verifies deep cross-investigation lookup preserving Threat Memory & provenance."""
    test_ip = f"198.51.100.{uuid.uuid4().int % 250 + 1}"
    
    # 1. First Incident
    inc1 = IncidentModel(
        id=str(uuid.uuid4()),
        incident_number=f"INC-{uuid.uuid4().hex[:6].upper()}",
        title=f"Brute force from {test_ip}",
        severity="HIGH",
        status="OPEN",
        risk_score=75.0,
        confidence=0.9,
        created_at=datetime.now(timezone.utc) - timedelta(days=2),
    )
    # 2. Second Incident
    inc2 = IncidentModel(
        id=str(uuid.uuid4()),
        incident_number=f"INC-{uuid.uuid4().hex[:6].upper()}",
        title=f"Credential stuffing via {test_ip}",
        severity="CRITICAL",
        status="CONTAINED",
        risk_score=85.0,
        confidence=0.95,
        created_at=datetime.now(timezone.utc) - timedelta(days=1),
    )
    # 3. Threat Memory entry
    tm_entry = ThreatMemoryEntryModel(
        id=str(uuid.uuid4()),
        memory_type="IP",
        subject_type="INDICATOR",
        canonical_key=test_ip,
        status="VERIFIED",
        observation_count=2,
        incident_count=2,
        campaign_count=1,
        confidence=0.95,
        provenance_type="ANALYST_VERIFIED",
        summary="Threat actor proxy node verified in SOC review",
        first_seen_at=datetime.now(timezone.utc) - timedelta(days=5),
        last_seen_at=datetime.now(timezone.utc) - timedelta(hours=3),
    )
    db_session.add_all([inc1, inc2, tm_entry])
    db_session.commit()

    res = client.get(f"/api/search/indicator/{test_ip}")
    assert res.status_code == 200
    data = res.json()
    assert data["indicator_value"] == test_ip
    assert data["total_investigations"] >= 2
    assert data["historical_memory"] is not None
    assert data["historical_memory"]["status"] == "VERIFIED"
    assert data["historical_memory"]["provenance_type"] == "ANALYST_VERIFIED"
    assert len(data["related_investigations"]) >= 2
    assert any(r["investigation_id"] == inc1.id for r in data["related_investigations"])
    assert any(r["investigation_id"] == inc2.id for r in data["related_investigations"])


def test_investigations_list_api_filters_and_facets(client: TestClient, db_session: Session):
    """Verifies GET /api/investigations with risk filters, status filters, and facets."""
    tag = uuid.uuid4().hex[:6]
    inc_crit = IncidentModel(
        id=str(uuid.uuid4()),
        incident_number=f"INC-CRIT-{tag}",
        title=f"Critical Ransomware {tag}",
        severity="CRITICAL",
        status="OPEN",
        risk_score=95.0,
        confidence=0.99,
        created_at=datetime.now(timezone.utc),
    )
    inc_low = IncidentModel(
        id=str(uuid.uuid4()),
        incident_number=f"INC-LOW-{tag}",
        title=f"Informational Log {tag}",
        severity="LOW",
        status="CLOSED",
        risk_score=15.0,
        confidence=0.7,
        created_at=datetime.now(timezone.utc) - timedelta(days=1),
    )
    db_session.add_all([inc_crit, inc_low])
    db_session.commit()

    # Query with q=tag
    res = client.get(f"/api/investigations?q={tag}")
    assert res.status_code == 200
    data = res.json()
    assert data["total"] == 2
    assert "facets" in data
    assert data["facets"]["risk"]["CRITICAL"] >= 1
    assert data["facets"]["risk"]["LOW"] >= 1

    # Filter only CRITICAL risk
    res_crit = client.get(f"/api/investigations?q={tag}&risk=CRITICAL")
    assert res_crit.status_code == 200
    data_crit = res_crit.json()
    assert data_crit["total"] == 1
    assert data_crit["items"][0]["id"] == inc_crit.id
    assert data_crit["items"][0]["severity"] == "CRITICAL"


def test_empty_search_query_handling(client: TestClient):
    """Verifies that whitespace search or empty results return a clean, truthful payload."""
    res = client.get("/api/search?q=nonexistent_token_xyz_999999")
    assert res.status_code == 200
    data = res.json()
    assert data["total"] == 0
    assert len(data["results"]) == 0
    assert data["has_more"] is False
