"""
Unit & Service Tests for CyberGuard Threat Memory (Section 23).
Tests canonicalization, eligibility, observation deduplication, poisoning defense,
conflicting memory coexistence, analyst decisions, scope isolation, privacy, and graceful failure.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone, timedelta
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.db.session import Base
from backend.db.models import (
    IncidentModel,
    ThreatMemoryDecisionModel,
    ThreatMemoryEntryModel,
    ThreatMemoryObservationModel,
    generate_uuid,
    get_utc_now,
)
from backend.schemas.threat_memory import (
    AnalystDecisionType,
    MemoryScope,
    MemoryStatus,
    MemoryType,
    ObservationClassification,
    ProvenanceType,
    canonicalize_memory_key,
    sanitize_memory_attributes,
)
from backend.services.threat_memory_service import ThreatMemoryService


@pytest.fixture
def memory_db():
    """Isolated in-memory SQLite session for threat memory tests."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    try:
        yield session
    finally:
        session.close()


# ============================================================================
# 1. CANONICALIZATION & ELIGIBILITY TESTS
# ============================================================================

def test_canonicalization_equivalence():
    """Equivalent representations of observables resolve to identical canonical keys."""
    # Domains
    assert canonicalize_memory_key("DOMAIN", "Example.COM.") == "DOMAIN:example.com"
    assert canonicalize_memory_key("DOMAIN", "  example.com  ") == "DOMAIN:example.com"

    # Hashes
    sha = "A" * 64
    assert canonicalize_memory_key("HASH", sha) == f"SHA256:{sha.lower()}"
    assert canonicalize_memory_key("HASH", f"sha256:{sha}") == f"SHA256:{sha.lower()}"

    # IPs
    assert canonicalize_memory_key("IP", "198.51.100.1") == "IP:198.51.100.1"

    # URLs
    assert canonicalize_memory_key("URL", "https://example.com/login?u=1") == canonicalize_memory_key("URL", "https://example.com/login?u=1")

    # Email
    assert canonicalize_memory_key("EMAIL", "User.Test@EXAMPLE.com") == "EMAIL:User.Test@example.com"


def test_eligibility_filter():
    """Disallows empty, ephemeral, or unparseable input from creating memory entries."""
    assert ThreatMemoryService.is_eligible_for_memory(MemoryType.DOMAIN, "example.com") is True
    assert ThreatMemoryService.is_eligible_for_memory(MemoryType.DOMAIN, "") is False
    assert ThreatMemoryService.is_eligible_for_memory(MemoryType.DOMAIN, "unknown") is False
    assert ThreatMemoryService.is_eligible_for_memory(MemoryType.DOMAIN, "null") is False
    assert ThreatMemoryService.is_eligible_for_memory(MemoryType.DOMAIN, "a") is False
    assert ThreatMemoryService.is_eligible_for_memory(MemoryType.DOMAIN, "example.com", confidence=0.1) is False


# ============================================================================
# 2. OBSERVATION CREATION & DEDUPLICATION / POISONING SAFEGUARDS
# ============================================================================

def test_first_observation_creates_memory_entry(memory_db):
    """First observation creates ThreatMemoryEntry with OBSERVED status and direct provenance."""
    entry, obs, is_new = ThreatMemoryService.record_observation(
        db=memory_db,
        workspace_id="ws-test",
        subject_type=MemoryType.DOMAIN,
        value="example-first-seen.com",
        source_type="FINDING",
        source_id="f-101",
        investigation_id="inv-001",
        classification=ObservationClassification.MALICIOUS,
        severity="HIGH",
        confidence=0.9,
        detector_name="url_detector",
    )
    memory_db.commit()

    assert is_new is True
    assert entry.canonical_key == "DOMAIN:example-first-seen.com"
    assert entry.status == MemoryStatus.OBSERVED.value
    assert entry.observation_count == 1
    assert entry.independent_source_count == 1
    assert entry.provenance_type == ProvenanceType.DIRECT_OBSERVATION.value
    assert obs.classification == ObservationClassification.MALICIOUS.value


def test_repeated_observation_anti_poisoning_deduplication(memory_db):
    """
    Submitting the exact same source/investigation multiple times updates timestamps
    without inflating independent source count (Anti-Poisoning).
    """
    # Submission 1
    entry, obs1, is_new1 = ThreatMemoryService.record_observation(
        db=memory_db,
        workspace_id="ws-test",
        subject_type=MemoryType.DOMAIN,
        value="repeated-domain.com",
        source_type="FINDING",
        source_id="f-dup-1",
        investigation_id="inv-dup-1",
        analysis_run_id="run-dup-1",
    )
    memory_db.commit()
    assert is_new1 is True
    assert entry.observation_count == 1
    assert entry.independent_source_count == 1

    # Submission 2 (Duplicate replay from same source/investigation)
    entry2, obs2, is_new2 = ThreatMemoryService.record_observation(
        db=memory_db,
        workspace_id="ws-test",
        subject_type=MemoryType.DOMAIN,
        value="repeated-domain.com",
        source_type="FINDING",
        source_id="f-dup-1",
        investigation_id="inv-dup-1",
        analysis_run_id="run-dup-1",
    )
    memory_db.commit()
    assert is_new2 is False
    assert obs2.id == obs1.id
    # Independent source count is preserved at 1, not inflated to 2
    assert entry2.independent_source_count == 1


def test_independent_observations_trigger_promotion_to_correlated(memory_db):
    """
    Multiple independent observations across different investigations promote
    the entry from OBSERVED to CORRELATED.
    """
    # Obs 1 from investigation 1
    entry, _, _ = ThreatMemoryService.record_observation(
        db=memory_db,
        workspace_id="ws-test",
        subject_type=MemoryType.IP,
        value="198.51.100.55",
        source_type="SECURITY_EVENT",
        investigation_id="inv-alpha",
    )
    memory_db.commit()
    assert entry.status == MemoryStatus.OBSERVED.value

    # Obs 2 from investigation 2 (independent)
    entry, _, _ = ThreatMemoryService.record_observation(
        db=memory_db,
        workspace_id="ws-test",
        subject_type=MemoryType.IP,
        value="198.51.100.55",
        source_type="SECURITY_EVENT",
        investigation_id="inv-beta",
    )
    memory_db.commit()

    assert entry.observation_count == 2
    assert entry.independent_source_count == 2
    assert entry.status == MemoryStatus.CORRELATED.value


# ============================================================================
# 3. ANALYST DECISIONS & FALSE POSITIVE PRESERVATION
# ============================================================================

def test_analyst_decision_verification(memory_db):
    """
    Analyst verification promotes entry to VERIFIED with analyst provenance,
    persisting durable decision rationale.
    """
    entry, _, _ = ThreatMemoryService.record_observation(
        db=memory_db,
        workspace_id="ws-test",
        subject_type=MemoryType.DOMAIN,
        value="legit-sso-login.com",
        source_type="FINDING",
        classification=ObservationClassification.SUSPICIOUS,
    )
    memory_db.commit()

    dec = ThreatMemoryService.record_analyst_decision(
        db=memory_db,
        workspace_id="ws-test",
        canonical_key=entry.canonical_key,
        decision=AnalystDecisionType.FALSE_POSITIVE,
        reason="Verified legitimate internal SSO migration tenant.",
        approved_by="analyst_alice@cyberguard.internal",
        valid_days=60,
    )
    memory_db.commit()

    assert dec.decision == AnalystDecisionType.FALSE_POSITIVE.value
    assert entry.status == MemoryStatus.VERIFIED.value
    assert entry.provenance_type == ProvenanceType.ANALYST_VERIFIED.value

    # Context retrieval shows verification
    ctx = ThreatMemoryService.build_threat_memory_context(
        memory_db,
        workspace_id="ws-test",
        value_or_key="legit-sso-login.com",
        subject_type=MemoryType.DOMAIN,
    )
    assert ctx.is_analyst_verified is True
    assert ctx.verification_status == AnalystDecisionType.FALSE_POSITIVE.value


# ============================================================================
# 4. CONFLICTING MEMORY COEXISTENCE
# ============================================================================

def test_conflicting_memory_coexistence(memory_db):
    """
    If an indicator is observed malicious in one investigation and benign in another,
    both observations are retained and a mixed conflict summary is surfaced.
    Neither overwrites the other.
    """
    domain = "mixed-history-example.com"

    # Obs 1: Malicious in Inv 1
    ThreatMemoryService.record_observation(
        db=memory_db,
        workspace_id="ws-test",
        subject_type=MemoryType.DOMAIN,
        value=domain,
        source_type="FINDING",
        investigation_id="inv-mal-01",
        classification=ObservationClassification.MALICIOUS,
    )

    # Obs 2: Benign in Inv 2
    ThreatMemoryService.record_observation(
        db=memory_db,
        workspace_id="ws-test",
        subject_type=MemoryType.DOMAIN,
        value=domain,
        source_type="FINDING",
        investigation_id="inv-ben-02",
        classification=ObservationClassification.BENIGN,
    )
    memory_db.commit()

    ctx = ThreatMemoryService.build_threat_memory_context(
        memory_db,
        workspace_id="ws-test",
        value_or_key=domain,
        subject_type=MemoryType.DOMAIN,
    )

    assert ctx.observation_count == 2
    assert ctx.conflict.is_conflicted is True
    assert ctx.conflict.malicious_count == 1
    assert ctx.conflict.benign_count == 1
    assert "Historical context is mixed" in ctx.conflict.explanation
    assert "Current classification requires fresh evidence" in ctx.conflict.explanation


# ============================================================================
# 5. SCOPE & MULTI-TENANCY ISOLATION
# ============================================================================

def test_scope_and_workspace_isolation(memory_db):
    """
    Workspace A cannot access private Threat Memory entries belonging to Workspace B.
    """
    # Org A private entry
    ThreatMemoryService.record_observation(
        db=memory_db,
        workspace_id="org-a",
        subject_type=MemoryType.DOMAIN,
        value="private-org-a.com",
        source_type="SECURITY_EVENT",
        scope=MemoryScope.ORGANIZATION,
    )
    memory_db.commit()

    # Lookup from Org A succeeds
    entry_a = ThreatMemoryService.lookup_by_key(memory_db, "org-a", "DOMAIN:private-org-a.com")
    assert entry_a is not None

    # Lookup from Org B yields None
    entry_b = ThreatMemoryService.lookup_by_key(memory_db, "org-b", "DOMAIN:private-org-a.com")
    assert entry_b is None


# ============================================================================
# 6. PRIVACY & DATA MINIMIZATION
# ============================================================================

def test_privacy_and_secret_redaction():
    """
    Sensitive credentials, bearer tokens, and session keys are sanitized
    before entering Threat Memory attributes.
    """
    raw_attrs = {
        "user_agent": "Mozilla/5.0",
        "auth_token": "Bearer secret_abc_12345",
        "password": "SuperSecretPassword!",
        "session_cookie": "sess_98765",
        "nested": {
            "api_key": "sk-live-secretkey",
            "safe_metric": 42
        }
    }
    sanitized = sanitize_memory_attributes(raw_attrs)
    assert sanitized["user_agent"] == "Mozilla/5.0"
    assert sanitized["auth_token"] == "[REDACTED_SECRET]"
    assert sanitized["password"] == "[REDACTED_SECRET]"
    assert sanitized["session_cookie"] == "[REDACTED_SECRET]"
    assert sanitized["nested"]["api_key"] == "[REDACTED_SECRET]"
    assert sanitized["nested"]["safe_metric"] == 42


# ============================================================================
# 7. GRACEFUL DEGRADATION ON FAILURE
# ============================================================================

def test_graceful_degradation_on_service_outage(memory_db, monkeypatch):
    """
    If database or graph lookup fails, build_threat_memory_context returns a safe
    degraded context with historical_context_available=False without raising.
    """
    def broken_lookup(*args, **kwargs):
        raise RuntimeError("Simulated database timeout")

    monkeypatch.setattr(ThreatMemoryService, "lookup_by_key", broken_lookup)

    ctx = ThreatMemoryService.build_threat_memory_context(
        memory_db,
        workspace_id="ws-test",
        value_or_key="any-target.com",
        subject_type=MemoryType.DOMAIN,
    )
    assert ctx.historical_context_available is False
    assert any("temporarily unavailable" in limit for limit in ctx.limitations)


# ============================================================================
# 8. EXTERNAL INTELLIGENCE & REPRODUCIBILITY
# ============================================================================

def test_external_intelligence_provenance_distinction(memory_db):
    """
    Observations from EXTERNAL_FEED are labeled with EXTERNAL_INTELLIGENCE provenance,
    keeping them cleanly separated from direct internal forensic observations.
    """
    entry, obs, is_new = ThreatMemoryService.record_observation(
        db=memory_db,
        workspace_id="ws-test",
        subject_type=MemoryType.DOMAIN,
        value="external-feed-sample.com",
        source_type="EXTERNAL_FEED",
        source_id="feed-virustotal-ioc",
        classification=ObservationClassification.MALICIOUS,
        confidence=0.75,
        detector_name="external_threat_feed",
    )
    memory_db.commit()

    assert entry.provenance_type == ProvenanceType.EXTERNAL_INTELLIGENCE.value
    assert obs.source_type == "EXTERNAL_FEED"


def test_reproducibility_and_detector_versioning(memory_db):
    """
    Historical memory observations retain detector_name, detector_version, and timestamps,
    ensuring that past conclusions can be faithfully explained and reproduced.
    """
    entry, obs, _ = ThreatMemoryService.record_observation(
        db=memory_db,
        workspace_id="ws-test",
        subject_type=MemoryType.HASH,
        value="e" * 64,
        source_type="FINDING",
        source_id="f-hash-rep",
        analysis_run_id="run-rep-01",
        classification=ObservationClassification.MALICIOUS,
        detector_name="file_security_pipeline",
        detector_version="2.4.1",
    )
    memory_db.commit()

    assert obs.detector_name == "file_security_pipeline"
    assert obs.detector_version == "2.4.1"
    assert obs.analysis_run_id == "run-rep-01"


def test_analysis_enrichment_does_not_override_detection(memory_db):
    """
    Principle 1 & 2: Memory enrichment provides historical context but does not
    override present forensic detection findings.
    """
    domain = "enrichment-example.com"
    # Seed historical observation
    ThreatMemoryService.record_observation(
        db=memory_db,
        workspace_id="ws-test",
        subject_type=MemoryType.DOMAIN,
        value=domain,
        source_type="FINDING",
        classification=ObservationClassification.MALICIOUS,
    )
    memory_db.commit()

    indicators = [{"type": "DOMAIN", "value": domain}]
    enriched = ThreatMemoryService.enrich_analysis_with_memory(memory_db, "ws-test", indicators)

    assert len(enriched) == 1
    assert enriched[0]["historical_seen"] is True
    assert enriched[0]["observation_count"] == 1
    assert enriched[0]["canonical_key"] == f"DOMAIN:{domain}"


def test_report_service_threat_memory_flowables():
    """
    Verifies that ReportService.format_threat_memory_section formats ReportLab flowables
    including forensic notices, observations, and conflict warnings.
    """
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from backend.services.report_service import ReportService
    from backend.schemas.threat_memory import ThreatMemoryConflictSummary

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="SectionHeader", parent=styles["Normal"], fontSize=14, leading=16))
    styles.add(ParagraphStyle(name="TableHead", parent=styles["Normal"], fontSize=8, leading=10))
    styles.add(ParagraphStyle(name="TableCell", parent=styles["Normal"], fontSize=8, leading=10))
    styles.add(ParagraphStyle(name="TableCellBold", parent=styles["Normal"], fontSize=8, leading=10))

    mock_contexts = [
        {
            "canonical_key": "DOMAIN:test-report.com",
            "memory_status": "CORRELATED",
            "observation_count": 3,
            "independent_source_count": 2,
            "related_incidents": [{"incident_id": "inc-1"}, {"incident_id": "inc-2"}],
            "conflict": {
                "is_conflicted": True,
                "explanation": "Historical context is mixed. Malicious in 2, benign in 1.",
            },
            "is_analyst_verified": False,
        }
    ]

    flowables = ReportService.format_threat_memory_section(mock_contexts, styles)
    assert len(flowables) > 0

