"""
End-to-End Multi-Investigation Scenario Tests for CyberGuard Threat Memory (Section 23).
Demonstrates the complete end-to-end specification lifecycle:
Investigation #1 -> Phishing finding & memory persisted ->
Investigation #2 -> Retrospective lookup discovers Inv #1 ->
Analyst Verification -> Verified provenance in memory ->
Subsequent investigation -> Novelty progression from first-seen to recurring.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone, timedelta
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.db.session import Base
from backend.db.models import (
    AnalysisRunModel,
    ArtifactModel,
    CampaignModel,
    EmergingPatternCandidateModel,
    FindingEvidenceModel,
    FindingModel,
    IncidentModel,
    NoveltyAssessmentModel,
    RelationshipModel,
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
)
from backend.services.threat_memory_service import ThreatMemoryService


@pytest.fixture
def scenario_db():
    """Isolated in-memory SQLite session for synthetic scenario tests."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    try:
        yield session
    finally:
        session.close()


def test_complete_section_23_end_to_end_scenario(scenario_db):
    """
    Validates Section 23 Success Criteria:
    Investigation #1:
        Domain X observed
        Phishing finding generated
        Observation persisted
        Threat Memory updated
    Investigation #2:
        Domain X observed again
        Threat Memory lookup
        Historical context returned
        Investigation #1 discovered
        Previous evidence discovered
        Previous classification discovered
        Campaign/infrastructure relationships discovered
        Current analysis enriched
    Later:
        Analyst verifies one observation
        Verification persisted
        Historical memory shows verified provenance
    Another investigation:
        Same pattern appears
        Novelty history shows first-seen -> recurring
        Threat Memory exposes the progression
    """
    workspace_id = "tenant-cyberguard-demo"
    target_domain = "example-banking-login.com"
    target_ip = "198.51.100.42"

    # ========================================================================
    # STEP 1: Investigation #1 (First observation of Domain X)
    # ========================================================================
    inc1 = IncidentModel(
        id=generate_uuid(),
        incident_number="INC-2026-0001",
        workspace_id=workspace_id,
        title="Phishing attack targeting Treasury staff",
        status="INVESTIGATING",
        severity="HIGH",
        risk_score=82.0,
    )
    scenario_db.add(inc1)

    campaign1 = CampaignModel(
        id=generate_uuid(),
        campaign_id="CAMP-2026-X1",
        name="Operation PhishHook",
        workspace_id=workspace_id,
    )
    scenario_db.add(campaign1)
    scenario_db.flush()

    # Link infrastructure edge in Section 14 Knowledge Graph: Domain -> resolves_to -> IP
    rel1 = RelationshipModel(
        id=generate_uuid(),
        source_type="DOMAIN",
        source_id=f"DOMAIN:{target_domain}",
        relationship_type="RESOLVES_TO",
        target_type="IP",
        target_id=f"IP:{target_ip}",
        confidence=0.95,
        origin="OBSERVED",
        status="ACTIVE",
        workspace_id=workspace_id,
    )
    scenario_db.add(rel1)
    scenario_db.flush()

    # Domain X observed in Inv #1
    entry1, obs1, is_new1 = ThreatMemoryService.record_observation(
        db=scenario_db,
        workspace_id=workspace_id,
        subject_type=MemoryType.DOMAIN,
        value=target_domain,
        source_type="FINDING",
        source_id="f-phish-01",
        investigation_id="INV-001",
        incident_id=inc1.id,
        campaign_id=campaign1.id,
        classification=ObservationClassification.MALICIOUS,
        severity="HIGH",
        confidence=0.90,
        evidence_reference="E-PHISH-01",
        detector_name="url_domain_intelligence",
        detector_version="1.0.0",
        observed_at=datetime(2026, 8, 11, 10, 0, tzinfo=timezone.utc),
    )
    scenario_db.commit()

    assert is_new1 is True
    assert entry1.canonical_key == f"DOMAIN:{target_domain}"
    assert entry1.observation_count == 1
    assert entry1.incident_count == 1
    assert entry1.campaign_count == 1
    assert entry1.status == MemoryStatus.OBSERVED.value

    # ========================================================================
    # STEP 2: Investigation #2 (Domain X observed again)
    # ========================================================================
    inc2 = IncidentModel(
        id=generate_uuid(),
        incident_number="INC-2026-0002",
        workspace_id=workspace_id,
        title="Suspicious email with credential link",
        status="OPEN",
        severity="MEDIUM",
        risk_score=65.0,
    )
    scenario_db.add(inc2)
    scenario_db.flush()

    # Record observation in Inv #2
    entry2, obs2, is_new2 = ThreatMemoryService.record_observation(
        db=scenario_db,
        workspace_id=workspace_id,
        subject_type=MemoryType.DOMAIN,
        value=target_domain,
        source_type="FINDING",
        source_id="f-phish-02",
        investigation_id="INV-002",
        incident_id=inc2.id,
        classification=ObservationClassification.MALICIOUS,
        severity="HIGH",
        confidence=0.88,
        evidence_reference="E-PHISH-02",
        detector_name="url_domain_intelligence",
        detector_version="1.0.0",
        observed_at=datetime(2026, 10, 3, 14, 30, tzinfo=timezone.utc),
    )
    scenario_db.commit()

    assert is_new2 is False
    assert entry2.observation_count == 2
    assert entry2.independent_source_count == 2
    # Automatically promoted to CORRELATED across independent investigations
    assert entry2.status == MemoryStatus.CORRELATED.value

    # Investigation #2 performs retrospective Threat Memory lookup
    mem_context = ThreatMemoryService.build_threat_memory_context(
        scenario_db,
        workspace_id=workspace_id,
        value_or_key=target_domain,
        subject_type=MemoryType.DOMAIN,
        include_graph=True,
    )

    # 1. Historical context returned
    assert mem_context.historical_context_available is True
    assert mem_context.observation_count == 2
    assert mem_context.independent_source_count == 2

    # 2. Previous Investigation #1 discovered
    prior_inv_ids = [o.investigation_id for o in mem_context.prior_observations]
    assert "INV-001" in prior_inv_ids
    assert "INV-002" in prior_inv_ids

    # 3. Previous evidence discovered
    prior_ev_refs = [o.evidence_reference for o in mem_context.prior_observations]
    assert "E-PHISH-01" in prior_ev_refs

    # 4. Previous classifications discovered
    assert mem_context.conflict.malicious_count == 2
    assert mem_context.conflict.is_conflicted is False

    # 5. Related incidents & campaigns discovered
    rel_inc_numbers = [inc["incident_number"] for inc in mem_context.related_incidents]
    assert "INC-2026-0001" in rel_inc_numbers

    rel_camp_ids = [c["campaign_id"] for c in mem_context.related_campaigns]
    assert "CAMP-2026-X1" in rel_camp_ids

    # 6. Graph infrastructure discovered (resolves_to 198.51.100.42)
    assert len(mem_context.related_infrastructure) >= 1
    assert any(target_ip in str(infra.get("target_id")) for infra in mem_context.related_infrastructure)

    # 7. Contextual enrichment test
    enriched = ThreatMemoryService.enrich_analysis_with_memory(
        scenario_db,
        workspace_id=workspace_id,
        indicators=[{"type": "DOMAIN", "value": target_domain}],
    )
    assert len(enriched) == 1
    assert enriched[0]["historical_seen"] is True
    assert enriched[0]["observation_count"] == 2
    assert enriched[0]["incident_count"] >= 1

    # ========================================================================
    # STEP 3: Analyst Verification (Human Review)
    # ========================================================================
    dec = ThreatMemoryService.record_analyst_decision(
        db=scenario_db,
        workspace_id=workspace_id,
        canonical_key=entry2.canonical_key,
        decision=AnalystDecisionType.VERIFIED_MALICIOUS,
        reason="Confirmed credential harvesting kit targeting Treasury single sign-on.",
        approved_by="senior_analyst_sam@cyberguard.internal",
        valid_days=90,
        evidence_ids=["E-PHISH-01", "E-PHISH-02"],
    )
    scenario_db.commit()

    # Re-inspect memory context
    verified_context = ThreatMemoryService.build_threat_memory_context(
        scenario_db,
        workspace_id=workspace_id,
        value_or_key=target_domain,
        subject_type=MemoryType.DOMAIN,
    )
    assert verified_context.is_analyst_verified is True
    assert verified_context.verification_status == AnalystDecisionType.VERIFIED_MALICIOUS.value
    assert verified_context.memory_status == MemoryStatus.VERIFIED

    # ========================================================================
    # STEP 4: Novelty Progression Integration (First Seen -> Recurring)
    # ========================================================================
    # Day 1: Pattern initially evaluated as novel
    nov1 = NoveltyAssessmentModel(
        id=generate_uuid(),
        workspace_id=workspace_id,
        entity_type="DOMAIN",
        entity_id=target_domain,
        novelty_type="STRUCTURAL_ANOMALY",
        novelty_score=0.92,
        novelty_level="HIGH",
        similarity_score=0.08,
        historical_sample_count=0,
        fingerprint_hash=target_domain,
        created_at=datetime(2026, 8, 11, 10, 0, tzinfo=timezone.utc),
    )
    scenario_db.add(nov1)

    # Day 50: Pattern observed repeatedly across incidents, captured as emerging candidate
    emerging_cand = EmergingPatternCandidateModel(
        id=generate_uuid(),
        workspace_id=workspace_id,
        pattern_type="STRUCTURAL_ANOMALY",
        fingerprint_hash=target_domain,
        fingerprint_repr=f"DOMAIN:{target_domain}",
        novelty_score=0.20,
        recurrence_score=0.85,
        first_seen=datetime(2026, 8, 11, 10, 0, tzinfo=timezone.utc),
        last_seen=datetime(2026, 10, 3, 14, 30, tzinfo=timezone.utc),
        observation_count=4,
        incident_count=2,
        status="EMERGING",
    )
    scenario_db.add(emerging_cand)
    scenario_db.commit()

    # Check that Threat Memory retrieves the pattern evolution
    progression = ThreatMemoryService.get_novelty_progression(
        scenario_db,
        workspace_id=workspace_id,
        canonical_key=f"DOMAIN:{target_domain}",
    )
    assert len(progression) == 2
    assert progression[0]["type"] == "NOVELTY_ASSESSMENT"
    assert progression[0]["novelty_score"] == 0.92
    assert progression[0]["novelty_level"] == "HIGH"
    assert progression[1]["type"] == "EMERGING_PATTERN"
    assert progression[1]["status"] == "EMERGING"
    assert progression[1]["observation_count"] == 4
    assert progression[1]["recurrence_score"] == 0.85
