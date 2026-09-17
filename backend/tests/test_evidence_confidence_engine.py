import json
import pytest
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient

from backend.main import app
from backend.services.evidence_confidence_engine import EvidenceConfidenceEngine
from backend.schemas.evidence_confidence import (
    EvidenceCategory,
    ConclusionType,
    EvaluatedEvidence,
    ForensicConclusion
)
from backend.schemas.email import (
    EmailAnalysisResponse,
    AuthenticationAnalysis,
    ProtocolResult,
    LookalikeDetectionResult,
    URLAnalysisResult
)
from backend.schemas.url_analysis import URLFeatures
from backend.schemas.threat_score import ThreatScoreResult
from backend.schemas.attribution import AttributionResult
from backend.schemas.ip_intelligence import IPIntelligence
from backend.schemas.domain_intelligence import DomainIntelligence, DomainRegistration
from backend.services.ai_analyst_service import AIAnalystService


client = TestClient(app)


@pytest.fixture
def engine():
    return EvidenceConfidenceEngine()


def test_unanimous_evidence(engine):
    """
    Unanimous corroboration across multiple independent modules (Auth, Threat Score,
    Lookalike, URL, IP Intel) yields HIGH or VERY HIGH confidence without false precision.
    """
    analysis = EmailAnalysisResponse(
        id="test-unanimous",
        evidence_id="EVD-UNANIMOUS-001",
        subject="URGENT: Verify Bank Credentials",
        plain_text_body="Immediate action required. Verify your corporate bank account: https://micros0ft-login.com/auth",
        threat_score=ThreatScoreResult(
            score=88,
            severity="critical",
            reasons=[],
            positive_evidence=[],
            summary="Critical threat indicators detected"
        ),
        authentication=AuthenticationAnalysis(
            spf=ProtocolResult(result="fail"),
            dkim=ProtocolResult(result="fail"),
            dmarc=ProtocolResult(result="fail")
        ),
        ml_phishing_probability=0.92,
        lookalike_domains=[
            LookalikeDetectionResult(
                domain="micros0ft-login.com",
                brand_name="Microsoft",
                suspected_brand="Microsoft",
                similarity=0.92,
                techniques=["homoglyph_substitution", "subdomain_impersonation"],
                confidence_label="HIGH"
            )
        ],
        url_analysis=[
            URLAnalysisResult(
                url="https://micros0ft-login.com/auth",
                domain="micros0ft-login.com",
                features=URLFeatures(scheme="https", hostname="micros0ft-login.com"),
                suspicion_score=85,
                suspicion_level="high",
                score_reasons=["Lookalike domain", "Credential keyword in path"]
            )
        ],
        attribution=AttributionResult(
            attribution_id="ATTR-UNANIMOUS",
            probable_origin_ip="203.0.113.25",
            probable_origin_asn="AS64512",
            probable_origin_provider="Threat Hosting Corp",
            probable_infrastructure_country="United States",
            confidence_score=82,
            confidence_level="HIGH",
            supporting_evidence=[],
            conflicting_evidence=[],
            analysis_timestamp=datetime.now(timezone.utc).isoformat()
        )
    )

    conclusions = engine.evaluate_email(analysis)
    assert len(conclusions) >= 5

    # 1. Threat Classification Conclusion
    threat_conc = next(c for c in conclusions if c.type == ConclusionType.THREAT_CLASSIFICATION)
    assert threat_conc.confidence_level in ("HIGH", "VERY HIGH")
    assert threat_conc.confidence_score >= 70
    assert float(threat_conc.confidence_score).is_integer()  # Zero false precision!
    assert any(e.evidence_category == EvidenceCategory.CONFIRMED_EVIDENCE for e in threat_conc.supporting_evidence)

    # 2. Lookalike Conclusion
    look_conc = next(c for c in conclusions if c.type == ConclusionType.LOOKALIKE_DOMAIN)
    assert look_conc.confidence_score >= 70
    assert "micros0ft-login.com" in look_conc.supporting_evidence[0].statement


def test_contradictory_evidence(engine):
    """
    Explicitly detects contradictory evidence:
    - Earliest public relay geolocates to Singapore.
    - WHOIS organization registration points to Netherlands.
    - Sender Date header specifies timezone offset +0530 (India).
    Engine surfaces these in conflicting_evidence[] and applies deduction penalties.
    """
    analysis = EmailAnalysisResponse(
        id="test-contradiction",
        evidence_id="EVD-CONTRADICTION-001",
        date="Fri, 11 Sep 2026 14:30:00 +0530",  # Indian Timezone (+0530)
        attribution=AttributionResult(
            attribution_id="ATTR-SG",
            probable_origin_ip="203.0.113.88",
            probable_origin_asn="AS4657",
            probable_origin_provider="Singapore StarHub",
            probable_infrastructure_country="Singapore",  # Singapore Geo
            confidence_score=75,
            confidence_level="HIGH",
            supporting_evidence=[],
            conflicting_evidence=[],
            analysis_timestamp=datetime.now(timezone.utc).isoformat()
        ),
        domain_intelligence={
            "target-portal.com": DomainIntelligence(
                domain="target-portal.com",
                registration=DomainRegistration(
                    registrar="Dutch Registrar BV",
                    country="Netherlands",  # Netherlands WHOIS
                    registration_source="RDAP"
                )
            )
        }
    )

    conclusions = engine.evaluate_email(analysis)
    geo_conc = next(c for c in conclusions if c.type == ConclusionType.GEOLOCATION)

    # Verify contradictions surfaced in conflicting_evidence
    assert len(geo_conc.conflicting_evidence) >= 2

    # Check WHOIS contradiction
    whois_conflicts = [e for e in geo_conc.conflicting_evidence if "Netherlands" in e.statement]
    assert len(whois_conflicts) == 1
    assert whois_conflicts[0].is_conflicting is True

    # Check Timezone contradiction
    tz_conflicts = [e for e in geo_conc.conflicting_evidence if "+0530" in e.statement]
    assert len(tz_conflicts) == 1
    assert tz_conflicts[0].is_conflicting is True

    # Net score is heavily penalized due to contradictions
    assert geo_conc.confidence_score < 70
    assert geo_conc.confidence_level in ("LOW", "MODERATE")


def test_single_weak_signal(engine):
    """
    A single weak signal (e.g. only 1 generic urgency keyword cue without ML or IoC overlap)
    must produce bounded confidence (LOW or MODERATE, <= 50%) categorized as weak_hypothesis,
    rejecting false precision.
    """
    analysis = EmailAnalysisResponse(
        id="test-weak-signal",
        evidence_id="EVD-WEAK-001",
        plain_text_body="Please review this project update urgently when you get a chance.",
        threat_score=ThreatScoreResult(score=10, severity="low", reasons=[], positive_evidence=[], summary="Low threat"),
        ml_phishing_probability=0.20
    )

    conclusions = engine.evaluate_email(analysis)
    nlp_conc = next(c for c in conclusions if c.type == ConclusionType.NLP_CLASSIFICATION)

    assert nlp_conc.confidence_score <= 50
    assert nlp_conc.confidence_level in ("LOW", "MODERATE")
    assert float(nlp_conc.confidence_score).is_integer()
    assert any(e.evidence_category == EvidenceCategory.WEAK_HYPOTHESIS for e in nlp_conc.supporting_evidence)


def test_missing_evidence(engine):
    """
    Missing or sparse telemetry (no public IP, no URLs, no attachments) produces explicit
    unavailable_information category and prominent limitation disclaimers.
    """
    analysis = EmailAnalysisResponse(
        id="test-empty",
        evidence_id="EVD-EMPTY-001",
        plain_text_body="Hello world.",
        ips=[],
        urls=[],
        attachments=[]
    )

    conclusions = engine.evaluate_email(analysis)

    # Geolocation conclusion with missing public IP
    geo_conc = next(c for c in conclusions if c.type == ConclusionType.GEOLOCATION)
    assert geo_conc.confidence_score == 0.0
    assert geo_conc.confidence_level == "LOW"
    assert any(e.evidence_category == EvidenceCategory.UNAVAILABLE_INFORMATION for e in geo_conc.conflicting_evidence)
    assert len(geo_conc.limitations) >= 1

    # Attachment conclusion with no attachments
    att_conc = next(c for c in conclusions if c.type == ConclusionType.ATTACHMENT_VERDICT)
    assert any(e.evidence_category == EvidenceCategory.UNAVAILABLE_INFORMATION for e in att_conc.conflicting_evidence)


def test_dependent_evidence_sources_anti_double_counting(engine):
    """
    Anti-double-counting: Multiple feeds derived from the same underlying provider
    (e.g., three MaxMind-derived geo lookups) are clustered under 'maxmind_derived_geo'
    and assigned diminishing returns rather than counting 3 independent times.
    """
    cluster_items = [
        EvaluatedEvidence(
            evidence_id="EVD-GEO-1",
            statement="MaxMind GeoIP API indicates Singapore",
            source_module="MaxMindClient",
            source_quality=0.8,
            reliability=0.8,
            independence_cluster="maxmind_derived_geo",
            specificity=0.8,
            consistency=0.8,
            raw_contribution=30.0,
            effective_contribution=30.0
        ),
        EvaluatedEvidence(
            evidence_id="EVD-GEO-2",
            statement="GeoLite2 secondary mirror indicates Singapore",
            source_module="GeoLiteMirror",
            source_quality=0.8,
            reliability=0.8,
            independence_cluster="maxmind_derived_geo",
            specificity=0.8,
            consistency=0.8,
            raw_contribution=30.0,
            effective_contribution=30.0
        ),
        EvaluatedEvidence(
            evidence_id="EVD-GEO-3",
            statement="Third MaxMind-derived aggregator indicates Singapore",
            source_module="IPApiAggregator",
            source_quality=0.8,
            reliability=0.8,
            independence_cluster="maxmind_derived_geo",
            specificity=0.8,
            consistency=0.8,
            raw_contribution=30.0,
            effective_contribution=30.0
        )
    ]

    processed = engine._apply_quality_and_diminishing_returns(cluster_items)

    # 1st item gets full multiplier
    # 2nd item gets 0.3x multiplier
    # 3rd item gets 0.1x multiplier
    assert processed[0].effective_contribution > processed[1].effective_contribution
    assert processed[1].effective_contribution > processed[2].effective_contribution
    assert processed[2].effective_contribution < (processed[0].effective_contribution * 0.2)


def test_outdated_intelligence_recency_decay(engine):
    """
    Intelligence with observation timestamp older than 365 days is penalized
    by recency decay (0.5x).
    """
    fresh_item = EvaluatedEvidence(
        evidence_id="EVD-WHOIS-FRESH",
        statement="Domain registration verified via RDAP",
        source_module="DomainIntel",
        source_quality=0.85,
        reliability=0.85,
        recency_days=10.0,
        specificity=0.85,
        consistency=0.85,
        raw_contribution=20.0,
        effective_contribution=20.0
    )

    stale_item = EvaluatedEvidence(
        evidence_id="EVD-WHOIS-STALE",
        statement="Domain registration verified via archived WHOIS record",
        source_module="DomainIntel",
        source_quality=0.85,
        reliability=0.85,
        recency_days=400.0,  # > 365 days!
        specificity=0.85,
        consistency=0.85,
        raw_contribution=20.0,
        effective_contribution=20.0
    )

    processed = engine._apply_quality_and_diminishing_returns([fresh_item, stale_item])

    assert processed[1].effective_contribution < processed[0].effective_contribution
    # Stale item should be roughly half of fresh item
    assert processed[1].effective_contribution <= (processed[0].effective_contribution * 0.6)


def test_high_confidence_campaign_correlation(engine):
    """
    Multi-case technical IoC correlation raises campaign association confidence to HIGH.
    """
    analysis = EmailAnalysisResponse(
        id="test-campaign-high",
        evidence_id="EVD-CAMP-HIGH-001",
        attribution=AttributionResult(
            attribution_id="ATTR-CAMP",
            probable_origin_ip="203.0.113.25",
            related_campaigns=["CASE-2026-000031", "CASE-2026-000045"],
            confidence_score=80,
            confidence_level="HIGH",
            supporting_evidence=[],
            conflicting_evidence=[],
            analysis_timestamp=datetime.now(timezone.utc).isoformat()
        )
    )

    conclusions = engine.evaluate_email(analysis)
    camp_conc = next(c for c in conclusions if c.type == ConclusionType.CAMPAIGN_ASSOCIATION)

    assert camp_conc.confidence_level in ("HIGH", "VERY HIGH")
    assert camp_conc.confidence_score >= 70
    assert "CASE-2026-000031" in camp_conc.statement


def test_confidence_api_endpoints():
    """
    Tests POST /api/emails/confidence and GET /api/emails/{id}/confidence endpoints.
    """
    payload = {
        "id": "api-test-email",
        "evidence_id": "EVD-API-CONF-001",
        "subject": "Wire Transfer Request",
        "plain_text_body": "Please wire $45,000 urgently to the account below.",
        "threat_score": {
            "score": 75,
            "severity": "high",
            "reasons": [],
            "positive_evidence": [],
            "summary": "High risk BEC"
        }
    }

    # 1. POST /api/emails/confidence
    res = client.post("/api/emails/confidence", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "conclusions" in data
    assert len(data["conclusions"]) >= 4
    assert "overall_confidence_score" in data
    assert "overall_confidence_level" in data
    assert data["engine_version"] == "1.0.0"

    # 2. GET /api/emails/{id}/confidence with stored email
    from backend.db.session import SessionLocal
    from backend.db.models import AnalysisPayloadModel
    db = SessionLocal()
    try:
        if not db.query(AnalysisPayloadModel).filter_by(evidence_id="api-test-email").first():
            db.add(AnalysisPayloadModel(evidence_id="api-test-email", analysis_json=json.dumps(payload)))
            db.commit()
    finally:
        db.close()

    res_get = client.get("/api/emails/api-test-email/confidence")
    assert res_get.status_code == 200
    data_get = res_get.json()
    assert len(data_get["conclusions"]) >= 4


def test_llm_assistant_payload_confidence_grounding():
    """
    Verifies that AIAnalystService._build_evidence_payload includes forensic_conclusions
    with structured certainty distinctions (confirmed, probable, weak, unavailable).
    """
    ai_service = AIAnalystService()

    conclusion = ForensicConclusion(
        conclusion_id="CONC-TEST-001",
        type=ConclusionType.INFRASTRUCTURE_ATTRIBUTION,
        statement="Probable attacker-controlled origin on AS64512",
        confidence_score=78.0,
        confidence_level="HIGH",
        supporting_evidence=[
            EvaluatedEvidence(
                evidence_id="EVD-1",
                statement="Relay IP on AS64512",
                source_module="RelayReconstructor",
                source_quality=0.85,
                reliability=0.85,
                specificity=0.85,
                consistency=0.85,
                raw_contribution=30.0,
                effective_contribution=30.0,
                evidence_category=EvidenceCategory.PROBABLE_INFERENCE
            )
        ],
        conflicting_evidence=[],
        limitations=["Location refers to network infrastructure."],
        source_modules=["RelayReconstructor"],
        generated_at=datetime.now(timezone.utc).isoformat(),
        engine_version="1.0.0"
    )

    analysis = EmailAnalysisResponse(
        id="test-llm-payload",
        evidence_id="EVD-LLM-001",
        subject="Security Notice",
        forensic_conclusions=[conclusion]
    )

    payload = ai_service._build_evidence_payload(analysis)

    assert "forensic_conclusions" in payload
    assert len(payload["forensic_conclusions"]) == 1
    first_conc = payload["forensic_conclusions"][0]
    assert first_conc["confidence_level"] == "HIGH"
    assert first_conc["confidence_score"] == 78.0
    assert first_conc["supporting_evidence"][0]["category"] == "probable_inference"
