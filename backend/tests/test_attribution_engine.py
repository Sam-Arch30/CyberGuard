import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.main import app
from backend.db.session import get_db, SessionLocal
import json
from backend.db.models import CaseModel, CaseEmailModel, AuditLogModel, EmailAnalysisModel
from backend.services.attribution_engine import AttributionEngine, global_attribution_engine
from backend.services.graph_service import InvestigationGraphService
from backend.schemas.graph import NodeType
from backend.schemas.attribution import AttributionResult

client = TestClient(app)


# =============================================================================
# 1. STRONG ATTRIBUTION TEST
# =============================================================================
def test_strong_attribution():
    """
    Verifies that a high-risk email with consistent multi-hop relay infrastructure,
    matching ASN, domain DNS A record resolution, and lookalike domain hosting produces
    HIGH or VERY HIGH confidence with detailed supporting evidence.
    """
    engine = AttributionEngine()

    sample_email = {
        "id": "eml-strong-001",
        "evidence_id": "EVD-STRONG01",
        "subject": "CRITICAL: Urgent Invoice Verification",
        "from_header": "Accounts <billing@paypa1-security.com>",
        "threat_score": {"score": 85.0, "severity": "critical"},
        "authentication": {
            "spf": {"result": "fail"},
            "dkim": {"result": "fail"},
            "dmarc": {"result": "fail"},
            "alignment": {"reply_to_mismatch": True}
        },
        "relay_analysis": {
            "earliest_observable_node": {
                "earliest_observable_ip": "198.51.100.44",
                "from_host": "relay.paypa1-security.com"
            },
            "transmission_order_hops": [
                {"hop_number": 1, "from_ip": "198.51.100.44", "from_host": "relay.paypa1-security.com"}
            ]
        },
        "ip_intelligence": {
            "198.51.100.44": {
                "ip": "198.51.100.44",
                "country": "Germany",
                "asn": "AS24940",
                "organization": "Hetzner Online GmbH",
                "is_hosting": True,
                "is_proxy_vpn_tor": False
            }
        },
        "domain_intelligence": {
            "paypa1-security.com": {
                "domain": "paypa1-security.com",
                "dns": {
                    "a": ["198.51.100.44"],
                    "ns": ["ns1.bulletproof-dns.org"]
                },
                "lookalike": {
                    "domain": "paypa1-security.com",
                    "suspected_brand": "paypal.com"
                }
            }
        },
        "lookalike_domains": [
            {"domain": "paypa1-security.com", "suspected_brand": "paypal.com"}
        ],
        "urls": ["https://paypa1-security.com/invoice/pay"]
    }

    result = engine.attribute_email(sample_email)

    assert isinstance(result, AttributionResult)
    assert result.probable_origin_ip == "198.51.100.44"
    assert result.probable_origin_asn == "AS24940"
    assert result.probable_origin_provider == "Hetzner Online GmbH"
    assert result.probable_infrastructure_country == "Germany"
    assert result.confidence_score >= 70.0
    assert result.confidence_level in ["HIGH", "VERY HIGH"]

    # Check that individual evidence contributions are explainable
    supporting_types = {item.evidence_type for item in result.supporting_evidence}
    assert "EARLIEST_UNTRUSTED_RELAY" in supporting_types
    assert "DOMAIN_HOSTING_RELATIONSHIP" in supporting_types
    assert "ASN_CONSISTENCY" in supporting_types
    assert "AUTHENTICATION_FAILURE_ALIGNMENT" in supporting_types

    # Ensure mandatory non-human disclaimer is present
    assert "physical location" in result.disclaimer.lower()


# =============================================================================
# 2. WEAK ATTRIBUTION TEST (Insufficient / Sparse Evidence)
# =============================================================================
def test_weak_attribution():
    """
    Verifies that sparse data without resolvable public IPs yields LOW confidence
    and explicitly marks missing intelligence as Insufficient / Unknown.
    """
    engine = AttributionEngine()

    sparse_email = {
        "id": "eml-sparse-002",
        "subject": "Hello there",
        "from_header": "Friend <friend@local.internal>",
        "threat_score": {"score": 25.0, "severity": "low"},
        "relay_analysis": {
            "earliest_observable_node": {
                "earliest_observable_ip": None,
                "reason": "No public IP in headers"
            },
            "transmission_order_hops": [
                {"hop_number": 1, "from_ip": "10.0.0.1", "from_host": "internal-host"}
            ]
        },
        "ips": ["10.0.0.1", "192.168.1.50"]
    }

    result = engine.attribute_email(sparse_email)

    assert result.probable_origin_ip is None
    assert result.confidence_score == 0.0
    assert result.confidence_level == "LOW"
    assert len(result.conflicting_evidence) > 0
    assert any(e.evidence_type == "MISSING_PUBLIC_ORIGIN_INFRASTRUCTURE" for e in result.conflicting_evidence)


# =============================================================================
# 3. CONTRADICTORY GEOLOCATION SIGNALS TEST
# =============================================================================
def test_contradictory_geolocation_signals():
    """
    Verifies that divergent/contradictory geographic routing across multiple hops and domains
    incurs a conflicting penalty and is recorded transparently in conflicting_evidence.
    """
    engine = AttributionEngine()

    contradictory_email = {
        "id": "eml-contra-003",
        "subject": "Wire Details",
        "from_header": "Accounting <billing@fake-multihop.org>",
        "threat_score": {"score": 75.0, "severity": "high"},
        "relay_analysis": {
            "earliest_observable_node": {"earliest_observable_ip": "198.51.100.10"}
        },
        "ip_intelligence": {
            "198.51.100.10": {"country": "Russia", "asn": "AS12345", "organization": "Host A", "is_proxy_vpn_tor": False},
            "198.51.100.20": {"country": "Panama", "asn": "AS23456", "organization": "Host B", "is_proxy_vpn_tor": False},
            "198.51.100.30": {"country": "Singapore", "asn": "AS34567", "organization": "Host C", "is_proxy_vpn_tor": False},
            "198.51.100.40": {"country": "Seychelles", "asn": "AS45678", "organization": "Host D", "is_proxy_vpn_tor": False}
        },
        "domain_intelligence": {
            "fake-multihop.org": {
                "dns": {"a": ["198.51.100.20"]}
            }
        }
    }

    result = engine.attribute_email(contradictory_email)

    conflicting_types = {item.evidence_type for item in result.conflicting_evidence}
    assert "CONTRADICTORY_GEOLOCATION_SIGNALS" in conflicting_types
    contra_item = next(item for item in result.conflicting_evidence if item.evidence_type == "CONTRADICTORY_GEOLOCATION_SIGNALS")
    assert contra_item.contribution < 0


# =============================================================================
# 4. MISSING WHOIS INFORMATION TEST
# =============================================================================
def test_missing_whois_information():
    """
    Verifies that missing or unresolvable WHOIS/RDAP registration details do not cause
    crashes or hallucinated identities, defaulting cleanly to Unknown or Insufficient.
    """
    engine = AttributionEngine()

    missing_whois_email = {
        "id": "eml-whois-004",
        "subject": "Missing Registration Domain",
        "from_header": "Unknown <contact@nonexistent-whois.tld>",
        "threat_score": {"score": 60.0, "severity": "high"},
        "relay_analysis": {
            "earliest_observable_node": {"earliest_observable_ip": "203.0.113.88"}
        },
        "ip_intelligence": {
            "203.0.113.88": {
                "country": None,
                "asn": None,
                "organization": None
            }
        },
        "domain_intelligence": {
            "nonexistent-whois.tld": {
                "registration": {
                    "registrar": None,
                    "registration_date": None,
                    "nameservers": [],
                    "registration_source": "unavailable"
                },
                "dns": {"a": []}
            }
        }
    }

    result = engine.attribute_email(missing_whois_email)

    assert result.probable_origin_ip == "203.0.113.88"
    assert result.probable_origin_asn is None
    assert result.probable_origin_provider is None
    assert result.probable_infrastructure_country is None
    # Confidence remains bounded and modest due to lack of reinforcing DNS/WHOIS data
    assert result.confidence_score < 70.0


# =============================================================================
# 5. PROXY / VPN / TOR-LIKE INFRASTRUCTURE TEST
# =============================================================================
def test_proxy_vpn_tor_infrastructure():
    """
    Verifies that origin IPs identified as public proxies, VPNs, or Tor exit nodes
    produce explicit cautionary evidence attributing to proxy egress rather than the actor.
    """
    engine = AttributionEngine()

    tor_email = {
        "id": "eml-tor-005",
        "subject": "Anonymous Threat",
        "from_header": "Spammer <spammer@darknet-node.org>",
        "threat_score": {"score": 80.0, "severity": "critical"},
        "relay_analysis": {
            "earliest_observable_node": {"earliest_observable_ip": "185.220.101.5"}
        },
        "ip_intelligence": {
            "185.220.101.5": {
                "ip": "185.220.101.5",
                "country": "Germany",
                "asn": "AS208294",
                "organization": "Zwiebelfreunde e.V.",
                "is_hosting": True,
                "is_proxy_vpn_tor": True
            }
        }
    }

    result = engine.attribute_email(tor_email)

    assert result.probable_origin_ip == "185.220.101.5"
    conflicting_types = {item.evidence_type for item in result.conflicting_evidence}
    assert "ANONYMIZATION_INFRASTRUCTURE_DETECTED" in conflicting_types
    proxy_evidence = next(item for item in result.conflicting_evidence if item.evidence_type == "ANONYMIZATION_INFRASTRUCTURE_DETECTED")
    assert proxy_evidence.contribution < 0
    assert "proxy egress infrastructure" in proxy_evidence.observation.lower()


# =============================================================================
# 6. MALFORMED HEADERS TEST
# =============================================================================
def test_malformed_headers():
    """
    Verifies graceful handling of completely empty, broken, or malformed header inputs.
    """
    engine = AttributionEngine()

    malformed_email = {
        "id": "eml-broken-006",
        "subject": None,
        "from_header": None,
        "received": ["corrupted-gibberish-without-proper-smtp-tokens;invalid-date"],
        "threat_score": None,
        "relay_analysis": None
    }

    result = engine.attribute_email(malformed_email)

    assert isinstance(result, AttributionResult)
    assert result.probable_origin_ip is None
    assert result.confidence_score == 0.0
    assert result.confidence_level == "LOW"


# =============================================================================
# 7. LEGITIMATE EMAILS TEST
# =============================================================================
def test_legitimate_emails():
    """
    Verifies that benign emails sent via reputable ESPs (e.g. Google, Microsoft)
    with passing SPF/DKIM/DMARC authentication do NOT receive high malicious infrastructure attribution.
    """
    engine = AttributionEngine()

    legit_email = {
        "id": "eml-legit-007",
        "subject": "Quarterly Engineering Update",
        "from_header": "Tech Lead <lead@google.com>",
        "threat_score": {"score": 5.0, "severity": "low"},
        "authentication": {
            "spf": {"result": "pass"},
            "dkim": {"result": "pass"},
            "dmarc": {"result": "pass"}
        },
        "relay_analysis": {
            "earliest_observable_node": {"earliest_observable_ip": "209.85.220.41"}
        },
        "ip_intelligence": {
            "209.85.220.41": {
                "ip": "209.85.220.41",
                "country": "United States",
                "asn": "AS15169",
                "organization": "Google LLC",
                "is_hosting": True,
                "is_proxy_vpn_tor": False
            }
        }
    }

    result = engine.attribute_email(legit_email)

    # Legitimate ESP penalty applied
    conflicting_types = {item.evidence_type for item in result.conflicting_evidence}
    assert "LEGITIMATE_SERVICE_PROVIDER_INFRASTRUCTURE" in conflicting_types
    # Overall malicious attribution confidence should remain LOW or minimal
    assert result.confidence_score < 40.0
    assert result.confidence_level == "LOW"


# =============================================================================
# 8. API ENDPOINTS TEST
# =============================================================================
def test_attribution_api_endpoints():
    """
    Verifies GET /api/emails/{id}/attribution and POST /api/emails/attribution endpoints.
    """
    # Test on-the-fly POST endpoint
    payload = {
        "id": "test-api-001",
        "subject": "PayPal Security Notice",
        "threat_score": {"score": 82.0, "severity": "critical"},
        "relay_analysis": {
            "earliest_observable_node": {"earliest_observable_ip": "198.51.100.99"}
        },
        "ip_intelligence": {
            "198.51.100.99": {
                "ip": "198.51.100.99",
                "country": "Netherlands",
                "asn": "AS12345",
                "organization": "Test Datacenter"
            }
        }
    }
    resp = client.post("/api/emails/attribution", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["probable_origin_ip"] == "198.51.100.99"
    assert data["probable_origin_asn"] == "AS12345"
    assert data["probable_infrastructure_country"] == "Netherlands"
    assert "disclaimer" in data

    # Test GET endpoint with seeded sample-001
    db = SessionLocal()
    try:
        db.query(EmailAnalysisModel).filter_by(evidence_id="sample-001").delete()
        ea = EmailAnalysisModel(
            evidence_id="sample-001",
            email_sha256="sha-sample-001",
            subject="PayPal Security Notice",
            sender="spoofed@paypal.com",
            threat_score=85.0,
            severity="high",
            indicators_json=json.dumps({
                "ips": ["203.0.113.25"],
                "domains": ["paypal-fake.com"],
                "urls": ["https://paypal-fake.com/login"],
                "ip_intelligence": {
                    "203.0.113.25": {
                        "ip": "203.0.113.25",
                        "country": "Netherlands",
                        "asn": "AS12345",
                        "organization": "Test Datacenter"
                    }
                },
                "relay_analysis": {
                    "earliest_observable_node": {"earliest_observable_ip": "203.0.113.25"}
                },
                "authentication": {
                    "spf": {"result": "fail"},
                    "dkim": {"result": "fail"},
                    "dmarc": {"result": "fail"}
                }
            })
        )
        db.add(ea)
        db.commit()
    finally:
        db.close()

    resp_sample = client.get("/api/emails/sample-001/attribution")
    assert resp_sample.status_code == 200
    data_sample = resp_sample.json()
    assert data_sample["probable_origin_ip"] == "203.0.113.25"
    assert data_sample["confidence_level"] in ["HIGH", "VERY HIGH", "MODERATE"]


# =============================================================================
# 9. CASE & CAMPAIGN ATTRIBUTION API ENDPOINTS
# =============================================================================
def test_case_and_campaign_attribution_endpoints():
    """
    Verifies GET /api/cases/{case_id}/attribution and GET /api/campaigns/{campaign_id}/attribution.
    """
    resp_case = client.get("/api/cases/CASE-NONEXISTENT/attribution")
    assert resp_case.status_code == 200
    case_data = resp_case.json()
    assert case_data["case_id"] == "CASE-NONEXISTENT"
    assert case_data["total_emails_analyzed"] == 0

    resp_camp = client.get("/api/campaigns/CAMP-FINANCE-2026/attribution")
    assert resp_camp.status_code == 200
    camp_data = resp_camp.json()
    assert "attribution" in camp_data
    assert "shared_infrastructure_summary" in camp_data


# =============================================================================
# 10. INVESTIGATION GRAPH ATTRIBUTION INTEGRATION TEST
# =============================================================================
def test_investigation_graph_attribution_nodes():
    """
    Verifies that the investigation graph connects attribution relationships:
    Email -> Origin IP (ORIGIN_INFRASTRUCTURE)
    IP -> ASN (BELONGS_TO_ASN)
    IP -> Country (HOSTED_IN_COUNTRY)
    Campaign -> Infrastructure (UTILIZES_INFRASTRUCTURE)
    """
    graph_service = InvestigationGraphService()

    sample_email = {
        "id": "email-graph-attr-01",
        "email_sha256": "abcdef1234567890abcdef1234567890",
        "subject": "Attack graph email",
        "relay_analysis": {
            "earliest_observable_node": {"earliest_observable_ip": "198.51.100.50"}
        },
        "ip_intelligence": {
            "198.51.100.50": {
                "ip": "198.51.100.50",
                "country": "Singapore",
                "asn": "AS45678",
                "organization": "Singapore Hosting"
            }
        },
        "attribution": {
            "attribution_id": "ATTR-TEST-GRAPH",
            "probable_origin_ip": "198.51.100.50",
            "probable_origin_asn": "AS45678",
            "probable_origin_provider": "Singapore Hosting",
            "probable_infrastructure_country": "Singapore",
            "campaign_id": "CASE-2026-000042",
            "related_campaigns": ["CASE-2026-000042"],
            "confidence_score": 82.0,
            "confidence_level": "HIGH"
        }
    }

    graph = graph_service.build_graph(sample_email)

    node_types = {n.type for n in graph.nodes}
    assert NodeType.IP in node_types
    assert NodeType.ASN in node_types
    assert NodeType.COUNTRY in node_types
    assert NodeType.CAMPAIGN in node_types

    edge_labels = {e.label for e in graph.edges}
    assert "ORIGIN_INFRASTRUCTURE" in edge_labels
    assert "BELONGS_TO_ASN" in edge_labels
    assert "HOSTED_IN_COUNTRY" in edge_labels
    assert "UTILIZES_INFRASTRUCTURE" in edge_labels
