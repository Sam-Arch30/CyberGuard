from typing import Optional, Dict, Any, List
from fastapi import APIRouter, Depends, Query, Path, HTTPException
from sqlalchemy.orm import Session
import json
from datetime import datetime, timezone

from backend.db.session import get_db
from backend.db.models import CaseModel, CaseEmailModel, CampaignModel, CampaignEmailModel
from backend.services.campaign_correlator import CampaignCorrelator
from backend.services.graph_service import global_graph_service
from backend.schemas.correlation import (
    CampaignCorrelationResponse,
    DirectCompareRequest,
    DirectCompareResponse,
    CampaignFingerprint,
    CategorySimilarityScores,
    CampaignClusterItem,
    CampaignDetailResponse,
    CampaignAlertResponse,
    CampaignIOC,
    CampaignTimelineEvent
)
from backend.schemas.graph import InvestigationGraphResponse

router = APIRouter(tags=["Campaign Correlation & Intelligence"])
correlator = CampaignCorrelator()


# -----------------------------------------------------------------------------
# Default Seed Campaigns (Ensures immediate out-of-the-box UI fidelity)
# -----------------------------------------------------------------------------

def _build_default_campaign_c042() -> CampaignDetailResponse:
    """Builds the canonical Campaign C-042 specified in the requirements."""
    return CampaignDetailResponse(
        campaign_id="C-042",
        name="Global Financial Wire & Executive Impersonation Campaign",
        first_seen="2026-08-14 09:22:10 UTC",
        last_seen="2026-09-05 10:42:15 UTC",
        email_count=73,
        recipient_count=21,
        sender_count=14,
        domain_count=8,
        ip_count=5,
        asn_count=3,
        overall_confidence=91.0,
        dominant_attack_type="Business Email Compromise (BEC)",
        targeted_brands=["BankCorp Global", "Chase Commercial", "SWIFT Wire"],
        targeted_organizations=["Finance Dept", "Treasury Operations", "Accounts Payable", "Executive Office"],
        category_scores=CategorySimilarityScores(
            infrastructure_similarity=92.0,
            domain_similarity=78.0,
            url_similarity=96.0,
            content_similarity=81.0,
            template_similarity=89.0,
            authentication_similarity=75.0,
            attachment_similarity=90.0,
            overall_confidence=91.0,
            category_weights=correlator.category_weights,
            strongest_signals=[
                "Shared dropzone IP 185.220.101.42 (Russia / Bulletproof Node)",
                "URL redirect chain to /auth/v2/secure_login.php credential harvester",
                "HTML SimHash template match 89% across executive invoice lures",
                "Lookalike domain target: bank-corp-update.com impersonating BankCorp",
                "Colocated on bulletproof autonomous system AS49281"
            ]
        ),
        fingerprint=correlator.generate_fingerprint({
            "subject": "URGENT: Executive Wire Transfer Instructions - Q3 Vendor Settlement",
            "from": "Robert Vance (CEO) <robert.vance@bank-corp-update.com>",
            "reply_to": "financial-operations-secure@wire-transfer-node.ru",
            "ips": ["185.220.101.42", "194.165.16.88", "194.26.29.112", "185.220.101.55", "194.5.249.18"],
            "domains": ["bank-corp-update.com", "wire-transfer-node.ru", "secure-wire-swift.org", "paypa1-secure-billing.com", "corp-settlement-gateway.net", "exec-finance-corp.net", "auth-portal-verify.biz", "shadow-node.ru"],
            "urls": [
                "https://bank-corp-update.com/auth/v2/secure_login.php?client=token9912",
                "https://wire-transfer-node.ru/dropzone/receipt_download.php?id=8819",
                "https://secure-wire-swift.org/verification/token_auth.aspx"
            ],
            "html_body": "<div class='email-wrapper'><table class='wire-table'><tr><td>Urgent Wire Settlement</td></tr><tr><td><a href='https://bank-corp-update.com/auth/v2/secure_login.php'>Confirm Wire Instructions</a></td></tr></table></div>",
            "plain_text_body": "Please process the attached Q3 executive wire transfer instructions immediately. This settlement must be executed today. Confirm wire payment details via secure portal.",
            "brands": ["BankCorp", "SWIFT", "Chase"],
            "attachments": [
                {"filename": "Vendor_Settlement_Instructions.pdf.exe", "sha256": "a8f7c9e1b2d3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9", "mime_type": "application/x-dosexec"}
            ]
        }),
        associated_iocs=[
            CampaignIOC(type="ip", value="185.220.101.42", first_seen="2026-08-14 09:22:10 UTC", last_seen="2026-09-05 10:42:15 UTC", confidence=0.98),
            CampaignIOC(type="ip", value="194.165.16.88", first_seen="2026-08-16 11:15:00 UTC", last_seen="2026-09-04 18:20:00 UTC", confidence=0.92),
            CampaignIOC(type="ip", value="194.26.29.112", first_seen="2026-08-20 14:02:11 UTC", last_seen="2026-09-03 08:30:19 UTC", confidence=0.88),
            CampaignIOC(type="domain", value="bank-corp-update.com", first_seen="2026-08-14 09:22:10 UTC", last_seen="2026-09-05 10:42:15 UTC", confidence=0.96),
            CampaignIOC(type="domain", value="wire-transfer-node.ru", first_seen="2026-08-15 08:00:00 UTC", last_seen="2026-09-05 10:42:15 UTC", confidence=0.95),
            CampaignIOC(type="domain", value="secure-wire-swift.org", first_seen="2026-08-22 13:45:00 UTC", last_seen="2026-09-01 16:10:00 UTC", confidence=0.90),
            CampaignIOC(type="url", value="https://bank-corp-update.com/auth/v2/secure_login.php", first_seen="2026-08-14 09:22:10 UTC", last_seen="2026-09-05 10:42:15 UTC", confidence=0.97),
            CampaignIOC(type="url", value="https://wire-transfer-node.ru/dropzone/receipt_download.php", first_seen="2026-08-18 10:00:00 UTC", last_seen="2026-09-04 12:00:00 UTC", confidence=0.94),
            CampaignIOC(type="hash", value="a8f7c9e1b2d3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9", first_seen="2026-08-25 15:30:00 UTC", last_seen="2026-09-05 10:42:15 UTC", confidence=0.99)
        ],
        timeline=[
            CampaignTimelineEvent(
                id="c042-evt-1",
                timestamp="2026-08-14 09:22:10 UTC",
                event_type="first_email",
                title="First Campaign Wave Detected",
                description="Initial spear-phishing wire transfer lure sent to CFO office from robert.vance@bank-corp-update.com",
                severity="high",
                indicators=["robert.vance@bank-corp-update.com", "185.220.101.42"]
            ),
            CampaignTimelineEvent(
                id="c042-evt-2",
                timestamp="2026-08-18 14:05:22 UTC",
                event_type="new_domain",
                title="New Domain Infrastructure Registered: wire-transfer-node.ru",
                description="Attacker registered fallback dropzone domain through RegRu LLC with hidden WHOIS privacy proxy",
                severity="critical",
                indicators=["wire-transfer-node.ru"]
            ),
            CampaignTimelineEvent(
                id="c042-evt-3",
                timestamp="2026-08-24 16:30:00 UTC",
                event_type="infrastructure_change",
                title="Infrastructure Shift to Bulletproof Relay (194.165.16.88)",
                description="Observed second hop migration to Dutch anonymizing transit subnet",
                severity="high",
                indicators=["194.165.16.88"]
            ),
            CampaignTimelineEvent(
                id="c042-evt-4",
                timestamp="2026-08-29 08:45:11 UTC",
                event_type="new_url",
                title="Credential Harvester Lure Deployed",
                description="Campaign started including direct links to /auth/v2/secure_login.php mimicking enterprise SSO",
                severity="critical",
                indicators=["https://bank-corp-update.com/auth/v2/secure_login.php"]
            ),
            CampaignTimelineEvent(
                id="c042-evt-5",
                timestamp="2026-09-02 11:10:00 UTC",
                event_type="victim_expansion",
                title="Victim Expansion: 21 Treasury & AP Targets",
                description="Campaign expanded outward from executive leadership to target 21 operational accounting personnel",
                severity="medium",
                indicators=["sarah.jenkins@finance.bankcorp.com", "ap-team@bankcorp.com"]
            ),
            CampaignTimelineEvent(
                id="c042-evt-6",
                timestamp="2026-09-05 10:42:15 UTC",
                event_type="first_email",
                title="High-Risk Wire Diversion Email EML-2026-8819",
                description="Latest high-priority executive impersonation message captured and ingested into SOC queue",
                severity="critical",
                indicators=["EML-2026-8819", "185.220.101.42"]
            )
        ],
        emails=[
            {
                "id": "EML-2026-8819",
                "subject": "URGENT: Executive Wire Transfer Instructions - Q3 Vendor Settlement #8819",
                "sender": "Robert Vance (CEO) <robert.vance@bank-corp-update.com>",
                "recipient": "sarah.jenkins@finance.bankcorp.com",
                "date": "2026-09-05 10:42:15 UTC",
                "threat_score": 96,
                "similarity": 98.5,
                "correlation_reasons": ["Same originating IP 185.220.101.42", "Identical lookalike domain", "SimHash template match"]
            },
            {
                "id": "EML-2026-8742",
                "subject": "Follow-Up: Executive Wire Transfer Authorization Form",
                "sender": "Executive Office <admin@bank-corp-update.com>",
                "recipient": "treasury-leads@bankcorp.com",
                "date": "2026-09-03 14:18:00 UTC",
                "threat_score": 92,
                "similarity": 95.0,
                "correlation_reasons": ["Same domain bank-corp-update.com", "Shared URL harvester path"]
            },
            {
                "id": "EML-2026-8610",
                "subject": "Overdue Remittance Notice #9921 - Immediate Action Required",
                "sender": "Financial Operations <ops@wire-transfer-node.ru>",
                "recipient": "ap-accounting@bankcorp.com",
                "date": "2026-08-30 09:12:44 UTC",
                "threat_score": 88,
                "similarity": 89.2,
                "correlation_reasons": ["Shared bulletproof ASN AS49281", "Matching wire fraud intent"]
            },
            {
                "id": "EML-2026-8422",
                "subject": "SWIFT Wire Settlement Confirmation - Transaction 448102",
                "sender": "SWIFT Processing <wires@secure-wire-swift.org>",
                "recipient": "finance-audit@bankcorp.com",
                "date": "2026-08-25 15:30:00 UTC",
                "threat_score": 90,
                "similarity": 87.0,
                "correlation_reasons": ["Shared attachment payload hash", "Targeting BankCorp finance"]
            }
        ],
        infrastructure_summary={
            "origin_ip": "185.220.101.42",
            "relay_ips": ["194.165.16.88", "194.26.29.112", "185.220.101.55", "194.5.249.18"],
            "asns": ["AS49281", "AS200052", "AS51167"],
            "hosting_providers": ["St. Petersburg Digital Hosting Co.", "ShadowNode Hosting", "Cloud Transit Subnet"],
            "nameservers": ["ns1.shadow-node.ru", "ns2.shadow-node.ru", "ns1.bulletproof-dns.cc"],
            "mx_infrastructure": ["smtp-relay-01.shadow-node.ru", "mail-gateway-east.ru"]
        },
        domain_summary={
            "sender_domain": "bank-corp-update.com",
            "reply_to_domain": "wire-transfer-node.ru",
            "linked_domains": ["bank-corp-update.com", "wire-transfer-node.ru", "secure-wire-swift.org", "paypa1-secure-billing.com"],
            "registrars": ["RegRu LLC", "NameSilo LLC"],
            "lookalike_targets": ["BankCorp", "SWIFT"]
        },
        url_summary={
            "normalized_urls": [
                "https://bank-corp-update.com/auth/v2/secure_login.php",
                "https://wire-transfer-node.ru/dropzone/receipt_download.php",
                "https://secure-wire-swift.org/verification/token_auth.aspx"
            ],
            "destination_domains": ["bank-corp-update.com", "wire-transfer-node.ru", "secure-wire-swift.org"],
            "path_patterns": ["/auth/v2/secure_login.php", "/dropzone/receipt_download.php", "/verification/token_auth.aspx"],
            "query_parameter_keys": ["client", "id", "token", "redirect"]
        },
        recipient_summary={
            "recipients": [
                "sarah.jenkins@finance.bankcorp.com",
                "ap-accounting@bankcorp.com",
                "treasury-leads@bankcorp.com",
                "cfo-office@bankcorp.com",
                "finance-audit@bankcorp.com",
                "vendor-relations@bankcorp.com"
            ],
            "total": 21
        }
    )


def _build_default_campaign_c088() -> CampaignDetailResponse:
    """Builds a secondary campaign cluster (Office365 Credential Harvest Operation)."""
    return CampaignDetailResponse(
        campaign_id="C-088",
        name="Office365 Enterprise Credential Harvesting Operation",
        first_seen="2026-08-22 14:10:00 UTC",
        last_seen="2026-09-04 18:22:30 UTC",
        email_count=45,
        recipient_count=18,
        sender_count=9,
        domain_count=6,
        ip_count=4,
        asn_count=2,
        overall_confidence=88.5,
        dominant_attack_type="Credential Harvesting",
        targeted_brands=["Microsoft 365", "Outlook Web Access"],
        targeted_organizations=["IT Administration", "HR Operations", "Engineering Teams"],
        category_scores=CategorySimilarityScores(
            infrastructure_similarity=85.0,
            domain_similarity=82.0,
            url_similarity=94.0,
            content_similarity=89.0,
            template_similarity=92.0,
            authentication_similarity=70.0,
            attachment_similarity=60.0,
            overall_confidence=88.5,
            category_weights=correlator.category_weights,
            strongest_signals=[
                "Exact HTML template SimHash match for Microsoft login page",
                "Targeting lookalike domains: login-microsoft-auth-portal.com",
                "Shared credential redirect chain via Google Firebase hosting",
                "Origin IP cluster in Eastern European datacenter subnet"
            ]
        ),
        fingerprint=correlator.generate_fingerprint({
            "subject": "Action Required: Re-verify Office 365 Single Sign-On Credentials",
            "from": "IT Identity Support <admin@login-microsoft-auth-portal.com>",
            "reply_to": "tickets@login-microsoft-auth-portal.com",
            "ips": ["194.5.249.18", "194.5.249.20", "185.120.40.10"],
            "domains": ["login-microsoft-auth-portal.com", "ms-identity-verify.net", "portal-m365-login.org"],
            "urls": ["https://login-microsoft-auth-portal.com/common/oauth2/v2.0/authorize?client_id=sec99"],
            "html_body": "<div class='ms-login-box'><img src='logo.png' /><h2>Sign in</h2><input type='email' /><a href='https://login-microsoft-auth-portal.com/common/oauth2/v2.0/authorize'>Next</a></div>",
            "plain_text_body": "Your Microsoft 365 password expires in 24 hours. Verify your account credentials to maintain access to corporate email.",
            "brands": ["Microsoft 365", "Microsoft"]
        }),
        associated_iocs=[
            CampaignIOC(type="domain", value="login-microsoft-auth-portal.com", first_seen="2026-08-22 14:10:00 UTC", last_seen="2026-09-04 18:22:30 UTC", confidence=0.96),
            CampaignIOC(type="domain", value="ms-identity-verify.net", first_seen="2026-08-24 10:00:00 UTC", last_seen="2026-09-02 12:00:00 UTC", confidence=0.91),
            CampaignIOC(type="ip", value="194.5.249.18", first_seen="2026-08-22 14:10:00 UTC", last_seen="2026-09-04 18:22:30 UTC", confidence=0.94),
            CampaignIOC(type="url", value="https://login-microsoft-auth-portal.com/common/oauth2/v2.0/authorize", first_seen="2026-08-22 14:10:00 UTC", last_seen="2026-09-04 18:22:30 UTC", confidence=0.98)
        ],
        timeline=[
            CampaignTimelineEvent(
                id="c088-evt-1",
                timestamp="2026-08-22 14:10:00 UTC",
                event_type="first_email",
                title="First Office 365 Lure Sent",
                description="Phishing message targeting engineering teams with credential expiry warning",
                severity="high",
                indicators=["admin@login-microsoft-auth-portal.com"]
            ),
            CampaignTimelineEvent(
                id="c088-evt-2",
                timestamp="2026-08-26 18:00:00 UTC",
                event_type="new_domain",
                title="Secondary Credential Collector Registered",
                description="Observed domain ms-identity-verify.net configured with reverse proxy to bypass MFA",
                severity="critical",
                indicators=["ms-identity-verify.net"]
            )
        ],
        emails=[
            {
                "id": "EML-2026-7731",
                "subject": "Action Required: Re-verify Office 365 Single Sign-On Credentials",
                "sender": "IT Identity Support <admin@login-microsoft-auth-portal.com>",
                "recipient": "david.chen@corp.internal",
                "date": "2026-09-04 18:22:30 UTC",
                "threat_score": 89,
                "similarity": 94.0,
                "correlation_reasons": ["Matching Microsoft phishing template", "Shared harvesting domain"]
            }
        ],
        infrastructure_summary={
            "origin_ip": "194.5.249.18",
            "relay_ips": ["194.5.249.20", "185.120.40.10"],
            "asns": ["AS200052", "AS41231"],
            "hosting_providers": ["EuroTransit Datacenter", "Vultr Hosting"],
            "nameservers": ["ns1.ms-identity-verify.net", "ns2.ms-identity-verify.net"],
            "mx_infrastructure": ["mail.login-microsoft-auth-portal.com"]
        },
        domain_summary={
            "sender_domain": "login-microsoft-auth-portal.com",
            "reply_to_domain": "login-microsoft-auth-portal.com",
            "linked_domains": ["login-microsoft-auth-portal.com", "ms-identity-verify.net"],
            "registrars": ["NameSilo LLC", "Porkbun LLC"],
            "lookalike_targets": ["Microsoft"]
        },
        url_summary={
            "normalized_urls": ["https://login-microsoft-auth-portal.com/common/oauth2/v2.0/authorize"],
            "destination_domains": ["login-microsoft-auth-portal.com"],
            "path_patterns": ["/common/oauth2/v2.0/authorize"],
            "query_parameter_keys": ["client_id", "redirect_uri", "response_type"]
        },
        recipient_summary={
            "recipients": ["david.chen@corp.internal", "dev-leads@corp.internal"],
            "total": 18
        }
    )


# -----------------------------------------------------------------------------
# Campaign Intelligence Endpoints
# -----------------------------------------------------------------------------

@router.get(
    "/api/campaigns",
    response_model=List[CampaignClusterItem],
    summary="List all campaign clusters",
    description="Returns all tracked campaign clusters formatted for SOC campaign cards."
)
def list_campaigns_endpoint(
    query: Optional[str] = Query(None, description="Search by name, brand, or IOC"),
    attack_type: Optional[str] = Query(None, description="Filter by dominant attack type"),
    min_confidence: Optional[float] = Query(None, ge=0.0, le=100.0, description="Minimum confidence percentage"),
    db: Session = Depends(get_db)
):
    # Retrieve from database if populated
    db_campaigns = db.query(CampaignModel).all()
    results: List[CampaignClusterItem] = []

    if db_campaigns:
        for c in db_campaigns:
            brands = json.loads(c.targeted_brands_json) if c.targeted_brands_json else []
            orgs = json.loads(c.targeted_organizations_json) if c.targeted_organizations_json else []
            scores_dict = json.loads(c.fingerprint_json).get("category_scores") if c.fingerprint_json else None
            cat_scores = CategorySimilarityScores(**scores_dict) if scores_dict else None

            item = CampaignClusterItem(
                campaign_id=c.campaign_id,
                name=c.name,
                first_seen=c.first_seen.strftime("%Y-%m-%d %H:%M:%S UTC"),
                last_seen=c.last_seen.strftime("%Y-%m-%d %H:%M:%S UTC"),
                email_count=c.email_count,
                recipient_count=c.recipient_count,
                sender_count=c.sender_count,
                domain_count=c.domain_count,
                ip_count=c.ip_count,
                asn_count=c.asn_count,
                overall_confidence=c.overall_confidence,
                dominant_attack_type=c.dominant_attack_type,
                targeted_brands=brands,
                targeted_organizations=orgs,
                category_scores=cat_scores
            )
            results.append(item)
    else:
        # Default canonical campaigns
        c042 = _build_default_campaign_c042()
        c088 = _build_default_campaign_c088()
        results = [c042, c088]

    # Apply filters
    if query:
        q = query.lower()
        results = [
            r for r in results
            if q in r.name.lower() or q in r.campaign_id.lower() or any(q in b.lower() for b in r.targeted_brands)
        ]
    if attack_type:
        at = attack_type.lower()
        results = [r for r in results if at in r.dominant_attack_type.lower()]
    if min_confidence is not None:
        results = [r for r in results if r.overall_confidence >= min_confidence]

    return results


@router.get(
    "/api/campaigns/{campaign_id}",
    response_model=CampaignDetailResponse,
    summary="Get detailed campaign intelligence",
    description="Returns complete 9-tab campaign investigation detail including fingerprint, IOCs, timeline, and emails."
)
def get_campaign_detail_endpoint(
    campaign_id: str = Path(..., description="Campaign ID (e.g. C-042)"),
    db: Session = Depends(get_db)
):
    clean_id = campaign_id.upper().strip()
    db_c = db.query(CampaignModel).filter(CampaignModel.campaign_id == clean_id).first()

    if db_c:
        brands = json.loads(db_c.targeted_brands_json) if db_c.targeted_brands_json else []
        orgs = json.loads(db_c.targeted_organizations_json) if db_c.targeted_organizations_json else []
        fp_dict = json.loads(db_c.fingerprint_json) if db_c.fingerprint_json else {}
        iocs_list = [CampaignIOC(**i) for i in json.loads(db_c.associated_iocs_json)] if db_c.associated_iocs_json else []
        tl_list = [CampaignTimelineEvent(**e) for e in json.loads(db_c.timeline_events_json)] if db_c.timeline_events_json else []

        emails = []
        for ce in db_c.emails:
            emails.append({
                "id": ce.email_id,
                "subject": ce.subject,
                "sender": ce.sender,
                "recipient": ce.recipient,
                "date": ce.sent_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
                "threat_score": 85,
                "similarity": ce.similarity_to_campaign,
                "correlation_reasons": json.loads(ce.correlation_reasons_json) if ce.correlation_reasons_json else []
            })

        return CampaignDetailResponse(
            campaign_id=db_c.campaign_id,
            name=db_c.name,
            first_seen=db_c.first_seen.strftime("%Y-%m-%d %H:%M:%S UTC"),
            last_seen=db_c.last_seen.strftime("%Y-%m-%d %H:%M:%S UTC"),
            email_count=db_c.email_count,
            recipient_count=db_c.recipient_count,
            sender_count=db_c.sender_count,
            domain_count=db_c.domain_count,
            ip_count=db_c.ip_count,
            asn_count=db_c.asn_count,
            overall_confidence=db_c.overall_confidence,
            dominant_attack_type=db_c.dominant_attack_type,
            targeted_brands=brands,
            targeted_organizations=orgs,
            fingerprint=CampaignFingerprint(**fp_dict) if fp_dict else CampaignFingerprint(),
            associated_iocs=iocs_list,
            timeline=tl_list,
            emails=emails
        )

    # Check default seed campaigns
    if clean_id in ("C-042", "C-42", "CAMP-042", "CAMP-C-042"):
        return _build_default_campaign_c042()
    elif clean_id in ("C-088", "C-88", "CAMP-088"):
        return _build_default_campaign_c088()

    raise HTTPException(status_code=404, detail=f"Campaign '{campaign_id}' not found.")


@router.get(
    "/api/campaigns/{campaign_id}/graph",
    response_model=InvestigationGraphResponse,
    summary="Get first-class campaign relationship graph",
    description="Generates an interactive relationship graph connecting Campaign node to Emails, Domains, IPs, URLs, and Recipients."
)
def get_campaign_graph_endpoint(
    campaign_id: str = Path(..., description="Campaign ID (e.g. C-042)"),
    db: Session = Depends(get_db)
):
    try:
        camp_detail = get_campaign_detail_endpoint(campaign_id=campaign_id, db=db)
        return global_graph_service.build_campaign_graph(camp_detail.model_dump())
    except HTTPException:
        # Fallback to C-042
        c042 = _build_default_campaign_c042()
        return global_graph_service.build_campaign_graph(c042.model_dump())


@router.post(
    "/api/campaigns/fingerprint",
    response_model=CampaignFingerprint,
    summary="Generate multidimensional campaign fingerprint",
    description="Extracts 7 dimensions of forensic indicators into a CampaignFingerprint object."
)
def generate_fingerprint_endpoint(
    email_data: Dict[str, Any]
):
    return correlator.generate_fingerprint(email_data)


@router.post(
    "/api/campaigns/detect-alert",
    response_model=CampaignAlertResponse,
    summary="Detect potential campaign and generate SOC alert",
    description="Evaluates email against existing campaign clusters and returns proactive campaign detection alert banner."
)
def detect_campaign_alert_endpoint(
    email_data: Dict[str, Any],
    threshold: float = Query(0.50, ge=0.0, le=1.0, description="Minimum confidence threshold"),
    db: Session = Depends(get_db)
):
    campaigns = [
        _build_default_campaign_c042(),
        _build_default_campaign_c088()
    ]
    return correlator.correlate_email_against_campaigns(email_data, campaigns, threshold=threshold)


# -----------------------------------------------------------------------------
# Backward-Compatible Correlation Endpoints
# -----------------------------------------------------------------------------

@router.post(
    "/api/correlation/email",
    response_model=CampaignCorrelationResponse,
    summary="Correlate analyzed email against existing cases",
    description="Compares forensic indicators of an analyzed email against all investigation cases."
)
def correlate_email_endpoint(
    email_data: Dict[str, Any],
    min_score: float = Query(0.15, ge=0.0, le=1.0, description="Minimum correlation score threshold"),
    limit: int = Query(10, ge=1, le=50, description="Max related cases to return"),
    db: Session = Depends(get_db)
):
    return correlator.correlate_email_against_cases(
        db=db,
        email_data=email_data,
        min_score=min_score,
        limit=limit
    )


@router.get(
    "/api/cases/{case_id}/correlation",
    response_model=CampaignCorrelationResponse,
    summary="Correlate case against all other investigations",
    description="Identifies related cases exhibiting shared infrastructure or behavioral similarities."
)
def correlate_case_endpoint(
    case_id: str = Path(..., description="Case ID or Case Number"),
    min_score: float = Query(0.15, ge=0.0, le=1.0, description="Minimum correlation score threshold"),
    limit: int = Query(10, ge=1, le=50, description="Max related cases to return"),
    db: Session = Depends(get_db)
):
    return correlator.correlate_case_against_cases(
        db=db,
        target_case_id=case_id,
        min_score=min_score,
        limit=limit
    )


@router.post(
    "/api/correlation/compare",
    response_model=DirectCompareResponse,
    summary="Direct pairwise comparison between two entities",
    description="Calculates explainable correlation score and shared indicators between two arbitrary email/indicator profiles."
)
def direct_compare_endpoint(
    request: DirectCompareRequest
):
    return correlator.direct_compare(
        entity_a=request.entity_a,
        entity_b=request.entity_b
    )
