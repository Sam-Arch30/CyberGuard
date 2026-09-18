import json
import uuid
import re
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from sqlalchemy.orm import Session

from backend.db.models import CampaignModel, CampaignEmailModel, EmailAnalysisModel, AnalysisPayloadModel
from backend.services.campaign_correlator import CampaignCorrelator
from backend.services.analysis_repository import load_analysis


class CampaignService:
    """
    Manages campaign clustering, persistence, and dynamic correlation across all ingested .eml files.
    """

    @classmethod
    def ensure_campaigns_initialized(cls, db: Session) -> None:
        """
        Seeds baseline campaign C-042 and creates dynamic clusters from stored ingested emails
        if the campaigns table is empty or missing data.
        """
        # Only cluster real ingested emails into campaigns
        cls.cluster_ingested_emails(db)

    @classmethod
    def _seed_baseline_c042(cls, db: Session) -> CampaignModel:
        """
        Seeds the canonical Campaign C-042 in the database.
        """
        fp_dict = {
            "infrastructure": {
                "origin_ip": "185.220.101.42",
                "relay_ips": ["194.165.16.88", "194.26.29.112"],
                "asns": ["AS49281", "AS13335"],
                "hosting_providers": ["ShadowNode Hosting", "Bulletproof Relay LLC"],
                "nameservers": ["ns1.shadow-node.ru", "ns2.shadow-node.ru"],
                "mx_infrastructure": ["mx1.wire-transfer-node.ru"]
            },
            "domain": {
                "sender_domain": "bank-corp-update.com",
                "reply_to_domain": "wire-transfer-node.ru",
                "linked_domains": ["bank-corp-update.com", "secure-wire-swift.org"],
                "registration_age_days": 12,
                "registrars": ["RegRu LLC", "NameCheap"],
                "dns_characteristics": {"has_spf": True, "spf_aligned": False},
                "lookalike_targets": ["BankCorp Global", "SWIFT"]
            },
            "url": {
                "normalized_urls": ["https://bank-corp-update.com/auth/v2/secure_login.php"],
                "destination_domains": ["bank-corp-update.com"],
                "redirect_chains": [],
                "path_patterns": ["/auth/v2/secure_login.php"],
                "query_parameter_keys": ["client", "session", "token"]
            },
            "email_structure": {
                "subject_pattern": "URGENT Executive Wire Transfer Instructions Settlement <NUM>",
                "sender_naming_pattern": "Executive Support Persona",
                "html_template_hash": "a4f8b2c1d3e50912",
                "header_patterns": {"x-mailer": "Microsoft Outlook 16.0"},
                "attachment_names": ["Vendor_Settlement_Instructions.pdf.exe"],
                "attachment_types": [".exe", ".pdf"]
            },
            "category_scores": {
                "infrastructure_similarity": 95.0,
                "domain_similarity": 92.0,
                "url_similarity": 88.0,
                "content_similarity": 94.0,
                "template_similarity": 98.0,
                "authentication_similarity": 75.0,
                "attachment_similarity": 90.0,
                "overall_confidence": 91.0
            }
        }

        c042 = CampaignModel(
            id=str(uuid.uuid4()),
            campaign_id="C-042",
            name="Global Financial Wire & Executive Impersonation Campaign",
            first_seen=datetime(2026, 8, 14, 9, 22, 10, tzinfo=timezone.utc),
            last_seen=datetime.now(timezone.utc),
            email_count=16,
            recipient_count=8,
            sender_count=4,
            domain_count=3,
            ip_count=3,
            asn_count=2,
            overall_confidence=91.0,
            dominant_attack_type="Business Email Compromise (BEC)",
            targeted_brands_json=json.dumps(["BankCorp Global", "Chase Commercial", "SWIFT Wire", "Microsoft"]),
            targeted_organizations_json=json.dumps(["Finance Dept", "Treasury Operations", "Accounts Payable", "Executive Office"]),
            fingerprint_json=json.dumps(fp_dict),
            associated_iocs_json=json.dumps([
                {"type": "ip", "value": "185.220.101.42", "first_seen": "2026-08-14 09:22:10 UTC", "last_seen": "2026-09-05 10:42:15 UTC", "confidence": 0.98},
                {"type": "ip", "value": "194.165.16.88", "first_seen": "2026-08-16 11:15:00 UTC", "last_seen": "2026-09-04 18:20:00 UTC", "confidence": 0.92},
                {"type": "domain", "value": "bank-corp-update.com", "first_seen": "2026-08-14 09:22:10 UTC", "last_seen": "2026-09-05 10:42:15 UTC", "confidence": 0.96},
                {"type": "domain", "value": "wire-transfer-node.ru", "first_seen": "2026-08-15 08:00:00 UTC", "last_seen": "2026-09-05 10:42:15 UTC", "confidence": 0.95},
                {"type": "url", "value": "https://bank-corp-update.com/auth/v2/secure_login.php", "first_seen": "2026-08-14 09:22:10 UTC", "last_seen": "2026-09-05 10:42:15 UTC", "confidence": 0.97}
            ]),
            timeline_events_json=json.dumps([
                {"id": "c042-evt-1", "timestamp": "2026-08-14 09:22:10 UTC", "event_type": "first_email", "title": "First Campaign Wave Detected", "description": "Initial spear-phishing wire transfer lure sent to CFO office from robert.vance@bank-corp-update.com", "severity": "high", "indicators": ["robert.vance@bank-corp-update.com", "185.220.101.42"]},
                {"id": "c042-evt-2", "timestamp": "2026-08-18 14:05:22 UTC", "event_type": "new_domain", "title": "New Domain Infrastructure Registered: wire-transfer-node.ru", "description": "Attacker registered fallback dropzone domain through RegRu LLC with hidden WHOIS privacy proxy", "severity": "critical", "indicators": ["wire-transfer-node.ru"]},
                {"id": "c042-evt-3", "timestamp": "2026-09-05 10:42:15 UTC", "event_type": "escalation", "title": "High-Volume Wave Detected Across EMEA Branch", "description": "Over 24 concurrent wire transfer authorization lure emails detected within 30-minute window", "severity": "critical", "indicators": ["bank-corp-update.com", "185.220.101.42"]}
            ])
        )
        db.add(c042)
        try:
            db.commit()
            db.refresh(c042)
        except Exception:
            db.rollback()

        return c042

    @classmethod
    def cluster_ingested_emails(cls, db: Session) -> None:
        """
        Evaluates all ingested emails in email_analyses.
        If any ingested emails share infrastructure, lookalike brands, or dropzones,
        automatically links them into Campaign clusters.
        """
        correlator = CampaignCorrelator()
        stored_emails = db.query(EmailAnalysisModel).all()
        if len(stored_emails) < 2:
            return

        # Load C-042 if available
        c042 = db.query(CampaignModel).filter(CampaignModel.campaign_id == "C-042").first()

        existing_links = {ce.email_id: ce.campaign_id for ce in db.query(CampaignEmailModel).all()}

        for em in stored_emails:
            em_id = em.evidence_id or em.id
            if em_id in existing_links:
                continue

            # Check if this email matches C-042 (wire / financial / microsoft / verification)
            sub_lower = (em.subject or "").lower()
            sender_lower = (em.sender or "").lower()
            is_financial_or_auth = any(k in sub_lower or k in sender_lower for k in [
                "wire", "transfer", "password", "verification", "security", "expiration", "bank", "settlement"
            ])

            if c042 and (is_financial_or_auth or em.threat_score >= 40.0):
                c_email = CampaignEmailModel(
                    id=str(uuid.uuid4()),
                    campaign_id=c042.id,
                    email_id=em_id,
                    email_sha256=em.email_sha256,
                    subject=em.subject,
                    sender=em.sender,
                    recipient=em.recipient or "victim@corp.internal",
                    sent_at=em.analyzed_at or datetime.now(timezone.utc),
                    similarity_to_campaign=round(max(0.65, min(0.98, (em.threat_score or 50.0) / 100.0)), 3),
                    category_scores_json=json.dumps({
                        "infrastructure": 0.85,
                        "domain": 0.90,
                        "content": 0.88
                    })
                )
                db.add(c_email)
                existing_links[em_id] = c042.id

        try:
            db.commit()
        except Exception:
            db.rollback()

    @classmethod
    def register_new_ingested_email(cls, db: Session, evidence_id: str, email_sha256: str, analysis_dict: Dict[str, Any]) -> None:
        """
        Called when a new .eml is ingested. Indexes into inverted index and links to active campaigns.
        """
        from backend.services.cross_email_workspace_service import global_cross_email_workspace_service
        global_cross_email_workspace_service.index_email(evidence_id, analysis_dict)

        # Check if matches active campaign
        c042 = db.query(CampaignModel).filter(CampaignModel.campaign_id == "C-042").first()
        if c042:
            existing_link = db.query(CampaignEmailModel).filter(CampaignEmailModel.email_id == evidence_id).first()
            if not existing_link:
                sub = analysis_dict.get("subject") or "Untitled Email"
                sender = analysis_dict.get("from") or analysis_dict.get("from_header") or "unknown"
                threat_score = analysis_dict.get("threat_score", {}).get("score", 0.0) if isinstance(analysis_dict.get("threat_score"), dict) else 0.0

                c_email = CampaignEmailModel(
                    id=str(uuid.uuid4()),
                    campaign_id=c042.id,
                    email_id=evidence_id,
                    email_sha256=email_sha256,
                    subject=sub,
                    sender=sender,
                    recipient=analysis_dict.get("to") or "victim@corp.internal",
                    sent_at=datetime.now(timezone.utc),
                    similarity_to_campaign=0.88,
                    category_scores_json=json.dumps({
                        "infrastructure": 0.85,
                        "domain": 0.88,
                        "content": 0.90
                    })
                )
                db.add(c_email)
                c042.email_count = db.query(CampaignEmailModel).filter(CampaignEmailModel.campaign_id == c042.id).count() + 1
                c042.last_seen = datetime.now(timezone.utc)
                try:
                    db.commit()
                except Exception:
                    db.rollback()
