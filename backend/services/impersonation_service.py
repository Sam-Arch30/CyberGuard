"""
Digital Impersonation Detection Engine (Section 12).
Provides authoritative reference profile management, identity claim extraction,
deterministic identity comparison, domain/homoglyph/display-name analysis,
website credential-harvesting correlation, executive/authority impersonation detection,
contradicting evidence calibration, and canonical persistence.
"""
from __future__ import annotations

import re
import json
import logging
import tldextract
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlsplit

from sqlalchemy.orm import Session

from backend.db.models import (
    ArtifactModel,
    AnalysisRunModel,
    FindingModel,
    FindingEvidenceModel,
    ThreatEventModel,
    EntityModel,
    IndicatorModel,
    RelationshipModel,
    AuditLogModel,
    ProtectedIdentityModel,
    generate_uuid,
    get_utc_now,
)
from backend.schemas.unified import (
    ArtifactTypeEnum,
    AnalysisStatusEnum,
    AnalysisTriggerEnum,
    EntityTypeEnum,
    IndicatorTypeEnum,
    RelationshipTypeEnum,
    SeverityEnum,
    normalize_domain,
    normalize_email_address,
)
from backend.schemas.impersonation import (
    IdentityClaimTypeEnum,
    ReferenceSourceEnum,
    VerificationStatusEnum,
    ComparisonOutcomeEnum,
    ImpersonationClassificationEnum,
    IdentityEvidenceCategoryEnum,
    IdentityClaim,
    ProtectedIdentityProfile,
    ImpersonationFindingEvidence,
    ImpersonationFinding,
    ImpersonationAssessment,
    CreateProtectedIdentityRequest,
    UpdateProtectedIdentityRequest,
    ImpersonationAnalysisResponse,
)
from backend.services.lookalike_detector import (
    LookalikeDetectorService,
    normalize_homoglyphs,
    reverse_digit_substitutions,
    levenshtein_distance,
)
from backend.services.website_inspector import WebsiteInspector, WebsiteInspectionResult

logger = logging.getLogger("cyberguard.impersonation_service")


# ============================================================================
# 1. PROTECTED IDENTITY PROFILE MANAGER
# ============================================================================

class ProtectedIdentityManager:
    """
    Manages authoritative reference identity profiles (organizations, brands,
    executives, institutions) used as ground truth for impersonation detection.
    """

    def __init__(self):
        self._in_memory_profiles: Dict[str, ProtectedIdentityProfile] = {}
        self._seed_default_system_profiles()

    def _seed_default_system_profiles(self):
        """Seeds trusted default reference profiles for common high-value targets."""
        defaults = [
            ProtectedIdentityProfile(
                id="sys-prof-microsoft",
                display_name="Microsoft",
                entity_type=IdentityClaimTypeEnum.ORGANIZATION,
                trusted_domains=["microsoft.com", "office.com", "office365.com", "outlook.com", "live.com", "azure.com"],
                trusted_email_patterns=["*@microsoft.com", "*@outlook.com", "*@office365.com"],
                known_names=["Microsoft", "Microsoft Security", "Office 365", "Outlook Team", "Microsoft 365", "Azure Security"],
                known_brand_terms=["microsoft", "office365", "outlook", "azure", "onedrive", "sharepoint"],
                authorized_delegated_senders=["sendgrid.net", "exacttarget.com", "marketo.org"],
                source=ReferenceSourceEnum.SYSTEM_CONFIGURED,
                verification_status=VerificationStatusEnum.VERIFIED,
                revision=1,
            ),
            ProtectedIdentityProfile(
                id="sys-prof-google",
                display_name="Google",
                entity_type=IdentityClaimTypeEnum.ORGANIZATION,
                trusted_domains=["google.com", "gmail.com", "googlemail.com", "workspace.google.com"],
                trusted_email_patterns=["*@google.com", "*@gmail.com"],
                known_names=["Google", "Google Security", "Google Workspace", "Gmail Support", "Google Account Team"],
                known_brand_terms=["google", "gmail", "googlemail", "workspace", "gsuite"],
                authorized_delegated_senders=["google.com", "sendgrid.net"],
                source=ReferenceSourceEnum.SYSTEM_CONFIGURED,
                verification_status=VerificationStatusEnum.VERIFIED,
                revision=1,
            ),
            ProtectedIdentityProfile(
                id="sys-prof-paypal",
                display_name="PayPal",
                entity_type=IdentityClaimTypeEnum.BRAND,
                trusted_domains=["paypal.com", "paypal-communication.com"],
                trusted_email_patterns=["*@paypal.com", "*@paypal-communication.com"],
                known_names=["PayPal", "PayPal Security", "PayPal Support", "PayPal Resolution Center"],
                known_brand_terms=["paypal", "paypal-service", "paypal-security"],
                authorized_delegated_senders=["exacttarget.com"],
                source=ReferenceSourceEnum.SYSTEM_CONFIGURED,
                verification_status=VerificationStatusEnum.VERIFIED,
                revision=1,
            ),
            ProtectedIdentityProfile(
                id="sys-prof-apple",
                display_name="Apple",
                entity_type=IdentityClaimTypeEnum.ORGANIZATION,
                trusted_domains=["apple.com", "icloud.com", "email.apple.com"],
                trusted_email_patterns=["*@apple.com", "*@icloud.com", "*@email.apple.com"],
                known_names=["Apple", "Apple Support", "iCloud Security", "Apple ID Support"],
                known_brand_terms=["apple", "icloud", "appleid", "itunes"],
                authorized_delegated_senders=["email.apple.com"],
                source=ReferenceSourceEnum.SYSTEM_CONFIGURED,
                verification_status=VerificationStatusEnum.VERIFIED,
                revision=1,
            ),
            ProtectedIdentityProfile(
                id="sys-prof-github",
                display_name="GitHub",
                entity_type=IdentityClaimTypeEnum.ORGANIZATION,
                trusted_domains=["github.com"],
                trusted_email_patterns=["*@github.com"],
                known_names=["GitHub", "GitHub Support", "GitHub Security Team"],
                known_brand_terms=["github"],
                authorized_delegated_senders=["github.com"],
                source=ReferenceSourceEnum.SYSTEM_CONFIGURED,
                verification_status=VerificationStatusEnum.VERIFIED,
                revision=1,
            ),
            ProtectedIdentityProfile(
                id="sys-prof-acme",
                display_name="Acme Corporation",
                entity_type=IdentityClaimTypeEnum.ORGANIZATION,
                trusted_domains=["acme.example", "acme.test", "corp.acme.example"],
                trusted_email_patterns=["*@acme.example", "*@acme.test", "*@corp.acme.example"],
                trusted_sender_addresses=["security@acme.example", "billing@acme.example", "support@acme.example"],
                known_names=["Acme", "Acme Corp", "Acme Corporation", "Acme Security", "Acme Support", "Acme Employee Portal"],
                known_roles=["CEO", "Chief Executive Officer", "IT Administrator", "Security Team", "Finance Department"],
                known_brand_terms=["acme", "acme-corp", "acmepay"],
                authorized_delegated_senders=["mailchimp.com", "sendgrid.net", "zendesk.com"],
                source=ReferenceSourceEnum.SYSTEM_CONFIGURED,
                verification_status=VerificationStatusEnum.VERIFIED,
                revision=1,
                metadata={
                    "executives": [
                        {"name": "Alice Example", "role": "CEO", "email": "alice@acme.example"},
                        {"name": "Bob Chief", "role": "CFO", "email": "bob.cfo@acme.example"},
                    ]
                }
            ),
        ]
        for p in defaults:
            self._in_memory_profiles[p.id] = p

    def get_all(self, db: Optional[Session] = None, active_only: bool = True) -> List[ProtectedIdentityProfile]:
        """Returns all reference profiles from database or in-memory fallback, merged by ID."""
        profiles_dict = dict(self._in_memory_profiles)
        if db is not None:
            try:
                query = db.query(ProtectedIdentityModel)
                if active_only:
                    query = query.filter(ProtectedIdentityModel.is_active.is_(True))
                db_models = query.all()
                for m in db_models:
                    profiles_dict[m.id] = self._db_model_to_schema(m)
            except Exception as e:
                logger.warning(f"Error reading ProtectedIdentityModel from DB: {e}")

        if active_only:
            return [p for p in profiles_dict.values() if p.is_active]
        return list(profiles_dict.values())

    def get_by_id(self, profile_id: str, db: Optional[Session] = None) -> Optional[ProtectedIdentityProfile]:
        """Retrieves a single protected profile by ID."""
        if db is not None:
            try:
                m = db.query(ProtectedIdentityModel).filter(ProtectedIdentityModel.id == profile_id).first()
                if m:
                    return self._db_model_to_schema(m)
            except Exception as e:
                logger.warning(f"DB lookup failed for profile {profile_id}: {e}")
        return self._in_memory_profiles.get(profile_id)

    def find_by_domain(self, domain: str, db: Optional[Session] = None) -> Optional[ProtectedIdentityProfile]:
        """Matches a domain against trusted domains or known brand terms of protected profiles."""
        if not domain:
            return None
        clean_dom = domain.lower().strip().rstrip(".")
        ext = tldextract.extract(clean_dom)
        reg_domain = f"{ext.domain}.{ext.suffix}".lower() if ext.suffix else ext.domain.lower()

        for p in self.get_all(db):
            for td in p.trusted_domains:
                td_clean = td.lower().strip().rstrip(".")
                if clean_dom == td_clean or reg_domain == td_clean or clean_dom.endswith(f".{td_clean}"):
                    return p
        return None

    def find_by_name(self, name: str, db: Optional[Session] = None) -> Optional[ProtectedIdentityProfile]:
        """Matches a display name or brand name against known names."""
        if not name:
            return None
        clean_name = name.lower().strip()
        for p in self.get_all(db):
            if p.display_name.lower() == clean_name:
                return p
            for kn in p.known_names:
                if kn.lower() == clean_name:
                    return p
                # Safe token matching for multi-word names
                if len(kn) >= 4 and kn.lower() in clean_name:
                    return p
        return None

    def find_by_brand_term(self, term: str, db: Optional[Session] = None) -> Optional[ProtectedIdentityProfile]:
        """Matches an extracted keyword or brand label."""
        if not term:
            return None
        clean_term = term.lower().strip()
        for p in self.get_all(db):
            for bt in p.known_brand_terms:
                if bt.lower() == clean_term or clean_term == bt.lower():
                    return p
        return None

    def find_by_executive_name(self, name: str, db: Optional[Session] = None) -> Optional[Tuple[ProtectedIdentityProfile, Dict[str, Any]]]:
        """Matches an executive's full name from configured metadata."""
        if not name or len(name.strip().split()) < 2:
            # Require at least two words for a human full name to prevent false positives on common first names
            return None
        clean_name = name.lower().strip()
        for p in self.get_all(db):
            execs = p.metadata.get("executives", [])
            for ex in execs:
                ex_name = ex.get("name", "").lower().strip()
                if ex_name == clean_name:
                    return p, ex
        return None

    def create_profile(
        self,
        request: CreateProtectedIdentityRequest,
        db: Optional[Session] = None,
        user: str = "SOC Analyst",
    ) -> ProtectedIdentityProfile:
        """Creates a new protected reference identity and records an audit log."""
        prof_id = generate_uuid()
        now = datetime.now(timezone.utc)
        profile = ProtectedIdentityProfile(
            id=prof_id,
            display_name=request.display_name,
            entity_type=request.entity_type,
            trusted_domains=[d.lower().strip().rstrip(".") for d in request.trusted_domains],
            trusted_email_patterns=request.trusted_email_patterns,
            trusted_sender_addresses=[a.lower().strip() for a in request.trusted_sender_addresses],
            known_names=request.known_names,
            known_roles=request.known_roles,
            known_brand_terms=[b.lower().strip() for b in request.known_brand_terms],
            authorized_delegated_senders=[s.lower().strip() for s in request.authorized_delegated_senders],
            source=request.source,
            verification_status=request.verification_status,
            is_active=True,
            revision=1,
            created_at=now,
            updated_at=now,
            metadata=request.metadata,
        )

        self._in_memory_profiles[prof_id] = profile

        if db is not None:
            db_model = ProtectedIdentityModel(
                id=prof_id,
                display_name=profile.display_name,
                entity_type=profile.entity_type.value,
                source=profile.source.value,
                verification_status=profile.verification_status.value,
                is_active=True,
                revision=1,
                trusted_domains_json=json.dumps(profile.trusted_domains),
                trusted_emails_json=json.dumps(profile.trusted_email_patterns),
                known_names_json=json.dumps(profile.known_names),
                known_roles_json=json.dumps(profile.known_roles),
                known_brand_terms_json=json.dumps(profile.known_brand_terms),
                authorized_delegated_senders_json=json.dumps(profile.authorized_delegated_senders),
                metadata_json=json.dumps(profile.metadata),
                created_at=now,
                updated_at=now,
            )
            db.add(db_model)

            # Audit event
            audit = AuditLogModel(
                id=generate_uuid(),
                timestamp=get_utc_now(),
                user=user,
                action="PROTECTED_IDENTITY_CREATED",
                resource_type="protected_identity",
                resource_id=prof_id,
                metadata_json=json.dumps({
                    "display_name": profile.display_name,
                    "trusted_domains": profile.trusted_domains,
                }),
                details=f"Created protected identity '{profile.display_name}' with {len(profile.trusted_domains)} trusted domains.",
            )
            db.add(audit)
            db.commit()

        logger.info(f"Created protected identity profile '{profile.display_name}' ({prof_id})")
        return profile

    def update_profile(
        self,
        profile_id: str,
        request: UpdateProtectedIdentityRequest,
        db: Optional[Session] = None,
        user: str = "SOC Analyst",
    ) -> Optional[ProtectedIdentityProfile]:
        """Updates an existing profile, increments revision number, and writes audit records."""
        profile = self.get_by_id(profile_id, db)
        if not profile:
            return None

        now = datetime.now(timezone.utc)
        old_domains = set(profile.trusted_domains)

        if request.display_name is not None:
            profile.display_name = request.display_name
        if request.entity_type is not None:
            profile.entity_type = request.entity_type
        if request.trusted_domains is not None:
            profile.trusted_domains = [d.lower().strip().rstrip(".") for d in request.trusted_domains]
        if request.trusted_email_patterns is not None:
            profile.trusted_email_patterns = request.trusted_email_patterns
        if request.trusted_sender_addresses is not None:
            profile.trusted_sender_addresses = [a.lower().strip() for a in request.trusted_sender_addresses]
        if request.known_names is not None:
            profile.known_names = request.known_names
        if request.known_roles is not None:
            profile.known_roles = request.known_roles
        if request.known_brand_terms is not None:
            profile.known_brand_terms = [b.lower().strip() for b in request.known_brand_terms]
        if request.authorized_delegated_senders is not None:
            profile.authorized_delegated_senders = [s.lower().strip() for s in request.authorized_delegated_senders]
        if request.is_active is not None:
            profile.is_active = request.is_active
        if request.metadata is not None:
            profile.metadata.update(request.metadata)

        profile.revision += 1
        profile.updated_at = now
        self._in_memory_profiles[profile_id] = profile

        if db is not None:
            db_model = db.query(ProtectedIdentityModel).filter(ProtectedIdentityModel.id == profile_id).first()
            if db_model:
                db_model.display_name = profile.display_name
                db_model.entity_type = profile.entity_type.value
                db_model.trusted_domains_json = json.dumps(profile.trusted_domains)
                db_model.trusted_emails_json = json.dumps(profile.trusted_email_patterns)
                db_model.known_names_json = json.dumps(profile.known_names)
                db_model.known_roles_json = json.dumps(profile.known_roles)
                db_model.known_brand_terms_json = json.dumps(profile.known_brand_terms)
                db_model.authorized_delegated_senders_json = json.dumps(profile.authorized_delegated_senders)
                db_model.is_active = profile.is_active
                db_model.revision = profile.revision
                db_model.metadata_json = json.dumps(profile.metadata)
                db_model.updated_at = now

            # Audit changes
            new_domains = set(profile.trusted_domains)
            added_doms = list(new_domains - old_domains)
            removed_doms = list(old_domains - new_domains)

            actions = ["PROTECTED_IDENTITY_UPDATED"]
            if added_doms:
                actions.append("TRUSTED_DOMAIN_ADDED")
            if removed_doms:
                actions.append("TRUSTED_DOMAIN_REMOVED")

            audit = AuditLogModel(
                id=generate_uuid(),
                timestamp=get_utc_now(),
                user=user,
                action="; ".join(actions),
                resource_type="protected_identity",
                resource_id=profile_id,
                metadata_json=json.dumps({
                    "revision": profile.revision,
                    "added_domains": added_doms,
                    "removed_domains": removed_doms,
                }),
                details=f"Updated profile '{profile.display_name}' to revision {profile.revision}.",
            )
            db.add(audit)
            db.commit()

        logger.info(f"Updated profile '{profile.display_name}' to revision {profile.revision}")
        return profile

    def disable_profile(self, profile_id: str, db: Optional[Session] = None, user: str = "SOC Analyst") -> bool:
        """Disables a profile and records an audit log."""
        profile = self.get_by_id(profile_id, db)
        if not profile:
            return False

        profile.is_active = False
        profile.revision += 1
        profile.updated_at = datetime.now(timezone.utc)
        self._in_memory_profiles[profile_id] = profile

        if db is not None:
            db_model = db.query(ProtectedIdentityModel).filter(ProtectedIdentityModel.id == profile_id).first()
            if db_model:
                db_model.is_active = False
                db_model.revision = profile.revision
                db_model.updated_at = profile.updated_at

            audit = AuditLogModel(
                id=generate_uuid(),
                timestamp=get_utc_now(),
                user=user,
                action="PROTECTED_IDENTITY_DISABLED",
                resource_type="protected_identity",
                resource_id=profile_id,
                metadata_json=json.dumps({"revision": profile.revision}),
                details=f"Deactivated protected identity '{profile.display_name}'.",
            )
            db.add(audit)
            db.commit()
        return True

    def _db_model_to_schema(self, m: ProtectedIdentityModel) -> ProtectedIdentityProfile:
        """Converts SQLAlchemy model to Pydantic ProtectedIdentityProfile."""
        return ProtectedIdentityProfile(
            id=m.id,
            display_name=m.display_name,
            entity_type=IdentityClaimTypeEnum(m.entity_type),
            trusted_domains=json.loads(m.trusted_domains_json or "[]"),
            trusted_email_patterns=json.loads(m.trusted_emails_json or "[]"),
            trusted_sender_addresses=[],
            known_names=json.loads(m.known_names_json or "[]"),
            known_roles=json.loads(m.known_roles_json or "[]"),
            known_brand_terms=json.loads(m.known_brand_terms_json or "[]"),
            authorized_delegated_senders=json.loads(m.authorized_delegated_senders_json or "[]"),
            source=ReferenceSourceEnum(m.source),
            verification_status=VerificationStatusEnum(m.verification_status),
            is_active=m.is_active,
            revision=m.revision,
            created_at=m.created_at,
            updated_at=m.updated_at,
            metadata=json.loads(m.metadata_json or "{}"),
        )


global_protected_identity_manager = ProtectedIdentityManager()


# ============================================================================
# 2. IDENTITY CLAIM EXTRACTOR
# ============================================================================

class IdentityClaimExtractor:
    """
    Extracts explicit identity claims from email headers, URLs, web pages,
    and text contents without fabricating verified assertions.
    """

    AUTHORITY_ROLE_PATTERNS = [
        (r'\b(?:ceo|chief executive officer)\b', "CEO"),
        (r'\b(?:cfo|chief financial officer)\b', "CFO"),
        (r'\b(?:coo|chief operating officer)\b', "COO"),
        (r'\b(?:it support|helpdesk|tech support)\b', "IT Support"),
        (r'\b(?:security team|infosec|soc team)\b', "Security Team"),
        (r'\b(?:human resources|hr department)\b', "Human Resources"),
        (r'\b(?:finance department|billing department)\b', "Finance"),
    ]

    @classmethod
    def extract_from_email(cls, email_data: Dict[str, Any]) -> List[IdentityClaim]:
        """Extracts identity claims from email metadata and content."""
        claims: List[IdentityClaim] = []

        from_disp = email_data.get("from_display_name") or ""
        from_addr = email_data.get("from_address") or ""
        from_dom = email_data.get("from_domain") or ""
        reply_to_addr = email_data.get("reply_to_address") or ""
        reply_to_dom = email_data.get("reply_to_domain") or ""
        subject = email_data.get("subject") or ""
        body_text = email_data.get("body_text") or email_data.get("plain_text_body") or ""

        # 1. From Display Name Claim
        if from_disp.strip():
            claims.append(IdentityClaim(
                claim_type=IdentityClaimTypeEnum.PERSON if " " in from_disp.strip() else IdentityClaimTypeEnum.ORGANIZATION,
                claimed_name=from_disp.strip(),
                claimed_domain=from_dom or None,
                claimed_email=from_addr or None,
                text_span=f"From: {from_disp} <{from_addr}>",
                metadata={"header": "From", "display_name": from_disp},
            ))

        # 2. Reply-To Claim if explicitly specified
        if reply_to_addr and reply_to_addr != from_addr:
            claims.append(IdentityClaim(
                claim_type=IdentityClaimTypeEnum.SERVICE,
                claimed_name=email_data.get("reply_to_display_name") or reply_to_addr,
                claimed_domain=reply_to_dom or None,
                claimed_email=reply_to_addr,
                text_span=f"Reply-To: {reply_to_addr}",
                metadata={"header": "Reply-To"},
            ))

        # 3. Role / Authority claims in Subject or Body
        combined_text = f"{subject}\n{body_text}"
        for pattern, role_title in cls.AUTHORITY_ROLE_PATTERNS:
            m = re.search(pattern, combined_text, re.IGNORECASE)
            if m:
                claims.append(IdentityClaim(
                    claim_type=IdentityClaimTypeEnum.ROLE,
                    claimed_name=role_title,
                    claimed_role=role_title,
                    text_span=m.group(0),
                    metadata={"source_field": "content", "matched_role": role_title},
                ))

        return claims

    @classmethod
    def extract_from_website(cls, web_data: Dict[str, Any]) -> List[IdentityClaim]:
        """Extracts identity claims from website HTML title, meta tags, and form contexts."""
        claims: List[IdentityClaim] = []
        title = web_data.get("title") or ""
        url = web_data.get("url") or ""
        base_dom = web_data.get("base_domain") or ""
        brand_mentions = web_data.get("brand_mentions") or []

        # 1. Page Title claim
        if title:
            # Look for common "Brand - Page" or "Brand Login" patterns
            cleaned_title = re.sub(r'[-–|:].*$', '', title).strip()
            claimed_name = cleaned_title if len(cleaned_title) >= 3 else title.strip()
            claims.append(IdentityClaim(
                claim_type=IdentityClaimTypeEnum.ORGANIZATION,
                claimed_name=claimed_name,
                claimed_domain=base_dom or None,
                text_span=f"<title>{title}</title>",
                metadata={"title": title, "url": url},
            ))

        # 2. Extracted brand mentions
        for bm in brand_mentions:
            claims.append(IdentityClaim(
                claim_type=IdentityClaimTypeEnum.BRAND,
                claimed_name=bm,
                text_span=f"Brand mention: {bm}",
                metadata={"brand_mention": bm},
            ))

        return claims

    @classmethod
    def extract_from_url(cls, url: str) -> List[IdentityClaim]:
        """Extracts identity claims from deceptive subdomains or lookalike URL paths."""
        claims: List[IdentityClaim] = []
        try:
            p = urlsplit(url if "://" in url else f"http://{url}")
            host = p.netloc.split(":")[0].lower().rstrip(".")
            ext = tldextract.extract(host)

            # Check if subdomain contains a brand or domain-like string (e.g. paypal.com.security.evil.test)
            if ext.subdomain:
                sub_parts = ext.subdomain.split(".")
                for part in sub_parts:
                    if len(part) >= 3:
                        claims.append(IdentityClaim(
                            claim_type=IdentityClaimTypeEnum.BRAND,
                            claimed_name=part,
                            claimed_domain=host,
                            text_span=f"Subdomain: {part} in {host}",
                            metadata={"subdomain": ext.subdomain, "host": host},
                        ))
        except Exception:
            pass
        return claims


# ============================================================================
# 3. IDENTITY COMPARISON SERVICE
# ============================================================================

class IdentityComparisonService:
    """
    Centralized service that compares an IdentityClaim and Observed Technical Identity
    against an authoritative ProtectedIdentityProfile.
    """

    def __init__(self, lookalike_detector: Optional[LookalikeDetectorService] = None):
        self.lookalike_detector = lookalike_detector or LookalikeDetectorService()

    def compare_domain(
        self,
        observed_domain: str,
        profile: ProtectedIdentityProfile,
    ) -> Tuple[ComparisonOutcomeEnum, Dict[str, Any]]:
        """
        Compares an observed technical domain against a protected profile's trusted domains,
        authorized delegated senders, and lookalike algorithms.
        """
        if not observed_domain:
            return ComparisonOutcomeEnum.UNKNOWN, {"reason": "No observed domain provided"}

        clean_obs = observed_domain.lower().strip().rstrip(".")
        ext_obs = tldextract.extract(clean_obs)
        if ext_obs.suffix:
            reg_obs = f"{ext_obs.domain}.{ext_obs.suffix}".lower()
        else:
            obs_parts = clean_obs.split(".")
            reg_obs = f"{obs_parts[-2]}.{obs_parts[-1]}".lower() if len(obs_parts) >= 2 else clean_obs

        # Helper to get the primary domain label (e.g. 'paypal' from 'paypal.com' or 'acm3' from 'acm3.example')
        def _get_base_label(d: str) -> str:
            clean = d.lower().strip().rstrip(".")
            ext = tldextract.extract(clean)
            if ext.suffix and ext.domain:
                return ext.domain.lower()
            parts = clean.split(".")
            if len(parts) >= 2:
                return parts[-2].lower()
            return clean

        # 1. Exact Match with Trusted Domains
        for td in profile.trusted_domains:
            clean_td = td.lower().strip().rstrip(".")
            if clean_obs == clean_td or reg_obs == clean_td or clean_obs.endswith(f".{clean_td}"):
                return ComparisonOutcomeEnum.MATCH, {
                    "matched_trusted_domain": clean_td,
                    "is_authorized": True,
                    "is_delegated": False,
                }

        # 2. Match with Authorized Delegated Senders (e.g. Mailchimp, SendGrid)
        for ds in profile.authorized_delegated_senders:
            clean_ds = ds.lower().strip().rstrip(".")
            if clean_obs == clean_ds or reg_obs == clean_ds or clean_obs.endswith(f".{clean_ds}"):
                return ComparisonOutcomeEnum.MATCH, {
                    "matched_delegated_sender": clean_ds,
                    "is_authorized": True,
                    "is_delegated": True,
                }

        # 3. Deceptive Subdomain Hierarchy: Subdomain explicitly contains trusted brand/domain
        subdomain_to_check = ext_obs.subdomain
        if not subdomain_to_check and not ext_obs.suffix:
            parts = clean_obs.split(".")
            if len(parts) > 2:
                subdomain_to_check = ".".join(parts[:-2])

        for td in profile.trusted_domains:
            clean_td = td.lower().strip().rstrip(".")
            base_label = _get_base_label(clean_td)
            if subdomain_to_check and (clean_td in subdomain_to_check or base_label in subdomain_to_check.split(".")):
                return ComparisonOutcomeEnum.LOOKALIKE, {
                    "technique": "deceptive_subdomain",
                    "subdomain": subdomain_to_check,
                    "registrable_domain": reg_obs,
                    "targeted_brand_domain": clean_td,
                    "similarity": 0.95,
                }

        # 4. Homoglyphs & Leet Substitutions
        homo_clean, has_homo = normalize_homoglyphs(clean_obs)
        leet_clean, has_leet = reverse_digit_substitutions(homo_clean)
        homo_base = _get_base_label(homo_clean)
        leet_base = _get_base_label(leet_clean)
        obs_base = _get_base_label(clean_obs)

        for td in profile.trusted_domains:
            clean_td = td.lower().strip().rstrip(".")
            td_base = _get_base_label(clean_td)

            # Exact base match after homoglyph / leet normalization
            if has_homo and homo_base == td_base:
                return ComparisonOutcomeEnum.LOOKALIKE, {
                    "technique": "unicode_homoglyphs",
                    "normalized_domain": homo_clean,
                    "targeted_brand_domain": clean_td,
                    "similarity": 0.95,
                }

            if has_leet and leet_base == td_base:
                return ComparisonOutcomeEnum.LOOKALIKE, {
                    "technique": "leet_substitution",
                    "normalized_domain": leet_clean,
                    "targeted_brand_domain": clean_td,
                    "similarity": 0.95,
                }

            # Levenshtein Edit Distance on primary label
            dist = levenshtein_distance(obs_base, td_base)
            max_len = max(len(obs_base), len(td_base))
            sim = 1.0 - (dist / max_len) if max_len > 0 else 0.0

            # Edit distance of 1 or 2 with similarity >= 0.75 is a lookalike
            if 1 <= dist <= 2 and sim >= 0.75:
                return ComparisonOutcomeEnum.LOOKALIKE, {
                    "technique": "typosquatting_edit_distance",
                    "edit_distance": dist,
                    "similarity": round(sim, 3),
                    "targeted_brand_domain": clean_td,
                }

        return ComparisonOutcomeEnum.MISMATCH, {
            "reason": f"Observed domain '{clean_obs}' is not recognized under protected profile '{profile.display_name}'",
            "registrable_domain": reg_obs,
        }

    def compare_name(
        self,
        claimed_name: str,
        profile: ProtectedIdentityProfile,
    ) -> Tuple[ComparisonOutcomeEnum, Dict[str, Any]]:
        """Compares claimed display name or organization name against protected reference."""
        if not claimed_name:
            return ComparisonOutcomeEnum.UNKNOWN, {"reason": "No name provided"}

        clean_claim = claimed_name.lower().strip()
        ref_name = profile.display_name.lower().strip()

        # Exact match
        if clean_claim == ref_name:
            return ComparisonOutcomeEnum.MATCH, {"matched_name": profile.display_name}

        # Known names / aliases
        for kn in profile.known_names:
            if kn.lower().strip() == clean_claim:
                return ComparisonOutcomeEnum.MATCH, {"matched_alias": kn}
            if len(kn) >= 4 and kn.lower().strip() in clean_claim:
                return ComparisonOutcomeEnum.PARTIAL_MATCH, {"matched_alias": kn}

        return ComparisonOutcomeEnum.MISMATCH, {"reason": "Name does not match protected profile"}


# ============================================================================
# 4. DIGITAL IMPERSONATION PIPELINE & DETECTORS
# ============================================================================

class DigitalImpersonationPipeline:
    """
    Main orchestration engine for Section 12. Consumes multi-source artifacts,
    extracts identity claims, evaluates against authoritative protected profiles,
    weighs supporting vs. contradicting technical evidence, and produces explainable findings.
    """
    PIPELINE_VERSION = "1.0.0"

    def __init__(
        self,
        identity_manager: Optional[ProtectedIdentityManager] = None,
        comparison_service: Optional[IdentityComparisonService] = None,
    ):
        self.identity_manager = identity_manager or global_protected_identity_manager
        self.comparison_service = comparison_service or IdentityComparisonService()

    def analyze(
        self,
        artifact_type: ArtifactTypeEnum,
        email_data: Optional[Dict[str, Any]] = None,
        url_data: Optional[Dict[str, Any]] = None,
        website_data: Optional[Dict[str, Any]] = None,
        target_identity_hint: Optional[str] = None,
        db: Optional[Session] = None,
        artifact_id: Optional[str] = None,
        trigger: AnalysisTriggerEnum = AnalysisTriggerEnum.USER,
    ) -> ImpersonationAnalysisResponse:
        """Executes full digital impersonation analysis."""
        claims: List[IdentityClaim] = []
        supporting_findings: List[ImpersonationFinding] = []
        contradicting_findings: List[ImpersonationFinding] = []
        limitations: List[str] = []
        profiles_used: Dict[str, int] = {}

        # 1. Claim Extraction
        if email_data:
            claims.extend(IdentityClaimExtractor.extract_from_email(email_data))
        if website_data:
            claims.extend(IdentityClaimExtractor.extract_from_website(website_data))
        if url_data:
            raw_url = url_data.get("url") or ""
            if raw_url:
                claims.extend(IdentityClaimExtractor.extract_from_url(raw_url))

        # 2. Target Reference Profile Resolution
        target_profile: Optional[ProtectedIdentityProfile] = None

        # Check explicit hint first
        if target_identity_hint:
            target_profile = self.identity_manager.get_by_id(target_identity_hint, db) or \
                             self.identity_manager.find_by_name(target_identity_hint, db)

        # Match from claims if not explicitly hinted
        if not target_profile:
            for c in claims:
                p = self.identity_manager.find_by_name(c.claimed_name, db) or \
                    self.identity_manager.find_by_brand_term(c.claimed_name, db)
                if not p:
                    exec_match = self.identity_manager.find_by_executive_name(c.claimed_name, db)
                    if exec_match:
                        p = exec_match[0]
                if p:
                    target_profile = p
                    break

        # Check observed domains if still not matched
        if not target_profile and email_data:
            from_dom = email_data.get("from_domain")
            if from_dom:
                # Lookalike search across all profiles
                for prof in self.identity_manager.get_all(db):
                    outcome, _ = self.comparison_service.compare_domain(from_dom, prof)
                    if outcome in (ComparisonOutcomeEnum.MATCH, ComparisonOutcomeEnum.LOOKALIKE):
                        target_profile = prof
                        break

        if target_profile:
            profiles_used[target_profile.id] = target_profile.revision

        # 3. Evaluate Claims & Evidence against Reference Profile
        if target_profile:
            self._evaluate_email_impersonation(
                email_data=email_data,
                profile=target_profile,
                supporting=supporting_findings,
                contradicting=contradicting_findings,
                limitations=limitations,
            )
            self._evaluate_domain_impersonation(
                email_data=email_data,
                url_data=url_data,
                profile=target_profile,
                supporting=supporting_findings,
                contradicting=contradicting_findings,
                limitations=limitations,
            )
            self._evaluate_website_impersonation(
                website_data=website_data,
                profile=target_profile,
                supporting=supporting_findings,
                contradicting=contradicting_findings,
                limitations=limitations,
            )
            self._evaluate_executive_authority_impersonation(
                email_data=email_data,
                claims=claims,
                profile=target_profile,
                supporting=supporting_findings,
                contradicting=contradicting_findings,
                limitations=limitations,
                db=db,
            )
        else:
            # No reference profile could be resolved for claims
            if claims:
                limitations.append(
                    "Claims of identity observed in telemetry, but no authoritative ProtectedIdentityProfile was configured or matched."
                )

        # 4. Impersonation Assessment & Classification Synthesis
        assessment = self._synthesize_assessment(
            target_profile=target_profile,
            claims=claims,
            supporting=supporting_findings,
            contradicting=contradicting_findings,
            limitations=limitations,
            profiles_used=profiles_used,
        )

        # 5. Canonical Persistence
        run_id = generate_uuid()
        entities_created: List[str] = []
        relationships_created: List[str] = []
        threat_events_created: List[str] = []

        if db is not None:
            self._persist_results(
                run_id=run_id,
                artifact_id=artifact_id,
                assessment=assessment,
                target_profile=target_profile,
                email_data=email_data,
                url_data=url_data,
                website_data=website_data,
                trigger=trigger,
                db=db,
                entities_created=entities_created,
                relationships_created=relationships_created,
                threat_events_created=threat_events_created,
            )

        return ImpersonationAnalysisResponse(
            analysis_run_id=run_id,
            artifact_id=artifact_id,
            assessment=assessment,
            entities_created=entities_created,
            relationships_created=relationships_created,
            threat_events_created=threat_events_created,
        )

    # ------------------------------------------------------------------------
    # Analytical Sub-Engine Evaluators
    # ------------------------------------------------------------------------

    def _evaluate_email_impersonation(
        self,
        email_data: Optional[Dict[str, Any]],
        profile: ProtectedIdentityProfile,
        supporting: List[ImpersonationFinding],
        contradicting: List[ImpersonationFinding],
        limitations: List[str],
    ):
        if not email_data:
            return

        from_disp = email_data.get("from_display_name") or ""
        from_dom = (email_data.get("from_domain") or "").lower().strip().rstrip(".")
        from_addr = email_data.get("from_address") or ""
        reply_to_dom = (email_data.get("reply_to_domain") or "").lower().strip().rstrip(".")
        reply_to_addr = email_data.get("reply_to_address") or ""
        spf_res = (email_data.get("spf_result") or "").lower().strip()
        dkim_res = (email_data.get("dkim_result") or "").lower().strip()
        dmarc_res = (email_data.get("dmarc_result") or "").lower().strip()

        # Check technical sender domain
        dom_outcome, dom_info = self.comparison_service.compare_domain(from_dom, profile)

        # 1. Contradicting Evidence: Trusted sending infrastructure
        if dom_outcome == ComparisonOutcomeEnum.MATCH:
            if dom_info.get("is_delegated"):
                contradicting.append(ImpersonationFinding(
                    finding_type="AUTHORIZED_DELEGATED_SENDER",
                    title=f"Authorized Delegated Sender Observed ({from_dom})",
                    description=f"Sender domain '{from_dom}' matches configured authorized delegated sending platform for '{profile.display_name}'.",
                    severity=SeverityEnum.SAFE,
                    confidence=0.95,
                    category=IdentityEvidenceCategoryEnum.EMAIL_IDENTITY,
                    rule_id="IMP_DEL_001",
                    target_identity_id=profile.id,
                    target_identity_name=profile.display_name,
                    evidence_items=[
                        ImpersonationFindingEvidence(
                            category=IdentityEvidenceCategoryEnum.EMAIL_IDENTITY,
                            source="EmailHeader",
                            key="from_domain",
                            value=from_dom,
                            is_contradicting=True,
                            notes="Domain in authorized delegated senders list",
                        )
                    ],
                    limitation="Legitimate marketing or transactional platforms can be spoofed if DKIM/DMARC are not enforced.",
                ))
            if dkim_res == "pass" and (dmarc_res == "pass" or spf_res == "pass"):
                contradicting.append(ImpersonationFinding(
                    finding_type="AUTHENTICATED_LEGITIMATE_SENDER",
                    title=f"Cryptographic Authentication Passes for {profile.display_name}",
                    description=f"Email from '{from_dom}' verified via DKIM and DMARC alignment against protected domain.",
                    severity=SeverityEnum.SAFE,
                    confidence=0.98,
                    category=IdentityEvidenceCategoryEnum.AUTHENTICATION_IDENTITY,
                    rule_id="IMP_AUTH_PASS_001",
                    target_identity_id=profile.id,
                    target_identity_name=profile.display_name,
                    evidence_items=[
                        ImpersonationFindingEvidence(
                            category=IdentityEvidenceCategoryEnum.AUTHENTICATION_IDENTITY,
                            source="EmailAuthentication",
                            key="dkim_dmarc_status",
                            value=f"DKIM: {dkim_res}, DMARC: {dmarc_res}, SPF: {spf_res}",
                            is_contradicting=True,
                        )
                    ],
                    limitation="DMARC PASS proves domain authorization; it does not guarantee account compromise did not occur.",
                ))

        # 2. Supporting Evidence: Display Name Impersonation
        name_outcome, _ = self.comparison_service.compare_name(from_disp, profile)
        if name_outcome in (ComparisonOutcomeEnum.MATCH, ComparisonOutcomeEnum.PARTIAL_MATCH):
            # If display name matches protected identity, but sender domain does NOT match
            if dom_outcome != ComparisonOutcomeEnum.MATCH:
                supporting.append(ImpersonationFinding(
                    finding_type="DISPLAY_NAME_IMPERSONATION_SIGNAL",
                    title=f"Display Name Impersonation Targeting '{profile.display_name}'",
                    description=(
                        f"Display name '{from_disp}' claims identity of '{profile.display_name}', "
                        f"but email was sent from unrelated domain '{from_dom}' ({from_addr})."
                    ),
                    severity=SeverityEnum.HIGH,
                    confidence=0.92,
                    risk_contribution=35.0,
                    rule_id="IMP_NAME_001",
                    category=IdentityEvidenceCategoryEnum.NAME_IDENTITY,
                    target_identity_id=profile.id,
                    target_identity_name=profile.display_name,
                    evidence_items=[
                        ImpersonationFindingEvidence(
                            category=IdentityEvidenceCategoryEnum.NAME_IDENTITY,
                            source="EmailHeader",
                            key="claimed_display_name",
                            value=from_disp,
                        ),
                        ImpersonationFindingEvidence(
                            category=IdentityEvidenceCategoryEnum.EMAIL_IDENTITY,
                            source="EmailHeader",
                            key="actual_sender_domain",
                            value=from_dom,
                        ),
                        ImpersonationFindingEvidence(
                            category=IdentityEvidenceCategoryEnum.DOMAIN_IDENTITY,
                            source="ProtectedProfile",
                            key="reference_trusted_domains",
                            value=", ".join(profile.trusted_domains),
                        ),
                    ],
                    limitation="Free webmail or employee personal communications may use corporate display names without malicious intent.",
                    mitre_attack_ids=["T1566.002"],
                ))

        # 3. Supporting Evidence: Reply-To Deception
        if reply_to_dom and from_dom and reply_to_dom != from_dom:
            # Check if From claimed protected identity or trusted domain, but Reply-To goes elsewhere
            is_from_trusted = (dom_outcome == ComparisonOutcomeEnum.MATCH) or (name_outcome == ComparisonOutcomeEnum.MATCH)
            if is_from_trusted and not any(reply_to_dom.endswith(td) for td in profile.trusted_domains):
                supporting.append(ImpersonationFinding(
                    finding_type="IDENTITY_REPLY_TO_MISMATCH",
                    title="Suspicious Reply-To Redirection on Protected Identity",
                    description=(
                        f"Email claiming '{profile.display_name}' (From: {from_addr}) specifies a divergent "
                        f"Reply-To address '{reply_to_addr}' ({reply_to_dom}) to intercept responses."
                    ),
                    severity=SeverityEnum.HIGH,
                    confidence=0.90,
                    risk_contribution=25.0,
                    rule_id="IMP_RT_001",
                    category=IdentityEvidenceCategoryEnum.EMAIL_IDENTITY,
                    target_identity_id=profile.id,
                    target_identity_name=profile.display_name,
                    evidence_items=[
                        ImpersonationFindingEvidence(
                            category=IdentityEvidenceCategoryEnum.EMAIL_IDENTITY,
                            source="EmailHeader",
                            key="from_address",
                            value=from_addr,
                        ),
                        ImpersonationFindingEvidence(
                            category=IdentityEvidenceCategoryEnum.EMAIL_IDENTITY,
                            source="EmailHeader",
                            key="reply_to_address",
                            value=reply_to_addr,
                        ),
                    ],
                    limitation="Support ticketing platforms or marketing campaigns occasionally utilize separate reply collection endpoints.",
                    mitre_attack_ids=["T1566.002"],
                ))

        # 4. Authentication Failure on Claimed Identity
        if name_outcome in (ComparisonOutcomeEnum.MATCH, ComparisonOutcomeEnum.PARTIAL_MATCH) and dom_outcome != ComparisonOutcomeEnum.MATCH:
            if dmarc_res in ("fail", "none") or spf_res in ("fail", "softfail"):
                supporting.append(ImpersonationFinding(
                    finding_type="UNAUTHORIZED_SENDER_DOMAIN",
                    title=f"Unauthenticated Sending Infrastructure for '{profile.display_name}'",
                    description=f"Message claiming '{profile.display_name}' failed domain authorization (DMARC: {dmarc_res or 'none'}, SPF: {spf_res or 'none'}).",
                    severity=SeverityEnum.MEDIUM,
                    confidence=0.88,
                    risk_contribution=20.0,
                    rule_id="IMP_SND_001",
                    category=IdentityEvidenceCategoryEnum.AUTHENTICATION_IDENTITY,
                    target_identity_id=profile.id,
                    target_identity_name=profile.display_name,
                    evidence_items=[
                        ImpersonationFindingEvidence(
                            category=IdentityEvidenceCategoryEnum.AUTHENTICATION_IDENTITY,
                            source="AuthenticationResults",
                            key="dmarc_spf_evaluation",
                            value=f"DMARC: {dmarc_res}, SPF: {spf_res}",
                        )
                    ],
                    limitation="Missing DMARC records on third-party senders do not definitively establish attacker infrastructure.",
                ))

    def _evaluate_domain_impersonation(
        self,
        email_data: Optional[Dict[str, Any]],
        url_data: Optional[Dict[str, Any]],
        profile: ProtectedIdentityProfile,
        supporting: List[ImpersonationFinding],
        contradicting: List[ImpersonationFinding],
        limitations: List[str],
    ):
        observed_domains: Set[str] = set()
        if email_data:
            if email_data.get("from_domain"):
                observed_domains.add(email_data["from_domain"])
            if email_data.get("reply_to_domain"):
                observed_domains.add(email_data["reply_to_domain"])
        if url_data:
            raw_url = url_data.get("url") or ""
            if raw_url:
                try:
                    p = urlsplit(raw_url if "://" in raw_url else f"http://{raw_url}")
                    if p.netloc:
                        observed_domains.add(p.netloc.split(":")[0])
                except Exception:
                    pass

        for dom in observed_domains:
            outcome, info = self.comparison_service.compare_domain(dom, profile)

            if outcome == ComparisonOutcomeEnum.LOOKALIKE:
                tech = info.get("technique", "lookalike")

                if tech == "deceptive_subdomain":
                    supporting.append(ImpersonationFinding(
                        finding_type="DECEPTIVE_BRAND_SUBDOMAIN",
                        title=f"Deceptive Subdomain Hierarchy Targeting '{profile.display_name}'",
                        description=(
                            f"Domain '{dom}' deceptively embeds protected brand '{profile.display_name}' "
                            f"as a subdomain prefix before registrable domain '{info.get('registrable_domain')}'."
                        ),
                        severity=SeverityEnum.HIGH,
                        confidence=0.94,
                        risk_contribution=35.0,
                        rule_id="IMP_SUB_001",
                        category=IdentityEvidenceCategoryEnum.DOMAIN_IDENTITY,
                        target_identity_id=profile.id,
                        target_identity_name=profile.display_name,
                        evidence_items=[
                            ImpersonationFindingEvidence(
                                category=IdentityEvidenceCategoryEnum.DOMAIN_IDENTITY,
                                source="URLDecomposition",
                                key="observed_hostname",
                                value=dom,
                            ),
                            ImpersonationFindingEvidence(
                                category=IdentityEvidenceCategoryEnum.DOMAIN_IDENTITY,
                                source="URLDecomposition",
                                key="subdomain_trick",
                                value=f"Subdomain: {info.get('subdomain')} on Base: {info.get('registrable_domain')}",
                            )
                        ],
                        limitation="Multi-tenant cloud architectures or proxy gateways occasionally host customer subdomains legitimately.",
                        mitre_attack_ids=["T1566.002"],
                    ))

                elif tech == "unicode_homoglyphs":
                    supporting.append(ImpersonationFinding(
                        finding_type="HOMOGLYPH_IMPERSONATION_SIGNAL",
                        title=f"Homoglyph/IDN Visual Spoofing Targeting '{profile.display_name}'",
                        description=(
                            f"Domain '{dom}' uses visually deceptive homoglyphs "
                            f"to imitate authentic domain '{info.get('targeted_brand_domain')}'."
                        ),
                        severity=SeverityEnum.HIGH,
                        confidence=0.96,
                        risk_contribution=40.0,
                        rule_id="IMP_HOM_001",
                        category=IdentityEvidenceCategoryEnum.DOMAIN_IDENTITY,
                        target_identity_id=profile.id,
                        target_identity_name=profile.display_name,
                        evidence_items=[
                            ImpersonationFindingEvidence(
                                category=IdentityEvidenceCategoryEnum.DOMAIN_IDENTITY,
                                source="LookalikeDetectorService",
                                key="observed_domain",
                                value=dom,
                            ),
                            ImpersonationFindingEvidence(
                                category=IdentityEvidenceCategoryEnum.DOMAIN_IDENTITY,
                                source="LookalikeDetectorService",
                                key="normalized_equivalent",
                                value=info.get("normalized_domain", ""),
                            )
                        ],
                        limitation="Internationalized domain names legitimately represent non-Latin languages and alphabets.",
                        mitre_attack_ids=["T1566.002"],
                    ))

                else:
                    supporting.append(ImpersonationFinding(
                        finding_type="DOMAIN_IMPERSONATION_SIGNAL",
                        title=f"Lookalike Domain Targeting '{profile.display_name}' ({dom})",
                        description=(
                            f"Domain '{dom}' exhibits high typosquatting similarity ({info.get('similarity', 0.85):.2f}) "
                            f"targeting authentic reference domain '{info.get('targeted_brand_domain')}'."
                        ),
                        severity=SeverityEnum.HIGH,
                        confidence=0.92,
                        risk_contribution=30.0,
                        rule_id="IMP_DOM_001",
                        category=IdentityEvidenceCategoryEnum.DOMAIN_IDENTITY,
                        target_identity_id=profile.id,
                        target_identity_name=profile.display_name,
                        evidence_items=[
                            ImpersonationFindingEvidence(
                                category=IdentityEvidenceCategoryEnum.DOMAIN_IDENTITY,
                                source="LookalikeDetectorService",
                                key="observed_domain",
                                value=dom,
                            ),
                            ImpersonationFindingEvidence(
                                category=IdentityEvidenceCategoryEnum.DOMAIN_IDENTITY,
                                source="LookalikeDetectorService",
                                key="edit_distance",
                                value=str(info.get("edit_distance", 1)),
                            )
                        ],
                        limitation="Coincidental domain phonetic overlap can occur between independent business entities.",
                        mitre_attack_ids=["T1566.002"],
                    ))

    def _evaluate_website_impersonation(
        self,
        website_data: Optional[Dict[str, Any]],
        profile: ProtectedIdentityProfile,
        supporting: List[ImpersonationFinding],
        contradicting: List[ImpersonationFinding],
        limitations: List[str],
    ):
        if not website_data:
            return

        title = website_data.get("title") or ""
        url = website_data.get("url") or ""
        base_dom = website_data.get("base_domain") or ""
        has_login = website_data.get("has_login_form", False)
        has_password = website_data.get("has_password_field", False)
        has_cross_domain = website_data.get("has_cross_domain_form", False)

        dom_outcome, dom_info = self.comparison_service.compare_domain(base_dom, profile)

        # Contradicting: Authentic website
        if dom_outcome == ComparisonOutcomeEnum.MATCH:
            contradicting.append(ImpersonationFinding(
                finding_type="AUTHENTIC_WEBSITE_DESTINATION",
                title=f"Web Content Hosted on Official {profile.display_name} Domain",
                description=f"Destination '{base_dom}' is a verified authoritative domain for '{profile.display_name}'.",
                severity=SeverityEnum.SAFE,
                confidence=1.0,
                category=IdentityEvidenceCategoryEnum.WEBSITE_IDENTITY,
                rule_id="IMP_WEB_LEGIT_001",
                target_identity_id=profile.id,
                target_identity_name=profile.display_name,
                evidence_items=[
                    ImpersonationFindingEvidence(
                        category=IdentityEvidenceCategoryEnum.WEBSITE_IDENTITY,
                        source="WebsiteInspector",
                        key="base_domain",
                        value=base_dom,
                        is_contradicting=True,
                    )
                ],
                limitation="Does not preclude open-redirect abuse or user-generated content hosting.",
            ))
            return

        # Check if Title claims the protected brand/organization
        title_claims_brand = False
        clean_title = title.lower()
        if profile.display_name.lower() in clean_title:
            title_claims_brand = True
        else:
            for kn in profile.known_names:
                if len(kn) >= 3 and kn.lower() in clean_title:
                    title_claims_brand = True
                    break

        if title_claims_brand:
            supporting.append(ImpersonationFinding(
                finding_type="WEBSITE_BRAND_CLAIM",
                title=f"Website Page Title Claims '{profile.display_name}'",
                description=f"Web page title '{title}' claims to represent '{profile.display_name}', but is hosted on '{base_dom}'.",
                severity=SeverityEnum.MEDIUM,
                confidence=0.88,
                risk_contribution=20.0,
                rule_id="IMP_WEB_001",
                category=IdentityEvidenceCategoryEnum.WEBSITE_IDENTITY,
                target_identity_id=profile.id,
                target_identity_name=profile.display_name,
                evidence_items=[
                    ImpersonationFindingEvidence(
                        category=IdentityEvidenceCategoryEnum.WEBSITE_IDENTITY,
                        source="WebsiteInspector",
                        key="page_title",
                        value=title,
                    ),
                    ImpersonationFindingEvidence(
                        category=IdentityEvidenceCategoryEnum.WEBSITE_IDENTITY,
                        source="WebsiteInspector",
                        key="untrusted_host",
                        value=base_dom,
                    ),
                ],
                limitation="News articles, review sites, or partner portals legitimately reference third-party brands in page titles.",
            ))

            if dom_outcome in (ComparisonOutcomeEnum.MISMATCH, ComparisonOutcomeEnum.LOOKALIKE):
                supporting.append(ImpersonationFinding(
                    finding_type="WEBSITE_IDENTITY_MISMATCH",
                    title=f"Website Hosting Domain Conflicts with '{profile.display_name}'",
                    description=f"Website asserting '{profile.display_name}' identity is hosted on untrusted infrastructure '{base_dom}'.",
                    severity=SeverityEnum.HIGH,
                    confidence=0.92,
                    risk_contribution=30.0,
                    rule_id="IMP_WEB_002",
                    category=IdentityEvidenceCategoryEnum.WEBSITE_IDENTITY,
                    target_identity_id=profile.id,
                    target_identity_name=profile.display_name,
                    evidence_items=[
                        ImpersonationFindingEvidence(
                            category=IdentityEvidenceCategoryEnum.WEBSITE_IDENTITY,
                            source="WebsiteInspector",
                            key="host_domain",
                            value=base_dom,
                        )
                    ],
                    limitation="Legitimate brand affiliates or resellers may operate websites without formal domain inclusion.",
                ))

            # Severe: Fake login portal / Credential harvesting
            if has_login or has_password:
                supporting.append(ImpersonationFinding(
                    finding_type="CREDENTIAL_HARVESTING_IMPERSONATION_SUSPECTED",
                    title=f"Credential Harvesting Portal Impersonating '{profile.display_name}'",
                    description=(
                        f"Untrusted page on '{base_dom}' claiming to represent '{profile.display_name}' "
                        f"presents a credential authentication form with password input fields."
                    ),
                    severity=SeverityEnum.CRITICAL,
                    confidence=0.95,
                    risk_contribution=45.0,
                    rule_id="IMP_HARV_001",
                    category=IdentityEvidenceCategoryEnum.WEBSITE_IDENTITY,
                    target_identity_id=profile.id,
                    target_identity_name=profile.display_name,
                    evidence_items=[
                        ImpersonationFindingEvidence(
                            category=IdentityEvidenceCategoryEnum.WEBSITE_IDENTITY,
                            source="WebsiteInspector",
                            key="login_form_detected",
                            value=f"has_password: {has_password}, cross_domain: {has_cross_domain}",
                        )
                    ],
                    limitation="Custom enterprise single-sign-on deployments may use dedicated third-party identity provider domains.",
                    mitre_attack_ids=["T1566.002", "T1056"],
                ))

    def _evaluate_executive_authority_impersonation(
        self,
        email_data: Optional[Dict[str, Any]],
        claims: List[IdentityClaim],
        profile: ProtectedIdentityProfile,
        supporting: List[ImpersonationFinding],
        contradicting: List[ImpersonationFinding],
        limitations: List[str],
        db: Optional[Session] = None,
    ):
        if not email_data:
            return

        from_disp = email_data.get("from_display_name") or ""
        from_dom = (email_data.get("from_domain") or "").lower().strip()
        from_addr = email_data.get("from_address") or ""
        subject = email_data.get("subject") or ""
        body_text = email_data.get("body_text") or email_data.get("plain_text_body") or ""

        # Check if From display name matches a configured executive
        exec_match = self.identity_manager.find_by_executive_name(from_disp, db=db)
        if exec_match:
            exec_profile, exec_info = exec_match
            exec_name = exec_info.get("name")
            exec_role = exec_info.get("role", "Executive")
            exec_email = exec_info.get("email", "")

            # If sender address is NOT the executive's authoritative address
            if from_addr.lower() != exec_email.lower():
                supporting.append(ImpersonationFinding(
                    finding_type="EXECUTIVE_IMPERSONATION_SUSPECTED",
                    title=f"Executive Impersonation Targeting '{exec_name}' ({exec_role})",
                    description=(
                        f"Display name matches configured {exec_profile.display_name} executive '{exec_name}' ({exec_role}), "
                        f"but email originated from unauthorized address '{from_addr}' (expected '{exec_email}')."
                    ),
                    severity=SeverityEnum.CRITICAL,
                    confidence=0.95,
                    risk_contribution=45.0,
                    rule_id="IMP_EXEC_001",
                    category=IdentityEvidenceCategoryEnum.NAME_IDENTITY,
                    target_identity_id=exec_profile.id,
                    target_identity_name=exec_profile.display_name,
                    evidence_items=[
                        ImpersonationFindingEvidence(
                            category=IdentityEvidenceCategoryEnum.NAME_IDENTITY,
                            source="ProtectedExecutiveDirectory",
                            key="executive_name",
                            value=f"{exec_name} ({exec_role})",
                        ),
                        ImpersonationFindingEvidence(
                            category=IdentityEvidenceCategoryEnum.EMAIL_IDENTITY,
                            source="EmailHeader",
                            key="actual_sender",
                            value=from_addr,
                        ),
                    ],
                    limitation="Executives occasionally use personal mobile devices or external accounts during travel emergencies.",
                    mitre_attack_ids=["T1566.002", "T1656"],
                ))

                # Check for BEC / Financial Transfer intent
                combined_content = f"{subject}\n{body_text}".lower()
                financial_keywords = ["wire transfer", "payment", "bank transfer", "invoice", "gift card", "urgent payment", "remittance"]
                has_financial = any(fk in combined_content for fk in financial_keywords)

                if has_financial:
                    supporting.append(ImpersonationFinding(
                        finding_type="BUSINESS_EMAIL_IMPERSONATION_SUSPECTED",
                        title=f"Business Email Compromise (BEC) Intent Targeting {exec_name}",
                        description=(
                            f"Executive impersonation of '{exec_name}' is combined with financial or payment urgency "
                            f"demands, indicating a targeted Business Email Compromise pattern."
                        ),
                        severity=SeverityEnum.CRITICAL,
                        confidence=0.96,
                        risk_contribution=50.0,
                        rule_id="IMP_BEC_001",
                        category=IdentityEvidenceCategoryEnum.CONTENT_CONTEXT,
                        target_identity_id=exec_profile.id,
                        target_identity_name=exec_profile.display_name,
                        evidence_items=[
                            ImpersonationFindingEvidence(
                                category=IdentityEvidenceCategoryEnum.CONTENT_CONTEXT,
                                source="EmailContent",
                                key="financial_urgency_detected",
                                value="Financial keywords identified in message body",
                            )
                        ],
                        limitation="CyberGuard identifies communication patterns; it does not authorize or block bank transfers.",
                        mitre_attack_ids=["T1566.002", "T1656"],
                    ))

        # Check for generic authority claims (e.g. "IT Support - Action Required")
        for c in claims:
            if c.claim_type == IdentityClaimTypeEnum.ROLE:
                # If role claimed, but sender domain does not match any trusted domain
                dom_outcome, _ = self.comparison_service.compare_domain(from_dom, profile)
                if dom_outcome != ComparisonOutcomeEnum.MATCH:
                    supporting.append(ImpersonationFinding(
                        finding_type="AUTHORITY_IMPERSONATION_SIGNAL",
                        title=f"Internal Authority Role Impersonation ('{c.claimed_role}')",
                        description=(
                            f"Message claims internal authority role '{c.claimed_role}', "
                            f"but originates from untrusted domain '{from_dom}'."
                        ),
                        severity=SeverityEnum.MEDIUM,
                        confidence=0.85,
                        risk_contribution=20.0,
                        rule_id="IMP_AUTH_001",
                        category=IdentityEvidenceCategoryEnum.NAME_IDENTITY,
                        target_identity_id=profile.id,
                        target_identity_name=profile.display_name,
                        evidence_items=[
                            ImpersonationFindingEvidence(
                                category=IdentityEvidenceCategoryEnum.NAME_IDENTITY,
                                source="EmailContent",
                                key="claimed_role",
                                value=c.claimed_role or "Authority",
                            )
                        ],
                        limitation="External vendors or contracting partners frequently operate authorized support services on separate domains.",
                        mitre_attack_ids=["T1656"],
                    ))

    # ------------------------------------------------------------------------
    # Aggregator & Synthesis
    # ------------------------------------------------------------------------

    def _synthesize_assessment(
        self,
        target_profile: Optional[ProtectedIdentityProfile],
        claims: List[IdentityClaim],
        supporting: List[ImpersonationFinding],
        contradicting: List[ImpersonationFinding],
        limitations: List[str],
        profiles_used: Dict[str, int],
    ) -> ImpersonationAssessment:
        """
        Synthesizes overall impersonation assessment preserving epistemic modesty.
        """
        # Baseline score calculation
        total_risk = sum(f.risk_contribution for f in supporting)
        # Contradicting evidence discount
        if contradicting:
            total_risk = max(0.0, total_risk * 0.2)

        risk_score = min(100.0, round(total_risk, 1))

        # Scoped classification
        classification: ImpersonationClassificationEnum
        summary: str

        if not target_profile:
            if claims:
                classification = ImpersonationClassificationEnum.INSUFFICIENT_EVIDENCE
                summary = "Identity claims were observed in content, but no authoritative reference profile was matched."
            else:
                classification = ImpersonationClassificationEnum.NO_IMPERSONATION_EVIDENCE
                summary = "No identity claims or impersonation patterns were observed."
            confidence = 0.5 if claims else 1.0

        elif contradicting and not supporting:
            classification = ImpersonationClassificationEnum.NO_IMPERSONATION_EVIDENCE
            summary = f"Telemetry verified against authoritative reference identity for '{target_profile.display_name}'."
            confidence = 0.98

        elif any(f.finding_type in ("CREDENTIAL_HARVESTING_IMPERSONATION_SUSPECTED", "EXECUTIVE_IMPERSONATION_SUSPECTED", "BUSINESS_EMAIL_IMPERSONATION_SUSPECTED", "HOMOGLYPH_IMPERSONATION_SIGNAL") for f in supporting):
            classification = ImpersonationClassificationEnum.STRONG_IMPERSONATION_INDICATORS
            summary = f"Strong multi-vector digital impersonation indicators targeting '{target_profile.display_name}'."
            confidence = 0.94

        elif supporting:
            classification = ImpersonationClassificationEnum.IMPERSONATION_SUSPECTED
            summary = f"Possible digital impersonation patterns observed targeting '{target_profile.display_name}'."
            confidence = 0.88

        else:
            classification = ImpersonationClassificationEnum.NO_IMPERSONATION_EVIDENCE
            summary = f"No deceptive discrepancies identified against reference identity '{target_profile.display_name}'."
            confidence = 0.95

        # Explicit limitations
        limitations.append("Absence of impersonation does not establish that communication is benign (e.g. compromised legitimate accounts).")
        limitations.append("Conclusions are evidence-based hypotheses, not definitive legal brand attribution.")

        return ImpersonationAssessment(
            classification=classification,
            confidence=confidence,
            risk_score=risk_score,
            target_identity=target_profile.display_name if target_profile else None,
            target_identity_id=target_profile.id if target_profile else None,
            claims=claims,
            supporting_findings=supporting,
            contradicting_findings=contradicting,
            limitations=limitations,
            summary=summary,
            profile_revisions_used=profiles_used,
        )

    # ------------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------------

    def _persist_results(
        self,
        run_id: str,
        artifact_id: Optional[str],
        assessment: ImpersonationAssessment,
        target_profile: Optional[ProtectedIdentityProfile],
        email_data: Optional[Dict[str, Any]],
        url_data: Optional[Dict[str, Any]],
        website_data: Optional[Dict[str, Any]],
        trigger: AnalysisTriggerEnum,
        db: Session,
        entities_created: List[str],
        relationships_created: List[str],
        threat_events_created: List[str],
    ):
        """Persists AnalysisRun, Findings, Evidence, Entities, Relationships, and ThreatEvents."""
        try:
            # 1. Create AnalysisRun record if artifact_id exists
            if artifact_id:
                run = AnalysisRunModel(
                    id=run_id,
                    artifact_id=artifact_id,
                    status=AnalysisStatusEnum.COMPLETED.value,
                    started_at=get_utc_now(),
                    completed_at=get_utc_now(),
                    trigger=trigger.value,
                    pipeline_version=self.PIPELINE_VERSION,
                    overall_risk_score=assessment.risk_score,
                    overall_severity=SeverityEnum.CRITICAL.value if assessment.risk_score >= 80 else (
                        SeverityEnum.HIGH.value if assessment.risk_score >= 50 else (
                            SeverityEnum.MEDIUM.value if assessment.risk_score >= 25 else SeverityEnum.SAFE.value
                        )
                    ),
                    confidence=assessment.confidence,
                    metadata_json=json.dumps({
                        "analyzer_name": "digital_impersonation_analyzer",
                        "classification": assessment.classification.value,
                        "target_identity": assessment.target_identity,
                        "supporting_count": len(assessment.supporting_findings),
                        "contradicting_count": len(assessment.contradicting_findings),
                        "profiles_used": assessment.profile_revisions_used,
                    }),
                )
                db.add(run)
                db.flush()

            # 2. Findings and Evidence
            all_findings = assessment.supporting_findings + assessment.contradicting_findings
            for f in all_findings:
                fid = generate_uuid()
                f_model = FindingModel(
                    id=fid,
                    analysis_run_id=run_id if artifact_id else None,
                    analyzer="digital_impersonation_analyzer",
                    finding_type=f.finding_type,
                    title=f.title,
                    description=f.description,
                    severity=f.severity.value,
                    confidence=f.confidence,
                    risk_contribution=f.risk_contribution,
                    method="DETERMINISTIC",
                    rule_id=f.rule_id,
                    metadata_json=json.dumps({
                        "category": f.category.value,
                        "rule_version": f.rule_version,
                        "target_identity": f.target_identity_name,
                        "limitation": f.limitation,
                        "mitre_attack_ids": f.mitre_attack_ids,
                    }),
                )
                db.add(f_model)

                for ev in f.evidence_items:
                    ev_model = FindingEvidenceModel(
                        id=generate_uuid(),
                        finding_id=fid,
                        evidence_type="IMPERSONATION_EVIDENCE",
                        source=ev.source,
                        key=ev.key,
                        value=ev.value,
                        confidence=ev.confidence,
                        artifact_id=artifact_id,
                        metadata_json=json.dumps({
                            "category": ev.category.value,
                            "is_contradicting": ev.is_contradicting,
                            "notes": ev.notes,
                        }),
                    )
                    db.add(ev_model)

            # 3. Security Graph Entities & Relationships
            if target_profile:
                # Entity for the authentic reference organization
                ref_ent = EntityModel(
                    id=generate_uuid(),
                    entity_type=EntityTypeEnum.ORGANIZATION.value,
                    name=target_profile.display_name,
                    external_id=target_profile.id,
                    attributes_json=json.dumps({
                        "source": target_profile.source.value,
                        "trusted_domains": target_profile.trusted_domains,
                        "is_reference_identity": True,
                    }),
                )
                db.add(ref_ent)
                entities_created.append(ref_ent.id)

                # If artifact claims this identity, link ARTIFACT -> CLAIMS_IDENTITY -> ENTITY
                if artifact_id:
                    rel_claims = RelationshipModel(
                        id=generate_uuid(),
                        source_type="ARTIFACT",
                        source_id=artifact_id,
                        relationship_type="CLAIMS_IDENTITY",
                        target_type="ENTITY",
                        target_id=ref_ent.id,
                        confidence=0.90,
                        metadata_json=json.dumps({"target_identity": target_profile.display_name}),
                    )
                    db.add(rel_claims)
                    relationships_created.append(rel_claims.id)

                    rel_targets = RelationshipModel(
                        id=generate_uuid(),
                        source_type="ARTIFACT",
                        source_id=artifact_id,
                        relationship_type="TARGETS",
                        target_type="ENTITY",
                        target_id=ref_ent.id,
                        confidence=0.88,
                        metadata_json=json.dumps({"classification": assessment.classification.value}),
                    )
                    db.add(rel_targets)
                    relationships_created.append(rel_targets.id)

            # 4. ThreatEvents
            if assessment.classification in (
                ImpersonationClassificationEnum.IMPERSONATION_SUSPECTED,
                ImpersonationClassificationEnum.STRONG_IMPERSONATION_INDICATORS,
            ):
                event_type = "DIGITAL_IMPERSONATION_SUSPECTED"
                if any(f.finding_type == "CREDENTIAL_HARVESTING_IMPERSONATION_SUSPECTED" for f in assessment.supporting_findings):
                    event_type = "CREDENTIAL_HARVESTING_IMPERSONATION_SUSPECTED"
                elif any(f.finding_type in ("EXECUTIVE_IMPERSONATION_SUSPECTED", "BUSINESS_EMAIL_IMPERSONATION_SUSPECTED") for f in assessment.supporting_findings):
                    event_type = "EXECUTIVE_IMPERSONATION_SUSPECTED"
                elif target_profile and target_profile.entity_type in (IdentityClaimTypeEnum.ORGANIZATION, IdentityClaimTypeEnum.BRAND):
                    event_type = "BRAND_IMPERSONATION_SUSPECTED"

                te = ThreatEventModel(
                    id=generate_uuid(),
                    event_type=event_type,
                    source_artifact_id=artifact_id,
                    analysis_run_id=run_id if artifact_id else None,
                    severity="CRITICAL" if assessment.risk_score >= 80 else "HIGH",
                    risk_score=assessment.risk_score,
                    confidence=assessment.confidence,
                    status="OPEN",
                    summary=assessment.summary,
                    metadata_json=json.dumps({
                        "classification": assessment.classification.value,
                        "target_identity": assessment.target_identity,
                        "supporting_findings_count": len(assessment.supporting_findings),
                        "contradicting_findings_count": len(assessment.contradicting_findings),
                    }),
                )
                db.add(te)
                threat_events_created.append(te.id)

            db.commit()

        except Exception as e:
            logger.error(f"Error persisting impersonation analysis: {e}", exc_info=True)
            db.rollback()


global_impersonation_pipeline = DigitalImpersonationPipeline()
