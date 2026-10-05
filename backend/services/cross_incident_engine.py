"""
Section 15: Cross-Incident Pattern Detection & Campaign Correlation Engine.
Identifies recurring patterns across otherwise separate CyberGuard investigations.
Strictly preserves: OBSERVATION != RELATIONSHIP != CORRELATION != CAUSATION.
Never claims 'same threat actor'; reports explainable cross-incident similarity.
"""
import hashlib
import ipaddress
import json
import logging
import math
import re
import uuid
from collections import Counter, defaultdict
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Set, Optional, Any, Tuple

from sqlalchemy.orm import Session
from sqlalchemy import or_, and_, desc

from backend.db.models import (
    IncidentModel,
    IncidentCorrelationModel,
    CampaignModel,
    CampaignIncidentModel,
    ThreatEventModel,
    ArtifactModel,
    AuditLogModel,
    EntityModel,
    RelationshipModel,
)
from backend.schemas.cross_incident import (
    CorrelationFeatureCategory,
    IndicatorSpecificity,
    CorrelationEvidenceItem,
    ContradictingEvidenceItem,
    FeatureBreakdown,
    IncidentCorrelationProfile,
    IncidentCorrelationResult,
    CampaignCandidateResponse,
    RelatedIncidentItem,
    CrossIncidentSearchResponse,
)
from backend.schemas.knowledge_graph import (
    GraphEntityType,
    GraphRelationshipType,
    RelationshipOrigin,
    RelationshipStatus,
    make_canonical_key,
)
from backend.services.security_graph_service import SecurityGraphService

logger = logging.getLogger("cyberguard.cross_incident")


# -----------------------------------------------------------------------------
# Engine Versions & Configurable Category Weights
# -----------------------------------------------------------------------------

ENGINE_VERSION = "2.0.0"
CONFIG_VERSION = "2.0.0"

DEFAULT_CATEGORY_WEIGHTS: Dict[str, float] = {
    CorrelationFeatureCategory.INFRASTRUCTURE.value: 0.35,
    CorrelationFeatureCategory.ARTIFACT.value: 0.35,
    CorrelationFeatureCategory.IDENTITY.value: 0.10,
    CorrelationFeatureCategory.CONTENT.value: 0.10,
    CorrelationFeatureCategory.BEHAVIOR.value: 0.03,
    CorrelationFeatureCategory.TACTIC.value: 0.02,
    CorrelationFeatureCategory.TEMPORAL.value: 0.05,
    CorrelationFeatureCategory.TARGETING.value: 0.02,
}

# Correlation Thresholds
CANDIDATE_CORRELATION_THRESHOLD = 0.40
CAMPAIGN_CLUSTER_THRESHOLD = 0.55
HIGH_SIMILARITY_THRESHOLD = 0.70
MODERATE_SIMILARITY_THRESHOLD = 0.45
WEAK_SIMILARITY_THRESHOLD = 0.20

# False-Positive Control & Suppression Sets
COMMON_PUBLIC_RESOLVERS = {
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
    "9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220",
    "127.0.0.1", "0.0.0.0", "::1"
}

COMMON_CDN_IPS = {
    "104.16.0.1", "104.16.0.2", "104.21.0.1", "104.21.0.2",  # Cloudflare
    "151.101.1.1", "151.101.65.1",                             # Fastly
    "23.235.32.1", "23.235.33.1",                              # Fastly
}

COMMON_CLOUD_ASNS = {
    "AS13335",  # Cloudflare
    "AS16509",  # Amazon AWS
    "AS14618",  # Amazon AWS
    "AS8075",   # Microsoft
    "AS15169",  # Google
    "AS54113",  # Fastly
    "AS16625",  # Akamai
    "AS11377",  # SendGrid / Twilio
    "AS14782",  # Mailchimp
    "AS36351",  # SoftLayer
    "AS14061",  # DigitalOcean
}

COMMON_WEBMAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.uk",
    "outlook.com", "hotmail.com", "live.com", "msn.com",
    "aol.com", "icloud.com", "me.com", "mac.com",
    "mail.com", "protonmail.com", "proton.me", "zoho.com",
    "yandex.com", "gmx.com", "fastmail.com"
}

COMMON_CLOUD_DOMAINS = {
    "google.com", "microsoft.com", "apple.com", "amazon.com",
    "amazonaws.com", "cloudflare.com", "akamai.com", "azure.com",
    "office365.com", "sendgrid.net", "mailchimp.com", "github.com"
}

GENERIC_URL_PATHS = {
    "/", "/login", "/login.php", "/login.html", "/auth", "/verify",
    "/account", "/signin", "/index.html", "/index.php", "/home"
}

EMPTY_FILE_HASHES = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "d41d8cd98f00b204e9800998ecf8427e",
    "da39a3ee5e6b4b0d3255bfef95601890afd80709",
}


# -----------------------------------------------------------------------------
# SimHash and Text Processing Utilities
# -----------------------------------------------------------------------------

def compute_simhash(tokens: List[str], hash_bits: int = 64) -> int:
    """Computes a 64-bit SimHash vector fingerprint from tokenized features."""
    if not tokens:
        return 0
    v = [0] * hash_bits
    for token in tokens:
        token_hash = int(hashlib.md5(token.encode("utf-8")).hexdigest()[:16], 16)
        for i in range(hash_bits):
            bitmask = 1 << i
            if token_hash & bitmask:
                v[i] += 1
            else:
                v[i] -= 1
    fingerprint = 0
    for i in range(hash_bits):
        if v[i] > 0:
            fingerprint |= (1 << i)
    return fingerprint


def simhash_similarity(h1: int, h2: int, hash_bits: int = 64) -> float:
    """Computes Hamming distance-based similarity (0.0 to 1.0) between two SimHashes."""
    if h1 == 0 or h2 == 0:
        return 0.0
    x = (h1 ^ h2) & ((1 << hash_bits) - 1)
    dist = bin(x).count("1")
    return max(0.0, 1.0 - (dist / hash_bits))


def normalize_message_template(text: str) -> str:
    """
    Normalizes variable tokens (numbers, hex strings, timestamps)
    to generate an explainable template string.
    """
    if not text:
        return ""
    s = text.lower()
    # Replace UUIDs
    s = re.sub(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', '<UUID>', s)
    # Replace hex tokens
    s = re.sub(r'\b[0-9a-f]{16,64}\b', '<HEX>', s)
    # Replace numbers/amounts
    s = re.sub(r'\b\d+[\d,.]*\b', '<NUM>', s)
    # Replace email addresses
    s = re.sub(r'[\w\.-]+@[\w\.-]+\.\w+', '<EMAIL>', s)
    # Normalize whitespaces
    return " ".join(s.split())


# -----------------------------------------------------------------------------
# Prevalence & Specificity Service
# -----------------------------------------------------------------------------

class PrevalenceTracker:
    """
    Tracks indicator occurrences across incidents within a workspace
    to compute inverse prevalence weights and indicator specificity.
    """

    def __init__(self):
        # (workspace_id, indicator_key) -> count of distinct incidents
        self._counts: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self._initialized_workspaces: Set[str] = set()

    def build_index_for_workspace(self, workspace_id: str, db: Session) -> None:
        """Counts entity occurrences across all incidents in the workspace."""
        self._counts[workspace_id].clear()
        entities = db.query(EntityModel).filter(
            or_(EntityModel.workspace_id == workspace_id, EntityModel.workspace_id == "default")
        ).all()
        for ent in entities:
            # Check distinct incidents referencing this entity in relationships
            rels = db.query(RelationshipModel).filter(
                or_(RelationshipModel.source_id == ent.id, RelationshipModel.target_id == ent.id)
            ).all()
            incident_ids = set()
            for r in rels:
                if r.relationship_type == GraphRelationshipType.OBSERVED_IN.value:
                    incident_ids.add(r.target_id if r.source_id == ent.id else r.source_id)
            if incident_ids:
                self._counts[workspace_id][ent.canonical_key] = len(incident_ids)
        self._initialized_workspaces.add(workspace_id)

    def get_prevalence(self, indicator_key: str, workspace_id: str, db: Session) -> int:
        if workspace_id not in self._initialized_workspaces:
            self.build_index_for_workspace(workspace_id, db)
        return self._counts[workspace_id].get(indicator_key, 1)

    def classify_specificity(
        self,
        indicator_type: str,
        value: str,
        workspace_id: str,
        db: Session
    ) -> Tuple[IndicatorSpecificity, float]:
        """
        Returns (IndicatorSpecificity, base_weight) based on indicator nature and prevalence.
        """
        val_clean = value.strip().lower()

        # 1. Hashes
        if indicator_type == "hash":
            if val_clean in EMPTY_FILE_HASHES:
                return IndicatorSpecificity.LOW, 0.01
            return IndicatorSpecificity.HIGH, 0.35

        # 2. URLs
        if indicator_type == "url":
            # Check for generic path
            for gp in GENERIC_URL_PATHS:
                if val_clean.endswith(gp):
                    return IndicatorSpecificity.MEDIUM, 0.15
            return IndicatorSpecificity.HIGH, 0.30

        # 3. Domains
        if indicator_type == "domain":
            if val_clean in COMMON_WEBMAIL_DOMAINS or val_clean in COMMON_CLOUD_DOMAINS:
                return IndicatorSpecificity.LOW, 0.02
            prev = self.get_prevalence(val_clean, workspace_id, db)
            if prev <= 3:
                return IndicatorSpecificity.HIGH, 0.28
            elif prev <= 10:
                return IndicatorSpecificity.MEDIUM, 0.18
            else:
                return IndicatorSpecificity.LOW, 0.05

        # 4. IPs
        if indicator_type == "ip":
            if val_clean in COMMON_PUBLIC_RESOLVERS or val_clean in COMMON_CDN_IPS:
                return IndicatorSpecificity.LOW, 0.02
            try:
                addr = ipaddress.ip_address(val_clean)
                if addr.is_private or addr.is_loopback:
                    return IndicatorSpecificity.LOW, 0.01
            except ValueError:
                return IndicatorSpecificity.LOW, 0.01

            prev = self.get_prevalence(val_clean, workspace_id, db)
            if prev <= 3:
                return IndicatorSpecificity.MEDIUM, 0.20
            else:
                return IndicatorSpecificity.LOW, 0.05

        # 5. Protected Identities
        if indicator_type == "identity":
            return IndicatorSpecificity.MEDIUM, 0.08

        # 6. Template
        if indicator_type == "template":
            return IndicatorSpecificity.MEDIUM, 0.15

        return IndicatorSpecificity.LOW, 0.05


# Global prevalence tracker
prevalence_tracker = PrevalenceTracker()


# -----------------------------------------------------------------------------
# Main Cross-Incident Correlation Engine
# -----------------------------------------------------------------------------

class CrossIncidentCorrelationEngine:
    """
    Core engine for Section 15.
    Computes profile extractions, inverted candidate generation,
    pairwise evidence weighing (supporting vs. contradicting),
    and graph-based campaign clustering.
    """

    def __init__(
        self,
        category_weights: Optional[Dict[str, float]] = None,
        candidate_threshold: float = CANDIDATE_CORRELATION_THRESHOLD,
        campaign_threshold: float = CAMPAIGN_CLUSTER_THRESHOLD,
    ):
        self.category_weights = dict(DEFAULT_CATEGORY_WEIGHTS)
        if category_weights:
            self.category_weights.update(category_weights)
        self.candidate_threshold = candidate_threshold
        self.campaign_threshold = campaign_threshold
        self.graph_service = SecurityGraphService()

    # -------------------------------------------------------------------------
    # 1. Profile Extraction
    # -------------------------------------------------------------------------

    def extract_incident_profile(
        self,
        incident: IncidentModel,
        db: Session
    ) -> IncidentCorrelationProfile:
        """
        Derives an IncidentCorrelationProfile from normalized incident records,
        threat events, and the Security Knowledge Graph.
        Does NOT re-parse raw files or artifacts.
        """
        domains: Set[str] = set()
        ips: Set[str] = set()
        urls: Set[str] = set()
        hashes: Set[str] = set()
        sender_domains: Set[str] = set()
        sender_addresses: Set[str] = set()
        protected_identities: Set[str] = set()
        targeted_accounts: Set[str] = set()
        targeted_services: Set[str] = set()
        threat_event_types: Set[str] = set()
        finding_types: Set[str] = set()
        tactic_features: Set[str] = set()
        template_text_samples: List[str] = []

        # 1. Pull from Knowledge Graph Subgraph
        try:
            subgraph = self.graph_service.get_incident_subgraph(
                incident_id=incident.id,
                workspace_id=incident.workspace_id or "default",
                db=db
            )
            for node in subgraph.nodes:
                if node.type == GraphEntityType.DOMAIN.value:
                    domains.add(node.canonical_key or node.display_value.lower())
                elif node.type == GraphEntityType.IP.value:
                    ips.add(node.canonical_key or node.display_value.lower())
                elif node.type == GraphEntityType.URL.value:
                    urls.add(node.canonical_key or node.display_value)
                elif node.type == GraphEntityType.HASH.value:
                    hashes.add(node.canonical_key or node.display_value.lower())
                elif node.type == GraphEntityType.IDENTITY.value:
                    protected_identities.add(node.display_value)
                elif node.type == GraphEntityType.ACCOUNT.value:
                    targeted_accounts.add(node.display_value)
                elif node.type == GraphEntityType.API_SERVICE.value:
                    targeted_services.add(node.display_value)
        except Exception as exc:
            logger.debug(f"Knowledge graph query for incident {incident.id} returned empty or error: {exc}")

        # 2. Pull from ThreatEventModel
        threat_events = db.query(ThreatEventModel).filter(
            ThreatEventModel.incident_id == incident.id
        ).all()
        for te in threat_events:
            threat_event_types.add(te.event_type)
            if te.summary:
                template_text_samples.append(te.summary)
            if te.metadata_json:
                try:
                    meta = json.loads(te.metadata_json)
                    if "domain" in meta:
                        domains.add(meta["domain"].lower())
                    if "ip" in meta:
                        ips.add(meta["ip"].lower())
                    if "url" in meta:
                        urls.add(meta["url"])
                    if "sha256" in meta:
                        hashes.add(meta["sha256"].lower())
                    if "target_brand" in meta:
                        protected_identities.add(meta["target_brand"])
                    if "tactic" in meta:
                        tactic_features.add(meta["tactic"])
                except Exception:
                    pass

        # 3. Pull from Incident metadata_json (for backward-compatibility with ingestion)
        if incident.metadata_json:
            try:
                meta = json.loads(incident.metadata_json)
                for d in meta.get("domains", []):
                    domains.add(d.lower())
                for ip in meta.get("ips", []):
                    ips.add(ip.lower())
                for u in meta.get("urls", []):
                    urls.add(u)
                for h in meta.get("hashes", []):
                    hashes.add(h.lower())
                for pi in meta.get("protected_identities", []):
                    protected_identities.add(pi)
                for s in meta.get("senders", []):
                    sender_addresses.add(s.lower())
                    if "@" in s:
                        sender_domains.add(s.split("@")[-1].lower())
                if "subject" in meta:
                    template_text_samples.append(meta["subject"])
                if "template" in meta:
                    template_text_samples.append(meta["template"])
            except Exception:
                pass

        # 4. Compute Template Fingerprint
        combined_text = " ".join(template_text_samples)
        norm_template = normalize_message_template(combined_text)
        tokens = [w for w in norm_template.split() if len(w) > 2]
        template_fp_int = compute_simhash(tokens)
        template_fingerprint = f"{template_fp_int:016x}" if template_fp_int != 0 else None

        return IncidentCorrelationProfile(
            incident_id=incident.id,
            workspace_id=incident.workspace_id or "default",
            time_start=incident.opened_at,
            time_end=incident.closed_at or incident.updated_at,
            domains=sorted(list(domains)),
            ips=sorted(list(ips)),
            urls=sorted(list(urls)),
            hashes=sorted(list(hashes)),
            sender_domains=sorted(list(sender_domains)),
            sender_addresses=sorted(list(sender_addresses)),
            protected_identities=sorted(list(protected_identities)),
            targeted_accounts=sorted(list(targeted_accounts)),
            targeted_services=sorted(list(targeted_services)),
            threat_event_types=sorted(list(threat_event_types)),
            finding_types=sorted(list(finding_types)),
            tactic_features=sorted(list(tactic_features)),
            template_fingerprint=template_fingerprint,
            profile_version=CONFIG_VERSION,
            generated_at=datetime.now(timezone.utc),
        )

    # -------------------------------------------------------------------------
    # 2. Sub-Linear Candidate Generation
    # -------------------------------------------------------------------------

    def generate_candidate_incident_ids(
        self,
        profile: IncidentCorrelationProfile,
        workspace_id: str,
        db: Session,
        max_candidates: int = 50
    ) -> List[str]:
        """
        Uses inverted indicator querying to select only candidate incidents
        sharing at least 1 high/medium-specificity indicator.
        Suppresses universal bridge indicators (Cloudflare IPs, public resolvers).
        Avoids O(N^2) full table scans.
        """
        candidate_ids: Set[str] = set()

        # 1. Exact Hashes (Highest specificity)
        for h in profile.hashes:
            if h not in EMPTY_FILE_HASHES:
                # Query incidents containing this hash in knowledge graph or metadata
                matching_nodes = db.query(EntityModel).filter(
                    EntityModel.entity_type == GraphEntityType.HASH.value,
                    EntityModel.canonical_key == h
                ).all()
                for node in matching_nodes:
                    rels = db.query(RelationshipModel).filter(
                        or_(RelationshipModel.source_id == node.id, RelationshipModel.target_id == node.id),
                        RelationshipModel.relationship_type == GraphRelationshipType.OBSERVED_IN.value
                    ).all()
                    for r in rels:
                        target = r.target_id if r.source_id == node.id else r.source_id
                        if target != profile.incident_id:
                            candidate_ids.add(target)

        # 2. Domains (Filtered for generic webmail/cloud)
        for d in profile.domains:
            if d not in COMMON_WEBMAIL_DOMAINS and d not in COMMON_CLOUD_DOMAINS:
                matching_nodes = db.query(EntityModel).filter(
                    EntityModel.entity_type == GraphEntityType.DOMAIN.value,
                    EntityModel.canonical_key == d
                ).all()
                for node in matching_nodes:
                    rels = db.query(RelationshipModel).filter(
                        or_(RelationshipModel.source_id == node.id, RelationshipModel.target_id == node.id),
                        RelationshipModel.relationship_type == GraphRelationshipType.OBSERVED_IN.value
                    ).all()
                    for r in rels:
                        target = r.target_id if r.source_id == node.id else r.source_id
                        if target != profile.incident_id:
                            candidate_ids.add(target)

        # 3. URLs
        for u in profile.urls:
            matching_nodes = db.query(EntityModel).filter(
                EntityModel.entity_type == GraphEntityType.URL.value,
                EntityModel.canonical_key == u
            ).all()
            for node in matching_nodes:
                rels = db.query(RelationshipModel).filter(
                    or_(RelationshipModel.source_id == node.id, RelationshipModel.target_id == node.id),
                    RelationshipModel.relationship_type == GraphRelationshipType.OBSERVED_IN.value
                ).all()
                for r in rels:
                    target = r.target_id if r.source_id == node.id else r.source_id
                    if target != profile.incident_id:
                        candidate_ids.add(target)

        # 4. Dedicated IPs (Suppress public resolvers and CDN IPs)
        for ip in profile.ips:
            if ip not in COMMON_PUBLIC_RESOLVERS and ip not in COMMON_CDN_IPS:
                matching_nodes = db.query(EntityModel).filter(
                    EntityModel.entity_type == GraphEntityType.IP.value,
                    EntityModel.canonical_key == ip
                ).all()
                for node in matching_nodes:
                    rels = db.query(RelationshipModel).filter(
                        or_(RelationshipModel.source_id == node.id, RelationshipModel.target_id == node.id),
                        RelationshipModel.relationship_type == GraphRelationshipType.OBSERVED_IN.value
                    ).all()
                    for r in rels:
                        target = r.target_id if r.source_id == node.id else r.source_id
                        if target != profile.incident_id:
                            candidate_ids.add(target)

        # Fallback to direct incident search if KG is sparse
        if not candidate_ids:
            all_incidents = db.query(IncidentModel).filter(
                IncidentModel.id != profile.incident_id,
                or_(IncidentModel.workspace_id == workspace_id, IncidentModel.workspace_id == "default")
            ).order_by(desc(IncidentModel.created_at)).limit(max_candidates).all()
            return [inc.id for inc in all_incidents]

        return list(candidate_ids)[:max_candidates]

    # -------------------------------------------------------------------------
    # 3. Pairwise Incident Correlation
    # -------------------------------------------------------------------------

    def correlate_incident_pair(
        self,
        profile_a: IncidentCorrelationProfile,
        profile_b: IncidentCorrelationProfile,
        db: Session
    ) -> IncidentCorrelationResult:
        """
        Computes explainable cross-incident correlation between two incident profiles.
        Weighs supporting evidence against contradicting evidence.
        Score measures similarity strength, NEVER 'probability same attacker'.
        """
        supporting_evidence: List[CorrelationEvidenceItem] = []
        contradicting_evidence: List[ContradictingEvidenceItem] = []
        category_raw_scores: Dict[str, float] = defaultdict(float)

        workspace_id = profile_a.workspace_id

        # --- A. ARTIFACT FEATURES: Hashes ---
        shared_hashes = set(profile_a.hashes).intersection(set(profile_b.hashes))
        for h in shared_hashes:
            if h in EMPTY_FILE_HASHES:
                contradicting_evidence.append(ContradictingEvidenceItem(
                    category=CorrelationFeatureCategory.ARTIFACT,
                    factor="EMPTY_FILE_HASH_OVERLAP",
                    description=f"Shared hash {h[:12]}... is an empty file hash; zero forensic correlation value.",
                    weight_penalty=0.10,
                    weight_label="moderate"
                ))
            else:
                spec, _ = prevalence_tracker.classify_specificity("hash", h, workspace_id, db)
                sub_wt = 1.0
                cat_wt = self.category_weights.get(CorrelationFeatureCategory.ARTIFACT.value, 0.35)
                contrib = round(sub_wt * cat_wt, 4)
                category_raw_scores[CorrelationFeatureCategory.ARTIFACT.value] = max(
                    category_raw_scores[CorrelationFeatureCategory.ARTIFACT.value], sub_wt
                )
                supporting_evidence.append(CorrelationEvidenceItem(
                    category=CorrelationFeatureCategory.ARTIFACT,
                    evidence_type="SHARED_FILE_HASH",
                    description=f"Exact cryptographic SHA-256 attachment/file hash match ({h[:16]}...).",
                    weight=contrib,
                    weight_label="strong",
                    specificity=spec,
                    value=h,
                    prevalence_count=prevalence_tracker.get_prevalence(h, workspace_id, db)
                ))

        # --- B. INFRASTRUCTURE FEATURES: Domains & Lookalikes ---
        shared_domains = set(profile_a.domains).intersection(set(profile_b.domains))
        for d in shared_domains:
            if d in COMMON_WEBMAIL_DOMAINS or d in COMMON_CLOUD_DOMAINS:
                contradicting_evidence.append(ContradictingEvidenceItem(
                    category=CorrelationFeatureCategory.INFRASTRUCTURE,
                    factor="COMMON_HOSTING_DOMAIN",
                    description=f"Shared domain '{d}' is a generic webmail/cloud provider; negligible correlation value.",
                    weight_penalty=0.05,
                    weight_label="weak"
                ))
            else:
                spec, _ = prevalence_tracker.classify_specificity("domain", d, workspace_id, db)
                prev = prevalence_tracker.get_prevalence(d, workspace_id, db)
                sub_wt = 1.0 if prev <= 5 else 0.60
                cat_wt = self.category_weights.get(CorrelationFeatureCategory.INFRASTRUCTURE.value, 0.35)
                contrib = round(sub_wt * cat_wt, 4)
                category_raw_scores[CorrelationFeatureCategory.INFRASTRUCTURE.value] = max(
                    category_raw_scores[CorrelationFeatureCategory.INFRASTRUCTURE.value], sub_wt
                )
                label = "strong" if prev <= 3 else "moderate"
                supporting_evidence.append(CorrelationEvidenceItem(
                    category=CorrelationFeatureCategory.INFRASTRUCTURE,
                    evidence_type="SHARED_RARE_DOMAIN" if prev <= 5 else "SHARED_DOMAIN",
                    description=f"Shared infrastructure domain '{d}' observed across both incidents (prevalence: {prev}).",
                    weight=contrib,
                    weight_label=label,
                    specificity=spec,
                    value=d,
                    prevalence_count=prev
                ))

        # Lookalike Domain Pattern Check (if no exact domain overlap)
        if not shared_domains and profile_a.domains and profile_b.domains:
            for da in profile_a.domains:
                for db_dom in profile_b.domains:
                    tokens_a = set(re.split(r'[-._]', da))
                    tokens_b = set(re.split(r'[-._]', db_dom))
                    shared_tokens = tokens_a.intersection(tokens_b) - {"com", "net", "org", "test", "secure", "login", "verify", "auth"}
                    if shared_tokens:
                        sub_wt = 0.70
                        cat_wt = self.category_weights.get(CorrelationFeatureCategory.INFRASTRUCTURE.value, 0.35)
                        contrib = round(sub_wt * cat_wt, 4)
                        category_raw_scores[CorrelationFeatureCategory.INFRASTRUCTURE.value] = max(
                            category_raw_scores[CorrelationFeatureCategory.INFRASTRUCTURE.value], sub_wt
                        )
                        supporting_evidence.append(CorrelationEvidenceItem(
                            category=CorrelationFeatureCategory.INFRASTRUCTURE,
                            evidence_type="SIMILAR_LOOKALIKE_DOMAIN_PATTERN",
                            description=f"Lexically related lookalike domain family between '{da}' and '{db_dom}' targeting token '{list(shared_tokens)[0]}'.",
                            weight=contrib,
                            weight_label="moderate",
                            specificity=IndicatorSpecificity.MEDIUM,
                            value=f"{da} <-> {db_dom}"
                        ))
                        break

        # --- C. INFRASTRUCTURE FEATURES: IPs ---
        shared_ips = set(profile_a.ips).intersection(set(profile_b.ips))
        for ip in shared_ips:
            if ip in COMMON_PUBLIC_RESOLVERS or ip in COMMON_CDN_IPS:
                contradicting_evidence.append(ContradictingEvidenceItem(
                    category=CorrelationFeatureCategory.INFRASTRUCTURE,
                    factor="COMMON_CDN_INFRASTRUCTURE",
                    description=f"Shared IP '{ip}' belongs to a major CDN or public DNS resolver; does not indicate related activity.",
                    weight_penalty=0.15,
                    weight_label="strong"
                ))
            else:
                spec, _ = prevalence_tracker.classify_specificity("ip", ip, workspace_id, db)
                prev = prevalence_tracker.get_prevalence(ip, workspace_id, db)
                sub_wt = 0.60 if prev <= 3 else 0.20
                cat_wt = self.category_weights.get(CorrelationFeatureCategory.INFRASTRUCTURE.value, 0.35)
                contrib = round(sub_wt * cat_wt, 4)
                category_raw_scores[CorrelationFeatureCategory.INFRASTRUCTURE.value] = max(
                    category_raw_scores[CorrelationFeatureCategory.INFRASTRUCTURE.value], sub_wt
                )
                supporting_evidence.append(CorrelationEvidenceItem(
                    category=CorrelationFeatureCategory.INFRASTRUCTURE,
                    evidence_type="SHARED_RARE_IP" if prev <= 3 else "SHARED_IP",
                    description=f"Shared network IP '{ip}' (prevalence: {prev}).",
                    weight=contrib,
                    weight_label="moderate" if prev <= 3 else "weak",
                    specificity=spec,
                    value=ip,
                    prevalence_count=prev
                ))

        # --- D. INFRASTRUCTURE FEATURES: URLs ---
        shared_urls = set(profile_a.urls).intersection(set(profile_b.urls))
        for u in shared_urls:
            spec, _ = prevalence_tracker.classify_specificity("url", u, workspace_id, db)
            sub_wt = 1.0
            cat_wt = self.category_weights.get(CorrelationFeatureCategory.INFRASTRUCTURE.value, 0.35)
            contrib = round(sub_wt * cat_wt, 4)
            category_raw_scores[CorrelationFeatureCategory.INFRASTRUCTURE.value] = max(
                category_raw_scores[CorrelationFeatureCategory.INFRASTRUCTURE.value], sub_wt
            )
            supporting_evidence.append(CorrelationEvidenceItem(
                category=CorrelationFeatureCategory.INFRASTRUCTURE,
                evidence_type="SHARED_URL",
                description=f"Identical normalized destination URL ({u[:30]}...).",
                weight=contrib,
                weight_label="strong",
                specificity=spec,
                value=u
            ))

        # --- E. IDENTITY FEATURES: Protected Identities ---
        shared_brands = set(profile_a.protected_identities).intersection(set(profile_b.protected_identities))
        for b in shared_brands:
            sub_wt = 1.0
            cat_wt = self.category_weights.get(CorrelationFeatureCategory.IDENTITY.value, 0.10)
            contrib = round(sub_wt * cat_wt, 4)
            category_raw_scores[CorrelationFeatureCategory.IDENTITY.value] = max(
                category_raw_scores[CorrelationFeatureCategory.IDENTITY.value], sub_wt
            )
            supporting_evidence.append(CorrelationEvidenceItem(
                category=CorrelationFeatureCategory.IDENTITY,
                evidence_type="SHARED_TARGET_IDENTITY",
                description=f"Both incidents targeted protected brand/identity '{b}'.",
                weight=contrib,
                weight_label="weak",
                specificity=IndicatorSpecificity.MEDIUM,
                value=b
            ))

        # Contradicting brand check: If both have distinct identities with NO overlap
        if profile_a.protected_identities and profile_b.protected_identities and not shared_brands:
            contradicting_evidence.append(ContradictingEvidenceItem(
                category=CorrelationFeatureCategory.IDENTITY,
                factor="CONFLICTING_TARGETS",
                description=f"Incidents target conflicting identities ('{profile_a.protected_identities[0]}' vs '{profile_b.protected_identities[0]}').",
                weight_penalty=0.10,
                weight_label="moderate"
            ))

        # --- F. CONTENT FEATURES: Message Templates ---
        if profile_a.template_fingerprint and profile_b.template_fingerprint:
            h1 = int(profile_a.template_fingerprint, 16)
            h2 = int(profile_b.template_fingerprint, 16)
            tmpl_sim = simhash_similarity(h1, h2)
            if tmpl_sim >= 0.85:
                sub_wt = tmpl_sim
                cat_wt = self.category_weights.get(CorrelationFeatureCategory.CONTENT.value, 0.10)
                contrib = round(sub_wt * cat_wt, 4)
                category_raw_scores[CorrelationFeatureCategory.CONTENT.value] = max(
                    category_raw_scores[CorrelationFeatureCategory.CONTENT.value], sub_wt
                )
                supporting_evidence.append(CorrelationEvidenceItem(
                    category=CorrelationFeatureCategory.CONTENT,
                    evidence_type="SIMILAR_MESSAGE_TEMPLATE",
                    description=f"High structural message template similarity ({round(tmpl_sim * 100, 1)}% SimHash match).",
                    weight=contrib,
                    weight_label="moderate",
                    specificity=IndicatorSpecificity.MEDIUM,
                    value=f"SimHash similarity {round(tmpl_sim, 3)}"
                ))

        # --- G. TEMPORAL FEATURES: Proximity ---
        if profile_a.time_start and profile_b.time_start:
            dt_a = profile_a.time_start if profile_a.time_start.tzinfo else profile_a.time_start.replace(tzinfo=timezone.utc)
            dt_b = profile_b.time_start if profile_b.time_start.tzinfo else profile_b.time_start.replace(tzinfo=timezone.utc)
            diff = abs((dt_a - dt_b).total_seconds())

            if diff <= 7200:  # <= 2 hours
                sub_wt = 1.0
                cat_wt = self.category_weights.get(CorrelationFeatureCategory.TEMPORAL.value, 0.05)
                contrib = round(sub_wt * cat_wt, 4)
                category_raw_scores[CorrelationFeatureCategory.TEMPORAL.value] = max(
                    category_raw_scores[CorrelationFeatureCategory.TEMPORAL.value], sub_wt
                )
                supporting_evidence.append(CorrelationEvidenceItem(
                    category=CorrelationFeatureCategory.TEMPORAL,
                    evidence_type="CLOSE_TEMPORAL_PROXIMITY",
                    description=f"Events occurred within {int(diff // 60)} minutes of each other.",
                    weight=contrib,
                    weight_label="moderate",
                    specificity=IndicatorSpecificity.MEDIUM,
                    value=f"{int(diff // 60)} min"
                ))
            elif diff <= 86400:  # <= 24 hours
                sub_wt = 0.50
                cat_wt = self.category_weights.get(CorrelationFeatureCategory.TEMPORAL.value, 0.05)
                contrib = round(sub_wt * cat_wt, 4)
                category_raw_scores[CorrelationFeatureCategory.TEMPORAL.value] = max(
                    category_raw_scores[CorrelationFeatureCategory.TEMPORAL.value], sub_wt
                )
                supporting_evidence.append(CorrelationEvidenceItem(
                    category=CorrelationFeatureCategory.TEMPORAL,
                    evidence_type="MODERATE_TEMPORAL_PROXIMITY",
                    description=f"Events occurred within {int(diff // 3600)} hours of each other.",
                    weight=contrib,
                    weight_label="weak",
                    specificity=IndicatorSpecificity.LOW,
                    value=f"{int(diff // 3600)} hrs"
                ))
            elif diff > 30 * 86400:  # > 30 days
                if not shared_hashes:
                    contradicting_evidence.append(ContradictingEvidenceItem(
                        category=CorrelationFeatureCategory.TEMPORAL,
                        factor="LARGE_TIME_SEPARATION",
                        description=f"Incidents occurred {int(diff // 86400)} days apart without persistent artifact overlap.",
                        weight_penalty=0.15,
                        weight_label="moderate"
                    ))

        # --- H. BEHAVIOR & TACTIC FEATURES ---
        shared_tactics = set(profile_a.threat_event_types).intersection(set(profile_b.threat_event_types))
        for st in shared_tactics:
            sub_wt = 1.0
            cat_wt = self.category_weights.get(CorrelationFeatureCategory.TACTIC.value, 0.05)
            contrib = round(sub_wt * cat_wt, 4)
            category_raw_scores[CorrelationFeatureCategory.TACTIC.value] = max(
                category_raw_scores[CorrelationFeatureCategory.TACTIC.value], sub_wt
            )
            supporting_evidence.append(CorrelationEvidenceItem(
                category=CorrelationFeatureCategory.TACTIC,
                evidence_type="SHARED_THREAT_TACTIC",
                description=f"Common threat event behavior/tactic '{st}'.",
                weight=contrib,
                weight_label="weak",
                specificity=IndicatorSpecificity.LOW,
                value=st
            ))

        # --- Compute Final Score ---
        raw_score = 0.0
        for cat_name, cat_wt in self.category_weights.items():
            cat_val = min(1.0, category_raw_scores.get(cat_name, 0.0))
            raw_score += cat_val * cat_wt

        total_penalty = sum(ce.weight_penalty for ce in contradicting_evidence)
        final_score = max(0.0, min(1.0, round(raw_score - total_penalty, 4)))

        # Assign calibrated relationship label
        if final_score >= HIGH_SIMILARITY_THRESHOLD:
            relationship_label = "Strong cross-incident similarity"
        elif final_score >= MODERATE_SIMILARITY_THRESHOLD:
            relationship_label = "Moderate cross-incident similarity"
        elif final_score >= WEAK_SIMILARITY_THRESHOLD:
            relationship_label = "Weak cross-incident similarity"
        else:
            relationship_label = "Inconclusive / No significant relationship"

        breakdown = FeatureBreakdown(
            category_scores={k: round(v, 4) for k, v in category_raw_scores.items()},
            category_weights=self.category_weights,
            raw_score=round(raw_score, 4),
            penalty_score=round(total_penalty, 4),
            final_score=final_score,
        )

        return IncidentCorrelationResult(
            id=str(uuid.uuid4()),
            workspace_id=workspace_id,
            incident_a_id=profile_a.incident_id,
            incident_b_id=profile_b.incident_id,
            correlation_score=final_score,
            confidence=1.0,
            relationship_label=relationship_label,
            assessment_meaning="The incidents share multiple uncommon characteristics and may represent related activity (not attribution to same actor).",
            supporting_evidence=supporting_evidence,
            contradicting_evidence=contradicting_evidence,
            feature_breakdown=breakdown,
            status="ACTIVE",
            engine_version=ENGINE_VERSION,
            config_version=CONFIG_VERSION,
            created_at=datetime.now(timezone.utc),
        )

    # -------------------------------------------------------------------------
    # 4. Campaign Candidate Generation & Clustering
    # -------------------------------------------------------------------------

    def generate_campaign_candidates(
        self,
        workspace_id: str,
        db: Session
    ) -> List[CampaignCandidateResponse]:
        """
        Clusters related incidents into Campaign Candidates using graph-based threshold clustering.
        Enforces Transitive-Correlation & Bridge Indicator Controls:
        - Weak edges or shared CDN/public IPs CANNOT bridge incidents into mega-clusters.
        - Edges require high specificity or score >= CAMPAIGN_CLUSTER_THRESHOLD (0.55).
        - Connects campaign candidates into the Security Knowledge Graph.
        """
        # 1. Fetch all candidate correlations in the workspace
        correlations = db.query(IncidentCorrelationModel).filter(
            IncidentCorrelationModel.workspace_id == workspace_id,
            IncidentCorrelationModel.status.in_(["ACTIVE", "CONFIRMED"]),
            IncidentCorrelationModel.correlation_score >= self.campaign_threshold
        ).all()

        if not correlations:
            return []

        # 2. Build Adjacency Graph with Transitive Safeguards
        adj: Dict[str, Set[str]] = defaultdict(set)
        edge_data: Dict[Tuple[str, str], IncidentCorrelationModel] = {}

        for corr in correlations:
            # Check for high-specificity evidence in supporting evidence
            try:
                supp_ev = json.loads(corr.supporting_evidence_json)
                has_high_specificity = any(
                    e.get("specificity") == IndicatorSpecificity.HIGH.value for e in supp_ev
                )
            except Exception:
                has_high_specificity = False

            # Transitive Safeguard: Require either HIGH specificity indicator OR score >= 0.65
            if has_high_specificity or corr.correlation_score >= 0.65:
                u, v = corr.incident_a_id, corr.incident_b_id
                adj[u].add(v)
                adj[v].add(u)
                edge_data[(u, v)] = corr
                edge_data[(v, u)] = corr

        # 3. Find Connected Components
        visited: Set[str] = set()
        components: List[List[str]] = []

        for node in list(adj.keys()):
            if node not in visited:
                comp = []
                queue = [node]
                visited.add(node)
                while queue:
                    curr = queue.pop(0)
                    comp.append(curr)
                    for nbr in adj[curr]:
                        if nbr not in visited:
                            visited.add(nbr)
                            queue.append(nbr)
                if len(comp) >= 2:
                    components.append(comp)

        # 4. Construct CampaignCandidateResponse and Persist
        results: List[CampaignCandidateResponse] = []

        for idx, comp in enumerate(components, start=1):
            camp_id = f"CAMP-CAND-{idx:03d}"
            camp_name = f"Campaign Candidate {camp_id} ({len(comp)} Correlated Incidents)"

            # Aggregate evidence across component edges
            all_supp: List[CorrelationEvidenceItem] = []
            all_contra: List[ContradictingEvidenceItem] = []
            dominant_attacks = []

            first_seen = datetime.now(timezone.utc)
            last_seen = datetime(1970, 1, 1, tzinfo=timezone.utc)

            # Query incident details
            incidents = db.query(IncidentModel).filter(IncidentModel.id.in_(comp)).all()
            for inc in incidents:
                if inc.opened_at:
                    dt = inc.opened_at if inc.opened_at.tzinfo else inc.opened_at.replace(tzinfo=timezone.utc)
                    if dt < first_seen:
                        first_seen = dt
                    if dt > last_seen:
                        last_seen = dt

            # Collect unique evidence
            seen_evidence_vals = set()
            for i in range(len(comp)):
                for j in range(i + 1, len(comp)):
                    pair = (comp[i], comp[j])
                    if pair in edge_data:
                        c_model = edge_data[pair]
                        try:
                            for e in json.loads(c_model.supporting_evidence_json):
                                ev_obj = CorrelationEvidenceItem(**e)
                                if ev_obj.value not in seen_evidence_vals:
                                    all_supp.append(ev_obj)
                                    seen_evidence_vals.add(ev_obj.value)
                            for ce in json.loads(c_model.contradicting_evidence_json):
                                all_contra.append(ContradictingEvidenceItem(**ce))
                        except Exception:
                            pass

            summary = (
                f"Cluster of {len(comp)} incidents exhibiting recurring patterns across "
                f"{len(all_supp)} corroborated forensic indicators (not an attribution claim)."
            )

            # Check if campaign already exists in database
            db_camp = db.query(CampaignModel).filter(
                CampaignModel.campaign_id == camp_id,
                CampaignModel.workspace_id == workspace_id
            ).first()

            if not db_camp:
                db_camp = CampaignModel(
                    id=str(uuid.uuid4()),
                    campaign_id=camp_id,
                    name=camp_name,
                    workspace_id=workspace_id,
                    status="CANDIDATE",
                    overall_confidence=round(sum(c.correlation_score for c in correlations) / len(correlations) * 100, 1) if correlations else 80.0,
                    first_seen=first_seen,
                    last_seen=last_seen,
                    dominant_attack_type="Coordinated Pattern Activity",
                    supporting_evidence_json=json.dumps([e.model_dump() for e in all_supp]),
                    contradicting_evidence_json=json.dumps([e.model_dump() for e in all_contra]),
                    correlation_summary=summary,
                    engine_version=ENGINE_VERSION,
                    created_at=datetime.now(timezone.utc),
                )
                db.add(db_camp)
                db.flush()

                # Link member incidents
                for inc_id in comp:
                    c_inc = CampaignIncidentModel(
                        campaign_id=db_camp.id,
                        incident_id=inc_id,
                        similarity_score=self.campaign_threshold,
                        status="CANDIDATE",
                        membership_reasons_json=json.dumps(["Corroborated cross-incident correlation"]),
                        added_at=datetime.now(timezone.utc),
                        added_by="AUTOMATED"
                    )
                    db.add(c_inc)
                db.commit()

                # Knowledge Graph Integration: Link Campaign Node
                try:
                    camp_entity = self.graph_service.get_or_create_entity(
                        entity_type=GraphEntityType.CAMPAIGN,
                        canonical_key=f"campaign:{workspace_id}:{camp_id.lower()}",
                        display_value=camp_name,
                        workspace_id=workspace_id,
                        db=db
                    )
                    for inc_id in comp:
                        inc_entity = self.graph_service.get_or_create_entity(
                            entity_type=GraphEntityType.INCIDENT,
                            canonical_key=f"incident:{workspace_id}:{inc_id}",
                            display_value=f"Incident {inc_id[:8]}",
                            workspace_id=workspace_id,
                            db=db
                        )
                        self.graph_service.create_relationship(
                            source_id=camp_entity.id,
                            target_id=inc_entity.id,
                            relationship_type=GraphRelationshipType.ASSOCIATED_WITH,
                            confidence=0.85,
                            origin=RelationshipOrigin.INFERRED,
                            workspace_id=workspace_id,
                            db=db
                        )
                except Exception as g_err:
                    logger.debug(f"Failed to link campaign to knowledge graph: {g_err}")

            results.append(CampaignCandidateResponse(
                id=db_camp.id,
                campaign_id=db_camp.campaign_id,
                workspace_id=workspace_id,
                name=db_camp.name,
                status=db_camp.status,
                overall_confidence=db_camp.overall_confidence,
                correlation_summary=summary,
                incident_count=len(comp),
                incident_ids=comp,
                supporting_evidence=all_supp,
                contradicting_evidence=all_contra,
                first_seen=first_seen,
                last_seen=last_seen,
                dominant_attack_type="Coordinated Pattern Activity",
                engine_version=ENGINE_VERSION,
            ))

        return results

    # -------------------------------------------------------------------------
    # 5. Analyst Feedback & Audit Service
    # -------------------------------------------------------------------------

    def review_correlation(
        self,
        correlation_id: str,
        decision: str,  # "CONFIRM" or "REJECT"
        notes: Optional[str],
        analyst_id: str,
        db: Session
    ) -> IncidentCorrelationResult:
        """
        Analyst feedback handling for pairwise correlation.
        Updates status and logs audit trail.
        """
        corr = db.query(IncidentCorrelationModel).filter(
            IncidentCorrelationModel.id == correlation_id
        ).first()
        if not corr:
            raise KeyError(f"Correlation record {correlation_id} not found.")

        new_status = "CONFIRMED" if decision.upper() == "CONFIRM" else "REJECTED"
        corr.status = new_status
        corr.reviewed_by = analyst_id
        corr.reviewed_at = datetime.now(timezone.utc)
        corr.review_notes = notes
        corr.updated_at = datetime.now(timezone.utc)

        # Audit Log
        audit = AuditLogModel(
            user=analyst_id,
            action=f"CORRELATION_{new_status}",
            resource_type="incident_correlation",
            resource_id=correlation_id,
            details=json.dumps({"decision": decision, "notes": notes, "score": corr.correlation_score}),
            metadata_json=json.dumps({"decision": decision, "notes": notes, "score": corr.correlation_score}),
            timestamp=datetime.now(timezone.utc),
        )
        db.add(audit)
        db.commit()
        db.refresh(corr)

        return IncidentCorrelationResult(
            id=corr.id,
            workspace_id=corr.workspace_id,
            incident_a_id=corr.incident_a_id,
            incident_b_id=corr.incident_b_id,
            correlation_score=corr.correlation_score,
            confidence=corr.confidence,
            relationship_label=corr.relationship_label,
            supporting_evidence=[CorrelationEvidenceItem(**e) for e in json.loads(corr.supporting_evidence_json)],
            contradicting_evidence=[ContradictingEvidenceItem(**e) for e in json.loads(corr.contradicting_evidence_json)],
            feature_breakdown=FeatureBreakdown(**json.loads(corr.feature_breakdown_json)),
            status=corr.status,
            reviewed_by=corr.reviewed_by,
            reviewed_at=corr.reviewed_at,
            review_notes=corr.review_notes,
            engine_version=corr.engine_version,
            config_version=corr.config_version,
            created_at=corr.created_at,
        )

    def review_campaign_candidate(
        self,
        campaign_id: str,
        decision: str,  # "CONFIRM" or "REJECT"
        notes: Optional[str],
        analyst_id: str,
        db: Session
    ) -> CampaignCandidateResponse:
        """
        Analyst feedback handling for campaign candidate.
        Updates status, updates Knowledge Graph edge origin if confirmed, and logs audit trail.
        """
        camp = db.query(CampaignModel).filter(
            or_(CampaignModel.id == campaign_id, CampaignModel.campaign_id == campaign_id)
        ).first()
        if not camp:
            raise KeyError(f"Campaign candidate {campaign_id} not found.")

        new_status = "REVIEWED_CONFIRMED" if decision.upper() == "CONFIRM" else "REVIEWED_REJECTED"
        camp.status = new_status
        camp.updated_at = datetime.now(timezone.utc)

        # Audit Log
        audit = AuditLogModel(
            user=analyst_id,
            action=f"CAMPAIGN_MEMBERSHIP_{'CONFIRMED' if decision.upper() == 'CONFIRM' else 'REJECTED'}",
            resource_type="campaign",
            resource_id=camp.id,
            details=json.dumps({"decision": decision, "notes": notes}),
            metadata_json=json.dumps({"decision": decision, "notes": notes}),
            timestamp=datetime.now(timezone.utc),
        )
        db.add(audit)
        db.commit()
        db.refresh(camp)

        # Update Knowledge Graph edge origin if confirmed
        if new_status == "REVIEWED_CONFIRMED":
            try:
                camp_entity = self.graph_service.get_or_create_entity(
                    entity_type=GraphEntityType.CAMPAIGN,
                    canonical_key=f"campaign:{camp.workspace_id}:{camp.campaign_id.lower()}",
                    display_value=camp.name,
                    workspace_id=camp.workspace_id,
                    db=db
                )
                rels = db.query(RelationshipModel).filter(
                    RelationshipModel.source_id == camp_entity.id
                ).all()
                for r in rels:
                    r.origin = "ANALYST_CONFIRMED"
                db.commit()
            except Exception:
                pass

        inc_ids = [ci.incident_id for ci in camp.incidents] if hasattr(camp, "incidents") and camp.incidents else []
        supp = [CorrelationEvidenceItem(**e) for e in json.loads(camp.supporting_evidence_json)] if camp.supporting_evidence_json else []
        contra = [ContradictingEvidenceItem(**e) for e in json.loads(camp.contradicting_evidence_json)] if camp.contradicting_evidence_json else []

        return CampaignCandidateResponse(
            id=camp.id,
            campaign_id=camp.campaign_id,
            workspace_id=camp.workspace_id,
            name=camp.name,
            status=camp.status,
            overall_confidence=camp.overall_confidence,
            correlation_summary=camp.correlation_summary or "",
            incident_count=len(inc_ids),
            incident_ids=inc_ids,
            supporting_evidence=supp,
            contradicting_evidence=contra,
            first_seen=camp.first_seen,
            last_seen=camp.last_seen,
            dominant_attack_type=camp.dominant_attack_type,
            engine_version=camp.engine_version,
        )


# Global instance
global_cross_incident_engine = CrossIncidentCorrelationEngine()
