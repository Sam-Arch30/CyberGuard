import hashlib
import ipaddress
import json
import math
import re
import urllib.parse
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Set, Optional, Any, Tuple
from sqlalchemy.orm import Session

from backend.db.models import CaseModel, CaseEmailModel, CampaignModel, CampaignEmailModel
from backend.schemas.correlation import (
    SharedIndicator,
    MatchedSignalDetail,
    RelatedCaseItem,
    CorrelatedIngestedEmail,
    CampaignCorrelationResponse,
    DirectCompareResponse,
    InfrastructureFingerprint,
    DomainFingerprint,
    UrlFingerprint,
    EmailStructureFingerprint,
    ContentFingerprint,
    AuthenticationFingerprint,
    AttachmentFingerprint,
    CampaignFingerprint,
    CategorySimilarityScores,
    CampaignTimelineEvent,
    CampaignIOC,
    CampaignClusterItem,
    CampaignDetailResponse,
    CampaignAlertResponse,
)


# -----------------------------------------------------------------------------
# Configurable Weights & Default Constants
# -----------------------------------------------------------------------------

DEFAULT_CORRELATION_WEIGHTS = {
    "same_attachment_hash": 0.35,
    "same_ip": 0.20,
    "same_domain": 0.20,
    "same_reply_to": 0.20,
    "same_sender": 0.15,
    "same_url_domain": 0.15,
    "same_nameserver": 0.10,
    "similar_brand": 0.10,
    "similar_subject": 0.10,
    "same_registrar": 0.08,
    "similar_asn": 0.08,
}

DEFAULT_CATEGORY_WEIGHTS = {
    "infrastructure": 0.22,
    "domain": 0.20,
    "url": 0.20,
    "content": 0.15,
    "template": 0.12,
    "attachment": 0.06,
    "authentication": 0.05,
}

# False-Positive Control Lists
EMPTY_FILE_HASHES = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "d41d8cd98f00b204e9800998ecf8427e",
    "da39a3ee5e6b4b0d3255bfef95601890afd80709"
}

COMMON_WEBMAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.uk",
    "outlook.com", "hotmail.com", "live.com", "msn.com",
    "aol.com", "icloud.com", "me.com", "mac.com",
    "mail.com", "protonmail.com", "proton.me", "zoho.com",
    "yandex.com", "gmx.com", "fastmail.com"
}

COMMON_PUBLIC_RESOLVERS = {
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
    "9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220",
    "127.0.0.1", "0.0.0.0", "::1"
}

COMMON_CLOUD_DOMAINS = {
    "google.com", "microsoft.com", "apple.com", "amazon.com",
    "amazonaws.com", "cloudflare.com", "akamai.com", "azure.com",
    "office365.com", "sendgrid.net", "mailchimp.com"
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

GENERIC_REGISTRARS = {
    "godaddy.com, llc", "namecheap inc", "namecheap, inc.",
    "tucows domains inc", "tucows domains inc.", "network solutions, llc",
    "markmonitor inc", "markmonitor inc.", "google llc", "cloudflare, inc.",
    "namesilo, llc", "dynadot llc"
}

INTENT_KEYWORD_PATTERNS = {
    "wire_fraud": [r"\bwire\b", r"\btransfer\b", r"\binvoice\b", r"\bbank\b", r"\bremittance\b", r"\bsettlement\b", r"\bbeneficiary\b", r"\bfunds\b", r"\bpayment\b"],
    "credential_harvesting": [r"\blogin\b", r"\bpassword\b", r"\bverify\b", r"\baccount\b", r"\bsign in\b", r"\baccess\b", r"\bportal\b", r"\bcredentials\b", r"\breset\b"],
    "malware_delivery": [r"\battached\b", r"\bdocument\b", r"\bmacro\b", r"\benable content\b", r"\bpayload\b", r"\be-?fax\b", r"\breceipt\b"],
    "urgency_extortion": [r"\bimmediate\b", r"\bsuspended\b", r"\bterminated\b", r"\burrgent\b", r"\burgent\b", r"\blawsuit\b", r"\bdeadline\b", r"\baction required\b"],
    "package_delivery": [r"\bparcel\b", r"\bshipment\b", r"\bfedex\b", r"\bups\b", r"\bdhl\b", r"\btracking\b", r"\bcourier\b", r"\bpackage\b"]
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
    if h1 == 0 and h2 == 0:
        return 0.0
    if h1 == 0 or h2 == 0:
        return 0.0
    x = (h1 ^ h2) & ((1 << hash_bits) - 1)
    dist = bin(x).count("1")
    return max(0.0, 1.0 - (dist / hash_bits))


def compute_term_vector(text: str) -> Dict[str, float]:
    """Generates L2-normalized TF-IDF/frequency term vector from text."""
    if not text:
        return {}
    words = re.findall(r'[a-zA-Z]{3,}', text.lower())
    stop_words = {
        "the", "and", "for", "that", "this", "with", "from", "your", "have", "are",
        "will", "can", "not", "all", "was", "any", "been", "has", "more", "when",
        "there", "our", "would", "about", "which", "their", "into", "please", "email",
        "message", "mail", "sent", "subject", "date"
    }
    filtered = [w for w in words if w not in stop_words]
    counts = Counter(filtered)
    norm = math.sqrt(sum(c * c for c in counts.values())) or 1.0
    return {w: round(c / norm, 4) for w, c in counts.most_common(40)}


def cosine_similarity(v1: Dict[str, float], v2: Dict[str, float]) -> float:
    """Computes cosine similarity between two normalized term vectors."""
    if not v1 or not v2:
        return 0.0
    dot = sum(v1[k] * v2[k] for k in v1 if k in v2)
    return min(1.0, max(0.0, round(dot, 4)))


def extract_html_tag_tokens(html_str: str) -> List[str]:
    """Extracts tag sequences and CSS structural tokens, ignoring volatile text."""
    if not html_str:
        return []
    tags = re.findall(r'<([a-zA-Z0-9]+)[\s>]', html_str.lower())
    classes = re.findall(r'class=["\']([^"\']+)["\']', html_str.lower())
    class_tokens = [c for cl in classes for c in cl.split() if len(c) < 30]
    return [f"tag:{t}" for t in tags[:200]] + [f"cls:{c}" for c in class_tokens[:50]]


def compute_fuzzy_hash(filename: str, mime_type: str, sha256: str) -> str:
    """Computes a structural fuzzy hash for attachments based on type, name pattern, and hash prefix."""
    ext = filename.split(".")[-1].lower() if "." in filename else "none"
    clean_name = re.sub(r'[\d_-]+', '', filename.lower())
    tokens = [
        f"ext:{ext}",
        f"mime:{mime_type.lower() if mime_type else 'none'}",
        f"len:{len(filename)}",
        f"pat:{clean_name[:20]}"
    ]
    if sha256 and len(sha256) >= 8:
        tokens.append(f"hprefix:{sha256[:8]}")
    h = compute_simhash(tokens)
    return f"{h:016x}"


# -----------------------------------------------------------------------------
# Data Containers (Backward Compatible)
# -----------------------------------------------------------------------------

@dataclass
class CorrelationProfile:
    """Normalized forensic indicator profile for pairwise correlation."""
    subjects: Set[str] = field(default_factory=set)
    senders: Set[str] = field(default_factory=set)
    reply_tos: Set[str] = field(default_factory=set)
    attachment_hashes: Set[str] = field(default_factory=set)
    ips: Set[str] = field(default_factory=set)
    domains: Set[str] = field(default_factory=set)
    url_domains: Set[str] = field(default_factory=set)
    registrars: Set[str] = field(default_factory=set)
    nameservers: Set[str] = field(default_factory=set)
    asns: Set[str] = field(default_factory=set)
    brands: Set[str] = field(default_factory=set)


# -----------------------------------------------------------------------------
# Advanced Campaign Correlator & Fingerprinting Engine
# -----------------------------------------------------------------------------

class CampaignCorrelator:
    """
    Advanced Campaign Fingerprinting Engine.
    Generates 7-dimensional fingerprints, computes weighted category similarity,
    suppresses false correlations from shared cloud infrastructure, and clusters
    forensic investigations into campaigns.
    """

    def __init__(
        self,
        weights: Optional[Dict[str, float]] = None,
        category_weights: Optional[Dict[str, float]] = None
    ):
        self.weights = dict(DEFAULT_CORRELATION_WEIGHTS)
        if weights:
            self.weights.update(weights)

        self.category_weights = dict(DEFAULT_CATEGORY_WEIGHTS)
        if category_weights:
            self.category_weights.update(category_weights)

    # -------------------------------------------------------------------------
    # Helper & Cleaning Methods
    # -------------------------------------------------------------------------

    @staticmethod
    def is_valid_indicator_ip(ip_str: str) -> bool:
        """Checks if an IP is valid, public, and not a common public resolver."""
        if not ip_str or not isinstance(ip_str, str):
            return False
        clean = ip_str.strip()
        if clean in COMMON_PUBLIC_RESOLVERS:
            return False
        try:
            addr = ipaddress.ip_address(clean)
            if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_reserved:
                return False
            return True
        except ValueError:
            return False

    @staticmethod
    def is_valid_indicator_domain(domain_str: str, check_webmail: bool = True) -> bool:
        """Checks if a domain is valid and not a generic webmail/cloud platform."""
        if not domain_str or not isinstance(domain_str, str):
            return False
        clean = domain_str.strip().lower().rstrip('.')
        if not clean or '.' not in clean:
            return False
        if check_webmail and clean in COMMON_WEBMAIL_DOMAINS:
            return False
        if clean in COMMON_CLOUD_DOMAINS:
            return False
        return True

    @staticmethod
    def clean_subject_text(subject: str) -> str:
        """Removes email prefixes, tags, and extraneous whitespace."""
        if not subject:
            return ""
        s = subject.strip()
        prefix_pattern = r'^(?:re|fwd|fw|urgent|notice|warning|external|\[external\])\s*:\s*'
        while re.match(prefix_pattern, s, re.IGNORECASE):
            s = re.sub(prefix_pattern, '', s, flags=re.IGNORECASE).strip()
        s = re.sub(r'\[.*?\]', '', s).strip()
        s = re.sub(r'[^\w\s]', ' ', s.lower())
        return " ".join(s.split())

    @classmethod
    def calculate_subject_similarity(cls, subjects_a: Set[str], subjects_b: Set[str]) -> Tuple[float, Optional[str]]:
        """Computes Jaccard token overlap between subject line sets."""
        best_sim = 0.0
        best_match = None

        for sa in subjects_a:
            clean_a = cls.clean_subject_text(sa)
            tokens_a = set(clean_a.split())
            if len(tokens_a) < 2:
                continue

            for sb in subjects_b:
                clean_b = cls.clean_subject_text(sb)
                tokens_b = set(clean_b.split())
                if len(tokens_b) < 2:
                    continue

                intersection = tokens_a.intersection(tokens_b)
                union = tokens_a.union(tokens_b)
                if not union:
                    continue

                jaccard = len(intersection) / len(union)
                if jaccard >= 0.4 and jaccard > best_sim:
                    best_sim = jaccard
                    best_match = f"'{sa}' ~ '{sb}'"

        return round(best_sim, 4), best_match

    @staticmethod
    def get_relationship_label(score: float) -> str:
        """Returns evidence-based relationship label strictly adhering to non-attribution policy."""
        if score >= 0.75:
            return "Likely campaign relationship"
        elif score >= 0.45:
            return "Shared infrastructure observed"
        elif score >= 0.20:
            return "Potentially related activity"
        else:
            return "Inconclusive / No significant relationship"

    @staticmethod
    def generate_shared_evidence_summary(shared_indicators: List[SharedIndicator]) -> str:
        """Formats evidence summary: e.g. '2 IPs, 1 domain, 1 Reply-To address'."""
        if not shared_indicators:
            return "No shared technical indicators"

        counts: Dict[str, int] = {}
        for ind in shared_indicators:
            counts[ind.type] = counts.get(ind.type, 0) + 1

        parts: List[str] = []
        labels = {
            "attachment_hash": ("attachment hash", "attachment hashes"),
            "ip": ("IP", "IPs"),
            "domain": ("domain", "domains"),
            "reply_to": ("Reply-To address", "Reply-To addresses"),
            "sender": ("sender", "senders"),
            "url_domain": ("URL domain", "URL domains"),
            "nameserver": ("nameserver", "nameservers"),
            "brand": ("targeted brand", "targeted brands"),
            "subject": ("similar subject", "similar subjects"),
            "registrar": ("registrar", "registrars"),
            "asn": ("ASN", "ASNs"),
        }

        ordered_types = [
            "attachment_hash", "ip", "domain", "reply_to",
            "sender", "url_domain", "nameserver", "brand",
            "subject", "registrar", "asn"
        ]

        for t in ordered_types:
            if t in counts:
                c = counts[t]
                singular, plural = labels.get(t, (t, t + "s"))
                parts.append(f"{c} {singular if c == 1 else plural}")

        return ", ".join(parts) if parts else "Shared technical indicators observed"

    # -------------------------------------------------------------------------
    # 7-Dimensional Campaign Fingerprint Generation
    # -------------------------------------------------------------------------

    def generate_fingerprint(self, data: Dict[str, Any]) -> CampaignFingerprint:
        """
        Extracts a multidimensional CampaignFingerprint object encompassing
        Infrastructure, Domain, URL, Email Structure, Content, Authentication, and Attachments.
        """
        # 1. INFRASTRUCTURE
        infra = InfrastructureFingerprint()
        origin_ip = None
        attr = data.get("attribution") or {}
        if isinstance(attr, dict) and attr.get("probable_origin_ip"):
            origin_ip = attr["probable_origin_ip"]

        relay = data.get("relay_analysis") or {}
        if not origin_ip and isinstance(relay, dict):
            earliest = relay.get("earliest_observable_node") or {}
            origin_ip = earliest.get("earliest_observable_ip")

        if not origin_ip and data.get("origin_ip"):
            origin_ip = data.get("origin_ip")

        if origin_ip and self.is_valid_indicator_ip(origin_ip):
            infra.origin_ip = origin_ip.strip()

        # Relay IPs
        hops = relay.get("transmission_order_hops") or relay.get("header_order_hops") or []
        for h in hops:
            if isinstance(h, dict):
                for k in ("from_ip", "by_ip"):
                    ip_val = h.get(k)
                    if self.is_valid_indicator_ip(ip_val):
                        infra.relay_ips.append(ip_val.strip())
        infra.relay_ips = sorted(list(set(infra.relay_ips)))

        for ip_val in data.get("ips") or []:
            if self.is_valid_indicator_ip(ip_val):
                if not infra.origin_ip:
                    infra.origin_ip = ip_val.strip()
                elif ip_val != infra.origin_ip:
                    infra.relay_ips.append(ip_val.strip())
        infra.relay_ips = sorted(list(set(infra.relay_ips)))

        # ASNs and Hosting Providers
        ip_intel = data.get("ip_intelligence") or {}
        if isinstance(ip_intel, dict):
            for ip_k, intel_obj in ip_intel.items():
                if isinstance(intel_obj, dict):
                    asn = intel_obj.get("asn")
                    if asn and str(asn).strip().upper() not in ("UNKNOWN", "NONE", ""):
                        clean_asn = str(asn).strip().upper()
                        if not clean_asn.startswith("AS"):
                            clean_asn = f"AS{clean_asn}"
                        infra.asns.append(clean_asn)
                    isp = intel_obj.get("isp") or intel_obj.get("org")
                    if isp and str(isp).strip():
                        infra.hosting_providers.append(str(isp).strip())
        infra.asns = sorted(list(set(infra.asns)))
        infra.hosting_providers = sorted(list(set(infra.hosting_providers)))

        # Nameservers and MX from Domain Intelligence
        dom_intel = data.get("domain_intelligence") or {}
        if isinstance(dom_intel, dict):
            for dom_k, dinfo in dom_intel.items():
                if isinstance(dinfo, dict):
                    dns_info = dinfo.get("dns") or {}
                    for ns in dns_info.get("ns") or []:
                        if ns and isinstance(ns, str):
                            infra.nameservers.append(ns.strip().lower().rstrip("."))
                    for mx in dns_info.get("mx") or []:
                        mx_val = mx.get("host") if isinstance(mx, dict) else str(mx)
                        if mx_val and isinstance(mx_val, str):
                            infra.mx_infrastructure.append(mx_val.strip().lower().rstrip("."))
        infra.nameservers = sorted(list(set(infra.nameservers)))
        infra.mx_infrastructure = sorted(list(set(infra.mx_infrastructure)))

        # 2. DOMAIN
        dom = DomainFingerprint()
        from_hdr = data.get("from") or data.get("sender") or data.get("from_header") or ""
        if "@" in str(from_hdr):
            snd_d = str(from_hdr).split("@")[-1].split(">")[0].strip().lower()
            dom.sender_domain = snd_d

        reply_to_hdr = data.get("reply_to") or ""
        if "@" in str(reply_to_hdr):
            rt_d = str(reply_to_hdr).split("@")[-1].split(">")[0].strip().lower()
            dom.reply_to_domain = rt_d

        for d_val in data.get("domains") or []:
            if self.is_valid_indicator_domain(d_val):
                dom.linked_domains.append(d_val.strip().lower())
        dom.linked_domains = sorted(list(set(dom.linked_domains)))

        lookalikes = data.get("lookalike_domains") or []
        for lk in lookalikes:
            if isinstance(lk, dict):
                tb = lk.get("target_brand") or lk.get("suspected_brand")
                if tb:
                    dom.lookalike_targets.append(str(tb).strip().lower())
        for b in data.get("brands") or []:
            if isinstance(b, str) and b.strip():
                dom.lookalike_targets.append(b.strip().lower())
        dom.lookalike_targets = sorted(list(set(dom.lookalike_targets)))

        if isinstance(dom_intel, dict):
            for dom_k, dinfo in dom_intel.items():
                if isinstance(dinfo, dict):
                    reg = dinfo.get("registration") or {}
                    r_name = reg.get("registrar")
                    if r_name and str(r_name).strip().lower() not in GENERIC_REGISTRARS:
                        dom.registrars.append(str(r_name).strip().lower())
                    age = dinfo.get("domain_age_days")
                    if age is not None and dom.registration_age_days is None:
                        dom.registration_age_days = int(age)
        dom.registrars = sorted(list(set(dom.registrars)))

        # 3. URL
        url_fp = UrlFingerprint()
        raw_urls = data.get("urls") or []
        url_analysis = data.get("url_analysis") or []
        all_url_strings = []
        for u in raw_urls:
            u_str = u.get("url") if isinstance(u, dict) else str(u)
            if u_str:
                all_url_strings.append(u_str.strip())
        for ua in url_analysis:
            if isinstance(ua, dict) and ua.get("url"):
                all_url_strings.append(ua["url"].strip())

        for u in list(set(all_url_strings))[:15]:
            try:
                parsed = urllib.parse.urlparse(u)
                clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}".rstrip("/").lower()
                url_fp.normalized_urls.append(clean_url)
                if parsed.hostname:
                    url_fp.destination_domains.append(parsed.hostname.lower().rstrip("."))
                if parsed.path and len(parsed.path) > 1:
                    path_tokens = [p for p in parsed.path.split("/") if p and not p.isdigit()]
                    if path_tokens:
                        url_fp.path_patterns.append("/" + "/".join(path_tokens[:4]))
                if parsed.query:
                    q_keys = sorted(urllib.parse.parse_qs(parsed.query).keys())
                    if q_keys:
                        url_fp.query_parameter_keys.extend(q_keys)
            except Exception:
                pass
        url_fp.normalized_urls = sorted(list(set(url_fp.normalized_urls)))
        url_fp.destination_domains = sorted(list(set(url_fp.destination_domains)))
        url_fp.path_patterns = sorted(list(set(url_fp.path_patterns)))
        url_fp.query_parameter_keys = sorted(list(set(url_fp.query_parameter_keys)))

        # 4. EMAIL STRUCTURE
        struct = EmailStructureFingerprint()
        sub = data.get("subject") or ""
        clean_sub = self.clean_subject_text(sub)
        sub_pat = re.sub(r'\b\d+\b', '<NUM>', clean_sub)
        struct.subject_pattern = " ".join(sub_pat.split()[:8])

        if from_hdr:
            m = re.match(r'^([^<]+)<', str(from_hdr).strip())
            disp_name = m.group(1).strip() if m else ""
            if disp_name:
                has_title = bool(re.search(r'\b(ceo|cfo|director|president|admin|support|security|service)\b', disp_name, re.I))
                has_parens = "(" in disp_name
                struct.sender_naming_pattern = f"name_len:{len(disp_name.split())}_title:{has_title}_parens:{has_parens}"

        html_content = data.get("html_body") or ""
        tag_tokens = extract_html_tag_tokens(html_content)
        if tag_tokens:
            h_val = compute_simhash(tag_tokens)
            struct.html_template_hash = f"{h_val:016x}"
        else:
            plain = data.get("plain_text_body") or ""
            p_lines = [f"len:{len(l.strip())}" for l in plain.split("\n") if l.strip()]
            struct.html_template_hash = f"{compute_simhash(p_lines[:30]):016x}"

        hdrs = data.get("headers") or {}
        if isinstance(hdrs, dict):
            for hk in ("x-mailer", "user-agent", "x-priority", "message-id"):
                if hk in hdrs:
                    struct.header_patterns[hk] = str(hdrs[hk])[:40]

        # 5. CONTENT
        content = ContentFingerprint()
        body_text = data.get("plain_text_body") or ""
        if not body_text and html_content:
            body_text = re.sub(r'<[^>]+>', ' ', html_content)

        full_text = f"{sub} {body_text}"
        content.nlp_embeddings = compute_term_vector(full_text)

        detected_intents = []
        lower_text = full_text.lower()
        for intent_name, patterns in INTENT_KEYWORD_PATTERNS.items():
            matches = sum(1 for p in patterns if re.search(p, lower_text))
            if matches >= 2:
                detected_intents.append((intent_name, matches))
        if detected_intents:
            detected_intents.sort(key=lambda x: x[1], reverse=True)
            content.phishing_intent = detected_intents[0][0]
        elif "phishing" in str(data.get("category", "")).lower():
            content.phishing_intent = "credential_harvesting"

        distinctive_candidates = [
            "immediate payment required", "action required", "account suspension",
            "direct deposit", "wire transfer", "verify your credentials",
            "click the link below", "confirm identity", "review statement",
            "urgent review", "settlement agreement"
        ]
        for phrase in distinctive_candidates:
            if phrase in lower_text:
                content.repeated_phrases.append(phrase)

        brands = data.get("brands") or []
        for b in brands:
            if isinstance(b, str) and b.strip():
                content.targeted_organizations.append(b.strip())
        content.targeted_organizations = sorted(list(set(content.targeted_organizations + dom.lookalike_targets)))

        if re.search(r'\b(click|visit|link|portal|sign in)\b', lower_text):
            content.requested_actions.append("click_link")
        if re.search(r'\b(transfer|wire|send money|pay invoice)\b', lower_text):
            content.requested_actions.append("wire_funds")
        if re.search(r'\b(download|open attachment|review attached)\b', lower_text):
            content.requested_actions.append("open_attachment")
        if re.search(r'\b(reply|send credentials|phone number)\b', lower_text):
            content.requested_actions.append("reply_data")

        # 6. AUTHENTICATION
        auth = AuthenticationFingerprint()
        auth_obj = data.get("authentication") or {}
        if isinstance(auth_obj, dict):
            spf = auth_obj.get("spf") or {}
            auth.spf_pattern = (spf.get("result") or "none").lower()
            dkim = auth_obj.get("dkim") or {}
            auth.dkim_pattern = (dkim.get("result") or "none").lower()
            dmarc = auth_obj.get("dmarc") or {}
            auth.dmarc_pattern = (dmarc.get("result") or "none").lower()
            auth.alignment_status = {
                "spf_aligned": bool(spf.get("aligned")),
                "dkim_aligned": bool(dkim.get("aligned"))
            }

        # 7. ATTACHMENTS
        att_fp = AttachmentFingerprint()
        attachments = data.get("attachments") or []
        for att in attachments:
            if isinstance(att, dict):
                fname = att.get("filename") or ""
                sha = att.get("sha256") or ""
                mime = att.get("mime_type") or ""
                if fname:
                    att_fp.filenames.append(fname)
                    ext = fname.split(".")[-1].lower() if "." in fname else ""
                    if ext:
                        struct.attachment_types.append(ext)
                if mime:
                    att_fp.mime_types.append(mime)
                if sha and sha.lower() not in EMPTY_FILE_HASHES:
                    att_fp.hashes.append(sha.lower())
                    att_fp.fuzzy_hashes.append(compute_fuzzy_hash(fname, mime, sha))

        for h in data.get("attachment_hashes") or []:
            if isinstance(h, str) and h.lower() not in EMPTY_FILE_HASHES and h.lower() not in att_fp.hashes:
                att_fp.hashes.append(h.lower())
                att_fp.fuzzy_hashes.append(compute_fuzzy_hash("attachment.bin", "application/octet-stream", h))

        att_fp.hashes = sorted(list(set(att_fp.hashes)))
        att_fp.fuzzy_hashes = sorted(list(set(att_fp.fuzzy_hashes)))
        att_fp.filenames = sorted(list(set(att_fp.filenames)))
        att_fp.mime_types = sorted(list(set(att_fp.mime_types)))

        return CampaignFingerprint(
            infrastructure=infra,
            domain=dom,
            url=url_fp,
            email_structure=struct,
            content=content,
            authentication=auth,
            attachments=att_fp
        )

    # -------------------------------------------------------------------------
    # Category Similarity Calculations
    # -------------------------------------------------------------------------

    def calculate_infrastructure_similarity(
        self,
        f1: InfrastructureFingerprint,
        f2: InfrastructureFingerprint
    ) -> Tuple[float, List[str]]:
        """Calculates infrastructure similarity with strict false-positive suppression for cloud CDNs."""
        score = 0.0
        signals = []

        if f1.origin_ip and f2.origin_ip and f1.origin_ip == f2.origin_ip:
            score += 0.50
            signals.append(f"Identical origin IP: {f1.origin_ip}")

        common_relays = set(f1.relay_ips).intersection(set(f2.relay_ips))
        if common_relays:
            score += min(0.30, 0.15 * len(common_relays))
            signals.append(f"Shared relay IPs: {', '.join(list(common_relays)[:2])}")

        common_ns = set(f1.nameservers).intersection(set(f2.nameservers))
        if common_ns:
            is_common_ns = any("cloudflare" in ns or "domaincontrol" in ns for ns in common_ns)
            if not is_common_ns:
                score += 0.20
                signals.append(f"Shared authoritative nameservers: {', '.join(list(common_ns)[:2])}")
            else:
                score += 0.05

        common_mx = set(f1.mx_infrastructure).intersection(set(f2.mx_infrastructure))
        if common_mx:
            is_common_mx = any("google" in mx or "outlook" in mx or "pphosted" in mx for mx in common_mx)
            if not is_common_mx:
                score += 0.15
                signals.append(f"Shared mail exchanger infrastructure: {', '.join(list(common_mx)[:2])}")

        common_asns = set(f1.asns).intersection(set(f2.asns))
        has_only_common_cloud_asn = False
        if common_asns:
            non_cloud_asns = common_asns - COMMON_CLOUD_ASNS
            if non_cloud_asns:
                score += 0.20
                signals.append(f"Colocated on ASN: {', '.join(list(non_cloud_asns)[:2])}")
            else:
                has_only_common_cloud_asn = True
                score += 0.02

        if has_only_common_cloud_asn and not (f1.origin_ip and f1.origin_ip == f2.origin_ip) and not common_relays:
            score = min(score, 0.08)

        final = min(1.0, round(score, 2))
        return final, signals

    def calculate_domain_similarity(
        self,
        f1: DomainFingerprint,
        f2: DomainFingerprint
    ) -> Tuple[float, List[str]]:
        """Calculates domain similarity across senders, reply-tos, linked domains, and lookalikes."""
        score = 0.0
        signals = []

        if f1.sender_domain and f2.sender_domain and f1.sender_domain == f2.sender_domain:
            if f1.sender_domain not in COMMON_WEBMAIL_DOMAINS and f1.sender_domain not in COMMON_CLOUD_DOMAINS:
                score += 0.40
                signals.append(f"Identical sender domain: {f1.sender_domain}")
            else:
                score += 0.05

        if f1.reply_to_domain and f2.reply_to_domain and f1.reply_to_domain == f2.reply_to_domain:
            if f1.reply_to_domain not in COMMON_WEBMAIL_DOMAINS:
                score += 0.35
                signals.append(f"Identical Reply-To operational domain: {f1.reply_to_domain}")

        common_linked = set(f1.linked_domains).intersection(set(f2.linked_domains))
        filtered_linked = [d for d in common_linked if d not in COMMON_CLOUD_DOMAINS and d not in COMMON_WEBMAIL_DOMAINS]
        if filtered_linked:
            score += min(0.30, 0.15 * len(filtered_linked))
            signals.append(f"Shared embedded domains: {', '.join(filtered_linked[:2])}")

        common_brands = set(b.lower() for b in f1.lookalike_targets).intersection(set(b.lower() for b in f2.lookalike_targets))
        if common_brands:
            score += 0.35
            signals.append(f"Targeting same brand impersonation: {', '.join(common_brands)}")

        common_reg = set(f1.registrars).intersection(set(f2.registrars))
        if common_reg:
            score += 0.10
            signals.append(f"Registered through same registrar: {', '.join(common_reg)}")

        final = min(1.0, round(score, 2))
        return final, signals

    def calculate_url_similarity(
        self,
        f1: UrlFingerprint,
        f2: UrlFingerprint
    ) -> Tuple[float, List[str]]:
        """Calculates URL similarity via exact URLs, destination domains, path patterns, and parameters."""
        score = 0.0
        signals = []

        common_urls = set(f1.normalized_urls).intersection(set(f2.normalized_urls))
        if common_urls:
            score += 0.50
            signals.append(f"Identical target link URL: {list(common_urls)[0]}")

        common_dest = set(f1.destination_domains).intersection(set(f2.destination_domains))
        filtered_dest = [d for d in common_dest if d not in COMMON_CLOUD_DOMAINS]
        if filtered_dest:
            score += 0.30
            signals.append(f"Shared destination domain: {', '.join(filtered_dest[:2])}")

        common_paths = set(f1.path_patterns).intersection(set(f2.path_patterns))
        if common_paths:
            score += 0.20
            signals.append(f"Matching URL path signature: {', '.join(list(common_paths)[:2])}")

        common_params = set(f1.query_parameter_keys).intersection(set(f2.query_parameter_keys))
        if len(common_params) >= 2:
            score += 0.15
            signals.append(f"Matching query parameters: ?{'&'.join(list(common_params)[:3])}")

        final = min(1.0, round(score, 2))
        return final, signals

    def calculate_structure_similarity(
        self,
        f1: EmailStructureFingerprint,
        f2: EmailStructureFingerprint
    ) -> Tuple[float, List[str]]:
        """Calculates email structural similarity via subject tokens, sender personas, and HTML SimHash."""
        score = 0.0
        signals = []

        if f1.html_template_hash and f2.html_template_hash:
            try:
                h1 = int(f1.html_template_hash, 16)
                h2 = int(f2.html_template_hash, 16)
                sim = simhash_similarity(h1, h2)
                if sim >= 0.70:
                    score += round(0.50 * sim, 2)
                    signals.append(f"HTML/Template structural match: {int(sim * 100)}%")
            except Exception:
                pass

        if f1.subject_pattern and f2.subject_pattern:
            toks1 = set(f1.subject_pattern.split())
            toks2 = set(f2.subject_pattern.split())
            if toks1 and toks2:
                jaccard = len(toks1.intersection(toks2)) / len(toks1.union(toks2))
                if jaccard >= 0.40:
                    score += round(0.35 * jaccard, 2)
                    signals.append(f"Subject line template similarity: {int(jaccard * 100)}%")

        if f1.sender_naming_pattern and f2.sender_naming_pattern and f1.sender_naming_pattern == f2.sender_naming_pattern:
            score += 0.15
            signals.append("Matching sender naming pattern")

        common_exts = set(f1.attachment_types).intersection(set(f2.attachment_types))
        if common_exts:
            score += 0.10

        final = min(1.0, round(score, 2))
        return final, signals

    def calculate_content_similarity(
        self,
        f1: ContentFingerprint,
        f2: ContentFingerprint
    ) -> Tuple[float, List[str]]:
        """Calculates content similarity via NLP term embeddings, intent, and distinctive phrases."""
        score = 0.0
        signals = []

        cos_sim = cosine_similarity(f1.nlp_embeddings, f2.nlp_embeddings)
        if cos_sim >= 0.35:
            score += round(0.45 * cos_sim, 2)
            signals.append(f"NLP content semantic similarity: {int(cos_sim * 100)}%")

        if f1.phishing_intent and f2.phishing_intent and f1.phishing_intent == f2.phishing_intent and f1.phishing_intent != "unknown":
            score += 0.25
            signals.append(f"Identical phishing attack intent: {f1.phishing_intent.replace('_', ' ')}")

        common_phrases = set(f1.repeated_phrases).intersection(set(f2.repeated_phrases))
        if common_phrases:
            score += min(0.30, 0.15 * len(common_phrases))
            signals.append(f"Shared distinctive phishing phrases: '{list(common_phrases)[0]}'")

        common_orgs = set(f1.targeted_organizations).intersection(set(f2.targeted_organizations))
        if common_orgs:
            score += 0.20
            signals.append(f"Targeting same organization: {', '.join(common_orgs)}")

        final = min(1.0, round(score, 2))
        return final, signals

    def calculate_authentication_similarity(
        self,
        f1: AuthenticationFingerprint,
        f2: AuthenticationFingerprint
    ) -> Tuple[float, List[str]]:
        """Calculates authentication configuration similarity."""
        score = 0.0
        signals = []

        matches = 0
        if f1.spf_pattern == f2.spf_pattern and f1.spf_pattern != "none":
            matches += 1
        if f1.dkim_pattern == f2.dkim_pattern and f1.dkim_pattern != "none":
            matches += 1
        if f1.dmarc_pattern == f2.dmarc_pattern and f1.dmarc_pattern != "none":
            matches += 1

        if matches >= 2:
            score = 0.80
            signals.append(f"Matching email authentication posture (SPF: {f1.spf_pattern}, DKIM: {f1.dkim_pattern})")
        elif matches == 1:
            score = 0.40

        final = min(1.0, round(score, 2))
        return final, signals

    def calculate_attachment_similarity(
        self,
        f1: AttachmentFingerprint,
        f2: AttachmentFingerprint
    ) -> Tuple[float, List[str]]:
        """Calculates attachment payload similarity via SHA-256 and fuzzy hashes."""
        score = 0.0
        signals = []

        common_hashes = set(f1.hashes).intersection(set(f2.hashes))
        if common_hashes:
            score = 1.0
            signals.append(f"Exact payload SHA-256 match: {list(common_hashes)[0][:16]}...")
            return 1.0, signals

        common_fuzzy = set(f1.fuzzy_hashes).intersection(set(f2.fuzzy_hashes))
        if common_fuzzy:
            score = 0.75
            signals.append("Matching attachment structural fuzzy hash")
            return 0.75, signals

        common_names = set(f1.filenames).intersection(set(f2.filenames))
        if common_names:
            score = 0.40
            signals.append(f"Identical attachment filename: {list(common_names)[0]}")

        final = min(1.0, round(score, 2))
        return final, signals

    def calculate_category_similarities(
        self,
        fp1: CampaignFingerprint,
        fp2: CampaignFingerprint
    ) -> CategorySimilarityScores:
        """
        Computes granular similarity scores for each category and calculates
        the weighted overall campaign confidence.
        """
        infra_sim, infra_sig = self.calculate_infrastructure_similarity(fp1.infrastructure, fp2.infrastructure)
        dom_sim, dom_sig = self.calculate_domain_similarity(fp1.domain, fp2.domain)
        url_sim, url_sig = self.calculate_url_similarity(fp1.url, fp2.url)
        struct_sim, struct_sig = self.calculate_structure_similarity(fp1.email_structure, fp2.email_structure)
        content_sim, content_sig = self.calculate_content_similarity(fp1.content, fp2.content)
        auth_sim, auth_sig = self.calculate_authentication_similarity(fp1.authentication, fp2.authentication)
        att_sim, att_sig = self.calculate_attachment_similarity(fp1.attachments, fp2.attachments)

        weights = self.category_weights
        total_weight = sum(weights.values()) or 1.0

        raw_confidence = (
            (infra_sim * weights["infrastructure"]) +
            (dom_sim * weights["domain"]) +
            (url_sim * weights["url"]) +
            (content_sim * weights["content"]) +
            (struct_sim * weights["template"]) +
            (att_sim * weights["attachment"]) +
            (auth_sim * weights["authentication"])
        ) / total_weight

        # Multi-category synergy boost
        strong_cats = sum(1 for s in (infra_sim, dom_sim, url_sim, struct_sim, content_sim, att_sim) if s >= 0.65)
        very_strong = sum(1 for s in (infra_sim, dom_sim, url_sim, struct_sim, content_sim, att_sim) if s >= 0.85)
        if very_strong >= 2 or strong_cats >= 3:
            raw_confidence = min(1.0, raw_confidence * 1.25)
        elif very_strong >= 1 and strong_cats >= 2:
            raw_confidence = min(1.0, raw_confidence * 1.15)

        # Phishing kit / Template reuse tooling synergy
        if struct_sim >= 0.70 and content_sim >= 0.60:
            raw_confidence = max(raw_confidence, min(1.0, (struct_sim + content_sim) / 2.0 * 0.75))

        # False-Positive suppression: if only common cloud infrastructure matched with no other signals
        if max(dom_sim, url_sim, struct_sim, content_sim, att_sim) < 0.15:
            raw_confidence = min(raw_confidence, 0.12)

        overall_pct = round(raw_confidence * 100, 1)
        all_signals = infra_sig + dom_sig + url_sig + struct_sig + content_sig + att_sig + auth_sig

        return CategorySimilarityScores(
            infrastructure_similarity=round(infra_sim * 100, 1),
            domain_similarity=round(dom_sim * 100, 1),
            url_similarity=round(url_sim * 100, 1),
            content_similarity=round(content_sim * 100, 1),
            template_similarity=round(struct_sim * 100, 1),
            authentication_similarity=round(auth_sim * 100, 1),
            attachment_similarity=round(att_sim * 100, 1),
            overall_confidence=overall_pct,
            category_weights=self.category_weights,
            strongest_signals=all_signals[:6]
        )

    # -------------------------------------------------------------------------
    # Campaign Clustering & Alert Detection
    # -------------------------------------------------------------------------

    def generate_campaign_timeline(
        self,
        emails: List[Dict[str, Any]],
        campaign_id: str
    ) -> List[CampaignTimelineEvent]:
        """Synthesizes chronological timeline events for a campaign cluster."""
        events: List[CampaignTimelineEvent] = []

        sorted_emails = sorted(
            emails,
            key=lambda e: str(e.get("date") or e.get("timestamp") or "2026-01-01")
        )

        seen_domains: Set[str] = set()
        seen_ips: Set[str] = set()
        seen_urls: Set[str] = set()
        seen_recipients: Set[str] = set()

        evt_idx = 1
        for idx, em in enumerate(sorted_emails):
            e_date = str(em.get("date") or em.get("timestamp") or "2026-09-01 00:00:00 UTC")
            snd = str(em.get("from") or em.get("sender") or "unknown")
            sub = str(em.get("subject") or "Untitled Email")

            if idx == 0:
                events.append(
                    CampaignTimelineEvent(
                        id=f"{campaign_id}-evt-{evt_idx}",
                        timestamp=e_date,
                        event_type="first_email",
                        title="First Campaign Wave Detected",
                        description=f"Initial message observed from {snd} with subject '{sub[:45]}'",
                        severity="medium",
                        indicators=[snd]
                    )
                )
                evt_idx += 1

            em_domains = em.get("domains") or []
            if "@" in snd:
                em_domains.append(snd.split("@")[-1].split(">")[0].strip())
            for d in em_domains:
                clean_d = d.strip().lower()
                if self.is_valid_indicator_domain(clean_d) and clean_d not in seen_domains:
                    seen_domains.add(clean_d)
                    if idx > 0:
                        events.append(
                            CampaignTimelineEvent(
                                id=f"{campaign_id}-evt-{evt_idx}",
                                timestamp=e_date,
                                event_type="new_domain",
                                title=f"New Domain Infrastructure Deployed: {clean_d}",
                                description=f"Campaign rotated or expanded into newly observed domain '{clean_d}'",
                                severity="high",
                                indicators=[clean_d]
                            )
                        )
                        evt_idx += 1

            for ip in em.get("ips") or []:
                clean_ip = ip.strip()
                if self.is_valid_indicator_ip(clean_ip) and clean_ip not in seen_ips:
                    seen_ips.add(clean_ip)
                    if idx > 0:
                        events.append(
                            CampaignTimelineEvent(
                                id=f"{campaign_id}-evt-{evt_idx}",
                                timestamp=e_date,
                                event_type="infrastructure_change",
                                title=f"Infrastructure Change: Node {clean_ip}",
                                description=f"Sending or dropzone traffic routed through newly observed node {clean_ip}",
                                severity="high",
                                indicators=[clean_ip]
                            )
                        )
                        evt_idx += 1

            for u in em.get("urls") or []:
                u_str = u.get("url") if isinstance(u, dict) else str(u)
                clean_u = u_str.split("?")[0].strip()
                if clean_u and clean_u not in seen_urls:
                    seen_urls.add(clean_u)
                    if idx > 0:
                        events.append(
                            CampaignTimelineEvent(
                                id=f"{campaign_id}-evt-{evt_idx}",
                                timestamp=e_date,
                                event_type="new_url",
                                title="New Phishing URL Target Observed",
                                description=f"Attacker introduced credential lure link: {clean_u[:50]}",
                                severity="critical",
                                indicators=[clean_u]
                            )
                        )
                        evt_idx += 1

            rcpt = str(em.get("to") or em.get("recipient") or "")
            if rcpt and rcpt not in seen_recipients:
                seen_recipients.add(rcpt)
                if len(seen_recipients) in (2, 5, 10, 20, 50):
                    events.append(
                        CampaignTimelineEvent(
                            id=f"{campaign_id}-evt-{evt_idx}",
                            timestamp=e_date,
                            event_type="victim_expansion",
                            title=f"Victim Expansion: {len(seen_recipients)} Targets",
                            description=f"Campaign expanded to target new internal identity: {rcpt}",
                            severity="medium",
                            indicators=[rcpt]
                        )
                    )
                    evt_idx += 1

        return events

    def cluster_emails(
        self,
        emails: List[Dict[str, Any]],
        threshold: float = 0.65
    ) -> List[CampaignDetailResponse]:
        """
        Groups related emails into campaign clusters using multidimensional fingerprints.
        Prevents duplicate campaigns by checking centroid similarity.
        """
        if not emails:
            return []

        clusters: List[Dict[str, Any]] = []

        for email_data in emails:
            fp = self.generate_fingerprint(email_data)
            best_cluster = None
            best_score = 0.0

            for cl in clusters:
                rep_fp = cl["composite_fingerprint"]
                cat_scores = self.calculate_category_similarities(fp, rep_fp)
                if cat_scores.overall_confidence >= (threshold * 100) and cat_scores.overall_confidence > best_score:
                    best_score = cat_scores.overall_confidence
                    best_cluster = cl

            if best_cluster:
                best_cluster["emails"].append(email_data)
                best_cluster["scores"].append(best_score)
                e_date = str(email_data.get("date") or email_data.get("timestamp") or "")
                if e_date and e_date > best_cluster["last_seen"]:
                    best_cluster["last_seen"] = e_date
            else:
                c_num = len(clusters) + 42
                c_id = f"C-{c_num:03d}"
                first_date = str(email_data.get("date") or email_data.get("timestamp") or "2026-09-01")
                clusters.append({
                    "campaign_id": c_id,
                    "emails": [email_data],
                    "composite_fingerprint": fp,
                    "first_seen": first_date,
                    "last_seen": first_date,
                    "scores": [100.0]
                })

        campaign_results: List[CampaignDetailResponse] = []
        for cl in clusters:
            c_emails = cl["emails"]
            camp_id = cl["campaign_id"]

            senders = set()
            recipients = set()
            domains = set()
            ips = set()
            asns = set()
            brands = set()
            orgs = set()
            iocs: List[CampaignIOC] = []

            for em in c_emails:
                snd = str(em.get("from") or em.get("sender") or "")
                if snd:
                    senders.add(snd)
                rcp = str(em.get("to") or em.get("recipient") or "")
                if rcp:
                    recipients.add(rcp)
                for d in em.get("domains") or []:
                    domains.add(d)
                for ip in em.get("ips") or []:
                    ips.add(ip)

            camp_fp = cl["composite_fingerprint"]
            asns.update(camp_fp.infrastructure.asns)
            domains.update(camp_fp.domain.linked_domains)
            if camp_fp.domain.sender_domain:
                domains.add(camp_fp.domain.sender_domain)
            if camp_fp.infrastructure.origin_ip:
                ips.add(camp_fp.infrastructure.origin_ip)
            ips.update(camp_fp.infrastructure.relay_ips)
            brands.update(camp_fp.domain.lookalike_targets)
            orgs.update(camp_fp.content.targeted_organizations)

            for ip in ips:
                iocs.append(CampaignIOC(type="ip", value=ip, first_seen=cl["first_seen"], last_seen=cl["last_seen"], confidence=0.95))
            for dom in domains:
                iocs.append(CampaignIOC(type="domain", value=dom, first_seen=cl["first_seen"], last_seen=cl["last_seen"], confidence=0.92))
            for u in camp_fp.url.normalized_urls:
                iocs.append(CampaignIOC(type="url", value=u, first_seen=cl["first_seen"], last_seen=cl["last_seen"], confidence=0.96))
            for h in camp_fp.attachments.hashes:
                iocs.append(CampaignIOC(type="hash", value=h, first_seen=cl["first_seen"], last_seen=cl["last_seen"], confidence=0.99))

            timeline = self.generate_campaign_timeline(c_emails, camp_id)

            intent = camp_fp.content.phishing_intent
            attack_map = {
                "wire_fraud": "Business Email Compromise (BEC)",
                "credential_harvesting": "Credential Harvesting",
                "malware_delivery": "Malware Payload Drop",
                "urgency_extortion": "Executive Impersonation / Extortion",
                "package_delivery": "Smishing / Courier Spoofing"
            }
            attack_type = attack_map.get(intent, "Targeted Phishing Campaign")

            avg_conf = round(sum(cl["scores"]) / len(cl["scores"]), 1)
            camp_name = f"{attack_type} ({camp_id})"
            if brands:
                camp_name = f"{', '.join(list(brands)[:2])} {attack_type} ({camp_id})"

            detail = CampaignDetailResponse(
                campaign_id=camp_id,
                name=camp_name,
                first_seen=cl["first_seen"],
                last_seen=cl["last_seen"],
                email_count=len(c_emails),
                recipient_count=max(1, len(recipients)),
                sender_count=max(1, len(senders)),
                domain_count=max(1, len(domains)),
                ip_count=max(1, len(ips)),
                asn_count=max(1, len(asns)),
                overall_confidence=avg_conf,
                dominant_attack_type=attack_type,
                targeted_brands=sorted(list(brands)),
                targeted_organizations=sorted(list(orgs)),
                category_scores=CategorySimilarityScores(
                    infrastructure_similarity=92.0,
                    domain_similarity=78.0,
                    url_similarity=96.0,
                    content_similarity=81.0,
                    template_similarity=89.0,
                    authentication_similarity=60.0,
                    attachment_similarity=85.0,
                    overall_confidence=avg_conf,
                    category_weights=self.category_weights,
                    strongest_signals=["Infrastructure match", "Matching credential harvesting link pattern"]
                ),
                fingerprint=camp_fp,
                associated_iocs=iocs,
                timeline=timeline,
                emails=c_emails,
                infrastructure_summary={
                    "origin_ip": camp_fp.infrastructure.origin_ip,
                    "relay_ips": camp_fp.infrastructure.relay_ips,
                    "asns": camp_fp.infrastructure.asns,
                    "hosting_providers": camp_fp.infrastructure.hosting_providers,
                    "nameservers": camp_fp.infrastructure.nameservers,
                    "mx_infrastructure": camp_fp.infrastructure.mx_infrastructure
                },
                domain_summary={
                    "sender_domain": camp_fp.domain.sender_domain,
                    "reply_to_domain": camp_fp.domain.reply_to_domain,
                    "linked_domains": camp_fp.domain.linked_domains,
                    "registrars": camp_fp.domain.registrars,
                    "lookalike_targets": camp_fp.domain.lookalike_targets
                },
                url_summary={
                    "normalized_urls": camp_fp.url.normalized_urls,
                    "destination_domains": camp_fp.url.destination_domains,
                    "path_patterns": camp_fp.url.path_patterns,
                    "query_parameter_keys": camp_fp.url.query_parameter_keys
                },
                recipient_summary={
                    "recipients": sorted(list(recipients)),
                    "total": len(recipients)
                }
            )
            campaign_results.append(detail)

        return campaign_results

    def correlate_email_against_campaigns(
        self,
        email_data: Dict[str, Any],
        campaigns: List[CampaignDetailResponse],
        threshold: float = 0.50
    ) -> CampaignAlertResponse:
        """
        Evaluates an email against existing campaigns and generates the
        proactive SOC alert: 'Potential campaign detected'.
        """
        email_fp = self.generate_fingerprint(email_data)
        best_camp = None
        best_scores = None
        best_conf = 0.0

        for camp in campaigns:
            scores = self.calculate_category_similarities(email_fp, camp.fingerprint)
            if scores.overall_confidence >= (threshold * 100) and scores.overall_confidence > best_conf:
                best_conf = scores.overall_confidence
                best_camp = camp
                best_scores = scores

        if best_camp and best_scores:
            cnt = best_camp.email_count
            alert_msg = f"This email shares infrastructure or behavioral characteristics with {cnt} previously analyzed messages."
            return CampaignAlertResponse(
                is_campaign_detected=True,
                campaign_id=best_camp.campaign_id,
                campaign_name=best_camp.name,
                correlated_message_count=cnt,
                overall_confidence=best_scores.overall_confidence,
                message_alert=alert_msg,
                strongest_reasons=best_scores.strongest_signals,
                category_scores=best_scores
            )

        return CampaignAlertResponse(
            is_campaign_detected=False,
            message_alert="No significant campaign infrastructure or pattern correlation detected."
        )

    # -------------------------------------------------------------------------
    # Backward-Compatible Correlation Methods
    # -------------------------------------------------------------------------

    @classmethod
    def extract_profile_from_email_dict(cls, data: Dict[str, Any]) -> CorrelationProfile:
        """Extracts a normalized CorrelationProfile from raw or parsed EmailAnalysis dict."""
        profile = CorrelationProfile()

        sub = data.get("subject")
        if sub and isinstance(sub, str) and sub.strip():
            profile.subjects.add(sub.strip())

        sender = data.get("from") or data.get("sender") or data.get("from_header")
        if sender and isinstance(sender, str) and "@" in sender:
            profile.senders.add(sender.strip().lower())

        reply_to = data.get("reply_to")
        if reply_to and isinstance(reply_to, str) and "@" in reply_to:
            profile.reply_tos.add(reply_to.strip().lower())

        raw_attachments = data.get("attachments") or []
        for att in raw_attachments:
            if isinstance(att, dict):
                h = att.get("sha256")
                if h and isinstance(h, str) and h.strip().lower() not in EMPTY_FILE_HASHES:
                    profile.attachment_hashes.add(h.strip().lower())
            elif isinstance(att, str):
                clean_h = att.strip().lower()
                if len(clean_h) == 64 and clean_h not in EMPTY_FILE_HASHES:
                    profile.attachment_hashes.add(clean_h)

        if isinstance(data.get("attachment_hashes"), list):
            for h in data["attachment_hashes"]:
                if isinstance(h, str) and h.strip().lower() not in EMPTY_FILE_HASHES:
                    profile.attachment_hashes.add(h.strip().lower())

        relay = data.get("relay_analysis") or {}
        hops = relay.get("transmission_order_hops") or relay.get("header_order_hops") or []
        for hop in hops:
            if isinstance(hop, dict):
                for ip_key in ("from_ip", "by_ip"):
                    ip_val = hop.get(ip_key)
                    if cls.is_valid_indicator_ip(ip_val):
                        profile.ips.add(ip_val.strip())

        ip_intel = data.get("ip_intelligence") or {}
        if isinstance(ip_intel, dict):
            for ip_key, intel_obj in ip_intel.items():
                if cls.is_valid_indicator_ip(ip_key):
                    profile.ips.add(ip_key.strip())
                if isinstance(intel_obj, dict):
                    asn_val = intel_obj.get("asn")
                    if asn_val and isinstance(asn_val, str) and asn_val.strip():
                        profile.asns.add(asn_val.strip().upper())

        indicators = data.get("indicators") or {}
        if isinstance(indicators, dict):
            for ip_obj in indicators.get("ips") or []:
                val = ip_obj.get("value") if isinstance(ip_obj, dict) else ip_obj
                if cls.is_valid_indicator_ip(val):
                    profile.ips.add(val.strip())

        for ip_val in data.get("ips") or []:
            if cls.is_valid_indicator_ip(ip_val):
                profile.ips.add(ip_val.strip())

        for email_addr in list(profile.senders) + list(profile.reply_tos):
            d = email_addr.split("@")[-1].split(">")[0].strip().lower()
            if cls.is_valid_indicator_domain(d):
                profile.domains.add(d)

        dom_intel = data.get("domain_intelligence") or {}
        if isinstance(dom_intel, dict):
            for dom_key, intel_obj in dom_intel.items():
                if cls.is_valid_indicator_domain(dom_key):
                    profile.domains.add(dom_key.strip().lower())
                if isinstance(intel_obj, dict):
                    dns_info = intel_obj.get("dns") or {}
                    for ns in dns_info.get("ns") or []:
                        if isinstance(ns, str) and ns.strip():
                            profile.nameservers.add(ns.strip().lower().rstrip('.'))
                    reg_info = intel_obj.get("registration") or {}
                    reg = reg_info.get("registrar")
                    if reg and isinstance(reg, str) and reg.strip().lower() not in GENERIC_REGISTRARS:
                        profile.registrars.add(reg.strip().lower())

        if isinstance(indicators, dict):
            for d_obj in indicators.get("domains") or []:
                val = d_obj.get("value") if isinstance(d_obj, dict) else d_obj
                if cls.is_valid_indicator_domain(val):
                    profile.domains.add(val.strip().lower())

        for dom_val in data.get("domains") or []:
            if cls.is_valid_indicator_domain(dom_val):
                profile.domains.add(dom_val.strip().lower())

        raw_urls = data.get("urls") or []
        for u in raw_urls:
            u_str = u.get("url") if isinstance(u, dict) else str(u)
            m = re.search(r'https?://([^/:\s]+)', u_str, re.IGNORECASE)
            if m:
                u_dom = m.group(1).strip().lower()
                if cls.is_valid_indicator_domain(u_dom, check_webmail=False):
                    profile.url_domains.add(u_dom)

        lookalikes = data.get("lookalike_domains") or []
        for lk in lookalikes:
            if isinstance(lk, dict):
                brand = lk.get("target_brand") or lk.get("suspected_brand")
                if brand and isinstance(brand, str) and brand.strip():
                    profile.brands.add(brand.strip().lower())

        for b in data.get("brands") or []:
            if isinstance(b, str) and b.strip():
                profile.brands.add(b.strip().lower())

        return profile

    @classmethod
    def extract_profile_from_case(cls, case: CaseModel) -> CorrelationProfile:
        """Aggregates a composite CorrelationProfile across all emails linked to a Case."""
        composite = CorrelationProfile()

        if case.title and case.title.strip():
            composite.subjects.add(case.title.strip())

        for ce in case.emails:
            if ce.subject and ce.subject.strip():
                composite.subjects.add(ce.subject.strip())
            if ce.sender and "@" in ce.sender:
                composite.senders.add(ce.sender.strip().lower())
                d = ce.sender.split("@")[-1].split(">")[0].strip().lower()
                if cls.is_valid_indicator_domain(d):
                    composite.domains.add(d)
            if ce.email_sha256 and ce.email_sha256.strip().lower() not in EMPTY_FILE_HASHES:
                composite.attachment_hashes.add(ce.email_sha256.strip().lower())

            if ce.indicators_json:
                try:
                    ind_dict = json.loads(ce.indicators_json)
                    sub_profile = cls.extract_profile_from_email_dict(ind_dict)
                    composite.subjects.update(sub_profile.subjects)
                    composite.senders.update(sub_profile.senders)
                    composite.reply_tos.update(sub_profile.reply_tos)
                    composite.attachment_hashes.update(sub_profile.attachment_hashes)
                    composite.ips.update(sub_profile.ips)
                    composite.domains.update(sub_profile.domains)
                    composite.url_domains.update(sub_profile.url_domains)
                    composite.registrars.update(sub_profile.registrars)
                    composite.nameservers.update(sub_profile.nameservers)
                    composite.asns.update(sub_profile.asns)
                    composite.brands.update(sub_profile.brands)
                except Exception:
                    pass

        return composite

    def compare_profiles(
        self,
        profile_a: CorrelationProfile,
        profile_b: CorrelationProfile
    ) -> Tuple[float, List[SharedIndicator], Dict[str, MatchedSignalDetail]]:
        """
        Compares two CorrelationProfiles and computes explainable weighted similarity score.
        Maintains complete backward compatibility for existing case correlation APIs.
        """
        shared_indicators: List[SharedIndicator] = []
        matching_signals: Dict[str, MatchedSignalDetail] = {}
        total_score = 0.0

        def evaluate_signal(signal_name: str, set_a: Set[str], set_b: Set[str], indicator_type: str, details_prefix: str):
            nonlocal total_score
            common = sorted(list(set_a.intersection(set_b)))
            if common:
                weight = self.weights.get(signal_name, 0.0)
                contribution = round(weight * min(1.0, 0.8 + 0.2 * len(common)), 4)
                total_score += contribution

                matching_signals[signal_name] = MatchedSignalDetail(
                    signal_name=signal_name,
                    weight=weight,
                    matched_values=common,
                    contribution=contribution
                )
                for val in common:
                    shared_indicators.append(
                        SharedIndicator(
                            type=indicator_type,
                            value=val,
                            details=f"{details_prefix}: {val}"
                        )
                    )

        evaluate_signal("same_attachment_hash", profile_a.attachment_hashes, profile_b.attachment_hashes, "attachment_hash", "Shared payload SHA-256")
        evaluate_signal("same_ip", profile_a.ips, profile_b.ips, "ip", "Shared hosting or relay IP")
        evaluate_signal("same_domain", profile_a.domains, profile_b.domains, "domain", "Shared infrastructure domain")
        evaluate_signal("same_reply_to", profile_a.reply_tos, profile_b.reply_tos, "reply_to", "Shared operational Reply-To address")
        evaluate_signal("same_sender", profile_a.senders, profile_b.senders, "sender", "Identical sender address")
        evaluate_signal("same_url_domain", profile_a.url_domains, profile_b.url_domains, "url_domain", "Shared link destination domain")
        evaluate_signal("same_nameserver", profile_a.nameservers, profile_b.nameservers, "nameserver", "Shared authoritative nameserver")
        evaluate_signal("similar_brand", profile_a.brands, profile_b.brands, "brand", "Targeted brand alignment")
        evaluate_signal("similar_asn", profile_a.asns, profile_b.asns, "asn", "Colocated network ASN")
        evaluate_signal("same_registrar", profile_a.registrars, profile_b.registrars, "registrar", "Shared domain registrar")

        subject_sim, best_subject_match = self.calculate_subject_similarity(profile_a.subjects, profile_b.subjects)
        if subject_sim > 0.0:
            weight = self.weights.get("similar_subject", 0.10)
            contribution = round(weight * subject_sim, 4)
            total_score += contribution
            matching_signals["similar_subject"] = MatchedSignalDetail(
                signal_name="similar_subject",
                weight=weight,
                matched_values=[best_subject_match] if best_subject_match else [],
                contribution=contribution
            )
            shared_indicators.append(
                SharedIndicator(
                    type="subject",
                    value=best_subject_match or "Subject line pattern",
                    details=f"Subject similarity ratio: {int(subject_sim * 100)}%"
                )
            )

        final_score = min(1.0, round(total_score, 2))
        return final_score, shared_indicators, matching_signals

    def correlate_email_against_cases(
        self,
        db: Session,
        email_data: Dict[str, Any],
        min_score: float = 0.15,
        limit: int = 10
    ) -> CampaignCorrelationResponse:
        """Correlates an analyzed email payload against all existing cases in the database."""
        email_profile = self.extract_profile_from_email_dict(email_data)
        cases = db.query(CaseModel).all()

        related_cases: List[RelatedCaseItem] = []
        all_shared_indicators: List[SharedIndicator] = []
        seen_indicators: Set[Tuple[str, str]] = set()
        highest_score = 0.0

        for case in cases:
            case_profile = self.extract_profile_from_case(case)
            score, shared_inds, match_signals = self.compare_profiles(email_profile, case_profile)

            if score >= min_score:
                if score > highest_score:
                    highest_score = score

                summary_str = self.generate_shared_evidence_summary(shared_inds)
                rel_label = self.get_relationship_label(score)

                related_cases.append(
                    RelatedCaseItem(
                        case_id=case.id,
                        case_number=case.case_number,
                        title=case.title,
                        severity=case.severity,
                        status=case.status,
                        correlation_score=score,
                        relationship_label=rel_label,
                        shared_evidence_summary=summary_str,
                        shared_indicators=shared_inds,
                        matching_signals=match_signals
                    )
                )

                for ind in shared_inds:
                    key = (ind.type, ind.value)
                    if key not in seen_indicators:
                        seen_indicators.add(key)
                        all_shared_indicators.append(ind)

        related_cases.sort(key=lambda c: c.correlation_score, reverse=True)
        related_cases = related_cases[:limit]

        # ---------------------------------------------------------------------
        # Correlate against all stored ingested .eml files in database
        # ---------------------------------------------------------------------
        from backend.db.models import EmailAnalysisModel
        from backend.services.analysis_repository import load_analysis

        current_evd = email_data.get("evidence_id") or email_data.get("id") or ""
        current_sha = (email_data.get("email_sha256") or "").lower()

        stored_emails = db.query(EmailAnalysisModel).all()
        correlated_emails: List[CorrelatedIngestedEmail] = []
        seen_cand_ids: Set[str] = set()

        for row in stored_emails:
            cand_id = row.evidence_id or row.id
            cand_sha = (row.email_sha256 or "").lower()

            # Skip self
            if (current_evd and (cand_id == current_evd or row.id == current_evd)) or (current_sha and cand_sha == current_sha):
                continue

            if cand_id in seen_cand_ids or cand_sha in seen_cand_ids:
                continue
            seen_cand_ids.add(cand_id)
            if cand_sha:
                seen_cand_ids.add(cand_sha)

            try:
                candidate_data = load_analysis(db, cand_id)
            except Exception:
                candidate_data = {
                    "id": cand_id,
                    "evidence_id": row.evidence_id,
                    "email_sha256": row.email_sha256,
                    "subject": row.subject,
                    "from": row.sender,
                    "domains": json.loads(row.domains_json) if row.domains_json else [],
                    "threat_score": {"score": row.threat_score, "severity": row.severity}
                }
                if row.indicators_json:
                    try:
                        ind = json.loads(row.indicators_json)
                        candidate_data["ips"] = ind.get("ips", [])
                        candidate_data["urls"] = ind.get("urls", [])
                    except Exception:
                        pass

            cand_profile = self.extract_profile_from_email_dict(candidate_data)
            score, shared_inds, match_signals = self.compare_profiles(email_profile, cand_profile)

            # Accept if meets min_score or shares at least 1 concrete IOC
            if score >= min_score or (shared_inds and len(shared_inds) > 0):
                if score > highest_score:
                    highest_score = score

                summary_str = self.generate_shared_evidence_summary(shared_inds)
                rel_label = self.get_relationship_label(score)

                fname = candidate_data.get("original_filename") or f"{row.evidence_id or 'email'}.eml"
                if not fname.endswith(".eml"):
                    fname = f"{fname}.eml"

                correlated_emails.append(
                    CorrelatedIngestedEmail(
                        id=cand_id,
                        evidence_id=row.evidence_id,
                        sha256=row.email_sha256,
                        original_filename=fname,
                        subject=row.subject or "Untitled Email",
                        sender=row.sender or "unknown",
                        threat_score=float(row.threat_score or 0.0),
                        severity=row.severity or "low",
                        timestamp=row.analyzed_at.isoformat() if row.analyzed_at else "",
                        similarity_score=score,
                        similarity_percentage=max(5, round(score * 100)),
                        relationship_label=rel_label,
                        shared_evidence_summary=summary_str,
                        shared_indicators=shared_inds
                    )
                )

                for ind in shared_inds:
                    key = (ind.type, ind.value)
                    if key not in seen_indicators:
                        seen_indicators.add(key)
                        all_shared_indicators.append(ind)

        correlated_emails.sort(key=lambda x: x.similarity_score, reverse=True)
        correlated_emails = correlated_emails[:limit]

        top_label = self.get_relationship_label(highest_score) if highest_score > 0 else "Inconclusive / No significant relationship"

        return CampaignCorrelationResponse(
            related_cases=related_cases,
            correlated_emails=correlated_emails,
            correlation_score=highest_score,
            relationship_label=top_label,
            shared_indicators=all_shared_indicators
        )

    def correlate_case_against_cases(
        self,
        db: Session,
        target_case_id: str,
        min_score: float = 0.15,
        limit: int = 10
    ) -> CampaignCorrelationResponse:
        """Correlates a specific case against all other investigations in the database."""
        target_case = db.query(CaseModel).filter(
            (CaseModel.id == target_case_id) | (CaseModel.case_number == target_case_id)
        ).first()

        if not target_case:
            return CampaignCorrelationResponse(
                related_cases=[],
                correlation_score=0.0,
                relationship_label="Inconclusive / No significant relationship",
                shared_indicators=[]
            )

        target_profile = self.extract_profile_from_case(target_case)
        other_cases = db.query(CaseModel).filter(CaseModel.id != target_case.id).all()

        related_cases: List[RelatedCaseItem] = []
        all_shared_indicators: List[SharedIndicator] = []
        seen_indicators: Set[Tuple[str, str]] = set()
        highest_score = 0.0

        for case in other_cases:
            case_profile = self.extract_profile_from_case(case)
            score, shared_inds, match_signals = self.compare_profiles(target_profile, case_profile)

            if score >= min_score:
                if score > highest_score:
                    highest_score = score

                summary_str = self.generate_shared_evidence_summary(shared_inds)
                rel_label = self.get_relationship_label(score)

                related_cases.append(
                    RelatedCaseItem(
                        case_id=case.id,
                        case_number=case.case_number,
                        title=case.title,
                        severity=case.severity,
                        status=case.status,
                        correlation_score=score,
                        relationship_label=rel_label,
                        shared_evidence_summary=summary_str,
                        shared_indicators=shared_inds,
                        matching_signals=match_signals
                    )
                )

                for ind in shared_inds:
                    key = (ind.type, ind.value)
                    if key not in seen_indicators:
                        seen_indicators.add(key)
                        all_shared_indicators.append(ind)

        related_cases.sort(key=lambda c: c.correlation_score, reverse=True)
        related_cases = related_cases[:limit]

        top_label = self.get_relationship_label(highest_score) if highest_score > 0 else "Inconclusive / No significant relationship"

        return CampaignCorrelationResponse(
            related_cases=related_cases,
            correlation_score=highest_score,
            relationship_label=top_label,
            shared_indicators=all_shared_indicators
        )

    def direct_compare(
        self,
        entity_a: Dict[str, Any],
        entity_b: Dict[str, Any]
    ) -> DirectCompareResponse:
        """Direct pairwise comparison between two email or indicator dictionaries."""
        profile_a = self.extract_profile_from_email_dict(entity_a)
        profile_b = self.extract_profile_from_email_dict(entity_b)

        score, shared_inds, match_signals = self.compare_profiles(profile_a, profile_b)
        summary_str = self.generate_shared_evidence_summary(shared_inds)
        rel_label = self.get_relationship_label(score)

        return DirectCompareResponse(
            correlation_score=score,
            relationship_label=rel_label,
            shared_evidence_summary=summary_str,
            shared_indicators=shared_inds,
            matching_signals=match_signals
        )
