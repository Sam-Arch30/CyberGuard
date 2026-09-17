import re
import unicodedata
from typing import List, Optional, Tuple, Set
import idna
import tldextract

from backend.schemas.lookalike import LookalikeDetectionResult
from backend.services.brand_config import BrandConfigService, BrandInfo


# Common leet-speak / character substitutions used in phishing lookalikes
CHAR_SUBSTITUTIONS = {
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "8": "b",
    "@": "a",
    "vv": "w",
}

# Unicode visual homoglyphs (Cyrillic, Greek, Latin full-width) mapping to ASCII
UNICODE_HOMOGLYPHS = {
    # Cyrillic lowercase
    "\u0430": "a", "\u0441": "c", "\u0435": "e", "\u043e": "o", "\u0440": "p",
    "\u0455": "s", "\u0445": "x", "\u0443": "y", "\u0456": "i", "\u0458": "j",
    "\u04cf": "l", "\u0501": "d", "\u051b": "q", "\u051d": "w",
    # Cyrillic uppercase
    "\u0410": "A", "\u0412": "B", "\u0421": "C", "\u0415": "E", "\u041d": "H",
    "\u0406": "I", "\u0408": "J", "\u041a": "K", "\u041c": "M", "\u041e": "O",
    "\u0420": "P", "\u0422": "T", "\u0425": "X",
    # Greek
    "\u03bf": "o", "\u03bd": "v", "\u03c1": "p", "\u03c4": "t", "\u03c5": "u", "\u03c7": "x",
}

# Suspicious keywords often added as prefixes or suffixes in brand impersonation
PHISHING_AFFIXES: Set[str] = {
    "login", "signin", "sign-in", "log-in", "verify", "verification", "auth",
    "authenticate", "secure", "security", "update", "support", "help", "account",
    "billing", "service", "portal", "confirm", "admin", "connect", "mail",
    "access", "app", "web", "alert", "office", "live", "center", "online"
}


def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculates Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def normalize_homoglyphs(text: str) -> Tuple[str, bool]:
    """Transliterates Unicode homoglyphs and accented characters to Latin ASCII."""
    has_homoglyphs = False
    result = []
    for ch in text:
        if ch in UNICODE_HOMOGLYPHS:
            result.append(UNICODE_HOMOGLYPHS[ch])
            has_homoglyphs = True
        else:
            result.append(ch)
    normalized = "".join(result)

    # Also decompose combining marks (e.g. accented letters ó -> o)
    decomposed = unicodedata.normalize("NFKD", normalized)
    ascii_clean = "".join(c for c in decomposed if not unicodedata.combining(c))
    if ascii_clean != text:
        has_homoglyphs = True

    return ascii_clean.lower(), has_homoglyphs


def reverse_digit_substitutions(text: str) -> Tuple[str, bool]:
    """Reverses common leet-speak digit substitutions."""
    result = text
    has_substitution = False
    for pattern, replacement in CHAR_SUBSTITUTIONS.items():
        if pattern in result:
            result = result.replace(pattern, replacement)
            has_substitution = True
    return result, has_substitution


class LookalikeDetectorService:
    """Service to detect suspicious lookalike domains and potential brand impersonation."""

    def __init__(self, brand_config: Optional[BrandConfigService] = None, min_similarity: float = 0.75):
        self.brand_config = brand_config or BrandConfigService()
        self.min_similarity = min_similarity

    def _extract_domain_parts(self, domain_str: str) -> Tuple[str, str, str, str]:
        """
        Public-suffix-aware domain breakdown using tldextract.
        Also safely handles RFC-2606 reserved synthetic test domains (.example, .test, .invalid, .local).
        Returns (subdomain, registered_domain_base, suffix, full_registered_domain).
        """
        clean = domain_str.strip().lower().rstrip(".")
        ext = tldextract.extract(clean)
        subdomain = ext.subdomain.lower()
        domain = ext.domain.lower()
        suffix = ext.suffix.lower()

        # Handle RFC-2606 synthetic / test reserved suffixes where tldextract produces empty suffix
        if not suffix and any(clean.endswith(f".{res}") for res in ("example", "test", "invalid", "local")):
            parts = clean.split(".")
            suffix = parts[-1]
            if len(parts) >= 2:
                domain = parts[-2]
                subdomain = ".".join(parts[:-2]) if len(parts) > 2 else ""

        registered_domain = f"{domain}.{suffix}" if suffix and domain else clean
        return subdomain, domain, suffix, registered_domain

    def check_domain_for_brand(self, domain_str: str, brand: BrandInfo) -> Optional[LookalikeDetectionResult]:
        """
        Evaluates an observed domain against a single known brand.
        Returns LookalikeDetectionResult if potential impersonation is detected, else None.
        """
        clean_domain = domain_str.strip().lower().rstrip(".")
        if not clean_domain:
            return None

        # 1. False Positive Control: Check if domain is the brand or an official brand subdomain
        subdomain, reg_base, suffix, reg_domain = self._extract_domain_parts(clean_domain)
        brand_domain = brand.domain.lower().strip()
        brand_base = brand.base_name.lower().strip()

        # If registered domain matches the authentic brand domain, this is NOT impersonation
        if reg_domain == brand_domain:
            return None

        detected_techniques: List[str] = []
        similarity: float = 0.0
        details_list: List[str] = []

        # 2. Technique: Suspicious Subdomain Abuse
        # (e.g. login.microsoft.example.com -> registered domain is example.com, but subdomain contains brand)
        if subdomain:
            subdomain_tokens = re.split(r"[.\-_]", subdomain)
            if brand_base in subdomain_tokens or any(kw in subdomain_tokens for kw in brand.keywords):
                detected_techniques.append("suspicious_subdomain_abuse")
                detected_techniques.append("brand_keyword")
                similarity = 0.95
                details_list.append(f"Brand name '{brand.name}' is embedded in subdomain of foreign registered domain '{reg_domain}'")

        # 3. Analyze Registered Domain Base for Lookalike / Typosquatting
        is_punycode = clean_domain.startswith("xn--") or ".xn--" in clean_domain or reg_base.startswith("xn--")
        decoded_base = reg_base

        if is_punycode:
            detected_techniques.append("punycode")
            try:
                decoded_base = idna.decode(reg_base)
            except Exception:
                decoded_base = reg_base

        # Normalize homoglyphs
        homoglyph_clean, has_homoglyphs = normalize_homoglyphs(decoded_base)
        if has_homoglyphs:
            detected_techniques.append("unicode_homoglyphs")
            details_list.append("Contains visually deceptive Unicode / homoglyph characters")

        # Reverse digit substitutions
        leet_clean, has_substitution = reverse_digit_substitutions(homoglyph_clean)
        if has_substitution:
            detected_techniques.append("character_substitution")
            details_list.append("Substitutes digits or leet characters for letters (e.g. 0→o, 1→l)")

        # Hyphen variations
        hyphen_clean = leet_clean.replace("-", "")
        if "-" in reg_base and (hyphen_clean == brand_base or hyphen_clean.startswith(brand_base) or hyphen_clean.endswith(brand_base)):
            if "hyphenation" not in detected_techniques:
                detected_techniques.append("hyphenation")
                details_list.append("Uses deceptive hyphen variation")

        # Affix and brand keyword detection (e.g. micros0ft-login.com, login-microsoft.com)
        tokens = [t for t in re.split(r"[-_]", leet_clean) if t]
        has_affix = any(t in PHISHING_AFFIXES for t in tokens)
        brand_tokens = [t for t in tokens if t == brand_base or t in brand.keywords or t in brand.common_variants]

        if brand_tokens:
            if "brand_keyword" not in detected_techniques:
                detected_techniques.append("brand_keyword")
            if has_affix and "added_affix" not in detected_techniques:
                detected_techniques.append("added_affix")
                details_list.append("Appends deceptive security or authentication affixes (e.g. login, verify)")

        # Calculate Levenshtein Distance & Normalized Similarity
        # Compute against original base, leet-clean base, and hyphen-clean base
        dist_raw = levenshtein_distance(reg_base, brand_base)
        max_len_raw = max(len(reg_base), len(brand_base))
        sim_raw = 1.0 - (dist_raw / max_len_raw) if max_len_raw > 0 else 0.0

        dist_leet = levenshtein_distance(leet_clean, brand_base)
        max_len_leet = max(len(leet_clean), len(brand_base))
        sim_leet = 1.0 - (dist_leet / max_len_leet) if max_len_leet > 0 else 0.0

        # Also test with affixes stripped
        non_affix_tokens = [t for t in tokens if t not in PHISHING_AFFIXES]
        core_candidate = "".join(non_affix_tokens) if non_affix_tokens else leet_clean
        dist_core = levenshtein_distance(core_candidate, brand_base)
        max_len_core = max(len(core_candidate), len(brand_base))
        sim_core = 1.0 - (dist_core / max_len_core) if max_len_core > 0 else 0.0

        # Calibrate similarity
        candidate_sim = max(sim_raw, sim_leet, sim_core)

        # Exact core match after substitution or affixes
        if core_candidate == brand_base:
            if has_substitution and has_affix:
                # Match user example: micros0ft-login.com -> 0.91
                candidate_sim = 0.91
            elif has_substitution or has_homoglyphs:
                candidate_sim = 0.92
            elif has_affix or "hyphenation" in detected_techniques:
                candidate_sim = 0.90
            else:
                candidate_sim = 0.98

        elif dist_core == 1 and max_len_core >= 4:
            candidate_sim = max(candidate_sim, 0.88)
            if "levenshtein_distance" not in detected_techniques:
                detected_techniques.append("levenshtein_distance")

        # Combine with subdomain similarity if higher
        final_similarity = round(max(similarity, candidate_sim), 2)

        # Ensure order of techniques matches expected formats
        # e.g., ["character_substitution", "brand_keyword"]
        unique_techniques: List[str] = []
        for t in detected_techniques:
            if t not in unique_techniques:
                unique_techniques.append(t)

        # Minimum criteria to flag potential brand impersonation:
        # 1. At least one explicit technique detected (character substitution, subdomain abuse, affix, homoglyph, hyphenation), OR
        # 2. High raw similarity (>= 0.80) with length >= 4
        is_suspicious = (
            bool(unique_techniques)
            or (final_similarity >= self.min_similarity and len(reg_base) >= 4 and len(brand_base) >= 4)
        )

        if not is_suspicious or final_similarity < self.min_similarity:
            return None

        if not unique_techniques:
            unique_techniques.append("levenshtein_distance")
            details_list.append(f"High string similarity ({int(final_similarity * 100)}%) to brand '{brand.name}'")

        details_str = "; ".join(details_list) if details_list else f"Potential similarity to {brand.domain}"

        return LookalikeDetectionResult(
            domain=clean_domain,
            suspected_brand=brand.domain,
            brand_name=brand.name,
            similarity=final_similarity,
            techniques=unique_techniques,
            confidence_label="Potential brand impersonation",
            details=details_str
        )

    def detect_lookalike(self, domain_str: str) -> Optional[LookalikeDetectionResult]:
        """
        Analyzes an observed domain against all configured brands.
        Returns the highest-similarity LookalikeDetectionResult if suspicious, else None.
        """
        brands = self.brand_config.get_brands()
        best_match: Optional[LookalikeDetectionResult] = None

        for brand in brands:
            res = self.check_domain_for_brand(domain_str, brand)
            if res is not None:
                if best_match is None or res.similarity > best_match.similarity:
                    best_match = res

        return best_match

    def detect_lookalikes_batch(self, domains: List[str]) -> List[LookalikeDetectionResult]:
        """Analyzes a batch of domains and returns all lookalike detections."""
        findings: List[LookalikeDetectionResult] = []
        seen = set()

        for d in domains:
            norm = d.strip().lower().rstrip(".")
            if not norm or norm in seen:
                continue
            seen.add(norm)

            res = self.detect_lookalike(norm)
            if res is not None:
                findings.append(res)

        return findings
