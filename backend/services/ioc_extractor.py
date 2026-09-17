import hashlib
import ipaddress
import re
from typing import List, Dict, Any, Optional, Tuple, Set
from html.parser import HTMLParser
from urllib.parse import urlparse

try:
    import tldextract
except ImportError:
    tldextract = None

from backend.schemas.email import (
    IPIndicator,
    DomainIndicator,
    URLIndicator,
    EmailAddressIndicator,
    AttachmentIndicator
)


class HTMLLinkExtractor(HTMLParser):
    """HTML parser to safely extract URLs from href and src attributes with visible text tracking."""

    def __init__(self):
        super().__init__()
        self.extracted: List[Tuple[str, str]] = []
        self.links_with_text: List[Tuple[str, str]] = []
        self._current_a_href: Optional[str] = None
        self._current_a_text: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]):
        lower_tag = tag.lower()
        for attr, value in attrs:
            if attr.lower() in ('href', 'src', 'action', 'data-url') and value:
                val = value.strip()
                if val.startswith(('http://', 'https://', 'ftp://', 'ftps://')):
                    source_label = f"html_{lower_tag}_{attr.lower()}"
                    self.extracted.append((val, source_label))
                    if lower_tag == 'a' and attr.lower() == 'href':
                        self._current_a_href = val
                        self._current_a_text = []

    def handle_data(self, data: str):
        if self._current_a_href is not None:
            self._current_a_text.append(data)

    def handle_endtag(self, tag: str):
        if tag.lower() == 'a' and self._current_a_href is not None:
            vis_text = " ".join(self._current_a_text).strip()
            self.links_with_text.append((self._current_a_href, vis_text))
            self._current_a_href = None
            self._current_a_text = []


class IOCExtractorService:
    """Service to extract, normalize, and classify Indicators of Compromise (IOCs)."""

    @staticmethod
    def calculate_sha256(data_bytes: bytes) -> str:
        """Calculates SHA-256 hex digest of raw byte stream."""
        if not data_bytes:
            return hashlib.sha256(b"").hexdigest()
        return hashlib.sha256(data_bytes).hexdigest()

    @staticmethod
    def calculate_hashes(data_bytes: bytes) -> Tuple[str, str, str]:
        """Calculates SHA-256, MD5, and SHA-1 hex digests of raw bytes."""
        b = data_bytes or b""
        sha256_hash = hashlib.sha256(b).hexdigest()
        md5_hash = hashlib.md5(b).hexdigest()
        sha1_hash = hashlib.sha1(b).hexdigest()
        return sha256_hash, md5_hash, sha1_hash

    @staticmethod
    def classify_ip_scope(ip_str: str) -> Tuple[int, str]:
        """
        Classifies an IP string using Python's ipaddress module.
        Returns (version, scope). Scope can be: public, private, loopback, link_local, reserved, unknown.
        """
        try:
            obj = ipaddress.ip_address(ip_str)
            version = obj.version
            if obj.is_loopback:
                scope = "loopback"
            elif obj.is_private:
                scope = "private"
            elif obj.is_link_local:
                scope = "link_local"
            elif obj.is_reserved or obj.is_multicast:
                scope = "reserved"
            elif obj.is_global:
                scope = "public"
            else:
                scope = "unknown"
            return version, scope
        except ValueError:
            return 4, "unknown"

    @classmethod
    def extract_ips(cls, sources: List[Tuple[str, str]]) -> List[IPIndicator]:
        """
        Extracts IPv4 and IPv6 addresses from (text, source_name) tuples.
        Classifies scope and version using ipaddress module.
        """
        ipv4_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        ipv6_pattern = re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:|\b:(?::[0-9a-fA-F]{1,4}){1,7}\b')

        results: List[IPIndicator] = []
        seen: Set[str] = set()

        for text, src in sources:
            if not text:
                continue

            for match in ipv4_pattern.findall(text):
                try:
                    obj = ipaddress.ip_address(match)
                    ip_norm = str(obj)
                    if ip_norm not in seen:
                        seen.add(ip_norm)
                        ver, scope = cls.classify_ip_scope(ip_norm)
                        results.append(IPIndicator(
                            value=ip_norm,
                            version=ver,
                            scope=scope,
                            source=src
                        ))
                except ValueError:
                    continue

            for match in ipv6_pattern.findall(text):
                try:
                    obj = ipaddress.ip_address(match)
                    ip_norm = str(obj)
                    if ip_norm not in seen:
                        seen.add(ip_norm)
                        ver, scope = cls.classify_ip_scope(ip_norm)
                        results.append(IPIndicator(
                            value=ip_norm,
                            version=ver,
                            scope=scope,
                            source=src
                        ))
                except ValueError:
                    continue

        return results

    @classmethod
    def extract_urls(cls, plain_text: Optional[str], html_body: Optional[str], headers_dict: Dict[str, Any]) -> List[URLIndicator]:
        """Extracts and conservatively normalizes unique URLs with source tracking."""
        url_pattern = re.compile(r'https?://[^\s<>"\'\)\(\]\[\}\s,]+', re.IGNORECASE)
        results: List[URLIndicator] = []
        seen: Set[str] = set()

        def add_url(u: str, src: str):
            clean_u = u.rstrip('.,;:!?"\')]>')
            if clean_u and clean_u not in seen:
                seen.add(clean_u)
                results.append(URLIndicator(value=clean_u, source=src))

        if plain_text:
            for match in url_pattern.findall(plain_text):
                add_url(match, "plain_text_body")

        if html_body:
            try:
                parser = HTMLLinkExtractor()
                parser.feed(html_body)
                for u, src_tag in parser.extracted:
                    add_url(u, src_tag)
            except Exception:
                pass

            for match in url_pattern.findall(html_body):
                add_url(match, "html_body")

        for h_name, h_val in headers_dict.items():
            if h_val and isinstance(h_val, str):
                for match in url_pattern.findall(h_val):
                    add_url(match, f"header_{h_name.lower()}")

        return results

    @classmethod
    def extract_html_links(cls, html_body: Optional[str]) -> List[Tuple[str, str]]:
        """Extracts HTML anchor links as tuples of (href, visible_text)."""
        if not html_body:
            return []
        try:
            parser = HTMLLinkExtractor()
            parser.feed(html_body)
            return parser.links_with_text
        except Exception:
            return []

    @classmethod
    def extract_email_addresses(cls, headers_dict: Dict[str, Any], plain_text: Optional[str], html_body: Optional[str]) -> List[EmailAddressIndicator]:
        """Extracts unique email addresses with source tracking."""
        email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
        results: List[EmailAddressIndicator] = []
        seen: Set[str] = set()

        def add_email(email_str: str, src: str):
            clean_email = email_str.lower().strip()
            if clean_email and clean_email not in seen:
                seen.add(clean_email)
                results.append(EmailAddressIndicator(value=clean_email, source=src))

        for h_key in ("from", "to", "cc", "reply_to", "return_path"):
            val = headers_dict.get(h_key)
            if val:
                val_str = ", ".join(val) if isinstance(val, list) else str(val)
                for match in email_pattern.findall(val_str):
                    add_email(match, f"header_{h_key}")

        if plain_text:
            for match in email_pattern.findall(plain_text):
                add_email(match, "plain_text_body")

        if html_body:
            for match in email_pattern.findall(html_body):
                add_email(match, "html_body")

        return results

    @classmethod
    def extract_domains(cls, urls: List[URLIndicator], email_indicators: List[EmailAddressIndicator], text_sources: List[Tuple[str, str]]) -> List[DomainIndicator]:
        """
        Extracts and normalizes domain names from URLs, emails, and header text.
        Uses tldextract for public-suffix-aware domain parsing if available.
        """
        results: List[DomainIndicator] = []
        seen: Set[str] = set()

        NON_DOMAIN_EXTENSIONS = {
            'png', 'jpg', 'jpeg', 'gif', 'svg', 'webp', 'bmp', 'ico', 'tif', 'tiff',
            'css', 'js', 'json', 'xml', 'html', 'htm', 'php', 'asp', 'aspx', 'jsp',
            'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'rtf', 'csv',
            'zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'iso', 'dmg',
            'exe', 'dll', 'bat', 'cmd', 'ps1', 'sh', 'bin', 'msi', 'apk',
            'log', 'bak', 'tmp', 'map', 'ts', 'tsx', 'jsx', 'woff', 'woff2', 'ttf', 'eot',
            'getelementbyid', 'matchmedia', 'backgroundcolor', 'mailfrom', 'from', 'ap'
        }

        def add_domain(raw_domain: str, src: str):
            if not raw_domain:
                return

            clean_domain = raw_domain.lower().strip('.')
            if not clean_domain:
                return

            if clean_domain in ('localhost', 'local', 'broadcasthost') or '.' not in clean_domain:
                return

            last_part = clean_domain.split('.')[-1]
            if last_part in NON_DOMAIN_EXTENSIONS:
                return

            try:
                ipaddress.ip_address(clean_domain)
                return
            except ValueError:
                pass

            RFC_RESERVED_TLDS = {'example', 'test', 'invalid', 'internal'}
            if last_part in RFC_RESERVED_TLDS and len(clean_domain.split('.')) >= 2:
                if clean_domain not in seen:
                    seen.add(clean_domain)
                    results.append(DomainIndicator(value=clean_domain, source=src))
                return

            if tldextract:
                ext = tldextract.extract(clean_domain)
                if ext.domain and ext.suffix and ext.suffix.lower() not in NON_DOMAIN_EXTENSIONS:
                    fqdn = f"{ext.subdomain}.{ext.domain}.{ext.suffix}".strip('.') if ext.subdomain else f"{ext.domain}.{ext.suffix}"
                    if fqdn not in seen:
                        seen.add(fqdn)
                        results.append(DomainIndicator(value=fqdn, source=src))
                # Strict: if tldextract is available, do not fall back to adding non-domains with empty suffix
                return

            # Fallback when tldextract is unavailable: require valid alphanumeric domain parts and alphabetic TLD
            parts = clean_domain.split('.')
            if len(parts) >= 2 and parts[-1].isalpha() and 2 <= len(parts[-1]) <= 6 and parts[-1] not in NON_DOMAIN_EXTENSIONS:
                if clean_domain not in seen:
                    seen.add(clean_domain)
                    results.append(DomainIndicator(value=clean_domain, source=src))

        for url_obj in urls:
            try:
                parsed = urlparse(url_obj.value)
                if parsed.netloc:
                    host = parsed.netloc.split(':')[0]
                    add_domain(host, f"url ({url_obj.source})")
            except Exception:
                pass

        for email_obj in email_indicators:
            if '@' in email_obj.value:
                domain_part = email_obj.value.split('@')[-1]
                add_domain(domain_part, f"email ({email_obj.source})")

        domain_pattern = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b')
        for text, src in text_sources:
            if not text:
                continue
            for match in domain_pattern.findall(text):
                add_domain(match, src)

        return results

    @classmethod
    def extract_attachment_indicators(cls, attachments_raw: List[Dict[str, Any]]) -> List[AttachmentIndicator]:
        """
        Calculates SHA-256, MD5, SHA-1 hashes for attachments and runs safe static malware analysis.
        attachments_raw is a list of dicts with 'filename', 'mime_type', 'bytes'.
        """
        from backend.services.attachment_intelligence_service import AttachmentIntelligenceService

        results: List[AttachmentIndicator] = []

        for att in attachments_raw:
            raw_b = att.get("bytes") or b""
            fn = att.get("filename") or "unnamed_attachment"
            mime = att.get("mime_type") or "application/octet-stream"

            static_res = AttachmentIntelligenceService.analyze_attachment(
                payload=raw_b,
                filename=fn,
                mime_type=mime
            )

            results.append(
                AttachmentIndicator(
                    filename=fn,
                    mime_type=mime,
                    size=len(raw_b),
                    sha256=static_res.sha256,
                    md5=static_res.md5,
                    sha1=static_res.sha1,
                    static_analysis=static_res
                )
            )

        return results
