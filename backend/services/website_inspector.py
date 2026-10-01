"""
Static HTML & Website Inspector (Section 7).
Safely parses retrieved webpage content using standard library HTML parsing.
Performs static analysis of forms, input types, password fields, script tags,
meta tags, external links, download candidates, and credential harvesting signals.
CRITICAL: Never executes JavaScript or submits forms.
"""
from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlsplit

import tldextract

logger = logging.getLogger("cyberguard.website_inspector")

# Common executable/suspicious download extensions
SUSPICIOUS_DOWNLOAD_EXTENSIONS = {
    ".exe", ".scr", ".zip", ".rar", ".7z", ".tar", ".gz",
    ".apk", ".msi", ".iso", ".dmg", ".bat", ".cmd", ".ps1",
    ".vbs", ".js", ".hta", ".wsf", ".jar", ".bin",
}

# Credential/Login keywords
LOGIN_KEYWORDS = {
    "login", "signin", "sign-in", "log-in", "auth", "authenticate",
    "password", "passcode", "account", "verify", "security",
    "banking", "portal", "update", "credential", "session",
}

# Common brand keywords for potential impersonation checks
COMMON_BRAND_KEYWORDS = {
    "microsoft", "office365", "outlook", "google", "gmail",
    "apple", "icloud", "amazon", "paypal", "netflix",
    "chase", "wellsfargo", "bankofamerica", "citibank",
    "dhl", "fedex", "usps", "ups", "dropbox", "docuSign",
}


@dataclass
class FormInfo:
    """Extracted HTML form metadata."""
    action: str
    resolved_action: str
    method: str
    action_domain: str = ""
    is_cross_domain: bool = False
    input_types: List[str] = field(default_factory=list)
    input_names: List[str] = field(default_factory=list)
    has_password: bool = False
    has_username_or_email: bool = False
    is_login_form: bool = False


@dataclass
class ScriptReference:
    """Static reference to a script resource."""
    src: str
    resolved_src: str
    is_external: bool = False
    src_domain: str = ""


@dataclass
class DownloadCandidate:
    """Discovered potential file download reference in HTML."""
    url: str
    resolved_url: str
    filename: str
    extension: str


@dataclass
class WebsiteInspectionResult:
    """Normalized output of safe static website analysis."""
    url: str
    base_domain: str
    title: Optional[str] = None
    meta_tags: Dict[str, str] = field(default_factory=dict)
    forms: List[FormInfo] = field(default_factory=list)
    has_login_form: bool = False
    has_password_field: bool = False
    has_cross_domain_form: bool = False
    cross_domain_form_actions: List[str] = field(default_factory=list)
    external_links_count: int = 0
    internal_links_count: int = 0
    external_links: List[str] = field(default_factory=list)
    scripts: List[ScriptReference] = field(default_factory=list)
    download_candidates: List[DownloadCandidate] = field(default_factory=list)
    favicon_url: Optional[str] = None
    credential_harvesting_signals: List[str] = field(default_factory=list)
    brand_mentions: List[str] = field(default_factory=list)
    text_snippet: str = ""


class _SafeStaticHTMLParser(HTMLParser):
    """
    SAX-style static HTML parser that extracts metadata without executing content.
    Robust against malformed HTML.
    """

    def __init__(self, page_url: str):
        super().__init__(convert_charrefs=True)
        self.page_url = page_url
        self.page_domain = self._extract_domain(page_url)

        self.title_tokens: List[str] = []
        self._in_title = False

        self.meta_tags: Dict[str, str] = {}
        self.forms: List[FormInfo] = []
        self._current_form: Optional[FormInfo] = None

        self.links: List[str] = []
        self.scripts: List[ScriptReference] = []
        self.downloads: List[DownloadCandidate] = []
        self.favicon_url: Optional[str] = None

        self.text_chunks: List[str] = []
        self._text_size = 0
        self._max_text_size = 10000

    def _extract_domain(self, url: str) -> str:
        try:
            parsed = urlsplit(url)
            ext = tldextract.extract(parsed.hostname or "")
            if ext.domain and ext.suffix:
                return f"{ext.domain}.{ext.suffix}".lower()
            return (parsed.hostname or "").lower()
        except Exception:
            return ""

    def handle_starttag(self, tag: str, attrs: List[tuple[str, Optional[str]]]):
        tag_lower = tag.lower()
        attr_dict = {k.lower(): (v or "") for k, v in attrs}

        # 1. Page Title
        if tag_lower == "title":
            self._in_title = True

        # 2. Meta Tags
        elif tag_lower == "meta":
            name = attr_dict.get("name") or attr_dict.get("property") or attr_dict.get("http-equiv")
            content = attr_dict.get("content")
            if name and content:
                self.meta_tags[name.lower()] = content

        # 3. Form Tag
        elif tag_lower == "form":
            raw_action = attr_dict.get("action", "")
            resolved_action = urljoin(self.page_url, raw_action) if raw_action else self.page_url
            action_dom = self._extract_domain(resolved_action)
            is_cross = bool(self.page_domain and action_dom and self.page_domain != action_dom)
            method = attr_dict.get("method", "GET").upper()

            self._current_form = FormInfo(
                action=raw_action,
                resolved_action=resolved_action,
                method=method,
                action_domain=action_dom,
                is_cross_domain=is_cross,
            )
            self.forms.append(self._current_form)

        # 4. Input Tag
        elif tag_lower == "input":
            input_type = attr_dict.get("type", "text").lower()
            input_name = attr_dict.get("name", "").lower()

            target_form = self._current_form
            if target_form:
                target_form.input_types.append(input_type)
                if input_name:
                    target_form.input_names.append(input_name)

                if input_type == "password":
                    target_form.has_password = True
                if input_type in ("email", "text") and any(k in input_name for k in ("user", "login", "email", "account")):
                    target_form.has_username_or_email = True

        # 5. Link Tag (Favicon or Stylesheet)
        elif tag_lower == "link":
            rel = attr_dict.get("rel", "").lower()
            href = attr_dict.get("href", "")
            if "icon" in rel and href and not self.favicon_url:
                self.favicon_url = urljoin(self.page_url, href)

        # 6. Anchor Tag
        elif tag_lower == "a":
            href = attr_dict.get("href", "")
            if href and not href.startswith(("#", "javascript:", "mailto:", "tel:")):
                resolved_link = urljoin(self.page_url, href)
                self.links.append(resolved_link)
                self._check_download(resolved_link)

        # 7. Script Tag (Static reference recording only)
        elif tag_lower == "script":
            src = attr_dict.get("src", "")
            if src:
                resolved_src = urljoin(self.page_url, src)
                src_dom = self._extract_domain(resolved_src)
                is_ext = bool(self.page_domain and src_dom and self.page_domain != src_dom)
                self.scripts.append(
                    ScriptReference(
                        src=src,
                        resolved_src=resolved_src,
                        is_external=is_ext,
                        src_domain=src_dom,
                    )
                )

    def handle_endtag(self, tag: str):
        if tag.lower() == "title":
            self._in_title = False
        elif tag.lower() == "form":
            if self._current_form:
                # Mark as login form if it has password input or login keywords
                if self._current_form.has_password:
                    self._current_form.is_login_form = True
                else:
                    form_tokens = " ".join(self._current_form.input_names + [self._current_form.action]).lower()
                    if any(k in form_tokens for k in LOGIN_KEYWORDS):
                        self._current_form.is_login_form = True
            self._current_form = None

    def handle_data(self, data: str):
        if self._in_title:
            self.title_tokens.append(data.strip())
        elif self._text_size < self._max_text_size:
            cleaned = data.strip()
            if cleaned:
                self.text_chunks.append(cleaned)
                self._text_size += len(cleaned)

    def _check_download(self, link_url: str):
        try:
            parsed = urlsplit(link_url)
            path = parsed.path.lower()
            _, ext = os.path.splitext(path)
            if ext in SUSPICIOUS_DOWNLOAD_EXTENSIONS:
                fname = os.path.basename(path)
                self.downloads.append(
                    DownloadCandidate(
                        url=link_url,
                        resolved_url=link_url,
                        filename=fname,
                        extension=ext,
                    )
                )
        except Exception:
            pass


class WebsiteInspector:
    """
    Analyzes HTML content statically to identify credential-harvesting indicators,
    forms, cross-domain data submissions, and external resource patterns.
    """

    @classmethod
    def inspect_html(cls, page_url: str, html_content: str) -> WebsiteInspectionResult:
        """Parses static HTML without executing active scripts."""
        parser = _SafeStaticHTMLParser(page_url)
        try:
            parser.feed(html_content or "")
        except Exception as e:
            logger.warning(f"Error during HTML parsing for '{page_url}': {e}")

        title = " ".join(parser.title_tokens).strip() or None
        base_dom = parser.page_domain

        # Calculate link counts
        internal_links = 0
        external_links = []
        for link in parser.links:
            link_dom = parser._extract_domain(link)
            if link_dom and base_dom and link_dom != base_dom:
                external_links.append(link)
            else:
                internal_links += 1

        # Check forms and credential harvesting
        has_password = any(f.has_password for f in parser.forms)
        has_login = any(f.is_login_form for f in parser.forms)
        cross_domain_actions = [f.resolved_action for f in parser.forms if f.is_cross_domain]
        has_cross_domain = len(cross_domain_actions) > 0

        # Credential harvesting heuristics
        cred_signals: List[str] = []
        if has_password:
            cred_signals.append("PASSWORD_FIELD_DETECTED")
        if has_login:
            cred_signals.append("LOGIN_FORM_DETECTED")
        if has_cross_domain:
            cred_signals.append("CROSS_DOMAIN_FORM_ACTION")

        # Brand mentions in title or page text
        brand_mentions: List[str] = []
        search_corpus = f"{title or ''} {' '.join(parser.text_chunks[:50])}".lower()
        for brand in COMMON_BRAND_KEYWORDS:
            if brand in search_corpus:
                brand_mentions.append(brand)

        if brand_mentions and has_password:
            cred_signals.append("BRAND_IMPERSONATION_CREDENTIAL_FORM")

        return WebsiteInspectionResult(
            url=page_url,
            base_domain=base_dom,
            title=title,
            meta_tags=parser.meta_tags,
            forms=parser.forms,
            has_login_form=has_login,
            has_password_field=has_password,
            has_cross_domain_form=has_cross_domain,
            cross_domain_form_actions=cross_domain_actions,
            external_links_count=len(external_links),
            internal_links_count=internal_links,
            external_links=external_links[:20],
            scripts=parser.scripts,
            download_candidates=parser.downloads,
            favicon_url=parser.favicon_url,
            credential_harvesting_signals=cred_signals,
            brand_mentions=brand_mentions,
            text_snippet=" ".join(parser.text_chunks[:20]),
        )
