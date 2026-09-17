import re
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse

from backend.schemas.email import (
    ProtocolResult,
    SenderAlignment,
    AuthenticationAnalysis
)


class AuthAnalyzerService:
    """Service to parse authentication headers (SPF, DKIM, DMARC) and evaluate sender alignment."""

    @staticmethod
    def extract_domain_from_header(header_val: Optional[str]) -> Optional[str]:
        """Extracts normalized domain name from an email address or header string."""
        if not header_val:
            return None

        import email.utils
        _, addr = email.utils.parseaddr(header_val)
        if not addr or '@' not in addr:
            match = re.search(r'[\w\.-]+@([\w\.-]+\.[a-zA-Z]{2,})', header_val)
            if match:
                return match.group(1).lower().strip('.')
            return None

        domain_part = addr.split('@')[-1].strip().lower()
        domain_part = re.sub(r'[^a-z0-9\.-]', '', domain_part).strip('.')
        if domain_part and '.' in domain_part:
            return domain_part

        return None

    @classmethod
    def parse_authentication_headers(
        cls,
        auth_headers: List[str],
        received_spf_headers: Optional[List[str]] = None,
        raw_headers_text: Optional[str] = None
    ) -> Tuple[ProtocolResult, ProtocolResult, ProtocolResult, Optional[str]]:
        """
        Parses Authentication-Results, ARC-Authentication-Results, Received-SPF, and raw headers text.
        Returns (spf_result, dkim_result, dmarc_result, full_observed_header).
        """
        headers_to_check: List[str] = []
        if auth_headers:
            headers_to_check.extend([a for a in auth_headers if a])
        if received_spf_headers:
            headers_to_check.extend([s for s in received_spf_headers if s])

        combined_auth_str = "\n".join(headers_to_check)

        if not combined_auth_str and raw_headers_text:
            # Extract any header lines containing authentication results
            auth_lines = re.findall(r'(?:Authentication-Results|ARC-Authentication-Results|Received-SPF|DKIM-Signature):[^\r\n]+(?:\r?\n[ \t]+[^\r\n]+)*', raw_headers_text, re.IGNORECASE)
            if auth_lines:
                combined_auth_str = "\n".join(auth_lines)

        full_observed_header = combined_auth_str if combined_auth_str else None

        spf = ProtocolResult(result="unknown", details=None)
        dkim = ProtocolResult(result="unknown", details=None)
        dmarc = ProtocolResult(result="unknown", details=None)

        if not full_observed_header:
            spf.result = "none"
            spf.details = "No Authentication-Results or Received-SPF header present."
            dkim.result = "none"
            dkim.details = "No Authentication-Results or DKIM-Signature header present."
            dmarc.result = "none"
            dmarc.details = "No Authentication-Results header present."
            return spf, dkim, dmarc, None

        # 1. Parse SPF
        spf_match = re.search(r'\bspf=(pass|fail|softfail|neutral|none|temperror|permerror)\b', full_observed_header, re.IGNORECASE)
        if spf_match:
            spf.result = spf_match.group(1).lower()
            start_pos = spf_match.start()
            end_pos = full_observed_header.find(';', start_pos)
            if end_pos == -1:
                end_pos = min(start_pos + 160, len(full_observed_header))
            spf.details = full_observed_header[start_pos:end_pos].strip()
        else:
            rec_spf_match = re.search(r'\b(?:Received-SPF:)?\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b', full_observed_header, re.IGNORECASE)
            if rec_spf_match:
                spf.result = rec_spf_match.group(1).lower()
                spf.details = full_observed_header[:160].strip()
            else:
                spf.result = "none"
                spf.details = "No SPF result found in headers."

        # 2. Parse DKIM
        dkim_match = re.search(r'\bdkim=(pass|fail|neutral|none|temperror|permerror)\b', full_observed_header, re.IGNORECASE)
        if dkim_match:
            dkim.result = dkim_match.group(1).lower()
            start_pos = dkim_match.start()
            end_pos = full_observed_header.find(';', start_pos)
            if end_pos == -1:
                end_pos = min(start_pos + 160, len(full_observed_header))
            dkim.details = full_observed_header[start_pos:end_pos].strip()
        elif re.search(r'\bDKIM-Signature:', full_observed_header, re.IGNORECASE):
            dkim.result = "unknown"
            dkim.details = "DKIM-Signature header observed on message but cryptographic verification result is unverified."
        else:
            dkim.result = "none"
            dkim.details = "No DKIM result or DKIM-Signature header found."

        # 3. Parse DMARC
        dmarc_match = re.search(r'\bdmarc=(pass|fail|neutral|none|temperror|permerror)\b', full_observed_header, re.IGNORECASE)
        if dmarc_match:
            dmarc.result = dmarc_match.group(1).lower()
            start_pos = dmarc_match.start()
            end_pos = full_observed_header.find(';', start_pos)
            if end_pos == -1:
                end_pos = min(start_pos + 160, len(full_observed_header))
            dmarc.details = full_observed_header[start_pos:end_pos].strip()
        else:
            dmarc.result = "none"
            dmarc.details = "No DMARC result found in Authentication-Results."

        return spf, dkim, dmarc, full_observed_header

    @classmethod
    def analyze_sender_alignment(
        cls,
        from_header: Optional[str],
        reply_to: Optional[str],
        return_path: Optional[str]
    ) -> SenderAlignment:
        """
        Extracts domains from From, Reply-To, and Return-Path.
        Evaluates domain alignment mismatches.
        """
        from_dom = cls.extract_domain_from_header(from_header)
        reply_dom = cls.extract_domain_from_header(reply_to)
        return_dom = cls.extract_domain_from_header(return_path)

        reply_mismatch = False
        if reply_dom and from_dom:
            reply_mismatch = (reply_dom.lower() != from_dom.lower())

        return_mismatch = False
        if return_dom and from_dom:
            return_mismatch = (return_dom.lower() != from_dom.lower())

        return SenderAlignment(
            from_domain=from_dom,
            reply_to_domain=reply_dom,
            return_path_domain=return_dom,
            reply_to_mismatch=reply_mismatch,
            return_path_mismatch=return_mismatch
        )

    @classmethod
    def analyze_authentication(
        cls,
        from_header: Optional[str],
        reply_to: Optional[str],
        return_path: Optional[str],
        auth_headers: List[str],
        received_spf_headers: Optional[List[str]] = None,
        raw_headers_text: Optional[str] = None
    ) -> AuthenticationAnalysis:
        """Assembles full authentication analysis object."""
        spf, dkim, dmarc, observed = cls.parse_authentication_headers(
            auth_headers,
            received_spf_headers,
            raw_headers_text
        )
        alignment = cls.analyze_sender_alignment(from_header, reply_to, return_path)

        return AuthenticationAnalysis(
            verification_type="observed_header",
            verification_notice="Observed authentication result from supplied headers (unverified by local mail server)",
            observed_header=observed,
            spf=spf,
            dkim=dkim,
            dmarc=dmarc,
            alignment=alignment
        )
