import email
import re
import mimetypes
from email import policy
from email.header import decode_header
from typing import List, Dict, Any, Optional

from backend.schemas.email import (
    EmailAnalysisResponse,
    HeaderInfo,
    BodyInfo,
    AttachmentInfo,
    FileMeta,
    IndicatorsGroup,
    URLIndicator,
    DomainIndicator,
    IPIndicator
)
from backend.services.ioc_extractor import IOCExtractorService
from backend.services.auth_analyzer import AuthAnalyzerService
from backend.services.relay_reconstructor import RelayReconstructorService
from backend.services.url_analyzer import URLAnalyzerService


class EmailParseException(Exception):
    """Raised when an email file is malformed, corrupted, or invalid."""
    pass


class EmailParserService:
    """Service to parse RFC-822 / .eml files safely and extract structured email details."""

    @staticmethod
    def _decode_header_value(header_val: Optional[Any]) -> Optional[str]:
        """Safely decode email header strings including encoded-words (=?UTF-8?...?)."""
        if header_val is None:
            return None

        header_str = str(header_val).strip()
        if not header_str:
            return None

        try:
            from email.header import decode_header, make_header
            decoded = str(make_header(decode_header(header_str)))
            return decoded.strip()
        except Exception:
            return header_str

    @classmethod
    def parse_eml_bytes(cls, content_bytes: bytes, filename: str = "uploaded.eml") -> EmailAnalysisResponse:
        """
        Parses raw bytes of an .eml file into structured JSON data.

        Raises:
            EmailParseException: if the byte stream is empty or malformed.
        """
        if not content_bytes or len(content_bytes.strip()) == 0:
            raise EmailParseException("Uploaded email file is empty.")

        # 1. Calculate evidence SHA-256 hash strictly from original bytes
        email_sha256 = IOCExtractorService.calculate_sha256(content_bytes)
        raw_email_str = content_bytes.decode("utf-8", errors="replace")

        try:
            msg = email.message_from_bytes(content_bytes, policy=policy.default)
        except Exception as e:
            raise EmailParseException(f"Failed to parse email structure: {str(e)}")

        if msg is None:
            raise EmailParseException("Unable to parse email file as RFC-822 message.")

        # Extract headers safely
        try:
            from_header = cls._decode_header_value(msg.get("From"))
            to_header = cls._decode_header_value(msg.get("To"))
            cc_header = cls._decode_header_value(msg.get("Cc"))
            subject = cls._decode_header_value(msg.get("Subject"))
            date = cls._decode_header_value(msg.get("Date"))
            reply_to = cls._decode_header_value(msg.get("Reply-To"))
            if not reply_to:
                # Fallback to search raw email for folded or non-standard Reply-To header
                rt_match = re.search(r'(?im)^Reply-To:\s*([^\r\n]+(?:\r?\n[ \t]+[^\r\n]+)*)', raw_email_str)
                if rt_match:
                    unfolded_rt = re.sub(r'\s+', ' ', rt_match.group(1)).strip()
                    reply_to = cls._decode_header_value(unfolded_rt)

            return_path = cls._decode_header_value(msg.get("Return-Path"))
            message_id = cls._decode_header_value(msg.get("Message-ID"))

            raw_received = msg.get_all("Received", []) or []
            received_headers = [
                cls._decode_header_value(r) for r in raw_received if r is not None
            ]
            received_headers = [r for r in received_headers if r]

            raw_auth_results = msg.get_all("Authentication-Results", []) or []
            raw_arc_auth = msg.get_all("ARC-Authentication-Results", []) or []
            raw_x_auth = msg.get_all("X-Authentication-Results", []) or []

            all_auth = raw_auth_results + raw_arc_auth + raw_x_auth
            auth_results_list = [
                cls._decode_header_value(a) for a in all_auth if a is not None
            ]
            auth_results_list = [a for a in auth_results_list if a]
            auth_results_str = "; ".join(auth_results_list) if auth_results_list else None

            raw_rec_spf = msg.get_all("Received-SPF", []) or []
            received_spf_headers = [
                cls._decode_header_value(s) for s in raw_rec_spf if s is not None
            ]
            received_spf_headers = [s for s in received_spf_headers if s]

        except Exception as e:
            raise EmailParseException(f"Malformed headers in email: {str(e)}")

        # 2. Analyze Email Authentication & Sender Alignment
        try:
            auth_analysis = AuthAnalyzerService.analyze_authentication(
                from_header=from_header,
                reply_to=reply_to,
                return_path=return_path,
                auth_headers=auth_results_list,
                received_spf_headers=received_spf_headers,
                raw_headers_text=raw_email_str
            )
        except Exception as e:
            from backend.schemas.email import ProtocolResult, SenderAlignment, AuthenticationAnalysis
            auth_analysis = AuthenticationAnalysis(
                spf=ProtocolResult(result="unknown", details=f"Error analyzing SPF: {str(e)}"),
                dkim=ProtocolResult(result="unknown", details=f"Error analyzing DKIM: {str(e)}"),
                dmarc=ProtocolResult(result="unknown", details=f"Error analyzing DMARC: {str(e)}"),
                alignment=SenderAlignment(
                    from_domain=None,
                    reply_to_domain=None,
                    return_path_domain=None,
                    reply_to_mismatch=False,
                    return_path_mismatch=False,
                    display_name_spoofing=False,
                    details=None
                ),
                raw_auth_results=auth_results_str
            )

        # 3. Reconstruct Relay Path from Received headers
        try:
            relay_analysis = RelayReconstructorService.reconstruct_relay_path(received_headers)
        except Exception as e:
            from backend.schemas.email import EarliestObservableNode, RelayPathAnalysis
            relay_analysis = RelayPathAnalysis(
                header_order_hops=[],
                transmission_order_hops=[],
                earliest_observable_node=EarliestObservableNode(
                    earliest_observable_ip=None,
                    from_host=None,
                    confidence="none",
                    reason=f"Relay reconstruction encountered error: {str(e)}"
                )
            )

        headers_dict = {
            "from": from_header,
            "to": to_header,
            "cc": cc_header,
            "subject": subject,
            "date": date,
            "reply_to": reply_to,
            "return_path": return_path,
            "message_id": message_id,
            "received": received_headers,
            "authentication_results": auth_results_str
        }

        plain_text_parts: List[str] = []
        html_parts: List[str] = []
        attachments_raw: List[Dict[str, Any]] = []

        # Iterate over parts
        try:
            if msg.is_multipart():
                parts = list(msg.walk())
            else:
                parts = [msg]

            attachment_counter = 1
            for part in parts:
                content_type = part.get_content_type() or "application/octet-stream"
                content_maintype = part.get_content_maintype()
                content_disposition = (part.get_content_disposition() or "").lower()

                # Skip multipart container parts (they are envelopes, not payloads)
                if content_maintype == "multipart":
                    continue

                # 1. Obtain filename across all standard and non-standard email headers
                part_filename = part.get_filename()
                if not part_filename:
                    part_filename = part.get_param("name", header="content-type")
                if not part_filename:
                    part_filename = part.get_param("filename", header="content-disposition")

                if not part_filename:
                    disp_header = str(part.get("Content-Disposition", ""))
                    fn_match = re.search(r'filename\*?=(?:["\']([^"\']+)["\']|([^\s;]+))', disp_header, re.I)
                    if fn_match:
                        part_filename = fn_match.group(1) or fn_match.group(2)

                if not part_filename:
                    type_header = str(part.get("Content-Type", ""))
                    name_match = re.search(r'name\*?=(?:["\']([^"\']+)["\']|([^\s;]+))', type_header, re.I)
                    if name_match:
                        part_filename = name_match.group(1) or name_match.group(2)

                # 2. Forensic attachment evaluation:
                # - Any part explicitly declared with Content-Disposition: attachment
                # - Any part with a filename or name parameter (including inline attachments/documents)
                # - Any non-text payload (application/*, image/*, audio/*, video/*) that is not pure text body
                is_explicit_attachment = (
                    content_disposition == "attachment"
                    or part_filename is not None
                )
                is_non_text_payload = (
                    content_type.lower() not in ("text/plain", "text/html")
                    and content_maintype != "multipart"
                )

                if is_explicit_attachment or is_non_text_payload:
                    fname = cls._decode_header_value(part_filename) if part_filename else None
                    if not fname:
                        ext = mimetypes.guess_extension(content_type) or ".bin"
                        fname = f"attachment_{attachment_counter}{ext}"
                    attachment_counter += 1

                    try:
                        payload = part.get_payload(decode=True) or b""
                    except Exception:
                        payload = b""

                    attachments_raw.append({
                        "filename": fname,
                        "mime_type": content_type,
                        "bytes": payload
                    })
                else:
                    if content_type == "text/plain":
                        try:
                            text_content = part.get_content()
                            if isinstance(text_content, str):
                                plain_text_parts.append(text_content)
                        except Exception:
                            payload = part.get_payload(decode=True)
                            if payload:
                                plain_text_parts.append(payload.decode("utf-8", errors="replace"))

                    elif content_type == "text/html":
                        try:
                            html_content = part.get_content()
                            if isinstance(html_content, str):
                                html_parts.append(html_content)
                        except Exception:
                            payload = part.get_payload(decode=True)
                            if payload:
                                html_parts.append(payload.decode("utf-8", errors="replace"))

            # Safety fallback: If msg.walk() found no attachments, scan raw MIME text for boundary attachments
            if len(attachments_raw) == 0 and ("filename=" in raw_email_str.lower() or "attachment" in raw_email_str.lower()):
                raw_matches = re.finditer(
                    r'(?:Content-Disposition:\s*(?:attachment|inline)[^;\r\n]*;\s*filename=["\']?([^"\'\r\n;]+)["\']?|Content-Type:\s*([^;\r\n]+)[^;\r\n]*;\s*name=["\']?([^"\'\r\n;]+)["\']?)',
                    raw_email_str,
                    re.IGNORECASE
                )
                for rm in raw_matches:
                    raw_fn = rm.group(1) or rm.group(3)
                    raw_mime = rm.group(2) or "application/octet-stream"
                    if raw_fn:
                        attachments_raw.append({
                            "filename": cls._decode_header_value(raw_fn) or f"attachment_{attachment_counter}.bin",
                            "mime_type": raw_mime.strip(),
                            "bytes": b""
                        })
                        attachment_counter += 1

        except Exception as e:
            raise EmailParseException(f"Error parsing email body/attachments: {str(e)}")

        plain_text_str = "\n".join(plain_text_parts) if plain_text_parts else None
        html_str = "\n".join(html_parts) if html_parts else None

        # 4. Extract IOCs using IOCExtractorService
        url_indicators = IOCExtractorService.extract_urls(plain_text_str, html_str, headers_dict)
        html_links = IOCExtractorService.extract_html_links(html_str)
        email_indicators = IOCExtractorService.extract_email_addresses(headers_dict, plain_text_str, html_str)

        # Static non-invasive URL analysis
        url_analyzer = URLAnalyzerService()
        url_strings = [u.value for u in url_indicators]
        analyzed_urls = url_analyzer.analyze_urls(url_strings, html_links=html_links)

        text_sources = [
            (plain_text_str or "", "plain_text_body"),
        ]
        if html_str:
            clean_html_text = re.sub(r'(?is)<(script|style)[^>]*>.*?</\1>', ' ', html_str)
            clean_html_text = re.sub(r'<[^>]+>', ' ', clean_html_text)
            text_sources.append((clean_html_text, "html_body"))
        for idx, r in enumerate(received_headers):
            text_sources.append((r, f"received_header_{idx+1}"))

        ip_indicators = IOCExtractorService.extract_ips(text_sources)
        domain_indicators = IOCExtractorService.extract_domains(url_indicators, email_indicators, text_sources)
        attachment_indicators = IOCExtractorService.extract_attachment_indicators(attachments_raw)

        # Feed extracted attachment indicators (URLs, Domains, IPs) into the global IOC pipeline
        for att in attachment_indicators:
            if att.static_analysis:
                att_name = att.filename or "attachment"
                for u in att.static_analysis.embedded_urls:
                    if not any(ui.value == u for ui in url_indicators):
                        url_indicators.append(URLIndicator(value=u, source=f"attachment ({att_name})"))
                for d in att.static_analysis.embedded_domains:
                    if not any(di.value == d for di in domain_indicators):
                        domain_indicators.append(DomainIndicator(value=d, source=f"attachment ({att_name})"))
                for ip_val in att.static_analysis.embedded_ips:
                    if not any(ipi.value == ip_val for ipi in ip_indicators):
                        ver, scope = IOCExtractorService.classify_ip_scope(ip_val)
                        ip_indicators.append(IPIndicator(value=ip_val, version=ver, scope=scope, source=f"attachment ({att_name})"))

        indicators_group = IndicatorsGroup(
            ips=ip_indicators,
            domains=domain_indicators,
            urls=url_indicators,
            email_addresses=email_indicators,
            attachments=attachment_indicators
        )

        headers_obj = HeaderInfo(
            from_header=from_header,
            to=to_header,
            cc=cc_header,
            subject=subject,
            date=date,
            reply_to=reply_to,
            return_path=return_path,
            message_id=message_id,
            received=received_headers,
            authentication_results=auth_results_str
        )

        body_obj = BodyInfo(
            plain_text=plain_text_str,
            html=html_str
        )

        file_meta = FileMeta(
            filename=filename,
            size_bytes=len(content_bytes)
        )

        attachments_info = [
            AttachmentInfo(
                filename=att.filename,
                mime_type=att.mime_type,
                size=att.size,
                sha256=att.sha256,
                md5=att.md5,
                sha1=att.sha1,
                static_analysis=att.static_analysis
            )
            for att in attachment_indicators
        ]

        return EmailAnalysisResponse(
            email_sha256=email_sha256,
            authentication=auth_analysis,
            relay_analysis=relay_analysis,
            indicators=indicators_group,
            url_analysis=analyzed_urls,
            subject=subject,
            from_header=from_header,
            to=to_header,
            cc=cc_header,
            date=date,
            reply_to=reply_to,
            return_path=return_path,
            message_id=message_id,
            received=received_headers,
            authentication_results=auth_results_str,
            plain_text_body=plain_text_str,
            html_body=html_str,
            raw_email=raw_email_str,
            urls=[u.value for u in url_indicators],
            ips=[i.value for i in ip_indicators],
            domains=[d.value for d in domain_indicators],
            emails=[e.value for e in email_indicators],
            attachments=attachments_info,
            file_info=file_meta,
            headers=headers_obj,
            body=body_obj
        )
