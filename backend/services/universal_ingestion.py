"""
Universal Ingestion Gateway for CyberGuard.

Accepts multiple forms of cybersecurity evidence through one consistent backend layer:
- Raw file uploads (EML, PDF, executables, archives, images, audio, video, logs)
- Text inputs (URLs, domains, IPs, email addresses, suspicious message text)
- Structured JSON security events (authentication logs, API logs, system telemetry)

Performs:
1. Input validation & sanitization
2. Deterministic type detection (signatures, standard parsers, magic bytes)
3. Cryptographic hashing & content identity
4. Normalization (URL, domain, IP, email, JSON)
5. Durable persistence into evidence storage
6. Artifact & Ingestion database record creation
7. Candidate analyzer routing registry resolution
8. Provenance preservation and audit trail logging
"""
from __future__ import annotations

import io
import json
import logging
import os
import re
import uuid
import ipaddress
import urllib.parse
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Union
from sqlalchemy.orm import Session

from backend.db.models import (
    ArtifactModel,
    ArtifactStorageRecordModel,
    IngestionRecordModel,
    IndicatorModel,
    RelationshipModel,
    ThreatEventModel,
)
from backend.schemas.unified import (
    ArtifactTypeEnum,
    AnalysisStatusEnum,
    InputModeEnum,
    IndicatorTypeEnum,
    RelationshipTypeEnum,
    SeverityEnum,
    SupportStatusEnum,
    CapabilityStatusEnum,
    DetectedInput,
    AnalyzerCapabilityRead,
    IngestionResult,
    normalize_domain,
    normalize_ip,
    normalize_url,
    normalize_email_address,
)
from backend.services.evidence_storage import (
    evidence_storage,
    StorageBackend,
    StorageError,
    StoragePayloadTooLargeError,
)
from backend.services.upload_security import (
    UploadSecurityService,
    MAX_UPLOAD_SIZE_BYTES,
    MAX_UPLOAD_SIZE_MB,
    RFC822_HEADER_TOKENS,
)
from backend.services.ssrf_protector import SSRFProtector
from backend.services.audit_service import AuditService
from backend.services.unified_service import (
    ArtifactService,
    StorageRecordService,
    IngestionService,
    IndicatorService,
    RelationshipService,
    ThreatEventService,
    get_utc_now,
    generate_uuid,
)

logger = logging.getLogger("cyberguard.ingestion")


# ============================================================================
# INGESTION EXCEPTIONS
# ============================================================================

class IngestionException(Exception):
    """Base exception for all ingestion failures."""
    def __init__(self, message: str, error_code: str = "INGESTION_FAILED", details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.details = details or {}


class InvalidInputError(IngestionException):
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, error_code="INVALID_INPUT", details=details)


class FileTooLargeError(IngestionException):
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, error_code="FILE_TOO_LARGE", details=details)


class UnsupportedFormatError(IngestionException):
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, error_code="UNSUPPORTED_FORMAT", details=details)


class MalformedEventError(IngestionException):
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, error_code="MALFORMED_EVENT", details=details)


class StorageFailureError(IngestionException):
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, error_code="STORAGE_FAILURE", details=details)


# ============================================================================
# CAPABILITY & ROUTING REGISTRY
# ============================================================================

@dataclass
class AnalyzerCapability:
    name: str
    version: str
    supported_artifact_types: List[ArtifactTypeEnum]
    status: CapabilityStatusEnum
    description: str


class CapabilityRegistry:
    """
    Central registry of CyberGuard analyzer capabilities.
    Strictly distinguishes between AVAILABLE analyzers and future NOT_IMPLEMENTED capabilities.
    """
    def __init__(self) -> None:
        self._capabilities: Dict[str, AnalyzerCapability] = {}
        self._register_default_capabilities()

    def register(self, cap: AnalyzerCapability) -> None:
        self._capabilities[cap.name] = cap

    def get(self, name: str) -> Optional[AnalyzerCapability]:
        return self._capabilities.get(name)

    def list_all(self) -> List[AnalyzerCapability]:
        return list(self._capabilities.values())

    def get_candidate_analyzers(self, artifact_type: ArtifactTypeEnum) -> List[str]:
        """Returns names of available or partially supported analyzers for the artifact type."""
        candidates = []
        for name, cap in self._capabilities.items():
            if cap.status in (CapabilityStatusEnum.AVAILABLE, CapabilityStatusEnum.NOT_CONFIGURED):
                if artifact_type in cap.supported_artifact_types:
                    candidates.append(name)
        return candidates

    def _register_default_capabilities(self) -> None:
        # 1. Operational Analyzers in CyberGuard
        self.register(AnalyzerCapability(
            name="email_forensics",
            version="1.0.0",
            supported_artifact_types=[ArtifactTypeEnum.EMAIL],
            status=CapabilityStatusEnum.AVAILABLE,
            description="Parses RFC-822 headers, MIME structure, body tokens, and relay transport hops.",
        ))
        self.register(AnalyzerCapability(
            name="auth_analyzer",
            version="1.0.0",
            supported_artifact_types=[ArtifactTypeEnum.EMAIL],
            status=CapabilityStatusEnum.AVAILABLE,
            description="Evaluates SPF, DKIM, DMARC, and sender domain alignment.",
        ))
        self.register(AnalyzerCapability(
            name="url_analyzer",
            version="1.0.0",
            supported_artifact_types=[ArtifactTypeEnum.URL],
            status=CapabilityStatusEnum.AVAILABLE,
            description="Performs lexical, lookalike, punycode, and display-text mismatch URL analysis.",
        ))
        self.register(AnalyzerCapability(
            name="domain_intelligence",
            version="1.0.0",
            supported_artifact_types=[ArtifactTypeEnum.DOMAIN],
            status=CapabilityStatusEnum.AVAILABLE,
            description="Enriches domains with DNS records, RDAP/WHOIS age, and MX reputation.",
        ))
        self.register(AnalyzerCapability(
            name="ip_intelligence",
            version="1.0.0",
            supported_artifact_types=[ArtifactTypeEnum.IP],
            status=CapabilityStatusEnum.AVAILABLE,
            description="Enriches IP addresses with ASN, geolocation, and infrastructure heuristics.",
        ))
        self.register(AnalyzerCapability(
            name="attachment_intelligence",
            version="1.0.0",
            supported_artifact_types=[ArtifactTypeEnum.ATTACHMENT, ArtifactTypeEnum.FILE],
            status=CapabilityStatusEnum.AVAILABLE,
            description="Static analysis of files and attachments for disguised double extensions and binary headers.",
        ))
        self.register(AnalyzerCapability(
            name="nlp_classifier",
            version="1.0.0",
            supported_artifact_types=[ArtifactTypeEnum.TEXT, ArtifactTypeEnum.EMAIL],
            status=CapabilityStatusEnum.AVAILABLE,
            description="Machine-learning phishing intent, language urgency, and credential harvesting assessment.",
        ))
        self.register(AnalyzerCapability(
            name="threat_scorer",
            version="1.0.0",
            supported_artifact_types=[ArtifactTypeEnum.EMAIL, ArtifactTypeEnum.URL],
            status=CapabilityStatusEnum.AVAILABLE,
            description="Calculates deterministic multi-factor risk scores and severity classifications.",
        ))
        self.register(AnalyzerCapability(
            name="attribution_engine",
            version="1.0.0",
            supported_artifact_types=[ArtifactTypeEnum.EMAIL],
            status=CapabilityStatusEnum.AVAILABLE,
            description="Probabilistic threat infrastructure attribution to threat groups.",
        ))
        self.register(AnalyzerCapability(
            name="ai_analyst",
            version="1.0.0",
            supported_artifact_types=[ArtifactTypeEnum.EMAIL],
            status=CapabilityStatusEnum.AVAILABLE if os.getenv("LLM_API_KEY") or os.getenv("GEMINI_API_KEY") else CapabilityStatusEnum.NOT_CONFIGURED,
            description="LLM-assisted forensic synthesis, timeline generation, and remediation recommendations.",
        ))
        self.register(AnalyzerCapability(
            name="auth_event_parser",
            version="1.0.0",
            supported_artifact_types=[ArtifactTypeEnum.AUTH_LOG],
            status=CapabilityStatusEnum.AVAILABLE,
            description="Normalizes structured authentication logs and produces ThreatEvents.",
        ))
        self.register(AnalyzerCapability(
            name="auth_security_analyzer",
            version="1.0.0",
            supported_artifact_types=[ArtifactTypeEnum.AUTH_LOG],
            status=CapabilityStatusEnum.AVAILABLE,
            description="Analyzes authentication telemetry for brute force, password spray, impossible travel, and account takeover.",
        ))
        self.register(AnalyzerCapability(
            name="file_metadata",
            version="1.0.0",
            supported_artifact_types=[ArtifactTypeEnum.FILE, ArtifactTypeEnum.IMAGE, ArtifactTypeEnum.AUDIO, ArtifactTypeEnum.VIDEO],
            status=CapabilityStatusEnum.AVAILABLE,
            description="Extracts cryptographic SHA-256/SHA-1/MD5 hashes, byte sizes, and file container metadata.",
        ))
        self.register(AnalyzerCapability(
            name="file_security_analyzer",
            version="2.0.0",
            supported_artifact_types=[ArtifactTypeEnum.FILE, ArtifactTypeEnum.ATTACHMENT],
            status=CapabilityStatusEnum.AVAILABLE,
            description="Safe static file analysis: cryptographic identity, format verification, PE, PDF, Office, scripts, archives, and reputation.",
        ))

        # 2. Future / Architectural Placeholders (Explicitly NOT_IMPLEMENTED)
        self.register(AnalyzerCapability(
            name="deepfake_audio",
            version="0.0.0",
            supported_artifact_types=[ArtifactTypeEnum.AUDIO],
            status=CapabilityStatusEnum.NOT_IMPLEMENTED,
            description="Voice clone and spectral anomaly detector (Planned Section 25).",
        ))
        self.register(AnalyzerCapability(
            name="deepfake_video",
            version="0.0.0",
            supported_artifact_types=[ArtifactTypeEnum.VIDEO],
            status=CapabilityStatusEnum.NOT_IMPLEMENTED,
            description="Facial manipulation and temporal artifact detector (Planned Section 26).",
        ))
        self.register(AnalyzerCapability(
            name="endpoint_telemetry_scanner",
            version="0.0.0",
            supported_artifact_types=[ArtifactTypeEnum.ENDPOINT_EVENT],
            status=CapabilityStatusEnum.NOT_IMPLEMENTED,
            description="Real-time host endpoint telemetry scanner (Planned Section 28).",
        ))
        self.register(AnalyzerCapability(
            name="network_security_analyzer",
            version="1.0.0",
            supported_artifact_types=[ArtifactTypeEnum.NETWORK_LOG],
            status=CapabilityStatusEnum.AVAILABLE,
            description="Analyzes defensive network telemetry, NetFlow, DNS logs, and connection summaries for beaconing, bursts, scan patterns, and exfiltration.",
        ))
        self.register(AnalyzerCapability(
            name="api_abuse_analyzer",
            version="1.0.0",
            supported_artifact_types=[ArtifactTypeEnum.API_LOG],
            status=CapabilityStatusEnum.AVAILABLE,
            description="Analyzes defensive API telemetry for rate anomalies, endpoint/resource enumeration, authz failures, scraping, and exfiltration.",
        ))


global_capability_registry = CapabilityRegistry()


# ============================================================================
# DETERMINISTIC TYPE DETECTOR
# ============================================================================

EMAIL_ADDRESS_REGEX = re.compile(
    r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
)

RFC1123_DOMAIN_PATTERN = re.compile(
    r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$'
)


class TypeDetector:
    """
    Deterministic evidence classification service.
    Examines file signatures, magic bytes, structural tokens, and RFC standards
    without invoking heavy external dependencies or LLMs.
    """

    @classmethod
    def detect_file(
        cls,
        content_bytes: bytes,
        filename: Optional[str] = None,
        reported_mime: Optional[str] = None,
    ) -> DetectedInput:
        """
        Classifies raw file bytes into canonical ArtifactTypeEnum with confidence and warnings.
        """
        if not content_bytes or len(content_bytes) == 0:
            raise InvalidInputError("File payload is empty (0 bytes).")

        size = len(content_bytes)
        safe_name = UploadSecurityService.sanitize_filename(filename or "evidence.bin")
        _, ext = os.path.splitext(safe_name.lower())
        warnings: List[str] = []
        meta: Dict[str, Any] = {"size_bytes": size, "original_filename": safe_name}

        # 1. Executable binary check
        is_pe = content_bytes.startswith(b"MZ")
        is_elf = content_bytes.startswith(b"\x7fELF")
        is_macho = content_bytes.startswith((b"\xca\xfe\xba\xbe", b"\xfe\xed\xfa\xce", b"\xcf\xfa\xed\xfe"))
        if is_pe or is_elf or is_macho:
            fmt = "Windows PE" if is_pe else ("Linux ELF" if is_elf else "Mach-O")
            warnings.append(f"Executable binary ({fmt}) detected. Execution is strictly prohibited; static analysis candidate.")
            meta["is_executable"] = True
            meta["binary_format"] = fmt
            return DetectedInput(
                input_mode=InputModeEnum.FILE_UPLOAD,
                artifact_type=ArtifactTypeEnum.FILE,
                detected_mime="application/x-executable",
                reported_mime=reported_mime,
                confidence=0.99,
                detector="binary_magic_executable",
                support_status=SupportStatusEnum.SUPPORTED,
                warnings=warnings,
                candidate_analyzers=global_capability_registry.get_candidate_analyzers(ArtifactTypeEnum.FILE),
                metadata=meta,
            )

        # 2. RFC-822 Email inspection
        # Check first 4KB for standard email headers or "From " mbox marker
        sample_4k = content_bytes[:4096].decode("utf-8", errors="ignore")
        has_rfc_headers = any(pattern.search(sample_4k) for pattern in RFC822_HEADER_TOKENS)
        is_mbox = sample_4k.startswith("From ")
        if has_rfc_headers or is_mbox:
            warnings_email = list(warnings)
            if ext and ext not in (".eml", ".msg", ".txt", ""):
                warnings_email.append(f"MIME/extension mismatch: file has extension '{ext}' but content contains genuine RFC-822 email headers.")
            return DetectedInput(
                input_mode=InputModeEnum.FILE_UPLOAD,
                artifact_type=ArtifactTypeEnum.EMAIL,
                detected_mime="message/rfc822",
                reported_mime=reported_mime,
                confidence=0.98 if has_rfc_headers else 0.85,
                detector="rfc822_header_tokens",
                support_status=SupportStatusEnum.SUPPORTED,
                warnings=warnings_email,
                candidate_analyzers=global_capability_registry.get_candidate_analyzers(ArtifactTypeEnum.EMAIL),
                metadata=meta,
            )

        # 3. PDF document
        if content_bytes.startswith(b"%PDF-"):
            meta["format"] = "PDF"
            return DetectedInput(
                input_mode=InputModeEnum.FILE_UPLOAD,
                artifact_type=ArtifactTypeEnum.FILE,
                detected_mime="application/pdf",
                reported_mime=reported_mime,
                confidence=0.99,
                detector="pdf_header",
                support_status=SupportStatusEnum.SUPPORTED,
                warnings=warnings,
                candidate_analyzers=global_capability_registry.get_candidate_analyzers(ArtifactTypeEnum.FILE),
                metadata=meta,
            )

        # 4. Images
        img_type = None
        img_mime = None
        if content_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
            img_type = "PNG"
            img_mime = "image/png"
            if len(content_bytes) >= 24:
                try:
                    w = int.from_bytes(content_bytes[16:20], byteorder="big")
                    h = int.from_bytes(content_bytes[20:24], byteorder="big")
                    meta["width"] = w
                    meta["height"] = h
                except Exception:
                    pass
        elif content_bytes.startswith(b"\xff\xd8\xff"):
            img_type = "JPEG"
            img_mime = "image/jpeg"
        elif content_bytes.startswith((b"GIF87a", b"GIF89a")):
            img_type = "GIF"
            img_mime = "image/gif"
        elif content_bytes.startswith(b"RIFF") and len(content_bytes) >= 12 and content_bytes[8:12] == b"WEBP":
            img_type = "WEBP"
            img_mime = "image/webp"
        elif content_bytes.startswith(b"BM"):
            img_type = "BMP"
            img_mime = "image/bmp"
        elif content_bytes.startswith((b"II*\x00", b"MM\x00*")):
            img_type = "TIFF"
            img_mime = "image/tiff"
        elif ext in (".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".tiff") or (reported_mime and reported_mime.startswith("image/")):
            img_type = ext.lstrip(".").upper() or "IMAGE"
            img_mime = reported_mime or f"image/{ext.lstrip('.')}"

        if img_type:
            meta["format"] = img_type
            return DetectedInput(
                input_mode=InputModeEnum.FILE_UPLOAD,
                artifact_type=ArtifactTypeEnum.IMAGE,
                detected_mime=img_mime,
                reported_mime=reported_mime,
                confidence=0.96 if img_mime and img_mime != "application/octet-stream" else 0.80,
                detector="image_signature",
                support_status=SupportStatusEnum.SUPPORTED,
                warnings=warnings,
                candidate_analyzers=global_capability_registry.get_candidate_analyzers(ArtifactTypeEnum.IMAGE),
                metadata=meta,
            )

        # 5. Audio
        audio_type = None
        audio_mime = None
        if content_bytes.startswith(b"ID3") or content_bytes.startswith((b"\xff\xfb", b"\xff\xf3")):
            audio_type = "MP3"
            audio_mime = "audio/mpeg"
        elif content_bytes.startswith(b"RIFF") and len(content_bytes) >= 12 and content_bytes[8:12] == b"WAVE":
            audio_type = "WAV"
            audio_mime = "audio/wav"
        elif content_bytes.startswith(b"fLaC"):
            audio_type = "FLAC"
            audio_mime = "audio/flac"
        elif content_bytes.startswith(b"OggS"):
            audio_type = "OGG"
            audio_mime = "audio/ogg"
        elif ext in (".mp3", ".wav", ".flac", ".ogg", ".m4a", ".aac") or (reported_mime and reported_mime.startswith("audio/")):
            audio_type = ext.lstrip(".").upper() or "AUDIO"
            audio_mime = reported_mime or f"audio/{ext.lstrip('.')}"

        if audio_type:
            meta["format"] = audio_type
            warnings.append("Audio evidence persisted. Deepfake voice analysis is currently NOT_IMPLEMENTED.")
            return DetectedInput(
                input_mode=InputModeEnum.FILE_UPLOAD,
                artifact_type=ArtifactTypeEnum.AUDIO,
                detected_mime=audio_mime,
                reported_mime=reported_mime,
                confidence=0.90,
                detector="audio_signature",
                support_status=SupportStatusEnum.PARTIALLY_SUPPORTED,
                warnings=warnings,
                candidate_analyzers=global_capability_registry.get_candidate_analyzers(ArtifactTypeEnum.AUDIO),
                metadata=meta,
            )

        # 6. Video
        video_type = None
        video_mime = None
        if len(content_bytes) >= 12 and content_bytes[4:8] == b"ftyp":
            video_type = "MP4"
            video_mime = "video/mp4"
        elif content_bytes.startswith(b"\x1a\x45\xdf\xa3"):
            video_type = "MKV/WEBM"
            video_mime = "video/webm"
        elif content_bytes.startswith(b"RIFF") and len(content_bytes) >= 12 and content_bytes[8:12] == b"AVI ":
            video_type = "AVI"
            video_mime = "video/x-msvideo"
        elif ext in (".mp4", ".mkv", ".avi", ".mov", ".webm") or (reported_mime and reported_mime.startswith("video/")):
            video_type = ext.lstrip(".").upper() or "VIDEO"
            video_mime = reported_mime or f"video/{ext.lstrip('.')}"

        if video_type:
            meta["format"] = video_type
            warnings.append("Video evidence persisted. Deepfake facial manipulation analysis is currently NOT_IMPLEMENTED.")
            return DetectedInput(
                input_mode=InputModeEnum.FILE_UPLOAD,
                artifact_type=ArtifactTypeEnum.VIDEO,
                detected_mime=video_mime,
                reported_mime=reported_mime,
                confidence=0.90,
                detector="video_signature",
                support_status=SupportStatusEnum.PARTIALLY_SUPPORTED,
                warnings=warnings,
                candidate_analyzers=global_capability_registry.get_candidate_analyzers(ArtifactTypeEnum.VIDEO),
                metadata=meta,
            )

        # 7. Archives
        is_zip = content_bytes.startswith((b"PK\x03\x04", b"PK\x05\x06"))
        is_gz = content_bytes.startswith(b"\x1f\x8b")
        is_7z = content_bytes.startswith(b"7z\xbc\xaf\x27\x1c")
        is_tar = len(content_bytes) >= 262 and content_bytes[257:262] == b"ustar"
        if is_zip or is_gz or is_7z or is_tar or ext in (".zip", ".tar", ".gz", ".7z", ".rar"):
            arch_fmt = "zip" if is_zip else ("gz" if is_gz else ("7z" if is_7z else ("tar" if is_tar else "archive")))
            meta["is_archive"] = True
            meta["archive_format"] = arch_fmt
            warnings.append("Archive file detected. Automatic recursive decompression is deferred to controlled sandboxing.")
            return DetectedInput(
                input_mode=InputModeEnum.FILE_UPLOAD,
                artifact_type=ArtifactTypeEnum.FILE,
                detected_mime="application/zip" if is_zip else "application/octet-stream",
                reported_mime=reported_mime,
                confidence=0.95,
                detector="archive_signature",
                support_status=SupportStatusEnum.SUPPORTED,
                warnings=warnings,
                candidate_analyzers=global_capability_registry.get_candidate_analyzers(ArtifactTypeEnum.FILE),
                metadata=meta,
            )

        # 8. Structured Logs / JSON in file
        if ext in (".json", ".jsonl", ".log") or content_bytes[:10].strip().startswith((b"{", b"[")):
            try:
                decoded = content_bytes.decode("utf-8")
                parsed_json = json.loads(decoded)
                if isinstance(parsed_json, dict):
                    event_det = cls.detect_event(parsed_json)
                    event_det.input_mode = InputModeEnum.FILE_UPLOAD
                    event_det.reported_mime = reported_mime
                    event_det.metadata.update(meta)
                    return event_det
            except Exception:
                pass

        # 9. Plain text fallback
        try:
            sample_text = content_bytes[:4096].decode("utf-8")
            if ext in (".txt", ".log", ".csv", ".tsv") or all(c.isprintable() or c in "\r\n\t " for c in sample_text):
                meta["char_count"] = len(content_bytes)
                return DetectedInput(
                    input_mode=InputModeEnum.FILE_UPLOAD,
                    artifact_type=ArtifactTypeEnum.TEXT,
                    detected_mime="text/plain",
                    reported_mime=reported_mime,
                    confidence=0.85,
                    detector="plain_text_utf8",
                    support_status=SupportStatusEnum.SUPPORTED,
                    warnings=warnings,
                    candidate_analyzers=global_capability_registry.get_candidate_analyzers(ArtifactTypeEnum.TEXT),
                    metadata=meta,
                )
        except UnicodeDecodeError:
            pass

        # 10. Generic Binary
        return DetectedInput(
            input_mode=InputModeEnum.FILE_UPLOAD,
            artifact_type=ArtifactTypeEnum.FILE,
            detected_mime="application/octet-stream",
            reported_mime=reported_mime,
            confidence=0.70,
            detector="binary_fallback",
            support_status=SupportStatusEnum.SUPPORTED,
            warnings=warnings,
            candidate_analyzers=global_capability_registry.get_candidate_analyzers(ArtifactTypeEnum.FILE),
            metadata=meta,
        )

    @classmethod
    def detect_text(cls, text: str) -> DetectedInput:
        """
        Classifies pasted text strings (URLs, domains, IPs, emails, JSON, plain text).
        Performs strictly deterministic syntax validation without network lookups.
        """
        if not text or not isinstance(text, str):
            raise InvalidInputError("Input text cannot be empty or null.")

        clean = text.strip()
        if len(clean) == 0:
            raise InvalidInputError("Input text cannot be empty or whitespace only.")

        meta: Dict[str, Any] = {"raw_length": len(clean)}
        warnings: List[str] = []

        # 1. IP Address Check (IPv4 / IPv6)
        ip_cand = clean.lower().replace("[.]", ".").replace("(.)", ".")
        if ip_cand.startswith("ipv6:"):
            ip_cand = ip_cand[5:].strip()

        ip_obj = None
        try:
            ip_obj = ipaddress.ip_address(ip_cand)
        except ValueError:
            if "." in ip_cand and ":" not in ip_cand:
                parts = ip_cand.split(".")
                if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                    try:
                        clean_octets = ".".join(str(int(p)) for p in parts)
                        ip_obj = ipaddress.ip_address(clean_octets)
                    except ValueError:
                        pass

        if ip_obj is not None:
            meta["ip_version"] = ip_obj.version
            meta["is_loopback"] = ip_obj.is_loopback
            meta["is_private"] = ip_obj.is_private
            meta["is_link_local"] = ip_obj.is_link_local
            meta["is_multicast"] = ip_obj.is_multicast
            meta["is_reserved"] = ip_obj.is_reserved
            meta["is_global"] = ip_obj.is_global

            if ip_obj.is_loopback or ip_obj.is_private or ip_obj.is_link_local:
                meta["is_internal_network"] = True
                warnings.append("Internal/private/loopback IP address detected. Network access is restricted.")

            return DetectedInput(
                input_mode=InputModeEnum.TEXT_INPUT,
                artifact_type=ArtifactTypeEnum.IP,
                confidence=1.0,
                detector="ipaddress_standard_library",
                support_status=SupportStatusEnum.SUPPORTED,
                warnings=warnings,
                candidate_analyzers=global_capability_registry.get_candidate_analyzers(ArtifactTypeEnum.IP),
                metadata=meta,
            )

        # 2. Defanged URL / Standard URL Check
        # Handle defanged hxxp:// or [.]
        url_cleaned = clean.replace("hxxp://", "http://").replace("hxxps://", "https://").replace("[.]", ".").replace("(.)", ".")
        
        # Check scheme or URL structure
        has_scheme = any(url_cleaned.lower().startswith(s) for s in ("http://", "https://", "ftp://"))
        has_url_chars = "/" in url_cleaned or "?" in url_cleaned
        
        is_url = False
        parsed_url = None

        if has_scheme:
            try:
                parsed_url = urllib.parse.urlsplit(url_cleaned)
                if parsed_url.scheme and parsed_url.netloc:
                    is_url = True
            except Exception:
                pass
        elif has_url_chars:
            # Possible scheme-less URL (e.g. "example.com/login" or "192.168.1.1/admin?id=1")
            host_candidate = url_cleaned.split("/")[0].split("?")[0].strip()
            if RFC1123_DOMAIN_PATTERN.match(host_candidate):
                is_url = True
                url_cleaned = "https://" + url_cleaned
                parsed_url = urllib.parse.urlsplit(url_cleaned)
            else:
                try:
                    ipaddress.ip_address(host_candidate)
                    is_url = True
                    url_cleaned = "http://" + url_cleaned
                    parsed_url = urllib.parse.urlsplit(url_cleaned)
                except ValueError:
                    pass

        if is_url and parsed_url:
            host = parsed_url.hostname or ""
            meta["scheme"] = parsed_url.scheme
            meta["host"] = host
            meta["path"] = parsed_url.path
            
            # SSRF safety verification on host without network calls
            is_ssrf_risk = False
            if host.lower() in ("localhost", "127.0.0.1", "0.0.0.0", "::1", "169.254.169.254", "instance-data"):
                is_ssrf_risk = True
            else:
                try:
                    target_ip = ipaddress.ip_address(host)
                    if target_ip.is_loopback or target_ip.is_private or target_ip.is_link_local:
                        is_ssrf_risk = True
                except ValueError:
                    pass

            if is_ssrf_risk:
                meta["is_internal_network"] = True
                meta["ssrf_risk"] = True
                warnings.append("URL targets loopback, private network, or cloud metadata interface (potential SSRF target).")

            return DetectedInput(
                input_mode=InputModeEnum.TEXT_INPUT,
                artifact_type=ArtifactTypeEnum.URL,
                confidence=0.98 if has_scheme else 0.88,
                detector="url_standard_parser",
                support_status=SupportStatusEnum.SUPPORTED,
                warnings=warnings,
                candidate_analyzers=global_capability_registry.get_candidate_analyzers(ArtifactTypeEnum.URL),
                metadata=meta,
            )

        # 3. Email Address Check (RFC 5322)
        if EMAIL_ADDRESS_REGEX.match(clean):
            meta["subtype"] = "EMAIL_ADDRESS"
            meta["normalized_email"] = normalize_email_address(clean)
            return DetectedInput(
                input_mode=InputModeEnum.TEXT_INPUT,
                artifact_type=ArtifactTypeEnum.TEXT,
                confidence=0.98,
                detector="email_address_regex",
                support_status=SupportStatusEnum.SUPPORTED,
                warnings=warnings,
                candidate_analyzers=["ioc_extraction"],
                metadata=meta,
            )

        # 4. Domain Check
        domain_cleaned = clean.replace("[.]", ".").replace("(.)", ".").rstrip(".")
        if RFC1123_DOMAIN_PATTERN.match(domain_cleaned) and not any(c in domain_cleaned for c in ("/", "\\", " ", "\t", ":", "@", "?")):
            meta["domain"] = domain_cleaned.lower()
            if any(domain_cleaned.lower().endswith(s) for s in (".local", ".internal", ".corp", ".lan", ".home")):
                meta["is_internal_network"] = True
                warnings.append("Internal corporate or non-public domain detected.")

            return DetectedInput(
                input_mode=InputModeEnum.TEXT_INPUT,
                artifact_type=ArtifactTypeEnum.DOMAIN,
                confidence=0.95,
                detector="rfc1123_domain_parser",
                support_status=SupportStatusEnum.SUPPORTED,
                warnings=warnings,
                candidate_analyzers=global_capability_registry.get_candidate_analyzers(ArtifactTypeEnum.DOMAIN),
                metadata=meta,
            )

        # 5. Structured JSON in text
        if clean.startswith(("{", "[")) and clean.endswith(("}", "]")):
            try:
                parsed_json = json.loads(clean)
                if isinstance(parsed_json, dict):
                    event_det = cls.detect_event(parsed_json)
                    event_det.input_mode = InputModeEnum.TEXT_INPUT
                    event_det.metadata.update(meta)
                    return event_det
            except Exception:
                pass

        # 6. Social Engineering / Suspicious Message / Plain Text
        meta["char_count"] = len(clean)
        meta["word_count"] = len(clean.split())
        return DetectedInput(
            input_mode=InputModeEnum.TEXT_INPUT,
            artifact_type=ArtifactTypeEnum.TEXT,
            confidence=0.85,
            detector="plain_text_message",
            support_status=SupportStatusEnum.SUPPORTED,
            warnings=warnings,
            candidate_analyzers=global_capability_registry.get_candidate_analyzers(ArtifactTypeEnum.TEXT),
            metadata=meta,
        )

    @classmethod
    def detect_event(cls, event_dict: Dict[str, Any], source_type: Optional[str] = None) -> DetectedInput:
        """
        Classifies structured JSON security events.
        """
        if not isinstance(event_dict, dict):
            raise MalformedEventError("Structured event must be a JSON dictionary.")

        warnings: List[str] = []
        meta = {"event_keys": list(event_dict.keys())}
        src = (source_type or event_dict.get("source_type") or event_dict.get("type") or "").upper()

        if "AUTH" in src or any(k in event_dict for k in ("password", "login", "user_id", "auth_status", "mfa_result", "failed_attempts")):
            art_type = ArtifactTypeEnum.AUTH_LOG
            analyzers = global_capability_registry.get_candidate_analyzers(ArtifactTypeEnum.AUTH_LOG)
        elif "API" in src or any(k in event_dict for k in ("http_method", "endpoint", "status_code", "api_key", "route")):
            art_type = ArtifactTypeEnum.API_LOG
            analyzers = global_capability_registry.get_candidate_analyzers(ArtifactTypeEnum.API_LOG)
        elif "NETWORK" in src or any(k in event_dict for k in ("src_ip", "dst_ip", "src_port", "dst_port", "protocol", "packet_size")):
            art_type = ArtifactTypeEnum.NETWORK_LOG
            analyzers = global_capability_registry.get_candidate_analyzers(ArtifactTypeEnum.NETWORK_LOG)
        elif "ENDPOINT" in src or any(k in event_dict for k in ("process_name", "pid", "parent_pid", "command_line", "host_id")):
            art_type = ArtifactTypeEnum.ENDPOINT_EVENT
            analyzers = global_capability_registry.get_candidate_analyzers(ArtifactTypeEnum.ENDPOINT_EVENT)
        else:
            art_type = ArtifactTypeEnum.SYSTEM_LOG
            analyzers = global_capability_registry.get_candidate_analyzers(ArtifactTypeEnum.SYSTEM_LOG)

        return DetectedInput(
            input_mode=InputModeEnum.STRUCTURED_EVENT,
            artifact_type=art_type,
            detected_mime="application/json",
            confidence=0.92,
            detector="structured_event_schema",
            support_status=SupportStatusEnum.SUPPORTED,
            warnings=warnings,
            candidate_analyzers=analyzers,
            metadata=meta,
        )


# ============================================================================
# UNIVERSAL INGESTION SERVICE
# ============================================================================

class UniversalIngestionService:
    """
    Central orchestration service for universal evidence ingestion.
    Coordinates validation, classification, storage, database records,
    and routing resolution.
    """

    @classmethod
    def detect_only(
        cls,
        text: Optional[str] = None,
        content_bytes: Optional[bytes] = None,
        filename: Optional[str] = None,
        reported_mime: Optional[str] = None,
    ) -> DetectedInput:
        """
        Lightweight classification endpoint: returns detection metadata without
        modifying storage or database state.
        """
        if content_bytes is not None:
            return TypeDetector.detect_file(content_bytes, filename=filename, reported_mime=reported_mime)
        if text is not None:
            return TypeDetector.detect_text(text)
        raise InvalidInputError("Either text or file payload must be provided for detection.")

    @classmethod
    def ingest_file(
        cls,
        db: Session,
        content_bytes: bytes,
        filename: Optional[str] = None,
        reported_mime: Optional[str] = None,
        source: str = "UPLOAD",
        submitted_by: Optional[str] = None,
        notes: Optional[str] = None,
        case_id: Optional[str] = None,
        incident_id: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> IngestionResult:
        """
        Ingests a raw file upload, classifies it, persists bytes, and creates canonical records.
        """
        # 1. Validate file size and content
        if len(content_bytes) > MAX_UPLOAD_SIZE_BYTES:
            raise FileTooLargeError(
                f"Uploaded file exceeds maximum allowed size of {MAX_UPLOAD_SIZE_MB} MB."
            )
        if len(content_bytes) == 0:
            raise InvalidInputError("Uploaded file is empty (0 bytes).")

        safe_name = UploadSecurityService.sanitize_filename(filename or "evidence.bin")
        uploader_name = (submitted_by or "SOC Analyst").strip()
        req_id = request_id or f"REQ-{uuid.uuid4().hex[:12].upper()}"

        AuditService.log_audit(
            db=db,
            action="INGESTION_RECEIVED",
            resource_type="file",
            resource_id=req_id,
            user=uploader_name,
            metadata={"filename": safe_name, "size": len(content_bytes), "source": source},
            details=f"File '{safe_name}' ({len(content_bytes)} bytes) received via Universal Ingestion Gateway."
        )

        # 2. Classify input
        classification = TypeDetector.detect_file(
            content_bytes=content_bytes,
            filename=safe_name,
            reported_mime=reported_mime,
        )

        AuditService.log_audit(
            db=db,
            action="INPUT_CLASSIFIED",
            resource_type="file",
            resource_id=req_id,
            user=uploader_name,
            metadata={
                "artifact_type": classification.artifact_type.value,
                "detector": classification.detector,
                "confidence": classification.confidence,
            },
            details=f"File '{safe_name}' classified as {classification.artifact_type.value} by detector '{classification.detector}'."
        )

        # 3. Persist bytes to content-addressed storage
        try:
            storage_res = evidence_storage.store_bytes(
                data=content_bytes,
                original_filename=safe_name,
                mime_type=classification.detected_mime or reported_mime or "application/octet-stream",
            )
        except Exception as e:
            logger.error("Storage persistence failed for %s: %s", safe_name, e)
            raise StorageFailureError(f"Failed to persist evidence to storage: {str(e)}")

        # 4. Create or retrieve ArtifactModel
        artifact = ArtifactService.create_or_get_artifact(
            db=db,
            artifact_type=classification.artifact_type,
            name=safe_name,
            source=source,
            mime_type=classification.detected_mime or reported_mime,
            size=storage_res.size,
            sha256=storage_res.sha256,
            sha1=storage_res.sha1,
            md5=storage_res.md5,
            storage_reference=storage_res.storage_key,
            metadata={
                "original_filename": safe_name,
                "uploader": uploader_name,
                "notes": notes,
                "classification": classification.model_dump(),
            },
        )

        # 5. Record physical storage record
        StorageRecordService.create_or_get_storage_record(
            db=db,
            artifact_id=artifact.id,
            storage_key=storage_res.storage_key,
            sha256=storage_res.sha256,
            size=storage_res.size,
            mime_type=classification.detected_mime or reported_mime,
            original_filename=safe_name,
            integrity_status="VERIFIED",
        )

        # 6. Record discrete Ingestion provenance
        ingestion = IngestionService.record_ingestion(
            db=db,
            artifact_id=artifact.id,
            source=source,
            submitted_by=uploader_name,
            original_filename=safe_name,
            request_id=req_id,
            context={"notes": notes, "case_id": case_id, "incident_id": incident_id},
            metadata={"classification": classification.model_dump()},
        )

        # 7. Establish association to incident or case if provided
        if incident_id:
            try:
                RelationshipService.create_relationship(
                    db=db,
                    source_type="INCIDENT",
                    source_id=incident_id,
                    relationship_type=RelationshipTypeEnum.ASSOCIATED_WITH,
                    target_type="ARTIFACT",
                    target_id=artifact.id,
                    confidence=1.0,
                    method="INGESTION_LINK",
                )
            except Exception:
                pass

        AuditService.log_audit(
            db=db,
            action="ARTIFACT_CREATED",
            resource_type="artifact",
            resource_id=artifact.id,
            user=uploader_name,
            metadata={"artifact_type": artifact.artifact_type, "sha256": artifact.sha256},
            details=f"Artifact {artifact.id} created and persisted under storage key {storage_res.storage_key}."
        )

        return IngestionResult(
            ingestion_id=ingestion.id,
            artifact_id=artifact.id,
            artifact_type=classification.artifact_type,
            input_mode=InputModeEnum.FILE_UPLOAD,
            name=safe_name,
            sha256=storage_res.sha256,
            size=storage_res.size,
            mime_type=classification.detected_mime or reported_mime,
            classification=classification,
            storage_status="STORED",
            storage_key=storage_res.storage_key,
            analysis_status=AnalysisStatusEnum.INGESTED,
            candidate_analyzers=classification.candidate_analyzers,
            warnings=classification.warnings,
            metadata=json.loads(artifact.metadata_json or "{}"),
            created_at=ingestion.received_at,
        )

    @classmethod
    def ingest_text(
        cls,
        db: Session,
        text: str,
        source: str = "TEXT_INPUT",
        submitted_by: Optional[str] = None,
        notes: Optional[str] = None,
        case_id: Optional[str] = None,
        incident_id: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> IngestionResult:
        """
        Ingests a text input (URL, domain, IP, email address, message, JSON log),
        classifies, normalizes, stores the forensic representation, and registers indicators.
        """
        if not text or not isinstance(text, str) or len(text.strip()) == 0:
            raise InvalidInputError("Text input cannot be empty.")

        clean_text = text.strip()
        uploader_name = (submitted_by or "SOC Analyst").strip()
        req_id = request_id or f"REQ-{uuid.uuid4().hex[:12].upper()}"

        AuditService.log_audit(
            db=db,
            action="INGESTION_RECEIVED",
            resource_type="text",
            resource_id=req_id,
            user=uploader_name,
            metadata={"length": len(clean_text), "source": source},
            details="Text input received via Universal Ingestion Gateway."
        )

        # 1. Classify input
        classification = TypeDetector.detect_text(clean_text)

        # 2. Determine normalized value based on detected type
        orig_val = clean_text
        norm_val = clean_text
        if classification.artifact_type == ArtifactTypeEnum.URL:
            # Defang cleanup if necessary
            target_url = clean_text.replace("hxxp://", "http://").replace("hxxps://", "https://").replace("[.]", ".").replace("(.)", ".")
            if not target_url.lower().startswith(("http://", "https://", "ftp://")):
                target_url = "https://" + target_url
            norm_val = normalize_url(target_url)
        elif classification.artifact_type == ArtifactTypeEnum.DOMAIN:
            clean_dom = clean_text.replace("[.]", ".").replace("(.)", ".").rstrip(".")
            norm_val = normalize_domain(clean_dom)
        elif classification.artifact_type == ArtifactTypeEnum.IP:
            norm_val = normalize_ip(clean_text)
        elif classification.metadata.get("subtype") == "EMAIL_ADDRESS":
            norm_val = normalize_email_address(clean_text)

        AuditService.log_audit(
            db=db,
            action="INPUT_CLASSIFIED",
            resource_type="text",
            resource_id=req_id,
            user=uploader_name,
            metadata={
                "artifact_type": classification.artifact_type.value,
                "detector": classification.detector,
                "confidence": classification.confidence,
                "normalized_value": norm_val,
            },
            details=f"Text input classified as {classification.artifact_type.value} (normalized: {norm_val})."
        )

        # 3. Persist raw text bytes into durable evidence storage
        text_bytes = clean_text.encode("utf-8")
        safe_filename = f"{classification.artifact_type.value.lower()}_{uuid.uuid4().hex[:8]}.txt"
        try:
            storage_res = evidence_storage.store_bytes(
                data=text_bytes,
                original_filename=safe_filename,
                mime_type="text/plain",
            )
        except Exception as e:
            logger.error("Storage persistence failed for text input: %s", e)
            raise StorageFailureError(f"Failed to persist text evidence: {str(e)}")

        # 4. Create or retrieve ArtifactModel
        artifact = ArtifactService.create_or_get_artifact(
            db=db,
            artifact_type=classification.artifact_type,
            name=norm_val[:255],
            source=source,
            mime_type="text/plain",
            size=len(text_bytes),
            sha256=storage_res.sha256,
            sha1=storage_res.sha1,
            md5=storage_res.md5,
            storage_reference=storage_res.storage_key,
            metadata={
                "original_value": orig_val,
                "normalized_value": norm_val,
                "uploader": uploader_name,
                "notes": notes,
                "classification": classification.model_dump(),
            },
        )

        # 5. Record physical storage record
        StorageRecordService.create_or_get_storage_record(
            db=db,
            artifact_id=artifact.id,
            storage_key=storage_res.storage_key,
            sha256=storage_res.sha256,
            size=storage_res.size,
            mime_type="text/plain",
            original_filename=safe_filename,
            integrity_status="VERIFIED",
        )

        # 6. Record discrete Ingestion record
        ingestion = IngestionService.record_ingestion(
            db=db,
            artifact_id=artifact.id,
            source=source,
            submitted_by=uploader_name,
            original_filename=safe_filename,
            request_id=req_id,
            context={"notes": notes, "case_id": case_id, "incident_id": incident_id},
            metadata={"classification": classification.model_dump()},
        )

        # 7. Upsert normalized Indicator if applicable
        if classification.artifact_type in (ArtifactTypeEnum.IP, ArtifactTypeEnum.DOMAIN, ArtifactTypeEnum.URL) or classification.metadata.get("subtype") == "EMAIL_ADDRESS":
            ind_type = (
                IndicatorTypeEnum.EMAIL_ADDRESS if classification.metadata.get("subtype") == "EMAIL_ADDRESS"
                else IndicatorTypeEnum(classification.artifact_type.value)
            )
            IndicatorService.upsert_indicator(
                db=db,
                indicator_type=ind_type,
                value=norm_val,
                confidence=1.0,
                metadata={"source_artifact": artifact.id},
            )

        # 8. Link to incident if provided
        if incident_id:
            try:
                RelationshipService.create_relationship(
                    db=db,
                    source_type="INCIDENT",
                    source_id=incident_id,
                    relationship_type=RelationshipTypeEnum.ASSOCIATED_WITH,
                    target_type="ARTIFACT",
                    target_id=artifact.id,
                    confidence=1.0,
                    method="INGESTION_LINK",
                )
            except Exception:
                pass

        AuditService.log_audit(
            db=db,
            action="ARTIFACT_CREATED",
            resource_type="artifact",
            resource_id=artifact.id,
            user=uploader_name,
            metadata={"artifact_type": artifact.artifact_type, "normalized_value": norm_val},
            details=f"Artifact {artifact.id} created from text input '{norm_val}'."
        )

        return IngestionResult(
            ingestion_id=ingestion.id,
            artifact_id=artifact.id,
            artifact_type=classification.artifact_type,
            input_mode=InputModeEnum.TEXT_INPUT,
            name=norm_val[:255],
            original_value=orig_val,
            normalized_value=norm_val,
            sha256=storage_res.sha256,
            size=len(text_bytes),
            mime_type="text/plain",
            classification=classification,
            storage_status="STORED",
            storage_key=storage_res.storage_key,
            analysis_status=AnalysisStatusEnum.INGESTED,
            candidate_analyzers=classification.candidate_analyzers,
            warnings=classification.warnings,
            metadata=json.loads(artifact.metadata_json or "{}"),
            created_at=ingestion.received_at,
        )

    @classmethod
    def ingest_event(
        cls,
        db: Session,
        event_dict: Dict[str, Any],
        source_type: Optional[str] = None,
        source: str = "STRUCTURED_EVENT",
        submitted_by: Optional[str] = None,
        notes: Optional[str] = None,
        case_id: Optional[str] = None,
        incident_id: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> IngestionResult:
        """
        Ingests a structured JSON event (authentication, API, or system log),
        stores the raw event in evidence storage, creates an Artifact, and records a ThreatEvent.
        """
        if not event_dict or not isinstance(event_dict, dict):
            raise MalformedEventError("Structured event must be a non-empty JSON object.")

        uploader_name = (submitted_by or "SOC Analyst").strip()
        req_id = request_id or f"REQ-{uuid.uuid4().hex[:12].upper()}"

        # 1. Classify event
        classification = TypeDetector.detect_event(event_dict, source_type=source_type)

        AuditService.log_audit(
            db=db,
            action="INGESTION_RECEIVED",
            resource_type="event",
            resource_id=req_id,
            user=uploader_name,
            metadata={"artifact_type": classification.artifact_type.value, "source": source},
            details=f"Structured {classification.artifact_type.value} event received via Universal Ingestion Gateway."
        )

        # 2. Serialize to canonical JSON bytes and store in evidence storage
        json_bytes = json.dumps(event_dict, indent=2, sort_keys=True).encode("utf-8")
        safe_filename = f"{classification.artifact_type.value.lower()}_{uuid.uuid4().hex[:8]}.json"

        try:
            storage_res = evidence_storage.store_bytes(
                data=json_bytes,
                original_filename=safe_filename,
                mime_type="application/json",
            )
        except Exception as e:
            logger.error("Storage persistence failed for structured event: %s", e)
            raise StorageFailureError(f"Failed to persist event evidence: {str(e)}")

        # 3. Create ArtifactModel
        artifact = ArtifactService.create_or_get_artifact(
            db=db,
            artifact_type=classification.artifact_type,
            name=f"{classification.artifact_type.value} Event #{req_id[-6:]}",
            source=source,
            mime_type="application/json",
            size=len(json_bytes),
            sha256=storage_res.sha256,
            sha1=storage_res.sha1,
            md5=storage_res.md5,
            storage_reference=storage_res.storage_key,
            metadata={
                "uploader": uploader_name,
                "notes": notes,
                "raw_event_summary": {k: str(v)[:100] for k, v in list(event_dict.items())[:10]},
                "classification": classification.model_dump(),
            },
        )

        # 4. Storage & Ingestion records
        StorageRecordService.create_or_get_storage_record(
            db=db,
            artifact_id=artifact.id,
            storage_key=storage_res.storage_key,
            sha256=storage_res.sha256,
            size=storage_res.size,
            mime_type="application/json",
            original_filename=safe_filename,
            integrity_status="VERIFIED",
        )

        ingestion = IngestionService.record_ingestion(
            db=db,
            artifact_id=artifact.id,
            source=source,
            submitted_by=uploader_name,
            original_filename=safe_filename,
            request_id=req_id,
            context={"notes": notes, "case_id": case_id, "incident_id": incident_id},
            metadata={"classification": classification.model_dump()},
        )

        # 5. Extract ThreatEvent if event resembles an authentication failure or suspicious access
        if classification.artifact_type == ArtifactTypeEnum.AUTH_LOG:
            event_type = event_dict.get("event_type") or event_dict.get("action") or "authentication_attempt"
            summary = event_dict.get("summary") or event_dict.get("message") or f"Auth event for user {event_dict.get('user', 'unknown')}"
            sev = SeverityEnum.HIGH if "fail" in str(event_type).lower() or event_dict.get("status") == "failure" else SeverityEnum.LOW
            ThreatEventService.create_threat_event(
                db=db,
                event_type=str(event_type),
                summary=str(summary),
                severity=sev,
                source_artifact_id=artifact.id,
                metadata={"raw_keys": list(event_dict.keys())},
            )

        # 6. Incident relationship if provided
        if incident_id:
            try:
                RelationshipService.create_relationship(
                    db=db,
                    source_type="INCIDENT",
                    source_id=incident_id,
                    relationship_type=RelationshipTypeEnum.ASSOCIATED_WITH,
                    target_type="ARTIFACT",
                    target_id=artifact.id,
                    confidence=1.0,
                    method="INGESTION_LINK",
                )
            except Exception:
                pass

        AuditService.log_audit(
            db=db,
            action="ARTIFACT_CREATED",
            resource_type="artifact",
            resource_id=artifact.id,
            user=uploader_name,
            metadata={"artifact_type": artifact.artifact_type},
            details=f"Artifact {artifact.id} created from structured {classification.artifact_type.value} event."
        )

        return IngestionResult(
            ingestion_id=ingestion.id,
            artifact_id=artifact.id,
            artifact_type=classification.artifact_type,
            input_mode=InputModeEnum.STRUCTURED_EVENT,
            name=artifact.name,
            sha256=storage_res.sha256,
            size=len(json_bytes),
            mime_type="application/json",
            classification=classification,
            storage_status="STORED",
            storage_key=storage_res.storage_key,
            analysis_status=AnalysisStatusEnum.INGESTED,
            candidate_analyzers=classification.candidate_analyzers,
            warnings=classification.warnings,
            metadata=json.loads(artifact.metadata_json or "{}"),
            created_at=ingestion.received_at,
        )

    @classmethod
    def register_derived_artifact(
        cls,
        db: Session,
        parent_artifact_id: str,
        artifact_type: ArtifactTypeEnum,
        name: str,
        data_bytes: bytes,
        mime_type: Optional[str] = None,
        relationship_type: RelationshipTypeEnum = RelationshipTypeEnum.CONTAINS,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ArtifactModel:
        """
        Registers a derived artifact (such as an attachment extracted from an email or a URL
        extracted from a document) with full parent linkage and knowledge graph relationship.
        """
        # Verify parent exists
        parent = ArtifactService.get_artifact(db, parent_artifact_id)
        if not parent:
            raise InvalidInputError(f"Parent artifact '{parent_artifact_id}' does not exist.")

        safe_name = UploadSecurityService.sanitize_filename(name)
        storage_res = evidence_storage.store_bytes(
            data=data_bytes,
            original_filename=safe_name,
            mime_type=mime_type or "application/octet-stream",
        )

        child_art = ArtifactService.create_or_get_artifact(
            db=db,
            artifact_type=artifact_type,
            name=safe_name,
            source="EXTRACTION",
            mime_type=mime_type,
            size=storage_res.size,
            sha256=storage_res.sha256,
            sha1=storage_res.sha1,
            md5=storage_res.md5,
            storage_reference=storage_res.storage_key,
            parent_artifact_id=parent.id,
            metadata=metadata or {},
        )

        StorageRecordService.create_or_get_storage_record(
            db=db,
            artifact_id=child_art.id,
            storage_key=storage_res.storage_key,
            sha256=storage_res.sha256,
            size=storage_res.size,
            mime_type=mime_type,
            original_filename=safe_name,
            integrity_status="VERIFIED",
        )

        IngestionService.record_ingestion(
            db=db,
            artifact_id=child_art.id,
            source="DERIVED",
            original_filename=safe_name,
            context={"parent_artifact_id": parent.id},
        )

        # Establish graph relationship
        RelationshipService.create_relationship(
            db=db,
            source_type="ARTIFACT",
            source_id=parent.id,
            relationship_type=relationship_type,
            target_type="ARTIFACT",
            target_id=child_art.id,
            confidence=1.0,
            method="EXTRACTION",
        )

        AuditService.log_audit(
            db=db,
            action="DERIVED_ARTIFACT_CREATED",
            resource_type="artifact",
            resource_id=child_art.id,
            user="System",
            metadata={"parent_artifact_id": parent.id, "artifact_type": child_art.artifact_type},
            details=f"Derived artifact {child_art.id} ('{child_art.name}') created from parent {parent.id}."
        )

        return child_art
