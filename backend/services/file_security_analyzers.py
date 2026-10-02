"""
File Security and Static Malware Analyzers (Section 8).
Implements safe, evidence-driven, zero-execution static file analysis:
1. FileIdentityAnalyzer: Cryptographic hashes (SHA-256 primary, SHA-1, MD5), streaming hashing,
   magic byte MIME verification, claimed vs detected mismatch (FILE_TYPE_MISMATCH), polyglot detection.
2. FilenameSecurityAnalyzer: Original filename preservation, safe display name, double extension
   evasion (DOUBLE_EXTENSION), misleading chains, Unicode deception (UNICODE_FILENAME_DECEPTION, RLO).
3. DocumentStaticAnalyzer: Safe PDF analysis (JavaScript, OpenAction, Launch, EmbeddedFiles, URIs,
   encryption, metadata) and Office analysis (DOCX, XLSX, PPTX, DOCM, XLSM, OLE, macros, external rels).
4. ExecutableStaticAnalyzer: Static PE analysis (architecture, compile time, sections, entropy,
   Authenticode status, suspicious imports) and Shannon entropy (HIGH_ENTROPY_CONTENT).
5. ScriptStaticAnalyzer: Static text analysis for PowerShell, Bash, Batch, VBScript, JavaScript, Python
   (encoded commands, remote downloaders, shell chains, credentials, persistence).
6. ArchiveSecurityAnalyzer: Safe ZIP, TAR, GZIP inspection with Zip-Slip path traversal defense,
   Zip-Bomb limits (entries, uncompressed bytes, compression ratio), password detection, child extraction.
7. FileIOCAnalyzer: Bounded string observable extraction (URLs, domains, IPs, emails, hashes).
8. FileReputationAnalyzer: Hash reputation lookup via ThreatIntelligenceService (NO MATCH != SAFE).
9. FileClassificationService: Conservative classification (KNOWN_MALICIOUS, MALWARE_SUSPECTED, SUSPICIOUS, BENIGN_LIKELY, UNKNOWN).
"""
from __future__ import annotations

import io
import math
import os
import re
import struct
import tarfile
import unicodedata
import zipfile
import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from backend.schemas.unified import (
    ArtifactTypeEnum,
    AnalysisStatusEnum,
    FindingMethodEnum,
    IndicatorTypeEnum,
    RelationshipTypeEnum,
    SeverityEnum,
    normalize_domain,
    normalize_ip,
    normalize_url,
)
from backend.services.threat_intelligence_service import ThreatIntelligenceService, ThreatIntelResult
from backend.services.upload_security import UploadSecurityService
from backend.schemas.file_security import (
    PESectionInfo,
    PEImportInfo,
    PEMetadata,
    PDFStaticMetadata,
    OfficeStaticMetadata,
    ScriptStaticMetadata,
    ArchiveEntryInfo,
    ArchiveStaticMetadata,
    ImageStaticMetadata,
    FileIdentityInfo,
    FilenameSecurityInfo,
    EntropyEvaluation,
    ThreatIntelHashInfo,
    DerivedChildArtifact,
)

# Optional image inspection via Pillow
try:
    from PIL import Image as PILImage
    from PIL.ExifTags import TAGS as EXIF_TAGS
    HAS_PILLOW = True
except ImportError:
    HAS_PILLOW = False


# ============================================================================
# ANALYZER EXECUTION CONTAINER
# ============================================================================

class AnalyzerExecutionResult:
    """Standard container for analyzer findings, evidence, indicators, and relationships."""

    def __init__(self, analyzer_name: str, version: str = "1.0.0"):
        self.analyzer_name = analyzer_name
        self.version = version
        self.status: AnalysisStatusEnum = AnalysisStatusEnum.COMPLETED
        self.findings: List[Dict[str, Any]] = []
        self.evidence_items: List[Dict[str, Any]] = []
        self.finding_evidence_links: List[Tuple[int, int, float, str]] = []  # (finding_idx, evidence_idx, relevance, notes)
        self.indicators: List[Dict[str, Any]] = []
        self.relationships: List[Dict[str, Any]] = []
        self.threat_events: List[Dict[str, Any]] = []
        self.derived_artifacts: List[Dict[str, Any]] = []
        self.metadata: Dict[str, Any] = {}
        self.errors: List[str] = []

    def add_evidence(
        self,
        source: str,
        evidence_type: str,
        raw_content: Optional[str] = None,
        parsed_content: Optional[Dict[str, Any]] = None,
        confidence: float = 1.0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> int:
        idx = len(self.evidence_items)
        self.evidence_items.append({
            "source": source,
            "evidence_type": evidence_type,
            "raw_content": raw_content,
            "parsed_content": parsed_content or {},
            "confidence": confidence,
            "metadata": metadata or {},
        })
        return idx

    def add_finding(
        self,
        title: str,
        description: str,
        finding_type: str,
        category: str,
        severity: SeverityEnum,
        confidence: float = 1.0,
        method: FindingMethodEnum = FindingMethodEnum.DETERMINISTIC,
        mitre_technique_id: Optional[str] = None,
        remediation: Optional[str] = None,
        evidence_indices: Optional[List[int]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> int:
        idx = len(self.findings)
        self.findings.append({
            "title": title,
            "description": description,
            "finding_type": finding_type,
            "category": category,
            "severity": severity,
            "confidence": confidence,
            "method": method,
            "mitre_technique_id": mitre_technique_id,
            "remediation": remediation,
            "metadata": metadata or {},
        })
        if evidence_indices:
            for e_idx in evidence_indices:
                self.finding_evidence_links.append((idx, e_idx, 1.0, "Supporting evidence"))
        return idx

    def add_indicator(
        self,
        indicator_type: IndicatorTypeEnum,
        value: str,
        normalized_value: Optional[str] = None,
        reputation: Optional[str] = None,
        threat_types: Optional[str] = None,
        source: Optional[str] = None,
    ):
        norm = normalized_value
        if not norm:
            if indicator_type == IndicatorTypeEnum.URL:
                norm = normalize_url(value)
            elif indicator_type == IndicatorTypeEnum.DOMAIN:
                norm = normalize_domain(value)
            elif indicator_type == IndicatorTypeEnum.IP:
                norm = normalize_ip(value)
            elif indicator_type == IndicatorTypeEnum.FILE_HASH:
                norm = value.strip().lower()
            else:
                norm = value.strip()

        self.indicators.append({
            "indicator_type": indicator_type,
            "value": value,
            "normalized_value": norm,
            "reputation": reputation,
            "threat_types": threat_types,
            "source": source,
        })

    def add_relationship(
        self,
        source_type: str,
        source_id: str,
        relationship_type: RelationshipTypeEnum,
        target_type: str,
        target_id: str,
        confidence: float = 1.0,
        method: str = "DETERMINISTIC",
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self.relationships.append({
            "source_type": source_type,
            "source_id": source_id,
            "relationship_type": relationship_type,
            "target_type": target_type,
            "target_id": target_id,
            "confidence": confidence,
            "method": method,
            "metadata": metadata or {},
        })


# ============================================================================
# 1. FILE IDENTITY ANALYZER
# ============================================================================

class FileIdentityAnalyzer:
    """
    Extracts cryptographic identity (SHA-256 primary, SHA-1, MD5 via streaming),
    verifies magic bytes signatures against claimed file type / Content-Type,
    and detects polyglot/ambiguous file structures.
    """
    name = "file_identity"
    version = "2.0.0"

    SUSPICIOUS_EXTENSIONS = {
        ".exe", ".scr", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
        ".wsf", ".wsh", ".ps1", ".ps1xml", ".ps2", ".psc1", ".psc2",
        ".msh", ".msh1", ".msh2", ".mshxml", ".msh1xml", ".msh2xml",
        ".jar", ".iso", ".img", ".vhd", ".vhdx", ".hta", ".cpl", ".msc",
        ".inf", ".reg", ".dll", ".sys", ".drv", ".ocx", ".pif", ".com",
        ".docm", ".xlsm", ".pptm"
    }

    @classmethod
    def calculate_streaming_hashes(cls, stream_or_bytes: Any) -> Tuple[str, str, str]:
        """
        Calculates SHA-256 (primary integrity identifier), SHA-1, and MD5 using streaming chunks.
        Never loads massive files entirely into memory solely to calculate hashes.
        """
        h_sha256 = hashlib.sha256()
        h_sha1 = hashlib.sha1()
        h_md5 = hashlib.md5()

        if isinstance(stream_or_bytes, bytes):
            stream = io.BytesIO(stream_or_bytes)
        else:
            stream = stream_or_bytes

        # Save position if seekable
        seekable = hasattr(stream, "seek") and hasattr(stream, "tell")
        orig_pos = stream.tell() if seekable else 0

        chunk_size = 64 * 1024
        while True:
            chunk = stream.read(chunk_size)
            if not chunk:
                break
            h_sha256.update(chunk)
            h_sha1.update(chunk)
            h_md5.update(chunk)

        if seekable:
            stream.seek(orig_pos)

        return h_sha256.hexdigest(), h_sha1.hexdigest(), h_md5.hexdigest()

    @classmethod
    def detect_file_type(cls, payload: bytes, filename: str, reported_mime: Optional[str] = None) -> Tuple[str, str, str, bool]:
        """
        Inspects file signatures, magic bytes, and container structure to determine
        (detected_type, detected_mime, claimed_type, is_polyglot).
        Never trusts client-reported Content-Type or filename extension alone.
        """
        clean_fn = UploadSecurityService.sanitize_filename(filename or "file.bin")
        lower_fn = clean_fn.lower()
        _, ext = os.path.splitext(lower_fn)

        claimed = "Generic binary"
        if ext == ".pdf":
            claimed = "PDF document"
        elif ext in (".docx", ".doc"):
            claimed = "Microsoft Word document"
        elif ext in (".xlsx", ".xls"):
            claimed = "Microsoft Excel spreadsheet"
        elif ext in (".pptx", ".ppt"):
            claimed = "Microsoft PowerPoint presentation"
        elif ext == ".docm":
            claimed = "Word Macro-enabled document"
        elif ext == ".xlsm":
            claimed = "Excel Macro-enabled spreadsheet"
        elif ext in (".zip", ".7z", ".rar", ".tar", ".gz"):
            claimed = "Archive"
        elif ext in (".exe", ".dll", ".scr", ".com", ".sys"):
            claimed = "Windows executable"
        elif ext in (".html", ".htm"):
            claimed = "HTML document"
        elif ext in (".ps1", ".bat", ".cmd", ".sh", ".vbs", ".js", ".py"):
            claimed = f"Script ({ext})"
        elif ext in (".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp"):
            claimed = "Image"
        elif ext == ".txt":
            claimed = "Plain text"

        is_polyglot = False

        # 1. PDF detection (%PDF-)
        if payload.startswith(b"%PDF-"):
            return "PDF document", "application/pdf", claimed, False

        # 2. Windows PE detection (MZ ... PE\0\0)
        if payload.startswith(b"MZ") and len(payload) >= 64:
            try:
                e_lfanew = struct.unpack_from("<I", payload, 0x3C)[0]
                if e_lfanew + 4 <= len(payload) and payload[e_lfanew:e_lfanew+4] == b"PE\x00\x00":
                    return "Windows executable", "application/vnd.microsoft.portable-executable", claimed, False
            except Exception:
                pass
            return "DOS Executable / MZ binary", "application/x-dosexec", claimed, False

        # 3. Linux ELF detection
        if payload.startswith(b"\x7fELF"):
            return "Linux ELF executable", "application/x-executable", claimed, False

        # 4. Mach-O detection
        if payload.startswith((b"\xca\xfe\xba\xbe", b"\xfe\xed\xfa\xce", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe")):
            return "Mach-O executable", "application/x-mach-binary", claimed, False

        # 5. ZIP-based containers (PK\x03\x04)
        if payload.startswith(b"PK\x03\x04"):
            try:
                with zipfile.ZipFile(io.BytesIO(payload), "r") as zf:
                    namelist = [n.lower() for n in zf.namelist()]
                    is_word = any(n.startswith("word/") for n in namelist)
                    is_excel = any(n.startswith("xl/") for n in namelist)
                    is_ppt = any(n.startswith("ppt/") for n in namelist)
                    has_vba = any("vbaproject.bin" in n for n in namelist)

                    if has_vba:
                        if is_word:
                            return "Word Macro-enabled document (DOCM)", "application/vnd.ms-word.document.macroEnabled.12", claimed, False
                        if is_excel:
                            return "Excel Macro-enabled spreadsheet (XLSM)", "application/vnd.ms-excel.sheet.macroEnabled.12", claimed, False
                        if is_ppt:
                            return "PowerPoint Macro-enabled presentation (PPTM)", "application/vnd.ms-powerpoint.presentation.macroEnabled.12", claimed, False
                        return "Office OpenXML (Macro-enabled)", "application/vnd.ms-office.vbaProject", claimed, False

                    if is_word:
                        return "Microsoft Word OpenXML (DOCX)", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", claimed, False
                    if is_excel:
                        return "Microsoft Excel OpenXML (XLSX)", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", claimed, False
                    if is_ppt:
                        return "Microsoft PowerPoint OpenXML (PPTX)", "application/vnd.openxmlformats-officedocument.presentationml.presentation", claimed, False
                    if any(n.startswith("meta-inf/") for n in namelist):
                        return "Java Archive (JAR)", "application/java-archive", claimed, False

                    return "ZIP Archive", "application/zip", claimed, False
            except Exception:
                return "ZIP Archive", "application/zip", claimed, False

        # 6. OLE Compound Document (\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1)
        if payload.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
            if b"WordDocument" in payload:
                return "Microsoft Word 97-2003 Document (DOC)", "application/msword", claimed, False
            if b"Workbook" in payload:
                return "Microsoft Excel 97-2003 Spreadsheet (XLS)", "application/vnd.ms-excel", claimed, False
            if b"PowerPoint Document" in payload:
                return "Microsoft PowerPoint 97-2003 Presentation (PPT)", "application/vnd.ms-powerpoint", claimed, False
            return "OLE Compound Document", "application/x-ole-storage", claimed, False

        # 7. GZIP Archive
        if payload.startswith(b"\x1f\x8b"):
            return "GZIP Archive", "application/gzip", claimed, False

        # 8. TAR Archive (magic at offset 257)
        if len(payload) >= 262 and payload[257:262] == b"ustar":
            return "TAR Archive", "application/x-tar", claimed, False

        # 9. 7-Zip Archive
        if payload.startswith(b"7z\xbc\xaf\x27\x1c"):
            return "7-Zip Archive", "application/x-7z-compressed", claimed, False

        # 10. RAR Archive
        if payload.startswith((b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00")):
            return "RAR Archive", "application/vnd.rar", claimed, False

        # 11. Images
        if payload.startswith(b"\x89PNG\r\n\x1a\n"):
            return "PNG Image", "image/png", claimed, False
        if payload.startswith(b"\xff\xd8\xff"):
            return "JPEG Image", "image/jpeg", claimed, False
        if payload.startswith((b"GIF87a", b"GIF89a")):
            # Check for GIF-ZIP polyglot
            if b"PK\x03\x04" in payload:
                is_polyglot = True
            return "GIF Image", "image/gif", claimed, is_polyglot
        if payload.startswith(b"RIFF") and len(payload) >= 12 and payload[8:12] == b"WEBP":
            return "WebP Image", "image/webp", claimed, False
        if payload.startswith(b"BM"):
            return "BMP Image", "image/bmp", claimed, False

        # 12. Text, Scripts & HTML
        sample = payload[:2048].decode("latin-1", errors="ignore").lower().strip()
        if sample.startswith(("<html", "<!doctype html", "<head", "<body")):
            return "HTML document", "text/html", claimed, False

        if ext == ".ps1" or (sample.startswith(("#", "$")) and ("powershell" in sample or "invoke-" in sample or "-command" in sample)):
            return "PowerShell Script", "application/x-powershell", claimed, False

        if sample.startswith(("#!/bin/sh", "#!/bin/bash", "#!/usr/bin/env sh", "#!/usr/bin/env bash")) or ext == ".sh":
            return "Shell Script", "application/x-sh", claimed, False

        if sample.startswith(("@echo off", "rem ", "setlocal")) or ext in (".bat", ".cmd"):
            return "Batch Script", "application/x-bat", claimed, False

        if ext == ".js" or sample.startswith(("function", "var ", "let ", "const ", "(function")):
            return "JavaScript Source", "application/javascript", claimed, False

        if ext == ".py" or sample.startswith(("#!/usr/bin/env python", "import ", "def ", "class ")):
            return "Python Script", "text/x-python", claimed, False

        if ext == ".vbs" or sample.startswith(("dim ", "set ", "wscript.")):
            return "VBScript Source", "text/vbscript", claimed, False

        # Plain text
        try:
            payload[:4096].decode("utf-8")
            if not any(b == 0 for b in payload[:1024]):
                return "Plain text", "text/plain", claimed, False
        except UnicodeDecodeError:
            pass

        return "Generic binary", "application/octet-stream", claimed, False

    def analyze(
        self,
        payload_bytes: bytes,
        filename: str,
        reported_mime: Optional[str] = None,
    ) -> Tuple[AnalyzerExecutionResult, FileIdentityInfo]:
        result = AnalyzerExecutionResult(self.name, self.version)
        size_bytes = len(payload_bytes)

        # 1. Hashes
        sha256_hash, sha1_hash, md5_hash = self.calculate_streaming_hashes(payload_bytes)

        # 2. File type identification
        detected_type, detected_mime, claimed_type, is_polyglot = self.detect_file_type(
            payload_bytes, filename, reported_mime
        )

        clean_fn = UploadSecurityService.sanitize_filename(filename or "file.bin")
        _, ext = os.path.splitext(clean_fn.lower())

        # Safe display name
        safe_display = re.sub(r'[\r\n\x00-\x1f\x7f]', '', os.path.basename(clean_fn)) or "unnamed_file"

        identity_info = FileIdentityInfo(
            sha256=sha256_hash,
            sha1=sha1_hash,
            md5=md5_hash,
            size_bytes=size_bytes,
            original_filename=filename,
            safe_display_name=safe_display,
            claimed_extension=ext or ".bin",
            reported_mime=reported_mime,
            detected_mime=detected_mime,
            detected_file_type=detected_type,
            is_polyglot=is_polyglot,
        )

        # Evidence: Identity
        e_idx = result.add_evidence(
            source="FILE_IDENTITY_ANALYZER",
            evidence_type="FILE_IDENTIFIER",
            raw_content=f"SHA-256: {sha256_hash}, Size: {size_bytes} bytes",
            parsed_content={
                "sha256": sha256_hash,
                "sha1": sha1_hash,
                "md5": md5_hash,
                "size_bytes": size_bytes,
                "detected_type": detected_type,
                "detected_mime": detected_mime,
                "claimed_type": claimed_type,
                "claimed_extension": ext,
                "reported_mime": reported_mime,
                "is_polyglot": is_polyglot,
            },
            confidence=1.0,
        )

        # Register Indicators for file hashes
        result.add_indicator(
            indicator_type=IndicatorTypeEnum.FILE_HASH,
            value=sha256_hash,
            source=f"FILE_SHA256 ({safe_display})",
        )
        result.add_indicator(
            indicator_type=IndicatorTypeEnum.FILENAME,
            value=safe_display,
            source="ATTACHMENT_NAME",
        )

        # Check for Meaningful Disagreement (FILE_TYPE_MISMATCH)
        is_mismatch = False
        mismatch_desc = None
        severity = SeverityEnum.MEDIUM

        if "Windows executable" in detected_type or "Linux ELF" in detected_type or "Mach-O" in detected_type:
            if ext not in (".exe", ".dll", ".scr", ".com", ".sys", ".elf", ".bin", ""):
                is_mismatch = True
                severity = SeverityEnum.HIGH
                mismatch_desc = (
                    f"Executable payload ({detected_type}) disguised as non-executable '{ext}' "
                    f"(Claimed type: {claimed_type}, Detected MIME: {detected_mime})"
                )
            # Record finding for executable
            result.add_finding(
                title=f"Executable Binary Payload: {detected_type}",
                description=f"File contains valid compiled executable headers ({detected_type}). Untrusted binary content must remain inert.",
                finding_type="EXECUTABLE_ATTACHMENT",
                category="FILE_STRUCTURE",
                severity=SeverityEnum.MEDIUM,
                confidence=1.0,
                evidence_indices=[e_idx],
                metadata={"detected_type": detected_type, "detected_mime": detected_mime},
            )

        elif "PDF" in detected_type:
            if ext != ".pdf":
                is_mismatch = True
                mismatch_desc = f"PDF payload disguised with non-PDF extension '{ext}'"
        elif "ZIP Archive" in detected_type:
            if ext not in (".zip", ".jar", ".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm"):
                is_mismatch = True
                mismatch_desc = f"ZIP archive disguised with non-archive extension '{ext}'"
        elif "Macro-enabled" in detected_type:
            if ext in (".docx", ".xlsx", ".pptx", ".pdf", ".txt", ".jpg", ".png"):
                is_mismatch = True
                severity = SeverityEnum.HIGH
                mismatch_desc = f"Macro-bearing Office document disguised with clean extension '{ext}'"
        elif "Script" in detected_type or "PowerShell" in detected_type or "Shell Script" in detected_type or "Batch Script" in detected_type:
            if ext in (".pdf", ".docx", ".xlsx", ".jpg", ".png", ".txt"):
                is_mismatch = True
                severity = SeverityEnum.HIGH
                mismatch_desc = f"Script payload ({detected_type}) disguised with clean data extension '{ext}'"
            result.add_finding(
                title=f"Script Payload Detected: {detected_type}",
                description=f"File contains executable script commands ({detected_type}). Inspected via static analysis only.",
                finding_type="SCRIPT_ATTACHMENT",
                category="FILE_STRUCTURE",
                severity=SeverityEnum.LOW,
                confidence=0.95,
                evidence_indices=[e_idx],
                metadata={"script_type": detected_type},
            )

        if is_mismatch and mismatch_desc:
            result.add_finding(
                title="File Type and Extension Mismatch Detected",
                description=mismatch_desc,
                finding_type="FILE_TYPE_MISMATCH",
                category="EVASION",
                severity=severity,
                confidence=0.99,
                mitre_technique_id="T1036.008",  # Masquerading: File Type Ambiguities
                remediation="Treat as high-risk evasion attempt. Validate original provenance before handling.",
                evidence_indices=[e_idx],
                metadata={"detected_type": detected_type, "claimed_type": claimed_type, "extension": ext},
            )

        # Polyglot Finding
        if is_polyglot:
            result.add_finding(
                title="Ambiguous File Structure (Polyglot / Mixed Signatures)",
                description=f"File payload exhibits multiple valid file format headers (e.g. GIF + ZIP). Note: polyglot files can be used for bypass or legitimate containers.",
                finding_type="AMBIGUOUS_FILE_STRUCTURE",
                category="FILE_STRUCTURE",
                severity=SeverityEnum.MEDIUM,
                confidence=0.90,
                evidence_indices=[e_idx],
                metadata={"detected_type": detected_type},
            )

        return result, identity_info


# ============================================================================
# 2. FILENAME SECURITY ANALYZER
# ============================================================================

class FilenameSecurityAnalyzer:
    """
    Safely analyzes original filenames for double extensions, misleading extension chains,
    and deceptive Unicode control characters (Right-to-Left Override, BiDi, invisible chars).
    Guarantees non-ASCII international filenames are NOT falsely flagged as suspicious.
    """
    name = "filename_security"
    version = "2.0.0"

    DOC_EXTENSIONS = {
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".txt", ".jpg", ".jpeg", ".png", ".csv", ".rtf", ".odt"
    }

    EXEC_EXTENSIONS = FileIdentityAnalyzer.SUSPICIOUS_EXTENSIONS

    # Suspicious BiDi and invisible Unicode characters
    SUSPICIOUS_UNICODE_CODEPOINTS = {
        0x202E: "RIGHT-TO-LEFT OVERRIDE (RLO)",
        0x202D: "LEFT-TO-RIGHT OVERRIDE (LRO)",
        0x202A: "LEFT-TO-RIGHT EMBEDDING (LRE)",
        0x202B: "RIGHT-TO-LEFT EMBEDDING (RLE)",
        0x202C: "POP DIRECTIONAL FORMATTING (PDF)",
        0x2066: "LEFT-TO-RIGHT ISOLATE (LRI)",
        0x2067: "RIGHT-TO-LEFT ISOLATE (RLI)",
        0x2068: "FIRST STRONG ISOLATE (FSI)",
        0x2069: "POP DIRECTIONAL ISOLATE (PDI)",
        0x200B: "ZERO WIDTH SPACE",
        0x200C: "ZERO WIDTH NON-JOINER",
        0x200D: "ZERO WIDTH JOINER",
        0xFEFF: "ZERO WIDTH NO-BREAK SPACE / BOM",
        0x00AD: "SOFT HYPHEN",
    }

    def analyze(self, raw_filename: str) -> Tuple[AnalyzerExecutionResult, FilenameSecurityInfo]:
        result = AnalyzerExecutionResult(self.name, self.version)
        signals: List[str] = []
        fn = raw_filename or "unnamed_file"

        # 1. Unicode control character inspection
        detected_unicode_controls: List[str] = []
        has_unicode_deception = False

        for idx, ch in enumerate(fn):
            cp = ord(ch)
            if cp in self.SUSPICIOUS_UNICODE_CODEPOINTS:
                has_unicode_deception = True
                name = self.SUSPICIOUS_UNICODE_CODEPOINTS[cp]
                detected_unicode_controls.append(f"U+{cp:04X} ({name}) at character index {idx}")

        if has_unicode_deception:
            signals.append(f"Deceptive Unicode control character(s) detected: {', '.join(detected_unicode_controls)}")
            e_idx = result.add_evidence(
                source="FILENAME_SECURITY_ANALYZER",
                evidence_type="UNICODE_FILENAME_ANOMALY",
                raw_content=fn,
                parsed_content={
                    "raw_filename": fn,
                    "controls": detected_unicode_controls,
                },
            )
            result.add_finding(
                title="Deceptive Unicode Control Characters in Filename",
                description=(
                    f"Filename contains directional or invisible Unicode override characters: "
                    f"{'; '.join(detected_unicode_controls)}. Attackers use Right-to-Left Override (RLO) "
                    f"to reverse visual extension presentation (e.g. invoice[RLO]cod.exe appears as invoiceexe.doc)."
                ),
                finding_type="UNICODE_FILENAME_DECEPTION",
                category="EVASION",
                severity=SeverityEnum.HIGH,
                confidence=1.0,
                mitre_technique_id="T1036.002",  # Right-to-Left Override
                remediation="Do not open based on visual appearance. Inspect true extension and binary magic bytes.",
                evidence_indices=[e_idx],
                metadata={"detected_controls": detected_unicode_controls},
            )

        # 2. Double Extension & Misleading Chains
        parts = fn.lower().split(".")
        is_double_ext = False
        is_deceptive = False

        if len(parts) >= 3:
            first_ext = f".{parts[-2]}"
            second_ext = f".{parts[-1]}"

            if first_ext in self.DOC_EXTENSIONS and second_ext in self.EXEC_EXTENSIONS:
                is_double_ext = True
                signals.append(f"Double extension evasion: inner '{first_ext}' disguised before executable '{second_ext}'")
                e_idx = result.add_evidence(
                    source="FILENAME_SECURITY_ANALYZER",
                    evidence_type="DOUBLE_EXTENSION_ANOMALY",
                    raw_content=fn,
                    parsed_content={"inner_extension": first_ext, "outer_extension": second_ext},
                )
                result.add_finding(
                    title="Double Extension Evasion Technique Detected",
                    description=(
                        f"Filename '{fn}' employs dual extensions ({first_ext}{second_ext}) to mislead users into "
                        f"treating an executable binary as an inert document."
                    ),
                    finding_type="DOUBLE_EXTENSION",
                    category="EVASION",
                    severity=SeverityEnum.HIGH,
                    confidence=1.0,
                    mitre_technique_id="T1036.007",  # Double File Extension
                    remediation="Block execution and verify user intent.",
                    evidence_indices=[e_idx],
                    metadata={"inner_ext": first_ext, "outer_ext": second_ext},
                )

        if len(parts) > 4:
            is_deceptive = True
            signals.append(f"Excessive extension chain detected ({len(parts)-1} dot-separated segments)")
            e_idx = result.add_evidence(
                source="FILENAME_SECURITY_ANALYZER",
                evidence_type="EXCESSIVE_EXTENSION_CHAIN",
                raw_content=fn,
                parsed_content={"segments": parts},
            )
            result.add_finding(
                title="Deceptive Filename: Excessive Extension Chain",
                description=f"Filename '{fn}' contains multiple chained extensions designed to confuse OS extension handlers.",
                finding_type="DECEPTIVE_FILENAME",
                category="EVASION",
                severity=SeverityEnum.MEDIUM,
                confidence=0.90,
                evidence_indices=[e_idx],
            )

        info = FilenameSecurityInfo(
            is_double_extension=is_double_ext,
            is_deceptive=is_deceptive,
            has_unicode_deception=has_unicode_deception,
            detected_control_characters=detected_unicode_controls,
            signals=signals,
        )

        return result, info


# ============================================================================
# 3. DOCUMENT STATIC ANALYZER (PDF & OFFICE)
# ============================================================================

class DocumentStaticAnalyzer:
    """
    Safely inspects PDF and Microsoft Office documents (OpenXML & OLE).
    Strict Security Mandates:
    - Never execute PDF JavaScript or render via external applications.
    - Never execute Office macros or instantiate OLE controls.
    - Inspects structural objects, auto-actions, external relationships, and metadata.
    """
    name = "document_static_analyzer"
    version = "2.0.0"

    @classmethod
    def parse_pdf(cls, payload: bytes) -> Tuple[AnalyzerExecutionResult, PDFStaticMetadata]:
        result = AnalyzerExecutionResult(cls.name, cls.version)
        warnings: List[str] = []

        if not payload.startswith(b"%PDF-"):
            return result, PDFStaticMetadata(is_pdf=False, warnings=["Missing %PDF- magic header"])

        version_match = re.search(rb'%PDF-(\d+\.\d+)', payload[:64])
        pdf_version = version_match.group(1).decode("latin-1") if version_match else "1.0"

        # Check for JavaScript (/JavaScript or /JS)
        has_js = bool(re.search(rb'/(?:JavaScript|JS)\b', payload, re.IGNORECASE))
        js_snippets: List[str] = []
        if has_js:
            for match in re.finditer(rb'/(?:JavaScript|JS)\s*(?:<<[^>]*>>|\(([^)]+)\)|\<([^>]+)\>)', payload, re.IGNORECASE):
                snip = match.group(1) or match.group(2) or match.group(0)
                decoded = snip.decode("latin-1", errors="replace").strip()
                if decoded:
                    js_snippets.append(decoded[:150])
                if len(js_snippets) >= 3:
                    break

            e_idx = result.add_evidence(
                source="PDF_STATIC_PARSER",
                evidence_type="PDF_JAVASCRIPT_STREAM",
                raw_content=js_snippets[0] if js_snippets else "JavaScript dictionary entry",
                parsed_content={"snippets": js_snippets},
            )
            result.add_finding(
                title="Active Embedded JavaScript in PDF",
                description=(
                    "PDF file contains active embedded JavaScript streams (/JavaScript or /JS). "
                    "Note: Embedded JavaScript is an active content indicator; presence of script alone is not confirmed malware."
                ),
                finding_type="PDF_JAVASCRIPT_PRESENT",
                category="ACTIVE_CONTENT",
                severity=SeverityEnum.MEDIUM,
                confidence=0.95,
                mitre_technique_id="T1059.007",  # JavaScript
                remediation="Disable automatic PDF JavaScript execution in viewer.",
                evidence_indices=[e_idx],
                metadata={"snippets": js_snippets},
            )

        # Check for /OpenAction or /AA
        has_open_action = bool(re.search(rb'/(?:OpenAction|AA)\b', payload))
        if has_open_action:
            e_idx = result.add_evidence(
                source="PDF_STATIC_PARSER",
                evidence_type="PDF_AUTO_ACTION",
                raw_content="/OpenAction or /AA operator present",
            )
            result.add_finding(
                title="Automatic Action Trigger in PDF",
                description="PDF defines an auto-execution trigger (/OpenAction or /AA) that initiates actions immediately upon document opening.",
                finding_type="PDF_OPEN_ACTION_PRESENT",
                category="EXECUTION",
                severity=SeverityEnum.MEDIUM,
                confidence=0.95,
                evidence_indices=[e_idx],
            )

        # Check for /Launch action
        has_launch_action = bool(re.search(rb'/Launch\b', payload))
        if has_launch_action:
            e_idx = result.add_evidence(
                source="PDF_STATIC_PARSER",
                evidence_type="PDF_LAUNCH_OPERATOR",
                raw_content="/Launch operator present",
            )
            result.add_finding(
                title="External Program Launcher in PDF (/Launch Action)",
                description="PDF contains a /Launch action operator designed to invoke external desktop binaries or shell commands.",
                finding_type="PDF_LAUNCH_ACTION_PRESENT",
                category="EXECUTION",
                severity=SeverityEnum.HIGH,
                confidence=0.99,
                mitre_technique_id="T1204.002",  # User Execution: Malicious File
                remediation="Quarantine file and prevent user launch.",
                evidence_indices=[e_idx],
            )

        # Check for /EmbeddedFiles or /EF
        has_embedded_files = bool(re.search(rb'/(?:EmbeddedFiles|EF)\b', payload))
        embedded_names: List[str] = []
        if has_embedded_files:
            for match in re.finditer(rb'/(?:F|UF)\s*\(([^)]+)\)', payload):
                embedded_names.append(match.group(1).decode("latin-1", errors="replace"))

            e_idx = result.add_evidence(
                source="PDF_STATIC_PARSER",
                evidence_type="PDF_EMBEDDED_FILES",
                parsed_content={"filenames": embedded_names[:10]},
            )
            result.add_finding(
                title="Hidden Embedded Files in PDF (/EmbeddedFiles)",
                description=f"PDF packages embedded child payload files: {', '.join(embedded_names[:5]) or 'embedded stream'}.",
                finding_type="PDF_EMBEDDED_FILE",
                category="EMBEDDED_CONTENT",
                severity=SeverityEnum.MEDIUM,
                confidence=0.95,
                evidence_indices=[e_idx],
                metadata={"embedded_files": embedded_names[:10]},
            )

        # Check for /Encrypt
        is_encrypted = bool(re.search(rb'/Encrypt\b', payload))
        if is_encrypted:
            e_idx = result.add_evidence(
                source="PDF_STATIC_PARSER",
                evidence_type="PDF_ENCRYPTION_DICTIONARY",
                raw_content="/Encrypt dictionary present",
            )
            result.add_finding(
                title="PDF Content Streams Encrypted (/Encrypt)",
                description="PDF streams are encrypted using standard security handlers or password protection, limiting static visibility.",
                finding_type="PDF_ENCRYPTED",
                category="OBFUSCATION",
                severity=SeverityEnum.LOW,
                confidence=1.0,
                evidence_indices=[e_idx],
            )

        # Check for /SubmitForm
        has_submit_form = bool(re.search(rb'/SubmitForm\b', payload))

        # Check for external /URI hyperlinks
        external_uris: List[str] = []
        for match in re.finditer(rb'/URI\s*(?:\((https?://[^)]+)\)|<([0-9a-fA-F]+)>)', payload, re.IGNORECASE):
            uri = match.group(1)
            if uri:
                external_uris.append(uri.decode("latin-1", errors="replace").strip())
            elif match.group(2):
                try:
                    hex_str = match.group(2).decode("ascii")
                    decoded_uri = bytes.fromhex(hex_str).decode("latin-1", errors="replace").strip()
                    if decoded_uri.startswith("http"):
                        external_uris.append(decoded_uri)
                except Exception:
                    pass

        clean_uris = list(dict.fromkeys(external_uris))[:25]
        if clean_uris:
            e_idx = result.add_evidence(
                source="PDF_STATIC_PARSER",
                evidence_type="PDF_EXTERNAL_URIS",
                parsed_content={"uris": clean_uris},
            )
            result.add_finding(
                title="External Hyperlinks Embedded in PDF",
                description=f"PDF dictionary references {len(clean_uris)} external hyperlink(s).",
                finding_type="PDF_EXTERNAL_URL",
                category="IOC",
                severity=SeverityEnum.LOW,
                confidence=1.0,
                evidence_indices=[e_idx],
                metadata={"urls": clean_uris},
            )
            for u in clean_uris:
                result.add_indicator(
                    indicator_type=IndicatorTypeEnum.URL,
                    value=u,
                    source="PDF_URI_DICTIONARY",
                )

        # PDF metadata extraction
        metadata: Dict[str, str] = {}
        for meta_key in [b"Title", b"Author", b"Creator", b"Producer", b"CreationDate", b"ModDate"]:
            m = re.search(rb'/' + meta_key + rb'\s*\(([^)]*)\)', payload)
            if m:
                metadata[meta_key.decode("ascii")] = m.group(1).decode("latin-1", errors="replace")

        # Suspicious structure check
        suspicious_elements: List[str] = []
        if has_js:
            suspicious_elements.append("Embedded JavaScript (/JavaScript or /JS)")
        if has_open_action:
            suspicious_elements.append("Auto-execution trigger (/OpenAction or /AA)")
        if has_launch_action:
            suspicious_elements.append("External launcher (/Launch)")
        if has_embedded_files:
            suspicious_elements.append("Embedded files (/EmbeddedFiles)")
        if has_submit_form:
            suspicious_elements.append("Form submission action (/SubmitForm)")

        if payload.count(b"%%EOF") > 3 or payload.count(b"xref") > 5:
            result.add_finding(
                title="Suspicious PDF Structure (Multi-Revision / Obfuscation)",
                description="PDF contains abnormal revision counts or multiple trailer definitions.",
                finding_type="PDF_SUSPICIOUS_STRUCTURE",
                category="FILE_STRUCTURE",
                severity=SeverityEnum.LOW,
                confidence=0.80,
            )

        pdf_meta = PDFStaticMetadata(
            is_pdf=True,
            pdf_version=pdf_version,
            has_javascript=has_js,
            javascript_snippets=js_snippets,
            has_open_action=has_open_action,
            has_launch_action=has_launch_action,
            has_embedded_files=has_embedded_files,
            embedded_file_names=embedded_names[:10],
            has_submit_form=has_submit_form,
            has_external_uri=len(clean_uris) > 0,
            external_uris=clean_uris,
            is_encrypted=is_encrypted,
            suspicious_elements=suspicious_elements,
            metadata=metadata,
            warnings=warnings,
        )

        return result, pdf_meta

    @classmethod
    def parse_office(cls, payload: bytes, detected_type: str) -> Tuple[AnalyzerExecutionResult, OfficeStaticMetadata]:
        result = AnalyzerExecutionResult(cls.name, cls.version)
        warnings: List[str] = []
        has_macros = False
        vba_present = False
        macro_names: List[str] = []
        has_external_rels = False
        external_rels: List[str] = []
        has_embedded_objects = False
        suspicious_keywords: Set[str] = set()
        metadata: Dict[str, str] = {}

        # 1. OpenXML inspection via safe zip
        if payload.startswith(b"PK\x03\x04"):
            try:
                with zipfile.ZipFile(io.BytesIO(payload), "r") as zf:
                    namelist = zf.namelist()
                    for name in namelist:
                        lower_name = name.lower()
                        if "vbaproject.bin" in lower_name:
                            has_macros = True
                            vba_present = True
                            macro_names.append(name)
                        if "oleobject" in lower_name or "embeddings/" in lower_name:
                            has_embedded_objects = True

                        # Inspect relationships for external template injection (e.g. Follina)
                        if lower_name.endswith(".rels"):
                            try:
                                rel_bytes = zf.read(name)
                                for rel_tag in re.finditer(rb'<Relationship\b[^>]*>', rel_bytes, re.IGNORECASE):
                                    tag_str = rel_tag.group(0)
                                    if b'TargetMode="External"' in tag_str or b"TargetMode='External'" in tag_str:
                                        target_m = re.search(rb'Target=["\']([^"\']+)["\']', tag_str, re.IGNORECASE)
                                        if target_m:
                                            ext_target = target_m.group(1).decode("latin-1", errors="ignore")
                                            has_external_rels = True
                                            external_rels.append(ext_target)
                            except Exception:
                                pass

                        # Metadata extraction from docProps/core.xml
                        if lower_name == "docprops/core.xml":
                            try:
                                core_bytes = zf.read(name).decode("utf-8", errors="ignore")
                                for tag in ["dc:title", "dc:creator", "cp:lastModifiedBy", "cp:revision", "dcterms:created", "dcterms:modified"]:
                                    m = re.search(rf'<{tag}[^>]*>(.*?)</{tag}>', core_bytes)
                                    if m:
                                        metadata[tag.split(":")[-1]] = m.group(1)
                            except Exception:
                                pass

                    # If vbaProject.bin is found, scan it for macro keywords
                    if vba_present:
                        try:
                            for name in namelist:
                                if "vbaproject.bin" in name.lower():
                                    vba_data = zf.read(name)
                                    for kw in [b"AutoOpen", b"Auto_Open", b"Workbook_Open", b"Document_Open",
                                               b"Shell", b"Environ", b"WScript.Shell", b"powershell", b"cmd.exe",
                                               b"URLDownloadToFile"]:
                                        if re.search(rb'\b' + kw + rb'\b', vba_data, re.IGNORECASE):
                                            suspicious_keywords.add(kw.decode("ascii"))
                        except Exception:
                            pass

            except Exception as e:
                warnings.append(f"OpenXML inspection notice: {str(e)}")

        # 2. OLE Compound Document inspection
        elif payload.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
            if b"_VBA_PROJECT" in payload or b"VBA" in payload:
                has_macros = True
                vba_present = True
                macro_names.append("OLE_VBA_PROJECT")
            for kw in [b"AutoOpen", b"Auto_Open", b"Workbook_Open", b"Document_Open", b"Shell", b"powershell"]:
                if kw in payload:
                    suspicious_keywords.add(kw.decode("ascii"))

        # Create Findings
        if has_macros:
            e_idx = result.add_evidence(
                source="OFFICE_STATIC_PARSER",
                evidence_type="VBA_MACRO_PROJECT",
                parsed_content={
                    "macro_names": macro_names,
                    "suspicious_keywords": sorted(list(suspicious_keywords)),
                },
            )
            result.add_finding(
                title="VBA Macro Code Present in Office Document",
                description=(
                    f"Document contains an embedded VBA macro project ({', '.join(macro_names)}). "
                    f"CRITICAL: MACRO_PRESENT indicates active automation capability; it does NOT confirm malicious intent "
                    f"unless verified malicious behavior or suspicious command chains are observed."
                ),
                finding_type="MACRO_PRESENT",
                category="ACTIVE_CONTENT",
                severity=SeverityEnum.MEDIUM,
                confidence=1.0,
                mitre_technique_id="T1059.005",  # Visual Basic
                remediation="Ensure macro execution is disabled by policy. Review macro source before execution.",
                evidence_indices=[e_idx],
                metadata={"macro_names": macro_names, "keywords": sorted(list(suspicious_keywords))},
            )

        if has_external_rels:
            clean_ext = list(dict.fromkeys(external_rels))[:15]
            e_idx = result.add_evidence(
                source="OFFICE_STATIC_PARSER",
                evidence_type="OFFICE_EXTERNAL_RELATIONSHIPS",
                parsed_content={"targets": clean_ext},
            )
            result.add_finding(
                title="External Template / Relationship Target in Office Document",
                description=(
                    f"Document defines external relationship targets ({len(clean_ext)} external URL(s)). "
                    f"Adversaries use external relationships for remote template injection (e.g. Follina CVE-2022-30190)."
                ),
                finding_type="SUSPICIOUS_DOCUMENT_RELATIONSHIP",
                category="EVASION",
                severity=SeverityEnum.MEDIUM,
                confidence=0.95,
                mitre_technique_id="T1221",  # Template Injection
                remediation="Investigate external relationship target URLs before opening.",
                evidence_indices=[e_idx],
                metadata={"targets": clean_ext},
            )
            for u in clean_ext:
                result.add_indicator(
                    indicator_type=IndicatorTypeEnum.URL,
                    value=u,
                    source="OFFICE_EXTERNAL_RELATIONSHIP",
                )

        if has_embedded_objects:
            result.add_finding(
                title="Embedded OLE Binary Objects in Document",
                description="Document packages embedded OLE objects or binary packages (oleObject.bin).",
                finding_type="EMBEDDED_OBJECT_PRESENT",
                category="EMBEDDED_CONTENT",
                severity=SeverityEnum.LOW,
                confidence=0.90,
            )

        office_meta = OfficeStaticMetadata(
            is_office=True,
            office_format=detected_type,
            has_macros=has_macros,
            vba_project_present=vba_present,
            macro_names=macro_names,
            has_external_relationships=has_external_rels,
            external_relationships=external_rels[:15],
            has_embedded_objects=has_embedded_objects,
            suspicious_keywords=sorted(list(suspicious_keywords)),
            metadata=metadata,
            warnings=warnings,
        )

        return result, office_meta


# ============================================================================
# 4. EXECUTABLE STATIC ANALYZER
# ============================================================================

class ExecutableStaticAnalyzer:
    """
    Safely parses Windows PE binary structures without execution.
    Analyzes architecture, compile timestamp, sections, entropy, Authenticode status,
    and suspicious imported APIs.
    """
    name = "executable_static_analyzer"
    version = "2.0.0"

    SUSPICIOUS_PE_APIS = {
        # Memory and process injection
        "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
        "WriteProcessMemory", "ReadProcessMemory", "CreateRemoteThread",
        "QueueUserAPC", "SetThreadContext", "ResumeThread", "NtWriteVirtualMemory",
        # Execution
        "WinExec", "ShellExecuteA", "ShellExecuteW", "ShellExecuteExA", "ShellExecuteExW",
        "CreateProcessA", "CreateProcessW",
        # Network and payload download
        "URLDownloadToFileA", "URLDownloadToFileW", "InternetOpenA", "InternetOpenW",
        "InternetOpenUrlA", "InternetOpenUrlW", "HttpSendRequestA", "HttpSendRequestW",
        "WSAStartup", "connect", "InternetReadFile",
        # Evasion / Anti-analysis
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "FindWindowA", "FindWindowW",
        "OutputDebugStringA", "OutputDebugStringW", "CryptDecrypt"
    }

    @classmethod
    def calculate_entropy(cls, payload: bytes) -> float:
        """Calculates Shannon Entropy (0.00 to 8.00) of byte sequence."""
        if not payload:
            return 0.0
        length = len(payload)
        freq = [0] * 256
        for b in payload:
            freq[b] += 1
        entropy = 0.0
        for count in freq:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return round(entropy, 2)

    @classmethod
    def evaluate_entropy_level(cls, entropy: float) -> Tuple[str, str, bool]:
        """Evaluates entropy level and returns (tier, description, is_high)."""
        if entropy < 3.5:
            level = "low"
            desc = f"Low entropy ({entropy:.2f}/8.00) typical of sparse or uncompressed plain text."
            is_high = False
        elif entropy < 6.8:
            level = "normal"
            desc = f"Normal entropy ({entropy:.2f}/8.00) typical of compiled binary code or formatted documents."
            is_high = False
        elif entropy < 7.2:
            level = "high"
            desc = f"High entropy ({entropy:.2f}/8.00) indicates compressed data or dense binary encoding."
            is_high = False
        else:
            level = "very_high"
            desc = (
                f"Very high entropy ({entropy:.2f}/8.00) indicates packed executable code, strong encryption, "
                f"or high-density compression. NOTE: High entropy alone is NOT proof of malware."
            )
            is_high = True
        return level, desc, is_high

    def analyze(self, payload: bytes) -> Tuple[AnalyzerExecutionResult, PEMetadata, EntropyEvaluation]:
        result = AnalyzerExecutionResult(self.name, self.version)
        warnings: List[str] = []

        overall_entropy = self.calculate_entropy(payload)
        ent_level, ent_desc, is_high = self.evaluate_entropy_level(overall_entropy)
        entropy_eval = EntropyEvaluation(
            entropy=overall_entropy,
            level=ent_level,
            description=ent_desc,
            is_high_entropy=is_high,
        )

        if is_high:
            result.add_finding(
                title=f"High Entropy Content ({overall_entropy:.2f} / 8.00)",
                description=(
                    f"Overall file byte entropy is {overall_entropy:.2f}, indicating compression, binary packing, "
                    f"or encryption. NOTE: High entropy alone is NOT proof of malware without corroborating malicious structure."
                ),
                finding_type="HIGH_ENTROPY_CONTENT",
                category="OBFUSCATION",
                severity=SeverityEnum.LOW,
                confidence=0.85,
                mitre_technique_id="T1027.002",  # Software Packing
                metadata={"entropy": overall_entropy},
            )

        if len(payload) < 64 or not payload.startswith(b"MZ"):
            pe_meta = PEMetadata(is_pe=False, warnings=["Not a valid MZ header"])
            return result, pe_meta, entropy_eval

        try:
            e_lfanew = struct.unpack_from("<I", payload, 0x3C)[0]
            if e_lfanew + 24 > len(payload) or payload[e_lfanew:e_lfanew+4] != b"PE\x00\x00":
                pe_meta = PEMetadata(is_pe=False, warnings=["Missing PE signature at e_lfanew offset"])
                return result, pe_meta, entropy_eval

            # COFF Header
            coff_offset = e_lfanew + 4
            machine, num_sections, timedatestamp, _, _, opt_hdr_size, characteristics = struct.unpack_from(
                "<HHIIIHH", payload, coff_offset
            )

            arch_map = {
                0x014C: "x86 (32-bit)",
                0x8664: "x64 (AMD64 / 64-bit)",
                0x0200: "Intel Itanium",
                0xAA64: "ARM64",
                0x01C0: "ARM"
            }
            architecture = arch_map.get(machine, f"Unknown (0x{machine:04X})")

            # Compile timestamp (untrusted metadata)
            compile_ts_str = "Invalid/Unavailable"
            try:
                if 315532800 <= timedatestamp <= 2147483647:
                    dt = datetime.fromtimestamp(timedatestamp, tz=timezone.utc)
                    compile_ts_str = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
                else:
                    compile_ts_str = f"Suspicious/Anomalous timestamp (raw: {timedatestamp})"
                    warnings.append(f"Compile timestamp anomaly: {timedatestamp}")
            except Exception:
                pass

            # Optional Header
            opt_offset = coff_offset + 20
            subsystem_str = "Unknown"
            entry_point_str = "0x0"
            has_authenticode = False
            signature_status = "Unsigned"

            if opt_hdr_size >= 68 and opt_offset + opt_hdr_size <= len(payload):
                magic = struct.unpack_from("<H", payload, opt_offset)[0]
                is_64 = (magic == 0x020B)
                entry_point = struct.unpack_from("<I", payload, opt_offset + 16)[0]
                entry_point_str = f"0x{entry_point:08X}"

                subsystem = struct.unpack_from("<H", payload, opt_offset + 68)[0]
                subsystem_map = {
                    1: "Native",
                    2: "Windows GUI",
                    3: "Windows CUI (Console)",
                    7: "POSIX CUI",
                    9: "Windows CE GUI",
                    10: "EFI Application"
                }
                subsystem_str = subsystem_map.get(subsystem, f"Subsystem-{subsystem}")

                # Security directory
                data_dirs_offset = opt_offset + (112 if is_64 else 96)
                sec_dir_offset = data_dirs_offset + (4 * 8)
                if sec_dir_offset + 8 <= opt_offset + opt_hdr_size:
                    sec_rva, sec_size = struct.unpack_from("<II", payload, sec_dir_offset)
                    if sec_size > 0 and sec_rva > 0:
                        has_authenticode = True
                        signature_status = "Signed"
                    else:
                        signature_status = "Unsigned"

            # Authenticode Finding (Unsigned does NOT mean malware!)
            if signature_status == "Unsigned":
                result.add_finding(
                    title="Unsigned Windows Executable Binary",
                    description=(
                        "Executable binary lacks an Authenticode digital signature. "
                        "NOTE: Unsigned code is common in open-source and internal software; unsigned status alone is NOT proof of malware."
                    ),
                    finding_type="EXECUTABLE_UNSIGNED",
                    category="AUTHENTICODE",
                    severity=SeverityEnum.LOW,
                    confidence=1.0,
                    metadata={"signature_status": "Unsigned"},
                )

            # Sections parsing
            sections: List[PESectionInfo] = []
            sec_table_offset = opt_offset + opt_hdr_size
            bounded_sections = min(num_sections, 32)

            for i in range(bounded_sections):
                s_off = sec_table_offset + (i * 40)
                if s_off + 40 > len(payload):
                    break
                s_name_raw = payload[s_off:s_off+8]
                s_name = s_name_raw.split(b"\x00")[0].decode("latin-1", errors="replace").strip()
                v_size, v_addr, raw_size, raw_ptr, _, _, _, _, s_chars = struct.unpack_from(
                    "<IIIIIIHHI", payload, s_off + 8
                )

                sec_bytes = b""
                if raw_ptr < len(payload) and raw_size > 0:
                    end_ptr = min(raw_ptr + raw_size, len(payload))
                    sec_bytes = payload[raw_ptr:end_ptr]
                s_entropy = self.calculate_entropy(sec_bytes)

                is_suspicious_sec = False
                known_packer_prefixes = ["upx", ".aspack", ".themida", ".vmp", "mpress"]
                if any(s_name.lower().startswith(p) for p in known_packer_prefixes):
                    is_suspicious_sec = True
                    result.add_finding(
                        title=f"Unusual / Packed Section Header: '{s_name}'",
                        description=f"Section '{s_name}' matches known binary packer signatures ({s_name}).",
                        finding_type="UNUSUAL_SECTION_NAME",
                        category="OBFUSCATION",
                        severity=SeverityEnum.MEDIUM,
                        confidence=0.90,
                        mitre_technique_id="T1027.002",
                        metadata={"section": s_name},
                    )

                if s_entropy > 7.2 and (s_chars & 0x20000000):  # IMAGE_SCN_MEM_EXECUTE
                    is_suspicious_sec = True
                    result.add_finding(
                        title=f"High Entropy Executable Section: '{s_name}' ({s_entropy:.2f})",
                        description=f"Executable section '{s_name}' exhibits high entropy ({s_entropy:.2f}), indicating packed or encrypted payload code.",
                        finding_type="HIGH_ENTROPY_SECTION",
                        category="OBFUSCATION",
                        severity=SeverityEnum.MEDIUM,
                        confidence=0.90,
                        metadata={"section": s_name, "entropy": s_entropy},
                    )

                sections.append(PESectionInfo(
                    name=s_name,
                    virtual_size=v_size,
                    virtual_address=f"0x{v_addr:08X}",
                    raw_size=raw_size,
                    entropy=s_entropy,
                    characteristics=f"0x{s_chars:08X}",
                    is_suspicious=is_suspicious_sec,
                ))

            # Scan for DLLs and suspicious API strings
            imported_dlls: Set[str] = set()
            suspicious_imports: Set[str] = set()

            dll_pattern = re.compile(rb'\b([a-zA-Z0-9_\-\.]+\.(?:dll|drv|ocx|sys))\b', re.IGNORECASE)
            for m in dll_pattern.finditer(payload):
                dll_name = m.group(1).decode("latin-1", errors="ignore")
                if len(dll_name) < 40 and not dll_name.startswith("."):
                    imported_dlls.add(dll_name)

            for api in self.SUSPICIOUS_PE_APIS:
                if api.encode("ascii") in payload:
                    suspicious_imports.add(api)

            if len(suspicious_imports) >= 2:
                result.add_finding(
                    title=f"Suspicious API Import Set ({len(suspicious_imports)} high-risk APIs)",
                    description=(
                        f"Executable binary references high-risk APIs commonly used in process injection, "
                        f"execution, or evasion: {', '.join(sorted(list(suspicious_imports))[:5])}."
                    ),
                    finding_type="SUSPICIOUS_IMPORT_SET",
                    category="BEHAVIORAL_HEURISTIC",
                    severity=SeverityEnum.MEDIUM,
                    confidence=0.85,
                    metadata={"suspicious_apis": sorted(list(suspicious_imports))},
                )

            imports_list: List[PEImportInfo] = []
            for dll in sorted(list(imported_dlls))[:15]:
                imports_list.append(PEImportInfo(
                    dll=dll,
                    functions=[api for api in suspicious_imports if dll.lower().startswith(("kernel", "user", "url", "wininet"))][:5],
                ))

            pe_meta = PEMetadata(
                is_pe=True,
                architecture=architecture,
                compile_timestamp=compile_ts_str,
                subsystem=subsystem_str,
                entry_point=entry_point_str,
                number_of_sections=len(sections),
                sections=sections,
                imported_dlls=sorted(list(imported_dlls))[:20],
                imports=imports_list,
                suspicious_imports=sorted(list(suspicious_imports)),
                has_authenticode=has_authenticode,
                signature_status=signature_status,
                warnings=warnings,
            )
            return result, pe_meta, entropy_eval

        except Exception as exc:
            pe_meta = PEMetadata(is_pe=True, warnings=[f"PE parser non-fatal error: {str(exc)}"])
            return result, pe_meta, entropy_eval


# ============================================================================
# 5. SCRIPT STATIC ANALYZER
# ============================================================================

class ScriptStaticAnalyzer:
    """
    Pure static text analysis for scripts (.ps1, .bat, .cmd, .sh, .vbs, .js, .py).
    Detects encoded commands, remote downloaders, shell execution chains,
    credential access terms, and persistence commands without executing.
    """
    name = "script_static_analyzer"
    version = "2.0.0"

    PATTERNS: Dict[str, Tuple[re.Pattern, str, SeverityEnum]] = {
        "ENCODED_POWERSHELL": (
            re.compile(r'(?:-enc|-encodedcommand)\s+[A-Za-z0-9+/=]{16,}', re.IGNORECASE),
            "Base64 encoded PowerShell command execution argument",
            SeverityEnum.HIGH,
        ),
        "BASE64_DECODE_EXEC": (
            re.compile(r'\[System\.Convert\]::FromBase64String\([^\)]+\)', re.IGNORECASE),
            "Base64 decode string invocation in script",
            SeverityEnum.MEDIUM,
        ),
        "DOWNLOAD_STRING": (
            re.compile(r'(?:DownloadString|DownloadFile)\s*\([^\)]+\)', re.IGNORECASE),
            "WebClient remote payload download invocation",
            SeverityEnum.HIGH,
        ),
        "INVOKE_WEBREQUEST": (
            re.compile(r'(?:Invoke-WebRequest|iwr|curl|wget)\s+["\']?https?://', re.IGNORECASE),
            "Remote HTTP web request payload download command",
            SeverityEnum.MEDIUM,
        ),
        "POWERSHELL_IEX": (
            re.compile(r'\b(?:iex|Invoke-Expression)\b', re.IGNORECASE),
            "PowerShell dynamic execution wrapper (IEX / Invoke-Expression)",
            SeverityEnum.MEDIUM,
        ),
        "HIDDEN_WINDOW_EXEC": (
            re.compile(r'-w(?:indowstyle)?\s+hidden\b', re.IGNORECASE),
            "Hidden window execution parameter",
            SeverityEnum.MEDIUM,
        ),
        "CREDENTIAL_DUMP": (
            re.compile(r'\b(?:mimikatz|sekurlsa|lsass|samdump)\b', re.IGNORECASE),
            "Credential access or LSASS memory dump keywords",
            SeverityEnum.HIGH,
        ),
        "PERSISTENCE_RUNKEY": (
            re.compile(r'reg(?:\.exe)?\s+add\s+["\']?[^"\']+\\CurrentVersion\\Run', re.IGNORECASE),
            "Registry Run key persistence configuration",
            SeverityEnum.HIGH,
        ),
        "SCHEDULED_TASK": (
            re.compile(r'schtasks(?:\.exe)?\s+/create', re.IGNORECASE),
            "Scheduled task persistence command",
            SeverityEnum.MEDIUM,
        ),
    }

    def analyze(self, text_payload: str, script_type: str = "Script") -> Tuple[AnalyzerExecutionResult, ScriptStaticMetadata]:
        result = AnalyzerExecutionResult(self.name, self.version)
        matched_patterns: List[str] = []
        snippets: List[str] = []
        has_encoded = False
        has_download = False
        has_exec_chains = False
        has_cred_access = False
        has_persistence = False

        # Scan text for patterns
        for key, (pattern, desc, severity) in self.PATTERNS.items():
            match = pattern.search(text_payload)
            if match:
                matched_patterns.append(f"{key}: {desc}")
                snip = match.group(0)[:120]
                snippets.append(snip)

                if "ENCODED" in key:
                    has_encoded = True
                if "DOWNLOAD" in key or "WEBREQUEST" in key:
                    has_download = True
                if "IEX" in key or "HIDDEN" in key:
                    has_exec_chains = True
                if "CREDENTIAL" in key:
                    has_cred_access = True
                if "PERSISTENCE" in key or "SCHEDULED" in key:
                    has_persistence = True

                e_idx = result.add_evidence(
                    source="SCRIPT_STATIC_ANALYZER",
                    evidence_type="SCRIPT_PATTERN_MATCH",
                    raw_content=snip,
                    parsed_content={"pattern": key, "description": desc},
                )
                result.add_finding(
                    title=f"Suspicious Script Pattern: {key}",
                    description=f"{desc}. Matched snippet: '{snip}'.",
                    finding_type="SUSPICIOUS_STATIC_SCRIPT",
                    category="BEHAVIORAL_HEURISTIC",
                    severity=severity,
                    confidence=0.90,
                    evidence_indices=[e_idx],
                    metadata={"pattern": key, "snippet": snip},
                )

        script_meta = ScriptStaticMetadata(
            is_script=True,
            script_type=script_type,
            has_encoded_commands=has_encoded,
            has_download_commands=has_download,
            has_execution_chains=has_exec_chains,
            has_credential_access=has_cred_access,
            has_persistence_commands=has_persistence,
            matched_patterns=matched_patterns,
            snippets=snippets[:10],
            warnings=[],
        )

        return result, script_meta


# ============================================================================
# 6. ARCHIVE SECURITY ANALYZER
# ============================================================================

class ArchiveSecurityAnalyzer:
    """
    Safely inspects archive containers (ZIP, TAR, GZIP).
    Defends against:
    - Zip-Slip path traversal (../../etc/passwd, absolute paths, drive letters).
    - Zip-Bomb attacks (excessive entries, expansion limits, compression ratio > 100:1).
    - Password-protected archives (ARCHIVE_ENCRYPTED).
    Extracts child entries into memory up to limits as child Artifact candidates.
    """
    name = "archive_security"
    version = "2.0.0"

    MAX_ENTRIES = 250
    MAX_UNCOMPRESSED_TOTAL = 50 * 1024 * 1024  # 50 MB
    MAX_FILE_SIZE = 25 * 1024 * 1024           # 25 MB
    MAX_COMPRESSION_RATIO = 100.0              # 100:1
    MAX_ARCHIVE_DEPTH = 3
    MAX_PATH_LENGTH = 255

    @classmethod
    def is_safe_path(cls, path_str: str) -> bool:
        """
        Validates that an archive path does NOT escape the controlled extraction root.
        Rejects:
        - Parent directory traversal (../ or ..\\)
        - Absolute paths (/ or \\)
        - Windows drive letters (C:)
        - Control/null bytes
        """
        if not path_str or len(path_str) > cls.MAX_PATH_LENGTH:
            return False
        if "\x00" in path_str or "\r" in path_str or "\n" in path_str:
            return False
        if "../" in path_str or "..\\" in path_str:
            return False
        if path_str.startswith(("/", "\\")):
            return False
        if re.match(r'^[a-zA-Z]:', path_str):
            return False
        # Normalize and ensure no parent traversal
        norm = os.path.normpath(path_str)
        if norm == ".." or norm.startswith(("../", "..\\")):
            return False
        return True

    def analyze_zip(self, payload: bytes) -> Tuple[AnalyzerExecutionResult, ArchiveStaticMetadata, List[Dict[str, Any]]]:
        result = AnalyzerExecutionResult(self.name, self.version)
        entries: List[ArchiveEntryInfo] = []
        suspicious_entries: List[str] = []
        safety_violations: List[str] = []
        child_artifacts: List[Dict[str, Any]] = []

        total_uncompressed = 0
        total_files = 0
        is_encrypted = False
        has_nested = False
        has_traversal = False
        has_hidden_exec = False

        try:
            with zipfile.ZipFile(io.BytesIO(payload), "r") as zf:
                infolist = zf.infolist()
                total_files = len(infolist)

                # 1. Zip Bomb guard: excessive entry count
                if total_files > self.MAX_ENTRIES:
                    safety_violations.append(f"Zip bomb guard: entry count ({total_files}) exceeds limit ({self.MAX_ENTRIES})")
                    result.add_finding(
                        title="Archive Extraction Limit Reached: Excessive Entries",
                        description=f"Archive contains {total_files} entries, exceeding safe threshold of {self.MAX_ENTRIES}.",
                        finding_type="ARCHIVE_EXTRACTION_LIMIT_REACHED",
                        category="RESOURCE_LIMIT",
                        severity=SeverityEnum.HIGH,
                        confidence=1.0,
                    )

                for info in infolist[:self.MAX_ENTRIES]:
                    fn = info.filename
                    u_size = info.file_size
                    c_size = info.compress_size
                    total_uncompressed += u_size

                    # Check encryption (flag_bits bit 0)
                    entry_encrypted = bool(info.flag_bits & 0x1)
                    if entry_encrypted:
                        is_encrypted = True

                    # Check Zip-Slip path traversal
                    is_safe = self.is_safe_path(fn)
                    entry_traversal = not is_safe
                    if entry_traversal:
                        has_traversal = True
                        safety_violations.append(f"Zip-Slip path traversal detected: '{fn}'")
                        e_idx = result.add_evidence(
                            source="ARCHIVE_SECURITY_ANALYZER",
                            evidence_type="ZIP_SLIP_PATH_TRAVERSAL",
                            raw_content=fn,
                        )
                        result.add_finding(
                            title=f"Path Traversal Exploit in Archive (Zip-Slip): '{fn}'",
                            description=(
                                f"Archive entry '{fn}' contains path traversal sequences attempting to escape the extraction "
                                f"root directory. Extraction was rejected immediately."
                            ),
                            finding_type="PATH_TRAVERSAL_DETECTED",
                            category="EXPLOIT",
                            severity=SeverityEnum.CRITICAL,
                            confidence=1.0,
                            mitre_technique_id="T1083",  # File and Directory Discovery
                            remediation="Block archive immediately. Path traversal indicates hostile payload delivery.",
                            evidence_indices=[e_idx],
                            metadata={"entry": fn},
                        )

                    # Check suspicious extension
                    lower_fn = fn.lower()
                    entry_suspicious_ext = any(lower_fn.endswith(ext) for ext in FileIdentityAnalyzer.SUSPICIOUS_EXTENSIONS)
                    if entry_suspicious_ext:
                        has_hidden_exec = True
                        suspicious_entries.append(fn)

                    # Check nested archive
                    entry_nested = lower_fn.endswith((".zip", ".tar", ".gz", ".7z", ".rar", ".iso"))
                    if entry_nested:
                        has_nested = True

                    entries.append(ArchiveEntryInfo(
                        filename=fn,
                        uncompressed_size=u_size,
                        compressed_size=c_size,
                        is_encrypted=entry_encrypted,
                        is_suspicious_extension=entry_suspicious_ext,
                        is_nested_archive=entry_nested,
                        is_path_traversal=entry_traversal,
                    ))

                    # Safely extract child bytes if safe and unencrypted
                    if is_safe and not entry_encrypted and not info.is_dir() and u_size <= self.MAX_FILE_SIZE:
                        if total_uncompressed <= self.MAX_UNCOMPRESSED_TOTAL:
                            try:
                                child_bytes = zf.read(info)
                                c_sha256 = hashlib.sha256(child_bytes).hexdigest()
                                child_artifacts.append({
                                    "filename": os.path.basename(fn) or "archive_entry",
                                    "original_entry_path": fn,
                                    "bytes": child_bytes,
                                    "size": u_size,
                                    "sha256": c_sha256,
                                    "source": "ARCHIVE_EXTRACTION",
                                })
                            except Exception:
                                pass

                # 2. Total uncompressed size limit
                if total_uncompressed > self.MAX_UNCOMPRESSED_TOTAL:
                    safety_violations.append(
                        f"Zip bomb guard: aggregate uncompressed size ({total_uncompressed} bytes) exceeds limit ({self.MAX_UNCOMPRESSED_TOTAL} bytes)"
                    )
                    result.add_finding(
                        title="Archive Extraction Limit Reached: Aggregate Uncompressed Size",
                        description=f"Total uncompressed size ({total_uncompressed} bytes) exceeds safety ceiling of 50 MB.",
                        finding_type="ARCHIVE_EXTRACTION_LIMIT_REACHED",
                        category="RESOURCE_LIMIT",
                        severity=SeverityEnum.HIGH,
                        confidence=1.0,
                    )

                # 3. Compression ratio limit
                compressed_len = max(len(payload), 1)
                ratio = total_uncompressed / compressed_len
                if ratio > self.MAX_COMPRESSION_RATIO:
                    safety_violations.append(
                        f"Zip bomb guard: compression ratio ({ratio:.1f}:1) exceeds limit ({self.MAX_COMPRESSION_RATIO}:1)"
                    )
                    result.add_finding(
                        title="Archive Extraction Limit Reached: High Compression Ratio",
                        description=f"Archive compression ratio ({ratio:.1f}:1) exceeds safe threshold of 100:1.",
                        finding_type="ARCHIVE_EXTRACTION_LIMIT_REACHED",
                        category="RESOURCE_LIMIT",
                        severity=SeverityEnum.HIGH,
                        confidence=1.0,
                    )

        except zipfile.BadZipFile as exc:
            safety_violations.append(f"Corrupted or malformed archive format: {str(exc)}")
        except Exception as exc:
            safety_violations.append(f"Archive inspection error: {str(exc)}")

        # Encrypted Archive Finding
        if is_encrypted:
            result.add_finding(
                title="Archive is Password-Protected / Encrypted",
                description=(
                    "Archive contains password-protected entries preventing automated static inspection. "
                    "NOTE: Password protection alone is NOT proof of malware, but frequently used to evade email gateways."
                ),
                finding_type="ARCHIVE_ENCRYPTED",
                category="EVASION",
                severity=SeverityEnum.MEDIUM,
                confidence=1.0,
            )

        ratio = round(total_uncompressed / max(len(payload), 1), 2)
        archive_meta = ArchiveStaticMetadata(
            is_archive=True,
            archive_type="ZIP",
            total_files=total_files,
            uncompressed_size=total_uncompressed,
            compression_ratio=ratio,
            is_encrypted=is_encrypted,
            has_nested_archives=has_nested,
            has_path_traversal=has_traversal,
            has_hidden_executables=has_hidden_exec,
            suspicious_entries=suspicious_entries[:20],
            entries=entries[:50],
            safety_violations=safety_violations,
        )

        return result, archive_meta, child_artifacts


# ============================================================================
# 7. FILE IOC ANALYZER
# ============================================================================

class FileIOCAnalyzer:
    """
    Extracts discoverable IOCs (URLs, domains, IPs, emails, hashes) from printable strings
    with bounded string lengths and counts to prevent database saturation.
    """
    name = "file_ioc_extractor"
    version = "2.0.0"

    MAX_EXTRACTED_CHARS = 100_000
    MAX_IOCS_PER_TYPE = 50

    SCHEMA_NAMESPACES = (
        "schemas.openxmlformats.org", "schemas.microsoft.com", "www.w3.org",
        "purl.org", "oasis-open.org", "xml.org", "adobe.com"
    )

    def analyze(self, payload: bytes) -> Tuple[AnalyzerExecutionResult, Dict[str, List[str]]]:
        result = AnalyzerExecutionResult(self.name, self.version)
        sample_text = payload[:self.MAX_EXTRACTED_CHARS].decode("latin-1", errors="ignore")

        urls: Set[str] = set()
        domains: Set[str] = set()
        ips: Set[str] = set()
        emails: Set[str] = set()
        hashes: Set[str] = set()

        # 1. URLs
        for m in re.finditer(r'https?://[a-zA-Z0-9\-\._~:/\?#\[\]@!$&\'\(\)\*\+,;=%]+', sample_text):
            u = m.group(0).rstrip(")>].,;\"'")
            if len(u) > 10 and "." in u:
                if not any(ns in u.lower() for ns in self.SCHEMA_NAMESPACES):
                    urls.add(u)
                    if len(urls) >= self.MAX_IOCS_PER_TYPE:
                        break

        # 2. Domains from URLs
        for u in urls:
            m = re.search(r'https?://([a-zA-Z0-9\-\.]+)', u)
            if m:
                h = m.group(1).split(":")[0].lower()
                if "." in h and not h.replace(".", "").isdigit():
                    domains.add(h)

        # 3. IP Addresses
        for ip in re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', sample_text):
            octets = [int(o) for o in ip.split(".")]
            if all(0 <= o <= 255 for o in octets):
                if not (octets[0] in (0, 127, 255) or (octets[0] == 169 and octets[1] == 254)):
                    ips.add(ip)
                    if len(ips) >= self.MAX_IOCS_PER_TYPE:
                        break

        # 4. Email addresses
        for em in re.findall(r'\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b', sample_text):
            emails.add(em.lower())
            if len(emails) >= self.MAX_IOCS_PER_TYPE:
                break

        # 5. Hashes
        for h in re.findall(r'\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{32}\b', sample_text):
            hashes.add(h.lower())
            if len(hashes) >= self.MAX_IOCS_PER_TYPE:
                break

        clean_urls = sorted(list(urls))[:self.MAX_IOCS_PER_TYPE]
        clean_domains = sorted(list(domains))[:self.MAX_IOCS_PER_TYPE]
        clean_ips = sorted(list(ips))[:self.MAX_IOCS_PER_TYPE]
        clean_emails = sorted(list(emails))[:self.MAX_IOCS_PER_TYPE]
        clean_hashes = sorted(list(hashes))[:self.MAX_IOCS_PER_TYPE]

        for u in clean_urls:
            result.add_indicator(IndicatorTypeEnum.URL, u, source="FILE_PRINTABLE_STRINGS")
        for d in clean_domains:
            result.add_indicator(IndicatorTypeEnum.DOMAIN, d, source="FILE_PRINTABLE_STRINGS")
        for ip in clean_ips:
            result.add_indicator(IndicatorTypeEnum.IP, ip, source="FILE_PRINTABLE_STRINGS")
        for em in clean_emails:
            result.add_indicator(IndicatorTypeEnum.EMAIL_ADDRESS, em, source="FILE_PRINTABLE_STRINGS")

        if clean_urls:
            result.add_finding(
                title=f"External URLs Embedded in File Payload ({len(clean_urls)} discovered)",
                description=f"File contains printable external URL references: {', '.join(clean_urls[:3])}.",
                finding_type="EXTERNAL_URL_EMBEDDED",
                category="IOC",
                severity=SeverityEnum.LOW,
                confidence=1.0,
                metadata={"urls": clean_urls},
            )

        ioc_dict = {
            "urls": clean_urls,
            "domains": clean_domains,
            "ips": clean_ips,
            "emails": clean_emails,
            "hashes": clean_hashes,
        }

        return result, ioc_dict


# ============================================================================
# 8. FILE REPUTATION ANALYZER
# ============================================================================

class FileReputationAnalyzer:
    """
    Queries ThreatIntelligenceService for file hash reputation.
    CRITICAL MANDATES:
    - Privacy: NEVER transmits user file payloads. Only queries cryptographic hashes.
    - Neutrality: NO MATCH does NOT equal SAFE. Unmatched hashes return verdict='UNKNOWN'.
    """
    name = "file_reputation_analyzer"
    version = "2.0.0"

    def __init__(self, threat_intel_service: Optional[ThreatIntelligenceService] = None):
        self.threat_intel = threat_intel_service or ThreatIntelligenceService()

    async def analyze(self, sha256: str, sha1: Optional[str] = None, md5: Optional[str] = None) -> Tuple[AnalyzerExecutionResult, ThreatIntelHashInfo]:
        result = AnalyzerExecutionResult(self.name, self.version)

        ti_results: List[ThreatIntelResult] = await self.threat_intel.lookup_file_hash(
            sha256=sha256, sha1=sha1, md5=md5
        )

        ti_res = ti_results[0] if ti_results else ThreatIntelResult(
            provider="cyberguard_threat_intel",
            query=sha256,
            indicator_type="HASH",
            is_malicious=False,
            verdict="UNKNOWN",
            confidence=0.0,
            details="Threat intelligence lookup unavailable",
        )

        hash_info = ThreatIntelHashInfo(
            provider=ti_res.provider,
            sha256_queried=sha256,
            verdict=ti_res.verdict,
            is_malicious=ti_res.is_malicious,
            threat_types=ti_res.threat_types,
            confidence=ti_res.confidence,
            details=ti_res.details,
            retrieved_at=ti_res.retrieved_at,
        )

        if ti_res.is_malicious:
            e_idx = result.add_evidence(
                source="THREAT_INTELLIGENCE_SERVICE",
                evidence_type="FILE_HASH_REPUTATION_MATCH",
                raw_content=f"Hash: {sha256}, Provider: {ti_res.provider}",
                parsed_content={
                    "verdict": ti_res.verdict,
                    "threat_types": ti_res.threat_types,
                    "confidence": ti_res.confidence,
                },
                confidence=ti_res.confidence,
            )
            result.add_finding(
                title=f"Threat Intelligence Hash Match: {ti_res.verdict}",
                description=(
                    f"Cryptographic hash {sha256[:12]}... matches known malicious records in "
                    f"threat intelligence feed ({ti_res.provider}). Threat classifications: {', '.join(ti_res.threat_types) or 'Malware'}."
                ),
                finding_type="THREAT_INTELLIGENCE_HASH_MATCH",
                category="THREAT_INTEL",
                severity=SeverityEnum.CRITICAL,
                confidence=ti_res.confidence,
                mitre_technique_id="T1588.002",  # Tool: Malware
                evidence_indices=[e_idx],
                metadata={"verdict": ti_res.verdict, "threat_types": ti_res.threat_types},
            )

        return result, hash_info


# ============================================================================
# 9. FILE CLASSIFICATION SERVICE
# ============================================================================

class FileClassificationService:
    """
    Conservative, evidence-driven file risk synthesis.
    Distinguishes:
    - KNOWN_MALICIOUS (requires verified TI match or verified high-confidence signature)
    - MALWARE_SUSPECTED (multiple corroborating high-severity signals)
    - SUSPICIOUS (macros present, double extension, RLO, suspicious script, high entropy)
    - BENIGN_LIKELY (clean standard document/media)
    - UNKNOWN (unsupported or encrypted container)
    CRITICAL RULE: UNKNOWN != SAFE.
    """

    @classmethod
    def classify(
        cls,
        findings: List[Dict[str, Any]],
        hash_reputation: ThreatIntelHashInfo,
        detected_type: str,
    ) -> Tuple[str, float, SeverityEnum, float, str]:
        """
        Returns: (classification, risk_score, severity, confidence, summary)
        """
        score = 0.0
        confidence = 0.85

        # 1. Threat Intel match
        if hash_reputation.is_malicious:
            return (
                "KNOWN_MALICIOUS",
                95.0,
                SeverityEnum.CRITICAL,
                0.98,
                f"Known malicious file: cryptographic hash matches verified threat intelligence signature ({', '.join(hash_reputation.threat_types) or 'Malware'})."
            )

        # Check finding types
        finding_types = {f.get("finding_type") for f in findings}

        # Zip-Slip exploit
        if "PATH_TRAVERSAL_DETECTED" in finding_types:
            return (
                "MALWARE_SUSPECTED",
                88.0,
                SeverityEnum.CRITICAL,
                0.95,
                "Malware suspected: archive attempts Zip-Slip path traversal vulnerability exploitation."
            )

        # Disguised executable
        if "FILE_TYPE_MISMATCH" in finding_types and ("Windows executable" in detected_type or "Linux ELF" in detected_type):
            score += 45.0

        if "DOUBLE_EXTENSION" in finding_types:
            score += 30.0

        if "UNICODE_FILENAME_DECEPTION" in finding_types:
            score += 30.0

        if "PDF_LAUNCH_ACTION_PRESENT" in finding_types:
            score += 35.0

        if "PDF_JAVASCRIPT_PRESENT" in finding_types:
            score += 20.0

        if "PDF_OPEN_ACTION_PRESENT" in finding_types:
            score += 15.0

        if "MACRO_PRESENT" in finding_types:
            score += 25.0

        if "SUSPICIOUS_DOCUMENT_RELATIONSHIP" in finding_types:
            score += 25.0

        if "SUSPICIOUS_STATIC_SCRIPT" in finding_types:
            score += 30.0

        if "SUSPICIOUS_IMPORT_SET" in finding_types:
            score += 20.0

        if "UNUSUAL_SECTION_NAME" in finding_types or "HIGH_ENTROPY_SECTION" in finding_types:
            score += 15.0

        if "ARCHIVE_EXTRACTION_LIMIT_REACHED" in finding_types:
            score += 25.0

        if "ARCHIVE_ENCRYPTED" in finding_types:
            score += 15.0

        final_score = min(max(score, 0.0), 100.0)

        if final_score >= 70.0:
            classification = "MALWARE_SUSPECTED"
            severity = SeverityEnum.HIGH
            summary = "Malware suspected: multiple corroborating evasion, disguised executable, or suspicious automation signals detected."
        elif final_score >= 25.0:
            classification = "SUSPICIOUS"
            severity = SeverityEnum.MEDIUM
            summary = "Suspicious file: exhibits active automation (macros/scripts), unusual sections, or extension anomalies."
        elif final_score > 0.0:
            classification = "BENIGN_LIKELY"
            severity = SeverityEnum.LOW
            summary = "Likely benign: minor structural signals observed without active malicious evasion."
        else:
            if detected_type in ("Generic binary", "Unknown Archive"):
                classification = "UNKNOWN"
                severity = SeverityEnum.SAFE
                summary = "Unknown format: file structure is not recognized or lacks deterministic parsing rules. (Note: Unknown != Safe)."
            else:
                classification = "BENIGN_LIKELY"
                severity = SeverityEnum.SAFE
                summary = "Benign: standard clean file structure with zero suspicious indicators or evasion markers detected."

        return classification, final_score, severity, confidence, summary
