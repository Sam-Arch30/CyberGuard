import io
import math
import os
import re
import struct
import zipfile
import hashlib
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple, Set

from backend.schemas.attachment_analysis import (
    AttachmentStaticAnalysisResult,
    PESectionInfo,
    PEImportInfo,
    PEMetadata,
    PDFStaticMetadata,
    OfficeStaticMetadata,
    ArchiveEntryInfo,
    ArchiveStaticMetadata
)


class AttachmentIntelligenceService:
    """
    Attachment Intelligence and Safe Static Malware Analysis Service.
    
    CRITICAL SECURITY MANDATES:
    1. Zero execution: Never run binaries, macros, scripts, or embedded payloads.
    2. Zero dynamic sandboxing: All inspection is strictly static binary/text analysis.
    3. Hostile input posture: Enforce strict byte limits, decompression guards, and path traversal defenses.
    """

    MAX_PAYLOAD_SIZE = 25 * 1024 * 1024       # 25 MB max attachment input
    MAX_UNCOMPRESSED_SIZE = 100 * 1024 * 1024 # 100 MB max aggregate uncompressed
    MAX_COMPRESSION_RATIO = 100.0             # 100:1 max decompression ratio
    MAX_ARCHIVE_FILES = 500                   # Max 500 files per archive
    MAX_ARCHIVE_DEPTH = 3                     # Max nested archive depth

    SUSPICIOUS_EXTENSIONS = {
        ".exe", ".scr", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
        ".wsf", ".wsh", ".ps1", ".ps1xml", ".ps2", ".psc1", ".psc2",
        ".msh", ".msh1", ".msh2", ".mshxml", ".msh1xml", ".msh2xml",
        ".jar", ".iso", ".img", ".vhd", ".vhdx", ".hta", ".cpl", ".msc",
        ".inf", ".reg", ".dll", ".sys", ".drv", ".ocx", ".pif", ".com",
        ".docm", ".xlsm", ".pptm"
    }

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

    # In-memory reputation cache: sha256 -> Dict[str, Any]
    _reputation_cache: Dict[str, Dict[str, Any]] = {}

    @classmethod
    def calculate_hashes(cls, payload: bytes) -> Tuple[str, str, str]:
        """Calculates SHA-256 (primary forensic identifier), SHA-1, and MD5."""
        sha256_hash = hashlib.sha256(payload).hexdigest()
        sha1_hash = hashlib.sha1(payload).hexdigest()
        md5_hash = hashlib.md5(payload).hexdigest()
        return sha256_hash, sha1_hash, md5_hash

    @classmethod
    def calculate_entropy(cls, payload: bytes) -> float:
        """
        Calculates Shannon Entropy (0.00 to 8.00) of the byte sequence.
        H = -sum(p * log2(p))
        """
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
    def evaluate_entropy_level(cls, entropy: float, detected_type: str) -> Tuple[str, str]:
        """
        Evaluates entropy level and generates an explainable forensic explanation.
        Explicitly notes that high entropy alone is NOT classified as malware.
        """
        if entropy < 3.5:
            level = "low"
            desc = f"Low entropy ({entropy:.2f}/8.00) indicates uncompressed plain text or sparse structured bytes."
        elif entropy < 6.8:
            level = "normal"
            desc = f"Normal entropy ({entropy:.2f}/8.00) typical of compiled binary code, images, or formatted documents."
        elif entropy < 7.5:
            level = "high"
            desc = f"High entropy ({entropy:.2f}/8.00) indicates compressed data or dense binary encoding."
        else:
            level = "very_high"
            desc = f"Very high entropy ({entropy:.2f}/8.00) indicates packed executable code, strong encryption, or maximum compression. Note: high entropy alone is not proof of malware without malicious structure."
        return level, desc

    @classmethod
    def detect_file_type(cls, payload: bytes, filename: str, mime_type: str) -> Tuple[str, str, str]:
        """
        Inspects magic bytes and structure to identify detected_type, detected_mime_type, and claimed_type.
        Never trusts the filename extension alone.
        """
        lower_fn = filename.lower()
        claimed = "Generic binary"
        if lower_fn.endswith(".pdf"):
            claimed = "PDF document"
        elif lower_fn.endswith((".docx", ".doc")):
            claimed = "Microsoft Word document"
        elif lower_fn.endswith((".xlsx", ".xls")):
            claimed = "Microsoft Excel spreadsheet"
        elif lower_fn.endswith((".pptx", ".ppt")):
            claimed = "Microsoft PowerPoint presentation"
        elif lower_fn.endswith(".docm"):
            claimed = "Word Macro-enabled document"
        elif lower_fn.endswith(".xlsm"):
            claimed = "Excel Macro-enabled spreadsheet"
        elif lower_fn.endswith((".zip", ".7z", ".rar", ".tar", ".gz")):
            claimed = "Archive"
        elif lower_fn.endswith((".exe", ".dll", ".scr", ".com")):
            claimed = "Windows executable"
        elif lower_fn.endswith((".html", ".htm")):
            claimed = "HTML document"
        elif lower_fn.endswith(".js"):
            claimed = "JavaScript source"
        elif lower_fn.endswith(".txt"):
            claimed = "Plain text"

        # 1. PDF detection (%PDF)
        if payload.startswith(b"%PDF"):
            return "PDF document", "application/pdf", claimed

        # 2. Windows PE detection (MZ)
        if payload.startswith(b"MZ") and len(payload) >= 64:
            e_lfanew = struct.unpack_from("<I", payload, 0x3C)[0]
            if e_lfanew + 4 <= len(payload) and payload[e_lfanew:e_lfanew+4] == b"PE\x00\x00":
                return "Windows executable", "application/vnd.microsoft.portable-executable", claimed

        # 3. ZIP-based containers (PK\x03\x04)
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
                            return "Word Macro-enabled document (DOCM)", "application/vnd.ms-word.document.macroEnabled.12", claimed
                        if is_excel:
                            return "Excel Macro-enabled spreadsheet (XLSM)", "application/vnd.ms-excel.sheet.macroEnabled.12", claimed
                        if is_ppt:
                            return "PowerPoint Macro-enabled presentation (PPTM)", "application/vnd.ms-powerpoint.presentation.macroEnabled.12", claimed
                        return "Office OpenXML (Macro-enabled)", "application/vnd.ms-office.vbaProject", claimed

                    if is_word:
                        return "Microsoft Word OpenXML (DOCX)", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", claimed
                    if is_excel:
                        return "Microsoft Excel OpenXML (XLSX)", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", claimed
                    if is_ppt:
                        return "Microsoft PowerPoint OpenXML (PPTX)", "application/vnd.openxmlformats-officedocument.presentationml.presentation", claimed

                    return "ZIP Archive", "application/zip", claimed
            except Exception:
                return "ZIP Archive", "application/zip", claimed

        # 4. OLE Compound Document (\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1)
        if payload.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
            if b"WordDocument" in payload:
                return "Microsoft Word 97-2003 Document (DOC)", "application/msword", claimed
            if b"Workbook" in payload:
                return "Microsoft Excel 97-2003 Spreadsheet (XLS)", "application/vnd.ms-excel", claimed
            if b"PowerPoint Document" in payload:
                return "Microsoft PowerPoint 97-2003 Presentation (PPT)", "application/vnd.ms-powerpoint", claimed
            return "OLE Compound Document", "application/x-ole-storage", claimed

        # 5. RAR Archive
        if payload.startswith(b"Rar!\x1a\x07\x00") or payload.startswith(b"Rar!\x1a\x07\x01\x00"):
            return "RAR Archive", "application/vnd.rar", claimed

        # 6. 7-Zip Archive
        if payload.startswith(b"7z\xbc\xaf\x27\x1c"):
            return "7-Zip Archive", "application/x-7z-compressed", claimed

        # 7. HTML detection
        sample_text = payload[:1024].decode("latin-1", errors="ignore").lower().strip()
        if sample_text.startswith(("<html", "<!doctype html", "<head", "<body")):
            return "HTML document", "text/html", claimed

        # 8. JavaScript detection
        if (sample_text.startswith(("function", "var ", "let ", "const ", "(function", "//", "/*"))
            or lower_fn.endswith(".js")):
            return "JavaScript source", "application/javascript", claimed

        # 9. Plain text detection
        try:
            payload[:4096].decode("utf-8")
            if not any(b == 0 for b in payload[:1024]):
                return "Plain text", "text/plain", claimed
        except UnicodeDecodeError:
            pass

        return "Generic binary", "application/octet-stream", claimed

    @classmethod
    def check_extension_mismatch(cls, filename: str, detected_type: str) -> Tuple[bool, Optional[str], bool]:
        """
        Detects MIME / extension mismatches and double extensions (e.g. invoice.pdf.exe).
        Returns: (is_mismatch, mismatch_details, is_double_extension)
        """
        lower_fn = filename.lower()
        parts = lower_fn.split(".")

        # Double extension check
        is_double_ext = False
        if len(parts) >= 3:
            first_ext = f".{parts[-2]}"
            second_ext = f".{parts[-1]}"
            doc_exts = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".jpg", ".png", ".csv"}
            exec_exts = cls.SUSPICIOUS_EXTENSIONS
            if first_ext in doc_exts and second_ext in exec_exts:
                is_double_ext = True

        # Mismatch check: Claimed document/image/text, but detected executable or archive
        is_mismatch = False
        details = None

        if "Windows executable" in detected_type:
            if not lower_fn.endswith((".exe", ".dll", ".scr", ".com")):
                is_mismatch = True
                details = f"Executable disguised as '{parts[-1] if len(parts) > 1 else 'unknown'}' (Claimed type: Document/Data, Detected type: Windows executable)"
        elif "PDF document" in detected_type:
            if not lower_fn.endswith(".pdf"):
                is_mismatch = True
                details = f"PDF payload with non-PDF extension '{parts[-1]}'"
        elif "ZIP Archive" in detected_type:
            if not lower_fn.endswith((".zip", ".jar", ".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm")):
                is_mismatch = True
                details = f"ZIP archive disguised with extension '{parts[-1]}'"
        elif "Macro-enabled" in detected_type:
            if lower_fn.endswith((".docx", ".xlsx", ".pptx", ".pdf", ".txt")):
                is_mismatch = True
                details = f"Macro-bearing payload disguised with clean document extension '{parts[-1]}'"

        if is_double_ext and not details:
            details = f"Double extension anomaly detected: '{filename}' uses dual extensions to conceal executable payload"

        return is_mismatch or is_double_ext, details, is_double_ext

    @classmethod
    def parse_pe_headers(cls, payload: bytes) -> PEMetadata:
        """
        Safely parses Windows Portable Executable (PE) headers without code execution.
        Extracts architecture, compile timestamp, sections, imports, and Authenticode status.
        """
        warnings: List[str] = []
        try:
            if len(payload) < 64 or not payload.startswith(b"MZ"):
                return PEMetadata(is_pe=False, warnings=["Not a valid MZ header"])

            e_lfanew = struct.unpack_from("<I", payload, 0x3C)[0]
            if e_lfanew + 24 > len(payload) or payload[e_lfanew:e_lfanew+4] != b"PE\x00\x00":
                return PEMetadata(is_pe=False, warnings=["Missing PE signature at e_lfanew"])

            # COFF File Header (20 bytes following PE\x00\x00)
            coff_offset = e_lfanew + 4
            machine, num_sections, timedatestamp, _, _, opt_hdr_size, characteristics = struct.unpack_from(
                "<HHIIIHH", payload, coff_offset
            )

            # Machine architecture mapping
            arch_map = {
                0x014C: "x86 (32-bit)",
                0x8664: "x64 (AMD64 / 64-bit)",
                0x0200: "Intel Itanium",
                0xAA64: "ARM64",
                0x01C0: "ARM"
            }
            architecture = arch_map.get(machine, f"Unknown (0x{machine:04X})")

            # Compile timestamp
            compile_ts_str = "Invalid/Unavailable"
            try:
                if 315532800 <= timedatestamp <= 2147483647: # between 1980 and 2038
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

                # Security Directory offset in Data Directories
                data_dirs_offset = opt_offset + (112 if is_64 else 96)
                # Security Directory is entry 4 (each entry is 8 bytes: RVA, Size)
                sec_dir_offset = data_dirs_offset + (4 * 8)
                if sec_dir_offset + 8 <= opt_offset + opt_hdr_size:
                    sec_rva, sec_size = struct.unpack_from("<II", payload, sec_dir_offset)
                    if sec_size > 0 and sec_rva > 0:
                        has_authenticode = True
                        signature_status = "Signed"
                    else:
                        signature_status = "Unsigned"

            # Parse Sections
            sections: List[PESectionInfo] = []
            sec_table_offset = opt_offset + opt_hdr_size
            bounded_sections = min(num_sections, 32) # Guard against malformed section count

            for i in range(bounded_sections):
                s_off = sec_table_offset + (i * 40)
                if s_off + 40 > len(payload):
                    break
                s_name_raw = payload[s_off:s_off+8]
                s_name = s_name_raw.split(b"\x00")[0].decode("latin-1", errors="replace").strip()
                v_size, v_addr, raw_size, raw_ptr, _, _, _, _, s_chars = struct.unpack_from(
                    "<IIIIIIHHI", payload, s_off + 8
                )

                # Section entropy
                sec_bytes = b""
                if raw_ptr < len(payload) and raw_size > 0:
                    end_ptr = min(raw_ptr + raw_size, len(payload))
                    sec_bytes = payload[raw_ptr:end_ptr]
                s_entropy = cls.calculate_entropy(sec_bytes)

                # Flag suspicious sections (packer names or high entropy in executable sections)
                is_suspicious_sec = False
                known_packer_prefixes = ["upx", ".aspack", ".themida", ".vmp", "mpress"]
                if any(s_name.lower().startswith(p) for p in known_packer_prefixes):
                    is_suspicious_sec = True
                if s_entropy > 7.5 and (s_chars & 0x20000000): # IMAGE_SCN_MEM_EXECUTE
                    is_suspicious_sec = True

                sections.append(PESectionInfo(
                    name=s_name,
                    virtual_size=v_size,
                    virtual_address=f"0x{v_addr:08X}",
                    raw_size=raw_size,
                    entropy=s_entropy,
                    characteristics=f"0x{s_chars:08X}",
                    is_suspicious=is_suspicious_sec
                ))

            # Scan for Imported DLLs and Suspicious APIs safely in payload strings
            imported_dlls: Set[str] = set()
            suspicious_imports: Set[str] = set()

            dll_pattern = re.compile(rb'\b([a-zA-Z0-9_\-\.]+\.(?:dll|drv|ocx|sys))\b', re.IGNORECASE)
            for m in dll_pattern.finditer(payload):
                dll_name = m.group(1).decode("latin-1", errors="ignore")
                if len(dll_name) < 40 and not dll_name.startswith("."):
                    imported_dlls.add(dll_name)

            for api in cls.SUSPICIOUS_PE_APIS:
                if api.encode("ascii") in payload:
                    suspicious_imports.add(api)

            imports_list: List[PEImportInfo] = []
            for dll in sorted(list(imported_dlls))[:15]:
                imports_list.append(PEImportInfo(
                    dll=dll,
                    functions=[api for api in suspicious_imports if dll.lower().startswith(("kernel", "user", "url", "wininet"))][:5]
                ))

            return PEMetadata(
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
                warnings=warnings
            )
        except Exception as e:
            return PEMetadata(
                is_pe=True,
                warnings=[f"PE parser encountered non-fatal error: {str(e)}"]
            )

    @classmethod
    def parse_pdf(cls, payload: bytes) -> PDFStaticMetadata:
        """
        Safely scans PDF structure for active objects, JavaScript, launch actions,
        embedded payload files, and external URIs without rendering or executing.
        """
        warnings: List[str] = []
        try:
            if not payload.startswith(b"%PDF"):
                return PDFStaticMetadata(is_pdf=False, warnings=["Missing %PDF magic header"])

            # Extract version
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
                        js_snippets.append(decoded[:120])
                    if len(js_snippets) >= 3:
                        break

            # Check for /OpenAction or /AA
            has_open_action = bool(re.search(rb'/(?:OpenAction|AA)\b', payload))

            # Check for /Launch
            has_launch_action = bool(re.search(rb'/Launch\b', payload))

            # Check for /EmbeddedFiles or /EF
            has_embedded_files = bool(re.search(rb'/(?:EmbeddedFiles|EF)\b', payload))
            embedded_names: List[str] = []
            if has_embedded_files:
                for match in re.finditer(rb'/(?:F|UF)\s*\(([^)]+)\)', payload):
                    embedded_names.append(match.group(1).decode("latin-1", errors="replace"))

            # Check for /SubmitForm
            has_submit_form = bool(re.search(rb'/SubmitForm\b', payload))

            # Check for /URI
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

            # Metadata extraction
            metadata: Dict[str, str] = {}
            for meta_key in [b"Title", b"Author", b"Creator", b"Producer", b"CreationDate"]:
                m = re.search(rb'/' + meta_key + rb'\s*\(([^)]*)\)', payload)
                if m:
                    metadata[meta_key.decode("ascii")] = m.group(1).decode("latin-1", errors="replace")

            # Collect suspicious elements
            suspicious_elements: List[str] = []
            if has_js:
                suspicious_elements.append("Embedded JavaScript (/JavaScript or /JS)")
            if has_open_action:
                suspicious_elements.append("Auto-execution trigger (/OpenAction or /AA)")
            if has_launch_action:
                suspicious_elements.append("External program execution (/Launch)")
            if has_embedded_files:
                suspicious_elements.append("Embedded file payloads (/EmbeddedFiles or /EF)")
            if has_submit_form:
                suspicious_elements.append("Data exfiltration form action (/SubmitForm)")

            return PDFStaticMetadata(
                is_pdf=True,
                pdf_version=pdf_version,
                has_javascript=has_js,
                javascript_snippets=js_snippets,
                has_open_action=has_open_action,
                has_launch_action=has_launch_action,
                has_embedded_files=has_embedded_files,
                embedded_file_names=embedded_names[:10],
                has_submit_form=has_submit_form,
                has_external_uri=len(external_uris) > 0,
                external_uris=list(dict.fromkeys(external_uris))[:20],
                suspicious_elements=suspicious_elements,
                metadata=metadata,
                warnings=warnings
            )
        except Exception as e:
            return PDFStaticMetadata(
                is_pdf=True,
                warnings=[f"PDF parser encountered error: {str(e)}"]
            )

    @classmethod
    def parse_office(cls, payload: bytes, detected_type: str) -> OfficeStaticMetadata:
        """
        Safely inspects Office OpenXML (DOCX, XLSX, PPTX, DOCM, XLSM) and OLE files.
        Detects macros, external template injection relationships, and embedded objects.
        """
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
                                for m in re.finditer(rb'TargetMode="External"[^>]*Target="([^"]+)"', rel_bytes, re.IGNORECASE):
                                    ext_target = m.group(1).decode("latin-1", errors="ignore")
                                    has_external_rels = True
                                    external_rels.append(ext_target)
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

        return OfficeStaticMetadata(
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
            warnings=warnings
        )

    @classmethod
    def parse_archive(cls, payload: bytes) -> ArchiveStaticMetadata:
        """
        Safely inspects archive contents with strict defense against zip bombs,
        path traversal (e.g. ../), password protection, and hidden executables.
        Never extracts files to disk.
        """
        entries: List[ArchiveEntryInfo] = []
        suspicious_entries: List[str] = []
        safety_violations: List[str] = []
        total_uncompressed = 0
        total_files = 0
        is_encrypted = False
        has_nested = False
        has_traversal = False
        has_hidden_exec = False

        if not payload.startswith(b"PK\x03\x04"):
            return ArchiveStaticMetadata(
                is_archive=True,
                archive_type="Unknown Archive",
                safety_violations=["Unrecognized archive header bytes"]
            )

        try:
            with zipfile.ZipFile(io.BytesIO(payload), "r") as zf:
                infolist = zf.infolist()
                total_files = len(infolist)

                # 1. Guard against excessive entry count
                if total_files > cls.MAX_ARCHIVE_FILES:
                    safety_violations.append(
                        f"Zip bomb guard: excessive entry count ({total_files} > {cls.MAX_ARCHIVE_FILES})"
                    )

                for info in infolist[:cls.MAX_ARCHIVE_FILES]:
                    fn = info.filename
                    u_size = info.file_size
                    c_size = info.compress_size
                    total_uncompressed += u_size

                    # Check password protection (flag_bits bit 0)
                    entry_encrypted = bool(info.flag_bits & 0x1)
                    if entry_encrypted:
                        is_encrypted = True

                    # Check path traversal
                    entry_traversal = False
                    if "../" in fn or "..\\" in fn or fn.startswith("/") or re.match(r'^[a-zA-Z]:', fn):
                        entry_traversal = True
                        has_traversal = True
                        safety_violations.append(f"Path traversal exploit detected: '{fn}'")

                    # Check suspicious extensions
                    entry_suspicious_ext = False
                    lower_fn = fn.lower()
                    for ext in cls.SUSPICIOUS_EXTENSIONS:
                        if lower_fn.endswith(ext):
                            entry_suspicious_ext = True
                            has_hidden_exec = True
                            suspicious_entries.append(fn)
                            break

                    # Check nested archives
                    entry_nested = False
                    if lower_fn.endswith((".zip", ".rar", ".7z", ".tar", ".gz", ".iso")):
                        entry_nested = True
                        has_nested = True

                    entries.append(ArchiveEntryInfo(
                        filename=fn,
                        uncompressed_size=u_size,
                        compressed_size=c_size,
                        is_encrypted=entry_encrypted,
                        is_suspicious_extension=entry_suspicious_ext,
                        is_nested_archive=entry_nested,
                        is_path_traversal=entry_traversal
                    ))

                # 2. Guard against uncompressed size bomb
                if total_uncompressed > cls.MAX_UNCOMPRESSED_SIZE:
                    safety_violations.append(
                        f"Zip bomb guard: aggregate uncompressed size ({total_uncompressed} bytes) exceeds limit (100MB)"
                    )

                # 3. Guard against excessive compression ratio
                compressed_total = max(len(payload), 1)
                ratio = total_uncompressed / compressed_total
                if ratio > cls.MAX_COMPRESSION_RATIO:
                    safety_violations.append(
                        f"Zip bomb guard: anomalous compression ratio ({ratio:.1f}:1 > 100:1)"
                    )

        except zipfile.BadZipFile as e:
            safety_violations.append(f"Corrupted or malformed archive format: {str(e)}")
        except Exception as e:
            safety_violations.append(f"Archive inspection exception: {str(e)}")

        ratio = round(total_uncompressed / max(len(payload), 1), 2)

        return ArchiveStaticMetadata(
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
            safety_violations=safety_violations
        )

    @classmethod
    def extract_embedded_iocs(cls, payload: bytes) -> Tuple[List[str], List[str], List[str], List[str]]:
        """
        Extracts embedded URLs, domains, IPs, and hashes from printable attachment bytes.
        """
        urls: Set[str] = set()
        domains: Set[str] = set()
        ips: Set[str] = set()
        hashes: Set[str] = set()

        text = payload[:1024 * 1024].decode("latin-1", errors="ignore")

        # 1. URLs
        url_matches = re.findall(r'https?://[a-zA-Z0-9\-\._~:/\?#\[\]@!$&\'\(\)\*\+,;=%]+', text)
        schema_namespaces = (
            "schemas.openxmlformats.org",
            "schemas.microsoft.com",
            "www.w3.org",
            "purl.org",
            "oasis-open.org",
            "xml.org"
        )
        for u in url_matches:
            clean_u = u.rstrip(")>].,;\"'")
            if len(clean_u) > 10 and "." in clean_u:
                if not any(ns in clean_u.lower() for ns in schema_namespaces):
                    urls.add(clean_u)

        # 2. Domains from URLs
        for u in urls:
            try:
                d_match = re.search(r'https?://([a-zA-Z0-9\-\.]+)', u)
                if d_match:
                    host = d_match.group(1).split(":")[0].lower()
                    if "." in host and not host.replace(".", "").isdigit():
                        domains.add(host)
            except Exception:
                pass

        # 3. IPs
        ip_matches = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', text)
        for ip in ip_matches:
            octets = [int(o) for o in ip.split(".")]
            if all(0 <= o <= 255 for o in octets):
                if not (octets[0] in (0, 127, 255) or (octets[0] == 169 and octets[1] == 254)):
                    ips.add(ip)

        # 4. Hashes
        hash_matches = re.findall(r'\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{32}\b', text)
        for h in hash_matches:
            hashes.add(h.lower())

        return sorted(list(urls))[:25], sorted(list(domains))[:25], sorted(list(ips))[:25], sorted(list(hashes))[:25]

    @classmethod
    def query_reputation(cls, sha256: str) -> Tuple[str, Optional[str], Optional[str]]:
        """
        Queries approved external threat intelligence integration if configured.
        Returns: (reputation_status, provider, details)
        Strict rule: If no provider is configured, returns 'Reputation unavailable'. Do NOT fabricate.
        """
        if sha256 in cls._reputation_cache:
            cached = cls._reputation_cache[sha256]
            return cached["status"], cached.get("provider"), cached.get("details")

        # In production, check if an external TI provider (e.g. VirusTotal/AlienVault) API key is configured
        ti_api_key = os.environ.get("THREAT_INTEL_API_KEY")
        if not ti_api_key:
            return "Reputation unavailable", None, "No external threat-intelligence reputation provider configured."

        # If configured, provider query logic would go here
        return "Reputation unavailable", None, "External threat-intelligence integration pending query."

    @classmethod
    def calculate_threat_level(
        cls,
        is_mismatch: bool,
        is_double_ext: bool,
        detected_type: str,
        pe_meta: Optional[PEMetadata],
        pdf_meta: Optional[PDFStaticMetadata],
        office_meta: Optional[OfficeStaticMetadata],
        archive_meta: Optional[ArchiveStaticMetadata],
        entropy: float,
        embedded_urls: List[str]
    ) -> Tuple[str, int, List[str], str]:
        """
        Computes deterministic attachment threat score (0 to 100), categorical threat level,
        explainable risk signals, and executive summary.
        """
        score = 0
        signals: List[str] = []

        # 1. Disguised executable / mismatch
        if is_mismatch and "Windows executable" in detected_type:
            score += 45
            signals.append("Executable disguised as document (High-severity evasion)")
        elif is_mismatch:
            score += 30
            signals.append("File format and extension mismatch detected")

        if is_double_ext:
            score += 30
            signals.append("Double extension evasion technique detected")

        # 2. Executable specific signals
        if pe_meta and pe_meta.is_pe:
            if pe_meta.signature_status == "Unsigned":
                score += 25
                signals.append("Unsigned Windows executable binary")
            if pe_meta.suspicious_imports:
                score += min(len(pe_meta.suspicious_imports) * 10, 30)
                signals.append(f"Suspicious API imports detected ({', '.join(pe_meta.suspicious_imports[:3])})")
            if any(s.is_suspicious for s in pe_meta.sections):
                score += 20
                signals.append("Suspicious section headers or packed binary sections")

        # 3. PDF specific signals
        if pdf_meta and pdf_meta.is_pdf:
            if pdf_meta.has_javascript:
                score += 35
                signals.append("PDF contains active embedded JavaScript (/JavaScript or /JS)")
            if pdf_meta.has_open_action:
                score += 25
                signals.append("PDF triggers automatic execution on open (/OpenAction or /AA)")
            if pdf_meta.has_launch_action:
                score += 40
                signals.append("PDF contains external program launcher (/Launch)")
            if pdf_meta.has_embedded_files:
                score += 25
                signals.append("PDF packages hidden embedded files (/EmbeddedFiles)")

        # 4. Office specific signals
        if office_meta and office_meta.is_office:
            if office_meta.has_macros:
                score += 35
                signals.append("Document contains VBA macro code (vbaProject.bin)")
            if office_meta.has_external_relationships:
                score += 30
                signals.append("External template relationship injection detected")
            if office_meta.suspicious_keywords:
                score += 25
                signals.append(f"Suspicious macro execution keywords ({', '.join(office_meta.suspicious_keywords[:3])})")

        # 5. Archive specific signals
        if archive_meta and archive_meta.is_archive:
            if archive_meta.has_path_traversal:
                score += 50
                signals.append("Path traversal exploit detected in archive (Zip Slip vulnerability)")
            if archive_meta.has_hidden_executables:
                score += 35
                signals.append("Archive contains hidden executable or script payloads")
            if archive_meta.is_encrypted:
                score += 25
                signals.append("Password-protected archive prevents automated inspection")
            if archive_meta.has_nested_archives:
                score += 15
                signals.append("Nested archive encapsulation detected")

        # 6. Embedded URLs
        if embedded_urls:
            score += 15
            signals.append(f"Embedded URLs discovered within attachment ({len(embedded_urls)} link(s))")

        # 7. Entropy (bounded, not malware alone)
        if entropy > 7.5 and "Windows executable" in detected_type:
            score += 15
            signals.append("Very high entropy in executable binary indicates packing or obfuscation")

        # Bound score between 0 and 100
        final_score = max(0, min(score, 100))

        if final_score >= 75:
            level = "CRITICAL"
            summary = "Critical threat: Attachment exhibits high-confidence malware delivery, format spoofing, or active evasion techniques."
        elif final_score >= 50:
            level = "HIGH"
            summary = "High threat: Attachment contains active macro scripts, hidden executables, or suspicious auto-actions."
        elif final_score >= 25:
            level = "MEDIUM"
            summary = "Medium threat: Suspicious characteristics detected, such as password protection, double extensions, or unsigned code."
        elif final_score >= 10:
            level = "LOW"
            summary = "Low threat: Minor indicators observed (e.g. external links), but no active malware characteristics."
        else:
            level = "BENIGN"
            summary = "Benign: No suspicious code, macro objects, extension mismatches, or malicious actions detected."

        return level, final_score, signals, summary

    @classmethod
    def analyze_attachment(
        cls,
        payload: bytes,
        filename: Optional[str] = None,
        mime_type: Optional[str] = None
    ) -> AttachmentStaticAnalysisResult:
        """
        Executes safe static malware and intelligence analysis on an email attachment.
        Zero execution is guaranteed.
        """
        fn = filename or "unnamed_attachment.bin"
        # Sanitize filename
        clean_fn = re.sub(r'[\r\n\x00]', '', os.path.basename(fn)) or "attachment.bin"
        declared_mime = mime_type or "application/octet-stream"
        payload_bytes = payload or b""

        # 1. Hashes
        sha256_hash, sha1_hash, md5_hash = cls.calculate_hashes(payload_bytes)

        # 2. Entropy
        entropy = cls.calculate_entropy(payload_bytes)

        # 3. File type identification (magic bytes)
        detected_type, detected_mime, claimed_type = cls.detect_file_type(payload_bytes, clean_fn, declared_mime)
        entropy_level, entropy_analysis = cls.evaluate_entropy_level(entropy, detected_type)

        # 4. Extension mismatch
        is_mismatch, mismatch_details, is_double_ext = cls.check_extension_mismatch(clean_fn, detected_type)

        # Extract extension
        ext = os.path.splitext(clean_fn)[1].lower() or ".bin"

        # 5. Deep Format Parsers
        pe_meta: Optional[PEMetadata] = None
        pdf_meta: Optional[PDFStaticMetadata] = None
        office_meta: Optional[OfficeStaticMetadata] = None
        archive_meta: Optional[ArchiveStaticMetadata] = None
        signature_status = "N/A"

        if "Windows executable" in detected_type or payload_bytes.startswith(b"MZ"):
            pe_meta = cls.parse_pe_headers(payload_bytes)
            signature_status = pe_meta.signature_status
        elif "PDF" in detected_type or payload_bytes.startswith(b"%PDF"):
            pdf_meta = cls.parse_pdf(payload_bytes)
        elif "Word" in detected_type or "Excel" in detected_type or "PowerPoint" in detected_type or "Office" in detected_type or "OLE" in detected_type:
            office_meta = cls.parse_office(payload_bytes, detected_type)
        elif "Archive" in detected_type or payload_bytes.startswith(b"PK\x03\x04"):
            archive_meta = cls.parse_archive(payload_bytes)

        # 6. Extract Embedded IOCs
        embedded_urls, embedded_domains, embedded_ips, embedded_hashes = cls.extract_embedded_iocs(payload_bytes)

        # Merge URLs from deep format parsers
        if pdf_meta and pdf_meta.external_uris:
            for u in pdf_meta.external_uris:
                if u not in embedded_urls:
                    embedded_urls.append(u)
        if office_meta and office_meta.external_relationships:
            for u in office_meta.external_relationships:
                if u not in embedded_urls:
                    embedded_urls.append(u)

        total_indicators = len(embedded_urls) + len(embedded_domains) + len(embedded_ips) + len(embedded_hashes)

        # 7. Threat scoring & signals
        threat_level, threat_score, risk_signals, analysis_summary = cls.calculate_threat_level(
            is_mismatch=is_mismatch,
            is_double_ext=is_double_ext,
            detected_type=detected_type,
            pe_meta=pe_meta,
            pdf_meta=pdf_meta,
            office_meta=office_meta,
            archive_meta=archive_meta,
            entropy=entropy,
            embedded_urls=embedded_urls
        )

        # 8. Reputation lookup
        rep_status, rep_provider, rep_details = cls.query_reputation(sha256_hash)

        # 9. Evidence ID token
        evd_id = f"EVD-ATT-{sha256_hash[:8].upper()}"
        now_utc = datetime.now(timezone.utc).isoformat()

        magic_hex = payload_bytes[:16].hex(" ") if payload_bytes else ""

        return AttachmentStaticAnalysisResult(
            original_filename=clean_fn,
            extension=ext,
            claimed_type=claimed_type,
            mime_type=declared_mime,
            detected_mime_type=detected_mime,
            detected_type=detected_type,
            magic_bytes_hex=magic_hex,
            size=len(payload_bytes),
            extension_mismatch=is_mismatch,
            mismatch_details=mismatch_details,
            double_extension=is_double_ext,
            sha256=sha256_hash,
            sha1=sha1_hash,
            md5=md5_hash,
            entropy=entropy,
            entropy_level=entropy_level,
            entropy_analysis=entropy_analysis,
            signature_status=signature_status,
            pe_metadata=pe_meta,
            pdf_metadata=pdf_meta,
            office_metadata=office_meta,
            archive_metadata=archive_meta,
            embedded_urls=embedded_urls,
            embedded_domains=embedded_domains,
            embedded_ips=embedded_ips,
            embedded_hashes=embedded_hashes,
            embedded_indicators_count=total_indicators,
            threat_level=threat_level,
            threat_score=threat_score,
            risk_signals=risk_signals,
            analysis_summary=analysis_summary,
            reputation_status=rep_status,
            reputation_provider=rep_provider,
            reputation_details=rep_details,
            evidence_id=evd_id,
            timestamp=now_utc
        )
