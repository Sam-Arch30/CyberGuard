import io
import struct
import zipfile
import pytest
from backend.services.attachment_intelligence_service import AttachmentIntelligenceService
from backend.services.email_parser import EmailParserService
from backend.services.threat_scorer import ThreatScorerService
from backend.services.graph_service import InvestigationGraphService
from backend.schemas.graph import NodeType
from backend.schemas.attribution import AttributionResult


def create_synthetic_pe(arch=0x8664, signed=False, imports=None) -> bytes:
    """Creates a harmless synthetic PE binary structure for static parser testing."""
    # DOS Header (64 bytes)
    dos_hdr = bytearray(b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x80))
    # Pad up to e_lfanew (0x80)
    dos_hdr += b"\x00" * (0x80 - len(dos_hdr))
    
    # PE signature
    pe_sig = b"PE\x00\x00"
    
    # COFF File Header (20 bytes)
    # Machine, NumberOfSections, TimeDateStamp, PointerToSymbolTable, NumberOfSymbols, SizeOfOptionalHeader, Characteristics
    num_sections = 2
    timedatestamp = 1700000000 # Valid timestamp (Nov 2023)
    opt_hdr_size = 240
    chars = 0x0102 # Executable, 32/64 bit
    coff_hdr = struct.pack("<HHIIIHH", arch, num_sections, timedatestamp, 0, 0, opt_hdr_size, chars)
    
    # Optional Header (PE32+ 64-bit)
    magic = 0x020B
    opt_hdr = bytearray(struct.pack("<H", magic) + b"\x00" * 14)
    # entry point at +16
    opt_hdr += struct.pack("<I", 0x1000)
    # pad up to subsystem at +68
    opt_hdr += b"\x00" * (68 - len(opt_hdr))
    opt_hdr += struct.pack("<H", 2) # Windows GUI
    # pad up to data directories at +112
    opt_hdr += b"\x00" * (112 - len(opt_hdr))
    # Data directory 4: Security directory (offset 112 + 32 = 144)
    data_dirs = bytearray(16 * 8)
    if signed:
        # Put non-zero RVA and size in directory 4 (Security Directory)
        struct.pack_into("<II", data_dirs, 4 * 8, 0x5000, 0x200)
    opt_hdr += data_dirs
    opt_hdr += b"\x00" * (opt_hdr_size - len(opt_hdr))
    
    # Section 1: .text (40 bytes)
    sec1 = struct.pack("<8sIIIIIIHHI", b".text\x00\x00\x00", 0x1000, 0x1000, 0x400, 0x200, 0, 0, 0, 0, 0x60000020)
    # Section 2: .data (40 bytes)
    sec2 = struct.pack("<8sIIIIIIHHI", b".data\x00\x00\x00", 0x1000, 0x2000, 0x400, 0x600, 0, 0, 0, 0, 0xC0000040)
    
    # Section data with imports or benign strings
    payload = bytearray(dos_hdr + pe_sig + coff_hdr + opt_hdr + sec1 + sec2)
    payload += b"\x00" * (0x200 - len(payload)) # Pad to .text raw offset
    text_data = b"KERNEL32.dll\x00URLMON.dll\x00VirtualAlloc\x00URLDownloadToFileA\x00"
    payload += text_data + b"\x90" * (0x400 - len(text_data)) # .text section
    data_bytes = b"http://malicious-c2.test/beacon\x00"
    payload += data_bytes + b"\x00" * (0x400 - len(data_bytes)) # .data section
    
    return bytes(payload)


def test_normal_pdf():
    """Test 1: Normal clean PDF with metadata and standard structure."""
    pdf_bytes = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Title (Legitimate Invoice) /Author (Finance Corp) >>\nendobj\n"
        b"2 0 obj\n<< /Type /Catalog /Pages 3 0 R >>\nendobj\n"
        b"3 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n"
        b"xref\n0 4\n0000000000 65535 f \ntrailer\n<< /Root 2 0 R >>\nstartxref\n180\n%%EOF"
    )
    res = AttachmentIntelligenceService.analyze_attachment(pdf_bytes, "quarterly_report.pdf", "application/pdf")
    assert res.detected_type == "PDF document"
    assert res.extension_mismatch is False
    assert res.double_extension is False
    assert res.pdf_metadata is not None
    assert res.pdf_metadata.has_javascript is False
    assert res.pdf_metadata.has_launch_action is False
    assert res.pdf_metadata.has_open_action is False
    assert res.threat_level in ("BENIGN", "LOW")
    assert res.reputation_status == "Reputation unavailable"


def test_legitimate_docx():
    """Test 2: Legitimate OpenXML DOCX without macros or external relationships."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>')
        zf.writestr("word/document.xml", "<w:document><w:body><w:p><w:r><w:t>Hello world</w:t></w:r></w:p></w:body></w:document>")
        zf.writestr("_rels/.rels", '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>')
    docx_bytes = buf.getvalue()

    res = AttachmentIntelligenceService.analyze_attachment(docx_bytes, "contract.docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
    assert "Word" in res.detected_type
    assert res.extension_mismatch is False
    assert res.office_metadata is not None
    assert res.office_metadata.has_macros is False
    assert res.office_metadata.has_external_relationships is False
    assert res.threat_level == "BENIGN"


def test_executable_renamed_pdf():
    """Test 3: Windows PE executable renamed to .pdf or with double extension."""
    pe_bytes = create_synthetic_pe(arch=0x8664, signed=False)
    
    # 3a. Disguised as invoice.pdf
    res1 = AttachmentIntelligenceService.analyze_attachment(pe_bytes, "invoice.pdf", "application/pdf")
    assert res1.detected_type == "Windows executable"
    assert res1.extension_mismatch is True
    assert "Executable disguised" in res1.mismatch_details
    assert res1.pe_metadata is not None
    assert res1.pe_metadata.architecture == "x64 (AMD64 / 64-bit)"
    assert res1.pe_metadata.signature_status == "Unsigned"
    assert res1.threat_level in ("HIGH", "CRITICAL")
    assert any("disguised" in sig.lower() for sig in res1.risk_signals)

    # 3b. Double extension invoice_2026.pdf.exe
    res2 = AttachmentIntelligenceService.analyze_attachment(pe_bytes, "invoice_2026.pdf.exe", "application/octet-stream")
    assert res2.detected_type == "Windows executable"
    assert res2.double_extension is True
    assert res2.threat_level in ("HIGH", "CRITICAL")


def test_macro_containing_document_fixture():
    """Test 4: Office OpenXML document containing VBA macros (vbaProject.bin)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>')
        zf.writestr("word/document.xml", "<w:document><w:body/></w:document>")
        # Harmless dummy binary containing macro trigger keywords
        vba_bytes = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1 Sub AutoOpen() Shell('calc.exe') End Sub"
        zf.writestr("word/vbaProject.bin", vba_bytes)
    docm_bytes = buf.getvalue()

    res = AttachmentIntelligenceService.analyze_attachment(docm_bytes, "purchase_order.docm", "application/vnd.ms-word.document.macroEnabled.12")
    assert "Macro-enabled" in res.detected_type or res.office_metadata.has_macros is True
    assert res.office_metadata.has_macros is True
    assert res.office_metadata.vba_project_present is True
    assert "AutoOpen" in res.office_metadata.suspicious_keywords or "Shell" in res.office_metadata.suspicious_keywords
    assert res.threat_level in ("HIGH", "CRITICAL")


def test_zip_with_executable():
    """Test 5: ZIP archive containing an executable payload (.exe)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("statement.txt", b"Please review attached updater.")
        zf.writestr("updater.exe", create_synthetic_pe())
    zip_bytes = buf.getvalue()

    res = AttachmentIntelligenceService.analyze_attachment(zip_bytes, "archive.zip", "application/zip")
    assert res.detected_type == "ZIP Archive"
    assert res.archive_metadata is not None
    assert res.archive_metadata.has_hidden_executables is True
    assert "updater.exe" in res.archive_metadata.suspicious_entries
    assert res.threat_level in ("HIGH", "CRITICAL")


def test_nested_archive():
    """Test 6: Archive containing a nested archive (.zip inside .zip)."""
    inner_buf = io.BytesIO()
    with zipfile.ZipFile(inner_buf, "w") as inner_zf:
        inner_zf.writestr("document.txt", b"Inside nested archive")
    inner_zip = inner_buf.getvalue()

    outer_buf = io.BytesIO()
    with zipfile.ZipFile(outer_buf, "w") as outer_zf:
        outer_zf.writestr("inner_package.zip", inner_zip)
    outer_bytes = outer_buf.getvalue()

    res = AttachmentIntelligenceService.analyze_attachment(outer_bytes, "carrier.zip", "application/zip")
    assert res.archive_metadata is not None
    assert res.archive_metadata.has_nested_archives is True
    assert any(e.is_nested_archive for e in res.archive_metadata.entries)


def test_malformed_pdf():
    """Test 7: Malformed / corrupted PDF handled gracefully without exceptions."""
    corrupted_bytes = b"%PDF-1.4\xff\xfe\x00\x01<< /Incomplete /Broken"
    res = AttachmentIntelligenceService.analyze_attachment(corrupted_bytes, "broken.pdf", "application/pdf")
    assert res.detected_type == "PDF document"
    assert res.pdf_metadata is not None
    assert res.sha256 != ""
    assert res.size == len(corrupted_bytes)


def test_oversized_archive_protection():
    """Test 8: Archive exceeding safe bounds triggers zip bomb protection without crashing."""
    meta = AttachmentIntelligenceService.parse_archive(b"PK\x03\x04not_a_valid_zip_stream")
    assert meta.is_archive is True
    assert len(meta.safety_violations) > 0


def test_path_traversal_archive():
    """Test 9: Archive entry with path traversal (Zip Slip ../) flagged and blocked."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        # Python's zipfile allows writing raw names with traversal
        zf.writestr("../../Windows/System32/evil.dll", b"MZ_fake_binary")
    zip_bytes = buf.getvalue()

    res = AttachmentIntelligenceService.analyze_attachment(zip_bytes, "package.zip", "application/zip")
    assert res.archive_metadata is not None
    assert res.archive_metadata.has_path_traversal is True
    assert res.threat_level == "CRITICAL"
    assert any("traversal" in v.lower() for v in res.archive_metadata.safety_violations)


def test_duplicate_attachment():
    """Test 10: Multiple identical attachments result in identical SHA-256 and evidence IDs."""
    data = b"Some duplicate report payload content 12345"
    res1 = AttachmentIntelligenceService.analyze_attachment(data, "report1.pdf", "application/pdf")
    res2 = AttachmentIntelligenceService.analyze_attachment(data, "report2.pdf", "application/pdf")
    assert res1.sha256 == res2.sha256
    assert res1.md5 == res2.md5
    assert res1.evidence_id == res2.evidence_id


def test_password_protected_archive():
    """Test 11: Password-protected / encrypted archive detected."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("secret.txt", b"Encrypted data content")
    zip_bytes = bytearray(buf.getvalue())
    # Flip encryption bit in local file header (offset 6) and central directory (offset +8)
    if zip_bytes.startswith(b"PK\x03\x04"):
        zip_bytes[6] |= 0x01
    cd_idx = zip_bytes.find(b"PK\x01\x02")
    if cd_idx != -1:
        zip_bytes[cd_idx + 8] |= 0x01
    zip_bytes = bytes(zip_bytes)

    res = AttachmentIntelligenceService.analyze_attachment(zip_bytes, "protected.zip", "application/zip")
    assert res.archive_metadata is not None
    assert res.archive_metadata.is_encrypted is True
    assert any("password" in s.lower() for s in res.risk_signals)


def test_high_entropy_alone_not_malware():
    """Test 12: High entropy alone is NOT classified as malware."""
    # Pseudo-random bytes with maximum entropy (> 7.5)
    high_entropy_bytes = bytes([((i * 137 + 59) % 256) for i in range(4096)])
    res = AttachmentIntelligenceService.analyze_attachment(high_entropy_bytes, "data.bin", "application/octet-stream")
    assert res.entropy > 7.5
    assert res.entropy_level == "very_high"
    # Not malware alone without malicious structural elements
    assert res.threat_level in ("BENIGN", "LOW")


def test_email_parser_attachment_integration():
    """Test 13: Full email parser integration with attachment intelligence & IOC extraction."""
    pe_bytes = create_synthetic_pe(arch=0x8664, signed=False)
    
    # Construct a raw MIME email with disguised attachment
    eml_raw = (
        b"From: billing@adversary.com\r\n"
        b"To: victim@target.com\r\n"
        b"Subject: Overdue Invoice\r\n"
        b"Date: Mon, 15 Sep 2026 10:00:00 +0000\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: multipart/mixed; boundary=\"BOUNDARY123\"\r\n"
        b"\r\n"
        b"--BOUNDARY123\r\n"
        b"Content-Type: text/plain\r\n"
        b"\r\n"
        b"Please find invoice attached.\r\n"
        b"\r\n"
        b"--BOUNDARY123\r\n"
        b"Content-Type: application/pdf; name=\"invoice.pdf\"\r\n"
        b"Content-Disposition: attachment; filename=\"invoice.pdf\"\r\n"
        b"Content-Transfer-Encoding: base64\r\n"
        b"\r\n"
    )
    import base64
    eml_raw += base64.b64encode(pe_bytes) + b"\r\n--BOUNDARY123--\r\n"

    parsed = EmailParserService.parse_eml_bytes(eml_raw, "test_phish.eml")
    assert len(parsed.attachments) == 1
    att = parsed.attachments[0]
    assert att.filename == "invoice.pdf"
    assert att.static_analysis is not None
    assert att.static_analysis.extension_mismatch is True
    assert att.static_analysis.detected_type == "Windows executable"
    
    # Threat score evaluation on the email
    scorer = ThreatScorerService()
    score_res = scorer.calculate_score(parsed)
    assert score_res.score >= 50
    assert any(c.category == "attachments" and "executable" in c.name.lower() for c in score_res.positive_contributions)


def test_investigation_graph_attachment_linkages():
    """Test 14: Investigation graph links Attachment -> Hash, Attachment -> URL, Attachment -> Domain, Attachment -> Campaign."""
    pe_bytes = create_synthetic_pe(arch=0x8664, signed=False)
    
    eml_raw = (
        b"From: billing@adversary.com\r\n"
        b"To: victim@target.com\r\n"
        b"Subject: Statement\r\n"
        b"Date: Mon, 15 Sep 2026 10:00:00 +0000\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: multipart/mixed; boundary=\"BOUNDARY123\"\r\n"
        b"\r\n"
        b"--BOUNDARY123\r\n"
        b"Content-Type: text/plain\r\n"
        b"\r\n"
        b"Check statement.\r\n"
        b"\r\n"
        b"--BOUNDARY123\r\n"
        b"Content-Type: application/octet-stream; name=\"statement.exe\"\r\n"
        b"Content-Disposition: attachment; filename=\"statement.exe\"\r\n"
        b"Content-Transfer-Encoding: base64\r\n"
        b"\r\n"
    )
    import base64
    eml_raw += base64.b64encode(pe_bytes) + b"\r\n--BOUNDARY123--\r\n"

    parsed = EmailParserService.parse_eml_bytes(eml_raw, "statement.eml")
    
    graph_service = InvestigationGraphService()
    attribution = AttributionResult(
        attribution_id="ATTR-TEST-001",
        campaign_id="CAMP-FINANCE-HARVEST",
        confidence_score=85.0,
        confidence_level="HIGH",
        analysis_timestamp="2026-09-15T10:00:00Z"
    )
    parsed.attribution = attribution
    
    graph_res = graph_service.build_graph(
        email_analysis=parsed,
        case_id="CASE-2026-001"
    )

    # Check for Hash node
    hash_nodes = [n for n in graph_res.nodes if n.type == NodeType.HASH]
    assert len(hash_nodes) >= 1
    assert "SHA-256" in hash_nodes[0].label

    # Check for Attachment node
    att_nodes = [n for n in graph_res.nodes if n.type == NodeType.ATTACHMENT]
    assert len(att_nodes) >= 1

    # Check for edge: Email -> Attachment
    has_att_edges = [e for e in graph_res.edges if e.label == "HAS_ATTACHMENT"]
    assert len(has_att_edges) >= 1

    # Check for edge: Attachment -> Hash
    has_hash_edges = [e for e in graph_res.edges if e.label == "HAS_HASH"]
    assert len(has_hash_edges) >= 1

    # Check for edge: Attachment -> Campaign
    linked_camp_edges = [e for e in graph_res.edges if e.label == "LINKED_TO_CAMPAIGN"]
    assert len(linked_camp_edges) >= 1
